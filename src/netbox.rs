use crate::model::*;
use anyhow::{Context, Result, ensure};
use reqwest::{
    Url,
    blocking::Client,
    header::{AUTHORIZATION, HeaderValue},
    redirect::Policy,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const LIMIT: usize = 100;
const MAX_OBJECTS: usize = 250_000;
const MAX_PAGE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
struct Page {
    count: usize,
    next: Option<String>,
    results: Vec<Value>,
}

fn id(v: &Value) -> Result<u64> {
    v["id"]
        .as_u64()
        .filter(|n| *n > 0)
        .context("missing or invalid ID")
}
fn str_value(v: &Value) -> Result<String> {
    v.as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .context("missing or invalid string")
}
fn status(v: &Value) -> Result<String> {
    if v.is_object() {
        str_value(&v["value"])
    } else {
        str_value(v)
    }
}
fn address(v: &Value) -> Result<Option<String>> {
    if v.is_null() {
        Ok(None)
    } else {
        str_value(&v["address"]).map(Some)
    }
}

fn collect_pages(mut page: impl FnMut(usize) -> Result<Page>) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total = None;
    loop {
        let p = page(out.len())?;
        let expected = *total.get_or_insert(p.count);
        ensure!(
            expected == p.count && expected <= MAX_OBJECTS,
            "API page count changed or exceeds limit"
        );
        ensure!(
            p.results.len() <= LIMIT && out.len() + p.results.len() <= expected,
            "invalid API page size"
        );
        ensure!(
            p.next.is_none() || !p.results.is_empty(),
            "empty intermediate API page"
        );
        for row in p.results {
            ensure!(seen.insert(id(&row)?), "duplicate API object across pages");
            out.push(row);
        }
        if p.next.is_none() {
            ensure!(
                out.len() == expected,
                "incomplete API result: read {} of {expected}",
                out.len()
            );
            return Ok(out);
        }
        ensure!(
            out.len() < expected,
            "unexpected continuation after final API page"
        );
        // Ignore the server-provided next URL: requests stay on the selected HTTPS origin.
        ensure!(
            !p.next.as_deref().unwrap_or_default().is_empty(),
            "empty continuation URL"
        );
    }
}

struct NetBox {
    base: Url,
    client: Client,
    auth: HeaderValue,
}
impl NetBox {
    fn new(base: &str, token_file: &Path) -> Result<Self> {
        let mut base = Url::parse(base).context("invalid NetBox URL")?;
        ensure!(
            base.scheme() == "https"
                && base.host_str().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none(),
            "NetBox URL must be HTTPS without credentials, query or fragment"
        );
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let token = fs::read_to_string(token_file).context("read token file")?;
        let token = token.trim();
        ensure!(
            !token.is_empty() && token.len() <= 512 && token.bytes().all(|b| b.is_ascii_graphic()),
            "invalid token file"
        );
        let scheme = if token.starts_with("nbt_") {
            "Bearer"
        } else {
            "Token"
        };
        let mut auth = HeaderValue::from_str(&format!("{scheme} {token}"))
            .map_err(|_| anyhow::anyhow!("invalid token header"))?;
        auth.set_sensitive(true);
        let client = Client::builder()
            .timeout(Duration::from_secs(25))
            .connect_timeout(Duration::from_secs(8))
            .redirect(Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self { base, client, auth })
    }
    fn get<T: serde::de::DeserializeOwned>(&self, url: Url) -> Result<T> {
        let mut retries = 0;
        let response = loop {
            let result = self
                .client
                .get(url.clone())
                .header(AUTHORIZATION, self.auth.clone())
                .send();
            let transient = match &result {
                Err(e) => e.is_timeout() || e.is_connect(),
                Ok(r) => {
                    let status = r.status();
                    status.is_server_error()
                        || status.as_u16() == 429
                        || (status.as_u16() == 404 && !r.headers().contains_key("api-version"))
                }
            };
            if transient && retries < 2 {
                retries += 1;
                std::thread::sleep(Duration::from_secs(retries));
                continue;
            }
            let response = result?;
            ensure!(response.status().is_success(), "HTTP {}", response.status());
            break response;
        };
        let mut bytes = Vec::new();
        response.take(MAX_PAGE_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_PAGE_BYTES,
            "API response is too large"
        );
        serde_json::from_slice(&bytes).context("decode NetBox JSON")
    }

    fn rows(&self, path: &str, fields: &str, filter: Option<(&str, &str)>) -> Result<Vec<Value>> {
        collect_pages(|offset| {
            let mut u = self.base.join(path)?;
            u.query_pairs_mut()
                .append_pair("fields", fields)
                .append_pair("ordering", "id")
                .append_pair("limit", &LIMIT.to_string())
                .append_pair("offset", &offset.to_string());
            if let Some((key, val)) = filter {
                u.query_pairs_mut().append_pair(key, val);
            }
            let p: Page = self
                .get(u)
                .with_context(|| format!("GET {path} at offset {offset}"))?;
            ensure!(
                p.next.is_none() || !p.results.is_empty(),
                "empty intermediate API page"
            );
            Ok(p)
        })
        .with_context(|| format!("incomplete snapshot from {path}"))
    }
}

pub(crate) fn baseline_metadata(
    url: &str,
    token: &Path,
    snapshot: &Snapshot,
) -> Result<crate::baseline_inventory::Metadata> {
    use std::collections::BTreeMap;
    let nb = NetBox::new(url, token)?;
    let site = snapshot.site.slug.as_str();
    let assets: BTreeMap<_, _> = nb
        .rows(
            "api/dcim/devices/",
            "id,name,role,status,device_type,primary_ip4",
            Some(("site", site)),
        )?
        .into_iter()
        .map(|v| Ok((id(&v)?, v)))
        .collect::<Result<_>>()?;
    let model_ids = assets
        .values()
        .filter(|v| v["role"]["slug"] == "gpu-server" && v["status"]["value"] == "active")
        .map(|v| id(&v["device_type"]))
        .collect::<Result<BTreeSet<_>>>()?;
    let mut gpu_types = BTreeMap::new();
    for model in model_ids {
        let mut url = nb.base.join(&format!("api/dcim/device-types/{model}/"))?;
        url.query_pairs_mut()
            .append_pair("fields", "id,slug,custom_fields");
        let data: Value = nb
            .get(url)
            .with_context(|| format!("read GPU device type #{model}"))?;
        ensure!(id(&data)? == model, "NetBox returned the wrong device type");
        gpu_types.insert(model, data);
    }
    let tags = nb
        .rows("api/dcim/cables/", "id,status,tags", Some(("site", site)))?
        .into_iter()
        .map(|v| Ok((i64::try_from(id(&v)?)?, v)))
        .collect::<Result<_>>()?;
    Ok(crate::baseline_inventory::Metadata {
        assets,
        gpu_types,
        tags,
    })
}

pub(crate) fn snapshot(url: &str, site: &str, token_file: &Path) -> Result<Snapshot> {
    ensure!(
        !site.is_empty()
            && site
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "invalid site slug"
    );
    let nb = NetBox::new(url, token_file)?;
    let sites = nb.rows("api/dcim/sites/", "id,slug", Some(("slug", site)))?;
    ensure!(
        sites.len() == 1 && sites[0]["slug"].as_str() == Some(site),
        "site filter did not return the exact requested site"
    );
    let s = Site {
        id: id(&sites[0])?,
        slug: site.to_owned(),
    };
    let mut devices = Vec::new();
    for r in nb.rows(
        "api/dcim/devices/",
        "id,name,site,role,status,primary_ip4,oob_ip",
        Some(("site", site)),
    )? {
        ensure!(
            id(&r["site"])? == s.id,
            "device filter returned an object from another site"
        );
        devices.push(Device {
            id: id(&r)?,
            name: str_value(&r["name"])?,
            role: str_value(&r["role"]["slug"])?,
            status: status(&r["status"])?,
            primary_ip4: address(&r["primary_ip4"])?,
            oob_ip: address(&r["oob_ip"])?,
        });
    }
    ensure!(!devices.is_empty(), "site returned no devices");
    let dev: BTreeSet<_> = devices.iter().map(|d| d.id).collect();
    let mut interfaces = Vec::new();
    // Related tables use compact projections. Retain only IDs reachable from the requested site.
    for r in nb.rows("api/dcim/interfaces/", "id,device,name,enabled", None)? {
        let d = id(&r["device"])?;
        if dev.contains(&d) {
            interfaces.push(Interface {
                id: id(&r)?,
                device_id: d,
                name: str_value(&r["name"])?,
                enabled: r["enabled"]
                    .as_bool()
                    .context("missing interface enabled state")?,
            });
        }
    }
    let ids: BTreeSet<_> = interfaces.iter().map(|i| i.id).collect();
    let mut ips = Vec::new();
    for r in nb.rows(
        "api/ipam/ip-addresses/",
        "id,address,assigned_object_type,assigned_object_id,vrf,status,tags",
        None,
    )? {
        let Some(interface) = r["assigned_object_id"].as_u64().filter(|n| ids.contains(n)) else {
            continue;
        };
        if r["assigned_object_type"].as_str() != Some("dcim.interface") {
            continue;
        }
        ips.push(Address {
            id: id(&r)?,
            address: str_value(&r["address"])?,
            interface_id: interface,
            status: Some(status(&r["status"])?),
            tags: r["tags"]
                .as_array()
                .context("missing IP tags")?
                .iter()
                .map(|t| str_value(&t["slug"]))
                .collect::<Result<Vec<_>>>()?,
            vrf_id: if r["vrf"].is_null() {
                None
            } else {
                Some(id(&r["vrf"])?)
            },
        });
    }
    let mut cables = Vec::new();
    for r in nb.rows(
        "api/dcim/cables/",
        "id,status,a_terminations,b_terminations",
        None,
    )? {
        let a = terms(&r["a_terminations"])?;
        let b = terms(&r["b_terminations"])?;
        if a.iter()
            .chain(&b)
            .any(|e| e.kind == "dcim.interface" && ids.contains(&e.id))
        {
            cables.push(Cable {
                id: i64::try_from(id(&r)?)?,
                status: status(&r["status"])?,
                a,
                b,
            });
        }
    }
    let s = Snapshot {
        schema_version: 1,
        captured_at_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        site: s,
        devices,
        interfaces,
        ip_addresses: ips,
        cables,
    };
    s.validate()?;
    Ok(s)
}

fn terms(v: &Value) -> Result<Vec<Termination>> {
    v.as_array()
        .context("missing cable terminations")?
        .iter()
        .map(|r| {
            Ok(Termination {
                kind: str_value(&r["object_type"])?,
                id: r["object_id"].as_u64().context("missing termination ID")?,
            })
        })
        .collect()
}

fn breakout_links(
    cable: &Cable,
    rows: &[Value],
    interfaces: &std::collections::BTreeMap<u64, Value>,
) -> Result<Vec<Cable>> {
    let ([local], [_, _]) = (cable.a.as_slice(), cable.b.as_slice()) else {
        anyhow::bail!("invalid breakout terminations: #{}", cable.id);
    };
    ensure!(
        local.kind == "dcim.interface" && cable.b.iter().all(|p| p.kind == "dcim.interface"),
        "breakout must connect interfaces"
    );
    let parent = interfaces
        .get(&local.id)
        .context("missing breakout parent")?;
    ensure!(
        parent["channels"] == 2 && parent["enabled"] == true,
        "invalid breakout parent channels"
    );
    let positions = rows
        .iter()
        .map(|r| {
            Ok((
                (
                    r["cable_end"].as_str().context("missing cable end")?,
                    r["connector"].as_u64().context("missing connector")?,
                ),
                r,
            ))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    ensure!(
        rows.len() == 3 && positions.len() == 3,
        "invalid breakout connector count"
    );
    let local_position = positions
        .get(&("A", 1))
        .context("missing breakout parent connector")?;
    ensure!(
        local_position["termination_id"].as_u64() == Some(local.id)
            && local_position["positions"] == serde_json::json!([1, 2]),
        "breakout parent positions differ"
    );
    let children: Vec<_> = interfaces
        .values()
        .filter(|i| i["parent"]["id"].as_u64() == Some(local.id) && !i["channel_id"].is_null())
        .collect();
    ensure!(children.len() == 2, "expected two breakout child channels");
    let mut links = Vec::with_capacity(2);
    for side in 1..=2 {
        let at = positions
            .get(&("B", side))
            .context("missing breakout peer connector")?;
        let peer = at["termination_id"]
            .as_u64()
            .context("missing breakout peer ID")?;
        ensure!(
            at["positions"] == serde_json::json!([1]) && cable.b.iter().any(|b| b.id == peer),
            "breakout peer position changed"
        );
        let channel = children
            .iter()
            .find(|i| i["channel_id"].as_u64() == Some(side))
            .context("missing breakout channel")?;
        ensure!(channel["enabled"] == true, "disabled breakout child");
        // The signed key matches the prior publisher's per-channel membership.
        let channel_key = cable
            .id
            .checked_mul(10)
            .and_then(|v| v.checked_add(side as i64))
            .and_then(i64::checked_neg)
            .context("invalid breakout cable ID")?;
        links.push(Cable {
            id: channel_key,
            status: cable.status.clone(),
            a: vec![Termination {
                kind: "dcim.interface".into(),
                id: id(channel)?,
            }],
            b: vec![Termination {
                kind: "dcim.interface".into(),
                id: peer,
            }],
        });
    }
    ensure!(
        links[0].b[0].id != links[1].b[0].id,
        "duplicate breakout peer connector"
    );
    Ok(links)
}

pub(crate) fn approved_snapshot(
    url: &str,
    site: &str,
    token: &Path,
    policy: &crate::policy::Policy,
    cable_tag: &str,
) -> Result<(Snapshot, crate::baseline_inventory::Metadata)> {
    use std::collections::BTreeMap;
    let nb = NetBox::new(url, token)?;
    let sites = nb.rows("api/dcim/sites/", "id,slug", Some(("slug", site)))?;
    ensure!(
        sites.len() == 1 && sites[0]["slug"] == site,
        "wrong NetBox site"
    );
    let s = Site {
        id: id(&sites[0])?,
        slug: site.into(),
    };
    let assets = nb
        .rows(
            "api/dcim/devices/",
            "id,name,role,status,device_type,primary_ip4,oob_ip,site",
            Some(("site", site)),
        )?
        .into_iter()
        .map(|d| Ok((id(&d)?, d)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let devices = assets
        .values()
        .map(|d| {
            ensure!(id(&d["site"])? == s.id, "device outside approved site");
            Ok(Device {
                id: id(d)?,
                name: str_value(&d["name"])?,
                role: str_value(&d["role"]["slug"])?,
                status: status(&d["status"])?,
                primary_ip4: address(&d["primary_ip4"])?,
                oob_ip: address(&d["oob_ip"])?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let rows = nb
        .rows(
            "api/dcim/interfaces/",
            "id,device,name,enabled,custom_fields,parent,channels,channel_id",
            Some(("site", site)),
        )?
        .into_iter()
        .map(|p| Ok((id(&p)?, p)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let interfaces = rows
        .values()
        .map(|p| {
            let device_id = id(&p["device"])?;
            ensure!(
                assets.contains_key(&device_id),
                "interface outside approved site"
            );
            Ok(Interface {
                id: id(p)?,
                device_id,
                name: str_value(&p["name"])?,
                enabled: p["enabled"]
                    .as_bool()
                    .context("missing interface enabled state")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for (name, alias) in &policy.interface_aliases {
        let (host, interface) = crate::baseline_ports::endpoint(name)?;
        let Some(guid) = interface.strip_suffix("_1").filter(|g| {
            g.len() == 16
                && g.bytes().all(|c| c.is_ascii_hexdigit())
                && host.to_ascii_uppercase().starts_with("B300-")
        }) else {
            continue;
        };
        let p = rows
            .get(&alias.interface_id)
            .context("missing GUID interface")?;
        let reported = p["custom_fields"]["node_guid"]
            .as_str()
            .unwrap_or_default()
            .replace(':', "")
            .to_ascii_lowercase();
        ensure!(
            reported
                .strip_prefix("0x")
                .unwrap_or(&reported)
                .eq_ignore_ascii_case(guid),
            "NetBox HCA GUID changed: {name}"
        );
    }
    let mut cables = Vec::new();
    let mut tags = BTreeMap::new();
    for c in nb.rows(
        "api/dcim/cables/",
        "id,status,tags,profile,a_terminations,b_terminations",
        Some(("site", site)),
    )? {
        let base = Cable {
            id: i64::try_from(id(&c)?)?,
            status: status(&c["status"])?,
            a: terms(&c["a_terminations"])?,
            b: terms(&c["b_terminations"])?,
        };
        let links = if c["profile"]["value"] == "breakout-1c2p-2c1p"
            && c["tags"]
                .as_array()
                .is_some_and(|a| a.iter().any(|t| t["slug"] == cable_tag))
        {
            let connectors = nb.rows(
                "api/dcim/cable-terminations/",
                "id,cable,cable_end,connector,positions,termination_id",
                Some(("cable_id", &base.id.to_string())),
            )?;
            ensure!(
                connectors
                    .iter()
                    .all(|t| t["cable"].as_i64() == Some(base.id)),
                "wrong cable returned for breakout connector"
            );
            breakout_links(&base, &connectors, &rows)
                .with_context(|| format!("expand breakout cable #{}", base.id))?
        } else {
            vec![base]
        };
        for cable in links {
            ensure!(
                tags.insert(cable.id, c.clone()).is_none(),
                "duplicate cable key"
            );
            cables.push(cable);
        }
    }
    let model_ids = assets
        .values()
        .filter(|v| v["role"]["slug"] == "gpu-server" && v["status"]["value"] == "active")
        .map(|v| id(&v["device_type"]))
        .collect::<Result<BTreeSet<_>>>()?;
    let mut gpu_types = BTreeMap::new();
    for model in model_ids {
        let mut u = nb.base.join(&format!("api/dcim/device-types/{model}/"))?;
        u.query_pairs_mut()
            .append_pair("fields", "id,slug,custom_fields");
        let v: Value = nb.get(u)?;
        ensure!(id(&v)? == model, "wrong GPU device type");
        gpu_types.insert(model, v);
    }
    let snapshot = Snapshot {
        schema_version: 1,
        captured_at_unix: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        site: s,
        devices,
        interfaces,
        ip_addresses: Vec::new(),
        cables,
    };
    snapshot.validate()?;
    Ok((
        snapshot,
        crate::baseline_inventory::Metadata {
            assets,
            gpu_types,
            tags,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn breakout_membership_tracks_connector_ids() -> Result<()> {
        let interface = |id| Termination {
            id,
            kind: "dcim.interface".into(),
        };
        let cable = Cable {
            id: 200,
            status: "connected".into(),
            a: vec![interface(10)],
            b: vec![interface(21), interface(22)],
        };
        let interfaces = [
            (10, json!({"id":10, "channels":2, "enabled":true})),
            (
                11,
                json!({"id":11, "parent":{"id":10}, "channel_id":1, "enabled":true}),
            ),
            (
                12,
                json!({"id":12, "parent":{"id":10}, "channel_id":2, "enabled":true}),
            ),
        ]
        .into();
        let mut rows = [
            json!({"cable_end":"A", "connector":1, "positions":[1,2], "termination_id":10}),
            json!({"cable_end":"B", "connector":1, "positions":[1], "termination_id":22}),
            json!({"cable_end":"B", "connector":2, "positions":[1], "termination_id":21}),
        ];
        let links = breakout_links(&cable, &rows, &interfaces)?;
        assert_eq!(
            (links[0].id, links[0].a[0].id, links[0].b[0].id),
            (-2001, 11, 22)
        );
        assert_eq!(
            (links[1].id, links[1].a[0].id, links[1].b[0].id),
            (-2002, 12, 21)
        );

        rows[2]["termination_id"] = json!(22);
        assert!(breakout_links(&cable, &rows, &interfaces).is_err());
        Ok(())
    }

    #[test]
    fn duplicate_ids_stop_snapshot() {
        assert!(
            collect_pages(|offset| Ok(Page {
                count: 2,
                next: (offset == 0).then(|| "next".into()),
                results: vec![json!({"id":1})]
            }))
            .is_err()
        );
    }
    #[test]
    fn final_page_must_match_count() {
        assert!(
            collect_pages(|_| Ok(Page {
                count: 2,
                next: None,
                results: vec![json!({"id":1})]
            }))
            .is_err()
        );
    }
    #[test]
    fn follows_offsets_without_following_supplied_url() -> Result<()> {
        let rows = collect_pages(|offset| {
            Ok(Page {
                count: 2,
                next: (offset == 0).then(|| "https://untrusted.invalid/".into()),
                results: vec![json!({"id":offset+1})],
            })
        })?;
        assert_eq!(rows.len(), 2);
        Ok(())
    }
}
