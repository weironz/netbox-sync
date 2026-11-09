use crate::model::*;
use anyhow::{Context, Result, bail, ensure};
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
            let response = self
                .client
                .get(u)
                .header(AUTHORIZATION, self.auth.clone())
                .send()
                .with_context(|| format!("GET {path} at offset {offset}"))?;
            if !response.status().is_success() {
                bail!("GET {path} returned HTTP {}", response.status());
            }
            let mut buf = Vec::new();
            response
                .take(MAX_PAGE_BYTES + 1)
                .read_to_end(&mut buf)
                .context("read API page")?;
            ensure!(buf.len() as u64 <= MAX_PAGE_BYTES, "API page too large");
            let p: Page =
                serde_json::from_slice(&buf).with_context(|| format!("decode {path} page"))?;
            ensure!(
                p.next.is_none() || !p.results.is_empty(),
                "empty intermediate API page"
            );
            Ok(p)
        })
        .with_context(|| format!("incomplete snapshot from {path}"))
    }
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
    let terms = |v: &Value| -> Result<Vec<Termination>> {
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
    };
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
                id: id(&r)?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
