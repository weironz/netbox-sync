use crate::{
    model::{Address, Device, Snapshot, host_address},
    policy::Policy,
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_yaml_ng::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize)]
pub(crate) struct Issue {
    host: String,
    field: &'static str,
    expected: String,
    observed: Option<String>,
}
#[derive(Serialize)]
pub(crate) struct LinkReport {
    a: String,
    b: String,
    review: String,
    state: &'static str,
}
#[derive(Serialize)]
pub(crate) struct Report {
    schema_version: u32,
    pub site: String,
    pub netbox_site: String,
    pub expected_devices: usize,
    pub equivalent_devices: usize,
    pub candidate_written: bool,
    pub issues: Vec<Issue>,
    resolved_devices: Vec<ResolvedDevice>,
    untracked_devices: Vec<String>,
    link_summary: BTreeMap<&'static str, usize>,
    links: Vec<LinkReport>,
}

#[derive(Serialize)]
struct ResolvedDevice {
    host: String,
    netbox_id: u64,
    netbox_name: String,
    used_alias: bool,
    business_ip: Option<String>,
    bmc_ip: Option<String>,
}

fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .with_context(|| format!("missing inventory field {k}"))
}
fn address_issue(
    host: &str,
    name: &'static str,
    expected: &str,
    observed: Option<&str>,
    issues: &mut Vec<Issue>,
) -> Result<()> {
    let expected_ip =
        host_address(expected).with_context(|| format!("invalid {name} for {host}"))?;
    let observed_ip = observed.map(host_address).transpose()?;
    if observed_ip == Some(expected_ip) {
        return Ok(());
    }
    issues.push(Issue {
        host: host.to_owned(),
        field: name,
        expected: expected.to_owned(),
        observed: observed.map(str::to_owned),
    });
    Ok(())
}

fn link_report(
    doc: &Value,
    snapshot: &Snapshot,
    aliases: &BTreeMap<u64, String>,
) -> Result<Vec<LinkReport>> {
    let Some(baseline) = doc.get("port_baseline") else {
        return Ok(Vec::new());
    };
    let links = baseline
        .get("connections")
        .and_then(Value::as_sequence)
        .context("invalid port_baseline.connections")?;
    let names: BTreeMap<_, _> = snapshot
        .devices
        .iter()
        .map(|d| (d.id, aliases.get(&d.id).unwrap_or(&d.name).as_str()))
        .collect();
    let endpoints: BTreeMap<_, _> = snapshot
        .interfaces
        .iter()
        .map(|i| {
            (
                i.id,
                format!("{}/{}", names[&i.device_id], i.name).to_lowercase(),
            )
        })
        .collect();
    let known: BTreeSet<_> = endpoints.values().collect();
    let mut pairs: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
    let mut peers: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for c in &snapshot.cables {
        let ([a], [b]) = (c.a.as_slice(), c.b.as_slice()) else {
            continue;
        };
        if a.kind != "dcim.interface" || b.kind != "dcim.interface" {
            continue;
        }
        let (Some(a), Some(b)) = (
            endpoints.get(&a.id).map(String::as_str),
            endpoints.get(&b.id).map(String::as_str),
        ) else {
            continue;
        };
        let p = if a <= b { (a, b) } else { (b, a) };
        pairs.entry(p).or_default().push(&c.status);
        if matches!(c.status.as_str(), "active" | "connected") {
            peers.entry(a).or_default().insert(b);
            peers.entry(b).or_default().insert(a);
        }
    }
    links
        .iter()
        .map(|l| {
            let a = field(l, "a")?;
            let b = field(l, "b")?;
            let an = a.to_lowercase();
            let bn = b.to_lowercase();
            let (ak, bk) = if an <= bn {
                (an.as_str(), bn.as_str())
            } else {
                (bn.as_str(), an.as_str())
            };
            let statuses = pairs.get(&(ak, bk));
            let another =
                |x: &str, y: &str| peers.get(x).is_some_and(|p| p.iter().any(|q| *q != y));
            let state = match statuses.map(Vec::as_slice) {
                Some(["active" | "connected"]) if !another(ak, bk) && !another(bk, ak) => {
                    "exact_active"
                }
                Some(["active" | "connected"]) => "ambiguous_cable",
                Some([_]) => "exact_nonactive",
                Some(_) => "ambiguous_cable",
                None if another(ak, bk) || another(bk, ak) => "different_active_peer",
                None if !known.contains(&an) || !known.contains(&bn) => "interface_missing",
                None => "no_direct_cable",
            };
            Ok(LinkReport {
                a: a.to_owned(),
                b: b.to_owned(),
                review: l
                    .get("review")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified")
                    .to_owned(),
                state,
            })
        })
        .collect()
}

type Aliases<'a> = (BTreeMap<String, &'a Device>, BTreeMap<u64, String>);

fn resolve_aliases<'a>(
    policy: Option<&Policy>,
    snapshot: &'a Snapshot,
    inventory_names: &BTreeSet<String>,
    known: &BTreeMap<String, &'a Device>,
) -> Result<Aliases<'a>> {
    let mut aliases = BTreeMap::new();
    let mut names = BTreeMap::new();
    if let Some(policy) = policy {
        let by_id: BTreeMap<_, _> = snapshot.devices.iter().map(|d| (d.id, d)).collect();
        for (host, expected) in &policy.aliases {
            let key = host.to_lowercase();
            ensure!(
                inventory_names.contains(&key),
                "alias host {host} is not in inventory"
            );
            let d = by_id.get(&expected.device_id).copied().with_context(|| {
                format!(
                    "alias device ID {} is missing at this site",
                    expected.device_id
                )
            })?;
            ensure!(
                d.name == expected.netbox_name,
                "alias {host} points to an unexpected NetBox name"
            );
            ensure!(
                known.get(&key).is_none_or(|direct| direct.id == d.id),
                "alias {host} conflicts with a directly matching device"
            );
            aliases.insert(key, d);
            names.insert(d.id, host.clone());
        }
    }
    Ok((aliases, names))
}

fn select_business_ip<'a>(
    host: &str,
    d: &'a Device,
    tag: Option<&str>,
    addresses: &[(&'a Address, bool)],
    issues: &mut Vec<Issue>,
) -> Result<Option<&'a str>> {
    let Some(tag) = tag else {
        return Ok(d.primary_ip4.as_deref());
    };
    let matches: Vec<_> = addresses
        .iter()
        .filter(|(a, _)| a.tags.iter().any(|t| t == tag))
        .collect();
    if let [(a, enabled)] = matches.as_slice()
        && *enabled
        && a.status.as_deref() == Some("active")
        && host_address(&a.address)?.is_ipv4()
    {
        return Ok(Some(&a.address));
    }
    issues.push(Issue {
        host: host.to_owned(),
        field: "business_tag",
        expected: format!("one active IPv4 tagged {tag} on an enabled interface"),
        observed: Some(format!("{} tagged addresses", matches.len())),
    });
    Ok(None)
}

pub(crate) fn build(
    input: &str,
    snapshot: &Snapshot,
    mapped_site: Option<&str>,
    policy: Option<&Policy>,
) -> Result<(Report, Option<String>)> {
    snapshot.validate()?;
    let doc: Value = serde_yaml_ng::from_str(input).context("parse inventory YAML")?;
    ensure!(
        doc.get("version").and_then(Value::as_u64) == Some(1),
        "unsupported monitoring inventory version"
    );
    let site = field(&doc, "site")?.to_owned();
    if let Some(p) = policy {
        p.validate(&site, &snapshot.site.slug)?;
        ensure!(
            mapped_site.is_none_or(|m| m == p.netbox_site),
            "--netbox-site conflicts with the policy"
        );
    }
    let target_site = policy
        .map(|p| p.netbox_site.as_str())
        .or(mapped_site)
        .unwrap_or(&site);
    ensure!(
        snapshot.site.slug == target_site,
        "NetBox site does not match inventory; use --netbox-site for an explicit mapping"
    );
    let known: BTreeMap<_, _> = snapshot
        .devices
        .iter()
        .map(|d| (d.name.to_lowercase(), d))
        .collect();
    let inv = doc
        .get("devices")
        .and_then(Value::as_sequence)
        .context("invalid inventory devices")?;
    let inventory_names = inv
        .iter()
        .map(|r| Ok(field(r, "host")?.to_lowercase()))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        inventory_names.len() == inv.len(),
        "duplicate inventory device names"
    );
    let (aliases, alias_names) = resolve_aliases(policy, snapshot, &inventory_names, &known)?;
    let links = link_report(&doc, snapshot, &alias_names)?;
    let mut link_summary = BTreeMap::new();
    for l in &links {
        *link_summary.entry(l.state).or_insert(0) += 1;
    }
    let interfaces: BTreeMap<_, _> = snapshot.interfaces.iter().map(|i| (i.id, i)).collect();
    let mut addresses: BTreeMap<u64, Vec<(&Address, bool)>> = BTreeMap::new();
    for a in &snapshot.ip_addresses {
        let i = interfaces[&a.interface_id];
        addresses
            .entry(i.device_id)
            .or_default()
            .push((a, i.enabled));
    }
    let mut issues = Vec::new();
    let mut matched = BTreeSet::new();
    let mut resolved_devices = Vec::new();
    let mut expected_devices = 0;
    let mut equivalent_devices = 0;
    for row in inv {
        let host = field(row, "host")?.to_owned();
        let key = host.to_lowercase();
        let selected_alias = aliases.get(&key).copied();
        let selected = selected_alias.or_else(|| known.get(&key).copied());
        if let Some(d) = selected {
            ensure!(
                matched.insert(d.id),
                "more than one inventory host maps to NetBox device {}",
                d.id
            );
        }
        let active = row
            .get("active")
            .map(|v| v.as_bool().context("invalid inventory active flag"))
            .transpose()?
            .unwrap_or(true);
        if !active {
            continue;
        }
        expected_devices += 1;
        let Some(d) = selected else {
            issues.push(Issue {
                host,
                field: "device",
                expected: "present".into(),
                observed: None,
            });
            continue;
        };
        let start = issues.len();
        let role = field(row, "role")?.to_owned();
        if d.role != role {
            issues.push(Issue {
                host: host.clone(),
                field: "role",
                expected: role.clone(),
                observed: Some(d.role.clone()),
            });
        }
        if d.status != "active" {
            issues.push(Issue {
                host: host.clone(),
                field: "status",
                expected: "active".into(),
                observed: Some(d.status.clone()),
            });
        }
        let assigned = addresses.get(&d.id).map(Vec::as_slice).unwrap_or_default();
        let tag = policy
            .and_then(|p| p.business_ip_tag_by_role.get(&role))
            .map(String::as_str);
        let biz = select_business_ip(&host, d, tag, assigned, &mut issues)?;
        let bmc = d.oob_ip.as_deref();
        if policy.is_some_and(|p| p.require_oob_roles.contains(&role)) {
            let ip = bmc.map(host_address).transpose()?;
            let mut valid = 0;
            if let Some(ip) = ip.filter(|i| i.is_ipv4()) {
                for (a, enabled) in assigned {
                    if *enabled
                        && a.status.as_deref() == Some("active")
                        && host_address(&a.address)? == ip
                    {
                        valid += 1;
                    }
                }
            }
            if valid != 1 {
                issues.push(Issue {
                    host: host.clone(),
                    field: "oob",
                    expected: "one active assigned IPv4 matching the device OOB IP".into(),
                    observed: bmc.map(str::to_owned),
                });
            }
        }
        for (field, actual) in [("primary", biz), ("bmc", bmc)] {
            if field == "primary" && tag.is_some() && biz.is_none() {
                continue;
            }
            if let Some(v) = row.get(field) {
                let expected = v
                    .as_str()
                    .with_context(|| format!("invalid {field} for {host}"))?;
                address_issue(&host, field, expected, actual, &mut issues)?;
            }
        }
        if start == issues.len() {
            equivalent_devices += 1;
        }
        resolved_devices.push(ResolvedDevice {
            host,
            netbox_id: d.id,
            netbox_name: d.name.clone(),
            used_alias: selected_alias.is_some(),
            business_ip: biz.map(host_address).transpose()?.map(|ip| ip.to_string()),
            bmc_ip: bmc.map(host_address).transpose()?.map(|ip| ip.to_string()),
        });
    }
    ensure!(expected_devices > 0, "inventory has no active devices");
    let untracked_devices = known
        .into_values()
        .filter(|d| !matched.contains(&d.id))
        .map(|d| d.name.clone())
        .collect();
    let candidate = issues.is_empty().then(|| input.to_owned());
    let report = Report {
        schema_version: 1,
        site,
        netbox_site: snapshot.site.slug.clone(),
        expected_devices,
        equivalent_devices,
        candidate_written: candidate.is_some(),
        issues,
        resolved_devices,
        untracked_devices,
        link_summary,
        links,
    };
    Ok((report, candidate))
}
