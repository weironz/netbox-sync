use crate::model::{Snapshot, host_address};
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
    untracked_devices: Vec<String>,
    link_summary: BTreeMap<&'static str, usize>,
    links: Vec<LinkReport>,
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
) -> Result<Option<String>> {
    let expected_ip =
        host_address(expected).with_context(|| format!("invalid {name} for {host}"))?;
    let observed_ip = observed.map(host_address).transpose()?;
    if observed_ip == Some(expected_ip) {
        return Ok(Some(expected_ip.to_string()));
    }
    issues.push(Issue {
        host: host.to_owned(),
        field: name,
        expected: expected.to_owned(),
        observed: observed.map(str::to_owned),
    });
    Ok(None)
}

fn link_report(doc: &Value, snapshot: &Snapshot) -> Result<Vec<LinkReport>> {
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
        .map(|d| (d.id, d.name.as_str()))
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

pub(crate) fn build(
    input: &str,
    snapshot: &Snapshot,
    mapped_site: Option<&str>,
) -> Result<(Report, Option<String>)> {
    snapshot.validate()?;
    let mut doc: Value = serde_yaml_ng::from_str(input).context("parse inventory YAML")?;
    ensure!(
        doc.get("version").and_then(Value::as_u64) == Some(1),
        "unsupported monitoring inventory version"
    );
    let site = field(&doc, "site")?.to_owned();
    ensure!(
        snapshot.site.slug == mapped_site.unwrap_or(&site),
        "NetBox site does not match inventory; use --netbox-site for an explicit mapping"
    );
    let links = link_report(&doc, snapshot)?;
    let mut link_summary = BTreeMap::new();
    for l in &links {
        *link_summary.entry(l.state).or_insert(0) += 1;
    }
    let known: BTreeMap<_, _> = snapshot
        .devices
        .iter()
        .map(|d| (d.name.to_lowercase(), d))
        .collect();
    let devices = doc
        .get_mut("devices")
        .and_then(Value::as_sequence_mut)
        .context("invalid inventory devices")?;
    let mut issues = Vec::new();
    let mut seen = BTreeSet::new();
    let mut expected_devices = 0;
    let mut equivalent_devices = 0;
    for row in devices {
        let host = field(row, "host")?.to_owned();
        let key = host.to_lowercase();
        ensure!(
            seen.insert(key.clone()),
            "duplicate inventory device {host}"
        );
        let active = row
            .get("active")
            .map(|v| v.as_bool().context("invalid inventory active flag"))
            .transpose()?
            .unwrap_or(true);
        if !active {
            continue;
        }
        expected_devices += 1;
        let Some(d) = known.get(&key) else {
            issues.push(Issue {
                host,
                field: "device",
                expected: "present".into(),
                observed: None,
            });
            continue;
        };
        let start = issues.len();
        let role = field(row, "role")?;
        if d.role != role {
            issues.push(Issue {
                host: host.clone(),
                field: "role",
                expected: role.into(),
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
        for (name, actual) in [
            ("primary", d.primary_ip4.as_deref()),
            ("bmc", d.oob_ip.as_deref()),
        ] {
            if let Some(v) = row.get(name) {
                let expected = v
                    .as_str()
                    .with_context(|| format!("invalid {name} for {host}"))?;
                if let Some(normalized) = address_issue(&host, name, expected, actual, &mut issues)?
                {
                    row[name] = Value::String(normalized);
                }
            }
        }
        if start == issues.len() {
            equivalent_devices += 1;
        }
    }
    ensure!(expected_devices > 0, "inventory has no active devices");
    let untracked_devices = known
        .into_iter()
        .filter(|(k, _)| !seen.contains(k))
        .map(|(_, v)| v.name.clone())
        .collect();
    let candidate = if issues.is_empty() {
        Some(serde_yaml_ng::to_string(&doc)?)
    } else {
        None
    };
    let report = Report {
        schema_version: 1,
        site,
        netbox_site: snapshot.site.slug.clone(),
        expected_devices,
        equivalent_devices,
        candidate_written: candidate.is_some(),
        issues,
        untracked_devices,
        link_summary,
        links,
    };
    Ok((report, candidate))
}
