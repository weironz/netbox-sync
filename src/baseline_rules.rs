use crate::{
    approvals::{map_field, text_field},
    baseline_inventory::Baseline,
    baseline_ports::{Labels, ROLES, labels},
    model::host_address,
    render::Files,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value as Json, json};
use serde_yaml_ng::{Mapping, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const COUNTS: [(&str, &str); 5] = [
    ("gpu-server", "gpu_servers"),
    ("cpu-server", "cpu_servers"),
    ("ib-switch", "ib_switches"),
    ("ethernet-switch", "ethernet_switches"),
    ("firewall", "firewalls"),
];
const COMPONENTS: [(&str, &str); 5] = [
    ("gpus", "gpu_count"),
    ("nvme", "nvme_count"),
    ("dimms", "dimm_count"),
    ("fans", "fan_count"),
    ("cpus", "cpu_count"),
];
const BEHAVIOR: &str = include_str!("baseline_behavior.json");

fn expand_behavior(value: &mut Json, replacements: &[(&str, &str)]) {
    match value {
        Json::String(text) => {
            for (key, replacement) in replacements {
                *text = text.replace(key, replacement);
            }
        }
        Json::Array(items) => {
            for item in items {
                expand_behavior(item, replacements);
            }
        }
        Json::Object(fields) => {
            for item in fields.values_mut() {
                expand_behavior(item, replacements);
            }
        }
        _ => {}
    }
}

pub(crate) fn job(job: &str) -> Result<(&str, Option<u16>, Option<&str>)> {
    match job {
        "b300-redfish" | "cpu-redfish" => Ok(("bmc", None, None)),
        "biz-ping" | "q3400-snmp" | "sonic-snmp" | "fortigate-snmp" => Ok(("primary", None, None)),
        "node" => Ok(("primary", Some(9100), Some("host_metrics"))),
        "gpu-smi" | "dcgm" => Ok(("primary", Some(9400), Some("gpu_runtime"))),
        _ => anyhow::bail!("unsupported monitoring job: {job}"),
    }
}
fn positive(row: &Mapping, key: &str) -> Result<u64> {
    row.get(key)
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
        .with_context(|| format!("missing positive {key}"))
}
fn seq_field<'a>(row: &'a Mapping, key: &str) -> Result<&'a Vec<Value>> {
    row.get(key)
        .and_then(Value::as_sequence)
        .with_context(|| format!("expected sequence: {key}"))
}
fn constant(record: &str, n: u64, labels: Option<Labels>) -> Json {
    let mut row = json!({"record":record,"expr":format!("vector({n})")});
    if let Some(labels) = labels {
        row["labels"] = json!(labels);
    }
    row
}
fn fixed_tail(behavior: &Json, k: &str) -> Result<Vec<Json>> {
    Ok(behavior[k][0]["rules"]
        .as_array()
        .context("missing rule templates")?
        .clone())
}

pub(crate) fn render(b: &Baseline, mut fleet: Json) -> Result<(Files, BTreeMap<String, u64>)> {
    let site = text_field(&b.config, "site")?;
    let roles = map_field(&b.config, "roles")?;
    let hardware = map_field(&b.config, "hardware_profiles")?;
    let fabric = map_field(&b.config, "fabric_profiles")?;
    let target_labels = map_field(&b.config, "target_labels")?;
    let mut seen_hosts = BTreeSet::new();
    let mut addresses: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut logical_checks = BTreeSet::new();
    ensure!(
        roles.len() == COUNTS.len() && COUNTS.iter().all(|(r, _)| roles.contains_key(*r)),
        "unknown or missing device role"
    );
    for role in roles.values() {
        let role = role.as_mapping().context("invalid role configuration")?;
        ensure!(
            role.len() == 2 && !text_field(role, "group")?.is_empty(),
            "invalid role fields"
        );
        let mut unique = BTreeSet::new();
        for j in seq_field(role, "checks")? {
            let j = j.as_str().context("invalid role check")?;
            job(j)?;
            ensure!(unique.insert(j), "duplicate role check");
            logical_checks.insert(j);
        }
        ensure!(!unique.is_empty(), "role needs a monitoring check");
    }
    ensure!(
        logical_checks.len() == target_labels.len()
            && logical_checks
                .iter()
                .all(|j| target_labels.contains_key(*j)),
        "role checks and target label policy differ"
    );
    for profile in hardware.values() {
        let profile = profile.as_mapping().context("invalid hardware profile")?;
        ensure!(
            profile.len() == COMPONENTS.len(),
            "unexpected hardware profile key"
        );
        for (key, _) in COMPONENTS {
            positive(profile, key)?;
        }
    }
    for profile in fabric.values() {
        let profile = profile.as_mapping().context("invalid fabric profile")?;
        ensure!(!profile.is_empty(), "empty fabric profile");
        for (peer, n) in profile {
            let peer = peer.as_str().context("invalid fabric peer")?;
            ensure!(
                !peer.is_empty()
                    && peer
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                    && n.as_u64().is_some_and(|i| i > 0),
                "invalid fabric peer"
            );
        }
    }
    let mut counts: BTreeMap<String, u64> =
        COUNTS.iter().map(|(_, n)| (n.to_string(), 0)).collect();
    let mut device_rules = Vec::new();
    let mut expected_targets = Vec::new();
    let mut gpu_sizes = Vec::new();
    let mut ib_links = 0_u64;
    for d in seq_field(&b.config, "devices")? {
        let d = d.as_mapping().context("invalid active device")?;
        let host = text_field(d, "host")?;
        let role = text_field(d, "role")?;
        ensure!(
            host.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                && !host.is_empty()
                && seen_hosts.insert(host.to_lowercase()),
            "invalid or duplicate device: {host}"
        );
        let label = COUNTS
            .iter()
            .find(|(r, _)| *r == role)
            .context("unknown inventory role")?
            .1;
        *counts.get_mut(label).context("missing role count")? += 1;
        for j in seq_field(map_field(roles, role)?, "checks")? {
            let j = j.as_str().context("invalid role check")?;
            let (addr, port, feature) = job(j)?;
            let ip = text_field(d, addr)?;
            host_address(ip)?;
            let endpoint = port.map_or_else(|| ip.into(), |p| format!("{ip}:{p}"));
            ensure!(
                addresses.entry(j).or_default().insert(endpoint.clone()),
                "duplicate endpoint for {j}"
            );
            let mut rule = constant(
                "monitoring:expected:target",
                1,
                Some(labels([
                    ("target_job", j),
                    ("instance", &endpoint),
                    ("host", host),
                    ("role", role),
                ])),
            );
            if let Some(name) = feature {
                rule["expr"] = json!(format!(
                    "vector(1) and on() (greenstor:feature_enabled{{feature=\"{name}\"}} == 1)"
                ));
            }
            expected_targets.push(rule);
        }
        if role != "gpu-server" {
            continue;
        }
        let bmc = text_field(d, "bmc")?;
        let mut profile = map_field(hardware, text_field(d, "hardware_profile")?)?.clone();
        if let Some(over) = d.get("hardware_override") {
            let over = over.as_mapping().context("invalid hardware override")?;
            ensure!(
                over.keys()
                    .all(|k| COMPONENTS.iter().any(|(n, _)| Some(*n) == k.as_str())),
                "unknown hardware override"
            );
            profile.extend(over.clone());
        }
        for (key, metric) in COMPONENTS {
            let n = positive(&profile, key)?;
            device_rules.push(constant(
                &format!("monitoring:expected:{metric}"),
                n,
                Some(labels([("host", host), ("instance", bmc)])),
            ));
            if key == "gpus" {
                gpu_sizes.push(n);
            }
        }
        let mut total = 0;
        for (peer, n) in map_field(fabric, text_field(d, "fabric_profile")?)? {
            let peer = peer.as_str().context("invalid fabric peer")?;
            let n = n.as_u64().context("invalid fabric size")?;
            total += n;
            device_rules.push(constant(
                "monitoring:expected:ib_peer_links",
                n,
                Some(labels([("node", host), ("peer", peer)])),
            ));
        }
        device_rules.push(constant(
            "monitoring:expected:ib_node_links",
            total,
            Some(labels([("node", host)])),
        ));
        ib_links += total;
    }
    let nodes = counts["gpu_servers"];
    let switches = counts["ib_switches"] + counts["ethernet_switches"];
    let gpus = gpu_sizes.iter().sum();
    let gpus_per_node = *gpu_sizes.iter().min().context("missing GPU device")?;
    let servers = nodes + counts["cpu_servers"];
    let network = switches + counts["firewalls"];
    counts.extend(
        [
            ("devices", servers + network),
            ("servers", servers),
            ("gpus", gpus),
            ("ib_links", ib_links),
            ("switches", switches),
            ("network_devices", network),
            (
                "bmcs",
                addresses.get("b300-redfish").map_or(0, |e| e.len() as u64)
                    + addresses.get("cpu-redfish").map_or(0, |e| e.len() as u64),
            ),
        ]
        .map(|(k, n)| (k.to_string(), n)),
    );
    let freshness = b.ports.freshness_seconds.to_string();
    let dashboard = b.ports.dashboard_url.as_deref().unwrap_or("/d/q3400-snmp");
    let dashboard_root = dashboard.rsplit_once("/d/").map_or(dashboard, |(p, _)| p);
    let mut behavior: Json = serde_json::from_str(BEHAVIOR)?;
    expand_behavior(
        &mut behavior,
        &[
            ("__FRESHNESS__", &freshness),
            ("__DASHBOARD_ROOT__", dashboard_root),
            ("__DASHBOARD__", dashboard),
            ("__SITE__", site),
        ],
    );
    let mut inventory: Vec<_> = counts
        .iter()
        .map(|(k, v)| constant(&format!("monitoring:expected:{k}"), *v, None))
        .collect();
    let canonical = serde_json::to_vec(&serde_json::to_value(&b.config)?)?;
    let hash = format!("{:x}", Sha256::digest(canonical));
    inventory.push(constant(
        "monitoring_inventory_info",
        1,
        Some(labels([("site", site), ("sha256", &hash)])),
    ));
    for j in logical_checks {
        let n = addresses.get(j).map_or(0, |x| x.len() as u64);
        counts.insert(j.into(), n);
        inventory.push(constant(
            "monitoring:expected:job_targets",
            n,
            Some(labels([("target_job", j)])),
        ));
    }
    inventory.extend(device_rules);
    inventory.extend(expected_targets);
    let inventory_doc = json!({"groups":[{"name":"monitoring-inventory-baselines","rules":inventory},behavior["inventory_integrity"]]});

    let mut ports = vec![constant(
        "monitoring:port_baseline:enabled",
        1,
        Some(labels([("site", site)])),
    )];
    ports.extend(
        b.compiled
            .ports
            .values()
            .map(|p| constant("monitoring:port:inventory", 1, Some(p.clone()))),
    );
    ports.extend(
        b.compiled
            .links
            .iter()
            .map(|p| constant("monitoring:link:expected", 1, Some(p.clone()))),
    );
    for (device, _) in b.ports.collectors() {
        let p: Vec<_> = b
            .compiled
            .ports
            .values()
            .filter(|p| &p["device"] == device)
            .collect();
        let network = &p.first().context("collector has no ports")?["network"];
        for role in ROLES {
            let n = p
                .iter()
                .filter(|x| x["expected"] == "up" && x["port_role"] == role)
                .count() as u64;
            ports.push(constant(
                "monitoring:port:role_expected",
                n,
                Some(labels([
                    ("site", site),
                    ("device", device),
                    ("port_role", role),
                    ("network", network),
                ])),
            ));
        }
    }
    ports.extend(fixed_tail(&behavior, "port")?);
    let port_doc = json!({"groups":[{"name":"declared-port-baseline","interval":"1m","rules":ports},behavior["port"][1]]});

    let firewall_doc = if !b.ports.firewalls.is_empty() {
        let mut fw: Vec<_> = b
            .ports
            .firewalls
            .keys()
            .map(|name| {
                let p = b
                    .compiled
                    .ports
                    .values()
                    .find(|p| &p["device"] == name)
                    .context("missing firewall collector")?;
                Ok(constant(
                    "monitoring:firewall:device",
                    1,
                    Some(labels([
                        ("site", site),
                        ("device", name),
                        ("instance", &p["instance"]),
                    ])),
                ))
            })
            .collect::<Result<_>>()?;
        let mut tail = fixed_tail(&behavior, "firewall")?.into_iter();
        fw.push(tail.next().context("missing firewall rules")?);
        for edge in &b.ports.internet_edges {
            for member in &edge.members {
                let p = &b.compiled.ports[member];
                let mut fields = labels([
                    ("site", site),
                    ("edge", &edge.name),
                    ("device", &p["device"]),
                    ("instance", &p["instance"]),
                    ("ifName", &p["ifName"]),
                ]);
                if let Some(counter) = edge.counters.get(member) {
                    fields.extend(labels([
                        ("ifName", &counter.interface),
                        ("carrier_ifName", &p["ifName"]),
                        ("vlan_id", &counter.vlan_id.to_string()),
                    ]));
                }
                fw.push(constant("monitoring:internet:interface", 1, Some(fields)));
            }
        }
        fw.extend(tail);
        json!({"groups":[{"name":"declared-firewall-boundaries","interval":"1m","rules":fw},behavior["firewall"][1]]})
    } else {
        Json::Null
    };
    let mut patch = BTreeMap::from([
        ("nodes", nodes),
        ("switches", switches),
        ("gpus", gpus),
        ("gpus_per_node", gpus_per_node),
    ]);
    for group in fleet["groups"]
        .as_array_mut()
        .context("missing fleet rule groups")?
    {
        for rule in group["rules"]
            .as_array_mut()
            .context("missing fleet rules")?
        {
            if let Some(field) = rule["record"]
                .as_str()
                .and_then(|x| x.strip_prefix("b300:expected:"))
                && let Some(n) = patch.remove(field)
            {
                rule["expr"] = json!(format!("vector({n})"));
            }
        }
    }
    ensure!(
        patch.is_empty(),
        "legacy fleet template missing expected-value rules"
    );
    let files = [
        ("inventory_baseline.yml", inventory_doc),
        ("port_baseline.yml", port_doc),
        ("firewall_baseline.yml", firewall_doc),
        ("fleet_baseline.yml", fleet),
    ]
    .into_iter()
    .map(|(name, doc)| Ok((name.into(), serde_yaml_ng::to_string(&doc)?.into_bytes())))
    .collect::<Result<_>>()?;
    Ok((files, counts))
}
