use crate::{
    model::{Cable, Snapshot, host_address},
    policy::Policy,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approvals {
    version: u32,
    inventory: Mapping,
    pub(crate) exclude_roles: BTreeSet<String>,
    fleet_by_role: BTreeMap<String, String>,
    links: Vec<ApprovedLink>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ApprovedLink {
    Pending(PendingLink),
    Cable(CableApproval),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingLink {
    pending: Mapping,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CableApproval {
    cable: i64,
    first: Option<u64>,
    #[serde(default)]
    monitoring: Mapping,
}

#[derive(Serialize)]
struct InventoryDevice<'a> {
    host: &'a str,
    role: &'a str,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    primary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fleet: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bmc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

pub(crate) fn load_yaml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_yaml_ng::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

pub(crate) struct Endpoints {
    pub(crate) canonical: BTreeMap<u64, String>,
    pub(crate) ids: BTreeMap<(u64, String), u64>,
    pub(crate) reverse: BTreeMap<u64, String>,
    pub(crate) devices: BTreeMap<String, u64>,
}

pub(crate) fn endpoints(snapshot: &Snapshot, policy: &Policy) -> Result<Endpoints> {
    let devices: BTreeMap<_, _> = snapshot.devices.iter().map(|d| (d.id, d)).collect();
    let mut aliases: BTreeMap<_, _> = devices
        .values()
        .map(|d| (d.name.to_lowercase(), d.id))
        .collect();
    let mut canonical: BTreeMap<_, _> = devices.values().map(|d| (d.id, d.name.clone())).collect();
    for (name, alias) in &policy.aliases {
        let d = devices
            .get(&alias.device_id)
            .with_context(|| format!("missing approved device alias {name}"))?;
        ensure!(d.name == alias.netbox_name, "device alias changed: {name}");
        ensure!(
            aliases
                .get(&name.to_lowercase())
                .is_none_or(|id| *id == d.id),
            "device alias collides: {name}"
        );
        aliases.insert(name.to_lowercase(), d.id);
        canonical.insert(d.id, name.clone());
    }

    let interfaces: BTreeMap<_, _> = snapshot.interfaces.iter().map(|i| (i.id, i)).collect();
    let mut ids: BTreeMap<_, _> = interfaces
        .values()
        .map(|i| ((i.device_id, i.name.to_lowercase()), i.id))
        .collect();
    let reverse = interfaces
        .values()
        .map(|i| (i.id, format!("{}/{}", canonical[&i.device_id], i.name)))
        .collect();
    for (endpoint, alias) in &policy.interface_aliases {
        let (host, port) = endpoint
            .split_once('/')
            .context("invalid interface alias")?;
        let i = interfaces
            .get(&alias.interface_id)
            .with_context(|| format!("missing approved interface alias {endpoint}"))?;
        ensure!(
            i.device_id == alias.device_id
                && aliases.get(&host.to_lowercase()) == Some(&i.device_id)
                && i.name == alias.netbox_name,
            "interface alias changed: {endpoint}"
        );
        let key = (i.device_id, port.to_lowercase());
        ensure!(
            ids.get(&key).is_none_or(|id| *id == i.id),
            "interface alias collides: {endpoint}"
        );
        ids.insert(key, i.id);
    }
    Ok(Endpoints {
        canonical,
        ids,
        reverse,
        devices: aliases,
    })
}

pub(crate) fn map_field<'a>(map: &'a Mapping, key: &str) -> Result<&'a Mapping> {
    map.get(key)
        .and_then(Value::as_mapping)
        .with_context(|| format!("expected mapping: {key}"))
}

pub(crate) fn text_field<'a>(map: &'a Mapping, key: &str) -> Result<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("expected text: {key}"))
}

pub(crate) fn pollable(ports: &Mapping) -> Result<BTreeMap<String, String>> {
    let profiles = map_field(ports, "profiles")?;
    let mut names = BTreeMap::new();
    let mut collectors = BTreeSet::new();
    for section in ["switches", "firewalls"] {
        if !ports.contains_key(section) {
            continue;
        }
        for (host, collector) in map_field(ports, section)? {
            let host = host.as_str().context("invalid collector name")?;
            ensure!(
                collectors.insert(host.to_lowercase()),
                "duplicate port collector: {host}"
            );
            let collector = collector.as_mapping().context("invalid port collector")?;
            let profile = map_field(profiles, text_field(collector, "profile")?)?;
            let interfaces = profile
                .get("interfaces")
                .and_then(Value::as_sequence)
                .context("expected profile interfaces")?;
            for iface in interfaces {
                let iface = iface.as_str().context("invalid profile interface")?;
                let name = format!("{host}/{iface}");
                ensure!(
                    names.insert(name.to_lowercase(), name).is_none(),
                    "duplicate port interface"
                );
            }
        }
    }
    Ok(names)
}

fn ipv4(raw: Option<&str>) -> Result<String> {
    let ip = host_address(raw.context("missing IPv4 monitoring address")?)?;
    ensure!(ip.is_ipv4(), "expected IPv4 monitoring address");
    Ok(ip.to_string())
}

pub(crate) fn cable_ends(cable: &Cable) -> Result<[u64; 2]> {
    if let ([a], [b]) = (cable.a.as_slice(), cable.b.as_slice())
        && a.kind == "dcim.interface"
        && b.kind == "dcim.interface"
        && a.id != b.id
    {
        return Ok([a.id, b.id]);
    }
    anyhow::bail!("invalid approved cable ends: #{}", cable.id)
}

impl Approvals {
    pub(crate) fn project(
        &self,
        snapshot: &Snapshot,
        policy: &Policy,
        probe_only: bool,
    ) -> Result<Mapping> {
        ensure!(self.version == 1, "unsupported monitoring approvals schema");
        let mut config = self.inventory.clone();
        let site = text_field(&config, "site")?;
        policy.validate(site, &snapshot.site.slug)?;
        ensure!(
            !config.contains_key("devices"),
            "approvals cannot carry a device inventory"
        );
        if probe_only {
            let mut probe = Mapping::new();
            for key in ["site", "roles", "target_labels"] {
                probe.insert(
                    Value::from(key),
                    config
                        .get(key)
                        .with_context(|| format!("missing {key}"))?
                        .clone(),
                );
            }
            return Ok(probe);
        }

        snapshot.validate()?;
        let endpoints = endpoints(snapshot, policy)?;
        let roles = map_field(&config, "roles")?;
        let mut devices = Vec::new();
        for device in &snapshot.devices {
            let host = &endpoints.canonical[&device.id];
            let active = device.status == "active" && !self.exclude_roles.contains(&device.role);
            let mut row = InventoryDevice {
                host,
                role: &device.role,
                active,
                primary: None,
                fleet: None,
                bmc: None,
                reason: Some("NetBox lifecycle or monitoring role exclusion"),
            };
            if active {
                ensure!(
                    roles.contains_key(device.role.as_str()),
                    "unmapped active device role: {}",
                    device.role
                );
                row.primary = Some(ipv4(device.primary_ip4.as_deref())?);
                row.fleet = Some(self.fleet_by_role.get(&device.role).map_or(host, |s| s));
                row.reason = None;
                if device.role == "gpu-server" {
                    row.bmc = Some(ipv4(device.oob_ip.as_deref())?);
                }
            }
            let index = roles
                .keys()
                .position(|k| k.as_str() == Some(&device.role))
                .unwrap_or(roles.len());
            devices.push((index, host.to_lowercase(), row));
        }
        devices.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        config.insert(
            Value::from("devices"),
            serde_yaml_ng::to_value(devices.into_iter().map(|x| x.2).collect::<Vec<_>>())?,
        );
        let ports = config
            .get_mut("port_baseline")
            .and_then(Value::as_mapping_mut)
            .context("missing port baseline")?;
        ensure!(
            !ports.contains_key("connections"),
            "approvals cannot carry a cable inventory"
        );
        let polled = pollable(ports)?;
        let mut endpoint = endpoints.reverse;
        for (name, alias) in &policy.interface_aliases {
            let (_, port) = name.split_once('/').context("invalid interface alias")?;
            endpoint.insert(
                alias.interface_id,
                format!("{}/{port}", endpoints.canonical[&alias.device_id]),
            );
        }
        for name in endpoint.values_mut() {
            if let Some(canonical) = polled.get(&name.to_lowercase()) {
                *name = canonical.clone();
            }
        }

        let cables: BTreeMap<_, _> = snapshot.cables.iter().map(|c| (c.id, c)).collect();
        let mut seen = BTreeSet::new();
        let mut connections = Vec::new();
        for approval in &self.links {
            let cable = match approval {
                ApprovedLink::Pending(pending) => {
                    ensure!(
                        matches!(
                            text_field(&pending.pending, "review")?,
                            "planned" | "peer_pending"
                        ),
                        "invalid pending link exception"
                    );
                    connections.push(Value::Mapping(pending.pending.clone()));
                    continue;
                }
                ApprovedLink::Cable(cable) => cable,
            };
            let id = cable.cable;
            ensure!(seen.insert(id), "duplicate approved cable: #{id}");
            let [a, b] = cable_ends(
                cables
                    .get(&id)
                    .with_context(|| format!("missing approved cable: #{id}"))?,
            )?;
            let a_name = endpoint
                .get(&a)
                .with_context(|| format!("cable #{id} endpoint {a} is outside the site"))?;
            let b_name = endpoint
                .get(&b)
                .with_context(|| format!("cable #{id} endpoint {b} is outside the site"))?;
            let first = cable.first.unwrap_or_else(|| {
                if polled.contains_key(&a_name.to_lowercase()) {
                    a
                } else {
                    b
                }
            });
            ensure!(
                first == a || first == b,
                "approved first interface no longer belongs to cable #{id}"
            );
            let (a, b) = if first == a {
                (a_name, b_name)
            } else {
                (b_name, a_name)
            };
            let select = |name: &str| -> Result<&String> {
                match name {
                    "a" => Ok(a),
                    "b" => Ok(b),
                    _ => anyhow::bail!("invalid endpoint selector on cable #{id}"),
                }
            };
            let mut row = cable.monitoring.clone();
            ensure!(
                row.keys().all(|k| matches!(
                    k.as_str(),
                    Some(
                        "role"
                            | "purpose"
                            | "review"
                            | "endpoint_roles"
                            | "observe_via"
                            | "planned_peers"
                            | "external_peer"
                            | "internet_boundary"
                    )
                )) && row
                    .get("review")
                    .is_none_or(|v| v.as_str() == Some("confirmed")),
                "invalid monitoring policy: #{id}"
            );
            for field in ["endpoint_roles", "planned_peers", "observe_via"] {
                if let Some(mapping) = row.get_mut(field) {
                    let original = mapping.as_mapping().context("invalid endpoint policy")?;
                    let mut resolved = Mapping::new();
                    for (k, v) in original {
                        let key = select(k.as_str().context("invalid endpoint key")?)?;
                        let val = if field == "observe_via" {
                            Value::from(
                                select(v.as_str().context("invalid observation endpoint")?)?
                                    .as_str(),
                            )
                        } else {
                            v.clone()
                        };
                        resolved.insert(Value::from(key.as_str()), val);
                    }
                    *mapping = Value::Mapping(resolved);
                }
            }
            row.entry(Value::from("role")).or_insert_with(|| {
                Value::from(if polled.contains_key(&b.to_lowercase()) {
                    "switch"
                } else {
                    "server"
                })
            });
            row.insert(Value::from("a"), Value::from(a.as_str()));
            row.insert(Value::from("b"), Value::from(b.as_str()));
            connections.push(Value::Mapping(row));
        }
        ports.insert(Value::from("connections"), Value::Sequence(connections));
        Ok(config)
    }

    pub(crate) fn retained_links(&self) -> impl Iterator<Item = &Mapping> {
        self.links.iter().filter_map(|link| match link {
            ApprovedLink::Pending(link) => Some(&link.pending),
            ApprovedLink::Cable(_) => None,
        })
    }
}
