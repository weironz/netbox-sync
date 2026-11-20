use crate::{
    approvals::{self, Approvals, map_field, text_field},
    baseline_ports::{CompiledPorts, PortConfig, endpoint},
    model::{Snapshot, host_address},
    policy::Policy,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use serde_yaml_ng::{Mapping, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    pub(crate) exclude_roles: BTreeSet<String>,
    pub(crate) minimum_devices: usize,
    pub(crate) gpu_profiles: BTreeMap<String, Mapping>,
    pub(crate) cable_tag: String,
    #[serde(default)]
    pub(crate) require_cable_tag: bool,
    #[serde(default)]
    pub(crate) retain_confirmed: bool,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Metadata {
    pub(crate) assets: BTreeMap<u64, Json>,
    pub(crate) gpu_types: BTreeMap<u64, Json>,
    pub(crate) tags: BTreeMap<i64, Json>,
}

#[derive(Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Membership {
    pub(crate) cable_ids: BTreeSet<i64>,
    pub(crate) device_ids: BTreeSet<u64>,
}

pub(crate) struct Baseline {
    pub(crate) config: Mapping,
    pub(crate) ports: PortConfig,
    pub(crate) compiled: CompiledPorts,
    pub(crate) membership: Membership,
    pub(crate) retained: Vec<String>,
}

fn put(row: &mut Mapping, key: &str, value: impl Into<Value>) {
    row.insert(Value::from(key), value.into());
}
fn link_key(a: &str, b: &str) -> [String; 2] {
    let mut keys = [a.to_lowercase(), b.to_lowercase()];
    keys.sort();
    keys
}
fn tagged(row: &Json, tag: &str) -> bool {
    row["tags"]
        .as_array()
        .is_some_and(|tags| tags.iter().any(|x| x["slug"].as_str() == Some(tag)))
}
fn integer_pair(a: u64, b: u64) -> [u64; 2] {
    [a.min(b), a.max(b)]
}

pub(crate) fn reconcile(
    approvals: &Approvals,
    snapshot: &Snapshot,
    policy: &Policy,
    settings: &Settings,
    metadata: &Metadata,
    previous: Option<&Membership>,
) -> Result<Baseline> {
    ensure!(
        settings.exclude_roles == approvals.exclude_roles,
        "baseline and inventory role exclusions differ"
    );
    reconcile_projected(
        approvals.project(snapshot, policy, false)?,
        snapshot,
        policy,
        settings,
        metadata,
        previous,
        approvals.retained_links(),
    )
}

pub(crate) fn reconcile_projected<'a>(
    mut config: Mapping,
    snapshot: &Snapshot,
    policy: &Policy,
    settings: &Settings,
    metadata: &Metadata,
    previous: Option<&Membership>,
    retained_links: impl IntoIterator<Item = &'a Mapping>,
) -> Result<Baseline> {
    let endpoints = approvals::endpoints(snapshot, policy)?;
    let inventory = config
        .get("devices")
        .and_then(Value::as_sequence)
        .context("missing projected devices")?;
    let approved: BTreeMap<_, _> = inventory
        .iter()
        .map(|d| {
            let d = d.as_mapping().context("invalid projected device")?;
            Ok((text_field(d, "host")?.to_lowercase(), d))
        })
        .collect::<Result<_>>()?;
    let mut by_host = BTreeMap::new();
    let mut membership = Membership::default();
    let mut devices_by_id = BTreeMap::new();
    ensure!(
        snapshot.devices.len() == metadata.assets.len(),
        "device list changed since snapshot"
    );
    for d in &snapshot.devices {
        let asset = metadata
            .assets
            .get(&d.id)
            .context("device list changed since snapshot")?;
        ensure!(
            asset["name"].as_str() == Some(&d.name)
                && asset["role"]["slug"].as_str() == Some(&d.role)
                && asset["status"]["value"].as_str() == Some(&d.status)
                && asset["primary_ip4"]["address"].as_str() == d.primary_ip4.as_deref(),
            "device changed since snapshot: {}",
            d.name
        );
        let host = &endpoints.canonical[&d.id];
        let host_key = host.to_lowercase();
        devices_by_id.insert(d.id, d);
        if d.status != "active" || settings.exclude_roles.contains(&d.role) {
            continue;
        }
        let mut row = (*approved
            .get(&host_key)
            .context("missing projected device")?)
        .clone();
        ensure!(
            text_field(&row, "role")? == d.role,
            "device role changed: {host}"
        );
        if let Some(ip) = &d.oob_ip {
            put(&mut row, "bmc", host_address(ip)?.to_string());
        }
        if d.role == "gpu-server" {
            let model_id = asset["device_type"]["id"]
                .as_u64()
                .context("missing device type")?;
            let model = metadata
                .gpu_types
                .get(&model_id)
                .context("missing GPU device type")?;
            let slug = model["slug"].as_str().context("missing GPU type slug")?;
            let count = model["custom_fields"]["expected_gpu_count"]
                .as_u64()
                .filter(|n| *n > 0)
                .with_context(|| format!("missing positive expected_gpu_count: {slug}"))?;
            if !row.contains_key("hardware_profile") {
                row.extend(
                    settings
                        .gpu_profiles
                        .get(slug)
                        .with_context(|| format!("unapproved GPU profile: {slug}"))?
                        .clone(),
                );
            }
            let over = row
                .entry(Value::from("hardware_override"))
                .or_insert_with(|| Value::Mapping(Mapping::new()));
            put(
                over.as_mapping_mut().context("invalid hardware override")?,
                "gpus",
                count,
            );
        }
        by_host.insert(host_key, (d.role.as_str(), row));
        membership.device_ids.insert(d.id);
    }
    ensure!(
        by_host.len() >= settings.minimum_devices,
        "too few active assets"
    );
    put(
        &mut config,
        "devices",
        Value::Sequence(
            by_host
                .values()
                .map(|(_, row)| Value::Mapping(row.clone()))
                .collect(),
        ),
    );
    let layout = map_field(&config, "port_baseline")?;
    let polled = approvals::pollable(layout)?;
    let declared = layout
        .get("connections")
        .and_then(Value::as_sequence)
        .context("missing connection inventory")?;
    let device_ports: BTreeMap<_, _> = snapshot.interfaces.iter().map(|p| (p.id, p)).collect();
    let cables: BTreeMap<_, _> = snapshot.cables.iter().map(|c| (c.id, c)).collect();
    ensure!(
        cables.keys().eq(metadata.tags.keys()),
        "cable list changed since snapshot"
    );
    let mut by_pair: BTreeMap<[u64; 2], Vec<_>> = BTreeMap::new();
    let mut occupied: BTreeMap<u64, BTreeSet<i64>> = BTreeMap::new();
    for (id, cable) in &cables {
        ensure!(
            metadata.tags[id]["status"]["value"].as_str() == Some(&cable.status),
            "cable status changed: #{id}"
        );
        if cable.status == "connected" {
            for term in cable
                .a
                .iter()
                .chain(&cable.b)
                .filter(|e| e.kind == "dcim.interface")
            {
                occupied.entry(term.id).or_default().insert(*id);
            }
        }
        if let Ok([a, b]) = approvals::cable_ends(cable) {
            by_pair.entry(integer_pair(a, b)).or_default().push(*cable);
        }
    }
    let find_id = |endpoint_name: &str| -> Result<Option<u64>> {
        let (host, port) = endpoint(endpoint_name)?;
        Ok(endpoints
            .devices
            .get(&host.to_lowercase())
            .and_then(|id| endpoints.ids.get(&(*id, port.to_lowercase())))
            .copied())
    };
    let connected = |port: u64, id: i64| {
        occupied
            .get(&port)
            .is_some_and(|owners| owners.len() == 1 && owners.contains(&id))
            && device_ports.get(&port).is_some_and(|p| p.enabled)
    };
    let mut selected = Vec::new();
    let mut used = BTreeSet::new();
    let mut retained = Vec::new();
    let mut exceptions = BTreeSet::new();
    for item in retained_links {
        ensure!(
            exceptions.insert(link_key(text_field(item, "a")?, text_field(item, "b")?)),
            "duplicate retained link"
        );
    }
    for row in declared {
        let conn = row.as_mapping().context("invalid connection")?;
        let a = text_field(conn, "a")?;
        let b = text_field(conn, "b")?;
        let review = conn
            .get("review")
            .and_then(Value::as_str)
            .unwrap_or("confirmed");
        let retained_link = exceptions.remove(&link_key(a, b));
        let endpoints = [find_id(a)?, find_id(b)?];
        let choices = match endpoints {
            [Some(x), Some(y)] => by_pair
                .get(&integer_pair(x, y))
                .map(Vec::as_slice)
                .unwrap_or_default(),
            _ => &[],
        };
        let hits: Vec<_> = choices.iter().filter(|c| c.status == "connected").collect();
        if !hits.is_empty() {
            ensure!(
                hits.len() == 1
                    && endpoints[0] != endpoints[1]
                    && endpoints
                        .iter()
                        .all(|p| p.is_some_and(|p| connected(p, hits[0].id))),
                "ambiguous or disabled connected cable: {a} ↔ {b}"
            );
            let id = hits[0].id;
            used.insert(id);
            if !retained_link {
                ensure!(
                    !settings.require_cable_tag || tagged(&metadata.tags[&id], &settings.cable_tag),
                    "confirmed cable lost monitoring approval: #{id}"
                );
                membership.cable_ids.insert(id);
            }
        }
        if retained_link {
            ensure!(
                matches!(review, "planned" | "peer_pending")
                    || (settings.retain_confirmed && review == "confirmed"),
                "retained connection lacks approval: {a}"
            );
            retained.push(a.into());
        } else {
            ensure!(
                review == "confirmed",
                "unapproved cable outside retained set"
            );
            if hits.is_empty() {
                if choices.len() == 1
                    && choices[0].status == "decommissioning"
                    && endpoints
                        .iter()
                        .all(|id| id.is_none_or(|id| !occupied.contains_key(&id)))
                {
                    continue;
                }
                anyhow::bail!("confirmed cable mismatch: {a} ↔ {b}");
            }
        }
        selected.push(row.clone());
    }
    ensure!(exceptions.is_empty(), "unknown retained link");
    for (id, asset) in &metadata.tags {
        let cable = cables[id];
        if used.contains(id)
            || !tagged(asset, &settings.cable_tag)
            || cable.status == "decommissioning"
        {
            continue;
        }
        let [a, b] = approvals::cable_ends(cable)?;
        ensure!(
            cable.status == "connected" && connected(a, *id) && connected(b, *id),
            "invalid enrolled cable: #{id}"
        );
        let mut a = &endpoints.reverse[&a];
        let mut b = &endpoints.reverse[&b];
        if !polled.contains_key(&a.to_lowercase()) {
            std::mem::swap(&mut a, &mut b);
        }
        let local = polled
            .get(&a.to_lowercase())
            .context("enrolled cable lacks a known polled endpoint")?;
        let (remote, port) = endpoint(b)?;
        let peer = polled.get(&b.to_lowercase());
        let (device_role, _) = by_host
            .get(&remote.to_lowercase())
            .context("enrolled peer is outside monitored scope")?;
        let mut conn = Mapping::new();
        put(&mut conn, "a", local.as_str());
        put(&mut conn, "b", peer.unwrap_or(b).as_str());
        put(
            &mut conn,
            "role",
            if peer.is_some() { "switch" } else { "server" },
        );
        put(&mut conn, "review", "confirmed");
        if peer.is_none() && *device_role == "gpu-server" && port.starts_with("BF3-storage-") {
            put(&mut conn, "purpose", "服务器存储网");
        }
        selected.push(Value::Mapping(conn));
        membership.cable_ids.insert(*id);
    }
    if let Some(old) = previous {
        for id in old.device_ids.difference(&membership.device_ids) {
            ensure!(
                devices_by_id
                    .get(id)
                    .is_some_and(|v| v.status == "decommissioning"),
                "previously expected device disappeared or lost scope: #{id}"
            );
        }
        for id in old.cable_ids.difference(&membership.cable_ids) {
            ensure!(
                cables
                    .get(id)
                    .is_some_and(|v| v.status == "decommissioning"),
                "previously confirmed cable disappeared or lost scope: #{id}"
            );
        }
    }
    let layout = config
        .get_mut("port_baseline")
        .and_then(Value::as_mapping_mut)
        .context("missing port baseline")?;
    put(layout, "connections", Value::Sequence(selected));
    let ports: PortConfig = serde_yaml_ng::from_value(Value::Mapping(layout.clone()))?;
    let devices = by_host
        .values()
        .map(|(role, row)| {
            Ok((
                text_field(row, "host")?,
                (*role, text_field(row, "primary")?),
            ))
        })
        .collect::<Result<_>>()?;
    let compiled = ports.compile(text_field(&config, "site")?, &devices)?;
    Ok(Baseline {
        config,
        ports,
        compiled,
        membership,
        retained,
    })
}
