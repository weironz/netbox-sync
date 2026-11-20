use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) type Labels = BTreeMap<String, String>;
pub(crate) const ROLES: [&str; 3] = ["mgmt", "server", "switch"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortConfig {
    version: u32,
    pub freshness_seconds: u64,
    #[serde(default)]
    pub dashboard_url: Option<String>,
    #[serde(rename = "source", default)]
    _source: Option<serde_yaml_ng::Value>,
    profiles: BTreeMap<String, Profile>,
    pub switches: BTreeMap<String, Collector>,
    #[serde(default)]
    pub firewalls: BTreeMap<String, Collector>,
    #[serde(default)]
    pub internet_edges: Vec<InternetEdge>,
    connections: Vec<Connection>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    interfaces: Vec<String>,
    interface_type: String,
    #[serde(default)]
    overrides: BTreeMap<String, Override>,
}
#[derive(Deserialize)]
struct Override {
    role: Option<String>,
    interface_type: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Collector {
    profile: String,
    #[serde(rename = "guid", default)]
    _guid: Option<String>,
    pub job: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    a: String,
    b: String,
    role: String,
    #[serde(default = "confirmed")]
    review: String,
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    endpoint_roles: BTreeMap<String, String>,
    #[serde(default)]
    planned_peers: BTreeMap<String, String>,
    #[serde(default)]
    observe_via: BTreeMap<String, String>,
    #[serde(default)]
    external_peer: bool,
    #[serde(default)]
    internet_boundary: bool,
}
fn confirmed() -> String {
    "confirmed".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InternetEdge {
    pub name: String,
    pub members: Vec<String>,
    #[serde(default)]
    pub counters: BTreeMap<String, Counter>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Counter {
    #[serde(rename = "ifName")]
    pub interface: String,
    pub vlan_id: u16,
}

pub(crate) struct CompiledPorts {
    pub ports: BTreeMap<String, Labels>,
    pub links: Vec<Labels>,
}
pub(crate) fn endpoint(s: &str) -> Result<(&str, &str)> {
    let (host, port) = s
        .split_once('/')
        .context("endpoint must contain device/interface")?;
    ensure!(!host.is_empty() && !port.is_empty(), "invalid endpoint {s}");
    Ok((host, port))
}

fn network(role: &str) -> Result<&str> {
    match role {
        "ib-switch" => Ok("ib"),
        "ethernet-switch" => Ok("ethernet"),
        "firewall" => Ok("firewall"),
        _ => anyhow::bail!("unsupported collector role: {role}"),
    }
}
fn management(interface_type: &str) -> bool {
    matches!(interface_type, "ethernet-mgmt" | "fnm")
}
fn interface_valid(name: &str) -> bool {
    !name.is_empty() && !name.contains(['\n', '\r', '"'])
}
pub(crate) fn labels<const N: usize>(values: [(&str, &str); N]) -> Labels {
    values
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
}

impl PortConfig {
    pub(crate) fn collectors(&self) -> impl Iterator<Item = (&String, &Collector)> {
        self.switches.iter().chain(&self.firewalls)
    }

    pub(crate) fn compile(
        &self,
        site: &str,
        devices: &BTreeMap<&str, (&str, &str)>,
    ) -> Result<CompiledPorts> {
        ensure!(
            self.version == 1
                && (30..=600).contains(&self.freshness_seconds)
                && !self.switches.is_empty()
                && !self.profiles.is_empty(),
            "invalid port baseline"
        );
        let mut ports = BTreeMap::new();
        for (host, collector) in self.collectors() {
            let &(role, ip) = devices
                .get(host.as_str())
                .with_context(|| format!("port collector must be active: {host}"))?;
            let net = network(role)?;
            ensure!(
                matches!(
                    collector.job.as_str(),
                    "q3400-snmp" | "sonic-snmp" | "fortigate-snmp"
                ) && (collector.job == "fortigate-snmp") == (role == "firewall")
                    && self.firewalls.contains_key(host) == (role == "firewall")
                    && !(self.firewalls.contains_key(host) && self.switches.contains_key(host)),
                "invalid port collector: {host}"
            );
            let profile = self
                .profiles
                .get(&collector.profile)
                .context("unknown port profile")?;
            ensure!(
                !profile.interfaces.is_empty()
                    && profile
                        .overrides
                        .keys()
                        .all(|p| profile.interfaces.contains(p)),
                "invalid port profile"
            );
            for name in &profile.interfaces {
                let opt = profile.overrides.get(name);
                let port_role = opt.and_then(|v| v.role.as_deref()).unwrap_or("unassigned");
                let ty = opt
                    .and_then(|v| v.interface_type.as_deref())
                    .unwrap_or(&profile.interface_type);
                ensure!(
                    interface_valid(name)
                        && (port_role == "unassigned" || ROLES.contains(&port_role)),
                    "invalid interface: {host}/{name}"
                );
                let data = labels([
                    ("device", host),
                    ("instance", ip),
                    ("ifName", name),
                    ("port_role", port_role),
                    ("interface_type", ty),
                    ("expected", "unused"),
                    ("link_id", ""),
                    ("peer_device", ""),
                    ("peer_port", ""),
                    ("planned_peer", ""),
                    ("review", "idle"),
                    ("site", site),
                    ("job", &collector.job),
                    ("network", net),
                    ("source_job", &collector.job),
                    ("source_instance", ip),
                    ("source_ifName", name),
                    ("observation", "local"),
                    ("purpose", ""),
                ]);
                ensure!(
                    ports.insert(format!("{host}/{name}"), data).is_none(),
                    "duplicate interface: {host}/{name}"
                );
            }
        }

        let mut links = Vec::new();
        let mut used = BTreeSet::new();
        let mut external_interfaces = BTreeSet::new();
        for c in &self.connections {
            let (a, b) = (c.a.as_str(), c.b.as_str());
            let (a_device, a_port) = endpoint(a)?;
            let (b_device, b_port) = endpoint(b)?;
            ensure!(
                ROLES.contains(&c.role.as_str())
                    && matches!(c.review.as_str(), "confirmed" | "planned" | "peer_pending")
                    && used.insert(a)
                    && used.insert(b),
                "invalid or duplicate connection: {a} ↔ {b}"
            );
            let left = ports
                .get(a)
                .with_context(|| format!("missing polled endpoint: {a}"))?;
            let right = ports.get(b);
            ensure!(
                c.role != "server" || right.is_none(),
                "server link connects two switches"
            );
            if let Some(r) = right
                && left["network"] != r["network"]
            {
                let networks = BTreeSet::from([left["network"].as_str(), r["network"].as_str()]);
                let mgmt = networks == BTreeSet::from(["ib", "ethernet"])
                    && c.role == "mgmt"
                    && [left, r]
                        .iter()
                        .any(|p| p["network"] == "ib" && management(&p["interface_type"]));
                ensure!(
                    networks == BTreeSet::from(["ethernet", "firewall"]) || mgmt,
                    "incompatible port networks"
                );
            }
            for (ep, role) in &c.endpoint_roles {
                let port = ports
                    .get(ep)
                    .context("endpoint role refers to an unmonitored endpoint")?;
                ensure!(
                    (ep == a || ep == b)
                        && ROLES.contains(&role.as_str())
                        && (role == "mgmt") == management(&port["interface_type"]),
                    "invalid endpoint role: {ep}"
                );
            }
            ensure!(
                c.review != "peer_pending"
                    || (c.planned_peers.contains_key(a) && c.planned_peers.contains_key(b)),
                "pending peer needs both original endpoints"
            );
            ensure!(
                !c.external_peer
                    || (left["network"] == "firewall" && right.is_none() && c.role == "switch"),
                "external peer must be a firewall uplink"
            );
            if c.external_peer {
                external_interfaces.insert(a);
            }
            if c.internet_boundary {
                let firewall: Vec<_> = [a, b]
                    .into_iter()
                    .filter(|ep| ports.get(*ep).is_some_and(|p| p["network"] == "firewall"))
                    .collect();
                ensure!(
                    c.role == "switch"
                        && firewall.len() == 1
                        && ports[firewall[0]]["interface_type"] == "ethernet",
                    "Internet edge requires one physical firewall port"
                );
                external_interfaces.insert(firewall[0]);
            }
            let peer_role = devices.get(b_device).map(|p| p.0);
            let unresolved = left["network"] == "firewall"
                && c.review == "peer_pending"
                && peer_role == Some("ethernet-switch")
                && b_port.starts_with("unverified-");
            ensure!(
                c.role != "switch"
                    || right.is_some()
                    || c.external_peer
                    || unresolved
                    || peer_role == Some("firewall"),
                "external interconnect needs an active network device"
            );
            let pair = if a < b {
                format!("{a}|{b}")
            } else {
                format!("{b}|{a}")
            };
            let hash = format!("{:x}", Sha256::digest(pair.as_bytes()));
            let id = format!("link-{}", &hash[..20]);
            links.push(labels([
                ("link_id", &id),
                ("site", site),
                ("port_role", &c.role),
                ("network", &left["network"]),
                ("purpose", &c.purpose),
                ("instance", &left["instance"]),
                ("a_device", a_device),
                ("a_port", a_port),
                ("b_device", b_device),
                ("b_port", b_port),
                ("review", &c.review),
            ]));
            for (end, peer) in [(a, b), (b, a)] {
                if let Some(p) = ports.get_mut(end) {
                    let (remote, port) = endpoint(peer)?;
                    p.extend(labels([
                        ("port_role", c.endpoint_roles.get(end).unwrap_or(&c.role)),
                        ("expected", "up"),
                        ("link_id", &id),
                        ("peer_device", remote),
                        ("peer_port", port),
                        (
                            "planned_peer",
                            c.planned_peers.get(end).map_or(peer, String::as_str),
                        ),
                        ("review", &c.review),
                        ("purpose", &c.purpose),
                    ]));
                }
            }
            for (dest, src) in &c.observe_via {
                ensure!(
                    c.role == "mgmt" && ((dest == a && src == b) || (dest == b && src == a)),
                    "invalid peer observation"
                );
                let p = ports.get(src).context("unmonitored source endpoint")?;
                let labels = labels([
                    ("source_job", &p["job"]),
                    ("source_instance", &p["instance"]),
                    ("source_ifName", &p["ifName"]),
                    ("observation", "peer"),
                ]);
                ports
                    .get_mut(dest)
                    .context("unmonitored destination endpoint")?
                    .extend(labels);
            }
        }

        let mut seen_edges = BTreeSet::new();
        let mut members = BTreeSet::new();
        let mut counters = BTreeSet::new();
        for edge in &self.internet_edges {
            ensure!(
                !edge.name.is_empty()
                    && seen_edges.insert(&edge.name)
                    && !edge.members.is_empty()
                    && edge.counters.keys().all(|p| edge.members.contains(p)),
                "invalid Internet edge"
            );
            for member in &edge.members {
                let p = ports
                    .get(member)
                    .context("Internet edge requires monitored endpoint")?;
                ensure!(
                    members.insert(member)
                        && external_interfaces.contains(member.as_str())
                        && p["network"] == "firewall"
                        && p["expected"] == "up"
                        && p["interface_type"] == "ethernet",
                    "invalid or duplicate Internet endpoint"
                );
                let counter = match edge.counters.get(member) {
                    Some(c) => {
                        ensure!(
                            interface_valid(&c.interface) && (1..=4094).contains(&c.vlan_id),
                            "invalid VLAN counter"
                        );
                        c.interface.as_str()
                    }
                    None => p["ifName"].as_str(),
                };
                ensure!(
                    counters.insert((p["instance"].clone(), counter.to_owned())),
                    "duplicate Internet counter"
                );
            }
        }
        Ok(CompiledPorts { ports, links })
    }
}
