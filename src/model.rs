use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Site {
    pub id: u64,
    pub slug: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Device {
    pub id: u64,
    pub name: String,
    pub role: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_ip4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oob_ip: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Interface {
    pub id: u64,
    pub device_id: u64,
    pub name: String,
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Address {
    pub id: u64,
    pub address: String,
    pub interface_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Termination {
    pub kind: String,
    pub id: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Cable {
    pub id: u64,
    pub status: String,
    pub a: Vec<Termination>,
    pub b: Vec<Termination>,
}
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub schema_version: u32,
    pub captured_at_unix: u64,
    pub site: Site,
    pub devices: Vec<Device>,
    pub interfaces: Vec<Interface>,
    pub ip_addresses: Vec<Address>,
    pub cables: Vec<Cable>,
}

pub(crate) fn host_address(value: &str) -> Result<IpAddr> {
    let (host, prefix) = value
        .split_once('/')
        .map_or((value, None), |(a, b)| (a, Some(b)));
    let ip: IpAddr = host.parse().context("invalid IP address")?;
    if let Some(prefix) = prefix {
        let n: u8 = prefix.parse().context("invalid prefix length")?;
        ensure!(
            n <= if ip.is_ipv4() { 32 } else { 128 },
            "invalid prefix length"
        );
    }
    Ok(ip)
}

impl Snapshot {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported snapshot schema");
        ensure!(
            self.site.id > 0 && !self.site.slug.is_empty(),
            "invalid site"
        );
        ensure!(!self.devices.is_empty(), "empty device snapshot");
        let mut devices = BTreeSet::new();
        let mut names = BTreeSet::new();
        for d in &self.devices {
            ensure!(
                d.id > 0 && devices.insert(d.id),
                "duplicate or invalid device ID"
            );
            ensure!(
                !d.name.is_empty() && !d.name.contains('/') && names.insert(d.name.to_lowercase()),
                "ambiguous device name: {}",
                d.name
            );
            ensure!(
                !d.role.is_empty() && !d.status.is_empty(),
                "incomplete device {}",
                d.name
            );
            if let Some(ip) = &d.primary_ip4 {
                ensure!(host_address(ip)?.is_ipv4(), "primary_ip4 is not IPv4");
            }
            if let Some(ip) = &d.oob_ip {
                host_address(ip)?;
            }
        }
        let mut interfaces = BTreeSet::new();
        let mut interface_names = BTreeSet::new();
        for i in &self.interfaces {
            ensure!(
                i.id > 0 && interfaces.insert(i.id) && devices.contains(&i.device_id),
                "invalid interface or missing device"
            );
            ensure!(
                !i.name.is_empty() && interface_names.insert((i.device_id, i.name.to_lowercase())),
                "ambiguous interface name"
            );
        }
        let mut ips = BTreeSet::new();
        for i in &self.ip_addresses {
            ensure!(
                i.id > 0 && ips.insert(i.id) && interfaces.contains(&i.interface_id),
                "invalid IP assignment"
            );
            host_address(&i.address)?;
        }
        let mut cables = BTreeSet::new();
        for c in &self.cables {
            ensure!(
                c.id > 0 && cables.insert(c.id) && !c.status.is_empty(),
                "duplicate or invalid cable"
            );
            ensure!(
                c.a.iter()
                    .chain(&c.b)
                    .any(|t| t.kind == "dcim.interface" && interfaces.contains(&t.id)),
                "cable has no endpoint at the selected site"
            );
        }
        Ok(())
    }
}
