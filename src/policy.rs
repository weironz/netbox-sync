use anyhow::{Result, ensure};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Alias {
    pub device_id: u64,
    pub netbox_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    pub version: u32,
    pub inventory_site: String,
    pub netbox_site: String,
    #[serde(default)]
    pub aliases: BTreeMap<String, Alias>,
    #[serde(default)]
    pub business_ip_tag_by_role: BTreeMap<String, String>,
    #[serde(default)]
    pub require_oob_roles: BTreeSet<String>,
}

impl Policy {
    pub(crate) fn validate(&self, inventory_site: &str, netbox_site: &str) -> Result<()> {
        ensure!(self.version == 1, "unsupported policy version");
        ensure!(
            self.inventory_site == inventory_site && self.netbox_site == netbox_site,
            "policy site does not match the inventory and snapshot"
        );
        let mut hosts = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for (host, a) in &self.aliases {
            ensure!(
                !host.is_empty()
                    && hosts.insert(host.to_lowercase())
                    && a.device_id > 0
                    && ids.insert(a.device_id)
                    && !a.netbox_name.is_empty(),
                "invalid or duplicate alias mapping"
            );
        }
        ensure!(
            self.business_ip_tag_by_role
                .iter()
                .all(|(r, t)| !r.is_empty() && !t.is_empty())
                && self.require_oob_roles.iter().all(|r| !r.is_empty()),
            "invalid address selection policy"
        );
        Ok(())
    }
}
