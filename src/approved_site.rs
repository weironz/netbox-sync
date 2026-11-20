use crate::{
    approvals::{load_yaml, map_field, text_field},
    baseline,
    baseline_inventory::{self, Metadata, Settings},
    baseline_ports::PortConfig,
    baseline_rules, daemon,
    model::{Snapshot, host_address},
    netbox,
    policy::{InterfaceAlias, Policy},
    render::{Files, label_text},
};
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::Deserialize;
use serde_json::{Value as Json, json};
use serde_yaml_ng::{Mapping, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    time::Duration,
};

const TARGETS: [(&str, &str); 9] = [
    ("b300-redfish", "bmc_targets.yml"),
    ("cpu-redfish", "cpu_bmc_targets.yml"),
    ("biz-ping", "biz_targets.yml"),
    ("node", "node_targets.yml"),
    ("gpu-smi", "gpu_targets.yml"),
    ("dcgm", "dcgm_targets.yml"),
    ("q3400-snmp", "snmp_targets.yml"),
    ("sonic-snmp", "sonic_targets.yml"),
    ("fortigate-snmp", "fortigate_targets.yml"),
];

#[derive(Args)]
pub(crate) struct Options {
    #[arg(long, env = "NETBOX_APPROVED_SITE_DIR")]
    site_dir: PathBuf,
    #[arg(long, env = "NETBOX_URL", required_unless_present = "snapshot")]
    netbox_url: Option<String>,
    #[arg(long, env = "NETBOX_TOKEN_FILE", required_unless_present = "snapshot")]
    token_file: Option<PathBuf>,
    #[arg(long, env = "NETBOX_OUTPUT_DIR")]
    output_dir: PathBuf,
    #[arg(
        long,
        env = "NETBOX_BASELINE_OUTPUT_DIR",
        required_unless_present = "dry_run"
    )]
    baseline_output_dir: Option<PathBuf>,
    #[arg(long, env = "PROMETHEUS_URL", required_unless_present = "dry_run")]
    prometheus_url: Option<String>,
    #[arg(
        long,
        env = "VMAGENT_URL",
        required_unless_present = "dry_run",
        requires = "redfish_targets"
    )]
    vmagent_url: Option<String>,
    #[arg(long, env = "NETBOX_REDFISH_TARGETS_FILE")]
    redfish_targets: Option<PathBuf>,
    #[arg(long, env="NETBOX_SYNC_INTERVAL", default_value="10m", value_parser=daemon::interval)]
    interval: Duration,
    #[arg(long, env = "NETBOX_PROMTOOL", default_value = "/bin/promtool")]
    promtool: PathBuf,
    #[arg(long)]
    once: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long, requires_all=["dry_run","metadata"])]
    snapshot: Option<PathBuf>,
    #[arg(long, requires = "snapshot")]
    metadata: Option<PathBuf>,
    #[arg(long, requires = "dry_run")]
    preview_out: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approvals {
    minimum_devices: usize,
    retained_confirmed: Vec<Mapping>,
    interface_aliases: BTreeMap<String, InterfaceAlias>,
}

fn sequence<'a>(m: &'a Mapping, name: &str) -> Result<&'a Vec<Value>> {
    m.get(name)
        .and_then(Value::as_sequence)
        .with_context(|| format!("missing sequence {name}"))
}

fn active_inventory(inventory: &Mapping) -> Result<BTreeMap<&str, &Mapping>> {
    let mut active = BTreeMap::new();
    for d in sequence(inventory, "devices")? {
        let d = d.as_mapping().context("invalid inventory device")?;
        if d.get("active")
            .and_then(Value::as_bool)
            .context("invalid activation state")?
        {
            let host = text_field(d, "host")?;
            ensure!(
                active.insert(host, d).is_none(),
                "duplicate approved host: {host}"
            );
        }
    }
    Ok(active)
}

fn validate_addresses(
    approved: &BTreeMap<&str, &Mapping>,
    snapshot: &Snapshot,
    policy: &Policy,
) -> Result<()> {
    let endpoints = crate::approvals::endpoints(snapshot, policy)?;
    for d in &snapshot.devices {
        if d.status != "active" {
            continue;
        }
        let host = endpoints
            .canonical
            .get(&d.id)
            .context("device lacks canonical name")?;
        let row = approved
            .get(host.as_str())
            .with_context(|| format!("unapproved active device: {host}"))?;
        ensure!(
            host_address(text_field(row, "primary")?)?
                == host_address(d.primary_ip4.as_deref().context("missing primary IPv4")?)?,
            "primary address changed: {host}"
        );
        if let Some(expected) = row.get("bmc").and_then(Value::as_str) {
            ensure!(
                host_address(expected)?
                    == host_address(d.oob_ip.as_deref().context("missing OOB address")?)?,
                "BMC address changed: {host}"
            );
        }
    }
    Ok(())
}

fn targets(inventory: &Mapping) -> Result<BTreeMap<String, Vec<Json>>> {
    let site = text_field(inventory, "site")?;
    let roles = map_field(inventory, "roles")?;
    let labels = map_field(inventory, "target_labels")?;
    let mut result: BTreeMap<String, Vec<Json>> = BTreeMap::new();
    for (host, d) in active_inventory(inventory)? {
        let role = text_field(d, "role")?;
        let group = map_field(roles, role)?;
        let fields = [
            ("host", host),
            ("role", role),
            ("group", text_field(group, "group")?),
            ("site", site),
            (
                "fleet",
                d.get("fleet").and_then(Value::as_str).unwrap_or(host),
            ),
        ];
        for j in sequence(group, "checks")? {
            let j = j.as_str().context("invalid check")?;
            let (address, port, _) = baseline_rules::job(j)?;
            let address = text_field(d, address)?;
            host_address(address)?;
            let address = port.map_or_else(|| address.to_owned(), |p| format!("{address}:{p}"));
            let fields = map_field(labels, j)?
                .iter()
                .map(|(k, v)| {
                    Ok((
                        k.as_str().context("invalid target label")?.to_owned(),
                        label_text(v.as_str().context("invalid label template")?, &fields)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            result
                .entry(j.to_owned())
                .or_default()
                .push(json!({"targets":[address],"labels":fields}));
        }
    }
    Ok(result)
}

fn sorted_values(v: &[Json]) -> Result<Vec<String>> {
    let mut rows = v
        .iter()
        .map(serde_json::to_string)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.sort();
    Ok(rows)
}

fn normalized_rules(v: &Json) -> Result<Vec<(String, Json, Vec<String>)>> {
    v["groups"]
        .as_array()
        .context("missing rule groups")?
        .iter()
        .map(|g| {
            let mut rules = g["rules"].as_array().context("missing rules")?.clone();
            for r in &mut rules {
                if r["record"] == "monitoring_inventory_info"
                    && let Some(labels) = r["labels"].as_object_mut()
                {
                    labels.remove("sha256");
                }
            }
            Ok((
                g["name"]
                    .as_str()
                    .context("missing rule group name")?
                    .into(),
                g["interval"].clone(),
                sorted_values(&rules)?,
            ))
        })
        .collect()
}

fn verify_collector(o: &Options, targets: &BTreeMap<String, Vec<Json>>) -> Result<Option<usize>> {
    let Some(url) = &o.vmagent_url else {
        return Ok(None);
    };
    let redfish: Json = serde_json::from_slice(&fs::read(
        o.redfish_targets
            .as_deref()
            .context("missing Redfish targets file")?,
    )?)?;
    let features: Json = load_yaml(&o.site_dir.join("inband-features.yml"))?;
    let mut expected = BTreeMap::new();
    for (job, rows) in targets {
        if let Some(feature) = baseline_rules::job(job)?.2 {
            let enabled = features["features"][feature]
                .as_bool()
                .context("missing in-band policy")?;
            if !enabled {
                continue;
            }
        }
        let collector_job = match job.as_str() {
            "b300-redfish" | "cpu-redfish" => "redfish",
            "q3400-snmp" | "sonic-snmp" | "fortigate-snmp" => "snmp",
            j => j,
        };
        for r in rows {
            let host = r["labels"]["host"]
                .as_str()
                .context("missing expected host")?;
            let target = r["targets"][0]
                .as_str()
                .context("missing expected address")?;
            ensure!(
                expected
                    .insert(
                        (collector_job.to_owned(), host.to_owned()),
                        target.to_owned()
                    )
                    .is_none(),
                "duplicate approved collector identity"
            );
        }
    }
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;
    let response = client
        .get(format!("{}/api/v1/targets", url.trim_end_matches('/')))
        .send()?
        .error_for_status()?;
    // The endpoint returns service discovery labels; do not log its raw response.
    let data: Json = serde_json::from_reader(std::io::Read::take(response, 16 * 1024 * 1024))?;
    let mut actual = BTreeMap::new();
    for r in data["data"]["activeTargets"]
        .as_array()
        .context("missing active vmagent targets")?
    {
        let labels = &r["labels"];
        let job = labels["job"].as_str().unwrap_or_default();
        if !matches!(
            job,
            "redfish" | "snmp" | "biz-ping" | "node" | "dcgm" | "gpu-smi"
        ) {
            continue;
        }
        let host = labels["host"].as_str().context("missing observed host")?;
        let instance = labels["instance"].as_str().context("missing instance")?;
        let target = match job {
            "redfish" => {
                let address = redfish["targets"][host]["address"]
                    .as_str()
                    .context("missing Redfish target address")?;
                let address = if address.contains("://") {
                    address.to_owned()
                } else {
                    format!("https://{address}")
                };
                reqwest::Url::parse(&address)?
                    .host_str()
                    .context("missing Redfish host")?
                    .to_owned()
            }
            "snmp" => instance.strip_suffix(":161").unwrap_or(instance).to_owned(),
            _ => instance.to_owned(),
        };
        ensure!(
            actual
                .insert((job.to_owned(), host.to_owned()), target)
                .is_none(),
            "duplicate active collector identity"
        );
    }
    ensure!(
        actual == expected,
        "vmagent target identity or address differs from approved inventory"
    );
    Ok(Some(actual.len()))
}

fn prepare(o: &Options) -> Result<(Files, Json)> {
    let input = &o.site_dir;
    let inventory: Mapping = load_yaml(&input.join("inventory.yml"))?;
    let site = text_field(&inventory, "site")?;
    ensure!(
        inventory.get("version").and_then(Value::as_u64) == Some(1),
        "unsupported inventory schema"
    );
    let approved: Approvals = load_yaml(&input.join("netbox-sync/approvals.yml"))?;
    let policy = Policy {
        version: 1,
        inventory_site: site.into(),
        netbox_site: site.into(),
        aliases: BTreeMap::new(),
        interface_aliases: approved.interface_aliases,
        business_ip_tag_by_role: BTreeMap::new(),
        require_oob_roles: BTreeSet::new(),
    };
    policy.validate(site, site)?;
    let settings = Settings {
        exclude_roles: BTreeSet::new(),
        minimum_devices: approved.minimum_devices,
        gpu_profiles: BTreeMap::new(),
        cable_tag: "monitoring-baseline".into(),
        require_cable_tag: true,
        retain_confirmed: true,
    };
    let (snapshot, metadata): (Snapshot, Metadata) = match (&o.snapshot, &o.metadata) {
        (Some(s), Some(m)) => (
            serde_json::from_slice(&fs::read(s)?)?,
            serde_json::from_slice(&fs::read(m)?)?,
        ),
        _ => netbox::approved_snapshot(
            o.netbox_url.as_deref().context("missing NetBox URL")?,
            site,
            o.token_file
                .as_deref()
                .context("missing NetBox token file")?,
            &policy,
            &settings.cable_tag,
        )?,
    };
    snapshot.validate()?;
    ensure!(
        snapshot.site.slug == site,
        "snapshot belongs to another site"
    );
    let approved_hosts = active_inventory(&inventory)?;
    validate_addresses(&approved_hosts, &snapshot, &policy)?;
    let layout = map_field(&inventory, "port_baseline")?;
    let retained = sequence(layout, "connections")?
        .iter()
        .filter_map(|v| v.as_mapping())
        .filter(|m| {
            m.get("review")
                .and_then(Value::as_str)
                .is_some_and(|v| v != "confirmed")
        })
        .chain(approved.retained_confirmed.iter());
    let previous = o
        .baseline_output_dir
        .as_ref()
        .map(|d| baseline::read_membership(&d.join("current/membership.json")))
        .transpose()?
        .flatten();
    let baseline = baseline_inventory::reconcile_projected(
        inventory.clone(),
        &snapshot,
        &policy,
        &settings,
        &metadata,
        previous.as_ref(),
        retained,
    )?;
    let approved_ports: PortConfig = serde_yaml_ng::from_value(Value::Mapping(layout.clone()))?;
    let approved_devices = approved_hosts
        .iter()
        .map(|(h, d)| Ok((*h, (text_field(d, "role")?, text_field(d, "primary")?))))
        .collect::<Result<_>>()?;
    let approved_ports = approved_ports.compile(site, &approved_devices)?;
    ensure!(
        approved_ports.ports == baseline.compiled.ports
            && approved_ports.links == baseline.compiled.links,
        "port baseline or cable peer differs from approved inventory"
    );
    let candidate_targets = targets(&baseline.config)?;
    let approved_targets = targets(&inventory)?;
    for (job, rows) in &candidate_targets {
        ensure!(
            sorted_values(rows)?
                == sorted_values(approved_targets.get(job).context("new target job")?)?,
            "approved target or labels changed: {job}"
        );
    }
    ensure!(
        candidate_targets.keys().eq(approved_targets.keys()),
        "target jobs differ"
    );
    for (job, name) in TARGETS {
        if let Some(rows) = candidate_targets.get(job) {
            let configured: Vec<Json> = load_yaml(&input.join("prometheus").join(name))?;
            ensure!(
                sorted_values(rows)? == sorted_values(&configured)?,
                "configured targets differ: {job}"
            );
        }
    }
    let rules_dir = input.join("prometheus/rules");
    let fleet = load_yaml(&rules_dir.join("fleet_baseline.yml"))?;
    let (mut files, counts) = baseline_rules::render(&baseline, fleet)?;
    for (job, name) in TARGETS {
        if let Some(rows) = candidate_targets.get(job) {
            // The files are consumed as YAML through the existing file_sd names.
            files.insert(
                name.replace(".yml", ".targets"),
                serde_yaml_ng::to_string(rows)?.into_bytes(),
            );
        }
    }
    files.insert(
        "membership.json".into(),
        serde_json::to_vec(&baseline.membership)?,
    );
    if let Some(dir) = &o.preview_out {
        fs::create_dir(dir)?;
        for (name, data) in &files {
            fs::write(dir.join(name), data)?;
        }
    }
    for (name, body) in files.iter().filter(|(n, _)| n.ends_with(".yml")) {
        let configured: Json = load_yaml(&rules_dir.join(name))?;
        let candidate: Json = serde_yaml_ng::from_slice(body)?;
        ensure!(
            normalized_rules(&configured)? == normalized_rules(&candidate)?,
            "configured rules differ: {name}"
        );
    }
    let collector = verify_collector(o, &candidate_targets)?;
    let split = baseline
        .membership
        .cable_ids
        .iter()
        .filter(|i| **i < 0)
        .count();
    let mut ports = BTreeMap::new();
    for p in baseline
        .compiled
        .ports
        .values()
        .filter(|p| p["expected"] == "up")
    {
        *ports.entry(&p["network"]).or_insert(0) += 1;
    }
    let report = json!({
        "site":site,"counts":counts,"links":baseline.compiled.links.len(),
        "confirmed_cables":baseline.membership.cable_ids.len(),
        "breakout_links":split,"ports":ports,"collector_targets":collector,
        "snapshot_at":snapshot.captured_at_unix, "retained":baseline.retained.len(),
    });
    Ok((files, report))
}

pub(crate) fn run(o: Options) -> Result<u8> {
    let lock = fs::File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(o.output_dir.join("run.lock"))?;
    lock.try_lock()
        .context("another approved-site sync owns this state")?;
    let status_path = o.output_dir.join(if o.dry_run {
        "dry-run.json"
    } else {
        "status.json"
    });
    loop {
        let result = prepare(&o).and_then(|(files, mut info)| {
            if !o.dry_run {
                let generation = baseline::publish(
                    o.baseline_output_dir
                        .as_deref()
                        .context("missing publication directory")?,
                    &files,
                    &o.promtool,
                    o.prometheus_url
                        .as_deref()
                        .context("missing Prometheus URL")?,
                )?;
                info["generation"] = json!(generation);
            }
            info["last_success"] = json!(daemon::now());
            info["error"] = Json::Null;
            Ok(info)
        });
        let mut status = match result.as_ref() {
            Ok(report) => report.clone(),
            Err(error) => {
                let mut previous: Json = fs::read(&status_path)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or_else(|| json!({}));
                previous["error"] = json!(format!("{error:#}"));
                previous
            }
        };
        status["last_attempt"] = json!(daemon::now());
        daemon::atomic_json(&status_path, &status)?;
        println!("{status}");
        if o.once || o.dry_run {
            return Ok(if result.is_ok() { 0 } else { 2 });
        }
        std::thread::sleep(if result.is_err() {
            o.interval.min(Duration::from_secs(60))
        } else {
            o.interval
        });
    }
}

#[derive(Args)]
pub(crate) struct Health {
    #[arg(long, env = "NETBOX_OUTPUT_DIR")]
    output_dir: PathBuf,
    #[arg(long, env="NETBOX_MAX_AGE",default_value="30m",value_parser=daemon::interval)]
    max_age: Duration,
}

pub(crate) fn health(o: Health) -> Result<u8> {
    let info: Json = serde_json::from_slice(&fs::read(o.output_dir.join("status.json"))?)?;
    println!("{info}");
    let fresh = info["last_success"]
        .as_u64()
        .and_then(|ts| daemon::now().checked_sub(ts))
        .is_some_and(|age| age <= o.max_age.as_secs());
    Ok(if fresh && info["error"].is_null() {
        0
    } else {
        2
    })
}
