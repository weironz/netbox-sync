use crate::plan::{Report, ResolvedDevice};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

pub(crate) type Files = BTreeMap<String, Vec<u8>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenderSpec {
    version: u32,
    jobs: BTreeMap<String, Job>,
    shared: Shared,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    file: String,
    address: Address,
    port: Option<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Address {
    Business,
    Bmc,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Shared {
    protocols: BTreeMap<String, Protocol>,
    prometheus_jobs: BTreeMap<String, String>,
    ufm_host: Option<String>,
    #[serde(default)]
    preserve_jobs: BTreeSet<String>,
    #[serde(default)]
    preserve_job_prefixes: Vec<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    Redfish,
    Snmp,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Redfish => "redfish",
            Self::Snmp => "snmp",
        }
    }
}

fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}

fn seq<'a>(v: &'a Value, k: &str) -> Result<&'a Vec<Value>> {
    v[k].as_array().with_context(|| format!("missing list {k}"))
}

fn label_text(template: &str, fields: &[(&str, &str)]) -> Result<String> {
    let mut rest = template;
    let mut out = String::new();
    while let Some((before, after)) = rest.split_once('{') {
        let (field, tail) = after.split_once('}').context("invalid label template")?;
        let value = fields
            .iter()
            .find_map(|(name, value)| (*name == field).then_some(*value))
            .with_context(|| format!("unknown label field {field}"))?;
        ensure!(!before.contains('}'), "invalid label template");
        out.push_str(before);
        out.push_str(value);
        rest = tail;
    }
    ensure!(!rest.contains('}'), "invalid label template");
    out.push_str(rest);
    Ok(out)
}

fn address<'a>(d: &'a ResolvedDevice, kind: &Address) -> Result<&'a str> {
    match kind {
        Address::Business => d.business_ip.as_deref(),
        Address::Bmc => d.bmc_ip.as_deref(),
    }
    .with_context(|| format!("required address missing for {}", d.host))
}

fn single_target(v: &mut Value, key: &str) -> Result<()> {
    ensure!(
        seq(v, "static_configs")?.len() == 1 && seq(&v["static_configs"][0], "targets")?.len() == 1,
        "invalid static target for {key}"
    );
    Ok(())
}

fn template(dir: &Path, name: &str) -> Result<(Vec<u8>, Value)> {
    let p = Path::new(name);
    ensure!(
        p.components().count() == 1 && matches!(p.components().next(), Some(Component::Normal(_))),
        "invalid template file name"
    );
    let bytes = fs::read(dir.join(p)).with_context(|| format!("read template {name}"))?;
    let value =
        serde_yaml_ng::from_slice(&bytes).with_context(|| format!("parse template {name}"))?;
    Ok((bytes, value))
}

// Keep byte-for-byte equivalence after rendering against the approved template.
fn equivalent(name: &str, bytes: Vec<u8>, before: &Value, after: &Value) -> Result<Vec<u8>> {
    ensure!(
        before == after,
        "generated {name} differs from its approved template"
    );
    Ok(bytes)
}

pub(crate) fn build(
    inventory: &str,
    report: &Report,
    spec: &RenderSpec,
    templates: &Path,
) -> Result<(Files, Files)> {
    ensure!(spec.version == 1, "unsupported render spec version");
    let inventory: Value = serde_yaml_ng::from_str(inventory)?;
    let active: Vec<_> = seq(&inventory, "devices")?
        .iter()
        .filter(|d| d["active"].as_bool().unwrap_or(true))
        .collect();
    let resolved: BTreeMap<_, _> = report
        .resolved_devices
        .iter()
        .map(|d| (d.host.as_str(), d))
        .collect();
    ensure!(
        active.len() == resolved.len(),
        "device projection count differs"
    );
    let labels_by_job = inventory["target_labels"]
        .as_object()
        .context("missing target label policies")?;
    ensure!(
        labels_by_job.keys().collect::<BTreeSet<_>>() == spec.jobs.keys().collect(),
        "render job set differs from inventory check policy"
    );
    let mut prom = BTreeMap::new();
    let mut binding = BTreeMap::new();
    for (name, job) in &spec.jobs {
        let mut rows = Vec::new();
        let policy = labels_by_job[name]
            .as_object()
            .context("invalid label policy")?;
        for d in &active {
            let host = string(d, "host")?;
            let role = string(d, "role")?;
            let role_config = &inventory["roles"][role];
            if !seq(role_config, "checks")?
                .iter()
                .any(|c| c.as_str() == Some(name))
            {
                continue;
            }
            let fields = [
                ("host", host),
                ("role", role),
                ("site", report.site.as_str()),
                ("group", string(role_config, "group")?),
                ("fleet", d["fleet"].as_str().unwrap_or(host)),
            ];
            let resolved = resolved.get(host).context("missing resolved device")?;
            let addr = address(resolved, &job.address)?;
            let target = if let Some(port) = job.port {
                format!(
                    "{}:{port}",
                    if addr.contains(':') {
                        format!("[{addr}]")
                    } else {
                        addr.to_owned()
                    }
                )
            } else {
                addr.to_owned()
            };
            let labels = policy
                .iter()
                .map(|(k, v)| {
                    Ok((
                        k.clone(),
                        label_text(v.as_str().context("invalid label format")?, &fields)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            ensure!(
                binding
                    .insert((name.as_str(), addr.to_owned()), labels.clone())
                    .is_none(),
                "duplicate target {target} for {name}"
            );
            rows.push(json!({"targets": [target], "labels": labels}));
        }
        let (bytes, before) = template(&templates.join("prometheus"), &job.file)?;
        ensure!(
            prom.insert(
                job.file.clone(),
                equivalent(&job.file, bytes, &before, &json!(rows))?
            )
            .is_none(),
            "duplicate target output"
        );
    }

    let mut expected = BTreeMap::new();
    for d in active {
        let host = string(d, "host")?;
        let role = string(d, "role")?;
        let protocol = *spec
            .shared
            .protocols
            .get(role)
            .with_context(|| format!("unknown protocol for {role}"))?;
        let d = resolved.get(host).context("missing resolved device")?;
        let addr = address(
            d,
            match protocol {
                Protocol::Redfish => &Address::Bmc,
                Protocol::Snmp => &Address::Business,
            },
        )?;
        let key = format!("{}_{}", protocol.name(), addr.replace('.', "_"));
        ensure!(
            expected.insert(key, (role, protocol, addr)).is_none(),
            "duplicate shared target"
        );
    }
    let dir = templates.join("vmagent");
    let (inv_bytes, inv_before) = template(&dir, "inventory.json")?;
    let (scrape_bytes, scrape_before) = template(&dir, "scrape.yml")?;
    let mut inv = inv_before.clone();
    let mut scrape = scrape_before.clone();
    let mut matched = BTreeSet::new();
    let mut jobs = BTreeMap::new();
    for job in scrape["scrape_configs"]
        .as_array_mut()
        .context("missing scrape configs")?
    {
        let name = string(job, "job_name")?.to_owned();
        ensure!(jobs.insert(name, job).is_none(), "duplicate scrape job");
    }
    for target in inv["targets"]
        .as_array_mut()
        .context("missing shared targets")?
    {
        let key = string(target, "key")?.to_owned();
        let &(role, protocol, addr) = expected
            .get(&key)
            .with_context(|| format!("unapproved shared key {key}"))?;
        ensure!(matched.insert(key.clone()), "duplicate shared key");
        target["address"] = json!(addr);
        target["protocol"] = json!(protocol.name());
        if let Some(label_job) = spec.shared.prometheus_jobs.get(role) {
            let mut labels = binding
                .get(&(label_job.as_str(), addr.to_owned()))
                .context("missing consumer target")?
                .clone();
            labels.insert("job".into(), label_job.clone());
            labels.insert("instance".into(), addr.into());
            target["prometheus_labels"] = json!(labels);
        } else {
            target["prometheus_labels"] = Value::Null;
        }
        let job = jobs
            .remove(&key)
            .with_context(|| format!("missing shared scrape job {key}"))?;
        single_target(job, &key)?;
        job["static_configs"][0]["labels"] =
            json!({"shared_key": key, "shared_protocol": protocol.name(), "shared_address": addr});
        job["scrape_interval"] = json!(format!(
            "{}s",
            target["interval_secs"]
                .as_u64()
                .context("invalid interval")?
        ));
        match protocol {
            Protocol::Redfish => job["params"]["target"] = json!([string(target, "alias")?]),
            Protocol::Snmp => {
                job["params"]["target"] = json!([format!("{addr}:161")]);
                job["params"]["module"] = json!([string(target, "module")?]);
                job["params"]["auth"] = json!([string(target, "auth")?]);
            }
        }
    }
    ensure!(
        matched.len() == expected.len(),
        "shared collector membership differs"
    );
    if let Some(host) = &spec.shared.ufm_host {
        let ufm = resolved.get(host.as_str()).context("missing UFM device")?;
        let ip = address(ufm, &Address::Business)?;
        for name in ["ufm-rest", "ufm-telemetry", "ufm-optics"] {
            let job = jobs
                .remove(name)
                .with_context(|| format!("missing {name}"))?;
            single_target(job, name)?;
            let group = &job["static_configs"][0];
            ensure!(
                group["targets"][0]
                    .as_str()
                    .is_some_and(|s| s.rsplit_once(':').is_some_and(|(a, _)| a == ip))
                    && group["labels"]["greenstor_delivery_class"] == "ufm",
                "UFM target or routing marker differs"
            );
        }
    }
    for name in jobs.keys() {
        ensure!(
            spec.shared.preserve_jobs.contains(name)
                || spec
                    .shared
                    .preserve_job_prefixes
                    .iter()
                    .any(|prefix| !prefix.is_empty() && name.starts_with(prefix)),
            "unapproved scrape job {name}"
        );
    }
    let vm = BTreeMap::from([
        (
            "inventory.json".into(),
            equivalent("inventory.json", inv_bytes, &inv_before, &inv)?,
        ),
        (
            "scrape.yml".into(),
            equivalent("scrape.yml", scrape_bytes, &scrape_before, &scrape)?,
        ),
    ]);
    Ok((prom, vm))
}
