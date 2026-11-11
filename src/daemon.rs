use crate::{model::Snapshot, netbox, plan, policy::Policy, render};
use anyhow::{Context, Result, ensure};
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, ValueEnum)]
enum PortMode {
    Audit,
    Off,
}

#[derive(Args)]
pub(crate) struct RunOptions {
    #[arg(long, env = "NETBOX_URL", hide_env_values = true)]
    netbox_url: String,
    #[arg(long, env = "NETBOX_SITE", hide_env_values = true)]
    site: String,
    #[arg(long, env = "NETBOX_TOKEN_FILE", hide_env_values = true)]
    token_file: PathBuf,
    #[arg(
        long,
        env = "NETBOX_INVENTORY_FILE",
        hide_env_values = true,
        required_unless_present = "inventory_generator",
        conflicts_with = "inventory_generator"
    )]
    inventory: Option<PathBuf>,
    /// Executable receiving the snapshot JSON path and returning inventory YAML on stdout.
    /// With --probe-only it returns the site, roles and target labels without resolving cables.
    #[arg(long, env = "NETBOX_INVENTORY_GENERATOR", hide_env_values = true)]
    inventory_generator: Option<PathBuf>,
    #[arg(long, env = "NETBOX_POLICY_FILE", hide_env_values = true)]
    policy: PathBuf,
    #[arg(long, env = "NETBOX_RENDER_FILE", hide_env_values = true)]
    render_file: PathBuf,
    #[arg(long, env = "NETBOX_TEMPLATES_DIR", hide_env_values = true)]
    templates_dir: PathBuf,
    #[arg(long, env = "NETBOX_OUTPUT_DIR", hide_env_values = true)]
    output_dir: PathBuf,
    #[arg(long, env = "NETBOX_PROMETHEUS_PUBLISH_DIR", hide_env_values = true)]
    prometheus_publish_dir: PathBuf,
    #[arg(long, env = "NETBOX_VMAGENT_PUBLISH_DIR", hide_env_values = true)]
    vmagent_publish_dir: PathBuf,
    #[arg(long, env = "NETBOX_SYNC_INTERVAL", default_value = "1h", value_parser = interval)]
    interval: Duration,
    #[arg(long, env = "NETBOX_PORT_MODE", value_enum, default_value = "audit")]
    port_mode: PortMode,
    #[arg(long, env = "NETBOX_RUN_ONCE", action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", default_value_t = false)]
    once: bool,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Status {
    site: String,
    last_attempt: u64,
    last_success: Option<u64>,
    snapshot_at: Option<u64>,
    expected_devices: Option<usize>,
    equivalent_devices: Option<usize>,
    audited_links: Option<usize>,
    files_verified: Option<usize>,
    generations: Option<[String; 2]>,
    last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_probe_success: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    probe_targets: Option<usize>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn interval(s: &str) -> std::result::Result<Duration, String> {
    let (n, scale) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        _ => return Err("duration must have a suffix: s, m or h".into()),
    };
    let seconds = n.parse::<u64>().ok().and_then(|n| n.checked_mul(scale));
    match seconds {
        Some(n) if (10..=604_800).contains(&n) => Ok(Duration::from_secs(n)),
        _ => Err("duration must be between 10s and 168h".into()),
    }
}

fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let dir = path.parent().context("missing state directory")?;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    sync_dir(dir)
}

fn read_status(path: &Path, site: &str) -> Result<Status> {
    match fs::read(path) {
        Ok(bytes) => {
            let status: Status = serde_json::from_slice(&bytes).context("invalid saved status")?;
            ensure!(
                status.site == site,
                "saved state belongs to a different site"
            );
            Ok(status)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Status {
            site: site.into(),
            ..Status::default()
        }),
        Err(e) => Err(e.into()),
    }
}

#[derive(Args)]
pub(crate) struct StatusOptions {
    #[arg(long, env = "NETBOX_OUTPUT_DIR", hide_env_values = true)]
    output_dir: PathBuf,
    #[arg(long, env = "NETBOX_MAX_AGE", default_value = "3h", value_parser = interval)]
    max_age: Duration,
}

pub(crate) fn status(opts: StatusOptions) -> Result<u8> {
    let s: Status = serde_json::from_slice(
        &fs::read(opts.output_dir.join("status.json")).context("read sync status")?,
    )?;
    println!("{}", serde_json::to_string_pretty(&s)?);
    Ok(
        if s.last_success
            .is_some_and(|t| now().saturating_sub(t) <= opts.max_age.as_secs())
        {
            0
        } else {
            2
        },
    )
}

#[cfg(unix)]
fn publish(dir: &Path, files: &render::Files) -> Result<String> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let current = dir.join("current");
    if let Ok(target) = fs::read_link(&current) {
        ensure!(
            target.components().count() == 1
                && target.to_str().is_some_and(|s| s.starts_with("version-")),
            "invalid publication pointer"
        );
        if files
            .iter()
            .all(|(name, bytes)| fs::read(dir.join(&target).join(name)).is_ok_and(|b| &b == bytes))
        {
            return Ok(target.to_string_lossy().into_owned());
        }
    } else {
        ensure!(!current.exists(), "current publication must be a symlink");
    }
    let version = tempfile::Builder::new()
        .prefix("version-")
        .tempdir_in(dir)?;
    fs::set_permissions(version.path(), fs::Permissions::from_mode(0o755))?;
    for (name, bytes) in files {
        let p = version.path().join(name);
        let mut file = File::create_new(&p)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    sync_dir(version.path())?;
    let name = version
        .path()
        .file_name()
        .context("missing version directory name")?
        .to_os_string();
    let stage = tempfile::tempdir_in(dir)?;
    let next = stage.path().join("next");
    symlink(&name, &next)?;
    // Keep the prepared directory before making it visible to readers.
    let _prepared = version.keep();
    fs::rename(next, &current)?;
    sync_dir(dir)?;
    Ok(name.to_string_lossy().into_owned())
}

#[cfg(not(unix))]
fn publish(_: &Path, _: &render::Files) -> Result<String> {
    anyhow::bail!("managed file publication requires Linux")
}

fn generate_inventory(o: &RunOptions, snapshot: &Snapshot, probe_only: bool) -> Result<String> {
    let program = o
        .inventory_generator
        .as_ref()
        .context("missing inventory generator")?;
    ensure!(
        program.is_absolute(),
        "inventory generator must use an absolute executable path"
    );
    let mut input = tempfile::NamedTempFile::new_in(&o.output_dir)?;
    serde_json::to_writer(&mut input, snapshot)?;
    let mut command = Command::new(program);
    command.arg(input.path());
    if probe_only {
        command.arg("--probe-only");
    }
    let output = command.output().context("run inventory generator")?;
    ensure!(
        output.status.success(),
        "inventory generator failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout).context("inventory generator output is not UTF-8")
}

fn round(o: &RunOptions, s: &mut Status, fetch: impl FnOnce() -> Result<Snapshot>) -> Result<()> {
    let snapshot = fetch().context("fetch NetBox snapshot")?;
    let legacy = o
        .inventory
        .as_ref()
        .map(fs::read_to_string)
        .transpose()
        .context("read approved inventory")?;
    let policy: Policy =
        serde_yaml_ng::from_slice(&fs::read(&o.policy)?).context("parse policy")?;
    let spec: render::RenderSpec = serde_yaml_ng::from_slice(&fs::read(&o.render_file)?)
        .context("parse render specification")?;
    if spec.live_probe.is_some() {
        let probe;
        let inventory = match legacy.as_deref() {
            Some(text) => text,
            None => {
                probe = generate_inventory(o, &snapshot, true)?;
                &probe
            }
        };
        let path = o.prometheus_publish_dir.join("probe.yml");
        let previous = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::read(o.templates_dir.join("prometheus").join("biz_targets.yml"))
                    .context("read initial approved probe list")?
            }
            Err(e) => return Err(e.into()),
        };
        let (next, count) = render::live_probe(inventory, &snapshot, &policy, &spec, &previous)?;
        if next != previous || !path.is_file() {
            let mut file = tempfile::NamedTempFile::new_in(&o.prometheus_publish_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.as_file()
                    .set_permissions(fs::Permissions::from_mode(0o644))?;
            }
            file.write_all(&next)?;
            file.as_file().sync_all()?;
            file.persist(path).map_err(|e| e.error)?;
            sync_dir(&o.prometheus_publish_dir)?;
        }
        s.last_probe_success = Some(now());
        s.probe_targets = Some(count);
    }
    let inventory = match legacy {
        Some(text) => text,
        None => generate_inventory(o, &snapshot, false)?,
    };
    let (mut report, candidate) = plan::build(&inventory, &snapshot, Some(&o.site), Some(&policy))?;
    if matches!(o.port_mode, PortMode::Off) {
        report.links.clear();
        report.link_summary.clear();
    }
    s.snapshot_at = Some(snapshot.captured_at_unix);
    s.expected_devices = Some(report.expected_devices);
    s.equivalent_devices = Some(report.equivalent_devices);
    s.audited_links = Some(report.links.len());
    atomic_json(&o.output_dir.join("snapshot.json"), &snapshot)?;
    atomic_json(&o.output_dir.join("plan.json"), &report)?;
    ensure!(
        candidate.as_deref() == Some(inventory.as_str()) && report.untracked_devices.is_empty(),
        "device drift needs review; see plan.json"
    );
    let (prom, vm) = render::build(
        &inventory,
        &report,
        &snapshot,
        &policy,
        &spec,
        &o.templates_dir,
    )?;
    // Both renderers have passed equality validation before either pointer is updated.
    // In this mode, every release is byte-equivalent to its reviewed template.
    let prom_version =
        publish(&o.prometheus_publish_dir, &prom).context("publish Prometheus targets")?;
    let vm_version = publish(&o.vmagent_publish_dir, &vm).context("publish vmagent targets")?;
    s.last_success = Some(now());
    s.generations = Some([prom_version, vm_version]);
    s.files_verified = Some(prom.len() + vm.len());
    Ok(())
}

pub(crate) fn run(o: RunOptions) -> Result<u8> {
    let paths = [
        &o.output_dir,
        &o.prometheus_publish_dir,
        &o.vmagent_publish_dir,
    ];
    for (i, p) in paths.iter().enumerate() {
        let p = p
            .canonicalize()
            .context("output directory must already exist")?;
        ensure!(p.is_dir(), "output path must be a directory");
        for other in &paths[..i] {
            let q = other.canonicalize()?;
            ensure!(
                !p.starts_with(&q) && !q.starts_with(&p),
                "state and publication directories must be distinct"
            );
        }
    }
    let lock_path = o.output_dir.join("run.lock");
    let lock = File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    lock.try_lock()
        .context("another sync process owns the state directory")?;
    let status_path = o.output_dir.join("status.json");
    let mut state = read_status(&status_path, &o.site)?;
    loop {
        state.last_attempt = now();
        let outcome = round(&o, &mut state, || {
            netbox::snapshot(&o.netbox_url, &o.site, &o.token_file)
        });
        state.last_error = outcome.as_ref().err().map(|e| format!("{e:#}"));
        atomic_json(&status_path, &state)?;
        if let Some(e) = &state.last_error {
            eprintln!("sync failed; last published version retained where available: {e}");
        } else {
            println!(
                "{}: {} devices, {} audited links, {} verified files",
                o.site,
                state.equivalent_devices.unwrap_or_default(),
                state.audited_links.unwrap_or_default(),
                state.files_verified.unwrap_or_default()
            );
        }
        if o.once {
            return Ok(if outcome.is_ok() { 0 } else { 2 });
        }
        thread::sleep(o.interval);
    }
}
