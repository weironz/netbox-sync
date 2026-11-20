mod approvals;
mod baseline;
mod baseline_inventory;
mod baseline_ports;
mod baseline_rules;
mod daemon;
mod model;
mod netbox;
mod plan;
mod policy;
mod render;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Continuously validate and publish approved device targets.
    Run(Box<daemon::RunOptions>),
    /// Print persisted status and fail when no recent valid sync exists.
    Status(daemon::StatusOptions),
    /// Read NetBox and save a minimal site snapshot. Does not modify NetBox.
    Snapshot {
        #[arg(long, env = "NETBOX_URL", hide_env_values = true)]
        netbox_url: String,
        #[arg(long, env = "NETBOX_SITE", hide_env_values = true)]
        site: String,
        #[arg(long, env = "NETBOX_TOKEN_FILE", hide_env_values = true)]
        token_file: PathBuf,
        #[arg(long, env = "NETBOX_SNAPSHOT_FILE", hide_env_values = true)]
        output: PathBuf,
    },
    /// Render an approved monitoring inventory from a saved snapshot.
    Inventory {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long, env = "NETBOX_APPROVALS_FILE")]
        approvals: PathBuf,
        #[arg(long, env = "NETBOX_POLICY_FILE")]
        policy: PathBuf,
        #[arg(long)]
        probe_only: bool,
    },
    /// Render rule files to a new directory without updating a running Prometheus.
    BaselinePreview {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long, env = "NETBOX_APPROVALS_FILE")]
        approvals: PathBuf,
        #[arg(long, env = "NETBOX_POLICY_FILE")]
        policy: PathBuf,
        #[arg(long, env = "NETBOX_BASELINE_INPUTS_DIR")]
        inputs: PathBuf,
        #[arg(long)]
        membership: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Compare a snapshot with inventory.yml; output a report and, if equivalent, a candidate.
    Plan {
        #[arg(long, env = "NETBOX_SNAPSHOT_FILE", hide_env_values = true)]
        snapshot: PathBuf,
        #[arg(long, env = "NETBOX_INVENTORY_FILE", hide_env_values = true)]
        inventory: PathBuf,
        #[arg(long, env = "NETBOX_PLAN_DIR", hide_env_values = true)]
        out_dir: PathBuf,
        /// Explicit NetBox site slug if it differs from inventory.site.
        #[arg(long, env = "NETBOX_SITE", hide_env_values = true)]
        netbox_site: Option<String>,
        /// Optional site-specific alias and address-purpose policy.
        #[arg(long, env = "NETBOX_POLICY_FILE", hide_env_values = true)]
        policy: Option<PathBuf>,
    },
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(dir).context("create temporary output")?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map_err(|e| e.error)
        .with_context(|| format!("write new output {}", path.display()))?;
    Ok(())
}
fn run(c: Cli) -> Result<u8> {
    match c.command {
        Commands::Run(o) => daemon::run(*o),
        Commands::Status(o) => daemon::status(o),
        Commands::Snapshot {
            netbox_url,
            site,
            token_file,
            output,
        } => {
            let s = netbox::snapshot(&netbox_url, &site, &token_file)?;
            write_new(&output, &serde_json::to_vec_pretty(&s)?)?;
            println!(
                "{}: {} devices, {} interfaces, {} assigned IPs, {} cables",
                s.site.slug,
                s.devices.len(),
                s.interfaces.len(),
                s.ip_addresses.len(),
                s.cables.len()
            );
            Ok(0)
        }
        Commands::Inventory {
            snapshot,
            approvals,
            policy,
            probe_only,
        } => {
            let snapshot = serde_json::from_slice(&fs::read(snapshot)?)?;
            let approvals: approvals::Approvals = approvals::load_yaml(&approvals)?;
            let policy = approvals::load_yaml(&policy)?;
            let inventory = approvals.project(&snapshot, &policy, probe_only)?;
            print!("{}", serde_yaml_ng::to_string(&inventory)?);
            Ok(0)
        }
        Commands::BaselinePreview {
            snapshot,
            metadata,
            approvals,
            policy,
            inputs,
            membership,
            output,
        } => {
            let snapshot = serde_json::from_slice(&fs::read(snapshot)?)?;
            let metadata = serde_json::from_slice(&fs::read(metadata)?)?;
            let approvals = approvals::load_yaml(&approvals)?;
            let policy = approvals::load_yaml(&policy)?;
            let membership = membership
                .as_deref()
                .map(baseline::read_membership)
                .transpose()?
                .flatten();
            let (files, result) = baseline::compile(
                &inputs,
                &approvals,
                &snapshot,
                &policy,
                &metadata,
                membership.as_ref(),
            )?;
            fs::create_dir(&output)?;
            for (name, bytes) in files {
                write_new(&output.join(name), &bytes)?;
            }
            println!("{}", serde_json::to_string(&result)?);
            Ok(0)
        }
        Commands::Plan {
            snapshot,
            inventory,
            out_dir,
            netbox_site,
            policy,
        } => {
            let snapshot: model::Snapshot =
                serde_json::from_slice(&fs::read(snapshot).context("read snapshot")?)
                    .context("parse snapshot")?;
            let source = fs::read_to_string(inventory).context("read inventory")?;
            let policy: Option<policy::Policy> = policy
                .map(|p| -> Result<_> {
                    serde_yaml_ng::from_str(&fs::read_to_string(p).context("read policy")?)
                        .context("parse policy YAML")
                })
                .transpose()?;
            let (report, candidate) =
                plan::build(&source, &snapshot, netbox_site.as_deref(), policy.as_ref())?;
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder
                .create(&out_dir)
                .with_context(|| format!("create new output directory {}", out_dir.display()))?;
            if let Some(c) = &candidate {
                write_new(&out_dir.join("inventory.candidate.yml"), c.as_bytes())?;
            }
            write_new(
                &out_dir.join("plan.json"),
                &serde_json::to_vec_pretty(&report)?,
            )?;
            println!(
                "{}: {}/{} devices equivalent; {} differences; candidate {}",
                report.site,
                report.equivalent_devices,
                report.expected_devices,
                report.issues.len(),
                if candidate.is_some() {
                    "written"
                } else {
                    "blocked"
                }
            );
            Ok(if candidate.is_some() { 0 } else { 2 })
        }
    }
}
fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
