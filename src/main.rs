mod model;
mod netbox;
mod plan;
mod policy;

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
    /// Read NetBox and save a minimal site snapshot. Does not modify NetBox.
    Snapshot {
        #[arg(long)]
        netbox_url: String,
        #[arg(long)]
        site: String,
        #[arg(long)]
        token_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Compare a snapshot with inventory.yml; output a report and, if equivalent, a candidate.
    Plan {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        /// Explicit NetBox site slug if it differs from inventory.site.
        #[arg(long)]
        netbox_site: Option<String>,
        /// Optional site-specific alias and address-purpose policy.
        #[arg(long)]
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
