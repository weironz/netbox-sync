use crate::{
    approvals::{self, Approvals},
    baseline_inventory::{self, Membership, Metadata, Settings},
    baseline_rules,
    model::Snapshot,
    policy::Policy,
    render::Files,
};
#[cfg(unix)]
use anyhow::ensure;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{fs, io, path::Path};

#[cfg(unix)]
use std::{
    io::Write,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) fn read_membership(path: &Path) -> Result<Option<Membership>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("parse approved membership")?,
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn compile(
    inputs: &Path,
    approvals: &Approvals,
    snapshot: &Snapshot,
    policy: &Policy,
    metadata: &Metadata,
    previous: Option<&Membership>,
) -> Result<(Files, Value)> {
    let settings: Settings = approvals::load_yaml(&inputs.join("baseline.yml"))?;
    let fleet = approvals::load_yaml(&inputs.join("fleet_baseline.yml"))?;
    let baseline =
        baseline_inventory::reconcile(approvals, snapshot, policy, &settings, metadata, previous)?;
    let (mut files, counts) = baseline_rules::render(&baseline, fleet)?;
    let mut port_counts = std::collections::BTreeMap::new();
    let mut bf3 = 0;
    for port in baseline
        .compiled
        .ports
        .values()
        .filter(|p| p["expected"] == "up")
    {
        if port["network"] != "ib" || port["interface_type"] == "infiniband" {
            *port_counts.entry(port["network"].clone()).or_insert(0) += 1;
        }
        if port["job"] == "sonic-snmp"
            && port["purpose"] == "服务器存储网"
            && port["peer_device"].to_uppercase().starts_with("B300-")
        {
            bf3 += 1;
        }
    }
    port_counts.insert("bf3".into(), bf3);
    let members = serde_json::to_vec(&baseline.membership)?;
    files.insert("membership.json".into(), members);
    Ok((
        files,
        json!({
            "snapshot_at":snapshot.captured_at_unix,"counts":counts,"retained":baseline.retained,
            "confirmed_cables":baseline.membership.cable_ids.len(),"links":baseline.compiled.links.len(),
            "ports":port_counts,
        }),
    ))
}

#[cfg(unix)]
fn check_rules(stage: &Path, files: &Files, promtool: &Path) -> Result<()> {
    let mut child = Command::new(promtool)
        .args(["check", "rules"])
        .args(
            files
                .keys()
                .filter(|k| k.ends_with(".yml"))
                .map(|p| stage.join(p)),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .context("start promtool")?;
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "promtool rejected generated rules");
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("promtool timed out");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
fn pointer(root: &Path, target: &Path) -> Result<()> {
    let staged = tempfile::tempdir_in(root)?;
    let next = staged.path().join("next");
    std::os::unix::fs::symlink(target, &next)?;
    fs::rename(next, root.join("current"))?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn publish(
    root: &Path,
    files: &Files,
    promtool: &Path,
    prometheus: &str,
) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let current = root.join("current");
    let previous = fs::read_link(&current).context("missing last approved rule generation")?;
    ensure!(
        previous.components().count() == 1
            && previous
                .to_str()
                .is_some_and(|v| v.starts_with("version-") && !v.is_empty()),
        "invalid last approved rule generation"
    );
    ensure!(
        root.join(&previous).is_dir(),
        "last approved rule generation does not exist"
    );
    if files
        .iter()
        .all(|(name, bytes)| fs::read(current.join(name)).is_ok_and(|current| current == *bytes))
    {
        return Ok(previous.to_string_lossy().into_owned());
    }
    let stage = tempfile::Builder::new()
        .prefix("version-")
        .tempdir_in(root)?;
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o755))?;
    for (name, bytes) in files {
        let mut f = fs::File::create_new(stage.path().join(name))?;
        f.set_permissions(fs::Permissions::from_mode(0o644))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    check_rules(stage.path(), files, promtool)?;
    crate::daemon::sync_dir(stage.path())?;
    let name = stage
        .path()
        .file_name()
        .context("missing rule generation identifier")?
        .to_os_string();
    let endpoint = format!("{}/-/reload", prometheus.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let reload = || -> Result<()> {
        let response = client
            .post(&endpoint)
            .send()
            .context("Prometheus reload request")?;
        ensure!(
            response.status().is_success(),
            "Prometheus reload returned HTTP {}",
            response.status()
        );
        Ok(())
    };
    pointer(root, Path::new(&name))?;
    let _ = stage.keep();
    if let Err(err) = crate::daemon::sync_dir(root).and_then(|()| reload()) {
        pointer(root, &previous).context("restore last approved rule generation")?;
        crate::daemon::sync_dir(root).context("persist restored rule generation")?;
        reload().context("reload restored rule generation")?;
        return Err(err);
    }
    Ok(name.to_string_lossy().into_owned())
}

#[cfg(not(unix))]
pub(crate) fn publish(_: &Path, _: &Files, _: &Path, _: &str) -> Result<String> {
    anyhow::bail!("rule publication requires Linux")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        net::TcpListener,
    };

    #[test]
    fn reload_failure_restores_previous_rules() -> Result<()> {
        let root = tempfile::tempdir()?;
        let previous = Path::new("version-previous");
        fs::create_dir(root.path().join(previous))?;
        pointer(root.path(), previous)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let dir = root.path().to_owned();
        let server = thread::spawn(move || {
            for (status, old) in [("500 Internal Server Error", false), ("200 OK", true)] {
                let (mut connection, _) = listener.accept().unwrap();
                let mut request = String::new();
                BufReader::new(&connection).read_line(&mut request).unwrap();
                assert!(request.starts_with("POST /-/reload "));
                assert_eq!(fs::read_link(dir.join("current")).unwrap() == previous, old);
                write!(
                    connection,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
        });
        let files = Files::from([("rules.yml".into(), b"groups: []\n".to_vec())]);
        let result = publish(
            root.path(),
            &files,
            Path::new("/bin/true"),
            &format!("http://{address}"),
        );
        assert!(result.unwrap_err().to_string().contains("HTTP 500"));
        server.join().unwrap();
        assert_eq!(fs::read_link(root.path().join("current"))?, previous);
        Ok(())
    }
}
