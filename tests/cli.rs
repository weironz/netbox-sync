use serde_json::{Value, json};
use std::{fs, process::Command};

const INVENTORY: &str = "version: 1\nsite: test-site\nroles: {switch: {checks: [snmp]}}\ndevices:\n- {host: leaf-01, role: switch, primary: 192.0.2.10}\n- {host: host-01, role: server, primary: 192.0.2.20, bmc: 192.0.2.21}\nport_baseline:\n  connections:\n  - {a: leaf-01/sw1p1, b: host-01/HCA-01, role: server, review: confirmed}\n";

fn sample(address: &str) -> Value {
    json!({
        "schema_version": 1,
        "captured_at_unix": 1,
        "site": {"id": 1, "slug": "test-site"},
        "devices": [
            {"id": 11, "name": "leaf-01", "role": "switch", "status": "active", "primary_ip4": address},
            {"id": 22, "name": "host-01", "role": "server", "status": "active", "primary_ip4": "192.0.2.20/24", "oob_ip": "192.0.2.21/24"}
        ],
        "interfaces": [{"id": 101, "device_id": 11, "name": "sw1p1", "enabled": true}],
        "ip_addresses": [],
        "cables": []
    })
}

fn run_plan(
    address: &str,
    site: Option<&str>,
) -> anyhow::Result<(tempfile::TempDir, std::process::Output)> {
    let dir = tempfile::tempdir()?;
    let inv = dir.path().join("inventory.yml");
    let snapshot = dir.path().join("snapshot.json");
    let out = dir.path().join("out");
    fs::write(&inv, INVENTORY)?;
    fs::write(&snapshot, serde_json::to_vec(&sample(address))?)?;
    let mut c = Command::new(env!("CARGO_BIN_EXE_netbox-sync"));
    c.arg("plan")
        .arg("--snapshot")
        .arg(snapshot)
        .arg("--inventory")
        .arg(inv)
        .arg("--out-dir")
        .arg(out);
    if let Some(site) = site {
        c.args(["--netbox-site", site]);
    }
    let output = c.output()?;
    Ok((dir, output))
}

#[test]
fn equivalent_devices_create_a_candidate_without_removing_a_missing_link() -> anyhow::Result<()> {
    let (dir, out) = run_plan("192.0.2.10/24", None)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let candidate = fs::read_to_string(dir.path().join("out/inventory.candidate.yml"))?;
    let original: serde_yaml_ng::Value = serde_yaml_ng::from_str(INVENTORY)?;
    let generated: serde_yaml_ng::Value = serde_yaml_ng::from_str(&candidate)?;
    assert_eq!(original, generated);
    let report: Value = serde_json::from_slice(&fs::read(dir.path().join("out/plan.json"))?)?;
    assert_eq!(report["candidate_written"], true);
    assert_eq!(report["links"][0]["state"], "interface_missing");
    assert_eq!(
        fs::read_to_string(dir.path().join("inventory.yml"))?,
        INVENTORY
    );
    Ok(())
}

#[test]
fn a_different_primary_address_only_creates_the_diff() -> anyhow::Result<()> {
    let (dir, out) = run_plan("192.0.2.99/24", None)?;
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.path().join("out/plan.json").is_file());
    assert!(!dir.path().join("out/inventory.candidate.yml").exists());
    Ok(())
}

#[test]
fn site_mismatch_is_rejected_before_output() -> anyhow::Result<()> {
    let (dir, out) = run_plan("192.0.2.10/24", Some("other-site"))?;
    assert_eq!(out.status.code(), Some(1));
    assert!(!dir.path().join("out").exists());
    Ok(())
}
