use serde_json::{Value, json};
use std::{fs, process::Command};

const INVENTORY: &str = "version: 1\nsite: test-site\nroles: {switch: {checks: [snmp]}}\ndevices:\n- {host: leaf-01, role: switch, primary: 192.0.2.10}\n- {host: host-01, role: server, primary: 192.0.2.20, bmc: 192.0.2.21}\nport_baseline:\n  source: {audited_at_utc: \"2026-01-01T00:00:00Z\"}\n  connections:\n  - {a: leaf-01/sw1p1, b: host-01/HCA-01, role: server, review: confirmed}\n";

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
    assert_eq!(candidate, INVENTORY);
    let report: Value = serde_json::from_slice(&fs::read(dir.path().join("out/plan.json"))?)?;
    assert_eq!(report["candidate_written"], true);
    assert_eq!(report["links"][0]["state"], "interface_missing");
    assert_eq!(
        report["links"][0]["missing_endpoints"],
        json!(["host-01/HCA-01"])
    );
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

const POLICY: &str = "version: 1\ninventory_site: test-site\nnetbox_site: test-site\naliases:\n  host-01: {device_id: 22, netbox_name: registered-host}\nbusiness_ip_tag_by_role: {server: monitoring-biz}\nrequire_oob_roles: [server]\n";

fn run_policy(
    ambiguous: bool,
    wrong_oob_owner: bool,
    policy: &str,
) -> anyhow::Result<(tempfile::TempDir, std::process::Output)> {
    let dir = tempfile::tempdir()?;
    let inv = dir.path().join("inventory.yml");
    let snapshot = dir.path().join("snapshot.json");
    let policy_file = dir.path().join("policy.yml");
    let out = dir.path().join("out");
    let mut s = sample("192.0.2.10/24");
    s["devices"][1]["name"] = json!("registered-host");
    s["devices"][1]["primary_ip4"] = json!("192.0.2.21/24");
    s["interfaces"].as_array_mut().unwrap().extend([
        json!({"id": 102, "device_id": 22, "name": "bond0", "enabled": true}),
        json!({"id": 103, "device_id": 22, "name": "BMC", "enabled": true}),
    ]);
    s["ip_addresses"] = json!([
        {"id": 201, "address": "192.0.2.20/24", "interface_id": 102, "status": "active", "tags": ["monitoring-biz"]},
        {"id": 202, "address": "192.0.2.21/24", "interface_id": if wrong_oob_owner { 101 } else { 103 }, "status": "active"}
    ]);
    if ambiguous {
        s["ip_addresses"].as_array_mut().unwrap().push(json!({"id":203,"address":"192.0.2.99/24","interface_id":102,"status":"active","tags":["monitoring-biz"]}));
    }
    fs::write(&inv, INVENTORY)?;
    fs::write(&snapshot, serde_json::to_vec(&s)?)?;
    fs::write(&policy_file, policy)?;
    let output = Command::new(env!("CARGO_BIN_EXE_netbox-sync"))
        .arg("plan")
        .arg("--snapshot")
        .arg(snapshot)
        .arg("--inventory")
        .arg(inv)
        .arg("--policy")
        .arg(policy_file)
        .arg("--out-dir")
        .arg(out)
        .output()?;
    Ok((dir, output))
}

#[test]
fn policy_uses_exact_alias_and_tagged_business_ip_instead_of_bmc_primary() -> anyhow::Result<()> {
    let (dir, out) = run_policy(false, false, POLICY)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let p: Value = serde_json::from_slice(&fs::read(dir.path().join("out/plan.json"))?)?;
    let h = p["resolved_devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["host"] == "host-01")
        .unwrap();
    assert_eq!(h["business_ip"], "192.0.2.20");
    assert_eq!(h["bmc_ip"], "192.0.2.21");
    assert_eq!(h["netbox_id"], 22);
    let candidate: serde_yaml_ng::Value = serde_yaml_ng::from_str(&fs::read_to_string(
        dir.path().join("out/inventory.candidate.yml"),
    )?)?;
    assert_eq!(
        candidate,
        serde_yaml_ng::from_str::<serde_yaml_ng::Value>(INVENTORY)?
    );
    Ok(())
}

#[test]
fn policy_blocks_ambiguous_business_tags() -> anyhow::Result<()> {
    let (dir, out) = run_policy(true, false, POLICY)?;
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&fs::read(dir.path().join("out/plan.json"))?)?;
    assert_eq!(report["issues"][0]["field"], "business_tag");
    assert!(!dir.path().join("out/inventory.candidate.yml").exists());
    Ok(())
}

#[test]
fn policy_rejects_alias_id_with_different_name() -> anyhow::Result<()> {
    let (dir, out) = run_policy(
        false,
        false,
        &POLICY.replace("registered-host", "different-device"),
    )?;
    assert_eq!(out.status.code(), Some(1));
    assert!(!dir.path().join("out").exists());
    Ok(())
}

#[test]
fn policy_rejects_an_oob_ip_assigned_to_another_device() -> anyhow::Result<()> {
    let (dir, out) = run_policy(false, true, POLICY)?;
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&fs::read(dir.path().join("out/plan.json"))?)?;
    assert_eq!(report["issues"][0]["field"], "oob");
    assert!(!dir.path().join("out/inventory.candidate.yml").exists());
    Ok(())
}

#[test]
fn plan_accepts_environment_and_cli_takes_precedence() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let snapshot = dir.path().join("snapshot.json");
    let inventory = dir.path().join("inventory.yml");
    let out = dir.path().join("plan");
    let shadow = dir.path().join("shadow");
    fs::write(&snapshot, serde_json::to_vec(&sample("192.0.2.10/24"))?)?;
    fs::write(&inventory, INVENTORY)?;
    let mut plan = Command::new(env!("CARGO_BIN_EXE_netbox-sync"));
    plan.arg("plan")
        .env("NETBOX_SNAPSHOT_FILE", &snapshot)
        .env("NETBOX_INVENTORY_FILE", &inventory)
        .env("NETBOX_SITE", "test-site")
        .env("NETBOX_PLAN_DIR", &out)
        .env_remove("NETBOX_POLICY_FILE");
    let result = plan.output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(out.join("inventory.candidate.yml"))?,
        INVENTORY
    );
    let result = plan
        .env("NETBOX_SITE", "wrong-site")
        .arg("--netbox-site")
        .arg("test-site")
        .arg("--out-dir")
        .arg(&shadow)
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(out.join("plan.json"))?,
        fs::read(shadow.join("plan.json"))?
    );
    Ok(())
}

#[test]
fn snapshot_resolves_env_and_cli_before_reading_token_file() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_netbox-sync"))
        .arg("snapshot")
        .env("NETBOX_URL", "http://example.invalid")
        .env("NETBOX_SITE", "test-site")
        .env("NETBOX_TOKEN_FILE", dir.path().join("missing-token"))
        .env("NETBOX_SNAPSHOT_FILE", dir.path().join("snapshot.json"))
        .args(["--netbox-url", "https://example.invalid"])
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("read token file"));
    assert!(!dir.path().join("snapshot.json").exists());
    Ok(())
}

#[test]
fn run_cli_overrides_environment_and_failed_fetch_preserves_last_success() -> anyhow::Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let dir = tempfile::tempdir()?;
    let state = dir.path().join("state");
    let prom = dir.path().join("prom");
    let vm = dir.path().join("vm");
    for p in [&state, &prom, &vm] {
        fs::create_dir(p)?;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let status = state.join("status.json");
    fs::write(
        &status,
        serde_json::to_vec(&json!({
            "site": "test-site",
            "last_attempt": now - 10,
            "last_success": now - 10,
            "generations": ["version-prom", "version-vm"],
        }))?,
    )?;
    let out = Command::new(env!("CARGO_BIN_EXE_netbox-sync"))
        .arg("run")
        .env("NETBOX_URL", "https://example.invalid")
        .env("NETBOX_SITE", "test-site")
        .env("NETBOX_TOKEN_FILE", dir.path().join("missing-token"))
        .env("NETBOX_INVENTORY_FILE", dir.path().join("inventory.yml"))
        .env("NETBOX_POLICY_FILE", dir.path().join("policy.yml"))
        .env("NETBOX_RENDER_FILE", dir.path().join("render.yml"))
        .env("NETBOX_TEMPLATES_DIR", dir.path())
        .env("NETBOX_OUTPUT_DIR", &state)
        .env("NETBOX_PROMETHEUS_PUBLISH_DIR", &prom)
        .env("NETBOX_VMAGENT_PUBLISH_DIR", &vm)
        .env("NETBOX_SYNC_INTERVAL", "1m")
        .env("NETBOX_PORT_MODE", "audit")
        .env("NETBOX_RUN_ONCE", "true")
        .args(["--netbox-url", "http://example.invalid"])
        .output()?;
    assert_eq!(out.status.code(), Some(2));
    let saved: Value = serde_json::from_slice(&fs::read(&status)?)?;
    assert!(
        saved["last_error"]
            .as_str()
            .unwrap()
            .contains("must be HTTPS")
    );
    assert_eq!(saved["last_success"], now - 10);
    assert_eq!(saved["generations"], json!(["version-prom", "version-vm"]));
    assert!(!prom.join("current").exists() && !vm.join("current").exists());
    let healthy = Command::new(env!("CARGO_BIN_EXE_netbox-sync"))
        .arg("status")
        .env("NETBOX_OUTPUT_DIR", &state)
        .env("NETBOX_MAX_AGE", "1h")
        .output()?;
    assert!(healthy.status.success());
    Ok(())
}
