#![allow(clippy::unwrap_used, reason = "integration test")]
//! End-to-end CLI verification for `S-DX-001` (`canton-rs daemon doctor` and `daemon up` preflight `D-01..D-08`).

use std::collections::BTreeSet;
use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};

static SEQ: AtomicU64 = AtomicU64::new(0);
static PORT_CURSOR: AtomicU16 = AtomicU16::new(31000);

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_canton-rs"))
}

fn sample_dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar")
        .canonicalize()
        .unwrap()
}

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "crs-sdx001-{label}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct DaemonTeardownGuard {
    state_dir: PathBuf,
}

impl Drop for DaemonTeardownGuard {
    fn drop(&mut self) {
        kill_any_pids_in_state_dir(&self.state_dir);
    }
}

fn kill_any_pids_in_state_dir(state_dir: &Path) {
    if state_dir.join("daemon.sock").exists()
        || state_dir.join("daemon.sock").symlink_metadata().is_ok()
    {
        let _ = Command::new(bin())
            .args(["daemon", "down", "--state-dir"])
            .arg(state_dir)
            .args(["--timeout-secs", "4"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let pids_file = state_dir.join("daemon.pids.json");
    if let Ok(raw) = std::fs::read_to_string(&pids_file) {
        if let Ok(v) = serde_json::from_str::<Value>(&raw) {
            if let Some(sup_pid) = v.get("supervisor_pid").and_then(Value::as_u64) {
                let _ = Command::new("kill")
                    .args(["-KILL", &sup_pid.to_string()])
                    .stderr(Stdio::null())
                    .status();
            }
            if let Some(nodes) = v.get("nodes").and_then(Value::as_object) {
                for entry in nodes.values() {
                    if let Some(pid) = entry.get("pid").and_then(Value::as_u64) {
                        let _ = Command::new("kill")
                            .args(["-KILL", &pid.to_string()])
                            .stderr(Stdio::null())
                            .status();
                    }
                }
            }
        }
    }
}

fn kill_process_tree(child: &mut Child, state_dir: &Path) {
    let parent_pid = child.id();
    let kids_out = Command::new("pgrep")
        .args(["-P", &parent_pid.to_string()])
        .output();
    if let Ok(out) = kids_out {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Ok(kpid) = line.trim().parse::<u32>() {
                let _ = Command::new("kill")
                    .args(["-KILL", &kpid.to_string()])
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    kill_any_pids_in_state_dir(state_dir);
}

fn distinct_free_ports(count: usize) -> Vec<u16> {
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let cand = PORT_CURSOR.fetch_add(1, Ordering::Relaxed);
        if !(1024..48000).contains(&cand) || matches!(cand, 3080 | 3901 | 6432 | 6501 | 6502) {
            PORT_CURSOR.store(31000, Ordering::Relaxed);
            continue;
        }
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", cand)) {
            drop(listener);
            out.push(cand);
        }
    }
    out
}

fn check_by_id<'a>(json: &'a Value, id: &str) -> &'a Value {
    json["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("missing check {id} in {json}"))
}

fn run_doctor_cmd(extra_args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .env("CANTON_RS_TEST_MODE", "1")
        .args(["daemon", "doctor"])
        .args(extra_args)
        .output()
        .unwrap()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn recursive_dir_sha256(root: &Path) -> String {
    fn walk(base: &Path, cur: &Path, entries: &mut BTreeSet<(String, Vec<u8>)>) {
        if cur.exists() {
            for entry in std::fs::read_dir(cur).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    entries.insert((rel, b"<DIR>".to_vec()));
                    walk(base, &path, entries);
                } else if meta.is_file() {
                    entries.insert((rel, std::fs::read(&path).unwrap()));
                } else {
                    entries.insert((rel, b"<OTHER>".to_vec()));
                }
            }
        }
    }
    let mut items = BTreeSet::new();
    walk(root, root, &mut items);
    let mut h = Sha256::new();
    for (rel, data) in items {
        h.update(rel.as_bytes());
        h.update(b":");
        h.update(&data);
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

#[test]
fn sdx001_d01_clean_environment() {
    let dir = TempDirGuard::new("d01");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let ports = distinct_free_ports(2);
    let manifest = dir.path().join("canton-daemon.yaml");
    std::fs::write(
        &manifest,
        format!(
            "name: d01-clean\nmetrics_port: 0\nservices:\n  seq1:\n    role: sequencer\n    ports: [\"{}:public\"]\n  p1:\n    role: participant\n    ports: [\"{}:json-api\"]\n    dars: [\"{}\"]\n    depends_on: [seq1]\n",
            ports[0],
            ports[1],
            sample_dar().display(),
        ),
    )
    .unwrap();

    let out = run_doctor_cmd(&[
        "-f",
        &manifest.display().to_string(),
        "--state-dir",
        &state_dir.display().to_string(),
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit=0 on clean environment\nstdout: {stdout}\nstderr: {stderr}"
    );

    let json: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
    for id in ["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9"] {
        assert_eq!(
            check_by_id(&json, id)["status"],
            "ok",
            "expected {id}=ok on clean host: {}",
            check_by_id(&json, id)
        );
    }
    let d10_status = check_by_id(&json, "D10")["status"].as_str().unwrap();
    assert!(
        matches!(d10_status, "ok" | "warn"),
        "D10 must be ok or warn on host: {d10_status}"
    );
}

#[test]
fn sdx001_d02_port_in_use() {
    let dir = TempDirGuard::new("d02");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let busy_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let p_busy = busy_listener.local_addr().unwrap().port();
    let p_free = distinct_free_ports(1)[0];

    let manifest = dir.path().join("canton-daemon.yaml");
    std::fs::write(
        &manifest,
        format!(
            "name: d02-busy\nmetrics_port: 0\nservices:\n  seq1:\n    role: sequencer\n    ports: [\"{p_free}:public\"]\n  p1:\n    role: participant\n    ports: [\"{p_busy}:json-api\"]\n    depends_on: [seq1]\n"
        ),
    )
    .unwrap();

    let out = run_doctor_cmd(&[
        "-f",
        &manifest.display().to_string(),
        "--state-dir",
        &state_dir.display().to_string(),
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit=2, stdout={stdout}"
    );
    let json: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["exit_code"], 2);
    let d3 = check_by_id(&json, "D3");
    assert_eq!(d3["status"], "fail", "expected D3=fail: {d3}");
    assert!(
        d3["message"]
            .as_str()
            .unwrap()
            .contains(&p_busy.to_string()),
        "D3 message must identify occupied port {p_busy}: {d3}"
    );
    assert!(d3["fix"].as_str().is_some(), "D3 fail must carry fix: {d3}");
    // D1..D10 must all run without short-circuiting.
    assert_eq!(json["checks"].as_array().unwrap().len(), 10);
    assert_eq!(check_by_id(&json, "D9")["status"], "ok");
}

#[test]
fn sdx001_d03_protected_hub_port() {
    let dir = TempDirGuard::new("d03");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let manifest = dir.path().join("canton-daemon.yaml");
    std::fs::write(
        &manifest,
        "name: d03-hub\nmetrics_port: 0\nservices:\n  seq1:\n    role: sequencer\n    ports: [\"6432:public\"]\n",
    )
    .unwrap();

    let out = run_doctor_cmd(&[
        "-f",
        &manifest.display().to_string(),
        "--state-dir",
        &state_dir.display().to_string(),
        "--format",
        "json",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit=2, stdout={stdout}"
    );
    let json: Value = serde_json::from_str(&stdout).unwrap();
    let d2 = check_by_id(&json, "D2");
    assert_eq!(
        d2["status"], "fail",
        "D2 must fail on protected hub port 6432: {d2}"
    );
    assert!(d2["message"].as_str().unwrap().contains("6432"), "{d2}");
}

#[test]
fn sdx001_d04_port_overflow_no_wrap_no_panic() {
    let dir = TempDirGuard::new("d04");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    for (base_port, label) in [(60000u16, "60000"), (61000u16, "61000")] {
        let manifest = dir.path().join(format!("overflow-{label}.yaml"));
        std::fs::write(
            &manifest,
            format!(
                "name: d04-overflow\nmetrics_port: 0\nservices:\n  seq1:\n    role: sequencer\n    ports: [\"{base_port}:public\"]\n"
            ),
        )
        .unwrap();

        let out = run_doctor_cmd(&[
            "-f",
            &manifest.display().to_string(),
            "--port-offset",
            "6000",
            "--state-dir",
            &state_dir.display().to_string(),
            "--format",
            "json",
        ]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("panicked"),
            "port overflow must never panic: {stderr}"
        );
        assert_eq!(
            out.status.code(),
            Some(2),
            "port overflow ({base_port}+6000) must exit 2\nstdout: {stdout}\nstderr: {stderr}"
        );

        let json: Value = serde_json::from_str(&stdout).unwrap();
        let d1 = check_by_id(&json, "D1");
        assert_eq!(
            d1["status"], "fail",
            "D1 must Fail on {base_port}+6000 overflow: {d1}"
        );
        let msg = d1["message"].as_str().unwrap();
        assert!(
            msg.contains("overflow") && msg.contains("65535"),
            "D1 must report u16 overflow rather than wrapped port: {msg}"
        );
        assert!(
            json["ports"]["seq1.public"].is_null(),
            "overflowing port must map to null rather than wrapping: {}",
            json["ports"]
        );
    }
}

#[test]
fn sdx001_d05_cli_purity() {
    let dir = TempDirGuard::new("d05");
    let existing_state = dir.path().join("existing-state");
    std::fs::create_dir_all(&existing_state).unwrap();
    std::fs::write(existing_state.join("sentinel.txt"), b"keep-exact-bytes").unwrap();
    let ghost_state = dir.path().join("nonexistent-state");

    let p_free = distinct_free_ports(1)[0];
    let busy_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let p_busy = busy_listener.local_addr().unwrap().port();
    let manifest_ok = dir.path().join("clean.yaml");
    std::fs::write(
        &manifest_ok,
        format!(
            "name: d05-clean\nmetrics_port: 0\nservices:\n  seq1:\n    role: sequencer\n    ports: [\"{p_free}:public\"]\n"
        ),
    )
    .unwrap();
    let manifest_busy = dir.path().join("busy.yaml");
    std::fs::write(
        &manifest_busy,
        format!(
            "name: d05-busy\nmetrics_port: 0\nservices:\n  seq1:\n    role: sequencer\n    ports: [\"{p_busy}:public\"]\n"
        ),
    )
    .unwrap();

    let h_before = recursive_dir_sha256(&existing_state);

    let out1 = run_doctor_cmd(&[
        "-f",
        &manifest_ok.display().to_string(),
        "--state-dir",
        &existing_state.display().to_string(),
        "--format",
        "json",
    ]);
    assert_eq!(out1.status.code(), Some(0));

    let out2 = run_doctor_cmd(&[
        "-f",
        &manifest_busy.display().to_string(),
        "--state-dir",
        &existing_state.display().to_string(),
        "--format",
        "json",
    ]);
    assert_eq!(out2.status.code(), Some(2));

    let h_after = recursive_dir_sha256(&existing_state);
    assert_eq!(
        h_before, h_after,
        "D-A1 violation: doctor altered existing state_dir contents"
    );

    // Nonexistent state_dir must remain nonexistent.
    let out3 = run_doctor_cmd(&[
        "-f",
        &manifest_ok.display().to_string(),
        "--state-dir",
        &ghost_state.display().to_string(),
    ]);
    assert_eq!(out3.status.code(), Some(0));
    assert!(
        !ghost_state.exists(),
        "D-A1 violation: doctor created state_dir"
    );

    // Free planned port must remain unbound (`L(H_after) == L(H_before)`).
    let rebind = TcpListener::bind(("127.0.0.1", p_free));
    assert!(
        rebind.is_ok(),
        "D-A1 violation: free port {p_free} remained occupied after doctor: {:?}",
        rebind.err()
    );
    drop(busy_listener);
}

#[test]
fn sdx001_d06_up_preflight_blocks_spawn() {
    let dir = TempDirGuard::new("d06");
    let state_dir = dir.path().join("up-state-must-not-exist");
    let p_seq = distinct_free_ports(1)[0];
    let busy_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let p_busy = busy_listener.local_addr().unwrap().port();

    let manifest = dir.path().join("canton-daemon.yaml");
    std::fs::write(
        &manifest,
        format!(
            "name: d06-up-block\nmetrics_port: 0\nservices:\n  seq1:\n    role: sequencer\n    ports: [\"{p_seq}:public\"]\n    storage:\n      type: files\n  p1:\n    role: participant\n    ports: [\"{p_busy}:json-api\"]\n    dars: [\"{}\"]\n    depends_on: [seq1]\n",
            sample_dar().display(),
        ),
    )
    .unwrap();

    let mut child = Command::new(bin())
        .env("CANTON_RS_TEST_MODE", "1")
        .args(["daemon", "up", "-f"])
        .arg(&manifest)
        .args(["--state-dir"])
        .arg(&state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut exit_status = None;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            exit_status = Some(status);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let state_created_before_cleanup = state_dir.exists();
    let seq_bound_before_cleanup = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], p_seq)),
        Duration::from_millis(100),
    )
    .is_ok();
    let kept_running = exit_status.is_none();

    let mut stderr = String::new();
    if kept_running {
        kill_process_tree(&mut child, &state_dir);
    } else {
        let _ = child.wait();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
    }

    assert!(
        !state_created_before_cleanup && !seq_bound_before_cleanup && !kept_running,
        "D-A3/A2 violation: daemon up spawned child processes or created state_dir before doctor preflight refused (state_created={state_created_before_cleanup}, seq_bound={seq_bound_before_cleanup}, kept_running={kept_running})"
    );
    let code = exit_status.and_then(|s| s.code());
    assert_eq!(
        code,
        Some(2),
        "D-A3 violation: expected exit code 2 from daemon up preflight failure, got {code:?}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains(&p_busy.to_string()),
        "D-A3 violation: daemon up failure must name occupied port {p_busy}: {stderr}"
    );
    drop(busy_listener);
}

#[test]
fn sdx001_d07_running_instance_reports_running() {
    let dir = TempDirGuard::new("d07");
    let state_dir = dir.path().join("running-state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let _guard = DaemonTeardownGuard {
        state_dir: state_dir.clone(),
    };
    let p_seq = distinct_free_ports(1)[0];

    let manifest = dir.path().join("canton-daemon.yaml");
    std::fs::write(
        &manifest,
        format!(
            "name: d07-running\nmetrics_port: 0\nservices:\n  seq1:\n    role: sequencer\n    ports: [\"{p_seq}:public\"]\n    storage:\n      type: files\n"
        ),
    )
    .unwrap();

    let up_out = Command::new(bin())
        .env("CANTON_RS_TEST_MODE", "1")
        .args(["daemon", "up", "-d", "-f"])
        .arg(&manifest)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()
        .unwrap();
    assert!(
        up_out.status.success(),
        "daemon up -d failed (status={:?})\nstdout: {}\nstderr: {}",
        up_out.status.code(),
        String::from_utf8_lossy(&up_out.stdout),
        String::from_utf8_lossy(&up_out.stderr)
    );

    let doc_out = run_doctor_cmd(&[
        "-f",
        &manifest.display().to_string(),
        "--state-dir",
        &state_dir.display().to_string(),
        "--format",
        "json",
    ]);
    let doc_stdout = String::from_utf8_lossy(&doc_out.stdout);
    let doc_stderr = String::from_utf8_lossy(&doc_out.stderr);
    assert_eq!(
        doc_out.status.code(),
        Some(0),
        "doctor against own running instance must exit 0\nstdout: {doc_stdout}\nstderr: {doc_stderr}"
    );
    let json: Value = serde_json::from_str(&doc_stdout).unwrap();
    assert_eq!(json["exit_code"], 0);
    let d3 = check_by_id(&json, "D3");
    assert_eq!(
        d3["status"], "running",
        "D3 must report 'running' when own instance owns ports: {d3}"
    );

    let down_out = Command::new(bin())
        .args(["daemon", "down", "--state-dir"])
        .arg(&state_dir)
        .args(["--clean-files", "--timeout-secs", "10"])
        .output()
        .unwrap();
    assert!(
        down_out.status.success(),
        "daemon down failed: {}",
        String::from_utf8_lossy(&down_out.stderr)
    );
}

#[test]
fn sdx001_d08_json_schema_determinism() {
    let dir = TempDirGuard::new("d08");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let busy_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let p_busy = busy_listener.local_addr().unwrap().port();
    let p_free = distinct_free_ports(1)[0];

    let manifest = dir.path().join("canton-daemon.yaml");
    std::fs::write(
        &manifest,
        format!(
            "name: d08-json\nmetrics_port: 0\nservices:\n  seq1:\n    role: sequencer\n    ports: [\"{p_free}:public\"]\n  p1:\n    role: participant\n    ports: [\"{p_busy}:json-api\"]\n    depends_on: [seq1]\n"
        ),
    )
    .unwrap();

    let run1 = run_doctor_cmd(&[
        "-f",
        &manifest.display().to_string(),
        "--state-dir",
        &state_dir.display().to_string(),
        "--format",
        "json",
    ]);
    let run2 = run_doctor_cmd(&[
        "-f",
        &manifest.display().to_string(),
        "--state-dir",
        &state_dir.display().to_string(),
        "--format",
        "json",
    ]);
    let text_run = run_doctor_cmd(&[
        "-f",
        &manifest.display().to_string(),
        "--state-dir",
        &state_dir.display().to_string(),
        "--format",
        "text",
    ]);

    assert_eq!(run1.status.code(), Some(2));
    assert_eq!(run2.status.code(), Some(2));
    assert_eq!(text_run.status.code(), Some(2));

    // A1 byte determinism: h(out1) == h(out2).
    assert_eq!(
        sha256_bytes(&run1.stdout),
        sha256_bytes(&run2.stdout),
        "A1 determinism failure: doctor --format json output differed across identical runs"
    );

    let json: Value = serde_json::from_slice(&run1.stdout).unwrap();
    assert_eq!(json["schema"], "canton-rs.doctor/1");
    assert_eq!(json["exit_code"], 2);
    let obj_keys: Vec<&String> = json.as_object().unwrap().keys().collect();
    assert_eq!(obj_keys, vec!["schema", "exit_code", "ports", "checks"]);

    let port_keys: Vec<&String> = json["ports"].as_object().unwrap().keys().collect();
    let mut sorted_port_keys = port_keys.clone();
    sorted_port_keys.sort();
    assert_eq!(
        port_keys, sorted_port_keys,
        "ports JSON keys must be sorted"
    );

    let checks = json["checks"].as_array().unwrap();
    let ids: Vec<&str> = checks.iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        vec!["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"]
    );
    for c in checks {
        let keys: Vec<&String> = c.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["id", "status", "message", "fix"]);
    }

    // D-A4 isomorphism between text and JSON views of R.
    let text_out = String::from_utf8_lossy(&text_run.stdout);
    let d3 = check_by_id(&json, "D3");
    assert!(
        text_out.contains(&format!(
            "[D3 ] fail    {}",
            d3["message"].as_str().unwrap()
        )),
        "text output must render exact D3 message from R:\ntext={text_out}\njson={d3}"
    );
}
