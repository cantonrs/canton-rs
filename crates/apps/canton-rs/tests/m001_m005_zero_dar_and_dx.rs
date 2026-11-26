//! E2E integration tests for `M-001` (zero-DAR boot, embedded `--with-sample-dar`, `doctor [D9]`,
//! `daemon up` rollback) and `M-005` (path normalization without `././`, `daemon remove --force`).

#![allow(clippy::unwrap_used, reason = "integration test")]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn bin() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("canton-rs")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn sample_dar() -> PathBuf {
    repo_root().join("contracts/target/sample-contract.dar")
}

fn unique_dir(tag: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("m001-{tag}-{}-{seq}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("work")).expect("mkdir work");
    fs::create_dir_all(root.join("xdg")).expect("mkdir xdg");
    root
}

fn run_cli(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .current_dir(cwd)
        .env("XDG_STATE_HOME", xdg)
        .env_remove("CANTON_RS_TEST_MODE")
        .env_remove("CANTON_RS_PG_URL")
        .env_remove("CANTON_RS_STATE_PG_URL")
        .args(args)
        .output()
        .expect("run canton-rs")
}

fn http_call(
    port: u16,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> (u16, String) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("connect 127.0.0.1:{port} failed: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("set read timeout");
    let body_bytes = body.unwrap_or(&[]);
    let ct_header = content_type
        .map(|ct| format!("Content-Type: {ct}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{ct_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream.write_all(req.as_bytes()).expect("write req head");
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes).expect("write req body");
    }
    stream.flush().expect("flush");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp_body.to_string())
}

fn port_is_listening(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok()
}

struct InstanceGuard {
    cwd: PathBuf,
    xdg: PathBuf,
    name: String,
    root: PathBuf,
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        let _ = run_cli(
            &self.cwd,
            &self.xdg,
            &["daemon", "remove", "--name", &self.name, "--force"],
        );
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn m001_zero_dar_empty_dir_init_doctor_up_dynamic_upload_and_m005_path_norm() {
    let root = unique_dir("zero");
    let work = root.join("work");
    let xdg = root.join("xdg");
    let inst = "m1-zero";
    let offset = 18_100u16;
    let json_port = 7575 + offset;
    let seq_port = 5018 + offset;
    let med_port = 5017 + offset;
    let _guard = InstanceGuard {
        cwd: work.clone(),
        xdg: xdg.clone(),
        name: inst.to_string(),
        root,
    };

    // 1. `daemon init` in empty dir outside repo -> `dars: []`, no sample DAR extracted.
    let init_out = run_cli(&work, &xdg, &["daemon", "init", "-o", "canton-daemon.yaml"]);
    assert!(
        init_out.status.success(),
        "daemon init failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    let yaml_text = fs::read_to_string(work.join("canton-daemon.yaml")).expect("read yaml");
    assert!(yaml_text.contains("dars: []"), "{yaml_text}");
    assert!(!work.join("sample-contract.dar").exists());

    // 2. `daemon config` normalizes relative paths without `././` (`M-005`).
    let cfg_out = run_cli(
        &work,
        &xdg,
        &["daemon", "config", "-f", "canton-daemon.yaml"],
    );
    assert!(
        cfg_out.status.success(),
        "daemon config failed: {}",
        String::from_utf8_lossy(&cfg_out.stderr)
    );
    let cfg_stdout = String::from_utf8_lossy(&cfg_out.stdout);
    assert!(
        !cfg_stdout.contains("././"),
        "daemon config must normalize ././ paths:\n{cfg_stdout}"
    );

    // 3. `daemon doctor` passes `[D9] ok` with zero DARs and exit 0.
    let offset_s = offset.to_string();
    let doc_out = run_cli(
        &work,
        &xdg,
        &[
            "daemon",
            "doctor",
            "-f",
            "canton-daemon.yaml",
            "--name",
            inst,
            "--port-offset",
            &offset_s,
        ],
    );
    let doc_stdout = String::from_utf8_lossy(&doc_out.stdout);
    assert!(
        doc_out.status.success(),
        "daemon doctor failed (code {:?}):\n{doc_stdout}\n{}",
        doc_out.status.code(),
        String::from_utf8_lossy(&doc_out.stderr)
    );
    assert!(
        doc_stdout.contains("[D9 ] ok") && doc_stdout.contains("no DAR files configured"),
        "expected D9 ok for zero-DAR:\n{doc_stdout}"
    );
    assert!(!doc_stdout.contains("././"), "{doc_stdout}");

    // 4. `daemon up -d` succeeds with zero DARs!
    let up_out = run_cli(
        &work,
        &xdg,
        &[
            "daemon",
            "up",
            "-f",
            "canton-daemon.yaml",
            "--name",
            inst,
            "--port-offset",
            &offset_s,
            "-d",
        ],
    );
    assert!(
        up_out.status.success(),
        "daemon up failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&up_out.stdout),
        String::from_utf8_lossy(&up_out.stderr)
    );

    // 5. `/v2/version`, `/v2/parties`, and `/v2/packages` answer 200 on zero-DAR participant,
    //    and `sample-contract` is NOT loaded yet (negative control before dynamic upload).
    let (v_status, v_body) = http_call(json_port, "GET", "/v2/version", None, None);
    assert_eq!(v_status, 200, "GET /v2/version failed: {v_body}");
    let (p_status, p_body) = http_call(json_port, "GET", "/v2/parties", None, None);
    assert_eq!(p_status, 200, "GET /v2/parties failed: {p_body}");
    let (pkg_status, pkg_body) = http_call(json_port, "GET", "/v2/packages", None, None);
    assert_eq!(pkg_status, 200, "GET /v2/packages failed: {pkg_body}");
    let pkg_before: Vec<String> = serde_json::from_str::<Value>(&pkg_body)
        .expect("parse /v2/packages")["packageIds"]
        .as_array()
        .expect("packageIds array")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let alloc_req = serde_json::json!({ "partyIdHint": "AliceZero" }).to_string();
    let (al_status, al_body) = http_call(
        json_port,
        "POST",
        "/v2/parties",
        Some("application/json"),
        Some(alloc_req.as_bytes()),
    );
    assert_eq!(al_status, 200, "party allocation failed: {al_body}");
    let al_json: Value = serde_json::from_str(&al_body).expect("parse allocate party");
    let party = al_json["partyDetails"]["party"]
        .as_str()
        .expect("party id")
        .to_string();

    let submit_before = serde_json::json!({
        "commands": [{
            "CreateCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": {
                    "bank": party,
                    "owner": party,
                    "auditor": party,
                    "assetSymbol": "USD",
                    "amount": "100.0"
                }
            }
        }],
        "commandId": "m001-zero-before-upload",
        "actAs": [party],
        "userId": "test-user"
    })
    .to_string();
    let (pre_status, pre_body) = http_call(
        json_port,
        "POST",
        "/v2/commands/submit-and-wait",
        Some("application/json"),
        Some(submit_before.as_bytes()),
    );
    assert!(
        (400..500).contains(&pre_status),
        "zero-DAR participant must reject unknown template before upload (got {pre_status}): {pre_body}"
    );

    // 6. Dynamically upload `sample-contract.dar` via `POST /v2/packages` and create a contract!
    let dar_bytes = fs::read(sample_dar()).expect("read sample-contract.dar");
    let (up_dar_status, up_dar_body) = http_call(
        json_port,
        "POST",
        "/v2/packages",
        Some("application/octet-stream"),
        Some(&dar_bytes),
    );
    assert_eq!(
        up_dar_status, 200,
        "dynamic DAR upload failed ({up_dar_status}): {up_dar_body}"
    );
    let (pkg2_status, pkg2_body) = http_call(json_port, "GET", "/v2/packages", None, None);
    assert_eq!(
        pkg2_status, 200,
        "GET /v2/packages after upload: {pkg2_body}"
    );
    let pkg_after: Vec<String> = serde_json::from_str::<Value>(&pkg2_body)
        .expect("parse /v2/packages after")["packageIds"]
        .as_array()
        .expect("packageIds array")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert!(
        pkg_after.len() > pkg_before.len(),
        "dynamic DAR upload must add packages (before={}, after={})",
        pkg_before.len(),
        pkg_after.len()
    );

    let submit_req = serde_json::json!({
        "commands": [{
            "CreateCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": {
                    "bank": party,
                    "owner": party,
                    "auditor": party,
                    "assetSymbol": "USD",
                    "amount": "100.0"
                }
            }
        }],
        "commandId": "m001-zero-upload-create-1",
        "actAs": [party],
        "userId": "test-user"
    })
    .to_string();
    let (sub_status, sub_body) = http_call(
        json_port,
        "POST",
        "/v2/commands/submit-and-wait",
        Some("application/json"),
        Some(submit_req.as_bytes()),
    );
    assert_eq!(
        sub_status, 200,
        "create after dynamic DAR upload failed ({sub_status}): {sub_body}"
    );

    // 7. `daemon remove --force` cleans up cleanly with 0 stray listeners.
    let rm_out = run_cli(
        &work,
        &xdg,
        &["daemon", "remove", "--name", inst, "--force"],
    );
    assert!(
        rm_out.status.success(),
        "daemon remove --force failed: {}",
        String::from_utf8_lossy(&rm_out.stderr)
    );
    assert!(
        !port_is_listening(json_port),
        "participant port still bound"
    );
    assert!(!port_is_listening(seq_port), "sequencer port still bound");
    assert!(!port_is_listening(med_port), "mediator port still bound");
}

#[test]
fn m001_with_sample_dar_empty_dir_creates_asset_holding_immediately() {
    let root = unique_dir("sample");
    let work = root.join("work");
    let xdg = root.join("xdg");
    let inst = "m1-sample";
    let offset = 18_200u16;
    let json_port = 7575 + offset;
    let seq_port = 5018 + offset;
    let med_port = 5017 + offset;
    let _guard = InstanceGuard {
        cwd: work.clone(),
        xdg: xdg.clone(),
        name: inst.to_string(),
        root,
    };

    let init_out = run_cli(
        &work,
        &xdg,
        &[
            "daemon",
            "init",
            "--with-sample-dar",
            "-o",
            "canton-daemon.yaml",
        ],
    );
    assert!(
        init_out.status.success(),
        "daemon init --with-sample-dar failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    let extracted = work.join("sample-contract.dar");
    assert!(extracted.is_file(), "sample-contract.dar must be extracted");
    assert_eq!(
        fs::read(&extracted).expect("read extracted"),
        fs::read(sample_dar()).expect("read canonical sample-contract.dar")
    );

    let offset_s = offset.to_string();
    let doc_out = run_cli(
        &work,
        &xdg,
        &[
            "daemon",
            "doctor",
            "-f",
            "canton-daemon.yaml",
            "--name",
            inst,
            "--port-offset",
            &offset_s,
        ],
    );
    let doc_stdout = String::from_utf8_lossy(&doc_out.stdout);
    assert!(
        doc_out.status.success(),
        "daemon doctor failed:\n{doc_stdout}\n{}",
        String::from_utf8_lossy(&doc_out.stderr)
    );
    assert!(
        doc_stdout.contains("[D9 ] ok") && doc_stdout.contains("verified 1 DAR archive(s)"),
        "{doc_stdout}"
    );

    let up_out = run_cli(
        &work,
        &xdg,
        &[
            "daemon",
            "up",
            "-f",
            "canton-daemon.yaml",
            "--name",
            inst,
            "--port-offset",
            &offset_s,
            "-d",
        ],
    );
    assert!(
        up_out.status.success(),
        "daemon up failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&up_out.stdout),
        String::from_utf8_lossy(&up_out.stderr)
    );

    let alloc_req = serde_json::json!({ "partyIdHint": "BobSample" }).to_string();
    let (al_status, al_body) = http_call(
        json_port,
        "POST",
        "/v2/parties",
        Some("application/json"),
        Some(alloc_req.as_bytes()),
    );
    assert_eq!(al_status, 200, "party allocation failed: {al_body}");
    let al_json: Value = serde_json::from_str(&al_body).expect("parse allocate party");
    let party = al_json["partyDetails"]["party"]
        .as_str()
        .expect("party id")
        .to_string();

    let submit_req = serde_json::json!({
        "commands": [{
            "CreateCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": {
                    "bank": party,
                    "owner": party,
                    "auditor": party,
                    "assetSymbol": "EUR",
                    "amount": "42.0"
                }
            }
        }],
        "commandId": "m001-sample-create-1",
        "actAs": [party],
        "userId": "test-user"
    })
    .to_string();
    let (sub_status, sub_body) = http_call(
        json_port,
        "POST",
        "/v2/commands/submit-and-wait",
        Some("application/json"),
        Some(submit_req.as_bytes()),
    );
    assert_eq!(
        sub_status, 200,
        "immediate AssetHolding create failed ({sub_status}): {sub_body}"
    );

    let rm_out = run_cli(
        &work,
        &xdg,
        &["daemon", "remove", "--name", inst, "--force"],
    );
    assert!(
        rm_out.status.success(),
        "daemon remove --force failed: {}",
        String::from_utf8_lossy(&rm_out.stderr)
    );
    assert!(!port_is_listening(json_port));
    assert!(!port_is_listening(seq_port));
    assert!(!port_is_listening(med_port));
}

#[test]
fn m001_negative_control_broken_dar_fails_doctor_and_rolls_back_upstream_slots() {
    let root = unique_dir("rollback");
    let work = root.join("work");
    let xdg = root.join("xdg");
    let state_dir = root.join("rollback-state");
    let offset = 18_300u16;
    let seq_port = 5018 + offset;
    let med_port = 5017 + offset;
    let json_port = 7575 + offset;

    let broken_yaml = work.join("broken.yaml");
    fs::write(
        &broken_yaml,
        r#"name: rollback-test
synchronizer: rb-sync
state_dir: ./unused
metrics_port: 0
services:
  sequencer1:
    role: sequencer
    ports: ["5018:public", "5019:metrics"]
    restart: no
  mediator1:
    role: mediator
    ports: ["5017:admin"]
    depends_on: [sequencer1]
    restart: no
  participant1:
    role: participant
    ports: ["7575:json-api"]
    dars: ["./does-not-exist.dar"]
    depends_on: [sequencer1, mediator1]
    restart: no
"#,
    )
    .expect("write broken yaml");

    // (a) Negative control: `daemon doctor` rejects missing configured DAR at [D9] (exit 2).
    let offset_s = offset.to_string();
    let doc_out = run_cli(
        &work,
        &xdg,
        &[
            "daemon",
            "doctor",
            "-f",
            "broken.yaml",
            "--state-dir",
            state_dir.to_str().expect("utf8"),
            "--port-offset",
            &offset_s,
        ],
    );
    assert_eq!(
        doc_out.status.code(),
        Some(2),
        "doctor must fail with exit 2"
    );
    let doc_stdout = String::from_utf8_lossy(&doc_out.stdout);
    assert!(
        doc_stdout.contains("[D9 ] fail") && doc_stdout.contains("does-not-exist.dar"),
        "{doc_stdout}"
    );

    // (b) True runtime rollback: bypass preflight via `--daemon-supervisor-worker` so
    // `sequencer1` and `mediator1` genuinely boot and become healthy, then `participant1`
    // fails immediately on the missing DAR; verify rollback stops `sequencer1` & `mediator1`
    // before writing `daemon.ready.json` (`ok: false`) and leaves 0 stray processes.
    let worker_out = run_cli(
        &work,
        &xdg,
        &[
            "daemon",
            "up",
            "--daemon-supervisor-worker",
            "-f",
            "broken.yaml",
            "--state-dir",
            state_dir.to_str().expect("utf8"),
            "--port-offset",
            &offset_s,
            "--metrics-port",
            "0",
        ],
    );
    assert!(
        !worker_out.status.success(),
        "supervisor worker must fail when participant1 has broken DAR"
    );

    let ack_raw = fs::read_to_string(state_dir.join("daemon.ready.json")).expect("read ready ack");
    let ack: Value = serde_json::from_str(&ack_raw).expect("parse ready ack");
    assert_eq!(
        ack["ok"],
        Value::Bool(false),
        "ack must report ok=false: {ack}"
    );
    let nodes = ack["nodes"].as_array().expect("ready nodes array");
    assert_eq!(
        nodes.len(),
        2,
        "sequencer1 and mediator1 should have started before participant1 failed: {ack}"
    );

    // Wait briefly for OS socket teardown, then verify 0 stray listeners & no socket/PID manifest.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline
        && (port_is_listening(seq_port)
            || port_is_listening(med_port)
            || port_is_listening(json_port))
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !port_is_listening(seq_port),
        "sequencer1 must be rolled back on participant1 startup failure"
    );
    assert!(
        !port_is_listening(med_port),
        "mediator1 must be rolled back on participant1 startup failure"
    );
    assert!(
        !port_is_listening(json_port),
        "participant1 must not be listening"
    );
    assert!(
        !state_dir.join("daemon.pids.json").exists(),
        "daemon.pids.json must be removed after rollback"
    );
    assert!(
        state_dir.join("daemon.sock").symlink_metadata().is_err(),
        "daemon.sock must be unlinked after rollback"
    );

    let _ = fs::remove_dir_all(&root);
}
