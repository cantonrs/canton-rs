//! E2E integration tests for `M-002` (`--dev-auth` CLI interop + `--token-env`/`--token-file`)
//! and `M-003` (`daemon scenario run smoke-create` & `steady-burst-5` HTTP package discovery).
//!
//! Runs every CLI invocation from an isolated empty temp directory (outside the repository root)
//! so template discovery is proven independent of `contracts/target/sample-contract.dar` in CWD.

#![allow(clippy::unwrap_used, reason = "integration test")]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
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

fn unique_root(tag: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("m002-m003-{tag}-{}-{seq}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("xdg")).expect("mkdir xdg");
    fs::create_dir_all(root.join("cwd")).expect("mkdir cwd");
    root
}

fn choose_free_block(start: u16, count: u16) -> u16 {
    let mut base = start;
    while base < 58_000 {
        let mut sockets = Vec::new();
        let mut all_ok = true;
        for delta in 0..count {
            match TcpListener::bind(("127.0.0.1", base + delta)) {
                Ok(s) => sockets.push(s),
                Err(_) => {
                    all_ok = false;
                    break;
                }
            }
        }
        drop(sockets);
        if all_ok {
            return base;
        }
        base = base.saturating_add(20);
    }
    panic!("no free {count}-port block found starting at {start}");
}

fn write_manifest(
    dir: &Path,
    name: &str,
    base_port: u16,
    dar_path: Option<&Path>,
) -> (PathBuf, u16, Vec<u16>) {
    fs::create_dir_all(dir).expect("mkdir manifest dir");
    let manifest_path = dir.join("canton-daemon.yaml");
    let s_pub = base_port;
    let s_adm = base_port + 1;
    let m_adm = base_port + 2;
    let p1_json = base_port + 3;
    let metrics_port = base_port + 4;
    let dars_yaml = match dar_path {
        Some(p) => format!("[\"{}\"]", p.display()),
        None => "[]".to_string(),
    };
    let yaml = format!(
        "name: {name}
synchronizer: m002-sync
state_dir: ./unused-state
metrics_port: {metrics_port}
services:
  s1:
    role: sequencer
    ports: [\"{s_pub}:public\", \"{s_adm}:metrics\"]
    restart: unless-stopped
  m1:
    role: mediator
    ports: [\"{m_adm}:admin\"]
    depends_on: [s1]
    restart: unless-stopped
  p1:
    role: participant
    ports: [\"{p1_json}:json-api\"]
    dars: {dars_yaml}
    depends_on: [s1, m1]
    restart: unless-stopped
"
    );
    fs::write(&manifest_path, yaml).expect("write manifest");
    (
        manifest_path,
        p1_json,
        vec![s_pub, s_adm, m_adm, p1_json, metrics_port],
    )
}

fn run_in(cwd: &Path, xdg: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.current_dir(cwd)
        .args(args)
        .env("XDG_STATE_HOME", xdg)
        .env("CANTON_RS_DETACH_TIMEOUT_SECS", "90");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("failed to run canton-rs {:?}: {e}", args))
}

fn http_call(
    port: u16,
    method: &str,
    path: &str,
    body: Option<(&[u8], &str)>,
    token: Option<&str>,
) -> Result<(u16, String), String> {
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e| format!("addr: {e}"))?;
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let (payload, content_type) = body.unwrap_or((b"", "application/json"));
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {content_type}\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.write_all(payload))
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "missing HTTP header".to_string())?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line: {head}"))?;
    Ok((
        status,
        String::from_utf8_lossy(&raw[split + 4..]).into_owned(),
    ))
}

fn wait_ready(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok((200, _)) = http_call(port, "GET", "/readyz", None, None) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("participant on port {port} did not return 200 on /readyz within {timeout:?}");
}

struct InstanceGuard {
    root: PathBuf,
    cwd: PathBuf,
    xdg: PathBuf,
    name: String,
    ports: Vec<u16>,
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        let _ = run_in(
            &self.cwd,
            &self.xdg,
            &["daemon", "remove", "--name", &self.name, "--force"],
            &[],
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if self
                .ports
                .iter()
                .all(|&p| TcpListener::bind(("127.0.0.1", p)).is_ok())
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn m002_m003_dev_auth_cli_interop_and_scenarios_e2e() {
    let root = unique_root("devauth");
    let xdg = root.join("xdg");
    let cwd = root.join("cwd");
    let inst = "m002-dev";
    let base_port = choose_free_block(29_400, 6);
    let (manifest, p1_port, ports) =
        write_manifest(&root.join("cfg"), inst, base_port, Some(&sample_dar()));
    let _guard = InstanceGuard {
        root: root.clone(),
        cwd: cwd.clone(),
        xdg: xdg.clone(),
        name: inst.to_string(),
        ports,
    };

    let m_str = manifest.display().to_string();
    let up = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "up",
            "--name",
            inst,
            "-f",
            &m_str,
            "--state-in-files",
            "--dev-auth",
            "-d",
        ],
        &[],
    );
    assert!(
        up.status.success(),
        "daemon up --dev-auth failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&up.stdout),
        String::from_utf8_lossy(&up.stderr)
    );
    wait_ready(p1_port, Duration::from_secs(20));

    // Confirm raw unauthenticated /v2/state/ledger-end is rejected with 401.
    let (unauth_status, _) =
        http_call(p1_port, "GET", "/v2/state/ledger-end", None, None).expect("unauth call");
    assert_eq!(
        unauth_status, 401,
        "--dev-auth must reject unauthenticated calls"
    );

    // 1. M-003 + M-002: `daemon scenario run smoke-create` succeeds from empty CWD under --dev-auth!
    let smoke = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "scenario",
            "run",
            "smoke-create",
            "--name",
            inst,
            "--json",
        ],
        &[],
    );
    assert!(
        smoke.status.success(),
        "smoke-create failed under --dev-auth:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&smoke.stdout),
        String::from_utf8_lossy(&smoke.stderr)
    );
    let smoke_json: Value = serde_json::from_slice(&smoke.stdout).expect("parse smoke-create json");
    assert_eq!(smoke_json["ok"], true, "smoke-create report: {smoke_json}");
    let smoke_alice = smoke_json["steps"][0]["summary"]
        .as_str()
        .and_then(|s| s.split_whitespace().last())
        .expect("extract SmokeAlice party")
        .to_string();
    assert!(
        smoke_alice.starts_with("SmokeAlice::"),
        "unexpected party: {smoke_alice}"
    );

    // 2. M-003 + M-002: `daemon scenario run steady-burst-5` succeeds under --dev-auth!
    let burst = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "scenario",
            "run",
            "steady-burst-5",
            "--name",
            inst,
            "--json",
        ],
        &[],
    );
    assert!(
        burst.status.success(),
        "steady-burst-5 failed under --dev-auth:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&burst.stdout),
        String::from_utf8_lossy(&burst.stderr)
    );
    let burst_json: Value = serde_json::from_slice(&burst.stdout).expect("parse burst json");
    assert_eq!(burst_json["ok"], true, "burst report: {burst_json}");

    // 3. M-002: `daemon contracts ls` succeeds without extra token flags under --dev-auth!
    let acs = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "contracts",
            "ls",
            "--name",
            inst,
            "--party",
            &smoke_alice,
            "--format",
            "json",
        ],
        &[],
    );
    assert!(
        acs.status.success(),
        "daemon contracts ls failed under --dev-auth:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&acs.stdout),
        String::from_utf8_lossy(&acs.stderr)
    );
    let acs_json: Value = serde_json::from_slice(&acs.stdout).expect("parse contracts ls json");
    let contracts = acs_json["contracts"].as_array().expect("contracts array");
    assert!(
        !contracts.is_empty(),
        "expected >= 1 active AssetHolding contract for {smoke_alice}, got {acs_json}"
    );

    // 4. M-002: `daemon tx ls` and `daemon tx replay` succeed without extra token flags!
    let tx_ls = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "tx",
            "ls",
            "--name",
            inst,
            "--party",
            &smoke_alice,
            "--format",
            "json",
        ],
        &[],
    );
    assert!(
        tx_ls.status.success(),
        "daemon tx ls failed under --dev-auth:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&tx_ls.stdout),
        String::from_utf8_lossy(&tx_ls.stderr)
    );
    let tx_json: Value = serde_json::from_slice(&tx_ls.stdout).expect("parse tx ls json");
    let updates = tx_json["updates"].as_array().expect("updates array");
    assert!(!updates.is_empty(), "expected >= 1 update, got {tx_json}");
    let update_id = updates[0]["updateId"].as_str().expect("updateId");

    let tx_replay = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "tx",
            "replay",
            "--name",
            inst,
            "--party",
            &smoke_alice,
            "--id",
            update_id,
            "--format",
            "json",
        ],
        &[],
    );
    assert!(
        tx_replay.status.success(),
        "daemon tx replay failed under --dev-auth:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&tx_replay.stdout),
        String::from_utf8_lossy(&tx_replay.stderr)
    );
    let replay_json: Value =
        serde_json::from_slice(&tx_replay.stdout).expect("parse tx replay json");
    assert_eq!(replay_json["visible"], true, "replay: {replay_json}");

    // 5. M-002: `daemon snapshot` succeeds without extra token flags under --dev-auth!
    let snap_tar = root.join("dev-snap.tar");
    let snap_str = snap_tar.display().to_string();
    let snap = run_in(
        &cwd,
        &xdg,
        &[
            "daemon", "snapshot", "--name", inst, "--out", &snap_str, "--format", "json",
        ],
        &[],
    );
    assert!(
        snap.status.success(),
        "daemon snapshot failed under --dev-auth:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&snap.stdout),
        String::from_utf8_lossy(&snap.stderr)
    );
    assert!(snap_tar.is_file(), "snapshot tarball must exist");
    wait_ready(p1_port, Duration::from_secs(20));

    // 6. M-002 Negative controls: explicit invalid token via --token-env / --token-file MUST override
    //    auto-signing and fail with HTTP 401!
    let bad_contracts = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "contracts",
            "ls",
            "--name",
            inst,
            "--party",
            &smoke_alice,
            "--token-env",
            "M002_BAD_TOKEN",
        ],
        &[("M002_BAD_TOKEN", "invalid.jwt.token")],
    );
    assert!(
        !bad_contracts.status.success(),
        "invalid --token-env on contracts ls must fail"
    );
    let bad_contracts_err = String::from_utf8_lossy(&bad_contracts.stderr);
    assert!(
        bad_contracts_err.contains("401"),
        "expected 401 on invalid --token-env contracts ls, got: {bad_contracts_err}"
    );

    let bad_tx = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "tx",
            "ls",
            "--name",
            inst,
            "--party",
            &smoke_alice,
            "--token-env",
            "M002_BAD_TOKEN",
        ],
        &[("M002_BAD_TOKEN", "invalid.jwt.token")],
    );
    assert!(
        !bad_tx.status.success(),
        "invalid --token-env on tx ls must fail"
    );
    assert!(
        String::from_utf8_lossy(&bad_tx.stderr).contains("401"),
        "expected 401 on invalid --token-env tx ls, got: {}",
        String::from_utf8_lossy(&bad_tx.stderr)
    );

    let bad_scen = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "scenario",
            "run",
            "smoke-create",
            "--name",
            inst,
            "--token-env",
            "M002_BAD_TOKEN",
            "--json",
        ],
        &[("M002_BAD_TOKEN", "invalid.jwt.token")],
    );
    assert!(
        !bad_scen.status.success(),
        "invalid --token-env on scenario run must fail"
    );
    let bad_scen_out = format!(
        "{}\n{}",
        String::from_utf8_lossy(&bad_scen.stdout),
        String::from_utf8_lossy(&bad_scen.stderr)
    );
    assert!(
        bad_scen_out.contains("401"),
        "expected 401 on invalid --token-env scenario run, got: {bad_scen_out}"
    );

    let bad_tok_file = root.join("bad.tok");
    fs::write(&bad_tok_file, "invalid.jwt.token\n").expect("write bad tok");
    let bad_tok_str = bad_tok_file.display().to_string();
    let bad_snap_tar = root.join("bad-snap.tar");
    let bad_snap_str = bad_snap_tar.display().to_string();
    let bad_snap = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "snapshot",
            "--name",
            inst,
            "--out",
            &bad_snap_str,
            "--token-file",
            &bad_tok_str,
        ],
        &[],
    );
    assert!(
        !bad_snap.status.success(),
        "invalid --token-file on snapshot must fail"
    );
    assert!(
        String::from_utf8_lossy(&bad_snap.stderr).contains("401"),
        "expected 401 on invalid --token-file snapshot, got: {}",
        String::from_utf8_lossy(&bad_snap.stderr)
    );
    assert!(
        !bad_snap_tar.exists(),
        "failed snapshot must not write output bundle"
    );

    // 7. M-002 Positive control for explicit --token-file with explicit --url:
    let creds = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "creds",
            "--name",
            inst,
            "--party",
            &smoke_alice,
            "--format",
            "json",
        ],
        &[],
    );
    assert!(creds.status.success(), "daemon creds failed");
    let creds_json: Value = serde_json::from_slice(&creds.stdout).expect("parse creds");
    let valid_tok = creds_json["token"].as_str().expect("token");
    let good_tok_file = root.join("good.tok");
    fs::write(&good_tok_file, format!("{valid_tok}\n")).expect("write good tok");
    let good_tok_str = good_tok_file.display().to_string();
    let url = format!("http://127.0.0.1:{p1_port}");
    let url_contracts = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "contracts",
            "ls",
            "--url",
            &url,
            "--party",
            &smoke_alice,
            "--token-file",
            &good_tok_str,
            "--format",
            "json",
        ],
        &[],
    );
    assert!(
        url_contracts.status.success(),
        "explicit --url + --token-file failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&url_contracts.stdout),
        String::from_utf8_lossy(&url_contracts.stderr)
    );
}

#[test]
fn m003_zero_dar_negative_control_and_plain_auth_scenarios_e2e() {
    let root = unique_root("zerodar");
    let xdg = root.join("xdg");
    let cwd = root.join("cwd");
    let inst = "m003-zero";
    let base_port = choose_free_block(29_500, 6);
    let (manifest, p1_port, ports) = write_manifest(&root.join("cfg"), inst, base_port, None);
    let _guard = InstanceGuard {
        root,
        cwd: cwd.clone(),
        xdg: xdg.clone(),
        name: inst.to_string(),
        ports,
    };

    let m_str = manifest.display().to_string();
    let up = run_in(
        &cwd,
        &xdg,
        &[
            "daemon",
            "up",
            "--name",
            inst,
            "-f",
            &m_str,
            "--state-in-files",
            "-d",
        ],
        &[],
    );
    assert!(
        up.status.success(),
        "zero-DAR daemon up failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&up.stdout),
        String::from_utf8_lossy(&up.stderr)
    );
    wait_ready(p1_port, Duration::from_secs(20));

    // 1. Negative control: zero-DAR stack fails `smoke-create` with clear diagnostic & non-zero exit.
    let zero_run = run_in(
        &cwd,
        &xdg,
        &["daemon", "scenario", "run", "smoke-create", "--name", inst],
        &[],
    );
    assert!(
        !zero_run.status.success(),
        "smoke-create on zero-DAR stack must exit non-zero"
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&zero_run.stdout),
        String::from_utf8_lossy(&zero_run.stderr)
    );
    assert!(
        combined.contains("--with-sample-dar")
            && combined.contains("Upload a DAR first")
            && combined.contains("checked "),
        "expected diagnostic guidance on zero-DAR failure, got:\n{combined}"
    );

    // 2. Upload sample-contract.dar dynamically over HTTP, then verify BOTH `smoke-create` and
    //    `steady-burst-5` pass without `--dev-auth` from the empty temp CWD!
    let dar_bytes = fs::read(sample_dar()).expect("read sample-contract.dar");
    let (up_status, up_body) = http_call(
        p1_port,
        "POST",
        "/v2/packages",
        Some((&dar_bytes, "application/octet-stream")),
        None,
    )
    .expect("upload sample-contract.dar");
    assert_eq!(up_status, 200, "DAR upload failed: {up_body}");

    for scenario in ["smoke-create", "steady-burst-5"] {
        let out = run_in(
            &cwd,
            &xdg,
            &[
                "daemon", "scenario", "run", scenario, "--name", inst, "--json",
            ],
            &[],
        );
        assert!(
            out.status.success(),
            "scenario '{scenario}' failed after DAR upload:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let report: Value = serde_json::from_slice(&out.stdout).expect("parse scenario json");
        assert_eq!(report["ok"], true, "report for {scenario}: {report}");
    }
}
