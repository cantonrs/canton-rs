//! E2E integration tests for S-DX-002: `localnet up --port-base`, `daemon status --format json`,
//! `daemon env`, preflight atomicity, live HTTP/gRPC probing, and schema determinism (`P-01`, `P-03`..`P-07`).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use canton_sequencer_server::health::health_check_response::ServingStatus;
use canton_sequencer_server::health::health_client::HealthClient;
use canton_sequencer_server::health::HealthCheckRequest;
use serde_json::Value;
use tonic::transport::Endpoint;

static PORT_LOCK: Mutex<()> = Mutex::new(());
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

const FIXED_PORTS: [u16; 5] = [47000, 47001, 47002, 47100, 47101];
const DAEMON_PORTS: [u16; 6] = [48100, 48101, 48102, 48110, 48111, 48200];

fn bin() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("canton-rs")
}

fn sample_dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar")
        .canonicalize()
        .expect("canonicalize sample-contract.dar")
}

fn unique_temp_path(tag: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("sdx002-{tag}-{}-{seq}", std::process::id()))
}

fn wait_ports_free(ports: &[u16], within: Duration) {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        let all_closed = ports.iter().all(|p| {
            let addr: SocketAddr = format!("127.0.0.1:{p}")
                .parse()
                .expect("valid loopback addr");
            TcpStream::connect_timeout(&addr, Duration::from_millis(80)).is_err()
        });
        if all_closed {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("ports did not release within {within:?}: {ports:?}");
}

fn children_of(pid: u32) -> Vec<u32> {
    let out = Command::new("pgrep")
        .args(["-P", &pid.to_string()])
        .output()
        .expect("pgrep");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

fn canton_children_of(pid: u32) -> Vec<String> {
    let out = Command::new("ps")
        .args(["-axo", "ppid=,comm="])
        .output()
        .expect("ps ppid,comm");
    let pid_str = pid.to_string();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let (ppid, comm) = trimmed.split_once(char::is_whitespace)?;
            if ppid != pid_str {
                return None;
            }
            let cmd = comm.trim();
            if cmd.ends_with("/canton-rs") || cmd == "canton-rs" {
                Some(cmd.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn pid_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn wait_for_marker(child: &mut Child, marker: &str) -> String {
    let err = child.stderr.take().expect("stderr piped");
    let (tx, rx) = std::sync::mpsc::channel();
    let wanted = marker.to_string();
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut sent = false;
        for line in BufReader::new(err).lines().map_while(Result::ok) {
            if !sent && line.contains(&wanted) {
                sent = true;
                let _ = tx.send(Ok(line.clone()));
            }
            seen.push_str(&line);
            seen.push('\n');
        }
        if !sent {
            let _ = tx.send(Err(seen));
        }
    });
    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(line)) => line,
        Ok(Err(seen)) => panic!("localnet ended before {marker:?}:\n{seen}"),
        Err(_) => panic!("timed out waiting for {marker:?}"),
    }
}

struct KeptLocalnetGuard {
    child: Option<Child>,
    ports: Vec<u16>,
    cleanup_dir: Option<PathBuf>,
}

impl KeptLocalnetGuard {
    fn start(port_base: u16, state_dir: &Path, clean_after: bool) -> Self {
        let _ = std::fs::remove_dir_all(state_dir);
        let mut child = Command::new(bin())
            .args([
                "localnet",
                "up",
                "--port-base",
                &port_base.to_string(),
                "--state-dir",
            ])
            .arg(state_dir)
            .args(["--keep", "--no-splice", "--no-scan", "--dar"])
            .arg(sample_dar())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn localnet up --keep");

        let _line = wait_for_marker(&mut child, "LocalNet is up");
        Self {
            child: Some(child),
            ports: FIXED_PORTS.to_vec(),
            cleanup_dir: clean_after.then(|| state_dir.to_path_buf()),
        }
    }

    fn stop_and_wait(&mut self) {
        if let Some(mut child) = self.child.take() {
            let kids = children_of(child.id());
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let _ = child.wait();
            let deadline = Instant::now() + Duration::from_secs(15);
            while kids.iter().any(|k| pid_alive(*k)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(80));
            }
            for k in &kids {
                if pid_alive(*k) {
                    let _ = Command::new("kill")
                        .args(["-KILL", &k.to_string()])
                        .status();
                }
            }
            wait_ports_free(&self.ports, Duration::from_secs(15));
        }
        if let Some(dir) = self.cleanup_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl Drop for KeptLocalnetGuard {
    fn drop(&mut self) {
        self.stop_and_wait();
    }
}

struct DaemonStackGuard {
    state_dir: PathBuf,
    temp_root: PathBuf,
}

impl Drop for DaemonStackGuard {
    fn drop(&mut self) {
        let _ = Command::new(bin())
            .args(["daemon", "down", "--state-dir"])
            .arg(&self.state_dir)
            .arg("--clean-files")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&self.temp_root);
    }
}

fn run_daemon_status_json(state_dir: &Path) -> (String, Value) {
    let out = Command::new(bin())
        .args(["daemon", "status", "--state-dir"])
        .arg(state_dir)
        .args(["--format", "json"])
        .output()
        .expect("run daemon status --format json");
    assert!(
        out.status.success(),
        "daemon status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let raw = String::from_utf8(out.stdout).expect("utf8 status stdout");
    let parsed: Value = serde_json::from_str(&raw).expect("valid status json");
    (raw, parsed)
}

fn endpoint_ports_map(status: &Value) -> BTreeMap<String, u16> {
    let obj = status["endpoints"]
        .as_object()
        .expect("endpoints JSON object");
    obj.iter()
        .map(|(k, v)| {
            let url = v["url"].as_str().expect("endpoint url string");
            let port_str = url.rsplit(':').next().expect("port after :");
            let port = port_str.parse::<u16>().expect("numeric port");
            (k.clone(), port)
        })
        .collect()
}

fn http_get(url: &str, path: &str) -> Result<(u16, String), String> {
    let host_port = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("expected http:// URL, got {url}"))?;
    let addr: SocketAddr = host_port.parse().map_err(|e| format!("{host_port}: {e}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("connect {addr}: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write {addr}: {e}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read {addr}: {e}"))?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "missing HTTP header separator".to_string())?;
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("missing status code in {head}"))?;
    Ok((code, body.to_string()))
}

fn check_grpc_serving(url: &str) -> bool {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio rt");
    rt.block_on(async move {
        let ep = Endpoint::from_shared(url.to_string())
            .expect("valid endpoint")
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(3));
        let Ok(ch) = ep.connect().await else {
            return false;
        };
        let mut client = HealthClient::new(ch);
        match client
            .check(HealthCheckRequest {
                service: String::new(),
            })
            .await
        {
            Ok(resp) => resp.into_inner().status == ServingStatus::Serving as i32,
            Err(_) => false,
        }
    })
}

fn normalize_status_snapshot_preserving_key_order(raw: &str, expected_state_dir: &Path) -> String {
    let canonical_dir = expected_state_dir
        .canonicalize()
        .unwrap_or_else(|_| expected_state_dir.to_path_buf());
    let escaped_dir =
        serde_json::to_string(&canonical_dir.display().to_string()).expect("escape canonical dir");
    let expected_ver = env!("CARGO_PKG_VERSION");
    let escaped_ver = serde_json::to_string(expected_ver).expect("escape version");

    let mut out = String::new();
    for line in raw.trim_end().lines() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        if trimmed.starts_with("\"state_dir\":") {
            assert!(
                trimmed.contains(&escaped_dir),
                "unexpected state_dir line {line}; expected {escaped_dir}"
            );
            out.push_str(indent);
            out.push_str("\"state_dir\": \"<STATE_DIR>\",\n");
        } else if trimmed.starts_with("\"version\":") {
            assert!(
                trimmed.contains(&escaped_ver),
                "unexpected version line {line}; expected {escaped_ver}"
            );
            out.push_str(indent);
            out.push_str("\"version\": \"<VERSION>\"\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[test]
fn sdx002_p01_port_base_reproducible() {
    let _serial = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wait_ports_free(&FIXED_PORTS, Duration::from_secs(10));

    let dir1 = unique_temp_path("p01-run1");
    let mut net1 = KeptLocalnetGuard::start(47000, &dir1, true);
    let (_, status1) = run_daemon_status_json(&dir1);
    let ports1 = endpoint_ports_map(&status1);
    net1.stop_and_wait();

    let dir2 = unique_temp_path("p01-run2");
    let mut net2 = KeptLocalnetGuard::start(47000, &dir2, true);
    let (_, status2) = run_daemon_status_json(&dir2);
    let ports2 = endpoint_ports_map(&status2);
    net2.stop_and_wait();

    assert_eq!(ports1, ports2, "fixed-port mapping drifted across restarts");
    let expected = BTreeMap::from([
        ("m1.admin".to_string(), 47002),
        ("p1.json".to_string(), 47100),
        ("p2.json".to_string(), 47101),
        ("s1.admin".to_string(), 47001),
        ("s1.public".to_string(), 47000),
    ]);
    assert_eq!(ports1, expected);
}

#[test]
fn sdx002_p03_port_occupied_atomicity() {
    let _serial = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wait_ports_free(&FIXED_PORTS, Duration::from_secs(10));

    let occupied = TcpListener::bind("127.0.0.1:47100").expect("bind blocker on 47100");
    let state_dir = unique_temp_path("p03-busy");
    let _ = std::fs::remove_dir_all(&state_dir);
    assert!(!state_dir.exists());

    let mut child = Command::new(bin())
        .args(["localnet", "up", "--port-base", "47000", "--state-dir"])
        .arg(&state_dir)
        .args(["--no-splice", "--no-scan", "--dar"])
        .arg(sample_dar())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn blocked localnet up");

    let mut max_canton_children = 0usize;
    let mut state_ever_existed = false;
    let status = loop {
        max_canton_children = max_canton_children.max(canton_children_of(child.id()).len());
        state_ever_existed |= state_dir.exists();
        if let Some(exit) = child.try_wait().expect("try_wait") {
            break exit;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    drop(occupied);
    let _ = std::fs::remove_dir_all(&state_dir);

    assert_eq!(
        status.code(),
        Some(2),
        "expected EXIT_PREFLIGHT=2 when 47100 is busy, stderr:\n{stderr}"
    );
    assert_eq!(
        max_canton_children, 0,
        "preflight must reject BEFORE spawning any canton-rs child process"
    );
    assert!(
        !state_ever_existed,
        "state dir must not be created when preflight rejects"
    );
    assert!(
        !stderr.contains("sequencer_ready"),
        "sequencer started before preflight:\n{stderr}"
    );
    assert!(
        stderr.contains("47100"),
        "stderr did not mention occupied port 47100:\n{stderr}"
    );

    for (tag, bad_base) in [("overflow", 65500u16), ("hub", 6432u16)] {
        let bad_dir = unique_temp_path(&format!("p03-{tag}"));
        let _ = std::fs::remove_dir_all(&bad_dir);
        let out = Command::new(bin())
            .args([
                "localnet",
                "up",
                "--port-base",
                &bad_base.to_string(),
                "--state-dir",
            ])
            .arg(&bad_dir)
            .args(["--no-splice", "--no-scan", "--dar"])
            .arg(sample_dar())
            .output()
            .expect("run localnet up invalid port-base");
        assert_eq!(
            out.status.code(),
            Some(2),
            "port-base {bad_base} expected exit=2, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !bad_dir.exists(),
            "state dir created despite port-base {bad_base} failure"
        );
    }
}

#[test]
fn sdx002_p04_status_probe_consistency() {
    let _serial = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wait_ports_free(&FIXED_PORTS, Duration::from_secs(10));

    // Part A: fixed-port LocalNet endpoints probed via real HTTP and gRPC Health/Check.
    let dir = unique_temp_path("p04-localnet");
    let mut net = KeptLocalnetGuard::start(47000, &dir, true);
    let (_, status) = run_daemon_status_json(&dir);
    let endpoints = status["endpoints"].as_object().expect("endpoints map");
    assert_eq!(endpoints.len(), 5);
    for (label, entry) in endpoints {
        let state = entry["state"].as_str().expect("state str");
        let url = entry["url"].as_str().expect("url str");
        assert_eq!(state, "up", "endpoint {label} should be up: {entry}");
        match label.as_str() {
            "p1.json" | "p2.json" => {
                let (code, body) = http_get(url, "/v2/version").expect("GET /v2/version");
                assert_eq!(code, 200, "{label} answered {code}: {body}");
            }
            "m1.admin" => {
                let (code, body) = http_get(url, "/status").expect("GET /status");
                assert_eq!(code, 200, "{label} answered {code}: {body}");
            }
            "s1.public" | "s1.admin" => {
                assert!(
                    check_grpc_serving(url),
                    "gRPC Health/Check failed for {label} at {url}"
                );
                if label == "s1.public" {
                    let port = url.rsplit(':').next().expect("port");
                    let seq_st = Command::new(bin())
                        .args(["sequencer", "status", "--port", port])
                        .output()
                        .expect("sequencer status");
                    assert!(
                        seq_st.status.success(),
                        "sequencer status failed: {}",
                        String::from_utf8_lossy(&seq_st.stderr)
                    );
                }
            }
            other => panic!("unexpected endpoint label {other}"),
        }
    }

    let text_out = Command::new(bin())
        .args(["daemon", "status", "--state-dir"])
        .arg(&dir)
        .output()
        .expect("daemon status text");
    assert!(text_out.status.success());
    let text = String::from_utf8_lossy(&text_out.stdout);
    assert!(text.contains("p1.json") && text.contains("up"), "{text}");
    net.stop_and_wait();

    // Part B: supervised daemon stack (`up -d`) + live `stop` state transition (`up` -> `down`) + `ps --json` regression check.
    wait_ports_free(&DAEMON_PORTS, Duration::from_secs(10));
    let temp_root = unique_temp_path("p04-daemon");
    std::fs::create_dir_all(&temp_root).expect("create temp_root");
    let sup_state = temp_root.join("state");
    let manifest_path = temp_root.join("canton-daemon.yaml");
    let dar = sample_dar();
    let yaml = format!(
        "name: sdx002-status-test
synchronizer: sdx002-sync
state_dir: {state}
metrics_port: 48200
services:
  s1:
    role: sequencer
    ports: [\"48100:public\", \"48101:admin\", \"48101:metrics\"]
    restart: unless-stopped
  m1:
    role: mediator
    ports: [\"48102:admin\"]
    depends_on: [s1]
    restart: unless-stopped
  p1:
    role: participant
    ports: [\"48110:json-api\"]
    dars: [\"{dar}\"]
    depends_on: [s1, m1]
    restart: unless-stopped
  p2:
    role: participant
    ports: [\"48111:json-api\"]
    dars: [\"{dar}\"]
    depends_on: [s1, m1]
    restart: unless-stopped
",
        state = sup_state.display(),
        dar = dar.display()
    );
    std::fs::write(&manifest_path, yaml).expect("write manifest");

    let _daemon_guard = DaemonStackGuard {
        state_dir: sup_state.clone(),
        temp_root,
    };
    let up = Command::new(bin())
        .args(["daemon", "up", "-d", "-f"])
        .arg(&manifest_path)
        .arg("--state-dir")
        .arg(&sup_state)
        .output()
        .expect("daemon up -d");
    assert!(
        up.status.success(),
        "daemon up failed: stdout={} stderr={}",
        String::from_utf8_lossy(&up.stdout),
        String::from_utf8_lossy(&up.stderr)
    );

    let deadline = Instant::now() + Duration::from_secs(45);
    let mut ready_status = Value::Null;
    while Instant::now() < deadline {
        let (_, st) = run_daemon_status_json(&sup_state);
        let p1_up = st["endpoints"]["p1.json"]["state"] == "up";
        let p2_up = st["endpoints"]["p2.json"]["state"] == "up";
        let s1_up = st["endpoints"]["s1.public"]["state"] == "up";
        let m1_up = st["endpoints"]["m1.admin"]["state"] == "up";
        let metrics_up = st["endpoints"]["metrics"]["state"] == "up";
        if p1_up && p2_up && s1_up && m1_up && metrics_up {
            ready_status = st;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    assert_eq!(
        ready_status["endpoints"]["p1.json"]["state"], "up",
        "supervisor endpoints failed to reach up: {ready_status}"
    );
    assert_eq!(ready_status["endpoints"]["metrics"]["state"], "up");

    // Verify existing `daemon ps --json` stays compatible (`P-04` / backward compatibility).
    let ps = Command::new(bin())
        .args(["daemon", "ps", "--state-dir"])
        .arg(&sup_state)
        .arg("--json")
        .output()
        .expect("daemon ps --json");
    assert!(ps.status.success());
    let ps_json: Value = serde_json::from_slice(&ps.stdout).expect("parse ps --json");
    assert!(ps_json["snapshot"]["nodes"].is_array());

    // Stop `p2` and verify `p2.json` reflects real reachability (`down`) while `p1.json` stays `up`.
    let stop_p2 = Command::new(bin())
        .args(["daemon", "stop", "--state-dir"])
        .arg(&sup_state)
        .arg("p2")
        .output()
        .expect("daemon stop p2");
    assert!(
        stop_p2.status.success(),
        "daemon stop p2 failed: {}",
        String::from_utf8_lossy(&stop_p2.stderr)
    );

    let stop_deadline = Instant::now() + Duration::from_secs(15);
    let mut after_stop = Value::Null;
    while Instant::now() < stop_deadline {
        let (_, st) = run_daemon_status_json(&sup_state);
        if st["endpoints"]["p2.json"]["state"] == "down" {
            after_stop = st;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(
        after_stop["endpoints"]["p2.json"]["state"], "down",
        "stopped p2 did not transition to down: {after_stop}"
    );
    assert_eq!(after_stop["endpoints"]["p1.json"]["state"], "up");
    assert!(http_get("http://127.0.0.1:48111", "/v2/version").is_err());
    assert_eq!(
        http_get("http://127.0.0.1:48110", "/v2/version")
            .expect("p1 reachable")
            .0,
        200
    );

    let down = Command::new(bin())
        .args(["daemon", "down", "--state-dir"])
        .arg(&sup_state)
        .arg("--clean-files")
        .output()
        .expect("daemon down");
    assert!(down.status.success());
    wait_ports_free(&DAEMON_PORTS, Duration::from_secs(15));
}

#[test]
fn sdx002_p05_daemon_env_eval_and_query() {
    let _serial = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wait_ports_free(&FIXED_PORTS, Duration::from_secs(10));

    let dir = unique_temp_path("p05-env");
    let _net = KeptLocalnetGuard::start(47000, &dir, true);
    let (_, status) = run_daemon_status_json(&dir);

    let env_out = Command::new(bin())
        .args(["daemon", "env", "--state-dir"])
        .arg(&dir)
        .output()
        .expect("run daemon env");
    assert!(
        env_out.status.success(),
        "daemon env failed: {}",
        String::from_utf8_lossy(&env_out.stderr)
    );
    let env_text = String::from_utf8(env_out.stdout).expect("utf8 env output");

    let sh_out = Command::new("/bin/sh")
        .args([
            "-eu",
            "-c",
            "eval \"$ENV_TEXT\"\n\
             printf 'm1.admin=%s\\n' \"$CANTON_RS_M1_ADMIN_URL\"\n\
             printf 'p1.json=%s\\n' \"$CANTON_RS_P1_JSON_URL\"\n\
             printf 'p2.json=%s\\n' \"$CANTON_RS_P2_JSON_URL\"\n\
             printf 's1.admin=%s\\n' \"$CANTON_RS_S1_ADMIN_URL\"\n\
             printf 's1.public=%s\\n' \"$CANTON_RS_S1_PUBLIC_URL\"",
        ])
        .env("ENV_TEXT", &env_text)
        .output()
        .expect("eval daemon env in /bin/sh");
    assert!(
        sh_out.status.success(),
        "shell eval failed: {}",
        String::from_utf8_lossy(&sh_out.stderr)
    );

    let mut evaluated = BTreeMap::new();
    for line in String::from_utf8_lossy(&sh_out.stdout).lines() {
        let (k, v) = line.split_once('=').expect("k=v line");
        evaluated.insert(k.to_string(), v.to_string());
    }
    let endpoints = status["endpoints"].as_object().expect("endpoints");
    assert_eq!(evaluated.len(), endpoints.len());
    for (label, entry) in endpoints {
        assert_eq!(
            evaluated.get(label).map(String::as_str),
            entry["url"].as_str(),
            "env var mismatch for {label}"
        );
    }

    let p1_url = evaluated
        .get("p1.json")
        .expect("CANTON_RS_P1_JSON_URL present");
    let (code, body) = http_get(p1_url, "/v2/version").expect("query $CANTON_RS_P1_JSON_URL");
    assert_eq!(code, 200, "GET /v2/version returned {code}: {body}");
    let version_json: Value = serde_json::from_str(&body).expect("json version body");
    assert!(
        version_json.get("version").is_some(),
        "missing version field in {version_json}"
    );
}

#[test]
fn sdx002_p06_status_json_schema_snapshot() {
    let _serial = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wait_ports_free(&FIXED_PORTS, Duration::from_secs(10));

    let dir = unique_temp_path("p06-snapshot");
    let _net = KeptLocalnetGuard::start(47000, &dir, true);

    let expected_snapshot = include_str!("fixtures/sdx_002_status_snapshot.json");
    for run in 1..=6 {
        let (raw, parsed) = run_daemon_status_json(&dir);
        let normalized = normalize_status_snapshot_preserving_key_order(&raw, &dir);
        assert_eq!(
            normalized, expected_snapshot,
            "status JSON drifted from golden snapshot on run #{run}:\ngot:\n{normalized}\nexpected:\n{expected_snapshot}"
        );
        assert_eq!(parsed["schema"], "canton-rs.status/1");
        let reparsed: Value =
            serde_json::from_str(&serde_json::to_string_pretty(&parsed).expect("re-render"))
                .expect("re-parse");
        assert_eq!(reparsed, parsed);
    }
}

#[test]
fn sdx002_p07_default_localnet_regression() {
    let _serial = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let out = Command::new(bin())
        .args(["localnet", "up", "--no-splice", "--no-scan", "--dar"])
        .arg(sample_dar())
        .output()
        .expect("run default localnet up without --port-base");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "default localnet up failed ({:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code()
    );
    let parsed: Value = serde_json::from_str(&stdout).expect("parse localnet up summary json");
    assert_eq!(
        parsed["pass"], true,
        "localnet scenario did not pass: {parsed}"
    );
}
