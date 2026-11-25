//! E2E integration tests for `S-DX-006` (`R-01`..`R-08` + `R-A1`..`R-A7`):
//! - `R-01`: `dar inspect` matches golden snapshot & live SHA-256 package IDs, deterministic across runs, exits `3` on tampered `.dalf`.
//! - `R-02`: `dar diff x x` reports zero diffs and `upgradeCheck.passed == true` across `sample-contract.dar` and `sdx006-*`.
//! - `R-03`: `dar diff sdx006-v1 sdx006-v2` detects additive `Optional` field `note` on `Main:Vault` with `upgradeCheck.passed == true`.
//! - `R-04`: `dar diff` flags dropped fields (`v3-dropfield`), key type changes (`v4-keychange`), and removed templates (`v2-added -> v3-dropfield`) with `upgradeCheck.passed == false`.
//! - `R-05`: `dar diff(a, b)` and `dar diff(b, a)` satisfy strict anti-symmetry (`added`/`removed`, `fieldsAdded`/`fieldsRemoved`, `changed` symmetric).
//! - `R-06`: `daemon dar watch` detects saved compatible DAR within 10s, uploads & vets across all participants (`p1`, `p2`), and exits `0` on `SIGINT`.
//! - `R-07`: `daemon dar watch` blocks incompatible upgrade locally without sending `POST /v2/packages` HTTP requests to `p1`/`p2`, and keeps watching for subsequent compatible upgrades.
//! - `R-08`: `daemon dar watch` rejects truncated/corrupt DAR writes without panicking, without modifying participant packages, and continues watching cleanly.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

static DAR_TEST_LOCK: Mutex<()> = Mutex::new(());
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

fn sample_contract_dar() -> PathBuf {
    repo_root().join("contracts/target/sample-contract.dar")
}

fn golden_snapshot_path() -> PathBuf {
    repo_root().join("tests/e2e/fixtures/dar_inspect_sample_contract.json")
}

fn oracle_fixture_txt_path() -> PathBuf {
    repo_root().join("tests/e2e/fixtures/inspect_dar_sample_contract.txt")
}

fn sdx006_dar(variant: &str) -> PathBuf {
    repo_root()
        .join("contracts/fixtures")
        .join(variant)
        .join("target/sdx006-pkg.dar")
}

fn unique_temp_path(tag: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("sdx006-{tag}-{}-{seq}", std::process::id()))
}

fn alloc_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

fn run_cli_json(args: &[&str]) -> Value {
    let out = Command::new(bin()).args(args).output().expect("spawn cli");
    assert!(
        out.status.success(),
        "canton-rs {:?} failed ({}):\nstdout:\n{}\nstderr:\n{}",
        args,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse cli json")
}

fn str_array(val: &Value, key: &str) -> Vec<String> {
    val[key]
        .as_array()
        .unwrap_or_else(|| panic!("missing array field '{key}' in {val}"))
        .iter()
        .map(|v| v.as_str().expect("string element").to_string())
        .collect()
}

fn http_raw(base_url: &str, method: &str, path: &str, body: Option<&Value>) -> (u16, String) {
    let host_port = base_url
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("expected http:// URL, got {base_url}"));
    let addr: SocketAddr = host_port.parse().expect("parse host:port");
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).expect("connect");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(req.as_bytes()).expect("write http");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read http");
    let text = String::from_utf8_lossy(&raw);
    let (head, rest) = text.split_once("\r\n\r\n").expect("HTTP headers");
    let code: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("HTTP status");
    let body_str = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut decoded = String::new();
        let mut cursor = rest;
        while let Some((len_hex, after)) = cursor.split_once("\r\n") {
            let size = usize::from_str_radix(len_hex.trim(), 16).unwrap_or(0);
            if size == 0 || after.len() < size {
                break;
            }
            decoded.push_str(&after[..size]);
            cursor = after[size..].trim_start_matches("\r\n");
        }
        decoded
    } else {
        rest.to_string()
    };
    (code, body_str)
}

fn http_json(base_url: &str, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
    let (code, body_str) = http_raw(base_url, method, path, body);
    let parsed = serde_json::from_str(&body_str).unwrap_or(Value::String(body_str));
    (code, parsed)
}

fn http_text(base_url: &str, method: &str, path: &str) -> String {
    let (code, body_str) = http_raw(base_url, method, path, None);
    assert_eq!(code, 200, "GET {path} failed ({code}): {body_str}");
    body_str
}

fn send_sigint(child: &Child) {
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("invoke kill -INT");
    assert!(status.success(), "kill -INT failed: {status}");
}

struct DualParticipantStack {
    xdg: PathBuf,
    work: PathBuf,
    name: String,
    p1_url: String,
    p2_url: String,
}

impl DualParticipantStack {
    fn start(tag: &str, seed_dar: &Path) -> Self {
        let work = unique_temp_path(tag);
        let xdg = work.join("xdg");
        std::fs::create_dir_all(&xdg).expect("mkdir xdg");
        let name = format!("sdx006-{tag}-{}", std::process::id());

        let s_pub = alloc_free_port();
        let s_adm = alloc_free_port();
        let m_adm = alloc_free_port();
        let p1_json = alloc_free_port();
        let p2_json = alloc_free_port();
        let metrics = alloc_free_port();

        let manifest = work.join("canton-daemon.yaml");
        let yaml = format!(
            "name: {name}
synchronizer: sdx006-test-sync
state_dir: ./canton-rs-state
metrics_port: {metrics}
services:
  s1:
    role: sequencer
    ports: [\"{s_pub}:public\", \"{s_adm}:admin\", \"{s_adm}:metrics\"]
    restart: unless-stopped
  m1:
    role: mediator
    ports: [\"{m_adm}:admin\"]
    depends_on: [s1]
    restart: unless-stopped
  p1:
    role: participant
    ports: [\"{p1_json}:json-api\"]
    dars: [\"{dar}\"]
    depends_on: [s1, m1]
    restart: unless-stopped
  p2:
    role: participant
    ports: [\"{p2_json}:json-api\"]
    dars: [\"{dar}\"]
    depends_on: [s1, m1]
    restart: unless-stopped
",
            dar = seed_dar.display()
        );
        std::fs::write(&manifest, yaml).expect("write manifest");

        let up = Command::new(bin())
            .env("XDG_STATE_HOME", &xdg)
            .args([
                "daemon",
                "up",
                "--name",
                &name,
                "-f",
                manifest.to_str().expect("manifest str"),
                "-d",
            ])
            .stdin(Stdio::null())
            .output()
            .expect("spawn daemon up");
        assert!(
            up.status.success(),
            "daemon up failed ({}):\nstdout:\n{}\nstderr:\n{}",
            up.status,
            String::from_utf8_lossy(&up.stdout),
            String::from_utf8_lossy(&up.stderr)
        );

        let stack = Self {
            xdg,
            work,
            name,
            p1_url: format!("http://127.0.0.1:{p1_json}"),
            p2_url: format!("http://127.0.0.1:{p2_json}"),
        };
        stack.wait_ready();
        stack
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.env("XDG_STATE_HOME", &self.xdg)
            .args(args)
            .stdin(Stdio::null());
        c
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(45);
        while Instant::now() < deadline {
            let out = self
                .cmd(&["daemon", "status", "--name", &self.name, "--format", "json"])
                .output()
                .expect("daemon status");
            if out.status.success() {
                if let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) {
                    let eps = &v["endpoints"];
                    if ["s1.public", "m1.admin", "p1.json", "p2.json"]
                        .iter()
                        .all(|k| eps[k]["state"] == "up")
                    {
                        return;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("stack '{}' did not become ready within 45s", self.name);
    }

    fn package_ids(&self, url: &str) -> BTreeSet<String> {
        let (code, body) = http_json(url, "GET", "/v2/packages", None);
        assert_eq!(code, 200, "GET /v2/packages failed ({code}): {body}");
        body["packageIds"]
            .as_array()
            .expect("packageIds array")
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    }

    fn is_vetted(&self, url: &str, pkg_id: &str) -> bool {
        let req = json!({ "packageMetadataFilter": { "packageIds": [pkg_id] } });
        let (code, body) = http_json(url, "POST", "/v2/package-vetting/list", Some(&req));
        assert_eq!(
            code, 200,
            "POST /v2/package-vetting/list failed ({code}): {body}"
        );
        body["vettedPackages"].as_array().is_some_and(|groups| {
            groups.iter().any(|group| {
                group["packages"].as_array().is_some_and(|pkgs| {
                    pkgs.iter()
                        .any(|pkg| pkg["packageId"].as_str() == Some(pkg_id))
                })
            })
        })
    }

    fn post_packages_count(&self, url: &str) -> u64 {
        let raw = http_text(url, "GET", "/metrics");
        raw.lines()
            .filter(|line| {
                line.starts_with("canton_rs_api_requests_total{")
                    && line.contains("method=\"POST /v2/packages\"")
            })
            .filter_map(|line| line.split_whitespace().last()?.parse::<u64>().ok())
            .sum()
    }
}

impl Drop for DualParticipantStack {
    fn drop(&mut self) {
        let _ = self
            .cmd(&["daemon", "remove", "--name", &self.name, "--force"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

struct WatchProc {
    child: Child,
    stdout_rx: mpsc::Receiver<String>,
    stderr_rx: mpsc::Receiver<String>,
    out_thread: Option<JoinHandle<()>>,
    err_thread: Option<JoinHandle<()>>,
}

impl WatchProc {
    fn spawn(stack: &DualParticipantStack, watch_path: &Path, debounce_ms: u64) -> Self {
        let deb = debounce_ms.to_string();
        let mut child = stack
            .cmd(&[
                "daemon",
                "dar",
                "watch",
                "--name",
                &stack.name,
                "--debounce-ms",
                &deb,
                watch_path.to_str().expect("watch path str"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn daemon dar watch");

        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");

        let (stdout_tx, stdout_rx) = mpsc::channel();
        let out_thread = std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                if stdout_tx.send(line).is_err() {
                    break;
                }
            }
        });

        let (stderr_tx, stderr_rx) = mpsc::channel();
        let err_thread = std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if stderr_tx.send(line).is_err() {
                    break;
                }
            }
        });

        let mut proc = Self {
            child,
            stdout_rx,
            stderr_rx,
            out_thread: Some(out_thread),
            err_thread: Some(err_thread),
        };
        proc.wait_ready(Duration::from_secs(10));
        proc
    }

    fn wait_ready(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            match self.stderr_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(line) => {
                    let ready = line.starts_with("watching ");
                    seen.push(line);
                    if ready {
                        return;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        panic!("dar watch did not emit 'watching ' readiness line; stderr={seen:?}");
    }

    fn wait_stdout_line(&self, timeout: Duration, needle: &str) -> String {
        let deadline = Instant::now() + timeout;
        let mut seen = Vec::new();
        while Instant::now() < deadline {
            let rem = deadline.saturating_duration_since(Instant::now());
            let step = rem.min(Duration::from_millis(100));
            match self.stdout_rx.recv_timeout(step) {
                Ok(line) => {
                    let matched = line.contains(needle);
                    seen.push(line.clone());
                    if matched {
                        return line;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        panic!(
            "timed out waiting for stdout line containing '{needle}' within {:?}; seen={seen:?}",
            timeout
        );
    }

    fn shutdown_sigint(mut self) {
        send_sigint(&self.child);
        let sig_t = Instant::now();
        let status = loop {
            if let Some(st) = self.child.try_wait().expect("try_wait") {
                break st;
            }
            assert!(
                sig_t.elapsed() < Duration::from_secs(2),
                "dar watch did not exit cleanly after SIGINT within 2s"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            status.code(),
            Some(0),
            "expected exit code 0 after SIGINT, got {status:?}"
        );
        if let Some(h) = self.out_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.err_thread.take() {
            let _ = h.join();
        }
    }
}

impl Drop for WatchProc {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(h) = self.out_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.err_thread.take() {
            let _ = h.join();
        }
    }
}

fn overwrite_atomic(src: &Path, dst: &Path) {
    let parent = dst.parent().expect("dst parent");
    let tmp = parent.join(format!(
        ".tmp-write-{}",
        TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::copy(src, &tmp).expect("copy to tmp dar");
    std::fs::rename(&tmp, dst).expect("rename tmp dar");
}

#[test]
fn sdx006_r01_inspect_snapshot_and_hash_integrity() {
    let sample = sample_contract_dar();
    let sample_str = sample.to_str().expect("sample str");
    assert_eq!(
        std::fs::metadata(&sample).expect("sample metadata").len(),
        258_649,
        "sample-contract.dar size invariant violated"
    );

    let out1 = run_cli_json(&["dar", "inspect", sample_str, "--format", "json"]);
    let out2 = run_cli_json(&["dar", "inspect", sample_str, "--format", "json"]);
    assert_eq!(out1, out2, "R-A7: dar inspect must be deterministic");

    let golden: Value = serde_json::from_slice(
        &std::fs::read(golden_snapshot_path()).expect("read golden snapshot"),
    )
    .expect("parse golden json");
    assert_eq!(
        out1, golden,
        "dar inspect output drifted from golden snapshot"
    );

    // Cross-check every packageId against the pinned `daml inspect-dar` oracle dump
    // AND recompute SHA-256 of each `.dalf` Archive.payload independently via Python.
    let pkg_ids: Vec<String> = out1["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .map(|p| p["packageId"].as_str().expect("packageId").to_string())
        .collect();
    assert_eq!(pkg_ids.len(), 31);
    let main_id = out1["mainPackageId"].as_str().expect("mainPackageId");

    let oracle_txt = std::fs::read_to_string(oracle_fixture_txt_path()).expect("oracle txt");
    for pid in &pkg_ids {
        assert!(
            oracle_txt.contains(pid),
            "oracle inspect_dar_sample_contract.txt missing packageId {pid}"
        );
    }

    let tmp_dir = unique_temp_path("r01-tamper");
    std::fs::create_dir_all(&tmp_dir).expect("mkdir r01");
    let tampered = tmp_dir.join("tampered.dar");

    let py_check = Command::new("python3")
        .args([
            "-c",
            r#"
import sys, json, zipfile, hashlib

sample, tampered, report_json = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
main_id = report_json["mainPackageId"]
reported = sorted(p["packageId"] for p in report_json["packages"])

def read_varint(buf, i):
    shift = 0; val = 0
    while True:
        b = buf[i]; i += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80): return val, i
        shift += 7

def parse_archive_fields(data):
    i = 0; payload_span = None; declared_hash = ""
    while i < len(data):
        tag, i = read_varint(data, i); fn, wt = tag >> 3, tag & 7
        if wt == 0: _, i = read_varint(data, i)
        elif wt == 2:
            ln, i = read_varint(data, i)
            if fn == 3: payload_span = (i, i + ln)
            elif fn == 4: declared_hash = data[i:i+ln].decode()
            i += ln
        else:
            raise RuntimeError(f"unexpected wire type {wt}")
    return payload_span, declared_hash

calc_hashes = []
tampered_written = False
with zipfile.ZipFile(sample, "r") as zin, zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as zout:
    for info in zin.infolist():
        raw = zin.read(info.filename)
        if info.filename.endswith(".dalf"):
            span, declared = parse_archive_fields(raw)
            assert span is not None
            calc = hashlib.sha256(raw[span[0]:span[1]]).hexdigest()
            assert calc == declared, (info.filename, calc, declared)
            calc_hashes.append(calc)
            if calc == main_id and not tampered_written:
                buf = bytearray(raw)
                buf[span[0] + len(buf[span[0]:span[1]]) // 2] ^= 0x01
                raw = bytes(buf)
                tampered_written = True
        zout.writestr(info, raw)

assert sorted(calc_hashes) == reported
assert tampered_written
"#,
            sample_str,
            tampered.to_str().expect("tampered str"),
            &serde_json::to_string(&out1).expect("serialize out1"),
        ])
        .output()
        .expect("python3 hash check");
    assert!(
        py_check.status.success(),
        "python3 payload hash / tamper script failed: {}",
        String::from_utf8_lossy(&py_check.stderr)
    );

    let bad = Command::new(bin())
        .args([
            "dar",
            "inspect",
            tampered.to_str().expect("tampered str"),
            "--format",
            "json",
        ])
        .output()
        .expect("run dar inspect on tampered dar");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    assert_eq!(
        bad.status.code(),
        Some(3),
        "R-A1: tampered dalf payload must exit 3 (EXIT_MISMATCH); got {:?}, stderr={}",
        bad.status.code(),
        String::from_utf8_lossy(&bad.stderr)
    );
    let _ = main_id;
}

#[test]
fn sdx006_r02_diff_self_is_empty_and_deterministic() {
    let paths = vec![
        sample_contract_dar(),
        sdx006_dar("sdx006-v1"),
        sdx006_dar("sdx006-v2"),
        sdx006_dar("sdx006-v2-added"),
        sdx006_dar("sdx006-v3-dropfield"),
        sdx006_dar("sdx006-v4-keychange"),
    ];
    for p in paths {
        let p_str = p.to_str().expect("dar str");
        let d1 = run_cli_json(&["dar", "diff", p_str, p_str, "--format", "json"]);
        let d2 = run_cli_json(&["dar", "diff", p_str, p_str, "--format", "json"]);
        assert_eq!(d1, d2, "R-A7: dar diff(x, x) must be deterministic");
        assert!(str_array(&d1, "added").is_empty());
        assert!(str_array(&d1, "removed").is_empty());
        assert!(str_array(&d1, "changed").is_empty());
        assert!(str_array(&d1, "interfacesAdded").is_empty());
        assert!(str_array(&d1, "interfacesRemoved").is_empty());
        assert!(str_array(&d1, "interfacesChanged").is_empty());
        assert!(d1["templateChanges"].as_array().expect("tc").is_empty());
        assert_eq!(d1["upgradeCheck"]["passed"], json!(true));
    }
}

#[test]
fn sdx006_r03_diff_additive_optional_field_passes_upgrade() {
    let v1 = sdx006_dar("sdx006-v1");
    let v2 = sdx006_dar("sdx006-v2");
    let v1_str = v1.to_str().expect("v1 str");
    let v2_str = v2.to_str().expect("v2 str");

    let diff = run_cli_json(&["dar", "diff", v1_str, v2_str, "--format", "json"]);
    assert!(str_array(&diff, "added").is_empty());
    assert!(str_array(&diff, "removed").is_empty());
    assert_eq!(str_array(&diff, "changed"), vec!["Main:Vault"]);
    assert_eq!(
        str_array(&diff["templateChanges"][0], "fieldsAdded"),
        vec!["note"]
    );
    assert!(str_array(&diff["templateChanges"][0], "fieldsRemoved").is_empty());
    assert_eq!(diff["upgradeCheck"]["passed"], json!(true));

    let chk = Command::new(bin())
        .args(["dar", "check-upgrade", v1_str, v2_str])
        .output()
        .expect("check-upgrade v1 v2");
    assert!(chk.status.success(), "R-A3: check-upgrade v1->v2 must pass");
}

#[test]
fn sdx006_r04_diff_breaking_changes_fail_upgrade() {
    let v1 = sdx006_dar("sdx006-v1");
    let v2_added = sdx006_dar("sdx006-v2-added");
    let v3_drop = sdx006_dar("sdx006-v3-dropfield");
    let v4_key = sdx006_dar("sdx006-v4-keychange");

    let v1_s = v1.to_str().expect("v1");
    let v2a_s = v2_added.to_str().expect("v2a");
    let v3_s = v3_drop.to_str().expect("v3");
    let v4_s = v4_key.to_str().expect("v4");

    // 1. Dropped field (`balance` removed from `Main:Vault`).
    let d_drop = run_cli_json(&["dar", "diff", v1_s, v3_s, "--format", "json"]);
    assert_eq!(str_array(&d_drop, "changed"), vec!["Main:Vault"]);
    assert_eq!(
        str_array(&d_drop["templateChanges"][0], "fieldsRemoved"),
        vec!["balance"]
    );
    assert_eq!(d_drop["upgradeCheck"]["passed"], json!(false));

    // 2. Changed key type (`(Party, Text)` -> `Party`).
    let d_key = run_cli_json(&["dar", "diff", v1_s, v4_s, "--format", "json"]);
    assert_eq!(str_array(&d_key, "changed"), vec!["Main:Vault"]);
    assert!(
        !d_key["templateChanges"][0]["keyChanged"].is_null(),
        "keyChanged must be reported for v1->v4-keychange: {d_key}"
    );
    assert_eq!(d_key["upgradeCheck"]["passed"], json!(false));

    // 3. Removed template (`Main:Receipt` present in `v2-added`, missing in `v3-dropfield`).
    let d_rem = run_cli_json(&["dar", "diff", v2a_s, v3_s, "--format", "json"]);
    assert_eq!(str_array(&d_rem, "removed"), vec!["Main:Receipt"]);
    assert_eq!(d_rem["upgradeCheck"]["passed"], json!(false));

    // R-A3: agree with `canton-rs dar check-upgrade` on all three breaking pairs.
    for (old, new) in [(v1_s, v3_s), (v1_s, v4_s), (v2a_s, v3_s)] {
        let chk = Command::new(bin())
            .args(["dar", "check-upgrade", old, new])
            .output()
            .expect("check-upgrade breaking");
        assert!(
            !chk.status.success(),
            "check-upgrade unexpectedly passed for {old} -> {new}"
        );
    }
}

#[test]
fn sdx006_r05_diff_antisymmetry() {
    let pairs = [
        (sdx006_dar("sdx006-v1"), sdx006_dar("sdx006-v2")),
        (sdx006_dar("sdx006-v1"), sdx006_dar("sdx006-v2-added")),
        (
            sdx006_dar("sdx006-v2-added"),
            sdx006_dar("sdx006-v3-dropfield"),
        ),
    ];
    for (a, b) in &pairs {
        let a_s = a.to_str().expect("a");
        let b_s = b.to_str().expect("b");
        let fwd = run_cli_json(&["dar", "diff", a_s, b_s, "--format", "json"]);
        let rev = run_cli_json(&["dar", "diff", b_s, a_s, "--format", "json"]);

        assert_eq!(str_array(&fwd, "added"), str_array(&rev, "removed"));
        assert_eq!(str_array(&fwd, "removed"), str_array(&rev, "added"));
        assert_eq!(str_array(&fwd, "changed"), str_array(&rev, "changed"));
        assert_eq!(
            str_array(&fwd, "interfacesAdded"),
            str_array(&rev, "interfacesRemoved")
        );
        assert_eq!(
            str_array(&fwd, "interfacesRemoved"),
            str_array(&rev, "interfacesAdded")
        );
        assert_eq!(
            str_array(&fwd, "interfacesChanged"),
            str_array(&rev, "interfacesChanged")
        );

        let tc_fwd = fwd["templateChanges"].as_array().expect("tc fwd");
        let tc_rev = rev["templateChanges"].as_array().expect("tc rev");
        assert_eq!(tc_fwd.len(), tc_rev.len());
        for (tf, tr) in tc_fwd.iter().zip(tc_rev.iter()) {
            assert_eq!(tf["template"], tr["template"]);
            assert_eq!(str_array(tf, "fieldsAdded"), str_array(tr, "fieldsRemoved"));
            assert_eq!(str_array(tf, "fieldsRemoved"), str_array(tr, "fieldsAdded"));
            assert_eq!(
                str_array(tf, "choicesAdded"),
                str_array(tr, "choicesRemoved")
            );
            assert_eq!(
                str_array(tf, "choicesRemoved"),
                str_array(tr, "choicesAdded")
            );
            assert_eq!(
                str_array(tf, "implementsAdded"),
                str_array(tr, "implementsRemoved")
            );
            assert_eq!(
                str_array(tf, "implementsRemoved"),
                str_array(tr, "implementsAdded")
            );
            match (&tf["keyChanged"], &tr["keyChanged"]) {
                (Value::Null, Value::Null) => {}
                (f, r) => {
                    assert_eq!(f["before"], r["after"]);
                    assert_eq!(f["after"], r["before"]);
                }
            }
        }
    }
}

#[test]
fn sdx006_r06_watch_uploads_and_vets_both_participants() {
    let _guard = DAR_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let v1 = sdx006_dar("sdx006-v1");
    let v2 = sdx006_dar("sdx006-v2");

    let v2_inspect = run_cli_json(&[
        "dar",
        "inspect",
        v2.to_str().expect("v2"),
        "--format",
        "json",
    ]);
    let v2_pkg_id = v2_inspect["mainPackageId"].as_str().expect("v2 pkg id");

    let stack = DualParticipantStack::start("r06", &v1);
    let watched = stack.work.join("watched.dar");
    overwrite_atomic(&v1, &watched);

    let watch = WatchProc::spawn(&stack, &watched, 150);
    std::thread::sleep(Duration::from_millis(50));

    overwrite_atomic(&v2, &watched);
    let line = watch.wait_stdout_line(Duration::from_secs(10), "uploaded ");
    assert_eq!(line.trim(), format!("uploaded {v2_pkg_id}"));

    assert!(
        stack.package_ids(&stack.p1_url).contains(v2_pkg_id),
        "p1 missing uploaded package {v2_pkg_id}"
    );
    assert!(
        stack.package_ids(&stack.p2_url).contains(v2_pkg_id),
        "p2 missing uploaded package {v2_pkg_id}"
    );
    assert!(
        stack.is_vetted(&stack.p1_url, v2_pkg_id),
        "p1 did not vet {v2_pkg_id}"
    );
    assert!(
        stack.is_vetted(&stack.p2_url, v2_pkg_id),
        "p2 did not vet {v2_pkg_id}"
    );

    watch.shutdown_sigint();
}

#[test]
fn sdx006_r07_watch_rejects_incompatible_locally_and_keeps_watching() {
    let _guard = DAR_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let v1 = sdx006_dar("sdx006-v1");
    let v2 = sdx006_dar("sdx006-v2");
    let v3_drop = sdx006_dar("sdx006-v3-dropfield");
    let v2_added = sdx006_dar("sdx006-v2-added");

    let v2_id = run_cli_json(&[
        "dar",
        "inspect",
        v2.to_str().expect("v2"),
        "--format",
        "json",
    ])["mainPackageId"]
        .as_str()
        .expect("v2 id")
        .to_string();
    let v2a_id = run_cli_json(&[
        "dar",
        "inspect",
        v2_added.to_str().expect("v2a"),
        "--format",
        "json",
    ])["mainPackageId"]
        .as_str()
        .expect("v2a id")
        .to_string();

    let stack = DualParticipantStack::start("r07", &v1);
    let watched = stack.work.join("watched.dar");
    overwrite_atomic(&v1, &watched);

    let watch = WatchProc::spawn(&stack, &watched, 150);
    std::thread::sleep(Duration::from_millis(50));

    // Step 1: Compatible upgrade v1 -> v2 succeeds and increments POST /v2/packages metrics.
    overwrite_atomic(&v2, &watched);
    let up_line = watch.wait_stdout_line(Duration::from_secs(10), "uploaded ");
    assert_eq!(up_line.trim(), format!("uploaded {v2_id}"));

    let p1_pkgs_before = stack.package_ids(&stack.p1_url);
    let p2_pkgs_before = stack.package_ids(&stack.p2_url);
    let p1_posts_before = stack.post_packages_count(&stack.p1_url);
    let p2_posts_before = stack.post_packages_count(&stack.p2_url);
    assert!(
        p1_posts_before >= 1 && p2_posts_before >= 1,
        "expected POST /v2/packages metrics >= 1 on p1 ({p1_posts_before}) and p2 ({p2_posts_before})"
    );

    // Step 2: Incompatible v3-dropfield MUST be blocked locally by dar watch
    // BEFORE any `POST /v2/packages` HTTP call hits either participant.
    overwrite_atomic(&v3_drop, &watched);
    let rej_line = watch.wait_stdout_line(Duration::from_secs(10), "rejected:");
    assert!(
        rej_line.contains("NOT_VALID_UPGRADE_PACKAGE"),
        "expected NOT_VALID_UPGRADE_PACKAGE in rejection line, got: {rej_line}"
    );

    // Give any stray background request a brief window to settle before checking metrics/store.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(stack.package_ids(&stack.p1_url), p1_pkgs_before);
    assert_eq!(stack.package_ids(&stack.p2_url), p2_pkgs_before);
    assert_eq!(
        stack.post_packages_count(&stack.p1_url),
        p1_posts_before,
        "M-watch-skip-upgrade check: p1 received POST /v2/packages for locally-invalid upgrade"
    );
    assert_eq!(
        stack.post_packages_count(&stack.p2_url),
        p2_posts_before,
        "M-watch-skip-upgrade check: p2 received POST /v2/packages for locally-invalid upgrade"
    );

    // Step 3: Watcher stays alive (`R-A5`) and uploads subsequent valid v2-added upgrade.
    overwrite_atomic(&v2_added, &watched);
    let up2_line = watch.wait_stdout_line(Duration::from_secs(10), "uploaded ");
    assert_eq!(up2_line.trim(), format!("uploaded {v2a_id}"));
    assert!(stack.is_vetted(&stack.p1_url, &v2a_id));
    assert!(stack.is_vetted(&stack.p2_url, &v2a_id));
    assert_eq!(
        stack.post_packages_count(&stack.p1_url),
        p1_posts_before + 1
    );
    assert_eq!(
        stack.post_packages_count(&stack.p2_url),
        p2_posts_before + 1
    );

    watch.shutdown_sigint();
}

#[test]
fn sdx006_r08_watch_truncated_dar_no_panic_no_upload() {
    let _guard = DAR_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let v1 = sdx006_dar("sdx006-v1");
    let v2 = sdx006_dar("sdx006-v2");

    let stack = DualParticipantStack::start("r08", &v1);
    let watched = stack.work.join("watched.dar");
    overwrite_atomic(&v1, &watched);

    let watch = WatchProc::spawn(&stack, &watched, 150);
    std::thread::sleep(Duration::from_millis(50));

    let p1_pkgs_before = stack.package_ids(&stack.p1_url);
    let p2_pkgs_before = stack.package_ids(&stack.p2_url);
    let p1_posts_before = stack.post_packages_count(&stack.p1_url);
    let p2_posts_before = stack.post_packages_count(&stack.p2_url);

    // Write a 40% truncated DAR directly over watched.dar.
    let v2_bytes = std::fs::read(&v2).expect("read v2");
    let trunc_len = (v2_bytes.len() * 40) / 100;
    std::fs::write(&watched, &v2_bytes[..trunc_len]).expect("write truncated dar");
    let line1 = watch.wait_stdout_line(Duration::from_secs(10), "rejected: parse error:");
    assert!(line1.starts_with("rejected: parse error:"), "got: {line1}");

    // Follow with raw non-ZIP bytes to ensure watcher keeps running cleanly.
    std::fs::write(&watched, b"not-a-valid-dar-zip-archive-bytes").expect("write garbage bytes");
    let line2 = watch.wait_stdout_line(Duration::from_secs(10), "rejected: parse error:");
    assert!(line2.starts_with("rejected: parse error:"), "got: {line2}");

    assert_eq!(stack.package_ids(&stack.p1_url), p1_pkgs_before);
    assert_eq!(stack.package_ids(&stack.p2_url), p2_pkgs_before);
    assert_eq!(stack.post_packages_count(&stack.p1_url), p1_posts_before);
    assert_eq!(stack.post_packages_count(&stack.p2_url), p2_posts_before);

    watch.shutdown_sigint();
}
