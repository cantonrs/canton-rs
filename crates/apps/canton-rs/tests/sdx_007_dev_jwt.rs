//! E2E integration tests for `S-DX-007` (`J-01..J-06`, `J-A1..J-A6`):
//! - `J-01`: `daemon up --dev-auth` creates `dev-jwt.key` (`0600`), unauth `/v2/parties` -> `401`,
//!   `daemon creds` prints `"개발용, 운영 사용 금지"` and signed HS256 token -> `/v2/parties` -> `200`,
//!   and `daemon status --format json` shows `p1.json` as `"up"`.
//! - `J-02`: Token issued for instance `a` fails with `401` on instance `b` (both with distinct
//!   secrets AND when `b` shares `a`'s `dev-jwt.key`, proving `aud` enforcement).
//! - `J-03`: `--ttl 1s` token fails with `401` once expired (`now >= iat + ttl`).
//! - `J-04`: Modifying payload (valid JSON `exp - 1`) OR signature flips -> `401`.
//! - `J-05`: Starting on `0.0.0.0` (`--bind 0.0.0.0` or `--metrics-bind 0.0.0.0`) refuses
//!   `daemon creds` with `exit = 2` and leaves participant dev auth disabled (`open`).
//! - `J-06`: Secret bytes (hex/upper-hex/base64/base64url) appear `0` times across logs,
//!   `status`, `ps`, `inspect`, `daemon.*.json`, and `ps` command lines.

#![allow(clippy::unwrap_used, reason = "integration test")]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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
    let root = std::env::temp_dir().join(format!("sdx007-{tag}-{}-{seq}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("xdg")).expect("mkdir xdg");
    root
}

fn write_manifest(dir: &Path, name: &str, base_port: u16, metrics_port: u16) -> PathBuf {
    fs::create_dir_all(dir).expect("mkdir manifest dir");
    let manifest_path = dir.join("canton-daemon.yaml");
    let dar = sample_dar();
    let s_pub = base_port;
    let s_adm = base_port + 1;
    let m_adm = base_port + 2;
    let p1_json = base_port + 3;
    let yaml = format!(
        "name: {name}
synchronizer: sdx007-sync
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
    dars: [\"{dar}\"]
    depends_on: [s1, m1]
    restart: unless-stopped
",
        dar = dar.display()
    );
    fs::write(&manifest_path, yaml).expect("write manifest");
    manifest_path
}

fn run_with_xdg(xdg_state_home: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env("XDG_STATE_HOME", xdg_state_home)
        .env("CANTON_RS_DETACH_TIMEOUT_SECS", "90")
        .output()
        .unwrap_or_else(|e| panic!("failed to run canton-rs {:?}: {e}", args))
}

fn daemon_up_dev(xdg: &Path, name: &str, manifest: &Path, extra_args: &[&str]) {
    let m_str = manifest.display().to_string();
    let mut args = vec![
        "daemon",
        "up",
        "--name",
        name,
        "-f",
        &m_str,
        "--state-in-files",
        "--dev-auth",
        "-d",
    ];
    args.extend_from_slice(extra_args);
    let out = run_with_xdg(xdg, &args);
    assert!(
        out.status.success(),
        "daemon up failed for '{name}': stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn instance_dir(xdg: &Path, name: &str) -> PathBuf {
    xdg.join("canton-rs/instances").join(name)
}

fn http_get(port: u16, path: &str, token: Option<&str>) -> Result<(u16, String), String> {
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e| format!("addr: {e}"))?;
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}Connection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
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
    let body = String::from_utf8_lossy(&raw[split + 4..]).into_owned();
    Ok((status, body))
}

fn wait_ready(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok((200, _)) = http_get(port, "/readyz", None) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("participant on port {port} did not return 200 on /readyz within {timeout:?}");
}

fn creds_json(xdg: &Path, name: &str, extra_args: &[&str]) -> Value {
    let mut args = vec!["daemon", "creds", "--name", name, "--format", "json"];
    args.extend_from_slice(extra_args);
    let out = run_with_xdg(xdg, &args);
    assert!(
        out.status.success(),
        "daemon creds failed for '{name}': stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse creds json")
}

struct InstanceGuard {
    root: PathBuf,
    xdg: PathBuf,
    names: Vec<String>,
    ports: Vec<u16>,
}

impl InstanceGuard {
    fn new(root: PathBuf, xdg: PathBuf, names: Vec<String>, ports: Vec<u16>) -> Self {
        Self {
            root,
            xdg,
            names,
            ports,
        }
    }
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = Command::new(bin())
                .args(["daemon", "down", "--name", name, "--timeout-secs", "5"])
                .env("XDG_STATE_HOME", &self.xdg)
                .output();
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let busy = self.ports.iter().any(|p| {
                let addr: SocketAddr = format!("127.0.0.1:{p}").parse().unwrap();
                TcpStream::connect_timeout(&addr, Duration::from_millis(30)).is_ok()
            });
            if !busy {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn b64url_decode(s: &str) -> Vec<u8> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|c| *c != b'=') {
        let val = B64.iter().position(|x| *x == c).expect("valid b64url") as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

fn b64url_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        }
    }
    out
}

fn b64_std_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn decode_hex_bytes(hex_str: &str) -> Vec<u8> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("hex byte"))
        .collect()
}

#[test]
fn j01_issue_and_use() {
    let root = unique_root("j01");
    let xdg = root.join("xdg");
    let manifest = write_manifest(&root, "j01-a", 38110, 0);
    let _guard = InstanceGuard::new(
        root,
        xdg.clone(),
        vec!["j01-a".to_string()],
        vec![38110, 38111, 38112, 38113],
    );

    daemon_up_dev(&xdg, "j01-a", &manifest, &[]);
    wait_ready(38113, Duration::from_secs(45));

    let dir = instance_dir(&xdg, "j01-a");
    let key_path = dir.join("dev-jwt.key");
    assert!(key_path.is_file(), "dev-jwt.key missing");
    #[cfg(unix)]
    {
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "dev-jwt.key must have 0600 permissions");
    }
    let key_hex = fs::read_to_string(&key_path).unwrap();
    let trimmed = key_hex.trim();
    assert_eq!(trimmed.len(), 64, "256-bit hex secret must be 64 chars");
    assert!(trimmed
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));

    // Unauthenticated call must fail with 401.
    let (unauth_code, _) = http_get(38113, "/v2/parties", None).unwrap();
    assert_eq!(unauth_code, 401, "expected 401 without bearer token");

    // Text output includes mandatory warning + token.
    let text_out = run_with_xdg(&xdg, &["daemon", "creds", "--name", "j01-a"]);
    assert!(
        text_out.status.success(),
        "daemon creds text failed: {}",
        String::from_utf8_lossy(&text_out.stderr)
    );
    let text = String::from_utf8_lossy(&text_out.stdout);
    assert!(
        text.contains("개발용, 운영 사용 금지"),
        "missing warning in text output: {text}"
    );

    // JSON output includes claims + mandatory warning, and authorizes `/v2/parties`.
    let json = creds_json(&xdg, "j01-a", &[]);
    assert!(
        json["warning"]
            .as_str()
            .is_some_and(|w| w.contains("개발용, 운영 사용 금지")),
        "missing warning in json: {json}"
    );
    assert_eq!(json["canton_rs_dev"], true);
    assert_eq!(json["scope"], "daml_ledger_api");
    assert_eq!(json["sub"], "participant_admin");
    let aud = json["aud"].as_str().unwrap();
    assert!(aud.starts_with("p1::1220"), "unexpected aud: {aud}");
    assert!(json["exp"].as_i64().unwrap() > json["iat"].as_i64().unwrap());

    let tok = json["token"].as_str().unwrap();
    let (auth_code, parties_body) = http_get(38113, "/v2/parties", Some(tok)).unwrap();
    assert_eq!(auth_code, 200, "GET /v2/parties failed: {parties_body}");

    let (pid_code, pid_body) = http_get(38113, "/v2/parties/participant-id", Some(tok)).unwrap();
    assert_eq!(pid_code, 200, "GET /v2/parties/participant-id: {pid_body}");
    let pid_json: Value = serde_json::from_str(&pid_body).unwrap();
    assert_eq!(pid_json["participantId"], aud);

    // `daemon status` reports `p1.json` as up even with dev-auth enabled.
    let st_out = run_with_xdg(
        &xdg,
        &["daemon", "status", "--name", "j01-a", "--format", "json"],
    );
    assert!(st_out.status.success());
    let st_json: Value = serde_json::from_slice(&st_out.stdout).unwrap();
    assert_eq!(
        st_json["endpoints"]["p1.json"]["state"], "up",
        "daemon status should report p1.json up: {st_json}"
    );
}

#[test]
fn j02_instance_isolation() {
    let root = unique_root("j02");
    let xdg = root.join("xdg");
    let manifest = write_manifest(&root, "j02-stack", 38210, 0);
    let _guard = InstanceGuard::new(
        root,
        xdg.clone(),
        vec!["j02-a".to_string(), "j02-b".to_string()],
        vec![38210, 38211, 38212, 38213, 38260, 38261, 38262, 38263],
    );

    std::thread::scope(|s| {
        s.spawn(|| daemon_up_dev(&xdg, "j02-a", &manifest, &["--port-offset", "0"]));
        s.spawn(|| daemon_up_dev(&xdg, "j02-b", &manifest, &["--port-offset", "50"]));
    });
    wait_ready(38213, Duration::from_secs(45));
    wait_ready(38263, Duration::from_secs(45));

    let cred_a = creds_json(&xdg, "j02-a", &[]);
    let tok_a = cred_a["token"].as_str().unwrap();
    assert_eq!(http_get(38213, "/v2/parties", Some(tok_a)).unwrap().0, 200);
    assert_eq!(
        http_get(38263, "/v2/parties", Some(tok_a)).unwrap().0,
        401,
        "a's token must be rejected by b"
    );

    // Same-secret / distinct-aud check (kills Mutation #2 when `aud` validation is removed):
    // Copy a's dev-jwt.key over b's and restart p1 on b so both share identical HS256 secret.
    let key_a = fs::read(instance_dir(&xdg, "j02-a").join("dev-jwt.key")).unwrap();
    let key_b_path = instance_dir(&xdg, "j02-b").join("dev-jwt.key");
    fs::write(&key_b_path, &key_a).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&key_b_path, fs::Permissions::from_mode(0o600)).unwrap();

    let restart = run_with_xdg(&xdg, &["daemon", "restart", "p1", "--name", "j02-b"]);
    assert!(
        restart.status.success(),
        "restart p1 on b failed: {}",
        String::from_utf8_lossy(&restart.stderr)
    );
    wait_ready(38263, Duration::from_secs(45));

    let cred_b = creds_json(&xdg, "j02-b", &[]);
    let tok_b = cred_b["token"].as_str().unwrap();
    assert_ne!(cred_a["aud"], cred_b["aud"]);
    assert_eq!(
        http_get(38263, "/v2/parties", Some(tok_b)).unwrap().0,
        200,
        "b's own token must pass after key reload"
    );
    assert_eq!(
        http_get(38263, "/v2/parties", Some(tok_a)).unwrap().0,
        401,
        "a's token must STILL return 401 on b even when sharing the HS256 secret (aud check)"
    );
}

#[test]
fn j03_ttl_expiration() {
    let root = unique_root("j03");
    let xdg = root.join("xdg");
    let manifest = write_manifest(&root, "j03-c", 38310, 0);
    let _guard = InstanceGuard::new(
        root,
        xdg.clone(),
        vec!["j03-c".to_string()],
        vec![38310, 38311, 38312, 38313],
    );

    daemon_up_dev(&xdg, "j03-c", &manifest, &[]);
    wait_ready(38313, Duration::from_secs(45));

    let long_cred = creds_json(&xdg, "j03-c", &["--ttl", "60s"]);
    let long_tok = long_cred["token"].as_str().unwrap();
    assert_eq!(
        http_get(38313, "/v2/parties", Some(long_tok)).unwrap().0,
        200
    );

    let short_cred = creds_json(&xdg, "j03-c", &["--ttl", "1s"]);
    let short_tok = short_cred["token"].as_str().unwrap();
    assert_eq!(
        short_cred["exp"].as_i64().unwrap() - short_cred["iat"].as_i64().unwrap(),
        1
    );

    std::thread::sleep(Duration::from_millis(2200));
    assert_eq!(
        http_get(38313, "/v2/parties", Some(short_tok)).unwrap().0,
        401,
        "--ttl 1s token must be rejected after 2.2s"
    );
    assert_eq!(
        http_get(38313, "/v2/parties", Some(long_tok)).unwrap().0,
        200,
        "--ttl 60s token must remain valid"
    );
}

#[test]
fn j04_tampered_token_rejected() {
    let root = unique_root("j04");
    let xdg = root.join("xdg");
    let manifest = write_manifest(&root, "j04-d", 38410, 0);
    let _guard = InstanceGuard::new(
        root,
        xdg.clone(),
        vec!["j04-d".to_string()],
        vec![38410, 38411, 38412, 38413],
    );

    daemon_up_dev(&xdg, "j04-d", &manifest, &[]);
    wait_ready(38413, Duration::from_secs(45));

    let cred = creds_json(&xdg, "j04-d", &["--ttl", "1h"]);
    let tok = cred["token"].as_str().unwrap();
    assert_eq!(http_get(38413, "/v2/parties", Some(tok)).unwrap().0, 200);

    let parts: Vec<&str> = tok.split('.').collect();
    assert_eq!(parts.len(), 3);

    // Payload tamper keeping valid JSON (`exp` altered by 1s): fails 401 when HMAC is checked,
    // returns 200 if signature verification is disabled (Mutation #1).
    let raw_payload = b64url_decode(parts[1]);
    let mut claims: Value = serde_json::from_slice(&raw_payload).unwrap();
    let orig_exp = claims["exp"].as_i64().unwrap();
    claims["exp"] = Value::from(orig_exp - 1);
    let tampered_payload = b64url_encode(claims.to_string().as_bytes());
    assert_ne!(tampered_payload, parts[1]);
    let payload_tampered_tok = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);
    assert_eq!(
        http_get(38413, "/v2/parties", Some(&payload_tampered_tok))
            .unwrap()
            .0,
        401,
        "payload-tampered JWT must be rejected with 401"
    );

    // Signature flip: must also return 401.
    let mut sig_bytes = parts[2].as_bytes().to_vec();
    sig_bytes[0] = if sig_bytes[0] == b'A' { b'B' } else { b'A' };
    let sig_tampered_tok = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        String::from_utf8(sig_bytes).unwrap()
    );
    assert_eq!(
        http_get(38413, "/v2/parties", Some(&sig_tampered_tok))
            .unwrap()
            .0,
        401,
        "signature-tampered JWT must be rejected with 401"
    );
}

#[test]
fn j05_non_loopback_refused() {
    let root = unique_root("j05");
    let xdg = root.join("xdg");
    let manifest = write_manifest(&root, "j05-nl", 38510, 38514);
    let _guard = InstanceGuard::new(
        root,
        xdg.clone(),
        vec!["j05-nl1".to_string(), "j05-nl2".to_string()],
        vec![
            38510, 38511, 38512, 38513, 38514, 38560, 38561, 38562, 38563, 38564,
        ],
    );

    std::thread::scope(|s| {
        s.spawn(|| {
            daemon_up_dev(
                &xdg,
                "j05-nl1",
                &manifest,
                &["--port-offset", "0", "--bind", "0.0.0.0"],
            )
        });
        s.spawn(|| {
            daemon_up_dev(
                &xdg,
                "j05-nl2",
                &manifest,
                &["--port-offset", "50", "--metrics-bind", "0.0.0.0"],
            )
        });
    });
    wait_ready(38513, Duration::from_secs(45));
    wait_ready(38563, Duration::from_secs(45));

    for inst in ["j05-nl1", "j05-nl2"] {
        let out = run_with_xdg(&xdg, &["daemon", "creds", "--name", inst]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "daemon creds must exit 2 for non-loopback '{inst}': stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !instance_dir(&xdg, inst).join("dev-jwt.key").exists(),
            "dev-jwt.key must not be created on non-loopback instance '{inst}'"
        );
    }

    // J-A5: dev auth mode must NOT be turned on when any bind is non-loopback.
    let (code, body) = http_get(38513, "/v2/parties", None).unwrap();
    assert_eq!(
        code, 200,
        "non-loopback participant should leave dev-auth off (open): {body}"
    );
    let insp = run_with_xdg(
        &xdg,
        &["daemon", "inspect", "p1", "--name", "j05-nl1", "--json"],
    );
    assert!(insp.status.success());
    let insp_json: Value = serde_json::from_slice(&insp.stdout).unwrap();
    assert_eq!(insp_json["auth_mode"], "open");
}

#[test]
fn j06_secret_not_exposed() {
    let root = unique_root("j06");
    let xdg = root.join("xdg");
    let manifest = write_manifest(&root, "j06-sec", 38610, 38614);
    let _guard = InstanceGuard::new(
        root,
        xdg.clone(),
        vec!["j06-sec".to_string()],
        vec![38610, 38611, 38612, 38613, 38614],
    );

    daemon_up_dev(&xdg, "j06-sec", &manifest, &[]);
    wait_ready(38613, Duration::from_secs(45));

    let cred = creds_json(&xdg, "j06-sec", &[]);
    let tok = cred["token"].as_str().unwrap();
    assert_eq!(http_get(38613, "/v2/parties", Some(tok)).unwrap().0, 200);
    assert_eq!(http_get(38613, "/v2/parties", None).unwrap().0, 401);

    let dir = instance_dir(&xdg, "j06-sec");
    let hex_lower = fs::read_to_string(dir.join("dev-jwt.key"))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(hex_lower.len(), 64);
    let hex_upper = hex_lower.to_ascii_uppercase();
    let raw_bytes = decode_hex_bytes(&hex_lower);
    let b64_std = b64_std_encode(&raw_bytes);
    let b64_url = b64url_encode(&raw_bytes);

    let mut haystack = String::new();
    for args in [
        &["daemon", "status", "--name", "j06-sec"][..],
        &["daemon", "status", "--name", "j06-sec", "--format", "json"][..],
        &["daemon", "ps", "--name", "j06-sec"][..],
        &["daemon", "ps", "--name", "j06-sec", "--json"][..],
        &["daemon", "inspect", "p1", "--name", "j06-sec"][..],
        &["daemon", "inspect", "p1", "--name", "j06-sec", "--json"][..],
        &["daemon", "logs", "--name", "j06-sec"][..],
    ] {
        let out = run_with_xdg(&xdg, args);
        assert!(
            out.status.success(),
            "command {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        haystack.push_str(&String::from_utf8_lossy(&out.stdout));
        haystack.push_str(&String::from_utf8_lossy(&out.stderr));
        haystack.push('\n');
    }

    for meta_file in [
        "daemon.recipe.json",
        "instance.json",
        "daemon.pids.json",
        "daemon.ready.json",
    ] {
        let p = dir.join(meta_file);
        if p.is_file() {
            haystack.push_str(&fs::read_to_string(&p).unwrap());
            haystack.push('\n');
        }
    }

    let logs_dir = dir.join("logs");
    if logs_dir.is_dir() {
        for entry in fs::read_dir(&logs_dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_file() {
                haystack.push_str(&fs::read_to_string(&p).unwrap_or_default());
                haystack.push('\n');
            }
        }
    }

    // Inspect live child command lines via `ps`.
    if let Ok(pids_raw) = fs::read_to_string(dir.join("daemon.pids.json")) {
        if let Ok(pids_json) = serde_json::from_str::<Value>(&pids_raw) {
            if let Some(entries) = pids_json["entries"].as_array() {
                for entry in entries {
                    if let Some(pid) = entry["pid"].as_u64() {
                        if let Ok(ps_out) = Command::new("ps")
                            .args(["-p", &pid.to_string(), "-ww", "-o", "args="])
                            .output()
                        {
                            haystack.push_str(&String::from_utf8_lossy(&ps_out.stdout));
                            haystack.push('\n');
                        }
                    }
                }
            }
        }
    }

    for needle in [&hex_lower, &hex_upper, &b64_std, &b64_url] {
        assert!(
            !haystack.contains(needle.as_str()),
            "secret representation '{needle}' leaked in logs/status/inspect/argv!"
        );
    }
}
