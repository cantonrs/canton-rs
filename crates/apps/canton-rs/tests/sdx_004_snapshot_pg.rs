//! PostgreSQL (`--pg-url`) E2E integration test for `S-DX-004` (`S-09`).
//!
//! Requires `CANTON_RS_PG_URL` pointing to a live PostgreSQL instance (see
//! `scripts/verify-sdx-004-pg.sh`). Panics immediately if unset (no silent skip).

#![cfg(feature = "pg-tests")]

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
const BASE_OFFSETS: [u16; 6] = [0, 1, 2, 100, 101, 300];
const ASSET_TEMPLATE: &str = "#sample-contract:AssetHolding:AssetHolding";

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

fn sdx006_v1_dar() -> PathBuf {
    repo_root().join("contracts/fixtures/sdx006-v1/target/sdx006-pkg.dar")
}

fn unique_temp_path(tag: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("sdx004-pg-{tag}-{}-{seq}", std::process::id()))
}

fn choose_clean_base_port() -> u16 {
    for candidate in [42500u16, 44500, 46500] {
        let busy = [0u16, 1000].iter().any(|off| {
            BASE_OFFSETS.iter().any(|d| {
                let p = candidate + off + d;
                TcpListener::bind(("127.0.0.1", p)).is_err()
            })
        });
        if !busy {
            return candidate;
        }
    }
    42500
}

fn wait_ports_free_best_effort(
    base_port: u16,
    offsets: &[u16],
    within: Duration,
) -> Option<Vec<u16>> {
    let ports: Vec<u16> = offsets
        .iter()
        .flat_map(|off| BASE_OFFSETS.iter().map(move |d| base_port + off + d))
        .collect();
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        let all_free = ports.iter().all(|p| {
            let addr: SocketAddr = format!("127.0.0.1:{p}").parse().expect("loopback addr");
            TcpStream::connect_timeout(&addr, Duration::from_millis(40)).is_err()
        });
        if all_free {
            return None;
        }
        std::thread::sleep(Duration::from_millis(80));
    }
    Some(ports)
}

fn wait_ports_free(base_port: u16, offsets: &[u16], within: Duration) {
    if let Some(ports) = wait_ports_free_best_effort(base_port, offsets, within) {
        panic!("ports remained busy after PG test cleanup: {ports:?}");
    }
}

fn write_dual_manifest(dir: &Path, name: &str, base_port: u16) -> PathBuf {
    fs::create_dir_all(dir).expect("mkdir manifest dir");
    let manifest_path = dir.join("canton-daemon.yaml");
    let dar = sample_dar();
    let yaml = format!(
        "name: {name}
synchronizer: sdx004-pg-sync
state_dir: ./canton-rs-state
metrics_port: {metrics}
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
  p2:
    role: participant
    ports: [\"{p2_json}:json-api\"]
    dars: [\"{dar}\"]
    depends_on: [s1, m1]
    restart: unless-stopped
",
        s_pub = base_port,
        s_adm = base_port + 1,
        m_adm = base_port + 2,
        p1_json = base_port + 100,
        p2_json = base_port + 101,
        metrics = base_port + 300,
        dar = dar.display(),
    );
    fs::write(&manifest_path, yaml).expect("write manifest");
    manifest_path
}

struct PgStackGuard {
    root: PathBuf,
    xdg: PathBuf,
    base_port: u16,
    names: Vec<String>,
}

impl PgStackGuard {
    fn new(tag: &str) -> Self {
        let root = unique_temp_path(tag);
        let xdg = root.join("xdg");
        fs::create_dir_all(&xdg).expect("mkdir xdg");
        let base_port = choose_clean_base_port();
        wait_ports_free(base_port, &[0, 1000], Duration::from_secs(10));
        Self {
            root,
            xdg,
            base_port,
            names: Vec::new(),
        }
    }

    fn track(&mut self, name: &str) {
        if !self.names.iter().any(|n| n == name) {
            self.names.push(name.to_string());
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.env("XDG_STATE_HOME", &self.xdg)
            .args(args)
            .stdin(Stdio::null());
        c
    }

    fn run_checked(&self, args: &[&str]) -> Output {
        let out = self.cmd(args).output().expect("spawn canton-rs");
        assert!(
            out.status.success(),
            "canton-rs {:?} failed ({}):\nstdout:\n{}\nstderr:\n{}",
            args,
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn start_pg_stack(&mut self, name: &str, pg_url: &str) -> StackEndpoints {
        let manifest = write_dual_manifest(&self.root.join("work"), name, self.base_port);
        self.track(name);
        self.run_checked(&[
            "daemon",
            "up",
            "--name",
            name,
            "-f",
            manifest.to_str().expect("manifest"),
            "--pg-url",
            pg_url,
            "-d",
        ]);
        self.wait_ready(name)
    }

    fn wait_ready(&self, name: &str) -> StackEndpoints {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            let out = self
                .cmd(&["daemon", "status", "--name", name, "--format", "json"])
                .output()
                .expect("daemon status");
            if out.status.success() {
                if let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) {
                    let eps = &v["endpoints"];
                    let required = ["s1.public", "s1.metrics", "m1.admin", "p1.json", "p2.json"];
                    if required.iter().all(|k| eps[k]["state"] == "up") {
                        return StackEndpoints::from_status_json(&v);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("PG stack '{name}' did not become ready within 120s");
    }
}

impl Drop for PgStackGuard {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = self
                .cmd(&["daemon", "remove", "--name", name, "--force"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if let Some(ports) =
            wait_ports_free_best_effort(self.base_port, &[0, 1000], Duration::from_secs(12))
        {
            eprintln!("WARN: ports remained busy after PG cleanup: {ports:?}");
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Debug)]
struct StackEndpoints {
    p1_url: String,
    p2_url: String,
    ports: BTreeSet<u16>,
}

impl StackEndpoints {
    fn from_status_json(v: &Value) -> Self {
        let eps = v["endpoints"].as_object().expect("endpoints object");
        let mut ports = BTreeSet::new();
        for ep in eps.values() {
            if let Some(url) = ep["url"].as_str() {
                if let Some(port) = url
                    .split("://")
                    .nth(1)
                    .and_then(|r| r.split('/').next())
                    .and_then(|hp| hp.rsplit_once(':'))
                    .and_then(|(_, p)| p.parse::<u16>().ok())
                {
                    ports.insert(port);
                }
            }
        }
        Self {
            p1_url: eps["p1.json"]["url"]
                .as_str()
                .expect("p1.json url")
                .to_string(),
            p2_url: eps["p2.json"]["url"]
                .as_str()
                .expect("p2.json url")
                .to_string(),
            ports,
        }
    }
}

fn http_send(
    base_url: &str,
    method: &str,
    path: &str,
    content_type: &str,
    payload: &[u8],
) -> (u16, String) {
    let host_port = base_url
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("expected http:// URL, got {base_url}"));
    let addr: SocketAddr = host_port.parse().expect("parse host:port");
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).expect("connect");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let head_str = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(head_str.as_bytes()).expect("write header");
    if !payload.is_empty() {
        stream.write_all(payload).expect("write body");
    }
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
    let payload = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    let (code, text) = http_send(base_url, method, path, "application/json", &payload);
    let parsed = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (code, parsed)
}

fn allocate_party(base_url: &str, hint: &str) -> String {
    let (code, body) = http_json(
        base_url,
        "POST",
        "/v2/parties",
        Some(&json!({"partyIdHint": hint, "identityProviderId": ""})),
    );
    assert_eq!(code, 200, "allocate party {hint} failed ({code}): {body}");
    body.pointer("/partyDetails/party")
        .and_then(Value::as_str)
        .expect("party id")
        .to_string()
}

fn create_user(base_url: &str, user_id: &str, primary_party: &str) {
    let req = json!({
        "user": {
            "id": user_id,
            "primaryParty": primary_party,
            "isDeactivated": false,
            "identityProviderId": ""
        },
        "rights": []
    });
    let (code, body) = http_json(base_url, "POST", "/v2/users", Some(&req));
    assert_eq!(code, 200, "POST /v2/users failed ({code}): {body}");
}

fn upload_dar(base_url: &str, dar_path: &Path) {
    let bytes = fs::read(dar_path).expect("read dar bytes");
    let (code, body) = http_send(
        base_url,
        "POST",
        "/v2/packages",
        "application/octet-stream",
        &bytes,
    );
    assert!(code < 300, "POST /v2/packages failed ({code}): {body}");
}

fn create_holding(p1_url: &str, cmd_id: &str, bank: &str, bob: &str, amount: &str) -> String {
    let req = json!({
        "commands": {
            "commands": [{
                "CreateCommand": {
                    "templateId": ASSET_TEMPLATE,
                    "createArguments": {
                        "bank": bank,
                        "owner": bank,
                        "auditor": bob,
                        "assetSymbol": "USD",
                        "amount": amount
                    }
                }
            }],
            "commandId": cmd_id,
            "actAs": [bank],
            "userId": "participant_admin"
        }
    });
    let (code, resp) = http_json(
        p1_url,
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        Some(&req),
    );
    assert_eq!(code, 200, "create {cmd_id} failed ({code}): {resp}");
    resp["transaction"]["events"]
        .as_array()
        .expect("events")
        .iter()
        .find_map(|e| {
            e.pointer("/CreatedEvent/contractId")
                .and_then(Value::as_str)
        })
        .expect("created cid")
        .to_string()
}

fn settle_holding(p1_url: &str, cmd_id: &str, bank: &str, cid: &str) {
    let req = json!({
        "commands": {
            "commands": [{
                "ExerciseCommand": {
                    "templateId": ASSET_TEMPLATE,
                    "contractId": cid,
                    "choice": "Settle",
                    "choiceArgument": {}
                }
            }],
            "commandId": cmd_id,
            "actAs": [bank],
            "userId": "participant_admin"
        }
    });
    let (code, resp) = http_json(
        p1_url,
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        Some(&req),
    );
    assert_eq!(code, 200, "settle {cmd_id} failed ({code}): {resp}");
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParticipantObs {
    ledger_end: u64,
    acs: Vec<Value>,
    parties: Vec<(String, bool)>,
    packages: Vec<String>,
    users: Vec<(String, String, bool)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClusterObs {
    p1: ParticipantObs,
    p2: ParticipantObs,
}

fn canonical_acs(base_url: &str, parties: &[String], at_offset: u64) -> Vec<Value> {
    let mut filters = serde_json::Map::new();
    for p in parties {
        filters.insert(
            p.clone(),
            json!({
                "cumulative": [{
                    "identifierFilter": {
                        "WildcardFilter": {"value": {"includeCreatedEventBlob": false}}
                    }
                }]
            }),
        );
    }
    let body = json!({
        "eventFormat": {
            "filtersByParty": Value::Object(filters),
            "verbose": true
        },
        "activeAtOffset": at_offset
    });
    let (code, resp) = http_json(base_url, "POST", "/v2/state/active-contracts", Some(&body));
    assert_eq!(code, 200, "active-contracts failed ({code}): {resp}");
    let mut rows: Vec<(String, Value)> = Vec::new();
    for item in resp.as_array().expect("acs array") {
        let Some(ac) = item.pointer("/contractEntry/JsActiveContract") else {
            continue;
        };
        let ev = &ac["createdEvent"];
        let cid = ev["contractId"].as_str().expect("cid").to_string();
        rows.push((
            cid.clone(),
            json!({
                "contractId": cid,
                "templateId": ev["templateId"],
                "createArgument": ev["createArgument"],
                "offset": ev["offset"],
                "nodeId": ev["nodeId"],
                "signatories": ev["signatories"],
                "observers": ev["observers"],
                "synchronizerId": ac["synchronizerId"],
                "reassignmentCounter": ac["reassignmentCounter"],
            }),
        ));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows.into_iter().map(|(_, v)| v).collect()
}

fn capture_participant_obs(base_url: &str) -> ParticipantObs {
    let (code, end_v) = http_json(base_url, "GET", "/v2/state/ledger-end", None);
    assert_eq!(code, 200, "ledger-end failed ({code}): {end_v}");
    let ledger_end = end_v["offset"].as_u64().expect("offset");

    let (code, parties_v) = http_json(base_url, "GET", "/v2/parties", None);
    assert_eq!(code, 200, "parties failed ({code}): {parties_v}");
    let mut parties: Vec<(String, bool)> = parties_v["partyDetails"]
        .as_array()
        .expect("partyDetails")
        .iter()
        .map(|d| {
            (
                d["party"].as_str().expect("party").to_string(),
                d["isLocal"].as_bool().expect("isLocal"),
            )
        })
        .collect();
    parties.sort();
    let ids: Vec<String> = parties.iter().map(|(p, _)| p.clone()).collect();
    let acs = canonical_acs(base_url, &ids, ledger_end);

    let (code, pkgs_v) = http_json(base_url, "GET", "/v2/packages", None);
    assert_eq!(code, 200, "packages failed ({code}): {pkgs_v}");
    let mut packages: Vec<String> = pkgs_v["packageIds"]
        .as_array()
        .expect("packageIds")
        .iter()
        .map(|s| s.as_str().expect("pkg").to_string())
        .collect();
    packages.sort();

    let (code, users_v) = http_json(base_url, "GET", "/v2/users", None);
    assert_eq!(code, 200, "users failed ({code}): {users_v}");
    let mut users: Vec<(String, String, bool)> = users_v["users"]
        .as_array()
        .expect("users")
        .iter()
        .map(|u| {
            (
                u["id"].as_str().expect("user id").to_string(),
                u["primaryParty"].as_str().unwrap_or("").to_string(),
                u["isDeactivated"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    users.sort();

    ParticipantObs {
        ledger_end,
        acs,
        parties,
        packages,
        users,
    }
}

fn capture_obs(ep: &StackEndpoints) -> ClusterObs {
    ClusterObs {
        p1: capture_participant_obs(&ep.p1_url),
        p2: capture_participant_obs(&ep.p2_url),
    }
}

fn wait_acs_len(base_url: &str, party: &str, expected: usize) {
    let parties = vec![party.to_string()];
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_len = 0usize;
    while Instant::now() < deadline {
        let (_, end_v) = http_json(base_url, "GET", "/v2/state/ledger-end", None);
        if let Some(end) = end_v["offset"].as_u64() {
            last_len = canonical_acs(base_url, &parties, end).len();
            if last_len == expected {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(80));
    }
    panic!("PG participant at {base_url} did not reach ACS len={expected} (last_len={last_len}) within 60s");
}

#[test]
fn s09_pg_roundtrip_and_clone() {
    let pg_url = std::env::var("CANTON_RS_PG_URL")
        .expect("CANTON_RS_PG_URL must be set (run scripts/verify-sdx-004-pg.sh)");
    let mut g = PgStackGuard::new("s09");
    let ep = g.start_pg_stack("pg-a", &pg_url);

    let alice = allocate_party(&ep.p1_url, "Alice");
    let _auditor = allocate_party(&ep.p1_url, "Auditor");
    let bob = allocate_party(&ep.p2_url, "Bob");
    create_user(&ep.p1_url, "dev-user", &alice);
    create_user(&ep.p2_url, "dev-user", &bob);
    upload_dar(&ep.p1_url, &sdx006_v1_dar());
    upload_dar(&ep.p2_url, &sdx006_v1_dar());
    std::thread::sleep(Duration::from_millis(200));

    let mut cids = Vec::new();
    for i in 0..20 {
        cids.push(create_holding(
            &ep.p1_url,
            &format!("pg-seed-c-{i}"),
            &alice,
            &bob,
            &format!("{}.0", 10 + i),
        ));
    }
    for (idx, cid) in cids.iter().take(5).enumerate() {
        settle_holding(&ep.p1_url, &format!("pg-seed-a-{idx}"), &alice, cid);
    }
    let remaining: Vec<String> = cids.into_iter().skip(5).collect();
    wait_acs_len(&ep.p1_url, &alice, 15);
    wait_acs_len(&ep.p2_url, &bob, 15);

    let obs_t = capture_obs(&ep);
    assert_eq!(obs_t.p1.acs.len(), 15);
    assert_eq!(obs_t.p2.acs.len(), 15);

    let snap = g.root.join("s09-pg-snap.tar");
    let snap_out = g.run_checked(&[
        "daemon",
        "snapshot",
        "--name",
        "pg-a",
        "--out",
        snap.to_str().expect("snap str"),
        "--format",
        "json",
    ]);
    let snap_report: Value = serde_json::from_slice(&snap_out.stdout).expect("snap report json");
    assert_eq!(snap_report["storage_mode"], "postgres");
    #[cfg(unix)]
    {
        let mode = fs::metadata(&snap).expect("snap stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "PG snapshot bundle must be 0600");
    }

    let ep_after_snap = g.wait_ready("pg-a");
    assert_eq!(capture_obs(&ep_after_snap), obs_t, "PG S-02 invariance");

    for i in 0..10 {
        let _ = create_holding(
            &ep_after_snap.p1_url,
            &format!("pg-drift-c-{i}"),
            &alice,
            &bob,
            "90.0",
        );
    }
    for (idx, cid) in remaining.iter().take(3).enumerate() {
        settle_holding(
            &ep_after_snap.p1_url,
            &format!("pg-drift-a-{idx}"),
            &alice,
            cid,
        );
    }
    wait_acs_len(&ep_after_snap.p2_url, &bob, 22);
    assert_ne!(capture_obs(&ep_after_snap), obs_t);

    g.run_checked(&[
        "daemon",
        "restore",
        "--name",
        "pg-a",
        "--from",
        snap.to_str().expect("snap str"),
        "--force",
    ]);
    let ep_restored = g.wait_ready("pg-a");
    assert_eq!(
        capture_obs(&ep_restored),
        obs_t,
        "PG S-01 roundtrip mismatch"
    );

    // Clone into a distinct PG schema/instance name `pg-b` while `pg-a` stays running.
    g.track("pg-b");
    g.run_checked(&[
        "daemon",
        "restore",
        "--name",
        "pg-b",
        "--from",
        snap.to_str().expect("snap str"),
        "--pg-url",
        &pg_url,
    ]);
    let ep_b = g.wait_ready("pg-b");
    assert_eq!(
        capture_obs(&ep_b),
        obs_t,
        "PG clone obs(pg-b) != obs(pg-a_t)"
    );
    assert!(ep_restored.ports.is_disjoint(&ep_b.ports));
}
