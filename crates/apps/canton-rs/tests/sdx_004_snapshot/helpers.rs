#![allow(clippy::unwrap_used, reason = "integration test")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(super) static SNAPSHOT_TEST_LOCK: Mutex<()> = Mutex::new(());
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

const BASE_OFFSETS: [u16; 6] = [0, 1, 2, 100, 101, 300];
pub(super) const ASSET_TEMPLATE: &str = "#sample-contract:AssetHolding:AssetHolding";
pub(super) const HELD_TEMPLATE: &str = "#confirm-subview:Confirm:Held";

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

pub(super) fn confirm_dar() -> PathBuf {
    repo_root().join("contracts/fixtures/confirm/target/confirm-subview.dar")
}

fn unique_temp_path(tag: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("sdx004-{tag}-{}-{seq}", std::process::id()))
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
            let addr: SocketAddr = format!("127.0.0.1:{p}")
                .parse()
                .expect("valid loopback addr");
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
        panic!("ports remained busy after cleanup: {ports:?}");
    }
}

fn choose_clean_base_port() -> u16 {
    for candidate in [42000u16, 44000, 46000] {
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
    42000
}

fn write_dual_manifest(
    dir: &Path,
    name: &str,
    base_port: u16,
    extra_dar: Option<&Path>,
) -> PathBuf {
    fs::create_dir_all(dir).expect("mkdir manifest dir");
    let manifest_path = dir.join("canton-daemon.yaml");
    let dar = sample_dar();
    let dars_yaml = match extra_dar {
        Some(extra) => format!("[\"{}\", \"{}\"]", dar.display(), extra.display()),
        None => format!("[\"{}\"]", dar.display()),
    };
    let s_pub = base_port;
    let s_adm = base_port + 1;
    let m_adm = base_port + 2;
    let p1_json = base_port + 100;
    let p2_json = base_port + 101;
    let metrics = base_port + 300;
    let yaml = format!(
        "name: {name}
synchronizer: sdx004-sync
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
    dars: {dars_yaml}
    depends_on: [s1, m1]
    restart: unless-stopped
  p2:
    role: participant
    ports: [\"{p2_json}:json-api\"]
    dars: {dars_yaml}
    depends_on: [s1, m1]
    restart: unless-stopped
"
    );
    fs::write(&manifest_path, yaml).expect("write manifest");
    manifest_path
}

pub(super) struct InstancesGuard {
    pub(super) root: PathBuf,
    xdg: PathBuf,
    base_port: u16,
    names: Vec<String>,
    offsets: Vec<u16>,
}

impl InstancesGuard {
    pub(super) fn new(tag: &str) -> Self {
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
            offsets: vec![0, 1000],
        }
    }

    pub(super) fn track(&mut self, name: &str) {
        if !self.names.iter().any(|n| n == name) {
            self.names.push(name.to_string());
        }
    }

    fn work_dir(&self) -> PathBuf {
        self.root.join("work")
    }

    pub(super) fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.env("XDG_STATE_HOME", &self.xdg)
            .args(args)
            .stdin(Stdio::null());
        c
    }

    pub(super) fn run_checked(&self, args: &[&str]) -> Output {
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

    pub(super) fn start_stack(&mut self, name: &str, extra_dar: Option<&Path>) -> StackEndpoints {
        let work = self.work_dir();
        let manifest = write_dual_manifest(&work, name, self.base_port, extra_dar);
        self.track(name);
        self.run_checked(&[
            "daemon",
            "up",
            "--name",
            name,
            "-f",
            manifest.to_str().expect("manifest str"),
            "--state-in-files",
            "-d",
        ]);
        self.wait_ready(name)
    }

    pub(super) fn wait_ready(&self, name: &str) -> StackEndpoints {
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
        let status_dump = self
            .cmd(&["daemon", "status", "--name", name, "--format", "json"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let inst_dir = self.xdg.join("canton-rs/instances").join(name);
        let logs_dir = inst_dir.join("logs");
        let mut logs_dump = String::new();
        if let Ok(rd) = fs::read_dir(&logs_dir) {
            for ent in rd.flatten() {
                if let Ok(text) = fs::read_to_string(ent.path()) {
                    let tail: Vec<&str> = text.lines().rev().take(20).collect();
                    let tail_rev: Vec<&str> = tail.into_iter().rev().collect();
                    logs_dump.push_str(&format!(
                        "\n--- {} ---\n{}\n",
                        ent.path().display(),
                        tail_rev.join("\n")
                    ));
                }
            }
        }
        panic!(
            "instance '{name}' did not become ready within 120s\nstatus: {status_dump}\nlogs:{logs_dump}"
        );
    }

    pub(super) fn status_json(&self, name: &str) -> Value {
        let out = self.run_checked(&["daemon", "status", "--name", name, "--format", "json"]);
        serde_json::from_slice(&out.stdout).expect("parse status json")
    }
}

impl Drop for InstancesGuard {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = self
                .cmd(&["daemon", "remove", "--name", name, "--force"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if let Some(ports) =
            wait_ports_free_best_effort(self.base_port, &self.offsets, Duration::from_secs(12))
        {
            eprintln!("WARN: ports remained busy after cleanup: {ports:?}");
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Debug)]
pub(super) struct StackEndpoints {
    pub(super) s1_metrics_url: String,
    pub(super) m1_admin_url: String,
    pub(super) p1_url: String,
    pub(super) p2_url: String,
    pub(super) ports: BTreeSet<u16>,
}

impl StackEndpoints {
    fn from_status_json(v: &Value) -> Self {
        let eps = v["endpoints"].as_object().expect("endpoints object");
        let mut ports = BTreeSet::new();
        for ep in eps.values() {
            if let Some(url) = ep["url"].as_str() {
                if let Some(port) = extract_port_from_url(url) {
                    ports.insert(port);
                }
            }
        }
        let get_url = |k: &str| {
            eps.get(k)
                .and_then(|e| e["url"].as_str())
                .unwrap_or_else(|| panic!("missing endpoint url '{k}' in {v}"))
                .to_string()
        };
        Self {
            s1_metrics_url: get_url("s1.metrics"),
            m1_admin_url: get_url("m1.admin"),
            p1_url: get_url("p1.json"),
            p2_url: get_url("p2.json"),
            ports,
        }
    }
}

fn extract_port_from_url(url: &str) -> Option<u16> {
    let rest = url.split("://").nth(1)?;
    let host_port = rest.split('/').next()?;
    let (_, port_str) = host_port.rsplit_once(':')?;
    port_str.parse::<u16>().ok()
}

pub(super) fn http_send(
    base_url: &str,
    method: &str,
    path: &str,
    content_type: &str,
    payload: &[u8],
    timeout: Duration,
) -> (u16, String) {
    let host_port = base_url
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("expected http:// URL, got {base_url}"));
    let addr: SocketAddr = host_port.parse().expect("parse host:port");
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).expect("connect");
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
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

pub(super) fn http_json(
    base_url: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> (u16, Value) {
    let payload = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    let (code, text) = http_send(
        base_url,
        method,
        path,
        "application/json",
        &payload,
        Duration::from_secs(30),
    );
    let parsed = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (code, parsed)
}

fn http_upload_dar(base_url: &str, dar_path: &Path) {
    let bytes = fs::read(dar_path).expect("read dar bytes");
    let (code, body) = http_send(
        base_url,
        "POST",
        "/v2/packages",
        "application/octet-stream",
        &bytes,
        Duration::from_secs(30),
    );
    assert!(
        code < 300,
        "POST /v2/packages ({}) to {base_url} failed ({code}): {body}",
        dar_path.display()
    );
}

pub(super) fn allocate_party(base_url: &str, hint: &str) -> String {
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
    assert_eq!(
        code, 200,
        "POST /v2/users {user_id} failed ({code}): {body}"
    );
}

pub(super) fn submit_tx(
    base_url: &str,
    act_as: &[&str],
    cmd_id: &str,
    cmd: Value,
) -> (u64, Vec<String>) {
    let req = json!({
        "commands": {
            "commands": [cmd],
            "commandId": cmd_id,
            "actAs": act_as,
            "userId": "participant_admin"
        }
    });
    let (code, resp) = http_json(
        base_url,
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        Some(&req),
    );
    assert_eq!(code, 200, "submit {cmd_id} failed ({code}): {resp}");
    let tx = &resp["transaction"];
    let offset = tx["offset"].as_u64().expect("tx offset");
    let created = tx["events"]
        .as_array()
        .expect("tx events")
        .iter()
        .filter_map(|e| {
            e.pointer("/CreatedEvent/contractId")
                .and_then(Value::as_str)
                .map(String::from)
        })
        .collect();
    (offset, created)
}

pub(super) fn create_holding(
    p1_url: &str,
    cmd_id: &str,
    bank: &str,
    owner: &str,
    auditor: &str,
    amount: &str,
) -> String {
    let cmd = json!({
        "CreateCommand": {
            "templateId": ASSET_TEMPLATE,
            "createArguments": {
                "bank": bank,
                "owner": owner,
                "auditor": auditor,
                "assetSymbol": "USD",
                "amount": amount
            }
        }
    });
    let act_as: Vec<&str> = if bank == owner {
        vec![bank]
    } else {
        vec![bank, owner]
    };
    let (_, created) = submit_tx(p1_url, &act_as, cmd_id, cmd);
    created
        .into_iter()
        .next()
        .expect("AssetHolding created contractId")
}

pub(super) fn settle_holding(p1_url: &str, cmd_id: &str, bank: &str, cid: &str) {
    let cmd = json!({
        "ExerciseCommand": {
            "templateId": ASSET_TEMPLATE,
            "contractId": cid,
            "choice": "Settle",
            "choiceArgument": {}
        }
    });
    let (_, _) = submit_tx(p1_url, &[bank], cmd_id, cmd);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ParticipantObs {
    pub(super) ledger_end: u64,
    pub(super) acs: Vec<Value>,
    pub(super) parties: Vec<(String, bool)>,
    pub(super) packages: Vec<String>,
    pub(super) users: Vec<(String, String, bool)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ClusterObs {
    pub(super) p1: ParticipantObs,
    pub(super) p2: ParticipantObs,
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
    assert_eq!(
        code, 200,
        "POST /v2/state/active-contracts on {base_url} failed ({code}): {resp}"
    );
    let mut rows: Vec<(String, Value)> = Vec::new();
    for item in resp.as_array().expect("active-contracts array") {
        let Some(ac) = item.pointer("/contractEntry/JsActiveContract") else {
            continue;
        };
        let ev = &ac["createdEvent"];
        let cid = ev["contractId"]
            .as_str()
            .expect("createdEvent.contractId")
            .to_string();
        let canonical = json!({
            "contractId": cid,
            "templateId": ev["templateId"],
            "createArgument": ev["createArgument"],
            "offset": ev["offset"],
            "nodeId": ev["nodeId"],
            "signatories": ev["signatories"],
            "observers": ev["observers"],
            "synchronizerId": ac["synchronizerId"],
            "reassignmentCounter": ac["reassignmentCounter"],
        });
        rows.push((cid, canonical));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows.into_iter().map(|(_, v)| v).collect()
}

fn capture_participant_obs(base_url: &str) -> ParticipantObs {
    let (code, end_v) = http_json(base_url, "GET", "/v2/state/ledger-end", None);
    assert_eq!(
        code, 200,
        "GET /v2/state/ledger-end failed ({code}): {end_v}"
    );
    let ledger_end = end_v["offset"].as_u64().expect("ledger_end offset");

    let (code, parties_v) = http_json(base_url, "GET", "/v2/parties", None);
    assert_eq!(code, 200, "GET /v2/parties failed ({code}): {parties_v}");
    let mut parties: Vec<(String, bool)> = parties_v["partyDetails"]
        .as_array()
        .expect("partyDetails array")
        .iter()
        .map(|d| {
            (
                d["party"].as_str().expect("party").to_string(),
                d["isLocal"].as_bool().expect("isLocal"),
            )
        })
        .collect();
    parties.sort();
    let party_ids: Vec<String> = parties.iter().map(|(p, _)| p.clone()).collect();

    let acs = canonical_acs(base_url, &party_ids, ledger_end);

    let (code, pkgs_v) = http_json(base_url, "GET", "/v2/packages", None);
    assert_eq!(code, 200, "GET /v2/packages failed ({code}): {pkgs_v}");
    let mut packages: Vec<String> = pkgs_v["packageIds"]
        .as_array()
        .expect("packageIds array")
        .iter()
        .map(|s| s.as_str().expect("pkgId").to_string())
        .collect();
    packages.sort();

    let (code, users_v) = http_json(base_url, "GET", "/v2/users", None);
    assert_eq!(code, 200, "GET /v2/users failed ({code}): {users_v}");
    let mut users: Vec<(String, String, bool)> = users_v["users"]
        .as_array()
        .expect("users array")
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

pub(super) fn capture_obs(ep: &StackEndpoints) -> ClusterObs {
    ClusterObs {
        p1: capture_participant_obs(&ep.p1_url),
        p2: capture_participant_obs(&ep.p2_url),
    }
}

pub(super) fn wait_acs_len(base_url: &str, party: &str, expected: usize) {
    let parties = vec![party.to_string()];
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_len = 0usize;
    while Instant::now() < deadline {
        let (_, end_v) = http_json(base_url, "GET", "/v2/state/ledger-end", None);
        if let Some(end) = end_v["offset"].as_u64() {
            let acs = canonical_acs(base_url, &parties, end);
            last_len = acs.len();
            if last_len == expected {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(80));
    }
    panic!(
        "participant at {base_url} did not reach ACS len={expected} (last_len={last_len}) for {party} within 60s"
    );
}

pub(super) fn wait_topology_settle() {
    // Allow brief sequencer topology propagation between participants after party allocation.
    std::thread::sleep(Duration::from_millis(200));
}

pub(super) fn seed_rich_workload(ep: &StackEndpoints) -> (String, String, String, Vec<String>) {
    let alice = allocate_party(&ep.p1_url, "Alice");
    let auditor = allocate_party(&ep.p1_url, "Auditor");
    let bob = allocate_party(&ep.p2_url, "Bob");
    create_user(&ep.p1_url, "dev-user", &alice);
    create_user(&ep.p2_url, "dev-user", &bob);
    http_upload_dar(&ep.p1_url, &sdx006_v1_dar());
    http_upload_dar(&ep.p2_url, &sdx006_v1_dar());
    wait_topology_settle();

    let mut active_cids = Vec::new();
    for i in 0..20 {
        let cid = create_holding(
            &ep.p1_url,
            &format!("seed-c-{i}"),
            &alice,
            &alice,
            &bob,
            &format!("{}.0", 10 + i),
        );
        active_cids.push(cid);
    }
    for (idx, cid) in active_cids.iter().take(5).enumerate() {
        settle_holding(&ep.p1_url, &format!("seed-a-{idx}"), &alice, cid);
    }
    let remaining: Vec<String> = active_cids.into_iter().skip(5).collect();
    wait_acs_len(&ep.p1_url, &alice, 15);
    wait_acs_len(&ep.p2_url, &bob, 15);
    (alice, auditor, bob, remaining)
}

pub(super) fn unpack_tar_to(tar_path: &Path, dst_dir: &Path) {
    fs::create_dir_all(dst_dir).expect("mkdir unpack dst");
    let out = Command::new("tar")
        .arg("-xf")
        .arg(tar_path)
        .arg("-C")
        .arg(dst_dir)
        .output()
        .expect("run tar -xf");
    assert!(
        out.status.success(),
        "tar -xf failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

pub(super) fn repack_tar_from(src_dir: &Path, tar_path: &Path) {
    let out = Command::new("tar")
        .arg("-cf")
        .arg(tar_path)
        .arg("-C")
        .arg(src_dir)
        .arg(".")
        .output()
        .expect("run tar -cf");
    assert!(
        out.status.success(),
        "tar -cf failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Mirror structs matching exact field declaration order in `supervisor::snapshot`.
#[derive(Clone, Serialize, Deserialize)]
struct MirrorFileEntry {
    bundle_rel_path: String,
    store_rel_path: String,
    sha256: String,
    size: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct MirrorComponent {
    pub(super) id: String,
    kind: String,
    #[serde(default)]
    service: Option<String>,
    files: Vec<MirrorFileEntry>,
    sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct MirrorManifest {
    format_version: u32,
    pub(super) canton_rs_version: String,
    created_at_unix_secs: u64,
    source_name: String,
    storage_mode: String,
    #[serde(default)]
    pg_schema: Option<String>,
    source_manifest_hash: String,
    manifest_hash: String,
    pub(super) components: Vec<MirrorComponent>,
    ledger_ends: BTreeMap<String, u64>,
    node_identities: BTreeMap<String, String>,
    #[serde(default)]
    scan_history_lines: Option<usize>,
}

pub(super) fn strip_component_from_bundle(src_tar: &Path, comp_id: &str, dst_tar: &Path) {
    let stage = unique_temp_path("strip-comp");
    unpack_tar_to(src_tar, &stage);
    let manifest_path = stage.join("snapshot.json");
    let raw = fs::read_to_string(&manifest_path).expect("read snapshot.json");
    let mut manifest: MirrorManifest = serde_json::from_str(&raw).expect("parse snapshot.json");
    manifest.components.retain(|c| c.id != comp_id);
    let comp_json = serde_json::to_vec(&manifest.components).expect("serialize components");
    manifest.manifest_hash = hex::encode(Sha256::digest(&comp_json));
    let updated = serde_json::to_vec_pretty(&manifest).expect("serialize manifest");
    fs::write(&manifest_path, updated).expect("write snapshot.json");

    let comp_dir = stage.join("stores").join(comp_id);
    if comp_dir.exists() {
        fs::remove_dir_all(&comp_dir).expect("remove component files");
    }
    repack_tar_from(&stage, dst_tar);
    let _ = fs::remove_dir_all(&stage);
}
