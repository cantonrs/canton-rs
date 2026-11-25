//! E2E integration tests for S-DX-003: named instances (`daemon up --name`, auto port-offset
//! `off = k * W`, `daemon list`, `daemon remove [--dry-run] [--force]`, `--name` flag routing,
//! isolation, symlink boundary, and protected-path guards `I-01`..`I-08`).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

static INSTANCE_TEST_LOCK: Mutex<()> = Mutex::new(());
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

const BASE_OFFSET_PORT: u16 = 41000;
const BASE_OFFSETS: [u16; 6] = [0, 1, 2, 100, 101, 300];

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
    std::env::temp_dir().join(format!("sdx003-{tag}-{}-{seq}", std::process::id()))
}

fn wait_ports_free(offsets: &[u16], within: Duration) {
    let ports: Vec<u16> = offsets
        .iter()
        .flat_map(|off| BASE_OFFSETS.iter().map(move |d| BASE_OFFSET_PORT + off + d))
        .collect();
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        let all_free = ports.iter().all(|p| {
            let addr: SocketAddr = format!("127.0.0.1:{p}")
                .parse()
                .expect("valid loopback addr");
            TcpStream::connect_timeout(&addr, Duration::from_millis(60)).is_err()
        });
        if all_free {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("ports remained busy after cleanup: {ports:?}");
}

fn write_test_manifest(dir: &Path) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mkdir manifest dir");
    let manifest_path = dir.join("canton-daemon.yaml");
    let dar = sample_dar();
    let yaml = format!(
        "name: sdx003-template
synchronizer: sdx003-sync
state_dir: ./canton-rs-state
metrics_port: 41300
services:
  s1:
    role: sequencer
    ports: [\"41000:public\", \"41001:admin\", \"41001:metrics\"]
    restart: unless-stopped
  m1:
    role: mediator
    ports: [\"41002:admin\"]
    depends_on: [s1]
    restart: unless-stopped
  p1:
    role: participant
    ports: [\"41100:json-api\"]
    dars: [\"{dar}\"]
    depends_on: [s1, m1]
    restart: unless-stopped
  p2:
    role: participant
    ports: [\"41101:json-api\"]
    dars: [\"{dar}\"]
    depends_on: [s1, m1]
    restart: unless-stopped
",
        dar = dar.display()
    );
    std::fs::write(&manifest_path, yaml).expect("write manifest");
    manifest_path
}

struct InstancesGuard {
    xdg: PathBuf,
    names: Vec<String>,
    offsets: Vec<u16>,
}

impl InstancesGuard {
    fn new(tag: &str, offsets: Vec<u16>) -> Self {
        let xdg = unique_temp_path(tag);
        let _ = std::fs::remove_dir_all(&xdg);
        std::fs::create_dir_all(&xdg).expect("mkdir xdg");
        wait_ports_free(&offsets, Duration::from_secs(10));
        Self {
            xdg,
            names: Vec::new(),
            offsets,
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

    fn instance_dir(&self, name: &str) -> PathBuf {
        self.xdg.join("canton-rs/instances").join(name)
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
        if !self.offsets.is_empty() {
            let ports: Vec<u16> = self
                .offsets
                .iter()
                .flat_map(|off| BASE_OFFSETS.iter().map(move |d| BASE_OFFSET_PORT + off + d))
                .collect();
            let deadline = Instant::now() + Duration::from_secs(12);
            while Instant::now() < deadline {
                if ports.iter().all(|p| {
                    let addr: SocketAddr = format!("127.0.0.1:{p}").parse().expect("loopback addr");
                    TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_err()
                }) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(80));
            }
        }
        let _ = std::fs::remove_dir_all(&self.xdg);
    }
}

fn http_json(base_url: &str, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
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
    let parsed = serde_json::from_str(&body_str).unwrap_or(Value::String(body_str));
    (code, parsed)
}

fn wait_instance_ready(guard: &InstancesGuard, name: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        let out = guard
            .cmd(&["daemon", "status", "--name", name, "--format", "json"])
            .output()
            .expect("daemon status");
        if out.status.success() {
            if let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) {
                let eps = &v["endpoints"];
                let ready = ["s1.public", "m1.admin", "p1.json", "p2.json", "metrics"]
                    .iter()
                    .all(|k| eps[k]["state"] == "up");
                if ready {
                    return v;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("instance '{name}' did not become fully up within 45s");
}

fn allocate_party(p_url: &str, hint: &str) -> String {
    let (code, body) = http_json(
        p_url,
        "POST",
        "/v2/parties",
        Some(&json!({"partyIdHint": hint, "identityProviderId": ""})),
    );
    assert_eq!(code, 200, "allocate {hint} -> {code}: {body}");
    body.pointer("/partyDetails/party")
        .and_then(Value::as_str)
        .expect("party id")
        .to_string()
}

fn wildcard_filter(party: &str) -> Value {
    json!({party: {"cumulative": [{"identifierFilter": {"WildcardFilter": {"value": {"includeCreatedEventBlob": false}}}}]}})
}

fn active_contract_ids(p_url: &str, party: &str) -> Vec<String> {
    let (code, end) = http_json(p_url, "GET", "/v2/state/ledger-end", None);
    assert_eq!(code, 200, "ledger-end -> {code}: {end}");
    let body = json!({
        "eventFormat": {"filtersByParty": wildcard_filter(party), "verbose": false},
        "activeAtOffset": end["offset"]
    });
    let (code, acs) = http_json(p_url, "POST", "/v2/state/active-contracts", Some(&body));
    assert_eq!(code, 200, "acs -> {code}: {acs}");
    acs.as_array()
        .expect("acs array")
        .iter()
        .filter_map(|e| {
            e.pointer("/contractEntry/JsActiveContract/createdEvent/contractId")
                .and_then(Value::as_str)
                .map(String::from)
        })
        .collect()
}

fn submit_command(p_url: &str, party: &str, cmd_id: &str, cmd: Value) -> Value {
    let body = json!({
        "commands": {"commands": [cmd], "commandId": cmd_id, "actAs": [party], "userId": "participant_admin"},
        "transactionFormat": {"eventFormat": {"filtersByParty": wildcard_filter(party), "verbose": true},
                              "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"}
    });
    let (code, resp) = http_json(
        p_url,
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        Some(&body),
    );
    assert_eq!(code, 200, "{cmd_id} failed {code}: {resp}");
    resp
}

fn run_two_participant_scenario(p1_url: &str, p2_url: &str, tag: &str) {
    let alice = allocate_party(p1_url, &format!("alice-{tag}"));
    let bob = allocate_party(p2_url, &format!("bob-{tag}"));
    let tmpl = "#sample-contract:AssetHolding:AssetHolding";
    let created = submit_command(
        p1_url,
        &alice,
        &format!("create-{tag}"),
        json!({"CreateCommand": {"templateId": tmpl, "createArguments": {
            "bank": alice, "owner": alice, "auditor": bob, "assetSymbol": "USD", "amount": "42.0"}}}),
    );
    let cid = created
        .pointer("/transaction/events/0/CreatedEvent/contractId")
        .and_then(Value::as_str)
        .expect("created contractId")
        .to_string();

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if active_contract_ids(p2_url, &bob).contains(&cid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(120));
    }
    assert!(
        active_contract_ids(p2_url, &bob).contains(&cid),
        "p2 ({p2_url}) never observed contract {cid}"
    );

    submit_command(
        p1_url,
        &alice,
        &format!("settle-{tag}"),
        json!({"ExerciseCommand": {"templateId": tmpl, "contractId": cid, "choice": "Settle", "choiceArgument": {}}}),
    );
    let settle_deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < settle_deadline {
        if !active_contract_ids(p2_url, &bob).contains(&cid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(120));
    }
    assert!(
        !active_contract_ids(p2_url, &bob).contains(&cid),
        "p2 ({p2_url}) still shows settled contract {cid}"
    );
}

fn hash_tree_recursive(root: &Path, subpaths: Option<&[&str]>) -> String {
    let mut files = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        if dir.is_file() {
            out.push(dir.to_path_buf());
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                out.push(p);
            } else if meta.is_dir() {
                walk(&p, out);
            } else if meta.is_file() {
                out.push(p);
            }
        }
    }
    match subpaths {
        Some(list) => {
            for rel in list {
                walk(&root.join(rel), &mut files);
            }
        }
        None => walk(root, &mut files),
    }
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        let rel = path.strip_prefix(root).unwrap_or(&path);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        let meta = std::fs::symlink_metadata(&path).expect("stat file");
        if meta.file_type().is_symlink() {
            hasher.update(b"L:");
            let target = std::fs::read_link(&path).expect("readlink");
            hasher.update(target.to_string_lossy().as_bytes());
        } else {
            hasher.update(b"F:");
            let bytes = std::fs::read(&path).expect("read file bytes");
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
        }
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

fn endpoint_ports(status: &Value) -> BTreeMap<String, u16> {
    status["endpoints"]
        .as_object()
        .expect("endpoints map")
        .iter()
        .map(|(k, v)| {
            let url = v["url"].as_str().expect("url");
            let port: u16 = url.rsplit(':').next().expect("port").parse().expect("u16");
            (k.clone(), port)
        })
        .collect()
}

#[test]
fn sdx003_i01_two_instances_concurrent_auto_offset() {
    let _serial = INSTANCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut guard = InstancesGuard::new("i01", vec![0, 1000]);
    let manifest = write_test_manifest(&guard.xdg.join("cfg"));
    let manifest_str = manifest.to_str().expect("utf8 path");

    for name in ["a", "b"] {
        guard.track(name);
        let up = guard
            .cmd(&["daemon", "up", "-d", "--name", name, "-f", manifest_str])
            .output()
            .expect("daemon up --name");
        assert!(
            up.status.success(),
            "up {name} failed ({:?}): stdout={} stderr={}",
            up.status.code(),
            String::from_utf8_lossy(&up.stdout),
            String::from_utf8_lossy(&up.stderr)
        );
    }

    let status_a = wait_instance_ready(&guard, "a");
    let status_b = wait_instance_ready(&guard, "b");
    assert_eq!(status_a["instance"], "a");
    assert_eq!(status_b["instance"], "b");

    #[cfg(unix)]
    for name in ["a", "b"] {
        let mode = std::fs::metadata(guard.instance_dir(name).join("instance.json"))
            .expect("stat instance.json")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{name}/instance.json must have mode 0600");
    }

    let list_out = guard
        .cmd(&["daemon", "list", "--format", "json"])
        .output()
        .expect("daemon list --format json");
    assert!(list_out.status.success());
    let list: Value = serde_json::from_slice(&list_out.stdout).expect("parse list json");
    assert_eq!(list["schema"], "canton-rs.instances/1");
    let rows = list["instances"].as_array().expect("instances array");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["name"], "a");
    assert_eq!(rows[0]["port_offset"], 0);
    assert_eq!(rows[0]["state"], "running");
    assert_eq!(rows[1]["name"], "b");
    assert_eq!(rows[1]["port_offset"], 1000);
    assert_eq!(rows[1]["state"], "running");

    let ports_a = endpoint_ports(&status_a);
    let ports_b = endpoint_ports(&status_b);
    let set_a: std::collections::BTreeSet<u16> = ports_a.values().copied().collect();
    let set_b: std::collections::BTreeSet<u16> = ports_b.values().copied().collect();
    assert!(
        set_a.is_disjoint(&set_b),
        "instances a and b share ports: a={ports_a:?}, b={ports_b:?}"
    );
    assert_ne!(ports_a["p1.json"], ports_b["p1.json"]);

    run_two_participant_scenario(
        status_a["endpoints"]["p1.json"]["url"]
            .as_str()
            .expect("a p1"),
        status_a["endpoints"]["p2.json"]["url"]
            .as_str()
            .expect("a p2"),
        "inst-a",
    );
    run_two_participant_scenario(
        status_b["endpoints"]["p1.json"]["url"]
            .as_str()
            .expect("b p1"),
        status_b["endpoints"]["p2.json"]["url"]
            .as_str()
            .expect("b p2"),
        "inst-b",
    );

    for sub in [
        vec!["daemon", "ps", "--name", "a", "--json"],
        vec!["daemon", "env", "--name", "b"],
        vec!["daemon", "logs", "--name", "a", "--tail", "5"],
    ] {
        let res = guard.cmd(&sub).output().expect("subcommand --name");
        assert!(
            res.status.success(),
            "subcommand {sub:?} failed: {}",
            String::from_utf8_lossy(&res.stderr)
        );
    }
}

#[test]
fn sdx003_i02_isolation_state_and_obs() {
    let _serial = INSTANCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut guard = InstancesGuard::new("i02", vec![0, 1000]);
    let manifest = write_test_manifest(&guard.xdg.join("cfg"));
    let manifest_str = manifest.to_str().expect("utf8");

    for name in ["a", "b"] {
        guard.track(name);
        let up = guard
            .cmd(&["daemon", "up", "-d", "--name", name, "-f", manifest_str])
            .output()
            .expect("up");
        assert!(up.status.success());
    }
    let st_a = wait_instance_ready(&guard, "a");
    let st_b = wait_instance_ready(&guard, "b");
    let b_p1 = st_b["endpoints"]["p1.json"]["url"].as_str().expect("b p1");
    let b_p2 = st_b["endpoints"]["p2.json"]["url"].as_str().expect("b p2");
    let a_p1 = st_a["endpoints"]["p1.json"]["url"].as_str().expect("a p1");
    let a_p2 = st_a["endpoints"]["p2.json"]["url"].as_str().expect("a p2");

    let bob_b = allocate_party(b_p1, "bob-iso");
    let (_, end_before) = http_json(b_p1, "GET", "/v2/state/ledger-end", None);
    let acs_b1_before = active_contract_ids(b_p1, &bob_b);
    let acs_b2_before = active_contract_ids(b_p2, &bob_b);
    let dir_b = guard.instance_dir("b");
    let state_hash_before =
        hash_tree_recursive(&dir_b, Some(&["instance.json", "s1", "m1", "p1", "p2"]));

    let alice_a = allocate_party(a_p1, "alice-a");
    let bob_a = allocate_party(a_p2, "bob-a");
    let tmpl = "#sample-contract:AssetHolding:AssetHolding";
    for idx in 0..10 {
        submit_command(
            a_p1,
            &alice_a,
            &format!("iso-create-{idx}"),
            json!({"CreateCommand": {"templateId": tmpl, "createArguments": {
                "bank": alice_a, "owner": alice_a, "auditor": bob_a, "assetSymbol": "USD", "amount": "10.0"}}}),
        );
    }
    assert_eq!(active_contract_ids(a_p1, &alice_a).len(), 10);

    let (_, end_after) = http_json(b_p1, "GET", "/v2/state/ledger-end", None);
    let acs_b1_after = active_contract_ids(b_p1, &bob_b);
    let acs_b2_after = active_contract_ids(b_p2, &bob_b);
    let state_hash_after =
        hash_tree_recursive(&dir_b, Some(&["instance.json", "s1", "m1", "p1", "p2"]));

    assert_eq!(end_before, end_after, "instance b ledger-end changed!");
    assert_eq!(acs_b1_before, acs_b1_after);
    assert_eq!(acs_b2_before, acs_b2_after);
    assert_eq!(
        state_hash_before, state_hash_after,
        "instance b state files mutated while operating on a"
    );
}

#[test]
fn sdx003_i03_invalid_names_rejected() {
    let _serial = INSTANCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let guard = InstancesGuard::new("i03", vec![]);
    let manifest = write_test_manifest(&guard.xdg.join("cfg"));
    let manifest_str = manifest.to_str().expect("utf8");
    let too_long = "a".repeat(64);
    let bad_names = ["A", "a_b", "-a", "a-", too_long.as_str(), ""];

    for bad in bad_names {
        let out = guard
            .cmd(&["daemon", "up", "-d", "--name", bad, "-f", manifest_str])
            .output()
            .expect("daemon up bad name");
        assert_eq!(
            out.status.code(),
            Some(2),
            "invalid name {bad:?} must exit 2, got {:?}, stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let inst_root = guard.xdg.join("canton-rs/instances");
    assert!(
        !inst_root.exists()
            || std::fs::read_dir(&inst_root)
                .expect("read_dir")
                .next()
                .is_none(),
        "invalid instance names must create no directories under {}",
        inst_root.display()
    );
}

#[test]
fn sdx003_i04_duplicate_up_refused() {
    let _serial = INSTANCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut guard = InstancesGuard::new("i04", vec![0]);
    let manifest = write_test_manifest(&guard.xdg.join("cfg"));
    let manifest_str = manifest.to_str().expect("utf8");
    guard.track("a");

    let first = guard
        .cmd(&["daemon", "up", "-d", "--name", "a", "-f", manifest_str])
        .output()
        .expect("first up");
    assert!(first.status.success());
    let _ = wait_instance_ready(&guard, "a");

    let ps_before = guard
        .cmd(&["daemon", "ps", "--name", "a", "--json"])
        .output()
        .expect("ps before");
    let pids_before: Vec<u64> = serde_json::from_slice::<Value>(&ps_before.stdout).expect("json")
        ["snapshot"]["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter_map(|n| n["pid"].as_u64())
        .collect();

    let second = guard
        .cmd(&["daemon", "up", "-d", "--name", "a", "-f", manifest_str])
        .output()
        .expect("second up");
    assert_eq!(
        second.status.code(),
        Some(2),
        "duplicate running up must exit 2, stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );

    let ps_after = guard
        .cmd(&["daemon", "ps", "--name", "a", "--json"])
        .output()
        .expect("ps after");
    let pids_after: Vec<u64> = serde_json::from_slice::<Value>(&ps_after.stdout).expect("json")
        ["snapshot"]["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter_map(|n| n["pid"].as_u64())
        .collect();
    assert_eq!(pids_before, pids_after, "duplicate up mutated running PIDs");

    let down = guard
        .cmd(&["daemon", "down", "--name", "a"])
        .output()
        .expect("daemon down --name a");
    assert!(down.status.success());
    wait_ports_free(&[0], Duration::from_secs(12));

    // Stopped instance restarts cleanly in the same slot (`I-A1`).
    let restart = guard
        .cmd(&["daemon", "up", "-d", "--name", "a", "-f", manifest_str])
        .output()
        .expect("restart stopped instance a");
    assert!(
        restart.status.success(),
        "restarting stopped instance failed: {}",
        String::from_utf8_lossy(&restart.stderr)
    );
    let _ = wait_instance_ready(&guard, "a");
}

#[test]
fn sdx003_i05_remove_dry_run_purity_and_equality() {
    let _serial = INSTANCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut guard = InstancesGuard::new("i05", vec![0]);
    let manifest = write_test_manifest(&guard.xdg.join("cfg"));
    let manifest_str = manifest.to_str().expect("utf8");
    guard.track("a");

    let up = guard
        .cmd(&["daemon", "up", "-d", "--name", "a", "-f", manifest_str])
        .output()
        .expect("up");
    assert!(up.status.success());
    let _ = wait_instance_ready(&guard, "a");
    let down = guard
        .cmd(&["daemon", "down", "--name", "a"])
        .output()
        .expect("down");
    assert!(down.status.success());

    let dir_a = guard.instance_dir("a");
    let hash_before = hash_tree_recursive(&dir_a, None);

    let dry = guard
        .cmd(&[
            "daemon",
            "remove",
            "--name",
            "a",
            "--dry-run",
            "--format",
            "json",
        ])
        .output()
        .expect("remove dry-run");
    assert!(dry.status.success());
    let dry_json: Value = serde_json::from_slice(&dry.stdout).expect("dry json");
    assert_eq!(dry_json["dry_run"], true);
    let hash_after_dry = hash_tree_recursive(&dir_a, None);
    assert_eq!(
        hash_before, hash_after_dry,
        "dry-run mutated instance directory"
    );

    let real = guard
        .cmd(&["daemon", "remove", "--name", "a", "--format", "json"])
        .output()
        .expect("real remove");
    assert!(real.status.success());
    let real_json: Value = serde_json::from_slice(&real.stdout).expect("real json");
    assert_eq!(real_json["dry_run"], false);
    assert_eq!(
        dry_json["paths"], real_json["paths"],
        "dry-run path set != actually removed paths"
    );
    assert!(!dir_a.exists());

    let list_out = guard
        .cmd(&["daemon", "list", "--format", "json"])
        .output()
        .expect("list after remove");
    let list_json: Value = serde_json::from_slice(&list_out.stdout).expect("parse list");
    assert_eq!(list_json["instances"].as_array().expect("arr").len(), 0);
}

#[test]
fn sdx003_i06_remove_symlink_boundary() {
    let _serial = INSTANCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut guard = InstancesGuard::new("i06", vec![0]);
    let manifest = write_test_manifest(&guard.xdg.join("cfg"));
    let manifest_str = manifest.to_str().expect("utf8");
    guard.track("a");

    let up = guard
        .cmd(&["daemon", "up", "-d", "--name", "a", "-f", manifest_str])
        .output()
        .expect("up");
    assert!(up.status.success());
    let _ = wait_instance_ready(&guard, "a");
    let down = guard
        .cmd(&["daemon", "down", "--name", "a"])
        .output()
        .expect("down");
    assert!(down.status.success());

    let outside = unique_temp_path("i06-outside");
    std::fs::create_dir_all(&outside).expect("mkdir outside");
    let canary = outside.join("canary.txt");
    std::fs::write(&canary, "DO-NOT-DELETE").expect("write canary");

    let dir_a = guard.instance_dir("a");
    #[cfg(unix)]
    {
        symlink(&outside, dir_a.join("escape_dir")).expect("symlink escape_dir");
        symlink(&canary, dir_a.join("escape_file")).expect("symlink escape_file");
    }

    let rem = guard
        .cmd(&["daemon", "remove", "--name", "a", "--force"])
        .output()
        .expect("remove with symlinks");
    assert!(
        rem.status.success(),
        "remove failed: {}",
        String::from_utf8_lossy(&rem.stderr)
    );
    assert!(!dir_a.exists());
    assert!(outside.is_dir(), "external target directory was deleted!");
    assert_eq!(
        std::fs::read_to_string(&canary).expect("read canary"),
        "DO-NOT-DELETE"
    );
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn sdx003_i07_protected_folder_refused() {
    let _serial = INSTANCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let guard = InstancesGuard::new("i07", vec![]);
    let manifest = write_test_manifest(&guard.xdg.join("cfg"));
    let manifest_str = manifest.to_str().expect("utf8");

    for protected in ["canton-rs-state", "./canton-rs-state"] {
        let up = guard
            .cmd(&[
                "daemon",
                "up",
                "-d",
                "--state-dir",
                protected,
                "--name",
                "x",
                "-f",
                manifest_str,
            ])
            .output()
            .expect("up protected");
        assert_eq!(
            up.status.code(),
            Some(2),
            "combining --state-dir {protected} with --name x must exit 2"
        );
    }
    let st = guard
        .cmd(&[
            "daemon",
            "status",
            "--state-dir",
            "canton-rs-state",
            "--name",
            "x",
        ])
        .output()
        .expect("status protected");
    assert_eq!(st.status.code(), Some(2));
    assert!(!guard.instance_dir("x").exists());
}

#[test]
fn sdx003_i08_non_tty_running_remove_requires_force() {
    let _serial = INSTANCE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut guard = InstancesGuard::new("i08", vec![0]);
    let manifest = write_test_manifest(&guard.xdg.join("cfg"));
    let manifest_str = manifest.to_str().expect("utf8");
    guard.track("a");

    let up = guard
        .cmd(&["daemon", "up", "-d", "--name", "a", "-f", manifest_str])
        .output()
        .expect("up");
    assert!(up.status.success());
    let _ = wait_instance_ready(&guard, "a");

    let no_force = guard
        .cmd(&["daemon", "remove", "--name", "a"])
        .output()
        .expect("remove without --force on non-tty");
    assert_eq!(
        no_force.status.code(),
        Some(2),
        "non-TTY running remove without --force must exit 2, stderr={}",
        String::from_utf8_lossy(&no_force.stderr)
    );
    assert!(guard.instance_dir("a").exists());

    // Confirm instance is still healthy after refusal.
    let st = guard
        .cmd(&["daemon", "status", "--name", "a", "--format", "json"])
        .output()
        .expect("status after refusal");
    assert!(st.status.success());
    let st_json: Value = serde_json::from_slice(&st.stdout).expect("parse status");
    assert_eq!(st_json["endpoints"]["p1.json"]["state"], "up");

    let forced = guard
        .cmd(&["daemon", "remove", "--name", "a", "--force"])
        .output()
        .expect("remove --force");
    assert!(
        forced.status.success(),
        "remove --force failed: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    assert!(!guard.instance_dir("a").exists());
}
