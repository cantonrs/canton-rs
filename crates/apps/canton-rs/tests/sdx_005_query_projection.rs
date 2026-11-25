//! E2E integration tests for S-DX-005 query/watch CLI & projection guarantees (`V-05`..`V-08`):
//! - `V-05`: `daemon contracts ls --at t` matches `fold(apply, ∅, deltas(0, t])` at 10 distinct offsets across 50 create/archive ops (`V-A4`).
//! - `V-06`: `daemon contracts watch` output across 20 creates/archives folds cleanly from `ls(p, t0)` to `ls(p, t1)` (`V-A5`).
//! - `V-07`: `daemon contracts watch` shuts down cleanly in `< 1s` on `SIGINT` with exit code `0` and drops `canton_rs_active_subscriptions{...,transport="ws"}` to `0`.
//! - `V-08`: `--template` (`#pkg:Mod:Ent` and `<pkgId>:Mod:Ent`) isolates templates across `contracts ls`, `contracts watch`, and `tx ls`, while invalid filters exit `2`.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

static QUERY_TEST_LOCK: Mutex<()> = Mutex::new(());
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn bin() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("canton-rs")
}

fn events_dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/events-dar/events-oracle.dar")
        .canonicalize()
        .expect("canonicalize events-oracle.dar")
}

fn unique_temp_path(tag: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("sdx005-{tag}-{}-{seq}", std::process::id()))
}

fn alloc_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

fn write_manifest(dir: &Path, name: &str) -> (PathBuf, u16) {
    std::fs::create_dir_all(dir).expect("mkdir manifest dir");
    let s_pub = alloc_free_port();
    let s_adm = alloc_free_port();
    let m_adm = alloc_free_port();
    let p_json = alloc_free_port();
    let metrics = alloc_free_port();
    let dar = events_dar();
    let manifest = dir.join("canton-daemon.yaml");
    let yaml = format!(
        "name: {name}
synchronizer: sdx005-test-sync
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
    ports: [\"{p_json}:json-api\"]
    dars: [\"{dar}\"]
    depends_on: [s1, m1]
    restart: unless-stopped
",
        dar = dar.display()
    );
    std::fs::write(&manifest, yaml).expect("write manifest");
    (manifest, p_json)
}

struct QueryStack {
    xdg: PathBuf,
    work: PathBuf,
    name: String,
    p1_url: String,
}

impl QueryStack {
    fn start(tag: &str) -> Self {
        let work = unique_temp_path(tag);
        let xdg = work.join("xdg");
        std::fs::create_dir_all(&xdg).expect("mkdir xdg");
        let name = format!("sdx005-{tag}-{}", std::process::id());
        let (manifest, p_json) = write_manifest(&work, &name);

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
            "daemon up failed ({}):\nstdout:{}\nstderr:{}",
            up.status,
            String::from_utf8_lossy(&up.stdout),
            String::from_utf8_lossy(&up.stderr)
        );

        let stack = Self {
            xdg,
            work,
            name,
            p1_url: format!("http://127.0.0.1:{p_json}"),
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
                    if ["s1.public", "m1.admin", "p1.json"]
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

    fn allocate_party(&self, hint: &str) -> String {
        let (code, body) = http_json(
            &self.p1_url,
            "POST",
            "/v2/parties",
            Some(&json!({"partyIdHint": hint, "identityProviderId": ""})),
        );
        assert_eq!(code, 200, "allocate {hint} failed ({code}): {body}");
        body.pointer("/partyDetails/party")
            .and_then(Value::as_str)
            .expect("party id")
            .to_string()
    }

    fn submit(&self, party: &str, cmd_id: &str, cmd: Value) -> (String, u64, Vec<String>) {
        let body = json!({
            "commands": {
                "commands": [cmd],
                "commandId": cmd_id,
                "actAs": [party],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": {
                    "filtersByParty": {
                        party: {
                            "cumulative": [{
                                "identifierFilter": {
                                    "WildcardFilter": {"value": {"includeCreatedEventBlob": false}}
                                }
                            }]
                        }
                    },
                    "verbose": false
                },
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        });
        let (code, resp) = http_json(
            &self.p1_url,
            "POST",
            "/v2/commands/submit-and-wait-for-transaction",
            Some(&body),
        );
        assert_eq!(code, 200, "{cmd_id} failed ({code}): {resp}");
        let tx = &resp["transaction"];
        let update_id = tx["updateId"].as_str().expect("updateId").to_string();
        let offset = tx["offset"].as_u64().expect("offset");
        let created = tx["events"]
            .as_array()
            .expect("events")
            .iter()
            .filter_map(|e| {
                e.pointer("/CreatedEvent/contractId")
                    .and_then(Value::as_str)
                    .map(String::from)
            })
            .collect();
        (update_id, offset, created)
    }

    fn ledger_end(&self) -> u64 {
        let (code, resp) = http_json(&self.p1_url, "GET", "/v2/state/ledger-end", None);
        assert_eq!(code, 200, "ledger-end failed ({code}): {resp}");
        resp["offset"].as_u64().expect("offset")
    }

    fn ws_active_subs(&self) -> usize {
        let raw = http_text(&self.p1_url, "GET", "/metrics");
        for line in raw.lines() {
            if line.starts_with("canton_rs_active_subscriptions{")
                && line.contains("transport=\"ws\"")
            {
                if let Some(val_str) = line.split_whitespace().last() {
                    if let Ok(n) = val_str.parse::<usize>() {
                        return n;
                    }
                }
            }
        }
        panic!(
            "missing canton_rs_active_subscriptions{{...,transport=\"ws\"}} in /metrics:\n{raw}"
        );
    }

    fn contracts_ls_json(&self, party: &str, at: Option<u64>, template: Option<&str>) -> Value {
        let mut args = vec![
            "daemon".to_string(),
            "contracts".to_string(),
            "ls".to_string(),
            "--name".to_string(),
            self.name.clone(),
            "--party".to_string(),
            party.to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];
        if let Some(off) = at {
            args.push("--at".to_string());
            args.push(off.to_string());
        }
        if let Some(t) = template {
            args.push("--template".to_string());
            args.push(t.to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = self.cmd(&arg_refs).output().expect("contracts ls");
        assert!(
            out.status.success(),
            "contracts ls failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("parse contracts ls json")
    }
}

impl Drop for QueryStack {
    fn drop(&mut self) {
        let _ = self
            .cmd(&["daemon", "remove", "--name", &self.name, "--force"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&self.work);
    }
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

fn cid_set(ls_json: &Value) -> BTreeSet<String> {
    ls_json["contracts"]
        .as_array()
        .expect("contracts array")
        .iter()
        .filter_map(|c| c["contractId"].as_str().map(String::from))
        .collect()
}

fn send_sigint(child: &Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as libc::pid_t;
        // SAFETY: sending SIGINT to our own spawned child process while waiting on it cleanly tests V-06/V-07.
        unsafe {
            libc::kill(pid, libc::SIGINT);
        }
    }
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

#[test]
fn sdx005_v05_acs_matches_delta_fold() {
    let _guard = QUERY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = QueryStack::start("v05");
    let alice = stack.allocate_party("Alice");
    let bob = stack.allocate_party("Bob");

    let mut rng = SplitMix64(0x5d05_0005);
    let mut created_total = 0usize;
    let mut live: Vec<String> = Vec::new();
    let mut sample_offsets: BTreeSet<u64> = BTreeSet::new();

    // Randomly create 50 Box contracts and interleave archives (~25 archives) while recording offsets.
    let mut step = 0usize;
    while created_total < 50 {
        let do_archive = !live.is_empty() && rng.next().is_multiple_of(3);
        if do_archive {
            let idx = (rng.next() as usize) % live.len();
            let cid = live.remove(idx);
            let (_, off, new_cids) = stack.submit(
                &alice,
                &format!("v05-bump-{step}"),
                json!({
                    "ExerciseCommand": {
                        "templateId": "#events-oracle:Events:Box",
                        "contractId": cid,
                        "choice": "Bump",
                        "choiceArgument": {}
                    }
                }),
            );
            // Bump archives old cid and creates 1 new Box contract!
            live.extend(new_cids);
            created_total += 1;
            sample_offsets.insert(off);
        } else {
            let (_, off, new_cids) = stack.submit(
                &alice,
                &format!("v05-create-{step}"),
                json!({
                    "CreateCommand": {
                        "templateId": "#events-oracle:Events:Box",
                        "createArguments": {"owner": alice, "watcher": bob, "n": step.to_string()}
                    }
                }),
            );
            live.extend(new_cids);
            created_total += 1;
            sample_offsets.insert(off);
        }
        step += 1;
    }

    let final_end = stack.ledger_end();
    let (u_code, updates_val) = http_json(
        &stack.p1_url,
        "POST",
        "/v2/updates",
        Some(&json!({
            "beginExclusive": 0,
            "endInclusive": final_end,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": {
                        "filtersByParty": {
                            &alice: {
                                "cumulative": [{
                                    "identifierFilter": {
                                        "WildcardFilter": {"value": {"includeCreatedEventBlob": false}}
                                    }
                                }]
                            }
                        },
                        "verbose": false
                    },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                }
            }
        })),
    );
    assert_eq!(u_code, 200, "/v2/updates failed: {updates_val}");
    let updates = updates_val.as_array().expect("updates array");

    // Pick 10 distinct evenly-spaced offsets across all recorded transaction offsets.
    let all_offs: Vec<u64> = sample_offsets.into_iter().collect();
    assert!(
        all_offs.len() >= 10,
        "expected >= 10 distinct offsets, got {}",
        all_offs.len()
    );
    let mut picked = Vec::new();
    for i in 0..10 {
        let idx = i * (all_offs.len() - 1) / 9;
        picked.push(all_offs[idx]);
    }

    for &t in &picked {
        let mut expected: BTreeSet<String> = BTreeSet::new();
        for item in updates {
            let Some(tx) = item.pointer("/update/Transaction/value") else {
                continue;
            };
            let off = tx["offset"].as_u64().unwrap_or(0);
            if off > t {
                continue;
            }
            for ev in tx["events"].as_array().expect("tx events") {
                if let Some(cid) = ev
                    .pointer("/CreatedEvent/contractId")
                    .and_then(Value::as_str)
                {
                    expected.insert(cid.to_string());
                } else if let Some(cid) = ev
                    .pointer("/ArchivedEvent/contractId")
                    .and_then(Value::as_str)
                {
                    expected.remove(cid);
                }
            }
        }
        let ls = stack.contracts_ls_json(&alice, Some(t), None);
        let actual = cid_set(&ls);
        assert_eq!(
            actual,
            expected,
            "V-A4 mismatch at offset {t}: ls={} fold={}",
            actual.len(),
            expected.len()
        );
    }
}

#[test]
fn sdx005_v06_watch_matches_acs_fold() {
    let _guard = QUERY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = QueryStack::start("v06");
    let alice = stack.allocate_party("Alice");
    let bob = stack.allocate_party("Bob");

    // Seed initial contracts before starting watch at t0.
    let mut to_archive = Vec::new();
    for i in 0..4 {
        let (_, _, cids) = stack.submit(
            &alice,
            &format!("v06-seed-{i}"),
            json!({
                "CreateCommand": {
                    "templateId": "#events-oracle:Events:Box",
                    "createArguments": {"owner": alice, "watcher": bob, "n": i.to_string()}
                }
            }),
        );
        to_archive.extend(cids);
    }

    let ls_0 = stack.contracts_ls_json(&alice, None, None);
    let t0 = ls_0["activeAtOffset"].as_u64().expect("t0");
    let mut folded = cid_set(&ls_0);

    let t0_str = t0.to_string();
    let mut child = stack
        .cmd(&[
            "daemon",
            "contracts",
            "watch",
            "--name",
            &stack.name,
            "--party",
            &alice,
            "--from",
            &t0_str,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn contracts watch");

    let stdout = child.stdout.take().expect("child stdout");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    // Wait until WS subscription is registered server-side.
    let sub_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < sub_deadline && stack.ws_active_subs() < 1 {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(stack.ws_active_subs(), 1, "expected active WS subscription");

    // Apply 20 changes: 12 creates + 8 archives (4 seeded + 4 created, leaving 8 archived and 12 created = 20 deltas).
    for i in 0..12 {
        let (_, _, cids) = stack.submit(
            &alice,
            &format!("v06-mut-c-{i}"),
            json!({
                "CreateCommand": {
                    "templateId": "#events-oracle:Events:Box",
                    "createArguments": {"owner": alice, "watcher": bob, "n": (100 + i).to_string()}
                }
            }),
        );
        if i < 4 {
            to_archive.extend(cids);
        }
    }
    for (i, cid) in to_archive.iter().enumerate() {
        let _ = stack.submit(
            &alice,
            &format!("v06-mut-a-{i}"),
            json!({
                "ExerciseCommand": {
                    "templateId": "#events-oracle:Events:Box",
                    "contractId": cid,
                    "choice": "Archive",
                    "choiceArgument": {}
                }
            }),
        );
    }

    let mut lines = Vec::new();
    let collect_deadline = Instant::now() + Duration::from_secs(15);
    while lines.len() < 20 && Instant::now() < collect_deadline {
        let rem = collect_deadline.saturating_duration_since(Instant::now());
        if let Ok(line) = rx.recv_timeout(rem.min(Duration::from_millis(200))) {
            lines.push(line);
        }
    }
    assert_eq!(
        lines.len(),
        20,
        "expected 20 streamed delta lines from watch, got {} ({lines:?})",
        lines.len()
    );

    send_sigint(&child);
    let status = child.wait().expect("wait watch");
    assert!(status.success(), "watch failed on SIGINT: {status}");
    let _ = reader_handle.join();

    for line in &lines {
        let mut parts = line.split_whitespace();
        let op = parts.next().expect("op");
        let cid = parts.next().expect("cid");
        match op {
            "+" => {
                folded.insert(cid.to_string());
            }
            "-" => {
                folded.remove(cid);
            }
            other => panic!("unexpected watch op '{other}' in '{line}'"),
        }
    }

    let ls_1 = stack.contracts_ls_json(&alice, None, None);
    let expected = cid_set(&ls_1);
    assert_eq!(folded, expected, "V-A5 fold(ls(t0), watch) != ls(t1)");
}

#[test]
fn sdx005_v07_watch_sigint_clean_shutdown_and_zero_subs() {
    let _guard = QUERY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = QueryStack::start("v07");
    let alice = stack.allocate_party("Alice");

    let mut child = stack
        .cmd(&[
            "daemon",
            "contracts",
            "watch",
            "--name",
            &stack.name,
            "--party",
            &alice,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn watch");

    let sub_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < sub_deadline && stack.ws_active_subs() < 1 {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        stack.ws_active_subs(),
        1,
        "expected server-side WS subscription gauge == 1 while watching"
    );

    let sig_t = Instant::now();
    send_sigint(&child);
    let exit_status = loop {
        if let Some(st) = child.try_wait().expect("try_wait") {
            break st;
        }
        assert!(
            sig_t.elapsed() < Duration::from_secs(1),
            "watch did not exit within 1s after SIGINT ({:?})",
            sig_t.elapsed()
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        exit_status.code(),
        Some(0),
        "expected exit code 0 after SIGINT, got {exit_status:?}"
    );

    let drain_deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < drain_deadline && stack.ws_active_subs() != 0 {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        stack.ws_active_subs(),
        0,
        "expected server-side WS subscription gauge == 0 after Ctrl-C"
    );
}

#[test]
fn sdx005_v08_template_filter_isolation() {
    let _guard = QUERY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = QueryStack::start("v08");
    let alice = stack.allocate_party("Alice");
    let bob = stack.allocate_party("Bob");

    let (_, _, box_cids) = stack.submit(
        &alice,
        "v08-box",
        json!({
            "CreateCommand": {
                "templateId": "#events-oracle:Events:Box",
                "createArguments": {"owner": alice, "watcher": bob, "n": "1"}
            }
        }),
    );
    let (_, _, gift_cids) = stack.submit(
        &alice,
        "v08-gift",
        json!({
            "CreateCommand": {
                "templateId": "#events-oracle:Events:Gift",
                "createArguments": {"owner": alice, "watcher": bob}
            }
        }),
    );
    let box_cid = &box_cids[0];
    let gift_cid = &gift_cids[0];

    // Check `#package-name:Module:Entity` AND resolved `<package-id>:Module:Entity` on `contracts ls`.
    let ls_name = stack.contracts_ls_json(&alice, None, Some("#events-oracle:Events:Box"));
    let name_cids = cid_set(&ls_name);
    assert_eq!(name_cids, BTreeSet::from([box_cid.clone()]));
    let pkg_tpl = ls_name["contracts"][0]["templateId"]
        .as_str()
        .expect("resolved pkgId templateId")
        .to_string();
    assert!(
        !pkg_tpl.starts_with('#'),
        "expected pkgId:Mod:Ent, got {pkg_tpl}"
    );
    assert!(pkg_tpl.ends_with(":Events:Box"));

    let ls_id = stack.contracts_ls_json(&alice, None, Some(&pkg_tpl));
    assert_eq!(cid_set(&ls_id), BTreeSet::from([box_cid.clone()]));

    // Check `tx ls --template #events-oracle:Events:Box` and `--template <pkgId>:Events:Box`.
    for tpl_arg in ["#events-oracle:Events:Box", pkg_tpl.as_str()] {
        let tx_out = stack
            .cmd(&[
                "daemon",
                "tx",
                "ls",
                "--name",
                &stack.name,
                "--party",
                &alice,
                "--template",
                tpl_arg,
                "--format",
                "json",
            ])
            .output()
            .expect("tx ls filtered");
        assert!(tx_out.status.success());
        let tx_json: Value = serde_json::from_slice(&tx_out.stdout).expect("parse tx ls");
        let updates = tx_json["updates"].as_array().expect("updates");
        assert_eq!(
            updates.len(),
            1,
            "expected only Box update for {tpl_arg}: {updates:?}"
        );
        assert_eq!(updates[0]["templates"], json!([pkg_tpl]));
    }

    // Check `contracts watch --template #events-oracle:Events:Box --from 0`.
    let mut watch = stack
        .cmd(&[
            "daemon",
            "contracts",
            "watch",
            "--name",
            &stack.name,
            "--party",
            &alice,
            "--template",
            "#events-oracle:Events:Box",
            "--from",
            "0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn filtered watch");
    let stdout = watch.stdout.take().expect("stdout");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut watch_lines = Vec::new();
    while Instant::now() < deadline {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(150)) {
            watch_lines.push(line);
        } else if !watch_lines.is_empty() {
            break;
        }
    }
    send_sigint(&watch);
    let status = watch.wait().expect("wait watch");
    assert!(status.success());
    let _ = reader.join();

    assert_eq!(
        watch_lines.len(),
        1,
        "expected 1 filtered Box line, got {watch_lines:?}"
    );
    assert!(watch_lines[0].contains(box_cid));
    assert!(!watch_lines[0].contains(gift_cid));

    // Negative preflight control: malformed `--template` exits with EXIT_PREFLIGHT (2).
    let bad = stack
        .cmd(&[
            "daemon",
            "contracts",
            "ls",
            "--name",
            &stack.name,
            "--party",
            &alice,
            "--template",
            "not-a-valid-template",
        ])
        .output()
        .expect("bad template");
    assert_eq!(bad.status.code(), Some(2));
}
