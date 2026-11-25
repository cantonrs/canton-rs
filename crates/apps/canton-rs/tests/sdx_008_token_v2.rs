//! Integration tests T-01..T-09 for `canton-rs token` (CIP-0112 Token Standard V2, `S-DX-008`).
//!
//! Runs against live `canton-rs daemon up --dev-auth` instances, verifying:
//! - S-DX-002 instance registry endpoint resolution (`--name`)
//! - S-DX-007 automatic development JWT signing (`--dev-auth`)
//! - T-A1 supply conservation, T-A2 transfer accept, T-A3 pending locks,
//!   T-A4 reject/withdraw restoration, T-A5 insufficient balance atomicity,
//!   T-A6 batch settlement atomicity, and T-09 exact `10^-10` decimal precision.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

type BalanceTable = BTreeMap<(String, String), (String, String, String)>;

static PORT_SEQ: AtomicU16 = AtomicU16::new(0);

fn bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_canton-rs") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return pb;
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../target/debug/canton-rs")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn boot_dar() -> PathBuf {
    let dar = repo_root().join("contracts/target/sample-contract.dar");
    assert!(dar.is_file(), "missing boot DAR at {}", dar.display());
    dar
}

fn test_token_dar() -> PathBuf {
    let dar = repo_root().join("references/splice/daml/dars/splice-test-token-v2-1.0.2.dar");
    assert!(dar.is_file(), "missing V2 test DAR at {}", dar.display());
    dar
}

fn choose_clean_ports() -> (u16, u16, u16, u16, u16) {
    let pid_base = (std::process::id() % 400) as u16 * 10;
    for attempt in 0..200u16 {
        let idx = PORT_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = 35000 + ((pid_base + idx * 10 + attempt * 10) % 9000);
        let ports = (base, base + 1, base + 2, base + 3, base + 4);
        let all_free = [ports.0, ports.1, ports.2, ports.3, ports.4]
            .into_iter()
            .all(|p| TcpListener::bind(("127.0.0.1", p)).is_ok());
        if all_free {
            return ports;
        }
    }
    panic!("unable to find 5 free consecutive ports in 35000..=44000");
}

struct TokenHarness {
    name: String,
    work_dir: PathBuf,
    xdg_state_home: PathBuf,
    http_url: String,
    admin_jwt: String,
}

impl TokenHarness {
    fn start(tag: &str) -> Self {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let name = format!("sdx008-{tag}-{}-{uniq}", std::process::id());
        let work_dir = std::env::temp_dir().join(&name);
        let xdg_state_home = work_dir.join("xdg");
        let state_dir = work_dir.join("state");
        fs::create_dir_all(&xdg_state_home).expect("mkdir xdg");
        fs::create_dir_all(&state_dir).expect("mkdir state");

        let (pub_p, adm_p, med_p, http_p, met_p) = choose_clean_ports();
        let manifest_path = work_dir.join("manifest.yaml");
        let boot_dar_path = boot_dar();
        let yaml = format!(
            "name: {name}\nsynchronizer: sync-{tag}\nstate_dir: {}\nmetrics_port: {met_p}\nservices:\n  s1:\n    role: sequencer\n    ports: [\"{pub_p}:public\", \"{adm_p}:admin\"]\n    restart: no\n  m1:\n    role: mediator\n    ports: [\"{med_p}:admin\"]\n    depends_on: [s1]\n    restart: no\n  p1:\n    role: participant\n    ports: [\"{http_p}:json-api\"]\n    dars: [\"{}\"]\n    depends_on: [s1, m1]\n    restart: no\n",
            state_dir.display(),
            boot_dar_path.display()
        );
        fs::write(&manifest_path, yaml).expect("write manifest");

        let up = Command::new(bin())
            .env("XDG_STATE_HOME", &xdg_state_home)
            .args([
                "daemon",
                "up",
                "--name",
                &name,
                "-f",
                &manifest_path.to_string_lossy(),
                "--state-in-files",
                "--port-offset",
                "0",
                "--dev-auth",
                "-d",
            ])
            .output()
            .expect("spawn daemon up");
        assert!(
            up.status.success(),
            "daemon up failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&up.stdout),
            String::from_utf8_lossy(&up.stderr)
        );

        let http_url = format!("http://127.0.0.1:{http_p}");
        wait_readyz("127.0.0.1", http_p);

        let creds = Command::new(bin())
            .env("XDG_STATE_HOME", &xdg_state_home)
            .args([
                "daemon",
                "creds",
                "--name",
                &name,
                "--user",
                "participant_admin",
                "--format",
                "json",
            ])
            .output()
            .expect("run daemon creds");
        assert!(
            creds.status.success(),
            "daemon creds failed: {}",
            String::from_utf8_lossy(&creds.stderr)
        );
        let creds_json: Value =
            serde_json::from_slice(&creds.stdout).expect("parse daemon creds json");
        let admin_jwt = creds_json["token"]
            .as_str()
            .expect("creds token")
            .to_string();

        Self {
            name,
            work_dir,
            xdg_state_home,
            http_url,
            admin_jwt,
        }
    }

    fn run_raw(&self, args: &[&str]) -> Output {
        Command::new(bin())
            .env("XDG_STATE_HOME", &self.xdg_state_home)
            .args(args)
            .output()
            .expect("execute canton-rs token")
    }

    fn token_json(&self, args: &[&str]) -> Value {
        let mut full = Vec::with_capacity(args.len() + 4);
        full.push("token");
        full.extend_from_slice(args);
        full.extend(["--name", &self.name, "--format", "json"]);
        let out = self.run_raw(&full);
        assert!(
            out.status.success(),
            "canton-rs {} failed (exit={:?}):\nstdout={}\nstderr={}",
            full.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "invalid json output for `{}`: {e}\nstdout={}",
                full.join(" "),
                String::from_utf8_lossy(&out.stdout)
            )
        })
    }

    fn allocate_party(&self, hint: &str) -> String {
        let (_, port_str) = self.http_url.rsplit_once(':').expect("url port");
        let port: u16 = port_str.parse().expect("port u16");
        let payload = serde_json::to_vec(&json!({
            "partyIdHint": hint,
            "identityProviderId": ""
        }))
        .expect("serialize party req");
        let (st, body) =
            http_post_json("127.0.0.1", port, "/v2/parties", &payload, &self.admin_jwt);
        assert!(
            (200..300).contains(&st),
            "POST /v2/parties({hint}) -> {st}: {body}"
        );
        body["partyDetails"]["party"]
            .as_str()
            .expect("party string")
            .to_string()
    }

    fn balances_map(&self) -> (BalanceTable, BTreeMap<String, String>) {
        let out = self.token_json(&["balances"]);
        let mut bal = BTreeMap::new();
        if let Some(arr) = out["balances"].as_array() {
            for r in arr {
                let p = r["party"].as_str().expect("party").to_string();
                let inst = r["instrument"].as_str().expect("instrument").to_string();
                let avail = r["available"].as_str().expect("avail").to_string();
                let locked = r["locked"].as_str().expect("locked").to_string();
                let total = r["total"].as_str().expect("total").to_string();
                bal.insert((p, inst), (avail, locked, total));
            }
        }
        let mut supplies = BTreeMap::new();
        if let Some(arr) = out["supplies"].as_array() {
            for r in arr {
                let inst = r["instrument"].as_str().expect("inst").to_string();
                let sup = r["supply"].as_str().expect("supply").to_string();
                supplies.insert(inst, sup);
            }
        }
        (bal, supplies)
    }

    fn assert_party_bal(
        &self,
        party: &str,
        instrument: &str,
        expected_avail: &str,
        expected_locked: &str,
    ) {
        let (bal, _) = self.balances_map();
        let actual = bal
            .get(&(party.to_string(), instrument.to_string()))
            .cloned()
            .unwrap_or_else(|| ("0.0".to_string(), "0.0".to_string(), "0.0".to_string()));
        assert_eq!(
            (actual.0.as_str(), actual.1.as_str()),
            (expected_avail, expected_locked),
            "balance mismatch for {party} ({instrument}): got {actual:?}"
        );
    }

    fn assert_supply(&self, instrument: &str, expected_supply: &str) {
        let (_, supplies) = self.balances_map();
        let actual = supplies
            .get(instrument)
            .cloned()
            .unwrap_or_else(|| "0.0".to_string());
        assert_eq!(
            actual, expected_supply,
            "supply mismatch for {instrument} (T-A1 violation)"
        );
    }
}

impl Drop for TokenHarness {
    fn drop(&mut self) {
        let _ = Command::new(bin())
            .env("XDG_STATE_HOME", &self.xdg_state_home)
            .args(["daemon", "remove", "--name", &self.name, "--force"])
            .output();
        let _ = fs::remove_dir_all(&self.work_dir);
    }
}

fn wait_readyz(host: &str, port: u16) {
    for _ in 0..60 {
        if let Ok(mut s) = TcpStream::connect((host, port)) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let req =
                format!("GET /readyz HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
            if s.write_all(req.as_bytes()).is_ok() {
                let mut buf = String::new();
                let _ = s.read_to_string(&mut buf);
                if buf.starts_with("HTTP/1.1 200") || buf.starts_with("HTTP/1.0 200") {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("endpoint http://{host}:{port}/readyz did not return 200");
}

fn http_post_json(host: &str, port: u16, path: &str, body: &[u8], jwt: &str) -> (u16, Value) {
    let mut s = TcpStream::connect((host, port)).expect("connect http");
    s.set_read_timeout(Some(Duration::from_secs(20))).ok();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAuthorization: Bearer {jwt}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).expect("write header");
    s.write_all(body).expect("write body");
    let mut resp = String::new();
    s.read_to_string(&mut resp).expect("read resp");
    let (head, raw_body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, "{}"));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    let val = serde_json::from_str(raw_body).unwrap_or(Value::Null);
    (status, val)
}

#[test]
fn t01_mint() {
    let h = TokenHarness::start("t01");
    let dar = test_token_dar();
    let dar_s = dar.to_string_lossy();
    let admin = h.allocate_party("Admin");
    let alice = h.allocate_party("Alice");

    let created = h.token_json(&[
        "create",
        "--instrument",
        "USDX",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);
    assert_eq!(created["instrument"], "USDX");

    let minted = h.token_json(&[
        "mint", "USDX", &alice, "100.0", "--admin", &admin, "--dar", &dar_s,
    ]);
    assert_eq!(minted["amount"], "100.0");

    let bal = h.token_json(&["balance", &alice, "USDX"]);
    assert_eq!(bal["balances"][0]["available"], "100.0");
    assert_eq!(bal["balances"][0]["locked"], "0.0");
    assert_eq!(bal["balances"][0]["total"], "100.0");
    h.assert_supply("USDX", "100.0");

    let act = h.token_json(&["activity", &alice]);
    assert!(
        !act["events"].as_array().expect("events").is_empty(),
        "activity for Alice should record mint events"
    );
}

#[test]
fn t02_transfer_accept() {
    let h = TokenHarness::start("t02");
    let dar = test_token_dar();
    let dar_s = dar.to_string_lossy();
    let admin = h.allocate_party("Admin");
    let alice = h.allocate_party("Alice");
    let bob = h.allocate_party("Bob");
    let carol = h.allocate_party("Carol");

    h.token_json(&[
        "create",
        "--instrument",
        "USDX",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);
    h.token_json(&[
        "mint", "USDX", &alice, "100.0", "--admin", &admin, "--dar", &dar_s,
    ]);
    let xfer = h.token_json(&[
        "transfer",
        "USDX",
        &alice,
        &bob,
        "30.0",
        "--auto-accept",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);
    assert_eq!(xfer["status"], "accepted");

    h.assert_party_bal(&alice, "USDX", "70.0", "0.0");
    h.assert_party_bal(&bob, "USDX", "30.0", "0.0");
    h.assert_party_bal(&carol, "USDX", "0.0", "0.0");
    h.assert_supply("USDX", "100.0");
}

#[test]
fn t03_transfer_pending_lock() {
    let h = TokenHarness::start("t03");
    let dar = test_token_dar();
    let dar_s = dar.to_string_lossy();
    let admin = h.allocate_party("Admin");
    let alice = h.allocate_party("Alice");
    let bob = h.allocate_party("Bob");

    h.token_json(&[
        "create",
        "--instrument",
        "USDX",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);
    h.token_json(&[
        "mint", "USDX", &alice, "100.0", "--admin", &admin, "--dar", &dar_s,
    ]);
    let xfer = h.token_json(&[
        "transfer", "USDX", &alice, &bob, "30.0", "--admin", &admin, "--dar", &dar_s,
    ]);
    assert!(xfer["instruction_cid"].as_str().is_some());

    h.assert_party_bal(&alice, "USDX", "70.0", "30.0");
    h.assert_party_bal(&bob, "USDX", "0.0", "0.0");
    h.assert_supply("USDX", "100.0");
}

#[test]
fn t04_transfer_reject() {
    let h = TokenHarness::start("t04");
    let dar = test_token_dar();
    let dar_s = dar.to_string_lossy();
    let admin = h.allocate_party("Admin");
    let alice = h.allocate_party("Alice");
    let bob = h.allocate_party("Bob");

    h.token_json(&[
        "create",
        "--instrument",
        "USDX",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);
    h.token_json(&[
        "mint", "USDX", &alice, "100.0", "--admin", &admin, "--dar", &dar_s,
    ]);
    let xfer = h.token_json(&[
        "transfer", "USDX", &alice, &bob, "30.0", "--admin", &admin, "--dar", &dar_s,
    ]);
    let instr = xfer["instruction_cid"].as_str().expect("instruction cid");

    h.token_json(&["transfer", "reject", instr, "--dar", &dar_s]);
    h.assert_party_bal(&alice, "USDX", "100.0", "0.0");
    h.assert_party_bal(&bob, "USDX", "0.0", "0.0");
    h.assert_supply("USDX", "100.0");
}

#[test]
fn t05_transfer_withdraw() {
    let h = TokenHarness::start("t05");
    let dar = test_token_dar();
    let dar_s = dar.to_string_lossy();
    let admin = h.allocate_party("Admin");
    let alice = h.allocate_party("Alice");
    let bob = h.allocate_party("Bob");

    h.token_json(&[
        "create",
        "--instrument",
        "USDX",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);
    h.token_json(&[
        "mint", "USDX", &alice, "100.0", "--admin", &admin, "--dar", &dar_s,
    ]);
    let xfer = h.token_json(&[
        "transfer", "USDX", &alice, &bob, "30.0", "--admin", &admin, "--dar", &dar_s,
    ]);
    let instr = xfer["instruction_cid"].as_str().expect("instruction cid");

    h.token_json(&["transfer", "withdraw", instr, "--dar", &dar_s]);
    h.assert_party_bal(&alice, "USDX", "100.0", "0.0");
    h.assert_party_bal(&bob, "USDX", "0.0", "0.0");
    h.assert_supply("USDX", "100.0");
}

#[test]
fn t06_insufficient_balance() {
    let h = TokenHarness::start("t06");
    let dar = test_token_dar();
    let dar_s = dar.to_string_lossy();
    let admin = h.allocate_party("Admin");
    let alice = h.allocate_party("Alice");
    let bob = h.allocate_party("Bob");

    h.token_json(&[
        "create",
        "--instrument",
        "USDX",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);
    h.token_json(&[
        "mint", "USDX", &alice, "100.0", "--admin", &admin, "--dar", &dar_s,
    ]);

    let fail = h.run_raw(&[
        "token", "transfer", "--name", &h.name, "USDX", &alice, &bob, "1000.0", "--admin", &admin,
        "--dar", &dar_s,
    ]);
    assert!(
        !fail.status.success(),
        "insufficient transfer must fail (T-A5), got exit 0: {}",
        String::from_utf8_lossy(&fail.stdout)
    );
    h.assert_party_bal(&alice, "USDX", "100.0", "0.0");
    h.assert_party_bal(&bob, "USDX", "0.0", "0.0");
    h.assert_supply("USDX", "100.0");
}

#[test]
fn t07_dvp_settle_success() {
    let h = TokenHarness::start("t07");
    let dar = test_token_dar();
    let dar_s = dar.to_string_lossy();
    let admin = h.allocate_party("Admin");
    let alice = h.allocate_party("Alice");
    let bob = h.allocate_party("Bob");

    h.token_json(&[
        "create",
        "--instrument",
        "USDX",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);
    h.token_json(&[
        "mint", "USDX", &alice, "100.0", "--admin", &admin, "--dar", &dar_s,
    ]);
    h.token_json(&[
        "mint", "USDY", &bob, "50.0", "--admin", &admin, "--dar", &dar_s,
    ]);

    let a1 = h.token_json(&[
        "allocation",
        "create",
        "--settlement-id",
        "dvp-1",
        "--executor",
        &admin,
        "--authorizer",
        &alice,
        "--admin",
        &admin,
        "--leg",
        &format!("leg1:sender:{bob}:USDX:10.0"),
        "--leg",
        &format!("leg2:receiver:{bob}:USDY:5.0"),
        "--dar",
        &dar_s,
    ]);
    let a1_cid = a1["allocation_cid"].as_str().expect("alloc1 cid");

    let a2 = h.token_json(&[
        "allocation",
        "create",
        "--settlement-id",
        "dvp-1",
        "--executor",
        &admin,
        "--authorizer",
        &bob,
        "--admin",
        &admin,
        "--leg",
        &format!("leg1:receiver:{alice}:USDX:10.0"),
        "--leg",
        &format!("leg2:sender:{alice}:USDY:5.0"),
        "--dar",
        &dar_s,
    ]);
    let a2_cid = a2["allocation_cid"].as_str().expect("alloc2 cid");

    let list = h.token_json(&["allocation", "list"]);
    assert_eq!(list["allocations"].as_array().expect("allocs").len(), 2);

    h.assert_party_bal(&alice, "USDX", "90.0", "10.0");
    h.assert_party_bal(&bob, "USDY", "45.0", "5.0");

    let leg1 = format!("leg1:{alice}:{bob}:USDX:10.0");
    let leg2 = format!("leg2:{bob}:{alice}:USDY:5.0");
    let mut settle_args = vec![
        "settle",
        "dvp-1",
        "--executor",
        &admin,
        "--admin",
        &admin,
        "--alloc",
        a1_cid,
        "--leg",
        &leg1,
        "--leg",
        &leg2,
        "--dar",
        &dar_s,
    ];
    let include_counterparty_alloc = true;
    if include_counterparty_alloc {
        settle_args.extend(["--alloc", a2_cid]);
    }
    h.token_json(&settle_args);

    h.assert_party_bal(&alice, "USDX", "90.0", "0.0");
    h.assert_party_bal(&alice, "USDY", "5.0", "0.0");
    h.assert_party_bal(&bob, "USDX", "10.0", "0.0");
    h.assert_party_bal(&bob, "USDY", "45.0", "0.0");
    h.assert_supply("USDX", "100.0");
    h.assert_supply("USDY", "50.0");
}

#[test]
fn t08_dvp_settle_atomic_failure() {
    let h = TokenHarness::start("t08");
    let dar = test_token_dar();
    let dar_s = dar.to_string_lossy();
    let admin = h.allocate_party("Admin");
    let alice = h.allocate_party("Alice");
    let bob = h.allocate_party("Bob");

    h.token_json(&[
        "create",
        "--instrument",
        "USDX",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);
    h.token_json(&[
        "mint", "USDX", &alice, "100.0", "--admin", &admin, "--dar", &dar_s,
    ]);
    h.token_json(&[
        "mint", "USDY", &bob, "50.0", "--admin", &admin, "--dar", &dar_s,
    ]);

    let a1 = h.token_json(&[
        "allocation",
        "create",
        "--settlement-id",
        "dvp-2",
        "--executor",
        &admin,
        "--authorizer",
        &alice,
        "--admin",
        &admin,
        "--leg",
        &format!("leg1:sender:{bob}:USDX:10.0"),
        "--leg",
        &format!("leg2:receiver:{bob}:USDY:5.0"),
        "--dar",
        &dar_s,
    ]);
    let a1_cid = a1["allocation_cid"].as_str().expect("alloc1 cid");

    let a2 = h.token_json(&[
        "allocation",
        "create",
        "--settlement-id",
        "dvp-2",
        "--executor",
        &admin,
        "--authorizer",
        &bob,
        "--admin",
        &admin,
        "--leg",
        &format!("leg1:receiver:{alice}:USDX:10.0"),
        "--leg",
        &format!("leg2:sender:{alice}:USDY:5.0"),
        "--dar",
        &dar_s,
    ]);
    let a2_cid = a2["allocation_cid"].as_str().expect("alloc2 cid");

    // Bob withdraws alloc2 before settlement.
    h.token_json(&["allocation", "withdraw", a2_cid, "--dar", &dar_s]);

    let fail = h.run_raw(&[
        "token",
        "settle",
        "--name",
        &h.name,
        "dvp-2",
        "--executor",
        &admin,
        "--admin",
        &admin,
        "--alloc",
        a1_cid,
        "--alloc",
        a2_cid,
        "--leg",
        &format!("leg1:{alice}:{bob}:USDX:10.0"),
        "--leg",
        &format!("leg2:{bob}:{alice}:USDY:5.0"),
        "--dar",
        &dar_s,
    ]);
    assert!(
        !fail.status.success(),
        "settle with withdrawn allocation must fail atomically (T-A6)"
    );

    // Zero partial settlement: Alice still has USDX 90 avail + 10 locked, Bob has USDY 50 avail + 0 locked.
    h.assert_party_bal(&alice, "USDX", "90.0", "10.0");
    h.assert_party_bal(&alice, "USDY", "0.0", "0.0");
    h.assert_party_bal(&bob, "USDX", "0.0", "0.0");
    h.assert_party_bal(&bob, "USDY", "50.0", "0.0");
    h.assert_supply("USDX", "100.0");
    h.assert_supply("USDY", "50.0");
}

#[test]
fn t09_decimal_precision() {
    let h = TokenHarness::start("t09");
    let dar = test_token_dar();
    let dar_s = dar.to_string_lossy();
    let admin = h.allocate_party("Admin");
    let alice = h.allocate_party("Alice");
    let bob = h.allocate_party("Bob");

    h.token_json(&[
        "create",
        "--instrument",
        "USDX",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);
    h.token_json(&[
        "mint",
        "USDX",
        &alice,
        "1000000.0",
        "--admin",
        &admin,
        "--dar",
        &dar_s,
    ]);

    for _ in 0..100 {
        h.token_json(&[
            "transfer",
            "USDX",
            &alice,
            &bob,
            "0.0000000001",
            "--auto-accept",
            "--admin",
            &admin,
            "--dar",
            &dar_s,
        ]);
    }

    h.assert_party_bal(&bob, "USDX", "0.00000001", "0.0");
    h.assert_party_bal(&alice, "USDX", "999999.99999999", "0.0");
    h.assert_supply("USDX", "1000000.0");
}
