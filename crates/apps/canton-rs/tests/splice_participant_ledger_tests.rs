//! S-SPL-038 integration tests: `PersistentSplice::open_participant_ledger` against a real
//! `canton-rs json-api` process with JWT auth, Scan + `/registry/*` unification, hosted wallet
//! transfers, automation settlement, and `splice-ledger-meta` restart recovery.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use canton_participant::splice_ledger_backend::sign_hs256_jwt;
use canton_participant::splice_persist::PersistentSplice;
use canton_participant::state_store::FileStore;
use canton_participant::{ParticipantLedgerConfig, SpliceBootstrapConfig};
use serde_json::{json, Value as Json};

fn get_bin_path() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("canton-rs");
    path
}

fn splice_dars_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/splice-dars")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

struct ChildGuard {
    child: Child,
    temp_dirs: Vec<PathBuf>,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for d in &self.temp_dirs {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

fn http_json(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> Result<(u16, Json), String> {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect :{port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "missing HTTP headers".to_string())?;
    let head = String::from_utf8_lossy(&raw[..pos]);
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "bad HTTP status".to_string())?;
    let body = &raw[pos + 4..];
    let json = if body.is_empty() {
        Json::Null
    } else {
        serde_json::from_slice(body)
            .unwrap_or_else(|_| Json::String(String::from_utf8_lossy(body).into_owned()))
    };
    Ok((status, json))
}

fn wait_ready(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok((200, _)) = http_json(port, "GET", "/livez", None) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("canton-rs json-api on :{port} did not become ready in time");
}

fn parse_resp_json(resp: &canton_participant::scan_api::Response) -> Json {
    serde_json::from_str(&resp.body).unwrap_or_else(|_| json!({ "raw": resp.body }))
}

#[test]
fn participant_ledger_backend_boots_serves_scan_registry_and_recovers_on_restart() {
    let bin = get_bin_path();
    let dars = splice_dars_dir();
    assert!(
        dars.exists(),
        "missing splice-dars dir at {}",
        dars.display()
    );

    let port = free_port();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base_tmp = std::env::temp_dir().join(format!("splice-ledger-test-{nonce}"));
    let state_dir = base_tmp.join("splice-meta");
    std::fs::create_dir_all(&base_tmp).unwrap();

    let child = Command::new(&bin)
        .args([
            "json-api",
            "--port",
            &port.to_string(),
            "--jwt-hmac-secret",
            "unsafe",
            "--jwt-audience",
            "https://canton.network.global",
            "--jwt-max-lifetime-seconds",
            "86400",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn canton-rs json-api");

    let _guard = ChildGuard {
        child,
        temp_dirs: vec![base_tmp],
    };
    wait_ready(port);

    let ledger_cfg = ParticipantLedgerConfig {
        host: "127.0.0.1".into(),
        port,
        auth_unsafe_secret: Some("unsafe".into()),
        user_id: "ledger-api-user".into(),
        ..ParticipantLedgerConfig::default()
    };
    let user_jwt = sign_hs256_jwt("unsafe", "ledger-api-user", "https://canton.network.global");

    let (alice_party, bob_party, ledger_end_before_restart);
    {
        let store = FileStore::new(&state_dir).expect("FileStore::new");
        let boot_cfg = SpliceBootstrapConfig::default();
        let (app, report) = PersistentSplice::open_participant_ledger(
            &dars,
            boot_cfg,
            ledger_cfg.clone(),
            store,
            true,
            Some(&state_dir),
        )
        .expect("open_participant_ledger initial");
        assert!(report.bootstrapped, "fresh ledger must bootstrap DSO");
        assert_eq!(report.replayed, 0);

        let (end_status, end_json) =
            http_json(port, "GET", "/v2/state/ledger-end", Some(&user_jwt)).unwrap();
        assert_eq!(end_status, 200);
        assert!(end_json["offset"].as_u64().unwrap_or(0) > 0);

        let dso_resp = app.handle_http("GET", "/api/scan/v0/dso", &[], b"");
        assert_eq!(dso_resp.status, 200, "scan /v0/dso: {}", dso_resp.body);
        let dso_body = parse_resp_json(&dso_resp);
        let dso_party = dso_body["dso_party_id"]
            .as_str()
            .expect("dso_party_id")
            .to_string();

        let rules_resp = app.handle_http("POST", "/api/scan/v0/amulet-rules", &[], b"{}");
        assert_eq!(
            rules_resp.status, 200,
            "scan /v0/amulet-rules: {}",
            rules_resp.body
        );
        let rules_body = parse_resp_json(&rules_resp);
        assert!(
            rules_body["amulet_rules_update"]["contract"]["created_event_blob"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "missing created_event_blob in /v0/amulet-rules: {rules_body}"
        );

        let reg_req = json!({
            "choiceArguments": {
                "expectedAdmin": dso_party,
                "transfer": {
                    "sender": dso_party,
                    "receiver": dso_party,
                    "amount": "1.0",
                    "instrumentId": { "admin": dso_party, "id": "Amulet" },
                    "requestedAt": "2026-11-18T00:00:00Z",
                    "executeBefore": "2026-11-19T00:00:00Z",
                    "inputHoldingCids": [],
                    "meta": { "values": {} }
                },
                "extraArgs": { "context": { "values": {} }, "meta": { "values": {} } }
            },
            "excludeDebugFields": true
        });
        let reg_resp = app.handle_http(
            "POST",
            "/registry/transfer-instruction/v1/transfer-factory",
            &[],
            reg_req.to_string().as_bytes(),
        );
        assert_eq!(
            reg_resp.status, 200,
            "registry transfer-factory: {}",
            reg_resp.body
        );
        let reg_body = parse_resp_json(&reg_resp);
        assert!(
            reg_body["choiceContext"]["disclosedContracts"]
                .as_array()
                .is_some_and(|a| !a.is_empty()),
            "missing disclosedContracts in registry response: {reg_body}"
        );

        let reg_alice = app.handle_http("POST", "/v0/register", &[], br#"{"username":"alice"}"#);
        assert_eq!(reg_alice.status, 200, "register alice: {}", reg_alice.body);
        alice_party = parse_resp_json(&reg_alice)["party_id"]
            .as_str()
            .unwrap()
            .to_string();

        let reg_bob = app.handle_http("POST", "/v0/register", &[], br#"{"username":"bob"}"#);
        assert_eq!(reg_bob.status, 200, "register bob: {}", reg_bob.body);
        bob_party = parse_resp_json(&reg_bob)["party_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(alice_party, bob_party);

        let tap_resp = app.handle_http(
            "POST",
            "/v0/wallet/tap?user=alice",
            &[],
            br#"{"amount":"100.0"}"#,
        );
        assert_eq!(tap_resp.status, 200, "tap: {}", tap_resp.body);

        let bal_alice = app.handle_http("GET", "/v0/wallet/balance?user=alice", &[], b"");
        assert_eq!(bal_alice.status, 200);
        assert_eq!(
            parse_resp_json(&bal_alice)["effective_unlocked_qty"].as_str(),
            Some("100.0000000000")
        );

        let offer_body = json!({
            "receiver_party_id": bob_party,
            "amount": "25.0",
            "tracking_id": "trk-1",
            "description": "participant ledger transfer test"
        })
        .to_string();
        let offer_resp = app.handle_http(
            "POST",
            "/v0/wallet/transfer-offers?user=alice",
            &[],
            offer_body.as_bytes(),
        );
        assert_eq!(offer_resp.status, 200, "create offer: {}", offer_resp.body);
        let offer_cid = parse_resp_json(&offer_resp)["offer_contract_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Idempotent retry must return 200 with identical contract id.
        let retry_same = app.handle_http(
            "POST",
            "/v0/wallet/transfer-offers?user=alice",
            &[],
            offer_body.as_bytes(),
        );
        assert_eq!(retry_same.status, 200);
        assert_eq!(
            parse_resp_json(&retry_same)["offer_contract_id"].as_str(),
            Some(offer_cid.as_str())
        );

        // Conflicting tracking_id with different amount must return 409 Conflict.
        let conflict_body = json!({
            "receiver_party_id": bob_party,
            "amount": "30.0",
            "tracking_id": "trk-1",
            "description": "participant ledger transfer test"
        })
        .to_string();
        let retry_conflict = app.handle_http(
            "POST",
            "/v0/wallet/transfer-offers?user=alice",
            &[],
            conflict_body.as_bytes(),
        );
        assert_eq!(retry_conflict.status, 409);

        let accept_path = format!("/v0/wallet/transfer-offers/{offer_cid}/accept?user=bob");
        let accept_resp = app.handle_http("POST", &accept_path, &[], b"{}");
        assert_eq!(
            accept_resp.status, 200,
            "accept offer: {}",
            accept_resp.body
        );

        let tick = app.automation_tick().expect("automation_tick");
        assert!(
            tick.transfers_completed >= 1,
            "expected >= 1 transfer settled, got {tick:?}"
        );

        let status_resp =
            app.handle_http("GET", "/v0/wallet/transfer-offers/trk-1/status", &[], b"");
        assert_eq!(status_resp.status, 200);
        assert_eq!(
            parse_resp_json(&status_resp)["status"].as_str(),
            Some("completed")
        );

        let bal_bob = app.handle_http("GET", "/v0/wallet/balance?user=bob", &[], b"");
        assert_eq!(bal_bob.status, 200);
        assert_eq!(
            parse_resp_json(&bal_bob)["effective_unlocked_qty"].as_str(),
            Some("25.0000000000")
        );

        let (_, end_json_after) =
            http_json(port, "GET", "/v2/state/ledger-end", Some(&user_jwt)).unwrap();
        ledger_end_before_restart = end_json_after["offset"].as_u64().unwrap();
    }

    // Simulated restart: reopen on the same FileStore and same running participant ledger.
    let store2 = FileStore::new(&state_dir).expect("FileStore::new reopen");
    let (reopened, report2) = PersistentSplice::open_participant_ledger(
        &dars,
        SpliceBootstrapConfig::default(),
        ledger_cfg,
        store2,
        true,
        Some(&state_dir),
    )
    .expect("reopen_participant_ledger");
    assert!(!report2.bootstrapped, "reopen must NOT re-bootstrap DSO");
    assert_eq!(report2.replayed, 1, "expected splice-ledger-meta restored");

    let (_, end_after_reopen) =
        http_json(port, "GET", "/v2/state/ledger-end", Some(&user_jwt)).unwrap();
    assert_eq!(
        end_after_reopen["offset"].as_u64(),
        Some(ledger_end_before_restart),
        "reopen must not submit duplicate transactions"
    );

    let status_after =
        reopened.handle_http("GET", "/v0/wallet/transfer-offers/trk-1/status", &[], b"");
    assert_eq!(status_after.status, 200);
    assert_eq!(
        parse_resp_json(&status_after)["status"].as_str(),
        Some("completed")
    );

    let bob_after = reopened.handle_http("GET", "/v0/wallet/balance?user=bob", &[], b"");
    assert_eq!(bob_after.status, 200);
    assert_eq!(
        parse_resp_json(&bob_after)["effective_unlocked_qty"].as_str(),
        Some("25.0000000000")
    );

    // Tracking ID already completed -> retry with same parameters must be rejected (409), not re-submitted.
    let post_restart_dup = reopened.handle_http(
        "POST",
        "/v0/wallet/transfer-offers?user=alice",
        &[],
        json!({
            "receiver_party_id": bob_party,
            "amount": "25.0",
            "tracking_id": "trk-1",
            "description": "participant ledger transfer test"
        })
        .to_string()
        .as_bytes(),
    );
    assert_eq!(post_restart_dup.status, 409);
}
