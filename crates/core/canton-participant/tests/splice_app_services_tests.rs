//! End-to-end integration tests for the real DAR-backed Splice 0.10.1 App Services
//! (`SV`, `Validator`, `Wallet`, `Automation`, and `Scan` integration) using the unmodified
//! official DARs in `tests/oracle/splice-dars`.

use std::path::PathBuf;
use std::sync::Mutex;

use canton_participant::{handle_splice_http, SpliceAppRuntime, SpliceBootstrapConfig};
use serde_json::{json, Value as Json};

fn splice_dar_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("tests/oracle/splice-dars")
}

fn http_json(
    rt: &Mutex<SpliceAppRuntime>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Json>,
) -> (u16, Json) {
    let hdrs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    let body_bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    let resp = handle_splice_http(rt, method, path, &hdrs, &body_bytes);
    let parsed: Json =
        serde_json::from_str(&resp.body).unwrap_or_else(|_| json!({ "raw": resp.body }));
    (resp.status, parsed)
}

#[test]
fn sv_bootstrap_and_validator_onboarding_with_scan_blobs() {
    let rt = Mutex::new(
        SpliceAppRuntime::from_dar_dir(&splice_dar_dir(), SpliceBootstrapConfig::default())
            .expect("load official Splice DARs"),
    );

    let (st, boot) = http_json(&rt, "POST", "/api/sv/v0/admin/bootstrap", &[], None);
    assert_eq!(st, 200, "bootstrap: {boot}");
    assert_eq!(boot["already_bootstrapped"], json!(false));

    // Re-bootstrapping is idempotent.
    let (st, boot2) = http_json(&rt, "POST", "/api/sv/v0/admin/bootstrap", &[], None);
    assert_eq!(st, 200);
    assert_eq!(boot2["already_bootstrapped"], json!(true));

    // Prepare secret and reject bad secret attempts.
    let (st, prep) = http_json(
        &rt,
        "POST",
        "/api/sv/v0/admin/validator/onboarding/prepare",
        &[],
        Some(json!({ "expires_in": 3600, "party_hint": "val-edge" })),
    );
    assert_eq!(st, 200, "prepare: {prep}");
    let secret = prep["secret"].as_str().expect("secret string").to_string();
    let val_party =
        "val-edge::1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let (bad_st, _) = http_json(
        &rt,
        "POST",
        "/v0/onboard/validator",
        &[],
        Some(json!({
            "party_id": val_party,
            "secret": "wrong-secret",
        })),
    );
    assert_eq!(bad_st, 401);

    // Valid onboarding issues ValidatorLicense.
    let (st, onboard) = http_json(
        &rt,
        "POST",
        "/v0/onboard/validator",
        &[],
        Some(json!({
            "party_id": val_party,
            "secret": secret,
            "version": "0.10.1",
            "contact_point": "ops@edge.example",
        })),
    );
    assert_eq!(st, 200, "onboard: {onboard}");
    let license_cid = onboard["validator_license_contract_id"]
        .as_str()
        .expect("validator license cid");
    assert!(license_cid.starts_with("00"));

    // One-time secret cannot be reused.
    let (reuse_st, _) = http_json(
        &rt,
        "POST",
        "/v0/onboard/validator",
        &[],
        Some(json!({ "party_id": val_party, "secret": secret })),
    );
    assert_eq!(reuse_st, 401);

    // Scan endpoints expose DSO, AmuletRules, and ValidatorLicenses with non-empty V12 blobs.
    let (st, dso_info) = http_json(&rt, "GET", "/api/scan/v0/dso", &[], None);
    assert_eq!(st, 200, "scan /v0/dso: {dso_info}");
    assert!(
        !dso_info["dso_rules"]["contract"]["created_event_blob"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "DsoRules blob must be present"
    );
    assert!(
        !dso_info["amulet_rules"]["contract"]["created_event_blob"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "AmuletRules blob must be present"
    );

    let (st, ar) = http_json(
        &rt,
        "POST",
        "/api/scan/v0/amulet-rules",
        &[],
        Some(json!({})),
    );
    assert_eq!(st, 200, "amulet-rules: {ar}");
    assert!(ar["amulet_rules_update"]["contract"]["created_event_blob"].is_string());

    let (st, licenses) = http_json(
        &rt,
        "GET",
        "/api/scan/v0/admin/validator/licenses?limit=10",
        &[],
        None,
    );
    assert_eq!(st, 200, "licenses: {licenses}");
    let list = licenses["validator_licenses"]
        .as_array()
        .expect("licenses array");
    assert_eq!(list.len(), 2, "primary validator + partner validator");
    for lic in list {
        assert!(!lic["created_event_blob"]
            .as_str()
            .unwrap_or_default()
            .is_empty());
    }
}

#[test]
fn validator_user_registration_liveness_and_transfer_preapproval() {
    let rt = Mutex::new(
        SpliceAppRuntime::from_dar_dir(&splice_dar_dir(), SpliceBootstrapConfig::default())
            .expect("load DARs"),
    );
    let (st, _) = http_json(&rt, "POST", "/v0/admin/bootstrap", &[], None);
    assert_eq!(st, 200);

    // Register Alice and Bob.
    let (st, alice_reg) = http_json(
        &rt,
        "POST",
        "/api/validator/v0/admin/users",
        &[],
        Some(json!({ "name": "alice" })),
    );
    assert_eq!(st, 200, "register alice: {alice_reg}");
    let alice_party = alice_reg["party_id"]
        .as_str()
        .expect("alice party")
        .to_string();

    let (st, bob_reg) = http_json(
        &rt,
        "POST",
        "/api/validator/v0/register",
        &[("x-wallet-user", "bob")],
        Some(json!({})),
    );
    assert_eq!(st, 200, "register bob: {bob_reg}");
    let bob_party = bob_reg["party_id"].as_str().expect("bob party").to_string();

    let (st, users) = http_json(&rt, "GET", "/v0/admin/users", &[], None);
    assert_eq!(st, 200);
    assert_eq!(users["usernames"], json!(["alice", "bob"]));

    let (st, status) = http_json(
        &rt,
        "GET",
        "/v0/wallet/user-status",
        &[("x-wallet-user", "alice")],
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(status["user_onboarded"], json!(true));
    assert_eq!(status["user_wallet_installed"], json!(true));

    // Record validator liveness activity through real DAR choice.
    let (st, live) = http_json(&rt, "POST", "/v0/admin/liveness", &[], Some(json!({})));
    assert_eq!(st, 200, "liveness: {live}");
    assert!(live["validator_license_contract_id"].is_string());

    // Create TransferPreapproval for Bob via AmuletRules_CreateTransferPreapproval.
    let (st, pre) = http_json(
        &rt,
        "POST",
        "/v0/admin/transfer-preapprovals",
        &[],
        Some(json!({
            "receiver_party_id": bob_party,
            "expires_in_micros": 86_400_000_000i64,
        })),
    );
    assert_eq!(st, 200, "create preapproval: {pre}");
    assert!(pre["transfer_preapproval_contract_id"].is_string());

    let (st, lookup) = http_json(
        &rt,
        "GET",
        &format!("/v0/admin/transfer-preapprovals/by-party/{bob_party}"),
        &[],
        None,
    );
    assert_eq!(st, 200, "lookup preapproval: {lookup}");
    assert_eq!(
        lookup["transfer_preapproval"]["payload"]["receiver"],
        json!(bob_party)
    );

    // Cancel TransferPreapproval and verify 404 afterward.
    let (st, _) = http_json(
        &rt,
        "DELETE",
        &format!("/v0/admin/transfer-preapprovals/by-party/{bob_party}"),
        &[],
        None,
    );
    assert_eq!(st, 200);
    let (st, _) = http_json(
        &rt,
        "GET",
        &format!("/v0/admin/transfer-preapprovals/by-party/{bob_party}"),
        &[],
        None,
    );
    assert_eq!(st, 404);

    // Offboard Alice and verify external party balance query stays valid.
    let (st, _) = http_json(
        &rt,
        "POST",
        "/v0/admin/users/offboard?username=alice",
        &[],
        None,
    );
    assert_eq!(st, 200);
    let (st, users_after) = http_json(&rt, "GET", "/v0/admin/users", &[], None);
    assert_eq!(st, 200);
    assert_eq!(users_after["usernames"], json!(["bob"]));

    let (st, ext_bal) = http_json(
        &rt,
        "GET",
        &format!("/v0/admin/external-party/balance?party_id={alice_party}"),
        &[],
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(ext_bal["total_available_coin"], json!("0.0000000000"));
}

#[test]
fn wallet_tap_transfer_offer_automation_and_idempotency() {
    let rt = Mutex::new(
        SpliceAppRuntime::from_dar_dir(&splice_dar_dir(), SpliceBootstrapConfig::default())
            .expect("load DARs"),
    );
    assert_eq!(
        http_json(&rt, "POST", "/v0/admin/bootstrap", &[], None).0,
        200
    );
    let (_, a_reg) = http_json(
        &rt,
        "POST",
        "/v0/admin/users",
        &[],
        Some(json!({ "name": "alice" })),
    );
    let (_, b_reg) = http_json(
        &rt,
        "POST",
        "/v0/admin/users",
        &[],
        Some(json!({ "name": "bob" })),
    );
    let alice = a_reg["party_id"].as_str().unwrap().to_string();
    let bob = b_reg["party_id"].as_str().unwrap().to_string();

    // Tap Amulets for Alice.
    let (st, tap) = http_json(
        &rt,
        "POST",
        "/api/wallet/v0/wallet/tap",
        &[("x-wallet-user", "alice")],
        Some(json!({ "amount": "500.0" })),
    );
    assert_eq!(st, 200, "tap: {tap}");

    let (st, bal) = http_json(
        &rt,
        "GET",
        "/v0/wallet/balance",
        &[("x-wallet-user", "alice")],
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(bal["effective_unlocked_qty"], json!("500.0000000000"));

    // Create TransferOffer with tracking_id + test idempotency & 409 conflict.
    let expires_at = rt.lock().unwrap().now_micros() + 3_600_000_000;
    let create_req = json!({
        "receiver_party_id": bob,
        "amount": "125.5",
        "description": "consulting invoice",
        "expires_at": expires_at,
        "tracking_id": "xfer-idem-1",
    });
    let (st, offer1) = http_json(
        &rt,
        "POST",
        "/v0/wallet/transfer-offers",
        &[("x-wallet-user", "alice")],
        Some(create_req.clone()),
    );
    assert_eq!(st, 200, "create offer: {offer1}");
    let offer_cid = offer1["offer_contract_id"].as_str().unwrap().to_string();

    // Identical retry with same tracking_id returns 200 with same contract_id.
    let (st_retry, offer_retry) = http_json(
        &rt,
        "POST",
        "/v0/wallet/transfer-offers",
        &[("x-wallet-user", "alice")],
        Some(create_req),
    );
    assert_eq!(st_retry, 200);
    assert_eq!(offer_retry["offer_contract_id"], json!(offer_cid));

    // Conflicting parameters with same tracking_id return 409 Conflict.
    let (st_conflict, _) = http_json(
        &rt,
        "POST",
        "/v0/wallet/transfer-offers",
        &[("x-wallet-user", "alice")],
        Some(json!({
            "receiver_party_id": bob,
            "amount": "999.0",
            "description": "consulting invoice",
            "expires_at": expires_at,
            "tracking_id": "xfer-idem-1",
        })),
    );
    assert_eq!(st_conflict, 409);

    // Bob lists pending offers and accepts.
    let (st, offers) = http_json(
        &rt,
        "GET",
        "/v0/wallet/transfer-offers",
        &[("x-wallet-user", "bob")],
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(offers["offers"].as_array().unwrap().len(), 1);

    let (st, acc) = http_json(
        &rt,
        "POST",
        &format!("/v0/wallet/transfer-offers/{offer_cid}/accept"),
        &[("x-wallet-user", "bob")],
        None,
    );
    assert_eq!(st, 200, "accept: {acc}");

    let (st, st_acc) = http_json(
        &rt,
        "GET",
        "/v0/wallet/transfer-offers/xfer-idem-1/status",
        &[],
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(st_acc["status"], json!("accepted"));

    // Run Automation tick -> settles AcceptedTransferOffer via WalletAppInstall_ExecuteBatch.
    let (st, tick1) = http_json(&rt, "POST", "/v0/admin/automation/tick", &[], None);
    assert_eq!(st, 200, "automation tick1: {tick1}");
    assert_eq!(tick1["transfers_completed"], json!(1));
    assert!(tick1["errors"].as_array().unwrap().is_empty());

    let (st, st_done) = http_json(
        &rt,
        "GET",
        "/v0/wallet/transfer-offers/xfer-idem-1/status",
        &[],
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(st_done["status"], json!("completed"));
    assert!(st_done["transaction_id"].is_string());

    // Check updated balances for Alice and Bob.
    let (_, alice_bal) = http_json(
        &rt,
        "GET",
        "/v0/wallet/balance",
        &[("x-wallet-user", "alice")],
        None,
    );
    let (_, bob_bal) = http_json(
        &rt,
        "GET",
        "/v0/wallet/balance",
        &[("x-wallet-user", "bob")],
        None,
    );
    assert_eq!(alice_bal["effective_unlocked_qty"], json!("374.5000000000"));
    assert_eq!(bob_bal["effective_unlocked_qty"], json!("125.5000000000"));

    // Transaction log shows tap & transfer for Alice.
    let (st, txs) = http_json(
        &rt,
        "POST",
        "/v0/wallet/transactions",
        &[("x-wallet-user", "alice")],
        Some(json!({ "page_size": 20 })),
    );
    assert_eq!(st, 200);
    assert!(!txs["items"].as_array().unwrap().is_empty());

    // Re-running automation immediately is a clean no-op for transfers.
    let (st, tick2) = http_json(&rt, "POST", "/v0/admin/automation/tick", &[], None);
    assert_eq!(st, 200);
    assert_eq!(tick2["transfers_completed"], json!(0));

    // Expire an unaccepted offer after time advance.
    let short_expiry = rt.lock().unwrap().now_micros() + 10_000_000;
    let (st, exp_offer) = http_json(
        &rt,
        "POST",
        "/v0/wallet/transfer-offers",
        &[("x-wallet-user", "alice")],
        Some(json!({
            "receiver_party_id": bob,
            "amount": "10.0",
            "description": "will expire",
            "expires_at": short_expiry,
            "tracking_id": "xfer-expire-1",
        })),
    );
    assert_eq!(st, 200, "exp_offer: {exp_offer}");
    assert_eq!(
        http_json(
            &rt,
            "POST",
            "/v0/admin/time/advance",
            &[],
            Some(json!({ "microseconds": 20_000_000, "tick": true })),
        )
        .0,
        200
    );
    let (st, exp_status) = http_json(
        &rt,
        "GET",
        "/v0/wallet/transfer-offers/xfer-expire-1/status",
        &[],
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(exp_status["status"], json!("failed"));
    assert_eq!(exp_status["failure_kind"], json!("expired"));
    let _ = alice;
}

#[test]
fn traffic_purchase_governance_vote_and_round_advancement() {
    let rt = Mutex::new(
        SpliceAppRuntime::from_dar_dir(&splice_dar_dir(), SpliceBootstrapConfig::default())
            .expect("load DARs"),
    );
    assert_eq!(
        http_json(&rt, "POST", "/v0/admin/bootstrap", &[], None).0,
        200
    );
    let (_, a_reg) = http_json(
        &rt,
        "POST",
        "/v0/admin/users",
        &[],
        Some(json!({ "name": "alice" })),
    );
    let alice = a_reg["party_id"].as_str().unwrap().to_string();
    let validator_party = rt.lock().unwrap().config().validator_party.clone();

    // Tap Amulets for Alice so she can buy synchronizer traffic.
    assert_eq!(
        http_json(
            &rt,
            "POST",
            "/v0/wallet/tap",
            &[("x-wallet-user", "alice")],
            Some(json!({ "amount": "5000.0" })),
        )
        .0,
        200
    );

    let expires_at = rt.lock().unwrap().now_micros() + 3_600_000_000;
    let (st, traffic_req) = http_json(
        &rt,
        "POST",
        "/v0/wallet/buy-traffic-requests",
        &[("x-wallet-user", "alice")],
        Some(json!({
            "receiving_validator_party_id": validator_party,
            "traffic_amount": 1_200_000,
            "tracking_id": "traffic-1",
            "expires_at": expires_at,
        })),
    );
    assert_eq!(st, 200, "create buy traffic: {traffic_req}");

    let (st, tick1) = http_json(&rt, "POST", "/v0/admin/automation/tick", &[], None);
    assert_eq!(st, 200, "tick1: {tick1}");
    assert_eq!(tick1["traffic_requests_completed"], json!(1));
    assert!(tick1["errors"].as_array().unwrap().is_empty(), "{tick1}");

    let (st, traffic_status) = http_json(
        &rt,
        "POST",
        "/v0/wallet/buy-traffic-requests/traffic-1/status",
        &[],
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(traffic_status["status"], json!("completed"));
    assert!(traffic_status["purchased_traffic_contract_id"].is_string());

    // SV governance vote request -> creates FeaturedAppRight on CloseVoteRequest (via automation).
    let (st, vr) = http_json(
        &rt,
        "POST",
        "/api/sv/v0/admin/sv/voterequest/create",
        &[],
        Some(json!({
            "action": {
                "tag": "ARC_DsoRules",
                "value": {
                    "dsoAction": {
                        "tag": "SRARC_GrantFeaturedAppRight",
                        "value": { "provider": alice }
                    }
                }
            },
            "url": "https://governance.example/featured-alice",
            "description": "Grant featured app right to Alice",
        })),
    );
    assert_eq!(st, 200, "voterequest: {vr}");
    let req_cid = vr["vote_request_contract_id"].as_str().unwrap().to_string();

    let (st, list_vr) = http_json(&rt, "GET", "/v0/admin/sv/voterequests", &[], None);
    assert_eq!(st, 200);
    assert_eq!(
        list_vr["dso_rules_vote_requests"].as_array().unwrap().len(),
        1
    );

    // Advance time past tickDuration and run automation: collects SV coupon, advances round, closes vote.
    let (st, adv) = http_json(
        &rt,
        "POST",
        "/v0/admin/time/advance",
        &[],
        Some(json!({ "microseconds": 650_000_000, "tick": true })),
    );
    assert_eq!(st, 200, "advance + tick: {adv}");
    let rep = &adv["tick_report"];
    assert_eq!(rep["sv_reward_coupons_collected"], json!(1), "{rep}");
    assert_eq!(rep["mining_rounds_advanced"], json!(1), "{rep}");
    assert_eq!(rep["vote_requests_closed"], json!(1), "{rep}");

    // Confirm FeaturedAppRight was granted on-ledger and closed vote outcome is queryable.
    let (st, alice_status) = http_json(
        &rt,
        "GET",
        "/v0/wallet/user-status",
        &[("x-wallet-user", "alice")],
        None,
    );
    assert_eq!(st, 200);
    assert_eq!(alice_status["has_featured_app_right"], json!(true));

    let (st, vr_outcome) = http_json(
        &rt,
        "GET",
        &format!("/v0/admin/sv/voterequest/{req_cid}"),
        &[],
        None,
    );
    assert_eq!(st, 200, "vr_outcome: {vr_outcome}");

    // Scan `/v2/updates` & `/v0/state/acs` reflect all committed transactions & active contracts.
    let (st, updates) = http_json(
        &rt,
        "POST",
        "/api/scan/v2/updates",
        &[],
        Some(json!({ "page_size": 100 })),
    );
    assert_eq!(st, 200);
    assert!(updates["transactions"].as_array().unwrap().len() >= 8);

    let (st, acs) = http_json(
        &rt,
        "POST",
        "/api/scan/v0/state/acs",
        &[],
        Some(json!({
            "migration_id": 0,
            "record_time": "2099-01-01T00:00:00Z",
            "record_time_match": "at_or_before",
            "page_size": 200,
        })),
    );
    assert_eq!(st, 200, "scan acs: {acs}");
    let contracts = acs["created_events"].as_array().expect("created_events");
    assert!(
        contracts.iter().any(|c| c["template_id"]
            .as_str()
            .unwrap_or_default()
            .ends_with(":Splice.DecentralizedSynchronizer:MemberTraffic")),
        "MemberTraffic contract must exist in Scan ACS"
    );
    assert!(
        contracts.iter().any(|c| c["template_id"]
            .as_str()
            .unwrap_or_default()
            .ends_with(":Splice.Round:SummarizingMiningRound")),
        "Round advancement must produce SummarizingMiningRound in Scan ACS"
    );
}
