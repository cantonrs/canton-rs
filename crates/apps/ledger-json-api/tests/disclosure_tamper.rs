//! AT-C06 (Rust side): a disclosed contract whose blob was changed in ANY single position is refused, and the refusal leaves
//! the ledger as it was. The node's answers for tampering at nine positions of ITS blob are recorded in
//! tests/oracle/disclosure/jvm-tamper.tsv (the classes: contract id mismatch, undecodable payload, failed authentication);
//! this ledger's blob has another encoding, so the check here is the property, not the position-by-position codes.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

use ledger_json_api::{start_test_server, ExecutionService};
use serde_json::{json, Value};

fn call(port: u16, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let ctype = if path == "/v2/dars" {
        "application/octet-stream"
    } else {
        "application/json"
    };
    let head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |i| i + 4);
    let status: u16 = String::from_utf8_lossy(&raw[..at])
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (
        status,
        serde_json::from_slice(&raw[at..]).unwrap_or(Value::Null),
    )
}

fn post(port: u16, path: &str, v: Value) -> (u16, Value) {
    call(port, "POST", path, v.to_string().as_bytes())
}

#[test]
fn a_blob_changed_in_any_single_position_is_refused_and_leaves_the_ledger_unchanged() {
    let (port, stop) = start_test_server(Arc::new(ExecutionService::new()));
    let dar = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/disclosure/disc-1.0.0.dar");
    assert_eq!(
        call(port, "POST", "/v2/dars", &std::fs::read(dar).unwrap()).0,
        200
    );
    let party = |hint: &str| {
        post(
            port,
            "/v2/parties",
            json!({"partyIdHint": hint, "identityProviderId": ""}),
        )
        .1["partyDetails"]["party"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (own, tak) = (party("own"), party("tak"));
    let fmt = json!({"eventFormat": {"filtersByParty": {own.clone(): {"cumulative": [{"identifierFilter": {"WildcardFilter": {"value": {"includeCreatedEventBlob": true}}}}]}}, "verbose": true},
                     "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"});
    let (s, b) = post(
        port,
        "/v2/commands/submit-and-wait-for-transaction",
        json!({"commands": {"commands": [{"CreateCommand": {"templateId": "#disc:Main:Offer", "createArguments": {"owner": own, "price": "3"}}}],
                            "commandId": "mk", "actAs": [own], "userId": "participant_admin"}, "transactionFormat": fmt}),
    );
    assert_eq!(s, 200, "{b}");
    let ev = &b["transaction"]["events"][0]["CreatedEvent"];
    let (cid, blob, tpl) = (
        ev["contractId"].as_str().unwrap().to_string(),
        ev["createdEventBlob"].as_str().unwrap().to_string(),
        ev["templateId"].as_str().unwrap().to_string(),
    );
    let sync = b["transaction"]["synchronizerId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!blob.is_empty());
    let take = |blob: &str, cmd: &str| {
        post(
            port,
            "/v2/commands/submit-and-wait-for-transaction",
            json!({"commands": {"commands": [{"ExerciseCommand": {"templateId": "#disc:Main:Offer", "contractId": cid, "choice": "Take", "choiceArgument": {"taker": tak}}}],
                                "commandId": cmd, "actAs": [tak], "userId": "participant_admin",
                                "disclosedContracts": [{"templateId": tpl, "contractId": cid, "createdEventBlob": blob, "synchronizerId": sync}]}}),
        )
    };
    // the control: the untouched blob is accepted by a command that has not run yet is NOT done here (it would consume the
    // contract); instead every tampered copy must fail, and only afterwards the genuine one must still work
    let chars: Vec<char> = blob.chars().collect();
    let mut classes = std::collections::BTreeSet::new();
    for (i, c) in chars.iter().enumerate() {
        let mut t = chars.clone();
        t[i] = if *c != 'a' { 'a' } else { 'b' };
        let tampered: String = t.into_iter().collect();
        let (status, body) = take(&tampered, &format!("t{i}"));
        assert!(
            status == 400 || status == 404,
            "position {i}: a tampered blob was accepted ({status})"
        );
        classes.insert(body["code"].as_str().unwrap_or("?").to_string());
    }
    // the refusals touched nothing: the genuine blob still works, once
    let (ok, _) = take(&blob, "genuine");
    assert_eq!(ok, 200, "the contract was still there for the genuine blob");
    let (again, body) = take(&blob, "genuine-again");
    assert_eq!(again, 404, "{body}");
    assert_eq!(body["code"], "LOCAL_VERDICT_INACTIVE_CONTRACTS");
    // every refusal was one of the node's classes (decode/mismatch error or failed authentication)
    for c in &classes {
        assert!(
            c == "INVALID_ARGUMENT" || c == "INTERPRETATION_UPGRADE_ERROR_AUTHENTICATION_FAILED",
            "unexpected class {c}"
        );
    }
    assert!(
        classes.contains("INTERPRETATION_UPGRADE_ERROR_AUTHENTICATION_FAILED"),
        "a content change under the same id must fail authentication: {classes:?}"
    );
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
}
