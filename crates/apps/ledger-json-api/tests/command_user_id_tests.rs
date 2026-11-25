//! `RequiredClaim.MatchUserId` (Canton 3.7.2 `Authorizer.authorizeRequiredClaim`): the user id of a submission or a completion
//! stream is checked against the user of the token, and an empty one is the token's user.
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::collections::HashMap;

use ledger_json_api::{
    auth::sign_token, dispatch_request, AuthConfig, ExecutionService, HttpRequest,
};
use serde_json::{json, Value};

const SECRET: &str = "testsecret";

fn token(sub: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sign_token(
        SECRET,
        &json!({ "sub": sub, "scope": "daml_ledger_api", "exp": now + 120 }),
    )
}

fn call(svc: &ExecutionService, path: &str, body: Vec<u8>, token: &str) -> (u16, Value) {
    let mut headers = HashMap::new();
    headers.insert("authorization".to_string(), format!("Bearer {token}"));
    let resp = dispatch_request(
        svc,
        &HttpRequest {
            method: "POST".into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers,
            body,
        },
    );
    (
        resp.status,
        serde_json::from_slice(&resp.body).unwrap_or(Value::Null),
    )
}

fn post(svc: &ExecutionService, path: &str, body: Value, token: &str) -> (u16, Value) {
    call(svc, path, body.to_string().into_bytes(), token)
}

/// A ledger with the sample DAR, a party `alice`, and a user `alice_user` who acts as her.
fn ledger() -> (ExecutionService, String) {
    let svc = ExecutionService::new();
    svc.set_auth(AuthConfig::hmac(SECRET));
    let admin = token("participant_admin");
    let dar = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar"),
    )
    .unwrap();
    assert_eq!(call(&svc, "/v2/dars", dar, &admin).0, 200);
    let (s, b) = post(
        &svc,
        "/v2/parties",
        json!({"partyIdHint": "alice", "identityProviderId": ""}),
        &admin,
    );
    assert_eq!(s, 200, "{b}");
    let alice = b["partyDetails"]["party"].as_str().unwrap().to_string();
    let (s, b) = post(
        &svc,
        "/v2/users",
        json!({"user": {"id": "alice_user"}, "rights": [
            {"kind": {"CanActAs": {"value": {"party": &alice}}}}
        ]}),
        &admin,
    );
    assert_eq!(s, 200, "{b}");
    (svc, alice)
}

fn create(alice: &str, command_id: &str, user_id: Option<&str>) -> Value {
    let mut body = json!({"commands": [{"CreateCommand": {
        "templateId": "#sample-contract:AssetHolding:AssetHolding",
        "createArguments": {"bank": alice, "owner": alice, "auditor": alice, "assetSymbol": "USD", "amount": "1.0"}}}],
        "commandId": command_id, "actAs": [alice]});
    if let Some(u) = user_id {
        body["userId"] = json!(u);
    }
    body
}

fn completion_users(svc: &ExecutionService, alice: &str, command_id: &str) -> Vec<String> {
    let (s, b) = post(
        svc,
        "/v2/commands/completions",
        json!({"userId": "alice_user", "parties": [alice], "beginExclusive": 0}),
        &token("alice_user"),
    );
    assert_eq!(s, 200, "{b}");
    b.as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c.pointer("/completionResponse/Completion/value"))
        .filter(|c| c["commandId"] == command_id)
        .map(|c| c["userId"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn a_submission_for_another_user_is_refused_with_the_generic_permission_error() {
    let (svc, alice) = ledger();
    let (s, b) = post(
        &svc,
        "/v2/commands/submit-and-wait",
        create(&alice, "c-other", Some("participant_admin")),
        &token("alice_user"),
    );
    assert_eq!(s, 403, "{b}");
    assert_eq!(b["code"], "NA");
    let (s, b) = post(
        &svc,
        "/v2/commands/completions",
        json!({"userId": "participant_admin", "parties": [&alice], "beginExclusive": 0}),
        &token("alice_user"),
    );
    assert_eq!(s, 403, "the completions of another user: {b}");
}

#[test]
fn an_empty_user_id_is_the_user_of_the_token() {
    let (svc, alice) = ledger();
    let (s, b) = post(
        &svc,
        "/v2/commands/submit-and-wait",
        create(&alice, "c-own", None),
        &token("alice_user"),
    );
    assert_eq!(s, 200, "{b}");
    assert_eq!(completion_users(&svc, &alice, "c-own"), vec!["alice_user"]);
    let (s, b) = post(
        &svc,
        "/v2/commands/completions",
        json!({"parties": [&alice], "beginExclusive": 0}),
        &token("alice_user"),
    );
    assert_eq!(
        s, 200,
        "a completion stream without a user id reads the token's: {b}"
    );
    assert!(b.to_string().contains("c-own"), "{b}");
}
