//! S-API-015: the gRPC server with JWT authentication against what a Canton 3.7.2 sandbox with the `unsafe-jwt-hmac-256`
//! auth service answered (`tests/oracle/grpc-auth/expected.jsonl`, recorded by `scripts/verify-grpc-auth.sh`).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::{collections::HashMap, path::PathBuf, sync::Arc};

use ledger_grpc_api::oracle::{compare, parse_requests, replay};
use ledger_json_api::{auth::sign_token, AuthConfig, ExecutionService};
use serde_json::{json, Value};

const SECRET: &str = "testsecret";

fn dir() -> PathBuf {
    std::env::var("GRPC_AUTH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/grpc-auth")
        })
}

/// The tokens of `tokens.json` for this machine's clock (the same reading as `scripts/grpc_auth_tokens.py`).
fn tokens() -> HashMap<String, String> {
    let spec: Value =
        serde_json::from_str(&std::fs::read_to_string(dir().join("tokens.json")).unwrap()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    spec.as_object()
        .unwrap()
        .iter()
        .map(|(name, s)| {
            if let Some(raw) = s.get("raw").and_then(Value::as_str) {
                return (name.clone(), raw.to_string());
            }
            let mut claims =
                json!({ "exp": now + s.get("exp").and_then(Value::as_i64).unwrap_or(120) });
            if let Some(sub) = s.get("sub").and_then(Value::as_str) {
                claims["sub"] = json!(sub);
            }
            for rel in ["nbf", "iat"] {
                if let Some(v) = s.get(rel).and_then(Value::as_i64) {
                    claims[rel] = json!(now + v);
                }
            }
            for key in ["aud", "iss"] {
                if let Some(v) = s.get(key) {
                    claims[key] = v.clone();
                }
            }
            match s.get("scope") {
                Some(Value::Null) => {}
                Some(Value::String(scope)) => claims["scope"] = json!(scope),
                _ => claims["scope"] = json!("daml_ledger_api"),
            }
            let secret = s.get("secret").and_then(Value::as_str).unwrap_or(SECRET);
            (name.clone(), sign_token(secret, &claims))
        })
        .collect()
}

#[test]
fn grpc_auth_responses_agree_with_the_recorded_canton_sandbox() {
    let tsv = std::fs::read_to_string(dir().join("requests.tsv")).expect("requests.tsv");
    let expected: Vec<Value> = std::fs::read_to_string(dir().join("expected.jsonl"))
        .expect("expected.jsonl")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let tokens = tokens();
    let got = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ledger = Arc::new(ExecutionService::new());
        // a corpus may configure the auth service the way its sandbox was configured (config.json: audience, leeway)
        let mut cfg = AuthConfig::hmac(SECRET);
        if let Ok(text) = std::fs::read_to_string(dir().join("config.json")) {
            let c: Value = serde_json::from_str(&text).unwrap();
            if let Some(a) = c["audience"].as_str() {
                cfg = cfg.with_audience(a);
            }
            if let Some(l) = c["leeway"].as_i64() {
                cfg = cfg.with_leeway(l);
            }
        }
        ledger.set_auth(cfg);
        let server = tokio::spawn(ledger_grpc_api::server::serve_listener(ledger, listener));
        let out = replay(&addr.to_string(), &tsv, &tokens).await;
        server.abort();
        out
    });
    let specs = parse_requests(&tsv);
    let mut problems = Vec::new();
    let mut agreed = 0;
    for (spec, got) in specs.iter().zip(&got) {
        let Some(want) = expected.iter().find(|e| e["id"] == spec.id.as_str()) else {
            problems.push(format!("{}: not recorded", spec.id));
            continue;
        };
        let diffs = compare(want, got, &spec.exact);
        if diffs.is_empty() {
            agreed += 1;
        } else {
            problems.push(format!(
                "  {} {} ({}): {}",
                spec.id,
                spec.path,
                spec.token.as_deref().unwrap_or("-"),
                diffs.join("; ")
            ));
        }
    }
    // [CANTON-NOTE: INVARIANT] AT-U01: the two refused submissions of the read-only user (a060 for its own party, a061 for
    // another) leave no trace: the ledger end read just before (a059e) and just after (a061e) is the same offset, on the node
    // (the recording) and in Rust. A refused command must not advance the ledger.
    let offset = |rows: &[Value], id: &str| -> Option<i64> {
        rows.iter()
            .find(|r| r["id"] == id)
            .and_then(|r| r["body"]["offset"].as_i64())
    };
    // (only the base corpus has these rows)
    let has_rows = expected.iter().any(|r| r["id"] == "a059e");
    let (n0, n1) = (offset(&expected, "a059e"), offset(&expected, "a061e"));
    if has_rows && (n0.is_none() || n0 != n1) {
        problems.push(format!(
            "the node's ledger end moved across the refused submissions: {n0:?} -> {n1:?}"
        ));
    }
    let (r0, r1) = (offset(&got, "a059e"), offset(&got, "a061e"));
    if has_rows && (r0.is_none() || r0 != r1) {
        problems.push(format!(
            "Rust's ledger end moved across the refused submissions: {r0:?} -> {r1:?}"
        ));
    }
    println!(
        "grpc-auth: {agreed} of {} responses agree with the recorded Canton sandbox",
        specs.len()
    );
    assert!(
        problems.is_empty(),
        "MISMATCH against the recorded Canton responses:\n{}",
        problems.join("\n")
    );
}
