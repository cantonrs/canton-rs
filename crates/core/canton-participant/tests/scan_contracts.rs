//! G8 (S-SPL-009): the contract endpoints of the Rust scan answer as the official Splice 0.10.1 scan app did, from the update history alone
//! (`tests/oracle/splice-scan/updates.json`, recorded with the answers in `answers.json` by `scripts/splice-scan-state.py`). The only input that
//! is not in the history is each contract's salt, which is read out of the official blobs.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use canton_participant::scan_api::UpdateHistory;
use lf_eval::World;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn varint(b: &mut &[u8]) -> u64 {
    let (mut v, mut shift) = (0u64, 0);
    loop {
        let c = b[0];
        *b = &b[1..];
        v |= u64::from(c & 0x7f) << shift;
        shift += 7;
        if c < 0x80 {
            return v;
        }
    }
}

/// The length-delimited field `number` of a message.
fn field(mut b: &[u8], number: u64) -> Vec<u8> {
    while !b.is_empty() {
        let key = varint(&mut b);
        match key & 7 {
            0 => {
                varint(&mut b);
            }
            1 => b = &b[8..],
            2 => {
                let len = varint(&mut b) as usize;
                if key >> 3 == number {
                    return b[..len].to_vec();
                }
                b = &b[len..];
            }
            other => panic!("wire type {other}"),
        }
    }
    Vec::new()
}

fn unbase64(text: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.bytes().filter(|c| *c != b'=') {
        acc = acc << 6 | A.iter().position(|a| *a == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// Every contract with a blob anywhere in an answer: its contract id and the salt inside the blob.
fn salts(json: &Value, into: &mut HashMap<String, Vec<u8>>) {
    match json {
        Value::Object(o) => {
            if let (Some(id), Some(blob)) = (o.get("contract_id"), o.get("created_event_blob")) {
                let versioned = unbase64(blob.as_str().unwrap());
                let instance = field(&versioned, 2);
                into.insert(id.as_str().unwrap().into(), field(&instance, 8));
            }
            o.values().for_each(|v| salts(v, into));
        }
        Value::Array(a) => a.iter().for_each(|v| salts(v, into)),
        _ => {}
    }
}

#[test]
fn the_contract_endpoints_answer_as_the_official_scan_did() {
    let dir = root().join("tests/oracle/splice-scan");
    let updates: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("updates.json")).unwrap()).unwrap();
    let answers: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("answers.json")).unwrap()).unwrap();
    let mut auth = HashMap::new();
    salts(&answers, &mut auth);
    let worlds = [
        "splice-amulet-0.1.25.dar",
        "splice-dso-governance-0.1.31.dar",
        "splice-validator-lifecycle-0.1.7.dar",
        "splice-wallet-0.1.26.dar",
    ]
    .iter()
    .map(|d| World::open(&root().join("tests/oracle/splice-dars").join(d)).unwrap())
    .collect();
    let scan = UpdateHistory::new(updates["transactions"].as_array().unwrap().clone())
        .with_contracts(worlds, auth)
        .unwrap();
    let served = [
        "dso-party-id",
        "amulet-rules",
        "ans-rules",
        "external-party-amulet-rules",
        "amulet-price-votes",
        "unclaimed-development-fund-coupons",
        "open-and-issuing-mining-rounds",
        "closed-rounds",
        "featured-apps",
        "dso",
    ];
    for name in served {
        let case = &answers[name];
        let body = case["body"]
            .as_object()
            .map_or(String::new(), |_| case["body"].to_string());
        let got = scan.handle(
            case["method"].as_str().unwrap(),
            &format!("/api/scan{}", case["path"].as_str().unwrap()),
            &body,
        );
        assert_eq!(got.status, 200, "{name}: {}", got.body);
        let got: Value = serde_json::from_str(&got.body).unwrap();
        if got != case["answer"] {
            panic!("{name}: {}", first_difference(&got, &case["answer"], "$"));
        }
    }
    // a client that caches the active rules contract is sent none
    let id = answers["amulet-rules"]["answer"]["amulet_rules_update"]["contract"]["contract_id"]
        .as_str()
        .unwrap();
    let cached = scan.handle(
        "POST",
        "/api/scan/v0/amulet-rules",
        &serde_json::json!({"cached_amulet_rules_contract_id": id}).to_string(),
    );
    let cached: Value = serde_json::from_str(&cached.body).unwrap();
    assert!(
        cached["amulet_rules_update"].get("contract").is_none(),
        "{cached}"
    );
    assert_eq!(
        cached["amulet_rules_update"]["domain_id"],
        answers["amulet-rules"]["answer"]["amulet_rules_update"]["domain_id"]
    );
}

/// Where two JSON values first differ (a long value is cut).
fn first_difference(got: &Value, want: &Value, path: &str) -> String {
    match (got, want) {
        (Value::Object(a), Value::Object(b)) => {
            for k in a.keys().chain(b.keys()) {
                let (x, y) = (
                    a.get(k).unwrap_or(&Value::Null),
                    b.get(k).unwrap_or(&Value::Null),
                );
                if x != y {
                    return first_difference(x, y, &format!("{path}.{k}"));
                }
            }
            "equal".into()
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                if x != y {
                    return first_difference(x, y, &format!("{path}[{i}]"));
                }
            }
            "equal".into()
        }
        _ => format!(
            "{path}: got {:.120} want {:.120}",
            got.to_string(),
            want.to_string()
        ),
    }
}

#[test]
fn a_history_without_the_ans_rules_has_no_ans_rules() {
    let dir = root().join("tests/oracle/splice-scan");
    let updates: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("updates.json")).unwrap()).unwrap();
    let kept: Vec<Value> = updates["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| !u.to_string().contains("Splice.Ans:AnsRules"))
        .cloned()
        .collect();
    let scan = UpdateHistory::new(kept)
        .with_contracts(Vec::new(), HashMap::new())
        .unwrap();
    assert_eq!(
        scan.handle("POST", "/api/scan/v0/ans-rules", "{}").status,
        404
    );
    // a contract whose salt is unknown is not answered with a blob that would be wrong
    let all = UpdateHistory::new(updates["transactions"].as_array().unwrap().clone())
        .with_contracts(Vec::new(), HashMap::new())
        .unwrap();
    assert_eq!(
        all.handle("POST", "/api/scan/v0/amulet-rules", "{}").status,
        500
    );
}

#[test]
fn a_client_that_caches_rounds_is_sent_only_the_others() {
    let dir = root().join("tests/oracle/splice-scan");
    let updates: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("updates.json")).unwrap()).unwrap();
    let answers: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("answers.json")).unwrap()).unwrap();
    let mut auth = HashMap::new();
    salts(&answers, &mut auth);
    let worlds = [
        "splice-amulet-0.1.25.dar",
        "splice-dso-governance-0.1.31.dar",
    ]
    .iter()
    .map(|d| World::open(&root().join("tests/oracle/splice-dars").join(d)).unwrap())
    .collect();
    let scan = UpdateHistory::new(updates["transactions"].as_array().unwrap().clone())
        .with_contracts(worlds, auth)
        .unwrap();
    let official = &answers["open-and-issuing-mining-rounds"]["answer"];
    let cached: Vec<String> = official["open_mining_rounds"]
        .as_object()
        .unwrap()
        .keys()
        .take(2)
        .cloned()
        .collect();
    let body = serde_json::json!({"cached_open_mining_round_contract_ids": cached, "cached_issuing_round_contract_ids": []});
    let got = scan.handle(
        "POST",
        "/api/scan/v0/open-and-issuing-mining-rounds",
        &body.to_string(),
    );
    let got: Value = serde_json::from_str(&got.body).unwrap();
    for (id, round) in got["open_mining_rounds"].as_object().unwrap() {
        assert_eq!(round.get("contract").is_none(), cached.contains(id), "{id}");
        assert!(round.get("domain_id").is_some());
    }
    assert_eq!(
        got["open_mining_rounds"].as_object().unwrap().len(),
        official["open_mining_rounds"].as_object().unwrap().len()
    );
}
