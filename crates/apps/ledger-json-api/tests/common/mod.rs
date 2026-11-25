//! The scripted ledger history and the observations shared by the request-log store tests (file and PostgreSQL backends).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![allow(
    dead_code,
    reason = "helper or sentinel retained for protocol/test binary compatibility"
)]
use std::collections::HashMap;
use std::path::Path;

use ledger_json_api::http::{dispatch_request, HttpRequest};
use ledger_json_api::ExecutionService;
use serde_json::{json, Value};

pub fn dar_bytes() -> Vec<u8> {
    let p =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar");
    std::fs::read(p).expect("sample-contract.dar")
}

pub fn call(svc: &ExecutionService, method: &str, path: &str, body: Vec<u8>) -> (u16, Value) {
    let req = HttpRequest {
        method: method.into(),
        path: path.into(),
        query_params: HashMap::new(),
        headers: HashMap::new(),
        body,
    };
    let resp = dispatch_request(svc, &req);
    let json = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
    (resp.status, json)
}

pub fn post(svc: &ExecutionService, path: &str, body: Value) -> (u16, Value) {
    call(svc, "POST", path, serde_json::to_vec(&body).unwrap())
}

pub fn party(svc: &ExecutionService, hint: &str) -> String {
    let (_, v) = call(svc, "GET", "/v2/parties", vec![]);
    v["partyDetails"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["party"].as_str())
        .find(|p| p.starts_with(&format!("{hint}::")))
        .unwrap_or_else(|| panic!("party {hint} is not allocated: {v}"))
        .to_string()
}

pub fn create(
    svc: &ExecutionService,
    id: &str,
    bank: &str,
    owner: &str,
    amount: &str,
) -> (u16, Value) {
    post(
        svc,
        "/v2/commands/submit-and-wait",
        json!({"commands":[{"CreateCommand":{
            "templateId":"#sample-contract:AssetHolding:AssetHolding",
            "createArguments":{"bank":bank,"owner":owner,"auditor":bank,"assetSymbol":"USD","amount":amount}}}],
            "commandId":id,"actAs":[bank,owner],"userId":"participant_admin"}),
    )
}

pub fn acs(svc: &ExecutionService, who: &str) -> Value {
    let (_, end) = call(svc, "GET", "/v2/state/ledger-end", vec![]);
    post(
        svc,
        "/v2/state/active-contracts",
        json!({"eventFormat":{"filtersByParty":{who:{"cumulative":[{"identifierFilter":{"WildcardFilter":
            {"value":{"includeCreatedEventBlob":false}}}}]}},"verbose":true},"activeAtOffset":end["offset"]}),
    )
    .1
}

/// Everything a client can observe about the ledger, as (status, body) pairs.
pub fn snapshot(svc: &ExecutionService) -> Vec<(u16, Value)> {
    let bank = party(svc, "bank");
    let owner = party(svc, "owner");
    let mut out = vec![
        call(svc, "GET", "/v2/parties", vec![]),
        call(svc, "GET", "/v2/users", vec![]),
        call(svc, "GET", "/v2/packages", vec![]),
        call(svc, "GET", "/v2/state/ledger-end", vec![]),
        (200, acs(svc, &bank)),
        (200, acs(svc, &owner)),
    ];
    let end = out[3].1["offset"].as_u64().unwrap();
    for offset in 1..=end {
        out.push(post(
            svc,
            "/v2/updates/update-by-offset",
            json!({"offset":offset,"updateFormat":{"includeTransactions":{"eventFormat":{"filtersByParty":
                {bank.clone():{"cumulative":[{"identifierFilter":{"WildcardFilter":{"value":{"includeCreatedEventBlob":false}}}}]}},
                "verbose":true},"transactionShape":"TRANSACTION_SHAPE_ACS_DELTA"}}}),
        ));
    }
    out
}

/// The scripted history; each step is one client call. Returns the status of the step.
pub fn step(svc: &ExecutionService, n: usize) -> u16 {
    match n {
        0 => call(svc, "POST", "/v2/dars", dar_bytes()).0,
        1 => {
            post(
                svc,
                "/v2/parties",
                json!({"partyIdHint":"bank","identityProviderId":""}),
            )
            .0
        }
        2 => {
            post(
                svc,
                "/v2/parties",
                json!({"partyIdHint":"owner","identityProviderId":""}),
            )
            .0
        }
        3 => {
            let bank = party(svc, "bank");
            post(
                svc,
                "/v2/users",
                json!({"user":{"id":"alice","primaryParty":bank,"isDeactivated":false,
                    "metadata":{"resourceVersion":"","annotations":{"k":"v"}},"identityProviderId":""},
                    "rights":[{"kind":{"CanActAs":{"value":{"party":bank}}}}]}),
            )
            .0
        }
        4 => {
            create(
                svc,
                "c1",
                &party(svc, "bank"),
                &party(svc, "owner"),
                "100.0",
            )
            .0
        }
        5 => create(svc, "c2", &party(svc, "bank"), &party(svc, "owner"), "5.5").0,
        // refused (ensure amount > 0): not logged, leaves no trace and does not use up the command id
        6 => create(svc, "c3", &party(svc, "bank"), &party(svc, "owner"), "0.0").0,
        7 => {
            let (bank, owner) = (party(svc, "bank"), party(svc, "owner"));
            let contract = first_contract(&acs(svc, &owner));
            post(
                svc,
                "/v2/commands/submit-and-wait",
                json!({"commands":[{"ExerciseCommand":{
                    "templateId":"#sample-contract:AssetHolding:AssetHolding","contractId":contract,
                    "choice":"Transfer","choiceArgument":{"newOwner":bank}}}],
                    "commandId":"c4","actAs":[owner,bank],"userId":"participant_admin"}),
            )
            .0
        }
        // the id of an accepted command again: DUPLICATE_COMMAND
        8 => {
            create(
                svc,
                "c1",
                &party(svc, "bank"),
                &party(svc, "owner"),
                "100.0",
            )
            .0
        }
        // a command list whose second command is refused (ensure amount > 0) after the first drew a contract id: the whole
        // submission fails, but the id is spent and a rejection completion is recorded. A client that kept an id from before a
        // restart relies on the replay drawing the same ids, so the failed request has to be replayed too.
        9 => {
            let (bank, owner) = (party(svc, "bank"), party(svc, "owner"));
            let one = |amount: &str| {
                json!({"CreateCommand":{"templateId":"#sample-contract:AssetHolding:AssetHolding",
                    "createArguments":{"bank":bank,"owner":owner,"auditor":bank,"assetSymbol":"USD","amount":amount}}})
            };
            post(
                svc,
                "/v2/commands/submit-and-wait",
                json!({"commands":[one("7.5"), one("0.0")],"commandId":"c5","actAs":[bank,owner],"userId":"participant_admin"}),
            )
            .0
        }
        10 => create(svc, "c6", &party(svc, "bank"), &party(svc, "owner"), "9.0").0,
        _ => unreachable!(),
    }
}

pub fn first_contract(acs: &Value) -> String {
    let text = acs.to_string();
    let at = text.find("\"contractId\":\"").expect("an active contract") + 14;
    text[at..].split('"').next().unwrap().to_string()
}

pub const STEPS: usize = 11;

/// What each scripted step answers (so a silently failing step cannot make a test vacuous).
pub const EXPECTED_STATUS: [u16; STEPS] = [200, 200, 200, 200, 200, 200, 400, 200, 409, 400, 200];

/// Timestamps (and V12 contract-id unicum tails derived from creation time) differ between two separate runs; the rest must not.
pub fn strip_times(v: &Value) -> Value {
    match v {
        Value::String(s) if s.len() == 27 && s.ends_with('Z') && s.as_bytes()[10] == b'T' => {
            json!("<time>")
        }
        Value::String(s)
            if s.len() == 138
                && s.starts_with("00")
                && s.get(66..74) == Some("ca121220")
                && s.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            json!(format!("{}<unicum>", &s[..74]))
        }
        Value::Array(a) => Value::Array(a.iter().map(strip_times).collect()),
        Value::Object(m) => {
            Value::Object(m.iter().map(|(k, v)| (k.clone(), strip_times(v))).collect())
        }
        other => other.clone(),
    }
}

pub fn stripped(s: Vec<(u16, Value)>) -> Vec<(u16, Value)> {
    s.into_iter().map(|(c, v)| (c, strip_times(&v))).collect()
}

/// Compares two snapshots and, when they differ, says which observation does (a full dump of both is unreadable).
pub fn assert_same(a: &[(u16, Value)], b: &[(u16, Value)], what: &str) {
    assert_eq!(a.len(), b.len(), "{what}: different number of observations");
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        assert!(
            x == y,
            "{what}: observation {i} differs\n  left : {x:?}\n  right: {y:?}"
        );
    }
}

/// Snapshots need the parties to exist; before that only the unconditional reads are compared.
pub fn snapshot_if_ready(svc: &ExecutionService, after_step: usize) -> Vec<(u16, Value)> {
    if after_step >= 2 {
        snapshot(svc)
    } else {
        vec![
            call(svc, "GET", "/v2/parties", vec![]),
            call(svc, "GET", "/v2/packages", vec![]),
            call(svc, "GET", "/v2/state/ledger-end", vec![]),
        ]
    }
}
