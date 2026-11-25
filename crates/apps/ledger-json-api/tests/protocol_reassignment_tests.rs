//! G7 B1 (S-NET-040 part 8): `POST /v2/commands/submit-and-wait-for-reassignment` on a Rust participant with two Rust synchronizers, compared
//! with what the Canton 3.7.2 JSON API answered for the same sequence (`tests/oracle/reassignment/json-api.jsonl`, recorded by
//! `scripts/oracle-json-reassignment.sh`): the shape of every answer, update and ACS entry, and the values that do not depend on the
//! run (counters, the links between the ids, the synchronizers, offsets, the refusal).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "protocol")]
use canton_participant::multi_node::MultiNode;
use ledger_json_api::protocol::NodeCommitter;
use ledger_json_api::service::ExecutionService;
use ledger_json_api::{dispatch_request, HttpRequest};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn start(name: &str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = canton_sequencer_server::new_synchronizer_with_groups(name, "rs1", 1);
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(canton_sequencer_server::serve(address, config))
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    format!("http://{address}")
}

/// The JVM's exchanges by name.
fn recorded() -> std::collections::HashMap<String, Value> {
    let text =
        std::fs::read_to_string(root().join("tests/oracle/reassignment/json-api.jsonl")).unwrap();
    text.lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .map(|v| (v["name"].as_str().unwrap().to_string(), v))
        .collect()
}

/// The structure of a JSON value: objects with their keys, arrays by their first element, scalars by their type.
fn skeleton(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            Value::Object(m.iter().map(|(k, v)| (k.clone(), skeleton(v))).collect())
        }
        Value::Array(a) => Value::Array(a.first().map(skeleton).into_iter().collect()),
        Value::String(_) => json!("string"),
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("bool"),
        Value::Null => json!("null"),
    }
}

fn same_shape(what: &str, ours: &Value, jvm: &Value) {
    assert_eq!(
        skeleton(ours),
        skeleton(jvm),
        "{what}: the shape differs from the JVM's\nours: {ours:#}\njvm: {jvm:#}"
    );
}

#[test]
fn reassignment_through_the_json_api_answers_as_the_jvm_does() {
    let jvm = recorded();
    let (url_a, url_b) = (start("syncA"), start("syncB"));
    let dar = root().join("contracts/target/sample-contract.dar");
    let multi = MultiNode::connect_in(&[&url_a, &url_b], "p1", &dar, None).expect("joins both");
    let mut nodes = multi.nodes.into_iter();
    let (a, b) = (nodes.next().unwrap(), nodes.next().unwrap());
    let svc = ExecutionService::new();
    svc.load_dar(&dar).expect("load the DAR");
    svc.set_committer(Arc::new(NodeCommitter::new_multi(
        vec![("syncA".into(), a), ("syncB".into(), b)],
        "sample-contract",
        Duration::from_secs(20),
    )));
    let alice = svc.protocol_party("alice").unwrap().expect("alice on both");
    let call = |method: &str, path: &str, body: Value| {
        let resp = dispatch_request(
            &svc,
            &HttpRequest {
                method: method.into(),
                path: path.into(),
                query_params: Default::default(),
                headers: Default::default(),
                body: if body.is_null() {
                    Vec::new()
                } else {
                    body.to_string().into_bytes()
                },
            },
        );
        (
            resp.status,
            serde_json::from_slice::<Value>(&resp.body).unwrap_or_default(),
        )
    };

    // the synchronizers: two, with their aliases
    let (st, syncs) = call("GET", "/v2/state/connected-synchronizers", Value::Null);
    assert_eq!(st, 200);
    same_shape(
        "connected synchronizers",
        &syncs,
        &jvm["connected_synchronizers"]["response"],
    );
    let ids: Vec<String> = syncs["connectedSynchronizers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["synchronizerId"].as_str().unwrap().to_string())
        .collect();
    let aliases: Vec<&str> = syncs["connectedSynchronizers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["synchronizerAlias"].as_str().unwrap())
        .collect();
    assert_eq!(aliases, ["syncA", "syncB"]);
    let (sync_a, sync_b) = (ids[0].clone(), ids[1].clone());

    // a contract of alice on syncA (the first synchronizer takes the transactions)
    let (st, created) = call(
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": { "commands": [{ "CreateCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": { "bank": alice, "owner": alice, "auditor": alice, "assetSymbol": "USD", "amount": "100.0" }
            } }], "userId": "u", "commandId": "create-1", "actAs": [alice] }
        }),
    );
    assert_eq!(st, 200, "{created}");
    let cid = created
        .pointer("/transaction/events/0/CreatedEvent/contractId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a created event: {created}"))
        .to_string();
    let event_format = json!({ "filtersByParty": { alice.clone(): {} }, "verbose": false });
    let end = |call: &dyn Fn(&str, &str, Value) -> (u16, Value)| {
        call("GET", "/v2/state/ledger-end", Value::Null).1["offset"]
            .as_u64()
            .unwrap()
    };
    let (_, acs) = call(
        "POST",
        "/v2/state/active-contracts",
        json!({ "eventFormat": event_format, "activeAtOffset": end(&call) }),
    );
    assert_eq!(
        acs[0]["contractEntry"]["JsActiveContract"]["synchronizerId"],
        json!(sync_a)
    );
    assert_eq!(
        acs[0]["contractEntry"]["JsActiveContract"]["reassignmentCounter"],
        json!(0)
    );

    // unassign syncA -> syncB
    let (st, u) = call(
        "POST",
        "/v2/commands/submit-and-wait-for-reassignment",
        json!({ "reassignmentCommands": { "submitter": alice, "commandId": "unassign-1", "userId": "u",
            "commands": [{ "command": { "UnassignCommand": { "value": { "contractId": cid, "source": sync_a, "target": sync_b } } } }] },
            "eventFormat": event_format }),
    );
    assert_eq!(st, 200, "{u}");
    same_shape("unassign", &u, &jvm["unassign"]["response"]);
    let ue = &u["reassignment"]["events"][0]["JsUnassignedEvent"]["value"];
    assert_eq!(ue["contractId"], json!(cid));
    assert_eq!(
        (ue["source"].clone(), ue["target"].clone()),
        (json!(sync_a), json!(sync_b))
    );
    assert_eq!(ue["reassignmentCounter"], json!(1));
    assert_eq!(ue["assignmentExclusivity"], Value::Null);
    assert_eq!(ue["submitter"], json!(alice));
    assert_eq!(ue["witnessParties"], json!([alice]));
    assert_eq!(ue["packageName"], json!("sample-contract"));
    assert_eq!(ue["offset"], u["reassignment"]["offset"]);
    assert_eq!(
        u["reassignment"]["synchronizerId"],
        json!(sync_a),
        "an unassignment is an update of the source"
    );
    let rid = ue["reassignmentId"].as_str().unwrap().to_string();
    assert!(rid.starts_with("001220") && rid.len() == 70, "{rid}");
    // between the synchronizers the contract is in no ACS
    let (_, acs) = call(
        "POST",
        "/v2/state/active-contracts",
        json!({ "eventFormat": event_format, "activeAtOffset": end(&call) }),
    );
    assert_eq!(acs, json!([]));

    // assign on syncB
    let (st, a) = call(
        "POST",
        "/v2/commands/submit-and-wait-for-reassignment",
        json!({ "reassignmentCommands": { "submitter": alice, "commandId": "assign-1", "userId": "u",
            "commands": [{ "command": { "AssignCommand": { "value": { "reassignmentId": rid, "source": sync_a, "target": sync_b } } } }] },
            "eventFormat": event_format }),
    );
    assert_eq!(st, 200, "{a}");
    same_shape("assign", &a, &jvm["assign"]["response"]);
    let ae = &a["reassignment"]["events"][0]["JsAssignmentEvent"];
    assert_eq!(ae["reassignmentId"], json!(rid));
    assert_eq!(ae["reassignmentCounter"], json!(1));
    assert_eq!(ae["createdEvent"]["contractId"], json!(cid));
    assert_eq!(ae["createdEvent"]["offset"], a["reassignment"]["offset"]);
    assert_eq!(
        a["reassignment"]["synchronizerId"],
        json!(sync_b),
        "an assignment is an update of the target"
    );

    // the update stream: the transaction, then both reassignments, as the JVM shows them
    let e = end(&call);
    let (st, ups) = call(
        "POST",
        "/v2/updates",
        json!({ "beginExclusive": 0, "endInclusive": e, "updateFormat": {
            "includeTransactions": { "eventFormat": event_format, "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA" },
            "includeReassignments": event_format } }),
    );
    assert_eq!(st, 200, "{ups}");
    let kinds = |list: &Value| -> Vec<String> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|u| {
                u["update"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .next()
                    .unwrap()
                    .clone()
            })
            .collect()
    };
    assert_eq!(kinds(&ups), kinds(&jvm["updates"]["response"]));
    for (i, (ours, theirs)) in ups
        .as_array()
        .unwrap()
        .iter()
        .zip(jvm["updates"]["response"].as_array().unwrap())
        .enumerate()
        .skip(1)
    {
        same_shape(&format!("update {i}"), ours, theirs);
    }

    // the ACS: on syncB with counter 1
    let (_, acs) = call(
        "POST",
        "/v2/state/active-contracts",
        json!({ "eventFormat": event_format, "activeAtOffset": e }),
    );
    same_shape("ACS after", &acs, &jvm["acs_after"]["response"]);
    assert_eq!(
        acs[0]["contractEntry"]["JsActiveContract"]["synchronizerId"],
        json!(sync_b)
    );
    assert_eq!(
        acs[0]["contractEntry"]["JsActiveContract"]["reassignmentCounter"],
        json!(1)
    );

    // the contract is no longer on syncA: refused as the JVM refuses it
    let (st, err) = call(
        "POST",
        "/v2/commands/submit-and-wait-for-reassignment",
        json!({ "reassignmentCommands": { "submitter": alice, "commandId": "unassign-2", "userId": "u",
            "commands": [{ "command": { "UnassignCommand": { "value": { "contractId": cid, "source": sync_a, "target": sync_b } } } }] },
            "eventFormat": event_format }),
    );
    let theirs = &jvm["unassign_not_on_source"];
    assert_eq!(st as u64, theirs["status"].as_u64().unwrap());
    for key in ["code", "errorCategory", "grpcCodeValue"] {
        assert_eq!(err[key], theirs["response"][key], "{key}: {err}");
    }
    let mut ours_keys: Vec<&String> = err.as_object().unwrap().keys().collect();
    let mut their_keys: Vec<&String> = theirs["response"].as_object().unwrap().keys().collect();
    ours_keys.sort();
    their_keys.sort();
    assert_eq!(ours_keys, their_keys);
    let cause = err["cause"].as_str().unwrap();
    assert!(
        cause.starts_with(&format!(
            "The submitted request has invalid arguments: Cannot unassign contract `ContractId({cid})` because it's not active. Current status ReassignedAway("
        )),
        "{cause}"
    );
}
