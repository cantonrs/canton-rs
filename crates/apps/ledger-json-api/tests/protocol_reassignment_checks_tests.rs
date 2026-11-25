//! G7 B1 (U-44): an unassignment is refused, before anything is sent, for what the TARGET synchronizer lacks, in the words of the official
//! participant (`tests/oracle/reassignment/json-api-checks-hosting.jsonl`, recorded by `scripts/oracle-json-reassignment-checks.sh`):
//! a stakeholder that no participant hosts on the target synchronizer; and an assignment is compared with the stored unassignment
//! (`json-api-checks-assign.jsonl`): an unknown id, the directions swapped, and an id whose assignment was approved.
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
    let url = format!("http://{address}");
    for _ in 0..100 {
        if std::net::TcpStream::connect(address).is_ok() {
            return url;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the synchronizer {name} did not listen");
}

#[test]
fn a_stakeholder_not_hosted_on_the_target_synchronizer_refuses_the_unassignment_in_the_official_words(
) {
    let recorded: Value = std::fs::read_to_string(
        root().join("tests/oracle/reassignment/json-api-checks-hosting.jsonl"),
    )
    .unwrap()
    .lines()
    .map(|l| serde_json::from_str::<Value>(l).unwrap())
    .find(|v| v["name"] == "unassign_refused")
    .expect("the recorded refusal");
    let official_cause = recorded["response"]["cause"].as_str().unwrap();
    // `<prefix> TreeSet(alice::...)`: the words around the party
    let (words, _) = official_cause.split_once("TreeSet(").unwrap();

    let (url_a, url_b) = (start("syncA"), start("syncB"));
    let dar = root().join("contracts/target/sample-contract.dar");
    let multi = MultiNode::connect_in(&[&url_a, &url_b], "p1", &dar, None).expect("joins both");
    let mut nodes = multi.nodes.into_iter();
    let (mut a, b) = (nodes.next().unwrap(), nodes.next().unwrap());
    // alice is hosted on the FIRST synchronizer only
    let alice = a
        .host_party("alice", Duration::from_secs(20))
        .expect("alice on syncA");
    let svc = ExecutionService::new();
    svc.load_dar(&dar).expect("load the DAR");
    svc.set_committer(Arc::new(NodeCommitter::new_multi(
        vec![("syncA".into(), a), ("syncB".into(), b)],
        "sample-contract",
        Duration::from_secs(20),
    )));
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
    let (_, syncs) = call("GET", "/v2/state/connected-synchronizers", Value::Null);
    let id = |alias: &str| {
        syncs["connectedSynchronizers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["synchronizerAlias"] == json!(alias))
            .unwrap()["synchronizerId"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (sync_a, sync_b) = (id("syncA"), id("syncB"));
    let (st, created) = call(
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        json!({"commands": {"commands": [{"CreateCommand": {
            "templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": alice, "owner": alice, "auditor": alice, "assetSymbol": "USD", "amount": "100.0"}}}],
            "userId": "u", "commandId": "create-1", "actAs": [alice]}}),
    );
    assert_eq!(st, 200, "{created}");
    let cid = created
        .pointer("/transaction/events/0/CreatedEvent/contractId")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let (st, refused) = call(
        "POST",
        "/v2/commands/submit-and-wait-for-reassignment",
        json!({"reassignmentCommands": {"submitter": alice, "commandId": "unassign-1", "userId": "u",
            "commands": [{"command": {"UnassignCommand": {"value": {"contractId": cid, "source": sync_a, "target": sync_b}}}}]},
            "eventFormat": {"filtersByParty": {alice.clone(): {}}, "verbose": false}}),
    );
    assert_eq!(st, recorded["status"].as_u64().unwrap() as u16, "{refused}");
    assert_eq!(refused["code"], recorded["response"]["code"]);
    assert_eq!(
        refused["errorCategory"],
        recorded["response"]["errorCategory"]
    );
    assert_eq!(refused["cause"], json!(format!("{words}TreeSet({alice})")));
}

fn recorded(name: &str, file: &str) -> Value {
    std::fs::read_to_string(root().join("tests/oracle/reassignment").join(file))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not in {file}"))
}

#[test]
fn an_assignment_is_compared_with_the_stored_unassignment_as_the_official_participant_does() {
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
    let (_, syncs) = call("GET", "/v2/state/connected-synchronizers", Value::Null);
    let id = |alias: &str| {
        syncs["connectedSynchronizers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["synchronizerAlias"] == json!(alias))
            .unwrap()["synchronizerId"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (sync_a, sync_b) = (id("syncA"), id("syncB"));
    let (_, created) = call(
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        json!({"commands": {"commands": [{"CreateCommand": {
            "templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": alice, "owner": alice, "auditor": alice, "assetSymbol": "USD", "amount": "100.0"}}}],
            "userId": "u", "commandId": "create-1", "actAs": [alice]}}),
    );
    let cid = created
        .pointer("/transaction/events/0/CreatedEvent/contractId")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let format = json!({"filtersByParty": {alice.clone(): {}}, "verbose": false});
    let reassign = |command_id: &str, command: Value| {
        call(
            "POST",
            "/v2/commands/submit-and-wait-for-reassignment",
            json!({"reassignmentCommands": {"submitter": alice, "commandId": command_id, "userId": "u",
                "commands": [{"command": command}]}, "eventFormat": format}),
        )
    };
    let (st, u) = reassign(
        "unassign-1",
        json!({"UnassignCommand": {"value": {"contractId": cid, "source": sync_a, "target": sync_b}}}),
    );
    assert_eq!(st, 200, "{u}");
    let rid = u["reassignment"]["events"][0]["JsUnassignedEvent"]["value"]["reassignmentId"]
        .as_str()
        .unwrap()
        .to_string();
    let assign = |name: &str, rid: &str, source: &str, target: &str| {
        reassign(
            name,
            json!({"AssignCommand": {"value": {"reassignmentId": rid, "source": source, "target": target}}}),
        )
    };
    // the words of a refusal with the recorded id swapped for the one asked about
    let words = |name: &str, asked: &str| {
        let r = recorded(name, "json-api-checks-assign.jsonl");
        let cause = r["response"]["cause"].as_str().unwrap().to_string();
        let start = cause.find("ReassignmentId(").unwrap() + "ReassignmentId(".len();
        let end = cause[start..].find(')').unwrap() + start;
        (
            r["status"].as_u64().unwrap() as u16,
            format!("{}{asked}{}", &cause[..start], &cause[end..]),
        )
    };
    let unknown = format!("00{}", "ab".repeat(34));
    let (st, refused) = assign("assign-unknown", &unknown, &sync_a, &sync_b);
    let (want_st, want_cause) = words("assign_unknown_id", &unknown);
    assert_eq!((st, refused["cause"].clone()), (want_st, json!(want_cause)));
    // the directions swapped: asked on the wrong synchronizer, the stored unassignment is not found
    let (st, refused) = assign("assign-wrong-direction", &rid, &sync_b, &sync_a);
    let (want_st, want_cause) = words("assign_wrong_direction", &rid);
    assert_eq!((st, refused["cause"].clone()), (want_st, json!(want_cause)));
    // the source is not compared: the right target is enough
    let (st, assigned) = assign("assign-source-ignored", &rid, &sync_b, &sync_b);
    assert_eq!(st, 200, "{assigned}");
    // and now it is done
    let (st, refused) = assign("assign-again", &rid, &sync_a, &sync_b);
    let (want_st, want_cause) = words("assign_right", &rid);
    assert_eq!((st, refused["cause"].clone()), (want_st, json!(want_cause)));
}

fn run_unassign_then_restart_and_assign(strip_stored_unassignments: bool) -> (u16, Value) {
    let (url_a, url_b) = (start("syncA"), start("syncB"));
    let dar = root().join("contracts/target/sample-contract.dar");
    let state_dir = std::env::temp_dir().join(format!(
        "canton_rs_r6e_no_synth_{strip_stored_unassignments}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&state_dir);

    let (sync_a, sync_b, rid, alice) = {
        let multi = MultiNode::connect_in(&[&url_a, &url_b], "p1", &dar, Some(&state_dir))
            .expect("joins both");
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
        let (_, syncs) = call("GET", "/v2/state/connected-synchronizers", Value::Null);
        let id = |alias: &str| {
            syncs["connectedSynchronizers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["synchronizerAlias"] == json!(alias))
                .unwrap()["synchronizerId"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let (sync_a, sync_b) = (id("syncA"), id("syncB"));
        let (st, created) = call(
            "POST",
            "/v2/commands/submit-and-wait-for-transaction",
            json!({"commands": {"commands": [{"CreateCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": {"bank": alice, "owner": alice, "auditor": alice, "assetSymbol": "USD", "amount": "100.0"}}}],
                "userId": "u", "commandId": "create-1", "actAs": [alice]}}),
        );
        assert_eq!(st, 200, "{created}");
        let cid = created
            .pointer("/transaction/events/0/CreatedEvent/contractId")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let (st, u) = call(
            "POST",
            "/v2/commands/submit-and-wait-for-reassignment",
            json!({"reassignmentCommands": {"submitter": alice, "commandId": "unassign-1", "userId": "u",
                "commands": [{"command": {"UnassignCommand": {"value": {"contractId": cid, "source": sync_a, "target": sync_b}}}}]},
                "eventFormat": {"filtersByParty": {alice.clone(): {}}, "verbose": false}}),
        );
        assert_eq!(st, 200, "{u}");
        let rid = u["reassignment"]["events"][0]["JsUnassignedEvent"]["value"]["reassignmentId"]
            .as_str()
            .unwrap()
            .to_string();
        svc.clear_committer();
        (sync_a, sync_b, rid, alice)
    };

    if strip_stored_unassignments {
        for sub in ["sync-0", "sync-1"] {
            let _ = std::fs::remove_file(state_dir.join(sub).join("stored-unassignments.journal"));
        }
    }

    let multi2 = MultiNode::connect_in(&[&url_a, &url_b], "p1", &dar, Some(&state_dir))
        .expect("rejoins both after restart");
    let mut nodes2 = multi2.nodes.into_iter();
    let (a2, b2) = (nodes2.next().unwrap(), nodes2.next().unwrap());
    let svc2 = ExecutionService::new();
    svc2.load_dar(&dar).expect("load DAR after restart");
    let committer2 = Arc::new(NodeCommitter::new_multi(
        vec![("syncA".into(), a2), ("syncB".into(), b2)],
        "sample-contract",
        Duration::from_secs(20),
    ));
    committer2
        .show_known_contracts_in(&svc2)
        .expect("load unassigned.journal");
    svc2.set_committer(committer2);

    let resp = dispatch_request(
        &svc2,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/commands/submit-and-wait-for-reassignment".into(),
            query_params: Default::default(),
            headers: Default::default(),
            body: json!({
                "reassignmentCommands": {
                    "submitter": alice,
                    "commandId": "assign-after-restart",
                    "userId": "u",
                    "commands": [{"command": {"AssignCommand": {"value": {
                        "reassignmentId": rid, "source": sync_a, "target": sync_b
                    }}}}]
                },
                "eventFormat": {"filtersByParty": {alice: {}}, "verbose": false}
            })
            .to_string()
            .into_bytes(),
        },
    );
    let body: Value = serde_json::from_slice(&resp.body).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&state_dir);
    (resp.status, body)
}

#[test]
fn r6e_unassign_survives_restart_and_assign_commits() {
    let (status, body) = run_unassign_then_restart_and_assign(false);
    assert_eq!(
        status, 200,
        "restart after unassign must persist StoredUnassignment and commit assign: {body}"
    );
    assert!(
        body["reassignment"]["events"][0]["JsAssignmentEvent"]["reassignmentId"]
            .as_str()
            .is_some(),
        "expected JsAssignmentEvent in restart assign response: {body}"
    );
}

#[test]
fn r6e_assign_without_stored_unassignment_abstains_instead_of_synthesizing() {
    // Strip persisted `stored-unassignments.journal` before restart so neither `from` nor `to` holds
    // `StoredUnassignment`: target must answer LocalAbstain (`UnassignmentDataNotFound`), not synthesize.
    let (status, body) = run_unassign_then_restart_and_assign(true);
    assert_eq!(
        status, 400,
        "assign without real StoredUnassignment must fail with 400 Abstain: {body}"
    );
    let cause = body["cause"].as_str().unwrap_or("");
    assert!(
        cause.contains("Abstain") && cause.contains("UnassignmentDataNotFound"),
        "expected UnassignmentDataNotFound Abstain in failure cause, got: {body}"
    );
}
