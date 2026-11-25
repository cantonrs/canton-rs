//! S-SPL-010: a contract the Rust participant creates is served by the scan with the blob the node itself holds. The node's history file and
//! the contract salts it writes next to it are all the scan side reads (plus the DAR): the blob it builds from them is byte for byte the
//! serialized instance the participant keeps. No JVM.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "protocol")]
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use canton_participant::node::Node;
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use canton_participant::topology_wire::ParticipantIdentity;
use ledger_json_api::history::UpdateRecorder;
use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::protocol::NodeCommitter;
use ledger_json_api::service::ExecutionService;
use lf_eval::scan_state::{base64, contract_json, Acs};
use lf_eval::typed_json::Types;
use serde_json::json;

fn dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

/// A Rust sequencer on a free local port, and a participant joined to it.
fn node() -> Node {
    node_for(&dar())
}

fn node_for(dar: &Path) -> Node {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = canton_sequencer_server::new_synchronizer_with_groups("testsync", "ts1", 1);
    let served = config.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(canton_sequencer_server::serve(address, served))
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let url = format!("http://{address}");
    let physical = config.physical_synchronizer_id();
    let identity = ParticipantIdentity::generate("api");
    let mut client = SequencerConnect::connect(&url).unwrap();
    client
        .register_onboarding(
            &identity.member(),
            &physical,
            identity.onboarding_transactions(&format!(
                "{}::{}",
                config.name, config.namespace_fingerprint
            )),
        )
        .unwrap();
    let challenge = client.challenge(&identity.member(), &[37]).unwrap();
    let signature = identity
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = client
        .authenticate(&identity.member(), &challenge.nonce, signature)
        .unwrap();
    std::thread::sleep(Duration::from_millis(700));
    let setup = client
        .subscribe(
            &identity.member(),
            &physical,
            &token,
            Some(0),
            8,
            Duration::from_secs(5),
        )
        .unwrap();
    let cursor = canton_participant::sequencing_wire::decode_delivered(setup.last().unwrap())
        .unwrap()
        .timestamp_micros;
    Node::open(identity, client, token, &physical, dar, cursor).expect("the node opens")
}

#[test]
fn the_blob_the_scan_builds_for_a_node_contract_is_the_instance_the_node_holds() {
    let dir = tempfile::tempdir().unwrap();
    let history = dir.path().join("history.jsonl");
    let recorder = Arc::new(UpdateRecorder::new(&history, "sync::test", 0));
    let committer = Arc::new(NodeCommitter::new(
        node(),
        "sample-contract",
        Duration::from_secs(20),
    ));
    committer.record_salts_in(Arc::clone(&recorder));
    let service = ExecutionService::new();
    service.load_dar(&dar()).expect("load sample dar");
    service.set_update_recorder(Arc::clone(&recorder));
    service.set_committer(Arc::clone(&committer) as Arc<_>);
    let bank = service.protocol_party("bank").unwrap().unwrap();
    let id = service
        .json_create(
            std::slice::from_ref(&bank),
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank": bank, "owner": bank, "auditor": bank, "assetSymbol": "USD", "amount": "100.0"}),
                meta: None,
            },
        )
        .expect("the create is approved")
        .result
        .contract_id;

    let updates: Vec<serde_json::Value> = std::fs::read_to_string(&history)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(updates.len(), 1, "the create is in the history");
    let salts: Vec<serde_json::Value> = std::fs::read_to_string(recorder.authentication_path())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(salts.len(), 1);
    assert_eq!(salts[0]["contract_id"], id);
    let salt: Vec<u8> = {
        let hex = salts[0]["authentication_data"].as_str().unwrap();
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    };

    let world = lf_eval::World::open(&dar()).unwrap();
    let types = Types::new(&world);
    let acs = Acs::from_updates(&updates).unwrap();
    let active = acs.of_template("AssetHolding:AssetHolding");
    let [contract] = active.as_slice() else {
        panic!("one active contract")
    };
    let served = contract_json(&types, contract, &salt).unwrap();
    let held = committer
        .instance_bytes(&id)
        .expect("the node holds the instance");
    assert_eq!(served["created_event_blob"], base64(&held));
}
