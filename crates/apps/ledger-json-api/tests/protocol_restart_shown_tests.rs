//! P-13 (JSON API side): what the participant applied and the JSON API had not shown when the process stopped is shown after the restart,
//! once.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "protocol")]
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use canton_participant::node::Node;
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::protocol::NodeCommitter;
use ledger_json_api::service::ExecutionService;
use ledger_json_api::TreeEvent;
use serde_json::json;

fn dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn synchronizer() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = canton_sequencer_server::new_synchronizer_with_groups("testsync", "ts1", 1);
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

fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ok() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The node of `committer` opened again from `dir`, as after a restart.
fn reopen(url: &str, committer: NodeCommitter, dir: &Path) -> Node {
    let node = committer.into_node();
    let identity = node.identity;
    let physical = {
        let mut c = SequencerConnect::connect(url).unwrap();
        c.synchronizer_id().unwrap().physical_synchronizer_id
    };
    let mut client = SequencerConnect::connect(url).unwrap();
    let challenge = client.challenge(&identity.member(), &[37]).unwrap();
    let signature = identity
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = client
        .authenticate(&identity.member(), &challenge.nonce, signature)
        .unwrap();
    Node::open_in(identity, client, token, &physical, &dar(), 0, Some(dir))
        .expect("the node opens again from its directory")
}

fn archives_of(service: &ExecutionService, id: &str) -> usize {
    service
        .get_updates(0, None, &[])
        .iter()
        .flat_map(|t| t.events_by_id.values())
        .filter(|e| matches!(e, TreeEvent::Exercised(x) if x.contract_id == id && x.consuming))
        .count()
}

#[test]
fn a_consumption_the_api_had_not_shown_is_shown_after_a_restart_once() {
    let url = synchronizer();
    let dir = std::env::temp_dir().join(format!("p13-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let alpha = {
        let node = Node::connect(&url, "alpha", &dar()).expect("alpha joins");
        let service = Arc::new(ExecutionService::new());
        service.load_dar(&dar()).unwrap();
        service.set_committer(Arc::new(NodeCommitter::new(
            node,
            "sample-contract",
            Duration::from_secs(30),
        )));
        service
    };
    let beta_node = Node::connect_in(&url, "beta", &dar(), Some(&dir)).expect("beta joins");
    let beta = Arc::new(ExecutionService::new());
    beta.load_dar(&dar()).unwrap();
    let committer = Arc::new(NodeCommitter::new(
        beta_node,
        "sample-contract",
        Duration::from_secs(30),
    ));
    beta.set_committer(Arc::clone(&committer) as Arc<_>);
    // the process stops after the participant applied what alice did and before the API showed it: nobody shows what the node reads
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let bob = beta.protocol_party("bob").unwrap().unwrap();
    let id = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank": alice, "owner": alice, "auditor": bob, "assetSymbol": "USD", "amount": "7.0"}),
                meta: None,
            },
        )
        .unwrap()
        .result
        .contract_id;
    eventually("bob's participant never applied the create", || {
        committer.protocol_is_active(&id)
    });
    alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: id.clone(),
                choice: "Settle".into(),
                argument: json!({}),
                meta: None,
            },
        )
        .expect("the settle is approved");
    eventually("bob's participant never applied the archive", || {
        !committer.protocol_is_active(&id)
    });
    assert_eq!(archives_of(&beta, &id), 0, "the API did not show it");
    beta.clear_committer();
    let committer = Arc::try_unwrap(committer)
        .ok()
        .expect("the service let go of the committer");

    // restart: the API shows the archive it missed, once
    let restarted = Arc::new(ExecutionService::new());
    restarted.load_dar(&dar()).unwrap();
    let committer = Arc::new(NodeCommitter::new(
        reopen(&url, committer, &dir),
        "sample-contract",
        Duration::from_secs(30),
    ));
    restarted.set_committer(Arc::clone(&committer) as Arc<_>);
    committer.show_known_contracts_in(&restarted).unwrap();
    committer.show_remote_transactions_in(Arc::clone(&restarted));
    eventually("the archive was not shown after the restart", || {
        archives_of(&restarted, &id) == 1
    });
    assert!(restarted
        .get_active_contracts(&[])
        .unwrap()
        .active_contracts
        .is_empty());
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(archives_of(&restarted, &id), 1, "shown more than once");

    // and a second restart shows nothing again
    restarted.clear_committer();
    let committer = Arc::try_unwrap(committer)
        .ok()
        .expect("the service let go of the committer");
    let again = Arc::new(ExecutionService::new());
    again.load_dar(&dar()).unwrap();
    let committer = Arc::new(NodeCommitter::new(
        reopen(&url, committer, &dir),
        "sample-contract",
        Duration::from_secs(30),
    ));
    again.set_committer(Arc::clone(&committer) as Arc<_>);
    committer.show_known_contracts_in(&again).unwrap();
    committer.show_remote_transactions_in(Arc::clone(&again));
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        archives_of(&again, &id),
        0,
        "shown again after it was shown"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
