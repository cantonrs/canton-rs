//! P-8: the commands of one submission are one transaction with one root per command, judged by the synchronizer in one confirmation request.
//! A refusal of any command leaves nothing behind, in the service and in the participant.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "protocol")]
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use canton_participant::node::Node;
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use canton_participant::topology_wire::ParticipantIdentity;
use ledger_json_api::protocol::NodeCommitter;
use ledger_json_api::service::ExecutionService;
use ledger_json_api::{dispatch_request, HttpRequest};
use serde_json::json;

fn dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn node() -> Node {
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
    Node::open(identity, client, token, &physical, &dar(), cursor).expect("the node opens")
}

fn service() -> (ExecutionService, Arc<NodeCommitter>) {
    let service = ExecutionService::new();
    service.load_dar(&dar()).expect("load sample dar");
    let committer = Arc::new(NodeCommitter::new(
        node(),
        "sample-contract",
        Duration::from_secs(20),
    ));
    service.set_committer(Arc::clone(&committer) as Arc<_>);
    (service, committer)
}

fn post(svc: &ExecutionService, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let req = HttpRequest {
        method: "POST".into(),
        path: path.into(),
        query_params: Default::default(),
        headers: Default::default(),
        body: body.to_string().into_bytes(),
    };
    let resp = dispatch_request(svc, &req);
    let j: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
    (resp.status, j)
}

fn create(bank: &str, auditor: &str, symbol: &str) -> serde_json::Value {
    json!({
        "CreateCommand": {
            "templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": bank, "owner": bank, "auditor": auditor, "assetSymbol": symbol, "amount": "100.0"}
        }
    })
}

fn submit(
    svc: &ExecutionService,
    parties: &[&str],
    command_id: &str,
    commands: Vec<serde_json::Value>,
) -> (u16, serde_json::Value) {
    post(
        svc,
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": commands,
                "userId": "u-multi",
                "commandId": command_id,
                "actAs": parties
            }
        }),
    )
}

/// What the participant's protocol ledger holds, as a fresh service in front of it would show it.
fn protocol_contracts(committer: &NodeCommitter) -> usize {
    let fresh = ExecutionService::new();
    fresh.load_dar(&dar()).expect("load sample dar");
    committer.show_known_contracts_in(&fresh).unwrap()
}

#[test]
fn a_submission_whose_second_command_cannot_be_sent_sends_none_of_them() {
    let (svc, committer) = service();
    let bank = svc.protocol_party("bank").unwrap().unwrap();
    // the second create names a party nobody hosts: no request can be built for it
    let (status, body) = submit(
        &svc,
        &[&bank],
        "two-one-bad",
        vec![
            create(&bank, &bank, "USD"),
            create(&bank, "ghost::1220", "EUR"),
        ],
    );
    assert_ne!(status, 200, "{body}");
    assert_eq!(
        protocol_contracts(&committer),
        0,
        "the first command's contract reached the participant's protocol ledger"
    );
    assert!(svc
        .get_active_contracts(&[])
        .unwrap()
        .active_contracts
        .is_empty());
}

#[test]
fn the_commands_of_a_submission_are_one_transaction_with_a_root_each() {
    let (svc, committer) = service();
    let bank = svc.protocol_party("bank").unwrap().unwrap();
    let (status, body) = submit(
        &svc,
        &[&bank],
        "two-good",
        vec![create(&bank, &bank, "USD"), create(&bank, &bank, "EUR")],
    );
    assert_eq!(status, 200, "{body}");
    let events = body["transaction"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 2, "{body}");
    let ids: Vec<String> = events
        .iter()
        .map(|e| {
            e["CreatedEvent"]["contractId"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    for id in &ids {
        assert!(id.starts_with("00") && id.len() > 64, "{id}");
        assert!(
            committer.protocol_is_active(id),
            "{id} is not in the protocol ledger"
        );
    }
    assert_ne!(ids[0], ids[1]);
    // a create and an exercise of an existing contract, then a single create: both still go through
    let (status, body) = submit(
        &svc,
        &[&bank],
        "create-and-settle",
        vec![
            create(&bank, &bank, "CHF"),
            json!({"ExerciseCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "contractId": ids[0],
                "choice": "Settle",
                "choiceArgument": {}
            }}),
        ],
    );
    assert_eq!(status, 200, "{body}");
    assert!(!committer.protocol_is_active(&ids[0]), "settled");
    let owner = svc.protocol_party("owner").unwrap().unwrap();
    let (status, body) = submit(
        &svc,
        &[&bank, &owner],
        "one",
        vec![json!({"CreateCommand": {
            "templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": bank, "owner": owner, "auditor": bank, "assetSymbol": "GBP", "amount": "5.0"}
        }})],
    );
    assert_eq!(status, 200, "{body}");
    let gbp = body["transaction"]["events"][0]["CreatedEvent"]["contractId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(protocol_contracts(&committer), 3, "EUR, CHF and GBP");
    // a create, and a choice that consumes GBP and creates a holding below the second root
    let (status, body) = submit(
        &svc,
        &[&bank, &owner],
        "create-and-transfer-another",
        vec![
            create(&bank, &bank, "AUD"),
            json!({"ExerciseCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "contractId": gbp,
                "choice": "Transfer",
                "choiceArgument": {"newOwner": bank}
            }}),
        ],
    );
    assert_eq!(status, 200, "{body}");
    assert!(!committer.protocol_is_active(&gbp), "transferred");
    assert_eq!(
        protocol_contracts(&committer),
        4,
        "EUR, CHF, AUD and the transferred GBP"
    );
    // a command that exercises the contract it creates: two roots of one request, the created holding transient
    let (status, body) = submit(
        &svc,
        &[&bank, &owner],
        "create-and-transfer",
        vec![json!({"CreateAndExerciseCommand": {
            "templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": bank, "owner": owner, "auditor": bank, "assetSymbol": "JPY", "amount": "7.0"},
            "choice": "Transfer",
            "choiceArgument": {"newOwner": bank}
        }})],
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        protocol_contracts(&committer),
        5,
        "and the transferred JPY holding"
    );
}

#[test]
fn another_participant_confirms_and_shows_every_root_of_one_transaction() {
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
    let url = format!("http://{address}");
    let participant = |name: &str| {
        let node = Node::connect(&url, name, &dar()).expect("the participant joins");
        let svc = Arc::new(ExecutionService::new());
        svc.load_dar(&dar()).expect("load the DAR");
        let committer = Arc::new(NodeCommitter::new(
            node,
            "sample-contract",
            Duration::from_secs(30),
        ));
        committer.show_remote_transactions_in(Arc::clone(&svc));
        svc.set_committer(Arc::clone(&committer) as Arc<_>);
        (svc, committer)
    };
    let (alpha, _) = participant("alpha");
    let (beta, beta_committer) = participant("beta");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let bob = beta.protocol_party("bob").unwrap().unwrap();
    let (status, body) = submit(
        &alpha,
        &[&alice],
        "two-for-bob",
        vec![create(&alice, &bob, "USD"), create(&alice, &bob, "EUR")],
    );
    assert_eq!(status, 200, "{body}");
    let ids: Vec<String> = body["transaction"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            e["CreatedEvent"]["contractId"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(ids.len(), 2, "{body}");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let shown: Vec<String> = beta
            .get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .into_iter()
            .map(|c| c.contract_id)
            .collect();
        if ids.iter().all(|id| shown.contains(id)) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bob sees {shown:?}, not {ids:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    for id in &ids {
        assert!(
            beta_committer.protocol_is_active(id),
            "{id} not in bob's protocol ledger"
        );
    }
}

type ParticipantHandle = (Arc<ExecutionService>, Arc<NodeCommitter>);

fn two_participants() -> (ParticipantHandle, ParticipantHandle) {
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
    let url = format!("http://{address}");
    let participant = |name: &str| {
        let node = Node::connect(&url, name, &dar()).expect("the participant joins");
        let svc = Arc::new(ExecutionService::new());
        svc.load_dar(&dar()).expect("load the DAR");
        let committer = Arc::new(NodeCommitter::new(
            node,
            "sample-contract",
            Duration::from_secs(30),
        ));
        committer.show_remote_transactions_in(Arc::clone(&svc));
        svc.set_committer(Arc::clone(&committer) as Arc<_>);
        (svc, committer)
    };
    (participant("alpha"), participant("beta"))
}

fn create_and_transfer(
    bank: &str,
    owner: &str,
    auditor: &str,
    new_owner: &str,
    symbol: &str,
) -> serde_json::Value {
    json!({"CreateAndExerciseCommand": {
        "templateId": "#sample-contract:AssetHolding:AssetHolding",
        "createArguments": {"bank": bank, "owner": owner, "auditor": auditor, "assetSymbol": symbol, "amount": "7.0"},
        "choice": "Transfer",
        "choiceArgument": {"newOwner": new_owner}
    }})
}

/// A command that exercises the contract created before it in the same submission (`CreateAndExerciseCommand`): one request, the created
/// contract transient on both participants (`ExtractUsedAndCreated`), and a refusal of the exercise leaves nothing.
#[test]
fn a_command_using_a_contract_created_before_it_is_in_the_same_request() {
    let ((alpha, alpha_committer), (beta, beta_committer)) = two_participants();
    let bank = alpha.protocol_party("bank").unwrap().unwrap();
    let owner = alpha.protocol_party("owner").unwrap().unwrap();
    let auditor = beta.protocol_party("auditor").unwrap().unwrap();
    let remote = |svc: &ExecutionService| {
        svc.get_updates(0, None, &[])
            .iter()
            .filter(|t| t.command_id.is_empty())
            .count()
    };
    let (status, body) = submit(
        &alpha,
        &[&bank, &owner],
        "create-and-transfer",
        vec![create_and_transfer(&bank, &owner, &auditor, &bank, "JPY")],
    );
    assert_eq!(status, 200, "{body}");
    let events = body["transaction"]["events"].as_array().unwrap();
    let created: Vec<String> = events
        .iter()
        .filter_map(|e| e["CreatedEvent"]["contractId"].as_str().map(String::from))
        .collect();
    // the flat transaction leaves the transient holding out: only the transferred one
    let [transferred] = created.as_slice() else {
        panic!("{body}")
    };
    assert!(alpha_committer.protocol_is_active(transferred));
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !beta_committer.protocol_is_active(transferred) || beta.v2_contract(transferred).is_none()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the auditor's participant never saw {transferred}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        remote(&beta),
        1,
        "the other participant saw more than one transaction"
    );
    let shown: Vec<String> = beta
        .get_active_contracts(&[])
        .unwrap()
        .active_contracts
        .into_iter()
        .map(|c| c.contract_id)
        .collect();
    assert_eq!(
        &shown,
        std::slice::from_ref(transferred),
        "the auditor's contracts"
    );

    // the exercise fails (the new owner is the owner): the create of the same command is not left behind
    let before = protocol_contracts(&alpha_committer);
    let (status, body) = submit(
        &alpha,
        &[&bank, &owner],
        "create-and-fail",
        vec![create_and_transfer(&bank, &owner, &auditor, &owner, "NOK")],
    );
    assert_ne!(status, 200, "{body}");
    assert_eq!(
        protocol_contracts(&alpha_committer),
        before,
        "the create reached the participant's protocol ledger"
    );
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(remote(&beta), 1, "the auditor saw the create");
}

/// R-13b: multi-root submission must preserve and check all request `actAs` parties (including non-signatory `actAs` parties)
/// rather than inferring `act_as` solely from root signatories and actors.
#[test]
fn r13b_unhosted_non_signatory_act_as_is_rejected_on_multi_command_batch() {
    let (svc, _committer) = service();
    let bank = svc.protocol_party("bank").unwrap().unwrap();
    let extra = svc.protocol_party("extra").unwrap().unwrap();

    // Positive control: hosted non-signatory party `extra` in `actAs` alongside `bank` succeeds and stays in completion `actAs`.
    let (st_ok, body_ok) = submit(
        &svc,
        &[&bank, &extra],
        "r13b-hosted-extra",
        vec![create(&bank, &bank, "USD"), create(&bank, &bank, "EUR")],
    );
    assert_eq!(st_ok, 200, "{body_ok}");
    let (st_comp, comps) = post(
        &svc,
        "/v2/commands/completions",
        json!({ "userId": "u-multi", "parties": [&bank, &extra], "beginExclusive": 0 }),
    );
    assert_eq!(st_comp, 200, "{comps}");
    let completion = comps
        .as_array()
        .expect("completions array")
        .iter()
        .map(|item| &item["completionResponse"]["Completion"]["value"])
        .find(|c| c["commandId"] == "r13b-hosted-extra")
        .unwrap_or_else(|| panic!("missing completion for r13b-hosted-extra: {comps}"));
    let comp_act_as: Vec<&str> = completion["actAs"]
        .as_array()
        .expect("completion actAs array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        comp_act_as.contains(&bank.as_str()) && comp_act_as.contains(&extra.as_str()),
        "completion actAs must preserve non-signatory co-submitter extra: {completion}"
    );

    // Negative control / R-13b gap: an unhosted non-signatory party in `actAs` on a multi-command batch must fail `check_submitters`.
    let (st_bad, body_bad) = submit(
        &svc,
        &[&bank, "unhosted::12200000"],
        "r13b-unhosted-extra",
        vec![create(&bank, &bank, "GBP"), create(&bank, &bank, "CHF")],
    );
    assert_eq!(
        st_bad, 404,
        "unhosted non-signatory actAs party in multi-command batch must be rejected: {body_bad}"
    );
    assert_eq!(
        body_bad["code"], "NO_SYNCHRONIZER_ON_WHICH_ALL_SUBMITTERS_CAN_SUBMIT",
        "{body_bad}"
    );
}
