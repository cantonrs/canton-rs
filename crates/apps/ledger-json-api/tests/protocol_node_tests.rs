//! F4 (S-SUBMIT-003): the JSON API service with a Rust participant behind it. Every create and exercise is judged by the Rust sequencer and the
//! Rust mediator before the service applies it, and the party ids and contract ids are the protocol's. No JVM.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "protocol")]
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use canton_participant::node::Node;
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use canton_participant::topology_wire::ParticipantIdentity;
use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::protocol::NodeCommitter;
use ledger_json_api::service::ExecutionService;
use serde_json::json;

fn dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn tree_dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/fixtures/tree/target/tree-view.dar")
}

/// A Rust sequencer on a free local port, and a participant joined to it.
fn node() -> Node {
    node_for(&dar())
}

fn start_sequencer() -> (String, canton_sequencer_server::SynchronizerConfig) {
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
    (format!("http://{address}"), config)
}

fn node_for(dar: &Path) -> Node {
    let (url, config) = start_sequencer();
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

fn service() -> ExecutionService {
    let service = ExecutionService::new();
    service.load_dar(&dar()).expect("load sample dar");
    service.set_committer(Arc::new(NodeCommitter::new(
        node(),
        "sample-contract",
        Duration::from_secs(20),
    )));
    service
}

fn payload(bank: &str) -> serde_json::Value {
    json!({"bank": bank, "owner": bank, "auditor": bank, "assetSymbol": "USD", "amount": "100.0"})
}

#[test]
fn a_create_and_a_settle_go_through_the_rust_protocol() {
    let service = service();
    let bank = service
        .protocol_party("bank")
        .expect("a synchronizer is behind the service")
        .expect("the party is hosted");
    assert!(bank.starts_with("bank::12"), "{bank}");
    let id = service
        .json_create(
            std::slice::from_ref(&bank),
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: payload(&bank),
                meta: None,
            },
        )
        .expect("the create is approved")
        .result
        .contract_id;
    // the protocol's id: the hex of a V1 contract id (`00` + discriminator + suffix), not the service's `#n:0`
    assert!(id.starts_with("00") && id.len() > 64, "{id}");
    assert_eq!(
        service
            .get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .len(),
        1
    );
    service
        .json_exercise(
            std::slice::from_ref(&bank),
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: id,
                choice: "Settle".into(),
                argument: json!({}),
                meta: None,
            },
        )
        .expect("the settle is approved");
    assert_eq!(
        service
            .get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .len(),
        0
    );
}

#[test]
fn a_transaction_the_committer_cannot_send_is_refused_and_changes_nothing() {
    let service = service();
    let bank = service.protocol_party("bank").unwrap().unwrap();
    // a party nobody hosts: the node cannot send a request about it
    let error = service
        .json_create(
            std::slice::from_ref(&bank),
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank": bank, "owner": bank, "auditor": "ghost::1220", "assetSymbol": "USD", "amount": "1.0"}),
                meta: None,
            },
        )
        .expect_err("refused");
    assert!(
        error.to_string().contains("ghost::1220") || error.to_string().contains("protocol"),
        "{error}"
    );
    assert_eq!(
        service
            .get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .len(),
        0
    );
}

/// The acting parties of an exercise are the choice's controllers, not everybody in `actAs` (F5, tests/oracle/json-api p06). `Settle` is
/// controlled by the bank; submitting it as bank+owner must still be judged with the bank alone as actor, or the participant's own model
/// conformance rejects the request (`ActorsDiffer`).
#[test]
fn an_exercise_submitted_by_more_parties_than_its_controllers_is_judged_with_the_controllers() {
    let service = service();
    let bank = service.protocol_party("bank").unwrap().unwrap();
    let owner = service.protocol_party("owner").unwrap().unwrap();
    let both = vec![bank.clone(), owner.clone()];
    let id = service
        .json_create(
            &both,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank": bank, "owner": owner, "auditor": bank, "assetSymbol": "USD", "amount": "5.0"}),
                meta: None,
            },
        )
        .expect("the create is approved")
        .result
        .contract_id;
    service
        .json_exercise(
            &both,
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: id,
                choice: "Settle".into(),
                argument: json!({}),
                meta: None,
            },
        )
        .expect("the settle is approved with the bank as the only actor");
    assert!(service
        .get_active_contracts(&[])
        .unwrap()
        .active_contracts
        .is_empty());
}

/// `Transfer` and `SplitTransfer` create contracts under the exercise (F1 extension, S-SUBMIT-006): the ids the engine used are the ones the
/// protocol derived from the exercise's seed, the synchronizer approves, and the new contracts are in the ACS (and can be exercised again).
#[test]
fn exercises_that_create_contracts_are_judged_and_applied() {
    let service = service();
    let bank = service.protocol_party("bank").unwrap().unwrap();
    let owner = service.protocol_party("owner").unwrap().unwrap();
    let both = vec![bank.clone(), owner.clone()];
    let held = service
        .json_create(
            &both,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank": bank, "owner": owner, "auditor": bank, "assetSymbol": "USD", "amount": "100.0"}),
                meta: None,
            },
        )
        .expect("the create is approved")
        .result
        .contract_id;
    let moved = service
        .json_exercise(
            std::slice::from_ref(&owner),
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: held.clone(),
                choice: "Transfer".into(),
                argument: json!({"newOwner": bank}),
                meta: None,
            },
        )
        .expect("the transfer is approved");
    let active = service.get_active_contracts(&[]).unwrap().active_contracts;
    assert_eq!(
        active.len(),
        1,
        "the input is gone and one holding was created"
    );
    let new_id = active[0].contract_id.clone();
    assert!(new_id.starts_with("00") && new_id.len() > 64, "{new_id}");
    assert_ne!(new_id, held);
    drop(moved);
    // a second holding is split in two (the recipient is a signatory, so it authorizes the contract it receives)
    let whole = service
        .json_create(
            &both,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank": bank, "owner": owner, "auditor": bank, "assetSymbol": "EUR", "amount": "50.0"}),
                meta: None,
            },
        )
        .expect("the create is approved")
        .result
        .contract_id;
    service
        .json_exercise(
            std::slice::from_ref(&owner),
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: whole,
                choice: "SplitTransfer".into(),
                argument: json!({"transferAmount": "30.0", "recipient": bank}),
                meta: None,
            },
        )
        .expect("the split is approved");
    let active = service.get_active_contracts(&[]).unwrap().active_contracts;
    assert_eq!(
        active.len(),
        3,
        "the transferred holding and the two the split created"
    );
    assert!(active.iter().all(|c| c.contract_id.starts_with("00")));
}

/// G8 P0 through the JSON API: a choice whose body fetches one contract, exercises a consuming choice on another (which creates a contract) and
/// creates a third (`Tree.Driver.Run`, the fixture of S-SPL-002). The engine places every node of the tree (`lf_eval::NodePaths`), the ids of the
/// contracts created below the root derive from those places, and the protocol judges the whole subtree in one view. The same transaction was
/// confirmed by the official participant in `the_official_participant_confirms_a_subtree_with_a_fetch_and_a_nested_create`; here the committer
/// has to produce what that test builds by hand.
fn tree_service() -> (ExecutionService, String, String, String) {
    let service = ExecutionService::new();
    let package = service
        .load_dar(&tree_dar())
        .expect("load the tree DAR")
        .main_package_id;
    service.set_committer(Arc::new(NodeCommitter::new(
        node_for(&tree_dar()),
        "tree-view",
        Duration::from_secs(20),
    )));
    let erin = service.protocol_party("erin").unwrap().unwrap();
    let gwen = service.protocol_party("gwen").unwrap().unwrap();
    (service, package, erin, gwen)
}

fn tree_create(
    service: &ExecutionService,
    package: &str,
    act_as: &[String],
    template: &str,
    payload: serde_json::Value,
) -> String {
    service
        .json_create(
            act_as,
            CreateRequest {
                template_id: TemplateId::new(package, "Tree", template),
                payload,
                meta: None,
            },
        )
        .unwrap_or_else(|e| panic!("create {template}: {e}"))
        .result
        .contract_id
}

fn active_templates(service: &ExecutionService) -> Vec<String> {
    let mut names: Vec<String> = service
        .get_active_contracts(&[])
        .unwrap()
        .active_contracts
        .iter()
        .map(|c| c.template_id.entity_name.clone())
        .collect();
    names.sort();
    names
}

#[test]
fn a_choice_with_a_fetch_a_nested_exercise_and_a_create_is_judged_in_one_view() {
    let (service, package, erin, gwen) = tree_service();
    let held = |service: &ExecutionService| {
        tree_create(
            service,
            &package,
            std::slice::from_ref(&erin),
            "Held",
            json!({"r": erin, "a": gwen}),
        )
    };
    let driver = tree_create(
        &service,
        &package,
        std::slice::from_ref(&gwen),
        "Driver",
        json!({"a": gwen, "r": erin}),
    );
    let peer = held(&service);
    let touched = held(&service);
    service
        .json_exercise(
            std::slice::from_ref(&gwen),
            ExerciseRequest {
                template_id: TemplateId::new(&package, "Tree", "Driver"),
                contract_id: driver,
                choice: "Run".into(),
                argument: json!({"peer": peer, "held": touched}),
                meta: None,
            },
        )
        .expect("the subtree is approved");
    // `Touch` consumed `touched` and created a `Receipt`; `Run` created a `Log`; `peer` was only read
    assert_eq!(
        active_templates(&service),
        vec!["Driver", "Held", "Log", "Receipt"],
        "the fetch left `peer`, the nested exercise took `touched`"
    );
}

/// The acting parties of a fetch are the parties that authorize the code that fetches (the signatories and controllers of the enclosing
/// exercise), not the `actAs` parties of the submission: `Driver.Run` submitted by gwen **and** erin, with gwen the choice's only controller, is
/// judged with a fetch quorum of gwen's (source: `LfTransactionUtil.actingParties`, `TransactionViewDecompositionFactory`; the engine's
/// `Fetch` event carries the authorizers).
#[test]
fn a_fetch_inside_a_choice_is_judged_with_the_authorizers_not_the_submitters() {
    let (service, package, erin, gwen) = tree_service();
    let driver = tree_create(
        &service,
        &package,
        std::slice::from_ref(&gwen),
        "Driver",
        json!({"a": gwen, "r": erin}),
    );
    let mk = |service: &ExecutionService| {
        tree_create(
            service,
            &package,
            std::slice::from_ref(&erin),
            "Held",
            json!({"r": erin, "a": gwen}),
        )
    };
    let peer = mk(&service);
    let touched = mk(&service);
    let before = active_templates(&service);
    service
        .json_exercise(
            &[gwen.clone(), erin.clone()],
            ExerciseRequest {
                template_id: TemplateId::new(&package, "Tree", "Driver"),
                contract_id: driver,
                choice: "Run".into(),
                argument: json!({"peer": peer, "held": touched}),
                meta: None,
            },
        )
        .expect("judged by the synchronizer and applied");
    assert_ne!(
        active_templates(&service),
        before,
        "the transaction was applied"
    );
}

/// G8 P6 (S-SPL-028) through the JSON API: a choice whose body catches an exception (`Scratch.Attempt`: a `try` that fetches its own contract and
/// throws) is sent with a `Rollback` node holding the fetch, and `AttemptThenCreate` creates a contract after it, whose id derives from a position
/// that counts the two fetches in the rollback (S-SPL-027). The same transactions were confirmed by the official participant in
/// `the_official_participant_confirms_*_a_rollback_*`; here the committer has to produce what those tests build by hand.
#[test]
fn a_choice_that_catches_an_exception_is_sent_with_a_rollback_node() {
    let dar = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/fixtures/lookup/target/lookup-view.dar");
    let service = ExecutionService::new();
    let package = service
        .load_dar(&dar)
        .expect("load the lookup DAR")
        .main_package_id;
    service.set_committer(Arc::new(NodeCommitter::new(
        node_for(&dar),
        "lookup-view",
        Duration::from_secs(20),
    )));
    let erin = service.protocol_party("erin").unwrap().unwrap();
    let scratch = service
        .json_create(
            std::slice::from_ref(&erin),
            CreateRequest {
                template_id: TemplateId::new(&package, "Lookup", "Scratch"),
                payload: json!({"owner": erin}),
                meta: None,
            },
        )
        .expect("create the scratch")
        .result
        .contract_id;
    for choice in ["Attempt", "AttemptThenCreate"] {
        service
            .json_exercise(
                std::slice::from_ref(&erin),
                ExerciseRequest {
                    template_id: TemplateId::new(&package, "Lookup", "Scratch"),
                    contract_id: scratch.clone(),
                    choice: choice.into(),
                    argument: json!({}),
                    meta: None,
                },
            )
            .unwrap_or_else(|e| panic!("{choice} is approved: {e}"));
    }
    // `Attempt` left everything as it was, `AttemptThenCreate` created one more `Scratch`
    let active = service.get_active_contracts(&[]).unwrap().active_contracts;
    assert_eq!(active.len(), 2, "{active:?}");
}

fn post(svc: &ExecutionService, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    use ledger_json_api::{dispatch_request, HttpRequest};
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

fn create_command(party: &str, command_id: &str) -> serde_json::Value {
    json!({
        "commands": [{
            "CreateCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": payload(party)
            }
        }],
        "userId": "u-in-flight",
        "commandId": command_id,
        "actAs": [party]
    })
}

/// The completions of `party`'s commands, as the stream lists them.
fn completions_of(svc: &ExecutionService, party: &str) -> Vec<serde_json::Value> {
    let (st, comps) = post(
        svc,
        "/v2/commands/completions",
        json!({ "userId": "u-in-flight", "parties": [party], "beginExclusive": 0 }),
    );
    assert_eq!(st, 200, "{comps}");
    comps
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["completionResponse"]["Completion"]["value"].as_object())
        .map(|c| serde_json::Value::Object(c.clone()))
        .collect()
}

fn eventually(what: &str, within: Duration, mut ok: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + within;
    while !ok() {
        assert!(std::time::Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A service whose commands wait `tracking` for their verdict, its late fates and other participants' transactions shown in it.
fn tracking_service(node: Node, tracking: Duration) -> Arc<ExecutionService> {
    let svc = Arc::new(ExecutionService::new());
    svc.load_dar(&dar()).expect("load sample dar");
    let committer = NodeCommitter::new(node, "sample-contract", Duration::from_secs(20))
        .with_tracking_timeout(tracking);
    committer.show_remote_transactions_in(Arc::clone(&svc));
    svc.set_committer(Arc::new(committer));
    svc
}

/// A Rust sequencer whose mediator runs on its own (`mediator_node`), and its state directory: a test stops and starts the mediator.
fn start_external_mediator(dir: &Path) -> (String, canton_sequencer_server::SynchronizerConfig) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = canton_sequencer_server::new_synchronizer_in(dir, "testsync", "ts1", 1).unwrap();
    let served = config.clone();
    let state = dir.to_path_buf();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(canton_sequencer_server::serve_with(
                address,
                served,
                canton_sequencer_server::ServeOptions {
                    state_dir: Some(state),
                    external_mediator: true,
                    ..Default::default()
                },
            ))
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    (format!("http://{address}"), config)
}

/// P-7: the wait for a command's verdict ends before the verdict, the verdict approves. The caller is answered as Canton's command service
/// answers (`REQUEST_TIME_OUT`, 504, not a rejection), and when the approval comes the transaction and its completion are in the service: the
/// Ledger API store and the participant agree.
#[test]
fn a_command_approved_after_its_wait_ended_is_applied_and_completed_when_the_approval_comes() {
    use canton_sequencer_server::mediator_node;
    let tmp = tempfile::tempdir().unwrap();
    let (url, _) = start_external_mediator(tmp.path());
    let node = Node::connect(&url, "late-api", &dar()).expect("node connects");
    let svc = tracking_service(node, Duration::from_millis(1));
    let bank = svc
        .protocol_party("late-bank")
        .unwrap()
        .expect("hosted party");
    // the mediator judges a first command and stops: when it comes back it reads on from where it stopped
    let mediator = mediator_node::start(&url, tmp.path(), 0).expect("the mediator joins");
    post(
        &svc,
        "/v2/commands/submit-and-wait",
        create_command(&bank, "first-create"),
    );
    eventually(
        "the first create never reached the service",
        Duration::from_secs(15),
        || {
            svc.get_active_contracts(&[])
                .unwrap()
                .active_contracts
                .len()
                == 1
        },
    );
    drop(mediator);

    let (st, err) = post(
        &svc,
        "/v2/commands/submit-and-wait",
        create_command(&bank, "late-create"),
    );
    assert_eq!(st, 504, "{err}");
    assert_eq!(err["code"], "REQUEST_TIME_OUT", "{err}");
    assert_eq!(err["grpcCodeValue"], 4, "{err}");
    assert!(
        err["cause"]
            .as_str()
            .unwrap()
            .contains("command-id=late-create"),
        "{err}"
    );
    let late = |svc: &ExecutionService| {
        completions_of(svc, &bank)
            .into_iter()
            .filter(|c| c["commandId"] == "late-create")
            .collect::<Vec<_>>()
    };
    assert!(late(&svc).is_empty(), "the command is still in flight");
    let _mediator = mediator_node::start(&url, tmp.path(), 0).expect("the mediator comes back");
    eventually(
        "the approved create never reached the service's active contracts",
        Duration::from_secs(15),
        || {
            svc.get_active_contracts(&[])
                .unwrap()
                .active_contracts
                .len()
                == 2
        },
    );
    let completions = late(&svc);
    assert_eq!(completions.len(), 1, "{completions:?}");
    assert_eq!(completions[0]["status"]["code"].as_i64().unwrap_or(0), 0);
    assert_ne!(completions[0]["updateId"], "", "{:?}", completions[0]);
    // the command was accepted: its id is taken
    let (st, dup) = post(
        &svc,
        "/v2/commands/submit-and-wait",
        create_command(&bank, "late-create"),
    );
    assert_eq!(st, 409, "{dup}");
    assert_eq!(dup["code"], "DUPLICATE_COMMAND", "{dup}");
}

/// P-7 / P-14: no mediator, so no verdict. The caller's wait ends with `REQUEST_TIME_OUT` and nothing is recorded; once the synchronizer's
/// time passes the request's decision time (learned from a time proof on this quiet synchronizer) the command completes as timed out
/// (`LOCAL_VERDICT_TIMEOUT`), with no transaction.
#[test]
fn a_command_without_a_verdict_completes_as_timed_out_at_its_decision_time() {
    let tmp = tempfile::tempdir().unwrap();
    let (url, config) = start_external_mediator(tmp.path());
    shorten_timeouts(&url, &config);
    let node = Node::connect(&url, "u31-timeout", &dar()).expect("node connects");
    let svc = tracking_service(node, Duration::from_millis(1200));
    let erin = svc
        .protocol_party("erin-timeout")
        .unwrap()
        .expect("hosted party");

    let (st, err) = post(
        &svc,
        "/v2/commands/submit-and-wait",
        create_command(&erin, "proto-timeout-1"),
    );
    assert_eq!(st, 504, "{err}");
    assert_eq!(err["code"], "REQUEST_TIME_OUT", "{err}");
    assert!(
        completions_of(&svc, &erin).is_empty(),
        "the command is still in flight"
    );
    eventually(
        "the command never completed after its decision time",
        Duration::from_secs(15),
        || !completions_of(&svc, &erin).is_empty(),
    );
    let completions = completions_of(&svc, &erin);
    assert_eq!(completions.len(), 1, "{completions:?}");
    let comp = &completions[0];
    assert_eq!(comp["commandId"], "proto-timeout-1");
    assert_eq!(comp["updateId"], "");
    assert_eq!(comp["status"]["code"], 10);
    assert!(
        comp["status"]["message"]
            .as_str()
            .unwrap()
            .starts_with("LOCAL_VERDICT_TIMEOUT(2,0): Rejected transaction due to a participant determined timeout"),
        "{comp}"
    );
    assert!(svc
        .get_active_contracts(&[])
        .unwrap()
        .active_contracts
        .is_empty());
}

/// Sets the synchronizer's confirmation response and mediator reaction timeouts to one second each (a decision time two seconds after a
/// request), as its owner does: a parameters broadcast signed by both owners of its namespace, sent by a member that joins for it.
fn shorten_timeouts(url: &str, config: &canton_sequencer_server::SynchronizerConfig) {
    use canton_participant::sequencing_wire as sw;
    use canton_participant::topology_wire as tw;
    use canton_proto::com::digitalasset::canton::protocol::v31::TopologyTransaction;
    use prost::Message;
    let physical = config.physical_synchronizer_id();
    let identity = ParticipantIdentity::generate("owner");
    let mut client = SequencerConnect::connect(url).unwrap();
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
    let mut parameters = tw::default_dynamic_parameters();
    let mut second = parameters
        .confirmation_response_timeout
        .take()
        .unwrap_or_default();
    second.seconds = 1;
    second.nanos = 0;
    parameters.confirmation_response_timeout = Some(second);
    parameters.mediator_reaction_timeout = Some(second);
    let state = tw::synchronizer_parameters_state(
        &format!("{}::{}", config.name, config.namespace_fingerprint),
        parameters,
    );
    let (data, version) = tw::unversioned(&state).unwrap();
    let mut tx = TopologyTransaction::decode(data.as_slice()).unwrap();
    tx.serial = 2;
    let bytes = tw::versioned(tx.encode_to_vec(), version);
    let signatures = vec![
        config.keys.namespace.sign_transaction(&bytes),
        config.keys.mediator_namespace.sign_transaction(&bytes),
    ];
    let broadcast = tw::topology_broadcast(&physical, &[tw::signed(bytes, signatures)]);
    let request = sw::submission_request_to_groups(
        &identity.member(),
        "short-timeouts",
        &[(vec![tw::ALL_MEMBERS.to_string()], broadcast)],
        i64::MAX,
    );
    client
        .send_async(
            &identity.member(),
            &physical,
            &token,
            sw::signed_submission_request(request, &identity.signing_key),
        )
        .unwrap();
    // in force after the topology change delay
    std::thread::sleep(Duration::from_millis(800));
}

#[test]
fn journal_compaction_and_pruned_offset_survive_restart() {
    use canton_participant::state_store::{FileStore, StateStore};
    use ledger_json_api::{dispatch_request, HttpRequest};

    let dir = tempfile::tempdir().unwrap();
    let (url, _) = start_sequencer();

    let svc = ExecutionService::new();
    svc.load_dar(&dar()).expect("load sample dar");
    svc.set_max_dedup(Duration::from_secs(0));
    let committer = Arc::new(NodeCommitter::new(
        Node::connect_in(&url, "api", &dar(), Some(dir.path())).expect("first node connect"),
        "sample-contract",
        Duration::from_secs(20),
    ));
    committer.keep_updates_in(&svc);
    svc.set_committer(committer);

    let erin = svc
        .protocol_party("erin")
        .expect("protocol")
        .expect("hosted");
    let post = |path: &str, body: serde_json::Value| -> (u16, serde_json::Value) {
        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".into(), "application/json".into());
        let resp = dispatch_request(
            &svc,
            &HttpRequest {
                method: "POST".into(),
                path: path.into(),
                query_params: Default::default(),
                headers,
                body: serde_json::to_vec(&body).unwrap(),
            },
        );
        let j = serde_json::from_slice(&resp.body).unwrap_or_default();
        (resp.status, j)
    };
    let (st1, c1) = post(
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": payload(&erin)
                    }
                }],
                "commandId": "jc-1",
                "userId": "participant_admin",
                "actAs": [erin]
            }
        }),
    );
    assert_eq!(st1, 200, "{c1}");
    let first_cid = c1["transaction"]["events"][0]["CreatedEvent"]["contractId"]
        .as_str()
        .unwrap()
        .to_string();
    let (st2, c2) = post(
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "ExerciseCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "contractId": first_cid,
                        "choice": "Archive",
                        "choiceArgument": {}
                    }
                }],
                "commandId": "jc-2",
                "userId": "participant_admin",
                "actAs": [erin]
            }
        }),
    );
    assert_eq!(st2, 200, "{c2}");
    let prune_at = svc.v2_ledger_end();
    let (st3, c3) = post(
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": payload(&erin)
                    }
                }],
                "commandId": "jc-3",
                "userId": "participant_admin",
                "actAs": [erin]
            }
        }),
    );
    assert_eq!(st3, 200, "{c3}");
    let keep_cid = c3["transaction"]["events"][0]["CreatedEvent"]["contractId"]
        .as_str()
        .unwrap()
        .to_string();

    // [CANTON-NOTE: WHY] No reconciliation tick has passed yet, so the ACS digest bound (P-15) refuses any prune; this test is about the
    // journals, so it prunes past that bound as the node's `ignoreCommitments` does.
    let (st_p, prune_body) = post(
        "/v2/admin/prune",
        json!({ "pruneUpTo": prune_at, "ignoreCommitments": true }),
    );
    assert_eq!(st_p, 200, "{prune_body}");
    assert!(svc.v2_contract(&first_cid).is_none());
    assert!(svc.v2_contract(&keep_cid).is_some());

    // Journals on disk must only keep entries after `prune_at` plus `pruned.journal`
    let store: Arc<dyn StateStore> = FileStore::new(dir.path()).unwrap();
    assert_eq!(
        store
            .read("pruned.journal")
            .unwrap()
            .as_deref()
            .map(str::trim),
        Some(prune_at.to_string().as_str())
    );
    let updates_lines = store
        .read("updates.journal")
        .unwrap()
        .unwrap_or_default()
        .lines()
        .count();
    assert_eq!(updates_lines, 1);

    // Drop first node/service before restarting from the same directory & sequencer
    drop(svc);
    let restarted = ExecutionService::new();
    restarted.load_dar(&dar()).expect("load sample dar");
    let committer2 = Arc::new(NodeCommitter::new(
        Node::connect_in(&url, "api", &dar(), Some(dir.path())).expect("restarted node connect"),
        "sample-contract",
        Duration::from_secs(20),
    ));
    let loaded = committer2.keep_updates_in(&restarted);
    assert_eq!(loaded, 1);
    let pruned_resp = dispatch_request(
        &restarted,
        &HttpRequest {
            method: "GET".into(),
            path: "/v2/state/latest-pruned-offsets".into(),
            query_params: Default::default(),
            headers: Default::default(),
            body: Vec::new(),
        },
    );
    assert_eq!(pruned_resp.status, 200);
    let pruned_json: serde_json::Value = serde_json::from_slice(&pruned_resp.body).unwrap();
    assert_eq!(pruned_json["participantPrunedUpToInclusive"], prune_at);
}

fn events_dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/events-dar/events-oracle.dar")
}

/// A choice with an `observer` clause (`Events:Gift.Share`, observer `other`): the view the Rust participant sends must list the choice
/// observer among its informees, or its own conformance check refuses the exercise with `InformeesDiffer` (AUDIT U-50, 2026-11-24:
/// `scripts/verify-official-events.sh` step `ora-share-1`).
#[test]
fn an_exercise_of_a_choice_with_its_own_observer_is_approved() {
    let service = ExecutionService::new();
    service.load_dar(&events_dar()).expect("load events dar");
    service.set_committer(Arc::new(NodeCommitter::new(
        node_for(&events_dar()),
        "events-oracle",
        Duration::from_secs(20),
    )));
    let pkg = service
        .packages_named("events-oracle")
        .into_iter()
        .next()
        .expect("events-oracle loaded");
    let gift = TemplateId::new(pkg, "Events", "Gift");
    let owner = service.protocol_party("owner").unwrap().unwrap();
    let watcher = service.protocol_party("watcher").unwrap().unwrap();
    let other = service.protocol_party("other").unwrap().unwrap();
    let id = service
        .json_create(
            std::slice::from_ref(&owner),
            CreateRequest {
                template_id: gift.clone(),
                payload: json!({"owner": owner, "watcher": watcher}),
                meta: None,
            },
        )
        .expect("the create is approved")
        .result
        .contract_id;
    service
        .json_exercise(
            std::slice::from_ref(&owner),
            ExerciseRequest {
                template_id: gift,
                contract_id: id,
                choice: "Share".into(),
                argument: json!({"other": other}),
                meta: None,
            },
        )
        .expect("the exercise with a choice observer is approved");
}

fn querynkey_dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/fixtures/querynkey/target/querynkey-view.dar")
}

fn texts(value: Option<ValueBox>) -> Vec<String> {
    match value {
        Some(ValueBox(lf_eval::Value::List(list))) => list
            .to_vec()
            .into_iter()
            .map(|v| match v {
                lf_eval::Value::Text(t) => t,
                other => panic!("a note is text, got {other:?}"),
            })
            .collect(),
        other => panic!("QueryN returns a list, got {other:?}"),
    }
}

/// `lookupNByKey` (Daml-LF `QueryNByKey`) on the protocol path (UNRESOLVED U-21): several contracts share a key, the choice asks for at
/// most `n` of them, and the Rust participant's own conformance check accepts the views it sends (the query is a node of the transaction).
#[test]
fn a_query_of_n_contracts_by_key_is_judged_and_returns_at_most_n() {
    let service = ExecutionService::new();
    service
        .load_dar(&querynkey_dar())
        .expect("load querynkey dar");
    service.set_committer(Arc::new(NodeCommitter::new(
        node_for(&querynkey_dar()),
        "querynkey-view",
        Duration::from_secs(20),
    )));
    let pkg = service
        .packages_named("querynkey-view")
        .into_iter()
        .next()
        .expect("querynkey-view loaded");
    let item = TemplateId::new(pkg, "QueryN", "Item");
    let owner = service.protocol_party("owner").unwrap().unwrap();
    let mut ids = Vec::new();
    for note in ["a", "b", "c"] {
        ids.push(
            service
                .json_create(
                    std::slice::from_ref(&owner),
                    CreateRequest {
                        template_id: item.clone(),
                        payload: json!({"owner": owner, "label": "k", "note": note}),
                        meta: None,
                    },
                )
                .expect("the create is approved")
                .result
                .contract_id,
        );
    }
    let query = |n: i64, wanted: &str| {
        texts(
            service
                .json_exercise(
                    std::slice::from_ref(&owner),
                    ExerciseRequest {
                        template_id: item.clone(),
                        contract_id: ids[0].clone(),
                        choice: "QueryN".into(),
                        argument: json!({"n": n.to_string(), "wanted": wanted}),
                        meta: None,
                    },
                )
                .unwrap_or_else(|e| panic!("QueryN {n} {wanted} is approved: {e:?}"))
                .result
                .result_value,
        )
    };
    assert_eq!(query(10, "k"), vec!["a", "b", "c"]);
    assert_eq!(query(2, "k").len(), 2);
    assert!(query(5, "none").is_empty());
}
