//! G11 / S-LOCAL-002: two JSON API services, each with its own Rust participant, on one Rust synchronizer. A contract that alice's participant
//! creates with bob as an observer shows up in bob's participant's API (the transaction was approved by the synchronizer and sent to bob's
//! participant), and archiving it makes it disappear there too. No JVM.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "protocol")]
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use canton_participant::node::Node;
use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::protocol::NodeCommitter;
use ledger_json_api::service::ExecutionService;
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

/// A participant on the synchronizer at `url` with a JSON API service in front of it.
fn participant(url: &str, name: &str) -> Arc<ExecutionService> {
    let node = Node::connect(url, name, &dar()).expect("the participant joins the synchronizer");
    let service = Arc::new(ExecutionService::new());
    service.load_dar(&dar()).expect("load the DAR");
    let committer = Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(30),
    ));
    committer.show_remote_transactions_in(Arc::clone(&service));
    service.set_committer(committer);
    service
}

fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ok() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_contract_alices_participant_creates_shows_in_bobs_api_and_its_archival_too() {
    let url = synchronizer();
    let alpha = participant(&url, "alpha");
    let beta = participant(&url, "beta");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let bob = beta.protocol_party("bob").unwrap().unwrap();
    assert_ne!(alice.split("::").nth(1), None);
    // bob only observes: alice is the one signatory, so one submission is enough
    let id = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank": alice, "owner": alice, "auditor": bob, "assetSymbol": "USD", "amount": "42.0"}),
                meta: None,
            },
        )
        .expect("the create is approved by the synchronizer")
        .result
        .contract_id;
    assert!(
        id.starts_with("00") && id.len() > 64,
        "a protocol contract id: {id}"
    );
    eventually("bob's API never showed the contract", || {
        beta.get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .iter()
            .any(|c| c.contract_id == id)
    });
    let shown = beta
        .get_active_contracts(&[])
        .unwrap()
        .active_contracts
        .into_iter()
        .find(|c| c.contract_id == id)
        .unwrap();
    assert_eq!(shown.signatories, vec![alice.clone()]);
    assert_eq!(shown.observers, vec![bob]);
    assert_eq!(shown.create_arguments["amount"], json!("42.0000000000"));
    assert_eq!(shown.create_arguments["assetSymbol"], json!("USD"));

    // alice settles it: the contract is gone on both sides
    alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: id,
                choice: "Settle".into(),
                argument: json!({}),
                meta: None,
            },
        )
        .expect("the settle is approved");
    assert!(alpha
        .get_active_contracts(&[])
        .unwrap()
        .active_contracts
        .is_empty());
    eventually("bob's API never dropped the archived contract", || {
        beta.get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .is_empty()
    });
}

/// A participant that is restarted shows the same contracts through a service that starts fresh (S-LOCAL-005): the node's state directory held
/// what alice's participant created for bob, and the new service's ACS has it from the first call.
#[test]
fn a_restarted_participant_shows_its_contracts_through_a_fresh_service() {
    use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
    let url = synchronizer();
    let dir = std::env::temp_dir().join(format!("two-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let alpha = participant(&url, "alpha");
    // beta keeps its state in a directory
    let node = Node::connect_in(&url, "beta", &dar(), Some(&dir)).expect("beta joins");
    let beta_service = Arc::new(ExecutionService::new());
    beta_service.load_dar(&dar()).unwrap();
    let committer = Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(30),
    ));
    committer.show_remote_transactions_in(Arc::clone(&beta_service));
    beta_service.set_committer(Arc::clone(&committer) as Arc<_>);
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let bob = beta_service.protocol_party("bob").unwrap().unwrap();
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
    eventually("bob's API never showed the contract", || {
        beta_service
            .get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .iter()
            .any(|c| c.contract_id == id)
    });

    // restart beta: the service is dropped, the node is opened again from its directory with the identity that was kept
    beta_service.clear_committer();
    let committer = Arc::try_unwrap(committer)
        .ok()
        .expect("the service let go of the committer");
    let node = committer.into_node();
    let identity = node.identity;
    let physical = {
        let mut c = SequencerConnect::connect(&url).unwrap();
        c.synchronizer_id().unwrap().physical_synchronizer_id
    };
    let mut client = SequencerConnect::connect(&url).unwrap();
    let challenge = client.challenge(&identity.member(), &[37]).unwrap();
    let signature = identity
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = client
        .authenticate(&identity.member(), &challenge.nonce, signature)
        .unwrap();
    let node = Node::open_in(identity, client, token, &physical, &dar(), 0, Some(&dir))
        .expect("beta opens again from its directory");
    let fresh = Arc::new(ExecutionService::new());
    fresh.load_dar(&dar()).unwrap();
    let committer = Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(30),
    ));
    let shown = committer.show_known_contracts_in(&fresh).unwrap();
    assert_eq!(shown, 1, "the node kept the contract alice created for bob");
    let contracts = fresh.get_active_contracts(&[]).unwrap().active_contracts;
    assert_eq!(contracts.len(), 1);
    assert_eq!(contracts[0].contract_id, id);
    assert_eq!(
        contracts[0].create_arguments["amount"],
        json!("7.0000000000")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remote_approved_transactions_and_non_creating_exercises_record_scan_history_and_acs_snapshots() {
    use canton_participant::scan_api::UpdateHistory;
    use ledger_json_api::history::UpdateRecorder;

    let url = synchronizer();
    let dir = std::env::temp_dir().join(format!("two-scan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let attach_history = |url: &str, name: &str, hist_path: &Path| {
        let node = Node::connect(url, name, &dar()).expect("join");
        let service = Arc::new(ExecutionService::new());
        service.load_dar(&dar()).expect("load dar");
        let recorder = Arc::new(UpdateRecorder::new(hist_path, "testsync::ts1", 0));
        service.set_update_recorder(Arc::clone(&recorder));
        let committer = Arc::new(NodeCommitter::new(
            node,
            "sample-contract",
            Duration::from_secs(30),
        ));
        committer.record_salts_in(recorder);
        committer.show_remote_transactions_in(Arc::clone(&service));
        service.set_committer(committer);
        service
    };

    let alpha_hist = dir.join("alpha.jsonl");
    let beta_hist = dir.join("beta.jsonl");
    let beta_auth = dir.join("beta.jsonl.auth");
    let alpha = attach_history(&url, "alpha", &alpha_hist);
    let beta = attach_history(&url, "beta", &beta_hist);

    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let bob = beta.protocol_party("bob").unwrap().unwrap();

    let cid = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({
                    "bank": alice,
                    "owner": alice,
                    "auditor": bob,
                    "assetSymbol": "USD",
                    "amount": "9.5"
                }),
                meta: None,
            },
        )
        .expect("create succeeds")
        .result
        .contract_id;

    let read_lines = |p: &Path| -> Vec<serde_json::Value> {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    };

    eventually("beta never recorded remote create update + salt", || {
        read_lines(&beta_hist).len() == 1 && read_lines(&beta_auth).len() == 1
    });

    let t1 = read_lines(&beta_hist)[0]["record_time"]
        .as_str()
        .unwrap()
        .to_string();

    // Verify beta's recorded remote history serves /v2/state/acs with a real created_event_blob
    let mut auth_map = std::collections::HashMap::new();
    for entry in read_lines(&beta_auth) {
        let id = entry["contract_id"].as_str().unwrap().to_string();
        let hex_str = entry["authentication_data"].as_str().unwrap();
        let bytes: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
            .collect();
        auth_map.insert(id, bytes);
    }
    let scan_t1 = UpdateHistory::new(read_lines(&beta_hist))
        .with_contracts(
            vec![lf_eval::World::open(&dar()).unwrap()],
            auth_map.clone(),
        )
        .unwrap();
    let acs_t1 = scan_t1.handle(
        "POST",
        "/api/scan/v2/state/acs",
        &json!({ "migration_id": 0, "record_time": t1, "page_size": 10 }).to_string(),
    );
    assert_eq!(acs_t1.status, 200, "{}", acs_t1.body);
    let acs_t1_json: serde_json::Value = serde_json::from_str(&acs_t1.body).unwrap();
    assert_eq!(acs_t1_json["created_events"][0]["contract_id"], cid);
    assert!(
        !acs_t1_json["created_events"][0]["created_event_blob"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "expected non-empty created_event_blob from recorded salt"
    );

    // Non-creating exercise (Settle) uses deterministic protocol timestamp and is also recorded by beta
    alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid,
                choice: "Settle".into(),
                argument: json!({}),
                meta: None,
            },
        )
        .expect("settle succeeds");

    eventually("beta never recorded remote Settle archive", || {
        read_lines(&beta_hist).len() == 2
    });
    let alpha_updates = read_lines(&alpha_hist);
    assert_eq!(alpha_updates.len(), 2);
    assert_ne!(
        alpha_updates[1]["effective_at"].as_str(),
        Some(alpha_updates[1]["record_time"].as_str().unwrap()),
        "protocol non-creating exercise effective_at should reflect synchronizer time rather than fallback record_time"
    );

    let beta_updates = read_lines(&beta_hist);
    let t2 = beta_updates[1]["record_time"].as_str().unwrap().to_string();
    let scan_t2 = UpdateHistory::new(beta_updates)
        .with_contracts(vec![lf_eval::World::open(&dar()).unwrap()], auth_map)
        .unwrap();
    let acs_t2 = scan_t2.handle(
        "POST",
        "/api/scan/v2/state/acs",
        &json!({ "migration_id": 0, "record_time": t2, "page_size": 10 }).to_string(),
    );
    assert_eq!(acs_t2.status, 200, "{}", acs_t2.body);
    assert!(
        serde_json::from_str::<serde_json::Value>(&acs_t2.body).unwrap()["created_events"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A participant with a JSON API service in front of it, and its committer.
fn participant_with_committer(
    url: &str,
    name: &str,
) -> (Arc<ExecutionService>, Arc<NodeCommitter>) {
    let node = Node::connect(url, name, &dar()).expect("the participant joins the synchronizer");
    let service = Arc::new(ExecutionService::new());
    service.load_dar(&dar()).expect("load the DAR");
    let committer = Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(30),
    ));
    committer.show_remote_transactions_in(Arc::clone(&service));
    service.set_committer(Arc::clone(&committer) as _);
    (service, committer)
}

/// Creates an `AssetHolding` of `bank` audited by `auditor` through `/v2/commands/submit-and-wait-for-transaction`; its contract id.
fn v2_create(service: &ExecutionService, bank: &str, auditor: &str, amount: &str) -> String {
    let mut headers = std::collections::HashMap::new();
    headers.insert("content-type".into(), "application/json".into());
    let body = json!({
        "commands": {
            "commands": [{
                "CreateCommand": {
                    "templateId": "#sample-contract:AssetHolding:AssetHolding",
                    "createArguments": {"bank": bank, "owner": bank, "auditor": auditor, "assetSymbol": "USD", "amount": amount}
                }
            }],
            "commandId": format!("create-{amount}-{}", std::process::id()),
            "userId": "participant_admin",
            "actAs": [bank]
        }
    });
    let resp = ledger_json_api::dispatch_request(
        service,
        &ledger_json_api::HttpRequest {
            method: "POST".into(),
            path: "/v2/commands/submit-and-wait-for-transaction".into(),
            query_params: Default::default(),
            headers,
            body: serde_json::to_vec(&body).unwrap(),
        },
    );
    let answer: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
    assert_eq!(resp.status, 200, "{answer}");
    answer["transaction"]["events"][0]["CreatedEvent"]["contractId"]
        .as_str()
        .unwrap()
        .to_string()
}

/// P-9 / P-15: two Rust participants that share a contract send each other ACS commitments at the first event past a reconciliation
/// boundary, and find them matching; pruning waits for that tick (the "ACS digest ingestion" bound) and not only for the deduplication
/// window.
#[test]
fn shared_contracts_are_committed_to_matched_and_bound_pruning() {
    let url = synchronizer();
    let (alpha, alpha_committer) = participant_with_committer(&url, "alpha-cmt");
    let (beta, beta_committer) = participant_with_committer(&url, "beta-cmt");
    let committers = [alpha_committer, beta_committer];
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let bob = beta.protocol_party("bob").unwrap().unwrap();
    v2_create(&alpha, &alice, &bob, "1.0");
    v2_create(&alpha, &alice, &bob, "1.5");
    alpha.set_max_dedup(Duration::ZERO);
    let end = alpha.v2_ledger_end() as i64;
    assert_eq!(
        ledger_json_api::v2_prune::safe_pruning_offset(&alpha, None, end, false).unwrap(),
        None,
        "before the first commitment tick nothing is safe to prune"
    );
    assert!(
        ledger_json_api::v2_prune::safe_pruning_offset(&alpha, None, end, true)
            .unwrap()
            .is_some(),
        "the deduplication window alone allows it"
    );

    // past the next boundary, an event both participants see makes the tick
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    std::thread::sleep(Duration::from_secs(61 - now.as_secs() % 60));
    v2_create(&alpha, &alice, &bob, "2.0");
    let deadline = Instant::now() + Duration::from_secs(60);
    let matched = |c: &NodeCommitter| {
        c.commitment_periods()
            .iter()
            .any(|p| p.verdict == canton_participant::acs_commitment::PeriodVerdict::Matched)
    };
    while !(committers.iter().all(|c| matched(c))) {
        assert!(
            Instant::now() < deadline,
            "the commitments never matched: {:?}",
            committers
                .iter()
                .map(|c| c.commitment_periods())
                .collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    for c in &committers {
        assert!(
            !c.commitment_periods().iter().any(|p| matches!(
                p.verdict,
                canton_participant::acs_commitment::PeriodVerdict::Mismatched { .. }
            )),
            "{:?}",
            c.commitment_periods()
        );
    }
    assert!(
        ledger_json_api::v2_prune::safe_pruning_offset(&alpha, None, end, false)
            .unwrap()
            .is_some(),
        "the first contract is before the tick: safe to prune"
    );
}

/// P-14: the repair service's purge and import change the participant's protocol ledger, not only the API's store, and an import
/// authenticates every contract before it adds any.
#[test]
fn repair_changes_the_protocol_ledger_and_imports_only_authentic_contracts() {
    use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
    use ledger_json_api::admin_state;
    use prost::Message;
    let url = synchronizer();
    let (alpha, committer) = participant_with_committer(&url, "alpha-repair");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let first = v2_create(&alpha, &alice, &alice, "1.0");
    let second = v2_create(&alpha, &alice, &alice, "2.0");
    assert!(committer.protocol_is_active(&first));
    let sync = admin_state::list_registered_syncs(&alpha)
        .into_iter()
        .next()
        .expect("a synchronizer");
    let export = admin_state::export_acs(
        &alpha,
        std::slice::from_ref(&alice),
        &sync.synchronizer_id,
        alpha.v2_ledger_end() as i64,
        &Default::default(),
        &[],
    )
    .unwrap();

    admin_state::purge_contracts(&alpha, &sync.alias, &[first.clone(), second.clone()], false)
        .unwrap();
    assert!(
        !committer.protocol_is_active(&first) && !committer.protocol_is_active(&second),
        "a purge removes the contracts from the protocol ledger"
    );

    // the first record carries the second contract's instance: not authentic for its id, and nothing is imported
    let mut frames: Vec<serde_json::Value> = Vec::new();
    let mut slice = export.as_slice();
    while !slice.is_empty() {
        let frame = p30::ActiveContract::decode_length_delimited(&mut slice).unwrap();
        frames.push(serde_json::from_slice(&frame.active_contract).unwrap());
    }
    let encode = |frames: &[serde_json::Value]| {
        let mut out = Vec::new();
        for f in frames {
            p30::ActiveContract {
                active_contract: serde_json::to_vec(f).unwrap(),
            }
            .encode_length_delimited(&mut out)
            .unwrap();
        }
        out
    };
    let blob_of = |id: &str| {
        frames.iter().find(|f| f["contract_id"] == id).unwrap()["created_event_blob"].clone()
    };
    let mut tampered = frames.clone();
    for f in &mut tampered {
        if f["contract_id"] == first.as_str() {
            f["created_event_blob"] = blob_of(&second);
        }
    }
    let import = |bytes: &[u8]| {
        admin_state::import_acs(
            &alpha,
            bytes,
            None,
            1,
            &[],
            &sync.synchronizer_id,
            &Default::default(),
        )
    };
    let refused = import(&encode(&tampered)).expect_err("an inauthentic contract is refused");
    assert!(refused.1.contains("IMPORT_ACS_ERROR"), "{refused:?}");
    assert!(
        !committer.protocol_is_active(&first) && !committer.protocol_is_active(&second),
        "all or none"
    );

    assert_eq!(import(&encode(&frames)).unwrap(), 2);
    assert!(committer.protocol_is_active(&first) && committer.protocol_is_active(&second));
    // the repaired contract is one the participant can exercise
    alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: first.clone(),
                choice: "Settle".into(),
                argument: json!({}),
                meta: None,
            },
        )
        .expect("the settle of the imported contract is approved");
    assert!(!committer.protocol_is_active(&first));
}

#[test]
fn remote_transaction_reaches_receiving_participant_exex_subscriber() {
    use ledger_json_api::exex::{ExExContractEvent, ExExNotification, ExExPartyScope};
    use std::collections::BTreeSet;

    let url = synchronizer();
    let alpha = participant(&url, "alpha-exex");
    let beta = participant(&url, "beta-exex");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let bob = beta.protocol_party("bob").unwrap().unwrap();

    let mut bob_set = BTreeSet::new();
    bob_set.insert(bob.clone());
    let rx_bob =
        beta.exex()
            .register_channel("beta-bob-exex", ExExPartyScope::Parties(bob_set), 16);

    let mut eve_set = BTreeSet::new();
    eve_set.insert("Eve::12200000".to_string());
    let rx_eve =
        beta.exex()
            .register_channel("beta-eve-exex", ExExPartyScope::Parties(eve_set), 16);

    let cid = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank": alice, "owner": alice, "auditor": bob, "assetSymbol": "EUR", "amount": "77.0"}),
                meta: None,
            },
        )
        .expect("alice create")
        .result
        .contract_id;

    let deadline = Instant::now() + Duration::from_secs(15);
    let notif = loop {
        if let Ok(msg) = rx_bob.try_recv() {
            break msg;
        }
        assert!(
            Instant::now() < deadline,
            "beta ExEx subscriber never received remote transaction for {cid}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    match notif {
        ExExNotification::Committed {
            seq,
            offset,
            events,
            ..
        } => {
            assert_eq!(seq, 1);
            assert!(offset >= 1);
            assert!(events.iter().any(|ev| match ev {
                ExExContractEvent::Created { contract_id, .. } => contract_id == &cid,
                _ => false,
            }));
        }
        other => panic!("unexpected notification: {other:?}"),
    }
    assert!(
        rx_eve.try_recv().is_err(),
        "non-stakeholder Eve ExEx on beta must not receive remote transaction"
    );
}

/// R-13k: submitting and remote participants must assign the exact same 34-byte Merkle `root_hash` `updateId` (`1220...`)
/// so `POST /v2/updates/update-by-id` succeeds with the identical ID on both participants.
#[test]
fn r13k_remote_and_local_update_id_match_on_update_by_id() {
    let url = synchronizer();
    let alpha = participant(&url, "alpha-r13k");
    let beta = participant(&url, "beta-r13k");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let bob = beta.protocol_party("bob").unwrap().unwrap();

    let post_json =
        |svc: &ExecutionService, path: &str, body: serde_json::Value| -> (u16, serde_json::Value) {
            let mut headers = std::collections::HashMap::new();
            headers.insert("content-type".into(), "application/json".into());
            let resp = ledger_json_api::dispatch_request(
                svc,
                &ledger_json_api::HttpRequest {
                    method: "POST".into(),
                    path: path.into(),
                    query_params: Default::default(),
                    headers,
                    body: serde_json::to_vec(&body).unwrap(),
                },
            );
            (
                resp.status,
                serde_json::from_slice(&resp.body).unwrap_or_default(),
            )
        };

    let (st_sub_local, body_local) = post_json(
        &alpha,
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": {
                            "bank": &alice,
                            "owner": &alice,
                            "auditor": &alice,
                            "assetSymbol": "USD",
                            "amount": "11.0"
                        }
                    }
                }],
                "commandId": "r13k-alpha-only-offset-skew",
                "userId": "participant_admin",
                "actAs": [&alice]
            }
        }),
    );
    assert_eq!(st_sub_local, 200, "{body_local}");

    let (st_sub, body_sub) = post_json(
        &alpha,
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": {
                            "bank": &alice,
                            "owner": &alice,
                            "auditor": &bob,
                            "assetSymbol": "USD",
                            "amount": "55.0"
                        }
                    }
                }],
                "commandId": "r13k-shared-create",
                "userId": "participant_admin",
                "actAs": [&alice]
            }
        }),
    );
    assert_eq!(st_sub, 200, "{body_sub}");
    let alpha_uid = body_sub["transaction"]["updateId"]
        .as_str()
        .unwrap()
        .to_string();
    let alpha_offset = body_sub["transaction"]["offset"].as_u64().unwrap();
    let cid = body_sub["transaction"]["events"][0]["CreatedEvent"]["contractId"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        alpha_uid.starts_with("1220")
            && alpha_uid.len() == 68
            && alpha_uid.chars().all(|c| c.is_ascii_hexdigit()),
        "expected 68-char 1220... Merkle root_hash updateId on alpha: {alpha_uid}"
    );
    assert_ne!(
        alpha_uid,
        format!("1220{alpha_offset:064x}"),
        "updateId must be Merkle root_hash, not offset-synthesized"
    );

    eventually("beta never received remote contract", || {
        beta.v2_contract(&cid).is_some()
    });

    let lookup_body = |party: &str, uid: &str| {
        json!({
            "updateId": uid,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": {
                        "filtersByParty": { party: {} },
                        "verbose": false
                    },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                }
            }
        })
    };

    let (st_a, by_id_a) = post_json(
        &alpha,
        "/v2/updates/update-by-id",
        lookup_body(&alice, &alpha_uid),
    );
    assert_eq!(
        st_a, 200,
        "alpha update-by-id failed for {alpha_uid}: {by_id_a}"
    );
    let (st_b, by_id_b) = post_json(
        &beta,
        "/v2/updates/update-by-id",
        lookup_body(&bob, &alpha_uid),
    );
    assert_eq!(
        st_b, 200,
        "beta remote update-by-id must succeed with alpha's exact updateId {alpha_uid}: {by_id_b}"
    );
    let beta_offset = by_id_b["update"]["Transaction"]["value"]["offset"]
        .as_u64()
        .unwrap();
    assert_ne!(
        alpha_offset, beta_offset,
        "alpha and beta offsets must differ to prove updateId is not offset-derived"
    );
    assert_ne!(
        alpha_uid,
        format!("1220{beta_offset:064x}"),
        "updateId must not equal beta offset-synthesized id"
    );
    assert_eq!(
        by_id_a["update"]["Transaction"]["value"]["updateId"],
        by_id_b["update"]["Transaction"]["value"]["updateId"]
    );
    assert_eq!(
        by_id_b["update"]["Transaction"]["value"]["events"][0]["CreatedEvent"]["contractId"],
        cid
    );

    // Negative controls: unknown hex updateId and non-stakeholder party filter return 404.
    let (st_miss, _) = post_json(
        &beta,
        "/v2/updates/update-by-id",
        lookup_body(
            &bob,
            &"1220"
                .chars()
                .chain(std::iter::repeat_n('0', 64))
                .collect::<String>(),
        ),
    );
    assert_eq!(st_miss, 404);
    let (st_other, _) = post_json(
        &beta,
        "/v2/updates/update-by-id",
        lookup_body("stranger::12200000", &alpha_uid),
    );
    assert_eq!(st_other, 404);
}

#[test]
fn r13a_journal_sink_failure_and_command_scoping_preserve_unrecorded_fates() {
    let url = synchronizer();
    let state_dir = tempfile::tempdir().unwrap();

    let node = Node::connect_in(&url, "alpha-r13a", &dar(), Some(state_dir.path()))
        .expect("join with file store");
    let svc = Arc::new(ExecutionService::new());
    svc.load_dar(&dar()).expect("load dar");
    let committer = Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(30),
    ));
    committer.keep_updates_in(&svc);
    svc.set_committer(committer);

    let alice = svc.protocol_party("alice").unwrap().unwrap();
    let post_create = |svc: &ExecutionService, cmd_id: &str| -> (u16, serde_json::Value) {
        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".into(), "application/json".into());
        let resp = ledger_json_api::dispatch_request(
            svc,
            &ledger_json_api::HttpRequest {
                method: "POST".into(),
                path: "/v2/commands/submit-and-wait-for-transaction".into(),
                query_params: Default::default(),
                headers,
                body: serde_json::to_vec(&json!({
                    "commands": {
                        "commands": [{
                            "CreateCommand": {
                                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                                "createArguments": {
                                    "bank": &alice,
                                    "owner": &alice,
                                    "auditor": &alice,
                                    "assetSymbol": "USD",
                                    "amount": "25.0"
                                }
                            }
                        }],
                        "commandId": cmd_id,
                        "userId": "participant_admin",
                        "actAs": [&alice]
                    }
                }))
                .unwrap(),
            },
        );
        (
            resp.status,
            serde_json::from_slice(&resp.body).unwrap_or_default(),
        )
    };

    // Block `updates.journal` by creating a directory with that name so `append_journal` fails (EISDIR).
    let blocked_journal = state_dir.path().join("updates.journal");
    std::fs::create_dir_all(&blocked_journal).unwrap();
    let (st_fail, body_fail) = post_create(&svc, "r13a-journal-fail");
    assert_ne!(
        st_fail, 200,
        "journal sink failure when writing updates.journal must not return 200 or mark command recorded: {body_fail}"
    );

    // Unblock `updates.journal`, then submit a second command on the SAME thread: its `command_recorded`
    // must NOT sweep `r13a-journal-fail` out of the awaited queue on this thread.
    std::fs::remove_dir_all(&blocked_journal).unwrap();
    let (st_ok, body_ok) = post_create(&svc, "r13a-ok-peer");
    assert_eq!(st_ok, 200, "{body_ok}");
    drop(svc);

    // Reopen node from the same state directory: `r13a-journal-fail` must still be handed over as unshown/late.
    let reopened = Node::connect_in(&url, "alpha-r13a", &dar(), Some(state_dir.path()))
        .expect("reopen from file store");
    let shared = canton_participant::node::SharedNode::new(reopened);
    let late_ids: Vec<String> = shared
        .with(|n| n.take_late_fates().unwrap_or_default())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|f| {
            serde_json::from_str::<serde_json::Value>(&f.settled.tag)
                .ok()
                .and_then(|v| v["command_id"].as_str().map(str::to_string))
        })
        .collect();
    let unshown = shared.take_unshown().unwrap_or_default();
    assert!(
        late_ids.iter().any(|id| id == "r13a-journal-fail") || !unshown.is_empty(),
        "unrecorded cmd r13a-journal-fail must remain recoverable across restart (late={late_ids:?}, unshown={})",
        unshown.len()
    );
}

#[test]
fn r13a_failed_update_journal_does_not_expose_completion_or_advance_ledger_end() {
    let url = synchronizer();
    let state_dir = tempfile::tempdir().unwrap();

    let node = Node::connect_in(&url, "alpha-r13a-order", &dar(), Some(state_dir.path()))
        .expect("join with file store");
    let svc = Arc::new(ExecutionService::new());
    svc.load_dar(&dar()).expect("load dar");
    let committer = Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(30),
    ));
    committer.keep_updates_in(&svc);
    svc.set_committer(committer);

    let alice = svc.protocol_party("alice").unwrap().unwrap();
    let call = |method: &str, path: &str, body: serde_json::Value| -> (u16, serde_json::Value) {
        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".into(), "application/json".into());
        let resp = ledger_json_api::dispatch_request(
            &svc,
            &ledger_json_api::HttpRequest {
                method: method.into(),
                path: path.into(),
                query_params: Default::default(),
                headers,
                body: if body.is_null() {
                    Vec::new()
                } else {
                    serde_json::to_vec(&body).unwrap()
                },
            },
        );
        (
            resp.status,
            serde_json::from_slice(&resp.body).unwrap_or_default(),
        )
    };

    let blocked_journal = state_dir.path().join("updates.journal");
    std::fs::create_dir_all(&blocked_journal).unwrap();
    let (st_fail, body_fail) = call(
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": {
                            "bank": &alice,
                            "owner": &alice,
                            "auditor": &alice,
                            "assetSymbol": "USD",
                            "amount": "25.0"
                        }
                    }
                }],
                "commandId": "r13a-order-fail",
                "userId": "participant_admin",
                "actAs": [&alice]
            }
        }),
    );
    assert_eq!(
        st_fail, 500,
        "update journal failure must return 500: {body_fail}"
    );
    let (_, end_body) = call("GET", "/v2/state/ledger-end", serde_json::Value::Null);
    assert_eq!(
        end_body["offset"],
        json!(0),
        "failed update journal must NOT advance ledger_end: {end_body}"
    );
    let (st_comp, comps) = call(
        "POST",
        "/v2/commands/completions",
        json!({ "userId": "participant_admin", "parties": [&alice], "beginExclusive": 0 }),
    );
    assert_eq!(st_comp, 200, "{comps}");
    let completion_count = comps
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["completionResponse"].get("Completion").is_some())
        .count();
    assert_eq!(
        completion_count, 0,
        "failed update journal must NOT expose completion before update persists: {comps}"
    );
    assert!(
        !state_dir.path().join("completions.journal").exists(),
        "failed update journal must not create completions.journal on disk"
    );
}

#[test]
fn r13a_remote_update_journal_failure_preserves_unshown_across_restart() {
    let url = synchronizer();
    let alpha = participant(&url, "alpha-r13a-rem");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();

    let beta_dir = tempfile::tempdir().unwrap();
    let (bob, cid, alpha_uid) = {
        let beta_node = Node::connect_in(&url, "beta-r13a-rem", &dar(), Some(beta_dir.path()))
            .expect("beta joins with file store");
        let beta = Arc::new(ExecutionService::new());
        beta.load_dar(&dar()).expect("load dar");
        let committer = Arc::new(NodeCommitter::new(
            beta_node,
            "sample-contract",
            Duration::from_secs(30),
        ));
        committer.keep_updates_in(&beta);
        committer.show_remote_transactions_in(Arc::clone(&beta));
        beta.set_committer(committer);

        let bob = beta.protocol_party("bob").unwrap().unwrap();
        std::fs::create_dir_all(beta_dir.path().join("updates.journal")).unwrap();

        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".into(), "application/json".into());
        let create_resp = ledger_json_api::dispatch_request(
            &alpha,
            &ledger_json_api::HttpRequest {
                method: "POST".into(),
                path: "/v2/commands/submit-and-wait-for-transaction".into(),
                query_params: Default::default(),
                headers,
                body: serde_json::to_vec(&json!({
                    "commands": {
                        "commands": [{
                            "CreateCommand": {
                                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                                "createArguments": {
                                    "bank": &alice,
                                    "owner": &alice,
                                    "auditor": &bob,
                                    "assetSymbol": "USD",
                                    "amount": "33.0"
                                }
                            }
                        }],
                        "commandId": "r13a-remote-fail",
                        "userId": "participant_admin",
                        "actAs": [&alice]
                    }
                }))
                .unwrap(),
            },
        );
        assert_eq!(create_resp.status, 200);
        let created: serde_json::Value = serde_json::from_slice(&create_resp.body).unwrap();
        let cid = created["transaction"]["events"][0]["CreatedEvent"]["contractId"]
            .as_str()
            .unwrap()
            .to_string();
        let uid = created["transaction"]["updateId"]
            .as_str()
            .unwrap()
            .to_string();

        eventually("beta never witnessed remote contract in memory", || {
            beta.v2_contract(&cid).is_some()
        });
        // Give the live reader thread a brief window to finish its remote delivery attempt.
        std::thread::sleep(Duration::from_millis(150));
        let end_resp = ledger_json_api::dispatch_request(
            &beta,
            &ledger_json_api::HttpRequest {
                method: "GET".into(),
                path: "/v2/state/ledger-end".into(),
                query_params: Default::default(),
                headers: Default::default(),
                body: Vec::new(),
            },
        );
        let end_body: serde_json::Value =
            serde_json::from_slice(&end_resp.body).unwrap_or_default();
        assert_eq!(
            end_body["offset"],
            json!(0),
            "remote updates.journal failure must NOT advance beta ledger_end: {end_body}"
        );
        (bob, cid, uid)
    };

    // Unblock `updates.journal` and reopen beta: the missed remote update must still be unshown and recover!
    std::fs::remove_dir_all(beta_dir.path().join("updates.journal")).unwrap();
    let beta_node2 = Node::connect_in(&url, "beta-r13a-rem", &dar(), Some(beta_dir.path()))
        .expect("reopen beta from file store");
    let beta2 = Arc::new(ExecutionService::new());
    beta2.load_dar(&dar()).expect("load dar");
    let committer2 = Arc::new(NodeCommitter::new(
        beta_node2,
        "sample-contract",
        Duration::from_secs(30),
    ));
    committer2.keep_updates_in(&beta2);
    committer2.show_remote_transactions_in(Arc::clone(&beta2));
    beta2.set_committer(committer2);

    let mut headers = std::collections::HashMap::new();
    headers.insert("content-type".into(), "application/json".into());
    let resp = ledger_json_api::dispatch_request(
        &beta2,
        &ledger_json_api::HttpRequest {
            method: "POST".into(),
            path: "/v2/updates/update-by-id".into(),
            query_params: Default::default(),
            headers,
            body: serde_json::to_vec(&json!({
                "updateId": alpha_uid,
                "updateFormat": {
                    "includeTransactions": {
                        "eventFormat": { "filtersByParty": { (&bob): {} }, "verbose": false },
                        "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                    }
                }
            }))
            .unwrap(),
        },
    );
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
    assert_eq!(
        resp.status, 200,
        "remote update whose journal failed before restart must recover after restart ({cid}): {body}"
    );
}
