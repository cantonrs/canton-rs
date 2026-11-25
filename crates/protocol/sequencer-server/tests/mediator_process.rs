//! G11 / S-LOCAL-004: the mediator as a process of its own. The sequencer runs with its mediators switched off; the mediator joins as a member,
//! is delivered what is addressed to its group, and judges the requests of the Rust participants. No mediator inside the sequencer.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
mod common;

use canton_participant::node::{Node, Verdict};
use canton_sequencer_server::mediator_node;
use lf_eval::Value;
use std::path::PathBuf;
use std::time::Duration;

fn dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn holding(owner: &str, coeff: i128) -> Value {
    Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party(owner.into())),
            ("owner".into(), Value::Party(owner.into())),
            ("auditor".into(), Value::Party(owner.into())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            ("amount".into(), Value::Numeric { coeff, scale: 10 }),
        ],
    }
}

fn dir(label: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mediator-process-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_mediator_of_its_own_judges_a_create_and_a_settle() {
    let state = dir("ok");
    let (config, url) = common::start_external_mediator(&state);
    let physical = config.physical_synchronizer_id();
    let mediator = mediator_node::start(&url, &state, 0).expect("the mediator joins");
    assert!(
        mediator.member.starts_with("MED::rm1::"),
        "{}",
        mediator.member
    );
    let mut m = common::join(&url, &config, "submitter");
    let erin = common::host(&mut m, &physical, "erin");
    let mut node = Node::open(m.identity, m.client, m.token, &physical, &dar(), m.cursor)
        .expect("the node opens");
    let timeout = Duration::from_secs(20);
    let (id, verdict) = node
        .submit_create(
            "sample-contract",
            "AssetHolding:AssetHolding",
            &holding(&erin, 1_000_000_000_000),
            "ext-create",
            timeout,
        )
        .expect("the create is judged by the mediator process");
    assert_eq!(verdict, Verdict::Approved);
    assert!(node.is_active(&id));
    let verdict = node
        .submit_exercise(
            &id,
            "Settle",
            &Value::Record {
                tycon: None,
                fields: vec![],
            },
            std::slice::from_ref(&erin),
            "ext-settle",
            timeout,
        )
        .expect("the settle is judged");
    assert_eq!(verdict, Verdict::Approved);
    assert!(!node.is_active(&id));
    drop(mediator);
    let _ = std::fs::remove_dir_all(&state);
}

/// With nobody to be the mediator the request gets **no verdict**: the sequencer's own mediator is really off (it would answer otherwise).
#[test]
fn without_the_mediator_process_nothing_decides() {
    let state = dir("none");
    let (config, url) = common::start_external_mediator(&state);
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "submitter");
    let erin = common::host(&mut m, &physical, "erin");
    let mut node = Node::open(m.identity, m.client, m.token, &physical, &dar(), m.cursor)
        .expect("the node opens");
    let outcome = node.submit_create(
        "sample-contract",
        "AssetHolding:AssetHolding",
        &holding(&erin, 2_000_000_000_000),
        "ext-none",
        Duration::from_secs(5),
    );
    let error = outcome.expect_err("no mediator, no verdict");
    assert!(error.contains("no verdict"), "{error}");
    let _ = std::fs::remove_dir_all(&state);
}

fn confirm_dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/fixtures/confirm/target/confirm-subview.dar")
}

/// A request is in flight (the second participant has not confirmed yet), the mediator is stopped and started again, and the verdict still
/// comes: the new mediator rebuilt the request from where the old one stopped (S-LOCAL-005). Without what the old one kept it does not know the
/// request, ignores the confirmation, and nothing is decided.
///
/// The request is `alice`'s `Touch` (alpha) on a `Held` that `bob` (beta) signs: alpha may submit only for its own party, and beta has to
/// confirm the consumption of bob's contract.
fn restart_in_flight(keep_state: bool) -> Result<Verdict, String> {
    use canton_participant::node::SharedNode;
    use std::sync::Arc;
    let state = dir(if keep_state {
        "restart-keep"
    } else {
        "restart-lose"
    });
    let (config, url) = common::start_external_mediator(&state);
    let physical = config.physical_synchronizer_id();
    let mediator = mediator_node::start(&url, &state, 0).expect("the mediator joins");
    let mut m1 = common::join(&url, &config, "alpha");
    let mut m2 = common::join(&url, &config, "beta");
    let alice = common::host(&mut m1, &physical, "alice");
    let bob = common::host(&mut m2, &physical, "bob");
    let one = Node::open(
        m1.identity,
        m1.client,
        m1.token,
        &physical,
        &confirm_dar(),
        m1.cursor,
    )
    .unwrap();
    let two = Node::open(
        m2.identity,
        m2.client,
        m2.token,
        &physical,
        &confirm_dar(),
        m2.cursor,
    )
    .unwrap();
    let one = Arc::new(SharedNode::new(one));
    let two = Arc::new(SharedNode::new(two));
    let _reader_one = one.start_reader();
    // bob signs a contract alice observes; beta reads only while it waits for this verdict
    let (id, verdict) = two
        .with(|n| {
            n.submit_create(
                "confirm-subview",
                "Confirm:Held",
                &Value::Record {
                    tycon: Some("Confirm:Held".into()),
                    fields: vec![
                        ("r".into(), Value::Party(bob.clone())),
                        ("a".into(), Value::Party(alice.clone())),
                    ],
                },
                "restart-held",
                Duration::from_secs(20),
            )
        })
        .unwrap()
        .expect("the create is judged");
    assert_eq!(verdict, Verdict::Approved);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while one.with(|n| n.instance_bytes(&id)).unwrap().is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "alpha never learned the contract"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // alice touches it: the second participant has to confirm, and it is not reading
    let submitter = {
        let one = Arc::clone(&one);
        std::thread::spawn(move || {
            one.submit_exercise(
                "confirm-subview",
                &id,
                "Touch",
                &Value::Record {
                    tycon: None,
                    fields: vec![],
                },
                std::slice::from_ref(&alice),
                "restart-mediator",
                None,
                &[],
                Duration::from_secs(12),
            )
        })
    };
    // the mediator registered the request and waits for bob's participant
    std::thread::sleep(Duration::from_millis(2500));
    drop(mediator);
    if !keep_state {
        let _ = std::fs::remove_file(state.join("mediator-0.state"));
    }
    let _mediator = mediator_node::start(&url, &state, 0).expect("the mediator joins again");
    // now the second participant reads, and confirms
    let _reader_two = two.start_reader();
    let outcome = submitter.join().unwrap().map(|(v, _)| v);
    let _ = std::fs::remove_dir_all(&state);
    outcome
}

#[test]
fn a_restarted_mediator_decides_the_request_that_was_in_flight() {
    assert_eq!(
        restart_in_flight(true).expect("the verdict comes"),
        Verdict::Approved
    );
}

#[test]
fn a_mediator_that_lost_what_it_kept_does_not_know_the_request() {
    let error = restart_in_flight(false).expect_err("nothing decides the request");
    assert!(error.contains("no verdict"), "{error}");
}

/// B2 / S-LOCAL-011: a mediator that shares **nothing** with the sequencer. It makes its own identity in its own directory, the operator
/// loads its onboarding transactions and names it the only mediator of group 0 through the sequencer's topology administration (the calls
/// the official console makes), and it judges the participants' requests; the sequencer's own mediator stepped down.
#[test]
fn a_mediator_onboarded_after_genesis_with_its_own_keys_judges_a_create() {
    use canton_participant::state_store::FileStore;
    use canton_participant::topology_state::decode;
    use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
    use canton_sequencer_server::{mediator_identity::MediatorIdentity, topology_admin};
    let own = dir("own-identity");
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let store = FileStore::new(&own).unwrap();
    let identity = MediatorIdentity::load_or_create(store.as_ref(), "solo").unwrap();
    // the sequencer does not know it before the operator authorizes it
    assert!(
        mediator_node::start_own(&url, std::sync::Arc::clone(&store) as std::sync::Arc<_>).is_err()
    );
    let onboarded = topology_admin::onboard_mediator(
        &url,
        &physical,
        identity.onboarding_transactions(),
        &identity.uid(),
        0,
        true,
    )
    .expect("the operator onboards it");
    assert_eq!((onboarded.group, onboarded.serial), (0, 2));
    assert_eq!(onboarded.active, vec![identity.uid()]);
    // signed by the synchronizer's owners only (both namespaces of the decentralized namespace here)
    let mut signers: Vec<String> = onboarded
        .transaction
        .signatures
        .iter()
        .map(|s| s.signed_by.clone())
        .collect();
    signers.sort();
    let mut owners = vec![
        config.keys.namespace.fingerprint.clone(),
        config.keys.mediator_namespace.fingerprint.clone(),
    ];
    owners.sort();
    assert_eq!(signers, owners);
    let mediator = mediator_node::start_own(&url, store).expect("the mediator joins");
    assert_eq!(
        (mediator.member.clone(), mediator.group),
        (identity.member(), 0)
    );
    let mut m = common::join(&url, &config, "submitter");
    // what a participant downloads: the mediator's identity in one broadcast, the group change in a later one, as the official store has it
    let state = m
        .client
        .download_topology_state(&m.identity.member(), &physical, &m.token)
        .unwrap();
    let mine: Vec<(i64, &'static str)> = decode(&state)
        .unwrap()
        .iter()
        .filter_map(|e| {
            let kind = match e.tx.mapping.as_ref()?.mapping.as_ref()? {
                Mapping::NamespaceDelegation(d) if d.namespace == identity.namespace() => {
                    "delegation"
                }
                Mapping::OwnerToKeyMapping(o) if o.member == identity.member() => "keys",
                Mapping::MediatorSynchronizerState(s) if s.active.contains(&identity.uid()) => {
                    "group"
                }
                _ => return None,
            };
            Some((e.valid_from, kind))
        })
        .collect();
    assert_eq!(
        mine.iter().map(|(_, k)| *k).collect::<Vec<_>>(),
        ["delegation", "keys", "group"]
    );
    assert_eq!(mine[0].0, mine[1].0, "the identity is one broadcast");
    assert!(mine[2].0 > mine[1].0, "the group change is a later one");
    let erin = common::host(&mut m, &physical, "erin");
    let mut node = Node::open(m.identity, m.client, m.token, &physical, &dar(), m.cursor)
        .expect("the node opens");
    let (id, verdict) = node
        .submit_create(
            "sample-contract",
            "AssetHolding:AssetHolding",
            &holding(&erin, 3_000_000_000_000),
            "own-create",
            Duration::from_secs(20),
        )
        .expect("the create is judged by the onboarded mediator");
    assert_eq!(verdict, Verdict::Approved);
    assert!(node.is_active(&id));
    // without it nobody decides: the sequencer's own mediator is no longer in the group
    drop(mediator);
    let outcome = node.submit_create(
        "sample-contract",
        "AssetHolding:AssetHolding",
        &holding(&erin, 4_000_000_000_000),
        "own-none",
        Duration::from_secs(5),
    );
    assert!(outcome.expect_err("no verdict").contains("no verdict"));
    let _ = std::fs::remove_dir_all(&own);
}
