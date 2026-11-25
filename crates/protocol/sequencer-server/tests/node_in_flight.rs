//! P-7 / P-13: the fate of a Rust participant's own submission is decided by the synchronizer's time, not by how long a caller waited for it.
//! A wait that ends first leaves the submission in flight; when its verdict comes, what it changed reaches whoever shows this participant's
//! transactions, also across a restart.
#![allow(clippy::unwrap_used, reason = "integration test helpers")]
mod common;

use canton_participant::node::{
    LateFate, Node, RemoteTransaction, SharedNode, Verdict, REJECTION_NOTE, STILL_IN_FLIGHT,
};
use canton_sequencer_server::{mediator_node, SynchronizerConfig};
use lf_eval::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn holding(bank: &str, owner: &str, coeff: i128) -> Value {
    Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party(bank.into())),
            ("owner".into(), Value::Party(owner.into())),
            ("auditor".into(), Value::Party(bank.into())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            ("amount".into(), Value::Numeric { coeff, scale: 10 }),
        ],
    }
}

fn eventually(what: &str, within: Duration, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !ok() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A sequencer whose mediator runs in its own process, with a state directory of its own under the system's temporary directory.
fn start_with_stoppable_mediator(name: &str) -> (SynchronizerConfig, String, PathBuf) {
    let dir = std::env::temp_dir().join(format!("in-flight-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (config, url) = common::start_external_mediator(&dir);
    (config, url, dir)
}

/// Runs the mediator for one approved create and stops it, so that a mediator started again later reads on from there.
///
/// [CANTON-NOTE: WHY] A wait that "ends before the verdict" must be made so, not hoped for: with a running mediator a 1 ms wait often
/// outlives the approval (AUDIT-2026-11-23 B-2: about 18 failures in 30 parallel runs). While no mediator runs no verdict can come, so
/// the wait ends first on every run. A mediator started for the first time begins at the sequencer's current time and would miss a
/// request sent before it; one that has kept how far it read (after its first event) starts again from there and judges it.
fn warm_up_and_stop_mediator(node: &SharedNode, owner: &str, url: &str, dir: &std::path::Path) {
    let mediator = mediator_node::start(url, dir, 0).expect("the mediator joins");
    let first = create_prepared(node, owner, "warm-up");
    assert_eq!(
        node.submit_prepared(first, Duration::from_secs(20))
            .unwrap()
            .0,
        Verdict::Approved
    );
    drop(mediator);
}

/// The step-1 reproduction: the caller stops waiting before the verdict, the verdict approves, and the transaction must still reach the
/// handler that shows this participant's transactions, as it is in the participant's own contract set.
#[test]
fn a_create_whose_wait_ends_before_its_approval_still_reaches_the_transaction_handler() {
    let (config, url, dir) = start_with_stoppable_mediator("abandoner");
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "abandoner");
    let erin = common::host(&mut m, &physical, "erin");
    let node = Node::open(m.identity, m.client, m.token, &physical, &dar(), m.cursor)
        .expect("the node opens");
    let shared = Arc::new(SharedNode::new(node));
    let shown: Arc<Mutex<Vec<RemoteTransaction>>> = Arc::default();
    let sink = Arc::clone(&shown);
    shared.on_remote(Box::new(move |tx| {
        sink.lock().unwrap().push(tx);
        Ok(())
    }));
    let _reader = shared.start_reader();
    warm_up_and_stop_mediator(&shared, &erin, &url, &dir);

    // no mediator running: the wait ends before any verdict
    let prepared = create_prepared(&shared, &erin, "abandoned-create");
    let id = prepared.built.contract_id_hex.clone();
    let waited = shared.submit_prepared(prepared, Duration::from_millis(1));
    assert!(
        waited.is_err(),
        "the wait ends before any verdict: {waited:?}"
    );
    let mediator = mediator_node::start(&url, &dir, 0).expect("the mediator joins again");

    eventually(
        "the synchronizer never approved the create",
        Duration::from_secs(15),
        || shared.with(|n| n.runtime.ledger.is_active(&id)).unwrap(),
    );
    eventually(
        "the approved create is in the participant's contract set but never reached the transaction handler",
        Duration::from_secs(5),
        || {
            shown
                .lock()
                .unwrap()
                .iter()
                .any(|tx| tx.created.iter().any(|c| c.contract_id == id))
        },
    );
    assert!(
        shared.known_contracts().iter().any(|c| c.contract_id == id),
        "the participant can exercise the contract it created"
    );
    drop(mediator);
    let _ = std::fs::remove_dir_all(&dir);
}

fn create_prepared(
    node: &SharedNode,
    owner: &str,
    command_id: &str,
) -> canton_participant::node::PreparedCreate {
    node.with(|n| {
        n.prepare_create(
            "sample-contract",
            "AssetHolding:AssetHolding",
            &holding(owner, owner, 10_000_000_000),
            command_id,
            None,
            &mut canton_participant::submit::Os,
        )
    })
    .unwrap()
    .unwrap()
}

fn collect_late(node: &SharedNode) -> Arc<Mutex<Vec<LateFate>>> {
    let late: Arc<Mutex<Vec<LateFate>>> = Arc::default();
    let sink = Arc::clone(&late);
    node.on_late(Box::new(move |fate| {
        sink.lock().unwrap().push(fate);
        Ok(())
    }));
    late
}

/// With a late handler, an approval nobody waits for goes to it with its transaction and its tag, and not to the handler of other
/// participants' transactions.
#[test]
fn a_late_approval_goes_to_the_late_handler_with_its_transaction_and_its_tag() {
    let (config, url, dir) = start_with_stoppable_mediator("late");
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "late");
    let erin = common::host(&mut m, &physical, "erin");
    let node = Node::open(m.identity, m.client, m.token, &physical, &dar(), m.cursor)
        .expect("the node opens");
    let shared = Arc::new(SharedNode::new(node));
    let shown: Arc<Mutex<Vec<RemoteTransaction>>> = Arc::default();
    let sink = Arc::clone(&shown);
    shared.on_remote(Box::new(move |tx| {
        sink.lock().unwrap().push(tx);
        Ok(())
    }));
    let late = collect_late(&shared);
    let _reader = shared.start_reader();
    warm_up_and_stop_mediator(&shared, &erin, &url, &dir);

    // no mediator running: the wait ends before any verdict
    let prepared = create_prepared(&shared, &erin, "late-create");
    let id = prepared.built.contract_id_hex.clone();
    let error = shared
        .submit_prepared_tagged(prepared, Duration::from_millis(1), "the caller's command")
        .expect_err("the wait ends first");
    assert!(error.starts_with(STILL_IN_FLIGHT), "{error}");
    let mediator = mediator_node::start(&url, &dir, 0).expect("the mediator joins again");
    eventually(
        "the approval never came to the late handler",
        Duration::from_secs(15),
        || !late.lock().unwrap().is_empty(),
    );
    let fates = late.lock().unwrap().clone();
    assert_eq!(fates.len(), 1, "{fates:?}");
    assert_eq!(fates[0].settled.verdict, Verdict::Approved);
    assert_eq!(fates[0].settled.tag, "the caller's command");
    let tx = fates[0]
        .transaction
        .as_ref()
        .expect("the approval's transaction");
    assert!(tx.created.iter().any(|c| c.contract_id == id), "{tx:?}");
    assert!(shared.known_contracts().iter().any(|c| c.contract_id == id));
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !shown
            .lock()
            .unwrap()
            .iter()
            .any(|tx| tx.created.iter().any(|c| c.contract_id == id)),
        "the transaction is shown once, with its fate"
    );
    drop(mediator);
    let _ = std::fs::remove_dir_all(&dir);
}

/// P-7 / P-14: on a quiet synchronizer (no mediator, so no verdict) the request times out when the synchronizer's time passes its decision
/// time, which the participant learns by asking for a time proof: no event would come otherwise.
#[test]
fn a_request_without_a_verdict_times_out_at_its_decision_time_learned_from_a_time_proof() {
    let dir = std::env::temp_dir().join(format!("in-flight-quiet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (config, url) = common::start_external_mediator(&dir);
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "quiet");
    let erin = common::host(&mut m, &physical, "erin");
    m.send(
        &physical,
        &[(
            vec![canton_participant::topology_wire::ALL_MEMBERS.to_string()],
            common::parameters_broadcast_with(&config, 2, |p| {
                let mut second = p.confirmation_response_timeout.take().unwrap_or_default();
                second.seconds = 1;
                second.nanos = 0;
                p.confirmation_response_timeout = Some(second);
                p.mediator_reaction_timeout = Some(second);
            }),
        )],
        "short-timeouts",
        common::far_future(),
    )
    .unwrap();
    m.settle(&physical);
    let node = Node::open(m.identity, m.client, m.token, &physical, &dar(), m.cursor)
        .expect("the node opens");
    assert_eq!(
        node.runtime.config.timeouts.decision_time(0),
        2_000_000,
        "the node follows the synchronizer's parameters"
    );
    let shared = Arc::new(SharedNode::new(node));
    let _reader = shared.start_reader();

    let prepared = create_prepared(&shared, &erin, "quiet-create");
    let sent = Instant::now();
    let (verdict, notes) = shared
        .submit_prepared(prepared, Duration::from_secs(15))
        .expect("the request's fate is known within its decision time, not the wait's");
    assert_eq!(verdict, Verdict::Rejected);
    assert!(
        notes.iter().any(|n| n
            == &format!(
                "{REJECTION_NOTE}{}",
                canton_participant::in_flight::LOCAL_VERDICT_TIMEOUT
            )),
        "{notes:?}"
    );
    assert!(
        sent.elapsed() < Duration::from_secs(10),
        "{:?}",
        sent.elapsed()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// P-13: a request in flight when its participant stops is decided while it is down; after the restart its fate is handed over, and the
/// contract it created has its instance (the participant began the request, with what it creates, before it stopped; the mediator only
/// judges it after that).
#[test]
fn a_request_in_flight_across_a_restart_gets_its_fate_and_its_created_contract() {
    use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
    let base = std::env::temp_dir().join(format!("in-flight-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (sequencer_dir, dir) = (base.join("sequencer"), base.join("participant"));
    std::fs::create_dir_all(&sequencer_dir).unwrap();
    let (config, url) = common::start_external_mediator(&sequencer_dir);
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "restarted");
    let erin = common::host(&mut m, &physical, "erin");
    let node = Node::open_in(
        m.identity,
        m.client,
        m.token,
        &physical,
        &dar(),
        m.cursor,
        Some(&dir),
    )
    .expect("the participant opens with a state directory");
    let one = Arc::new(SharedNode::new(node));
    let reader = one.start_reader();
    // the mediator judges a first create and stops: when it comes back it reads on from where it stopped
    let mediator = mediator_node::start(&url, &sequencer_dir, 0).expect("the mediator joins");
    let first = create_prepared(&one, &erin, "restart-first");
    assert_eq!(
        one.submit_prepared(first, Duration::from_secs(20))
            .unwrap()
            .0,
        Verdict::Approved
    );
    drop(mediator);

    // no mediator running: the create waits for its verdict
    let prepared = create_prepared(&one, &erin, "restart-create");
    let id = prepared.built.contract_id_hex.clone();
    let error = one
        .submit_prepared_tagged(prepared, Duration::from_millis(1), "restart-tag")
        .expect_err("the wait ends first");
    assert!(error.starts_with(STILL_IN_FLIGHT), "{error}");
    eventually(
        "the participant never began its own request",
        Duration::from_secs(15),
        || one.with(|n| n.runtime.ledger.in_flight() == 1).unwrap(),
    );

    // the participant stops with the request in flight; the mediator comes and judges it while the participant is down
    drop(reader);
    let identity = Arc::try_unwrap(one)
        .ok()
        .expect("nobody else holds the node")
        .into_node()
        .identity;
    let mediator = mediator_node::start(&url, &sequencer_dir, 0).expect("the mediator joins");

    let mut client = SequencerConnect::connect(&url).unwrap();
    let challenge = client.challenge(&identity.member(), &[37]).unwrap();
    let signature = identity
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = client
        .authenticate(&identity.member(), &challenge.nonce, signature)
        .unwrap();
    let again = Node::open_in(identity, client, token, &physical, &dar(), 0, Some(&dir))
        .expect("the participant opens again");
    let again = Arc::new(SharedNode::new(again));
    let late = collect_late(&again);
    let _reader = again.start_reader();
    eventually(
        "the request's fate never came after the restart",
        Duration::from_secs(20),
        || !late.lock().unwrap().is_empty(),
    );
    let fates = late.lock().unwrap().clone();
    assert_eq!(fates.len(), 1, "{fates:?}");
    assert_eq!(fates[0].settled.tag, "restart-tag");
    assert_eq!(fates[0].settled.verdict, Verdict::Approved, "{fates:?}");
    let tx = fates[0]
        .transaction
        .as_ref()
        .expect("the approval's transaction");
    assert!(
        tx.created.iter().any(|c| c.contract_id == id),
        "the created contract comes with its instance: {tx:?}"
    );
    assert!(
        again.known_contracts().iter().any(|c| c.contract_id == id),
        "the participant can exercise the contract"
    );
    assert!(again.with(|n| n.runtime.ledger.is_active(&id)).unwrap());
    drop(mediator);
    let _ = std::fs::remove_dir_all(&base);
}

/// P-14: a participant acknowledges the last event it handled when it starts (`PeriodicAcknowledgements`), and the sequencer takes it.
#[test]
fn a_participant_acknowledges_what_it_has_read_when_it_starts() {
    let dir = std::env::temp_dir().join(format!("in-flight-ack-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (config, url) = common::start_external_mediator(&dir);
    let physical = config.physical_synchronizer_id();
    let m = common::join(&url, &config, "acknowledging");
    let member = m.identity.member();
    let cursor = m.cursor;
    let node = Node::open(m.identity, m.client, m.token, &physical, &dar(), m.cursor)
        .expect("the node opens");
    let shared = Arc::new(SharedNode::new(node));
    let _reader = shared.start_reader();
    let expected = format!("K {member} {cursor}");
    eventually(
        "the sequencer never recorded the participant's acknowledgement",
        Duration::from_secs(10),
        || {
            std::fs::read_to_string(dir.join("journal"))
                .unwrap_or_default()
                .lines()
                .any(|l| l == expected)
        },
    );
    let _ = std::fs::remove_dir_all(&dir);
}
