//! F2 (S-SUBMIT-002): a Rust participant submits through the Rust sequencer and the Rust mediator it contains, and learns the verdict. This is the
//! all-Rust path of the equal-conditions comparison (`doc/performance/EQUAL-CONDITIONS.md`, configuration C2), with no JVM and no JSON API.
mod common;

use canton_participant::node::{Node, Verdict};
use lf_eval::Value;
use std::path::PathBuf;
use std::time::Duration;

fn dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn holding(owner: &str, auditor: &str, coeff: i128) -> Value {
    Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party(owner.into())),
            ("owner".into(), Value::Party(owner.into())),
            ("auditor".into(), Value::Party(auditor.into())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            ("amount".into(), Value::Numeric { coeff, scale: 10 }),
        ],
    }
}

fn started() -> (Node, String) {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "submitter");
    let erin = common::host(&mut m, &physical, "erin");
    let node = Node::open(m.identity, m.client, m.token, &physical, &dar(), m.cursor)
        .expect("the node opens");
    assert!(
        node.hosted().contains(&erin),
        "the topology says this node hosts erin: {:?}",
        node.hosted()
    );
    (node, erin)
}

#[test]
fn a_create_and_a_settle_are_approved_by_the_rust_mediator() {
    let (mut node, erin) = started();
    let timeout = Duration::from_secs(20);
    let (id, verdict) = node
        .submit_create(
            "sample-contract",
            "AssetHolding:AssetHolding",
            &holding(&erin, &erin, 1_000_000_000_000),
            "cmd-create",
            timeout,
        )
        .expect("the create is sent and judged");
    assert_eq!(verdict, Verdict::Approved);
    assert!(
        node.is_active(&id),
        "the approved create is in the node's contract set"
    );
    let verdict = node
        .submit_exercise(
            &id,
            "Settle",
            &Value::Record {
                tycon: None,
                fields: vec![],
            },
            std::slice::from_ref(&erin),
            "cmd-settle",
            timeout,
        )
        .expect("the settle is sent and judged");
    assert_eq!(verdict, Verdict::Approved);
    assert!(
        !node.is_active(&id),
        "the approved consuming exercise archives the contract"
    );
}

#[test]
fn a_settle_by_a_party_that_does_not_control_the_choice_is_rejected_and_the_contract_stays() {
    let (mut node, erin) = started();
    let timeout = Duration::from_secs(20);
    let (id, verdict) = node
        .submit_create(
            "sample-contract",
            "AssetHolding:AssetHolding",
            &holding(&erin, &erin, 500_000_000_000),
            "cmd-create-2",
            timeout,
        )
        .unwrap();
    assert_eq!(verdict, Verdict::Approved);
    // the submitting participant's admin party is not the bank, the controller of `Settle`
    let admin = node.identity.uid();
    let verdict = node
        .submit_exercise(
            &id,
            "Settle",
            &Value::Record {
                tycon: None,
                fields: vec![],
            },
            &[admin],
            "cmd-settle-2",
            timeout,
        )
        .unwrap();
    assert_eq!(verdict, Verdict::Rejected);
    assert!(node.is_active(&id), "a rejected request changes nothing");
}

#[test]
fn a_stakeholder_nobody_is_known_to_host_is_refused_before_anything_is_sent() {
    let (mut node, erin) = started();
    let outcome = node.submit_create(
        "sample-contract",
        "AssetHolding:AssetHolding",
        &holding(&erin, "nobody::1220", 1_000_000_000_000),
        "cmd-create-3",
        Duration::from_secs(5),
    );
    let error = outcome.unwrap_err();
    assert!(
        error.contains("no participant is known to host nobody::1220"),
        "{error}"
    );
}

/// Many threads submit through one node at once (F5/concurrency of `doc/performance/EQUAL-CONDITIONS.md`): every create is judged and approved,
/// every id is its own, each contract is then settled concurrently, and the waits **overlapped** (more than one request was waiting at a time).
#[test]
fn many_threads_submit_through_one_node_and_their_waits_overlap() {
    use canton_participant::node::SharedNode;
    use std::sync::Arc;
    let (mut node, erin) = started();
    let timeout = Duration::from_secs(60);
    // each thread's create is built and sent by the thread itself
    let prepared: Vec<_> = (0..8)
        .map(|i| {
            node.prepare_create(
                "sample-contract",
                "AssetHolding:AssetHolding",
                &holding(&erin, &erin, 1_000_000_000_000 + i),
                &format!("many-create-{i}"),
                None,
                &mut canton_participant::submit::Os,
            )
            .expect("the create is built")
        })
        .collect();
    let ids: Vec<String> = prepared
        .iter()
        .map(|p| p.built.contract_id_hex.clone())
        .collect();
    let shared = Arc::new(SharedNode::new(node));
    let handles: Vec<_> = prepared
        .into_iter()
        .map(|p| {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || shared.submit_prepared(p, timeout))
        })
        .collect();
    for h in handles {
        let (verdict, notes) = h.join().unwrap().expect("the create is judged");
        assert_eq!(verdict, Verdict::Approved, "{notes:?}");
    }
    let mut distinct = ids.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 8, "every create has its own id");
    let handles: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let (shared, id, erin) = (Arc::clone(&shared), id.clone(), erin.clone());
            std::thread::spawn(move || {
                shared.submit_exercise(
                    "sample-contract",
                    &id,
                    "Settle",
                    &Value::Record {
                        tycon: None,
                        fields: vec![],
                    },
                    &[erin],
                    &format!("many-settle-{i}"),
                    None,
                    &[],
                    timeout,
                )
            })
        })
        .collect();
    for h in handles {
        let (verdict, notes) = h.join().unwrap().expect("the settle is judged");
        assert_eq!(verdict, Verdict::Approved, "{notes:?}");
    }
    assert!(
        shared.most_in_flight() > 1,
        "the waits of the 8 submissions overlapped (at most {} at once)",
        shared.most_in_flight()
    );
    assert!(shared
        .with(|n| ids.iter().all(|id| !n.is_active(id)))
        .unwrap());
}

fn holding3(bank: &str, owner: &str, auditor: &str, coeff: i128) -> Value {
    Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party(bank.into())),
            ("owner".into(), Value::Party(owner.into())),
            ("auditor".into(), Value::Party(auditor.into())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            ("amount".into(), Value::Numeric { coeff, scale: 10 }),
        ],
    }
}

/// An exercise that creates contracts (F1 extension, S-SUBMIT-006): `Transfer` consumes a holding of the bank and one owner and creates
/// one for the new owner; `SplitTransfer` creates two. The ids are promised from the exercise's plan before the request is built, the
/// request carries the created contracts in its view with the second quorum, and the Rust mediator approves.
#[test]
fn an_exercise_that_creates_contracts_is_approved_by_the_rust_mediator() {
    use canton_participant::node::{CreatedByExercise, SharedNode};
    use canton_participant::submit::{ExercisePlan, Os};
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "submitter");
    let erin = common::host(&mut m, &physical, "erin");
    let frank = common::host(&mut m, &physical, "frank");
    let mut node = Node::open(m.identity, m.client, m.token, &physical, &dar(), m.cursor)
        .expect("the node opens");
    let timeout = Duration::from_secs(30);
    // erin (bank) and frank (owner) hold 10; frank transfers it to erin
    let (held, verdict) = node
        .submit_create(
            "sample-contract",
            "AssetHolding:AssetHolding",
            &holding3(&erin, &frank, &erin, 100_000_000_000),
            "xfer-create",
            timeout,
        )
        .expect("the create is judged");
    assert_eq!(verdict, Verdict::Approved);
    let shared = SharedNode::new(node);
    let now = shared.with(|n| n.current_time()).unwrap().unwrap();
    let plan = ExercisePlan::draw(&mut Os, now);
    let moved = holding3(&erin, &erin, &erin, 100_000_000_000);
    let promised = shared
        .promise_created(
            "sample-contract",
            &plan,
            0,
            "AssetHolding:AssetHolding",
            &moved,
        )
        .expect("the id is promised");
    let (verdict, notes) = shared
        .submit_exercise(
            "sample-contract",
            &held,
            "Transfer",
            &Value::Record {
                tycon: None,
                fields: vec![("newOwner".into(), Value::Party(erin.clone()))],
            },
            std::slice::from_ref(&frank),
            "xfer-transfer",
            Some(plan),
            &[CreatedByExercise {
                template: "AssetHolding:AssetHolding",
                payload: &moved,
                expected_id: &promised,
            }],
            timeout,
        )
        .expect("the transfer is judged");
    assert_eq!(verdict, Verdict::Approved, "{notes:?}");
    assert!(
        shared.with(|n| !n.is_active(&held)).unwrap(),
        "the input is consumed"
    );
    assert!(
        shared.with(|n| n.is_active(&promised)).unwrap(),
        "the created holding is active under the id that was promised"
    );
    // the created contract can be exercised in turn: the bank settles it
    let (verdict, notes) = shared
        .submit_exercise(
            "sample-contract",
            &promised,
            "Settle",
            &Value::Record {
                tycon: None,
                fields: vec![],
            },
            std::slice::from_ref(&erin),
            "xfer-settle",
            None,
            &[],
            timeout,
        )
        .expect("the settle is judged");
    assert_eq!(verdict, Verdict::Approved, "{notes:?}");

    // a split creates two contracts, in order
    let (whole, verdict) = shared
        .with(|n| {
            n.submit_create(
                "sample-contract",
                "AssetHolding:AssetHolding",
                &holding3(&erin, &frank, &erin, 100_000_000_000),
                "split-create",
                timeout,
            )
        })
        .unwrap()
        .expect("the create is judged");
    assert_eq!(verdict, Verdict::Approved);
    let now = shared.with(|n| n.current_time()).unwrap().unwrap();
    let plan = ExercisePlan::draw(&mut Os, now);
    let part = holding3(&erin, &erin, &erin, 30_000_000_000);
    let rest = holding3(&erin, &frank, &erin, 70_000_000_000);
    let ids: Vec<String> = [&part, &rest]
        .iter()
        .enumerate()
        .map(|(i, v)| {
            shared
                .promise_created("sample-contract", &plan, i, "AssetHolding:AssetHolding", v)
                .unwrap()
        })
        .collect();
    let (verdict, notes) = shared
        .submit_exercise(
            "sample-contract",
            &whole,
            "SplitTransfer",
            &Value::Record {
                tycon: None,
                fields: vec![
                    (
                        "transferAmount".into(),
                        Value::Numeric {
                            coeff: 30_000_000_000,
                            scale: 10,
                        },
                    ),
                    ("recipient".into(), Value::Party(erin)),
                ],
            },
            std::slice::from_ref(&frank),
            "split-transfer",
            Some(plan),
            &[
                CreatedByExercise {
                    template: "AssetHolding:AssetHolding",
                    payload: &part,
                    expected_id: &ids[0],
                },
                CreatedByExercise {
                    template: "AssetHolding:AssetHolding",
                    payload: &rest,
                    expected_id: &ids[1],
                },
            ],
            timeout,
        )
        .expect("the split is judged");
    assert_eq!(verdict, Verdict::Approved, "{notes:?}");
    assert!(shared
        .with(|n| ids.iter().all(|id| n.is_active(id)) && !n.is_active(&whole))
        .unwrap());
}

/// P-14: a submission the sequencer refuses when it sequences it (here, to a mediator group that does not exist) fails with the sequencer's
/// deliver error as soon as that error is read, instead of waiting for a verdict that never comes.
#[test]
fn a_submission_the_sequencer_refuses_fails_with_its_deliver_error() {
    let (mut node, erin) = started();
    node.use_mediator_group(7);
    let sent = std::time::Instant::now();
    let (_, verdict) = node
        .submit_create(
            "sample-contract",
            "AssetHolding:AssetHolding",
            &holding(&erin, &erin, 1_000_000_000_000),
            "cmd-refused",
            Duration::from_secs(30),
        )
        .expect("the refusal is the submission's outcome, not a timeout");
    assert_eq!(verdict, Verdict::Rejected);
    assert!(
        sent.elapsed() < Duration::from_secs(15),
        "{:?}",
        sent.elapsed()
    );
    assert!(
        node.last_notes.iter().any(|n| n
            .strip_prefix(canton_participant::node::REJECTION_NOTE)
            .is_some_and(
                |status| status.starts_with("9:SEQUENCER_SUBMISSION_REQUEST_REFUSED")
                    && status.contains("List(7)")
            )),
        "{:?}",
        node.last_notes
    );
}
