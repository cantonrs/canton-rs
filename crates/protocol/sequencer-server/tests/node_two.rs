//! G11 / S-LOCAL-001: two Rust participants on one Rust synchronizer. A transaction whose confirming parties are hosted by different
//! participants is confirmed by **both**: the submitter finds the other participant (and its encryption key) in the topology it follows, the
//! other one keeps reading in the background and confirms, and both end up with the same contracts. A participant submits only for the
//! parties it hosts with submission permission (Canton's routing), so such a transaction is an exercise of a contract another participant
//! created: `bob` (beta) creates a `Held` that `alice` (alpha) observes, and alice's `Touch` consumes it, which bob's participant confirms.
mod common;

use canton_participant::node::{Node, SharedNode, Verdict};
use canton_participant::routing::ROUTING_REFUSAL;
use lf_eval::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const PACKAGE: &str = "confirm-subview";

fn dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/fixtures/confirm/target/confirm-subview.dar")
}

fn held(r: &str, a: &str) -> Value {
    Value::Record {
        tycon: Some("Confirm:Held".into()),
        fields: vec![
            ("r".into(), Value::Party(r.into())),
            ("a".into(), Value::Party(a.into())),
        ],
    }
}

fn unit() -> Value {
    Value::Record {
        tycon: None,
        fields: vec![],
    }
}

/// alpha hosts `alice`, beta hosts `bob`; both open and keep reading.
struct Two {
    alice: String,
    bob: String,
    one: Arc<SharedNode>,
    two: Arc<SharedNode>,
    _readers: (
        canton_participant::node::Reader,
        canton_participant::node::Reader,
    ),
}

fn two_participants() -> Two {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m1 = common::join(&url, &config, "alpha");
    let mut m2 = common::join(&url, &config, "beta");
    let alice = common::host(&mut m1, &physical, "alice");
    let bob = common::host(&mut m2, &physical, "bob");
    let one = Node::open(
        m1.identity,
        m1.client,
        m1.token,
        &physical,
        &dar(),
        m1.cursor,
    )
    .expect("the first participant opens");
    let two = Node::open(
        m2.identity,
        m2.client,
        m2.token,
        &physical,
        &dar(),
        m2.cursor,
    )
    .expect("the second participant opens");
    let one = Arc::new(SharedNode::new(one));
    let two = Arc::new(SharedNode::new(two));
    let _readers = (one.start_reader(), two.start_reader());
    Two {
        alice,
        bob,
        one,
        two,
        _readers,
    }
}

fn eventually(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_contract_between_parties_of_two_participants_is_confirmed_by_both() {
    let Two {
        alice,
        bob,
        one,
        two,
        _readers,
    } = two_participants();
    let timeout = Duration::from_secs(30);

    // bob signs on his own participant; alice, an observer, learns the contract on hers
    let prepared = two
        .with(|n| {
            n.prepare_create(
                PACKAGE,
                "Confirm:Held",
                &held(&bob, &alice),
                "two-create",
                None,
                &mut canton_participant::submit::Os,
            )
        })
        .unwrap()
        .expect("the request is built: the first participant is found in the topology");
    let id = prepared.built.contract_id_hex.clone();
    let (verdict, notes) = two
        .submit_prepared(prepared, timeout)
        .expect("the create is judged");
    assert_eq!(verdict, Verdict::Approved, "{notes:?}");
    eventually("the first participant never learned the contract", || {
        one.with(|n| n.is_active(&id) && n.instance_bytes(&id).is_some())
            .unwrap()
    });

    // alice touches it: bob's participant has to confirm, as bob signs the consumed contract
    let (verdict, notes) = one
        .submit_exercise(
            PACKAGE,
            &id,
            "Touch",
            &unit(),
            std::slice::from_ref(&alice),
            "two-touch",
            None,
            &[],
            timeout,
        )
        .expect("the touch is judged");
    assert_eq!(verdict, Verdict::Approved, "both confirmed: {notes:?}");
    // both ledgers end with the contract archived
    assert!(!one.with(|n| n.is_active(&id)).unwrap());
    eventually(
        "the second participant never learned that the contract was archived",
        || !two.with(|n| n.is_active(&id)).unwrap(),
    );
}

/// Canton's routing: a participant submits only for parties it hosts with submission permission and a hosting threshold of 1
/// (`NO_SYNCHRONIZER_ON_WHICH_ALL_SUBMITTERS_CAN_SUBMIT`), and nothing is sent. The receiving side refuses the same request
/// (`AuthorizationValidator`, `canNotSubmit`), so a request built anyway would be rejected as malformed.
#[test]
fn a_participant_does_not_submit_for_a_party_another_participant_hosts() {
    let Two {
        alice,
        bob,
        one,
        two,
        _readers,
    } = two_participants();
    let timeout = Duration::from_secs(30);
    let refused = |error: &str| {
        assert!(
            error.starts_with(ROUTING_REFUSAL)
                && error.contains(
                    "NO_SYNCHRONIZER_ON_WHICH_ALL_SUBMITTERS_CAN_SUBMIT(11,0): This participant cannot submit as the given submitter on any connected synchronizer"
                ),
            "{error}"
        );
    };

    // alpha creates for bob, whom only beta hosts
    let error = one
        .with(|n| {
            n.submit_create(
                PACKAGE,
                "Confirm:Held",
                &held(&bob, &alice),
                "for-bob",
                timeout,
            )
        })
        .unwrap()
        .expect_err("alpha may not submit for bob");
    refused(&error);

    // control: beta creates the same contract for bob
    let (id, verdict) = two
        .with(|n| {
            n.submit_create(
                PACKAGE,
                "Confirm:Held",
                &held(&bob, &alice),
                "by-beta",
                timeout,
            )
        })
        .unwrap()
        .expect("beta submits for its own party");
    assert_eq!(verdict, Verdict::Approved);
    eventually("the first participant never learned the contract", || {
        one.with(|n| n.instance_bytes(&id).is_some()).unwrap()
    });

    // alpha exercises acting as bob
    let error = one
        .submit_exercise(
            PACKAGE,
            &id,
            "Touch",
            &unit(),
            std::slice::from_ref(&bob),
            "touch-as-bob",
            None,
            &[],
            timeout,
        )
        .expect_err("alpha may not act as bob");
    refused(&error);
    assert_eq!(one.most_in_flight(), 0, "alpha sent nothing");
    assert!(one.with(|n| n.is_active(&id)).unwrap());
}
