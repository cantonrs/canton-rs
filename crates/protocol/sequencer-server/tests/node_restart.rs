//! G11 / S-LOCAL-005: a participant that is restarted continues where it stopped. Its state directory holds the contract set, the cursor in the
//! sequencer's events, the topology it followed and the contracts it can exercise: after a restart it still knows the contracts it created
//! and the ones another participant created for it, can exercise its own, and catches up on what happened while it was down.
mod common;

use canton_participant::node::{Node, SharedNode, Verdict};
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use lf_eval::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn holding(bank: &str, owner: &str, auditor: &str, coeff: i128) -> Value {
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

fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ok() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_restarted_participant_keeps_its_contracts_and_catches_up() {
    let dir = std::env::temp_dir().join(format!("node-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m1 = common::join(&url, &config, "alpha");
    let mut m2 = common::join(&url, &config, "beta");
    let alice = common::host(&mut m1, &physical, "alice");
    let bob = common::host(&mut m2, &physical, "bob");
    let one = Node::open_in(
        m1.identity,
        m1.client,
        m1.token,
        &physical,
        &dar(),
        m1.cursor,
        Some(&dir),
    )
    .expect("the first participant opens with a state directory");
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
    let reader_one = one.start_reader();
    let _reader_two = two.start_reader();
    let timeout = Duration::from_secs(30);

    // alice's own contract, and one that bob's participant creates with alice as the observer
    let own = one
        .with(|n| {
            n.prepare_create(
                "sample-contract",
                "AssetHolding:AssetHolding",
                &holding(&alice, &alice, &alice, 100_000_000_000),
                "restart-own",
                None,
                &mut canton_participant::submit::Os,
            )
        })
        .unwrap()
        .unwrap();
    let own_id = own.built.contract_id_hex.clone();
    assert_eq!(
        one.submit_prepared(own, timeout).unwrap().0,
        Verdict::Approved
    );
    let from_bob = two
        .with(|n| {
            n.prepare_create(
                "sample-contract",
                "AssetHolding:AssetHolding",
                &holding(&bob, &bob, &alice, 200_000_000_000),
                "restart-remote",
                None,
                &mut canton_participant::submit::Os,
            )
        })
        .unwrap()
        .unwrap();
    let remote_id = from_bob.built.contract_id_hex.clone();
    assert_eq!(
        two.submit_prepared(from_bob, timeout).unwrap().0,
        Verdict::Approved
    );
    eventually("alice's participant never learned bob's contract", || {
        one.known_contracts()
            .iter()
            .any(|c| c.contract_id == remote_id)
    });

    // restart: stop reading, drop the node, keep only the identity (the keys), and open again from the same state directory
    drop(reader_one);
    let shared = Arc::try_unwrap(one)
        .ok()
        .expect("nobody else holds the first node");
    let node = shared.into_node();
    let identity = node.identity;
    // bob's participant creates another contract while the first one is down
    let while_down = two
        .with(|n| {
            n.prepare_create(
                "sample-contract",
                "AssetHolding:AssetHolding",
                &holding(&bob, &bob, &alice, 300_000_000_000),
                "restart-down",
                None,
                &mut canton_participant::submit::Os,
            )
        })
        .unwrap()
        .unwrap();
    let down_id = while_down.built.contract_id_hex.clone();
    assert_eq!(
        two.submit_prepared(while_down, timeout).unwrap().0,
        Verdict::Approved
    );
    let mut client = SequencerConnect::connect(&url).unwrap();
    let challenge = client.challenge(&identity.member(), &[37]).unwrap();
    let signature = identity
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = client
        .authenticate(&identity.member(), &challenge.nonce, signature)
        .unwrap();
    let again = Node::open_in(identity, client, token, &physical, &dar(), 0, Some(&dir))
        .expect("the participant opens again from its state directory");
    // what it kept
    let known: Vec<String> = again
        .known_contracts()
        .into_iter()
        .map(|c| c.contract_id)
        .collect();
    assert!(
        known.contains(&own_id),
        "its own contract survived: {known:?}"
    );
    assert!(
        known.contains(&remote_id),
        "the contract bob's participant created survived"
    );
    assert!(again.is_active(&own_id) && again.is_active(&remote_id));
    let again = Arc::new(SharedNode::new(again));
    let _reader = again.start_reader();
    // what happened while it was down is read from where it stopped
    eventually(
        "the participant never caught up on what happened while it was down",
        || {
            again
                .known_contracts()
                .iter()
                .any(|c| c.contract_id == down_id)
        },
    );
    // and it can exercise the contract it created before the restart
    let (verdict, notes) = again
        .submit_exercise(
            "sample-contract",
            &own_id,
            "Settle",
            &Value::Record {
                tycon: None,
                fields: vec![],
            },
            std::slice::from_ref(&alice),
            "restart-settle",
            None,
            &[],
            timeout,
        )
        .expect("the settle is judged");
    assert_eq!(verdict, Verdict::Approved, "{notes:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// State kept for one synchronizer is refused by a node of another one (its cursor is a time of the other's events).
#[test]
fn state_of_another_synchronizer_is_refused() {
    let dir = std::env::temp_dir().join(format!("node-other-sync-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let m = common::join(&url, &config, "alpha");
    let store = canton_participant::state_store::FileStore::new(&dir).unwrap();
    canton_participant::state_store::StateStore::write(
        store.as_ref(),
        "synchronizer",
        "other::1220aa::37-0\n",
    )
    .unwrap();
    let error = Node::open_in(
        m.identity,
        m.client,
        m.token,
        &physical,
        &dar(),
        m.cursor,
        Some(&dir),
    )
    .err()
    .expect("refused");
    assert!(
        error.contains("belongs to the synchronizer other::1220aa::37-0"),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
