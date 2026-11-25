//! G7 B1 (S-NET-040 part 7): one Rust participant on two Rust synchronizers (`MultiNode`: one identity, a node per synchronizer) moves a
//! contract from syncA to syncB through the protocol - its unassignment judged by syncA's Rust mediator, its assignment by syncB's - and
//! then exercises it on syncB. No JVM: the requests' wire format is the one the JVM accepted (`scripts/verify-rust-reassignment.sh`).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use canton_participant::multi_node::{logical, MultiNode};
use canton_participant::node::Verdict;
use canton_participant::reassignment_wire::reassignment_id;
use lf_eval::Value;
use std::path::PathBuf;
use std::time::Duration;

fn dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn start(name: &str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = canton_sequencer_server::new_synchronizer_with_groups(name, "rs1", 1);
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

fn holding(owner: &str) -> Value {
    Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party(owner.into())),
            ("owner".into(), Value::Party(owner.into())),
            ("auditor".into(), Value::Party(owner.into())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            (
                "amount".into(),
                Value::Numeric {
                    coeff: 1_000_000_000_000,
                    scale: 10,
                },
            ),
        ],
    }
}

#[test]
fn a_contract_moves_from_one_rust_synchronizer_to_the_other_and_is_exercised_there() {
    let (url_a, url_b) = (start("syncA"), start("syncB"));
    let mut p =
        MultiNode::connect_in(&[&url_a, &url_b], "multi", &dar(), None).expect("joins both");
    let timeout = Duration::from_secs(20);
    let alice = p.nodes[0]
        .host_party("alice", timeout)
        .expect("alice on syncA");
    assert_eq!(
        p.nodes[1]
            .host_party("alice", timeout)
            .expect("alice on syncB"),
        alice,
        "one party id"
    );
    let (sync_a, sync_b) = (
        p.nodes[0].physical_synchronizer_id().to_string(),
        p.nodes[1].physical_synchronizer_id().to_string(),
    );
    assert_eq!(p.index_of(&logical(&sync_b)), Some(1));
    let (cid, verdict) = p.nodes[0]
        .submit_create(
            "sample-contract",
            "AssetHolding:AssetHolding",
            &holding(&alice),
            "create",
            timeout,
        )
        .expect("create");
    assert_eq!(verdict, Verdict::Approved);
    assert_eq!(p.locate(&cid), Some(0));
    // a contract that is not on the source cannot be unassigned from it
    assert!(p
        .unassign(&cid, &sync_b, &sync_a, &alice, "wrong-source", timeout)
        .is_err());

    let u = p
        .unassign(&cid, &sync_a, &sync_b, &alice, "unassign", timeout)
        .expect("unassign");
    assert_eq!(
        u.verdict,
        Verdict::Approved,
        "notes: {:?}",
        p.nodes[0].last_notes
    );
    assert_eq!(u.counter, 1);
    let at = u.request_id.expect("the unassignment's request id");
    assert_eq!(
        u.reassignment_id,
        reassignment_id(&logical(&sync_a), &logical(&sync_b), at, &[(&cid, 1)])
    );
    assert_eq!(p.locate(&cid), None, "in flight between the synchronizers");
    assert!(
        p.nodes[0].instance_bytes(&cid).is_none(),
        "not exercisable on syncA any more"
    );

    let a = p
        .assign(&u, &sync_a, &sync_b, &alice, "assign", timeout)
        .expect("assign");
    assert_eq!(
        a.verdict,
        Verdict::Approved,
        "notes: {:?}",
        p.nodes[1].last_notes
    );
    assert_eq!(a.counter, 1);
    assert!(
        a.request_id.is_some_and(|t| t > at),
        "the assignment is sequenced after the unassignment"
    );
    assert_eq!(p.locate(&cid), Some(1));
    assert_eq!(p.nodes[1].reassignment_counter(&cid), 1);

    // the contract is used on its new synchronizer
    let verdict = p.nodes[1]
        .submit_exercise(
            &cid,
            "Settle",
            &Value::Record {
                tycon: None,
                fields: vec![],
            },
            std::slice::from_ref(&alice),
            "settle-on-b",
            timeout,
        )
        .expect("settle on syncB");
    assert_eq!(
        verdict,
        Verdict::Approved,
        "notes: {:?}",
        p.nodes[1].last_notes
    );
    assert!(!p.nodes[1].is_active(&cid));
}
