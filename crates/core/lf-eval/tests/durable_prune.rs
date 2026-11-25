//! AT-T08 (storage side): prune, snapshot and ACS reads on the durable ledger, alone and concurrently.
//!
//! [CANTON-NOTE: LIMITATION] There is no node oracle: pruning is disabled in the Community participant ("The command is currently
//! disabled", measured through the console, UNRESOLVED U-17). The rules here come from the Ledger API contract (a read below the
//! pruned offset is refused, a read at or above it is exact) and are checked against a straightforward model.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use lf_eval::durable::{DurableLedger, ReadError};
use lf_eval::tx_model::{ContractId, Node, TransactionTree};

fn path(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("prune-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("j.log")
}

fn alice() -> HashSet<String> {
    ["alice".to_string()].into_iter().collect()
}

fn create(n: u8) -> (TransactionTree, ContractId) {
    let cid = ContractId::derive("pkg", "Asset", &[n], &[n]);
    let mut t = TransactionTree::new();
    t.insert_node(
        Node::Create {
            contract_id: cid.clone(),
            template_id: "Asset".into(),
            payload: vec![n],
            signatories: alice(),
            observers: HashSet::new(),
            key: None,
        },
        true,
    );
    (t, cid)
}

fn archive(cid: &ContractId) -> TransactionTree {
    let mut t = TransactionTree::new();
    t.insert_node(
        Node::Exercise {
            contract_id: cid.clone(),
            choice: "Archive".into(),
            acting_parties: alice(),
            consuming: true,
            children: vec![],
        },
        true,
    );
    t
}

/// n contracts created at offsets 1..=n.
fn ledger_with(name: &str, n: u8) -> (DurableLedger, Vec<ContractId>, PathBuf) {
    let p = path(name);
    let mut l = DurableLedger::open(&p).unwrap();
    let mut ids = vec![];
    for i in 1..=n {
        let (tx, cid) = create(i);
        l.commit(tx, alice(), i64::from(i), None, None).unwrap();
        ids.push(cid);
    }
    (l, ids, p)
}

#[test]
fn a_snapshot_below_the_pruned_offset_is_refused_and_at_or_above_it_is_exact() {
    let (mut l, ids, _) = ledger_with("basic", 6);
    l.commit(archive(&ids[0]), alice(), 7, None, None).unwrap(); // offset 7 archives contract 1
    l.prune(4).unwrap();
    assert_eq!(l.pruned_up_to(), 4);
    assert_eq!(
        l.acs_at(3),
        Err(ReadError::Pruned {
            requested: 3,
            pruned_up_to: 4
        })
    );
    // at the boundary and above: exactly the contracts created up to that offset and not yet archived
    assert_eq!(l.acs_at(4).unwrap().active_contracts.len(), 4);
    assert_eq!(l.acs_at(6).unwrap().active_contracts.len(), 6);
    let end = l.acs_at(7).unwrap();
    assert_eq!(end.active_contracts.len(), 5);
    assert!(!end.active_contracts.contains_key(&ids[0]));
    assert_eq!(
        l.acs_at(8),
        Err(ReadError::BeyondLedgerEnd {
            requested: 8,
            ledger_end: 7
        })
    );
}

#[test]
fn pruning_is_durable_and_never_goes_backwards_or_past_the_end() {
    let (mut l, _, p) = ledger_with("durable", 5);
    assert!(l.prune(9).is_err(), "cannot prune past the ledger end");
    l.prune(3).unwrap();
    l.prune(2).unwrap(); // a smaller prune is a no-op
    assert_eq!(l.pruned_up_to(), 3);
    drop(l);
    let r = DurableLedger::open(&p).unwrap();
    assert_eq!(r.pruned_up_to(), 3, "the prune marker survives a restart");
    assert_eq!(
        r.acs_at(2),
        Err(ReadError::Pruned {
            requested: 2,
            pruned_up_to: 3
        })
    );
    assert_eq!(
        r.acs_at(5).unwrap().active_contracts.len(),
        5,
        "the snapshot above the boundary is unchanged by the restart"
    );
    assert_eq!(r.ledger_end(), 5);
}

#[test]
fn a_pruned_ledger_keeps_committing_with_the_next_offset() {
    let (mut l, _, p) = ledger_with("continue", 3);
    l.prune(3).unwrap(); // everything is pruned
    let (tx, _) = create(9);
    assert_eq!(l.commit(tx, alice(), 10, None, None).unwrap(), 4);
    drop(l);
    let r = DurableLedger::open(&p).unwrap();
    assert_eq!(r.ledger_end(), 4);
    assert_eq!(r.acs_at(4).unwrap().active_contracts.len(), 4);
}

/// Readers, a pruner and a committer race behind one lock (the service's own shape). Every read returns either a snapshot that
/// equals the model's for that offset, or `Pruned` with a boundary above the requested offset; never a half-state.
#[test]
fn concurrent_commits_prunes_and_snapshots_stay_consistent() {
    let (l, _, _) = ledger_with("race", 5);
    let shared = Arc::new(RwLock::new(l));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut readers = vec![];
    for r in 0..4u8 {
        let (s, st) = (std::sync::Arc::clone(&shared), std::sync::Arc::clone(&stop));
        readers.push(std::thread::spawn(move || {
            let mut checked = 0u32;
            while !st.load(std::sync::atomic::Ordering::SeqCst) {
                let g = s.read().unwrap();
                let end = g.ledger_end();
                let at = (end / 2 + u64::from(r)).min(end);
                match g.acs_at(at) {
                    // the model: contracts are created one per offset and never archived here, so the snapshot at offset N has N contracts
                    Ok(state) => {
                        assert_eq!(state.active_contracts.len() as u64, at, "snapshot at {at}")
                    }
                    Err(ReadError::Pruned {
                        requested,
                        pruned_up_to,
                    }) => assert!(requested < pruned_up_to),
                    Err(e) => panic!("unexpected {e:?}"),
                }
                checked += 1;
            }
            checked
        }));
    }
    for i in 6..=40u8 {
        let (tx, _) = create(i);
        shared
            .write()
            .unwrap()
            .commit(tx, alice(), i64::from(i), None, None)
            .unwrap();
        if i % 5 == 0 {
            let up = shared.read().unwrap().ledger_end() - 2;
            shared.write().unwrap().prune(up).unwrap();
        }
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let total: u32 = readers.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(total > 0);
    let g = shared.read().unwrap();
    assert_eq!(g.ledger_end(), 40);
    assert_eq!(g.acs_at(40).unwrap().active_contracts.len(), 40);
}

/// The test must be able to fail: reading the pruned range really is refused (a ledger that ignored the boundary would pass the
/// "exact" assertions above but not this one).
#[test]
fn the_pruned_range_is_not_readable() {
    let (mut l, _, _) = ledger_with("refused", 4);
    l.prune(4).unwrap();
    for off in 0..4 {
        assert!(
            matches!(l.acs_at(off), Err(ReadError::Pruned { .. })),
            "offset {off}"
        );
    }
}
