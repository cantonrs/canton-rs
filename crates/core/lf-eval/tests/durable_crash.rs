//! S-STORE-001 / AT-T04: the durable ledger recovers a committed prefix after a crash at EVERY write boundary of a commit, and a
//! retried command is safe (deduplicated if its record survived, committed exactly once if not).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::collections::HashSet;
use std::path::PathBuf;

use lf_eval::durable::{CrashPoint, DedupKey, DurableError, DurableLedger};
use lf_eval::tx_model::{ContractId, Node, TransactionTree};

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("durable-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn parties(p: &str) -> HashSet<String> {
    [p.to_string()].into_iter().collect()
}

/// A transaction that creates one contract; `n` makes the contract id and payload distinct.
fn create_tx(n: u8) -> (TransactionTree, ContractId) {
    let cid = ContractId::derive("pkg", "Asset", &[n], &[n, 100]);
    let mut t = TransactionTree::new();
    t.insert_node(
        Node::Create {
            contract_id: cid.clone(),
            template_id: "Asset".into(),
            payload: vec![n, 100],
            signatories: parties("alice"),
            observers: HashSet::new(),
            key: None,
        },
        true,
    );
    (t, cid)
}

fn key(cmd: &str) -> DedupKey {
    DedupKey {
        user_id: "u".into(),
        command_id: cmd.into(),
        act_as: vec!["alice".into()],
    }
}

/// What a client does after a lost answer: resubmit the same command. Returns the offset it ends up with and whether the ledger
/// answered it from the dedup table.
fn retry(l: &mut DurableLedger, cmd: &str, n: u8) -> (u64, bool) {
    if let Some(e) = l.dedup.get(&key(cmd)) {
        return (e.offset, true);
    }
    let (tx, _) = create_tx(n);
    (
        l.commit(
            tx,
            parties("alice"),
            1_000 * i64::from(n),
            Some(key(cmd)),
            None,
        )
        .unwrap(),
        false,
    )
}

#[test]
fn a_clean_file_replays_to_the_same_ledger() {
    let d = dir("clean");
    let path = d.join("j.log");
    let mut l = DurableLedger::open(&path).unwrap();
    for n in 1..=4u8 {
        let (tx, _) = create_tx(n);
        assert_eq!(
            l.commit(
                tx,
                parties("alice"),
                1000 * i64::from(n),
                Some(key(&format!("c{n}"))),
                None
            )
            .unwrap(),
            u64::from(n)
        );
    }
    let (state, history) = (l.state.clone(), l.history.clone());
    drop(l);
    let r = DurableLedger::open(&path).unwrap();
    assert_eq!(r.recovery.records, 4);
    assert_eq!(r.recovery.truncated_bytes, 0);
    assert_eq!(r.state, state);
    assert_eq!(r.history, history);
    assert_eq!(r.dedup.len(), 4);
    assert_eq!(r.next_offset(), 5);
}

#[test]
fn a_rejected_transaction_writes_nothing() {
    let d = dir("reject");
    let path = d.join("j.log");
    let mut l = DurableLedger::open(&path).unwrap();
    let (tx, cid) = create_tx(1);
    l.commit(tx, parties("alice"), 1, None, None).unwrap();
    let before = std::fs::metadata(&path).unwrap().len();
    // consume a contract that does not exist
    let mut bad = TransactionTree::new();
    bad.insert_node(
        Node::Exercise {
            contract_id: ContractId("00ff".into()),
            choice: "X".into(),
            acting_parties: parties("alice"),
            consuming: true,
            children: vec![],
        },
        true,
    );
    assert!(matches!(
        l.commit(bad, parties("alice"), 2, None, None),
        Err(DurableError::Rejected(_))
    ));
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        before,
        "a rejected commit must not touch the file"
    );
    assert!(l.state.active_contracts.contains_key(&cid));
}

/// The core of AT-T04: for every crash point, the recovered ledger is a prefix of the committed history, the dedup table is
/// exactly the dedup entries of that prefix (a transaction and its dedup record stand or fall together), and a retry of the
/// interrupted command ends with the contract existing exactly once.
#[test]
fn every_crash_point_recovers_a_consistent_prefix_and_a_retry_is_safe() {
    for point in CrashPoint::ALL {
        for lose_unsynced in [false, true] {
            if lose_unsynced && point != CrashPoint::AfterWriteBeforeSync {
                continue;
            }
            let d = dir(&format!("{point:?}-{lose_unsynced}"));
            let path = d.join("j.log");
            let mut l = DurableLedger::open(&path).unwrap();
            let (tx1, cid1) = create_tx(1);
            l.commit(tx1, parties("alice"), 1000, Some(key("c1")), None)
                .unwrap();
            let synced = l.synced_len();
            let (tx2, cid2) = create_tx(2);
            let r = l.commit(tx2, parties("alice"), 2000, Some(key("c2")), Some(point));
            assert!(
                matches!(r, Err(DurableError::Crashed(p)) if p == point),
                "{point:?}: {r:?}"
            );
            drop(l); // the process is dead
            if lose_unsynced {
                DurableLedger::lose_unsynced(&path, synced).unwrap();
            }

            let mut rec = DurableLedger::open(&path).unwrap();
            let record2_survives = matches!(point, CrashPoint::AfterSyncBeforeReturn)
                || (point == CrashPoint::AfterWriteBeforeSync && !lose_unsynced);
            let tag = format!("{point:?} lose_unsynced={lose_unsynced}");
            // prefix: the first commit is always there, the second iff its record is whole
            assert_eq!(
                rec.history.len(),
                if record2_survives { 2 } else { 1 },
                "{tag}"
            );
            assert!(rec.state.active_contracts.contains_key(&cid1), "{tag}");
            assert_eq!(
                rec.state.active_contracts.contains_key(&cid2),
                record2_survives,
                "{tag}"
            );
            // atomicity: the dedup entry of c2 exists exactly when its transaction does
            assert_eq!(
                rec.dedup.contains_key(&key("c2")),
                record2_survives,
                "{tag}"
            );
            assert!(rec.dedup.contains_key(&key("c1")), "{tag}");
            // a torn record was cut off, a whole one was not
            let torn = matches!(point, CrashPoint::MidHeader | CrashPoint::MidBody);
            assert_eq!(rec.recovery.truncated_bytes > 0, torn, "{tag}");
            // the retry: answered from the dedup table when the record survived, committed once otherwise
            let (offset, deduplicated) = retry(&mut rec, "c2", 2);
            assert_eq!(deduplicated, record2_survives, "{tag}");
            assert_eq!(
                offset, 2,
                "{tag}: the retried command has offset 2 either way"
            );
            assert_eq!(
                rec.state.active_contracts.len(),
                2,
                "{tag}: exactly two contracts, none twice"
            );
            // and the file is clean and replayable again
            drop(rec);
            let again = DurableLedger::open(&path).unwrap();
            assert_eq!(
                (again.recovery.records, again.recovery.truncated_bytes),
                (2, 0),
                "{tag}"
            );
        }
    }
}

#[test]
fn a_corrupt_byte_inside_a_record_cuts_the_log_at_that_record() {
    let d = dir("corrupt");
    let path = d.join("j.log");
    let mut l = DurableLedger::open(&path).unwrap();
    for n in 1..=3u8 {
        let (tx, _) = create_tx(n);
        l.commit(
            tx,
            parties("alice"),
            i64::from(n),
            Some(key(&format!("c{n}"))),
            None,
        )
        .unwrap();
    }
    drop(l);
    let mut bytes = std::fs::read(&path).unwrap();
    // flip one byte in the body of the second record
    let first_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    let second_body = 8 + first_len + 8;
    bytes[second_body + 5] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    let r = DurableLedger::open(&path).unwrap();
    assert_eq!(
        r.recovery.records, 1,
        "recovery stops at the first record whose checksum fails"
    );
    assert!(r.recovery.truncated_bytes > 0);
    assert_eq!(r.dedup.len(), 1);
}

/// The test must be able to fail: a recovery that kept a half-written record would show it.
#[test]
fn a_half_written_record_is_never_replayed() {
    let d = dir("half");
    let path = d.join("j.log");
    let mut l = DurableLedger::open(&path).unwrap();
    let (tx, _) = create_tx(1);
    let _ = l.commit(
        tx,
        parties("alice"),
        1,
        Some(key("c1")),
        Some(CrashPoint::MidBody),
    );
    drop(l);
    let r = DurableLedger::open(&path).unwrap();
    assert_eq!(r.history.len(), 0);
    assert!(r.state.active_contracts.is_empty());
    assert!(
        r.dedup.is_empty(),
        "a transaction that is not in the log has no dedup entry either"
    );
}
