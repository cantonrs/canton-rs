use super::{Conflict, Effects, Ledger, Timeouts};

fn effects(consumes: &[&str], creates: &[&str]) -> Effects {
    Effects {
        consumes: consumes.iter().map(|s| s.to_string()).collect(),
        creates: creates
            .iter()
            .map(|s| (s.to_string(), "M:T".to_string()))
            .collect(),
        instances: Vec::new(),
        remote_events: Vec::new(),
    }
}

#[test]
fn a_contract_is_active_only_after_an_approved_verdict() {
    let mut l = Ledger::new();
    l.begin(1, effects(&[], &["a"])).unwrap();
    assert!(!l.is_active("a"), "in flight is not active");
    assert!(l.resolve(1, true).unwrap());
    assert!(l.is_active("a"));
    // a rejected creation leaves nothing
    l.begin(2, effects(&[], &["b"])).unwrap();
    assert!(l.resolve(2, false).unwrap());
    assert!(!l.is_active("b"));
    assert_eq!(l.in_flight(), 0);
}

#[test]
fn a_contract_cannot_be_consumed_twice() {
    let mut l = Ledger::new();
    l.begin(1, effects(&[], &["a"])).unwrap();
    l.resolve(1, true).unwrap();
    l.begin(2, effects(&["a"], &[])).unwrap();
    l.resolve(2, true).unwrap();
    assert!(!l.is_active("a"));
    assert_eq!(l.archived_by("a"), Some(2));
    assert_eq!(
        l.begin(3, effects(&["a"], &[])),
        Err(Conflict::ArchivedContract {
            id: "a".into(),
            by_request: 2
        })
    );
}

#[test]
fn a_contract_in_flight_is_locked_and_a_rejection_frees_it() {
    let mut l = Ledger::new();
    l.begin(1, effects(&[], &["a"])).unwrap();
    l.resolve(1, true).unwrap();
    l.begin(2, effects(&["a"], &[])).unwrap();
    assert_eq!(
        l.begin(3, effects(&["a"], &[])),
        Err(Conflict::LockedContract {
            id: "a".into(),
            by_request: 2
        })
    );
    l.resolve(2, false).unwrap();
    assert!(l.is_active("a"), "a rejected request does not consume");
    l.begin(4, effects(&["a"], &[])).unwrap();
}

#[test]
fn unknown_and_duplicate_contracts_are_refused() {
    let mut l = Ledger::new();
    assert_eq!(
        l.begin(1, effects(&["x"], &[])),
        Err(Conflict::UnknownContract("x".into()))
    );
    l.begin(2, effects(&[], &["a"])).unwrap();
    assert_eq!(
        l.begin(3, effects(&[], &["a"])),
        Err(Conflict::LockedContract {
            id: "a".into(),
            by_request: 2,
        }),
        "a contract another request in flight creates"
    );
    l.resolve(2, true).unwrap();
    assert_eq!(
        l.begin(4, effects(&[], &["a"])),
        Err(Conflict::ContractAlreadyExists("a".into()))
    );
    assert_eq!(
        l.begin(2, effects(&[], &["z"])),
        Err(Conflict::RequestAlreadyDecided(2)),
        "a decided request is not processed again"
    );
    l.begin(9, effects(&[], &["y"])).unwrap();
    assert_eq!(
        l.begin(9, effects(&[], &["w"])),
        Err(Conflict::RequestAlreadyInFlight(9))
    );
}

#[test]
fn a_refused_request_locks_nothing() {
    let mut l = Ledger::new();
    l.begin(1, effects(&[], &["a"])).unwrap();
    l.resolve(1, true).unwrap();
    // consumes `a` (fine) and creates `a` again (not fine): nothing is locked afterwards
    assert!(l.begin(2, effects(&["a"], &["a"])).is_err());
    l.begin(3, effects(&["a"], &[])).unwrap();
}

/// A root that consumes what an earlier root of the same request created: the contract is transient, never active, and archived by the
/// request once it is approved; a rejection leaves nothing.
#[test]
fn a_contract_created_and_consumed_by_one_request_is_transient() {
    let mut l = Ledger::new();
    let mut both = effects(&["t"], &["t", "kept"]);
    both.instances = vec![b"t".to_vec(), b"kept".to_vec()];
    l.begin(1, both).unwrap();
    assert_eq!(
        l.begin(2, effects(&["t"], &[])),
        Err(Conflict::LockedContract {
            id: "t".into(),
            by_request: 1
        }),
        "a transient contract in flight is locked"
    );
    assert!(l.resolve(1, true).unwrap());
    assert!(!l.is_active("t"));
    assert!(l.is_active("kept"));
    assert_eq!(l.archived_by("t"), Some(1));
    let applied = l.take_applied().unwrap();
    assert!(applied.consumed.is_empty(), "{applied:?}");
    assert_eq!(
        applied.created,
        vec![("kept".to_string(), b"kept".to_vec())]
    );
    l.begin(3, effects(&["u"], &["u"])).unwrap();
    assert!(l.resolve(3, false).unwrap());
    assert!(!l.is_active("u"));
    assert_eq!(l.archived_by("u"), None);
}

fn temp_journal(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("view-acs-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger.journal");
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn an_unassigned_contract_leaves_without_being_archived_and_can_come_back() {
    let path = temp_journal("reassign");
    {
        let mut l = Ledger::open(&path).unwrap();
        l.import("c", "M:T").unwrap();
        l.begin_reassignment(
            1,
            crate::reassignment_wire::Kind::Unassignment,
            vec!["c".into()],
            vec![],
            vec![("c".into(), 1)],
            i64::MAX,
        )
        .unwrap();
        assert!(!l.is_active("c") || l.in_flight() == 1);
        assert!(l.resolve(1, true).unwrap());
    }
    // replayed: gone from here, not archived, counter 1
    let mut l = Ledger::open(&path).unwrap();
    assert!(!l.is_active("c"));
    assert_eq!(l.archived_by("c"), None);
    assert_eq!(l.unassigned_by("c"), Some(1));
    assert_eq!(l.counter_of("c"), 1);
    // the contract comes back (an assignment with counter 2), and a rejected one changes nothing
    l.begin_reassignment(
        2,
        crate::reassignment_wire::Kind::Assignment,
        vec![],
        vec![("c".into(), "M:T".into(), vec![9])],
        vec![("c".into(), 2)],
        i64::MAX,
    )
    .unwrap();
    assert!(l.resolve(2, true).unwrap());
    assert_eq!(
        l.take_applied().map(|a| a.created),
        Some(vec![("c".to_string(), vec![9])])
    );
    drop(l);
    let mut l = Ledger::open(&path).unwrap();
    assert!(l.is_active("c"));
    assert_eq!(l.unassigned_by("c"), None);
    assert_eq!(l.counter_of("c"), 2);
    l.begin_reassignment(
        3,
        crate::reassignment_wire::Kind::Unassignment,
        vec!["c".into()],
        vec![],
        vec![("c".into(), 3)],
        i64::MAX,
    )
    .unwrap();
    assert!(l.resolve(3, false).unwrap());
    assert!(l.is_active("c"));
    assert_eq!(l.counter_of("c"), 2);
}

#[test]
fn a_restart_replays_the_journal_to_the_same_state() {
    let path = temp_journal("restart");
    {
        let mut l = Ledger::open(&path).unwrap();
        l.import("old", "M:T").unwrap();
        l.begin(1, effects(&[], &["a"])).unwrap();
        l.resolve(1, true).unwrap();
        l.begin(2, effects(&["a", "old"], &[])).unwrap();
        // process "dies" here: request 2 is in flight
    }
    let mut l = Ledger::open(&path).unwrap();
    assert!(l.is_active("a") && l.is_active("old"));
    assert_eq!(l.in_flight(), 1, "request 2 is still in flight");
    // what request 2 touches is still locked after the restart
    assert_eq!(
        l.begin(3, effects(&["a"], &[])),
        Err(Conflict::LockedContract {
            id: "a".into(),
            by_request: 2
        })
    );
    // the verdict arrives after the restart
    assert!(l.resolve(2, true).unwrap());
    assert_eq!(l.archived_by("a"), Some(2));
    assert_eq!(l.archived_by("old"), Some(2));
    // and once more after another restart
    drop(l);
    let l = Ledger::open(&path).unwrap();
    assert!(l.active_ids().is_empty());
    assert_eq!(l.archived_by("old"), Some(2));
    assert_eq!(l.in_flight(), 0);
}

#[test]
fn events_processed_again_after_a_restart_change_nothing() {
    let path = temp_journal("again");
    let mut l = Ledger::open(&path).unwrap();
    l.begin(1, effects(&[], &["a"])).unwrap();
    l.resolve(1, true).unwrap();
    drop(l);
    // the participant re-reads the events from before the restart
    let mut l = Ledger::open(&path).unwrap();
    assert_eq!(
        l.begin(1, effects(&[], &["a"])),
        Err(Conflict::RequestAlreadyDecided(1))
    );
    assert!(
        !l.resolve(1, true).unwrap(),
        "the verdict of a decided request is ignored"
    );
    assert_eq!(l.active_ids(), vec!["a".to_string()]);
}

#[test]
fn a_record_the_process_died_writing_is_ignored_and_cut_off() {
    let path = temp_journal("torn");
    {
        let mut l = Ledger::open(&path).unwrap();
        l.begin(1, effects(&[], &["a"])).unwrap();
        l.resolve(1, true).unwrap();
    }
    // a torn record: half a line, no newline
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"B\t2\ta\t").unwrap();
    }
    let mut l = Ledger::open(&path).unwrap();
    assert!(l.is_active("a"), "the torn record never happened");
    assert_eq!(l.in_flight(), 0);
    l.begin(2, effects(&["a"], &[])).unwrap();
    drop(l);
    let l = Ledger::open(&path).unwrap();
    assert_eq!(
        l.in_flight(),
        1,
        "the record written after the cut is whole"
    );
}

#[test]
fn a_journal_that_cannot_be_written_stops_the_change() {
    let mut l = Ledger::open(&temp_journal("readonly")).unwrap();
    l.begin(1, effects(&[], &["a"])).unwrap();
    // a journal in a store that cannot be written: every append fails
    struct Unwritable;
    impl crate::state_store::StateStore for Unwritable {
        fn read(&self, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn write(&self, _: &str, _: &str) -> Result<(), String> {
            Err("read-only".into())
        }
        fn append(&self, _: &str, _: &str) -> Result<(), String> {
            Err("read-only".into())
        }
        fn create_new(&self, _: &str, _: &str) -> Result<bool, String> {
            Err("read-only".into())
        }
        fn describe(&self) -> String {
            "a store that cannot be written".into()
        }
    }
    let mut bad = Ledger::open_in(std::sync::Arc::new(Unwritable), "ledger.journal").unwrap();
    assert!(matches!(
        bad.begin(1, effects(&[], &["a"])),
        Err(Conflict::Journal(_))
    ));
    assert_eq!(
        bad.in_flight(),
        0,
        "a change that could not be made durable is not made"
    );
    assert!(matches!(bad.import("x", "M:T"), Err(Conflict::Journal(_))));
    assert!(!bad.is_active("x"));
}

#[test]
fn an_import_does_not_overwrite_what_is_known() {
    let mut l = Ledger::new();
    l.import("a", "M:T").unwrap();
    assert_eq!(
        l.import("a", "M:T"),
        Err(Conflict::ContractAlreadyExists("a".into()))
    );
    l.begin(1, effects(&["a"], &[])).unwrap();
    l.resolve(1, true).unwrap();
    assert_eq!(
        l.import("a", "M:T"),
        Err(Conflict::ContractAlreadyExists("a".into())),
        "an archived contract is not imported again"
    );
}

#[test]
fn a_request_whose_verdict_never_comes_is_rejected_at_its_decision_time() {
    let t = Timeouts::default();
    let mut l = Ledger::new();
    l.begin(1, effects(&[], &["a"])).unwrap();
    l.resolve(1, true).unwrap();
    let request = 1_000_000_000_000;
    l.begin_until(request, effects(&["a"], &[]), t.decision_time(request))
        .unwrap();
    assert_eq!(
        l.expire(t.decision_time(request) - 1).unwrap(),
        Vec::<i64>::new(),
        "not yet"
    );
    assert_eq!(l.in_flight(), 1);
    assert_eq!(l.expire(t.decision_time(request)).unwrap(), vec![request]);
    assert_eq!(l.in_flight(), 0);
    assert!(
        l.is_active("a"),
        "a request that timed out consumed nothing"
    );
    // the lock is gone: the contract can be consumed by the next request
    l.begin(request + 1, effects(&["a"], &[])).unwrap();
}

#[test]
fn the_decision_time_survives_a_restart_and_an_approved_request_is_not_expired() {
    let path = temp_journal("deadline");
    let mut l = Ledger::open(&path).unwrap();
    l.import("a", "M:T").unwrap();
    l.begin_until(10, effects(&["a"], &[]), 100).unwrap();
    l.begin_until(11, effects(&[], &["b"]), 100).unwrap();
    l.resolve(11, true).unwrap();
    drop(l);
    let mut l = Ledger::open(&path).unwrap();
    assert_eq!(l.expire(99).unwrap(), Vec::<i64>::new());
    assert_eq!(
        l.expire(100).unwrap(),
        vec![10],
        "only the request still in flight expires"
    );
    assert!(l.is_active("a") && l.is_active("b"));
    drop(l);
    let l = Ledger::open(&path).unwrap();
    assert_eq!(l.in_flight(), 0, "the expiry was journaled");
}

/// P-13: a request begun before a restart and approved after it hands over the instances of what it created, the ones it kept refused too.
#[test]
fn a_request_in_flight_across_a_restart_keeps_the_instances_it_creates() {
    let path = temp_journal("instances");
    let mut l = Ledger::open(&path).unwrap();
    l.import("a", "M:T").unwrap();
    let mut begun = effects(&["a"], &["b"]);
    begun.instances = vec![vec![0xb0, 0x0b]];
    l.begin_until(10, begun, 100).unwrap();
    let mut refused = effects(&[], &["c"]);
    refused.instances = vec![vec![0xc0]];
    l.keep_refused(10, refused, 100).unwrap();
    l.begin_until(11, effects(&[], &["d"]), 100).unwrap();
    drop(l);
    let mut l = Ledger::open(&path).unwrap();
    assert!(l.resolve(10, true).unwrap());
    let applied = l.take_applied().expect("the approval changed the set");
    assert_eq!(
        applied.created,
        vec![
            ("b".to_string(), vec![0xb0, 0x0b]),
            ("c".to_string(), vec![0xc0])
        ]
    );
    assert!(l.resolve(11, true).unwrap());
    assert!(
        l.take_applied().unwrap().created.is_empty(),
        "a request whose effects did not come from a view has no instance to hand over"
    );
    drop(l);
    let mut l = Ledger::open(&path).unwrap();
    let kept = l.take_replayed_instances();
    assert_eq!(
        kept.keys().collect::<Vec<_>>(),
        vec!["b", "c"],
        "the replay knows the instances of the active contracts it created"
    );
    assert!(l.take_replayed_instances().is_empty(), "taken once");
}

#[test]
fn the_time_limits_follow_the_synchronizers_parameters() {
    let t = Timeouts::default();
    assert_eq!(t.response_deadline(100), 100 + 30_000_000);
    assert_eq!(t.decision_time(100), 100 + 60_000_000);
    assert!(
        !t.too_late(100, 100 + 30_000_000),
        "the deadline itself is still in time"
    );
    assert!(t.too_late(100, 100 + 30_000_001));
    let slow = Timeouts {
        confirmation_response_micros: 5,
        mediator_reaction_micros: 7,
    };
    assert_eq!(slow.decision_time(1), 13);
}

#[test]
fn an_answered_request_is_remembered_across_a_restart() {
    let path = temp_journal("answered");
    let mut l = Ledger::open(&path).unwrap();
    assert!(!l.knows_request(7));
    assert!(l.mark_answered(7).unwrap());
    assert!(!l.mark_answered(7).unwrap(), "answered once only");
    assert!(l.knows_request(7));
    drop(l);
    let l = Ledger::open(&path).unwrap();
    assert!(l.knows_request(7), "the journal remembers it");
}

#[test]
fn keep_refused_reassignment_is_atomic_on_journal_failure_and_roundtrips() {
    use crate::state_store::StateStore;
    use std::sync::{Arc, Mutex};

    struct FailNthAppend {
        text: Mutex<String>,
        fail_on_call: usize,
        calls: Mutex<usize>,
    }
    impl StateStore for FailNthAppend {
        fn read(&self, _key: &str) -> Result<Option<String>, String> {
            Ok(Some(self.text.lock().unwrap().clone()))
        }
        fn write(&self, _key: &str, text: &str) -> Result<(), String> {
            *self.text.lock().unwrap() = text.to_string();
            Ok(())
        }
        fn append(&self, _key: &str, line: &str) -> Result<(), String> {
            let mut n = self.calls.lock().unwrap();
            *n += 1;
            if *n == self.fail_on_call {
                return Err("injected append failure".to_string());
            }
            let mut t = self.text.lock().unwrap();
            t.push_str(line);
            t.push('\n');
            Ok(())
        }
        fn create_new(&self, _key: &str, _text: &str) -> Result<bool, String> {
            Ok(true)
        }
        fn describe(&self) -> String {
            "FailNthAppend".to_string()
        }
    }

    // 1. Failing during `keep_refused_reassignment` must leave ZERO partial lines on disk
    //    (no orphaned `F` line without `X`).
    let store2 = Arc::new(FailNthAppend {
        text: Mutex::new(String::new()),
        fail_on_call: 3, // append 1 = import, append 2 = F (pre-fix), append 3 = X (pre-fix)
        calls: Mutex::new(0),
    });
    let mut l2 =
        Ledger::open_in(Arc::clone(&store2) as Arc<dyn StateStore>, "ledger.journal").unwrap();
    l2.import("a", "M:T").unwrap(); // append #1
    let fail_first_append = Arc::new(FailNthAppend {
        text: Mutex::new(String::new()),
        fail_on_call: 2, // fails on the 1st append of keep_refused_reassignment
        calls: Mutex::new(0),
    });
    let mut l_fail_first = Ledger::open_in(
        Arc::clone(&fail_first_append) as Arc<dyn StateStore>,
        "ledger.journal",
    )
    .unwrap();
    l_fail_first.import("a", "M:T").unwrap();
    let res1 = l_fail_first.keep_refused_reassignment(
        42,
        crate::reassignment_wire::Kind::Unassignment,
        vec!["a".to_string()],
        Vec::new(),
        vec![("a".to_string(), 1)],
        500,
    );
    assert!(res1.is_err());
    assert!(
        !fail_first_append.text.lock().unwrap().contains("\nF\t"),
        "journal failure must leave zero orphaned F lines: {}",
        fail_first_append.text.lock().unwrap()
    );
    let res2 = l2.keep_refused_reassignment(
        42,
        crate::reassignment_wire::Kind::Unassignment,
        vec!["a".to_string()],
        Vec::new(),
        vec![("a".to_string(), 1)],
        500,
    );
    // Under single-line FX, res2 succeeds cleanly in 1 append; under legacy 2-line F+X, res2 fails on X leaving orphaned F!
    assert!(
        !store2.text.lock().unwrap().contains("\nF\t"),
        "failing on second append must never leave orphaned F line on disk: {} (res={res2:?})",
        store2.text.lock().unwrap()
    );

    let store3 = Arc::new(FailNthAppend {
        text: Mutex::new(String::new()),
        fail_on_call: 99,
        calls: Mutex::new(0),
    });
    let mut l3 =
        Ledger::open_in(Arc::clone(&store3) as Arc<dyn StateStore>, "ledger.journal").unwrap();
    l3.import("a", "M:T").unwrap();
    let calls_before = *store3.calls.lock().unwrap();
    l3.keep_refused_reassignment(
        42,
        crate::reassignment_wire::Kind::Unassignment,
        vec!["a".to_string()],
        Vec::new(),
        vec![("a".to_string(), 1)],
        500,
    )
    .unwrap();
    let calls_used = *store3.calls.lock().unwrap() - calls_before;
    assert_eq!(
        calls_used, 1,
        "keep_refused_reassignment must write a single atomic journal record (used {calls_used} appends): {}",
        store3.text.lock().unwrap()
    );
    // Replay round-trip check
    let replayed = Ledger::open_in(store3 as Arc<dyn StateStore>, "ledger.journal").unwrap();
    assert!(replayed.refused_here(42));
    assert!(replayed.reassigning.contains_key(&42));
}
