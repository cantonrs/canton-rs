//! S-STORE-004: the request-log store. A service rebuilt from its log must answer exactly like the one that wrote it (parties,
//! users, packages, active contracts, updates, dedup), a crash at any write boundary must leave either the whole request or none
//! of it, and a request whose answer was lost must be answered with DUPLICATE_COMMAND on retry.
//!
//! Docker-free: the log is a temp file; the DAR is `contracts/target/sample-contract.dar`.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::*;
use ledger_json_api::store::{FileLog, LoggedRequest, RequestLog};
use ledger_json_api::ExecutionService;
use lf_eval::durable::CrashPoint;

/// A log backend that can be told to crash on its next append (the crash point is shared with the test).
struct Hooked {
    inner: FileLog,
    crash: Arc<Mutex<Option<CrashPoint>>>,
}

impl RequestLog for Hooked {
    fn load(&mut self) -> std::io::Result<Vec<LoggedRequest>> {
        self.inner.load()
    }
    fn append(&mut self, rec: &LoggedRequest) -> std::io::Result<()> {
        if let Some(p) = self.crash.lock().unwrap().take() {
            self.inner.inject_crash(p);
        }
        self.inner.append(rec)
    }
}

type CrashSlot = Arc<Mutex<Option<CrashPoint>>>;

fn open(path: &Path) -> (ExecutionService, CrashSlot, usize) {
    let svc = ExecutionService::new();
    let crash: CrashSlot = Arc::new(Mutex::new(None));
    let log = Hooked {
        inner: FileLog::open(path).expect("open log"),
        crash: Arc::clone(&crash),
    };
    let report = svc.attach_store(Box::new(log)).expect("attach store");
    (svc, crash, report.replayed)
}

fn temp_log() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.log");
    (dir, path)
}

#[test]
fn restart_at_every_step_rebuilds_the_same_ledger() {
    let mut finals = Vec::new();
    for restart_after in 0..STEPS {
        let (_dir, path) = temp_log();
        let (svc, _, replayed) = open(&path);
        assert_eq!(replayed, 0);
        for (n, want) in EXPECTED_STATUS.iter().enumerate().take(restart_after + 1) {
            let code = step(&svc, n);
            assert_eq!(code, *want, "step {n}");
        }
        let before = snapshot_if_ready(&svc, restart_after);
        drop(svc);
        let (svc, _, replayed) = open(&path);
        assert!(replayed > 0 || restart_after == 6);
        let after = snapshot_if_ready(&svc, restart_after);
        assert_eq!(
            after, before,
            "the rebuilt ledger differs after step {restart_after}"
        );
        for n in restart_after + 1..STEPS {
            step(&svc, n);
        }
        finals.push(stripped(snapshot(&svc)));
    }
    // restarting anywhere in the script ends in the same ledger as any other restart point (up to the run's own timestamps)
    for f in &finals[1..] {
        assert_same(f, &finals[0], "final ledgers of different restart points");
    }
}

#[test]
fn restart_equals_an_uninterrupted_run() {
    let (_d1, p1) = temp_log();
    let (_d2, p2) = temp_log();
    let (straight, _, _) = open(&p1);
    for n in 0..STEPS {
        step(&straight, n);
    }
    let (first, _, _) = open(&p2);
    for n in 0..5 {
        step(&first, n);
    }
    drop(first);
    let (second, _, _) = open(&p2);
    for n in 5..STEPS {
        step(&second, n);
    }
    assert_same(
        &stripped(snapshot(&second)),
        &stripped(snapshot(&straight)),
        "restarted vs uninterrupted",
    );
}

#[test]
fn only_state_changing_successes_are_logged() {
    let (_dir, path) = temp_log();
    let (svc, _, _) = open(&path);
    for n in 0..STEPS {
        step(&svc, n);
    }
    // reads and the refused step 6 and the duplicate step 8 are not in the log: dar, 2 parties, user, 3 commands
    let mut log = FileLog::open(&path).unwrap();
    let records = log.load().unwrap();
    let paths: Vec<_> = records.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/v2/dars",
            "/v2/parties",
            "/v2/parties",
            "/v2/users",
            "/v2/commands/submit-and-wait",
            "/v2/commands/submit-and-wait",
            "/v2/commands/submit-and-wait",
            "/v2/commands/submit-and-wait", // the rejected two-command submission: it drew an id, so it is kept
            "/v2/commands/submit-and-wait",
        ]
    );
    // the log keeps no credential: v1 tokens become the parties they grant
    assert!(records
        .iter()
        .all(|r| r.headers.iter().all(|(k, _)| k != "authorization")));
}

#[test]
fn crash_at_every_write_boundary_keeps_all_or_none_of_the_request() {
    for point in CrashPoint::ALL {
        let (_dir, path) = temp_log();
        let (svc, crash, _) = open(&path);
        for n in 0..4 {
            step(&svc, n);
        }
        let (bank, owner) = (party(&svc, "bank"), party(&svc, "owner"));
        let synced_before = std::fs::metadata(&path).unwrap().len();
        *crash.lock().unwrap() = Some(point);
        // the commit happens in memory, the record cannot be completed: the client gets no success
        let (code, _) = create(&svc, "cx", &bank, &owner, "7.0");
        assert_eq!(code, 503, "{point:?}");
        // the service stops taking writes (its memory is ahead of its disk) but still reads
        let (again, _) = create(&svc, "cy", &bank, &owner, "8.0");
        assert_eq!(again, 503);
        assert_eq!(call(&svc, "GET", "/v2/parties", vec![]).0, 200);
        drop(svc);

        if point == CrashPoint::AfterWriteBeforeSync {
            // a power failure: what was written but not synced is gone
            lf_eval::recfile::RecordFile::lose_unsynced(&path, synced_before).unwrap();
        }
        let (svc, _, _) = open(&path);
        let retry = create(&svc, "cx", &bank, &owner, "7.0");
        if point == CrashPoint::AfterSyncBeforeReturn {
            // durable, answer lost: the retry must not create a second contract
            assert_eq!(retry.0, 409, "{point:?} {}", retry.1);
            assert!(
                retry.1.to_string().contains("DUPLICATE_COMMAND"),
                "{}",
                retry.1
            );
        } else {
            assert_eq!(retry.0, 200, "{point:?} {}", retry.1);
        }
        // either way exactly one contract of 7.0 exists
        let sevens = acs(&svc, &owner)
            .to_string()
            .matches("\"amount\":\"7.0000000000\"")
            .count();
        assert_eq!(sevens, 1, "{point:?}");
    }
}

#[test]
fn a_log_that_no_longer_replays_refuses_to_start() {
    let (_dir, path) = temp_log();
    {
        let (svc, _, _) = open(&path);
        for n in 0..5 {
            step(&svc, n);
        }
    }
    // keep only the commands: replay without the DAR and parties must fail loudly, not start an empty ledger
    let mut log = FileLog::open(&path).unwrap();
    let records = log.load().unwrap();
    let (_d2, p2) = temp_log();
    let mut broken = FileLog::open(&p2).unwrap();
    for r in records.iter().filter(|r| r.path.contains("commands")) {
        broken.append(r).unwrap();
    }
    drop(broken);
    let svc = ExecutionService::new();
    let err = svc
        .attach_store(Box::new(FileLog::open(&p2).unwrap()))
        .expect_err("the replay must fail");
    assert!(err.contains("replay of record 0"), "{err}");
}

/// S-STORE-007: a prune is state that must survive a restart (the admin route is logged and replayed at its original time).
#[test]
fn a_prune_survives_a_restart() {
    let (_dir, path) = temp_log();
    let (svc, _, _) = open(&path);
    svc.set_max_dedup(std::time::Duration::from_secs(10));
    for n in 0..6 {
        step(&svc, n);
    }
    ledger_json_api::clock::advance(60_000_000); // the commands are now older than the deduplication window
    let end = call(&svc, "GET", "/v2/state/ledger-end", vec![]).1["offset"]
        .as_u64()
        .unwrap();
    let body = serde_json::to_vec(&serde_json::json!({ "pruneUpTo": end - 1 })).unwrap();
    let (code, answer) = call(&svc, "POST", "/v2/admin/prune", body);
    assert_eq!(code, 200, "{answer}");
    let latest = call(&svc, "GET", "/v2/state/latest-pruned-offsets", vec![]);
    assert_eq!(latest.1["participantPrunedUpToInclusive"], end - 1);
    drop(svc);

    let (svc, _, _) = open(&path);
    assert_eq!(
        call(&svc, "GET", "/v2/state/latest-pruned-offsets", vec![]),
        latest
    );
    // a read below the pruned offset is refused after the restart as before
    let (code, refused) = post(
        &svc,
        "/v2/state/active-contracts",
        serde_json::json!({"eventFormat":{"filtersByParty":{party(&svc, "owner"):{"cumulative":[{"identifierFilter":
            {"WildcardFilter":{"value":{"includeCreatedEventBlob":false}}}}]}},"verbose":true},"activeAtOffset":1}),
    );
    assert_eq!(code, 400, "{refused}");
    assert_eq!(refused["code"], "PARTICIPANT_PRUNED_DATA_ACCESSED");
}
