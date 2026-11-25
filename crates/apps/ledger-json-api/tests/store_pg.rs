//! S-STORE-005: the request log in PostgreSQL. The same guarantees as `store_restart.rs` (restart equivalence, all-or-none at the
//! write boundary, DUPLICATE_COMMAND for a request whose answer was lost) on a real database, plus what only a database adds:
//! one writer per ledger, a gap or a damaged row refuses to start.
//!
//! Needs a PostgreSQL server: `CANTON_RS_PG_URL=postgres://user:pass@host:port/db` (a missing variable panics, it never skips).
//! The file is compiled only with the `pg-tests` feature so a plain `cargo test` stays Docker-free (no `#[ignore]`: AT-V01);
//! `scripts/verify-pg-store.sh` starts a dedicated container and runs it with `--features pg-tests`.
#![cfg(feature = "pg-tests")]

mod common;

use std::io::ErrorKind;
use std::sync::{Arc, Mutex};

use common::*;
use ledger_json_api::store::{LogSnapshot, LoggedRequest, RequestLog};
use ledger_json_api::store_pg::{PgCrash, PgLog};
use ledger_json_api::ExecutionService;

fn url() -> String {
    std::env::var("CANTON_RS_PG_URL").expect("CANTON_RS_PG_URL must point at a PostgreSQL server")
}

/// A ledger id nobody else uses (each test owns its rows; the database is shared).
fn fresh_ledger(name: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("test-{name}-{}-{nanos}", std::process::id())
}

type CrashSlot = Arc<Mutex<Option<PgCrash>>>;

struct Hooked {
    inner: PgLog,
    crash: CrashSlot,
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
    fn load_snapshot(&mut self) -> std::io::Result<Option<LogSnapshot>> {
        self.inner.load_snapshot()
    }
    fn save_snapshot(&mut self, snap: &LogSnapshot) -> std::io::Result<()> {
        self.inner.save_snapshot(snap)
    }
    fn load_after(&mut self, after_seq: u64) -> std::io::Result<Vec<LoggedRequest>> {
        self.inner.load_after(after_seq)
    }
    fn compact_before(&mut self, seq: u64) -> std::io::Result<()> {
        self.inner.compact_before(seq)
    }
    fn current_seq(&self) -> u64 {
        self.inner.current_seq()
    }
}

/// The database URL with `application_name` set, so a test can terminate exactly its own sessions.
fn url_named(name: &str) -> String {
    let base = url();
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}application_name={name}")
}

fn open(ledger: &str) -> (ExecutionService, CrashSlot, usize) {
    open_at(&url(), ledger)
}

fn open_at(db_url: &str, ledger: &str) -> (ExecutionService, CrashSlot, usize) {
    let svc = ExecutionService::new();
    let crash: CrashSlot = Arc::new(Mutex::new(None));
    let log = Hooked {
        inner: PgLog::connect(db_url, ledger).expect("connect"),
        crash: Arc::clone(&crash),
    };
    let report = svc.attach_store(Box::new(log)).expect("attach store");
    (svc, crash, report.replayed)
}

fn sql() -> postgres::Client {
    postgres::Client::connect(&url(), postgres::NoTls).expect("sql connection")
}

#[test]
fn restart_at_every_step_rebuilds_the_same_ledger() {
    for restart_after in 0..STEPS {
        let ledger = fresh_ledger("restart");
        let (svc, _, replayed) = open(&ledger);
        assert_eq!(replayed, 0);
        for (n, want) in EXPECTED_STATUS.iter().enumerate().take(restart_after + 1) {
            assert_eq!(step(&svc, n), *want, "step {n}");
        }
        let before = snapshot_if_ready(&svc, restart_after);
        drop(svc); // closes the connection: the writer lock is released with it
        let (svc, _, replayed) = open(&ledger);
        assert!(replayed > 0 || restart_after == 6);
        let after = snapshot_if_ready(&svc, restart_after);
        assert_same(
            &after,
            &before,
            &format!("restart after step {restart_after}"),
        );
        for n in restart_after + 1..STEPS {
            step(&svc, n);
        }
    }
}

#[test]
fn the_table_holds_one_row_per_state_changing_request() {
    let ledger = fresh_ledger("rows");
    let (svc, _, _) = open(&ledger);
    for n in 0..STEPS {
        step(&svc, n);
    }
    let rows = sql()
        .query(
            "SELECT seq, method, path, status FROM canton_rs_ledger_log WHERE ledger_id = $1 ORDER BY seq",
            &[&ledger],
        )
        .unwrap();
    let got: Vec<(i64, String, String, i32)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    let seen: Vec<(&str, i32)> = got.iter().map(|(_, _, p, s)| (p.as_str(), *s)).collect();
    // the refused single create (c3), the duplicate (c1 again) leave no trace and are not kept; the refused two-command
    // submission (c5) drew a contract id and is kept with its 400
    let command = "/v2/commands/submit-and-wait";
    assert_eq!(
        seen,
        [
            ("/v2/dars", 200),
            ("/v2/parties", 200),
            ("/v2/parties", 200),
            ("/v2/users", 200),
            (command, 200),
            (command, 200),
            (command, 200),
            (command, 400),
            (command, 200),
        ]
    );
    assert!(got
        .iter()
        .enumerate()
        .all(|(i, (seq, m, _, _))| *seq == i as i64 + 1 && m == "POST"));
}

#[test]
fn crash_at_the_insert_keeps_all_or_none_of_the_request() {
    for point in [PgCrash::BeforeInsert, PgCrash::AfterCommit] {
        let ledger = fresh_ledger("crash");
        let (svc, crash, _) = open(&ledger);
        for n in 0..4 {
            step(&svc, n);
        }
        let (bank, owner) = (party(&svc, "bank"), party(&svc, "owner"));
        *crash.lock().unwrap() = Some(point);
        assert_eq!(create(&svc, "cx", &bank, &owner, "7.0").0, 503, "{point:?}");
        // the service stops taking writes but still reads
        assert_eq!(create(&svc, "cy", &bank, &owner, "8.0").0, 503);
        assert_eq!(call(&svc, "GET", "/v2/parties", vec![]).0, 200);
        drop(svc);

        let (svc, _, _) = open(&ledger);
        let retry = create(&svc, "cx", &bank, &owner, "7.0");
        if point == PgCrash::AfterCommit {
            assert_eq!(retry.0, 409, "{point:?} {}", retry.1);
            assert!(
                retry.1.to_string().contains("DUPLICATE_COMMAND"),
                "{}",
                retry.1
            );
        } else {
            assert_eq!(retry.0, 200, "{point:?} {}", retry.1);
        }
        let sevens = acs(&svc, &owner)
            .to_string()
            .matches("\"amount\":\"7.0000000000\"")
            .count();
        assert_eq!(sevens, 1, "{point:?}");
    }
}

#[test]
fn one_writer_per_ledger() {
    let ledger = fresh_ledger("writer");
    let first = PgLog::connect(&url(), &ledger).unwrap();
    // a second service on the same ledger must not start (it would interleave records)
    let err = PgLog::connect(&url(), &ledger)
        .err()
        .expect("second writer");
    assert_eq!(err.kind(), ErrorKind::AddrInUse, "{err}");
    // another ledger in the same database is independent
    let other = PgLog::connect(&url(), &fresh_ledger("other")).unwrap();
    drop(other);
    // once the first writer is gone (its connection closed) the lock is free again
    drop(first);
    PgLog::connect(&url(), &ledger).expect("the lock is released with the connection");
}

#[test]
fn a_gap_or_a_damaged_row_refuses_to_start() {
    let ledger = fresh_ledger("damage");
    {
        let (svc, _, _) = open(&ledger);
        for n in 0..5 {
            step(&svc, n);
        }
    }
    let mut db = sql();
    // damaged: the record bytes are not a logged request
    db.execute(
        "UPDATE canton_rs_ledger_log SET record = '\\x0102'::bytea WHERE ledger_id = $1 AND seq = 3",
        &[&ledger],
    )
    .unwrap();
    let err = PgLog::connect(&url(), &ledger).err().expect("damaged row");
    assert!(
        err.to_string().contains("undecodable record at seq 3"),
        "{err}"
    );
    // a missing row in the middle: the log has a gap
    db.execute(
        "DELETE FROM canton_rs_ledger_log WHERE ledger_id = $1 AND seq = 3",
        &[&ledger],
    )
    .unwrap();
    let err = PgLog::connect(&url(), &ledger).err().expect("gap");
    assert!(
        err.to_string()
            .contains("has a gap: expected seq 3, found 4"),
        "{err}"
    );
}

#[test]
fn a_database_of_another_layout_version_is_refused() {
    let mut db = sql();
    // use a throwaway schema so the shared tables are untouched
    let schema = fresh_ledger("layout").replace('-', "_");
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; CREATE TABLE {schema}.canton_rs_schema (version integer NOT NULL);
         INSERT INTO {schema}.canton_rs_schema VALUES (99);"
    ))
    .unwrap();
    let url = format!("{}?options=-c%20search_path%3D{schema}", self::url());
    let err = PgLog::connect(&url, "x").err().expect("layout version");
    assert!(err.to_string().contains("layout version 99"), "{err}");
    db.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .unwrap();
}

#[test]
fn snapshot_and_compaction_rebuild_identical_pg_ledger() {
    let ledger = fresh_ledger("snap");
    let (svc, _, replayed0) = open(&ledger);
    assert_eq!(replayed0, 0);
    for n in 0..8 {
        assert_eq!(step(&svc, n), EXPECTED_STATUS[n], "step {n}");
    }
    let compacted_seq = svc
        .compact_store()
        .expect("compact store")
        .expect("seq returned");
    assert!(compacted_seq > 0);
    for n in 8..STEPS {
        assert_eq!(step(&svc, n), EXPECTED_STATUS[n], "step {n}");
    }
    let before = snapshot_if_ready(&svc, STEPS - 1);
    drop(svc);

    // Reopening loads checkpointed prefix and replays only the <=3 tail steps after compacted_seq
    let (svc2, _, tail_replayed) = open(&ledger);
    assert!(
        tail_replayed <= 3,
        "expected only post-compaction tail (<=3) to replay, got {tail_replayed}"
    );
    let after = snapshot_if_ready(&svc2, STEPS - 1);
    assert_same(&after, &before, "PG snapshot + compaction equivalence");
}

#[test]
fn pg_log_reconnects_and_reacquires_lock_after_backend_termination() {
    let ledger = fresh_ledger("reconnect");
    // a short, unique application name (PostgreSQL keeps 63 bytes) that only this test's sessions carry
    let app = format!("rc{}", std::process::id());
    let (svc, _, _) = open_at(&url_named(&app), &ledger);
    for n in 0..4 {
        assert_eq!(step(&svc, n), EXPECTED_STATUS[n]);
    }
    let (bank, owner) = (party(&svc, "bank"), party(&svc, "owner"));
    assert_eq!(create(&svc, "pre-drop", &bank, &owner, "1.0").0, 200);

    // Terminate exactly this test's backend (identified by its application name), never another test's
    let mut admin = sql();
    let killed: i64 = admin
        .query_one(
            "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity \
             WHERE application_name = $1 AND pid <> pg_backend_pid()",
            &[&app],
        )
        .unwrap()
        .get(0);
    assert!(
        killed >= 1,
        "the test's own backend was found and terminated"
    );
    drop(admin);
    std::thread::sleep(std::time::Duration::from_millis(150));

    // Next write automatically reconnects, re-acquires the advisory lock, and persists
    let res = create(&svc, "post-drop", &bank, &owner, "2.0");
    assert_eq!(res.0, 200, "reconnect after termination: {}", res.1);

    // Writer lock must still be held by the reconnected PgLog
    let stolen = PgLog::connect(&url(), &ledger)
        .err()
        .expect("lock must be re-acquired by surviving PgLog");
    assert_eq!(stolen.kind(), ErrorKind::AddrInUse, "{stolen}");
}
