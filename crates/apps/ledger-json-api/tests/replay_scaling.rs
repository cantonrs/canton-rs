//! S-STORE-006 (U-16): replaying the request log must cost time proportional to its length. The replay used to be quadratic: every
//! command copied the whole ledger (contracts, active set, journal, update stream) before it ran, so a log three times as long took
//! about nine times as long to replay. This test builds a log of N and of 4N commands in memory (no disk) and compares the replays.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use ledger_json_api::store::{LoggedRequest, RequestLog};
use ledger_json_api::ExecutionService;

/// A log in memory shared between services, so building it costs no `fsync`.
#[derive(Clone, Default)]
struct MemLog(Arc<Mutex<Vec<LoggedRequest>>>);

impl RequestLog for MemLog {
    fn load(&mut self) -> std::io::Result<Vec<LoggedRequest>> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn append(&mut self, rec: &LoggedRequest) -> std::io::Result<()> {
        self.0.lock().unwrap().push(rec.clone());
        Ok(())
    }
}

/// Builds a ledger of `n` created contracts and returns the log and the time a replay of it takes (microseconds).
fn build_and_replay(n: usize) -> (usize, u128) {
    let log = MemLog::default();
    let svc = ExecutionService::new();
    svc.attach_store(Box::new(log.clone())).unwrap();
    for step_no in 0..3 {
        assert_eq!(step(&svc, step_no), 200);
    }
    let (bank, owner) = (party(&svc, "bank"), party(&svc, "owner"));
    for i in 0..n {
        let (code, body) = create(
            &svc,
            &format!("n{i}"),
            &bank,
            &owner,
            &format!("{}.0", i + 1),
        );
        assert_eq!(code, 200, "{body}");
    }
    let records = log.0.lock().unwrap().len();
    let replayed = ExecutionService::new();
    let report = replayed.attach_store(Box::new(log)).unwrap();
    assert_eq!(report.replayed, records);
    // the replayed ledger holds all the contracts
    assert_eq!(acs(&replayed, &owner).as_array().unwrap().len(), n);
    (records, report.micros)
}

#[test]
fn replay_time_grows_in_proportion_to_the_log() {
    let (small_records, small) = build_and_replay(300);
    let (large_records, large) = build_and_replay(1200);
    assert!(large_records > 2 * small_records);
    // 4x the records: proportional growth gives at most 4x (measured 2.3x: the DAR load is a fixed cost), copying two of the
    // stores per command again gives 5.9x (measured with that mutation) and the old full quadratic replay more.
    let ratio = large as f64 / small.max(1) as f64;
    eprintln!("replay of {large_records} records: {large} us, of {small_records}: {small} us, ratio {ratio:.1}");
    assert!(
        ratio < 4.0,
        "replaying 4x the commands took {ratio:.1}x as long ({small} us vs {large} us): quadratic again?"
    );
}
