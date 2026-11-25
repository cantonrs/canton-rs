//! G8 U-39 (S-SPL-036): the receive-side replay of the recorded Splice LocalNet with the official sandbox on a **simulated clock**.
//! The official p1 submits each recorded transaction at its recorded effective time (the harness moves every node's clock there and holds
//! it), so the time-bound Splice choices (a round that opens at a recorded instant, `targetClosesAt`, ledger time against record time) see
//! the times the recording saw. The Rust participant confirms every party, as in `sequencer_connect.rs`'s wall-clock replay (S-SPL-021).
//!
//! Needs the sandbox and its facts: `scripts/verify-receive-simclock.sh`. Compiled only with the `sequencer-tests` feature.
#![cfg(feature = "sequencer-tests")]

mod p1_peer;
use p1_peer::*;

/// Moves the sandbox's simulated clock (`to,<instant>[,freeze]`, `run`, `now`: see the harness script) and returns the clock's time after
/// the command, as the console prints it.
fn clock(command: &str) -> String {
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let name = format!("{}.clockcmd", unique("clock"));
    // written under another name first and renamed: the watcher must not read half a file
    std::fs::write(dir.join(format!("{name}.tmp")), command).unwrap();
    std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
    let needle = format!("SCF clockcmd_done={name}=");
    // [CANTON-NOTE: SEMANTICS] The BFT orderer stamps a block with the leader's clock when it proposes the block, and a block proposed
    // before the clock moved still carries the old time (plus 1 ms per block while the clock is held). A request submitted right after a
    // jump was measured to be sequenced 78 s before its ledger time, which p1 itself refuses (`The delta of the ledger time ... and the
    // record time ... exceeds the max of 1m`). So a move is done only once the sequencer delivers a block stamped at or after the target.
    let target = command
        .strip_prefix("to,")
        .map(|rest| micros_of_iso(rest.split(',').next().unwrap()));
    let mut now = None;
    for _ in 0..1200 {
        let log = node_log();
        if let Some(at) = log.find(&needle) {
            let line = log[at + needle.len()..].lines().next().unwrap_or_default();
            let answer = now.get_or_insert_with(|| line.trim().to_string()).clone();
            assert!(
                !answer.starts_with("error"),
                "the clock refused {command}: {answer}"
            );
            let stamped = |l: &str| {
                l.split("block's BFT time = ")
                    .nth(1)
                    .and_then(|rest| rest.split(',').next())
                    .map(micros_of_iso)
            };
            let Some(target) = target else {
                return answer;
            };
            if log[at..]
                .lines()
                .filter_map(stamped)
                .any(|block| block >= target)
            {
                return answer;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("the harness never answered the clock command {command} (or no block reached its time)");
}

/// The 64 recorded transactions after the bootstrap, submitted by p1 at their recorded times and confirmed by the Rust participant.
/// [CANTON-NOTE: SEMANTICS] p1's Ledger API takes its ledger time from the node's clock (`CantonExternalClockBackend` over the SimClock),
/// and the sequencer stamps the request with the same clock, so a transaction submitted while the clock is held at its recorded effective
/// time has that ledger time and a record time a few microseconds later, as in the recording. The seeds (the contracts the bootstrap left)
/// are created at the bootstrap's recorded effective time, before the first transaction.
#[test]
fn the_rust_participant_confirms_the_recorded_splice_transactions_p1_submits_at_their_recorded_times(
) {
    // the parties are hosted while the clock still runs (a topology change takes effect only once the clock passes its effective time);
    // the first hold is the seeds' time
    let ReceiveReplay {
        results,
        rejects,
        answered,
    } = receive_replay(
        "recv-simclock",
        2400,
        ReplayOptions {
            settle: true,
            split_roots: true,
            reconstruct_rights: true,
            match_by_template: true,
        },
        |index, at| {
            let now = clock(&format!("to,{at},freeze"));
            eprintln!("SIMCLOCK {index:?} recorded {at} clock {now}");
        },
    );
    let approved: Vec<&String> = results.iter().filter(|l| l.contains("APPROVED")).collect();
    let refused: Vec<&String> = results
        .iter()
        .filter(|l| l.starts_with("tx ") && l.contains("p1 answered"))
        .collect();
    let skipped: Vec<&String> = results
        .iter()
        .filter(|l| l.starts_with("tx ") && l.contains("skipped"))
        .collect();
    eprintln!(
        "SIMCLOCK approved {}, p1 answered an error to {}, skipped {}, the runtime answered {answered} request(s), {} rejected",
        approved.len(),
        refused.len(),
        skipped.len(),
        rejects.len()
    );
    for line in refused.iter().chain(skipped.iter()) {
        eprintln!("SIMCLOCK not approved: {line}");
    }
    assert!(
        rejects.is_empty(),
        "the Rust participant rejected what p1 submitted: {rejects:?}"
    );
    assert!(
        approved.len() >= 64,
        "only {} recorded transactions were approved: {results:?}",
        approved.len()
    );
}
