//! Scenarios on the simulated cluster: the faults bundle 6 closed (a forged certificate, a manipulated canonical commit set, a node that floods
//! future-epoch messages, a crash and restart in the middle of an epoch) and a property run over many seeds.
use super::*;
use crate::consensus::{commit_message, pre_prepare_message, prepare_message};

const NODES: usize = 4;
const EPOCH_LENGTH: i64 = 8;
const FAULTY: usize = 3;

fn assert_safe(sim: &Sim) {
    assert!(
        sim.conflicts.is_empty(),
        "two blocks at one height: {:?}",
        &sim.conflicts[..sim.conflicts.len().min(3)]
    );
}

fn last_outputs(sim: &Sim) -> Vec<Option<i64>> {
    (0..sim.len()).map(|i| sim.last_output(i)).collect()
}

/// Every honest node output at least `blocks` blocks after `before`.
fn assert_live(sim: &Sim, before: &[Option<i64>], blocks: i64) {
    for i in sim.honest() {
        let from = before[i].unwrap_or(-1);
        let now = sim.last_output(i).unwrap_or(-1);
        assert!(
            now - from >= blocks,
            "{} output blocks up to {now} after {from}, fewer than {blocks} more (outputs of all: {:?})",
            sim.name(i),
            last_outputs(sim)
        );
    }
}

/// The honest outputs of blocks the faulty node led whose proposal is of view 0 (the faulty node's own, not an empty block of a new view).
fn faulty_proposals_output(sim: &Sim) -> usize {
    sim.honest()
        .flat_map(|i| sim.outputs[i].values())
        .filter(|o| o.original_leader == sim.name(FAULTY) && o.proposal_view == 0)
        .count()
}

/// The faulty node runs nothing and sends, for every block it leads that node 0 has not ordered, a commit certificate of an empty proposal of its
/// own: with `genuine`, commits signed by the nodes they name; otherwise all signed by the faulty node under the others' names.
fn run_with_certificates(genuine: bool) -> Sim {
    let mut sim = Sim::new(NODES, EPOCH_LENGTH, 7);
    sim.byzantine.insert(FAULTY);
    sim.crash(FAULTY);
    sim.run_with(15_000, |sim| {
        if !sim.now_ms.is_multiple_of(500) {
            return;
        }
        let Some(epoch) = sim.node(0).map(|n| n.epoch().clone()) else {
            return;
        };
        let Some(segment) = epoch.segment_of(sim.name(FAULTY)).cloned() else {
            return;
        };
        for block in segment.slots {
            if sim.node(0).is_some_and(|n| n.is_ordered(block)) {
                continue;
            }
            let proposal = sim.sign_as(
                FAULTY,
                FAULTY,
                &pre_prepare_message(
                    epoch.info.number,
                    block,
                    0,
                    sim.name(FAULTY),
                    bft::OrderingBlock { proofs: vec![] },
                    bft::CanonicalCommitSet {
                        canonical_commits: vec![],
                    },
                ),
            );
            let hash = block_hash_of_evidence(&proposal.message).unwrap();
            let commits: Vec<bft::SignedMessage> = [FAULTY, 0, 1]
                .into_iter()
                .map(|claimed| {
                    let signer = if genuine { claimed } else { FAULTY };
                    sim.sign_as(
                        signer,
                        claimed,
                        &commit_message(
                            epoch.info.number,
                            block,
                            0,
                            sim.name(claimed),
                            hash.clone(),
                            sim.now_ms as i64 * 1_000,
                        ),
                    )
                })
                .collect();
            for to in 0..FAULTY {
                sim.post(
                    FAULTY,
                    to,
                    Wire::Certificate(bft::CommitCertificate {
                        pre_prepare: Some(proposal.clone()),
                        commits: commits.clone(),
                    }),
                );
            }
        }
    });
    sim
}

#[test]
fn a_certificate_with_forged_commits_orders_nothing_and_the_others_go_on() {
    // the control: the same certificates with genuine commits are taken, so the run would see a forged one that got through
    let genuine = run_with_certificates(true);
    assert!(
        faulty_proposals_output(&genuine) > 0,
        "genuine certificates order the faulty node's proposals"
    );
    assert_safe(&genuine);

    let sim = run_with_certificates(false);
    assert_safe(&sim);
    assert_eq!(
        faulty_proposals_output(&sim),
        0,
        "no proposal of a forged certificate is output"
    );
    assert!(sim.some_honest_dropped("a commit certificate refused"));
    assert_live(&sim, &[None; NODES], 2 * EPOCH_LENGTH);
}

/// The faulty node's proposals go out with the last commit of their canonical commit set re-signed by the faulty node under the name it carries
/// (`PbftMessageValidatorImpl.validateCanonicalCommitSet`: each commit is the signature of the node it names).
fn forge_a_canonical_commit(sim: &Sim, from: usize, m: bft::SignedMessage) -> bft::SignedMessage {
    let Some(mut message) = decode_consensus(&m) else {
        return m;
    };
    let Some(bft::consensus_message::Message::PrePrepare(pp)) = message.message.as_mut() else {
        return m;
    };
    let Some(set) = pp.bft_time_canonical_commit_set.as_mut() else {
        return m;
    };
    let Some(target) = set
        .canonical_commits
        .iter()
        .position(|c| c.from != sim.name(from))
    else {
        return m;
    };
    let Some(commit) = decode_consensus(&set.canonical_commits[target]) else {
        return m;
    };
    let claimed = (0..sim.len())
        .find(|i| sim.name(*i) == commit.from)
        .unwrap();
    set.canonical_commits[target] = sim.sign_as(from, claimed, &commit);
    sim.sign_as(from, from, &message)
}

#[test]
fn proposals_with_a_forged_canonical_commit_are_refused_and_the_others_go_on() {
    let mut sim = Sim::new(NODES, EPOCH_LENGTH, 21);
    sim.set_tamper(FAULTY, forge_a_canonical_commit);
    sim.run_for(15_000);
    assert_safe(&sim);
    assert!(
        sim.some_honest_dropped("that does not hold"),
        "the honest nodes refused the faulty proposals"
    );
    assert_live(&sim, &[None; NODES], 2 * EPOCH_LENGTH);
}

#[test]
fn a_node_that_floods_messages_of_future_epochs_does_not_stop_the_others() {
    let mut sim = Sim::new(NODES, EPOCH_LENGTH, 33);
    sim.byzantine.insert(FAULTY);
    let mut flooded = 0u64;
    sim.run_with(12_000, |sim| {
        if !sim.now_ms.is_multiple_of(250) {
            return;
        }
        let Some(epoch) = sim.node(0).map(ConsensusNode::epoch_number) else {
            return;
        };
        for k in 0..100u64 {
            flooded += 1;
            let mut hash = vec![0u8; 34];
            hash[..8].copy_from_slice(&flooded.to_be_bytes());
            let junk = sim.sign_as(
                FAULTY,
                FAULTY,
                &prepare_message(
                    epoch + 50,
                    (epoch + 50) * EPOCH_LENGTH + (k as i64 % EPOCH_LENGTH),
                    0,
                    sim.name(FAULTY),
                    hash,
                ),
            );
            for to in 0..FAULTY {
                sim.post(FAULTY, to, Wire::Consensus(junk.clone()));
            }
        }
    });
    assert!(
        flooded > 4 * crate::fair_queue::CONSENSUS_QUEUE_PER_NODE_QUOTA as u64,
        "the flood is over the quota"
    );
    assert!(sim.some_honest_dropped("PerNodeQuotaExceeded"));
    assert_safe(&sim);
    assert_live(&sim, &[None; NODES], 3 * EPOCH_LENGTH);
}

#[test]
fn a_node_that_crashes_in_the_middle_of_an_epoch_restarts_and_catches_up() {
    let mut sim = Sim::new(NODES, EPOCH_LENGTH, 45);
    let victim = 2;
    // until the victim has output a block in the middle of an epoch after the first
    for _ in 0..1_000 {
        if sim
            .last_output(victim)
            .is_some_and(|b| b >= EPOCH_LENGTH && (b + 1) % EPOCH_LENGTH != 0)
        {
            break;
        }
        sim.run_for(TICK_MS);
    }
    let crashed_at = sim.last_output(victim).unwrap();
    assert!(
        (crashed_at + 1) % EPOCH_LENGTH != 0,
        "in the middle of an epoch"
    );
    sim.crash(victim);
    sim.run_for(5_000);
    let others = last_outputs(&sim);
    assert!(
        others[0].unwrap() > crashed_at + EPOCH_LENGTH,
        "the three others went on without it"
    );
    sim.restart(victim);
    sim.run_for(15_000);
    assert_safe(&sim);
    let epochs: Vec<i64> = (0..NODES)
        .map(|i| sim.node(i).unwrap().epoch_number())
        .collect();
    assert!(
        epochs[victim] + 1 >= epochs[0],
        "the restarted node caught up: epochs {epochs:?}"
    );
    assert_live(&sim, &others, 2 * EPOCH_LENGTH);
}

/// A run of one seed: messages dropped, delayed and duplicated at rates drawn from the seed, one node crashed and restarted at drawn times; then the
/// network heals. Returns the run and the honest outputs at the moment it healed.
fn faulty_then_healed(seed: u64) -> (Sim, Vec<Option<i64>>) {
    let mut schedule = Rng::new(seed.wrapping_mul(31).wrapping_add(17));
    let mut sim = Sim::new(NODES, EPOCH_LENGTH, seed);
    sim.faults = Faults {
        drop_pct: schedule.below(25),
        dup_pct: schedule.below(25),
        max_delay_ms: 1 + schedule.below(300),
    };
    let victim = schedule.below(NODES as u64) as usize;
    let crash_at = 1_000 + schedule.below(5_000);
    let down_for = 1_000 + schedule.below(4_000);
    sim.run_for(crash_at);
    sim.crash(victim);
    sim.run_for(down_for);
    sim.restart(victim);
    sim.run_for(10_000 - (crash_at + down_for).min(9_000));
    sim.faults = Faults::NONE;
    let healed = last_outputs(&sim);
    sim.run_for(12_000);
    (sim, healed)
}

const SEEDS: u64 = 16;

#[test]
fn over_many_seeds_no_two_blocks_at_one_height_and_blocks_go_on_once_the_faults_heal() {
    let failures: Vec<String> = std::thread::scope(|scope| {
        let runs: Vec<_> = (0..SEEDS)
            .map(|seed| {
                scope.spawn(move || {
                    let (sim, healed) = faulty_then_healed(seed);
                    let mut failed = Vec::new();
                    if !sim.conflicts.is_empty() {
                        failed.push(format!("seed {seed}: {:?}", &sim.conflicts[..1]));
                    }
                    for i in sim.honest() {
                        let (from, now) = (healed[i].unwrap_or(-1), sim.last_output(i).unwrap_or(-1));
                        if now - from < 2 * EPOCH_LENGTH {
                            failed.push(format!(
                                "seed {seed}: {} output up to {now} after healing at {from} (all: {:?})",
                                sim.name(i),
                                last_outputs(&sim)
                            ));
                        }
                    }
                    failed
                })
            })
            .collect();
        runs.into_iter().flat_map(|r| r.join().unwrap()).collect()
    });
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_seed_gives_the_same_run() {
    let (a, _) = faulty_then_healed(5);
    let (b, _) = faulty_then_healed(5);
    assert_eq!(a.fingerprint_of_run(), b.fingerprint_of_run());
    let (c, _) = faulty_then_healed(6);
    assert_ne!(a.fingerprint_of_run(), c.fingerprint_of_run());
}
