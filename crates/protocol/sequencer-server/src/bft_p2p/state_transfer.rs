//! A state transfer of the epochs between the one a node's state is for and the one it joins (U-52): the blocks of each, with the view of their
//! proposals, rebuild the leader selection state epoch by epoch (`BlacklistLeaderSelectionPolicy`), and the blocks after the last one this node's
//! sequencer got go to the output (S-20).
//!
//! [CANTON-NOTE: SEMANTICS] `StateTransferManager.handleStoredBlock` sends every transferred block to the output (`OrderingMode.StateTransfer`), and
//! the output provides blocks only from its initial height on (`OutputModule`: `firstBlockToProcess` is `initialHeightToProvide` when onboarding,
//! the block after the last one stored when restarting; `PekkoBlockSubscription` starts its Peano queue at the sequencer's initial height). This
//! node has no onboarding snapshot: without a block to resume after, its first height is the first block of the epoch it joins, and nothing
//! transferred is output.
use canton_bft_orderer::node::BatchRef;
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft;
use std::collections::{BTreeMap, BTreeSet};

/// A block for the output stage, as `OutputState.waiting` holds it: `(epoch, block, BFT time, last in its epoch, leader, batches)`.
pub(super) type WaitingBlock = (i64, i64, i64, bool, String, Vec<BatchRef>);

pub(super) struct CatchUp {
    pub(super) policy: canton_bft_orderer::blacklist::PolicyState,
    /// The epoch the node joins and the message that told it (fed again when the transfer is done).
    pub(super) target_epoch: i64,
    pub(super) trigger: bft::SignedMessage,
    /// The blocks of the epoch being fetched and the view of their proposals.
    pub(super) collected: BTreeMap<i64, i64>,
    /// The nodes whose commits the transferred certificates of that epoch carry: the ordering topology the epoch had.
    pub(super) voters: BTreeSet<String>,
    pub(super) last_request: Option<std::time::Instant>,
    /// The verified proposals of the blocks of the epoch being fetched.
    proposals: BTreeMap<i64, bft::SignedMessage>,
    /// The last block this node's sequencer got and its BFT time; `None` when the node has nothing to resume after.
    output_after: Option<(i64, i64)>,
}

fn decode(signed: &bft::SignedMessage) -> Option<bft::ConsensusMessage> {
    use prost::Message as _;
    let inner = canton_bft_orderer::wire::unwrap_versioned(&signed.message, 30).ok()?;
    bft::ConsensusMessage::decode(inner.as_slice()).ok()
}

impl CatchUp {
    pub(super) fn new(
        policy: canton_bft_orderer::blacklist::PolicyState,
        target_epoch: i64,
        trigger: bft::SignedMessage,
        output_after: Option<(i64, i64)>,
    ) -> Self {
        Self {
            policy,
            target_epoch,
            trigger,
            collected: BTreeMap::new(),
            voters: BTreeSet::new(),
            last_request: None,
            proposals: BTreeMap::new(),
            output_after,
        }
    }

    /// The proposal of a transferred block whose certificate holds.
    pub(super) fn keep_proposal(&mut self, block: i64, pre_prepare: bft::SignedMessage) {
        self.proposals.insert(block, pre_prepare);
    }

    /// The blocks of the complete epoch `epoch` that go to the output: those after the last one the sequencer got, in order, each with the BFT time
    /// that follows from the commits its proposal carries and the block before (`BftTime.blockBftTime`), its leader the node that proposed it
    /// (`StateTransferMessageSender.sendBlockToOutput` passes `prePrepare.from`).
    ///
    /// [CANTON-NOTE: SEMANTICS] Matches `StateTransferManager.scala:594-606` (`handleStoredBlock`): when a block height gap exists,
    /// retain higher buffered proposals in `self.proposals` and advance `output_after` only through the last contiguous block emitted.
    pub(super) fn take_output(&mut self, epoch: i64) -> Vec<WaitingBlock> {
        let Some((mut last_block, mut last_time)) = self.output_after else {
            self.proposals.clear();
            return Vec::new();
        };
        let mut last_of_epoch: BTreeMap<i64, i64> = BTreeMap::new();
        for (&block, signed) in &self.proposals {
            if let Some(msg) = decode(signed) {
                let ep = msg
                    .block_metadata
                    .as_ref()
                    .map_or(epoch, |m| m.epoch_number);
                last_of_epoch
                    .entry(ep)
                    .and_modify(|max_b| *max_b = (*max_b).max(block))
                    .or_insert(block);
            }
        }
        let mut out = Vec::new();
        while let Some((&block, _)) = self.proposals.first_key_value() {
            if block <= last_block {
                self.proposals.pop_first();
                continue;
            }
            if block != last_block + 1 {
                break;
            }
            let Some(signed) = self.proposals.get(&block) else {
                break;
            };
            let Some(message) = decode(signed) else {
                break;
            };
            let block_epoch = message
                .block_metadata
                .as_ref()
                .map_or(epoch, |m| m.epoch_number);
            let Some(bft::consensus_message::Message::PrePrepare(pp)) = message.message else {
                break;
            };
            let commit_times: Vec<i64> = pp
                .bft_time_canonical_commit_set
                .iter()
                .flat_map(|set| &set.canonical_commits)
                .filter_map(|m| match decode(m)?.message {
                    Some(bft::consensus_message::Message::Commit(c)) => Some(c.local_timestamp),
                    _ => None,
                })
                .collect();
            let time = canton_bft_orderer::bft_time::block_bft_time(&commit_times, last_time);
            let batches = pp
                .block
                .into_iter()
                .flat_map(|b| b.proofs)
                .map(|p| BatchRef {
                    id: p.batch_id,
                    epoch: p.epoch_number,
                    ackers: p.acks.into_iter().map(|a| a.from).collect(),
                })
                .collect();
            self.proposals.pop_first();
            out.push((
                block_epoch,
                block,
                time,
                last_of_epoch.get(&block_epoch) == Some(&block),
                message.from,
                batches,
            ));
            (last_block, last_time) = (block, time);
        }
        self.output_after = Some((last_block, last_time));
        out
    }
}

impl super::Consensus {
    /// The transferred blocks join the output stage behind what is already there (the epochs come in order, and the node starts its own epoch
    /// after the transfer is done).
    pub(super) fn output_transferred(&self, blocks: Vec<WaitingBlock>) -> Result<(), String> {
        let (Some(first), Some(last)) = (blocks.first(), blocks.last()) else {
            return Ok(());
        };
        crate::diag::diag_eprintln!(
            "OUTPUT state transfer: blocks {} to {} of epoch {} go to the output",
            first.1,
            last.1,
            first.0
        );
        {
            let mut output = self.lock_output()?;
            output.waiting.extend(blocks);
        }
        // [CANTON-NOTE: INVARIANT] Drop `self.output` lock BEFORE calling `release_output()` to avoid self-deadlock.
        self.release_output()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_bft_orderer::consensus::{commit_message, pre_prepare_message};
    use prost::Message as _;
    use std::sync::{Arc, Mutex};

    fn signed_msg(from: &str, message: &bft::ConsensusMessage) -> bft::SignedMessage {
        let evidence = canton_bft_orderer::wire::wrap_versioned(30, &message.encode_to_vec());
        bft::SignedMessage {
            message: evidence,
            from: from.to_string(),
            signature: None,
        }
    }

    fn pp_block(epoch: i64, block: i64, from: &str, commit_ts: i64) -> bft::SignedMessage {
        let commit = signed_msg(
            from,
            &commit_message(epoch, block, 0, from, vec![0; 34], commit_ts),
        );
        signed_msg(
            from,
            &pre_prepare_message(
                epoch,
                block,
                0,
                from,
                bft::OrderingBlock { proofs: vec![] },
                bft::CanonicalCommitSet {
                    canonical_commits: vec![commit],
                },
            ),
        )
    }

    #[test]
    fn take_output_keeps_buffered_blocks_after_gap_until_missing_block_arrives() {
        let trigger = pp_block(1, 20, "SEQ::b::fp", 20_000);
        let policy = canton_bft_orderer::blacklist::PolicyState::first(
            &["SEQ::a::fp".into(), "SEQ::b::fp".into()],
            20,
        );
        let mut catchup = CatchUp::new(policy, 1, trigger, Some((7, 7_000)));
        for block in [8, 9, 11, 12] {
            catchup.keep_proposal(block, pp_block(0, block, "SEQ::b::fp", block * 1_000));
        }
        let first = catchup.take_output(0);
        let first_blocks: Vec<i64> = first.iter().map(|b| b.1).collect();
        assert_eq!(first_blocks, vec![8, 9]);
        assert_eq!(catchup.output_after, Some((9, 9_000)));
        assert!(!first[1].3, "block 9 is not the last buffered block");

        catchup.keep_proposal(10, pp_block(0, 10, "SEQ::b::fp", 10_000));
        let second = catchup.take_output(0);
        let second_blocks: Vec<i64> = second.iter().map(|b| b.1).collect();
        assert_eq!(
            second_blocks,
            vec![10, 11, 12],
            "buffered blocks 11 and 12 after gap at 10 must emit once block 10 arrives"
        );
        assert_eq!(catchup.output_after, Some((12, 12_000)));
        assert!(!second[0].3 && !second[1].3 && second[2].3);

        // Gap right at the start of buffered proposals (`{14, 15}` when `output_after == 12`, then `13`).
        for block in [14, 15] {
            catchup.keep_proposal(block, pp_block(0, block, "SEQ::b::fp", block * 1_000));
        }
        assert!(catchup.take_output(0).is_empty());
        assert_eq!(catchup.output_after, Some((12, 12_000)));
        catchup.keep_proposal(13, pp_block(0, 13, "SEQ::b::fp", 13_000));
        let unblocked = catchup.take_output(0);
        let unblocked_blocks: Vec<i64> = unblocked.iter().map(|b| b.1).collect();
        assert_eq!(unblocked_blocks, vec![13, 14, 15]);
    }

    #[test]
    fn poisoned_output_lock_fails_boundary_catchup_and_delivery() {
        let registry = Arc::new(crate::onboarding::Registry::default());
        let consensus = super::super::Consensus::new(
            "SEQ::rs1::fp".into(),
            [3; 32],
            "fp".into(),
            None,
            registry,
        );
        let nodes = vec!["SEQ::a::fp".to_string(), "SEQ::b::fp".to_string()];
        consensus.set_nodes(nodes.clone());
        {
            let mut out = consensus.output.lock().unwrap_or_else(|e| e.into_inner());
            out.restored_last_output_block = Some(7);
            out.restored_last_bft_time = Some(7_000);
        }
        {
            let mut persisted = consensus
                .persisted_policy
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *persisted = Some(canton_bft_orderer::blacklist::PolicyState::first(
                &nodes, 20,
            ));
        }

        let delivered: Arc<Mutex<Vec<(i64, i64)>>> = Arc::new(Mutex::new(Vec::new()));
        let delivered_sink = Arc::clone(&delivered);
        consensus.set_block_end_sink(Arc::new(move |block, time, _tick| {
            if let Ok(mut g) = delivered_sink.lock() {
                g.push((block, time));
            }
            false
        }));

        // Deliberately poison `consensus.output`.
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                if let Ok(_guard) = consensus.output.lock() {
                    panic!("deliberate test poison of consensus.output");
                }
            });
            let _ = h.join();
        });
        assert!(consensus.output.is_poisoned());

        // (a) `on_message` reaching CatchUp creation must propagate error and not install CatchUp.
        let last_commit_ep0 = signed_msg(
            "SEQ::b::fp",
            &commit_message(0, 19, 0, "SEQ::b::fp", vec![0; 34], 19_000),
        );
        let boundary_trigger = signed_msg(
            "SEQ::b::fp",
            &pre_prepare_message(
                1,
                20,
                0,
                "SEQ::b::fp",
                bft::OrderingBlock { proofs: vec![] },
                bft::CanonicalCommitSet {
                    canonical_commits: vec![last_commit_ep0],
                },
            ),
        );
        let err_msg = consensus
            .on_message(boundary_trigger)
            .expect_err("poisoned output lock must cause on_message at boundary to fail");
        assert!(
            err_msg.contains("output") && err_msg.contains("poisoned"),
            "{err_msg}"
        );
        assert!(
            consensus
                .catchup
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none(),
            "failed CatchUp entry must not partially initialize CatchUp state"
        );

        // (b) `output_transferred` must propagate error and deliver 0 blocks.
        let err_tx = consensus
            .output_transferred(vec![(0, 8, 8_000, false, "SEQ::b::fp".into(), vec![])])
            .expect_err("poisoned output lock must reject output_transferred");
        assert!(
            err_tx.contains("output") && err_tx.contains("poisoned"),
            "{err_tx}"
        );
        let got = delivered.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            got.is_empty(),
            "poisoned output lock must halt transfer delivery instead of delivering blocks: {got:?}"
        );
    }
}
