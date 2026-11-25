//! Ordering of a consensus node: commit certificates, pre-prepares, output draining and epochs.

use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft;

use crate::consensus::{
    block_hash_of_evidence, commit_message, pre_prepare_message, prepare_message,
};
use crate::epoch::Epoch;
use crate::verify::MAX_PROOFS_PER_PROPOSAL;

use super::{
    hex_of, BatchRef, ConsensusNode, EpochTopology, Event, ReceivedCommit, StoredPrePrepare,
    EMPTY_BLOCK_CREATION_MILLIS,
};

impl ConsensusNode {
    /// A block completed by a commit certificate (a quorum of commits and the proposal they name): ordered without this node's own votes.
    ///
    /// [CANTON-NOTE: SEMANTICS] `SegmentBlockState.completeBlock`: a verified certificate completes the block whatever this node has of it in
    /// progress (a proposal of an earlier view, votes for another hash), and this node does not vote on it.
    pub(super) fn order_with_commit_certificate(
        &mut self,
        block: i64,
        cert: bft::CommitCertificate,
        now_ms: u64,
        now_micros: i64,
        out: &mut Vec<bft::SignedMessage>,
    ) {
        let Some(signed) = cert.pre_prepare.clone() else {
            return;
        };
        let Some(bft::consensus_message::Message::PrePrepare(pp)) =
            Self::decode_consensus(&signed).and_then(|c| c.message)
        else {
            return;
        };
        let Ok(hash) = block_hash_of_evidence(&signed.message) else {
            return;
        };
        if let Some(state) = self.blocks.get_mut(&block) {
            if state.pre_prepare.as_ref().is_some_and(|p| p.hash != hash) {
                state.pre_prepare = None;
            }
        }
        self.take_pre_prepare(block, signed, pp);
        let Some(state) = self.blocks.get_mut(&block) else {
            return;
        };
        if state.pre_prepare.as_ref().is_none_or(|p| p.hash != hash) {
            return;
        }
        for commit in cert.commits {
            if let Some(c) = Self::decode_consensus(&commit) {
                if let Some(bft::consensus_message::Message::Commit(body)) = c.message {
                    state
                        .commits
                        .insert(c.from, (body.block_hash, body.local_timestamp, commit));
                }
            }
        }
        self.complete_if_committed(block, &hash, now_ms, now_micros, out);
    }

    /// A proposal for a block (its leader checked by the caller): both parts present, its proofs hold, then it is the block's pre-prepare.
    pub(super) fn take_pre_prepare(
        &mut self,
        block: i64,
        signed: bft::SignedMessage,
        pp: bft::PrePrepare,
    ) {
        // both parts have to be there (an empty block carries an empty one): the nodes refuse the message otherwise
        if pp.block.is_none() || pp.bft_time_canonical_commit_set.is_none() {
            self.events.push(Event::Dropped(
                "a pre-prepare without its block or commit set".into(),
            ));
            return;
        }
        let state = self.blocks.entry(block).or_default();
        if state.pre_prepare.is_some() {
            return;
        }
        let Ok(hash) = block_hash_of_evidence(&signed.message) else {
            return;
        };
        let proofs = pp
            .block
            .as_ref()
            .map(|b| b.proofs.clone())
            .unwrap_or_default();
        if let Err(why) = self.check_proofs(&proofs) {
            self.events.push(Event::Dropped(format!(
                "a pre-prepare for block {block} with proofs that do not hold: {why}"
            )));
            return;
        }
        let empty = proofs.is_empty();
        if std::env::var_os("BFT_NODE_DUMP").is_some() {
            self.events.push(Event::Dropped(format!(
                "DUMP pre-prepare block {block} evidence {} hash {}",
                hex_of(&signed.message),
                hex_of(&hash)
            )));
        }
        let state = self.blocks.entry(block).or_default();
        state.pre_prepare = Some(StoredPrePrepare {
            hash,
            empty,
            signed,
        });
    }

    /// The steps of a block that its state allows, once each (`PbftBlockState.advance`).
    pub(super) fn advance(
        &mut self,
        block: i64,
        now_ms: u64,
        now_micros: i64,
        out: &mut Vec<bft::SignedMessage>,
    ) {
        let strong = self.strong();
        let me = self.me.clone();
        let epoch = self.epoch.info.number;
        let Some(state) = self.blocks.get(&block) else {
            return;
        };
        let Some(pp) = &state.pre_prepare else {
            return;
        };
        let hash = pp.hash.clone();
        let view = state.view;
        // my Prepare: every node sends one, the leader too
        if !state.prepares.contains_key(&me) {
            let signed = self.sign(&prepare_message(epoch, block, view, &me, hash.clone()));
            self.blocks
                .get_mut(&block)
                .expect("the block has a state")
                .prepares
                .insert(me.clone(), (hash.clone(), signed.clone()));
            out.push(signed);
        }
        // my Commit: a strong quorum of Prepares of this hash (the block is prepared: its certificate is what a view change carries)
        let state = self.blocks.get(&block).expect("the block has a state");
        let matching_prepares = state.prepares.values().filter(|h| h.0 == hash).count();
        if matching_prepares >= strong {
            let state = self.blocks.get_mut(&block).expect("the block has a state");
            if let Some(pre_prepare) = state.pre_prepare.as_ref().map(|p| p.signed.clone()) {
                // the prepares of the quorum, by sender (`PbftBlockState.prepareCertificate`)
                let prepares: Vec<bft::SignedMessage> = state
                    .prepares
                    .values()
                    .filter(|h| h.0 == hash)
                    .map(|h| h.1.clone())
                    .take(strong)
                    .collect();
                state.prepare_cert = Some(bft::PrepareCertificate {
                    pre_prepare: Some(pre_prepare),
                    prepares,
                });
            }
        }
        let state = self.blocks.get(&block).expect("the block has a state");
        if matching_prepares >= strong && !state.commit_sent {
            let signed = self.sign(&commit_message(
                epoch,
                block,
                view,
                &me,
                hash.clone(),
                now_micros,
            ));
            let state = self.blocks.get_mut(&block).expect("the block has a state");
            state.commit_sent = true;
            state
                .commits
                .entry(me)
                .or_insert((hash.clone(), now_micros, signed.clone()));
            out.push(signed);
        }
        self.complete_if_committed(block, &hash, now_ms, now_micros, out);
    }

    /// The block is ordered once it has a strong quorum of Commits of the hash of its proposal (a commit certificate): whether or not this node voted.
    fn complete_if_committed(
        &mut self,
        block: i64,
        hash: &[u8],
        now_ms: u64,
        now_micros: i64,
        out: &mut Vec<bft::SignedMessage>,
    ) {
        let strong = self.strong();
        let epoch = self.epoch.info.number;
        let Some(state) = self.blocks.get_mut(&block) else {
            return;
        };
        let Some(empty) = state.pre_prepare.as_ref().map(|p| p.empty) else {
            return;
        };
        if state.ordered.is_some() {
            return;
        }
        let mut matching: Vec<(&String, &ReceivedCommit)> =
            state.commits.iter().filter(|(_, c)| c.0 == hash).collect();
        if matching.len() < strong {
            return;
        }
        matching.sort_by(|a, b| (a.0, a.1 .1).cmp(&(b.0, b.1 .1)));
        let certificate: Vec<bft::SignedMessage> = matching
            .into_iter()
            .take(strong)
            .map(|(_, c)| c.2.clone())
            .collect();
        state.ordered = Some(certificate);
        // a block ordered in a view other than the first (its proposal is the one of a new view): its original leader is punished in the next epoch
        let proposal_view = state
            .pre_prepare
            .as_ref()
            .and_then(|p| Self::decode_consensus(&p.signed))
            .map(|c| c.view_number)
            .unwrap_or(0);
        if proposal_view != 0 {
            if let Some(leader) = self.epoch.leader_of(block) {
                self.punished.insert(leader.to_string());
            }
        }
        self.events.push(Event::BlockOrdered {
            epoch,
            block,
            empty,
        });
        self.drain_output();
        self.on_ordered(block, now_ms, now_micros, out);
    }

    /// The blocks that are ordered and whose turn it is, in the order of their numbers (`OutputModule`): each gets its BFT time from the commits that ordered the block
    /// before it (`BftTime.blockBftTime`, the median of the canonical commit set and at least a millisecond after the previous block).
    fn drain_output(&mut self) {
        loop {
            let block = self.next_output_block;
            let Some(state) = self.blocks.get(&block) else {
                return;
            };
            if state.ordered.is_none() {
                return;
            }
            let Some(proposal) = state
                .pre_prepare
                .as_ref()
                .and_then(|p| Self::decode_consensus(&p.signed))
            else {
                return;
            };
            let proposal_view = proposal.view_number;
            let original_leader = self.epoch.leader_of(block).unwrap_or_default().to_string();
            let Some(bft::consensus_message::Message::PrePrepare(pp)) = proposal.message else {
                return;
            };
            let commit_times: Vec<i64> = pp
                .bft_time_canonical_commit_set
                .map(|set| set.canonical_commits)
                .unwrap_or_default()
                .iter()
                .filter_map(|m| match Self::decode_consensus(m)?.message {
                    Some(bft::consensus_message::Message::Commit(c)) => Some(c.local_timestamp),
                    _ => None,
                })
                .collect();
            let (time, previous_known) = match self.last_block_bft_time {
                Some(previous) => (
                    crate::bft_time::block_bft_time(&commit_times, previous),
                    true,
                ),
                None => (crate::bft_time::median(&commit_times), false),
            };
            self.last_block_bft_time = Some(time);
            self.next_output_block += 1;
            let is_last_in_epoch =
                block == self.epoch.info.start_block_number + self.epoch.info.length - 1;
            self.events.push(Event::BlockOutput {
                epoch: self.epoch.info.number,
                block,
                bft_time_micros: time,
                previous_known,
                is_last_in_epoch,
                batches: pp
                    .block
                    .map(|b| {
                        b.proofs
                            .into_iter()
                            .map(|p| BatchRef {
                                id: p.batch_id,
                                epoch: p.epoch_number,
                                ackers: p.acks.into_iter().map(|a| a.from).collect(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                original_leader,
                proposal_view,
            });
        }
    }

    fn on_ordered(
        &mut self,
        block: i64,
        now_ms: u64,
        now_micros: i64,
        out: &mut Vec<bft::SignedMessage>,
    ) {
        // a leader proposes its next block a while after its previous one was ordered
        if self
            .epoch
            .segment_of(&self.me)
            .is_some_and(|s| s.slots.contains(&block))
        {
            self.propose_not_before_ms = now_ms + EMPTY_BLOCK_CREATION_MILLIS;
        }
        // the segment made progress: its timer starts over (`IssSegmentModule`, after `OrderedBlockStored`), and stops when the segment is complete
        if let Some(si) = self.segment_index_of_block(block) {
            if !self.segments[si].in_view_change {
                let view = self.segments[si].view;
                self.segments[si].timer_deadline_ms = if self.segment_complete(si) {
                    None
                } else {
                    Some(now_ms + self.timeout_for_view(view))
                };
            }
        }
        let ordered = self.blocks.values().filter(|b| b.ordered.is_some()).count() as i64;
        if ordered == self.epoch.info.length {
            self.next_epoch(now_ms, now_micros, out);
        }
    }

    /// The next epoch: the next number, after this one, the same length, the leaders rotated.
    fn next_epoch(&mut self, now_ms: u64, now_micros: i64, out: &mut Vec<bft::SignedMessage>) {
        let last = self.epoch.info.last_block_number();
        self.last_epoch_last_commits = self
            .blocks
            .get(&last)
            .and_then(|b| b.ordered.clone())
            .unwrap_or_default();
        // [CANTON-NOTE: SEMANTICS] The next epoch runs on the ordering topology in force at its start (`NewEpochTopology`): its nodes lead, vote and
        // make its quorums, and the leader selection carries the blacklist over to them.
        let next = self
            .topology_source
            .as_ref()
            .and_then(|source| source(self.epoch.info.number + 1))
            .map(|mut t| {
                t.nodes.sort();
                t.nodes.dedup();
                t
            })
            .filter(|t| !t.nodes.is_empty() && t.length > 0)
            .unwrap_or_else(|| EpochTopology {
                nodes: self.nodes.clone(),
                length: self.epoch.info.length,
            });
        let info = self.epoch.info.next(next.length);
        self.previous_nodes = Some(std::mem::replace(&mut self.nodes, next.nodes));
        self.policy = self.policy.next(&self.nodes, &self.punished);
        self.policy.epoch_length = next.length;
        self.punished.clear();
        self.epoch = Epoch::with_leaders(info, self.policy.leaders());
        self.blocks.clear();
        self.reset_segments(now_ms);
        self.next_slot_index = 0;
        self.propose_not_before_ms = now_ms + EMPTY_BLOCK_CREATION_MILLIS;
        self.events.push(Event::EpochStarted {
            epoch: info.number,
            start_block: info.start_block_number,
        });
        // what the others sent for this epoch before it started here
        for signed in self.future.drain() {
            self.accept(signed, now_ms, now_micros, out);
        }
    }

    pub(super) fn maybe_propose(
        &mut self,
        now_ms: u64,
        now_micros: i64,
        out: &mut Vec<bft::SignedMessage>,
    ) {
        let Some(segment) = self.epoch.segment_of(&self.me).cloned() else {
            return;
        };
        if now_ms < self.propose_not_before_ms && self.pending_proofs.is_empty() {
            return;
        }
        // a segment in another view is led by the leader of that view, with a proposal for every block in the `NewView`
        if let Some(si) = self.segment_index_of_block(segment.slots[0]) {
            if self.segments[si].view != 0 || self.segments[si].in_view_change {
                return;
            }
        }
        // [CANTON-NOTE: RESTART] a slot of this segment that already has a proposal (one this node made before it was restarted, learned again from the peers' retransmission)
        // is not proposed again: the others have it, and a second, different proposal for the slot would be a lie
        while segment
            .slots
            .get(self.next_slot_index)
            .is_some_and(|b| self.blocks.get(b).is_some_and(|s| s.pre_prepare.is_some()))
        {
            self.next_slot_index += 1;
        }
        let Some(&block) = segment.slots.get(self.next_slot_index) else {
            return;
        };
        // one block at a time: the previous slot of the segment is ordered
        if self.next_slot_index > 0 && !self.is_ordered(segment.slots[self.next_slot_index - 1]) {
            return;
        }
        // the commits that ordered the previous block of the segment, or the last block of the epoch before
        let commits: Vec<bft::SignedMessage> = if self.next_slot_index > 0 {
            self.blocks
                .get(&segment.slots[self.next_slot_index - 1])
                .and_then(|b| b.ordered.clone())
                .unwrap_or_default()
        } else {
            self.last_epoch_last_commits.clone()
        };
        let message = pre_prepare_message(
            self.epoch.info.number,
            block,
            0,
            &self.me,
            bft::OrderingBlock {
                // the first block of a genesis segment is empty (its canonical commit set is), or the others refuse it
                proofs: if self.epoch.info.number == 0 && self.next_slot_index == 0 {
                    Vec::new()
                } else {
                    let take = self.pending_proofs.len().min(MAX_PROOFS_PER_PROPOSAL);
                    self.pending_proofs.drain(..take).collect()
                },
            },
            bft::CanonicalCommitSet {
                canonical_commits: commits,
            },
        );
        let signed = self.sign(&message);
        self.next_slot_index += 1;
        // not again before the block is ordered
        self.propose_not_before_ms = u64::MAX;
        // the proposal comes back into this node as if it had been received (its own Prepare follows)
        let mut mine = Vec::new();
        self.accept(signed.clone(), now_ms, now_micros, &mut mine);
        out.push(signed);
        out.extend(mine);
    }
}
