//! The consensus of one node in the normal case (B3, B4): the PBFT of each block of an epoch, as follower and as leader of its own segment, with empty blocks.
//! A pure state machine: messages and the clock come in, the messages to send to the other nodes come out.
//!
//! [CANTON-NOTE: SEMANTICS] `doc/slices/BFT-CONSENSUS-SPEC.md` (sections 2, 3, 4, 6, 8): per block, in view 0, every node sends a `Prepare` for the hash of the `PrePrepare` (the
//! leader too: its PrePrepare is not its Prepare); with a strong quorum of Prepares of that hash it sends its `Commit` (hash and its clock in microseconds); with a strong
//! quorum of Commits the block is ordered. A leader proposes one block at a time, an empty one, 500 ms after the epoch started or after its previous block was ordered, and puts
//! in the commits that ordered its previous block (the last block of the previous epoch for its first slot). An epoch is over when all its blocks are ordered; the next one has
//! the next number, starts after it, has the same length and rotates the leaders. Not here: view changes, availability, state transfer, persistence.
use crate::consensus::consensus_evidence;
use crate::epoch::Epoch;
use crate::fair_queue::FairBoundedQueue;
use crate::topology::{strong_quorum_size, EpochInfo};
use crate::wire::{sign_message, unwrap_versioned, AuthenticatedMessageType};
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft;
use prost::Message;
use std::collections::BTreeMap;

pub use crate::verify::{KeyLookup, BATCH_VALIDITY_EPOCHS, MAX_PROOFS_PER_PROPOSAL};

mod ordering;
mod view_change;

/// The ordering topology in force for an epoch: its nodes and its length in blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochTopology {
    pub nodes: Vec<String>,
    pub length: i64,
}

/// Where a node reads the ordering topology of the epoch it is about to start (`OrderingTopologyProvider`); `None` keeps the current one.
pub type TopologySource = Box<dyn Fn(i64) -> Option<EpochTopology> + Send>;

/// The pause before a leader proposes its next (empty) block (`consensusEmptyBlockCreationTimeout`, `CFG:348`).
pub const EMPTY_BLOCK_CREATION_MILLIS: u64 = 500;

/// What a node signs with: its signing key and the fingerprint the topology lists it under.
pub struct Signer {
    pub key: ed25519_dalek::SigningKey,
    pub fingerprint: String,
}

/// A batch a block names (`ProofOfAvailability`): its id, the epoch it was made in and the nodes that acked it (the ones to ask for it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchRef {
    pub id: Vec<u8>,
    pub epoch: i64,
    pub ackers: Vec<String>,
}

/// What happened, for the one who runs the node.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    BlockOrdered {
        epoch: i64,
        block: i64,
        empty: bool,
    },
    EpochStarted {
        epoch: i64,
        start_block: i64,
    },
    /// A block is out of the orderer: the blocks come in the order of their numbers, with the time every sequencer gives them (`BftTime`) and the batches the block
    /// names (the output module fetches them). `previous_known` is false for the first block this node saw (its time is only the median of its commit set).
    BlockOutput {
        epoch: i64,
        block: i64,
        bft_time_micros: i64,
        previous_known: bool,
        is_last_in_epoch: bool,
        batches: Vec<BatchRef>,
        original_leader: String,
        proposal_view: i64,
    },
    /// A segment moved to a new view (`moving from view number 0 to 1`): its leader in that view.
    ViewChangeStarted {
        epoch: i64,
        first_block: i64,
        view: i64,
        leader: String,
    },
    ViewChangeCompleted {
        epoch: i64,
        first_block: i64,
        view: i64,
    },
    /// A message the node did not take, and why.
    Dropped(String),
}

struct StoredPrePrepare {
    /// The hash of the evidence bytes as received or sent.
    hash: Vec<u8>,
    empty: bool,
    /// The message as it was received or sent (a certificate carries it; a `NewView` re-uses proposals of older views).
    signed: bft::SignedMessage,
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A `Commit` as it was received: the hash it names, its time and the message itself.
type ReceivedCommit = (Vec<u8>, i64, bft::SignedMessage);

/// A `Prepare` as it was received: the hash it names and the message itself (a prepare certificate carries it).
type ReceivedPrepare = (Vec<u8>, bft::SignedMessage);

#[derive(Default)]
struct BlockState {
    /// The view the block is in (`SegmentBlockState.currentViewNumber`); the state below belongs to it.
    view: i64,
    pre_prepare: Option<StoredPrePrepare>,
    /// `Prepare`s by sender: the hash they name.
    prepares: BTreeMap<String, ReceivedPrepare>,
    /// The prepare certificate of the highest view in which the block reached the prepared state (`PbftBlockState.prepareCertificate`): what a `ViewChange` carries.
    prepare_cert: Option<bft::PrepareCertificate>,
    /// `Commit`s by sender: the hash, the time and the message as it was received (kept for the canonical commit set of a later block).
    commits: BTreeMap<String, ReceivedCommit>,
    commit_sent: bool,
    ordered: Option<Vec<bft::SignedMessage>>,
}

/// What the nodes of a segment have sent for a view change to one view (`PbftViewChangeState`).
#[derive(Default)]
struct ViewChangeState {
    view_changes: BTreeMap<String, bft::SignedMessage>,
    new_view: Option<bft::SignedMessage>,
    /// A `NewView` this node made (it leads the view) is not made twice.
    new_view_made: bool,
}

/// The view of one segment and what goes on in it (`SegmentState`).
struct SegmentView {
    view: i64,
    in_view_change: bool,
    /// When the segment's timer runs out: no block of the segment was ordered for that long (a leader that is away), or a view change that has a strong quorum of
    /// view change messages did not finish (`PbftNormalTimeout`, `PbftNestedViewChangeTimeout`).
    timer_deadline_ms: Option<u64>,
    strong_quorum_seen: bool,
    view_changes: BTreeMap<i64, ViewChangeState>,
    /// Votes of a view the node has not entered yet, or of the view being installed (`SegmentState.futureViewMessagesQueue`).
    future: FairBoundedQueue<bft::SignedMessage>,
}

/// `pbftViewChangeTimeout` (10 s), the step per view (2 s) and its upper bound (30 s) of `SequencingParameters`.
pub const VIEW_CHANGE_TIMEOUT_MILLIS: u64 = 10_000;
const VIEW_CHANGE_TIMEOUT_STEP_MILLIS: u64 = 2_000;
const VIEW_CHANGE_TIMEOUT_UPPER_BOUND_MILLIS: u64 = 30_000;

pub struct ConsensusNode {
    /// Batches that are stored by enough nodes (their proofs of availability) and wait for this node to lead a block: the next proposal carries them.
    pending_proofs: Vec<bft::ProofOfAvailability>,
    /// The next block the output is waiting for, and the BFT time of the block before it (`BftTime.blockBftTime`).
    next_output_block: i64,
    last_block_bft_time: Option<i64>,
    /// The leader selection policy: who leads the epochs (a leader whose segment needed a view change sits out some epochs).
    policy: crate::blacklist::PolicyState,
    /// The original leaders of the blocks of this epoch that were ordered in a view other than the first (`BlacklistLeaderSelectionPolicy.addBlock`).
    punished: std::collections::BTreeSet<String>,
    /// The timeout of a view change (`viewChangeTimeoutOverride` when set, otherwise the base plus a step per view up to a bound).
    view_change_timeout_override_ms: Option<u64>,
    segments: Vec<SegmentView>,
    me: String,
    nodes: Vec<String>,
    /// The topology of the epoch before, when this node ran it (`previousMembership`): what the canonical commit set of a segment's first block is checked against.
    previous_nodes: Option<Vec<String>>,
    signer: Signer,
    epoch: Epoch,
    blocks: BTreeMap<i64, BlockState>,
    /// The commits of the last block of the epoch before, for the first slot of this node's segment.
    last_epoch_last_commits: Vec<bft::SignedMessage>,
    /// The slot of this node's segment it proposes next, and when it may.
    next_slot_index: usize,
    propose_not_before_ms: u64,
    /// Messages of later epochs (`IssConsensusModule.futurePbftMessageQueue`).
    future: FairBoundedQueue<bft::SignedMessage>,
    /// Diagnostics only: the ten-second slot of the last stuck-block report.
    last_stuck_report: u64,
    events: Vec<Event>,
    /// Where the keys of the nodes are looked up: every message another message embeds is checked with it.
    keys: KeyLookup,
    /// Where the topology of each next epoch comes from; without one the topology stays the one the node started with.
    topology_source: Option<TopologySource>,
}

impl ConsensusNode {
    /// A node of `nodes` (all of them, this one included) at the start of the epoch `info`, `now_ms` being its clock; `keys` finds its peers' keys.
    pub fn new(
        me: &str,
        nodes: &[String],
        info: EpochInfo,
        signer: Signer,
        keys: KeyLookup,
        now_ms: u64,
    ) -> Self {
        Self::with_policy(me, nodes, info, signer, keys, now_ms, None)
    }

    /// The same, with the leader selection state of the epoch (what a state transfer rebuilt); without one the node assumes no node is blacklisted.
    pub fn with_policy(
        me: &str,
        nodes: &[String],
        info: EpochInfo,
        signer: Signer,
        keys: KeyLookup,
        now_ms: u64,
        policy: Option<crate::blacklist::PolicyState>,
    ) -> Self {
        let mut nodes = nodes.to_vec();
        nodes.sort();
        // [CANTON-NOTE: LEADERS] A node that starts in the middle of the history has no blacklist (its state is transferred in the official node, U-52): it
        // assumes none, which is right for a cluster that has not changed a view yet.
        let policy = policy
            .filter(|p| p.epoch_number == info.number)
            .unwrap_or_else(|| {
                let mut p = crate::blacklist::PolicyState::first(&nodes, info.length);
                p.epoch_number = info.number;
                p.start_block = info.start_block_number;
                p
            });
        let epoch = Epoch::with_leaders(info, policy.leaders());
        let events = vec![Event::EpochStarted {
            epoch: info.number,
            start_block: info.start_block_number,
        }];
        Self {
            pending_proofs: Vec::new(),
            next_output_block: info.start_block_number,
            last_block_bft_time: None,
            policy,
            punished: std::collections::BTreeSet::new(),
            me: me.to_string(),
            nodes,
            previous_nodes: None,
            signer,
            epoch,
            blocks: BTreeMap::new(),
            last_epoch_last_commits: Vec::new(),
            next_slot_index: 0,
            propose_not_before_ms: now_ms + EMPTY_BLOCK_CREATION_MILLIS,
            future: FairBoundedQueue::consensus(false),
            last_stuck_report: 0,
            events,
            keys,
            topology_source: None,
            view_change_timeout_override_ms: None,
            segments: Vec::new(),
        }
        .with_fresh_segments(now_ms)
    }

    /// Restores the commits of the previous epoch's last block and the last output block's BFT time when resuming directly at a later epoch.
    pub fn restore_epoch_boundary(
        &mut self,
        last_epoch_commits: Vec<bft::SignedMessage>,
        last_bft_time: Option<i64>,
    ) {
        self.last_epoch_last_commits = last_epoch_commits;
        if let Some(t) = last_bft_time {
            self.last_block_bft_time = Some(t);
        }
    }

    /// One view state per segment of the epoch, each with its timer running.
    fn with_fresh_segments(mut self, now_ms: u64) -> Self {
        self.reset_segments(now_ms);
        self
    }

    fn reset_segments(&mut self, now_ms: u64) {
        let timeout = self.timeout_for_view(0);
        self.segments = self
            .epoch
            .segments
            .iter()
            .map(|_| SegmentView {
                view: 0,
                in_view_change: false,
                timer_deadline_ms: Some(now_ms + timeout),
                strong_quorum_seen: false,
                view_changes: BTreeMap::new(),
                future: FairBoundedQueue::consensus(true),
            })
            .collect();
    }

    /// `ViewChangeTimeoutCalculator`: the override, or 10 s plus 2 s per view (at most 30 s of steps).
    fn timeout_for_view(&self, view: i64) -> u64 {
        self.view_change_timeout_override_ms.unwrap_or_else(|| {
            VIEW_CHANGE_TIMEOUT_MILLIS
                + (VIEW_CHANGE_TIMEOUT_STEP_MILLIS * view.max(0) as u64)
                    .min(VIEW_CHANGE_TIMEOUT_UPPER_BOUND_MILLIS)
        })
    }

    /// Sets the view change timeout (`viewChangeTimeoutOverride`); the timers of the segments restart.
    pub fn set_view_change_timeout(&mut self, millis: u64, now_ms: u64) {
        self.view_change_timeout_override_ms = Some(millis);
        self.reset_segments(now_ms);
    }

    /// A batch that is available (stored and acked by enough nodes): this node proposes it in its next block (`AvailabilityModule` hands proofs of availability to
    /// the consensus, which puts them in the proposal it makes as the leader of a segment).
    pub fn queue_proof(&mut self, proof: bft::ProofOfAvailability) {
        self.pending_proofs.push(proof);
    }

    /// Lets the node take the ordering topology in force at every epoch boundary (its nodes, and so its leaders and quorums).
    pub fn set_topology_source(&mut self, source: TopologySource) {
        self.topology_source = Some(source);
    }

    /// The epoch number the node is in (a batch made now is valid from it).
    pub fn epoch_number(&self) -> i64 {
        self.epoch.info.number
    }

    /// The leader selection state of the epoch the node is in.
    pub fn policy_state(&self) -> &crate::blacklist::PolicyState {
        &self.policy
    }

    /// `PbftMessageValidatorImpl.validateProofsOfAvailability` against this epoch's topology.
    fn check_proofs(&self, proofs: &[bft::ProofOfAvailability]) -> Result<(), String> {
        crate::verify::check_proofs(proofs, &self.nodes, &self.keys, self.epoch.info.number)
    }

    /// [`crate::verify::check_pre_prepare`] for a block of segment `segment` of this epoch.
    fn check_pre_prepare(
        &self,
        segment: usize,
        block: i64,
        pp: &bft::PrePrepare,
    ) -> Result<(), String> {
        let slots = &self.epoch.segments[segment].slots;
        let previous_in_segment = slots
            .iter()
            .position(|b| *b == block)
            .and_then(|i| i.checked_sub(1))
            .map(|i| slots[i]);
        crate::verify::check_pre_prepare(
            pp,
            &crate::verify::ProposalPlace {
                epoch: self.epoch.info.number,
                block,
                epoch_start_block: self.epoch.info.start_block_number,
                previous_in_segment,
                current: &self.nodes,
                previous: self.previous_nodes.as_deref(),
            },
            &self.keys,
        )
    }

    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    fn strong(&self) -> usize {
        strong_quorum_size(self.nodes.len())
    }

    /// Whether the block is ordered here (all its commits in).
    pub fn is_ordered(&self, block: i64) -> bool {
        self.blocks.get(&block).is_some_and(|b| b.ordered.is_some())
    }

    fn sign(&self, message: &bft::ConsensusMessage) -> bft::SignedMessage {
        let evidence = consensus_evidence(message);
        let signature = sign_message(
            AuthenticatedMessageType::BftSignedConsensusMessage,
            &self.me,
            &evidence,
            &self.signer.key,
            &self.signer.fingerprint,
        )
        .expect("a hash of the sizes of a message");
        bft::SignedMessage {
            message: evidence,
            from: self.me.clone(),
            signature: Some(signature),
        }
    }

    /// A signed consensus message of another node (its signature checked by the caller). Returns what to send to the other nodes.
    pub fn on_message(
        &mut self,
        signed: bft::SignedMessage,
        now_ms: u64,
        now_micros: i64,
    ) -> Vec<bft::SignedMessage> {
        let mut out = Vec::new();
        self.accept(signed, now_ms, now_micros, &mut out);
        out
    }

    /// A commit certificate of a block of the current epoch (a peer's retransmission): a strong quorum of commits for the proposal. Ordered without this node's votes.
    /// Returns what to send to the other nodes, or why the certificate was not taken (nothing of it is kept then).
    pub fn on_commit_certificate(
        &mut self,
        cert: bft::CommitCertificate,
        now_ms: u64,
        now_micros: i64,
    ) -> Result<Vec<bft::SignedMessage>, String> {
        let Some(pp) = cert.pre_prepare.as_ref().and_then(Self::decode_consensus) else {
            return Err("a commit certificate without a decodable pre-prepare".into());
        };
        let meta = pp.block_metadata.unwrap_or_default();
        if meta.epoch_number != self.epoch.info.number
            || !self.epoch.contains_block(meta.block_number)
        {
            return Err(format!(
                "a commit certificate for block {} of epoch {}, not of this epoch",
                meta.block_number, meta.epoch_number
            ));
        }
        if self.is_ordered(meta.block_number) {
            return Err(format!("block {} is already ordered", meta.block_number));
        }
        // [CANTON-NOTE: SEMANTICS] `RetransmissionMessageValidator.validateCommitCertificates` and `IssConsensusSignatureVerifier.verifyConsensusCertificate`:
        // every message of the certificate verifies and the commits are a strong quorum of distinct nodes for the pre-prepare's hash.
        let wrapped = bft::ConsensusCertificate {
            certificate: Some(bft::consensus_certificate::Certificate::CommitCertificate(
                cert.clone(),
            )),
        };
        self.verify_certificate(&wrapped, pp.view_number)?;
        let mut out = Vec::new();
        self.order_with_commit_certificate(meta.block_number, cert, now_ms, now_micros, &mut out);
        Ok(out)
    }

    /// The clock moved: a leader whose time has come proposes its next block. Returns what to send to the other nodes.
    pub fn tick(&mut self, now_ms: u64, now_micros: i64) -> Vec<bft::SignedMessage> {
        let mut out = Vec::new();
        // a segment whose timer ran out: no block was ordered in it for the timeout (a leader that is away), or its view change did not finish
        for si in 0..self.segments.len() {
            let due = self.segments[si]
                .timer_deadline_ms
                .is_some_and(|deadline| now_ms >= deadline);
            if due && !self.segment_complete(si) {
                let next = self.segments[si].view + 1;
                self.start_view_change(si, next, now_ms, &mut out);
            }
        }
        if std::env::var_os("BFT_NODE_DUMP").is_some() && now_ms / 10_000 != self.last_stuck_report
        {
            self.last_stuck_report = now_ms / 10_000;
            self.report_stuck_blocks();
        }
        self.maybe_propose(now_ms, now_micros, &mut out);
        out
    }

    /// What this node has of the epoch, in the shape of `EpochStatus` (a retransmission request): a segment per leader, a status per slot, and for a block in
    /// progress who prepared and committed it, by the sorted nodes. The peers answer with what the status says is missing.
    pub fn epoch_status(&self) -> bft::EpochStatus {
        use bft::{block_status, segment_status};
        let segments = self
            .epoch
            .segments
            .iter()
            .enumerate()
            .map(|(index, segment)| {
                let seg_view = &self.segments[index];
                // a segment in a view change reports who sent view changes for the view and which of its blocks are complete (`SegmentStatus.InViewChange`)
                if seg_view.in_view_change {
                    let sent = seg_view.view_changes.get(&seg_view.view);
                    return bft::SegmentStatus {
                        status: Some(segment_status::Status::InViewChange(
                            bft::SegmentInViewChange {
                                view_number: seg_view.view,
                                view_change_messages_present: self
                                    .nodes
                                    .iter()
                                    .map(|n| sent.is_some_and(|v| v.view_changes.contains_key(n)))
                                    .collect(),
                                are_blocks_complete: segment
                                    .slots
                                    .iter()
                                    .map(|b| self.is_ordered(*b))
                                    .collect(),
                            },
                        )),
                    };
                }
                let statuses: Vec<bft::BlockStatus> = segment
                    .slots
                    .iter()
                    .map(|block| {
                        let state = self.blocks.get(block);
                        if state.is_some_and(|b| b.ordered.is_some()) {
                            return bft::BlockStatus {
                                status: Some(block_status::Status::Complete(())),
                            };
                        }
                        bft::BlockStatus {
                            status: Some(block_status::Status::InProgress(bft::BlockInProgress {
                                pre_prepared: state.is_some_and(|b| b.pre_prepare.is_some()),
                                prepares_present: self
                                    .nodes
                                    .iter()
                                    .map(|n| state.is_some_and(|b| b.prepares.contains_key(n)))
                                    .collect(),
                                commits_present: self
                                    .nodes
                                    .iter()
                                    .map(|n| state.is_some_and(|b| b.commits.contains_key(n)))
                                    .collect(),
                            })),
                        }
                    })
                    .collect();
                let complete = statuses
                    .iter()
                    .all(|s| matches!(s.status, Some(block_status::Status::Complete(()))));
                bft::SegmentStatus {
                    status: Some(if complete {
                        segment_status::Status::Complete(())
                    } else {
                        segment_status::Status::InProgress(bft::SegmentInProgress {
                            view_number: seg_view.view,
                            block_statuses: statuses,
                        })
                    }),
                }
            })
            .collect();
        bft::EpochStatus {
            epoch_number: self.epoch.info.number,
            segments,
        }
    }

    /// Diagnostics only (`BFT_NODE_DUMP`): the blocks that have a pre-prepare and are not ordered, with who prepared and committed them.
    fn report_stuck_blocks(&mut self) {
        let mut lines = Vec::new();
        for (block, state) in &self.blocks {
            let (Some(pp), None) = (&state.pre_prepare, &state.ordered) else {
                continue;
            };
            let agree = |h: &Vec<u8>| if *h == pp.hash { "same" } else { "OTHER" };
            let prepares: Vec<String> = state
                .prepares
                .iter()
                .map(|(from, h)| format!("{}:{}", &from[..from.len().min(12)], agree(&h.0)))
                .collect();
            let commits: Vec<String> = state
                .commits
                .iter()
                .map(|(from, c)| format!("{}:{}", &from[..from.len().min(12)], agree(&c.0)))
                .collect();
            lines.push(format!(
                "block {block} empty={} prepares=[{}] commits=[{}] commit_sent={}",
                pp.empty,
                prepares.join(","),
                commits.join(","),
                state.commit_sent
            ));
        }
        for l in lines {
            self.events.push(Event::Dropped(format!("STUCK {l}")));
        }
    }

    fn accept(
        &mut self,
        signed: bft::SignedMessage,
        now_ms: u64,
        now_micros: i64,
        out: &mut Vec<bft::SignedMessage>,
    ) {
        let Ok(inner) = unwrap_versioned(&signed.message, 30) else {
            self.events
                .push(Event::Dropped("a message of another wire version".into()));
            return;
        };
        let Ok(message) = bft::ConsensusMessage::decode(inner.as_slice()) else {
            self.events
                .push(Event::Dropped("an undecodable consensus message".into()));
            return;
        };
        // [CANTON-NOTE: INVARIANT] The signature binds the outer sender, and every vote below is counted under the sender the message names
        // inside. Canton parses a network message with the outer sender (`SignedMessage.fromProtoWithNodeId` in
        // `IssConsensusModule.parseNetworkMessage`), so the two are one there; a message that names another node inside is dropped here,
        // or one node could vote for a quorum alone.
        if message.from != signed.from {
            self.events.push(Event::Dropped(format!(
                "a consensus message of {} sent as {}",
                message.from, signed.from
            )));
            return;
        }
        let Some(meta) = message.block_metadata else {
            self.events.push(Event::Dropped(
                "a consensus message without block metadata".into(),
            ));
            return;
        };
        if meta.epoch_number < self.epoch.info.number {
            return;
        }
        if meta.epoch_number > self.epoch.info.number {
            let from = signed.from.clone();
            if let Err(why) = self.future.enqueue(&from, signed) {
                self.events.push(Event::Dropped(format!(
                    "a message of {from} for epoch {} is not queued: {why:?}",
                    meta.epoch_number
                )));
            }
            return;
        }
        // `IssConsensusSignatureVerifier`: a message of the epoch is from a node of its topology
        if !self.nodes.contains(&signed.from) {
            self.events.push(Event::Dropped(format!(
                "a consensus message of {}, which is not in the topology of epoch {}",
                signed.from, self.epoch.info.number
            )));
            return;
        }
        if !self.epoch.contains_block(meta.block_number) {
            self.events.push(Event::Dropped(format!(
                "block {} is not in the epoch",
                meta.block_number
            )));
            return;
        }
        let block = meta.block_number;
        // view change messages belong to a segment, named by its first block
        if matches!(
            message.message,
            Some(bft::consensus_message::Message::ViewChange(_))
                | Some(bft::consensus_message::Message::NewView(_))
        ) {
            self.on_view_change_message(signed, message, now_ms, now_micros, out);
            return;
        }
        let Some(si) = self.segment_index_of_block(block) else {
            return;
        };
        // [CANTON-NOTE: VIEW] A vote of an older view is stale; one of a later view, or any while a view change is being installed, waits for the view
        // (`SegmentState.processPbftNormalCaseMessage` and its future queues).
        let segment_view = self.segments[si].view;
        if message.view_number < segment_view {
            return;
        }
        if message.view_number > segment_view || self.segments[si].in_view_change {
            let from = signed.from.clone();
            if let Err(why) = self.segments[si].future.enqueue(&from, signed) {
                self.events.push(Event::Dropped(format!(
                    "a message of {from} for view {} is not queued: {why:?}",
                    message.view_number
                )));
            }
            return;
        }
        match message.message {
            Some(bft::consensus_message::Message::PrePrepare(pp)) => {
                let leader = self.leader_in_view(si, segment_view);
                if leader.as_deref() != Some(message.from.as_str()) {
                    self.events.push(Event::Dropped(format!(
                        "a pre-prepare of {} for block {block}, which it does not lead",
                        message.from
                    )));
                    return;
                }
                if let Err(why) = self.check_pre_prepare(si, block, &pp) {
                    self.events.push(Event::Dropped(format!(
                        "a pre-prepare of {} for block {block} that does not hold: {why}",
                        message.from
                    )));
                    return;
                }
                self.take_pre_prepare(block, signed, pp);
            }
            Some(bft::consensus_message::Message::Prepare(p)) => {
                if let Some(pp) = self.blocks.get(&block).and_then(|b| b.pre_prepare.as_ref()) {
                    if pp.hash != p.block_hash {
                        self.events.push(Event::Dropped(format!(
                            "a prepare of {} for block {block} names the hash {} and not {}",
                            message.from,
                            hex_of(&p.block_hash),
                            hex_of(&pp.hash)
                        )));
                    }
                }
                self.blocks
                    .entry(block)
                    .or_default()
                    .prepares
                    .entry(message.from.clone())
                    .or_insert((p.block_hash, signed));
            }
            Some(bft::consensus_message::Message::Commit(c)) => {
                let state = self.blocks.entry(block).or_default();
                // a commit of this node that comes back (put back after a restart) means it already voted: it does not sign a second one
                if message.from == self.me {
                    state.commit_sent = true;
                }
                state.commits.entry(message.from.clone()).or_insert((
                    c.block_hash,
                    c.local_timestamp,
                    signed,
                ));
            }
            _ => return,
        }
        self.advance(block, now_ms, now_micros, out);
    }

    // ----- view changes (`SegmentState`, `PbftViewChangeState`, `NewView`) -----
}

#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;
