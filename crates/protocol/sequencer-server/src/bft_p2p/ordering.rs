//! Consensus state machine dispatch, retransmission, state transfer coordination, and ticks for [`Consensus`].

use std::sync::Arc;

use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::BftOrderingMessage;

use super::state_transfer::CatchUp;
use super::{lock_critical, lock_or_recover, pbft_discriminator, Consensus, SignedMessage};
use crate::onboarding::Registry;

impl Consensus {
    /// A peer's status of the epoch (`EpochStatus`, its retransmission request): a node that has not started answers with a status of its own that says it has
    /// nothing, and the peer then sends it what it has of the epoch (the proposals, prepares and commits), the proposal among them, from which the node learns
    /// where the epoch started. A status of the same epoch is answered once a second at most.
    pub fn on_status(&self, signed: &SignedMessage) {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            block_status, segment_status, BlockInProgress, BlockStatus, EpochStatus, SegmentInProgress, SegmentStatus,
        };
        use prost::Message as _;
        if self.is_started() {
            return;
        }
        let Some(theirs) = canton_bft_orderer::wire::unwrap_versioned(&signed.message, 30)
            .ok()
            .and_then(|inner| EpochStatus::decode(inner.as_slice()).ok())
        else {
            return;
        };
        let now = std::time::Instant::now();
        {
            let mut last = lock_or_recover(&self.last_status, "last_status");
            if last.is_some_and(|t| now.duration_since(t) < std::time::Duration::from_secs(1)) {
                return;
            }
            *last = Some(now);
        }
        let nodes = lock_or_recover(&self.nodes, "nodes").len();
        // the same shape as theirs (a segment per leader, a status per slot), with nothing present
        let segments = theirs
            .segments
            .iter()
            .map(|segment| {
                let slots = match &segment.status {
                    Some(segment_status::Status::InProgress(p)) => p.block_statuses.len(),
                    Some(segment_status::Status::InViewChange(v)) => v.are_blocks_complete.len(),
                    _ => 0,
                };
                // a segment the peer has completed has nothing the peer could still send for blocks in progress: it is left out of the request as complete
                if slots == 0 {
                    return SegmentStatus {
                        status: Some(segment_status::Status::Complete(())),
                    };
                }
                SegmentStatus {
                    status: Some(segment_status::Status::InProgress(SegmentInProgress {
                        view_number: 0,
                        block_statuses: (0..slots)
                            .map(|_| BlockStatus {
                                status: Some(block_status::Status::InProgress(BlockInProgress {
                                    pre_prepared: false,
                                    prepares_present: vec![false; nodes],
                                    commits_present: vec![false; nodes],
                                })),
                            })
                            .collect(),
                    })),
                }
            })
            .collect();
        let status = EpochStatus {
            epoch_number: theirs.epoch_number,
            segments,
        };
        self.send_status(status);
    }

    /// Signs a status and sends it to every peer as a retransmission request.
    fn send_status(
        &self,
        status: canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::EpochStatus,
    ) {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            bft_ordering_message_body::Message, retransmission_message, BftOrderingMessageBody, RetransmissionMessage,
        };
        use prost::Message as _;
        let theirs_epoch = status.epoch_number;
        let evidence = canton_bft_orderer::wire::wrap_versioned(30, &status.encode_to_vec());
        let Ok(signature) = canton_bft_orderer::wire::sign_message(
            canton_bft_orderer::wire::AuthenticatedMessageType::BftSignedRetransmissionMessage,
            &self.member,
            &evidence,
            &ed25519_dalek::SigningKey::from_bytes(&self.signing_seed),
            &self.fingerprint,
        ) else {
            return;
        };
        let request = SignedMessage {
            message: evidence,
            from: self.member.clone(),
            signature: Some(signature),
        };
        let senders = lock_or_recover(&self.senders, "senders").clone();
        crate::diag::diag_eprintln!(
            "CONSENSUS asks the peers for what they have of epoch {}",
            theirs_epoch
        );
        for sender in senders {
            let _ = sender.try_send(BftOrderingMessage {
                trace_context: String::new(),
                body: Some(BftOrderingMessageBody {
                    message: Some(Message::RetransmissionMessage(RetransmissionMessage {
                        message: Some(retransmission_message::Message::RetransmissionRequest(
                            request.clone(),
                        )),
                    })),
                }),
                sent_by: self.member.clone(),
                sent_at: None,
            });
        }
    }

    /// Where the consensus finds a node's key by its fingerprint: the sequencers' keys in the topology, and this node's own.
    fn key_lookup(&self) -> canton_bft_orderer::node::KeyLookup {
        let registry = std::sync::Arc::clone(&self.registry);
        // [CANTON-NOTE: OWN KEY] The registry was read from the topology before this node was onboarded: its own key is not in it, but the acks this node
        // signed are in the proposals it votes on (the batches it stored), so it knows its own key and fingerprint.
        let own_member = self.member.clone();
        let own_fingerprint = self.fingerprint.clone();
        let own_key = canton_algo::member_signature::own_ed25519_key(
            &canton_participant::topology_wire::Ed25519Key::from_seed(self.signing_seed).spki_der,
        )
        .ok();
        Box::new(move |from, fingerprint| {
            if from == own_member && fingerprint == own_fingerprint {
                return own_key.clone();
            }
            registry
                .get(from)
                .and_then(|r| r.signing_keys.iter().find(|k| k.id == fingerprint).cloned())
        })
    }

    fn build_node(
        &self,
        nodes: &[String],
        info: canton_bft_orderer::topology::EpochInfo,
        policy: Option<canton_bft_orderer::blacklist::PolicyState>,
        last_commits: Vec<SignedMessage>,
        last_bft_time: Option<i64>,
        ms: u64,
    ) -> canton_bft_orderer::node::ConsensusNode {
        let mut node = canton_bft_orderer::node::ConsensusNode::with_policy(
            &self.member,
            nodes,
            info,
            canton_bft_orderer::node::Signer {
                key: ed25519_dalek::SigningKey::from_bytes(&self.signing_seed),
                fingerprint: self.fingerprint.clone(),
            },
            self.key_lookup(),
            ms,
            policy,
        );
        node.restore_epoch_boundary(last_commits, last_bft_time);
        if let Some(millis) = self.view_change_timeout_ms {
            node.set_view_change_timeout(millis, ms);
        }
        // [CANTON-NOTE: LIMITATION] The official node reads the topology of the next epoch at the end of the current one (`OrderingTopologyProvider`
        // at the epoch's last BFT time); this node reads the sequencers the synchronizer has now (`refresh_topology`), which differs only while a
        // change is pending at the boundary.
        let current = Arc::clone(&self.nodes);
        let epoch_length = self.epoch_length;
        node.set_topology_source(Box::new(move |_epoch| {
            let nodes = lock_or_recover(&current, "nodes").clone();
            let length = epoch_length.unwrap_or(10 * nodes.len() as i64);
            Some(canton_bft_orderer::node::EpochTopology { nodes, length })
        }));
        node
    }

    /// The sequencers of the synchronizer as its topology names them now, with their keys: the next epoch runs on them, and their messages are
    /// checked with these keys.
    pub fn refresh_topology(&self, sequencers: &Registry) {
        let members = sequencers.members();
        if members.is_empty() {
            return;
        }
        for member in &members {
            if let Some(registered) = sequencers.get(member) {
                self.registry.insert(registered);
            }
        }
        self.set_nodes(members);
    }

    /// Returns the BFT timestamp of the last block previously emitted before restart.
    pub fn restored_last_bft_time(&self) -> Option<i64> {
        self.lock_output()
            .ok()
            .and_then(|o| o.restored_last_bft_time)
    }

    /// Starts consensus immediately at genesis (epoch 0) or resumes directly from recovered `ord_*` / state-file epoch state without waiting for an external peer.
    pub fn start_genesis_or_resume(&self) -> Result<(), String> {
        let (ms, micros) = self.now();
        let (events, out) = {
            let mut guard = lock_critical(&self.node, "node")?;
            if guard.is_some() {
                return Ok(());
            }
            let mut nodes = lock_or_recover(&self.nodes, "nodes").clone();
            if !nodes.contains(&self.member) {
                nodes.push(self.member.clone());
            }
            nodes.sort();
            nodes.dedup();
            let default_len = self
                .epoch_length
                .unwrap_or_else(|| 10 * nodes.len().max(1) as i64);
            let saved_epoch = lock_critical(&self.persisted_epoch, "persisted_epoch")?.clone();
            let saved_policy = lock_critical(&self.persisted_policy, "persisted_policy")?.clone();
            let info = if let Some(ep) = saved_epoch {
                canton_bft_orderer::topology::EpochInfo {
                    number: ep.epoch_number,
                    start_block_number: ep.start_block_number,
                    length: ep.epoch_length.max(1),
                }
            } else if let Some(p) = &saved_policy {
                canton_bft_orderer::topology::EpochInfo {
                    number: p.epoch_number,
                    start_block_number: p.start_block,
                    length: p.epoch_length.max(1),
                }
            } else {
                canton_bft_orderer::topology::EpochInfo {
                    number: 0,
                    start_block_number: 0,
                    length: default_len,
                }
            };
            let mut signed_before = std::mem::take(&mut *lock_critical(&self.replay, "replay")?);
            let prev_commits: Vec<SignedMessage> = if info.number > 0 {
                let prev_epoch = info.number - 1;
                let prev_last_block = info.start_block_number - 1;
                let strong = canton_bft_orderer::topology::strong_quorum_size(nodes.len());
                let mut by_view: std::collections::BTreeMap<i64, Vec<SignedMessage>> =
                    std::collections::BTreeMap::new();
                for m in &signed_before {
                    if let Some((e, b, v, d)) = pbft_discriminator(m) {
                        if e == prev_epoch && b == prev_last_block && d == 2 {
                            by_view.entry(v).or_default().push(m.clone());
                        }
                    }
                }
                by_view
                    .into_values()
                    .rfind(|v| v.len() >= strong)
                    .map(|v| v.into_iter().take(strong).collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let last_bft_time = if info.number > 0 {
                self.lock_output()?.epoch_boundary_bft_time
            } else {
                None
            };
            let mut node = self.build_node(
                &nodes,
                info,
                saved_policy.filter(|p| p.epoch_number == info.number),
                prev_commits,
                last_bft_time,
                ms,
            );
            // Replay Prepare(1)/Commit(2) before PrePrepare(0) so already-sent own votes are never re-signed.
            let replay_order = |m: &SignedMessage| match pbft_discriminator(m) {
                Some((e, b, v, 1)) => (e, b, v, 0i16),
                Some((e, b, v, 2)) => (e, b, v, 1i16),
                Some((e, b, v, 0)) => (e, b, v, 2i16),
                Some((e, b, v, d)) => (e, b, v, d + 10),
                None => (0, 0, 0, i16::MAX),
            };
            signed_before.sort_by_key(replay_order);
            let mut replay_count = 0usize;
            for mine in signed_before {
                if pbft_discriminator(&mine).is_some_and(|(e, _, _, _)| e >= info.number) {
                    let _ = node.on_message(mine, ms, micros);
                    replay_count += 1;
                }
            }
            if replay_count > 0 {
                crate::diag::diag_eprintln!(
                    "CONSENSUS resumed epoch {} at block {} with {} saved message(s)",
                    info.number,
                    info.start_block_number,
                    replay_count
                );
            } else {
                crate::diag::diag_eprintln!(
                    "CONSENSUS started genesis epoch {} at block {}, length {}, nodes {}",
                    info.number,
                    info.start_block_number,
                    info.length,
                    nodes.len()
                );
            }
            self.save_policy(node.policy_state())?;
            let pending_before = std::mem::take(&mut *lock_critical(&self.pending, "pending")?);
            let mut out = Vec::new();
            for old in pending_before {
                out.extend(node.on_message(old, ms, micros));
            }
            let events = node.take_events();
            *guard = Some(node);
            (events, out)
        };
        self.after_events(events)?;
        self.broadcast(out)
    }

    /// The epoch a `PrePrepare` is in and where it started, from the commits its leader carries: those of the last block of the epoch before.
    fn epoch_of(signed: &SignedMessage) -> Option<(i64, i64)> {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            consensus_message::Message, ConsensusMessage,
        };
        use prost::Message as _;
        let decode = |m: &SignedMessage| {
            canton_bft_orderer::wire::unwrap_versioned(&m.message, 30)
                .ok()
                .and_then(|inner| ConsensusMessage::decode(inner.as_slice()).ok())
        };
        let pp = decode(signed)?;
        let epoch = pp.block_metadata?.epoch_number;
        let Some(Message::PrePrepare(body)) = pp.message else {
            return None;
        };
        let commit = body
            .bft_time_canonical_commit_set?
            .canonical_commits
            .first()
            .cloned()?;
        let meta = decode(&commit)?.block_metadata?;
        (meta.epoch_number == epoch - 1).then_some((epoch, meta.block_number + 1))
    }

    /// A consensus message of a peer (its signature checked).
    pub fn on_message(&self, signed: SignedMessage) -> Result<(), String> {
        if std::env::var_os("BFT_P2P_TRACE").is_some() {
            crate::diag::diag_eprintln!("CONSENSUS received a message of {}", signed.from);
        }
        self.record_pbft_messages(std::slice::from_ref(&signed), true, true)?;
        let (ms, micros) = self.now();
        let (out, events) = {
            let mut guard = lock_critical(&self.node, "node")?;
            if guard.is_none() {
                // a state transfer in progress: everything waits for it
                if self.lock_catchup()?.is_some() {
                    let mut pending = lock_critical(&self.pending, "pending")?;
                    if pending.len() < 4096 {
                        pending.push(signed);
                    }
                    return Ok(());
                }
                let Some((epoch, start)) = Self::epoch_of(&signed) else {
                    // [CANTON-NOTE: RETRANSMISSION] only the first block of a segment names the last block of the epoch before: keep the others for later
                    let mut pending = lock_critical(&self.pending, "pending")?;
                    if pending.len() < 4096 {
                        pending.push(signed);
                    }
                    return Ok(());
                };
                let nodes = lock_or_recover(&self.nodes, "nodes").clone();
                let length = self.epoch_length.unwrap_or(10 * nodes.len() as i64);
                // [CANTON-NOTE: STATE-TRANSFER] The state this node kept is for an earlier epoch than the one it joins (or this is a fresh join at epoch > 0 with no persisted policy):
                // fetch the epochs between from peers to rebuild leader selection state (U-52).
                let kept = lock_critical(&self.persisted_policy, "persisted_policy")?.clone();
                let no_result_yet = self.lock_ready_policy()?.is_none();
                let transfer_from = kept
                    .clone()
                    .filter(|p| p.epoch_number < epoch && no_result_yet)
                    .or_else(|| {
                        (kept.is_none() && epoch > 0 && no_result_yet).then(|| {
                            canton_bft_orderer::blacklist::PolicyState::first(&nodes, length)
                        })
                    });
                if let Some(base_policy) = transfer_from {
                    crate::diag::diag_eprintln!(
                            "CONSENSUS state transfer: this node's state is for epoch {}, the peers are in epoch {epoch}",
                            base_policy.epoch_number
                        );
                    let output_after = {
                        let o = self.lock_output()?;
                        o.restored_last_output_block.zip(o.restored_last_bft_time)
                    };
                    *self.lock_catchup()? =
                        Some(CatchUp::new(base_policy, epoch, signed, output_after));
                    drop(guard);
                    self.request_epoch()?;
                    return Ok(());
                }
                let policy = self
                    .lock_ready_policy()?
                    .take()
                    .or_else(|| kept.filter(|p| p.epoch_number == epoch));
                crate::diag::diag_eprintln!(
                    "CONSENSUS joining epoch {epoch} at block {start}, length {length}, nodes {}",
                    nodes.len()
                );
                let node = self.build_node(
                    &nodes,
                    canton_bft_orderer::topology::EpochInfo {
                        number: epoch,
                        start_block_number: start,
                        length,
                    },
                    policy,
                    Vec::new(),
                    None,
                    ms,
                );
                *guard = Some(node);
            }
            let Some(n) = guard.as_mut() else {
                return Ok(());
            };
            let mut out = Vec::new();
            // what this node signed before it was restarted comes back first (its own proposals and votes of the epoch)
            let signed_before = std::mem::take(&mut *lock_critical(&self.replay, "replay")?);
            if !signed_before.is_empty() {
                crate::diag::diag_eprintln!(
                    "CONSENSUS puts back {} message(s) this node signed before",
                    signed_before.len()
                );
            }
            for mine in signed_before {
                n.on_message(mine, ms, micros);
            }
            let earlier = std::mem::take(&mut *lock_critical(&self.pending, "pending")?);
            for old in earlier {
                out.extend(n.on_message(old, ms, micros));
            }
            out.extend(n.on_message(signed, ms, micros));
            self.save_policy(n.policy_state())?;
            (out, n.take_events())
        };
        self.after_events(events)?;
        self.broadcast(out)
    }

    /// Asks the peers for the blocks of the epoch the state transfer is at (`BlockTransferRequest`, signed as a `StateTransferMessage`).
    fn request_epoch(&self) -> Result<(), String> {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::{
            v30::{bft_ordering_message_body::Message, BftOrderingMessageBody, BlockTransferRequest},
            v31::{state_transfer_message, StateTransferMessage},
        };
        use prost::Message as _;
        let epoch = {
            let mut guard = self.lock_catchup()?;
            let Some(c) = guard.as_mut() else {
                return Ok(());
            };
            c.last_request = Some(std::time::Instant::now());
            c.policy.epoch_number
        };
        let body = StateTransferMessage {
            message: Some(state_transfer_message::Message::BlockRequest(
                BlockTransferRequest { epoch },
            )),
        };
        let evidence = canton_bft_orderer::wire::wrap_versioned(31, &body.encode_to_vec());
        let Ok(signature) = canton_bft_orderer::wire::sign_message(
            canton_bft_orderer::wire::AuthenticatedMessageType::BftSignedStateTransferMessage,
            &self.member,
            &evidence,
            &ed25519_dalek::SigningKey::from_bytes(&self.signing_seed),
            &self.fingerprint,
        ) else {
            return Ok(());
        };
        let signed = SignedMessage {
            message: evidence,
            from: self.member.clone(),
            signature: Some(signature),
        };
        crate::diag::diag_eprintln!(
            "CONSENSUS state transfer: asks the peers for the blocks of epoch {epoch}"
        );
        let senders = lock_or_recover(&self.senders, "senders").clone();
        for sender in senders {
            let _ = sender.try_send(BftOrderingMessage {
                trace_context: String::new(),
                body: Some(BftOrderingMessageBody {
                    message: Some(Message::StateTransferMessage(signed.clone())),
                }),
                sent_by: self.member.clone(),
                sent_at: None,
            });
        }
        Ok(())
    }

    /// The length of an epoch of `nodes` nodes when no length is configured (ten blocks per node); `None` when one is.
    fn epoch_length_of(&self, nodes: usize) -> Option<i64> {
        self.epoch_length.is_none().then_some(10 * nodes as i64)
    }

    fn finish_or_advance_catchup(
        &self,
        nodes: &[String],
        all_blocks: &[(i64, i64)],
        guard: &mut Option<CatchUp>,
    ) -> (Option<CatchUp>, bool) {
        let Some(c) = guard.as_mut() else {
            return (None, false);
        };
        let done_epoch = c.policy.epoch_number;
        // the next epoch is the one the node joins (this node's current topology), or another past one: its topology is read from its own
        // certificates when they arrive (`on_transferred_blocks`), until then it is taken to be the one before
        let joins_next = done_epoch + 1 >= c.target_epoch;
        let next_nodes = if joins_next {
            nodes.to_vec()
        } else {
            c.policy.nodes.clone()
        };
        c.policy = c.policy.after_blocks(&next_nodes, all_blocks);
        if joins_next {
            if let Some(length) = self.epoch_length_of(nodes.len()) {
                c.policy.epoch_length = length;
            }
        }
        c.collected.clear();
        c.voters.clear();
        crate::diag::diag_eprintln!(
            "CONSENSUS state transfer: epoch {done_epoch} is complete, leaders of epoch {} are {:?}, blacklisted {:?}",
            c.policy.epoch_number,
            c.policy.leaders(),
            c.policy.blacklisted_nodes()
        );
        if c.policy.epoch_number >= c.target_epoch {
            (guard.take(), false)
        } else {
            (None, true)
        }
    }

    /// Blocks of an epoch a peer transferred (`(block, view of its proposal)`, their certificates checked by the caller): when the epoch is complete, the leader
    /// selection state moves to the next epoch; at the epoch the node joins the transfer is done and the node starts with that state.
    pub fn on_transferred_blocks(
        &self,
        epoch: i64,
        blocks: Vec<(i64, i64)>,
        voters: &std::collections::BTreeSet<String>,
    ) -> Result<(), String> {
        let nodes = lock_or_recover(&self.nodes, "nodes").clone();
        let (done, again, output) = {
            let mut guard = self.lock_catchup()?;
            let Some(c) = guard.as_mut() else {
                return Ok(());
            };
            if epoch != c.policy.epoch_number {
                return Ok(());
            }
            for (block, view) in blocks {
                c.collected.insert(block, view);
            }
            // [CANTON-NOTE: SEMANTICS] An epoch has ten blocks for each node of **its** ordering topology (measured on the official nodes: 20 with two
            // sequencers, 30 once a third is in). A past epoch's topology is not this node's current one (a node that joins is not in the epochs
            // before): it is taken from the epoch's own certificates, as the nodes whose verified commits they carry. A configured epoch length
            // stays what it is.
            // [CANTON-NOTE: LIMITATION] A node of that topology that committed no block of the epoch is not counted, so an epoch through which a
            // node was down is taken to be shorter than it was. The official node gets the topology of an epoch from its onboarding snapshot.
            c.voters.extend(voters.iter().cloned());
            if let Some(length) = self
                .epoch_length_of(c.voters.len())
                .filter(|_| self.epoch_length.is_none() && !c.voters.is_empty())
            {
                c.policy.nodes = c.voters.iter().cloned().collect();
                c.policy.epoch_length = length;
            }
            if (c.collected.len() as i64) < c.policy.epoch_length {
                crate::diag::diag_eprintln!(
                    "CONSENSUS state transfer: {} of the {} blocks of epoch {epoch}",
                    c.collected.len(),
                    c.policy.epoch_length
                );
                return Ok(());
            }
            let all: Vec<(i64, i64)> = c.collected.iter().map(|(b, v)| (*b, *v)).collect();
            let output = c.take_output(epoch);
            let (done, again) = self.finish_or_advance_catchup(&nodes, &all, &mut guard);
            (done, again, output)
        };
        self.output_transferred(output)?;
        if again {
            self.request_epoch()?;
        }
        if let Some(c) = done {
            self.save_policy(&c.policy)?;
            *self.lock_ready_policy()? = Some(c.policy);
            // the message that told the epoch starts the node, with the pending ones after it
            self.on_message(c.trigger)?;
        }
        Ok(())
    }

    /// A peer's `BlockTransferResponse`: the commit certificates of the blocks of the epoch the state transfer is at. Every certificate has to be of
    /// that epoch and hold like a live one (`StateTransferMessageValidator.validateBlockTransferResponse`, `verifyCommitCertificateSignatures`);
    /// a response with one that does not is dropped whole.
    pub fn on_block_transfer_response(
        &self,
        sent_by: &str,
        certificates: Vec<canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::CommitCertificate>,
    ) -> Result<(), String> {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            consensus_certificate::Certificate, ConsensusCertificate, ConsensusMessage,
        };
        use prost::Message as _;
        let Some(epoch) = self.lock_catchup()?.as_ref().map(|c| c.policy.epoch_number) else {
            return Ok(());
        };
        let nodes = lock_or_recover(&self.nodes, "nodes").clone();
        // [CANTON-NOTE: LIMITATION] A past epoch's membership is not known here: the official node does not transfer the epochs before its onboarding (its
        // snapshot carries their leader selection state, U-52), this node does. Its votes must come from known sequencers, and a strong quorum is counted
        // among the sequencers other than this node (the topology before it joined); an epoch it was already in is held to that smaller quorum too.
        let others = nodes.iter().filter(|n| **n != self.member).count();
        let membership = canton_bft_orderer::verify::Membership {
            nodes: &nodes,
            strong_quorum: canton_bft_orderer::topology::strong_quorum_size(others),
        };
        let keys = self.key_lookup();
        let mut blocks = Vec::new();
        // the nodes whose verified commits the certificates carry: the ordering topology the epoch had
        let mut voters = std::collections::BTreeSet::new();
        let mut proposals = Vec::new();
        for cert in certificates {
            let proposal = cert
                .pre_prepare
                .as_ref()
                .and_then(|pp| canton_bft_orderer::wire::unwrap_versioned(&pp.message, 30).ok())
                .and_then(|i| ConsensusMessage::decode(i.as_slice()).ok());
            let Some((meta, view)) =
                proposal.and_then(|p| p.block_metadata.map(|m| (m, p.view_number)))
            else {
                crate::diag::diag_eprintln!(
                    "P2P {sent_by}: a block transfer response with an undecodable pre-prepare, dropped"
                );
                return Ok(());
            };
            if meta.epoch_number != epoch {
                crate::diag::diag_eprintln!(
                    "P2P {sent_by}: a block transfer response with a block of epoch {}, not {epoch}, dropped",
                    meta.epoch_number
                );
                return Ok(());
            }
            let senders: Vec<String> = cert.commits.iter().map(|m| m.from.clone()).collect();
            let pre_prepare = cert.pre_prepare.clone().unwrap_or_default();
            let wrapped = ConsensusCertificate {
                certificate: Some(Certificate::CommitCertificate(cert)),
            };
            if let Err(e) =
                canton_bft_orderer::verify::verify_certificate(&wrapped, &membership, &keys, None)
            {
                crate::diag::diag_eprintln!(
                    "P2P {sent_by}: a transferred certificate of block {} does not hold, the response is dropped: {e}",
                    meta.block_number
                );
                return Ok(());
            }
            blocks.push((meta.block_number, view));
            proposals.push((meta.block_number, pre_prepare));
            voters.extend(senders);
        }
        if let Some(c) = self.lock_catchup()?.as_mut() {
            for (block, pre_prepare) in proposals {
                c.keep_proposal(block, pre_prepare);
            }
        }
        crate::diag::diag_eprintln!(
            "P2P {sent_by}: {} transferred certificate(s) of epoch {epoch} hold (a strong quorum is {})",
            blocks.len(),
            membership.strong_quorum
        );
        self.on_transferred_blocks(epoch, blocks, &voters)
    }

    /// Advances state transfer past an empty/pruned historical epoch so fresh nodes joining later epochs do not stall (U-52).
    pub fn on_empty_transferred_epoch(&self) -> Result<(), String> {
        let nodes = lock_or_recover(&self.nodes, "nodes").clone();
        let (done, again) = {
            let mut guard = self.lock_catchup()?;
            self.finish_or_advance_catchup(&nodes, &[], &mut guard)
        };
        if again {
            self.request_epoch()?;
        }
        if let Some(c) = done {
            self.save_policy(&c.policy)?;
            *self.lock_ready_policy()? = Some(c.policy);
            self.on_message(c.trigger)?;
        }
        Ok(())
    }

    /// Writes the leader selection state once for each epoch (state file `.policy` and/or `ord_leader_selection_state`).
    fn save_policy(
        &self,
        policy: &canton_bft_orderer::blacklist::PolicyState,
    ) -> Result<(), String> {
        let mut last = lock_critical(&self.last_policy_epoch, "last_policy_epoch")?;
        if *last == policy.epoch_number {
            return Ok(());
        }
        let mut wrote = false;
        let path = lock_critical(&self.policy_file, "policy_file")?.clone();
        if let Some(path) = path {
            let tmp = path.with_extension("policy.tmp");
            if std::fs::write(&tmp, policy.to_text()).is_ok()
                && std::fs::rename(&tmp, &path).is_ok()
            {
                wrote = true;
            }
        }
        let ord_store = lock_critical(&self.ord_store, "ord_store")?.clone();
        if let Some(store) = ord_store {
            store.save_leader_policy(policy);
            wrote = true;
        }
        if wrote {
            *last = policy.epoch_number;
        }
        Ok(())
    }

    /// A commit certificate of a peer's retransmission (a strong quorum of commits for a proposal): the block is ordered without this node's own votes. The node
    /// verifies the certificate (signatures, senders, hash, quorum); its messages are recorded only once it is taken. Returns why it was not taken.
    pub fn on_commit_certificate(
        &self,
        cert: canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::CommitCertificate,
    ) -> Result<(), String> {
        let messages: Vec<SignedMessage> = cert
            .pre_prepare
            .iter()
            .chain(&cert.commits)
            .cloned()
            .collect();
        let (ms, micros) = self.now();
        let (out, events) = {
            let mut guard = lock_critical(&self.node, "node")?;
            match guard.as_mut() {
                Some(n) => (n.on_commit_certificate(cert, ms, micros)?, n.take_events()),
                None => return Err("the consensus has not started".into()),
            }
        };
        // before the events: a block ordered by the certificate saves its messages from what is recorded
        self.record_pbft_messages(&messages, true, true)?;
        self.after_events(events)?;
        self.broadcast(out)
    }

    /// The clock: a leader whose time has come proposes.
    pub fn tick(&self) -> Result<(), String> {
        self.prune_closed_senders();
        self.disseminate()?;
        let (ms, micros) = self.now();
        let (out, events) = {
            let mut guard = lock_critical(&self.node, "node")?;
            match guard.as_mut() {
                Some(n) => {
                    let out = n.tick(ms, micros);
                    self.save_policy(n.policy_state())?;
                    (out, n.take_events())
                }
                None => {
                    drop(guard);
                    // a state transfer whose request went unanswered is asked again
                    let due = self.lock_catchup()?.as_ref().is_some_and(|c| {
                        c.last_request
                            .is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(3))
                    });
                    if due {
                        self.request_epoch()?;
                    }
                    return Ok(());
                }
            }
        };
        self.after_events(events)?;
        self.broadcast(out)?;
        // [CANTON-NOTE: RETRANSMISSION] a started node keeps telling the peers what it has of the epoch (the official node does it every few seconds); a peer that has
        // more answers with the commit certificates and the in-progress messages the status lacks, which is how a node that was away catches up
        let due = {
            let mut last = lock_or_recover(&self.last_status, "last_status");
            let now = std::time::Instant::now();
            let due =
                last.is_none_or(|t| now.duration_since(t) >= std::time::Duration::from_secs(3));
            if due {
                *last = Some(now);
            }
            due
        };
        if due {
            let status = lock_critical(&self.node, "node")?
                .as_ref()
                .map(|n| n.epoch_status());
            if let Some(status) = status {
                self.send_status(status);
            }
        }
        Ok(())
    }
}

pub(super) fn report(events: Vec<canton_bft_orderer::node::Event>) {
    for e in events {
        match e {
            canton_bft_orderer::node::Event::BlockOrdered {
                epoch,
                block,
                empty,
            } => {
                crate::diag::diag_eprintln!(
                    "CONSENSUS ordered block {block} of epoch {epoch}{}",
                    if empty { " (empty)" } else { "" }
                )
            }
            canton_bft_orderer::node::Event::BlockOutput {
                epoch,
                block,
                bft_time_micros,
                previous_known,
                batches,
                ..
            } => crate::diag::diag_eprintln!(
                "OUTPUT block {block} epoch {epoch} bft_time_micros {bft_time_micros} previous_known {previous_known} batches {}",
                batches.len()
            ),
            canton_bft_orderer::node::Event::EpochStarted { epoch, start_block } => {
                crate::diag::diag_eprintln!("CONSENSUS epoch {epoch} started at block {start_block}")
            }
            canton_bft_orderer::node::Event::ViewChangeStarted {
                epoch,
                first_block,
                view,
                leader,
            } => crate::diag::diag_eprintln!(
                "CONSENSUS segment starting at block {first_block} of epoch {epoch} moves to view {view}, led by {leader}"
            ),
            canton_bft_orderer::node::Event::ViewChangeCompleted {
                epoch,
                first_block,
                view,
            } => crate::diag::diag_eprintln!(
                "CONSENSUS view change of the segment starting at block {first_block} of epoch {epoch} completed in view {view}"
            ),
            canton_bft_orderer::node::Event::Dropped(why) => crate::diag::diag_eprintln!("CONSENSUS dropped: {why}"),
        }
    }
}
