//! A deterministic simulation of a cluster of [`ConsensusNode`]s: a virtual clock and an in-memory network that drops, delays (and so reorders) and
//! duplicates messages, crashes and restarts nodes, and lets a scenario play a faulty node with its key. The same seed gives the same run.
//!
//! What the runtime (`bft_p2p.rs`) does around the node is modelled here as plainly as possible: the transport checks the outer signature of a
//! message once, every node keeps what it signed and received (its state file) and puts it back when it restarts, and a node re-sends what it has of
//! the epoch a peer is in for the blocks that peer has not ordered yet (retransmission).
use crate::availability::{ack_hash, batch_id, Request};
use crate::blacklist::PolicyState;
use crate::consensus::block_hash_of_evidence;
use crate::node::{ConsensusNode, Event, KeyLookup, Signer};
use crate::topology::{strong_quorum_size, EpochInfo};
use crate::verify::decode_consensus;
use crate::wire::{sign_message, verify_message_signature, AuthenticatedMessageType};
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft;
use std::collections::{BTreeMap, BTreeSet};

/// The clock moves in steps of this many milliseconds; every live node ticks at each step.
pub const TICK_MS: u64 = 10;
/// How often a node re-sends to each peer what it has of the peer's epoch.
pub const RETRANSMIT_MS: u64 = 1_000;
/// How often every node gets a new available batch to propose.
pub const BATCH_MS: u64 = 700;
/// The view change timeout of the simulated nodes (the default 10 s makes the runs long).
pub const VIEW_CHANGE_TIMEOUT_MS: u64 = 3_000;

/// xorshift64*: enough for a schedule, and the same on every machine.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self((seed ^ 0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number in `0..n`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// What the network does to a message: out of 100, how many are lost and how many arrive twice; each copy takes `1..=max_delay_ms`.
#[derive(Clone, Copy, Debug)]
pub struct Faults {
    pub drop_pct: u64,
    pub dup_pct: u64,
    pub max_delay_ms: u64,
}

impl Faults {
    pub const NONE: Faults = Faults {
        drop_pct: 0,
        dup_pct: 0,
        max_delay_ms: 5,
    };
}

/// A block as a node handed it to its output: what every honest node must agree on at a height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub epoch: i64,
    pub bft_time_micros: i64,
    pub batches: Vec<Vec<u8>>,
    pub original_leader: String,
    pub proposal_view: i64,
    pub is_last_in_epoch: bool,
}

pub enum Wire {
    Consensus(bft::SignedMessage),
    /// A retransmitted commit certificate (`RetransmissionMessage.RetransmissionResponse`).
    Certificate(bft::CommitCertificate),
}

/// Rewrites what a faulty node sends: it gets the message as the node made it and returns what goes on the wire.
pub type Tamper = fn(&Sim, usize, bft::SignedMessage) -> bft::SignedMessage;

/// What a node keeps when it stops, to start again from (`.policy` and the state file of `persist_to`).
struct Saved {
    info: EpochInfo,
    policy: PolicyState,
}

pub struct Sim {
    pub now_ms: u64,
    pub faults: Faults,
    rng: Rng,
    names: Vec<String>,
    nodes: Vec<Option<ConsensusNode>>,
    saved: Vec<Option<Saved>>,
    /// Nodes a scenario plays: they are left out of the safety and liveness checks.
    pub byzantine: BTreeSet<usize>,
    tamper: BTreeMap<usize, Tamper>,
    /// What each node signed or received, by epoch, each message once (its state file).
    logs: Vec<BTreeMap<i64, Vec<bft::SignedMessage>>>,
    logged: Vec<BTreeSet<Vec<u8>>>,
    in_flight: BTreeMap<(u64, u64), (usize, usize, Wire)>,
    next_seq: u64,
    next_batch: u64,
    /// What each node output, by height.
    pub outputs: Vec<BTreeMap<i64, Output>>,
    /// The first honest output at each height and who made it.
    decided: BTreeMap<i64, (usize, Output)>,
    /// Two different blocks at one height (a node against itself across a restart, or against another honest node).
    pub conflicts: Vec<String>,
    /// Why each node dropped what it dropped (`Event::Dropped`, refused certificates, signatures the transport refused).
    pub dropped: Vec<Vec<String>>,
    pub delivered: u64,
}

fn sign_key(i: usize) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[i as u8 + 1; 32])
}

fn fingerprint(name: &str) -> String {
    format!("fp-{name}")
}

/// The keys of `names` as the cluster signs: node i has the seed `[i + 1; 32]` and the fingerprint `fp-<name>`.
fn keys_of(names: &[String]) -> KeyLookup {
    let names = names.to_vec();
    Box::new(move |from, fp| {
        let i = names.iter().position(|n| n == from)?;
        (fp == fingerprint(from))
            .then(|| crate::wire::test_key(&sign_key(i).verifying_key(), Some(fp)))
    })
}

/// A commit certificate of `block` from what a node has: a strong quorum of commits of one view and hash, and the proposal of that hash (sent on its
/// own or carried by a `NewView`).
fn certificate_in(
    log: &[bft::SignedMessage],
    block: i64,
    strong: usize,
) -> Option<bft::CommitCertificate> {
    use bft::consensus_message::Message;
    let mut proposals: BTreeMap<Vec<u8>, bft::SignedMessage> = BTreeMap::new();
    let mut commits: BTreeMap<(i64, Vec<u8>), BTreeMap<String, bft::SignedMessage>> =
        BTreeMap::new();
    let mut propose = |m: &bft::SignedMessage| {
        let of_block = decode_consensus(m)
            .and_then(|c| c.block_metadata)
            .is_some_and(|meta| meta.block_number == block);
        if let (true, Ok(hash)) = (of_block, block_hash_of_evidence(&m.message)) {
            proposals.entry(hash).or_insert_with(|| m.clone());
        }
    };
    for m in log {
        let Some(c) = decode_consensus(m) else {
            continue;
        };
        let of_block = c
            .block_metadata
            .is_some_and(|meta| meta.block_number == block);
        match c.message {
            Some(Message::PrePrepare(_)) => propose(m),
            Some(Message::NewView(nv)) => nv.pre_prepares.iter().for_each(&mut propose),
            Some(Message::Commit(body)) if of_block => {
                commits
                    .entry((c.view_number, body.block_hash))
                    .or_default()
                    .entry(c.from)
                    .or_insert_with(|| m.clone());
            }
            _ => {}
        }
    }
    commits
        .into_iter()
        .rev()
        .find_map(|((_, hash), by_sender)| {
            let pre_prepare = proposals.get(&hash)?.clone();
            (by_sender.len() >= strong).then(|| bft::CommitCertificate {
                pre_prepare: Some(pre_prepare),
                commits: by_sender.into_values().take(strong).collect(),
            })
        })
}

fn epoch_of(signed: &bft::SignedMessage) -> Option<i64> {
    decode_consensus(signed)?
        .block_metadata
        .map(|m| m.epoch_number)
}

impl Sim {
    /// `n` honest nodes at the genesis epoch of `epoch_length` blocks, all up, on a network without faults.
    pub fn new(n: usize, epoch_length: i64, seed: u64) -> Self {
        let names: Vec<String> = (0..n).map(|i| format!("SEQ::n{i}")).collect();
        let info = EpochInfo {
            number: 0,
            start_block_number: 0,
            length: epoch_length,
        };
        let mut sim = Self {
            now_ms: 0,
            faults: Faults::NONE,
            rng: Rng::new(seed),
            nodes: (0..n).map(|_| None).collect(),
            saved: (0..n).map(|_| None).collect(),
            byzantine: BTreeSet::new(),
            tamper: BTreeMap::new(),
            logs: vec![BTreeMap::new(); n],
            logged: vec![BTreeSet::new(); n],
            in_flight: BTreeMap::new(),
            next_seq: 0,
            next_batch: 0,
            outputs: vec![BTreeMap::new(); n],
            decided: BTreeMap::new(),
            conflicts: Vec::new(),
            dropped: vec![Vec::new(); n],
            delivered: 0,
            names,
        };
        for i in 0..n {
            let mut node = ConsensusNode::new(
                &sim.names[i],
                &sim.names,
                info,
                sim.signer(i),
                keys_of(&sim.names),
                0,
            );
            node.set_view_change_timeout(VIEW_CHANGE_TIMEOUT_MS, 0);
            sim.nodes[i] = Some(node);
            sim.collect(i);
        }
        sim
    }

    pub fn name(&self, i: usize) -> &str {
        &self.names[i]
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    fn signer(&self, i: usize) -> Signer {
        Signer {
            key: sign_key(i),
            fingerprint: fingerprint(&self.names[i]),
        }
    }

    pub fn node(&self, i: usize) -> Option<&ConsensusNode> {
        self.nodes[i].as_ref()
    }

    pub fn honest(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.len()).filter(|i| !self.byzantine.contains(i))
    }

    /// `message` signed by node `signer` with its key, under the name and fingerprint of node `claimed`.
    pub fn sign_as(
        &self,
        signer: usize,
        claimed: usize,
        message: &bft::ConsensusMessage,
    ) -> bft::SignedMessage {
        let evidence = crate::consensus::consensus_evidence(message);
        let signature = sign_message(
            AuthenticatedMessageType::BftSignedConsensusMessage,
            &self.names[claimed],
            &evidence,
            &sign_key(signer),
            &fingerprint(&self.names[claimed]),
        )
        .expect("a message of the sizes a node makes");
        bft::SignedMessage {
            message: evidence,
            from: self.names[claimed].clone(),
            signature: Some(signature),
        }
    }

    pub fn set_tamper(&mut self, node: usize, tamper: Tamper) {
        self.byzantine.insert(node);
        self.tamper.insert(node, tamper);
    }

    /// The node stops: what is in flight to it is lost, it keeps its state file and the epoch and leader selection it was in.
    pub fn crash(&mut self, i: usize) {
        if let Some(node) = self.nodes[i].take() {
            self.saved[i] = Some(Saved {
                info: node.epoch().info,
                policy: node.policy_state().clone(),
            });
        }
    }

    /// The node starts again the way `Consensus::start_genesis_or_resume` resumes it: at the epoch it was in, with the commits of the epoch
    /// before's last block and that block's BFT time, and with what it signed and received put back (its votes before its proposals).
    pub fn restart(&mut self, i: usize) {
        let Some(saved) = self.saved[i].take() else {
            return;
        };
        let info = saved.info;
        let mut node = ConsensusNode::with_policy(
            &self.names[i],
            &self.names,
            info,
            self.signer(i),
            keys_of(&self.names),
            self.now_ms,
            Some(saved.policy),
        );
        node.set_view_change_timeout(VIEW_CHANGE_TIMEOUT_MS, self.now_ms);
        let strong = strong_quorum_size(self.len());
        let previous_commits: Vec<bft::SignedMessage> = {
            let mut by_view: BTreeMap<i64, Vec<bft::SignedMessage>> = BTreeMap::new();
            for m in self.logs[i].get(&(info.number - 1)).into_iter().flatten() {
                if let Some(c) = decode_consensus(m) {
                    let block = c.block_metadata.map(|b| b.block_number);
                    if block == Some(info.start_block_number - 1)
                        && matches!(c.message, Some(bft::consensus_message::Message::Commit(_)))
                    {
                        by_view.entry(c.view_number).or_default().push(m.clone());
                    }
                }
            }
            by_view
                .into_values()
                .rfind(|v| v.len() >= strong)
                .map(|v| v.into_iter().take(strong).collect())
                .unwrap_or_default()
        };
        let last_time = self.outputs[i]
            .get(&(info.start_block_number - 1))
            .map(|o| o.bft_time_micros);
        node.restore_epoch_boundary(previous_commits, last_time);
        let mut replay: Vec<bft::SignedMessage> = self.logs[i]
            .range(info.number..)
            .flat_map(|(_, ms)| ms.iter().cloned())
            .collect();
        replay.sort_by_key(|m| match decode_consensus(m).and_then(|c| c.message) {
            Some(bft::consensus_message::Message::Prepare(_)) => 0,
            Some(bft::consensus_message::Message::Commit(_)) => 1,
            Some(bft::consensus_message::Message::PrePrepare(_)) => 2,
            _ => 3,
        });
        let micros = self.micros();
        for m in replay {
            let _ = node.on_message(m, self.now_ms, micros);
        }
        self.nodes[i] = Some(node);
        self.collect(i);
    }

    fn micros(&self) -> i64 {
        self.now_ms as i64 * 1_000
    }

    fn log(&mut self, i: usize, m: &bft::SignedMessage) {
        let Some(epoch) = epoch_of(m) else { return };
        if self.logged[i].insert(m.message.clone()) {
            self.logs[i].entry(epoch).or_default().push(m.clone());
        }
    }

    /// Puts a message on the network from `from` to `to`, with the faults of the moment.
    pub fn post(&mut self, from: usize, to: usize, wire: Wire) {
        if self.rng.below(100) < self.faults.drop_pct {
            return;
        }
        let copies = 1 + u64::from(self.rng.below(100) < self.faults.dup_pct);
        for _ in 0..copies {
            let delay = 1 + self.rng.below(self.faults.max_delay_ms);
            self.next_seq += 1;
            let wire = match &wire {
                Wire::Consensus(m) => Wire::Consensus(m.clone()),
                Wire::Certificate(c) => Wire::Certificate(c.clone()),
            };
            self.in_flight
                .insert((self.now_ms + delay, self.next_seq), (from, to, wire));
        }
    }

    /// What a node sends goes to every other node (rewritten first when the node is a faulty one).
    fn broadcast(&mut self, from: usize, messages: Vec<bft::SignedMessage>) {
        for m in messages {
            let m = match self.tamper.get(&from).copied() {
                Some(tamper) => tamper(self, from, m),
                None => m,
            };
            self.log(from, &m);
            for to in 0..self.len() {
                if to != from {
                    self.post(from, to, Wire::Consensus(m.clone()));
                }
            }
        }
    }

    fn deliver(&mut self, to: usize, wire: Wire) {
        let (now, micros) = (self.now_ms, self.micros());
        let keys = &self.names;
        let Some(node) = self.nodes[to].as_mut() else {
            return;
        };
        self.delivered += 1;
        let out = match wire {
            Wire::Consensus(m) => {
                // the transport: the message is signed by the node it names (`verify_signed_message`)
                let sender = keys.iter().position(|n| *n == m.from);
                let verified = sender.zip(m.signature.as_ref()).is_some_and(|(s, sig)| {
                    verify_message_signature(
                        AuthenticatedMessageType::BftSignedConsensusMessage,
                        &m.from,
                        &m.message,
                        sig,
                        &crate::wire::test_key(&sign_key(s).verifying_key(), Some(&sig.signed_by)),
                    )
                    .is_ok()
                        && sig.signed_by == fingerprint(&m.from)
                });
                if !verified {
                    self.dropped[to].push(format!("the transport refused a message of {}", m.from));
                    return;
                }
                let out = node.on_message(m.clone(), now, micros);
                self.log(to, &m);
                out
            }
            Wire::Certificate(c) => match node.on_commit_certificate(c, now, micros) {
                Ok(out) => out,
                Err(why) => {
                    self.dropped[to].push(format!("a commit certificate refused: {why}"));
                    Vec::new()
                }
            },
        };
        self.collect(to);
        self.broadcast(to, out);
    }

    /// The node's events: outputs are checked against the node's earlier ones and the other honest nodes'.
    fn collect(&mut self, i: usize) {
        let Some(node) = self.nodes[i].as_mut() else {
            return;
        };
        for event in node.take_events() {
            match event {
                Event::BlockOutput {
                    epoch,
                    block,
                    bft_time_micros,
                    is_last_in_epoch,
                    batches,
                    original_leader,
                    proposal_view,
                    ..
                } => {
                    let output = Output {
                        epoch,
                        bft_time_micros,
                        batches: batches.into_iter().map(|b| b.id).collect(),
                        original_leader,
                        proposal_view,
                        is_last_in_epoch,
                    };
                    if self.byzantine.contains(&i) {
                        continue;
                    }
                    if let Some(before) = self.outputs[i].get(&block) {
                        if *before != output {
                            self.conflicts.push(format!(
                                "{} output block {block} as {output:?} after {before:?}",
                                self.names[i]
                            ));
                        }
                    }
                    match self.decided.get(&block) {
                        Some((other, first)) if *first != output => self.conflicts.push(format!(
                            "block {block}: {} has {output:?}, {} has {first:?}",
                            self.names[i], self.names[*other]
                        )),
                        Some(_) => {}
                        None => {
                            self.decided.insert(block, (i, output.clone()));
                        }
                    }
                    self.outputs[i].insert(block, output);
                }
                Event::Dropped(why) => self.dropped[i].push(why),
                _ => {}
            }
        }
    }

    /// Every node re-sends to each live peer what it has of the peer's epoch for the blocks the peer has not ordered (`RetransmissionsManager`):
    /// the commit certificate of a block it has ordered itself, otherwise the messages it has of the block's segment.
    fn retransmit(&mut self) {
        let strong = strong_quorum_size(self.len());
        let mut resend = Vec::new();
        for to in 0..self.len() {
            let Some(receiver) = self.nodes[to].as_ref() else {
                continue;
            };
            let epoch = receiver.epoch().clone();
            let missing: BTreeSet<i64> = (epoch.info.start_block_number
                ..=epoch.info.last_block_number())
                .filter(|b| !receiver.is_ordered(*b))
                .collect();
            for from in (0..self.len()).filter(|from| *from != to) {
                let Some(sender) = self.nodes[from].as_ref() else {
                    continue;
                };
                let log = self.logs[from]
                    .get(&epoch.info.number)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let ahead = sender.epoch_number() > epoch.info.number;
                let mut uncertified = missing.clone();
                for &block in &missing {
                    if !(ahead || sender.is_ordered(block)) {
                        continue;
                    }
                    if let Some(cert) = certificate_in(log, block, strong) {
                        uncertified.remove(&block);
                        resend.push((from, to, Wire::Certificate(cert)));
                    }
                }
                for m in log {
                    let Some(meta) = decode_consensus(m).and_then(|c| c.block_metadata) else {
                        continue;
                    };
                    let wanted = epoch
                        .segments
                        .iter()
                        .find(|s| s.slots.contains(&meta.block_number))
                        .is_some_and(|s| s.slots.iter().any(|b| uncertified.contains(b)));
                    if wanted {
                        resend.push((from, to, Wire::Consensus(m.clone())));
                    }
                }
            }
        }
        for (from, to, wire) in resend {
            self.post(from, to, wire);
        }
    }

    /// A batch stored and acked by every node, valid from the node's epoch (an `AvailabilityModule` proof of availability).
    pub fn proof(&mut self, epoch: i64) -> bft::ProofOfAvailability {
        use ed25519_dalek::Signer as _;
        self.next_batch += 1;
        let id = batch_id(
            &[Request {
                tag: "send".into(),
                payload: self.next_batch.to_be_bytes().to_vec(),
            }],
            epoch,
            37,
        )
        .expect("a batch id");
        let acks = (0..self.len())
            .map(|i| {
                let digest = ack_hash(&id, epoch, &self.names[i]).expect("an ack hash");
                bft::AvailabilityAck {
                    from: self.names[i].clone(),
                    signature: Some(crate::wire::test_signature(
                        sign_key(i)
                            .sign(&crate::wire::bytes_to_sign(&digest))
                            .to_bytes()
                            .to_vec(),
                        &fingerprint(&self.names[i]),
                    )),
                }
            })
            .collect();
        bft::ProofOfAvailability {
            batch_id: id.0,
            acks,
            epoch_number: epoch,
        }
    }

    fn offer_batches(&mut self) {
        for i in 0..self.len() {
            let Some(epoch) = self.nodes[i].as_ref().map(ConsensusNode::epoch_number) else {
                continue;
            };
            let proof = self.proof(epoch);
            if let Some(node) = self.nodes[i].as_mut() {
                node.queue_proof(proof);
            }
        }
    }

    /// Moves the clock by `ms`, a step at a time: what is due arrives, every live node ticks, and now and then nodes retransmit and get batches.
    pub fn run_for(&mut self, ms: u64) {
        self.run_with(ms, |_| {});
    }

    /// The same, with `each_step` called at every step (a scenario's faulty node acts there).
    pub fn run_with(&mut self, ms: u64, mut each_step: impl FnMut(&mut Sim)) {
        let end = self.now_ms + ms;
        while self.now_ms < end {
            self.now_ms += TICK_MS;
            while let Some(entry) = self.in_flight.first_entry() {
                if entry.key().0 > self.now_ms {
                    break;
                }
                let (_, to, wire) = entry.remove();
                self.deliver(to, wire);
            }
            let (now, micros) = (self.now_ms, self.micros());
            for i in 0..self.len() {
                let Some(node) = self.nodes[i].as_mut() else {
                    continue;
                };
                let out = node.tick(now, micros);
                self.collect(i);
                self.broadcast(i, out);
            }
            if self.now_ms.is_multiple_of(RETRANSMIT_MS) {
                self.retransmit();
            }
            if self.now_ms.is_multiple_of(BATCH_MS) {
                self.offer_batches();
            }
            each_step(self);
        }
    }

    /// The highest block a node output, if any.
    pub fn last_output(&self, i: usize) -> Option<i64> {
        self.outputs[i].keys().next_back().copied()
    }

    /// Whether some honest node dropped something for a reason that contains `text`.
    pub fn some_honest_dropped(&self, text: &str) -> bool {
        self.honest()
            .any(|i| self.dropped[i].iter().any(|why| why.contains(text)))
    }

    /// A digest of the run: who output what, and how many messages arrived (two runs of one seed have the same).
    pub fn fingerprint_of_run(&self) -> (Vec<BTreeMap<i64, Output>>, u64) {
        (self.outputs.clone(), self.delivered)
    }
}

#[path = "testing_scenarios.rs"]
mod scenarios;
