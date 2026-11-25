//! One ordering node: a synchronous PBFT state machine. It does no I/O and has no clock: the caller hands it messages (`handle`), time
//! (`tick`) and requests (`submit`) and sends what it returns.
//!
//! [CANTON-NOTE: SEMANTICS] The protocol, in one slot at a time (a slot is a block of requests; the next slot is proposed once the one
//! before is committed, so a proposal names the block it follows):
//! 1. The **leader** of the view signs a `PrePrepare` (slot, chain hash of the block before, requests) and sends it to all.
//! 2. A **backup** that accepts it (right leader, right view, next slot, extends its chain) signs a `Prepare` for it. **Prepared** is a
//!    proposal with `2f` backups' `Prepare`s.
//! 3. A node that has a prepared proposal signs a `Commit`. **Committed** is a proposal with `2f + 1` `Commit`s: it is appended to the log
//!    with that certificate, and the chain hash moves on.
//! 4. A node whose requests do not get committed in time sends a **`ViewChange`** for the next view with its last committed block and its
//!    prepared proposal (each with its proof). `2f + 1` of them let the next leader send a **`NewView`**: from the proofs it takes the
//!    longest committed head and the highest prepared proposal for the slot after it and proposes that one again. Every node checks the
//!    leader's choice against the proofs itself.
//! 5. A node that is behind asks for blocks (`StateRequest`) and believes only a block with a valid certificate that extends its chain.
//!
//! [CANTON-NOTE: INVARIANT] A node that sent a `ViewChange` for view `w` takes no part in any view below `w` until a `NewView` for `w` or later
//! (the proofs a new leader collects say what the senders have prepared; a node that prepared more afterwards would make them stale).
//! That promise is part of the durable state (`Durable::vc_target`).
//!
//! [CANTON-NOTE: LIMITATION] A node that was cut off, escalated its view change target alone and rejoins finds the others in a lower view:
//! it takes no part (it only catches up on blocks) until the next view change brings it in. The cluster does not need it while `2f + 1` nodes
//! are up. One slot is in flight at a time (no pipelining), and the log is never truncated.
use crate::crypto::{request_id, Hash};
use crate::types::{
    verify_committed_block, verify_view_change, Commit, CommittedBlock, Config, Msg, NewView,
    NodeId, PrePrepare, Prepare, PreparedCert, Reject, Seq, Signed, View, ViewChange,
};
use ed25519_dalek::SigningKey;
use std::collections::{BTreeMap, BTreeSet};

/// What a node asks its caller to send.
#[derive(Clone, Debug)]
pub enum Out {
    Send {
        to: NodeId,
        msg: Msg,
    },
    /// To every other node.
    Broadcast(Msg),
}

/// What happened, for tests and operators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Committed(Seq),
    ViewChangeStarted(View),
    EnteredView(View),
    /// A message or certificate was refused.
    Rejected {
        why: Reject,
        what: &'static str,
    },
    /// The leader of a view sent two different proposals for one slot.
    Equivocation {
        view: View,
        seq: Seq,
    },
    /// Two valid certificates for different blocks in one slot: more than `f` nodes are faulty. The new block is not taken.
    Fork {
        seq: Seq,
    },
}

/// What a node must keep to come back after a crash.
#[derive(Clone)]
pub struct Durable {
    pub log: Vec<CommittedBlock>,
    pub view: View,
    pub vc_target: Option<View>,
}

struct Slot {
    pp: Signed<PrePrepare>,
    digest: Hash,
    prepares: BTreeMap<NodeId, Signed<Prepare>>,
    commits: BTreeMap<NodeId, Signed<Commit>>,
    sent_commit: bool,
}

/// How far the future may be buffered (messages for a view or slot not reached yet).
const FUTURE_LIMIT: usize = 2000;
/// How many blocks one `StateResponse` carries.
const STATE_BATCH: usize = 50;
/// How many requests one block carries at most.
const BATCH_LIMIT: usize = 100;

pub struct BftNode {
    id: NodeId,
    cfg: Config,
    key: SigningKey,
    view: View,
    vc_target: Option<View>,
    log: Vec<CommittedBlock>,
    head: Hash,
    pending: Vec<Vec<u8>>,
    ordered: BTreeSet<Hash>,
    slot: Option<Slot>,
    future: Vec<(NodeId, Msg)>,
    vcs: BTreeMap<View, BTreeMap<NodeId, Signed<ViewChange>>>,
    vc_targets: BTreeMap<NodeId, View>,
    own_vc: Option<Signed<ViewChange>>,
    new_view_sent: BTreeSet<View>,
    awaiting_new_view: Option<Signed<NewView>>,
    state_requested_at: BTreeMap<NodeId, u64>,
    ticks: u64,
    idle: u64,
    timeout: u64,
    base_timeout: u64,
    status_every: u64,
    events: Vec<Event>,
}

/// What a `NewView` has to say, recomputed from its view changes by the leader that makes it and by every node that checks it.
struct Plan {
    base_seq: Seq,
    base_hash: Hash,
    /// A node whose view change has the base head (where to fetch the blocks from).
    source: NodeId,
    /// The proposal that has to be made again: its requests (the slot is `base_seq + 1`, it follows `base_hash`).
    requests: Option<Vec<Vec<u8>>>,
}

fn plan(view_changes: &[Signed<ViewChange>]) -> Plan {
    let best = view_changes
        .iter()
        .max_by_key(|v| (v.body.head_seq, std::cmp::Reverse(v.from)))
        .expect("a new view has view changes");
    let (base_seq, base_hash) = (best.body.head_seq, best.body.head_hash);
    // only a proposal for the slot after the base can matter; the highest view wins
    let requests = view_changes
        .iter()
        .filter(|v| v.body.head_seq == base_seq)
        .filter_map(|v| v.body.prepared.as_ref())
        .max_by_key(|c| c.pre_prepare.body.view)
        .map(|c| c.pre_prepare.body.requests.clone());
    Plan {
        base_seq,
        base_hash,
        source: best.from,
        requests,
    }
}

impl BftNode {
    pub fn new(id: NodeId, cfg: Config, key: SigningKey) -> Self {
        Self::recover(
            id,
            cfg,
            key,
            Durable {
                log: Vec::new(),
                view: 0,
                vc_target: None,
            },
        )
    }

    /// A node that comes back with what it had kept.
    pub fn recover(id: NodeId, cfg: Config, key: SigningKey, durable: Durable) -> Self {
        let mut head = [0u8; 32];
        let mut ordered = BTreeSet::new();
        for b in &durable.log {
            head = crate::crypto::entry_hash(&head, b.seq(), &b.pre_prepare.body.digest());
            for r in &b.pre_prepare.body.requests {
                ordered.insert(request_id(r));
            }
        }
        Self {
            id,
            cfg,
            key,
            view: durable.view,
            vc_target: durable.vc_target,
            log: durable.log,
            head,
            pending: Vec::new(),
            ordered,
            slot: None,
            future: Vec::new(),
            vcs: BTreeMap::new(),
            vc_targets: BTreeMap::new(),
            own_vc: None,
            new_view_sent: BTreeSet::new(),
            awaiting_new_view: None,
            state_requested_at: BTreeMap::new(),
            ticks: 0,
            idle: 0,
            timeout: 12,
            base_timeout: 12,
            status_every: 6,
            events: Vec::new(),
        }
    }

    pub fn durable(&self) -> Durable {
        Durable {
            log: self.log.clone(),
            view: self.view,
            vc_target: self.vc_target,
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }
    pub fn view(&self) -> View {
        self.view
    }
    pub fn in_view_change(&self) -> bool {
        self.vc_target.is_some()
    }
    pub fn log(&self) -> &[CommittedBlock] {
        &self.log
    }
    pub fn head_seq(&self) -> Seq {
        self.log.len() as Seq
    }
    pub fn head_hash(&self) -> Hash {
        self.head
    }
    pub fn pending_requests(&self) -> usize {
        self.pending.len()
    }
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// The requests in the order they were committed.
    pub fn ordered_requests(&self) -> Vec<Vec<u8>> {
        self.log
            .iter()
            .flat_map(|b| b.pre_prepare.body.requests.iter().cloned())
            .collect()
    }

    fn is_leader(&self) -> bool {
        self.cfg.leader(self.view) == self.id && self.vc_target.is_none()
    }

    fn reject(&mut self, why: Reject, what: &'static str) {
        self.events.push(Event::Rejected { why, what });
    }

    // ------------------------------------------------------------------ inputs

    /// A request from a client.
    pub fn submit(&mut self, request: Vec<u8>) -> Vec<Out> {
        let mut out = Vec::new();
        self.on_request(request, &mut out);
        out
    }

    /// One tick of the clock: timers, status hints, the leader's proposal.
    pub fn tick(&mut self) -> Vec<Out> {
        let mut out = Vec::new();
        self.ticks += 1;
        if self.ticks.is_multiple_of(self.status_every) {
            out.push(Out::Broadcast(Msg::Status {
                head_seq: self.head_seq(),
            }));
            // a view change that nobody answered is said again (a node that was cut off hears it when it comes back)
            if let Some(vc) = &self.own_vc {
                if self.vc_target == Some(vc.body.new_view) {
                    out.push(Out::Broadcast(Msg::ViewChange(vc.clone())));
                }
            }
        }
        if self.is_leader() && self.slot.is_none() {
            self.propose(&mut out);
        }
        // [CANTON-NOTE: SEMANTICS] a request a follower holds is said to the leader again now and then: the leader it first told may be
        // gone (a view change) or may never have heard (a lost message). The leader ignores a request it already holds.
        if self.ticks.is_multiple_of(self.status_every)
            && self.vc_target.is_none()
            && !self.is_leader()
        {
            self.forward_pending(&mut out);
        }
        if !self.pending.is_empty() || self.vc_target.is_some() {
            self.idle += 1;
        } else {
            self.idle = 0;
        }
        if self.idle >= self.timeout {
            self.idle = 0;
            self.timeout = (self.timeout * 2).min(self.base_timeout * 64);
            let target = self.vc_target.map_or(self.view + 1, |t| t + 1);
            self.start_view_change(target, &mut out);
        }
        out
    }

    /// A message from the network. `from` is who delivered it; what a signed message says about its sender is checked from the signature.
    pub fn handle(&mut self, from: NodeId, msg: Msg) -> Vec<Out> {
        let mut out = Vec::new();
        self.on_message(from, msg, &mut out);
        out
    }

    fn on_message(&mut self, from: NodeId, msg: Msg, out: &mut Vec<Out>) {
        match msg {
            Msg::Request(r) => self.on_request(r, out),
            Msg::PrePrepare(s) => self.on_pre_prepare(s, out),
            Msg::Prepare(s) => self.on_prepare(s, out),
            Msg::Commit(s) => self.on_commit(s, out),
            Msg::ViewChange(s) => self.on_view_change(s, out),
            Msg::NewView(s) => self.on_new_view(s, out),
            Msg::Status { head_seq } => {
                if head_seq > self.head_seq() {
                    self.request_state(from, out);
                }
            }
            Msg::StateRequest { from_seq } => self.on_state_request(from, from_seq, out),
            Msg::StateResponse(blocks) => self.on_state_response(blocks, out),
        }
    }

    // --------------------------------------------------------------- requests

    fn on_request(&mut self, request: Vec<u8>, out: &mut Vec<Out>) {
        let id = request_id(&request);
        if self.ordered.contains(&id) || self.pending.contains(&request) {
            return;
        }
        self.pending.push(request.clone());
        if self.vc_target.is_some() {
            return;
        }
        if self.is_leader() {
            if self.slot.is_none() {
                self.propose(out);
            }
        } else {
            out.push(Out::Send {
                to: self.cfg.leader(self.view),
                msg: Msg::Request(request),
            });
        }
    }

    fn forward_pending(&self, out: &mut Vec<Out>) {
        let leader = self.cfg.leader(self.view);
        for r in &self.pending {
            out.push(Out::Send {
                to: leader,
                msg: Msg::Request(r.clone()),
            });
        }
    }

    fn propose(&mut self, out: &mut Vec<Out>) {
        if !self.is_leader() || self.slot.is_some() || self.pending.is_empty() {
            return;
        }
        let requests: Vec<Vec<u8>> = self.pending.iter().take(BATCH_LIMIT).cloned().collect();
        let pp = Signed::sign(
            PrePrepare {
                view: self.view,
                seq: self.head_seq() + 1,
                prev: self.head,
                requests,
            },
            self.id,
            &self.key,
        );
        self.slot = Some(Slot::new(pp.clone()));
        out.push(Out::Broadcast(Msg::PrePrepare(pp)));
        self.advance(out);
    }

    // ----------------------------------------------------------- normal case

    fn defer(&mut self, from: NodeId, msg: Msg) {
        if self.future.len() >= FUTURE_LIMIT {
            self.future.remove(0);
        }
        self.future.push((from, msg));
    }

    fn replay_future(&mut self, out: &mut Vec<Out>) {
        let again = std::mem::take(&mut self.future);
        for (from, msg) in again {
            self.on_message(from, msg, out);
        }
    }

    fn on_pre_prepare(&mut self, s: Signed<PrePrepare>, out: &mut Vec<Out>) {
        if !s.verifies(&self.cfg) {
            return self.reject(Reject::BadSignature, "pre-prepare");
        }
        let pp = &s.body;
        if s.from != self.cfg.leader(pp.view) {
            return self.reject(Reject::WrongLeader, "pre-prepare");
        }
        if pp.view < self.view || self.vc_target.is_some() && pp.view <= self.view {
            return;
        }
        if pp.view > self.view {
            return self.defer(s.from, Msg::PrePrepare(s));
        }
        let next = self.head_seq() + 1;
        if pp.seq > next {
            let leader = s.from;
            self.request_state(leader, out);
            return self.defer(s.from, Msg::PrePrepare(s));
        }
        if pp.seq < next {
            return;
        }
        if pp.prev != self.head {
            return self.reject(Reject::ChainMismatch, "pre-prepare");
        }
        if let Some(slot) = &self.slot {
            if slot.pp.body.view == pp.view {
                if slot.digest != pp.digest() {
                    self.events.push(Event::Equivocation {
                        view: pp.view,
                        seq: pp.seq,
                    });
                }
                return;
            }
        }
        let mut slot = Slot::new(s.clone());
        if self.id != self.cfg.leader(pp.view) {
            let prepare = Signed::sign(
                Prepare {
                    view: pp.view,
                    seq: pp.seq,
                    digest: slot.digest,
                },
                self.id,
                &self.key,
            );
            slot.prepares.insert(self.id, prepare.clone());
            out.push(Out::Broadcast(Msg::Prepare(prepare)));
        }
        self.slot = Some(slot);
        self.replay_future(out);
        self.advance(out);
    }

    /// The checks a vote shares: signed, for the current view and the next slot (else kept for later or dropped).
    fn vote_is_current(
        &mut self,
        view: View,
        seq: Seq,
        from: NodeId,
        msg: &Msg,
        out: &mut Vec<Out>,
    ) -> bool {
        if view < self.view || self.vc_target.is_some() && view <= self.view {
            return false;
        }
        if view > self.view {
            self.defer(from, msg.clone());
            return false;
        }
        let next = self.head_seq() + 1;
        if seq > next {
            self.request_state(from, out);
            self.defer(from, msg.clone());
            return false;
        }
        if seq < next {
            return false;
        }
        if self.slot.is_none() {
            self.defer(from, msg.clone());
            return false;
        }
        true
    }

    fn on_prepare(&mut self, s: Signed<Prepare>, out: &mut Vec<Out>) {
        if !s.verifies(&self.cfg) {
            return self.reject(Reject::BadSignature, "prepare");
        }
        let (view, seq, from) = (s.body.view, s.body.seq, s.from);
        if !self.vote_is_current(view, seq, from, &Msg::Prepare(s.clone()), out) {
            return;
        }
        let leader = self.cfg.leader(view);
        let slot = self.slot.as_mut().expect("checked");
        // a vote for another proposal is no vote for this one; the leader's proposal is its vote, so its Prepare counts for nothing
        if s.body.digest != slot.digest || from == leader {
            return;
        }
        slot.prepares.entry(from).or_insert(s);
        self.advance(out);
    }

    fn on_commit(&mut self, s: Signed<Commit>, out: &mut Vec<Out>) {
        if !s.verifies(&self.cfg) {
            return self.reject(Reject::BadSignature, "commit");
        }
        let (view, seq, from) = (s.body.view, s.body.seq, s.from);
        if !self.vote_is_current(view, seq, from, &Msg::Commit(s.clone()), out) {
            return;
        }
        let slot = self.slot.as_mut().expect("checked");
        if s.body.digest != slot.digest {
            return;
        }
        slot.commits.entry(from).or_insert(s);
        self.advance(out);
    }

    /// Moves the slot as far as its votes allow: prepared, then (this node's own commit) and committed.
    fn advance(&mut self, out: &mut Vec<Out>) {
        loop {
            let Some(slot) = self.slot.as_mut() else {
                return;
            };
            let (view, seq) = (slot.pp.body.view, slot.pp.body.seq);
            if !slot.sent_commit && slot.prepares.len() >= 2 * self.cfg.f {
                slot.sent_commit = true;
                let commit = Signed::sign(
                    Commit {
                        view,
                        seq,
                        digest: slot.digest,
                    },
                    self.id,
                    &self.key,
                );
                slot.commits.insert(self.id, commit.clone());
                out.push(Out::Broadcast(Msg::Commit(commit)));
            }
            // [CANTON-NOTE: SEMANTICS] 2f + 1 commits settle the slot even before this node saw its own proposal prepared: they are the
            // certificate a state transfer would hand out, and a node that holds one is as sure as one that was sent it.
            if slot.commits.len() >= self.cfg.quorum() {
                let block = CommittedBlock {
                    pre_prepare: slot.pp.clone(),
                    commits: slot.commits.values().cloned().collect(),
                };
                self.slot = None;
                self.append(block);
                self.propose(out);
                self.replay_future(out);
                continue;
            }
            return;
        }
    }

    fn append(&mut self, block: CommittedBlock) {
        let seq = block.seq();
        self.head = crate::crypto::entry_hash(&self.head, seq, &block.pre_prepare.body.digest());
        for r in &block.pre_prepare.body.requests {
            self.ordered.insert(request_id(r));
        }
        self.pending
            .retain(|r| !self.ordered.contains(&request_id(r)));
        self.log.push(block);
        self.idle = 0;
        self.timeout = self.base_timeout;
        self.events.push(Event::Committed(seq));
    }

    // ------------------------------------------------------------ view change

    fn start_view_change(&mut self, target: View, out: &mut Vec<Out>) {
        if self.vc_target.is_some_and(|t| t >= target) || target <= self.view {
            return;
        }
        self.vc_target = Some(target);
        let prepared = self.slot.as_ref().and_then(|s| {
            (s.prepares.len() >= 2 * self.cfg.f).then(|| PreparedCert {
                pre_prepare: s.pp.clone(),
                prepares: s.prepares.values().take(2 * self.cfg.f).cloned().collect(),
            })
        });
        let vc = Signed::sign(
            ViewChange {
                new_view: target,
                head_seq: self.head_seq(),
                head_hash: self.head,
                head_proof: self.log.last().cloned().map(Box::new),
                prepared,
            },
            self.id,
            &self.key,
        );
        self.vcs
            .entry(target)
            .or_default()
            .insert(self.id, vc.clone());
        self.vc_targets.insert(self.id, target);
        self.own_vc = Some(vc.clone());
        self.events.push(Event::ViewChangeStarted(target));
        out.push(Out::Broadcast(Msg::ViewChange(vc)));
        self.try_new_view(target, out);
    }

    fn on_view_change(&mut self, s: Signed<ViewChange>, out: &mut Vec<Out>) {
        if let Err(why) = verify_view_change(&self.cfg, &s) {
            return self.reject(why, "view change");
        }
        let w = s.body.new_view;
        if w <= self.view {
            return;
        }
        let from = s.from;
        if s.body.head_seq > self.head_seq() {
            self.request_state(from, out);
        }
        let known = self.vc_targets.entry(from).or_insert(0);
        *known = (*known).max(w);
        self.vcs.entry(w).or_default().insert(from, s);
        // f + 1 nodes that want a higher view than this node is waiting for include an honest one: join the lowest of the highest f + 1
        let current = self.vc_target.unwrap_or(self.view);
        let mut higher: Vec<View> = self
            .vc_targets
            .iter()
            .filter(|(id, t)| **id != self.id && **t > current)
            .map(|(_, t)| *t)
            .collect();
        higher.sort_unstable_by(|a, b| b.cmp(a));
        if higher.len() > self.cfg.f {
            self.start_view_change(higher[self.cfg.f], out);
        }
        self.try_new_view(w, out);
    }

    /// The leader of `w` that has `2f + 1` view changes for it makes the new view.
    fn try_new_view(&mut self, w: View, out: &mut Vec<Out>) {
        if self.cfg.leader(w) != self.id
            || self.new_view_sent.contains(&w)
            || self.vc_target != Some(w)
        {
            return;
        }
        let Some(have) = self.vcs.get(&w) else {
            return;
        };
        if have.len() < self.cfg.quorum() {
            return;
        }
        let chosen: Vec<Signed<ViewChange>> =
            have.values().take(self.cfg.quorum()).cloned().collect();
        let p = plan(&chosen);
        if self.head_seq() < p.base_seq {
            // the leader has to know the blocks the view changes commit before it can propose on top of them
            self.request_state(p.source, out);
            return;
        }
        let reproposal = p.requests.map(|requests| {
            Signed::sign(
                PrePrepare {
                    view: w,
                    seq: p.base_seq + 1,
                    prev: p.base_hash,
                    requests,
                },
                self.id,
                &self.key,
            )
        });
        let nv = Signed::sign(
            NewView {
                view: w,
                view_changes: chosen,
                reproposal,
            },
            self.id,
            &self.key,
        );
        self.new_view_sent.insert(w);
        out.push(Out::Broadcast(Msg::NewView(nv.clone())));
        self.install_new_view(nv, out);
    }

    fn on_new_view(&mut self, s: Signed<NewView>, out: &mut Vec<Out>) {
        if !s.verifies(&self.cfg) {
            return self.reject(Reject::BadSignature, "new view");
        }
        let w = s.body.view;
        if s.from != self.cfg.leader(w) {
            return self.reject(Reject::WrongLeader, "new view");
        }
        if w <= self.view || self.vc_target.is_some_and(|t| w < t) {
            return;
        }
        // 2f + 1 distinct view changes for this view, each with valid proofs
        let mut senders = BTreeSet::new();
        for vc in &s.body.view_changes {
            if vc.body.new_view != w {
                return self.reject(Reject::WrongView, "new view");
            }
            if let Err(why) = verify_view_change(&self.cfg, vc) {
                return self.reject(why, "new view");
            }
            if !senders.insert(vc.from) {
                return self.reject(Reject::DuplicateVoter, "new view");
            }
        }
        if senders.len() < self.cfg.quorum() {
            return self.reject(Reject::NotEnoughVotes(senders.len()), "new view");
        }
        // the leader's choice is checked against the proofs: the same base and the proposal that has to be made again
        let p = plan(&s.body.view_changes);
        let ok = match (&s.body.reproposal, &p.requests) {
            (None, None) => true,
            (Some(pp), Some(requests)) => {
                pp.verifies(&self.cfg)
                    && pp.from == s.from
                    && pp.body.view == w
                    && pp.body.seq == p.base_seq + 1
                    && pp.body.prev == p.base_hash
                    && pp.body.requests == *requests
            }
            _ => false,
        };
        if !ok {
            return self.reject(
                Reject::Malformed("the new view does not follow from its view changes"),
                "new view",
            );
        }
        if self.head_seq() < p.base_seq {
            self.awaiting_new_view = Some(s);
            self.request_state(p.source, out);
            return;
        }
        self.install_new_view(s, out);
    }

    fn install_new_view(&mut self, nv: Signed<NewView>, out: &mut Vec<Out>) {
        let w = nv.body.view;
        self.view = w;
        self.vc_target = None;
        self.slot = None;
        self.vcs.retain(|v, _| *v > w);
        self.vc_targets.retain(|_, t| *t > w);
        self.awaiting_new_view = None;
        self.timeout = self.base_timeout;
        self.idle = 0;
        self.events.push(Event::EnteredView(w));
        if let Some(pp) = nv.body.reproposal {
            self.on_pre_prepare(pp, out);
        }
        if self.is_leader() && self.slot.is_none() {
            self.propose(out);
        } else if !self.is_leader() {
            self.forward_pending(out);
        }
        self.replay_future(out);
    }

    // ---------------------------------------------------------- state transfer

    fn request_state(&mut self, to: NodeId, out: &mut Vec<Out>) {
        if to == self.id || to >= self.cfg.n {
            return;
        }
        if self
            .state_requested_at
            .get(&to)
            .is_some_and(|t| self.ticks < t + 3)
        {
            return;
        }
        self.state_requested_at.insert(to, self.ticks);
        out.push(Out::Send {
            to,
            msg: Msg::StateRequest {
                from_seq: self.head_seq() + 1,
            },
        });
    }

    fn on_state_request(&mut self, from: NodeId, from_seq: Seq, out: &mut Vec<Out>) {
        if from >= self.cfg.n || from_seq == 0 || from_seq > self.head_seq() {
            return;
        }
        let blocks: Vec<CommittedBlock> = self.log[(from_seq - 1) as usize..]
            .iter()
            .take(STATE_BATCH)
            .cloned()
            .collect();
        out.push(Out::Send {
            to: from,
            msg: Msg::StateResponse(blocks),
        });
    }

    /// Takes blocks a peer sent. [CANTON-NOTE: SEMANTICS] A block is believed only with its certificate and only on top of this node's own
    /// chain: a block for a slot already committed here is compared (a different one with a valid certificate is a fork, reported and not
    /// taken; a stale or identical one is ignored), a block that leaves a gap or does not extend the chain ends the response.
    fn on_state_response(&mut self, blocks: Vec<CommittedBlock>, out: &mut Vec<Out>) {
        let mut applied = false;
        for b in blocks {
            let seq = b.seq();
            if seq <= self.head_seq() {
                let ours = &self.log[(seq - 1) as usize];
                if ours.pre_prepare.body.digest() != b.pre_prepare.body.digest() {
                    let prev = b.pre_prepare.body.prev;
                    if verify_committed_block(&self.cfg, &b, &prev).is_ok() {
                        self.events.push(Event::Fork { seq });
                    } else {
                        self.reject(Reject::Malformed("a different block for a committed slot, without a valid certificate"), "state transfer");
                    }
                }
                continue;
            }
            if seq != self.head_seq() + 1 {
                self.reject(Reject::WrongSlot, "state transfer");
                break;
            }
            match verify_committed_block(&self.cfg, &b, &self.head) {
                Ok(_) => {
                    self.append(b);
                    applied = true;
                }
                Err(why) => {
                    self.reject(why, "state transfer");
                    break;
                }
            }
        }
        if !applied {
            return;
        }
        if self
            .slot
            .as_ref()
            .is_some_and(|s| s.pp.body.seq <= self.head_seq())
        {
            self.slot = None;
        }
        if let Some(nv) = self.awaiting_new_view.take() {
            self.on_new_view(nv, out);
        }
        if let Some(t) = self.vc_target {
            self.try_new_view(t, out);
        }
        self.propose(out);
        self.replay_future(out);
    }
}

impl Slot {
    fn new(pp: Signed<PrePrepare>) -> Self {
        let digest = pp.body.digest();
        Self {
            pp,
            digest,
            prepares: BTreeMap::new(),
            commits: BTreeMap::new(),
            sent_commit: false,
        }
    }
}
