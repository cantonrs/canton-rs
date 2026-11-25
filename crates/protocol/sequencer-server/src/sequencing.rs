//! Sequencing: a member sends a submission request, the sequencer gives it a timestamp and delivers it to its recipients as signed events,
//! and a subscriber reads the events addressed to it (`SendAsync` and `Subscribe`).
//!
//! [CANTON-NOTE: SEMANTICS] Read from the official sequencer's events as the Rust participant decodes them (S-NET-004) and the Canton source:
//! - An event is a **v32 `SequencedEvent`** (versioned 32) in a **`SignedContent`** (versioned 30) signed by the sequencer's signing key over
//!   the multihash of hash purpose 1 (`SequencedEventSignature`).
//! - Every event gets **one timestamp from one clock** that never goes back; each member sees only the events addressed to it, and an
//!   event's `previous_timestamp` is the timestamp of the **previous event of that member** (`None` for the first): the chain a subscriber
//!   checks to know it missed nothing.
//! - The **sender** always receives an event for its submission, carrying its `message_id` (a receipt): with the envelopes addressed to it if
//!   any, with an empty batch if not (that is how a participant asks for the time: a request with an empty batch is a **time proof**). A
//!   subscriber's `timestamp` is **inclusive**.
//! - A submission is checked twice (see [`crate::submission_validator`]): by `SendAsync` before it answers, and once the submission has
//!   its sequencing time, at that time; the second check decides whether it is delivered, answered with an error event, or dropped.
//!
//! [CANTON-NOTE: LIMITATION] Topology timestamps are not handled (an event's `topology_timestamp` is always empty). The events are kept in
//! memory and, once a journal is attached, written to it before the call is answered ([`crate::persistence`]).
use crate::onboarding::{Registered, Registry};
use crate::synchronizer_state::SynchronizerKeys;
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::{RecipientsTree, SignedContent};
use prost::Message;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tonic::Status;

pub use crate::submission::{may_change_ordering_topology, read_submission, submission_priority};
pub use pruning::MediatorPruneRefused;

mod compaction;
mod pruning;
mod submit;
mod subscription;
mod traffic_control;
pub mod traffic_purchase;

/// One envelope of a stored event: the content and its signatures (the recipients are the member the event is stored for).
#[derive(Clone)]
pub(crate) struct StoredEnvelope {
    /// Flattened groups the receiver may see (compatibility summary and mediator/journal consumers).
    pub(crate) recipients: Vec<Vec<String>>,
    /// Preserved hierarchical recipient trees for this member (`RecipientsTree.forMember`). When non-empty, delivery serializes these verbatim.
    pub(crate) recipient_trees: Vec<RecipientsTree>,
    pub(crate) content: Vec<u8>,
    pub(crate) signatures: Vec<Signature>,
}

#[derive(Clone)]
pub(crate) struct StoredEvent {
    pub(crate) timestamp: i64,
    pub(crate) previous: Option<i64>,
    pub(crate) message_id: Option<String>,
    pub(crate) envelopes: Vec<StoredEnvelope>,
    /// A rejection instead of a delivery: `(gRPC code, message)`.
    pub(crate) error: Option<(i32, String)>,
    /// The details of the error status (`google.protobuf.Any`: type url and value): the official nodes put an `ErrorInfo` in them.
    pub(crate) error_details: Vec<(String, Vec<u8>)>,
    /// What the sender spent on it while traffic control is on: `(cost, extra traffic consumed, base traffic remaining)` after it.
    pub(crate) receipt: Option<(u64, u64, u64)>,
}

struct Inner {
    /// One mediator for each mediator group, by group index.
    mediators: Vec<crate::mediator::Mediator>,
    physical_synchronizer_id: String,
    keys: Arc<SynchronizerKeys>,
    registry: Arc<Registry>,
    events: Mutex<BTreeMap<String, Vec<StoredEvent>>>,
    /// Where every stored event is journaled (attached once the journal has been replayed).
    journal: std::sync::OnceLock<Arc<crate::persistence::Journal>>,
    /// The ordering cluster that decides the order, when the sequencer runs in BFT mode.
    ordering: std::sync::OnceLock<Arc<crate::ordering::BftOrdering>>,
    /// The latest acknowledgement of each member: events up to it are not read again and may be forgotten.
    acks: Mutex<BTreeMap<String, i64>>,
    news: tokio::sync::Notify,
    /// The synchronizer's topology state: what the topology broadcasts are checked against and kept in.
    store: Arc<crate::synchronizer_state::TopologyStore>,
    /// What every member has spent and was sold, while traffic control is on.
    traffic: crate::traffic::Traffic,
    /// The mediators that run as processes of their own: mediator group index -> the member that serves it. While there are any, the
    /// mediators inside the sequencer do not run: the messages addressed to a group are delivered to its member like any other member's.
    external_mediators: Mutex<BTreeMap<u32, String>>,
    /// An observer makes events only of what the BFT orderer decides: no tick, no verdict of an embedded mediator, no expiry of its own.
    observer: std::sync::atomic::AtomicBool,
    /// What an observer hands the submissions it is sent to, to be ordered (the BFT orderer's mempool).
    orderer: std::sync::OnceLock<Arc<Orderer>>,
    /// The aggregations in flight (`InFlightAggregations`): the requests that carry an aggregation rule and what has been aggregated of them.
    aggregations: Mutex<crate::aggregation::Aggregations>,
    /// This sequencer's own member ID (`SEQ::...`), when known (used to attribute `topology-tick-<height>` message IDs).
    self_member: std::sync::OnceLock<String>,
    /// The rate of each participant's confirmation requests (`GrpcSequencerService.checkRate`).
    confirmation_rates: crate::rate_limit::ConfirmationRates,
    /// Post-ordering topology tick tracking across BFT blocks (`BlockUpdateGenerator.MaybeTopologyTickChunk`).
    block_ticks: Mutex<BlockTickState>,
    /// How far the mediators inside may take the time as passed.
    mediator_clock: crate::mediator_clock::MediatorClock,
    /// Quiesce flag rejecting new `SendAsync` submissions while taking a consistent snapshot.
    quiesced: std::sync::atomic::AtomicBool,
    /// Number of active `SendAsync` calls currently inside `submit`.
    in_flight_submissions: std::sync::atomic::AtomicUsize,
}

pub(crate) struct SubmissionGuard(Arc<Inner>);

impl Drop for SubmissionGuard {
    fn drop(&mut self) {
        self.0
            .in_flight_submissions
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Default)]
struct BlockTickState {
    initialized: bool,
    last_block_ts: i64,
    last_chunk_ts: i64,
    latest_bft_block_ts: Option<i64>,
    latest_pending_topology_tx_ts: Option<i64>,
    latest_topology_tx_ts: Option<i64>,
}

/// Takes a submission an observer is sent into the BFT orderer's mempool (`BftBlockOrderer.send`); `Err` is the mempool's refusal
/// (`SequencerNode.RequestRejected.rejectionMessage`).
pub type Orderer = dyn Fn(&str, &[u8]) -> Result<(), String> + Send + Sync;

/// The orderer's refusal as the sender gets it.
///
/// [CANTON-NOTE: SEMANTICS] `BftBlockOrderer.sendToMempoolGeneric` maps every refusal but `P2PNotReady` to `SequencerErrors.Overloaded`
/// (`SEQUENCER_OVERLOADED`, `ContentionOnSharedResources`: gRPC `ABORTED`), which the sequencer client retries at once.
pub(crate) fn overloaded(reason: String) -> Status {
    Status::aborted(format!("SEQUENCER_OVERLOADED(2,0): {reason}"))
}

/// The sequencer's ordering of submissions into per-member event logs.
#[derive(Clone)]
pub struct Sequencer {
    inner: Arc<Inner>,
}

/// A protobuf varint.
fn varint(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// The bytes of a `google.rpc.ErrorInfo` (`reason`, then the metadata in the order given: the official nodes write a map in the order they built it, which a
/// generated map type would not keep).
fn error_info(reason: &str, metadata: &[(&str, &str)]) -> Vec<u8> {
    let mut out = vec![0x0a];
    out.extend(varint(reason.len()));
    out.extend(reason.as_bytes());
    for (key, value) in metadata {
        let mut entry = vec![0x0a];
        entry.extend(varint(key.len()));
        entry.extend(key.as_bytes());
        entry.push(0x12);
        entry.extend(varint(value.len()));
        entry.extend(value.as_bytes());
        out.push(0x1a);
        out.extend(varint(entry.len()));
        out.extend(entry);
    }
    out
}

/// The sequencer's clock: microseconds since the epoch, never going back (one clock for `GetTime` and for the events).
static LAST: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// Moves the clock past `micros`: after a restart, nothing is sequenced before what the journal holds.
pub fn advance_clock_to(micros: i64) {
    LAST.fetch_max(micros, std::sync::atomic::Ordering::SeqCst);
}

pub fn now_micros() -> i64 {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0);
    let mut last = LAST.load(std::sync::atomic::Ordering::SeqCst);
    loop {
        let next = wall.max(last + 1);
        match LAST.compare_exchange(
            last,
            next,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(_) => return next,
            Err(seen) => last = seen,
        }
    }
}

impl Sequencer {
    pub fn new(
        physical_synchronizer_id: String,
        keys: Arc<SynchronizerKeys>,
        registry: Arc<Registry>,
        store: Arc<crate::synchronizer_state::TopologyStore>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                mediators: (0..keys.groups() as u32)
                    .map(|group| {
                        crate::mediator::Mediator::new(
                            group,
                            physical_synchronizer_id.clone(),
                            std::sync::Arc::clone(&keys),
                            std::sync::Arc::clone(&registry),
                            std::sync::Arc::clone(&store),
                        )
                    })
                    .collect(),
                store,
                physical_synchronizer_id,
                keys,
                registry,
                events: Default::default(),
                journal: std::sync::OnceLock::new(),
                ordering: std::sync::OnceLock::new(),
                acks: Default::default(),
                news: tokio::sync::Notify::new(),
                traffic: Default::default(),
                external_mediators: Default::default(),
                observer: std::sync::atomic::AtomicBool::new(false),
                orderer: std::sync::OnceLock::new(),
                aggregations: Default::default(),
                self_member: std::sync::OnceLock::new(),
                confirmation_rates: Default::default(),
                block_ticks: Mutex::new(BlockTickState::default()),
                mediator_clock: Default::default(),
                quiesced: std::sync::atomic::AtomicBool::new(false),
                in_flight_submissions: std::sync::atomic::AtomicUsize::new(0),
            }),
        }
    }

    pub fn set_quiesced(&self, quiesced: bool) {
        self.inner
            .quiesced
            .store(quiesced, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_quiesced(&self) -> bool {
        self.inner
            .quiesced
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn in_flight_submissions(&self) -> usize {
        self.inner
            .in_flight_submissions
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn try_enter_submission(&self) -> Result<SubmissionGuard, Status> {
        use std::sync::atomic::Ordering;
        if self.inner.quiesced.load(Ordering::SeqCst) {
            return Err(Status::unavailable("sequencer quiesced for snapshot"));
        }
        self.inner
            .in_flight_submissions
            .fetch_add(1, Ordering::SeqCst);
        if self.inner.quiesced.load(Ordering::SeqCst) {
            self.inner
                .in_flight_submissions
                .fetch_sub(1, Ordering::SeqCst);
            return Err(Status::unavailable("sequencer quiesced for snapshot"));
        }
        Ok(SubmissionGuard(Arc::clone(&self.inner)))
    }

    /// Sets this sequencer's member ID (`SEQ::...`) so emitted `topology-tick-<height>` events carry its `message_id`.
    pub fn set_self_member(&self, member: &str) {
        let _ = self.inner.self_member.set(member.to_string());
    }

    /// Lets the mediator of `group` run as a process of its own, registered as `member` (it authenticates with `registered`'s keys and reads
    /// what is addressed to its group as an event of its own). The mediator inside the sequencer is then switched off.
    ///
    /// [CANTON-NOTE: SEMANTICS] A mediator is a member of the synchronizer like a participant: it is told what is addressed to its group by
    /// the sequencer, and what it decides it sends back through the sequencer. Only the sequencer's embedded shortcut (reading the submission
    /// directly and writing events straight into the members' logs) went around that.
    pub fn use_external_mediator(&self, group: u32, registered: Registered) {
        let member = registered.member.clone();
        self.inner.registry.insert(registered);
        self.inner
            .external_mediators
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(group, member);
    }

    /// Who serves each mediator group at the time `at` when it is not the mediator inside the sequencer: group -> the members of their own
    /// processes the group's messages are delivered to (none when the group has nobody left). A group that is not in the answer is served by
    /// the mediator inside.
    ///
    /// [CANTON-NOTE: SEMANTICS] The topology decides who serves a group (its `MediatorSynchronizerState`): a mediator onboarded after
    /// genesis has a namespace of its own and is a member like any other; the mediators of the synchronizer's own mediator namespace are the
    /// ones whose keys the sequencer holds (inside, or as processes of their own with `RUST_SEQUENCER_EXTERNAL_MEDIATOR=1`).
    fn mediator_routes(&self, at: i64) -> BTreeMap<u32, Vec<String>> {
        let inside = format!("::{}", self.inner.keys.mediator_namespace.fingerprint);
        let mut routes: BTreeMap<u32, Vec<String>> = self
            .inner
            .external_mediators
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(g, m)| (*g, vec![m.clone()]))
            .collect();
        for (g, group) in self.inner.store.mediator_groups_at(at) {
            let inside_active = group.active.iter().any(|uid| uid.ends_with(&inside));
            let own: Vec<String> = group
                .active
                .iter()
                .filter(|uid| !uid.ends_with(&inside))
                .map(|uid| format!("MED::{uid}"))
                .collect();
            if inside_active && own.is_empty() {
                continue;
            }
            let route = routes.entry(g).or_default();
            if !inside_active {
                route.retain(|m| !m.ends_with(&inside));
            }
            route.extend(own);
        }
        routes
    }

    /// Registers the mediators the topology names that have keys of their own (onboarded after genesis), so that they can authenticate
    /// and are sent what every member is sent.
    ///
    /// [CANTON-NOTE: SEMANTICS] The official sequencer learns its members from the topology: a mediator becomes a member once a
    /// `MediatorSynchronizerState` names it and its key mapping is known; nothing is registered for it by hand.
    ///
    /// [CANTON-NOTE: LIMITATION] Every signing key of the mapping may answer the authentication challenge (the key usages are not kept).
    pub fn follow_mediators(&self) {
        let inside = format!("::{}", self.inner.keys.mediator_namespace.fingerprint);
        for group in self.inner.store.mediator_groups_at(i64::MAX).values() {
            for uid in group.active.iter().chain(&group.observers) {
                if uid.ends_with(&inside) {
                    continue;
                }
                let member = format!("MED::{uid}");
                if self.inner.registry.is_registered(&member) {
                    continue;
                }
                let Some(keys) = self.inner.store.signing_keys_of(&member) else {
                    crate::diag::diag_eprintln!(
                        "MEDIATOR {member} is in a mediator group but has no key mapping"
                    );
                    continue;
                };
                crate::diag::diag_eprintln!("MEDIATOR {member} joins as a member");
                self.inner.registry.insert(Registered {
                    member,
                    signing_keys: keys.clone(),
                    authentication_keys: crate::membership::for_authentication(keys),
                    encryption_keys: Vec::new(),
                });
            }
        }
    }

    /// Sequences the submission `signed_request` (the `SendAsyncRequest.signed_submission_request` bytes) sent by `member`.
    pub fn submit(&self, member: &str, signed_request: &[u8]) -> Result<(), Status> {
        // [CANTON-NOTE: LIMITATION] An observer does not order what its members send it: that is the availability and consensus work of the BFT orderer
        // (`doc/slices/BFT-OUTPUT-SPEC.md` O5). Sequencing it from its own clock would give its members an event the other sequencers do not have (a fork), so
        // the submission is checked, answered as an accepted one and dropped; the sender, which hears nothing, sends it again to another sequencer.
        if self.is_observer() {
            self.submit_checked(member, signed_request, false)?;
            match self.inner.orderer.get() {
                Some(orderer) => orderer(member, signed_request).map_err(overloaded)?,
                None => crate::diag::diag_eprintln!(
                    "OBSERVER dropped a submission of {member}: there is no orderer to give it to"
                ),
            }
            return Ok(());
        }
        match self.inner.ordering.get() {
            None => self.submit_checked(member, signed_request, true),
            Some(ordering) => {
                // the caller gets the refusals it would get without BFT; the order is decided by the ordering cluster
                self.submit_checked(member, signed_request, false)?;
                ordering.order(member, signed_request);
                Ok(())
            }
        }
    }

    /// A submission the ordering cluster committed: sequenced now, in the order the cluster decided.
    pub fn apply_ordered(&self, member: &str, signed_request: &[u8]) {
        if let Err(why) = self.submit_checked(member, signed_request, true) {
            crate::diag::diag_eprintln!(
                "ORDERING a committed submission was refused: {}",
                why.message()
            );
        }
    }

    /// From now on the sequencer makes events only of the submissions it is given (`apply_ordered_at`): the ticks, the verdicts of mediators and the expiry of
    /// requests are what the other sequencers of the synchronizer order as requests of their own, with the times the orderer gave them, so a sequencer that made them
    /// from its clock would give its members events the others do not have (a member that reads from two sequencers sees a fork).
    pub fn set_observer(&self) {
        self.inner
            .observer
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Where an observer sends the submissions it is sent (`BftBlockOrderer.send`): the orderer makes them into batches and the cluster decides their place.
    pub fn set_orderer(&self, orderer: Arc<Orderer>) {
        let _ = self.inner.orderer.set(orderer);
    }

    pub fn has_orderer(&self) -> bool {
        self.inner.orderer.get().is_some()
    }

    /// Moves the monotonic sequencing clock to at least `floor_micros`.
    pub fn advance_clock_to_floor(&self, floor_micros: i64) {
        advance_clock_to(floor_micros);
    }

    /// Advances the observer sequencer's BFT block clock and local monotonic clock after recovery.
    pub fn advance_bft_time_to(&self, ts: i64) {
        advance_clock_to(ts);
        let mut bt = self
            .inner
            .block_ticks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !bt.initialized {
            bt.initialized = true;
            bt.last_block_ts = ts;
            bt.last_chunk_ts = ts;
        } else {
            bt.last_block_ts = bt.last_block_ts.max(ts);
            bt.last_chunk_ts = bt.last_chunk_ts.max(ts);
        }
        bt.latest_bft_block_ts = Some(bt.latest_bft_block_ts.map_or(ts, |t| t.max(ts)));
    }

    /// The current sequencing time for `GetTime`: in BFT observer mode returns the latest decided BFT block/event timestamp (`None` before block 0 so new subscribers start at `0`), otherwise `Some(now_micros())`.
    pub fn current_time(&self) -> Option<i64> {
        if self.is_observer() {
            return self
                .inner
                .block_ticks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .latest_bft_block_ts;
        }
        Some(now_micros())
    }

    /// Orders topology `transactions` across the BFT cluster as an `AllMembersOfSynchronizer` broadcast signed by this sequencer, and waits until sequenced.
    pub async fn order_topology_broadcast(
        &self,
        transactions: &[canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction],
    ) -> Result<(), Status> {
        let Some(last) = transactions.last() else {
            return Ok(());
        };
        let orderer = self
            .inner
            .orderer
            .get()
            .ok_or_else(|| Status::failed_precondition("BFT orderer is not attached"))?;
        let sender = self.inner.self_member.get().cloned().unwrap_or_default();
        if sender.is_empty() {
            return Err(Status::internal(
                "BFT sequencer self_member is not set before topology broadcast",
            ));
        }
        let target_hash = tw::transaction_hash(&last.transaction);
        let id_hex: String = target_hash
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        let message_id = format!("topo-{id_hex}-{}", wall_micros());
        let content = tw::topology_broadcast(&self.inner.physical_synchronizer_id, transactions);
        let max_seq =
            wall_micros().max(LAST.load(std::sync::atomic::Ordering::SeqCst)) + 60_000_000;
        let req = sw::submission_request(
            &sender,
            &message_id,
            &[(tw::ALL_MEMBERS.to_string(), content)],
            max_seq,
        );
        let signed = sw::signed_submission_request(req, &self.inner.keys.sequencer_signing);
        orderer(&sender, &signed).map_err(overloaded)?;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
        loop {
            let notified = self.inner.news.notified();
            if self.inner.store.contains_tx_hash(&target_hash) {
                return Ok(());
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                if self.inner.store.contains_tx_hash(&target_hash) {
                    return Ok(());
                }
                return Err(Status::deadline_exceeded(
                    "timed out waiting for BFT ordering of topology transactions",
                ));
            }
        }
    }

    fn is_observer(&self) -> bool {
        self.inner
            .observer
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A submission the (official) BFT orderer decided, at the time it gave it (`at`, microseconds): sequenced now, at that time.
    pub fn apply_ordered_at(&self, member: &str, signed_request: &[u8], at: i64) {
        if let Err(why) = self.submit_checked_at(member, signed_request, true, Some(at)) {
            crate::diag::diag_eprintln!(
                "ORDERING a committed submission was refused: {}",
                why.message()
            );
        }
    }

    /// An acknowledgement the (official) BFT orderer decided (the request tag `acknowledge`): applied for the member it names, as if the member had sent it here.
    ///
    /// [CANTON-NOTE: SEMANTICS] The official nodes order the acknowledgements of their members too, so every node of the cluster learns up to where a member has read;
    /// a member that reads from the official sequencers and from this one acknowledges at both, and the ordered one is the same acknowledgement.
    pub fn apply_ordered_acknowledgement(&self, signed_request: &[u8]) {
        let member = tw::unversioned(signed_request)
            .and_then(|(data, _)| SignedContent::decode(data.as_slice()).ok())
            .and_then(|signed| signed.content)
            .and_then(|content| tw::unversioned(&content))
            .and_then(|(bytes, _)| {
                canton_proto::com::digitalasset::canton::sequencer::api::v30::AcknowledgeRequest::decode(bytes.as_slice()).ok()
            })
            .map(|request| request.member);
        let Some(member) = member else {
            crate::diag::diag_eprintln!("ORDERING a committed acknowledgement does not decode");
            return;
        };
        if let Err(why) = self.acknowledge(&member, signed_request) {
            crate::diag::diag_eprintln!(
                "ORDERING a committed acknowledgement of {member} was refused: {}",
                why.message()
            );
        }
    }

    /// The BFT ordering mode: from now on submissions are ordered by `ordering`.
    pub fn use_ordering(&self, ordering: Arc<crate::ordering::BftOrdering>) {
        let _ = self.inner.ordering.set(ordering);
    }

    /// Sends a tick once a topology change sequenced now has taken effect (the topology change delay and a little more).
    ///
    /// [CANTON-NOTE: SEMANTICS] A participant learns that a topology change is in force only from an event whose timestamp is past the
    /// change's effective time (sequencing time + `topology_change_delay`). Measured with the JVM participant: without such an event its
    /// `connect` waits for its own trust certificate and package vetting to take effect and fails after a minute ("Condition never became
    /// true within 1m"); Canton calls the event that moves the clock on a time-advancing broadcast.
    pub fn tick_after_topology_change(&self) {
        if self.is_observer() {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_micros(
                crate::synchronizer_state::TOPOLOGY_CHANGE_DELAY_MICROS as u64 + 50_000,
            ))
            .await;
            this.tick();
        });
    }

    /// Completes one BFT ordered block (`BlockUpdateGenerator.MaybeTopologyTickChunk` / `EndOfBlock`):
    ///
    /// [CANTON-NOTE: SEMANTICS] Emits an empty-batch `AllMembersOfSynchronizer` tick when a pending topology
    /// transaction's effective time (`ts + topology_change_delay`) falls strictly between `last_block_ts` and
    /// `max(last_chunk_ts + 1, base_block_time)`; otherwise, if the orderer requested an epoch-end check
    /// (`tick_topology_at_least`), emits a `SequencersOfSynchronizer` tick at `max(last_chunk_ts + 1, at_least)`.
    /// Updates `last_block_ts = last_chunk_ts` and returns `(emitted_tick, has_pending_for_next_epoch)`.
    pub fn finish_ordered_block(
        &self,
        block_height: i64,
        base_block_time: i64,
        tick_topology_at_least: Option<i64>,
    ) -> (Option<(&'static str, i64)>, bool) {
        let epsilon = crate::synchronizer_state::TOPOLOGY_CHANGE_DELAY_MICROS;
        let (emit_spec, has_pending) = {
            let mut bt = self
                .inner
                .block_ticks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !bt.initialized {
                bt.initialized = true;
                bt.last_block_ts = base_block_time - 1;
                bt.last_chunk_ts = base_block_time - 1;
            }
            let block_end = (bt.last_chunk_ts + 1).max(base_block_time);
            let create_tick = bt
                .latest_pending_topology_tx_ts
                .is_some_and(|ts| bt.last_block_ts < ts + epsilon && ts + epsilon < block_end);
            let emit_spec = if create_tick {
                bt.latest_pending_topology_tx_ts = None;
                let tick_at_least = bt
                    .last_chunk_ts
                    .max(base_block_time)
                    .max(tick_topology_at_least.unwrap_or(i64::MIN));
                let tick_ts = (bt.last_chunk_ts + 1).max(tick_at_least);
                bt.last_chunk_ts = tick_ts;
                Some(("all", tick_ts, false))
            } else if let Some(at_least) = tick_topology_at_least {
                let tick_ts = (bt.last_chunk_ts + 1).max(at_least);
                bt.last_chunk_ts = tick_ts;
                Some(("sequencers", tick_ts, true))
            } else {
                None
            };
            bt.last_block_ts = bt.last_chunk_ts;
            let floor = base_block_time.max(bt.last_chunk_ts);
            bt.latest_bft_block_ts = Some(bt.latest_bft_block_ts.map_or(floor, |t| t.max(floor)));
            let has_pending = tick_topology_at_least.is_some_and(|epoch_end| {
                bt.latest_topology_tx_ts
                    .is_some_and(|tx_ts| tx_ts + epsilon > epoch_end)
            });
            (emit_spec, has_pending)
        };

        if let Some((scope, tick_ts, sequencers_only)) = emit_spec {
            self.emit_tick_to(block_height, tick_ts, sequencers_only);
            return (Some((scope, tick_ts)), has_pending);
        }
        (None, has_pending)
    }

    fn emit_tick_to(&self, block_height: i64, timestamp: i64, sequencers_only: bool) {
        let self_member = self.inner.self_member.get().map(String::as_str);
        let members: Vec<String> = self
            .inner
            .registry
            .members()
            .into_iter()
            .filter(|m| !sequencers_only || m.starts_with("SEQ::"))
            .collect();
        if members.is_empty() {
            return;
        }
        let mut events = self
            .inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        advance_clock_to(timestamp);
        let trace = std::env::var_os("BFT_SEQUENCED_TRACE").is_some();
        for member in members {
            let log = events.entry(member.clone()).or_default();
            let previous = log.last().map(|e| e.timestamp);
            let message_id = (self_member == Some(member.as_str()))
                .then(|| format!("topology-tick-{block_height}"));
            if trace {
                crate::diag::diag_eprintln!(
                    "SEQUENCED member={member} index={} ts={timestamp} envelopes=0 message_id={}",
                    log.len(),
                    message_id.as_deref().unwrap_or("")
                );
            }
            self.push_event(
                &member,
                log,
                StoredEvent {
                    timestamp,
                    previous,
                    message_id,
                    envelopes: Vec::new(),
                    error: None,
                    error_details: Vec::new(),
                    receipt: None,
                },
            );
        }
        drop(events);
        self.inner.news.notify_waiters();
    }

    /// The sequencer itself sequences `content` (an envelope no member sent) to **every registered member**: how the topology a member
    /// registered reaches all members, and how a new member gets its first event (a participant's connection waits for the topology it
    /// registered to take effect, which the clock of its events tells it).
    pub fn broadcast(&self, content: Vec<u8>) -> i64 {
        if self.is_observer() {
            return 0;
        }
        let mut events = self
            .inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let timestamp = now_micros();
        for member in self.inner.registry.members() {
            let log = events.entry(member.clone()).or_default();
            let previous = log.last().map(|e| e.timestamp);
            self.push_event(
                &member,
                log,
                StoredEvent {
                    timestamp,
                    previous,
                    message_id: None,
                    envelopes: vec![StoredEnvelope {
                        // [CANTON-NOTE: SEMANTICS] a topology broadcast is addressed to the group of all members: the participant discards one
                        // addressed to itself ("invalid recipients", measured)
                        recipients: vec![vec![tw::ALL_MEMBERS.to_string()]],
                        recipient_trees: Vec::new(),
                        content: content.clone(),
                        signatures: Vec::new(),
                    }],
                    error: None,
                    error_details: Vec::new(),
                    receipt: None,
                },
            );
        }
        drop(events);
        self.inner.news.notify_waiters();
        timestamp
    }

    /// The synchronizer's topology state.
    pub fn store(&self) -> Arc<crate::synchronizer_state::TopologyStore> {
        std::sync::Arc::clone(&self.inner.store)
    }

    /// Maximum event stream offset currently sequenced across registered members.
    pub fn head_offset(&self) -> u64 {
        let Ok(events) = self.inner.events.lock() else {
            return 0;
        };
        events
            .values()
            .map(|list| list.len() as u64)
            .max()
            .unwrap_or(0)
    }

    /// Count of registered members currently tracked in the synchronizer registry.
    pub fn connected_member_count(&self) -> u64 {
        self.inner.registry.members().len() as u64
    }

    /// The sequencer itself sequences topology `transactions` to every member (what the synchronizer's owners decide, such as an upgrade
    /// announcement): the state takes what is authorized, and a tick follows once it took effect. Returns what became of each.
    pub fn sequence_topology(
        &self,
        transactions: &[canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction],
    ) -> Vec<String> {
        self.sequence_topology_outcomes(transactions)
            .iter()
            .map(|o| o.note().to_string())
            .collect()
    }

    /// Like [`Self::sequence_topology`], returning what became of each transaction.
    pub fn sequence_topology_outcomes(
        &self,
        transactions: &[canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction],
    ) -> Vec<canton_participant::topology_state::Outcome> {
        let content = tw::topology_broadcast(&self.inner.physical_synchronizer_id, transactions);
        let at = self.broadcast(content.clone());
        let outcomes = self
            .inner
            .store
            .accept_broadcast(&content, at)
            .unwrap_or_default();
        for outcome in &outcomes {
            crate::diag::diag_eprintln!("TOPOLOGY {}", outcome.note());
        }
        crate::membership::follow_broadcast(
            &self.inner.registry,
            &self.inner.store,
            &content,
            &outcomes,
        );
        self.follow_mediators();
        self.tick_after_topology_change();
        outcomes
    }

    /// A **tick**: an event with an empty batch to every registered member, no message id, no sender. It moves every member's clock on: a
    /// topology change takes effect after the topology change delay, and a participant that registered sees it take effect only when an
    /// event with a later timestamp reaches it.
    pub fn tick(&self) {
        if self.is_observer() {
            return;
        }
        let mut events = self
            .inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let timestamp = now_micros();
        for member in self.inner.registry.members() {
            let log = events.entry(member.clone()).or_default();
            let previous = log.last().map(|e| e.timestamp);
            self.push_event(
                &member,
                log,
                StoredEvent {
                    timestamp,
                    previous,
                    message_id: None,
                    envelopes: Vec::new(),
                    error: None,
                    error_details: Vec::new(),
                    receipt: None,
                },
            );
        }
        drop(events);
        self.inner.news.notify_waiters();
    }

    /// Sequences a message of the mediator to the members it names (the sequencer itself is the sender: no message id).
    pub fn deliver(&self, outgoing: crate::mediator::Outgoing) {
        if self.is_observer() {
            return;
        }
        let mut events = self
            .inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let timestamp = now_micros();
        for member in &outgoing.to {
            if !self.inner.registry.is_registered(member) {
                continue;
            }
            let log = events.entry(member.clone()).or_default();
            let previous = log.last().map(|e| e.timestamp);
            self.push_event(
                member,
                log,
                StoredEvent {
                    timestamp,
                    previous,
                    message_id: None,
                    envelopes: vec![StoredEnvelope {
                        recipients: vec![vec![member.clone()]],
                        recipient_trees: Vec::new(),
                        content: outgoing.content.clone(),
                        signatures: outgoing.signatures.clone(),
                    }],
                    error: None,
                    error_details: Vec::new(),
                    receipt: None,
                },
            );
        }
        drop(events);
        self.inner.news.notify_waiters();
    }

    /// Lets the mediators inside give up on the requests whose response time has passed at the sequencer's clock, never past a submission
    /// they have not been shown yet ([`crate::mediator_clock`]).
    pub fn expire_requests(&self) {
        if self.is_observer() {
            return;
        }
        let now = {
            let _events = self
                .inner
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.inner.mediator_clock.passed(now_micros())
        };
        let external = self.mediator_routes(now);
        let due: Vec<_> = self
            .inner
            .mediators
            .iter()
            .filter(|m| !external.contains_key(&m.group()))
            .flat_map(|m| m.expire(now))
            .collect();
        if !due.is_empty() {
            if let Some(journal) = self.inner.journal.get() {
                journal.write(&format!("X {now}"));
            }
        }
        for outgoing in due {
            self.deliver(outgoing);
        }
    }

    /// Replays a journaled mediator input: the mediator's state is rebuilt, what it would send is not (those are journaled events).
    pub(crate) fn replay_mediator_input(
        &self,
        timestamp: i64,
        sender: &str,
        seen: &[crate::mediator::SeenEnvelope],
    ) {
        advance_clock_to(timestamp);
        for mediator in &self.inner.mediators {
            let _ = mediator.handle(timestamp, sender, seen);
        }
    }

    /// Replays a journaled time-out of requests at `now`.
    pub(crate) fn replay_expiry(&self, now: i64) {
        advance_clock_to(now);
        for mediator in &self.inner.mediators {
            let _ = mediator.expire(now);
        }
    }

    /// Stores `event` for `member` (the next link of `log`, its chain of events) and journals it. The caller holds the lock on the events:
    /// the journal has the events in the order they were ordered.
    fn push_event(&self, member: &str, log: &mut Vec<StoredEvent>, event: StoredEvent) {
        if let Some(journal) = self.inner.journal.get() {
            journal.write(&crate::persistence::event_line(member, &event));
        }
        log.push(event);
    }

    /// Takes a journaled event back (no journaling) and moves the clock past it: what is sequenced from now on is later.
    pub(crate) fn restore_event(&self, member: String, event: StoredEvent) {
        advance_clock_to(event.timestamp);
        if let Ok(mut bt) = self.inner.block_ticks.lock() {
            bt.latest_bft_block_ts = Some(
                bt.latest_bft_block_ts
                    .map_or(event.timestamp, |t| t.max(event.timestamp)),
            );
        }
        self.inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(member)
            .or_default()
            .push(event);
    }

    /// How long after the upgrade time the old synchronizer still runs: the decision timeout (confirmation response timeout + mediator
    /// reaction timeout) in force at the upgrade time, so that every request in flight is decided or timed out
    /// (`SequencerUtils.timeOffsetPastSynchronizerUpgrade`; 60 s with the default parameters, measured as the time of the last event).
    fn upgrade_offset(&self, upgrade_micros: i64) -> i64 {
        let t = self.inner.store.timeouts_at(upgrade_micros);
        t.confirmation_response_micros + t.mediator_reaction_micros
    }

    /// When the announced upgrade time has passed: one last event to every member at the end of the upgrade's time offset (measured on the
    /// official sequencer: an event with no content at exactly upgrade time + 60 s), after which this synchronizer sequences nothing more.
    /// Called now and then; does nothing before the upgrade time or once that event exists.
    pub fn close_after_upgrade(&self) {
        if self.is_observer() {
            return;
        }
        let Some(lsu) = self.inner.store.announced_upgrade() else {
            return;
        };
        if wall_micros() <= lsu.upgrade_micros {
            return;
        }
        let end = lsu.upgrade_micros + self.upgrade_offset(lsu.upgrade_micros);
        if LAST.load(std::sync::atomic::Ordering::SeqCst) >= end {
            return;
        }
        advance_clock_to(end - 1);
        crate::diag::diag_eprintln!(
            "UPGRADE the upgrade time {} has passed: the last event is at {}",
            canton_participant::topology_state::iso_utc(lsu.upgrade_micros),
            canton_participant::topology_state::iso_utc(end)
        );
        self.tick();
    }

    /// From now on every event is journaled in `journal` (called once the journal has been replayed).
    pub fn attach(&self, journal: Arc<crate::persistence::Journal>) {
        let _ = self.inner.journal.set(journal);
    }
}

/// The wall clock in microseconds, without moving the sequencing clock.
pub fn wall_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// A physical synchronizer id as the node prints it: the fingerprint cut to 12 digits (`mysync::1220a2b1c74b...::37-0`).
fn short_psid(psid: &str) -> String {
    let parts: Vec<&str> = psid.split("::").collect();
    match parts.as_slice() {
        [name, fp, suffix] if fp.len() > 12 => format!("{name}::{}...::{suffix}", &fp[..12]),
        _ => psid.to_string(),
    }
}
