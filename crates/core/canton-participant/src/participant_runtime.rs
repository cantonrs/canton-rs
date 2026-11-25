//! The event loop of a receiving participant (G5 5.6o, S-NET-023): everything the earlier slices built, run on the sequenced events in
//! order, with a cursor that survives a restart.
//!
//! [CANTON-NOTE: SEMANTICS] For every event the sequencer delivers to the participant, in sequencing order:
//! 1. **Verdicts** (the mediator's signed `ConfirmationResultMessage`) are checked against the request they name (its root hash, its
//!    decision time, the signatures of its mediator group: `view_validation::check_verdict`) and **resolve** it: an approval changes the
//!    contract set, anything else frees the locks (`view_acs`).
//! 2. **Requests** (an encrypted view this participant can read plus the root hash message of the same event; the request id is the
//!    event's sequencing time) are **decided** (`view_decision`): approve, reject or malformed, and the answer is recorded as
//!    answered **before** it is sent. An event is never answered twice, also after a restart or when the participant reads the same
//!    events again.
//! 3. The event's **sequencing time** then **expires** the requests whose decision time has passed without a verdict (the participant
//!    treats them as rejected). Sequencing time only moves with events, so this is the participant's clock.
//! 4. The **cursor** (the sequencing time of the last event handled) is saved, with what the next event and a resubscription are checked
//!    against (`sequenced_event_validation::LastEvent`). The loop resumes just after it.
//!
//! [`Runtime::step`] does this for one event and does no I/O: it returns what must be sent. [`Runtime::receive`] first checks the event as
//! the sequencer client does (`sequenced_event_validation`). [`Runtime::poll`] subscribes, receives, and sends the answers (a request whose
//! answer would be too late for the mediator is not answered); an event that is refused stops the subscription for good.
//!
//! [CANTON-NOTE: LIMITATION] A runtime that does not follow the topology (`Config::follow_topology` unset) trusts every configured
//! submitter key for every submitter and any configured mediator key for every verdict, and does not check the submitting participant's
//! permission (it has no hosting table).
use crate::confirmation_wire::{confirmation_responses, mediator_group, ViewResponse};
use crate::root_hash_messages::Request;
use crate::sequenced_event_validation::{self as validation, verifies_at, LastEvent, NotHandled};
use crate::sequencer_connect::{SequencerConnect, Token};
use crate::sequencing_wire::{
    signed_submission_request, submission_request_signed, Delivered, Receipt,
};
use crate::topology_wire::Ed25519Key;
use crate::view_acs::{decode_verdict, Ledger, Timeouts};
use crate::view_conformance::Engine;
use crate::view_decision::{decide_all_envelopes, Decision, Participant};
use crate::view_validation::{
    check_verdict, HostsOf, MediatorTrust, ReceivedVerdict, RequestFacts, TimeTolerances,
};
use canton_algo::signing::PublicKey;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::ViewType;
use std::path::Path;
use std::time::Duration;

mod commitments;
mod cost_estimate;
mod outbox;
mod repair;
mod submissions;
mod topology_journal;
mod unassignments;
pub use unassignments::SharedUnassignments;

pub use cost_estimate::{
    mock_confirmation_response, pay_with, submission_cost_with, PricedEnvelope,
};

/// What the participant is and trusts.
pub struct Config {
    pub member: String,
    pub encryption_fingerprint: String,
    pub encryption_secret: [u8; 32],
    /// The parties this participant hosts with permission to confirm.
    pub hosted_parties: Vec<String>,
    pub timeouts: Timeouts,
    /// The keys of the participant that submits the requests (a request's top-level view is signed with one of them). When the topology is
    /// followed, a request is verified with the keys of the participant it names instead (see `submitter_keys` below).
    pub submitter_keys: Vec<PublicKey>,
    /// The keys of the mediator (its verdicts are signed with one of them). When the topology is followed, the request's mediator group
    /// decides instead.
    pub mediator_keys: Vec<PublicKey>,
    /// The encryption keys of the other participants, by member (what a request's randomness is encrypted for).
    pub peer_encryption_keys:
        std::collections::BTreeMap<String, Vec<crate::topology_state::EncryptionKey>>,
    pub physical_synchronizer_id: String,
    /// Whether the hosted parties, the trusted keys and the time limits come from the synchronizer's topology (the state downloaded
    /// at the start, then the authorized broadcasts in the event stream) instead of this configuration. [CANTON-NOTE: SEMANTICS] When set, the
    /// state replaces `hosted_parties`, `submitter_keys`, `mediator_keys`, `peer_encryption_keys` and (if the state has them) `timeouts`.
    pub follow_topology: bool,
    /// The synchronizer's `topology_change_delay` (static parameters): a topology change sequenced at `t` is in force from `t + delay` on.
    /// [CANTON-NOTE: SEMANTICS] Measured on the official node (S-NET-037, `validFrom - sequenced` of a change = 250 000 micros).
    pub topology_change_delay_micros: i64,
}

/// An answer that has to go to the mediator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToSend {
    pub request_time: i64,
    pub root_hash: Vec<u8>,
    /// The mediator group the answer goes to: the one the request's root hash message is sent to.
    pub mediator_group: u32,
    /// One decision per view the participant was shown (see `decide_all`); only the views it confirms something in are sent.
    pub decisions: Vec<Decision>,
}

impl ToSend {
    /// The decision for the first view (the only one for a request with one view).
    pub fn decision(&self) -> &Decision {
        &self.decisions[0]
    }
}

/// What one event led to.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Step {
    pub to_send: Vec<ToSend>,
    /// `(request id, approved)` of the verdicts that resolved a request in flight.
    pub verdicts: Vec<(i64, bool)>,
    /// Requests rejected because their decision time passed.
    pub expired: Vec<i64>,
    /// What was set aside, and why (a verdict that is not the mediator's, a request already answered, an answer too late, ...).
    pub notes: Vec<String>,
    /// An envelope of the event was a topology broadcast: the synchronizer's state may have changed.
    pub topology_changed: bool,
    /// `(message id, sequencing time)` when the event is this participant's own submission coming back: the sequencing time is the request
    /// id the verdict will be about.
    pub own_requests: Vec<(String, i64)>,
    /// `(request id, approved)` of the mediator-signed verdicts about requests this participant did not keep in flight: it rejected them
    /// itself (or never saw them). A submitter whose own request the mediator rejected learns the verdict from here.
    pub unresolved_verdicts: Vec<(i64, bool)>,
    /// What an approved request changed in this participant's contract set (the contracts it created, with their instances, and the ones it
    /// consumed): the transactions this participant has to show to its parties, whoever submitted them.
    pub applied: Vec<crate::view_acs::Applied>,
    /// `(request id, gRPC code, message)` of the verdicts that rejected a request: why (the refusing participant's error, or the mediator's).
    pub rejections: Vec<(i64, i32, String)>,
    /// `(request id, JSON)` of what the refusing participant's reason adds (see `Verdict::reject_context`), for the rejections above.
    pub rejection_contexts: Vec<(i64, String)>,
    /// `(message id, gRPC code, message)` when the event is the sequencer's refusal of this participant's own submission (a deliver error):
    /// that submission failed with this status and no verdict will come (`InFlightSubmissionTracker.observeDeliverError`).
    pub deliver_errors: Vec<(String, i32, String)>,
    /// The submissions of this participant whose fate the event decided (see `in_flight`).
    pub settled: Vec<crate::in_flight::Settled>,
    /// The ACS commitments of the reconciliation ticks the event completed, one per counter-participant (sent by [`Runtime::poll`]).
    pub commitments: Vec<crate::acs_commitment_runtime::Outgoing>,
}

/// The participant's running state: its engine, its contract set, and where it is in the sequenced events.
pub struct Runtime {
    pub config: Config,
    pub engine: Engine,
    pub ledger: Ledger,
    cursor: i64,
    /// The event at the cursor and what the sequencer client keeps to check the next ones.
    subscription: validation::Subscription,
    /// Where the cursor and the topology journal are kept (`None`: in memory only).
    store: Option<std::sync::Arc<dyn crate::state_store::StateStore>>,
    /// The topology as followed (only when `config.follow_topology`), after the state was loaded.
    tracker: Option<crate::topology_state::Tracker>,
    /// The topology changes seen but not yet in force: (the time they take effect, the stored transaction), in the order they came.
    pending_topology: Vec<(i64, Vec<u8>)>,
    /// This participant's own signing key, trusted for the requests it submits itself.
    /// [CANTON-NOTE: SEMANTICS] The keys learned from the topology are the **other** participants' (a receiver does not see its own requests).
    /// A participant that also submits gets its own requests back as events and must accept their signature, or it judges them malformed
    /// (`BadSignature`, measured with the node of `crate::node`).
    own_signing_key: Option<PublicKey>,
    /// This participant's admin party (named by its uid): it is hosted by the participant without any topology transaction and has to confirm
    /// every request this participant submits (the confirmation quorum of a root view names it).
    own_admin_party: Option<String>,
    /// Most recent sequencer subscribe transport/stream failure (`None` when healthy or empty wait).
    pub last_subscribe_error: Option<String>,
    /// What this participant keeps of each request it answered (kept under [`REQUESTS_JOURNAL`]): what the verdict about it is checked against.
    requests: std::collections::BTreeMap<i64, RequestFacts>,
    /// This participant's own submissions in flight (kept under `in_flight::JOURNAL`).
    pub(crate) in_flight: crate::in_flight::InFlight,
    /// What this participant shares with each counter-participant, for its ACS commitments.
    commitments: crate::acs_commitment_runtime::Commitments,
    /// This participant's own fresh requests, by root hash (P-3, see `submissions`).
    submissions: submissions::Submissions,
    /// The approved transactions not shown yet (P-13, see `outbox`).
    outbox: outbox::Outbox,
    /// In-flight unassignments awaiting mediator verdict, keyed by request time (`P-14`).
    pending_unassignments:
        std::collections::BTreeMap<i64, (String, crate::reassignment_receive::StoredUnassignment)>,
    /// Approved unassignments keyed by `reassignment_id`, cross-checked when a corresponding assignment arrives (`P-14`).
    stored_unassignments:
        std::collections::BTreeMap<String, crate::reassignment_receive::StoredUnassignment>,
    /// The approved unassignments of the participant's runtimes on all its synchronizers, when it has several (U-60, see
    /// [`SharedUnassignments`]).
    shared_unassignments: Option<SharedUnassignments>,
}

/// The store key of the journal of the requests' facts (one [`RequestFacts::record`] line each).
const REQUESTS_JOURNAL: &str = "requests.journal";
/// The store key persisting pending and approved `StoredUnassignment` records across restarts (`R-6e`).
pub(super) const STORED_UNASSIGNMENTS_JOURNAL: &str = "stored-unassignments.journal";

impl Runtime {
    /// Trusts `key` as the signer of the requests this participant submits, and hosts its admin party `admin_party`.
    pub fn trust_own_submissions(&mut self, key: PublicKey, admin_party: &str) {
        self.own_signing_key = Some(key);
        self.own_admin_party = Some(admin_party.to_string());
        self.add_own_key();
    }

    /// What the topology does not say about this participant itself, added again each time the topology is learned.
    fn add_own_key(&mut self) {
        if let Some(key) = &self.own_signing_key {
            if !self.config.submitter_keys.contains(key) {
                self.config.submitter_keys.push(key.clone());
            }
        }
        if let Some(admin) = &self.own_admin_party {
            if !self.config.hosted_parties.contains(admin) {
                self.config.hosted_parties.push(admin.clone());
            }
        }
    }

    /// A participant whose state lives in `state_dir` (the contract set's journal and the cursor) if given, else in memory. A new
    /// state starts at `start_cursor`; an existing one continues where it stopped.
    pub fn open(
        config: Config,
        engine: Engine,
        state_dir: Option<&Path>,
        start_cursor: i64,
    ) -> Result<Self, String> {
        let store = match state_dir {
            None => None,
            Some(dir) => Some(crate::state_store::FileStore::new(dir)?
                as std::sync::Arc<dyn crate::state_store::StateStore>),
        };
        Self::open_in(config, engine, store, start_cursor)
    }

    /// Like [`Runtime::open`], with the state kept in `store` (a directory or a database) when given.
    pub fn open_in(
        config: Config,
        engine: Engine,
        store: Option<std::sync::Arc<dyn crate::state_store::StateStore>>,
        start_cursor: i64,
    ) -> Result<Self, String> {
        let (ledger, (cursor, last_event), requests, (pending_unassignments, stored_unassignments)) =
            match &store {
                None => (
                    Ledger::new(),
                    (start_cursor, None),
                    Default::default(),
                    Default::default(),
                ),
                Some(store) => {
                    let ledger = Ledger::open_in(std::sync::Arc::clone(store), "ledger.journal")?;
                    let kept = store
                        .read("cursor")?
                        .and_then(|t| validation::parse_cursor(&t))
                        .unwrap_or((start_cursor, None));
                    let requests = open_requests(store.as_ref(), kept.0)?;
                    let unassignments = unassignments::open_stored_unassignments(store.as_ref())?;
                    (ledger, kept, requests, unassignments)
                }
            };
        Ok(Runtime {
            config,
            engine,
            ledger,
            cursor,
            subscription: validation::Subscription::resumed(last_event),
            tracker: None,
            pending_topology: Vec::new(),
            own_signing_key: None,
            own_admin_party: None,
            last_subscribe_error: None,
            requests,
            in_flight: crate::in_flight::InFlight::open(store.clone())?,
            commitments: crate::acs_commitment_runtime::Commitments::open(store.clone())?,
            submissions: submissions::Submissions::open(store.clone(), cursor)?,
            outbox: outbox::Outbox::open(store.clone())?,
            pending_unassignments,
            stored_unassignments,
            shared_unassignments: None,
            store,
        })
    }

    /// Keeps the facts of `request` (written before the answer is recorded, see [`Ledger::mark_answered`]).
    fn remember_request(&mut self, request: i64, facts: RequestFacts) -> Result<(), String> {
        if let Some(store) = &self.store {
            store.append(REQUESTS_JOURNAL, &facts.record(request))?;
        }
        self.requests.insert(request, facts);
        Ok(())
    }

    /// Drops the facts of the requests whose decision time is before `now`: no verdict can resolve them any more.
    ///
    /// [CANTON-NOTE: WHY] Without this the facts of every request ever answered stay in memory for the life of the process. The journal is
    /// cut down when it is next opened (`open_requests`).
    fn forget_requests(&mut self, now: i64) {
        self.requests.retain(|_, facts| facts.decision_time >= now);
    }

    /// Whose signatures make a verdict the mediator's: the groups in force when the topology is followed, else the configured keys.
    ///
    /// [CANTON-NOTE: SEMANTICS] A runtime configured by hand keeps the meaning of `mediator_keys`: any one of them signs a verdict.
    fn check_verdict(&self, received: &ReceivedVerdict) -> Result<(), String> {
        let request = received.verdict.request_id;
        let facts = self.requests.get(&request);
        // [CANTON-NOTE: INVARIANT] The facts of a request are dropped once its decision time has passed (`forget_requests`), so a verdict
        // that comes later still has to be set aside without them: a request's id is its sequencing time, which gives its decision time.
        if facts.is_none() && received.sequenced_at > self.config.timeouts.decision_time(request) {
            return Err(format!(
                "it is sequenced at {}, after the decision time of the request",
                received.sequenced_at
            ));
        }
        crate::view_validation::check_timeout_not_early(
            received.verdict,
            received.sequenced_at,
            self.config.timeouts.response_deadline(request),
        )?;
        match &self.tracker {
            Some(tracker) => {
                let keys_of = |member: &str| tracker.signing_keys_of(member);
                check_verdict(
                    received,
                    facts,
                    &MediatorTrust::Topology {
                        groups: tracker.mediator_groups(),
                        keys_of: &keys_of,
                    },
                )
            }
            None => check_verdict(
                received,
                facts,
                &MediatorTrust::Configured(&self.config.mediator_keys),
            ),
        }
    }

    /// The sequencing time of the last event handled; the next event to read is after it.
    pub fn cursor(&self) -> i64 {
        self.cursor
    }

    /// The last event handled (`None` after an opening or a rewind at a time): what the next event is checked against.
    pub fn last_event(&self) -> Option<&LastEvent> {
        self.subscription.last()
    }

    /// Moves the cursor back (to read events again). Everything already answered or decided stays so: reading again changes nothing.
    pub fn rewind(&mut self, to: i64) -> Result<(), String> {
        self.set_cursor(to, None)
    }

    fn set_cursor(&mut self, to: i64, last_event: Option<LastEvent>) -> Result<(), String> {
        if let Some(store) = &self.store {
            // replaced at once, the event with its cursor: a crash leaves the old pair or the new one, never half of one
            store.write(
                "cursor",
                &validation::cursor_record(to, last_event.as_ref()),
            )?;
        }
        self.cursor = to;
        self.subscription.handled(last_event);
        Ok(())
    }

    /// Names the sequencer this participant is connected to (its uid): the topology's keys of that sequencer sign the events.
    pub fn connected_to(&mut self, sequencer_uid: &str) {
        self.subscription.connected_to(sequencer_uid);
    }

    /// Checks one event the subscription delivered (`signed_sequenced_event` bytes) as the sequencer client does, then handles it unless it is
    /// the last one handled, delivered again (`None`: the event a resubscription starts with, checked and not handled again). A refused
    /// event is not handled, the cursor stays, and every later event is refused the same way.
    pub fn receive(&mut self, raw: &[u8]) -> Result<Option<Step>, NotHandled> {
        let psid = self.config.physical_synchronizer_id.clone();
        let (event, replay) = self.subscription.admit(raw, self.cursor, &psid)?;
        // the sequencer's keys are the topology's at the event's timestamp: what took effect before it
        let mut step = Step::default();
        self.apply_due_topology(event.timestamp_micros, &mut step);
        let keys = self.config.follow_topology.then(|| {
            (self.tracker.as_ref().zip(self.subscription.sequencer()))
                .and_then(|(tracker, sequencer)| tracker.signing_keys_of(sequencer))
                .unwrap_or_default()
        });
        self.subscription
            .authenticate(&event, replay, &psid, keys.as_deref())?;
        if replay {
            return Ok(None);
        }
        self.handle(&event, step)
            .map(Some)
            .map_err(NotHandled::Failed)
    }

    /// Handles one event (see the module documentation) and advances the cursor. The event is taken as checked (see [`Runtime::receive`]).
    pub fn step(&mut self, event: &Delivered) -> Result<Step, String> {
        self.handle(event, Step::default())
    }

    fn handle(&mut self, event: &Delivered, mut step: Step) -> Result<Step, String> {
        let previous = self.cursor;
        match event.receipt() {
            Some(Receipt::Sequenced(id)) => step
                .own_requests
                .push((id.to_string(), event.timestamp_micros)),
            Some(Receipt::Refused(id, code, why)) => {
                step.deliver_errors
                    .push((id.to_string(), code, why.to_string()))
            }
            None => {}
        }
        // [CANTON-NOTE: SEMANTICS] The state a request is judged by is the state **at its sequencing time**: a topology change is in force from
        // its sequencing time plus the topology change delay, so what was sequenced inside that delay is still judged by the old state. The
        // changes that took effect before this event are applied first; a change this event carries waits for the clock.
        self.apply_due_topology(event.timestamp_micros, &mut step);
        let checked = crate::root_hash_messages::check(event);
        step.notes.extend(checked.alarms);
        for (i, envelope) in event.envelopes.iter().enumerate() {
            if let Some(transactions) = crate::topology_state::broadcast_transactions(envelope) {
                let recipients = event.recipients.get(i).map_or(&[][..], Vec::as_slice);
                if !crate::topology_state::is_addressed_to_all(recipients) {
                    step.notes.push(format!(
                        "Discarding a topology broadcast at {} with invalid recipients: {recipients:?}",
                        event.timestamp_micros
                    ));
                    continue;
                }
                step.topology_changed = true;
                if self.config.follow_topology {
                    for stored in &transactions {
                        // written before it is used: a restart replays what was seen
                        self.journal_topology(stored)?;
                        let change = (
                            event.timestamp_micros + self.config.topology_change_delay_micros,
                            stored.clone(),
                        );
                        // an event read again does not schedule its changes twice
                        if !self.pending_topology.contains(&change) {
                            self.pending_topology.push(change);
                        }
                    }
                }
                continue;
            }
            if self.receive_commitment(envelope, event.timestamp_micros, &mut step) {
                continue;
            }
            if let Some((verdict, signed_hash)) = decode_verdict(envelope) {
                let signatures: &[Signature] = event
                    .envelope_signatures
                    .get(i)
                    .map_or(&[][..], Vec::as_slice);
                self.verdict(
                    &verdict,
                    &signed_hash,
                    signatures,
                    event.timestamp_micros,
                    &mut step,
                )?;
            }
        }
        match checked.request {
            Request::Good(request) => self.request(event.timestamp_micros, &request, &mut step)?,
            Request::BadRootHashMessages {
                root_hash,
                mediator_group,
                why,
            } => self.answer_malformed(
                event.timestamp_micros,
                root_hash,
                mediator_group,
                format!("LOCAL_VERDICT_BAD_ROOT_HASH_MESSAGES: {why}"),
                &mut step,
            )?,
            Request::Dropped(_) | Request::None => {}
        }
        step.expired = self
            .ledger
            .expire(event.timestamp_micros)
            .map_err(|c| format!("{c:?}"))?;
        for expired_id in &step.expired {
            if self.pending_unassignments.remove(expired_id).is_some() {
                if let Some(store) = &self.store {
                    store.append(STORED_UNASSIGNMENTS_JOURNAL, &format!("R\t{expired_id}"))?;
                }
            }
        }
        self.forget_requests(event.timestamp_micros);
        self.submissions.forget(event.timestamp_micros);
        self.track_commitments(previous, event.timestamp_micros, &mut step)?;
        // the fates the event decides are kept before the cursor moves past it
        step.settled =
            self.in_flight
                .observe(&step, event.timestamp_micros, &self.config.timeouts)?;
        self.outbox.keep(&step.applied)?;
        self.set_cursor(event.timestamp_micros, Some(LastEvent::of(event)))?;
        Ok(step)
    }

    /// Applies a verdict of the mediator, once it is checked to be about a request this participant keeps (see [`Runtime::check_verdict`]).
    fn verdict(
        &mut self,
        verdict: &crate::view_acs::Verdict,
        signed_hash: &[u8],
        signatures: &[Signature],
        sequenced_at: i64,
        step: &mut Step,
    ) -> Result<(), String> {
        // [CANTON-NOTE: SEMANTICS] A verdict sequenced after the decision time is set aside here, so the request it names expires
        // below (`expire` runs after the event's verdicts) instead of being resolved by it.
        if let Err(why) = self.check_verdict(&ReceivedVerdict {
            verdict,
            signed_hash,
            signatures,
            sequenced_at,
        }) {
            step.notes.push(format!(
                "the verdict on {} is set aside: {why}",
                verdict.request_id
            ));
            return Ok(());
        }
        if !verdict.approved && !verdict.reason.is_empty() {
            step.rejections.push((
                verdict.request_id,
                verdict.reason_code,
                verdict.reason.clone(),
            ));
            if let Ok(mut context) =
                serde_json::from_str::<serde_json::Value>(&verdict.reject_context)
            {
                // the synchronizer the request went to: the official error names it in its context (`psid`)
                context["psid"] = serde_json::json!(self.config.physical_synchronizer_id.clone());
                step.rejection_contexts
                    .push((verdict.request_id, context.to_string()));
            }
        }
        let mediator_active = match (
            &self.tracker,
            self.requests
                .get(&verdict.request_id)
                .and_then(|f| f.mediator_group),
        ) {
            (Some(tracker), Some(group_id)) => {
                let active = tracker
                    .mediator_groups()
                    .get(&group_id)
                    .is_some_and(crate::topology_state::MediatorGroup::is_active);
                if !active {
                    step.notes.push(format!(
                        "Mediator group {group_id} has been deactivated while processing request {}; rolling back",
                        verdict.request_id
                    ));
                }
                active
            }
            // [CANTON-NOTE: SEMANTICS] When topology is followed without a tracked mediator_group for this
            // verdict (for example legacy requests before group tagging), require at least one active mediator group.
            (Some(tracker), None) => {
                let any_active = tracker
                    .mediator_groups()
                    .values()
                    .any(crate::topology_state::MediatorGroup::is_active);
                if !any_active {
                    step.notes.push(format!(
                        "No active mediator group exists at result time for request {}; rolling back",
                        verdict.request_id
                    ));
                }
                any_active
            }
            // [CANTON-NOTE: LIMITATION] Manual/hand-configured runtimes without a topology tracker skip group liveness checks.
            (None, _) => true,
        };
        let effective_approved = verdict.approved && mediator_active;
        let overruled = effective_approved && self.ledger.refused_here(verdict.request_id);
        if self
            .ledger
            .resolve(verdict.request_id, effective_approved)
            .map_err(|c| format!("{c:?}"))?
        {
            if let Some((reassignment_id, stored)) =
                self.pending_unassignments.remove(&verdict.request_id)
            {
                if let Some(store) = &self.store {
                    let tag = if effective_approved { "A" } else { "R" };
                    store.append(
                        STORED_UNASSIGNMENTS_JOURNAL,
                        &format!("{tag}\t{}", verdict.request_id),
                    )?;
                }
                if effective_approved {
                    self.hold_unassignment(reassignment_id, stored);
                }
            }
            if overruled {
                step.notes.push(format!(
                    "Mediator approved a request that has been locally rejected: {}",
                    verdict.request_id
                ));
            }
            step.verdicts.push((verdict.request_id, effective_approved));
            if let Some(mut applied) = self.ledger.take_applied() {
                applied.root_hash = verdict.root_hash.clone();
                step.applied.push(applied);
            }
        } else {
            step.unresolved_verdicts
                .push((verdict.request_id, verdict.approved));
            step.notes.push(format!(
                "the verdict on {} is for a request that is not in flight",
                verdict.request_id
            ));
        }
        Ok(())
    }

    /// Decides a request whose root hash message and views fit together (`root_hash_messages`), and records it as answered before the
    /// answer is sent.
    fn request(
        &mut self,
        request_time: i64,
        request: &crate::root_hash_messages::Good,
        step: &mut Step,
    ) -> Result<(), String> {
        if request.view_type != ViewType::Transaction {
            // an unassignment or assignment request: its own view type, its own tree (G7 B1)
            let received = request.views.iter().find_map(|view| {
                crate::reassignment_receive::decrypt(
                    view,
                    &self.config.encryption_fingerprint,
                    &self.config.encryption_secret,
                )
            });
            if let Some(received) = received {
                self.reassignment_request(request_time, request, &received, step)?;
            }
            return Ok(());
        }
        let view_envelopes: Vec<&[u8]> = request
            .views
            .iter()
            .copied()
            .filter(|view| {
                crate::view_receive::decrypt_views(
                    view,
                    &self.config.encryption_fingerprint,
                    &self.config.encryption_secret,
                )
                .is_ok()
                    || self.is_view_for_this_participant(view)
            })
            .collect();
        if view_envelopes.is_empty() {
            return Ok(());
        }
        if self.ledger.knows_request(request_time) {
            step.notes
                .push(format!("the request {request_time} is already answered"));
            return Ok(());
        }
        if let Some(why) = self.replayed(request_time, &request.root_hash, &view_envelopes)? {
            let (root_hash, group) = (request.root_hash.clone(), request.mediator_group);
            return self.answer_malformed(request_time, root_hash, group, why, step);
        }
        let time_tolerances = self.time_tolerances();
        let uid = self.config.member.trim_start_matches("PAR::").to_string();
        let physical = self.config.physical_synchronizer_id.clone();
        let (tracker, configured_keys, own_key) = (
            self.tracker.as_ref(),
            &self.config.submitter_keys,
            self.own_signing_key.as_ref(),
        );
        let verify = |submitting: Option<&str>, s: &Signature, root: &[u8]| {
            let keys = submitter_keys(
                tracker,
                configured_keys,
                own_key.map(|key| (uid.as_str(), key)),
                submitting,
            );
            verifies_at(&keys, s, root, &physical, request_time)
        };
        // [CANTON-NOTE: SEMANTICS] The hosting the authorization check reads is the topology in force before this event (see
        // `apply_due_topology` in `step`): the state at the request's sequencing time.
        let hosts_of = self
            .tracker
            .as_ref()
            .map(|tracker| move |party: &str| tracker.hosts_of(party));
        let party_keys = self
            .tracker
            .as_ref()
            .map(|tracker| move |party: &str| tracker.party_signing_keys(party));
        let decided = decide_all_envelopes(
            &Participant {
                encryption_fingerprint: &self.config.encryption_fingerprint,
                encryption_secret: &self.config.encryption_secret,
                engine: &self.engine,
                hosted_parties: &self.config.hosted_parties,
                verify_submitter: &verify,
                time_tolerances,
                uid: &uid,
                hosts_of: hosts_of.as_ref().map(|f| f as &HostsOf),
                party_keys: party_keys
                    .as_ref()
                    .map(|f| f as &crate::external_hash::PartyKeys),
            },
            &mut self.ledger,
            request_time,
            Some(self.config.timeouts.decision_time(request_time)),
            &request.root_hash,
            Some(request.mediator_group),
            &view_envelopes,
        );
        let mut decisions = match decided {
            Ok(decisions) => decisions,
            Err(why) => {
                step.notes.push(format!(
                    "the request {request_time} is not processed: {why}"
                ));
                Vec::new()
            }
        };
        // a participant with no party to answer for in a view says nothing about it (a malformed request is answered by everyone)
        decisions.retain(|d| {
            !d.confirming_parties.is_empty()
                || matches!(d.outcome, crate::confirmation_wire::Outcome::Malformed(_))
        });
        self.record_answer(
            request_time,
            &request.root_hash,
            request.mediator_group,
            decisions,
            step,
        )
    }

    /// Answers the request of an event as malformed and does nothing else with it (Canton's `BadRootHashMessagesRequestProcessor`).
    fn answer_malformed(
        &mut self,
        request_time: i64,
        root_hash: Vec<u8>,
        mediator_group: u32,
        why: String,
        step: &mut Step,
    ) -> Result<(), String> {
        if self.ledger.knows_request(request_time) {
            step.notes
                .push(format!("the request {request_time} is already answered"));
            return Ok(());
        }
        let decision = Decision {
            outcome: crate::confirmation_wire::Outcome::Malformed(why),
            view_position: Vec::new(),
            confirming_parties: Vec::new(),
        };
        self.record_answer(
            request_time,
            &root_hash,
            mediator_group,
            vec![decision],
            step,
        )
    }

    /// Records `request_time` as answered (what its verdict is checked against first), then queues the answer when there is one.
    fn record_answer(
        &mut self,
        request_time: i64,
        root_hash: &[u8],
        mediator_group: u32,
        decisions: Vec<Decision>,
        step: &mut Step,
    ) -> Result<(), String> {
        self.remember_request(
            request_time,
            RequestFacts {
                root_hash: root_hash.to_vec(),
                mediator_group: Some(mediator_group),
                decision_time: self.config.timeouts.decision_time(request_time),
            },
        )?;
        self.ledger
            .mark_answered(request_time)
            .map_err(|c| format!("{c:?}"))?;
        if decisions.is_empty() {
            step.notes.push(format!(
                "nothing to answer for in the request {request_time}"
            ));
        } else {
            step.to_send.push(ToSend {
                request_time,
                root_hash: root_hash.to_vec(),
                mediator_group,
                decisions,
            });
        }
        Ok(())
    }

    /// Answers an unassignment or assignment request (see `reassignment_receive`): decides, locks what an approval changes, and records the
    /// request as answered before the answer is sent.
    fn reassignment_request(
        &mut self,
        request_time: i64,
        request: &crate::root_hash_messages::Good,
        received: &Result<crate::reassignment_receive::Received, String>,
        step: &mut Step,
    ) -> Result<(), String> {
        use crate::confirmation_wire::Outcome;
        if self.ledger.knows_request(request_time) {
            step.notes
                .push(format!("the request {request_time} is already answered"));
            return Ok(());
        }
        if let Some(why) =
            crate::reassignment_receive::other_mediator(received, request.mediator_group)
        {
            step.notes.push(format!(
                "the request {request_time} is not processed: {why}"
            ));
            let (root_hash, group) = (&request.root_hash, request.mediator_group);
            return self.record_answer(request_time, root_hash, group, Vec::new(), step);
        }
        let uid = self.config.member.trim_start_matches("PAR::").to_string();
        let keys = submitter_keys(
            self.tracker.as_ref(),
            &self.config.submitter_keys,
            self.own_signing_key.as_ref().map(|key| (uid.as_str(), key)),
            received
                .as_ref()
                .ok()
                .map(|r| r.common.submitting_participant_uid.as_str()),
        );
        let physical = self.config.physical_synchronizer_id.clone();
        let verify =
            move |s: &Signature, root: &[u8]| verifies_at(&keys, s, root, &physical, request_time);
        let tracker_ref = self.tracker.as_ref();
        let hosts_of = tracker_ref.map(|tracker| move |party: &str| tracker.hosts_of(party));
        let vetted_of = tracker_ref.map(|tracker| {
            move |participant_uid: &str| {
                tracker.vetted_packages_of_participant_at(participant_uid, request_time)
            }
        });
        let stored_unassignment = received
            .as_ref()
            .ok()
            .filter(|r| r.common.kind == crate::reassignment_wire::Kind::Assignment)
            .and_then(|r| r.reassignment_id.as_deref())
            .and_then(|id| self.known_unassignment(id));
        let ctx = crate::reassignment_receive::ReassignmentContext {
            own_uid: Some(&uid),
            engine: Some(&self.engine),
            hosts_of: hosts_of.as_ref().map(|f| f as &HostsOf),
            vetted_of: vetted_of
                .as_ref()
                .map(|f| f as &dyn Fn(&str) -> Option<std::collections::BTreeSet<String>>),
            stored_unassignment: stored_unassignment.as_ref(),
        };
        let decide_outcome = crate::reassignment_receive::decide_with_phase7(
            received,
            &request.root_hash,
            &self.config.physical_synchronizer_id,
            &self.config.hosted_parties,
            &verify,
            &self.ledger,
            &ctx,
        );
        let mut decision = decide_outcome.decision;
        let decision_time = self.config.timeouts.decision_time(request_time);
        // [CANTON-NOTE: SEMANTICS] `ReassignmentProcessingSteps.scala:530-564`: run Phase 3 locking whenever Phase 7 preconditions
        // hold (`phase7_valid`), keeping `LocalAbstain` for non-reassigning participants even on activeness conflicts and applying the
        // commit set on an approving mediator verdict.
        if decide_outcome.phase7_valid {
            if let Ok(r) = received {
                let (leaving, arriving, counters) =
                    crate::reassignment_receive::effects(r, &self.ledger);
                match &decision.outcome {
                    Outcome::Approve | Outcome::Abstain(_) => {
                        if let Err(conflict) = self.ledger.begin_reassignment(
                            request_time,
                            r.common.kind,
                            leaving.clone(),
                            arriving.clone(),
                            counters.clone(),
                            decision_time,
                        ) {
                            if matches!(conflict, crate::view_acs::Conflict::Journal(_)) {
                                return Err(format!(
                                    "the reassignment cannot be begun: {conflict:?}"
                                ));
                            }
                            if decide_outcome.is_reassigning {
                                decision.outcome = Outcome::Reject(format!("{conflict:?}"));
                            }
                            step.notes.push(format!(
                                "reassignment request {request_time} activeness conflict: {conflict:?}"
                            ));
                            self.ledger
                                .keep_refused_reassignment(
                                    request_time,
                                    r.common.kind,
                                    leaving,
                                    arriving,
                                    counters,
                                    decision_time,
                                )
                                .map_err(|c| format!("the reassignment cannot be kept: {c:?}"))?;
                        } else if decide_outcome.is_reassigning
                            && r.common.kind == crate::reassignment_wire::Kind::Unassignment
                            && matches!(decision.outcome, Outcome::Approve)
                        {
                            if let Some(target) = &r.target {
                                fn logical(psid: &str) -> &str {
                                    psid.rsplit_once("::").map_or(psid, |(l, _)| l)
                                }
                                let pairs: Vec<(&str, i64)> = r
                                    .contracts
                                    .iter()
                                    .map(|c| (c.contract_id.as_str(), c.counter))
                                    .collect();
                                let rid = crate::reassignment_wire::reassignment_id(
                                    logical(&r.common.synchronizer),
                                    logical(target),
                                    request_time,
                                    &pairs,
                                );
                                let stored = crate::reassignment_receive::StoredUnassignment {
                                    contracts: r
                                        .contracts
                                        .iter()
                                        .map(|c| {
                                            crate::reassignment_receive::StoredReassignedContract {
                                                contract_id: c.contract_id.clone(),
                                                counter: c.counter,
                                                source_validation_package_id: c
                                                    .source_validation_package_id
                                                    .clone(),
                                                target_validation_package_id: c
                                                    .target_validation_package_id
                                                    .clone(),
                                                instance: c.instance.clone(),
                                            }
                                        })
                                        .collect(),
                                    stakeholders: r.common.stakeholders.iter().cloned().collect(),
                                    reassigning_participants: r
                                        .common
                                        .reassigning_participant_uids
                                        .iter()
                                        .cloned()
                                        .collect(),
                                    unassignment_ts: request_time,
                                };
                                if let Some(store) = &self.store {
                                    let json = serde_json::to_string(&stored).map_err(|e| {
                                        format!("encode pending stored unassignment: {e}")
                                    })?;
                                    store.append(
                                        STORED_UNASSIGNMENTS_JOURNAL,
                                        &format!("P\t{request_time}\t{rid}\t{json}"),
                                    )?;
                                }
                                self.pending_unassignments
                                    .insert(request_time, (rid, stored));
                            }
                        }
                    }
                    Outcome::Reject(_) => {
                        self.ledger
                            .keep_refused_reassignment(
                                request_time,
                                r.common.kind,
                                leaving,
                                arriving,
                                counters,
                                decision_time,
                            )
                            .map_err(|c| format!("the reassignment cannot be kept: {c:?}"))?;
                    }
                    Outcome::Malformed(_) => {}
                }
            }
        }
        step.notes.push(format!(
            "reassignment request {request_time}: {:?} for {:?}",
            decision.outcome, decision.confirming_parties
        ));
        let decisions = if decision.confirming_parties.is_empty()
            && !matches!(decision.outcome, Outcome::Malformed(_))
        {
            Vec::new()
        } else {
            vec![decision]
        };
        self.record_answer(
            request_time,
            &request.root_hash,
            request.mediator_group,
            decisions,
            step,
        )
    }

    /// Puts into force the changes that took effect **before** `now` (a request sequenced at `now` is judged by what was in force before it),
    /// and hands what that learned to the configuration.
    fn apply_due_topology(&mut self, now: i64, step: &mut Step) {
        if !self.config.follow_topology || self.pending_topology.iter().all(|(at, _)| *at >= now) {
            return;
        }
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_topology)
            .into_iter()
            .partition(|(at, _)| *at < now);
        self.pending_topology = later;
        if let Some(tracker) = self.tracker.as_mut() {
            // the transactions of one event (one broadcast) take effect together and are one batch
            let mut batch_at = None;
            for (at, stored) in &due {
                if batch_at != Some(*at) {
                    tracker.end_batch();
                    tracker.begin_batch();
                    batch_at = Some(*at);
                }
                step.notes.push(tracker.apply_stored(stored));
            }
            tracker.end_batch();
        }
        if let Some(tracker) = &self.tracker {
            // the keys follow the topology too: a participant that joins is trusted from its key mapping on
            let learned = tracker.learned();
            self.config.hosted_parties = learned.hosted_parties;
            self.config.submitter_keys = learned.submitter_keys;
            self.add_own_key();
            self.config.mediator_keys = learned.mediator_keys;
            self.config.peer_encryption_keys = learned.encryption_keys;
            if let Some(t) = learned.timeouts {
                self.config.timeouts = t;
            }
        }
    }

    /// How far a request's times may be from its sequencing time: the synchronizer's parameters in force.
    ///
    /// [CANTON-NOTE: SEMANTICS] Canton reads them with `findDynamicSynchronizerParametersOrDefault`: without parameters (a runtime configured
    /// by hand follows no topology, or the state named none) the defaults hold.
    fn time_tolerances(&self) -> TimeTolerances {
        self.tracker
            .as_ref()
            .and_then(|t| t.parameters())
            .map(|(_, parameters)| TimeTolerances::of(parameters))
            .unwrap_or_default()
    }

    /// The topology state the runtime follows; `None` for a runtime configured by hand.
    pub fn topology(&self) -> Option<&crate::topology_state::Tracker> {
        self.tracker.as_ref()
    }

    /// How many topology changes wait for their effective time.
    pub fn pending_topology_changes(&self) -> usize {
        self.pending_topology.len()
    }

    /// Active vetted package IDs known for `participant_uid` in the tracked topology state.
    pub fn vetted_packages_of(
        &self,
        participant_uid: &str,
    ) -> Option<std::collections::BTreeSet<String>> {
        self.tracker
            .as_ref()?
            .learned()
            .vetted_packages
            .get(participant_uid)
            .cloned()
    }

    /// All active vetted package sets keyed by `participant_uid`.
    pub fn learned_vetted_packages(
        &self,
    ) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
        self.tracker
            .as_ref()
            .map(|t| t.learned().vetted_packages)
            .unwrap_or_default()
    }

    /// Latest tracked topology serial for `VettedPackages` of `participant_uid`.
    pub fn vetted_serial_of(&self, participant_uid: &str) -> Option<u32> {
        self.tracker
            .as_ref()
            .and_then(|t| t.vetted_serial_of(participant_uid))
    }

    /// Whether an envelope that does not decrypt is nonetheless a view addressed to this participant (its session key entry exists):
    /// such a request must be answered as malformed, not ignored.
    fn is_view_for_this_participant(&self, envelope: &[u8]) -> bool {
        matches!(
            crate::view_receive::decrypt_views(
                envelope,
                &self.config.encryption_fingerprint,
                &self.config.encryption_secret,
            ),
            Err(e) if e != crate::view_receive::ReceiveError::NotAnEncryptedViewMessage
                && e != crate::view_receive::ReceiveError::NoSessionKeyForThisParticipant
        )
    }

    /// Loads the topology state the synchronizer gives a member that joined (see [`Config::follow_topology`]) and replays what the
    /// journal holds of the broadcasts seen since. Returns what the participant learned.
    ///
    /// [CANTON-NOTE: SEMANTICS] The downloaded state is the state **as of the onboarding**, so the events after it have to be read
    /// from the onboarding on: a fresh runtime has to start at or before it.
    pub fn load_topology(
        &mut self,
        connection: &mut SequencerConnect,
        token: &Token,
    ) -> Result<crate::topology_state::Learned, String> {
        let state = connection
            .download_topology_state_in_force(
                &self.config.member,
                &self.config.physical_synchronizer_id,
                token,
            )
            .map_err(|e| e.to_string())?;
        // [CANTON-NOTE: SEMANTICS] Propagate parameter/crypto-spec lookup errors cleanly (`GrpcInternalSequencerConnection.scala:347-357`)
        // instead of silently falling back to unrestricted key validation.
        let specs = Some(connection.required_schemes().map_err(|e| e.to_string())?);
        let entries = crate::topology_state::decode(&state)?;
        self.load_topology_state_with_specs(&entries, specs)
    }

    /// Starts following the topology from `entries` (the state a synchronizer handed out), then replays what the journal holds of the
    /// broadcasts seen since. Returns what the participant learned; an error when the configured synchronizer id does not parse.
    pub fn load_topology_state(
        &mut self,
        entries: &[crate::topology_state::Entry],
    ) -> Result<crate::topology_state::Learned, String> {
        self.load_topology_state_with_specs(entries, None)
    }

    fn load_topology_state_with_specs(
        &mut self,
        entries: &[crate::topology_state::Entry],
        specs: Option<crate::crypto_handshake::Required>,
    ) -> Result<crate::topology_state::Learned, String> {
        let mut tracker = crate::topology_state::Tracker::for_synchronizer(
            entries,
            &self.config.member,
            &self.config.physical_synchronizer_id,
        )?;
        if let Some(specs) = specs {
            tracker.set_crypto_specs(specs);
        }
        for stored in self.journaled_topology() {
            tracker.apply_stored(&stored);
        }
        let learned = tracker.learned();
        self.config.hosted_parties = learned.hosted_parties.clone();
        self.config.submitter_keys = learned.submitter_keys.clone();
        self.add_own_key();
        self.config.mediator_keys = learned.mediator_keys.clone();
        self.config.peer_encryption_keys = learned.encryption_keys.clone();
        if let Some(t) = learned.timeouts {
            self.config.timeouts = t;
        }
        self.tracker = Some(tracker);
        Ok(learned)
    }

    /// The participants that host `party` as the followed topology says (member id, permission: 1 submission, 2 confirmation,
    /// 3 observation) with the encryption key of each when the topology has one. Empty when the topology is not followed or names none.
    pub fn hosts_of(
        &self,
        party: &str,
    ) -> Vec<(String, i32, Option<crate::topology_state::EncryptionKey>)> {
        let Some(tracker) = &self.tracker else {
            return Vec::new();
        };
        let Some((_, hosts)) = tracker.hosts_of(party) else {
            return Vec::new();
        };
        hosts
            .into_iter()
            .map(|(uid, permission)| {
                let member = format!("PAR::{uid}");
                let key = self
                    .config
                    .peer_encryption_keys
                    .get(&member)
                    .and_then(|keys| keys.first().cloned());
                (member, permission, key)
            })
            .collect()
    }

    /// Reads the events after the cursor that arrive within `wait`, handles each, and sends the answers that are still in time.
    /// Returns what the steps led to, in order.
    pub fn poll(
        &mut self,
        connection: &mut SequencerConnect,
        token: &Token,
        signing_key: &Ed25519Key,
        wait: Duration,
    ) -> Result<Vec<Step>, String> {
        self.poll_until(connection, token, signing_key, wait, &mut |_| false)
    }

    /// Like [`Runtime::poll`], and returns as soon as `stop` says so about a step (the step is included), instead of at the end of `wait`.
    /// A submitter waits for the verdict of its request this way: the verdict is the event that matters, not the end of a window.
    pub fn poll_until(
        &mut self,
        connection: &mut SequencerConnect,
        token: &Token,
        signing_key: &Ed25519Key,
        wait: Duration,
        stop: &mut dyn FnMut(&Step) -> bool,
    ) -> Result<Vec<Step>, String> {
        if let Some(refused) = self.subscription.halted() {
            self.last_subscribe_error = Some(refused.to_string());
            return Ok(Vec::new());
        }
        if self.config.follow_topology && self.tracker.is_none() {
            self.load_topology(connection, token)?;
        }
        if self.config.follow_topology && self.subscription.sequencer().is_none() {
            let id = connection.synchronizer_id().map_err(|e| e.to_string())?;
            self.connected_to(&id.sequencer_uid);
        }
        let mut steps = Vec::new();
        let deadline = std::time::Instant::now() + wait;
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let from = self.subscription.subscribe_from(self.cursor);
            // a wait that ends without an event is reported as an error of the stream: ask again until the time is up
            let events = match connection.subscribe(
                &self.config.member,
                &self.config.physical_synchronizer_id,
                token,
                Some(from),
                1,
                remaining,
            ) {
                Ok(ev) => {
                    self.last_subscribe_error = None;
                    ev
                }
                Err(err) => {
                    self.last_subscribe_error = Some(err.to_string());
                    self.subscription.broken();
                    Vec::new()
                }
            };
            let Some(raw) = events.first() else {
                // nothing more is coming: the sequencer's clock tells when a change that waits for its effective time is in force
                if !self.pending_topology.is_empty() {
                    if let Ok(Some(now)) = connection.sequencer_time(
                        &self.config.member,
                        &self.config.physical_synchronizer_id,
                        Some(token),
                    ) {
                        let mut step = Step::default();
                        self.apply_due_topology(now, &mut step);
                        if !step.notes.is_empty() {
                            step.topology_changed = true;
                            steps.push(step);
                        }
                    }
                }
                // [CANTON-NOTE: WHY] Never past the end of the window: a reader that holds the node for a short slice must give it back on time.
                std::thread::sleep(
                    Duration::from_millis(200)
                        .min(deadline.saturating_duration_since(std::time::Instant::now())),
                );
                continue;
            };
            let mut step = match self.receive(raw) {
                Ok(Some(step)) => step,
                Ok(None) => continue,
                Err(NotHandled::Refused(refused)) => {
                    self.last_subscribe_error = Some(refused.to_string());
                    break;
                }
                Err(NotHandled::Failed(why)) => return Err(why),
            };
            let event_time = self.cursor;
            let mut sent = Vec::new();
            for answer in std::mem::take(&mut step.to_send) {
                let now = connection
                    .sequencer_time(
                        &self.config.member,
                        &self.config.physical_synchronizer_id,
                        Some(token),
                    )
                    .map_err(|e| e.to_string())?
                    .unwrap_or(event_time);
                if self.config.timeouts.too_late(answer.request_time, now) {
                    step.notes.push(format!(
                        "the answer to {} would be too late for the mediator",
                        answer.request_time
                    ));
                    continue;
                }
                self.send(connection, token, signing_key, &answer, now)?;
                sent.push(answer);
            }
            step.to_send = sent;
            if let Err(why) = self.send_commitments(
                connection,
                token,
                signing_key,
                &step.commitments,
                event_time,
            ) {
                step.notes
                    .push(format!("the ACS commitments were not sent: {why}"));
                step.commitments.clear();
            }
            let done = stop(&step);
            steps.push(step);
            if done {
                break;
            }
        }
        Ok(steps)
    }

    fn send(
        &self,
        connection: &mut SequencerConnect,
        token: &Token,
        signing_key: &Ed25519Key,
        answer: &ToSend,
        now: i64,
    ) -> Result<(), String> {
        let (content, signatures) = confirmation_responses(
            answer.request_time,
            &answer.root_hash,
            &self.config.physical_synchronizer_id,
            &self.config.member,
            &answer
                .decisions
                .iter()
                .map(|d| ViewResponse {
                    view_position: &d.view_position,
                    outcome: d.outcome.clone(),
                    confirming_parties: &d.confirming_parties,
                })
                .collect::<Vec<_>>(),
            signing_key,
        );
        let message_id = format!("resp-{}", answer.request_time);
        let signed = signed_submission_request(
            submission_request_signed(
                &self.config.member,
                &message_id,
                &[(
                    vec![mediator_group(answer.mediator_group)],
                    content,
                    signatures,
                )],
                // the mediator takes it until the response deadline; the sequencer must be able to sequence it by then
                self.config
                    .timeouts
                    .response_deadline(answer.request_time)
                    .max(now + 1_000_000),
            ),
            signing_key,
        );
        connection
            .send_async(
                &self.config.member,
                &self.config.physical_synchronizer_id,
                token,
                self.pay(signed, signing_key),
            )
            .map_err(|e| e.to_string())
    }
}

/// The facts of the requests a verdict may still resolve, read from `store`, which is left holding only those.
///
/// [CANTON-NOTE: SEMANTICS] `cursor` is the sequencing time of the last event handled: a request whose decision time is before it has
/// expired. A line the process died writing does not parse and is skipped: that request's verdict is checked as an unknown one's.
fn open_requests(
    store: &dyn crate::state_store::StateStore,
    cursor: i64,
) -> Result<std::collections::BTreeMap<i64, RequestFacts>, String> {
    let journal = store.read(REQUESTS_JOURNAL)?.unwrap_or_default();
    let recorded = journal.lines().count();
    let requests: std::collections::BTreeMap<i64, RequestFacts> = journal
        .lines()
        .filter_map(RequestFacts::parse)
        .filter(|(_, facts)| facts.decision_time >= cursor)
        .collect();
    if requests.len() < recorded {
        let kept: String = requests
            .iter()
            .map(|(request, facts)| format!("{}\n", facts.record(*request)))
            .collect();
        store.write(REQUESTS_JOURNAL, &kept)?;
    }
    Ok(requests)
}

/// The keys a request's signature may be made with when `submitting` (a participant uid) is the submitting participant the request names.
///
/// [CANTON-NOTE: SEMANTICS] With the topology followed: that participant's signing keys in force, and this participant's own key when it is
/// the one named (`own`: its uid and key, see [`Runtime::trust_own_submissions`]); another participant's key does not do.
/// [CANTON-NOTE: LIMITATION] A runtime configured by hand does not know whose key is whose: every key it was given (`configured`) stays
/// trusted for every submitter, as before. A signature on a tree whose submitter metadata is blinded (Canton does not verify one there) is
/// verified against `configured` too, which is every other participant's key when the topology is followed.
fn submitter_keys(
    tracker: Option<&crate::topology_state::Tracker>,
    configured: &[PublicKey],
    own: Option<(&str, &PublicKey)>,
    submitting: Option<&str>,
) -> Vec<PublicKey> {
    match (tracker, submitting) {
        (Some(tracker), Some(submitting)) => {
            let mut keys = tracker
                .signing_keys_of(&format!("PAR::{submitting}"))
                .unwrap_or_default();
            if let Some((_, key)) = own.filter(|(me, _)| *me == submitting) {
                keys.push(key.clone());
            }
            keys
        }
        _ => configured.to_vec(),
    }
}

#[cfg(test)]
mod tests;
