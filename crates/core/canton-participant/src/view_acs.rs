//! The active contract set a receiving participant keeps, and the conflict checks that stop a contract from being used twice
//! (G5 5.6k, S-NET-019).
//!
//! [CANTON-NOTE: SEMANTICS] A participant must not confirm a request that uses a contract that is not **active**, because the ledger
//! model forbids consuming a contract twice (and using an archived one). Canton does this with a conflict detector over the
//! participant's ACS; this module is the same discipline in small:
//! - A contract becomes **active** only when a request that creates it is **approved**: the mediator's verdict (a
//!   `ConfirmationResultMessage`, signed by the mediator) decides, not the participant's own validation.
//! - A request that consumes or creates contracts **locks** them while it is *in flight* (validated, verdict not yet received): a second
//!   request that touches a locked contract is refused (`LockedContract`), and so is one that consumes a contract that is not active
//!   (`UnknownContract`) or was already archived (`ArchivedContract`, naming the request that archived it).
//! - On an approved verdict the effects are applied (consumed contracts are archived, created ones become active); on any other
//!   verdict the locks are released and nothing changes. A request this participant refused keeps the effects of its conforming views
//!   without locking them (`Ledger::keep_refused`): the mediator may approve it anyway, and then they are applied too.
//! - A contract a request fetches or exercises without consuming it must be active and not locked by another request; it is not locked.
//!
//! - **Persistence** is an append-only **journal** (one record per line: `I` import, `B` begin, `R` resolve), written and synced
//!   **before** the change is applied in memory (write-ahead), so a restart replays it to the same state: contracts, archived
//!   contracts, the requests that were in flight (still locking what they touch) and the requests already decided. A last line that
//!   is incomplete (the process died while writing it) is ignored and cut off. Because a participant that restarts re-reads the
//!   sequenced events from where it last stopped, **processing is idempotent**: a request that was already begun is
//!   `RequestAlreadyInFlight`, one already decided `RequestAlreadyDecided`, and a verdict for a decided request is ignored.
//! - **Import** adds a contract that exists since before this participant hosted a stakeholder of it (an ACS snapshot). It does not
//!   trust the exporter: `view_conformance::import_contract` authenticates the instance (the engine reproduces it and the id is the
//!   unicum of its stored contract salt) before the contract is recorded.
//!
//! - **Time limits** (G5 5.6n, S-NET-022): a request has a **response deadline** (the sequencing time of the request plus the
//!   synchronizer's `confirmationResponseTimeout`: after it the mediator no longer accepts responses and, if a confirming party has
//!   not answered, finalizes the request as timed out) and a **decision time** (plus `mediatorReactionTimeout` as well: the time by which
//!   a participant must have the verdict; without it the participant treats the request as **rejected**). `Ledger::begin_until` records
//!   the decision time, `Ledger::expire(now)` resolves the requests whose decision time has passed as rejected and frees their locks.
//!
//! [CANTON-NOTE: LIMITATION] Requests are processed in the order the caller feeds them (the sequencing order); contract keys are not
//! checked or locked here. The journal grows without compaction; it holds the
//! participant's contract state, not the sequencer cursor (the caller re-subscribes from the last verdict it applied).
use std::collections::{BTreeMap, BTreeSet};

mod ledger;
#[cfg(test)]
mod tests;
mod verdict;

pub(crate) use verdict::contract_of;
pub use verdict::{
    decode_verdict, effects_of, mediator_signed, mediator_signed_at, Verdict, VerdictKind,
};

/// Boxed payload for [`RemoteEvent::Exercise`] so the enum stays compact (`large_enum_variant`).
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteExercise {
    pub depth: usize,
    pub contract_id: String,
    pub input_instance: Vec<u8>,
    pub choice: String,
    pub consuming: bool,
    pub actors: Vec<String>,
    pub observers: Vec<String>,
    pub interface_id: Option<String>,
    pub argument: lf_eval::Value,
    pub result: Option<lf_eval::Value>,
}

/// Replayed Ledger-API-level event derived from a conforming view for remote participants (`S-DX-005`).
#[derive(Debug, Clone, PartialEq)]
pub enum RemoteEvent {
    Create {
        depth: usize,
        contract_id: String,
        instance: Vec<u8>,
    },
    Exercise(Box<RemoteExercise>),
    Fetch {
        depth: usize,
        /// The fetched contract (hex id), its instance as the view carries it, the fetch's acting parties and the interface it was fetched
        /// through (U-56: what an externally signed hash covers). Empty when restored from the outbox journal, which keeps the depth only.
        contract_id: String,
        input_instance: Vec<u8>,
        actors: Vec<String>,
        interface_id: Option<String>,
    },
}

/// What a request does to the contract set: the contracts it archives and the ones it creates (id as hex, template id).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Effects {
    pub consumes: Vec<String>,
    pub creates: Vec<(String, String)>,
    /// The serialized instances of the created contracts, in the order of `creates` (empty when the effects did not come from a view).
    pub instances: Vec<Vec<u8>>,
    /// Ordered transaction tree events replayed from conforming views for remote `LEDGER_EFFECTS` publication (`S-DX-005`).
    pub remote_events: Vec<RemoteEvent>,
}

impl Effects {
    fn created_ids(&self) -> BTreeSet<&String> {
        self.creates.iter().map(|(id, _)| id).collect()
    }
}

/// What an approved request changed in the contract set, with the instances of what it created.
#[derive(Debug, Clone, PartialEq)]
pub struct Applied {
    pub request_id: i64,
    pub consumed: Vec<String>,
    /// `(contract id, serialized instance)`.
    pub created: Vec<(String, Vec<u8>)>,
    /// Set when the request was a reassignment: its kind and the counters it set. An unassignment's `consumed` contracts **left** this
    /// synchronizer (they are not archived); an assignment's `created` ones **arrived**.
    pub reassignment: Option<(crate::reassignment_wire::Kind, Vec<(String, i64)>)>,
    /// Root hash bytes (`1220...` multihash) of the approved transaction tree, used as Ledger API `updateId`.
    pub root_hash: Vec<u8>,
    /// Ordered remote events produced during view conformance for `LEDGER_EFFECTS` / `ACS_DELTA` projection (`S-DX-005`).
    pub remote_events: Vec<RemoteEvent>,
}

/// The two time limits of a confirmation request, from the synchronizer's dynamic parameters (microseconds).
///
/// [CANTON-NOTE: SEMANTICS] Read from `DynamicSynchronizerParameters`: `confirmationResponseTimeout` is how long after the request's
/// sequencing time responses are accepted; `decisionTimeout = confirmationResponseTimeout + mediatorReactionTimeout` is how long a
/// participant waits for the verdict. The defaults are 30 s each; the sandbox's topology state confirms them (and the mediator's
/// `Finalized ... at <time>` of a timed-out request *is* the decision time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub confirmation_response_micros: i64,
    pub mediator_reaction_micros: i64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            confirmation_response_micros: 30_000_000,
            mediator_reaction_micros: 30_000_000,
        }
    }
}

impl Timeouts {
    /// The last time (sequencing time) at which the mediator takes a response to the request sequenced at `request_time`.
    pub fn response_deadline(&self, request_time: i64) -> i64 {
        request_time + self.confirmation_response_micros
    }

    /// The time by which the participant must have the verdict of the request sequenced at `request_time`.
    pub fn decision_time(&self, request_time: i64) -> i64 {
        request_time + self.confirmation_response_micros + self.mediator_reaction_micros
    }

    /// Whether an answer sequenced at `now` is too late for the request sequenced at `request_time`.
    pub fn too_late(&self, request_time: i64, now: i64) -> bool {
        now > self.response_deadline(request_time)
    }
}

/// Why a request is refused by the contract set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conflict {
    /// The contract is not active here (never created by a request this participant saw approved).
    UnknownContract(String),
    /// The contract was consumed by an earlier request (its sequencing time).
    ArchivedContract { id: String, by_request: i64 },
    /// A request in flight (not yet decided) uses the contract.
    LockedContract { id: String, by_request: i64 },
    /// A contract with this id is already active, archived or being created.
    ContractAlreadyExists(String),
    /// The request was begun before and its verdict is not in yet.
    RequestAlreadyInFlight(i64),
    /// The request was begun and decided before (the caller processes an event again after a restart).
    RequestAlreadyDecided(i64),
    /// The journal could not be written, so the change was not made.
    Journal(String),
}

/// Where a ledger's journal lives: a key of a [`StateStore`] (a file of a directory, or the lines of a database).
struct Journal {
    store: std::sync::Arc<dyn crate::state_store::StateStore>,
    key: String,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "journal {:?} in {}", self.key, self.store.describe())
    }
}

/// The contract set of a participant.
#[derive(Debug, Default)]
pub struct Ledger {
    active: BTreeMap<String, String>,
    archived: BTreeMap<String, i64>,
    /// contract id -> the in-flight request that consumes it
    consumed_by: BTreeMap<String, i64>,
    /// contract id -> the in-flight request that creates it
    created_by: BTreeMap<String, i64>,
    pending: BTreeMap<i64, Effects>,
    /// request -> the effects of the views this participant refused although they conform: what an approving verdict still commits
    /// (see [`Ledger::keep_refused`]). They lock nothing.
    refused: BTreeMap<i64, Effects>,
    /// request -> the time by which its verdict must be in (`i64::MAX`: no limit)
    decision_times: BTreeMap<i64, i64>,
    decided: BTreeSet<i64>,
    /// requests this participant has already answered to the mediator (or decided not to answer): never answered twice
    answered: BTreeSet<i64>,
    journal: Option<Journal>,
    /// What the last approved resolution changed, until it is taken ([`Ledger::take_applied`]).
    applied: Option<Applied>,
    /// The reassignment requests in flight: request -> (the contracts it takes off this synchronizer, the counters it sets).
    reassigning: BTreeMap<i64, Reassigning>,
    /// contract id -> the approved unassignment that took it off this synchronizer (it is not archived: it lives on elsewhere)
    unassigned: BTreeMap<String, i64>,
    /// contract id -> its reassignment counter, for the contracts a reassignment touched (absent: 0)
    counters: BTreeMap<String, i64>,
    /// The instances of the contracts the journal's replay made active, until taken ([`Ledger::take_replayed_instances`]).
    replayed_instances: BTreeMap<String, Vec<u8>>,
    /// Active keyed contracts indexed by 32-byte key hash -> (contract_id -> stakeholders), for U-21 exhaustive key query checks.
    active_keys: BTreeMap<Vec<u8>, BTreeMap<String, BTreeSet<String>>>,
    /// Reverse index from active contract_id to its 32-byte key hash for removal on archive/unassign/purge.
    contract_key_hash: BTreeMap<String, Vec<u8>>,
}

/// The instances of a `B` or `F` record: hex, comma-separated.
///
/// [CANTON-NOTE: INVARIANT] Kept with the request they belong to, in the same record: a request begun before a restart and approved after it
/// still hands over what it created (P-13). Records written before they were kept have no such field and replay without instances.
pub(super) fn join_instances(instances: &[Vec<u8>]) -> String {
    instances
        .iter()
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn split_instances(field: Option<&str>) -> Vec<Vec<u8>> {
    field
        .map(|f| {
            split_list(f)
                .iter()
                .filter_map(|i| hex::decode(i).ok())
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn join_creates(creates: &[(String, String)]) -> String {
    creates
        .iter()
        .map(|(id, t)| format!("{id}={t}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// A reassignment in flight: the contracts it takes off this synchronizer, and the counters it sets.
pub(super) type Reassigning = (
    crate::reassignment_wire::Kind,
    Vec<String>,
    Vec<(String, i64)>,
);

pub(super) fn kind_code(kind: crate::reassignment_wire::Kind) -> &'static str {
    match kind {
        crate::reassignment_wire::Kind::Unassignment => "U",
        crate::reassignment_wire::Kind::Assignment => "A",
    }
}

pub(super) fn decode_kind(code: &str) -> Option<crate::reassignment_wire::Kind> {
    match code {
        "U" => Some(crate::reassignment_wire::Kind::Unassignment),
        "A" => Some(crate::reassignment_wire::Kind::Assignment),
        _ => None,
    }
}

pub(super) fn split_counters(field: &str) -> Vec<(String, i64)> {
    split_list(field)
        .into_iter()
        .filter_map(|c| {
            let (id, n) = c.split_once('=')?;
            Some((id.to_string(), n.parse().ok()?))
        })
        .collect()
}

pub(super) fn split_creates(field: &str) -> Vec<(String, String)> {
    split_list(field)
        .into_iter()
        .filter_map(|c| {
            c.split_once('=')
                .map(|(i, t)| (i.to_string(), t.to_string()))
        })
        .collect()
}

pub(super) fn split_list(field: &str) -> Vec<String> {
    field
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}
