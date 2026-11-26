//! A participant that submits (F2 of `doc/performance/EQUAL-CONDITIONS.md`): commands in, the synchronizer's verdict out.
//!
//! [`Node`] joins what the earlier slices built into the loop a Ledger API needs: a command becomes a request ([`crate::submit`]), the request
//! is sent to the sequencer, and the node reads the sequenced events ([`Runtime::poll_until`]) until the verdict about **its own request**
//! arrives. The node confirms for the parties it hosts through the same code that confirms other participants' requests: its own request comes
//! back as an event like any other, so the submitter's admin party and the signatories it hosts answer through `Runtime::step`.
//!
//! [CANTON-NOTE: SEMANTICS] A command returns when the verdict is known, not when it was sent: this is what makes the time of a command the
//! time of the whole protocol (view decomposition, sequencing, the mediator's decision), as it is on the official participant.
//!
//! Many threads can submit at once through [`SharedNode`]; [`Node`] itself is the single-threaded core.
//!
//! [CANTON-NOTE: LIMITATION] The commands [`crate::submit`] can build: a create of a template without a key whose argument [`crate::value_forms`]
//! can write, and a consuming or non-consuming exercise without created contracts or children. Anything else is refused before it is sent.
//! The contracts the node can exercise are the ones it created itself (it keeps their instances); contracts created by other participants
//! are not imported. Hosted parties and the keys of the mediator come from the synchronizer's topology (`follow_topology`); the keys of other
//! participants that host a stakeholder are given with [`Node::add_peer`].
use crate::participant_runtime::Runtime;
use crate::sequencer_connect::{SequencerConnect, Token};
use crate::state_store::StateStore;
use crate::submit::{Built, NewInView, Peer, StoredContract};
use crate::topology_wire::ParticipantIdentity;
pub(super) use crate::view_conformance::open_instance;
use crate::view_conformance::OpenedContract;
use lf_eval::{Value, World};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

mod fates;
mod lifecycle;
mod multi_root;
mod reassignment;
mod shared;
mod shown;
mod submit;
mod topology;
pub use fates::ExerciseCommand;
pub use multi_root::{ExerciseRoot, RootCommand, TransactionCommand};
pub use shared::{Reader, SharedNode};

/// The synchronizer's decision about a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Approved,
    Rejected,
}

/// A transaction another participant (or this one) got approved, as this participant has to show it to its parties: the contracts it created
/// (read from the views) and the ids it consumed.
#[derive(Debug, Clone)]
pub struct RemoteTransaction {
    pub request_id: i64,
    pub created: Vec<OpenedContract>,
    pub consumed: Vec<String>,
    /// Set for a reassignment (see `view_acs::Applied::reassignment`): `consumed` left this synchronizer, `created` arrived.
    pub reassignment: Option<(crate::reassignment_wire::Kind, Vec<(String, i64)>)>,
    /// Root hash bytes (`1220...` multihash) of the approved transaction tree.
    pub root_hash: Vec<u8>,
    /// Ordered transaction tree events replayed during view conformance for `LEDGER_EFFECTS` projection (`S-DX-005`).
    pub events: Vec<crate::view_acs::RemoteEvent>,
}

/// Called, outside the node, with every approved transaction this node did not submit itself.
/// Returning `Err` keeps the transaction unshown so a journal/sink failure retries across restarts.
pub type RemoteHandler = Box<dyn Fn(RemoteTransaction) -> Result<(), String> + Send + Sync>;

/// A contract's description for the protocol (see [`Node::describe`]).
pub struct Described {
    pub package_id: String,
    pub module: Vec<String>,
    pub name: Vec<String>,
    pub arg: crate::contract_wire::LfValue,
    pub hash_arg: crate::contract_id::HashValue,
    pub signatories: Vec<String>,
    pub stakeholders: Vec<String>,
    pub key: Option<crate::submit::NewKey>,
}

impl Described {
    pub(super) fn in_view_at<'a>(
        &'a self,
        package_name: &'a str,
        path: &'a [i32],
    ) -> NewInView<'a> {
        NewInView {
            package_name,
            package_id: &self.package_id,
            module: &self.module,
            name: &self.name,
            arg: &self.arg,
            hash_arg: &self.hash_arg,
            signatories: &self.signatories,
            stakeholders: &self.stakeholders,
            key: self.key.as_ref(),
            path,
        }
    }
}

/// A contract an exercise creates, as the service's engine produced it.
pub struct CreatedByExercise<'a> {
    pub template: &'a str,
    pub payload: &'a Value,
    /// The id the engine already used for this contract; the request is refused if the protocol derives another.
    pub expected_id: &'a str,
}

/// A node below the root exercise of a transaction, as the engine's journal gives it (G8 P0/P4/P5/P6).
pub enum TreeNode<'a> {
    /// A nested exercise of a contract this node knows.
    Exercise {
        contract_id: &'a str,
        choice: &'a str,
        argument: Option<&'a Value>,
        consuming: bool,
        actors: Vec<String>,
        /// The choice's own observers (`ExerciseNode.choiceObservers`): informees of the exercise and recipients of its view.
        observers: Vec<String>,
        interface_id: Option<&'a str>,
        by_key: bool,
    },
    /// A fetch of a contract this node knows, with its acting parties.
    Fetch {
        contract_id: &'a str,
        actors: Vec<String>,
        interface_id: Option<&'a str>,
        by_key: bool,
    },
    /// A key query node: `lookupByKey` (at most one contract) or `lookupNByKey` (at most `n`); Daml-LF `QueryByKey` either way.
    Lookup {
        template: &'a str,
        key: &'a Value,
        /// The contracts the query found, in the order the engine found them.
        contract_ids: Vec<&'a str>,
    },
    Create(CreatedByExercise<'a>),
    /// A caught exception; the entries one level deeper that follow it are its children (S-SPL-028).
    Rollback,
}

/// A node below the root and its nesting depth (1 for a child of the root exercise); the entries are in the order the engine ran them.
pub struct TreeEntry<'a> {
    pub depth: usize,
    pub node: TreeNode<'a>,
}

/// A create request built and not sent, with the contract it will create.
pub struct PreparedCreate {
    pub built: Built,
    pub stored: StoredContract,
    pub command_id: String,
}

/// A submission of this node whose fate became known when nobody waited for it any more (the wait ended first, or the node restarted).
#[derive(Debug, Clone)]
pub struct LateFate {
    pub settled: crate::in_flight::Settled,
    /// What an approved submission changed, as this node shows another participant's transaction (`None` when it changed nothing here, or
    /// when the change was read before a restart: the contracts are then among the ones the node knows).
    pub transaction: Option<RemoteTransaction>,
}

/// Called, outside the node, with every [`LateFate`] (see [`SharedNode::on_late`]).
/// Returning `Err` keeps the fate un-handed-over so a journal/sink failure retries across restarts.
pub type LateHandler = Box<dyn Fn(LateFate) -> Result<(), String> + Send + Sync>;

/// The verdicts of the node's own requests, kept apart from the node so that a waiter can look for its verdict without holding the node.
///
/// [CANTON-NOTE: SEMANTICS] Whoever reads the sequencer's events records the verdict of **every** pending request, not just its own: events
/// are read once, in order, and a verdict that was read and not kept would never come again. This is what lets many requests wait at once
/// while one thread at a time reads the stream.
#[derive(Default)]
pub(super) struct Board {
    done: Mutex<BTreeMap<String, (Verdict, Vec<String>)>>,
    /// The request id of each awaited submission whose fate was read, until its waiter takes it (see [`SharedNode::awaited_recorded`]).
    pub(super) requests: Mutex<BTreeMap<String, Option<i64>>>,
    changed: Condvar,
    /// Set to stop the background reader.
    stop: std::sync::atomic::AtomicBool,
    /// Sequencing timestamp (microseconds) of the most recently approved request.
    last_approved: Mutex<Option<i64>>,
    /// Most recent background reader poll error (`None` once connected/healthy).
    poll_error: Mutex<Option<String>>,
}

impl Board {
    pub(super) fn note_poll(&self, res: &Result<(), String>) {
        if let Ok(mut g) = self.poll_error.lock() {
            match res {
                Ok(()) => *g = None,
                Err(why) => *g = Some(why.clone()),
            }
        }
    }

    pub(super) fn note_approved_time(&self, request_id: Option<i64>) {
        if let Some(t) = request_id {
            if let Ok(mut g) = self.last_approved.lock() {
                *g = Some(t);
            }
        }
    }

    pub(super) fn put(&self, message_id: &str, verdict: Verdict, notes: Vec<String>) {
        if let Ok(mut done) = self.done.lock() {
            done.insert(message_id.to_string(), (verdict, notes));
        }
        self.changed.notify_all();
    }

    pub(super) fn note_request(&self, message_id: &str, request_id: Option<i64>) {
        if let Ok(mut requests) = self.requests.lock() {
            requests.insert(message_id.to_string(), request_id);
        }
    }

    pub(super) fn take_request(&self, message_id: &str) -> Option<i64> {
        self.requests.lock().ok()?.remove(message_id).flatten()
    }

    pub(super) fn take(&self, message_id: &str) -> Option<(Verdict, Vec<String>)> {
        self.done.lock().ok()?.remove(message_id)
    }

    /// Sleeps up to `limit`, or until the board changes.
    pub(super) fn pause(&self, limit: Duration) {
        if let Ok(done) = self.done.lock() {
            let _ = self.changed.wait_timeout(done, limit);
        }
    }

    /// Waits up to `limit` for any change of the board.
    pub(super) fn wait_a_while(&self, message_id: &str, limit: Duration) {
        if let Ok(done) = self.done.lock() {
            if !done.contains_key(message_id) {
                let _ = self.changed.wait_timeout(done, limit);
            }
        }
    }
}

/// How often the background reader looks when nothing waits for a verdict: it must still read, because other participants' requests need this
/// participant's confirmation, but it need not hold the node all the time.
pub(super) const IDLE_PAUSE: Duration = Duration::from_millis(10);

/// The prefix of the note that carries a rejecting verdict's reason, or the sequencer's deliver error: `rejected by the verdict: <gRPC code>:<Status message>`.
pub const REJECTION_NOTE: &str = "rejected by the verdict: ";
/// The note that follows [`REJECTION_NOTE`] with what the refusing participant's reason adds (a JSON object, `Verdict::reject_context`).
pub const REJECTION_CONTEXT_NOTE: &str = "rejection context: ";
/// The prefix of the error a wait for a verdict ends with when its time is up and the submission is still in flight: its fate is not known
/// yet and comes later (a [`LateFate`]).
pub const STILL_IN_FLIGHT: &str = "still in flight: ";

/// How long one reader holds the node while it reads the stream; a submitter that needs the node waits at most this long.
///
/// [CANTON-NOTE: WHY] Short, because the reader holds the node while it blocks on the stream, and a submitter that needs the node to send
/// its request waits for the slice to end. With a slice longer than the time the synchronizer takes to judge a request, the requests could not
/// overlap at all: each reader would hold the node until its own verdict came.
pub(super) const READ_SLICE: Duration = Duration::from_millis(2);

pub struct Node {
    pub identity: ParticipantIdentity,
    /// What the runtime set aside and answered while the last request waited for its verdict (why it was rejected, when it was).
    pub last_notes: Vec<String>,
    pub runtime: Runtime,
    client: SequencerConnect,
    token: Token,
    physical: String,
    mediator_group: u32,
    user_id: String,
    world: World,
    vetted_package_ids: BTreeSet<String>,
    package_names_by_id: BTreeMap<String, String>,
    contracts: BTreeMap<String, StoredContract>,
    /// The unassignments this node submitted and the synchronizer approved whose assignment has not been approved yet, by reassignment id
    /// (each with this node's synchronizer, the source, and the target it was unassigned to). Kept in the state store (`unassigned.journal`): the official participant keeps an
    /// unassigned contract across a restart and takes the assign afterwards (tests/oracle/reassignment/json-api-restart-unassigned.jsonl).
    unassigned: BTreeMap<String, (ReassignmentDone, String, String)>,
    /// Where the state is kept (the contracts this node can exercise are the key `contracts.journal`), when the node has a state store.
    store: Option<Arc<dyn StateStore>>,
    directory: BTreeMap<String, Peer>,
    board: Arc<Board>,
    /// The most requests that were waiting for a verdict at the same time (evidence that waits overlapped).
    most_in_flight: usize,
    /// Approved transactions of other participants, waiting for the reader to hand them over.
    remote: Vec<RemoteTransaction>,
    /// The fates of this node's submissions nobody waited for, waiting for the reader to hand them over (see [`SharedNode::on_late`]).
    late: Vec<LateFate>,
    /// When to ask the sequencer for the time and to acknowledge what was read.
    clock: crate::sequencer_time::TimeKeeper,
}

pub(super) fn register_loaded_dar_package_names(
    archive: &lf_archive::DarArchive,
    map: &mut BTreeMap<String, String>,
) {
    if let Some(name) = &archive.package_name {
        map.insert(archive.main_package_id.clone(), name.clone());
    }
    for dalf in &archive.dalfs {
        if let Some(name) = &dalf.package_name {
            map.entry(dalf.package_id.clone())
                .or_insert_with(|| name.clone());
        }
    }
}

pub(super) fn parse_dar_package_names(
    dar: &Path,
    map: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let archive = lf_archive::parse_dar_file(dar).map_err(|e| e.to_string())?;
    register_loaded_dar_package_names(&archive, map);
    Ok(())
}

pub(super) fn split_qualified(template: &str) -> Result<(Option<&str>, &str, &str), String> {
    let mut parts = template.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(pkg), Some(module), Some(name), None)
            if pkg.len() == 64 && pkg.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Ok((Some(pkg), module, name))
        }
        (Some(module), Some(name), None, None) => Ok((None, module, name)),
        _ => Err(format!(
            "a template is [PackageId:]Module:Name, not {template}"
        )),
    }
}

/// A reassignment this node submitted and the synchronizer decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassignmentDone {
    pub verdict: Verdict,
    /// The request's sequencing time (its record time; for an unassignment also the time in the reassignment id).
    pub request_id: Option<i64>,
    pub reassignment_id: String,
    pub counter: i64,
    /// The contract instance as the request carried it.
    pub instance: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LiveTopologyCheck {
    Enforce,
    SkipForAllocation,
}

pub(super) struct CreateSpec<'a> {
    pub(super) package_name: &'a str,
    pub(super) template: &'a str,
    pub(super) payload: &'a Value,
    pub(super) command_id: &'a str,
    pub(super) now: Option<i64>,
    pub(super) topology_check: LiveTopologyCheck,
    /// A classic submission, or one its external parties authorized (U-56).
    pub(super) submission: crate::submit::Submission,
}

/// A contract this node can exercise, from a contract another participant created (its instance bytes as the view carried them).
pub(super) fn stored_from(opened: &OpenedContract, instance: &[u8]) -> StoredContract {
    let (module, name) = opened
        .template
        .split_once(':')
        .unwrap_or(("", &opened.template));
    StoredContract {
        contract_id_hex: opened.contract_id.clone(),
        instance: instance.to_vec(),
        package_id: opened.package_id.clone(),
        module: module.split('.').map(String::from).collect(),
        name: name.split('.').map(String::from).collect(),
        signatories: opened.signatories.iter().cloned().collect(),
        stakeholders: opened.stakeholders.iter().cloned().collect(),
    }
}

/// The journal line of a contract that became known: `+`, id, instance (hex), package, module, name, signatories, stakeholders.
pub(super) fn contract_line(c: &StoredContract) -> String {
    format!(
        "+\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        c.contract_id_hex,
        hex::encode(&c.instance),
        c.package_id,
        c.module.join("."),
        c.name.join("."),
        c.signatories.join(","),
        c.stakeholders.join(",")
    )
}

/// The pending unassignments a journal holds: every `+` line adds one, every `-` line removes it; an incomplete last line is ignored.
pub(super) fn replay_unassignments(
    text: &str,
) -> BTreeMap<String, (ReassignmentDone, String, String)> {
    let mut out = BTreeMap::new();
    for line in text.split_inclusive('\n') {
        if !line.ends_with('\n') {
            break;
        }
        let f: Vec<&str> = line.trim_end_matches('\n').split('\t').collect();
        match f.as_slice() {
            ["+", id, source, target, request_id, counter, instance] => {
                let (Ok(instance), Ok(counter)) = (hex::decode(instance), counter.parse()) else {
                    continue;
                };
                out.insert(
                    id.to_string(),
                    (
                        ReassignmentDone {
                            verdict: Verdict::Approved,
                            request_id: request_id.parse().ok(),
                            reassignment_id: id.to_string(),
                            counter,
                            instance,
                        },
                        source.to_string(),
                        target.to_string(),
                    ),
                );
            }
            ["-", id] => {
                out.remove(*id);
            }
            _ => {}
        }
    }
    out
}

/// The contracts a journal holds: every `+` line adds one, every `-` line removes it; an incomplete last line is ignored.
pub(super) fn replay_contracts(text: &str) -> BTreeMap<String, StoredContract> {
    let mut out = BTreeMap::new();
    let split = |field: &str| -> Vec<String> {
        field
            .split(',')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    };
    for line in text.split_inclusive('\n') {
        if !line.ends_with('\n') {
            break; // the process died while writing this line
        }
        let f: Vec<&str> = line.trim_end_matches('\n').split('\t').collect();
        match f.as_slice() {
            ["+", id, instance, package, module, name, signatories, stakeholders] => {
                let Ok(instance) = hex::decode(instance) else {
                    continue;
                };
                out.insert(
                    id.to_string(),
                    StoredContract {
                        contract_id_hex: id.to_string(),
                        instance,
                        package_id: package.to_string(),
                        module: module.split('.').map(String::from).collect(),
                        name: name.split('.').map(String::from).collect(),
                        signatories: split(signatories),
                        stakeholders: split(stakeholders),
                    },
                );
            }
            ["-", id] => {
                out.remove(*id);
            }
            _ => {}
        }
    }
    out
}
