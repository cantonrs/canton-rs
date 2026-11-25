//! The synchronizer behind the JSON API (F4 of `doc/performance/EQUAL-CONDITIONS.md`): a [`canton_participant::node::Node`] that judges every
//! transaction through the Rust protocol (views, sequencer, mediator) before the service applies it.
//!
//! [CANTON-NOTE: SEMANTICS] The protocol derives a contract's id from its content, its creation time and a random salt, and the engine needs the
//! id **when it creates the contract** (a choice body may already use it). So the id is promised first and the request built later: at allocation
//! the node builds the create request once with a recording [`Randomness`], keeps the draws and the time, and returns the id the request would
//! have; at commit it builds the request again from the same draws and time, which gives the same id, and sends it.
//!
//! [CANTON-NOTE: LIMITATION] A transaction with one root: a create of a template [`canton_participant::value_forms`] can write, or an exercise
//! of a contract the node knows whose subtree stays in one view (G8 P0): nested exercises and fetches of contracts the node knows, and creates
//! at any depth, placed by the engine's journal ([`lf_eval::NodePaths`]). Anything else is refused before it is sent, with the reason: a
//! contract used twice in the subtree, one created and consumed in the same transaction, a fetch whose acting parties are not agreed on by
//! every theory measured so far (see [`tree_shape`]), a create that was rolled back. A subtree whose nodes are visible to participants that do
//! not see the root (a view of its own) is not built: the request would carry too few views. The party ids are the participant's own
//! (`name::<namespace>`).
use crate::service::{ApiError, ExecutionService, RemoteApplied, TransactionCommit};
use canton_participant::node::{Node, Reader, SharedNode};
pub(in crate::protocol) use canton_participant::node::{TreeEntry, TreeNode};
use canton_participant::submit::{ExercisePlan, Randomness};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

mod committer;
mod errors;
mod official;
mod reassignment;
mod remote;
mod subview;
mod transaction;

pub(crate) use errors::sync_rejected;
pub use official::{official_updates_in, show_official_contracts_in};

fn join_journal_lines(lines: &[String]) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

pub(super) fn compact_journals(node: &SharedNode, state: &crate::v2::V2State, pruned_up_to: u64) {
    let mut update_lines = Vec::new();
    for u in state.updates() {
        match crate::snapshot::update_line(&u) {
            Ok(line) => update_lines.push(line),
            Err(e) => crate::diag::diag_eprintln!("compact updates.journal encode: {e}"),
        }
    }
    let mut completion_lines = Vec::new();
    for c in state.completions() {
        match crate::snapshot::completion_line(&c) {
            Ok(line) => completion_lines.push(line),
            Err(e) => crate::diag::diag_eprintln!("compact completions.journal encode: {e}"),
        }
    }
    let mut dedup_lines = Vec::new();
    if let Ok(d) = state.dedup.lock() {
        for (k, (off, at, sub)) in d.iter() {
            match crate::snapshot::dedup_line(k, (*off, *at, sub)) {
                Ok(line) => dedup_lines.push(line),
                Err(e) => crate::diag::diag_eprintln!("compact dedup.journal encode: {e}"),
            }
        }
    }
    let writes = [
        ("pruned.journal", format!("{pruned_up_to}\n")),
        ("updates.journal", join_journal_lines(&update_lines)),
        ("completions.journal", join_journal_lines(&completion_lines)),
        ("dedup.journal", join_journal_lines(&dedup_lines)),
    ];
    for (key, body) in writes {
        if let Err(e) = node.write_journal(key, &body) {
            crate::diag::diag_eprintln!("failed to rewrite {key} after prune: {e}");
        }
    }
}

/// What an allocation recorded: the random draws the request used and the time it was built at.
#[derive(Clone)]
pub(super) struct Recorded {
    pub(super) draws: Vec<[u8; 32]>,
    pub(super) now: i64,
}

#[derive(Default)]
pub(super) struct Recording(pub(super) Vec<[u8; 32]>);

impl Randomness for Recording {
    fn fresh(&mut self, label: &str) -> [u8; 32] {
        let bytes = canton_participant::submit::Os.fresh(label);
        self.0.push(bytes);
        bytes
    }
}

/// Replays recorded draws in order, then falls back to fresh randomness.
pub(super) struct Replay {
    pub(super) draws: Vec<[u8; 32]>,
    pub(super) at: usize,
}

impl Randomness for Replay {
    fn fresh(&mut self, label: &str) -> [u8; 32] {
        let bytes = self
            .draws
            .get(self.at)
            .copied()
            .unwrap_or_else(|| canton_participant::submit::Os.fresh(label));
        self.at += 1;
        bytes
    }
}

/// What allocation promised for the contracts one exercise creates: the plan their ids derive from and the ids, in the order of creation.
pub(super) struct ExerciseRecord {
    pub(super) plan: ExercisePlan,
    pub(super) ids: Vec<(usize, String)>,
}

/// How many promises are kept for transactions that were never committed (the engine failed after allocating).
pub(super) const MAX_PROMISES: usize = 4096;

/// A contract another participant created, as the service shows it.
/// `PAR::p1::122037a0652f...` as the official errors print a member.
pub(super) fn shorten_member(member: &str) -> String {
    match member.rsplit_once("::") {
        Some((head, fingerprint)) => {
            format!("{head}::{}...", &fingerprint[..fingerprint.len().min(12)])
        }
        None => member.to_string(),
    }
}

pub struct NodeCommitter {
    node: std::sync::Arc<SharedNode>,
    /// Keeps reading the synchronizer's events, so that requests of other participants are confirmed (stops when the committer is dropped).
    _reader: Reader,
    package_name: String,
    /// How long administrative calls (hosting a party, vetting, reassigning) wait.
    timeout: Duration,
    /// How long a command waits for its verdict before the caller is answered `REQUEST_TIME_OUT` (the command service's tracking timeout).
    tracking_timeout: Duration,
    recorded: Mutex<BTreeMap<String, Recorded>>,
    /// The exercises with promised ids, by session (see [`ProtocolCommitter::allocate_contract_id`]), and the session of each promised id.
    exercises: Mutex<BTreeMap<u64, ExerciseRecord>>,
    session_of: Mutex<BTreeMap<String, u64>>,
    /// The plans of prepared interactive exercises that create nothing, by command id (U-56): the execution builds its request with the
    /// plan its prepared transaction was read from.
    prepared_plans: Mutex<BTreeMap<String, ExercisePlan>>,
    sessions: std::sync::atomic::AtomicU64,
    commands: std::sync::atomic::AtomicU64,
    /// The transactions of several commands whose ids are being promised, by id (see [`ProtocolCommitter::begin_transaction`]).
    transactions: Mutex<BTreeMap<u64, transaction::Pending>>,
    /// Where the contract salts of what this node creates are written for the scan app (`record_salts_in`).
    recorder: std::sync::Arc<Mutex<Option<std::sync::Arc<crate::history::UpdateRecorder>>>>,
    /// The participant's other synchronizers, one node each with its reader (S-NET-040); `node` is the first and takes the transactions.
    others: Vec<(std::sync::Arc<SharedNode>, Reader)>,
    /// The alias of each synchronizer, `node` first (empty: one synchronizer, no alias given).
    aliases: Vec<String>,
    /// The unassignments this participant made, by reassignment id: what its assignment needs, and the source's physical id.
    /// The unassignments waiting for their assignment, by reassignment id: what the source node answered, the source and the target.
    unassigned:
        Mutex<BTreeMap<String, (canton_participant::node::ReassignmentDone, String, String)>>,
    /// The reassignment ids whose assignment was approved (the official participant says "reassignment already completed" for them).
    completed: Mutex<std::collections::BTreeSet<String>>,
}

use errors::invalid_argument;
pub(in crate::protocol) use errors::{command_tag, map_submit_err, refuse};
use official::to_remote;
use remote::hold_until_shown;
pub(in crate::protocol) use subview::{below_root, Below};

impl NodeCommitter {
    pub fn new(node: Node, package_name: &str, timeout: Duration) -> Self {
        let node = std::sync::Arc::new(SharedNode::new(node));
        hold_until_shown(&node);
        let reader = node.start_reader();
        Self {
            node,
            _reader: reader,
            package_name: package_name.to_string(),
            timeout,
            tracking_timeout: timeout,
            recorded: Mutex::new(BTreeMap::new()),
            exercises: Mutex::new(BTreeMap::new()),
            session_of: Mutex::new(BTreeMap::new()),
            prepared_plans: Mutex::new(BTreeMap::new()),
            sessions: std::sync::atomic::AtomicU64::new(0),
            transactions: Mutex::new(BTreeMap::new()),
            commands: std::sync::atomic::AtomicU64::new(0),
            recorder: std::sync::Arc::new(Mutex::new(None)),
            others: Vec::new(),
            aliases: Vec::new(),
            unassigned: Mutex::new(BTreeMap::new()),
            completed: Mutex::new(std::collections::BTreeSet::new()),
        }
    }

    /// Commands wait `timeout` for their verdict (administrative calls keep the committer's timeout).
    pub fn with_tracking_timeout(mut self, timeout: Duration) -> Self {
        self.tracking_timeout = timeout;
        self
    }

    /// Name the one synchronizer of this committer (`GET /v2/state/connected-synchronizers` lists it under this alias).
    pub fn with_alias(mut self, alias: &str) -> Self {
        self.aliases = vec![alias.to_string()];
        self
    }

    /// A committer for a participant on several synchronizers: `(alias, node)` each, the nodes sharing one identity
    /// ([`canton_participant::multi_node::MultiNode`]). Transactions go to the first; reassignments move contracts between them.
    pub fn new_multi(nodes: Vec<(String, Node)>, package_name: &str, timeout: Duration) -> Self {
        let mut nodes = nodes.into_iter();
        let (first_alias, first) = nodes.next().expect("at least one synchronizer");
        let mut committer = Self::new(first, package_name, timeout);
        committer.aliases.push(first_alias);
        for (alias, node) in nodes {
            let shared = std::sync::Arc::new(SharedNode::new(node));
            hold_until_shown(&shared);
            let reader = shared.start_reader();
            committer.others.push((shared, reader));
            committer.aliases.push(alias);
        }
        committer
    }

    pub(super) fn all_nodes(&self) -> Vec<&std::sync::Arc<SharedNode>> {
        std::iter::once(&self.node)
            .chain(self.others.iter().map(|(n, _)| n))
            .collect()
    }

    /// The node of the synchronizer a contract is active on: where a transaction that uses it has to go (the first node when none holds it).
    ///
    /// [CANTON-NOTE: SEMANTICS] A contract that was reassigned lives on the target synchronizer only; the official participant submits the
    /// transaction that uses it there (synchronizer routing by the contracts the transaction touches).
    pub(super) fn node_holding(&self, contract_id: &str) -> &std::sync::Arc<SharedNode> {
        self.all_nodes()
            .into_iter()
            .find(|n| n.instance_bytes(contract_id).is_some())
            .unwrap_or(&self.node)
    }

    pub(super) fn node_of(
        &self,
        synchronizer: &str,
    ) -> Result<&std::sync::Arc<SharedNode>, ApiError> {
        let wanted = canton_participant::multi_node::logical(synchronizer);
        self.all_nodes()
            .into_iter()
            .find(|n| {
                n.with(|n| {
                    canton_participant::multi_node::logical(n.physical_synchronizer_id()) == wanted
                })
                .unwrap_or(false)
            })
            .ok_or_else(|| {
                invalid_argument(format!(
                    "this participant is not connected to {synchronizer}"
                ))
            })
    }
}

impl NodeCommitter {
    /// Shows `service` what other participants get approved: every transaction this participant is sent and did not submit itself is applied
    /// to the service's ledger, so that its parties see the contracts others created for them and the ones consumed.
    /// Shows `service` the contracts the node knows to be active (what it kept across a restart, and what it learned since): a service that
    /// starts fresh in front of a participant that continues has the participant's contracts in its ACS from the first call.
    ///
    /// [CANTON-NOTE: LIMITATION] Only the contracts, not the transactions that made them: the update stream of the new service starts empty.
    pub fn show_known_contracts_in(&self, service: &ExecutionService) -> Result<usize, ApiError> {
        // [CANTON-NOTE: SEMANTICS] Every synchronizer's node of a multi-synchronizer participant, not only the first: a contract that was
        // reassigned lives in the node of the synchronizer it is on, with its reassignment counter, and the service shows it there (the
        // official participant keeps both across a restart: tests/oracle/reassignment/json-api-restart.jsonl, U-44).
        // the unassignments that were waiting for their assignment when the process stopped: an assign can still name them
        let mut count = 0;
        for node in self.all_nodes() {
            for (done, source, target) in node.pending_unassignments() {
                // the contract is the service's again (an assign answers with it) but in no ACS until that assign
                let opened = node.open_instance_bytes(&done.instance);
                if let Some(c) = opened {
                    let contract_id = c.contract_id.clone();
                    service.apply_remote_without_v2(RemoteApplied {
                        request_id: 0,
                        created: vec![to_remote(c)],
                        consumed: Vec::new(),
                        root_hash: None,
                        events: Vec::new(),
                    })?;
                    service.v2_state().note_in_flight(
                        &contract_id,
                        canton_participant::multi_node::logical(&target),
                    );
                    count += 1;
                }
                if let Ok(mut pending) = self.unassigned.lock() {
                    pending.insert(done.reassignment_id.clone(), (done, source, target.clone()));
                }
            }
        }
        for (index, node) in self.all_nodes().into_iter().enumerate() {
            let synchronizer = node
                .with(|n| canton_participant::multi_node::logical(n.physical_synchronizer_id()))
                .ok();
            for c in node.known_contracts() {
                let counter = node.reassignment_counter(&c.contract_id);
                if let Some(synchronizer) = &synchronizer {
                    if index > 0 || counter > 0 {
                        service.v2_state().note_location(
                            &c.contract_id,
                            synchronizer.clone(),
                            counter,
                        );
                    }
                }
                if !service.has_known_contract(&c.contract_id) {
                    service.apply_remote_without_v2(RemoteApplied {
                        request_id: 0,
                        created: vec![to_remote(c)],
                        consumed: Vec::new(),
                        root_hash: None,
                        events: Vec::new(),
                    })?;
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Keeps what this service records of the ledger API (updates, completions, command deduplication) in the participant's state
    /// (`updates.journal`, `completions.journal`, `dedup.journal`: one JSON line each) and puts back what it kept before the process
    /// stopped, so the streams, the deduplication and the offsets go on where they stopped (U-44: the official participant keeps all of it
    /// across a restart, `tests/oracle/reassignment/json-api-restart.jsonl`). Returns how many updates it put back.
    pub fn keep_updates_in(&self, service: &ExecutionService) -> usize {
        fn lines<T>(text: &str, parse: impl Fn(&str) -> Result<T, String>) -> Vec<T> {
            text.lines().filter_map(|line| parse(line).ok()).collect()
        }
        let updates = lines(
            &self.node.read_journal("updates.journal"),
            crate::snapshot::update_from_line,
        );
        let completions = lines(
            &self.node.read_journal("completions.journal"),
            crate::snapshot::completion_from_line,
        );
        let dedup = lines(
            &self.node.read_journal("dedup.journal"),
            crate::snapshot::dedup_from_line,
        );
        let pruned = self
            .node
            .read_journal("pruned.journal")
            .lines()
            .filter_map(|l| l.trim().parse::<u64>().ok())
            .max()
            .unwrap_or(0);
        let count = updates.len();
        let node = std::sync::Arc::clone(&self.node);
        let prune_node = std::sync::Arc::clone(&self.node);
        service.restore_journals(
            updates,
            completions,
            dedup,
            std::sync::Arc::new(move |key, line| node.append_journal(key, &line)),
        );
        if pruned > 0 {
            let state = service.v2_state();
            state
                .pruned_up_to
                .fetch_max(pruned, std::sync::atomic::Ordering::SeqCst);
            state
                .ledger_end
                .fetch_max(pruned, std::sync::atomic::Ordering::SeqCst);
            service.evict_pruned_up_to(pruned);
        }
        if let Ok(mut sink) = service.v2_state().journal_prune_sink.lock() {
            *sink = Some(std::sync::Arc::new(move |state, prune_up_to| {
                compact_journals(&prune_node, state, prune_up_to);
            }));
        }
        count
    }

    /// Puts back what the Ledger API's administration kept in the node's state: the DARs that were uploaded (loaded and vetted again), then the parties,
    /// users and identity providers as they stood. Returns how many DARs came back and whether the administration state did. Before `keep_updates_in`,
    /// which starts the journaling.
    pub fn restore_admin_in(&self, service: &ExecutionService) -> (usize, bool) {
        let mut dars = 0;
        for line in self.node.read_journal("dars.journal").lines() {
            let Some(bytes) = crate::v2::unbase64(line) else {
                continue;
            };
            if let Ok(loaded) = lf_archive::parse_loaded_dar(std::io::Cursor::new(&bytes)) {
                for node in self.all_nodes() {
                    if let Err(e) = node.upload_and_vet_loaded_dar(&loaded, self.timeout) {
                        crate::diag::diag_eprintln!(
                            "failed to restore dynamically uploaded DAR on protocol node: {e}"
                        );
                    }
                }
            }
            let request = crate::http::HttpRequest {
                method: "POST".into(),
                path: "/v2/dars".into(),
                query_params: Default::default(),
                headers: Default::default(),
                body: bytes,
            };
            if crate::v2_packages::upload(service, &request, false).status < 300 {
                dars += 1;
            }
        }
        let state = service.v2_state();
        let restored = self
            .node
            .read_journal("admin.journal")
            .lines()
            .rfind(|l| !l.trim().is_empty())
            .is_some_and(|line| state.restore_admin(line).is_ok());
        (dars, restored)
    }

    /// The serialized instance of a contract this node holds (see `Node::instance_bytes`).
    pub fn instance_bytes(&self, contract_id: &str) -> Option<Vec<u8>> {
        self.node_holding(contract_id).instance_bytes(contract_id)
    }

    /// Writes the contract salt of every contract this node creates to `recorder`'s authentication file, so the scan served over its history
    /// can build the blob of those contracts (S-SPL-010).
    pub fn record_salts_in(&self, recorder: std::sync::Arc<crate::history::UpdateRecorder>) {
        if let Ok(mut r) = self.recorder.lock() {
            *r = Some(recorder);
        }
    }

    /// After the synchronizer approved `commit`: the salts of the contracts it created (and protocol effective time for non-creating updates). A failure is reported, the commit stands.
    pub(super) fn note_salts_with_remap(
        &self,
        commit: &TransactionCommit,
        remapped: &BTreeMap<String, String>,
    ) {
        let Some(recorder) = self.recorder.lock().ok().and_then(|r| r.clone()) else {
            return;
        };
        if commit.created_contracts.iter().all(|c| !c.active) {
            if let Some(t) = self.node.last_approved_request_id() {
                recorder.note_effective_at(t);
            }
        }
        for c in &commit.created_contracts {
            if !c.active {
                continue;
            }
            let cid = remapped.get(&c.contract_id).unwrap_or(&c.contract_id);
            let noted = self
                .node
                .instance_bytes(cid)
                .ok_or_else(|| "the node holds no instance".to_string())
                .and_then(|bytes| canton_participant::contract_wire::instance_facts(&bytes))
                .and_then(|(salt, created_at)| {
                    recorder.note_created_at(cid, created_at);
                    recorder.note_authentication(cid, &salt)
                });
            if let Err(e) = noted {
                crate::diag::diag_eprintln!("scan history: the salt of {} not recorded: {e}", cid);
            }
        }
    }

    /// Gives the node back (to restart it): stops the background reader first.
    pub fn into_node(self) -> Node {
        let NodeCommitter { node, _reader, .. } = self;
        drop(_reader);
        std::sync::Arc::try_unwrap(node)
            .ok()
            .expect("nobody else holds the node")
            .into_node()
    }

    /// Whether the participant's protocol ledger holds `contract_id` (hex) as active.
    pub fn protocol_is_active(&self, contract_id: &str) -> bool {
        self.node
            .with(|n| n.is_active(contract_id))
            .unwrap_or(false)
    }

    /// Every ACS commitment comparison of this participant's nodes so far (counter-participant, tick, verdict).
    pub fn commitment_periods(&self) -> Vec<canton_participant::acs_commitment::PeriodStatus> {
        self.all_nodes()
            .into_iter()
            .filter_map(|n| n.with(|n| n.runtime.commitment_periods()).ok())
            .flatten()
            .collect()
    }
}

impl NodeCommitter {
    pub(super) fn command_id(&self) -> String {
        format!(
            "json-api-{}",
            self.commands
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        )
    }

    pub(super) fn recording_command_id(&self) -> String {
        crate::service::current_command()
            .map(|c| c.command_id)
            .or_else(crate::service::current_v1_recording_id)
            .unwrap_or_else(|| self.command_id())
    }
}
