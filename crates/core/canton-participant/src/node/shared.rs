use super::{
    Board, CreatedByExercise, LateHandler, Node, PreparedCreate, ReassignmentDone, RemoteHandler,
    TreeEntry, TreeNode, Verdict, IDLE_PAUSE, READ_SLICE, STILL_IN_FLIGHT,
};
use crate::node::ExerciseCommand;
use crate::submit::ExercisePlan;
use crate::view_conformance::{open_instance, OpenedContract};
use lf_eval::Value;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The background reader of a [`SharedNode`]; dropping it stops the thread.
pub struct Reader {
    board: Arc<Board>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.board
            .stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.board.changed.notify_all();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// A [`Node`] that many threads submit through at once.
///
/// [CANTON-NOTE: SEMANTICS] A submission holds the node only to build and send its request, and then waits for its verdict **outside** the
/// node: the waiters take turns reading the sequencer's events (one at a time, [`READ_SLICE`] each) and every verdict that is read goes on the
/// board, where its owner finds it. The waits of different requests therefore overlap, as they do on the official participant; behind one
/// lock held for the whole submission they would add up.
pub struct SharedNode {
    node: Mutex<Node>,
    pub(super) board: Arc<Board>,
    handler: Mutex<Option<RemoteHandler>>,
    late_handler: Mutex<Option<LateHandler>>,
}

impl SharedNode {
    pub fn new(node: Node) -> Self {
        let board = std::sync::Arc::clone(&node.board);
        Self {
            node: Mutex::new(node),
            board,
            handler: Mutex::new(None),
            late_handler: Mutex::new(None),
        }
    }

    /// Hands every approved transaction this node did not submit to `handler`, from the reader thread and **outside** the node (so the
    /// handler may take its own locks without ordering them against the node's).
    pub fn on_remote(&self, handler: RemoteHandler) {
        if let Ok(mut h) = self.handler.lock() {
            *h = Some(handler);
        }
    }

    /// Hands every [`LateFate`] of this node's submissions to `handler`, from the reader thread and outside the node, an approval with its
    /// transaction. A fate is handed over again after a restart until `handler` returned. Until a handler is set the fates are kept, and the
    /// transaction of an approval goes to the [`RemoteHandler`].
    pub fn on_late(&self, handler: LateHandler) {
        if let Ok(mut h) = self.late_handler.lock() {
            *h = Some(handler);
        }
    }

    /// Starts the thread that keeps reading the sequencer's events, so that the requests of other participants are confirmed (and the
    /// verdicts of this node's own recorded) when nobody is waiting. It stops when the returned [`Reader`] is dropped.
    ///
    /// [CANTON-NOTE: SEMANTICS] A participant that reads only while one of its own submissions waits would never confirm a request another
    /// participant sent it, and that participant's transaction would time out. Reading is part of being a participant, not of submitting.
    pub fn start_reader(self: &Arc<Self>) -> Reader {
        let shared = Arc::clone(self);
        let board = Arc::clone(&self.board);
        let handle = std::thread::spawn(move || {
            while !shared.board.stop.load(std::sync::atomic::Ordering::SeqCst) {
                // [CANTON-NOTE: WHY] A late fate is kept until a handler takes it (a fate read at the start, before the service registered,
                // is not lost); the transaction of an approval nobody takes the fate of is shown as any other.
                let has_late = shared.late_handler.lock().is_ok_and(|h| h.is_some());
                let (busy, remote, late, poll_res) = match shared.node.try_lock() {
                    Ok(mut node) => {
                        let in_flight = !node.runtime.in_flight.is_empty();
                        let res = node.poll_slice(READ_SLICE).and_then(|()| {
                            node.runtime
                                .last_subscribe_error
                                .clone()
                                .map_or(Ok(()), Err)
                        });
                        let mut remote = std::mem::take(&mut node.remote);
                        let late = if has_late {
                            std::mem::take(&mut node.late)
                        } else {
                            remote
                                .extend(node.late.iter_mut().filter_map(|f| f.transaction.take()));
                            Vec::new()
                        };
                        (in_flight, remote, late, Some(res))
                    }
                    Err(_) => (true, Vec::new(), Vec::new(), None),
                };
                if let Some(res) = poll_res {
                    shared.board.note_poll(&res);
                }
                // outside the node: the handler takes the service's locks, and the service takes the node's while it runs the engine
                let mut shown: Vec<i64> = Vec::new();
                if !remote.is_empty() {
                    if let Ok(handler) = shared.handler.lock() {
                        if let Some(handler) = handler.as_ref() {
                            for tx in remote {
                                let rid = tx.request_id;
                                match handler(tx) {
                                    Ok(()) => shown.push(rid),
                                    Err(err) => crate::diag::diag_eprintln!(
                                        "remote handler kept request {rid} unshown: {err}"
                                    ),
                                }
                            }
                        }
                    }
                }
                if !late.is_empty() {
                    let delivered: Vec<String> = match shared.late_handler.lock() {
                        Ok(handler) => match handler.as_ref() {
                            Some(handler) => late
                                .into_iter()
                                .filter_map(|fate| {
                                    let id = fate.settled.message_id.clone();
                                    let rid = fate.transaction.as_ref().map(|t| t.request_id);
                                    match handler(fate) {
                                        Ok(()) => {
                                            shown.extend(rid);
                                            Some(id)
                                        }
                                        Err(err) => {
                                            crate::diag::diag_eprintln!(
                                                "late handler kept fate {id} pending: {err}"
                                            );
                                            None
                                        }
                                    }
                                })
                                .collect(),
                            None => Vec::new(),
                        },
                        Err(_) => Vec::new(),
                    };
                    // marked only once shown: a crash in between hands it over again after the restart
                    let _ = shared.with(|n| {
                        for id in &delivered {
                            let _ = n.fate_handed_over(id);
                        }
                    });
                }
                if !shown.is_empty() {
                    let _ = shared.with(|n| {
                        for request in &shown {
                            let _ = n.runtime.applied_shown(*request);
                        }
                    });
                }
                shared.board.pause(if busy {
                    Duration::from_millis(1)
                } else {
                    IDLE_PAUSE
                });
            }
        });
        Reader {
            board,
            handle: Some(handle),
        }
    }

    /// The most requests that waited for a verdict at the same moment since the node opened.
    pub fn most_in_flight(&self) -> usize {
        self.with(|n| n.most_in_flight).unwrap_or(0)
    }

    /// Returns `Ok(())` while the background reader's sequencer stream is healthy, or the latest poll failure.
    pub fn sequencer_status(&self) -> Result<(), String> {
        let Ok(g) = self.board.poll_error.lock() else {
            return Err("participant board lock poisoned".to_string());
        };
        match g.as_ref() {
            None => Ok(()),
            Some(err) => Err(err.clone()),
        }
    }

    /// Runs `f` with the node held (for what is short: building a request, asking the time, hosting a party).
    pub fn with<R>(&self, f: impl FnOnce(&mut Node) -> R) -> Result<R, String> {
        let mut node = self
            .node
            .lock()
            .map_err(|_| "the node is poisoned".to_string())?;
        Ok(f(&mut node))
    }

    /// Waits for the verdict about `message_id`, reading the stream when the node is free and sleeping on the board when another thread
    /// reads it.
    pub(super) fn wait(
        &self,
        message_id: &str,
        timeout: Duration,
    ) -> Result<(Verdict, Vec<String>), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(found) = self.board.take(message_id) {
                return Ok(found);
            }
            if Instant::now() >= deadline {
                // under the node: a verdict recorded since the last look is taken, else nobody waits for it any more
                return self.with(|n| n.give_up(message_id, timeout))?;
            }
            match self.node.try_lock() {
                Ok(mut node) => {
                    let read = node.poll_slice(READ_SLICE);
                    if let Err(e) = read {
                        // the submission is in flight whatever the reading did: its fate comes later
                        node.runtime.in_flight.stop_awaiting(message_id);
                        return Err(format!(
                            "{STILL_IN_FLIGHT}reading the sequencer failed: {e}"
                        ));
                    }
                    drop(node);
                    // let a submitter that waits for the node take it before the next slice
                    self.board
                        .wait_a_while(message_id, Duration::from_millis(1));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    self.board
                        .wait_a_while(message_id, Duration::from_millis(5));
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err("the node is poisoned".to_string())
                }
            }
        }
    }

    /// Sends a prepared create and waits for its verdict; the notes are what the runtime set aside meanwhile.
    pub fn submit_prepared(
        &self,
        prepared: PreparedCreate,
        timeout: Duration,
    ) -> Result<(Verdict, Vec<String>), String> {
        self.submit_prepared_tagged(prepared, timeout, "")
    }

    /// Exercises `choice` on a contract the node created and waits for the verdict. `created` and `plan` as in [`Node::prepare_exercise`].
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn submit_exercise(
        &self,
        package_name: &str,
        contract_id_hex: &str,
        choice: &str,
        argument: &Value,
        actors: &[String],
        command_id: &str,
        plan: Option<ExercisePlan>,
        created: &[CreatedByExercise],
        timeout: Duration,
    ) -> Result<(Verdict, Vec<String>), String> {
        let entries: Vec<TreeEntry> = created
            .iter()
            .map(|c| TreeEntry {
                depth: 1,
                node: TreeNode::Create(CreatedByExercise {
                    template: c.template,
                    payload: c.payload,
                    expected_id: c.expected_id,
                }),
            })
            .collect();
        self.submit_exercise_tree(
            package_name,
            contract_id_hex,
            choice,
            argument,
            actors,
            command_id,
            plan,
            &entries,
            timeout,
        )
    }

    /// Exercises `choice` whose subtree stays in one view and waits for the verdict. `entries` as in [`Node::prepare_exercise_tree`].
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn submit_exercise_tree(
        &self,
        package_name: &str,
        contract_id_hex: &str,
        choice: &str,
        argument: &Value,
        actors: &[String],
        command_id: &str,
        plan: Option<ExercisePlan>,
        entries: &[TreeEntry],
        timeout: Duration,
    ) -> Result<(Verdict, Vec<String>), String> {
        self.submit_exercise_full(
            package_name,
            contract_id_hex,
            choice,
            argument,
            actors,
            command_id,
            plan,
            entries,
            None,
            false,
            timeout,
        )
    }

    /// Exercises `choice` with full P4/P5/P6 support (`root_interface_id`, `root_by_key`, nested keys/interfaces/rollbacks).
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn submit_exercise_full(
        &self,
        package_name: &str,
        contract_id_hex: &str,
        choice: &str,
        argument: &Value,
        actors: &[String],
        command_id: &str,
        plan: Option<ExercisePlan>,
        entries: &[TreeEntry],
        root_interface_id: Option<&str>,
        root_by_key: bool,
        timeout: Duration,
    ) -> Result<(Verdict, Vec<String>), String> {
        self.submit_exercise_with_options(
            package_name,
            contract_id_hex,
            choice,
            argument,
            actors,
            command_id,
            plan,
            entries,
            root_interface_id,
            root_by_key,
            None,
            &[],
            timeout,
        )
    }

    /// Exercises `choice` with full P4/P5/P6 support plus optional smart-contract upgrade target package and explicitly disclosed contracts.
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn submit_exercise_with_options(
        &self,
        package_name: &str,
        contract_id_hex: &str,
        choice: &str,
        argument: &Value,
        actors: &[String],
        command_id: &str,
        plan: Option<ExercisePlan>,
        entries: &[TreeEntry],
        root_interface_id: Option<&str>,
        root_by_key: bool,
        root_package_id: Option<&str>,
        disclosed_instances: &[(String, Vec<u8>)],
        timeout: Duration,
    ) -> Result<(Verdict, Vec<String>), String> {
        self.submit_exercise_command(ExerciseCommand {
            package_name,
            contract_id_hex,
            choice,
            argument,
            actors,
            observers: &[],
            command_id,
            plan,
            entries,
            root_interface_id,
            root_by_key,
            root_package_id,
            disclosed_instances,
            timeout,
            tag: "",
            submission: crate::submit::Submission::default(),
        })
    }

    /// Gives the node back (to restart it).
    pub fn into_node(self) -> Node {
        self.node.into_inner().expect("the node is not poisoned")
    }

    /// See [`Node::known_contracts`].
    pub fn known_contracts(&self) -> Vec<OpenedContract> {
        self.with(|n| n.known_contracts()).unwrap_or_default()
    }

    /// Appends a line to the journal `key` of this node's state (no-op when no store is configured).
    pub fn append_journal(&self, key: &str, line: &str) -> Result<(), String> {
        let mut res = Ok(());
        self.with(|n| {
            if let Some(store) = &n.store {
                res = store.append(key, line);
            }
        })?;
        res
    }

    /// The text of the journal `key` of this node's state (empty when there is none).
    pub fn read_journal(&self, key: &str) -> String {
        self.with(|n| {
            n.store
                .as_ref()
                .and_then(|s| s.read(key).ok().flatten())
                .unwrap_or_default()
        })
        .unwrap_or_default()
    }

    /// Atomically rewrites the journal `key` of this node's state (no-op when no store is configured).
    pub fn write_journal(&self, key: &str, text: &str) -> Result<(), String> {
        let mut res = Ok(());
        let _ = self.with(|n| {
            if let Some(store) = &n.store {
                res = store.write(key, text);
            }
        });
        res
    }

    /// See [`Node::reassignment_counter`].
    pub fn reassignment_counter(&self, contract_id_hex: &str) -> i64 {
        self.with(|n| n.reassignment_counter(contract_id_hex))
            .unwrap_or(0)
    }

    /// Decodes a serialized contract instance with this node's engine (the packages it knows).
    pub fn open_instance_bytes(&self, instance: &[u8]) -> Option<OpenedContract> {
        self.with(|n| open_instance(&n.runtime.engine, instance).ok())
            .ok()
            .flatten()
    }

    /// See [`Node::party_is_active`].
    pub fn party_is_active(&self, party: &str) -> bool {
        self.with(|n| n.party_is_active(party)).unwrap_or(false)
    }

    /// See [`Node::has_vetted`].
    pub fn has_vetted(&self, package_id: &str) -> bool {
        self.with(|n| n.has_vetted(package_id)).unwrap_or(false)
    }

    /// See [`Node::pending_unassignments`].
    pub fn pending_unassignments(&self) -> Vec<(ReassignmentDone, String, String)> {
        self.with(|n| n.pending_unassignments()).unwrap_or_default()
    }

    /// See [`Node::forget_unassignment`].
    pub fn forget_unassignment(&self, reassignment_id: &str) {
        let _ = self.with(|n| n.forget_unassignment(reassignment_id));
    }

    /// See [`Node::instance_bytes`].
    pub fn instance_bytes(&self, contract_id_hex: &str) -> Option<Vec<u8>> {
        self.with(|n| n.instance_bytes(contract_id_hex))
            .ok()
            .flatten()
    }

    /// See [`Node::promise_created`].
    pub fn promise_created(
        &self,
        package_name: &str,
        plan: &ExercisePlan,
        index: usize,
        template: &str,
        payload: &Value,
    ) -> Result<String, String> {
        self.with(|n| n.promise_created(package_name, plan, index, template, payload))?
    }

    /// See [`Node::promise_created_at`].
    pub fn promise_created_at(
        &self,
        package_name: &str,
        plan: &ExercisePlan,
        index: usize,
        path: &[i32],
        template: &str,
        payload: &Value,
    ) -> Result<String, String> {
        self.with(|n| n.promise_created_at(package_name, plan, index, path, template, payload))?
    }

    /// See [`Node::adopt_instance`].
    pub fn adopt_instance(&self, instance: &[u8]) -> Result<(), String> {
        self.with(|n| n.adopt_instance(instance))?
    }

    /// See [`Node::upload_and_vet_dar`].
    pub fn upload_and_vet_dar(&self, dar: &Path, timeout: Duration) -> Result<Vec<String>, String> {
        self.with(|n| n.upload_and_vet_dar(dar, timeout))?
    }

    /// See [`Node::upload_and_vet_loaded_dar`].
    pub fn upload_and_vet_loaded_dar(
        &self,
        loaded: &lf_archive::LoadedDar,
        timeout: Duration,
    ) -> Result<Vec<String>, String> {
        self.with(|n| n.upload_and_vet_loaded_dar(loaded, timeout))?
    }

    /// See [`Node::sync_vetted_packages`].
    pub fn sync_vetted_packages(
        &self,
        vetted_ids: &[String],
        timeout: Duration,
    ) -> Result<(), String> {
        self.with(|n| n.sync_vetted_packages(vetted_ids, timeout))?
    }

    /// Number of pending topology changes queued for their effective time.
    pub fn pending_topology_changes(&self) -> usize {
        self.with(|n| n.runtime.pending_topology_changes())
            .unwrap_or(0)
    }

    /// Current non-blocking count of in-flight submissions and view confirmations on this node.
    pub fn in_flight_count(&self) -> usize {
        self.node
            .try_lock()
            .map(|n| n.runtime.in_flight.len() + n.runtime.ledger.in_flight())
            .unwrap_or(0)
    }

    /// Sequencing timestamp (microseconds) of the most recently approved request.
    pub fn last_approved_request_id(&self) -> Option<i64> {
        self.board.last_approved.lock().ok().and_then(|g| *g)
    }
}
