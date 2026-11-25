use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::payload_schema::PayloadSchema;
use lf_eval::engine::{Contract as EngineContract, Engine, NewContract};
use lf_eval::fat_contract::{
    compute_contract_hash, compute_key_hash, compute_unicum, encode_base64, encode_fat_contract,
    format_v12_contract_id, FatContractInput,
};
use lf_eval::journal::LedgerJournal;
use lf_eval::ledger::{visible, Holding, SingleContractLedger, PACKAGE_ID};
use lf_eval::tx_model::{
    ActiveLedgerState, ContractId, Node, TransactionTree as LfTransactionTree, TxError,
};
use sha2::Digest;

use crate::ledger_v2::{CommandCompletion, CompletionStreamResponse, DeduplicationStore};
use crate::models::json_api::{
    ArchivedContract, ContractView, CreateRequest, CreateResult, CreatedContract, ExerciseRequest,
    ExerciseResult, JsonApiResponse, JsonEvent, QueryContractsRequest,
};
use crate::models::ledger_api::{
    ActiveContract, Command, CreatedEvent, ExercisedEvent, GetActiveContractsResponse,
    SubmitAndWaitRequest, TemplateId, TransactionTree, TreeEvent,
};

mod batch;
mod commit;
mod context;
mod dar_loader;
mod queries;
mod submit;
mod types;
mod v1_json;

pub use context::{arrival, set_arrival, CommandIdentity, REQUEST_TIME_OUT};
pub(crate) use context::{
    capture_engine_events, clear_protocol_update_id, current_disclosed_contracts, current_read_as,
    disclosed_contract_by_id, enter_command, enter_external_authorization, enter_v1_recording,
    enter_v2_command, enter_v2_prepare_dry_run, is_v2_prepare_dry_run, take_dry_run_commits,
    take_last_commit_remapped_cids, take_protocol_update_id, translate_payload,
    with_exercise_by_key, CapturedJournal,
};
#[cfg(feature = "protocol")]
pub(crate) use context::{
    current_command, current_external_authorization, current_v1_recording_id,
    set_protocol_remapped_cids, set_protocol_update_id,
};
pub(crate) use types::{
    map_codec_error, map_exec_error, root_exercise_actors, BatchUndo, LedgerUndo,
    TemplateResolution,
};
pub use types::{
    ApiError, DarPackageInfo, GenericContract, HostedParty, LfPackage, PackagesResponse,
    ProtocolCommitter, ReassignCommand, ReassignOutcome, RemoteApplied, RemoteCreated,
    RemoteTxEvent, RemoteTxExercise, SignedTopologyRecord, TransactionCommit,
};

pub struct ExecutionService {
    pub(crate) ledger: RwLock<SingleContractLedger>,
    pub(crate) active_state: RwLock<ActiveLedgerState>,
    pub(crate) journal: RwLock<LedgerJournal>,
    pub(crate) dedup_store: RwLock<DeduplicationStore>,
    pub(crate) update_stream: RwLock<Vec<TransactionTree>>,
    pub(crate) offset_counter: AtomicU64,
    pub(crate) event_counter: AtomicU64,
    pub(crate) contract_counter: Arc<AtomicU64>,
    pub(crate) dar_info: RwLock<Option<DarPackageInfo>>,
    /// Every loaded DAR's main package: `(package name, main package id)`. `dar_info` keeps only the last DAR, so a
    /// package-name template reference (`#name:Module:Entity`) of an earlier DAR must resolve through this list (S-TX-004).
    pub(crate) package_names: RwLock<Vec<(String, String, String)>>,
    /// Raw DAR bytes recorded in load order so checkpoint restore can rebuild `lf_packages` directly.
    pub(crate) dar_blobs: RwLock<Vec<Vec<u8>>>,
    /// A logical clock that stamps the arrival of every HTTP request and the completion of every committed transaction, so a
    /// contract consumed by a submission that finished AFTER another one arrived can be reported as locked, not as missing.
    pub(crate) clock: AtomicU64,
    /// Contract id -> the stamp of the commit that consumed it.
    pub(crate) consumed_at: RwLock<HashMap<String, u64>>,
    pub(crate) lf_packages: RwLock<Vec<Arc<LfPackage>>>,
    pub(crate) generic_contracts: RwLock<HashMap<String, GenericContract>>,
    pub(crate) creation_seq_counter: AtomicU64,
    pub(crate) v2: crate::v2::V2State,
    /// Serializes the multi-command submissions of the v2 endpoints (S-API-003).
    pub(crate) v2_submit_lock: std::sync::Mutex<()>,
    /// JWT authentication, when configured (S-API-015).
    pub(crate) auth: RwLock<Option<crate::auth::AuthConfig>>,
    /// Whether `/v2/traffic/*` enforcement routes are enabled (`false` in sandbox mode by default).
    pub(crate) traffic_enforcement: std::sync::atomic::AtomicBool,
    /// Optional cap on HTTP blocking list endpoints (`http-ledger-api.websocket-config.http-list-max-elements-limit`).
    pub(crate) http_list_max_elements_limit: RwLock<Option<usize>>,
    /// Optional idle wait timeout in milliseconds (`http-ledger-api.websocket-config.http-list-wait-time`).
    pub(crate) http_list_wait_time_ms: RwLock<Option<u64>>,
    /// The request log of a persistent service (S-STORE-004); `None` for the in-memory service.
    pub(crate) persist: std::sync::Mutex<Option<Box<dyn crate::store::RequestLog>>>,
    /// The changes of the running `v2_atomic` batch, if one runs.
    pub(crate) batch: std::sync::Mutex<Option<BatchUndo>>,
    /// Set when a write to the request log failed: no further state change is accepted until a restart.
    pub(crate) persist_failed: std::sync::atomic::AtomicBool,
    /// The synchronizer behind the service, if any (see [`ProtocolCommitter`]).
    pub(crate) committer: RwLock<Option<Arc<dyn ProtocolCommitter>>>,
    /// Where committed transactions are written for the scan app (`set_update_recorder`).
    pub(crate) recorder: RwLock<Option<Arc<crate::history::UpdateRecorder>>>,
    /// Optional automatic checkpoint cadence in number of logged requests (`0` disables auto-checkpointing).
    pub(crate) snapshot_every: AtomicU64,
    /// Per-node Prometheus metrics, readiness diagnostics, and Zero-Payload X-Ray traces.
    pub observability: crate::observability::ObservabilityState,
    /// When true, new write/command submissions return `503 NODE_QUIESCED` for snapshotting (`S-DX-004`).
    pub(crate) quiesced: AtomicBool,
    /// Active HTTP/gRPC write/command requests currently executing on this service (`S-DX-004`).
    pub(crate) in_flight_writes: AtomicUsize,
}

/// RAII guard tracking one active write/command call against [`ExecutionService::in_flight_writes`].
pub(crate) struct WriteGuard<'a>(&'a AtomicUsize);

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Default for ExecutionService {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionService {
    /// Creates an [`ExecutionService`] propagating CSPRNG initialization errors cleanly.
    pub fn try_new() -> Result<Self, String> {
        Self::try_new_with_v2(crate::v2::V2State::try_new()?)
    }

    /// Creates an [`ExecutionService`] using a custom CSPRNG closure for ExEx HMAC initialization.
    pub fn try_new_with_exex_rng<E: std::fmt::Display>(
        fill_key: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, String> {
        Self::try_new_with_v2(crate::v2::V2State::try_new_with_exex_rng(fill_key)?)
    }

    fn try_new_with_v2(v2: crate::v2::V2State) -> Result<Self, String> {
        Ok(Self {
            ledger: RwLock::new(SingleContractLedger::new()),
            active_state: RwLock::new(ActiveLedgerState::new()),
            journal: RwLock::new(LedgerJournal::new()),
            dedup_store: RwLock::new(DeduplicationStore::new()),
            update_stream: RwLock::new(Vec::new()),
            offset_counter: AtomicU64::new(1),
            event_counter: AtomicU64::new(1),
            contract_counter: Arc::new(AtomicU64::new(0)),
            dar_info: RwLock::new(None),
            package_names: RwLock::new(Vec::new()),
            dar_blobs: RwLock::new(Vec::new()),
            clock: AtomicU64::new(0),
            consumed_at: RwLock::new(HashMap::new()),
            lf_packages: RwLock::new(Vec::new()),
            generic_contracts: RwLock::new(HashMap::new()),
            creation_seq_counter: AtomicU64::new(1),
            v2,
            v2_submit_lock: std::sync::Mutex::new(()),
            auth: RwLock::new(None),
            traffic_enforcement: std::sync::atomic::AtomicBool::new(false),
            http_list_max_elements_limit: RwLock::new(None),
            http_list_wait_time_ms: RwLock::new(None),
            persist: std::sync::Mutex::new(None),
            batch: std::sync::Mutex::new(None),
            persist_failed: std::sync::atomic::AtomicBool::new(false),
            committer: RwLock::new(None),
            recorder: RwLock::new(None),
            snapshot_every: AtomicU64::new(0),
            observability: crate::observability::ObservabilityState::default(),
            quiesced: AtomicBool::new(false),
            in_flight_writes: AtomicUsize::new(0),
        })
    }

    pub fn new() -> Self {
        Self::try_new().expect("system CSPRNG required for ExEx HMAC key")
    }

    pub fn with_ledger(ledger: SingleContractLedger) -> Self {
        let initial_counter = ledger.contracts.len() as u64;
        // [CANTON-NOTE: INVARIANT] Synchronize legacy ledger contracts to active_state upon construction.
        // [CANTON-NOTE: WHY] Guarantees that active_state reflects all pre-existing active contracts,
        // preventing double-spend rejections or missing contract errors when transactions are evaluated.
        let mut active_state = ActiveLedgerState::new();
        for (idx, maybe_holding) in ledger.contracts.iter().enumerate() {
            if let Some(holding) = maybe_holding {
                let cid = ContractId(Self::format_contract_id(idx));
                let mut stakeholders = HashSet::new();
                stakeholders.insert(holding.bank.clone());
                stakeholders.insert(holding.owner.clone());
                stakeholders.insert(holding.auditor.clone());
                active_state.active_contracts.insert(
                    cid,
                    lf_eval::tx_model::ActiveContract {
                        template_id: TemplateId::asset_holding().to_string(),
                        payload: serde_json::to_vec(&Self::holding_to_value(holding))
                            .unwrap_or_default(),
                        stakeholders,
                        key: None,
                    },
                );
            }
        }
        Self {
            ledger: RwLock::new(ledger),
            active_state: RwLock::new(active_state),
            journal: RwLock::new(LedgerJournal::new()),
            dedup_store: RwLock::new(DeduplicationStore::new()),
            update_stream: RwLock::new(Vec::new()),
            offset_counter: AtomicU64::new(1),
            event_counter: AtomicU64::new(1),
            contract_counter: Arc::new(AtomicU64::new(initial_counter)),
            dar_info: RwLock::new(None),
            package_names: RwLock::new(Vec::new()),
            dar_blobs: RwLock::new(Vec::new()),
            clock: AtomicU64::new(0),
            consumed_at: RwLock::new(HashMap::new()),
            lf_packages: RwLock::new(Vec::new()),
            generic_contracts: RwLock::new(HashMap::new()),
            creation_seq_counter: AtomicU64::new(1),
            v2: crate::v2::V2State::default(),
            v2_submit_lock: std::sync::Mutex::new(()),
            auth: RwLock::new(None),
            traffic_enforcement: std::sync::atomic::AtomicBool::new(false),
            http_list_max_elements_limit: RwLock::new(None),
            http_list_wait_time_ms: RwLock::new(None),
            persist: std::sync::Mutex::new(None),
            batch: std::sync::Mutex::new(None),
            persist_failed: std::sync::atomic::AtomicBool::new(false),
            committer: RwLock::new(None),
            recorder: RwLock::new(None),
            snapshot_every: AtomicU64::new(0),
            observability: crate::observability::ObservabilityState::default(),
            quiesced: AtomicBool::new(false),
            in_flight_writes: AtomicUsize::new(0),
        }
    }

    /// Sets or clears the quiesce gate rejecting new write/command submissions (`S-DX-004`).
    pub fn set_quiesced(&self, quiesced: bool) {
        self.quiesced.store(quiesced, Ordering::SeqCst);
    }

    /// Returns whether new write/command submissions are currently refused.
    pub fn is_quiesced(&self) -> bool {
        self.quiesced.load(Ordering::SeqCst)
    }

    /// Enters an active write/command section unless the service is quiesced.
    pub(crate) fn try_enter_write(&self) -> Result<WriteGuard<'_>, ()> {
        if self.quiesced.load(Ordering::SeqCst) {
            return Err(());
        }
        self.in_flight_writes.fetch_add(1, Ordering::SeqCst);
        if self.quiesced.load(Ordering::SeqCst) {
            self.in_flight_writes.fetch_sub(1, Ordering::SeqCst);
            return Err(());
        }
        Ok(WriteGuard(&self.in_flight_writes))
    }

    /// Total in-flight writes across HTTP/gRPC dispatch, v2 dedup reservations, and protocol consensus.
    pub fn total_in_flight(&self) -> usize {
        let writes = self.in_flight_writes.load(Ordering::SeqCst);
        let dedup_in_flight = self.v2.in_flight.lock().map(|g| g.len()).unwrap_or(0);
        let proto = self
            .committer
            .read()
            .ok()
            .and_then(|c| c.as_ref().map(|p| p.protocol_in_flight()))
            .unwrap_or(0);
        writes.max(dedup_in_flight) + proto
    }

    /// Sets the maximum deduplication duration pruning measures offsets against (default 168 hours, Canton's).
    pub fn set_max_dedup(&self, d: std::time::Duration) {
        self.v2
            .max_dedup_micros
            .store(d.as_micros() as i64, Ordering::SeqCst);
    }

    /// Sets an explicit ACS-commitment safe-to-prune timestamp ceiling in microseconds (`None` disables commitment gating).
    pub fn set_acs_safe_to_prune_micros(&self, micros: Option<i64>) {
        if let Ok(mut g) = self.v2.acs_safe_to_prune_micros.lock() {
            *g = micros;
        }
    }

    /// Returns the active commitment safe-to-prune timestamp ceiling, preferring explicit setting over committer state.
    pub(crate) fn effective_acs_safe_to_prune_micros(&self) -> Option<i64> {
        if let Ok(g) = self.v2.acs_safe_to_prune_micros.lock() {
            if let Some(m) = *g {
                return Some(m);
            }
        }
        self.committer
            .read()
            .ok()
            .and_then(|c| c.as_ref()?.safe_to_prune_micros())
    }

    /// Sets automatic checkpointing cadence in number of logged requests (`0` disables auto-checkpointing).
    pub fn set_snapshot_every(&self, every: u64) {
        self.snapshot_every.store(every, Ordering::SeqCst);
    }

    /// Returns the in-process `CantonExEx` execution extension hub for this participant.
    pub fn exex(&self) -> &crate::exex::ExExHub {
        &self.v2.exex
    }

    /// Replays historical committed updates (`offset >= from_offset`) filtered by `scope`.
    pub fn backfill_exex_from(
        &self,
        from_offset: u64,
        scope: &crate::exex::ExExPartyScope,
    ) -> Vec<crate::exex::ExExNotification> {
        let sync_id = self.v2.synchronizer_id();
        let updates = self.v2.updates();
        self.v2
            .exex
            .backfill_stored_updates(&sync_id, &updates, from_offset, scope)
    }

    /// Physically removes inactive contracts archived at or below `prune_up_to`,
    /// along with updates, completions, and deduplication records up to `prune_up_to` (`U-17`).
    pub(crate) fn evict_pruned_up_to(&self, prune_up_to: u64) {
        self.v2.exex.notify_pruned(prune_up_to);
        let mut archived_le = std::collections::BTreeSet::new();
        let mut retained_above_cids = std::collections::BTreeSet::new();
        if let Ok(mut updates) = self.v2.updates.lock() {
            for u in updates.iter() {
                if u.offset <= prune_up_to {
                    for ev in &u.events {
                        if !ev.created && ev.exercise.as_ref().is_none_or(|x| x.consuming) {
                            archived_le.insert(ev.contract.contract_id.clone());
                        }
                    }
                } else {
                    for ev in &u.events {
                        retained_above_cids.insert(ev.contract.contract_id.clone());
                    }
                }
            }
            updates.retain(|u| u.offset > prune_up_to);
        }
        if let Ok(mut completions) = self.v2.completions.lock() {
            completions.retain(|c| c.offset > prune_up_to);
        }
        if let Ok(mut dedup) = self.v2.dedup.lock() {
            dedup.retain(|_, (off, _, _)| *off > prune_up_to);
        }
        let candidates: Vec<String> = archived_le
            .difference(&retained_above_cids)
            .cloned()
            .collect();
        if candidates.is_empty() {
            return;
        }
        let mut evicted = Vec::new();
        if let Ok(mut generic) = self.generic_contracts.write() {
            for cid in &candidates {
                if generic.get(cid).is_some_and(|c| !c.active) {
                    generic.remove(cid);
                    evicted.push(cid.clone());
                }
            }
        }
        if !evicted.is_empty() {
            if let Ok(mut active) = self.active_state.write() {
                for cid in &evicted {
                    active.active_contracts.remove(&ContractId(cid.clone()));
                }
            }
            if let Ok(mut cons) = self.consumed_at.write() {
                for cid in &evicted {
                    cons.remove(cid);
                }
            }
        }
    }

    /// [CANTON-NOTE: SEMANTICS] All commands of one submission form one transaction: when `body` fails, every change the
    /// commands before the failure made is undone (the generic contracts, the active state, the legacy ledger, the journal
    /// and the update stream), as if the submission had never run. Submissions are serialized by a lock, so nothing else
    /// observes the in-between state.
    /// [CANTON-NOTE: WHY] The per-command entry points (`json_create`, `json_exercise`) each commit on their own; this
    /// gives a batch the all-or-nothing behavior Canton has without rewriting them.
    pub fn v2_atomic<T, E: From<ApiError>>(
        &self,
        body: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let poisoned = |what: &str| E::from(ApiError::Ledger(format!("{what} lock poisoned")));
        let _guard = self.v2_submit_lock.lock().map_err(|_| poisoned("submit"))?;
        // [CANTON-NOTE: WHY] Undo, not copy: the stores used to be cloned whole before every submission (contracts, active set,
        // legacy ledger, journal, update stream), which made each command cost O(size of the ledger) and a long ledger
        // quadratic to build or replay. Now only the changes the batch makes are recorded and reverted on failure.
        let journal_cp = self
            .journal
            .read()
            .map_err(|_| poisoned("journal"))?
            .checkpoint();
        let stream_len = self
            .update_stream
            .read()
            .map_err(|_| poisoned("update stream"))?
            .len();
        self.active_state
            .write()
            .map_err(|_| poisoned("active state"))?
            .begin_batch();
        if let Ok(mut b) = self.batch.lock() {
            *b = Some(BatchUndo::default());
        }
        let dry_run = is_v2_prepare_dry_run();
        let dry_snap = if dry_run {
            Some((
                self.offset_counter.load(Ordering::SeqCst),
                self.event_counter.load(Ordering::SeqCst),
                self.contract_counter.load(Ordering::SeqCst),
                self.creation_seq_counter.load(Ordering::SeqCst),
                self.clock.load(Ordering::SeqCst),
                self.v2.submission_seq.load(Ordering::SeqCst),
                self.consumed_at.read().ok().map(|m| m.clone()),
            ))
        } else {
            None
        };
        let result = body();
        let batch = self.batch.lock().ok().and_then(|mut b| b.take());
        let revert = result.is_err() || dry_run;
        if let Ok(mut a) = self.active_state.write() {
            if revert {
                a.rollback_batch();
            } else {
                a.end_batch();
            }
        }
        if revert {
            if let Some(batch) = batch {
                if let Ok(mut g) = self.generic_contracts.write() {
                    for (cid, old) in batch.contracts.into_iter().rev() {
                        match old {
                            Some(c) => g.insert(cid, c),
                            None => g.remove(&cid),
                        };
                    }
                }
                if let Ok(mut l) = self.ledger.write() {
                    for op in batch.ledger.into_iter().rev() {
                        match op {
                            LedgerUndo::Replaced(old) => *l = *old,
                            LedgerUndo::Padded(contracts, ids) => {
                                l.contracts.truncate(contracts);
                                l.contract_ids.truncate(ids);
                            }
                            LedgerUndo::Slot(idx, old) => {
                                if idx < l.contracts.len() {
                                    l.contracts[idx] = old;
                                }
                            }
                        }
                    }
                }
            }
            if let Ok(mut j) = self.journal.write() {
                j.rollback_to(journal_cp);
            }
            if let Ok(mut u) = self.update_stream.write() {
                u.truncate(stream_len);
            }
            if let Some((off, ev, cc, csc, clk, sseq, cons)) = dry_snap {
                self.offset_counter.store(off, Ordering::SeqCst);
                self.event_counter.store(ev, Ordering::SeqCst);
                self.contract_counter.store(cc, Ordering::SeqCst);
                self.creation_seq_counter.store(csc, Ordering::SeqCst);
                self.clock.store(clk, Ordering::SeqCst);
                self.v2.submission_seq.store(sseq, Ordering::SeqCst);
                if let (Some(prev), Ok(mut cur)) = (cons, self.consumed_at.write()) {
                    *cur = prev;
                }
            }
        }
        result
    }

    /// Notes the previous state of a contract entry for the running batch (a no-op outside `v2_atomic`).
    fn note_contract(&self, cid: &str, old: Option<GenericContract>) {
        if let Ok(mut b) = self.batch.lock() {
            if let Some(b) = b.as_mut() {
                b.contracts.push((cid.to_string(), old));
            }
        }
    }

    fn note_ledger(&self, op: impl FnOnce() -> LedgerUndo) {
        if let Ok(mut b) = self.batch.lock() {
            if let Some(b) = b.as_mut() {
                b.ledger.push(op());
            }
        }
    }

    /// Turns JWT authentication on (every call but the health endpoints then needs a valid bearer token).
    pub fn set_auth(&self, cfg: crate::auth::AuthConfig) {
        if let Ok(mut a) = self.auth.write() {
            *a = Some(cfg);
        }
    }

    pub(crate) fn auth_config(&self) -> Option<crate::auth::AuthConfig> {
        self.auth.read().ok()?.clone()
    }

    /// Enables or disables `/v2/traffic/*` endpoints (`http-ledger-api.traffic-enforcement`).
    pub fn set_traffic_enforcement(&self, enabled: bool) {
        self.traffic_enforcement.store(enabled, Ordering::SeqCst);
    }

    /// Whether `/v2/traffic/*` enforcement endpoints are enabled.
    pub fn traffic_enforcement_enabled(&self) -> bool {
        self.traffic_enforcement.load(Ordering::SeqCst)
    }

    /// Sets the optional max element cap for HTTP blocking list routes (`http-list-max-elements-limit`).
    pub fn set_http_list_max_elements_limit(&self, limit: Option<usize>) {
        if let Ok(mut slot) = self.http_list_max_elements_limit.write() {
            *slot = limit;
        }
    }

    /// Configured max element cap for HTTP blocking list routes (`None` = unlimited).
    pub fn http_list_max_elements_limit(&self) -> Option<usize> {
        self.http_list_max_elements_limit
            .read()
            .ok()
            .and_then(|s| *s)
    }

    /// Sets the optional idle wait time (in ms) for HTTP blocking list routes (`http-list-wait-time`).
    pub fn set_http_list_wait_time_ms(&self, wait_ms: Option<u64>) {
        if let Ok(mut slot) = self.http_list_wait_time_ms.write() {
            *slot = wait_ms;
        }
    }

    /// Configured idle wait time (in ms) for HTTP blocking list routes.
    pub fn http_list_wait_time_ms(&self) -> Option<u64> {
        self.http_list_wait_time_ms.read().ok().and_then(|s| *s)
    }

    /// The state the Canton-shaped v2 endpoints read (S-API-001).
    /// What a request can change without succeeding: the counters ids are drawn from and the completions a rejection records.
    ///
    /// [CANTON-NOTE: SEMANTICS] A failed command still draws a contract id and still leaves a completion, so a client that held
    /// an id from before a restart needs the replay to draw the same ids. The request log therefore keeps a failed request
    /// when this fingerprint moved while it ran (and drops the ones that left no trace, so a stream of bad requests does not
    /// grow the log).
    pub(crate) fn state_fingerprint(&self) -> [u64; 6] {
        let v2 = self.v2_state();
        [
            self.offset_counter.load(Ordering::SeqCst),
            self.event_counter.load(Ordering::SeqCst),
            self.contract_counter.load(Ordering::SeqCst),
            v2.ledger_end.load(Ordering::SeqCst),
            v2.submission_seq.load(Ordering::SeqCst),
            v2.completions_len() as u64,
        ]
    }

    pub(crate) fn persist_slot(
        &self,
    ) -> &std::sync::Mutex<Option<Box<dyn crate::store::RequestLog>>> {
        &self.persist
    }

    pub fn v2_state(&self) -> &crate::v2::V2State {
        &self.v2
    }

    /// Role-aware readiness check (`GET /readyz`): verifies persistence health and synchronizer link.
    pub fn check_ready(&self) -> Result<(), String> {
        if self
            .persist_failed
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("request log persistence failed".to_string());
        }
        let committer = self.committer.read().ok().and_then(|c| c.clone());
        if let Some(c) = committer {
            c.check_ready()?;
        }
        Ok(())
    }

    /// The package ids of the loaded DARs (latest main package first), for `GET /v2/packages`.
    pub fn package_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        let loaded = self
            .v2_state()
            .loaded_dars
            .lock()
            .map(|d| d.clone())
            .unwrap_or_default();
        if !loaded.is_empty() {
            for entry in loaded.iter().rev() {
                for id in &entry.package_ids {
                    if !ids.contains(id) {
                        ids.push(id.clone());
                    }
                }
            }
        } else if !self.v2_state().dar_ever_loaded.load(Ordering::SeqCst) {
            ids = self.packages_response().package_ids;
        }
        // the packages an official database holds beyond the DAR that is loaded (U-47): listed, not executable here
        if let Ok(known) = self.v2_state().known_packages.lock() {
            for id in known.iter() {
                if !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
        }
        ids
    }

    /// Lists the packages an official participant's database holds (see `package_ids`).
    pub fn note_known_packages(&self, ids: &[String]) {
        if let Ok(mut known) = self.v2_state().known_packages.lock() {
            *known = ids.to_vec();
        }
    }

    fn sync_contract_counter_from_ledger(&self, ledger: &SingleContractLedger) {
        // [CANTON-NOTE: INVARIANT] The contract ID counter must always stay strictly ahead of
        // the highest contract ID allocated by either the legacy SingleContractLedger or the generic Engine.
        // [CANTON-NOTE: WHY] Without cross-path synchronization, SingleContractLedger (which indexes from 0)
        // and generic Engine (which increments an independent counter from 0) allocate colliding contract IDs
        // (such as #0:0), causing ACS duplicate ID corruption and permanent shadowing of legacy contracts.
        let next_id = ledger.contracts.len() as u64;
        self.contract_counter.fetch_max(next_id, Ordering::SeqCst);
    }

    fn pad_ledger_slots(&self) {
        // [CANTON-NOTE: INVARIANT] SingleContractLedger contract slots must account for generic contract IDs
        // so that subsequent legacy operations never reuse an ID previously issued to a generic contract.
        // [CANTON-NOTE: WHY] SingleContractLedger allocates IDs as its contracts vector length minus one.
        // Padding inactive None slots guarantees globally distinct contract IDs across both execution paths.
        if let Ok(mut ledger) = self.ledger.write() {
            let current_max = self.contract_counter.load(Ordering::SeqCst) as usize;
            if ledger.contracts.len() < current_max {
                let (c, i) = (ledger.contracts.len(), ledger.contract_ids.len());
                self.note_ledger(|| LedgerUndo::Padded(c, i));
            }
            while ledger.contracts.len() < current_max {
                let idx = ledger.contracts.len();
                ledger.contracts.push(None);
                ledger.contract_ids.push(format!("#generic:{idx}"));
            }
        }
    }

    fn mark_ledger_contract_archived(&self, contract_id: &str) {
        // [CANTON-NOTE: SEMANTICS] When a contract is archived in Daml, it transitions to an inactive state
        // and must never be available for subsequent choice execution or ACS queries.
        // [CANTON-NOTE: INVARIANT] SingleContractLedger contract slots corresponding to consumed contracts
        // must be set to None, synchronizing with generic_contracts (active = false).
        // [CANTON-NOTE: WHY] If a contract was originally created or promoted from SingleContractLedger,
        // consuming it in Generic mode leaves its legacy slot as Some(holding) unless explicitly archived.
        // Synchronizing the legacy slot prevents cross-store inconsistencies.
        // [CANTON-NOTE: LIMITATION] SingleContractLedger uses numeric index contract IDs (#<idx>:0);
        // non-matching opaque IDs are silently ignored as they have no corresponding legacy slot.
        if let Ok(idx) = Self::parse_contract_id(contract_id) {
            if let Ok(mut ledger) = self.ledger.write() {
                if idx < ledger.contracts.len() {
                    let old = ledger.contracts[idx].take();
                    self.note_ledger(|| LedgerUndo::Slot(idx, old));
                }
            }
        }
    }

    /// [CANTON-NOTE: INVARIANT] Single unified commit path for all state-mutating operations.
    ///
    /// [CANTON-NOTE: WHY] Prevents divergence between `submit_and_wait` and `json_exercise`.
    /// Guarantees atomic rollback if `apply_transaction` rejects the transaction tree.
    /// [CANTON-NOTE: SEMANTICS] Phase 1 validates TOCTOU concurrency and verifies `ActiveLedgerState::apply_transaction`.
    /// Phase 2 only modifies in-memory stores (`generic_contracts`, `ledger`, `journal`, `update_stream`) once validation succeeds.
    /// The vetting transaction the synchronizer's participant signs for `package_ids` at `serial` (see [`ProtocolCommitter::vetting_transaction`]).
    pub fn protocol_vetting(
        &self,
        package_ids: &[String],
        serial: u32,
    ) -> Option<SignedTopologyRecord> {
        let committer = self.committer.read().ok().and_then(|c| c.clone())?;
        committer.vetting_transaction(package_ids, serial)
    }

    /// Broadcasts an updated set of vetted package IDs through the protocol committer, if attached.
    pub fn sync_vetted_packages(
        &self,
        synchronizer_id: Option<&str>,
        vetted_pkg_ids: &[String],
    ) -> Result<(), ApiError> {
        let Some(committer) = self.committer.read().ok().and_then(|c| c.clone()) else {
            return Ok(());
        };
        committer.sync_vetted_packages(synchronizer_id, vetted_pkg_ids)
    }

    /// Number of pending topology changes waiting to become effective in the protocol runtime.
    pub fn pending_topology_changes(&self) -> usize {
        self.committer
            .read()
            .ok()
            .and_then(|c| c.as_ref().map(|c| c.pending_topology_changes()))
            .unwrap_or(0)
    }

    /// Records a bound port (`"ledger"` / `"admin"` / `"http"`) for Admin `Status` / `ParticipantStatus`.
    pub fn set_admin_port(&self, name: &str, port: u16) {
        if let Ok(mut ports) = self.v2.admin_ports.lock() {
            ports.insert(name.to_string(), i32::from(port));
        }
    }

    /// Recorded service ports for Admin `Status` / `ParticipantStatus`.
    pub fn admin_ports(&self) -> std::collections::BTreeMap<String, i32> {
        self.v2
            .admin_ports
            .lock()
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    /// The synchronizer's party for `hint`, when there is a synchronizer behind the service.
    pub fn protocol_party(&self, hint: &str) -> Option<Result<String, ApiError>> {
        let committer = self.committer.read().ok().and_then(|c| c.clone())?;
        let allocated = committer.allocate_party(hint);
        if let Some(Ok(party)) = &allocated {
            // `--official-write`: the party is in the official database's topology store too, so the official participant lists it (U-50)
            let sink = self
                .v2_state()
                .official_topology_sink
                .lock()
                .ok()
                .and_then(|s| s.clone());
            if let (Some(sink), Some(hosted)) = (sink, committer.hosting_transaction(hint)) {
                if &hosted.party == party {
                    sink(&hosted);
                }
            }
        }
        allocated
    }

    /// Returns whether `contract_id` is already held in the generic contract store (e.g. adopted from an official database).
    pub(crate) fn has_known_contract(&self, contract_id: &str) -> bool {
        self.generic_contracts
            .read()
            .is_ok_and(|g| g.contains_key(contract_id))
    }

    /// Puts a synchronizer behind the service: from now on every transaction is judged by it before it is applied.
    /// Lets go of the synchronizer behind the service (before the node behind it is restarted).
    /// Puts back what a protocol-mode participant kept of the ledger API's own state (updates, completions and command deduplication,
    /// oldest first) and moves the ledger end past them, so the offsets go on where they stopped (U-44). Then hands every later entry to
    /// `sink`.
    #[cfg_attr(
        not(feature = "protocol"),
        allow(dead_code, reason = "used by the protocol-mode committer")
    )]
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) fn restore_journals(
        &self,
        updates: Vec<crate::v2_commands::StoredUpdate>,
        completions: Vec<crate::v2_completions::Completion>,
        dedup: Vec<((String, String, Vec<String>), (u64, i64, String))>,
        sink: std::sync::Arc<dyn Fn(&str, String) -> Result<(), String> + Send + Sync>,
    ) {
        let state = self.v2_state();
        let last = updates
            .iter()
            .map(|u| u.offset)
            .chain(completions.iter().map(|c| c.offset))
            .max()
            .unwrap_or(0);
        if let Ok(mut created) = state.created_offsets.lock() {
            for item in &updates {
                for ev in item.events.iter().filter(|e| e.created) {
                    created.insert(ev.contract.contract_id.clone(), (item.offset, ev.node));
                }
            }
        }
        if let Ok(mut u) = state.updates.lock() {
            u.retain(|x| x.update_id != "remote-0");
            for item in updates {
                if !u.iter().any(|x| x.offset == item.offset) {
                    u.push(item);
                }
            }
            u.sort_by_key(|x| x.offset);
        }
        if let Ok(mut c) = state.completions.lock() {
            for item in completions {
                if !c.iter().any(|x| x.offset == item.offset) {
                    c.push(item);
                }
            }
            c.sort_by_key(|x| x.offset);
        }
        if let Ok(mut d) = state.dedup.lock() {
            d.extend(dedup);
        }
        state
            .ledger_end
            .fetch_max(last, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut s) = state.journal_sink.lock() {
            *s = Some(sink);
        }
    }

    #[doc(hidden)]
    #[expect(
        clippy::type_complexity,
        reason = "test hook mirrors restore_journals sink callback signature"
    )]
    pub fn set_journal_sink_for_test(
        &self,
        sink: std::sync::Arc<dyn Fn(&str, String) -> Result<(), String> + Send + Sync>,
    ) {
        let state = self.v2_state();
        if let Ok(mut s) = state.journal_sink.lock() {
            *s = Some(sink);
        }
    }

    /// Makes the parties of an official participant's database this service's parties (see `V2State::adopt_official_parties`).
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub fn adopt_official_parties(
        &self,
        participant_uid: &str,
        parties: &[(String, bool)],
        records: &[(
            String,
            u64,
            std::collections::BTreeMap<String, String>,
            String,
        )],
    ) {
        self.v2_state()
            .adopt_official_parties(participant_uid, parties, records);
    }

    /// Makes the users, identity providers and DARs of an official participant's database this service's (see `adopt_official_parties`): users as
    /// `(id, primary party, deactivated, resource version, identity provider, annotations, rights (code, party))`, identity providers as `(id, issuer,
    /// JWKS URL, audience, deactivated)`, and every DAR is loaded.
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub fn adopt_official_users_and_idps(
        &self,
        users: &[(
            String,
            String,
            bool,
            u64,
            String,
            std::collections::BTreeMap<String, String>,
            Vec<(i32, String)>,
        )],
        idps: &[(String, String, String, String, bool)],
    ) {
        let state = self.v2_state();
        crate::v2_users::adopt_official_users(state, users);
        crate::v2_idps::adopt_official_idps(state, idps);
    }

    /// Puts the ledger end of an official participant's database as this service's (the offsets of what it commits go on from there).
    pub fn note_created_offset(
        &self,
        contract_id: &str,
        offset: u64,
        node: u64,
        synchronizer: &str,
    ) {
        if let Ok(mut m) = self.v2_state().created_offsets.lock() {
            m.insert(contract_id.to_string(), (offset, node));
        }
        // the contract is on the synchronizer of the database it was read from, not on the one this service joined
        self.v2_state()
            .note_location(contract_id, synchronizer.to_string(), 0);
    }

    /// Puts the ledger end of an official participant's database as this service's (the offsets of what it commits go on from there).
    pub fn adopt_official_ledger_end(&self, offset: u64) {
        self.v2_state()
            .ledger_end
            .fetch_max(offset, std::sync::atomic::Ordering::SeqCst);
    }

    /// Shows the command completions of an official participant's database and the synchronizer times its checkpoints carry.
    #[cfg_attr(
        not(feature = "protocol"),
        allow(dead_code, reason = "used by the protocol-mode participant")
    )]
    pub(crate) fn adopt_official_completions(
        &self,
        completions: Vec<crate::v2_completions::Completion>,
        checkpoint: Vec<(String, String)>,
    ) {
        self.v2_state().adopt_completions(completions, checkpoint);
    }

    /// The packages of every DAR loaded so far.
    #[cfg_attr(
        not(feature = "protocol"),
        allow(dead_code, reason = "used by the protocol-mode participant")
    )]
    pub(crate) fn loaded_packages(&self) -> Result<Vec<Arc<LfPackage>>, ApiError> {
        self.lf_packages
            .read()
            .map(|p| p.clone())
            .map_err(|e| ApiError::Ledger(e.to_string()))
    }

    /// Shows the update history of an official participant's database (see [`crate::protocol::official_updates_in`]).
    #[cfg_attr(
        not(feature = "protocol"),
        allow(dead_code, reason = "used by the protocol-mode participant")
    )]
    pub(crate) fn adopt_official_updates(&self, updates: Vec<crate::v2_commands::StoredUpdate>) {
        self.v2_state().adopt_updates(updates);
    }

    pub fn clear_committer(&self) {
        if let Ok(mut c) = self.committer.write() {
            *c = None;
        }
    }

    /// Writes every transaction this service commits to `recorder` (the update history `canton-rs scan serve` answers from).
    pub fn set_update_recorder(&self, recorder: Arc<crate::history::UpdateRecorder>) {
        if let Ok(mut r) = self.recorder.write() {
            *r = Some(recorder);
        }
    }

    pub fn set_committer(&self, committer: Arc<dyn ProtocolCommitter>) {
        // [CANTON-NOTE: SEMANTICS] a participant on several synchronizers reports the real one a contract is on: the first takes the
        // transactions (S-NET-040)
        if let Some((_, first)) = committer.synchronizers().into_iter().next() {
            if let Ok(mut s) = self.v2_state().synchronizer.lock() {
                *s = first;
            }
        }
        if !self
            .v2
            .official_parties
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            if let Some(uid) = committer.participant_id() {
                self.v2.set_participant_id(&uid);
            }
        }
        if let Ok(mut c) = self.committer.write() {
            *c = Some(committer);
        }
    }
}
