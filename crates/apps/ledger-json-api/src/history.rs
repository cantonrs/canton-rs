//! The update history a node writes for the scan app (G8, S-SPL-007): every transaction the engine ran and the ledger committed is rendered
//! as the update item the official Splice scan app prints (`lf_eval::scan_update`) and appended to a history file, one JSON object per line.
//! `canton-rs scan serve --history <file>` answers the scan update endpoints from that file and re-reads it when it grows.
//!
//! [CANTON-NOTE: WHY] A node renders at commit time, not at request time: the item needs the contracts the engine had in memory (the created
//! ones and the ones exercised) and the update id of the commit, and the engine of a command is gone once the command has returned.
//!
//! [CANTON-NOTE: LIMITATION] One package world renders a transaction: a command that touches contracts of two loaded DARs is not recorded
//! (the failure goes to stderr, the commit is not affected). Transactions the node only confirmed for another participant carry no engine
//! journal and are not recorded either.
use crate::service::LfPackage;
use lf_eval::scan_update::{render_update_with, UpdateMeta};
use lf_eval::typed_json::Types;
use lf_eval::{Contract, EngineEvent};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// What a command remembers of its engine so the commit can render the update later.
#[derive(Clone)]
pub struct HistoryInput {
    pub package: Arc<LfPackage>,
    /// Every contract the journal names (created or exercised), as the engine held it when the command ran.
    pub contracts: HashMap<String, Contract>,
    /// The journal of the whole transaction in execution order (a root create is a `Create` event of its own here: the committer's own
    /// `engine_events` keep only what it needs to place the nodes of an exercise).
    pub events: Vec<EngineEvent>,
    /// Explicit ledger effective timestamp override (microseconds) when not derived from created contracts.
    pub effective_at_micros: Option<i64>,
    /// Explicit synchronizer record timestamp override (microseconds), e.g. from remote transaction delivery.
    pub record_time_micros: Option<i64>,
}

impl std::fmt::Debug for HistoryInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryInput")
            .field("package", &self.package.main_package_id)
            .field("contracts", &self.contracts.len())
            .finish()
    }
}

impl HistoryInput {
    pub fn new(package: Arc<LfPackage>) -> Self {
        Self {
            package,
            contracts: HashMap::new(),
            events: Vec::new(),
            effective_at_micros: None,
            record_time_micros: None,
        }
    }

    /// Remembers the contracts `events` name, looked up in the engine that produced them.
    pub fn remember(&mut self, events: &[EngineEvent], lookup: impl Fn(&str) -> Option<Contract>) {
        self.events.extend(events.iter().cloned());
        for event in events {
            if let EngineEvent::Create { contract_id, .. }
            | EngineEvent::Exercise { contract_id, .. } = event
            {
                if let Some(c) = lookup(contract_id) {
                    self.contracts.insert(contract_id.clone(), c);
                }
            }
        }
    }
}

/// Appends rendered updates to the history file.
pub struct UpdateRecorder {
    path: PathBuf,
    synchronizer_id: String,
    migration_id: i64,
    /// When the contracts this node created were created, by contract id (the ledger time of the request that made them): the update that
    /// creates them is recorded at that time, as the protocol's contracts carry it.
    created_at: Mutex<HashMap<String, i64>>,
    /// One-shot protocol effective time for a non-creating exercise whose commit was just approved.
    pending_effective: Mutex<Option<i64>>,
    /// The record time of the last update written: record times strictly increase so the history keeps the commit order.
    last_micros: Mutex<i64>,
}

impl UpdateRecorder {
    /// The file the contract salts go to: next to the history, one JSON object per line (`{"contract_id", "authentication_data"}`, hex).
    pub fn authentication_path(&self) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(".auth");
        PathBuf::from(name)
    }

    /// Remembers when a contract of this node was created (see `created_at`).
    pub fn note_created_at(&self, contract_id: &str, micros: i64) {
        if let Ok(mut m) = self.created_at.lock() {
            m.insert(contract_id.to_string(), micros);
        }
    }

    /// Sets the protocol effective time (microseconds) for the immediately following recorded update.
    pub fn note_effective_at(&self, micros: i64) {
        if let Ok(mut p) = self.pending_effective.lock() {
            *p = Some(micros);
        }
    }

    /// Remembers the `authentication_data` (the contract salt message) of a contract this node created: a scan's blob of the contract needs
    /// it and no update states it (S-SPL-010).
    pub fn note_authentication(
        &self,
        contract_id: &str,
        authentication_data: &[u8],
    ) -> Result<(), String> {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mut line = serde_json::json!({
            "contract_id": contract_id,
            "authentication_data": hex(authentication_data),
        })
        .to_string();
        line.push('\n');
        let path = self.authentication_path();
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut f| f.write_all(line.as_bytes()))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }

    pub fn new(path: impl Into<PathBuf>, synchronizer_id: &str, migration_id: i64) -> Self {
        Self {
            path: path.into(),
            synchronizer_id: synchronizer_id.to_string(),
            migration_id,
            created_at: Mutex::new(HashMap::new()),
            pending_effective: Mutex::new(None),
            last_micros: Mutex::new(0),
        }
    }

    /// Renders the committed transaction and appends it. `update_id` and `workflow_id` are those of the transaction tree the commit recorded.
    pub fn record(
        &self,
        input: &HistoryInput,
        update_id: &str,
        workflow_id: &str,
    ) -> Result<(), String> {
        let events = &input.events;
        if events.is_empty() {
            return Ok(());
        }
        let micros = {
            let mut last = self.last_micros.lock().map_err(|e| e.to_string())?;
            let base = input
                .record_time_micros
                .unwrap_or_else(crate::clock::now_micros);
            let now = base.max(*last + 1);
            *last = now;
            now
        };
        // an update that creates a contract of this node is effective at the time the protocol gave that contract;
        // non-creating updates use the explicit / pending protocol time when provided before falling back to record time.
        let pending = self
            .pending_effective
            .lock()
            .ok()
            .and_then(|mut p| p.take());
        let effective = events
            .iter()
            .find_map(|e| match e {
                EngineEvent::Create { contract_id, .. } => self
                    .created_at
                    .lock()
                    .ok()
                    .and_then(|m| m.get(contract_id).copied()),
                _ => None,
            })
            .or(input.effective_at_micros)
            .or(pending)
            .unwrap_or(micros);
        let types = Types::new(&input.package.world);
        let meta = UpdateMeta {
            update_id,
            migration_id: self.migration_id,
            workflow_id,
            synchronizer_id: &self.synchronizer_id,
            record_time_micros: micros,
            effective_at_micros: effective,
        };
        let item = render_update_with(
            &types,
            &|id| input.contracts.get(id).cloned(),
            &meta,
            events,
        )?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("cannot open {}: {e}", self.path.display()))?;
        // one write call per line: a reader never sees half of one
        let mut line = serde_json::to_string(&item).map_err(|e| e.to_string())?;
        line.push('\n');
        file.write_all(line.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", self.path.display()))
    }
}
