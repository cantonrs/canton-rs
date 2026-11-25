//! JSON Ledger API v2 (`/v2/...`, the shape Canton 3.7.2 documents in `openapi.yaml`) - S-API-001.
//!
//! Every response shape here was recorded from a real Canton 3.7.2 sandbox (`tests/oracle/json-api`, replayed by
//! `scripts/verify-json-api.sh`); the Rust test `tests/json_api_v2_oracle.rs` replays the same requests against this module.
//! [CANTON-NOTE: LIMITATION] This module covers the metadata, party, package, user and idp reads, party allocation and the error
//! bodies. Commands, updates, completions, DAR upload and the other `openapi.yaml` endpoints are served by the sibling `v2_*` modules;
//! `/v2/...` paths that none of them nor the older routes claim answer Canton's 404 body.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;

/// `1220` (the multihash prefix of SHA-256) + 64 hex digits: the shape of a Canton namespace fingerprint.
fn namespace() -> String {
    // a fixed fingerprint for this participant: SHA-256 of a constant text, written out so the crate needs no hash dependency
    "12204e24ac89d9fb4bb2b9a40aab08c20c660ccd3c0d257a5b49ef84d9b04016b25d".to_string()
}

/// A party's local metadata once it was updated: resource version and annotations.
pub(crate) type PartyMeta =
    std::collections::HashMap<String, (u64, std::collections::BTreeMap<String, String>)>;

/// A DAR currently held by this participant (loaded at start-up or uploaded via the API).
#[derive(Clone)]
pub(crate) struct LoadedDarEntry {
    pub main_package_id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub bytes: Vec<u8>,
    pub package_ids: Vec<String>,
}

/// Synchronizer registration and lifecycle entry managed via Admin `SynchronizerConnectivityService`.
#[derive(Clone, Debug)]
pub struct RegisteredSync {
    pub alias: String,
    pub synchronizer_id: String,
    pub physical_synchronizer_id: String,
    pub sequencer_endpoints: Vec<String>,
    pub manual_connect: bool,
    pub priority: i32,
    pub connected: bool,
    pub handshake_only: bool,
}

/// Configured slow counter-participant threshold entry for Admin `ParticipantInspectionService`.
#[derive(Clone, Debug)]
pub struct SlowCounterConfig {
    pub synchronizer_ids: Vec<String>,
    pub distinguished_participant_uids: Vec<String>,
    pub threshold_distinguished: u64,
    pub threshold_default: u64,
    pub participant_uids_metrics: Vec<String>,
}

/// Pending repair operation metadata tracked by `ParticipantRepairService`.
#[derive(Clone, Debug)]
pub struct PendingRepairOp {
    pub synchronizer_id: String,
    pub operation_id: String,
    pub name: String,
    pub status: String,
}

/// The ledger state the v2 endpoints read: allocated parties and the ledger end.
/// Command deduplication table: `(user, command id, sorted act-as)` -> `(completion offset, record micros, submission id)`.
pub(crate) type DedupTable =
    std::collections::HashMap<(String, String, Vec<String>), (u64, i64, String)>;

pub struct V2State {
    /// The participant's id (`name::fingerprint`); replaced once by [`V2State::adopt_official_parties`] when the service starts on an official database.
    pub(crate) participant: std::sync::RwLock<String>,
    /// Parties of the topology that another participant hosts (`isLocal: false`), read from an official database.
    pub(crate) remote_parties: Mutex<std::collections::BTreeSet<String>>,
    /// Set when the party list comes from an official participant's database: a party without a metadata record has an empty resource version
    /// (the official API lists a console-enabled party that way), and `isLocal` and the identity provider come from the database.
    pub(crate) official_parties: std::sync::atomic::AtomicBool,
    /// The offset a contract was created at and its node in the creating transaction, for the contracts read from an official database (U-47):
    /// the ACS reports them in the created event (a contract this service made is reported at the ledger end, node 0, as before).
    pub(crate) created_offsets: Mutex<std::collections::HashMap<String, (u64, u64)>>,
    /// The record time of each synchronizer at the ledger end of an official database `(synchronizer id, RFC 3339 time)`: what its `OffsetCheckpoint`s say.
    pub(crate) official_checkpoint: Mutex<Vec<(String, String)>>,
    /// The ids of the packages an official database holds, listed by `/v2/packages` besides the loaded DAR's (U-47).
    pub(crate) known_packages: Mutex<Vec<String>>,
    /// The identity provider of a party record (absent: the default one).
    pub(crate) party_idp: Mutex<std::collections::HashMap<String, String>>,
    pub(crate) parties: Mutex<Vec<String>>,
    pub(crate) ledger_end: AtomicU64,
    pub(crate) updates: Mutex<Vec<crate::v2_commands::StoredUpdate>>,
    pub(crate) packages: Mutex<crate::v2_packages::Packages>,
    pub(crate) loaded_dars: Mutex<Vec<LoadedDarEntry>>,
    pub(crate) dar_ever_loaded: std::sync::atomic::AtomicBool,
    /// Resource version and annotations of a party's local metadata, once it was updated.
    pub(crate) party_meta: Mutex<PartyMeta>,
    pub(crate) completions: Mutex<Vec<crate::v2_completions::Completion>>,
    /// Command deduplication: (user, command id, sorted act-as) -> (completion offset, record time in microseconds, submission id).
    pub(crate) dedup: Mutex<DedupTable>,
    /// The change ids whose submission is in flight (`crate::dedup`).
    pub(crate) in_flight: crate::dedup::InFlightChanges,
    /// The topology serial of the participant's package-vetting state (starts at 1, the preloaded packages).
    pub(crate) vetting_serial: Mutex<u64>,
    pub(crate) idps: Mutex<crate::v2_idps::Idps>,
    pub(crate) users: Mutex<std::collections::BTreeMap<String, crate::v2_users::UserRec>>,
    /// Numbers the submission ids the service makes up (per service, so a replayed ledger makes the same ones).
    pub(crate) submission_seq: AtomicU64,
    /// The highest offset pruned so far (S-STORE-007; 0: nothing). Reads below it are refused, the data stays in memory.
    pub(crate) pruned_up_to: AtomicU64,
    /// The maximum deduplication duration in microseconds: an offset younger than this cannot be pruned (Canton default 168 h).
    pub(crate) max_dedup_micros: std::sync::atomic::AtomicI64,
    /// Safe-to-prune timestamp ceiling from ACS commitment reconciliation (`None` = unconstrained by commitments).
    pub(crate) acs_safe_to_prune_micros: Mutex<Option<i64>>,
    /// Externally onboarded parties and their authorized signing keys/threshold.
    pub(crate) external_parties:
        Mutex<std::collections::HashMap<String, crate::v2_interactive::ExternalPartyInfo>>,
    /// Prepared transactions cached by `(logical synchronizer, hash_32)` for low-latency execute, bounded in size and age.
    pub(crate) prepared_cache: Mutex<crate::prepared_cache::PreparedCache>,
    /// Configured synchronizer identifier (defaults to `SYNCHRONIZER`; overridable in tests for oracle replay).
    pub(crate) synchronizer: Mutex<String>,
    /// Where reassigned contracts are (S-NET-040).
    pub(crate) reassign: Mutex<crate::v2_reassign::ReassignState>,
    /// Told of every update, completion and deduplication entry when it is recorded, as `(journal key, one line)`: a protocol-mode
    /// participant keeps them across a restart (U-44).
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) journal_sink:
        Mutex<Option<std::sync::Arc<dyn Fn(&str, String) -> Result<(), String> + Send + Sync>>>,
    /// The parties the Ledger API allocated (their records are in the official tables; a party the topology lists without a record has none).
    pub(crate) api_parties: Mutex<std::collections::BTreeSet<String>>,
    /// Told the administration state after every change, and the bytes of every DAR uploaded: what writes them to an official database
    /// (`--official-write`, U-47).
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) official_admin_sink:
        Mutex<Option<std::sync::Arc<dyn Fn(&OfficialAdminRows) + Send + Sync>>>,
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) official_dar_sink: Mutex<Option<std::sync::Arc<dyn Fn(&[u8]) + Send + Sync>>>,
    /// Told the topology transaction of every party this participant starts to host (`--official-write`, U-50): what writes it to the official database's topology store.
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) official_topology_sink:
        Mutex<Option<std::sync::Arc<dyn Fn(&crate::service::HostedParty) + Send + Sync>>>,
    /// Told every committed update with its completion, and every refused command's completion: what writes the transactions to an official database.
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) official_update_sink: Mutex<
        Option<
            std::sync::Arc<
                dyn Fn(
                        &crate::v2_commands::StoredUpdate,
                        Option<&crate::v2_completions::Completion>,
                    ) + Send
                    + Sync,
            >,
        >,
    >,
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) official_rejection_sink:
        Mutex<Option<std::sync::Arc<dyn Fn(&crate::v2_completions::Completion) + Send + Sync>>>,
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) official_prune_sink:
        Mutex<Option<std::sync::Arc<dyn Fn(u64) -> Result<(), String> + Send + Sync>>>,
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) journal_prune_sink: Mutex<Option<std::sync::Arc<dyn Fn(&Self, u64) + Send + Sync>>>,
    /// Memoized `(template_package_id, "Module:Template") -> [(iface_package_id, "Module:Interface")]`.
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) implemented_interfaces_cache:
        Mutex<std::collections::HashMap<(String, String), Vec<(String, String)>>>,
    /// Synchronizer registration/connection table (`None` until first Admin connectivity call).
    pub(crate) registered_syncs: Mutex<Option<Vec<RegisteredSync>>>,
    /// Slow counter-participant thresholds managed via `ParticipantInspectionService`.
    pub(crate) slow_counter_configs: Mutex<Vec<SlowCounterConfig>>,
    /// Sequenced event ranges ignored via `ParticipantRepairService/{IgnoreEvents,UnignoreEvents}`.
    pub(crate) ignored_events: Mutex<Vec<(String, i64, i64)>>,
    /// Pending repair operations tracked by `ParticipantRepairService`.
    pub(crate) pending_repair_ops: Mutex<Vec<PendingRepairOp>>,
    /// Stored participant-added signed topology transactions (`store_id`, `SignedTopologyTransaction` protobuf bytes).
    pub(crate) extra_topology_txs: Mutex<Vec<(String, Vec<u8>)>>,
    /// Runtime log level toggled by `StatusService/SetLogLevel`.
    pub(crate) admin_log_level: Mutex<String>,
    /// Admin/Ledger API bound ports for `Status` / `ParticipantStatus` reporting.
    pub(crate) admin_ports: Mutex<std::collections::BTreeMap<String, i32>>,
    /// Traffic enforcement accounts and pruneable event/correlation timestamps.
    pub(crate) traffic: Mutex<crate::v2_traffic::TrafficState>,
    /// In-process privacy-scoped post-commit execution extension hub (`CantonExEx`).
    pub exex: crate::exex::ExExHub,
    /// Serializes `(ledger_end advance -> record_update)` so offsets and ExEx delivery order match.
    pub(crate) commit_publish_lock: Mutex<()>,
}

/// The administration state in the shape of the official tables (`lapi_users`, `lapi_user_rights`, `lapi_user_annotations`, `lapi_party_records`,
/// `lapi_party_record_annotations`, `lapi_identity_provider_config`).
#[allow(
    clippy::type_complexity,
    reason = "protocol or ledger hook signature uses an inline composite type"
)]
pub struct OfficialAdminRows {
    pub users: Vec<(
        String,
        String,
        bool,
        u64,
        String,
        std::collections::BTreeMap<String, String>,
        Vec<(i32, Option<String>)>,
    )>,
    /// `(party, resource version, identity provider, annotations)` of each party with a record.
    pub parties: Vec<(
        String,
        u64,
        String,
        std::collections::BTreeMap<String, String>,
    )>,
    pub idps: Vec<(String, String, String, String, bool)>,
}

impl Default for V2State {
    fn default() -> Self {
        Self::try_new().expect("system CSPRNG required for ExEx HMAC key")
    }
}

impl V2State {
    /// How many entries the command deduplication table holds (an observation of S-SIM-001 K-10: a `prepare` must add none).
    pub fn dedup_entry_count(&self) -> usize {
        self.dedup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Initializes Ledger API v2 runtime state using the system CSPRNG for ExEx HMAC keys.
    pub fn try_new() -> Result<Self, String> {
        Self::try_new_with_exex(crate::exex::ExExHub::try_new()?)
    }

    /// Initializes Ledger API v2 runtime state with an injected CSPRNG closure for ExEx HMAC key generation.
    pub fn try_new_with_exex_rng<E: std::fmt::Display>(
        fill_key: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, String> {
        Self::try_new_with_exex(crate::exex::ExExHub::try_new_with_rng(fill_key)?)
    }

    fn try_new_with_exex(exex: crate::exex::ExExHub) -> Result<Self, String> {
        let participant = format!("rust::{}", namespace());
        Ok(Self {
            parties: Mutex::new(vec![participant.clone()]),
            participant: std::sync::RwLock::new(participant),
            remote_parties: Mutex::new(Default::default()),
            official_parties: std::sync::atomic::AtomicBool::new(false),
            party_idp: Mutex::new(Default::default()),
            known_packages: Mutex::new(Vec::new()),
            created_offsets: Mutex::new(Default::default()),
            official_checkpoint: Mutex::new(Vec::new()),
            ledger_end: AtomicU64::new(0),
            updates: Mutex::new(Vec::new()),
            users: Mutex::new(crate::v2_users::default_users()),
            packages: Mutex::new(Default::default()),
            loaded_dars: Mutex::new(Vec::new()),
            dar_ever_loaded: std::sync::atomic::AtomicBool::new(false),
            idps: Mutex::new(Default::default()),
            vetting_serial: Mutex::new(1),
            completions: Mutex::new(Vec::new()),
            dedup: Mutex::new(Default::default()),
            in_flight: Mutex::new(Default::default()),
            party_meta: Mutex::new(Default::default()),
            submission_seq: AtomicU64::new(1),
            pruned_up_to: AtomicU64::new(0),
            max_dedup_micros: std::sync::atomic::AtomicI64::new(168 * 3_600 * 1_000_000),
            acs_safe_to_prune_micros: Mutex::new(None),
            external_parties: Mutex::new(Default::default()),
            prepared_cache: Mutex::new(Default::default()),
            synchronizer: Mutex::new(crate::v2_commands::SYNCHRONIZER.to_string()),
            reassign: Mutex::new(Default::default()),
            journal_sink: Mutex::new(None),
            api_parties: Mutex::new(Default::default()),
            official_admin_sink: Mutex::new(None),
            official_dar_sink: Mutex::new(None),
            official_topology_sink: Mutex::new(None),
            official_update_sink: Mutex::new(None),
            official_rejection_sink: Mutex::new(None),
            official_prune_sink: Mutex::new(None),
            journal_prune_sink: Mutex::new(None),
            implemented_interfaces_cache: Mutex::new(Default::default()),
            registered_syncs: Mutex::new(None),
            slow_counter_configs: Mutex::new(Vec::new()),
            ignored_events: Mutex::new(Vec::new()),
            pending_repair_ops: Mutex::new(Vec::new()),
            extra_topology_txs: Mutex::new(Vec::new()),
            admin_log_level: Mutex::new("INFO".to_string()),
            admin_ports: Mutex::new(Default::default()),
            traffic: Mutex::new(Default::default()),
            exex,
            commit_publish_lock: Mutex::new(()),
        })
    }

    /// Hands one line to the journal sink, when the participant keeps a journal; returns `false` if encoding fails, the sink fails, or its lock is poisoned.
    pub(crate) fn journal(&self, key: &str, line: impl FnOnce() -> Result<String, String>) -> bool {
        let Ok(sink_guard) = self.journal_sink.lock() else {
            crate::diag::diag_eprintln!(
                "an entry of {key} is not kept: journal_sink lock poisoned"
            );
            return false;
        };
        let sink = sink_guard.clone();
        drop(sink_guard);
        if let Some(sink) = sink {
            match line() {
                Ok(line) => {
                    if let Err(e) = sink(key, line) {
                        crate::diag::diag_eprintln!("an entry of {key} could not be written: {e}");
                        return false;
                    }
                }
                Err(e) => {
                    crate::diag::diag_eprintln!("an entry of {key} is not kept: {e}");
                    return false;
                }
            }
        }
        true
    }

    pub(crate) fn record_completion(&self, c: crate::v2_completions::Completion) -> bool {
        if c.status_code != 0 {
            let sink = self
                .official_rejection_sink
                .lock()
                .ok()
                .and_then(|s| s.clone());
            if let Some(sink) = sink {
                sink(&c);
            }
        }
        if !self.journal("completions.journal", || {
            crate::snapshot::completion_line(&c)
        }) {
            return false;
        }
        match self.completions.lock() {
            Ok(mut v) => {
                v.push(c);
                true
            }
            Err(_) => false,
        }
    }

    pub(crate) fn completions_len(&self) -> usize {
        self.completions.lock().map_or(0, |v| v.len())
    }

    pub(crate) fn completions(&self) -> Vec<crate::v2_completions::Completion> {
        self.completions
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Takes the parties an official participant's database holds as this service's parties (U-47): its uid as the participant id, every
    /// party of its topology (`(party, hosted by this participant)`), and the metadata records of the parties allocated with metadata
    /// `(party, resource version, annotations, identity provider)`.
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )]
    pub(crate) fn adopt_official_parties(
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
        if let Ok(mut p) = self.participant.write() {
            *p = participant_uid.to_string();
        }
        if let Ok(mut all) = self.parties.lock() {
            *all = parties.iter().map(|(p, _)| p.clone()).collect();
        }
        if let Ok(mut remote) = self.remote_parties.lock() {
            *remote = parties
                .iter()
                .filter(|(_, local)| !local)
                .map(|(p, _)| p.clone())
                .collect();
        }
        if let Ok(mut meta) = self.party_meta.lock() {
            meta.clear();
            for (party, version, annotations, _) in records {
                meta.insert(party.clone(), (*version, annotations.clone()));
            }
        }
        if let Ok(mut idp) = self.party_idp.lock() {
            idp.clear();
            for (party, _, _, provider) in records {
                if !provider.is_empty() {
                    idp.insert(party.clone(), provider.clone());
                }
            }
        }
        self.official_parties
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Replaces the initial participant identifier (when adopting a non-official protocol node's UID).
    pub(crate) fn set_participant_id(&self, uid: &str) {
        let old = if let Ok(mut p) = self.participant.write() {
            let prev = std::mem::replace(&mut *p, uid.to_string());
            Some(prev)
        } else {
            None
        };
        if let Ok(mut all) = self.parties.lock() {
            let already = all.iter().any(|p| p == uid);
            if !already {
                if let Some(prev) = old.as_deref() {
                    if let Some(slot) = all.iter_mut().find(|p| p.as_str() == prev) {
                        *slot = uid.to_string();
                        return;
                    }
                }
                all.push(uid.to_string());
            }
        }
    }

    /// The participant's id (`name::fingerprint`).
    pub(crate) fn participant_id(&self) -> String {
        self.participant
            .read()
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    /// Keeps a committed update for the by-id and by-offset reads (S-API-004); returns `false` if journaling or locking fails.
    pub(crate) fn record_update(&self, update: crate::v2_commands::StoredUpdate) -> bool {
        if !self.journal("updates.journal", || crate::snapshot::update_line(&update)) {
            return false;
        }
        self.apply_recorded_update_effects(update, None)
    }

    /// Atomically journals `updates.journal` then `completions.journal` before exposing either update,
    /// completion, or `created_offsets` in memory (`R-13a`).
    pub(crate) fn record_update_and_completion(
        &self,
        update: crate::v2_commands::StoredUpdate,
        completion: crate::v2_completions::Completion,
    ) -> bool {
        if !self.journal("updates.journal", || crate::snapshot::update_line(&update)) {
            return false;
        }
        if !self.journal("completions.journal", || {
            crate::snapshot::completion_line(&completion)
        }) {
            return false;
        }
        self.apply_recorded_update_effects(update, Some(completion))
    }

    fn apply_recorded_update_effects(
        &self,
        update: crate::v2_commands::StoredUpdate,
        explicit_completion: Option<crate::v2_completions::Completion>,
    ) -> bool {
        let Ok(mut updates) = self.updates.lock() else {
            return false;
        };
        let mut maybe_completions = if explicit_completion.is_some() {
            let Ok(guard) = self.completions.lock() else {
                return false;
            };
            Some(guard)
        } else {
            None
        };
        if let Ok(mut created) = self.created_offsets.lock() {
            for e in update.events.iter().filter(|e| e.created) {
                created.insert(e.contract.contract_id.clone(), (update.offset, e.node));
            }
        }
        let sink = self
            .official_update_sink
            .lock()
            .ok()
            .and_then(|s| s.clone());
        if let Some(sink) = sink {
            if let Some(comp) = explicit_completion.as_ref() {
                sink(&update, Some(comp));
            } else {
                let completion = self
                    .completions
                    .lock()
                    .ok()
                    .and_then(|c| c.iter().rev().find(|c| c.offset == update.offset).cloned());
                sink(&update, completion.as_ref());
            }
        }
        if update.topology.is_none() && self.exex.has_subscribers() {
            let sync_id = self.synchronizer_id();
            self.exex.publish_stored_update(&sync_id, &update);
        }
        if let (Some(comp), Some(mut completions)) = (explicit_completion, maybe_completions.take())
        {
            completions.push(comp);
        }
        updates.push(update);
        true
    }

    /// Puts the updates of an official participant's history before the updates of this service (they are read again at every start, so they
    /// are not journaled).
    #[cfg_attr(
        not(feature = "protocol"),
        allow(dead_code, reason = "used by the protocol-mode participant")
    )]
    pub(crate) fn adopt_updates(&self, mut adopted: Vec<crate::v2_commands::StoredUpdate>) {
        if let Ok(mut u) = self.updates.lock() {
            adopted.append(&mut u);
            *u = adopted;
        }
    }

    /// Puts the completions of an official participant's history before the completions of this service (read again at every start: not
    /// journaled) and the synchronizer times its checkpoints show.
    #[cfg_attr(
        not(feature = "protocol"),
        allow(dead_code, reason = "used by the protocol-mode participant")
    )]
    pub(crate) fn adopt_completions(
        &self,
        mut adopted: Vec<crate::v2_completions::Completion>,
        checkpoint: Vec<(String, String)>,
    ) {
        if let Ok(mut v) = self.completions.lock() {
            adopted.append(&mut v);
            *v = adopted;
        }
        if let Ok(mut c) = self.official_checkpoint.lock() {
            *c = checkpoint;
        }
    }

    /// The synchronizer times of the official database's checkpoints (`None` when the service does not run on one).
    pub(crate) fn official_checkpoint(&self) -> Option<Vec<(String, String)>> {
        self.official_checkpoint
            .lock()
            .ok()
            .filter(|c| !c.is_empty())
            .map(|c| c.clone())
    }

    /// The committed updates, oldest first.
    pub(crate) fn updates(&self) -> Vec<crate::v2_commands::StoredUpdate> {
        self.updates.lock().map(|u| u.clone()).unwrap_or_default()
    }

    pub(crate) fn synchronizer_id(&self) -> String {
        self.synchronizer
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| crate::v2_commands::SYNCHRONIZER.to_string())
    }

    /// The synchronizer this service's updates and completions are on (a participant that joined one says which).
    #[cfg_attr(
        not(feature = "protocol"),
        allow(dead_code, reason = "used by the protocol-mode participant")
    )]
    pub(crate) fn set_synchronizer(&self, s: &str) {
        if let Ok(mut guard) = self.synchronizer.lock() {
            *guard = s.to_string();
        }
    }

    pub fn set_synchronizer_id_for_test(&self, s: &str) {
        if let Ok(mut guard) = self.synchronizer.lock() {
            *guard = s.to_string();
        }
    }
}

fn error_body(code: &str, cause: &str, grpc: u64, context: Value) -> Value {
    json!({
        "code": code,
        "cause": cause,
        "correlationId": null,
        "traceId": "0000000000000000",
        "context": context,
        "resources": [],
        "errorCategory": 8,
        "grpcCodeValue": grpc,
        "retryInfo": null,
        "definiteAnswer": null
    })
}

pub(crate) fn party_json(state: &V2State, party: &str, own: bool) -> Value {
    // the participant's own party has an empty resource version until it is updated (measured)
    let official = state
        .official_parties
        .load(std::sync::atomic::Ordering::SeqCst);
    let (version, annotations) = state
        .party_meta
        .lock()
        .ok()
        .and_then(|m| m.get(party).cloned())
        .map(|(v, a)| (v.to_string(), a))
        .unwrap_or_else(|| {
            (
                // on an official database a party without a record is listed with an empty version, the way the official API lists it
                if own || official {
                    String::new()
                } else {
                    "0".into()
                },
                Default::default(),
            )
        });
    let is_local = !state
        .remote_parties
        .lock()
        .map(|r| r.contains(party))
        .unwrap_or(false);
    let idp = state
        .party_idp
        .lock()
        .ok()
        .and_then(|m| m.get(party).cloned())
        .unwrap_or_default();
    json!({
        "party": party,
        "isLocal": is_local,
        "localMetadata": { "resourceVersion": version, "annotations": annotations },
        "identityProviderId": idp
    })
}

/// The characters Daml-LF allows in a party identifier (letters, digits, `:`, `-`, `_` and space).
fn invalid_party_char(hint: &str) -> Option<char> {
    hint.chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | ' ')))
}

pub(crate) fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Canton's page token for the parties listing: the base64 of a protobuf message holding the last party (field 1).
pub(crate) fn page_token(last: &str) -> String {
    // field 1, then the length as a protobuf varint
    let mut raw = vec![0x0a];
    let mut n = last.len();
    while n >= 0x80 {
        raw.push((n & 0x7f) as u8 | 0x80);
        n >>= 7;
    }
    raw.push(n as u8);
    raw.extend_from_slice(last.as_bytes());
    base64(&raw)
}

pub(crate) fn decode_page_token(token: &str) -> Option<String> {
    let raw = unbase64(token)?;
    if raw.first() != Some(&0x0a) {
        return None;
    }
    let (mut len, mut shift, mut i) = (0usize, 0, 1);
    loop {
        let b = *raw.get(i)?;
        len |= usize::from(b & 0x7f) << shift;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (raw.len() == i + len).then(|| String::from_utf8_lossy(&raw[i..]).into_owned())
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub(crate) fn unbase64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.trim_end_matches('=').bytes() {
        let v = B64.iter().position(|b| *b == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Reads an `EventFormat` that has `filtersForAnyParty` as one with a `filtersByParty` entry for every party the participant knows.
///
/// [CANTON-NOTE: SEMANTICS] The any-party filter asks for what every party sees (it needs the right to read as any party, which the auth check treats as
/// the call naming no party). Measured on the hub's participant: the events of `filtersForAnyParty` with a wildcard are those of the wildcard of every
/// party, each with the witnesses that sees it. `None` when the body has no such filter.
pub(crate) fn expand_any_party(state: &V2State, req: &HttpRequest) -> Option<HttpRequest> {
    if !req
        .body
        .windows(b"filtersForAnyParty".len())
        .any(|w| w == b"filtersForAnyParty")
    {
        return None;
    }
    let mut body: Value = serde_json::from_slice(&req.body).ok()?;
    let parties: Vec<String> = state.parties.lock().ok()?.iter().cloned().collect();
    fn walk(v: &mut Value, parties: &[String]) -> bool {
        let mut changed = false;
        match v {
            Value::Object(map) => {
                if let Some(any) = map.remove("filtersForAnyParty") {
                    let by = map
                        .entry("filtersByParty")
                        .or_insert_with(|| Value::Object(Default::default()));
                    if let Some(by) = by.as_object_mut() {
                        for p in parties {
                            by.entry(p.clone()).or_insert_with(|| any.clone());
                        }
                    }
                    changed = true;
                }
                for x in map.values_mut() {
                    changed |= walk(x, parties);
                }
            }
            Value::Array(items) => {
                for x in items {
                    changed |= walk(x, parties);
                }
            }
            _ => {}
        }
        changed
    }
    if !walk(&mut body, &parties) {
        return None;
    }
    let mut expanded = req.clone();
    expanded.body = serde_json::to_vec(&body).ok()?;
    Some(expanded)
}

/// The administration state a protocol-mode participant keeps across a restart: what `POST /v2/parties`, `PATCH /v2/parties/{id}`, the user and the
/// identity-provider endpoints changed.
#[derive(serde::Serialize, serde::Deserialize)]
struct AdminRepr {
    parties: Vec<String>,
    remote_parties: std::collections::BTreeSet<String>,
    party_meta: PartyMeta,
    party_idp: std::collections::HashMap<String, String>,
    users: std::collections::BTreeMap<String, crate::v2_users::UserRec>,
    idps: crate::v2_idps::Idps,
}

impl V2State {
    /// Tells the journal the administration state as it stands (one line, the latest wins), when the participant keeps a journal.
    ///
    /// [CANTON-NOTE: SEMANTICS] The Rust participant keeps what its Ledger API administration wrote (parties with their annotations, users with their
    /// rights, identity providers) in its own state, as the official one does in its `lapi_*` tables; a restart finds them again (U-47).
    pub(crate) fn persist_admin(&self) {
        let sink = self.official_admin_sink.lock().ok().and_then(|s| s.clone());
        if let Some(sink) = sink {
            sink(&self.official_admin_rows());
        }
        self.journal("admin.journal", || {
            let repr = AdminRepr {
                parties: self.parties.lock().map_err(|e| e.to_string())?.clone(),
                remote_parties: self
                    .remote_parties
                    .lock()
                    .map_err(|e| e.to_string())?
                    .clone(),
                party_meta: self.party_meta.lock().map_err(|e| e.to_string())?.clone(),
                party_idp: self.party_idp.lock().map_err(|e| e.to_string())?.clone(),
                users: self.users.lock().map_err(|e| e.to_string())?.clone(),
                idps: self.idps.lock().map_err(|e| e.to_string())?.clone(),
            };
            serde_json::to_string(&repr).map_err(|e| e.to_string())
        });
    }

    /// The administration state as the official tables hold it.
    pub(crate) fn official_admin_rows(&self) -> OfficialAdminRows {
        let participant = self.participant_id();
        let meta = self
            .party_meta
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        let idp = self.party_idp.lock().map(|m| m.clone()).unwrap_or_default();
        let api = self
            .api_parties
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default();
        let mut parties = Vec::new();
        for party in self.parties.lock().map(|p| p.clone()).unwrap_or_default() {
            if party == participant || !(api.contains(&party) || meta.contains_key(&party)) {
                continue;
            }
            let (version, annotations) = meta.get(&party).cloned().unwrap_or_default();
            let provider = idp.get(&party).cloned().unwrap_or_default();
            parties.push((party, version, provider, annotations));
        }
        OfficialAdminRows {
            users: crate::v2_users::official_rows(
                &self.users.lock().map(|u| u.clone()).unwrap_or_default(),
            ),
            parties,
            idps: crate::v2_idps::official_rows(
                &self.idps.lock().map(|i| i.clone()).unwrap_or_default(),
            ),
        }
    }

    /// Puts the administration state back from the last line [`V2State::persist_admin`] wrote.
    #[cfg_attr(
        not(feature = "protocol"),
        allow(dead_code, reason = "used by the protocol-mode participant")
    )]
    pub(crate) fn restore_admin(&self, line: &str) -> Result<(), String> {
        let repr: AdminRepr = serde_json::from_str(line).map_err(|e| e.to_string())?;
        *self.parties.lock().map_err(|e| e.to_string())? = repr.parties;
        *self.remote_parties.lock().map_err(|e| e.to_string())? = repr.remote_parties;
        *self.party_meta.lock().map_err(|e| e.to_string())? = repr.party_meta;
        *self.party_idp.lock().map_err(|e| e.to_string())? = repr.party_idp;
        *self.users.lock().map_err(|e| e.to_string())? = repr.users;
        *self.idps.lock().map_err(|e| e.to_string())? = repr.idps;
        Ok(())
    }
}

/// Routes the v2 requests; a change of the administration state is handed to the journal after it was answered.
pub fn route(service: &ExecutionService, req: &HttpRequest) -> Option<HttpResponse> {
    let response = route_inner(service, req)?;
    let path = req.path.trim_end_matches('/');
    if req.method != "GET"
        && response.status < 300
        && ["/v2/parties", "/v2/users", "/v2/idps"]
            .iter()
            .any(|p| path.starts_with(p))
    {
        service.v2_state().persist_admin();
    }
    Some(response)
}

/// Routes the v2 requests. `None` means this module does not own the path (the older routes handle it).
fn route_inner(service: &ExecutionService, req: &HttpRequest) -> Option<HttpResponse> {
    let path = req.path.trim_end_matches('/');
    let state = service.v2_state();
    let method = req.method.as_str();
    if method == "POST" {
        if let Some(expanded) = expand_any_party(state, req) {
            return route_inner(service, &expanded);
        }
    }
    // Canton answers the health endpoints with plain text (`/livez` has an empty body)
    if method == "GET" && path == "/livez" {
        return Some(text(200, ""));
    }
    if method == "GET" && path == "/readyz" {
        return Some(match service.check_ready() {
            Ok(()) => text(200, "[+] ledger ok (SERVING)\nreadyz check passed\n"),
            Err(why) => text(503, &format!("[-] ledger not ready: {why}\n")),
        });
    }
    if method == "GET" && path == "/metrics" {
        let mut resp = text(200, &service.observability.render_prometheus(service));
        resp.headers.insert(
            "Content-Type".into(),
            "text/plain; version=0.0.4; charset=utf-8".into(),
        );
        return Some(resp);
    }
    if method == "GET" && path == "/_telemetry" {
        return Some(HttpResponse::json(
            200,
            &service.observability.telemetry_json(service),
        ));
    }
    if method == "POST" && (path == "/_quiesce/pause" || path == "/_quiesce") {
        service.set_quiesced(true);
        return Some(HttpResponse::json(
            200,
            &json!({ "quiesced": true, "in_flight": service.total_in_flight() }),
        ));
    }
    if method == "POST" && (path == "/_quiesce/resume" || path == "/_resume") {
        service.set_quiesced(false);
        return Some(HttpResponse::json(
            200,
            &json!({ "quiesced": false, "in_flight": service.total_in_flight() }),
        ));
    }
    if method == "GET" && path == "/_quiesce" {
        return Some(HttpResponse::json(
            200,
            &json!({
                "quiesced": service.is_quiesced(),
                "in_flight": service.total_in_flight(),
            }),
        ));
    }
    if method == "GET" && path == "/_xray" {
        let root_hash = req.query_params.get("root_hash").map(String::as_str);
        let since_ms = req
            .query_params
            .get("since_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let records = service.observability.snapshot_xray(root_hash, since_ms);
        return Some(HttpResponse::json(200, &json!({ "traces": records })));
    }
    if method == "POST" && path == "/_xray" {
        let active = req
            .query_params
            .get("active")
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or_else(|| {
                serde_json::from_slice::<Value>(&req.body)
                    .ok()
                    .and_then(|v| v.get("active").and_then(Value::as_bool))
                    .unwrap_or(true)
            });
        service.observability.set_wiretap_active(active);
        return Some(HttpResponse::json(200, &json!({ "active": active })));
    }
    if method == "GET" && path == "/_exex" {
        return Some(HttpResponse::json(200, &service.exex().telemetry_json()));
    }
    if method == "GET" && path == "/docs/openapi" {
        return crate::v2_misc::docs("openapi");
    }
    if method == "GET" && path == "/docs/asyncapi" {
        return crate::v2_misc::docs("asyncapi");
    }
    if !path.starts_with("/v2/") {
        return None;
    }
    // paths of the older (invented) v2-style routes stay with the old router
    if path == "/v2/command/submit-and-wait" {
        return None;
    }
    let ok = |v: Value| Some(HttpResponse::json(200, &v));
    match (method, path) {
        ("GET", "/v2/version") => ok(json!({
            "version": "3.7.2",
            "features": {
                "experimental": {
                    "staticTime": { "supported": false },
                    "commandInspectionService": { "supported": false }
                },
                "userManagement": { "supported": true, "maxRightsPerUser": 1000, "maxUsersPageSize": 1000 },
                "partyManagement": { "maxPartiesPageSize": 10000 },
                "offsetCheckpoint": {
                    "maxOffsetCheckpointEmissionDelay": { "seconds": 75, "nanos": 0, "unknownFields": { "fields": {} } }
                },
                "packageFeature": { "maxVettedPackagesPageSize": 100 }
            }
        })),
        ("GET", "/v2/state/ledger-end") => ok(json!({
            "offset": state.ledger_end.load(Ordering::SeqCst),
            "synchronizerTimes": []
        })),
        ("GET", "/v2/state/connected-synchronizers") => {
            // [CANTON-NOTE: SEMANTICS] with several synchronizers behind the service, each with its alias (the JVM names the hosting
            // permission of the asked party; S-NET-040 recording)
            let has_committer = service
                .committer
                .read()
                .ok()
                .is_some_and(|c| c.as_ref().is_some_and(|c| !c.synchronizers().is_empty()));
            let permission = if has_committer {
                "PARTICIPANT_PERMISSION_SUBMISSION"
            } else {
                "PARTICIPANT_PERMISSION_UNSPECIFIED"
            };
            ok(json!({
                "connectedSynchronizers": service.connected_synchronizers().into_iter().map(|(alias, id)| json!({
                    "synchronizerAlias": alias,
                    "synchronizerId": id,
                    "permission": permission
                })).collect::<Vec<_>>()
            }))
        }
        ("GET", "/v2/state/latest-pruned-offsets") => {
            let pruned = state.pruned_up_to.load(Ordering::SeqCst);
            ok(json!({
                "participantPrunedUpToInclusive": pruned,
                "allDivulgedContractsPrunedUpToInclusive": pruned
            }))
        }
        ("POST", "/v2/admin/prune") => Some(crate::v2_prune::prune(service, req)),
        (m, p) if p.starts_with("/v2/idps") => {
            crate::v2_idps::route(service, req, m, p).or_else(|| Some(not_found(req)))
        }
        ("GET", "/v2/packages") => ok(json!({ "packageIds": service.package_ids() })),
        ("GET", "/v2/parties/participant-id") => {
            ok(json!({ "participantId": state.participant_id() }))
        }
        ("GET", "/v2/parties") => {
            let parties = state.parties.lock().ok()?;
            // alphabetical like Canton; the participant's own party is listed with an empty resourceVersion
            let mut all: Vec<&String> = parties.iter().collect();
            all.sort();
            let after = req
                .query_params
                .get("pageToken")
                .and_then(|t| decode_page_token(t));
            let size = req
                .query_params
                .get("pageSize")
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(10000);
            let rest: Vec<&String> = all
                .into_iter()
                .filter(|p| after.as_ref().is_none_or(|a| p.as_str() > a.as_str()))
                .collect();
            let page: Vec<&String> = rest.iter().copied().take(size).collect();
            let next = match page.last() {
                Some(last) if rest.len() > size => page_token(last),
                _ => String::new(),
            };
            ok(json!({
                "partyDetails": page.iter().map(|p| party_json(state, p, **p == state.participant_id())).collect::<Vec<_>>(),
                "nextPageToken": next
            }))
        }
        ("POST", "/v2/parties") => {
            let body: Value = match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(_) => return Some(HttpResponse::json(400, &json!("Invalid value for: body"))),
            };
            let hint = body["partyIdHint"].as_str().unwrap_or("");
            if let Some(c) = invalid_party_char(hint) {
                return Some(HttpResponse::json(
                    400,
                    &error_body(
                        "INVALID_ARGUMENT",
                        &format!(
                            "The submitted request has invalid arguments: non expected character 0x{:x} in Daml-LF Party \"{hint}\"",
                            c as u32
                        ),
                        3,
                        json!({
                            "participant": format!("'{}'", state.participant_id().split("::").next().unwrap_or("").to_string()),
                            "parties": format!("['{hint}']"),
                            "category": "8",
                            "tid": "0000000000000000",
                            "definite_answer": "false"
                        }),
                    ),
                ));
            }
            let id = match service.protocol_party(hint) {
                Some(Ok(id)) => id,
                Some(Err(e)) => {
                    return Some(HttpResponse::json(
                        500,
                        &error_body("INTERNAL", &e.to_string(), 13, json!({})),
                    ))
                }
                None => format!("{hint}::{}", namespace()),
            };
            let inserted_party = if let Ok(mut parties) = state.parties.lock() {
                if !parties.contains(&id) {
                    parties.push(id.clone());
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if inserted_party {
                crate::v2_topology_events::record_party_authorization(
                    service,
                    None,
                    vec![crate::v2_topology_events::StoredTopologyEvent {
                        party_id: id.clone(),
                        participant_id: state.participant_id(),
                        kind: crate::v2_topology_events::TopologyAuthorizationKind::Added(1),
                    }],
                    3,
                );
            }
            if let Ok(mut api) = state.api_parties.lock() {
                api.insert(id.clone());
            }
            // [CANTON-NOTE: SEMANTICS] The party record the official participant creates with the party carries the annotations of the request
            // (`localMetadata.annotations`) at resource version 0.
            let annotations: std::collections::BTreeMap<String, String> = body
                .pointer("/localMetadata/annotations")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect();
            if let Ok(mut meta) = state.party_meta.lock() {
                meta.entry(id.clone()).or_insert((0, annotations));
            }
            ok(json!({ "partyDetails": party_json(state, &id, false) }))
        }
        ("POST", "/v2/parties/external/generate-topology") => {
            Some(crate::v2_interactive::generate_topology(service, req))
        }
        ("POST", "/v2/parties/external/allocate") => {
            Some(crate::v2_interactive::allocate_external_party(service, req))
        }
        ("GET", p) if p.starts_with("/v2/parties/") && !p.starts_with("/v2/parties/external/") => {
            let party = percent_decode(&p["/v2/parties/".len()..]);
            let parties = state.parties.lock().ok()?;
            let found: Vec<Value> = parties
                .iter()
                .filter(|x| **x == party)
                .map(|x| party_json(state, x, *x == state.participant_id()))
                .collect();
            ok(json!({ "partyDetails": found }))
        }
        ("POST", "/v2/state/active-contracts") => {
            Some(crate::v2_commands::active_contracts(service, req))
        }
        ("POST", "/v2/dars") | ("POST", "/v2/packages") => {
            Some(crate::v2_packages::upload(service, req, false))
        }
        ("POST", "/v2/dars/validate") => Some(crate::v2_packages::upload(service, req, true)),
        ("POST", p)
            if p.starts_with("/v2/interactive-submission/")
                && !p.ends_with("/preferred-packages")
                && !p.ends_with("/preferred-package-version") =>
        {
            crate::v2_misc::interactive(service, req, &p["/v2/interactive-submission/".len()..])
                .or_else(|| Some(not_found(req)))
        }
        ("GET", "/v2/interactive-submission/preferred-package-version")
        | ("POST", "/v2/interactive-submission/preferred-package-version") => {
            Some(crate::v2_packages::preferred_package_version(service, req))
        }
        ("GET", p) if p.starts_with("/v2/jose/jwks/synchronizer/") => {
            crate::v2_misc::jwks(service, p).or_else(|| Some(not_found(req)))
        }
        ("GET", "/v2/package-vetting") | ("POST", "/v2/package-vetting") => {
            Some(crate::v2_packages::vetting_root(service, req))
        }
        ("POST", "/v2/package-vetting/update") => {
            Some(crate::v2_packages::vetting_update(service, req))
        }
        ("POST", "/v2/interactive-submission/preferred-packages") => {
            Some(crate::v2_packages::preferred_packages(service, req))
        }
        ("POST", "/v2/package-vetting/list") => {
            Some(crate::v2_packages::vetting_list(service, req))
        }
        ("GET", p) if p.starts_with("/v2/packages/") => {
            let rest = &p["/v2/packages/".len()..];
            Some(match rest.strip_suffix("/status") {
                Some(id) => crate::v2_packages::package_status(service, &percent_decode(id)),
                None => crate::v2_packages::get_package(service, &percent_decode(rest)),
            })
        }
        ("POST", "/v2/commands/submit-and-wait") => {
            Some(crate::v2_commands::submit(service, req, false))
        }
        ("POST", "/v2/commands/submit-and-wait-for-transaction") => {
            Some(crate::v2_commands::submit(service, req, true))
        }
        ("POST", "/v2/commands/submit-and-wait-for-transaction-tree") => {
            Some(crate::v2_commands::submit_tree(service, req))
        }
        ("POST", "/v2/commands/submit-and-wait-for-reassignment") => {
            Some(crate::v2_reassign::submit(service, req))
        }
        ("POST", "/v2/commands/async/submit-reassignment") => {
            Some(crate::v2_reassign::submit_async(service, req))
        }
        (m, p) if p.starts_with("/v2/users") || p == "/v2/authenticated-user" => {
            crate::v2_users::route(service, req, m, p).or_else(|| Some(not_found(req)))
        }
        ("PATCH", p) if p.starts_with("/v2/parties/") => Some(crate::v2_parties::update(
            service,
            req,
            &percent_decode(&p["/v2/parties/".len()..]),
        )),
        ("POST", "/v2/commands/async/submit") => {
            Some(crate::v2_commands::submit_async(service, req))
        }
        ("POST", "/v2/commands/completions") => {
            Some(crate::v2_completions::completions(service, req, true))
        }
        ("POST", "/v2/commands/command-completions") => {
            Some(crate::v2_completions::completions(service, req, false))
        }
        ("POST", "/v2/commands/completion-by-hash") => {
            Some(crate::v2_completions::completion_by_hash(service, req))
        }
        ("POST", "/v2/updates") => Some(crate::v2_updates::updates(service, req)),
        ("POST", "/v2/updates/flats") => Some(crate::v2_updates::updates_with_default_shape(
            service, req, false,
        )),
        ("POST", "/v2/updates/trees") => Some(crate::v2_updates::updates_with_default_shape(
            service, req, true,
        )),
        ("POST", "/v2/updates/get-updates-page") => {
            Some(crate::v2_updates::updates_page(service, req))
        }
        ("POST", "/v2/updates/update-by-hash") => {
            Some(crate::v2_updates::update_by_hash(service, req))
        }
        ("POST", "/v2/updates/transaction-by-id") => {
            Some(crate::v2_queries::transaction_by_id(service, req))
        }
        ("POST", "/v2/updates/transaction-by-offset") => {
            Some(crate::v2_queries::transaction_by_offset(service, req))
        }
        ("GET", p) if p.starts_with("/v2/updates/transaction-tree-by-id/") => {
            Some(crate::v2_queries::transaction_tree_by_id_get(
                service,
                req,
                &percent_decode(&p["/v2/updates/transaction-tree-by-id/".len()..]),
            ))
        }
        ("GET", p) if p.starts_with("/v2/updates/transaction-tree-by-offset/") => {
            Some(crate::v2_queries::transaction_tree_by_offset_get(
                service,
                req,
                &percent_decode(&p["/v2/updates/transaction-tree-by-offset/".len()..]),
            ))
        }
        ("GET", p)
            if service.traffic_enforcement_enabled() && p.starts_with("/v2/traffic/accounts/") =>
        {
            Some(crate::v2_traffic::get_account(
                service,
                &percent_decode(&p["/v2/traffic/accounts/".len()..]),
            ))
        }
        ("POST", "/v2/traffic/accounts") if service.traffic_enforcement_enabled() => {
            Some(crate::v2_traffic::update_account(service, req))
        }
        ("POST", "/v2/traffic/prune") if service.traffic_enforcement_enabled() => {
            Some(crate::v2_traffic::prune(service, req, true))
        }
        ("POST", "/v2/traffic/events/prune") if service.traffic_enforcement_enabled() => {
            Some(crate::v2_traffic::prune(service, req, false))
        }
        ("POST", "/v2/state/active-contracts-page") => {
            Some(crate::v2_updates::active_contracts_page(service, req))
        }
        ("GET", "/v2/state/active-contracts-page") => Some(crate::v2_commands::bad_body(
            "Invalid value for: body (exhausted input)".to_string(),
        )),
        ("GET", "/v2/state/convert-record-time-to-offset") => {
            Some(crate::v2_updates::convert_record_time(service, req))
        }
        ("POST", "/v2/updates/update-by-id") => Some(crate::v2_queries::update_by_id(service, req)),
        ("POST", "/v2/updates/update-by-offset") => {
            Some(crate::v2_queries::update_by_offset(service, req))
        }
        ("POST", "/v2/contracts/contract-by-id") => {
            Some(crate::v2_queries::contract_by_id(service, req))
        }
        ("POST", "/v2/events/events-by-contract-id") => {
            Some(crate::v2_queries::events_by_contract_id(service, req))
        }
        _ => Some(not_found(req)),
    }
}

fn text(status: u16, body: &str) -> HttpResponse {
    let mut resp = HttpResponse::json(status, &Value::Null);
    resp.body = body.as_bytes().to_vec();
    resp.headers
        .insert("Content-Type".into(), "text/plain; charset=UTF-8".into());
    resp.headers
        .insert("Content-Length".into(), resp.body.len().to_string());
    resp
}

/// Canton's body for a path or method the JSON API does not serve.
fn not_found(req: &HttpRequest) -> HttpResponse {
    HttpResponse::json(
        404,
        &json!({
            "errors": [format!("HttpMethod({}), uri: http://localhost{}", req.method, req.path)],
            "status": 404,
            "ledgerApiError": null
        }),
    )
}
