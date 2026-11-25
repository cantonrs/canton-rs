//! Shared service domain types, protocol committer trait, and error mappings.

use std::collections::HashSet;
use std::sync::Arc;

use lf_eval::codec::CodecError;
use lf_eval::engine::{ExecError, NewContract};
use lf_eval::ledger::SingleContractLedger;
use lf_eval::tx_model::TransactionTree as LfTransactionTree;
use thiserror::Error;

use crate::models::ledger_api::{TemplateId, TransactionTree};

/// [CANTON-NOTE: SEMANTICS] Encapsulates a dynamically loaded Daml package from a DAR archive.
///
/// Holds the evaluable bytecode environment (`World`) alongside the parsed
/// module and template surface definitions. Module surfaces provide type schemas
/// (`SurfaceType`) for encoding/decoding arguments, while `World` evaluates
/// signatories, observers, preconditions (`ensure`), and choice body expressions.
pub struct LfPackage {
    pub main_package_id: String,
    pub world: lf_eval::World,
    pub surfaces: Vec<lf_archive::ModuleSurface>,
}

/// [CANTON-NOTE: WHY] Represents an on-ledger contract managed by the generic `lf_eval::Engine`.
///
/// Unlike the legacy hardcoded `Holding` structure which expects a fixed 5-field schema,
/// `GenericContract` stores arbitrary Daml template payloads as both typed `lf_eval::Value`
/// expressions (for bytecode evaluation) and serialized JSON representations (for HTTP API responses).
#[derive(Clone, Debug)]
pub struct GenericContract {
    pub contract_id: String,
    pub package_id: String,
    pub template_id: TemplateId,
    pub payload_value: lf_eval::Value,
    pub json_payload: serde_json::Value,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    pub witness_parties: Vec<String>,
    pub active: bool,
    /// The contract key value (templates that declare a key), reported as `contractKey` in created events.
    pub key_value: Option<lf_eval::Value>,
    /// When the creating transaction was committed (microseconds since the epoch): the `createdAt` of its created events.
    ///
    /// [CANTON-NOTE: SEMANTICS] It is a property of the contract, fixed at creation. It used to be read from the clock each
    /// time an event was rendered, so the same contract reported a different `createdAt` on every query.
    pub created_at_micros: i64,
    /// Base64-encoded Canton 3.7.2 `Versioned(FatContractInstance)` created-event blob (empty for legacy `#N:M` ids).
    pub created_event_blob: String,
    /// Base64-encoded Canton 3.7.2 `SValueHash` contract key hash (empty for unkeyed contracts).
    pub contract_key_hash: String,
    /// Maintainers of the contract key, if keyed.
    pub key_maintainers: Vec<String>,
    /// Monotonic creation sequence used to preserve Canton 3.7.2 LIFO global NUCK order (Tier 3).
    pub creation_seq: u64,
}

/// A contract another participant created, as the service shows it.
#[derive(Clone, Debug)]
pub struct RemoteCreated {
    pub contract_id: String,
    pub package_id: String,
    /// `Module:Name`.
    pub template: String,
    pub payload: lf_eval::Value,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    pub created_at_micros: i64,
    /// Protocol authentication salt extracted from `FatContractInstance` when known.
    pub salt: Option<[u8; 32]>,
    /// The versioned `FatContractInstance` bytes as a participant stored them, when read from an official database: they are the created-event blob
    /// as they are (measured on the hub's participant, 66 of 66 blobs equal the stored instance).
    pub blob: Option<Vec<u8>>,
}

/// Boxed payload for [`RemoteTxEvent::Exercise`] so the enum stays compact (`large_enum_variant`).
#[derive(Clone, Debug)]
pub struct RemoteTxExercise {
    pub depth: usize,
    pub contract_id: String,
    pub contract: Option<RemoteCreated>,
    pub choice: String,
    pub consuming: bool,
    pub actors: Vec<String>,
    pub observers: Vec<String>,
    pub interface_id: Option<String>,
    pub argument: lf_eval::Value,
    pub result: Option<lf_eval::Value>,
}

/// Replayed event carried from a remote participant's view conformance for `LEDGER_EFFECTS` tree publication (`S-DX-005`).
#[derive(Clone, Debug)]
pub enum RemoteTxEvent {
    Create {
        depth: usize,
        contract_id: String,
        contract: Option<Box<RemoteCreated>>,
    },
    Exercise(Box<RemoteTxExercise>),
    Fetch {
        depth: usize,
    },
}

/// A transaction that was approved without this service's submission: what it created and consumed ([`ExecutionService::apply_remote`]).
#[derive(Clone, Debug)]
pub struct RemoteApplied {
    pub request_id: i64,
    pub created: Vec<RemoteCreated>,
    pub consumed: Vec<String>,
    pub root_hash: Option<Vec<u8>>,
    /// Ordered replayed tree events for remote `LEDGER_EFFECTS` projection (`S-DX-005`).
    pub events: Vec<RemoteTxEvent>,
}

/// The synchronizer behind the service (F4 of `doc/performance/EQUAL-CONDITIONS.md`): without one the service commits a transaction at once, in
/// memory; with one, a transaction is first judged by the protocol (views, sequencer, mediator) and applied only when it is approved.
/// What a participant signed to host a party (U-50): the topology transaction as the synchronizer got it.
#[derive(Clone, Debug)]
pub struct HostedParty {
    /// `name::namespace`
    pub party: String,
    /// The transaction's versioned bytes (what the signatures cover).
    pub transaction: Vec<u8>,
    /// Each signature as a `crypto.v30.Signature` message.
    pub signatures: Vec<Vec<u8>>,
    /// The signed transaction as a node stores it (`SignedTopologyTransaction` in its own versioned wrapper).
    pub stored: Vec<u8>,
}

/// A signed topology transaction as an official database's topology store takes it (U-50): its bytes, each signature and the stored form.
#[derive(Clone, Debug)]
pub struct SignedTopologyRecord {
    pub transaction: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
    pub stored: Vec<u8>,
}

pub trait ProtocolCommitter: Send + Sync {
    /// The transaction at `serial` that makes this participant vet `package_ids` (the whole list), signed with its namespace key (U-50). `None`: not offered.
    fn vetting_transaction(
        &self,
        _package_ids: &[String],
        _serial: u32,
    ) -> Option<SignedTopologyRecord> {
        None
    }
    /// The topology transaction that makes this participant host the party `hint`, for the official database's topology store (U-50). `None`: nothing to write.
    fn hosting_transaction(&self, _hint: &str) -> Option<HostedParty> {
        None
    }

    /// The id of a contract the engine is creating, if the protocol chooses it (the protocol derives contract ids from the contract's content,
    /// the creation time and a salt, so the engine must not invent its own). `None` leaves the service's own numbering.
    ///
    /// `session` belongs to one command: it starts empty and the committer may set it on the first call, so that the ids of the contracts of
    /// one transaction can share what they are derived from (the contracts created under one exercise share its seed).
    fn allocate_contract_id(
        &self,
        _new: &NewContract<'_>,
        _session: &mut Option<u64>,
    ) -> Option<String> {
        None
    }

    /// Starts a transaction of `roots` roots whose commands run one by one and are committed together ([`Self::commit_transaction`]).
    /// `None`: this committer commits every command on its own.
    fn begin_transaction(&self, _roots: usize) -> Option<Result<u64, ApiError>> {
        None
    }

    /// Like [`Self::allocate_contract_id`] for a contract of the `root`-th root of a transaction [`Self::begin_transaction`] started.
    fn allocate_in_transaction(
        &self,
        _transaction: u64,
        _root: usize,
        _new: &NewContract<'_>,
    ) -> Option<String> {
        None
    }

    /// Judges the commits of a started transaction, one per root in order, as one transaction: all of them are approved or none.
    fn commit_transaction(
        &self,
        _transaction: u64,
        _commits: &[TransactionCommit],
    ) -> Result<(), ApiError> {
        Err(ApiError::Ledger(
            "this committer does not commit transactions of several roots".into(),
        ))
    }

    /// Forgets a started transaction that will not be committed.
    fn abort_transaction(&self, _transaction: u64) {}

    /// The service recorded what the submissions this thread waited for came to (their completions and transactions): the committer need
    /// not hand them over again after a restart (P-13).
    fn command_recorded(&self) {}

    /// Marks the awaited fates associated with `command_id` recorded on this thread without clearing unrecorded peers.
    fn command_recorded_for(&self, _command_id: &str) {
        self.command_recorded();
    }

    /// The id of a new party the synchronizer hosts for this participant (the party's name is a hint; the protocol puts the participant's
    /// namespace behind it and has to tell the topology). `None` leaves the service's own party ids.
    fn allocate_party(&self, _hint: &str) -> Option<Result<String, ApiError>> {
        None
    }

    /// Judges `commit` before it is applied. `Ok` means the synchronizer approved it; `Err` is what the client is told, and nothing is applied.
    fn commit(&self, commit: &TransactionCommit) -> Result<(), ApiError>;

    /// Loads and vets a dynamically uploaded DAR on the backing protocol node (if any).
    fn vet_dar(&self, _dar_bytes: &[u8]) -> Result<(), ApiError> {
        Ok(())
    }

    /// Loads and vets a pre-parsed dynamically uploaded DAR on the backing protocol node (if any).
    fn vet_loaded_dar(&self, _loaded: &lf_archive::LoadedDar) -> Result<(), ApiError> {
        Ok(())
    }

    /// Synchronizes the exact set of vetted package IDs with the backing protocol node (if any).
    fn sync_vetted_packages(
        &self,
        _synchronizer_id: Option<&str>,
        _vetted_pkg_ids: &[String],
    ) -> Result<(), ApiError> {
        Ok(())
    }

    /// Pending effective-time topology changes queued in the backing protocol runtime.
    fn pending_topology_changes(&self) -> usize {
        0
    }

    /// Returns the raw `Versioned(FatContractInstance)` bytes of a contract known to the backing protocol node, if any.
    fn instance_bytes(&self, _contract_id: &str) -> Option<Vec<u8>> {
        None
    }

    /// Returns the latest timestamp (microseconds since epoch) cleared by pairwise ACS commitment reconciliation, if active.
    fn safe_to_prune_micros(&self) -> Option<i64> {
        None
    }

    /// Repair: authenticates each `(contract id, serialized instance)` and adds them all to the participant's protocol ledger, or none of them
    /// (`None`: no participant behind the service).
    fn repair_add(&self, _contracts: &[(String, Vec<u8>)]) -> Option<Result<Vec<String>, String>> {
        None
    }

    /// Repair: purges the contracts from the participant's protocol ledger (`None`: no participant behind the service).
    fn repair_purge(&self, _ids: &[String], _ignore_inactive: bool) -> Option<Result<(), String>> {
        None
    }

    /// What the traffic cost of a submission by `act_as` at `at_micros` is estimated from (S-SIM-001): `None` while traffic control is off
    /// on the synchronizer transactions go to, or without a protocol node (`τ = ⊥`).
    fn traffic_cost_inputs(
        &self,
        _act_as: &[String],
        _at_micros: i64,
    ) -> Option<crate::cost_estimation::TrafficCostInputs> {
        None
    }

    /// The prepared transaction an interactive submission of `commits` under `command_id` is signed as, read from the request the protocol
    /// will send for it (U-56): its hash is the one its confirmers recompute. `None`: not offered for this shape (or no protocol node).
    fn prepared_transaction(
        &self,
        _commits: &[TransactionCommit],
        _command_id: &str,
        _max_record_time: Option<i64>,
    ) -> Option<
        Result<
            canton_proto::com::daml::ledger::api::v2::interactive::PreparedTransaction,
            ApiError,
        >,
    > {
        None
    }

    /// The confirmation request the protocol would send for `commits` under `command_id`, built and never sent, as `(content size,
    /// recipients)` per envelope (S-SIM-001). `None`: not built for this shape (or no protocol node).
    fn priced_confirmation_request(
        &self,
        _commits: &[TransactionCommit],
        _command_id: &str,
        _external: Option<
            &canton_proto::com::digitalasset::canton::protocol::v32::ExternalAuthorization,
        >,
    ) -> Option<Result<Vec<(usize, usize)>, ApiError>> {
        None
    }

    /// The synchronizers this participant is connected to, as `(alias, logical id)`, the first being the one transactions go to. Empty: the
    /// service's own single synchronizer.
    fn synchronizers(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Verifies live connectivity to backing synchronizer(s) for `GET /readyz`.
    fn check_ready(&self) -> Result<(), String> {
        Ok(())
    }

    /// The protocol participant identifier (`name::namespace`) backing this committer, if known.
    fn participant_id(&self) -> Option<String> {
        None
    }

    /// Runs a reassignment command through the protocol (G7 B1). `None`: this committer cannot reassign.
    fn reassign(&self, _command: &ReassignCommand) -> Option<Result<ReassignOutcome, ApiError>> {
        None
    }

    /// The signing keys of the external `party` and their threshold as the synchronizer's topology has them (`None`: unknown here).
    fn party_signing_keys(
        &self,
        _party: &str,
    ) -> Option<(
        u32,
        Vec<canton_proto::com::digitalasset::canton::crypto::v30::SigningPublicKey>,
    )> {
        None
    }

    /// Number of protocol-layer submissions or view confirmations currently in flight.
    fn protocol_in_flight(&self) -> usize {
        0
    }
}

/// One command of `submit-and-wait-for-reassignment`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassignCommand {
    Unassign {
        contract_id: String,
        source: String,
        target: String,
        submitter: String,
        command_id: String,
    },
    Assign {
        reassignment_id: String,
        source: String,
        target: String,
        submitter: String,
        command_id: String,
    },
}

/// What an approved reassignment did (logical synchronizer ids).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassignOutcome {
    pub reassignment_id: String,
    pub contract_id: String,
    pub source: String,
    pub target: String,
    pub counter: i64,
    /// The request's sequencing time (its record time), microseconds.
    pub record_time_micros: i64,
}

/// What `v2_atomic` records to revert a failed batch (see there).
#[derive(Default)]
pub(crate) struct BatchUndo {
    /// The previous entry of every contract the batch touched (`None`: it did not exist), in order.
    pub(super) contracts: Vec<(String, Option<GenericContract>)>,
    pub(super) ledger: Vec<LedgerUndo>,
}

pub(crate) enum LedgerUndo {
    /// The whole legacy ledger was replaced; this is the old one.
    Replaced(Box<SingleContractLedger>),
    /// Slots were appended: the lengths of `contracts` and `contract_ids` before.
    Padded(usize, usize),
    /// A slot was emptied: its index and old content.
    Slot(usize, Option<lf_eval::ledger::Holding>),
}

/// [CANTON-NOTE: SEMANTICS] Encapsulates staged mutations for an atomic transaction commit.
///
/// Ensures two-phase commit semantics: ActiveLedgerState transaction validation is verified
/// before any active status in `generic_contracts` is altered. If validation fails, in-flight
/// mutations are discarded and the active set remains untouched.
#[derive(Clone, Debug)]
pub struct TransactionCommit {
    pub consumed_cids: Vec<String>,
    pub archived_cids: Vec<String>,
    pub created_contracts: Vec<GenericContract>,
    pub legacy_archived_cids: Vec<String>,
    pub working_ledger: Option<SingleContractLedger>,
    pub lf_tree: LfTransactionTree,
    pub act_as_set: HashSet<String>,
    pub tx_tree_record: Option<TransactionTree>,
    /// The argument of the root exercise as the engine got it (`None` for a transaction whose root is not an exercise of a loaded package).
    pub root_argument: Option<lf_eval::Value>,
    /// The engine's journal of the root exercise, in execution order (empty for a transaction that did not run the engine): what a committer
    /// needs to place every node of the tree (`lf_eval::NodePaths`). The tree in `lf_tree` is flat, with every created contract a direct
    /// child of the root exercise.
    pub engine_events: Vec<lf_eval::EngineEvent>,
    /// The `try` bodies the command rolled back, with `at` relative to `engine_events` (see [`lf_eval::engine::RolledBack`]).
    pub engine_rolled_back: Vec<lf_eval::engine::RolledBack>,
    /// Key queries (`lookupByKey`) and by-key resolutions recorded while evaluating this transaction.
    pub engine_key_lookups: Vec<lf_eval::engine::RecordedKeyLookup>,
    /// Whether the root exercise was invoked by contract key (`ExerciseByKeyCommand`).
    pub root_by_key: bool,
    /// Target execution package id of the root exercise (differs from the stored contract's package id on smart-contract upgrade/downgrade).
    pub root_package_id: Option<String>,
    /// Explicitly disclosed contract blobs `(contract_id_hex, raw_fat_contract_bytes)` supplied with the command.
    pub disclosed_contracts: Vec<(String, Vec<u8>)>,
    /// What the update history needs to render this transaction once it is committed (`None`: not recorded).
    pub history: Option<crate::history::HistoryInput>,
}

/// [CANTON-NOTE: INVARIANT] Internal resolution target for a template reference.
///
/// When a DAR package is loaded, templates declared in that DAR resolve to `Generic`
/// (and declared interfaces resolve to `Interface`), allowing arbitrary Daml templates
/// and interfaces to be executed via `Engine`. If no DAR is loaded or the template is
/// unrecognised, the service falls back to `LegacyAssetHolding` to guarantee zero
/// regressions for pre-existing fixture test suites.
#[derive(Clone)]
pub(crate) enum TemplateResolution {
    Generic {
        package: Arc<LfPackage>,
        local_id: String,
        package_id: String,
    },
    Interface {
        package: Arc<LfPackage>,
        interface_id: String,
        interface_package_id: String,
    },
    LegacyAssetHolding,
    NotFound(String),
}

/// Maps internal Daml-LF codec errors to public API errors.
/// The acting parties of the root exercise of a command.
///
/// [CANTON-NOTE: SEMANTICS] The acting parties of an exercise node are the choice's controllers as the engine evaluated them, not the
/// `actAs` set of the submission: a command submitted as alice+bob for a choice controlled by alice records alice alone (measured on the
/// Canton 3.7.2 JVM, tests/oracle/json-api p06). Taking `actAs` would also make a participant's own model conformance reject the
/// request (`ActorsDiffer`). Falls back to `fallback` only if the engine journal holds no root exercise.
pub(crate) fn root_exercise_actors(
    outcome: &lf_eval::ChoiceOutcome,
    fallback: &[String],
) -> Vec<String> {
    outcome
        .events
        .iter()
        .find_map(|e| match e {
            lf_eval::EngineEvent::Exercise {
                actors, depth: 0, ..
            } => Some(actors.clone()),
            _ => None,
        })
        .unwrap_or_else(|| fallback.to_vec())
}

pub(crate) fn map_codec_error(err: CodecError) -> ApiError {
    match err {
        CodecError::UnknownTemplate(tmpl) => ApiError::TemplateNotFound(tmpl),
        CodecError::UnknownChoice { choice, template } => {
            ApiError::InvalidArgument(format!("Unknown choice '{choice}' on template {template}"))
        }
        other => ApiError::InvalidArgument(other.to_string()),
    }
}

/// Maps Daml-LF evaluator execution errors to public API errors.
///
/// Ensures exact HTTP status mapping:
/// - Unauthorized signatory / controller -> 403 Forbidden
/// - Precondition violation (ensure failed) -> 400 Bad Request
/// - Unknown template or choice -> 404 / 400
/// - Inactive / missing contract -> 404 Not Found
/// - Unhandled Daml exceptions (e.g. assertMsg failure) -> 400 Bad Request
pub(crate) fn map_exec_error(err: ExecError) -> ApiError {
    match err {
        // [CANTON-NOTE: SEMANTICS] In Daml authorization semantics, creating contracts requires
        // authorization of all declared signatories (authorizers), while exercising choices requires
        // authorization of the designated controllers.
        // [CANTON-NOTE: INVARIANT] Map ExecError::Unauthorized to ApiError::Unauthorized (HTTP 403)
        // preserving exact substrings ("requires authorizers", "requires controller", "requires authorization")
        // expected by API clients and test verifiers.
        ExecError::Unauthorized {
            kind,
            what,
            missing,
            authorized,
            ..
        } => {
            let role_desc = match kind {
                lf_eval::AuthKind::Signatories => "authorizers",
                lf_eval::AuthKind::Controllers => "controller",
                // a fetch needs one stakeholder of the contract among the authorizing parties
                lf_eval::AuthKind::Stakeholders => "stakeholder",
            };
            ApiError::Unauthorized(format!(
                "{what} requires {role_desc} {missing:?}; requires authorization of {missing:?}; authorized: {authorized:?}"
            ))
        }
        ExecError::PreconditionFailed { message } => {
            ApiError::PreconditionFailed(if message.starts_with("Template precondition violated") {
                message
            } else {
                format!("Template precondition violated: {message}")
            })
        }
        ExecError::UnknownTemplate { template_id, .. } => ApiError::TemplateNotFound(template_id),
        ExecError::UnknownChoice {
            choice,
            template_id,
        } => ApiError::InvalidArgument(format!(
            "Unknown choice '{choice}' on template {template_id}"
        )),
        ExecError::ContractNotFound(cid) | ExecError::ContractNotActive(cid) => {
            ApiError::ContractNotActive(cid)
        }
        ExecError::Unhandled { error_id, message } => {
            if message.is_empty() {
                ApiError::InvalidArgument(format!("unhandled exception {error_id}"))
            } else {
                ApiError::InvalidArgument(format!("{error_id}: {message}"))
            }
        }
        ExecError::Eval(e) => ApiError::Ledger(e.to_string()),
    }
}

/// Information about a dynamically loaded DAR archive and its constituent packages.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DarPackageInfo {
    pub main_package_id: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub lf_version: String,
    pub modules: Vec<String>,
    pub dalfs: Vec<lf_archive::DalfInfo>,
    pub module_surfaces: Vec<lf_archive::ModuleSurface>,
}

/// Response payload for GET /v1/packages.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackagesResponse {
    pub packages: Vec<String>,
    /// Same ids as `packages`. Official JSON Ledger API spells this field `packageIds`.
    #[serde(rename = "packageIds", default)]
    pub package_ids: Vec<String>,
    pub main_package_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiError {
    #[error("Template not found: {0}")]
    TemplateNotFound(String),
    #[error("Authorization failure: {0}")]
    Unauthorized(String),
    #[error("Precondition failed: {0}")]
    PreconditionFailed(String),
    #[error("Contract not active: {0}")]
    ContractNotActive(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Ledger execution error: {0}")]
    Ledger(String),
    #[error("DAR package error: {0}")]
    Dar(String),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("{code}({category},0): {cause}")]
    SynchronizerRejected {
        code: String,
        cause: String,
        grpc_code: i32,
        http_status: u16,
        category: u64,
        /// What the refusing participant added (`Verdict::reject_context`, JSON with `parties`, `reported_by`, `metadata`, `psid`): the
        /// error's `context`, `resources` and `details` are built from it.
        details: Option<String>,
    },
}

impl ApiError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Unauthorized(_) => 403,
            Self::ContractNotActive(_) | Self::TemplateNotFound(_) => 404,
            Self::Internal(_) => 500,
            Self::SynchronizerRejected { http_status, .. } => *http_status,
            Self::PreconditionFailed(_)
            | Self::InvalidArgument(_)
            | Self::Ledger(_)
            | Self::Dar(_)
            | Self::BadRequest(_) => 400,
        }
    }
}
