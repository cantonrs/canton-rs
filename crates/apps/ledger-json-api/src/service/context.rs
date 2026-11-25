//! Per-request execution context, thread-local dry-run/capture guards, and payload helpers.

use std::collections::HashMap;

use lf_eval::fat_contract::{compute_key_hash, encode_base64};
use sha2::Digest;

use super::{GenericContract, TransactionCommit};

#[derive(Clone, Default)]
pub(crate) struct CapturedJournal {
    pub(crate) events: Vec<lf_eval::EngineEvent>,
    pub(crate) contracts: HashMap<String, lf_eval::Contract>,
}

thread_local! {
    // The engine journals and transient contracts committed while a capture is open (see `capture_engine_events`).
    pub(super) static ENGINE_CAPTURE: std::cell::RefCell<Option<CapturedJournal>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` and returns what it returned with the engine events (in execution order, `depth` included) and contract
/// snapshots of every transaction it committed: the tree of a command with nested exercises and transient contracts.
pub(crate) fn capture_engine_events<T>(f: impl FnOnce() -> T) -> (T, CapturedJournal) {
    let outer = ENGINE_CAPTURE.with(|c| c.borrow_mut().replace(CapturedJournal::default()));
    let result = f();
    let captured = ENGINE_CAPTURE.with(|c| std::mem::replace(&mut *c.borrow_mut(), outer));
    (result, captured.unwrap_or_default())
}

thread_local! {
    // Active v2 submission execution context (explicitly disclosed contracts, `readAs`, and V12 allocation mode).
    static V2_COMMAND_MODE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static DISCLOSED_CONTRACTS: std::cell::RefCell<Vec<GenericContract>> = const { std::cell::RefCell::new(Vec::new()) };
    static READ_AS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    // Interactive prepare dry-run context: `(tx_uuid, seq)` and captured commits.
    static PREPARE_TX_UUID: std::cell::RefCell<Option<(String, u64)>> = const { std::cell::RefCell::new(None) };
    pub(super) static DRY_RUN_COMMITS: std::cell::RefCell<Vec<TransactionCommit>> = const { std::cell::RefCell::new(Vec::new()) };
    static EXERCISE_BY_KEY_MODE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// RAII guard for per-request v2 disclosure, `readAs`, and V12 allocation mode.
pub(crate) struct V2CommandGuard;

impl Drop for V2CommandGuard {
    fn drop(&mut self) {
        V2_COMMAND_MODE.with(|m| m.set(false));
        DISCLOSED_CONTRACTS.with(|d| d.borrow_mut().clear());
        READ_AS.with(|r| r.borrow_mut().clear());
    }
}

/// RAII guard for `/v2/interactive-submission/prepare` dry-run capture (never commits or mutates counters).
pub(crate) struct V2PrepareDryRunGuard;

impl Drop for V2PrepareDryRunGuard {
    fn drop(&mut self) {
        PREPARE_TX_UUID.with(|p| *p.borrow_mut() = None);
        DRY_RUN_COMMITS.with(|c| c.borrow_mut().clear());
    }
}

pub(crate) fn enter_v2_prepare_dry_run(tx_uuid: String) -> V2PrepareDryRunGuard {
    PREPARE_TX_UUID.with(|p| *p.borrow_mut() = Some((tx_uuid, 0)));
    DRY_RUN_COMMITS.with(|c| c.borrow_mut().clear());
    V2PrepareDryRunGuard
}

pub(crate) fn is_v2_prepare_dry_run() -> bool {
    PREPARE_TX_UUID.with(|p| p.borrow().is_some())
}

pub(crate) fn take_dry_run_commits() -> Vec<TransactionCommit> {
    DRY_RUN_COMMITS.with(|c| std::mem::take(&mut *c.borrow_mut()))
}

pub(super) fn prepare_v12_material() -> Option<([u8; 32], [u8; 32])> {
    PREPARE_TX_UUID.with(|p| {
        let mut borrow = p.borrow_mut();
        let (uuid, seq) = borrow.as_mut()?;
        let cur = *seq;
        *seq += 1;
        let salt: [u8; 32] =
            sha2::Sha256::digest(format!("canton-rs:prepare-v12-salt:{uuid}:{cur}").as_bytes())
                .into();
        let disc: [u8; 32] =
            sha2::Sha256::digest(format!("canton-rs:prepare-v12-disc:{uuid}:{cur}").as_bytes())
                .into();
        Some((salt, disc))
    })
}

/// Who a command is for, as its completion names it: what a protocol submission carries as its tag so that a completion can be recorded when
/// the submission's fate comes after the wait for it ended, or after a restart (see `protocol_late`).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommandIdentity {
    pub command_id: String,
    pub user_id: String,
    /// The client's `submissionId` (empty: none was given).
    pub submission_id: String,
    pub act_as: Vec<String>,
}

thread_local! {
    static COMMAND: std::cell::RefCell<Option<CommandIdentity>> = const { std::cell::RefCell::new(None) };
    static V1_RECORDING_ID: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    static PROTOCOL_UPDATE_ID: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    static PROTOCOL_REMAPPED_CIDS: std::cell::RefCell<std::collections::BTreeMap<String, String>> =
        const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
    static LAST_COMMIT_REMAPPED_CIDS: std::cell::RefCell<std::collections::BTreeMap<String, String>> =
        const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

static V1_RECORDING_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// RAII guard for the isolated per-request recording scope used by v1 JSON API commands
/// without populating `CommandIdentity` (which must remain v2-only).
pub(crate) struct V1RecordingGuard(Option<String>);

impl Drop for V1RecordingGuard {
    fn drop(&mut self) {
        let prev = self.0.take();
        V1_RECORDING_ID.with(|r| *r.borrow_mut() = prev);
    }
}

pub(crate) fn enter_v1_recording() -> (String, V1RecordingGuard) {
    let seq = V1_RECORDING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let id = format!("v1-rec-{seq}");
    let prev = V1_RECORDING_ID.with(|r| r.borrow_mut().replace(id.clone()));
    (id, V1RecordingGuard(prev))
}

#[cfg_attr(
    not(feature = "protocol"),
    allow(dead_code, reason = "read by the protocol committer")
)]
pub(crate) fn current_v1_recording_id() -> Option<String> {
    V1_RECORDING_ID.with(|r| r.borrow().clone())
}

/// RAII guard for the identity of the command the current thread submits.
pub(crate) struct CommandIdentityGuard;

impl Drop for CommandIdentityGuard {
    fn drop(&mut self) {
        COMMAND.with(|c| *c.borrow_mut() = None);
    }
}

/// The code the command service answers with when the wait for a command's completion ends first (`CommonErrors.RequestTimeOut`,
/// category `DeadlineExceededRequestStateUnknown`): the command is not rejected, it is still in flight.
pub const REQUEST_TIME_OUT: &str = "REQUEST_TIME_OUT";

impl super::ApiError {
    /// Whether the command was not judged yet when its wait ended (see [`REQUEST_TIME_OUT`]): its completion comes later, not now.
    pub(crate) fn is_request_time_out(&self) -> bool {
        matches!(self, super::ApiError::SynchronizerRejected { code, .. } if code == REQUEST_TIME_OUT)
    }
}

/// The command the current thread submits is `identity` until the guard is dropped.
pub(crate) fn enter_command(identity: CommandIdentity) -> CommandIdentityGuard {
    COMMAND.with(|c| *c.borrow_mut() = Some(identity));
    PROTOCOL_UPDATE_ID.with(|u| *u.borrow_mut() = None);
    PROTOCOL_REMAPPED_CIDS.with(|m| m.borrow_mut().clear());
    LAST_COMMIT_REMAPPED_CIDS.with(|m| m.borrow_mut().clear());
    CommandIdentityGuard
}

#[cfg(feature = "protocol")]
pub(crate) fn set_protocol_update_id(update_id: String) {
    PROTOCOL_UPDATE_ID.with(|u| *u.borrow_mut() = Some(update_id));
}

pub(crate) fn clear_protocol_update_id() {
    PROTOCOL_UPDATE_ID.with(|u| *u.borrow_mut() = None);
}

pub(crate) fn take_protocol_update_id() -> Option<String> {
    PROTOCOL_UPDATE_ID.with(|u| u.borrow_mut().take())
}

#[cfg(feature = "protocol")]
pub(crate) fn set_protocol_remapped_cids(map: std::collections::BTreeMap<String, String>) {
    PROTOCOL_REMAPPED_CIDS.with(|m| *m.borrow_mut() = map);
}

pub(crate) fn clear_protocol_remapped_cids() {
    PROTOCOL_REMAPPED_CIDS.with(|m| m.borrow_mut().clear());
}

pub(crate) fn take_protocol_remapped_cids() -> std::collections::BTreeMap<String, String> {
    PROTOCOL_REMAPPED_CIDS.with(|m| std::mem::take(&mut *m.borrow_mut()))
}

pub(crate) fn set_last_commit_remapped_cids(map: std::collections::BTreeMap<String, String>) {
    LAST_COMMIT_REMAPPED_CIDS.with(|m| *m.borrow_mut() = map);
}

pub(crate) fn take_last_commit_remapped_cids() -> std::collections::BTreeMap<String, String> {
    LAST_COMMIT_REMAPPED_CIDS.with(|m| std::mem::take(&mut *m.borrow_mut()))
}

/// The command the current thread submits, if it said (see [`enter_command`]).
#[cfg_attr(
    not(feature = "protocol"),
    allow(dead_code, reason = "read by the protocol committer")
)]
pub(crate) fn current_command() -> Option<CommandIdentity> {
    COMMAND.with(|c| c.borrow().clone())
}

/// Enters v2 command execution mode for the current thread, resetting all thread-local state on drop.
pub(crate) fn enter_v2_command(
    disclosed: Vec<GenericContract>,
    read_as: Vec<String>,
) -> V2CommandGuard {
    V2_COMMAND_MODE.with(|m| m.set(true));
    DISCLOSED_CONTRACTS.with(|d| *d.borrow_mut() = disclosed);
    READ_AS.with(|r| *r.borrow_mut() = read_as);
    PROTOCOL_UPDATE_ID.with(|u| *u.borrow_mut() = None);
    PROTOCOL_REMAPPED_CIDS.with(|m| m.borrow_mut().clear());
    LAST_COMMIT_REMAPPED_CIDS.with(|m| m.borrow_mut().clear());
    V2CommandGuard
}

pub(crate) fn is_v2_command_mode() -> bool {
    V2_COMMAND_MODE.with(std::cell::Cell::get)
}

pub(crate) fn current_disclosed_contracts() -> Vec<GenericContract> {
    DISCLOSED_CONTRACTS.with(|d| d.borrow().clone())
}

pub(crate) fn decoded_disclosed_blobs() -> Vec<(String, Vec<u8>)> {
    DISCLOSED_CONTRACTS.with(|d| {
        d.borrow()
            .iter()
            .filter_map(|c| {
                let bytes =
                    lf_eval::fat_contract::decode_strict_base64(&c.created_event_blob).ok()?;
                Some((c.contract_id.clone(), bytes))
            })
            .collect()
    })
}

pub(crate) fn disclosed_contract_by_id(id: &str) -> Option<GenericContract> {
    DISCLOSED_CONTRACTS.with(|d| d.borrow().iter().find(|c| c.contract_id == id).cloned())
}

pub(crate) fn current_read_as() -> Vec<String> {
    READ_AS.with(|r| r.borrow().clone())
}

pub(crate) fn current_exercise_by_key() -> bool {
    EXERCISE_BY_KEY_MODE.with(std::cell::Cell::get)
}

/// Run `f` with `root_by_key` flagged for the current thread (restoring the prior value on unwind).
pub(crate) fn with_exercise_by_key<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            EXERCISE_BY_KEY_MODE.with(|m| m.set(self.0));
        }
    }
    let prev = EXERCISE_BY_KEY_MODE.with(|m| m.replace(true));
    let _reset = Reset(prev);
    f()
}

#[derive(Clone, Debug)]
pub(super) struct AllocatedContractMeta {
    pub(super) created_event_blob: String,
    pub(super) contract_key_hash: String,
    pub(super) key_maintainers: Vec<String>,
    pub(super) created_at_micros: i64,
}

pub(super) fn compute_key_hash_b64(
    world: &lf_eval::World,
    package_id: &str,
    local_template: &str,
    key: Option<&lf_eval::Value>,
) -> String {
    let Some(key_val) = key else {
        return String::new();
    };
    let types = lf_eval::typed_json::Types::new(world);
    let Ok(pkg_name) = types.package_name(package_id) else {
        return String::new();
    };
    let Ok(Some(key_ty)) = types.template_key_type(package_id, local_template) else {
        return String::new();
    };
    compute_key_hash(&types, &pkg_name, local_template, &key_ty, key_val)
        .map(|kh| encode_base64(&kh))
        .unwrap_or_default()
}

/// A sortable key for a package version such as `1.10.0` (numeric parts compare as numbers, so 1.10 > 1.9).
pub(super) fn version_key(v: &str) -> Vec<u64> {
    v.split(['.', '-'])
        .map(|p| p.parse().unwrap_or(0))
        .collect()
}

/// [CANTON-NOTE: SEMANTICS] Translates a contract payload to the record of another version of its template (smart contract
/// upgrade, measured on the node in AT-L08): fields the target has and the contract lacks become `None` (they must be
/// `Optional`); fields the contract has and the target lacks must be `None` (a downgrade that would drop a value fails with
/// `INTERPRETATION_UPGRADE_ERROR_TRANSLATION_FAILED`); the others are kept by name.
pub(crate) fn translate_payload(
    source: &lf_eval::Value,
    target_fields: &[lf_archive::FieldDef],
) -> Result<lf_eval::Value, String> {
    let lf_eval::Value::Record { tycon, fields } = source else {
        return Err("the contract payload is not a record".to_string());
    };
    let mut out = Vec::new();
    for t in target_fields {
        match fields.iter().find(|(n, _)| n == &t.name) {
            Some((n, v)) => out.push((n.clone(), v.clone())),
            None if matches!(t.ty, lf_archive::SurfaceType::Optional(_)) => {
                out.push((t.name.clone(), lf_eval::Value::Optional(None)))
            }
            None => return Err(format!("the new field {} is not optional", t.name)),
        }
    }
    for (n, v) in fields {
        if !target_fields.iter().any(|t| &t.name == n)
            && !matches!(v, lf_eval::Value::Optional(None))
        {
            return Err(format!(
                "the field {n} has a value the target version cannot hold"
            ));
        }
    }
    Ok(lf_eval::Value::Record {
        tycon: tycon.clone(),
        fields: out,
    })
}

thread_local! {
    /// The stamp of the HTTP request this thread is serving (set when the connection is accepted).
    static ARRIVAL: std::cell::Cell<u64> = const { std::cell::Cell::new(u64::MAX) };
}

/// Records the arrival stamp of the request the current thread is about to serve.
pub fn set_arrival(stamp: u64) {
    ARRIVAL.with(|a| a.set(stamp));
}

/// The arrival stamp of the current request (`u64::MAX`, "arrived after everything", when none was set).
pub fn arrival() -> u64 {
    ARRIVAL.with(std::cell::Cell::get)
}

/// The external parties' authorization of the interactive submission being executed (U-56).
pub type ExternalAuthorization =
    canton_proto::com::digitalasset::canton::protocol::v32::ExternalAuthorization;

thread_local! {
    static EXTERNAL_AUTHORIZATION: std::cell::RefCell<Option<ExternalAuthorization>> =
        const { std::cell::RefCell::new(None) };
}

/// While alive, the commits of this thread are externally signed submissions carrying the authorization it was entered with.
pub(crate) struct ExternalAuthorizationGuard(Option<ExternalAuthorization>);

impl Drop for ExternalAuthorizationGuard {
    fn drop(&mut self) {
        let prev = self.0.take();
        EXTERNAL_AUTHORIZATION.with(|e| *e.borrow_mut() = prev);
    }
}

/// Marks the commits of this thread as an externally signed submission `authorization` covers (`execute` of an interactive submission).
pub(crate) fn enter_external_authorization(
    authorization: ExternalAuthorization,
) -> ExternalAuthorizationGuard {
    ExternalAuthorizationGuard(
        EXTERNAL_AUTHORIZATION.with(|e| e.borrow_mut().replace(authorization)),
    )
}

/// The external authorization the commits of this thread carry, if they are an externally signed submission.
#[cfg_attr(
    not(feature = "protocol"),
    allow(dead_code, reason = "read by the protocol committer")
)]
pub(crate) fn current_external_authorization() -> Option<ExternalAuthorization> {
    EXTERNAL_AUTHORIZATION.with(|e| e.borrow().clone())
}
