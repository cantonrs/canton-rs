//! Immutable Cold Archive Segments (`Static Files` tier before PostgreSQL pruning) and
//! deterministic 4-stage catch-up replay (`canton-rs db archive | verify-archive | replay | stats | tui`).
//!
//! [CANTON-NOTE: INVARIANT] Every map/set in segment construction, hashing, and replay uses
//! `BTreeMap` / `BTreeSet` so segment SHA-256 digests and reconstructed ACS commitments are
//! bit-for-bit deterministic across OSes and runs. Contract events preserve Stakeholder scoping
//! (`stakeholders`) and support optional payload redaction (`payload_json: None`) while keeping
//! `payload_sha256` intact for zero-payload cryptographic auditability.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

mod io;
mod jsonl;
#[cfg(feature = "postgres")]
mod pg;
mod replay;
#[cfg(test)]
mod tests;
mod verify;

pub use io::{
    ensure_existing_segments_prunable_provenance, ensure_prunable_coverage_dir_streaming,
    list_segment_paths, load_segments_from_dir, populate_cold_stats_from_dir,
    verify_archive_dir_streaming, write_segment_to_dir,
};
pub use jsonl::{parse_jsonl_history_events, parse_jsonl_history_reader};
#[cfg(feature = "postgres")]
pub use pg::{collect_pg_storage_stats, export_pg_range_to_segment, read_pg_archive_identity, PgArchiveIdentity};
pub use replay::{staged_replay, staged_replay_dir_streaming};
pub use verify::{
    build_cold_segment, compute_acs_state_root, ensure_prunable_coverage,
    ensure_prunable_coverage_from, hash_payload_json, verify_archive_chain,
    verify_archive_signer, verify_single_segment,
};

/// Domain error enum for cold archive export, verification, and staged replay.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ColdArchiveError {
    #[error("invalid offset range: from_offset ({from}) must be >= 1 and <= to_offset ({to})")]
    InvalidOffsetRange { from: i64, to: i64 },

    #[error("event offset {offset} lies outside segment range [{from}, {to}]")]
    EventOutOfRange { offset: i64, from: i64, to: i64 },

    #[error("events are not sorted monotonically at offset {prev} -> {next}")]
    NonMonotonicEventOffsets { prev: i64, next: i64 },

    #[error(
        "segment integrity mismatch on [{from}..={to}]: expected {expected}, computed {actual}"
    )]
    IntegrityMismatch {
        from: i64,
        to: i64,
        expected: String,
        actual: String,
    },

    #[error("broken segment hash chain before [{from}..={to}]: expected prev={expected:?}, found {actual:?}")]
    BrokenHashChain {
        from: i64,
        to: i64,
        expected: Option<String>,
        actual: Option<String>,
    },

    #[error("overlapping, non-monotonic or gapped segment range: previous ended at {prev_to}, next starts at {next_from}")]
    DisjointOrOverlappingRange { prev_to: i64, next_from: i64 },

    #[error("Ed25519 signature verification failed on segment [{from}..={to}]: {reason}")]
    SignatureInvalid { from: i64, to: i64, reason: String },

    #[error("refusing to prune: {reason}")]
    NotPrunable { reason: String },

    #[error("I/O error on cold archive '{path}': {reason}")]
    Io { path: String, reason: String },

    #[error("JSON serialization error: {0}")]
    Json(String),

    #[error("PostgreSQL query error during cold archive operation: {0}")]
    Postgres(String),
}

/// Lifecycle transition captured inside an immutable cold archive segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColdArchiveEventKind {
    Activate,
    Deactivate,
}

/// Canonical, Stakeholder-scoped ledger event stored in a [`ColdArchiveSegment`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdArchiveEvent {
    pub offset: i64,
    pub update_id: String,
    pub synchronizer_id: String,
    pub record_time_micros: i64,
    pub kind: ColdArchiveEventKind,
    pub contract_id: String,
    pub template_id: String,
    pub stakeholders: BTreeSet<String>,
    /// Optional contract create arguments (omitted in zero-payload archive mode).
    pub payload_json: Option<serde_json::Value>,
    /// SHA-256 hex digest of the canonical payload bytes (always present even if `payload_json` is redacted).
    pub payload_sha256: String,
}

/// Provenance of a [`ColdArchiveSegment`]: only PostgreSQL-exported segments carry database contracts
/// verbatim and are eligible to back `--prune-after-archive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColdArchiveSourceKind {
    Pg,
    Jsonl,
}

impl ColdArchiveSourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pg => "pg",
            Self::Jsonl => "jsonl",
        }
    }
}

/// Coverage, provenance, and signer policy enforced before physical database pruning.
#[derive(Clone, Copy, Debug)]
pub struct PruneCoverageSpec<'a> {
    pub expected_start: i64,
    pub prune_up_to: i64,
    pub expected_participant_id: &'a str,
    pub expected_synchronizer_id: &'a str,
    pub expected_signer_public_key_hex: &'a str,
}

/// Immutable, hash-chained, optionally Ed25519-signed historical ledger segment (`.crs-seg.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdArchiveSegment {
    pub format_version: u32,
    pub synchronizer_id: String,
    pub participant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<ColdArchiveSourceKind>,
    pub from_offset: i64,
    pub to_offset: i64,
    pub prev_segment_sha256: Option<String>,
    pub events_count: usize,
    pub events: Vec<ColdArchiveEvent>,
    pub acs_state_root_sha256: String,
    pub segment_sha256: String,
    pub signer_public_key_hex: Option<String>,
    pub ed25519_signature_hex: Option<String>,
}

/// Input specification for constructing a new [`ColdArchiveSegment`].
pub struct BuildSegmentSpec<'a> {
    pub synchronizer_id: &'a str,
    pub participant_id: &'a str,
    pub source_kind: Option<ColdArchiveSourceKind>,
    pub from_offset: i64,
    pub to_offset: i64,
    pub prev_segment_sha256: Option<String>,
    pub events: Vec<ColdArchiveEvent>,
    pub signing_key_bytes: Option<&'a [u8; 32]>,
}

/// Verification summary across a directory/chain of cold archive segments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveVerifyReport {
    pub segments_verified: usize,
    pub signed_segments: usize,
    pub total_events: usize,
    pub min_offset: Option<i64>,
    pub max_offset: Option<i64>,
    pub head_segment_sha256: Option<String>,
}

/// Per-stage execution metrics emitted by [`staged_replay`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStageMetric {
    pub stage: String,
    pub elapsed_us: u64,
    pub items_processed: usize,
}

/// Header summary for a verified or inspected [`ColdArchiveSegment`] (without holding event payloads in memory).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdArchiveSegmentMeta {
    pub synchronizer_id: String,
    pub participant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<ColdArchiveSourceKind>,
    pub from_offset: i64,
    pub to_offset: i64,
    pub prev_segment_sha256: Option<String>,
    pub events_count: usize,
    pub acs_state_root_sha256: String,
    pub segment_sha256: String,
    pub signer_public_key_hex: Option<String>,
    pub ed25519_signature_hex: Option<String>,
    pub integrity_ok: bool,
}

impl ColdArchiveSegmentMeta {
    pub fn from_segment(seg: &ColdArchiveSegment, integrity_ok: bool) -> Self {
        Self {
            synchronizer_id: seg.synchronizer_id.clone(),
            participant_id: seg.participant_id.clone(),
            source_kind: seg.source_kind,
            from_offset: seg.from_offset,
            to_offset: seg.to_offset,
            prev_segment_sha256: seg.prev_segment_sha256.clone(),
            events_count: seg.events_count,
            acs_state_root_sha256: seg.acs_state_root_sha256.clone(),
            segment_sha256: seg.segment_sha256.clone(),
            signer_public_key_hex: seg.signer_public_key_hex.clone(),
            ed25519_signature_hex: seg.ed25519_signature_hex.clone(),
            integrity_ok,
        }
    }
}

/// Deterministic 4-stage replay report reconstructing ACS and a canton-rs self-hash digest from cold segments.
///
/// [CANTON-NOTE: LIMITATION] `acs_commitment_sha256` is `canton-rs`'s deterministic SHA-256 over the replayed
/// active contract set, NOT Canton's protocol `AcsCommitment` (which uses homomorphic LtHash16). If
/// `from_offset > 1`, `is_partial` is `true` because activations prior to `from_offset` are absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedReplayReport {
    pub replayed_segments: usize,
    pub replayed_events: usize,
    pub from_offset: i64,
    pub up_to_offset: i64,
    pub is_partial: bool,
    pub active_contracts_count: usize,
    pub template_histogram: BTreeMap<String, usize>,
    pub party_active_counts: BTreeMap<String, usize>,
    pub acs_commitment_sha256: String,
    pub hash_kind: String,
    pub stages: Vec<ReplayStageMetric>,
}

/// Table-level PostgreSQL storage diagnostics row for `canton-rs db stats` and `canton-rs db tui`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageTableStat {
    pub category: String,
    pub table_name: String,
    pub row_count: u64,
    pub total_bytes: u64,
}

/// Unified PostgreSQL + Cold Archive storage snapshot for `canton-rs db stats` and `canton-rs db tui`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageOverviewStats {
    pub ledger_end: i64,
    pub pruned_up_to: i64,
    pub prunable_activations: u64,
    pub prunable_deactivations: u64,
    pub total_db_bytes: u64,
    pub tables: Vec<StorageTableStat>,
    pub cold_segments_count: usize,
    pub cold_events_count: usize,
    pub cold_max_offset: Option<i64>,
    pub cold_chain_valid: bool,
}
