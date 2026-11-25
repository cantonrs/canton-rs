//! Physical row deletion for Ledger API & Participant PostgreSQL stores (`prune_up_to`, `U-17`).
//!
//! [CANTON-NOTE: SEMANTICS] Mirrors Canton 3.7.2 physical pruning boundaries:
//! - Activations (`lapi_events_activate_contract` + filter tables) are deleted ONLY when paired with a
//!   deactivation at `event_offset <= prune_up_to`, so still-active contracts and contracts archived after
//!   `prune_up_to` remain intact for `activeAtOffset >= prune_up_to` queries and live execution.
//! - Deactivations, witnessed events, `lapi_update_meta`, `lapi_command_completions`, and
//!   `par_command_deduplication` at or below `prune_up_to` are physically removed.
//! - `par_contracts` and `par_active_contracts` rows for pruned contracts are deleted ONLY when no surviving
//!   event in any Ledger API event table still references that contract.
#[cfg(any(feature = "postgres", test))]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "postgres")]
use postgres::{Client, Transaction};

/// Row counts removed during one transactional `prune_up_to` pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OfficialPruneReport {
    pub pruned_activations: usize,
    pub pruned_deactivations: usize,
    pub pruned_witnessed: usize,
    pub pruned_meta: usize,
    pub pruned_completions: usize,
    pub pruned_dedup: usize,
    pub pruned_contracts: usize,
    pub pruned_active_contracts: usize,
}

#[cfg(feature = "postgres")]
fn pg_err(context: &str) -> impl FnOnce(postgres::Error) -> String + '_ {
    move |e| match e.as_db_error() {
        Some(d) => format!("{context}: {} ({})", d.message(), d.detail().unwrap_or("")),
        None => format!("{context}: {e}"),
    }
}

#[cfg(feature = "postgres")]
fn delete_by_seq_ids(tx: &mut Transaction<'_>, sql: &str, ids: &[i64]) -> Result<usize, String> {
    if ids.is_empty() {
        return Ok(0);
    }
    let count = tx
        .execute(sql, &[&ids])
        .map_err(pg_err("prune seq delete"))?;
    Ok(count as usize)
}

/// Physically deletes Ledger API and participant contract rows at or before `prune_up_to`,
/// advancing `lapi_parameters.participant_pruned_up_to_inclusive` atomically.
#[cfg(feature = "postgres")]
pub fn prune_up_to(client: &mut Client, prune_up_to: i64) -> Result<OfficialPruneReport, String> {
    if prune_up_to <= 0 {
        return Err("INVALID_ARGUMENT: prune_up_to must be positive".to_string());
    }
    let mut tx = client
        .transaction()
        .map_err(pg_err("begin prune transaction"))?;
    let params = tx
        .query_opt(
            "SELECT COALESCE(ledger_end, 0), COALESCE(participant_pruned_up_to_inclusive, 0) \
             FROM lapi_parameters FOR UPDATE",
            &[],
        )
        .map_err(pg_err("read lapi_parameters"))?
        .ok_or_else(|| "lapi_parameters is empty: ledger not initialized".to_string())?;
    let ledger_end: i64 = params.get(0);
    let prev_pruned: i64 = params.get(1);

    if prune_up_to >= ledger_end {
        return Err(format!(
            "OFFSET_OUT_OF_RANGE: prune_up_to ({prune_up_to}) must be before ledger_end ({ledger_end})"
        ));
    }
    if prune_up_to <= prev_pruned {
        tx.commit().map_err(pg_err("commit no-op prune"))?;
        return Ok(OfficialPruneReport::default());
    }

    // [CANTON-NOTE: INVARIANT] Delete an activation row ONLY if a matching deactivation also lies <= prune_up_to.
    let act_rows = tx
        .query(
            "SELECT a.event_sequential_id, a.internal_contract_id \
             FROM lapi_events_activate_contract a \
             WHERE a.event_offset <= $1 \
               AND EXISTS ( \
                 SELECT 1 FROM lapi_events_deactivate_contract d \
                 WHERE d.event_offset <= $1 \
                   AND ( \
                     d.deactivated_event_sequential_id = a.event_sequential_id \
                     OR (d.deactivated_event_sequential_id IS NULL \
                         AND d.internal_contract_id = a.internal_contract_id \
                         AND d.event_sequential_id > a.event_sequential_id) \
                   ) \
               )",
            &[&prune_up_to],
        )
        .map_err(pg_err("query prunable activations"))?;

    let mut act_seq_ids = Vec::with_capacity(act_rows.len());
    let mut candidate_cids = BTreeSet::new();
    for row in act_rows {
        act_seq_ids.push(row.get::<_, i64>(0));
        candidate_cids.insert(row.get::<_, i64>(1));
    }

    delete_by_seq_ids(
        &mut tx,
        "DELETE FROM lapi_filter_activate_stakeholder WHERE event_sequential_id = ANY($1)",
        &act_seq_ids,
    )?;
    delete_by_seq_ids(
        &mut tx,
        "DELETE FROM lapi_filter_activate_witness WHERE event_sequential_id = ANY($1)",
        &act_seq_ids,
    )?;
    delete_by_seq_ids(
        &mut tx,
        "DELETE FROM lapi_filter_achs_stakeholder WHERE event_sequential_id = ANY($1)",
        &act_seq_ids,
    )?;
    let pruned_activations = delete_by_seq_ids(
        &mut tx,
        "DELETE FROM lapi_events_activate_contract WHERE event_sequential_id = ANY($1)",
        &act_seq_ids,
    )?;

    let deact_rows = tx
        .query(
            "SELECT event_sequential_id, internal_contract_id \
             FROM lapi_events_deactivate_contract WHERE event_offset <= $1",
            &[&prune_up_to],
        )
        .map_err(pg_err("query prunable deactivations"))?;
    let mut deact_seq_ids = Vec::with_capacity(deact_rows.len());
    for row in deact_rows {
        deact_seq_ids.push(row.get::<_, i64>(0));
        if let Some(cid) = row.get::<_, Option<i64>>(1) {
            candidate_cids.insert(cid);
        }
    }
    delete_by_seq_ids(
        &mut tx,
        "DELETE FROM lapi_filter_deactivate_stakeholder WHERE event_sequential_id = ANY($1)",
        &deact_seq_ids,
    )?;
    delete_by_seq_ids(
        &mut tx,
        "DELETE FROM lapi_filter_deactivate_witness WHERE event_sequential_id = ANY($1)",
        &deact_seq_ids,
    )?;
    let pruned_deactivations = delete_by_seq_ids(
        &mut tx,
        "DELETE FROM lapi_events_deactivate_contract WHERE event_sequential_id = ANY($1)",
        &deact_seq_ids,
    )?;

    let wit_rows = tx
        .query(
            "SELECT event_sequential_id FROM lapi_events_various_witnessed WHERE event_offset <= $1",
            &[&prune_up_to],
        )
        .map_err(pg_err("query prunable witnessed"))?;
    let wit_seq_ids: Vec<i64> = wit_rows.iter().map(|r| r.get(0)).collect();
    delete_by_seq_ids(
        &mut tx,
        "DELETE FROM lapi_filter_various_witness WHERE event_sequential_id = ANY($1)",
        &wit_seq_ids,
    )?;
    let pruned_witnessed = delete_by_seq_ids(
        &mut tx,
        "DELETE FROM lapi_events_various_witnessed WHERE event_sequential_id = ANY($1)",
        &wit_seq_ids,
    )?;

    let pruned_meta = tx
        .execute(
            "DELETE FROM lapi_update_meta WHERE event_offset <= $1",
            &[&prune_up_to],
        )
        .map_err(pg_err("prune lapi_update_meta"))? as usize;
    let pruned_completions = tx
        .execute(
            "DELETE FROM lapi_command_completions WHERE completion_offset <= $1",
            &[&prune_up_to],
        )
        .map_err(pg_err("prune lapi_command_completions"))? as usize;
    let pruned_dedup = tx
        .execute(
            "DELETE FROM par_command_deduplication WHERE offset_definite_answer <= $1",
            &[&prune_up_to],
        )
        .map_err(pg_err("prune par_command_deduplication"))? as usize;

    let mut pruned_contracts = 0usize;
    let mut pruned_active_contracts = 0usize;
    if !candidate_cids.is_empty() {
        let candidate_list: Vec<i64> = candidate_cids.into_iter().collect();
        let orphaned = tx
            .query(
                "SELECT p.internal_contract_id, p.contract_id \
                 FROM par_contracts p \
                 WHERE p.internal_contract_id = ANY($1) \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM lapi_events_activate_contract a \
                     WHERE a.internal_contract_id = p.internal_contract_id \
                   ) \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM lapi_events_deactivate_contract d \
                     WHERE d.internal_contract_id = p.internal_contract_id OR d.contract_id = p.contract_id \
                   ) \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM lapi_events_various_witnessed w \
                     WHERE w.internal_contract_id = p.internal_contract_id OR w.contract_id = p.contract_id \
                   )",
                &[&candidate_list],
            )
            .map_err(pg_err("query orphaned contracts"))?;
        if !orphaned.is_empty() {
            let orphan_internal: Vec<i64> = orphaned.iter().map(|r| r.get(0)).collect();
            let orphan_raw: Vec<Vec<u8>> = orphaned.iter().map(|r| r.get(1)).collect();
            let raw_slices: Vec<&[u8]> = orphan_raw.iter().map(Vec::as_slice).collect();
            pruned_active_contracts =
                tx.execute(
                    "DELETE FROM par_active_contracts WHERE contract_id = ANY($1)",
                    &[&raw_slices],
                )
                .map_err(pg_err("prune par_active_contracts"))? as usize;
            pruned_contracts = tx
                .execute(
                    "DELETE FROM par_contracts WHERE internal_contract_id = ANY($1)",
                    &[&orphan_internal],
                )
                .map_err(pg_err("prune par_contracts"))? as usize;
        }
    }

    tx.execute(
        "UPDATE lapi_parameters SET participant_pruned_up_to_inclusive = GREATEST(COALESCE(participant_pruned_up_to_inclusive, 0), $1)",
        &[&prune_up_to],
    )
    .map_err(pg_err("update participant_pruned_up_to_inclusive"))?;
    tx.commit().map_err(pg_err("commit prune transaction"))?;

    Ok(OfficialPruneReport {
        pruned_activations,
        pruned_deactivations,
        pruned_witnessed,
        pruned_meta,
        pruned_completions,
        pruned_dedup,
        pruned_contracts,
        pruned_active_contracts,
    })
}

/// What a participant's tables say about how far it may be pruned (Canton 3.7.2 `FirstUnsafeOffsetComputation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneSafetyInputs {
    pub ledger_end: i64,
    pub pruned_up_to: i64,
    /// Lowest, over relevant synchronizers, of the latest ACS digest checkpoint offset (0: one has none).
    pub acs_digest_checkpoint: i64,
    /// Lowest, over relevant synchronizers, of the ACS commitment matching watermark (0: one has none).
    pub commitment_matching_watermark: i64,
    /// `par_settings.max_deduplication_duration` (None: not recorded).
    pub max_dedup_micros: Option<i64>,
    /// First offset published within the deduplication duration before the ledger end's publication time.
    pub first_offset_in_dedup_window: Option<i64>,
    /// Synchronizer undergoing hard migration (`par_synchronizer_connection_configs.status` in `'S' | 'T'`).
    pub migrating_synchronizer: Option<String>,
    /// Relevant synchronizer with no record time at or before `ledger_end` (`FirstUnsafeOffsetComputation.scala:327-337`).
    pub missing_record_time_synchronizer: Option<String>,
    /// Earliest unsafe offset due to legacy `par_last_computed_acs_commitments` / `par_outstanding_acs_commitments` reconciliation.
    pub legacy_acs_reconciliation_first_unsafe: Option<i64>,
    /// Earliest unsafe offset due to `par_in_flight_submission`.
    pub in_flight_submission_first_unsafe: Option<i64>,
    /// Earliest unsafe offset due to `lapi_ledger_end_synchronizer_index.sequencer_timestamp`.
    pub synchronizer_index_crash_recovery_first_unsafe: Option<i64>,
    /// Earliest unsafe offset due to `par_journal_requests` clean replay bound (`cleanReplayTs`).
    pub request_journal_crash_recovery_first_unsafe: Option<i64>,
    /// Earliest unsafe offset due to not-yet-effective `common_topology_transactions`.
    pub topology_crash_recovery_first_unsafe: Option<i64>,
}

/// Why a prune is refused, in the words of the Ledger API's refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PruneRefusal {
    #[error("INVALID_ARGUMENT: prune_up_to must be positive")]
    InvalidArgument,
    #[error(
        "OFFSET_OUT_OF_RANGE: prune_up_to ({prune_up_to}) must be before ledger_end ({ledger_end})"
    )]
    OffsetOutOfRange { prune_up_to: i64, ledger_end: i64 },
    #[error("UNSAFE_TO_PRUNE: Participant cannot prune at specified offset due to {cause} (first unsafe offset {first_unsafe})")]
    Unsafe { first_unsafe: i64, cause: String },
}

/// A prune that may go ahead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneVerdict {
    AlreadyPruned,
    Safe,
}

/// Decides whether pruning up to `prune_up_to` is safe given `inputs`.
pub fn check_prune_safety(
    prune_up_to: i64,
    inputs: &PruneSafetyInputs,
) -> Result<PruneVerdict, PruneRefusal> {
    if prune_up_to <= 0 {
        return Err(PruneRefusal::InvalidArgument);
    }
    if prune_up_to >= inputs.ledger_end {
        return Err(PruneRefusal::OffsetOutOfRange {
            prune_up_to,
            ledger_end: inputs.ledger_end,
        });
    }
    if prune_up_to <= inputs.pruned_up_to {
        return Ok(PruneVerdict::AlreadyPruned);
    }
    match first_unsafe_offset(inputs) {
        Some((first_unsafe, cause)) if first_unsafe <= prune_up_to => Err(PruneRefusal::Unsafe {
            first_unsafe,
            cause,
        }),
        _ => Ok(PruneVerdict::Safe),
    }
}

/// The highest offset a prune may reach now (None: nothing beyond what is pruned already).
pub fn highest_safe_prune_offset(inputs: &PruneSafetyInputs) -> Option<i64> {
    let below_end = inputs.ledger_end.saturating_sub(1);
    let bound = match first_unsafe_offset(inputs) {
        Some((first_unsafe, _)) => below_end.min(first_unsafe.saturating_sub(1)),
        None => below_end,
    };
    (bound > inputs.pruned_up_to).then_some(bound)
}

fn first_unsafe_offset(inputs: &PruneSafetyInputs) -> Option<(i64, String)> {
    // [CANTON-NOTE: SEMANTICS] Mirrors Canton 3.7.2 `FirstUnsafeOffsetComputation.scala`:
    // - Hard migrations (`S`/`T` in `par_synchronizer_connection_configs`) refuse pruning outright.
    // - Digest checkpoints & matching watermarks at offset O make O + 1 the first unsafe offset.
    // - Deduplication window inspects both `lapi_update_meta` and `lapi_command_completions`.
    // - Legacy commitments (`pv < 36` or unknown), in-flight submissions, synchronizer index crash recovery,
    //   request journal `cleanReplayTs`, and not-yet-effective topology transactions map timestamps to first unsafe offsets.
    if let Some(lsid) = &inputs.migrating_synchronizer {
        return Some((
            1,
            format!("hard migration in progress on synchronizer {lsid}"),
        ));
    }
    if let Some(lsid) = &inputs.missing_record_time_synchronizer {
        return Some((
            1,
            format!("no record time at or before ledger end on synchronizer {lsid}"),
        ));
    }
    let dedup_cause = match inputs.max_dedup_micros {
        Some(micros) => format!("max deduplication duration of {}s", micros / 1_000_000),
        None => "max deduplication duration of unknown".to_string(),
    };
    let dedup_first_unsafe = match inputs.max_dedup_micros {
        Some(_) => inputs.first_offset_in_dedup_window,
        None => Some(1),
    };
    let candidates = [
        (
            Some(inputs.acs_digest_checkpoint.saturating_add(1)),
            "ACS digest ingestion",
        ),
        (
            Some(inputs.commitment_matching_watermark.saturating_add(1)),
            "ACS commitment matching",
        ),
        (dedup_first_unsafe, dedup_cause.as_str()),
        (
            inputs.legacy_acs_reconciliation_first_unsafe,
            "ACS background reconciliation",
        ),
        (
            inputs.in_flight_submission_first_unsafe,
            "inFlightSubmissionTs",
        ),
        (
            inputs.synchronizer_index_crash_recovery_first_unsafe,
            "Synchronizer index crash recovery",
        ),
        (
            inputs.request_journal_crash_recovery_first_unsafe,
            "cleanReplayTs",
        ),
        (
            inputs.topology_crash_recovery_first_unsafe,
            "Topology event crash recovery",
        ),
    ];
    candidates
        .into_iter()
        .filter_map(|(offset, cause)| offset.map(|o| (o, cause.to_string())))
        .min_by_key(|(offset, _)| *offset)
}

/// Decodes a `google.protobuf.Duration` (seconds = field 1, nanos = field 2) into microseconds.
pub fn decode_proto_duration_micros(bytes: &[u8]) -> Option<i64> {
    fn varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *bytes.get(*pos)?;
            *pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }
    let (mut seconds, mut nanos) = (0i64, 0i64);
    let mut pos = 0;
    while pos < bytes.len() {
        let tag = varint(bytes, &mut pos)?;
        let value = varint(bytes, &mut pos)?;
        match tag {
            0x08 => seconds = i64::try_from(value).ok()?,
            0x10 => nanos = i64::try_from(value).ok()?,
            _ => return None,
        }
    }
    seconds.checked_mul(1_000_000)?.checked_add(nanos / 1_000)
}

/// Parses a Canton physical synchronizer ID `<logical-id>::<pv>-<serial>` into `(lsid, pv, serial)`.
#[cfg(any(feature = "postgres", test))]
fn parse_physical_synchronizer_id(psid: &str) -> Option<(&str, u32, u32)> {
    let (lsid, suffix) = psid.rsplit_once("::")?;
    let (pv_str, serial_str) = suffix.rsplit_once('-')?;
    let pv = pv_str.parse::<u32>().ok()?;
    let serial = serial_str.parse::<u32>().ok()?;
    (!lsid.is_empty()).then_some((lsid, pv, serial))
}

/// Computes the latest clean commitment timestamp at or before `before_or_at` (`AcsCommitmentStore.scala:416-434`).
#[cfg(any(feature = "postgres", test))]
fn latest_clean_period(before_or_at: i64, unclean_periods: &[(i64, i64)]) -> i64 {
    let mut descending: Vec<(i64, i64)> = unclean_periods.to_vec();
    descending.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
    let mut starting_clean = before_or_at;
    for (start_exclusive, end_inclusive) in descending {
        if end_inclusive < starting_clean {
            break;
        }
        if start_exclusive < starting_clean {
            starting_clean = start_exclusive;
        }
    }
    starting_clean
}

#[cfg(any(feature = "postgres", test))]
#[derive(Clone, Copy)]
struct TopologyStateRow {
    sequenced: i64,
    valid_from: i64,
    valid_until: Option<i64>,
    operation: i32,
}

/// Mirrors `StoredTopologyTransactions.toEffectiveStateChanges(fromEffectiveInclusive = record_time, onlyAtEffective = false)`
/// (`TopologyTransactionCollection.scala:83-115`) to find the earliest `sequenced` timestamp among pending state changes.
#[cfg(any(feature = "postgres", test))]
fn topology_crash_recovery_sequenced(record_time: i64, rows: &[TopologyStateRow]) -> Option<i64> {
    const TOPOLOGY_OP_REPLACE: i32 = 2;
    let mut valid_from_map: BTreeMap<i64, Vec<&TopologyStateRow>> = BTreeMap::new();
    let mut valid_until_map: BTreeMap<i64, Vec<&TopologyStateRow>> = BTreeMap::new();
    let mut effective_times = BTreeSet::new();
    for row in rows {
        valid_from_map.entry(row.valid_from).or_default().push(row);
        effective_times.insert(row.valid_from);
        if let Some(vu) = row.valid_until {
            valid_until_map.entry(vu).or_default().push(row);
            effective_times.insert(vu);
        }
    }
    let mut earliest_seq: Option<i64> = None;
    for t in effective_times {
        if t < record_time {
            continue;
        }
        let after = valid_from_map.get(&t).map(Vec::as_slice).unwrap_or(&[]);
        let Some(seq) = after.iter().map(|r| r.sequenced).min() else {
            continue;
        };
        let before = valid_until_map.get(&t).map(Vec::as_slice).unwrap_or(&[]);
        let has_positive = after.iter().any(|r| r.operation == TOPOLOGY_OP_REPLACE)
            || before.iter().any(|r| r.operation == TOPOLOGY_OP_REPLACE);
        if has_positive {
            earliest_seq = Some(earliest_seq.map_or(seq, |prev| prev.min(seq)));
        }
    }
    earliest_seq
}

#[cfg(feature = "postgres")]
fn min_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

#[cfg(feature = "postgres")]
fn update_min_opt(slot: &mut Option<i64>, cand: Option<i64>) {
    *slot = min_opt(*slot, cand);
}

#[cfg(feature = "postgres")]
fn first_synchronizer_offset_after_or_at(
    client: &mut Client,
    lapi_sync_id: i32,
    ts_micros: i64,
    ledger_end: i64,
) -> Result<Option<i64>, String> {
    // [CANTON-NOTE: SEMANTICS] Mirrors `EventStorageBackendTemplate.firstSynchronizerOffsetAfterOrAt` (`:1268-1299`).
    let row = client
        .query_opt(
            "SELECT offset_val FROM ( \
               (SELECT completion_offset AS offset_val, record_time \
                FROM lapi_command_completions \
                WHERE synchronizer_id = $1 AND record_time >= $2 AND completion_offset <= $3 \
                ORDER BY synchronizer_id ASC, record_time ASC, completion_offset ASC \
                LIMIT 1) \
               UNION ALL \
               (SELECT event_offset AS offset_val, record_time \
                FROM lapi_update_meta \
                WHERE synchronizer_id = $1 AND record_time >= $2 AND event_offset <= $3 \
                ORDER BY synchronizer_id ASC, record_time ASC, event_offset ASC \
                LIMIT 1) \
             ) t \
             ORDER BY record_time ASC, offset_val ASC \
             LIMIT 1",
            &[&lapi_sync_id, &ts_micros, &ledger_end],
        )
        .map_err(pg_err("first_synchronizer_offset_after_or_at"))?;
    Ok(row.map(|r| r.get::<_, i64>(0)))
}

#[cfg(feature = "postgres")]
fn last_record_time_before_or_at_synchronizer_offset(
    client: &mut Client,
    lapi_sync_id: i32,
    ledger_end: i64,
) -> Result<Option<i64>, String> {
    // [CANTON-NOTE: SEMANTICS] Mirrors `EventStorageBackendTemplate.lastSynchronizerOffsetBeforeOrAt` (`:1464-1504`).
    let row = client
        .query_one(
            "SELECT MAX(record_time) FROM ( \
               (SELECT record_time \
                FROM lapi_command_completions \
                WHERE synchronizer_id = $1 AND completion_offset <= $2 \
                ORDER BY completion_offset DESC, record_time DESC \
                LIMIT 1) \
               UNION ALL \
               (SELECT record_time \
                FROM lapi_update_meta \
                WHERE synchronizer_id = $1 AND event_offset <= $2 \
                ORDER BY event_offset DESC, record_time DESC \
                LIMIT 1) \
             ) t",
            &[&lapi_sync_id, &ledger_end],
        )
        .map_err(pg_err("last_record_time_before_or_at_synchronizer_offset"))?;
    Ok(row.get::<_, Option<i64>>(0))
}

#[cfg(feature = "postgres")]
struct RelevantSync {
    lsid: String,
    lsid_idx: i32,
    lapi_sync_id: Option<i32>,
    active_psid: Option<(u32, u32)>,
}

/// Reads [`PruneSafetyInputs`] from a participant database whose writer lock the caller holds.
///
/// [CANTON-NOTE: LIMITATION] Offline PG safety inspection does not parse participant HOCON config files and
/// therefore assumes Canton 3.7.2 defaults (`ParticipantNodeConfig.scala:518-521, 549-574`; `DbAcsCommitmentStore.scala:421-422`):
/// `acsDigestProcessorEnabled = true`, `disableOldAcsCommitmentProcessor = OnNewProtocolVersions` (legacy processor
/// disabled when active `pv >= 36`), and `safeToPruneCommitmentState = Match`.
#[cfg(feature = "postgres")]
pub fn load_prune_safety_inputs(client: &mut Client) -> Result<PruneSafetyInputs, String> {
    let params = client
        .query_opt(
            "SELECT COALESCE(ledger_end, 0), COALESCE(participant_pruned_up_to_inclusive, 0), \
                    COALESCE(ledger_end_publication_time, 0) \
             FROM lapi_parameters LIMIT 1",
            &[],
        )
        .map_err(pg_err("read lapi_parameters"))?
        .ok_or_else(|| "lapi_parameters is empty: ledger not initialized".to_string())?;
    let ledger_end: i64 = params.get(0);
    let pruned_up_to: i64 = params.get(1);
    let end_publication_time: i64 = params.get(2);

    // 1. Synchronizer relevance & hard-migration refusal (`par_synchronizer_connection_configs`).
    let config_rows = client
        .query(
            "SELECT synchronizer_alias, physical_synchronizer_id, TRIM(status::text) \
             FROM par_synchronizer_connection_configs",
            &[],
        )
        .map_err(pg_err("read par_synchronizer_connection_configs"))?;

    let mut statuses_by_lsid: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut active_psid_by_lsid: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    let mut migrating_synchronizer: Option<String> = None;
    for r in config_rows {
        let alias: String = r.get(0);
        let psid_opt: Option<String> = r.get(1);
        let status: String = r.get(2);
        let lsid = psid_opt
            .as_deref()
            .and_then(parse_physical_synchronizer_id)
            .map(|(l, pv, ser)| (l.to_string(), Some((pv, ser))))
            .unwrap_or_else(|| (psid_opt.clone().unwrap_or(alias), None));
        if matches!(status.as_str(), "S" | "T") {
            migrating_synchronizer = Some(lsid.0.clone());
        }
        if status == "A" {
            if let Some(ps) = lsid.1 {
                active_psid_by_lsid.insert(lsid.0.clone(), ps);
            }
        }
        statuses_by_lsid.entry(lsid.0).or_default().push(status);
    }

    let lsid_rows = client
        .query(
            "SELECT s.id, s.string, si.internal_id \
             FROM common_static_strings s \
             LEFT JOIN lapi_string_interning si ON si.external_string = ('d|' || s.string) \
             WHERE s.source = 1 \
             ORDER BY s.id ASC",
            &[],
        )
        .map_err(pg_err("read relevant logical synchronizers"))?;

    let mut relevant_syncs = Vec::new();
    for r in lsid_rows {
        let lsid_idx: i32 = r.get(0);
        let lsid: String = r.get(1);
        let lapi_sync_id: Option<i32> = r.get(2);
        if let Some(statuses) = statuses_by_lsid.get(&lsid) {
            if !statuses.is_empty() && statuses.iter().all(|s| s == "I") {
                continue;
            }
        }
        let active_psid = active_psid_by_lsid.get(&lsid).copied();
        relevant_syncs.push(RelevantSync {
            lsid,
            lsid_idx,
            lapi_sync_id,
            active_psid,
        });
    }

    // 2. Max deduplication window across both `lapi_update_meta` and `lapi_command_completions`.
    let max_dedup_micros = client
        .query_opt(
            "SELECT max_deduplication_duration FROM par_settings LIMIT 1",
            &[],
        )
        .map_err(pg_err("read par_settings"))?
        .and_then(|r| r.get::<_, Option<Vec<u8>>>(0))
        .and_then(|bytes| decode_proto_duration_micros(&bytes));
    let first_offset_in_dedup_window = match max_dedup_micros {
        Some(window) => client
            .query_one(
                "SELECT MIN(off) FROM ( \
                   SELECT MIN(event_offset) AS off \
                   FROM lapi_update_meta \
                   WHERE publication_time >= $1 AND event_offset <= $2 \
                   UNION ALL \
                   SELECT MIN(completion_offset) AS off \
                   FROM lapi_command_completions \
                   WHERE publication_time >= $1 AND completion_offset <= $2 \
                 ) t",
                &[&end_publication_time.saturating_sub(window), &ledger_end],
            )
            .map_err(pg_err("read dedup publication times"))?
            .get::<_, Option<i64>>(0),
        None => None,
    };

    // 3 & 4. ACS digest checkpoint & commitment matching watermark scoped to relevant synchronizers.
    let (acs_digest_checkpoint, commitment_matching_watermark) = if relevant_syncs.is_empty() {
        if !statuses_by_lsid.is_empty() {
            (ledger_end, ledger_end)
        } else {
            (0, 0)
        }
    } else {
        let mut min_digest: Option<i64> = None;
        let mut min_watermark: Option<i64> = None;
        for sync in &relevant_syncs {
            let cp = client
                .query_one(
                    "SELECT COALESCE(MAX(change_offset), 0) \
                     FROM par_acs_running_digests_checkpoint \
                     WHERE synchronizer_idx = $1",
                    &[&sync.lsid_idx],
                )
                .map_err(pg_err("read par_acs_running_digests_checkpoint"))?
                .get::<_, i64>(0);
            update_min_opt(&mut min_digest, Some(cp));
            let wm = client
                .query_opt(
                    "SELECT watermark_matching \
                     FROM par_acs_commitment_period_watermark \
                     WHERE synchronizer_idx = $1",
                    &[&sync.lsid_idx],
                )
                .map_err(pg_err("read par_acs_commitment_period_watermark"))?
                .map_or(0, |r| r.get::<_, i64>(0));
            update_min_opt(&mut min_watermark, Some(wm));
        }
        (min_digest.unwrap_or(0), min_watermark.unwrap_or(0))
    };

    // Per-synchronizer criteria: record time availability (`:327-337`), 5 (legacy ACS),
    // 6 (in-flight submissions), 7 (synchronizer index), plus `sync_index_by_lsid` fed into physical criteria 8 & 9.
    let mut missing_record_time_synchronizer: Option<String> = None;
    let mut legacy_acs_reconciliation_first_unsafe: Option<i64> = None;
    let mut in_flight_submission_first_unsafe: Option<i64> = None;
    let mut synchronizer_index_crash_recovery_first_unsafe: Option<i64> = None;
    let mut sync_index_by_lsid: BTreeMap<String, (Option<i64>, i64, Option<i32>)> = BTreeMap::new();

    for sync in &relevant_syncs {
        // [CANTON-NOTE: SEMANTICS] `FirstUnsafeOffsetComputation.scala:327-337`:
        // `lastRecordTimeBeforeOrAtSynchronizerOffset` is ALWAYS queried for every relevant synchronizer
        // regardless of protocol version; if `None`, pruning is refused (`LedgerPruningOffsetUnsafeSynchronizer`).
        let up_to_opt = match sync.lapi_sync_id {
            Some(sid) => {
                last_record_time_before_or_at_synchronizer_offset(client, sid, ledger_end)?
            }
            None => None,
        };
        if up_to_opt.is_none() && missing_record_time_synchronizer.is_none() {
            missing_record_time_synchronizer = Some(sync.lsid.clone());
        }

        // Criterion 5: Legacy ACS background reconciliation (`OnNewProtocolVersions`: active ONLY when `pv < 36` or PV unknown).
        let legacy_disabled_by_pv = sync.active_psid.is_some_and(|(pv, _)| pv >= 36);
        if !legacy_disabled_by_pv {
            let computed_opt = client
                .query_opt(
                    "SELECT ts FROM par_last_computed_acs_commitments WHERE synchronizer_idx = $1",
                    &[&sync.lsid_idx],
                )
                .map_err(pg_err("read par_last_computed_acs_commitments"))?
                .map(|r| r.get::<_, i64>(0));
            match (up_to_opt, computed_opt, sync.lapi_sync_id) {
                (Some(up_to), Some(computed), Some(sid)) => {
                    let adj = up_to.min(computed);
                    let unsafe_periods: Vec<(i64, i64)> = client
                        .query(
                            "SELECT o.from_exclusive, o.to_inclusive \
                             FROM par_outstanding_acs_commitments o \
                             WHERE o.synchronizer_idx = $1 \
                               AND o.from_exclusive < $2 \
                               AND o.matching_state != 2 \
                               AND NOT EXISTS ( \
                                 SELECT 1 FROM acs_no_wait_counter_participants nw \
                                 WHERE nw.synchronizer_id = $3 AND nw.participant_id = o.counter_participant \
                               )",
                            &[&sync.lsid_idx, &adj, &sync.lsid],
                        )
                        .map_err(pg_err("read par_outstanding_acs_commitments"))?
                        .into_iter()
                        .map(|r| (r.get(0), r.get(1)))
                        .collect();
                    let safe_tick = latest_clean_period(adj, &unsafe_periods);
                    let off =
                        first_synchronizer_offset_after_or_at(client, sid, safe_tick, ledger_end)?;
                    update_min_opt(&mut legacy_acs_reconciliation_first_unsafe, off);
                }
                _ => update_min_opt(&mut legacy_acs_reconciliation_first_unsafe, Some(1)),
            }
        }

        // Criterion 6: In-flight submissions (`par_in_flight_submission`).
        let inf_row = client
            .query_one(
                "SELECT MIN(sequencing_time), MIN(sequencing_timeout) \
                 FROM par_in_flight_submission \
                 WHERE submission_synchronizer_id = $1",
                &[&sync.lsid],
            )
            .map_err(pg_err("read par_in_flight_submission"))?;
        if let Some(earliest_in_flight) = min_opt(
            inf_row.get::<_, Option<i64>>(0),
            inf_row.get::<_, Option<i64>>(1),
        ) {
            let off = match sync.lapi_sync_id {
                Some(sid) => first_synchronizer_offset_after_or_at(
                    client,
                    sid,
                    earliest_in_flight,
                    ledger_end,
                )?,
                None => Some(1),
            };
            update_min_opt(&mut in_flight_submission_first_unsafe, off);
        }

        // Criterion 7: Synchronizer index crash recovery (`lapi_ledger_end_synchronizer_index`).
        if let Some(sid) = sync.lapi_sync_id {
            if let Some(idx_row) = client
                .query_opt(
                    "SELECT sequencer_timestamp, repair_timestamp, record_time \
                     FROM lapi_ledger_end_synchronizer_index \
                     WHERE synchronizer_id = $1",
                    &[&sid],
                )
                .map_err(pg_err("read lapi_ledger_end_synchronizer_index"))?
            {
                let seq_ts: Option<i64> = idx_row.get(0);
                let repair_ts: Option<i64> = idx_row.get(1);
                let raw_rt: i64 = idx_row.get(2);
                let record_time = raw_rt
                    .max(repair_ts.unwrap_or(i64::MIN))
                    .max(seq_ts.unwrap_or(i64::MIN));
                if let Some(st) = seq_ts {
                    let off = first_synchronizer_offset_after_or_at(client, sid, st, ledger_end)?;
                    update_min_opt(&mut synchronizer_index_crash_recovery_first_unsafe, off);
                }
                sync_index_by_lsid.insert(sync.lsid.clone(), (seq_ts, record_time, Some(sid)));
            }
        }
    }

    // 8 & 9. Physical synchronizer crash recovery (`source = 2` request journal, `source = 3` topology store).
    let mut request_journal_crash_recovery_first_unsafe: Option<i64> = None;
    let mut topology_crash_recovery_first_unsafe: Option<i64> = None;
    if !sync_index_by_lsid.is_empty() {
        let phys_strings = client
            .query(
                "SELECT id, string, source FROM common_static_strings WHERE source IN (2, 3) ORDER BY id ASC",
                &[],
            )
            .map_err(pg_err("read physical synchronizer static strings"))?;

        for row in phys_strings {
            let store_idx: i32 = row.get(0);
            let psid_str: String = row.get(1);
            let source: i32 = row.get(2);
            let Some((lsid, pv, serial)) = parse_physical_synchronizer_id(&psid_str) else {
                continue;
            };
            let Some(&(seq_ts, record_time, lapi_sid_opt)) = sync_index_by_lsid.get(lsid) else {
                continue;
            };
            if let Some((active_pv, active_ser)) = active_psid_by_lsid.get(lsid).copied() {
                if (pv, serial) < (active_pv, active_ser) {
                    continue;
                }
            }
            let Some(lapi_sid) = lapi_sid_opt else {
                continue;
            };

            if source == 2 {
                // [CANTON-NOTE: SEMANTICS] `RequestJournalStore.scala:135-163` + `FirstUnsafeOffsetComputation.scala:471`:
                // Scala uses `Ordering[Option[CantonTimestamp]].min(requestReplayTs, cleanSequencerIndexTs)` where `None < Some`,
                // so when `cleanRequestTimestamp == None` or `cleanSequencerIndexTs == None`, `cleanReplayTs` yields `None` (unconstrained).
                let clean_ts: Option<i64> = client
                    .query_one(
                        "SELECT MAX(request_timestamp) FROM par_journal_requests \
                         WHERE physical_synchronizer_idx = $1 AND request_timestamp <= $2",
                        &[&store_idx, &record_time],
                    )
                    .map_err(pg_err("read clean request timestamp"))?
                    .get(0);
                let replay_ts = match clean_ts {
                    None => None,
                    Some(ts) => {
                        let committed_after = client
                            .query_opt(
                                "WITH committed_after AS ( \
                                   SELECT request_counter FROM par_journal_requests \
                                   WHERE physical_synchronizer_idx = $1 AND commit_time > $2 \
                                 ) \
                                 SELECT j.request_timestamp FROM par_journal_requests j \
                                 WHERE j.physical_synchronizer_idx = $1 \
                                   AND j.request_counter = (SELECT MIN(request_counter) FROM committed_after)",
                                &[&store_idx, &ts],
                            )
                            .map_err(pg_err("read firstRequestWithCommitTimeAfter"))?
                            .map(|r| r.get::<_, i64>(0));
                        let base = committed_after.unwrap_or(ts);
                        Some(if base == i64::MIN {
                            i64::MIN
                        } else {
                            base.saturating_sub(1)
                        })
                    }
                };
                let seq_pred = seq_ts.map(|s| {
                    if s == i64::MIN {
                        i64::MIN
                    } else {
                        s.saturating_sub(1)
                    }
                });
                if let (Some(r), Some(s)) = (replay_ts, seq_pred) {
                    let bound_ts = r.min(s);
                    let off = first_synchronizer_offset_after_or_at(
                        client, lapi_sid, bound_ts, ledger_end,
                    )?;
                    update_min_opt(&mut request_journal_crash_recovery_first_unsafe, off);
                }
            } else if source == 3 {
                let topo_rows: Vec<TopologyStateRow> = client
                    .query(
                        "SELECT sequenced, valid_from, valid_until, operation \
                         FROM common_topology_transactions \
                         WHERE store_id = $1 \
                           AND (valid_from >= $2 OR valid_until >= $2) \
                           AND (valid_until IS NULL OR valid_from != valid_until) \
                           AND is_proposal = false \
                           AND rejection_reason IS NULL",
                        &[&store_idx, &record_time],
                    )
                    .map_err(pg_err("read common_topology_transactions"))?
                    .into_iter()
                    .map(|r| TopologyStateRow {
                        sequenced: r.get(0),
                        valid_from: r.get(1),
                        valid_until: r.get(2),
                        operation: r.get(3),
                    })
                    .collect();
                if let Some(min_seq) = topology_crash_recovery_sequenced(record_time, &topo_rows) {
                    let off = first_synchronizer_offset_after_or_at(
                        client, lapi_sid, min_seq, ledger_end,
                    )?;
                    update_min_opt(&mut topology_crash_recovery_first_unsafe, off);
                }
            }
        }
    }

    Ok(PruneSafetyInputs {
        ledger_end,
        pruned_up_to,
        acs_digest_checkpoint,
        commitment_matching_watermark,
        max_dedup_micros,
        first_offset_in_dedup_window,
        migrating_synchronizer,
        missing_record_time_synchronizer,
        legacy_acs_reconciliation_first_unsafe,
        in_flight_submission_first_unsafe,
        synchronizer_index_crash_recovery_first_unsafe,
        request_journal_crash_recovery_first_unsafe,
        topology_crash_recovery_first_unsafe,
    })
}

/// Refuses a prune to `prune_up_to` that Canton's participant would refuse as unsafe.
#[cfg(feature = "postgres")]
pub fn check_safe_to_prune(client: &mut Client, prune_up_to: i64) -> Result<PruneVerdict, String> {
    let inputs = load_prune_safety_inputs(client)?;
    check_prune_safety(prune_up_to, &inputs).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe_inputs() -> PruneSafetyInputs {
        PruneSafetyInputs {
            ledger_end: 100,
            pruned_up_to: 0,
            acs_digest_checkpoint: 80,
            commitment_matching_watermark: 90,
            max_dedup_micros: Some(10_000_000),
            first_offset_in_dedup_window: Some(95),
            migrating_synchronizer: None,
            missing_record_time_synchronizer: None,
            legacy_acs_reconciliation_first_unsafe: None,
            in_flight_submission_first_unsafe: None,
            synchronizer_index_crash_recovery_first_unsafe: None,
            request_journal_crash_recovery_first_unsafe: None,
            topology_crash_recovery_first_unsafe: None,
        }
    }

    fn unsafe_cause(prune_up_to: i64, inputs: &PruneSafetyInputs) -> (i64, String) {
        match check_prune_safety(prune_up_to, inputs) {
            Err(PruneRefusal::Unsafe {
                first_unsafe,
                cause,
            }) => (first_unsafe, cause),
            other => panic!("expected UNSAFE_TO_PRUNE at {prune_up_to}, got {other:?}"),
        }
    }

    #[test]
    fn prune_safety_follows_digest_checkpoint_matching_watermark_and_dedup_window() {
        let inputs = safe_inputs();
        assert_eq!(check_prune_safety(80, &inputs), Ok(PruneVerdict::Safe));
        assert_eq!(
            unsafe_cause(81, &inputs),
            (81, "ACS digest ingestion".to_string())
        );

        let matching_behind = PruneSafetyInputs {
            commitment_matching_watermark: 50,
            ..safe_inputs()
        };
        assert_eq!(
            unsafe_cause(60, &matching_behind),
            (51, "ACS commitment matching".to_string())
        );

        let young = PruneSafetyInputs {
            first_offset_in_dedup_window: Some(40),
            ..safe_inputs()
        };
        assert_eq!(
            unsafe_cause(40, &young),
            (40, "max deduplication duration of 10s".to_string())
        );
        assert_eq!(check_prune_safety(39, &young), Ok(PruneVerdict::Safe));

        let no_checkpoint = PruneSafetyInputs {
            acs_digest_checkpoint: 0,
            ..safe_inputs()
        };
        assert_eq!(unsafe_cause(1, &no_checkpoint).0, 1);

        let unknown_dedup = PruneSafetyInputs {
            max_dedup_micros: None,
            first_offset_in_dedup_window: None,
            ..safe_inputs()
        };
        assert_eq!(
            unsafe_cause(1, &unknown_dedup),
            (1, "max deduplication duration of unknown".to_string())
        );

        let pruned = PruneSafetyInputs {
            pruned_up_to: 70,
            acs_digest_checkpoint: 0,
            ..safe_inputs()
        };
        assert_eq!(
            check_prune_safety(70, &pruned),
            Ok(PruneVerdict::AlreadyPruned)
        );
        assert_eq!(
            check_prune_safety(0, &inputs),
            Err(PruneRefusal::InvalidArgument)
        );
        assert!(matches!(
            check_prune_safety(100, &inputs),
            Err(PruneRefusal::OffsetOutOfRange { .. })
        ));

        assert_eq!(highest_safe_prune_offset(&inputs), Some(80));
        assert_eq!(highest_safe_prune_offset(&no_checkpoint), None);
        assert_eq!(highest_safe_prune_offset(&young), Some(39));
    }

    #[test]
    fn decodes_protobuf_duration_bytes_of_par_settings() {
        // google.protobuf.Duration { seconds: 604800 } as Canton stores `max_deduplication_duration`
        assert_eq!(
            decode_proto_duration_micros(&[0x08, 0x80, 0xF5, 0x24]),
            Some(604_800_000_000)
        );
        assert_eq!(
            decode_proto_duration_micros(&[0x08, 0x0A, 0x10, 0xE8, 0x07]),
            Some(10_000_001)
        );
        assert_eq!(decode_proto_duration_micros(&[]), Some(0));
        assert_eq!(decode_proto_duration_micros(&[0x08]), None);
    }

    #[test]
    fn prune_safety_enforces_all_r4_criteria_and_helpers() {
        let migrating = PruneSafetyInputs {
            migrating_synchronizer: Some("sync1::1220aa".into()),
            ..safe_inputs()
        };
        assert_eq!(
            unsafe_cause(10, &migrating),
            (
                1,
                "hard migration in progress on synchronizer sync1::1220aa".into()
            )
        );
        assert_eq!(highest_safe_prune_offset(&migrating), None);

        let legacy_blocked = PruneSafetyInputs {
            legacy_acs_reconciliation_first_unsafe: Some(25),
            ..safe_inputs()
        };
        assert_eq!(
            unsafe_cause(30, &legacy_blocked),
            (25, "ACS background reconciliation".into())
        );
        assert_eq!(
            check_prune_safety(24, &legacy_blocked),
            Ok(PruneVerdict::Safe)
        );

        let inflight = PruneSafetyInputs {
            in_flight_submission_first_unsafe: Some(30),
            ..safe_inputs()
        };
        assert_eq!(
            unsafe_cause(30, &inflight),
            (30, "inFlightSubmissionTs".into())
        );

        let sync_idx = PruneSafetyInputs {
            synchronizer_index_crash_recovery_first_unsafe: Some(35),
            ..safe_inputs()
        };
        assert_eq!(
            unsafe_cause(40, &sync_idx),
            (35, "Synchronizer index crash recovery".into())
        );

        let clean_replay = PruneSafetyInputs {
            request_journal_crash_recovery_first_unsafe: Some(20),
            ..safe_inputs()
        };
        assert_eq!(
            unsafe_cause(25, &clean_replay),
            (20, "cleanReplayTs".into())
        );

        let topo_crash = PruneSafetyInputs {
            topology_crash_recovery_first_unsafe: Some(15),
            ..safe_inputs()
        };
        assert_eq!(
            unsafe_cause(15, &topo_crash),
            (15, "Topology event crash recovery".into())
        );

        assert_eq!(
            parse_physical_synchronizer_id("sync1::1220aa::34-1"),
            Some(("sync1::1220aa", 34, 1))
        );
        assert_eq!(parse_physical_synchronizer_id("sync1::1220aa"), None);

        assert_eq!(
            latest_clean_period(100, &[(30, 50), (45, 90), (85, 110)]),
            30
        );
        assert_eq!(latest_clean_period(100, &[(10, 40), (60, 80)]), 100);

        let rows = vec![
            TopologyStateRow {
                sequenced: 500,
                valid_from: 1000,
                valid_until: Some(2500),
                operation: 2,
            },
            TopologyStateRow {
                sequenced: 2000,
                valid_from: 2500,
                valid_until: None,
                operation: 1, // Remove removing prior Replace at 2500
            },
        ];
        assert_eq!(topology_crash_recovery_sequenced(1500, &rows), Some(2000));
        assert_eq!(topology_crash_recovery_sequenced(2600, &rows), None);
    }
}
