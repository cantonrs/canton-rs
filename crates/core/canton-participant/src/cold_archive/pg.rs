use std::collections::BTreeSet;
use std::path::Path;

use super::io::populate_cold_stats_from_dir;
use super::verify::{build_cold_segment, hash_payload_json};
use super::{
    BuildSegmentSpec, ColdArchiveError, ColdArchiveEvent, ColdArchiveEventKind, ColdArchiveSegment,
    ColdArchiveSourceKind, StorageOverviewStats, StorageTableStat,
};

/// Participant and primary logical synchronizer identity of a PostgreSQL node database.
#[cfg(feature = "postgres")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PgArchiveIdentity {
    pub participant_id: String,
    pub synchronizer_id: String,
}

#[cfg(feature = "postgres")]
fn read_pg_archive_identity_with<C: postgres::GenericClient>(
    client: &mut C,
) -> Result<PgArchiveIdentity, ColdArchiveError> {
    let pg = |e: postgres::Error| ColdArchiveError::Postgres(e.to_string());
    let participant_id: String = client
        .query_opt("SELECT participant_id FROM lapi_parameters LIMIT 1", &[])
        .map_err(pg)?
        .and_then(|r| r.get::<_, Option<String>>(0))
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            ColdArchiveError::Postgres(
                "lapi_parameters has no participant_id row for cold archive provenance".to_string(),
            )
        })?;

    let synchronizer_id = match client
        .query_opt(
            "SELECT external_string FROM lapi_string_interning WHERE external_string LIKE 'd|%' ORDER BY internal_id LIMIT 1",
            &[],
        )
        .map_err(pg)?
        .and_then(|r| r.get::<_, Option<String>>(0))
    {
        Some(ext) => decode_interned_sync(Some(ext.as_str()), None, "canton-sync"),
        None => client
            .query_opt(
                "SELECT string FROM common_static_strings WHERE source = 1 ORDER BY id LIMIT 1",
                &[],
            )
            .map_err(pg)?
            .map_or_else(
                || "canton-sync".to_string(),
                |r| r.get::<_, String>(0),
            ),
    };

    Ok(PgArchiveIdentity {
        participant_id,
        synchronizer_id,
    })
}

/// Reads the participant ID and primary synchronizer ID from a participant PostgreSQL database.
#[cfg(feature = "postgres")]
pub fn read_pg_archive_identity(
    client: &mut postgres::Client,
) -> Result<PgArchiveIdentity, ColdArchiveError> {
    read_pg_archive_identity_with(client)
}

#[cfg(feature = "postgres")]
fn decode_interned_sync(ext: Option<&str>, raw_id: Option<i32>, fallback: &str) -> String {
    if let Some(s) = ext {
        return s.strip_prefix("d|").unwrap_or(s).to_string();
    }
    raw_id.map_or_else(|| fallback.to_string(), |id| id.to_string())
}

/// Exports PostgreSQL `lapi_events_activate_contract` & `lapi_events_deactivate_contract` in
/// `[from_offset, to_offset]` into an immutable [`ColdArchiveSegment`].
#[cfg(feature = "postgres")]
pub fn export_pg_range_to_segment(
    client: &mut postgres::Client,
    from_offset: i64,
    to_offset: i64,
    prev_segment_sha256: Option<String>,
    zero_payload: bool,
    signing_key_bytes: Option<&[u8; 32]>,
) -> Result<ColdArchiveSegment, ColdArchiveError> {
    const PG_EXPORT_CHUNK: i64 = 1_000;
    if from_offset < 1 || from_offset > to_offset {
        return Err(ColdArchiveError::InvalidOffsetRange {
            from: from_offset,
            to: to_offset,
        });
    }

    // one repeatable-read snapshot: activations and deactivations must describe the same ledger state
    let mut client = client
        .build_transaction()
        .isolation_level(postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .map_err(|e| ColdArchiveError::Postgres(e.to_string()))?;
    let identity = read_pg_archive_identity_with(&mut client)?;
    let participant_id = identity.participant_id;
    let mut sync_name = identity.synchronizer_id;
    let pg = |e: postgres::Error| ColdArchiveError::Postgres(e.to_string());
    let mut events = Vec::new();
    let mut sync_assigned = false;

    // [CANTON-NOTE: WHY] Pruning deletes `par_contracts` rows of archived contracts, so the segment keeps each contract's
    // id, template, stakeholders and the stored instance (`par_contracts.instance`, the fat contract blob a repair import
    // takes), not only the internal row number. Stream in bounded offset chunks inside the RepeatableRead snapshot.
    let mut chunk_from = from_offset;
    while chunk_from <= to_offset {
        let chunk_to = chunk_from
            .saturating_add(PG_EXPORT_CHUNK - 1)
            .min(to_offset);
        let act_rows = client
            .query(
                "SELECT a.event_offset, COALESCE(ENCODE(a.update_id, 'hex'), ''), \
                        si.external_string, a.synchronizer_id, COALESCE(a.record_time, 0), \
                        a.internal_contract_id, ENCODE(c.contract_id, 'hex'), c.package_id, c.template_id, c.instance \
                 FROM lapi_events_activate_contract a \
                 LEFT JOIN lapi_string_interning si ON si.internal_id = a.synchronizer_id \
                 LEFT JOIN par_contracts c ON c.internal_contract_id = a.internal_contract_id \
                 WHERE a.event_offset >= $1 AND a.event_offset <= $2 \
                 ORDER BY a.event_offset ASC, a.event_sequential_id ASC",
                &[&chunk_from, &chunk_to],
            )
            .map_err(pg)?;

        for r in act_rows {
            let offset: i64 = r.get(0);
            let update_id: String = r.get(1);
            let ext_sync: Option<String> = r.get(2);
            let raw_sync_id: Option<i32> = r.get(3);
            let sync_id = decode_interned_sync(ext_sync.as_deref(), raw_sync_id, &sync_name);
            if !sync_assigned && ext_sync.is_some() {
                sync_name.clone_from(&sync_id);
                sync_assigned = true;
            }
            let record_time_micros: i64 = r.get(4);
            let internal_cid: i64 = r.get(5);
            let (Some(cid), Some(package_id), Some(local_template), Some(instance)) = (
                r.get::<_, Option<String>>(6),
                r.get::<_, Option<String>>(7),
                r.get::<_, Option<String>>(8),
                r.get::<_, Option<Vec<u8>>>(9),
            ) else {
                return Err(ColdArchiveError::Postgres(format!(
                    "activation at offset {offset} (internal contract {internal_cid}) has no par_contracts row"
                )));
            };
            let raw = lf_eval::fat_contract::decode_fat_contract_blob(&instance).map_err(|e| {
                ColdArchiveError::Postgres(format!("decode contract instance {cid}: {e}"))
            })?;
            let mut stakeholders = BTreeSet::new();
            stakeholders.extend(raw.non_maintainer_signatories);
            stakeholders.extend(raw.non_signatory_stakeholders);
            if let Some(k) = raw.key {
                stakeholders.extend(k.maintainers);
            }
            let payload = serde_json::json!({ "contract_instance_hex": hex::encode(&instance) });
            let payload_sha256 = hash_payload_json(Some(&payload));
            events.push(ColdArchiveEvent {
                offset,
                update_id,
                synchronizer_id: sync_id,
                record_time_micros,
                kind: ColdArchiveEventKind::Activate,
                contract_id: cid,
                template_id: format!("{package_id}:{local_template}"),
                stakeholders,
                payload_json: if zero_payload { None } else { Some(payload) },
                payload_sha256,
            });
        }

        let deact_rows = client
            .query(
                "SELECT d.event_offset, COALESCE(ENCODE(d.update_id, 'hex'), ''), \
                        si.external_string, d.synchronizer_id, COALESCE(d.record_time, 0), \
                        COALESCE(ENCODE(d.contract_id, 'hex'), ENCODE(c.contract_id, 'hex')) \
                 FROM lapi_events_deactivate_contract d \
                 LEFT JOIN lapi_string_interning si ON si.internal_id = d.synchronizer_id \
                 LEFT JOIN par_contracts c ON c.internal_contract_id = d.internal_contract_id \
                 WHERE d.event_offset >= $1 AND d.event_offset <= $2 \
                 ORDER BY d.event_offset ASC, d.event_sequential_id ASC",
                &[&chunk_from, &chunk_to],
            )
            .map_err(pg)?;

        for r in deact_rows {
            let offset: i64 = r.get(0);
            let update_id: String = r.get(1);
            let sync_id = decode_interned_sync(
                r.get::<_, Option<String>>(2).as_deref(),
                r.get::<_, Option<i32>>(3),
                &sync_name,
            );
            let record_time_micros: i64 = r.get(4);
            let cid: String = r.get::<_, Option<String>>(5).ok_or_else(|| {
                ColdArchiveError::Postgres(format!(
                    "deactivation at offset {offset} has no contract id"
                ))
            })?;
            events.push(ColdArchiveEvent {
                offset,
                update_id,
                synchronizer_id: sync_id,
                record_time_micros,
                kind: ColdArchiveEventKind::Deactivate,
                contract_id: cid,
                template_id: "lapi:DeactivateContract".to_string(),
                stakeholders: BTreeSet::new(),
                payload_json: None,
                payload_sha256: hash_payload_json(None),
            });
        }

        chunk_from = chunk_to.saturating_add(1);
    }

    events.sort_by_key(|e| (e.offset, e.kind));
    client.commit().map_err(pg)?;

    build_cold_segment(BuildSegmentSpec {
        synchronizer_id: &sync_name,
        participant_id: &participant_id,
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset,
        to_offset,
        prev_segment_sha256,
        events,
        signing_key_bytes,
    })
}

/// Queries table row counts, disk relation sizes, ledger offsets, and prunable headroom from PostgreSQL.
#[cfg(feature = "postgres")]
pub fn collect_pg_storage_stats(
    client: &mut postgres::Client,
    archive_dir: Option<&Path>,
) -> Result<StorageOverviewStats, String> {
    let safety = crate::official_prune::load_prune_safety_inputs(client)?;
    let (ledger_end, pruned_up_to) = (safety.ledger_end, safety.pruned_up_to);
    // "prunable" counts what a prune to the participant's current safe point would delete, not everything below the end
    let (prunable_activations, prunable_deactivations): (i64, i64) =
        match crate::official_prune::highest_safe_prune_offset(&safety) {
            Some(safe) => {
                let count = |client: &mut postgres::Client, sql: &str| {
                    client
                        .query_one(sql, &[&safe])
                        .map(|r| r.get::<_, i64>(0))
                        .map_err(|e| format!("failed to count prunable events: {e}"))
                };
                (
                    count(
                        client,
                        "SELECT COUNT(*) FROM lapi_events_activate_contract a \
                         WHERE a.event_offset <= $1 \
                           AND EXISTS ( \
                             SELECT 1 FROM lapi_events_deactivate_contract d \
                             WHERE d.event_offset <= $1 \
                               AND d.internal_contract_id = a.internal_contract_id \
                           )",
                    )?,
                    count(
                        client,
                        "SELECT COUNT(*) FROM lapi_events_deactivate_contract WHERE event_offset <= $1",
                    )?,
                )
            }
            None => (0, 0),
        };

    let rel_rows = client
        .query(
            "SELECT c.relname, \
                    GREATEST(c.reltuples::bigint, 0) AS est_rows, \
                    pg_total_relation_size(c.oid) AS total_bytes \
             FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             WHERE n.nspname = current_schema() \
               AND c.relkind = 'r' \
               AND (c.relname LIKE 'lapi_%' OR c.relname LIKE 'par_%' \
                    OR c.relname LIKE 'ord_%' OR c.relname LIKE 'pqs_%' \
                    OR c.relname LIKE 'common_%' OR c.relname = 'canton_rs_state' \
                    OR c.relname = 'flyway_schema_history') \
             ORDER BY pg_total_relation_size(c.oid) DESC, c.relname ASC",
            &[],
        )
        .map_err(|e| format!("failed to query pg_class storage stats: {e}"))?;

    let mut tables = Vec::with_capacity(rel_rows.len());
    let mut total_db_bytes = 0u64;
    for row in rel_rows {
        let name: String = row.get(0);
        // planner estimate (`reltuples`): an exact COUNT(*) per table is a full scan on a large ledger
        let est_rows: i64 = row.get(1);
        let bytes_i64: i64 = row.get(2);
        let bytes = u64::try_from(bytes_i64).unwrap_or(0);
        total_db_bytes += bytes;
        let category = if name.starts_with("lapi_") {
            "Ledger API"
        } else if name.starts_with("par_") {
            "Participant"
        } else if name.starts_with("ord_") {
            "BFT Orderer"
        } else if name.starts_with("pqs_") {
            "PQS Index"
        } else {
            "Common / Meta"
        };
        tables.push(StorageTableStat {
            category: category.to_string(),
            table_name: name,
            row_count: u64::try_from(est_rows).unwrap_or(0),
            total_bytes: bytes,
        });
    }

    let mut stats = StorageOverviewStats {
        ledger_end,
        pruned_up_to,
        prunable_activations: u64::try_from(prunable_activations).unwrap_or(0),
        prunable_deactivations: u64::try_from(prunable_deactivations).unwrap_or(0),
        total_db_bytes,
        tables,
        cold_segments_count: 0,
        cold_events_count: 0,
        cold_max_offset: None,
        cold_chain_valid: true,
    };

    if let Some(dir) = archive_dir {
        populate_cold_stats_from_dir(dir, &mut stats);
    }
    Ok(stats)
}
