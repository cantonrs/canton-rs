use std::collections::BTreeSet;

use super::verify::hash_payload_json;
use super::{ColdArchiveError, ColdArchiveEvent, ColdArchiveEventKind};

/// Streams Scan/JSON-API JSONL history lines (`--scan-history` format) from `reader` without loading the file whole.
pub fn parse_jsonl_history_reader<R: std::io::BufRead>(
    reader: R,
    from_offset: i64,
    to_offset: i64,
    zero_payload: bool,
) -> Result<Vec<ColdArchiveEvent>, ColdArchiveError> {
    let mut events = Vec::new();
    for (line_idx, line_res) in reader.lines().enumerate() {
        let line = line_res.map_err(|e| ColdArchiveError::Io {
            path: "jsonl-history".to_string(),
            reason: e.to_string(),
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| ColdArchiveError::Json(format!("line {}: {e}", line_idx + 1)))?;
        let offset = v
            .get("offset")
            .and_then(|x| {
                x.as_i64()
                    .or_else(|| x.as_str().and_then(|s| s.parse::<i64>().ok()))
            })
            .ok_or_else(|| ColdArchiveError::Json(format!("line {}: no offset", line_idx + 1)))?;
        let contract_id = |ev: &serde_json::Value| {
            ev.get("contractId")
                .or_else(|| ev.get("contract_id"))
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    ColdArchiveError::Json(format!(
                        "line {}: event without contractId",
                        line_idx + 1
                    ))
                })
        };
        if offset < from_offset || offset > to_offset {
            continue;
        }
        let update_id = v
            .get("update_id")
            .or_else(|| v.get("updateId"))
            .and_then(|x| x.as_str())
            .unwrap_or("tx")
            .to_string();
        let sync_id = v
            .get("synchronizer_id")
            .or_else(|| v.get("synchronizerId"))
            .and_then(|x| x.as_str())
            .unwrap_or("canton-rs::sync")
            .to_string();
        let record_time_micros = v
            .get("record_time_micros")
            .and_then(|x| x.as_i64())
            .unwrap_or(offset * 1_000);

        if let Some(arr) = v.get("events").and_then(|x| x.as_array()) {
            for item in arr {
                if let Some(created) = item.get("CreatedEvent").or_else(|| item.get("created")) {
                    let cid = contract_id(created)?;
                    let tmpl = created
                        .get("templateId")
                        .or_else(|| created.get("template_id"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("unknown:Template")
                        .to_string();
                    let mut stakeholders = BTreeSet::new();
                    for key in ["signatories", "observers", "stakeholders"] {
                        if let Some(ps) = created.get(key).and_then(|x| x.as_array()) {
                            for p in ps.iter().filter_map(|x| x.as_str()) {
                                stakeholders.insert(p.to_string());
                            }
                        }
                    }
                    let args = created
                        .get("createArgument")
                        .or_else(|| created.get("createArguments"))
                        .or_else(|| created.get("payload"));
                    let payload_sha256 = hash_payload_json(args);
                    events.push(ColdArchiveEvent {
                        offset,
                        update_id: update_id.clone(),
                        synchronizer_id: sync_id.clone(),
                        record_time_micros,
                        kind: ColdArchiveEventKind::Activate,
                        contract_id: cid,
                        template_id: tmpl,
                        stakeholders,
                        payload_json: if zero_payload { None } else { args.cloned() },
                        payload_sha256,
                    });
                } else if let Some(arch) =
                    item.get("ArchivedEvent").or_else(|| item.get("archived"))
                {
                    let cid = contract_id(arch)?;
                    let tmpl = arch
                        .get("templateId")
                        .or_else(|| arch.get("template_id"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("unknown:Template")
                        .to_string();
                    let mut stakeholders = BTreeSet::new();
                    if let Some(ps) = arch.get("witnessParties").and_then(|x| x.as_array()) {
                        for p in ps.iter().filter_map(|x| x.as_str()) {
                            stakeholders.insert(p.to_string());
                        }
                    }
                    events.push(ColdArchiveEvent {
                        offset,
                        update_id: update_id.clone(),
                        synchronizer_id: sync_id.clone(),
                        record_time_micros,
                        kind: ColdArchiveEventKind::Deactivate,
                        contract_id: cid,
                        template_id: tmpl,
                        stakeholders,
                        payload_json: None,
                        payload_sha256: hash_payload_json(None),
                    });
                }
            }
        }
    }
    events.sort_by_key(|e| e.offset);
    Ok(events)
}

/// Parses Scan/JSON-API JSONL history text (`--scan-history` format) into canonical [`ColdArchiveEvent`]s.
pub fn parse_jsonl_history_events(
    jsonl_raw: &str,
    from_offset: i64,
    to_offset: i64,
    zero_payload: bool,
) -> Result<Vec<ColdArchiveEvent>, ColdArchiveError> {
    parse_jsonl_history_reader(
        std::io::Cursor::new(jsonl_raw.as_bytes()),
        from_offset,
        to_offset,
        zero_payload,
    )
}
