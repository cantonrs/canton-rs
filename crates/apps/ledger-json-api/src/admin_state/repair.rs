use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
use lf_eval::tx_model::ContractId;
use prost::Message as _;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use super::connectivity::{get_sync_id, list_registered_syncs};
use super::{logical_sync, AdminErr};
use crate::service::{ExecutionService, GenericContract};
use crate::v2::PendingRepairOp;
use crate::v2_commands::{rfc3339_from_micros, Ev, StoredUpdate};
use crate::TemplateId;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ExportedContractRecord {
    contract_id: String,
    package_id: String,
    module_name: String,
    entity_name: String,
    json_payload: Json,
    signatories: Vec<String>,
    observers: Vec<String>,
    witness_parties: Vec<String>,
    synchronizer_id: String,
    reassignment_counter: i64,
    created_at_micros: i64,
    created_event_blob: String,
    contract_key_hash: String,
    key_maintainers: Vec<String>,
}

pub fn purge_contracts(
    service: &ExecutionService,
    synchronizer_alias: &str,
    contract_ids: &[String],
    ignore_already_purged: bool,
) -> Result<(), AdminErr> {
    if synchronizer_alias.trim().is_empty() {
        return Err((
            3,
            "INVALID_ARGUMENT(8,00000000): synchronizer_alias must not be empty".to_string(),
        ));
    }
    let syncs = list_registered_syncs(service);
    if !syncs.iter().any(|s| s.alias == synchronizer_alias) {
        return Err((
            5,
            format!("SYNCHRONIZER_NOT_FOUND(11,00000000): Unknown synchronizer alias '{synchronizer_alias}'"),
        ));
    }
    let mut g_lock = service
        .generic_contracts
        .write()
        .map_err(|_| (13, "generic_contracts lock poisoned".to_string()))?;
    let mut a_lock = service
        .active_state
        .write()
        .map_err(|_| (13, "active_state lock poisoned".to_string()))?;
    if !ignore_already_purged {
        for cid in contract_ids {
            let active = g_lock.get(cid).is_some_and(|c| c.active);
            if !active {
                return Err((
                    5,
                    format!(
                        "CONTRACT_NOT_FOUND(11,00000000): Cannot purge contract {cid} because it is not active"
                    ),
                ));
            }
        }
    }
    // [CANTON-NOTE: SEMANTICS] `RepairService.purgeContracts` purges the synchronizer's active contract store, which requests are judged
    // against, before the Ledger API sees the archival (P-14).
    let committer = service.committer.read().ok().and_then(|c| c.clone());
    if let Some(Err(e)) = committer
        .as_ref()
        .and_then(|c| c.repair_purge(contract_ids, ignore_already_purged))
    {
        return Err((9, format!("FAILED_PRECONDITION(9,00000000): {e}")));
    }
    for cid in contract_ids {
        if let Some(c) = g_lock.get_mut(cid) {
            c.active = false;
        }
        a_lock.active_contracts.remove(&ContractId(cid.clone()));
    }
    Ok(())
}

pub fn export_acs(
    service: &ExecutionService,
    party_ids: &[String],
    synchronizer_id: &str,
    ledger_offset: i64,
    renames: &BTreeMap<String, String>,
    excluded_stakeholders: &[String],
) -> Result<Vec<u8>, AdminErr> {
    let end = service.v2_state().ledger_end.load(Ordering::SeqCst) as i64;
    if ledger_offset < 0 || ledger_offset > end {
        return Err((
            3,
            format!(
                "INVALID_ARGUMENT(8,00000000): Ledger offset {ledger_offset} needs to be smaller or equal to ledger end {end}"
            ),
        ));
    }
    let contracts = if ledger_offset == end {
        service.v2_active_contracts()
    } else {
        service.v2_active_contracts_at(ledger_offset as u64)
    };
    let excluded: BTreeSet<&str> = excluded_stakeholders.iter().map(String::as_str).collect();
    let committer = service.committer.read().ok().and_then(|c| c.clone());
    let mut out = Vec::new();
    for c in contracts {
        let mut stakeholders: Vec<&str> = c
            .signatories
            .iter()
            .chain(c.observers.iter())
            .map(String::as_str)
            .collect();
        stakeholders.sort_unstable();
        stakeholders.dedup();
        if !party_ids.is_empty() && !party_ids.iter().any(|p| stakeholders.contains(&p.as_str())) {
            continue;
        }
        if stakeholders.iter().any(|p| excluded.contains(p)) {
            continue;
        }
        let Some((current_sync, counter)) = service.v2_state().location_of(&c.contract_id) else {
            continue;
        };
        if !synchronizer_id.is_empty()
            && current_sync != synchronizer_id
            && logical_sync(&current_sync) != logical_sync(synchronizer_id)
        {
            continue;
        }
        let assigned_sync = renames.get(&c.contract_id).cloned().unwrap_or(current_sync);
        // the instance the participant holds (with the salt its id was derived from), which an import authenticates
        let created_event_blob = committer
            .as_ref()
            .and_then(|p| p.instance_bytes(&c.contract_id))
            .map(|b| lf_eval::fat_contract::encode_base64(&b))
            .unwrap_or(c.created_event_blob);
        let rec = ExportedContractRecord {
            contract_id: c.contract_id,
            package_id: if c.package_id.is_empty() {
                c.template_id.package_id.clone()
            } else {
                c.package_id
            },
            module_name: c.template_id.module_name,
            entity_name: c.template_id.entity_name,
            json_payload: c.json_payload,
            signatories: c.signatories,
            observers: c.observers,
            witness_parties: c.witness_parties,
            synchronizer_id: assigned_sync,
            reassignment_counter: counter,
            created_at_micros: c.created_at_micros,
            created_event_blob,
            contract_key_hash: c.contract_key_hash,
            key_maintainers: c.key_maintainers,
        };
        let payload = serde_json::to_vec(&rec).map_err(|e| (13, e.to_string()))?;
        let msg = p30::ActiveContract {
            active_contract: payload,
        };
        msg.encode_length_delimited(&mut out)
            .map_err(|e| (13, e.to_string()))?;
    }
    Ok(out)
}

#[derive(Default)]
pub struct ImportOverrides {
    pub contract_override: BTreeMap<String, String>,
    pub package_id_override: BTreeMap<String, String>,
    pub package_name_override: BTreeMap<String, String>,
}

pub fn import_acs(
    service: &ExecutionService,
    snapshot_bytes: &[u8],
    workflow_id_prefix: Option<&str>,
    contract_import_mode: i32,
    excluded_stakeholders: &[String],
    synchronizer_id: &str,
    overrides: &ImportOverrides,
) -> Result<usize, AdminErr> {
    if contract_import_mode == 0 {
        return Err((
            3,
            "INVALID_ARGUMENT(8,00000000): contract_import_mode must be set".to_string(),
        ));
    }
    if synchronizer_id.trim().is_empty() {
        return Err((
            3,
            "INVALID_ARGUMENT(8,00000000): synchronizer_id must be set for ImportAcs".to_string(),
        ));
    }
    let excluded: BTreeSet<&str> = excluded_stakeholders.iter().map(String::as_str).collect();
    let mut slice = snapshot_bytes;
    let mut records = Vec::new();
    while !slice.is_empty() {
        let len = prost::decode_length_delimiter(&mut slice).map_err(|e| {
            (
                3,
                format!("INVALID_ARGUMENT: invalid ACS snapshot frame: {e}"),
            )
        })?;
        if slice.len() < len {
            return Err((
                3,
                "INVALID_ARGUMENT: truncated ACS snapshot frame".to_string(),
            ));
        }
        let frame = &slice[..len];
        slice = &slice[len..];
        let wrapper = p30::ActiveContract::decode(frame).map_err(|e| {
            (
                3,
                format!("INVALID_ARGUMENT: invalid ActiveContract proto: {e}"),
            )
        })?;
        let rec: ExportedContractRecord = serde_json::from_slice(&wrapper.active_contract)
            .map_err(|e| {
                (
                    3,
                    format!("INVALID_ARGUMENT: invalid exported contract payload: {e}"),
                )
            })?;
        records.push(rec);
    }

    records.retain(|rec| {
        let other_sync = !rec.synchronizer_id.is_empty()
            && rec.synchronizer_id != synchronizer_id
            && logical_sync(&rec.synchronizer_id) != logical_sync(synchronizer_id);
        let excluded_party = rec
            .signatories
            .iter()
            .chain(rec.observers.iter())
            .any(|p| excluded.contains(p.as_str()));
        !other_sync && !excluded_party
    });
    // [CANTON-NOTE: SEMANTICS] `ContractAuthenticationImportProcessor` authenticates every contract ("Failed to authenticate contract with
    // id: ...", `IMPORT_ACS_ERROR`) and the repair adds them to the synchronizer's active contract store, all or none (P-14).
    if let Some(committer) = service.committer.read().ok().and_then(|c| c.clone()) {
        let mut contracts = Vec::new();
        for rec in &records {
            let instance = crate::v2::unbase64(&rec.created_event_blob)
                .filter(|b| !b.is_empty())
                .ok_or_else(|| {
                    (
                        3,
                        format!(
                            "IMPORT_ACS_ERROR(8,00000000): Failed to authenticate contract with id: {}: the export carries no contract instance",
                            rec.contract_id
                        ),
                    )
                })?;
            contracts.push((rec.contract_id.clone(), instance));
        }
        if let Some(Err(e)) = committer.repair_add(&contracts) {
            return Err((3, format!("IMPORT_ACS_ERROR(8,00000000): {e}")));
        }
    }
    let packages = service
        .lf_packages
        .read()
        .map_err(|_| (13, "lf_packages lock poisoned".to_string()))?
        .clone();
    let mut imported_events = Vec::new();
    let mut node_idx = 0u64;
    let wf_prefix = workflow_id_prefix
        .filter(|s| !s.is_empty())
        .unwrap_or("import");

    for rec in records {
        if !rec.synchronizer_id.is_empty()
            && rec.synchronizer_id != synchronizer_id
            && logical_sync(&rec.synchronizer_id) != logical_sync(synchronizer_id)
        {
            continue;
        }
        if rec
            .signatories
            .iter()
            .chain(rec.observers.iter())
            .any(|p| excluded.contains(p.as_str()))
        {
            continue;
        }
        let mut pkg_id = overrides
            .contract_override
            .get(&rec.contract_id)
            .or_else(|| overrides.package_id_override.get(&rec.package_id))
            .cloned()
            .unwrap_or_else(|| rec.package_id.clone());
        if !overrides.package_name_override.is_empty() {
            if let Some(pkg_name) = service.v2_package_name(&pkg_id) {
                if let Some(ov) = overrides.package_name_override.get(&pkg_name) {
                    pkg_id = ov.clone();
                }
            }
        }
        let template_id = TemplateId {
            package_id: pkg_id.clone(),
            module_name: rec.module_name.clone(),
            entity_name: rec.entity_name.clone(),
        };
        let payload_value = lf_eval::Value::Record {
            tycon: Some(format!("{}:{}", rec.module_name, rec.entity_name)),
            fields: rec
                .json_payload
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), json_to_approx_lf(v)))
                        .collect()
                })
                .unwrap_or_default(),
        };
        // If package metadata defines proper typed conversion, prefer it cleanly
        let typed_payload = packages
            .iter()
            .find(|p| p.main_package_id == pkg_id || p.world.has_package(&pkg_id))
            .and_then(|p| {
                let types = lf_eval::typed_json::Types::new(&p.world);
                let local = format!("{}:{}", rec.module_name, rec.entity_name);
                let ty = types.template(&pkg_id, &local).ok()?;
                types.decode(&ty, &rec.json_payload).ok()
            })
            .unwrap_or(payload_value);

        let g_contract = GenericContract {
            contract_id: rec.contract_id.clone(),
            package_id: pkg_id,
            template_id: template_id.clone(),
            payload_value: typed_payload,
            json_payload: rec.json_payload.clone(),
            signatories: rec.signatories.clone(),
            observers: rec.observers.clone(),
            witness_parties: if rec.witness_parties.is_empty() {
                rec.signatories
                    .iter()
                    .chain(rec.observers.iter())
                    .cloned()
                    .collect()
            } else {
                rec.witness_parties.clone()
            },
            active: true,
            key_value: None,
            created_at_micros: rec.created_at_micros,
            created_event_blob: rec.created_event_blob.clone(),
            contract_key_hash: rec.contract_key_hash.clone(),
            key_maintainers: rec.key_maintainers.clone(),
            creation_seq: service.next_creation_seq(),
        };
        let mut stakeholders = BTreeSet::new();
        stakeholders.extend(rec.signatories.iter().cloned());
        stakeholders.extend(rec.observers.iter().cloned());
        if let Ok(mut g) = service.generic_contracts.write() {
            g.insert(rec.contract_id.clone(), g_contract.clone());
        }
        if let Ok(mut st) = service.active_state.write() {
            st.active_contracts.insert(
                ContractId(rec.contract_id.clone()),
                lf_eval::tx_model::ActiveContract {
                    template_id: template_id.to_string(),
                    payload: serde_json::to_vec(&rec.json_payload).unwrap_or_default(),
                    stakeholders: stakeholders.into_iter().collect(),
                    key: None,
                },
            );
        }
        service.v2_state().note_location(
            &rec.contract_id,
            synchronizer_id.to_string(),
            rec.reassignment_counter,
        );
        imported_events.push(Ev {
            node: node_idx,
            created: true,
            contract: g_contract,
            exercise: None,
        });
        node_idx += 1;
    }

    if imported_events.is_empty() {
        return Ok(0);
    }
    let count = imported_events.len();
    let _publish_guard = service
        .v2_state()
        .commit_publish_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let offset = service.v2_state().ledger_end.load(Ordering::SeqCst) + 1;
    let now = crate::clock::now_micros();
    {
        let mut offs = service
            .v2_state()
            .created_offsets
            .lock()
            .map_err(|_| (13, "created_offsets lock poisoned".to_string()))?;
        for ev in &imported_events {
            offs.insert(ev.contract.contract_id.clone(), (offset, ev.node));
        }
    }
    let update = StoredUpdate {
        update_id: format!("import-{wf_prefix}-{offset}"),
        offset,
        command_id: format!("{wf_prefix}-{offset}"),
        effective_at: rfc3339_from_micros(now),
        events: imported_events,
        at_micros: now,
        external_transaction_hash: None,
        reassignment: None,
        topology: None,
        official: None,
        trace_parent: None,
        act_as: Vec::new(),
    };
    service.v2_state().record_update(update);
    service
        .v2_state()
        .ledger_end
        .store(offset, Ordering::SeqCst);
    drop(_publish_guard);
    Ok(count)
}

fn json_to_approx_lf(v: &Json) -> lf_eval::Value {
    match v {
        Json::Bool(b) => lf_eval::Value::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                lf_eval::Value::Int64(i)
            } else {
                lf_eval::Value::Text(n.to_string())
            }
        }
        Json::String(s) => lf_eval::Value::Text(s.clone()),
        Json::Array(arr) => lf_eval::Value::List(arr.iter().map(json_to_approx_lf).collect()),
        Json::Object(obj) => lf_eval::Value::Record {
            tycon: None,
            fields: obj
                .iter()
                .map(|(k, x)| (k.clone(), json_to_approx_lf(x)))
                .collect(),
        },
        Json::Null => lf_eval::Value::Optional(None),
    }
}

pub fn change_assignation(
    service: &ExecutionService,
    source_alias: &str,
    target_alias: &str,
    skip_inactive: bool,
    contracts: &[(String, Option<i64>)],
) -> Result<(), AdminErr> {
    let (_, src_id) = get_sync_id(service, source_alias)?;
    let (_, tgt_id) = get_sync_id(service, target_alias)?;
    let g = service
        .generic_contracts
        .read()
        .map_err(|_| (13, "generic_contracts lock poisoned".to_string()))?;
    for (cid, counter_override) in contracts {
        let active = g.get(cid).is_some_and(|c| c.active);
        if !active {
            if skip_inactive {
                continue;
            }
            return Err((
                5,
                format!(
                    "CONTRACT_NOT_FOUND(11,00000000): Contract {cid} is not active on source synchronizer {src_id}"
                ),
            ));
        }
        let next_counter =
            counter_override.unwrap_or_else(|| service.v2_state().reassignment_counter_of(cid) + 1);
        service
            .v2_state()
            .note_location(cid, tgt_id.clone(), next_counter);
    }
    Ok(())
}

pub fn ignore_events(
    service: &ExecutionService,
    physical_sync_id: &str,
    from: i64,
    to: i64,
) -> Result<(), AdminErr> {
    if from > to {
        return Err((
            3,
            format!("INVALID_ARGUMENT(8,00000000): from_inclusive ({from}) > to_inclusive ({to})"),
        ));
    }
    service
        .v2_state()
        .ignored_events
        .lock()
        .map_err(|_| (13, "ignored_events lock poisoned".to_string()))?
        .push((physical_sync_id.to_string(), from, to));
    Ok(())
}

pub fn unignore_events(
    service: &ExecutionService,
    physical_sync_id: &str,
    from: i64,
    to: i64,
) -> Result<(), AdminErr> {
    if from > to {
        return Err((
            3,
            format!("INVALID_ARGUMENT(8,00000000): from_inclusive ({from}) > to_inclusive ({to})"),
        ));
    }
    service
        .v2_state()
        .ignored_events
        .lock()
        .map_err(|_| (13, "ignored_events lock poisoned".to_string()))?
        .retain(|(sid, f, t)| !(sid == physical_sync_id && *f >= from && *t <= to));
    Ok(())
}

pub fn rollback_unassignment(
    service: &ExecutionService,
    reassignment_id: &str,
    source_synchronizer_id: &str,
    target_synchronizer_id: &str,
) -> Result<(), AdminErr> {
    let mut cleared = false;
    let matching: Vec<String> = service
        .v2_active_contracts()
        .into_iter()
        .map(|c| c.contract_id)
        .collect();
    for cid in &matching {
        if service.v2_state().clear_in_flight(cid) {
            let next = service.v2_state().reassignment_counter_of(cid) + 1;
            service
                .v2_state()
                .note_location(cid, source_synchronizer_id.to_string(), next);
            cleared = true;
        }
    }
    service
        .v2_state()
        .pending_repair_ops
        .lock()
        .map_err(|_| (13, "pending_repair_ops lock poisoned".to_string()))?
        .retain(|o| {
            !(o.synchronizer_id == target_synchronizer_id && o.operation_id == reassignment_id)
        });
    let _ = cleared;
    Ok(())
}

pub fn list_pending_ops(
    service: &ExecutionService,
    sync_filter: &str,
    op_id_filter: &str,
) -> Vec<PendingRepairOp> {
    service
        .v2_state()
        .pending_repair_ops
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|o| {
            (sync_filter.is_empty() || o.synchronizer_id == sync_filter)
                && (op_id_filter.is_empty() || o.operation_id == op_id_filter)
        })
        .cloned()
        .collect()
}

pub fn delete_pending_op(service: &ExecutionService, sync_id: &str, op_id: &str) {
    service
        .v2_state()
        .pending_repair_ops
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|o| !(o.synchronizer_id == sync_id && o.operation_id == op_id));
}
