//! `ParticipantInspectionService` and `ParticipantRepairService` gRPC handlers
//! (including server-streaming `ExportAcs` and client-streaming `ImportAcs`).

use std::collections::BTreeMap;

use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
use canton_proto::com::digitalasset::canton::topology::admin::v30 as t30;
use ledger_json_api::{
    admin_state::{
        change_assignation, count_in_flight, delete_pending_op, export_acs,
        get_slow_counter_configs, ignore_events, import_acs, list_pending_ops,
        lookup_offset_by_time, purge_contracts, rollback_unassignment, set_slow_counter_configs,
        unignore_events, ImportOverrides,
    },
    v2::SlowCounterConfig,
    ExecutionService,
};
use prost_reflect::{DynamicMessage, MethodDescriptor};
use tonic::Status;

use super::{decode_typed, encode_typed, map_admin_err};

fn sync_id_of(sync: Option<&t30::Synchronizer>) -> String {
    match sync.and_then(|s| s.kind.as_ref()) {
        Some(t30::synchronizer::Kind::Id(id)) => id.clone(),
        Some(t30::synchronizer::Kind::PhysicalId(pid)) => pid.clone(),
        None => String::new(),
    }
}

/// Dispatches unary `ParticipantInspectionService` and `ParticipantRepairService` RPCs.
pub fn handle_repair_method(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    match (method.parent_service().full_name(), method.name()) {
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantInspectionService",
            "LookupOffsetByTime",
        ) => Some((|| {
            let req: p30::LookupOffsetByTimeRequest = decode_typed(request)?;
            let Some(ts) = req.timestamp else {
                return Err(Status::invalid_argument("Timestamp not specified"));
            };
            let target_micros = ts
                .seconds
                .saturating_mul(1_000_000)
                .saturating_add(i64::from(ts.nanos) / 1_000);
            let offset = lookup_offset_by_time(ledger, target_micros);
            Ok(vec![encode_typed(
                method,
                &p30::LookupOffsetByTimeResponse { offset },
            )?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantInspectionService",
            "CountInFlight",
        ) => Some((|| {
            let _req: p30::CountInFlightRequest = decode_typed(request)?;
            let (subs, txs) = count_in_flight(ledger);
            Ok(vec![encode_typed(
                method,
                &p30::CountInFlightResponse {
                    pending_submissions: u32::try_from(subs).unwrap_or(u32::MAX),
                    pending_transactions: u32::try_from(txs).unwrap_or(u32::MAX),
                },
            )?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantInspectionService",
            "LookupSentAcsCommitments",
        ) => Some((|| {
            let req: p30::LookupSentAcsCommitmentsRequest = decode_typed(request)?;
            let syncs: Vec<String> = if req.time_ranges.is_empty() {
                ledger
                    .connected_synchronizers()
                    .into_iter()
                    .map(|(_, id)| id)
                    .collect()
            } else {
                req.time_ranges
                    .into_iter()
                    .map(|tr| tr.synchronizer_id)
                    .collect()
            };
            let sent = syncs
                .into_iter()
                .map(|synchronizer_id| p30::SentAcsCommitmentPerSynchronizer {
                    synchronizer_id,
                    sent: Vec::new(),
                })
                .collect();
            Ok(vec![encode_typed(
                method,
                &p30::LookupSentAcsCommitmentsResponse { sent },
            )?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantInspectionService",
            "LookupReceivedAcsCommitments",
        ) => Some((|| {
            let req: p30::LookupReceivedAcsCommitmentsRequest = decode_typed(request)?;
            let syncs: Vec<String> = if req.time_ranges.is_empty() {
                ledger
                    .connected_synchronizers()
                    .into_iter()
                    .map(|(_, id)| id)
                    .collect()
            } else {
                req.time_ranges
                    .into_iter()
                    .map(|tr| tr.synchronizer_id)
                    .collect()
            };
            let received = syncs
                .into_iter()
                .map(
                    |synchronizer_id| p30::ReceivedAcsCommitmentPerSynchronizer {
                        synchronizer_id,
                        received: Vec::new(),
                    },
                )
                .collect();
            Ok(vec![encode_typed(
                method,
                &p30::LookupReceivedAcsCommitmentsResponse { received },
            )?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantInspectionService",
            "SetConfigForSlowCounterParticipants",
        ) => Some((|| {
            let req: p30::SetConfigForSlowCounterParticipantsRequest = decode_typed(request)?;
            let configs = req
                .configs
                .into_iter()
                .map(|c| SlowCounterConfig {
                    synchronizer_ids: c.synchronizer_ids,
                    distinguished_participant_uids: c.distinguished_participant_uids,
                    threshold_distinguished: c.threshold_distinguished,
                    threshold_default: c.threshold_default,
                    participant_uids_metrics: c.participant_uids_metrics,
                })
                .collect();
            set_slow_counter_configs(ledger, configs).map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::SetConfigForSlowCounterParticipantsResponse {},
            )?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantInspectionService",
            "GetConfigForSlowCounterParticipants",
        ) => Some((|| {
            let req: p30::GetConfigForSlowCounterParticipantsRequest = decode_typed(request)?;
            let configs = get_slow_counter_configs(ledger, &req.synchronizer_ids)
                .into_iter()
                .map(|c| p30::SlowCounterParticipantSynchronizerConfig {
                    synchronizer_ids: c.synchronizer_ids,
                    distinguished_participant_uids: c.distinguished_participant_uids,
                    threshold_distinguished: c.threshold_distinguished,
                    threshold_default: c.threshold_default,
                    participant_uids_metrics: c.participant_uids_metrics,
                })
                .collect();
            Ok(vec![encode_typed(
                method,
                &p30::GetConfigForSlowCounterParticipantsResponse { configs },
            )?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantInspectionService",
            "GetIntervalsBehindForCounterParticipants",
        ) => Some((|| {
            let _req: p30::GetIntervalsBehindForCounterParticipantsRequest = decode_typed(request)?;
            Ok(vec![encode_typed(
                method,
                &p30::GetIntervalsBehindForCounterParticipantsResponse {
                    intervals_behind: Vec::new(),
                },
            )?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService",
            "PurgeContracts",
        ) => Some((|| {
            let req: p30::PurgeContractsRequest = decode_typed(request)?;
            purge_contracts(
                ledger,
                &req.synchronizer_alias,
                &req.contract_ids,
                req.ignore_already_purged,
            )
            .map_err(map_admin_err)?;
            Ok(vec![encode_typed(method, &p30::PurgeContractsResponse {})?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService",
            "ChangeAssignation",
        ) => Some((|| {
            let req: p30::ChangeAssignationRequest = decode_typed(request)?;
            let contracts: Vec<(String, Option<i64>)> = req
                .contracts
                .into_iter()
                .map(|c| (c.id, c.reassignment_counter_override))
                .collect();
            change_assignation(
                ledger,
                &req.source_synchronizer_alias,
                &req.target_synchronizer_alias,
                req.skip_inactive,
                &contracts,
            )
            .map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::ChangeAssignationResponse {},
            )?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService",
            "IgnoreEvents",
        ) => Some((|| {
            let req: p30::IgnoreEventsRequest = decode_typed(request)?;
            ignore_events(
                ledger,
                &req.physical_synchronizer_id,
                req.from_inclusive,
                req.to_inclusive,
            )
            .map_err(map_admin_err)?;
            Ok(vec![encode_typed(method, &p30::IgnoreEventsResponse {})?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService",
            "UnignoreEvents",
        ) => Some((|| {
            let req: p30::UnignoreEventsRequest = decode_typed(request)?;
            unignore_events(
                ledger,
                &req.physical_synchronizer_id,
                req.from_inclusive,
                req.to_inclusive,
            )
            .map_err(map_admin_err)?;
            Ok(vec![encode_typed(method, &p30::UnignoreEventsResponse {})?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService",
            "RollbackUnassignment",
        ) => Some((|| {
            let req: p30::RollbackUnassignmentRequest = decode_typed(request)?;
            rollback_unassignment(
                ledger,
                &req.reassignment_id,
                &req.source_synchronizer_id,
                &req.target_synchronizer_id,
            )
            .map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::RollbackUnassignmentResponse {},
            )?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService",
            "ListPendingOperations",
        ) => Some((|| {
            let req: p30::ListPendingOperationsRequest = decode_typed(request)?;
            let sync_filter = sync_id_of(req.filter_synchronizer.as_ref());
            let key_filter = req.filter_operation_key.unwrap_or_default();
            let pending_operations = list_pending_ops(ledger, &sync_filter, &key_filter)
                .into_iter()
                .filter(|o| req.operation_name.as_deref().is_none_or(|n| o.name == n))
                .map(|o| p30::PendingOperationMetadata {
                    operation_name: o.name,
                    operation_key: o.operation_id,
                    synchronizer: Some(t30::Synchronizer {
                        kind: Some(t30::synchronizer::Kind::PhysicalId(o.synchronizer_id)),
                    }),
                })
                .collect();
            Ok(vec![encode_typed(
                method,
                &p30::ListPendingOperationsResponse { pending_operations },
            )?])
        })()),
        (
            "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService",
            "DeletePendingOperation",
        ) => Some((|| {
            let req: p30::DeletePendingOperationRequest = decode_typed(request)?;
            let sync_id = sync_id_of(req.synchronizer.as_ref());
            delete_pending_op(ledger, &sync_id, &req.operation_key);
            Ok(vec![encode_typed(
                method,
                &p30::DeletePendingOperationResponse {},
            )?])
        })()),
        _ => None,
    }
}

/// Dispatches server-streaming `ParticipantRepairService` RPCs (`ExportAcs`).
pub fn handle_repair_server_streaming(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    if method.name() != "ExportAcs" {
        return None;
    }
    Some((|| {
        let req: p30::ExportAcsRequest = decode_typed(request)?;
        let renames: BTreeMap<String, String> = req
            .contract_synchronizer_renames
            .into_iter()
            .map(|(k, v)| (k, v.target_synchronizer_id))
            .collect();
        let bytes = export_acs(
            ledger,
            &req.party_ids,
            &req.synchronizer_id,
            req.ledger_offset,
            &renames,
            &req.excluded_stakeholder_ids,
        )
        .map_err(map_admin_err)?;
        if bytes.is_empty() {
            return Ok(vec![encode_typed(
                method,
                &p30::ExportAcsResponse { chunk: Vec::new() },
            )?]);
        }
        let mut out = Vec::new();
        for chunk in bytes.chunks(65_536) {
            out.push(encode_typed(
                method,
                &p30::ExportAcsResponse {
                    chunk: chunk.to_vec(),
                },
            )?);
        }
        Ok(out)
    })())
}

/// Dispatches client-streaming `ParticipantRepairService` RPCs (`ImportAcs`).
pub fn handle_repair_client_streaming(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    requests: Vec<DynamicMessage>,
) -> Option<Result<DynamicMessage, Status>> {
    if method.name() != "ImportAcs" {
        return None;
    }
    Some((|| {
        if requests.is_empty() {
            return Err(Status::invalid_argument(
                "ImportAcs stream must contain at least one request message",
            ));
        }
        let first: p30::ImportAcsRequest = decode_typed(&requests[0])?;
        let mut snapshot = first.acs_snapshot;
        for msg in requests.into_iter().skip(1) {
            let chunk_req: p30::ImportAcsRequest = decode_typed(&msg)?;
            snapshot.extend_from_slice(&chunk_req.acs_snapshot);
        }
        let overrides = match first.representative_package_id_override {
            Some(ov) => ImportOverrides {
                contract_override: ov.contract_override.into_iter().collect(),
                package_id_override: ov.package_id_override.into_iter().collect(),
                package_name_override: ov.package_name_override.into_iter().collect(),
            },
            None => ImportOverrides::default(),
        };
        import_acs(
            ledger,
            &snapshot,
            first.workflow_id_prefix.as_deref(),
            first.contract_import_mode.unwrap_or(0),
            &first.excluded_stakeholder_ids,
            first.synchronizer_id.as_deref().unwrap_or(""),
            &overrides,
        )
        .map_err(map_admin_err)?;
        encode_typed(method, &p30::ImportAcsResponse {})
    })())
}
