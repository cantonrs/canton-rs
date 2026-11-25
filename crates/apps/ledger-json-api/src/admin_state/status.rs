use std::sync::atomic::Ordering;

use serde_json::{json, Value as Json};

use super::connectivity::list_registered_syncs;
use super::AdminErr;
use crate::service::ExecutionService;

pub fn set_log_level(service: &ExecutionService, level: &str) -> Result<(), AdminErr> {
    let upper = level.trim().to_ascii_uppercase();
    if !matches!(
        upper.as_str(),
        "TRACE" | "DEBUG" | "INFO" | "WARN" | "WARNING" | "ERROR" | "OFF"
    ) {
        return Err((
            3,
            format!("INVALID_ARGUMENT(8,00000000): Unsupported log level '{level}'"),
        ));
    }
    *service
        .v2_state()
        .admin_log_level
        .lock()
        .map_err(|_| (13, "admin_log_level lock poisoned".to_string()))? = upper;
    Ok(())
}

pub fn log_level(service: &ExecutionService) -> String {
    service
        .v2_state()
        .admin_log_level
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

pub fn health_dump_json(service: &ExecutionService) -> Vec<u8> {
    let uid = service.participant_id();
    let ledger_end = service.v2_state().ledger_end.load(Ordering::SeqCst);
    let parties_count = service
        .v2_state()
        .parties
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    let pkgs_count = service.package_ids().len();
    let active_contracts = service.v2_active_contracts().len();
    let registered_syncs: Vec<Json> = list_registered_syncs(service)
        .into_iter()
        .map(|s| {
            json!({
                "alias": s.alias,
                "synchronizerId": s.synchronizer_id,
                "physicalSynchronizerId": s.physical_synchronizer_id,
                "connected": s.connected,
                "endpoints": s.sequencer_endpoints,
            })
        })
        .collect();
    serde_json::to_vec_pretty(&json!({
        "participant": uid,
        "version": "3.7.2",
        "logLevel": log_level(service),
        "ledgerEnd": ledger_end,
        "partiesCount": parties_count,
        "packagesCount": pkgs_count,
        "activeContractsCount": active_contracts,
        "ports": service.admin_ports(),
        "synchronizers": registered_syncs,
    }))
    .unwrap_or_default()
}
