use std::collections::BTreeSet;

use super::{logical_sync, AdminErr};
use crate::service::ExecutionService;
use crate::v2::{RegisteredSync, SlowCounterConfig};
use crate::v2_updates::parse_micros;

/// Ensures `v2.registered_syncs` is initialized from initial/configured connected synchronizers.
pub fn ensure_registered_syncs(service: &ExecutionService) {
    if service
        .v2_state()
        .registered_syncs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
    {
        return;
    }
    // Call `connected_synchronizers()` BEFORE acquiring the `registered_syncs` write lock to avoid self-deadlock.
    let initial = service.connected_synchronizers();
    let entries = initial
        .into_iter()
        .map(|(alias, sync_id)| RegisteredSync {
            alias,
            synchronizer_id: logical_sync(&sync_id).to_string(),
            physical_synchronizer_id: sync_id,
            sequencer_endpoints: Vec::new(),
            manual_connect: false,
            priority: 0,
            connected: true,
            handshake_only: false,
        })
        .collect();
    let mut guard = service
        .v2_state()
        .registered_syncs
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(entries);
    }
}

pub fn list_registered_syncs(service: &ExecutionService) -> Vec<RegisteredSync> {
    ensure_registered_syncs(service);
    service
        .v2_state()
        .registered_syncs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_default()
}

pub fn list_connected_syncs(service: &ExecutionService) -> Vec<RegisteredSync> {
    list_registered_syncs(service)
        .into_iter()
        .filter(|s| s.connected)
        .collect()
}

fn validate_sync_config(reg: &RegisteredSync) -> Result<(), AdminErr> {
    if reg.alias.trim().is_empty() {
        return Err((
            3,
            "INVALID_ARGUMENT(8,00000000): synchronizer_alias must not be empty".to_string(),
        ));
    }
    for ep in &reg.sequencer_endpoints {
        if !(ep.starts_with("http://") || ep.starts_with("https://")) {
            return Err((
                3,
                format!("INVALID_ARGUMENT(8,00000000): Invalid sequencer URL endpoint '{ep}'"),
            ));
        }
    }
    Ok(())
}

fn resolve_default_sync_id(service: &ExecutionService, alias: &str, physical: &str) -> String {
    if !physical.is_empty() {
        return physical.to_string();
    }
    let cur = service.v2_state().synchronizer_id();
    if alias == "mysync" || cur.starts_with(&format!("{alias}::")) {
        return cur;
    }
    let fp = cur
        .split_once("::")
        .map(|(_, r)| r)
        .unwrap_or("12204e24ac89d9fb4bb2b9a40aab08c20c660ccd3c0d257a5b49ef84d9b04016b25d::37-0");
    format!("{alias}::{fp}")
}

pub fn register_sync(
    service: &ExecutionService,
    mut reg: RegisteredSync,
    validate_endpoint: bool,
) -> Result<(), AdminErr> {
    validate_sync_config(&reg)?;
    if validate_endpoint && reg.sequencer_endpoints.is_empty() && reg.synchronizer_id.is_empty() {
        return Err((
            3,
            "SEQUENCER_CONNECTION_ERROR(8,00000000): Missing sequencer endpoints".to_string(),
        ));
    }
    ensure_registered_syncs(service);
    if reg.physical_synchronizer_id.is_empty() {
        reg.physical_synchronizer_id =
            resolve_default_sync_id(service, &reg.alias, &reg.physical_synchronizer_id);
    }
    if reg.synchronizer_id.is_empty() {
        reg.synchronizer_id = logical_sync(&reg.physical_synchronizer_id).to_string();
    }
    let mut guard = service
        .v2_state()
        .registered_syncs
        .lock()
        .map_err(|_| (13, "registered_syncs lock poisoned".to_string()))?;
    let list = guard.get_or_insert_with(Vec::new);
    if list.iter().any(|s| s.alias == reg.alias) {
        return Err((
            6,
            format!(
                "SYNCHRONIZER_ALREADY_REGISTERED(9,00000000): Synchronizer alias '{}' is already registered",
                reg.alias
            ),
        ));
    }
    list.push(reg);
    Ok(())
}

pub fn modify_sync(
    service: &ExecutionService,
    physical_filter: Option<&str>,
    updated: RegisteredSync,
) -> Result<(), AdminErr> {
    validate_sync_config(&updated)?;
    ensure_registered_syncs(service);
    let mut guard = service
        .v2_state()
        .registered_syncs
        .lock()
        .map_err(|_| (13, "registered_syncs lock poisoned".to_string()))?;
    let list = guard.get_or_insert_with(Vec::new);
    let pos = list
        .iter()
        .position(|s| match physical_filter.filter(|p| !p.is_empty()) {
            Some(pid) => s.physical_synchronizer_id == pid || s.synchronizer_id == pid,
            None => s.alias == updated.alias,
        })
        .ok_or_else(|| {
            (
                5,
                format!(
                    "SYNCHRONIZER_NOT_FOUND(11,00000000): Unknown synchronizer '{}'",
                    updated.alias
                ),
            )
        })?;
    let existing = &mut list[pos];
    existing.sequencer_endpoints = updated.sequencer_endpoints;
    existing.manual_connect = updated.manual_connect;
    existing.priority = updated.priority;
    if !updated.physical_synchronizer_id.is_empty() {
        existing.physical_synchronizer_id = updated.physical_synchronizer_id;
        existing.synchronizer_id = logical_sync(&existing.physical_synchronizer_id).to_string();
    }
    Ok(())
}

pub fn connect_sync(service: &ExecutionService, mut reg: RegisteredSync) -> Result<bool, AdminErr> {
    validate_sync_config(&reg)?;
    ensure_registered_syncs(service);
    if reg.physical_synchronizer_id.is_empty() {
        reg.physical_synchronizer_id =
            resolve_default_sync_id(service, &reg.alias, &reg.physical_synchronizer_id);
    }
    if reg.synchronizer_id.is_empty() {
        reg.synchronizer_id = logical_sync(&reg.physical_synchronizer_id).to_string();
    }
    reg.connected = true;
    reg.handshake_only = false;
    let mut guard = service
        .v2_state()
        .registered_syncs
        .lock()
        .map_err(|_| (13, "registered_syncs lock poisoned".to_string()))?;
    let list = guard.get_or_insert_with(Vec::new);
    if let Some(existing) = list.iter_mut().find(|s| s.alias == reg.alias) {
        existing.sequencer_endpoints = reg.sequencer_endpoints;
        existing.manual_connect = reg.manual_connect;
        existing.priority = reg.priority;
        existing.synchronizer_id = reg.synchronizer_id;
        existing.physical_synchronizer_id = reg.physical_synchronizer_id;
        existing.connected = true;
        existing.handshake_only = false;
    } else {
        list.push(reg);
    }
    Ok(true)
}

pub fn disconnect_sync(service: &ExecutionService, alias: &str) -> Result<(), AdminErr> {
    ensure_registered_syncs(service);
    let mut guard = service
        .v2_state()
        .registered_syncs
        .lock()
        .map_err(|_| (13, "registered_syncs lock poisoned".to_string()))?;
    let list = guard.get_or_insert_with(Vec::new);
    let Some(entry) = list.iter_mut().find(|s| s.alias == alias) else {
        return Err((
            5,
            format!("SYNCHRONIZER_NOT_FOUND(11,00000000): Unknown synchronizer alias '{alias}'"),
        ));
    };
    entry.connected = false;
    Ok(())
}

pub fn disconnect_all_syncs(service: &ExecutionService) -> Result<(), AdminErr> {
    ensure_registered_syncs(service);
    let mut guard = service
        .v2_state()
        .registered_syncs
        .lock()
        .map_err(|_| (13, "registered_syncs lock poisoned".to_string()))?;
    if let Some(list) = guard.as_mut() {
        for s in list {
            s.connected = false;
        }
    }
    Ok(())
}

pub fn reconnect_sync(service: &ExecutionService, alias: &str) -> Result<bool, AdminErr> {
    ensure_registered_syncs(service);
    let mut guard = service
        .v2_state()
        .registered_syncs
        .lock()
        .map_err(|_| (13, "registered_syncs lock poisoned".to_string()))?;
    let list = guard.get_or_insert_with(Vec::new);
    let Some(entry) = list.iter_mut().find(|s| s.alias == alias) else {
        return Err((
            5,
            format!("SYNCHRONIZER_NOT_FOUND(11,00000000): Unknown synchronizer alias '{alias}'"),
        ));
    };
    entry.connected = true;
    entry.handshake_only = false;
    Ok(true)
}

pub fn reconnect_all_syncs(
    service: &ExecutionService,
    _ignore_failures: bool,
) -> Result<(), AdminErr> {
    ensure_registered_syncs(service);
    let mut guard = service
        .v2_state()
        .registered_syncs
        .lock()
        .map_err(|_| (13, "registered_syncs lock poisoned".to_string()))?;
    if let Some(list) = guard.as_mut() {
        for s in list {
            if !s.manual_connect {
                s.connected = true;
                s.handshake_only = false;
            }
        }
    }
    Ok(())
}

pub fn get_sync_id(service: &ExecutionService, alias: &str) -> Result<(String, String), AdminErr> {
    ensure_registered_syncs(service);
    let list = list_registered_syncs(service);
    let Some(entry) = list.into_iter().find(|s| s.alias == alias) else {
        return Err((
            5,
            format!("SYNCHRONIZER_NOT_FOUND(11,00000000): Unknown synchronizer alias '{alias}'"),
        ));
    };
    Ok((entry.synchronizer_id, entry.physical_synchronizer_id))
}

pub fn lookup_offset_by_time(service: &ExecutionService, target_micros: i64) -> Option<i64> {
    let updates = service.v2_state().updates();
    updates
        .iter()
        .filter_map(|u| {
            let rec_micros = parse_micros(&u.effective_at).unwrap_or(u.at_micros);
            (rec_micros <= target_micros).then_some(u.offset as i64)
        })
        .max()
}

pub fn count_in_flight(service: &ExecutionService) -> (u64, u64) {
    let pending_txs = service.v2_state().in_flight_count() as u64;
    (0, pending_txs)
}

pub fn set_slow_counter_configs(
    service: &ExecutionService,
    configs: Vec<SlowCounterConfig>,
) -> Result<(), AdminErr> {
    let mut seen = BTreeSet::new();
    for cfg in &configs {
        for sid in &cfg.synchronizer_ids {
            if !seen.insert(sid.clone()) {
                return Err((
                    3,
                    format!(
                        "INVALID_ARGUMENT(8,00000000): synchronizerIds are not distinct: duplicate '{sid}'"
                    ),
                ));
            }
        }
    }
    let mut guard = service
        .v2_state()
        .slow_counter_configs
        .lock()
        .map_err(|_| (13, "slow_counter_configs lock poisoned".to_string()))?;
    *guard = configs;
    Ok(())
}

pub fn get_slow_counter_configs(
    service: &ExecutionService,
    filter_sync_ids: &[String],
) -> Vec<SlowCounterConfig> {
    let configs = service
        .v2_state()
        .slow_counter_configs
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    if filter_sync_ids.is_empty() {
        return configs;
    }
    configs
        .into_iter()
        .filter(|c| {
            c.synchronizer_ids
                .iter()
                .any(|sid| filter_sync_ids.contains(sid))
        })
        .collect()
}
