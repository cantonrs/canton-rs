//! Participant Admin API backing helpers for `ledger-grpc-api`:
//! synchronizer lifecycle, inspection queries, ACS repair (`ExportAcs`/`ImportAcs`/`PurgeContracts`/
//! `ChangeAssignation`), topology read/write views, and status/log-level state.

mod connectivity;
mod repair;
mod status;
mod topology;

use crate::v2_commands::rfc3339_from_micros;
use crate::v2_updates::parse_micros;

pub use connectivity::{
    connect_sync, count_in_flight, disconnect_all_syncs, disconnect_sync, ensure_registered_syncs,
    get_slow_counter_configs, get_sync_id, list_connected_syncs, list_registered_syncs,
    lookup_offset_by_time, modify_sync, reconnect_all_syncs, reconnect_sync, register_sync,
    set_slow_counter_configs,
};
pub use repair::{
    change_assignation, delete_pending_op, export_acs, ignore_events, import_acs, list_pending_ops,
    purge_contracts, rollback_unassignment, unignore_events, ImportOverrides,
};
pub use status::{health_dump_json, log_level, set_log_level};
pub use topology::{
    add_topology_txs, add_topology_txs_in_store, authorize_party_to_participant,
    authorize_party_to_participant_in_store, authorize_party_to_participant_spec,
    authorize_vetted_packages, extra_topology_txs, import_topology_txs, topology_party_mappings,
    topology_party_mappings_in_store, topology_vetted_packages, PartyAuthorizeSpec,
};

pub type AdminErr = (i32, String);

/// Formats UTC microseconds since Unix epoch as RFC 3339 (`Z`).
pub fn format_rfc3339_micros(micros: i64) -> String {
    rfc3339_from_micros(micros)
}

/// Parses an RFC 3339 timestamp into UTC microseconds since Unix epoch.
pub fn parse_rfc3339_micros(s: &str) -> Option<i64> {
    parse_micros(s)
}

pub(super) fn logical_sync(id: &str) -> &str {
    match id.split_once("::") {
        Some((name, rest)) => match rest.split_once("::") {
            Some((fp, _)) => &id[..name.len() + 2 + fp.len()],
            None => id,
        },
        None => id,
    }
}
