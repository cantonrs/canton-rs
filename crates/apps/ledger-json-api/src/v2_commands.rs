//! JSON Ledger API v2 DAR upload, command submission and active contracts (S-API-002).
//!
//! Shapes and error codes were recorded from a real Canton 3.7.2 sandbox (`tests/oracle/json-api`, requests `q01`..`q19`).
//! The execution itself is the crate's existing generic path (`json_create`, `json_exercise` on the DAR-loaded `lf-eval`
//! engine); this module translates the v2 request into it and the result back into Canton's JSON.
//! [CANTON-NOTE: LIMITATION] One command per submission; the transaction shape is Canton's default (`ACS_DELTA`: archived
//! and created events, no exercised events) unless a `transactionFormat` asks for `LEDGER_EFFECTS`. Events carry `offset` and node ids of this
//! ledger, and `witnessParties` are the stakeholders that acted. Parties are not checked against the allocated ones.
use std::sync::atomic::Ordering;

use crate::service::ExecutionService;

pub(crate) const SYNCHRONIZER: &str =
    "mysync::12207ba0509c855abfc0146fafb1d6c69262551e9cb13bdaf5f0f53dfc9b436eca89";

mod acs;
mod blobs;
mod errors;
mod events;
mod execute;
mod proto_values;

pub(crate) use acs::{
    acs_entries_filtered, all_update_parties, expand_event_format_filters, transaction_format,
    transaction_tree_json,
};
pub use acs::{active_contracts, submit_tree};
pub use blobs::value_json;
pub(crate) use blobs::{blob_for, created_event, enter_want_blob, enter_want_blob_for};
#[cfg(feature = "protocol")]
pub(crate) use errors::shorten_id;
pub(crate) use errors::{
    bad_body, canton_error, map_error, now_rfc3339, refusal_status_details, rfc3339_from_micros,
    update_id, Kind,
};
#[cfg(feature = "protocol")]
pub(crate) use events::OfficialMeta;
pub(crate) use events::{
    archived_event, events_json, finish_with_hash, record_rejected_completion,
    transaction_json_for, StoredUpdate,
};
pub(crate) use execute::{
    acs_delta_events, dry_run_prepare_commands, encode_choice_values, Ev, ExInfo, Shape,
};
pub use execute::{submit, submit_async};
pub use proto_values::with_proto_values;

/// Loads an uploaded DAR into the service (through a temporary file: the loader reads paths).
pub(crate) fn load_dar_bytes(
    service: &ExecutionService,
    bytes: &[u8],
) -> Result<crate::service::DarPackageInfo, String> {
    let path = std::env::temp_dir().join(format!(
        "v2-upload-{}-{}.dar",
        std::process::id(),
        update_counter()
    ));
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    let result = service.load_dar(&path).map_err(|e| e.to_string());
    let _ = std::fs::remove_file(&path);
    result
}

pub(crate) fn unix_micros_now() -> i64 {
    crate::clock::now_micros()
}

pub(crate) fn update_counter() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    N.fetch_add(1, Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::value_json;
    use lf_eval::Value;
    use serde_json::json;

    #[test]
    fn value_json_keeps_non_trailing_nones_and_drops_trailing() {
        let rec = Value::Record {
            tycon: None,
            fields: vec![
                ("owner".into(), Value::Party("Alice".into())),
                ("provider".into(), Value::Optional(None)),
                ("id".into(), Value::Text("".into())),
                ("note".into(), Value::Optional(None)),
            ],
        };
        assert_eq!(
            value_json(&rec),
            json!({
                "owner": "Alice",
                "provider": null,
                "id": "",
            })
        );
    }
}
