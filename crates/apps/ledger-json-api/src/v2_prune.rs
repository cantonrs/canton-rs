//! Participant pruning (S-STORE-007, U-17): what `p1.pruning.prune(offset)` answers on Canton 3.7.2 Community, and the errors
//! that reads below the pruned offset give.
//!
//! [CANTON-NOTE: SEMANTICS] Measured against the node (tests/oracle/prune, `scripts/verify-prune.sh`; Community 3.7.2 with a
//! maximum deduplication duration of 10 s):
//! - `prune(0)` is `INVALID_ARGUMENT`; an offset at or after the ledger end is `OFFSET_OUT_OF_RANGE` (checked first, also on a
//!   young ledger); an offset not older than the deduplication window is `UNSAFE_TO_PRUNE` (HTTP-side `FAILED_PRECONDITION`);
//!   an offset at or below the one pruned already succeeds and changes nothing.
//! - after a prune to P: `GET /v2/state/latest-pruned-offsets` reports P twice; an active-contract read at an offset below P, an
//!   update stream starting before P and a completion stream starting before P are `PARTICIPANT_PRUNED_DATA_ACCESSED`
//!   (HTTP 400, `earliest_offset` P); an update by offset or id at or below P is `UPDATE_NOT_FOUND`; the active-contract read at
//!   P itself works.
//!
//! [CANTON-NOTE: LIMITATION] The node's unsafe-to-prune reason also depends on its ACS commitment processing ("ACS digest
//! ingestion"): a protocol-backed service bounds pruning by its participant's latest reconciliation tick (the committer's
//! `safe_to_prune_micros`); without a participant only the deduplication window is modelled. The pruned
//! data is not deleted (reads refuse it); a prune in the middle of a transaction's offsets was not measured. The prune call
//! itself is the console's on the node; here it is the admin route `POST /v2/admin/prune {"pruneUpTo": N}`.
use std::sync::atomic::Ordering;

use serde_json::{json, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;

/// A refused read of pruned data: 400 `PARTICIPANT_PRUNED_DATA_ACCESSED` with the earliest readable offset in its context.
pub(crate) fn pruned_error(cause: String, pruned: u64, filters: Option<String>) -> HttpResponse {
    let mut context = json!({
        "category": "9",
        "definite_answer": "false",
        "earliest_offset": pruned.to_string(),
        "participant": "'rust'",
        "tid": "0000000000000000"
    });
    if let Some(f) = filters {
        context["filters"] = json!(f);
    }
    HttpResponse::json(
        400,
        &json!({
            "code": "PARTICIPANT_PRUNED_DATA_ACCESSED", "cause": cause, "correlationId": Json::Null,
            "traceId": "0000000000000000", "context": context, "resources": [],
            "errorCategory": 9, "grpcCodeValue": 9, "retryInfo": Json::Null, "definiteAnswer": Json::Null
        }),
    )
}

fn refused(code: &str, grpc_status: &str, grpc_code: u64, cause: String) -> HttpResponse {
    HttpResponse::json(
        400,
        &json!({ "code": code, "cause": cause, "grpcStatus": grpc_status, "grpcCodeValue": grpc_code }),
    )
}

/// Rejects `activeAtOffset` below the latest pruned offset with `PARTICIPANT_PRUNED_DATA_ACCESSED`.
pub(crate) fn check_active_at_not_pruned(
    service: &ExecutionService,
    at: u64,
    parties: &[String],
) -> Result<(), HttpResponse> {
    let pruned = service.v2_state().pruned_up_to.load(Ordering::SeqCst);
    if at < pruned {
        let filters_text = parties
            .iter()
            .map(|p| {
                format!("{p}: {{templates: [], interfaces: [], all-templates, created_event_blob: false}}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(pruned_error(
            format!("Active contracts request at offset {at} precedes pruned offset {pruned}"),
            pruned,
            Some(format!("{{{filters_text}}}")),
        ));
    }
    Ok(())
}

#[cfg(any(feature = "protocol", test))]
fn build_prune_safety_inputs(
    service: &ExecutionService,
    before_or_at_micros: Option<i64>,
    ledger_end: i64,
    ignore_commitments: bool,
) -> (
    canton_participant::official_prune::PruneSafetyInputs,
    Option<i64>,
) {
    let state = service.v2_state();
    let pruned_up_to = state.pruned_up_to.load(Ordering::SeqCst) as i64;
    let dedup_window = state.max_dedup_micros.load(Ordering::SeqCst).max(0);
    let mut ceiling = crate::clock::now_micros().saturating_sub(dedup_window);
    if let Some(before) = before_or_at_micros {
        ceiling = ceiling.min(before);
    }
    let updates = state.updates();
    let acs_digest_checkpoint = if ignore_commitments {
        ledger_end
    } else if let Some(safe_micros) = service.effective_acs_safe_to_prune_micros() {
        updates
            .iter()
            .filter(|u| u.at_micros <= safe_micros)
            .map(|u| u.offset as i64)
            .max()
            .unwrap_or(0)
    } else {
        ledger_end
    };
    let max_eligible_by_time = updates
        .iter()
        .filter(|u| u.offset > 0 && (u.offset as i64) < ledger_end && u.at_micros <= ceiling)
        .map(|u| u.offset as i64)
        .max();
    let first_offset_in_dedup_window = updates
        .iter()
        .filter(|u| u.at_micros > ceiling)
        .map(|u| u.offset as i64)
        .min();
    let inputs = canton_participant::official_prune::PruneSafetyInputs {
        ledger_end,
        pruned_up_to,
        acs_digest_checkpoint,
        commitment_matching_watermark: ledger_end,
        max_dedup_micros: Some(dedup_window),
        first_offset_in_dedup_window,
        migrating_synchronizer: None,
        missing_record_time_synchronizer: None,
        legacy_acs_reconciliation_first_unsafe: None,
        in_flight_submission_first_unsafe: None,
        synchronizer_index_crash_recovery_first_unsafe: None,
        request_journal_crash_recovery_first_unsafe: None,
        topology_crash_recovery_first_unsafe: None,
    };
    (inputs, max_eligible_by_time)
}

/// Computes the highest offset `< ledger_end` safe to prune at or before `before_or_at_micros` (`U-17`).
#[cfg(any(feature = "protocol", test))]
pub fn safe_pruning_offset(
    service: &ExecutionService,
    before_or_at_micros: Option<i64>,
    ledger_end: i64,
    ignore_commitments: bool,
) -> Result<Option<i64>, String> {
    if ledger_end < 0 {
        return Err("ledger_end must be non-negative".to_string());
    }
    if ledger_end <= 1 {
        return Ok(None);
    }
    let (mut inputs, max_eligible) =
        build_prune_safety_inputs(service, before_or_at_micros, ledger_end, ignore_commitments);
    let Some(max_eligible) = max_eligible else {
        return Ok(None);
    };
    if inputs.first_offset_in_dedup_window.is_none() {
        // Cap below non-update party-allocation offsets at the tail while letting commitment checks bind below it.
        inputs.ledger_end = inputs.ledger_end.min(max_eligible.saturating_add(1));
    }
    let bound = canton_participant::official_prune::highest_safe_prune_offset(&inputs);
    Ok(bound
        .map(|b| b.min(max_eligible))
        .filter(|b| *b > inputs.pruned_up_to))
}

/// Computes the highest offset `< ledger_end` safe to prune at or before `before_or_at_micros` (`U-17`).
#[cfg(not(any(feature = "protocol", test)))]
pub fn safe_pruning_offset(
    service: &ExecutionService,
    before_or_at_micros: Option<i64>,
    ledger_end: i64,
    ignore_commitments: bool,
) -> Result<Option<i64>, String> {
    if ledger_end < 0 {
        return Err("ledger_end must be non-negative".to_string());
    }
    if ledger_end <= 1 {
        return Ok(None);
    }
    let state = service.v2_state();
    let dedup_window = state.max_dedup_micros.load(Ordering::SeqCst).max(0);
    let mut ceiling = crate::clock::now_micros().saturating_sub(dedup_window);
    if let Some(before) = before_or_at_micros {
        ceiling = ceiling.min(before);
    }
    if !ignore_commitments {
        if let Some(acs_safe) = service.effective_acs_safe_to_prune_micros() {
            ceiling = ceiling.min(acs_safe);
        }
    }
    let end_u64 = ledger_end as u64;
    Ok(state
        .updates()
        .into_iter()
        .filter(|u| u.offset > 0 && u.offset < end_u64 && u.at_micros <= ceiling)
        .map(|u| u.offset as i64)
        .max())
}

/// `POST /v2/admin/prune` with `{"pruneUpTo": N}`: the participant console's `prune(N)`.
pub fn prune(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = serde_json::from_slice(&req.body).unwrap_or(Json::Null);
    let offset = body
        .get("pruneUpTo")
        .and_then(|o| o.as_u64().or_else(|| o.as_str()?.parse().ok()))
        .unwrap_or(0);
    let ignore_commitments = body
        .get("ignoreCommitments")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    let state = service.v2_state();
    let end = state.ledger_end.load(Ordering::SeqCst);
    #[cfg(any(feature = "protocol", test))]
    {
        use canton_participant::official_prune::{check_prune_safety, PruneRefusal, PruneVerdict};
        let (mut inputs, _) =
            build_prune_safety_inputs(service, None, end as i64, ignore_commitments);
        if crate::store::is_replaying() {
            inputs.acs_digest_checkpoint = inputs.ledger_end;
            inputs.commitment_matching_watermark = inputs.ledger_end;
            inputs.first_offset_in_dedup_window = None;
        }
        let prune_i64 = i64::try_from(offset).unwrap_or(i64::MAX);
        match check_prune_safety(prune_i64, &inputs) {
            Ok(PruneVerdict::AlreadyPruned) => {
                return HttpResponse::json(200, &json!({ "result": "ok" }));
            }
            Ok(PruneVerdict::Safe) => {}
            Err(PruneRefusal::InvalidArgument) => {
                return refused(
                    "INVALID_ARGUMENT",
                    "INVALID_ARGUMENT",
                    3,
                    "The submitted request has invalid arguments: prune_up_to not specified or zero".into(),
                );
            }
            Err(PruneRefusal::OffsetOutOfRange { .. }) => {
                return refused(
                    "OFFSET_OUT_OF_RANGE",
                    "FAILED_PRECONDITION",
                    9,
                    format!("prune_up_to needs to be before ledger end Some(Offset({end}))"),
                );
            }
            Err(PruneRefusal::Unsafe { cause, .. }) => {
                return refused(
                    "UNSAFE_TO_PRUNE",
                    "FAILED_PRECONDITION",
                    9,
                    format!("Participant cannot prune at specified offset due to {cause}"),
                );
            }
        }
    }
    #[cfg(not(any(feature = "protocol", test)))]
    {
        if offset == 0 {
            return refused(
                "INVALID_ARGUMENT",
                "INVALID_ARGUMENT",
                3,
                "The submitted request has invalid arguments: prune_up_to not specified or zero"
                    .into(),
            );
        }
        if offset >= end {
            return refused(
                "OFFSET_OUT_OF_RANGE",
                "FAILED_PRECONDITION",
                9,
                format!("prune_up_to needs to be before ledger end Some(Offset({end}))"),
            );
        }
        if offset <= state.pruned_up_to.load(Ordering::SeqCst) {
            return HttpResponse::json(200, &json!({ "result": "ok" }));
        }
        let window = state.max_dedup_micros.load(Ordering::SeqCst);
        let updates = state.updates();
        let newest = updates
            .iter()
            .filter(|u| u.offset <= offset)
            .map(|u| u.at_micros)
            .max();
        if !crate::store::is_replaying() {
            if !ignore_commitments {
                if let Some(safe_micros) = service.effective_acs_safe_to_prune_micros() {
                    if newest.is_none_or(|at| at > safe_micros) {
                        return refused(
                            "UNSAFE_TO_PRUNE",
                            "FAILED_PRECONDITION",
                            9,
                            "Participant cannot prune at specified offset due to ACS digest ingestion"
                                .into(),
                        );
                    }
                }
            }
            if newest.is_some_and(|at| crate::clock::now_micros() - at < window) {
                return refused(
                    "UNSAFE_TO_PRUNE",
                    "FAILED_PRECONDITION",
                    9,
                    format!(
                        "Participant cannot prune at specified offset due to max deduplication duration of {}s",
                        window / 1_000_000
                    ),
                );
            }
        }
    }
    if let Some(sink) = state
        .official_prune_sink
        .lock()
        .ok()
        .and_then(|s| s.clone())
    {
        if let Err(cause) = sink(offset) {
            return HttpResponse::json(
                500,
                &json!({ "code": "INTERNAL", "cause": cause, "grpcStatus": "INTERNAL", "grpcCodeValue": 13 }),
            );
        }
    }
    state.pruned_up_to.fetch_max(offset, Ordering::SeqCst);
    service.evict_pruned_up_to(offset);
    if let Some(sink) = state.journal_prune_sink.lock().ok().and_then(|s| s.clone()) {
        sink(state, offset);
    }
    HttpResponse::json(200, &json!({ "result": "ok" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::dispatch_request;
    use std::collections::HashMap;

    fn post_json(svc: &ExecutionService, path: &str, body: Json) -> (u16, Json) {
        let resp = dispatch_request(
            svc,
            &HttpRequest {
                method: "POST".into(),
                path: path.into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::to_vec(&body).unwrap(),
            },
        );
        let json = serde_json::from_slice(&resp.body).unwrap_or(Json::Null);
        (resp.status, json)
    }

    #[test]
    fn active_at_offset_symmetry_and_acs_commitment_gating() {
        let svc = ExecutionService::new();
        let dar_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        svc.load_dar(&dar_path).unwrap();
        let alice = post_json(
            &svc,
            "/v2/parties",
            json!({"partyIdHint":"alice","identityProviderId":""}),
        )
        .1["partyDetails"]["party"]
            .as_str()
            .unwrap()
            .to_string();
        for i in 1..=2 {
            let (st, b) = post_json(
                &svc,
                "/v2/commands/submit-and-wait",
                json!({
                    "commands": [{
                        "CreateCommand": {
                            "templateId": "#sample-contract:AssetHolding:AssetHolding",
                            "createArguments": {
                                "bank": alice, "owner": alice, "auditor": alice,
                                "assetSymbol": format!("USD{i}"), "amount": "5.0"
                            }
                        }
                    }],
                    "commandId": format!("c-{i}"),
                    "userId": "participant_admin",
                    "actAs": [alice]
                }),
            );
            assert_eq!(st, 200, "{b}");
        }
        let end = svc.v2_state().ledger_end.load(Ordering::SeqCst);
        let updates = svc.v2_state().updates();
        let first_offset = updates[0].offset;
        let first_at = updates[0].at_micros;

        // 1) POST /v2/state/active-contracts rejects activeAtOffset > ledger_end
        let (st, err) = post_json(
            &svc,
            "/v2/state/active-contracts",
            json!({
                "eventFormat": {
                    "filtersByParty": {
                        alice.clone(): { "cumulative": [{ "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": false } } } }] }
                    },
                    "verbose": true
                },
                "activeAtOffset": end + 100
            }),
        );
        assert_eq!(st, 400);
        assert_eq!(err["code"], "OFFSET_AFTER_LEDGER_END");

        // 2) ACS commitment gating blocks prune until safe_to_prune_micros passes the update time
        svc.set_max_dedup(std::time::Duration::from_secs(0));
        svc.set_acs_safe_to_prune_micros(Some(first_at - 1));
        let (st, err) = post_json(&svc, "/v2/admin/prune", json!({"pruneUpTo": first_offset}));
        assert_eq!(st, 400);
        assert_eq!(err["code"], "UNSAFE_TO_PRUNE");
        assert!(err["cause"]
            .as_str()
            .unwrap()
            .contains("ACS digest ingestion"));

        svc.set_acs_safe_to_prune_micros(Some(first_at));
        let (st, ok) = post_json(&svc, "/v2/admin/prune", json!({"pruneUpTo": first_offset}));
        assert_eq!(st, 200, "{ok}");

        // 3) POST /v2/state/active-contracts-page rejects activeAtOffset < pruned_up_to
        let (st, err) = post_json(
            &svc,
            "/v2/state/active-contracts-page",
            json!({
                "eventFormat": {
                    "filtersByParty": {
                        alice: { "cumulative": [{ "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": false } } } }] }
                    },
                    "verbose": true
                },
                "maxPageSize": 10,
                "activeAtOffset": first_offset - 1
            }),
        );
        assert_eq!(st, 400);
        assert_eq!(err["code"], "PARTICIPANT_PRUNED_DATA_ACCESSED");
    }

    #[test]
    fn physical_eviction_preserves_active_and_evicts_archived_across_incremental_prunes() {
        let svc = ExecutionService::new();
        let dar_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        svc.load_dar(&dar_path).unwrap();
        svc.set_max_dedup(std::time::Duration::from_secs(0));
        let alice = post_json(
            &svc,
            "/v2/parties",
            json!({"partyIdHint":"alice","identityProviderId":""}),
        )
        .1["partyDetails"]["party"]
            .as_str()
            .unwrap()
            .to_string();

        let create_holding = |sym: &str, cmd_id: &str| -> (String, u64) {
            let (st, b) = post_json(
                &svc,
                "/v2/commands/submit-and-wait-for-transaction",
                json!({
                    "commands": {
                        "commands": [{
                            "CreateCommand": {
                                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                                "createArguments": {
                                    "bank": alice, "owner": alice, "auditor": alice,
                                    "assetSymbol": sym, "amount": "5.0"
                                }
                            }
                        }],
                        "commandId": cmd_id,
                        "userId": "participant_admin",
                        "actAs": [alice]
                    }
                }),
            );
            assert_eq!(st, 200, "{b}");
            let tx = &b["transaction"];
            let cid = tx["events"][0]["CreatedEvent"]["contractId"]
                .as_str()
                .unwrap()
                .to_string();
            let off = tx["offset"].as_u64().unwrap();
            (cid, off)
        };
        let archive_holding = |cid: &str, cmd_id: &str| -> u64 {
            let (st, b) = post_json(
                &svc,
                "/v2/commands/submit-and-wait-for-transaction",
                json!({
                    "commands": {
                        "commands": [{
                            "ExerciseCommand": {
                                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                                "contractId": cid,
                                "choice": "Archive",
                                "choiceArgument": {}
                            }
                        }],
                        "commandId": cmd_id,
                        "userId": "participant_admin",
                        "actAs": [alice]
                    }
                }),
            );
            assert_eq!(st, 200, "{b}");
            b["transaction"]["offset"].as_u64().unwrap()
        };

        let (cid_old, _off_old_c) = create_holding("OLD", "c-old");
        let off_old_a = archive_holding(&cid_old, "a-old");
        let (cid_keep, off_keep_c) = create_holding("KEEP", "c-keep");
        let (cid_later, _off_later_c) = create_holding("LATER", "c-later");
        let off_later_a = archive_holding(&cid_later, "a-later");
        let (_cid_tail, _off_tail_c) = create_holding("TAIL", "c-tail");

        // Incremental step 1: prune at off_keep_c (after cid_old archived & cid_keep created, before cid_later archived)
        let (st, ok) = post_json(&svc, "/v2/admin/prune", json!({"pruneUpTo": off_keep_c}));
        assert_eq!(st, 200, "{ok}");

        assert!(
            svc.v2_contract(&cid_old).is_none(),
            "archived contract before prune must be physically evicted"
        );
        assert!(
            svc.v2_contract(&cid_keep).is_some(),
            "still-active contract created before prune must survive"
        );
        assert!(
            svc.v2_contract(&cid_later).is_some(),
            "contract archived after prune must survive for snapshot rewind"
        );
        assert!(svc
            .v2_state()
            .updates()
            .iter()
            .all(|u| u.offset > off_keep_c));
        assert!(svc
            .v2_state()
            .completions()
            .iter()
            .all(|c| c.offset > off_keep_c));
        assert!(svc
            .v2_state()
            .dedup
            .lock()
            .unwrap()
            .values()
            .all(|(off, _, _)| *off > off_keep_c));

        // Negative control: contract-by-id rejects evicted cid_old
        let (st_old, _) = post_json(
            &svc,
            "/v2/contracts/contract-by-id",
            json!({"contractId": cid_old, "queryingParties": [alice]}),
        );
        assert_eq!(st_old, 404);
        // Active contract remains readable via contract-by-id & active-contracts at pruned_up_to
        let (st_keep, _) = post_json(
            &svc,
            "/v2/contracts/contract-by-id",
            json!({"contractId": cid_keep, "queryingParties": [alice]}),
        );
        assert_eq!(st_keep, 200);
        let (st_acs, acs) = post_json(
            &svc,
            "/v2/state/active-contracts",
            json!({
                "eventFormat": {
                    "filtersByParty": {
                        alice.clone(): { "cumulative": [{ "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": false } } } }] }
                    },
                    "verbose": true
                },
                "activeAtOffset": off_keep_c
            }),
        );
        assert_eq!(st_acs, 200, "{acs}");
        let acs_cids: Vec<&str> = acs
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| {
                e["contractEntry"]["JsActiveContract"]["createdEvent"]["contractId"].as_str()
            })
            .collect();
        assert!(acs_cids.contains(&cid_keep.as_str()));
        assert!(!acs_cids.contains(&cid_old.as_str()));

        // Step 2: second incremental prune past off_later_a must also evict cid_later while keeping cid_keep
        assert!(off_old_a < off_keep_c);
        let (st2, ok2) = post_json(&svc, "/v2/admin/prune", json!({"pruneUpTo": off_later_a}));
        assert_eq!(st2, 200, "{ok2}");
        assert!(svc.v2_contract(&cid_later).is_none());
        assert!(svc.v2_contract(&cid_keep).is_some());
    }

    #[test]
    fn safe_pruning_offset_and_official_sink_failure_semantics() {
        let svc = ExecutionService::new();
        assert_eq!(
            safe_pruning_offset(&svc, None, -1, false).unwrap_err(),
            "ledger_end must be non-negative"
        );
        assert_eq!(safe_pruning_offset(&svc, None, 1, false).unwrap(), None);

        let dar_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        svc.load_dar(&dar_path).unwrap();
        let alice = post_json(
            &svc,
            "/v2/parties",
            json!({"partyIdHint":"alice","identityProviderId":""}),
        )
        .1["partyDetails"]["party"]
            .as_str()
            .unwrap()
            .to_string();
        for i in 1..=2 {
            let (st, b) = post_json(
                &svc,
                "/v2/commands/submit-and-wait",
                json!({
                    "commands": [{
                        "CreateCommand": {
                            "templateId": "#sample-contract:AssetHolding:AssetHolding",
                            "createArguments": {
                                "bank": alice, "owner": alice, "auditor": alice,
                                "assetSymbol": format!("EUR{i}"), "amount": "5.0"
                            }
                        }
                    }],
                    "commandId": format!("s-{i}"),
                    "userId": "participant_admin",
                    "actAs": [alice]
                }),
            );
            assert_eq!(st, 200, "{b}");
        }
        let updates = svc.v2_state().updates();
        let end = svc.v2_state().ledger_end.load(Ordering::SeqCst) as i64;
        let u0 = updates[0].offset as i64;
        let u0_at = updates[0].at_micros;

        // Default 168h dedup window blocks young updates
        assert_eq!(safe_pruning_offset(&svc, None, end, false).unwrap(), None);

        svc.set_max_dedup(std::time::Duration::from_secs(0));
        // Commitment gate blocks unless ignore_commitments is set
        svc.set_acs_safe_to_prune_micros(Some(u0_at - 1));
        assert_eq!(safe_pruning_offset(&svc, None, end, false).unwrap(), None);
        assert!(safe_pruning_offset(&svc, None, end, true).unwrap() >= Some(u0));
        // before_or_at strictly before first update also leaves None
        assert_eq!(
            safe_pruning_offset(&svc, Some(u0_at - 1), end, true).unwrap(),
            None
        );

        // Failing official_prune_sink aborts prune without advancing pruned_up_to
        if let Ok(mut sink) = svc.v2_state().official_prune_sink.lock() {
            *sink = Some(std::sync::Arc::new(|_| Err("simulated pg failure".into())));
        }
        let (st, err) = post_json(
            &svc,
            "/v2/admin/prune",
            json!({"pruneUpTo": u0, "ignoreCommitments": true}),
        );
        assert_eq!(st, 500, "{err}");
        assert_eq!(err["code"], "INTERNAL");
        assert_eq!(svc.v2_state().pruned_up_to.load(Ordering::SeqCst), 0);
    }
}
