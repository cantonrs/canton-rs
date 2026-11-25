//! `POST /v2/commands/submit-and-wait-for-reassignment` and the reassignment updates (G7 B1, S-NET-040 part 8): a contract moves between the
//! synchronizers of the participant behind the service ([`crate::service::ProtocolCommitter::reassign`]).
//!
//! [CANTON-NOTE: SEMANTICS] Shapes recorded from the Canton 3.7.2 JSON API (`scripts/oracle-json-reassignment.sh`,
//! `tests/oracle/reassignment/json-api.jsonl`):
//! - The request is `{reassignmentCommands: {submitter, commandId, userId, commands: [{command: {UnassignCommand: {value: {contractId,
//!   source, target}}}} | {command: {AssignCommand: {value: {reassignmentId, source, target}}}}]}, eventFormat}`.
//! - The answer is `{reassignment: {updateId, commandId, workflowId, offset, events, recordTime, synchronizerId, traceContext,
//!   paidTrafficCost}}`; `synchronizerId` is the source of an unassignment and the target of an assignment.
//! - An unassigned event is `{JsUnassignedEvent: {value: {...}}}` with the contract, both synchronizers, the counter (already incremented),
//!   `assignmentExclusivity: null` (not enforced under protocol version 37), the submitter and the witnesses; an assigned event is
//!   `{JsAssignmentEvent: {createdEvent, reassignmentCounter, reassignmentId, source, target, submitter}}` - **without** a `value` wrapper.
//! - In the update stream a reassignment is `{update: {Reassignment: {value: <the same reassignment>}}}`; in the ACS a contract carries
//!   the synchronizer it is on and its counter, and a contract between an unassignment and its assignment is in no ACS.
//! - Unassigning a contract that is not active on the source is `INVALID_ARGUMENT` (400, category 8): "Cannot unassign contract
//!   `ContractId(<id>)` because it's not active. Current status ReassignedAway(<target>)" for a contract that moved away.
//!
//! [CANTON-NOTE: LIMITATION] One command per request; the reassignments of other participants are not shown; a reassignment update is shown
//! to the parties of the request's filter that are stakeholders, whatever the `updateFormat` asks for; a restarted service shows the contracts of every synchronizer's node with their synchronizer and counter
//! (`NodeCommitter::show_known_contracts_in`), but not the reassignment updates (U-44); `traceparent` is derived from the update id and `paidTrafficCost` is 0.
use crate::http::{HttpRequest, HttpResponse};
use crate::service::{ExecutionService, ReassignCommand, ReassignOutcome};
use crate::v2_commands::{canton_error, created_event, rfc3339_from_micros, update_id, Kind};
use serde_json::{json, Value as Json};
use std::collections::HashMap;
use std::sync::atomic::Ordering;

/// A reassignment as the update stream keeps it.
#[derive(Clone, Debug)]
pub(crate) struct StoredReassignment {
    pub(crate) unassign: bool,
    pub(crate) outcome: ReassignOutcome,
    pub(crate) submitter: String,
    pub(crate) witnesses: Vec<String>,
}

/// Where the contracts are: the synchronizer and counter of those a reassignment touched, and those between an unassignment and its
/// assignment.
#[derive(Default)]
pub(crate) struct ReassignState {
    located: HashMap<String, (String, i64)>,
    in_flight: HashMap<String, String>,
}

impl crate::v2::V2State {
    /// Records where a contract is when the service starts again (from the nodes that kept it): the synchronizer it is on and its
    /// reassignment counter. A restarted service has no reassignment in memory; the nodes do keep the contracts and the counters.
    /// Records a contract that was unassigned and not yet assigned when the service starts again: it is in no ACS until its assign.
    #[cfg_attr(
        not(feature = "protocol"),
        allow(dead_code, reason = "used by the protocol-mode committer")
    )]
    pub(crate) fn note_in_flight(&self, contract_id: &str, target: String) {
        if let Ok(mut r) = self.reassign.lock() {
            r.in_flight.insert(contract_id.to_string(), target);
        }
    }

    #[cfg_attr(
        not(feature = "protocol"),
        allow(dead_code, reason = "used by the protocol-mode committer")
    )]
    pub(crate) fn note_location(&self, contract_id: &str, synchronizer: String, counter: i64) {
        if let Ok(mut r) = self.reassign.lock() {
            r.located
                .insert(contract_id.to_string(), (synchronizer, counter));
        }
    }

    /// The synchronizer a contract is on and its counter (the service's own synchronizer and 0 for one no reassignment touched); `None`
    /// while it is between synchronizers.
    pub(crate) fn location_of(&self, contract_id: &str) -> Option<(String, i64)> {
        let r = self.reassign.lock().ok()?;
        if r.in_flight.contains_key(contract_id) {
            return None;
        }
        Some(
            r.located
                .get(contract_id)
                .cloned()
                .unwrap_or_else(|| (self.synchronizer_id(), 0)),
        )
    }

    pub(crate) fn in_flight_count(&self) -> usize {
        self.reassign.lock().map(|r| r.in_flight.len()).unwrap_or(0)
    }

    pub(crate) fn reassignment_counter_of(&self, contract_id: &str) -> i64 {
        self.reassign
            .lock()
            .ok()
            .and_then(|r| r.located.get(contract_id).map(|(_, c)| *c))
            .unwrap_or(0)
    }

    pub(crate) fn clear_in_flight(&self, contract_id: &str) -> bool {
        self.reassign
            .lock()
            .map(|mut r| r.in_flight.remove(contract_id).is_some())
            .unwrap_or(false)
    }
}

fn bad_request(cause: String) -> HttpResponse {
    canton_error(
        Kind::Ctx {
            submission: false,
            definite: true,
            field: None,
            retry: None,
        },
        400,
        "INVALID_ARGUMENT",
        format!("The submitted request has invalid arguments: {cause}"),
        8,
        3,
        json!([]),
    )
}

fn str_at<'a>(v: &'a Json, key: &str) -> &'a str {
    v.get(key).and_then(Json::as_str).unwrap_or("")
}

/// The event of a reassignment, as both the answer and the update stream write it.
fn event_json(service: &ExecutionService, r: &StoredReassignment, offset: u64) -> Option<Json> {
    let contract = service
        .generic_contracts
        .read()
        .ok()?
        .get(&r.outcome.contract_id)
        .cloned()?;
    let created = created_event(service, &contract, offset, 0, &r.witnesses);
    let o = &r.outcome;
    Some(if r.unassign {
        json!({ "JsUnassignedEvent": { "value": {
            "assignmentExclusivity": null,
            "contractId": o.contract_id,
            "nodeId": 0,
            "offset": offset,
            "packageName": created["packageName"],
            "reassignmentCounter": o.counter,
            "reassignmentId": o.reassignment_id,
            "source": o.source,
            "submitter": r.submitter,
            "target": o.target,
            "templateId": created["templateId"],
            "witnessParties": r.witnesses,
        } } })
    } else {
        json!({ "JsAssignmentEvent": {
            "createdEvent": created,
            "reassignmentCounter": o.counter,
            "reassignmentId": o.reassignment_id,
            "source": o.source,
            "submitter": r.submitter,
            "target": o.target,
        } })
    })
}

/// The reassignment object (`JsReassignment`) of an update.
pub(crate) fn reassignment_json(
    service: &ExecutionService,
    u: &crate::v2_commands::StoredUpdate,
    r: &StoredReassignment,
) -> Option<Json> {
    Some(json!({
        "commandId": u.command_id,
        "events": [event_json(service, r, u.offset)?],
        "offset": u.offset,
        "paidTrafficCost": 0,
        "recordTime": rfc3339_from_micros(r.outcome.record_time_micros),
        "synchronizerId": if r.unassign { &r.outcome.source } else { &r.outcome.target },
        // a W3C `traceparent` as the JVM always sends one (version 00, sampled 03); the ids are taken from the update id
        "traceContext": { "traceparent": format!("00-{}-{}-03", &u.update_id[4..36], &u.update_id[36..52]), "tracestate": null },
        "updateId": u.update_id,
        "workflowId": "",
    }))
}

/// The update-stream entry of a reassignment the `parties` can see.
pub(crate) fn visible(
    service: &ExecutionService,
    u: &crate::v2_commands::StoredUpdate,
    r: &StoredReassignment,
    parties: &[String],
) -> Option<Json> {
    if !parties.is_empty() && !r.witnesses.iter().any(|w| parties.contains(w)) {
        return None;
    }
    Some(json!({ "update": { "Reassignment": { "value": reassignment_json(service, u, r)? } } }))
}

/// `POST /v2/commands/submit-and-wait-for-reassignment`.
pub fn submit(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = serde_json::from_slice(&req.body).unwrap_or(Json::Null);
    let cmds = &body["reassignmentCommands"];
    let submitter = str_at(cmds, "submitter").to_string();
    let command_id = str_at(cmds, "commandId").to_string();
    let list = cmds["commands"].as_array().cloned().unwrap_or_default();
    let [one] = list.as_slice() else {
        return bad_request(format!(
            "this participant takes one reassignment command per request, not {}",
            list.len()
        ));
    };
    let command = if let Some(u) = one.pointer("/command/UnassignCommand/value") {
        ReassignCommand::Unassign {
            contract_id: str_at(u, "contractId").to_string(),
            source: str_at(u, "source").to_string(),
            target: str_at(u, "target").to_string(),
            submitter: submitter.clone(),
            command_id: command_id.clone(),
        }
    } else if let Some(a) = one.pointer("/command/AssignCommand/value") {
        ReassignCommand::Assign {
            reassignment_id: str_at(a, "reassignmentId").to_string(),
            source: str_at(a, "source").to_string(),
            target: str_at(a, "target").to_string(),
            submitter: submitter.clone(),
            command_id: command_id.clone(),
        }
    } else {
        return bad_request("a reassignment command is UnassignCommand or AssignCommand".into());
    };
    let state = service.v2_state();
    // [CANTON-NOTE: SEMANTICS] the source must be where the contract is: one that moved away is refused before anything is sent
    if let ReassignCommand::Unassign {
        contract_id,
        source,
        ..
    } = &command
    {
        let here = state.location_of(contract_id);
        let in_flight_to = state
            .reassign
            .lock()
            .ok()
            .and_then(|r| r.in_flight.get(contract_id).cloned());
        let away_to = match (&here, in_flight_to) {
            (_, Some(target)) => Some(target),
            (Some((sync, _)), None) if sync != source => Some(sync.clone()),
            _ => None,
        };
        if let Some(target) = away_to {
            let short = target.get(..target.len().min(19)).unwrap_or(&target);
            return bad_request(format!(
                "Cannot unassign contract `ContractId({contract_id})` because it's not active. Current status ReassignedAway({short}...)"
            ));
        }
    }
    let committer = service.committer.read().ok().and_then(|c| c.clone());
    let Some(result) = committer.as_ref().and_then(|c| c.reassign(&command)) else {
        return bad_request("this participant is connected to one synchronizer: there is nothing to reassign between".into());
    };
    let outcome = match result {
        Ok(o) => o,
        Err(e) => return crate::v2_commands::map_error(e, None, service),
    };
    let unassign = matches!(command, ReassignCommand::Unassign { .. });
    let witnesses = service
        .generic_contracts
        .read()
        .ok()
        .and_then(|m| m.get(&outcome.contract_id).cloned())
        .map(|c| {
            let mut w: Vec<String> = c
                .signatories
                .iter()
                .chain(c.observers.iter())
                .cloned()
                .collect();
            w.sort();
            w.dedup();
            w
        })
        .unwrap_or_default();
    if let Ok(mut r) = state.reassign.lock() {
        if unassign {
            r.in_flight
                .insert(outcome.contract_id.clone(), outcome.target.clone());
        } else {
            r.in_flight.remove(&outcome.contract_id);
            r.located.insert(
                outcome.contract_id.clone(),
                (outcome.target.clone(), outcome.counter),
            );
        }
    }
    let _publish_guard = state
        .commit_publish_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let offset = state.ledger_end.load(Ordering::SeqCst) + 1;
    let act_as = vec![submitter.clone()];
    let update = crate::v2_commands::StoredUpdate {
        update_id: update_id(offset),
        offset,
        command_id,
        effective_at: rfc3339_from_micros(outcome.record_time_micros),
        events: Vec::new(),
        at_micros: crate::clock::now_micros(),
        external_transaction_hash: None,
        official: None,
        trace_parent: None,
        act_as,
        reassignment: Some(Box::new(StoredReassignment {
            unassign,
            outcome,
            submitter,
            witnesses,
        })),
        topology: None,
    };
    if !state.record_update(update.clone()) {
        drop(_publish_guard);
        return crate::v2_commands::canton_error(
            crate::v2_commands::Kind::Request,
            500,
            "INTERNAL_ERROR",
            "failed to persist reassignment update journal".to_string(),
            13,
            13,
            json!([]),
        );
    }
    state.ledger_end.store(offset, Ordering::SeqCst);
    drop(_publish_guard);
    let r = update.reassignment.as_deref().expect("just set");
    match reassignment_json(service, &update, r) {
        Some(j) => HttpResponse::json(200, &json!({ "reassignment": j })),
        None => bad_request("the reassigned contract is not known to this service".into()),
    }
}

/// `POST /v2/commands/async/submit-reassignment`: submits a reassignment and answers `{}` on acceptance.
pub fn submit_async(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let resp = submit(service, req);
    if resp.status == 200 {
        HttpResponse::json(200, &json!({}))
    } else {
        resp
    }
}
