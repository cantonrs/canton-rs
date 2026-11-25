use super::blobs::{created_event_with, implemented_interfaces_for_event};
use super::errors::{canton_error, now_rfc3339, update_id, Kind};
use super::execute::{acs_delta_events, Ev, ExInfo, Shape};
use super::proto_values::{proto_values, template_value, value_proto, witnesses_of};
use super::SYNCHRONIZER;
use crate::http::HttpResponse;
use crate::models::ledger_api::TemplateId;
use crate::service::{ExecutionService, GenericContract};
use serde_json::{json, Value as Json};
use std::sync::atomic::Ordering;

/// An update (transaction) the ledger committed, kept so the by-id and by-offset reads can answer later (S-API-004).
#[derive(Clone)]
pub(crate) struct StoredUpdate {
    pub(crate) update_id: String,
    pub(crate) offset: u64,
    pub(crate) command_id: String,
    pub(crate) effective_at: String,
    pub(crate) events: Vec<Ev>,
    /// When the update was committed (microseconds since the epoch): what pruning measures the deduplication window by.
    pub(crate) at_micros: i64,
    /// Lowercase hex encoding of the 32-byte preparedTransactionHash for interactive submissions.
    pub(crate) external_transaction_hash: Option<String>,
    /// Set for a reassignment (it has no transaction events; see `v2_reassign`).
    pub(crate) reassignment: Option<Box<crate::v2_reassign::StoredReassignment>>,
    /// Set for a topology transaction (participant authorization changes; see `v2_topology_events`).
    pub(crate) topology: Option<Box<crate::v2_topology_events::StoredTopologyTransaction>>,
    /// What an official participant recorded of an update of its history (`--official-pg-url`): shown instead of this service's own values.
    pub(crate) official: Option<Box<OfficialMeta>>,
    /// The W3C `traceparent` of the submission (see `trace_context`).
    pub(crate) trace_parent: Option<String>,
    /// Submitters (`actAs`) that initiated this command; empty for remote or system-initiated updates.
    pub(crate) act_as: Vec<String>,
}

/// The values of an update adopted from an official participant's database that the service does not make up itself.
#[derive(Clone)]
pub(crate) struct OfficialMeta {
    pub(crate) workflow_id: String,
    pub(crate) record_time: String,
    pub(crate) synchronizer_id: String,
    pub(crate) trace_parent: Option<String>,
    pub(crate) traffic_cost: i64,
    /// The parties that submitted the command: the only ones that see its `commandId`.
    pub(crate) submitters: Vec<String>,
}

/// The events of an update as the given shape writes them. `filter`: keep only the events the witness parties are
/// informees of. A submission that named no format is read as its act-as parties: it shows the events those parties are
/// informees of, with only those parties as witnesses (measured: the owner who transfers a holding away sees the archive,
/// not the successor it can no longer see; S-API-016).
pub(crate) fn events_json(
    service: &ExecutionService,
    u: &StoredUpdate,
    witnesses: &[String],
    shape: Shape,
    filter: bool,
) -> Vec<Json> {
    let archived_in_tx: std::collections::HashSet<&String> = u
        .events
        .iter()
        .filter(|e| !e.created && e.exercise.as_ref().is_none_or(|x| x.consuming))
        .map(|e| &e.contract.contract_id)
        .collect();
    let created_in_tx: std::collections::HashSet<&String> = u
        .events
        .iter()
        .filter(|e| e.created)
        .map(|e| &e.contract.contract_id)
        .collect();
    let events: Vec<Ev> = match shape {
        Shape::AcsDelta => acs_delta_events(&u.events),
        Shape::LedgerEffects => u.events.clone(),
    };
    // the witnesses an official update stored for each node, the ones the asked parties are among
    let stored_witnesses: std::collections::HashMap<u64, Vec<String>> = if u.official.is_some() {
        events
            .iter()
            .map(|e| {
                (
                    e.node,
                    stored_witnesses_of(&e.contract, shape)
                        .into_iter()
                        .filter(|p| !filter || witnesses.contains(p))
                        .collect(),
                )
            })
            .collect()
    } else {
        Default::default()
    };
    events
        .iter()
        .filter_map(|e| {
            let c = &e.contract;
            // [CANTON-NOTE: SEMANTICS] In the LEDGER_EFFECTS shape the informees of an exercise also see its consequences:
            // an event below an exercise node is visible to, and witnessed by, the exercise's stakeholders and actors.
            let inherited: Vec<String> = if shape == Shape::LedgerEffects {
                events
                    .iter()
                    .filter_map(|x| x.exercise.as_ref().map(|i| (x, i)))
                    .filter(|(x, i)| x.node < e.node && e.node <= i.last_descendant)
                    .flat_map(|(x, i)| {
                        x.contract
                            .signatories
                            .iter()
                            .chain(&x.contract.observers)
                            .chain(&i.acting)
                            .chain(&i.choice_observers)
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .collect()
            } else {
                Vec::new()
            };
            // [CANTON-NOTE: SEMANTICS] An event of an official participant's history is seen by the witnesses the participant stored for it
            // (its stakeholders and the actors and stakeholders of the exercises above it), not by the ones this service works out.
            let stored = u.official.is_some();
            if stored {
                if filter
                    && !stored_witnesses_of(c, shape)
                        .iter()
                        .any(|p| witnesses.contains(p))
                {
                    return None;
                }
            } else if filter && !informee_of(e, witnesses) && !inherited.iter().any(|p| witnesses.contains(p)) {
                return None;
            }
            // [CANTON-NOTE: SEMANTICS] In the ACS_DELTA shape an archival shows only to a stakeholder of the archived contract;
            // an actor who is none (a taker of a disclosed contract) does not see it (measured on the node, AT-U02).
            if filter
                && !stored
                && shape == Shape::AcsDelta
                && !e.created
                && !e.contract.signatories.iter().chain(&e.contract.observers).any(|p| witnesses.contains(p))
            {
                return None;
            }
            Some(match (&e.exercise, e.created) {
                (_, true) => {
                    let mut witness: Vec<String> = Vec::new();
                    for p in c.signatories.iter().chain(&c.observers).chain(&inherited) {
                        if witnesses.contains(p) && !witness.contains(p) {
                            witness.push(p.clone());
                        }
                    }
                    let mut ev = created_event_with(service, c, u.offset, e.node, witness);
                    if shape == Shape::LedgerEffects && archived_in_tx.contains(&c.contract_id) {
                        ev["acsDelta"] = json!(false);
                    }
                    json!({ "CreatedEvent": ev })
                }
                (Some(x), false) if shape == Shape::LedgerEffects => {
                    let mut ev = exercised_event(service, e, x, u.offset, witnesses, &inherited);
                    // consuming a contract created in the same transaction does not change the active set
                    if created_in_tx.contains(&c.contract_id) {
                        ev["acsDelta"] = json!(false);
                    }
                    json!({ "ExercisedEvent": ev })
                }
                _ => json!({ "ArchivedEvent": archived_event(service, c, u.offset, e.node, witnesses) }),
            })
        })
        .map(|mut event| {
            if let Some(body) = event.as_object_mut().and_then(|o| o.values_mut().next()) {
                // [CANTON-NOTE: SEMANTICS] An event changes the ACS of the asked parties (`acsDelta`) only when one of them is a stakeholder of its
                // contract: a party that sees a creation only as an additional witness (under an exercise it is not a stakeholder of) gets `false`.
                if stored_witnesses.contains_key(&body["nodeId"].as_u64().unwrap_or(u64::MAX))
                    && body.get("acsDelta").is_some()
                {
                    let node = body["nodeId"].as_u64().unwrap_or(u64::MAX);
                    let stakeholder = events.iter().any(|e| {
                        e.node == node
                            && (!filter
                                || e.contract
                                    .signatories
                                    .iter()
                                    .chain(&e.contract.observers)
                                    .any(|p| witnesses.contains(p)))
                    });
                    if !stakeholder {
                        body["acsDelta"] = json!(false);
                    }
                }
                match stored_witnesses.get(&body["nodeId"].as_u64().unwrap_or(u64::MAX)) {
                    // the order the participant stored them in (the additional witnesses first)
                    Some(stored) => body["witnessParties"] = json!(stored),
                    None => order_witnesses(service, body),
                }
            }
            event
        })
        .collect()
}

/// [CANTON-NOTE: SEMANTICS] The official participant lists the witnesses of an event in a Scala `Set` order (alphabetical up to four, CHAMP hash
/// order beyond; see `scala_witness_order`); the order of signatories then observers is kept off the official mode.
pub(crate) fn order_witnesses(service: &ExecutionService, event: &mut Json) {
    if !service
        .v2_state()
        .official_parties
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        return;
    }
    if let Some(w) = event.get_mut("witnessParties").and_then(Json::as_array_mut) {
        let parties: Vec<String> = w
            .iter()
            .filter_map(|p| p.as_str().map(String::from))
            .collect();
        *w = lf_eval::script::scala_witness_order(&parties)
            .into_iter()
            .map(Json::from)
            .collect();
    }
}

/// The witnesses an event of an official update has in a shape: in `LEDGER_EFFECTS` all the ones the participant stored for it (the additional
/// witnesses first), in `ACS_DELTA` only the stakeholders of the contract (measured: a contract created under an exercise shows its stakeholders alone in the
/// `ACS_DELTA` shape and the exercise's actors besides in `LEDGER_EFFECTS`).
pub(super) fn stored_witnesses_of(c: &GenericContract, shape: Shape) -> Vec<String> {
    match shape {
        Shape::LedgerEffects => c.witness_parties.clone(),
        Shape::AcsDelta => {
            let mut stakeholders: Vec<String> = c.signatories.clone();
            for p in &c.observers {
                if !stakeholders.contains(p) {
                    stakeholders.push(p.clone());
                }
            }
            lf_eval::script::scala_witness_order(&stakeholders)
        }
    }
}

/// Whether the parties are informees of the event: stakeholders of its contract (and, for an exercise, its actors and choice observers).
pub(crate) fn informee_of(e: &Ev, parties: &[String]) -> bool {
    let c = &e.contract;
    c.signatories
        .iter()
        .chain(&c.observers)
        .chain(e.exercise.iter().flat_map(|x| x.acting.iter()))
        .chain(e.exercise.iter().flat_map(|x| x.choice_observers.iter()))
        .any(|p| parties.contains(p))
}

pub(super) fn exercised_event(
    service: &ExecutionService,
    e: &Ev,
    x: &ExInfo,
    offset: u64,
    witnesses: &[String],
    inherited: &[String],
) -> Json {
    let c = &e.contract;
    let mut witness: Vec<&String> = Vec::new();
    for p in c
        .signatories
        .iter()
        .chain(&c.observers)
        .chain(&x.acting)
        .chain(&x.choice_observers)
        .chain(inherited)
    {
        if witnesses.contains(p) && !witness.contains(&p) {
            witness.push(p);
        }
    }
    let iface_json = x.interface_id.as_deref().map_or(Json::Null, |id| {
        let mut parts = id.splitn(3, ':');
        let (pkg, mod_n, ent_n) = (
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
            parts.next().unwrap_or(""),
        );
        if pkg.is_empty() || mod_n.is_empty() || ent_n.is_empty() {
            json!(id)
        } else {
            template_value(&TemplateId::new(pkg, mod_n, ent_n))
        }
    });
    json!({
        "offset": offset,
        "nodeId": e.node,
        "contractId": c.contract_id,
        "templateId": template_value(&c.template_id),
        "interfaceId": iface_json,
        "choice": x.choice,
        "choiceArgument": match (proto_values(), &x.argument_value) {
            (Some(verbose), Some(v)) => value_proto(v, verbose),
            _ => x.argument.clone(),
        },
        "actingParties": x.acting,
        "consuming": x.consuming,
        "witnessParties": witness,
        "lastDescendantNodeId": x.last_descendant,
        "exerciseResult": match (proto_values(), &x.result_value) {
            (Some(verbose), Some(v)) => value_proto(v, verbose),
            _ => x.result.clone(),
        },
        "packageName": service.v2_package_name(&c.template_id.package_id).unwrap_or_default(),
        "implementedInterfaces": if x.consuming {
            implemented_interfaces_for_event(service, c)
        } else {
            Vec::new()
        },
        "acsDelta": x.consuming
    })
}

pub(crate) fn archived_event(
    service: &ExecutionService,
    c: &GenericContract,
    offset: u64,
    node: u64,
    witnesses: &[String],
) -> Json {
    let witness = witnesses_of(c, witnesses);
    json!({
        "offset": offset,
        "nodeId": node,
        "contractId": c.contract_id,
        "templateId": template_value(&c.template_id),
        "witnessParties": witness,
        "packageName": service.v2_package_name(&c.template_id.package_id).unwrap_or_default(),
        "implementedInterfaces": implemented_interfaces_for_event(service, c)
    })
}

/// [`transaction_json`] as the asked parties see it: an update of an official participant's history shows its `commandId` and `paidTrafficCost` only to the
/// parties that submitted the command (measured on the hub's participant: the other parties' view has an empty `commandId` and a `null` cost).
pub(crate) fn transaction_json_for(
    service: &ExecutionService,
    u: &StoredUpdate,
    events: Vec<Json>,
    parties: &[String],
) -> Json {
    let mut tx = transaction_json(u, events);
    // an update this service committed is on the synchronizer the service joined (the constant only when it joined none)
    if u.official.is_none() {
        tx["synchronizerId"] = json!(service.v2_state().synchronizer_id());
    }
    if let Some(o) = &u.official {
        if !o.submitters.iter().any(|p| parties.contains(p)) {
            tx["commandId"] = json!("");
            tx["paidTrafficCost"] = Json::Null;
        }
    }
    tx
}

/// The `Transaction` object of an update (the body of `submit-and-wait-for-transaction` and the `value` of an `Update`).
pub(crate) fn transaction_json(u: &StoredUpdate, events: Vec<Json>) -> Json {
    json!({
        "updateId": u.update_id,
        "commandId": u.command_id,
        "workflowId": u.official.as_ref().map_or("", |o| o.workflow_id.as_str()),
        "effectiveAt": u.effective_at,
        "events": events,
        "offset": u.offset,
        "synchronizerId": u.official.as_ref().map_or(SYNCHRONIZER, |o| o.synchronizer_id.as_str()),
        // [CANTON-NOTE: SEMANTICS] an update of the official history shows the trace context the participant recorded
        "traceContext": crate::trace_context::json(
            u.official.as_ref().map(|o| o.trace_parent.as_deref()),
            u.trace_parent.as_deref(),
        ),
        "recordTime": u.official.as_ref().map_or(u.effective_at.as_str(), |o| o.record_time.as_str()),
        "externalTransactionHash": u.external_transaction_hash,
        "paidTrafficCost": u.official.as_ref().map_or(0, |o| o.traffic_cost),
        "transactionHash": u.external_transaction_hash
    })
}

/// Records a synchronizer-rejected command completion (`U-31`): advances `ledger_end` and appends
/// a non-zero `status` `Completion` with empty `update_id` (and no `StoredUpdate` or dedup entry).
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
pub(crate) fn record_rejected_completion(
    state: &crate::v2::V2State,
    command_id: &str,
    user_id: &str,
    submission_id: &str,
    act_as: &[String],
    transaction_hash: Option<String>,
    status_code: i32,
    status_message: String,
    refusal: Option<String>,
) -> bool {
    let _publish_guard = state
        .commit_publish_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let offset = state.ledger_end.load(Ordering::SeqCst) + 1;
    let ok = state.record_completion(crate::v2_completions::Completion {
        offset,
        update_id: String::new(),
        command_id: command_id.to_string(),
        user_id: user_id.to_string(),
        submission_id: submission_id.to_string(),
        act_as: act_as.to_vec(),
        record_time: now_rfc3339(),
        transaction_hash,
        status_code,
        status_message,
        refusal,
        official: None,
        trace_parent: crate::trace_context::current(),
    });
    if ok {
        state.ledger_end.store(offset, Ordering::SeqCst);
    }
    ok
}

#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
pub(crate) fn finish_with_hash(
    service: &ExecutionService,
    command_id: &str,
    act_as: &[String],
    events: Vec<Ev>,
    with_transaction: bool,
    state: &crate::v2::V2State,
    (user_id, submission_id): (String, String),
    format: Option<(Vec<String>, Shape)>,
    tx_hashes: Option<(String, String)>,
) -> HttpResponse {
    let _publish_guard = state
        .commit_publish_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let offset = state.ledger_end.load(Ordering::SeqCst) + 1;
    let (hash_b64, hash_hex) = match tx_hashes {
        Some((b64, hex)) => (Some(b64), Some(hex)),
        None => (None, None),
    };
    let resolved_update_id =
        crate::service::take_protocol_update_id().unwrap_or_else(|| update_id(offset));
    // [CANTON-NOTE: SEMANTICS] A submission that was accepted leaves a completion; one that failed in interpretation
    // (answered with an error) leaves none (measured: the failed command is absent from the completion stream).
    // Persist updates.journal BEFORE completions.journal and advance ledger_end only after both succeed.
    let completion = crate::v2_completions::Completion {
        offset,
        update_id: resolved_update_id.clone(),
        command_id: command_id.to_string(),
        user_id,
        submission_id,
        act_as: act_as.to_vec(),
        record_time: now_rfc3339(),
        transaction_hash: hash_b64,
        status_code: 0,
        status_message: String::new(),
        refusal: None,
        official: None,
        trace_parent: crate::trace_context::current(),
    };
    let update = StoredUpdate {
        update_id: resolved_update_id,
        offset,
        command_id: command_id.to_string(),
        effective_at: now_rfc3339(),
        events,
        at_micros: crate::clock::now_micros(),
        external_transaction_hash: hash_hex,
        reassignment: None,
        topology: None,
        official: None,
        trace_parent: crate::trace_context::current(),
        act_as: act_as.to_vec(),
    };
    let persisted = state.record_update_and_completion(update.clone(), completion);
    if !persisted {
        drop(_publish_guard);
        return canton_error(
            Kind::Request,
            500,
            "INTERNAL_ERROR",
            format!("failed to persist update/completion journal for command {command_id}"),
            13,
            13,
            json!([]),
        );
    }
    state.ledger_end.store(offset, Ordering::SeqCst);
    drop(_publish_guard);
    service.command_recorded_for(command_id);
    if !with_transaction {
        return HttpResponse::json(
            200,
            &json!({ "updateId": update.update_id, "completionOffset": offset }),
        );
    }
    // a `transactionFormat` in the request picks the shape and the parties whose view is returned (measured: the
    // witnesses are then the filter parties, not the act-as parties)
    let events = match format {
        Some((parties, shape)) => events_json(service, &update, &parties, shape, true),
        None => events_json(service, &update, act_as, Shape::AcsDelta, true),
    };
    HttpResponse::json(
        200,
        &json!({ "transaction": transaction_json_for(service, &update, events, &[]) }),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
pub(super) fn finish(
    service: &ExecutionService,
    command_id: &str,
    act_as: &[String],
    events: Vec<Ev>,
    with_transaction: bool,
    state: &crate::v2::V2State,
    user_and_submission: (String, String),
    format: Option<(Vec<String>, Shape)>,
) -> HttpResponse {
    finish_with_hash(
        service,
        command_id,
        act_as,
        events,
        with_transaction,
        state,
        user_and_submission,
        format,
        None,
    )
}
