//! S-API-004: reads of what the ledger committed (`update-by-id`, `update-by-offset`, `contract-by-id`,
//! `events-by-contract-id`), checked against the Canton 3.7.2 sandbox by `scripts/verify-json-api.sh`.
//!
//! [CANTON-NOTE: SEMANTICS] An update is shown to a party only through the events the party is a stakeholder of
//! (`witnessParties` is the stakeholders intersected with the filter parties); an update none of whose events the party
//! sees is "not found, or not visible". Only the default transaction shape (ACS_DELTA) is produced.
use serde_json::{json, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2_commands::{
    acs_delta_events, archived_event, bad_body, canton_error, created_event, enter_want_blob,
    enter_want_blob_for, events_json, Ev, Kind, Shape, StoredUpdate, SYNCHRONIZER,
};

pub(crate) fn body_of(req: &HttpRequest) -> Result<Json, HttpResponse> {
    serde_json::from_slice(&req.body).map_err(|_| bad_body("Invalid value for: body".to_string()))
}

pub(crate) fn missing_field(name: &'static str) -> HttpResponse {
    canton_error(
        Kind::MissingField {
            name,
            correlated: false,
        },
        400,
        "MISSING_FIELD",
        format!("The submitted command is missing a mandatory field: {name}"),
        8,
        3,
        json!([]),
    )
}

fn not_found(code: &str, cause: &str, resources: Json) -> HttpResponse {
    canton_error(Kind::Request, 404, code, cause.into(), 11, 5, resources)
}

/// The parties of an `EventFormat` (`filtersByParty` keys, plus all known parties when `filtersForAnyParty` is set).
pub(crate) fn format_parties(service: &ExecutionService, format: &Json) -> Vec<String> {
    let mut parties: Vec<String> = format
        .get("filtersByParty")
        .and_then(Json::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    if format
        .get("filtersForAnyParty")
        .is_some_and(|v| v.is_object())
    {
        if let Ok(known) = service.v2_state().parties.lock() {
            for p in known.iter() {
                if !parties.contains(p) {
                    parties.push(p.clone());
                }
            }
        }
    }
    parties
}

pub(crate) fn stakeholder_of(e: &Ev, parties: &[String]) -> bool {
    e.contract
        .signatories
        .iter()
        .chain(&e.contract.observers)
        .any(|p| parties.contains(p))
}

/// Template constraint extracted from `includeTransactions.eventFormat` (`S-DX-005`).
pub(crate) enum TxTemplateFilter {
    Any,
    Specific(std::collections::BTreeSet<(String, String)>),
}

fn parse_template_spec(raw: &str) -> Option<(String, String)> {
    let stripped = raw.strip_prefix('#');
    let body = stripped.unwrap_or(raw);
    let (pkg, rest) = body.split_once(':')?;
    if pkg.is_empty() || !rest.contains(':') {
        return None;
    }
    if stripped.is_some() {
        Some((pkg.to_string(), rest.to_string()))
    } else {
        Some((format!("id:{pkg}"), rest.to_string()))
    }
}

fn parse_cumulative_templates(ef: &Json) -> TxTemplateFilter {
    let mut allowed = std::collections::BTreeSet::new();
    let collect_party_filters =
        |party_filter: &Json, out: &mut std::collections::BTreeSet<(String, String)>| -> bool {
            let Some(cum) = party_filter.get("cumulative").and_then(Json::as_array) else {
                return false;
            };
            if cum.is_empty() {
                return false;
            }
            for item in cum {
                let idf = &item["identifierFilter"];
                if let Some(tpl) = idf.get("TemplateFilter") {
                    let raw = tpl
                        .get("value")
                        .and_then(|v| v.get("templateId"))
                        .and_then(Json::as_str)
                        .unwrap_or("");
                    if let Some(spec) = parse_template_spec(raw) {
                        out.insert(spec);
                    } else {
                        return false;
                    }
                } else {
                    // WildcardFilter, InterfaceFilter, or empty object => do not restrict updates by template.
                    return false;
                }
            }
            true
        };
    if let Some(any) = ef.get("filtersForAnyParty").filter(|v| v.is_object()) {
        if !collect_party_filters(any, &mut allowed) {
            return TxTemplateFilter::Any;
        }
    }
    if let Some(by_party) = ef.get("filtersByParty").and_then(Json::as_object) {
        if by_party.is_empty() && allowed.is_empty() {
            return TxTemplateFilter::Any;
        }
        for pf in by_party.values() {
            if !collect_party_filters(pf, &mut allowed) {
                return TxTemplateFilter::Any;
            }
        }
    }
    if allowed.is_empty() {
        TxTemplateFilter::Any
    } else {
        TxTemplateFilter::Specific(allowed)
    }
}

fn event_matches_templates(
    ev: &Json,
    allowed: &std::collections::BTreeSet<(String, String)>,
) -> bool {
    let Some(body) = ev.as_object().and_then(|o| o.values().next()) else {
        return false;
    };
    let pkg_name = body.get("packageName").and_then(Json::as_str).unwrap_or("");
    let (pkg_id, local) = match body.get("templateId") {
        Some(Json::String(s)) => match s.split_once(':') {
            Some((p, r)) => (p.to_string(), r.to_string()),
            None => return false,
        },
        Some(Json::Object(obj)) => {
            let p = obj.get("packageId").and_then(Json::as_str).unwrap_or("");
            let m = obj.get("moduleName").and_then(Json::as_str).unwrap_or("");
            let e = obj.get("entityName").and_then(Json::as_str).unwrap_or("");
            (p.to_string(), format!("{m}:{e}"))
        }
        _ => return false,
    };
    allowed.contains(&(pkg_name.to_string(), local.clone()))
        || allowed.contains(&(format!("id:{pkg_id}"), local))
}

/// Parsed `UpdateFormat` selection covering transactions, reassignments, and topology authorization events.
pub(crate) struct UpdateSelection {
    pub(crate) tx_parties: Option<Vec<String>>,
    pub(crate) tx_shape: Shape,
    pub(crate) tx_templates: TxTemplateFilter,
    pub(crate) reassignment_parties: Option<Vec<String>>,
    pub(crate) topology: crate::v2_topology_events::TopologyFilter,
}

/// Parses and validates `updateFormat` across transactions, reassignments, and topology events.
pub(crate) fn update_selection(
    service: &ExecutionService,
    body: &Json,
) -> Result<UpdateSelection, HttpResponse> {
    let Some(format) = body.get("updateFormat") else {
        return Err(missing_field("update_format"));
    };
    let (tx_parties, tx_shape, tx_templates) = match format
        .get("includeTransactions")
        .filter(|v| !v.is_null())
    {
        None => (None, Shape::AcsDelta, TxTemplateFilter::Any),
        Some(tx) => match tx.get("transactionShape").and_then(Json::as_str) {
            None => {
                return Err(bad_body(
                        "Invalid value for: body (Got value '{\"Unrecognized\":{\"unrecognizedValue\":0}}' with wrong type, expecting string at 'transactionShape')"
                            .to_string(),
                    ));
            }
            Some("TRANSACTION_SHAPE_ACS_DELTA" | "TRANSACTION_SHAPE_LEDGER_EFFECTS") => {
                let shape = Shape::parse(tx.get("transactionShape").and_then(Json::as_str))
                    .unwrap_or(Shape::AcsDelta);
                let ef = tx.get("eventFormat").unwrap_or(&Json::Null);
                let parties = format_parties(service, ef);
                let templates = parse_cumulative_templates(ef);
                (Some(parties), shape, templates)
            }
            Some(other) => {
                return Err(canton_error(
                        Kind::Request,
                        400,
                        "INVALID_ARGUMENT",
                        format!(
                            "The submitted request has invalid arguments: transaction shape {other} is not supported by this server (only TRANSACTION_SHAPE_ACS_DELTA)"
                        ),
                        8,
                        3,
                        json!([]),
                    ));
            }
        },
    };
    let reassignment_parties = format
        .get("includeReassignments")
        .filter(|v| !v.is_null())
        .map(|ef| format_parties(service, ef));
    let topology = crate::v2_topology_events::parse_topology_filter(body).map_err(bad_body)?;
    Ok(UpdateSelection {
        tx_parties,
        tx_shape,
        tx_templates,
        reassignment_parties,
        topology,
    })
}

/// Renders one `StoredUpdate` according to `selection`, returning `None` when filtered out.
pub(crate) fn selected_update_json(
    service: &ExecutionService,
    u: &StoredUpdate,
    selection: &UpdateSelection,
) -> Option<Json> {
    if let Some(topo) = &u.topology {
        return crate::v2_topology_events::topology_json(u, topo, &selection.topology);
    }
    if let Some(r) = &u.reassignment {
        let parties = selection
            .reassignment_parties
            .as_deref()
            .or(selection.tx_parties.as_deref())?;
        return crate::v2_reassign::visible(service, u, r, parties);
    }
    let parties = selection.tx_parties.as_deref()?;
    let mut events = events_json(service, u, parties, selection.tx_shape, true);
    if let TxTemplateFilter::Specific(ref allowed) = selection.tx_templates {
        events.retain(|ev| event_matches_templates(ev, allowed));
    }
    (!events.is_empty()).then(|| {
        json!({ "update": { "Transaction": { "value": crate::v2_commands::transaction_json_for(service, u, events, parties) } } })
    })
}

pub(crate) fn update_response(
    service: &ExecutionService,
    update: Option<StoredUpdate>,
    selection: &UpdateSelection,
    absent: impl Fn() -> HttpResponse,
) -> HttpResponse {
    let Some(u) = update else {
        return absent();
    };
    match selected_update_json(service, &u, selection) {
        Some(v) => HttpResponse::json(200, &v),
        None => absent(),
    }
}

/// `POST /v2/updates/update-by-id`.
pub fn update_by_id(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body = match body_of(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(id) = body.get("updateId").and_then(Json::as_str) else {
        return bad_body("Invalid value for: body (Missing required field at 'updateId')".into());
    };
    let selection = match update_selection(service, &body) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return canton_error(
            Kind::Request,
            400,
            "INVALID_ARGUMENT",
            format!(
                "The submitted request has invalid arguments: Failed to parse hex string: {id}"
            ),
            8,
            3,
            json!([]),
        );
    }
    let pruned = service
        .v2_state()
        .pruned_up_to
        .load(std::sync::atomic::Ordering::SeqCst);
    // a pruned update is gone: "not found", like one that never existed (S-STORE-007)
    let update = service
        .v2_state()
        .updates()
        .into_iter()
        .find(|u| u.update_id == id && u.offset > pruned);
    let _blob_guard = enter_want_blob_for(&body);
    update_response(service, update, &selection, || {
        not_found(
            "UPDATE_NOT_FOUND",
            "Update not found, or not visible.",
            json!([["UPDATE_ID", id]]),
        )
    })
}

/// `POST /v2/updates/update-by-offset`.
pub fn update_by_offset(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body = match body_of(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(offset) = body
        .get("offset")
        .and_then(|o| o.as_i64().or_else(|| o.as_str()?.parse().ok()))
    else {
        return bad_body("Invalid value for: body (Missing required field at 'offset')".into());
    };
    let selection = match update_selection(service, &body) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if offset <= 0 {
        return canton_error(
            Kind::BadOffset,
            400,
            "NON_POSITIVE_OFFSET",
            format!("Offset {offset} in offset is not a positive integer: the offset has to be a positive integer (>0)"),
            8,
            3,
            json!([]),
        );
    }
    let pruned = service
        .v2_state()
        .pruned_up_to
        .load(std::sync::atomic::Ordering::SeqCst);
    let update = service
        .v2_state()
        .updates()
        .into_iter()
        .find(|u| u.offset as i64 == offset && u.offset > pruned);
    let _blob_guard = enter_want_blob_for(&body);
    update_response(service, update, &selection, || {
        not_found(
            "UPDATE_NOT_FOUND",
            "Update not found, or not visible.",
            json!([["OFFSET", offset.to_string()]]),
        )
    })
}

/// A contract id this server could have issued or that Canton would parse (hex digits, or the `#n:m` form this
/// ledger's own contracts use).
fn parsable_contract_id(service: &ExecutionService, id: &str) -> bool {
    service.v2_contract(id).is_some()
        || (!id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit()))
}

fn contract_not_visible(id: &str) -> HttpResponse {
    not_found(
        "CONTRACT_PAYLOAD_NOT_FOUND",
        "Contract payload not found, or not visible.",
        json!([["CONTRACT_ID", id]]),
    )
}

/// `POST /v2/contracts/contract-by-id`: the creation of a contract, active or archived.
pub fn contract_by_id(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body = match body_of(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(id) = body.get("contractId").and_then(Json::as_str) else {
        return missing_field("contract_id");
    };
    if !parsable_contract_id(service, id) {
        return canton_error(
            Kind::Request,
            400,
            "INVALID_FIELD",
            format!(
                "The submitted command has a field with invalid value: Invalid field contract_id: cannot parse ContractId \"{id}\""
            ),
            8,
            3,
            json!([]),
        );
    }
    let querying: Vec<String> = body
        .get("queryingParties")
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let Some(contract) = service.v2_contract(id) else {
        return contract_not_visible(id);
    };
    let witnesses: Vec<String> = if querying.is_empty() {
        contract
            .signatories
            .iter()
            .chain(&contract.observers)
            .cloned()
            .collect()
    } else {
        querying
    };
    let created = service
        .v2_state()
        .updates()
        .into_iter()
        .flat_map(|u| u.events.into_iter().map(move |e| (u.offset, e)))
        .find(|(_, e)| e.created && e.contract.contract_id == id);
    let probe = Ev {
        contract: contract.clone(),
        created: true,
        node: 0,
        exercise: None,
    };
    if !stakeholder_of(&probe, &witnesses) {
        return contract_not_visible(id);
    }
    // [CANTON-NOTE: SEMANTICS] Canton reports offset 1 and node 0 here and `acsDelta: false` (measured); this server
    // reports the real creating offset and node where it knows them.
    let (offset, node) = created.map_or((1, 0), |(o, e)| (o, e.node));
    let _blob_guard = enter_want_blob(true);
    let mut event = created_event(service, &contract, offset, node, &witnesses);
    event["acsDelta"] = json!(false);
    HttpResponse::json(200, &json!({ "createdEvent": event }))
}

/// `POST /v2/events/events-by-contract-id`: the creation and, if any, the archival of a contract, as the filter
/// parties see them.
pub fn events_by_contract_id(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body = match body_of(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(id) = body.get("contractId").and_then(Json::as_str) else {
        return missing_field("contract_id");
    };
    let Some(format) = body.get("eventFormat") else {
        return missing_field("event_format");
    };
    let parties = format_parties(service, format);
    let absent = || {
        not_found(
            "CONTRACT_EVENTS_NOT_FOUND",
            "Contract events not found, or not visible.",
            json!([["CONTRACT_ID", id]]),
        )
    };
    let events: Vec<(u64, Ev)> = service
        .v2_state()
        .updates()
        .into_iter()
        .flat_map(|u| {
            acs_delta_events(&u.events)
                .into_iter()
                .map(move |e| (u.offset, e))
        })
        .filter(|(_, e)| e.contract.contract_id == id && stakeholder_of(e, &parties))
        .collect();
    let Some((c_off, created)) = events.iter().find(|(_, e)| e.created).cloned() else {
        return absent();
    };
    let archived = events.iter().find(|(_, e)| !e.created);
    let _blob_guard = enter_want_blob_for(&body);
    HttpResponse::json(
        200,
        &json!({
            "created": {
                "createdEvent": created_event(service, &created.contract, c_off, created.node, &parties),
                "synchronizerId": SYNCHRONIZER
            },
            "archived": archived.map(|(a_off, a)| json!({
                "archivedEvent": archived_event(service, &a.contract, *a_off, a.node, &parties),
                "synchronizerId": SYNCHRONIZER
            }))
        }),
    )
}

fn tx_lookup_parties(service: &ExecutionService, body: &Json) -> (Option<Vec<String>>, Shape) {
    if let Some(tf) = body.get("transactionFormat") {
        let parties = tf
            .get("eventFormat")
            .map(|ef| format_parties(service, ef))
            .unwrap_or_default();
        let shape = Shape::parse(tf.get("transactionShape").and_then(Json::as_str))
            .unwrap_or(Shape::AcsDelta);
        return (Some(parties), shape);
    }
    let parties: Vec<String> = body
        .get("requestingParties")
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if parties.is_empty() {
        if let Some(ef) = body.get("eventFormat") {
            return (Some(format_parties(service, ef)), Shape::AcsDelta);
        }
        return (None, Shape::AcsDelta);
    }
    (Some(parties), Shape::AcsDelta)
}

fn transaction_wrap_response(
    service: &ExecutionService,
    update: Option<crate::v2_commands::StoredUpdate>,
    parties: Option<Vec<String>>,
    shape: Shape,
    absent: impl Fn() -> HttpResponse,
) -> HttpResponse {
    let Some(u) = update else {
        return absent();
    };
    let view_parties = parties.unwrap_or_else(|| crate::v2_commands::all_update_parties(&u));
    let events = events_json(service, &u, &view_parties, shape, true);
    if events.is_empty() {
        return absent();
    }
    HttpResponse::json(
        200,
        &json!({ "transaction": crate::v2_commands::transaction_json_for(service, &u, events, &view_parties) }),
    )
}

fn tree_wrap_response(
    service: &ExecutionService,
    update: Option<crate::v2_commands::StoredUpdate>,
    parties: Option<Vec<String>>,
    absent: impl Fn() -> HttpResponse,
) -> HttpResponse {
    let Some(u) = update else {
        return absent();
    };
    let view_parties = parties.unwrap_or_else(|| crate::v2_commands::all_update_parties(&u));
    let Some(tree) = crate::v2_commands::transaction_tree_json(service, &u, &view_parties) else {
        return absent();
    };
    HttpResponse::json(200, &json!({ "transaction": tree }))
}

/// `POST /v2/updates/transaction-by-id`.
pub fn transaction_by_id(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body = match body_of(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(id) = body.get("updateId").and_then(Json::as_str) else {
        return bad_body("Invalid value for: body (Missing required field at 'updateId')".into());
    };
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return canton_error(
            Kind::Request,
            400,
            "INVALID_ARGUMENT",
            format!(
                "The submitted request has invalid arguments: Failed to parse hex string: {id}"
            ),
            8,
            3,
            json!([]),
        );
    }
    let pruned = service
        .v2_state()
        .pruned_up_to
        .load(std::sync::atomic::Ordering::SeqCst);
    let update = service
        .v2_state()
        .updates()
        .into_iter()
        .find(|u| u.update_id == id && u.offset > pruned);
    let (parties, shape) = tx_lookup_parties(service, &body);
    let _blob_guard = enter_want_blob_for(&body);
    transaction_wrap_response(service, update, parties, shape, || {
        not_found(
            "UPDATE_NOT_FOUND",
            "Update not found, or not visible.",
            json!([["UPDATE_ID", id]]),
        )
    })
}

/// `POST /v2/updates/transaction-by-offset`.
pub fn transaction_by_offset(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body = match body_of(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let Some(offset) = body
        .get("offset")
        .and_then(|o| o.as_i64().or_else(|| o.as_str()?.parse().ok()))
    else {
        return bad_body("Invalid value for: body (Missing required field at 'offset')".into());
    };
    if offset <= 0 {
        return canton_error(
            Kind::BadOffset,
            400,
            "NON_POSITIVE_OFFSET",
            format!(
                "Offset {offset} in offset is not a positive integer: the offset has to be a positive integer (>0)"
            ),
            8,
            3,
            json!([]),
        );
    }
    let pruned = service
        .v2_state()
        .pruned_up_to
        .load(std::sync::atomic::Ordering::SeqCst);
    let update = service
        .v2_state()
        .updates()
        .into_iter()
        .find(|u| u.offset as i64 == offset && u.offset > pruned);
    let (parties, shape) = tx_lookup_parties(service, &body);
    let _blob_guard = enter_want_blob_for(&body);
    transaction_wrap_response(service, update, parties, shape, || {
        not_found(
            "UPDATE_NOT_FOUND",
            "Update not found, or not visible.",
            json!([["OFFSET", offset.to_string()]]),
        )
    })
}

fn query_parties_opt(req: &HttpRequest) -> Option<Vec<String>> {
    let raw = req.query_params.get("parties")?;
    let list: Vec<String> = raw
        .split(['\x1f', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    (!list.is_empty()).then_some(list)
}

/// `GET /v2/updates/transaction-tree-by-id/{update-id}`.
pub fn transaction_tree_by_id_get(
    service: &ExecutionService,
    req: &HttpRequest,
    id: &str,
) -> HttpResponse {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return canton_error(
            Kind::Request,
            400,
            "INVALID_ARGUMENT",
            format!(
                "The submitted request has invalid arguments: Failed to parse hex string: {id}"
            ),
            8,
            3,
            json!([]),
        );
    }
    let pruned = service
        .v2_state()
        .pruned_up_to
        .load(std::sync::atomic::Ordering::SeqCst);
    let update = service
        .v2_state()
        .updates()
        .into_iter()
        .find(|u| u.update_id == id && u.offset > pruned);
    tree_wrap_response(service, update, query_parties_opt(req), || {
        not_found(
            "UPDATE_NOT_FOUND",
            "Update not found, or not visible.",
            json!([["UPDATE_ID", id]]),
        )
    })
}

/// `GET /v2/updates/transaction-tree-by-offset/{offset}`.
pub fn transaction_tree_by_offset_get(
    service: &ExecutionService,
    req: &HttpRequest,
    offset_raw: &str,
) -> HttpResponse {
    let Ok(offset) = offset_raw.parse::<i64>() else {
        return bad_body(format!("Invalid value for: offset ({offset_raw:?})"));
    };
    if offset <= 0 {
        return canton_error(
            Kind::BadOffset,
            400,
            "NON_POSITIVE_OFFSET",
            format!(
                "Offset {offset} in offset is not a positive integer: the offset has to be a positive integer (>0)"
            ),
            8,
            3,
            json!([]),
        );
    }
    let pruned = service
        .v2_state()
        .pruned_up_to
        .load(std::sync::atomic::Ordering::SeqCst);
    let update = service
        .v2_state()
        .updates()
        .into_iter()
        .find(|u| u.offset as i64 == offset && u.offset > pruned);
    tree_wrap_response(service, update, query_parties_opt(req), || {
        not_found(
            "UPDATE_NOT_FOUND",
            "Update not found, or not visible.",
            json!([["OFFSET", offset.to_string()]]),
        )
    })
}
