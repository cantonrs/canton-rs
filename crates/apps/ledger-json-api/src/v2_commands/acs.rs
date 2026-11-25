use super::blobs::{created_event, enter_want_blob_for, interface_view_json};
use super::errors::{canton_error, Kind};
use super::events::{events_json, transaction_json_for, StoredUpdate};
use super::execute::{submit, Shape};
use super::proto_values::proto_values;
use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use serde_json::{json, Map, Value as Json};
use std::sync::atomic::Ordering;

/// Expands `eventFormat` (`filtersByParty` plus optional `filtersForAnyParty`) into per-party filter maps.
pub(crate) fn expand_event_format_filters(
    service: &ExecutionService,
    event_format: &Json,
) -> Option<Map<String, Json>> {
    let by_party = event_format.get("filtersByParty").and_then(Json::as_object);
    let any_party = event_format
        .get("filtersForAnyParty")
        .and_then(Json::as_object);
    if by_party.is_none() && any_party.is_none() {
        return None;
    }
    let mut merged = by_party.cloned().unwrap_or_default();
    if let Some(any) = any_party {
        let any_cum = any
            .get("cumulative")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default();
        if let Ok(parties) = service.v2_state().parties.lock() {
            for party in parties.iter() {
                let entry = merged
                    .entry(party.clone())
                    .or_insert_with(|| json!({ "cumulative": [] }));
                if let Some(obj) = entry.as_object_mut() {
                    if let Some(list) = obj
                        .entry("cumulative")
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                    {
                        list.extend(any_cum.iter().cloned());
                    }
                }
            }
        }
    }
    Some(merged)
}

/// `POST /v2/state/active-contracts`: the active contracts the filtered parties are stakeholders of, as Canton's array.
pub fn active_contracts(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = serde_json::from_slice(&req.body).unwrap_or(Json::Null);
    let Some(filters) = body
        .get("eventFormat")
        .and_then(|ef| expand_event_format_filters(service, ef))
    else {
        return canton_error(
            Kind::MissingField {
                name: "event_format",
                correlated: false,
            },
            400,
            "MISSING_FIELD",
            "The submitted command is missing a mandatory field: event_format".into(),
            8,
            3,
            json!([]),
        );
    };
    let parties: Vec<String> = filters.keys().cloned().collect();
    // [CANTON-NOTE: SEMANTICS] `activeAtOffset` below the pruned offset is refused; at or above it the ACS is the one as of
    // that offset (S-STORE-007, measured: the pruned offset itself is still readable).
    let at = body
        .get("activeAtOffset")
        .and_then(|o| o.as_u64().or_else(|| o.as_str()?.parse().ok()));
    if let Some(at) = at {
        let end = service.v2_state().ledger_end.load(Ordering::SeqCst);
        if at > end {
            return crate::v2_updates::offset_after_ledger_end_error(at, end, &parties, None);
        }
        if let Err(resp) = crate::v2_prune::check_active_at_not_pruned(service, at, &parties) {
            return resp;
        }
    }
    let limit = match crate::v2_updates::parse_stream_list_limit(req) {
        Ok(l) => l,
        Err(resp) => return resp,
    };
    let _blob_guard = enter_want_blob_for(&body);
    let result = acs_entries_filtered(service, &filters, &parties, at);
    match result {
        Ok(entries) => crate::v2_updates::finish_stream_list(service, limit, entries),
        Err(resp) => resp,
    }
}

/// One filter of a party's `cumulative` list.
pub(super) enum AcsFilter {
    Wildcard,
    Template {
        name: String,
        local: String,
    },
    Interface {
        name: String,
        local: String,
        view: bool,
    },
}

/// A filter's identifier must be a package-name reference `#name:Module:Entity`.
pub(super) fn parse_filter_id(id: &str) -> Result<(String, String), HttpResponse> {
    if let Some(rest) = id.strip_prefix('#') {
        if let Some((name, local)) = rest.split_once(':') {
            return Ok((name.to_string(), local.to_string()));
        }
    }
    let pkg = id.split(':').next().unwrap_or(id);
    Err(canton_error(
        Kind::Request,
        400,
        "INVALID_FIELD",
        format!("The submitted command has a field with invalid value: Invalid field packageId: Received an identifier with package ID {pkg}, but expected a package name."),
        8,
        3,
        json!([]),
    ))
}

pub(super) fn filter_error(
    code: &str,
    cause: String,
    category: u64,
    party: &str,
    filters: &str,
) -> HttpResponse {
    HttpResponse::json(
        404,
        &json!({
            "code": code, "cause": cause, "correlationId": Json::Null, "traceId": "0000000000000000",
            "context": { "category": category.to_string(), "definite_answer": "false", "filters": format!("{{{party}: {filters}}}"),
                         "participant": "'rust'", "tid": "0000000000000000" },
            "resources": [], "errorCategory": category, "grpcCodeValue": 5, "retryInfo": Json::Null, "definiteAnswer": Json::Null
        }),
    )
}

/// The active contracts the filters select. [CANTON-NOTE: SEMANTICS] Measured on the node (AT-U06): a template or interface
/// filter names its package by NAME (`#name:Module:Entity`; a package id is `INVALID_FIELD`), and a name covers every loaded
/// version of the package; an unknown package name, template or interface is a 404 naming it; an interface filter returns the
/// contracts whose template implements the interface, each with its view when `includeInterfaceView` is set; the filters of
/// a party are a union and a contract appears once.
pub(crate) fn acs_entries_filtered(
    service: &ExecutionService,
    filters: &Map<String, Json>,
    parties: &[String],
    at: Option<u64>,
) -> Result<Vec<Json>, HttpResponse> {
    let mut per_party: Vec<(String, Vec<AcsFilter>)> = Vec::new();
    for (party, f) in filters {
        let list = f
            .get("cumulative")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default();
        let mut parsed = Vec::new();
        let (mut tpl_text, mut itf_text) = (Vec::new(), Vec::new());
        for item in &list {
            let idf = &item["identifierFilter"];
            if idf.get("WildcardFilter").is_some() {
                parsed.push(AcsFilter::Wildcard);
            } else if let Some(t) = idf.get("TemplateFilter") {
                let id = t["value"]["templateId"].as_str().unwrap_or("");
                let (name, local) = parse_filter_id(id)?;
                tpl_text.push(format!("'{id}'"));
                parsed.push(AcsFilter::Template { name, local });
            } else if let Some(i) = idf.get("InterfaceFilter") {
                let id = i["value"]["interfaceId"].as_str().unwrap_or("");
                let (name, local) = parse_filter_id(id)?;
                itf_text.push(format!("'{id}'"));
                let view = i["value"]["includeInterfaceView"]
                    .as_bool()
                    .unwrap_or(false);
                parsed.push(AcsFilter::Interface { name, local, view });
            }
        }
        if parsed.is_empty() {
            parsed.push(AcsFilter::Wildcard);
        }
        let text = format!(
            "{{templates: [{}], interfaces: [{}]}}",
            tpl_text.join(", "),
            itf_text.join(", ")
        );
        for fl in &parsed {
            match fl {
                AcsFilter::Template { name, local } | AcsFilter::Interface { name, local, .. } => {
                    let ids = service.packages_named(name);
                    if ids.is_empty() {
                        return Err(filter_error(
                            "PACKAGE_NAMES_NOT_FOUND",
                            format!("The following package names do not match upgradable packages uploaded on this participant: [{name}]."),
                            11,
                            party,
                            &text,
                        ));
                    }
                    let is_interface = matches!(fl, AcsFilter::Interface { .. });
                    let found = ids.iter().any(|id| {
                        if is_interface {
                            service
                                .with_world(id, |w| w.interface_exists(id, local))
                                .unwrap_or(false)
                        } else {
                            service
                                .v2_template_fields(&crate::models::ledger_api::TemplateId::new(
                                    id.clone(),
                                    local.split(':').next().unwrap_or(""),
                                    local.split(':').nth(1).unwrap_or(""),
                                ))
                                .is_some()
                        }
                    });
                    if !found {
                        let (code, what) = if is_interface {
                            (
                                "NO_INTERFACE_FOR_PACKAGE_NAME_AND_QUALIFIED_NAME",
                                "interface",
                            )
                        } else {
                            (
                                "NO_TEMPLATES_FOR_PACKAGE_NAME_AND_QUALIFIED_NAME",
                                "template",
                            )
                        };
                        return Err(filter_error(
                            code,
                            format!("The following package-name/{what} qualified-name pairs do not reference any {what}-id uploaded on this participant: [({name},{local})]."),
                            11,
                            party,
                            &text,
                        ));
                    }
                }
                AcsFilter::Wildcard => {}
            }
        }
        per_party.push((party.clone(), parsed));
    }
    let end = service.v2_state().ledger_end.load(Ordering::SeqCst);
    let mut out = Vec::new();
    let contracts = match at {
        Some(at) if at < end => service.v2_active_contracts_at(at),
        _ => service.v2_active_contracts(),
    };
    for c in contracts {
        let local = format!(
            "{}:{}",
            c.template_id.module_name, c.template_id.entity_name
        );
        let pkg_name = service.v2_package_name(&c.package_id).unwrap_or_default();
        let mut selected = false;
        let mut views: Vec<Json> = Vec::new();
        let mut seen_views: std::collections::HashSet<(String, String)> = Default::default();
        for (party, list) in &per_party {
            if !c.signatories.iter().chain(&c.observers).any(|p| p == party) {
                continue;
            }
            for fl in list {
                match fl {
                    AcsFilter::Wildcard => selected = true,
                    AcsFilter::Template { name, local: l } => {
                        if &pkg_name == name && &local == l {
                            selected = true;
                        }
                    }
                    AcsFilter::Interface {
                        name,
                        local: l,
                        view,
                    } => {
                        for iid in service.packages_named(name) {
                            let hit = service
                                .with_world(&c.package_id, |w| {
                                    w.template_implements(&c.package_id, &local, &iid, l)
                                        .unwrap_or(false)
                                        .then(|| {
                                            w.eval_interface_view_in(
                                                &c.package_id,
                                                &local,
                                                &iid,
                                                l,
                                                &c.payload_value,
                                            )
                                            .ok()
                                        })
                                })
                                .flatten();
                            if let Some(v) = hit {
                                selected = true;
                                if *view && seen_views.insert((iid.clone(), l.clone())) {
                                    views.push(interface_view_json(
                                        service,
                                        &c.package_id,
                                        &iid,
                                        l,
                                        v.as_ref(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        if selected {
            // a contract read from an official database keeps the offset it was created at there
            let (at, node) = service
                .v2_state()
                .created_offsets
                .lock()
                .ok()
                .and_then(|m| m.get(&c.contract_id).copied())
                .unwrap_or((end, 0));
            let mut ev = created_event(service, &c, at, node, parties);
            ev["interfaceViews"] = Json::Array(views);
            out.push((c, ev));
        }
    }
    Ok(out
        .into_iter()
        .filter_map(|(c, ev)| Some((service.v2_state().location_of(&c.contract_id)?, ev)))
        .enumerate()
        .map(|(i, ((synchronizer, counter), ev))| {
            // [CANTON-NOTE: SEMANTICS] the synchronizer the contract is on and its reassignment counter; a contract between an
            // unassignment and its assignment is in no ACS (S-NET-040, recorded from the JVM)
            json!({
                "workflowId": "",
                "contractEntry": { "JsActiveContract": {
                    "createdEvent": ev,
                    "synchronizerId": synchronizer,
                    "reassignmentCounter": counter
                } },
                "streamContinuationToken": if proto_values().is_some() { crate::v2::base64(format!("{i}").as_bytes()) } else { format!("{i}") }
            })
        })
        .collect())
}

/// `transactionFormat` of a `submit-and-wait-for-transaction` body: the parties of its event format and its shape.
pub(crate) fn transaction_format(
    service: &ExecutionService,
    body: &Json,
) -> Option<(Vec<String>, Shape)> {
    let f = body.get("transactionFormat")?;
    let parties = f
        .get("eventFormat")
        .map(|ef| crate::v2_queries::format_parties(service, ef))
        .unwrap_or_default();
    let shape =
        Shape::parse(f.get("transactionShape").and_then(Json::as_str)).unwrap_or(Shape::AcsDelta);
    Some((parties, shape))
}

/// Renders a committed [`StoredUpdate`] as Canton OpenAPI 3.6.4 `JsTransactionTree`.
pub(crate) fn transaction_tree_json(
    service: &ExecutionService,
    u: &StoredUpdate,
    parties: &[String],
) -> Option<Json> {
    let evs = events_json(service, u, parties, Shape::LedgerEffects, true);
    if evs.is_empty() {
        return None;
    }
    let mut events_by_id = Map::new();
    for ev in evs {
        if let Some(created) = ev.get("CreatedEvent") {
            let id = created
                .get("nodeId")
                .and_then(Json::as_u64)
                .map(|n| n.to_string())
                .unwrap_or_else(|| events_by_id.len().to_string());
            events_by_id.insert(id, json!({ "CreatedTreeEvent": { "value": created } }));
        } else if let Some(exercised) = ev.get("ExercisedEvent") {
            let id = exercised
                .get("nodeId")
                .and_then(Json::as_u64)
                .map(|n| n.to_string())
                .unwrap_or_else(|| events_by_id.len().to_string());
            events_by_id.insert(id, json!({ "ExercisedTreeEvent": { "value": exercised } }));
        }
    }
    if events_by_id.is_empty() {
        return None;
    }
    let flat = transaction_json_for(service, u, Vec::new(), parties);
    Some(json!({
        "updateId": flat["updateId"],
        "commandId": flat["commandId"],
        "workflowId": flat["workflowId"],
        "effectiveAt": flat["effectiveAt"],
        "offset": flat["offset"],
        "eventsById": events_by_id,
        "synchronizerId": flat["synchronizerId"],
        "traceContext": flat["traceContext"],
        "recordTime": flat["recordTime"],
    }))
}

/// Collects every stakeholding/witness/acting/observer party present in a stored update.
pub(crate) fn all_update_parties(u: &StoredUpdate) -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for e in &u.events {
        for p in e
            .contract
            .signatories
            .iter()
            .chain(&e.contract.observers)
            .chain(&e.contract.witness_parties)
        {
            set.insert(p.clone());
        }
        if let Some(x) = &e.exercise {
            for p in x.acting.iter().chain(&x.choice_observers) {
                set.insert(p.clone());
            }
        }
    }
    if let Some(r) = &u.reassignment {
        for p in &r.witnesses {
            set.insert(p.clone());
        }
    }
    if let Some(t) = &u.topology {
        for ev in &t.events {
            set.insert(ev.party_id.clone());
        }
    }
    set.into_iter().collect()
}

/// `POST /v2/commands/submit-and-wait-for-transaction-tree`.
pub fn submit_tree(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = serde_json::from_slice(&req.body).unwrap_or(Json::Null);
    let act_as: Vec<String> = body
        .pointer("/commands/actAs")
        .or_else(|| body.get("actAs"))
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut normalized_req = req.clone();
    if body.get("commands").is_some_and(Json::is_array) {
        normalized_req.body = json!({ "commands": body }).to_string().into_bytes();
    }
    let resp = submit(service, &normalized_req, true);
    if resp.status != 200 {
        return resp;
    }
    let Ok(tx_json) = serde_json::from_slice::<Json>(&resp.body) else {
        return resp;
    };
    let offset = tx_json
        .pointer("/transaction/offset")
        .and_then(Json::as_u64)
        .unwrap_or(0);
    let Some(update) = service
        .v2_state()
        .updates()
        .into_iter()
        .rfind(|u| u.offset == offset)
    else {
        return resp;
    };
    let view_parties = if act_as.is_empty() {
        all_update_parties(&update)
    } else {
        act_as
    };
    let tree = transaction_tree_json(service, &update, &view_parties)
        .or_else(|| transaction_tree_json(service, &update, &all_update_parties(&update)));
    HttpResponse::json(200, &json!({ "transactionTree": tree }))
}
