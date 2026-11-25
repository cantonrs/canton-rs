use super::errors::{canton_error, rfc3339_from_micros, Kind};
use super::events::order_witnesses;
use super::proto_values::{
    proto_values, record_proto, retype_times, template_value, value_proto_typed, witnesses_of,
};
use super::SYNCHRONIZER;
use crate::http::HttpResponse;
use crate::models::ledger_api::TemplateId;
use crate::service::{ExecutionService, GenericContract};
use lf_eval::fat_contract::{
    authenticate_fat_contract, decode_fat_contract_blob, decode_strict_base64, encode_base64,
    encode_fat_contract, FatContractInput,
};
use lf_eval::{render_numeric, Value};
use serde_json::{json, Map, Value as Json};

/// A Daml value as Canton's JSON encoding writes it (Int64 and Numeric as strings, records as objects).
pub fn value_json(v: &Value) -> Json {
    match v {
        Value::Int64(n) => json!(n.to_string()),
        Value::Numeric { coeff, scale } => json!(render_numeric(*coeff, *scale)),
        Value::Text(t) | Value::Party(t) | Value::ContractId(t) => json!(t),
        Value::Bool(b) => json!(b),
        Value::Unit => json!({}),
        Value::List(items) => Json::Array(items.iter().map(value_json).collect()),
        Value::Optional(None) => Json::Null,
        Value::Optional(Some(inner)) => value_json(inner),
        // [CANTON-NOTE: SEMANTICS] Matches Canton 3.7.2 `SchemaProcessorsImpl.scala:251` (`removeTrailingNonesInRecords = true`)
        // and `JsonCodec.scala:66-68`: drop only trailing `Optional(None)` fields (so AT-L08 omitted trailing `note` stays absent),
        // while keeping non-trailing `Optional(None)` fields as `null`.
        Value::Record { fields, .. } => {
            let limit = fields
                .iter()
                .rposition(|(_, x)| !matches!(x, Value::Optional(None)))
                .map_or(0, |i| i + 1);
            Json::Object(
                fields
                    .iter()
                    .take(limit)
                    .map(|(k, x)| (k.clone(), value_json(x)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Enum { constructor, .. } => json!(constructor),
        Value::Variant {
            constructor, value, ..
        } => json!({ "tag": constructor, "value": value_json(value) }),
        other => json!(format!("{other:?}")),
    }
}

pub(crate) fn created_event(
    service: &ExecutionService,
    c: &GenericContract,
    offset: u64,
    node: u64,
    witnesses: &[String],
) -> Json {
    let witness: Vec<String> = witnesses_of(c, witnesses).into_iter().cloned().collect();
    created_event_with(service, c, offset, node, witness)
}

thread_local! {
    // Whether the request being served asked for `includeCreatedEventBlob`.
    static WANT_BLOB: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn want_blob() -> bool {
    WANT_BLOB.with(std::cell::Cell::get)
}

/// Whether any filter of the request body asks for the created-event blob.
pub(crate) fn body_wants_blob(v: &Json) -> bool {
    match v {
        Json::Object(m) => m.iter().any(|(k, x)| {
            (k == "includeCreatedEventBlob" && x == &Json::Bool(true)) || body_wants_blob(x)
        }),
        Json::Array(a) => a.iter().any(body_wants_blob),
        _ => false,
    }
}

pub(crate) fn set_want_blob(v: bool) {
    WANT_BLOB.with(|w| w.set(v));
}

pub(crate) struct WantBlobGuard;

impl Drop for WantBlobGuard {
    fn drop(&mut self) {
        set_want_blob(false);
        VIEW_FILTERS.with(|v| v.borrow_mut().clear());
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum IfaceFilterRef {
    ByPkgName { name: String, local: String },
    ByPkgId { pkg_id: String, local: String },
}

thread_local! {
    // The interfaces whose view the request being served asked for (`InterfaceFilter` with `includeInterfaceView: true`).
    static VIEW_FILTERS: std::cell::RefCell<Vec<IfaceFilterRef>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Parses an `InterfaceFilter.interfaceId` value: `#pkg-name:Module:Entity`, `<pkg_id>:Module:Entity`,
/// or protobuf-JSON `{"packageId": ..., "moduleName": ..., "entityName": ...}`.
pub(super) fn parse_view_filter_id(v: &Json) -> Option<IfaceFilterRef> {
    if let Some(id) = v.as_str() {
        if let Some(rest) = id.strip_prefix('#') {
            let (name, local) = rest.split_once(':')?;
            if name.is_empty() || !local.contains(':') {
                return None;
            }
            return Some(IfaceFilterRef::ByPkgName {
                name: name.to_string(),
                local: local.to_string(),
            });
        }
        let (pkg, local) = id.split_once(':')?;
        if pkg.is_empty() || !local.contains(':') {
            return None;
        }
        return Some(IfaceFilterRef::ByPkgId {
            pkg_id: pkg.to_string(),
            local: local.to_string(),
        });
    }
    let obj = v.as_object()?;
    let pkg = obj.get("packageId").and_then(Json::as_str)?;
    let module = obj.get("moduleName").and_then(Json::as_str)?;
    let entity = obj.get("entityName").and_then(Json::as_str)?;
    if pkg.is_empty() || module.is_empty() || entity.is_empty() {
        return None;
    }
    let local = format!("{module}:{entity}");
    if let Some(name) = pkg.strip_prefix('#') {
        if name.is_empty() {
            return None;
        }
        Some(IfaceFilterRef::ByPkgName {
            name: name.to_string(),
            local,
        })
    } else {
        Some(IfaceFilterRef::ByPkgId {
            pkg_id: pkg.to_string(),
            local,
        })
    }
}

/// The interfaces a request body asks the view of, from the `InterfaceFilter`s anywhere in it.
pub(super) fn body_interface_views(v: &Json, out: &mut Vec<IfaceFilterRef>) {
    match v {
        Json::Object(m) => {
            if let Some(i) = m.get("InterfaceFilter") {
                let inner = i.get("value").unwrap_or(i);
                if inner["includeInterfaceView"].as_bool() == Some(true) {
                    if let Some(r) = parse_view_filter_id(&inner["interfaceId"]) {
                        if !out.contains(&r) {
                            out.push(r);
                        }
                    }
                }
            }
            for x in m.values() {
                body_interface_views(x, out);
            }
        }
        Json::Array(a) => a.iter().for_each(|x| body_interface_views(x, out)),
        _ => {}
    }
}

/// [`enter_want_blob`] for a request body that also names the interface views the created events carry.
pub(crate) fn enter_want_blob_for(body: &Json) -> WantBlobGuard {
    let mut views = Vec::new();
    body_interface_views(body, &mut views);
    VIEW_FILTERS.with(|v| *v.borrow_mut() = views);
    enter_want_blob(body_wants_blob(body))
}

pub(super) fn filter_package_ids<'a>(
    service: &ExecutionService,
    r: &'a IfaceFilterRef,
) -> (Vec<String>, &'a str) {
    match r {
        IfaceFilterRef::ByPkgName { name, local } => (service.packages_named(name), local.as_str()),
        IfaceFilterRef::ByPkgId { pkg_id, local } => (vec![pkg_id.clone()], local.as_str()),
    }
}

pub(super) fn encode_interface_view_value(
    service: &ExecutionService,
    iface_pkg_id: &str,
    iface_local: &str,
    v: &Value,
) -> Json {
    let (mod_n, ent_n) = iface_local.split_once(':').unwrap_or(("", iface_local));
    if let Some(verbose) = proto_values() {
        let fallback_id = TemplateId::new(iface_pkg_id, mod_n, ent_n);
        return service
            .with_world(iface_pkg_id, |w| {
                let types = lf_eval::typed_json::Types::new(w);
                types
                    .interface_view_type(iface_pkg_id, iface_local)
                    .ok()
                    .map(|ty| value_proto_typed(&types, &ty, v, verbose))
            })
            .flatten()
            .map(|pv| pv.get("record").cloned().unwrap_or(pv))
            .unwrap_or_else(|| record_proto(v, Some(&fallback_id), verbose));
    }
    service
        .with_world(iface_pkg_id, |w| {
            let types = lf_eval::typed_json::Types::new(w);
            let view_ty = types.interface_view_type(iface_pkg_id, iface_local).ok()?;
            // [CANTON-NOTE: SEMANTICS] Canton 3.7.2 (`ProtocolConverters.scala:389-392` ->
            // `SchemaProcessorsImpl.scala:250-251` with `removeTrailingNonesInRecords = true` ->
            // `JsonCodec.scala:66-68`) omits trailing `Optional(None)` fields in
            // `interfaceViews[*].viewValue` while serializing non-trailing `Optional(None)` fields as explicit `null`.
            types.encode_ledger_api(&view_ty, v).ok()
        })
        .flatten()
        .unwrap_or_else(|| value_json(v))
}

pub(super) fn interface_view_json(
    service: &ExecutionService,
    impl_pkg_id: &str,
    iface_pkg_id: &str,
    iface_local: &str,
    v: Option<&Value>,
) -> Json {
    let (mod_n, ent_n) = iface_local.split_once(':').unwrap_or(("", iface_local));
    json!({
        "implementationPackageId": impl_pkg_id,
        "interfaceId": template_value(&TemplateId::new(iface_pkg_id, mod_n, ent_n)),
        "viewStatus": { "code": 0, "details": [], "message": "" },
        "viewValue": v.map_or(Json::Null, |val| encode_interface_view_value(service, iface_pkg_id, iface_local, val))
    })
}

/// The `implementedInterfaces` of a consuming `ExercisedEvent` or `ArchivedEvent`: all interfaces
/// implemented by the contract's template that match a requested `InterfaceFilter` with `includeInterfaceView`.
pub(super) fn implemented_interfaces_for_event(
    service: &ExecutionService,
    c: &GenericContract,
) -> Vec<Json> {
    let filters = VIEW_FILTERS.with(|v| v.borrow().clone());
    if filters.is_empty() {
        return Vec::new();
    }
    let local = format!(
        "{}:{}",
        c.template_id.module_name, c.template_id.entity_name
    );
    let impls = service.v2_implemented_interfaces(&c.package_id, &local);
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = Default::default();
    for (iface_pkg, iface_local) in impls {
        let matched = filters.iter().any(|f| match f {
            IfaceFilterRef::ByPkgId { pkg_id, local: l } => {
                pkg_id == &iface_pkg && l == &iface_local
            }
            IfaceFilterRef::ByPkgName { name, local: l } => {
                l == &iface_local && service.packages_named(name).iter().any(|p| p == &iface_pkg)
            }
        });
        if matched && seen.insert((iface_pkg.clone(), iface_local.clone())) {
            let (mod_n, ent_n) = iface_local.split_once(':').unwrap_or(("", &iface_local));
            out.push(template_value(&TemplateId::new(iface_pkg, mod_n, ent_n)));
        }
    }
    out
}

/// The `interfaceViews` of a created event of the update streams: the views of the interfaces the request asked for that the contract's template implements
/// (the same views the active contract set builds).
pub(super) fn requested_interface_views(
    service: &ExecutionService,
    c: &GenericContract,
) -> Vec<Json> {
    let filters = VIEW_FILTERS.with(|v| v.borrow().clone());
    let local = format!(
        "{}:{}",
        c.template_id.module_name, c.template_id.entity_name
    );
    let mut views = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = Default::default();
    for f in &filters {
        let (pkg_ids, l) = filter_package_ids(service, f);
        for iid in pkg_ids {
            if seen.contains(&(iid.clone(), l.to_string())) {
                continue;
            }
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
                seen.insert((iid.clone(), l.to_string()));
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
    views
}

pub(crate) fn enter_want_blob(v: bool) -> WantBlobGuard {
    set_want_blob(v);
    WantBlobGuard
}

/// Base64-encoded Canton 3.7.2 `Versioned(FatContractInstance)` created-event blob.
pub(crate) fn blob_for(service: &ExecutionService, c: &GenericContract) -> String {
    if let Some(bytes) = service.v2_instance_bytes(&c.contract_id) {
        return encode_base64(&bytes);
    }
    if !c.created_event_blob.is_empty() {
        return c.created_event_blob.clone();
    }
    if c.contract_id.len() != 138 {
        return String::new();
    }
    let Some(pkg) = service.v2_lf_package(&c.package_id) else {
        return String::new();
    };
    let pkg_name = service.v2_package_name(&c.package_id).unwrap_or_default();
    let non_sig_obs: Vec<String> = c
        .observers
        .iter()
        .filter(|o| !c.signatories.contains(o))
        .cloned()
        .collect();
    let key_hash_vec = if c.key_value.is_some() && !c.contract_key_hash.is_empty() {
        decode_strict_base64(&c.contract_key_hash).ok()
    } else {
        None
    };
    let key_hash_arr: Option<[u8; 32]> = key_hash_vec.as_deref().and_then(|b| b.try_into().ok());
    encode_fat_contract(
        &pkg.world,
        &FatContractInput {
            contract_id: &c.contract_id,
            package_id: &c.package_id,
            package_name: &pkg_name,
            module_name: &c.template_id.module_name,
            entity_name: &c.template_id.entity_name,
            payload: &c.payload_value,
            signatories: &c.signatories,
            observers: &non_sig_obs,
            created_at_micros: c.created_at_micros,
            salt: &[0u8; 32],
            key: c.key_value.as_ref(),
            key_maintainers: &c.key_maintainers,
            key_hash: key_hash_arr.as_ref(),
        },
    )
    .map(|b| encode_base64(&b))
    .unwrap_or_default()
}

/// [CANTON-NOTE: SEMANTICS] Explicit disclosure, as the node answers it (AT-U02, tests/oracle/disclosure): the disclosed
/// contracts of a command are checked in this order: an empty blob is `MISSING_FIELD` (`DisclosedContract.createdEventBlob`);
/// a `#name` template is `INVALID_FIELD`; a blob that does not decode as canonical `Versioned(FatContractInstance)` is
/// `INVALID_ARGUMENT`; a contract id or a template id that differs from the blob's is `INVALID_ARGUMENT` ("Mismatch between
/// DisclosedContract.…"); another synchronizer is `INVALID_PRESCRIBED_SYNCHRONIZER_ID`; a blob whose content fails Stage 2
/// template/Unicum authentication (tampered payload/key/salt under the same contract id) is
/// `INTERPRETATION_UPGRADE_ERROR_AUTHENTICATION_FAILED`; a disclosed contract that was archived on this ledger is
/// `LOCAL_VERDICT_INACTIVE_CONTRACTS`. A valid unseen foreign contract is visible for this submission without persisting
/// into `/v2/state/active-contracts` unless consumed.
pub(crate) fn check_disclosed(
    service: &ExecutionService,
    cmds: &Json,
) -> Result<Vec<GenericContract>, HttpResponse> {
    let list = cmds
        .get("disclosedContracts")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out: Vec<GenericContract> = Vec::new();
    for (idx, d) in list.iter().enumerate() {
        let blob = d["createdEventBlob"].as_str().unwrap_or("");
        if blob.is_empty() {
            return Err(canton_error(
                Kind::MissingField {
                    name: "DisclosedContract.createdEventBlob",
                    correlated: true,
                },
                400,
                "MISSING_FIELD",
                "The submitted command is missing a mandatory field: DisclosedContract.createdEventBlob"
                    .into(),
                8,
                3,
                json!([]),
            ));
        }
        let template = d["templateId"].as_str().unwrap_or("");
        if let Some(name) = template.strip_prefix('#') {
            let name = name.split(':').next().unwrap_or(name);
            return Err(canton_error(
                Kind::Request,
                400,
                "INVALID_FIELD",
                format!("The submitted command has a field with invalid value: Invalid field package_id: non expected character 0x23 in Daml-LF Package ID \"#{name}\""),
                8,
                3,
                json!([]),
            ));
        }
        let cid = d["contractId"].as_str().unwrap_or("").to_string();
        let invalid = |msg: String| {
            canton_error(
                Kind::RequestCorrelated,
                400,
                "INVALID_ARGUMENT",
                format!("The submitted request has invalid arguments: {msg}"),
                8,
                3,
                json!([]),
            )
        };
        let Ok(blob_bytes) = decode_strict_base64(blob) else {
            return Err(invalid("Unable to decode disclosed contract event payload: DecodeError(the blob is not canonical base64)".into()));
        };
        let raw = match decode_fat_contract_blob(&blob_bytes) {
            Ok(r) => r,
            Err(e) => {
                return Err(invalid(format!(
                    "Unable to decode disclosed contract event payload: {}",
                    e.0
                )));
            }
        };
        if !cid.is_empty() && raw.contract_id != cid {
            return Err(invalid(format!(
                "Mismatch between DisclosedContract.contract_id ({cid}) and contract_id from decoded DisclosedContract.created_event ({})",
                raw.contract_id
            )));
        }
        let effective_cid = if cid.is_empty() {
            raw.contract_id.clone()
        } else {
            cid
        };
        let decoded_template =
            format!("{}:{}:{}", raw.package_id, raw.module_name, raw.entity_name);
        if !template.is_empty() && decoded_template != template {
            return Err(invalid(format!(
                "Mismatch between DisclosedContract.template_id ({template}) and template_id from decoded DisclosedContract.created_event ({decoded_template})"
            )));
        }
        if let Some(sync) = d["synchronizerId"].as_str().filter(|s| !s.is_empty()) {
            let active_sync = service.v2_state().synchronizer_id();
            if sync != active_sync && sync != SYNCHRONIZER {
                return Err(HttpResponse::json(
                    400,
                    &json!({
                        "code": "INVALID_PRESCRIBED_SYNCHRONIZER_ID",
                        "cause": format!("Cannot submit transaction to prescribed synchronizer `{sync}` because: cannot resolve {sync} to a physical synchronizer id"),
                        "correlationId": Json::Null, "traceId": Json::Null,
                        "context": { "category": "9", "definite_answer": "false" },
                        "resources": [], "errorCategory": 9, "grpcCodeValue": 9, "retryInfo": Json::Null, "definiteAnswer": Json::Null
                    }),
                ));
            }
        }
        let auth = service.v2_lf_package(&raw.package_id).and_then(|pkg| {
            authenticate_fat_contract(&pkg.world, &raw)
                .ok()
                .map(|a| (pkg, a))
        });
        let Some((pkg, auth)) = auth else {
            return Err(canton_error(
                Kind::Interpretation { failure: false },
                400,
                "INTERPRETATION_UPGRADE_ERROR_AUTHENTICATION_FAILED",
                format!(
                    "Interpretation error: Error when authenticating contract {effective_cid} against template {}:{} : failed to authenticate contract",
                    raw.module_name, raw.entity_name
                ),
                8,
                3,
                json!([["CONTRACT_ID", effective_cid], ["TEMPLATE_ID", decoded_template]]),
            ));
        };
        if service
            .v2_contract(&effective_cid)
            .is_some_and(|c| !c.active)
        {
            return Err(HttpResponse::json(
                404,
                &json!({
                    "code": "LOCAL_VERDICT_INACTIVE_CONTRACTS",
                    "cause": "Rejected transaction is referring to inactive contracts ",
                    "correlationId": Json::Null, "traceId": "0000000000000000",
                    "context": {
                        "CONTRACT_ID": format!("List({effective_cid})"), "category": "11",
                        "confirming_parties": "", "definite_answer": "false", "participant": "rust",
                        "psid": SYNCHRONIZER, "reported_by_participant_id": "PAR::rust", "tid": "0000000000000000"
                    },
                    "resources": [["CONTRACT_ID", effective_cid]], "errorCategory": 11, "grpcCodeValue": 5,
                    "retryInfo": Json::Null, "definiteAnswer": Json::Null
                }),
            ));
        }
        if out.iter().any(|g| g.contract_id == effective_cid) {
            continue;
        }
        let local_tpl = format!("{}:{}", auth.module_name, auth.entity_name);
        let json_payload =
            crate::payload_schema::PayloadSchema::template(&pkg, &raw.package_id, &local_tpl)
                .ok()
                .and_then(|s| s.to_json(&auth.payload).ok())
                .unwrap_or_else(|| value_json(&auth.payload));
        let mut witness = auth.signatories.clone();
        for obs in &auth.observers {
            if !witness.contains(obs) {
                witness.push(obs.clone());
            }
        }
        let contract_key_hash = auth
            .key_hash
            .as_ref()
            .map(|kh| encode_base64(kh))
            .unwrap_or_default();
        out.push(GenericContract {
            contract_id: effective_cid,
            package_id: auth.package_id,
            template_id: TemplateId {
                package_id: raw.package_id,
                module_name: auth.module_name,
                entity_name: auth.entity_name,
            },
            payload_value: auth.payload,
            json_payload,
            signatories: auth.signatories,
            observers: auth.observers,
            witness_parties: witness,
            active: true,
            key_value: auth.key,
            created_at_micros: auth.created_at_micros,
            created_event_blob: blob.to_string(),
            contract_key_hash,
            key_maintainers: auth.key_maintainers,
            creation_seq: idx as u64,
        });
    }
    Ok(out)
}

/// A `CreatedEvent` with the witness list already worked out.
pub(crate) fn created_event_with(
    service: &ExecutionService,
    c: &GenericContract,
    offset: u64,
    node: u64,
    witness: Vec<String>,
) -> Json {
    // a party that signs twice (a contract whose bank and owner are one party) is one signatory
    let mut signatories: Vec<&String> = Vec::new();
    for p in &c.signatories {
        if !signatories.contains(&p) {
            signatories.push(p);
        }
    }
    let observers: Vec<&String> = c
        .observers
        .iter()
        .filter(|o| !c.signatories.contains(o))
        .collect();
    let mut ev = json!({
        "offset": offset,
        "nodeId": node,
        "contractId": c.contract_id,
        "templateId": template_value(&c.template_id),
        "contractKey": c.key_value.as_ref().map_or(Json::Null, value_json),
        "contractKeyHash": c.contract_key_hash,
        "createdEventBlob": if want_blob() { blob_for(service, c) } else { String::new() },
        "interfaceViews": [],
        "witnessParties": witness,
        "signatories": signatories,
        "observers": observers,
        "createdAt": rfc3339_from_micros(c.created_at_micros),
        "packageName": service.v2_package_name(&c.template_id.package_id).unwrap_or_default(),
        "representativePackageId": c.template_id.package_id,
        "acsDelta": true
    });
    // the argument is a JSON object in the JSON API and a `Record` message (named `createArguments`) over gRPC
    match proto_values() {
        Some(verbose) => {
            ev["createArguments"] = record_proto(&c.payload_value, Some(&c.template_id), verbose);
            if service
                .v2_state()
                .official_parties
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                retype_times(service, c, &mut ev["createArguments"]);
            }
        }
        None if service
            .v2_state()
            .official_parties
            .load(std::sync::atomic::Ordering::SeqCst) =>
        {
            // [CANTON-NOTE: SEMANTICS] On an official database a record field that is `None` is `null` in the argument (measured on the hub's
            // 3.7.2 participant, ACS and updates: `settlementBank: null`). AT-L08's omitted `note` was a field the contract's package version
            // did not have, which this service cannot tell from an explicit `None`, so it only keeps the plain encoding off the official mode.
            ev["createArgument"] = c.json_payload.clone()
        }
        None => {
            ev["createArgument"] = crate::payload_schema::typed_only_contract_json(
                service,
                &c.template_id,
                &c.payload_value,
            )
            .unwrap_or_else(|| value_json(&c.payload_value))
        }
    }
    ev["interfaceViews"] = Json::Array(requested_interface_views(service, c));
    order_witnesses(service, &mut ev);
    ev
}
