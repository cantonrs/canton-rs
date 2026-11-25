use crate::models::ledger_api::TemplateId;
use crate::service::{ExecutionService, GenericContract};
use lf_eval::{render_numeric, Value};
use serde_json::{json, Map, Value as Json};

thread_local! {
    /// While set, values are written the way the gRPC `Value`/`Record` messages are (protobuf JSON): the flag is whether
    /// field labels and record ids are included (`verbose`). The gRPC bridge sets it around a dispatched request.
    static PROTO_VALUES: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Runs `f` with values written in the gRPC (protobuf JSON) encoding.
pub fn with_proto_values<R>(verbose: bool, f: impl FnOnce() -> R) -> R {
    let previous = PROTO_VALUES.replace(Some(verbose));
    let out = f();
    PROTO_VALUES.set(previous);
    out
}

pub(crate) fn proto_values() -> Option<bool> {
    PROTO_VALUES.get()
}

/// A template id as the JSON API writes it (`package:Module:Entity`) or, over gRPC, as an `Identifier` message.
pub(crate) fn template_value(t: &TemplateId) -> Json {
    if proto_values().is_some() {
        json!({ "packageId": t.package_id, "moduleName": t.module_name, "entityName": t.entity_name })
    } else {
        json!(t.to_string())
    }
}

pub(super) fn identifier_json(tycon: &str, package_id: &str) -> Json {
    let (module, entity) = tycon.rsplit_once(':').unwrap_or(("", tycon));
    json!({ "packageId": package_id, "moduleName": module, "entityName": entity })
}

/// Writes the `Time` and `Date` fields of a contract argument given as a protobuf `Record` the way the Ledger API does (`timestamp`, `date`) instead of as
/// the `int64` the evaluator's value keeps them as (only the declared types say which numbers are times). Reads the types of the contract's package; a contract
/// whose types are not known is left as it is.
///
/// [CANTON-NOTE: SEMANTICS] Measured on the hub's participant over gRPC (`GetUpdates`): a `Time` field is `{"timestamp": "1794486802862811"}` and a `Date`
/// field inside an `Optional` is `{"optional": {"value": {"date": 20788}}}`.
pub(super) fn retype_times(service: &ExecutionService, c: &GenericContract, record: &mut Json) {
    use lf_eval::typed_json::{LfType, Types};
    fn walk(types: &Types, ty: &LfType, value: &mut Json) {
        match ty {
            LfType::Timestamp => {
                if let Some(n) = value.get("int64").cloned() {
                    *value = json!({ "timestamp": n });
                }
            }
            LfType::Date => {
                if let Some(n) = value.get("int64").cloned() {
                    // a date is a number of days, written as a number
                    *value = json!({ "date": n.as_str().and_then(|t| t.parse::<i64>().ok()).map_or(n, |d| json!(d)) });
                }
            }
            LfType::Optional(inner) => {
                if let Some(x) = value.pointer_mut("/optional/value") {
                    walk(types, inner, x);
                }
            }
            LfType::List(inner) => {
                if let Some(items) = value
                    .pointer_mut("/list/elements")
                    .and_then(Json::as_array_mut)
                {
                    for x in items {
                        walk(types, inner, x);
                    }
                }
            }
            LfType::Con { .. } => {
                if let (Ok(fields), Some(items)) = (
                    types.record_fields(ty),
                    value
                        .pointer_mut("/record/fields")
                        .and_then(Json::as_array_mut),
                ) {
                    for ((_, field_type), item) in fields.iter().zip(items) {
                        if let Some(x) = item.get_mut("value") {
                            walk(types, field_type, x);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let Some(package) = service.v2_lf_package(&c.template_id.package_id) else {
        return;
    };
    let types = Types::new(&package.world);
    let local = format!(
        "{}:{}",
        c.template_id.module_name, c.template_id.entity_name
    );
    let Ok(ty) = types.template(&c.template_id.package_id, &local) else {
        return;
    };
    let (Ok(fields), Some(items)) = (
        types.record_fields(&ty),
        record.get_mut("fields").and_then(Json::as_array_mut),
    ) else {
        return;
    };
    for ((_, field_type), item) in fields.iter().zip(items) {
        if let Some(x) = item.get_mut("value") {
            walk(&types, field_type, x);
        }
    }
}

/// A record as a `Record` message: the fields (with labels when verbose) and, when verbose, its record id.
pub(crate) fn record_proto(v: &Value, id: Option<&TemplateId>, verbose: bool) -> Json {
    let Value::Record { tycon, fields } = v else {
        return json!({});
    };
    let mut out = Map::new();
    if verbose {
        if let Some(t) = id {
            out.insert(
                "recordId".into(),
                json!({ "packageId": t.package_id, "moduleName": t.module_name, "entityName": t.entity_name }),
            );
        } else if let Some(t) = tycon {
            out.insert("recordId".into(), identifier_json(t, ""));
        }
    }
    out.insert(
        "fields".into(),
        Json::Array(
            fields
                .iter()
                .map(|(label, x)| {
                    if verbose {
                        json!({ "label": label, "value": value_proto(x, verbose) })
                    } else {
                        json!({ "value": value_proto(x, verbose) })
                    }
                })
                .collect(),
        ),
    );
    Json::Object(out)
}

/// A Daml value as a `Value` message in protobuf JSON.
pub(crate) fn value_proto(v: &Value, verbose: bool) -> Json {
    match v {
        Value::Int64(n) => json!({ "int64": n.to_string() }),
        Value::Numeric { coeff, scale } => json!({ "numeric": render_numeric(*coeff, *scale) }),
        Value::Text(t) => json!({ "text": t }),
        Value::Party(t) => json!({ "party": t }),
        Value::ContractId(t) => json!({ "contractId": t }),
        Value::Bool(b) => json!({ "bool": b }),
        Value::Unit => json!({ "unit": {} }),
        Value::List(items) => {
            json!({ "list": { "elements": items.iter().map(|x| value_proto(x, verbose)).collect::<Vec<_>>() } })
        }
        Value::Optional(None) => json!({ "optional": {} }),
        Value::Optional(Some(inner)) => {
            json!({ "optional": { "value": value_proto(inner, verbose) } })
        }
        Value::Record { .. } => json!({ "record": record_proto(v, None, verbose) }),
        Value::Variant {
            constructor,
            value,
            tycon,
            ..
        } => {
            let mut m = Map::new();
            if verbose {
                if let Some(t) = tycon {
                    m.insert("variantId".into(), identifier_json(t, ""));
                }
            }
            m.insert("constructor".into(), json!(constructor));
            m.insert("value".into(), value_proto(value, verbose));
            json!({ "variant": m })
        }
        Value::Enum {
            constructor, tycon, ..
        } => {
            let mut m = Map::new();
            if verbose {
                if let Some(t) = tycon {
                    m.insert("enumId".into(), identifier_json(t, ""));
                }
            }
            m.insert("constructor".into(), json!(constructor));
            json!({ "enum": m })
        }
        other => json!({ "text": format!("{other:?}") }),
    }
}

/// Type-aware protobuf-JSON encoder (`Value` message) handling `Timestamp`, `Date`, `TextMap`, and `GenMap`.
pub(super) fn value_proto_typed(
    types: &lf_eval::typed_json::Types<'_>,
    ty: &lf_eval::typed_json::LfType,
    v: &Value,
    verbose: bool,
) -> Json {
    use lf_eval::typed_json::LfType;
    match (ty, v) {
        (LfType::Timestamp, Value::Int64(n)) => json!({ "timestamp": n.to_string() }),
        (LfType::Date, Value::Int64(n)) => json!({ "date": n }),
        (LfType::TextMap(inner), Value::Map(entries)) => {
            let items: Vec<Json> = entries
                .iter()
                .filter_map(|(k, val)| {
                    let Value::Text(ks) = k else { return None };
                    Some(json!({
                        "key": ks,
                        "value": value_proto_typed(types, inner, val, verbose),
                    }))
                })
                .collect();
            json!({ "textMap": { "entries": items } })
        }
        (LfType::GenMap(kty, vty), Value::Map(entries)) => {
            let items: Vec<Json> = entries
                .iter()
                .map(|(k, val)| {
                    json!({
                        "key": value_proto_typed(types, kty, k, verbose),
                        "value": value_proto_typed(types, vty, val, verbose),
                    })
                })
                .collect();
            json!({ "genMap": { "entries": items } })
        }
        (LfType::Optional(_), Value::Optional(None)) => json!({ "optional": {} }),
        (LfType::Optional(inner), Value::Optional(Some(x))) => {
            json!({ "optional": { "value": value_proto_typed(types, inner, x, verbose) } })
        }
        (LfType::List(inner), Value::List(items)) => json!({
            "list": {
                "elements": items
                    .iter()
                    .map(|x| value_proto_typed(types, inner, x, verbose))
                    .collect::<Vec<_>>()
            }
        }),
        (
            LfType::Con {
                package_id,
                module,
                name,
                ..
            },
            Value::Record { fields, .. },
        ) => {
            let Ok(spec) = types.record_fields(ty) else {
                return value_proto(v, verbose);
            };
            if spec.len() != fields.len() {
                return value_proto(v, verbose);
            }
            let mut out = Map::new();
            if verbose {
                out.insert(
                    "recordId".into(),
                    json!({ "packageId": package_id, "moduleName": module, "entityName": name }),
                );
            }
            let encoded_fields: Vec<Json> = spec
                .iter()
                .zip(fields)
                .map(|((label, fty), (_, fv))| {
                    let ev = value_proto_typed(types, fty, fv, verbose);
                    if verbose {
                        json!({ "label": label, "value": ev })
                    } else {
                        json!({ "value": ev })
                    }
                })
                .collect();
            out.insert("fields".into(), Json::Array(encoded_fields));
            json!({ "record": Json::Object(out) })
        }
        (
            LfType::Con {
                package_id,
                module,
                name,
                ..
            },
            Value::Variant {
                constructor, value, ..
            },
        ) => {
            let Ok(cons) = types.constructors(ty) else {
                return value_proto(v, verbose);
            };
            let Some((_, vty)) = cons.into_iter().find(|(c, _)| c == constructor) else {
                return value_proto(v, verbose);
            };
            let mut m = Map::new();
            if verbose {
                m.insert(
                    "variantId".into(),
                    json!({ "packageId": package_id, "moduleName": module, "entityName": name }),
                );
            }
            m.insert("constructor".into(), json!(constructor));
            m.insert(
                "value".into(),
                value_proto_typed(types, &vty, value, verbose),
            );
            json!({ "variant": Json::Object(m) })
        }
        (
            LfType::Con {
                package_id,
                module,
                name,
                ..
            },
            Value::Enum { constructor, .. },
        ) => {
            let mut m = Map::new();
            if verbose {
                m.insert(
                    "enumId".into(),
                    json!({ "packageId": package_id, "moduleName": module, "entityName": name }),
                );
            }
            m.insert("constructor".into(), json!(constructor));
            json!({ "enum": Json::Object(m) })
        }
        _ => value_proto(v, verbose),
    }
}

/// The stakeholders of a contract among `witnesses`, each once (a party can be signatory and observer at once).
pub(super) fn witnesses_of<'a>(c: &'a GenericContract, witnesses: &[String]) -> Vec<&'a String> {
    let mut out: Vec<&String> = Vec::new();
    for p in c.signatories.iter().chain(&c.observers) {
        if witnesses.contains(p) && !out.contains(&p) {
            out.push(p);
        }
    }
    out
}
