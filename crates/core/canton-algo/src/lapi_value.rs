//! A Daml-LF value as the Ledger API writes it (`com.daml.ledger.api.v2.Value`): what an interactive submission's prepared transaction
//! carries and its hash covers. One conversion for the JSON API's `prepare` and the participant's recomputation of an externally signed
//! hash (U-56).
//!
//! [CANTON-NOTE: SEMANTICS] With the value's Daml-LF type, a record carries its record id and field labels and a timestamp or date its
//! own case (the enrichment `TransactionEnricher` adds before hashing); a `Numeric` is written with all the digits of its scale.
use canton_proto::com::daml::ledger::api::v2 as lapi;
use lf_eval::typed_json::{LfType, Types};
use lf_eval::{render_numeric, Value};

/// The value as the Ledger API writes it; `types_ty` gives labels, record ids and the timestamp/date cases when known.
fn format_numeric_for_proto(coeff: i128, scale: u8) -> String {
    let s = render_numeric(coeff, scale);
    // Keep canonical integer decimal dot if scale > 0 or matches Canton Numeric.toString
    if scale == 0 && !s.contains('.') {
        format!("{s}.")
    } else if !s.contains('.') {
        let mut out = format!("{s}.");
        for _ in 0..scale {
            out.push('0');
        }
        out
    } else {
        // pad trailing zeros to `scale` when `render_numeric` trimmed them
        let (int_p, dec_p) = s.split_once('.').unwrap_or((&s, ""));
        if dec_p.len() < scale as usize {
            let mut out = format!("{int_p}.{dec_p}");
            for _ in dec_p.len()..(scale as usize) {
                out.push('0');
            }
            out
        } else {
            s
        }
    }
}

pub fn lf_to_lapi_value(types_ty: Option<(&Types<'_>, &LfType)>, val: &Value) -> lapi::Value {
    let sum = match (types_ty, val) {
        (_, Value::Unit) => lapi::value::Sum::Unit(()),
        (_, Value::Bool(b)) => lapi::value::Sum::Bool(*b),
        (Some((_, LfType::Timestamp)), Value::Int64(n)) => lapi::value::Sum::Timestamp(*n),
        (Some((_, LfType::Date)), Value::Int64(n)) => lapi::value::Sum::Date(*n as i32),
        (_, Value::Int64(n)) => lapi::value::Sum::Int64(*n),
        (_, Value::Numeric { coeff, scale }) => {
            lapi::value::Sum::Numeric(format_numeric_for_proto(*coeff, *scale))
        }
        (_, Value::Text(t)) => lapi::value::Sum::Text(t.clone()),
        (_, Value::Party(p)) => lapi::value::Sum::Party(p.clone()),
        (_, Value::ContractId(c)) => lapi::value::Sum::ContractId(c.clone()),
        (Some((types, LfType::Optional(inner))), Value::Optional(opt)) => {
            lapi::value::Sum::Optional(Box::new(lapi::Optional {
                value: opt
                    .as_deref()
                    .map(|v| Box::new(lf_to_lapi_value(Some((types, inner)), v))),
            }))
        }
        (None, Value::Optional(opt)) => lapi::value::Sum::Optional(Box::new(lapi::Optional {
            value: opt.as_deref().map(|v| Box::new(lf_to_lapi_value(None, v))),
        })),
        (Some((types, LfType::List(inner))), Value::List(list)) => {
            lapi::value::Sum::List(lapi::List {
                elements: list
                    .iter()
                    .map(|x| lf_to_lapi_value(Some((types, inner)), x))
                    .collect(),
            })
        }
        (None, Value::List(list)) => lapi::value::Sum::List(lapi::List {
            elements: list.iter().map(|x| lf_to_lapi_value(None, x)).collect(),
        }),
        (Some((types, LfType::TextMap(inner))), Value::Map(entries)) => {
            lapi::value::Sum::TextMap(lapi::TextMap {
                entries: entries
                    .iter()
                    .filter_map(|(k, v)| match k {
                        Value::Text(key) => Some(lapi::text_map::Entry {
                            key: key.clone(),
                            value: Some(lf_to_lapi_value(Some((types, inner)), v)),
                        }),
                        _ => None,
                    })
                    .collect(),
            })
        }
        (Some((types, LfType::GenMap(k_ty, v_ty))), Value::Map(entries)) => {
            lapi::value::Sum::GenMap(lapi::GenMap {
                entries: entries
                    .iter()
                    .map(|(k, v)| lapi::gen_map::Entry {
                        key: Some(lf_to_lapi_value(Some((types, k_ty)), k)),
                        value: Some(lf_to_lapi_value(Some((types, v_ty)), v)),
                    })
                    .collect(),
            })
        }
        (None, Value::Map(entries)) => {
            if entries.iter().all(|(k, _)| matches!(k, Value::Text(_))) {
                lapi::value::Sum::TextMap(lapi::TextMap {
                    entries: entries
                        .iter()
                        .filter_map(|(k, v)| match k {
                            Value::Text(key) => Some(lapi::text_map::Entry {
                                key: key.clone(),
                                value: Some(lf_to_lapi_value(None, v)),
                            }),
                            _ => None,
                        })
                        .collect(),
                })
            } else {
                lapi::value::Sum::GenMap(lapi::GenMap {
                    entries: entries
                        .iter()
                        .map(|(k, v)| lapi::gen_map::Entry {
                            key: Some(lf_to_lapi_value(None, k)),
                            value: Some(lf_to_lapi_value(None, v)),
                        })
                        .collect(),
                })
            }
        }
        (
            Some((
                types,
                ty @ LfType::Con {
                    package_id,
                    module,
                    name,
                    ..
                },
            )),
            Value::Record { fields, .. },
        ) => {
            let field_types: std::collections::BTreeMap<String, LfType> = types
                .record_fields(ty)
                .unwrap_or_default()
                .into_iter()
                .collect();
            lapi::value::Sum::Record(lapi::Record {
                record_id: Some(lapi::Identifier {
                    package_id: package_id.clone(),
                    module_name: module.clone(),
                    entity_name: name.clone(),
                }),
                fields: fields
                    .iter()
                    .map(|(label, v)| lapi::RecordField {
                        label: label.clone(),
                        value: Some(lf_to_lapi_value(
                            field_types.get(label).map(|ft| (types, ft)),
                            v,
                        )),
                    })
                    .collect(),
            })
        }
        (None, Value::Record { tycon, fields }) => lapi::value::Sum::Record(lapi::Record {
            record_id: tycon.as_deref().map(|t| parse_colon_identifier(t, "")),
            fields: fields
                .iter()
                .map(|(label, v)| lapi::RecordField {
                    label: label.clone(),
                    value: Some(lf_to_lapi_value(None, v)),
                })
                .collect(),
        }),
        (
            Some((
                types,
                ty @ LfType::Con {
                    package_id,
                    module,
                    name,
                    ..
                },
            )),
            Value::Variant {
                constructor, value, ..
            },
        ) => {
            let inner_ty = types
                .constructors(ty)
                .ok()
                .and_then(|cs| cs.into_iter().find(|(c, _)| c == constructor))
                .map(|(_, t)| t);
            lapi::value::Sum::Variant(Box::new(lapi::Variant {
                variant_id: Some(lapi::Identifier {
                    package_id: package_id.clone(),
                    module_name: module.clone(),
                    entity_name: name.clone(),
                }),
                constructor: constructor.clone(),
                value: Some(Box::new(lf_to_lapi_value(
                    inner_ty.as_ref().map(|t| (types, t)),
                    value,
                ))),
            }))
        }
        (
            None,
            Value::Variant {
                tycon,
                constructor,
                value,
                ..
            },
        ) => lapi::value::Sum::Variant(Box::new(lapi::Variant {
            variant_id: tycon.as_deref().map(|t| parse_colon_identifier(t, "")),
            constructor: constructor.clone(),
            value: Some(Box::new(lf_to_lapi_value(None, value))),
        })),
        (
            Some((
                _,
                LfType::Con {
                    package_id,
                    module,
                    name,
                    ..
                },
            )),
            Value::Enum { constructor, .. },
        ) => lapi::value::Sum::Enum(lapi::Enum {
            enum_id: Some(lapi::Identifier {
                package_id: package_id.clone(),
                module_name: module.clone(),
                entity_name: name.clone(),
            }),
            constructor: constructor.clone(),
        }),
        (
            None,
            Value::Enum {
                tycon, constructor, ..
            },
        ) => lapi::value::Sum::Enum(lapi::Enum {
            enum_id: tycon.as_deref().map(|t| parse_colon_identifier(t, "")),
            constructor: constructor.clone(),
        }),
        (_, other) => lapi::value::Sum::Text(format!("{other:?}")),
    };
    lapi::Value { sum: Some(sum) }
}

/// A `[pkg:]Module:Name` identifier as the Ledger API writes it, with `default_pkg` when the package is not named.
pub fn parse_colon_identifier(s: &str, default_pkg: &str) -> lapi::Identifier {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.as_slice() {
        [pkg, module, entity] => lapi::Identifier {
            package_id: (*pkg).to_string(),
            module_name: (*module).to_string(),
            entity_name: (*entity).to_string(),
        },
        [module, entity] => lapi::Identifier {
            package_id: default_pkg.to_string(),
            module_name: (*module).to_string(),
            entity_name: (*entity).to_string(),
        },
        _ => lapi::Identifier {
            package_id: default_pkg.to_string(),
            module_name: String::new(),
            entity_name: s.to_string(),
        },
    }
}
