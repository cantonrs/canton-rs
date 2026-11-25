//! Conversion between Daml-LF values and Ledger API protobuf values, and identifier helpers.

use std::collections::BTreeSet;

use canton_proto::com::daml::ledger::api::v2 as lapi;
use lf_eval::typed_json::{format_date, format_timestamp};
use lf_eval::Value;
use serde_json::{json, Map, Value as Json};
use sha2::{Digest, Sha256};

use crate::TemplateId;

pub(super) fn lapi_identifier(tpl: &TemplateId) -> lapi::Identifier {
    lapi::Identifier {
        package_id: tpl.package_id.clone(),
        module_name: tpl.module_name.clone(),
        entity_name: tpl.entity_name.clone(),
    }
}

pub(super) use canton_algo::lapi_value::{lf_to_lapi_value, parse_colon_identifier};

pub(super) fn lapi_to_lf_and_json(val: &lapi::Value) -> Result<(Value, Json), String> {
    let Some(sum) = &val.sum else {
        return Err("missing lapi Value.sum".into());
    };
    use lapi::value::Sum;
    Ok(match sum {
        Sum::Unit(()) => (Value::Unit, json!({})),
        Sum::Bool(b) => (Value::Bool(*b), json!(b)),
        Sum::Int64(n) => (Value::Int64(*n), json!(n.to_string())),
        Sum::Timestamp(ts) => (Value::Int64(*ts), Json::String(format_timestamp(*ts))),
        Sum::Date(d) => (
            Value::Int64(i64::from(*d)),
            Json::String(format_date(i64::from(*d))),
        ),
        Sum::Numeric(s) => {
            let (coeff, scale) = parse_numeric_text(s)?;
            (Value::Numeric { coeff, scale }, Json::String(s.clone()))
        }
        Sum::Text(t) => (Value::Text(t.clone()), Json::String(t.clone())),
        Sum::Party(p) => (Value::Party(p.clone()), Json::String(p.clone())),
        Sum::ContractId(cid) => (Value::ContractId(cid.clone()), Json::String(cid.clone())),
        Sum::Optional(opt) => match &opt.value {
            None => (Value::Optional(None), Json::Null),
            Some(inner) => {
                let (lv, jv) = lapi_to_lf_and_json(inner)?;
                (Value::Optional(Some(Box::new(lv))), jv)
            }
        },
        Sum::List(list) => {
            let mut lvs = Vec::with_capacity(list.elements.len());
            let mut jvs = Vec::with_capacity(list.elements.len());
            for el in &list.elements {
                let (lv, jv) = lapi_to_lf_and_json(el)?;
                lvs.push(lv);
                jvs.push(jv);
            }
            (Value::List(lvs.into()), Json::Array(jvs))
        }
        Sum::TextMap(tm) => {
            let mut entries = Vec::with_capacity(tm.entries.len());
            let mut obj = Map::new();
            for e in &tm.entries {
                let v = e
                    .value
                    .as_ref()
                    .ok_or_else(|| "TextMap entry missing value".to_string())?;
                let (lv, jv) = lapi_to_lf_and_json(v)?;
                obj.insert(e.key.clone(), jv);
                entries.push((Value::Text(e.key.clone()), lv));
            }
            (Value::Map(entries), Json::Object(obj))
        }
        Sum::GenMap(gm) => {
            let mut entries = Vec::with_capacity(gm.entries.len());
            let mut pairs = Vec::with_capacity(gm.entries.len());
            for e in &gm.entries {
                let k = e
                    .key
                    .as_ref()
                    .ok_or_else(|| "GenMap entry missing key".to_string())?;
                let v = e
                    .value
                    .as_ref()
                    .ok_or_else(|| "GenMap entry missing value".to_string())?;
                let (lk, jk) = lapi_to_lf_and_json(k)?;
                let (lv, jv) = lapi_to_lf_and_json(v)?;
                pairs.push(Json::Array(vec![jk, jv]));
                entries.push((lk, lv));
            }
            (Value::Map(entries), Json::Array(pairs))
        }
        Sum::Record(rec) => {
            let tycon = rec
                .record_id
                .as_ref()
                .map(|id| format!("{}:{}", id.module_name, id.entity_name));
            let mut lf_fields = Vec::with_capacity(rec.fields.len());
            let mut obj = Map::new();
            for (idx, f) in rec.fields.iter().enumerate() {
                let label = if f.label.is_empty() {
                    format!("_{idx}")
                } else {
                    f.label.clone()
                };
                let v = f
                    .value
                    .as_ref()
                    .ok_or_else(|| "RecordField missing value".to_string())?;
                let (lv, jv) = lapi_to_lf_and_json(v)?;
                if !matches!(lv, Value::Optional(None)) {
                    obj.insert(label.clone(), jv);
                }
                lf_fields.push((label, lv));
            }
            (
                Value::Record {
                    tycon,
                    fields: lf_fields,
                },
                Json::Object(obj),
            )
        }
        Sum::Variant(var) => {
            let tycon = var
                .variant_id
                .as_ref()
                .map(|id| format!("{}:{}", id.module_name, id.entity_name));
            let inner = var
                .value
                .as_deref()
                .ok_or_else(|| "Variant missing value".to_string())?;
            let (lv, jv) = lapi_to_lf_and_json(inner)?;
            (
                Value::Variant {
                    tycon,
                    constructor: var.constructor.clone(),
                    rank: lf_eval::CtorRank::default(),
                    value: Box::new(lv),
                },
                json!({ "tag": var.constructor, "value": jv }),
            )
        }
        Sum::Enum(en) => {
            let tycon = en
                .enum_id
                .as_ref()
                .map(|id| format!("{}:{}", id.module_name, id.entity_name));
            (
                Value::Enum {
                    tycon,
                    constructor: en.constructor.clone(),
                    rank: lf_eval::CtorRank::default(),
                },
                Json::String(en.constructor.clone()),
            )
        }
    })
}

fn parse_numeric_text(s: &str) -> Result<(i128, u8), String> {
    let trimmed = s.trim();
    let (int_p, dec_p) = match trimmed.split_once('.') {
        Some((i, d)) => (i, d),
        None => (trimmed, ""),
    };
    let scale = u8::try_from(dec_p.len()).map_err(|_| format!("numeric scale overflow: {s}"))?;
    let combined = format!("{int_p}{dec_p}");
    let coeff = combined
        .parse::<i128>()
        .map_err(|e| format!("invalid numeric '{s}': {e}"))?;
    Ok((coeff, scale))
}

pub(super) fn derive_node_seed(tx_uuid: &str, node_id: i32) -> Vec<u8> {
    Sha256::digest(format!("canton-rs:prepare-seed:{tx_uuid}:{node_id}").as_bytes()).to_vec()
}

pub(super) fn sorted_stakeholders(sigs: &[String], obs: &[String]) -> Vec<String> {
    let mut set: BTreeSet<String> = sigs.iter().cloned().collect();
    for o in obs {
        set.insert(o.clone());
    }
    set.into_iter().collect()
}
