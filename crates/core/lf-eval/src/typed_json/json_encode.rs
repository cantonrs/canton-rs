//! Encoding of typed values as JSON (`Types::encode`).

use lf_archive::proto::daml_lf_2::def_data_type::DataCons;
use lf_archive::proto::daml_lf_2::Type;
use serde_json::Value as Json;

use crate::Value;

use super::text::{format_date, format_numeric, format_timestamp, numeric_trimmed, substitute};
use super::{string, LfType, Res, Types};

impl<'w> Types<'w> {
    /// Writes `value` of type `ty` as the Daml-LF JSON the official apps print (the inverse of [`Types::decode`]).
    ///
    /// [CANTON-NOTE: SEMANTICS] Source: the scan app's `compact_json` encoding (`ApiCodecCompressed`). `Int64` and `Numeric` are strings (a
    /// numeric at its scale), a timestamp is RFC 3339 in UTC with the fraction's trailing zeros dropped (`...:00.53937Z`, no fraction at a
    /// whole second), a record an object of every field (an absent optional is `null`), unit `{}`.
    pub fn encode(&self, ty: &LfType, value: &Value) -> Res<Json> {
        self.encode_at(ty, value, "$")
    }

    fn encode_at(&self, ty: &LfType, value: &Value, path: &str) -> Res<Json> {
        let bad = || {
            format!("{path}: {value:?} is no {ty:?}")
                .chars()
                .take(300)
                .collect::<String>()
        };
        Ok(match (ty, value) {
            (LfType::Unit, Value::Unit) => Json::Object(Default::default()),
            (LfType::Bool, Value::Bool(b)) => Json::Bool(*b),
            (LfType::Int64, Value::Int64(i)) if self.int64_numbers.get() => Json::from(*i),
            (LfType::Int64, Value::Int64(i)) => Json::String(i.to_string()),
            (LfType::Text, Value::Text(t)) => Json::String(t.clone()),
            (LfType::Party, Value::Party(p)) => Json::String(p.clone()),
            (LfType::ContractId, Value::ContractId(c)) => Json::String(c.clone()),
            (LfType::Timestamp, Value::Int64(micros)) => Json::String(format_timestamp(*micros)),
            (LfType::Date, Value::Int64(days)) => Json::String(format_date(*days)),
            (LfType::Numeric(_), Value::Numeric { coeff, scale }) => {
                Json::String(if self.ledger_numerics.get() {
                    crate::render_numeric(*coeff, *scale)
                } else if self.api_numerics.get() {
                    numeric_trimmed(*coeff, *scale)
                } else {
                    format_numeric(*coeff, *scale)
                })
            }
            (LfType::List(inner), Value::List(items)) => Json::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, v)| self.encode_at(inner, v, &format!("{path}[{i}]")))
                    .collect::<Res<Vec<_>>>()?,
            ),
            (LfType::Optional(inner), Value::Optional(content)) => match content {
                None => Json::Null,
                Some(v) if matches!(**inner, LfType::Optional(_)) => {
                    // an optional of an optional: `Some x` is `[x]`, `Some None` is `[]`
                    if matches!(**v, Value::Optional(None)) {
                        Json::Array(Vec::new())
                    } else {
                        let Value::Optional(Some(x)) = &**v else {
                            return Err(bad());
                        };
                        let LfType::Optional(innermost) = &**inner else {
                            return Err(bad());
                        };
                        Json::Array(vec![self.encode_at(innermost, x, path)?])
                    }
                }
                Some(v) => self.encode_at(inner, v, path)?,
            },
            (LfType::TextMap(inner), Value::Map(entries)) => {
                let mut object = serde_json::Map::new();
                for (k, v) in entries {
                    let Value::Text(key) = k else {
                        return Err(bad());
                    };
                    object.insert(
                        key.clone(),
                        self.encode_at(inner, v, &format!("{path}.{key}"))?,
                    );
                }
                Json::Object(object)
            }
            (LfType::GenMap(key, val), Value::Map(entries)) => Json::Array(
                entries
                    .iter()
                    .map(|(k, v)| {
                        Ok(Json::Array(vec![
                            self.encode_at(key, k, path)?,
                            self.encode_at(val, v, path)?,
                        ]))
                    })
                    .collect::<Res<Vec<_>>>()?,
            ),
            (
                LfType::Con {
                    package_id,
                    module,
                    name,
                    args,
                },
                _,
            ) => {
                let (package, def) = self.data(package_id, module, name)?;
                let params: Vec<String> = def
                    .params
                    .iter()
                    .map(|p| string(package, p.var_interned_str))
                    .collect::<Res<_>>()?;
                let field_type = |t: Option<&Type>| -> Res<LfType> {
                    let resolved = self.resolve(package_id, t.ok_or("a field without a type")?)?;
                    Ok(substitute(&resolved, &params, args))
                };
                match (
                    def.data_cons
                        .as_ref()
                        .ok_or("a data type without content")?,
                    value,
                ) {
                    (DataCons::Record(record), Value::Record { fields, .. }) => {
                        if fields.len() != record.fields.len() {
                            return Err(bad());
                        }
                        let limit = if self.remove_trailing_nones.get() {
                            fields
                                .iter()
                                .rposition(|(_, v)| !matches!(v, Value::Optional(None)))
                                .map_or(0, |i| i + 1)
                        } else {
                            fields.len()
                        };
                        let mut object = serde_json::Map::new();
                        for (f, (_, v)) in record.fields.iter().zip(fields).take(limit) {
                            if self.omit_none_fields.get() && matches!(v, Value::Optional(None)) {
                                continue;
                            }
                            let label = string(package, f.field_interned_str)?;
                            let fty = field_type(f.r#type.as_ref())?;
                            let json = self.encode_at(&fty, v, &format!("{path}.{label}"))?;
                            object.insert(label, json);
                        }
                        Json::Object(object)
                    }
                    (
                        DataCons::Variant(variant),
                        Value::Variant {
                            constructor, value, ..
                        },
                    ) => {
                        let mut found = None;
                        for f in &variant.fields {
                            if &string(package, f.field_interned_str)? == constructor {
                                found = Some(field_type(f.r#type.as_ref())?);
                            }
                        }
                        let vty = found.ok_or_else(bad)?;
                        let mut object = serde_json::Map::new();
                        object.insert("tag".into(), Json::String(constructor.clone()));
                        object.insert(
                            "value".into(),
                            self.encode_at(&vty, value, &format!("{path}.{constructor}"))?,
                        );
                        Json::Object(object)
                    }
                    (DataCons::Enum(_), Value::Enum { constructor, .. }) => {
                        Json::String(constructor.clone())
                    }
                    _ => return Err(bad()),
                }
            }
            _ => return Err(bad()),
        })
    }
}
