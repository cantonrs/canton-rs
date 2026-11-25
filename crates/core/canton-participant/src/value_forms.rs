//! A template argument in the two forms the protocol writes it (G5, F1 of `doc/performance/EQUAL-CONDITIONS.md`): the serialized value a
//! created contract carries (`LfValue`) and the typed value its hash is computed over (`HashValue`). Both come from the evaluator's [`Value`]
//! and the declared type, so a submitting participant needs no hand-written form per template.
//!
//! [CANTON-NOTE: SEMANTICS] The type is needed because the evaluator's `Value` does not say what an `Int64` is: the contract hash tells a
//! `Timestamp` (code 3) and a `Date` (code 7) from an `Int64` (code 0), and a `Numeric` is hashed by its unscaled integer at the type's scale.
//!
//! [CANTON-NOTE: LIMITATION] Everything an LF value can hold except contract ids inside a template argument (the serialized form has them,
//! the hash form does not) and types the evaluator cannot name; anything else is refused with the type named, never written approximately: the
//! two forms are checked against what the official participant accepts, so a guess here would be a contract the synchronizer rejects.
//! A map is written sorted by key (`SortedLookupList` / `TreeMap`); the entries of a text or party key are ordered by the key's text.
use crate::contract_id::HashValue;
use crate::contract_wire::LfValue;
use lf_eval::typed_json::{LfType, Types};
use lf_eval::Value;

/// Both forms of `value`, a value of `ty`.
pub fn forms(types: &Types, ty: &LfType, value: &Value) -> Result<(LfValue, HashValue), String> {
    Ok((lf_value(types, ty, value)?, hash_value(types, ty, value)?))
}

fn refuse(ty: &LfType, value: &Value) -> String {
    format!("a value of type {ty:?} written as {value:?} has no protocol form here")
}

/// The scale of a numeric type: the type's, else the value's.
fn scale_of(ty: &LfType, found: u8) -> u8 {
    match ty {
        LfType::Numeric(Some(s)) => *s,
        _ => found,
    }
}

/// `coeff` (at `scale`) at `target` scale; `None` when digits would be lost.
fn rescale(coeff: i128, scale: u8, target: u8) -> Option<i128> {
    match target.cmp(&scale) {
        std::cmp::Ordering::Equal => Some(coeff),
        std::cmp::Ordering::Greater => {
            coeff.checked_mul(10i128.checked_pow(u32::from(target - scale))?)
        }
        std::cmp::Ordering::Less => {
            let divisor = 10i128.checked_pow(u32::from(scale - target))?;
            (coeff % divisor == 0).then_some(coeff / divisor)
        }
    }
}

/// The text of a numeric at its full scale (`100.5000000000`, `-3.2500000000`).
fn numeric_text(unscaled: i128, scale: u8) -> String {
    let negative = unscaled < 0;
    let digits = unscaled.unsigned_abs().to_string();
    let scale = usize::from(scale);
    let padded = if digits.len() <= scale {
        format!("{digits:0>width$}", width = scale + 1)
    } else {
        digits
    };
    let (whole, frac) = padded.split_at(padded.len() - scale);
    let sign = if negative { "-" } else { "" };
    if scale == 0 {
        format!("{sign}{whole}")
    } else {
        format!("{sign}{whole}.{frac}")
    }
}

/// Only the serialized form of `value` (the chosen value of an exercise is serialized and not hashed, so it may hold contract ids).
pub fn lf_form(types: &Types, ty: &LfType, value: &Value) -> Result<LfValue, String> {
    lf_value(types, ty, value)
}

fn lf_value(types: &Types, ty: &LfType, value: &Value) -> Result<LfValue, String> {
    Ok(match (ty, value) {
        (LfType::Unit, Value::Unit) => LfValue::Unit,
        (LfType::Bool, Value::Bool(b)) => LfValue::Bool(*b),
        (LfType::Int64, Value::Int64(i)) => LfValue::Int64(*i),
        (LfType::Text, Value::Text(t)) => LfValue::Text(t.clone()),
        (LfType::Party, Value::Party(p)) => LfValue::Party(p.clone()),
        // [CANTON-NOTE: SEMANTICS] A contract id is written as its bytes (the id is hex of them); a value that is not hex is no contract id of the
        // protocol and is refused here instead of reaching the encoder, which takes hex for granted. Only the serialized form has it: a contract
        // id in a template argument has no hash form here (`hash_value`), so a contract with one is still refused. An engine's temporary id (`#1`)
        // passes as it is: it names a contract the same transaction creates and `view_tree::build_transaction` replaces it (`Transaction::temp_ids`).
        (LfType::ContractId, Value::ContractId(id))
            if hex::decode(id).is_ok() || id.starts_with('#') =>
        {
            LfValue::ContractId(id.clone())
        }
        (LfType::Numeric(_), Value::Numeric { coeff, scale }) => {
            let target = scale_of(ty, *scale);
            let unscaled = rescale(*coeff, *scale, target).ok_or_else(|| refuse(ty, value))?;
            LfValue::Numeric(numeric_text(unscaled, target))
        }
        (LfType::Timestamp, Value::Int64(micros)) => LfValue::Timestamp(*micros),
        (LfType::Date, Value::Int64(days)) => {
            LfValue::Date(i32::try_from(*days).map_err(|_| refuse(ty, value))?)
        }
        (LfType::Optional(_), Value::Optional(None)) => LfValue::Optional(None),
        (LfType::Optional(inner), Value::Optional(Some(v))) => {
            LfValue::Optional(Some(Box::new(lf_value(types, inner, v)?)))
        }
        (LfType::TextMap(item), Value::Map(entries)) => LfValue::TextMap(
            sorted_by_key(entries)
                .into_iter()
                .map(|(k, v)| match k {
                    Value::Text(k) => Ok((k.clone(), lf_value(types, item, v)?)),
                    _ => Err(refuse(ty, value)),
                })
                .collect::<Result<_, String>>()?,
        ),
        (LfType::GenMap(key, item), Value::Map(entries)) => LfValue::GenMap(
            sorted_by_key(entries)
                .into_iter()
                .map(|(k, v)| Ok((lf_value(types, key, k)?, lf_value(types, item, v)?)))
                .collect::<Result<_, String>>()?,
        ),
        (
            LfType::Con { .. },
            Value::Variant {
                constructor,
                value: inner,
                ..
            },
        ) => {
            let declared = types.constructors(ty)?;
            let (_, vty) = declared
                .iter()
                .find(|(n, _)| n == constructor)
                .ok_or_else(|| refuse(ty, value))?;
            LfValue::Variant(constructor.clone(), Box::new(lf_value(types, vty, inner)?))
        }
        (LfType::Con { .. }, Value::Enum { constructor, .. }) => LfValue::Enum(constructor.clone()),
        (LfType::List(item), Value::List(items)) => LfValue::List(
            items
                .iter()
                .map(|v| lf_value(types, item, v))
                .collect::<Result<_, _>>()?,
        ),
        (LfType::Con { .. }, Value::Record { fields, .. }) => {
            let declared = types.record_fields(ty)?;
            LfValue::Record(
                ordered(&declared, fields, ty)?
                    .into_iter()
                    .map(|(t, v)| lf_value(types, t, v))
                    .collect::<Result<_, _>>()?,
            )
        }
        _ => return Err(refuse(ty, value)),
    })
}

/// Only the typed hash form of `value`, a value of `ty` (the receiving side hashes a contract's arguments with the type the template declares).
pub fn hash_form(types: &Types, ty: &LfType, value: &Value) -> Result<HashValue, String> {
    hash_value(types, ty, value)
}

fn hash_value(types: &Types, ty: &LfType, value: &Value) -> Result<HashValue, String> {
    Ok(match (ty, value) {
        (LfType::Unit, Value::Unit) => HashValue::Unit,
        (LfType::Bool, Value::Bool(b)) => HashValue::Bool(*b),
        (LfType::Int64, Value::Int64(i)) => HashValue::Int64(*i),
        (LfType::Timestamp, Value::Int64(micros)) => HashValue::Timestamp(*micros),
        (LfType::Date, Value::Int64(days)) => {
            HashValue::Date(i32::try_from(*days).map_err(|_| refuse(ty, value))?)
        }
        (LfType::Text, Value::Text(t)) => HashValue::Text(t.clone()),
        (LfType::Party, Value::Party(p)) => HashValue::Party(p.clone()),
        (LfType::Numeric(_), Value::Numeric { coeff, scale }) => {
            let target = scale_of(ty, *scale);
            HashValue::Numeric(rescale(*coeff, *scale, target).ok_or_else(|| refuse(ty, value))?)
        }
        // a contract id in a template argument is hashed by its bytes (`addCid`); one that is not hex yet (an engine's temporary id for a contract
        // the same transaction creates) has no bytes: such a create is refused (the id of a contract that holds it would depend on it twice)
        (LfType::ContractId, Value::ContractId(id)) => {
            HashValue::ContractId(hex::decode(id).map_err(|_| refuse(ty, value))?)
        }
        (LfType::Optional(_), Value::Optional(None)) => HashValue::Optional(None),
        (LfType::Optional(inner), Value::Optional(Some(v))) => {
            HashValue::Optional(Some(Box::new(hash_value(types, inner, v)?)))
        }
        (LfType::List(item), Value::List(items)) => HashValue::List(
            items
                .iter()
                .map(|v| hash_value(types, item, v))
                .collect::<Result<_, _>>()?,
        ),
        (LfType::TextMap(item), Value::Map(entries)) => HashValue::TextMap(
            sorted_by_key(entries)
                .into_iter()
                .map(|(k, v)| match k {
                    Value::Text(k) => Ok((k.clone(), hash_value(types, item, v)?)),
                    _ => Err(refuse(ty, value)),
                })
                .collect::<Result<_, String>>()?,
        ),
        (LfType::GenMap(key, item), Value::Map(entries)) => HashValue::GenMap(
            sorted_by_key(entries)
                .into_iter()
                .map(|(k, v)| Ok((hash_value(types, key, k)?, hash_value(types, item, v)?)))
                .collect::<Result<_, String>>()?,
        ),
        (
            LfType::Con { module, name, .. },
            Value::Variant {
                constructor,
                value: inner,
                ..
            },
        ) => {
            let declared = types.constructors(ty)?;
            let (rank, (_, vty)) = declared
                .iter()
                .enumerate()
                .find(|(_, (n, _))| n == constructor)
                .ok_or_else(|| refuse(ty, value))?;
            HashValue::Variant {
                module: module.split('.').map(String::from).collect(),
                name: name.split('.').map(String::from).collect(),
                constructor: constructor.clone(),
                rank: rank as i32,
                value: Box::new(hash_value(types, vty, inner)?),
            }
        }
        (LfType::Con { module, name, .. }, Value::Enum { constructor, .. }) => {
            let declared = types.constructors(ty)?;
            let rank = declared
                .iter()
                .position(|(n, _)| n == constructor)
                .ok_or_else(|| refuse(ty, value))?;
            HashValue::Enum {
                module: module.split('.').map(String::from).collect(),
                name: name.split('.').map(String::from).collect(),
                constructor: constructor.clone(),
                rank: rank as i32,
            }
        }
        (LfType::Con { module, name, .. }, Value::Record { fields, .. }) => {
            let declared = types.record_fields(ty)?;
            let labelled = ordered(&declared, fields, ty)?;
            HashValue::Record {
                module: module.split('.').map(String::from).collect(),
                name: name.split('.').map(String::from).collect(),
                fields: declared
                    .iter()
                    .zip(labelled)
                    .map(|((label, _), (t, v))| Ok((label.clone(), hash_value(types, t, v)?)))
                    .collect::<Result<_, String>>()?,
            }
        }
        _ => return Err(refuse(ty, value)),
    })
}

/// The entries of a map ordered by key: text and party keys by their text, other keys as they are.
fn sorted_by_key(entries: &[(Value, Value)]) -> Vec<(&Value, &Value)> {
    let mut sorted: Vec<(&Value, &Value)> = entries.iter().map(|(k, v)| (k, v)).collect();
    let text = |v: &Value| match v {
        Value::Text(t) | Value::Party(t) => Some(t.clone()),
        _ => None,
    };
    if sorted.iter().all(|(k, _)| text(k).is_some()) {
        sorted.sort_by_key(|(k, _)| text(k));
    }
    sorted
}

/// The record's values in the type's declaration order, each with its declared type; a field the value lacks or an extra one is an error.
fn ordered<'a>(
    declared: &'a [(String, LfType)],
    fields: &'a [(String, Value)],
    ty: &LfType,
) -> Result<Vec<(&'a LfType, &'a Value)>, String> {
    if declared.len() != fields.len() {
        return Err(format!(
            "{ty:?} has {} fields, the value {}",
            declared.len(),
            fields.len()
        ));
    }
    declared
        .iter()
        .map(|(label, t)| {
            fields
                .iter()
                .find(|(n, _)| n == label)
                .map(|(_, v)| (t, v))
                .ok_or_else(|| format!("{ty:?}: the value has no field {label}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numerics_are_written_at_their_full_scale() {
        assert_eq!(numeric_text(1_005_000_000_000, 10), "100.5000000000");
        assert_eq!(numeric_text(-32_500_000_000, 10), "-3.2500000000");
        assert_eq!(numeric_text(5, 10), "0.0000000005");
        assert_eq!(numeric_text(42, 0), "42");
        assert_eq!(rescale(1005, 1, 10), Some(1_005_000_000_000));
        assert_eq!(rescale(10_000, 4, 1), Some(10));
        assert_eq!(rescale(10_051, 4, 1), None);
    }
}
