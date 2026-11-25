//! The protobuf wire form of typed values (`Types::to_wire`, `Types::from_wire`).

use lf_archive::proto::daml_lf_2::def_data_type::DataCons;
use lf_archive::proto::daml_lf_2::Type;

use crate::{CtorRank, Value};

use super::text::{numeric_plain, rescale_exact, substitute};
use super::{string, LfType, Res, Types};

impl Types<'_> {
    /// The value as the protocol serializes it: the bare `com.digitalasset.daml.lf.value.Value` message of a contract instance's `create_arg`
    /// (G8, S-SPL-008).
    ///
    /// [CANTON-NOTE: SEMANTICS] Source: Daml-LF `ValueCoder.encodeValue` as the Canton 3.7.2 contract coder uses it (serialization version
    /// "2.1"): a record is a list of its fields **without labels** and without a record id, a variant carries its constructor name and no
    /// variant id, an enum its constructor, a numeric its decimal string at its scale (`Numeric.toString`), a contract id its raw bytes, a
    /// date the day count (`int32`), a record without its trailing `None` fields, a timestamp the microseconds (`sfixed64`), a `None` is an empty `Optional`, a text map the entries
    /// in the map's order.
    pub fn to_wire(&self, ty: &LfType, value: &Value) -> Res<Vec<u8>> {
        let bad = || {
            format!("{value:?} is no {ty:?}")
                .chars()
                .take(300)
                .collect::<String>()
        };
        let mut out = Vec::new();
        match (ty, value) {
            (LfType::Unit, Value::Unit) => wire_field(&mut out, 1, &[]),
            (LfType::Bool, Value::Bool(b)) => {
                wire_tag(&mut out, 2, 0);
                wire_varint(&mut out, u64::from(*b));
            }
            (LfType::Int64, Value::Int64(i)) => {
                wire_tag(&mut out, 3, 0);
                wire_varint(&mut out, ((*i << 1) ^ (*i >> 63)) as u64);
            }
            (LfType::Date, Value::Int64(days)) => {
                wire_tag(&mut out, 4, 0);
                wire_varint(&mut out, *days as i32 as i64 as u64);
            }
            (LfType::Timestamp, Value::Int64(micros)) => {
                wire_tag(&mut out, 5, 1);
                out.extend_from_slice(&micros.to_le_bytes());
            }
            (LfType::Numeric(expected_scale), Value::Numeric { coeff, scale }) => {
                let (coeff, scale) = match expected_scale {
                    Some(target) => (
                        rescale_exact(*coeff, *scale, *target).ok_or_else(|| {
                            format!("numeric value cannot be represented at scale {target}")
                        })?,
                        *target,
                    ),
                    None => (*coeff, *scale),
                };
                wire_field(&mut out, 6, numeric_plain(coeff, scale).as_bytes())
            }
            (LfType::Party, Value::Party(p)) => wire_field(&mut out, 7, p.as_bytes()),
            (LfType::Text, Value::Text(t)) => wire_field(&mut out, 8, t.as_bytes()),
            (LfType::ContractId, Value::ContractId(c)) => {
                let bytes = (0..c.len() / 2)
                    .map(|i| u8::from_str_radix(&c[2 * i..2 * i + 2], 16))
                    .collect::<Result<Vec<u8>, _>>()
                    .map_err(|_| format!("contract id {c} is not hex"))?;
                wire_field(&mut out, 9, &bytes)
            }
            (LfType::List(inner), Value::List(items)) => {
                let mut list = Vec::new();
                for v in items.iter() {
                    wire_field(&mut list, 1, &self.to_wire(inner, v)?);
                }
                wire_field(&mut out, 11, &list)
            }
            (LfType::Optional(inner), Value::Optional(content)) => {
                let mut optional = Vec::new();
                if let Some(v) = content {
                    wire_field(&mut optional, 1, &self.to_wire(inner, v)?);
                }
                wire_field(&mut out, 10, &optional)
            }
            (LfType::TextMap(inner), Value::Map(entries)) => {
                let mut map = Vec::new();
                for (k, v) in entries {
                    let Value::Text(key) = k else {
                        return Err(bad());
                    };
                    let mut entry = Vec::new();
                    wire_field(&mut entry, 1, key.as_bytes());
                    wire_field(&mut entry, 2, &self.to_wire(inner, v)?);
                    wire_field(&mut map, 1, &entry);
                }
                wire_field(&mut out, 16, &map)
            }
            (LfType::GenMap(key, val), Value::Map(entries)) => {
                let mut map = Vec::new();
                for (k, v) in entries {
                    let mut entry = Vec::new();
                    wire_field(&mut entry, 1, &self.to_wire(key, k)?);
                    wire_field(&mut entry, 2, &self.to_wire(val, v)?);
                    wire_field(&mut map, 1, &entry);
                }
                wire_field(&mut out, 12, &map)
            }
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
                        let mut message = Vec::new();
                        // a record is written without its trailing `None` fields (what a later version of the template may add)
                        let kept = fields
                            .iter()
                            .rposition(|(_, v)| !matches!(v, Value::Optional(None)))
                            .map_or(0, |i| i + 1);
                        for (f, (_, v)) in record.fields.iter().zip(fields).take(kept) {
                            let fty = field_type(f.r#type.as_ref())?;
                            let mut field = Vec::new();
                            wire_field(&mut field, 1, &self.to_wire(&fty, v)?);
                            wire_field(&mut message, 1, &field);
                        }
                        wire_field(&mut out, 13, &message)
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
                        let mut message = Vec::new();
                        wire_field(&mut message, 1, constructor.as_bytes());
                        wire_field(&mut message, 2, &self.to_wire(&vty, value)?);
                        wire_field(&mut out, 14, &message)
                    }
                    (DataCons::Enum(_), Value::Enum { constructor, .. }) => {
                        let mut message = Vec::new();
                        wire_field(&mut message, 1, constructor.as_bytes());
                        wire_field(&mut out, 15, &message)
                    }
                    _ => return Err(bad()),
                }
            }
            _ => return Err(bad()),
        }
        Ok(out)
    }
}

/// A reader of the protobuf subset the `Value` message uses: (field number, wire type, payload).
fn wire_fields(mut b: &[u8]) -> Res<Vec<(u32, u8, Vec<u8>)>> {
    fn varint(b: &mut &[u8]) -> Res<u64> {
        let (mut v, mut shift) = (0u64, 0u32);
        loop {
            let (c, rest) = b.split_first().ok_or("a value cut off")?;
            *b = rest;
            v |= u64::from(c & 0x7f) << shift;
            shift += 7;
            if c < &0x80 {
                return Ok(v);
            }
            if shift > 63 {
                return Err("a varint too long".into());
            }
        }
    }
    let mut out = Vec::new();
    while !b.is_empty() {
        let key = varint(&mut b)?;
        let (field, wire) = ((key >> 3) as u32, (key & 7) as u8);
        let payload = match wire {
            0 => varint(&mut b)?.to_le_bytes().to_vec(),
            1 => {
                if b.len() < 8 {
                    return Err("a fixed64 cut off".into());
                }
                let (p, rest) = b.split_at(8);
                b = rest;
                p.to_vec()
            }
            2 => {
                let len = varint(&mut b)? as usize;
                if b.len() < len {
                    return Err("a field cut off".into());
                }
                let (p, rest) = b.split_at(len);
                b = rest;
                p.to_vec()
            }
            other => return Err(format!("wire type {other} is not a Value's")),
        };
        out.push((field, wire, payload));
    }
    Ok(out)
}

impl Types<'_> {
    /// The inverse of [`Types::to_wire`]: the bare `Value` message of a contract's `create_arg` (or the payload of a chosen value) as a
    /// [`Value`] of `ty`. The declared type tells what an `int64` is (a timestamp and a date are carried by their own fields, but a record has no
    /// labels, so the type gives them) and which constructor a rank names.
    pub fn from_wire(&self, ty: &LfType, bytes: &[u8]) -> Res<Value> {
        let fields = wire_fields(bytes)?;
        let bad = |what: &str| -> String { format!("{what}: {ty:?} is not what the value holds") };
        let (number, _, payload) = fields.first().ok_or_else(|| bad("an empty value"))?.clone();
        let zigzag = |p: &[u8]| -> i64 {
            let v = u64::from_le_bytes(p.try_into().unwrap_or([0; 8]));
            ((v >> 1) as i64) ^ -((v & 1) as i64)
        };
        Ok(match (ty, number) {
            (LfType::Unit, 1) => Value::Unit,
            (LfType::Bool, 2) => Value::Bool(payload.first().copied().unwrap_or(0) != 0),
            (LfType::Int64, 3) => Value::Int64(zigzag(&payload)),
            (LfType::Date, 4) => Value::Int64(i64::from(u64::from_le_bytes(
                payload.try_into().unwrap_or([0; 8]),
            ) as u32 as i32)),
            (LfType::Timestamp, 5) => Value::Int64(i64::from_le_bytes(
                payload.try_into().map_err(|_| bad("a timestamp"))?,
            )),
            (LfType::Numeric(expected_scale), 6) => {
                let text = String::from_utf8(payload).map_err(|e| e.to_string())?;
                let negative = text.starts_with('-');
                let body = text.strip_prefix('-').unwrap_or(&text);
                let (whole, frac) = match body.split_once('.') {
                    Some((w, f)) => {
                        if f.is_empty() {
                            return Err(bad("a numeric"));
                        }
                        (w, f)
                    }
                    None => (body, ""),
                };
                if whole.is_empty()
                    || !whole.bytes().all(|b| b.is_ascii_digit())
                    || !frac.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(bad("a numeric"));
                }
                let found_scale = u8::try_from(frac.len()).map_err(|_| bad("a numeric"))?;
                let digits = format!("{whole}{frac}");
                let mag: i128 = digits.parse().map_err(|_| bad("a numeric"))?;
                let coeff = if negative {
                    mag.checked_neg().ok_or_else(|| bad("a numeric"))?
                } else {
                    mag
                };
                if coeff == 0 && negative {
                    return Err(bad("a numeric"));
                }
                match expected_scale {
                    Some(target) => {
                        let scaled = rescale_exact(coeff, found_scale, *target)
                            .ok_or_else(|| bad("a numeric"))?;
                        Value::Numeric {
                            coeff: scaled,
                            scale: *target,
                        }
                    }
                    None => Value::Numeric {
                        coeff,
                        scale: found_scale,
                    },
                }
            }
            (LfType::Party, 7) => {
                Value::Party(String::from_utf8(payload).map_err(|e| e.to_string())?)
            }
            (LfType::Text, 8) => {
                Value::Text(String::from_utf8(payload).map_err(|e| e.to_string())?)
            }
            (LfType::ContractId, 9) => {
                Value::ContractId(payload.iter().map(|b| format!("{b:02x}")).collect())
            }
            (LfType::Optional(inner), 10) => {
                let message = wire_fields(&payload)?;
                match message.first() {
                    None => Value::Optional(None),
                    Some((_, _, v)) => Value::Optional(Some(Box::new(self.from_wire(inner, v)?))),
                }
            }
            (LfType::List(inner), 11) => Value::List(
                wire_fields(&payload)?
                    .iter()
                    .map(|(_, _, v)| self.from_wire(inner, v))
                    .collect::<Res<Vec<_>>>()?
                    .into(),
            ),
            (LfType::TextMap(inner), 16) => {
                let mut entries = Vec::new();
                for (_, _, entry) in wire_fields(&payload)? {
                    let parts = wire_fields(&entry)?;
                    let key = parts
                        .iter()
                        .find(|(n, _, _)| *n == 1)
                        .map(|(_, _, p)| p.clone())
                        .unwrap_or_default();
                    let value = parts
                        .iter()
                        .find(|(n, _, _)| *n == 2)
                        .map(|(_, _, p)| p.clone())
                        .unwrap_or_default();
                    entries.push((
                        Value::Text(String::from_utf8(key).map_err(|e| e.to_string())?),
                        self.from_wire(inner, &value)?,
                    ));
                }
                sorted_map(entries)?
            }
            (LfType::GenMap(key, val), 12) => {
                let mut entries = Vec::new();
                for (_, _, entry) in wire_fields(&payload)? {
                    let parts = wire_fields(&entry)?;
                    let k = parts
                        .iter()
                        .find(|(n, _, _)| *n == 1)
                        .map(|(_, _, p)| p.clone())
                        .unwrap_or_default();
                    let v = parts
                        .iter()
                        .find(|(n, _, _)| *n == 2)
                        .map(|(_, _, p)| p.clone())
                        .unwrap_or_default();
                    entries.push((self.from_wire(key, &k)?, self.from_wire(val, &v)?));
                }
                // [CANTON-NOTE: SEMANTICS] Wire values are contract arguments and transaction values, which Speedy imports
                // with `SMap.fromStrictlyOrderedEntries` and rejects as "Unexpected non-strictly ordered GenMap value".
                if !crate::value_order::strictly_ordered_keys(&entries)
                    .map_err(|e| e.to_string())?
                {
                    return Err("Unexpected non-strictly ordered GenMap value".to_string());
                }
                Value::Map(entries)
            }
            (LfType::Con { .. }, 13) => {
                let declared = self.record_fields(ty)?;
                let given: Vec<Vec<u8>> = wire_fields(&payload)?
                    .into_iter()
                    .map(|(_, _, f)| f)
                    .collect();
                if given.len() > declared.len() {
                    return Err(bad("more fields than the record has"));
                }
                let mut out = Vec::new();
                for (i, (label, fty)) in declared.iter().enumerate() {
                    // a field the value leaves out is a trailing `None` (`to_wire` does not write those)
                    let value = match given.get(i) {
                        Some(field) => {
                            let inner = wire_fields(field)?;
                            let (_, _, v) = inner.first().ok_or_else(|| bad("an empty field"))?;
                            self.from_wire(fty, v)?
                        }
                        None => Value::Optional(None),
                    };
                    out.push((label.clone(), value));
                }
                let tycon = match ty {
                    LfType::Con { module, name, .. } => Some(format!("{module}:{name}")),
                    _ => None,
                };
                Value::Record { tycon, fields: out }
            }
            (LfType::Con { module, name, .. }, 14) => {
                let parts = wire_fields(&payload)?;
                let constructor = String::from_utf8(
                    parts
                        .iter()
                        .find(|(n, _, _)| *n == 1)
                        .map(|(_, _, p)| p.clone())
                        .unwrap_or_default(),
                )
                .map_err(|e| e.to_string())?;
                let inner = parts
                    .iter()
                    .find(|(n, _, _)| *n == 2)
                    .map(|(_, _, p)| p.clone())
                    .unwrap_or_default();
                let declared = self.constructors(ty)?;
                let (rank, (_, vty)) = (0u32..)
                    .zip(&declared)
                    .find(|(_, (n, _))| *n == constructor)
                    .ok_or_else(|| bad("an unknown constructor"))?;
                Value::Variant {
                    tycon: Some(format!("{module}:{name}")),
                    constructor,
                    rank: CtorRank::known(rank),
                    value: Box::new(self.from_wire(vty, &inner)?),
                }
            }
            (LfType::Con { module, name, .. }, 15) => {
                let parts = wire_fields(&payload)?;
                let constructor = String::from_utf8(
                    parts
                        .iter()
                        .find(|(n, _, _)| *n == 1)
                        .map(|(_, _, p)| p.clone())
                        .unwrap_or_default(),
                )
                .map_err(|e| e.to_string())?;
                let rank = (0u32..)
                    .zip(self.constructors(ty)?)
                    .find_map(|(rank, (n, _))| (n == constructor).then_some(rank))
                    .ok_or_else(|| bad("an unknown constructor"))?;
                Value::Enum {
                    tycon: Some(format!("{module}:{name}")),
                    constructor,
                    rank: CtorRank::known(rank),
                }
            }
            _ => return Err(bad(&format!("field {number}"))),
        })
    }
}

/// A map in key order, a later entry replacing an earlier one with an equal key (Speedy `SMap.apply`).
pub(super) fn sorted_map(entries: Vec<(Value, Value)>) -> Res<Value> {
    crate::value_order::sort_map_entries(entries)
        .map(Value::Map)
        .map_err(|e| e.to_string())
}

pub fn wire_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub fn wire_tag(out: &mut Vec<u8>, field: u32, wire_type: u8) {
    wire_varint(out, u64::from(field << 3 | u32::from(wire_type)));
}

/// A length-delimited field.
pub fn wire_field(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    wire_tag(out, field, 2);
    wire_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}
