//! Labelled value codec: JSON-ish records <-> `lf_eval::Value` <-> protobuf wire bytes.
//!
//! Why it exists: `lf_archive::Value` is *positional* (a record is just `Vec<Value>`), while
//! the evaluator projects record fields *by name*. `Value::to_lf_value` therefore drops the
//! labels and has no inverse by itself. This module supplies the missing half by taking the
//! labels (and the field types) from the DAR's `TemplateSurface.fields` / `ChoiceDef.params`
//! through a `RecordSchema`. Both directions are schema driven, which is also what lets
//! `Date`/`Timestamp` survive: the evaluator stores both as `Int64`, so only the schema can
//! say which wire type to emit.
//!
//! Wire format of ledger payloads/arguments = protobuf of `lf_archive::Value::Record`
//! (fields in schema order). It is canonical: `decode_record` rejects bytes that do not
//! re-encode to themselves (e.g. unknown trailing fields), because ACS commitments hash
//! these bytes and two encodings of one value must not exist. Empty input is invalid:
//! a zero-parameter choice argument is an *empty record* (`6a 00`), not zero bytes.
//!
//! Supported types: Party, Text, Bool, Unit, Int64, Numeric, Date, Timestamp, ContractId,
//! List, Optional (not `Optional (Optional _)`), and tuples of these (as a record of its values in order: `value_to_lf` and
//! `lf_to_value` only, not the JSON forms). Anything that needs data-type definitions
//! (nested records, variants, enums, maps, type variables) is rejected with
//! `CodecError::UnsupportedType` rather than guessed: `SurfaceType::TypeCon` carries no
//! field list, so labels for it cannot be recovered from the surface alone.
//!
//! Model limits: contract ids are carried as the UTF-8 bytes of the evaluator's id string
//! (the exact inverse of `to_lf_value`); this is NOT Canton's binary contract-id format.
//! Party strings are opaque text that must satisfy `lf_archive`'s syntax check; this codec
//! does not know about Canton party-id suffixes/namespaces. The JSON shape follows the
//! spirit of the Daml JSON API (records as objects, Int64/Numeric as strings) but is not a
//! verified drop-in for the official JSON encoding; Date/Timestamp have no JSON form here.

use lf_archive::{ChoiceDef, ModuleSurface, SurfaceType, TemplateSurface};
use thiserror::Error;

use crate::{parse_numeric, render_numeric, Value};

#[derive(Debug, Error, PartialEq)]
pub enum CodecError {
    /// Zero bytes can never be a valid payload/argument (see module docs).
    #[error("empty input is not a valid encoded value")]
    EmptyInput,
    /// Protobuf decoding failed, or the decoded value violates an LF invariant (party
    /// syntax, numeric precision, date/timestamp range, ...).
    #[error("invalid wire value: {0}")]
    Wire(String),
    /// Valid protobuf, but not the canonical encoding of the value it decodes to.
    #[error("wire bytes are not the canonical encoding of the decoded value")]
    NonCanonical,
    #[error("{path}: expected a record, found {found}")]
    NotARecord { path: String, found: String },
    #[error("{record}: expected {expected} fields, found {found}")]
    ArityMismatch {
        record: String,
        expected: usize,
        found: usize,
    },
    #[error("{record}: unknown field `{field}`")]
    UnknownField { record: String, field: String },
    #[error("{record}: missing field `{field}`")]
    MissingField { record: String, field: String },
    #[error("{path}: expected {expected}, found {found}")]
    TypeMismatch {
        path: String,
        expected: String,
        found: String,
    },
    #[error("{path}: invalid numeric `{text}`")]
    InvalidNumeric { path: String, text: String },
    /// A numeric whose scale differs from the field's scale in a way that would change its
    /// value (extra non-zero fraction digits) or overflow the coefficient.
    #[error("{path}: numeric `{text}` does not fit scale {scale}")]
    NumericScale {
        path: String,
        text: String,
        scale: u8,
    },
    #[error("{path}: type `{ty}` is not supported by this codec")]
    UnsupportedType { path: String, ty: String },
    #[error("{path}: contract id is not valid UTF-8")]
    InvalidContractId { path: String },
    /// An error of the richer `typed_json` codec (records inside records, variants, maps), which a caller falls back to when this codec
    /// has no surface for a type.
    #[error("{0}")]
    Typed(String),
    #[error("template {0} is not in the supplied surfaces")]
    UnknownTemplate(String),
    #[error("template {template} has no choice {choice} in the supplied surfaces")]
    UnknownChoice { template: String, choice: String },
}

/// Field labels and types of one record type (a template payload or a choice argument).
#[derive(Clone, Debug, PartialEq)]
pub struct RecordSchema {
    /// Evaluator-style type name (`"Module:Name"`), stored as the `tycon` of decoded records.
    pub tycon: String,
    pub fields: Vec<(String, SurfaceType)>,
}

impl RecordSchema {
    /// Payload schema of a template: its record fields in declaration order.
    pub fn for_template(module: &str, template: &TemplateSurface) -> Self {
        Self {
            tycon: format!("{module}:{}", template.name),
            fields: template
                .fields
                .iter()
                .map(|f| (f.name.clone(), f.ty.clone()))
                .collect(),
        }
    }

    /// Argument schema of a choice. The tycon follows the convention that a choice declared
    /// in a template has an argument record of the same name in the same module; the
    /// evaluator never reads the tycon (it projects by label), so a choice whose argument
    /// type lives elsewhere (e.g. the implicit `Archive`) is still evaluated correctly.
    pub fn for_choice_arg(module: &str, choice: &ChoiceDef) -> Self {
        Self {
            tycon: format!("{module}:{}", choice.name),
            fields: choice
                .params
                .iter()
                .map(|p| (p.name.clone(), p.ty.clone()))
                .collect(),
        }
    }

    /// Payload schema of `template_id` (`"Module:Entity"`) looked up in module surfaces.
    pub fn template(surfaces: &[ModuleSurface], template_id: &str) -> Result<Self, CodecError> {
        let (module, template) = find_template(surfaces, template_id)?;
        Ok(Self::for_template(&module.name, template))
    }

    /// Argument schema of `choice` on `template_id`.
    pub fn choice_arg(
        surfaces: &[ModuleSurface],
        template_id: &str,
        choice: &str,
    ) -> Result<Self, CodecError> {
        let (module, template) = find_template(surfaces, template_id)?;
        let def = template
            .choices
            .iter()
            .find(|c| c.name == choice)
            .ok_or_else(|| CodecError::UnknownChoice {
                template: template_id.to_string(),
                choice: choice.to_string(),
            })?;
        Ok(Self::for_choice_arg(&module.name, def))
    }

    /// Builds a labelled record from a JSON object. Every schema field must be present
    /// (an absent `Optional` field is `None`); keys not in the schema are rejected so a typo
    /// in a field name can never silently produce a default.
    pub fn from_json(&self, json: &serde_json::Value) -> Result<Value, CodecError> {
        let object = json.as_object().ok_or_else(|| CodecError::NotARecord {
            path: self.tycon.clone(),
            found: json_kind(json).to_string(),
        })?;
        for key in object.keys() {
            if !self.fields.iter().any(|(name, _)| name == key) {
                return Err(CodecError::UnknownField {
                    record: self.tycon.clone(),
                    field: key.clone(),
                });
            }
        }
        let mut fields = Vec::with_capacity(self.fields.len());
        for (name, ty) in &self.fields {
            let path = format!("{}.{name}", self.tycon);
            let value = match (object.get(name), ty) {
                (Some(json), _) => json_to_value(ty, json, &path)?,
                (None, SurfaceType::Optional(_)) => Value::Optional(None),
                (None, _) => {
                    return Err(CodecError::MissingField {
                        record: self.tycon.clone(),
                        field: name.clone(),
                    })
                }
            };
            fields.push((name.clone(), value));
        }
        Ok(Value::Record {
            tycon: Some(self.tycon.clone()),
            fields,
        })
    }

    /// Inverse of `from_json` for a record value.
    pub fn to_json(&self, value: &Value) -> Result<serde_json::Value, CodecError> {
        let fields = self.record_fields(value)?;
        let mut object = serde_json::Map::new();
        for (name, ty) in &self.fields {
            let path = format!("{}.{name}", self.tycon);
            let field = self.field(fields, name)?;
            object.insert(name.clone(), value_to_json(ty, field, &path)?);
        }
        Ok(serde_json::Value::Object(object))
    }

    /// Validates `value` against the schema and encodes it as the wire bytes
    /// (protobuf of `lf_archive::Value::Record`, fields in schema order).
    pub fn encode(&self, value: &Value) -> Result<Vec<u8>, CodecError> {
        let fields = self.record_fields(value)?;
        let mut out = Vec::with_capacity(self.fields.len());
        for (name, ty) in &self.fields {
            let path = format!("{}.{name}", self.tycon);
            out.push(value_to_lf(ty, self.field(fields, name)?, &path)?);
        }
        let lf = lf_archive::Value::Record { fields: out };
        // Same invariants the decoder enforces (party syntax, numeric precision, ranges):
        // never emit bytes this codec would refuse to read back.
        lf.validate(0)
            .map_err(|e| CodecError::Wire(e.to_string()))?;
        Ok(lf.encode_to_vec())
    }

    /// Decodes wire bytes into a labelled record. Errors: empty input, malformed protobuf,
    /// non-canonical bytes, wrong arity, or a field whose wire type does not match the schema.
    pub fn decode(&self, bytes: &[u8]) -> Result<Value, CodecError> {
        if bytes.is_empty() {
            return Err(CodecError::EmptyInput);
        }
        let lf = lf_archive::Value::decode_from_slice(bytes)
            .map_err(|e| CodecError::Wire(e.to_string()))?;
        // prost silently skips unknown fields; re-encoding exposes them.
        if lf.encode_to_vec() != bytes {
            return Err(CodecError::NonCanonical);
        }
        let lf_archive::Value::Record { fields } = lf else {
            return Err(CodecError::NotARecord {
                path: self.tycon.clone(),
                found: lf_kind_of(&lf).to_string(),
            });
        };
        if fields.len() != self.fields.len() {
            return Err(CodecError::ArityMismatch {
                record: self.tycon.clone(),
                expected: self.fields.len(),
                found: fields.len(),
            });
        }
        let mut labelled = Vec::with_capacity(fields.len());
        for ((name, ty), lf_field) in self.fields.iter().zip(&fields) {
            let path = format!("{}.{name}", self.tycon);
            labelled.push((name.clone(), lf_to_value(ty, lf_field, &path)?));
        }
        Ok(Value::Record {
            tycon: Some(self.tycon.clone()),
            fields: labelled,
        })
    }

    fn record_fields<'v>(&self, value: &'v Value) -> Result<&'v [(String, Value)], CodecError> {
        match value {
            Value::Record { fields, .. } => {
                for (name, _) in fields {
                    if !self.fields.iter().any(|(known, _)| known == name) {
                        return Err(CodecError::UnknownField {
                            record: self.tycon.clone(),
                            field: name.clone(),
                        });
                    }
                }
                Ok(fields)
            }
            other => Err(CodecError::NotARecord {
                path: self.tycon.clone(),
                found: value_kind(other).to_string(),
            }),
        }
    }

    fn field<'v>(
        &self,
        fields: &'v [(String, Value)],
        name: &str,
    ) -> Result<&'v Value, CodecError> {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
            .ok_or_else(|| CodecError::MissingField {
                record: self.tycon.clone(),
                field: name.to_string(),
            })
    }
}

fn find_template<'a>(
    surfaces: &'a [ModuleSurface],
    template_id: &str,
) -> Result<(&'a ModuleSurface, &'a TemplateSurface), CodecError> {
    let unknown = || CodecError::UnknownTemplate(template_id.to_string());
    let (module, entity) = template_id.split_once(':').ok_or_else(unknown)?;
    let module = surfaces
        .iter()
        .find(|m| m.name == module)
        .ok_or_else(unknown)?;
    let template = module
        .templates
        .iter()
        .find(|t| t.name == entity)
        .ok_or_else(unknown)?;
    Ok((module, template))
}

/// Decimal scale of a `Numeric` surface type. `Numeric(None)` is what the surface prints as
/// `Decimal`, i.e. scale 10.
fn numeric_scale(scale: &Option<u8>) -> u8 {
    scale.unwrap_or(10)
}

fn mismatch(path: &str, ty: &SurfaceType, found: &str) -> CodecError {
    CodecError::TypeMismatch {
        path: path.to_string(),
        expected: ty.display_daml(),
        found: found.to_string(),
    }
}

fn unsupported(path: &str, ty: &SurfaceType) -> CodecError {
    CodecError::UnsupportedType {
        path: path.to_string(),
        ty: ty.display_daml(),
    }
}

/// `Optional (Optional _)` cannot be told apart from `Optional _` in the plain
/// null-or-value JSON shape, so it is refused instead of risking silent data loss.
fn check_optional_inner(
    path: &str,
    outer: &SurfaceType,
    inner: &SurfaceType,
) -> Result<(), CodecError> {
    if matches!(inner, SurfaceType::Optional(_)) {
        return Err(unsupported(path, outer));
    }
    Ok(())
}

/// Evaluator value -> LF wire value for a field of type `ty`.
fn value_to_lf(
    ty: &SurfaceType,
    value: &Value,
    path: &str,
) -> Result<lf_archive::Value, CodecError> {
    use lf_archive::Value as Lf;
    Ok(match (ty, value) {
        (SurfaceType::Party, Value::Party(p)) => Lf::Party(p.clone()),
        (SurfaceType::Text, Value::Text(t)) => Lf::Text(t.clone()),
        (SurfaceType::Bool, Value::Bool(b)) => Lf::Bool(*b),
        (SurfaceType::Unit, Value::Unit) => Lf::Unit,
        (SurfaceType::Int64, Value::Int64(n)) => Lf::Int64(*n),
        (SurfaceType::Date, Value::Int64(days)) => {
            // Out-of-i32 days can never be a valid LF date; refuse instead of truncating.
            Lf::Date(
                i32::try_from(*days)
                    .map_err(|_| CodecError::Wire(format!("{path}: date {days} out of range")))?,
            )
        }
        (SurfaceType::Timestamp, Value::Int64(micros)) => Lf::Timestamp(*micros),
        (
            SurfaceType::Numeric(scale),
            Value::Numeric {
                coeff,
                scale: actual,
            },
        ) => {
            let want = numeric_scale(scale);
            if *actual != want {
                // Scale is part of the Daml type; silently rescaling would hide a model bug.
                return Err(CodecError::NumericScale {
                    path: path.to_string(),
                    text: render_numeric(*coeff, *actual),
                    scale: want,
                });
            }
            Lf::Numeric(render_numeric(*coeff, *actual))
        }
        (SurfaceType::ContractId(_), Value::ContractId(cid)) => {
            Lf::ContractId(cid.as_bytes().to_vec())
        }
        (SurfaceType::List(inner), Value::List(items)) => Lf::List(
            items
                .iter()
                .enumerate()
                .map(|(i, item)| value_to_lf(inner, item, &format!("{path}[{i}]")))
                .collect::<Result<_, _>>()?,
        ),
        (SurfaceType::Optional(inner), Value::Optional(opt)) => {
            check_optional_inner(path, ty, inner)?;
            Lf::Optional(match opt {
                Some(v) => Some(Box::new(value_to_lf(inner, v, path)?)),
                None => None,
            })
        }
        // [CANTON-NOTE: SEMANTICS] A Daml tuple `(a, b, ..)` is the record `DA.Types:TupleN` with the fields `_1`, `_2`, ...; on the LF wire
        // (a choice argument or a contract key) it is a record of its values in order, without labels or a record id.
        (SurfaceType::Tuple(elems), Value::Record { fields, .. })
            if fields.len() == elems.len() =>
        {
            Lf::Record {
                fields: elems
                    .iter()
                    .zip(fields)
                    .enumerate()
                    .map(|(i, (ty, (_, v)))| value_to_lf(ty, v, &format!("{path}._{}", i + 1)))
                    .collect::<Result<_, _>>()?,
            }
        }
        (supported, found) if is_supported(supported) => {
            return Err(mismatch(path, supported, value_kind(found)))
        }
        (other, _) => return Err(unsupported(path, other)),
    })
}

/// LF wire value -> evaluator value for a field of type `ty`.
fn lf_to_value(ty: &SurfaceType, lf: &lf_archive::Value, path: &str) -> Result<Value, CodecError> {
    use lf_archive::Value as Lf;
    Ok(match (ty, lf) {
        (SurfaceType::Party, Lf::Party(p)) => Value::Party(p.clone()),
        (SurfaceType::Text, Lf::Text(t)) => Value::Text(t.clone()),
        (SurfaceType::Bool, Lf::Bool(b)) => Value::Bool(*b),
        (SurfaceType::Unit, Lf::Unit) => Value::Unit,
        (SurfaceType::Int64, Lf::Int64(n)) => Value::Int64(*n),
        (SurfaceType::Date, Lf::Date(days)) => Value::Int64(i64::from(*days)),
        (SurfaceType::Timestamp, Lf::Timestamp(micros)) => Value::Int64(*micros),
        (SurfaceType::Numeric(scale), Lf::Numeric(text)) => {
            numeric_from_text(path, text, numeric_scale(scale))?
        }
        (SurfaceType::ContractId(_), Lf::ContractId(bytes)) => {
            // [CANTON-NOTE: SEMANTICS] A contract id in a value has two byte forms: the **text** form (the id as UTF-8, what the JSON
            // API and the IDE ledger carry) and Canton's **binary** form (`00 ++ discriminator ++ suffix`, at least 33 bytes, what a
            // participant writes in the argument of a choice, measured on a `Look { other : ContractId }` p1 submitted). The engine
            // names a contract by its hex string, so the binary form is hex-encoded. Bytes that are neither are still refused.
            if bytes.len() >= 33 && bytes[0] == 0 {
                Value::ContractId(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
            } else {
                Value::ContractId(String::from_utf8(bytes.clone()).map_err(|_| {
                    CodecError::InvalidContractId {
                        path: path.to_string(),
                    }
                })?)
            }
        }
        (SurfaceType::List(inner), Lf::List(items)) => Value::List(
            items
                .iter()
                .enumerate()
                .map(|(i, item)| lf_to_value(inner, item, &format!("{path}[{i}]")))
                .collect::<Result<_, _>>()?,
        ),
        (SurfaceType::Optional(inner), Lf::Optional(opt)) => {
            check_optional_inner(path, ty, inner)?;
            Value::Optional(match opt {
                Some(v) => Some(Box::new(lf_to_value(inner, v, path)?)),
                None => None,
            })
        }
        (SurfaceType::Tuple(elems), Lf::Record { fields }) if fields.len() == elems.len() => {
            Value::Record {
                tycon: Some(format!("DA.Types:Tuple{}", elems.len())),
                fields: elems
                    .iter()
                    .zip(fields)
                    .enumerate()
                    .map(|(i, (ty, lf))| {
                        Ok((
                            format!("_{}", i + 1),
                            lf_to_value(ty, lf, &format!("{path}._{}", i + 1))?,
                        ))
                    })
                    .collect::<Result<_, CodecError>>()?,
            }
        }
        (supported, found) if is_supported(supported) => {
            return Err(mismatch(path, supported, lf_kind_of(found)))
        }
        (other, _) => return Err(unsupported(path, other)),
    })
}

/// JSON -> evaluator value. Int64/Numeric accept a JSON string (Daml JSON style) or an
/// integer; a non-integer JSON number is refused because going through `f64` would change
/// decimals silently.
fn json_to_value(
    ty: &SurfaceType,
    json: &serde_json::Value,
    path: &str,
) -> Result<Value, CodecError> {
    use serde_json::Value as J;
    Ok(match (ty, json) {
        (SurfaceType::Party, J::String(s)) => {
            // [CANTON-NOTE: INVARIANT] Party identifiers must satisfy Daml-LF lexical syntax rules
            // (non-empty, <=255 bytes, no leading/trailing whitespace, valid character set) before being
            // admitted into evaluator Value::Party representation.
            // [CANTON-NOTE: WHY] In the JSON API HTTP ingress path, RecordSchema::from_json constructs
            // the Value payload passed directly to Engine::execute_create without invoking RecordSchema::encode.
            // Validating syntax here prevents malformed party identifiers from entering ledger state.
            lf_archive::Value::Party(s.clone())
                .validate(0)
                .map_err(|e| CodecError::Wire(e.to_string()))?;
            Value::Party(s.clone())
        }
        (SurfaceType::Text, J::String(s)) => Value::Text(s.clone()),
        (SurfaceType::Bool, J::Bool(b)) => Value::Bool(*b),
        (SurfaceType::Unit, J::Null) => Value::Unit,
        (SurfaceType::Int64, J::Number(n)) => Value::Int64(
            n.as_i64()
                .ok_or_else(|| mismatch(path, ty, "non-i64 number"))?,
        ),
        (SurfaceType::Int64, J::String(s)) => {
            Value::Int64(s.parse::<i64>().map_err(|_| CodecError::TypeMismatch {
                path: path.to_string(),
                expected: ty.display_daml(),
                found: format!("string `{s}`"),
            })?)
        }
        (SurfaceType::Numeric(scale), J::String(s)) => {
            numeric_from_text(path, s, numeric_scale(scale))?
        }
        (SurfaceType::Numeric(scale), J::Number(n)) if n.is_i64() || n.is_u64() => {
            numeric_from_text(path, &n.to_string(), numeric_scale(scale))?
        }
        (SurfaceType::ContractId(_), J::String(s)) => Value::ContractId(s.clone()),
        (SurfaceType::List(inner), J::Array(items)) => Value::List(
            items
                .iter()
                .enumerate()
                .map(|(i, item)| json_to_value(inner, item, &format!("{path}[{i}]")))
                .collect::<Result<_, _>>()?,
        ),
        (SurfaceType::Optional(inner), json) => {
            check_optional_inner(path, ty, inner)?;
            if json.is_null() {
                Value::Optional(None)
            } else {
                Value::Optional(Some(Box::new(json_to_value(inner, json, path)?)))
            }
        }
        (SurfaceType::Tuple(elems), J::Object(object)) => {
            let record = format!("DA.Types:Tuple{}", elems.len());
            for key in object.keys() {
                let valid = key
                    .strip_prefix('_')
                    .and_then(|n| n.parse::<usize>().ok())
                    .is_some_and(|idx| (1..=elems.len()).contains(&idx));
                if !valid {
                    return Err(CodecError::UnknownField {
                        record,
                        field: key.clone(),
                    });
                }
            }
            let mut fields = Vec::with_capacity(elems.len());
            for (i, elem_ty) in elems.iter().enumerate() {
                let fname = format!("_{}", i + 1);
                let fpath = format!("{path}.{fname}");
                let val = match (object.get(&fname), elem_ty) {
                    (Some(v), _) => json_to_value(elem_ty, v, &fpath)?,
                    (None, SurfaceType::Optional(_)) => Value::Optional(None),
                    (None, _) => {
                        return Err(CodecError::MissingField {
                            record,
                            field: fname,
                        })
                    }
                };
                fields.push((fname, val));
            }
            Value::Record {
                tycon: Some(record),
                fields,
            }
        }
        (SurfaceType::Date | SurfaceType::Timestamp, _) => return Err(unsupported(path, ty)),
        (supported, found) if is_supported(supported) => {
            return Err(mismatch(path, supported, json_kind(found)))
        }
        (other, _) => return Err(unsupported(path, other)),
    })
}

/// Evaluator value -> JSON, the inverse of `json_to_value` (Int64/Numeric as strings).
fn value_to_json(
    ty: &SurfaceType,
    value: &Value,
    path: &str,
) -> Result<serde_json::Value, CodecError> {
    use serde_json::Value as J;
    Ok(match (ty, value) {
        (SurfaceType::Party, Value::Party(s)) | (SurfaceType::Text, Value::Text(s)) => {
            J::String(s.clone())
        }
        (SurfaceType::ContractId(_), Value::ContractId(s)) => J::String(s.clone()),
        (SurfaceType::Bool, Value::Bool(b)) => J::Bool(*b),
        (SurfaceType::Unit, Value::Unit) => J::Null,
        (SurfaceType::Int64, Value::Int64(n)) => J::String(n.to_string()),
        (
            SurfaceType::Numeric(scale),
            Value::Numeric {
                coeff,
                scale: actual,
            },
        ) => {
            let want = numeric_scale(scale);
            if *actual != want {
                return Err(CodecError::NumericScale {
                    path: path.to_string(),
                    text: render_numeric(*coeff, *actual),
                    scale: want,
                });
            }
            J::String(render_numeric(*coeff, *actual))
        }
        (SurfaceType::List(inner), Value::List(items)) => J::Array(
            items
                .iter()
                .enumerate()
                .map(|(i, item)| value_to_json(inner, item, &format!("{path}[{i}]")))
                .collect::<Result<_, _>>()?,
        ),
        (SurfaceType::Optional(inner), Value::Optional(opt)) => {
            check_optional_inner(path, ty, inner)?;
            match opt {
                Some(v) => value_to_json(inner, v, path)?,
                None => J::Null,
            }
        }
        (SurfaceType::Tuple(elems), Value::Record { fields, .. })
            if fields.len() == elems.len() =>
        {
            let mut object = serde_json::Map::new();
            for (i, (elem_ty, (_, val))) in elems.iter().zip(fields).enumerate() {
                let fname = format!("_{}", i + 1);
                let fpath = format!("{path}.{fname}");
                object.insert(fname, value_to_json(elem_ty, val, &fpath)?);
            }
            J::Object(object)
        }
        (SurfaceType::Date | SurfaceType::Timestamp, _) => return Err(unsupported(path, ty)),
        (supported, found) if is_supported(supported) => {
            return Err(mismatch(path, supported, value_kind(found)))
        }
        (other, _) => return Err(unsupported(path, other)),
    })
}

fn is_supported(ty: &SurfaceType) -> bool {
    matches!(
        ty,
        SurfaceType::Party
            | SurfaceType::Text
            | SurfaceType::Bool
            | SurfaceType::Unit
            | SurfaceType::Int64
            | SurfaceType::Numeric(_)
            | SurfaceType::Date
            | SurfaceType::Timestamp
            | SurfaceType::ContractId(_)
            | SurfaceType::List(_)
            | SurfaceType::Optional(_)
            | SurfaceType::Tuple(_)
    )
}

/// Parses a decimal text (`-?digits(.digits)?`) into a `Value::Numeric` of exactly `scale`
/// fraction digits. Trailing zeros may be dropped or added (`100` and `100.0000000000` are the
/// same Decimal), but a value that would lose non-zero digits or overflow is refused: the
/// evaluator's numeric builtins require equal scales, so a wrong scale must not leak in.
fn numeric_from_text(path: &str, text: &str, scale: u8) -> Result<Value, CodecError> {
    let invalid = || CodecError::InvalidNumeric {
        path: path.to_string(),
        text: text.to_string(),
    };
    // `parse_numeric` is lenient (repeated signs, empty parts); check the shape first.
    let body = text.strip_prefix('-').unwrap_or(text);
    let (whole, frac) = body.split_once('.').unwrap_or((body, ""));
    let digits_only = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty()
        || !digits_only(whole)
        || !digits_only(frac)
        || (body.contains('.') && frac.is_empty())
    {
        return Err(invalid());
    }
    let (coeff, found_scale) = parse_numeric(text).map_err(|_| invalid())?;
    let too_wide = || CodecError::NumericScale {
        path: path.to_string(),
        text: text.to_string(),
        scale,
    };
    let coeff = if found_scale <= scale {
        let factor = 10i128
            .checked_pow(u32::from(scale - found_scale))
            .ok_or_else(too_wide)?;
        coeff.checked_mul(factor).ok_or_else(too_wide)?
    } else {
        let factor = 10i128
            .checked_pow(u32::from(found_scale - scale))
            .ok_or_else(too_wide)?;
        if coeff % factor != 0 {
            return Err(too_wide());
        }
        coeff / factor
    };
    Ok(Value::Numeric { coeff, scale })
}

fn json_kind(json: &serde_json::Value) -> &'static str {
    match json {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Int64(_) => "Int64",
        Value::Numeric { .. } => "Numeric",
        Value::Text(_) => "Text",
        Value::Party(_) => "Party",
        Value::ContractId(_) => "ContractId",
        Value::Bool(_) => "Bool",
        Value::Unit => "Unit",
        Value::List(_) => "List",
        Value::Optional(_) => "Optional",
        Value::Record { .. } | Value::Struct(_) => "Record",
        Value::Variant { .. } => "Variant",
        Value::Enum { .. } => "Enum",
        _ => "non-ledger value",
    }
}

fn lf_kind_of(value: &lf_archive::Value) -> &'static str {
    use lf_archive::Value as Lf;
    match value {
        Lf::Unit => "Unit",
        Lf::Bool(_) => "Bool",
        Lf::Int64(_) => "Int64",
        Lf::Date(_) => "Date",
        Lf::Timestamp(_) => "Timestamp",
        Lf::Numeric(_) => "Numeric",
        Lf::Party(_) => "Party",
        Lf::Text(_) => "Text",
        Lf::ContractId(_) => "ContractId",
        Lf::Optional(_) => "Optional",
        Lf::List(_) => "List",
        Lf::TextMap(_) => "TextMap",
        Lf::GenMap(_) => "GenMap",
        Lf::Record { .. } => "Record",
        Lf::Variant { .. } => "Variant",
        Lf::Enum { .. } => "Enum",
    }
}
