//! Daml-LF Value Protobuf Codec & AST.
//! Conforms to com.digitalasset.daml.lf.value (value.proto).
//!
//! Enforces:
//! - Full Daml-LF 2.1–2.4 Value universe encoding and decoding (AT-V01)
//! - Invariant checking: Date range, Timestamp range, Numeric precision, Party syntax (AT-V02)
//! - Recursion depth limit (100) preventing stack exhaustion on adversarial inputs (AT-A05)

use prost::Message;

pub const MAX_VALUE_RECURSION_DEPTH: usize = 100;

// Date range: 0001-01-01 (-719162 days) to 9999-12-31 (2932896 days since UNIX epoch)
pub const MIN_DATE_DAYS: i32 = -719_162;
pub const MAX_DATE_DAYS: i32 = 2_932_896;

// Timestamp range: 0001-01-01T00:00:00Z to 9999-12-31T23:59:59.999999Z in microseconds
pub const MIN_TIMESTAMP_MICROS: i64 = -62_135_596_800_000_000;
pub const MAX_TIMESTAMP_MICROS: i64 = 253_402_300_799_999_999;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    InvalidDate(i32),
    InvalidTimestamp(i64),
    InvalidNumeric(String),
    InvalidParty(String),
    InvalidContractId,
    RecursionLimitExceeded(usize),
    MalformedProtobuf(String),
    MissingField(&'static str),
}

impl std::fmt::Display for ValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDate(d) => write!(f, "date out of range [0001-01-01, 9999-12-31]: {d}"),
            Self::InvalidTimestamp(ts) => write!(f, "timestamp out of range: {ts}"),
            Self::InvalidNumeric(n) => write!(
                f,
                "invalid numeric string (max 38 digits, max 37 scale): {n}"
            ),
            Self::InvalidParty(p) => write!(f, "invalid party identifier syntax: {p}"),
            Self::InvalidContractId => write!(f, "contract id must be non-empty"),
            Self::RecursionLimitExceeded(d) => write!(f, "value recursion limit exceeded: {d}"),
            Self::MalformedProtobuf(m) => write!(f, "malformed protobuf: {m}"),
            Self::MissingField(name) => write!(f, "missing expected field: {name}"),
        }
    }
}

impl std::error::Error for ValueError {}

// -----------------------------------------------------------------------------
// Prost Protobuf Wire Types (com.digitalasset.daml.lf.value)
// -----------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub struct ProtoValue {
    #[prost(
        oneof = "proto_value::Sum",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16"
    )]
    pub sum: ::core::option::Option<proto_value::Sum>,
}

pub mod proto_value {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Sum {
        #[prost(message, tag = "1")]
        Unit(()),
        #[prost(bool, tag = "2")]
        Bool(bool),
        #[prost(sint64, tag = "3")]
        Int64(i64),
        #[prost(int32, tag = "4")]
        Date(i32),
        #[prost(sfixed64, tag = "5")]
        Timestamp(i64),
        #[prost(string, tag = "6")]
        Numeric(::prost::alloc::string::String),
        #[prost(string, tag = "7")]
        Party(::prost::alloc::string::String),
        #[prost(string, tag = "8")]
        Text(::prost::alloc::string::String),
        #[prost(bytes, tag = "9")]
        ContractId(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag = "10")]
        Optional(::prost::alloc::boxed::Box<super::ProtoOptional>),
        #[prost(message, tag = "11")]
        List(super::ProtoList),
        #[prost(message, tag = "12")]
        Map(super::ProtoMap),
        #[prost(message, tag = "13")]
        Record(super::ProtoRecord),
        #[prost(message, tag = "14")]
        Variant(::prost::alloc::boxed::Box<super::ProtoVariant>),
        #[prost(message, tag = "15")]
        Enum(super::ProtoEnum),
        #[prost(message, tag = "16")]
        TextMap(super::ProtoTextMap),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoRecord {
    #[prost(message, repeated, tag = "1")]
    pub fields: ::prost::alloc::vec::Vec<ProtoRecordField>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoRecordField {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<ProtoValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoVariant {
    #[prost(string, tag = "1")]
    pub constructor: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<ProtoValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoEnum {
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoList {
    #[prost(message, repeated, tag = "1")]
    pub elements: ::prost::alloc::vec::Vec<ProtoValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoOptional {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<ProtoValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoTextMapEntry {
    #[prost(string, tag = "1")]
    pub key: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<ProtoValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoTextMap {
    #[prost(message, repeated, tag = "1")]
    pub entries: ::prost::alloc::vec::Vec<ProtoTextMapEntry>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoMapEntry {
    #[prost(message, optional, tag = "1")]
    pub key: ::core::option::Option<ProtoValue>,
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<ProtoValue>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoMap {
    #[prost(message, repeated, tag = "1")]
    pub entries: ::prost::alloc::vec::Vec<ProtoMapEntry>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ProtoVersionedValue {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}

// -----------------------------------------------------------------------------
// High-Level Invariant-Validated Rust Value AST
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Unit,
    Bool(bool),
    Int64(i64),
    Date(i32),
    Timestamp(i64),
    Numeric(String),
    Party(String),
    Text(String),
    ContractId(Vec<u8>),
    Optional(Option<Box<Value>>),
    List(Vec<Value>),
    TextMap(Vec<(String, Value)>),
    GenMap(Vec<(Value, Value)>),
    Record {
        fields: Vec<Value>,
    },
    Variant {
        constructor: String,
        value: Box<Value>,
    },
    Enum {
        value: String,
    },
}

impl Value {
    /// Validates all Daml-LF value invariants and recursion limits.
    pub fn validate(&self, depth: usize) -> Result<(), ValueError> {
        if depth > MAX_VALUE_RECURSION_DEPTH {
            return Err(ValueError::RecursionLimitExceeded(depth));
        }

        match self {
            Self::Unit | Self::Bool(_) | Self::Int64(_) => Ok(()),
            Self::Date(days) => {
                if *days < MIN_DATE_DAYS || *days > MAX_DATE_DAYS {
                    Err(ValueError::InvalidDate(*days))
                } else {
                    Ok(())
                }
            }
            Self::Timestamp(micros) => {
                if *micros < MIN_TIMESTAMP_MICROS || *micros > MAX_TIMESTAMP_MICROS {
                    Err(ValueError::InvalidTimestamp(*micros))
                } else {
                    Ok(())
                }
            }
            Self::Numeric(s) => validate_numeric_str(s),
            Self::Party(p) => validate_party_str(p),
            Self::Text(_) => Ok(()),
            Self::ContractId(bytes) => {
                if bytes.is_empty() {
                    Err(ValueError::InvalidContractId)
                } else {
                    Ok(())
                }
            }
            Self::Optional(opt) => {
                if let Some(inner) = opt {
                    inner.validate(depth + 1)?;
                }
                Ok(())
            }
            Self::List(elements) => {
                for elem in elements {
                    elem.validate(depth + 1)?;
                }
                Ok(())
            }
            Self::TextMap(entries) => {
                for (_, val) in entries {
                    val.validate(depth + 1)?;
                }
                Ok(())
            }
            Self::GenMap(entries) => {
                for (k, v) in entries {
                    k.validate(depth + 1)?;
                    v.validate(depth + 1)?;
                }
                Ok(())
            }
            Self::Record { fields } => {
                for f in fields {
                    f.validate(depth + 1)?;
                }
                Ok(())
            }
            Self::Variant { constructor, value } => {
                if constructor.is_empty() {
                    return Err(ValueError::MalformedProtobuf(
                        "empty variant constructor".into(),
                    ));
                }
                value.validate(depth + 1)
            }
            Self::Enum { value } => {
                if value.is_empty() {
                    Err(ValueError::MalformedProtobuf("empty enum value".into()))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Converts from Prost ProtoValue into high-level Value with invariant validation.
    pub fn from_proto(proto: ProtoValue, depth: usize) -> Result<Self, ValueError> {
        if depth > MAX_VALUE_RECURSION_DEPTH {
            return Err(ValueError::RecursionLimitExceeded(depth));
        }

        let sum = proto
            .sum
            .ok_or_else(|| ValueError::MalformedProtobuf("empty ProtoValue sum".into()))?;

        let val = match sum {
            proto_value::Sum::Unit(()) => Value::Unit,
            proto_value::Sum::Bool(b) => Value::Bool(b),
            proto_value::Sum::Int64(i) => Value::Int64(i),
            proto_value::Sum::Date(d) => Value::Date(d),
            proto_value::Sum::Timestamp(ts) => Value::Timestamp(ts),
            proto_value::Sum::Numeric(n) => Value::Numeric(n),
            proto_value::Sum::Party(p) => Value::Party(p),
            proto_value::Sum::Text(t) => Value::Text(t),
            proto_value::Sum::ContractId(cid) => Value::ContractId(cid),
            proto_value::Sum::Optional(opt) => {
                let inner = match opt.value {
                    Some(pv) => Some(Box::new(Value::from_proto(pv, depth + 1)?)),
                    None => None,
                };
                Value::Optional(inner)
            }
            proto_value::Sum::List(list) => {
                let mut elements = Vec::with_capacity(list.elements.len());
                for pv in list.elements {
                    elements.push(Value::from_proto(pv, depth + 1)?);
                }
                Value::List(elements)
            }
            proto_value::Sum::TextMap(tmap) => {
                let mut entries = Vec::with_capacity(tmap.entries.len());
                for e in tmap.entries {
                    let v = e
                        .value
                        .ok_or(ValueError::MissingField("TextMap entry value"))?;
                    entries.push((e.key, Value::from_proto(v, depth + 1)?));
                }
                Value::TextMap(entries)
            }
            proto_value::Sum::Map(gmap) => {
                let mut entries = Vec::with_capacity(gmap.entries.len());
                for e in gmap.entries {
                    let k = e.key.ok_or(ValueError::MissingField("Map entry key"))?;
                    let v = e.value.ok_or(ValueError::MissingField("Map entry value"))?;
                    entries.push((
                        Value::from_proto(k, depth + 1)?,
                        Value::from_proto(v, depth + 1)?,
                    ));
                }
                Value::GenMap(entries)
            }
            proto_value::Sum::Record(rec) => {
                let mut fields = Vec::with_capacity(rec.fields.len());
                for f in rec.fields {
                    let v = f
                        .value
                        .ok_or(ValueError::MissingField("Record field value"))?;
                    fields.push(Value::from_proto(v, depth + 1)?);
                }
                Value::Record { fields }
            }
            proto_value::Sum::Variant(v) => {
                let inner = v.value.ok_or(ValueError::MissingField("Variant value"))?;
                Value::Variant {
                    constructor: v.constructor,
                    value: Box::new(Value::from_proto(inner, depth + 1)?),
                }
            }

            proto_value::Sum::Enum(e) => Value::Enum { value: e.value },
        };

        val.validate(depth)?;
        Ok(val)
    }

    /// Converts to Prost ProtoValue.
    pub fn to_proto(&self) -> ProtoValue {
        let sum = match self {
            Self::Unit => proto_value::Sum::Unit(()),
            Self::Bool(b) => proto_value::Sum::Bool(*b),
            Self::Int64(i) => proto_value::Sum::Int64(*i),
            Self::Date(d) => proto_value::Sum::Date(*d),
            Self::Timestamp(ts) => proto_value::Sum::Timestamp(*ts),
            Self::Numeric(n) => proto_value::Sum::Numeric(n.clone()),
            Self::Party(p) => proto_value::Sum::Party(p.clone()),
            Self::Text(t) => proto_value::Sum::Text(t.clone()),
            Self::ContractId(cid) => proto_value::Sum::ContractId(cid.clone()),
            Self::Optional(opt) => proto_value::Sum::Optional(Box::new(ProtoOptional {
                value: opt.as_ref().map(|v| v.to_proto()),
            })),
            Self::List(elements) => proto_value::Sum::List(ProtoList {
                elements: elements.iter().map(|e| e.to_proto()).collect(),
            }),
            Self::TextMap(entries) => proto_value::Sum::TextMap(ProtoTextMap {
                entries: entries
                    .iter()
                    .map(|(k, v)| ProtoTextMapEntry {
                        key: k.clone(),
                        value: Some(v.to_proto()),
                    })
                    .collect(),
            }),
            Self::GenMap(entries) => proto_value::Sum::Map(ProtoMap {
                entries: entries
                    .iter()
                    .map(|(k, v)| ProtoMapEntry {
                        key: Some(k.to_proto()),
                        value: Some(v.to_proto()),
                    })
                    .collect(),
            }),
            Self::Record { fields } => proto_value::Sum::Record(ProtoRecord {
                fields: fields
                    .iter()
                    .map(|f| ProtoRecordField {
                        value: Some(f.to_proto()),
                    })
                    .collect(),
            }),
            Self::Variant { constructor, value } => {
                proto_value::Sum::Variant(Box::new(ProtoVariant {
                    constructor: constructor.clone(),
                    value: Some(value.to_proto()),
                }))
            }
            Self::Enum { value } => proto_value::Sum::Enum(ProtoEnum {
                value: value.clone(),
            }),
        };

        ProtoValue { sum: Some(sum) }
    }

    /// Serializes value to protobuf bytes.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let pv = self.to_proto();
        pv.encode_to_vec()
    }

    /// Deserializes value from protobuf bytes.
    pub fn decode_from_slice(bytes: &[u8]) -> Result<Self, ValueError> {
        // [CANTON-NOTE: SEMANTICS] `ValueCoder.parseValue`: `setRecursionLimit(3 * MAXIMUM_NESTING + 1)`, bounded before decoding
        // (`ProtoValue` has the field numbers of the official `Value`).
        canton_proto::depth::check(
            "com.digitalasset.daml.lf.value.Value",
            bytes,
            3 * MAX_VALUE_RECURSION_DEPTH as u32 + 1,
        )
        .map_err(|e| ValueError::MalformedProtobuf(e.to_string()))?;
        let pv =
            ProtoValue::decode(bytes).map_err(|e| ValueError::MalformedProtobuf(e.to_string()))?;
        Self::from_proto(pv, 0)
    }
}

// -----------------------------------------------------------------------------
// Validation Helpers
// -----------------------------------------------------------------------------

fn validate_numeric_str(s: &str) -> Result<(), ValueError> {
    if s.is_empty() {
        return Err(ValueError::InvalidNumeric("empty string".into()));
    }

    let trimmed = s.strip_prefix('-').unwrap_or(s);
    if trimmed.is_empty() {
        return Err(ValueError::InvalidNumeric("only minus sign".into()));
    }

    let mut parts = trimmed.split('.');
    let Some(int_part) = parts.next() else {
        return Err(ValueError::InvalidNumeric("empty string".into()));
    };
    let frac_part = parts.next();

    if parts.next().is_some() {
        return Err(ValueError::InvalidNumeric("multiple decimal points".into()));
    }

    if int_part.is_empty() || !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(ValueError::InvalidNumeric("invalid integer part".into()));
    }

    let frac_len = if let Some(frac) = frac_part {
        if frac.is_empty() || !frac.chars().all(|c| c.is_ascii_digit()) {
            return Err(ValueError::InvalidNumeric("invalid fractional part".into()));
        }
        frac.len()
    } else {
        0
    };

    if frac_len > 37 {
        return Err(ValueError::InvalidNumeric(format!(
            "fractional scale {frac_len} exceeds maximum 37"
        )));
    }

    let total_digits = int_part.len() + frac_len;
    if total_digits > 38 {
        return Err(ValueError::InvalidNumeric(format!(
            "total digits {total_digits} exceeds maximum 38"
        )));
    }

    Ok(())
}

fn validate_party_str(s: &str) -> Result<(), ValueError> {
    if s.is_empty() {
        return Err(ValueError::InvalidParty("empty party string".into()));
    }
    if s.len() > 255 {
        return Err(ValueError::InvalidParty("party string > 255 bytes".into()));
    }
    if s.starts_with(' ') || s.ends_with(' ') {
        return Err(ValueError::InvalidParty(
            "party string cannot have leading or trailing whitespace".into(),
        ));
    }
    // Daml Party identifier specification: [a-zA-Z0-9:_\- ]+
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_' || c == '-' || c == ' ')
    {
        return Err(ValueError::InvalidParty(format!(
            "invalid character in party: {s}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_at_v01_roundtrip_all_primitive_types() {
        let values = vec![
            Value::Unit,
            Value::Bool(true),
            Value::Bool(false),
            Value::Int64(i64::MIN),
            Value::Int64(0),
            Value::Int64(i64::MAX),
            Value::Date(0),
            Value::Date(MIN_DATE_DAYS),
            Value::Date(MAX_DATE_DAYS),
            Value::Timestamp(0),
            Value::Timestamp(MIN_TIMESTAMP_MICROS),
            Value::Timestamp(MAX_TIMESTAMP_MICROS),
            Value::Numeric("12345678901234567890123456789012345678".to_string()),
            Value::Numeric("-123.4567890123456789012345678901234567".to_string()),
            Value::Party("Alice_123:Participant".to_string()),
            Value::Text("Hello, Daml 3.x with Unicode 🚀".to_string()),
            Value::ContractId(vec![0x00, 0x11, 0x22, 0x33, 0x44]),
            Value::Optional(Some(Box::new(Value::Int64(42)))),
            Value::Optional(None),
            Value::List(vec![Value::Int64(1), Value::Int64(2), Value::Int64(3)]),
            Value::TextMap(vec![
                ("key1".to_string(), Value::Text("val1".to_string())),
                ("key2".to_string(), Value::Bool(true)),
            ]),
            Value::Record {
                fields: vec![
                    Value::Party("Alice".to_string()),
                    Value::Numeric("100.00".to_string()),
                ],
            },
            Value::Variant {
                constructor: "SomeChoice".to_string(),
                value: Box::new(Value::Unit),
            },
            Value::Enum {
                value: "Active".to_string(),
            },
        ];

        for val in values {
            let bytes = val.encode_to_vec();
            let decoded =
                Value::decode_from_slice(&bytes).expect("roundtrip should decode cleanly");
            assert_eq!(val, decoded);
        }
    }

    #[test]
    fn test_at_v02_invalid_date_rejected() {
        assert!(Value::Date(MIN_DATE_DAYS - 1).validate(0).is_err());
        assert!(Value::Date(MAX_DATE_DAYS + 1).validate(0).is_err());
    }

    #[test]
    fn test_at_v02_invalid_timestamp_rejected() {
        assert!(Value::Timestamp(MIN_TIMESTAMP_MICROS - 1)
            .validate(0)
            .is_err());
        assert!(Value::Timestamp(MAX_TIMESTAMP_MICROS + 1)
            .validate(0)
            .is_err());
    }

    #[test]
    fn test_at_v02_invalid_numeric_rejected() {
        // > 37 scale
        assert!(
            Value::Numeric("1.12345678901234567890123456789012345678".to_string())
                .validate(0)
                .is_err()
        );
        // > 38 total digits
        assert!(
            Value::Numeric("123456789012345678901234567890123456789".to_string())
                .validate(0)
                .is_err()
        );
        // Bad format
        assert!(Value::Numeric("12.34.56".to_string()).validate(0).is_err());
        assert!(Value::Numeric("abc".to_string()).validate(0).is_err());
    }

    #[test]
    fn test_at_v02_invalid_party_rejected() {
        assert!(Value::Party("".to_string()).validate(0).is_err());
        assert!(Value::Party(" Alice".to_string()).validate(0).is_err());
        assert!(Value::Party("Alice ".to_string()).validate(0).is_err());
        assert!(Value::Party("   ".to_string()).validate(0).is_err());
        assert!(Value::Party("Alice@Daml!".to_string()).validate(0).is_err()); // @ and ! not permitted
    }

    #[test]
    fn test_at_a05_recursion_depth_limit() {
        // Build nested record deeper than 100
        let mut curr = Value::Unit;
        for _ in 0..105 {
            curr = Value::Optional(Some(Box::new(curr)));
        }
        let res = curr.validate(0);
        assert!(matches!(res, Err(ValueError::RecursionLimitExceeded(_))));
    }
}
