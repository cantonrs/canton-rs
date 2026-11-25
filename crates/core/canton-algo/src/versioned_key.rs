//! Decoding a version-wrapped `SigningPublicKey` the way Canton 3.7.2 does (AT-A06).
//!
//! A Canton key travels as `UntypedVersionedMessage { oneof wrapper { bytes data = 1 }, int32 version = 2 }` around a `v30`
//! message. The version selects the deserializer; it must not be possible to present data of another version, or data the
//! deserializer does not understand, as a valid v30 key.
//!
//! [CANTON-NOTE: ORACLE] Every rule below was measured on a Canton 3.7.2 node (`SigningPublicKey.fromTrustedByteString`,
//! tests/oracle/canton-crypto `ver` lines, 29 cases): a version other than 30 is refused, a 64-bit varint is truncated to its
//! low 32 bits (2^40 + 30 is version 30), the last of duplicate fields wins, unknown fields are ignored, an unrecognised enum
//! number is an error and not a default, an unspecified `format` or `key_spec` is an error, an empty `usage` list means every
//! usage, and the key bytes are validated against the key spec and format. The key rules themselves (legacy formats, EC point
//! forms, usages, key specs) live in [`crate::signing`] and are measured by the `pk` lines (U-12).
use crate::proto_wire::{as_i32, Reader, Value, WireError};
use crate::signing::{
    parse_private_key_bytes, parse_public_key_bytes, KeyFormat, KeySpec, ProtoError, Usage,
};

/// The only protobuf version this deserializer exists for.
pub const SUPPORTED_VERSION: i32 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDecodeError {
    /// The bytes are not a protobuf message at all.
    Buffer(String),
    /// A required field is absent.
    FieldNotSet(String),
    /// There is no deserializer for this version.
    UnsupportedVersion(i32),
    /// An enum field holds a number this version does not define.
    UnrecognizedEnum(String, i32),
    /// The key bytes do not parse as the declared key.
    CryptoDeserialization(String),
    /// The node throws an exception here instead of returning an error.
    Thrown(String),
}

/// A decoded key, named as the node prints it (for comparison with the recording).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedKey {
    pub key_spec: &'static str,
    pub format: &'static str,
    /// The usages, sorted by name.
    pub usage: Vec<&'static str>,
}

fn unwrap_versioned_bytes(bytes: &[u8]) -> Result<Vec<u8>, KeyDecodeError> {
    let mut r = Reader::new(bytes);
    let mut data: Option<Vec<u8>> = None;
    let mut version: i32 = 0;
    while let Some((field, wt)) = r
        .tag()
        .map_err(|e: WireError| KeyDecodeError::Buffer(format!("{e:?}")))?
    {
        match field {
            1 => {
                if let Value::Bytes(b) = r
                    .value(field, wt, 2)
                    .map_err(|e| KeyDecodeError::Buffer(format!("{e:?}")))?
                {
                    data = Some(b.to_vec());
                }
            }
            2 => {
                if let Value::Varint(v) = r
                    .value(field, wt, 0)
                    .map_err(|e| KeyDecodeError::Buffer(format!("{e:?}")))?
                {
                    version = as_i32(v);
                }
            }
            _ => r
                .skip(field, wt)
                .map_err(|e| KeyDecodeError::Buffer(format!("{e:?}")))?,
        }
    }
    let Some(inner) = data else {
        return Err(KeyDecodeError::FieldNotSet("data".into()));
    };
    if version != SUPPORTED_VERSION {
        return Err(KeyDecodeError::UnsupportedVersion(version));
    }
    Ok(inner)
}

fn map_proto_err(e: ProtoError) -> KeyDecodeError {
    match e {
        ProtoError::FieldNotSet(f) => KeyDecodeError::FieldNotSet(f),
        ProtoError::UnrecognizedEnum(f, v) => KeyDecodeError::UnrecognizedEnum(f, v),
        ProtoError::Thrown("InvalidProtocolBufferException" | "InvalidWireTypeException", m) => {
            KeyDecodeError::Buffer(m)
        }
        ProtoError::Thrown(_, m) => KeyDecodeError::Thrown(m),
        other => KeyDecodeError::CryptoDeserialization(format!("{other:?}")),
    }
}

fn finish_decoded_key(
    key_spec: KeySpec,
    format: KeyFormat,
    usages: &std::collections::BTreeSet<Usage>,
) -> DecodedKey {
    let mut usage: Vec<&'static str> = usages.iter().map(|u| u.name()).collect();
    usage.sort_unstable();
    DecodedKey {
        key_spec: key_spec.name(),
        format: format.name(),
        usage,
    }
}

pub fn decode_versioned_signing_public_key(bytes: &[u8]) -> Result<DecodedKey, KeyDecodeError> {
    let data = unwrap_versioned_bytes(bytes)?;
    let key = parse_public_key_bytes(&data).map_err(map_proto_err)?;
    Ok(finish_decoded_key(key.key_spec, key.format, &key.usage))
}

pub fn decode_versioned_signing_private_key(bytes: &[u8]) -> Result<DecodedKey, KeyDecodeError> {
    let data = unwrap_versioned_bytes(bytes)?;
    let key = parse_private_key_bytes(&data).map_err(map_proto_err)?;
    Ok(finish_decoded_key(key.key_spec, key.format, &key.usage))
}
