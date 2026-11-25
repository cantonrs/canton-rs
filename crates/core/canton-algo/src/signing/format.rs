//! Signature formats and the wire forms of signatures and delegations.

use std::collections::BTreeSet;

use crate::proto_wire::{as_i32, utf8, Reader, Value, WireError};

use super::keys::{create_public_key, fingerprint_from_proto, PublicKey};
use super::{KeyFormat, KeySpec, ProtoError, Usage};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFormat {
    /// Legacy: migrated to `Der` or `Concat` when a signature is created.
    Raw,
    Der,
    Concat,
    Symbolic,
}

impl SignatureFormat {
    /// The enum number of the proto.
    pub fn value(self) -> i32 {
        match self {
            SignatureFormat::Raw => 1,
            SignatureFormat::Der => 2,
            SignatureFormat::Concat => 3,
            SignatureFormat::Symbolic => 10000,
        }
    }

    fn from_proto(v: i32, field: &str) -> Result<SignatureFormat, ProtoError> {
        match v {
            0 => Err(ProtoError::FieldNotSet(field.into())),
            1 => Ok(SignatureFormat::Raw),
            2 => Ok(SignatureFormat::Der),
            3 => Ok(SignatureFormat::Concat),
            10000 => Ok(SignatureFormat::Symbolic),
            v => Err(ProtoError::UnrecognizedEnum(field.into(), v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmSpec {
    Ed25519,
    EcDsaSha256,
    EcDsaSha384,
    MlDsa65,
}

impl AlgorithmSpec {
    /// The enum number of the proto.
    pub fn value(self) -> i32 {
        match self {
            AlgorithmSpec::Ed25519 => 1,
            AlgorithmSpec::EcDsaSha256 => 2,
            AlgorithmSpec::EcDsaSha384 => 3,
            AlgorithmSpec::MlDsa65 => 4,
        }
    }

    /// `SigningAlgorithmSpec.fromProtoEnumOption`: unspecified is `None` (older messages carry no spec).
    fn from_proto_option(v: i32, field: &str) -> Result<Option<AlgorithmSpec>, ProtoError> {
        match v {
            0 => Ok(None),
            1 => Ok(Some(AlgorithmSpec::Ed25519)),
            2 => Ok(Some(AlgorithmSpec::EcDsaSha256)),
            3 => Ok(Some(AlgorithmSpec::EcDsaSha384)),
            4 => Ok(Some(AlgorithmSpec::MlDsa65)),
            v => Err(ProtoError::UnrecognizedEnum(field.into(), v)),
        }
    }

    pub(super) fn supported_key_specs(self) -> &'static [KeySpec] {
        match self {
            AlgorithmSpec::Ed25519 => &[KeySpec::EcCurve25519],
            AlgorithmSpec::EcDsaSha256 => &[KeySpec::EcP256, KeySpec::EcSecp256k1],
            AlgorithmSpec::EcDsaSha384 => &[KeySpec::EcP384],
            AlgorithmSpec::MlDsa65 => &[KeySpec::MlDsa65],
        }
    }

    pub(super) fn supported_format(self) -> SignatureFormat {
        match self {
            AlgorithmSpec::Ed25519 => SignatureFormat::Concat,
            _ => SignatureFormat::Der,
        }
    }
}

/// The delegation of a session key (`SignatureDelegation`), as read back by `toProtoV30`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub session_key: PublicKey,
    pub session_key_spec: KeySpec,
    pub valid_from_micros: i64,
    pub duration_seconds: i32,
    pub signature_format: SignatureFormat,
    pub signature: Vec<u8>,
    pub signature_spec: Option<AlgorithmSpec>,
}

/// A `Signature` as `Signature.fromProtoV30` builds it (after the legacy migration of the format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub format: SignatureFormat,
    pub signature: Vec<u8>,
    /// With a delegation this is the id of the session key, otherwise the signing key.
    pub signed_by: String,
    pub spec: Option<AlgorithmSpec>,
    pub delegation: Option<Delegation>,
    /// The long-term key that authorised the signature (the `signed_by` of the message).
    pub authorizing_key: String,
}

impl Signature {
    /// The message read back as the oracle prints it: `format|spec|signed_by|signature|delegation`.
    pub fn describe(&self) -> String {
        let delegation = match &self.delegation {
            None => "-".to_string(),
            Some(d) => format!(
                "{}/{}/{}/{}/{}/{}/{}",
                hex::encode(&d.session_key.key),
                match d.session_key_spec {
                    KeySpec::EcCurve25519 => 1,
                    KeySpec::EcP256 => 2,
                    KeySpec::EcP384 => 3,
                    KeySpec::EcSecp256k1 => 4,
                    KeySpec::MlDsa65 => 5,
                },
                d.valid_from_micros,
                d.duration_seconds,
                d.signature_format.value(),
                hex::encode(&d.signature),
                d.signature_spec.map_or(0, AlgorithmSpec::value)
            ),
        };
        format!(
            "{}|{}|{}|{}|{}",
            self.format.value(),
            self.spec.map_or(0, AlgorithmSpec::value),
            self.authorizing_key,
            hex::encode(&self.signature),
            delegation
        )
    }
}

/// `Signature.create`'s migration of a legacy `Raw` format.
///
/// [CANTON-NOTE: SEMANTICS] A `Raw` signature becomes `Concat` for Ed25519 and `Der` for ECDSA. Without an algorithm spec the
/// node looks at the length: exactly 64 bytes is `Concat`, anything else is `Der`.
fn migrate_format(
    format: SignatureFormat,
    spec: Option<AlgorithmSpec>,
    signature: &[u8],
) -> SignatureFormat {
    if format != SignatureFormat::Raw {
        return format;
    }
    match spec {
        Some(AlgorithmSpec::Ed25519) => SignatureFormat::Concat,
        Some(_) => SignatureFormat::Der,
        None if signature.len() == 64 => SignatureFormat::Concat,
        None => SignatureFormat::Der,
    }
}

/// The smallest and largest instant a ledger timestamp can hold, in microseconds since the epoch.
const TIMESTAMP_MIN: i64 = -62_135_596_800_000_000;

const TIMESTAMP_MAX: i64 = 253_402_300_799_999_999;

#[derive(Default)]
struct WireDelegation {
    session_key: Vec<u8>,
    session_key_spec: i32,
    from: i64,
    duration: i32,
    format: i32,
    signature: Vec<u8>,
    spec: i32,
}

impl WireDelegation {
    /// Merges one occurrence of the embedded message into `self` (protobuf merges repeated embedded messages).
    fn merge(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let mut r = Reader::new(bytes);
        while let Some((field, wt)) = r.tag()? {
            match field {
                1 | 6 => {
                    if let Value::Bytes(b) = r.value(field, wt, 2)? {
                        if field == 1 {
                            self.session_key = b.to_vec();
                        } else {
                            self.signature = b.to_vec();
                        }
                    }
                }
                2 | 3 | 4 | 5 | 7 => {
                    if let Value::Varint(v) = r.value(field, wt, 0)? {
                        match field {
                            2 => self.session_key_spec = as_i32(v),
                            3 => self.from = v as i64,
                            4 => self.duration = as_i32(v),
                            5 => self.format = as_i32(v),
                            _ => self.spec = as_i32(v),
                        }
                    }
                }
                _ => r.skip(field, wt)?,
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct WireSignature {
    format: i32,
    signature: Vec<u8>,
    signed_by: String,
    spec: i32,
    delegation: Option<WireDelegation>,
}

fn read_wire_signature(bytes: &[u8]) -> Result<WireSignature, WireError> {
    let mut out = WireSignature::default();
    let mut r = Reader::new(bytes);
    while let Some((field, wt)) = r.tag()? {
        match field {
            1 | 4 => {
                if let Value::Varint(v) = r.value(field, wt, 0)? {
                    if field == 1 {
                        out.format = as_i32(v);
                    } else {
                        out.spec = as_i32(v);
                    }
                }
            }
            2 => {
                if let Value::Bytes(b) = r.value(field, wt, 2)? {
                    out.signature = b.to_vec();
                }
            }
            3 => {
                if let Value::Bytes(b) = r.value(field, wt, 2)? {
                    out.signed_by = utf8(b)?;
                }
            }
            5 => {
                if let Value::Bytes(b) = r.value(field, wt, 2)? {
                    out.delegation
                        .get_or_insert_with(WireDelegation::default)
                        .merge(b)?;
                }
            }
            _ => r.skip(field, wt)?,
        }
    }
    Ok(out)
}

/// `Signature.fromProtoV30` applied to the wire bytes of a `v30.Signature`.
pub fn parse_signature(bytes: &[u8]) -> Result<Signature, ProtoError> {
    let m = read_wire_signature(bytes)?;
    let format = SignatureFormat::from_proto(m.format, "format")?;
    let long_term_key = fingerprint_from_proto(&m.signed_by, "signed_by")?;
    let spec = AlgorithmSpec::from_proto_option(m.spec, "signing_algorithm_spec")?;
    let delegation = m.delegation.as_ref().map(parse_delegation).transpose()?;
    // with a delegation the message's `signed_by` names the long-term key and the signer is the session key
    let signed_by = delegation.as_ref().map_or_else(
        || long_term_key.clone(),
        |d: &Delegation| d.session_key.id.clone(),
    );
    let format = migrate_format(format, spec, &m.signature);
    Ok(Signature {
        format,
        signature: m.signature,
        signed_by,
        spec,
        delegation,
        authorizing_key: long_term_key,
    })
}

/// `SignatureDelegation.fromProtoV30`.
fn parse_delegation(d: &WireDelegation) -> Result<Delegation, ProtoError> {
    let key_spec = KeySpec::from_proto(d.session_key_spec, "session_key_spec")?;
    let usage: BTreeSet<Usage> = [Usage::Protocol].into();
    let session_key = create_public_key(KeyFormat::DerX509Spki, &d.session_key, key_spec, usage)?;
    if !(TIMESTAMP_MIN..=TIMESTAMP_MAX).contains(&d.from) {
        return Err(ProtoError::TimestampConversion(format!(
            "cannot convert long {} into Timestamp",
            d.from
        )));
    }
    if d.duration <= 0 {
        return Err(ProtoError::InvariantViolation(
            "validity_period_duration_seconds must be positive".into(),
        ));
    }
    let format = SignatureFormat::from_proto(d.format, "format")?;
    let spec = AlgorithmSpec::from_proto_option(d.spec, "signing_algorithm_spec")?;
    Ok(Delegation {
        session_key,
        session_key_spec: key_spec,
        valid_from_micros: d.from,
        duration_seconds: d.duration,
        signature_format: migrate_format(format, spec, &d.signature),
        signature: d.signature.clone(),
        signature_spec: spec,
    })
}

/// `Signature.fromTrustedByteString`: the signature inside an `UntypedVersionedMessage` of version 30.
pub fn parse_versioned_signature(bytes: &[u8]) -> Result<Signature, ProtoError> {
    let mut data: Option<Vec<u8>> = None;
    let mut version = 0i32;
    let mut r = Reader::new(bytes);
    while let Some((field, wt)) = r.tag()? {
        match field {
            1 => {
                if let Value::Bytes(b) = r.value(field, wt, 2)? {
                    data = Some(b.to_vec());
                }
            }
            2 => {
                if let Value::Varint(v) = r.value(field, wt, 0)? {
                    version = as_i32(v);
                }
            }
            _ => r.skip(field, wt)?,
        }
    }
    let Some(data) = data else {
        return Err(ProtoError::FieldNotSet("signature: data".into()));
    };
    if version != 30 {
        return Err(ProtoError::Other(format!(
            "Unable to find deserializer for version ProtoVersion({version}) and message signature"
        )));
    }
    parse_signature(&data)
}
