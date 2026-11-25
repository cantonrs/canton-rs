//! Public and private key parsing, validation and fingerprints.

use std::collections::BTreeSet;

use canton_proto::com::digitalasset::canton::crypto::v30::{
    SigningPrivateKey as PbPrivateKey, SigningPublicKey as PbPublicKey,
};

use crate::ber;
use crate::ber::Params;
use crate::proto_wire::{as_i32, packed_i32s, utf8, Reader, Value};

use super::curves::{
    be_ge, be_is_zero, decode_point, ec_spki, ed25519_spki, trim_zeros, validate_ed25519_point,
    Curve, OID_EC_PUBLIC_KEY, OID_ED25519,
};
use super::{
    add_proof_of_ownership, crypto_err, key_spec_with_default_scheme, usage_is_valid,
    usages_from_proto, KeyFormat, KeySpec, ProtoError, Usage,
};

/// A public key as `SigningPublicKey.fromProtoV30` builds it (after migration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub key_spec: KeySpec,
    pub format: KeyFormat,
    pub usage: BTreeSet<Usage>,
    pub key: Vec<u8>,
    /// The fingerprint: the multihash of the key (the raw 32 bytes for an Ed25519 X.509 key) under purpose 12.
    pub id: String,
}

impl PublicKey {
    /// Builds a [`PublicKey`] from DER X.509 SPKI bytes *without* running key-curve validation.
    ///
    /// Mirrors constructing a `SigningPublicKey` without `CryptoKeyValidation.parseAndValidatePublicKey`
    /// before passing it into `verify_signature` (explaining the U-23 `InvalidSignature` vs
    /// `KeyParseAndValidateError` divergence in `crypto-accept-vectors.tsv`).
    pub fn from_unvalidated_spki_for_u23(
        key_spec: KeySpec,
        key: Vec<u8>,
        usage: BTreeSet<Usage>,
    ) -> Self {
        let fp_data = match key_spec {
            KeySpec::EcCurve25519 => ber::parse_spki(&key)
                .map(|spki| spki.key_bits)
                .unwrap_or_else(|_| key.clone()),
            _ => key.clone(),
        };
        let id = fingerprint(&fp_data);
        Self {
            key_spec,
            format: KeyFormat::DerX509Spki,
            usage: add_proof_of_ownership(&usage),
            key,
            id,
        }
    }
}

/// `Fingerprint.create`: the hash of the key data under the `PublicKeyFingerprint` purpose (12), as `1220...` hex.
fn fingerprint(data: &[u8]) -> String {
    crate::hash::multihash_sha256_hex(&crate::hash::sha256_with_purpose(12, data))
}

fn parse_public_key_fields(
    format: i32,
    public_key: &[u8],
    key_spec: i32,
    scheme: i32,
    usage: &[i32],
) -> Result<PublicKey, ProtoError> {
    let format = KeyFormat::from_proto(format)?;
    let key_spec = key_spec_with_default_scheme(key_spec, scheme)?;
    let usage = usages_from_proto(usage)?;
    create_public_key(format, public_key, key_spec, usage)
}

/// `SigningPublicKey.fromProtoV30` for a message that was decoded by prost.
pub fn parse_public_key(m: &PbPublicKey) -> Result<PublicKey, ProtoError> {
    #[allow(
        deprecated,
        reason = "populates legacy/deprecated Canton protobuf or pinned crypto fields for wire compatibility"
    )]
    let scheme = m.scheme;
    parse_public_key_fields(m.format, &m.public_key, m.key_spec, scheme, &m.usage)
}

/// `SigningPublicKey.fromProtoV30` from serialized protobuf wire bytes (truncated 64-bit enums, packed usage, unknown skips).
pub fn parse_public_key_bytes(bytes: &[u8]) -> Result<PublicKey, ProtoError> {
    let mut r = Reader::new(bytes);
    let mut format = 0i32;
    let mut public_key: Vec<u8> = Vec::new();
    let mut scheme = 0i32;
    let mut usage: Vec<i32> = Vec::new();
    let mut key_spec = 0i32;
    while let Some((field, wt)) = r.tag()? {
        match field {
            2 => {
                if let Value::Varint(v) = r.value(field, wt, 0)? {
                    format = as_i32(v);
                }
            }
            3 => {
                if let Value::Bytes(b) = r.value(field, wt, 2)? {
                    public_key = b.to_vec();
                }
            }
            4 => {
                if let Value::Varint(v) = r.value(field, wt, 0)? {
                    scheme = as_i32(v);
                }
            }
            5 => {
                if wt == 2 {
                    if let Value::Bytes(b) = r.value(field, wt, 2)? {
                        usage.extend(packed_i32s(b)?);
                    }
                } else if let Value::Varint(v) = r.value(field, wt, 0)? {
                    usage.push(as_i32(v));
                }
            }
            6 => {
                if let Value::Varint(v) = r.value(field, wt, 0)? {
                    key_spec = as_i32(v);
                }
            }
            _ => r.skip(field, wt)?,
        }
    }
    parse_public_key_fields(format, &public_key, key_spec, scheme, &usage)
}

/// `SigningPublicKey.create`: usage check, fingerprint data, legacy migration, validation.
pub fn create_public_key(
    format: KeyFormat,
    key: &[u8],
    key_spec: KeySpec,
    usage: BTreeSet<Usage>,
) -> Result<PublicKey, ProtoError> {
    if !usage_is_valid(&usage) {
        return Err(crypto_err("InvalidKeyUsage"));
    }
    // the fingerprint of an Ed25519 X.509 key covers only the raw key
    let data_for_fingerprint = match (format, key_spec) {
        (KeyFormat::DerX509Spki, KeySpec::EcCurve25519) => {
            ber::parse_spki(key).map_err(crypto_err)?.key_bits
        }
        _ => key.to_vec(),
    };
    let id = fingerprint(&data_for_fingerprint);
    let usage = add_proof_of_ownership(&usage);
    // [CANTON-NOTE: SEMANTICS] Legacy formats are migrated, and only these: a raw Ed25519 key becomes an X.509 key, and a
    // `DER` EC key (P-256, P-384) is already an X.509 key. `DER` secp256k1 and `DER` Ed25519 stay legacy and fail validation.
    let (format, key) = match (key_spec, format) {
        (KeySpec::EcCurve25519, KeyFormat::Raw) => {
            // SubjectPublicKeyInfo { AlgorithmIdentifier { id-Ed25519 }, BIT STRING key }
            let mut bit = vec![0x03];
            push_len(&mut bit, key.len() + 1);
            bit.push(0x00);
            bit.extend_from_slice(key);
            let mut body = vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
            body.extend_from_slice(&bit);
            let mut out = vec![0x30];
            push_len(&mut out, body.len());
            out.extend_from_slice(&body);
            (KeyFormat::DerX509Spki, out)
        }
        (KeySpec::EcP256 | KeySpec::EcP384 | KeySpec::MlDsa65, KeyFormat::Der) => {
            (KeyFormat::DerX509Spki, key.to_vec())
        }
        (_, f) => (f, key.to_vec()),
    };
    match format {
        KeyFormat::DerX509Spki => validate_public_key_bytes(key_spec, &key)?,
        KeyFormat::Symbolic => {}
        f => {
            return Err(crypto_err(format!(
                "Invalid format for public key: {}",
                f.name()
            )))
        }
    }
    Ok(PublicKey {
        key_spec,
        format,
        usage,
        key,
        id,
    })
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

/// `CryptoKeyValidation.parseAndValidatePublicKey` for the `DerX509Spki` format.
fn validate_public_key_bytes(key_spec: KeySpec, key: &[u8]) -> Result<(), ProtoError> {
    let spki = ber::parse_spki(key).map_err(crypto_err)?;
    match key_spec {
        KeySpec::EcCurve25519 => {
            if spki.algorithm.oid != OID_ED25519 {
                return Err(crypto_err("not an Ed25519 key"));
            }
            if !matches!(spki.algorithm.params, Params::Absent | Params::Null) {
                return Err(crypto_err("unexpected Ed25519 parameters"));
            }
            // [CANTON-NOTE: SEMANTICS] An Ed25519 X.509 key written with an indefinite length, or with unused bits in its
            // BIT STRING, is refused (an EC key is not): measured, pk `indefiniteLength` and `generatorUnused1`.
            if spki.indefinite || spki.unused_bits != 0 {
                return Err(crypto_err("Ed25519 key container not accepted"));
            }
            validate_ed25519_point(&spki.key_bits).map_err(crypto_err)
        }
        KeySpec::EcP256 | KeySpec::EcP384 | KeySpec::EcSecp256k1 => {
            let declared = key_spec.curve().expect("an EC key spec has a curve");
            if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
                return Err(crypto_err("not an EC key"));
            }
            let key_curve = Curve::from_algorithm_params(&spki.algorithm.params)?;
            let (x, y) = decode_point(key_curve, &spki.key_bits).map_err(crypto_err)?;
            if key_curve == declared {
                return Ok(());
            }
            // [CANTON-NOTE: SEMANTICS] A key of another curve than the declared spec: the node rebuilds the point on the
            // declared curve. A coordinate that does not fit that curve's field makes `createPoint` THROW; otherwise the
            // point is simply not on the curve (an error). Measured: a P-384 key declared as P-256 throws.
            if be_ge(&x, declared.prime()) || be_ge(&y, declared.prime()) {
                return Err(ProtoError::Thrown(
                    "IllegalArgumentException",
                    "x value invalid for the declared curve's field element".into(),
                ));
            }
            Err(crypto_err("EC key not in curve"))
        }
        KeySpec::MlDsa65 => {
            if spki.algorithm.oid != crate::mldsa65::OID_ML_DSA_65
                || !matches!(spki.algorithm.params, Params::Absent)
                || spki.indefinite
                || spki.unused_bits != 0
            {
                return Err(crypto_err("not an ML-DSA-65 public key container"));
            }
            crate::mldsa65::validate_public_key(&spki.key_bits).map_err(crypto_err)
        }
    }
}

/// A private key as `SigningPrivateKey.fromProtoV30` builds it, with the public key derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    pub key_spec: KeySpec,
    pub format: KeyFormat,
    pub usage: BTreeSet<Usage>,
    pub id: String,
    /// The X.509 public key (what `SigningKeyPair.create` derives); `None` for the symbolic format.
    pub public_spki: Option<Vec<u8>>,
}

/// `Fingerprint.fromProtoPrimitive`: a Daml-LF party string of at most 255 characters, then at most 68 characters.
///
/// [CANTON-NOTE: SEMANTICS] The id of a key is NOT checked to be a hash: any string of `A-Za-z0-9`, `:`, `-`, `_` and
/// space up to 68 characters is a valid fingerprint (measured: sk `idNotFingerprint`, `idShortHex`).
pub(super) fn fingerprint_from_proto(s: &str, field: &str) -> Result<String, ProtoError> {
    if s.is_empty() {
        return Err(ProtoError::StringConversion(
            "Daml-LF Party is empty".into(),
        ));
    }
    if s.chars().count() > 255 {
        return Err(ProtoError::StringConversion(
            "Daml-LF Party is too long (max: 255)".into(),
        ));
    }
    if let Some(c) = s
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | ' ')))
    {
        return Err(ProtoError::StringConversion(format!(
            "non expected character {c:?} in Daml-LF Party"
        )));
    }
    if s.len() > 68 {
        return Err(ProtoError::InvariantViolation(format!(
            "The given {field} has a maximum length of 68"
        )));
    }
    Ok(s.to_string())
}

fn parse_private_key_fields(
    id: &str,
    format: i32,
    private_key: &[u8],
    key_spec: i32,
    scheme: i32,
    usage: &[i32],
) -> Result<PrivateKey, ProtoError> {
    let id = fingerprint_from_proto(id, "id")?;
    let format = KeyFormat::from_proto(format)?;
    let key_spec = key_spec_with_default_scheme(key_spec, scheme)?;
    let usage = usages_from_proto(usage)?;
    if !usage_is_valid(&usage) {
        return Err(crypto_err("InvalidKeyUsage"));
    }
    let usage = add_proof_of_ownership(&usage);
    // legacy migrations: a raw Ed25519 seed is wrapped into PKCS#8, a `DER` P-256 or P-384 key already is PKCS#8
    let (format, key) = match (key_spec, format) {
        (KeySpec::EcCurve25519, KeyFormat::Raw) => {
            if private_key.len() != 32 {
                return Err(crypto_err("an Ed25519 seed is 32 bytes"));
            }
            let mut out = vec![
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
                0x04, 0x20,
            ];
            out.extend_from_slice(private_key);
            (KeyFormat::DerPkcs8Pki, out)
        }
        (KeySpec::EcP256 | KeySpec::EcP384 | KeySpec::MlDsa65, KeyFormat::Der) => {
            (KeyFormat::DerPkcs8Pki, private_key.to_vec())
        }
        (_, f) => (f, private_key.to_vec()),
    };
    let public_spki = match format {
        KeyFormat::DerPkcs8Pki => Some(validate_private_key_bytes(key_spec, &key)?),
        KeyFormat::Symbolic => None,
        f => {
            return Err(crypto_err(format!(
                "Invalid format for private key: {}",
                f.name()
            )))
        }
    };
    Ok(PrivateKey {
        key_spec,
        format,
        usage,
        id,
        public_spki,
    })
}

/// `SigningPrivateKey.fromProtoV30`.
pub fn parse_private_key(m: &PbPrivateKey) -> Result<PrivateKey, ProtoError> {
    #[allow(
        deprecated,
        reason = "populates legacy/deprecated Canton protobuf or pinned crypto fields for wire compatibility"
    )]
    let scheme = m.scheme;
    parse_private_key_fields(
        &m.id,
        m.format,
        &m.private_key,
        m.key_spec,
        scheme,
        &m.usage,
    )
}

/// `SigningPrivateKey.fromProtoV30` from serialized protobuf wire bytes.
pub fn parse_private_key_bytes(bytes: &[u8]) -> Result<PrivateKey, ProtoError> {
    let mut r = Reader::new(bytes);
    let mut id = String::new();
    let mut format = 0i32;
    let mut private_key: Vec<u8> = Vec::new();
    let mut scheme = 0i32;
    let mut usage: Vec<i32> = Vec::new();
    let mut key_spec = 0i32;
    while let Some((field, wt)) = r.tag()? {
        match field {
            1 => {
                if let Value::Bytes(b) = r.value(field, wt, 2)? {
                    id = utf8(b)?;
                }
            }
            2 => {
                if let Value::Varint(v) = r.value(field, wt, 0)? {
                    format = as_i32(v);
                }
            }
            3 => {
                if let Value::Bytes(b) = r.value(field, wt, 2)? {
                    private_key = b.to_vec();
                }
            }
            4 => {
                if let Value::Varint(v) = r.value(field, wt, 0)? {
                    scheme = as_i32(v);
                }
            }
            5 => {
                if wt == 2 {
                    if let Value::Bytes(b) = r.value(field, wt, 2)? {
                        usage.extend(packed_i32s(b)?);
                    }
                } else if let Value::Varint(v) = r.value(field, wt, 0)? {
                    usage.push(as_i32(v));
                }
            }
            6 => {
                if let Value::Varint(v) = r.value(field, wt, 0)? {
                    key_spec = as_i32(v);
                }
            }
            _ => r.skip(field, wt)?,
        }
    }
    parse_private_key_fields(&id, format, &private_key, key_spec, scheme, &usage)
}

/// Validates a PKCS#8 private key against its key spec and returns the X.509 public key derived from it.
fn validate_private_key_bytes(key_spec: KeySpec, key: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let pki = ber::parse_pkcs8(key).map_err(crypto_err)?;
    match key_spec {
        KeySpec::EcCurve25519 => {
            if pki.algorithm.oid != OID_ED25519
                || !matches!(pki.algorithm.params, Params::Absent | Params::Null)
            {
                return Err(crypto_err("not an Ed25519 private key"));
            }
            // the private key is an OCTET STRING that holds the 32-byte seed
            let inner = ber::read_only(&pki.private_key).map_err(crypto_err)?;
            if inner.tag != ber::OCTET_STRING || inner.content.len() != 32 {
                return Err(crypto_err("an Ed25519 seed is 32 bytes"));
            }
            let seed: [u8; 32] = inner.content.try_into().expect("length checked above");
            let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
            Ok(ed25519_spki(public.as_bytes()))
        }
        KeySpec::EcP256 | KeySpec::EcP384 | KeySpec::EcSecp256k1 => {
            let declared = key_spec.curve().expect("an EC key spec has a curve");
            if pki.algorithm.oid != OID_EC_PUBLIC_KEY {
                return Err(crypto_err("not an EC private key"));
            }
            let key_curve = Curve::from_algorithm_params(&pki.algorithm.params)?;
            // the scalar: a bare INTEGER, or `ECPrivateKey { INTEGER version, OCTET STRING d, ... }`
            let inner = ber::read_only(&pki.private_key).map_err(crypto_err)?;
            let d: Vec<u8> = match inner.tag {
                ber::INTEGER => {
                    // a signed integer: a set high bit is a negative number, which is out of range
                    if inner.content.first().is_none_or(|b| b & 0x80 != 0) {
                        return Err(crypto_err("private key scalar is out of range"));
                    }
                    inner.content.to_vec()
                }
                ber::SEQUENCE => {
                    let parts = ber::children(&inner).map_err(crypto_err)?;
                    if parts.len() < 2
                        || parts[0].tag != ber::INTEGER
                        || parts[1].tag != ber::OCTET_STRING
                    {
                        return Err(crypto_err("not an ECPrivateKey"));
                    }
                    parts[1].content.to_vec()
                }
                _ => return Err(crypto_err("unexpected private key structure")),
            };
            if key_curve != declared {
                return Err(crypto_err(
                    "EC private key parameters do not match expected curve",
                ));
            }
            // [CANTON-NOTE: SEMANTICS] The scalar is an integer: its length is free (a 33-byte value with a leading zero
            // or a 1-byte value are fine) but it must satisfy 1 <= d < n. The public key is derived from d, not read from
            // the optional public-key field of the structure.
            if be_is_zero(&d) || be_ge(&d, declared.order()) {
                return Err(crypto_err("private key scalar is out of range"));
            }
            let d = trim_zeros(&d);
            let mut padded = vec![0u8; declared.size() - d.len()];
            padded.extend_from_slice(d);
            Ok(ec_spki(declared, &public_point(declared, &padded)?))
        }
        KeySpec::MlDsa65 => {
            if pki.algorithm.oid != crate::mldsa65::OID_ML_DSA_65
                || !matches!(pki.algorithm.params, Params::Absent)
            {
                return Err(crypto_err("not an ML-DSA-65 private key"));
            }
            let pk = crate::mldsa65::derive_public_key_from_pkcs8_inner(&pki.private_key)
                .map_err(crypto_err)?;
            Ok(crate::mldsa65::encode_spki(&pk))
        }
    }
}

fn public_point(curve: Curve, scalar: &[u8]) -> Result<Vec<u8>, ProtoError> {
    macro_rules! derive {
        ($c:ident, $tr:ident, $m:ident) => {{
            use $c::elliptic_curve::sec1::$tr as _;
            let sk = $c::SecretKey::from_slice(scalar)
                .map_err(|_| crypto_err("private key scalar is out of range"))?;
            sk.public_key().$m(false).as_bytes().to_vec()
        }};
    }
    Ok(match curve {
        Curve::P256 => derive!(p256, ToSec1Point, to_sec1_point),
        Curve::P384 => derive!(p384, ToSec1Point, to_sec1_point),
        Curve::K256 => derive!(k256, ToEncodedPoint, to_encoded_point),
    })
}

/// What `pure.sign` says about a parsed private key: only its usage is checked here.
pub fn sign_usage_check(key: &PrivateKey, expected: &BTreeSet<Usage>) -> Result<(), &'static str> {
    if key.usage.intersection(expected).next().is_some() {
        Ok(())
    } else {
        Err("InvalidKeyUsage")
    }
}
