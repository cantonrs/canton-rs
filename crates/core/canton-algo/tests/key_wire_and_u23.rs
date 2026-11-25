//! C2 (`S-CRYPTO-009`): wire mutation tests, U-12 gaps (ML-DSA-65, explicit EC params,
//! unsupported curves, non-minimal OID, PKCS#8 [0]/[1], Ed25519 mixed-torsion P + T_8),
//! and full 14-vector U-23 reconciliation between the two provenance TSVs.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
// [CANTON-NOTE: STYLE] `(field << 3) | 0` spells the protobuf tag as field number and wire type 0 on purpose.
#![allow(
    clippy::identity_op,
    reason = "bit shift tag (field << 3) | 0 intentionally documents protobuf wire encoding"
)]

use std::collections::BTreeSet;

use canton_algo::mldsa65;
use canton_algo::signing::{
    create_public_key, parse_private_key, parse_private_key_bytes, parse_public_key,
    parse_public_key_bytes, verify_signature, verify_signature_allowing_experimental,
    AlgorithmSpec, KeyFormat, KeySpec, ProtoError, PublicKey, Signature, SignatureFormat, Usage,
    VerifyError,
};
use canton_algo::versioned_key::{
    decode_versioned_signing_private_key, decode_versioned_signing_public_key, KeyDecodeError,
};
use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::pkcs8::EncodePrivateKey as _;

fn proto_varint(field: u32, val: u64, out: &mut Vec<u8>) {
    encode_raw_varint(((u64::from(field)) << 3) | 0, out);
    encode_raw_varint(val, out);
}

fn proto_bytes(field: u32, data: &[u8], out: &mut Vec<u8>) {
    encode_raw_varint(((u64::from(field)) << 3) | 2, out);
    encode_raw_varint(data.len() as u64, out);
    out.extend_from_slice(data);
}

fn encode_raw_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn wrap_versioned(version: u64, data: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(d) = data {
        proto_bytes(1, d, &mut out);
    }
    proto_varint(2, version, &mut out);
    out
}

fn ed25519_sample() -> ([u8; 32], Vec<u8>, Vec<u8>) {
    let seed = [0x11u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pk_bytes = sk.verifying_key().to_bytes();
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(&pk_bytes);
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    pkcs8.extend_from_slice(&seed);
    (pk_bytes, spki, pkcs8)
}

fn pubkey_wire(format: u64, spki: &[u8], scheme: u64, usages: &[u64], key_spec: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if format != 0 {
        proto_varint(2, format, &mut out);
    }
    if !spki.is_empty() {
        proto_bytes(3, spki, &mut out);
    }
    if scheme != 0 {
        proto_varint(4, scheme, &mut out);
    }
    for &u in usages {
        proto_varint(5, u, &mut out);
    }
    if key_spec != 0 {
        proto_varint(6, key_spec, &mut out);
    }
    out
}

fn privkey_wire(
    id: &str,
    format: u64,
    pkcs8: &[u8],
    scheme: u64,
    usages: &[u64],
    key_spec: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    if !id.is_empty() {
        proto_bytes(1, id.as_bytes(), &mut out);
    }
    if format != 0 {
        proto_varint(2, format, &mut out);
    }
    if !pkcs8.is_empty() {
        proto_bytes(3, pkcs8, &mut out);
    }
    if scheme != 0 {
        proto_varint(4, scheme, &mut out);
    }
    for &u in usages {
        proto_varint(5, u, &mut out);
    }
    if key_spec != 0 {
        proto_varint(6, key_spec, &mut out);
    }
    out
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else if content.len() < 0x100 {
        out.extend_from_slice(&[0x81, content.len() as u8]);
    } else {
        out.extend_from_slice(&[0x82, (content.len() >> 8) as u8, content.len() as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn der_int_be(unsigned_be: &[u8]) -> Vec<u8> {
    let trimmed = &unsigned_be[unsigned_be.iter().take_while(|b| **b == 0).count()..];
    let mut body = Vec::new();
    if trimmed.is_empty() {
        body.push(0);
    } else {
        if trimmed[0] & 0x80 != 0 {
            body.push(0);
        }
        body.extend_from_slice(trimmed);
    }
    der_tlv(0x02, &body)
}

#[test]
fn wire_mutations_signing_public_and_private_keys() {
    let (raw_ed, spki_ed, pkcs8_ed) = ed25519_sample();
    let (_, p256_spki, p256_pkcs8) = p256_sample();

    // 1..5: duplicate fields last-wins on SigningPublicKey
    let mut dup_spec = pubkey_wire(4, &spki_ed, 0, &[4], 2);
    proto_varint(6, 1, &mut dup_spec);
    assert_eq!(
        parse_public_key_bytes(&dup_spec).unwrap().key_spec,
        KeySpec::EcCurve25519
    );

    let mut dup_format = pubkey_wire(5, &spki_ed, 0, &[4], 1);
    proto_varint(2, 4, &mut dup_format);
    assert_eq!(
        parse_public_key_bytes(&dup_format).unwrap().format,
        KeyFormat::DerX509Spki
    );

    let mut dup_key = pubkey_wire(4, b"garbage", 0, &[4], 1);
    proto_bytes(3, &spki_ed, &mut dup_key);
    assert_eq!(
        parse_public_key_bytes(&dup_key).unwrap().key_spec,
        KeySpec::EcCurve25519
    );

    let mut dup_scheme = pubkey_wire(4, &spki_ed, 99, &[4], 0);
    proto_varint(4, 1, &mut dup_scheme);
    assert_eq!(
        parse_public_key_bytes(&dup_scheme).unwrap().key_spec,
        KeySpec::EcCurve25519
    );

    let mut key_spec_beats_bad_scheme = pubkey_wire(4, &spki_ed, 777, &[4], 1);
    proto_varint(4, 777, &mut key_spec_beats_bad_scheme);
    assert_eq!(
        parse_public_key_bytes(&key_spec_beats_bad_scheme)
            .unwrap()
            .key_spec,
        KeySpec::EcCurve25519
    );

    // 6..9: packed usages & retired usage 2 & unknown usages
    let mut packed = pubkey_wire(4, &spki_ed, 0, &[], 1);
    let mut packed_vals = Vec::new();
    encode_raw_varint(2, &mut packed_vals); // retired -> dropped -> defaults to all usages
    proto_bytes(5, &packed_vals, &mut packed);
    let pk_all = parse_public_key_bytes(&packed).unwrap();
    assert_eq!(pk_all.usage, Usage::all());

    let mut packed_multi = pubkey_wire(4, &spki_ed, 0, &[], 1);
    let mut multi_vals = Vec::new();
    encode_raw_varint(1, &mut multi_vals);
    encode_raw_varint(3, &mut multi_vals);
    proto_bytes(5, &multi_vals, &mut packed_multi);
    let pk_multi = parse_public_key_bytes(&packed_multi).unwrap();
    assert!(pk_multi.usage.contains(&Usage::Namespace));
    assert!(pk_multi.usage.contains(&Usage::SequencerAuthentication));

    let bad_packed_enum = {
        let mut w = pubkey_wire(4, &spki_ed, 0, &[], 1);
        proto_bytes(5, &[99], &mut w);
        w
    };
    assert_eq!(
        parse_public_key_bytes(&bad_packed_enum).unwrap_err(),
        ProtoError::UnrecognizedEnum("usage".into(), 99)
    );

    let empty_packed = {
        let mut w = pubkey_wire(4, &spki_ed, 0, &[], 1);
        proto_bytes(5, &[], &mut w);
        w
    };
    assert_eq!(
        parse_public_key_bytes(&empty_packed).unwrap().usage,
        Usage::all()
    );

    // 10..13: unknown fields skipped (varint, 64-bit, length-delimited, group, 32-bit)
    let mut with_unknowns = pubkey_wire(4, &spki_ed, 0, &[4], 1);
    proto_varint(99, 123456, &mut with_unknowns);
    with_unknowns.extend_from_slice(&[(100 << 3) | 1, 1, 2, 3, 4, 5, 6, 7, 8]); // fixed64
    with_unknowns.extend_from_slice(&[(101 << 3) | 5, 1, 2, 3, 4]); // fixed32
    with_unknowns.extend_from_slice(&[(102 << 3) | 3, (1 << 3) | 0, 7, (102 << 3) | 4]); // group
    proto_bytes(103, b"ignored", &mut with_unknowns);
    assert_eq!(
        parse_public_key_bytes(&with_unknowns).unwrap().key_spec,
        KeySpec::EcCurve25519
    );

    // 14..17: 64-bit varint truncation on key_spec / format / outer version
    let trunc_pub = pubkey_wire(
        (1u64 << 40) | 4,
        &spki_ed,
        0,
        &[(1u64 << 32) | 4],
        (1u64 << 48) | 1,
    );
    let wrapped = wrap_versioned((1u64 << 40) | 30, Some(&trunc_pub));
    let decoded = decode_versioned_signing_public_key(&wrapped).unwrap();
    assert_eq!(decoded.key_spec, "EC-Curve25519");
    assert_eq!(decoded.format, "DER-encoded X.509 SubjectPublicKeyInfo");

    // 18..25: wrong-valid-wire-type skips vs invalid-wire-type (wt=6/7) / truncated protobuf errors
    // Valid wrong wire type (wt=2 on field 2 format) skips field 2 -> FieldNotSet("format")
    assert_eq!(
        parse_public_key_bytes(&[(2 << 3) | 2, 0]),
        Err(ProtoError::FieldNotSet("format".into()))
    );
    // Invalid protobuf wire type (wt=6 or wt=7) -> InvalidWireTypeException -> KeyDecodeError::Buffer
    assert!(matches!(
        parse_public_key_bytes(&[(2 << 3) | 6]),
        Err(ProtoError::Thrown("InvalidWireTypeException", _))
    ));
    assert!(matches!(
        decode_versioned_signing_public_key(&wrap_versioned(30, Some(&[(2 << 3) | 7]))),
        Err(KeyDecodeError::Buffer(_))
    ));
    // Valid wrong wire type (wt=0 on field 3 bytes) skips field 3 -> empty key -> CryptoDeserializationError
    let mut wrong_wt_key = pubkey_wire(4, &[], 0, &[4], 1);
    proto_varint(3, 1, &mut wrong_wt_key);
    assert_eq!(
        parse_public_key_bytes(&wrong_wt_key).unwrap_err().class(),
        "CryptoDeserializationError"
    );
    // Valid wrong wire type (wt=5 fixed32 on field 5 usage) skips usage -> defaults to Usage::all()
    let mut skipped_wt_usage = pubkey_wire(4, &spki_ed, 0, &[], 1);
    skipped_wt_usage.extend_from_slice(&[(5 << 3) | 5, 1, 2, 3, 4]);
    assert_eq!(
        parse_public_key_bytes(&skipped_wt_usage).unwrap().usage,
        Usage::all()
    );
    assert!(matches!(
        parse_public_key_bytes(&[(3 << 3) | 2, 10, 1, 2]),
        Err(ProtoError::Thrown("InvalidProtocolBufferException", _))
    ));
    assert!(matches!(
        parse_public_key_bytes(&[(2 << 3) | 0, 0x80]),
        Err(ProtoError::Thrown("InvalidProtocolBufferException", _))
    ));
    // Overlong 11-byte varint
    assert!(matches!(
        parse_public_key_bytes(&[
            (2 << 3) | 0,
            0x81,
            0x81,
            0x81,
            0x81,
            0x81,
            0x81,
            0x81,
            0x81,
            0x81,
            0x81,
            0x01
        ]),
        Err(ProtoError::Thrown("InvalidProtocolBufferException", _))
    ));
    // Unterminated start group
    assert!(matches!(
        parse_public_key_bytes(&[(99 << 3) | 3]),
        Err(ProtoError::Thrown("InvalidProtocolBufferException", _))
    ));

    // 26..30: versioned wrapper duplicate / missing / wrong version / truncated outer varint
    let ok_v30 = wrap_versioned(30, Some(&pubkey_wire(4, &spki_ed, 0, &[4], 1)));
    assert!(decode_versioned_signing_public_key(&ok_v30).is_ok());
    let mut dup_ver = wrap_versioned(31, Some(&pubkey_wire(4, &spki_ed, 0, &[4], 1)));
    proto_varint(2, 30, &mut dup_ver);
    assert!(decode_versioned_signing_public_key(&dup_ver).is_ok());
    assert_eq!(
        decode_versioned_signing_public_key(&wrap_versioned(30, None)),
        Err(KeyDecodeError::FieldNotSet("data".into()))
    );
    assert_eq!(
        decode_versioned_signing_public_key(&wrap_versioned(
            29,
            Some(&pubkey_wire(4, &spki_ed, 0, &[4], 1))
        )),
        Err(KeyDecodeError::UnsupportedVersion(29))
    );
    // Outer wrapper wrong valid wire type (wt=0 on field 1 data) skips field 1 -> FieldNotSet("data")
    assert_eq!(
        decode_versioned_signing_public_key(&[(1 << 3) | 0, 1]),
        Err(KeyDecodeError::FieldNotSet("data".into()))
    );

    // 31..44: SigningPrivateKey wire & versioned mutations
    let priv_ed = privkey_wire("key-1", 5, &pkcs8_ed, 0, &[4], 1);
    let wrapped_priv = wrap_versioned(30, Some(&priv_ed));
    let dec_priv = decode_versioned_signing_private_key(&wrapped_priv).unwrap();
    assert_eq!(dec_priv.key_spec, "EC-Curve25519");

    // Duplicate id last-wins
    let mut dup_id = privkey_wire("bad!id", 5, &pkcs8_ed, 0, &[4], 1);
    proto_bytes(1, b"good-id_2:abc", &mut dup_id);
    assert_eq!(
        parse_private_key_bytes(&dup_id).unwrap().id,
        "good-id_2:abc"
    );

    // Invalid UTF-8 in id -> Malformed -> KeyDecodeError::Buffer
    let mut bad_utf8_id = privkey_wire("", 5, &pkcs8_ed, 0, &[4], 1);
    proto_bytes(1, &[0xff, 0xfe], &mut bad_utf8_id);
    assert!(matches!(
        decode_versioned_signing_private_key(&wrap_versioned(30, Some(&bad_utf8_id))),
        Err(KeyDecodeError::Buffer(_))
    ));

    // Raw Ed25519 32-byte private key migration via wire (and 31-byte rejection)
    let priv_bad_raw_ed = privkey_wire("raw-ed-bad", 3, &[0x11u8; 31], 0, &[4], 1);
    assert!(parse_private_key_bytes(&priv_bad_raw_ed).is_err());
    let priv_seed_ed = privkey_wire("raw-seed", 3, &[0x11u8; 32], 0, &[4], 1);
    let _ = raw_ed;
    assert_eq!(
        parse_private_key_bytes(&priv_seed_ed)
            .unwrap()
            .public_spki
            .as_deref(),
        Some(spki_ed.as_slice())
    );

    // DER P-256 private key migration via wire + packed usage
    let mut priv_p256_der = privkey_wire("p256-1", 2, &p256_pkcs8, 0, &[], 2);
    proto_bytes(5, &[1, 4], &mut priv_p256_der);
    let parsed_p256 = parse_private_key_bytes(&priv_p256_der).unwrap();
    assert_eq!(parsed_p256.format, KeyFormat::DerPkcs8Pki);
    assert_eq!(
        parsed_p256.public_spki.as_deref(),
        Some(p256_spki.as_slice())
    );

    // Missing id -> StringConversionError
    let priv_no_id = privkey_wire("", 5, &pkcs8_ed, 0, &[4], 1);
    assert_eq!(
        parse_private_key_bytes(&priv_no_id).unwrap_err().class(),
        "StringConversionError"
    );

    // Over-68-byte id -> InvariantViolation
    let long_id = "a".repeat(69);
    let priv_long_id = privkey_wire(&long_id, 5, &pkcs8_ed, 0, &[4], 1);
    assert_eq!(
        parse_private_key_bytes(&priv_long_id).unwrap_err().class(),
        "InvariantViolation"
    );

    // Symbolic private key has public_spki == None
    let priv_sym = privkey_wire("sym-1", 10000, b"sym", 0, &[4], 2);
    assert_eq!(
        parse_private_key_bytes(&priv_sym).unwrap().public_spki,
        None
    );

    // Wrongs wire type (wt=6) on private key -> InvalidWireTypeException; truncated varint -> Buffer
    let mut bad_priv_wt = privkey_wire("bad-wt", 5, &pkcs8_ed, 0, &[4], 1);
    bad_priv_wt.push((3 << 3) | 6);
    assert!(matches!(
        parse_private_key_bytes(&bad_priv_wt),
        Err(ProtoError::Thrown("InvalidWireTypeException", _))
    ));

    // Malformed packed varint in private key usage
    let mut bad_packed = privkey_wire("bad-pack", 5, &pkcs8_ed, 0, &[], 1);
    proto_bytes(5, &[0x80], &mut bad_packed);
    assert!(matches!(
        parse_private_key_bytes(&bad_packed),
        Err(ProtoError::Thrown("InvalidProtocolBufferException", _))
    ));

    // Wrong usage alone on private key (ProofOfOwnership only = 5)
    let bad_priv_usage = privkey_wire("bad-use", 5, &pkcs8_ed, 0, &[5], 1);
    assert_eq!(
        parse_private_key_bytes(&bad_priv_usage)
            .unwrap_err()
            .class(),
        "CryptoDeserializationError"
    );

    // Wrong usage combo on private key (Namespace + ProofOfOwnership = 1, 5)
    let bad_priv_combo = privkey_wire("bad-combo", 5, &pkcs8_ed, 0, &[1, 5], 1);
    assert_eq!(
        parse_private_key_bytes(&bad_priv_combo)
            .unwrap_err()
            .class(),
        "CryptoDeserializationError"
    );

    // Invalid format Raw for P-256 private key
    let bad_p256_raw = privkey_wire("raw-ec", 3, &[1u8; 32], 0, &[4], 2);
    assert_eq!(
        parse_private_key_bytes(&bad_p256_raw).unwrap_err().class(),
        "CryptoDeserializationError"
    );
}

fn p256_sample() -> (p256::SecretKey, Vec<u8>, Vec<u8>) {
    let scalar = [0x33u8; 32];
    let sk = p256::SecretKey::from_slice(&scalar).unwrap();
    let point = sk.public_key().to_sec1_point(false);
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    spki.extend_from_slice(point.as_bytes());
    let pkcs8 = sk.to_pkcs8_der().unwrap().as_bytes().to_vec();
    (sk, spki, pkcs8)
}

#[test]
fn u12_extensions_oid_pkcs8_attrs_explicit_ec_unsupported_curves_and_ed25519_mixed_torsion() {
    let (_, spki_ed, pkcs8_ed) = ed25519_sample();

    // 1. Non-minimal OID (leading 0x80 byte in VLQ arc) rejected in SPKI & PKCS#8
    // OID 06 03 2b 65 70 -> 06 04 2b 80 65 70 (adjusted SEQUENCE lengths +1)
    let mut bad_oid_spki = vec![
        0x30, 0x2b, 0x30, 0x06, 0x06, 0x04, 0x2b, 0x80, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    bad_oid_spki.extend_from_slice(&spki_ed[12..]);
    assert_eq!(
        create_public_key(
            KeyFormat::DerX509Spki,
            &bad_oid_spki,
            KeySpec::EcCurve25519,
            Usage::all()
        )
        .unwrap_err()
        .class(),
        "CryptoDeserializationError"
    );

    // 2. PKCS#8 optional [0] attributes (v0 & v1) and [1] publicKey (v1 only)
    let mut pkcs8_v0_attr_body = Vec::new();
    pkcs8_v0_attr_body.extend_from_slice(&[0x02, 0x01, 0x00]);
    pkcs8_v0_attr_body.extend_from_slice(&pkcs8_ed[5..]); // alg + privKey
    pkcs8_v0_attr_body.extend_from_slice(&[0xa0, 0x02, 0x30, 0x00]); // [0] empty SEQUENCE attr
    let pkcs8_v0_with_attr = der_tlv(0x30, &pkcs8_v0_attr_body);
    #[allow(
        deprecated,
        reason = "populates legacy/deprecated Canton protobuf or pinned crypto fields for wire compatibility"
    )]
    let v0_attr_proto = canton_proto::com::digitalasset::canton::crypto::v30::SigningPrivateKey {
        id: "v0-attr".into(),
        format: 5,
        private_key: pkcs8_v0_with_attr,
        scheme: 0,
        usage: vec![4],
        key_spec: 1,
    };
    let parsed_v0_attr = parse_private_key(&v0_attr_proto).unwrap();
    #[allow(
        deprecated,
        reason = "populates legacy/deprecated Canton protobuf or pinned crypto fields for wire compatibility"
    )]
    let ed_pub_proto = canton_proto::com::digitalasset::canton::crypto::v30::SigningPublicKey {
        format: 4,
        public_key: spki_ed.clone(),
        scheme: 0,
        usage: vec![4],
        key_spec: 1,
    };
    assert_eq!(
        parse_public_key(&ed_pub_proto).unwrap().id,
        parse_public_key_bytes(&pubkey_wire(4, &spki_ed, 0, &[4], 1))
            .unwrap()
            .id
    );
    assert_eq!(
        parsed_v0_attr.public_spki.as_deref(),
        Some(spki_ed.as_slice())
    );

    // v1 with both [0] attributes and [1] publicKey accepted; v0 with [1] rejected
    let mut pkcs8_v1_body = Vec::new();
    pkcs8_v1_body.extend_from_slice(&[0x02, 0x01, 0x01]);
    pkcs8_v1_body.extend_from_slice(&pkcs8_ed[5..]);
    pkcs8_v1_body.extend_from_slice(&[0xa0, 0x02, 0x30, 0x00]);
    let mut pub_field = vec![0x00];
    pub_field.extend_from_slice(&spki_ed[12..]);
    pkcs8_v1_body.extend_from_slice(&der_tlv(0x81, &pub_field));
    let pkcs8_v1_both = der_tlv(0x30, &pkcs8_v1_body);
    assert!(
        parse_private_key_bytes(&privkey_wire("v1-both", 5, &pkcs8_v1_both, 0, &[4], 1)).is_ok()
    );

    let mut pkcs8_v0_pub_body = Vec::new();
    pkcs8_v0_pub_body.extend_from_slice(&[0x02, 0x01, 0x00]);
    pkcs8_v0_pub_body.extend_from_slice(&pkcs8_ed[5..]);
    pkcs8_v0_pub_body.extend_from_slice(&der_tlv(0x81, &pub_field));
    let pkcs8_v0_with_pub = der_tlv(0x30, &pkcs8_v0_pub_body);
    assert!(
        parse_private_key_bytes(&privkey_wire("v0-pub", 5, &pkcs8_v0_with_pub, 0, &[4], 1))
            .is_err()
    );

    // 3. Explicit ECParameters for P-256 in SPKI and PKCS#8
    let p256_p =
        hex::decode("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff").unwrap();
    let p256_a =
        hex::decode("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc").unwrap();
    let p256_b =
        hex::decode("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b").unwrap();
    let p256_g = hex::decode("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap();
    let p256_n =
        hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();

    let mut field_id_body = der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01]);
    field_id_body.extend_from_slice(&der_int_be(&p256_p));
    let mut curve_seq = der_tlv(0x04, &p256_a);
    curve_seq.extend_from_slice(&der_tlv(0x04, &p256_b));
    let mut ec_params_body = vec![0x02, 0x01, 0x01];
    ec_params_body.extend_from_slice(&der_tlv(0x30, &field_id_body));
    ec_params_body.extend_from_slice(&der_tlv(0x30, &curve_seq));
    ec_params_body.extend_from_slice(&der_tlv(0x04, &p256_g));
    ec_params_body.extend_from_slice(&der_int_be(&p256_n));
    ec_params_body.extend_from_slice(&[0x02, 0x01, 0x01]);
    let ec_params_der = der_tlv(0x30, &ec_params_body);

    let mut alg_explicit_body = der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    alg_explicit_body.extend_from_slice(&ec_params_der);
    let alg_explicit = der_tlv(0x30, &alg_explicit_body);

    let (p256_sk, p256_named_spki, _) = p256_sample();
    let mut explicit_spki_body = alg_explicit.clone();
    let mut bits = vec![0x00];
    bits.extend_from_slice(p256_sk.public_key().to_sec1_point(false).as_bytes());
    explicit_spki_body.extend_from_slice(&der_tlv(0x03, &bits));
    let explicit_spki = der_tlv(0x30, &explicit_spki_body);

    let parsed_explicit_pub = create_public_key(
        KeyFormat::DerX509Spki,
        &explicit_spki,
        KeySpec::EcP256,
        [Usage::Protocol].into(),
    )
    .unwrap();
    assert_eq!(parsed_explicit_pub.key_spec, KeySpec::EcP256);

    // Explicit P-256 PKCS#8 private key derives canonical named-curve SPKI
    let mut explicit_p8_body = vec![0x02, 0x01, 0x00];
    explicit_p8_body.extend_from_slice(&alg_explicit);
    explicit_p8_body.extend_from_slice(&der_tlv(0x04, &der_int_be(&[0x33u8; 32])));
    let explicit_p8 = der_tlv(0x30, &explicit_p8_body);
    let parsed_explicit_priv =
        parse_private_key_bytes(&privkey_wire("exp-p256", 5, &explicit_p8, 0, &[4], 2)).unwrap();
    assert_eq!(
        parsed_explicit_priv.public_spki.as_deref(),
        Some(p256_named_spki.as_slice())
    );

    // Mismatched explicit curve (P-256 explicit params declared as P-384) fails!
    assert_eq!(
        create_public_key(
            KeyFormat::DerX509Spki,
            &explicit_spki,
            KeySpec::EcP384,
            [Usage::Protocol].into(),
        )
        .unwrap_err()
        .class(),
        "CryptoDeserializationError"
    );

    // Modified explicit curve b fails!
    let mut bad_p256_b = p256_b;
    bad_p256_b[0] ^= 0xff;
    let mut bad_curve_seq = der_tlv(0x04, &p256_a);
    bad_curve_seq.extend_from_slice(&der_tlv(0x04, &bad_p256_b));
    let mut bad_ec_params_body = vec![0x02, 0x01, 0x01];
    bad_ec_params_body.extend_from_slice(&der_tlv(0x30, &field_id_body));
    bad_ec_params_body.extend_from_slice(&der_tlv(0x30, &bad_curve_seq));
    bad_ec_params_body.extend_from_slice(&der_tlv(0x04, &p256_g));
    bad_ec_params_body.extend_from_slice(&der_int_be(&p256_n));
    let mut bad_alg = der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    bad_alg.extend_from_slice(&der_tlv(0x30, &bad_ec_params_body));
    let mut bad_spki_body = der_tlv(0x30, &bad_alg);
    bad_spki_body.extend_from_slice(&der_tlv(0x03, &bits));
    assert!(create_public_key(
        KeyFormat::DerX509Spki,
        &der_tlv(0x30, &bad_spki_body),
        KeySpec::EcP256,
        Usage::all()
    )
    .is_err());

    // 4. Unsupported named curves (secp224r1, secp521r1, brainpoolP256r1) refused
    for unsupported_oid in [
        &[0x2b, 0x81, 0x04, 0x00, 0x21][..], // secp224r1
        &[0x2b, 0x81, 0x04, 0x00, 0x23][..], // secp521r1
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07][..], // brainpoolP256r1
    ] {
        let mut alg_b = der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
        alg_b.extend_from_slice(&der_tlv(0x06, unsupported_oid));
        let mut spki_b = der_tlv(0x30, &alg_b);
        spki_b.extend_from_slice(&der_tlv(0x03, &bits));
        assert!(create_public_key(
            KeyFormat::DerX509Spki,
            &der_tlv(0x30, &spki_b),
            KeySpec::EcP256,
            Usage::all()
        )
        .is_err());
    }

    // 5. Ed25519 mixed-torsion point P + T_8 and P + T_2 refused!
    let base = ED25519_BASEPOINT_POINT;
    for torsion_idx in [1usize, 4usize] {
        let mixed = (base + EIGHT_TORSION[torsion_idx]).compress().to_bytes();
        assert_ne!(mixed, [0u8; 32]);
        let mut mixed_spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        mixed_spki.extend_from_slice(&mixed);
        assert_eq!(
            create_public_key(
                KeyFormat::DerX509Spki,
                &mixed_spki,
                KeySpec::EcCurve25519,
                Usage::all()
            )
            .unwrap_err()
            .class(),
            "CryptoDeserializationError"
        );
    }
}

#[test]
fn u12_mldsa65_keys_pkcs8_and_signature_verification() {
    let seed = [0x5au8; 32];
    let (pk_raw, sk_raw) = mldsa65::keygen_from_seed(&seed);
    let spki = mldsa65::encode_spki(&pk_raw);

    // Public key parsing (DerX509Spki & legacy Der migration)
    let pub_key = create_public_key(
        KeyFormat::DerX509Spki,
        &spki,
        KeySpec::MlDsa65,
        [Usage::Protocol].into(),
    )
    .unwrap();
    let pub_key_legacy = create_public_key(
        KeyFormat::Der,
        &spki,
        KeySpec::MlDsa65,
        [Usage::Protocol].into(),
    )
    .unwrap();
    assert_eq!(pub_key_legacy.format, KeyFormat::DerX509Spki);
    assert_eq!(pub_key.id, pub_key_legacy.id);

    // Negative SPKI checks: wrong length, NULL params, wrong OID, unused bits
    let mut short_spki = mldsa65::encode_spki(&pk_raw);
    short_spki.pop();
    assert!(create_public_key(
        KeyFormat::DerX509Spki,
        &short_spki,
        KeySpec::MlDsa65,
        Usage::all()
    )
    .is_err());

    let (_, ed_spki, _) = ed25519_sample();
    assert!(create_public_key(
        KeyFormat::DerX509Spki,
        &ed_spki,
        KeySpec::MlDsa65,
        Usage::all()
    )
    .is_err());

    // Null params on ML-DSA-65 SPKI refused
    let mut null_alg = der_tlv(0x06, mldsa65::OID_ML_DSA_65);
    null_alg.extend_from_slice(&[0x05, 0x00]);
    let mut null_spki_body = der_tlv(0x30, &null_alg);
    let mut bit_bytes = vec![0x00];
    bit_bytes.extend_from_slice(&pk_raw);
    null_spki_body.extend_from_slice(&der_tlv(0x03, &bit_bytes));
    assert!(create_public_key(
        KeyFormat::DerX509Spki,
        &der_tlv(0x30, &null_spki_body),
        KeySpec::MlDsa65,
        Usage::all()
    )
    .is_err());

    // Unused bits != 0 refused
    bit_bytes[0] = 1;
    let mut unused_alg = der_tlv(0x30, &der_tlv(0x06, mldsa65::OID_ML_DSA_65));
    unused_alg.extend_from_slice(&der_tlv(0x03, &bit_bytes));
    assert!(create_public_key(
        KeyFormat::DerX509Spki,
        &der_tlv(0x30, &unused_alg),
        KeySpec::MlDsa65,
        Usage::all()
    )
    .is_err());

    // Private key parsing across seed [0], expandedKey OCTET STRING, both SEQUENCE
    for (idx, pkcs8) in [
        mldsa65::encode_pkcs8_seed(&seed),
        mldsa65::encode_pkcs8_expanded(&sk_raw),
        mldsa65::encode_pkcs8_both(&seed, &sk_raw),
    ]
    .into_iter()
    .enumerate()
    {
        #[allow(
            deprecated,
            reason = "populates legacy/deprecated Canton protobuf or pinned crypto fields for wire compatibility"
        )]
        let priv_proto = canton_proto::com::digitalasset::canton::crypto::v30::SigningPrivateKey {
            id: format!("mldsa-{idx}"),
            format: 5,
            private_key: pkcs8,
            scheme: 0,
            usage: vec![4],
            key_spec: 5,
        };
        let priv_key = parse_private_key(&priv_proto).unwrap();
        assert_eq!(priv_key.key_spec, KeySpec::MlDsa65);
        assert_eq!(priv_key.public_spki.as_deref(), Some(spki.as_slice()));
    }

    // Tampered expandedKey & seed/expandedKey mismatch refused
    let mut bad_sk = sk_raw;
    bad_sk[4000] ^= 0xff; // t0 tamper
    assert!(parse_private_key_bytes(&privkey_wire(
        "bad-t0",
        5,
        &mldsa65::encode_pkcs8_expanded(&bad_sk),
        0,
        &[4],
        5
    ))
    .is_err());
    assert!(parse_private_key_bytes(&privkey_wire(
        "mismatch",
        5,
        &mldsa65::encode_pkcs8_both(&seed, &bad_sk),
        0,
        &[4],
        5
    ))
    .is_err());

    // Sign & verify: default verify_signature rejects experimental MlDsa65; allow_experimental accepts
    let msg = b"ml-dsa-65 canton transaction hash";
    let sig_bytes = mldsa65::sign_deterministic(&sk_raw, msg, b"").unwrap();
    assert_eq!(sig_bytes.len(), 3309);
    let sig = Signature {
        format: SignatureFormat::Der,
        signature: sig_bytes.to_vec(),
        signed_by: pub_key.id.clone(),
        spec: Some(AlgorithmSpec::MlDsa65),
        delegation: None,
        authorizing_key: pub_key.id.clone(),
    };
    let expected: BTreeSet<Usage> = [Usage::Protocol].into();

    assert_eq!(
        verify_signature(msg, &pub_key, &sig, &expected),
        Err(VerifyError::NoMatchingAlgorithmSpec)
    );
    assert_eq!(
        verify_signature_allowing_experimental(msg, &pub_key, &sig, &expected),
        Ok(())
    );

    // spec: None infers MlDsa65 when experimental enabled
    let sig_none = Signature {
        spec: None,
        ..sig.clone()
    };
    assert_eq!(
        verify_signature_allowing_experimental(msg, &pub_key, &sig_none, &expected),
        Ok(())
    );

    // Corrupted message or signature rejects cleanly
    let mut bad_sig = sig.clone();
    bad_sig.signature[0] ^= 0x01;
    assert_eq!(
        verify_signature_allowing_experimental(msg, &pub_key, &bad_sig, &expected),
        Err(VerifyError::InvalidSignature)
    );
    assert_eq!(
        verify_signature_allowing_experimental(b"other", &pub_key, &sig, &expected),
        Err(VerifyError::InvalidSignature)
    );
}

fn key_spec_from_tsv(s: &str) -> KeySpec {
    match s {
        "EC-Curve25519" | "EcCurve25519" => KeySpec::EcCurve25519,
        "EC-P256" | "EcP256" => KeySpec::EcP256,
        "EC-P384" | "EcP384" => KeySpec::EcP384,
        "EC-Secp256k1" | "EcSecp256k1" => KeySpec::EcSecp256k1,
        other => panic!("unexpected TSV key_spec: {other}"),
    }
}

fn alg_from_tsv(s: &str) -> AlgorithmSpec {
    match s {
        "Ed25519" => AlgorithmSpec::Ed25519,
        "EC-DSA-SHA256" | "EcDsaSha256" => AlgorithmSpec::EcDsaSha256,
        "EC-DSA-SHA384" | "EcDsaSha384" => AlgorithmSpec::EcDsaSha384,
        other => panic!("unexpected TSV algorithm_spec: {other}"),
    }
}

#[test]
fn u23_all_14_provenance_vectors_match_both_recordings() {
    let g0_full = include_str!("../../../../tests/oracle/provenance/crypto-accept-vectors.tsv");
    let console_verdicts = include_str!(
        "../../../../tests/oracle/provenance/g0-3.7.2-console/crypto-accept-vectors.tsv"
    );

    let console_rows: Vec<(&str, &str)> = console_verdicts
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut cols = l.split('\t');
            (cols.next().unwrap(), cols.next().unwrap())
        })
        .collect();
    let full_rows: Vec<Vec<&str>> = g0_full
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split('\t').collect())
        .collect();

    assert_eq!(full_rows.len(), 13);
    assert_eq!(console_rows.len(), 13);

    for (cols, (cid, expected_console)) in full_rows.iter().zip(console_rows.iter()) {
        let vector_id = cols[0];
        assert_eq!(vector_id, *cid);
        let key_spec = key_spec_from_tsv(cols[2]);
        let alg = alg_from_tsv(cols[3]);
        let spki = hex::decode(cols[5]).unwrap();
        let hash = if cols[6] == "-" {
            Vec::new()
        } else {
            hex::decode(cols[6]).unwrap()
        };
        let sig_bytes = if cols[7] == "-" {
            Vec::new()
        } else {
            hex::decode(cols[7]).unwrap()
        };
        let canton_api_result = cols[8];

        let usage: BTreeSet<Usage> = if vector_id.contains("wrong_usage") {
            [Usage::Namespace].into()
        } else {
            [Usage::Protocol].into()
        };
        let expected_usage: BTreeSet<Usage> = [Usage::Protocol].into();

        // Recording A: validate key at parse/create time (SigningPublicKey.create + verify_signature)
        let path_a = match create_public_key(KeyFormat::DerX509Spki, &spki, key_spec, usage.clone())
        {
            Err(_) => "REJECT:KeyParseAndValidateError".to_string(),
            Ok(pk) => {
                if cols[4] != "-" {
                    assert_eq!(pk.id, cols[4], "{vector_id} fingerprint");
                }
                let sig = Signature {
                    format: if alg == AlgorithmSpec::Ed25519 {
                        SignatureFormat::Concat
                    } else {
                        SignatureFormat::Der
                    },
                    signature: sig_bytes.clone(),
                    signed_by: pk.id.clone(),
                    spec: Some(alg),
                    delegation: None,
                    authorizing_key: pk.id.clone(),
                };
                match verify_signature(&hash, &pk, &sig, &expected_usage) {
                    Ok(()) => "ACCEPT".to_string(),
                    Err(e) => format!("REJECT:{}", e.class()),
                }
            }
        };
        let expected_a_prefix = if canton_api_result == "ACCEPT" {
            "ACCEPT"
        } else if canton_api_result.starts_with("REJECT:KeyParseAndValidateError") {
            "REJECT:KeyParseAndValidateError"
        } else {
            canton_api_result.split('(').next().unwrap()
        };
        assert_eq!(
            path_a, expected_a_prefix,
            "recording A mismatch for {vector_id}"
        );

        // Recording B: unvalidated PublicKey wrapper into verify_signature (g0-3.7.2-console)
        let unvalidated_pk = PublicKey::from_unvalidated_spki_for_u23(key_spec, spki, usage);
        let sig_b = Signature {
            format: if alg == AlgorithmSpec::Ed25519 {
                SignatureFormat::Concat
            } else {
                SignatureFormat::Der
            },
            signature: sig_bytes,
            signed_by: unvalidated_pk.id.clone(),
            spec: Some(alg),
            delegation: None,
            authorizing_key: unvalidated_pk.id.clone(),
        };
        let path_b = match verify_signature(&hash, &unvalidated_pk, &sig_b, &expected_usage) {
            Ok(()) => "ACCEPT".to_string(),
            Err(VerifyError::InvalidKeyError) => "REJECT:CryptoDeserializationError".to_string(),
            Err(e) => format!("REJECT:{}", e.class()),
        };
        assert_eq!(
            path_b, *expected_console,
            "recording B mismatch for {vector_id}"
        );
    }
}
