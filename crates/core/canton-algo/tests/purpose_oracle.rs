//! AT-C02: a valid signature made for one hash purpose must not verify under another. Replays the recording of a Canton 3.7.2
//! node (`tests/oracle/canton-crypto/expected.tsv`, made by `scripts/verify-canton-crypto.sh --update`) against canton-algo:
//!
//! - the multihash of one message under each of the 54 public hash purposes equals the JVM's (`CryptoPureApi.digest`);
//! - each JVM signature verifies under its own purpose's hash and under no other (`accepts` is exactly the JVM's list);
//! - an Ed25519 signature is deterministic, so signing the JVM's hash with the JVM's private key gives the JVM's bytes.
//!
//! [CANTON-NOTE: ORACLE] The oracle is the node's own crypto API reached through the console (`p1.underlying.get.cryptoPureApi`),
//! not the source text of HashPurpose.scala (that one is checked by verify-canton-hash.sh).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::collections::BTreeMap;

use canton_algo::crypto_matrix::{verify_purpose_signature, CryptoAlgorithm};
use canton_algo::hash::{multihash_sha256_hex, sha256_with_purpose, PurposeHash};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::Signer;

const MESSAGE: &[u8] = b"hello purposes";

fn file() -> String {
    let path = std::env::var("CANTON_CRYPTO_FILE").unwrap_or_else(|_| {
        format!(
            "{}/../../../tests/oracle/canton-crypto/expected.tsv",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The value of a length-delimited protobuf field (wire type 2) with the given number, first occurrence.
fn proto_bytes(buf: &[u8], field: u64) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < buf.len() {
        let (key, n) = varint(&buf[i..])?;
        i += n;
        match key & 7 {
            0 => i += varint(&buf[i..])?.1,
            2 => {
                let (len, n) = varint(&buf[i..])?;
                i += n;
                let body = buf.get(i..i + len as usize)?;
                if key >> 3 == field {
                    return Some(body.to_vec());
                }
                i += len as usize;
            }
            _ => return None,
        }
    }
    None
}

fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, x) in b.iter().enumerate().take(10) {
        v |= u64::from(x & 0x7f) << (7 * i);
        if x & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

struct Spec {
    algo: CryptoAlgorithm,
    spki: Vec<u8>,
    private: Vec<u8>,
    signed: Vec<(String, i32, String, Vec<u8>)>, // purpose, id, jvm multihash hex, signature bytes
    accepts: BTreeMap<String, Vec<String>>,
}

fn parse() -> BTreeMap<String, Spec> {
    let mut out: BTreeMap<String, Spec> = BTreeMap::new();
    for line in file().lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["key", label, _spec, pubhex, privhex] => {
                let algo = if *label == "Ed25519" {
                    CryptoAlgorithm::Ed25519
                } else {
                    CryptoAlgorithm::EcDsaSecp256r1
                };
                out.insert(
                    (*label).to_string(),
                    Spec {
                        algo,
                        spki: proto_bytes(&hex::decode(pubhex).unwrap(), 3)
                            .expect("public key bytes"),
                        private: proto_bytes(&hex::decode(privhex).unwrap(), 3)
                            .expect("private key bytes"),
                        signed: vec![],
                        accepts: BTreeMap::new(),
                    },
                );
            }
            ["sign", label, name, id, hash, sig] => {
                let s = out.get_mut(*label).expect("key line first");
                let sig = proto_bytes(&hex::decode(sig).unwrap(), 2).expect("signature bytes");
                s.signed.push((
                    (*name).to_string(),
                    id.parse().unwrap(),
                    (*hash).to_string(),
                    sig,
                ));
            }
            ["accepts", label, name, list] => {
                let v = list
                    .split(',')
                    .filter(|x| !x.is_empty())
                    .map(str::to_string)
                    .collect();
                out.get_mut(*label)
                    .unwrap()
                    .accepts
                    .insert((*name).to_string(), v);
            }
            _ => {}
        }
    }
    out
}

#[test]
fn purposes_hash_sign_and_cross_verify_like_the_jvm() {
    let specs = parse();
    assert_eq!(specs.len(), 2, "Ed25519 and EC-P256 are both recorded");
    let mut checked = 0;
    for (label, spec) in &specs {
        assert!(
            spec.signed.len() >= 54,
            "{label}: {} purposes recorded",
            spec.signed.len()
        );
        let hashes: Vec<(String, Vec<u8>)> = spec
            .signed
            .iter()
            .map(|(n, id, jvm_hash, _)| {
                let mine = multihash_sha256_hex(&sha256_with_purpose(*id, MESSAGE));
                assert_eq!(
                    &mine, jvm_hash,
                    "{label}/{n}: the hash differs from the JVM's"
                );
                (n.clone(), hex::decode(mine).unwrap())
            })
            .collect();
        for (n, _, _, sig) in &spec.signed {
            let expected: &Vec<String> = &spec.accepts[n];
            let mut accepted = Vec::new();
            for (m, h) in &hashes {
                if verify_purpose_signature(spec.algo, &spec.spki, h, sig).is_ok() {
                    accepted.push(m.clone());
                }
            }
            assert_eq!(&accepted, expected, "{label}/{n}: the set of purposes this signature verifies under differs from the JVM's");
            assert_eq!(
                accepted,
                vec![n.clone()],
                "{label}/{n}: a signature must verify under its own purpose only"
            );
            checked += 1;
        }
    }
    assert!(checked >= 108, "{checked} signatures checked");
}

#[test]
fn ed25519_signatures_are_the_same_bytes_as_the_jvms() {
    let specs = parse();
    let spec = &specs["Ed25519"];
    let sk = ed25519_dalek::SigningKey::from_pkcs8_der(&spec.private).expect("PKCS#8 Ed25519 key");
    for (n, _, jvm_hash, sig) in &spec.signed {
        let mine = sk.sign(&hex::decode(jvm_hash).unwrap());
        assert_eq!(
            mine.to_bytes().to_vec(),
            *sig,
            "{n}: Ed25519 signature bytes differ from the JVM's"
        );
    }
}

/// The test must be able to fail: a hash of another purpose is not accepted for a signature (this is what the matrix measures).
#[test]
fn a_signature_of_the_wrong_message_is_refused() {
    let specs = parse();
    let spec = &specs["Ed25519"];
    let (_, id, _, sig) = &spec.signed[0];
    let other = multihash_sha256_hex(&sha256_with_purpose(*id, b"another message"));
    assert!(
        verify_purpose_signature(spec.algo, &spec.spki, &hex::decode(other).unwrap(), sig).is_err()
    );
}

/// One builder operation of a recorded case (the same list `scripts/gen-canton-crypto.py` feeds the JVM).
enum Op {
    Int(i32),
    Long(i64),
    Str(&'static str),
    Bytes(&'static [u8]),
    Raw(&'static [u8]),
    Bool(bool),
    Byte(u8),
    Set(&'static [&'static str]),
}

fn cases() -> Vec<(&'static str, Vec<Op>)> {
    use Op::*;
    let big: &'static [u8] = &[b'x'; 1000];
    vec![
        ("empty", vec![]),
        ("int0", vec![Int(0)]),
        ("intMinusOne", vec![Int(-1)]),
        ("intMax", vec![Int(i32::MAX)]),
        ("intMin", vec![Int(i32::MIN)]),
        ("long1", vec![Long(1)]),
        ("longMin", vec![Long(i64::MIN)]),
        ("longMax", vec![Long(i64::MAX)]),
        ("strEmpty", vec![Str("")]),
        ("strAb", vec![Str("ab")]),
        ("strUnicode", vec![Str("é😂")]),
        ("strNul", vec![Str("a\u{0}b")]),
        ("strAb_c", vec![Str("ab"), Str("c")]),
        ("strA_bc", vec![Str("a"), Str("bc")]),
        ("rawAb_c", vec![Raw(b"ab"), Raw(b"c")]),
        ("rawA_bc", vec![Raw(b"a"), Raw(b"bc")]),
        ("rawAbc", vec![Raw(b"abc")]),
        ("orderStrInt", vec![Str("a"), Int(1)]),
        ("orderIntStr", vec![Int(1), Str("a")]),
        ("bytesEmpty", vec![Bytes(b"")]),
        ("bytes1000", vec![Bytes(big)]),
        ("intThenLong", vec![Int(1), Long(1)]),
        ("longThenInt", vec![Long(1), Int(1)]),
        ("mixed", vec![Int(7), Str("x"), Bytes(b"yz"), Raw(b"w")]),
        ("boolTrue", vec![Bool(true)]),
        ("boolFalse", vec![Bool(false)]),
        ("byte7", vec![Byte(7)]),
        ("byteMinus1", vec![Byte(0xff)]),
        ("setBA", vec![Set(&["b", "a"])]),
        ("setAB", vec![Set(&["a", "b"])]),
        ("setEmpty", vec![Set(&[])]),
        ("setUtf16Order", vec![Set(&["\u{ff5e}", "\u{1f602}"])]),
        ("setOneElement", vec![Set(&["only"])]),
    ]
}

/// Field order, length prefixes and integer widths: the multihash of 33 builder programs under three purposes equals the JVM's
/// (`CryptoPureApi.build(purpose).add(..).finish()`), a Long adds 8 bytes, a String is a length-prefixed UTF-8 byte string, and
/// a finished builder cannot be used again (neither `add` nor `finish`).
#[test]
fn hash_builder_programs_hash_like_the_jvm() {
    let table: BTreeMap<_, _> = cases().into_iter().collect();
    let mut checked = 0;
    let mut distinct = std::collections::BTreeSet::new();
    for line in file().lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if let ["hb", name, pid, jvm_hash] = f.as_slice() {
            let (_, case) = name.split_once('/').unwrap();
            let mut h = PurposeHash::new(pid.parse().unwrap());
            for op in &table[case] {
                match op {
                    Op::Int(v) => h.add_int(*v).unwrap(),
                    Op::Long(v) => h.add_long(*v).unwrap(),
                    Op::Str(s) => h.add_string(s).unwrap(),
                    Op::Bool(v) => h.add_bool(*v).unwrap(),
                    Op::Byte(v) => h.add_byte(*v).unwrap(),
                    Op::Set(v) => h.add_string_set(v).unwrap(),
                    Op::Bytes(b) => h.add_byte_string(b).unwrap(),
                    Op::Raw(b) => h.add_without_length_prefix(b).unwrap(),
                }
            }
            let mine = multihash_sha256_hex(&h.finish().unwrap());
            assert_eq!(
                &mine, jvm_hash,
                "{name}: builder hash differs from the JVM's"
            );
            distinct.insert((pid.to_string(), mine));
            checked += 1;
        }
    }
    assert_eq!(checked, 3 * cases().len(), "3 purposes x every program");
    // Exactly these programs hash alike (the encoding fixes them, so the count is the boundary check): the three raw programs
    // ("ab","c" / "a","bc" / "abc") are one byte string without length prefixes (-2); a set ignores the order its elements were
    // given in (-1); the int 0, the empty string, the empty byte string and the empty set all encode as the int 0 (-3).
    // 33 programs - 6 = 27 distinct hashes per purpose. A builder that dropped a length prefix would collapse more of them.
    assert_eq!(distinct.len(), 3 * 27, "distinct hashes");
    let closed = file()
        .lines()
        .find(|l| l.starts_with("hbclosed"))
        .expect("hbclosed line")
        .to_string();
    assert_eq!(
        closed, "hbclosed\tfalse\tfalse",
        "the JVM builder must refuse any use after finish"
    );
    let mut h = PurposeHash::new(1);
    h.finish().unwrap();
    assert!(h.add_int(2).is_err() && h.finish().is_err());
}

/// AT-A06: a version-wrapped `SigningPublicKey` is accepted or refused like the node does (`SigningPublicKey.fromTrustedByteString`),
/// for 29 inputs: wrong or truncated versions, reordered and duplicated fields, unknown fields, unknown and unspecified enums,
/// an empty usage list, garbage inside the wrapper. The accepted ones must also read back the same key spec, format and usages.
#[test]
fn version_wrapper_is_decoded_like_the_node() {
    use canton_algo::versioned_key::{
        decode_versioned_signing_public_key as decode, KeyDecodeError as E,
    };
    let mut checked = 0;
    let mut accepted = 0;
    for line in file().lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let ["ver", name, input, outcome, detail] = f.as_slice() else {
            continue;
        };
        let bytes = hex::decode(input).unwrap();
        let mine = decode(&bytes);
        match (*outcome, &mine) {
            ("OK", Ok(k)) => {
                let want = format!("{}|{}|{}", k.key_spec, k.format, k.usage.join(","));
                assert_eq!(
                    &want, detail,
                    "{name}: the decoded key differs from the node's"
                );
                accepted += 1;
            }
            ("ERR", Err(e)) => {
                let class = match e {
                    E::UnsupportedVersion(_) => "OtherError(Unable to find deserializer",
                    E::FieldNotSet(_) => "FieldNotSet",
                    E::UnrecognizedEnum(..) => "UnrecognizedEnum",
                    E::CryptoDeserialization(_) => "CryptoDeserializationError",
                    E::Buffer(_) => "BufferException",
                    E::Thrown(_) => "THROW",
                };
                assert!(
                    detail.starts_with(class),
                    "{name}: the node says `{detail}` but this decoder says {e:?}"
                );
            }
            _ => {
                panic!("{name}: the node says {outcome} ({detail}) but this decoder says {mine:?}")
            }
        }
        checked += 1;
    }
    assert_eq!(
        checked, 29,
        "29 recorded cases (the valid key and 28 variants)"
    );
    assert_eq!(accepted, 10, "the node accepts exactly these");
}
