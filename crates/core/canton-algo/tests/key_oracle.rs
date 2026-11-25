//! U-12 and U-13 (part i): the accept/reject matrix of Canton signing keys and signatures, replayed against canton-algo.
//!
//! The recording (`tests/oracle/canton-crypto/expected.tsv`, made by `scripts/verify-canton-crypto.sh --update`) holds what a
//! Canton 3.7.2 node answered, through its console, to:
//!
//! - `pk`: `SigningPublicKey.fromProtoV30` on public-key messages (P-256, P-384, secp256k1 and Ed25519 variants: formats,
//!   legacy `DER`/`RAW`/scheme-only keys, usages, point encodings, SPKI containers, key spec mismatches);
//! - `sk`: `SigningPrivateKey.fromProtoV30` on private-key messages, plus the public key the node derives and its `sign` verdict;
//! - `sg`: `Signature.fromProtoV30` and `CryptoPureApi.verifySignature` on signatures with a wrong format, algorithm spec,
//!   signer, usage, hash, DER shape, scalar range and so on;
//!
//! Each line carries its input, so the same test runs on the recording and on a fresh node run (random keys, new signatures).
//!
//! [CANTON-NOTE: ORACLE] The oracle is the node's own Scala code reached through the console. Every case clears the node's
//! key-validation caches first (see `pkcache` below for why).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::collections::BTreeSet;

use canton_algo::signing::{
    parse_private_key, parse_public_key, parse_signature, sign_usage_check, verify_signature, Usage,
};
use canton_proto::com::digitalasset::canton::crypto::v30::{SigningPrivateKey, SigningPublicKey};
use prost::Message;

fn file() -> String {
    let path = std::env::var("CANTON_CRYPTO_FILE").unwrap_or_else(|_| {
        format!(
            "{}/../../../tests/oracle/canton-crypto/expected.tsv",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn lines_of(kind: &str) -> Vec<Vec<String>> {
    file()
        .lines()
        .map(|l| l.split('\t').map(str::to_string).collect::<Vec<_>>())
        .filter(|f| f.first().map(String::as_str) == Some(kind))
        .collect()
}

fn usage_names(u: &BTreeSet<Usage>) -> String {
    let mut v: Vec<&str> = u.iter().map(|x| x.name()).collect();
    v.sort_unstable();
    v.join(",")
}

fn usage_by_name(name: &str) -> BTreeSet<Usage> {
    match name {
        "protocol" => [Usage::Protocol].into(),
        "namespace" => [Usage::Namespace].into(),
        "sequencerAuth" => [Usage::SequencerAuthentication].into(),
        "all" => Usage::all(),
        other => panic!("unknown usage name {other}"),
    }
}

/// Compares one outcome with the node's. `class` is the node's error class, `thrown` says it threw an exception.
fn check_error(
    name: &str,
    outcome: &str,
    class: &str,
    got_class: &str,
    thrown: bool,
) -> Result<(), String> {
    let want_thrown = outcome == "THROW";
    if want_thrown != thrown || class != got_class {
        return Err(format!(
            "{name}: the node says {outcome}/{class}, this implementation says {got_class} (thrown: {thrown})"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------------
// pk

fn check_pk(f: &[String]) -> Result<(), String> {
    let [_, name, input, outcome, class, detail, id] = f else {
        return Err(format!("malformed pk line: {f:?}"));
    };
    let msg = SigningPublicKey::decode(hex::decode(input).unwrap().as_slice())
        .map_err(|e| format!("{name}: the recorded input does not decode: {e}"))?;
    match (outcome.as_str(), parse_public_key(&msg)) {
        ("OK", Ok(k)) => {
            let got = format!(
                "{}|{}|{}",
                k.key_spec.name(),
                k.format.name(),
                usage_names(&k.usage)
            );
            if &got != detail || &k.id != id {
                return Err(format!(
                    "{name}: the node reads `{detail}` id {id}, this implementation `{got}` id {}",
                    k.id
                ));
            }
            Ok(())
        }
        ("OK", Err(e)) => Err(format!(
            "{name}: the node accepts, this implementation says {e:?}"
        )),
        (_, Ok(k)) => Err(format!(
            "{name}: the node says {outcome}/{class}, this implementation accepts {k:?}"
        )),
        (_, Err(e)) => check_error(name, outcome, class, e.class(), e.is_thrown()),
    }
}

#[test]
fn public_key_variants_are_accepted_and_refused_like_the_node() {
    let lines = lines_of("pk");
    let mut accepted = 0;
    let mut thrown = 0;
    for f in &lines {
        check_pk(f).unwrap_or_else(|e| panic!("{e}"));
        accepted += usize::from(f[3] == "OK");
        thrown += usize::from(f[3] == "THROW");
    }
    // 4 key specs x (about 63 cases each); the counts keep the test from passing on a shrunken recording
    assert!(lines.len() >= 240, "{} pk cases", lines.len());
    assert!(accepted >= 70, "{accepted} accepted");
    assert!(lines.len() - accepted >= 120, "too few refusals");
    assert!(
        thrown >= 1,
        "the exception case (a P-384 key declared P-256) is missing"
    );
    for label in ["Ed25519", "EcP256", "EcP384", "EcSecp256k1"] {
        let n = lines
            .iter()
            .filter(|f| f[1].starts_with(&format!("{label}/")))
            .count();
        assert!(n >= 55, "{label}: {n} cases");
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// sk

fn check_sk(f: &[String]) -> Result<(), String> {
    let [_, name, input, outcome, class, detail, public, sign] = f else {
        return Err(format!("malformed sk line: {f:?}"));
    };
    let msg = SigningPrivateKey::decode(hex::decode(input).unwrap().as_slice())
        .map_err(|e| format!("{name}: the recorded input does not decode: {e}"))?;
    match (outcome.as_str(), parse_private_key(&msg)) {
        ("OK", Ok(k)) => {
            let got = format!(
                "{}|{}|{}",
                k.key_spec.name(),
                k.format.name(),
                usage_names(&k.usage)
            );
            if &got != detail {
                return Err(format!(
                    "{name}: the node reads `{detail}`, this implementation `{got}`"
                ));
            }
            // the public key the node derives from the private key (the symbolic format derives none)
            let derived = k.public_spki.as_ref().map(hex::encode);
            if derived.as_deref().unwrap_or("-") != public || (derived.is_none() != (public == "-"))
            {
                return Err(format!(
                    "{name}: the derived public key differs: node {public}, here {derived:?}"
                ));
            }
            // `pure.sign` checks the key usage; symbolic keys and the id cases hit node-side caches and are not compared
            if k.public_spki.is_some() && !name.contains("/id") {
                let want = if sign_usage_check(&k, &usage_by_name("protocol")).is_ok() {
                    "OK"
                } else {
                    "InvalidKeyUsage"
                };
                if want != sign {
                    return Err(format!(
                        "{name}: the node's sign verdict is {sign}, here {want}"
                    ));
                }
            }
            Ok(())
        }
        ("OK", Err(e)) => Err(format!(
            "{name}: the node accepts, this implementation says {e:?}"
        )),
        (_, Ok(k)) => Err(format!(
            "{name}: the node says {outcome}/{class}, this implementation accepts {k:?}"
        )),
        (_, Err(e)) => check_error(name, outcome, class, e.class(), e.is_thrown()),
    }
}

#[test]
fn private_key_variants_are_accepted_and_refused_like_the_node() {
    let lines = lines_of("sk");
    let mut accepted = 0;
    for f in &lines {
        check_sk(f).unwrap_or_else(|e| panic!("{e}"));
        accepted += usize::from(f[3] == "OK");
    }
    assert!(lines.len() >= 200, "{} sk cases", lines.len());
    assert!(accepted >= 70, "{accepted} accepted");
    assert!(lines.len() - accepted >= 100, "too few refusals");
}

// ---------------------------------------------------------------------------------------------------------------------
// sg

fn check_sg(f: &[String]) -> Result<(), String> {
    let [_, name, key, hash, use_name, sig, outcome, class, _detail] = f else {
        return Err(format!("malformed sg line: {f:?}"));
    };
    let key_msg = SigningPublicKey::decode(hex::decode(key).unwrap().as_slice()).unwrap();
    let key =
        parse_public_key(&key_msg).map_err(|e| format!("{name}: the key must be valid: {e:?}"))?;
    let hash = hex::decode(hash).unwrap();
    let wire = hex::decode(sig).unwrap();
    let parsed = parse_signature(&wire);
    match (outcome.as_str(), parsed) {
        ("PARSE" | "THROW", Err(e)) => check_error(
            name,
            if outcome == "PARSE" { "ERR" } else { "THROW" },
            class,
            e.class(),
            e.is_thrown(),
        ),
        ("PARSE" | "THROW", Ok(s)) => Err(format!(
            "{name}: the node refuses the message ({outcome}/{class}), here it parses: {s:?}"
        )),
        (_, Err(e)) => Err(format!(
            "{name}: the node parses it, this implementation says {e:?}"
        )),
        (_, Ok(s)) => match (
            outcome.as_str(),
            verify_signature(&hash, &key, &s, &usage_by_name(use_name)),
        ) {
            ("OK", Ok(())) => Ok(()),
            ("OK", Err(e)) => Err(format!(
                "{name}: the node accepts the signature, this implementation says {}",
                e.class()
            )),
            ("VERIFY", Ok(())) => Err(format!(
                "{name}: the node refuses ({class}), this implementation accepts"
            )),
            ("VERIFY", Err(e)) if e.class() == class => Ok(()),
            ("VERIFY", Err(e)) => Err(format!(
                "{name}: the node says {class}, this implementation says {}",
                e.class()
            )),
            _ => Err(format!("{name}: unexpected outcome {outcome}")),
        },
    }
}

#[test]
fn signatures_are_verified_like_the_node() {
    let lines = lines_of("sg");
    let mut ok = 0;
    let mut classes = BTreeSet::new();
    for f in &lines {
        check_sg(f).unwrap_or_else(|e| panic!("{e}"));
        ok += usize::from(f[6] == "OK");
        classes.insert(f[7].clone());
    }
    assert!(lines.len() >= 220, "{} sg cases", lines.len());
    assert!(ok >= 35, "{ok} accepted signatures");
    // every kind of refusal the node has for a signature is exercised
    for class in [
        "InvalidSignature",
        "InvalidKeyUsage",
        "SignatureWithWrongKey",
        "KeyAlgoSpecsMismatch",
        "UnsupportedSignatureFormat",
        "FieldNotSet",
        "UnrecognizedEnum",
        "StringConversionError",
        "InvariantViolation",
    ] {
        assert!(classes.contains(class), "no recorded case ends in {class}");
    }
    // a high-S signature is valid for every ECDSA curve (BC does not require the low-S form)
    for label in ["EcP256", "EcP384", "EcSecp256k1"] {
        let line = lines
            .iter()
            .find(|f| f[1] == format!("{label}/highS"))
            .expect("highS case");
        assert_eq!(line[6], "OK", "{label}: highS");
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// the node's key-validation cache

/// [CANTON-NOTE: LIMITATION] The node caches a key's validation result by fingerprint, and the fingerprint does not cover the
/// key spec. The recording shows the effect: a P-256 key validated once is accepted again when the same bytes are declared
/// P-384, while a cold cache refuses it. canton-algo has no such cache, so it follows the cold-cache column.
#[test]
fn the_node_validation_cache_effect_is_recorded() {
    let rows = lines_of("pkcache");
    assert_eq!(rows.len(), 4, "one row per key spec");
    let quirk = rows.iter().filter(|r| r[4] != r[5]).count();
    assert!(
        quirk >= 3,
        "the cache-order effect should show on the EC specs, saw {quirk}"
    );
    for r in &rows {
        assert_eq!(r[3], "OK", "{}: the genuine key is valid", r[1]);
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// negative controls: the checkers must be able to fail

/// A checker that cannot fail proves nothing: flip a recorded verdict and the checker must say so.
#[test]
fn the_checkers_detect_a_wrong_verdict() {
    let flip = |f: &[String], at: usize, to: &str| {
        let mut g = f.to_vec();
        g[at] = to.to_string();
        g
    };
    let pk = lines_of("pk");
    let ok = pk.iter().find(|f| f[3] == "OK").unwrap();
    assert!(check_pk(ok).is_ok());
    assert!(
        check_pk(&flip(ok, 3, "ERR")).is_err(),
        "an accepted key recorded as refused"
    );
    assert!(
        check_pk(&flip(ok, 5, "EC-P384|Symbolic|signing")).is_err(),
        "a wrong key reading"
    );
    let err = pk.iter().find(|f| f[3] == "ERR").unwrap();
    assert!(
        check_pk(&flip(err, 3, "OK")).is_err(),
        "a refused key recorded as accepted"
    );
    assert!(check_pk(&flip(err, 4, "FieldNotSet")).is_err() || err[4] == "FieldNotSet");

    let sk = lines_of("sk");
    let ok = sk.iter().find(|f| f[1] == "EcP256/valid").unwrap();
    assert!(check_sk(ok).is_ok());
    assert!(
        check_sk(&flip(ok, 6, &"00".repeat(91))).is_err(),
        "a wrong derived public key"
    );

    let sg = lines_of("sg");
    let ok = sg.iter().find(|f| f[1] == "EcP256/valid").unwrap();
    assert!(check_sg(ok).is_ok());
    assert!(check_sg(&flip(ok, 6, "VERIFY")).is_err());
    let bad = sg.iter().find(|f| f[1] == "EcP256/otherHash").unwrap();
    assert!(check_sg(bad).is_ok());
    assert!(
        check_sg(&flip(bad, 6, "OK")).is_err(),
        "a refused signature recorded as valid"
    );
}

/// Independent of the recording: things the node must never accept as a valid signature of a hash.
#[test]
fn a_signature_never_verifies_for_another_hash_or_a_tampered_signature() {
    let lines = lines_of("sg");
    for label in ["Ed25519", "EcP256", "EcP384", "EcSecp256k1"] {
        let f = lines
            .iter()
            .find(|f| f[1] == format!("{label}/valid"))
            .unwrap();
        let key = parse_public_key(
            &SigningPublicKey::decode(hex::decode(&f[2]).unwrap().as_slice()).unwrap(),
        )
        .unwrap();
        let hash = hex::decode(&f[3]).unwrap();
        let wire = hex::decode(&f[5]).unwrap();
        let sig = parse_signature(&wire).unwrap();
        let use_ = usage_by_name("protocol");
        assert!(
            verify_signature(&hash, &key, &sig, &use_).is_ok(),
            "{label}: the recorded signature verifies"
        );
        let mut other = hash.clone();
        other[10] ^= 1;
        assert!(
            verify_signature(&other, &key, &sig, &use_).is_err(),
            "{label}: another hash"
        );
        let mut bad = sig.clone();
        let mid = bad.signature.len() / 2;
        bad.signature[mid] ^= 1;
        assert!(
            verify_signature(&hash, &key, &bad, &use_).is_err(),
            "{label}: a tampered signature"
        );
    }
}
