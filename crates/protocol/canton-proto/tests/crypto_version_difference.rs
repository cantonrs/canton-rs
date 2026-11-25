//! G0 decision (2026-11-12): the differences between the crypto tables measured on Canton 3.7.1 and the 3.7.2 protos are a
//! *version difference*, not a defect of G0. This test pins that reading:
//!
//! * the 3.7.2 schema (the generated types, nothing hand-written) has exactly the ids and names that
//!   `tests/oracle/provenance/g0-3.7.2/diff-vs-g0.tsv` records as the 3.7.2 side, and
//! * the names and ids that only the 3.7.1 table has are *not* in the 3.7.2 schema, so a Rust component written against the
//!   3.7.1 table instead of 3.7.2 fails here.
//!
//! [CANTON-NOTE: ORACLE] The recorded diff is produced by `scripts/remeasure-g0-372.py` from the pinned 3.7.2 sources
//! (`make verify-g0-372`); this test reads that file, so the record and the generated types cannot drift apart unnoticed.
use canton_proto::com::digitalasset::canton::crypto::v30::{
    CryptoKeyFormat, EncryptionAlgorithmSpec, SigningKeyUsage, SymmetricKeyScheme,
};

const DIFF: &str = include_str!("../../../../tests/oracle/provenance/g0-3.7.2/diff-vs-g0.tsv");

fn row(table: &str) -> Vec<&'static str> {
    DIFF.lines()
        .find(|l| l.starts_with(&format!("{table}\t")))
        .unwrap_or_else(|| panic!("no {table} row in diff-vs-g0.tsv"))
        .split('\t')
        .collect()
}

#[test]
fn names_only_the_3_7_1_table_has_are_not_in_the_3_7_2_schema() {
    let cols = row("crypto_enum_names");
    let earlier_only: Vec<&str> = cols[3].split("; ").collect();
    assert_eq!(
        earlier_only.len(),
        4,
        "the record lists four renamed enum values"
    );
    for name in earlier_only {
        let known = CryptoKeyFormat::from_str_name(name).is_some()
            || EncryptionAlgorithmSpec::from_str_name(name).is_some()
            || SymmetricKeyScheme::from_str_name(name).is_some();
        assert!(
            !known,
            "{name} is a 3.7.1 name and must not exist in the 3.7.2 schema"
        );
    }
}

#[test]
fn the_3_7_2_names_that_replace_them_exist() {
    for (renamed, now) in [
        (
            "DER_PKCS8_PKI",
            "CRYPTO_KEY_FORMAT_DER_PKCS8_PRIVATE_KEY_INFO",
        ),
        (
            "DER_X509_SPKI",
            "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
        ),
    ] {
        assert!(
            CryptoKeyFormat::from_str_name(now).is_some(),
            "{renamed} became {now}"
        );
    }
    assert!(EncryptionAlgorithmSpec::from_str_name(
        "ENCRYPTION_ALGORITHM_SPEC_ECIES_HKDF_HMAC_SHA256_AES128CBC"
    )
    .is_some());
    assert!(SymmetricKeyScheme::from_str_name("SYMMETRIC_KEY_SCHEME_AES128GCM").is_some());
}

#[test]
fn signing_key_usage_ids_are_the_3_7_2_proto_numbers_the_record_lists() {
    let cols = row("crypto_signing_key_usage_ids");
    let mut checked = 0;
    for item in cols[3].split("; ") {
        // `SIGNING_KEY_USAGE_X: earlier id=N, proto=M`
        let (name, rest) = item.split_once(": ").expect("name: earlier id=N, proto=M");
        let proto: i32 = rest
            .rsplit_once("proto=")
            .expect("proto=")
            .1
            .parse()
            .unwrap();
        let earlier: i32 = rest
            .split_once("id=")
            .unwrap()
            .1
            .split(',')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let usage = SigningKeyUsage::from_str_name(name)
            .unwrap_or_else(|| panic!("{name} is not in the 3.7.2 schema"));
        assert_eq!(usage as i32, proto, "{name} has the 3.7.2 proto number");
        assert_ne!(
            usage as i32, earlier,
            "{name} must not keep the 3.7.1 table's id"
        );
        checked += 1;
    }
    assert_eq!(checked, 5);
}
