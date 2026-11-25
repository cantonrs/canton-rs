#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_archive::{parse_dar_file, DarError, DecodeError, ManifestError};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn test_sample_contract_dar() {
    let dar_path = repo_root().join("contracts/target/sample-contract.dar");
    assert!(
        dar_path.exists(),
        "sample-contract.dar must exist at {:?}",
        dar_path
    );

    let archive = parse_dar_file(&dar_path).expect("failed to parse sample-contract.dar");

    // Verification according to dispatch:
    // main package ID == 0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2
    assert_eq!(
        archive.main_package_id,
        "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"
    );

    // LF version == 2.1
    assert_eq!(archive.lf_version, "2.1");

    // package name == Some("sample-contract")
    assert_eq!(archive.package_name.as_deref(), Some("sample-contract"));

    // package version == Some("0.1.0")
    assert_eq!(archive.package_version.as_deref(), Some("0.1.0"));

    // modules contains "AssetHolding"
    assert!(
        archive.modules.iter().any(|m| m == "AssetHolding"),
        "modules did not contain 'AssetHolding': {:?}",
        archive.modules
    );

    // Verify main dalf exists in dalfs list
    let main_dalf = archive
        .dalfs
        .iter()
        .find(|d| d.is_main)
        .expect("main dalf not found");
    assert_eq!(main_dalf.package_id, archive.main_package_id);
}

#[test]
fn test_valid_minimal_dar() {
    let path = repo_root().join("tests/e2e/fixtures/valid_minimal.dar");
    let archive = parse_dar_file(path).expect("failed to parse valid_minimal.dar");

    assert_eq!(archive.lf_version, "2.1");
    assert_eq!(archive.package_name.as_deref(), Some("sample-contract"));
    assert_eq!(archive.package_version.as_deref(), Some("0.1.0"));
    assert_eq!(archive.modules, vec!["AssetHolding"]);
    assert_eq!(archive.dalfs.len(), 1);
    assert!(archive.dalfs[0].is_main);
}

#[test]
fn test_valid_multidalf_dar() {
    let path = repo_root().join("tests/e2e/fixtures/valid_multidalf.dar");
    let archive = parse_dar_file(path).expect("failed to parse valid_multidalf.dar");

    assert_eq!(archive.main_dalf_name, "main.dalf");
    assert_eq!(archive.package_name.as_deref(), Some("multidalf-contract"));
    assert_eq!(archive.package_version.as_deref(), Some("1.0.0"));
    assert_eq!(archive.modules, vec!["Main", "Helper"]);

    // Main package + daml-prim + daml-stdlib = 3 dalfs
    assert_eq!(archive.dalfs.len(), 3);
    assert_eq!(archive.dalfs[0].name, "main.dalf");
    assert!(archive.dalfs[0].is_main);

    let dep_names: Vec<&str> = archive.dalfs.iter().map(|d| d.name.as_str()).collect();
    assert!(dep_names.contains(&"daml-prim.dalf"));
    assert!(dep_names.contains(&"daml-stdlib.dalf"));
}

#[test]
fn test_valid_folded_manifest_dar() {
    let path = repo_root().join("tests/e2e/fixtures/valid_folded_manifest.dar");
    let archive = parse_dar_file(path).expect("failed to parse valid_folded_manifest.dar");

    assert_eq!(
        archive.main_dalf_name,
        "sample-very-long-name-contract-main-package-with-deep-hierarchy.dalf"
    );
    assert_eq!(archive.manifest_name.as_deref(), Some("folded-contract"));
    assert_eq!(archive.package_name.as_deref(), Some("sample-contract"));
}

#[test]
fn test_valid_lf_minors() {
    for minor in ["2", "3", "4"] {
        let path = repo_root().join(format!("tests/e2e/fixtures/valid_lf2{}.dar", minor));
        let archive = parse_dar_file(&path)
            .unwrap_or_else(|e| panic!("failed to parse valid_lf2{}.dar: {:?}", minor, e));
        assert_eq!(archive.lf_version, format!("2.{}", minor));
    }
}

#[test]
fn test_attack_entry_bomb() {
    let path = repo_root().join("tests/e2e/fixtures/attack_entry_bomb.dar");
    let err = parse_dar_file(path).expect_err("expected attack_entry_bomb to fail");
    assert!(
        matches!(err, DarError::EntryTooLarge { .. }),
        "expected EntryTooLarge, got: {:?}",
        err
    );
}

#[test]
fn test_attack_total_budget() {
    let path = repo_root().join("tests/e2e/fixtures/attack_total_budget.dar");
    let err = parse_dar_file(path).expect_err("expected attack_total_budget to fail");
    assert!(
        matches!(err, DarError::ArchiveTooLarge { .. }),
        "expected ArchiveTooLarge, got: {:?}",
        err
    );
}

#[test]
fn test_attack_path_traversal() {
    let path = repo_root().join("tests/e2e/fixtures/attack_path_traversal.dar");
    let err = parse_dar_file(path).expect_err("expected attack_path_traversal to fail");
    assert!(
        matches!(err, DarError::PathTraversal(..)),
        "expected PathTraversal, got: {:?}",
        err
    );
}

#[test]
fn test_corrupt_tampered_payload() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_tampered_payload.dar");
    let err = parse_dar_file(path).expect_err("expected corrupt_tampered_payload to fail");
    assert!(
        matches!(err, DarError::Decode(DecodeError::PackageIdMismatch { .. })),
        "expected PackageIdMismatch, got: {:?}",
        err
    );
}

#[test]
fn test_corrupt_legacy_lf1() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_legacy_lf1.dar");
    let err = parse_dar_file(path).expect_err("expected corrupt_legacy_lf1 to fail");
    assert!(
        matches!(
            err,
            DarError::Decode(DecodeError::UnsupportedMajorVersion(..))
        ),
        "expected UnsupportedMajorVersion, got: {:?}",
        err
    );
}

#[test]
fn test_corrupt_unknown_minor() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_unknown_minor.dar");
    let err = parse_dar_file(path).expect_err("expected corrupt_unknown_minor to fail");
    assert!(
        matches!(
            err,
            DarError::Decode(DecodeError::UnsupportedMinorVersion(..))
        ),
        "expected UnsupportedMinorVersion, got: {:?}",
        err
    );
}

#[test]
fn test_corrupt_interned_oob() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_interned_oob.dar");
    let err = parse_dar_file(path).expect_err("expected corrupt_interned_oob to fail");
    assert!(
        matches!(
            err,
            DarError::Decode(DecodeError::InternedIndexOutOfBounds { .. })
        ),
        "expected InternedIndexOutOfBounds, got: {:?}",
        err
    );
}

#[test]
fn test_corrupt_bad_magic() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_bad_magic.dar");
    let err = parse_dar_file(path).expect_err("expected corrupt_bad_magic to fail");
    assert!(
        matches!(err, DarError::Zip(..)),
        "expected Zip error, got: {:?}",
        err
    );
}

#[test]
fn test_corrupt_no_manifest() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_no_manifest.dar");
    let err = parse_dar_file(path).expect_err("expected corrupt_no_manifest to fail");
    assert!(
        matches!(err, DarError::Manifest(ManifestError::MissingManifest)),
        "expected MissingManifest, got: {:?}",
        err
    );
}

#[test]
fn test_corrupt_no_main_dalf() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_no_main_dalf.dar");
    let err = parse_dar_file(path).expect_err("expected corrupt_no_main_dalf to fail");
    assert!(
        matches!(err, DarError::Manifest(ManifestError::MissingMainDalf)),
        "expected MissingMainDalf, got: {:?}",
        err
    );
}

#[test]
fn test_corrupt_missing_main_file() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_missing_main_file.dar");
    let err = parse_dar_file(path).expect_err("expected corrupt_missing_main_file to fail");
    assert!(
        matches!(err, DarError::MainDalfNotFound(..)),
        "expected MainDalfNotFound, got: {:?}",
        err
    );
}

#[test]
fn test_corrupt_invalid_utf8() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_invalid_utf8.dar");
    let err = parse_dar_file(path).expect_err("expected corrupt_invalid_utf8 to fail");
    assert!(
        matches!(err, DarError::Manifest(ManifestError::InvalidUtf8(..))),
        "expected InvalidUtf8, got: {:?}",
        err
    );
}

#[test]
fn test_corrupt_bad_hash_func() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_bad_hash_func.dar");
    let err = parse_dar_file(path).expect_err("expected corrupt_bad_hash_func to fail");
    assert!(
        matches!(
            err,
            DarError::Decode(DecodeError::UnsupportedHashFunction(7))
        ),
        "expected UnsupportedHashFunction(7), got: {:?}",
        err
    );
}

#[test]
fn test_parse_dar_bytes_sample_contract() {
    let path = repo_root().join("contracts/target/sample-contract.dar");
    let bytes = std::fs::read(&path).expect("failed to read sample-contract.dar");
    let archive = lf_archive::parse_dar_bytes(&bytes).expect("parse_dar_bytes failed");

    assert_eq!(
        archive.main_package_id,
        "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"
    );
    assert_eq!(archive.lf_version, "2.1");
    assert_eq!(archive.package_name.as_deref(), Some("sample-contract"));
    assert_eq!(archive.package_version.as_deref(), Some("0.1.0"));
    assert!(archive.modules.contains(&"AssetHolding".to_string()));
}

#[test]
fn test_splice_core_dars_main_package_id_preservation() {
    let manifest_path = repo_root().join("tests/oracle/splice-dars/dars-manifest.tsv");
    let manifest_text =
        std::fs::read_to_string(&manifest_path).expect("failed to read dars-manifest.tsv");

    let core_dars = [
        "splice-amulet-0.1.25.dar",
        "splice-dso-governance-0.1.31.dar",
        "splice-wallet-0.1.26.dar",
        "splice-validator-lifecycle-0.1.7.dar",
    ];

    for dar_name in core_dars {
        let row = manifest_text
            .lines()
            .skip(1)
            .find_map(|line| {
                let cols: Vec<&str> = line.split('\t').collect();
                if cols.first().copied() == Some(dar_name) {
                    Some((cols[5].to_string(), cols[6].parse::<usize>().unwrap()))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| panic!("missing manifest row for {dar_name}"));

        let dar_path = repo_root().join("tests/oracle/splice-dars").join(dar_name);
        let parsed =
            parse_dar_file(&dar_path).unwrap_or_else(|e| panic!("failed to parse {dar_name}: {e}"));
        assert_eq!(
            parsed.main_package_id, row.0,
            "main_package_id mismatch for {dar_name}"
        );
        assert_eq!(
            parsed.dalfs.len(),
            row.1,
            "dalf_count mismatch for {dar_name}"
        );
    }
}
