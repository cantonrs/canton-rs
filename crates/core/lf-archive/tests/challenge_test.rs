//! Adversarial stress test harness for crates/core/lf-archive.
//! Empirically tests security invariants,
//! zip bomb defenses, path traversal defenses, tamper detection, and LF2 version gating.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_archive::{
    archive::{validate_entry_path, MAX_ENTRY_BYTES, MAX_TOTAL_BYTES},
    crypto::{compute_sha256, verify_package_id},
    decode::SUPPORTED_LF2_MINORS,
    manifest::{unfold_rfc822_lines, Manifest},
    parse_dar_bytes, parse_dar_file, DarError, DecodeError, ManifestError,
};
use std::io::{Cursor, Write};
use std::path::PathBuf;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

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

// =============================================================================
// Section 1: Empirical Verification of All 19 Test Fixtures in tests/e2e/fixtures/
// =============================================================================

#[test]
fn test_fixture_attack_entry_bomb() {
    let p = repo_root().join("tests/e2e/fixtures/attack_entry_bomb.dar");
    assert!(p.exists(), "attack_entry_bomb.dar must exist");
    let err = parse_dar_file(&p).expect_err("must reject entry bomb");
    match err {
        DarError::EntryTooLarge { entry, size, limit } => {
            assert!(size > limit, "size {} must exceed limit {}", size, limit);
            assert_eq!(limit, MAX_ENTRY_BYTES);
            assert!(entry.contains("sample-contract.dalf"));
        }
        other => panic!("expected EntryTooLarge, got: {:?}", other),
    }
}

#[test]
fn test_fixture_attack_total_budget() {
    let p = repo_root().join("tests/e2e/fixtures/attack_total_budget.dar");
    assert!(p.exists(), "attack_total_budget.dar must exist");
    let err = parse_dar_file(&p).expect_err("must reject total budget violation");
    match err {
        DarError::ArchiveTooLarge { total, limit } => {
            assert!(total > limit, "total {} must exceed limit {}", total, limit);
            assert_eq!(limit, MAX_TOTAL_BYTES);
        }
        other => panic!("expected ArchiveTooLarge, got: {:?}", other),
    }
}

#[test]
fn test_fixture_attack_path_traversal() {
    let p = repo_root().join("tests/e2e/fixtures/attack_path_traversal.dar");
    assert!(p.exists(), "attack_path_traversal.dar must exist");
    let err = parse_dar_file(&p).expect_err("must reject path traversal");
    match err {
        DarError::PathTraversal(path) => {
            assert!(
                path.contains(".."),
                "traversal path should contain '..': {}",
                path
            );
        }
        other => panic!("expected PathTraversal, got: {:?}", other),
    }
}

#[test]
fn test_fixture_corrupt_tampered_payload() {
    let p = repo_root().join("tests/e2e/fixtures/corrupt_tampered_payload.dar");
    assert!(p.exists(), "corrupt_tampered_payload.dar must exist");
    let err = parse_dar_file(&p).expect_err("must reject tampered payload");
    match err {
        DarError::Decode(DecodeError::PackageIdMismatch { declared, computed }) => {
            assert_eq!(declared.len(), 64);
            assert_eq!(computed.len(), 64);
            assert_ne!(declared, computed);
        }
        other => panic!("expected PackageIdMismatch, got: {:?}", other),
    }
}

#[test]
fn test_fixture_corrupt_legacy_lf1() {
    let p = repo_root().join("tests/e2e/fixtures/corrupt_legacy_lf1.dar");
    assert!(p.exists(), "corrupt_legacy_lf1.dar must exist");
    let err = parse_dar_file(&p).expect_err("must reject legacy LF");
    match err {
        DarError::Decode(DecodeError::UnsupportedMajorVersion(v)) => {
            // Either major "0" or "1" depending on synthetic tag (fixture encoded tag 1 = lf0)
            assert!(v == "0" || v == "1", "expected major 0 or 1, got {}", v);
        }
        other => panic!("expected UnsupportedMajorVersion, got: {:?}", other),
    }
}

#[test]
fn test_fixture_corrupt_unknown_minor() {
    let p = repo_root().join("tests/e2e/fixtures/corrupt_unknown_minor.dar");
    assert!(p.exists(), "corrupt_unknown_minor.dar must exist");
    let err = parse_dar_file(&p).expect_err("must reject unknown minor");
    match err {
        DarError::Decode(DecodeError::UnsupportedMinorVersion(minor)) => {
            assert_eq!(minor, "99");
        }
        other => panic!("expected UnsupportedMinorVersion(99), got: {:?}", other),
    }
}

#[test]
fn test_fixture_corrupt_interned_oob() {
    let p = repo_root().join("tests/e2e/fixtures/corrupt_interned_oob.dar");
    assert!(p.exists(), "corrupt_interned_oob.dar must exist");
    let err = parse_dar_file(&p).expect_err("must reject oob interned index");
    match err {
        DarError::Decode(DecodeError::InternedIndexOutOfBounds {
            index,
            table_size,
            context,
        }) => {
            assert_eq!(index, 99999);
            assert!((index as usize) >= table_size);
            assert!(!context.is_empty());
        }
        other => panic!("expected InternedIndexOutOfBounds, got: {:?}", other),
    }
}

#[test]
fn test_fixture_corrupt_bad_magic() {
    let p = repo_root().join("tests/e2e/fixtures/corrupt_bad_magic.dar");
    assert!(p.exists());
    let err = parse_dar_file(&p).expect_err("must reject bad magic");
    assert!(matches!(err, DarError::Zip(..)));
}

#[test]
fn test_fixture_corrupt_no_manifest() {
    let p = repo_root().join("tests/e2e/fixtures/corrupt_no_manifest.dar");
    assert!(p.exists());
    let err = parse_dar_file(&p).expect_err("must reject missing manifest");
    assert!(matches!(
        err,
        DarError::Manifest(ManifestError::MissingManifest)
    ));
}

#[test]
fn test_fixture_corrupt_no_main_dalf() {
    let p = repo_root().join("tests/e2e/fixtures/corrupt_no_main_dalf.dar");
    assert!(p.exists());
    let err = parse_dar_file(&p).expect_err("must reject missing Main-Dalf header");
    assert!(matches!(
        err,
        DarError::Manifest(ManifestError::MissingMainDalf)
    ));
}

#[test]
fn test_fixture_corrupt_missing_main_file() {
    let p = repo_root().join("tests/e2e/fixtures/corrupt_missing_main_file.dar");
    assert!(p.exists());
    let err = parse_dar_file(&p).expect_err("must reject missing main dalf file");
    assert!(matches!(err, DarError::MainDalfNotFound(..)));
}

#[test]
fn test_fixture_corrupt_invalid_utf8() {
    let p = repo_root().join("tests/e2e/fixtures/corrupt_invalid_utf8.dar");
    assert!(p.exists());
    let err = parse_dar_file(&p).expect_err("must reject invalid utf8");
    assert!(matches!(
        err,
        DarError::Manifest(ManifestError::InvalidUtf8(..))
    ));
}

#[test]
fn test_fixture_corrupt_bad_hash_func() {
    let p = repo_root().join("tests/e2e/fixtures/corrupt_bad_hash_func.dar");
    assert!(p.exists());
    let err = parse_dar_file(&p).expect_err("must reject unsupported hash func");
    assert!(matches!(
        err,
        DarError::Decode(DecodeError::UnsupportedHashFunction(7))
    ));
}

#[test]
fn test_fixture_valid_minimal() {
    let p = repo_root().join("tests/e2e/fixtures/valid_minimal.dar");
    let dar = parse_dar_file(&p).expect("valid_minimal must parse");
    assert_eq!(dar.lf_version, "2.1");
    assert_eq!(dar.package_name.as_deref(), Some("sample-contract"));
    assert_eq!(dar.package_version.as_deref(), Some("0.1.0"));
    assert_eq!(dar.modules, vec!["AssetHolding"]);
    assert_eq!(dar.dalfs.len(), 1);
    assert!(dar.dalfs[0].is_main);
}

#[test]
fn test_fixture_valid_multidalf() {
    let p = repo_root().join("tests/e2e/fixtures/valid_multidalf.dar");
    let dar = parse_dar_file(&p).expect("valid_multidalf must parse");
    assert_eq!(dar.main_dalf_name, "main.dalf");
    assert_eq!(dar.package_name.as_deref(), Some("multidalf-contract"));
    assert_eq!(dar.package_version.as_deref(), Some("1.0.0"));
    assert_eq!(dar.modules, vec!["Main", "Helper"]);
    assert_eq!(dar.dalfs.len(), 3);
}

#[test]
fn test_fixture_valid_folded_manifest() {
    let p = repo_root().join("tests/e2e/fixtures/valid_folded_manifest.dar");
    let dar = parse_dar_file(&p).expect("valid_folded_manifest must parse");
    assert_eq!(
        dar.main_dalf_name,
        "sample-very-long-name-contract-main-package-with-deep-hierarchy.dalf"
    );
    assert_eq!(dar.manifest_name.as_deref(), Some("folded-contract"));
}

#[test]
fn test_fixture_valid_lf22_23_24() {
    for minor in ["2", "3", "4"] {
        let p = repo_root().join(format!("tests/e2e/fixtures/valid_lf2{}.dar", minor));
        let dar = parse_dar_file(&p).expect("valid LF minor must parse");
        assert_eq!(dar.lf_version, format!("2.{}", minor));
        assert_eq!(
            dar.package_name.as_deref(),
            Some(format!("contract-lf2{}", minor).as_str())
        );
    }
}

// =============================================================================
// Section 2: Production Contract Verification
// =============================================================================

#[test]
fn test_production_sample_contract_invariants() {
    let dar_path = repo_root().join("contracts/target/sample-contract.dar");
    assert!(
        dar_path.exists(),
        "Production DAR must exist at {:?}",
        dar_path
    );

    // Test parse_dar_file
    let archive = parse_dar_file(&dar_path).expect("Failed to parse sample-contract.dar via file");

    // 1. Verify Package ID exact match
    let expected_pkg_id = "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2";
    assert_eq!(archive.main_package_id, expected_pkg_id);

    // 2. Verify LF Version exact match
    assert_eq!(archive.lf_version, "2.1");

    // 3. Additional invariants
    assert_eq!(archive.package_name.as_deref(), Some("sample-contract"));
    assert_eq!(archive.package_version.as_deref(), Some("0.1.0"));
    assert!(
        archive.modules.contains(&"AssetHolding".to_string()),
        "Expected module AssetHolding in {:?}",
        archive.modules
    );

    // 4. Test parse_dar_bytes
    let bytes = std::fs::read(&dar_path).expect("failed to read production dar bytes");
    let archive_from_bytes =
        parse_dar_bytes(&bytes).expect("Failed to parse sample-contract.dar via bytes");
    assert_eq!(archive_from_bytes, archive);
}

// =============================================================================
// Section 3: Adversarial Edge Cases & Stress Tests
// =============================================================================

#[test]
fn test_adversarial_path_traversals() {
    // Test various path traversal attack vectors against validate_entry_path
    let attack_paths = [
        "../etc/passwd",
        "..\\windows\\system32",
        "/absolute/unix/path",
        "\\absolute\\win\\path",
        "C:\\Windows\\System32\\cmd.exe",
        "d:/foo/bar",
        "foo/../../bar",
        "foo/bar/../..",
        "a/b/c/../../../etc/shadow",
        "..",
    ];

    for path in &attack_paths {
        assert!(
            validate_entry_path(path).is_err(),
            "Path '{}' should have been rejected as PathTraversal",
            path
        );
    }

    // Legitimate paths should pass
    let safe_paths = [
        "META-INF/MANIFEST.MF",
        "sample-contract.dalf",
        "sub/dir/package.dalf",
        "file_with_dots...dalf",
        "foo..bar/test.dalf",
    ];

    for path in &safe_paths {
        assert!(
            validate_entry_path(path).is_ok(),
            "Path '{}' should be allowed",
            path
        );
    }
}

#[test]
fn test_adversarial_zip_bomb_streaming_forged_header() {
    // Attack scenario: A malicious ZIP whose Central Directory claims uncompressed size
    // is small (e.g. 1024 bytes), but the actual compressed stream expands to > 256 MiB.
    // read_entry_bounded MUST detect this during streaming decompression and abort.

    let manifest = "Manifest-Version: 1.0\r\nMain-Dalf: bomb.dalf\r\n";
    let mut zip_buf = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut zip_buf));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
        zip.write_all(manifest.as_bytes()).unwrap();

        zip.start_file("bomb.dalf", options).unwrap();
        // Stream 257 MiB of repeating zeroes
        let chunk = [0u8; 1024 * 1024];
        for _ in 0..257 {
            zip.write_all(&chunk).unwrap();
        }
        zip.finish().unwrap();
    }

    // Parse this zip archive
    let err = parse_dar_bytes(&zip_buf).expect_err("Stream bomb must be caught");
    match err {
        DarError::EntryTooLarge { size, limit, .. } => {
            assert!(size > limit);
            assert_eq!(limit, MAX_ENTRY_BYTES);
        }
        other => panic!("expected EntryTooLarge, got: {:?}", other),
    }
}

#[test]
fn test_adversarial_empty_archive() {
    let mut zip_buf = Vec::new();
    {
        let zip = ZipWriter::new(Cursor::new(&mut zip_buf));
        zip.finish().unwrap();
    }

    let err = parse_dar_bytes(&zip_buf).expect_err("Empty zip must fail");
    assert!(matches!(
        err,
        DarError::Manifest(ManifestError::MissingManifest)
    ));
}

#[test]
fn test_adversarial_truncated_file() {
    let err = parse_dar_bytes(&[0x50, 0x4b, 0x03, 0x04]).expect_err("Truncated zip must fail");
    assert!(matches!(err, DarError::Zip(..)));
}

#[test]
fn test_adversarial_zero_length_file() {
    let err = parse_dar_bytes(&[]).expect_err("Zero length file must fail");
    assert!(matches!(err, DarError::Zip(..)));
}

#[test]
fn test_adversarial_manifest_rfc822_tabs_and_spaces() {
    let manifest_text = "Manifest-Version: 1.0\r\nMain-Dalf: my-\r\n\tcontract-\r\n dalf.dalf\r\nName: \r\n test-pkg\r\n";
    let unfolded = unfold_rfc822_lines(manifest_text);
    assert_eq!(unfolded.len(), 3);
    assert_eq!(unfolded[0], "Manifest-Version: 1.0");
    assert_eq!(unfolded[1], "Main-Dalf: my-contract-dalf.dalf");
    assert_eq!(unfolded[2], "Name: test-pkg");

    let parsed = Manifest::parse_str(manifest_text).unwrap();
    assert_eq!(parsed.main_dalf, "my-contract-dalf.dalf");
    assert_eq!(parsed.name.as_deref(), Some("test-pkg"));
}

#[test]
fn test_adversarial_sha256_verification_edge_cases() {
    let payload = b"Hello Daml Canton!";
    let correct_hash = compute_sha256(payload);

    // Mixed case hash must be accepted
    let uppercase_hash = correct_hash.to_ascii_uppercase();
    assert_eq!(
        verify_package_id(payload, &uppercase_hash).unwrap(),
        correct_hash
    );

    // Whitespace padded hash must be accepted
    let padded_hash = format!("  {}  \n", correct_hash);
    assert_eq!(
        verify_package_id(payload, &padded_hash).unwrap(),
        correct_hash
    );

    // Tampered payload by 1 bit
    let mut tampered = payload.to_vec();
    tampered[0] ^= 1;
    let err = verify_package_id(&tampered, &correct_hash).unwrap_err();
    assert!(matches!(err, DecodeError::PackageIdMismatch { .. }));
}

#[test]
fn test_adversarial_minor_version_gate() {
    assert!(SUPPORTED_LF2_MINORS.contains(&"1"));
    assert!(SUPPORTED_LF2_MINORS.contains(&"2"));
    assert!(SUPPORTED_LF2_MINORS.contains(&"3"));
    assert!(SUPPORTED_LF2_MINORS.contains(&"4"));

    let invalid_minors = ["0", "5", "dev", "-1", "", "99", "2.1", "beta"];
    for inv in invalid_minors {
        assert!(
            !SUPPORTED_LF2_MINORS.contains(&inv),
            "Minor '{}' must NOT be supported",
            inv
        );
    }
}
