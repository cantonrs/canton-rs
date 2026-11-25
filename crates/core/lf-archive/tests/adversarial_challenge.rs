#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_archive::manifest::{unfold_rfc822_lines, Manifest};
use lf_archive::proto::daml_lf::{Archive, HashFunction};
use lf_archive::{parse_dar_bytes, parse_dar_file, DarError, DecodeError, ManifestError};
use prost::Message;
use sha2::{Digest, Sha256};
use std::io::Write;
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

// ---------------------------------------------------------------------------
// Challenge 1: Multi-line RFC 822 Folded Headers
// ---------------------------------------------------------------------------

#[test]
fn challenge_rfc822_folding_edge_cases() {
    // 1. Multiple continuation lines with spaces and tabs
    let manifest_text = concat!(
        "Manifest-Version: 1.0\r\n",
        "Main-Dalf: long-prefix-\r\n",
        " middle-segment-\r\n",
        "\twith-tab-\r\n",
        " suffix.dalf\r\n",
        "Dalfs: dep1.dalf,\r\n",
        " dep2.dalf,\r\n",
        "\tdep3.dalf\r\n",
        "Format: daml-lf\r\n",
    );
    let manifest =
        Manifest::parse_str(manifest_text).expect("failed parsing complex folded manifest");
    assert_eq!(
        manifest.main_dalf,
        "long-prefix-middle-segment-with-tab-suffix.dalf"
    );
    assert_eq!(manifest.dalfs, vec!["dep1.dalf", "dep2.dalf", "dep3.dalf"]);
    assert_eq!(manifest.format.as_deref(), Some("daml-lf"));

    // 2. Orphaned continuation line at the start of manifest
    let orphan_text = " continuation line with no header\r\nMain-Dalf: test.dalf\r\n";
    let orphan_manifest =
        Manifest::parse_str(orphan_text).expect("orphaned continuation should not abort parse");
    assert_eq!(orphan_manifest.main_dalf, "test.dalf");

    // 3. Case-insensitivity in headers
    let case_variations = [
        "MAIN-DALF: contract.dalf\r\n",
        "main-dalf: contract.dalf\r\n",
        "mAiN-dAlF: contract.dalf\r\n",
    ];
    for case_text in case_variations {
        let m = Manifest::parse_str(case_text).expect("case insensitive main-dalf failed");
        assert_eq!(m.main_dalf, "contract.dalf");
    }

    // 4. Space-separated and mixed delimiter Dalfs
    let mixed_dalfs = "Main-Dalf: m.dalf\r\nDalfs: a.dalf   b.dalf,\tc.dalf , d.dalf\r\n";
    let m = Manifest::parse_str(mixed_dalfs).expect("mixed delimiter dalfs failed");
    assert_eq!(m.dalfs, vec!["a.dalf", "b.dalf", "c.dalf", "d.dalf"]);

    // 5. Raw unfold function edge cases
    let empty_unfold = unfold_rfc822_lines("");
    assert!(empty_unfold.is_empty());

    let single_line = unfold_rfc822_lines("Key: Value");
    assert_eq!(single_line, vec!["Key: Value"]);

    // 50 continuation lines
    let mut big_header = "Long-Key: v".to_string();
    for i in 0..50 {
        big_header.push_str(&format!("\r\n segment_{}", i));
    }
    let unfolded_big = unfold_rfc822_lines(&big_header);
    assert_eq!(unfolded_big.len(), 1);
    assert!(unfolded_big[0].contains("segment_0segment_1"));
}

// ---------------------------------------------------------------------------
// Challenge 2: Multi-DALF Archives & Dependency Graphs
// ---------------------------------------------------------------------------

#[test]
fn challenge_multi_dalf_fixtures_and_deduplication() {
    // 1. Verify valid_multidalf fixture
    let path = repo_root().join("tests/e2e/fixtures/valid_multidalf.dar");
    let archive = parse_dar_file(&path).expect("valid_multidalf.dar failed to parse");
    assert_eq!(archive.main_dalf_name, "main.dalf");
    assert_eq!(archive.dalfs.len(), 3);
    assert!(archive.dalfs[0].is_main);
    assert!(!archive.dalfs[1].is_main);
    assert!(!archive.dalfs[2].is_main);

    // 2. Build synthetic archive with duplicate dependencies, self-referential Dalfs, and unlisted dalfs
    // Extract a valid dalf bytes from valid_multidalf
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
    let mut main_dalf_bytes = Vec::new();
    std::io::copy(&mut zip.by_name("main.dalf").unwrap(), &mut main_dalf_bytes).unwrap();
    let mut prim_dalf_bytes = Vec::new();
    std::io::copy(
        &mut zip.by_name("daml-prim.dalf").unwrap(),
        &mut prim_dalf_bytes,
    )
    .unwrap();

    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

        // Manifest lists duplicate daml-prim.dalf and includes main.dalf in Dalfs list
        let manifest = "Manifest-Version: 1.0\r\n\
Main-Dalf: main.dalf\r\n\
Dalfs: daml-prim.dalf, main.dalf, daml-prim.dalf\r\n\
Format: daml-lf\r\n";
        zw.start_file("META-INF/MANIFEST.MF", opts).unwrap();
        zw.write_all(manifest.as_bytes()).unwrap();

        zw.start_file("main.dalf", opts).unwrap();
        zw.write_all(&main_dalf_bytes).unwrap();

        zw.start_file("daml-prim.dalf", opts).unwrap();
        zw.write_all(&prim_dalf_bytes).unwrap();

        // Extra unlisted dalf
        zw.start_file("unlisted-extra.dalf", opts).unwrap();
        zw.write_all(&prim_dalf_bytes).unwrap();

        zw.finish().unwrap();
    }

    let synthetic_bytes = buf.into_inner();
    let parsed = parse_dar_bytes(&synthetic_bytes).expect("synthetic multi-dalf should succeed");

    assert_eq!(parsed.main_dalf_name, "main.dalf");
    // Main DALF is first and is_main = true
    assert_eq!(parsed.dalfs[0].name, "main.dalf");
    assert!(parsed.dalfs[0].is_main);

    // Check deduplication: daml-prim.dalf appears exactly once
    let prim_count = parsed
        .dalfs
        .iter()
        .filter(|d| d.name == "daml-prim.dalf")
        .count();
    assert_eq!(prim_count, 1, "daml-prim.dalf should be deduplicated");

    // Check main.dalf appears only once
    let main_count = parsed
        .dalfs
        .iter()
        .filter(|d| d.name == "main.dalf")
        .count();
    assert_eq!(main_count, 1, "main.dalf should not be duplicated");

    // Check unlisted dalf was discovered
    let unlisted_count = parsed
        .dalfs
        .iter()
        .filter(|d| d.name == "unlisted-extra.dalf")
        .count();
    assert_eq!(unlisted_count, 1, "unlisted-extra.dalf should be included");
    assert!(
        !parsed
            .dalfs
            .iter()
            .find(|d| d.name == "unlisted-extra.dalf")
            .unwrap()
            .is_main
    );
}

// ---------------------------------------------------------------------------
// Challenge 3: Corrupt Inputs & Security Ceilings
// ---------------------------------------------------------------------------

#[test]
fn challenge_corrupt_files_exact_error_mapping() {
    let fixtures = repo_root().join("tests/e2e/fixtures");

    // 1. Corrupt bad magic
    let err_bad_magic = parse_dar_file(fixtures.join("corrupt_bad_magic.dar"))
        .expect_err("corrupt_bad_magic must fail");
    assert!(matches!(err_bad_magic, DarError::Zip(_)));

    // 2. Corrupt no manifest
    let err_no_manifest = parse_dar_file(fixtures.join("corrupt_no_manifest.dar"))
        .expect_err("corrupt_no_manifest must fail");
    assert!(matches!(
        err_no_manifest,
        DarError::Manifest(ManifestError::MissingManifest)
    ));

    // 3. Corrupt no main dalf
    let err_no_main_dalf = parse_dar_file(fixtures.join("corrupt_no_main_dalf.dar"))
        .expect_err("corrupt_no_main_dalf must fail");
    assert!(matches!(
        err_no_main_dalf,
        DarError::Manifest(ManifestError::MissingMainDalf)
    ));

    // 4. Corrupt missing main file
    let err_missing_file = parse_dar_file(fixtures.join("corrupt_missing_main_file.dar"))
        .expect_err("corrupt_missing_main_file must fail");
    assert!(matches!(err_missing_file, DarError::MainDalfNotFound(_)));

    // 5. Corrupt tampered payload
    let err_tampered = parse_dar_file(fixtures.join("corrupt_tampered_payload.dar"))
        .expect_err("corrupt_tampered_payload must fail");
    assert!(matches!(
        err_tampered,
        DarError::Decode(DecodeError::PackageIdMismatch { .. })
    ));

    // 6. Corrupt legacy LF1
    let err_lf1 = parse_dar_file(fixtures.join("corrupt_legacy_lf1.dar"))
        .expect_err("corrupt_legacy_lf1 must fail");
    assert!(matches!(
        err_lf1,
        DarError::Decode(DecodeError::UnsupportedMajorVersion(_))
    ));

    // 7. Corrupt unknown minor
    let err_minor = parse_dar_file(fixtures.join("corrupt_unknown_minor.dar"))
        .expect_err("corrupt_unknown_minor must fail");
    assert!(matches!(
        err_minor,
        DarError::Decode(DecodeError::UnsupportedMinorVersion(_))
    ));

    // 8. Corrupt interned out of bounds
    let err_oob = parse_dar_file(fixtures.join("corrupt_interned_oob.dar"))
        .expect_err("corrupt_interned_oob must fail");
    assert!(matches!(
        err_oob,
        DarError::Decode(DecodeError::InternedIndexOutOfBounds { .. })
    ));

    // 9. Corrupt invalid UTF-8
    let err_utf8 = parse_dar_file(fixtures.join("corrupt_invalid_utf8.dar"))
        .expect_err("corrupt_invalid_utf8 must fail");
    assert!(matches!(
        err_utf8,
        DarError::Manifest(ManifestError::InvalidUtf8(_))
    ));

    // 10. Corrupt bad hash function
    let err_hash_fn = parse_dar_file(fixtures.join("corrupt_bad_hash_func.dar"))
        .expect_err("corrupt_bad_hash_func must fail");
    assert!(matches!(
        err_hash_fn,
        DarError::Decode(DecodeError::UnsupportedHashFunction(7))
    ));

    // 11. Security bounds: entry bomb, total budget, path traversal
    let err_bomb = parse_dar_file(fixtures.join("attack_entry_bomb.dar"))
        .expect_err("attack_entry_bomb must fail");
    assert!(matches!(err_bomb, DarError::EntryTooLarge { .. }));

    let err_total = parse_dar_file(fixtures.join("attack_total_budget.dar"))
        .expect_err("attack_total_budget must fail");
    assert!(matches!(err_total, DarError::ArchiveTooLarge { .. }));

    let err_traversal = parse_dar_file(fixtures.join("attack_path_traversal.dar"))
        .expect_err("attack_path_traversal must fail");
    assert!(matches!(err_traversal, DarError::PathTraversal(_)));
}

// ---------------------------------------------------------------------------
// Challenge 4: Independent Package ID & AssetHolding Verification
// ---------------------------------------------------------------------------

#[test]
fn challenge_independent_package_id_and_modules() {
    let dar_path = repo_root().join("contracts/target/sample-contract.dar");
    assert!(dar_path.exists(), "sample-contract.dar not found");

    // Independent extraction of payload from ZIP
    let file = std::fs::File::open(&dar_path).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();

    // Read manifest
    let mut manifest_str = String::new();
    std::io::Read::read_to_string(
        &mut zip.by_name("META-INF/MANIFEST.MF").unwrap(),
        &mut manifest_str,
    )
    .unwrap();

    let unfolded = unfold_rfc822_lines(&manifest_str);
    let mut main_dalf_path = None;
    for line in &unfolded {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("Main-Dalf") {
                main_dalf_path = Some(v.trim().to_string());
                break;
            }
        }
    }
    let main_dalf_path = main_dalf_path.expect("Main-Dalf not found in manifest");

    // Read raw main dalf bytes
    let mut dalf_entry = zip
        .by_name(&main_dalf_path)
        .expect("main dalf entry not in zip");
    let mut dalf_bytes = Vec::new();
    std::io::Read::read_to_end(&mut dalf_entry, &mut dalf_bytes).unwrap();

    // Decode Archive message using prost
    let archive_envelope =
        Archive::decode(dalf_bytes.as_slice()).expect("prost Archive decode failed");

    // Verify hash_function
    assert_eq!(archive_envelope.hash_function, HashFunction::Sha256 as i32);

    // Compute independent SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&archive_envelope.payload);
    let computed_digest = hex::encode(hasher.finalize()).to_ascii_lowercase();

    // Independent check against Archive.hash
    assert_eq!(
        computed_digest,
        archive_envelope.hash.trim().to_ascii_lowercase()
    );

    // Expected package ID from dispatch
    let expected_pkg_id = "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2";
    assert_eq!(computed_digest, expected_pkg_id);

    // Now verify through lf_archive::parse_dar_file API
    let parsed_archive = parse_dar_file(&dar_path).expect("parse_dar_file failed");
    assert_eq!(parsed_archive.main_package_id, computed_digest);
    assert_eq!(parsed_archive.main_package_id, expected_pkg_id);

    // Verify modules contains "AssetHolding"
    assert!(
        parsed_archive.modules.contains(&"AssetHolding".to_string()),
        "modules {:?} did not contain AssetHolding",
        parsed_archive.modules
    );

    // Verify additional metadata
    assert_eq!(parsed_archive.lf_version, "2.1");
    assert_eq!(
        parsed_archive.package_name.as_deref(),
        Some("sample-contract")
    );
    assert_eq!(parsed_archive.package_version.as_deref(), Some("0.1.0"));
    assert_eq!(
        parsed_archive.manifest_name.as_deref(),
        Some("sample-contract-0.1.0")
    );
}

// ---------------------------------------------------------------------------
// Challenge 5: Path Traversal Bounds & Windows/Unix Separators
// ---------------------------------------------------------------------------

#[test]
fn challenge_path_traversal_variations() {
    use lf_archive::archive::validate_entry_path;

    // Reject parent directory
    assert!(validate_entry_path("../evil.dalf").is_err());
    assert!(validate_entry_path("foo/../bar.dalf").is_err());
    assert!(validate_entry_path("foo/bar/../../evil.dalf").is_err());
    assert!(validate_entry_path("..\\evil.dalf").is_err());
    assert!(validate_entry_path("foo\\..\\evil.dalf").is_err());

    // Reject absolute paths
    assert!(validate_entry_path("/etc/passwd").is_err());
    assert!(validate_entry_path("\\windows\\system32").is_err());

    // Reject Windows volume drive letters
    assert!(validate_entry_path("C:evil.dalf").is_err());
    assert!(validate_entry_path("D:\\evil.dalf").is_err());
    assert!(validate_entry_path("z:/evil.dalf").is_err());

    // Accept safe relative paths
    assert!(validate_entry_path("main.dalf").is_ok());
    assert!(validate_entry_path("META-INF/MANIFEST.MF").is_ok());
    assert!(validate_entry_path("sub/dir/package.dalf").is_ok());
    assert!(validate_entry_path("my..package.dalf").is_ok()); // double dot inside name, not standalone component
}

// ---------------------------------------------------------------------------
// Challenge 6: Manifest Corner Cases
// ---------------------------------------------------------------------------

#[test]
fn challenge_manifest_corner_cases() {
    // Empty string
    let res = Manifest::parse_str("");
    assert!(matches!(res, Err(ManifestError::MissingMainDalf)));

    // Whitespace only
    let res = Manifest::parse_str("   \r\n \t \r\n");
    assert!(matches!(res, Err(ManifestError::MissingMainDalf)));

    // Manifest without trailing newline
    let res = Manifest::parse_str("Main-Dalf: contract.dalf");
    assert!(res.is_ok());
    assert_eq!(res.unwrap().main_dalf, "contract.dalf");

    // Multiple colons in header value
    let res = Manifest::parse_str("Main-Dalf: urn:uuid:1234.dalf\r\n");
    assert!(res.is_ok());
    assert_eq!(res.unwrap().main_dalf, "urn:uuid:1234.dalf");

    // Invalid UTF-8 bytes
    let invalid_bytes = b"Main-Dalf: \xFF\xFEcontract.dalf\r\n";
    let res = Manifest::parse(invalid_bytes);
    assert!(matches!(res, Err(ManifestError::InvalidUtf8(_))));
}
