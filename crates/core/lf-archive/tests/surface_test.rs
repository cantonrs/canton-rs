//! Integration tests for Daml-LF2 module surface decoding (M1).

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_archive::{parse_dar_file, DarError, DecodeError, SurfaceType};
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

// ===========================================================================
// Positive Tests: AssetHolding in sample-contract.dar
// ===========================================================================

#[test]
fn test_sample_contract_surface_decoding() {
    let dar_path = repo_root().join("contracts/target/sample-contract.dar");
    assert!(
        dar_path.exists(),
        "sample-contract.dar must exist at {:?}",
        dar_path
    );

    let archive = parse_dar_file(&dar_path).expect("failed to parse sample-contract.dar");

    // 1. Verify Package ID
    assert_eq!(
        archive.main_package_id,
        "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"
    );

    // 2. Verify Module Surfaces length and name
    assert_eq!(archive.module_surfaces.len(), 1);
    let module = &archive.module_surfaces[0];
    assert_eq!(module.name, "AssetHolding");

    // 3. Verify Template Count and Identity
    assert_eq!(module.templates.len(), 1);
    let template = &module.templates[0];
    assert_eq!(template.name, "AssetHolding");
    assert_eq!(template.param_name, "this");

    // 4. Verify 5 Fields & Exact Types
    assert_eq!(template.fields.len(), 5);

    let expected_fields = [
        ("bank", SurfaceType::Party, "Party"),
        ("owner", SurfaceType::Party, "Party"),
        ("auditor", SurfaceType::Party, "Party"),
        ("assetSymbol", SurfaceType::Text, "Text"),
        ("amount", SurfaceType::Numeric(Some(10)), "Decimal"),
    ];

    for (i, (expected_name, expected_ty, expected_str)) in expected_fields.iter().enumerate() {
        let field = &template.fields[i];
        assert_eq!(field.name, *expected_name, "field {} name mismatch", i);
        assert_eq!(&field.ty, expected_ty, "field {} type mismatch", i);
        assert_eq!(
            &field.type_str, expected_str,
            "field {} type_str mismatch",
            i
        );
    }

    // 5. Verify Signatories and Observers
    assert_eq!(template.signatories, vec!["bank", "owner"]);
    assert_eq!(template.observers, vec!["auditor"]);

    // 6. Verify Ensure Precondition Byte Presence (unexecuted)
    assert!(template.ensure.present, "ensure should be present");
    assert!(
        template.ensure.bytes_len > 0,
        "ensure bytecode length should be non-zero"
    );

    // 7. Verify Choices (4 choices)
    assert_eq!(template.choices.len(), 4, "expected 4 choices");

    // 7a. Choice: Transfer
    let transfer = template
        .choices
        .iter()
        .find(|c| c.name == "Transfer")
        .expect("Transfer choice missing");
    assert!(transfer.consuming, "Transfer must be consuming");
    assert_eq!(transfer.controllers, vec!["owner"]);
    assert_eq!(transfer.params.len(), 1);
    assert_eq!(transfer.params[0].name, "newOwner");
    assert_eq!(transfer.params[0].ty, SurfaceType::Party);
    assert_eq!(transfer.params[0].type_str, "Party");
    assert_eq!(transfer.return_type_str, "ContractId AssetHolding");
    assert!(transfer.do_body.present, "Transfer do_body must be present");
    assert!(transfer.do_body.bytes_len > 0);

    // 7b. Choice: SplitTransfer
    let split = template
        .choices
        .iter()
        .find(|c| c.name == "SplitTransfer")
        .expect("SplitTransfer choice missing");
    assert!(split.consuming, "SplitTransfer must be consuming");
    assert_eq!(split.controllers, vec!["owner"]);
    assert_eq!(split.params.len(), 2);
    assert_eq!(split.params[0].name, "transferAmount");
    assert_eq!(split.params[0].type_str, "Decimal");
    assert_eq!(split.params[1].name, "recipient");
    assert_eq!(split.params[1].type_str, "Party");
    assert!(
        split.return_type_str.contains("Tuple2")
            || split
                .return_type_str
                .contains("(ContractId AssetHolding, ContractId AssetHolding)")
    );
    assert!(
        split.do_body.present,
        "SplitTransfer do_body must be present"
    );
    assert!(split.do_body.bytes_len > 0);

    // 7c. Choice: Settle
    let settle = template
        .choices
        .iter()
        .find(|c| c.name == "Settle")
        .expect("Settle choice missing");
    assert!(settle.consuming, "Settle must be consuming");
    assert_eq!(settle.controllers, vec!["bank"]);
    assert_eq!(settle.params.len(), 0);
    assert_eq!(settle.return_type_str, "()");
    assert!(settle.do_body.present, "Settle do_body must be present");
    assert!(settle.do_body.bytes_len > 0);

    // 7d. Choice: Archive
    let archive_choice = template
        .choices
        .iter()
        .find(|c| c.name == "Archive")
        .expect("Archive choice missing");
    assert!(archive_choice.consuming, "Archive must be consuming");
    assert_eq!(archive_choice.controllers, vec!["bank", "owner"]);
    assert_eq!(archive_choice.params.len(), 0);
    assert_eq!(archive_choice.return_type_str, "()");
    assert!(
        archive_choice.do_body.present,
        "Archive do_body must be present"
    );
    assert!(archive_choice.do_body.bytes_len > 0);
}

// ===========================================================================
// Backward Compatibility Tests: Synthetic Minimal & Multi-DALF Fixtures
// ===========================================================================

#[test]
fn test_backward_compatibility_minimal_dar() {
    let path = repo_root().join("tests/e2e/fixtures/valid_minimal.dar");
    let archive = parse_dar_file(path).expect("valid_minimal.dar must parse");

    assert_eq!(archive.lf_version, "2.1");
    assert_eq!(archive.package_name.as_deref(), Some("sample-contract"));
    assert_eq!(archive.modules, vec!["AssetHolding"]);

    // Must have module surfaces populated with 0 templates without error
    assert_eq!(archive.module_surfaces.len(), 1);
    assert_eq!(archive.module_surfaces[0].name, "AssetHolding");
    assert_eq!(archive.module_surfaces[0].templates.len(), 0);
}

#[test]
fn test_backward_compatibility_multidalf_dar() {
    let path = repo_root().join("tests/e2e/fixtures/valid_multidalf.dar");
    let archive = parse_dar_file(path).expect("valid_multidalf.dar must parse");

    assert_eq!(archive.main_dalf_name, "main.dalf");
    assert_eq!(archive.modules, vec!["Main", "Helper"]);

    // Main package has 2 modules, each with 0 templates
    assert_eq!(archive.module_surfaces.len(), 2);
    assert_eq!(archive.module_surfaces[0].name, "Main");
    assert_eq!(archive.module_surfaces[1].name, "Helper");

    // Dependencies (daml-prim, daml-stdlib) are strictly envelope-only
    assert_eq!(archive.dalfs.len(), 3);
    assert!(archive.dalfs.iter().any(|d| d.name == "daml-prim.dalf"));
    assert!(archive.dalfs.iter().any(|d| d.name == "daml-stdlib.dalf"));
}

#[test]
fn test_strict_dependency_isolation_in_production_dar() {
    let dar_path = repo_root().join("contracts/target/sample-contract.dar");
    let archive = parse_dar_file(&dar_path).expect("failed to parse sample-contract.dar");

    // 31 dalfs total (1 main + 30 dependencies)
    assert_eq!(archive.dalfs.len(), 31);
    let dep_dalfs: Vec<_> = archive.dalfs.iter().filter(|d| !d.is_main).collect();
    assert_eq!(dep_dalfs.len(), 30);

    // Module surfaces contains ONLY main contract modules, NOT dependency modules
    for mod_surface in &archive.module_surfaces {
        assert_ne!(mod_surface.name, "DA.Internal.Prelude");
        assert_ne!(mod_surface.name, "GHC.Types");
    }
}

// ===========================================================================
// Negative Tests: Fail-Closed Security & Tamper Defenses
// ===========================================================================

#[test]
fn test_negative_truncated_payload() {
    let truncated_bytes = vec![0x08, 0x01, 0x12]; // invalid protobuf
    let err = lf_archive::decode_dalf(&truncated_bytes).expect_err("must reject truncated payload");
    assert!(
        matches!(err, DecodeError::Protobuf(_))
            || matches!(err, DecodeError::PackageIdMismatch { .. })
            || matches!(err, DecodeError::MissingPayload)
    );
}

#[test]
fn test_negative_tampered_payload_hash() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_tampered_payload.dar");
    let err = parse_dar_file(path).expect_err("must reject tampered payload");
    assert!(matches!(
        err,
        DarError::Decode(DecodeError::PackageIdMismatch { .. })
    ));
}

#[test]
fn test_negative_interned_string_oob() {
    let path = repo_root().join("tests/e2e/fixtures/corrupt_interned_oob.dar");
    let err = parse_dar_file(path).expect_err("must reject oob interned index");
    assert!(matches!(
        err,
        DarError::Decode(DecodeError::InternedIndexOutOfBounds { .. })
    ));
}
