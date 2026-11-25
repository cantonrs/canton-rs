//! U-11: the upload endpoint refuses the DARs the JVM answers `DAR_VALIDATION_ERROR` for (the tampered packages of
//! `tests/oracle/dar-input`) and still accepts the valid sample. Docker-free: the JVM's answers for the same DARs are in
//! `tests/oracle/dar-input/expected.jsonl` and are compared by `lf-archive/tests/dar_input_oracle.rs`.
mod common;

use std::path::Path;

use common::call;
use ledger_json_api::ExecutionService;

fn upload(svc: &ExecutionService, rel: &str) -> (u16, serde_json::Value) {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(rel);
    call(svc, "POST", "/v2/dars", std::fs::read(p).expect("dar"))
}

#[test]
fn the_upload_refuses_a_package_that_does_not_type_check() {
    let jvm: Vec<String> = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tests/oracle/dar-input/expected.jsonl"),
    )
    .unwrap()
    .lines()
    .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
    .filter(|d| d["code"] == "DAR_VALIDATION_ERROR")
    .map(|d| d["id"].as_str().unwrap().to_string())
    .collect();
    assert!(
        jvm.len() >= 8,
        "the JVM recording has {} validation errors",
        jvm.len()
    );
    for id in &jvm {
        let svc = ExecutionService::new();
        let before = call(&svc, "GET", "/v2/packages", vec![]).1;
        let (status, body) = upload(&svc, &format!("tests/oracle/dar-input/dars/{id}.dar"));
        assert_eq!(status, 400, "{id}: {body}");
        assert_eq!(body["code"], "DAR_VALIDATION_ERROR", "{id}: {body}");
        // nothing of the refused DAR stays on the participant
        assert_eq!(call(&svc, "GET", "/v2/packages", vec![]).1, before, "{id}");
    }
}

#[test]
fn the_upload_still_accepts_the_valid_sample() {
    let svc = ExecutionService::new();
    let (status, body) = upload(&svc, "contracts/target/sample-contract.dar");
    assert_eq!(status, 200, "{body}");
}

/// The package an upgrade DAR upgrades is not one of its dependencies: the node accepted `upg-2.0.0.dar` without `upg-1.0.0`
/// (S-LF-014). Counting the upgraded package as a dependency refused a valid DAR.
#[test]
fn an_upgrade_dar_is_accepted_without_the_package_it_upgrades() {
    let svc = ExecutionService::new();
    let (status, body) = upload(&svc, "tests/oracle/upgrade/upg-2.0.0.dar");
    assert_eq!(status, 200, "{body}");
}

/// A fixture DAR with its main package edited by `edit` (a new package id), as a DAR of stored entries.
fn edited_dar(rel: &str, edit: impl FnOnce(&mut lf_archive::proto::daml_lf_2::Package)) -> Vec<u8> {
    use lf_archive::proto::daml_lf::{archive_payload::Sum, Archive, ArchivePayload, HashFunction};
    use prost::Message;
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(rel);
    let bytes = std::fs::read(&path).expect("dar");
    let dar = lf_archive::load_dar_file(&path).expect("dar");
    let main = dar.archive.main_package_id.clone();
    let mut edit = Some(edit);
    let mut entries = Vec::new();
    for (id, archive, payload) in lf_archive::dalf_entries(&bytes).expect("entries") {
        if id != main {
            entries.push((format!("{id}.dalf"), archive));
            continue;
        }
        let mut payload = ArchivePayload::decode(payload.as_slice()).expect("payload");
        let mut package = dar.packages[&main].clone();
        if let Some(edit) = edit.take() {
            edit(&mut package);
        }
        payload.sum = Some(Sum::DamlLf2(package.encode_to_vec()));
        let payload = payload.encode_to_vec();
        let archive = Archive {
            hash_function: HashFunction::Sha256 as i32,
            hash: lf_archive::compute_sha256(&payload),
            payload,
        };
        entries.insert(0, ("main.dalf".to_string(), archive.encode_to_vec()));
    }
    let dalfs: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    let manifest = format!(
        "Manifest-Version: 1.0\r\nMain-Dalf: main.dalf\r\nDalfs: {}\r\n",
        dalfs.join(", ")
    );
    entries.insert(0, ("META-INF/MANIFEST.MF".into(), manifest.into_bytes()));
    stored_zip(&entries)
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// A ZIP archive whose entries are stored uncompressed.
fn stored_zip(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let u16le = |v: usize| u16::try_from(v).expect("u16").to_le_bytes();
    let u32le = |v: usize| u32::try_from(v).expect("u32").to_le_bytes();
    let (mut out, mut central) = (Vec::new(), Vec::new());
    for (name, data) in entries {
        let offset = out.len();
        let crc = crc32(data).to_le_bytes();
        // version 20, no flags, stored, 1980-01-01 00:00
        let common = [
            &[20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0][..],
            &crc,
            &u32le(data.len()),
            &u32le(data.len()),
        ]
        .concat();
        out.extend([0x50, 0x4b, 0x03, 0x04]);
        out.extend(&common);
        out.extend(u16le(name.len()));
        out.extend([0, 0]);
        out.extend(name.as_bytes());
        out.extend(data);
        central.extend([0x50, 0x4b, 0x01, 0x02, 20, 0]);
        central.extend(&common);
        central.extend(u16le(name.len()));
        central.extend([0; 12]);
        central.extend(u32le(offset));
        central.extend(name.as_bytes());
    }
    let central_offset = out.len();
    out.extend(&central);
    out.extend([0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]);
    out.extend(u16le(entries.len()));
    out.extend(u16le(entries.len()));
    out.extend(u32le(central.len()));
    out.extend(u32le(central_offset));
    out.extend([0, 0]);
    out
}

/// Adds an unused serializable enum `Color` to the first module.
fn with_color_enum(p: &mut lf_archive::proto::daml_lf_2::Package) {
    use lf_archive::proto::daml_lf_2::{def_data_type, DefDataType, InternedDottedName};
    let mut intern = |s: &str| {
        p.interned_strings.push(s.to_string());
        i32::try_from(p.interned_strings.len() - 1).expect("index")
    };
    let name = intern("Color");
    let cons = vec![intern("Red"), intern("Blue")];
    p.interned_dotted_names.push(InternedDottedName {
        segments_interned_str: vec![name],
    });
    let dname = i32::try_from(p.interned_dotted_names.len() - 1).expect("index");
    p.modules[0].data_types.push(DefDataType {
        name_interned_dname: dname,
        serializable: true,
        data_cons: Some(def_data_type::DataCons::Enum(
            def_data_type::EnumConstructors {
                constructors_interned_str: cons,
            },
        )),
        ..Default::default()
    });
}

/// Canton vets a package only when every lineage it touches stays upgrade-compatible (`PackageUpgradeValidator`):
/// after a v1 of `upg` with an extra enum, the fixture v2 (without it) is `NOT_VALID_UPGRADE_PACKAGE` on both upload
/// paths, the fixture v1 is then a second `upg 1.0.0` (`KNOWN_PACKAGE_VERSION`), and the fixture v2 upgrades the
/// fixture v1 whichever comes first.
#[test]
fn an_upload_that_breaks_a_vetted_lineage_is_refused() {
    let svc = ExecutionService::new();
    let v1_with_color = edited_dar("tests/oracle/upgrade/upg-1.0.0.dar", with_color_enum);
    let (status, body) = call(&svc, "POST", "/v2/dars", v1_with_color);
    assert_eq!(status, 200, "{body}");
    let before = call(&svc, "GET", "/v2/packages", vec![]).1;
    let (status, body) = upload(&svc, "tests/oracle/upgrade/upg-2.0.0.dar");
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "NOT_VALID_UPGRADE_PACKAGE", "{body}");
    let cause = body["cause"].as_str().unwrap_or_default();
    assert!(
        cause.starts_with("Upgrade checks indicate that ")
            && cause.contains(" (upg v2.0.0) cannot be an upgrade of ")
            && cause.ends_with(" (upg v1.0.0). Reason: Data type Color appears in package that is being upgraded, but does not appear in the upgrading package."),
        "{body}"
    );
    assert_eq!(call(&svc, "GET", "/v2/packages", vec![]).1, before);

    // the admin (gRPC) upload refuses it the same way when it vets
    let v2 = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/upgrade/upg-2.0.0.dar"),
    )
    .expect("dar");
    let item = ledger_json_api::v2_packages::UploadDarItem {
        bytes: &v2,
        description: None,
        expected_main_package_id: None,
    };
    let refused = ledger_json_api::v2_packages::admin_upload_dars(&svc, &[item], true, None, false);
    assert!(
        matches!(&refused, Err((3, m)) if m.starts_with("NOT_VALID_UPGRADE_PACKAGE(8,00000000): Upgrade checks")),
        "{refused:?}"
    );

    let (status, body) = upload(&svc, "tests/oracle/upgrade/upg-1.0.0.dar");
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "KNOWN_PACKAGE_VERSION", "{body}");

    let svc = ExecutionService::new();
    assert_eq!(upload(&svc, "tests/oracle/upgrade/upg-2.0.0.dar").0, 200);
    let (status, body) = upload(&svc, "tests/oracle/upgrade/upg-1.0.0.dar");
    assert_eq!(status, 200, "{body}");
}

/// R-5: `POST /v2/dars/validate` (and gRPC `PackageService/ValidateDar` via `admin_validate_dar`) run the same
/// `check_upgrades` validation as `POST /v2/dars` without mutating participant package state.
#[test]
fn r5_validate_dar_rejects_incompatible_upgrade_and_accepts_compatible() {
    use ledger_json_api::{dispatch_request, HttpRequest};
    use std::collections::HashMap;

    let svc = ExecutionService::new();
    let v1_with_color = edited_dar("tests/oracle/upgrade/upg-1.0.0.dar", with_color_enum);
    let (status, body) = call(&svc, "POST", "/v2/dars", v1_with_color);
    assert_eq!(status, 200, "{body}");

    let v2 = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/upgrade/upg-2.0.0.dar"),
    )
    .expect("upg-2.0.0.dar");

    let validate_raw = |s: &ExecutionService, bytes: Vec<u8>| {
        dispatch_request(
            s,
            &HttpRequest {
                method: "POST".into(),
                path: "/v2/dars/validate".into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: bytes,
            },
        )
    };

    let bad = validate_raw(&svc, v2.clone());
    let bad_json: serde_json::Value =
        serde_json::from_slice(&bad.body).unwrap_or(serde_json::Value::Null);
    assert_eq!(
        bad.status, 400,
        "validate must reject upgrade breaking Color lineage: {bad_json}"
    );
    assert_eq!(bad_json["code"], "NOT_VALID_UPGRADE_PACKAGE", "{bad_json}");

    let admin_bad = ledger_json_api::v2_packages::admin_validate_dar(&svc, &v2, None);
    assert!(
        matches!(&admin_bad, Err((3, m)) if m.starts_with("NOT_VALID_UPGRADE_PACKAGE(8,00000000): ")),
        "admin validate must reject upgrade breaking Color lineage: {admin_bad:?}"
    );

    // Positive control: on a clean v1 lineage, compatible upg-2.0.0.dar validates with 200 + empty body.
    let ok_svc = ExecutionService::new();
    let (status, body) = upload(&ok_svc, "tests/oracle/upgrade/upg-1.0.0.dar");
    assert_eq!(status, 200, "{body}");
    let ok = validate_raw(&ok_svc, v2.clone());
    assert_eq!(ok.status, 200, "{}", String::from_utf8_lossy(&ok.body));
    assert!(ok.body.is_empty(), "validate must return empty body");
    assert!(ledger_json_api::v2_packages::admin_validate_dar(&ok_svc, &v2, None).is_ok());
}
