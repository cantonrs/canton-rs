//! U-11 (AT-L01): Differential validation oracle test comparing `lf_archive` full Daml-LF v2
//! package validation against Canton 3.7.2 JVM `Validation.checkPackages` across 41 valid and
//! tampered DARs (plus negative verification on `2.dev` rejection in default mode).
use std::collections::{HashMap, HashSet};
use std::path::Path;

use lf_archive::proto::daml_lf::{archive_payload, ArchivePayload};
use lf_archive::proto::daml_lf_2::Package;
use lf_archive::{
    check_dar_for_upload, dalf_payloads, load_dar_file, load_dar_file_allow_dev,
    typecheck::check_packages_with_versions,
};
use prost::Message;

#[derive(Debug)]
struct ManifestEntry {
    id: String,
    mode: String,
    dar_rel: String,
}

#[derive(Debug)]
enum JvmOutcome {
    Ok,
    Err { kind: String, detail: String },
}

fn load_manifest(dir: &Path) -> Vec<ManifestEntry> {
    let text = std::fs::read_to_string(dir.join("manifest.tsv")).expect("read manifest.tsv");
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = trimmed.split('\t').collect();
        assert_eq!(cols.len(), 3, "bad manifest line: {line}");
        out.push(ManifestEntry {
            id: cols[0].to_string(),
            mode: cols[1].to_string(),
            dar_rel: cols[2].to_string(),
        });
    }
    out
}

fn load_jvm_table(dir: &Path) -> HashMap<String, JvmOutcome> {
    let text = std::fs::read_to_string(dir.join("jvm.tsv")).expect("read jvm.tsv");
    let mut map = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = trimmed.split('\t').collect();
        assert!(cols.len() >= 3, "bad jvm.tsv line: {line}");
        let id = cols[0].to_string();
        let outcome = match cols[1] {
            "OK" => JvmOutcome::Ok,
            "ERR" => JvmOutcome::Err {
                kind: cols[2].to_string(),
                detail: cols.get(3).copied().unwrap_or("").to_string(),
            },
            other => panic!("unexpected status in jvm.tsv: {other}"),
        };
        map.insert(id, outcome);
    }
    map
}

fn run_raw_typecheck(path: &Path) -> Result<(), (String, String)> {
    let bytes = std::fs::read(path).expect("read dar bytes");
    let payloads = dalf_payloads(&bytes).map_err(|e| ("DarError".to_string(), e.to_string()))?;
    let mut packages = HashMap::new();
    let mut versions = HashMap::new();
    for (pkg_id, raw) in payloads {
        let ap = ArchivePayload::decode(raw.as_slice())
            .map_err(|e| ("DecodeError".to_string(), e.to_string()))?;
        let lf_ver = format!("2.{}", ap.minor);
        let Some(archive_payload::Sum::DamlLf2(pkg_bytes)) = ap.sum else {
            return Err(("DecodeError".to_string(), "not DamlLf2".to_string()));
        };
        let pkg = Package::decode(pkg_bytes.as_slice())
            .map_err(|e| ("DecodeError".to_string(), e.to_string()))?;
        packages.insert(pkg_id.clone(), pkg);
        versions.insert(pkg_id, lf_ver);
    }
    check_packages_with_versions(&packages, &versions)
        .map_err(|te| (te.kind.to_string(), te.detail))
}

fn run_rust_upload_check(path: &Path, mode: &str) -> Result<(), (String, String)> {
    let loaded = match mode {
        "default" => load_dar_file(path),
        "dev" => load_dar_file_allow_dev(path),
        other => panic!("unexpected mode {other}"),
    }
    .map_err(|e| ("DecodeOrVersionError".to_string(), e.to_string()))?;

    let known = HashSet::new();
    if let Err(e) = check_dar_for_upload(&loaded, &known) {
        return Err(("DarUploadError".to_string(), e.to_string()));
    }
    Ok(())
}

fn typecheck_kind_compatible(jvm_kind: &str, rust_kind: &str) -> bool {
    match jvm_kind {
        "EExpectedSerializableType" => {
            rust_kind == "ENonSerializableType" || rust_kind == "EExpectedSerializableType"
        }
        other => rust_kind == other,
    }
}

#[test]
fn validation_corpus_matches_canton_jvm_oracle() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/validation");
    let manifest = load_manifest(&dir);
    let jvm = load_jvm_table(&dir);
    assert!(
        manifest.len() >= 40,
        "validation corpus unexpectedly small: {}",
        manifest.len()
    );

    let mut mismatches = Vec::new();
    for entry in &manifest {
        let dar_path = dir.join(&entry.dar_rel);
        let expected = jvm
            .get(&entry.id)
            .unwrap_or_else(|| panic!("missing jvm.tsv row for {}", entry.id));

        // 1) Full upload pipeline (`load_dar_file*` + `check_dar_for_upload`)
        let upload_res = run_rust_upload_check(&dar_path, &entry.mode);
        match (expected, &upload_res) {
            (JvmOutcome::Ok, Ok(())) => {}
            (JvmOutcome::Ok, Err((rk, rmsg))) => {
                mismatches.push(format!(
                    "[upload] {}: JVM=OK but Rust rejected with {rk}: {rmsg}",
                    entry.id
                ));
            }
            (JvmOutcome::Err { kind, detail }, Ok(())) => {
                mismatches.push(format!(
                    "[upload] {}: JVM=ERR({kind}: {detail}) but Rust accepted!",
                    entry.id
                ));
            }
            (JvmOutcome::Err { kind, detail }, Err((rk, rmsg))) => {
                if kind == "DevVersionRejected" {
                    let msg_l = rmsg.to_ascii_lowercase();
                    if !msg_l.contains("dev")
                        && !msg_l.contains("minor")
                        && !msg_l.contains("unsupported")
                    {
                        mismatches.push(format!(
                            "[upload] {}: expected 2.dev rejection, got {rk}: {rmsg}",
                            entry.id
                        ));
                    }
                } else if rk == "DarUploadError"
                    && !typecheck_kind_compatible(
                        kind,
                        rmsg.split_whitespace().nth(2).unwrap_or(rmsg),
                    )
                    && !rmsg.contains(kind)
                {
                    // `check_dar_for_upload` formats `Validation("{kind} in package ...")`
                    let ok_ser = kind == "EExpectedSerializableType"
                        && rmsg.contains("ENonSerializableType");
                    if !ok_ser {
                        mismatches.push(format!(
                            "[upload] {}: JVM=ERR({kind}: {detail}) vs Rust={rk}: {rmsg}",
                            entry.id
                        ));
                    }
                }
            }
        }

        // 2) Direct typechecker check (bypasses surface decoder pre-rejections) for all
        // cases other than default-mode `2.dev` rejection.
        let is_default_dev_gate = matches!(
            expected,
            JvmOutcome::Err { kind, .. } if kind == "DevVersionRejected"
        );
        if !is_default_dev_gate {
            let raw_res = run_raw_typecheck(&dar_path);
            match (expected, raw_res) {
                (JvmOutcome::Ok, Ok(())) => {}
                (JvmOutcome::Ok, Err((rk, rmsg))) => {
                    mismatches.push(format!(
                        "[typecheck] {}: JVM=OK but typecheck failed with {rk}: {rmsg}",
                        entry.id
                    ));
                }
                (JvmOutcome::Err { kind, detail }, Ok(())) => {
                    mismatches.push(format!(
                        "[typecheck] {}: JVM=ERR({kind}: {detail}) but typecheck accepted!",
                        entry.id
                    ));
                }
                (JvmOutcome::Err { kind, detail }, Err((rk, rmsg))) => {
                    if !typecheck_kind_compatible(kind, &rk) {
                        mismatches.push(format!(
                            "[typecheck] {}: JVM=ERR({kind}: {detail}) vs Rust=ERR({rk}: {rmsg})",
                            entry.id
                        ));
                    }
                }
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "Validation oracle mismatches against Canton JVM:\n{}",
        mismatches.join("\n")
    );
}
