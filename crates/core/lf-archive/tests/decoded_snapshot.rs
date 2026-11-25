//! S-PROTO-002: what `lf-archive` decodes from real packages, frozen as a snapshot.
//!
//! The snapshot was recorded with the hand-written prost module that `lf-archive` used before it switched to the
//! types generated from the official 3.7.2 protos (`canton-proto`). The same decoder code must give the same
//! answer on the same 226 real packages (the sample DAR and four Splice DARs) after the switch. Each row holds
//! the package id, LF version, package name and version, module count and a SHA-256 over the full debug
//! rendering of the decoded module surfaces, so any difference in what is decoded changes the row.
//! Run with `UPDATE_SNAPSHOT=1` to rewrite the file (review the diff before committing it).
//!
//! Recorded history: the file was first written with the hand-written module (226 rows). After the switch to
//! the generated types 218 rows were identical (all 209 LF 2.1 packages and 9 of the LF 2.3 packages) and 8 rows
//! changed in `surface_sha256` only (4 in splice-dso-governance, 3 in splice-wallet, 1 in splice-amulet, all LF 2.3).
//! Dumping the surfaces of the old and new decoder for the three Splice packages showed that every difference is
//! a `bytes_len` of a choice update expression going from 0 to 4 or 5: the hand-written `Expr` dropped field 44
//! (`interned_expr`), the official one reads it. Package ids, versions, module counts and everything else are
//! unchanged. A later change (S-TX-001 part 2) made the surface walk follow `Expr.interned_expr`, which corrected the
//! signatories, observers and controllers of the same 8 LF 2.3 rows (the rows changed again, nothing else did).
//! A subsequent change (S-SPL-032) taught `Sum::Tapp` to fold curried LF 2.3 `Builtin`/`TypeCon` applications (`ContractId`,
//! `Optional`, `List`, `Numeric`, `GenMap`) instead of leaving `SurfaceType::Other("... Any ...")`, updating only those LF 2.3 rows'
//! `surface_sha256` (all LF 2.1 rows, ids, versions, and module counts remained unchanged).
//! The file holds the latest values.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::{fs, io::Read, path::PathBuf};

use sha2::{Digest, Sha256};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf()
}

fn dars() -> Vec<PathBuf> {
    let mut v = vec![root().join("contracts/target/sample-contract.dar")];
    let mut splice: Vec<PathBuf> = fs::read_dir(root().join("tests/oracle/splice-dars"))
        .expect("splice-dars")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "dar"))
        .collect();
    splice.sort();
    v.extend(splice);
    v
}

fn snapshot() -> String {
    let mut rows = vec![
        "dar\tentry\tpackage_id\tlf_version\tname\tversion\tmodules\tsurface_sha256".to_string(),
    ];
    for dar in dars() {
        let mut zip = zip::ZipArchive::new(fs::File::open(&dar).expect("open dar")).expect("zip");
        let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
        for i in 0..zip.len() {
            let mut f = zip.by_index(i).unwrap();
            if f.name().ends_with(".dalf") {
                let mut b = Vec::new();
                f.read_to_end(&mut b).unwrap();
                entries.push((f.name().to_string(), b));
            }
        }
        entries.sort();
        for (name, bytes) in entries {
            let d = lf_archive::decode_dalf(&bytes)
                .unwrap_or_else(|e| panic!("{} :: {name}: {e}", dar.display()));
            let digest = hex::encode(Sha256::digest(
                format!("{:?}|{:?}", d.modules, d.module_surfaces).as_bytes(),
            ));
            rows.push(format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                dar.file_name().unwrap().to_string_lossy(),
                name,
                d.package_id,
                d.lf_version,
                d.package_name.unwrap_or_default(),
                d.package_version.unwrap_or_default(),
                d.modules.len(),
                digest
            ));
        }
    }
    rows.join("\n") + "\n"
}

#[test]
fn decoded_packages_match_the_recorded_snapshot() {
    let path = root().join("crates/core/lf-archive/tests/fixtures/decoded-packages.tsv");
    let fresh = snapshot();
    if std::env::var("UPDATE_SNAPSHOT").is_ok() {
        fs::write(&path, &fresh).unwrap();
        return;
    }
    let recorded = fs::read_to_string(&path).expect("snapshot file");
    assert!(
        recorded.lines().count() > 200,
        "the snapshot must cover the real packages"
    );
    for (i, (a, b)) in recorded.lines().zip(fresh.lines()).enumerate() {
        assert_eq!(a, b, "snapshot row {i} differs");
    }
    assert_eq!(recorded.lines().count(), fresh.lines().count(), "row count");
}
