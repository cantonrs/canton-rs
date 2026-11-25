//! S-PROTO-001: the generated types against real, tool-made bytes.
//!
//! The DALF files inside the pinned sample DAR (built by the official `damlc`) and the four Splice DARs
//! (built by Splice's toolchain) were not produced by this repository. Decoding them with types generated
//! from the official Canton 3.7.2 `.proto` files and encoding them again must not lose or change anything.
//! prost writes fields in its own order (for example a oneof where the struct declares it), while `damlc`
//! (Haskell) writes `ArchivePayload.daml_lf_2` before `minor`, so byte identity cannot be required for every
//! message. The criterion is therefore: (1) the re-encoded length equals the original length, which a dropped
//! unknown field or a wrong wire type would break, and (2) decoding the re-encoded bytes gives the same message.
//! The outer `Archive` envelope is small and is also required to be byte-identical.
//!
//! What this proves: the generated types and the official schema agree with these real files. It does not
//! prove anything about Daml-LF semantics, only about the wire format of these packages.
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use canton_proto::daml_lf::{archive_payload::Sum as PayloadSum, Archive, ArchivePayload};
use canton_proto::daml_lf_1;
use canton_proto::daml_lf_2::{expr::Sum as ExprSum, Package};
use prost::Message;
use sha2::{Digest, Sha256};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf()
}

fn dar_paths() -> Vec<PathBuf> {
    let root = repo_root();
    let mut v = vec![root.join("contracts/target/sample-contract.dar")];
    let mut splice: Vec<PathBuf> = fs::read_dir(root.join("tests/oracle/splice-dars"))
        .expect("splice-dars dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "dar"))
        .collect();
    splice.sort();
    v.extend(splice);
    for p in &v {
        assert!(p.exists(), "required DAR is missing: {}", p.display());
    }
    v
}

fn dalfs(dar: &Path) -> Vec<(String, Vec<u8>)> {
    let mut zip = zip::ZipArchive::new(fs::File::open(dar).expect("open dar")).expect("zip");
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).expect("entry");
        if f.name().ends_with(".dalf") {
            let mut b = Vec::new();
            f.read_to_end(&mut b).expect("read dalf");
            out.push((f.name().to_string(), b));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Round-trip criterion for a large message: same length and same decoded value. Returns whether the bytes
/// were also byte-identical (informational). Never prints the byte vectors.
fn roundtrip<M: Message + Default + PartialEq>(ctx: &str, original: &[u8]) -> bool {
    let msg = M::decode(original).unwrap_or_else(|e| panic!("{ctx}: decode failed: {e}"));
    let again = msg.encode_to_vec();
    assert!(
        again.len() == original.len(),
        "{ctx}: re-encoded length {} != original length {} (a field was dropped or encoded differently)",
        again.len(),
        original.len()
    );
    let msg2 =
        M::decode(again.as_slice()).unwrap_or_else(|e| panic!("{ctx}: re-decode failed: {e}"));
    assert!(
        msg == msg2,
        "{ctx}: decoded messages differ after re-encoding"
    );
    again == original
}

fn dotted(pkg: &Package, idx: i32) -> String {
    pkg.interned_dotted_names[idx as usize]
        .segments_interned_str
        .iter()
        .map(|s| pkg.interned_strings[*s as usize].as_str())
        .collect::<Vec<_>>()
        .join(".")
}

#[test]
fn every_dalf_in_the_real_dars_round_trips_byte_for_byte() {
    let mut packages = 0usize;
    let mut lf2 = 0usize;
    let mut lf1 = 0usize;
    let (mut identical_payload, mut identical_pkg) = (0usize, 0usize);
    for dar in dar_paths() {
        for (name, bytes) in dalfs(&dar) {
            let ctx = format!("{} :: {}", dar.file_name().unwrap().to_string_lossy(), name);
            let archive =
                Archive::decode(bytes.as_slice()).unwrap_or_else(|e| panic!("{ctx}: Archive: {e}"));
            assert!(
                archive.encode_to_vec() == bytes,
                "{ctx}: Archive envelope is not byte-identical after re-encoding"
            );
            assert!(
                archive.hash == hex::encode(Sha256::digest(&archive.payload)),
                "{ctx}: the envelope hash is not the SHA-256 of the payload"
            );
            let payload = ArchivePayload::decode(archive.payload.as_slice())
                .unwrap_or_else(|e| panic!("{ctx}: ArchivePayload: {e}"));
            identical_payload += usize::from(roundtrip::<ArchivePayload>(&ctx, &archive.payload));
            match payload
                .sum
                .as_ref()
                .unwrap_or_else(|| panic!("{ctx}: payload has no Sum"))
            {
                PayloadSum::DamlLf2(pkg_bytes) => {
                    identical_pkg += usize::from(roundtrip::<Package>(&ctx, pkg_bytes));
                    lf2 += 1;
                }
                PayloadSum::DamlLf1(pkg_bytes) => {
                    identical_pkg += usize::from(roundtrip::<daml_lf_1::Package>(&ctx, pkg_bytes));
                    lf1 += 1;
                }
            }
            packages += 1;
        }
    }
    eprintln!(
        "round-tripped {packages} packages ({lf2} LF2, {lf1} LF1); byte-identical: ArchivePayload {identical_payload}/{packages}, Package {identical_pkg}/{packages}"
    );
    assert!(
        packages >= 40,
        "expected the sample and Splice DARs to hold many packages, got {packages}"
    );
    assert!(lf2 > 0);
}

/// Since S-PROTO-002 `lf-archive` decodes with these same generated types, so this is a consistency check of
/// its decoding logic (package ids, module and metadata resolution) and no longer a comparison with an
/// independently written decoder.
#[test]
fn package_ids_and_module_names_agree_with_lf_archive() {
    let mut compared = 0usize;
    for dar in dar_paths() {
        let info = lf_archive::parse_dar_file(&dar).expect("lf-archive parses the DAR");
        let ours = dalfs(&dar);
        assert_eq!(
            info.dalfs.len(),
            ours.len(),
            "{}: DALF count differs",
            dar.display()
        );
        for (name, bytes) in ours {
            let other = lf_archive::decode_dalf(&bytes)
                .unwrap_or_else(|e| panic!("{name}: lf-archive: {e}"));
            let archive = Archive::decode(bytes.as_slice()).expect("Archive");
            assert_eq!(archive.hash, other.package_id, "{name}: package id differs");
            let payload = ArchivePayload::decode(archive.payload.as_slice()).expect("payload");
            let Some(PayloadSum::DamlLf2(pkg_bytes)) = payload.sum else {
                continue;
            };
            let pkg = Package::decode(pkg_bytes.as_slice()).expect("Package");
            let mut mine: Vec<String> = pkg
                .modules
                .iter()
                .map(|m| dotted(&pkg, m.name_interned_dname))
                .collect();
            let mut theirs = other.modules.clone();
            mine.sort();
            theirs.sort();
            assert_eq!(mine, theirs, "{name}: module names differ");
            if let Some(md) = pkg.metadata.as_ref() {
                let n = pkg.interned_strings[md.name_interned_str as usize].clone();
                let v = pkg.interned_strings[md.version_interned_str as usize].clone();
                assert_eq!(Some(n), other.package_name, "{name}: package name differs");
                assert_eq!(
                    Some(v),
                    other.package_version,
                    "{name}: package version differs"
                );
            }
            compared += 1;
        }
    }
    eprintln!("compared {compared} LF2 packages with lf-archive");
    assert!(compared >= 40);
}

/// The Splice wire measurement (`tests/oracle/splice-dars/lf23-choice-update-wire.tsv`, recorded before the
/// official proto was available) said: LF 2.3 choice bodies use field 44 as an index into the package's
/// interned expressions, LF 2.1 uses the inline field. The official schema must say the same.
#[test]
fn official_schema_confirms_the_recorded_splice_choice_body_wire_measurement() {
    let table = fs::read_to_string(
        repo_root().join("tests/oracle/splice-dars/lf23-choice-update-wire.tsv"),
    )
    .expect("tsv");
    let mut checked = 0;
    for line in table.lines().skip(1) {
        let c: Vec<&str> = line.split('\t').collect();
        let (dar_name, lf, choices_expected) = (c[0], c[2], c[3].parse::<usize>().unwrap());
        let interned_expected: usize = c[6].parse().unwrap(); // sum_none: choices whose inline update is empty
        let inline_expected: usize = c[5].parse().unwrap(); // sum_some
        let target_expected: usize = c[8].parse().unwrap(); // interned targets that decode with a sum

        let (mut choices, mut interned, mut inline, mut targets_ok, mut out_of_range) =
            (0, 0, 0, 0, 0);
        // The recorded table counts the DAR's main package only (dependency packages are not included).
        let dar_path = repo_root().join("tests/oracle/splice-dars").join(dar_name);
        let main_name = lf_archive::parse_dar_file(&dar_path)
            .expect("parse dar")
            .main_dalf_name;
        for (_, bytes) in dalfs(&dar_path)
            .into_iter()
            .filter(|(n, _)| *n == main_name)
        {
            let archive = Archive::decode(bytes.as_slice()).unwrap();
            let payload = ArchivePayload::decode(archive.payload.as_slice()).unwrap();
            let Some(PayloadSum::DamlLf2(pb)) = payload.sum else {
                continue;
            };
            let pkg = Package::decode(pb.as_slice()).unwrap();
            for choice in pkg
                .modules
                .iter()
                .flat_map(|m| m.templates.iter())
                .flat_map(|t| t.choices.iter())
            {
                choices += 1;
                let update = choice
                    .update
                    .as_ref()
                    .expect("every choice has an update expression");
                match &update.sum {
                    Some(ExprSum::InternedExpr(i)) => {
                        interned += 1;
                        match pkg.interned_exprs.get(*i as usize) {
                            Some(e) if e.sum.is_some() => targets_ok += 1,
                            Some(_) => {}
                            None => out_of_range += 1,
                        }
                    }
                    Some(_) => inline += 1,
                    None => panic!("{dar_name}: a choice update has no expression at all"),
                }
            }
        }
        eprintln!("{dar_name} (LF {lf}): choices={choices} interned={interned} inline={inline} targets_ok={targets_ok}");
        assert_eq!(choices, choices_expected, "{dar_name}: choice count");
        assert_eq!(
            interned, interned_expected,
            "{dar_name}: interned-expression choices"
        );
        assert_eq!(inline, inline_expected, "{dar_name}: inline choices");
        assert_eq!(
            targets_ok, target_expected,
            "{dar_name}: interned targets with a sum"
        );
        assert_eq!(
            out_of_range, 0,
            "{dar_name}: interned index outside the package table"
        );
        checked += 1;
    }
    assert_eq!(checked, 4, "all four Splice DARs are covered by the table");
}

#[test]
fn the_module_tree_covers_the_main_packages() {
    // Spot checks that package paths follow the protobuf package names and that the big API surfaces exist.
    let _ = std::any::type_name::<canton_proto::com::daml::ledger::api::v2::SubmitAndWaitRequest>();
    let _ = std::any::type_name::<
        canton_proto::com::digitalasset::canton::sequencer::api::v30::SubscriptionRequest,
    >();
    let _ = std::any::type_name::<canton_proto::daml_lf_2::Package>();
}
