//! S-TX-001 (first part): the evaluator on a Daml-LF 2.3 package.
//!
//! `tests/oracle/lf-corpus/lf-corpus-lf23.dar` is the same Daml source as `lf-corpus.dar`, compiled with
//! `--target=2.3` by the toolchain image. In LF 2.3 the compiler stores shared sub-expressions in
//! `Package.interned_exprs` and refers to other packages through the package's import table
//! (`PackageImportId`). The evaluator must follow both; the expected values are the `daml script` answers
//! recorded in `cases.tsv`, the same as for the LF 2.1 build. The large JVM differential
//! (`scripts/verify-lf-diff.sh`, 11,031 cases) covers the same ground against the live oracle.
use std::{io::Read, path::PathBuf};

use lf_archive::proto::daml_lf_2::package::ImportsSum;
use lf_eval::{parse_arg, render, World};

fn dar_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/lf-corpus/lf-corpus-lf23.dar")
}

#[test]
fn the_corpus_dar_really_uses_interned_expressions_and_imports() {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(dar_path()).unwrap()).unwrap();
    let (mut lf23, mut with_interned, mut with_imports) = (0, 0, 0);
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).unwrap();
        if !entry.name().ends_with(".dalf") {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        let loaded = lf_archive::load_dalf(&bytes).unwrap();
        if loaded.lf_version == "2.3" {
            lf23 += 1;
            with_interned += usize::from(!loaded.package.interned_exprs.is_empty());
            with_imports += usize::from(matches!(
                loaded.package.imports_sum,
                Some(ImportsSum::PackageImports(ref i)) if !i.imported_packages.is_empty()
            ));
        }
    }
    assert!(lf23 > 0, "no LF 2.3 package in the DAR");
    assert!(with_interned > 0, "no package carries interned expressions");
    assert!(with_imports > 0, "no package carries an import table");
}

#[test]
fn lf23_corpus_matches_the_daml_script_answers() {
    let world = World::open(&dar_path()).expect("LF 2.3 corpus dar");
    let cases = include_str!("../../../../tests/oracle/lf-corpus/cases.tsv");
    let mut ran = 0;
    for line in cases.lines().filter(|line| !line.is_empty()) {
        let mut columns = line.split('\t');
        let script = columns.next().unwrap();
        let def = columns.next().unwrap();
        let left = parse_arg(columns.next().unwrap()).unwrap();
        let right = parse_arg(columns.next().unwrap()).unwrap();
        let expect = columns.next().unwrap();
        let result = world.eval("Main", def, &[left, right]);
        if expect == "ERROR" {
            let err = result.expect_err(script);
            assert!(err.to_string().contains("DIV_INT64 1 0"), "{script}: {err}");
        } else {
            let rendered = render(&result.unwrap_or_else(|e| panic!("{script}: {e}"))).unwrap();
            assert_eq!(rendered, expect, "{script}");
        }
        ran += 1;
    }
    assert!(ran >= 12, "all corpus cases ran, got {ran}");
}
