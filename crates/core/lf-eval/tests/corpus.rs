use std::path::PathBuf;

use lf_eval::{parse_arg, render, World};

#[test]
fn each_dalf_decodes() {
    let file = std::fs::File::open(dar_path()).unwrap();
    let mut zip = zip::ZipArchive::new(file).unwrap();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).unwrap();
        let name = entry.name().to_string();
        if !name.ends_with(".dalf") {
            continue;
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes).unwrap();
        lf_archive::load_dalf(&bytes).unwrap_or_else(|err| panic!("{name}: {err}"));
    }
}

fn dar_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/lf-corpus/lf-corpus.dar")
}

#[test]
fn corpus_matches_daml_script_output() {
    let world = World::open(&dar_path()).expect("corpus dar");
    let cases = include_str!("../../../../tests/oracle/lf-corpus/cases.tsv");
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
            let rendered = render(&result.expect(script)).unwrap();
            assert_eq!(rendered, expect, "{script}");
        }
    }
}
