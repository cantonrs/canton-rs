//! U-11: the partial type check must never refuse a package the JVM accepts. Every DAR of the repository's oracle corpora
//! that the loader can open (the Splice DARs, the key/disclosure/filter/upgrade/transaction corpora, the e2e fixtures and the
//! sample) must type-check. The tampered DARs of `dar-input` are covered by `dar_input_oracle.rs` against the JVM's answers.
use std::path::{Path, PathBuf};

use lf_archive::{parse_loaded_dar, typecheck::check_packages};

fn dars_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            dars_under(&p, out);
        } else if p.extension().is_some_and(|x| x == "dar") {
            out.push(p);
        }
    }
}

#[test]
fn the_partial_type_check_accepts_every_valid_dar_of_the_corpora() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut dars = Vec::new();
    for d in [
        "tests/oracle",
        "tests/e2e/fixtures",
        "contracts/target",
        "contracts/fixtures/fetch/target",
        "contracts/fixtures/subview/target",
        "contracts/fixtures/keyed/target",
    ] {
        dars_under(&root.join(d), &mut dars);
    }
    dars.retain(|p| !p.components().any(|c| c.as_os_str() == "dar-input"));
    let (mut checked, mut packages) = (0, 0);
    let mut refused = Vec::new();
    for p in &dars {
        let bytes = std::fs::read(p).expect("dar");
        // a DAR the loader itself refuses (hand-made bad inputs of the e2e fixtures) is not this test's business
        let Ok(loaded) = parse_loaded_dar(std::io::Cursor::new(bytes)) else {
            continue;
        };
        checked += 1;
        packages += loaded.packages.len();
        if let Err(e) = check_packages(&loaded.packages) {
            refused.push(format!("{}: {e}", p.display()));
        }
    }
    assert!(
        refused.is_empty(),
        "valid DARs refused:\n{}",
        refused.join("\n")
    );
    assert!(
        checked >= 15 && packages >= 100,
        "the corpus shrank: {checked} DARs, {packages} packages"
    );
}
