//! AT-L03: Numeric arithmetic never passes through a binary floating-point value.
//!
//! [CANTON-NOTE: INVARIANT] Daml `Numeric` is a decimal with up to 38 digits; an `f64` has about 15.9, so any
//! float on the arithmetic path would round silently. The differential (S-LF-005) proves equal answers on
//! 21,604 vectors; this scan proves the stronger statement for the sources: no `f32`/`f64` appears in
//! `lf-eval`'s source at all, so no such path can exist.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::path::Path;

fn scan(dir: &Path, hits: &mut Vec<String>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            scan(&p, hits);
        } else if p.extension().is_some_and(|x| x == "rs") {
            for (i, l) in std::fs::read_to_string(&p).unwrap().lines().enumerate() {
                let code = l.split("//").next().unwrap_or("");
                if code.contains("f64") || code.contains("f32") {
                    hits.push(format!("{}:{}: {}", p.display(), i + 1, l.trim()));
                }
            }
        }
    }
}

#[test]
fn lf_eval_sources_have_no_floating_point_type() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    scan(&src, &mut hits);
    assert!(
        hits.is_empty(),
        "floating point in lf-eval:\n{}",
        hits.join("\n")
    );
}

/// The scan itself must be able to fail: a line with a float type is found.
#[test]
fn the_scan_finds_a_float_when_there_is_one() {
    let dir = tempfile_dir();
    std::fs::write(dir.join("x.rs"), "fn f(x: f64) {}\n").unwrap();
    let mut hits = Vec::new();
    scan(&dir, &mut hits);
    assert_eq!(hits.len(), 1);
}

fn tempfile_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("numeric-no-float-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
