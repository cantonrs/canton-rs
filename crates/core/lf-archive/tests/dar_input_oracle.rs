//! Replays the DAR-input corpus (S-GUARD-004, AT-A01..A05/A07) against the Rust loader and
//! compares the accept/reject decision and the added package set with the recorded JVM
//! (Canton 3.7.2 `POST /v2/dars`) answers in `tests/oracle/dar-input/expected.jsonl`.
//!
//! [CANTON-NOTE: ORACLE] The expected file is a recording of the real JVM upload endpoint, the
//! "official reader" of DAR files. The Rust loader must not be more lenient than the JVM; where it is
//! deliberately stricter, the case id is listed in `STRICTER_THAN_JVM` with the reason, so a
//! silent change in either direction fails this test.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use lf_archive::{check_dar_for_upload, parse_loaded_dar};
use serde_json::Value;

/// Cases where the Rust loader intentionally rejects what the JVM accepts (security hardening).
/// Each entry: (case id, reason). Anything not listed must agree with the JVM exactly.
const STRICTER_THAN_JVM: &[(&str, &str)] = &[
    (
        "a02-dotdot-extra",
        "the JVM reads entries in memory and never writes them out, so `../evil.txt` is harmless there; the Rust loader rejects it so a later extractor can never be tricked (zip-slip)",
    ),
    (
        "a02-dotdot-inner",
        "same as a02-dotdot-extra: `a/../b.txt` has a parent component",
    ),
    (
        "a02-absolute",
        "same as a02-dotdot-extra: an absolute entry name `/abs/evil.txt`",
    ),
    (
        "a01-big-entry",
        "a 300 MiB entry; the JVM accepts it, the Rust loader keeps a 256 MiB per-entry ceiling (MAX_ENTRY_BYTES) against decompression bombs",
    ),
];

/// Cases where the Rust loader accepts what the JVM rejects (`lf_archive::typecheck`, U-11, completed in S-LF-016). The six
/// validation defects of S-LF-009 moved out of this list as the check grew. The list is empty; a new tampered case the check
/// cannot see goes here with the JVM's reason, and the test requires Rust to STILL accept it so the entry is removed once the
/// check covers it.
const LENIENT_THAN_JVM: &[(&str, &str)] = &[];

fn corpus_dir() -> PathBuf {
    if let Ok(d) = std::env::var("DAR_INPUT_DIR") {
        return PathBuf::from(d);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/dar-input")
}

#[test]
fn dar_input_corpus_matches_jvm_upload() {
    let dir = corpus_dir();
    let text = std::fs::read_to_string(dir.join("expected.jsonl"))
        .unwrap_or_else(|e| panic!("expected.jsonl missing in {}: {e}", dir.display()));
    let mut registry: BTreeSet<String> = BTreeSet::new();
    let mut cases: Vec<Value> = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: Value = serde_json::from_str(line).expect("expected.jsonl line is JSON");
        if v["id"] == "initial" {
            for p in v["packages"].as_array().expect("initial.packages") {
                registry.insert(p.as_str().unwrap().to_string());
            }
        } else {
            cases.push(v);
        }
    }
    assert!(cases.len() >= 33, "corpus shrank: {} cases", cases.len());

    let stricter: BTreeMap<&str, &str> = STRICTER_THAN_JVM.iter().cloned().collect();
    let lenient: BTreeMap<&str, &str> = LENIENT_THAN_JVM.iter().cloned().collect();
    let mut mismatches: Vec<String> = Vec::new();
    for c in &cases {
        let id = c["id"].as_str().unwrap();
        let jvm_ok = c["status"].as_u64() == Some(200);
        let jvm_added: BTreeSet<String> = c["added"]
            .as_array()
            .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
            .unwrap_or_default();
        let bytes = std::fs::read(dir.join("dars").join(format!("{id}.dar")))
            .unwrap_or_else(|e| panic!("{id}: DAR file missing: {e}"));
        // [CANTON-NOTE: ORACLE] accept = archive loads AND every package dependency is inside the DAR itself.
        // The JVM rejected `a07-missing-dependency` although `a02-base` had already put that package on the
        // ledger, so previously uploaded packages do not satisfy a DAR's dependencies: `known` stays empty.
        // [CANTON-NOTE: LIMITATION] One rejecting case backs this rule; more removed-dependency variants
        // (a package missing from a different DAR, several missing) are not recorded.
        let rust = parse_loaded_dar(std::io::Cursor::new(&bytes))
            .map_err(|e| e.to_string())
            .and_then(|l| {
                let known = std::collections::HashSet::new();
                check_dar_for_upload(&l, &known)
                    .map(|_| l.archive)
                    .map_err(|e| e.to_string())
            });
        let rust_ok = rust.is_ok();
        // AT-L04: BigNumeric exists only in LF 2.dev; the Rust loader must refuse it because the Daml-LF minor
        // version is unsupported, not for some other reason that would hide a change in version handling.
        if id.starts_with("l04-") {
            let why = rust
                .as_ref()
                .expect_err("an LF 2.dev package must be refused")
                .clone();
            assert!(
                why.contains("minor"),
                "{id}: refused for another reason: {why}"
            );
        }
        if stricter.contains_key(id) {
            if rust_ok || !jvm_ok {
                mismatches.push(format!(
                    "{id}: listed as stricter-than-JVM but jvm_ok={jvm_ok} rust_ok={rust_ok}"
                ));
            }
            continue;
        }
        if lenient.contains_key(id) {
            if !rust_ok || jvm_ok {
                mismatches.push(format!(
                    "{id}: listed as lenient-than-JVM (no type checker) but jvm_ok={jvm_ok} rust_ok={rust_ok}; \
                     remove it from LENIENT_THAN_JVM if Rust now rejects it"
                ));
            }
            continue;
        }
        if rust_ok != jvm_ok {
            let why = match &rust {
                Ok(_) => "accepted".to_string(),
                Err(e) => format!("rejected: {e}"),
            };
            mismatches.push(format!(
                "{id}: JVM status {} {} but Rust {why}",
                c["status"], c["code"]
            ));
            continue;
        }
        if let Ok(a) = rust {
            let ids: BTreeSet<String> = a.dalfs.iter().map(|d| d.package_id.clone()).collect();
            let added: BTreeSet<String> = ids.difference(&registry).cloned().collect();
            if added != jvm_added {
                mismatches.push(format!(
                    "{id}: added packages differ: JVM {} Rust {}",
                    jvm_added.len(),
                    added.len()
                ));
            }
            registry.extend(ids);
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} cases differ from the JVM:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
}
