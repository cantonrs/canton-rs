#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_eval::{render, EvalError, World};
use std::path::PathBuf;

fn oracle_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/oracle/any-typerep")
}

#[test]
fn u1_any_typerep_dev_matches_canton_jvm_oracle() {
    let dir = oracle_dir();
    let dar_path = dir.join("any-typerep.dar");
    let jvm_tsv = std::fs::read_to_string(dir.join("jvm.tsv")).expect("read jvm.tsv");
    let rows: Vec<&str> = jvm_tsv.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(rows.len(), 66, "expected all 66 U-1 cases in jvm.tsv");

    // Default World::open MUST fail closed on 2.dev DARs.
    match World::open(&dar_path) {
        Err(EvalError::Archive(msg)) => {
            assert!(msg.contains("dev"), "unexpected archive error: {msg}");
        }
        Err(other) => panic!("expected Archive error for 2.dev, got {other:?}"),
        Ok(_) => panic!("expected World::open to reject 2.dev"),
    }

    let world = World::open_allow_dev(&dar_path).expect("open_allow_dev any-typerep.dar");
    for line in rows {
        let mut parts = line.splitn(3, '\t');
        let cid = parts.next().unwrap();
        let status = parts.next().unwrap();
        let expected = parts.next().unwrap();
        assert_eq!(status, "OK", "unexpected JVM error in {cid}: {expected}");
        let val = world
            .eval("Main", cid, &[])
            .unwrap_or_else(|err| panic!("eval failed for {cid}: {err:?}"));
        let rendered =
            render(&val).unwrap_or_else(|err| panic!("render failed for {cid}: {err:?}"));
        assert_eq!(rendered, expected, "mismatch for case {cid}");
    }
}

#[test]
fn u1_lf21_con_args_and_typerep_match_canton_jvm_oracle() {
    let dir = oracle_dir();
    let dar_path = dir.join("any-lf21.dar");
    let jvm_tsv = std::fs::read_to_string(dir.join("jvm-lf21.tsv")).expect("read jvm-lf21.tsv");
    let rows: Vec<&str> = jvm_tsv.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(rows.len(), 3, "expected 3 LF 2.1 cases in jvm-lf21.tsv");

    let world = World::open(&dar_path).expect("open any-lf21.dar");
    for line in rows {
        let mut parts = line.splitn(3, '\t');
        let cid = parts.next().unwrap();
        let status = parts.next().unwrap();
        let expected = parts.next().unwrap();
        assert_eq!(status, "OK");
        let val = world
            .eval("Main", cid, &[])
            .unwrap_or_else(|err| panic!("LF 2.1 eval failed for {cid}: {err:?}"));
        let rendered = render(&val).unwrap();
        assert_eq!(rendered, expected, "LF 2.1 mismatch for case {cid}");
    }
}
