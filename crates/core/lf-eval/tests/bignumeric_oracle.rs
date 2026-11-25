#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_eval::{render, Engine, EvalError, Value, World};
use std::path::PathBuf;

fn oracle_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/oracle/lf-bignumeric-eval")
}

#[test]
fn u10_bignumeric_dev_matches_canton_jvm_oracle() {
    let dir = oracle_dir();
    let dar_path = dir.join("lf-bignumeric-eval.dar");
    let jvm_tsv = std::fs::read_to_string(dir.join("jvm.tsv")).expect("read jvm.tsv");
    let rows: Vec<&str> = jvm_tsv.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(rows.len(), 70, "expected 70 BigNumeric cases in jvm.tsv");

    // Default World::open MUST fail closed on 2.dev BigNumeric DARs.
    match World::open(&dar_path) {
        Err(EvalError::Archive(msg)) => {
            assert!(msg.contains("dev"), "unexpected archive error: {msg}");
        }
        Err(other) => panic!("expected Archive error for 2.dev, got {other:?}"),
        Ok(_) => panic!("expected World::open to reject 2.dev"),
    }

    let world = World::open_allow_dev(&dar_path).expect("open_allow_dev lf-bignumeric-eval.dar");
    for line in rows {
        let mut parts = line.splitn(3, '\t');
        let cid = parts.next().unwrap();
        let status = parts.next().unwrap();
        let expected = parts.next().unwrap();
        match status {
            "OK" => {
                let val = world
                    .eval("Main", cid, &[])
                    .unwrap_or_else(|err| panic!("eval failed for {cid}: {err:?}"));
                let rendered =
                    render(&val).unwrap_or_else(|err| panic!("render failed for {cid}: {err:?}"));
                assert_eq!(rendered, expected, "mismatch for case {cid}");
            }
            "ERR" => {
                assert_eq!(
                    expected, "com.digitalasset.daml.lf.speedy.SError$UnhandledException",
                    "unexpected JVM error kind in {cid}: {expected}"
                );
                let err = world
                    .eval("Main", cid, &[])
                    .expect_err(&format!("expected ArithmeticError for {cid}"));
                let msg = err.to_string();
                assert!(
                    matches!(
                        err,
                        EvalError::UnhandledException { .. } | EvalError::Thrown(_)
                    ) && msg.contains("DA.Exception.ArithmeticError:ArithmeticError"),
                    "expected ArithmeticError exception for {cid}, got {err:?} ({msg})"
                );
            }
            other => panic!("unexpected status {other} in {cid}"),
        }
    }
}

#[test]
fn u10_bignumeric_arithmetic_error_is_catchable_in_engine() {
    let dir = oracle_dir();
    let dar_path = dir.join("lf-bignumeric-eval.dar");
    let world = World::open_allow_dev(&dar_path).expect("open_allow_dev");
    let pkg_id = world.main_package_id().to_string();
    let mut engine = Engine::new(&world);

    let cid1 = engine
        .create_as(
            &["alice"],
            &pkg_id,
            "Main:BnCatchProbe",
            &Value::Record {
                tycon: Some("Main:BnCatchProbe".to_string()),
                fields: vec![("owner".to_string(), Value::Party("alice".to_string()))],
            },
        )
        .expect("create BnCatchProbe #1");

    let div_res = engine
        .exercise_as(&["alice"], &cid1, "TryDivZero", &Value::Unit)
        .expect("TryDivZero should catch ArithmeticError");
    match div_res {
        Value::Text(msg) => assert!(
            msg.starts_with("caught:") && !msg.trim().is_empty(),
            "unexpected caught ArithmeticError message: {msg:?}"
        ),
        other => panic!("expected Text from TryDivZero, got {other:?}"),
    }

    let cid2 = engine
        .create_as(
            &["alice"],
            &pkg_id,
            "Main:BnCatchProbe",
            &Value::Record {
                tycon: Some("Main:BnCatchProbe".to_string()),
                fields: vec![("owner".to_string(), Value::Party("alice".to_string()))],
            },
        )
        .expect("create BnCatchProbe #2");

    let ovf_res = engine
        .exercise_as(&["alice"], &cid2, "TryOverflow", &Value::Unit)
        .expect("TryOverflow should catch ArithmeticError");
    match ovf_res {
        Value::Text(msg) => assert!(
            msg.starts_with("caught:") && !msg.trim().is_empty(),
            "unexpected caught overflow ArithmeticError message: {msg:?}"
        ),
        other => panic!("expected Text from TryOverflow, got {other:?}"),
    }
}
