//! S-LF-002: the edge cases the JVM 3.7.2 differential (`scripts/verify-lf-diff.sh`) found in builtins
//! that `lf-eval` implements. The expected values are the JVM answers recorded in
//! `tests/oracle/lf-diff/` (not derived from this implementation); these tests keep them checked without Docker.
//! `EQUAL_LIST` needs the machine (it applies a function) and is covered by the differential only.

use crate::{exec_builtin, EvalError, Value, ADD_NUMERIC, MOD_INT64, SUB_NUMERIC, TEXT_TO_PARTY};

const MAX_NUMERIC10: i128 = 99_999_999_999_999_999_999_999_999_999_999_999_999; // 38 nines
fn num(coeff: i128) -> Value {
    Value::Numeric { coeff, scale: 10 }
}

#[test]
fn numeric_add_and_sub_stay_within_38_digits() {
    // JVM: 9999999999999999999999999999.9999999999 + 1 raises; the result would need 39 digits.
    let one = num(10_000_000_000);
    assert!(matches!(
        exec_builtin(ADD_NUMERIC, &[num(MAX_NUMERIC10), one.clone()]),
        Err(EvalError::Arithmetic(_))
    ));
    assert!(matches!(
        exec_builtin(SUB_NUMERIC, &[num(-MAX_NUMERIC10), one.clone()]),
        Err(EvalError::Arithmetic(_))
    ));
    // the largest values themselves are fine, and so is staying inside the range
    assert!(exec_builtin(ADD_NUMERIC, &[num(MAX_NUMERIC10), num(0)]).is_ok());
    assert!(exec_builtin(SUB_NUMERIC, &[num(MAX_NUMERIC10), one]).is_ok());
    // JVM: max + (-1) = 9999999999999999999999999998.9999999999
    assert!(matches!(
        exec_builtin(ADD_NUMERIC, &[num(MAX_NUMERIC10), num(-10_000_000_000)]),
        Ok(Value::Numeric { coeff, scale: 10 }) if coeff == MAX_NUMERIC10 - 10_000_000_000
    ));
}

#[test]
fn mod_of_int64_min_by_minus_one_is_zero_but_division_by_zero_is_an_error() {
    // JVM 3.7.2 (Speedy): Int64.min % -1 = 0.
    assert!(matches!(
        exec_builtin(MOD_INT64, &[Value::Int64(i64::MIN), Value::Int64(-1)]),
        Ok(Value::Int64(0))
    ));
    assert!(matches!(
        exec_builtin(MOD_INT64, &[Value::Int64(1), Value::Int64(0)]),
        Err(EvalError::Arithmetic(_))
    ));
    assert!(matches!(
        exec_builtin(MOD_INT64, &[Value::Int64(-10), Value::Int64(3)]),
        Ok(Value::Int64(-1))
    ));
}

#[test]
fn text_to_party_follows_the_party_id_syntax() {
    let parse = |s: &str| exec_builtin(TEXT_TO_PARTY, &[Value::Text(s.to_string())]).unwrap();
    // JVM answers from the differential: accepted
    for ok in ["alice", "Alice::1220", "a-b_c:d", "a b", &"p".repeat(255)] {
        assert!(matches!(parse(ok), Value::Optional(Some(_))), "{ok:?}");
    }
    // JVM answers: rejected (empty, '#', non-ASCII, longer than 255)
    for bad in ["", "#x", "😂", &"p".repeat(256)] {
        assert!(matches!(parse(bad), Value::Optional(None)), "{bad:?}");
    }
}

fn empty_world() -> crate::World {
    crate::World {
        main_package_id: String::new(),
        packages: std::collections::HashMap::new(),
        val_cache: crate::ValCache::default(),
        ctor_cache: crate::world::CtorCache::default(),
    }
}

/// Speedy `SBContractIdToText`: `None` on ledger (`UpdateMachine`), the id's text off ledger (`PureMachine`).
#[test]
fn contract_id_to_text_is_none_on_ledger_and_the_text_off_ledger() {
    let world = empty_world();
    let to_text = Value::Partial {
        builtin: crate::CONTRACT_ID_TO_TEXT,
        types: Vec::new(),
        args: Vec::new(),
    };
    let cid = Value::ContractId("00abcd".to_string());
    assert_eq!(
        world.apply_closed(&to_text, vec![cid.clone()]).unwrap(),
        Value::Optional(None)
    );
    assert_eq!(
        world.apply_off_ledger(&to_text, vec![cid]).unwrap(),
        Value::Optional(Some(Box::new(Value::Text("00abcd".to_string()))))
    );
}

/// Speedy `SBCodePointsToText` (`Utf8.pack`): a surrogate or a value outside `0..=0x10FFFF` is a crash
/// `invalid code point 0x<hex>.`, never a truncated character.
#[test]
fn code_points_to_text_rejects_what_utf8_pack_rejects() {
    let points = |cps: &[i64]| Value::List(cps.iter().map(|c| Value::Int64(*c)).collect());
    assert_eq!(
        exec_builtin(crate::CODE_POINTS_TO_TEXT, &[points(&[0x41, 0x10FFFF])]).unwrap(),
        Value::Text("A\u{10FFFF}".to_string())
    );
    for (cp, hex) in [
        (0x1_0000_0041, "0x100000041"),
        (0xD800, "0xd800"),
        (0xDFFF, "0xdfff"),
        (0x11_0000, "0x110000"),
        (-1, "0xffffffffffffffff"),
    ] {
        let err = exec_builtin(crate::CODE_POINTS_TO_TEXT, &[points(&[0x41, cp])]).unwrap_err();
        assert!(
            matches!(&err, EvalError::Crash(m) if *m == format!("invalid code point {hex}.")),
            "{cp:#x}: {err:?}"
        );
    }
}

/// A builtin the evaluator does not implement fails where it appears, not when (or if) it is saturated.
#[test]
fn an_unsupported_builtin_fails_when_evaluated() {
    use lf_archive::proto::daml_lf_2::{expr, Expr};
    let mut world = empty_world();
    world.packages.insert("p".to_string(), Default::default());
    let mut machine = crate::Machine {
        world: &world,
        control: crate::Control::Expr(Expr {
            sum: Some(expr::Sum::Builtin(9_999)),
            ..Default::default()
        }),
        env: crate::Env::new(),
        type_env: Vec::new(),
        package_id: "p".to_string(),
        kont: Vec::new(),
        steps: 0,
        host: None,
        ledger: crate::Ledger::On,
    };
    let result = machine.run_closed();
    assert!(
        matches!(result, Err(EvalError::Unsupported(_))),
        "{result:?}"
    );
}
