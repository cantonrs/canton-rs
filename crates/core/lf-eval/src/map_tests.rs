//! S-TX-001 (part 3): `GenMap`/`TextMap` builtins and the structural value order they rely on.
//!
//! The behaviours are Daml's (`DA.Map`, `DA.TextMap`): entries sorted by key, insertion replaces an existing key,
//! lookup returns an `Optional`, `TEXTMAP_TO_LIST` yields `<key, value>` structs. The `FeaturedAppRight` marker choice
//! of the Splice amulet DAR groups beneficiaries through a `GenMap Party Decimal`; its scenarios in
//! `tests/oracle/splice-diff/amulet` (JVM answers) cover the maps end to end.
use crate::{
    compare_values, exec_builtin, values_equal, Value, GENMAP_DELETE, GENMAP_EMPTY, GENMAP_INSERT,
    GENMAP_KEYS, GENMAP_LOOKUP, GENMAP_SIZE, GENMAP_VALUES, TEXTMAP_INSERT, TEXTMAP_TO_LIST,
};
use std::cmp::Ordering;

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn some(v: Value) -> Value {
    Value::Optional(Some(Box::new(v)))
}

fn insert(map: Value, key: Value, value: i64) -> Value {
    exec_builtin(GENMAP_INSERT, &[key, Value::Int64(value), map]).unwrap()
}

#[test]
fn genmap_keeps_entries_sorted_and_replaces_equal_keys() {
    let mut m = exec_builtin(GENMAP_EMPTY, &[]).unwrap();
    for (k, v) in [("b", 2), ("a", 1), ("c", 3), ("a", 10)] {
        m = insert(m, text(k), v);
    }
    assert_eq!(
        exec_builtin(GENMAP_KEYS, &[m.clone()]).unwrap(),
        Value::List(vec![text("a"), text("b"), text("c")].into())
    );
    assert_eq!(
        exec_builtin(GENMAP_VALUES, &[m.clone()]).unwrap(),
        Value::List(vec![Value::Int64(10), Value::Int64(2), Value::Int64(3)].into())
    );
    assert_eq!(
        exec_builtin(GENMAP_SIZE, std::slice::from_ref(&m)).unwrap(),
        Value::Int64(3)
    );
    assert_eq!(
        exec_builtin(GENMAP_LOOKUP, &[text("b"), m.clone()]).unwrap(),
        some(Value::Int64(2))
    );
    assert_eq!(
        exec_builtin(GENMAP_LOOKUP, &[text("z"), m.clone()]).unwrap(),
        Value::Optional(None)
    );
    let m = exec_builtin(GENMAP_DELETE, &[text("b"), m]).unwrap();
    assert_eq!(
        exec_builtin(GENMAP_SIZE, std::slice::from_ref(&m)).unwrap(),
        Value::Int64(2)
    );
    // deleting a missing key changes nothing
    assert_eq!(
        exec_builtin(GENMAP_DELETE, &[text("zz"), m.clone()]).unwrap(),
        m
    );
}

#[test]
fn textmap_insert_requires_text_keys_and_lists_structs() {
    let empty = exec_builtin(GENMAP_EMPTY, &[]).unwrap();
    assert!(exec_builtin(
        TEXTMAP_INSERT,
        &[Value::Int64(1), Value::Int64(1), empty.clone()]
    )
    .is_err());
    let m = exec_builtin(TEXTMAP_INSERT, &[text("k"), Value::Int64(7), empty]).unwrap();
    assert_eq!(
        exec_builtin(TEXTMAP_TO_LIST, &[m]).unwrap(),
        Value::List(
            vec![Value::Struct(vec![
                ("key".to_string(), text("k")),
                ("value".to_string(), Value::Int64(7)),
            ])]
            .into(),
        )
    );
}

#[test]
fn value_order_is_lexicographic_for_lists_and_none_first_for_optionals() {
    let list = |xs: &[i64]| Value::List(xs.iter().map(|n| Value::Int64(*n)).collect());
    assert_eq!(
        compare_values(&list(&[1, 2]), &list(&[1, 3])).unwrap(),
        Ordering::Less
    );
    assert_eq!(
        compare_values(&list(&[1, 2]), &list(&[1, 2, 0])).unwrap(),
        Ordering::Less
    );
    assert_eq!(
        compare_values(&list(&[]), &list(&[])).unwrap(),
        Ordering::Equal
    );
    assert_eq!(
        compare_values(&Value::Optional(None), &some(Value::Int64(0))).unwrap(),
        Ordering::Less
    );
    // text order is by code point (UTF-8 byte order agrees)
    assert_eq!(
        compare_values(&text("Z"), &text("a")).unwrap(),
        Ordering::Less
    );
    assert_eq!(
        compare_values(&text("a"), &text("😂")).unwrap(),
        Ordering::Less
    );
}

#[test]
fn variants_of_different_constructors_are_unequal_but_not_orderable() {
    let v = |c: &str| Value::Variant {
        tycon: None,
        constructor: c.to_string(),
        rank: crate::CtorRank::default(),
        value: Box::new(Value::Unit),
    };
    assert!(!values_equal(&v("A"), &v("B")).unwrap());
    assert!(values_equal(&v("A"), &v("A")).unwrap());
    // the declaration order of constructors is not part of a value: refuse to guess
    assert!(compare_values(&v("A"), &v("B")).is_err());
}

/// Speedy orders different constructors by `constructorRank`, whatever their names (`svalue.Ordering`).
#[test]
fn different_constructors_order_by_the_rank_they_carry() {
    let e = |c: &str, rank: u32| Value::Enum {
        tycon: None,
        constructor: c.to_string(),
        rank: crate::CtorRank::known(rank),
    };
    assert_eq!(
        compare_values(&e("Zed", 0), &e("Alpha", 1)).unwrap(),
        Ordering::Less
    );
    let v = |c: &str, rank: u32, n: i64| Value::Variant {
        tycon: None,
        constructor: c.to_string(),
        rank: crate::CtorRank::known(rank),
        value: Box::new(Value::Int64(n)),
    };
    assert_eq!(
        compare_values(&v("Zed", 0, 9), &v("Alpha", 1, 1)).unwrap(),
        Ordering::Less
    );
    assert_eq!(
        compare_values(&v("Zed", 0, 9), &v("Zed", 0, 1)).unwrap(),
        Ordering::Greater
    );
    assert!(values_equal(&e("Zed", 0), &e("Zed", 0)).unwrap());
}
