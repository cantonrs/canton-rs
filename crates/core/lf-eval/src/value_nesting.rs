//! The nesting limit of values that leave the engine (create arguments, choice arguments and results).

use crate::{EvalError, Value};

/// Daml-LF `Value.MAXIMUM_NESTING`: the root is at depth 0 and a value nested deeper than this is refused.
pub const MAXIMUM_NESTING: usize = 100;

/// Refuses a value nested deeper than [`MAXIMUM_NESTING`], as Speedy does when it turns a value into a transaction
/// value (`SValue.toValue`: `ValueNesting(100)`). Walks with its own stack, so a deep value cannot overflow the Rust
/// stack.
pub(crate) fn check_nesting(value: &Value) -> Result<(), EvalError> {
    let mut stack = vec![(value, 0usize)];
    while let Some((value, depth)) = stack.pop() {
        if depth > MAXIMUM_NESTING {
            return Err(EvalError::ValueNesting(MAXIMUM_NESTING));
        }
        let child = depth + 1;
        match value {
            Value::List(items) => stack.extend(items.iter().map(|v| (v, child))),
            Value::Optional(Some(inner)) | Value::Variant { value: inner, .. } => {
                stack.push((inner, child));
            }
            Value::Record { fields, .. } | Value::Struct(fields) => {
                stack.extend(fields.iter().map(|(_, v)| (v, child)));
            }
            Value::Map(entries) => {
                stack.extend(entries.iter().flat_map(|(k, v)| [(k, child), (v, child)]));
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compare_values, values_equal};

    fn nested(depth: usize, leaf: i64) -> Value {
        let mut value = Value::Int64(leaf);
        for _ in 0..depth {
            value = Value::Optional(Some(Box::new(value)));
        }
        value
    }

    /// Takes a deep value apart one level at a time, so that the test itself does not overflow when it drops it.
    fn dismantle(mut value: Value) {
        while let Value::Optional(Some(inner)) = value {
            value = *inner;
        }
    }

    #[test]
    fn a_value_nested_deeper_than_100_levels_is_refused() {
        assert!(check_nesting(&nested(MAXIMUM_NESTING, 0)).is_ok());
        let err = check_nesting(&nested(MAXIMUM_NESTING + 1, 0)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Value exceeds maximum nesting value of 100"
        );
        let deep_record = Value::Record {
            tycon: None,
            fields: vec![("f".into(), nested(MAXIMUM_NESTING, 0))],
        };
        assert!(check_nesting(&deep_record).is_err());
    }

    /// Comparing and checking a value far deeper than the stack could hold in recursion.
    #[test]
    fn deep_values_compare_without_recursion() {
        const DEPTH: usize = 1_000_000;
        let (a, b, c) = (nested(DEPTH, 1), nested(DEPTH, 1), nested(DEPTH, 2));
        assert!(compare_values(&a, &b).unwrap().is_eq());
        assert!(compare_values(&a, &c).unwrap().is_lt());
        assert!(values_equal(&a, &b).unwrap());
        assert!(!values_equal(&a, &c).unwrap());
        assert!(check_nesting(&a).is_err());
        for value in [a, b, c] {
            dismantle(value);
        }
    }
}
