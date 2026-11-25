//! Daml-LF total ordering, structural equality, and constructor declaration order registry.

use crate::{CanonType, EvalError, Value};

/// The position of a constructor in its enum or variant declaration (Speedy `constructorRank`), which orders two
/// values of different constructors. Every value the evaluator builds or decodes against its type carries it; a value
/// built without its type (a Ledger API value, a test harness) does not, and is then ordered through
/// [`constructor_order`].
///
/// Equality ignores the rank: two values of one type with the same constructor name have the same rank, and a value
/// with an unknown rank must still equal its typed twin.
#[derive(Clone, Copy, Debug, Default)]
pub struct CtorRank(pub Option<u32>);

impl CtorRank {
    pub fn known(rank: u32) -> Self {
        Self(Some(rank))
    }
}

impl PartialEq for CtorRank {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

/// The order of two different constructors: by the ranks the values carry, else by the registered declarations.
fn constructor_cmp(
    (cx, rx): (&str, CtorRank),
    (cy, ry): (&str, CtorRank),
) -> Result<std::cmp::Ordering, EvalError> {
    match (rx.0, ry.0) {
        (Some(x), Some(y)) => Ok(x.cmp(&y)),
        _ => constructor_order::compare(cx, cy).ok_or(EvalError::unsupported()),
    }
}

/// What is left to compare: a pair of values, or the lengths of two sequences whose common prefix compared equal.
enum Pending<'v> {
    Pair(&'v Value, &'v Value),
    Lengths(usize, usize),
}

/// Pushes the pairs of `xs` and `ys` so that they pop in order, after which their lengths decide.
fn push_sequences<'v>(
    stack: &mut Vec<Pending<'v>>,
    xs: impl Iterator<Item = &'v Value>,
    ys: impl Iterator<Item = &'v Value>,
    (x_len, y_len): (usize, usize),
) {
    stack.push(Pending::Lengths(x_len, y_len));
    let pairs: Vec<Pending<'v>> = xs.zip(ys).map(|(x, y)| Pending::Pair(x, y)).collect();
    stack.extend(pairs.into_iter().rev());
}

/// Pushes `pairs` so that they pop in order.
fn push_rev<'v>(
    stack: &mut Vec<(&'v Value, &'v Value)>,
    pairs: impl Iterator<Item = (&'v Value, &'v Value)>,
) {
    let pairs: Vec<_> = pairs.collect();
    stack.extend(pairs.into_iter().rev());
}

fn map_items(entries: &[(Value, Value)]) -> impl Iterator<Item = &Value> {
    entries.iter().flat_map(|(k, v)| [k, v])
}

/// Daml's total order on comparable values. Numerics compare only at the same scale. Different constructors of a
/// variant or enum order by their declaration rank (Speedy `svalue.Ordering`: `xRank compareTo yRank`).
///
/// [CANTON-NOTE: WHY] Like Speedy's `svalue.Ordering`, the walk keeps its own stack, so a deeply nested value cannot
/// overflow the Rust stack.
pub fn compare_values(a: &Value, b: &Value) -> Result<std::cmp::Ordering, EvalError> {
    use std::cmp::Ordering;
    let mut stack = vec![Pending::Pair(a, b)];
    while let Some(next) = stack.pop() {
        let (a, b) = match next {
            Pending::Pair(a, b) => (a, b),
            Pending::Lengths(x, y) => match x.cmp(&y) {
                Ordering::Equal => continue,
                other => return Ok(other),
            },
        };
        let order = match (a, b) {
            (Value::Int64(x), Value::Int64(y)) => x.cmp(y),
            (Value::Text(x), Value::Text(y)) | (Value::Party(x), Value::Party(y)) => x.cmp(y),
            (Value::ContractId(x), Value::ContractId(y)) => x.cmp(y),
            (
                Value::Numeric {
                    coeff: x,
                    scale: sx,
                },
                Value::Numeric {
                    coeff: y,
                    scale: sy,
                },
            ) if sx == sy => x.cmp(y),
            (Value::BigNumeric(x), Value::BigNumeric(y)) => x.cmp_value(y),
            (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
            (Value::Unit, Value::Unit) => Ordering::Equal,
            (Value::TypeRep { key: x, .. }, Value::TypeRep { key: y, .. }) => {
                CanonType::parse(x)?.cmp(&CanonType::parse(y)?)
            }
            (
                Value::Any {
                    key: kx,
                    payload: x,
                },
                Value::Any {
                    key: ky,
                    payload: y,
                },
            ) => {
                let order = CanonType::parse(kx)?.cmp(&CanonType::parse(ky)?);
                stack.push(Pending::Pair(x, y));
                order
            }
            (Value::List(x), Value::List(y)) => {
                push_sequences(&mut stack, x.iter(), y.iter(), (x.len(), y.len()));
                Ordering::Equal
            }
            // [CANTON-NOTE: SEMANTICS] Two GenMap/TextMap (or Set, which wraps a map) values compare as their entry
            // lists, which are kept sorted by key: first by (key, value) pair, then by length (Speedy interlaces keys
            // and values the same way).
            (Value::Map(x), Value::Map(y)) => {
                push_sequences(&mut stack, map_items(x), map_items(y), (x.len(), y.len()));
                Ordering::Equal
            }
            (Value::Optional(x), Value::Optional(y)) => match (x, y) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                (Some(p), Some(q)) => {
                    stack.push(Pending::Pair(p, q));
                    Ordering::Equal
                }
            },
            (Value::Record { fields: x, .. }, Value::Record { fields: y, .. })
            | (Value::Struct(x), Value::Struct(y)) => {
                push_sequences(
                    &mut stack,
                    x.iter().map(|(_, v)| v),
                    y.iter().map(|(_, v)| v),
                    (x.len(), y.len()),
                );
                Ordering::Equal
            }
            (Value::Enum { constructor: x, .. }, Value::Enum { constructor: y, .. }) if x == y => {
                Ordering::Equal
            }
            (
                Value::Variant {
                    constructor: cx,
                    value: x,
                    ..
                },
                Value::Variant {
                    constructor: cy,
                    value: y,
                    ..
                },
            ) if cx == cy => {
                stack.push(Pending::Pair(x, y));
                Ordering::Equal
            }
            (
                Value::Enum {
                    constructor: cx,
                    rank: rx,
                    ..
                },
                Value::Enum {
                    constructor: cy,
                    rank: ry,
                    ..
                },
            )
            | (
                Value::Variant {
                    constructor: cx,
                    rank: rx,
                    ..
                },
                Value::Variant {
                    constructor: cy,
                    rank: ry,
                    ..
                },
            ) => constructor_cmp((cx, *rx), (cy, *ry))?,
            _ => return Err(EvalError::unsupported()),
        };
        if order != Ordering::Equal {
            return Ok(order);
        }
    }
    Ok(Ordering::Equal)
}

/// Structural equality (`EQUAL`). Unlike ordering, values of different variant or enum constructors are simply
/// unequal. Walks with its own stack, like [`compare_values`].
pub fn values_equal(a: &Value, b: &Value) -> Result<bool, EvalError> {
    let mut stack = vec![(a, b)];
    while let Some((a, b)) = stack.pop() {
        let equal = match (a, b) {
            (Value::Enum { constructor: x, .. }, Value::Enum { constructor: y, .. }) => x == y,
            (
                Value::Variant {
                    constructor: cx,
                    value: x,
                    ..
                },
                Value::Variant {
                    constructor: cy,
                    value: y,
                    ..
                },
            ) => {
                stack.push((x, y));
                cx == cy
            }
            (Value::List(x), Value::List(y)) => {
                push_rev(&mut stack, x.iter().zip(y.iter()));
                x.len() == y.len()
            }
            (Value::Optional(x), Value::Optional(y)) => match (x, y) {
                (None, None) => true,
                (Some(p), Some(q)) => {
                    stack.push((p, q));
                    true
                }
                _ => false,
            },
            (Value::Record { fields: x, .. }, Value::Record { fields: y, .. })
            | (Value::Struct(x), Value::Struct(y)) => {
                push_rev(&mut stack, x.iter().zip(y).map(|((_, p), (_, q))| (p, q)));
                x.len() == y.len()
            }
            (Value::Map(x), Value::Map(y)) => {
                push_rev(&mut stack, map_items(x).zip(map_items(y)));
                x.len() == y.len()
            }
            (Value::TypeRep { key: x, .. }, Value::TypeRep { key: y, .. }) => {
                CanonType::parse(x)? == CanonType::parse(y)?
            }
            (
                Value::Any {
                    key: kx,
                    payload: x,
                },
                Value::Any {
                    key: ky,
                    payload: y,
                },
            ) => {
                stack.push((x, y));
                CanonType::parse(kx)? == CanonType::parse(ky)?
            }
            (Value::BigNumeric(x), Value::BigNumeric(y)) => x == y,
            _ => compare_values(a, b)?.is_eq(),
        };
        if !equal {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Where `key` is, or would be inserted, in map entries sorted by key.
pub(crate) fn map_position(
    entries: &[(Value, Value)],
    key: &Value,
) -> Result<Result<usize, usize>, EvalError> {
    let (mut lo, mut hi) = (0, entries.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        match compare_values(&entries[mid].0, key)? {
            std::cmp::Ordering::Equal => return Ok(Ok(mid)),
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    Ok(Err(lo))
}

/// Map entries from input order to key order, a later entry replacing an earlier one with an equal key. This is how
/// Speedy imports a command's `GenMap` and every `TextMap` (`SMap.apply`: `entries.to(TreeMap)`).
pub(crate) fn sort_map_entries(
    entries: Vec<(Value, Value)>,
) -> Result<Vec<(Value, Value)>, EvalError> {
    let mut sorted: Vec<(Value, Value)> = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        match map_position(&sorted, &key)? {
            Ok(at) => sorted[at] = (key, value),
            Err(at) => sorted.insert(at, (key, value)),
        }
    }
    Ok(sorted)
}

/// Whether the keys are strictly increasing, as Speedy demands of a `GenMap` in a contract argument
/// (`SMap.fromStrictlyOrderedEntries`).
pub(crate) fn strictly_ordered_keys(entries: &[(Value, Value)]) -> Result<bool, EvalError> {
    for pair in entries.windows(2) {
        if compare_values(&pair[0].0, &pair[1].0)? != std::cmp::Ordering::Less {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Declaration order of enum and variant constructors, needed to order two values with different constructors.
///
/// [CANTON-NOTE: LIMITATION] Only for values that carry no [`CtorRank`] (built by a test harness without their type):
/// every type definition of every opened package is registered, and two names are ordered by the first registered
/// type, in package id order, that declares both. Two different types that declare the same two names in opposite
/// order would be ordered wrongly; the test below checks that no such pair exists in the pinned Splice DARs.
pub(crate) mod constructor_order {
    use std::{
        cmp::Ordering,
        collections::HashMap,
        sync::{OnceLock, RwLock},
    };

    use lf_archive::proto::daml_lf_2::{def_data_type::DataCons, Package};
    use lf_archive::resolve_interned_string;

    #[derive(Default)]
    struct Registry {
        /// "package:module:type" -> type number, so reopening a DAR registers nothing new
        types: HashMap<String, u64>,
        /// constructor name -> (type number, position)
        positions: HashMap<String, Vec<(u64, u32)>>,
    }

    fn registry() -> &'static RwLock<Registry> {
        static REGISTRY: OnceLock<RwLock<Registry>> = OnceLock::new();
        REGISTRY.get_or_init(|| RwLock::new(Registry::default()))
    }

    pub(crate) fn register_packages(packages: &HashMap<String, Package>) {
        let Ok(mut reg) = registry().write() else {
            return;
        };
        let mut ids: Vec<&String> = packages.keys().collect();
        ids.sort();
        for (package_id, package) in ids.into_iter().filter_map(|id| packages.get_key_value(id)) {
            for module in &package.modules {
                for (index, data) in module.data_types.iter().enumerate() {
                    let names: Vec<String> = match &data.data_cons {
                        Some(DataCons::Enum(e)) => e
                            .constructors_interned_str
                            .iter()
                            .filter_map(|i| {
                                resolve_interned_string(package, *i, "enum constructor").ok()
                            })
                            .collect(),
                        Some(DataCons::Variant(f)) => f
                            .fields
                            .iter()
                            .filter_map(|f| {
                                resolve_interned_string(
                                    package,
                                    f.field_interned_str,
                                    "variant constructor",
                                )
                                .ok()
                            })
                            .collect(),
                        _ => continue,
                    };
                    let key = format!("{package_id}:{}:{index}", module.name_interned_dname);
                    if reg.types.contains_key(&key) {
                        continue;
                    }
                    let id = reg.types.len() as u64;
                    reg.types.insert(key, id);
                    for (position, name) in names.into_iter().enumerate() {
                        reg.positions
                            .entry(name)
                            .or_default()
                            .push((id, position as u32));
                    }
                }
            }
        }
    }

    /// The order of two constructor names, `None` when no registered type declares both.
    pub(crate) fn compare(a: &str, b: &str) -> Option<Ordering> {
        let reg = registry().read().ok()?;
        let (pa, pb) = (reg.positions.get(a)?, reg.positions.get(b)?);
        pa.iter()
            .find_map(|(ta, ia)| pb.iter().find(|(tb, _)| tb == ta).map(|(_, ib)| ia.cmp(ib)))
    }

    #[cfg(test)]
    mod tests {
        use std::path::Path;

        use super::*;
        use crate::World;

        /// No two registered types order the same pair of constructor names in opposite ways, so the name-based
        /// lookup in `compare` is unambiguous for the pinned Splice packages.
        #[test]
        fn pinned_splice_dars_have_no_ambiguous_constructor_pairs() {
            let dars =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/splice-dars");
            for name in [
                "splice-amulet-0.1.25.dar",
                "splice-wallet-0.1.26.dar",
                "splice-dso-governance-0.1.31.dar",
                "splice-validator-lifecycle-0.1.7.dar",
            ] {
                World::open(&dars.join(name)).expect("open DAR");
            }
            let reg = registry().read().unwrap();
            let mut checked = 0usize;
            for (a, pa) in &reg.positions {
                for (b, pb) in &reg.positions {
                    let orders: std::collections::BTreeSet<Ordering> = pa
                        .iter()
                        .flat_map(|(ta, ia)| {
                            pb.iter()
                                .filter(move |(tb, _)| tb == ta)
                                .map(move |(_, ib)| ia.cmp(ib))
                        })
                        .collect();
                    checked += 1;
                    assert!(
                        orders.len() <= 1,
                        "constructors {a} and {b} are ordered both ways"
                    );
                }
            }
            assert!(checked > 1000, "the registry should hold many constructors");
            assert_eq!(compare("SenderSide", "ReceiverSide"), Some(Ordering::Less));
        }
    }
}
