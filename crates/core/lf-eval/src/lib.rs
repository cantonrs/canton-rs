//! Explicit stack evaluator for the Daml-LF expressions the corpus uses.
//!
//! The machine reads packages from a DAR. It follows value references into
//! dependency DALFs. An expression it does not implement returns an error
//! instead of a guessed value.
//!
//! Update model: evaluating an `Update` expression yields an inert `Value::Action`; effects
//! happen only in *run mode* (`Control::Run`: choice root, `Update::Block` steps, `Kont::Run`),
//! in Daml evaluation order. `Create`/`Exercise`/`Fetch`/`GetTime` call out to an
//! `UpdateHost`, which owns ledger meaning (authorization, ACS, ids).
//!
//! Exceptions / `TryCatch`: `throw` raises `EvalError::Thrown(Value::AnyException)`. A
//! `Kont::Catch` frame (pushed by `Update::TryCatch`) holds a host checkpoint; `Machine::run`
//! unwinds the continuation stack to the nearest frame, asks the host to roll back to the
//! checkpoint, and offers the exception to the handler (`Optional (Update a)`: `None` means
//! "not mine", i.e. rethrow). ONLY `Thrown` is catchable. Host/ledger errors (authorization,
//! inactive/unknown contract, engine limits, `StepLimit`, `error`/arithmetic/`failWithStatus`
//! builtins) pass straight through every catch frame, except the arithmetic builtins, which raise the Daml
//! `ArithmeticError` exception (measured). What may be caught is checked against the JVM oracle
//! (`daml script --ide-ledger`, see `doc/slices/S-TX-001.md` and `tests/oracle/*`); the Scala (Speedy) sources are on
//! disk under `references/canton-3.7.2-src` and are read as a specification, not translated (the licensing consequence
//! is open: `doc/slices/S-LIC-002.md`).
//! Key-based updates (`LookupByKey` and friends) are supported (`key-diff` oracle); a few LF forms are still not (see
//! `doc/slices/UNRESOLVED.md`).
//! Nested Exercise/Fetch are checked against the same oracle; see `engine` for the rules and their measurements.

pub mod builtins;
pub mod cek;
pub mod codec;
pub mod codegen;
pub mod durable;
pub mod engine;
pub mod fat_contract;
pub mod journal;
pub mod ledger;
pub mod list;
pub mod recfile;
pub mod scan_state;
pub mod scan_update;
pub mod script;
pub mod tx_model;
pub mod typecheck;
pub mod typed_json;

pub use list::List;

mod bignumeric;
#[cfg(test)]
mod builtin_edge_tests;
mod crypto_secp;
mod eval_builtins;
#[cfg(test)]
mod map_tests;
mod numeric_ops;
#[cfg(test)]
mod synthetic_tests;
mod time_text;
mod value_nesting;
mod value_order;
mod world;

#[cfg(test)]
pub(crate) use eval_builtins::exec_builtin;
pub(crate) use eval_builtins::hex_bytes;
pub use eval_builtins::{
    builtin_supported, value_contains_nul, SUPPORTED_EXPR_FORMS, SUPPORTED_UPDATE_FORMS,
};
pub use value_nesting::MAXIMUM_NESTING;
pub use value_order::{compare_values, values_equal, CtorRank};
pub(crate) use value_order::{constructor_order, map_position};
pub use world::{parse_arg, parse_numeric, render, render_numeric, ValCache, World};

pub use bignumeric::BigNumericValue;

pub use builtins::{
    div_numeric, explode_text, implode_text, mul_numeric, rescale, sha256_text, validate_date_days,
    validate_timestamp_micros, BuiltinError, RoundingMode,
};
pub use cek::{CekError, CekMachine, ExecutionStatus, HostResponse, Need};
pub use engine::{
    ChoiceOutcome, Contract, ContractIdAllocator, Engine, EngineEvent, ExecError, NewContract,
    NodePaths, MAX_EXERCISE_DEPTH,
};
pub use journal::{JournalEntry, JournalError, LedgerJournal};
pub use ledger::{format_not_active_error, IdeContractIdAllocator, IdePartyAllocator};
pub use tx_model::{ActiveLedgerState, ContractId, Node, NodeId, TransactionTree, TxError};
pub use typecheck::{validate_package_strict, ValidationError};

#[cfg(test)]
use std::collections::HashMap;

use lf_archive::proto::daml_lf_2::{self, Expr};

mod canon_type;
mod env;
mod eval_error;
mod kont;
mod machine_expr;
mod machine_resolve;
mod machine_update;
mod machine_value;
mod update_host;
mod value;

pub(crate) use canon_type::CanonType;
pub use env::{Env, EnvIter, TypeEnv};
pub(crate) use eval_error::exception_parts;
pub use eval_error::{AuthDetail, AuthKind, AuthRule, EvalError};
pub(crate) use kont::Kont;
pub(crate) use machine_resolve::{
    package_of_reference_in, resolve_con_in, split_module_name, InterfaceInstance,
};
pub use update_host::{
    ExerciseInterfaceRequest, ExerciseRequest, FetchRequest, FetchedContract, TryCheckpoint,
    UpdateHost,
};
pub use value::Value;

pub(crate) const STEP_LIMIT: u32 = 5_000_000;
pub(crate) const TRACE: i32 = 0;
pub(crate) const ERROR: i32 = 1;
pub(crate) const EQUAL: i32 = 2;
pub(crate) const LESS_EQ: i32 = 3;
pub(crate) const LESS: i32 = 4;
pub(crate) const GREATER_EQ: i32 = 5;
pub(crate) const GREATER: i32 = 6;
pub(crate) const EXP_INT64: i32 = 12;
pub(crate) const MUL_NUMERIC: i32 = 15;
pub(crate) const DIV_NUMERIC: i32 = 16;
pub(crate) const INT64_TO_NUMERIC: i32 = 20;
pub(crate) const NUMERIC_TO_INT64: i32 = 21;
pub(crate) const TEXT_TO_INT64: i32 = 29;
pub(crate) const TIMESTAMP_TO_TEXT: i32 = 25;
pub(crate) const ROUND_NUMERIC: i32 = 17;
pub(crate) const CAST_NUMERIC: i32 = 18;
pub(crate) const SHIFT_NUMERIC: i32 = 19;
pub(crate) const TEXT_TO_NUMERIC: i32 = 30;
pub(crate) const SHA256_TEXT: i32 = 32;
pub(crate) const COERCE_CONTRACT_ID: i32 = 42;
/// [CANTON-NOTE: SEMANTICS] Not a Daml-LF builtin (those are small non-negative codes). The Daml Script runner replaces the library's
/// `Daml.Script.Internal.LowLevel:dangerousCast` (a body that only raises "Non-replaced call to internal-only dangerousCast") by a
/// function that returns its argument; this is that function. See `locate_val`.
pub(crate) const SCRIPT_DANGEROUS_CAST: i32 = -1000;
pub(crate) const ANY_EXCEPTION_MESSAGE: i32 = 59;
/// The one exception type whose message Speedy reads from the payload instead of calling its `message` definition.
pub(crate) const ARITHMETIC_ERROR: &str = "DA.Exception.ArithmeticError:ArithmeticError";
pub(crate) const KECCAK256_TEXT: i32 = 67;
pub(crate) const SECP256K1_BOOL: i32 = 68;
pub(crate) const SECP256K1_WITH_ECDSA_BOOL: i32 = 72;
pub(crate) const SECP256K1_VALIDATE_KEY: i32 = 73;
pub(crate) const HEX_TO_TEXT: i32 = 69;
pub(crate) const TEXT_TO_HEX: i32 = 70;
pub(crate) const SHA256_HEX: i32 = 71;
pub(crate) const DATE_TO_UNIX_DAYS: i32 = 38;
pub(crate) const UNIX_DAYS_TO_DATE: i32 = 39;
pub(crate) const TIMESTAMP_TO_UNIX_MICROSECONDS: i32 = 40;
pub(crate) const UNIX_MICROSECONDS_TO_TIMESTAMP: i32 = 41;
pub(crate) const DATE_TO_TEXT: i32 = 26;
/// 0001-01-01T00:00:00Z and 9999-12-31T23:59:59.999999Z as microseconds since the epoch.
pub(crate) const MIN_TIMESTAMP_MICROS: i64 = -62_135_596_800_000_000;
pub(crate) const MAX_TIMESTAMP_MICROS: i64 = 253_402_300_799_999_999;
/// 0001-01-01 and 9999-12-31 as days since the epoch.
pub(crate) const MIN_DATE_DAYS: i64 = -719_162;
pub(crate) const MAX_DATE_DAYS: i64 = 2_932_896;
pub(crate) const ADD_INT64: i32 = 7;
pub(crate) const SUB_INT64: i32 = 8;
pub(crate) const MUL_INT64: i32 = 9;
pub(crate) const DIV_INT64: i32 = 10;
pub(crate) const MOD_INT64: i32 = 11;
pub(crate) const ADD_NUMERIC: i32 = 13;
pub(crate) const SUB_NUMERIC: i32 = 14;
pub(crate) const INT64_TO_TEXT: i32 = 22;
pub(crate) const NUMERIC_TO_TEXT: i32 = 23;
pub(crate) const PARTY_TO_TEXT: i32 = 27;
pub(crate) const TEXT_TO_PARTY: i32 = 28;
pub(crate) const CONTRACT_ID_TO_TEXT: i32 = 31;
pub(crate) const EXPLODE_TEXT: i32 = 33;
pub(crate) const APPEND_TEXT: i32 = 34;
pub(crate) const IMPLODE_TEXT: i32 = 35;
pub(crate) const CODE_POINTS_TO_TEXT: i32 = 36;
pub(crate) const TEXT_TO_CODE_POINTS: i32 = 37;
pub(crate) const FOLDL: i32 = 43;
pub(crate) const FOLDR: i32 = 44;
pub(crate) const EQUAL_LIST: i32 = 45;
pub(crate) const UNRESOLVED_TYPE: &str = "<unresolved>";
pub(crate) const GENMAP_EMPTY: i32 = 52;
pub(crate) const GENMAP_INSERT: i32 = 53;
pub(crate) const GENMAP_LOOKUP: i32 = 54;
pub(crate) const GENMAP_DELETE: i32 = 55;
pub(crate) const GENMAP_KEYS: i32 = 56;
pub(crate) const GENMAP_VALUES: i32 = 57;
pub(crate) const GENMAP_SIZE: i32 = 58;
pub(crate) const TEXTMAP_EMPTY: i32 = 60;
pub(crate) const TEXTMAP_INSERT: i32 = 61;
pub(crate) const TEXTMAP_LOOKUP: i32 = 62;
pub(crate) const TEXTMAP_DELETE: i32 = 63;
pub(crate) const TEXTMAP_TO_LIST: i32 = 64;
pub(crate) const TEXTMAP_SIZE: i32 = 65;
pub(crate) const FAIL_WITH_STATUS: i32 = 66;
pub(crate) const SCALE_BIGNUMERIC: i32 = 2001;
pub(crate) const PRECISION_BIGNUMERIC: i32 = 2002;
pub(crate) const ADD_BIGNUMERIC: i32 = 2003;
pub(crate) const SUB_BIGNUMERIC: i32 = 2004;
pub(crate) const MUL_BIGNUMERIC: i32 = 2005;
pub(crate) const DIV_BIGNUMERIC: i32 = 2006;
pub(crate) const SHIFT_RIGHT_BIGNUMERIC: i32 = 2007;
pub(crate) const BIGNUMERIC_TO_NUMERIC: i32 = 2008;
pub(crate) const NUMERIC_TO_BIGNUMERIC: i32 = 2009;
pub(crate) const BIGNUMERIC_TO_TEXT: i32 = 2010;
pub(crate) const TYPE_REP_TYCON_NAME: i32 = 3011;

pub(crate) struct Machine<'a> {
    pub(crate) world: &'a World,
    pub(crate) control: Control,
    pub(crate) env: Env,
    pub(crate) type_env: TypeEnv,
    pub(crate) package_id: String,
    pub(crate) kont: Vec<Kont>,
    pub(crate) steps: u32,
    pub(crate) host: Option<&'a mut dyn UpdateHost>,
    pub(crate) ledger: Ledger,
}

/// Whether a machine evaluates as part of a transaction (Speedy's `UpdateMachine`), or off ledger (`PureMachine`: a
/// Daml script between its submissions, a top-level value). Only `CONTRACT_ID_TO_TEXT` tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ledger {
    On,
    Off,
}

pub(crate) enum Control {
    Expr(Expr),
    /// Run mode: the expression is an `Update` to be *executed* (effects hit the host).
    /// Plain `Expr` mode only ever builds `Value::Action`s from Updates.
    Run(Expr),
    Value(Value),
}

/// Template named by an Update node, with the package it lives in. `template_id` is the
/// evaluator's `"Module:Type"` form; the package id must travel with it because choice
/// lookup is per package (a nested exercise may target a dependency package).
#[derive(Clone)]
struct TemplateRef {
    package_id: String,
    template_id: String,
}

impl<'a> Machine<'a> {
    pub(crate) fn run(&mut self) -> Result<Value, EvalError> {
        loop {
            self.steps += 1;
            if self.steps > STEP_LIMIT {
                return Err(EvalError::StepLimit(STEP_LIMIT));
            }
            if self.kont.is_empty() {
                if let Control::Value(value) = &self.control {
                    return Ok(value.clone());
                }
            }
            if let Err(err) = self.step() {
                // Only a Daml exception is catchable; everything else (host errors,
                // limits, `Unsupported`, ...) leaves the machine untouched and aborts.
                let EvalError::Thrown(exception) = err else {
                    return Err(err);
                };
                self.unwind_to_handler(*exception)?;
            }
        }
    }

    /// `run` for machines with no host (pure evaluation, party lists, preconditions): they
    /// can never be nested under a parent `try`, so an escaped exception is final.
    pub(crate) fn run_closed(&mut self) -> Result<Value, EvalError> {
        self.run().map_err(EvalError::into_uncaught)
    }

    /// Daml exception unwinding: pop continuation frames until the nearest `Kont::Catch`.
    /// All popped frames are simply dropped: a pure frame holds no effect, and every try
    /// frame passed on the way has its host checkpoint rolled back (innermost first), which
    /// is what makes the host state consistent with "the failed `try` bodies never ran".
    /// If the stack runs out the exception is returned to the caller, which is either the
    /// root (flattened by `into_uncaught`) or the host of a nested exercise (whose parent
    /// machine continues the unwinding).
    fn unwind_to_handler(&mut self, exception: Value) -> Result<(), EvalError> {
        while let Some(frame) = self.kont.pop() {
            let Kont::Catch {
                checkpoint,
                var,
                catch_expr,
                mut env,
                type_env,
                package_id,
            } = frame
            else {
                continue;
            };
            // Roll back BEFORE running the handler: the handler (and what it returns) runs
            // against the state as it was when the `try` began. A failing rollback is a
            // host error and is not catchable.
            let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
            host.abort_try(checkpoint)?;
            env.push((var, exception.clone()));
            self.kont.push(Kont::CatchResult { exception });
            self.enter(catch_expr, env, type_env, package_id);
            return Ok(());
        }
        Err(EvalError::Thrown(Box::new(exception)))
    }

    fn step(&mut self) -> Result<(), EvalError> {
        let control = std::mem::replace(&mut self.control, Control::Value(Value::Unit));
        match control {
            Control::Expr(expr) => self.step_expr(expr),
            Control::Run(expr) => self.step_run(expr),
            Control::Value(value) => self.step_value(value),
        }
    }

    /// `(package, "Module:Name")` of a type constructor id of the current expression.
    fn template_ref(&self, id: Option<&daml_lf_2::TypeConId>) -> Result<TemplateRef, EvalError> {
        let id = id.ok_or(EvalError::unsupported())?;
        let (package_id, template_id) = resolve_con_in(self.package()?, &self.package_id, id)?;
        Ok(TemplateRef {
            package_id,
            template_id,
        })
    }
}

fn lookup(env: &Env, name: &str) -> Result<Value, EvalError> {
    env.get(name).cloned().ok_or(EvalError::unsupported())
}

/// U-8: two packages that define an exception of the same name are told apart by the package id in its name.
#[cfg(test)]
mod exception_tycon_tests {
    use super::*;
    use daml_lf_2::{DefException, InternedDottedName, Module};
    use lf_archive::proto::daml_lf_2::expr;
    use lf_archive::proto::daml_lf_2::Package;

    fn package_with_exception(message: &str) -> Package {
        let text = Expr {
            location: None,
            sum: Some(expr::Sum::BuiltinLit(daml_lf_2::BuiltinLit {
                sum: Some(daml_lf_2::builtin_lit::Sum::TextInternedStr(2)),
            })),
        };
        Package {
            interned_strings: vec!["M".into(), "E".into(), message.into()],
            interned_dotted_names: vec![
                InternedDottedName {
                    segments_interned_str: vec![0],
                },
                InternedDottedName {
                    segments_interned_str: vec![1],
                },
            ],
            modules: vec![Module {
                name_interned_dname: 0,
                exceptions: vec![DefException {
                    name_interned_dname: 1,
                    message: Some(text),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn world() -> World {
        let mut packages = HashMap::new();
        packages.insert("pkgA".to_string(), package_with_exception("from A"));
        packages.insert("pkgB".to_string(), package_with_exception("from B"));
        World {
            main_package_id: "pkgA".into(),
            packages,
            val_cache: ValCache::default(),
            ctor_cache: crate::world::CtorCache::default(),
        }
    }

    fn message_text(found: Option<(String, Expr)>) -> (String, i32) {
        let (id, e) = found.expect("an exception message");
        match e.sum {
            Some(expr::Sum::BuiltinLit(daml_lf_2::BuiltinLit {
                sum: Some(daml_lf_2::builtin_lit::Sum::TextInternedStr(i)),
            })) => (id, i),
            other => panic!("unexpected message expression {other:?}"),
        }
    }

    #[test]
    fn both_packages_own_the_name() {
        assert_eq!(
            world().exception_owners("M:E").unwrap(),
            vec!["pkgA".to_string(), "pkgB".to_string()]
        );
    }

    #[test]
    fn a_package_qualified_name_picks_that_package_whatever_the_current_one_is() {
        let w = world();
        for current in ["pkgA", "pkgB"] {
            assert_eq!(
                message_text(w.find_exception_message(current, "pkgB#M:E").unwrap()).0,
                "pkgB"
            );
            assert_eq!(
                message_text(w.find_exception_message(current, "pkgA#M:E").unwrap()).0,
                "pkgA"
            );
        }
    }

    #[test]
    fn a_plain_name_still_prefers_the_current_package() {
        let w = world();
        assert_eq!(
            message_text(w.find_exception_message("pkgB", "M:E").unwrap()).0,
            "pkgB"
        );
        assert_eq!(
            message_text(w.find_exception_message("pkgA", "M:E").unwrap()).0,
            "pkgA"
        );
    }

    #[test]
    fn an_unknown_name_or_package_has_no_message() {
        let w = world();
        assert!(w
            .find_exception_message("pkgA", "M:Nope")
            .unwrap()
            .is_none());
        assert!(w
            .find_exception_message("pkgA", "pkgC#M:E")
            .unwrap()
            .is_none());
    }
}

/// U-8: the order of `Map Party` keys. The JVM's party ids are `<name>-<hash>`; for names of letters, digits and `_` that
/// order equals the order of the plain names (tests/oracle/party-order, measured on the IDE ledger).
#[cfg(test)]
mod party_order_tests {
    use super::*;

    const JVM_ORDER: &str = include_str!("../../../../tests/oracle/party-order/expected.txt");

    #[test]
    fn plain_names_sort_like_the_jvm_party_ids() {
        let jvm: Vec<&str> = JVM_ORDER.trim().split(',').collect();
        // `Sv-b` contains `-`: the JVM puts it by the hash of `Sv`, which the Rust side cannot know (recorded limitation)
        let jvm_plain: Vec<&str> = jvm.iter().copied().filter(|n| !n.contains('-')).collect();
        let mut rust = jvm_plain.clone();
        rust.reverse();
        rust.sort_by(|a, b| {
            compare_values(&Value::Party(a.to_string()), &Value::Party(b.to_string())).unwrap()
        });
        assert_eq!(rust, jvm_plain);
    }

    #[test]
    fn a_name_with_a_dash_is_the_known_exception() {
        let jvm: Vec<&str> = JVM_ORDER.trim().split(',').collect();
        let pos = |n: &str| jvm.iter().position(|x| *x == n).unwrap();
        // by plain name `Sv` < `Sv-b`, the JVM has it the other way round
        assert!(pos("Sv-b") < pos("Sv"));
        assert_eq!(
            compare_values(&Value::Party("Sv".into()), &Value::Party("Sv-b".into())).unwrap(),
            std::cmp::Ordering::Less
        );
    }
}
