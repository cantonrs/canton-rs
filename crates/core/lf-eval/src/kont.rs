//! Continuation frames of the machine (`Kont`).

use lf_archive::proto::daml_lf_2;
use lf_archive::proto::daml_lf_2::{Expr, Type};

use crate::env::{Env, TypeEnv};
use crate::list::List;
use crate::machine_expr::OperandsFrame;
use crate::update_host::TryCheckpoint;
use crate::value::Value;
use crate::value_order::CtorRank;
use crate::TemplateRef;

pub(crate) enum Kont {
    /// The value coming back is that of the top-level value `key`: keep it in the world's cache (Speedy's `SEVal` caching).
    CacheVal {
        key: (String, String, String),
    },
    /// Evaluates application arguments right-to-left (`Anf.transformMultiApp`) before evaluating `fun`.
    ArgsRev {
        fun: Expr,
        pending: Vec<Expr>,
        collected_rev: Vec<Value>,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    Args {
        func: Option<Value>,
        rest: Vec<Expr>,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    ApplyValues {
        args: Vec<Value>,
    },
    Types {
        types: Vec<Type>,
        /// canonical keys of `types`, computed where the type application is evaluated
        keys: Vec<String>,
    },
    StructField {
        is_record: bool,
        tycon: Option<String>,
        got: Vec<(String, Value)>,
        rest: Vec<(String, Expr)>,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    FieldProj {
        field: String,
    },
    FieldUpdRecord {
        field: String,
        update: Expr,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    FieldUpdValue {
        record: Value,
        field: String,
    },
    VariantCon {
        tycon: Option<String>,
        constructor: String,
        rank: CtorRank,
    },
    OptionalSome,
    ConsFront {
        got: Vec<Value>,
        rest_front: Vec<Expr>,
        tail: Expr,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    ConsTail {
        front: Vec<Value>,
    },
    Case {
        alts: Vec<daml_lf_2::CaseAlt>,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    LetBind {
        binder: String,
        rest: Vec<(String, Expr)>,
        body: Expr,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    Throw {
        exception_tycon: Option<String>,
    },
    /// Evaluating the operands of an interface form; see `OperandOp`. Boxed: a `Kont` is built in many places of
    /// `step_value`, so its size multiplies into that function's stack frame (nested exercises recurse through it).
    Operands(Box<OperandsFrame>),
    UpdateCreate {
        package_id: String,
        template_id: String,
    },
    /// The value being returned must be a suspended `Value::Action`; run it.
    Run,
    /// `try` frame. The body's value reaching it means success (`host.end_try`); an
    /// exception unwinding the stack stops here instead (see `Machine::unwind_to_handler`).
    /// It captures the environment of the `TryCatch` node because the handler must run in
    /// that scope, not in whatever scope the failing code had.
    Catch {
        checkpoint: TryCheckpoint,
        var: String,
        catch_expr: Expr,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    /// The handler (`Optional (Update a)`) has been evaluated. `Some(action)` handles the
    /// exception (run the action, outside the already-popped try frame); `None` means the
    /// handler does not match this exception type and it is rethrown unchanged.
    CatchResult {
        exception: Value,
    },
    /// Wrap the evaluated payload as an `AnyException` of the given static exception type.
    ToAnyException {
        tycon: String,
    },
    /// Test an `AnyException` against an expected exception type.
    FromAnyException {
        tycon: String,
    },
    /// Monadic bind of `Update::Block`: like `LetBind`, but each next binding/body is run.
    UpdBind {
        binder: String,
        rest: Vec<(String, Expr)>,
        body: Expr,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    /// Waiting for the contract id of an `Exercise`; the choice argument is evaluated next.
    ExerciseCid {
        template: TemplateRef,
        choice: String,
        arg: Expr,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    /// Waiting for the choice argument of an `Exercise`; then the host call is made.
    ExerciseArg {
        template: TemplateRef,
        choice: String,
        cid: String,
    },
    FetchCid {
        template: TemplateRef,
    },
    Foldl {
        func: Value,
        items: List,
    },
    Foldr {
        func: Value,
        items: Vec<Value>,
    },
    /// `Update.ledger_time_lt`: the timestamp operand has been evaluated; answer `ledger time < operand`.
    LedgerTimeLt,
    /// `EQUAL_LIST`: the previous element comparison has produced a `Bool`; compare the rest.
    EqualList {
        func: Value,
        xs: Vec<Value>,
        ys: Vec<Value>,
    },
}
