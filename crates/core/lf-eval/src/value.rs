//! Runtime values of the machine (`Value`).

use lf_archive::proto::daml_lf_2::{Expr, Type};

use crate::bignumeric::BigNumericValue;
use crate::env::{Env, TypeEnv};
use crate::list::List;
use crate::value_order::CtorRank;
use crate::world::render_numeric;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Int64(i64),
    Numeric {
        coeff: i128,
        scale: u8,
    },
    BigNumeric(BigNumericValue),
    Text(String),
    Party(String),
    ContractId(String),
    Bool(bool),
    Unit,
    List(List),
    Optional(Option<Box<Value>>),
    Record {
        tycon: Option<String>,
        fields: Vec<(String, Value)>,
    },
    Variant {
        tycon: Option<String>,
        constructor: String,
        rank: CtorRank,
        value: Box<Value>,
    },
    Enum {
        tycon: Option<String>,
        constructor: String,
        rank: CtorRank,
    },
    Partial {
        builtin: i32,
        types: Vec<Type>,
        args: Vec<Value>,
    },
    Closure {
        params: Vec<String>,
        body: Expr,
        env: Env,
        package_id: String,
        type_env: TypeEnv,
    },
    TyClosure {
        params: Vec<String>,
        body: Expr,
        env: Env,
        package_id: String,
        type_env: TypeEnv,
    },
    Struct(Vec<(String, Value)>),
    /// A suspended `Update`: a closure over a not-yet-run Update expression. Producing one
    /// has no ledger effect; effects happen only when the machine runs it (`Kont::Run`,
    /// `Update::Block` bindings, choice root).
    Action {
        expr: Box<Expr>,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    /// [CANTON-NOTE: SEMANTICS] In Daml-LF 2.3 `FetchByKey T` and `QueryNByKey T` are not actions but *functions* that
    /// yield an action once applied to the key (`key -> Update`, `n -> key -> Update`); Speedy compiles them as
    /// `FetchByKeyDefRef(T)()` and `QueryNByKeyDefRef(T)()` of arity 2 and 3 including the token. `ExerciseByKey`
    /// carries its key and argument inside the node and is an ordinary action.
    ///
    /// The function `FetchByKey T` / `QueryNByKey T` evaluates to (`key -> Update`, `n -> key -> Update`). It collects
    /// its arguments and becomes a `KeyAction`.
    KeyFn {
        query_n: bool,
        package_id: String,
        template_id: String,
        args: Vec<Value>,
    },
    /// A saturated key lookup, still inert: the host is asked when the machine runs it (`Kont::Run`).
    /// [CANTON-NOTE: INVARIANT] Building it must not touch the host, exactly like `Value::Action`: a lookup that is
    /// only constructed (e.g. under `when False`) has no ledger effect and cannot fail.
    KeyAction {
        query_n: bool,
        package_id: String,
        template_id: String,
        key: Box<Value>,
        n: i64,
    },
    /// Daml `AnyException`: an exception payload tagged with its exception type. `tycon` is
    /// `"Module:Type"` as written by the `throw`/`ToAnyException` type annotation, NOT the
    /// payload's runtime tag, because `FromAnyException` matches on the static type. The
    /// package id is dropped (as everywhere in this evaluator's tycon strings), so two
    /// exception types with the same `Module:Type` in different packages would be conflated.
    AnyException {
        tycon: String,
        payload: Box<Value>,
    },
    /// A value of type `Any`: the value together with the canonical key of its type (`ToAny`).
    Any {
        key: String,
        payload: Box<Value>,
    },
    /// A `TypeRep`: the canonical key of a type and, for an unapplied type constructor, its `"<package>:<Module>:<Name>"`.
    TypeRep {
        key: String,
        tycon: Option<String>,
    },
    /// A `GenMap` or `TextMap`: entries kept sorted by key in Daml's value order, no duplicate keys. The two
    /// kinds share this representation (a `TextMap` has `Text` keys only).
    Map(Vec<(Value, Value)>),
    /// A value of an interface type: the template value (and the template it belongs to) behind it. Created by
    /// `ToInterface`, never stored on a ledger (a contract is always stored as its template payload).
    Iface {
        package_id: String,
        /// `"Module:Type"` of the template.
        template: String,
        payload: Box<Value>,
    },
}

impl Value {
    pub fn to_lf_value(&self) -> lf_archive::Value {
        match self {
            Self::Unit => lf_archive::Value::Unit,
            Self::Bool(b) => lf_archive::Value::Bool(*b),
            Self::Int64(n) => lf_archive::Value::Int64(*n),
            Self::Numeric { coeff, scale } => {
                lf_archive::Value::Numeric(render_numeric(*coeff, *scale))
            }
            Self::BigNumeric(bn) => lf_archive::Value::Text(bn.to_unscaled_string()),
            Self::Text(s) => lf_archive::Value::Text(s.clone()),
            Self::Party(p) => lf_archive::Value::Party(p.clone()),
            Self::ContractId(cid) => lf_archive::Value::ContractId(cid.as_bytes().to_vec()),
            Self::List(items) => {
                lf_archive::Value::List(items.iter().map(Self::to_lf_value).collect())
            }
            Self::Optional(opt) => {
                lf_archive::Value::Optional(opt.as_ref().map(|v| Box::new(v.to_lf_value())))
            }
            Self::Record { fields, .. } | Self::Struct(fields) => lf_archive::Value::Record {
                fields: fields.iter().map(|(_, v)| v.to_lf_value()).collect(),
            },
            Self::Variant {
                constructor, value, ..
            } => lf_archive::Value::Variant {
                constructor: constructor.clone(),
                value: Box::new(value.to_lf_value()),
            },
            Self::Enum { constructor, .. } => lf_archive::Value::Enum {
                value: constructor.clone(),
            },
            Self::Partial { .. }
            | Self::Closure { .. }
            | Self::TyClosure { .. }
            | Self::KeyFn { .. }
            | Self::KeyAction { .. }
            | Self::Action { .. } => lf_archive::Value::Unit,
            // Exceptions are never ledger data (they cannot be stored in a contract or
            // choice argument), so like closures they have no `lf_archive::Value` form.
            Self::AnyException { .. } => lf_archive::Value::Unit,
            Self::Any { payload, .. } => payload.to_lf_value(),
            Self::TypeRep { .. } => lf_archive::Value::Unit,
            // Maps have no `lf_archive::Value` form here (they are not stored in this model's payloads).
            Self::Map(_) => lf_archive::Value::Unit,
            // An interface value is its template value for serialization purposes.
            Self::Iface { payload, .. } => payload.to_lf_value(),
        }
    }
}
