//! Evaluation errors (`EvalError`) and authorization failure details.

use thiserror::Error;

use crate::value::Value;

/// Which authority rule an `EvalError::Unauthorized` violated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthKind {
    /// A `create`: every signatory of the new contract must have authorized it.
    Signatories,
    /// An `exercise`: every controller of the choice must be authorized by the caller's
    /// context (top-level `actAs`, or signatories + controllers of the enclosing exercise).
    Controllers,
    /// A `fetch`: at least one stakeholder (signatory or observer) of the fetched contract must be among the authorizing
    /// parties (Speedy `authorizeFetch`, `FetchMissingAuthorization`; measured on JVM 3.7.2 with `readAs`).
    Stakeholders,
}

/// Canton Speedy `FailedAuthorization` variant paired with the failing `NodeId(n)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRule {
    CreateMissingAuthorization,
    NoSignatories,
    MaintainersNotSubsetOfSignatories,
    FetchMissingAuthorization,
    ExerciseMissingAuthorization,
    NoControllers,
    NoAuthorizers,
    LookupByKeyMissingAuthorization,
}

/// Exact Canton authorization failure context (`NodeId(n)` + template + parties).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthDetail {
    pub node_id: usize,
    pub rule: AuthRule,
    /// Full `<package_id>:<Module>:<Entity>` identifier.
    pub template_id: String,
    pub required_parties: Vec<String>,
    /// Authorizers present at the failing node (or template signatories for
    /// `MaintainersNotSubsetOfSignatories`).
    pub context_parties: std::collections::BTreeSet<String>,
}

impl AuthDetail {
    /// Formats this failure like Canton Speedy `Pretty.prettyFailedAuthorization` (the inner
    /// message carried by Daml Script `AuthorizationError msg`, without `"Authorization failure: "`).
    pub fn format_canton(&self) -> String {
        let mut req: Vec<&str> = self.required_parties.iter().map(String::as_str).collect();
        req.sort();
        req.dedup();
        let ctx: Vec<&str> = self.context_parties.iter().map(String::as_str).collect();
        let id = format!("NodeId({})", self.node_id);
        match self.rule {
            AuthRule::NoControllers => format!("node {id} ({}) has no controllers", self.template_id),
            AuthRule::NoAuthorizers => format!("node {id} ({}) has no authorizers", self.template_id),
            AuthRule::NoSignatories => format!("node {id} ({}) has no signatories", self.template_id),
            AuthRule::CreateMissingAuthorization | AuthRule::ExerciseMissingAuthorization => {
                format!(
                    "node {id} ({}) requires authorizers {}, but only {} were given",
                    self.template_id,
                    req.join(","),
                    ctx.join(",")
                )
            }
            AuthRule::FetchMissingAuthorization => format!(
                "node {id} requires one of the stakeholders {} of the fetched contract to be an authorizer, but authorizers were {}",
                format_scala_set(&req),
                format_scala_set(&ctx),
            ),
            AuthRule::LookupByKeyMissingAuthorization => format!(
                "node {id} ({}) requires authorizers {} for lookup by key, but it only has {}",
                self.template_id,
                req.join(","),
                ctx.join(","),
            ),
            AuthRule::MaintainersNotSubsetOfSignatories => format!(
                "node {id} ({}) has maintainers {} which are not a subset of the signatories {}",
                self.template_id,
                req.join(","),
                format_scala_set(&ctx),
            ),
        }
    }
}

fn format_scala_set(items: &[&str]) -> String {
    format!("TreeSet({})", items.join(", "))
}

impl EvalError {
    /// `Unsupported` recording the caller's source location.
    #[track_caller]
    pub fn unsupported() -> Self {
        Self::Unsupported(std::panic::Location::caller())
    }
}

#[derive(Debug, Error)]
pub enum EvalError {
    #[error("{0}")]
    Archive(String),
    #[error("value {module}:{name} was not found")]
    MissingDef { module: String, name: String },
    /// An expression or value this evaluator cannot handle, with the place in its own source that gave up (so that a failure says where to look).
    #[error("unsupported expression (raised at {0})")]
    Unsupported(&'static std::panic::Location<'static>),
    #[error("{0}")]
    Arithmetic(String),
    #[error("evaluation exceeded {0} steps")]
    StepLimit(u32),
    #[error("unhandled exception {error_id}: {message}")]
    UnhandledException { error_id: String, message: String },
    /// A Daml exception in flight (`throw`, or a host-raised Daml exception such as
    /// `PreconditionFailed`); the boxed value is always a `Value::AnyException`. This is the
    /// ONLY error a `Kont::Catch` frame intercepts. It must cross nested-machine/host
    /// boundaries unchanged so an enclosing `try` can still catch an exception thrown by a
    /// nested exercise; it is converted to `UnhandledException` only at root entry points
    /// (see `into_uncaught`), never inside the machine.
    #[error("uncaught Daml exception {}", exception_summary(.0))]
    Thrown(Box<Value>),
    #[error("{0}")]
    Host(String),
    /// A value leaving the engine is nested deeper than Daml allows (Speedy `ValueNesting`); not catchable.
    #[error("Value exceeds maximum nesting value of {0}")]
    ValueNesting(usize),
    /// An internal error of the evaluated program that no Daml `try` catches (Speedy `SError.Crash`).
    #[error("{0}")]
    Crash(String),
    /// A create or exercise lacked the authority Daml demands (signatories must all have
    /// authorized a create; an exercise's controllers must all be authorized by the
    /// enclosing context). Typed (rather than a `Host` string) so callers can map it to an
    /// authorization status without parsing text. Deliberately NOT catchable by a Daml
    /// `try`: in Daml an authorization failure is a ledger/model error, not an exception.
    /// The Display text is the one the `Host` string carried before; `required` is only
    /// for structured consumers.
    #[error("{what} requires authorization of {missing:?}; authorized: {authorized:?}")]
    Unauthorized {
        kind: AuthKind,
        what: String,
        /// Everything the action needs (all signatories, or all controllers).
        required: Vec<String>,
        /// The subset of `required` not covered by `authorized`.
        missing: Vec<String>,
        authorized: std::collections::BTreeSet<String>,
        detail: Option<Box<AuthDetail>>,
    },
    /// A value in run position was not an `Update` action (ill-typed LF or a decoder gap).
    #[error("expected an Update action")]
    NotAnUpdate,
    /// An Update form this evaluator cannot run. Named so a gap is never mistaken for a
    /// generic evaluation failure. LookupByKey/ExerciseByKey/FetchByKey are NOT decodable
    /// (no proto messages, `DefTemplate.key` undecoded) and surface as
    /// `"undecodable update form"`.
    #[error("unsupported update form: {0}")]
    UnsupportedUpdate(&'static str),
    /// The `UpdateHost` in use does not implement this operation (default trait method).
    #[error("update host does not support {0}")]
    HostUnsupported(&'static str),
    /// `fetch`/`exercise` named a contract the host has never seen.
    #[error("contract {contract_id} not found")]
    ContractNotFound { contract_id: String },
    /// [CANTON-NOTE: SEMANTICS] A contract id was used as one template but names another (a `fetch`/`exercise` whose
    /// static template differs from the stored one). Typed so a differential harness can tell it from a generic host
    /// failure; the JVM reports it as the script `WronglyTypedContract` submit error.
    #[error("contract {contract_id} has template {actual}, not {expected}")]
    WrongContractTemplate {
        contract_id: String,
        actual: String,
        expected: String,
    },
    /// A Text containing a NUL character crossed the boundary to the ledger (a command argument, a created contract's
    /// payload, a choice result). The JVM's `MalformedText`: an uncatchable error that ends the whole script, so it is not
    /// a Daml exception and no `try` catches it.
    #[error("Text contains null character")]
    MalformedText,
    /// The contract exists but has been archived (consumed) in this transaction/ledger.
    #[error("contract {contract_id} is not active")]
    ContractNotActive { contract_id: String },
    /// `fetchByKey`/`exerciseByKey` found no active contract with the key (Speedy `ContractKeyNotFound`).
    #[error("contract key not found for template {template_id}")]
    ContractKeyNotFound { template_id: String },
    /// A caught (or rethrown) exception reached a `try` whose body had created or consumed a contract. Speedy forbids
    /// rolling such a body back (`EffectfulRollbackError`); it is a ledger error, not a Daml exception, so no `try`
    /// catches it. `contracts` lists the created and consumed contract ids.
    #[error("Tried to rollback side-effectful node(s): {contracts:?}")]
    EffectfulRollback { contracts: Vec<String> },
    /// A key lookup on a template whose maintainers evaluate to the empty set (Speedy
    /// `FetchEmptyContractKeyMaintainers`).
    #[error("empty contract key maintainers for template {template_id}")]
    EmptyKeyMaintainers { template_id: String },
}

impl EvalError {
    /// Turns an exception that escaped every `try` into the flat `UnhandledException` form
    /// existing callers match on (`error_id = UNHANDLED_EXCEPTION/<tycon>`, same strings the
    /// pre-TryCatch evaluator produced). Call it only where evaluation is at the root: a
    /// nested exercise must keep returning `Thrown`, otherwise a `try` around the exercise
    /// in the parent body could never see the exception. Any other error is returned as is.
    pub fn into_uncaught(self) -> Self {
        match self {
            Self::Thrown(exception) => {
                let (tycon, message) = exception_parts(&exception);
                Self::UnhandledException {
                    error_id: format!("UNHANDLED_EXCEPTION/{tycon}"),
                    message,
                }
            }
            other => other,
        }
    }
}

/// `(type name, message)` of an exception value. The message is the payload's `message`
/// field (Daml's `Exception` class requires a `message` method; for the built-in exception
/// records it is a plain field) or the payload itself if it is a bare `Text`. User
/// exceptions may compute `message` by a method this evaluator cannot call, in which case
/// the message is empty rather than guessed.
pub(crate) fn exception_parts(exception: &Value) -> (String, String) {
    let Value::AnyException { tycon, payload } = exception else {
        return ("Exception".to_string(), String::new());
    };
    let message = match payload.as_ref() {
        Value::Record { fields, .. } => fields
            .iter()
            .find_map(|(name, value)| match (name.as_str(), value) {
                ("message", Value::Text(text)) => Some(text.clone()),
                _ => None,
            })
            .unwrap_or_default(),
        Value::Text(text) => text.clone(),
        _ => String::new(),
    };
    (tycon.clone(), message)
}

fn exception_summary(exception: &Value) -> String {
    let (tycon, message) = exception_parts(exception);
    format!("{tycon}: {message}")
}
