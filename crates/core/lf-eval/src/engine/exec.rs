//! Template-agnostic command execution on top of `Engine`.
//!
//! `execute_create` / `execute_exercise` are the commands a ledger front end (e.g. a
//! participant) submits: *create template T with payload P as actAs A* and *exercise choice C
//! on contract X as actAs A*. Everything Daml-specific (ensure, signatories, observers,
//! controllers, the choice body, nested creates/exercises) is evaluated from the DAR; nothing
//! here names a template, a package or a field.
//!
//! Guarantees:
//! * Commit-on-`Ok`: a command that fails (any `ExecError`) leaves the engine's contracts and
//!   journal exactly as before. The mechanism is `Engine::atomically`'s snapshot/restore.
//! * Contract ids come from an injected `ContractIdAllocator`, so the embedding ledger keeps
//!   its own id scheme.
//!
//! Limits (this is the same model as `Engine`, not a Canton engine):
//! * Authorization is *local*: `actAs` is taken as given. There is no hosting/topology check,
//!   no confirmation by other signatories' participants and no readAs/visibility rule.
//! * The payload/argument `Value`s are not type-checked against the template here; shape
//!   errors surface as evaluator errors (`ExecError::Eval`). `crate::codec` is the layer that
//!   builds well-labelled values from the template surface.
//! * Allocator-side state is not transactional (see `ContractIdAllocator`).

use std::collections::BTreeSet;

use super::{Contract, Engine, EngineEvent, PRECONDITION_FAILED};
use crate::{AuthDetail, AuthKind, EvalError, ExerciseRequest, UpdateHost, Value};

/// What a `create` that is about to be recorded looks like; passed to the allocator so an id
/// scheme can depend on the contract (e.g. derive it from content/stakeholders).
pub struct NewContract<'a> {
    pub package_id: &'a str,
    /// `"Module:Type"`.
    pub template_id: &'a str,
    pub payload: &'a Value,
    pub signatories: &'a [String],
    pub observers: &'a [String],
    /// 0-based position of this create among the creates *attempted* by the current root
    /// command (creates inside a `try` that is rolled back still consume an index). Stable
    /// within a command, so it can serve as a deterministic node number.
    pub creation_index: usize,
    /// [CANTON-NOTE: SEMANTICS] Execution nesting depth of the create: 0 for root creates, >= 1 for creates inside choices.
    pub depth: usize,
    /// Where the create sits in the command's transaction tree: the child index of each ancestor below the root exercise and its own (see
    /// [`super::NodePaths`]). Empty for a root create.
    pub path: &'a [usize],
    /// The evaluated contract key value and its maintainers, if the template declares a key.
    pub key: Option<(&'a Value, &'a [String])>,
}

/// Injected contract-id scheme. Called when a `create` executes, i.e. before the command is
/// known to succeed (a choice body may already use the id), hence an allocator must treat
/// its own counters as non-transactional: a failed command may burn ids. That is the same
/// trade-off real ledgers make (ids are not reused) and avoids a rollback protocol here.
pub trait ContractIdAllocator {
    fn allocate(&mut self, new: &NewContract<'_>) -> String;
    /// Optional submission index hook for allocators that track root command/submission index.
    fn set_submission_idx(&mut self, _idx: usize) {}
}

impl<F> ContractIdAllocator for F
where
    F: FnMut(&NewContract<'_>) -> String,
{
    fn allocate(&mut self, new: &NewContract<'_>) -> String {
        self(new)
    }
}

/// Why a command was refused. Variants are chosen so a caller can map them to its own error
/// surface without parsing messages.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("template {template_id} is not defined in package {package_id}")]
    UnknownTemplate {
        package_id: String,
        template_id: String,
    },
    #[error("template {template_id} has no choice {choice}")]
    UnknownChoice { template_id: String, choice: String },
    #[error("contract {0} not found")]
    ContractNotFound(String),
    #[error("contract {0} is not active")]
    ContractNotActive(String),
    /// Daml authorization failure. `kind == Controllers` is the top-level (or nested)
    /// exercise rule: `required` are the choice's controllers (for the implicit `Archive`
    /// these are the contract's signatories). `kind == Signatories` is a create whose
    /// signatories were not all authorized (top-level actAs, or the authority inside the
    /// enclosing choice: signatories + controllers; observers confer none).
    #[error("{what} requires authorization of {missing:?}; authorized: {authorized:?}")]
    Unauthorized {
        kind: AuthKind,
        what: String,
        required: Vec<String>,
        missing: Vec<String>,
        authorized: BTreeSet<String>,
        detail: Option<Box<AuthDetail>>,
    },
    /// The template's `ensure` evaluated to false (Daml's built-in `PreconditionFailed`
    /// exception, uncaught). Note the message names only the template, unlike Canton's
    /// message which also prints the argument.
    #[error("precondition failed: {message}")]
    PreconditionFailed { message: String },
    /// A Daml exception that escaped every `try`, e.g. a failed `assertMsg` (the DAR raises
    /// `DA.Exception.AssertionFailed:AssertionFailed`) or a user `throw`. Which Daml failures
    /// are exceptions and which are plain errors follows `Machine`'s model, see lib.rs.
    #[error("unhandled exception {error_id}: {message}")]
    Unhandled { error_id: String, message: String },
    /// Any other evaluator/host error (unsupported construct, step limit, malformed payload,
    /// non-Daml assertion failures, ...). Kept as-is rather than guessed into a category.
    #[error("{0}")]
    Eval(EvalError),
}

impl ExecError {
    /// Returns the inner Canton `AuthorizationError` message (`"node NodeId(n) ..."` without
    /// `"Authorization failure: "`) when this error is `ExecError::Unauthorized`.
    pub fn canton_auth_message(&self) -> Option<String> {
        match self {
            Self::Unauthorized {
                detail: Some(detail),
                ..
            } => Some(detail.format_canton()),
            _ => None,
        }
    }

    fn from_eval(err: EvalError) -> Self {
        match err.into_uncaught() {
            EvalError::Unauthorized {
                kind,
                what,
                required,
                missing,
                authorized,
                detail,
            } => Self::Unauthorized {
                kind,
                what,
                required,
                missing,
                authorized,
                detail,
            },
            EvalError::ContractNotFound { contract_id } => Self::ContractNotFound(contract_id),
            EvalError::ContractNotActive { contract_id } => Self::ContractNotActive(contract_id),
            EvalError::UnhandledException { error_id, message } => {
                // `into_uncaught` renders an escaped exception as `UNHANDLED_EXCEPTION/<tycon>`.
                if error_id == format!("UNHANDLED_EXCEPTION/{PRECONDITION_FAILED}") {
                    Self::PreconditionFailed { message }
                } else {
                    Self::Unhandled { error_id, message }
                }
            }
            other => Self::Eval(other),
        }
    }
}

/// Result of a successful `execute_exercise`.
#[derive(Clone, Debug, PartialEq)]
pub struct ChoiceOutcome {
    /// Whether the exercised choice is consuming (it then appears in `archived`).
    pub consuming: bool,
    /// The choice's return value.
    pub result: Value,
    /// Every contract created by the command (including by nested exercises), in creation
    /// order. A contract created and archived again inside the same command is listed with
    /// `active == false`; creates inside a rolled-back `try` are not listed.
    pub created: Vec<Contract>,
    /// Contracts that existed before the command and were archived by it (the exercised
    /// contract when consuming, plus anything nested consuming exercises archived), in
    /// execution order, without duplicates.
    pub archived: Vec<String>,
    /// The journal slice of this command (committed events only).
    pub events: Vec<EngineEvent>,
    /// What the `try` bodies this command rolled back journaled, with `at` relative to `events` (the index in `events` the body would have
    /// begun at). Empty when nothing was rolled back. See [`super::RolledBack`].
    pub rolled_back: Vec<super::RolledBack>,
}

impl Engine<'_> {
    /// Top-level `create` of `template_id` (`"Module:Type"`, main package) authorized by
    /// `act_as`. Returns the stored contract. See `execute_create_in` for the rules.
    pub fn execute_create<A: AsRef<str>>(
        &mut self,
        act_as: &[A],
        template_id: &str,
        payload: &Value,
    ) -> Result<Contract, ExecError> {
        let package_id = self.world.main_package_id().to_string();
        self.execute_create_in(act_as, &package_id, template_id, payload)
    }

    /// Package-explicit variant of `execute_create`.
    ///
    /// Order (mirrors `SingleContractLedger::create`): `ensure` first, then authorization of
    /// all signatories by `act_as`, then observers and id allocation. A false `ensure`
    /// therefore wins over a missing authorization when both apply; whether Canton orders
    /// these two the same way is not verified here.
    pub fn execute_create_in<A: AsRef<str>>(
        &mut self,
        act_as: &[A],
        package_id: &str,
        template_id: &str,
        payload: &Value,
    ) -> Result<Contract, ExecError> {
        self.check_disclosed_active()
            .map_err(ExecError::from_eval)?;
        self.require_template(package_id, template_id)?;
        let actors: Vec<&str> = act_as.iter().map(AsRef::as_ref).collect();
        let contract_id = self
            .atomically(&actors, |engine| {
                engine.create_contract_in(package_id, template_id, payload)
            })
            .map_err(ExecError::from_eval)?;
        self.contracts
            .get(&contract_id)
            .cloned()
            .ok_or_else(|| ExecError::Eval(EvalError::Host("created contract vanished".into())))
    }

    /// Top-level exercise of `choice` on the active contract `contract_id` by `actors`.
    ///
    /// Check order: contract exists and is active, choice exists, then controllers ⊆ actors
    /// (`Unauthorized{kind: Controllers}`), then the body runs with authority = signatories ∪
    /// controllers. A consuming choice archives the contract *before* its body runs, so the
    /// body cannot touch `self`. Any failure restores the pre-command state (commit-on-`Ok`).
    pub fn execute_exercise<A: AsRef<str>>(
        &mut self,
        actors: &[A],
        contract_id: &str,
        choice: &str,
        arg: &Value,
    ) -> Result<ChoiceOutcome, ExecError> {
        self.check_disclosed_active()
            .map_err(ExecError::from_eval)?;
        // The template is taken from the stored contract, never from the caller: a caller
        // naming the wrong template would otherwise run a choice against a mismatching payload.
        let (package_id, template_id) = {
            let contract = self
                .contracts
                .get(contract_id)
                .ok_or_else(|| ExecError::ContractNotFound(contract_id.to_string()))?;
            // Visibility: a submitter can only act on contracts it can see. With no read-as parties, that means
            // at least one acting party is a stakeholder (signatory or observer) or the contract was disclosed.
            // Reported as ContractNotFound before checking active status or authorization.
            let visible = self.visible_to_command(contract, actors);
            if !actors.is_empty() && !visible {
                return Err(ExecError::ContractNotFound(contract_id.to_string()));
            }
            if !contract.active {
                return Err(ExecError::ContractNotActive(contract_id.to_string()));
            }
            (contract.package_id.clone(), contract.template_id.clone())
        };
        let (module, template) = self.require_template(&package_id, &template_id)?;
        if !self
            .world
            .choice_exists(&package_id, module, template, choice)
            .map_err(ExecError::Eval)?
        {
            return Err(ExecError::UnknownChoice {
                template_id,
                choice: choice.to_string(),
            });
        }
        let consuming = self
            .world
            .choice_is_consuming(&package_id, module, template, choice)
            .map_err(ExecError::Eval)?;

        let events_before = self.events.len();
        let known_before: BTreeSet<String> = self.contracts.keys().cloned().collect();
        let actors: Vec<&str> = actors.iter().map(AsRef::as_ref).collect();
        let result = self
            .atomically(&actors, |engine| {
                // a Text with a NUL character cannot be a choice argument or a choice result (uncatchable)
                if crate::value_contains_nul(arg) {
                    return Err(EvalError::MalformedText);
                }
                let result = engine.exercise(&ExerciseRequest {
                    package_id: &package_id,
                    template_id: &template_id,
                    contract_id,
                    choice,
                    arg,
                })?;
                if crate::value_contains_nul(&result) {
                    return Err(EvalError::MalformedText);
                }
                Ok(result)
            })
            .map_err(ExecError::from_eval)?;

        Ok(self.outcome_since(events_before, &known_before, consuming, result))
    }

    /// The effects of the command that just committed: contracts it created and ones it archived, derived from the
    /// committed journal. Events of a rolled-back `try` were truncated by the engine, so they cannot leak in.
    fn outcome_since(
        &self,
        events_before: usize,
        known_before: &BTreeSet<String>,
        consuming: bool,
        result: Value,
    ) -> ChoiceOutcome {
        let events = self.events[events_before..].to_vec();
        let rolled_back = self
            .rolled_back
            .iter()
            .filter(|g| g.at >= events_before)
            .map(|g| super::RolledBack {
                at: g.at - events_before,
                events: g.events.clone(),
            })
            .collect();
        let mut created = Vec::new();
        let mut archived: Vec<String> = Vec::new();
        for event in &events {
            match event {
                EngineEvent::Create { contract_id, .. } => {
                    if let Some(contract) = self.contracts.get(contract_id) {
                        created.push(contract.clone());
                    }
                }
                EngineEvent::Exercise {
                    contract_id,
                    consuming: true,
                    ..
                } if known_before.contains(contract_id) && !archived.contains(contract_id) => {
                    archived.push(contract_id.clone());
                }
                _ => {}
            }
        }
        ChoiceOutcome {
            consuming,
            result,
            created,
            archived,
            events,
            rolled_back,
        }
    }

    /// Top-level exercise of an interface choice (`exercise_interface`) on the active contract `contract_id` by
    /// `actors`: the contract must be visible to an actor (as for `execute_exercise`), its template must implement
    /// the interface, the interface choice's controllers must be authorized, and the body runs with the interface
    /// value as `this`. `interface_id` is `"Module:Name"` in `interface_package_id`.
    pub fn execute_exercise_interface<A: AsRef<str>>(
        &mut self,
        actors: &[A],
        interface_package_id: &str,
        interface_id: &str,
        contract_id: &str,
        choice: &str,
        arg: &Value,
    ) -> Result<ChoiceOutcome, ExecError> {
        {
            let contract = self
                .contracts
                .get(contract_id)
                .ok_or_else(|| ExecError::ContractNotFound(contract_id.to_string()))?;
            let visible = self.visible_to_command(contract, actors);
            if !actors.is_empty() && !visible {
                return Err(ExecError::ContractNotFound(contract_id.to_string()));
            }
            if !contract.active {
                return Err(ExecError::ContractNotActive(contract_id.to_string()));
            }
        }
        let consuming = self
            .world
            .interface_choice_is_consuming(interface_package_id, interface_id, choice)
            .map_err(|_| ExecError::UnknownChoice {
                template_id: interface_id.to_string(),
                choice: choice.to_string(),
            })?;
        let events_before = self.events.len();
        let known_before: BTreeSet<String> = self.contracts.keys().cloned().collect();
        let actors: Vec<&str> = actors.iter().map(AsRef::as_ref).collect();
        let result = self
            .atomically(&actors, |engine| {
                engine.exercise_interface(&crate::ExerciseInterfaceRequest {
                    interface_package_id,
                    interface_id,
                    contract_id,
                    choice,
                    arg,
                    guard: None,
                })
            })
            .map_err(ExecError::from_eval)?;
        Ok(self.outcome_since(events_before, &known_before, consuming, result))
    }

    /// `(module, entity)` of `template_id` after checking the package really defines it, so
    /// "no such template" is reported as such instead of as an opaque evaluator miss.
    fn require_template<'t>(
        &self,
        package_id: &str,
        template_id: &'t str,
    ) -> Result<(&'t str, &'t str), ExecError> {
        let unknown = || ExecError::UnknownTemplate {
            package_id: package_id.to_string(),
            template_id: template_id.to_string(),
        };
        let (module, template) = template_id.split_once(':').ok_or_else(unknown)?;
        if self
            .world
            .template_exists(package_id, module, template)
            .map_err(ExecError::Eval)?
        {
            Ok((module, template))
        } else {
            Err(unknown())
        }
    }
}
