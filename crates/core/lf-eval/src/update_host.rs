//! The ledger side of evaluation: `UpdateHost` and the requests it serves.

use crate::eval_error::EvalError;
use crate::value::Value;

/// A nested `exercise` as seen by the host. `template_id` is `"Module:Type"` and
/// `package_id` the package that defines it.
pub struct ExerciseRequest<'a> {
    pub package_id: &'a str,
    pub template_id: &'a str,
    pub contract_id: &'a str,
    pub choice: &'a str,
    pub arg: &'a Value,
}

/// An `exercise_interface` as seen by the host. `interface_id` is `"Module:Name"` of the interface in
/// `interface_package_id`; the contract's template is taken from the stored contract. `guard`, when present, is a
/// function from the interface value to `Bool`; a false guard aborts the command.
pub struct ExerciseInterfaceRequest<'a> {
    pub interface_package_id: &'a str,
    pub interface_id: &'a str,
    pub contract_id: &'a str,
    pub choice: &'a str,
    pub arg: &'a Value,
    pub guard: Option<&'a Value>,
}

/// What `UpdateHost::fetch_contract` returns: the stored contract with its template.
pub struct FetchedContract {
    pub package_id: String,
    /// `"Module:Type"`.
    pub template_id: String,
    pub payload: Value,
}

pub struct FetchRequest<'a> {
    pub package_id: &'a str,
    pub template_id: &'a str,
    pub contract_id: &'a str,
}

/// Speedy's `MaxContractKeyFetches`: `queryNByKey` never returns more contracts than this.
pub(crate) const MAX_CONTRACT_KEY_FETCHES: i64 = 1_000_000;

/// The ledger side of Update evaluation. The machine decides *when* an effect runs (lazily,
/// in Daml evaluation order); the host decides *what it means* (authorization, ACS,
/// contract ids). Everything but `create_contract` has a default that fails with a typed
/// `HostUnsupported`, so a host only claims the operations it really implements.
pub trait UpdateHost {
    fn create_contract(&mut self, template_id: &str, payload: &Value) -> Result<String, EvalError>;

    /// Package-aware create. Defaults to `create_contract` for hosts that only know one
    /// package (e.g. `SingleContractLedger`).
    fn create_contract_in(
        &mut self,
        _package_id: &str,
        template_id: &str,
        payload: &Value,
    ) -> Result<String, EvalError> {
        self.create_contract(template_id, payload)
    }

    /// Run a nested exercise and return the choice's result value. The host owns the
    /// authorization decision, the consuming flag and the recursion (it re-enters
    /// `World::eval_choice_update_in` with itself as host).
    fn exercise(&mut self, _request: &ExerciseRequest<'_>) -> Result<Value, EvalError> {
        Err(EvalError::HostUnsupported("exercise"))
    }

    /// Exercise an interface choice on an active contract (the host finds the template of the contract, checks
    /// that it implements the interface and runs the choice with authorization).
    fn exercise_interface(
        &mut self,
        _request: &ExerciseInterfaceRequest<'_>,
    ) -> Result<Value, EvalError> {
        Err(EvalError::HostUnsupported("exercise_interface"))
    }

    /// The stored contract behind an id, with its template (used by `fetch_interface`).
    fn fetch_contract(
        &mut self,
        _contract_id: &str,
        _interface_id: Option<&str>,
    ) -> Result<FetchedContract, EvalError> {
        Err(EvalError::HostUnsupported("fetch_contract"))
    }

    /// [CANTON-NOTE: SEMANTICS] Speedy `SBUKeyBuiltin`: `fetchByKey`, `exerciseByKey` and `queryNByKey` all resolve a key
    /// through this one host call. Order is most-recently-created first; `queryNByKey` additionally requires the
    /// maintainers to be authorized, the others do not (`KeyOperation.Fetch.authorizeLookup` is a no-op).
    ///
    /// Active contracts of a template whose key equals `key`, most recently created first, at most `n`, with their
    /// payloads. With `authorize` the maintainers of the key must be covered by the current authority (Speedy
    /// `authorizeQueryByKey`, used by `queryNByKey` only). A template with no key, or a key whose maintainers are empty,
    /// is an error; an empty result is not (the caller decides whether that is `ContractKeyNotFound`).
    fn lookup_by_key(
        &mut self,
        _package_id: &str,
        _template_id: &str,
        _key: &Value,
        _n: usize,
        _authorize: bool,
    ) -> Result<Vec<(String, Value)>, EvalError> {
        Err(EvalError::HostUnsupported("lookup_by_key"))
    }

    /// Return the payload of an active contract, or `ContractNotFound`/`ContractNotActive`.
    fn fetch(&mut self, _request: &FetchRequest<'_>) -> Result<Value, EvalError> {
        Err(EvalError::HostUnsupported("fetch"))
    }

    /// Ledger time in microseconds since the epoch.
    fn get_time(&mut self) -> Result<i64, EvalError> {
        Err(EvalError::HostUnsupported("get_time"))
    }

    /// Entering `try`: snapshot everything a rollback must restore (ACS incl. consumed
    /// flags, contracts created so far, journal/tx-builder position, authorizer stack).
    /// Defaults to `HostUnsupported`: a host that cannot roll back must refuse `try`
    /// outright, because silently running the body without a checkpoint would make a
    /// caught exception leave the ledger half-modified.
    fn begin_try(&mut self) -> Result<TryCheckpoint, EvalError> {
        Err(EvalError::HostUnsupported("begin_try"))
    }

    /// The `try` body finished normally: its effects stay and the checkpoint (plus any newer
    /// ones) is discarded. Tokens are issued in LIFO order by `begin_try`.
    fn end_try(&mut self, _checkpoint: TryCheckpoint) -> Result<(), EvalError> {
        Err(EvalError::HostUnsupported("end_try"))
    }

    /// An exception reached the `try`: restore the state captured by `begin_try` and discard
    /// the checkpoint (plus newer ones). Called BEFORE the handler runs, and also when the
    /// handler then declines (`None`) and the exception keeps propagating: the failed
    /// body's effects are gone either way.
    fn abort_try(&mut self, _checkpoint: TryCheckpoint) -> Result<(), EvalError> {
        Err(EvalError::HostUnsupported("abort_try"))
    }
}

/// Opaque handle for a host checkpoint taken by `UpdateHost::begin_try`. The host decides
/// what the number means (the `Engine` uses it as an index into its checkpoint stack).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TryCheckpoint(pub usize);
