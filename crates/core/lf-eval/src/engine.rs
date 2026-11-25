//! A small, generic ledger host for `World` Update evaluation.
//!
//! `Engine` implements `UpdateHost` over an in-memory active-contract set. Its purpose is to
//! drive the evaluator's `Update::{Create, Exercise, Fetch, GetTime}` paths end to end
//! (`Machine` -> host -> recursive choice body) with Daml-style authorization.
//!
//! What this is NOT (read before relying on it):
//! * Not a Canton/Daml engine. Contract ids are sequential `#n` strings, not the hashed
//!   Canton ids that `ledger::SingleContractLedger` reproduces.
//! * No transaction tree, no seeds, no key index (LookupByKey/ExerciseByKey are blocked on
//!   proto/`DefTemplate.key` decoding), no interfaces. A non-Daml error (authorization,
//!   inactive contract, limits, ...) aborts the *whole* root command (`atomically`) and is
//!   never caught by a Daml `try`.
//! * `try/catch` rollback is a snapshot/restore model (`begin_try`/`abort_try`), not
//!   Canton's `Rollback` transaction node: there is no tree to put a node in, the journal
//!   (`events`) just forgets the rolled-back part. Whether a real participant numbers
//!   node ids/seeds after a rollback the same way is not verified.
//! * Nested Exercise/Fetch have no official oracle on disk: no available DAR contains a
//!   choice whose body exercises or fetches, and `tx-corpus.dar` cannot be rebuilt without
//!   Docker. Behaviour here follows the Daml ledger model from documentation and is
//!   checked only by synthetic model tests plus one differential against real DAR values.
//!
//! Embedding: `execute_create` / `execute_exercise` (module `exec`) are the template-agnostic
//! command entry points: typed errors, commit-on-`Ok`, injected contract ids
//! (`set_contract_id_allocator`) and seeded contracts (`import_contract`). They add no
//! semantics beyond the model above; in particular authorization stays local (`actAs` is
//! trusted) and `SingleContractLedger` does NOT run on top of this engine, because it must
//! reproduce IDE-ledger strings and hashed ids that a generic path cannot.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    values_equal, AuthDetail, AuthKind, AuthRule, EvalError, ExerciseRequest, TryCheckpoint,
    UpdateHost, Value, World,
};

mod exec;

pub use exec::{ChoiceOutcome, ContractIdAllocator, ExecError, NewContract};

mod update_host;

use update_host::split_template;

/// Name of the built-in Daml exception raised when a template's `ensure` is false.
const PRECONDITION_FAILED: &str = "DA.Exception.PreconditionFailed:PreconditionFailed";

/// Bounds Rust recursion: every nested exercise re-enters the evaluator on the native
/// stack, so unbounded Daml recursion would overflow it long before `STEP_LIMIT` (which is
/// per choice body, not per transaction) triggers.
pub const MAX_EXERCISE_DEPTH: usize = 32;

#[derive(Clone, Debug, PartialEq)]
pub struct Contract {
    pub contract_id: String,
    pub package_id: String,
    /// `"Module:Type"`, the evaluator's template naming.
    pub template_id: String,
    pub payload: Value,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    pub active: bool,
    /// The contract key value, when the template declares a key (the participant reports it in created events).
    pub key: Option<Value>,
}

/// What happened, in execution order. `depth` is the exercise nesting level of the actor
/// (0 = top-level command).
#[derive(Clone, Debug, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "events are built once per node and read sequentially without heap boxing"
)] // [CANTON-NOTE: STYLE] events are built once per node and read in order; boxing the large variant would only add indirection
pub enum EngineEvent {
    Create {
        contract_id: String,
        template_id: String,
        depth: usize,
    },
    Exercise {
        contract_id: String,
        choice: String,
        consuming: bool,
        actors: Vec<String>,
        depth: usize,
        /// The chosen value the exercise was given, and (once the body has run) what it returned: a scan's update history states both for every
        /// exercised event, nested ones too.
        argument: Value,
        result: Option<Value>,
        /// The interface the choice was exercised through, if any.
        interface_id: Option<String>,
        /// The choice's observers (its `observer` clause evaluated; empty without one): who sees the exercise besides the stakeholders and the actors.
        observers: Vec<String>,
    },
    Fetch {
        contract_id: String,
        depth: usize,
        /// The acting parties of the fetch node: the parties authorizing the code that fetched (the signatories and controllers of the
        /// enclosing exercise, or the top-level `actAs` parties) **that are stakeholders of the fetched contract**, sorted.
        ///
        /// [CANTON-NOTE: SEMANTICS] Source: `PartialTransaction.insertFetch` (`actingParties = context.info.authorizers intersect
        /// contract.stakeholders`). Measured: the official participant rebuilds a fetch of a contract only the DSO party is a stakeholder of,
        /// inside a choice the SV controls, with the DSO alone as acting party (S-SPL-017).
        authorizers: Vec<String>,
        /// The interface through which the contract was fetched (`package:Module:Entity`), if any.
        interface_id: Option<String>,
    },
}

/// Where the nodes of a command's transaction tree sit, from the events the engine journals.
///
/// [CANTON-NOTE: SEMANTICS] A node's position is the child index of each ancestor below the root exercise and its own child index, counting
/// **every** node among its siblings: creates, exercises and fetches alike (measured: the official participant approves the request in which a
/// fetch takes a child index and refuses the one in which it does not, `doc/slices/S-SPL-002.md`). The root exercise has the empty path; a node
/// of a root create is not in a tree below anything, so its path is empty too. The ids of the contracts a command creates depend on these
/// positions (the node seed of a create is derived from its parent's seed and its index), which is why the engine hands a create its path
/// **before** the create is journaled.
///
/// [CANTON-NOTE: LIMITATION] A caught exception is a `Rollback` node in a Canton transaction, and it takes a child index there too; the journal
/// forgets what a rolled-back `try` did, so such a node is not counted here. A command with a rolled-back `try` is therefore not positioned
/// reliably, and a caller that sends the tree must refuse it.
#[derive(Clone, Debug, Default)]
pub struct NodePaths {
    /// `next[d]`: the child index the next node at depth `d` takes under the latest exercise open at depth `d - 1`.
    next: Vec<usize>,
    /// `open[d]`: the child index of the latest exercise at depth `d` (`d >= 1`).
    open: Vec<usize>,
}

impl NodePaths {
    /// The path of the node that comes next at `depth` (the number of exercises it is inside).
    pub fn peek(&self, depth: usize) -> Vec<usize> {
        if depth == 0 {
            return Vec::new();
        }
        let mut path: Vec<usize> = (1..depth)
            .map(|d| self.open.get(d).copied().unwrap_or(0))
            .collect();
        path.push(self.next.get(depth).copied().unwrap_or(0));
        path
    }

    /// Takes the next position at `depth` and returns it; `opens` says whether the node is an exercise (its children come next).
    pub fn record(&mut self, depth: usize, opens: bool) -> Vec<usize> {
        let path = self.peek(depth);
        if self.next.len() < depth + 2 {
            self.next.resize(depth + 2, 0);
        }
        if self.open.len() < depth + 2 {
            self.open.resize(depth + 2, 0);
        }
        if depth >= 1 {
            self.next[depth] += 1;
        }
        if opens {
            if let Some(own) = path.last() {
                self.open[depth] = *own;
            }
            self.next[depth + 1] = 0;
        }
        path
    }

    /// The positions of `events` (which begin at index `start` of the engine's journal), in order, and the state after them, **counting the
    /// nodes of rolled-back `try` bodies** among their siblings: a rollback takes no child index of its own, and the action nodes inside it
    /// take the next indices of the exercise around it (`PartialTransaction.rollbackTry` hands the counter back to the parent; measured:
    /// the official participant approves the request in which a create after a rollback holding two fetches has index 2,
    /// `doc/slices/S-SPL-027.md`). The returned positions are those of `events` only.
    pub fn of_events_with_rollbacks(
        events: &[EngineEvent],
        start: usize,
        rolled_back: &[RolledBack],
    ) -> (Self, Vec<Vec<usize>>) {
        let mut tracker = Self::default();
        let mut paths = Vec::new();
        let count_rolled = |tracker: &mut Self, at: usize| {
            for group in rolled_back.iter().filter(|g| g.at == at) {
                for event in &group.events {
                    tracker.record_event(event);
                }
            }
        };
        for (i, event) in events.iter().enumerate() {
            count_rolled(&mut tracker, start + i);
            paths.push(tracker.record_event(event));
        }
        count_rolled(&mut tracker, start + events.len());
        (tracker, paths)
    }

    fn record_event(&mut self, event: &EngineEvent) -> Vec<usize> {
        match event {
            EngineEvent::Create { depth, .. } | EngineEvent::Fetch { depth, .. } => {
                self.record(*depth, false)
            }
            EngineEvent::Exercise { depth, .. } => self.record(*depth, true),
        }
    }

    /// The positions of `events`, in order, and the state after them.
    pub fn of_events(events: &[EngineEvent]) -> (Self, Vec<Vec<usize>>) {
        let mut tracker = Self::default();
        let paths = events
            .iter()
            .map(|event| match event {
                EngineEvent::Create { depth, .. } | EngineEvent::Fetch { depth, .. } => {
                    tracker.record(*depth, false)
                }
                EngineEvent::Exercise { depth, .. } => tracker.record(*depth, true),
            })
            .collect();
        (tracker, paths)
    }
}

/// The key of a contract of a template with a key.
///
/// [CANTON-NOTE: SEMANTICS] `seq` orders keyed contracts by creation: `fetchByKey`, `exerciseByKey` and `queryNByKey`
/// return the most recently created contract first (Canton 3.5.1 release notes, "Standard library"; measured on JVM
/// 3.7.2, `tests/oracle/key-diff`). Contracts created earlier in the same command are always first, which falls out of
/// the creation order here because they are the newest.
#[derive(Clone, Debug)]
struct ContractKey {
    key: Value,
    seq: u64,
}

/// A key resolution a view states, as [`Engine::resolve_keys_from_view`] takes it: template `Module:Name`, the encoded key (Daml-LF
/// value bytes), and the contract ids in the stated order.
pub type ViewKeyResolution = (String, Vec<u8>, Vec<String>);

/// A key lookup the engine made (`fetchByKey`, `lookupByKey`, `queryNByKey`): the template, the key and the ids of the contracts it found
/// (most recent first). A participant that validates a view compares these with the key resolutions the view states.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyLookup {
    pub template_id: String,
    pub key: Value,
    pub contract_ids: Vec<String>,
}

/// A key lookup recorded together with the engine journal position and nesting depth where it happened.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedKeyLookup {
    pub package_id: String,
    pub lookup: KeyLookup,
    pub event_pos: usize,
    pub depth: usize,
    /// `true` for `lookupByKey` / `queryNByKey` (`authorize == true`), `false` for `fetchByKey` / `exerciseByKey`.
    pub is_query: bool,
}

/// What a caught exception rolled back: the journal events of the `try` body (nested rolled-back bodies inside it included, in order),
/// forgotten by [`Engine::events`] and kept here so the positions of the nodes after it count them ([`NodePaths::of_events_with_rollbacks`]).
/// `at` is the index in the journal the body would have begun at.
#[derive(Clone, Debug, PartialEq)]
pub struct RolledBack {
    pub at: usize,
    pub events: Vec<EngineEvent>,
}

pub struct Engine<'w> {
    world: &'w World,
    key_lookups: Vec<KeyLookup>,
    recorded_key_lookups: Vec<RecordedKeyLookup>,
    contracts: BTreeMap<String, Contract>,
    /// Keys of keyed contracts, by contract id; snapshotted together with `contracts` (a rolled-back or failed command
    /// must not leave a key behind).
    keys: BTreeMap<String, ContractKey>,
    next_key_seq: u64,
    /// `next_key_seq` when the current root command started: keyed contracts with a larger `seq` were created by this
    /// command and are visible to it whoever their stakeholders are.
    command_key_seq_start: u64,
    /// Contracts created by the current root command: visible to it whoever their stakeholders are.
    command_created: BTreeSet<String>,
    /// Contracts handed to the submitter by explicit disclosure: visible to it though it is no stakeholder.
    disclosed: BTreeSet<String>,
    /// Caller-supplied order of explicitly disclosed contract ids (deduplicated, preserving first occurrence).
    disclosed_order: Vec<String>,
    /// Key resolutions a validating participant takes from the view (`template "Module:Name"`, encoded key, contract ids in order);
    /// see [`Engine::resolve_keys_from_view`].
    view_key_resolutions: Option<Vec<ViewKeyResolution>>,
    /// Number of ledger effects (contract creations and consumptions by commands) so far. Never rewound. A `try`
    /// checkpoint remembers it so `abort_try` can tell whether the body had an effect. `import_contract` seeds the ACS
    /// and is not an effect.
    ledger_effects: u64,
    next_contract: u64,
    /// Stack of authorizer sets; the top is the authority of the code currently running.
    authorizers: Vec<BTreeSet<String>>,
    /// `readAs` parties of the command being submitted: they widen what the command can SEE (fetch, key lookup, exercise
    /// target) but confer no authority. Set by `set_read_as`, not reset by a command (a harness sets it per command).
    read_as: BTreeSet<String>,
    events: Vec<EngineEvent>,
    /// The events of `try` bodies that were rolled back, by journal index (see [`RolledBack`]).
    rolled_back: Vec<RolledBack>,
    depth: usize,
    now_micros: i64,
    /// Open `try` checkpoints, innermost last; a `TryCheckpoint` is an index into this.
    checkpoints: Vec<Checkpoint>,
    /// Injected contract-id scheme (the participant keeps its own ids). `None` = `#n`.
    allocator: Option<Box<dyn ContractIdAllocator + 'w>>,
    /// Creates attempted by the current root command, including ones a `try` later rolled
    /// back. Handed to the allocator as `NewContract::creation_index`; like `next_contract`
    /// it is never rewound, so an allocator never sees the same index twice per command.
    command_creates: usize,
    /// Where the events of the command that runs now begin in `events` (see [`NodePaths`]).
    command_events_start: usize,
    /// Canton `PartialTransaction.nextNodeIdx`: pre-order index assigned to each action node (and
    /// opened `try` rollback context) inside the active root command; not rewound on rollback.
    next_node_idx: usize,
}

/// Everything a caught exception must undo. Full clones keep the model obviously correct
/// (cost is O(contracts) per `try`; an undo log would be the scalable design).
/// Deliberately NOT captured: `next_contract` and `now_micros`. Contract ids are never
/// reused after a rollback, so an id that leaked out of the failed body (e.g. inside the
/// exception payload) cannot alias a contract created later; the id then resolves to
/// `ContractNotFound`, as a contract that never existed on the ledger would.
struct Checkpoint {
    /// `Engine::ledger_effects` when the `try` began.
    effects: u64,
    contracts: BTreeMap<String, Contract>,
    keys: BTreeMap<String, ContractKey>,
    events_len: usize,
    recorded_lookups_len: usize,
    /// Restored for robustness: nested exercises pop their own authorizer frame on error
    /// already, but a rollback must not depend on every host path having done so.
    authorizers: Vec<BTreeSet<String>>,
    depth: usize,
}

impl<'w> Engine<'w> {
    pub fn new(world: &'w World) -> Self {
        Self {
            world,
            contracts: BTreeMap::new(),
            keys: BTreeMap::new(),
            next_key_seq: 0,
            key_lookups: Vec::new(),
            recorded_key_lookups: Vec::new(),
            command_key_seq_start: 0,
            command_created: BTreeSet::new(),
            disclosed: BTreeSet::new(),
            disclosed_order: Vec::new(),
            view_key_resolutions: None,
            ledger_effects: 0,
            next_contract: 0,
            authorizers: Vec::new(),
            read_as: BTreeSet::new(),
            events: Vec::new(),
            rolled_back: Vec::new(),
            depth: 0,
            now_micros: 0,
            checkpoints: Vec::new(),
            allocator: None,
            command_creates: 0,
            command_events_start: 0,
            next_node_idx: 0,
        }
    }

    /// [CANTON-NOTE: SEMANTICS] Sets the `readAs` parties for the commands that follow: a contract is visible to a command
    /// when a stakeholder is among its `actAs` OR `readAs` parties (or the command created it). `readAs` never adds
    /// authority: signatories and controllers are still checked against `actAs` alone.
    pub fn set_read_as<A: AsRef<str>>(&mut self, parties: &[A]) {
        self.read_as = parties.iter().map(|p| p.as_ref().to_string()).collect();
    }

    /// Replaces the default `#n` contract ids by an injected scheme. The allocator is called
    /// at the moment a `create` runs (the id is a value the choice body can use, e.g. return
    /// or exercise), so it also runs for creates that are later rolled back or whose command
    /// fails: allocator-side counters are NOT transactional. Ids it returns must be unique
    /// among all contracts this engine holds; a repeat is rejected as a host error.
    pub fn set_contract_id_allocator(&mut self, allocator: impl ContractIdAllocator + 'w) {
        self.allocator = Some(Box::new(allocator));
    }

    /// [CANTON-NOTE: SEMANTICS] Sets the submission index for the injected contract ID allocator.
    pub fn set_submission_idx(&mut self, idx: usize) {
        if let Some(allocator) = self.allocator.as_deref_mut() {
            allocator.set_submission_idx(idx);
        }
    }

    /// Seeds an already existing active contract (e.g. a participant's ACS entry) so that
    /// choices and nested fetch/exercise can see it. `signatories`/`observers` are TRUSTED as
    /// given, not re-derived from the template: the caller owns what was validated when the
    /// contract was created. A duplicate id is an error rather than an overwrite.
    pub fn import_contract(&mut self, contract: Contract) -> Result<(), EvalError> {
        if self.contracts.contains_key(&contract.contract_id) {
            return Err(EvalError::Host(format!(
                "contract {} is already known to the engine",
                contract.contract_id
            )));
        }
        let (module, template) = split_template(&contract.template_id)?;
        let key = self.world.eval_template_key_in(
            &contract.package_id,
            module,
            template,
            &contract.payload,
        )?;
        let mut contract = contract;
        contract.key = key.as_ref().map(|(k, _)| k.clone());
        if let Some((key, _)) = key {
            self.record_key(&contract.contract_id, key);
        }
        self.contracts
            .insert(contract.contract_id.clone(), contract);
        Ok(())
    }

    /// The key lookups made so far, in order.
    pub fn key_lookups(&self) -> &[KeyLookup] {
        &self.key_lookups
    }

    /// The key lookups with journal position, depth, and whether each came from `lookupByKey`/`queryNByKey`.
    pub fn recorded_key_lookups(&self) -> &[RecordedKeyLookup] {
        &self.recorded_key_lookups
    }

    pub fn set_time_micros(&mut self, now_micros: i64) {
        self.now_micros = now_micros;
    }

    pub fn contract(&self, contract_id: &str) -> Option<&Contract> {
        self.contracts.get(contract_id)
    }

    pub fn active_contracts(&self) -> impl Iterator<Item = &Contract> {
        self.contracts.values().filter(|c| c.active)
    }

    /// The events of the `try` bodies this engine rolled back (see [`RolledBack`]).
    pub fn rolled_back(&self) -> &[RolledBack] {
        &self.rolled_back
    }

    /// The positions of every journal event, counting rolled-back bodies ([`NodePaths::of_events_with_rollbacks`]).
    pub fn node_paths(&self) -> (NodePaths, Vec<Vec<usize>>) {
        NodePaths::of_events_with_rollbacks(&self.events, 0, &self.rolled_back)
    }

    pub fn events(&self) -> &[EngineEvent] {
        &self.events
    }

    /// Number of `try` checkpoints currently open. Always 0 between root commands; exposed so
    /// tests can check that abandoned `try` frames do not leak checkpoints.
    pub fn open_checkpoints(&self) -> usize {
        self.checkpoints.len()
    }

    /// Top-level create authorized by `act_as` (all signatories must be in `act_as`).
    pub fn create_as(
        &mut self,
        act_as: &[&str],
        package_id: &str,
        template_id: &str,
        payload: &Value,
    ) -> Result<String, EvalError> {
        self.atomically(act_as, |engine| {
            engine.create_contract_in(package_id, template_id, payload)
        })
    }

    /// Top-level exercise on an existing contract. Authorization: the choice's controllers
    /// must be a subset of `act_as`. The template is taken from the stored contract.
    pub fn exercise_as(
        &mut self,
        act_as: &[&str],
        contract_id: &str,
        choice: &str,
        arg: &Value,
    ) -> Result<Value, EvalError> {
        let (package_id, template_id) = {
            let contract = self.lookup(contract_id)?;
            (contract.package_id.clone(), contract.template_id.clone())
        };
        self.atomically(act_as, |engine| {
            engine.exercise(&ExerciseRequest {
                package_id: &package_id,
                template_id: &template_id,
                contract_id,
                choice,
                arg,
            })
        })
    }

    /// Top-level interface exercise on an existing contract (used when replaying views with `interface_id`).
    pub fn exercise_interface_as(
        &mut self,
        act_as: &[&str],
        interface_package_id: &str,
        interface_id: &str,
        contract_id: &str,
        choice: &str,
        arg: &Value,
    ) -> Result<Value, EvalError> {
        self.atomically(act_as, |engine| {
            engine.exercise_interface(&crate::ExerciseInterfaceRequest {
                interface_package_id,
                interface_id,
                contract_id,
                choice,
                arg,
                guard: None,
            })
        })
    }

    /// Run a root `Update` taken from a (DAR) value: see `World::run_update_val`.
    pub fn run_update_val_as(
        &mut self,
        act_as: &[&str],
        module: &str,
        name: &str,
        fields: &[&str],
        args: &[Value],
    ) -> Result<Value, EvalError> {
        let world = self.world;
        self.atomically(act_as, |engine| {
            world.run_update_val(module, name, fields, args, engine)
        })
    }

    /// Runs `f` as one all-or-nothing command: on error the contract set, id counter and
    /// event log are restored. This is the whole-command abort for errors nothing can catch
    /// (and for exceptions no `try` caught); a *caught* exception only rolls back to its
    /// own `begin_try` checkpoint (see the `UpdateHost` impl below). This is also the root
    /// boundary where an escaped `Thrown` is flattened to `UnhandledException`.
    fn atomically<T>(
        &mut self,
        act_as: &[&str],
        f: impl FnOnce(&mut Self) -> Result<T, EvalError>,
    ) -> Result<T, EvalError> {
        let contracts = self.contracts.clone();
        let keys = self.keys.clone();
        self.command_key_seq_start = self.next_key_seq;
        self.command_created.clear();
        let next_contract = self.next_contract;
        let events_len = self.events.len();
        self.authorizers = vec![act_as.iter().map(|p| (*p).to_string()).collect()];
        self.depth = 0;
        self.checkpoints.clear();
        self.command_creates = 0;
        self.command_events_start = events_len;
        self.next_node_idx = 0;
        // a rollback of an earlier command has no say in the positions of this one
        self.rolled_back.clear();
        self.recorded_key_lookups.clear();
        let result = f(self).map_err(EvalError::into_uncaught);
        self.authorizers.clear();
        self.depth = 0;
        self.command_key_seq_start = self.next_key_seq;
        self.command_created.clear();
        // Checkpoints still open here belong to try frames abandoned by an uncatchable
        // error; they must not leak into the next command.
        self.checkpoints.clear();
        if result.is_err() {
            self.contracts = contracts;
            self.keys = keys;
            self.next_contract = next_contract;
            self.events.truncate(events_len);
            self.rolled_back.clear();
            self.recorded_key_lookups.clear();
        }
        result
    }

    /// [CANTON-NOTE: SEMANTICS] Several commands submitted together are one transaction: when any of them fails, none of them
    /// takes effect (the Daml Script host's `Submit` of a `Commands` list).
    pub(crate) fn transaction_as<T>(
        &mut self,
        act_as: &[&str],
        f: impl FnOnce(&mut Self) -> Result<T, EvalError>,
    ) -> Result<T, EvalError> {
        self.check_disclosed_active()?;
        self.atomically(act_as, f)
    }

    /// [CANTON-NOTE: SEMANTICS] A top-level exercise of a contract the submitters cannot see fails as if the contract did not exist
    /// (measured on `daml script --ide-ledger`, `readAsMissing`): a stakeholder must be among the `actAs` or `readAs` parties.
    pub(crate) fn require_visible_to_command(
        &self,
        contract_id: &str,
        actors: &[&str],
    ) -> Result<(), EvalError> {
        let contract = self.lookup(contract_id)?;
        if self.visible_to_command(contract, actors) {
            Ok(())
        } else {
            Err(EvalError::ContractNotFound {
                contract_id: contract_id.to_string(),
            })
        }
    }

    /// The active contract of a template with this key resolved in Canton NUCK precedence (`command_created` newest-first,
    /// then `disclosed` in caller order, then global active contracts visible to `parties` ∪ `read_as` newest-first).
    pub fn contract_by_key(
        &self,
        package_id: &str,
        template_id: &str,
        key: &Value,
        parties: &[&str],
    ) -> Result<Option<&Contract>, EvalError> {
        Ok(self
            .resolve_keys(package_id, template_id, key, 1, |p| parties.contains(&p))?
            .into_iter()
            .next())
    }

    /// Resolves up to `n` active contracts matching `(package_id, template_id, key)` in Canton 3.7.2 NUCK order:
    /// 1. Contracts created in the current root command (`seq >= command_key_seq_start`), newest first.
    /// 2. Explicitly disclosed contracts (`disclosed_order`), in caller-supplied disclosure order.
    /// 3. Global active contracts visible to `visible_to_party ∪ self.read_as`, newest first (deduplicated).
    fn resolve_keys<'a>(
        &'a self,
        package_id: &str,
        template_id: &str,
        key: &Value,
        n: usize,
        mut visible_to_party: impl FnMut(&str) -> bool,
    ) -> Result<Vec<&'a Contract>, EvalError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let matches = |contract: &Contract, stored: &ContractKey| -> Result<bool, EvalError> {
            if !contract.active
                || contract.template_id != template_id
                || contract.package_id != package_id
            {
                return Ok(false);
            }
            values_equal(&stored.key, key)
        };

        // Tier 1: locally created in this command, newest first.
        let mut local: Vec<(u64, &Contract)> = Vec::new();
        for (cid, stored) in &self.keys {
            if stored.seq < self.command_key_seq_start {
                continue;
            }
            let Some(contract) = self.contracts.get(cid) else {
                continue;
            };
            if matches(contract, stored)? {
                local.push((stored.seq, contract));
            }
        }
        local.sort_by_key(|hit| std::cmp::Reverse(hit.0));

        let mut resolved: Vec<&Contract> = Vec::new();
        for (_, c) in local {
            resolved.push(c);
            if resolved.len() == n {
                return Ok(resolved);
            }
        }

        if let Some(resolutions) = &self.view_key_resolutions {
            let wanted = key.to_lf_value().encode_to_vec();
            if let Some((_, _, ids)) = resolutions
                .iter()
                .find(|(t, k, _)| t == template_id && *k == wanted)
            {
                for cid in ids {
                    let Some(contract) = self.contracts.get(cid) else {
                        continue;
                    };
                    if contract.active && !resolved.iter().any(|c| c.contract_id == *cid) {
                        resolved.push(contract);
                        if resolved.len() == n {
                            break;
                        }
                    }
                }
            }
            return Ok(resolved);
        }

        // Tier 2: explicitly disclosed contracts, in caller-supplied disclosure order.
        for cid in &self.disclosed_order {
            let (Some(contract), Some(stored)) = (self.contracts.get(cid), self.keys.get(cid))
            else {
                continue;
            };
            if stored.seq >= self.command_key_seq_start {
                continue;
            }
            if matches(contract, stored)? {
                resolved.push(contract);
                if resolved.len() == n {
                    return Ok(resolved);
                }
            }
        }

        // Tier 3: participant-known global contracts visible to submitters ∪ read_as, newest first, deduplicated.
        let mut global: Vec<(u64, &Contract)> = Vec::new();
        for (cid, stored) in &self.keys {
            if stored.seq >= self.command_key_seq_start || self.disclosed.contains(cid) {
                continue;
            }
            let Some(contract) = self.contracts.get(cid) else {
                continue;
            };
            let visible = contract
                .signatories
                .iter()
                .chain(&contract.observers)
                .any(|p| visible_to_party(p) || self.read_as.contains(p));
            if visible && matches(contract, stored)? {
                global.push((stored.seq, contract));
            }
        }
        global.sort_by_key(|hit| std::cmp::Reverse(hit.0));
        for (_, c) in global {
            resolved.push(c);
            if resolved.len() == n {
                break;
            }
        }
        Ok(resolved)
    }

    fn lookup(&self, contract_id: &str) -> Result<&Contract, EvalError> {
        let contract =
            self.contracts
                .get(contract_id)
                .ok_or_else(|| EvalError::ContractNotFound {
                    contract_id: contract_id.to_string(),
                })?;
        // [CANTON-NOTE: SEMANTICS] Speedy resolves ledger contracts with submitter visibility before
        // checking active status or template type (`TransactionConductor.resolveLedgerContract` runs
        // before `processSrcContract` -> `WronglyTypedContract`).
        if !self.visible_to_submitters(contract) {
            return Err(EvalError::ContractNotFound {
                contract_id: contract_id.to_string(),
            });
        }
        if !contract.active {
            return Err(EvalError::ContractNotActive {
                contract_id: contract_id.to_string(),
            });
        }
        Ok(contract)
    }

    /// Looks up an active contract and checks it really is a `template_id`. The LF
    /// `Exercise`/`Fetch` node names the template statically; trusting the id alone would
    /// let a contract of another type run a choice with the wrong payload shape.
    fn lookup_typed(
        &self,
        contract_id: &str,
        package_id: &str,
        template_id: &str,
    ) -> Result<&Contract, EvalError> {
        let contract = self.lookup(contract_id)?;
        if contract.package_id != package_id || contract.template_id != template_id {
            return Err(EvalError::WrongContractTemplate {
                contract_id: contract_id.to_string(),
                actual: format!("{}:{}", contract.package_id, contract.template_id),
                expected: format!("{package_id}:{template_id}"),
            });
        }
        Ok(contract)
    }

    /// [CANTON-NOTE: SEMANTICS] A fetch (and a key lookup) only sees contracts the submitting parties can see: a
    /// stakeholder is among the top-level `actAs` parties, or the contract was created by this very command. Measured on
    /// JVM 3.7.2: fetching a contract whose only stakeholder is someone else is `not-found` (`mint_other_dso_round`,
    /// `fetchByOther`).
    /// [CANTON-NOTE: SEMANTICS] A fetch is authorized when at least one stakeholder of the fetched contract is among the
    /// parties authorizing the running code (top-level `actAs`, or the signatories and controllers of the enclosing
    /// exercise). Speedy `authorizeFetch` (`stakeholders ∩ authParties ≠ ∅`, else `FetchMissingAuthorization`); the JVM
    /// reports it as an authorization error. It only bites once a contract is visible without being authorized, i.e.
    /// through `readAs` (a party that cannot see a contract gets `not-found` first).
    fn authorize_fetch(&self, contract: &Contract) -> Result<(), EvalError> {
        let authorizers = self.current_authorizers()?;
        let stakeholders: Vec<String> = contract
            .signatories
            .iter()
            .chain(&contract.observers)
            .cloned()
            .collect();
        if stakeholders.iter().any(|p| authorizers.contains(p)) {
            return Ok(());
        }
        Err(EvalError::Unauthorized {
            kind: AuthKind::Stakeholders,
            what: format!("fetch of {}", contract.template_id),
            required: stakeholders.clone(),
            missing: stakeholders.clone(),
            authorized: authorizers.clone(),
            detail: Some(Box::new(AuthDetail {
                node_id: self.next_node_idx,
                rule: AuthRule::FetchMissingAuthorization,
                template_id: format!("{}:{}", contract.package_id, contract.template_id),
                required_parties: stakeholders,
                context_parties: authorizers.clone(),
            })),
        })
    }

    /// Top-level visibility of an exercise target: created in this command, explicitly disclosed, or a stakeholder among `actors ∪ readAs`.
    fn visible_to_command<A: AsRef<str>>(&self, contract: &Contract, actors: &[A]) -> bool {
        self.command_created.contains(&contract.contract_id)
            || self.disclosed.contains(&contract.contract_id)
            || contract
                .signatories
                .iter()
                .chain(contract.observers.iter())
                .any(|stakeholder| {
                    actors.iter().any(|a| a.as_ref() == stakeholder)
                        || self.read_as.contains(stakeholder)
                })
    }

    /// [CANTON-NOTE: SEMANTICS] Submitter visibility is `stakeholder ∈ (actAs ∪ readAs)` OR created in the current
    /// command OR explicitly disclosed (`disclose`). Canton 3.7.2 does not divulge contracts via witnessed fetches
    /// (`tests/oracle/divulgence`: `queryContractId` stays `None` after a witnessed `fetch`).
    fn visible_to_submitters(&self, contract: &Contract) -> bool {
        let Some(submitters) = self.authorizers.first() else {
            return true;
        };
        if submitters.is_empty() && self.read_as.is_empty() {
            return true;
        }
        self.command_created.contains(&contract.contract_id)
            || self.disclosed.contains(&contract.contract_id)
            || contract
                .signatories
                .iter()
                .chain(&contract.observers)
                .any(|p| submitters.contains(p) || self.read_as.contains(p))
    }

    /// Marks a contract as disclosed to the submitters in caller-supplied order (deduplicated, preserving first occurrence).
    /// Answers key queries that reach beyond the contracts created in the current command from the given resolutions only, in the given
    /// order, instead of from the engine's own contracts.
    ///
    /// [CANTON-NOTE: SEMANTICS] A participant that validates a view reinterprets it with the key resolutions the view states
    /// (`ViewParticipantData.resolved_keys`): the answer to a `queryNByKey` is the stated contract ids, in order, cut to `n`, not
    /// whatever the validator's own store holds (`ModelConformanceChecker` resolves keys from the view; UNRESOLVED U-21).
    pub fn resolve_keys_from_view(&mut self, resolutions: Vec<ViewKeyResolution>) {
        self.view_key_resolutions = Some(resolutions);
    }

    pub fn disclose(&mut self, contract_id: &str) {
        if self.disclosed.insert(contract_id.to_string()) {
            self.disclosed_order.push(contract_id.to_string());
        }
    }

    /// Clears all explicitly disclosed contracts.
    pub fn clear_disclosed(&mut self) {
        self.disclosed.clear();
        self.disclosed_order.clear();
    }

    /// Replaces the explicit disclosure set with `contract_ids` in caller-supplied order.
    pub fn set_disclosed<I, S>(&mut self, contract_ids: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.clear_disclosed();
        for cid in contract_ids {
            self.disclose(cid.as_ref());
        }
    }

    /// Rejects any explicitly disclosed contract already known to be archived before executing a command
    /// (Canton 3.7.2 JVM `--ide-ledger` validates disclosed inputs upfront, returning `NotActive`).
    pub(crate) fn check_disclosed_active(&self) -> Result<(), EvalError> {
        for cid in &self.disclosed_order {
            if let Some(c) = self.contracts.get(cid) {
                if !c.active {
                    return Err(EvalError::ContractNotActive {
                        contract_id: cid.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn record_key(&mut self, contract_id: &str, key: Value) {
        let seq = self.next_key_seq;
        self.next_key_seq += 1;
        self.keys
            .insert(contract_id.to_string(), ContractKey { key, seq });
    }

    fn current_authorizers(&self) -> Result<&BTreeSet<String>, EvalError> {
        self.authorizers
            .last()
            .ok_or_else(|| EvalError::Host("no authorization context".to_string()))
    }
}

impl Engine<'_> {
    /// Picks the id of a contract being created right now.
    ///
    /// Default scheme `#n` skips ids already present, so it cannot collide with contracts
    /// seeded through `import_contract` that happen to look like `#n` too. An injected
    /// allocator is trusted to be unique, but a duplicate is still refused: overwriting an
    /// existing contract would silently destroy ledger state.
    fn allocate_contract_id(
        &mut self,
        package_id: &str,
        template_id: &str,
        payload: &Value,
        signatories: &[String],
        observers: &[String],
        key: Option<(&Value, &[String])>,
    ) -> Result<String, EvalError> {
        let creation_index = self.command_creates;
        self.command_creates += 1;
        let (tracker, _) = NodePaths::of_events_with_rollbacks(
            &self.events[self.command_events_start..],
            self.command_events_start,
            &self.rolled_back,
        );
        let path = tracker.peek(self.depth);
        let contract_id = match self.allocator.as_mut() {
            Some(allocator) => allocator.allocate(&NewContract {
                package_id,
                template_id,
                payload,
                signatories,
                observers,
                creation_index,
                depth: self.depth,
                path: &path,
                key,
            }),
            None => loop {
                self.next_contract += 1;
                let candidate = format!("#{}", self.next_contract);
                if !self.contracts.contains_key(&candidate) {
                    break candidate;
                }
            },
        };
        if self.contracts.contains_key(&contract_id) {
            return Err(EvalError::Host(format!(
                "contract id {contract_id} was allocated twice"
            )));
        }
        Ok(contract_id)
    }

    /// Removes `checkpoint` and every newer one from the stack and returns it.
    fn take_checkpoint(&mut self, checkpoint: TryCheckpoint) -> Result<Checkpoint, EvalError> {
        if checkpoint.0 >= self.checkpoints.len() {
            return Err(EvalError::Host(format!(
                "stale try checkpoint {} ({} open)",
                checkpoint.0,
                self.checkpoints.len()
            )));
        }
        self.checkpoints.truncate(checkpoint.0 + 1);
        self.checkpoints
            .pop()
            .ok_or_else(|| EvalError::Host("no open try checkpoint".to_string()))
    }
}
