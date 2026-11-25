//! A Daml Script host (G10, AT-K06): runs a `Script a` of a compiled package the way `daml script --ide-ledger` does.
//!
//! [CANTON-NOTE: SEMANTICS] A script is a record `Script{runScript: () -> Free ScriptF (a, ())}`. Running it unwraps the free monad:
//! `Pure (a, ())` is the result; `Free ScriptF{unpack = Question{commandName, commandVersion, payload, continue}}` is a question to
//! the ledger, answered by applying `continue` to the answer. The library's `dangerousCast` is the identity here (the evaluator's
//! `SCRIPT_DANGEROUS_CAST`), exactly as the official runner replaces it.
//!
//! [CANTON-NOTE: LIMITATION] Only the commands listed in `Script::answer` are served; any other question stops the run with
//! `ScriptError::Unsupported(<commandName>)` and never with an invented answer.
//!
//! A host runs either on its own in-memory IDE ledger ([`ScriptHost::new`]) or against a participant ([`ScriptHost::remote`] with a
//! [`ScriptLedger`]): the questions are the same, only where the answers come from differs.
use crate::engine::Engine;
use crate::ledger::IdePartyAllocator;
use crate::{EvalError, ExerciseRequest, List, UpdateHost, Value, World};

/// One command of a submission, as a remote ledger is asked to run it (S-SCRIPT-002). `template` is `Module:Name`.
#[derive(Debug, Clone)]
pub enum LedgerCommand {
    Create {
        package_id: String,
        template: String,
        argument: Value,
    },
    Exercise {
        package_id: String,
        template: String,
        contract_id: String,
        choice: String,
        argument: Value,
    },
    CreateAndExercise {
        package_id: String,
        template: String,
        argument: Value,
        choice: String,
        choice_argument: Value,
    },
}

/// What one command produced, in command order (a create-and-exercise produces both).
#[derive(Debug, Clone)]
pub enum LedgerResult {
    Created(String),
    Exercised(Value),
}

/// A participant a script runs against (`daml script --ledger-host`): parties, submissions, the active contract set and time.
pub trait ScriptLedger {
    /// Allocates a party; `hint` is the id hint (or the requested name when there is no hint).
    fn allocate_party(&mut self, hint: &str) -> Result<String, String>;
    /// The parties the participant knows, with whether each is local.
    fn known_parties(&mut self) -> Result<Vec<(String, bool)>, String>;
    /// Runs one submission as one transaction. The outer error is a failure to talk to the ledger; the inner one is the ledger
    /// refusing the submission (what `submitMustFail` / `trySubmit` see as `Left`).
    fn submit(
        &mut self,
        act_as: &[String],
        read_as: &[String],
        commands: &[LedgerCommand],
    ) -> Result<Result<Vec<LedgerResult>, String>, String>;
    /// The active contracts of the template that one of `parties` can see: `(contract id, argument)`.
    fn active_contracts(
        &mut self,
        parties: &[String],
        package_id: &str,
        template: &str,
    ) -> Result<Vec<(String, Value)>, String>;
    /// The ledger's current time (microseconds since the epoch).
    fn now_micros(&mut self) -> Result<i64, String>;
}

fn remote_err(e: String) -> ScriptError {
    ScriptError::Eval(e)
}

#[derive(Debug, PartialEq)]
pub enum ScriptError {
    /// The evaluator failed while running the script.
    Eval(String),
    /// The script asked a question this host does not answer.
    Unsupported(String),
    /// The value is not the shape of a script step.
    Shape(String),
}

impl From<EvalError> for ScriptError {
    fn from(error: EvalError) -> Self {
        Self::Eval(match error {
            // [CANTON-NOTE: SEMANTICS] The script runner's spelling of a Daml exception nobody caught. The category 9 is measured for
            // every kind the fixture throws: `GeneralError` (`abort`, `error`, `throw`), a user exception, `ArithmeticError` (thrown, and
            // a division by zero), `AssertionFailed` (thrown, and a failed `assert`) and `PreconditionFailed` (failures.tsv).
            EvalError::UnhandledException { error_id, message } => {
                format!("Error: User failure: {error_id} (error category 9): {message}")
            }
            other => other.to_string(),
        })
    }
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eval(m) => write!(f, "evaluation failed: {m}"),
            Self::Unsupported(c) => write!(f, "script command {c} is not served by this host"),
            Self::Shape(m) => write!(f, "unexpected script shape: {m}"),
        }
    }
}

/// `scala.collection.Hashing.improve`, which Scala 2.13's CHAMP `HashMap`/`HashSet` apply to a key's `##`.
fn scala_improve(hcode: i32) -> u32 {
    let mut h = hcode.wrapping_add(!(hcode << 9));
    h ^= ((h as u32) >> 14) as i32;
    h = h.wrapping_add(h << 4);
    (h ^ ((h as u32) >> 10) as i32) as u32
}

/// The order a Scala 2.13 CHAMP `HashMap`/`HashSet` iterates its keys in, from each key's improved hash: a node's own entries before its
/// sub-nodes, both by the 5 hash bits of the level, lowest bits first. It depends on the whole set (whether a key sits in a node or in a
/// sub-node depends on the others), so a subset is ordered by filtering the whole set's order.
fn champ_order<K: Clone>(keys: Vec<(K, u32)>) -> Vec<K> {
    fn walk<K: Clone>(keys: Vec<(K, u32)>, shift: u32, out: &mut Vec<K>) {
        if shift >= 32 {
            // a full hash collision: a collision node keeps them as inserted
            out.extend(keys.into_iter().map(|(k, _)| k));
            return;
        }
        let mut groups: std::collections::BTreeMap<u32, Vec<(K, u32)>> = Default::default();
        for (k, h) in keys {
            groups.entry((h >> shift) & 31).or_default().push((k, h));
        }
        out.extend(
            groups
                .values()
                .filter(|g| g.len() == 1)
                .map(|g| g[0].0.clone()),
        );
        for group in groups.into_values().filter(|g| g.len() > 1) {
            walk(group, shift + 5, out);
        }
    }
    let mut out = Vec::with_capacity(keys.len());
    walk(keys, 0, &mut out);
    out
}

fn java_string_hash(s: &str) -> i32 {
    s.encode_utf16()
        .fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(c as i32))
}

/// The order a Scala 2.13 immutable `Map[String, _]` iterates its keys in, given in insertion order: as inserted up to four keys
/// (`Map1`..`Map4`), and beyond that the order of the CHAMP `HashMap` they become ([`champ_order`] of `String.hashCode`).
///
/// [CANTON-NOTE: SEMANTICS] The IDE ledger keeps its parties in such a map, and `listKnownParties` lists them in its order. Measured
/// (`remoteSuite` on `daml script --ide-ledger`, 26 parties): reproduced exactly. The fixture's four parties of `hintsAndOrder` come out in
/// allocation order, as a `Map4` keeps them.
fn scala_map_order(keys: &[String]) -> Vec<&String> {
    if keys.len() <= 4 {
        return keys.iter().collect();
    }
    champ_order(
        keys.iter()
            .map(|k| (k, scala_improve(java_string_hash(k))))
            .collect(),
    )
}

/// The order a participant's Ledger API lists the witnesses of an event in: up to four parties alphabetically, more than four in the order of a
/// Scala 2.13 CHAMP `HashSet[String]` ([`champ_order`] of `String.hashCode`).
///
/// [CANTON-NOTE: SEMANTICS] Measured on the hub's Canton 3.7.2 participant (`/v2/updates`, 62 transactions, 88 events): every witness list of up to
/// four parties was sorted, and the three lists of five to nine parties came out in exactly the CHAMP order of the party texts (`Holder`,
/// `HubLocalProbe`, `Beneficiary`, `SettlementBank_TEST`, `Exporter`, ...). A `Set` of up to four elements keeps the order it was built in, which
/// is sorted.
pub fn scala_witness_order(parties: &[String]) -> Vec<String> {
    if parties.len() <= 4 {
        let mut sorted = parties.to_vec();
        sorted.sort();
        return sorted;
    }
    champ_order(
        parties
            .iter()
            .map(|k| (k.clone(), scala_improve(java_string_hash(k))))
            .collect(),
    )
}

/// `ContractId.##` of a Daml-LF V1 contract id given as hex (`00` + 32-byte discriminator + suffix): the case class's
/// `MurmurHash3.productHash` over `"V1"`, the discriminator (`Hash.hashCode` = its bytes') and the suffix, each byte string hashed as a
/// protobuf `ByteString` (`size`, then `h * 31 + byte` over signed bytes, 0 made 1). Any other id is hashed as its text.
fn contract_id_hash(id: &str) -> i32 {
    fn mix(h: u32, data: u32) -> u32 {
        let mut k = data.wrapping_mul(0xcc9e_2d51);
        k = k.rotate_left(15).wrapping_mul(0x1b87_3593);
        (h ^ k)
            .rotate_left(13)
            .wrapping_mul(5)
            .wrapping_add(0xe654_6b64)
    }
    fn finalize(h: u32, length: u32) -> u32 {
        let mut h = h ^ length;
        h ^= h >> 16;
        h = h.wrapping_mul(0x85eb_ca6b);
        h ^= h >> 13;
        h = h.wrapping_mul(0xc2b2_ae35);
        h ^ (h >> 16)
    }
    fn byte_string_hash(bytes: &[u8]) -> u32 {
        let h = bytes.iter().fold(bytes.len() as u32, |h, b| {
            h.wrapping_mul(31).wrapping_add(*b as i8 as i32 as u32)
        });
        if h == 0 {
            1
        } else {
            h
        }
    }
    match hex::decode(id) {
        Ok(bytes) if bytes.len() > 33 && bytes[0] == 0 => {
            let mut h = mix(0xcafe_babe, java_string_hash("V1") as u32);
            h = mix(h, byte_string_hash(&bytes[1..33]));
            h = mix(h, byte_string_hash(&bytes[33..]));
            finalize(h, 2) as i32
        }
        _ => java_string_hash(id),
    }
}

/// The IDE ledger's set of active contracts (`IdeLedger.LedgerData.activeContracts`, an immutable `Set[ContractId]`), kept for its
/// iteration order, which is the order `query` lists contracts in (`activeContracts.toList`, then filtered).
///
/// [CANTON-NOTE: SEMANTICS] A Scala 2.13 `Set` keeps insertion order up to four elements (`Set1`..`Set4`, a removal keeps the order); a
/// fifth makes it a CHAMP `HashSet`, which stays one when it shrinks again, and orders by [`contract_id_hash`]. A submission adds the
/// contracts it created and then removes the ones it consumed (`++ localContractIds -- inactiveContracts`). Measured (`queryOrderIds` on
/// `daml script --ide-ledger`): eight contracts in exactly the official order.
#[derive(Default)]
struct IdeActiveSet {
    /// `Some` while the set is a `Set1`..`Set4` (in insertion order); `None` once it became a `HashSet`.
    small: Option<Vec<String>>,
    all: std::collections::BTreeSet<String>,
}

impl IdeActiveSet {
    fn new() -> Self {
        Self {
            small: Some(Vec::new()),
            all: Default::default(),
        }
    }

    fn add(&mut self, id: &str) {
        if !self.all.insert(id.to_string()) {
            return;
        }
        if let Some(small) = &mut self.small {
            if small.len() < 4 {
                small.push(id.to_string());
            } else {
                self.small = None;
            }
        }
    }

    fn remove(&mut self, id: &str) {
        if self.all.remove(id) {
            if let Some(small) = &mut self.small {
                small.retain(|c| c != id);
            }
        }
    }

    fn order(&self) -> Vec<String> {
        match &self.small {
            Some(small) => small.clone(),
            None => champ_order(
                self.all
                    .iter()
                    .map(|id| (id.clone(), scala_improve(contract_id_hash(id))))
                    .collect(),
            ),
        }
    }
}

/// A run of scripts against an in-memory ledger.
pub struct ScriptHost<'a> {
    world: &'a World,
    parties: IdePartyAllocator,
    ledger: Engine<'a>,
    /// The IDE ledger's clock (microseconds); `--static-time` starts it at the epoch.
    now_micros: i64,
    /// The parties allocated so far, in allocation order.
    known: Vec<String>,
    /// The users the IDE ledger knows, by user id.
    users: std::collections::BTreeMap<String, ScriptUser>,
    /// A participant to run against instead of the IDE ledger (`daml script --ledger-host`).
    remote: Option<Box<dyn ScriptLedger + 'a>>,
    /// Submissions made so far on the IDE ledger: the index of the next one seeds its contract ids.
    submissions: usize,
    /// The IDE ledger's active contracts in the order it keeps them.
    active: IdeActiveSet,
}

/// A user of the IDE ledger: its `User` value as the script made it, and the rights it holds in the order they were granted.
struct ScriptUser {
    user: Value,
    rights: Vec<Value>,
}

fn field<'v>(value: &'v Value, name: &str) -> Result<&'v Value, ScriptError> {
    match value {
        Value::Record { fields, .. } => fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
            .ok_or_else(|| ScriptError::Shape(format!("no field {name}"))),
        other => Err(ScriptError::Shape(format!(
            "{name} of a non-record {other:?}"
        ))),
    }
}

fn text(value: &Value) -> Result<&str, ScriptError> {
    match value {
        Value::Text(t) => Ok(t),
        other => Err(ScriptError::Shape(format!("text expected, got {other:?}"))),
    }
}

impl<'a> ScriptHost<'a> {
    pub fn new(world: &'a World) -> Self {
        let mut ledger = Engine::new(world);
        // [CANTON-NOTE: SEMANTICS] The IDE ledger's contract ids: Daml-LF V1, seeded by the submission's index in the script and the node's
        // place (`IdeContractIdAllocator`, checked against `daml script --ide-ledger` in tests/oracle/tx-corpus/cid-expected.tsv).
        if let Ok(name) = crate::typed_json::Types::new(world).package_name(world.main_package_id())
        {
            ledger.set_contract_id_allocator(crate::ledger::IdeContractIdAllocator::new(name));
        }
        Self {
            world,
            parties: IdePartyAllocator::new(),
            ledger,
            now_micros: 0,
            known: Vec::new(),
            users: Default::default(),
            remote: None,
            submissions: 0,
            active: IdeActiveSet::new(),
        }
    }

    /// A host whose ledger questions are answered by `ledger` (a participant) instead of the in-memory IDE ledger.
    pub fn remote(world: &'a World, ledger: Box<dyn ScriptLedger + 'a>) -> Self {
        let mut host = Self::new(world);
        host.remote = Some(ledger);
        host
    }

    /// A question to a remote ledger, or `None` when this host runs on the IDE ledger (or the question is not a ledger one).
    fn answer_remote(
        &mut self,
        command: &str,
        payload: &Value,
    ) -> Option<Result<Value, ScriptError>> {
        self.remote.as_ref()?;
        // [CANTON-NOTE: SEMANTICS] Measured against a Canton 3.7.2 participant (`daml script --ledger-host`): `allocateParty "alice"`
        // asks for the id hint `alice-d4d95138`, the same suffix sequence the IDE ledger uses (so a second run of the same script on
        // the same participant is refused: the party exists); an explicit id hint is sent as it is.
        if command == "AllocateParty" {
            let asked = (|| {
                let hint = text(field(payload, "idHint")?)?.to_string();
                let requested = text(field(payload, "requestedName")?)?.to_string();
                if !hint.is_empty() && !requested.is_empty() && hint != requested {
                    return Err(ScriptError::Eval(format!(
                        "Requested name '{requested}' cannot be different from id hint '{hint}'"
                    )));
                }
                Ok(if hint.is_empty() {
                    self.parties.allocate_party(&requested)
                } else {
                    hint
                })
            })();
            let ledger = self.remote.as_mut()?;
            return Some(asked.and_then(|asked| {
                ledger
                    .allocate_party(&asked)
                    .map(Value::Party)
                    .map_err(remote_err)
            }));
        }
        let ledger = self.remote.as_mut()?;
        Some(match command {
            "ListKnownParties" => ledger.known_parties().map_err(remote_err).map(|ps| {
                Value::List(List::from(
                    ps.into_iter()
                        .map(|(party, local)| Value::Record {
                            tycon: None,
                            fields: vec![
                                ("party".into(), Value::Party(party)),
                                ("displayName".into(), Value::Optional(None)),
                                ("isLocal".into(), Value::Bool(local)),
                            ],
                        })
                        .collect::<Vec<_>>(),
                ))
            }),
            "GetTime" => ledger.now_micros().map(Value::Int64).map_err(remote_err),
            "Sleep" => {
                let micros = match field(payload, "rel_time")
                    .or_else(|_| field(payload, "relTime"))
                    .or_else(|_| field(payload, "duration"))
                {
                    Ok(Value::Record { fields, .. }) => match fields.first() {
                        Some((_, Value::Int64(m))) => *m,
                        _ => 0,
                    },
                    Ok(Value::Int64(m)) => *m,
                    _ => 0,
                };
                std::thread::sleep(std::time::Duration::from_micros(micros.max(0) as u64));
                Ok(Value::Unit)
            }
            // [CANTON-NOTE: SEMANTICS] Setting the time needs a ledger on static time; a participant's JSON API has no time service.
            "SetTime" => Err(ScriptError::Unsupported(
                "SetTime (a participant's JSON API has no time service)".into(),
            )),
            "Submit" | "QueryACS" | "QueryContractId" => return None,
            "QueryByKey" | "CreateUser" | "GetUser" | "ListAllUsers" | "DeleteUser"
            | "ListUserRights" | "GrantUserRights" | "RevokeUserRights" => Err(
                ScriptError::Unsupported(format!("{command} on a remote ledger")),
            ),
            _ => return None,
        })
    }

    /// Run script `name` of `module` and return the value it ends with.
    pub fn run(&mut self, module: &str, name: &str) -> Result<Value, ScriptError> {
        let script = self.world.eval(module, name, &[])?;
        let step = self
            .world
            .apply_off_ledger(field(&script, "runScript")?, vec![Value::Unit])?;
        match self.drive(step)? {
            Outcome::Done(value) => Ok(value),
            // [CANTON-NOTE: SEMANTICS] An exception the script throws and nothing catches ends the run (measured: `abort "boom"`
            // dies with the exception's message).
            Outcome::Thrown(exception) => {
                // [CANTON-NOTE: SEMANTICS] The library throws its own errors (`InvalidUserId`, `UserNotFound`, ...) as a `toAny` of the
                // exception record, not as an `AnyException`: it is the same exception, named by the record's type.
                let exception = match exception {
                    Value::Any { key, payload } => {
                        let tycon = match payload.as_ref() {
                            Value::Record { tycon: Some(t), .. } => t.clone(),
                            _ => key
                                .split_once(':')
                                .map_or(key.clone(), |(_, t)| t.to_string()),
                        };
                        Value::AnyException { tycon, payload }
                    }
                    other => other,
                };
                let (tycon, _) = crate::exception_parts(&exception);
                // the exception's own `message` definition, as the machine evaluates it
                let message = match self.world.apply_off_ledger(
                    &Value::Partial {
                        builtin: crate::ANY_EXCEPTION_MESSAGE,
                        types: Vec::new(),
                        args: Vec::new(),
                    },
                    vec![exception],
                )? {
                    Value::Text(message) => message,
                    other => return Err(ScriptError::Shape(format!("{other:?}"))),
                };
                Err(EvalError::UnhandledException {
                    error_id: format!("UNHANDLED_EXCEPTION/{tycon}"),
                    message,
                }
                .into())
            }
        }
    }

    /// Unwrap the free monad from `step` until the script ends or throws.
    fn drive(&mut self, mut step: Value) -> Result<Outcome, ScriptError> {
        loop {
            match step {
                Value::Variant {
                    constructor, value, ..
                } if constructor == "Pure" => {
                    // the result is the pair (a, ())
                    return Ok(Outcome::Done(field(&value, "_1")?.clone()));
                }
                Value::Variant {
                    constructor, value, ..
                } if constructor == "Free" => {
                    let question = field(&value, "unpack")?;
                    let command = text(field(question, "commandName")?)?.to_string();
                    let payload = field(question, "payload")?;
                    let answer = match command.as_str() {
                        // an exception thrown by the script: the rest of this (nested) script never runs
                        "Throw" => return Ok(Outcome::Thrown(field(payload, "exc")?.clone())),
                        // `try ... catch`: run the nested script; a thrown exception is the `Left`, its value the `Right`
                        "Catch" => {
                            let mut nested = self
                                .world
                                .apply_off_ledger(field(payload, "act")?, vec![Value::Unit])?;
                            // the action may be the `Script` itself: its `runScript` is what runs
                            if let Ok(run) = field(&nested, "runScript") {
                                nested = self.world.apply_off_ledger(run, vec![Value::Unit])?;
                            }
                            match self.drive(nested).map_err(|e| catch_failed(&e))? {
                                Outcome::Done(value) => either(true, value),
                                Outcome::Thrown(exception) => either(false, exception),
                            }
                        }
                        _ => self.answer(&command, payload)?,
                    };
                    step = self
                        .world
                        .apply_off_ledger(field(question, "continue")?, vec![answer])?;
                }
                other => return Err(ScriptError::Shape(format!("{other:?}"))),
            }
        }
    }

    /// The ledger's answer to one question.
    fn answer(&mut self, command: &str, payload: &Value) -> Result<Value, ScriptError> {
        if let Some(answer) = self.answer_remote(command, payload) {
            return answer;
        }
        match command {
            // [CANTON-NOTE: SEMANTICS] Measured on `daml script --ide-ledger`: a name and an id hint that differ are refused
            // (`ConverterException: Requested name '<n>' cannot be different from id hint '<h>'`); an id hint is the party
            // exactly and uses up no random suffix; a name alone gets the IDE ledger's random suffix.
            "AllocateParty" => {
                let hint = text(field(payload, "idHint")?)?;
                let requested = text(field(payload, "requestedName")?)?;
                if !hint.is_empty() && !requested.is_empty() && hint != requested {
                    return Err(ScriptError::Eval(format!(
                        "Requested name '{requested}' cannot be different from id hint '{hint}'"
                    )));
                }
                let party = if !hint.is_empty() {
                    hint.to_string()
                } else {
                    self.parties.allocate_party(requested)
                };
                self.known.push(party.clone());
                Ok(Value::Party(party))
            }
            // the parties in allocation order (measured), each as `PartyDetails`
            "ListKnownParties" => Ok(Value::List(List::from(
                scala_map_order(&self.known)
                    .into_iter()
                    .map(|party| Value::Record {
                        tycon: None,
                        fields: vec![
                            ("party".into(), Value::Party(party.clone())),
                            ("displayName".into(), Value::Optional(None)),
                            ("isLocal".into(), Value::Bool(true)),
                        ],
                    })
                    .collect::<Vec<_>>(),
            ))),
            // [CANTON-NOTE: SEMANTICS] Measured with `--static-time`: `sleep` returns and the clock stays where it was
            // (`sleepClock` reads the epoch after `sleep (seconds 5)`). Wall-clock mode is not served.
            "Sleep" => Ok(Value::Unit),
            "GetTime" => Ok(Value::Int64(self.now_micros)),
            "SetTime" => {
                let Value::Int64(micros) = field(payload, "time")? else {
                    return Err(ScriptError::Shape("time".into()));
                };
                self.now_micros = *micros;
                self.ledger.set_time_micros(*micros);
                Ok(Value::Unit)
            }
            // [CANTON-NOTE: SEMANTICS] User management of the IDE ledger (measured on `daml script --ide-ledger`, tests/oracle/script-host
            // users-measured.tsv): every question but `ListAllUsers` is answered with an `Optional`: `None` of `ValidateUserId` is "valid", and for
            // the others `Some` is success (`()` for create and delete, the user, its rights or the rights that changed for the rest) and
            // `None` is the failure the library throws (`UserAlreadyExists`, `UserNotFound`). The ledger starts with **no**
            // user. Users are listed **by name** (`amy` before `zed` created first); a user's rights **in the order they were granted**;
            // granting a right the user holds answers only what was newly granted, revoking one it does not hold answers `[]`; a user
            // that is not there answers `None`, which the library throws as the catchable `UserNotFound`.
            "ValidateUserId" => {
                let name = text(field(payload, "name")?)?;
                Ok(Value::Optional(
                    validate_user_id(name).map(|err| Box::new(Value::Text(err))),
                ))
            }
            // [CANTON-NOTE: SEMANTICS] Measured (`usersCreateTwice`, `usersDeleteMissing`): the answer to creating an existing user and to
            // deleting a missing one is `None`; the library turns it into `UserAlreadyExists` / `UserNotFound` (message: the user id).
            "CreateUser" => {
                let user = field(payload, "user")?.clone();
                let id = user_id(&user)?;
                let rights = list_items(field(payload, "rights")?)?;
                if self.users.contains_key(&id) {
                    return Ok(Value::Optional(None));
                }
                let mut held: Vec<Value> = Vec::new();
                for right in rights {
                    if !held.contains(&right) {
                        held.push(right);
                    }
                }
                self.users.insert(id, ScriptUser { user, rights: held });
                Ok(Value::Optional(Some(Box::new(Value::Unit))))
            }
            "GetUser" => Ok(Value::Optional(
                self.users
                    .get(&user_id_of(payload)?)
                    .map(|u| Box::new(u.user.clone())),
            )),
            "ListAllUsers" => Ok(Value::List(List::from(
                self.users
                    .values()
                    .map(|u| u.user.clone())
                    .collect::<Vec<_>>(),
            ))),
            "DeleteUser" => {
                let id = user_id_of(payload)?;
                if self.users.remove(&id).is_none() {
                    return Ok(Value::Optional(None));
                }
                Ok(Value::Optional(Some(Box::new(Value::Unit))))
            }
            "ListUserRights" => {
                Ok(Value::Optional(self.users.get(&user_id_of(payload)?).map(
                    |u| Box::new(Value::List(List::from(u.rights.clone()))),
                )))
            }
            "GrantUserRights" | "RevokeUserRights" => {
                let id = user_id_of(payload)?;
                let asked = list_items(field(payload, "rights")?)?;
                let grant = command == "GrantUserRights";
                let Some(user) = self.users.get_mut(&id) else {
                    return Ok(Value::Optional(None));
                };
                let mut changed: Vec<Value> = Vec::new();
                for right in asked {
                    let held = user.rights.contains(&right);
                    if grant && !held {
                        user.rights.push(right.clone());
                        changed.push(right);
                    } else if !grant && held {
                        user.rights.retain(|r| r != &right);
                        changed.push(right);
                    }
                }
                Ok(Value::Optional(Some(Box::new(Value::List(List::from(
                    changed,
                ))))))
            }
            "Submit" => self.submit(payload),
            "QueryACS" => self.query(payload),
            "QueryContractId" => self.query_contract_id(payload),
            "QueryByKey" => self.query_by_key(payload),
            other => Err(ScriptError::Unsupported(other.to_string())),
        }
    }

    /// `Submit`: each submission is one transaction on the engine (all its commands or none); the answer is, per submission,
    /// `Right ([CommandResult], tree)`, or `Left error` when the submission failed and was asked to (`submitMustFail`).
    ///
    /// [CANTON-NOTE: LIMITATION] The transaction tree of the answer and the error of a `Left` are `()`: `submit` discards the tree
    /// (`fst`) and `submitMustFail` only looks at which side it is; `submitTree` and `trySubmit` would read them.
    fn submit(&mut self, payload: &Value) -> Result<Value, ScriptError> {
        if self.remote.is_some() {
            return self.submit_remote(payload);
        }
        let Value::List(submissions) = field(payload, "submissions")? else {
            return Err(ScriptError::Shape("submissions".into()));
        };
        let mut answers = Vec::new();
        for submission in submissions.iter() {
            let must_fail = match field(submission, "sErrorBehaviour")? {
                Value::Enum { constructor, .. } if constructor == "MustSucceed" => false,
                // `trySubmit` (`Try`) and `submitMustFail` answer alike: `Left` when the submission failed, `Right` when it did not
                Value::Enum { constructor, .. }
                    if constructor == "MustFail" || constructor == "Try" =>
                {
                    true
                }
                other => return Err(ScriptError::Shape(format!("{other:?}"))),
            };
            let act_as = non_empty_parties(field(submission, "sActAs")?)?;
            let acting: Vec<&str> = act_as.iter().map(String::as_str).collect();
            // [CANTON-NOTE: SEMANTICS] `readAs` parties let the submission see their contracts and give it no authority
            // (measured: `readAsWorks` exercises another party's contract only with `readAs`; `readAsMissing` is refused without).
            let Value::List(read_as) = field(submission, "sReadAs")? else {
                return Err(ScriptError::Shape("sReadAs".into()));
            };
            let read_as: Vec<String> = read_as
                .iter()
                .filter_map(|p| match p {
                    Value::Party(p) => Some(p.clone()),
                    _ => None,
                })
                .collect();
            self.ledger.set_read_as(&read_as);
            // [CANTON-NOTE: SEMANTICS] Explicit disclosures preserve caller order for key resolution without granting authority.
            let disclosures = match field(submission, "sDisclosures") {
                Ok(Value::List(items)) => items
                    .iter()
                    .map(|d| match field(d, "contractId")? {
                        Value::ContractId(cid) => Ok(cid.clone()),
                        other => Err(ScriptError::Shape(format!(
                            "disclosure contractId: {other:?}"
                        ))),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                Ok(other) => return Err(ScriptError::Shape(format!("sDisclosures: {other:?}"))),
                Err(_) => Vec::new(),
            };
            self.ledger.set_disclosed(&disclosures);
            let Value::List(commands) = field(submission, "sCommands")? else {
                self.ledger.clear_disclosed();
                self.ledger.set_read_as::<&str>(&[]);
                return Err(ScriptError::Shape("sCommands".into()));
            };
            let commands = match commands
                .iter()
                .map(|with_meta| field(with_meta, "command"))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(cmds) => cmds,
                Err(e) => {
                    self.ledger.clear_disclosed();
                    self.ledger.set_read_as::<&str>(&[]);
                    return Err(e);
                }
            };
            self.ledger.set_submission_idx(self.submissions);
            self.submissions += 1;
            let events_before = self.ledger.events().len();
            let outcome = self.ledger.transaction_as(&acting, |engine| {
                commands
                    .iter()
                    .map(|command| run_command(engine, &acting, command))
                    .collect::<Result<Vec<_>, _>>()
                    .map(|per_command| per_command.into_iter().flatten().collect::<Vec<_>>())
            });
            self.ledger.clear_disclosed();
            self.ledger.set_read_as::<&str>(&[]);
            if outcome.is_ok() {
                // what the transaction created goes in, then what it consumed goes out (`++ localContractIds -- inactiveContracts`)
                let events = &self.ledger.events()[events_before..];
                for event in events {
                    if let crate::EngineEvent::Create { contract_id, .. } = event {
                        self.active.add(contract_id);
                    }
                }
                for event in events {
                    if let crate::EngineEvent::Exercise {
                        contract_id,
                        consuming: true,
                        ..
                    } = event
                    {
                        self.active.remove(contract_id);
                    }
                }
            }
            answers.push(match (outcome, must_fail) {
                (Ok(results), _) => {
                    either(true, tuple2(Value::List(List::from(results)), Value::Unit))
                }
                (Err(_), true) => either(false, Value::Unit),
                (Err(error), false) => {
                    return Err(ScriptError::Eval(format!("Command Submit failed: {error}")))
                }
            });
        }
        Ok(Value::List(List::from(answers)))
    }

    /// `QueryByKey`: `Some (cid, template)` of the active contract with that key that one of the parties is a stakeholder of.
    fn query_by_key(&mut self, payload: &Value) -> Result<Value, ScriptError> {
        let Value::List(parties) = field(payload, "parties")? else {
            return Err(ScriptError::Shape("parties".into()));
        };
        let parties: Vec<&str> = parties
            .iter()
            .filter_map(|p| match p {
                Value::Party(p) => Some(p.as_str()),
                _ => None,
            })
            .collect();
        let Value::TypeRep { key: type_key, .. } =
            field(field(payload, "tplId")?, "getTemplateTypeRep")?
        else {
            return Err(ScriptError::Shape("getTemplateTypeRep".into()));
        };
        let (package, template) = split_any_key(type_key)?;
        let key = field(field(payload, "key")?, "getAnyContractKey")?;
        let hit = self
            .ledger
            .contract_by_key(package, template, key, &parties)?;
        Ok(Value::Optional(hit.map(|c| {
            let any = Value::Any {
                key: type_key.clone(),
                payload: Box::new(c.payload.clone()),
            };
            let template = Value::Record {
                tycon: Some("DA.Internal.Any:AnyTemplate".into()),
                fields: vec![("getAnyTemplate".into(), any)],
            };
            Box::new(tuple2(Value::ContractId(c.contract_id.clone()), template))
        })))
    }

    /// `QueryContractId`: `Some (template, typeRep, blob)` when the contract is active and a party of the query is a stakeholder.
    ///
    /// [CANTON-NOTE: LIMITATION] The third element is the contract's created-event blob (for disclosure); it is `""` here.
    fn query_contract_id(&mut self, payload: &Value) -> Result<Value, ScriptError> {
        if self.remote.is_some() {
            return self.query_contract_id_remote(payload);
        }
        let Value::List(parties) = field(payload, "parties")? else {
            return Err(ScriptError::Shape("parties".into()));
        };
        let parties: Vec<&str> = parties
            .iter()
            .filter_map(|p| match p {
                Value::Party(p) => Some(p.as_str()),
                _ => None,
            })
            .collect();
        let Value::ContractId(cid) = field(payload, "cid")? else {
            return Err(ScriptError::Shape("cid".into()));
        };
        let Value::TypeRep { key, .. } = field(field(payload, "tplId")?, "getTemplateTypeRep")?
        else {
            return Err(ScriptError::Shape("getTemplateTypeRep".into()));
        };
        let (package, template) = split_any_key(key)?;
        let hit = self.ledger.contract(cid).filter(|c| {
            c.active
                && c.package_id == package
                && c.template_id == template
                && c.signatories
                    .iter()
                    .chain(&c.observers)
                    .any(|s| parties.contains(&s.as_str()))
        });
        Ok(Value::Optional(hit.map(|c| {
            let any = Value::Any {
                key: key.clone(),
                payload: Box::new(c.payload.clone()),
            };
            let template = Value::Record {
                tycon: Some("DA.Internal.Any:AnyTemplate".into()),
                fields: vec![("getAnyTemplate".into(), any)],
            };
            let rep = field(payload, "tplId").cloned().unwrap_or(Value::Unit);
            Box::new(Value::Record {
                tycon: Some("DA.Types:Tuple3".into()),
                fields: vec![
                    ("_1".into(), template),
                    ("_2".into(), rep),
                    ("_3".into(), Value::Text(String::new())),
                ],
            })
        })))
    }

    /// `QueryACS`: the active contracts of the template that one of the parties is a stakeholder of, in contract id order.
    fn query(&mut self, payload: &Value) -> Result<Value, ScriptError> {
        if self.remote.is_some() {
            return self.query_remote(payload);
        }
        let Value::List(parties) = field(payload, "parties")? else {
            return Err(ScriptError::Shape("parties".into()));
        };
        let parties: Vec<&str> = parties
            .iter()
            .map(|p| match p {
                Value::Party(p) => Ok(p.as_str()),
                other => Err(ScriptError::Shape(format!("{other:?}"))),
            })
            .collect::<Result<_, _>>()?;
        let Value::TypeRep { key, .. } = field(field(payload, "tplId")?, "getTemplateTypeRep")?
        else {
            return Err(ScriptError::Shape("getTemplateTypeRep".into()));
        };
        let (package, template) = split_any_key(key)?;
        // in the IDE ledger's order of its whole active set, then filtered
        let by_id: std::collections::HashMap<&str, _> = self
            .ledger
            .active_contracts()
            .map(|c| (c.contract_id.as_str(), c))
            .collect();
        let order = self.active.order();
        let found = order
            .iter()
            .filter_map(|id| by_id.get(id.as_str()).copied())
            .filter(|c| c.package_id == package && c.template_id == template)
            .filter(|c| {
                c.signatories
                    .iter()
                    .chain(&c.observers)
                    .any(|s| parties.contains(&s.as_str()))
            })
            .map(|c| {
                let any = Value::Any {
                    key: key.clone(),
                    payload: Box::new(c.payload.clone()),
                };
                let template = Value::Record {
                    tycon: Some("DA.Internal.Any:AnyTemplate".into()),
                    fields: vec![("getAnyTemplate".into(), any)],
                };
                tuple2(Value::ContractId(c.contract_id.clone()), template)
            })
            .collect::<Vec<_>>();
        Ok(Value::List(List::from(found)))
    }

    /// `Submit` against a remote ledger: each submission is one transaction there.
    fn submit_remote(&mut self, payload: &Value) -> Result<Value, ScriptError> {
        let Value::List(submissions) = field(payload, "submissions")? else {
            return Err(ScriptError::Shape("submissions".into()));
        };
        let mut answers = Vec::new();
        for submission in submissions.iter() {
            let must_fail = match field(submission, "sErrorBehaviour")? {
                Value::Enum { constructor, .. } if constructor == "MustSucceed" => false,
                Value::Enum { constructor, .. }
                    if constructor == "MustFail" || constructor == "Try" =>
                {
                    true
                }
                other => return Err(ScriptError::Shape(format!("{other:?}"))),
            };
            let act_as = non_empty_parties(field(submission, "sActAs")?)?;
            let read_as: Vec<String> = match field(submission, "sReadAs")? {
                Value::List(ps) => ps
                    .iter()
                    .filter_map(|p| match p {
                        Value::Party(p) => Some(p.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => return Err(ScriptError::Shape("sReadAs".into())),
            };
            if let Ok(Value::List(d)) = field(submission, "sDisclosures") {
                if !d.is_empty() {
                    return Err(ScriptError::Unsupported(
                        "explicit disclosures on a remote ledger".into(),
                    ));
                }
            }
            let Value::List(commands) = field(submission, "sCommands")? else {
                return Err(ScriptError::Shape("sCommands".into()));
            };
            let commands = commands
                .iter()
                .map(|with_meta| ledger_command(field(with_meta, "command")?))
                .collect::<Result<Vec<_>, _>>()?;
            let ledger = self.remote.as_mut().expect("remote checked by the caller");
            let outcome = ledger
                .submit(&act_as, &read_as, &commands)
                .map_err(remote_err)?;
            answers.push(match (outcome, must_fail) {
                (Ok(results), _) => {
                    let results = results
                        .into_iter()
                        .map(|r| match r {
                            LedgerResult::Created(cid) => {
                                command_result("CreateResult", Value::ContractId(cid))
                            }
                            LedgerResult::Exercised(v) => command_result("ExerciseResult", v),
                        })
                        .collect::<Vec<_>>();
                    either(true, tuple2(Value::List(List::from(results)), Value::Unit))
                }
                (Err(_), true) => either(false, Value::Unit),
                (Err(error), false) => {
                    return Err(ScriptError::Eval(format!("Command Submit failed: {error}")))
                }
            });
        }
        Ok(Value::List(List::from(answers)))
    }

    /// The active contracts of `tplId` a remote ledger shows the payload's `parties`, as `(cid, AnyTemplate)` pairs.
    fn remote_contracts(
        &mut self,
        payload: &Value,
    ) -> Result<(String, Vec<(String, Value)>), ScriptError> {
        let Value::List(parties) = field(payload, "parties")? else {
            return Err(ScriptError::Shape("parties".into()));
        };
        let parties: Vec<String> = parties
            .iter()
            .filter_map(|p| match p {
                Value::Party(p) => Some(p.clone()),
                _ => None,
            })
            .collect();
        let Value::TypeRep { key, .. } = field(field(payload, "tplId")?, "getTemplateTypeRep")?
        else {
            return Err(ScriptError::Shape("getTemplateTypeRep".into()));
        };
        let (package, template) = split_any_key(key)?;
        let ledger = self.remote.as_mut().expect("remote checked by the caller");
        let found = ledger
            .active_contracts(&parties, package, template)
            .map_err(remote_err)?;
        Ok((key.clone(), found))
    }

    fn query_remote(&mut self, payload: &Value) -> Result<Value, ScriptError> {
        let (key, found) = self.remote_contracts(payload)?;
        let mut found = found;
        // in contract id order, as the IDE ledger answers
        found.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Value::List(List::from(
            found
                .into_iter()
                .map(|(cid, arg)| tuple2(Value::ContractId(cid), any_template(&key, arg)))
                .collect::<Vec<_>>(),
        )))
    }

    fn query_contract_id_remote(&mut self, payload: &Value) -> Result<Value, ScriptError> {
        let Value::ContractId(cid) = field(payload, "cid")?.clone() else {
            return Err(ScriptError::Shape("cid".into()));
        };
        let rep = field(payload, "tplId").cloned().unwrap_or(Value::Unit);
        let (key, found) = self.remote_contracts(payload)?;
        Ok(Value::Optional(
            found.into_iter().find(|(c, _)| *c == cid).map(|(_, arg)| {
                Box::new(Value::Record {
                    tycon: Some("DA.Types:Tuple3".into()),
                    fields: vec![
                        ("_1".into(), any_template(&key, arg)),
                        ("_2".into(), rep.clone()),
                        ("_3".into(), Value::Text(String::new())),
                    ],
                })
            }),
        ))
    }
}

fn any_template(key: &str, payload: Value) -> Value {
    Value::Record {
        tycon: Some("DA.Internal.Any:AnyTemplate".into()),
        fields: vec![(
            "getAnyTemplate".into(),
            Value::Any {
                key: key.to_string(),
                payload: Box::new(payload),
            },
        )],
    }
}

/// A script `Command` as a [`LedgerCommand`] for a remote ledger.
fn ledger_command(command: &Value) -> Result<LedgerCommand, ScriptError> {
    let shape = |what: &str| ScriptError::Shape(format!("script command: {what}"));
    let Value::Variant {
        constructor, value, ..
    } = command
    else {
        return Err(shape("command"));
    };
    let any_template = |v: &Value| match field(v, "getAnyTemplate") {
        Ok(Value::Any { key, payload }) => Ok((key.clone(), payload.as_ref().clone())),
        _ => Err(shape("getAnyTemplate")),
    };
    let any_choice = |v: &Value| match field(v, "getAnyChoice") {
        Ok(Value::Any { key, payload }) => Ok((
            key.rsplit(':').next().unwrap_or(key).to_string(),
            payload.as_ref().clone(),
        )),
        _ => Err(shape("getAnyChoice")),
    };
    let split = |key: &str| -> Result<(String, String), ScriptError> {
        key.split_once(':')
            .map(|(p, t)| (p.to_string(), t.to_string()))
            .ok_or_else(|| shape("type key"))
    };
    match constructor.as_str() {
        "Create" => {
            let (key, argument) = any_template(field(value, "argC")?)?;
            let (package_id, template) = split(&key)?;
            Ok(LedgerCommand::Create {
                package_id,
                template,
                argument,
            })
        }
        "Exercise" => {
            let Value::ContractId(contract_id) = field(value, "cId")? else {
                return Err(shape("cId"));
            };
            let Value::TypeRep { key, .. } = field(field(value, "tplId")?, "getTemplateTypeRep")?
            else {
                return Err(shape("tplId"));
            };
            let (package_id, template) = split(key)?;
            let (choice, argument) = any_choice(field(value, "argE")?)?;
            Ok(LedgerCommand::Exercise {
                package_id,
                template,
                contract_id: contract_id.clone(),
                choice,
                argument,
            })
        }
        "CreateAndExercise" => {
            let (key, argument) = any_template(field(value, "tplArgCE")?)?;
            let (package_id, template) = split(&key)?;
            let (choice, choice_argument) = any_choice(field(value, "choiceArgCE")?)?;
            Ok(LedgerCommand::CreateAndExercise {
                package_id,
                template,
                argument,
                choice,
                choice_argument,
            })
        }
        other => Err(ScriptError::Unsupported(format!(
            "script command {other} on a remote ledger"
        ))),
    }
}

/// How a (nested) script ended.
enum Outcome {
    Done(Value),
    /// An exception was thrown and not caught inside it.
    Thrown(Value),
}

fn catch_failed(inner: &ScriptError) -> ScriptError {
    match inner {
        ScriptError::Eval(message) => ScriptError::Eval(format!("Command Catch failed: {message}")),
        other => ScriptError::Shape(other.to_string()),
    }
}

const COMMAND_RESULT: &str =
    "Daml.Script.Internal.Questions.Commands.Stable.CommandResult:CommandResult";

/// One command of a submission, inside the submission's transaction.
fn run_command(
    engine: &mut Engine<'_>,
    act_as: &[&str],
    command: &Value,
) -> Result<Vec<Value>, EvalError> {
    let shape = |what: &str| EvalError::Host(format!("script command shape: {what}"));
    let Value::Variant {
        constructor, value, ..
    } = command
    else {
        return Err(shape("command"));
    };
    let any_template = |v: &Value| match field(v, "getAnyTemplate") {
        Ok(Value::Any { key, payload }) => Ok((key.clone(), payload.as_ref().clone())),
        _ => Err(shape("getAnyTemplate")),
    };
    let any_choice = |v: &Value| match field(v, "getAnyChoice") {
        Ok(Value::Any { key, payload }) => {
            // [CANTON-NOTE: SEMANTICS] A choice's argument type is named like the choice (`choice Append` makes `Append`), so the
            // choice is the last part of the argument's type key.
            let choice = key.rsplit(':').next().unwrap_or(key).to_string();
            Ok((choice, payload.as_ref().clone()))
        }
        _ => Err(shape("getAnyChoice")),
    };
    let split = |key: &str| -> Result<(String, String), EvalError> {
        key.split_once(':')
            .map(|(p, t)| (p.to_string(), t.to_string()))
            .ok_or_else(|| shape("type key"))
    };
    match constructor.as_str() {
        "Create" => {
            let (key, payload) = any_template(field_of(value, "argC")?)?;
            let (package, template) = split(&key)?;
            let id = engine.create_contract_in(&package, &template, &payload)?;
            Ok(vec![command_result("CreateResult", Value::ContractId(id))])
        }
        "Exercise" => {
            let Value::ContractId(contract) = field_of(value, "cId")? else {
                return Err(shape("cId"));
            };
            let (choice, arg) = any_choice(field_of(value, "argE")?)?;
            exercise_stored(engine, act_as, contract, &choice, &arg)
        }
        // one command that creates a contract and exercises a choice on it
        "CreateAndExercise" => {
            let (key, payload) = any_template(field_of(value, "tplArgCE")?)?;
            let (package, template) = split(&key)?;
            let id = engine.create_contract_in(&package, &template, &payload)?;
            let (choice, arg) = any_choice(field_of(value, "choiceArgCE")?)?;
            // [CANTON-NOTE: SEMANTICS] Measured: the results of a create-and-exercise command are `[CreateResult, ExerciseResult]`.
            let mut results = vec![command_result(
                "CreateResult",
                Value::ContractId(id.clone()),
            )];
            results.extend(exercise_stored(engine, act_as, &id, &choice, &arg)?);
            Ok(results)
        }
        "ExerciseByKey" => {
            let Value::TypeRep { key: type_key, .. } =
                field_of(field_of(value, "tplId")?, "getTemplateTypeRep")?
            else {
                return Err(shape("tplId"));
            };
            let (package, template) = split(type_key)?;
            let key = field_of(field_of(value, "keyE")?, "getAnyContractKey")?;
            let found = engine
                .contract_by_key(&package, &template, key, act_as)?
                .map(|c| c.contract_id.clone());
            let Some(contract) = found else {
                return Err(EvalError::ContractKeyNotFound {
                    template_id: template,
                });
            };
            let (choice, arg) = any_choice(field_of(value, "argE")?)?;
            exercise_stored(engine, act_as, &contract, &choice, &arg)
        }
        other => Err(EvalError::Host(format!(
            "script command {other} is not served by this host"
        ))),
    }
}

fn field_of<'v>(value: &'v Value, name: &str) -> Result<&'v Value, EvalError> {
    field(value, name).map_err(|_| EvalError::Host(format!("script command shape: {name}")))
}

fn exercise_stored(
    engine: &mut Engine<'_>,
    act_as: &[&str],
    contract: &str,
    choice: &str,
    arg: &Value,
) -> Result<Vec<Value>, EvalError> {
    engine.require_visible_to_command(contract, act_as)?;
    let (package_id, template_id) = {
        let stored = engine
            .contract(contract)
            .ok_or_else(|| EvalError::ContractNotFound {
                contract_id: contract.to_string(),
            })?;
        (stored.package_id.clone(), stored.template_id.clone())
    };
    let result = engine.exercise(&ExerciseRequest {
        package_id: &package_id,
        template_id: &template_id,
        contract_id: contract,
        choice,
        arg,
    })?;
    Ok(vec![command_result("ExerciseResult", result)])
}

/// The user id (the text inside its `UserId`) of a `User` value.
fn user_id(user: &Value) -> Result<String, ScriptError> {
    let id = field(user, "userId")?;
    Ok(text(field(id, "unpack")?)?.to_string())
}

/// The regular expression the ledger's user ids must match (measured: `usersValidate`, the message of `InvalidUserId`).
pub const USER_ID_REGEX: &str = r"[a-zA-Z0-9@^$.!`\-#+'~_|:\(\)]{1,128}";

/// `None` when `name` is a valid user id, otherwise the message the official ledger refuses it with
/// (`User ID "<name>" does not match regex "<USER_ID_REGEX>"`): 1 to 128 characters, each an ASCII letter or digit or one of
/// ``@^$.!`-#+'~_|:()``.
pub fn validate_user_id(name: &str) -> Option<String> {
    let ok_char = |c: char| c.is_ascii_alphanumeric() || "@^$.!`-#+'~_|:()".contains(c);
    let len = name.chars().count();
    if (1..=128).contains(&len) && name.chars().all(ok_char) {
        None
    } else {
        Some(format!(
            "User ID \"{name}\" does not match regex \"{USER_ID_REGEX}\""
        ))
    }
}

/// The user id a user-management question names (`userId` of its payload).
fn user_id_of(payload: &Value) -> Result<String, ScriptError> {
    let id = field(payload, "userId")?;
    Ok(text(field(id, "unpack")?)?.to_string())
}

fn list_items(value: &Value) -> Result<Vec<Value>, ScriptError> {
    match value {
        Value::List(items) => Ok(items.iter().cloned().collect()),
        other => Err(ScriptError::Shape(format!("list expected, got {other:?}"))),
    }
}

/// A `DA.Types:Either` value: `Left` (rank 0) or `Right` (rank 1).
fn either(right: bool, value: Value) -> Value {
    Value::Variant {
        tycon: Some("DA.Types:Either".into()),
        constructor: if right { "Right" } else { "Left" }.into(),
        rank: crate::CtorRank::known(u32::from(right)),
        value: Box::new(value),
    }
}

/// A script `CommandResult`; only ever matched by the script, never ordered, so its rank is left unknown.
fn command_result(constructor: &str, value: Value) -> Value {
    Value::Variant {
        tycon: Some(COMMAND_RESULT.into()),
        constructor: constructor.into(),
        rank: crate::CtorRank::default(),
        value: Box::new(value),
    }
}

fn tuple2(a: Value, b: Value) -> Value {
    Value::Record {
        tycon: Some("DA.Types:Tuple2".into()),
        fields: vec![("_1".into(), a), ("_2".into(), b)],
    }
}

/// The parties of a `NonEmpty Party` (`hd` and `tl`).
fn non_empty_parties(value: &Value) -> Result<Vec<String>, ScriptError> {
    let mut parties = Vec::new();
    let mut push = |v: &Value| match v {
        Value::Party(p) => {
            parties.push(p.clone());
            Ok(())
        }
        other => Err(ScriptError::Shape(format!("party expected, got {other:?}"))),
    };
    push(field(value, "hd")?)?;
    if let Value::List(tail) = field(value, "tl")? {
        for p in tail.iter() {
            push(p)?;
        }
    }
    Ok(parties)
}

/// The package id and `Module:Template` of an `Any` key (`<package>:<Module>:<Name>`).
fn split_any_key(key: &str) -> Result<(&str, &str), ScriptError> {
    key.split_once(':')
        .ok_or_else(|| ScriptError::Shape(format!("type key {key}")))
}

/// A script's result as `daml script --output-file` writes it (S-SCRIPT-002): records by field name (tuples as `_1`, `_2`, ...),
/// `Int64` as a number, `Numeric` as a decimal string with its scale, text, parties and contract ids as strings, `Optional` as `null`
/// or its value, lists as arrays, variants as `{"tag", "value"}`, enums as their constructor, unit as `{}`.
///
/// [CANTON-NOTE: LIMITATION] The runtime value carries no type: a `Time` or a `Date` is an `Int64` here and is written as a number,
/// where the official runner (which knows the script's type) writes an ISO text; an `Optional` of an `Optional` is flattened.
pub fn result_json(value: &Value) -> serde_json::Value {
    use serde_json::{json, Map, Value as Json};
    match value {
        Value::Int64(n) => json!(n),
        Value::Numeric { coeff, scale } => {
            Json::String(crate::typed_json::format_numeric(*coeff, *scale))
        }
        Value::BigNumeric(bn) => Json::String(bn.to_unscaled_string()),
        Value::Text(s) | Value::Party(s) | Value::ContractId(s) => Json::String(s.clone()),
        Value::Bool(b) => json!(b),
        Value::Unit => json!({}),
        Value::Optional(None) => Json::Null,
        Value::Optional(Some(inner)) => result_json(inner),
        Value::List(items) => Json::Array(items.iter().map(result_json).collect()),
        Value::Record { fields, .. } | Value::Struct(fields) => Json::Object(
            fields
                .iter()
                .map(|(n, v)| (n.clone(), result_json(v)))
                .collect::<Map<_, _>>(),
        ),
        Value::Variant {
            constructor, value, ..
        } => json!({ "tag": constructor, "value": result_json(value) }),
        Value::Enum { constructor, .. } => Json::String(constructor.clone()),
        Value::Map(entries) => {
            if entries.iter().all(|(k, _)| matches!(k, Value::Text(_))) {
                Json::Object(
                    entries
                        .iter()
                        .map(|(k, v)| match k {
                            Value::Text(t) => (t.clone(), result_json(v)),
                            _ => unreachable!("checked above"),
                        })
                        .collect(),
                )
            } else {
                Json::Array(
                    entries
                        .iter()
                        .map(|(k, v)| json!([result_json(k), result_json(v)]))
                        .collect(),
                )
            }
        }
        Value::Any { payload, .. } | Value::Iface { payload, .. } => result_json(payload),
        other => Json::String(format!("{other:?}")),
    }
}

#[cfg(test)]
mod witness_order_tests {
    use super::scala_witness_order;

    const FP: &str = "::12200312c1156c7964d0d07c1434e6d1f38d76087e4a033a2ffa45141391ea2e233b";

    fn parties(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| format!("{n}{FP}")).collect()
    }

    /// The witness lists of three events of the hub's Canton 3.7.2 participant, read back from `/v2/updates` (six, eight and nine parties).
    #[test]
    fn more_than_four_witnesses_come_in_the_order_of_a_scala_hash_set() {
        let cases: [(&[&str], &[&str]); 3] = [
            (
                &[
                    "Beneficiary",
                    "Holder",
                    "HubLocalProbe",
                    "Issuer",
                    "Regulator",
                    "SettlementBank_TEST",
                ],
                &[
                    "Holder",
                    "HubLocalProbe",
                    "Beneficiary",
                    "SettlementBank_TEST",
                    "Regulator",
                    "Issuer",
                ],
            ),
            (
                &[
                    "Beneficiary",
                    "Exporter",
                    "Holder",
                    "HubLocalProbe",
                    "Importer",
                    "Issuer",
                    "Regulator",
                    "SettlementBank",
                ],
                &[
                    "Holder",
                    "HubLocalProbe",
                    "Beneficiary",
                    "Exporter",
                    "SettlementBank",
                    "Regulator",
                    "Issuer",
                    "Importer",
                ],
            ),
            (
                &[
                    "Beneficiary",
                    "Exporter",
                    "Holder",
                    "HubLocalProbe",
                    "Importer",
                    "Issuer",
                    "Regulator",
                    "SettlementBank",
                    "SettlementBank_TEST",
                ],
                &[
                    "Holder",
                    "HubLocalProbe",
                    "Beneficiary",
                    "SettlementBank_TEST",
                    "Exporter",
                    "SettlementBank",
                    "Regulator",
                    "Issuer",
                    "Importer",
                ],
            ),
        ];
        for (given, official) in cases {
            assert_eq!(scala_witness_order(&parties(given)), parties(official));
        }
    }

    #[test]
    fn up_to_four_witnesses_are_alphabetical() {
        // the hub's participant listed `Issuer`, `SettlementBank` and `Exporter, Holder, Importer, Issuer` in this order
        assert_eq!(
            scala_witness_order(&parties(&["SettlementBank", "Issuer"])),
            parties(&["Issuer", "SettlementBank"])
        );
        assert_eq!(
            scala_witness_order(&parties(&["Issuer", "Importer", "Holder", "Exporter"])),
            parties(&["Exporter", "Holder", "Importer", "Issuer"])
        );
        assert!(scala_witness_order(&[]).is_empty());
    }
}
