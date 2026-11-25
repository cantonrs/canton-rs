//! `splice-replay <dar> <updates.json>`: re-execute the transactions an official Splice network committed (G8).
//!
//! `updates.json` is what the official scan app answers `POST /api/scan/v2/updates` (`daml_value_encoding: compact_json`): the update
//! history as the DSO party sees it, each transaction a tree of created and exercised events with their arguments and results. For every
//! transaction the Rust [`Engine`] is given the contracts active before it (as the official events created them), runs the transaction's
//! root commands with the official arguments at the official ledger time, and what it produces is compared with the official tree: the
//! events in execution order (kind, template or choice, consuming, actors, depth, contract), every created contract's payload, signatories
//! and observers, and the result of every root exercise. Contract ids are compared up to the renaming of the contracts the transaction
//! creates (the official id of the n-th created contract stands for the Rust id of the n-th).
//!
//! A contract a transaction uses but the history never creates (a `ValidatorRight` made when the LocalNet started, outside the DSO's view)
//! comes from the optional top-level `"seed"` of `updates.json`: created events in the shape of the scan's, read from the participants by
//! `scripts/splice-seed-contracts.py`. They are active from the start; the summary counts the seeds a transaction used (`seeded_used`) and
//! the contract ids the history uses that are neither created in it nor seeded (`unseeded_inputs`: "seed needed", never counted as same).
//!
//! One JSON line is printed for each transaction (`same`, `differs: ...` or `skipped: ...`) and a summary; the exit code is 1 when a
//! transaction differs.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env, fs,
    path::Path,
    process::ExitCode,
};

use lf_eval::typed_json::{timestamp_micros, LfType, Types};
use lf_eval::{Contract, Engine, EngineEvent, Value, World};
use serde_json::{json, Value as Json};

/// `pkg:Module:Entity` -> (`pkg`, `Module:Entity`).
fn template_of(event: &Json) -> Result<(String, String), String> {
    let id = event["template_id"]
        .as_str()
        .ok_or("an event without a template")?;
    let (package, rest) = id
        .split_once(':')
        .ok_or("a template id without a package")?;
    Ok((package.to_string(), rest.to_string()))
}

fn parties(json: &Json) -> Vec<String> {
    let mut all: Vec<String> = json
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    all.sort();
    all
}

fn sorted(mut parties: Vec<String>) -> Vec<String> {
    parties.sort();
    parties.dedup();
    parties
}

/// The contract ids of `value` renamed by `rename` (ids it does not know stay).
fn rename_ids(value: &Value, rename: &HashMap<String, String>) -> Value {
    let r = |v: &Value| rename_ids(v, rename);
    match value {
        Value::ContractId(id) => {
            Value::ContractId(rename.get(id).cloned().unwrap_or_else(|| id.clone()))
        }
        Value::List(items) => Value::List(items.iter().map(r).collect::<Vec<_>>().into()),
        Value::Optional(inner) => Value::Optional(inner.as_ref().map(|v| Box::new(r(v)))),
        Value::Record { tycon, fields } => Value::Record {
            tycon: tycon.clone(),
            fields: fields.iter().map(|(n, v)| (n.clone(), r(v))).collect(),
        },
        Value::Variant {
            tycon,
            constructor,
            rank,
            value,
        } => Value::Variant {
            tycon: tycon.clone(),
            constructor: constructor.clone(),
            rank: *rank,
            value: Box::new(r(value)),
        },
        Value::Map(entries) => Value::Map(entries.iter().map(|(k, v)| (r(k), r(v))).collect()),
        other => other.clone(),
    }
}

/// Whether the value the engine made is the official one, with the engine's contract ids read as official ids through `to_official`.
/// Type constructor names are not compared (the official JSON does not carry them); `Err` says where the two part.
fn same(
    ours: &Value,
    theirs: &Value,
    to_official: &HashMap<String, String>,
    path: &str,
) -> Result<(), String> {
    let differ = || {
        Err(format!("{path}: ours {ours:?}, the official {theirs:?}")
            .chars()
            .take(400)
            .collect::<String>())
    };
    match (ours, theirs) {
        (Value::ContractId(a), Value::ContractId(b)) => {
            if to_official.get(a).unwrap_or(a) == b {
                Ok(())
            } else {
                differ()
            }
        }
        (
            Value::Numeric {
                coeff: a,
                scale: sa,
            },
            Value::Numeric {
                coeff: b,
                scale: sb,
            },
        ) => {
            let (a, b) = (
                a * 10i128.pow(u32::from(*sb.max(sa) - *sa)),
                b * 10i128.pow(u32::from(*sb.max(sa) - *sb)),
            );
            if a == b {
                Ok(())
            } else {
                differ()
            }
        }
        (Value::List(a), Value::List(b)) => {
            if a.len() != b.len() {
                return differ();
            }
            a.iter()
                .zip(b.iter())
                .enumerate()
                .try_for_each(|(i, (x, y))| same(x, y, to_official, &format!("{path}[{i}]")))
        }
        (Value::Optional(None), Value::Optional(None)) => Ok(()),
        (Value::Optional(Some(a)), Value::Optional(Some(b))) => same(a, b, to_official, path),
        (Value::Record { fields: a, .. }, Value::Record { fields: b, .. }) => {
            if a.len() != b.len() {
                return differ();
            }
            a.iter().zip(b).try_for_each(|((na, x), (nb, y))| {
                if !na.is_empty() && !nb.is_empty() && na != nb {
                    return Err(format!(
                        "{path}: the field {na} where the official record has {nb}"
                    ));
                }
                same(x, y, to_official, &format!("{path}.{nb}"))
            })
        }
        // a record with no fields and unit are both `{}` in JSON
        (Value::Record { fields, .. }, Value::Unit)
        | (Value::Unit, Value::Record { fields, .. })
            if fields.is_empty() =>
        {
            Ok(())
        }
        (
            Value::Variant {
                constructor: ca,
                value: a,
                ..
            },
            Value::Variant {
                constructor: cb,
                value: b,
                ..
            },
        ) => {
            if ca != cb {
                return differ();
            }
            same(a, b, to_official, &format!("{path}.{ca}"))
        }
        (Value::Enum { constructor: a, .. }, Value::Enum { constructor: b, .. }) => {
            if a == b {
                Ok(())
            } else {
                differ()
            }
        }
        (Value::Map(a), Value::Map(b)) => {
            if a.len() != b.len() {
                return differ();
            }
            a.iter()
                .zip(b)
                .enumerate()
                .try_for_each(|(i, ((ka, va), (kb, vb)))| {
                    same(ka, kb, to_official, &format!("{path}{{{i}}}"))?;
                    same(va, vb, to_official, &format!("{path}{{{i}}}"))
                })
        }
        (a, b) if a == b => Ok(()),
        _ => differ(),
    }
}

/// The official events of a transaction in execution order, each with its depth in the tree.
fn preorder(tx: &Json) -> Vec<(&Json, usize)> {
    fn walk<'a>(tx: &'a Json, id: &str, depth: usize, out: &mut Vec<(&'a Json, usize)>) {
        let event = &tx["events_by_id"][id];
        out.push((event, depth));
        for child in event["child_event_ids"].as_array().into_iter().flatten() {
            if let Some(child) = child.as_str() {
                walk(tx, child, depth + 1, out);
            }
        }
    }
    let mut out = Vec::new();
    for root in tx["root_event_ids"].as_array().into_iter().flatten() {
        if let Some(root) = root.as_str() {
            walk(tx, root, 0, &mut out);
        }
    }
    out
}

/// Compares the events one root command made (`ours`, without fetches) with the official subtree of that root, pairs the contracts
/// it created, and compares each created contract with the official one. `offset` is the index of the first event in the transaction.
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn compare_events(
    engine: &Engine<'_>,
    types: &Types<'_>,
    ours: &[EngineEvent],
    official: &[(&Json, usize)],
    offset: usize,
    to_official: &mut HashMap<String, String>,
    to_rust: &mut HashMap<String, String>,
) -> Result<(), String> {
    if ours.len() != official.len() {
        let shape = |e: &EngineEvent| match e {
            EngineEvent::Create {
                template_id, depth, ..
            } => format!("{depth}:create {template_id}"),
            EngineEvent::Exercise { choice, depth, .. } => format!("{depth}:{choice}"),
            EngineEvent::Fetch { .. } => String::new(),
        };
        let theirs: Vec<String> = official
            .iter()
            .map(|(e, d)| {
                let what = e["choice"].as_str().map_or_else(
                    || format!("create {}", template_of(e).map(|t| t.1).unwrap_or_default()),
                    String::from,
                );
                format!("{d}:{what}")
            })
            .collect();
        return Err(format!(
            "{} events where the official transaction has {}: ours {:?}, the official {:?}",
            ours.len(),
            official.len(),
            ours.iter().map(shape).collect::<Vec<_>>(),
            theirs
        ));
    }
    for (i, (mine, (theirs, depth))) in ours.iter().zip(official).enumerate() {
        let i = i + offset;
        let their_id = theirs["contract_id"].as_str().unwrap_or_default();
        let (_, their_template) = template_of(theirs).unwrap_or_default();
        match (mine, theirs["event_type"].as_str()) {
            (
                EngineEvent::Create {
                    contract_id,
                    template_id,
                    depth: my_depth,
                },
                Some("created_event"),
            ) => {
                if template_id != &their_template || my_depth != depth {
                    return Err(format!(
                        "event {i}: ours creates {template_id} at depth {my_depth}, the official {their_template} at depth {depth}"
                    ));
                }
                match to_official.get(contract_id) {
                    Some(paired) if paired != their_id => {
                        return Err(format!(
                            "event {i}: the created contracts are paired differently"
                        ))
                    }
                    Some(_) => {}
                    None => {
                        to_official.insert(contract_id.clone(), their_id.to_string());
                        to_rust.insert(their_id.to_string(), contract_id.clone());
                    }
                }
                let Some(created) = engine.contract(contract_id) else {
                    return Err(format!(
                        "event {i}: the engine does not have the contract it created"
                    ));
                };
                let (package, _) = template_of(theirs).unwrap_or_default();
                let expected = types
                    .template(&package, &their_template)
                    .and_then(|ty| types.decode(&ty, &theirs["create_arguments"]));
                let expected = match expected {
                    Ok(v) => v,
                    Err(e) => return Err(format!("event {i}: {e}")),
                };
                if let Err(e) = same(&created.payload, &expected, to_official, &their_template) {
                    return Err(format!(
                        "event {i}: the created {their_template} differs at {e}"
                    ));
                }
                let (signatories, observers) = (
                    sorted(created.signatories.clone()),
                    sorted(created.observers.clone()),
                );
                // the Ledger API lists as observers the stakeholders that are not signatories
                let observers: Vec<String> = observers
                    .into_iter()
                    .filter(|o| !signatories.contains(o))
                    .collect();
                if signatories != parties(&theirs["signatories"])
                    || observers != parties(&theirs["observers"])
                {
                    return Err(format!(
                        "event {i}: {their_template} has signatories {signatories:?} and observers {observers:?}, the official {} and {}",
                        theirs["signatories"], theirs["observers"]
                    ));
                }
            }
            (
                EngineEvent::Exercise {
                    contract_id,
                    choice,
                    consuming,
                    actors,
                    depth: my_depth,
                    ..
                },
                Some("exercised_event"),
            ) => {
                let mine_as_official = to_official.get(contract_id).unwrap_or(contract_id);
                let same_event = Some(choice.as_str()) == theirs["choice"].as_str()
                    && Some(*consuming) == theirs["consuming"].as_bool()
                    && sorted(actors.clone()) == parties(&theirs["acting_parties"])
                    && my_depth == depth
                    && mine_as_official == their_id;
                if !same_event {
                    return Err(format!(
                        "event {i}: ours exercises {choice} (consuming {consuming}, depth {my_depth}, actors {actors:?}) on {}, the official {} (consuming {}, depth {depth}, actors {}) on {}",
                        &mine_as_official[..mine_as_official.len().min(16)],
                        theirs["choice"],
                        theirs["consuming"],
                        theirs["acting_parties"],
                        &their_id[..their_id.len().min(16)]
                    ));
                }
            }
            (mine, kind) => {
                return Err(
                    format!("event {i}: ours is {mine:?}, the official a {kind:?}")
                        .chars()
                        .take(300)
                        .collect(),
                )
            }
        }
    }
    Ok(())
}

enum Outcome {
    /// `rendered`: how the update this engine run produced reads as a scan's update item (see `lf_eval::scan_update`).
    Same {
        events: usize,
        rendered: String,
    },
    Differs(String),
    Skipped(String),
}

/// Re-executes one official transaction on top of `store` (the contracts active before it) and compares.
fn replay(
    world: &World,
    types: &Types<'_>,
    store: &BTreeMap<String, Contract>,
    tx: &Json,
) -> Outcome {
    let official = preorder(tx);
    for (event, depth) in &official {
        // a root command through an interface is not replayed; inside a transaction the engine exercises interface choices itself
        if *depth == 0 && !event["interface_id"].is_null() {
            return Outcome::Skipped("a root choice exercised through an interface".into());
        }
        match template_of(event) {
            Ok((package, _)) if !types.knows_package(&package) => {
                return Outcome::Skipped(format!("package {package} is not in the DAR"))
            }
            Err(e) => return Outcome::Differs(e),
            _ => {}
        }
    }
    let Some(time) = tx["effective_at"].as_str().and_then(timestamp_micros) else {
        return Outcome::Differs("a transaction without its ledger time".into());
    };
    let mut engine = Engine::new(world);
    engine.set_time_micros(time);
    for contract in store.values() {
        if let Err(e) = engine.import_contract(contract.clone()) {
            return Outcome::Differs(format!(
                "the contract {} cannot be imported: {e}",
                contract.contract_id
            ));
        }
        // what a submitter may see of the contracts it is no stakeholder of is the official submission's business (disclosure)
        engine.disclose(&contract.contract_id);
    }
    // the contracts this transaction creates: official id <-> the engine's id
    let mut to_rust: HashMap<String, String> = HashMap::new();
    let mut to_official: HashMap<String, String> = HashMap::new();
    // the result of each root exercise and the official one, compared once every created contract is paired
    let mut results: Vec<(Value, LfType, &Json, String)> = Vec::new();
    // how many of the engine's events (fetches left out) and of the official ones are compared already
    let mut compared = 0;
    for root in tx["root_event_ids"].as_array().into_iter().flatten() {
        let event = &tx["events_by_id"][root.as_str().unwrap_or_default()];
        let (package, template) = match template_of(event) {
            Ok(t) => t,
            Err(e) => return Outcome::Differs(e),
        };
        match event["event_type"].as_str() {
            Some("created_event") => {
                let payload = types
                    .template(&package, &template)
                    .and_then(|ty| types.decode(&ty, &event["create_arguments"]));
                let payload = match payload {
                    Ok(p) => rename_ids(&p, &to_rust),
                    Err(e) => return Outcome::Differs(format!("create {template}: {e}")),
                };
                let signatories = parties(&event["signatories"]);
                let act_as: Vec<&str> = signatories.iter().map(String::as_str).collect();
                match engine.create_as(&act_as, &package, &template, &payload) {
                    Ok(id) => {
                        let theirs = event["contract_id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string();
                        to_official.insert(id.clone(), theirs.clone());
                        to_rust.insert(theirs, id);
                    }
                    Err(e) => {
                        return Outcome::Differs(format!(
                            "create {template}: the engine refuses: {e}"
                        ))
                    }
                }
            }
            Some("exercised_event") => {
                let choice = event["choice"].as_str().unwrap_or_default();
                let choice_types = match types.choice(&package, &template, choice) {
                    Ok(t) => t,
                    Err(e) => return Outcome::Differs(e),
                };
                let argument = match types.decode(&choice_types.argument, &event["choice_argument"])
                {
                    Ok(a) => rename_ids(&a, &to_rust),
                    Err(e) => return Outcome::Differs(format!("{choice}: {e}")),
                };
                let theirs = event["contract_id"].as_str().unwrap_or_default();
                let target = to_rust
                    .get(theirs)
                    .cloned()
                    .unwrap_or_else(|| theirs.to_string());
                let actors = parties(&event["acting_parties"]);
                let act_as: Vec<&str> = actors.iter().map(String::as_str).collect();
                match engine.exercise_as(&act_as, &target, choice, &argument) {
                    Ok(result) => results.push((
                        result,
                        choice_types.result,
                        &event["exercise_result"],
                        choice.to_string(),
                    )),
                    Err(e) => {
                        return Outcome::Differs(format!("{choice}: the engine refuses: {e}"))
                    }
                }
            }
            other => return Outcome::Differs(format!("an event of type {other:?}")),
        }
        // what this root command did, against the official subtree of the root: compared now, so that the contracts it created are
        // paired before a later root command names them
        let subtree = 1 + official[compared + 1..]
            .iter()
            .take_while(|(_, depth)| *depth > 0)
            .count();
        let ours: Vec<EngineEvent> = engine
            .events()
            .iter()
            .filter(|e| !matches!(e, EngineEvent::Fetch { .. }))
            .skip(compared)
            .cloned()
            .collect();
        if let Err(why) = compare_events(
            &engine,
            types,
            &ours,
            &official[compared..compared + subtree],
            compared,
            &mut to_official,
            &mut to_rust,
        ) {
            return Outcome::Differs(why);
        }
        compared += subtree;
    }
    for (result, ty, theirs, choice) in &results {
        let expected = match types.decode(ty, theirs) {
            Ok(v) => v,
            Err(e) => return Outcome::Differs(format!("the result of {choice}: {e}")),
        };
        if let Err(e) = same(result, &expected, &to_official, "result") {
            return Outcome::Differs(format!("the result of {choice} differs at {e}"));
        }
    }
    let rendered = render_check(types, &engine, &to_official, tx);
    Outcome::Same {
        events: official.len(),
        rendered,
    }
}

/// The first place two JSON values differ, as a path.
fn first_difference(a: &Json, b: &Json, path: &str) -> Option<String> {
    match (a, b) {
        (Json::Object(x), Json::Object(y)) => {
            for k in x.keys().chain(y.keys()) {
                match (x.get(k), y.get(k)) {
                    (Some(p), Some(q)) => {
                        if let Some(d) = first_difference(p, q, &format!("{path}.{k}")) {
                            return Some(d);
                        }
                    }
                    _ => return Some(format!("{path}.{k} is in one only")),
                }
            }
            None
        }
        (Json::Array(x), Json::Array(y)) if x.len() == y.len() => x
            .iter()
            .zip(y)
            .enumerate()
            .find_map(|(i, (p, q))| first_difference(p, q, &format!("{path}[{i}]"))),
        _ if a == b => None,
        _ => Some(
            format!("{path}: ours {a}, the official {b}")
                .chars()
                .take(400)
                .collect(),
        ),
    }
}

/// `json` with every string that is exactly one of the engine's contract ids replaced by the official id (a longer text that merely contains an
/// id, such as a comment with `#4900` in it, stays).
fn rename_strings(json: Json, rename: &HashMap<String, String>) -> Json {
    match json {
        Json::String(s) => Json::String(rename.get(&s).cloned().unwrap_or(s)),
        Json::Array(items) => Json::Array(
            items
                .into_iter()
                .map(|j| rename_strings(j, rename))
                .collect(),
        ),
        Json::Object(map) => Json::Object(
            map.into_iter()
                .map(|(k, v)| (k, rename_strings(v, rename)))
                .collect(),
        ),
        other => other,
    }
}

/// What the engine run produced, written as the scan app writes an update, against the official update item (contract ids renamed to the
/// official ones). `same`, `differs: <where>` or `not rendered: <why>`.
fn render_check(
    types: &Types<'_>,
    engine: &Engine<'_>,
    to_official: &HashMap<String, String>,
    tx: &Json,
) -> String {
    use lf_eval::scan_update::{render_update, UpdateMeta};
    let micros = |key: &str| tx[key].as_str().and_then(timestamp_micros);
    let (Some(record), Some(effective)) = (micros("record_time"), micros("effective_at")) else {
        return "not rendered: a transaction without its times".into();
    };
    let meta = UpdateMeta {
        update_id: tx["update_id"].as_str().unwrap_or_default(),
        migration_id: tx["migration_id"].as_i64().unwrap_or_default(),
        workflow_id: tx["workflow_id"].as_str().unwrap_or_default(),
        synchronizer_id: tx["synchronizer_id"].as_str().unwrap_or_default(),
        record_time_micros: record,
        effective_at_micros: effective,
    };
    let rendered = match render_update(types, engine, &meta, engine.events()) {
        Ok(r) => r,
        Err(e) => return format!("not rendered: {e}"),
    };
    let ours = rename_strings(rendered, to_official);
    match first_difference(&ours, tx, "$") {
        None => "same".into(),
        Some(d) => format!("differs: {d}"),
    }
}

/// The contract a `created_event` makes (with its official id), or `None` for a package the engine does not know.
fn contract_of(types: &Types<'_>, event: &Json) -> Result<Option<Contract>, String> {
    let (package, template) = template_of(event)?;
    if !types.knows_package(&package) {
        return Ok(None);
    }
    let payload = types.decode(
        &types.template(&package, &template)?,
        &event["create_arguments"],
    )?;
    let id = event["contract_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    Ok(Some(Contract {
        contract_id: id,
        package_id: package,
        template_id: template,
        payload,
        signatories: parties(&event["signatories"]),
        observers: parties(&event["observers"]),
        active: true,
        key: None,
    }))
}

/// Brings `store` to the state after the official transaction: what it created is there (with the official ids), what it consumed is not.
fn apply(
    types: &Types<'_>,
    store: &mut BTreeMap<String, Contract>,
    tx: &Json,
) -> Result<(), String> {
    for (event, _) in preorder(tx) {
        let id = event["contract_id"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        match event["event_type"].as_str() {
            Some("created_event") => {
                if let Some(contract) = contract_of(types, event)? {
                    store.insert(id, contract);
                }
            }
            Some("exercised_event") if event["consuming"].as_bool() == Some(true) => {
                store.remove(&id);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Every string of `json` that is a contract id (a long hex string starting with the `00` version byte).
fn contract_ids(json: &Json, out: &mut BTreeSet<String>) {
    match json {
        Json::String(s)
            if s.len() >= 66 && s.starts_with("00") && s.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            out.insert(s.clone());
        }
        Json::Array(a) => a.iter().for_each(|v| contract_ids(v, out)),
        Json::Object(o) => o.values().for_each(|v| contract_ids(v, out)),
        _ => {}
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let [_, dar, updates] = args.as_slice() else {
        eprintln!("usage: splice-replay <dar> <updates.json>");
        return ExitCode::from(64);
    };
    let world = match World::open(Path::new(dar)) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("cannot load {dar}: {e}");
            return ExitCode::from(2);
        }
    };
    let types = Types::new(&world);
    let text = fs::read_to_string(updates).expect("the updates file");
    let parsed: Json = serde_json::from_str(&text).expect("JSON");
    let transactions = parsed["transactions"]
        .as_array()
        .or(parsed.as_array())
        .cloned()
        .unwrap_or_default();
    let mut store: BTreeMap<String, Contract> = BTreeMap::new();
    // [CANTON-NOTE: SEMANTICS] the contracts the history never creates: active from the start, as the participants' ledger holds them
    let mut seeded: BTreeSet<String> = BTreeSet::new();
    for event in parsed["seed"].as_array().into_iter().flatten() {
        match contract_of(&types, event) {
            Ok(Some(contract)) => {
                seeded.insert(contract.contract_id.clone());
                store.insert(contract.contract_id.clone(), contract);
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("a seed contract cannot be read: {e}");
                return ExitCode::from(2);
            }
        }
    }
    let mut created_in_history: BTreeSet<String> = BTreeSet::new();
    let mut used_in_history: BTreeSet<String> = BTreeSet::new();
    for tx in &transactions {
        for (event, _) in preorder(tx) {
            if event["event_type"].as_str() == Some("created_event") {
                created_in_history.insert(
                    event["contract_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
            }
        }
        contract_ids(tx, &mut used_in_history);
    }
    let (mut same_count, mut differ_count, mut skipped_count, mut events) = (0, 0, 0, 0);
    let (mut rendered_same, mut rendered_differs, mut not_rendered) = (0, 0, 0);
    let mut rendered_by_update: BTreeMap<String, String> = BTreeMap::new();
    for tx in &transactions {
        // a reassignment or another kind of update has no event tree
        if tx["events_by_id"].is_null() {
            continue;
        }
        let roots: Vec<String> = tx["root_event_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| {
                let e = &tx["events_by_id"][r.as_str().unwrap_or_default()];
                let template = template_of(e).map(|t| t.1).unwrap_or_default();
                e["choice"]
                    .as_str()
                    .map_or(format!("create {template}"), String::from)
            })
            .collect();
        let outcome = match replay(&world, &types, &store, tx) {
            Outcome::Same {
                events: n,
                rendered,
            } => {
                same_count += 1;
                events += n;
                match rendered.split(':').next() {
                    Some("same") => rendered_same += 1,
                    Some("differs") => rendered_differs += 1,
                    _ => not_rendered += 1,
                }
                rendered_by_update.insert(
                    tx["update_id"].as_str().unwrap_or_default().to_string(),
                    rendered,
                );
                "same".to_string()
            }
            Outcome::Differs(why) => {
                differ_count += 1;
                format!("differs: {why}")
            }
            Outcome::Skipped(why) => {
                skipped_count += 1;
                format!("skipped: {why}")
            }
        };
        println!(
            "{}",
            json!({"update_id": tx["update_id"], "record_time": tx["record_time"], "roots": roots, "outcome": outcome, "rendered": rendered_by_update.get(tx["update_id"].as_str().unwrap_or_default())})
        );
        if let Err(e) = apply(&types, &mut store, tx) {
            eprintln!(
                "the official transaction {} cannot be applied: {e}",
                tx["update_id"]
            );
            return ExitCode::from(2);
        }
    }
    // a contract the history uses that nothing in it creates and no seed holds: the replay cannot have it (never a "same")
    let unseeded: Vec<&String> = used_in_history
        .iter()
        .filter(|id| !created_in_history.contains(*id) && !seeded.contains(*id))
        .collect();
    let seeded_used = seeded
        .iter()
        .filter(|id| used_in_history.contains(*id))
        .count();
    println!(
        "{}",
        json!({"seeded": seeded.len(), "seeded_used": seeded_used, "unseeded_inputs": unseeded.len(), "unseeded_input_ids": unseeded.iter().map(|i| &i[..16]).collect::<Vec<_>>(), "transactions": transactions.len(), "same": same_count, "differs": differ_count, "skipped": skipped_count, "events_compared": events, "rendered_same": rendered_same, "rendered_differs": rendered_differs, "not_rendered": not_rendered})
    );
    if differ_count > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
