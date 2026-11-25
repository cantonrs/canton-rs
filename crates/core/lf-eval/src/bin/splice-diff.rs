//! `splice-diff <dar> <scenarios.json>`: run the Splice execution scenarios (S-TX-001) with the Rust `Engine`.
//!
//! The scenario file is the one `scripts/gen-splice-diff.py` also turns into a Daml script for the JVM. For every
//! scenario this prints one JSON line with the outcome of each step (`ok` or an error category) and the active
//! contracts the scenario's observers can see afterwards, in the same shape the Daml script prints, so the two
//! outputs can be compared (`scripts/compare-splice-diff.py`).
use std::{collections::BTreeSet, env, fs, path::Path, process::ExitCode};

use lf_eval::{parse_numeric, render_numeric, Engine, ExecError, Value, World};
use serde_json::{json, Value as Json};

fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `hashListInternal`: the length first, then the elements, joined by `|`.
fn hash_list(parts: &[String]) -> String {
    let mut all = vec![parts.len().to_string()];
    all.extend(parts.iter().cloned());
    sha256_hex(&all.join("|"))
}

/// The `Hashable Batch` instance of `Splice.Amulet.RewardAccountingV2`. A minting allowance is a record of the provider's
/// text and the amount's `show`; a batch of batches hashes its child hashes.
fn batch_hash(spec: &Json) -> Result<String, String> {
    let variant_hash = |tag: &str, fields: &[String]| {
        let mut all = vec![tag.to_string(), fields.len().to_string()];
        all.extend(fields.iter().cloned());
        sha256_hex(&all.join("|"))
    };
    if let Some(items) = spec.get("mint") {
        let mut hashes = Vec::new();
        for pair in items.as_array().ok_or("mint")? {
            let provider = sha256_hex(pair[0].as_str().ok_or("mint provider")?);
            let Value::Numeric { coeff, scale } = value_of(&json!({"num": pair[1]}))? else {
                return Err("mint amount".to_string());
            };
            // Daml's `show` of a Decimal: no trailing zeros, at least one decimal digit
            let shown = render_numeric(coeff, scale);
            let amount = sha256_hex(&match shown.split_once('.') {
                Some((whole, frac)) if frac.trim_end_matches('0').is_empty() => {
                    format!("{whole}.0")
                }
                Some((whole, frac)) => format!("{whole}.{}", frac.trim_end_matches('0')),
                None => format!("{shown}.0"),
            });
            hashes.push(hash_list(&[provider, amount]));
        }
        return Ok(variant_hash(
            "BatchOfMintingAllowances",
            &[hash_list(&hashes)],
        ));
    }
    let mut children = Vec::new();
    for child in spec["batches"].as_array().ok_or("batches")? {
        children.push(batch_hash(&child["batchhash"])?);
    }
    Ok(variant_hash("BatchOfBatches", &[hash_list(&children)]))
}

fn value_of(spec: &Json) -> Result<Value, String> {
    let obj = spec.as_object().ok_or("value spec is not an object")?;
    if let Some(p) = obj.get("party") {
        return Ok(Value::Party(p.as_str().ok_or("party")?.to_string()));
    }
    if let Some(t) = obj.get("text") {
        return Ok(Value::Text(t.as_str().ok_or("text")?.to_string()));
    }
    if let Some(n) = obj.get("num") {
        // Numeric 10, the scale of `Decimal`
        let (coeff, scale) = parse_numeric(n.as_str().ok_or("num")?).map_err(|e| e.to_string())?;
        let pad = 10u32
            .checked_sub(u32::from(scale))
            .ok_or("numeric scale above 10")?;
        return Ok(Value::Numeric {
            coeff: coeff * 10i128.pow(pad),
            scale: 10,
        });
    }
    if obj.contains_key("none") {
        return Ok(Value::Optional(None));
    }
    if let Some(r) = obj.get("rewards") {
        // [Splice.Api.FeaturedAppRightV1:AppRewardBeneficiary { beneficiary : Party, weight : Decimal }]
        let mut items = Vec::new();
        for pair in r.as_array().ok_or("rewards")? {
            let party = pair[0].as_str().ok_or("reward party")?.to_string();
            let weight = value_of(&json!({"num": pair[1]}))?;
            items.push(Value::Record {
                tycon: None,
                fields: vec![
                    ("beneficiary".to_string(), Value::Party(party)),
                    ("weight".to_string(), weight),
                ],
            });
        }
        return Ok(Value::List(items.into()));
    }
    if let Some(t) = obj.get("time") {
        // Timestamps are Int64 microseconds throughout this evaluator
        return Ok(Value::Int64(t.as_i64().ok_or("time")?));
    }
    if let Some(p) = obj.get("payment") {
        // Splice.Wallet.Payment:PaymentAmount { amount : Decimal, unit : Unit }
        let amount = value_of(&json!({"num": p["num"]}))?;
        let unit = p["unit"].as_str().ok_or("payment unit")?.to_string();
        return Ok(Value::Record {
            tycon: None,
            fields: vec![
                ("amount".to_string(), amount),
                (
                    "unit".to_string(),
                    Value::Enum {
                        tycon: None,
                        constructor: unit,
                        rank: lf_eval::CtorRank::default(),
                    },
                ),
            ],
        });
    }
    // Generic shapes (the dso-governance group): the spec lists record fields in DECLARATION order, because
    // structural equality of records in the evaluator compares fields by position.
    if let Some(id) = obj.get("cidstr") {
        return Ok(Value::ContractId(id.as_str().ok_or("cidstr")?.to_string()));
    }
    if let Some(n) = obj.get("int") {
        return Ok(Value::Int64(n.as_i64().ok_or("int")?));
    }
    if let Some(b) = obj.get("bool") {
        return Ok(Value::Bool(b.as_bool().ok_or("bool")?));
    }
    if obj.contains_key("unit") {
        return Ok(Value::Unit);
    }
    if let Some(us) = obj.get("reltime") {
        // DA.Time:RelTime { microseconds : Int }
        return Ok(Value::Record {
            tycon: None,
            fields: vec![(
                "microseconds".to_string(),
                Value::Int64(us.as_i64().ok_or("reltime")?),
            )],
        });
    }
    if let Some(items) = obj.get("list") {
        return items
            .as_array()
            .ok_or("list")?
            .iter()
            .map(value_of)
            .collect::<Result<Vec<_>, _>>()
            .map(|v| Value::List(v.into()));
    }
    if let Some(inner) = obj.get("some") {
        return Ok(Value::Optional(Some(Box::new(value_of(inner)?))));
    }
    if let Some(rec) = obj.get("record") {
        return record_of(&rec["fields"]);
    }
    if let Some(name) = obj.get("enum") {
        // an import-alias qualifier (`AL2.SenderSide`) is a Daml-script detail; the evaluator knows the bare name
        let name = name.as_str().ok_or("enum")?;
        return Ok(Value::Enum {
            tycon: None,
            constructor: name.rsplit('.').next().unwrap_or(name).to_string(),
            rank: lf_eval::CtorRank::default(),
        });
    }
    if let Some(v) = obj.get("variant") {
        // the Daml script qualifies constructors with an import alias (`MD1.AV_Text`); the evaluator knows the bare name
        let constructor = v["ctor"]
            .as_str()
            .ok_or("variant ctor")?
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .to_string();
        let value = if v.get("fields").is_some() {
            record_of(&v["fields"])?
        } else {
            value_of(&v["arg"])?
        };
        return Ok(Value::Variant {
            tycon: None,
            constructor,
            rank: lf_eval::CtorRank::default(),
            value: Box::new(value),
        });
    }
    if let Some(items) = obj.get("tuple") {
        // DA.Types:TupleN: fields _1, _2, ...
        let fields = items
            .as_array()
            .ok_or("tuple")?
            .iter()
            .enumerate()
            .map(|(i, v)| Ok((format!("_{}", i + 1), value_of(v)?)))
            .collect::<Result<Vec<_>, String>>()?;
        return Ok(Value::Record {
            tycon: None,
            fields,
        });
    }
    if let Some(items) = obj.get("set") {
        // DA.Set.Set a = record { map : GenMap a () }
        let mut out: Vec<(Value, Value)> = Vec::new();
        for item in items.as_array().ok_or("set")? {
            out.push((value_of(item)?, Value::Unit));
        }
        out.sort_by(|a, b| {
            lf_eval::compare_values(&a.0, &b.0).unwrap_or(std::cmp::Ordering::Equal)
        });
        return Ok(Value::Record {
            tycon: None,
            fields: vec![("map".to_string(), Value::Map(out))],
        });
    }
    if let Some(bh) = obj.get("batchhash") {
        // [CANTON-NOTE: SEMANTICS] Splice.Amulet.CryptoHash.Hash of a reward Batch, computed here the way the Daml library
        // does (SHA-256 over '|'-joined texts), so a scenario can start processing with the root a batch will have to match.
        return Ok(Value::Record {
            tycon: None,
            fields: vec![("value".to_string(), Value::Text(batch_hash(bh)?))],
        });
    }
    if let Some(entries) = obj.get("textmap") {
        // [CANTON-NOTE: SEMANTICS] DA.TextMap shares the evaluator's `Value::Map` (sorted by key); the spec lists
        // `[key, value]` pairs with a plain string key. Used for the token standard `ChoiceContext` and `Metadata`.
        let mut out: Vec<(Value, Value)> = Vec::new();
        for pair in entries.as_array().ok_or("textmap")? {
            out.push((
                Value::Text(pair[0].as_str().ok_or("textmap key")?.to_string()),
                value_of(&pair[1])?,
            ));
        }
        out.sort_by(|a, b| {
            lf_eval::compare_values(&a.0, &b.0).unwrap_or(std::cmp::Ordering::Equal)
        });
        return Ok(Value::Map(out));
    }
    // `coerce` (ContractId a -> ContractId b) and `asholding` (ContractId Amulet -> ContractId Holding) change only
    // the static type; the runtime value is the same contract id.
    if let Some(inner) = obj
        .get("coerce")
        .or_else(|| obj.get("asholding"))
        .or_else(|| obj.get("asholding2"))
        .or_else(|| obj.get("asalloc2"))
        .or_else(|| obj.get("asreward"))
    {
        return value_of(inner);
    }
    if let Some(entries) = obj.get("map") {
        // DA.Map (GenMap): entries kept sorted by key, as the evaluator's map builtins keep them
        let mut out: Vec<(Value, Value)> = Vec::new();
        for pair in entries.as_array().ok_or("map")? {
            out.push((value_of(&pair[0])?, value_of(&pair[1])?));
        }
        out.sort_by(|a, b| {
            lf_eval::compare_values(&a.0, &b.0).unwrap_or(std::cmp::Ordering::Equal)
        });
        return Ok(Value::Map(out));
    }
    Err(format!("unknown value spec {spec}"))
}

/// Replaces `{"cid": n}` (the contract created by step n) by `{"cidstr": id}` in a choice argument. `false` when a
/// referenced step created nothing, in which case the exercise step is skipped like the Daml script skips it.
fn resolve_cids(spec: &mut Json, created: &[Option<String>], engine: &Engine<'_>) -> bool {
    match spec {
        Json::Object(map) => {
            if let Some(found) = map.get("found").cloned() {
                // the first active contract of a template that a party sees (what the Daml script's `query` returns first)
                let suffix = format!(":{}", found["template"].as_str().unwrap_or_default());
                let party = found["party"].as_str().unwrap_or_default().to_string();
                let index = found["index"].as_u64().unwrap_or(0) as usize;
                let filters = where_filters(&found);
                let id = engine
                    .active_contracts()
                    .filter(|c| {
                        matches_filters(&c.payload, &filters)
                            && c.template_id.ends_with(&suffix)
                            && c.signatories
                                .iter()
                                .chain(c.observers.iter())
                                .any(|p| *p == party)
                    })
                    .nth(index)
                    .map(|c| c.contract_id.clone());
                return match id {
                    Some(id) => {
                        *spec = json!({ "cidstr": id });
                        true
                    }
                    None => false,
                };
            }
            if let Some(n) = map.get("cid").and_then(Json::as_u64) {
                return match created.get(n as usize).cloned().flatten() {
                    Some(id) => {
                        *spec = json!({ "cidstr": id });
                        true
                    }
                    None => false,
                };
            }
            map.values_mut().all(|v| resolve_cids(v, created, engine))
        }
        Json::Array(items) => items.iter_mut().all(|v| resolve_cids(v, created, engine)),
        _ => true,
    }
}

/// `where`: `[[path, value], ...]` keeps only the contracts whose field at a dotted path equals the value: an int, or any
/// value spec (a `batchhash`, a party, a text).
fn where_filters(spec: &Json) -> Vec<(String, Json)> {
    spec["where"]
        .as_array()
        .map(|ws| {
            ws.iter()
                .map(|w| (w[0].as_str().unwrap_or_default().to_string(), w[1].clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn matches_filters(payload: &Value, filters: &[(String, Json)]) -> bool {
    filters.iter().all(|(path, want)| {
        let Some(have) = path.split('.').try_fold(payload, |v, name| field(v, name)) else {
            return false;
        };
        match want.as_i64() {
            Some(n) => matches!(have, Value::Int64(m) if *m == n),
            None => value_of(want)
                .ok()
                .and_then(|w| lf_eval::values_equal(have, &w).ok())
                .unwrap_or(false),
        }
    })
}

/// The contract a step exercises: an earlier create step (`"on": n`), or "the first active contract of a template that
/// a party sees" (`"on": {"template", "party"}`), the way the Daml script's `query` returns it.
fn exercise_target(
    engine: &Engine<'_>,
    created: &[Option<String>],
    on: &Json,
) -> Result<Option<String>, String> {
    if let Some(n) = on.as_u64() {
        let n = usize::try_from(n).map_err(|e| e.to_string())?;
        return Ok(created.get(n).cloned().flatten());
    }
    let suffix = format!(":{}", on["template"].as_str().ok_or("on.template")?);
    let party = on["party"].as_str().ok_or("on.party")?.to_string();
    let filters = where_filters(on);
    Ok(engine
        .active_contracts()
        .find(|c| {
            matches_filters(&c.payload, &filters)
                && c.template_id.ends_with(&suffix)
                && c.signatories
                    .iter()
                    .chain(c.observers.iter())
                    .any(|p| *p == party)
        })
        .map(|c| c.contract_id.clone()))
}

/// A derived cell of an observed contract: `field#keys` (a map's party keys) or `field#weights` (an SV map's
/// `name:svRewardWeight` pairs); the Daml script computes the same strings.
fn virtual_cell(base: Option<&Value>, kind: &str) -> String {
    // `field#opt`: an Optional rendered as its value or `none`
    if kind == "opt" {
        return match base {
            Some(Value::Optional(Some(inner))) => format_value(inner),
            _ => "none".to_string(),
        };
    }
    let Some(Value::Map(entries)) = base else {
        return String::new();
    };
    let mut cells: Vec<String> = entries
        .iter()
        .map(|(k, v)| {
            let name = format_value(k);
            match kind {
                "keys" => name,
                // DA.Map Text Vote: `name:yes|no`
                "votes" => format!(
                    "{name}:{}",
                    if matches!(field(v, "accept"), Some(Value::Bool(true))) {
                        "yes"
                    } else {
                        "no"
                    }
                ),
                _ => format!(
                    "{name}:{}",
                    field(v, "svRewardWeight")
                        .map(format_value)
                        .unwrap_or_default()
                ),
            }
        })
        .collect();
    cells.sort();
    cells.join(if kind == "keys" { "," } else { ";" })
}

fn record_of(fields: &Json) -> Result<Value, String> {
    let mut out = Vec::new();
    if let Some(map) = fields.as_object() {
        for (name, spec) in map {
            out.push((name.clone(), value_of(spec)?));
        }
    }
    Ok(Value::Record {
        tycon: None,
        fields: out,
    })
}

/// What the JVM says about a failed authorization (`auth:<message>`), or an uncaught exception /
/// precondition (`failure:<errorId>|<message>`), using real `NodeId(n)` and all 8 `AuthRule`s
/// produced directly by the engine (including interface exercises).
fn detail(err: &ExecError) -> String {
    if let Some(message) = err.canton_auth_message() {
        return format!("auth:{message}");
    }
    match err {
        // a FailureStatus on the JVM: `failure:<errorId>|<message>`
        ExecError::Unhandled { error_id, message } => format!("failure:{error_id}|{message}"),
        ExecError::PreconditionFailed { message } => format!(
            "failure:UNHANDLED_EXCEPTION/DA.Exception.PreconditionFailed:PreconditionFailed|{message}"
        ),
        _ => String::new(),
    }
}

fn category(err: &ExecError) -> String {
    // diagnostics only: `SPLICE_DIFF_ERRORS=1` prints every step error with its message (the comparison itself uses categories)
    if std::env::var_os("SPLICE_DIFF_ERRORS").is_some() {
        eprintln!("step error: {err}");
    }
    match err {
        ExecError::Unauthorized { .. } => "auth".to_string(),
        ExecError::PreconditionFailed { .. } => "precondition".to_string(),
        ExecError::ContractNotFound(_) | ExecError::ContractNotActive(_) => "not-found".to_string(),
        ExecError::Unhandled { .. } => "exception".to_string(),
        ExecError::Eval(lf_eval::EvalError::WrongContractTemplate { .. }) => {
            "wrong-type".to_string()
        }
        other => format!(
            "other:{}",
            other.to_string().replace(['\t', '\n', '"'], " ")
        ),
    }
}

fn format_value(value: &Value) -> String {
    match value {
        Value::Party(p) => p.clone(),
        Value::Text(t) => t.clone(),
        Value::Numeric { coeff, scale } => render_numeric(*coeff, *scale),
        Value::Int64(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Optional(None) => "None".to_string(),
        other => format!("{other:?}"),
    }
}

fn field<'v>(payload: &'v Value, name: &str) -> Option<&'v Value> {
    match payload {
        Value::Record { fields, .. } => fields.iter().find(|(k, _)| k == name).map(|(_, v)| v),
        _ => None,
    }
}

fn run_scenario(
    world: &World,
    packages: &std::collections::BTreeMap<String, String>,
    spec: &Json,
    sc: &Json,
) -> Result<Json, String> {
    let name = sc["name"].as_str().ok_or("scenario name")?;
    let mut engine = Engine::new(world);
    let mut created: Vec<Option<String>> = Vec::new();
    let mut steps: Vec<(String, String)> = Vec::new();
    for st in sc["steps"].as_array().ok_or("steps")? {
        let who: Vec<String> = st["as"]
            .as_array()
            .map(|parties| {
                parties
                    .iter()
                    .map(|p| p.as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default();
        // `readAs` parties of this step: they widen visibility but add no authority
        let read_as: Vec<String> = st["read_as"]
            .as_array()
            .map(|ps| {
                ps.iter()
                    .map(|p| p.as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default();
        engine.set_read_as(&read_as);
        match st["op"].as_str() {
            Some("create") => {
                let template = st["template_id"].as_str().ok_or("template_id")?;
                let payload = record_of(&st["payload"])?;
                // a template of a **dependency** package (the DSO scenarios create an `AmuletRules` of splice-amulet) names it
                let created_result = match st["package_name"].as_str() {
                    Some(name) => {
                        let package = packages
                            .get(name)
                            .ok_or_else(|| format!("no package named {name} in the DAR"))?;
                        engine.execute_create_in(&who, package, template, &payload)
                    }
                    None => engine.execute_create(&who, template, &payload),
                };
                match created_result {
                    Ok(contract) => {
                        created.push(Some(contract.contract_id));
                        steps.push(("ok".to_string(), String::new()));
                    }
                    Err(err) => {
                        created.push(None);
                        steps.push((category(&err), detail(&err)));
                    }
                }
            }
            Some("exercise_iface") => {
                let interface = st["interface"].as_str().ok_or("interface")?;
                let iface_cfg = &spec["interfaces"][interface];
                let module = iface_cfg["module"].as_str().ok_or("interface module")?;
                let package_name = iface_cfg["package_name"]
                    .as_str()
                    .ok_or("interface package")?;
                let package_id = packages
                    .get(package_name)
                    .ok_or_else(|| format!("no package named {package_name} in the DAR"))?;
                let choice = st["choice"].as_str().ok_or("choice")?;
                // the interface's own name (`TransferFactory`), which can differ from the scenario's key (`TransferFactoryV1`)
                let iface_name = iface_cfg["name"].as_str().unwrap_or(interface);
                let target = exercise_target(&engine, &created, &st["on"])?;
                created.push(None);
                match target {
                    None => steps.push(("skip".to_string(), String::new())),
                    Some(cid) => {
                        let mut arg_json = st["arg"].clone();
                        if !resolve_cids(&mut arg_json, &created, &engine) {
                            steps.push(("skip".to_string(), String::new()));
                            continue;
                        }
                        let arg = record_of(&arg_json)?;
                        match engine.execute_exercise_interface(
                            &who,
                            package_id,
                            &format!("{module}:{iface_name}"),
                            &cid,
                            choice,
                            &arg,
                        ) {
                            Ok(_) => steps.push(("ok".to_string(), String::new())),
                            Err(err) => steps.push((category(&err), detail(&err))),
                        }
                    }
                }
            }
            Some("set_time") => {
                engine.set_time_micros(st["micros"].as_i64().ok_or("micros")?);
                created.push(None);
                steps.push(("time".to_string(), String::new()));
            }
            Some("exercise") => {
                let choice = st["choice"].as_str().ok_or("choice")?;
                let target = exercise_target(&engine, &created, &st["on"])?;
                created.push(None);
                match target {
                    None => steps.push(("skip".to_string(), String::new())),
                    Some(cid) => {
                        let mut arg_json = st["arg"].clone();
                        if !resolve_cids(&mut arg_json, &created, &engine) {
                            steps.push(("skip".to_string(), String::new()));
                            continue;
                        }
                        let arg = record_of(&arg_json)?;
                        match engine.execute_exercise(&who, &cid, choice, &arg) {
                            Ok(_) => steps.push(("ok".to_string(), String::new())),
                            Err(err) => steps.push((category(&err), detail(&err))),
                        }
                    }
                }
            }
            other => return Err(format!("unknown op {other:?}")),
        }
    }
    let mut acs = serde_json::Map::new();
    for ob in sc["observe"].as_array().ok_or("observe")? {
        let template = ob["template"].as_str().ok_or("observe template")?;
        let party = ob["party"].as_str().ok_or("observe party")?;
        let fields: Vec<&str> = ob["fields"]
            .as_array()
            .ok_or("observe fields")?
            .iter()
            .filter_map(Json::as_str)
            .collect();
        let suffix = format!(":{template}");
        let mut rows: Vec<String> = Vec::new();
        for c in engine.active_contracts() {
            if !c.template_id.ends_with(&suffix) {
                continue;
            }
            let stakeholders: BTreeSet<&String> =
                c.signatories.iter().chain(c.observers.iter()).collect();
            if !stakeholders.contains(&party.to_string()) {
                continue;
            }
            let cells: Vec<String> = fields
                .iter()
                .map(|f| {
                    let v = match f.split_once('#') {
                        Some((base, kind)) => virtual_cell(field(&c.payload, base), kind),
                        // `config.maxTextLength`: a field path through nested records
                        None => f
                            .split(':')
                            .next()
                            .unwrap_or_default()
                            .split('.')
                            .try_fold(&c.payload, |v, name| field(v, name))
                            .map(format_value)
                            .unwrap_or_default(),
                    };
                    format!("\"{f}\":\"{v}\"")
                })
                .collect();
            rows.push(format!("{{{}}}", cells.join(",")));
        }
        rows.sort();
        let parsed: Vec<Json> = rows
            .iter()
            .map(|r| serde_json::from_str(r).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        acs.insert(format!("{template}@{party}"), Json::Array(parsed));
    }
    for ob in sc["observe_views"].as_array().into_iter().flatten() {
        let interface = ob["interface"].as_str().ok_or("view interface")?;
        let party = ob["party"].as_str().ok_or("view party")?;
        let iface_cfg = &spec["interfaces"][interface];
        let module = iface_cfg["module"].as_str().ok_or("interface module")?;
        let package_name = iface_cfg["package_name"]
            .as_str()
            .ok_or("interface package")?;
        let iface_pkg = packages
            .get(package_name)
            .ok_or_else(|| format!("no package named {package_name} in the DAR"))?;
        let iface_name = iface_cfg["name"].as_str().unwrap_or(interface);
        let iface_id = format!("{module}:{iface_name}");
        let fields: Vec<(&str, String)> = iface_cfg["view_fields"]
            .as_array()
            .ok_or("view_fields")?
            .iter()
            .filter_map(|f| Some((f[0].as_str()?, f[1].as_str().unwrap_or("text").to_string())))
            .collect();
        let mut rows: Vec<String> = Vec::new();
        for c in engine.active_contracts() {
            let stakeholders: BTreeSet<&String> =
                c.signatories.iter().chain(c.observers.iter()).collect();
            if !stakeholders.contains(&party.to_string()) {
                continue;
            }
            if !world
                .template_implements(&c.package_id, &c.template_id, iface_pkg, &iface_id)
                .map_err(|e| e.to_string())?
            {
                continue;
            }
            let view = world
                .eval_interface_view_in(
                    &c.package_id,
                    &c.template_id,
                    iface_pkg,
                    &iface_id,
                    &c.payload,
                )
                .map_err(|e| format!("view of {}: {e}", c.contract_id))?;
            let cells: Vec<String> = fields
                .iter()
                .map(|(f, kind)| {
                    // a dotted path through nested records; `isset` renders an Optional as set/unset
                    let v = f.split('.').try_fold(&view, |v, name| field(v, name));
                    let cell = match (kind.as_str(), v) {
                        ("isset", Some(Value::Optional(Some(_)))) => "set".to_string(),
                        ("isset", _) => "unset".to_string(),
                        ("optparty", Some(Value::Optional(Some(inner)))) => format_value(inner),
                        ("optparty", _) => "none".to_string(),
                        (_, Some(v)) => format_value(v),
                        (_, None) => String::new(),
                    };
                    format!("\"{f}\":\"{cell}\"")
                })
                .collect();
            rows.push(format!("{{{}}}", cells.join(",")));
        }
        rows.sort();
        let parsed: Vec<Json> = rows
            .iter()
            .map(|r| serde_json::from_str(r).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        acs.insert(format!("view:{interface}@{party}"), Json::Array(parsed));
    }
    let (steps, details): (Vec<String>, Vec<String>) = steps.into_iter().unzip();
    Ok(json!({"name": name, "steps": steps, "details": details, "acs": acs}))
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let (Some(dar), Some(scenarios)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: splice-diff <dar> <scenarios.json>");
        return ExitCode::from(2);
    };
    let world = match World::open(Path::new(dar)) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(1);
        }
    };
    let spec: Json = match fs::read_to_string(scenarios)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(1);
        }
    };
    let packages: std::collections::BTreeMap<String, String> = match lf_archive::parse_dar_file(dar)
    {
        Ok(info) => info
            .dalfs
            .iter()
            .filter_map(|d| d.package_name.clone().map(|n| (n, d.package_id.clone())))
            .collect(),
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(1);
        }
    };
    for sc in spec["scenarios"].as_array().into_iter().flatten() {
        match run_scenario(&world, &packages, &spec, sc) {
            Ok(line) => println!("{line}"),
            Err(e) => {
                eprintln!("Error: scenario {}: {e}", sc["name"]);
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}
