//! A committed transaction as the Splice scan app prints it in its update history (G8, S-SPL-006): `UpdateHistoryItemV2`.
//!
//! A port of `ScanHttpEncodings.lapiToHttpUpdate` / `javaToHttpEvent` / `javaToHttpCreatedEvent` (`references/splice/apps/scan/.../http/
//! ScanHttpEncodings.scala`) and of the deterministic event ids `makeConsistentAcrossSvs` assigns: the events of the tree numbered 0, 1, 2, ... in
//! execution order (a fetch takes no number: a scan's tree holds created and exercised events only), an event id `<update id>:<number>`, an
//! exercised event listing the ids of the events directly below it.
//!
//! [CANTON-NOTE: LIMITATION] The offset and the external transaction hash the official item may carry are left out (`/v2/updates` has no offset).
use serde_json::{json, Map, Value as Json};

use crate::engine::{Contract, Engine, EngineEvent};
use crate::typed_json::{
    format_timestamp, format_timestamp_micros, format_timestamp_trimmed, Types,
};

/// What an update has besides its events.
pub struct UpdateMeta<'a> {
    pub update_id: &'a str,
    pub migration_id: i64,
    pub workflow_id: &'a str,
    pub synchronizer_id: &'a str,
    /// The record time and the ledger time (`effective_at`, and the creation time of every contract the transaction creates), in microseconds.
    pub record_time_micros: i64,
    pub effective_at_micros: i64,
}

/// The update item of a transaction whose events (in execution order) are `events`, run on `engine`.
pub fn render_update(
    types: &Types<'_>,
    engine: &Engine<'_>,
    meta: &UpdateMeta<'_>,
    events: &[EngineEvent],
) -> Result<Json, String> {
    render_update_with(types, &|id| engine.contract(id).cloned(), meta, events)
}

/// Like `render_update`, with the contracts the events name given by `contract` instead of an engine that is still alive: a node records
/// them while the engine runs and renders once the transaction is committed and has its update id.
pub fn render_update_with(
    types: &Types<'_>,
    contract: &dyn Fn(&str) -> Option<Contract>,
    meta: &UpdateMeta<'_>,
    events: &[EngineEvent],
) -> Result<Json, String> {
    let id = |n: usize| format!("{}:{n}", meta.update_id);
    let numbered: Vec<&EngineEvent> = events
        .iter()
        .filter(|e| !matches!(e, EngineEvent::Fetch { .. }))
        .collect();
    let mut roots: Vec<String> = Vec::new();
    let mut children: Vec<Vec<String>> = vec![Vec::new(); numbered.len()];
    let mut open: Vec<usize> = Vec::new();
    for (n, event) in numbered.iter().enumerate() {
        let depth = match event {
            EngineEvent::Create { depth, .. } | EngineEvent::Exercise { depth, .. } => *depth,
            EngineEvent::Fetch { .. } => unreachable!("filtered"),
        };
        open.truncate(depth);
        match open.last() {
            Some(parent) => children[*parent].push(id(n)),
            None => roots.push(id(n)),
        }
        if matches!(event, EngineEvent::Exercise { .. }) {
            open.push(n);
        }
    }
    let at = format_timestamp(meta.effective_at_micros);
    let mut by_id: Map<String, Json> = Map::new();
    for (n, event) in numbered.iter().enumerate() {
        let item = match event {
            EngineEvent::Create { contract_id, .. } => {
                let c = contract(contract_id)
                    .ok_or_else(|| format!("the created contract {contract_id} is unknown"))?;
                let ty = types.template(&c.package_id, &c.template_id)?;
                let mut signatories = c.signatories.clone();
                signatories.sort();
                let mut observers = c.observers.clone();
                observers.sort();
                observers.dedup();
                signatories.dedup();
                json!({
                    "event_type": "created_event",
                    "event_id": id(n),
                    "contract_id": contract_id,
                    "template_id": format!("{}:{}", c.package_id, c.template_id),
                    "package_name": types.package_name(&c.package_id)?,
                    "create_arguments": types.encode(&ty, &c.payload)?,
                    "created_at": format_timestamp_trimmed(meta.effective_at_micros),
                    "signatories": signatories,
                    "observers": observers,
                })
            }
            EngineEvent::Exercise {
                contract_id,
                choice,
                consuming,
                actors,
                argument,
                result,
                interface_id,
                ..
            } => {
                let c = contract(contract_id)
                    .ok_or_else(|| format!("the exercised contract {contract_id} is unknown"))?;
                let choice_types = match interface_id {
                    None => types.choice(&c.package_id, &c.template_id, choice)?,
                    Some(interface) => {
                        let (package, id) = interface
                            .split_once(':')
                            .ok_or("an interface id without a package")?;
                        types.interface_choice(package, id, choice)?
                    }
                };
                let result = result
                    .as_ref()
                    .ok_or_else(|| format!("{choice} has no result"))?;
                let mut acting = actors.clone();
                acting.sort();
                json!({
                    "event_type": "exercised_event",
                    "event_id": id(n),
                    "contract_id": contract_id,
                    "template_id": format!("{}:{}", c.package_id, c.template_id),
                    "package_name": types.package_name(&c.package_id)?,
                    "choice": choice,
                    "choice_argument": types.encode(&choice_types.argument, argument)?,
                    "child_event_ids": children[n],
                    "exercise_result": types.encode(&choice_types.result, result)?,
                    "consuming": consuming,
                    "acting_parties": acting,
                    "interface_id": interface_id,
                })
            }
            EngineEvent::Fetch { .. } => unreachable!("filtered"),
        };
        by_id.insert(id(n), item);
    }
    Ok(json!({
        "update_id": meta.update_id,
        "migration_id": meta.migration_id,
        "workflow_id": meta.workflow_id,
        "record_time": format_timestamp_micros(meta.record_time_micros),
        "synchronizer_id": meta.synchronizer_id,
        "effective_at": at,
        "root_event_ids": roots,
        "events_by_id": by_id,
    }))
}

/// What a contract's `created_event_blob` is made of (G8, S-SPL-008): a Daml-LF `FatContractInstance` wrapped in `Versioned`.
pub struct BlobContract<'a> {
    /// The contract id as hex (the scan's contract id spelling).
    pub contract_id: &'a str,
    pub package_id: &'a str,
    pub package_name: &'a str,
    /// `"Module.Path:Entity"`.
    pub template_id: &'a str,
    /// `Types::to_wire` of the contract's argument.
    pub create_arg: &'a [u8],
    pub signatories: &'a [String],
    pub observers: &'a [String],
    pub created_at_micros: i64,
    /// `ContractAuthenticationData` (the contract salt, as the node that created the contract made it): not part of any update.
    pub authentication_data: &'a [u8],
}

/// The blob of a contract without a key: `Versioned { version = "2.1", payload = FatContractInstance }` as the Canton contract coder writes it
/// (`ContractInstanceCoder`; the layout is the one `canton_participant::contract_wire` writes for the transaction protocol).
///
/// [CANTON-NOTE: LIMITATION] No contract key (the Splice templates the scan returns have none); a key makes the version "2".
pub fn created_event_blob(c: &BlobContract<'_>) -> Result<Vec<u8>, String> {
    use crate::typed_json::{wire_field, wire_tag};
    let id = (0..c.contract_id.len() / 2)
        .map(|i| u8::from_str_radix(&c.contract_id[2 * i..2 * i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| format!("contract id {} is not hex", c.contract_id))?;
    let (module, entity) = c
        .template_id
        .split_once(':')
        .ok_or("a template id without a module")?;
    let mut identifier = Vec::new();
    wire_field(&mut identifier, 1, c.package_id.as_bytes());
    for part in module.split('.') {
        wire_field(&mut identifier, 2, part.as_bytes());
    }
    for part in entity.split('.') {
        wire_field(&mut identifier, 3, part.as_bytes());
    }
    let sorted = |parties: &[String]| {
        let mut p = parties.to_vec();
        p.sort();
        p.dedup();
        p
    };
    let signatories = sorted(c.signatories);
    let observers: Vec<String> = sorted(c.observers)
        .into_iter()
        .filter(|o| !signatories.contains(o))
        .collect();
    let mut instance = Vec::new();
    wire_field(&mut instance, 1, &id);
    wire_field(&mut instance, 2, c.package_name.as_bytes());
    wire_field(&mut instance, 3, &identifier);
    wire_field(&mut instance, 4, c.create_arg);
    for s in &signatories {
        wire_field(&mut instance, 5, s.as_bytes());
    }
    for o in &observers {
        wire_field(&mut instance, 6, o.as_bytes());
    }
    wire_tag(&mut instance, 7, 1);
    instance.extend_from_slice(&c.created_at_micros.to_le_bytes());
    wire_field(&mut instance, 8, c.authentication_data);
    let mut versioned = Vec::new();
    wire_field(&mut versioned, 1, b"2.1");
    wire_field(&mut versioned, 2, &instance);
    Ok(versioned)
}
