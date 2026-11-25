use super::NodeCommitter;
use crate::service::{ApiError, ExecutionService, ProtocolCommitter, RemoteApplied, RemoteCreated};

/// The Daml value inside a stored `Versioned` message (field 2; field 1 is the version text).
fn versioned_value(bytes: &[u8]) -> Result<&[u8], String> {
    fn varint(bytes: &[u8]) -> Option<(usize, usize)> {
        let (mut value, mut shift) = (0usize, 0);
        for (at, b) in bytes.iter().enumerate() {
            value |= ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 {
                return Some((value, at + 1));
            }
            shift += 7;
        }
        None
    }
    let mut rest = bytes;
    while !rest.is_empty() {
        let (key, used) = varint(rest).ok_or("a versioned value that ends early")?;
        rest = &rest[used..];
        if key & 7 != 2 {
            return Err("a versioned value with a field that is not bytes".into());
        }
        let (len, used) = varint(rest).ok_or("a versioned value that ends early")?;
        let body = rest
            .get(used..used + len)
            .ok_or("a versioned value that ends early")?;
        if key >> 3 == 2 {
            return Ok(body);
        }
        rest = &rest[used + len..];
    }
    Err("a versioned value without its value".into())
}

/// What an exercise of the official history says to the service: the choice with its argument and result read by the types the contract's package
/// declares for the choice.
fn exercise_info(
    engine: &canton_participant::view_conformance::Engine,
    package_id: &str,
    template: &str,
    x: &canton_participant::official_state::OfficialExercise,
) -> Result<crate::v2_commands::ExInfo, String> {
    let types = lf_eval::typed_json::Types::new(&engine.world);
    let choice = types.choice(package_id, template, &x.choice)?;
    let read = |ty: &lf_eval::typed_json::LfType, bytes: &[u8]| -> Result<_, String> {
        let value = types.from_wire(ty, versioned_value(bytes)?)?;
        let json = types.encode_ledger_api(ty, &value)?;
        Ok((value, json))
    };
    let (argument_value, argument) = read(&choice.argument, &x.argument)?;
    let (result_value, result) = read(&choice.result, &x.result)?;
    Ok(crate::v2_commands::ExInfo {
        choice: x.choice.clone(),
        argument,
        argument_value: Some(argument_value),
        acting: x.actors.clone(),
        consuming: x.consuming,
        result,
        result_value: Some(result_value),
        last_descendant: x.last_descendant.max(0) as u64,
        interface_id: None,
        choice_observers: Vec::new(),
    })
}

/// One engine over all the DARs of an official participant's database.
///
/// [CANTON-NOTE: WHY] The service runs one DAR at a time, the contracts of an official participant are of several.
fn official_engine(
    dars: &[Vec<u8>],
) -> Result<Option<canton_participant::view_conformance::Engine>, ApiError> {
    let mut engine: Option<canton_participant::view_conformance::Engine> = None;
    for (i, bytes) in dars.iter().enumerate() {
        let path =
            std::env::temp_dir().join(format!("official-dar-{}-{i}.dar", std::process::id()));
        std::fs::write(&path, bytes).map_err(|e| ApiError::Ledger(e.to_string()))?;
        let loaded = match engine.as_mut() {
            None => {
                canton_participant::view_conformance::Engine::load(&path).map(|e| engine = Some(e))
            }
            Some(e) => e.add_dar(&path).map(|_| ()),
        };
        let _ = std::fs::remove_file(&path);
        loaded.map_err(|e| ApiError::Ledger(format!("DAR {i}: {e}")))?;
    }
    Ok(engine)
}

/// Shows the updates of an official participant's history (`updates`, read by `official_state::read_updates`) as the updates of `service`: the
/// creations and archivals of each transaction with the ids, times, witnesses and trace context the participant recorded. Returns how many were
/// shown and, for each that could not be, its offset and why.
///
/// [CANTON-NOTE: LIMITATION] Creations and exercises are read (consuming and non-consuming, with the argument and result by the choice's types);
/// reassignments and topology events are not.
pub fn official_updates_in(
    service: &ExecutionService,
    dars: &[Vec<u8>],
    updates: &[canton_participant::official_state::OfficialUpdate],
) -> Result<(usize, Vec<(i64, String)>), ApiError> {
    let Some(engine) = official_engine(dars)? else {
        return Ok((
            0,
            updates
                .iter()
                .map(|u| (u.offset, "no DAR".to_string()))
                .collect(),
        ));
    };
    let packages = service.loaded_packages()?;
    let (mut adopted, mut skipped) = (Vec::new(), Vec::new());
    'updates: for u in updates {
        let mut events = Vec::new();
        let mut effective = None;
        for e in &u.events {
            let opened = canton_participant::view_conformance::open_instance(&engine, &e.instance);
            let c = match opened {
                Ok(c) => c,
                Err(why) => {
                    skipped.push((u.offset, why));
                    continue 'updates;
                }
            };
            let (package_id, template) = (c.package_id.clone(), c.template.clone());
            let contract =
                match service.remote_contract(&packages, &to_remote_stored(c, &e.instance)) {
                    Ok(Some(contract)) => contract,
                    Ok(None) => {
                        skipped.push((u.offset, "its package is not loaded".to_string()));
                        continue 'updates;
                    }
                    Err(why) => {
                        skipped.push((u.offset, why.to_string()));
                        continue 'updates;
                    }
                };
            effective = effective
                .or(e.effective_micros)
                .or(Some(contract.created_at_micros));
            let mut contract = contract;
            // [CANTON-NOTE: SEMANTICS] Measured on the hub's participant: the additional witnesses come first, in the order the participant stored them,
            // then the stakeholders in the order of a Scala `Set` (alphabetical up to four).
            contract.witness_parties = e
                .additional
                .iter()
                .cloned()
                .chain(lf_eval::script::scala_witness_order(&e.stakeholders))
                .collect();
            let exercise = match &e.exercise {
                None => None,
                Some(x) => match exercise_info(&engine, &package_id, &template, x) {
                    Ok(info) => Some(info),
                    Err(why) => {
                        skipped.push((u.offset, why));
                        continue 'updates;
                    }
                },
            };
            events.push(crate::v2_commands::Ev {
                created: exercise.is_none(),
                exercise,
                node: e.node_id.max(0) as u64,
                contract,
            });
        }
        adopted.push(crate::v2_commands::StoredUpdate {
            update_id: u.update_id.clone(),
            offset: u.offset.max(0) as u64,
            command_id: u.command_id.clone(),
            effective_at: crate::v2_commands::rfc3339_from_micros(effective.unwrap_or(0)),
            events,
            at_micros: u.record_time_micros,
            external_transaction_hash: u.external_transaction_hash.clone(),
            reassignment: None,
            topology: None,
            official: Some(Box::new(crate::v2_commands::OfficialMeta {
                workflow_id: u.workflow_id.clone(),
                record_time: crate::v2_commands::rfc3339_from_micros(u.record_time_micros),
                synchronizer_id: u.synchronizer.clone(),
                trace_parent: u.trace_parent.clone(),
                traffic_cost: u.traffic_cost,
                submitters: u.submitters.clone(),
            })),
            trace_parent: None,
            act_as: u.submitters.clone(),
        });
    }
    let shown = adopted.len();
    service.adopt_official_updates(adopted);
    Ok((shown, skipped))
}

/// Shows the contracts an official participant's database holds as active (`(contract id, versioned FatContractInstance bytes)`) in the ACS of `service`:
/// each is read with an engine that has every DAR of the database (`dars`: the archives' bytes) and applied as a contract created elsewhere. Returns how
/// many were shown and, for each contract that could not be, its id and why (its package is not among the DARs, or the service cannot show its type).
pub fn show_official_contracts_in(
    service: &ExecutionService,
    dars: &[Vec<u8>],
    instances: &[(String, Vec<u8>)],
) -> Result<(usize, Vec<(String, String)>), ApiError> {
    let engine = official_engine(dars)?;
    let (mut shown, mut skipped) = (0, Vec::new());
    let Some(engine) = engine else {
        return Ok((
            0,
            instances
                .iter()
                .map(|(id, _)| (id.clone(), "no DAR".to_string()))
                .collect(),
        ));
    };
    for (contract_id, bytes) in instances {
        match canton_participant::view_conformance::open_instance(&engine, bytes) {
            Ok(c) => {
                let applied = service.apply_remote_without_v2(RemoteApplied {
                    request_id: 0,
                    created: vec![to_remote_stored(c, bytes)],
                    consumed: Vec::new(),
                    root_hash: None,
                    events: Vec::new(),
                });
                match applied {
                    Ok(()) => shown += 1,
                    // one contract the service cannot show does not stop the others: it is reported with the reason
                    Err(e) => skipped.push((contract_id.clone(), e.to_string())),
                }
            }
            Err(e) => skipped.push((contract_id.clone(), e)),
        }
    }
    Ok((shown, skipped))
}

/// A contract read from an official participant's database, with the instance bytes that are its created-event blob.
pub(super) fn to_remote_stored(
    c: canton_participant::view_conformance::OpenedContract,
    instance: &[u8],
) -> RemoteCreated {
    RemoteCreated {
        blob: Some(instance.to_vec()),
        ..to_remote(c)
    }
}

pub(super) fn to_remote(c: canton_participant::view_conformance::OpenedContract) -> RemoteCreated {
    RemoteCreated {
        observers: c.stakeholders.difference(&c.signatories).cloned().collect(),
        signatories: c.signatories.into_iter().collect(),
        contract_id: c.contract_id,
        package_id: c.package_id,
        template: c.template,
        payload: c.arg,
        created_at_micros: c.created_at_micros,
        salt: None,
        blob: None,
    }
}

impl NodeCommitter {
    /// Lets the participant exercise what an official participant's database holds: vets the packages of its DARs on the synchronizer this participant
    /// joined, then holds the active contracts' instances. Returns the DARs vetted, the contracts adopted and the problems met (one line each).
    pub fn adopt_official(
        &self,
        dars: &[Vec<u8>],
        instances: &[(String, Vec<u8>)],
    ) -> (usize, usize, Vec<String>) {
        let mut problems = Vec::new();
        let mut vetted = 0;
        for (i, bytes) in dars.iter().enumerate() {
            match <Self as ProtocolCommitter>::vet_dar(self, bytes) {
                Ok(()) => vetted += 1,
                Err(e) => problems.push(format!("DAR {i}: {e}")),
            }
        }
        let mut adopted = 0;
        for (id, bytes) in instances {
            match self.node.adopt_instance(bytes) {
                Ok(()) => adopted += 1,
                Err(e) => problems.push(format!("contract {}…: {e}", &id[..id.len().min(16)])),
            }
        }
        (vetted, adopted, problems)
    }
}
