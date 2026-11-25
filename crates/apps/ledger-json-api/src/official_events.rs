//! The transactions, contracts and command completions of a participant written to the Ledger API tables of an official Canton 3.7.2 participant's
//! database (`--official-write`, U-47): `lapi_events_activate_contract`, `lapi_events_deactivate_contract`, `lapi_events_various_witnessed`, the
//! `lapi_filter_*` tables, `lapi_update_meta`, `lapi_command_completions`, `lapi_string_interning`, `par_contracts`, and the ledger end in
//! `lapi_parameters`, `lapi_ledger_end_synchronizer_index` and `lapi_post_processing_end`.
//!
//! [CANTON-NOTE: SEMANTICS] The layout is what the official participant writes for the same transaction, measured by creating a contract through
//! a second Canton 3.7.2 on a copy of the hub's databases and comparing every table before and after: a create writes the activate row, one
//! stakeholder filter row per stakeholder (`first_per_sequential_id` true on the first of the event's parties in the order of a Scala `Set`), the
//! contract (`par_contracts`: id, instance, package id, `Module:Entity`), the completion, the update's meta row, and moves the ledger end (offset,
//! sequential id, interning id, publication time), the synchronizer's index time and the post-processing end. Strings (parties, templates, packages,
//! choices, users, synchronizers) are numbered in `lapi_string_interning` (`p|`, `t|#package-name:Module:Entity`, `i|`, `c|`, `u|`, `d|`); a list
//! of parties is a `01` byte and each party's number in four bytes.
//!
//! [CANTON-NOTE: LIMITATION] What the official participant's protocol processing writes besides (`common_sequenced_events`, `par_journal_requests`,
//! `par_active_contracts`, the ACS commitment tables, `par_fresh_submitted_transaction`, `par_command_deduplication`) is **not** written: it belongs to the
//! synchronizer the official participant is connected to, and the Rust participant has its own. The Ledger API shows the transactions; the official
//! participant cannot exercise a contract it only knows from here.
use std::collections::BTreeMap;

use postgres::{Client, Transaction};

use crate::service::ExecutionService;
use crate::v2_commands::StoredUpdate;
use crate::v2_completions::Completion;

type Res<T> = Result<T, String>;

fn db(e: postgres::Error) -> String {
    match e.as_db_error() {
        Some(d) => format!("{} ({})", d.message(), d.detail().unwrap_or("")),
        None => e.to_string(),
    }
}

/// The number of a string in `lapi_string_interning` (`kind` is the letter of the stored text: `p`, `t`, `i`, `c`, `u`, `d`), added when it is new.
fn intern(tx: &mut Transaction<'_>, kind: char, value: &str) -> Res<i32> {
    let stored = format!("{kind}|{value}");
    if let Some(r) = tx
        .query_opt(
            "SELECT internal_id FROM lapi_string_interning WHERE external_string = $1",
            &[&stored],
        )
        .map_err(db)?
    {
        return Ok(r.get(0));
    }
    let next: i32 = tx
        .query_one(
            "SELECT COALESCE(MAX(internal_id), 0) + 1 FROM lapi_string_interning",
            &[],
        )
        .map_err(db)?
        .get(0);
    tx.execute(
        "INSERT INTO lapi_string_interning (internal_id, external_string) VALUES ($1, $2)",
        &[&next, &stored],
    )
    .map_err(db)?;
    Ok(next)
}

/// A list of parties as the tables store it: a `01` byte, then each party's number in four bytes (big endian).
fn party_list(ids: &[i32]) -> Vec<u8> {
    let mut out = vec![1u8];
    for id in ids {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out
}

/// The trace context of a record: a protobuf message whose field 1 is the `traceparent`.
fn trace_context(traceparent: &str) -> Vec<u8> {
    let mut out = vec![0x0a, traceparent.len() as u8];
    out.extend_from_slice(traceparent.as_bytes());
    out
}

/// A value as the tables keep it: the `Versioned` message of the version `2.1` and the value's bytes.
fn versioned(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x0a, 0x03];
    out.extend_from_slice(b"2.1");
    out.push(0x12);
    let mut len = value.len();
    while len >= 0x80 {
        out.push((len & 0x7f) as u8 | 0x80);
        len >>= 7;
    }
    out.push(len as u8);
    out.extend_from_slice(value);
    out
}

fn decode_base64(text: &str) -> Vec<u8> {
    crate::v2::unbase64(text).unwrap_or_default()
}

/// Writes one committed transaction and its completion.
pub(crate) fn write_transaction(
    service: &ExecutionService,
    client: &mut Client,
    u: &StoredUpdate,
    completion: Option<&Completion>,
) -> Res<()> {
    let mut tx = client.transaction().map_err(db)?;
    let state = service.v2_state();
    let params = tx
        .query_one(
            "SELECT ledger_end, ledger_end_sequential_id FROM lapi_parameters FOR UPDATE",
            &[],
        )
        .map_err(db)?;
    let mut seq: i64 = params.get::<_, Option<i64>>(1).unwrap_or(0);
    let first_seq = seq + 1;
    let record_time = u.at_micros;
    let publication = crate::clock::now_micros().max(record_time);
    let synchronizer = u
        .official
        .as_ref()
        .map(|o| o.synchronizer_id.clone())
        .unwrap_or_else(|| state.synchronizer_id());
    let sync_id = intern(&mut tx, 'd', &synchronizer)?;
    let update_id = hex::decode(&u.update_id).map_err(|e| e.to_string())?;
    let trace = trace_context("00-00000000000000000000000000000000-0000000000000000-00");
    let (user, submission, command) = completion
        .map(|c| {
            (
                c.user_id.as_str(),
                c.submission_id.as_str(),
                c.command_id.as_str(),
            )
        })
        .unwrap_or(("", "", u.command_id.as_str()));
    let submitters: Vec<i32> = match completion {
        Some(c) => c
            .act_as
            .iter()
            .map(|p| intern(&mut tx, 'p', p))
            .collect::<Res<_>>()?,
        None => Vec::new(),
    };
    let command_param: Option<&str> = completion
        .map(|c| c.command_id.as_str())
        .or_else(|| (!u.command_id.is_empty()).then_some(u.command_id.as_str()));
    let submitters_param: Option<Vec<u8>> = completion.is_some().then(|| party_list(&submitters));
    let node_actors = |x: &crate::v2_commands::ExInfo| x.acting.clone();
    // the witnesses an event has besides its own stakeholders: the stakeholders and actors of the exercises above it
    let inherited = |node: u64| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for above in &u.events {
            if let Some(x) = &above.exercise {
                if above.node < node && node <= x.last_descendant {
                    for p in above
                        .contract
                        .signatories
                        .iter()
                        .chain(&above.contract.observers)
                        .chain(&node_actors(x))
                    {
                        if !out.contains(p) {
                            out.push(p.clone());
                        }
                    }
                }
            }
        }
        out
    };
    let mut written = 0;
    let mut active_seq: BTreeMap<String, i64> = BTreeMap::new();
    for e in &u.events {
        let c = &e.contract;
        let mut stakeholders: Vec<String> = c.signatories.clone();
        for p in &c.observers {
            if !stakeholders.contains(p) {
                stakeholders.push(p.clone());
            }
        }
        let stakeholders = lf_eval::script::scala_witness_order(&stakeholders);
        let stakeholder_ids: Vec<i32> = stakeholders
            .iter()
            .map(|p| intern(&mut tx, 'p', p))
            .collect::<Res<_>>()?;
        let package_name = service
            .v2_package_name(&c.template_id.package_id)
            .unwrap_or_default();
        let template_text = format!(
            "#{package_name}:{}:{}",
            c.template_id.module_name, c.template_id.entity_name
        );
        let template = intern(&mut tx, 't', &template_text)?;
        let package = intern(&mut tx, 'i', &c.template_id.package_id)?;
        let extra: Vec<String> = inherited(e.node)
            .into_iter()
            .filter(|p| !stakeholders.contains(p))
            .collect();
        let extra_ids: Vec<i32> = extra
            .iter()
            .map(|p| intern(&mut tx, 'p', p))
            .collect::<Res<_>>()?;
        let contract_id = hex::decode(&c.contract_id).map_err(|e| e.to_string())?;
        seq += 1;
        match (&e.exercise, e.created) {
            (None, true) => {
                let instance = decode_base64(&c.created_event_blob);
                if instance.is_empty() {
                    return Err(format!(
                        "the contract {} has no instance (only a protocol-mode contract does)",
                        c.contract_id
                    ));
                }
                let local = format!(
                    "{}:{}",
                    c.template_id.module_name, c.template_id.entity_name
                );
                let internal: i64 = match tx
                    .query_opt("SELECT internal_contract_id FROM par_contracts WHERE contract_id = $1", &[&contract_id])
                    .map_err(db)?
                {
                    Some(r) => r.get(0),
                    None => tx
                        .query_one(
                            "INSERT INTO par_contracts (contract_id, instance, package_id, template_id) VALUES ($1, $2, $3, $4) RETURNING internal_contract_id",
                            &[&contract_id, &instance, &c.template_id.package_id, &local],
                        )
                        .map_err(db)?
                        .get(0),
                };
                tx.execute(
                    "INSERT INTO lapi_events_activate_contract (event_offset, update_id, workflow_id, command_id, submitters, record_time, synchronizer_id, \
                     trace_context, event_type, event_sequential_id, node_id, additional_witnesses, representative_package_id, internal_contract_id, traffic_cost) \
                     VALUES ($1, $2, '', $3, $4, $5, $6, $7, 1, $8, $9, $10, $11, $12, 0)",
                    &[
                        &(u.offset as i64),
                        &update_id,
                        &command_param,
                        &submitters_param,
                        &record_time,
                        &sync_id,
                        &trace,
                        &seq,
                        &(e.node as i32),
                        &if extra_ids.is_empty() { Vec::new() } else { party_list(&extra_ids) },
                        &package,
                        &internal,
                    ],
                )
                .map_err(db)?;
                for (i, party) in stakeholder_ids.iter().enumerate() {
                    tx.execute(
                        "INSERT INTO lapi_filter_activate_stakeholder (event_sequential_id, template_id, party_id, first_per_sequential_id) VALUES ($1, $2, $3, $4)",
                        &[&seq, &template, party, &(i == 0).then_some(true)],
                    )
                    .map_err(db)?;
                }
                for (i, party) in extra_ids.iter().enumerate() {
                    tx.execute(
                        "INSERT INTO lapi_filter_activate_witness (event_sequential_id, template_id, party_id, first_per_sequential_id) VALUES ($1, $2, $3, $4)",
                        &[&seq, &template, party, &(i == 0).then_some(true)],
                    )
                    .map_err(db)?;
                }
                active_seq.insert(c.contract_id.clone(), seq);
                write_active_contract(&mut tx, &contract_id, true, record_time)?;
            }
            (Some(x), false) => {
                let types_pkg = service.v2_lf_package(&c.template_id.package_id);
                let (argument, result) = match &types_pkg {
                    Some(p) => {
                        let types = lf_eval::typed_json::Types::new(&p.world);
                        let local = format!(
                            "{}:{}",
                            c.template_id.module_name, c.template_id.entity_name
                        );
                        // [CANTON-NOTE: SEMANTICS] A choice exercised through an interface is declared by the interface (`pkg:Module:Name`), not by the template.
                        let ch = match x.interface_id.as_deref().and_then(|i| i.split_once(':')) {
                            Some((interface_package, interface_name)) => types.interface_choice(
                                interface_package,
                                interface_name,
                                &x.choice,
                            )?,
                            None => types.choice(&c.template_id.package_id, &local, &x.choice)?,
                        };
                        let arg = match &x.argument_value {
                            Some(v) => versioned(&types.to_wire(&ch.argument, v)?),
                            None => Vec::new(),
                        };
                        let res = match &x.result_value {
                            Some(v) => versioned(&types.to_wire(&ch.result, v)?),
                            None => Vec::new(),
                        };
                        (arg, res)
                    }
                    None => (Vec::new(), Vec::new()),
                };
                let choice = intern(&mut tx, 'c', &x.choice)?;
                // the interface an exercise went through is interned (`i|`) beside the choice (`c|`)
                let interface: Option<i32> = match &x.interface_id {
                    Some(i) => Some(intern(&mut tx, 'i', i)?),
                    None => None,
                };
                let actors: Vec<i32> = x
                    .acting
                    .iter()
                    .map(|p| intern(&mut tx, 'p', p))
                    .collect::<Res<_>>()?;
                let internal: Option<i64> = tx
                    .query_opt(
                        "SELECT internal_contract_id FROM par_contracts WHERE contract_id = $1",
                        &[&contract_id],
                    )
                    .map_err(db)?
                    .map(|r| r.get(0));
                if x.consuming {
                    let deactivated: i64 = match active_seq.get(&c.contract_id) {
                        Some(s) => *s,
                        None => tx
                            .query_one(
                                "SELECT a.event_sequential_id FROM lapi_events_activate_contract a JOIN par_contracts p ON p.internal_contract_id = a.internal_contract_id WHERE p.contract_id = $1",
                                &[&contract_id],
                            )
                            .map_err(|_| format!("the contract {} is not in lapi_events_activate_contract", c.contract_id))?
                            .get(0),
                    };
                    tx.execute(
                        "INSERT INTO lapi_events_deactivate_contract (event_offset, update_id, workflow_id, command_id, submitters, record_time, synchronizer_id, \
                         trace_context, event_type, event_sequential_id, node_id, deactivated_event_sequential_id, additional_witnesses, exercise_choice, \
                         exercise_argument, exercise_result, exercise_actors, exercise_last_descendant_node_id, contract_id, internal_contract_id, template_id, \
                         package_id, stakeholders, ledger_effective_time, traffic_cost, exercise_choice_interface) \
                         VALUES ($1, $2, '', $3, $4, $5, $6, $7, 3, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, 0, $23)",
                        &[
                            &(u.offset as i64),
                            &update_id,
                            &command_param,
                            &submitters_param,
                            &record_time,
                            &sync_id,
                            &trace,
                            &seq,
                            &(e.node as i32),
                            &deactivated,
                            &if extra_ids.is_empty() { Vec::new() } else { party_list(&extra_ids) },
                            &choice,
                            &argument,
                            &result,
                            &party_list(&actors),
                            &(x.last_descendant as i32),
                            &contract_id,
                            &internal,
                            &template,
                            &package,
                            &party_list(&stakeholder_ids),
                            &u.at_micros,
                            &interface,
                        ],
                    )
                    .map_err(db)?;
                    for (i, party) in stakeholder_ids.iter().enumerate() {
                        tx.execute(
                            "INSERT INTO lapi_filter_deactivate_stakeholder (event_sequential_id, template_id, party_id, first_per_sequential_id) VALUES ($1, $2, $3, $4)",
                            &[&seq, &template, party, &(i == 0).then_some(true)],
                        )
                        .map_err(db)?;
                    }
                    for (i, party) in extra_ids.iter().enumerate() {
                        tx.execute(
                            "INSERT INTO lapi_filter_deactivate_witness (event_sequential_id, template_id, party_id, first_per_sequential_id) VALUES ($1, $2, $3, $4)",
                            &[&seq, &template, party, &(i == 0).then_some(true)],
                        )
                        .map_err(db)?;
                    }
                    write_active_contract(&mut tx, &contract_id, false, record_time)?;
                } else {
                    // [CANTON-NOTE: SEMANTICS] A non-consuming exercise has no stakeholders: everybody who sees it (its actors, the contract's stakeholders and the
                    // witnesses above it) is in `additional_witnesses` and in the filter table, the first in the order of a Scala `Set` flagged first
                    // (measured on the hub's participant, and by the official Canton refusing to show the exercise to any party when the column is empty).
                    let mut seen: Vec<String> = c.signatories.clone();
                    for p in c.observers.iter().chain(&x.acting).chain(&extra) {
                        if !seen.contains(p) {
                            seen.push(p.clone());
                        }
                    }
                    let seen = lf_eval::script::scala_witness_order(&seen);
                    let seen_ids: Vec<i32> = seen
                        .iter()
                        .map(|p| intern(&mut tx, 'p', p))
                        .collect::<Res<_>>()?;
                    tx.execute(
                        "INSERT INTO lapi_events_various_witnessed (event_offset, update_id, workflow_id, command_id, submitters, record_time, synchronizer_id, \
                         trace_context, event_type, event_sequential_id, node_id, additional_witnesses, consuming, exercise_choice, exercise_argument, \
                         exercise_result, exercise_actors, exercise_last_descendant_node_id, contract_id, internal_contract_id, template_id, package_id, \
                         ledger_effective_time, traffic_cost, exercise_choice_interface) \
                         VALUES ($1, $2, '', $3, $4, $5, $6, $7, 5, $8, $9, $10, false, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, 0, $21)",
                        &[
                            &(u.offset as i64),
                            &update_id,
                            &command_param,
                            &submitters_param,
                            &record_time,
                            &sync_id,
                            &trace,
                            &seq,
                            &(e.node as i32),
                            &party_list(&seen_ids),
                            &choice,
                            &argument,
                            &result,
                            &party_list(&actors),
                            &(x.last_descendant as i32),
                            &contract_id,
                            &internal,
                            &template,
                            &package,
                            &u.at_micros,
                            &interface,
                        ],
                    )
                    .map_err(db)?;
                    for (i, party) in seen_ids.iter().enumerate() {
                        tx.execute(
                            "INSERT INTO lapi_filter_various_witness (event_sequential_id, template_id, party_id, first_per_sequential_id) VALUES ($1, $2, $3, $4)",
                            &[&seq, &template, party, &(i == 0).then_some(true)],
                        )
                        .map_err(db)?;
                    }
                }
            }
            _ => {
                // [CANTON-NOTE: LIMITATION] Non-create/non-exercise events are skipped without
                // incrementing `written` so transactions with zero indexed rows roll back cleanly.
                seq -= 1;
                continue;
            }
        }
        written += 1;
    }
    if written == 0 {
        // a transaction with no event the tables keep (a reassignment, an empty tree) writes no update
        tx.rollback().map_err(db)?;
        return Ok(());
    }
    tx.execute(
        "INSERT INTO lapi_update_meta (update_id, event_offset, publication_time, record_time, synchronizer_id, event_sequential_id_first, event_sequential_id_last) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &[&update_id, &(u.offset as i64), &publication, &record_time, &sync_id, &first_seq, &seq],
    )
    .map_err(db)?;
    if completion.is_some() {
        if let Some(phys_idx) = resolve_synchronizer_idx(&mut tx)? {
            let max_seq_time = record_time.saturating_add(60_000_000);
            tx.execute(
                "INSERT INTO par_fresh_submitted_transaction \
                 (physical_synchronizer_idx, root_hash_hex, request_id, max_sequencing_time) \
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[&phys_idx, &u.update_id, &record_time, &max_seq_time],
            )
            .map_err(db)?;
        }
    }
    if let Some(c) = completion {
        let user_id = intern(&mut tx, 'u', user)?;
        let dedup_offset = record_command_dedup(
            &mut tx,
            user,
            command,
            &c.act_as,
            c.offset as i64,
            publication,
            submission,
            &trace,
            true,
        )?;
        tx.execute(
            "INSERT INTO lapi_command_completions (completion_offset, record_time, publication_time, user_id, submitters, command_id, update_id, submission_id, \
             deduplication_offset, synchronizer_id, is_transaction, trace_context, traffic_cost) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, $11, 0)",
            &[
                &(c.offset as i64),
                &record_time,
                &publication,
                &user_id,
                &party_list(&submitters),
                &command,
                &update_id,
                &submission,
                &dedup_offset,
                &sync_id,
                &trace,
            ],
        )
        .map_err(db)?;
    }
    move_ledger_end(
        &mut tx,
        u.offset as i64,
        seq,
        publication,
        record_time,
        sync_id,
    )?;
    tx.commit().map_err(db)
}

/// Writes a refused command's completion.
pub(crate) fn write_rejection(
    client: &mut Client,
    service: &ExecutionService,
    c: &Completion,
) -> Res<()> {
    let mut tx = client.transaction().map_err(db)?;
    let params = tx
        .query_one(
            "SELECT ledger_end_sequential_id FROM lapi_parameters FOR UPDATE",
            &[],
        )
        .map_err(db)?;
    let seq: i64 = params.get::<_, Option<i64>>(0).unwrap_or(0);
    let publication = crate::clock::now_micros();
    let sync_id = intern(&mut tx, 'd', &service.v2_state().synchronizer_id())?;
    let user_id = intern(&mut tx, 'u', &c.user_id)?;
    let submitters: Vec<i32> = c
        .act_as
        .iter()
        .map(|p| intern(&mut tx, 'p', p))
        .collect::<Res<_>>()?;
    let trace = trace_context("00-00000000000000000000000000000000-0000000000000000-00");
    let dedup_offset = record_command_dedup(
        &mut tx,
        &c.user_id,
        &c.command_id,
        &c.act_as,
        c.offset as i64,
        publication,
        &c.submission_id,
        &trace,
        false,
    )?;
    tx.execute(
        "INSERT INTO lapi_command_completions (completion_offset, record_time, publication_time, user_id, submitters, command_id, submission_id, deduplication_offset, \
         rejection_status_code, rejection_status_message, synchronizer_id, is_transaction, trace_context, traffic_cost) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false, $12, 0)",
        &[
            &(c.offset as i64),
            &publication,
            &publication,
            &user_id,
            &party_list(&submitters),
            &c.command_id,
            &c.submission_id,
            &dedup_offset,
            &c.status_code,
            &c.status_message,
            &sync_id,
            &trace,
        ],
    )
    .map_err(db)?;
    move_ledger_end(
        &mut tx,
        c.offset as i64,
        seq,
        publication,
        publication,
        sync_id,
    )?;
    tx.commit().map_err(db)
}

fn resolve_synchronizer_idx(tx: &mut Transaction<'_>) -> Res<Option<i32>> {
    if let Some(row) = tx
        .query_opt(
            "SELECT synchronizer_idx FROM par_active_contracts ORDER BY ts LIMIT 1",
            &[],
        )
        .map_err(db)?
    {
        return Ok(Some(row.get(0)));
    }
    Ok(tx
        .query_opt(
            "SELECT id FROM common_static_strings WHERE source = 1 ORDER BY id LIMIT 1",
            &[],
        )
        .map_err(db)?
        .map(|r| r.get(0)))
}

fn record_command_dedup(
    tx: &mut Transaction<'_>,
    user_id: &str,
    command_id: &str,
    act_as: &[String],
    offset: i64,
    publication: i64,
    submission_id: &str,
    trace: &[u8],
    accepted: bool,
) -> Res<i64> {
    if user_id.is_empty() || command_id.is_empty() || act_as.is_empty() {
        return Ok(0);
    }
    let cih = canton_participant::takeover::change_id_hash(user_id, command_id, act_as);
    let prev_offset: i64 = tx
        .query_opt(
            "SELECT offset_definite_answer FROM par_command_deduplication WHERE change_id_hash = $1",
            &[&cih],
        )
        .map_err(db)?
        .map_or(0, |r| r.get(0));
    let stored_parties = canton_participant::takeover::encode_stored_parties_v30(act_as);
    let sub_opt = (!submission_id.is_empty()).then_some(submission_id);
    if accepted {
        tx.execute(
            "INSERT INTO par_command_deduplication \
             (change_id_hash, user_id, command_id, act_as, offset_definite_answer, publication_time_definite_answer, \
              submission_id_definite_answer, trace_context_definite_answer, offset_acceptance, publication_time_acceptance, \
              submission_id_acceptance, trace_context_acceptance) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $5, $6, $7, $8) \
             ON CONFLICT (change_id_hash) DO UPDATE SET \
               offset_definite_answer = EXCLUDED.offset_definite_answer, \
               publication_time_definite_answer = EXCLUDED.publication_time_definite_answer, \
               submission_id_definite_answer = EXCLUDED.submission_id_definite_answer, \
               trace_context_definite_answer = EXCLUDED.trace_context_definite_answer, \
               offset_acceptance = EXCLUDED.offset_acceptance, \
               publication_time_acceptance = EXCLUDED.publication_time_acceptance, \
               submission_id_acceptance = EXCLUDED.submission_id_acceptance, \
               trace_context_acceptance = EXCLUDED.trace_context_acceptance",
            &[
                &cih,
                &user_id,
                &command_id,
                &stored_parties,
                &offset,
                &publication,
                &sub_opt,
                &trace,
            ],
        )
        .map_err(db)?;
    } else {
        tx.execute(
            "INSERT INTO par_command_deduplication \
             (change_id_hash, user_id, command_id, act_as, offset_definite_answer, publication_time_definite_answer, \
              submission_id_definite_answer, trace_context_definite_answer, offset_acceptance, publication_time_acceptance, \
              submission_id_acceptance, trace_context_acceptance) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, NULL, NULL) \
             ON CONFLICT (change_id_hash) DO UPDATE SET \
               offset_definite_answer = EXCLUDED.offset_definite_answer, \
               publication_time_definite_answer = EXCLUDED.publication_time_definite_answer, \
               submission_id_definite_answer = EXCLUDED.submission_id_definite_answer, \
               trace_context_definite_answer = EXCLUDED.trace_context_definite_answer",
            &[
                &cih,
                &user_id,
                &command_id,
                &stored_parties,
                &offset,
                &publication,
                &sub_opt,
                &trace,
            ],
        )
        .map_err(db)?;
    }
    Ok(prev_offset)
}

/// The row a participant keeps for a contract's activation or deactivation in its active contract store (`par_active_contracts`, U-50 2).
///
/// [CANTON-NOTE: SEMANTICS] A 3.7.2 participant finds the synchronizer of a contract it is asked to use in this table (without a row the command fails with
/// `UNKNOWN_CONTRACT_SYNCHRONIZERS`). The synchronizer index is the one the participant has registered (the table's existing rows say which; the daemon's own
/// synchronizer is not known to it), the time is the update's record time, and the repair counter advances monotonically per `(synchronizer_idx, ts)`.
fn write_active_contract(
    tx: &mut Transaction<'_>,
    contract_id: &[u8],
    activation: bool,
    ts: i64,
) -> Res<()> {
    let idx = resolve_synchronizer_idx(tx)?
        .ok_or_else(|| "no synchronizer is registered in the database".to_string())?;
    // [CANTON-NOTE: SEMANTICS] The time of change is the time of the last request the participant journaled, not the update's record time: when a participant
    // connects to its synchronizer it throws away the changes of its active contract store that lie after the requests it had processed (crash recovery), so a
    // row at the daemon's clock would be gone before the first command. The hub's own latest rows carry this time.
    let ts: i64 = tx
        .query_one(
            "SELECT COALESCE((SELECT max(request_timestamp) FROM par_journal_requests), (SELECT max(ts) FROM par_active_contracts), $1)",
            &[&ts],
        )
        .map_err(db)?
        .get(0);
    let max_counter: Option<i64> = tx
        .query_one(
            "SELECT MAX(repair_counter) FROM par_active_contracts WHERE synchronizer_idx = $1 AND ts = $2",
            &[&idx, &ts],
        )
        .map_err(db)?
        .get(0);
    let repair_counter = max_counter.map_or(i64::MIN, |c| c.saturating_add(1));
    let (change, operation) = if activation {
        ("activation", "create")
    } else {
        ("deactivation", "archive")
    };
    tx.execute(
        "INSERT INTO par_active_contracts (synchronizer_idx, contract_id, change, operation, ts, repair_counter, remote_synchronizer_idx, reassignment_counter) \
         VALUES ($1, $2, $3::text::change_type, $4::text::operation_type, $5, $6, NULL, 0) ON CONFLICT DO NOTHING",
        &[&idx, &contract_id, &change, &operation, &ts, &repair_counter],
    )
    .map_err(db)?;
    Ok(())
}

/// Writes the update a participant makes when it starts to host `party`: the row of `lapi_events_party_to_participant` (the table the official Ledger API
/// lists parties from), the update's `lapi_update_meta` row at `offset`, and moves the ledger end there (U-50).
///
/// [CANTON-NOTE: SEMANTICS] Shape taken from the rows of the hub's own parties: one sequential event id, `participant_permission` 0 (submission) and
/// `participant_authorization_event` 0 (added), `record_time` the transaction's `valid_from`, no transaction hash. The update id is the multi-hash of the party id
/// and the offset (the node derives it from the topology transaction; an id nobody looks up only has to be unique).
pub(crate) fn write_party_added(
    service: &ExecutionService,
    client: &mut Client,
    party: &str,
    participant: &str,
    offset: i64,
    record_time: i64,
) -> Res<()> {
    let mut tx = client.transaction().map_err(db)?;
    let state = service.v2_state();
    let params = tx
        .query_one(
            "SELECT ledger_end_sequential_id FROM lapi_parameters FOR UPDATE",
            &[],
        )
        .map_err(db)?;
    let seq: i64 = params.get::<_, Option<i64>>(0).unwrap_or(0) + 1;
    let publication = crate::clock::now_micros().max(record_time);
    let sync_id = intern(&mut tx, 'd', &state.synchronizer_id())?;
    let party_id = intern(&mut tx, 'p', party)?;
    // participants have their own interning kind (`n|`), not the party's (`p|`): the party list asks for the interned id of this node's participant
    let participant_id = intern(&mut tx, 'n', participant)?;
    let update_id = {
        let mut h = canton_algo::PurposeHash::new(0);
        h.add_string(party)
            .and_then(|_| h.add_long(offset))
            .map_err(|e| format!("{e:?}"))?;
        let digest = h.finish().map_err(|e| format!("{e:?}"))?;
        let mut out = vec![0x12, 0x20];
        out.extend_from_slice(&digest);
        out
    };
    let trace = trace_context("00-00000000000000000000000000000000-0000000000000000-00");
    tx.execute(
        "INSERT INTO lapi_events_party_to_participant (event_sequential_id, event_offset, update_id, party_id, participant_id, participant_permission, \
         participant_authorization_event, synchronizer_id, record_time, trace_context, party) VALUES ($1, $2, $3, $4, $5, 0, 0, $6, $7, $8, $9)",
        &[
            &seq,
            &offset,
            &update_id,
            &party_id,
            &participant_id,
            &sync_id,
            &record_time,
            &trace,
            &party,
        ],
    )
    .map_err(db)?;
    tx.execute(
        "INSERT INTO lapi_update_meta (update_id, event_offset, publication_time, record_time, synchronizer_id, event_sequential_id_first, \
         event_sequential_id_last, transaction_hash) VALUES ($1, $2, $3, $4, $5, $6, $6, NULL)",
        &[&update_id, &offset, &publication, &record_time, &sync_id, &seq],
    )
    .map_err(db)?;
    // the synchronizer's observed time never goes back: the party's record time can lie before what the index already saw
    let observed: Option<i64> = tx
        .query_opt(
            "SELECT record_time FROM lapi_ledger_end_synchronizer_index WHERE synchronizer_id = $1",
            &[&sync_id],
        )
        .map_err(db)?
        .map(|r| r.get(0));
    move_ledger_end(
        &mut tx,
        offset,
        seq,
        publication,
        record_time.max(observed.unwrap_or(0)),
        sync_id,
    )?;
    tx.commit().map_err(db)
}

/// Moves the ledger end of the database to `offset`: the parameters, the synchronizer's index time and the post-processing end.
fn move_ledger_end(
    tx: &mut Transaction<'_>,
    offset: i64,
    seq: i64,
    publication: i64,
    record_time: i64,
    sync_id: i32,
) -> Res<()> {
    let interning: i32 = tx
        .query_one(
            "SELECT COALESCE(MAX(internal_id), 0) FROM lapi_string_interning",
            &[],
        )
        .map_err(db)?
        .get(0);
    tx.execute(
        "UPDATE lapi_parameters SET ledger_end = GREATEST(COALESCE(ledger_end, 0), $1), ledger_end_sequential_id = $2, \
         ledger_end_string_interning_id = $3, ledger_end_publication_time = $4",
        &[&offset, &seq, &interning, &publication],
    )
    .map_err(db)?;
    // [CANTON-NOTE: SEMANTICS] The synchronizer index of the participant (`lapi_ledger_end_synchronizer_index`) says up to which sequenced event of its
    // synchronizer the Ledger API has indexed. The official participant reads it when it connects and looks that event up in its sequenced event store, so a
    // row that exists is **left as it is** (a time the daemon invented is not in that store and the connection fails with "SequencerIndex … is not found");
    // only a database without a row for the synchronizer gets one.
    let present = tx
        .query_opt(
            "SELECT 1 FROM lapi_ledger_end_synchronizer_index WHERE synchronizer_id = $1",
            &[&sync_id],
        )
        .map_err(db)?;
    if present.is_none() {
        tx.execute(
            "INSERT INTO lapi_ledger_end_synchronizer_index (synchronizer_id, sequencer_timestamp, record_time) VALUES ($1, $2, $2)",
            &[&sync_id, &record_time],
        )
        .map_err(db)?;
    }
    tx.execute(
        "UPDATE lapi_post_processing_end SET post_processing_end = GREATEST(post_processing_end, $1)",
        &[&offset],
    )
    .map_err(db)?;
    Ok(())
}
