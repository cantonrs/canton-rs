//! Executing a prepared transaction (`execute`): checking the signatures and committing the prepared nodes.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;

use canton_algo::prepared_hash::hash_prepared_transaction;
use canton_algo::signing::Usage;
use canton_proto::com::daml::ledger::api::v2::interactive::daml_transaction::node::VersionedNode;
use canton_proto::com::daml::ledger::api::v2::interactive::metadata::input_contract;
use canton_proto::com::daml::ledger::api::v2::interactive::transaction::v1;
use canton_proto::com::daml::ledger::api::v2::interactive::transaction::v1::node::NodeType;
use canton_proto::com::daml::ledger::api::v2::interactive::PreparedTransaction;
use canton_proto::com::digitalasset::canton::crypto::v30 as crypto;
use lf_eval::fat_contract::{decode_fat_contract_blob, decode_strict_base64};
use lf_eval::tx_model::{ContractId, Node as LfNode, TransactionTree as LfTransactionTree};
use lf_eval::typed_json::Types;
use lf_eval::Value;
use prost::Message;
use serde_json::{json, Value as Json};

use crate::service::{ExecutionService, GenericContract, TransactionCommit};
use crate::v2::base64;
use crate::v2_commands::{
    blob_for, finish_with_hash, map_error, rfc3339_from_micros, transaction_format,
    unix_micros_now, Ev, ExInfo,
};
use crate::{HttpResponse, TemplateId};

use super::external_party::{
    parse_hashing_scheme, pb_signature_from_json, verify_transaction_hash_signature,
};
use super::values::lapi_to_lf_and_json;
use super::{
    fail_execute, fail_max_record_time, invalid_arg, logical_synchronizer, party_abbrev,
    synchronizer_matches,
};

fn gc_from_v1_create(
    service: &ExecutionService,
    c: &v1::Create,
    created_at_micros: i64,
    event_blob_bytes: &[u8],
) -> Result<GenericContract, String> {
    let tpl = c
        .template_id
        .as_ref()
        .ok_or_else(|| "Create node missing template_id".to_string())?;
    let arg = c
        .argument
        .as_ref()
        .ok_or_else(|| "Create node missing argument".to_string())?;
    let (payload_value, raw_json) = lapi_to_lf_and_json(arg)?;
    let local_tpl = format!("{}:{}", tpl.module_name, tpl.entity_name);
    let json_payload = if let Some(pkg) = service.v2_lf_package(&tpl.package_id) {
        let types = Types::new(&pkg.world);
        if let Ok(tpl_ty) = types.template(&tpl.package_id, &local_tpl) {
            types
                .encode_contract(&tpl_ty, &payload_value)
                .unwrap_or(raw_json)
        } else {
            raw_json
        }
    } else {
        raw_json
    };
    let sig_set: HashSet<&str> = c.signatories.iter().map(String::as_str).collect();
    let observers: Vec<String> = c
        .stakeholders
        .iter()
        .filter(|p| !sig_set.contains(p.as_str()))
        .cloned()
        .collect();
    let (key_value, contract_key_hash, key_maintainers) = match &c.key {
        Some(kwm) => {
            let kv = kwm
                .key
                .as_ref()
                .and_then(|gk| gk.key.as_ref())
                .and_then(|v| lapi_to_lf_and_json(v).ok())
                .map(|(lv, _)| lv);
            let kh = kwm
                .key
                .as_ref()
                .filter(|gk| !gk.hash.is_empty())
                .map(|gk| base64(&gk.hash))
                .unwrap_or_default();
            (kv, kh, kwm.maintainers.clone())
        }
        None => (None, String::new(), Vec::new()),
    };
    Ok(GenericContract {
        contract_id: c.contract_id.clone(),
        package_id: tpl.package_id.clone(),
        template_id: TemplateId {
            package_id: tpl.package_id.clone(),
            module_name: tpl.module_name.clone(),
            entity_name: tpl.entity_name.clone(),
        },
        payload_value,
        json_payload,
        signatories: c.signatories.clone(),
        observers,
        witness_parties: c.signatories.clone(),
        active: true,
        key_value,
        created_at_micros,
        created_event_blob: if event_blob_bytes.is_empty() {
            String::new()
        } else {
            base64(event_blob_bytes)
        },
        contract_key_hash,
        key_maintainers,
        creation_seq: service.next_creation_seq(),
    })
}

pub(super) struct StatelessPlan {
    pub(super) commits: Vec<TransactionCommit>,
    disclosed: Vec<GenericContract>,
    required_active_inputs: Vec<String>,
    events: Vec<Ev>,
}

pub(super) fn commit_from_prepared(
    service: &ExecutionService,
    prepared: &PreparedTransaction,
) -> Result<StatelessPlan, String> {
    let tx = prepared
        .transaction
        .as_ref()
        .ok_or_else(|| "PreparedTransaction missing transaction".to_string())?;
    let meta = prepared
        .metadata
        .as_ref()
        .ok_or_else(|| "PreparedTransaction missing metadata".to_string())?;
    let act_as_set: HashSet<String> = meta
        .submitter_info
        .as_ref()
        .map(|s| s.act_as.iter().cloned().collect())
        .unwrap_or_default();
    let now_micros = unix_micros_now();

    let mut nodes_by_id: HashMap<&str, &v1::Node> = HashMap::with_capacity(tx.nodes.len());
    for n in &tx.nodes {
        let Some(VersionedNode::V1(inner)) = &n.versioned_node else {
            return Err("node missing v1 versioned_node".into());
        };
        nodes_by_id.insert(n.node_id.as_str(), inner);
    }

    let mut input_by_cid: HashMap<String, GenericContract> = HashMap::new();
    let mut disclosed: Vec<GenericContract> = Vec::new();
    let mut required_active_inputs: Vec<String> = Vec::new();
    let mut seen_req: HashSet<String> = HashSet::new();

    for ic in &meta.input_contracts {
        let Some(input_contract::Contract::V1(c)) = &ic.contract else {
            continue;
        };
        if !ic.event_blob.is_empty() {
            // Verify raw blob decodes canonically when provided as disclosed input
            decode_fat_contract_blob(&ic.event_blob)
                .map_err(|e| format!("invalid input contract blob for {}: {e}", c.contract_id))?;
        }
        let gc = gc_from_v1_create(
            service,
            c,
            i64::try_from(ic.created_at).unwrap_or(0),
            &ic.event_blob,
        )?;
        if seen_req.insert(gc.contract_id.clone()) {
            required_active_inputs.push(gc.contract_id.clone());
        }
        if !ic.event_blob.is_empty() && service.v2_contract(&gc.contract_id).is_none() {
            disclosed.push(gc.clone());
        }
        input_by_cid.insert(gc.contract_id.clone(), gc);
    }

    let mut lf_tree = LfTransactionTree::new();
    let mut created_contracts: Vec<GenericContract> = Vec::new();
    let mut created_by_cid: HashMap<String, GenericContract> = HashMap::new();
    let mut consumed_cids: Vec<String> = Vec::new();
    let mut archived_cids: Vec<String> = Vec::new();
    let mut events: Vec<Ev> = Vec::new();
    let mut ev_node_seq: u64 = 0;

    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    fn walk_node(
        service: &ExecutionService,
        node_id: &str,
        nodes_by_id: &HashMap<&str, &v1::Node>,
        now_micros: i64,
        in_rollback: bool,
        input_by_cid: &HashMap<String, GenericContract>,
        created_by_cid: &mut HashMap<String, GenericContract>,
        created_contracts: &mut Vec<GenericContract>,
        consumed_cids: &mut Vec<String>,
        archived_cids: &mut Vec<String>,
        required_active_inputs: &mut Vec<String>,
        seen_req: &mut HashSet<String>,
        events: &mut Vec<Ev>,
        ev_node_seq: &mut u64,
        lf_tree: &mut LfTransactionTree,
        is_root: bool,
    ) -> Result<lf_eval::tx_model::NodeId, String> {
        let node = nodes_by_id
            .get(node_id)
            .ok_or_else(|| format!("missing node '{node_id}'"))?;
        let node_type = node
            .node_type
            .as_ref()
            .ok_or_else(|| format!("node '{node_id}' missing node_type"))?;
        match node_type {
            NodeType::Create(c) => {
                let mut gc = gc_from_v1_create(service, c, now_micros, &[])?;
                gc.created_event_blob = blob_for(service, &gc);
                let lf_key = gc.key_value.as_ref().map(|k| format!("{k:?}"));
                let lf_node = LfNode::Create {
                    contract_id: ContractId(gc.contract_id.clone()),
                    template_id: gc.template_id.to_string(),
                    payload: Vec::new(),
                    signatories: gc.signatories.iter().cloned().collect(),
                    observers: gc.observers.iter().cloned().collect(),
                    key: lf_key,
                };
                let lf_id = lf_tree.insert_node(lf_node, is_root);
                if !in_rollback {
                    let ev_idx = *ev_node_seq;
                    *ev_node_seq += 1;
                    events.push(Ev {
                        contract: gc.clone(),
                        created: true,
                        node: ev_idx,
                        exercise: None,
                    });
                    created_by_cid.insert(gc.contract_id.clone(), gc.clone());
                    created_contracts.push(gc);
                }
                Ok(lf_id)
            }
            NodeType::Fetch(f) => {
                if !in_rollback {
                    *ev_node_seq += 1;
                }
                if !created_by_cid.contains_key(&f.contract_id)
                    && seen_req.insert(f.contract_id.clone())
                {
                    required_active_inputs.push(f.contract_id.clone());
                }
                let tpl_str = f
                    .template_id
                    .as_ref()
                    .map(|t| format!("{}:{}:{}", t.package_id, t.module_name, t.entity_name))
                    .unwrap_or_default();
                let lf_id = lf_tree.insert_node(
                    LfNode::Fetch {
                        contract_id: ContractId(f.contract_id.clone()),
                        template_id: tpl_str,
                        stakeholders: f.stakeholders.iter().cloned().collect(),
                    },
                    is_root,
                );
                Ok(lf_id)
            }
            NodeType::Rollback(rb) => {
                let mut child_ids = Vec::with_capacity(rb.children.len());
                for ch in &rb.children {
                    let cid = walk_node(
                        service,
                        ch,
                        nodes_by_id,
                        now_micros,
                        true,
                        input_by_cid,
                        created_by_cid,
                        created_contracts,
                        consumed_cids,
                        archived_cids,
                        required_active_inputs,
                        seen_req,
                        events,
                        ev_node_seq,
                        lf_tree,
                        false,
                    )?;
                    child_ids.push(cid);
                }
                Ok(lf_tree.insert_node(
                    LfNode::Rollback {
                        children: child_ids,
                    },
                    is_root,
                ))
            }
            NodeType::Exercise(ex) => {
                if !created_by_cid.contains_key(&ex.contract_id)
                    && seen_req.insert(ex.contract_id.clone())
                {
                    required_active_inputs.push(ex.contract_id.clone());
                }
                let target_gc = created_by_cid
                    .get(&ex.contract_id)
                    .cloned()
                    .or_else(|| input_by_cid.get(&ex.contract_id).cloned())
                    .or_else(|| service.v2_contract(&ex.contract_id))
                    .ok_or_else(|| {
                        format!(
                            "missing contract '{}' for Exercise node '{node_id}'",
                            ex.contract_id
                        )
                    })?;

                let ex_ev_idx = if !in_rollback {
                    let idx = *ev_node_seq;
                    *ev_node_seq += 1;
                    let (arg_val, raw_arg_json) = match &ex.chosen_value {
                        Some(v) => lapi_to_lf_and_json(v)?,
                        None => (Value::Unit, json!({})),
                    };
                    let (res_val, raw_res_json) = match &ex.exercise_result {
                        Some(v) => {
                            let (lv, jv) = lapi_to_lf_and_json(v)?;
                            (Some(lv), Some(jv))
                        }
                        None => (None, None),
                    };
                    let iface_id_str = ex
                        .interface_id
                        .as_ref()
                        .map(|i| format!("{}:{}:{}", i.package_id, i.module_name, i.entity_name));
                    let (arg_json, res_json) = crate::v2_commands::encode_choice_values(
                        service,
                        &target_gc.template_id,
                        iface_id_str.as_deref(),
                        &ex.choice_id,
                        Some(&arg_val),
                        Some(raw_arg_json),
                        res_val.as_ref(),
                        raw_res_json.or_else(|| Some(json!(null))),
                    );
                    let ev_slot = events.len();
                    events.push(Ev {
                        contract: target_gc,
                        created: false,
                        node: idx,
                        exercise: Some(ExInfo {
                            choice: ex.choice_id.clone(),
                            argument: arg_json,
                            argument_value: Some(arg_val),
                            acting: ex.acting_parties.clone(),
                            consuming: ex.consuming,
                            result: res_json,
                            result_value: res_val,
                            last_descendant: idx,
                            interface_id: iface_id_str,
                            choice_observers: ex.choice_observers.clone(),
                        }),
                    });
                    Some(ev_slot)
                } else {
                    None
                };

                if !in_rollback && ex.consuming {
                    if let Some(gc) = created_by_cid.get_mut(&ex.contract_id) {
                        gc.active = false;
                    }
                    consumed_cids.push(ex.contract_id.clone());
                    archived_cids.push(ex.contract_id.clone());
                }

                let mut child_lf_ids = Vec::with_capacity(ex.children.len());
                for ch in &ex.children {
                    let cid = walk_node(
                        service,
                        ch,
                        nodes_by_id,
                        now_micros,
                        in_rollback,
                        input_by_cid,
                        created_by_cid,
                        created_contracts,
                        consumed_cids,
                        archived_cids,
                        required_active_inputs,
                        seen_req,
                        events,
                        ev_node_seq,
                        lf_tree,
                        false,
                    )?;
                    child_lf_ids.push(cid);
                }

                if let Some(slot) = ex_ev_idx {
                    let last = (*ev_node_seq).saturating_sub(1);
                    if let Some(ex_info) = events[slot].exercise.as_mut() {
                        ex_info.last_descendant = last.max(ex_info.last_descendant);
                    }
                }

                let lf_id = lf_tree.insert_node(
                    LfNode::Exercise {
                        contract_id: ContractId(ex.contract_id.clone()),
                        choice: ex.choice_id.clone(),
                        acting_parties: ex.acting_parties.iter().cloned().collect(),
                        consuming: ex.consuming,
                        children: child_lf_ids,
                    },
                    is_root,
                );
                Ok(lf_id)
            }
            NodeType::QueryByKey(q) => {
                let tpl_str = q
                    .template_id
                    .as_ref()
                    .map(|t| format!("{}:{}:{}", t.package_id, t.module_name, t.entity_name))
                    .unwrap_or_default();
                let key_str = q
                    .key
                    .as_ref()
                    .and_then(|kwm| kwm.key.as_ref())
                    .and_then(|gk| gk.key.as_ref())
                    .and_then(|v| lapi_to_lf_and_json(v).ok())
                    .map(|(lv, _)| format!("{lv:?}"))
                    .unwrap_or_default();
                Ok(lf_tree.insert_node(
                    LfNode::LookupByKey {
                        template_id: tpl_str,
                        key: key_str,
                        found: q.result.first().cloned().map(ContractId),
                    },
                    is_root,
                ))
            }
        }
    }

    for root in &tx.roots {
        walk_node(
            service,
            root,
            &nodes_by_id,
            now_micros,
            false,
            &input_by_cid,
            &mut created_by_cid,
            &mut created_contracts,
            &mut consumed_cids,
            &mut archived_cids,
            &mut required_active_inputs,
            &mut seen_req,
            &mut events,
            &mut ev_node_seq,
            &mut lf_tree,
            true,
        )?;
    }

    let commit = TransactionCommit {
        consumed_cids,
        archived_cids,
        created_contracts,
        legacy_archived_cids: Vec::new(),
        working_ledger: None,
        lf_tree,
        act_as_set,
        tx_tree_record: None,
        root_argument: None,
        engine_events: Vec::new(),
        engine_rolled_back: Vec::new(),
        engine_key_lookups: Vec::new(),
        root_by_key: false,
        root_package_id: None,
        disclosed_contracts: Vec::new(),
        history: None,
    };

    Ok(StatelessPlan {
        commits: vec![commit],
        disclosed,
        required_active_inputs,
        events,
    })
}

/// The `actAs` parties of the prepared transaction an execute call carries (what the call is authorized against); `None` when the body
/// has no prepared transaction that decodes.
pub(crate) fn prepared_act_as(body: &Json) -> Option<Vec<String>> {
    let bytes = decode_strict_base64(body.get("preparedTransaction")?.as_str()?).ok()?;
    let prepared = PreparedTransaction::decode(bytes.as_slice()).ok()?;
    Some(prepared.metadata?.submitter_info?.act_as)
}

/// `POST /v2/interactive-submission/{execute,executeAndWait,executeAndWaitForTransaction}`.
pub fn execute(service: &ExecutionService, body: &Json, endpoint: &str) -> HttpResponse {
    let Some(prepared_b64) = body["preparedTransaction"]
        .as_str()
        .filter(|s| !s.is_empty())
    else {
        return fail_execute("Missing preparedTransaction");
    };
    let prepared_bytes = match decode_strict_base64(prepared_b64) {
        Ok(b) => b,
        Err(e) => return fail_execute(format!("Invalid preparedTransaction base64: {e}")),
    };
    let prepared = match PreparedTransaction::decode(prepared_bytes.as_slice()) {
        Ok(p) => p,
        Err(e) => return fail_execute(format!("Invalid preparedTransaction protobuf: {e}")),
    };
    let scheme = match parse_hashing_scheme(body.get("hashingSchemeVersion"), false) {
        Ok(s) => s,
        Err(e) => return invalid_arg(e),
    };

    let Some(tx) = prepared.transaction.as_ref() else {
        return fail_execute("PreparedTransaction is missing transaction");
    };
    if tx.roots.len() > 1 {
        return fail_execute("Transaction with multiple root nodes are not supported");
    }
    let Some(meta) = prepared.metadata.as_ref() else {
        return fail_execute("PreparedTransaction is missing metadata");
    };
    let Some(sub_info) = meta.submitter_info.as_ref() else {
        return fail_execute("PreparedTransaction metadata is missing submitterInfo");
    };
    let max_record_time_micros = meta.max_record_time.and_then(|t| i64::try_from(t).ok());
    let act_as = sub_info.act_as.clone();
    let command_id = sub_info.command_id.clone();

    let state = service.v2_state();
    if !meta.synchronizer_id.is_empty()
        && !synchronizer_matches(&state.synchronizer_id(), &meta.synchronizer_id)
    {
        return fail_execute(format!("Unknown synchronizer '{}'", meta.synchronizer_id));
    }

    let hash_bytes = match hash_prepared_transaction(&prepared, scheme) {
        Ok(h) => h,
        Err(e) => return fail_execute(e),
    };
    let hash_hex = hex::encode(hash_bytes);
    let hash_b64 = base64(&hash_bytes);

    // Collect external party signatures from body.partySignatures.signatures
    let mut provided_by_party: HashMap<String, Vec<crypto::Signature>> = HashMap::new();
    if let Some(arr) = body
        .pointer("/partySignatures/signatures")
        .and_then(Json::as_array)
    {
        for entry in arr {
            let party = entry.get("party").and_then(Json::as_str).unwrap_or("");
            if party.is_empty() {
                continue;
            }
            let sig_objs = entry
                .get("signatures")
                .and_then(Json::as_array)
                .cloned()
                .unwrap_or_default();
            let slot = provided_by_party.entry(party.to_string()).or_default();
            for s in &sig_objs {
                if let Ok(pb_sig) = pb_signature_from_json(s) {
                    slot.push(pb_sig);
                }
            }
        }
    }

    // Verify signatures for every external party in actAs
    let ext_map = state
        .external_parties
        .lock()
        .expect("external_parties lock")
        .clone();
    // [CANTON-NOTE: SEMANTICS] `InteractiveSubmission.verifySignatures` (Canton 3.7.2): every `actAs` party must have provided a
    // signature, whether or not it is an external party, and each party's signatures are then checked against the signing keys the
    // party registered. A party hosted here without such keys has none to check against and is refused, it is not skipped.
    // The keys are the topology's when a protocol node has them, else the ones recorded at allocation (`crate::external_keys`).
    let unsigned: Vec<&str> = act_as
        .iter()
        .filter(|party| provided_by_party.get(*party).is_none_or(Vec::is_empty))
        .map(String::as_str)
        .collect();
    if !unsigned.is_empty() {
        return fail_execute(format!(
            "The following actAs parties did not provide an external signature: {}",
            unsigned.join(", ")
        ));
    }
    for party in &act_as {
        let Some((keys, threshold)) =
            crate::external_keys::signing_keys(service, party, ext_map.get(party))
        else {
            return fail_execute(format!(
                "Could not find party signing keys for {}.",
                party_abbrev(party)
            ));
        };
        let sigs = provided_by_party.get(party).map_or(&[][..], Vec::as_slice);
        if let Err(refused) = canton_algo::party_signatures::verify_party_signatures(
            &keys,
            threshold as usize,
            sigs,
            // [CANTON-NOTE: SEMANTICS] a transaction hash is signed as its raw 32 bytes; a signature over the 34-byte multihash (the
            // onboarding form) does not verify, as on the official participant (U-56 review R1-F3)
            |pk, sig| verify_transaction_hash_signature(&hash_bytes, pk, sig, Usage::Protocol),
        ) {
            return fail_execute(refused.message(
                &party_abbrev(party),
                &format!(
                    " Transaction hash to be signed: 1220{hash_hex}. \
                     Ensure the correct transaction hash is signed with the correct key(s)."
                ),
            ));
        }
    }

    // Check maxRecordTime from metadata
    if let Some(max_rt) = meta.max_record_time {
        let now_micros = unix_micros_now();
        if now_micros > max_rt as i64 {
            return fail_max_record_time(
                &rfc3339_from_micros(now_micros),
                &rfc3339_from_micros(max_rt as i64),
            );
        }
    }

    let user_id = body
        .get("userId")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string();
    if let Err(resp) = crate::dedup::validate_period(body.get("deduplicationPeriod")) {
        return resp;
    }
    let reservation = match crate::dedup::reserve(
        service,
        &user_id,
        &command_id,
        &act_as,
        body.get("deduplicationPeriod"),
    ) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let submission_id = body
        .get("submissionId")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| {
            format!(
                "00000000-0000-4000-8000-{:012x}",
                state.submission_seq.fetch_add(1, Ordering::SeqCst)
            )
        });

    let cache_key = (
        logical_synchronizer(&meta.synchronizer_id).to_string(),
        hash_bytes,
    );
    let cached = state
        .prepared_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&cache_key);

    let (commits, disclosed, read_as, required_active_inputs, events) = match cached {
        Some(c) => {
            if let Some(max_rt) = c.max_record_time_micros {
                let now_micros = unix_micros_now();
                if now_micros > max_rt {
                    return fail_max_record_time(
                        &rfc3339_from_micros(now_micros),
                        &rfc3339_from_micros(max_rt),
                    );
                }
            }
            (
                c.commits,
                c.disclosed,
                c.read_as,
                c.required_active_inputs,
                c.events,
            )
        }
        None => match commit_from_prepared(service, &prepared) {
            Ok(plan) => (
                plan.commits,
                plan.disclosed,
                Vec::new(),
                plan.required_active_inputs,
                plan.events,
            ),
            Err(e) => return fail_execute(e),
        },
    };

    // [CANTON-NOTE: SEMANTICS] the request carries the parties' signatures, the hashing scheme and the maximum record time they signed
    // (`SubmitterMetadata.external_authorization`): its confirmers recompute the hash and check them (U-56)
    let _external_guard = crate::service::enter_external_authorization(
        canton_proto::com::digitalasset::canton::protocol::v32::ExternalAuthorization {
            authentications: act_as
                .iter()
                .map(|party| canton_proto::com::digitalasset::canton::protocol::v30::ExternalPartyAuthorization {
                    party: party.clone(),
                    signatures: provided_by_party.get(party).cloned().unwrap_or_default(),
                })
                .collect(),
            hashing_scheme_version: scheme as i32,
            max_record_time: max_record_time_micros,
        },
    );
    let command_guard = crate::service::enter_command(crate::service::CommandIdentity {
        command_id: command_id.clone(),
        user_id: user_id.clone(),
        submission_id: submission_id.clone(),
        act_as: act_as.clone(),
    });
    let committed =
        service.commit_prepared_transaction(commits, &required_active_inputs, disclosed, read_as);
    drop(command_guard);
    if let Err(err) = committed {
        // the wait ended first: the command is still in flight and its completion comes when its fate is known
        if err.is_request_time_out() {
            reservation.keep_in_flight();
            if endpoint == "execute" {
                return HttpResponse::json(200, &json!({}));
            }
            return map_error(err, None, service);
        }
        if let crate::ApiError::SynchronizerRejected {
            grpc_code, details, ..
        } = &err
        {
            if crate::v2_commands::record_rejected_completion(
                state,
                &command_id,
                &user_id,
                &submission_id,
                &act_as,
                Some(hash_b64),
                *grpc_code,
                err.to_string(),
                details.clone(),
            ) {
                service.command_recorded_for(&command_id);
            }
            if endpoint == "execute" {
                return HttpResponse::json(200, &json!({}));
            }
        }
        return map_error(
            err,
            required_active_inputs.first().map(String::as_str),
            service,
        );
    }

    let with_transaction = endpoint == "executeAndWaitForTransaction";
    let _blob_guard = crate::v2_commands::enter_want_blob_for(body);
    let resp = finish_with_hash(
        service,
        &command_id,
        &act_as,
        events,
        with_transaction,
        state,
        (user_id, submission_id.clone()),
        transaction_format(service, body),
        Some((hash_b64, hash_hex)),
    );
    if resp.status == 200 {
        let offset = state.ledger_end.load(Ordering::SeqCst);
        crate::dedup::record(service, reservation.key(), offset, submission_id);
    }
    if endpoint == "execute" && resp.status == 200 {
        HttpResponse::json(200, &json!({}))
    } else {
        resp
    }
}
