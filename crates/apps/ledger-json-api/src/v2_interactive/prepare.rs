//! Preparing a transaction for external signing (`prepare`): the prepared transaction tree and its nodes.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;

use canton_algo::prepared_hash::{hash_prepared_transaction, PreparedHashError};
use canton_proto::com::daml::ledger::api::v2::interactive::daml_transaction::node::VersionedNode;
use canton_proto::com::daml::ledger::api::v2::interactive::daml_transaction::{
    Node as DamTxNode, NodeSeed,
};
use canton_proto::com::daml::ledger::api::v2::interactive::metadata::{
    input_contract, InputContract, SubmitterInfo,
};
use canton_proto::com::daml::ledger::api::v2::interactive::transaction::v1;
use canton_proto::com::daml::ledger::api::v2::interactive::transaction::v1::node::NodeType;
use canton_proto::com::daml::ledger::api::v2::interactive::{
    DamlTransaction, GlobalKey, GlobalKeyWithMaintainers, HashingSchemeVersion, Metadata,
    PreparedTransaction,
};
use lf_eval::engine::RolledBack;
use lf_eval::fat_contract::{compute_key_hash, decode_strict_base64};
use lf_eval::typed_json::Types;
use lf_eval::{EngineEvent, Value};
use prost::Message;
use serde_json::{json, Value as Json};

use crate::service::{ExecutionService, GenericContract, TransactionCommit};
use crate::v2::base64;
use crate::v2_commands::{
    blob_for, canton_error, dry_run_prepare_commands, now_rfc3339, unix_micros_now, value_json,
    Kind,
};
use crate::v2_updates::parse_micros;
use crate::{HttpResponse, TemplateId};

use super::external_party::parse_hashing_scheme;
use super::values::{
    derive_node_seed, lapi_identifier, lf_to_lapi_value, parse_colon_identifier,
    sorted_stakeholders,
};
use super::{
    fail_prepare, hashing_scheme_name, invalid_arg, logical_synchronizer, synchronizer_matches,
    CachedPrepared,
};

fn global_key_with_maintainers(
    service: &ExecutionService,
    gc: &GenericContract,
) -> Option<GlobalKeyWithMaintainers> {
    let key_val = gc.key_value.as_ref()?;
    let pkg_name = service.v2_package_name(&gc.package_id).unwrap_or_default();
    let pkg = service.v2_lf_package(&gc.package_id);
    let local_tpl = format!(
        "{}:{}",
        gc.template_id.module_name, gc.template_id.entity_name
    );
    let key_proto = if let Some(ref p) = pkg {
        let types = Types::new(&p.world);
        if let Ok(Some(key_ty)) = types.template_key_type(&gc.package_id, &local_tpl) {
            lf_to_lapi_value(Some((&types, &key_ty)), key_val)
        } else {
            lf_to_lapi_value(None, key_val)
        }
    } else {
        lf_to_lapi_value(None, key_val)
    };
    let hash_bytes = if !gc.contract_key_hash.is_empty() {
        decode_strict_base64(&gc.contract_key_hash).ok()
    } else {
        None
    }
    .filter(|b| b.len() == 32)
    .or_else(|| {
        let p = pkg.as_ref()?;
        let types = Types::new(&p.world);
        let key_ty = types.template_key_type(&gc.package_id, &local_tpl).ok()??;
        compute_key_hash(&types, &pkg_name, &local_tpl, &key_ty, key_val)
            .ok()
            .map(|arr| arr.to_vec())
    })?;
    let mut maintainers = gc.key_maintainers.clone();
    if maintainers.is_empty() {
        maintainers = gc.signatories.clone();
    }
    maintainers.sort();
    maintainers.dedup();
    Some(GlobalKeyWithMaintainers {
        key: Some(GlobalKey {
            template_id: Some(lapi_identifier(&gc.template_id)),
            key: Some(key_proto),
            package_name: pkg_name,
            hash: hash_bytes,
        }),
        maintainers,
    })
}

fn create_node_from_gc(service: &ExecutionService, gc: &GenericContract) -> v1::Create {
    let pkg_name = service.v2_package_name(&gc.package_id).unwrap_or_default();
    let local_tpl = format!(
        "{}:{}",
        gc.template_id.module_name, gc.template_id.entity_name
    );
    let arg = if let Some(pkg) = service.v2_lf_package(&gc.package_id) {
        let types = Types::new(&pkg.world);
        if let Ok(tpl_ty) = types.template(&gc.package_id, &local_tpl) {
            lf_to_lapi_value(Some((&types, &tpl_ty)), &gc.payload_value)
        } else {
            lf_to_lapi_value(None, &gc.payload_value)
        }
    } else {
        lf_to_lapi_value(None, &gc.payload_value)
    };
    let mut sigs = gc.signatories.clone();
    sigs.sort();
    sigs.dedup();
    let stakeholders = sorted_stakeholders(&gc.signatories, &gc.observers);
    let key = global_key_with_maintainers(service, gc);
    let lf_version = if key.is_some() { "2" } else { "2.1" }.to_string();
    v1::Create {
        lf_version,
        contract_id: gc.contract_id.clone(),
        package_name: pkg_name,
        template_id: Some(lapi_identifier(&gc.template_id)),
        argument: Some(arg),
        signatories: sigs,
        stakeholders,
        key,
    }
}

struct BuildPreparedCtx<'a> {
    service: &'a ExecutionService,
    tx_uuid: &'a str,
    nodes: Vec<DamTxNode>,
    node_seeds: Vec<NodeSeed>,
    roots: Vec<String>,
    next_id: i32,
    any_keyed: bool,
    created_in_tx: HashSet<String>,
    input_contracts: Vec<(String, GenericContract)>,
    seen_inputs: HashSet<String>,
}

impl<'a> BuildPreparedCtx<'a> {
    fn new(service: &'a ExecutionService, tx_uuid: &'a str) -> Self {
        Self {
            service,
            tx_uuid,
            nodes: Vec::new(),
            node_seeds: Vec::new(),
            roots: Vec::new(),
            next_id: 0,
            any_keyed: false,
            created_in_tx: HashSet::new(),
            input_contracts: Vec::new(),
            seen_inputs: HashSet::new(),
        }
    }

    fn alloc_id(&mut self) -> (i32, String) {
        let id = self.next_id;
        self.next_id += 1;
        (id, id.to_string())
    }

    fn push_node(&mut self, node_id: String, inner: v1::Node) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(DamTxNode {
            node_id,
            versioned_node: Some(VersionedNode::V1(inner)),
        });
        idx
    }

    fn attach_child(&mut self, parent_idx: Option<usize>, child_id: String) {
        match parent_idx {
            None => self.roots.push(child_id),
            Some(idx) => {
                if let Some(VersionedNode::V1(node)) = self.nodes[idx].versioned_node.as_mut() {
                    match node.node_type.as_mut() {
                        Some(NodeType::Exercise(ex)) => ex.children.push(child_id),
                        Some(NodeType::Rollback(rb)) => rb.children.push(child_id),
                        _ => {}
                    }
                }
            }
        }
    }

    fn note_input(&mut self, gc: &GenericContract) {
        if !self.created_in_tx.contains(&gc.contract_id)
            && self.seen_inputs.insert(gc.contract_id.clone())
        {
            self.input_contracts
                .push((gc.contract_id.clone(), gc.clone()));
        }
    }

    fn find_contract(
        &self,
        cid: &str,
        created_by_cid: &HashMap<&str, &GenericContract>,
        disclosed_by_cid: &HashMap<&str, &GenericContract>,
        history_contracts: Option<&HashMap<String, lf_eval::Contract>>,
    ) -> Option<GenericContract> {
        if let Some(c) = created_by_cid.get(cid) {
            return Some((*c).clone());
        }
        if let Some(c) = disclosed_by_cid.get(cid) {
            return Some((*c).clone());
        }
        if let Some(c) = self.service.v2_contract(cid) {
            return Some(c);
        }
        if let Some(hc) = history_contracts.and_then(|m| m.get(cid)) {
            let mut parts = hc.template_id.split(':');
            let (mod_n, ent_n) = match (parts.next(), parts.next()) {
                (Some(m), Some(e)) => (m.to_string(), e.to_string()),
                _ => (String::new(), hc.template_id.clone()),
            };
            return Some(GenericContract {
                contract_id: hc.contract_id.clone(),
                package_id: hc.package_id.clone(),
                template_id: TemplateId {
                    package_id: hc.package_id.clone(),
                    module_name: mod_n,
                    entity_name: ent_n,
                },
                payload_value: hc.payload.clone(),
                json_payload: value_json(&hc.payload),
                signatories: hc.signatories.clone(),
                observers: hc.observers.clone(),
                witness_parties: hc.signatories.clone(),
                active: hc.active,
                key_value: None,
                created_at_micros: 0,
                created_event_blob: String::new(),
                contract_key_hash: String::new(),
                key_maintainers: Vec::new(),
                creation_seq: 0,
            });
        }
        None
    }

    fn append_engine_slice(
        &mut self,
        events: &[EngineEvent],
        start_idx: usize,
        rolled_back: &[RolledBack],
        base_parent_idx: Option<usize>,
        base_depth: usize,
        created_by_cid: &HashMap<&str, &GenericContract>,
        disclosed_by_cid: &HashMap<&str, &GenericContract>,
        history_contracts: Option<&HashMap<String, lf_eval::Contract>>,
    ) {
        let mut stack: Vec<(usize, usize)> = Vec::new();
        if let Some(pidx) = base_parent_idx {
            stack.push((base_depth, pidx));
        }

        for (rel_i, ev) in events.iter().enumerate() {
            let abs_i = start_idx + rel_i;
            for rb in rolled_back.iter().filter(|g| g.at == abs_i) {
                let rb_parent_depth = rb
                    .events
                    .first()
                    .map(|e| match e {
                        EngineEvent::Create { depth, .. }
                        | EngineEvent::Exercise { depth, .. }
                        | EngineEvent::Fetch { depth, .. } => depth.saturating_sub(1),
                    })
                    .unwrap_or(base_depth);
                while stack.last().is_some_and(|(d, _)| *d > rb_parent_depth) {
                    stack.pop();
                }
                let rb_parent_idx = stack.last().map(|(_, idx)| *idx);
                let (_rb_id_num, rb_id) = self.alloc_id();
                let rb_idx = self.push_node(
                    rb_id.clone(),
                    v1::Node {
                        node_type: Some(NodeType::Rollback(v1::Rollback {
                            children: Vec::new(),
                        })),
                    },
                );
                self.attach_child(rb_parent_idx, rb_id);
                let inner_depth = rb_parent_depth + 1;
                self.append_engine_slice(
                    &rb.events,
                    usize::MAX, // nested rollbacks already flattened into rb.events
                    &[],
                    Some(rb_idx),
                    inner_depth,
                    created_by_cid,
                    disclosed_by_cid,
                    history_contracts,
                );
            }

            let ev_depth = match ev {
                EngineEvent::Create { depth, .. }
                | EngineEvent::Exercise { depth, .. }
                | EngineEvent::Fetch { depth, .. } => *depth,
            };
            while stack.last().is_some_and(|(d, _)| *d >= ev_depth) {
                stack.pop();
            }
            let parent_idx = stack.last().map(|(_, idx)| *idx);

            match ev {
                EngineEvent::Create {
                    contract_id,
                    template_id,
                    ..
                } => {
                    let (nid, nid_str) = self.alloc_id();
                    self.node_seeds.push(NodeSeed {
                        node_id: nid,
                        seed: derive_node_seed(self.tx_uuid, nid),
                    });
                    self.created_in_tx.insert(contract_id.clone());
                    let create = if let Some(gc) = self.find_contract(
                        contract_id,
                        created_by_cid,
                        disclosed_by_cid,
                        history_contracts,
                    ) {
                        let c = create_node_from_gc(self.service, &gc);
                        if c.key.is_some() {
                            self.any_keyed = true;
                        }
                        c
                    } else {
                        v1::Create {
                            lf_version: "2.1".into(),
                            contract_id: contract_id.clone(),
                            package_name: String::new(),
                            template_id: Some(parse_colon_identifier(template_id, "")),
                            argument: Some(lf_to_lapi_value(
                                None,
                                &Value::Record {
                                    tycon: Some(template_id.clone()),
                                    fields: Vec::new(),
                                },
                            )),
                            signatories: Vec::new(),
                            stakeholders: Vec::new(),
                            key: None,
                        }
                    };
                    self.push_node(
                        nid_str.clone(),
                        v1::Node {
                            node_type: Some(NodeType::Create(create)),
                        },
                    );
                    self.attach_child(parent_idx, nid_str);
                }
                EngineEvent::Fetch {
                    contract_id,
                    authorizers,
                    interface_id,
                    ..
                } => {
                    let (_, nid_str) = self.alloc_id();
                    let Some(gc) = self.find_contract(
                        contract_id,
                        created_by_cid,
                        disclosed_by_cid,
                        history_contracts,
                    ) else {
                        continue;
                    };
                    self.note_input(&gc);
                    let pkg_name = self
                        .service
                        .v2_package_name(&gc.package_id)
                        .unwrap_or_default();
                    let key = global_key_with_maintainers(self.service, &gc);
                    if key.is_some() {
                        self.any_keyed = true;
                    }
                    let lf_version = if key.is_some() { "2" } else { "2.1" }.to_string();
                    let mut sigs = gc.signatories.clone();
                    sigs.sort();
                    sigs.dedup();
                    let stakeholders = sorted_stakeholders(&gc.signatories, &gc.observers);
                    let mut acting = authorizers.clone();
                    acting.sort();
                    acting.dedup();
                    let fetch = v1::Fetch {
                        lf_version,
                        contract_id: gc.contract_id.clone(),
                        package_name: pkg_name,
                        template_id: Some(lapi_identifier(&gc.template_id)),
                        signatories: sigs,
                        stakeholders,
                        acting_parties: acting,
                        interface_id: interface_id.as_ref().map(|i| parse_colon_identifier(i, "")),
                        by_key: false,
                        key,
                    };
                    self.push_node(
                        nid_str.clone(),
                        v1::Node {
                            node_type: Some(NodeType::Fetch(fetch)),
                        },
                    );
                    self.attach_child(parent_idx, nid_str);
                }
                EngineEvent::Exercise {
                    contract_id,
                    choice,
                    consuming,
                    actors,
                    argument,
                    result,
                    interface_id,
                    observers,
                    depth,
                } => {
                    let (nid, nid_str) = self.alloc_id();
                    self.node_seeds.push(NodeSeed {
                        node_id: nid,
                        seed: derive_node_seed(self.tx_uuid, nid),
                    });
                    let Some(gc) = self.find_contract(
                        contract_id,
                        created_by_cid,
                        disclosed_by_cid,
                        history_contracts,
                    ) else {
                        continue;
                    };
                    self.note_input(&gc);
                    let pkg_name = self
                        .service
                        .v2_package_name(&gc.package_id)
                        .unwrap_or_default();
                    let local_tpl = format!(
                        "{}:{}",
                        gc.template_id.module_name, gc.template_id.entity_name
                    );
                    let pkg = self.service.v2_lf_package(&gc.package_id);
                    let (chosen_value, exercise_result) = if let Some(ref p) = pkg {
                        let types = Types::new(&p.world);
                        // [CANTON-NOTE: SEMANTICS] A choice exercised through an interface (`TransferFactory_Transfer` of the Token Standard) has the types
                        // of the interface's choice: its argument and result carry Time, Map and record ids that only those types name, and the hash
                        // covers them (a Time is a different value kind than an Int64).
                        let via_interface = interface_id.as_deref().and_then(|iface| {
                            let id = parse_colon_identifier(iface, &gc.package_id);
                            types
                                .interface_choice(
                                    &id.package_id,
                                    &format!("{}:{}", id.module_name, id.entity_name),
                                    choice,
                                )
                                .ok()
                        });
                        let choice_types = via_interface
                            .or_else(|| types.choice(&gc.package_id, &local_tpl, choice).ok());
                        let cv = match &choice_types {
                            Some(ct) => lf_to_lapi_value(Some((&types, &ct.argument)), argument),
                            None => lf_to_lapi_value(None, argument),
                        };
                        let res = result.as_ref().map(|r| match &choice_types {
                            Some(ct) => lf_to_lapi_value(Some((&types, &ct.result)), r),
                            None => lf_to_lapi_value(None, r),
                        });
                        (cv, res)
                    } else {
                        (
                            lf_to_lapi_value(None, argument),
                            result.as_ref().map(|r| lf_to_lapi_value(None, r)),
                        )
                    };
                    let key = global_key_with_maintainers(self.service, &gc);
                    if key.is_some() {
                        self.any_keyed = true;
                    }
                    let lf_version = if key.is_some() { "2" } else { "2.1" }.to_string();
                    let mut sigs = gc.signatories.clone();
                    sigs.sort();
                    sigs.dedup();
                    let stakeholders = sorted_stakeholders(&gc.signatories, &gc.observers);
                    let mut acting = actors.clone();
                    acting.sort();
                    acting.dedup();
                    let iface_proto = interface_id
                        .as_deref()
                        .map(|s| parse_colon_identifier(s, &gc.package_id));
                    let ex = v1::Exercise {
                        lf_version,
                        contract_id: gc.contract_id.clone(),
                        package_name: pkg_name,
                        template_id: Some(lapi_identifier(&gc.template_id)),
                        signatories: sigs,
                        stakeholders,
                        acting_parties: acting,
                        interface_id: iface_proto,
                        choice_id: choice.clone(),
                        chosen_value: Some(chosen_value),
                        consuming: *consuming,
                        exercise_result,
                        choice_observers: observers.clone(),
                        children: Vec::new(),
                        external_call_results: Vec::new(),
                        by_key: false,
                        key,
                    };
                    let idx = self.push_node(
                        nid_str.clone(),
                        v1::Node {
                            node_type: Some(NodeType::Exercise(ex)),
                        },
                    );
                    self.attach_child(parent_idx, nid_str);
                    stack.push((*depth, idx));
                }
            }
        }

        for rb in rolled_back
            .iter()
            .filter(|g| g.at == start_idx + events.len())
        {
            let rb_parent_depth = rb
                .events
                .first()
                .map(|e| match e {
                    EngineEvent::Create { depth, .. }
                    | EngineEvent::Exercise { depth, .. }
                    | EngineEvent::Fetch { depth, .. } => depth.saturating_sub(1),
                })
                .unwrap_or(base_depth);
            while stack.last().is_some_and(|(d, _)| *d > rb_parent_depth) {
                stack.pop();
            }
            let rb_parent_idx = stack.last().map(|(_, idx)| *idx);
            let (_rb_id_num, rb_id) = self.alloc_id();
            let rb_idx = self.push_node(
                rb_id.clone(),
                v1::Node {
                    node_type: Some(NodeType::Rollback(v1::Rollback {
                        children: Vec::new(),
                    })),
                },
            );
            self.attach_child(rb_parent_idx, rb_id);
            let inner_depth = rb_parent_depth + 1;
            self.append_engine_slice(
                &rb.events,
                usize::MAX,
                &[],
                Some(rb_idx),
                inner_depth,
                created_by_cid,
                disclosed_by_cid,
                history_contracts,
            );
        }
    }
}

fn prepare_tree_from_commits(
    service: &ExecutionService,
    commits: &[TransactionCommit],
    disclosed: &[GenericContract],
    act_as: &[String],
    command_id: &str,
    synchronizer_id: &str,
    tx_uuid: &str,
    max_record_time: Option<i64>,
    min_ledger_time: Option<i64>,
) -> PreparedTransaction {
    let mut ctx = BuildPreparedCtx::new(service, tx_uuid);
    let disclosed_by_cid: HashMap<&str, &GenericContract> = disclosed
        .iter()
        .map(|d| (d.contract_id.as_str(), d))
        .collect();

    for commit in commits {
        let created_by_cid: HashMap<&str, &GenericContract> = commit
            .created_contracts
            .iter()
            .map(|c| (c.contract_id.as_str(), c))
            .collect();
        if commit.engine_events.is_empty() {
            for gc in &commit.created_contracts {
                let (nid, nid_str) = ctx.alloc_id();
                ctx.node_seeds.push(NodeSeed {
                    node_id: nid,
                    seed: derive_node_seed(tx_uuid, nid),
                });
                ctx.created_in_tx.insert(gc.contract_id.clone());
                let create = create_node_from_gc(service, gc);
                if create.key.is_some() {
                    ctx.any_keyed = true;
                }
                ctx.push_node(
                    nid_str.clone(),
                    v1::Node {
                        node_type: Some(NodeType::Create(create)),
                    },
                );
                ctx.roots.push(nid_str);
            }
        } else {
            let hist_contracts = commit.history.as_ref().map(|h| &h.contracts);
            ctx.append_engine_slice(
                &commit.engine_events,
                0,
                &commit.engine_rolled_back,
                None,
                0,
                &created_by_cid,
                &disclosed_by_cid,
                hist_contracts,
            );
        }
    }

    // [CANTON-NOTE: SEMANTICS] The input contracts go out sorted by contract id, the order the hash takes them in
    // (`TransactionMetadataForHashing` sorts `disclosedContracts` by `LfContractId.coid`): a verifier that hashes the metadata as serialized
    // (the Wallet SDK's `core-tx-hashing`) gets the server's hash only when the serialization is in that order. With one input contract (all the
    // sample-contract flows) the order never showed; the transfer of the Token Standard has three (U-25).
    let mut sorted_inputs: Vec<&(String, GenericContract)> = ctx.input_contracts.iter().collect();
    sorted_inputs.sort_by(|(a, _), (b, _)| a.cmp(b));
    let input_contracts: Vec<InputContract> = sorted_inputs
        .into_iter()
        .map(|(_, gc)| {
            let create = create_node_from_gc(service, gc);
            let event_blob = if !gc.created_event_blob.is_empty() {
                decode_strict_base64(&gc.created_event_blob).unwrap_or_default()
            } else {
                let b64 = blob_for(service, gc);
                decode_strict_base64(&b64).unwrap_or_default()
            };
            InputContract {
                created_at: gc.created_at_micros.max(0) as u64,
                event_blob,
                contract: Some(input_contract::Contract::V1(create)),
            }
        })
        .collect();

    let version = if ctx.any_keyed { "2" } else { "2.1" }.to_string();
    let prep_time = unix_micros_now().max(0) as u64;
    let tx = DamlTransaction {
        version,
        roots: ctx.roots,
        nodes: ctx.nodes,
        node_seeds: ctx.node_seeds,
    };
    #[allow(
        deprecated,
        reason = "populates legacy/deprecated Canton protobuf or pinned crypto fields for wire compatibility"
    )]
    let meta = Metadata {
        submitter_info: Some(SubmitterInfo {
            act_as: act_as.to_vec(),
            command_id: command_id.to_string(),
        }),
        synchronizer_id: synchronizer_id.to_string(),
        mediator_group: 0,
        transaction_uuid: tx_uuid.to_string(),
        preparation_time: prep_time,
        input_contracts,
        min_ledger_effective_time: min_ledger_time.and_then(|t| u64::try_from(t).ok()),
        max_ledger_effective_time: max_record_time.and_then(|t| u64::try_from(t).ok()),
        global_key_mapping: Vec::new(),
        max_record_time: max_record_time.and_then(|t| u64::try_from(t).ok()),
    };
    PreparedTransaction {
        transaction: Some(tx),
        metadata: Some(meta),
    }
}

/// `POST /v2/interactive-submission/prepare`.
pub fn prepare(service: &ExecutionService, body: &Json) -> HttpResponse {
    // the official JSON codec checks the body's shape (here: the cost hints) before anything is interpreted
    let cost_hints = match crate::cost_estimation::parse_cost_hints(body) {
        Ok(h) => h,
        Err(text) => return crate::v2_commands::bad_body(text),
    };
    let synchronizer_req = body["synchronizerId"].as_str().unwrap_or("");
    let state = service.v2_state();
    let active_sync = state.synchronizer_id();
    let synchronizer_id = if synchronizer_req.is_empty() {
        active_sync
    } else if synchronizer_matches(&active_sync, synchronizer_req) {
        synchronizer_req.to_string()
    } else {
        return canton_error(
            Kind::RequestCorrelated,
            400,
            "INVALID_PRESCRIBED_SYNCHRONIZER_ID",
            format!("The prescribed synchronizer '{synchronizer_req}' is not connected"),
            8,
            3,
            json!([]),
        );
    };
    let scheme = match parse_hashing_scheme(body.get("hashingSchemeVersion"), true) {
        Ok(s) => s,
        Err(e) => return invalid_arg(e),
    };
    let max_record_time = body
        .get("maxRecordTime")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| parse_micros(s).ok_or_else(|| invalid_arg(format!("invalid maxRecordTime '{s}'"))))
        .transpose();
    let max_record_time = match max_record_time {
        Ok(v) => v,
        Err(r) => return r,
    };
    let min_ledger_time = body
        .get("minLedgerTime")
        .and_then(|m| {
            m.pointer("/MinLedgerTimeAbs/value")
                .or_else(|| m.pointer("/time/MinLedgerTimeAbs/value"))
                .or_else(|| m.get("minLedgerTimeAbs"))
        })
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .and_then(parse_micros);

    let act_as: Vec<String> = body["actAs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let command_id = body["commandId"].as_str().unwrap_or("").to_string();
    let seq = state.submission_seq.fetch_add(1, Ordering::SeqCst);
    let tx_uuid = format!("00000000-0000-4000-8000-{seq:012x}");

    let (events, commits, disclosed, read_as) =
        match dry_run_prepare_commands(service, body, &tx_uuid) {
            Ok(res) => res,
            Err(resp) => return resp,
        };
    // [CANTON-NOTE: SEMANTICS] the official participant refuses an `expectedSignatures` algorithm it does not support only once the command
    // got past package selection (a command it cannot route is refused for that first: recorded on p1, S-SIM-001 K-07); disabled hints are
    // not validated (`Option.when(!disabled)`)
    if let Some(name) = cost_hints
        .as_ref()
        .and_then(crate::cost_estimation::unsupported_algorithm)
    {
        return canton_error(
            Kind::RequestCorrelated,
            400,
            "INVALID_FIELD",
            crate::cost_estimation::unsupported_algorithm_cause(name),
            8,
            3,
            json!([]),
        );
    }

    // [CANTON-NOTE: SEMANTICS] with a protocol node, the prepared transaction is read from the request the protocol will send (its uuid,
    // times, seeds and contract discriminators), so that the hash the parties sign is the one its confirmers recompute (U-56)
    let from_protocol = service
        .committer
        .read()
        .ok()
        .and_then(|c| c.clone())
        .and_then(|c| c.prepared_transaction(&commits, &command_id, max_record_time));
    let prepared = match from_protocol {
        Some(Ok(prepared)) => prepared,
        Some(Err(e)) => return fail_prepare(e),
        None => prepare_tree_from_commits(
            service,
            &commits,
            &disclosed,
            &act_as,
            &command_id,
            &synchronizer_id,
            &tx_uuid,
            max_record_time,
            min_ledger_time,
        ),
    };

    let hash_bytes = match hash_prepared_transaction(&prepared, scheme) {
        Ok(h) => h,
        Err(PreparedHashError::UnsupportedSerializationVersion { version, .. })
            if scheme == HashingSchemeVersion::V2 && version == "2" =>
        {
            return fail_prepare(
                "Cannot hash node with LF serialization version V2 using hashing scheme V2. \
                 Does the transaction use contract keys? Please use hashing scheme V3 or higher.",
            );
        }
        Err(e) => return fail_prepare(e),
    };

    let mut required_active_inputs = Vec::new();
    let mut seen = HashSet::new();
    for commit in &commits {
        // [CANTON-NOTE: SEMANTICS] A contract the transaction creates is not an input of it, also when the transaction archives it again
        // (the `AmuletEventLog` of the Token Standard is created, exercised and archived inside one transaction and is in no ACS delta).
        let created_in_tx: HashSet<&str> = commit
            .created_contracts
            .iter()
            .map(|c| c.contract_id.as_str())
            .chain(commit.engine_events.iter().filter_map(|ev| match ev {
                EngineEvent::Create { contract_id, .. } => Some(contract_id.as_str()),
                _ => None,
            }))
            .collect();
        for cid in commit.consumed_cids.iter().chain(&commit.archived_cids) {
            if !created_in_tx.contains(cid.as_str()) && seen.insert(cid.clone()) {
                required_active_inputs.push(cid.clone());
            }
        }
        for ev in &commit.engine_events {
            if let EngineEvent::Exercise { contract_id, .. }
            | EngineEvent::Fetch { contract_id, .. } = ev
            {
                if !created_in_tx.contains(contract_id.as_str()) && seen.insert(contract_id.clone())
                {
                    required_active_inputs.push(contract_id.clone());
                }
            }
        }
    }

    // [CANTON-NOTE: SEMANTICS] the estimate reads the traffic control in force on the protocol node (`τ`); a service without one has none
    let traffic = service
        .committer
        .read()
        .ok()
        .and_then(|c| c.clone())
        .and_then(|c| c.traffic_cost_inputs(&act_as, unix_micros_now()));
    let request = match (&traffic, &cost_hints) {
        (Some(_), Some(_)) => service
            .committer
            .read()
            .ok()
            .and_then(|c| c.clone())
            .and_then(|c| {
                // the external parties' keys, as `execute` checks the signatures against them
                let recorded = state
                    .external_parties
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                let parties: Vec<_> = act_as
                    .iter()
                    .map(|p| {
                        (
                            p.clone(),
                            crate::external_keys::signing_keys(service, p, recorded.get(p)),
                        )
                    })
                    .collect();
                let mocks = cost_hints
                    .as_ref()
                    .and_then(|h| crate::cost_estimation::mock_external_authorization(h, &parties));
                c.priced_confirmation_request(&commits, &command_id, mocks.as_ref())
            })
            .and_then(|built| {
                built
                    .map_err(|e| {
                        crate::diag::diag_eprintln!(
                            "prepare: the confirmation request was not built for the estimate: {e:?}"
                        )
                    })
                    .ok()
            }),
        _ => None,
    };
    let estimate = crate::cost_estimation::estimate(
        cost_hints.as_ref(),
        traffic.as_ref(),
        request.as_deref(),
        now_rfc3339(),
    );
    if let crate::cost_estimation::Estimate::RequestNotBuilt { response } = &estimate {
        crate::diag::diag_eprintln!(
            "prepare: traffic control is on, the confirmation request of this shape is not priced (response cost {response:?}); costEstimation is null"
        );
    }

    let has_disclosed_inputs = !disclosed.is_empty();
    let cache_key = (
        logical_synchronizer(&synchronizer_id).to_string(),
        hash_bytes,
    );
    state
        .prepared_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            cache_key,
            CachedPrepared {
                commits,
                disclosed,
                read_as,
                required_active_inputs,
                events,
                max_record_time_micros: max_record_time,
                has_disclosed_inputs,
            },
        );

    let prepared_b64 = base64(&prepared.encode_to_vec());
    let hash_b64 = base64(&hash_bytes);
    HttpResponse::json(
        200,
        &json!({
            "preparedTransaction": prepared_b64,
            "preparedTransactionHash": hash_b64,
            "hashingSchemeVersion": hashing_scheme_name(scheme),
            "hashingDetails": null,
            "costEstimation": crate::cost_estimation::cost_estimation_json(&estimate)
        }),
    )
}
