//! The hash an externally signed request's parties signed, recomputed from the tree a confirming participant received (U-56): the
//! prepared transaction the root view describes, hashed as the interactive submission service hashes it.
//!
//! [CANTON-NOTE: SEMANTICS] Canton 3.7.2 `AuthenticationValidator.verifyExternalPartySignature` re-interprets the root view and hashes the
//! enriched transaction with `InteractiveSubmission.computeVersionedHash` (`ModelConformanceChecker.computeHash`): the transaction (its
//! nodes with record labels and identifiers, and its node seeds), the submitter's `actAs` and command id, the transaction uuid, the mediator
//! group, the physical synchronizer id, the time boundaries, the preparation time, the maximum record time and the input contracts.
//!
//! [CANTON-NOTE: LIMITATION] A root create and a root exercise with the actions below it (creates, exercises, fetches, in its view or in
//! subviews) are rebuilt; a root fetch, and a transaction whose contracts have a key (the key, `by_key` and `LookupByKey` nodes are not
//! rebuilt), are refused with an explicit error, so the caller keeps refusing the request rather than accept an external authorization it
//! cannot check.
use crate::view_conformance::{open_instance, Engine};
use crate::view_receive::{
    revealed_common_metadata, revealed_participant_metadata, revealed_submitter_metadata,
    revealed_views,
};
use canton_proto::com::daml::ledger::api::v2 as lapi;
use canton_proto::com::daml::ledger::api::v2::interactive::daml_transaction::node::VersionedNode;
use canton_proto::com::daml::ledger::api::v2::interactive::daml_transaction::{Node, NodeSeed};
use canton_proto::com::daml::ledger::api::v2::interactive::metadata::{
    InputContract, SubmitterInfo,
};
use canton_proto::com::daml::ledger::api::v2::interactive::transaction::v1;
use canton_proto::com::daml::ledger::api::v2::interactive::{
    DamlTransaction, Metadata, PreparedTransaction,
};
use canton_proto::com::digitalasset::canton::protocol::v30::GenTransactionTree;
use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
use canton_proto::com::digitalasset::daml::lf::transaction::FatContractInstance;

/// The length of a V1 contract id without its suffix: the version byte and the 32-byte discriminator.
const UNSUFFIXED_CONTRACT_ID_BYTES: usize = 33;

/// The prepared transaction the root view of `tree` describes, as the external parties signed it, from the views `tree` reveals (a
/// submitter's own tree reveals them all).
pub fn prepared_transaction(
    engine: &Engine,
    tree: &GenTransactionTree,
) -> Result<PreparedTransaction, String> {
    let views = revealed_views(tree).map_err(|e| format!("{e:?}"))?;
    prepared_transaction_in(engine, tree, &views)
}

/// Like [`prepared_transaction`], with the views the request reveals to this participant across all its trees (`views`): a subview
/// travels in a tree of its own.
pub fn prepared_transaction_in(
    engine: &Engine,
    tree: &GenTransactionTree,
    views: &[crate::view_receive::RevealedView],
) -> Result<PreparedTransaction, String> {
    let submitter = revealed_submitter_metadata(tree).map_err(|e| format!("{e:?}"))?;
    let common = revealed_common_metadata(tree).map_err(|e| format!("{e:?}"))?;
    let participant = revealed_participant_metadata(tree).map_err(|e| format!("{e:?}"))?;
    let roots: Vec<_> = views.iter().filter(|v| v.position.len() == 1).collect();
    let [root] = roots.as_slice() else {
        // `AuthenticationError.MultipleExternallySignedRootViews`
        return Err(format!(
            "Only single root transactions can currently be externally signed. Got {}",
            roots.len()
        ));
    };
    let action = root
        .participant_data
        .action_description
        .as_ref()
        .and_then(|a| a.description.as_ref())
        .ok_or("the root view has no action description")?;
    let built = match action {
        Description::Create(create) => {
            let [created] = root.participant_data.created_core.as_slice() else {
                return Err("a create view creates one contract".into());
            };
            let node = v1::node::NodeType::Create(create_node(engine, &created.contract, true)?);
            Built {
                nodes: vec![(node, Vec::new())],
                seeds: vec![(0, create.node_seed.clone())],
                inputs: Vec::new(),
            }
        }
        Description::Exercise(exercise) => exercise_tree(
            engine,
            root,
            views,
            exercise,
            &common,
            participant.ledger_time,
        )?,
        Description::Fetch(_) => {
            return Err(
                "recomputing the externally signed hash of a root fetch is not supported yet"
                    .into(),
            )
        }
    };
    let version = match built.nodes.first().map(|(n, _)| n) {
        Some(v1::node::NodeType::Create(c)) => c.lf_version.clone(),
        Some(v1::node::NodeType::Exercise(e)) => e.lf_version.clone(),
        _ => String::new(),
    };
    let input_contracts = built.inputs;
    #[expect(
        deprecated,
        reason = "`global_key_mapping` is a deprecated field of the Ledger API metadata, left empty"
    )]
    let metadata = Metadata {
        submitter_info: Some(SubmitterInfo {
            act_as: submitter.act_as.clone(),
            command_id: submitter.command_id.clone(),
        }),
        synchronizer_id: common.physical_synchronizer_id.clone(),
        mediator_group: u32::try_from(common.mediator_group)
            .map_err(|_| "a negative mediator group")?,
        transaction_uuid: common.uuid,
        preparation_time: u64::try_from(participant.preparation_time)
            .map_err(|_| "a preparation time before the epoch")?,
        input_contracts,
        // [CANTON-NOTE: LIMITATION] the time boundaries of the re-interpretation are taken as none: right for a create and for an exercise
        // that does not read the ledger time (the official prepare of `Settle` states none); a choice that reads the time is not told apart
        min_ledger_effective_time: None,
        max_ledger_effective_time: None,
        max_record_time: submitter
            .external_authorization
            .as_ref()
            .and_then(|e| e.max_record_time)
            .and_then(|t| u64::try_from(t).ok()),
        global_key_mapping: Vec::new(),
    };
    Ok(PreparedTransaction {
        transaction: Some(DamlTransaction {
            version,
            roots: vec!["0".into()],
            nodes: built
                .nodes
                .into_iter()
                .enumerate()
                .map(|(id, (node_type, children))| {
                    let node_type = match node_type {
                        v1::node::NodeType::Exercise(mut e) => {
                            e.children = children.iter().map(usize::to_string).collect();
                            v1::node::NodeType::Exercise(e)
                        }
                        other => other,
                    };
                    Node {
                        node_id: id.to_string(),
                        versioned_node: Some(VersionedNode::V1(v1::Node {
                            node_type: Some(node_type),
                        })),
                    }
                })
                .collect(),
            node_seeds: built
                .seeds
                .into_iter()
                .map(|(node_id, seed)| NodeSeed {
                    node_id: i32::try_from(node_id).unwrap_or(i32::MAX),
                    seed,
                })
                .collect(),
        }),
        metadata: Some(metadata),
    })
}

/// `Err` when the contract has a key: the rebuild does not carry keys yet (see the module LIMITATION).
fn refuse_contract_key(fci: &FatContractInstance) -> Result<(), String> {
    match fci.contract_key_with_maintainers {
        Some(_) => Err(
            "an externally signed transaction that uses a contract key is not supported yet (U-56)"
                .into(),
        ),
        None => Ok(()),
    }
}

/// The create node of the contract a view creates, enriched with the template's record labels and identifiers.
fn create_node(engine: &Engine, contract: &[u8], unsuffixed: bool) -> Result<v1::Create, String> {
    let (data, lf_version) =
        crate::view_conformance::unversioned_fat(contract).map_err(|e| format!("{e:?}"))?;
    let fci = <FatContractInstance as prost::Message>::decode(data.as_slice())
        .map_err(|e| e.to_string())?;
    // [CANTON-NOTE: LIMITATION] the hash of a transaction with a contract key covers the key, `by_key` and `LookupByKey` nodes, which this
    // rebuild does not carry yet: such a transaction is refused with this error rather than with a hash that cannot match (U-56 review
    // R1-F2)
    refuse_contract_key(&fci)?;
    let package_name = fci.package_name;
    let opened = open_instance(engine, contract)?;
    let id = hex::decode(&opened.contract_id).map_err(|e| e.to_string())?;
    // a contract the transaction creates is named by its discriminator alone; an input contract by its full id
    let shown = if unsuffixed {
        id.get(..UNSUFFIXED_CONTRACT_ID_BYTES)
            .ok_or("a contract id shorter than a discriminator")?
    } else {
        id.as_slice()
    };
    let types = lf_eval::typed_json::Types::new(&engine.world);
    let template_type = types
        .template(&opened.package_id, &opened.template)
        .map_err(|e| format!("the template {} is not loaded: {e}", opened.template))?;
    let (module_name, entity_name) = opened
        .template
        .split_once(':')
        .ok_or("a template without a module")?;
    Ok(v1::Create {
        lf_version,
        contract_id: hex::encode(shown),
        package_name,
        template_id: Some(lapi::Identifier {
            package_id: opened.package_id.clone(),
            module_name: module_name.to_string(),
            entity_name: entity_name.to_string(),
        }),
        argument: Some(canton_algo::lapi_value::lf_to_lapi_value(
            Some((&types, &template_type)),
            &opened.arg,
        )),
        signatories: opened.signatories.iter().cloned().collect(),
        stakeholders: opened.stakeholders.iter().cloned().collect(),
        key: None,
    })
}

/// The transaction a root view describes: its nodes in pre-order (node `i` has id `i`), each with the ids of its children, the seeds
/// of its creates and exercises, and the contracts it uses that it does not create.
struct Built {
    nodes: Vec<(v1::node::NodeType, Vec<usize>)>,
    seeds: Vec<(usize, Vec<u8>)>,
    inputs: Vec<InputContract>,
}

/// The transaction of a root view whose action is an exercise, from the engine's replay of the view.
///
/// [CANTON-NOTE: SEMANTICS] A child's seed is its parent exercise's seed derived by the child's index among its siblings (`deriveNodeSeed`;
/// every sibling takes an index, fetches included); the root's is the action description's. A contract the transaction creates is named
/// by its discriminator alone, in its create node, in the exercises on it and in the values that carry it; a contract it only uses is
/// named by its full id and listed as an input contract with its creation time.
///
/// [CANTON-NOTE: LIMITATION] A rollback scope is not rebuilt.
fn exercise_tree(
    engine: &Engine,
    root: &crate::view_receive::RevealedView,
    views: &[crate::view_receive::RevealedView],
    exercise: &canton_proto::com::digitalasset::canton::protocol::v30::action_description::ExerciseActionDescription,
    common: &canton_proto::com::digitalasset::canton::protocol::v30::CommonMetadata,
    ledger_time: i64,
) -> Result<Built, String> {
    use crate::view_acs::RemoteEvent;
    // [CANTON-NOTE: SEMANTICS] the root view's informees see its whole subtree: the subviews below it are replayed with it (their inputs and
    // creates), as the official re-interpretation of the root action covers every node below it
    let subviews: Vec<&crate::view_receive::RevealedView> = views
        .iter()
        .filter(|other| {
            other.position.len() > root.position.len() && other.position.ends_with(&root.position)
        })
        .collect();
    engine.set_ledger_time(ledger_time);
    let (_, _, _, events) = crate::view_conformance::check_exercise_view_with_events(
        engine, root, &subviews, common, None, None,
    )
    .map_err(|e| format!("the root exercise does not replay: {e:?}"))?;
    let created: std::collections::BTreeSet<String> = events
        .iter()
        .filter_map(|e| match e {
            RemoteEvent::Create { contract_id, .. } => Some(contract_id.clone()),
            _ => None,
        })
        .collect();
    let root_seed: [u8; 32] = exercise
        .node_seed
        .as_slice()
        .try_into()
        .map_err(|_| "a root seed of the wrong size")?;
    let mut built = Built {
        nodes: Vec::new(),
        seeds: Vec::new(),
        inputs: Vec::new(),
    };
    let mut inputs: std::collections::BTreeMap<String, InputContract> = Default::default();
    // the open exercises, innermost last: (node index, depth, seed, the next child's index)
    let mut open: Vec<(usize, usize, [u8; 32], i32)> = Vec::new();
    for event in &events {
        let depth = match event {
            RemoteEvent::Create { depth, .. } | RemoteEvent::Fetch { depth, .. } => *depth,
            RemoteEvent::Exercise(e) => e.depth,
        };
        while open.last().is_some_and(|(_, d, _, _)| *d >= depth) {
            open.pop();
        }
        let index = built.nodes.len();
        let seed = match open.last_mut() {
            None if index == 0 => root_seed,
            None => return Err("a replayed node outside the root exercise".into()),
            Some((parent, _, parent_seed, next)) => {
                let seed = crate::contract_id::derive_node_seed(parent_seed, *next);
                *next += 1;
                built.nodes[*parent].1.push(index);
                seed
            }
        };
        let node = match event {
            RemoteEvent::Create { instance, .. } => {
                let mut create = create_node(engine, instance, true)?;
                if let Some(argument) = create.argument.as_mut() {
                    unsuffix_created(argument, &created);
                }
                v1::node::NodeType::Create(create)
            }
            RemoteEvent::Exercise(replayed) => {
                let node = exercise_v1(engine, replayed, &created)?;
                if !created.contains(&replayed.contract_id) {
                    let opened = open_instance(engine, &replayed.input_instance)?;
                    inputs.entry(replayed.contract_id.clone()).or_insert(InputContract {
                        created_at: u64::try_from(opened.created_at_micros)
                            .map_err(|_| "an input contract created before the epoch")?,
                        // [CANTON-NOTE: WHY] the hash covers an input contract's creation time and create node, not its event blob
                        event_blob: Vec::new(),
                        contract: Some(
                            canton_proto::com::daml::ledger::api::v2::interactive::metadata::input_contract::Contract::V1(
                                create_node(engine, &replayed.input_instance, false)?,
                            ),
                        ),
                    });
                }
                open.push((index, depth, seed, 0));
                v1::node::NodeType::Exercise(node)
            }
            RemoteEvent::Fetch {
                contract_id,
                input_instance,
                actors,
                interface_id,
                ..
            } => {
                if input_instance.is_empty() {
                    return Err("a replayed fetch without the fetched contract".into());
                }
                let fetched = create_node(engine, input_instance, created.contains(contract_id))?;
                if !created.contains(contract_id) {
                    let opened = open_instance(engine, input_instance)?;
                    inputs.entry(contract_id.clone()).or_insert(InputContract {
                        created_at: u64::try_from(opened.created_at_micros)
                            .map_err(|_| "an input contract created before the epoch")?,
                        event_blob: Vec::new(),
                        contract: Some(
                            canton_proto::com::daml::ledger::api::v2::interactive::metadata::input_contract::Contract::V1(
                                create_node(engine, input_instance, false)?,
                            ),
                        ),
                    });
                }
                let mut acting: Vec<String> = actors.clone();
                acting.sort();
                acting.dedup();
                // [CANTON-NOTE: SEMANTICS] a fetch takes a child index among its siblings but carries no seed
                built.nodes.push((
                    v1::node::NodeType::Fetch(v1::Fetch {
                        lf_version: fetched.lf_version,
                        contract_id: fetched.contract_id,
                        package_name: fetched.package_name,
                        template_id: fetched.template_id,
                        signatories: fetched.signatories,
                        stakeholders: fetched.stakeholders,
                        acting_parties: acting,
                        interface_id: interface_id
                            .as_deref()
                            .map(|i| canton_algo::lapi_value::parse_colon_identifier(i, "")),
                        key: None,
                        by_key: false,
                    }),
                    Vec::new(),
                ));
                continue;
            }
        };
        built.seeds.push((index, seed.to_vec()));
        built.nodes.push((node, Vec::new()));
    }
    if !matches!(
        built.nodes.first(),
        Some((v1::node::NodeType::Exercise(_), _))
    ) {
        return Err("the replay of the root exercise does not start with it".into());
    }
    built.inputs = inputs.into_values().collect();
    Ok(built)
}

/// The exercise node of a replayed exercise (its children are filled in by the caller).
fn exercise_v1(
    engine: &Engine,
    replayed: &crate::view_acs::RemoteExercise,
    created: &std::collections::BTreeSet<String>,
) -> Result<v1::Exercise, String> {
    let input = create_node(
        engine,
        &replayed.input_instance,
        created.contains(&replayed.contract_id),
    )?;
    let opened = open_instance(engine, &replayed.input_instance)?;
    let types = lf_eval::typed_json::Types::new(&engine.world);
    let choice = types
        .choice(&opened.package_id, &opened.template, &replayed.choice)
        .map_err(|e| format!("the choice {} is not loaded: {e}", replayed.choice))?;
    let sorted = |parties: &[String]| {
        parties
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    };
    let mut chosen_value = canton_algo::lapi_value::lf_to_lapi_value(
        Some((&types, &choice.argument)),
        &replayed.argument,
    );
    unsuffix_created(&mut chosen_value, created);
    let exercise_result = replayed.result.as_ref().map(|r| {
        let mut value =
            canton_algo::lapi_value::lf_to_lapi_value(Some((&types, &choice.result)), r);
        unsuffix_created(&mut value, created);
        value
    });
    Ok(v1::Exercise {
        // the node's version is the exercised contract's
        lf_version: input.lf_version,
        contract_id: input.contract_id,
        package_name: input.package_name,
        template_id: input.template_id,
        signatories: input.signatories,
        stakeholders: input.stakeholders,
        acting_parties: sorted(&replayed.actors),
        interface_id: replayed
            .interface_id
            .as_deref()
            .map(|i| canton_algo::lapi_value::parse_colon_identifier(i, "")),
        choice_id: replayed.choice.clone(),
        chosen_value: Some(chosen_value),
        consuming: replayed.consuming,
        children: Vec::new(),
        exercise_result,
        choice_observers: sorted(&replayed.observers),
        key: None,
        by_key: false,
        external_call_results: Vec::new(),
    })
}

/// Names the contracts `created` (full ids, hex) by their discriminators alone wherever `value` carries them.
fn unsuffix_created(value: &mut lapi::Value, created: &std::collections::BTreeSet<String>) {
    use lapi::value::Sum;
    let Some(sum) = value.sum.as_mut() else {
        return;
    };
    match sum {
        Sum::ContractId(id) => {
            if created.contains(id.as_str()) {
                id.truncate(UNSUFFIXED_CONTRACT_ID_BYTES * 2);
            }
        }
        Sum::Record(r) => {
            for f in &mut r.fields {
                if let Some(v) = f.value.as_mut() {
                    unsuffix_created(v, created);
                }
            }
        }
        Sum::Variant(v) => {
            if let Some(v) = v.value.as_mut() {
                unsuffix_created(v, created);
            }
        }
        Sum::List(l) => {
            for v in &mut l.elements {
                unsuffix_created(v, created);
            }
        }
        Sum::Optional(o) => {
            if let Some(v) = o.value.as_mut() {
                unsuffix_created(v, created);
            }
        }
        Sum::TextMap(m) => {
            for e in &mut m.entries {
                if let Some(v) = e.value.as_mut() {
                    unsuffix_created(v, created);
                }
            }
        }
        Sum::GenMap(m) => {
            for e in &mut m.entries {
                if let Some(k) = e.key.as_mut() {
                    unsuffix_created(k, created);
                }
                if let Some(v) = e.value.as_mut() {
                    unsuffix_created(v, created);
                }
            }
        }
        _ => {}
    }
}

/// The signing keys of a party and how many of them must sign (`PartyToKeyMapping` or `PartyToParticipant.party_signing_keys`).
pub type PartyKeys<'a> = dyn Fn(
        &str,
    ) -> Option<(
        u32,
        Vec<canton_proto::com::digitalasset::canton::crypto::v30::SigningPublicKey>,
    )> + 'a;

/// Whether the external authorization of `tree`'s submitter metadata is valid: the hash recomputed from the root view, signed by every
/// `actAs` party with at least its threshold of distinct keys. `Ok` with no external authorization (a classic submission).
///
/// [CANTON-NOTE: SEMANTICS] `InteractiveSubmission.verifySignatures`: every `actAs` party must have signed (a party with no registered keys
/// cannot), each signature over the 32-byte hash as the prepare answered it (measured: a signature over the 34-byte multihash is
/// refused by the official participant, U-56 vector).
pub fn verify(
    engine: &Engine,
    tree: &GenTransactionTree,
    keys_of: &PartyKeys<'_>,
) -> Result<(), String> {
    let views = revealed_views(tree).map_err(|e| format!("{e:?}"))?;
    verify_in(engine, tree, &views, keys_of)
}

/// Like [`verify`], with the views the request reveals to this participant across all its trees (`views`).
pub fn verify_in(
    engine: &Engine,
    tree: &GenTransactionTree,
    views: &[crate::view_receive::RevealedView],
    keys_of: &PartyKeys<'_>,
) -> Result<(), String> {
    use canton_algo::signing::{parse_public_key, parse_signature, verify_signature, Usage};
    use canton_proto::com::daml::ledger::api::v2::interactive::HashingSchemeVersion;
    use prost::Message;
    let submitter = revealed_submitter_metadata(tree).map_err(|e| format!("{e:?}"))?;
    let Some(external) = submitter.external_authorization.as_ref() else {
        return Ok(());
    };
    let scheme = HashingSchemeVersion::try_from(external.hashing_scheme_version).map_err(|_| {
        format!(
            "unknown hashing scheme version {}",
            external.hashing_scheme_version
        )
    })?;
    let prepared = prepared_transaction_in(engine, tree, views)
        .map_err(|e| format!("Failed to compute externally signed hash: {e}"))?;
    let hash = canton_algo::prepared_hash::hash_prepared_transaction(&prepared, scheme)
        .map_err(|e| format!("Failed to compute externally signed hash: {e:?}"))?;
    let usage = std::collections::BTreeSet::from([Usage::Protocol]);
    for party in &submitter.act_as {
        let (threshold, keys) = keys_of(party)
            .ok_or_else(|| format!("Could not find party signing keys for {party}."))?;
        let keys: Vec<_> = keys
            .iter()
            .filter_map(|k| parse_public_key(k).ok())
            .collect();
        let signatures = external
            .authentications
            .iter()
            .filter(|a| a.party == *party)
            .flat_map(|a| a.signatures.iter().cloned())
            .collect::<Vec<_>>();
        canton_algo::party_signatures::verify_party_signatures(
            &keys,
            threshold.max(1) as usize,
            &signatures,
            |key, signature| {
                parse_signature(&signature.encode_to_vec())
                    .is_ok_and(|s| verify_signature(&hash, key, &s, &usage).is_ok())
            },
        )
        .map_err(|refused| refused.message(party, ""))?;
    }
    Ok(())
}

#[cfg(test)]
mod key_tests {
    use super::{refuse_contract_key, FatContractInstance};

    /// U-56 review R1-F2: a contract with a key is refused with an error that names the key, not rebuilt into a hash that cannot match.
    #[test]
    fn a_contract_with_a_key_is_refused_by_name() {
        let keyless = FatContractInstance::default();
        assert_eq!(refuse_contract_key(&keyless), Ok(()));
        let keyed = FatContractInstance {
            contract_key_with_maintainers: Some(Default::default()),
            ..Default::default()
        };
        let refused = refuse_contract_key(&keyed).unwrap_err();
        assert!(refused.contains("contract key"), "{refused}");
    }
}
