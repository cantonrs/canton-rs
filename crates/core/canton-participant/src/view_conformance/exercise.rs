//! Conformance of exercise and fetch views (`check_exercise_view*`, `check_fetch_view`).

use std::collections::BTreeSet;

use canton_proto::com::digitalasset::canton::protocol::v30::{
    CommonMetadata, ContractAuthenticationData,
};
use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
use lf_eval::Value;
use prost::Message;

use crate::contract_id::{contract_id_suffix, lf_contract_hash, unicum, KeyInputs, UnicumInputs};
use crate::topology_wire::unversioned;
use crate::view_informees::{replayed_core_informees, CoreInformees, InformeeContext};
use crate::view_receive::RevealedView;
use crate::view_validation::HostsOf;

use super::replay::{replay_contract, Replayed};
use super::{
    authenticate_created, check_resolved_keys_collecting, segments, stated_key,
    stated_stakeholders, unversioned_fat, Conforming, Engine, EngineKey, ExhaustiveKeyQuery,
    Nonconformance,
};

/// What the engine computes for an exercise view and the checks that follow from it.
#[derive(Debug, PartialEq, Eq)]
pub struct ConformingExercise {
    pub contract_id: String,
    pub template: String,
    pub choice: String,
    pub consuming: bool,
    /// What the parties that witness the replayed nodes need vetted (see `view_vetting`).
    pub party_packages: crate::view_vetting::PartyPackages,
    /// Exhaustive key queries (`contract_ids.len() < limit`) made during replay, checked against the participant's ACS (U-21).
    pub exhaustive_keys: Vec<ExhaustiveKeyQuery>,
}

/// Replays the exercise a view's root action describes.
///
/// [CANTON-NOTE: SEMANTICS] A view whose action is an exercise carries the **input contracts** of its core (the full instance, and
/// whether the exercise consumes it). The receiving participant checks that:
/// - the **input contract is authentic**: its id suffix is the unicum of the *stored* contract salt (from its authentication data),
///   its creation time, its metadata and the LF hash of its arguments (the salt was fixed when it was created, so unlike a created
///   contract it is not re-derived from this view);
/// - the **action is one the template allows**: the choice exists, its argument decodes, the actors are exactly the choice's
///   controllers, and the view's informees cover the contract's stakeholders;
/// - the **engine reproduces the effects**: replayed on an engine that holds the input contract, the exercise succeeds, consumes the
///   contract exactly when the view says so, and creates nothing the view does not list.
pub fn check_exercise_view(
    engine: &Engine,
    view: &RevealedView,
    common_metadata: &CommonMetadata,
) -> Result<ConformingExercise, Nonconformance> {
    check_exercise_view_placed(engine, view, common_metadata).map(|(conforming, _)| conforming)
}

/// Like [`check_exercise_view`], and says where in the exercise's tree each create of the view's core sits (`result.1[i]` for
/// `created_core[i]`, see [`check_discriminators_at`]), as the engine's replay placed it.
pub fn check_exercise_view_placed(
    engine: &Engine,
    view: &RevealedView,
    common_metadata: &CommonMetadata,
) -> Result<(ConformingExercise, Vec<Vec<usize>>), Nonconformance> {
    check_exercise_view_placed_with_subviews(engine, view, &[], common_metadata)
}

/// Like [`check_exercise_view_placed`], aggregating revealed descendant `subviews`' `core_inputs`, non-rolled-back
/// `created_core`, and `resolved_keys` into the root replay (Canton `TransactionView.inputContracts` / `ModelConformanceChecker`).
pub fn check_exercise_view_placed_with_subviews(
    engine: &Engine,
    view: &RevealedView,
    subviews: &[&RevealedView],
    common_metadata: &CommonMetadata,
) -> Result<(ConformingExercise, Vec<Vec<usize>>), Nonconformance> {
    check_exercise_view_in_request(engine, view, subviews, common_metadata)
        .map(|(conforming, positions, _)| (conforming, positions))
}

/// Like [`check_exercise_view_placed_with_subviews`], and gives the informees the replayed nodes give (see [`check_informees`]).
pub fn check_exercise_view_in_request(
    engine: &Engine,
    view: &RevealedView,
    subviews: &[&RevealedView],
    common_metadata: &CommonMetadata,
) -> Result<(ConformingExercise, Vec<Vec<usize>>, CoreInformees), Nonconformance> {
    check_exercise_view_with_topology(engine, view, subviews, common_metadata, None, None)
}

/// Like [`check_exercise_view_in_request`], using topology hosting (`hosts_of` and `root_admin`) for exact subview core decomposition (`P-10`).
pub fn check_exercise_view_with_topology(
    engine: &Engine,
    view: &RevealedView,
    subviews: &[&RevealedView],
    common_metadata: &CommonMetadata,
    root_admin: Option<&str>,
    hosts_of: Option<&HostsOf<'_>>,
) -> Result<(ConformingExercise, Vec<Vec<usize>>, CoreInformees), Nonconformance> {
    let (ce, pos, inf, _) = check_exercise_view_with_events(
        engine,
        view,
        subviews,
        common_metadata,
        root_admin,
        hosts_of,
    )?;
    Ok((ce, pos, inf))
}

/// Rewrites synthetic engine-assigned contract IDs inside a replayed `lf_eval::Value` to real Canton contract IDs (`S-DX-005`).
fn rewrite_value_contract_ids(
    val: &lf_eval::Value,
    map: &std::collections::BTreeMap<String, (String, Vec<u8>)>,
) -> lf_eval::Value {
    use lf_eval::Value as V;
    match val {
        V::ContractId(id) => V::ContractId(
            map.get(id)
                .map_or_else(|| id.clone(), |(real, _)| real.clone()),
        ),
        V::List(items) => V::List(lf_eval::List::from(
            items
                .iter()
                .map(|v| rewrite_value_contract_ids(v, map))
                .collect::<Vec<_>>(),
        )),
        V::Optional(opt) => V::Optional(
            opt.as_ref()
                .map(|v| Box::new(rewrite_value_contract_ids(v, map))),
        ),
        V::Record { tycon, fields } => V::Record {
            tycon: tycon.clone(),
            fields: fields
                .iter()
                .map(|(k, v)| (k.clone(), rewrite_value_contract_ids(v, map)))
                .collect(),
        },
        V::Variant {
            tycon,
            constructor,
            rank,
            value,
        } => V::Variant {
            tycon: tycon.clone(),
            constructor: constructor.clone(),
            rank: *rank,
            value: Box::new(rewrite_value_contract_ids(value, map)),
        },
        V::Struct(fields) => V::Struct(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), rewrite_value_contract_ids(v, map)))
                .collect(),
        ),
        V::Map(entries) => V::Map(
            entries
                .iter()
                .map(|(k, v)| {
                    (
                        rewrite_value_contract_ids(k, map),
                        rewrite_value_contract_ids(v, map),
                    )
                })
                .collect(),
        ),
        V::Any { key, payload } => V::Any {
            key: key.clone(),
            payload: Box::new(rewrite_value_contract_ids(payload, map)),
        },
        V::AnyException { tycon, payload } => V::AnyException {
            tycon: tycon.clone(),
            payload: Box::new(rewrite_value_contract_ids(payload, map)),
        },
        V::Iface {
            package_id,
            template,
            payload,
        } => V::Iface {
            package_id: package_id.clone(),
            template: template.clone(),
            payload: Box::new(rewrite_value_contract_ids(payload, map)),
        },
        other => other.clone(),
    }
}

/// Like [`check_exercise_view_with_topology`], also returning replayed pre-order [`crate::view_acs::RemoteEvent`]s for remote `LEDGER_EFFECTS` publication.
pub(crate) fn check_exercise_view_with_events(
    engine: &Engine,
    view: &RevealedView,
    subviews: &[&RevealedView],
    common_metadata: &CommonMetadata,
    root_admin: Option<&str>,
    hosts_of: Option<&HostsOf<'_>>,
) -> Result<
    (
        ConformingExercise,
        Vec<Vec<usize>>,
        CoreInformees,
        Vec<crate::view_acs::RemoteEvent>,
    ),
    Nonconformance,
> {
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    use lf_eval::engine::Contract;
    let malformed = |what: &str| Nonconformance::Malformed(what.to_string());
    let Some(Description::Exercise(exercise)) = view
        .participant_data
        .action_description
        .as_ref()
        .and_then(|a| a.description.clone())
    else {
        return Err(malformed("the view's action is not an exercise"));
    };
    if exercise.failed {
        return Err(Nonconformance::Unsupported("a failed exercise".into()));
    }
    let input = view
        .participant_data
        .core_inputs
        .iter()
        .find(|i| {
            unversioned_fat(&i.contract)
                .ok()
                .and_then(|(d, _)| FatContractInstance::decode(d.as_slice()).ok())
                .is_some_and(|f| hex::encode(&f.contract_id) == exercise.input_contract_id)
        })
        .ok_or_else(|| {
            malformed("the exercised contract is not among the view's input contracts")
        })?;
    let mut data_inputs: Vec<_> = view.participant_data.core_inputs.clone();
    for sv in subviews {
        data_inputs.extend(sv.participant_data.core_inputs.iter().cloned());
    }
    let replayed = replay_contract(engine, &input.contract)?;
    authenticate_stored(&replayed)?;
    // the action: the template of the contract (possibly upgraded/downgraded under the same package name), the choice, its argument, its controllers
    let (exec_pkg, exec_local) = exercise
        .template_id
        .split_once(':')
        .ok_or_else(|| malformed("exercise template_id lacks package"))?;
    if exec_local != replayed.template_id {
        return Err(Nonconformance::ActionDiffers(format!(
            "the exercise names the template {} but the input contract is a {}:{}",
            exercise.template_id, replayed.package_id, replayed.template_id
        )));
    }
    let types = lf_eval::typed_json::Types::new(&engine.world);
    let (package, exec_arg) = if exec_pkg == replayed.package_id {
        (replayed.package_id.clone(), replayed.arg.clone())
    } else {
        if !engine.world.has_package(exec_pkg) {
            return Err(Nonconformance::UnknownPackage(exec_pkg.to_string()));
        }
        let orig_name = types
            .package_name(&replayed.package_id)
            .map_err(|_| Nonconformance::UnknownPackage(replayed.package_id.clone()))?;
        let target_name = types
            .package_name(exec_pkg)
            .map_err(|_| Nonconformance::UnknownPackage(exec_pkg.to_string()))?;
        if orig_name != target_name {
            return Err(Nonconformance::ActionDiffers(format!(
                "upgrade package mismatch: {orig_name} vs {target_name}"
            )));
        }
        let exec_ty = types
            .template(exec_pkg, exec_local)
            .map_err(Nonconformance::ArgumentsDoNotDecode)?;
        let target_fields = types
            .record_fields(&exec_ty)
            .map_err(Nonconformance::ArgumentsDoNotDecode)?;
        if let lf_eval::Value::Record {
            fields: orig_fields,
            ..
        } = &replayed.arg
        {
            for (name, ft) in &target_fields {
                if !orig_fields.iter().any(|(oname, _)| oname == name)
                    && !matches!(ft, lf_eval::typed_json::LfType::Optional(_))
                {
                    return Err(Nonconformance::ActionDiffers(format!(
                        "upgraded template {exec_pkg}:{exec_local} adds non-optional field {name}"
                    )));
                }
            }
            for (oname, oval) in orig_fields {
                if !target_fields.iter().any(|(name, _)| name == oname)
                    && !matches!(oval, lf_eval::Value::Optional(None))
                {
                    return Err(Nonconformance::ActionDiffers(format!(
                        "downgraded template {exec_pkg}:{exec_local} drops populated field {oname}"
                    )));
                }
            }
        }
        let exec_arg = types
            .from_wire(&exec_ty, &replayed.fci.create_arg)
            .map_err(Nonconformance::ArgumentsDoNotDecode)?;
        match engine.world.eval_template_precond_in(
            exec_pkg,
            &replayed.module,
            &replayed.name,
            &exec_arg,
        ) {
            Ok(true) => {}
            Ok(false) => return Err(Nonconformance::EnsureFalse),
            Err(e) if e.to_string().contains("PreconditionFailed") => {
                return Err(Nonconformance::EnsureFalse)
            }
            Err(e) => return Err(Nonconformance::EngineError(e.to_string())),
        }
        let target_sigs: BTreeSet<String> = engine
            .world
            .eval_template_signatories_in(exec_pkg, &replayed.module, &replayed.name, &exec_arg)
            .map_err(|e| Nonconformance::EngineError(e.to_string()))?
            .into_iter()
            .collect();
        let target_obs: BTreeSet<String> = engine
            .world
            .eval_template_observers_in(exec_pkg, &replayed.module, &replayed.name, &exec_arg)
            .map_err(|e| Nonconformance::EngineError(e.to_string()))?
            .into_iter()
            .collect();
        let target_stakeholders: BTreeSet<String> =
            target_sigs.union(&target_obs).cloned().collect();
        if target_sigs != replayed.signatories || target_stakeholders != replayed.stakeholders {
            return Err(Nonconformance::ActionDiffers(
                "upgraded template metadata differs from stored contract".into(),
            ));
        }
        (exec_pkg.to_string(), exec_arg)
    };
    let versioned_value = Versioned::decode(exercise.chosen_value.as_slice())
        .map_err(|e| Nonconformance::ArgumentsDoNotDecode(e.to_string()))?;
    let (choice_arg, controllers, consuming): (lf_eval::Value, BTreeSet<String>, bool) =
        match exercise.interface_id.as_deref() {
            Some(iface_full) => {
                let (iface_pkg, iface_local) = iface_full
                    .split_once(':')
                    .ok_or_else(|| malformed("an interface id without a package"))?;
                if !engine.world.has_package(iface_pkg) {
                    return Err(Nonconformance::UnknownPackage(iface_pkg.to_string()));
                }
                if !engine
                    .world
                    .template_implements(&package, &replayed.template_id, iface_pkg, iface_local)
                    .map_err(|e| Nonconformance::EngineError(e.to_string()))?
                {
                    return Err(Nonconformance::ActionDiffers(format!(
                        "{} does not implement {iface_full}",
                        replayed.template_id
                    )));
                }
                let choice_types = types
                    .interface_choice(iface_pkg, iface_local, &exercise.choice)
                    .map_err(Nonconformance::ArgumentsDoNotDecode)?;
                let choice_arg = types
                    .from_wire(&choice_types.argument, &versioned_value.payload)
                    .map_err(Nonconformance::ArgumentsDoNotDecode)?;
                let iface_val = lf_eval::Value::Iface {
                    package_id: package.clone(),
                    template: replayed.template_id.clone(),
                    payload: Box::new(exec_arg.clone()),
                };
                let controllers = engine
                    .world
                    .eval_interface_choice_controllers_in(
                        iface_pkg,
                        iface_local,
                        &exercise.choice,
                        &iface_val,
                        &choice_arg,
                    )
                    .map_err(|e| Nonconformance::EngineError(e.to_string()))?
                    .into_iter()
                    .collect();
                let consuming = engine
                    .world
                    .interface_choice_is_consuming(iface_pkg, iface_local, &exercise.choice)
                    .map_err(|e| Nonconformance::EngineError(e.to_string()))?;
                (choice_arg, controllers, consuming)
            }
            None => {
                if !engine
                    .world
                    .choice_exists(&package, &replayed.module, &replayed.name, &exercise.choice)
                    .map_err(|e| Nonconformance::EngineError(e.to_string()))?
                {
                    return Err(Nonconformance::UnknownChoice(exercise.choice.clone()));
                }
                let choice_types = types
                    .choice(&package, &replayed.template_id, &exercise.choice)
                    .map_err(Nonconformance::ArgumentsDoNotDecode)?;
                let choice_arg = types
                    .from_wire(&choice_types.argument, &versioned_value.payload)
                    .map_err(Nonconformance::ArgumentsDoNotDecode)?;
                let controllers = engine
                    .world
                    .eval_choice_controllers_in(
                        &package,
                        &replayed.module,
                        &replayed.name,
                        &exercise.choice,
                        &exec_arg,
                        &choice_arg,
                    )
                    .map_err(|e| Nonconformance::EngineError(e.to_string()))?
                    .into_iter()
                    .collect();
                let consuming = engine
                    .world
                    .choice_is_consuming(
                        &package,
                        &replayed.module,
                        &replayed.name,
                        &exercise.choice,
                    )
                    .map_err(|e| Nonconformance::EngineError(e.to_string()))?;
                (choice_arg, controllers, consuming)
            }
        };
    let actors: BTreeSet<String> = exercise.actors.iter().cloned().collect();
    if controllers != actors {
        return Err(Nonconformance::ActorsDiffer {
            computed: controllers.into_iter().collect(),
            stated: actors.into_iter().collect(),
        });
    }
    // [CANTON-NOTE: SEMANTICS] Source `Node.scala`, `Exercise.informeesOfNode`: a **consuming** exercise informs every stakeholder of the contract, a
    // non-consuming one only its signatories (and the actors and choice observers).
    let informees: BTreeSet<&String> = view.common_data.informees.iter().collect();
    let must_inform = if consuming {
        &replayed.stakeholders
    } else {
        &replayed.signatories
    };
    if !must_inform.iter().all(|s| informees.contains(s)) {
        return Err(Nonconformance::ActionDiffers(
            "an informee of the view is missing: the contract's signatories (all stakeholders when the choice consumes) must be informees".into(),
        ));
    }
    // the replay: an engine that holds the contract exercises the choice
    let mut replay = lf_eval::engine::Engine::new(&engine.world);
    replay.set_time_micros(engine.ledger_time.get());
    replay
        .import_contract(Contract {
            contract_id: exercise.input_contract_id.clone(),
            package_id: package,
            template_id: replayed.template_id.clone(),
            payload: exec_arg,
            signatories: replayed.signatories.iter().cloned().collect(),
            observers: replayed
                .stakeholders
                .difference(&replayed.signatories)
                .cloned()
                .collect(),
            active: true,
            key: replayed.key.as_ref().map(|(k, _)| k.clone()),
        })
        .map_err(|e| Nonconformance::EngineError(e.to_string()))?;
    // A view carrying an authentic input contract may exercise it via explicit disclosure even when no actor is a stakeholder.
    replay.disclose(&exercise.input_contract_id);
    // [CANTON-NOTE: SEMANTICS] The other input contracts of the view's core are the ones the choice **fetches**: the replay has to
    // hold them too, each authentic like the exercised one (a contract the choice reads but the view does not list is a view that
    // does not describe what the engine does).
    let mut input_ids = vec![exercise.input_contract_id.clone()];
    let engine_key = |r: &Replayed| {
        r.key.as_ref().map(|(key, maintainers)| EngineKey {
            template_id: r.template_id.clone(),
            key: key.clone(),
            maintainers: maintainers.iter().cloned().collect(),
        })
    };
    let mut allowed_keys: Vec<EngineKey> = engine_key(&replayed).into_iter().collect();
    let active_subviews: Vec<&RevealedView> = subviews
        .iter()
        .copied()
        .filter(|sv| !sv.participant_data.rolled_back || view.participant_data.rolled_back)
        .collect();
    // [CANTON-NOTE: SEMANTICS] Contracts created by an earlier subview and consumed or fetched by a
    // sibling/ancestor view (`core_inputs` of a later subview) are created during `replay` itself;
    // pre-importing them into the root replay engine would duplicate them as pre-existing inputs and
    // break `created_core` matching.
    let mut created_in_subtree: BTreeSet<String> = BTreeSet::new();
    for c in view.participant_data.created_core.iter().chain(
        active_subviews
            .iter()
            .flat_map(|sv| &sv.participant_data.created_core),
    ) {
        if let Ok((d, _)) = unversioned_fat(&c.contract) {
            if let Ok(f) = FatContractInstance::decode(d.as_slice()) {
                created_in_subtree.insert(hex::encode(&f.contract_id));
            }
        }
    }
    let mut known_inputs: std::collections::BTreeMap<String, Vec<u8>> =
        std::collections::BTreeMap::new();
    known_inputs.insert(exercise.input_contract_id.clone(), input.contract.clone());
    for other in &data_inputs {
        let fetched = replay_contract(engine, &other.contract)?;
        authenticate_stored(&fetched)?;
        allowed_keys.extend(engine_key(&fetched));
        let id = hex::encode(&fetched.fci.contract_id);
        known_inputs
            .entry(id.clone())
            .or_insert_with(|| other.contract.clone());
        if created_in_subtree.contains(&id) || input_ids.contains(&id) {
            continue;
        }
        replay
            .import_contract(Contract {
                contract_id: id.clone(),
                package_id: fetched.package_id.clone(),
                template_id: fetched.template_id.clone(),
                payload: fetched.arg.clone(),
                signatories: fetched.signatories.iter().cloned().collect(),
                observers: fetched
                    .stakeholders
                    .difference(&fetched.signatories)
                    .cloned()
                    .collect(),
                active: true,
                key: fetched.key.as_ref().map(|(k, _)| k.clone()),
            })
            .map_err(|e| Nonconformance::EngineError(e.to_string()))?;
        // a contract in the view's inputs is one the confirmers may use whoever acts (the official engine fetched it: it is divulged to them)
        replay.disclose(&id);
        input_ids.push(id);
    }
    // [CANTON-NOTE: SEMANTICS] Key queries are answered from the key resolutions the view (and its revealed subviews) state, in their
    // order, not from what the replay happens to hold: `ModelConformanceChecker` reinterprets with the view's resolved keys (U-21).
    replay.resolve_keys_from_view(super::view_key_resolutions(
        view.participant_data.resolved_keys.iter().chain(
            active_subviews
                .iter()
                .flat_map(|sv| &sv.participant_data.resolved_keys),
        ),
    ));
    let actor_refs: Vec<&str> = exercise.actors.iter().map(String::as_str).collect();
    let replay_res = match exercise.interface_id.as_deref() {
        Some(iface_full) => {
            let (iface_pkg, iface_local) = iface_full
                .split_once(':')
                .ok_or_else(|| malformed("an interface id without a package"))?;
            replay.exercise_interface_as(
                &actor_refs,
                iface_pkg,
                iface_local,
                &exercise.input_contract_id,
                &exercise.choice,
                &choice_arg,
            )
        }
        None => replay.exercise_as(
            &actor_refs,
            &exercise.input_contract_id,
            &exercise.choice,
            &choice_arg,
        ),
    };
    replay_res.map_err(|e| {
        // name what the view does list: a contract the replay needs that is not among them is one the official engine did not fetch
        let listed: Vec<String> = input_ids
            .iter()
            .map(|i| i.chars().take(10).collect())
            .collect();
        Nonconformance::EngineError(format!(
            "{e} (the exercise of {} on {}; the view's inputs: {listed:?})",
            exercise.choice,
            exercise
                .input_contract_id
                .chars()
                .take(10)
                .collect::<String>()
        ))
    })?;
    // [CANTON-NOTE: SEMANTICS] Canton sets `InputContract.consumed = consumedInCore.contains(cid)` across all
    // non-rolled-back core nodes (`NextGenTransactionTreeFactory.createViewParticipantData`), so a nonconsuming root
    // choice that archives its input in a child (e.g. CIP-0112 TransferInstruction_Accept) carries `input.consumed = true`.
    let replayed_consumed_input = consuming
        || replay.events().iter().any(|ev| {
            matches!(
                ev,
                lf_eval::EngineEvent::Exercise {
                    contract_id,
                    consuming: true,
                    ..
                } if contract_id == &exercise.input_contract_id
            )
        });
    let subview_consumed_input = active_subviews.iter().any(|sv| {
        sv.participant_data.core_inputs.iter().any(|i| {
            i.consumed
                && unversioned_fat(&i.contract)
                    .ok()
                    .and_then(|(d, _)| FatContractInstance::decode(d.as_slice()).ok())
                    .is_some_and(|f| hex::encode(&f.contract_id) == exercise.input_contract_id)
        })
    });
    let view_consumed_input = input.consumed || subview_consumed_input;
    if (consuming && !input.consumed) || replayed_consumed_input != view_consumed_input {
        return Err(Nonconformance::ActionDiffers(format!(
            "the choice {} consuming the input, the view says the input is {}consumed",
            if replayed_consumed_input {
                "is"
            } else {
                "is not"
            },
            if view_consumed_input { "" } else { "not " }
        )));
    }
    // effects: the contracts the replay creates must be the contracts the view lists in its core, each authentic (its id derived
    // from this view) and each equal to what the engine made (template, arguments, signatories, observers)
    let vpd_salt = view
        .participant_data
        .salt
        .as_ref()
        .map(|s| s.salt.clone())
        .unwrap_or_default();
    let (_, event_paths) = replay.node_paths();
    let mut made: Vec<(Contract, Vec<usize>)> = replay
        .events()
        .iter()
        .zip(event_paths)
        .filter_map(|(event, path)| match event {
            // [CANTON-NOTE: SEMANTICS] Every create of the view's core is listed in `createdCore`, also one that the same view consumes
            // again (`consumedInCore`, NextGenTransactionTreeFactory.createViewParticipantData): a contract the replay archived after
            // creating it still counts. Measured (S-SPL-036): counting only the active ones, the Rust participant rejected two requests of
            // the split tap transactions p1 submitted ("the engine creates 2 contract(s), the view lists 3") that p1 approved; counting all,
            // it rejects none. Rolled-back creates are not in `events()`.
            lf_eval::EngineEvent::Create { contract_id, .. } => replay
                .contract(contract_id)
                .filter(|c| !input_ids.contains(&c.contract_id))
                .map(|c| (c.clone(), path)),
            _ => None,
        })
        .collect();
    let mut created_entries: Vec<(&[u8], usize, bool)> = view
        .participant_data
        .created_core
        .iter()
        .enumerate()
        .map(|(idx, c)| (c.contract.as_slice(), idx, true))
        .collect();
    for sv in &active_subviews {
        for (idx, c) in sv.participant_data.created_core.iter().enumerate() {
            created_entries.push((c.contract.as_slice(), idx, false));
        }
    }
    let mut created_map: std::collections::BTreeMap<String, (String, Vec<u8>)> =
        std::collections::BTreeMap::new();
    if made.len() != created_entries.len() {
        return Err(Nonconformance::ActionDiffers(format!(
            "the engine creates {} contract(s), the view lists {}",
            made.len(),
            created_entries.len()
        )));
    }
    let mut created_keys: Vec<EngineKey> = Vec::new();
    let mut pending = Vec::with_capacity(created_entries.len());
    for (contract_bytes, index, is_root) in created_entries {
        let listed = replay_contract(engine, contract_bytes)?;
        let real_cid = hex::encode(&listed.fci.contract_id);
        created_keys.extend(engine_key(&listed));
        if is_root {
            authenticate_created(&listed, &vpd_salt, index, view, common_metadata)?;
        }
        pending.push((contract_bytes, index, is_root, listed, real_cid));
    }
    // [CANTON-NOTE: WHY] Engine replay leaves temporary placeholder IDs (`#...`)
    // in later contracts' payloads when they reference contracts created earlier
    // in the same execution, whereas revealed views (and subviews) carry finalized
    // contract IDs. Match in fixed-point passes so resolved contracts populate
    // `created_map` for dependent siblings/subviews regardless of view ordering.
    let mut root_positions: Vec<(usize, Vec<usize>)> = Vec::new();
    while !pending.is_empty() {
        let mut next_pending = Vec::new();
        let mut matched_any = false;
        for (contract_bytes, index, is_root, listed, real_cid) in pending {
            let position = made.iter().position(|(m, _)| {
                m.template_id == listed.template_id
                    && rewrite_value_contract_ids(&m.payload, &created_map) == listed.arg
                    && m.signatories.iter().cloned().collect::<BTreeSet<_>>() == listed.signatories
            });
            if let Some(pos) = position {
                let (matched_contract, removed_path) = made.remove(pos);
                created_map.insert(
                    matched_contract.contract_id,
                    (real_cid, contract_bytes.to_vec()),
                );
                if is_root {
                    root_positions.push((index, removed_path));
                }
                matched_any = true;
            } else {
                next_pending.push((contract_bytes, index, is_root, listed, real_cid));
            }
        }
        if !matched_any {
            if let Some((_, _, _, listed, _)) = next_pending.into_iter().next() {
                // name what differs from the nearest contract the engine made: the first field whose value is not the same
                let nearest = made
                    .iter()
                    .find(|(m, _)| m.template_id == listed.template_id);
                let detail = nearest
                    .map(|(m, _)| {
                        let rewritten = rewrite_value_contract_ids(&m.payload, &created_map);
                        match (&rewritten, &listed.arg) {
                            (Value::Record { fields: a, .. }, Value::Record { fields: b, .. }) => a
                                .iter()
                                .zip(b.iter())
                                .find(|(x, y)| x != y)
                                .map(|(x, y)| {
                                    format!(
                                        "; field {} the engine has {:?}, the view {:?}",
                                        x.0, x.1, y.1
                                    )
                                    .chars()
                                    .take(500)
                                    .collect::<String>()
                                })
                                .unwrap_or_else(|| "; the signatories differ".to_string()),
                            _ => String::new(),
                        }
                    })
                    .unwrap_or_default();
                return Err(Nonconformance::ActionDiffers(format!(
                    "the view lists a {} the engine did not create{detail}",
                    listed.template_id
                )));
            }
            break;
        }
        pending = next_pending;
    }
    root_positions.sort_by_key(|(index, _)| *index);
    let positions: Vec<Vec<usize>> = root_positions.into_iter().map(|(_, path)| path).collect();
    let mut merged_resolved = view.participant_data.resolved_keys.clone();
    let mut seen_key_hashes: BTreeSet<Vec<u8>> = merged_resolved
        .iter()
        .filter_map(|r| r.key.as_ref().map(|k| k.hash.clone()))
        .collect();
    for sv in subviews {
        for r in &sv.participant_data.resolved_keys {
            let is_new = r
                .key
                .as_ref()
                .is_none_or(|k| seen_key_hashes.insert(k.hash.clone()));
            if is_new {
                merged_resolved.push(r.clone());
            }
        }
    }
    let exhaustive_keys = check_resolved_keys_collecting(
        engine,
        &merged_resolved,
        replay.key_lookups(),
        &created_keys,
        &allowed_keys,
    )?;
    let informees = replayed_core_informees(
        &replay,
        &InformeeContext {
            has_subviews: view.has_subviews,
            root_admin,
            hosts_of,
            resolved_keys: &merged_resolved,
        },
    );
    let remote_events = if view.participant_data.rolled_back {
        Vec::new()
    } else {
        replay
            .events()
            .iter()
            .filter_map(|ev| match ev {
                lf_eval::EngineEvent::Fetch {
                    contract_id,
                    depth,
                    authorizers,
                    interface_id,
                } => {
                    let real_cid = created_map
                        .get(contract_id)
                        .map(|(cid, _)| cid.clone())
                        .unwrap_or_else(|| contract_id.clone());
                    let input_instance = known_inputs
                        .get(&real_cid)
                        .cloned()
                        .or_else(|| created_map.get(contract_id).map(|(_, bytes)| bytes.clone()))
                        .unwrap_or_default();
                    Some(crate::view_acs::RemoteEvent::Fetch {
                        depth: *depth,
                        contract_id: real_cid,
                        input_instance,
                        actors: authorizers.clone(),
                        interface_id: interface_id.clone(),
                    })
                }
                lf_eval::EngineEvent::Create {
                    contract_id, depth, ..
                } => created_map.get(contract_id).map(|(real_cid, instance)| {
                    crate::view_acs::RemoteEvent::Create {
                        depth: *depth,
                        contract_id: real_cid.clone(),
                        instance: instance.clone(),
                    }
                }),
                lf_eval::EngineEvent::Exercise {
                    contract_id,
                    choice,
                    consuming,
                    actors,
                    depth,
                    argument,
                    result,
                    interface_id,
                    observers,
                } => {
                    let real_cid = created_map
                        .get(contract_id)
                        .map(|(cid, _)| cid.clone())
                        .unwrap_or_else(|| contract_id.clone());
                    let input_instance = known_inputs
                        .get(&real_cid)
                        .cloned()
                        .or_else(|| created_map.get(contract_id).map(|(_, bytes)| bytes.clone()))
                        .unwrap_or_default();
                    Some(crate::view_acs::RemoteEvent::Exercise(Box::new(
                        crate::view_acs::RemoteExercise {
                            depth: *depth,
                            contract_id: real_cid,
                            input_instance,
                            choice: choice.clone(),
                            consuming: *consuming,
                            actors: actors.clone(),
                            observers: observers.clone(),
                            interface_id: interface_id.clone(),
                            argument: rewrite_value_contract_ids(argument, &created_map),
                            result: result
                                .as_ref()
                                .map(|r| rewrite_value_contract_ids(r, &created_map)),
                        },
                    )))
                }
            })
            .collect()
    };
    let party_packages = crate::view_vetting::replayed_party_packages(&replay)?;
    Ok((
        ConformingExercise {
            contract_id: exercise.input_contract_id,
            template: replayed.template_id,
            choice: exercise.choice,
            consuming,
            party_packages,
            exhaustive_keys,
        },
        positions,
        informees,
        remote_events,
    ))
}

/// Checks a view whose root action **fetches** a contract (G8, U-33).
///
/// [CANTON-NOTE: SEMANTICS] A fetch view carries the fetched contract as its one core input (not consumed) and creates nothing. Checked: the
/// input is authentic (its id is the unicum of its stored salt, as for an exercise's input), the action names its template, no key or
/// interface is involved, and at least one actor is a stakeholder of the contract (the authorization of a fetch).
///
/// [CANTON-NOTE: SEMANTICS] `SerializableContractAuthenticator`: every input contract's id is recomputed from its instance and its stored
/// salt; the engine also has to reproduce the instance (its metadata from its arguments).
///
/// [CANTON-NOTE: LIMITATION] The quorums of a fetch view are not checked: what a fetch view's confirmers are was not measured.
pub fn check_fetch_view(
    engine: &Engine,
    view: &RevealedView,
) -> Result<Conforming, Nonconformance> {
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    let Some(Description::Fetch(fetch)) = view
        .participant_data
        .action_description
        .as_ref()
        .and_then(|a| a.description.clone())
    else {
        return Err(Nonconformance::Malformed(
            "the view's action is not a fetch".into(),
        ));
    };
    if !view.participant_data.created_core.is_empty()
        || view.participant_data.core_inputs.iter().any(|i| i.consumed)
    {
        return Err(Nonconformance::ActionDiffers(
            "a fetch view creates or consumes a contract".into(),
        ));
    }
    let input = view
        .participant_data
        .core_inputs
        .iter()
        .find(|i| {
            unversioned_fat(&i.contract)
                .ok()
                .and_then(|(d, _)| FatContractInstance::decode(d.as_slice()).ok())
                .is_some_and(|f| hex::encode(&f.contract_id) == fetch.input_contract_id)
        })
        .ok_or_else(|| {
            Nonconformance::Malformed("the fetched contract is not among the view's inputs".into())
        })?;
    let replayed = replay_contract(engine, &input.contract)?;
    authenticate_stored(&replayed)?;
    let fci = replayed.fci;
    let package = fci
        .template_id
        .as_ref()
        .map(|t| t.package_id.clone())
        .unwrap_or_default();
    let stated_template = fetch.template_id.clone();
    if !stated_template.starts_with(&format!("{package}:")) {
        return Err(Nonconformance::ActionDiffers(format!(
            "the fetch names the template {stated_template} but the contract is of package {package}"
        )));
    }
    if !fetch
        .actors
        .iter()
        .any(|a| stated_stakeholders(&fci).contains(a))
    {
        return Err(Nonconformance::ActionDiffers(
            "no actor of the fetch is a stakeholder of the contract".into(),
        ));
    }
    Ok(Conforming {
        contract_id: fetch.input_contract_id,
        template: stated_template,
    })
}

/// Checks that the id of a contract that was created *elsewhere* (an input contract of a view, or an imported one) is the unicum of
/// its **stored** contract salt (from its authentication data), its creation time, its metadata and the LF hash of its arguments.
/// Unlike a contract created in the view at hand, its salt is not re-derived: it was fixed when the contract was created.
pub(super) fn authenticate_stored(replayed: &Replayed) -> Result<(), Nonconformance> {
    let malformed = |what: &str| Nonconformance::Malformed(what.to_string());
    let (auth_data, _) = unversioned(&replayed.fci.authentication_data)
        .ok_or_else(|| malformed("unversioned authentication data"))?;
    let salt = ContractAuthenticationData::decode(auth_data.as_slice())
        .ok()
        .and_then(|a| a.contract_salt)
        .map(|s| s.salt)
        .ok_or_else(|| malformed("authentication data without a salt"))?;
    let salt: [u8; 32] = salt
        .try_into()
        .map_err(|_| malformed("a contract salt of the wrong size"))?;
    let hash = lf_contract_hash(
        &replayed.fci.package_name,
        &segments(&replayed.module),
        &segments(&replayed.name),
        &replayed.hash_arg,
    );
    let signatories: Vec<String> = replayed.signatories.iter().cloned().collect();
    let stakeholders: Vec<String> = replayed.stakeholders.iter().cloned().collect();
    let id = &replayed.fci.contract_id;
    let stated_key = stated_key(&replayed.fci)?;
    let derived = unicum(
        &salt,
        &UnicumInputs {
            created_at_micros: replayed.fci.created_at,
            signatories: &signatories,
            stakeholders: &stakeholders,
            key: stated_key.as_ref().map(|(h, m)| KeyInputs {
                hash: h,
                maintainers: m,
            }),
            contract_hash: &hash,
        },
    );
    if id.len() < 33 || id[33..] != contract_id_suffix(&derived)[..] {
        return Err(Nonconformance::ContractIdDiffers);
    }
    Ok(())
}
