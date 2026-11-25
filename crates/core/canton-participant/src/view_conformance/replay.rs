//! Replay of a created contract's create node from its stated instance.

use std::collections::BTreeSet;

use canton_proto::com::digitalasset::daml::lf::transaction::FatContractInstance;
use lf_eval::Value;
use prost::Message;

use crate::contract_id::{lf_contract_key_hash, HashValue};

use super::{
    hash_value, segments, stated_signatories, stated_stakeholders, unversioned_fat, Engine,
    Nonconformance,
};

/// A contract instance whose template, arguments, `ensure`, signatories and stakeholders the engine has replayed.
pub(super) struct Replayed {
    pub(super) fci: FatContractInstance,
    /// The arguments in the typed form the contract hash takes.
    pub(super) hash_arg: HashValue,
    /// The package of the template: a transaction may use several packages of the DAR (Splice's do).
    pub(super) package_id: String,
    pub(super) module: String,
    pub(super) name: String,
    pub(super) template_id: String,
    pub(super) arg: Value,
    pub(super) signatories: BTreeSet<String>,
    pub(super) stakeholders: BTreeSet<String>,
    /// The key the engine derives from the arguments (with its maintainers), if the template has one.
    pub(super) key: Option<(Value, Vec<String>)>,
}

/// Decodes a contract instance and has the engine reproduce what it states: the template (in `validation_package_id` if given, else the
/// contract's creation package), the arguments, the `ensure` clause, and the signatories and stakeholders from the arguments.
///
/// `[CANTON-NOTE: SEMANTICS]` `ReassignmentValidation.scala` (`authenticateContractsAgainstSource/Target`) validates contract instances
/// against the request's explicit validation package id rather than only the contract's creation template package.
pub(super) fn replay_contract(
    engine: &Engine,
    contract_bytes: &[u8],
) -> Result<Replayed, Nonconformance> {
    replay_contract_in(engine, contract_bytes, None)
}

pub(super) fn replay_contract_in(
    engine: &Engine,
    contract_bytes: &[u8],
    validation_package_id: Option<&str>,
) -> Result<Replayed, Nonconformance> {
    let (data, _) = unversioned_fat(contract_bytes)?;
    let fci = FatContractInstance::decode(data.as_slice())
        .map_err(|e| Nonconformance::Malformed(e.to_string()))?;
    let template = fci
        .template_id
        .as_ref()
        .ok_or_else(|| Nonconformance::Malformed("a contract without a template".into()))?;
    let eval_pkg = validation_package_id
        .filter(|p| !p.is_empty())
        .unwrap_or(&template.package_id);
    let types = lf_eval::typed_json::Types::new(&engine.world);
    if !types.knows_package(eval_pkg) {
        return Err(Nonconformance::UnknownPackage(eval_pkg.to_string()));
    }
    let package_id = eval_pkg.to_string();
    let (module, name) = (template.module_name.join("."), template.name.join("."));
    let template_id = format!("{module}:{name}");
    let template_type = types
        .template(eval_pkg, &template_id)
        .map_err(|_| Nonconformance::UnknownTemplate(template_id.clone()))?;
    let arg = types
        .from_wire(&template_type, &fci.create_arg)
        .map_err(Nonconformance::ArgumentsDoNotDecode)?;
    let hash_arg = crate::value_forms::hash_form(&types, &template_type, &arg)
        .map_err(Nonconformance::EngineError)?;
    // the engine's replay: the `ensure` clause, then the signatories and the observers
    match engine
        .world
        .eval_template_precond_in(eval_pkg, &module, &name, &arg)
    {
        Ok(true) => {}
        Ok(false) => return Err(Nonconformance::EnsureFalse),
        // [CANTON-NOTE: SEMANTICS] damlc compiles `ensure` so that a false precondition *throws* `PreconditionFailed` rather than
        // returning `False`; that exception is the engine's way to say the `ensure` clause does not hold.
        Err(e) if e.to_string().contains("PreconditionFailed") => {
            return Err(Nonconformance::EnsureFalse)
        }
        Err(e) => return Err(Nonconformance::EngineError(e.to_string())),
    }
    let eval = |r: Result<Vec<String>, lf_eval::EvalError>| {
        r.map(|v| v.into_iter().collect::<BTreeSet<_>>())
            .map_err(|e| Nonconformance::EngineError(e.to_string()))
    };
    let signatories = eval(
        engine
            .world
            .eval_template_signatories_in(eval_pkg, &module, &name, &arg),
    )?;
    let observers = eval(
        engine
            .world
            .eval_template_observers_in(eval_pkg, &module, &name, &arg),
    )?;
    let stated_signatories = stated_signatories(&fci);
    if signatories != stated_signatories {
        return Err(Nonconformance::SignatoriesDiffer {
            computed: signatories.into_iter().collect(),
            stated: stated_signatories.into_iter().collect(),
        });
    }
    let stated_stakeholders = stated_stakeholders(&fci);
    let computed_stakeholders: BTreeSet<String> = signatories.union(&observers).cloned().collect();
    if computed_stakeholders != stated_stakeholders {
        return Err(Nonconformance::StakeholdersDiffer {
            computed: computed_stakeholders.into_iter().collect(),
            stated: stated_stakeholders.into_iter().collect(),
        });
    }
    // the key: a template with a key states one (with its maintainers), a template without does not
    let computed_key = engine
        .world
        .eval_template_key_in(eval_pkg, &module, &name, &arg)
        .map_err(|e| Nonconformance::EngineError(e.to_string()))?;
    match (&computed_key, &fci.contract_key_with_maintainers) {
        (None, None) => {}
        (Some((key, computed)), Some(stated)) => {
            let computed: BTreeSet<&String> = computed.iter().collect();
            let stated_maintainers: BTreeSet<&String> = stated.maintainers.iter().collect();
            if computed != stated_maintainers {
                return Err(Nonconformance::KeyDiffers(format!(
                    "the maintainers are {stated_maintainers:?}, the template gives {computed:?}"
                )));
            }
            // the stated key hash is the hash of the key the engine derives from the arguments
            let recomputed = lf_contract_key_hash(
                &fci.package_name,
                &segments(&module),
                &segments(&name),
                &hash_value(key)?,
            );
            if stated.hash != recomputed {
                return Err(Nonconformance::KeyDiffers(
                    "the contract states a key hash that is not the hash of its key".into(),
                ));
            }
        }
        (Some(_), None) => {
            return Err(Nonconformance::KeyDiffers(
                "the template has a key and the contract states none".into(),
            ))
        }
        (None, Some(_)) => {
            return Err(Nonconformance::KeyDiffers(
                "the contract states a key and the template has none".into(),
            ))
        }
    }
    Ok(Replayed {
        fci,
        hash_arg,
        package_id,
        module,
        name,
        template_id,
        arg,
        signatories: stated_signatories,
        stakeholders: stated_stakeholders,
        key: computed_key,
    })
}
