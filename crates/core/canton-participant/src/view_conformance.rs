//! The model conformance a receiving participant runs on a created contract (G5 5.6h, S-NET-016): it replays the `create` in
//! its own engine (`lf-eval`) instead of trusting the sender.
//!
//! [CANTON-NOTE: SEMANTICS] For a view whose core creates a contract, the receiving participant has to be convinced that the
//! contract is one the template *really* produces:
//! - the **template exists** in a package it has (the id names a package of the DAR it loaded) and the arguments decode against
//!   the template's record type;
//! - the **`ensure` clause** holds for the arguments;
//! - the **signatories and observers** the template computes from the arguments are exactly the ones the contract states (the
//!   stakeholders are the signatories and the observers);
//! - the **contract id** is the one derived from the contract (`UnicumGenerator`: the contract salt in the authentication data, the
//!   creation time, the metadata and the LF contract hash of the arguments), and the **contract salt** itself is the one the view's
//!   position, the transaction's uuid, the synchronizer and the mediator group give.
//!
//! [CANTON-NOTE: LIMITATION] Create, exercise (with subviews) and fetch views are checked field by field, not by comparing the view
//! with one rebuilt from the replay (`ModelConformanceChecker`: `view == reconstructedView`); what each check leaves out is stated on
//! it (`check_resolved_keys`, `check_discriminators`, `check_quorums`, `stated_key`, `check_fetch_view`). Not checked here or by the
//! caller (`view_decision::check_one`): that the submitter may act as the authorizers (`AuthorizationValidator`) and that the ledger
//! time and preparation time are within the synchronizer's tolerances of the sequencing time (`TimeValidator`).
use crate::contract_id::{
    contract_id_suffix, contract_salt, derive_contract_discriminator, derive_node_seed,
    lf_contract_hash, lf_contract_key_hash, unicum, HashValue, KeyInputs, SaltInputs, UnicumInputs,
};
use crate::topology_wire::unversioned;
use crate::view_receive::RevealedView;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    CommonMetadata, ContractAuthenticationData,
};
use canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers;
use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
use canton_proto::com::digitalasset::daml::lf::value::Identifier;
use lf_archive::ModuleSurface;
use lf_eval::codec::RecordSchema;
use lf_eval::{Value, World};

use prost::Message;
use std::collections::BTreeSet;

mod exercise;
mod replay;

pub(crate) use exercise::check_exercise_view_with_events;
pub use exercise::{
    check_exercise_view, check_exercise_view_in_request, check_exercise_view_placed,
    check_exercise_view_placed_with_subviews, check_exercise_view_with_topology, check_fetch_view,
    ConformingExercise,
};

use exercise::authenticate_stored;
use replay::{replay_contract, replay_contract_in, Replayed};

/// The packages and surfaces of a DAR, which is what this participant's engine knows.
pub struct Engine {
    pub world: World,
    pub surfaces: Vec<ModuleSurface>,
    /// The ledger time (microseconds) of the request being checked: a replayed choice that reads the time gets this
    /// (`Engine::set_time_micros`). Set by the caller before it checks the views of a request.
    ledger_time: std::cell::Cell<i64>,
}

impl Engine {
    /// The ledger time the replays of the next views read (see the field).
    pub fn set_ledger_time(&self, micros: i64) {
        self.ledger_time.set(micros);
    }

    /// Creates an empty conformance engine with no loaded DARs (for zero-DAR participant boot).
    pub fn empty() -> Self {
        Engine {
            ledger_time: std::cell::Cell::new(0),
            world: World::empty(),
            surfaces: Vec::new(),
        }
    }

    pub fn load(dar: &std::path::Path) -> Result<Self, String> {
        Ok(Engine {
            ledger_time: std::cell::Cell::new(0),
            world: World::open(dar).map_err(|e| e.to_string())?,
            surfaces: lf_archive::parse_dar_file(dar)
                .map_err(|e| e.to_string())?
                .module_surfaces,
        })
    }

    /// Loads additional packages and module surfaces from a pre-parsed [`lf_archive::LoadedDar`].
    pub fn add_loaded_dar(&mut self, loaded: &lf_archive::LoadedDar) -> Vec<String> {
        let ids = self.world.add_loaded_dar(loaded);
        for surface in &loaded.archive.module_surfaces {
            if let Some(existing) = self.surfaces.iter_mut().find(|s| s.name == surface.name) {
                for tmpl in &surface.templates {
                    if !existing.templates.iter().any(|t| t.name == tmpl.name) {
                        existing.templates.push(tmpl.clone());
                    }
                }
            } else {
                self.surfaces.push(surface.clone());
            }
        }
        ids
    }

    /// Loads additional packages and module surfaces from `dar` into this participant's engine.
    pub fn add_dar(&mut self, dar: &std::path::Path) -> Result<Vec<String>, String> {
        let loaded = lf_archive::load_dar_file(dar).map_err(|e| e.to_string())?;
        Ok(self.add_loaded_dar(&loaded))
    }

    /// Whether `package_id` is loaded in this participant's DAR store (`BaseTopologySnapshot.scala:145-150`).
    pub fn knows_package(&self, package_id: &str) -> bool {
        lf_eval::typed_json::Types::new(&self.world).knows_package(package_id)
    }
}

/// Why a created contract is not accepted.
#[derive(Debug, PartialEq, Eq)]
pub enum Nonconformance {
    Malformed(String),
    UnknownPackage(String),
    UnknownTemplate(String),
    ArgumentsDoNotDecode(String),
    EnsureFalse,
    EngineError(String),
    SignatoriesDiffer {
        computed: Vec<String>,
        stated: Vec<String>,
    },
    StakeholdersDiffer {
        computed: Vec<String>,
        stated: Vec<String>,
    },
    ContractSaltDiffers,
    ContractIdDiffers,
    /// The contract's key (its presence or its maintainers) is not the one the template and the arguments give.
    KeyDiffers(String),
    /// The view's quorums are not the ones its action and contracts give.
    QuorumsDiffer(String),
    /// The discriminator in a created contract's id is not the one its node seed, the preparation time and its stakeholders give.
    DiscriminatorDiffers {
        contract_id: String,
    },
    Unsupported(String),
    UnknownChoice(String),
    ActorsDiffer {
        computed: Vec<String>,
        stated: Vec<String>,
    },
    /// The view describes an action the engine does not reproduce.
    ActionDiffers(String),
    /// The view's informees are not the ones its action gives.
    InformeesDiffer(String),
}

/// `Module:Entity` split into the dotted-name segments LF hashes.
fn segments(dotted: &str) -> Vec<String> {
    dotted.split('.').map(str::to_string).collect()
}

/// A labelled engine value in the form the contract hash takes.
fn hash_value(value: &Value) -> Result<HashValue, Nonconformance> {
    let unsupported = |what: &str| {
        Nonconformance::EngineError(format!("a value this participant cannot hash yet: {what}"))
    };
    Ok(match value {
        Value::Party(p) => HashValue::Party(p.clone()),
        Value::Text(t) => HashValue::Text(t.clone()),
        Value::Bool(b) => HashValue::Bool(*b),
        Value::Int64(i) => HashValue::Int64(*i),
        Value::Unit => HashValue::Unit,
        Value::Numeric { coeff, scale } => {
            // the hash covers the unscaled integer of a number at the scale of its type; `Numeric 10` is the one used here
            if *scale != 10 {
                return Err(unsupported("a numeric of a scale other than 10"));
            }
            HashValue::Numeric(*coeff)
        }
        Value::Optional(None) => HashValue::Optional(None),
        Value::Optional(Some(v)) => HashValue::Optional(Some(Box::new(hash_value(v)?))),
        Value::Record { tycon, fields } => {
            let (module, name) = tycon
                .as_deref()
                .and_then(|t| t.split_once(':'))
                .ok_or_else(|| unsupported("a record without a type name"))?;
            HashValue::Record {
                module: segments(module),
                name: segments(name),
                fields: fields
                    .iter()
                    .map(|(label, v)| Ok((label.clone(), hash_value(v)?)))
                    .collect::<Result<_, Nonconformance>>()?,
            }
        }
        _ => return Err(unsupported("a list, variant, enum or closure")),
    })
}

/// The contract ids this participant derived and checked, for the caller's log.
#[derive(Debug, PartialEq, Eq)]
pub struct Conforming {
    pub contract_id: String,
    pub template: String,
}

/// A key and its maintainers as the engine derives them (`template_id` is `Module:Name`).
pub struct EngineKey {
    pub template_id: String,
    pub key: Value,
    pub maintainers: BTreeSet<String>,
}

/// An exhaustive key query (`Node.QueryByKey.exhaustive`: `found.len() < limit`) observed during view conformance,
/// checked by `view_decision` against the participant's active contract set (`Ledger::active_contracts_for_key`, U-21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExhaustiveKeyQuery {
    pub template_id: String,
    pub key_hash: Vec<u8>,
    pub stated_ids: BTreeSet<String>,
    pub submitters: BTreeSet<String>,
    pub consumed_before: BTreeSet<String>,
}

/// Checks the **resolved keys** of a view against what the replay did.
///
/// [CANTON-NOTE: SEMANTICS] Measured on views p1 made (U-21, `contracts-keyed`): the view that CREATES a keyed contract lists that key with the
/// contract's maintainers and **no** contract id (nothing held the key); the view that reads a contract BY KEY lists the key with the
/// maintainers and the id of the contract it found. A key is the template id (`Identifier` bytes), the key value (a `Versioned` value,
/// compared as the bytes `Value::to_lf_value` writes) and the package name. The rules:
/// - every key lookup the replay made has an entry with the same template and key, the same contract ids and the template's maintainers;
/// - an exhaustive key lookup (`contract_ids.len() < limit`) must not omit any active visible contract in the view's inputs or local creates;
/// - every keyed contract the view creates (`required`) has an entry with its maintainers;
/// - an entry nothing in the view uses (no lookup, no created contract, no input contract with that key) is refused.
///
/// [CANTON-NOTE: LIMITATION] A key of an input contract that is only exercised by id is allowed but not required.
pub fn check_resolved_keys(
    engine: &Engine,
    resolved: &[KeyResolutionWithMaintainers],
    lookups: &[lf_eval::engine::KeyLookup],
    required: &[EngineKey],
    allowed: &[EngineKey],
) -> Result<(), Nonconformance> {
    check_resolved_keys_collecting(engine, resolved, lookups, required, allowed).map(|_| ())
}

/// Like [`check_resolved_keys`], also returning all exhaustive key queries for ACS cross-checking (`view_decision`, U-21).
pub(crate) fn check_resolved_keys_collecting(
    engine: &Engine,
    resolved: &[KeyResolutionWithMaintainers],
    lookups: &[lf_eval::engine::KeyLookup],
    required: &[EngineKey],
    allowed: &[EngineKey],
) -> Result<Vec<ExhaustiveKeyQuery>, Nonconformance> {
    let differs = |what: String| Nonconformance::KeyDiffers(what);
    // decode the entries: (template `Module:Name`, key payload bytes, maintainers, contract ids, pkg name, hash, package id)
    let mut entries: Vec<ResolvedKeyEntry> = Vec::new();
    for r in resolved {
        let key = r
            .key
            .as_ref()
            .ok_or_else(|| Nonconformance::Malformed("a resolved key without a key".into()))?;
        let id = Identifier::decode(key.template_id.as_slice())
            .map_err(|e| Nonconformance::Malformed(e.to_string()))?;
        if !engine.world.has_package(&id.package_id) {
            return Err(Nonconformance::UnknownPackage(id.package_id));
        }
        let versioned = Versioned::decode(key.key.as_slice())
            .map_err(|e| Nonconformance::Malformed(e.to_string()))?;
        entries.push((
            format!("{}:{}", id.module_name.join("."), id.name.join(".")),
            versioned.payload,
            r.maintainers.iter().cloned().collect(),
            r.contract_ids.iter().cloned().collect(),
            key.package_name.clone(),
            key.hash.clone(),
            id.package_id,
        ));
    }
    let payload = |v: &Value| v.to_lf_value().encode_to_vec();
    let find = |template: &str, key: &Value| {
        let bytes = payload(key);
        entries.iter().position(|e| e.0 == template && e.1 == bytes)
    };
    let mut used = vec![false; entries.len()];
    let mut exhaustive = Vec::new();
    let hash_matches = |i: usize, template: &str, key: &Value| -> Result<(), Nonconformance> {
        let (module, name) = template
            .split_once(':')
            .ok_or_else(|| Nonconformance::Malformed(template.to_string()))?;
        let recomputed = lf_contract_key_hash(
            &entries[i].4,
            &segments(module),
            &segments(name),
            &hash_value(key)?,
        );
        if entries[i].5 != recomputed {
            return Err(Nonconformance::KeyDiffers(format!(
                "the view states a key hash for a key of {template} that is not the hash of that key"
            )));
        }
        Ok(())
    };
    for l in lookups {
        let i = find(&l.template_id, &l.key).ok_or_else(|| {
            differs(format!(
                "the replay looked up a key of {} that the view does not resolve",
                l.template_id
            ))
        })?;
        used[i] = true;
        hash_matches(i, &l.template_id, &l.key)?;
        if !l.missed_in_view.is_empty() {
            return Err(differs(format!(
                "the view's exhaustive key query of {} omitted active contract(s) {:?}",
                l.template_id, l.missed_in_view
            )));
        }
        let stated: BTreeSet<String> = l.contract_ids.iter().cloned().collect();
        if entries[i].3 != stated {
            return Err(differs(format!(
                "the view resolves a key of {} to {:?}, the replay found {:?}",
                l.template_id, entries[i].3, stated
            )));
        }
        let (module, name) = l
            .template_id
            .split_once(':')
            .ok_or_else(|| Nonconformance::Malformed(l.template_id.clone()))?;
        let maintainers: BTreeSet<String> = engine
            .world
            .eval_key_maintainers_in(&entries[i].6, module, name, &l.key)
            .map_err(|e| Nonconformance::EngineError(e.to_string()))?
            .into_iter()
            .collect();
        if entries[i].2 != maintainers {
            return Err(differs(format!(
                "the view gives the maintainers {:?} for a key of {}, the template gives {maintainers:?}",
                entries[i].2, l.template_id
            )));
        }
        if l.is_exhaustive() {
            exhaustive.push(ExhaustiveKeyQuery {
                template_id: l.template_id.clone(),
                key_hash: entries[i].5.clone(),
                stated_ids: stated,
                submitters: l.submitters.clone(),
                consumed_before: l.consumed_before.clone(),
            });
        }
    }
    for k in required {
        let i = find(&k.template_id, &k.key).ok_or_else(|| {
            differs(format!(
                "the view creates a {} with a key and does not resolve that key",
                k.template_id
            ))
        })?;
        used[i] = true;
        hash_matches(i, &k.template_id, &k.key)?;
        if entries[i].2 != k.maintainers {
            return Err(differs(format!(
                "the view gives the maintainers {:?} for a key of {}, the contract has {:?}",
                entries[i].2, k.template_id, k.maintainers
            )));
        }
    }
    for k in allowed {
        if let Some(i) = find(&k.template_id, &k.key) {
            used[i] = true;
        }
    }
    if let Some(i) = used.iter().position(|u| !u) {
        return Err(differs(format!(
            "the view resolves a key of {} that nothing in it uses",
            entries[i].0
        )));
    }
    Ok(exhaustive)
}

/// Replays the creation of every contract in the core of `view`.
///
/// `common_metadata` is the revealed common metadata of the tree (the uuid, the synchronizer and the mediator group the contract
/// salt depends on).
pub fn check_view(
    engine: &Engine,
    view: &RevealedView,
    common_metadata: &CommonMetadata,
) -> Result<Vec<Conforming>, Nonconformance> {
    if !view.participant_data.core_inputs.is_empty() {
        return Err(Nonconformance::ActionDiffers(
            "a create view has input contracts".into(),
        ));
    }
    let mut accepted = Vec::new();
    let vpd_salt = view
        .participant_data
        .salt
        .as_ref()
        .map(|s| s.salt.clone())
        .unwrap_or_default();
    let mut created_keys: Vec<EngineKey> = Vec::new();
    for (index, created) in view.participant_data.created_core.iter().enumerate() {
        let replayed = replay_contract(engine, &created.contract)?;
        if let Some((key, maintainers)) = &replayed.key {
            created_keys.push(EngineKey {
                template_id: replayed.template_id.clone(),
                key: key.clone(),
                maintainers: maintainers.iter().cloned().collect(),
            });
        }
        authenticate_created(&replayed, &vpd_salt, index, view, common_metadata)?;
        // the informees of the view cover the stakeholders of the contract it creates
        let informees: BTreeSet<&String> = view.common_data.informees.iter().collect();
        if !replayed.stakeholders.iter().all(|s| informees.contains(s)) {
            return Err(Nonconformance::ActionDiffers(
                "not every stakeholder of the created contract is an informee of the view".into(),
            ));
        }
        accepted.push(Conforming {
            contract_id: hex::encode(&replayed.fci.contract_id),
            template: replayed.template_id,
        });
    }
    check_resolved_keys(
        engine,
        &view.participant_data.resolved_keys,
        &[],
        &created_keys,
        &[],
    )?;
    Ok(accepted)
}

/// Checks that the id of a contract created in `view` is the one its contract salt and its contents give: the salt is re-derived
/// from the view (its participant data salt, the index of the create in the view, the view's position, the transaction's uuid, the
/// synchronizer and the mediator group) and must be the one in the authentication data; the unicum of that salt and the contract
/// must be the suffix of the id.
fn authenticate_created(
    replayed: &Replayed,
    vpd_salt: &[u8],
    index: usize,
    view: &RevealedView,
    common_metadata: &CommonMetadata,
) -> Result<(), Nonconformance> {
    let fci = &replayed.fci;
    let template = fci
        .template_id
        .clone()
        .expect("replay_contract checked the template");
    let (auth_data, _) = unversioned(&fci.authentication_data)
        .ok_or_else(|| Nonconformance::Malformed("unversioned authentication data".into()))?;
    let stated_salt = ContractAuthenticationData::decode(auth_data.as_slice())
        .ok()
        .and_then(|a| a.contract_salt)
        .map(|s| s.salt)
        .ok_or_else(|| Nonconformance::Malformed("authentication data without a salt".into()))?;
    let derived_salt = contract_salt(&SaltInputs {
        view_participant_data_salt: vpd_salt,
        create_index: index as i32,
        view_position: &view.position,
        transaction_uuid: &common_metadata.uuid,
        synchronizer_id: &common_metadata.physical_synchronizer_id,
        mediator: &format!("MGR::{}", common_metadata.mediator_group),
    });
    if stated_salt != derived_salt {
        return Err(Nonconformance::ContractSaltDiffers);
    }
    let contract_hash = lf_contract_hash(
        &fci.package_name,
        &segments(&template.module_name.join(".")),
        &segments(&template.name.join(".")),
        &replayed.hash_arg,
    );
    let signatory_list: Vec<String> = replayed.signatories.iter().cloned().collect();
    let stakeholder_list: Vec<String> = replayed.stakeholders.iter().cloned().collect();
    let stated_key = stated_key(fci)?;
    let derived_unicum = unicum(
        &derived_salt,
        &UnicumInputs {
            created_at_micros: fci.created_at,
            signatories: &signatory_list,
            stakeholders: &stakeholder_list,
            key: stated_key.as_ref().map(|(h, m)| KeyInputs {
                hash: h,
                maintainers: m,
            }),
            contract_hash: &contract_hash,
        },
    );
    // the contract id is `00` ++ discriminator (32 bytes) ++ suffix; the suffix is what the unicum determines
    let id = &fci.contract_id;
    if id.len() < 33 || id[33..] != contract_id_suffix(&derived_unicum)[..] {
        return Err(Nonconformance::ContractIdDiffers);
    }
    Ok(())
}

/// Checks the **discriminator** of every contract the view creates in its core (`00 ++ discriminator ++ suffix`).
///
/// [CANTON-NOTE: SEMANTICS] The discriminator is `HMAC(node seed, preparation time ++ stakeholders)` of the *create node*. The seed
/// of a root create is in its action description; the seeds of the creates **inside an exercise** are derived from the
/// exercise's seed by the index of the child (`deriveNodeSeed(parent, index)`). Without this check a participant accepts an id
/// whose discriminator is unrelated to the transaction, and two transactions could then produce ids that collide.
///
/// [CANTON-NOTE: LIMITATION] A view with **subviews** is not checked here for the creates under an exercise: the child index counts the
/// nodes that are not in this view, and the view alone does not say how many precede a create. [`check_discriminators_at`] with the
/// positions of a replay checks them.
pub fn check_discriminators(
    view: &RevealedView,
    preparation_time_micros: i64,
) -> Result<(), Nonconformance> {
    check_discriminators_at(view, preparation_time_micros, None)
}

/// Like [`check_discriminators`], for a view whose creates may sit anywhere in its tree: `positions[i]` is the position of the `i`-th create of
/// the core (what [`check_exercise_view_placed`] reports from the engine's replay). The seed of a create is the exercise's seed derived once
/// per level of its position (`lf_eval::NodePaths`: every node among the siblings, fetches included, takes a child index). `None` means every
/// create is a direct child numbered by its place among the core's creates.
///
/// [CANTON-NOTE: SEMANTICS] The positions come from replaying the exercise, never from the view: the view does not state them, and a
/// sender that could name them could name the seeds it likes.
pub fn check_discriminators_at(
    view: &RevealedView,
    preparation_time_micros: i64,
    positions: Option<&[Vec<usize>]>,
) -> Result<(), Nonconformance> {
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    let seed_of = |bytes: &[u8]| -> Result<[u8; 32], Nonconformance> {
        bytes
            .try_into()
            .map_err(|_| Nonconformance::Malformed("a node seed of the wrong size".into()))
    };
    let data = &view.participant_data;
    let (root_seed, creates_are_children) = match data
        .action_description
        .as_ref()
        .and_then(|a| a.description.as_ref())
    {
        Some(Description::Create(c)) => (seed_of(&c.node_seed)?, false),
        Some(Description::Exercise(e)) => {
            // without the replay's positions a create's child index cannot be told from the view: the subviews take indices too
            if view.has_subviews && positions.is_none() {
                return Ok(());
            }
            (seed_of(&e.node_seed)?, true)
        }
        _ => return Ok(()),
    };
    for (index, created) in data.created_core.iter().enumerate() {
        let (bytes, _) = unversioned_fat(&created.contract)?;
        let fci = FatContractInstance::decode(bytes.as_slice())
            .map_err(|e| Nonconformance::Malformed(e.to_string()))?;
        let stakeholders: Vec<String> = stated_stakeholders(&fci).into_iter().collect();
        let seed = match (creates_are_children, positions) {
            (false, _) => root_seed,
            (true, None) => derive_node_seed(&root_seed, index as i32),
            (true, Some(positions)) => positions
                .get(index)
                .ok_or_else(|| Nonconformance::Malformed("a create without a position".into()))?
                .iter()
                .fold(root_seed, |seed, child| {
                    derive_node_seed(&seed, *child as i32)
                }),
        };
        let expected = derive_contract_discriminator(&seed, preparation_time_micros, &stakeholders);
        let id = &fci.contract_id;
        if id.len() < 33 || id[1..33] != expected[..] {
            return Err(Nonconformance::DiscriminatorDiffers {
                contract_id: hex::encode(id),
            });
        }
    }
    Ok(())
}

/// Checks the **quorums** of a root view's common data: who must confirm it.
///
/// [CANTON-NOTE: SEMANTICS] Measured on views p1 made (create, `Settle`, `Transfer`) and accepted from this participant:
/// - a root **create**: one quorum, the signatories of the created contract and the submitting participant's admin party;
/// - a root **exercise**: a first quorum of the actors, the signatories of the **consumed** input contracts and the admin party, and, if
///   the view creates contracts or reads (fetches) others, a **second quorum of the created contracts' signatories and of the
///   signatories of the contracts it only reads** (no admin party);
/// - a **nested** view (a subview; `admin_party` is `None`) has **no admin party**: measured on a child `Touch` of a consumed `Held` that
///   `erin` signs, exercised by `alice` (the controller of the parent): one quorum {alice (actor), erin (signatory of the consumed input)},
///   threshold 2. Only the submitting participant's admin party is missing; the rest is the rule of a root exercise. The admin party is
///   known from the submitter metadata, which a subview's recipient does not see (blinded).
/// - every member has weight 1 and a quorum's threshold is the number of its members. The informees list is sorted, and a
///   quorum names its members by index into it.
pub fn check_quorums(view: &RevealedView, admin_party: Option<&str>) -> Result<(), Nonconformance> {
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    let differs = |what: String| Nonconformance::QuorumsDiffer(what);
    let signatories_of = |bytes: &[u8]| -> Result<BTreeSet<String>, Nonconformance> {
        let (data, _) = unversioned_fat(bytes)?;
        let fci = FatContractInstance::decode(data.as_slice())
            .map_err(|e| Nonconformance::Malformed(e.to_string()))?;
        Ok(stated_signatories(&fci))
    };
    let data = &view.participant_data;
    let mut created = BTreeSet::new();
    for c in &data.created_core {
        created.extend(signatories_of(&c.contract)?);
    }
    let mut expected: Vec<BTreeSet<String>> = Vec::new();
    match data
        .action_description
        .as_ref()
        .and_then(|a| a.description.as_ref())
    {
        Some(Description::Create(_)) => {
            let mut q = created;
            if let Some(admin) = admin_party {
                q.insert(admin.to_string());
            }
            expected.push(q);
        }
        Some(Description::Exercise(e)) => {
            // [CANTON-NOTE: SEMANTICS] Measured (G8 P0, a nested exercise and a tree with a fetch, a nested create and a create, all in one
            // view, against the official participant): the first quorum is the actors, the signatories of the exercised input when it is
            // **consumed**, and the admin party. Every other node of the view gives a quorum of its own (a create the signatories of the
            // contract, a nested exercise its actors and the signatories of what it consumes, a fetch its acting parties), equal ones are one,
            // and the second and later quorums are ordered by their members.
            //
            // [CANTON-NOTE: LIMITATION] The view does not name the actors of a nested exercise or the acting parties of a fetch, so those
            // quorums are not derived here. What is checked: the first quorum exactly, the quorum of each created contract's signatories, that
            // no other quorum names a party the view's contracts and actors do not, and that every signatory of a core input confirms somewhere.
            let mut q: BTreeSet<String> = e.actors.iter().cloned().collect();
            let mut pool: BTreeSet<String> = q.clone();
            let mut input_signatories = BTreeSet::new();
            for i in &data.core_inputs {
                let (bytes, _) = unversioned_fat(&i.contract)?;
                let fci = FatContractInstance::decode(bytes.as_slice())
                    .map_err(|e| Nonconformance::Malformed(e.to_string()))?;
                let is_exercised = hex::encode(&fci.contract_id) == e.input_contract_id;
                let signatories = signatories_of(&i.contract)?;
                if is_exercised {
                    q.extend(signatories.iter().cloned());
                }
                pool.extend(signatories.iter().cloned());
                input_signatories.extend(signatories);
            }
            let mut required: BTreeSet<BTreeSet<String>> = BTreeSet::new();
            for c in &data.created_core {
                let signatories = signatories_of(&c.contract)?;
                pool.extend(signatories.iter().cloned());
                required.insert(signatories);
            }
            if let Some(admin) = admin_party {
                q.insert(admin.to_string());
            }
            let _ = created;
            let stated = stated_quorums(view)?;
            let Some((first, others)) = stated.split_first() else {
                return Err(differs("a view without quorums".into()));
            };
            if *first != q {
                return Err(differs(format!(
                    "the first quorum is {first:?}, the action gives {q:?}"
                )));
            }
            let others_set: BTreeSet<&BTreeSet<String>> = others.iter().collect();
            if others_set.len() != others.len() {
                return Err(differs("a quorum is stated twice".into()));
            }
            // a created contract whose signatories are the first quorum's members adds no quorum (measured: p1's subview `Touch` with a `Receipt`
            // signed by its actor and the signatory it consumes has the one quorum)
            if let Some(missing) = required
                .iter()
                .find(|r| **r != q && !others_set.contains(r))
            {
                return Err(differs(format!(
                    "no quorum of the signatories {missing:?} of a created contract (the view says {others:?})"
                )));
            }
            if let Some(stranger) = others.iter().find(|o| o.iter().any(|p| !pool.contains(p))) {
                return Err(differs(format!(
                    "a quorum {stranger:?} names a party no contract or actor of the view gives"
                )));
            }
            let confirming: BTreeSet<&String> = stated.iter().flatten().collect();
            if let Some(unconfirmed) = input_signatories.iter().find(|p| !confirming.contains(p)) {
                return Err(differs(format!(
                    "{unconfirmed} signs a contract the view uses but is in no quorum"
                )));
            }
            return Ok(());
        }
        _ => return Ok(()),
    }
    let stated = stated_quorums(view)?;
    if stated != expected {
        return Err(differs(format!(
            "the view says {stated:?}, the action gives {expected:?}"
        )));
    }
    Ok(())
}

/// The quorums a view's common data states, as sets of party ids (each member weight 1, the threshold the number of members).
fn stated_quorums(view: &RevealedView) -> Result<Vec<BTreeSet<String>>, Nonconformance> {
    let differs = |what: String| Nonconformance::QuorumsDiffer(what);
    let informees = &view.common_data.informees;
    let mut stated: Vec<BTreeSet<String>> = Vec::new();
    for q in &view.common_data.quorums {
        let mut members = BTreeSet::new();
        for m in &q.party_index_and_weight {
            if m.weight != 1 {
                return Err(differs(format!("a member with weight {}", m.weight)));
            }
            let party = informees
                .get(m.index as usize)
                .ok_or_else(|| differs("a member that is not an informee".into()))?;
            members.insert(party.clone());
        }
        if q.threshold as usize != members.len() {
            return Err(differs(format!(
                "a threshold of {} for {} members",
                q.threshold,
                members.len()
            )));
        }
        stated.push(members);
    }
    Ok(stated)
}

/// The versioned wrapper of a contract instance and the payload inside.
pub(crate) fn unversioned_fat(bytes: &[u8]) -> Result<(Vec<u8>, String), Nonconformance> {
    let v = Versioned::decode(bytes).map_err(|e| Nonconformance::Malformed(e.to_string()))?;
    Ok((v.payload, v.version))
}

/// A serialized contract instance read for display: what a participant shows its parties about a contract another participant created.
#[derive(Debug, Clone)]
pub struct OpenedContract {
    pub contract_id: String,
    pub package_id: String,
    /// `Module:Name`.
    pub template: String,
    pub arg: Value,
    pub signatories: BTreeSet<String>,
    pub stakeholders: BTreeSet<String>,
    pub created_at_micros: i64,
}

/// Reads a serialized contract instance (the versioned bytes a view carries) without replaying it: the view was validated when the request
/// was confirmed, so this only decodes.
pub fn open_instance(engine: &Engine, contract_bytes: &[u8]) -> Result<OpenedContract, String> {
    let (data, _) = unversioned_fat(contract_bytes).map_err(|e| format!("{e:?}"))?;
    let fci = FatContractInstance::decode(data.as_slice()).map_err(|e| e.to_string())?;
    let template = fci
        .template_id
        .as_ref()
        .ok_or("a contract without a template")?;
    let template_id = format!(
        "{}:{}",
        template.module_name.join("."),
        template.name.join(".")
    );
    // [CANTON-NOTE: WHY] The surface codec names a record, variant or enum field only as an opaque type constructor, so a template with such a
    // field (an enum is common: the official participants' own contracts have them) cannot be read by it. The typed codec resolves every type
    // from the packages, so it reads what the surface codec refuses; the surface codec stays first so what it handles reads as before.
    let surface = RecordSchema::template(&engine.surfaces, &template_id)
        .ok()
        .and_then(|schema| schema.decode(&fci.create_arg).ok());
    let arg = match surface {
        Some(arg) => arg,
        None => {
            let types = lf_eval::typed_json::Types::new(&engine.world);
            let ty = types
                .template(&template.package_id, &template_id)
                .map_err(|e| {
                    format!("the template {template_id} is not in the loaded package: {e}")
                })?;
            types.from_wire(&ty, &fci.create_arg)?
        }
    };
    Ok(OpenedContract {
        contract_id: hex::encode(&fci.contract_id),
        package_id: template.package_id.clone(),
        template: template_id,
        arg,
        signatories: stated_signatories(&fci),
        stakeholders: stated_stakeholders(&fci),
        created_at_micros: fci.created_at,
    })
}

/// The signatories a contract instance states: `non_maintainer_signatories` plus the maintainers of its key.
///
/// [CANTON-NOTE: SEMANTICS] Measured on a contract with a key that p1 created (U-21, `contracts-keyed`): the instance splits its
/// signatories into the ones that are not key maintainers (`non_maintainer_signatories`, empty when every signatory maintains the
/// key) and the maintainers (`contract_key_with_maintainers.maintainers`); a maintainer is always a signatory. Reading only the first
/// list makes every keyed contract look like it has no signatory.
pub(crate) fn stated_signatories(fci: &FatContractInstance) -> BTreeSet<String> {
    fci.non_maintainer_signatories
        .iter()
        .chain(
            fci.contract_key_with_maintainers
                .iter()
                .flat_map(|k| k.maintainers.iter()),
        )
        .cloned()
        .collect()
}

/// The view's key resolutions as the replay engine takes them: template `Module:Name`, encoded key, contract ids in the stated order
/// (entries of the same key from several views are merged, keeping the first order seen). An entry that does not decode is left out:
/// the replay then finds nothing for that key and the comparison of resolved keys reports it.
pub(super) fn view_key_resolutions<'a>(
    entries: impl Iterator<Item = &'a KeyResolutionWithMaintainers>,
) -> Vec<lf_eval::engine::ViewKeyResolution> {
    use canton_proto::com::digitalasset::daml::lf::transaction::Versioned;
    use canton_proto::com::digitalasset::daml::lf::value::Identifier;
    let mut out: Vec<lf_eval::engine::ViewKeyResolution> = Vec::new();
    for r in entries {
        let Some(key) = r.key.as_ref() else {
            continue;
        };
        let (Ok(id), Ok(versioned)) = (
            Identifier::decode(key.template_id.as_slice()),
            Versioned::decode(key.key.as_slice()),
        ) else {
            continue;
        };
        let template = format!("{}:{}", id.module_name.join("."), id.name.join("."));
        match out
            .iter_mut()
            .find(|(t, k, _)| *t == template && *k == versioned.payload)
        {
            Some((_, _, ids)) => {
                for cid in &r.contract_ids {
                    if !ids.contains(cid) {
                        ids.push(cid.clone());
                    }
                }
            }
            None => out.push((template, versioned.payload, r.contract_ids.clone())),
        }
    }
    out
}

/// One entry of a view's `resolved_keys` after decoding: template `Module:Name`, key payload bytes, maintainers, contract ids,
/// and the two trailing fields the comparison reads.
type ResolvedKeyEntry = (
    String,
    Vec<u8>,
    BTreeSet<String>,
    BTreeSet<String>,
    String,
    Vec<u8>,
    String,
);

/// The key a contract states about itself: its hash and its maintainers.
type StatedKey = ([u8; 32], Vec<String>);

/// The stakeholders a contract instance states: its signatories and the non-signatory stakeholders.
/// The key hash and the (sorted) maintainers the instance states, if it has a key.
///
/// [CANTON-NOTE: LIMITATION] The stated key hash is used as it is (the Unicum commits to it); it is not yet recomputed from the key
/// value the engine evaluates, so a wrong stated hash is caught only through the contract id it changes (U-21).
fn stated_key(fci: &FatContractInstance) -> Result<Option<StatedKey>, Nonconformance> {
    let Some(k) = &fci.contract_key_with_maintainers else {
        return Ok(None);
    };
    let hash: [u8; 32] = k.hash.as_slice().try_into().map_err(|_| {
        Nonconformance::Malformed(format!("a contract key hash of {} bytes", k.hash.len()))
    })?;
    let mut maintainers = k.maintainers.clone();
    maintainers.sort();
    Ok(Some((hash, maintainers)))
}

pub(crate) fn stated_stakeholders(fci: &FatContractInstance) -> BTreeSet<String> {
    stated_signatories(fci)
        .into_iter()
        .chain(fci.non_signatory_stakeholders.iter().cloned())
        .collect()
}

/// Why a contract is not imported.
#[derive(Debug, PartialEq, Eq)]
pub enum ImportError {
    /// The instance is not authentic (the engine does not reproduce it, or its id is not the unicum of its contents).
    NotAuthentic(Nonconformance),
    /// The contract set refuses it (already known, journal failure).
    Refused(crate::view_acs::Conflict),
}

/// Imports a contract the participant has not seen created (an ACS snapshot of a party it began to host): the serialized contract
/// instance is **authenticated first** (see [`authenticate_stored`]: the engine reproduces it and its id is the unicum of its stored
/// salt and contents), so an exporter cannot make the participant believe in a contract the template would not produce. Returns the id.
pub fn import_contract(
    engine: &Engine,
    ledger: &mut crate::view_acs::Ledger,
    contract_bytes: &[u8],
) -> Result<String, ImportError> {
    let (id, template_id) =
        authenticate_instance(engine, contract_bytes).map_err(ImportError::NotAuthentic)?;
    ledger
        .import(&id, &template_id)
        .map_err(ImportError::Refused)?;
    Ok(id)
}

/// Authenticates a serialized contract instance as [`import_contract`] does, without importing it: its id (hex) and template.
pub fn authenticate_instance(
    engine: &Engine,
    contract_bytes: &[u8],
) -> Result<(String, String), Nonconformance> {
    authenticate_instance_with_package(engine, contract_bytes, None)
}

/// Like [`authenticate_instance`], validating against `validation_package_id` when specified
/// (`ReassignmentValidation.scala` `authenticateContractsAgainstSource`/`Target`).
pub fn authenticate_instance_with_package(
    engine: &Engine,
    contract_bytes: &[u8],
    validation_package_id: Option<&str>,
) -> Result<(String, String), Nonconformance> {
    let replayed = replay_contract_in(engine, contract_bytes, validation_package_id)?;
    authenticate_stored(&replayed)?;
    Ok((hex::encode(&replayed.fci.contract_id), replayed.template_id))
}

#[cfg(test)]
mod key_tests {
    use super::*;
    use canton_proto::com::digitalasset::daml::lf::transaction::KeyWithMaintainers;

    fn keyed(
        non_maintainers: &[&str],
        maintainers: &[&str],
        observers: &[&str],
    ) -> FatContractInstance {
        FatContractInstance {
            non_maintainer_signatories: non_maintainers.iter().map(|s| s.to_string()).collect(),
            non_signatory_stakeholders: observers.iter().map(|s| s.to_string()).collect(),
            contract_key_with_maintainers: Some(KeyWithMaintainers {
                key: vec![],
                maintainers: maintainers.iter().map(|s| s.to_string()).collect(),
                hash: vec![7; 32],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn the_signatories_of_a_keyed_contract_include_the_key_maintainers() {
        let fci = keyed(&["b"], &["a"], &["c"]);
        assert_eq!(
            stated_signatories(&fci),
            ["a", "b"].map(String::from).into()
        );
        assert_eq!(
            stated_stakeholders(&fci),
            ["a", "b", "c"].map(String::from).into()
        );
        // when every signatory maintains the key there is no non-maintainer signatory at all
        let all = keyed(&[], &["a"], &[]);
        assert_eq!(stated_signatories(&all), ["a"].map(String::from).into());
    }

    #[test]
    fn a_contract_without_a_key_states_only_its_non_maintainer_signatories() {
        let fci = FatContractInstance {
            non_maintainer_signatories: vec!["a".into()],
            ..Default::default()
        };
        assert_eq!(stated_signatories(&fci), ["a"].map(String::from).into());
        assert_eq!(stated_key(&fci).unwrap(), None);
    }

    #[test]
    fn the_stated_key_is_the_hash_and_the_sorted_maintainers_and_a_short_hash_is_refused() {
        let fci = keyed(&[], &["b", "a"], &[]);
        assert_eq!(
            stated_key(&fci).unwrap(),
            Some(([7u8; 32], vec!["a".to_string(), "b".to_string()]))
        );
        let mut short = keyed(&[], &["a"], &[]);
        short.contract_key_with_maintainers.as_mut().unwrap().hash = vec![1, 2, 3];
        assert!(matches!(
            stated_key(&short),
            Err(Nonconformance::Malformed(_))
        ));
    }
}

#[cfg(test)]
mod resolved_key_tests {
    use super::*;
    use canton_proto::com::digitalasset::canton::protocol::v31::GlobalKey;
    use lf_eval::engine::KeyLookup;

    const OWNER: &str = "erin::1220abcd";

    fn engine() -> Engine {
        Engine::load(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../contracts/fixtures/keyed/target/keyed-vault.dar"),
        )
        .unwrap()
    }

    fn key(name: &str) -> Value {
        Value::Record {
            tycon: Some("DA.Types:Tuple2".into()),
            fields: vec![
                ("_1".into(), Value::Party(OWNER.into())),
                ("_2".into(), Value::Text(name.into())),
            ],
        }
    }

    /// An entry as p1 writes it (measured: the template id as `Identifier` bytes, the key as a `Versioned` value).
    fn entry(
        e: &Engine,
        name: &str,
        maintainers: &[&str],
        ids: &[&str],
    ) -> KeyResolutionWithMaintainers {
        KeyResolutionWithMaintainers {
            key: Some(GlobalKey {
                template_id: Identifier {
                    package_id: e.world.main_package_id().to_string(),
                    module_name: vec!["Keyed".into()],
                    name: vec!["Registry".into()],
                }
                .encode_to_vec(),
                key: Versioned {
                    version: "2".into(),
                    payload: key(name).to_lf_value().encode_to_vec(),
                }
                .encode_to_vec(),
                package_name: "keyed-vault".into(),
                hash: lf_contract_key_hash(
                    "keyed-vault",
                    &["Keyed".into()],
                    &["Registry".into()],
                    &hash_value(&key(name)).unwrap(),
                )
                .to_vec(),
            }),
            maintainers: maintainers.iter().map(|s| s.to_string()).collect(),
            contract_ids: ids.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn lookup(name: &str, ids: &[&str]) -> KeyLookup {
        KeyLookup {
            template_id: "Keyed:Registry".into(),
            key: key(name),
            contract_ids: ids.iter().map(|s| s.to_string()).collect(),
            limit: ids.len().max(1),
            submitters: BTreeSet::from([OWNER.to_string()]),
            missed_in_view: Vec::new(),
            consumed_before: BTreeSet::new(),
        }
    }

    fn created(name: &str) -> EngineKey {
        EngineKey {
            template_id: "Keyed:Registry".into(),
            key: key(name),
            maintainers: [OWNER.to_string()].into(),
        }
    }

    #[test]
    fn a_view_that_reads_a_contract_by_key_resolves_the_key_to_that_contract() {
        let e = engine();
        let ok = [entry(&e, "entry", &[OWNER], &["00aa"])];
        assert_eq!(
            check_resolved_keys(&e, &ok, &[lookup("entry", &["00aa"])], &[], &[]),
            Ok(())
        );
        // another contract id, other maintainers, a missing entry and a surplus entry are each refused
        let wrong_id = [entry(&e, "entry", &[OWNER], &["00bb"])];
        assert!(matches!(
            check_resolved_keys(&e, &wrong_id, &[lookup("entry", &["00aa"])], &[], &[]),
            Err(Nonconformance::KeyDiffers(_))
        ));
        let wrong_maintainers = [entry(&e, "entry", &["bob::1220"], &["00aa"])];
        assert!(matches!(
            check_resolved_keys(
                &e,
                &wrong_maintainers,
                &[lookup("entry", &["00aa"])],
                &[],
                &[]
            ),
            Err(Nonconformance::KeyDiffers(_))
        ));
        assert!(matches!(
            check_resolved_keys(&e, &[], &[lookup("entry", &["00aa"])], &[], &[]),
            Err(Nonconformance::KeyDiffers(_))
        ));
        let surplus = [
            entry(&e, "entry", &[OWNER], &["00aa"]),
            entry(&e, "other", &[OWNER], &[]),
        ];
        assert!(matches!(
            check_resolved_keys(&e, &surplus, &[lookup("entry", &["00aa"])], &[], &[]),
            Err(Nonconformance::KeyDiffers(_))
        ));
    }

    /// The replay really does look the key up: `ReadByKey` on an engine that holds the entry makes exactly one key lookup, and the
    /// check accepts the entry p1 would write for it (so the real-node test passes through this check, not past it).
    #[test]
    fn the_replay_of_a_read_by_key_records_the_lookup_the_view_has_to_resolve() {
        let e = engine();
        let package = e.world.main_package_id().to_string();
        let payload = Value::Record {
            tycon: Some("Keyed:Registry".into()),
            fields: vec![
                ("owner".into(), Value::Party(OWNER.into())),
                ("name".into(), Value::Text("entry".into())),
                ("payload".into(), Value::Text("hello".into())),
            ],
        };
        let mut replay = lf_eval::engine::Engine::new(&e.world);
        replay
            .import_contract(lf_eval::engine::Contract {
                contract_id: "00aa".into(),
                package_id: package,
                template_id: "Keyed:Registry".into(),
                payload,
                signatories: vec![OWNER.into()],
                observers: vec![],
                active: true,
                key: None,
            })
            .unwrap();
        let arg = Value::Record {
            tycon: None,
            fields: vec![("wanted".into(), key("entry"))],
        };
        replay
            .exercise_as(&[OWNER], "00aa", "ReadByKey", &arg)
            .unwrap();
        assert_eq!(replay.key_lookups(), &[lookup("entry", &["00aa"])]);
        let resolved = [entry(&e, "entry", &[OWNER], &["00aa"])];
        assert_eq!(
            check_resolved_keys(&e, &resolved, replay.key_lookups(), &[], &[]),
            Ok(())
        );
    }

    #[test]
    fn a_key_hash_that_is_not_the_hash_of_the_key_is_refused() {
        let e = engine();
        let mut bad = entry(&e, "entry", &[OWNER], &["00aa"]);
        bad.key.as_mut().unwrap().hash = vec![0; 32];
        assert!(matches!(
            check_resolved_keys(&e, &[bad], &[lookup("entry", &["00aa"])], &[], &[]),
            Err(Nonconformance::KeyDiffers(_))
        ));
    }

    #[test]
    fn a_view_that_creates_a_keyed_contract_resolves_its_key_with_the_maintainers() {
        let e = engine();
        let free = [entry(&e, "entry", &[OWNER], &[])];
        assert_eq!(
            check_resolved_keys(&e, &free, &[], &[created("entry")], &[]),
            Ok(())
        );
        // the key of the contract is not resolved at all
        assert!(matches!(
            check_resolved_keys(&e, &[], &[], &[created("entry")], &[]),
            Err(Nonconformance::KeyDiffers(_))
        ));
        // the key of an input contract that is only exercised by id may be listed (allowed) or left out
        let input = [EngineKey {
            template_id: "Keyed:Registry".into(),
            key: key("entry"),
            maintainers: [OWNER.to_string()].into(),
        }];
        assert_eq!(check_resolved_keys(&e, &free, &[], &[], &input), Ok(()));
        assert_eq!(check_resolved_keys(&e, &[], &[], &[], &input), Ok(()));
    }
}
