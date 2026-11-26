//! Decomposition runs (`Run`): views, node seeds and contract id substitution.

use std::collections::{BTreeMap, BTreeSet};

use crate::contract_wire::LfValue;
use crate::submit::{
    common_data_of, derive_created, sorted, Derivation, NewInView, Randomness, StoredContract,
};
use crate::{contract_id as ci, merkle_wire as mw};

use super::{children_of, seq_indices, Action, BuiltView, KeyUse, NewView, Run, Tail, Transaction};

impl Run<'_, '_> {
    /// The `resolved_keys` of a view: the key resolutions of the nodes in its core, one entry per key.
    fn resolved_keys_of(
        &self,
        core: &[usize],
    ) -> Result<
        Vec<canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers>,
        String,
    >{
        use canton_proto::com::digitalasset::canton::protocol::v31::{
            view_participant_data::KeyResolutionWithMaintainers, GlobalKey,
        };
        use canton_proto::com::digitalasset::daml::lf::{
            transaction::Versioned, value::Identifier,
        };
        use prost::Message;
        let mut uses: Vec<(usize, KeyUse)> = self.tx.keys.clone();
        // a lookup node states its key and what it found
        for node in core {
            if let Action::Lookup(k, found) = &self.tx.nodes[*node] {
                if found.len() <= 1 {
                    uses.push((*node, k.clone()));
                } else {
                    // one use per contract found: the resolved-key merge below appends each id to the key's entry in order
                    for contract in found {
                        let mut each = k.clone();
                        each.contract_id = Some(contract.contract_id_hex.clone());
                        uses.push((*node, each));
                    }
                }
            }
        }
        // a keyed contract the view creates states its key, free (nothing held it: measured on `Rename`, S-NET-034 and S-SPL-022)
        for node in core {
            if let Action::Create(c) = &self.tx.nodes[*node] {
                if let Some(key) = &c.key {
                    uses.push((
                        *node,
                        KeyUse {
                            package_name: c.package_name.clone(),
                            package_id: c.package_id.clone(),
                            module: c.module.clone(),
                            name: c.name.clone(),
                            value: key.value.clone(),
                            hash_value: key.hash_value.clone(),
                            maintainers: key.maintainers.clone(),
                            contract_id: None,
                        },
                    ));
                }
            }
        }
        let mut entries: Vec<(Vec<u8>, KeyResolutionWithMaintainers)> = Vec::new();
        for (node, k) in &uses {
            if !core.contains(node) {
                continue;
            }
            let hash = ci::lf_contract_key_hash(&k.package_name, &k.module, &k.name, &k.hash_value);
            let mut maintainers = k.maintainers.clone();
            maintainers.sort();
            let entry = KeyResolutionWithMaintainers {
                key: Some(GlobalKey {
                    template_id: Identifier {
                        package_id: k.package_id.clone(),
                        module_name: k.module.clone(),
                        name: k.name.clone(),
                    }
                    .encode_to_vec(),
                    key: Versioned {
                        version: "2".into(),
                        payload: k.value.encode(),
                    }
                    .encode_to_vec(),
                    package_name: k.package_name.clone(),
                    hash: hash.to_vec(),
                }),
                maintainers,
                contract_ids: k.contract_id.iter().cloned().collect(),
            };
            // [CANTON-NOTE: SEMANTICS] One entry per key, whose contracts are every contract the view's uses of that key observed
            // (`NextGenTransactionTreeFactory.buildResolvedKeys`: `observedKeyContractIds` grows with each node's `queriedContractIds`).
            // A use by id adds the key with no contract; a use by key or a lookup adds what it found.
            match entries.iter_mut().find(|(h, _)| *h == hash.to_vec()) {
                Some((_, known)) => {
                    for id in entry.contract_ids {
                        if !known.contract_ids.contains(&id) {
                            known.contract_ids.push(id);
                        }
                    }
                }
                None => entries.push((hash.to_vec(), entry)),
            }
        }
        Ok(entries.into_iter().map(|(_, e)| e).collect())
    }
}

impl Run<'_, '_> {
    /// The package preference stated by the exercise that roots `nv`: the one set for its node, else [`package_preference`].
    fn preference_of(&self, nv: &NewView) -> Result<Vec<String>, String> {
        match self.tx.package_preference.get(&nv.node) {
            Some(set) => Ok(set.clone()),
            None => package_preference(self.tx, nv),
        }
    }

    /// `NextGenTransactionTreeFactory.createTransactionView`.
    pub(super) fn view(
        &mut self,
        nv: &NewView,
        position: Vec<Vec<bool>>,
        random: &mut dyn Randomness,
    ) -> Result<BuiltView, String> {
        let cd_salt = random.fresh("vcd");
        let pd_salt = match (&self.root_salt, position.len()) {
            (Some(salt), 1) => *salt,
            _ => random.fresh("vpd-salt"),
        };
        let child_views: Vec<&NewView> = nv
            .tail
            .iter()
            .filter_map(|t| match t {
                Tail::New(v) => Some(&**v),
                Tail::Same(_) => None,
            })
            .collect();
        let child_positions = seq_indices(child_views.len());
        let mut core: Vec<usize> = vec![nv.node];
        let mut children: Vec<BuiltView> = Vec::new();
        let mut next_child = 0;
        for t in &nv.tail {
            match t {
                Tail::Same(n) => core.push(*n),
                Tail::New(v) => {
                    let mut p = vec![child_positions[next_child].clone()];
                    p.extend(position.iter().cloned());
                    next_child += 1;
                    children.push(self.view(v, p, random)?);
                }
            }
        }
        // creates of the core, in order; the other nodes use contracts that exist
        let subview_created: BTreeSet<String> = children
            .iter()
            .flat_map(|c| c.created_ids.iter().cloned())
            .collect();
        let mut created_here: Vec<(Vec<u8>, String)> = Vec::new();
        let mut inputs: Vec<(Vec<u8>, String, bool)> = Vec::new();
        let mut consumed: BTreeSet<String> = BTreeSet::new();
        let mut created_in_subview_archived_in_core: Vec<String> = Vec::new();
        for n in &core {
            match &self.tx.nodes[*n] {
                Action::Create(c) => {
                    let seed = self.seeds[n];
                    let signatories = sorted(c.signatories.clone());
                    let stakeholders = sorted(c.stakeholders.clone());
                    let (id, instance) = derive_created(
                        self.ctx,
                        &NewInView {
                            package_name: &c.package_name,
                            package_id: &c.package_id,
                            module: &c.module,
                            name: &c.name,
                            arg: &c.arg,
                            hash_arg: &c.hash_arg,
                            signatories: &signatories,
                            stakeholders: &stakeholders,
                            key: c.key.as_ref(),
                            path: &[],
                        },
                        &Derivation {
                            now: self.now,
                            vpd_salt: &pd_salt,
                            create_index: created_here.len() as i32,
                            transaction_uuid: &self.uuid,
                            node_seed: &seed,
                            view_position: &position,
                        },
                    )?;
                    let bytes = instance.encode();
                    self.created.push(StoredContract {
                        contract_id_hex: id.clone(),
                        instance: bytes.clone(),
                        package_id: c.package_id.clone(),
                        module: c.module.clone(),
                        name: c.name.clone(),
                        signatories,
                        stakeholders,
                    });
                    self.created_nodes.push(*n);
                    created_here.push((bytes, id));
                }
                // a lookup that found a contract has it as an input; a rollback is never a node of a view
                Action::Lookup(_, found) => {
                    for contract in found {
                        if !inputs.iter().any(|i| i.1 == contract.contract_id_hex)
                            && !created_here
                                .iter()
                                .any(|(_, id)| *id == contract.contract_id_hex)
                            && !subview_created.contains(&contract.contract_id_hex)
                        {
                            inputs.push((
                                contract.instance.clone(),
                                contract.contract_id_hex.clone(),
                                false,
                            ));
                        }
                    }
                }
                Action::Rollback { .. } => {}
                Action::Fetch { contract, .. } => {
                    if !inputs.iter().any(|i| i.1 == contract.contract_id_hex)
                        && !created_here
                            .iter()
                            .any(|(_, id)| *id == contract.contract_id_hex)
                        && !subview_created.contains(&contract.contract_id_hex)
                    {
                        inputs.push((
                            contract.instance.clone(),
                            contract.contract_id_hex.clone(),
                            false,
                        ));
                    }
                }
                Action::Exercise {
                    contract,
                    consuming,
                    ..
                } => {
                    let is_created_here = created_here
                        .iter()
                        .any(|(_, id)| *id == contract.contract_id_hex);
                    let is_created_in_subview = subview_created.contains(&contract.contract_id_hex);
                    if is_created_here {
                        if *consuming {
                            consumed.insert(contract.contract_id_hex.clone());
                        }
                    } else if is_created_in_subview {
                        if *consuming
                            && !created_in_subview_archived_in_core
                                .contains(&contract.contract_id_hex)
                        {
                            created_in_subview_archived_in_core
                                .push(contract.contract_id_hex.clone());
                        }
                    } else {
                        if !inputs.iter().any(|i| i.1 == contract.contract_id_hex) {
                            inputs.push((
                                contract.instance.clone(),
                                contract.contract_id_hex.clone(),
                                false,
                            ));
                        }
                        if *consuming {
                            consumed.insert(contract.contract_id_hex.clone());
                        }
                    }
                }
            }
        }
        let inputs: Vec<(Vec<u8>, bool)> = inputs
            .into_iter()
            .map(|(bytes, id, _)| {
                let c = consumed.contains(&id);
                (bytes, c)
            })
            .collect();
        let input_refs: Vec<(&[u8], bool)> =
            inputs.iter().map(|(b, c)| (b.as_slice(), *c)).collect();
        let created_refs: Vec<(&[u8], bool)> = created_here
            .iter()
            .map(|(b, id)| (b.as_slice(), consumed.contains(id)))
            .collect();
        let template_of = |c: &StoredContract| {
            format!(
                "{}:{}:{}",
                c.package_id,
                c.module.join("."),
                c.name.join(".")
            )
        };
        // [CANTON-NOTE: SEMANTICS] A node reached its contract BY KEY when one of its key uses resolves to that very contract. A key use that
        // only states a resolution (a free key: the consumed input's old key of `Rename`, S-SPL-022; the exercised contract's own key beside a
        // `lookupByKey`, S-SPL-023) does not make it a by-key one (measured: with `by_key` set from any key use, p1 refused the S-SPL-022
        // `Rename`).
        let node_contract = match &self.tx.nodes[nv.node] {
            Action::Exercise { contract, .. } | Action::Fetch { contract, .. } => {
                Some(contract.contract_id_hex.as_str())
            }
            _ => None,
        };
        let by_key = node_contract.is_some()
            && self
                .tx
                .keys
                .iter()
                .any(|(n, k)| *n == nv.node && k.contract_id.as_deref() == node_contract);
        let description = match &self.tx.nodes[nv.node] {
            Action::Create(_) => mw::create_description(&created_here[0].1, &self.seeds[&nv.node]),
            Action::Exercise {
                contract,
                choice,
                argument,
                actors,
                interface_id,
                ..
            } => mw::exercise_description_with_by_key(
                &mw::ExerciseSpec {
                    interface_id: interface_id.as_deref(),
                    package_preference: &self.preference_of(nv)?,
                    contract_id_hex: &contract.contract_id_hex,
                    template_id: &template_of(contract),
                    choice,
                    chosen_value: &crate::submit::versioned_as(
                        // [CANTON-NOTE: SEMANTICS] Official `Speedy` (`assignSerializationVersion`) assigns V2 ("2") if the exercised contract
                        // itself has a key and V1 ("2.1") otherwise, even when the same Daml-LF 2.3 package or another node in the transaction uses keys.
                        if let Some(has_key) =
                            crate::contract_wire::instance_has_key(&contract.instance)
                        {
                            if has_key {
                                "2"
                            } else {
                                "2.1"
                            }
                        } else if let Some(&create_node) =
                            self.tx.temp_ids.get(&contract.contract_id_hex)
                        {
                            match self.tx.nodes.get(create_node) {
                                Some(Action::Create(c)) if c.key.is_some() => "2",
                                _ => "2.1",
                            }
                        } else {
                            "2.1"
                        },
                        argument.as_ref().ok_or_else(|| {
                            "the chosen value of the exercise that roots a view is not known"
                                .to_string()
                        })?,
                    ),
                    actors: &actors.iter().map(String::as_str).collect::<Vec<_>>(),
                    node_seed: &self.seeds[&nv.node],
                },
                by_key,
            ),
            Action::Rollback { .. } => return Err("a rollback is not a node of a view".into()),
            Action::Lookup(..) => {
                return Err(
                    "a lookup by key cannot root a view (its description is not built)".into(),
                )
            }
            Action::Fetch {
                contract,
                actors,
                interface_id,
            } => mw::fetch_description_with_by_key(
                &contract.contract_id_hex,
                &actors.iter().map(String::as_str).collect::<Vec<_>>(),
                &template_of(contract),
                interface_id.as_deref(),
                by_key,
            ),
        };
        let mut resolved_keys = self.resolved_keys_of(&core)?;
        // [CANTON-NOTE: SEMANTICS] A view states the key resolutions of its subviews too: `NextGenTransactionTreeFactory` adds each child
        // view's `keyResolution` to the parent's (`viewKeyMaintainers`, `observedKeyContractIds`). Measured (S-G11-001): p1, an informee of
        // both views, rebuilt the parent of a subview that fetches a keyed contract with that key in its `resolved_keys` and refused ours
        // without it (`ViewReconstructionError`).
        for child in &children {
            for e in &child.resolved {
                let hash = e.key.as_ref().map(|k| k.hash.clone());
                match resolved_keys
                    .iter_mut()
                    .find(|known| known.key.as_ref().map(|k| k.hash.clone()) == hash)
                {
                    Some(known) => {
                        for id in &e.contract_ids {
                            if !known.contract_ids.contains(id) {
                                known.contract_ids.push(id.clone());
                            }
                        }
                    }
                    None => resolved_keys.push(e.clone()),
                }
            }
        }
        let pd = mw::view_participant_data_of(
            &input_refs,
            &created_refs,
            created_in_subview_archived_in_core,
            resolved_keys.clone(),
            description,
            &pd_salt,
            nv.in_rollback,
        );
        let informees: Vec<String> = nv.informees.iter().cloned().collect();
        let quorums: Vec<Vec<(String, i32)>> = nv
            .quorums
            .iter()
            .map(|q| q.iter().map(|p| (p.clone(), 1)).collect())
            .collect();
        let cd = common_data_of(&informees, &quorums, &cd_salt);
        let child_full: Vec<mw::Tree> = children.iter().map(|c| c.full.clone()).collect();
        let child_informee: Vec<mw::Tree> = children.iter().map(|c| c.informee.clone()).collect();
        let full = mw::view_node(
            &mw::Tree::leaf(&cd),
            &mw::Tree::leaf(&pd),
            &mw::merkle_seq(&child_full),
        );
        let informee = mw::view_node(
            &mw::Tree::leaf(&cd),
            &mw::Tree::blinded(pd.root_hash()),
            &mw::merkle_seq(&child_informee),
        );
        let key: [u8; 16] = random.fresh("view-key")[..16]
            .try_into()
            .expect("SeededRandom::fresh always yields 32 bytes");
        let members = nv
            .informees
            .iter()
            .flat_map(|p| (self.hosting)(p))
            .collect();
        let created_ids = if nv.in_rollback {
            BTreeSet::new()
        } else {
            let mut ids = subview_created;
            ids.extend(created_here.iter().map(|(_, id)| id.clone()));
            ids
        };
        Ok(BuiltView {
            key,
            full,
            informee,
            cd,
            pd,
            children,
            created_ids,
            members,
            resolved: resolved_keys,
        })
    }
}

/// The node seeds of the transaction: the root's is drawn, a child's is the parent's derived by the child's index among **all** its siblings
/// (a fetch takes an index, measured and `S-SPL-002`).
pub(super) fn node_seeds(
    tx: &Transaction,
    root_seeds: &[[u8; 32]],
    random: &mut dyn Randomness,
) -> BTreeMap<usize, [u8; 32]> {
    fn go(tx: &Transaction, node: usize, seed: [u8; 32], out: &mut BTreeMap<usize, [u8; 32]>) {
        out.insert(node, seed);
        // a rollback takes no index: its children count as children of the exercise around it
        fn flat(tx: &Transaction, node: usize, out: &mut Vec<usize>) {
            for c in children_of(&tx.nodes[node]) {
                match &tx.nodes[*c] {
                    Action::Rollback { .. } => flat(tx, *c, out),
                    _ => out.push(*c),
                }
            }
        }
        let mut kids = Vec::new();
        flat(tx, node, &mut kids);
        for (i, c) in kids.iter().enumerate() {
            if !matches!(tx.nodes[*c], Action::Fetch { .. } | Action::Lookup(..)) {
                go(tx, *c, ci::derive_node_seed(&seed, i as i32), out);
            }
        }
    }
    let mut out = BTreeMap::new();
    for (i, r) in tx.roots.iter().enumerate() {
        if !matches!(tx.nodes[*r], Action::Fetch { .. } | Action::Lookup(..)) {
            let seed = match root_seeds {
                [] => random.fresh("root-node-seed"),
                [only] => *only,
                many => many
                    .get(i)
                    .copied()
                    .unwrap_or_else(|| random.fresh("root-node-seed")),
            };
            go(tx, *r, seed, &mut out);
        }
    }
    out
}

/// What the light tree of `target` reveals: the path from the root to it unblinded in its structure, every other view a hash, the views above
/// `target` without their data. `chain` is the views from the root to `target`.
pub(super) fn light_node(chain: &[&BuiltView]) -> mw::Tree {
    let head = chain[0];
    let last = chain.len() == 1;
    let (cd, pd) = if last {
        (mw::Tree::leaf(&head.cd), mw::Tree::leaf(&head.pd))
    } else {
        (
            mw::Tree::blinded(head.cd.root_hash()),
            mw::Tree::blinded(head.pd.root_hash()),
        )
    };
    let subviews: Vec<mw::Tree> = head
        .children
        .iter()
        .map(|c| {
            if !last && std::ptr::eq(c, chain[1]) {
                light_node(&chain[1..])
            } else {
                mw::Tree::blinded(c.full.hash.clone())
            }
        })
        .collect();
    let seq = mw::merkle_seq(&subviews);
    // [CANTON-NOTE: SEMANTICS] In the light tree of the target view the subviews are blinded **as a whole**: the `MerkleSeq` itself is a
    // blinded node (`LightTransactionViewTree.findTheView` demands `subviews.areFullyBlinded`, which is `MerkleSeq.isFullyBlinded`: the
    // root is blinded). A seq whose root is unblinded and whose elements are blinded is refused as "Invalid blinding in a light
    // transaction view tree" (measured, S-G11-001: p1 refused the parent of a subview it also received).
    let seq = match (&seq.root_hash, last) {
        (Some(root), true) => mw::blinded_seq(root),
        _ => seq,
    };
    mw::view_node(&cd, &pd, &seq)
}

/// Replaces the contract ids in `value` that `map` names.
fn substitute_ids(value: &LfValue, map: &BTreeMap<String, String>) -> LfValue {
    let go = |v: &LfValue| substitute_ids(v, map);
    match value {
        LfValue::ContractId(id) => {
            LfValue::ContractId(map.get(id).cloned().unwrap_or_else(|| id.clone()))
        }
        LfValue::List(items) => LfValue::List(items.iter().map(go).collect()),
        LfValue::Record(items) => LfValue::Record(items.iter().map(go).collect()),
        LfValue::Optional(inner) => LfValue::Optional(inner.as_ref().map(|v| Box::new(go(v)))),
        LfValue::Variant(c, inner) => LfValue::Variant(c.clone(), Box::new(go(inner))),
        LfValue::TextMap(entries) => {
            LfValue::TextMap(entries.iter().map(|(k, v)| (k.clone(), go(v))).collect())
        }
        LfValue::GenMap(entries) => {
            LfValue::GenMap(entries.iter().map(|(k, v)| (go(k), go(v))).collect())
        }
        other => other.clone(),
    }
}

fn substitute_hash_with_bytes(
    value: &ci::HashValue,
    byte_map: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> ci::HashValue {
    let go = |v: &ci::HashValue| substitute_hash_with_bytes(v, byte_map);
    match value {
        ci::HashValue::ContractId(bytes) => ci::HashValue::ContractId(
            byte_map
                .get(bytes)
                .cloned()
                .unwrap_or_else(|| bytes.clone()),
        ),
        ci::HashValue::Optional(inner) => {
            ci::HashValue::Optional(inner.as_ref().map(|v| Box::new(go(v))))
        }
        ci::HashValue::List(items) => ci::HashValue::List(items.iter().map(go).collect()),
        ci::HashValue::Variant {
            module,
            name,
            constructor,
            rank,
            value,
        } => ci::HashValue::Variant {
            module: module.clone(),
            name: name.clone(),
            constructor: constructor.clone(),
            rank: *rank,
            value: Box::new(go(value)),
        },
        ci::HashValue::TextMap(entries) => {
            ci::HashValue::TextMap(entries.iter().map(|(k, v)| (k.clone(), go(v))).collect())
        }
        ci::HashValue::GenMap(entries) => {
            ci::HashValue::GenMap(entries.iter().map(|(k, v)| (go(k), go(v))).collect())
        }
        ci::HashValue::Record {
            module,
            name,
            fields,
        } => ci::HashValue::Record {
            module: module.clone(),
            name: name.clone(),
            fields: fields.iter().map(|(k, v)| (k.clone(), go(v))).collect(),
        },
        other => other.clone(),
    }
}

fn substitute_hash_ids(value: &ci::HashValue, map: &BTreeMap<String, String>) -> ci::HashValue {
    let mut byte_map = BTreeMap::new();
    for (from, to) in map {
        if let (Ok(kb), Ok(vb)) = (hex::decode(from), hex::decode(to)) {
            byte_map.insert(kb, vb);
        }
    }
    if byte_map.is_empty() {
        return value.clone();
    }
    substitute_hash_with_bytes(value, &byte_map)
}

pub(super) fn with_ids(
    tx: &Transaction,
    map: &BTreeMap<String, String>,
    contracts: &BTreeMap<String, StoredContract>,
) -> Transaction {
    let mut out = tx.clone();
    for node in &mut out.nodes {
        match node {
            Action::Exercise {
                argument, contract, ..
            } => {
                if let Some(a) = argument {
                    *a = substitute_ids(a, map);
                }
                if let Some(real) = contracts.get(&contract.contract_id_hex) {
                    *contract = real.clone();
                }
            }
            Action::Fetch { contract, .. } => {
                if let Some(real) = contracts.get(&contract.contract_id_hex) {
                    *contract = real.clone();
                }
            }
            Action::Create(created) => {
                created.arg = substitute_ids(&created.arg, map);
                created.hash_arg = substitute_hash_ids(&created.hash_arg, map);
                if let Some(ref mut key) = created.key {
                    key.value = substitute_ids(&key.value, map);
                    key.hash_value = substitute_hash_ids(&key.hash_value, map);
                }
            }
            Action::Lookup(key_use, stored) => {
                key_use.value = substitute_ids(&key_use.value, map);
                key_use.hash_value = substitute_hash_ids(&key_use.hash_value, map);
                if let Some(ref mut cid) = key_use.contract_id {
                    if let Some(real) = map.get(cid) {
                        *cid = real.clone();
                    }
                }
                for contract in stored.iter_mut() {
                    if let Some(real) = contracts.get(&contract.contract_id_hex) {
                        *contract = real.clone();
                    }
                }
            }
            Action::Rollback { .. } => {}
        }
    }
    for (_, key_use) in &mut out.keys {
        key_use.value = substitute_ids(&key_use.value, map);
        key_use.hash_value = substitute_hash_ids(&key_use.hash_value, map);
        if let Some(ref mut cid) = key_use.contract_id {
            if let Some(real) = map.get(cid) {
                *cid = real.clone();
            }
        }
    }
    out
}

/// `NextGenTransactionTreeFactory.buildPackagePreference`: the packages the package names of the view `nv` resolve to.
///
/// [CANTON-NOTE: SEMANTICS] Every exercise or fetch **through an interface** anywhere in the view (its core and its subviews) resolves the
/// contract's template by package name, so it adds `package name -> the contract's package` (the template's, not the interface's: measured
/// S-SPL-035). The confirmer reinterprets with these names (`ModelConformanceChecker.buildPackageNameMap`) and says `UnresolvedPackageName`
/// for a body whose name the view does not state (UNRESOLVED U-63: only the root exercise was looked at, and a nested `fetchFromInterface`
/// such as Splice's `AmuletRules_Mint` was refused).
pub(super) fn package_preference(tx: &Transaction, nv: &NewView) -> Result<Vec<String>, String> {
    let mut by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    collect_preference(tx, nv, &mut by_name);
    if let Some((name, ids)) = by_name.iter().find(|(_, ids)| ids.len() > 1) {
        // [CANTON-NOTE: INVARIANT] `ConflictingPackagePreferenceError`: one name cannot stand for two packages in one view.
        return Err(format!(
            "the view resolves the package name {name} to several packages: {ids:?}"
        ));
    }
    let ids: BTreeSet<String> = by_name.into_values().flatten().collect();
    Ok(ids.into_iter().collect())
}

fn collect_preference(
    tx: &Transaction,
    nv: &NewView,
    out: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let mut add = |node: usize| {
        if let Action::Exercise {
            contract,
            interface_id: Some(_),
            ..
        }
        | Action::Fetch {
            contract,
            interface_id: Some(_),
            ..
        } = &tx.nodes[node]
        {
            // [CANTON-NOTE: DEFENSIVE] An instance that does not decode names no package: its id stands in, so it adds its package
            // without taking part in the conflict check.
            let name = crate::contract_wire::instance_package_name(&contract.instance)
                .unwrap_or_else(|| contract.package_id.clone());
            out.entry(name)
                .or_default()
                .insert(contract.package_id.clone());
        }
    };
    add(nv.node);
    let mut nested = Vec::new();
    for t in &nv.tail {
        match t {
            Tail::Same(n) => add(*n),
            Tail::New(v) => nested.push(&**v),
        }
    }
    for v in nested {
        collect_preference(tx, v, out);
    }
}
