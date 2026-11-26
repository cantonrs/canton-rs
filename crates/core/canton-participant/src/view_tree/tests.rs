use super::*;

fn contract(id: &str, signatories: &[&str], stakeholders: &[&str]) -> StoredContract {
    StoredContract {
        contract_id_hex: id.into(),
        instance: vec![],
        package_id: "p".into(),
        module: vec!["M".into()],
        name: vec!["T".into()],
        signatories: signatories.iter().map(|s| s.to_string()).collect(),
        stakeholders: stakeholders.iter().map(|s| s.to_string()).collect(),
    }
}

fn contract_with_instance(id: &str, signatories: &[&str], stakeholders: &[&str]) -> StoredContract {
    let sig_vec: Vec<String> = signatories.iter().map(|s| s.to_string()).collect();
    let st_vec: Vec<String> = stakeholders.iter().map(|s| s.to_string()).collect();
    let instance = crate::contract_wire::ContractInstance {
        contract_id: hex::decode(id).expect("hex contract id"),
        package_name: "pkg".into(),
        package_id: "11".repeat(32),
        module: vec!["M".into()],
        name: vec!["T".into()],
        arg: LfValue::Unit,
        signatories: sig_vec.iter().cloned().collect(),
        stakeholders: st_vec.iter().cloned().collect(),
        created_at_micros: 1_700_000_000_000_000,
        authentication_data: vec![0u8; 32],
        key: None,
    }
    .encode();
    StoredContract {
        contract_id_hex: id.into(),
        instance,
        package_id: "11".repeat(32),
        module: vec!["M".into()],
        name: vec!["T".into()],
        signatories: sig_vec,
        stakeholders: st_vec,
    }
}

fn create(signatories: &[&str]) -> Action {
    Action::Create(NewContract {
        package_name: "n".into(),
        package_id: "p".into(),
        module: vec!["M".into()],
        name: vec!["T".into()],
        arg: LfValue::Unit,
        hash_arg: ci::HashValue::Unit,
        signatories: signatories.iter().map(|s| s.to_string()).collect(),
        stakeholders: signatories.iter().map(|s| s.to_string()).collect(),
        key: None,
    })
}

fn exercise(c: StoredContract, consuming: bool, actors: &[&str], children: Vec<usize>) -> Action {
    Action::Exercise {
        contract: c,
        choice: "C".into(),
        argument: Some(LfValue::Unit),
        consuming,
        actors: actors.iter().map(|s| s.to_string()).collect(),
        choice_observers: vec![],
        children,
        interface_id: None,
    }
}

fn q(parties: &[&str]) -> BTreeSet<String> {
    parties.iter().map(|s| s.to_string()).collect()
}

#[test]
fn indices_pair_the_lowest_layer_first() {
    assert_eq!(seq_indices(1), vec![Vec::<bool>::new()]);
    assert_eq!(seq_indices(2), vec![vec![false], vec![true]]);
    // the positions p1 gave three sibling subviews (S-SPL-003)
    assert_eq!(
        seq_indices(3),
        vec![vec![false, false], vec![true, false], vec![true]]
    );
}

/// The tree fixture of `contracts-tree`, everybody on one participant: one view whose quorums are the nodes' in order, without duplicates
/// (what the official participant rebuilt, S-SPL-002).
#[test]
fn a_tree_on_one_participant_is_one_view_with_the_quorums_of_its_nodes() {
    let driver = contract("d", &["gwen"], &["gwen", "erin"]);
    let peer = contract("p", &["erin"], &["erin", "gwen"]);
    let held = contract("h", &["erin"], &["erin", "gwen"]);
    let tx = Transaction {
        nodes: vec![
            exercise(driver, false, &["gwen"], vec![1, 2, 4]),
            Action::Fetch {
                contract: peer,
                actors: vec!["gwen".into()],
                interface_id: None,
            },
            exercise(held, true, &["gwen"], vec![3]),
            create(&["erin", "gwen"]),
            create(&["gwen"]),
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |_: &str| -> BTreeSet<String> { q(&["p1"]) };
    let views = decompose(&tx, "admin", &hosting);
    assert_eq!(views.len(), 1);
    assert_eq!(
        views[0].quorums,
        vec![q(&["admin", "gwen"]), q(&["erin", "gwen"]), q(&["gwen"])]
    );
    assert!(views[0].tail.iter().all(|t| matches!(t, Tail::Same(_))));
}

/// A child whose informees are hosted by a participant the parent's are not has a view of its own, and its quorum is not the parent's
/// (`TransactionViewDecompositionFactory.buildChildView`; `Confirm.Driver.Run`).
#[test]
fn a_child_hosted_elsewhere_is_a_subview_with_its_own_quorum() {
    let driver = contract("d", &["gwen"], &["gwen"]);
    let held = contract("h", &["erin"], &["erin", "gwen"]);
    let tx = Transaction {
        nodes: vec![
            exercise(driver, false, &["gwen"], vec![1]),
            exercise(held, true, &["gwen"], vec![]),
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |party: &str| -> BTreeSet<String> {
        if party == "erin" {
            q(&["p1", "rust"])
        } else {
            q(&["rust"])
        }
    };
    let views = decompose(&tx, "admin", &hosting);
    assert_eq!(views[0].quorums, vec![q(&["admin", "gwen"])]);
    let [Tail::New(child)] = views[0].tail.as_slice() else {
        panic!("one subview")
    };
    assert_eq!(child.quorums, vec![q(&["erin", "gwen"])]);
}

/// Depth three, everybody on one participant: root exercise, an exercise below it, another below that with a create at the bottom (the
/// shape of Splice's `DsoRules_*` and `AmuletRules_*` choices). One view; the quorums are the nodes' in traversal order without duplicates,
/// and the views of a deeper tree do not change the root's.
#[test]
fn a_chain_of_three_exercises_on_one_participant_is_one_view() {
    let a = contract("a", &["dso"], &["dso"]);
    let b = contract("b", &["dso", "sv"], &["dso", "sv"]);
    let c = contract("c", &["sv"], &["sv", "dso"]);
    let tx = Transaction {
        nodes: vec![
            exercise(a, false, &["dso"], vec![1]),
            exercise(b, true, &["sv"], vec![2]),
            exercise(c, true, &["sv"], vec![3]),
            create(&["sv", "dso"]),
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |_: &str| -> BTreeSet<String> { q(&["p1"]) };
    let views = decompose(&tx, "admin", &hosting);
    assert_eq!(views.len(), 1);
    assert_eq!(
        views[0].quorums,
        vec![q(&["admin", "dso"]), q(&["dso", "sv"]), q(&["sv"])]
    );
    // every node below the root is in the root's view: the second level, the third and the create
    let same: Vec<usize> = views[0]
        .tail
        .iter()
        .map(|t| match t {
            Tail::Same(n) => *n,
            Tail::New(_) => panic!("a subview in a one-participant tree"),
        })
        .collect();
    assert_eq!(same, vec![1, 2, 3]);
}

/// Depth three where the bottom exercise is hosted elsewhere: the chain's first two levels share the root's view, the third level is a
/// subview of the second (a subview is a child of the view that holds its parent node), and its quorum is its own.
#[test]
fn the_third_level_hosted_elsewhere_is_a_subview_of_the_second() {
    let a = contract("a", &["dso"], &["dso"]);
    let b = contract("b", &["dso"], &["dso"]);
    let c = contract("c", &["sv"], &["sv", "dso"]);
    let tx = Transaction {
        nodes: vec![
            exercise(a, false, &["dso"], vec![1]),
            exercise(b, true, &["dso"], vec![2]),
            exercise(c, true, &["dso"], vec![]),
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |party: &str| -> BTreeSet<String> {
        if party == "sv" {
            q(&["p1", "rust"])
        } else {
            q(&["rust"])
        }
    };
    let views = decompose(&tx, "admin", &hosting);
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].quorums, vec![q(&["admin", "dso"]), q(&["dso"])]);
    // the second level is in the root's view, the third is a subview below it
    let [Tail::Same(1), Tail::New(third)] = views[0].tail.as_slice() else {
        panic!("a node of the same view and one subview")
    };
    assert_eq!(third.node, 2);
    // signatories of the exercised contract (`sv`) and its acting party (`dso`)
    assert_eq!(third.quorums, vec![q(&["dso", "sv"])]);
    // positions list one entry per level, innermost first: a lone root view is `[[]]`, its only subview `[[], []]`
    let positions = view_positions(&tx, "admin", &hosting);
    assert_eq!(positions.len(), 2);
    assert_eq!(positions[0].0, vec![Vec::<bool>::new()]);
    assert_eq!(positions[1].0, vec![Vec::<bool>::new(), Vec::<bool>::new()]);
}

#[test]
fn temp_ids_with_new_subview_substitutes_created_cids_and_converges() {
    struct FixedRand(u8);
    impl crate::submit::Randomness for FixedRand {
        fn fresh(&mut self, _label: &str) -> [u8; 32] {
            self.0 = self.0.wrapping_add(1);
            [self.0; 32]
        }
    }

    let id = crate::topology_wire::ParticipantIdentity::generate("p1");
    let id2 = crate::topology_wire::ParticipantIdentity::generate("p2");
    let ctx = crate::submit::Context {
        identity: &id,
        synchronizer: "sync::1220",
        mediator_group: 0,
        user_id: "user",
    };
    let peer = crate::submit::Peer {
        member: id.member(),
        encryption_spki: id.encryption_spki().to_vec(),
        fingerprint: id.encryption_fingerprint(),
    };
    let peer2 = crate::submit::Peer {
        member: id2.member(),
        encryption_spki: id2.encryption_spki().to_vec(),
        fingerprint: id2.encryption_fingerprint(),
    };
    let temp_child = "00".repeat(33) + "aa";
    let root_c = contract(&("00".repeat(33) + "bb"), &["alice"], &["alice"]);
    let child_create = Action::Create(NewContract {
        package_name: "pkg".into(),
        package_id: "11".repeat(32),
        module: vec!["M".into()],
        name: vec!["Child".into()],
        arg: LfValue::Unit,
        hash_arg: ci::HashValue::Unit,
        signatories: vec!["alice".into()],
        stakeholders: vec!["alice".into(), "bob".into()],
        key: None,
    });
    let parent_ref_create = Action::Create(NewContract {
        package_name: "pkg".into(),
        package_id: "11".repeat(32),
        module: vec!["M".into()],
        name: vec!["Receipt".into()],
        arg: LfValue::Record(vec![LfValue::ContractId(temp_child.clone())]),
        hash_arg: ci::HashValue::Record {
            module: vec!["M".into()],
            name: vec!["Receipt".into()],
            fields: vec![(
                "refCid".into(),
                ci::HashValue::ContractId(hex::decode(&temp_child).expect("hex")),
            )],
        },
        signatories: vec!["alice".into()],
        stakeholders: vec!["alice".into()],
        key: None,
    });
    let temp_receipt = "00".repeat(33) + "cc";
    let mut tx = Transaction {
        nodes: vec![
            exercise(root_c, true, &["alice"], vec![1, 2]),
            child_create,
            parent_ref_create,
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: BTreeMap::from([(temp_child.clone(), 1usize), (temp_receipt, 2usize)]),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let p1_member = id.member();
    let p2_member = id2.member();
    let hosting = |party: &str| -> BTreeSet<String> {
        if party == "bob" {
            q(&[&p1_member, &p2_member])
        } else {
            q(&[&p1_member])
        }
    };
    let views = decompose(&tx, &id.uid(), &hosting);
    assert!(has_subview(&views));

    let built = build_planned(
        &ctx,
        &tx,
        &[peer, peer2],
        &hosting,
        &["alice".into()],
        "cmd-subview-temp",
        1_700_000_000_000_000,
        &[],
        &mut FixedRand(1),
    )
    .expect("build_planned with subview temp_ids");
    assert_eq!(built.created.len(), 2);
    let pos_child = built
        .created_nodes
        .iter()
        .position(|n| *n == 1)
        .expect("child node");
    let pos_receipt = built
        .created_nodes
        .iter()
        .position(|n| *n == 2)
        .expect("receipt node");
    let derived_child = &built.created[pos_child].contract_id_hex;
    assert_ne!(derived_child, &temp_child);
    let receipt_bytes = &built.created[pos_receipt].instance;
    let derived_bytes = hex::decode(derived_child).expect("derived hex");
    assert!(
        receipt_bytes
            .windows(derived_bytes.len())
            .any(|w| w == derived_bytes.as_slice()),
        "parent create instance must embed derived subview child ContractId"
    );
    let _ = &mut tx;
}

#[test]
fn same_view_transient_create_and_consume_sets_consumed_in_core() {
    struct FixedRand(u8);
    impl crate::submit::Randomness for FixedRand {
        fn fresh(&mut self, _label: &str) -> [u8; 32] {
            self.0 = self.0.wrapping_add(1);
            [self.0; 32]
        }
    }

    let id = crate::topology_wire::ParticipantIdentity::generate("p1");
    let ctx = crate::submit::Context {
        identity: &id,
        synchronizer: "sync::1220",
        mediator_group: 0,
        user_id: "user",
    };
    let peer = crate::submit::Peer {
        member: id.member(),
        encryption_spki: id.encryption_spki().to_vec(),
        fingerprint: id.encryption_fingerprint(),
    };
    let p1_member = id.member();
    let hosting = |_: &str| -> BTreeSet<String> { q(&[&p1_member]) };
    let root_c = contract_with_instance(&("00".repeat(33) + "aa"), &["alice"], &["alice"]);
    let temp_child = "00".repeat(33) + "bb";
    let transient_stub = contract(&temp_child, &["alice"], &["alice"]);
    let child_create = Action::Create(NewContract {
        package_name: "pkg".into(),
        package_id: "11".repeat(32),
        module: vec!["M".into()],
        name: vec!["Child".into()],
        arg: LfValue::Unit,
        hash_arg: ci::HashValue::Unit,
        signatories: vec!["alice".into()],
        stakeholders: vec!["alice".into()],
        key: None,
    });
    let tx = Transaction {
        nodes: vec![
            exercise(root_c, false, &["alice"], vec![1, 2]),
            child_create,
            exercise(transient_stub, true, &["alice"], vec![]),
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: BTreeMap::from([(temp_child, 1usize)]),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let built = build_planned(
        &ctx,
        &tx,
        &[peer],
        &hosting,
        &["alice".into()],
        "cmd-same-view-transient",
        1_700_000_000_000_000,
        &[],
        &mut FixedRand(10),
    )
    .expect("build same-view transient tx");
    let view_env = &built.envelopes.last().expect("view envelope").1;
    let decrypted = crate::view_receive::decrypt_views(
        view_env,
        &id.encryption_fingerprint(),
        id.encryption_secret(),
    )
    .expect("decrypt view");
    let revealed =
        crate::view_receive::revealed_views(decrypted.view_trees[0].tree.as_ref().expect("tree"))
            .expect("reveal views");
    assert_eq!(revealed.len(), 1);
    let pd = &revealed[0].participant_data;
    assert_eq!(pd.core_inputs.len(), 1);
    assert_eq!(pd.created_core.len(), 1);
    assert!(pd.created_core[0].consumed_in_core);
    assert!(pd.created_in_subview_archived_in_core.is_empty());
    let effects = crate::view_acs::effects_of(&revealed[0]).expect("effects");
    assert!(effects.creates.is_empty());
    assert!(effects.consumes.is_empty());
}

#[test]
fn subview_create_consumed_in_parent_core_sets_created_in_subview_archived_in_core() {
    struct FixedRand(u8);
    impl crate::submit::Randomness for FixedRand {
        fn fresh(&mut self, _label: &str) -> [u8; 32] {
            self.0 = self.0.wrapping_add(1);
            [self.0; 32]
        }
    }

    let id = crate::topology_wire::ParticipantIdentity::generate("p1");
    let id2 = crate::topology_wire::ParticipantIdentity::generate("p2");
    let ctx = crate::submit::Context {
        identity: &id,
        synchronizer: "sync::1220",
        mediator_group: 0,
        user_id: "user",
    };
    let peer = crate::submit::Peer {
        member: id.member(),
        encryption_spki: id.encryption_spki().to_vec(),
        fingerprint: id.encryption_fingerprint(),
    };
    let peer2 = crate::submit::Peer {
        member: id2.member(),
        encryption_spki: id2.encryption_spki().to_vec(),
        fingerprint: id2.encryption_fingerprint(),
    };
    let p1_member = id.member();
    let p2_member = id2.member();
    let hosting = |party: &str| -> BTreeSet<String> {
        if party == "bob" {
            q(&[&p1_member, &p2_member])
        } else {
            q(&[&p1_member])
        }
    };
    let root_c = contract_with_instance(&("00".repeat(33) + "aa"), &["alice"], &["alice"]);
    let sub_c = contract_with_instance(
        &("00".repeat(33) + "cc"),
        &["alice", "bob"],
        &["alice", "bob"],
    );
    let temp_child = "00".repeat(33) + "bb";
    let transient_stub = contract(&temp_child, &["alice"], &["alice"]);
    let child_create = Action::Create(NewContract {
        package_name: "pkg".into(),
        package_id: "11".repeat(32),
        module: vec!["M".into()],
        name: vec!["Child".into()],
        arg: LfValue::Unit,
        hash_arg: ci::HashValue::Unit,
        signatories: vec!["alice".into()],
        stakeholders: vec!["alice".into()],
        key: None,
    });
    let tx = Transaction {
        nodes: vec![
            exercise(root_c, false, &["alice"], vec![1, 3]),
            exercise(sub_c, false, &["alice"], vec![2]),
            child_create,
            exercise(transient_stub, true, &["alice"], vec![]),
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: BTreeMap::from([(temp_child, 2usize)]),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let built = build_planned(
        &ctx,
        &tx,
        &[peer, peer2],
        &hosting,
        &["alice".into()],
        "cmd-subview-archived-in-parent",
        1_700_000_000_000_000,
        &[],
        &mut FixedRand(20),
    )
    .expect("build subview transient tx");
    let child_id = built.created[0].contract_id_hex.clone();
    let mut parent_views = Vec::new();
    for (_, env) in &built.envelopes {
        if let Ok(dec) = crate::view_receive::decrypt_views(
            env,
            &id.encryption_fingerprint(),
            id.encryption_secret(),
        ) {
            for vt in dec.view_trees {
                if let Some(tree) = vt.tree.as_ref() {
                    if let Ok(rvs) = crate::view_receive::revealed_views(tree) {
                        parent_views.extend(rvs);
                    }
                }
            }
        }
    }
    let root_view = parent_views
        .iter()
        .find(|v| v.position.len() == 1)
        .expect("root view revealed");
    assert_eq!(root_view.participant_data.core_inputs.len(), 1);
    assert_eq!(
        root_view
            .participant_data
            .created_in_subview_archived_in_core,
        vec![child_id.clone()]
    );
    let root_effects = crate::view_acs::effects_of(root_view).expect("root effects");
    assert_eq!(root_effects.consumes, vec![child_id]);
}

fn named(id: &str, package_name: &str, package_id: &str, parties: &[&str]) -> StoredContract {
    let mut c = contract_with_instance(id, parties, parties);
    let instance = crate::contract_wire::ContractInstance {
        contract_id: hex::decode(id).expect("hex contract id"),
        package_name: package_name.into(),
        package_id: package_id.into(),
        module: vec!["M".into()],
        name: vec!["T".into()],
        arg: LfValue::Unit,
        signatories: q(parties),
        stakeholders: q(parties),
        created_at_micros: 1_700_000_000_000_000,
        authentication_data: vec![0u8; 32],
        key: None,
    };
    c.instance = instance.encode();
    c.package_id = package_id.into();
    c
}

fn via_interface(c: StoredContract) -> Action {
    Action::Fetch {
        contract: c,
        actors: vec!["erin".into()],
        interface_id: Some("ifacepkg:I:I".into()),
    }
}

fn preference_tx(nodes: Vec<Action>) -> Transaction {
    Transaction {
        nodes,
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    }
}

/// `buildPackagePreference` (UNRESOLVED U-63): a fetch through an interface **below** the root exercise names the fetched contract's
/// package; a plain fetch names none (the negative control: without the interface the view states no preference).
#[test]
fn a_nested_interface_fetch_states_its_package_in_the_root_exercise() {
    let root = contract_with_instance(&"0a".repeat(33), &["erin"], &["erin"]);
    let held = named(&"0b".repeat(33), "held", &"22".repeat(32), &["erin"]);
    let hosting = |_: &str| -> BTreeSet<String> { q(&["p1"]) };
    let tx = preference_tx(vec![
        exercise(root.clone(), false, &["erin"], vec![1]),
        via_interface(held.clone()),
    ]);
    let views = decompose(&tx, "admin", &hosting);
    assert_eq!(
        run::package_preference(&tx, &views[0]),
        Ok(vec!["22".repeat(32)])
    );
    let plain = preference_tx(vec![
        exercise(root, false, &["erin"], vec![1]),
        Action::Fetch {
            contract: held,
            actors: vec!["erin".into()],
            interface_id: None,
        },
    ]);
    let views = decompose(&plain, "admin", &hosting);
    assert_eq!(run::package_preference(&plain, &views[0]), Ok(Vec::new()));
}

/// The subviews count too (`go` walks a `NewView`'s tail nodes), and one name standing for two packages is refused
/// (`ConflictingPackagePreferenceError`).
#[test]
fn a_subview_interface_fetch_counts_and_one_name_for_two_packages_is_refused() {
    let root = contract_with_instance(&"0a".repeat(33), &["gwen"], &["gwen"]);
    let held = named(&"0b".repeat(33), "held", &"22".repeat(32), &["erin"]);
    let other = named(&"0c".repeat(33), "held", &"33".repeat(32), &["erin"]);
    let hosting = |party: &str| -> BTreeSet<String> {
        if party == "erin" {
            q(&["p1", "rust"])
        } else {
            q(&["p1"])
        }
    };
    let sub = preference_tx(vec![
        exercise(root.clone(), false, &["gwen"], vec![1]),
        exercise(
            contract("e", &["erin"], &["erin"]),
            true,
            &["gwen"],
            vec![2],
        ),
        via_interface(held.clone()),
    ]);
    let views = decompose(&sub, "admin", &hosting);
    assert!(views[0].tail.iter().any(|t| matches!(t, Tail::New(_))));
    assert_eq!(
        run::package_preference(&sub, &views[0]),
        Ok(vec!["22".repeat(32)])
    );
    let clash = preference_tx(vec![
        exercise(root, false, &["gwen"], vec![1, 2]),
        via_interface(held),
        via_interface(other),
    ]);
    let views = decompose(&clash, "admin", &hosting);
    assert!(
        run::package_preference(&clash, &views[0]).is_err_and(|e| e.contains("several packages"))
    );
}
