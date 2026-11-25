//! G5 5.6 (S-NET-005): the transaction-protocol leaf nodes built by Rust equal the ones the node's Scala classes build,
//! byte for byte and hash for hash. Run through `scripts/verify-merkle-views.sh`, which prints the node's values.
#![cfg(feature = "sequencer-tests")]
use canton_participant::merkle_wire as mw;

fn var(name: &str) -> String {
    std::env::var(format!("CANTON_RS_{name}")).unwrap_or_else(|_| {
        panic!("CANTON_RS_{name} is not set: run scripts/verify-merkle-views.sh")
    })
}

/// `Array.tabulate(32)(i => (seed + i).toByte)`: the salts the console script uses.
fn salt(seed: u8) -> Vec<u8> {
    (0..32u8).map(|i| seed.wrapping_add(i)).collect()
}

fn same(name: &str, node: &mw::LeafNode, bytes: &str, hash: &str) {
    assert_eq!(
        hex::encode(&node.bytes),
        var(bytes),
        "{name}: serialized node"
    );
    assert_eq!(
        hex::encode(node.root_hash()),
        var(hash),
        "{name}: root hash"
    );
}

#[test]
fn common_metadata_matches_the_node() {
    let node = mw::common_metadata(
        &var("SYNCHRONIZER"),
        0,
        &salt(1),
        "00000000-0000-0000-0000-000000000001",
    );
    same("CommonMetadata", &node, "CM_BYTES", "CM_HASH");
}

#[test]
fn participant_metadata_matches_the_node_with_and_without_a_workflow_id() {
    let with = mw::participant_metadata(
        1_700_000_000_000_000,
        1_700_000_001_000_000,
        Some("wf-1"),
        &salt(2),
    );
    same(
        "ParticipantMetadata (workflow)",
        &with,
        "PM_BYTES",
        "PM_HASH",
    );
    let without =
        mw::participant_metadata(1_700_000_000_000_000, 1_700_000_001_000_000, None, &salt(3));
    same(
        "ParticipantMetadata (no workflow)",
        &without,
        "PM2_BYTES",
        "PM2_HASH",
    );
}

#[test]
fn view_common_data_matches_the_node() {
    let alice = format!("alice::1220{}", "aa".repeat(32));
    let bob = format!("bob::1220{}", "bb".repeat(32));
    let node = mw::view_common_data(
        &[&alice, &bob],
        &[mw::QuorumSpec {
            confirmers: vec![(&alice, 2)],
            threshold: 2,
        }],
        &salt(4),
    );
    same("ViewCommonData", &node, "VCD_BYTES", "VCD_HASH");
}

fn alice() -> String {
    format!("alice::1220{}", "aa".repeat(32))
}

fn bob() -> String {
    format!("bob::1220{}", "bb".repeat(32))
}

#[test]
fn submitter_metadata_matches_the_node() {
    let node = mw::submitter_metadata(&submitter(&alice(), &var("P1_UID")), &salt(5));
    same("SubmitterMetadata", &node, "SM_BYTES", "SM_HASH");
}

fn submitter<'a>(alice: &'a str, uid: &'a str) -> mw::SubmitterInfo<'a> {
    mw::SubmitterInfo {
        act_as: vec![alice],
        user_id: "user-1",
        command_id: "cmd-1",
        submitting_participant_uid: uid,
        submission_id: Some("sub-1"),
        dedup_duration: (300, 0),
        max_sequencing_time_micros: 1_700_000_060_000_000,
    }
}

/// `pure.digest(HashPurpose.ViewParticipantData, [n])`: the hash the console script blinds the participant data to.
fn blinded_participant_data(n: u8) -> mw::Tree {
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&canton_algo::hash::sha256_with_purpose(9, &[n]));
    mw::Tree::blinded(out)
}

fn view(n: u8, subviews: &[mw::Tree]) -> mw::Tree {
    let (alice, bob) = (alice(), bob());
    let vcd = mw::view_common_data(
        &[&alice, &bob],
        &[mw::QuorumSpec {
            confirmers: vec![(&alice, 2)],
            threshold: 2,
        }],
        &salt(10 + n),
    );
    mw::view_node(
        &mw::Tree::leaf(&vcd),
        &blinded_participant_data(n),
        &mw::merkle_seq(subviews),
    )
}

#[test]
fn a_full_informee_tree_with_nested_views_matches_the_node() {
    let uid = var("P1_UID");
    let common = mw::common_metadata(
        &var("SYNCHRONIZER"),
        0,
        &salt(1),
        "00000000-0000-0000-0000-000000000001",
    );
    let participant = mw::participant_metadata(
        1_700_000_000_000_000,
        1_700_000_001_000_000,
        Some("wf-1"),
        &salt(2),
    );
    let submitter = mw::submitter_metadata(&submitter(&alice(), &uid), &salt(5));
    let v1 = view(1, &[view(0, &[])]);
    let roots = mw::merkle_seq(&[v1, view(2, &[]), view(3, &[])]);
    let tree = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        // an informee tree carries only the hash of the participant metadata
        &mw::Tree::blinded(participant.root_hash()),
        &roots,
    );
    use prost::Message;
    assert_eq!(
        hex::encode(&tree.root_hash),
        var("GTT_HASH"),
        "tree root hash"
    );
    assert_eq!(
        hex::encode(tree.proto.encode_to_vec()),
        var("GTT_PROTO"),
        "GenTransactionTree bytes"
    );
    assert_eq!(
        hex::encode(mw::full_informee_tree(&tree).encode_to_vec()),
        var("FIT_PROTO"),
        "FullInformeeTree bytes"
    );
}

#[test]
fn a_contract_instance_serializes_like_the_nodes_fat_contract_instance() {
    use canton_participant::contract_wire::{ContractInstance, LfValue};
    let (alice, bob) = (alice(), bob());
    let mut id = vec![0x00];
    id.extend(vec![0x11; 32]);
    id.push(0x10);
    id.extend(vec![0x22; 33]);
    let instance = ContractInstance {
        contract_id: id,
        package_name: "sample-contract".into(),
        package_id: "ab".repeat(32),
        module: vec!["Main".into()],
        name: vec!["Holding".into()],
        arg: LfValue::Record(vec![
            LfValue::Party(alice.clone()),
            LfValue::Int64(42),
            LfValue::Text("hi".into()),
            LfValue::List(vec![LfValue::Bool(true), LfValue::Unit]),
        ]),
        signatories: [alice.clone()].into(),
        stakeholders: [alice, bob].into(),
        created_at_micros: 1_700_000_000_000_000,
        authentication_data: vec![0x0a, 0x0b, 0x0c],
        key: None,
    };
    assert_eq!(hex::encode(instance.encode()), var("FCI_BYTES"));
}

#[test]
fn a_contract_instance_with_numerics_serializes_like_the_node() {
    use canton_participant::contract_wire::{ContractInstance, LfValue};
    let (alice, bob) = (alice(), bob());
    let mut id = vec![0x00];
    id.extend(vec![0x11; 32]);
    id.push(0x10);
    id.extend(vec![0x22; 33]);
    let instance = ContractInstance {
        contract_id: id,
        package_name: "sample-contract".into(),
        package_id: "ab".repeat(32),
        module: vec!["Main".into()],
        name: vec!["Holding".into()],
        arg: LfValue::Record(vec![
            LfValue::Numeric("100.5000000000".into()),
            LfValue::Numeric("-3.2500000000".into()),
        ]),
        signatories: [alice.clone()].into(),
        stakeholders: [alice, bob].into(),
        created_at_micros: 1_700_000_000_000_000,
        authentication_data: vec![0x0a, 0x0b, 0x0c],
        key: None,
    };
    assert_eq!(hex::encode(instance.encode()), var("FCI_NUMERIC_BYTES"));
}

#[test]
fn view_participant_data_of_a_create_matches_the_node() {
    use canton_participant::contract_wire::{ContractInstance, LfValue};
    let (alice, bob) = (alice(), bob());
    let mut id = vec![0x00];
    id.extend(vec![0x11; 32]);
    id.extend([0xca, 0x12, 0x12, 0x20]);
    id.extend(vec![0x33; 32]);
    let instance = ContractInstance {
        contract_id: id.clone(),
        package_name: "sample-contract".into(),
        package_id: "ab".repeat(32),
        module: vec!["Main".into()],
        name: vec!["Holding".into()],
        arg: LfValue::Record(vec![
            LfValue::Party(alice.clone()),
            LfValue::Int64(42),
            LfValue::Text("hi".into()),
            LfValue::List(vec![LfValue::Bool(true), LfValue::Unit]),
        ]),
        signatories: [alice.clone()].into(),
        stakeholders: [alice, bob].into(),
        created_at_micros: 1_700_000_000_000_000,
        authentication_data: vec![0x0a, 0x0b, 0x0c],
        key: None,
    };
    let node = mw::view_participant_data_create(
        &instance.encode(),
        &hex::encode(&id),
        &[0x44; 32],
        &salt(9),
    );
    same(
        "ViewParticipantData (create)",
        &node,
        "VPD_BYTES",
        "VPD_HASH",
    );
}

#[test]
fn view_common_data_with_the_admin_party_as_a_second_confirmer_matches_the_node() {
    let carol = format!("carol::1220{}", "dd".repeat(32));
    let admin = format!("rustp::1220{}", "cc".repeat(32));
    let mut informees = [alice(), carol.clone(), admin.clone()];
    informees.sort();
    let informee_refs: Vec<&str> = informees.iter().map(String::as_str).collect();
    let mut confirmers = vec![(carol.as_str(), 1), (admin.as_str(), 1)];
    confirmers.sort();
    let node = mw::view_common_data(
        &informee_refs,
        &[mw::QuorumSpec {
            confirmers,
            threshold: 2,
        }],
        &salt(7),
    );
    same(
        "ViewCommonData with admin",
        &node,
        "VCD_ADMIN_BYTES",
        "VCD_ADMIN_HASH",
    );
}

#[test]
fn view_participant_data_of_a_sample_template_create_matches_the_node() {
    use canton_participant::contract_wire::{ContractInstance, LfValue};
    let alice = alice();
    let carol = format!("carol::1220{}", "dd".repeat(32));
    let mut id = vec![0x00];
    id.extend(vec![0x11; 32]);
    id.extend([0xca, 0x12, 0x12, 0x20]);
    id.extend(vec![0x33; 32]);
    let instance = ContractInstance {
        contract_id: id.clone(),
        package_name: "sample-contract".into(),
        package_id: "cd".repeat(32),
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        arg: LfValue::Record(vec![
            LfValue::Party(carol.clone()),
            LfValue::Party(carol.clone()),
            LfValue::Party(alice.clone()),
            LfValue::Text("USD".into()),
            LfValue::Numeric("100.0000000000".into()),
        ]),
        signatories: [carol.clone()].into(),
        stakeholders: [carol, alice].into(),
        created_at_micros: 1_700_000_000_000_000,
        authentication_data: vec![0x0a, 0x0b, 0x0c],
        key: None,
    };
    let node = mw::view_participant_data_create(
        &instance.encode(),
        &hex::encode(&id),
        &[0x44; 32],
        &salt(9),
    );
    same(
        "ViewParticipantData (sample)",
        &node,
        "VPD_SAMPLE_BYTES",
        "VPD_SAMPLE_HASH",
    );
}
