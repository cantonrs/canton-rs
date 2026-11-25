//! G7 B1 (S-NET-040): the reassignment protocol's nodes built by Rust equal the ones Canton 3.7.2 builds, byte for byte
//! and hash for hash, and the reassignment ids of a real reassignment between two synchronizers are the ones Rust derives.
//! Run through `scripts/verify-reassignment-wire.sh`, which prints the node's values.
#![cfg(feature = "sequencer-tests")]
use canton_participant::merkle_wire::{LeafNode, Tree};
use canton_participant::reassignment_wire as rw;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    AssignmentMediatorMessage, UnassignmentMediatorMessage,
};
use prost::Message;

fn var(name: &str) -> String {
    std::env::var(format!("CANTON_RS_RA_{name}")).unwrap_or_else(|_| {
        panic!("CANTON_RS_RA_{name} is not set: run scripts/verify-reassignment-wire.sh")
    })
}

/// `Array.tabulate(32)(i => (seed + i).toByte)`: the salts the console script uses.
fn salt(seed: u8) -> Vec<u8> {
    (0..32u8).map(|i| seed.wrapping_add(i)).collect()
}

fn same(name: &str, node: &LeafNode, bytes: &str, hash: &str) {
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

const ALICE: &str = "alice::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB: &str = "bob::1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PKG: &str = "abababababababababababababababababababababababababababababababab";
const UUID: &str = "00000000-0000-0000-0000-0000000000a1";
const TARGET_TS: i64 = 1_700_000_005_000_000;
const UNASSIGN_TS: i64 = 1_700_000_006_000_000;

struct Fixture {
    p1: String,
    c1_cid: String,
    c1: Vec<u8>,
    c2_cid: String,
    c2: Vec<u8>,
}

fn fixture() -> Fixture {
    Fixture {
        p1: var("P1_UID"),
        c1_cid: var("C1_CID"),
        c1: hex::decode(var("C1_ENCODED")).unwrap(),
        c2_cid: var("C2_CID"),
        c2: hex::decode(var("C2_ENCODED")).unwrap(),
    }
}

fn contracts(f: &Fixture) -> Vec<rw::Reassigned<'_>> {
    vec![
        rw::Reassigned {
            contract_id: &f.c1_cid,
            encoded: &f.c1,
            source_validation_package_id: PKG,
            target_validation_package_id: PKG,
            counter: 1,
        },
        rw::Reassigned {
            contract_id: &f.c2_cid,
            encoded: &f.c2,
            source_validation_package_id: PKG,
            target_validation_package_id: PKG,
            counter: 3,
        },
    ]
}

fn parts<'a>(submitter: rw::Submitter<'a>, uids: &'a [&'a str]) -> rw::CommonParts<'a> {
    rw::CommonParts {
        stakeholders: &[ALICE, BOB],
        signatories: &[ALICE],
        reassigning_participant_uids: uids,
        uuid: UUID,
        mediator_group: 0,
        submitter,
    }
}

fn full_submitter(f: &Fixture) -> rw::Submitter<'_> {
    rw::Submitter {
        submitter: ALICE,
        submitting_participant_uid: &f.p1,
        command_id: "cmd-1",
        submission_id: Some("sub-1"),
        user_id: "user-1",
        workflow_id: Some("wf-1"),
    }
}

fn bare_submitter(f: &Fixture) -> rw::Submitter<'_> {
    rw::Submitter {
        submitter: ALICE,
        submitting_participant_uid: &f.p1,
        command_id: "cmd-2",
        submission_id: None,
        user_id: "user-1",
        workflow_id: None,
    }
}

#[test]
fn unassignment_nodes_tree_and_mediator_message_match_the_node() {
    let f = fixture();
    let uids = [f.p1.as_str()];
    let common =
        rw::unassignment_common_data(&var("PSID_A"), &parts(full_submitter(&f), &uids), &salt(1));
    same("UnassignmentCommonData", &common, "UCD_BYTES", "UCD_HASH");
    let view = rw::unassignment_view(&var("PSID_B"), TARGET_TS, &contracts(&f), &salt(2));
    same("UnassignmentView", &view, "UV_BYTES", "UV_HASH");
    let tree = rw::view_tree(&common, &Tree::leaf(&view));
    assert_eq!(
        hex::encode(tree.bytes()),
        var("UTREE_BYTES"),
        "UnassignmentViewTree bytes"
    );
    assert_eq!(
        hex::encode(&tree.root_hash),
        var("UTREE_HASH"),
        "UnassignmentViewTree root hash"
    );
    // the node's message carries `Signature.noSignature`: take it from there, the tree is what is compared
    let node =
        UnassignmentMediatorMessage::decode(hex::decode(var("UMM_PROTO")).unwrap().as_slice())
            .unwrap();
    let ours = rw::unassignment_mediator_message(
        &tree,
        node.submitting_participant_signature.clone().unwrap(),
    );
    assert_eq!(
        hex::encode(ours.encode_to_vec()),
        var("UMM_PROTO"),
        "UnassignmentMediatorMessage"
    );
    // read back: the node's mediator copy (view blinded) and the full tree give the node's root hash and the common data
    let read = rw::read_tree(rw::Kind::Unassignment, node.tree.as_ref().unwrap()).unwrap();
    assert_eq!(
        hex::encode(&read.root_hash),
        var("UTREE_HASH"),
        "read mediator message root hash"
    );
    assert_eq!(read.submitting_participant_uid, f.p1);
    assert_eq!(
        read.confirming_parties(),
        vec![ALICE.to_string(), f.p1.clone()]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
    assert_eq!(read.non_confirming_parties(), vec![BOB.to_string()]);
    assert_eq!(read.synchronizer, var("PSID_A"));
    let full = rw::read_tree(rw::Kind::Unassignment, &tree.proto).unwrap();
    assert_eq!(
        hex::encode(&full.root_hash),
        var("UTREE_HASH"),
        "read full tree root hash"
    );
}

#[test]
fn reassignment_id_of_fixed_inputs_matches_the_node() {
    let f = fixture();
    // given in the opposite order: the id sorts by contract id
    let id = rw::reassignment_id(
        &var("SYNC_A"),
        &var("SYNC_B"),
        UNASSIGN_TS,
        &[(&f.c2_cid, 3), (&f.c1_cid, 1)],
    );
    assert_eq!(id, var("RID"));
}

#[test]
fn assignment_nodes_tree_and_mediator_message_match_the_node() {
    let f = fixture();
    let uids = [f.p1.as_str()];
    let common = rw::assignment_common_data(
        &var("PSID_A"),
        &var("PSID_B"),
        UNASSIGN_TS,
        &parts(bare_submitter(&f), &uids),
        &salt(3),
    );
    same("AssignmentCommonData", &common, "ACD_BYTES", "ACD_HASH");
    let view = rw::assignment_view(&var("RID"), &contracts(&f), &salt(4));
    same("AssignmentView", &view, "AV_BYTES", "AV_HASH");
    let tree = rw::view_tree(&common, &Tree::leaf(&view));
    assert_eq!(
        hex::encode(tree.bytes()),
        var("ATREE_BYTES"),
        "AssignmentViewTree bytes"
    );
    assert_eq!(
        hex::encode(&tree.root_hash),
        var("ATREE_HASH"),
        "AssignmentViewTree root hash"
    );
    let node = AssignmentMediatorMessage::decode(hex::decode(var("AMM_PROTO")).unwrap().as_slice())
        .unwrap();
    let ours = rw::assignment_mediator_message(
        &tree,
        node.submitting_participant_signature.clone().unwrap(),
    );
    assert_eq!(
        hex::encode(ours.encode_to_vec()),
        var("AMM_PROTO"),
        "AssignmentMediatorMessage"
    );
    let read = rw::read_tree(rw::Kind::Assignment, node.tree.as_ref().unwrap()).unwrap();
    assert_eq!(
        hex::encode(&read.root_hash),
        var("ATREE_HASH"),
        "read mediator message root hash"
    );
    assert_eq!(read.synchronizer, var("PSID_B"));
    let full = rw::read_tree(rw::Kind::Assignment, &tree.proto).unwrap();
    assert_eq!(
        hex::encode(&full.root_hash),
        var("ATREE_HASH"),
        "read full tree root hash"
    );
}

/// `<reassignment id>,<source>,<target>,<contract id>,<counter>,<record time>,...` as the console prints a live unassignment.
fn live(name: &str) -> Vec<String> {
    var(name).split(',').map(str::to_string).collect()
}

#[test]
fn the_reassignment_ids_of_a_real_round_trip_are_the_ones_rust_derives() {
    let cid = var("LIVE_CID");
    for (n, (from, to), counter) in [
        (1, ("SYNC_A", "SYNC_B"), 1i64),
        (2, ("SYNC_B", "SYNC_A"), 2),
    ] {
        let u = live(&format!("LIVE{n}_UNASSIGN"));
        let a = live(&format!("LIVE{n}_ASSIGN"));
        assert_eq!(
            (u[1].as_str(), u[2].as_str()),
            (var(from).as_str(), var(to).as_str()),
            "round {n}: synchronizers"
        );
        assert_eq!(u[3], cid, "round {n}: contract");
        assert_eq!(
            u[4],
            counter.to_string(),
            "round {n}: the unassignment carries the incremented counter"
        );
        assert_eq!(
            a[4],
            counter.to_string(),
            "round {n}: the assignment keeps the counter"
        );
        assert_eq!(
            a[0], u[0],
            "round {n}: the assignment names the unassignment's reassignment id"
        );
        // protocol version 37 does not enforce the assignment exclusivity: the event carries none (`-1` = absent)
        assert_eq!(
            u[6], "-1",
            "round {n}: no assignment exclusivity under PV 37"
        );
        assert_eq!(
            u[7],
            var(from),
            "round {n}: the unassignment is an update of the source synchronizer"
        );
        assert_eq!(
            a[6],
            var(to),
            "round {n}: the assignment is an update of the target synchronizer"
        );
        let record_time: i64 = u[5].parse().unwrap();
        let assigned_at: i64 = a[5].parse().unwrap();
        assert!(
            assigned_at > record_time,
            "round {n}: the assignment is sequenced after the unassignment"
        );
        let ours = rw::reassignment_id(&var(from), &var(to), record_time, &[(&cid, counter)]);
        assert_eq!(
            ours, u[0],
            "round {n}: reassignment id over the unassignment's record time"
        );
    }
    // the contract is back on syncA with counter 2
    let acs = var("LIVE_ACS");
    assert_eq!(
        acs,
        format!("{cid}@{}#2", var("SYNC_A")),
        "ACS after the round trip"
    );
}
