//! G5 5.7 (S-NET-027): `LtHash16` equals the node's `LtHash16Blake3` on the same inputs, byte for byte. Run through
//! `scripts/verify-merkle-views.sh`, which prints the node's values.
#![cfg(feature = "sequencer-tests")]
use canton_participant::lthash::{commitment_digest, digest_element, ordered_pair, LtHash16};

fn var(name: &str) -> String {
    std::env::var(format!("CANTON_RS_{name}")).unwrap_or_else(|_| {
        panic!("CANTON_RS_{name} is not set: run scripts/verify-merkle-views.sh")
    })
}

fn long() -> Vec<u8> {
    // `Array.tabulate[Byte](3000)(i => (i * 7).toByte)`
    (0..3000usize).map(|i| (i * 7) as u8).collect()
}

fn hex_of(h: &LtHash16) -> String {
    hex::encode(h.to_bytes())
}

#[test]
fn adding_elements_gives_the_nodes_digest() {
    let mut h = LtHash16::empty();
    h.add(b"contract-a");
    h.add(b"contract-b");
    assert_eq!(hex_of(&h), var("LTHASH_AB"));
}

#[test]
fn removing_an_element_gives_the_nodes_digest() {
    let mut h = LtHash16::empty();
    h.add(b"contract-a");
    h.add(b"contract-b");
    h.remove(b"contract-b");
    assert_eq!(hex_of(&h), var("LTHASH_A"));
}

#[test]
fn an_element_longer_than_a_blake3_chunk_gives_the_nodes_digest() {
    let mut h = LtHash16::empty();
    h.add(&long());
    assert_eq!(hex_of(&h), var("LTHASH_LONG"));
}

#[test]
fn the_union_and_its_removal_give_the_nodes_digests() {
    let mut a = LtHash16::empty();
    a.add(b"contract-a");
    let mut long = LtHash16::empty();
    long.add(&long_bytes());
    a.union(&long);
    assert_eq!(hex_of(&a), var("LTHASH_UNION"));
    a.remove_all(&long);
    assert_eq!(hex_of(&a), var("LTHASH_REMOVEALL"));
}

fn long_bytes() -> Vec<u8> {
    long()
}

#[test]
fn a_digest_element_is_the_bytes_the_node_adds() {
    assert_eq!(
        hex::encode(digest_element(
            "00abcdef",
            3,
            "alice::1220aa",
            "erin::1220bb"
        )),
        var("COMMIT_ELEMENT")
    );
}

#[test]
fn the_commitment_a_participant_sends_is_the_nodes() {
    let mut set = LtHash16::empty();
    set.add(&digest_element(
        "00abcdef",
        0,
        "alice::1220aa",
        "erin::1220bb",
    ));
    set.add(&digest_element(
        "00abcdef",
        0,
        "erin::1220bb",
        "erin::1220bb",
    ));
    set.add(&digest_element(
        "00123456",
        1,
        "alice::1220aa",
        "bob::1220cc",
    ));
    assert_eq!(hex::encode(set.to_bytes()), var("COMMIT_SET"));
    assert_eq!(hex::encode(commitment_digest(&set)), var("COMMIT_DIGEST"));
    // a participant with nothing in common with the counterparticipant still has a (fixed) commitment
    assert_eq!(
        hex::encode(commitment_digest(&LtHash16::empty())),
        var("COMMIT_EMPTY_DIGEST")
    );
}

#[test]
fn the_pair_of_parties_is_ordered_the_way_scala_orders_strings() {
    let order = |a, b| {
        let (x, y) = ordered_pair(a, b);
        format!("{x}|{y}")
    };
    let rust: Vec<String> = vec![
        order("b::1", "A::2"),
        order("alice::1", "alice::10"),
        order("x", "x"),
    ];
    assert_eq!(rust.join(","), var("COMMIT_ORDER"));
}
