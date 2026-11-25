//! G5 5.6d-2 (S-NET-009): the contract id derivation of Rust (contract salt, LF contract hash, Unicum, suffix, authentication
//! data) equals the one of the node's Scala classes. Run through `scripts/verify-merkle-views.sh`.
#![cfg(feature = "sequencer-tests")]
use canton_participant::contract_id::{
    contract_id, contract_id_suffix, contract_salt, derive_contract_discriminator,
    derive_node_seed, derive_transaction_seed, lf_contract_hash, unicum, HashValue, SaltInputs,
    UnicumInputs,
};
use canton_participant::contract_wire::authentication_data;

fn var(name: &str) -> String {
    std::env::var(format!("CANTON_RS_{name}")).unwrap_or_else(|_| {
        panic!("CANTON_RS_{name} is not set: run scripts/verify-merkle-views.sh")
    })
}

fn s(x: &str) -> String {
    x.to_string()
}

fn alice() -> String {
    format!("alice::1220{}", "aa".repeat(32))
}
fn bob() -> String {
    format!("bob::1220{}", "bb".repeat(32))
}
fn carol() -> String {
    format!("carol::1220{}", "cc".repeat(32))
}

/// The view position of the console script: `[[R, L, R], [L]]`.
fn position() -> Vec<Vec<bool>> {
    vec![vec![true, false, true], vec![false]]
}

fn contract_salt_bytes() -> [u8; 32] {
    let vpd_salt: Vec<u8> = (0..32u8).map(|i| 9u8.wrapping_add(i)).collect();
    contract_salt(&SaltInputs {
        view_participant_data_salt: &vpd_salt,
        create_index: 3,
        view_position: &position(),
        transaction_uuid: "00000000-0000-0000-0000-0000000000aa",
        synchronizer_id: &var("SYNCHRONIZER"),
        mediator: "MGR::0",
    })
}

fn record(fields: Vec<(&str, HashValue)>) -> HashValue {
    HashValue::Record {
        module: vec![s("Main")],
        name: vec![s("Holding")],
        fields: fields.into_iter().map(|(l, v)| (s(l), v)).collect(),
    }
}

fn arg1() -> HashValue {
    record(vec![
        ("owner", HashValue::Party(alice())),
        ("amount", HashValue::Int64(42)),
        ("note", HashValue::Text(s("hi"))),
        (
            "flags",
            HashValue::List(vec![HashValue::Bool(true), HashValue::Unit]),
        ),
        (
            "day",
            HashValue::Optional(Some(Box::new(HashValue::Date(19000)))),
        ),
        ("at", HashValue::Timestamp(1_700_000_000_000_000)),
        ("tail1", HashValue::Optional(None)),
        ("tail2", HashValue::Optional(None)),
    ])
}

/// A `None` in the middle and a `Some(None)` stay; only the trailing `None`s go.
fn arg2() -> HashValue {
    record(vec![
        ("a", HashValue::Optional(None)),
        ("b", HashValue::Int64(1)),
        (
            "c",
            HashValue::Optional(Some(Box::new(HashValue::Optional(None)))),
        ),
        ("d", HashValue::Optional(None)),
    ])
}

/// Numerics by their unscaled value at scale 10: 100.5, -3.25 and 0.
fn arg3() -> HashValue {
    record(vec![
        ("amount", HashValue::Numeric(1_005_000_000_000)),
        ("debt", HashValue::Numeric(-32_500_000_000)),
        ("zero", HashValue::Numeric(0)),
    ])
}

fn hash(arg: &HashValue) -> [u8; 32] {
    lf_contract_hash("sample-contract", &[s("Main")], &[s("Holding")], arg)
}

#[test]
fn contract_salt_matches_the_node() {
    assert_eq!(hex::encode(contract_salt_bytes()), var("ID_SALT"));
}

#[test]
fn authentication_data_matches_the_node() {
    assert_eq!(
        hex::encode(authentication_data(&contract_salt_bytes())),
        var("ID_AUTH")
    );
}

#[test]
fn lf_contract_hash_in_typed_normal_form_matches_the_node() {
    assert_eq!(
        hex::encode(hash(&arg1())),
        var("ID_HASH1"),
        "all value kinds, trailing Nones dropped"
    );
    assert_eq!(
        hex::encode(hash(&arg2())),
        var("ID_HASH2"),
        "an inner None and a Some(None) stay"
    );
    assert_eq!(
        hex::encode(hash(&arg3())),
        var("ID_HASH3"),
        "numerics: positive, negative and zero"
    );
}

#[test]
fn unicum_and_suffix_match_the_node() {
    let salt = contract_salt_bytes();
    let created_at = 1_700_000_000_123_456;
    let u1 = unicum(
        &salt,
        &UnicumInputs {
            created_at_micros: created_at,
            signatories: &[alice()],
            stakeholders: &[alice(), bob()],
            key: None,
            contract_hash: &hash(&arg1()),
        },
    );
    assert_eq!(hex::encode(contract_id_suffix(&u1)), var("ID_SUFFIX1"));
    // unsorted parties in, sorted by the encoding; the stakeholders include the signatories
    let u2 = unicum(
        &salt,
        &UnicumInputs {
            created_at_micros: created_at,
            signatories: &[bob(), alice()],
            stakeholders: &[carol(), bob(), alice()],
            key: None,
            contract_hash: &hash(&arg2()),
        },
    );
    assert_eq!(hex::encode(contract_id_suffix(&u2)), var("ID_SUFFIX2"));
}

fn array(hex_text: &str) -> [u8; 32] {
    hex::decode(hex_text).unwrap().try_into().unwrap()
}

#[test]
fn seeds_discriminator_and_the_whole_contract_id_match_the_node() {
    let submission_seed: [u8; 32] = std::array::from_fn(|i| 50 + i as u8);
    let tx_seed = derive_transaction_seed(&submission_seed, &var("P1_UID"), 1_700_000_000_000_000);
    assert_eq!(hex::encode(tx_seed), var("ID_TXSEED"));
    let node_seed = derive_node_seed(&tx_seed, 2);
    assert_eq!(hex::encode(node_seed), var("ID_NODESEED"));
    // the parties are unsorted on purpose: the set is hashed in order
    let disc = derive_contract_discriminator(
        &node_seed,
        1_700_000_000_000_000,
        &[carol(), bob(), alice()],
    );
    assert_eq!(hex::encode(disc), var("ID_DISC"));
    // the first contract of the other test: discriminator + suffix = the id the ledger shows
    let u1 = unicum(
        &contract_salt_bytes(),
        &UnicumInputs {
            created_at_micros: 1_700_000_000_123_456,
            signatories: &[alice()],
            stakeholders: &[alice(), bob()],
            key: None,
            contract_hash: &hash(&arg1()),
        },
    );
    assert_eq!(contract_id(&array(&var("ID_DISC")), &u1), var("ID_CID"));
}
