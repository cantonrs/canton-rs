//! U-56 test vector: the tree of an externally signed create the official Canton 3.7.2 participant executed, as a Rust observer received
//! it (`doc/evidence/2026-11-24-U56/vector/p1-external-create.json`, recorded by
//! `ledger-json-api` `jvm_peer_tests::p1_externally_signed_create_reaches_the_rust_observer_with_its_authorization`). It pins what the
//! recomputation of the externally signed hash starts from: the submitter metadata carries the external authorization with the signer's
//! own signature over the hash the official `prepare` answered.
#![cfg(feature = "sequencer-grpc")]
#![allow(clippy::unwrap_used, reason = "integration test")]
use canton_participant::view_receive::{revealed_common_metadata, revealed_submitter_metadata};
use canton_proto::com::digitalasset::canton::protocol::v30::GenTransactionTree;
use prost::Message;

fn vector() -> serde_json::Value {
    vector_of("create")
}

/// The recorded vector of the externally signed `label` (`create`, or `exercise`: `Settle` on the contract the create made).
fn vector_of(label: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../doc/evidence/2026-11-24-U56/vector/p1-external-{label}.json"
    ));
    serde_json::from_slice(&std::fs::read(&path).expect("the recorded vector is readable")).unwrap()
}

/// The views the recorded request reveals to the Rust observer across all its trees (a subview travels in a tree of its own).
fn views_of(v: &serde_json::Value) -> Vec<canton_participant::view_receive::RevealedView> {
    v["trees"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|t| {
            let tree = GenTransactionTree::decode(b64(t.as_str().unwrap()).as_slice()).unwrap();
            canton_participant::view_receive::revealed_views(&tree).unwrap()
        })
        .collect()
}

fn b64(s: &str) -> Vec<u8> {
    canton_algo::prepared_hash::decode_base64(s).unwrap()
}

#[test]
fn the_recorded_tree_carries_the_external_authorization_the_signer_made() {
    let v = vector();
    let trees = v["trees"].as_array().unwrap();
    assert_eq!(trees.len(), 1, "one externally signed request was observed");
    let tree = GenTransactionTree::decode(b64(trees[0].as_str().unwrap()).as_slice()).unwrap();
    let submitter =
        revealed_submitter_metadata(&tree).expect("the root view reveals the submitter metadata");
    assert_eq!(
        submitter.act_as,
        vec![v["party"].as_str().unwrap().to_string()]
    );
    assert_eq!(
        submitter.command_id,
        v["prepareRequest"]["commandId"].as_str().unwrap()
    );
    let external = submitter
        .external_authorization
        .expect("the submitter metadata carries the external authorization");
    // HASHING_SCHEME_VERSION_V2 = 2
    assert_eq!(external.hashing_scheme_version, 2);
    let [authentication] = external.authentications.as_slice() else {
        panic!("one party authenticated: {:?}", external.authentications);
    };
    assert_eq!(authentication.party, v["party"].as_str().unwrap());
    let [signature] = authentication.signatures.as_slice() else {
        panic!("one signature: {:?}", authentication.signatures);
    };
    assert_eq!(
        signature.signature,
        b64(v["signature"]["signature"].as_str().unwrap())
    );
    assert_eq!(
        signature.signed_by,
        v["publicKeyFingerprint"].as_str().unwrap()
    );
    // the signature is the signer's over the 32-byte hash the official prepare answered: what the recomputation must reach
    let hash = b64(v["prepareAnswer"]["preparedTransactionHash"]
        .as_str()
        .unwrap());
    assert_eq!(hash.len(), 32);
    let key = ed25519_dalek::VerifyingKey::from_bytes(
        &b64(v["publicKeySpki"].as_str().unwrap())[12..]
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let sig = ed25519_dalek::Signature::from_slice(&signature.signature).unwrap();
    assert!(
        key.verify_strict(&hash, &sig).is_ok(),
        "the signature verifies against the prepared hash"
    );
    let mut tampered = hash;
    tampered[0] ^= 1;
    assert!(
        key.verify_strict(&tampered, &sig).is_err(),
        "control: another hash does not verify"
    );
    // what the hash depends on and the view reveals: the transaction uuid and the mediator group
    let common = revealed_common_metadata(&tree).unwrap();
    assert!(!common.uuid.is_empty());
}

#[test]
fn the_rust_hash_of_the_official_prepared_transaction_is_the_signed_hash() {
    use canton_proto::com::daml::ledger::api::v2::interactive::{
        HashingSchemeVersion, PreparedTransaction,
    };
    for label in ["create", "exercise", "hop-create", "forward"] {
        let v = vector_of(label);
        let prepared = PreparedTransaction::decode(
            b64(v["prepareAnswer"]["preparedTransaction"].as_str().unwrap()).as_slice(),
        )
        .unwrap();
        if std::env::var("U56_DUMP").is_ok() {
            println!("{prepared:#?}");
        }
        let hash = canton_algo::prepared_hash::hash_prepared_transaction(
            &prepared,
            HashingSchemeVersion::V2,
        )
        .unwrap();
        assert_eq!(
            hash.to_vec(),
            b64(v["prepareAnswer"]["preparedTransactionHash"]
                .as_str()
                .unwrap()),
            "{label}"
        );
    }
}

#[test]
fn the_prepared_transaction_rebuilt_from_the_tree_hashes_to_the_signed_hash() {
    use canton_proto::com::daml::ledger::api::v2::interactive::{
        HashingSchemeVersion, PreparedTransaction,
    };
    let v = vector();
    let tree = GenTransactionTree::decode(b64(v["trees"][0].as_str().unwrap()).as_slice()).unwrap();
    let dar = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar");
    let engine = canton_participant::view_conformance::Engine::load(&dar).unwrap();
    let rebuilt =
        canton_participant::external_hash::prepared_transaction_in(&engine, &tree, &views_of(&v))
            .unwrap();
    let official = PreparedTransaction::decode(
        b64(v["prepareAnswer"]["preparedTransaction"].as_str().unwrap()).as_slice(),
    )
    .unwrap();
    assert_eq!(rebuilt.metadata, official.metadata, "the metadata");
    assert_eq!(rebuilt.transaction, official.transaction, "the transaction");
    let hash =
        canton_algo::prepared_hash::hash_prepared_transaction(&rebuilt, HashingSchemeVersion::V2)
            .unwrap();
    assert_eq!(
        hash.to_vec(),
        b64(v["prepareAnswer"]["preparedTransactionHash"]
            .as_str()
            .unwrap()),
        "the recomputed hash is the one the external party signed"
    );
}

/// The engine, the tree and the party's registered key of the vector.
fn verification_inputs(
    label: &str,
) -> (
    canton_participant::view_conformance::Engine,
    GenTransactionTree,
    serde_json::Value,
) {
    let v = vector_of(label);
    let tree = GenTransactionTree::decode(b64(v["trees"][0].as_str().unwrap()).as_slice()).unwrap();
    let dar = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(match label {
        "create" | "exercise" => "../../../contracts/target/sample-contract.dar",
        "fetch" => "../../../contracts/fixtures/extfetch/target/ext-fetch.dar",
        _ => "../../../contracts/fixtures/chain/target/nested-chain.dar",
    });
    (
        canton_participant::view_conformance::Engine::load(&dar).unwrap(),
        tree,
        v,
    )
}

fn party_key(
    v: &serde_json::Value,
) -> canton_proto::com::digitalasset::canton::crypto::v30::SigningPublicKey {
    // CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO = 4, SIGNING_KEY_USAGE_PROTOCOL = 4, SIGNING_KEY_SPEC_EC_CURVE25519 = 1
    #[expect(
        deprecated,
        reason = "`scheme` is a deprecated proto field, left unset"
    )]
    canton_proto::com::digitalasset::canton::crypto::v30::SigningPublicKey {
        format: 4,
        public_key: b64(v["publicKeySpki"].as_str().unwrap()),
        scheme: 0,
        usage: vec![4],
        key_spec: 1,
    }
}

#[test]
fn the_external_authorization_of_the_official_request_verifies() {
    for label in [
        "create",
        "exercise",
        "hop-create",
        "forward",
        "fetch",
        "forward-subview",
    ] {
        let (engine, tree, v) = verification_inputs(label);
        let party = v["party"].as_str().unwrap().to_string();
        let key = party_key(&v);
        let keys = move |p: &str| (p == party).then(|| (1, vec![key.clone()]));
        assert_eq!(
            canton_participant::external_hash::verify_in(&engine, &tree, &views_of(&v), &keys),
            Ok(()),
            "{label}"
        );
    }
}

#[test]
fn a_forged_signature_a_changed_request_or_a_party_without_keys_does_not_verify() {
    use canton_proto::com::digitalasset::canton::protocol::v32::SubmitterMetadata;
    let (engine, tree, v) = verification_inputs("exercise");
    let party = v["party"].as_str().unwrap().to_string();
    let key = party_key(&v);
    let keys = |p: &str| (p == party).then(|| (1, vec![key.clone()]));
    // the submitter metadata leaf, re-encoded with a change (its hash in the tree is not checked here, the signature is)
    let with_submitter = |change: &dyn Fn(&mut SubmitterMetadata)| {
        let mut tree = tree.clone();
        let node = tree.submitter_metadata.as_mut().unwrap();
        let Some(canton_proto::com::digitalasset::canton::protocol::v30::blindable_node::BlindedOrNot::Unblinded(bytes)) =
            node.blinded_or_not.as_mut()
        else {
            panic!("the submitter metadata is revealed");
        };
        let (data, version) = canton_participant::topology_wire::unversioned(bytes).unwrap();
        let mut metadata = SubmitterMetadata::decode(data.as_slice()).unwrap();
        change(&mut metadata);
        *bytes = canton_participant::topology_wire::versioned(metadata.encode_to_vec(), version);
        tree
    };
    let forged = with_submitter(&|m| {
        m.external_authorization.as_mut().unwrap().authentications[0].signatures[0].signature[0] ^=
            1;
    });
    let forged_err =
        canton_participant::external_hash::verify_in(&engine, &forged, &views_of(&v), &keys)
            .unwrap_err();
    assert!(
        forged_err.contains("Received 0 valid signatures from distinct keys (1 invalid)")
            && forged_err.contains("Transaction hash to be signed: 1220"),
        "{forged_err}"
    );
    // another command id is another hash: the genuine signature no longer covers it
    let changed = with_submitter(&|m| m.command_id.push('x'));
    assert!(
        canton_participant::external_hash::verify_in(&engine, &changed, &views_of(&v), &keys)
            .unwrap_err()
            .contains("Received 0 valid signatures")
    );
    let empty = with_submitter(&|m| {
        m.external_authorization
            .as_mut()
            .unwrap()
            .authentications
            .clear()
    });
    let empty_err =
        canton_participant::external_hash::verify_in(&engine, &empty, &views_of(&v), &keys)
            .unwrap_err();
    assert!(
        empty_err.contains("The following actAs parties did not provide an external signature"),
        "{empty_err}"
    );
    let no_keys = |_: &str| None;
    assert!(
        canton_participant::external_hash::verify_in(&engine, &tree, &views_of(&v), &no_keys)
            .unwrap_err()
            .contains("Could not find party signing keys")
    );
}

/// U-56 review R2-F1: the transaction path (`prepared_transaction_in` and `verify_in`) refuses a contract that carries a contract key
/// by name rather than rebuilding a hash that cannot match. Removing the `refuse_contract_key(&fci)?` call in `create_node` (`own56`)
/// breaks this test.
#[test]
fn a_transaction_whose_contract_has_a_key_is_refused_by_name() {
    use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
    let (engine, tree, v) = verification_inputs("create");
    let mut views = views_of(&v);
    let contract_bytes = &mut views[0].participant_data.created_core[0].contract;
    let mut versioned = Versioned::decode(contract_bytes.as_slice()).unwrap();
    let mut fci = FatContractInstance::decode(versioned.payload.as_slice()).unwrap();
    fci.contract_key_with_maintainers = Some(Default::default());
    versioned.payload = fci.encode_to_vec();
    *contract_bytes = versioned.encode_to_vec();

    let prepared_err =
        canton_participant::external_hash::prepared_transaction_in(&engine, &tree, &views)
            .unwrap_err();
    assert!(
        prepared_err.contains("contract key"),
        "prepared_transaction_in must refuse a keyed contract by name: {prepared_err}"
    );

    let party = v["party"].as_str().unwrap().to_string();
    let key = party_key(&v);
    let keys = |p: &str| (p == party).then(|| (1, vec![key.clone()]));
    let verify_err =
        canton_participant::external_hash::verify_in(&engine, &tree, &views, &keys).unwrap_err();
    assert!(
        verify_err.contains("contract key"),
        "verify_in must refuse a keyed contract by name: {verify_err}"
    );
}

#[test]
fn the_exercise_rebuilt_from_the_tree_hashes_to_the_signed_hash() {
    use canton_proto::com::daml::ledger::api::v2::interactive::{
        HashingSchemeVersion, PreparedTransaction,
    };
    let v = vector_of("exercise");
    let tree = GenTransactionTree::decode(b64(v["trees"][0].as_str().unwrap()).as_slice()).unwrap();
    let dar = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar");
    let engine = canton_participant::view_conformance::Engine::load(&dar).unwrap();
    let rebuilt =
        canton_participant::external_hash::prepared_transaction_in(&engine, &tree, &views_of(&v))
            .unwrap();
    let mut official = PreparedTransaction::decode(
        b64(v["prepareAnswer"]["preparedTransaction"].as_str().unwrap()).as_slice(),
    )
    .unwrap();
    // the hash does not cover an input contract's event blob, which a confirming participant does not receive
    for input in &mut official.metadata.as_mut().unwrap().input_contracts {
        input.event_blob.clear();
    }
    assert_eq!(rebuilt.transaction, official.transaction, "the transaction");
    assert_eq!(rebuilt.metadata, official.metadata, "the metadata");
    let hash =
        canton_algo::prepared_hash::hash_prepared_transaction(&rebuilt, HashingSchemeVersion::V2)
            .unwrap();
    assert_eq!(
        hash.to_vec(),
        b64(v["prepareAnswer"]["preparedTransactionHash"]
            .as_str()
            .unwrap()),
        "the recomputed hash is the one the external party signed"
    );
}

#[test]
fn the_exercise_with_a_create_below_it_rebuilt_from_the_tree_hashes_to_the_signed_hash() {
    rebuilt_matches_the_official(
        "forward",
        "../../../contracts/fixtures/chain/target/nested-chain.dar",
    );
}

#[test]
fn the_exercise_with_a_fetch_below_it_rebuilt_from_the_tree_hashes_to_the_signed_hash() {
    rebuilt_matches_the_official(
        "fetch",
        "../../../contracts/fixtures/extfetch/target/ext-fetch.dar",
    );
}

#[test]
fn the_exercise_with_a_subview_rebuilt_from_its_trees_hashes_to_the_signed_hash() {
    rebuilt_matches_the_official(
        "forward-subview",
        "../../../contracts/fixtures/chain/target/nested-chain.dar",
    );
}

/// The prepared transaction rebuilt from the tree of the vector `label` is the official one (node by node id, the node seeds, the metadata
/// without the input contracts' event blobs) and hashes to the signed hash.
fn rebuilt_matches_the_official(label: &str, dar: &str) {
    use canton_proto::com::daml::ledger::api::v2::interactive::{
        HashingSchemeVersion, PreparedTransaction,
    };
    let v = vector_of(label);
    let tree = GenTransactionTree::decode(b64(v["trees"][0].as_str().unwrap()).as_slice()).unwrap();
    let engine = canton_participant::view_conformance::Engine::load(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(dar),
    )
    .unwrap();
    let rebuilt =
        canton_participant::external_hash::prepared_transaction_in(&engine, &tree, &views_of(&v))
            .unwrap();
    let mut official = PreparedTransaction::decode(
        b64(v["prepareAnswer"]["preparedTransaction"].as_str().unwrap()).as_slice(),
    )
    .unwrap();
    for input in &mut official.metadata.as_mut().unwrap().input_contracts {
        input.event_blob.clear();
    }
    // the hash walks the tree from its roots: the order of the node list is not part of it, so compare node by node id
    let by_id = |p: &PreparedTransaction| {
        let mut nodes = p.transaction.as_ref().unwrap().nodes.clone();
        nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        nodes
    };
    assert_eq!(by_id(&rebuilt), by_id(&official), "{label}: the nodes");
    assert_eq!(
        rebuilt.transaction.as_ref().unwrap().node_seeds,
        official.transaction.as_ref().unwrap().node_seeds,
        "{label}: the node seeds"
    );
    let mut rebuilt_metadata = rebuilt.metadata.clone().unwrap();
    let mut official_metadata = official.metadata.clone().unwrap();
    // the hash sorts the input contracts by id
    rebuilt_metadata
        .input_contracts
        .sort_by(|a, b| format!("{:?}", a.contract).cmp(&format!("{:?}", b.contract)));
    official_metadata
        .input_contracts
        .sort_by(|a, b| format!("{:?}", a.contract).cmp(&format!("{:?}", b.contract)));
    assert_eq!(rebuilt_metadata, official_metadata, "{label}: the metadata");
    let hash =
        canton_algo::prepared_hash::hash_prepared_transaction(&rebuilt, HashingSchemeVersion::V2)
            .unwrap();
    assert_eq!(
        hash.to_vec(),
        b64(v["prepareAnswer"]["preparedTransactionHash"]
            .as_str()
            .unwrap()),
        "{label}: the recomputed hash is the one the external party signed"
    );
}
