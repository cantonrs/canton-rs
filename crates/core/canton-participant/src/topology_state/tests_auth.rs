//! T-4, T-5, T-8: the authorization graphs, the serial rule, the delegation restrictions and the key usages, each refusal next to the
//! transaction that is accepted.
use super::tests::{join, send, tracker_of_roots, transaction_of};
use super::*;
use canton_proto::com::digitalasset::canton::crypto::v30::{
    public_key::Key as PublicKeyKind, PublicKey, SigningKeyUsage,
};
use canton_proto::com::digitalasset::canton::protocol::v30::namespace_delegation::{
    CanSignAllButNamespaceDelegations, CanSignAllMappings, CanSignSpecificMappings, Restriction,
};
use canton_proto::com::digitalasset::canton::protocol::v30::NamespaceDelegation;

const REPLACE: i32 = 1;

fn key(seed: u8) -> tw::Ed25519Key {
    tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

/// A delegation of `namespace` to `target`, with the target key's `usages` and the `restriction`.
fn delegation(
    namespace: &str,
    target: &tw::Ed25519Key,
    usages: &[SigningKeyUsage],
    restriction: Restriction,
    serial: u32,
    operation: i32,
) -> Vec<u8> {
    transaction_of(
        Mapping::NamespaceDelegation(NamespaceDelegation {
            namespace: namespace.to_string(),
            target_key: Some(target.public_key(usages)),
            restriction: Some(restriction),
            ..Default::default()
        }),
        serial,
        operation,
    )
}

fn all() -> Restriction {
    Restriction::CanSignAllMappings(CanSignAllMappings {})
}

fn signers(keys: &[&tw::Ed25519Key]) -> BTreeSet<String> {
    keys.iter().map(|k| k.fingerprint.clone()).collect()
}

fn hosting(party: &str, participant: &str, serial: u32, operation: i32) -> Vec<u8> {
    let bytes = tw::party_to_participant_at_serial(party, &[(participant, 1)], 1, serial);
    let (inner, version) = tw::unversioned(&bytes).unwrap();
    let mut tx = TopologyTransaction::decode(inner.as_slice()).unwrap();
    tx.operation = operation;
    tw::versioned(tx.encode_to_vec(), version)
}

/// T-4: a delegation signed in namespace A neither changes nor removes a key of namespace B. The same key delegated in both is two
/// delegations; removing A's leaves B's.
#[test]
fn a_delegation_in_one_namespace_does_not_change_or_remove_a_key_of_another() {
    let (a, b, k) = (key(81), key(82), key(83));
    let mut tracker = tracker_of_roots(&[&a, &b]);
    let (na, nb) = (a.fingerprint.clone(), b.fingerprint.clone());
    join(&mut tracker, &format!("p::{nb}"), &b);
    let ns = [SigningKeyUsage::Namespace];
    let in_b = delegation(&nb, &k, &ns, all(), 1, REPLACE);
    assert!(send(&mut tracker, &in_b, &[&b]).is_in_force());
    let in_a = delegation(&na, &k, &ns, all(), 1, REPLACE);
    assert!(send(&mut tracker, &in_a, &[&a]).is_in_force());
    let code = Code::PartyToParticipant;
    assert!(
        tracker.authorizes(&na, &signers(&[&k]), code)
            && tracker.authorizes(&nb, &signers(&[&k]), code)
    );

    // A revokes its own delegation of k: k no longer speaks for A, still for B
    let removed_in_a = delegation(&na, &k, &ns, all(), 2, REMOVE);
    assert!(send(&mut tracker, &removed_in_a, &[&a]).is_in_force());
    assert!(!tracker.authorizes(&na, &signers(&[&k]), code));
    assert!(
        tracker.authorizes(&nb, &signers(&[&k]), code),
        "a removal in namespace A took B's key"
    );
    let party_of_b = format!("bob::{nb}");
    let o = send(
        &mut tracker,
        &hosting(&party_of_b, &format!("p::{nb}"), 1, REPLACE),
        &[&k],
    );
    assert!(o.is_in_force(), "{}", o.note());

    // A signs B's delegations: neither a new key nor the removal of k takes effect in B
    let intruder = key(84);
    let into_b = delegation(&nb, &intruder, &ns, all(), 1, REPLACE);
    let o = send(&mut tracker, &into_b, &[&a]);
    assert!(matches!(o, Outcome::Refused(_)), "{}", o.note());
    assert!(!tracker.authorizes(&nb, &signers(&[&intruder]), code));
    let removal_of_b = delegation(&nb, &k, &ns, all(), 2, REMOVE);
    let o = send(&mut tracker, &removal_of_b, &[&a]);
    assert!(matches!(o, Outcome::Refused(_)), "{}", o.note());
    assert!(tracker.authorizes(&nb, &signers(&[&k]), code));
    // control: B removes it
    assert!(send(&mut tracker, &removal_of_b, &[&b]).is_in_force());
    assert!(!tracker.authorizes(&nb, &signers(&[&k]), code));
}

/// T-4: a key authorizes only through a chain from its namespace's root, and a revoked link revokes what it chained.
#[test]
fn a_key_authorizes_only_through_a_chain_from_the_root() {
    let (root, k1, k2) = (key(85), key(86), key(87));
    let mut tracker = tracker_of_roots(&[&root]);
    let n = root.fingerprint.clone();
    let ns = [SigningKeyUsage::Namespace];
    assert!(send(
        &mut tracker,
        &delegation(&n, &k1, &ns, all(), 1, REPLACE),
        &[&root]
    )
    .is_in_force());
    assert!(send(
        &mut tracker,
        &delegation(&n, &k2, &ns, all(), 1, REPLACE),
        &[&k1]
    )
    .is_in_force());
    let code = Code::VettedPackages;
    assert!(tracker.authorizes(&n, &signers(&[&k2]), code));
    // revoking k1 leaves k2 dangling
    assert!(send(
        &mut tracker,
        &delegation(&n, &k1, &ns, all(), 2, REMOVE),
        &[&root]
    )
    .is_in_force());
    assert!(!tracker.authorizes(&n, &signers(&[&k2]), code));
    assert!(tracker.authorizes(&n, &signers(&[&root]), code));
}

/// T-5: after a REMOVE the serial goes on. The removed hosting replayed and a fresh serial 1 are refused; the next serial is taken.
#[test]
fn after_a_remove_only_the_next_serial_is_taken() {
    let root = key(91);
    let mut tracker = tracker_of_roots(&[&root]);
    let n = root.fingerprint.clone();
    let (party, host) = (format!("alice::{n}"), format!("p1::{n}"));
    join(&mut tracker, &host, &root);
    join(&mut tracker, &format!("p2::{n}"), &root);
    let first = hosting(&party, &host, 1, REPLACE);
    assert!(send(&mut tracker, &first, &[&root]).is_in_force());
    assert!(send(&mut tracker, &hosting(&party, &host, 2, REMOVE), &[&root]).is_in_force());
    assert_eq!(tracker.hosts_of(&party), None);
    // the removed transaction replayed
    let o = send(&mut tracker, &first, &[&root]);
    assert!(
        o.note().contains("not the next one after 2"),
        "{}",
        o.note()
    );
    assert_eq!(
        tracker.hosts_of(&party),
        None,
        "the removed hosting came back"
    );
    // a new mapping starting over at serial 1, or skipping one
    let other_host = format!("p2::{n}");
    for serial in [1, 2, 4] {
        let o = send(
            &mut tracker,
            &hosting(&party, &other_host, serial, REPLACE),
            &[&root],
        );
        assert!(
            matches!(o, Outcome::Refused(_)),
            "serial {serial}: {}",
            o.note()
        );
    }
    // control: the next serial
    let o = send(
        &mut tracker,
        &hosting(&party, &other_host, 3, REPLACE),
        &[&root],
    );
    assert!(o.is_in_force(), "{}", o.note());
    assert_eq!(tracker.hosts_of(&party), Some((1, vec![(other_host, 1)])));
}

/// T-5, T-12: a revoked delegation does not come back, replayed or at the next serial, and a namespace delegation follows the serial
/// rule as any mapping.
#[test]
fn a_namespace_delegation_keeps_the_serial_rule_through_its_removal() {
    let (root, k) = (key(92), key(93));
    let mut tracker = tracker_of_roots(&[&root]);
    let n = root.fingerprint.clone();
    let ns = [SigningKeyUsage::Namespace];
    let code = Code::PartyToParticipant;
    let granted = delegation(&n, &k, &ns, all(), 1, REPLACE);
    assert!(send(&mut tracker, &granted, &[&root]).is_in_force());
    // the same key again at serial 1 with another restriction, or at a serial that skips one
    let narrower =
        Restriction::CanSignAllButNamespaceDelegations(CanSignAllButNamespaceDelegations {});
    for (serial, restriction) in [(1, narrower.clone()), (3, narrower.clone())] {
        let o = send(
            &mut tracker,
            &delegation(&n, &k, &ns, restriction, serial, REPLACE),
            &[&root],
        );
        assert!(
            o.note().contains("is not the next one"),
            "serial {serial}: {}",
            o.note()
        );
    }
    let revoked = delegation(&n, &k, &ns, all(), 2, REMOVE);
    assert!(send(&mut tracker, &revoked, &[&root]).is_in_force());
    assert!(!tracker.authorizes(&n, &signers(&[&k]), code));
    // replayed, the grant stays refused
    let o = send(&mut tracker, &granted, &[&root]);
    assert!(matches!(o, Outcome::Refused(_)), "{}", o.note());
    assert!(
        !tracker.authorizes(&n, &signers(&[&k]), code),
        "a revoked key came back"
    );
    // a new grant at the next serial is refused too: a revoked key is never delegated again (`checkKeyWasNotPreviouslyRevoked`)
    let o = send(
        &mut tracker,
        &delegation(&n, &k, &ns, narrower, 3, REPLACE),
        &[&root],
    );
    assert!(o.note().contains("NamespaceHasBeenRevoked"), "{}", o.note());
    assert!(!tracker.authorizes(&n, &signers(&[&k]), code));
}

/// T-8: a key delegated for specific mappings signs only those; a key that may not sign delegations cannot delegate; a root certificate
/// must be able to sign delegations.
#[test]
fn a_delegation_restriction_limits_what_its_key_signs() {
    let (root, hosts, no_nsd, k2) = (key(101), key(102), key(103), key(104));
    let mut tracker = tracker_of_roots(&[&root]);
    let n = root.fingerprint.clone();
    join(&mut tracker, &format!("p1::{n}"), &root);
    let ns = [SigningKeyUsage::Namespace];
    let only_hosting = Restriction::CanSignSpecificMapings(CanSignSpecificMappings {
        mappings: vec![Code::PartyToParticipant as i32],
    });
    assert!(send(
        &mut tracker,
        &delegation(&n, &hosts, &ns, only_hosting, 1, REPLACE),
        &[&root]
    )
    .is_in_force());
    // another mapping kind: not authorized; control: the kind it may sign
    let vetting = tw::vetted_packages(&format!("p1::{n}"), &["pkg".to_string()]);
    let o = send(&mut tracker, &vetting, &[&hosts]);
    assert!(matches!(o, Outcome::Refused(_)), "{}", o.note());
    let o = send(
        &mut tracker,
        &hosting(&format!("alice::{n}"), &format!("p1::{n}"), 1, REPLACE),
        &[&hosts],
    );
    assert!(o.is_in_force(), "{}", o.note());

    let not_delegations =
        Restriction::CanSignAllButNamespaceDelegations(CanSignAllButNamespaceDelegations {});
    assert!(send(
        &mut tracker,
        &delegation(&n, &no_nsd, &ns, not_delegations.clone(), 1, REPLACE),
        &[&root]
    )
    .is_in_force());
    let o = send(
        &mut tracker,
        &delegation(&n, &k2, &ns, all(), 1, REPLACE),
        &[&no_nsd],
    );
    assert!(matches!(o, Outcome::Refused(_)), "{}", o.note());
    assert!(!tracker.authorizes(&n, &signers(&[&k2]), Code::PartyToParticipant));
    // control: the same delegation by a key that may sign delegations
    let o = send(
        &mut tracker,
        &delegation(&n, &k2, &ns, all(), 1, REPLACE),
        &[&root],
    );
    assert!(o.is_in_force(), "{}", o.note());

    // a root certificate that could not sign further delegations does not parse
    let lone = key(105);
    let o = send(
        &mut tracker,
        &delegation(&lone.fingerprint, &lone, &ns, not_delegations, 1, REPLACE),
        &[&lone],
    );
    assert!(
        o.note().contains("needs to be be able to sign"),
        "{}",
        o.note()
    );
    let o = send(
        &mut tracker,
        &delegation(&lone.fingerprint, &lone, &ns, all(), 1, REPLACE),
        &[&lone],
    );
    assert!(o.is_in_force(), "{}", o.note());
}

/// T-8: a delegation's key must have the namespace usage, and a key a mapping names proves possession only if its usages allow it.
#[test]
fn a_key_without_the_usage_cannot_authorize() {
    let (root, protocol_only, member_key) = (key(111), key(112), key(113));
    let mut tracker = tracker_of_roots(&[&root]);
    let n = root.fingerprint.clone();
    join(&mut tracker, &format!("p1::{n}"), &root);
    let o = send(
        &mut tracker,
        &delegation(
            &n,
            &protocol_only,
            &[SigningKeyUsage::Protocol],
            all(),
            1,
            REPLACE,
        ),
        &[&root],
    );
    assert!(
        o.note().contains("must include a Namespace usage"),
        "{}",
        o.note()
    );
    let party = format!("alice::{n}");
    let o = send(
        &mut tracker,
        &hosting(&party, &format!("p1::{n}"), 1, REPLACE),
        &[&protocol_only],
    );
    assert!(matches!(o, Outcome::Refused(_)), "{}", o.note());
    // control: with the namespace usage
    let o = send(
        &mut tracker,
        &delegation(
            &n,
            &protocol_only,
            &[SigningKeyUsage::Namespace, SigningKeyUsage::Protocol],
            all(),
            1,
            REPLACE,
        ),
        &[&root],
    );
    assert!(o.is_in_force(), "{}", o.note());

    let member = format!("MED::joiner::{n}");
    let mapping = |usages: &[SigningKeyUsage], serial: u32| {
        tw::owner_to_key_mapping_at(
            &member,
            vec![PublicKey {
                key: Some(PublicKeyKind::SigningPublicKey(
                    member_key.public_key(usages),
                )),
            }],
            serial,
            REPLACE,
        )
    };
    let o = send(
        &mut tracker,
        &mapping(&[SigningKeyUsage::Protocol], 1),
        &[&root, &member_key],
    );
    assert!(
        o.note().contains("may not sign for that use"),
        "{}",
        o.note()
    );
    assert_eq!(tracker.signing_keys_of(&member), None);
    let o = send(
        &mut tracker,
        &mapping(
            &[SigningKeyUsage::Protocol, SigningKeyUsage::ProofOfOwnership],
            1,
        ),
        &[&root, &member_key],
    );
    assert!(o.note().contains("are in force"), "{}", o.note());
}

/// The node's `mergeSignatures`: the transaction in force broadcast again with another signature is taken, not refused for its serial.
#[test]
fn a_signature_after_the_threshold_merges_into_the_transaction_in_force() {
    let root = key(121);
    let mut tracker = tracker_of_roots(&[&root]);
    let n = root.fingerprint.clone();
    join(&mut tracker, &format!("p1::{n}"), &root);
    let tx = hosting(&format!("alice::{n}"), &format!("p1::{n}"), 1, REPLACE);
    assert!(send(&mut tracker, &tx, &[&root]).is_in_force());
    let o = send(&mut tracker, &tx, &[&root]);
    assert!(o.note().contains("signatures merged"), "{}", o.note());
}

/// A downloaded state builds the graphs from its delegations: a delegation the state lists without a chain to the root authorizes
/// nothing, and a REMOVE at the highest serial leaves the key out.
#[test]
fn a_downloaded_state_authorizes_through_the_same_graphs() {
    let (root, k, stray, signer_of_stray) = (key(131), key(132), key(133), key(134));
    let n = root.fingerprint.clone();
    let ns = [SigningKeyUsage::Namespace];
    let stored = |tx: Vec<u8>, by: &[&tw::Ed25519Key]| {
        let signatures = by.iter().map(|s| s.sign_transaction(&tx)).collect();
        tw::stored_form(&tw::signed(tx, signatures))
    };
    let state = decode(&[
        (
            0,
            stored(delegation(&n, &root, &ns, all(), 1, REPLACE), &[&root]),
        ),
        (
            0,
            stored(delegation(&n, &k, &ns, all(), 1, REPLACE), &[&root]),
        ),
        (
            0,
            stored(delegation(&n, &k, &ns, all(), 2, REMOVE), &[&root]),
        ),
        (
            0,
            stored(
                delegation(&n, &stray, &ns, all(), 1, REPLACE),
                &[&signer_of_stray],
            ),
        ),
    ])
    .unwrap();
    let tracker = Tracker::from_state(&state, "PAR::me::ns");
    let code = Code::PartyToParticipant;
    assert!(tracker.authorizes(&n, &signers(&[&root]), code));
    assert!(
        !tracker.authorizes(&n, &signers(&[&k]), code),
        "removed in the state"
    );
    assert!(
        !tracker.authorizes(&n, &signers(&[&stray]), code),
        "not chained to the root"
    );
}
