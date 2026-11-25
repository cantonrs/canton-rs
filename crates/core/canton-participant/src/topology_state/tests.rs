use super::*;

fn entry(tx_bytes: Vec<u8>) -> Entry {
    let signed = tw::signed(tx_bytes, vec![]);
    decode(&[(0, tw::stored_form(&signed))]).unwrap().remove(0)
}

fn party(party: &str, hosts: &[(&str, i32)], serial: u32) -> Entry {
    entry(tw::party_to_participant_at_serial(party, hosts, 1, serial))
}

#[test]
fn a_party_is_hosted_only_if_the_permission_lets_the_participant_confirm() {
    let entries = [
        party("a::ns", &[("me::fp", 1)], 1),
        party("b::ns", &[("me::fp", 2)], 1),
        party("c::ns", &[("me::fp", 3)], 1),
        party("d::ns", &[("other::fp", 1)], 1),
    ];
    let l = learn(&entries, "PAR::me::fp");
    assert_eq!(
        l.hosted_parties,
        vec!["a::ns".to_string(), "b::ns".to_string()]
    );
}

#[test]
fn the_highest_serial_of_a_party_is_the_current_hosting() {
    let entries = [
        party("a::ns", &[("me::fp", 1)], 1),
        party("a::ns", &[("other::fp", 1)], 2),
        party("b::ns", &[("other::fp", 1)], 1),
        party("b::ns", &[("me::fp", 2), ("other::fp", 1)], 2),
    ];
    let l = learn(&entries, "PAR::me::fp");
    assert_eq!(
        l.hosted_parties,
        vec!["b::ns".to_string()],
        "a was handed to the other participant, b was added to this one"
    );
}

#[test]
fn a_physical_synchronizer_id_parses_orders_and_forbids_a_protocol_version_downgrade() {
    let current = Psid::parse("sync::1220aa::37-0").unwrap();
    assert_eq!((current.serial, current.protocol_version), (0, 37));
    assert_eq!(current.to_string(), "sync::1220aa::37-0");
    assert_eq!(
        Psid::parse("sync::1220aa::dev-3").unwrap().protocol_version,
        i32::MAX
    );
    assert!(
        Psid::parse("sync::1220aa").is_err()
            && Psid::parse("sync::1220aa::37").is_err()
            && Psid::parse("a::b::x-1").is_err()
    );
    // logical id first, then serial, then protocol version
    assert!(Psid::parse("sync::1220aa::37-1").unwrap() > current);
    assert!(Psid::parse("sync::1220aa::38-0").unwrap() > current);
    assert!(
        Psid::parse("sync::1220aa::36-1").unwrap() > current,
        "a higher serial wins over a lower version"
    );
    // the downgrade rule: a higher serial on a lower version, only from version 37 on
    assert!(is_forbidden_protocol_version_downgrade(
        &current,
        &Psid::parse("sync::1220aa::36-1").unwrap()
    ));
    assert!(!is_forbidden_protocol_version_downgrade(
        &current,
        &Psid::parse("sync::1220aa::37-1").unwrap()
    ));
    assert!(
        !is_forbidden_protocol_version_downgrade(
            &current,
            &Psid::parse("sync::1220aa::36-0").unwrap()
        ),
        "same serial is no upgrade"
    );
    let old = Psid::parse("sync::1220aa::36-0").unwrap();
    assert!(
        !is_forbidden_protocol_version_downgrade(&old, &Psid::parse("sync::1220aa::35-1").unwrap()),
        "version 36 predates the rule"
    );
}

#[test]
fn a_timestamp_is_written_as_the_node_writes_it() {
    assert_eq!(
        iso_utc(0),
        "1970-01-01T00:00:00Z",
        "no fraction when it is zero"
    );
    assert_eq!(
        iso_utc(1_500_000),
        "1970-01-01T00:00:01.500Z",
        "three digits when they are enough"
    );
    // a request id of the JVM log: RequestId(2026-11-13T05:40:02.451173Z)
    assert_eq!(
        iso_utc(1_794_548_402_451_173),
        "2026-11-13T05:40:02.451173Z"
    );
    assert_eq!(iso_utc(-1), "1969-12-31T23:59:59.999999Z");
}

#[test]
fn a_state_that_does_not_decode_is_refused() {
    assert!(decode(&[(0, vec![1, 2, 3])]).is_err());
}

#[test]
fn an_envelope_that_is_not_a_topology_broadcast_is_not_taken_for_one() {
    assert!(!is_topology_broadcast(&[]));
    assert!(!is_topology_broadcast(&[1, 2, 3]));
    let broadcast = tw::topology_broadcast("sync", &[tw::signed(vec![1], vec![])]);
    assert!(is_topology_broadcast(&broadcast));
}

/// A delegation revoked by a REMOVE stops authorizing: the key of a namespace delegation is followed after the delegation and no
/// longer after its removal (both signed by the namespace's root key).
#[test]
fn a_removed_delegation_stops_authorizing_its_key() {
    use canton_proto::com::digitalasset::canton::crypto::v30::SigningKeyUsage;
    let root = tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
    let delegate =
        tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[8; 32]));
    let namespace = root.fingerprint.clone();
    let usages = [SigningKeyUsage::Namespace];
    // the state the participant downloaded: the root delegation of the namespace
    let root_delegation = tw::namespace_delegation(&namespace, root.public_key(&usages));
    let state = decode(&[(
        0,
        tw::stored_form(&tw::signed(
            root_delegation.clone(),
            vec![root.sign_transaction(&root_delegation)],
        )),
    )])
    .unwrap();
    let mut tracker = Tracker::from_state(&state, "PAR::me::ns");
    assert!(tracker
        .auth
        .is_authorized_key(&namespace, &root.fingerprint));
    // the root key delegates to another key: it is followed
    let add = tw::namespace_delegation(&namespace, delegate.public_key(&usages));
    let stored = tw::stored_form(&tw::signed(add.clone(), vec![root.sign_transaction(&add)]));
    assert!(tracker.apply_stored(&stored).contains("is in force"));
    assert!(tracker
        .auth
        .is_authorized_key(&namespace, &delegate.fingerprint));
    // a removal that nobody authorized changes nothing
    let remove = tw::namespace_delegation_removal(&namespace, delegate.public_key(&usages));
    let by_stranger =
        tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    let stored = tw::stored_form(&tw::signed(
        remove.clone(),
        vec![by_stranger.sign_transaction(&remove)],
    ));
    assert!(tracker
        .apply_stored(&stored)
        .contains("lacks the authorization"));
    assert!(tracker
        .auth
        .is_authorized_key(&namespace, &delegate.fingerprint));
    // the root key's removal revokes it
    let stored = tw::stored_form(&tw::signed(
        remove.clone(),
        vec![root.sign_transaction(&remove)],
    ));
    assert!(tracker.apply_stored(&stored).contains("is revoked"));
    assert!(!tracker
        .auth
        .is_authorized_key(&namespace, &delegate.fingerprint));
    assert!(
        tracker
            .auth
            .is_authorized_key(&namespace, &root.fingerprint),
        "the root key stays"
    );
}

/// Proof of possession: a key mapping signed in the member's namespace only is not followed until the key it names signed it too.
#[test]
fn a_key_mapping_needs_the_signature_of_the_key_it_names() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        public_key::Key, PublicKey, SigningKeyUsage,
    };
    let root = tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[11; 32]));
    let member_key =
        tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[12; 32]));
    let namespace = root.fingerprint.clone();
    let root_delegation =
        tw::namespace_delegation(&namespace, root.public_key(&[SigningKeyUsage::Namespace]));
    let state = decode(&[(
        0,
        tw::stored_form(&tw::signed(
            root_delegation.clone(),
            vec![root.sign_transaction(&root_delegation)],
        )),
    )])
    .unwrap();
    let mut tracker = Tracker::from_state(&state, "PAR::me::ns");
    let member = format!("MED::joiner::{namespace}");
    let mapping = tw::owner_to_key_mapping(
        &member,
        vec![PublicKey {
            key: Some(Key::SigningPublicKey(member_key.public_key(&[
                SigningKeyUsage::Protocol,
                SigningKeyUsage::ProofOfOwnership,
            ]))),
        }],
    );
    // the namespace alone: not followed
    let stored = tw::stored_form(&tw::signed(
        mapping.clone(),
        vec![root.sign_transaction(&mapping)],
    ));
    assert!(tracker
        .apply_stored(&stored)
        .contains("proof of possession"));
    assert!(!tracker.members.contains_key(&member));
    // a signature of another key (not the one the mapping names) does not count as the proof
    let other = tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[13; 32]));
    let stored = tw::stored_form(&tw::signed(
        mapping.clone(),
        vec![
            root.sign_transaction(&mapping),
            other.sign_transaction(&mapping),
        ],
    ));
    assert!(tracker
        .apply_stored(&stored)
        .contains("proof of possession"));
    // with the key's own signature as well: followed
    let stored = tw::stored_form(&tw::signed(
        mapping.clone(),
        vec![
            root.sign_transaction(&mapping),
            member_key.sign_transaction(&mapping),
        ],
    ));
    assert!(tracker.apply_stored(&stored).contains("are in force"));
    assert_eq!(
        tracker
            .members
            .get(&member)
            .map(|m| m.1.iter().map(|k| k.id.clone()).collect::<Vec<_>>()),
        Some(vec![member_key.fingerprint])
    );
}

/// The encryption keys of a mapping follow the namespace's authorization (an encryption key cannot sign, so it has no proof of
/// possession), are kept per member, are replaced by a newer serial and dropped with a REMOVE; other key specs are not taken.
#[test]
fn the_encryption_keys_of_a_member_follow_its_authorized_mapping() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        public_key::Key, PublicKey, SigningKeyUsage,
    };
    let root = tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[21; 32]));
    let member_key =
        tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[22; 32]));
    let namespace = root.fingerprint.clone();
    let delegation =
        tw::namespace_delegation(&namespace, root.public_key(&[SigningKeyUsage::Namespace]));
    let state = decode(&[(
        0,
        tw::stored_form(&tw::signed(
            delegation.clone(),
            vec![root.sign_transaction(&delegation)],
        )),
    )])
    .unwrap();
    let mut tracker = Tracker::from_state(&state, "PAR::me::ns");
    let member = format!("PAR::joiner::{namespace}");
    let first = tw::ParticipantIdentity::generate("enc-one");
    let second = tw::ParticipantIdentity::generate("enc-two");
    let mapping = |enc: Option<&tw::ParticipantIdentity>, serial: u32, operation: i32| {
        let mut keys = vec![PublicKey {
            key: Some(Key::SigningPublicKey(member_key.public_key(&[
                SigningKeyUsage::Protocol,
                SigningKeyUsage::ProofOfOwnership,
            ]))),
        }];
        if let Some(e) = enc {
            keys.push(tw::p256_encryption_key(e.encryption_spki()));
        }
        tw::owner_to_key_mapping_at(&member, keys, serial, operation)
    };
    let send = |tracker: &mut Tracker, tx: &[u8], by: &[&tw::Ed25519Key]| {
        let signatures = by.iter().map(|k| k.sign_transaction(tx)).collect();
        tracker.apply_stored(&tw::stored_form(&tw::signed(tx.to_vec(), signatures)))
    };
    let encryption = |tracker: &Tracker| tracker.learned().encryption_keys.get(&member).cloned();
    let key_of = |id: &tw::ParticipantIdentity| EncryptionKey {
        spki: id.encryption_spki().to_vec(),
        fingerprint: id.encryption_fingerprint(),
    };
    // the member's own key alone is not the namespace's authorization: no key at all, signing or encryption
    let m1 = mapping(Some(&first), 1, 1);
    let note = send(&mut tracker, &m1, &[&member_key]);
    assert!(note.contains("lacks the authorization"), "{note}");
    assert_eq!(encryption(&tracker), None);
    // authorized: the key is learned with the fingerprint of its DER
    assert!(send(&mut tracker, &m1, &[&root, &member_key]).contains("are in force"));
    assert_eq!(encryption(&tracker), Some(vec![key_of(&first)]));
    // a later serial with another key replaces the first one
    let m2 = mapping(Some(&second), 2, 1);
    assert!(send(&mut tracker, &m2, &[&root, &member_key]).contains("are in force"));
    assert_eq!(encryption(&tracker), Some(vec![key_of(&second)]));
    // a participant's mapping without an encryption key is refused (`InvalidOwnerToKeyMapping`): the key stays
    let m3 = mapping(None, 3, 1);
    let note = send(&mut tracker, &m3, &[&root, &member_key]);
    assert!(note.contains("no encryption key"), "{note}");
    assert_eq!(encryption(&tracker), Some(vec![key_of(&second)]));
    // a REMOVE (of the mapping in force) drops the member
    let m4 = mapping(Some(&second), 3, 2);
    send(&mut tracker, &m4, &[&root, &member_key]);
    assert_eq!(encryption(&tracker), None);
}

/// Synchronizer parameters: a change needs the threshold of the decentralized namespace's owners and exactly the next serial.
#[test]
fn a_parameter_change_needs_the_owners_threshold_and_the_next_serial() {
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        DynamicSynchronizerParameters, SynchronizerParametersState,
    };
    let [seq, med, mallory] = [71u8, 72, 73]
        .map(|s| tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[s; 32])));
    let mut tracker = tracker_of_roots(&[&seq, &med, &mallory]);
    let owners = [seq.fingerprint.as_str(), med.fingerprint.as_str()];
    let dns = decentralized_namespace_of(&owners.map(String::from).into()).unwrap();
    assert!(send(
        &mut tracker,
        &definition(&dns, 2, &owners, 1, 1),
        &[&seq, &med]
    )
    .is_in_force());
    let change = |secs: i64, serial: u32| {
        transaction_of(
            Mapping::SynchronizerParametersState(SynchronizerParametersState {
                synchronizer_id: format!("sync::{dns}"),
                synchronizer_parameters: Some(DynamicSynchronizerParameters {
                    confirmation_response_timeout: Some(prost_types::Duration {
                        seconds: secs,
                        nanos: 0,
                    }),
                    mediator_reaction_timeout: Some(prost_types::Duration {
                        seconds: 30,
                        nanos: 0,
                    }),
                    ..Default::default()
                }),
            }),
            serial,
            1,
        )
    };
    assert!(send(&mut tracker, &change(40, 1), &[&seq, &med]).is_in_force());
    // one owner of two proposes: waiting, nothing changes
    let o = propose(&mut tracker, &change(50, 2), &[&seq]);
    assert!(
        o.note().contains("waiting for the authorization"),
        "{}",
        o.note()
    );
    // a stranger's signature does not count, and what is not a proposal is refused
    let o = send(&mut tracker, &change(51, 2), &[&seq, &mallory]);
    assert!(o.note().contains("lacks the authorization"), "{}", o.note());
    assert_eq!(tracker.params_serial, Some(1));
    // both owners but a serial that skips one
    let o = send(&mut tracker, &change(50, 3), &[&seq, &med]);
    assert!(o.note().contains("not the next"), "{}", o.note());
    assert_eq!(tracker.params_serial, Some(1));
    // the other owner signs the first change: with the signature already seen, in force
    let o = send(&mut tracker, &change(50, 2), &[&med]);
    assert!(o.note().contains("are in force"), "{}", o.note());
    assert_eq!(tracker.params_serial, Some(2));
    assert_eq!(
        tracker
            .base
            .timeouts
            .map(|t| t.confirmation_response_micros),
        Some(50_000_000)
    );
}

#[allow(
    deprecated,
    reason = "populates legacy/deprecated Canton protobuf or pinned crypto fields for wire compatibility"
)]
fn vetted_tx_bytes(
    participant_uid: &str,
    pkg_ids: &[&str],
    serial: u32,
    operation: i32,
) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v30::vetted_packages::VettedPackage;
    use canton_proto::com::digitalasset::canton::protocol::v30::VettedPackages;
    use canton_proto::com::digitalasset::canton::protocol::v31;
    let tx = v31::TopologyTransaction {
        operation,
        serial,
        mapping: Some(v31::TopologyMapping {
            mapping: Some(v31::topology_mapping::Mapping::VettedPackages(
                VettedPackages {
                    participant_uid: participant_uid.to_string(),
                    package_ids: Vec::new(),
                    packages: pkg_ids
                        .iter()
                        .map(|id| VettedPackage {
                            package_id: (*id).to_string(),
                            valid_from_inclusive: None,
                            valid_until_exclusive: None,
                        })
                        .collect(),
                },
            )),
        }),
    };
    tw::versioned(tx.encode_to_vec(), tw::TOPOLOGY_TRANSACTION_VERSION)
}

#[test]
fn tracker_handles_vetted_package_serials_remove_and_replace() {
    use canton_proto::com::digitalasset::canton::crypto::v30::SigningKeyUsage;
    let root = tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[31; 32]));
    let ns = root.fingerprint.clone();
    let uid = format!("alpha::{ns}");
    let root_del = tw::namespace_delegation(&ns, root.public_key(&[SigningKeyUsage::Namespace]));
    let state = decode(&[(
        0,
        tw::stored_form(&tw::signed(
            root_del.clone(),
            vec![root.sign_transaction(&root_del)],
        )),
    )])
    .unwrap();
    let mut tracker = Tracker::from_state(&state, &format!("PAR::me::{ns}"));

    let v1 = vetted_tx_bytes(&uid, &["pkg-1"], 1, 1);
    let note1 = tracker.apply_stored(&tw::stored_form(&tw::signed(
        v1.clone(),
        vec![root.sign_transaction(&v1)],
    )));
    assert!(note1.contains("is in force"), "{note1}");
    assert_eq!(
        tracker.learned().vetted_packages.get(&uid),
        Some(&["pkg-1".to_string()].into_iter().collect())
    );

    let v_skip = vetted_tx_bytes(&uid, &["pkg-1", "pkg-2"], 3, 1);
    let note_skip = tracker.apply_stored(&tw::stored_form(&tw::signed(
        v_skip.clone(),
        vec![root.sign_transaction(&v_skip)],
    )));
    assert!(note_skip.contains("not the next"), "{note_skip}");

    let v2_rm = vetted_tx_bytes(&uid, &["pkg-1"], 2, 2);
    let note2 = tracker.apply_stored(&tw::stored_form(&tw::signed(
        v2_rm.clone(),
        vec![root.sign_transaction(&v2_rm)],
    )));
    assert!(note2.contains("is in force"), "{note2}");
    assert!(!tracker.learned().vetted_packages.contains_key(&uid));

    let v3 = vetted_tx_bytes(&uid, &["pkg-2"], 3, 1);
    let note3 = tracker.apply_stored(&tw::stored_form(&tw::signed(
        v3.clone(),
        vec![root.sign_transaction(&v3)],
    )));
    assert!(note3.contains("is in force"), "{note3}");
    assert_eq!(
        tracker.learned().vetted_packages.get(&uid),
        Some(&["pkg-2".to_string()].into_iter().collect())
    );
}

#[test]
fn tracker_treats_registered_participant_as_implicit_admin_party_when_unmapped() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        public_key::Key as PublicKeyKind, PublicKey, SigningKeyUsage,
    };
    let root = tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[41; 32]));
    let ns = root.fingerprint.clone();
    let peer_uid = format!("peer::{ns}");
    let peer_member = format!("PAR::{peer_uid}");
    let del = tw::namespace_delegation(&ns, root.public_key(&[SigningKeyUsage::Namespace]));
    let keys = tw::owner_to_key_mapping(
        &peer_member,
        vec![PublicKey {
            key: Some(PublicKeyKind::SigningPublicKey(root.public_key(&[
                SigningKeyUsage::Protocol,
                SigningKeyUsage::ProofOfOwnership,
            ]))),
        }],
    );
    let state = decode(&[
        (
            0,
            tw::stored_form(&tw::signed(del.clone(), vec![root.sign_transaction(&del)])),
        ),
        (
            1,
            tw::stored_form(&tw::signed(
                keys.clone(),
                vec![root.sign_transaction(&keys)],
            )),
        ),
    ])
    .unwrap();
    let mut tracker = Tracker::from_state(&state, &format!("PAR::me::{ns}"));

    assert_eq!(
        tracker.hosting_of(&peer_uid),
        Some((1, vec![peer_uid.clone()]))
    );
    assert_eq!(
        tracker.hosts_of(&peer_uid),
        Some((1, vec![(peer_uid.clone(), 1)]))
    );
    assert_eq!(tracker.hosts_of("unknown::ns"), None);

    // An explicit PartyToParticipant mapping overrides the fallback when present.
    let custom_uid = format!("other::{ns}");
    join(&mut tracker, &custom_uid, &root);
    let p2p = tw::party_to_participant_at_serial(&peer_uid, &[(&custom_uid, 2)], 1, 1);
    let note = tracker.apply_stored(&tw::stored_form(&tw::signed(
        p2p.clone(),
        vec![root.sign_transaction(&p2p)],
    )));
    assert!(note.contains("is in force"), "{note}");
    assert_eq!(
        tracker.hosting_of(&peer_uid),
        Some((1, vec![custom_uid.clone()]))
    );
    assert_eq!(
        tracker.hosts_of(&peer_uid),
        Some((1, vec![(custom_uid, 2)]))
    );
}

/// The (versioned) bytes of a topology transaction of `mapping`.
pub(super) fn transaction_of(mapping: Mapping, serial: u32, operation: i32) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v31;
    let tx = v31::TopologyTransaction {
        operation,
        serial,
        mapping: Some(v31::TopologyMapping {
            mapping: Some(mapping),
        }),
    };
    tw::versioned(tx.encode_to_vec(), tw::TOPOLOGY_TRANSACTION_VERSION)
}

pub(super) fn definition(
    namespace: &str,
    threshold: i32,
    owners: &[&str],
    serial: u32,
    op: i32,
) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v30::DecentralizedNamespaceDefinition;
    transaction_of(
        Mapping::DecentralizedNamespaceDefinition(DecentralizedNamespaceDefinition {
            decentralized_namespace: namespace.to_string(),
            threshold,
            owners: owners.iter().map(|o| o.to_string()).collect(),
        }),
        serial,
        op,
    )
}

/// A tracker whose downloaded state holds the root delegation of each key: each key speaks for its own namespace.
pub(super) fn tracker_of_roots(keys: &[&tw::Ed25519Key]) -> Tracker {
    use canton_proto::com::digitalasset::canton::crypto::v30::SigningKeyUsage;
    let state: Vec<(i64, Vec<u8>)> = keys
        .iter()
        .map(|k| {
            let d = tw::namespace_delegation(
                &k.fingerprint,
                k.public_key(&[SigningKeyUsage::Namespace]),
            );
            (
                0,
                tw::stored_form(&tw::signed(d.clone(), vec![k.sign_transaction(&d)])),
            )
        })
        .collect();
    Tracker::from_state(&decode(&state).unwrap(), "PAR::me::ns")
}

/// Makes the participant `uid` (of the namespace of `root`) a member as the synchronizer knows one: its keys, then its trust certificate
/// (a hosting names only members, `checkPartyToParticipant`).
pub(super) fn join(tracker: &mut Tracker, uid: &str, root: &tw::Ed25519Key) {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        public_key::Key, PublicKey, SigningKeyUsage,
    };
    let keys = tw::owner_to_key_mapping(
        &format!("PAR::{uid}"),
        vec![
            PublicKey {
                key: Some(Key::SigningPublicKey(
                    root.public_key(&[SigningKeyUsage::Namespace]),
                )),
            },
            tw::p256_encryption_key(&[7; 91]),
        ],
    );
    let o = send(tracker, &keys, &[root]);
    assert!(o.is_in_force(), "{}", o.note());
    let synchronizer = tracker
        .current_psid()
        .map_or_else(|| "sync::ns".to_string(), |p| p.logical.clone());
    let certificate = tw::synchronizer_trust_certificate(uid, &synchronizer, vec![]);
    let o = send(tracker, &certificate, &[root]);
    assert!(o.is_in_force(), "{}", o.note());
}

/// The mapping of a transaction's bytes.
pub(super) fn mapping_of(tx: &[u8]) -> Mapping {
    let (inner, _) = tw::unversioned(tx).unwrap();
    TopologyTransaction::decode(inner.as_slice())
        .unwrap()
        .mapping
        .unwrap()
        .mapping
        .unwrap()
}

/// Broadcasts `tx` as a proposal signed by `by`: it waits for more signatures instead of being refused.
pub(super) fn propose(tracker: &mut Tracker, tx: &[u8], by: &[&tw::Ed25519Key]) -> Outcome {
    let signatures = by.iter().map(|k| k.sign_transaction(tx)).collect();
    tracker
        .apply(&tw::stored_form(&tw::signed_proposal(
            tx.to_vec(),
            signatures,
        )))
        .outcome
}

pub(super) fn send(tracker: &mut Tracker, tx: &[u8], by: &[&tw::Ed25519Key]) -> Outcome {
    let signatures = by.iter().map(|k| k.sign_transaction(tx)).collect();
    tracker
        .apply(&tw::stored_form(&tw::signed(tx.to_vec(), signatures)))
        .outcome
}

/// `computeNamespace` against the JVM: the synchronizer `mysync` the official node bootstrapped has one owner, and its namespace is the one
/// derived from that owner (`tests/oracle/mediator-onboarding/jvm-facts.txt`).
#[test]
fn a_decentralized_namespace_is_derived_from_its_owners_as_the_jvm_derives_it() {
    let facts = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/oracle/mediator-onboarding/jvm-facts.txt"
    ))
    .unwrap();
    let fact = |key: &str| {
        facts
            .lines()
            .find_map(|l| l.strip_prefix(&format!("MOB {key}=")))
            .unwrap()
            .to_string()
    };
    let psid = Psid::parse(&fact("psid")).unwrap();
    let owners: BTreeSet<String> = [fact("owner_ns")].into();
    assert_eq!(
        decentralized_namespace_of(&owners).unwrap(),
        psid.namespace()
    );
}

/// T-1: once a decentralized namespace is defined, only its existing owners (their threshold) can change or remove it, an added owner
/// signs too, and the serial is exactly the next; a first definition needs every owner and a namespace derived from them.
#[test]
fn a_decentralized_namespace_changes_only_with_its_existing_owners() {
    let [a, b, c] = [51u8, 52, 53]
        .map(|s| tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[s; 32])));
    let mut tracker = tracker_of_roots(&[&a, &b, &c]);
    let (na, nb, nc) = (
        a.fingerprint.as_str(),
        b.fingerprint.as_str(),
        c.fingerprint.as_str(),
    );
    let n = decentralized_namespace_of(&[na, nb].map(String::from).into()).unwrap();
    // a root key's fingerprint is its namespace: the owners' keys are named by their namespaces
    let controls = |t: &Tracker, who: &[&str]| {
        t.authorizes(
            &n,
            &who.iter().map(|s| s.to_string()).collect(),
            Code::SynchronizerParametersState,
        )
    };

    // a first definition needs every owner
    let first = definition(&n, 2, &[na, nb], 1, 1);
    let o = send(&mut tracker, &first, &[&a]);
    assert!(!o.is_in_force(), "{}", o.note());
    let o = send(&mut tracker, &first, &[&a, &b]);
    assert!(o.is_in_force(), "{}", o.note());
    assert!(controls(&tracker, &[na, nb]) && !controls(&tracker, &[na]));

    // a stranger redefines the namespace as its own, or removes it, signing alone: nothing changes
    let takeover = definition(&n, 1, &[nc], 2, 1);
    let o = send(&mut tracker, &takeover, &[&c]);
    assert!(!o.is_in_force(), "{}", o.note());
    let removal = definition(&n, 1, &[nc], 2, 2);
    let o = send(&mut tracker, &removal, &[&c]);
    assert!(!o.is_in_force(), "{}", o.note());
    assert!(controls(&tracker, &[na, nb]), "the owners are unchanged");
    assert!(!controls(&tracker, &[nc]));

    // adding an owner: the existing threshold and the added owner (the signatures of a proposal add up over broadcasts)
    let added = definition(&n, 2, &[na, nb, nc], 2, 1);
    let o = propose(&mut tracker, &added, &[&a, &c]);
    assert!(!o.is_in_force(), "one existing owner of two: {}", o.note());
    let without_added = definition(&n, 1, &[na, nb, nc], 2, 1);
    let o = send(&mut tracker, &without_added, &[&a, &b]);
    assert!(!o.is_in_force(), "without the added owner: {}", o.note());
    let skipped = definition(&n, 2, &[na, nb, nc], 3, 1);
    let o = send(&mut tracker, &skipped, &[&a, &b, &c]);
    assert!(o.note().contains("not the next"), "{}", o.note());
    let o = send(&mut tracker, &added, &[&b]);
    assert!(o.is_in_force(), "{}", o.note());
    assert!(controls(&tracker, &[nb, nc]));

    // a first definition whose namespace is not derived from its owners
    let other = tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[54; 32]))
        .fingerprint;
    let underived = definition(&other, 1, &[nc], 1, 1);
    let o = send(&mut tracker, &underived, &[&c]);
    assert!(o.note().contains("not derived"), "{}", o.note());
    assert!(!tracker.authorizes(
        &other,
        &[nc.to_string()].into(),
        Code::SynchronizerParametersState
    ));
}

/// T-3: a tracker that follows synchronizer X takes neither the parameters nor the upgrade announcement of synchronizer Y, even when
/// they carry the signature of Y's namespace.
#[test]
fn a_tracker_takes_no_mapping_of_another_synchronizer() {
    let k = tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[61; 32]));
    let mut tracker = tracker_of_roots(&[&k]);
    tracker.set_current_psid(Psid::parse(&format!("x::{}::37-0", k.fingerprint)).unwrap());
    let y = format!("y::{}", k.fingerprint);
    let params = tw::synchronizer_parameters_state(&y, tw::default_dynamic_parameters());
    let o = send(&mut tracker, &params, &[&k]);
    assert!(!o.is_in_force(), "{}", o.note());
    assert_eq!(tracker.parameters(), None);
    use canton_proto::com::digitalasset::canton::protocol::v30::LsuAnnouncement;
    let announcement = transaction_of(
        Mapping::SynchronizerUpgradeAnnouncement(LsuAnnouncement {
            successor_physical_synchronizer_id: format!("{y}::37-1"),
            upgrade_time: Some(prost_types::Timestamp {
                seconds: 4_000_000_000,
                nanos: 0,
            }),
        }),
        1,
        1,
    );
    let o = send(&mut tracker, &announcement, &[&k]);
    assert!(!o.is_in_force(), "{}", o.note());
    assert_eq!(tracker.announced_upgrade(), None);
}

/// T-6: a downloaded transaction in force whose signature names a key the state knows and does not verify is not taken (Canton replays
/// the snapshot through its validation); the same transaction signed correctly is.
#[test]
fn a_downloaded_transaction_with_a_forged_signature_is_left_out() {
    use crate::topology_wire::{stored_form, ParticipantIdentity};
    let me = ParticipantIdentity::generate("forged-state");
    let state_with = |hosting: canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction| {
        let mut transactions = me.onboarding_transactions("sync::1220aa");
        transactions.push(hosting);
        let state: Vec<(i64, Vec<u8>)> = transactions.iter().map(|t| (0, stored_form(t))).collect();
        Tracker::from_state(&decode(&state).unwrap(), &me.member())
    };
    let erin = me.party_id("erin");
    let honest = state_with(me.party_hosting_transaction("erin"));
    assert!(
        honest.hosts_of(&erin).is_some(),
        "the signed hosting is in force"
    );
    let mut forged = me.party_hosting_transaction("erin");
    for s in &mut forged.signatures {
        s.signature[0] ^= 1;
    }
    assert!(
        state_with(forged).hosts_of(&erin).is_none(),
        "a forged signature is not taken"
    );
}
