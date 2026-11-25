//! T-6, T-7, T-10, T-11, T-12, T-17: the mapping-specific rules, each refusal next to the transaction that is accepted.
use super::tests::{join, send, tracker_of_roots, transaction_of};
use super::*;
use canton_proto::com::digitalasset::canton::crypto::v30::{
    public_key::Key as PublicKeyKind, PublicKey, SigningKeyUsage,
};
use canton_proto::com::digitalasset::canton::protocol::v30::DynamicSynchronizerParameters;
use canton_proto::com::digitalasset::canton::protocol::v31::party_to_participant::HostingParticipant;
use canton_proto::com::digitalasset::canton::protocol::v31::PartyToParticipant;

pub(super) const REPLACE: i32 = 1;
const NOMINATED: i32 = 1;
const ACTIVE: i32 = 4;
const SUBMISSION: i32 = 1;
const CONFIRMATION: i32 = 2;
const OBSERVATION: i32 = 3;

pub(super) fn key(seed: u8) -> tw::Ed25519Key {
    tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

/// The hosting of `party` by `hosts` (`(participant uid, permission, state)`).
pub(super) fn hosting(
    party: &str,
    hosts: &[(&str, i32, i32)],
    threshold: u32,
    serial: u32,
) -> Vec<u8> {
    transaction_of(
        Mapping::PartyToParticipant(PartyToParticipant {
            party: party.to_string(),
            threshold,
            participants: hosts
                .iter()
                .map(|(uid, permission, state)| HostingParticipant {
                    participant_uid: uid.to_string(),
                    permission: *permission,
                    state: *state,
                })
                .collect(),
            party_signing_keys: None,
        }),
        serial,
        REPLACE,
    )
}

pub(super) fn signing_key(k: &tw::Ed25519Key) -> PublicKey {
    PublicKey {
        key: Some(PublicKeyKind::SigningPublicKey(k.public_key(&[
            SigningKeyUsage::Protocol,
            SigningKeyUsage::ProofOfOwnership,
        ]))),
    }
}

/// T-10: a participant leaves alone or downgrades alone; an upgrade needs the party and the participant; the party alone nominates a
/// participant, which moves itself forward alone.
#[test]
fn a_hosting_change_needs_whom_the_change_concerns() {
    let (p, a, b) = (key(101), key(102), key(103));
    let mut tracker = tracker_of_roots(&[&p, &a, &b]);
    let party = format!("alice::{}", p.fingerprint);
    let (ua, ub) = (
        format!("pa::{}", a.fingerprint),
        format!("pb::{}", b.fingerprint),
    );
    join(&mut tracker, &ua, &a);
    join(&mut tracker, &ub, &b);
    let both = hosting(
        &party,
        &[(&ua, SUBMISSION, ACTIVE), (&ub, CONFIRMATION, ACTIVE)],
        1,
        1,
    );
    let o = send(&mut tracker, &both, &[&p, &a, &b]);
    assert!(o.is_in_force(), "{}", o.note());

    // b leaves alone
    let only_a = hosting(&party, &[(&ua, SUBMISSION, ACTIVE)], 1, 2);
    let o = send(&mut tracker, &only_a, &[&b]);
    assert!(
        o.is_in_force(),
        "a participant may unhost a party alone: {}",
        o.note()
    );
    // a downgrades itself alone
    let a_observes = hosting(&party, &[(&ua, OBSERVATION, ACTIVE)], 1, 3);
    let o = send(&mut tracker, &a_observes, &[&a]);
    assert!(
        o.is_in_force(),
        "a participant may downgrade alone: {}",
        o.note()
    );
    // an upgrade needs both
    let a_submits = hosting(&party, &[(&ua, SUBMISSION, ACTIVE)], 1, 4);
    assert!(!send(&mut tracker, &a_submits, &[&p]).is_in_force());
    assert!(!send(&mut tracker, &a_submits, &[&a]).is_in_force());
    let o = send(&mut tracker, &a_submits, &[&p, &a]);
    assert!(o.is_in_force(), "{}", o.note());
    // a threshold change needs the party
    let threshold_2 = hosting(&party, &[(&ua, SUBMISSION, ACTIVE)], 2, 5);
    assert!(!send(&mut tracker, &threshold_2, &[&a]).is_in_force());
    assert!(send(&mut tracker, &threshold_2, &[&p]).is_in_force());

    // the party alone nominates b; b moves itself forward alone, the party cannot move it forward for it
    let nominated = hosting(
        &party,
        &[(&ua, SUBMISSION, ACTIVE), (&ub, CONFIRMATION, NOMINATED)],
        2,
        6,
    );
    let o = send(&mut tracker, &nominated, &[&p]);
    assert!(o.is_in_force(), "the party alone nominates: {}", o.note());
    let active = hosting(
        &party,
        &[(&ua, SUBMISSION, ACTIVE), (&ub, CONFIRMATION, ACTIVE)],
        2,
        7,
    );
    assert!(!send(&mut tracker, &active, &[&p]).is_in_force());
    let o = send(&mut tracker, &active, &[&b]);
    assert!(o.is_in_force(), "b moves itself forward: {}", o.note());
}

/// T-11: a key rotation needs the proof of possession of the new key only; the namespace alone does not add a key.
#[test]
fn a_key_rotation_needs_the_proof_of_the_new_key_only() {
    let (root, k1, k2) = (key(111), key(112), key(113));
    let mut tracker = tracker_of_roots(&[&root]);
    let member = format!("MED::m::{}", root.fingerprint);
    let first = tw::owner_to_key_mapping_at(&member, vec![signing_key(&k1)], 1, REPLACE);
    assert!(send(&mut tracker, &first, &[&root, &k1]).is_in_force());
    let rotated = tw::owner_to_key_mapping_at(
        &member,
        vec![signing_key(&k1), signing_key(&k2)],
        2,
        REPLACE,
    );
    assert!(
        !send(&mut tracker, &rotated, &[&root]).is_in_force(),
        "the new key has to prove possession"
    );
    let o = send(&mut tracker, &rotated, &[&root, &k2]);
    assert!(
        o.is_in_force(),
        "the kept key need not sign again: {}",
        o.note()
    );
}

/// T-17: a trust certificate is taken only for the synchronizer followed; a removed decentralized namespace stays the previous definition,
/// so its owners cannot define it again as if it were new.
#[test]
fn a_trust_certificate_is_restricted_to_its_synchronizer_and_a_removed_namespace_stays_removed() {
    use super::tests::definition;
    let (k, a, b) = (key(121), key(122), key(123));
    let mut tracker = tracker_of_roots(&[&k, &a, &b]);
    tracker.set_current_psid(Psid::parse(&format!("x::{}::37-0", k.fingerprint)).unwrap());
    let participant = format!("p::{}", k.fingerprint);
    let other =
        tw::synchronizer_trust_certificate(&participant, &format!("y::{}", k.fingerprint), vec![]);
    let o = send(&mut tracker, &other, &[&k]);
    assert!(
        o.note().contains("restricted to synchronizer"),
        "{}",
        o.note()
    );

    let owners: BTreeSet<String> = [a.fingerprint.clone(), b.fingerprint.clone()].into();
    let n = decentralized_namespace_of(&owners).unwrap();
    let (na, nb) = (a.fingerprint.as_str(), b.fingerprint.as_str());
    assert!(send(
        &mut tracker,
        &definition(&n, 2, &[na, nb], 1, REPLACE),
        &[&a, &b]
    )
    .is_in_force());
    assert!(send(
        &mut tracker,
        &definition(&n, 2, &[na, nb], 2, REMOVE),
        &[&a, &b]
    )
    .is_in_force());
    let again = definition(&n, 2, &[na, nb], 3, REPLACE);
    let o = send(&mut tracker, &again, &[&a, &b]);
    assert!(
        !o.is_in_force(),
        "a removed namespace is not defined anew: {}",
        o.note()
    );
}

/// T-7: a broadcast is taken only when the group of all members is among its recipients.
#[test]
fn only_a_broadcast_to_all_members_is_taken() {
    assert!(is_addressed_to_all(&[tw::ALL_MEMBERS.to_string()]));
    assert!(is_addressed_to_all(&[
        "PAR::p::ns".to_string(),
        tw::ALL_MEMBERS.to_string()
    ]));
    assert!(!is_addressed_to_all(&["PAR::p::ns".to_string()]));
    assert!(!is_addressed_to_all(&[]));
}

/// T-6: in a downloaded state a proposal is not in force (a higher serial that is only proposed leaves the transaction in force as it
/// is) and waits for its signatures; a transaction that is not a proposal and lacks an authorization is refused, not kept waiting.
#[test]
fn a_downloaded_proposal_is_not_in_force_and_an_unauthorized_transaction_is_refused() {
    let (p, a, b) = (key(131), key(132), key(133));
    let party = format!("carol::{}", p.fingerprint);
    let (ua, ub) = (
        format!("pa::{}", a.fingerprint),
        format!("pb::{}", b.fingerprint),
    );
    let root = |k: &tw::Ed25519Key| {
        let d =
            tw::namespace_delegation(&k.fingerprint, k.public_key(&[SigningKeyUsage::Namespace]));
        tw::signed(d.clone(), vec![k.sign_transaction(&d)])
    };
    let first = hosting(&party, &[(&ua, SUBMISSION, ACTIVE)], 1, 1);
    let second = hosting(
        &party,
        &[(&ua, SUBMISSION, ACTIVE), (&ub, SUBMISSION, ACTIVE)],
        1,
        2,
    );
    let state: Vec<(i64, Vec<u8>)> = [
        root(&p),
        root(&a),
        root(&b),
        tw::signed(
            first.clone(),
            vec![p.sign_transaction(&first), a.sign_transaction(&first)],
        ),
        tw::signed_proposal(second.clone(), vec![p.sign_transaction(&second)]),
    ]
    .iter()
    .map(|s| (0, tw::stored_form(s)))
    .collect();
    let mut tracker = Tracker::from_state(&decode(&state).unwrap(), "PAR::me::ns");
    join(&mut tracker, &ub, &b);
    assert_eq!(
        tracker.hosts_of(&party).map(|(_, hosts)| hosts.len()),
        Some(1),
        "the proposal is not in force"
    );
    // b's signature completes the proposal the state held
    let o = send(&mut tracker, &second, &[&b]);
    assert!(o.is_in_force(), "{}", o.note());

    // not a proposal and not authorized: refused; as a proposal: waiting
    let third = hosting(&party, &[(&ua, SUBMISSION, ACTIVE)], 2, 3);
    assert!(matches!(
        send(&mut tracker, &third, &[&a]),
        Outcome::Refused(_)
    ));
    assert!(matches!(
        super::tests::propose(&mut tracker, &third, &[&a]),
        Outcome::Waiting(_)
    ));
}

/// T-12: what a peer could broadcast that the node's mapping checks refuse, each next to what they accept.
#[test]
fn the_mapping_checks_refuse_what_the_node_refuses() {
    use super::tests::definition;
    let (root, m1, a, b, c) = (key(141), key(142), key(144), key(145), key(146));
    let mut tracker = tracker_of_roots(&[&root, &a, &b]);
    tracker.set_current_psid(Psid::parse(&format!("sync::{}::37-0", root.fingerprint)).unwrap());
    let n = root.fingerprint.clone();
    let synchronizer = format!("sync::{n}");
    let refused = |o: Outcome, why: &str| {
        assert!(o.note().contains(why), "expected {why}: {}", o.note());
    };

    // a REMOVE of nothing in force
    let p1 = format!("p1::{n}");
    let certificate = tw::synchronizer_trust_certificate(&p1, &synchronizer, vec![]);
    let removal = transaction_of(super::tests::mapping_of(&certificate), 1, REMOVE);
    refused(
        send(&mut tracker, &removal, &[&root]),
        "NoCorrespondingActiveTxToRevoke",
    );
    // a participant without keys, or while onboarding is locked
    refused(
        send(&mut tracker, &certificate, &[&root]),
        "InsufficientKeys",
    );
    let keys = |member: &str, serial: u32, operation: i32, encryption: bool| {
        let mut public = vec![signing_key(&m1)];
        if encryption {
            public.push(tw::p256_encryption_key(&[7; 91]));
        }
        tw::owner_to_key_mapping_at(member, public, serial, operation)
    };
    refused(
        send(
            &mut tracker,
            &keys(&format!("PAR::{p1}"), 1, REPLACE, false),
            &[&root, &m1],
        ),
        "no encryption key",
    );
    assert!(send(
        &mut tracker,
        &keys(&format!("PAR::{p1}"), 1, REPLACE, true),
        &[&root, &m1]
    )
    .is_in_force());
    tracker.parameters = Some(DynamicSynchronizerParameters {
        onboarding_restriction: 2,
        ..tw::default_dynamic_parameters()
    });
    refused(
        send(&mut tracker, &certificate, &[&root]),
        "OnboardingRestrictionInPlace",
    );
    tracker.parameters = Some(tw::default_dynamic_parameters());
    assert!(send(&mut tracker, &certificate, &[&root]).is_in_force());
    // the keys of a member stay while it is one
    refused(
        send(
            &mut tracker,
            &keys(&format!("PAR::{p1}"), 2, REMOVE, true),
            &[&root],
        ),
        "InvalidOwnerToKeyMappingRemoval",
    );
    // a participant that left does not come back
    let left = transaction_of(super::tests::mapping_of(&certificate), 2, REMOVE);
    assert!(send(&mut tracker, &left, &[&root]).is_in_force());
    let back = transaction_of(super::tests::mapping_of(&certificate), 3, REPLACE);
    refused(
        send(&mut tracker, &back, &[&root]),
        "ParticipantCannotRejoinSynchronizer",
    );

    // a hosting by a participant that is not a member, twice the same participant, a state moved backward
    let p2 = format!("p2::{n}");
    let party = format!("dave::{n}");
    refused(
        send(
            &mut tracker,
            &hosting(&party, &[(&p2, SUBMISSION, ACTIVE)], 1, 1),
            &[&root],
        ),
        "UnknownMembers",
    );
    join(&mut tracker, &p2, &root);
    refused(
        send(
            &mut tracker,
            &hosting(
                &party,
                &[(&p2, SUBMISSION, ACTIVE), (&p2, OBSERVATION, ACTIVE)],
                1,
                1,
            ),
            &[&root],
        ),
        "Duplicate participants",
    );
    assert!(send(
        &mut tracker,
        &hosting(&party, &[(&p2, SUBMISSION, ACTIVE)], 1, 1),
        &[&root]
    )
    .is_in_force());
    refused(
        send(
            &mut tracker,
            &hosting(&party, &[(&p2, SUBMISSION, 3)], 1, 2),
            &[&root],
        ),
        "Invalid hosting state transitions",
    );

    // keys registered again after their removal
    let med = format!("MED::m::{n}");
    assert!(send(&mut tracker, &keys(&med, 1, REPLACE, false), &[&root, &m1]).is_in_force());
    assert!(send(&mut tracker, &keys(&med, 2, REMOVE, false), &[&root]).is_in_force());
    refused(
        send(&mut tracker, &keys(&med, 3, REPLACE, false), &[&root, &m1]),
        "CannotReregisterKeys",
    );

    // mediator groups: members without keys, a mediator in two groups, a threshold above the active ones
    let group = |index: u32, active: &[&str], threshold: u32, serial: u32| {
        let active: Vec<String> = active.iter().map(|s| s.to_string()).collect();
        tw::mediator_synchronizer_state_at(&synchronizer, index, threshold, &active, &[], serial)
    };
    let x = format!("x::{n}");
    refused(
        send(&mut tracker, &group(0, &[&x], 1, 1), &[&root]),
        "InsufficientKeys",
    );
    let med_x = format!("MED::{x}");
    assert!(send(
        &mut tracker,
        &keys(&med_x, 1, REPLACE, false),
        &[&root, &m1]
    )
    .is_in_force());
    refused(
        send(&mut tracker, &group(0, &[&x], 2, 1), &[&root]),
        "Threshold 2 is larger",
    );
    assert!(send(&mut tracker, &group(0, &[&x], 1, 1), &[&root]).is_in_force());
    refused(
        send(&mut tracker, &group(1, &[&x], 1, 1), &[&root]),
        "MediatorsAlreadyInOtherGroups",
    );

    // a decentralized namespace whose owner has no root certificate, or that is a namespace with delegations
    let (na, nc) = (a.fingerprint.as_str(), c.fingerprint.as_str());
    let owners: BTreeSet<String> = [na.to_string(), nc.to_string()].into();
    let dn = decentralized_namespace_of(&owners).unwrap();
    refused(
        send(
            &mut tracker,
            &definition(&dn, 1, &[na, nc], 1, REPLACE),
            &[&a, &c],
        ),
        "No root certificate",
    );
    let nb = b.fingerprint.as_str();
    let owners: BTreeSet<String> = [na.to_string(), nb.to_string()].into();
    let dn = decentralized_namespace_of(&owners).unwrap();
    assert!(send(
        &mut tracker,
        &definition(&dn, 1, &[na, nb], 1, REPLACE),
        &[&a, &b]
    )
    .is_in_force());
    let clash = tw::namespace_delegation(&dn, root.public_key(&[SigningKeyUsage::Namespace]));
    refused(send(&mut tracker, &clash, &[&a]), "NamespaceAlreadyInUse");

    // the synchronizer parameters stay
    let params = tw::synchronizer_parameters_state(&synchronizer, tw::default_dynamic_parameters());
    assert!(send(&mut tracker, &params, &[&root]).is_in_force());
    let removed = transaction_of(super::tests::mapping_of(&params), 2, REMOVE);
    refused(
        send(&mut tracker, &removed, &[&root]),
        "CannotRemoveMapping",
    );
}

/// T-10: a hosting that names the party's own namespace key among its signing keys authorizes the party itself when that key signs (an
/// external party has no namespace delegation, `namespaceKeyForSelfAuthorization`).
#[test]
fn an_external_party_authorizes_its_own_hosting() {
    use canton_proto::com::digitalasset::canton::crypto::v30::SigningKeysWithThreshold;
    let (q, a, other) = (key(151), key(152), key(153));
    let mut tracker = tracker_of_roots(&[&a]);
    let ua = format!("pa::{}", a.fingerprint);
    join(&mut tracker, &ua, &a);
    let external = |by: &tw::Ed25519Key| {
        transaction_of(
            Mapping::PartyToParticipant(PartyToParticipant {
                party: format!("ext::{}", q.fingerprint),
                threshold: 1,
                participants: vec![HostingParticipant {
                    participant_uid: ua.clone(),
                    permission: CONFIRMATION,
                    state: ACTIVE,
                }],
                party_signing_keys: Some(SigningKeysWithThreshold {
                    keys: vec![
                        by.public_key(&[SigningKeyUsage::Namespace, SigningKeyUsage::Protocol])
                    ],
                    threshold: 1,
                }),
            }),
            1,
            REPLACE,
        )
    };
    // a key that is not the party's namespace key does not authorize the party
    assert!(!send(&mut tracker, &external(&other), &[&other, &a]).is_in_force());
    let o = send(&mut tracker, &external(&q), &[&q, &a]);
    assert!(o.is_in_force(), "{}", o.note());
}

/// T-12: a mediator group needs at least one active mediator (`MediatorSynchronizerState.create`: "requires at least one active
/// mediator"), with a threshold of at most their number.
#[test]
fn a_mediator_group_without_an_active_mediator_is_refused() {
    let (root, m1) = (key(161), key(162));
    let mut tracker = tracker_of_roots(&[&root]);
    let n = root.fingerprint.clone();
    let synchronizer = format!("sync::{n}");
    let x = format!("x::{n}");
    let keys =
        tw::owner_to_key_mapping_at(&format!("MED::{x}"), vec![signing_key(&m1)], 1, REPLACE);
    assert!(send(&mut tracker, &keys, &[&root, &m1]).is_in_force());
    let group = |active: &[String], serial: u32| {
        tw::mediator_synchronizer_state_at(&synchronizer, 0, 1, active, &[], serial)
    };
    let o = send(&mut tracker, &group(&[], 1), &[&root]);
    assert!(
        o.note().contains("at least one active mediator"),
        "{}",
        o.note()
    );
    assert!(send(&mut tracker, &group(&[x], 1), &[&root]).is_in_force());
}

/// T-12: a hosting self-signed with the party's namespace key is refused once that namespace's root certificate was revoked
/// (`checkIsNotSelfSignedWithARevokedRootNSDKey`: `NamespaceHasBeenRevoked`).
#[test]
fn a_self_signed_hosting_of_a_revoked_namespace_is_refused() {
    use canton_proto::com::digitalasset::canton::crypto::v30::SigningKeysWithThreshold;
    let (q, a) = (key(171), key(172));
    let mut tracker = tracker_of_roots(&[&a]);
    let ua = format!("pa::{}", a.fingerprint);
    join(&mut tracker, &ua, &a);
    let external = transaction_of(
        Mapping::PartyToParticipant(PartyToParticipant {
            party: format!("ext::{}", q.fingerprint),
            threshold: 1,
            participants: vec![HostingParticipant {
                participant_uid: ua.clone(),
                permission: CONFIRMATION,
                state: ACTIVE,
            }],
            party_signing_keys: Some(SigningKeysWithThreshold {
                keys: vec![q.public_key(&[SigningKeyUsage::Namespace, SigningKeyUsage::Protocol])],
                threshold: 1,
            }),
        }),
        1,
        REPLACE,
    );
    let root =
        tw::namespace_delegation(&q.fingerprint, q.public_key(&[SigningKeyUsage::Namespace]));
    assert!(send(&mut tracker, &root, &[&q]).is_in_force());
    let revoked = transaction_of(super::tests::mapping_of(&root), 2, REMOVE);
    assert!(send(&mut tracker, &revoked, &[&q]).is_in_force());
    let o = send(&mut tracker, &external, &[&q, &a]);
    assert!(o.note().contains("NamespaceHasBeenRevoked"), "{}", o.note());
}

/// T-12: the tracker follows the sequencer group (`SequencerSynchronizerState`): a new sequencer needs keys, and one that leaves the group is
/// no longer in it.
#[test]
fn the_sequencer_group_is_followed_and_a_sequencer_can_leave_it() {
    use canton_proto::com::digitalasset::canton::protocol::v30::SequencerSynchronizerState;
    let (root, s1, s2) = (key(181), key(182), key(183));
    let mut tracker = tracker_of_roots(&[&root]);
    let n = root.fingerprint.clone();
    let (a, b) = (format!("seq-a::{n}"), format!("seq-b::{n}"));
    let group = |active: &[&String], serial: u32| {
        transaction_of(
            Mapping::SequencerSynchronizerState(SequencerSynchronizerState {
                synchronizer_id: format!("sync::{n}"),
                threshold: 1,
                active: active.iter().map(|s| s.to_string()).collect(),
                observers: vec![],
            }),
            serial,
            REPLACE,
        )
    };
    let keys = |member: &str, k: &tw::Ed25519Key| {
        tw::owner_to_key_mapping_at(member, vec![signing_key(k)], 1, REPLACE)
    };
    let o = send(&mut tracker, &group(&[&a], 1), &[&root]);
    assert!(o.note().contains("InsufficientKeys"), "{}", o.note());
    assert!(send(
        &mut tracker,
        &keys(&format!("SEQ::{a}"), &s1),
        &[&root, &s1]
    )
    .is_in_force());
    assert!(send(
        &mut tracker,
        &keys(&format!("SEQ::{b}"), &s2),
        &[&root, &s2]
    )
    .is_in_force());
    let o = send(&mut tracker, &group(&[&a, &b], 1), &[&root]);
    assert!(o.is_in_force(), "{}", o.note());
    assert!(tracker.is_in_sequencer_group(&b));
    assert!(send(&mut tracker, &group(&[&a], 2), &[&root]).is_in_force());
    assert!(tracker.is_in_sequencer_group(&a));
    assert!(!tracker.is_in_sequencer_group(&b), "b left the group");
    assert_eq!(tracker.sequencer_group().map(|g| g.serial), Some(2));
}

fn static_specs(
    max_keys: u32,
    signing_specs: &[i32],
    encryption_specs: &[i32],
) -> crate::crypto_handshake::Required {
    crate::crypto_handshake::Required {
        signing_keys: signing_specs.iter().copied().collect(),
        encryption_keys: encryption_specs.iter().copied().collect(),
        max_signing_keys_per_entity: Some(max_keys),
        ..crate::crypto_handshake::Required::default()
    }
}

/// T-12: `checkKeyMappingKeyCount` refuses an `OwnerToKeyMapping` carrying more keys than `max_signing_keys_per_entity`.
#[test]
fn an_owner_to_key_mapping_with_too_many_keys_is_refused() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{EncryptionKeySpec, SigningKeySpec};
    let (m_root, sk1, sk2) = (key(191), key(192), key(193));
    let mut tracker = tracker_of_roots(&[&m_root]);
    tracker.set_current_psid(
        psid::Psid::parse(&format!("sync::{}::37-0", m_root.fingerprint)).unwrap(),
    );
    tracker.set_crypto_specs(static_specs(
        2,
        &[SigningKeySpec::EcCurve25519 as i32],
        &[EncryptionKeySpec::EcP256 as i32],
    ));
    let uid = format!("med::{}", m_root.fingerprint);
    let member = format!("MED::{uid}");
    let too_many = tw::owner_to_key_mapping_at(
        &member,
        vec![signing_key(&sk1), signing_key(&sk2), signing_key(&m_root)],
        1,
        REPLACE,
    );
    let o = send(&mut tracker, &too_many, &[&m_root, &sk1, &sk2]);
    assert!(
        o.note().contains("At most 2 key(s)"),
        "expected max-keys refusal, got: {}",
        o.note()
    );
}

/// T-12: `OwnerToKeyMapping` needs at least one signing key and (for a participant) encryption key in the synchronizer's required specs.
#[test]
fn an_owner_to_key_mapping_without_a_supported_key_spec_is_refused() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{EncryptionKeySpec, SigningKeySpec};
    let (p_root, s_key) = (key(194), key(195));
    let mut tracker = tracker_of_roots(&[&p_root]);
    tracker.set_crypto_specs(static_specs(
        20,
        &[SigningKeySpec::EcCurve25519 as i32],
        &[EncryptionKeySpec::EcP256 as i32],
    ));
    let member = format!("PAR::p::{}", p_root.fingerprint);
    let mut bad_sig = s_key.public_key(&[SigningKeyUsage::Protocol]);
    bad_sig.key_spec = SigningKeySpec::EcP256 as i32;
    let enc_good = tw::p256_encryption_key(&[1; 33]);
    let wrong_signing_spec = tw::owner_to_key_mapping_at(
        &member,
        vec![
            PublicKey {
                key: Some(PublicKeyKind::SigningPublicKey(bad_sig)),
            },
            enc_good,
        ],
        1,
        REPLACE,
    );
    let o = send(&mut tracker, &wrong_signing_spec, &[&p_root, &s_key]);
    assert!(
        o.note().contains("no signing key matching required specs"),
        "expected unsupported signing spec refusal, got: {}",
        o.note()
    );

    let enc_template = tw::p256_encryption_key(&[2; 33]);
    let bad_enc = match enc_template.key {
        Some(PublicKeyKind::EncryptionPublicKey(mut ek)) => {
            ek.key_spec = EncryptionKeySpec::Rsa2048 as i32;
            PublicKey {
                key: Some(PublicKeyKind::EncryptionPublicKey(ek)),
            }
        }
        _ => unreachable!(),
    };
    let wrong_enc_spec =
        tw::owner_to_key_mapping_at(&member, vec![signing_key(&s_key), bad_enc], 1, REPLACE);
    let o = send(&mut tracker, &wrong_enc_spec, &[&p_root, &s_key]);
    assert!(
        o.note()
            .contains("no encryption key matching required specs"),
        "expected unsupported encryption spec refusal, got: {}",
        o.note()
    );
}

/// Positive control for `T-12`: keys whose specs match `StaticSynchronizerParameters` and stay within `max_signing_keys_per_entity` are accepted.
#[test]
fn an_owner_to_key_mapping_matching_static_specs_within_limit_is_accepted() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{EncryptionKeySpec, SigningKeySpec};
    let (p_root, s_key) = (key(196), key(197));
    let mut tracker = tracker_of_roots(&[&p_root]);
    tracker.set_current_psid(
        psid::Psid::parse(&format!("sync::{}::37-0", p_root.fingerprint)).unwrap(),
    );
    tracker.set_crypto_specs(static_specs(
        2,
        &[SigningKeySpec::EcCurve25519 as i32],
        &[EncryptionKeySpec::EcP256 as i32],
    ));
    let enc_good = tw::p256_encryption_key(&[3; 33]);
    let member = format!("PAR::p::{}", p_root.fingerprint);
    let valid =
        tw::owner_to_key_mapping_at(&member, vec![signing_key(&s_key), enc_good], 1, REPLACE);
    let o = send(&mut tracker, &valid, &[&p_root, &s_key]);
    assert!(o.is_in_force(), "{}", o.note());
}

/// R-13g / T-12: `PartyToParticipant` extends `KeyMapping` (`TopologyMapping.scala:2094, 2191`) so `party_signing_keys` obeys `checkKeyMappingKeyCount`.
#[test]
fn r13g_party_to_participant_signing_keys_above_limit_is_rejected() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        EncryptionKeySpec, SigningKeySpec, SigningKeysWithThreshold,
    };
    let (p, a, sk1, sk2, sk3) = (key(201), key(202), key(203), key(204), key(205));
    let mut tracker = tracker_of_roots(&[&p, &a]);
    tracker.set_current_psid(psid::Psid::parse(&format!("sync::{}::37-0", a.fingerprint)).unwrap());
    tracker.set_crypto_specs(static_specs(
        2,
        &[SigningKeySpec::EcCurve25519 as i32],
        &[EncryptionKeySpec::EcP256 as i32],
    ));
    let ua = format!("pa::{}", a.fingerprint);
    join(&mut tracker, &ua, &a);
    let make_ptp = |keys_list: &[&tw::Ed25519Key], serial: u32| {
        transaction_of(
            Mapping::PartyToParticipant(PartyToParticipant {
                party: format!("alice::{}", p.fingerprint),
                threshold: 1,
                participants: vec![HostingParticipant {
                    participant_uid: ua.clone(),
                    permission: CONFIRMATION,
                    state: ACTIVE,
                }],
                party_signing_keys: Some(SigningKeysWithThreshold {
                    keys: keys_list
                        .iter()
                        .map(|k| {
                            k.public_key(&[
                                SigningKeyUsage::Protocol,
                                SigningKeyUsage::ProofOfOwnership,
                            ])
                        })
                        .collect(),
                    threshold: 1,
                }),
            }),
            serial,
            REPLACE,
        )
    };
    let too_many = make_ptp(&[&sk1, &sk2, &sk3], 1);
    let o = send(&mut tracker, &too_many, &[&p, &a, &sk1, &sk2, &sk3]);
    assert!(
        o.note().contains("At most 2 key(s)"),
        "expected PartyToParticipant KeyMapping max-keys refusal, got: {}",
        o.note()
    );
    let ok = make_ptp(&[&sk1, &sk2], 1);
    let o_ok = send(&mut tracker, &ok, &[&p, &a, &sk1, &sk2]);
    assert!(
        o_ok.is_in_force(),
        "expected 2 keys accepted: {}",
        o_ok.note()
    );
}

/// R-13g / T-12: deprecated `PartyToKeyMapping` is followed and enforces `checkKeyMappingKeyCount`.
#[test]
fn r13g_party_to_key_mapping_above_limit_is_rejected() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{EncryptionKeySpec, SigningKeySpec};
    #[allow(
        deprecated,
        reason = "testing deprecated v31 PartyToKeyMapping max-keys enforcement"
    )]
    use canton_proto::com::digitalasset::canton::protocol::v30::PartyToKeyMapping;
    let (p, sk1, sk2, sk3) = (key(206), key(207), key(208), key(209));
    let mut tracker = tracker_of_roots(&[&p]);
    tracker.set_current_psid(psid::Psid::parse(&format!("sync::{}::37-0", p.fingerprint)).unwrap());
    tracker.set_crypto_specs(static_specs(
        2,
        &[SigningKeySpec::EcCurve25519 as i32],
        &[EncryptionKeySpec::EcP256 as i32],
    ));
    #[allow(
        deprecated,
        reason = "constructing deprecated v31 PartyToKeyMapping fixture"
    )]
    let make = |keys_list: Vec<&tw::Ed25519Key>| {
        transaction_of(
            Mapping::PartyToKeyMapping(PartyToKeyMapping {
                party: format!("bob::{}", p.fingerprint),
                threshold: 1,
                signing_keys: keys_list
                    .iter()
                    .map(|k| {
                        k.public_key(&[
                            SigningKeyUsage::Protocol,
                            SigningKeyUsage::ProofOfOwnership,
                        ])
                    })
                    .collect(),
            }),
            1,
            REPLACE,
        )
    };
    let o = send(
        &mut tracker,
        &make(vec![&sk1, &sk2, &sk3]),
        &[&p, &sk1, &sk2, &sk3],
    );
    assert!(
        o.note().contains("At most 2 key(s)"),
        "expected PartyToKeyMapping max-keys refusal, got: {}",
        o.note()
    );
    let o_ok = send(&mut tracker, &make(vec![&sk1, &sk2]), &[&p, &sk1, &sk2]);
    assert!(
        o_ok.is_in_force(),
        "expected 2 keys accepted: {}",
        o_ok.note()
    );
}
