//! The Rust sequencer's check of the identity a participant registers (`RegisterOnboardingTopologyTransactions`): the same refusals the
//! official node gives (measured in G5, `identity_transactions_without_a_trust_certificate_or_with_a_bad_signature_are_refused` and
//! `the_node_refuses_a_key_mapping_that_lacks_the_signature_of_a_signing_key_it_names` in canton-participant's tests/sequencer_connect.rs),
//! made by this repository's client with this repository's identity transactions.
mod common;
use canton_participant::sequencer_connect::{ConnectError, SequencerConnect};
use canton_participant::topology_wire::ParticipantIdentity;
use canton_sequencer_server::SynchronizerConfig;

fn synchronizer_uid(config: &SynchronizerConfig) -> String {
    format!("{}::{}", config.name, config.namespace_fingerprint)
}

fn refused(e: ConnectError) -> String {
    match e {
        ConnectError::Status(s) => s,
        other => panic!("expected a refusal by the sequencer, got {other}"),
    }
}

#[test]
fn a_complete_identity_registers_and_makes_the_member_active() {
    let (config, url) = common::start();
    let mut c = SequencerConnect::connect(&url).unwrap();
    let r = ParticipantIdentity::generate("onboard-ok");
    let physical = config.physical_synchronizer_id();
    assert!(!c.is_active_as(&r.member(), &physical, None).unwrap());
    c.register_onboarding(
        &r.member(),
        &physical,
        r.onboarding_transactions(&synchronizer_uid(&config)),
    )
    .expect("the complete identity is accepted");
    assert!(
        c.is_active_as(&r.member(), &physical, None).unwrap(),
        "a member that registered is active"
    );
}

#[test]
fn an_identity_that_is_incomplete_or_wrongly_signed_is_refused_as_the_official_node_does() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let uid = synchronizer_uid(&config);
    let register = |r: &ParticipantIdentity,
                    transactions: Vec<
        canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction,
    >| {
        SequencerConnect::connect(&url)
            .unwrap()
            .register_onboarding(&r.member(), &physical, transactions)
    };
    let r = ParticipantIdentity::generate("onboard-bad");
    let all = r.onboarding_transactions(&uid);
    // without the trust certificate
    let why = refused(register(&r, all[..2].to_vec()).expect_err("must be refused"));
    assert!(
        why.contains("Exactly one SynchronizerTrustCertificate is required for Participants"),
        "{why}"
    );
    // a flipped bit in a signature of the key mapping
    let mut tampered = all.clone();
    tampered[1].signatures[0].signature[0] ^= 1;
    let why = refused(register(&r, tampered).expect_err("must be refused"));
    assert!(
        why.contains("Unable to register onboarding topology transactions"),
        "{why}"
    );
    // a certificate for another participant than the one that registers
    let other = ParticipantIdentity::generate("onboard-other");
    let mut mixed = all.clone();
    mixed[2] = other.onboarding_transactions(&uid)[2].clone();
    let why = refused(register(&r, mixed).expect_err("must be refused"));
    assert!(
        why.contains("Mappings for unexpected UIDs for onboarding"),
        "{why}"
    );
    // a certificate for another synchronizer
    let elsewhere = r.onboarding_transactions("other::1220aa");
    let mut wrong_synchronizer = all.clone();
    wrong_synchronizer[2] = elsewhere[2].clone();
    let why = refused(register(&r, wrong_synchronizer).expect_err("must be refused"));
    assert!(why.contains("another synchronizer"), "{why}");
    // a key mapping that lacks the signature of a signing key it names (proof of possession): the namespace alone, or one key short
    for (label, keep) in [
        ("namespace only", vec![0]),
        ("no sequencer authentication key", vec![0, 1]),
        ("no protocol key", vec![0, 2]),
    ] {
        let mut partial = all.clone();
        let signatures = partial[1].signatures.clone();
        partial[1].signatures = keep.iter().map(|i| signatures[*i].clone()).collect();
        let why = refused(register(&r, partial).expect_err(label));
        assert!(
            why.contains("Unable to register onboarding topology transactions"),
            "{label}: {why}"
        );
    }
    // none of them registered the member
    let mut c = SequencerConnect::connect(&url).unwrap();
    assert!(!c.is_active_as(&r.member(), &physical, None).unwrap());
    // control: the same identity, complete, registers
    assert!(register(&r, all).is_ok());
}

#[test]
fn a_registered_member_authenticates_and_an_unregistered_or_wrongly_signing_one_does_not() {
    use canton_participant::sequencer_connect::AuthKey;
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut c = SequencerConnect::connect(&url).unwrap();
    let r = ParticipantIdentity::generate("auth-ok");
    // a member nobody registered gets no challenge
    let why = refused(c.challenge(&r.member(), &[37]).expect_err("not registered"));
    assert!(why.contains("is not registered"), "{why}");
    c.register_onboarding(
        &r.member(),
        &physical,
        r.onboarding_transactions(&synchronizer_uid(&config)),
    )
    .unwrap();
    // the challenge names the key it accepts: the one registered for sequencer authentication, not the protocol signing key
    let challenge = c.challenge(&r.member(), &[37]).unwrap();
    assert_eq!(
        challenge.fingerprints,
        vec![r.sequencer_auth_key.fingerprint.clone()]
    );
    // a signature of the protocol key (registered, but not for authentication) is refused
    let wrong_key = r
        .signing_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let why = refused(
        c.authenticate(&r.member(), &challenge.nonce, wrong_key)
            .expect_err("refused"),
    );
    assert!(
        why.contains("not signed by a key registered for sequencer authentication"),
        "{why}"
    );
    // a refused answer does not use up the nonce (`MemberAuthenticationService.validateSignature` removes it only after the signature
    // verified, so junk answers cannot knock it out): the right signature on it gets a token, and then it is used up
    let right = r
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    c.authenticate(&r.member(), &challenge.nonce, right.clone())
        .expect("the nonce survived the wrong answer");
    let why = refused(
        c.authenticate(&r.member(), &challenge.nonce, right)
            .expect_err("used up"),
    );
    assert!(why.contains("not the nonce this member was given"), "{why}");
    // a signature over another synchronizer's id does not verify
    let challenge = c.challenge(&r.member(), &[37]).unwrap();
    let other = r
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, "other::1220aa::37-0").unwrap());
    let why = refused(
        c.authenticate(&r.member(), &challenge.nonce, other)
            .expect_err("wrong id"),
    );
    assert!(why.contains("does not verify"), "{why}");
    // a bit of the nonce changed: not the nonce given
    let challenge = c.challenge(&r.member(), &[37]).unwrap();
    let mut changed = challenge.nonce;
    changed[0] ^= 1;
    let signature = r
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&changed, &physical).unwrap());
    let why = refused(
        c.authenticate(&r.member(), &changed, signature)
            .expect_err("changed nonce"),
    );
    assert!(why.contains("not the nonce this member was given"), "{why}");
    // control: the right key over the right nonce and synchronizer gives a token
    let challenge = c.challenge(&r.member(), &[37]).unwrap();
    let signature = r
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = c
        .authenticate(&r.member(), &challenge.nonce, signature)
        .unwrap();
    assert_eq!(token.token.len(), 20);
    assert!(token.expires_at_seconds > 0);
}

#[test]
fn the_authenticated_calls_need_the_token_of_the_member_and_answer_as_the_official_sequencer_does()
{
    use canton_participant::sequencer_connect::AuthKey;
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut c = SequencerConnect::connect(&url).unwrap();
    let register = |label: &str, c: &mut SequencerConnect| {
        let r = ParticipantIdentity::generate(label);
        c.register_onboarding(
            &r.member(),
            &physical,
            r.onboarding_transactions(&synchronizer_uid(&config)),
        )
        .unwrap();
        let challenge = c.challenge(&r.member(), &[37]).unwrap();
        let signature = r
            .sequencer_auth_key
            .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
        let token = c
            .authenticate(&r.member(), &challenge.nonce, signature)
            .unwrap();
        (r, token)
    };
    let (a, token_a) = register("traffic-a", &mut c);
    let (b, token_b) = register("traffic-b", &mut c);
    // a call without a token, and with another member's token, is refused
    let why = refused(
        c.sequencer_time(&a.member(), &physical, None)
            .expect_err("no token"),
    );
    assert!(why.contains("authentication token"), "{why}");
    let why = refused(
        c.sequencer_time(&a.member(), &physical, Some(&token_b))
            .expect_err("another member's token"),
    );
    assert!(why.contains("not valid for this member"), "{why}");
    // the clock answers and does not go back
    let t1 = c
        .sequencer_time(&a.member(), &physical, Some(&token_a))
        .unwrap()
        .unwrap();
    let t2 = c
        .sequencer_time(&a.member(), &physical, Some(&token_a))
        .unwrap()
        .unwrap();
    assert!(t2 > t1);
    // the traffic state: the member's own at the asked time is all zeros with no serial (measured on the official sequencer), another
    // member's is refused
    let own = c
        .traffic_state(&a.member(), &physical, &token_a, &a.member(), t1)
        .unwrap();
    assert_eq!(own, (0, 0, 0, 0, t1, None));
    let why = refused(
        c.traffic_state(&a.member(), &physical, &token_a, &b.member(), t1)
            .expect_err("another member's state"),
    );
    assert!(
        why.contains("just tried to use sequencer on behalf of")
            && why.contains("without permission"),
        "{why}"
    );
}

#[test]
fn the_state_a_member_downloads_is_signed_authorized_and_has_the_hash_the_server_gives() {
    use canton_participant::sequencer_connect::AuthKey;
    use canton_participant::topology_state::{decode, Tracker};
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut c = SequencerConnect::connect(&url).unwrap();
    let r = ParticipantIdentity::generate("state-member");
    c.register_onboarding(
        &r.member(),
        &physical,
        r.onboarding_transactions(&synchronizer_uid(&config)),
    )
    .unwrap();
    let challenge = c.challenge(&r.member(), &[37]).unwrap();
    let signature = r
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = c
        .authenticate(&r.member(), &challenge.nonce, signature)
        .unwrap();
    let hash = c
        .download_topology_state_hash(&r.member(), &physical, &token)
        .unwrap();
    let state = c
        .download_topology_state(&r.member(), &physical, &token)
        .unwrap();
    // the synchronizer's eight transactions (the two owners' delegations, the decentralized namespace they own, the key mappings of the
    // sequencer and the mediator, the parameters, who serves as mediator and as sequencer), then the three of the member
    assert_eq!(
        state.len(),
        11,
        "eight of the synchronizer, three of the member"
    );
    let entries = decode(&state).expect("the state decodes");
    let transactions: Vec<Vec<u8>> = entries
        .iter()
        .map(|e| e.signed.transaction.clone())
        .collect();
    assert_eq!(
        hash,
        canton_participant::topology_wire::topology_state_hash(&transactions)
    );
    // the member's transactions take effect after the topology change delay, the synchronizer's from the beginning of time
    assert_eq!(
        state[0].0,
        canton_sequencer_server::synchronizer_state::BEGINNING_OF_TIME_MICROS
    );
    assert!(state[8].0 > state[0].0);
    // a participant following the state with its own rules authorizes every transaction it follows: the delegation, the key mappings
    // of the sequencer, the mediator and itself, and the synchronizer's parameters
    let mut tracker = Tracker::from_state(&[], "PAR::someone-else::1220aa");
    let notes: Vec<String> = state
        .iter()
        .map(|(_, stored)| tracker.apply_stored(stored))
        .collect();
    // the owners' delegations, the decentralized namespace (both owners signed it), the key mappings and the parameters (both signed them)
    for i in 0..6 {
        assert!(notes[i].contains("in force"), "{i}: {notes:#?}");
    }
    assert!(notes[2].contains("decentralized namespace"), "{notes:#?}");
    let learned = tracker.learned();
    assert_eq!(
        learned.mediator_keys.len(),
        1,
        "the mediator's key is learned"
    );
    assert_eq!(
        learned.timeouts.map(|t| t.confirmation_response_micros),
        Some(30_000_000)
    );
    // a state that is not the one the server hashed is not accepted: another order is another hash
    let mut reordered = transactions;
    reordered.swap(0, 1);
    assert_ne!(
        hash,
        canton_participant::topology_wire::topology_state_hash(&reordered)
    );
}
