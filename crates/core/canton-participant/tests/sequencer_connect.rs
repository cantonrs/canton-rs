//! G5 (S-NET-001): the first session with a real Canton 3.7.2 sequencer. `canton_participant::sequencer_connect` calls the
//! sequencer's public `SequencerConnectService` over gRPC and the answers must be the ones the node's own console reports.
//!
//! Needs a running sequencer (`CANTON_RS_SEQUENCER_URL=http://host:port`) and the console's facts in
//! `CANTON_RS_EXPECT_SYNCHRONIZER` (the physical synchronizer id), `CANTON_RS_EXPECT_SEQUENCER_UID` and
//! `CANTON_RS_EXPECT_PROTOCOL_VERSION`, `CANTON_RS_MEMBER_P1` (a registered member) and `CANTON_RS_EXPECT_AUTH_KEY` (the fingerprint of
//! the registered member's `sequencer-auth` key); a missing variable panics. Compiled only with the `sequencer-tests` feature:
//! `scripts/verify-sequencer-connect.sh`.
#![cfg(feature = "sequencer-tests")]

use canton_participant::sequencer_connect::{ConnectError, SequencerConnect};

// the helpers this target shares with tests/receive_simclock.rs (S-SPL-036)
mod p1_peer;
use p1_peer::*;

/// The sequencer keeps one pending challenge per member: tests that ask for or answer p1's challenge must not interleave.
static P1: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The synchronizer's parameters are shared by every test that talks to the node. A test that changes them takes the write side;
/// every other test holds the read side from its first registration until its thread ends, so none of them reads the timeouts
/// (or has a request timed out) while they differ from what the test expects.
static PARAMS: std::sync::RwLock<()> = std::sync::RwLock::new(());

thread_local! {
    static PARAMS_READ: std::cell::RefCell<Option<std::sync::RwLockReadGuard<'static, ()>>> = const { std::cell::RefCell::new(None) };
    static PARAMS_WRITER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn hold_params_steady() {
    if PARAMS_WRITER.with(|w| w.get()) {
        return;
    }
    PARAMS_READ.with(|g| {
        if g.borrow().is_none() {
            *g.borrow_mut() = Some(PARAMS.read().unwrap_or_else(|e| e.into_inner()));
        }
    });
}

fn p1_guard() -> std::sync::MutexGuard<'static, ()> {
    P1.lock().unwrap_or_else(|e| e.into_inner())
}

fn refused(e: ConnectError) -> String {
    match e {
        ConnectError::Status(s) => s,
        other => panic!("expected a refusal by the sequencer, got {other}"),
    }
}

#[test]
fn the_handshake_settles_the_protocol_version_the_synchronizer_runs() {
    let want: i32 = var("CANTON_RS_EXPECT_PROTOCOL_VERSION").parse().unwrap();
    let mut c = client();
    // a client that speaks several versions gets the one the synchronizer runs; versions it does not know are ignored
    for offered in [vec![want], vec![34, 35, 36, want], vec![want, 99]] {
        let h = c.handshake(&offered, None).expect("handshake");
        assert_eq!(h.server_protocol_version, want, "offered {offered:?}");
        assert!(h.success);
    }
}

#[test]
fn a_client_that_cannot_speak_the_synchronizers_version_is_refused_with_the_reason() {
    let want: i32 = var("CANTON_RS_EXPECT_PROTOCOL_VERSION").parse().unwrap();
    let mut c = client();
    // none of the offered versions is the server's (also an empty list)
    for offered in [vec![30, 31], vec![]] {
        let why = refused(c.handshake(&offered, None).expect_err("must be refused"));
        assert!(
            why.contains("InvalidArgument") || why.contains("invalid argument"),
            "{why}"
        );
        assert!(
            why.contains(&format!(
                "protocol version required by the server ({want}) is not among the supported"
            )),
            "{why}"
        );
    }
    // a minimum above the server's version
    let why = refused(
        c.handshake(&[want], Some(want + 3))
            .expect_err("must be refused"),
    );
    assert!(
        why.contains(&format!("version required by the synchronizer ({want}) is lower than the minimum version configured")),
        "{why}"
    );
}

#[test]
fn the_synchronizer_id_and_the_sequencer_uid_are_the_consoles() {
    let id = client().synchronizer_id().expect("synchronizer id");
    assert_eq!(
        id.physical_synchronizer_id,
        var("CANTON_RS_EXPECT_SYNCHRONIZER")
    );
    assert_eq!(id.sequencer_uid, var("CANTON_RS_EXPECT_SEQUENCER_UID"));
}

/// A participant that connects to a synchronizer calls this first (G6: a server has to answer it): the name the sequencer's public API gives itself.
#[test]
fn the_sequencer_names_its_api() {
    let name = client().api_name().expect("GetApiInfo");
    assert_eq!(name, "sequencer-public-api");
}

#[test]
fn the_static_parameters_carry_the_protocol_version_and_the_required_crypto() {
    let want: i32 = var("CANTON_RS_EXPECT_PROTOCOL_VERSION").parse().unwrap();
    let (message, text) = client().synchronizer_parameters().expect("parameters");
    // protocol version 37 is the v32 form of the parameters message
    assert_eq!(message, "v32");
    assert!(
        text.contains(&format!("protocol_version: {want}")),
        "{text}"
    );
    for needed in [
        "required_signing_specs: Some",
        "required_hash_algorithms: [Sha256]",
        "required_symmetric_key_schemes: [Aes128gcm]",
        "required_signature_formats",
    ] {
        assert!(text.contains(needed), "{needed} missing in {text}");
    }
}

#[test]
fn verify_active_needs_an_authenticated_participant() {
    // the node answers an anonymous caller exactly like this (measured): the call is meant for a participant that has
    // authenticated, which this client has not (identity and authentication are the next step of G5)
    let why = refused(
        client()
            .is_active()
            .expect_err("anonymous VerifyActive is refused"),
    );
    assert!(
        why.contains("Unable to find participant id in gRPC context"),
        "{why}"
    );
}

#[test]
fn a_registered_member_gets_a_challenge_naming_the_key_it_must_sign_with() {
    let _guard = p1_guard();
    // `p1` is a member of the synchronizer. The sequencer's answer: a nonce to sign and the fingerprint(s) of the member's own
    // key(s) it accepts the signature from: the `sequencer-auth` key registered for `p1` in the topology (measured: the first
    // guess, the sequencer's own authentication key, was wrong). Signing the nonce and `Authenticate` are not done here.
    let c = client()
        .challenge(&var("CANTON_RS_MEMBER_P1"), &[37])
        .expect("challenge for a registered member");
    assert_eq!(c.nonce.len(), 20, "a nonce of 20 bytes (measured)");
    assert_eq!(c.fingerprints, vec![var("CANTON_RS_EXPECT_AUTH_KEY")]);
    // measured: asking again before answering gives the SAME nonce (the sequencer keeps one pending challenge per member; the
    // first guess "every challenge is fresh" was wrong)
    let again = client()
        .challenge(&var("CANTON_RS_MEMBER_P1"), &[37])
        .unwrap();
    assert_eq!(c.nonce, again.nonce);
}

#[test]
fn a_member_the_synchronizer_does_not_know_and_a_malformed_member_are_refused() {
    let unknown =
        "PAR::nobody::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for member in [unknown, "not a member"] {
        let why = refused(
            client()
                .challenge(member, &[37])
                .expect_err("must be refused"),
        );
        assert!(why.contains("Bad challenge request"), "{member}: {why}");
    }
    // the protocol version negotiation applies here too
    let why = refused(
        client()
            .challenge(&var("CANTON_RS_MEMBER_P1"), &[30])
            .expect_err("must be refused"),
    );
    assert!(
        why.contains("is not among the supported protocol versions"),
        "{why}"
    );
}

fn auth_key() -> canton_participant::sequencer_connect::AuthKey {
    let bytes = hex::decode(var("CANTON_RS_P1_AUTH_PRIVATE_KEY")).expect("hex");
    canton_participant::sequencer_connect::AuthKey::from_private_key_proto(&bytes)
        .expect("the exported key")
}

#[test]
fn the_challenge_hash_and_the_signature_are_byte_for_byte_the_nodes() {
    use canton_participant::sequencer_connect::AuthKey;
    use prost::Message;
    // the console signed this nonce (0, 1, ..., 19) for p1's `sequencer-auth` key and the synchronizer: Ed25519 is deterministic
    let nonce: Vec<u8> = (0..20).collect();
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    assert_eq!(
        hex::encode(AuthKey::challenge_hash(&nonce, &synchronizer).unwrap()),
        var("CANTON_RS_EXPECT_AUTH_HASH"),
        "the hash that is signed"
    );
    let key = auth_key();
    assert_eq!(key.fingerprint, var("CANTON_RS_EXPECT_AUTH_KEY"));
    let signature = key.sign_challenge(&nonce, &synchronizer).unwrap();
    assert_eq!(
        hex::encode(signature.encode_to_vec()),
        var("CANTON_RS_EXPECT_AUTH_SIGNATURE")
    );
}

#[test]
fn a_member_that_signs_the_challenge_gets_a_token() {
    let _guard = p1_guard();
    let member = var("CANTON_RS_MEMBER_P1");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let key = auth_key();
    let mut c = client();
    let challenge = c.challenge(&member, &[37]).expect("challenge");
    let signature = key.sign_challenge(&challenge.nonce, &synchronizer).unwrap();
    let token = c
        .authenticate(&member, &challenge.nonce, signature)
        .expect("the sequencer accepts the signature of the registered key");
    assert!(!token.token.is_empty());
    // the expiry is on the SEQUENCER's clock (the container's, which on a developer machine can be hours away from the host's: the
    // first version of this test compared it with the host's clock and failed by 12 hours), so only its sanity is checked
    assert!(
        token.expires_at_seconds > 1_700_000_000,
        "{}",
        token.expires_at_seconds
    );
    eprintln!(
        "token of {} bytes, expires at {}",
        token.token.len(),
        token.expires_at_seconds
    );
    // with the headers the node's own clients send the member can make the call that refused an anonymous caller
    assert!(c
        .is_active_as(&member, &synchronizer, Some(&token))
        .expect("verify-active as p1"));
    // MEASURED: the token is not what this call checks. A forged token, and no token at all, give the same answer as long as
    // the member header is there (the participant id is read from the headers); the token matters for the authenticated
    // services (`SequencerService`), not for `SequencerConnectService.VerifyActive`.
    let mut forged = token.clone();
    forged.token[0] ^= 0xff;
    let with_forged = c.is_active_as(&member, &synchronizer, Some(&forged));
    let without = c.is_active_as(&member, &synchronizer, None);
    // the authenticated service is different: `SequencerService.GetTime` answers with the sequencer's clock for the member that
    // authenticated and refuses a forged token and a missing one
    let time = c
        .sequencer_time(&member, &synchronizer, Some(&token))
        .expect("GetTime with the token")
        .expect("the sequencer's clock");
    // the token expires after the sequencer's own time (the measure that works across a skewed container clock)
    assert!(
        token.expires_at_seconds * 1_000_000 > time,
        "expiry {} vs time {time}",
        token.expires_at_seconds
    );
    for (what, answer) in [
        (
            "a forged token",
            c.sequencer_time(&member, &synchronizer, Some(&forged)),
        ),
        ("no token", c.sequencer_time(&member, &synchronizer, None)),
    ] {
        let why = refused(answer.expect_err("must be refused"));
        assert!(
            why.contains("does not have valid authentication credentials"),
            "{what}: {why}"
        );
    }
    assert!(with_forged.expect("forged token"));
    assert!(without.expect("no token"));
}

#[test]
fn a_signature_that_does_not_belong_to_the_challenge_is_refused() {
    let _guard = p1_guard();
    let member = var("CANTON_RS_MEMBER_P1");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let key = auth_key();
    let mut c = client();
    let challenge = c.challenge(&member, &[37]).expect("challenge");
    // a flipped bit of the signature
    let mut bad = key.sign_challenge(&challenge.nonce, &synchronizer).unwrap();
    bad.signature[0] ^= 1;
    let why = refused(
        c.authenticate(&member, &challenge.nonce, bad)
            .expect_err("must be refused"),
    );
    eprintln!("flipped signature: {why}");
    // a signature over another nonce
    let other: Vec<u8> = challenge.nonce.iter().map(|b| b ^ 0xff).collect();
    let wrong = key.sign_challenge(&other, &synchronizer).unwrap();
    let why2 = refused(
        c.authenticate(&member, &challenge.nonce, wrong)
            .expect_err("must be refused"),
    );
    eprintln!("signature over another nonce: {why2}");
    // a signature over another synchronizer id
    let elsewhere = key
        .sign_challenge(&challenge.nonce, "other::1220aa::37-0")
        .unwrap();
    let why3 = refused(
        c.authenticate(&member, &challenge.nonce, elsewhere)
            .expect_err("must be refused"),
    );
    eprintln!("signature for another synchronizer: {why3}");
}

// ---- G5 5.3 (S-NET-002): the identity transactions of a participant, rebuilt byte for byte ----

mod identity {
    use super::var;
    use canton_participant::topology_wire as tw;
    use canton_proto::com::digitalasset::canton::crypto::v30::{public_key::Key, SigningKeyUsage};
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        topology_mapping::Mapping, SignedTopologyTransaction, TopologyTransaction,
    };
    use canton_proto::com::digitalasset::canton::topology::admin::v30::TopologyTransactions;
    use prost::Message;

    /// The node's own export of `p1`'s identity: the stored form of each signed transaction.
    pub fn exported() -> Vec<Vec<u8>> {
        let file = std::fs::read(var("CANTON_RS_P1_IDENTITY_FILE")).expect("the identity export");
        let (data, _) = tw::unversioned(&file).expect("a versioned export");
        TopologyTransactions::decode(data.as_slice())
            .expect("TopologyTransactions")
            .items
            .into_iter()
            .map(|i| i.transaction)
            .collect()
    }

    pub fn key(name: &str) -> tw::Ed25519Key {
        let bytes = hex::decode(var(name)).expect("hex");
        use canton_proto::com::digitalasset::canton::crypto::v30::SigningPrivateKey;
        let pk = SigningPrivateKey::decode(bytes.as_slice()).expect("private key proto");
        tw::Ed25519Key::from_pkcs8_der(&pk.private_key).expect("pkcs8")
    }

    pub fn signed_of(stored: &[u8]) -> (SignedTopologyTransaction, TopologyTransaction) {
        let (data, version) = tw::unversioned(stored).expect("versioned");
        assert_eq!(version, tw::SIGNED_TOPOLOGY_TRANSACTION_VERSION);
        let signed = SignedTopologyTransaction::decode(data.as_slice()).expect("signed");
        let (inner, v) = tw::unversioned(&signed.transaction).expect("versioned transaction");
        assert_eq!(v, tw::TOPOLOGY_TRANSACTION_VERSION);
        (
            signed,
            TopologyTransaction::decode(inner.as_slice()).expect("transaction"),
        )
    }

    pub fn namespace_key_usages() -> [SigningKeyUsage; 1] {
        [SigningKeyUsage::Namespace]
    }

    pub fn public_keys_of(mapping: &Mapping) -> Vec<Key> {
        match mapping {
            Mapping::OwnerToKeyMapping(m) => {
                m.public_keys.iter().filter_map(|k| k.key.clone()).collect()
            }
            _ => Vec::new(),
        }
    }
}

#[test]
fn a_fingerprint_is_the_multihash_of_the_keys_der_and_the_namespace_is_the_root_fingerprint() {
    let ns = identity::key("CANTON_RS_P1_KEY_NAMESPACE");
    // p1's namespace is the fingerprint of its root key: the first exported transaction names it
    let exported = identity::exported();
    let (_, tx) = identity::signed_of(&exported[0]);
    let canton_proto::com::digitalasset::canton::protocol::v30::topology_mapping::Mapping::NamespaceDelegation(d) =
        tx.mapping.unwrap().mapping.unwrap()
    else {
        panic!("the first identity transaction is the root delegation")
    };
    assert_eq!(ns.fingerprint, d.namespace);
    // the fingerprint data of an Ed25519 key is the raw key: the last 32 bytes of its DER SubjectPublicKeyInfo
    let der = d.target_key.unwrap().public_key;
    assert_eq!(tw_fp(&der[der.len() - 32..]), d.namespace);
}

fn tw_fp(der: &[u8]) -> String {
    canton_participant::topology_wire::fingerprint(der)
}

#[test]
fn the_root_namespace_delegation_is_rebuilt_byte_for_byte() {
    use canton_participant::topology_wire as tw;
    let ns = identity::key("CANTON_RS_P1_KEY_NAMESPACE");
    let exported = identity::exported();
    let (signed, _) = identity::signed_of(&exported[0]);
    // rebuild: the transaction bytes, the signature, the signed message and its stored form
    let tx = tw::namespace_delegation(
        &ns.fingerprint,
        ns.public_key(&identity::namespace_key_usages()),
    );
    assert_eq!(tx, signed.transaction, "the versioned transaction bytes");
    let rebuilt = tw::signed(tx.clone(), vec![ns.sign_transaction(&tx)]);
    assert_eq!(
        rebuilt, signed,
        "the signed message (Ed25519 is deterministic: the signature too)"
    );
    assert_eq!(tw::stored_form(&rebuilt), exported[0], "the stored form");
}

#[test]
fn the_owner_to_key_mapping_is_rebuilt_byte_for_byte_with_its_three_signatures() {
    use canton_participant::topology_wire as tw;
    let ns = identity::key("CANTON_RS_P1_KEY_NAMESPACE");
    let signing = identity::key("CANTON_RS_P1_KEY_SIGNING");
    let auth = identity::key("CANTON_RS_P1_KEY_SEQUENCER_AUTH");
    let exported = identity::exported();
    assert_eq!(
        exported.len(),
        2,
        "the namespace delegation and the owner-to-key mapping"
    );
    let (signed, tx) = identity::signed_of(&exported[1]);
    let mapping = tx.mapping.unwrap().mapping.unwrap();
    let canton_proto::com::digitalasset::canton::protocol::v30::topology_mapping::Mapping::OwnerToKeyMapping(m) = &mapping
    else {
        panic!("the second identity transaction is the owner-to-key mapping")
    };
    // the node's own keys, in its order; the encryption key is only public here (nothing is decrypted)
    let keys = m.public_keys.clone();
    assert_eq!(keys.len(), 3);
    let rebuilt_tx = tw::owner_to_key_mapping(&m.member, keys);
    assert_eq!(
        rebuilt_tx, signed.transaction,
        "the versioned transaction bytes"
    );
    // the three signatures, in the node's order
    let signers: Vec<&str> = signed
        .signatures
        .iter()
        .map(|s| s.signed_by.as_str())
        .collect();
    let by_fingerprint = [&ns, &signing, &auth];
    let signatures = signers
        .iter()
        .map(|fp| {
            by_fingerprint
                .iter()
                .find(|k| k.fingerprint == *fp)
                .unwrap_or_else(|| panic!("no key for {fp}"))
                .sign_transaction(&rebuilt_tx)
        })
        .collect();
    let rebuilt = tw::signed(rebuilt_tx, signatures);
    assert_eq!(rebuilt, signed);
    assert_eq!(tw::stored_form(&rebuilt), exported[1]);
    let _ = identity::public_keys_of;
}

/// Registers a new Rust-made participant ([`p1_peer::registered_participant`]), holding the synchronizer's parameters steady first.
fn registered_participant(
    name: &str,
) -> (
    canton_participant::topology_wire::ParticipantIdentity,
    SequencerConnect,
) {
    hold_params_steady();
    p1_peer::registered_participant(name)
}

#[test]
fn a_participant_made_in_rust_is_registered_and_authenticates_on_the_official_synchronizer() {
    use canton_participant::sequencer_connect::AuthKey;
    // its own keys, its own identity: nothing of it comes from the node
    let (r1, mut c) = registered_participant("r1");
    let challenge = c
        .challenge(&r1.member(), &[37])
        .expect("challenge as the new member");
    assert_eq!(
        challenge.fingerprints,
        vec![r1.sequencer_auth_key.fingerprint.clone()]
    );
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let signature = r1
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &synchronizer).unwrap());
    let token = c
        .authenticate(&r1.member(), &challenge.nonce, signature)
        .expect("the sequencer accepts the signature of the Rust-made key");
    // and the authenticated service answers it
    let time = c
        .sequencer_time(&r1.member(), &synchronizer, Some(&token))
        .expect("GetTime as the Rust-made participant")
        .expect("the sequencer's clock");
    assert!(time > 0);
}

/// The node's rule for the proof of possession of a key mapping, which `Tracker` follows (G5 U-22): every **signing** key a mapping names has
/// to sign it as well. The onboarding registration is the node's own check of the member's transactions, so the real node is the oracle:
/// a mapping signed only in the member's namespace, or missing the signature of one of its two signing keys, is refused, and the complete
/// one is accepted.
#[test]
fn the_node_refuses_a_key_mapping_that_lacks_the_signature_of_a_signing_key_it_names() {
    use canton_participant::topology_wire::ParticipantIdentity;
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let register = |label: &str, keep: &dyn Fn(&ParticipantIdentity) -> Vec<usize>| {
        let r = ParticipantIdentity::generate(label);
        let mut all = r.onboarding_transactions(&synchronizer_uid());
        // the mapping carries three signatures: the namespace key, the protocol signing key, the sequencer authentication key
        let kept = keep(&r);
        let signatures = all[1].signatures.clone();
        all[1].signatures = kept.iter().map(|i| signatures[*i].clone()).collect();
        client().register_onboarding(&r.member(), &synchronizer, all)
    };
    // control: all three signatures
    assert!(
        register(&unique("r-pop-ok"), &|_| vec![0, 1, 2]).is_ok(),
        "the complete mapping is accepted"
    );
    for (label, keep) in [
        ("r-pop-ns-only", vec![0]),
        ("r-pop-no-seq", vec![0, 1]),
        ("r-pop-no-protocol", vec![0, 2]),
    ] {
        let why = refused(
            register(&unique(label), &|_| keep.clone()).expect_err(&format!(
                "{label}: a mapping without every key's signature is refused"
            )),
        );
        assert!(
            why.contains("Unable to register onboarding topology transactions"),
            "{label}: {why}"
        );
    }
}

/// The sizes the official sequencer uses, which a participant checks (G6: the Rust server answered with 16, then 32 and the JVM refused both):
/// the nonce of a challenge and the token of an authentication are 20 bytes.
#[test]
fn the_official_nonce_and_token_are_twenty_bytes() {
    use canton_participant::sequencer_connect::AuthKey;
    let (r, mut c) = registered_participant(&unique("r-sizes"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let challenge = c.challenge(&r.member(), &[37]).unwrap();
    assert_eq!(challenge.nonce.len(), 20);
    let signature = r
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &synchronizer).unwrap());
    let token = c
        .authenticate(&r.member(), &challenge.nonce, signature)
        .unwrap();
    assert_eq!(token.token.len(), 20);
}

/// The traffic state the official sequencer gives a member (traffic control is off in the sandbox): the member's own, at the asked time, is
/// all zeros with no serial; another member's is refused. A Rust sequencer answers the same (G6, S-NET-037).
#[test]
fn the_traffic_state_of_a_member_on_the_official_sequencer() {
    let (r, mut c, token) = authenticated(&unique("r-traffic"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let own = c
        .traffic_state(&r.member(), &synchronizer, &token, &r.member(), now)
        .unwrap();
    assert_eq!(own, (0, 0, 0, 0, now, None));
    for other in [
        var("CANTON_RS_MEMBER_P1"),
        "PAR::nobody::1220aa".to_string(),
    ] {
        let why = refused(
            c.traffic_state(&r.member(), &synchronizer, &token, &other, now)
                .expect_err("another member's state is refused"),
        );
        assert!(
            why.contains("just tried to use sequencer on behalf of")
                && why.contains("without permission"),
            "{why}"
        );
    }
}

/// The hash `DownloadTopologyStateForInitHash` gives is the hash the Canton source defines over the transactions of the state in the order the
/// download serves them (G6: the Rust sequencer computes the same).
#[test]
fn the_state_hash_of_the_official_sequencer_is_the_hash_of_the_transactions_it_serves() {
    let (r, mut c, token) = authenticated(&unique("r-statehash"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let hash = c
        .download_topology_state_hash(&r.member(), &synchronizer, &token)
        .unwrap();
    let state = c
        .download_topology_state(&r.member(), &synchronizer, &token)
        .unwrap();
    let transactions: Vec<Vec<u8>> = downloaded::decode(&state)
        .iter()
        .map(|e| e.signed.transaction.clone())
        .collect();
    assert!(!transactions.is_empty());
    assert_eq!(
        hash,
        canton_participant::topology_wire::topology_state_hash(&transactions),
        "{} transactions",
        transactions.len()
    );
    // control: another order is another hash
    let mut reversed = transactions.clone();
    reversed.reverse();
    assert_ne!(
        hash,
        canton_participant::topology_wire::topology_state_hash(&reversed)
    );
}

#[test]
fn identity_transactions_without_a_trust_certificate_or_with_a_bad_signature_are_refused() {
    use canton_participant::topology_wire::ParticipantIdentity;
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let r = ParticipantIdentity::generate("r-incomplete");
    let all = r.onboarding_transactions(&synchronizer_uid());
    // the identity without its trust certificate
    let why = refused(
        client()
            .register_onboarding(&r.member(), &synchronizer, all[..2].to_vec())
            .expect_err("must be refused"),
    );
    assert!(
        why.contains("Exactly one SynchronizerTrustCertificate is required for Participants"),
        "{why}"
    );
    // a flipped bit in a signature of the key mapping
    let mut tampered = all.clone();
    tampered[1].signatures[0].signature[0] ^= 1;
    let why = refused(
        client()
            .register_onboarding(&r.member(), &synchronizer, tampered)
            .expect_err("must be refused"),
    );
    assert!(
        why.contains("Unable to register onboarding topology transactions"),
        "{why}"
    );
    // a certificate for another participant than the one that registers
    let other = ParticipantIdentity::generate("r-other");
    let mut mixed = all.clone();
    mixed[2] = other.onboarding_transactions(&synchronizer_uid())[2].clone();
    let why = refused(
        client()
            .register_onboarding(&r.member(), &synchronizer, mixed)
            .expect_err("must be refused"),
    );
    assert!(
        why.contains("Mappings for unexpected UIDs for onboarding"),
        "{why}"
    );
}

/// An authenticated Rust-made participant ([`p1_peer::authenticated`]), holding the synchronizer's parameters steady first.
fn authenticated(
    name: &str,
) -> (
    canton_participant::topology_wire::ParticipantIdentity,
    SequencerConnect,
    canton_participant::sequencer_connect::Token,
) {
    hold_params_steady();
    p1_peer::authenticated(name)
}

#[test]
fn the_topology_state_of_the_synchronizer_downloads_and_every_signature_verifies() {
    use ed25519_dalek::Verifier;
    let (r, mut c, token) = authenticated("r-download");
    let items = c
        .download_topology_state(&r.member(), &var("CANTON_RS_EXPECT_SYNCHRONIZER"), &token)
        .expect("download");
    let entries = downloaded::decode(&items);
    let names: Vec<&str> = entries
        .iter()
        .map(|e| downloaded::name(downloaded::mapping(e)))
        .collect();
    // what a synchronizer's genesis state has: the sequencer's and the mediator's identities, the synchronizer's own (decentralized)
    // namespace, the synchronizer parameters and the two synchronizer states; then the members that joined (p1 with its vetted
    // packages, and this participant). An open synchronizer needs no `ParticipantSynchronizerPermission` for a member to join
    // (measured: none in the state although two participants are members).
    for needed in [
        "NamespaceDelegation",
        "OwnerToKeyMapping",
        "SynchronizerTrustCertificate",
        "SynchronizerParametersState",
        "MediatorSynchronizerState",
        "SequencerSynchronizerState",
        "DecentralizedNamespaceDefinition",
        "VettedPackages",
    ] {
        assert!(names.contains(&needed), "{needed} missing in {names:?}");
    }
    let members: Vec<String> = entries
        .iter()
        .filter_map(|e| match downloaded::mapping(e) {
            canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping::OwnerToKeyMapping(m) => {
                Some(m.member.clone())
            }
            _ => None,
        })
        .collect();
    assert!(members.contains(&var("CANTON_RS_MEMBER_P1")), "{members:?}");
    assert!(
        members.contains(&r.member()),
        "the participant itself is in the state it downloaded"
    );
    assert!(
        members.iter().any(|m| m.starts_with("SEQ::s1::"))
            && members.iter().any(|m| m.starts_with("MED::m1::")),
        "{members:?}"
    );
    // every signature of every transaction verifies against a key the state itself registers
    let keys = downloaded::keys(&entries);
    let mut verified = 0;
    for e in &entries {
        for sig in &e.signed.signatures {
            let key = keys
                .get(&sig.signed_by)
                .unwrap_or_else(|| panic!("no Ed25519 key {} in the state", sig.signed_by));
            let bytes: [u8; 64] = sig
                .signature
                .as_slice()
                .try_into()
                .expect("an Ed25519 signature is 64 bytes");
            key.verify(
                &canton_participant::topology_wire::transaction_hash(&e.signed.transaction),
                &ed25519_dalek::Signature::from_bytes(&bytes),
            )
            .unwrap_or_else(|_| panic!("signature of {} does not verify", sig.signed_by));
            verified += 1;
        }
    }
    assert!(
        verified >= entries.len(),
        "{verified} signatures over {} transactions",
        entries.len()
    );
    // the genesis transactions are valid from the beginning of time, the members' from when they joined, in order
    assert!(entries
        .windows(2)
        .all(|w| w[0].valid_from <= w[1].valid_from));
}

#[test]
fn a_message_to_oneself_is_sequenced_delivered_and_signed_by_the_sequencer() {
    use canton_participant::sequencing_wire as sw;
    use ed25519_dalek::Verifier;
    let (r, mut c, token) = authenticated("r-echo");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let before = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let id = unique("echo");
    let content = format!("hello from canton-rs {id}").into_bytes();
    let request = sw::submission_request(
        &r.member(),
        &id,
        &[(r.member(), content.clone())],
        before + 60_000_000,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        &token,
        sw::signed_submission_request(request, &r.signing_key),
    )
    .expect("the sequencer accepts the signed submission request");
    // Other tests (and the node itself) cause broadcasts that reach every member, so the first event after `before` need not be
    // ours: read on, from just after the last event seen, until our message id turns up.
    // [CANTON-NOTE: SEMANTICS] the subscription timestamp is inclusive: `before` itself would return the event the sequencer had
    // already sequenced at that instant, so ask from the next microsecond to see only newer events.
    let mut from = before + 1;
    let mut delivered: Vec<sw::Delivered> = Vec::new();
    // time-bounded, not event-bounded: other tests' broadcasts reach every member and would use up a count of iterations
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < patience {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(from),
                1,
                std::time::Duration::from_secs(5),
            )
            .expect("subscribe");
        let Some(event) = events.first() else { break };
        let d = sw::decode_delivered(event).expect("every event decodes");
        from = d.timestamp_micros + 1;
        let ours = d.message_id.as_deref() == Some(id.as_str());
        delivered.push(d);
        if ours {
            break;
        }
    }
    let ours = delivered
        .iter()
        .find(|d| d.message_id.as_deref() == Some(id.as_str()))
        .expect("the message comes back on the subscription");
    assert_eq!(ours.envelopes, vec![content]);
    assert_eq!(ours.recipients, vec![vec![r.member()]]);
    assert_eq!(ours.physical_synchronizer_id, synchronizer);
    assert!(ours.error.is_none());
    assert!(
        ours.timestamp_micros > before,
        "sequenced after the sequencer time we read"
    );
    // the sequencer signed the event; its key is in the topology state the participant downloads
    let state = downloaded::decode(
        &c.download_topology_state(&r.member(), &synchronizer, &token)
            .expect("download"),
    );
    let sequencer_keys = state.iter().find_map(|e| match downloaded::mapping(e) {
        canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping::OwnerToKeyMapping(m)
            if m.member.starts_with("SEQ::s1::") =>
        {
            Some(m.clone())
        }
        _ => None,
    });
    let keys = downloaded::keys(&state);
    let sig = ours.signatures.first().expect("the event is signed");
    let key = keys
        .get(&sig.signed_by)
        .expect("the signing key of the event is one the topology registers");
    assert!(sequencer_keys
        .expect("the sequencer's keys")
        .public_keys
        .iter()
        .any(|k| matches!(&k.key, Some(canton_proto::com::digitalasset::canton::crypto::v30::public_key::Key::SigningPublicKey(s)) if canton_participant::topology_wire::fingerprint(&s.public_key[s.public_key.len() - 32..]) == sig.signed_by)));
    let bytes: [u8; 64] = sig.signature.as_slice().try_into().expect("64 bytes");
    key.verify(
        &sw::event_hash(&ours.event_bytes),
        &ed25519_dalek::Signature::from_bytes(&bytes),
    )
    .expect("the sequencer's signature on the event verifies");
}

#[test]
fn the_sequencer_refuses_a_submission_it_cannot_accept_and_says_why() {
    use canton_participant::sequencing_wire as sw;
    let (r, mut c, token) = authenticated("r-reject");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let ok_time = now + 60_000_000;
    let unknown = format!("PAR::nobody::1220{}", "a".repeat(64));
    let bad_fingerprint = "PAR::nobody::1220aaaa".to_string();
    let mut attempt =
        |what: &str, request: Vec<u8>, key: &canton_participant::topology_wire::Ed25519Key| {
            refused(
                c.send_async(
                    &r.member(),
                    &synchronizer,
                    &token,
                    sw::signed_submission_request(request, key),
                )
                .expect_err(what),
            )
        };
    let why = attempt(
        "unknown recipient",
        sw::submission_request(
            &r.member(),
            &unique("u"),
            &[(unknown, b"x".to_vec())],
            ok_time,
        ),
        &r.signing_key,
    );
    assert!(why.contains("SEQUENCER_UNKNOWN_RECIPIENTS"), "{why}");
    let why = attempt(
        "a recipient that is not a valid member",
        sw::submission_request(
            &r.member(),
            &unique("m"),
            &[(bad_fingerprint, b"x".to_vec())],
            ok_time,
        ),
        &r.signing_key,
    );
    // observed: the 3.7.2 sequencer does not reject a short fingerprint as malformed; it treats it as an unknown member
    assert!(why.contains("SEQUENCER_UNKNOWN_RECIPIENTS"), "{why}");
    let why = attempt(
        "max sequencing time in the past",
        sw::submission_request(
            &r.member(),
            &unique("p"),
            &[(r.member(), b"x".to_vec())],
            now - 60_000_000,
        ),
        &r.signing_key,
    );
    assert!(why.contains("MAX_SEQUENCING_TIME_EXCEEDED"), "{why}");
    // signed by a key of the member, but not one that is valid for protocol messages
    let why = attempt(
        "signed with the wrong key",
        sw::submission_request(
            &r.member(),
            &unique("k"),
            &[(r.member(), b"x".to_vec())],
            ok_time,
        ),
        &r.sequencer_auth_key,
    );
    assert!(
        why.contains("SEQUENCER_SUBMISSION_REQUEST_REFUSED")
            && why.contains("SignatureWithWrongKey"),
        "{why}"
    );
    // sending on behalf of someone else
    let why = attempt(
        "a sender that is not the authenticated member",
        sw::submission_request(
            "PAR::other::1220bbbb",
            &unique("s"),
            &[(r.member(), b"x".to_vec())],
            ok_time,
        ),
        &r.signing_key,
    );
    assert!(why.contains("is not authorized to send"), "{why}");
}

/// AT-P08: what the official sequencer answers a submission that breaks one of its limits or shapes. The answers are printed as
/// `ORACLE_LIMIT <case>=<code>: <message>` or `ACCEPTED` (the Rust sequencer's own test compares against these).
#[test]
fn the_official_sequencer_refuses_submissions_that_break_its_limits_and_says_how() {
    use canton_participant::sequencing_wire as sw;
    let (r, mut c, token) = authenticated("r-limits");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let ok_time = now + 60_000_000;
    let me = r.member();
    let mut case = |name: &str, envelopes: Vec<(Vec<String>, Vec<u8>)>| {
        let request = sw::submission_request_to_groups(&me, &unique(name), &envelopes, ok_time);
        let answer = match c.send_async(
            &me,
            &synchronizer,
            &token,
            sw::signed_submission_request(request, &r.signing_key),
        ) {
            Ok(()) => "ACCEPTED".to_string(),
            Err(e) => refused(e),
        };
        println!("ORACLE_LIMIT {name}={answer}");
    };
    case("no_recipients", vec![(vec![], b"x".to_vec())]);
    case("no_content", vec![(vec![me.clone()], vec![])]);
    case(
        "two_mediator_groups",
        vec![(
            vec!["MGR::0".to_string(), "MGR::1".to_string()],
            b"x".to_vec(),
        )],
    );
    // an envelope that decompresses to more than the 10 MiB `max_request_size`: 11 MiB of zeros are a few hundred bytes on the wire
    case(
        "envelope_over_max_request_size",
        vec![(vec![me.clone()], vec![0u8; 11 * 1024 * 1024])],
    );
    // more recipients than `max_recipients_per_batch` (10000)
    let many: Vec<String> = (0..10_001)
        .map(|i| format!("PAR::p{i}::1220{}", "a".repeat(64)))
        .collect();
    case("too_many_recipients", vec![(many, b"x".to_vec())]);
    // the refusals of the request itself (not of its batch): the exact texts the Rust sequencer has to give
    let mut say =
        |name: &str, request: Vec<u8>, key: &canton_participant::topology_wire::Ed25519Key| {
            let answer = match c.send_async(
                &me,
                &synchronizer,
                &token,
                sw::signed_submission_request(request, key),
            ) {
                Ok(()) => "ACCEPTED".to_string(),
                Err(e) => refused(e),
            };
            println!("ORACLE_LIMIT {name}={answer}");
        };
    say(
        "unknown_recipient",
        sw::submission_request(
            &me,
            &unique("u"),
            &[(
                format!("PAR::nobody::1220{}", "a".repeat(64)),
                b"x".to_vec(),
            )],
            ok_time,
        ),
        &r.signing_key,
    );
    say(
        "max_sequencing_time_in_the_past",
        sw::submission_request(
            &me,
            &unique("p"),
            &[(me.clone(), b"x".to_vec())],
            now - 60_000_000,
        ),
        &r.signing_key,
    );
    say(
        "signed_with_an_authentication_key",
        sw::submission_request(&me, &unique("k"), &[(me.clone(), b"x".to_vec())], ok_time),
        &r.sequencer_auth_key,
    );
    say(
        "sender_is_not_the_authenticated_member",
        sw::submission_request(
            "PAR::other::1220bbbb",
            &unique("s"),
            &[(me.clone(), b"x".to_vec())],
            ok_time,
        ),
        &r.signing_key,
    );
    let stranger = canton_participant::topology_wire::ParticipantIdentity::generate("stranger-key");
    say(
        "signed_with_a_key_nobody_registered",
        sw::submission_request(&me, &unique("z"), &[(me.clone(), b"x".to_vec())], ok_time),
        &stranger.signing_key,
    );
    // not a signed content at all, and a signed content of another version
    let garbage = refused(
        c.send_async(&me, &synchronizer, &token, vec![1, 2, 3, 4, 5])
            .expect_err("garbage"),
    );
    println!("ORACLE_LIMIT garbage_request={garbage}");
    let other_version = refused(
        c.send_async(
            &me,
            &synchronizer,
            &token,
            canton_participant::topology_wire::versioned(Vec::new(), 99),
        )
        .expect_err("other version"),
    );
    println!("ORACLE_LIMIT other_version_request={other_version}");
}

/// AT-O07: what the official sequencer answers a traffic purchase: a duplicate serial, a purchase for a member that is not registered. The
/// answers are printed as `ORACLE_TRAFFIC <case>=<answer>`.
#[test]
fn the_official_sequencer_answers_traffic_purchases_for_registered_and_unregistered_members() {
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let ask = |command: String| -> String {
        let file = format!("{}.trafficcmd", unique("tc"));
        std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        let line = log_line_with(&["SCF trafficcmd_done=", &file]).expect("the console answers");
        let answer = line
            .split(&format!("{file}="))
            .nth(1)
            .unwrap_or_default()
            .to_string();
        // the console words a refusal in the node's log, just before it prints the result
        let log = node_log();
        let lines: Vec<&str> = log.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.contains(&file) && l.contains("SCF trafficcmd_done="))
            .unwrap_or(0);
        let why: Vec<&str> = lines[at.saturating_sub(14)..at]
            .iter()
            .copied()
            .filter(|l| {
                l.contains("GrpcRequestRefusedByServer")
                    || l.trim_start().starts_with("cause =")
                    || l.trim_start().starts_with("code =")
                    || l.contains("TRAFFIC")
            })
            .collect();
        format!(
            "{answer} :: {}",
            why.iter().map(|l| l.trim()).collect::<Vec<_>>().join(" | ")
        )
    };
    let p1 = var("CANTON_RS_MEMBER_P1");
    let ghost = format!("PAR::ghost{}::1220{}", unique("g").len(), "ab".repeat(32));
    let say = |case: &str, answer: String| println!("ORACLE_TRAFFIC {case}={answer}");
    say("p1_serial_1", ask(format!("set,{p1},1,1000")));
    say("p1_serial_1_again", ask(format!("set,{p1},1,1000")));
    say("p1_serial_2_other_balance", ask(format!("set,{p1},2,2500")));
    say("p1_serial_1_after_2", ask(format!("set,{p1},1,9")));
    say("p1_state", ask(format!("state,{p1}")));
    say("unregistered_serial_1", ask(format!("set,{ghost},1,700")));
    say(
        "unregistered_serial_1_again",
        ask(format!("set,{ghost},1,700")),
    );
    say("unregistered_state", ask(format!("state,{ghost}")));
}

/// AT-O07 with traffic control on: the owners turn it on (1000 bytes of base traffic, read-vs-write factor 200, base event cost 7), and a
/// registered member submits with no cost, a wrong cost, the right cost, more than it has, and again after a purchase. Printed as
/// `ORACLE_TRAFFIC_ON <case>=<answer>`. **It turns traffic control on for the shared sandbox (and off at the end): run it alone.**
#[test]
#[ignore = "turns traffic control on for the shared sandbox; run it alone"]
fn the_official_sequencer_with_traffic_control_on() {
    use canton_participant::sequencing_wire as sw;
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let ask = |command: String| -> String {
        let file = format!("{}.trafficcmd", unique("tc"));
        std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        let line = log_line_with(&["SCF trafficcmd_done=", &file]).expect("the console answers");
        line.split(&format!("{file}="))
            .nth(1)
            .unwrap_or_default()
            .to_string()
    };
    let say = |case: &str, answer: String| println!("ORACLE_TRAFFIC_ON {case}={answer}");
    let (r, mut c, token) = authenticated("r-traffic-on");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let me = r.member();
    say("state_while_off", ask(format!("state,{me}")));
    say("enable", ask("enable,1000,200,7".into()));
    std::thread::sleep(std::time::Duration::from_secs(3));
    say("state_after_enable", ask(format!("state,{me}")));
    let mut send = |name: &str, size: usize, cost: Option<i64>| {
        let now = c
            .sequencer_time(&me, &synchronizer, Some(&token))
            .unwrap()
            .unwrap();
        let request = sw::submission_request_costed(
            &me,
            &unique(name),
            &[(me.clone(), vec![b'x'; size])],
            now + 60_000_000,
            cost,
        );
        let answer = match c.send_async(
            &me,
            &synchronizer,
            &token,
            sw::signed_submission_request(request, &r.signing_key),
        ) {
            Ok(()) => "ACCEPTED".to_string(),
            Err(e) => refused(e),
        };
        say(name, answer);
    };
    // one envelope of `size` bytes to one recipient: write `size`, read `size * 1 * 200 / 10000`, plus the base event cost 7
    let cost = |size: i64| size + size * 200 / 10_000 + 7;
    send("no_cost_100", 100, None);
    send("cost_too_low_100", 100, Some(cost(100) - 1));
    send("cost_too_high_100", 100, Some(cost(100) + 5));
    std::thread::sleep(std::time::Duration::from_secs(2));
    say("state_after_high", ask(format!("state,{me}")));
    send("right_cost_100", 100, Some(cost(100)));
    std::thread::sleep(std::time::Duration::from_secs(2));
    say("state_after_right", ask(format!("state,{me}")));
    send("over_the_base_5000", 5000, Some(cost(5000)));
    say("purchase_10000", ask(format!("set,{me},1,10000")));
    std::thread::sleep(std::time::Duration::from_secs(3));
    say("state_after_purchase", ask(format!("state,{me}")));
    send("after_purchase_5000", 5000, Some(cost(5000)));
    std::thread::sleep(std::time::Duration::from_secs(2));
    say("state_after_extra", ask(format!("state,{me}")));
    say("disable", ask("disable".into()));
}

/// AT-O08: what the official synchronizer does with logical synchronizer upgrade announcements proposed by its owners (the sequencer and
/// the mediator): a downgrade, a successor that is not greater, a good one, and a change of a good one. Printed as `ORACLE_LSU <case>=<answer>`
/// with the node's refusal from its log. **It announces an upgrade a day ahead: run it alone** (`SEQ_TEST_ARGS=the_official_synchronizer_judges`).
#[test]
#[ignore = "announces an upgrade on the shared sandbox; run it alone"]
fn the_official_synchronizer_judges_upgrade_announcements() {
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let ask = |command: String| -> String {
        let file = format!("{}.lsucmd", unique("lsu"));
        std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        let line = log_line_with(&["SCF lsucmd_done=", &file]).expect("the console answers");
        let answer = line
            .split(&format!("{file}="))
            .nth(1)
            .unwrap_or_default()
            .to_string();
        let log = node_log();
        let lines: Vec<&str> = log.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.contains(&file) && l.contains("SCF lsucmd_done="))
            .unwrap_or(0);
        let why: Vec<&str> = lines[at.saturating_sub(40)..at]
            .iter()
            .copied()
            .filter(|l| {
                l.contains("TOPOLOGY_")
                    || l.contains("GrpcRequestRefusedByServer")
                    || l.contains("rejected")
            })
            .collect();
        format!(
            "{answer} :: {}",
            why.iter().map(|l| l.trim()).collect::<Vec<_>>().join(" | ")
        )
    };
    let say = |case: &str, answer: String| println!("ORACLE_LSU {case}={answer}");
    say("downgrade_36_1", ask("propose,36,1,86400".into()));
    say("not_greater_37_0", ask("propose,37,0,86400".into()));
    say("good_37_1", ask("propose,37,1,86400".into()));
    std::thread::sleep(std::time::Duration::from_secs(3));
    say("list_after_good", ask("list".into()));
    say(
        "same_successor_other_time",
        ask("propose,37,1,90000".into()),
    );
    say("greater_37_2", ask("propose,37,2,86400".into()));
    std::thread::sleep(std::time::Duration::from_secs(3));
    say("list_at_end", ask("list".into()));
}

/// AT-O08: what the official sequencer does once an announced upgrade time has passed: a submission, a subscription and the time it gives.
/// Printed as `ORACLE_LSU_AFTER <case>=<answer>`. **It upgrades the shared sandbox: run it alone.**
#[test]
#[ignore = "passes an upgrade time on the shared sandbox; run it alone"]
fn the_official_sequencer_after_the_upgrade_time() {
    use canton_participant::sequencing_wire as sw;
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let (r, mut c, token) = authenticated("r-lsu-after");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let file = format!("{}.lsucmd", unique("lsu"));
    std::fs::write(dir.join(format!("{file}.tmp")), "propose,37,1,20").unwrap();
    std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
    let line = log_line_with(&["SCF lsucmd_done=", &file]).expect("the console answers");
    println!(
        "ORACLE_LSU_AFTER announce={}",
        line.split(&format!("{file}=")).nth(1).unwrap_or_default()
    );
    let send = |c: &mut SequencerConnect, id: &str| -> String {
        let now = c
            .sequencer_time(&r.member(), &synchronizer, Some(&token))
            .ok()
            .flatten()
            .unwrap_or(0);
        let request = sw::submission_request(
            &r.member(),
            &unique(id),
            &[(r.member(), b"x".to_vec())],
            now + 60_000_000,
        );
        match c.send_async(
            &r.member(),
            &synchronizer,
            &token,
            sw::signed_submission_request(request, &r.signing_key),
        ) {
            Ok(()) => "ACCEPTED".to_string(),
            Err(e) => refused(e),
        }
    };
    println!(
        "ORACLE_LSU_AFTER before_upgrade_send={}",
        send(&mut c, "before")
    );
    std::thread::sleep(std::time::Duration::from_secs(30));
    println!(
        "ORACLE_LSU_AFTER after_upgrade_time={:?}",
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .map_err(|e| e.to_string())
    );
    println!(
        "ORACLE_LSU_AFTER after_upgrade_send={}",
        send(&mut c, "after")
    );
    let events = c
        .subscribe(
            &r.member(),
            &synchronizer,
            &token,
            None,
            200,
            std::time::Duration::from_secs(5),
        )
        .map(|es| {
            es.iter()
                .filter_map(|e| sw::decode_delivered(e))
                .map(|d| {
                    format!(
                        "{}:{}:{}",
                        d.timestamp_micros,
                        d.message_id.unwrap_or_default(),
                        d.error.unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
        })
        .map_err(|e| e.to_string());
    println!("ORACLE_LSU_AFTER events={events:?}");
    let log = node_log();
    for l in log
        .lines()
        .filter(|l| {
            l.contains("upgrade") || l.contains("Upgrade") || l.contains("LSU") || l.contains("Lsu")
        })
        .take(20)
    {
        println!(
            "ORACLE_LSU_AFTER log={}",
            l.chars().take(400).collect::<String>()
        );
    }
}

/// A 32-byte value derived from a label and the clock: salts and uuids of one request.
fn fresh(label: &str) -> [u8; 32] {
    canton_algo::hash::sha256_with_purpose(1, unique(label).as_bytes())
}

/// What a confirmation request is made of in these tests.
struct Request {
    /// the informee party (hosted by p1 unless a test says otherwise)
    informee: String,
    /// the root hash the root hash message carries (the tree's own unless a test corrupts it)
    root_hash_in_message: Option<Vec<u8>>,
    /// sign these bytes instead of the tree's root hash
    signed_instead: Option<Vec<u8>>,
}

/// A random version-4 UUID: the mediator refuses a transaction UUID it has seen (replay protection), so every request needs its own.
fn fresh_uuid() -> String {
    let h = fresh("uuid");
    format!(
        "{}-{}-4{}-8{}-{}",
        hex::encode(&h[0..4]),
        hex::encode(&h[4..6]),
        &hex::encode(&h[6..8])[1..],
        &hex::encode(&h[8..10])[1..],
        hex::encode(&h[10..16])
    )
}

/// The informee tree of a request with one root view (informee `informee`, confirmation threshold 1), built in Rust.
fn request_tree(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    informee: &str,
    now: i64,
    synchronizer: &str,
) -> canton_participant::merkle_wire::GenTree {
    use canton_participant::merkle_wire as mw;
    let uuid = fresh_uuid();
    let uid = r.member().trim_start_matches("PAR::").to_string();
    let common = mw::common_metadata(synchronizer, 0, &fresh("cm"), &uuid);
    let participant = mw::participant_metadata(now, now, None, &fresh("pm"));
    let submitter = mw::submitter_metadata(
        &mw::SubmitterInfo {
            act_as: vec![&informee],
            user_id: "rust-user",
            command_id: &unique("cmd"),
            submitting_participant_uid: &uid,
            submission_id: None,
            dedup_duration: (300, 0),
            max_sequencing_time_micros: now + 60_000_000,
        },
        &fresh("sm"),
    );
    let vcd = mw::view_common_data(
        &[informee],
        &[mw::QuorumSpec {
            confirmers: vec![(informee, 1)],
            threshold: 1,
        }],
        &fresh("vcd"),
    );
    let mut vpd_hash = vec![0x12, 0x20];
    vpd_hash.extend_from_slice(&fresh("vpd"));
    let view = mw::view_node(
        &mw::Tree::leaf(&vcd),
        &mw::Tree::blinded(vpd_hash),
        &mw::merkle_seq(&[]),
    );
    mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::blinded(participant.root_hash()),
        &mw::merkle_seq(&[view]),
    )
}

/// Builds the informee message and the root hash message for the informee, signs, sends, and returns the submitting member.
fn send_confirmation_request(request: Request, name: &str) -> String {
    use canton_participant::{confirmation_wire as cw, sequencing_wire as sw};
    let (r, mut c, token) = authenticated(name);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let tree = request_tree(&r, &request.informee, now, &synchronizer);
    let mediator = cw::mediator_group(0);
    let message_hash = request
        .root_hash_in_message
        .unwrap_or_else(|| tree.root_hash.clone());
    let envelopes = vec![
        (
            vec![mediator.clone()],
            cw::informee_message_signed_over(
                &tree,
                &r.signing_key,
                request.signed_instead.as_deref().unwrap_or(&tree.root_hash),
            ),
        ),
        (
            vec![mediator, var("CANTON_RS_MEMBER_P1")],
            cw::root_hash_message(&message_hash, &synchronizer, now),
        ),
    ];
    c.send_async(
        &r.member(),
        &synchronizer,
        &token,
        sw::signed_submission_request(
            sw::submission_request_to_groups(
                &r.member(),
                &unique("conf"),
                &envelopes,
                now + 60_000_000,
            ),
            &r.signing_key,
        ),
    )
    .expect("the sequencer accepts the submission");
    r.member()
}

/// The node's log shortens a member to `PAR::name::1220<12 hex>...`: the part that identifies it is the name.
fn log_name(member: &str) -> String {
    member
        .rsplit_once("::")
        .map(|(name, _)| name.to_string())
        .expect("a member")
}

#[test]
fn the_mediator_registers_a_confirmation_request_built_and_signed_in_rust() {
    let member = send_confirmation_request(
        Request {
            informee: var("CANTON_RS_ALICE"),
            root_hash_in_message: None,
            signed_instead: None,
        },
        &unique("r-conf"),
    );
    // Phase 2: the mediator parsed the informee tree, verified the Rust participant's signature on its root hash, found the
    // informee hosted, accepted the root hash message and registered the request
    let registered = log_line_with(&[
        "Phase 2: Registered request",
        &format!("submittingParticipant={}", log_name(&member)),
    ])
    .unwrap_or_else(|| {
        panic!(
            "the mediator did not register the request of {member}:\n{}",
            node_log()
                .lines()
                .filter(
                    |l| (l.contains("mediator=m1") || l.contains("participant=p1"))
                        && (l.contains("WARN") || l.contains("ERROR"))
                )
                .collect::<Vec<_>>()
                .join("\n")
        )
    });
    assert!(registered.contains("with 1 view(s)"), "{registered}");
    // Phases 5 and 6: p1 (the informee's participant) got the root hash message but no encrypted view, so it answers with a
    // rejection, and the mediator finalizes the request with that verdict
    let request_time = registered
        .split("request=")
        .nth(1)
        .and_then(|t| t.split(' ').next())
        .expect("the request time in the line");
    let finalized = log_line_with(&[
        "Phase 6: Finalized request",
        &format!("RequestId({request_time})"),
    ])
    .expect("the mediator finalizes the request");
    assert!(finalized.contains("ParticipantReject"), "{finalized}");
}

#[test]
fn the_mediator_rejects_a_root_hash_message_that_does_not_match_the_tree() {
    let mut wrong = vec![0x12, 0x20];
    wrong.extend_from_slice(&fresh("wrong"));
    // the node prints the first 12 hex digits of the hash it rejects
    let shown = hex::encode(&wrong[2..8]);
    send_confirmation_request(
        Request {
            informee: var("CANTON_RS_ALICE"),
            root_hash_in_message: Some(wrong),
            signed_instead: None,
        },
        &unique("r-wronghash"),
    );
    let line = log_line_with(&["Wrong root hashes", &format!("SHA-256:{shown}")])
        .expect("the mediator names the root hash that does not match the tree");
    assert!(
        line.contains("MEDIATOR_RECEIVED_MALFORMED_MESSAGE"),
        "{line}"
    );
}

#[test]
fn the_mediator_rejects_an_informee_that_no_participant_hosts() {
    let nobody = format!("nobody::1220{}", "cd".repeat(32));
    let member = send_confirmation_request(
        Request {
            informee: nobody,
            root_hash_in_message: None,
            signed_instead: None,
        },
        &unique("r-nohost"),
    );
    let line = log_line_with(&[
        "not being hosted by an active participant",
        "nobody::1220cdcdcdcd",
    ])
    .unwrap_or_else(|| panic!("no rejection for the unhosted informee of {member}"));
    assert!(line.contains("MEDIATOR_INVALID_MESSAGE"), "{line}");
}

#[test]
fn the_mediator_rejects_an_informee_message_whose_signature_is_not_over_the_root_hash() {
    let member = send_confirmation_request(
        Request {
            informee: var("CANTON_RS_ALICE"),
            root_hash_in_message: None,
            signed_instead: Some(fresh("not the root hash").to_vec()),
        },
        &unique("r-badsig"),
    );
    let line = log_line_with(&["with an invalid signature", &log_name(&member)])
        .expect("the mediator names the invalid signature of the submitting participant");
    assert!(
        line.contains("MEDIATOR_RECEIVED_MALFORMED_MESSAGE"),
        "{line}"
    );
}

/// [CANTON-NOTE: SEMANTICS] The verdict on a broadcast topology transaction is in the log of every node that runs it through
/// its topology processor (`Storing`/`Persisted` when it is accepted, `Rejected ... due to <reason>` when it is not). The
/// state a participant downloads at onboarding is *not* a witness: it is the state as of the onboarding time.
fn verdicts(node: &str, hash: &str) -> (Option<String>, Option<String>) {
    let accepted = log_line_with(&[
        node,
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{hash}"),
    ]);
    let rejected = node_log()
        .lines()
        .find(|l| {
            l.contains(node)
                && l.contains("Rejected transaction")
                && l.contains(&format!("TxHash(SHA-256:{hash}"))
        })
        .map(str::to_string);
    (accepted, rejected)
}

#[test]
fn a_party_hosted_by_the_rust_participant_is_accepted_by_sequencer_mediator_and_participant() {
    let (r, mut c, token) = authenticated(&unique("r-p2p"));
    let tx = r.party_hosting_transaction("carol");
    let hash = tx_hash_in_log(&tx.transaction);
    broadcast(&r, &mut c, &token, &[tx]);
    let namespace_prefix = &r.namespace()[..12];
    for node in ["sequencer=s1", "mediator=m1", "participant=p1"] {
        let (accepted, rejected) = verdicts(node, &hash);
        let line = accepted.unwrap_or_else(|| {
            panic!("{node} did not store the party transaction; rejected: {rejected:?}")
        });
        assert!(
            line.contains(&format!("signedBy=Set({namespace_prefix}")),
            "{node}: signed by the namespace key: {line}"
        );
        assert!(rejected.is_none(), "{node} also rejected it: {rejected:?}");
    }
}

#[test]
fn a_party_transaction_not_signed_by_its_namespace_is_rejected_by_every_node() {
    use canton_participant::topology_wire as tw;
    let (r, mut c, token) = authenticated(&unique("r-p2p-bad"));
    let bytes = tw::party_to_participant(&r.party_id("dave"), &r.uid());
    // signed by the participant's protocol key instead of the namespace key: no delegation authorizes that key
    let forged = tw::signed(bytes.clone(), vec![r.signing_key.sign_transaction(&bytes)]);
    let hash = tx_hash_in_log(&bytes);
    broadcast(&r, &mut c, &token, &[forged]);
    for node in ["sequencer=s1", "mediator=m1", "participant=p1"] {
        let rejected = log_line_with(&[
            node,
            "Rejected transaction",
            &format!("TxHash(SHA-256:{hash}"),
        ])
        .unwrap_or_else(|| panic!("{node} did not reject the forged party transaction"));
        assert!(
            rejected.contains("No delegation found for keys"),
            "{node}: {rejected}"
        );
        assert!(
            node_log().lines().all(|l| !(l.contains(node)
                && l.contains("Storing topology transaction")
                && l.contains(&format!("TxHash(SHA-256:{hash}")))),
            "{node} stored the forged party transaction"
        );
    }
}

/// What the Rust participant does as the one participant of a request: host a party, send a confirmation request for it,
/// learn the request's sequencing time from the delivery of its own submission, and answer the request.
fn rust_participant_runs_a_request(approve: bool, view_position: Vec<Vec<bool>>) -> (String, i64) {
    use canton_participant::{confirmation_wire as cw, sequencing_wire as sw};
    let (r, mut c, token) = authenticated(&unique("r-self"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    // the party is hosted by this participant, and the hosting must be in effect before the request
    let party = r.party_id("erin");
    let hosting = r.party_hosting_transaction("erin");
    let hash = tx_hash_in_log(&hosting.transaction);
    broadcast(&r, &mut c, &token, &[hosting]);
    log_line_with(&[
        "participant=p1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{hash}"),
    ])
    .expect("p1 stores the party hosting");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let tree = request_tree(&r, &party, now, &synchronizer);
    let mediator = cw::mediator_group(0);
    let request_message_id = unique("conf");
    let request = sw::submission_request_to_groups(
        &r.member(),
        &request_message_id,
        &[
            (
                vec![mediator.clone()],
                cw::informee_message(&tree, &r.signing_key),
            ),
            // the one participant that hosts an informee is this one
            (
                vec![mediator.clone(), r.member()],
                cw::root_hash_message(&tree.root_hash, &synchronizer, now),
            ),
        ],
        now + 60_000_000,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        &token,
        sw::signed_submission_request(request, &r.signing_key),
    )
    .expect("the sequencer accepts the request");
    // the sequencing time of our own submission is the request id the mediator uses
    let mut from = now + 1;
    let request_id = loop {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(from),
                1,
                std::time::Duration::from_secs(10),
            )
            .expect("subscribe");
        let d = sw::decode_delivered(events.first().expect("our request comes back")).unwrap();
        from = d.timestamp_micros + 1;
        if d.message_id.as_deref() == Some(request_message_id.as_str()) {
            break d.timestamp_micros;
        }
    };
    let (content, signatures) = cw::confirmation_responses(
        request_id,
        &tree.root_hash,
        &synchronizer,
        &r.member(),
        &[cw::ViewResponse {
            view_position: &view_position,
            outcome: if approve {
                cw::Outcome::Approve
            } else {
                cw::Outcome::Reject("rejected by the test".into())
            },
            confirming_parties: &[party],
        }],
        &r.signing_key,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        &token,
        sw::signed_submission_request(
            sw::submission_request_signed(
                &r.member(),
                &unique("resp"),
                &[(vec![mediator], content, signatures)],
                request_id + 30_000_000,
            ),
            &r.signing_key,
        ),
    )
    .expect("the sequencer accepts the responses");
    (r.member(), request_id)
}

/// The mediator's `Phase 6` line for the request `member` made.
fn finalized_line_of(member: &str) -> String {
    let registered = log_line_with(&[
        "Phase 2: Registered request",
        &format!("submittingParticipant={}", log_name(member)),
    ])
    .expect("the mediator registers the request");
    let request_time = registered
        .split("request=")
        .nth(1)
        .and_then(|t| t.split(' ').next())
        .expect("the request time");
    log_line_with(&[
        "Phase 6: Finalized request",
        &format!("RequestId({request_time})"),
    ])
    .unwrap_or_else(|| {
        panic!(
            "no verdict for {request_time}:\n{}",
            node_log()
                .lines()
                .filter(|l| l.contains("mediator=m1")
                    && (l.contains("WARN") || l.contains("ERROR") || l.contains("Phase")))
                .rev()
                .take(12)
                .map(|l| l.chars().take(500).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        )
    })
}

#[test]
fn the_mediator_approves_a_request_the_rust_participant_confirms_for_its_own_party() {
    let (member, _) = rust_participant_runs_a_request(true, vec![vec![]]);
    let finalized = finalized_line_of(&member);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn the_mediator_rejects_a_request_the_rust_participant_answers_with_a_rejection() {
    let (member, _) = rust_participant_runs_a_request(false, vec![vec![]]);
    let finalized = finalized_line_of(&member);
    assert!(finalized.contains("ParticipantReject"), "{finalized}");
}

#[test]
fn the_mediator_discards_a_response_for_a_view_position_the_tree_does_not_have() {
    let (member, _) = rust_participant_runs_a_request(true, vec![vec![true, true]]);
    let line = log_line_with(&[
        "MEDIATOR_RECEIVED_MALFORMED_MESSAGE",
        "with an unknown view position ViewPosition(RR)",
        &log_name(&member),
    ])
    .expect("the mediator names the unknown view position of the response");
    assert!(line.contains("Discarding response"), "{line}");
}

/// p1's public encryption key (DER SubjectPublicKeyInfo) as the topology state lists it.
fn p1_encryption_key(
    c: &mut SequencerConnect,
    r: &canton_participant::topology_wire::ParticipantIdentity,
    token: &canton_participant::sequencer_connect::Token,
) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::crypto::v30::public_key::Key;
    let state = c
        .download_topology_state(&r.member(), &var("CANTON_RS_EXPECT_SYNCHRONIZER"), token)
        .unwrap();
    let p1 = var("CANTON_RS_MEMBER_P1");
    downloaded::decode(&state)
        .iter()
        .find_map(|e| match downloaded::mapping(e) {
            downloaded::Mapping::OwnerToKeyMapping(m) if m.member == p1 => {
                m.public_keys.iter().find_map(|k| match &k.key {
                    Some(Key::EncryptionPublicKey(e)) => Some(e.public_key.clone()),
                    _ => None,
                })
            }
            _ => None,
        })
        .expect("p1's encryption key is in the topology state")
}

#[test]
fn p1_fingerprint_of_its_encryption_key_is_the_one_rust_computes_from_the_der() {
    let (r, mut c, token) = authenticated(&unique("r-fp"));
    let spki = p1_encryption_key(&mut c, &r, &token);
    assert_eq!(
        canton_participant::topology_wire::fingerprint(&spki),
        var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT")
    );
}

/// A request whose one view creates a contract and is sent, encrypted, to p1 (the participant of the informee alice).
/// Returns the submitting member.
fn send_encrypted_view_to_p1(
    name: &str,
    tamper: impl FnOnce(
        &mut canton_proto::com::digitalasset::canton::protocol::v32::EncryptedMultipleViewsMessage,
    ),
) -> String {
    use canton_participant::contract_id as ci;
    use canton_participant::contract_wire::{authentication_data, ContractInstance, LfValue};
    use canton_participant::{
        confirmation_wire as cw, merkle_wire as mw, sequencing_wire as sw, view_message as vm,
    };
    let (r, mut c, token) = authenticated(name);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let p1_key = p1_encryption_key(&mut c, &r, &token);
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    // the contract: its id is derived as the node derives it
    let uuid = fresh_uuid();
    let vpd_salt = fresh("vpd-salt");
    let salt = ci::contract_salt(&ci::SaltInputs {
        view_participant_data_salt: &vpd_salt,
        create_index: 0,
        view_position: &[vec![]],
        transaction_uuid: &uuid,
        synchronizer_id: &synchronizer,
        mediator: "MGR::0",
    });
    let record = |fields: Vec<(&str, ci::HashValue)>| ci::HashValue::Record {
        module: vec!["Main".into()],
        name: vec!["Holding".into()],
        fields: fields
            .into_iter()
            .map(|(l, v)| (l.to_string(), v))
            .collect(),
    };
    let contract_hash = ci::lf_contract_hash(
        "sample-contract",
        &["Main".into()],
        &["Holding".into()],
        &record(vec![
            ("owner", ci::HashValue::Party(alice.clone())),
            ("amount", ci::HashValue::Int64(42)),
        ]),
    );
    let unicum = ci::unicum(
        &salt,
        &ci::UnicumInputs {
            created_at_micros: now,
            signatories: std::slice::from_ref(&alice),
            stakeholders: std::slice::from_ref(&alice),
            key: None,
            contract_hash: &contract_hash,
        },
    );
    let node_seed = fresh("node-seed");
    let discriminator =
        ci::derive_contract_discriminator(&node_seed, now, std::slice::from_ref(&alice));
    let id_hex = ci::contract_id(&discriminator, &unicum);
    let instance = ContractInstance {
        contract_id: hex::decode(&id_hex).unwrap(),
        package_name: "sample-contract".into(),
        package_id: "ab".repeat(32),
        module: vec!["Main".into()],
        name: vec!["Holding".into()],
        arg: LfValue::Record(vec![LfValue::Party(alice.clone()), LfValue::Int64(42)]),
        signatories: [alice.clone()].into(),
        stakeholders: [alice.clone()].into(),
        created_at_micros: now,
        authentication_data: authentication_data(&salt),
        key: None,
    };
    let vpd = mw::view_participant_data_create(&instance.encode(), &id_hex, &node_seed, &vpd_salt);
    // the trees: the full one (what p1 reads) and the informee one (the mediator's; same root hash, participant data blinded)
    let uid = r.member().trim_start_matches("PAR::").to_string();
    let common = mw::common_metadata(&synchronizer, 0, &fresh("cm"), &uuid);
    let participant = mw::participant_metadata(now, now, None, &fresh("pm"));
    let submitter = mw::submitter_metadata(
        &mw::SubmitterInfo {
            act_as: vec![&alice],
            user_id: "rust-user",
            command_id: &unique("cmd"),
            submitting_participant_uid: &uid,
            submission_id: None,
            dedup_duration: (300, 0),
            max_sequencing_time_micros: now + 60_000_000,
        },
        &fresh("sm"),
    );
    let vcd = mw::view_common_data(
        &[&alice],
        &[mw::QuorumSpec {
            confirmers: vec![(&alice, 1)],
            threshold: 1,
        }],
        &fresh("vcd"),
    );
    let view = |participant_data: &mw::Tree| {
        mw::view_node(
            &mw::Tree::leaf(&vcd),
            participant_data,
            &mw::merkle_seq(&[]),
        )
    };
    let full_view = view(&mw::Tree::leaf(&vpd));
    let full = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::leaf(&participant),
        &mw::merkle_seq(std::slice::from_ref(&full_view)),
    );
    let informee_view = view(&mw::Tree::blinded(vpd.root_hash()));
    let informee = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::blinded(participant.root_hash()),
        &mw::merkle_seq(&[informee_view]),
    );
    assert_eq!(
        full.root_hash, informee.root_hash,
        "blinding keeps the root hash"
    );
    // the encrypted view for p1
    let encrypted = vm::encrypted_view_message(
        &vm::light_view_tree(&full),
        &full_view.hash,
        &fresh("randomness")[..16].try_into().unwrap(),
        &fresh("gcm-iv")[..12].try_into().unwrap(),
        &[vm::Recipient {
            encryption_spki: &p1_key,
            fingerprint: &var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
            ecies_iv: fresh("ecies-iv")[..16].try_into().unwrap(),
            ecies_ephemeral_scalar: fresh("ecies-eph"),
        }],
        &synchronizer,
        r.signing_key.sign_bytes(&full.root_hash),
    );
    let encrypted = {
        use canton_proto::com::digitalasset::canton::protocol::v32::{
            envelope_content::SomeEnvelopeContent, EnvelopeContent,
        };
        use prost::Message;
        let (inner, _) = canton_participant::topology_wire::unversioned(&encrypted).unwrap();
        let mut content = EnvelopeContent::decode(inner.as_slice()).unwrap();
        let Some(SomeEnvelopeContent::EncryptedMultipleViewsMessage(m)) =
            &mut content.some_envelope_content
        else {
            panic!("an encrypted view message")
        };
        tamper(m);
        canton_participant::topology_wire::versioned(content.encode_to_vec(), 32)
    };
    let mediator = cw::mediator_group(0);
    let request = sw::submission_request_to_groups(
        &r.member(),
        &unique("enc"),
        &[
            (
                vec![mediator.clone()],
                cw::informee_message(&informee, &r.signing_key),
            ),
            (
                vec![mediator, var("CANTON_RS_MEMBER_P1")],
                cw::root_hash_message(&full.root_hash, &synchronizer, now),
            ),
            (vec![var("CANTON_RS_MEMBER_P1")], encrypted),
        ],
        now + 60_000_000,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        &token,
        sw::signed_submission_request(request, &r.signing_key),
    )
    .expect("the sequencer accepts the request");
    r.member()
}

/// The request time of the request `member` made, as the mediator's log writes it.
fn request_time_of(member: &str) -> String {
    log_line_with(&[
        "Phase 2: Registered request",
        &format!("submittingParticipant={}", log_name(member)),
    ])
    .unwrap_or_else(|| {
        panic!(
            "the mediator did not register the request of {member}:\n{}",
            node_log()
                .lines()
                .filter(|l| l.contains(&log_name(member))
                    || (l.contains("mediator=m1") && l.contains("WARN")))
                .map(|l| l.chars().take(500).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        )
    })
    .split("request=")
    .nth(1)
    .and_then(|t| t.split(' ').next())
    .expect("the request time")
    .to_string()
}

/// The lines of p1's log that belong to the request `time` of `member`: they share the trace id of its `Phase 3` line.
fn p1_lines_of_request(time: &str) -> Vec<String> {
    let phase3 = log_line_with(&[
        "participant=p1",
        "Phase 3: Validating Transaction",
        &format!("request={time}"),
    ])
    .unwrap_or_else(|| panic!("p1 did not start validating the request {time}"));
    let tid = phase3
        .split("tid:")
        .nth(1)
        .and_then(|t| t.split(' ').next())
        .expect("a trace id")
        .to_string();
    // p1 answers within a few seconds; give it the time
    std::thread::sleep(std::time::Duration::from_secs(6));
    node_log()
        .lines()
        .filter(|l| l.contains("participant=p1") && l.contains(&format!("tid:{tid}")))
        .map(str::to_string)
        .collect()
}

#[test]
fn p1_decrypts_and_parses_a_view_that_rust_encrypted_and_tries_to_replay_it() {
    let member = send_encrypted_view_to_p1(&unique("r-enc"), |_| {});
    let lines = p1_lines_of_request(&request_time_of(&member));
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    // p1 decrypted the session key with its private key, decrypted and decompressed the views with it, parsed the light view
    // tree, and handed the view to its engine: the check that fails is the model conformance check (the template's package is
    // not on p1), not any decryption or parsing step
    assert!(
        has("LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK"),
        "p1 did not reach the model conformance check:\n{}",
        lines.join("\n")
    );
    assert!(!has("Decryption error"), "{}", lines.join("\n"));
    assert!(!has("MALFORMED_PAYLOAD"), "{}", lines.join("\n"));
    // [CANTON-NOTE: LIMITATION] p1 also finds the view "not correctly authorized": the submitter alice is not hosted by the
    // submitting (Rust) participant. That is the next hurdle (see S-NET-013).
    assert!(has("not correctly authorized"), "{}", lines.join("\n"));
}

#[test]
fn p1_cannot_decrypt_a_view_whose_ciphertext_was_tampered_with() {
    let member = send_encrypted_view_to_p1(&unique("r-enc-bad"), |m| {
        let last = m.compressed_view_trees.len() - 1;
        m.compressed_view_trees[last] ^= 1; // breaks the GCM tag
    });
    let lines = p1_lines_of_request(&request_time_of(&member));
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    assert!(
        has("Decryption error: SymmetricDecryptError") && has("mac check in GCM failed"),
        "{}",
        lines.join("\n")
    );
    assert!(
        has("LOCAL_VERDICT_MALFORMED_PAYLOAD"),
        "{}",
        lines.join("\n")
    );
    assert!(
        !has("LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK"),
        "p1 replayed a view it could not decrypt"
    );
}

/// Hosting and vetting broadcast for the Rust participant: it hosts the party `name` and vets the sample package; waits until
/// p1 has stored both and the change is in effect. Returns the party.
fn host_party_and_vet_sample(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    name: &str,
    shared_with_p1: bool,
) -> String {
    host_party_and_vet(
        r,
        c,
        token,
        name,
        shared_with_p1,
        &var("CANTON_RS_SAMPLE_PACKAGE"),
    )
}

/// Hosts the party `name` on `r` (with submission permission; `shared_with_p1` makes p1 a co-host that confirms) and vets `package`.
fn host_party_and_vet(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    name: &str,
    shared_with_p1: bool,
    package: &str,
) -> String {
    host_party_and_vet_all(r, c, token, name, shared_with_p1, &[package.to_string()])
}

/// Like [`host_party_and_vet`] for several packages (a DAR and everything it depends on).
fn host_party_and_vet_all(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    name: &str,
    shared_with_p1: bool,
    packages: &[String],
) -> String {
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let hosting = if shared_with_p1 {
        r.shared_party_proposal(name, &p1_uid)
    } else {
        r.party_hosting_transaction(name)
    };
    let vetting = r.vetting_transaction(packages);
    let hashes = [
        tx_hash_in_log(&hosting.transaction),
        tx_hash_in_log(&vetting.transaction),
    ];
    let hosting_hash = canton_participant::topology_wire::transaction_hash(&hosting.transaction);
    broadcast(r, c, token, &[hosting, vetting]);
    for hash in &hashes {
        log_line_with(&[
            "participant=p1",
            "Storing topology transaction",
            &format!("TxHash(SHA-256:{hash}"),
        ])
        .expect("p1 stores the transaction");
    }
    if shared_with_p1 {
        // the party needs p1's authorization too: p1 co-signs the proposal, and the synchronizer then stores it signed by both
        have_p1_authorize(&hosting_hash);
        let p1_ns = p1_uid.split("::").nth(1).unwrap()[..12].to_string();
        log_line_with(&[
            "sequencer=s1",
            "Storing topology transaction",
            &format!("TxHash(SHA-256:{}", hashes[0]),
            &r.namespace()[..12],
            &p1_ns,
        ])
        .expect("the synchronizer stores the party signed by both participants");
    }
    std::thread::sleep(std::time::Duration::from_secs(2));
    r.party_id(name)
}

/// A request that creates a real `AssetHolding` of the sample DAR: signatories `bank` and `owner` are the Rust participant's
/// party, the observer `auditor` is alice of p1. The view goes, encrypted, to p1. Returns the submitting member.
fn send_sample_create_to_p1(
    name: &str,
    amount: &str,
    wrong_stakeholders: bool,
    p1_confirms: bool,
) -> String {
    let (r, mut c, token) = authenticated(name);
    let erin = host_party_and_vet_sample(&r, &mut c, &token, "erin", p1_confirms);
    rust_creates_sample(
        &r,
        &mut c,
        &token,
        &erin,
        &erin,
        amount,
        wrong_stakeholders,
        p1_confirms,
    );
    r.member()
}

/// What a Rust-submitted create of the sample contract left behind: everything a later request needs to use the contract.
struct SampleCreated {
    /// The contract instance exactly as the create view carried it.
    instance: Vec<u8>,
    id_hex: String,
    /// The sequencing time of the create request.
    request_id: i64,
}

/// The create itself: `erin` (hosted by `r`) is bank and owner of an `AssetHolding` with auditor alice. The request is sent and
/// answered as the submitting participant.
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn rust_creates_sample(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    erin: &str,
    owner: &str,
    amount: &str,
    wrong_stakeholders: bool,
    p1_confirms: bool,
) -> SampleCreated {
    use canton_participant::contract_id as ci;
    use canton_participant::contract_wire::{authentication_data, ContractInstance, LfValue};
    use canton_participant::{
        confirmation_wire as cw, merkle_wire as mw, sequencing_wire as sw, view_message as vm,
    };
    let token = token.clone();
    let erin = erin.to_string();
    let owner = owner.to_string();
    // the signatories are the bank and the owner (one party when they are the same)
    let signatories: Vec<String> = {
        let mut s = vec![erin.clone(), owner.clone()];
        s.sort();
        s.dedup();
        s
    };
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let package_id = var("CANTON_RS_SAMPLE_PACKAGE");
    let p1_key = p1_encryption_key(c, r, &token);
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let uuid = fresh_uuid();
    let vpd_salt = fresh("vpd-salt");
    let salt = ci::contract_salt(&ci::SaltInputs {
        view_participant_data_salt: &vpd_salt,
        create_index: 0,
        view_position: &[vec![]],
        transaction_uuid: &uuid,
        synchronizer_id: &synchronizer,
        mediator: "MGR::0",
    });
    // `AssetHolding { bank, owner, auditor, assetSymbol, amount }` (the amount is a `Numeric 10`)
    let unscaled: i128 = {
        let (whole, frac) = amount.split_once('.').unwrap();
        format!("{whole}{frac:0<10}").parse().unwrap()
    };
    let hash_arg = ci::HashValue::Record {
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        fields: vec![
            ("bank".into(), ci::HashValue::Party(erin.clone())),
            ("owner".into(), ci::HashValue::Party(owner.clone())),
            ("auditor".into(), ci::HashValue::Party(alice.clone())),
            ("assetSymbol".into(), ci::HashValue::Text("USD".into())),
            ("amount".into(), ci::HashValue::Numeric(unscaled)),
        ],
    };
    let contract_hash = ci::lf_contract_hash(
        "sample-contract",
        &["AssetHolding".into()],
        &["AssetHolding".into()],
        &hash_arg,
    );
    let stakeholders: Vec<String> = {
        let mut s = vec![erin.clone(), owner.clone(), alice.clone()];
        s.sort();
        s.dedup();
        s
    };
    let unicum = ci::unicum(
        &salt,
        &ci::UnicumInputs {
            created_at_micros: now,
            signatories: &signatories,
            stakeholders: &stakeholders,
            key: None,
            contract_hash: &contract_hash,
        },
    );
    let node_seed = fresh("node-seed");
    let discriminator = ci::derive_contract_discriminator(&node_seed, now, &stakeholders);
    let id_hex = ci::contract_id(&discriminator, &unicum);
    let instance = ContractInstance {
        contract_id: hex::decode(&id_hex).unwrap(),
        package_name: "sample-contract".into(),
        package_id,
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        arg: LfValue::Record(vec![
            LfValue::Party(erin.clone()),
            LfValue::Party(owner.clone()),
            LfValue::Party(alice.clone()),
            LfValue::Text("USD".into()),
            LfValue::Numeric(format!(
                "{amount}{}",
                "0".repeat(10 - amount.split_once('.').unwrap().1.len())
            )),
        ]),
        signatories: signatories.iter().cloned().collect(),
        // a contract whose recorded stakeholders omit the observer the arguments name: the view does not describe what the engine
        // computes from the arguments
        stakeholders: if wrong_stakeholders {
            [erin.clone()].into()
        } else {
            stakeholders.iter().cloned().collect()
        },
        created_at_micros: now,
        authentication_data: authentication_data(&salt),
        key: None,
    };
    let instance_bytes = instance.encode();
    let vpd = mw::view_participant_data_create(&instance_bytes, &id_hex, &node_seed, &vpd_salt);
    let uid = r.member().trim_start_matches("PAR::").to_string();
    let common = mw::common_metadata(&synchronizer, 0, &fresh("cm"), &uuid);
    let participant = mw::participant_metadata(now, now, None, &fresh("pm"));
    let submitter = mw::submitter_metadata(
        &mw::SubmitterInfo {
            act_as: signatories.iter().map(String::as_str).collect(),
            user_id: "rust-user",
            command_id: &unique("cmd"),
            submitting_participant_uid: &uid,
            submission_id: None,
            dedup_duration: (300, 0),
            max_sequencing_time_micros: now + 60_000_000,
        },
        &fresh("sm"),
    );
    // [CANTON-NOTE: SEMANTICS] The informees of a root view are the stakeholders **plus the submitting participant's admin party**
    // (the party named by the participant's uid), which must confirm too: the quorum is {signatory: 1, admin party: 1} with
    // threshold 2. p1 reconstructs the view and compares it hash for hash, so this is not optional. Informees and confirmers are
    // sorted by party id.
    let admin = r.uid();
    let mut informees = stakeholders.clone();
    informees.push(admin.clone());
    informees.sort();
    informees.dedup();
    let informee_refs: Vec<&str> = informees.iter().map(String::as_str).collect();
    let mut confirmers: Vec<(&str, i32)> = signatories.iter().map(|s| (s.as_str(), 1)).collect();
    confirmers.push((admin.as_str(), 1));
    confirmers.sort();
    let threshold = confirmers.len() as i32;
    let vcd = mw::view_common_data(
        &informee_refs,
        &[mw::QuorumSpec {
            confirmers,
            threshold,
        }],
        &fresh("vcd"),
    );
    let view = |participant_data: &mw::Tree| {
        mw::view_node(
            &mw::Tree::leaf(&vcd),
            participant_data,
            &mw::merkle_seq(&[]),
        )
    };
    let full_view = view(&mw::Tree::leaf(&vpd));
    let full = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::leaf(&participant),
        &mw::merkle_seq(std::slice::from_ref(&full_view)),
    );
    let informee = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::blinded(participant.root_hash()),
        &mw::merkle_seq(&[view(&mw::Tree::blinded(vpd.root_hash()))]),
    );
    assert_eq!(full.root_hash, informee.root_hash);
    let encrypted = vm::encrypted_view_message(
        &vm::light_view_tree(&full),
        &full_view.hash,
        &fresh("randomness")[..16].try_into().unwrap(),
        &fresh("gcm-iv")[..12].try_into().unwrap(),
        &[
            vm::Recipient {
                encryption_spki: &p1_key,
                fingerprint: &var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
                ecies_iv: fresh("ecies-iv")[..16].try_into().unwrap(),
                ecies_ephemeral_scalar: fresh("ecies-eph"),
            },
            vm::Recipient {
                encryption_spki: r.encryption_spki(),
                fingerprint: &r.encryption_fingerprint(),
                ecies_iv: fresh("ecies-iv2")[..16].try_into().unwrap(),
                ecies_ephemeral_scalar: fresh("ecies-eph2"),
            },
        ],
        &synchronizer,
        r.signing_key.sign_bytes(&full.root_hash),
    );
    let mediator = cw::mediator_group(0);
    // the root hash message goes to the mediator and every participant hosting an informee: p1 (alice) and this one (erin)
    let request_message_id = unique("sample");
    let request = sw::submission_request_to_groups(
        &r.member(),
        &request_message_id,
        &[
            (
                vec![mediator.clone()],
                cw::informee_message(&informee, &r.signing_key),
            ),
            (
                vec![mediator.clone(), var("CANTON_RS_MEMBER_P1")],
                cw::root_hash_message(&full.root_hash, &synchronizer, now),
            ),
            (
                vec![mediator, r.member()],
                cw::root_hash_message(&full.root_hash, &synchronizer, now),
            ),
            // every informee participant must be among the recipients of the encrypted view
            (vec![var("CANTON_RS_MEMBER_P1"), r.member()], encrypted),
        ],
        now + 60_000_000,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        &token,
        sw::signed_submission_request(request, &r.signing_key),
    )
    .expect("the sequencer accepts the request");
    // the sequencing time of our own submission is the request id; answer the request as the participant that hosts erin and
    // is the submitting participant (whose admin party confirms too)
    let mut from = now + 1;
    let request_id = loop {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(from),
                1,
                std::time::Duration::from_secs(10),
            )
            .expect("subscribe");
        let d = sw::decode_delivered(events.first().expect("our request comes back")).unwrap();
        from = d.timestamp_micros + 1;
        if d.message_id.as_deref() == Some(request_message_id.as_str()) {
            break d.timestamp_micros;
        }
    };
    // when p1 hosts the signatory too, p1 confirms it (after validating); this participant then answers for its admin party only
    let mut confirming = if p1_confirms {
        vec![admin]
    } else {
        let mut all = signatories.clone();
        all.push(admin);
        all
    };
    confirming.sort();
    let (content, signatures) = cw::confirmation_responses(
        request_id,
        &full.root_hash,
        &synchronizer,
        &r.member(),
        &[cw::ViewResponse {
            view_position: &[vec![]],
            outcome: cw::Outcome::Approve,
            confirming_parties: &confirming,
        }],
        &r.signing_key,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        &token,
        sw::signed_submission_request(
            sw::submission_request_signed(
                &r.member(),
                &unique("resp"),
                &[(vec![cw::mediator_group(0)], content, signatures)],
                request_id + 30_000_000,
            ),
            &r.signing_key,
        ),
    )
    .expect("the sequencer accepts the responses");
    SampleCreated {
        instance: instance_bytes,
        id_hex,
        request_id,
    }
}

/// The keyed variant of `rust_creates_sample` (see U-21 in doc/slices/UNRESOLVED.md).
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn rust_creates_keyed_pact(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    erin: &str,
    tag: &str,
    wrong_resolved_key_hash: bool,
) -> SampleCreated {
    use canton_participant::contract_id as ci;
    use canton_participant::contract_wire::{authentication_data, ContractInstance, LfValue};
    use canton_participant::{
        confirmation_wire as cw, merkle_wire as mw, sequencing_wire as sw, view_message as vm,
    };
    let token = token.clone();
    let erin = erin.to_string();
    // `KeyedPact { a = erin, b = erin, c = alice, tag }`: the signatory is erin, who also maintains the key `(erin, tag)`
    let signatories: Vec<String> = vec![erin.clone()];
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let package_id = var("CANTON_RS_KEYED_PACKAGE");
    let p1_key = p1_encryption_key(c, r, &token);
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let uuid = fresh_uuid();
    let vpd_salt = fresh("vpd-salt");
    let salt = ci::contract_salt(&ci::SaltInputs {
        view_participant_data_salt: &vpd_salt,
        create_index: 0,
        view_position: &[vec![]],
        transaction_uuid: &uuid,
        synchronizer_id: &synchronizer,
        mediator: "MGR::0",
    });
    let hash_arg = ci::HashValue::Record {
        module: vec!["Keyed".into()],
        name: vec!["KeyedPact".into()],
        fields: vec![
            ("a".into(), ci::HashValue::Party(erin.clone())),
            ("b".into(), ci::HashValue::Party(erin.clone())),
            ("c".into(), ci::HashValue::Party(alice.clone())),
            ("tag".into(), ci::HashValue::Text(tag.into())),
        ],
    };
    let contract_hash = ci::lf_contract_hash(
        "keyed-vault",
        &["Keyed".into()],
        &["KeyedPact".into()],
        &hash_arg,
    );
    // the key `(a, tag)` of the template, a `Tuple2`, and its hash
    let key_hash_value = ci::HashValue::Record {
        module: vec!["DA".into(), "Types".into()],
        name: vec!["Tuple2".into()],
        fields: vec![
            ("_1".into(), ci::HashValue::Party(erin.clone())),
            ("_2".into(), ci::HashValue::Text(tag.into())),
        ],
    };
    let key_hash = ci::lf_contract_key_hash(
        "keyed-vault",
        &["Keyed".into()],
        &["KeyedPact".into()],
        &key_hash_value,
    );
    let stakeholders: Vec<String> = {
        let mut s = vec![erin.clone(), alice.clone()];
        s.sort();
        s.dedup();
        s
    };
    let unicum = ci::unicum(
        &salt,
        &ci::UnicumInputs {
            created_at_micros: now,
            signatories: &signatories,
            stakeholders: &stakeholders,
            key: Some(ci::KeyInputs {
                hash: &key_hash,
                maintainers: std::slice::from_ref(&erin),
            }),
            contract_hash: &contract_hash,
        },
    );
    let node_seed = fresh("node-seed");
    let discriminator = ci::derive_contract_discriminator(&node_seed, now, &stakeholders);
    let id_hex = ci::contract_id(&discriminator, &unicum);
    let key_value = LfValue::Record(vec![
        LfValue::Party(erin.clone()),
        LfValue::Text(tag.into()),
    ]);
    let instance = ContractInstance {
        contract_id: hex::decode(&id_hex).unwrap(),
        package_name: "keyed-vault".into(),
        package_id: package_id.clone(),
        module: vec!["Keyed".into()],
        name: vec!["KeyedPact".into()],
        arg: LfValue::Record(vec![
            LfValue::Party(erin.clone()),
            LfValue::Party(erin.clone()),
            LfValue::Party(alice.clone()),
            LfValue::Text(tag.into()),
        ]),
        signatories: signatories.iter().cloned().collect(),
        stakeholders: stakeholders.iter().cloned().collect(),
        created_at_micros: now,
        authentication_data: authentication_data(&salt),
        key: Some(canton_participant::contract_wire::ContractKey {
            value: key_value.clone(),
            maintainers: vec![erin.clone()],
            hash: key_hash,
        }),
    };
    let instance_bytes = instance.encode();
    // [CANTON-NOTE: SEMANTICS] the create view lists the key with its maintainers and no contract id (measured on p1's views)
    let resolved_key = {
        use canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers;
        use canton_proto::com::digitalasset::canton::protocol::v31::GlobalKey;
        use canton_proto::com::digitalasset::daml::lf::transaction::Versioned as LfVersioned;
        use canton_proto::com::digitalasset::daml::lf::value::Identifier;
        use prost::Message;
        KeyResolutionWithMaintainers {
            key: Some(GlobalKey {
                template_id: Identifier {
                    package_id: package_id.clone(),
                    module_name: vec!["Keyed".into()],
                    name: vec!["KeyedPact".into()],
                }
                .encode_to_vec(),
                key: LfVersioned {
                    version: "2".into(),
                    payload: key_value.encode(),
                }
                .encode_to_vec(),
                package_name: "keyed-vault".into(),
                // a view whose resolved key states a hash that is not the hash of its key
                hash: if wrong_resolved_key_hash {
                    vec![0; 32]
                } else {
                    key_hash.to_vec()
                },
            }),
            maintainers: vec![erin.clone()],
            contract_ids: vec![],
        }
    };
    let vpd = mw::view_participant_data_create_with_keys(
        &instance_bytes,
        &id_hex,
        &node_seed,
        &vpd_salt,
        vec![resolved_key],
    );
    let uid = r.member().trim_start_matches("PAR::").to_string();
    let common = mw::common_metadata(&synchronizer, 0, &fresh("cm"), &uuid);
    let participant = mw::participant_metadata(now, now, None, &fresh("pm"));
    let submitter = mw::submitter_metadata(
        &mw::SubmitterInfo {
            act_as: signatories.iter().map(String::as_str).collect(),
            user_id: "rust-user",
            command_id: &unique("cmd"),
            submitting_participant_uid: &uid,
            submission_id: None,
            dedup_duration: (300, 0),
            max_sequencing_time_micros: now + 60_000_000,
        },
        &fresh("sm"),
    );
    // [CANTON-NOTE: SEMANTICS] The informees of a root view are the stakeholders **plus the submitting participant's admin party**
    // (the party named by the participant's uid), which must confirm too: the quorum is {signatory: 1, admin party: 1} with
    // threshold 2. p1 reconstructs the view and compares it hash for hash, so this is not optional. Informees and confirmers are
    // sorted by party id.
    let admin = r.uid();
    let mut informees = stakeholders.clone();
    informees.push(admin.clone());
    informees.sort();
    informees.dedup();
    let informee_refs: Vec<&str> = informees.iter().map(String::as_str).collect();
    let mut confirmers: Vec<(&str, i32)> = signatories.iter().map(|s| (s.as_str(), 1)).collect();
    confirmers.push((admin.as_str(), 1));
    confirmers.sort();
    let threshold = confirmers.len() as i32;
    let vcd = mw::view_common_data(
        &informee_refs,
        &[mw::QuorumSpec {
            confirmers,
            threshold,
        }],
        &fresh("vcd"),
    );
    let view = |participant_data: &mw::Tree| {
        mw::view_node(
            &mw::Tree::leaf(&vcd),
            participant_data,
            &mw::merkle_seq(&[]),
        )
    };
    let full_view = view(&mw::Tree::leaf(&vpd));
    let full = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::leaf(&participant),
        &mw::merkle_seq(std::slice::from_ref(&full_view)),
    );
    let informee = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::blinded(participant.root_hash()),
        &mw::merkle_seq(&[view(&mw::Tree::blinded(vpd.root_hash()))]),
    );
    assert_eq!(full.root_hash, informee.root_hash);
    let encrypted = vm::encrypted_view_message(
        &vm::light_view_tree(&full),
        &full_view.hash,
        &fresh("randomness")[..16].try_into().unwrap(),
        &fresh("gcm-iv")[..12].try_into().unwrap(),
        &[
            vm::Recipient {
                encryption_spki: &p1_key,
                fingerprint: &var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
                ecies_iv: fresh("ecies-iv")[..16].try_into().unwrap(),
                ecies_ephemeral_scalar: fresh("ecies-eph"),
            },
            vm::Recipient {
                encryption_spki: r.encryption_spki(),
                fingerprint: &r.encryption_fingerprint(),
                ecies_iv: fresh("ecies-iv2")[..16].try_into().unwrap(),
                ecies_ephemeral_scalar: fresh("ecies-eph2"),
            },
        ],
        &synchronizer,
        r.signing_key.sign_bytes(&full.root_hash),
    );
    let mediator = cw::mediator_group(0);
    // the root hash message goes to the mediator and every participant hosting an informee: p1 (alice) and this one (erin)
    let request_message_id = unique("keyed");
    let request = sw::submission_request_to_groups(
        &r.member(),
        &request_message_id,
        &[
            (
                vec![mediator.clone()],
                cw::informee_message(&informee, &r.signing_key),
            ),
            (
                vec![mediator.clone(), var("CANTON_RS_MEMBER_P1")],
                cw::root_hash_message(&full.root_hash, &synchronizer, now),
            ),
            (
                vec![mediator, r.member()],
                cw::root_hash_message(&full.root_hash, &synchronizer, now),
            ),
            // every informee participant must be among the recipients of the encrypted view
            (vec![var("CANTON_RS_MEMBER_P1"), r.member()], encrypted),
        ],
        now + 60_000_000,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        &token,
        sw::signed_submission_request(request, &r.signing_key),
    )
    .expect("the sequencer accepts the request");
    // the sequencing time of our own submission is the request id; answer the request as the participant that hosts erin and
    // is the submitting participant (whose admin party confirms too)
    let mut from = now + 1;
    let request_id = loop {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(from),
                1,
                std::time::Duration::from_secs(10),
            )
            .expect("subscribe");
        let d = sw::decode_delivered(events.first().expect("our request comes back")).unwrap();
        from = d.timestamp_micros + 1;
        if d.message_id.as_deref() == Some(request_message_id.as_str()) {
            break d.timestamp_micros;
        }
    };
    // when p1 hosts the signatory too, p1 confirms it (after validating); this participant then answers for its admin party only
    let mut confirming = vec![admin];
    confirming.sort();
    let (content, signatures) = cw::confirmation_responses(
        request_id,
        &full.root_hash,
        &synchronizer,
        &r.member(),
        &[cw::ViewResponse {
            view_position: &[vec![]],
            outcome: cw::Outcome::Approve,
            confirming_parties: &confirming,
        }],
        &r.signing_key,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        &token,
        sw::signed_submission_request(
            sw::submission_request_signed(
                &r.member(),
                &unique("resp"),
                &[(vec![cw::mediator_group(0)], content, signatures)],
                request_id + 30_000_000,
            ),
            &r.signing_key,
        ),
    )
    .expect("the sequencer accepts the responses");
    SampleCreated {
        instance: instance_bytes,
        id_hex,
        request_id,
    }
}

/// U-21 (Rust submits): this participant creates a keyed contract (`KeyedPact`, signatory and key maintainer `erin`, a consortium party p1
/// co-hosts, observer alice hosted by p1) with the key in the instance, in the Unicum and in the view's `resolved_keys`. p1 validates the
/// view with its own engine and the mediator approves.
#[test]
fn p1_validates_a_keyed_pact_that_rust_created_and_the_mediator_approves_it() {
    let (r, mut c, token) = authenticated(&unique("r-kcreate"));
    // this participant submits, so it hosts erin with submission permission and p1 co-hosts and confirms (not the consortium
    // arrangement of the other keyed tests, where p1 submits and this participant only confirms)
    let erin = host_party_and_vet(
        &r,
        &mut c,
        &token,
        "erin",
        true,
        &var("CANTON_RS_KEYED_PACKAGE"),
    );
    rust_creates_keyed_pact(&r, &mut c, &token, &erin, "created-by-rust", false);
    let member = r.member();
    let time = request_time_of(&member);
    let lines = p1_lines_of_request(&time);
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    // p1 co-hosts erin, so it confirms after validating: its answer is `approved=1, rejected=0` (not "nothing to approve")
    assert!(has("approved=1, rejected=0"), "{}", lines.join("\n"));
    assert!(!has("LOCAL_VERDICT_FAILED"), "{}", lines.join("\n"));
    assert!(!has("LOCAL_VERDICT_MALFORMED"), "{}", lines.join("\n"));
    assert!(
        !lines.iter().any(|l| l.contains("WARN")),
        "{}",
        lines.join("\n")
    );
    let finalized = finalized_line_of(&member);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

/// Negative control: the same keyed create whose `resolved_keys` entry states a wrong key hash. p1 rejects it, so the mediator does not approve.
#[test]
fn p1_rejects_a_keyed_pact_whose_resolved_key_states_a_wrong_hash() {
    let (r, mut c, token) = authenticated(&unique("r-kcreate-bad"));
    let erin = host_party_and_vet(
        &r,
        &mut c,
        &token,
        "erin",
        true,
        &var("CANTON_RS_KEYED_PACKAGE"),
    );
    rust_creates_keyed_pact(&r, &mut c, &token, &erin, "wrong-hash", true);
    let member = r.member();
    let time = request_time_of(&member);
    let lines = p1_lines_of_request(&time);
    assert!(
        lines.iter().any(|l| l.contains("LOCAL_VERDICT_")),
        "p1 rejected the request: {}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("approved=1, rejected=0")),
        "{}",
        lines.join("\n")
    );
    let finalized = finalized_line_of(&member);
    assert!(!finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn p1_validates_a_sample_asset_holding_that_rust_created_and_the_mediator_approves_it() {
    let member = send_sample_create_to_p1(&unique("r-asset"), "100.0", false, false);
    let time = request_time_of(&member);
    let lines = p1_lines_of_request(&time);
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    // p1 decrypted the view, replayed the create in its engine (package, vetting, ensure clause, signatories), rebuilt the view
    // hash for hash, and has nothing to confirm: it hosts only the observer
    assert!(
        has("Finished validation for request") && has("with nothing to approve"),
        "{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("WARN")),
        "{}",
        lines.join("\n")
    );
    // the participant that hosts the signatory confirmed: the mediator's verdict
    let finalized = finalized_line_of(&member);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn p1_rejects_a_sample_asset_holding_whose_view_does_not_match_what_its_engine_computes() {
    let member = send_sample_create_to_p1(&unique("r-asset-bad"), "100.0", true, false);
    let time = request_time_of(&member);
    let lines = p1_lines_of_request(&time);
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    assert!(
        has("LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK"),
        "{}",
        lines.join("\n")
    );
    // (the detail, "Reconstructed view differs from received view", is on continuation lines that carry no trace id)
    assert!(has("ViewReconstructionError"), "{}", lines.join("\n"));
    assert!(!has("with nothing to approve"), "{}", lines.join("\n"));
    // [CANTON-NOTE: SEMANTICS] The mediator still approves: p1 only observes, so its rejection confirms or refuses no party, and
    // the verdict follows the confirming parties alone (here the participant that hosts the signatory and approves). A
    // rejection from a participant with nothing to confirm cannot veto a transaction.
    let finalized = finalized_line_of(&member);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn a_party_hosted_by_the_rust_participant_and_p1_needs_both_signatures_and_gets_them() {
    use canton_participant::topology_wire as tw;
    let (r, mut c, token) = authenticated(&unique("r-shared"));
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let proposal = r.shared_party_proposal("frank", &p1_uid);
    let hash = tx_hash_in_log(&proposal.transaction);
    broadcast(&r, &mut c, &token, std::slice::from_ref(&proposal));
    // alone, the proposal is stored as a proposal and the party is not hosted by p1 yet: nothing for p1 to do but wait
    log_line_with(&[
        "participant=p1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{hash}"),
    ])
    .expect("p1 stores the proposal");
    have_p1_authorize(&tw::transaction_hash(&proposal.transaction));
    let authorized = log_line_with(&[&format!(
        "SCF authorized={}",
        hex::encode(tw::transaction_hash(&proposal.transaction))
    )]);
    assert!(
        authorized.is_some(),
        "p1 did not co-sign: {}",
        node_log()
            .lines()
            .filter(|l| l.contains("SCF authorize"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    // the fully authorized transaction carries both namespaces' signatures
    let p1_ns = &p1_uid.split("::").nth(1).unwrap()[..12];
    let both = log_line_with(&[
        "sequencer=s1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{hash}"),
        &r.namespace()[..12],
        p1_ns,
    ]);
    assert!(
        both.is_some(),
        "the synchronizer never stored the transaction signed by both namespaces"
    );
}

#[test]
fn p1_confirms_an_asset_holding_whose_signatory_it_hosts_together_with_the_rust_participant() {
    let member = send_sample_create_to_p1(&unique("r-p1sign"), "100.0", false, true);
    let time = request_time_of(&member);
    let lines = p1_lines_of_request(&time);
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    // p1 hosts the signatory with confirmation permission, so it has something to approve and approves it
    assert!(
        !lines.iter().any(|l| l.contains("WARN")),
        "{}",
        lines.join("\n")
    );
    assert!(
        has("Phase 4: Sending for request") && has("approved=1, rejected=0"),
        "{}",
        lines.join("\n")
    );
    // the verdict needs p1's approval for the signatory (this participant answered for its admin party only)
    let finalized = finalized_line_of(&member);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn p1_rejects_what_does_not_match_its_engine_and_the_mediator_follows_when_p1_confirms_the_signatory(
) {
    let member = send_sample_create_to_p1(&unique("r-p1sign-bad"), "100.0", true, true);
    let time = request_time_of(&member);
    let lines = p1_lines_of_request(&time);
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    assert!(
        has("LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK"),
        "{}",
        lines.join("\n")
    );
    assert!(has("approved=0, rejected=1"), "{}", lines.join("\n"));
    // unlike an observer's rejection, the rejection of the participant that confirms the signatory decides the verdict
    let finalized = finalized_line_of(&member);
    assert!(!finalized.contains("with verdict Approve"), "{finalized}");
}

/// Makes `erin` a party hosted by the Rust participant (confirmation) and p1 (submission), threshold 1,
/// and has the Rust participant vet the sample package. Returns the party.
fn host_consortium_party(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    name: &str,
) -> String {
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let proposal = r.shared_party_proposal_with(name, &p1_uid, 2, 1, 1);
    let vetting = r.vetting_transaction(&[var("CANTON_RS_SAMPLE_PACKAGE")]);
    let hashes = [
        tx_hash_in_log(&proposal.transaction),
        tx_hash_in_log(&vetting.transaction),
    ];
    let proposal_hash = canton_participant::topology_wire::transaction_hash(&proposal.transaction);
    broadcast(r, c, token, &[proposal, vetting]);
    for hash in &hashes {
        log_line_with(&[
            "participant=p1",
            "Storing topology transaction",
            &format!("TxHash(SHA-256:{hash}"),
        ])
        .expect("p1 stores the transaction");
    }
    have_p1_authorize(&proposal_hash);
    let p1_ns = p1_uid.split("::").nth(1).unwrap()[..12].to_string();
    log_line_with(&[
        "sequencer=s1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{}", hashes[0]),
        &r.namespace()[..12],
        &p1_ns,
    ])
    .expect("the synchronizer stores the party signed by both participants");
    std::thread::sleep(std::time::Duration::from_secs(2));
    r.party_id(name)
}

/// Has p1 submit a create of the sample template (bank alice, owner `owner`, auditor alice) and returns the events the
/// Rust participant receives for it: everything delivered to it after `from`, until `count` events or the time is up.
fn p1_submits_and_rust_receives(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    owner: &str,
    amount: &str,
) -> Vec<canton_participant::sequencing_wire::Delivered> {
    use canton_participant::sequencing_wire as sw;
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let from = c
        .sequencer_time(&r.member(), &synchronizer, Some(token))
        .unwrap()
        .unwrap()
        + 1;
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let name = format!("{}.submit", unique("submit"));
    std::fs::write(
        dir.join(format!("{name}.tmp")),
        format!("{alice},{owner},{alice},{amount}"),
    )
    .unwrap();
    std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
    let mut out = Vec::new();
    let mut at = from;
    // time-bounded, not event-bounded: other tests' broadcasts reach every member and would use up a count of iterations
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < patience {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                token,
                Some(at),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default(); // a wait that ends without an event is an error of the stream
        let Some(event) = events.first() else {
            continue;
        };
        let d = sw::decode_delivered(event).expect("every event decodes");
        at = d.timestamp_micros + 1;
        // other tests' topology broadcasts reach every member too: only an encrypted view this participant can read counts
        let has_view = d.envelopes.iter().any(|e| {
            canton_participant::view_receive::decrypt_views(
                e,
                &r.encryption_fingerprint(),
                r.encryption_secret(),
            )
            .is_ok()
        });
        out.push(d);
        if has_view {
            break;
        }
    }
    out
}

/// Verifies a protocol signature over `message` with any of `keys`.
fn verifies_with_any(
    keys: &[SigningKey],
    signature: &canton_proto::com::digitalasset::canton::crypto::v30::Signature,
    message: &[u8],
) -> bool {
    canton_algo::member_signature::verify_by_keys(
        keys,
        message,
        signature,
        &canton_algo::member_signature::protocol_only(),
    )
    .is_ok()
}

/// A microsecond timestamp as the node's log writes it (`2026-11-11T07:32:22.511322Z`).
fn iso_micros(micros: i64) -> String {
    let (secs, frac) = (micros.div_euclid(1_000_000), micros.rem_euclid(1_000_000));
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // civil date from days since the epoch (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    // [CANTON-NOTE: WHY] as Java's `Instant.toString` (what the node logs): the fraction in groups of three digits, as many as needed, and
    // none when it is zero. A fixed six digits missed the node's line about one time in a thousand (a time whose microseconds end in 000).
    let fraction = if frac == 0 {
        String::new()
    } else if frac % 1000 == 0 {
        format!(".{:03}", frac / 1000)
    } else {
        format!(".{frac:06}")
    };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{fraction}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// What a request that p1 submits gives the Rust participant: it hosts `erin` with p1, receives the encrypted view, and has
/// everything needed to check it.
struct Received {
    identity: canton_participant::topology_wire::ParticipantIdentity,
    connection: SequencerConnect,
    token: canton_participant::sequencer_connect::Token,
    event: canton_participant::sequencing_wire::Delivered,
    /// The envelope content of the encrypted view message, and the root hash the event announced.
    view_envelope: Vec<u8>,
    announced_root_hash: Vec<u8>,
    p1_signing_keys: Vec<SigningKey>,
    party: String,
}

fn rust_receives_a_view_from_p1(name: &str) -> Received {
    use canton_participant::view_receive as vr;
    let (r, mut c, token) = authenticated(name);
    let erin = host_consortium_party(&r, &mut c, &token, "erin");
    let keys = p1_signing_keys(&mut c, &r, &token);
    let events = p1_submits_and_rust_receives(&r, &mut c, &token, &erin, "100.0");
    let event = events.last().expect("an event with the view").clone();
    let announced = event
        .envelopes
        .iter()
        .find_map(|e| vr::root_hash_of_message(e))
        .expect("a root hash message");
    let view_envelope = event
        .envelopes
        .iter()
        .find(|e| vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret()).is_ok())
        .expect("an encrypted view message this participant can read")
        .clone();
    Received {
        identity: r,
        connection: c,
        token,
        event,
        view_envelope,
        announced_root_hash: announced,
        p1_signing_keys: keys,
        party: erin,
    }
}

#[test]
fn the_rust_participant_decrypts_checks_and_confirms_a_view_that_p1_submitted() {
    use canton_participant::{confirmation_wire as cw, sequencing_wire as sw, view_receive as vr};
    let mut got = rust_receives_a_view_from_p1(&unique("r-recv"));
    let r = &got.identity;
    let views = vr::decrypt_views(
        &got.view_envelope,
        &r.encryption_fingerprint(),
        r.encryption_secret(),
    )
    .expect("the view decrypts with this participant's key");
    let revealed = vr::check_views(&views, &got.announced_root_hash, |sig, root| {
        verifies_with_any(&got.p1_signing_keys, sig, root)
    })
    .expect("the hashes and the signature check out");
    assert_eq!(revealed.len(), 1);
    let view = &revealed[0];
    // the party this participant hosts is among the informees, and the view is the one root view
    assert!(view.common_data.informees.contains(&got.party));
    // the engine of this participant replays the create: ensure, signatories, observers, contract salt and contract id
    let engine = canton_participant::view_conformance::Engine::load(std::path::Path::new(&var(
        "CANTON_RS_SAMPLE_DAR",
    )))
    .expect("the DAR loads");
    let common = vr::revealed_common_metadata(views.view_trees[0].tree.as_ref().unwrap()).unwrap();
    let conforming = canton_participant::view_conformance::check_view(&engine, view, &common)
        .expect("the contract p1 created is one this participant's engine produces too");
    assert_eq!(conforming.len(), 1);
    assert_eq!(conforming[0].template, "AssetHolding:AssetHolding");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let (content, signatures) = cw::confirmation_responses(
        got.event.timestamp_micros,
        &got.announced_root_hash,
        &synchronizer,
        &r.member(),
        &[cw::ViewResponse {
            view_position: &view.position,
            outcome: cw::Outcome::Approve,
            confirming_parties: std::slice::from_ref(&got.party),
        }],
        &r.signing_key,
    );
    let now = got
        .connection
        .sequencer_time(&r.member(), &synchronizer, Some(&got.token))
        .unwrap()
        .unwrap();
    got.connection
        .send_async(
            &r.member(),
            &synchronizer,
            &got.token,
            sw::signed_submission_request(
                sw::submission_request_signed(
                    &r.member(),
                    &unique("resp"),
                    &[(vec![cw::mediator_group(0)], content, signatures)],
                    now + 30_000_000,
                ),
                &r.signing_key,
            ),
        )
        .expect("the sequencer accepts the response");
    // the verdict of *this* request: the mediator finalizes the request p1 submitted with Approve
    let request = iso_micros(got.event.timestamp_micros);
    let finalized = log_line_with(&[
        "mediator=m1",
        "Phase 6: Finalized request",
        &format!("RequestId({request})"),
    ])
    .expect("the mediator finalizes the request p1 submitted");
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
    // the mediator logs a response from p1 and one from this participant (the second may arrive after the verdict)
    std::thread::sleep(std::time::Duration::from_secs(2));
    let responses = node_log()
        .lines()
        .filter(|l| {
            l.contains("mediator=m1")
                && l.contains("Phase 5: Received")
                && l.contains(&format!("request={request}"))
        })
        .count();
    assert!(
        responses >= 2,
        "the mediator logged {responses} response(s) for {request}"
    );
}

#[test]
fn the_rust_participant_refuses_a_received_view_that_does_not_check_out() {
    use canton_participant::view_receive as vr;
    let got = rust_receives_a_view_from_p1(&unique("r-recv-bad"));
    let r = &got.identity;
    let (fp, secret) = (r.encryption_fingerprint(), *r.encryption_secret());
    let views = vr::decrypt_views(&got.view_envelope, &fp, &secret).unwrap();
    let good_signature = |sig: &canton_proto::com::digitalasset::canton::crypto::v30::Signature,
                          root: &[u8]| {
        verifies_with_any(&got.p1_signing_keys, sig, root)
    };
    assert!(vr::check_views(&views, &got.announced_root_hash, good_signature).is_ok());
    // a root hash message that announces another tree
    let mut other = got.announced_root_hash.clone();
    *other.last_mut().unwrap() ^= 1;
    assert!(matches!(
        vr::check_views(&views, &other, good_signature),
        Err(vr::ReceiveError::HashMismatch(_))
    ));
    // a signature that is not from the submitting participant
    let stranger = [canton_algo::member_signature::own_ed25519_key(
        &canton_participant::topology_wire::Ed25519Key::from_seed([7; 32]).spki_der,
    )
    .unwrap()];
    assert_eq!(
        vr::check_views(&views, &got.announced_root_hash, |sig, root| {
            verifies_with_any(&stranger, sig, root)
        })
        .unwrap_err(),
        vr::ReceiveError::BadSignature
    );
    // a key this participant does not have a session key entry for
    assert_eq!(
        vr::decrypt_views(&got.view_envelope, "1220not-our-fingerprint", &secret).unwrap_err(),
        vr::ReceiveError::NoSessionKeyForThisParticipant
    );
    // a private key that is not ours
    assert_eq!(
        vr::decrypt_views(&got.view_envelope, &fp, &[9u8; 32]).unwrap_err(),
        vr::ReceiveError::SessionKeyDoesNotDecrypt
    );
    // a ciphertext that was changed on the way: re-encode the message with a flipped bit in the encrypted views
    let tampered = {
        use canton_proto::com::digitalasset::canton::protocol::v32::{
            envelope_content::SomeEnvelopeContent, EnvelopeContent,
        };
        use prost::Message;
        let (inner, _) =
            canton_participant::topology_wire::unversioned(&got.view_envelope).unwrap();
        let mut content = EnvelopeContent::decode(inner.as_slice()).unwrap();
        let Some(SomeEnvelopeContent::EncryptedMultipleViewsMessage(m)) =
            &mut content.some_envelope_content
        else {
            panic!("an encrypted view message")
        };
        let last = m.compressed_view_trees.len() - 1;
        m.compressed_view_trees[last] ^= 1;
        canton_participant::topology_wire::versioned(content.encode_to_vec(), 32)
    };
    assert_eq!(
        vr::decrypt_views(&tampered, &fp, &secret).unwrap_err(),
        vr::ReceiveError::ViewsDoNotDecrypt
    );
}

/// A copy of `view` whose created contract was changed by `change` (the contract instance and its decoded arguments).
fn with_changed_contract(
    view: &canton_participant::view_receive::RevealedView,
    change: impl FnOnce(
        &mut canton_proto::com::digitalasset::daml::lf::transaction::FatContractInstance,
        &mut Vec<canton_proto::com::digitalasset::daml::lf::value::Value>,
    ),
) -> canton_participant::view_receive::RevealedView {
    use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
    use canton_proto::com::digitalasset::daml::lf::value::{value::Sum, Value};
    use prost::Message;
    let mut changed = view.clone();
    let created = &mut changed.participant_data.created_core[0];
    let mut versioned = Versioned::decode(created.contract.as_slice()).unwrap();
    let mut fci = FatContractInstance::decode(versioned.payload.as_slice()).unwrap();
    let Some(Sum::Record(record)) = Value::decode(fci.create_arg.as_slice()).unwrap().sum else {
        panic!("a record argument")
    };
    let mut fields: Vec<Value> = record.fields.into_iter().filter_map(|f| f.value).collect();
    change(&mut fci, &mut fields);
    fci.create_arg = Value {
        sum: Some(Sum::Record(
            canton_proto::com::digitalasset::daml::lf::value::value::Record {
                fields: fields
                    .into_iter()
                    .map(|v| {
                        canton_proto::com::digitalasset::daml::lf::value::value::record::Field {
                            value: Some(v),
                        }
                    })
                    .collect(),
            },
        )),
    }
    .encode_to_vec();
    versioned.payload = fci.encode_to_vec();
    created.contract = versioned.encode_to_vec();
    changed
}

#[test]
fn the_rust_engine_refuses_a_contract_the_template_does_not_produce() {
    use canton_participant::view_conformance::{check_view, Engine, Nonconformance as N};
    use canton_participant::view_receive as vr;
    use canton_proto::com::digitalasset::daml::lf::value::{value::Sum, Value};
    let got = rust_receives_a_view_from_p1(&unique("r-engine"));
    let r = &got.identity;
    let views = vr::decrypt_views(
        &got.view_envelope,
        &r.encryption_fingerprint(),
        r.encryption_secret(),
    )
    .unwrap();
    let tree = views.view_trees[0].tree.as_ref().unwrap();
    let view = vr::revealed_root_views(tree).unwrap().remove(0);
    let common = vr::revealed_common_metadata(tree).unwrap();
    let engine = Engine::load(std::path::Path::new(&var("CANTON_RS_SAMPLE_DAR"))).unwrap();
    assert!(
        check_view(&engine, &view, &common).is_ok(),
        "the unchanged contract conforms"
    );
    let party = |v: &Value| match &v.sum {
        Some(Sum::Party(p)) => p.clone(),
        other => panic!("a party, found {other:?}"),
    };
    // `ensure amount > 0.0` (the amount is the fifth field)
    let zero = with_changed_contract(&view, |_, f| {
        f[4].sum = Some(Sum::Numeric("0.0000000000".into()))
    });
    assert_eq!(
        check_view(&engine, &zero, &common).unwrap_err(),
        N::EnsureFalse
    );
    // the signatories follow from the arguments: the owner as the bank leaves one signatory instead of two
    let other_bank = with_changed_contract(&view, |_, f| f[0].sum = Some(Sum::Party(party(&f[1]))));
    assert!(matches!(
        check_view(&engine, &other_bank, &common).unwrap_err(),
        N::SignatoriesDiffer { .. }
    ));
    // so do the observers: another auditor is another stakeholder
    let other_auditor = with_changed_contract(&view, |_, f| {
        f[2].sum = Some(Sum::Party(format!("zed::1220{}", "ee".repeat(32))))
    });
    assert!(matches!(
        check_view(&engine, &other_auditor, &common).unwrap_err(),
        N::StakeholdersDiffer { .. }
    ));
    // the contract id commits to the arguments: a changed symbol is not the contract the id was derived for
    let other_symbol =
        with_changed_contract(&view, |_, f| f[3].sum = Some(Sum::Text("EUR".into())));
    assert_eq!(
        check_view(&engine, &other_symbol, &common).unwrap_err(),
        N::ContractIdDiffers
    );
    // the contract salt commits to the view's position
    let mut elsewhere = view.clone();
    elsewhere.position = vec![vec![true]];
    assert_eq!(
        check_view(&engine, &elsewhere, &common).unwrap_err(),
        N::ContractSaltDiffers
    );
    // a package or a template this participant does not have
    let other_package = with_changed_contract(&view, |fci, _| {
        fci.template_id.as_mut().unwrap().package_id = "ab".repeat(32)
    });
    assert!(matches!(
        check_view(&engine, &other_package, &common).unwrap_err(),
        N::UnknownPackage(_)
    ));
    let other_template = with_changed_contract(&view, |fci, _| {
        fci.template_id.as_mut().unwrap().name = vec!["Nope".into()]
    });
    assert!(matches!(
        check_view(&engine, &other_template, &common).unwrap_err(),
        N::UnknownTemplate(_)
    ));
}

/// The two requests p1 makes for the sample contract `erin` is a stakeholder of — `create` and then `Settle` — as the Rust
/// participant receives them.
struct ReceivedExercise {
    identity: canton_participant::topology_wire::ParticipantIdentity,
    connection: SequencerConnect,
    token: canton_participant::sequencer_connect::Token,
    /// The event of the exercise: its envelopes hold the root hash message and the encrypted view.
    event: canton_participant::sequencing_wire::Delivered,
    view_envelope: Vec<u8>,
    announced_root_hash: Vec<u8>,
    p1_signing_keys: Vec<SigningKey>,
    party: String,
    contract_id: String,
}

fn rust_receives_an_exercise_from_p1(
    name: &str,
    choice: &str,
    actor_is_owner: bool,
    new_owner: Option<&str>,
) -> ReceivedExercise {
    // `new_owner` is the exercise's extra arguments after the choice, comma separated (`Transfer`: the new owner; `SplitTransfer`: the
    // amount and the recipient)
    use canton_participant::{sequencing_wire as sw, view_receive as vr};
    let (r, mut c, token) = authenticated(name);
    let erin = host_consortium_party(&r, &mut c, &token, "erin");
    let keys = p1_signing_keys(&mut c, &r, &token);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |extension: &str, content: String| {
        let name = format!("{}.{extension}", unique(extension));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let from = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap()
        + 1;
    // p1 creates the contract (bank alice, owner erin, auditor alice) and reports its id
    let created = command("submit", format!("{alice},{erin},{alice},100.0"));
    let line = log_line_with(&["SCF created=", &created]).expect("p1 creates the contract");
    let contract_id = line.rsplit('=').next().unwrap().trim().to_string();
    assert_ne!(contract_id, "?", "{line}");
    // then exercises `choice` on it as the bank
    let actor = if actor_is_owner {
        erin.clone()
    } else {
        alice.clone()
    };
    // `SplitTransfer` creates a holding owned by the recipient, who has to authorize it: the command acts as the recipient too
    let actor = match (choice, new_owner) {
        ("SplitTransfer", Some(args)) => format!("{actor}+{}", args.split(',').nth(1).unwrap()),
        _ => actor,
    };
    let extra = new_owner.map(|o| format!(",{o}")).unwrap_or_default();
    command("exercise", format!("{actor},{contract_id},{choice}{extra}"));
    // the Rust participant receives the views of both requests; the exercise is the last
    let readable = |d: &sw::Delivered| {
        d.envelopes.iter().any(|e| {
            vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret()).is_ok()
        })
    };
    let mut views = Vec::new();
    let mut at = from;
    // time-bounded, not event-bounded: other tests' broadcasts reach every member and would use up a count of iterations
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < patience {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(at),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default();
        let Some(event) = events.first() else {
            if views.len() >= 2 {
                break;
            }
            continue;
        };
        let d = sw::decode_delivered(event).expect("every event decodes");
        at = d.timestamp_micros + 1;
        if std::env::var("SEQ_TRACE").is_ok() {
            eprintln!(
                "event {}: {:?} {:?} {:?}",
                d.timestamp_micros,
                d.envelopes.iter().map(Vec::len).collect::<Vec<_>>(),
                d.recipients,
                d.envelopes
                    .iter()
                    .map(|e| vr::decrypt_views(
                        e,
                        &r.encryption_fingerprint(),
                        r.encryption_secret()
                    )
                    .err())
                    .collect::<Vec<_>>()
            );
        }
        if readable(&d) {
            views.push(d);
        }
        if views.len() >= 2 {
            break;
        }
    }
    if std::env::var("SEQ_DUMP_LOG").is_ok() {
        std::fs::write("/tmp/claude-501/node.log", node_log()).unwrap();
    }
    assert!(
        views.len() >= 2,
        "the Rust participant got {} view(s), not two\n{}",
        views.len(),
        node_log()
            .lines()
            .filter(|l| l.contains("SCF exercise_failed"))
            .map(|l| l.chars().take(600).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    );
    let event = views.pop().unwrap();
    let announced = event
        .envelopes
        .iter()
        .find_map(|e| vr::root_hash_of_message(e))
        .expect("a root hash message");
    let view_envelope = event
        .envelopes
        .iter()
        .find(|e| vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret()).is_ok())
        .unwrap()
        .clone();
    ReceivedExercise {
        identity: r,
        connection: c,
        token,
        event,
        view_envelope,
        announced_root_hash: announced,
        p1_signing_keys: keys,
        party: erin,
        contract_id,
    }
}

/// Sends the Rust participant's approval for `party` on the view at `position` of the request at `request_id`.
fn rust_approves(
    identity: &canton_participant::topology_wire::ParticipantIdentity,
    connection: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    request_id: i64,
    root_hash: &[u8],
    position: &[Vec<bool>],
    party: &str,
) {
    use canton_participant::{confirmation_wire as cw, sequencing_wire as sw};
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let (content, signatures) = cw::confirmation_responses(
        request_id,
        root_hash,
        &synchronizer,
        &identity.member(),
        &[cw::ViewResponse {
            view_position: position,
            outcome: cw::Outcome::Approve,
            confirming_parties: &[party.to_string()],
        }],
        &identity.signing_key,
    );
    let now = connection
        .sequencer_time(&identity.member(), &synchronizer, Some(token))
        .unwrap()
        .unwrap();
    connection
        .send_async(
            &identity.member(),
            &synchronizer,
            token,
            sw::signed_submission_request(
                sw::submission_request_signed(
                    &identity.member(),
                    &unique("resp"),
                    &[(vec![cw::mediator_group(0)], content, signatures)],
                    now + 30_000_000,
                ),
                &identity.signing_key,
            ),
        )
        .expect("the sequencer accepts the response");
}

#[test]
fn the_rust_participant_replays_an_exercise_p1_submitted_and_confirms_it() {
    use canton_participant::{view_conformance as vc, view_receive as vr};
    let mut got = rust_receives_an_exercise_from_p1(&unique("r-ex"), "Settle", false, None);
    let (fp, secret) = (
        got.identity.encryption_fingerprint(),
        *got.identity.encryption_secret(),
    );
    let views = vr::decrypt_views(&got.view_envelope, &fp, &secret).unwrap();
    let revealed = vr::check_views(&views, &got.announced_root_hash, |s, root| {
        verifies_with_any(&got.p1_signing_keys, s, root)
    })
    .expect("the hashes and the signature check out");
    let engine = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_SAMPLE_DAR"))).unwrap();
    let common = vr::revealed_common_metadata(views.view_trees[0].tree.as_ref().unwrap()).unwrap();
    let conforming = vc::check_exercise_view(&engine, &revealed[0], &common)
        .expect("the exercise p1 made is one this participant's engine reproduces");
    assert_eq!(
        conforming,
        vc::ConformingExercise {
            contract_id: got.contract_id.clone(),
            template: "AssetHolding:AssetHolding".into(),
            choice: "Settle".into(),
            consuming: true,
        }
    );
    rust_approves(
        &got.identity,
        &mut got.connection,
        &got.token,
        got.event.timestamp_micros,
        &got.announced_root_hash,
        &revealed[0].position,
        &got.party,
    );
    let request = iso_micros(got.event.timestamp_micros);
    let finalized = log_line_with(&[
        "mediator=m1",
        "Phase 6: Finalized request",
        &format!("RequestId({request})"),
    ])
    .expect("the mediator finalizes the exercise");
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

/// A copy of `view` whose input contract was changed by `change`.
fn with_changed_input(
    view: &canton_participant::view_receive::RevealedView,
    change: impl FnOnce(
        &mut canton_proto::com::digitalasset::daml::lf::transaction::FatContractInstance,
        &mut Vec<canton_proto::com::digitalasset::daml::lf::value::Value>,
    ),
) -> canton_participant::view_receive::RevealedView {
    use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
    use canton_proto::com::digitalasset::daml::lf::value::{value::Sum, Value};
    use prost::Message;
    let mut changed = view.clone();
    let input = &mut changed.participant_data.core_inputs[0];
    let mut versioned = Versioned::decode(input.contract.as_slice()).unwrap();
    let mut fci = FatContractInstance::decode(versioned.payload.as_slice()).unwrap();
    let Some(Sum::Record(record)) = Value::decode(fci.create_arg.as_slice()).unwrap().sum else {
        panic!("a record argument")
    };
    let mut fields: Vec<Value> = record.fields.into_iter().filter_map(|f| f.value).collect();
    change(&mut fci, &mut fields);
    fci.create_arg = Value {
        sum: Some(Sum::Record(
            canton_proto::com::digitalasset::daml::lf::value::value::Record {
                fields: fields
                    .into_iter()
                    .map(|v| {
                        canton_proto::com::digitalasset::daml::lf::value::value::record::Field {
                            value: Some(v),
                        }
                    })
                    .collect(),
            },
        )),
    }
    .encode_to_vec();
    versioned.payload = fci.encode_to_vec();
    input.contract = versioned.encode_to_vec();
    changed
}

/// The exercise a view's action describes, for a test to change.
fn exercise_of(
    v: &mut canton_participant::view_receive::RevealedView,
) -> &mut canton_proto::com::digitalasset::canton::protocol::v30::action_description::ExerciseActionDescription{
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    match v
        .participant_data
        .action_description
        .as_mut()
        .and_then(|a| a.description.as_mut())
    {
        Some(Description::Exercise(e)) => e,
        _ => panic!("an exercise"),
    }
}

#[test]
fn the_rust_engine_refuses_an_exercise_the_template_does_not_allow() {
    use canton_participant::view_conformance::{check_exercise_view, Engine, Nonconformance as N};
    use canton_participant::view_receive as vr;
    use canton_proto::com::digitalasset::daml::lf::value::value::Sum;
    let got = rust_receives_an_exercise_from_p1(&unique("r-ex-bad"), "Settle", false, None);
    let (fp, secret) = (
        got.identity.encryption_fingerprint(),
        *got.identity.encryption_secret(),
    );
    let views = vr::decrypt_views(&got.view_envelope, &fp, &secret).unwrap();
    let view = vr::revealed_root_views(views.view_trees[0].tree.as_ref().unwrap())
        .unwrap()
        .remove(0);
    let common = vr::revealed_common_metadata(views.view_trees[0].tree.as_ref().unwrap()).unwrap();
    let engine = Engine::load(std::path::Path::new(&var("CANTON_RS_SAMPLE_DAR"))).unwrap();
    assert!(
        check_exercise_view(&engine, &view, &common).is_ok(),
        "the unchanged exercise conforms"
    );
    // a choice the template does not have
    let mut v = view.clone();
    exercise_of(&mut v).choice = "Nope".into();
    assert!(matches!(
        check_exercise_view(&engine, &v, &common).unwrap_err(),
        N::UnknownChoice(_)
    ));
    // actors that are not the choice's controllers (the owner instead of the bank)
    let mut v = view.clone();
    let owner = got.party.clone();
    exercise_of(&mut v).actors = vec![owner];
    assert!(matches!(
        check_exercise_view(&engine, &v, &common).unwrap_err(),
        N::ActorsDiffer { .. }
    ));
    // a consuming choice whose input the view says is not consumed
    let mut v = view.clone();
    v.participant_data.core_inputs[0].consumed = false;
    assert!(matches!(
        check_exercise_view(&engine, &v, &common).unwrap_err(),
        N::ActionDiffers(_)
    ));
    // no input contract at all
    let mut v = view.clone();
    v.participant_data.core_inputs.clear();
    assert!(matches!(
        check_exercise_view(&engine, &v, &common).unwrap_err(),
        N::Malformed(_)
    ));
    // a failed exercise is not replayed here
    let mut v = view.clone();
    exercise_of(&mut v).failed = true;
    assert!(matches!(
        check_exercise_view(&engine, &v, &common).unwrap_err(),
        N::Unsupported(_)
    ));
    // the exercise names another template than the contract is
    let mut v = view.clone();
    exercise_of(&mut v).template_id = "ab".repeat(32) + ":AssetHolding:AssetHolding";
    // [CANTON-NOTE: TEST] since smart contract upgrade (S-SPL-033) an exercise may name another package of the same package name, so a package the
    // engine does not know is refused as `UnknownPackage`; `ActionDiffers` is for a known package of another name or another template
    assert!(matches!(
        check_exercise_view(&engine, &v, &common).unwrap_err(),
        N::UnknownPackage(_)
    ));
    // an informee is missing: the owner is a stakeholder of the contract
    let mut v = view.clone();
    v.common_data.informees.retain(|i| i != &got.party);
    assert!(matches!(
        check_exercise_view(&engine, &v, &common).unwrap_err(),
        N::ActionDiffers(_)
    ));
    // the input contract is not the one its id was derived for
    let changed = with_changed_input(&view, |_, f| f[3].sum = Some(Sum::Text("EUR".into())));
    assert_eq!(
        check_exercise_view(&engine, &changed, &common).unwrap_err(),
        N::ContractIdDiffers
    );
    // the input contract's `ensure` does not hold
    let zero = with_changed_input(&view, |_, f| {
        f[4].sum = Some(Sum::Numeric("0.0000000000".into()))
    });
    assert_eq!(
        check_exercise_view(&engine, &zero, &common).unwrap_err(),
        N::EnsureFalse
    );
}

#[test]
fn the_rust_participant_replays_a_transfer_that_creates_a_contract_and_confirms_it() {
    use canton_participant::{view_conformance as vc, view_receive as vr};
    // `Transfer` is controlled by the owner (erin): p1 acts as erin, and hands the holding to alice
    let alice = var("CANTON_RS_ALICE");
    let mut got =
        rust_receives_an_exercise_from_p1(&unique("r-xfer"), "Transfer", true, Some(&alice));
    let (fp, secret) = (
        got.identity.encryption_fingerprint(),
        *got.identity.encryption_secret(),
    );
    let views = vr::decrypt_views(&got.view_envelope, &fp, &secret).unwrap();
    let revealed = vr::check_views(&views, &got.announced_root_hash, |s, root| {
        verifies_with_any(&got.p1_signing_keys, s, root)
    })
    .expect("the hashes and the signature check out");
    let view = &revealed[0];
    // the exercise consumes the holding and creates the new one in the core of the same view
    assert_eq!(view.participant_data.core_inputs.len(), 1);
    assert_eq!(view.participant_data.created_core.len(), 1);
    let common = vr::revealed_common_metadata(views.view_trees[0].tree.as_ref().unwrap()).unwrap();
    let engine = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_SAMPLE_DAR"))).unwrap();
    let conforming = vc::check_exercise_view(&engine, view, &common)
        .expect("the transfer p1 made is one this participant's engine reproduces, created contract included");
    assert_eq!(conforming.choice, "Transfer");
    assert!(conforming.consuming);
    // the contract the transfer created is not the contract it consumed
    let created =
        vc::check_view(&engine, view, &common).expect("the created contract is authentic");
    assert_eq!(created.len(), 1);
    assert_ne!(created[0].contract_id, got.contract_id);
    rust_approves(
        &got.identity,
        &mut got.connection,
        &got.token,
        got.event.timestamp_micros,
        &got.announced_root_hash,
        &view.position,
        &got.party,
    );
    let request = iso_micros(got.event.timestamp_micros);
    let finalized = log_line_with(&[
        "mediator=m1",
        "Phase 6: Finalized request",
        &format!("RequestId({request})"),
    ])
    .expect("the mediator finalizes the transfer");
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn the_rust_engine_refuses_a_transfer_whose_created_contract_is_not_what_the_engine_makes() {
    use canton_participant::view_conformance::{check_exercise_view, Engine, Nonconformance as N};
    use canton_participant::view_receive as vr;
    let alice = var("CANTON_RS_ALICE");
    let got =
        rust_receives_an_exercise_from_p1(&unique("r-xfer-bad"), "Transfer", true, Some(&alice));
    let (fp, secret) = (
        got.identity.encryption_fingerprint(),
        *got.identity.encryption_secret(),
    );
    let views = vr::decrypt_views(&got.view_envelope, &fp, &secret).unwrap();
    let view = vr::revealed_root_views(views.view_trees[0].tree.as_ref().unwrap())
        .unwrap()
        .remove(0);
    let common = vr::revealed_common_metadata(views.view_trees[0].tree.as_ref().unwrap()).unwrap();
    let engine = Engine::load(std::path::Path::new(&var("CANTON_RS_SAMPLE_DAR"))).unwrap();
    assert!(check_exercise_view(&engine, &view, &common).is_ok());
    // the view omits the contract the engine creates
    let mut without = view.clone();
    without.participant_data.created_core.clear();
    assert!(matches!(
        check_exercise_view(&engine, &without, &common).unwrap_err(),
        N::ActionDiffers(_)
    ));
    // the view lists a contract the engine does not create: the same holding for another owner
    let other_owner = with_changed_contract(&view, |_, f| {
        use canton_proto::com::digitalasset::daml::lf::value::value::Sum;
        f[1].sum = Some(Sum::Party(format!("zed::1220{}", "ee".repeat(32))));
    });
    // (its signatories now differ from what the arguments give only if the stated ones are not updated: they are the old ones)
    assert!(check_exercise_view(&engine, &other_owner, &common).is_err());
    // a contract id that was not derived from this view: the exercise view at another position
    let mut elsewhere = view.clone();
    elsewhere.position = vec![vec![true]];
    assert_eq!(
        check_exercise_view(&engine, &elsewhere, &common).unwrap_err(),
        N::ContractSaltDiffers
    );
}

/// What the Rust participant receives for a `Notify` on an `Inbox` of p1's alice that names erin (hosted by the Rust participant)
/// as the peer: the `Note` is created in a subview that only erin's participant (and p1) are informees of.
struct ReceivedNested {
    identity: canton_participant::topology_wire::ParticipantIdentity,
    event: canton_participant::sequencing_wire::Delivered,
    view_envelope: Vec<u8>,
    announced_root_hash: Vec<u8>,
    p1_signing_keys: Vec<SigningKey>,
    party: String,
}

fn rust_receives_a_subview_from_p1(name: &str, msg: &str) -> ReceivedNested {
    use canton_participant::{sequencing_wire as sw, view_receive as vr};
    let (r, mut c, token) = authenticated(name);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    // the Rust participant hosts erin alone and vets the fixture's package
    let hosting = r.party_hosting_transaction("erin");
    let vetting = r.vetting_transaction(&[var("CANTON_RS_NESTED_PACKAGE")]);
    let hashes = [
        tx_hash_in_log(&hosting.transaction),
        tx_hash_in_log(&vetting.transaction),
    ];
    broadcast(&r, &mut c, &token, &[hosting, vetting]);
    for hash in &hashes {
        log_line_with(&[
            "participant=p1",
            "Storing topology transaction",
            &format!("TxHash(SHA-256:{hash}"),
        ])
        .expect("p1 stores the transaction");
    }
    std::thread::sleep(std::time::Duration::from_secs(2));
    let erin = r.party_id("erin");
    let keys = p1_signing_keys(&mut c, &r, &token);
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |content: String| {
        let name = format!("{}.nested", unique("nested"));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let from = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap()
        + 1;
    let inbox = command(format!("inbox,{alice}"));
    let line = log_line_with(&["SCF nested_done=", &inbox]).expect("p1 creates the inbox");
    let inbox_id = line.rsplit('=').next().unwrap().trim().to_string();
    assert_ne!(inbox_id, "?", "{line}");
    command(format!("notify,{alice},{inbox_id},{erin},{msg}"));
    let mut found = None;
    let mut at = from;
    // time-bounded, not event-bounded: other tests' broadcasts reach every member and would use up a count of iterations
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < patience {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(at),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default();
        let Some(event) = events.first() else {
            continue;
        };
        let d = sw::decode_delivered(event).expect("every event decodes");
        at = d.timestamp_micros + 1;
        if d.envelopes.iter().any(|e| {
            vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret()).is_ok()
        }) {
            found = Some(d);
            break;
        }
    }
    if std::env::var("SEQ_DUMP_LOG").is_ok() {
        std::fs::write("/tmp/claude-501/node.log", node_log()).unwrap();
    }
    let event = found.unwrap_or_else(|| {
        panic!(
            "the Rust participant got no readable view\n{}",
            node_log()
                .lines()
                .filter(|l| l.contains("SCF nested_failed"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    });
    let announced = event
        .envelopes
        .iter()
        .find_map(|e| vr::root_hash_of_message(e))
        .expect("a root hash message");
    let view_envelope = event
        .envelopes
        .iter()
        .find(|e| vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret()).is_ok())
        .unwrap()
        .clone();
    ReceivedNested {
        identity: r,
        event,
        view_envelope,
        announced_root_hash: announced,
        p1_signing_keys: keys,
        party: erin,
    }
}

#[test]
fn the_rust_participant_validates_a_subview_it_is_an_informee_of_and_the_mediator_approves_the_request(
) {
    use canton_participant::{view_conformance as vc, view_receive as vr};
    let got = rust_receives_a_subview_from_p1(&unique("r-sub"), "hello");
    let r = &got.identity;
    let views = vr::decrypt_views(
        &got.view_envelope,
        &r.encryption_fingerprint(),
        r.encryption_secret(),
    )
    .unwrap();
    // the tree this participant gets has the views above the one it may read blinded; the hashes still add up to the announced root
    let revealed = vr::check_views(&views, &got.announced_root_hash, |s, root| {
        verifies_with_any(&got.p1_signing_keys, s, root)
    })
    .expect("the hashes (with the blinded views above) and the signature check out");
    assert_eq!(revealed.len(), 1, "one revealed view");
    let view = &revealed[0];
    // a subview of a root view: two levels of position, and it is the only view this participant is an informee of
    assert_eq!(view.position.len(), 2, "{:?}", view.position);
    assert!(view.common_data.informees.contains(&got.party));
    let engine = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_NESTED_DAR"))).unwrap();
    let common = vr::revealed_common_metadata(views.view_trees[0].tree.as_ref().unwrap()).unwrap();
    let conforming = vc::check_view(&engine, view, &common)
        .expect("the note created in the subview is one this participant's engine produces, with an id derived from the subview position");
    assert_eq!(conforming.len(), 1);
    assert_eq!(conforming[0].template, "Nested:Note");
    // erin is only an observer of the note: this participant has no party to confirm for and sends no response; the verdict of
    // the request is p1's
    let request = iso_micros(got.event.timestamp_micros);
    let finalized = log_line_with(&[
        "mediator=m1",
        "Phase 6: Finalized request",
        &format!("RequestId({request})"),
    ])
    .expect("the mediator finalizes the request p1 made");
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

/// What the Rust participant receives of a transaction with a view under a view (the chain fixture, three participants).
struct ReceivedChain {
    identity: canton_participant::topology_wire::ParticipantIdentity,
    event: canton_participant::sequencing_wire::Delivered,
    announced_root_hash: Vec<u8>,
    p1_signing_keys: Vec<SigningKey>,
    party: String,
}

/// p1 runs the chain fixture with its owner alice, `peer1` erin (hosted by the Rust participant alone) and `peer2` dave (hosted by p2): the
/// Rust participant is an informee of `Forward` and of the `Note` created under it. Returns the event that carries its views.
fn rust_receives_a_chain_from_p1(name: &str, msg: &str) -> ReceivedChain {
    use canton_participant::{sequencing_wire as sw, view_receive as vr};
    let (r, mut c, token) = authenticated(name);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let hosting = r.party_hosting_transaction("erin");
    let vetting = r.vetting_transaction(&[var("CANTON_RS_CHAIN_PACKAGE")]);
    let hashes = [
        tx_hash_in_log(&hosting.transaction),
        tx_hash_in_log(&vetting.transaction),
    ];
    broadcast(&r, &mut c, &token, &[hosting, vetting]);
    for hash in &hashes {
        log_line_with(&[
            "participant=p1",
            "Storing topology transaction",
            &format!("TxHash(SHA-256:{hash}"),
        ])
        .expect("p1 stores the transaction");
    }
    std::thread::sleep(std::time::Duration::from_secs(2));
    let erin = r.party_id("erin");
    let keys = p1_signing_keys(&mut c, &r, &token);
    let (alice, dave) = (var("CANTON_RS_ALICE"), var("CANTON_RS_DAVE"));
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |content: String| {
        let name = format!("{}.chain", unique("chain"));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let from = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap()
        + 1;
    let inbox = command(format!("inbox,{alice}"));
    let line = log_line_with(&["SCF chain_done=", &inbox]).expect("p1 creates the inbox");
    let inbox_id = line.rsplit('=').next().unwrap().trim().to_string();
    assert_ne!(inbox_id, "?", "{line}");
    let start = command(format!("start,{alice},{inbox_id},{erin},{dave},{msg}"));
    let mut found = None;
    let mut at = from;
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < patience {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(at),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default();
        let Some(event) = events.first() else {
            continue;
        };
        let d = sw::decode_delivered(event).expect("every event decodes");
        at = d.timestamp_micros + 1;
        if d.envelopes.iter().any(|e| {
            vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret()).is_ok()
        }) {
            found = Some(d);
            break;
        }
    }
    let event = found.unwrap_or_else(|| {
        panic!(
            "the Rust participant got no readable view\n{}",
            node_log()
                .lines()
                .filter(|l| l.contains("SCF chain_failed") || l.contains(&start))
                .collect::<Vec<_>>()
                .join("\n")
        )
    });
    let announced = event
        .envelopes
        .iter()
        .find_map(|e| vr::root_hash_of_message(e))
        .expect("a root hash message");
    ReceivedChain {
        identity: r,
        event,
        announced_root_hash: announced,
        p1_signing_keys: keys,
        party: erin,
    }
}

/// A view under a view, and a participant that receives both: the Rust participant is an informee of `Forward` (under the root `Start`)
/// and of the `Note` created under `Forward` (because p2's dave observes it). It checks every view it was shown against the announced
/// root hash and p1's signature, and its engine reproduces each; the mediator approves the request.
#[test]
fn the_rust_participant_receives_a_view_and_the_view_under_it_and_both_check_out() {
    use canton_participant::{view_conformance as vc, view_receive as vr};
    let got = rust_receives_a_chain_from_p1(&unique("r-chain"), "deep");
    let r = &got.identity;
    let engine = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_CHAIN_DAR"))).unwrap();
    // [measured] the views come in more than one envelope: one encrypted view message per group of recipients. The view under `Forward`
    // (whose recipients include p2) is in an envelope of its own; every envelope this participant can open is checked
    let mut revealed = Vec::new();
    let mut envelopes = 0;
    for e in &got.event.envelopes {
        let Ok(views) = vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret())
        else {
            continue;
        };
        envelopes += 1;
        let these = vr::check_views(&views, &got.announced_root_hash, |s, root| {
            verifies_with_any(&got.p1_signing_keys, s, root)
        })
        .expect("the hashes (with what is blinded) and p1's signature check out in every envelope");
        let common =
            vr::revealed_common_metadata(views.view_trees[0].tree.as_ref().unwrap()).unwrap();
        for v in these {
            let conforming = vc::check_view(&engine, &v, &common)
                .unwrap_or_else(|e| panic!("the view at {:?} conforms: {e:?}", v.position));
            revealed.push((
                v,
                conforming
                    .iter()
                    .map(|c| c.template.clone())
                    .collect::<Vec<_>>(),
            ));
        }
    }
    assert_eq!(envelopes, 2, "two envelopes for this participant");
    let summary: Vec<(usize, Vec<String>)> = revealed
        .iter()
        .map(|(v, t)| (v.position.len(), t.clone()))
        .collect();
    println!("CHAIN views (depth, created): {summary:?}");
    // the create of the Hop and the Forward exercise under the root, and the Note under the Forward: a view and the view under it
    let deepest = revealed
        .iter()
        .map(|(v, _)| v)
        .max_by_key(|v| v.position.len())
        .unwrap();
    assert_eq!(
        deepest.position.len(),
        3,
        "a view under a view under the root: {summary:?}"
    );
    let parent = &deepest.position[1..];
    assert!(
        revealed
            .iter()
            .any(|(v, _)| v.position.as_slice() == parent),
        "the view above the deepest one is revealed to this participant too: {summary:?}"
    );
    assert!(
        revealed.iter().any(|(v, t)| v.position.len() == 3 && t == &vec!["Chain:Note".to_string()]),
        "the Note is created in the deepest view, and this participant's engine produces it: {summary:?}"
    );
    for (v, _) in &revealed {
        assert!(
            v.common_data.informees.contains(&got.party),
            "erin is an informee of every view this participant was shown"
        );
    }
    let request = iso_micros(got.event.timestamp_micros);
    let finalized = log_line_with(&[
        "mediator=m1",
        "Phase 6: Finalized request",
        &format!("RequestId({request})"),
    ])
    .expect("the mediator finalizes the request p1 made");
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

/// R-16 / P-10: Official Canton 3.7.2 `p1` sends a parent exercise (`Forward`) with a child subview (`Note` observed by `dave` on `p2`).
/// Under live synchronizer topology, Rust computes `CoreInformees::Exact` and approves (`m1` finalizes Approve); stripping `p2` from
/// `dave`'s hosts pulls `Note` into `Forward`'s core and triggers `Nonconformance::InformeesDiffer` (`Malformed`).
#[test]
fn r16_official_p1_parent_and_subview_informees_verified_under_topology() {
    use canton_participant::confirmation_wire::Outcome;
    use canton_participant::sequencer_connect::AuthKey;
    use canton_participant::view_conformance::{self as vc, Nonconformance};
    use canton_participant::view_informees::{check_informees, CoreInformees};
    use canton_participant::view_receive as vr;

    let got = rust_receives_a_chain_from_p1(&unique("r-r16-chain"), "r16-topo");
    let r = &got.identity;
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let dave = var("CANTON_RS_DAVE");

    let mut c = client();
    let challenge = c.challenge(&r.member(), &[37]).expect("challenge for r");
    let sig = r.sequencer_auth_key.sign_bytes(
        &AuthKey::challenge_hash(&challenge.nonce, &synchronizer).expect("challenge hash"),
    );
    let token = c
        .authenticate(&r.member(), &challenge.nonce, sig)
        .expect("re-authenticate r");
    let sync_info = c.synchronizer_id().expect("synchronizer id");

    let chain_engine = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_CHAIN_DAR"))).unwrap();
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let mut config = runtime_config(
        r,
        &got.party,
        got.p1_signing_keys.clone(),
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.follow_topology = true;
    let start_cursor = got.event.timestamp_micros.saturating_sub(1);
    let mut runtime = rt::Runtime::open(config, chain_engine, None, start_cursor).unwrap();
    runtime.load_topology(&mut c, &token).unwrap();
    runtime.connected_to(&sync_info.sequencer_uid);
    runtime.trust_own_submissions(
        canton_algo::member_signature::own_ed25519_key(&r.signing_key.spki_der).unwrap(),
        &r.uid(),
    );

    let dave_hosts = runtime.hosts_of(&dave);
    assert!(
        !dave_hosts.is_empty(),
        "live topology must host subview party dave on p2"
    );

    // Positive oracle 1: Runtime::step with live topology confirms BOTH parent view (`Forward`) and child subview (`Note`)
    // without emitting `Malformed` or refusing (`erin` is a plain observer in `Chain.daml`, so `confirming_parties` is empty ->
    // "nothing to answer for" while locking effects in flight until `m1`'s approving verdict commits `Note`).
    let step = runtime
        .step(&got.event)
        .expect("runtime processes official p1 parent+subview batch");
    assert!(
        step.to_send.is_empty()
            && !runtime.ledger.refused_here(got.event.timestamp_micros)
            && runtime.ledger.earliest_in_flight() == Some(got.event.timestamp_micros),
        "expected clean conforming lock with observer-only answer, got to_send={:?}, notes={:?}",
        step.to_send,
        step.notes
    );
    let verdict_steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 30, |rt| {
        rt.ledger.earliest_in_flight().is_none()
    });
    assert!(
        verdict_steps
            .iter()
            .flat_map(|s| &s.verdicts)
            .any(|&(req, ok)| req == got.event.timestamp_micros && ok),
        "expected approved verdict from m1 for parent+subview request {}: {:?}",
        got.event.timestamp_micros,
        verdict_steps
    );

    // Extract parent view (`Forward`, len 2, has_subviews=true) and child subview (`Note`, len 3) to test exact decomposition + negative control.
    let engine = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_CHAIN_DAR"))).unwrap();
    let mut revealed = Vec::new();
    let mut common_meta = None;
    for env in &got.event.envelopes {
        let Ok(views) = vr::decrypt_views(env, &r.encryption_fingerprint(), r.encryption_secret())
        else {
            continue;
        };
        if common_meta.is_none() {
            common_meta = views
                .view_trees
                .first()
                .and_then(|vt| vt.tree.as_ref())
                .and_then(|t| vr::revealed_common_metadata(t).ok());
        }
        revealed.extend(
            vr::check_views(&views, &got.announced_root_hash, |s, root| {
                verifies_with_any(&got.p1_signing_keys, s, root)
            })
            .expect("views check out"),
        );
    }
    let common = common_meta.expect("common metadata");
    let child_subview = revealed
        .iter()
        .find(|v| v.position.len() == 3)
        .expect("depth-3 child subview (Note)");
    let parent_view = revealed
        .iter()
        .find(|v| v.position.as_slice() == &child_subview.position[1..])
        .expect("depth-2 parent view (Forward)");
    assert!(parent_view.has_subviews);

    let tracker = runtime.topology().expect("topology tracker loaded");
    let hosts_with_p2 = |party: &str| tracker.hosts_of(party);
    let (_, _, ok_core) = vc::check_exercise_view_with_topology(
        &engine,
        parent_view,
        &[child_subview],
        &common,
        None,
        Some(&hosts_with_p2),
    )
    .expect("parent view conforms with live p2 hosting");
    assert!(matches!(ok_core, CoreInformees::Exact(_)), "{ok_core:?}");
    check_informees(parent_view, &ok_core, None).expect("positive parent informees match Exact");

    // Negative control A: strip `p2` from `dave`'s hosts -> `Note` is pulled into `Forward`'s core -> InformeesDiffer (`Malformed`).
    let hosts_without_p2 = |party: &str| {
        if party == dave {
            None
        } else {
            tracker.hosts_of(party)
        }
    };
    let (_, _, bad_core) = vc::check_exercise_view_with_topology(
        &engine,
        parent_view,
        &[child_subview],
        &common,
        None,
        Some(&hosts_without_p2),
    )
    .expect("parent view still replays cleanly without p2 hosting");
    assert!(matches!(bad_core, CoreInformees::Exact(_)), "{bad_core:?}");
    let err = check_informees(parent_view, &bad_core, None).unwrap_err();
    assert!(
        matches!(err, Nonconformance::InformeesDiffer(_)),
        "expected InformeesDiffer when stripping p2 from subview party dave, got {err:?}"
    );

    // Negative control B: end-to-end `Runtime::step` when `dave` has no hosts in topology answers `Outcome::Malformed(InformeesDiffer)`.
    {
        use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
        let downloaded = c
            .download_topology_state(&r.member(), &synchronizer, &token)
            .expect("download topology state");
        let mut entries =
            canton_participant::topology_state::decode(&downloaded).expect("decode topology state");
        entries.retain(|e| {
            !matches!(
                e.tx.mapping.as_ref().and_then(|m| m.mapping.as_ref()),
                Some(Mapping::PartyToParticipant(p)) if p.party == dave
            )
        });
        let mut bad_cfg = runtime_config(
            r,
            &got.party,
            got.p1_signing_keys.clone(),
            vec![],
            canton_participant::view_acs::Timeouts::default(),
        );
        bad_cfg.follow_topology = true;
        let mut rt_bad = rt::Runtime::open(bad_cfg, engine, None, start_cursor).unwrap();
        rt_bad.load_topology_state(&entries).unwrap();
        rt_bad.connected_to(&sync_info.sequencer_uid);
        let step_bad = rt_bad
            .step(&got.event)
            .expect("runtime step negative control");
        assert!(
            step_bad.to_send.iter().flat_map(|s| &s.decisions).any(|d| {
                matches!(&d.outcome, Outcome::Malformed(why) if why.contains("InformeesDiffer") || why.contains("informee"))
            }),
            "expected Runtime::step to emit Outcome::Malformed when dave's p2 hosting is stripped, got to_send={:?} notes={:?}",
            step_bad.to_send,
            step_bad.notes
        );
    }

    let request = iso_micros(got.event.timestamp_micros);
    let finalized = log_line_with(&[
        "mediator=m1",
        "Phase 6: Finalized request",
        &format!("RequestId({request})"),
    ])
    .expect("m1 finalizes official chain request");
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn the_rust_engine_refuses_a_subview_that_does_not_check_out() {
    use canton_participant::view_conformance::{check_view, Engine, Nonconformance as N};
    use canton_participant::view_receive as vr;
    use canton_proto::com::digitalasset::daml::lf::value::value::Sum;
    let got = rust_receives_a_subview_from_p1(&unique("r-sub-bad"), "hello");
    let r = &got.identity;
    let (fp, secret) = (r.encryption_fingerprint(), *r.encryption_secret());
    let views = vr::decrypt_views(&got.view_envelope, &fp, &secret).unwrap();
    let tree = views.view_trees[0].tree.as_ref().unwrap();
    let view = vr::revealed_views(tree).unwrap().remove(0);
    let common = vr::revealed_common_metadata(tree).unwrap();
    let engine = Engine::load(std::path::Path::new(&var("CANTON_RS_NESTED_DAR"))).unwrap();
    let keys = got.p1_signing_keys.clone();
    let signature_ok = |s: &canton_proto::com::digitalasset::canton::crypto::v30::Signature,
                        root: &[u8]| verifies_with_any(&keys, s, root);
    assert!(check_view(&engine, &view, &common).is_ok());
    // the contract salt commits to the whole position: the same view at the position of a root view, or one level off
    let mut as_root = view.clone();
    as_root.position = vec![vec![]];
    assert_eq!(
        check_view(&engine, &as_root, &common).unwrap_err(),
        N::ContractSaltDiffers
    );
    let mut other = view.clone();
    other.position = vec![vec![true], vec![]];
    assert_eq!(
        check_view(&engine, &other, &common).unwrap_err(),
        N::ContractSaltDiffers
    );
    // an `ensure` that does not hold (`msg /= ""`)
    let empty = with_changed_contract(&view, |_, f| f[2].sum = Some(Sum::Text(String::new())));
    assert_eq!(
        check_view(&engine, &empty, &common).unwrap_err(),
        N::EnsureFalse
    );
    // another peer is another observer, so other stakeholders
    let other_peer = with_changed_contract(&view, |_, f| {
        f[1].sum = Some(Sum::Party(format!("zed::1220{}", "ee".repeat(32))))
    });
    assert!(matches!(
        check_view(&engine, &other_peer, &common).unwrap_err(),
        N::StakeholdersDiffer { .. }
    ));
    // a text that changed after the id was derived
    let other_msg =
        with_changed_contract(&view, |_, f| f[2].sum = Some(Sum::Text("goodbye".into())));
    assert_eq!(
        check_view(&engine, &other_msg, &common).unwrap_err(),
        N::ContractIdDiffers
    );
    // the view's informees do not cover the stakeholders of the contract it creates
    let mut fewer = view.clone();
    fewer.common_data.informees.retain(|i| i != &got.party);
    assert!(matches!(
        check_view(&engine, &fewer, &common).unwrap_err(),
        N::ActionDiffers(_)
    ));
    // the message lists another view: the subview's hash is not among the view hashes
    let mut other_hashes = views.clone();
    other_hashes.view_hashes = vec![vec![0x12, 0x20, 9]];
    assert!(matches!(
        vr::check_views(&other_hashes, &got.announced_root_hash, signature_ok),
        Err(vr::ReceiveError::HashMismatch(_))
    ));
    // a root hash message that announces another tree
    let mut other_root = got.announced_root_hash.clone();
    *other_root.last_mut().unwrap() ^= 1;
    assert!(matches!(
        vr::check_views(&views, &other_root, signature_ok),
        Err(vr::ReceiveError::HashMismatch(_))
    ));
}

/// Everything the Rust participant is delivered while p1 creates a sample contract (informee: erin) and then consumes it with
/// `Settle`: both requests' views and the mediator's verdicts, in sequencing order, and what is needed to check them.
struct Followed {
    identity: canton_participant::topology_wire::ParticipantIdentity,
    events: Vec<canton_participant::sequencing_wire::Delivered>,
    p1_signing_keys: Vec<SigningKey>,
    mediator_keys: Vec<SigningKey>,
    contract_id: String,
}

fn rust_follows_a_create_and_a_settle(name: &str) -> Followed {
    use canton_participant::{sequencing_wire as sw, view_receive as vr};
    let (r, mut c, token) = authenticated(name);
    let erin = host_consortium_party(&r, &mut c, &token, "erin");
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    assert!(
        !mediator_keys.is_empty(),
        "the mediator's keys are in the topology state"
    );
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |extension: &str, content: String| {
        let name = format!("{}.{extension}", unique(extension));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let from = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap()
        + 1;
    let created = command("submit", format!("{alice},{erin},{alice},100.0"));
    let line = log_line_with(&["SCF created=", &created]).expect("p1 creates the contract");
    let contract_id = line.rsplit('=').next().unwrap().trim().to_string();
    assert_ne!(contract_id, "?", "{line}");
    command("exercise", format!("{alice},{contract_id},Settle"));
    // collect events until two requests and two verdicts arrived
    let mut events = Vec::new();
    let (mut views, mut verdicts) = (0, 0);
    let mut at = from;
    // time-bounded, not event-bounded: other tests' broadcasts reach every member and would use up a count of iterations
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < patience {
        let got = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(at),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default();
        let Some(event) = got.first() else {
            if views >= 2 && verdicts >= 2 {
                break;
            }
            continue;
        };
        let d = sw::decode_delivered(event).expect("every event decodes");
        at = d.timestamp_micros + 1;
        views += d
            .envelopes
            .iter()
            .filter(|e| {
                vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret()).is_ok()
            })
            .count();
        verdicts += d
            .envelopes
            .iter()
            .filter(|e| canton_participant::view_acs::decode_verdict(e).is_some())
            .count();
        events.push(d);
        if views >= 2 && verdicts >= 2 {
            break;
        }
    }
    assert!(
        views >= 2 && verdicts >= 2,
        "got {views} view(s) and {verdicts} verdict(s)"
    );
    Followed {
        identity: r,
        events,
        p1_signing_keys: p1_keys,
        mediator_keys,
        contract_id,
    }
}

/// Validates a received request as the participant does (decrypt, hashes, signature, engine replay) and returns its effects.
fn validated_effects(
    f: &Followed,
    envelope: &[u8],
    announced: &[u8],
    engine: &canton_participant::view_conformance::Engine,
) -> canton_participant::view_acs::Effects {
    use canton_participant::{view_acs, view_conformance as vc, view_receive as vr};
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    let r = &f.identity;
    let views =
        vr::decrypt_views(envelope, &r.encryption_fingerprint(), r.encryption_secret()).unwrap();
    let revealed = vr::check_views(&views, announced, |s, root| {
        verifies_with_any(&f.p1_signing_keys, s, root)
    })
    .unwrap();
    let view = &revealed[0];
    let common = vr::revealed_common_metadata(views.view_trees[0].tree.as_ref().unwrap()).unwrap();
    match view
        .participant_data
        .action_description
        .as_ref()
        .and_then(|a| a.description.as_ref())
    {
        Some(Description::Create(_)) => {
            vc::check_view(engine, view, &common).expect("the create conforms");
        }
        Some(Description::Exercise(_)) => {
            vc::check_exercise_view(engine, view, &common).expect("the exercise conforms");
        }
        other => panic!("an action this test does not handle: {other:?}"),
    }
    view_acs::effects_of(view).expect("the contracts of the view decode")
}

/// The requests of a followed flow in order: `(sequencing time, effects)` for each, and the verdicts: `(request id, approved)`.
fn replay_followed(
    f: &Followed,
) -> (
    Vec<(i64, canton_participant::view_acs::Effects)>,
    Vec<canton_participant::view_acs::Verdict>,
) {
    use canton_participant::{view_acs, view_conformance as vc, view_receive as vr};
    let engine = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_SAMPLE_DAR"))).unwrap();
    let (mut requests, mut verdicts) = (Vec::new(), Vec::new());
    for event in &f.events {
        let announced = event
            .envelopes
            .iter()
            .find_map(|e| vr::root_hash_of_message(e));
        for (i, envelope) in event.envelopes.iter().enumerate() {
            if let (Some(announced), true) = (
                announced.as_ref(),
                vr::decrypt_views(
                    envelope,
                    &f.identity.encryption_fingerprint(),
                    f.identity.encryption_secret(),
                )
                .is_ok(),
            ) {
                requests.push((
                    event.timestamp_micros,
                    validated_effects(f, envelope, announced, &engine),
                ));
            } else if let Some((verdict, signed)) = view_acs::decode_verdict(envelope) {
                // the verdict is the mediator's: signed by its key, over the content of the envelope
                assert!(
                    view_acs::mediator_signed(
                        &event.envelope_signatures[i],
                        &signed,
                        &f.mediator_keys
                    ),
                    "the verdict is not signed by the mediator"
                );
                verdicts.push(verdict);
            }
        }
    }
    (requests, verdicts)
}

#[test]
fn the_rust_participant_follows_a_contract_from_its_creation_to_its_consumption() {
    use canton_participant::view_acs::Ledger;
    let f = rust_follows_a_create_and_a_settle(&unique("r-acs"));
    let (requests, verdicts) = replay_followed(&f);
    assert_eq!(requests.len(), 2, "the create and the settle");
    assert!(verdicts.len() >= 2);
    assert!(verdicts.iter().all(|v| v.approved), "{verdicts:?}");
    let mut ledger = Ledger::new();
    // the create: in flight, then active once the mediator approved it
    let (create_time, create_effects) = &requests[0];
    assert_eq!(create_effects.creates.len(), 1);
    assert_eq!(create_effects.creates[0].0, f.contract_id);
    ledger
        .begin(*create_time, create_effects.clone())
        .expect("a new contract");
    assert!(
        !ledger.is_active(&f.contract_id),
        "not active before the verdict"
    );
    let create_verdict = verdicts
        .iter()
        .find(|v| v.request_id == *create_time)
        .expect("a verdict for the create");
    assert!(ledger
        .resolve(create_verdict.request_id, create_verdict.approved)
        .unwrap());
    assert!(ledger.is_active(&f.contract_id));
    // the settle: it consumes an active contract; after the verdict the contract is archived by that request
    let (settle_time, settle_effects) = &requests[1];
    assert_eq!(settle_effects.consumes, vec![f.contract_id.clone()]);
    ledger
        .begin(*settle_time, settle_effects.clone())
        .expect("the contract is active");
    let settle_verdict = verdicts
        .iter()
        .find(|v| v.request_id == *settle_time)
        .expect("a verdict for the settle");
    assert!(ledger
        .resolve(settle_verdict.request_id, settle_verdict.approved)
        .unwrap());
    assert!(!ledger.is_active(&f.contract_id));
    assert_eq!(ledger.archived_by(&f.contract_id), Some(*settle_time));
    assert_eq!(ledger.in_flight(), 0);
}

#[test]
fn the_rust_participant_refuses_to_use_a_contract_twice_or_before_it_exists() {
    use canton_participant::view_acs::{Conflict, Ledger};
    let f = rust_follows_a_create_and_a_settle(&unique("r-acs-bad"));
    let (requests, _) = replay_followed(&f);
    let (create_time, create_effects) = requests[0].clone();
    let (settle_time, settle_effects) = requests[1].clone();
    let id = f.contract_id.clone();
    // an exercise of a contract this participant has not seen created
    let mut l = Ledger::new();
    assert_eq!(
        l.begin(settle_time, settle_effects.clone()),
        Err(Conflict::UnknownContract(id.clone()))
    );
    // ... or whose creation is still in flight (not decided yet: not active)
    l.begin(create_time, create_effects.clone()).unwrap();
    assert_eq!(
        l.begin(settle_time, settle_effects.clone()),
        Err(Conflict::UnknownContract(id.clone()))
    );
    assert!(l.resolve(create_time, true).unwrap());
    // the same creation again: the contract exists
    assert_eq!(
        l.begin(create_time + 1, create_effects.clone()),
        Err(Conflict::ContractAlreadyExists(id.clone()))
    );
    // two exercises at once: the second finds the contract locked by the first
    l.begin(settle_time, settle_effects.clone()).unwrap();
    assert_eq!(
        l.begin(settle_time + 1, settle_effects.clone()),
        Err(Conflict::LockedContract {
            id: id.clone(),
            by_request: settle_time
        })
    );
    // a rejected verdict frees the contract; an approved one archives it
    assert!(l.resolve(settle_time, false).unwrap());
    assert!(l.is_active(&id));
    l.begin(settle_time + 2, settle_effects.clone()).unwrap();
    assert!(l.resolve(settle_time + 2, true).unwrap());
    // the settle played again after its approval: the contract is archived, and by which request
    assert_eq!(
        l.begin(settle_time + 3, settle_effects.clone()),
        Err(Conflict::ArchivedContract {
            id: id.clone(),
            by_request: settle_time + 2
        })
    );
    // a verdict for a request this participant never begun changes nothing
    assert!(!l.resolve(settle_time + 99, true).unwrap());
    // and a verdict that the mediator did not sign is not one: a stranger's key does not verify it
    let event = f
        .events
        .iter()
        .find(|e| {
            e.envelopes
                .iter()
                .any(|x| canton_participant::view_acs::decode_verdict(x).is_some())
        })
        .unwrap();
    let (i, envelope) = event
        .envelopes
        .iter()
        .enumerate()
        .find(|(_, x)| canton_participant::view_acs::decode_verdict(x).is_some())
        .unwrap();
    let (_, signed) = canton_participant::view_acs::decode_verdict(envelope).unwrap();
    assert!(canton_participant::view_acs::mediator_signed(
        &event.envelope_signatures[i],
        &signed,
        &f.mediator_keys
    ));
    assert!(!canton_participant::view_acs::mediator_signed(
        &event.envelope_signatures[i],
        &signed,
        &[canton_algo::member_signature::own_ed25519_key(
            &canton_participant::topology_wire::Ed25519Key::from_seed([7; 32]).spki_der
        )
        .unwrap()]
    ));
    let mut tampered = signed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(!canton_participant::view_acs::mediator_signed(
        &event.envelope_signatures[i],
        &tampered,
        &f.mediator_keys
    ));
}

/// What the Rust participant sees when it begins to host a party **after** a contract of that party was created: p1 hosted `erin`
/// alone and made a contract with it; then the Rust participant was added as a host and p1 consumed the contract.
struct Joined {
    identity: canton_participant::topology_wire::ParticipantIdentity,
    /// The serialized contract instance p1 exported for the contract (the created event blob).
    blob: Vec<u8>,
    contract_id: String,
    /// The consuming request as the Rust participant received it: its sequencing time, the view envelope and the announced root hash.
    exercise_time: i64,
    exercise_view: Vec<u8>,
    announced_root_hash: Vec<u8>,
    verdict: canton_participant::view_acs::Verdict,
    p1_signing_keys: Vec<SigningKey>,
}

fn rust_joins_after_the_contract_exists(name: &str) -> Joined {
    use canton_participant::{
        sequencing_wire as sw, topology_wire as tw, view_acs, view_receive as vr,
    };
    let (r, mut c, token) = authenticated(name);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    // 1. erin is hosted by p1 alone (Rust's namespace owns the party and p1 is added: both sign), and the Rust participant vets the package
    let proposal_bytes =
        tw::party_to_participant_at_serial(&r.party_id("erin"), &[(&p1_uid, 1)], 1, 1);
    let proposal = tw::signed_proposal(
        proposal_bytes.clone(),
        vec![r.namespace_key.sign_transaction(&proposal_bytes)],
    );
    let vetting = r.vetting_transaction(&[var("CANTON_RS_SAMPLE_PACKAGE")]);
    let hashes = [
        tx_hash_in_log(&proposal.transaction),
        tx_hash_in_log(&vetting.transaction),
    ];
    let proposal_hash = tw::transaction_hash(&proposal.transaction);
    broadcast(&r, &mut c, &token, &[proposal, vetting]);
    for hash in &hashes {
        log_line_with(&[
            "participant=p1",
            "Storing topology transaction",
            &format!("TxHash(SHA-256:{hash}"),
        ])
        .expect("p1 stores the transaction");
    }
    have_p1_authorize(&proposal_hash);
    let p1_ns = p1_uid.split("::").nth(1).unwrap()[..12].to_string();
    log_line_with(&[
        "sequencer=s1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{}", hashes[0]),
        &r.namespace()[..12],
        &p1_ns,
    ])
    .expect("the party is hosted by p1");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let erin = r.party_id("erin");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |extension: &str, content: String| {
        let name = format!("{}.{extension}", unique(extension));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    // 2. p1 creates the contract; the Rust participant does not host a stakeholder yet and is told nothing
    let created = command("submit", format!("{alice},{erin},{alice},100.0"));
    let line = log_line_with(&["SCF created=", &created]).expect("p1 creates the contract");
    let contract_id = line.rsplit('=').next().unwrap().trim().to_string();
    let blob_line = log_line_with(&["SCF blob=", &created]).expect("p1 exports the contract");
    let blob = hex::decode(blob_line.rsplit('=').next().unwrap().trim()).unwrap();
    // 3. the Rust participant becomes a host of erin too (serial 2 replaces the mapping; it only adds this participant's own namespace)
    let update = r.party_hosting_at_serial("erin", &[(&p1_uid, 1), (&r.uid(), 2)], 2);
    let update_hash = tx_hash_in_log(&update.transaction);
    broadcast(&r, &mut c, &token, &[update]);
    log_line_with(&[
        "participant=p1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{update_hash}"),
    ])
    .expect("p1 stores the new hosting");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let keys = p1_signing_keys(&mut c, &r, &token);
    // 4. p1 consumes the contract; now the Rust participant is a host and receives the request and its verdict
    let from = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap()
        + 1;
    command("exercise", format!("{alice},{contract_id},Settle"));
    let (mut request, mut verdict) = (None, None);
    let mut at = from;
    // time-bounded, not event-bounded: other tests' broadcasts reach every member and would use up a count of iterations
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < patience {
        let got = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(at),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default();
        let Some(event) = got.first() else { continue };
        let d = sw::decode_delivered(event).expect("every event decodes");
        at = d.timestamp_micros + 1;
        for e in &d.envelopes {
            if vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret()).is_ok() {
                let announced = d
                    .envelopes
                    .iter()
                    .find_map(|x| vr::root_hash_of_message(x))
                    .expect("a root hash message");
                request = Some((d.timestamp_micros, e.clone(), announced));
            } else if let Some((v, _)) = view_acs::decode_verdict(e) {
                verdict = Some(v);
            }
        }
        if request.is_some() && verdict.is_some() {
            break;
        }
    }
    let (exercise_time, exercise_view, announced_root_hash) =
        request.expect("the Rust participant receives the consuming request");
    Joined {
        identity: r,
        blob,
        contract_id,
        exercise_time,
        exercise_view,
        announced_root_hash,
        verdict: verdict.expect("and its verdict"),
        p1_signing_keys: keys,
    }
}

fn rust_engine() -> canton_participant::view_conformance::Engine {
    canton_participant::view_conformance::Engine::load(std::path::Path::new(&var(
        "CANTON_RS_SAMPLE_DAR",
    )))
    .unwrap()
}

#[test]
fn the_rust_participant_imports_a_contract_that_existed_before_it_hosted_the_party_and_then_follows_its_consumption(
) {
    use canton_participant::{view_acs, view_conformance as vc, view_receive as vr};
    let j = rust_joins_after_the_contract_exists(&unique("r-join"));
    let r = &j.identity;
    let engine = rust_engine();
    // the consuming request conforms (S-NET-017) ... but this participant has never seen the contract created
    let views = vr::decrypt_views(
        &j.exercise_view,
        &r.encryption_fingerprint(),
        r.encryption_secret(),
    )
    .unwrap();
    let revealed = vr::check_views(&views, &j.announced_root_hash, |s, root| {
        verifies_with_any(&j.p1_signing_keys, s, root)
    })
    .unwrap();
    let common = vr::revealed_common_metadata(views.view_trees[0].tree.as_ref().unwrap()).unwrap();
    vc::check_exercise_view(&engine, &revealed[0], &common).expect("the exercise conforms");
    let effects = view_acs::effects_of(&revealed[0]).unwrap();
    assert_eq!(effects.consumes, vec![j.contract_id.clone()]);
    let journal = std::env::temp_dir().join(format!("rust-join-{}.journal", unique("j")));
    let mut without = view_acs::Ledger::open(&journal).unwrap();
    assert_eq!(
        without.begin(j.exercise_time, effects.clone()),
        Err(view_acs::Conflict::UnknownContract(j.contract_id.clone())),
        "without the ACS import the contract is unknown"
    );
    // the snapshot p1 exports is authenticated, then the contract is active
    let mut ledger = view_acs::Ledger::open(
        &std::env::temp_dir().join(format!("rust-join-ok-{}.journal", unique("j"))),
    )
    .unwrap();
    let imported = vc::import_contract(&engine, &mut ledger, &j.blob)
        .expect("p1's exported contract is authentic");
    assert_eq!(imported, j.contract_id);
    assert!(ledger.is_active(&j.contract_id));
    // the request begins and the participant restarts before the verdict
    ledger
        .begin(j.exercise_time, effects.clone())
        .expect("the imported contract is active");
    drop(ledger);
    let path = std::env::temp_dir().join(format!("rust-join-restart-{}.journal", unique("j")));
    let mut ledger = view_acs::Ledger::open(&path).unwrap();
    vc::import_contract(&engine, &mut ledger, &j.blob).unwrap();
    ledger.begin(j.exercise_time, effects.clone()).unwrap();
    drop(ledger);
    let mut ledger = view_acs::Ledger::open(&path).unwrap();
    assert!(
        ledger.is_active(&j.contract_id) && ledger.in_flight() == 1,
        "the restart kept the import and the request in flight"
    );
    // the mediator's verdict, received after the restart
    assert_eq!(j.verdict.request_id, j.exercise_time);
    assert!(j.verdict.approved);
    assert!(ledger
        .resolve(j.verdict.request_id, j.verdict.approved)
        .unwrap());
    assert_eq!(ledger.archived_by(&j.contract_id), Some(j.exercise_time));
    // and the events read again after a further restart change nothing
    drop(ledger);
    let mut ledger = view_acs::Ledger::open(&path).unwrap();
    assert_eq!(
        ledger.begin(j.exercise_time, effects),
        Err(view_acs::Conflict::RequestAlreadyDecided(j.exercise_time))
    );
    assert!(!ledger.resolve(j.verdict.request_id, true).unwrap());
    assert!(ledger.active_ids().is_empty());
}

#[test]
fn the_rust_participant_refuses_to_import_a_contract_that_is_not_authentic() {
    use canton_participant::{
        view_acs::{Conflict, Ledger},
        view_conformance::{import_contract, ImportError, Nonconformance as N},
    };
    use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
    use canton_proto::com::digitalasset::daml::lf::value::{value::Sum, Value};
    use prost::Message;
    let j = rust_joins_after_the_contract_exists(&unique("r-join-bad"));
    let engine = rust_engine();
    let mut ledger = Ledger::new();
    // the exporter changes what the contract says: the symbol is not the one the id was derived for
    let mutate = |change: &dyn Fn(&mut FatContractInstance, &mut Vec<Value>)| {
        let mut versioned = Versioned::decode(j.blob.as_slice()).unwrap();
        let mut fci = FatContractInstance::decode(versioned.payload.as_slice()).unwrap();
        let Some(Sum::Record(record)) = Value::decode(fci.create_arg.as_slice()).unwrap().sum
        else {
            panic!("a record")
        };
        let mut fields: Vec<Value> = record.fields.into_iter().filter_map(|f| f.value).collect();
        change(&mut fci, &mut fields);
        fci.create_arg = Value {
            sum: Some(Sum::Record(
                canton_proto::com::digitalasset::daml::lf::value::value::Record {
                    fields: fields
                        .into_iter()
                        .map(|v| {
                            canton_proto::com::digitalasset::daml::lf::value::value::record::Field {
                                value: Some(v),
                            }
                        })
                        .collect(),
                },
            )),
        }
        .encode_to_vec();
        versioned.payload = fci.encode_to_vec();
        versioned.encode_to_vec()
    };
    let other_symbol = mutate(&|_, f| f[3].sum = Some(Sum::Text("EUR".into())));
    assert_eq!(
        import_contract(&engine, &mut ledger, &other_symbol),
        Err(ImportError::NotAuthentic(N::ContractIdDiffers))
    );
    // an amount the template does not allow
    let zero = mutate(&|_, f| f[4].sum = Some(Sum::Numeric("0.0000000000".into())));
    assert_eq!(
        import_contract(&engine, &mut ledger, &zero),
        Err(ImportError::NotAuthentic(N::EnsureFalse))
    );
    // a created-at time that was changed after the id was derived
    let later = mutate(&|fci, _| fci.created_at += 1);
    assert_eq!(
        import_contract(&engine, &mut ledger, &later),
        Err(ImportError::NotAuthentic(N::ContractIdDiffers))
    );
    // nothing was recorded
    assert!(ledger.active_ids().is_empty());
    // the real one is imported once; a second import is refused
    assert_eq!(
        import_contract(&engine, &mut ledger, &j.blob),
        Ok(j.contract_id.clone())
    );
    assert_eq!(
        import_contract(&engine, &mut ledger, &j.blob),
        Err(ImportError::Refused(Conflict::ContractAlreadyExists(
            j.contract_id.clone()
        )))
    );
    // bytes that are no contract instance at all
    assert!(matches!(
        import_contract(&engine, &mut Ledger::new(), &[1, 2, 3]),
        Err(ImportError::NotAuthentic(_))
    ));
}

/// `SequencerConnect::subscribe` that does not give up on the first error. With many tests subscribing at once, the sequencer
/// sometimes ends or refuses a stream at once (a member's previous stream is still closing); a test that waits for an event has to
/// ask again until its time is up rather than see an empty answer and stop looking after a few milliseconds.
trait SubscribePatiently {
    fn subscribe_patiently(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &canton_participant::sequencer_connect::Token,
        after_micros: Option<i64>,
        count: usize,
        wait: std::time::Duration,
    ) -> Result<Vec<Vec<u8>>, canton_participant::sequencer_connect::ConnectError>;
}

impl SubscribePatiently for SequencerConnect {
    fn subscribe_patiently(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &canton_participant::sequencer_connect::Token,
        after_micros: Option<i64>,
        count: usize,
        wait: std::time::Duration,
    ) -> Result<Vec<Vec<u8>>, canton_participant::sequencer_connect::ConnectError> {
        let deadline = std::time::Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(Vec::new());
            }
            match self.subscribe(
                member,
                synchronizer_id,
                token,
                after_micros,
                count,
                remaining,
            ) {
                Ok(events) if !events.is_empty() => return Ok(events),
                // nothing yet, or the stream ended or was refused: ask again
                _ => std::thread::sleep(std::time::Duration::from_millis(300)),
            }
        }
    }
}

/// A request for which the Rust participant's confirmation is **necessary**: `erin` is hosted by p1 (submission) and the Rust
/// participant (confirmation) with a confirmation **threshold of 2** — both have to confirm — and she is a signatory of the contract
/// p1 consumes (`Settle`, controller alice). [CANTON-NOTE: SEMANTICS] A party with a threshold above 1 cannot *submit*
/// (`DECENTRALIZED_PARTY_CANNOT_SUBMIT`), so the threshold is raised only after p1 created the contract with erin as its owner;
/// the signatory's authority then carries the exercise, which alice submits.
struct Necessary {
    identity: canton_participant::topology_wire::ParticipantIdentity,
    connection: SequencerConnect,
    token: canton_participant::sequencer_connect::Token,
    request_time: i64,
    view_envelope: Vec<u8>,
    announced_root_hash: Vec<u8>,
    p1_signing_keys: Vec<SigningKey>,
    blob: Vec<u8>,
    contract_id: String,
    party: String,
    /// Where to go on subscribing: just after the event that held the request.
    next_from: i64,
}

fn rust_must_confirm_a_settle(name: &str) -> Necessary {
    use canton_participant::{sequencing_wire as sw, topology_wire as tw, view_receive as vr};
    let (r, mut c, token) = authenticated(name);
    let erin = host_consortium_party(&r, &mut c, &token, "erin");
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |extension: &str, content: String| {
        let name = format!("{}.{extension}", unique(extension));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let created = command("submit", format!("{alice},{erin},{alice},100.0"));
    let line = log_line_with(&["SCF created=", &created]).expect("p1 creates the contract");
    let contract_id = line.rsplit('=').next().unwrap().trim().to_string();
    let blob_line = log_line_with(&["SCF blob=", &created]).expect("p1 exports the contract");
    let blob = hex::decode(blob_line.rsplit('=').next().unwrap().trim()).unwrap();
    // erin now needs both hosts to confirm (a change of the threshold is authorized by the party alone)
    let bytes = tw::party_to_participant_at_serial(&erin, &[(&p1_uid, 1), (&r.uid(), 2)], 2, 2);
    let raise = tw::signed(
        bytes.clone(),
        vec![r.namespace_key.sign_transaction(&bytes)],
    );
    let raise_hash = tx_hash_in_log(&raise.transaction);
    broadcast(&r, &mut c, &token, &[raise]);
    log_line_with(&[
        "participant=p1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{raise_hash}"),
    ])
    .expect("p1 stores the new threshold");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let keys = p1_signing_keys(&mut c, &r, &token);
    let from = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap()
        + 1;
    command("exercise", format!("{alice},{contract_id},Settle"));
    let mut request = None;
    let mut at = from;
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < patience && request.is_none() {
        let got = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(at),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default();
        let Some(event) = got.first() else { continue };
        let d = sw::decode_delivered(event).expect("every event decodes");
        at = d.timestamp_micros + 1;
        for e in &d.envelopes {
            if vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret()).is_ok() {
                let announced = d
                    .envelopes
                    .iter()
                    .find_map(|x| vr::root_hash_of_message(x))
                    .expect("a root hash message");
                request = Some((d.timestamp_micros, e.clone(), announced));
            }
        }
    }
    let (request_time, view_envelope, announced_root_hash) =
        request.expect("the Rust participant receives the request");
    let next_from = request_time + 1;
    Necessary {
        identity: r,
        connection: c,
        token,
        request_time,
        view_envelope,
        announced_root_hash,
        p1_signing_keys: keys,
        blob,
        contract_id,
        party: erin,
        next_from,
    }
}

/// Decides as the Rust participant would and sends the answer to the mediator. Returns the decision.
fn answer_as_rust(
    n: &mut Necessary,
    engine: &canton_participant::view_conformance::Engine,
    ledger: &mut canton_participant::view_acs::Ledger,
    secret: [u8; 32],
) -> canton_participant::view_decision::Decision {
    let decision = decide_as_rust(n, engine, ledger, secret);
    send_answer(n, &decision);
    decision
}

/// Decides as the Rust participant would, without sending anything.
fn decide_as_rust(
    n: &mut Necessary,
    engine: &canton_participant::view_conformance::Engine,
    ledger: &mut canton_participant::view_acs::Ledger,
    secret: [u8; 32],
) -> canton_participant::view_decision::Decision {
    use canton_participant::view_decision as vd;
    let keys = n.p1_signing_keys.clone();
    let hosted = [n.party.clone()];
    let verify = move |_submitting: Option<&str>,
                       s: &canton_proto::com::digitalasset::canton::crypto::v30::Signature,
                       root: &[u8]| { verifies_with_any(&keys, s, root) };
    let fingerprint = n.identity.encryption_fingerprint();
    vd::decide(
        &vd::Participant {
            encryption_fingerprint: &fingerprint,
            encryption_secret: &secret,
            engine,
            hosted_parties: &hosted,
            verify_submitter: &verify,
            time_tolerances: Default::default(),
            uid: &n.identity.uid(),
            hosts_of: None,
            party_keys: None,
        },
        ledger,
        &vd::Request {
            request_time: n.request_time,
            view_envelope: &n.view_envelope,
            announced_root_hash: &n.announced_root_hash,
            decision_time: Some(
                canton_participant::view_acs::Timeouts::default().decision_time(n.request_time),
            ),
        },
    )
}

/// Sends the answer `decision` to the mediator.
fn send_answer(n: &mut Necessary, decision: &canton_participant::view_decision::Decision) {
    use canton_participant::{confirmation_wire as cw, sequencing_wire as sw};
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let (content, signatures) = cw::confirmation_responses(
        n.request_time,
        &n.announced_root_hash,
        &synchronizer,
        &n.identity.member(),
        &[cw::ViewResponse {
            view_position: &decision.view_position,
            outcome: decision.outcome.clone(),
            confirming_parties: &decision.confirming_parties,
        }],
        &n.identity.signing_key,
    );
    let now = n
        .connection
        .sequencer_time(&n.identity.member(), &synchronizer, Some(&n.token))
        .unwrap()
        .unwrap();
    n.connection
        .send_async(
            &n.identity.member(),
            &synchronizer,
            &n.token,
            sw::signed_submission_request(
                sw::submission_request_signed(
                    &n.identity.member(),
                    &unique("resp"),
                    &[(vec![cw::mediator_group(0)], content, signatures)],
                    now + 30_000_000,
                ),
                &n.identity.signing_key,
            ),
        )
        .expect("the sequencer accepts the answer");
}

/// The mediator's line that finalizes the request received at `request_time`.
fn finalized_at(request_time: i64) -> String {
    let request = iso_micros(request_time);
    log_line_with(&[
        "mediator=m1",
        "Phase 6: Finalized request",
        &format!("RequestId({request})"),
    ])
    .expect("the mediator finalizes the request")
}

fn is_canton_log_entry_start(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() >= 19
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b' '
        && b[13] == b':'
        && b[16] == b':'
}

/// The verdict of the request received at `request_time` as the mediator logs it: the `Phase 6` line and its own
/// continuation lines (stopping before the next timestamped log entry so parallel tests cannot bleed into the verdict).
fn finalized_block_at(request_time: i64) -> String {
    let first = finalized_at(request_time);
    let log = node_log();
    let all: Vec<&str> = log.lines().collect();
    let at = all
        .iter()
        .position(|l| *l == first)
        .expect("the line is in the log");
    let end = all[(at + 1)..(at + 20).min(all.len())]
        .iter()
        .position(|l| is_canton_log_entry_start(l))
        .map_or((at + 20).min(all.len()), |offset| at + 1 + offset);
    all[at..end].join("\n")
}

#[test]
fn the_mediator_approves_when_the_necessary_rust_participant_approves() {
    use canton_participant::{
        confirmation_wire::Outcome, view_acs::Ledger, view_conformance as vc,
    };
    let mut n = rust_must_confirm_a_settle(&unique("r-nec-ok"));
    let engine = rust_engine();
    let mut ledger = Ledger::new();
    vc::import_contract(&engine, &mut ledger, &n.blob)
        .expect("the contract p1 exported is authentic");
    let secret = *n.identity.encryption_secret();
    let decision = answer_as_rust(&mut n, &engine, &mut ledger, secret);
    assert_eq!(decision.outcome, Outcome::Approve, "{decision:?}");
    assert_eq!(decision.confirming_parties, vec![n.party.clone()]);
    let finalized = finalized_at(n.request_time);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn the_mediator_rejects_the_request_when_the_rust_participant_does_not_know_the_contract() {
    use canton_participant::{confirmation_wire::Outcome, view_acs::Ledger};
    let mut n = rust_must_confirm_a_settle(&unique("r-nec-unknown"));
    let engine = rust_engine();
    // this participant never saw the contract: its contract set is empty
    let mut ledger = Ledger::new();
    let secret = *n.identity.encryption_secret();
    let decision = answer_as_rust(&mut n, &engine, &mut ledger, secret);
    let Outcome::Reject(why) = &decision.outcome else {
        panic!("{decision:?}")
    };
    assert!(
        why.contains("UnknownContract") && why.contains(&n.contract_id),
        "{why}"
    );
    assert_eq!(ledger.in_flight(), 0, "a refused request locks nothing");
    // p1 alone would approve; the verdict is a rejection because the Rust participant refused for the signatory it confirms
    let finalized = finalized_block_at(n.request_time);
    assert!(finalized.contains("ParticipantReject"), "{finalized}");
    assert!(
        finalized.contains("UnknownContract"),
        "the reason travels into the verdict: {finalized}"
    );
}

#[test]
fn the_mediator_rejects_the_request_when_the_rust_participant_cannot_reproduce_it() {
    use canton_participant::{
        confirmation_wire::Outcome, view_acs::Ledger, view_conformance as vc,
    };
    let mut n = rust_must_confirm_a_settle(&unique("r-nec-engine"));
    // an engine that has another package than the one the request is about
    let other = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_NESTED_DAR"))).unwrap();
    let mut ledger = Ledger::new();
    let secret = *n.identity.encryption_secret();
    let decision = answer_as_rust(&mut n, &other, &mut ledger, secret);
    // a failed model conformance check is malformed for its view (`LocalRejectError.MalformedRejects.ModelConformance`)
    let Outcome::Malformed(why) = &decision.outcome else {
        panic!("{decision:?}")
    };
    assert!(why.contains("UnknownPackage"), "{why}");
    let finalized = finalized_block_at(n.request_time);
    assert!(
        finalized.contains("ParticipantReject") && finalized.contains("UnknownPackage"),
        "{finalized}"
    );
}

#[test]
fn the_mediator_calls_the_request_malformed_when_the_rust_participant_cannot_read_it() {
    use canton_participant::{confirmation_wire::Outcome, view_acs::Ledger};
    let mut n = rust_must_confirm_a_settle(&unique("r-nec-malformed"));
    let engine = rust_engine();
    let mut ledger = Ledger::new();
    // the participant's key is not the key the session key was encrypted for: the view does not decrypt
    let decision = answer_as_rust(&mut n, &engine, &mut ledger, [9u8; 32]);
    let Outcome::Malformed(why) = &decision.outcome else {
        panic!("{decision:?}")
    };
    assert!(why.contains("SessionKeyDoesNotDecrypt"), "{why}");
    assert!(decision.confirming_parties.is_empty() && decision.view_position.is_empty());
    let finalized = finalized_at(n.request_time);
    assert!(!finalized.contains("with verdict Approve"), "{finalized}");
}

/// A contract set that knows the contract p1 exported and has it used by an earlier request: `decided` (archived by it, if approved)
/// or still in flight.
fn ledger_where_an_earlier_request_used_the_contract(
    n: &Necessary,
    engine: &canton_participant::view_conformance::Engine,
    approved: Option<bool>,
) -> canton_participant::view_acs::Ledger {
    use canton_participant::{
        view_acs::{Effects, Ledger},
        view_conformance as vc,
    };
    let mut ledger = Ledger::new();
    vc::import_contract(engine, &mut ledger, &n.blob).unwrap();
    let earlier = n.request_time - 1_000_000;
    ledger
        .begin(
            earlier,
            Effects {
                consumes: vec![n.contract_id.clone()],
                creates: vec![],
                instances: vec![],
                remote_events: vec![],
            },
        )
        .unwrap();
    if let Some(approved) = approved {
        ledger.resolve(earlier, approved).unwrap();
    }
    ledger
}

#[test]
fn the_double_spend_the_rust_participant_finds_reaches_the_mediator_as_a_rejection() {
    use canton_participant::confirmation_wire::Outcome;
    let mut n = rust_must_confirm_a_settle(&unique("r-nec-archived"));
    let engine = rust_engine();
    // an earlier request already consumed the contract (and was approved)
    let mut ledger = ledger_where_an_earlier_request_used_the_contract(&n, &engine, Some(true));
    let secret = *n.identity.encryption_secret();
    let decision = answer_as_rust(&mut n, &engine, &mut ledger, secret);
    let Outcome::Reject(why) = &decision.outcome else {
        panic!("{decision:?}")
    };
    assert!(why.contains("ArchivedContract"), "{why}");
    let finalized = finalized_block_at(n.request_time);
    assert!(
        finalized.contains("ParticipantReject") && finalized.contains("ArchivedContract"),
        "{finalized}"
    );
}

#[test]
fn a_contract_another_request_still_has_in_flight_is_refused_to_the_mediator() {
    use canton_participant::confirmation_wire::Outcome;
    let mut n = rust_must_confirm_a_settle(&unique("r-nec-locked"));
    let engine = rust_engine();
    // an earlier request holds the contract and has no verdict yet
    let mut ledger = ledger_where_an_earlier_request_used_the_contract(&n, &engine, None);
    let secret = *n.identity.encryption_secret();
    let decision = answer_as_rust(&mut n, &engine, &mut ledger, secret);
    let Outcome::Reject(why) = &decision.outcome else {
        panic!("{decision:?}")
    };
    assert!(why.contains("LockedContract"), "{why}");
    let finalized = finalized_block_at(n.request_time);
    assert!(
        finalized.contains("ParticipantReject") && finalized.contains("LockedContract"),
        "{finalized}"
    );
    // the earlier request is untouched: still the only one in flight
    assert_eq!(ledger.in_flight(), 1);
}

/// The time limits of the synchronizer, from its topology state (`SynchronizerParametersState`).
fn synchronizer_timeouts(
    c: &mut SequencerConnect,
    r: &canton_participant::topology_wire::ParticipantIdentity,
    token: &canton_participant::sequencer_connect::Token,
) -> canton_participant::view_acs::Timeouts {
    let state = c
        .download_topology_state(&r.member(), &var("CANTON_RS_EXPECT_SYNCHRONIZER"), token)
        .unwrap();
    let micros = |d: &Option<prost_types::Duration>| {
        let d = d.as_ref().expect("the parameter is set");
        d.seconds * 1_000_000 + i64::from(d.nanos) / 1_000
    };
    downloaded::decode(&state)
        .iter()
        .find_map(|e| match downloaded::mapping(e) {
            downloaded::Mapping::SynchronizerParametersState(p) => {
                let params = p.synchronizer_parameters.as_ref()?;
                Some(canton_participant::view_acs::Timeouts {
                    confirmation_response_micros: micros(&params.confirmation_response_timeout),
                    mediator_reaction_micros: micros(&params.mediator_reaction_timeout),
                })
            }
            _ => None,
        })
        .expect("the synchronizer's parameters are in the topology state")
}

/// Waits (up to 90 s of the test's time) for the mediator's verdict on the request `n` received, and checks the mediator signed it.
fn verdict_of(n: &mut Necessary) -> Option<canton_participant::view_acs::Verdict> {
    use canton_participant::{sequencing_wire as sw, view_acs};
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let mediator_keys = signing_keys_of(
        &mut n.connection,
        &n.identity,
        &n.token,
        &var("CANTON_RS_MEMBER_M1"),
    );
    let mut at = n.next_from;
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < patience {
        let got = n
            .connection
            .subscribe_patiently(
                &n.identity.member(),
                &synchronizer,
                &n.token,
                Some(at),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default();
        let Some(event) = got.first() else { continue };
        let d = sw::decode_delivered(event).expect("every event decodes");
        at = d.timestamp_micros + 1;
        for (i, e) in d.envelopes.iter().enumerate() {
            if let Some((v, signed)) = view_acs::decode_verdict(e) {
                if v.request_id == n.request_time {
                    assert!(
                        view_acs::mediator_signed(
                            &d.envelope_signatures[i],
                            &signed,
                            &mediator_keys
                        ),
                        "the verdict is not signed by the mediator"
                    );
                    return Some(v);
                }
            }
        }
    }
    None
}

#[test]
fn the_mediator_times_out_a_request_the_necessary_rust_participant_never_answers_and_the_locks_go()
{
    use canton_participant::{
        confirmation_wire::Outcome,
        view_acs::{Ledger, Timeouts, VerdictKind},
        view_conformance as vc,
    };
    let mut n = rust_must_confirm_a_settle(&unique("r-silent"));
    let engine = rust_engine();
    let timeouts = synchronizer_timeouts(&mut n.connection, &n.identity, &n.token);
    assert_eq!(
        timeouts,
        Timeouts::default(),
        "the sandbox runs with the default limits"
    );
    let mut ledger = Ledger::new();
    vc::import_contract(&engine, &mut ledger, &n.blob).unwrap();
    // the participant validates and would approve ... but says nothing
    let secret = *n.identity.encryption_secret();
    let decision = decide_as_rust(&mut n, &engine, &mut ledger, secret);
    assert_eq!(decision.outcome, Outcome::Approve);
    assert_eq!(
        ledger.in_flight(),
        1,
        "the request is in flight and locks the contract"
    );
    // the mediator does not get a response from a party that has to confirm: it finalizes the request as timed out
    let verdict =
        verdict_of(&mut n).expect("the mediator finalizes the request without the answer");
    assert_eq!(
        verdict.kind,
        VerdictKind::MediatorReject { malformed: false },
        "{verdict:?}"
    );
    assert!(!verdict.approved);
    assert!(
        verdict
            .reason
            .contains("did not receive sufficient confirmations"),
        "{}",
        verdict.reason
    );
    // the log names the party that did not answer, and the time the mediator writes is the decision time this participant computed
    let block = finalized_block_at(n.request_time);
    assert!(block.contains("MEDIATOR_SAYS_TX_TIMED_OUT"), "{block}");
    assert!(
        block.contains(&format!("unresponsiveParties=>{}", n.party)),
        "{block}"
    );
    assert!(
        block.contains(&format!(
            "at {}",
            iso_micros(timeouts.decision_time(n.request_time))
        )),
        "the decision time is {}: {block}",
        iso_micros(timeouts.decision_time(n.request_time))
    );
    // the verdict frees the locks: nothing was consumed and the contract can be used again
    assert!(ledger
        .resolve(verdict.request_id, verdict.approved)
        .unwrap());
    assert!(ledger.is_active(&n.contract_id));
    assert_eq!(ledger.in_flight(), 0);
    ledger
        .begin(
            n.request_time + 1,
            canton_participant::view_acs::Effects {
                consumes: vec![n.contract_id.clone()],
                creates: vec![],
                instances: vec![],
                remote_events: vec![],
            },
        )
        .expect("the contract is not locked any more");
}

#[test]
fn an_answer_after_the_deadline_does_not_change_the_verdict() {
    use canton_participant::{
        view_acs::{Ledger, Timeouts},
        view_conformance as vc,
    };
    let mut n = rust_must_confirm_a_settle(&unique("r-late"));
    let engine = rust_engine();
    let timeouts = Timeouts::default();
    let mut ledger = Ledger::new();
    vc::import_contract(&engine, &mut ledger, &n.blob).unwrap();
    let secret = *n.identity.encryption_secret();
    let decision = decide_as_rust(&mut n, &engine, &mut ledger, secret);
    // wait for the verdict (the mediator times the request out), then answer all the same
    let verdict = verdict_of(&mut n).expect("a verdict");
    assert!(!verdict.approved);
    let now = n
        .connection
        .sequencer_time(
            &n.identity.member(),
            &var("CANTON_RS_EXPECT_SYNCHRONIZER"),
            Some(&n.token),
        )
        .unwrap()
        .unwrap();
    assert!(
        timeouts.too_late(n.request_time, now),
        "an answer sent now is after the response deadline"
    );
    send_answer(&mut n, &decision);
    std::thread::sleep(std::time::Duration::from_secs(4));
    // the request is finalized once, as timed out; the late approval changed nothing
    let request = iso_micros(n.request_time);
    let finalizations = node_log()
        .lines()
        .filter(|l| {
            l.contains("mediator=m1")
                && l.contains("Phase 6: Finalized request")
                && l.contains(&format!("RequestId({request})"))
        })
        .count();
    assert_eq!(finalizations, 1, "the request is finalized exactly once");
    // the mediator says it dropped the answer, and why
    let dropped = log_line_with(&[
        "mediator=m1",
        "WARN",
        &format!("is too late as request RequestId({request})"),
    ])
    .expect("the mediator reports the late response");
    // [CANTON-NOTE: SEMANTICS] the warning names the response deadline, which is the request time plus the response timeout: the
    // same instant this participant computes
    assert!(
        dropped.contains("exceeded the participant response deadline")
            && dropped.contains(&format!(
                "[{}]",
                iso_micros(timeouts.response_deadline(n.request_time))
            )),
        "{dropped}"
    );
    ledger
        .resolve(verdict.request_id, verdict.approved)
        .unwrap();
    assert!(ledger.is_active(&n.contract_id));
}

#[test]
fn a_participant_that_never_gets_the_verdict_rejects_the_request_at_the_decision_time() {
    use canton_participant::{
        view_acs::{Ledger, Timeouts},
        view_conformance as vc,
    };
    let mut n = rust_must_confirm_a_settle(&unique("r-nover"));
    let engine = rust_engine();
    let timeouts = Timeouts::default();
    let mut ledger = Ledger::new();
    vc::import_contract(&engine, &mut ledger, &n.blob).unwrap();
    let secret = *n.identity.encryption_secret();
    decide_as_rust(&mut n, &engine, &mut ledger, secret);
    assert_eq!(ledger.in_flight(), 1);
    // events up to the decision time carry no verdict (the participant is cut off from it): nothing expires before the decision time
    assert!(ledger
        .expire(timeouts.decision_time(n.request_time) - 1)
        .unwrap()
        .is_empty());
    assert!(
        !ledger.is_active("not there"),
        "unrelated state is untouched"
    );
    // the sequencing time of the next event is at or after the decision time: the request is treated as rejected
    assert_eq!(
        ledger
            .expire(timeouts.decision_time(n.request_time))
            .unwrap(),
        vec![n.request_time]
    );
    assert!(ledger.is_active(&n.contract_id) && ledger.in_flight() == 0);
    // and the verdict that does arrive later (the mediator's) is ignored: the request is decided
    assert!(!ledger.resolve(n.request_time, true).unwrap());
    assert!(
        ledger.is_active(&n.contract_id),
        "a late approval cannot consume what a rejected request did not"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// S-NET-023 (G5 5.6o): the event loop. The participant runtime reads the sequenced events from a cursor and does by itself what the
// earlier tests did by hand: validate, decide, answer, apply verdicts, expire, and remember where it is.
// ---------------------------------------------------------------------------------------------------------------------

use canton_participant::participant_runtime as rt;

/// A Rust participant whose runtime followed p1 creating a contract for `erin` and then settling it, with erin's confirmation
/// threshold raised to 2 in between so that the runtime's answer to the settle is **necessary** for the mediator.
struct LoopRun {
    identity: canton_participant::topology_wire::ParticipantIdentity,
    connection: SequencerConnect,
    token: canton_participant::sequencer_connect::Token,
    runtime: rt::Runtime,
    steps: Vec<rt::Step>,
    contract_id: String,
    party: String,
    p1_keys: Vec<SigningKey>,
    mediator_keys: Vec<SigningKey>,
    state_dir: std::path::PathBuf,
    /// The sequencing time the runtime started from.
    start: i64,
}

fn runtime_follows_p1(name: &str) -> LoopRun {
    runtime_follows_p1_with(name, false)
}

/// With `learn`, the runtime is opened **before** the party is hosted and is given neither the party nor any key: it has to read
/// them from the topology state (and read it again when the hosting changes).
fn runtime_follows_p1_with(name: &str, learn: bool) -> LoopRun {
    use canton_participant::topology_wire as tw;
    let (r, mut c, token) = authenticated(name);
    let sync_id = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let before_hosting = c
        .sequencer_time(&r.member(), &sync_id, Some(&token))
        .unwrap()
        .unwrap();
    let erin = host_consortium_party(&r, &mut c, &token, "erin");
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |extension: &str, content: String| {
        let name = format!("{}.{extension}", unique(extension));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let start = if learn {
        before_hosting
    } else {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let state_dir = state_dir(name);
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys.clone(),
        mediator_keys.clone(),
        canton_participant::view_acs::Timeouts::default(),
    );
    if learn {
        config.hosted_parties = vec![];
        config.submitter_keys = vec![];
        config.mediator_keys = vec![];
        config.follow_topology = true;
    }
    let mut runtime = rt::Runtime::open(config, rust_engine(), Some(&state_dir), start).unwrap();
    // 1. p1 creates a contract owned by erin; the runtime follows it to the point where the mediator approved it
    let created = command("submit", format!("{alice},{erin},{alice},100.0"));
    let line = log_line_with(&["SCF created=", &created]).expect("p1 creates the contract");
    let contract_id = line.rsplit('=').next().unwrap().trim().to_string();
    assert_ne!(contract_id, "?", "{line}");
    let mut steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 90, |rt| {
        rt.ledger.is_active(&contract_id)
    });
    assert!(
        runtime.ledger.is_active(&contract_id),
        "the runtime follows the creation: {steps:#?}"
    );
    // 2. erin needs both hosts from now on; the runtime reads the topology change like any other event
    let bytes = tw::party_to_participant_at_serial(&erin, &[(&p1_uid, 1), (&r.uid(), 2)], 2, 2);
    let raise = tw::signed(
        bytes.clone(),
        vec![r.namespace_key.sign_transaction(&bytes)],
    );
    let raise_hash = tx_hash_in_log(&raise.transaction);
    broadcast(&r, &mut c, &token, &[raise]);
    log_line_with(&[
        "participant=p1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{raise_hash}"),
    ])
    .expect("p1 stores the new threshold");
    std::thread::sleep(std::time::Duration::from_secs(2));
    // 3. p1 settles the contract; only the runtime's own answer can make the mediator approve
    command("exercise", format!("{alice},{contract_id},Settle"));
    steps.extend(run_until(
        &mut runtime,
        &mut c,
        &token,
        &r.signing_key,
        90,
        |rt| rt.ledger.archived_by(&contract_id).is_some(),
    ));
    LoopRun {
        identity: r,
        connection: c,
        token,
        runtime,
        steps,
        contract_id,
        party: erin,
        p1_keys,
        mediator_keys,
        state_dir,
        start,
    }
}

#[test]
fn the_runtime_follows_p1_from_a_creation_to_the_consumption_and_answers_the_settle_by_itself() {
    use canton_participant::confirmation_wire::Outcome;
    let run = runtime_follows_p1(&unique("r-loop"));
    let archived_by = run
        .runtime
        .ledger
        .archived_by(&run.contract_id)
        .expect("the contract is archived by the settle");
    assert!(!run.runtime.ledger.is_active(&run.contract_id));
    assert_eq!(
        run.runtime.ledger.in_flight(),
        0,
        "nothing is left in flight"
    );
    // the runtime answered the settle itself, as the party's second host, and the mediator approved on that
    let answers: Vec<&rt::ToSend> = run.steps.iter().flat_map(|s| &s.to_send).collect();
    let settle = answers
        .iter()
        .find(|a| a.request_time == archived_by)
        .expect("the runtime answered the settle");
    assert_eq!(settle.decision().outcome, Outcome::Approve, "{settle:?}");
    assert_eq!(
        settle.decision().confirming_parties,
        vec![run.party.clone()]
    );
    let finalized = finalized_at(archived_by);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
    // verdicts were applied from the events: the create and the settle
    let verdicts: Vec<(i64, bool)> = run.steps.iter().flat_map(|s| s.verdicts.clone()).collect();
    assert!(
        verdicts.iter().any(|(t, ok)| *t == archived_by && *ok),
        "{verdicts:?}"
    );
    assert!(
        verdicts.len() >= 2,
        "the create's verdict and the settle's: {verdicts:?}"
    );
    // the cursor moved past the settle and is on disk
    assert!(run.runtime.cursor() > archived_by);
    let saved = std::fs::read_to_string(run.state_dir.join("cursor")).unwrap();
    // the saved value starts with the cursor; the rest is what the next event is checked against (the last event handled)
    assert_eq!(
        saved.split_whitespace().next(),
        Some(run.runtime.cursor().to_string().as_str())
    );
    let _ = std::fs::remove_dir_all(&run.state_dir);
}

#[test]
fn a_restarted_runtime_continues_at_its_cursor_and_reading_the_events_again_answers_nothing_twice()
{
    let run = runtime_follows_p1(&unique("r-loop-restart"));
    let LoopRun {
        identity,
        mut connection,
        token,
        runtime,
        steps,
        contract_id,
        party,
        p1_keys,
        mediator_keys,
        state_dir,
        start,
    } = run;
    let end = runtime.cursor();
    let answered_before = steps.iter().flat_map(|s| &s.to_send).count();
    assert!(answered_before >= 1, "something was answered");
    drop(runtime);
    let config = || {
        runtime_config(
            &identity,
            &party,
            p1_keys.clone(),
            mediator_keys.clone(),
            canton_participant::view_acs::Timeouts::default(),
        )
    };
    // a restart: the state directory has the contract set and the cursor
    let mut again = rt::Runtime::open(config(), rust_engine(), Some(&state_dir), start).unwrap();
    assert_eq!(
        again.cursor(),
        end,
        "it continues where it stopped, not where it was told to start"
    );
    assert!(
        again.ledger.archived_by(&contract_id).is_some(),
        "the contract set is back"
    );
    // reading everything again, from the start
    again.rewind(start).unwrap();
    let replay = run_until(
        &mut again,
        &mut connection,
        &token,
        &identity.signing_key,
        20,
        |rt| rt.cursor() >= end,
    );
    assert!(!replay.is_empty(), "the events are read again");
    assert!(
        replay.iter().all(|s| s.to_send.is_empty()),
        "nothing is answered twice: {replay:#?}"
    );
    let noted = replay
        .iter()
        .flat_map(|s| &s.notes)
        .filter(|n| n.contains("already answered"))
        .count();
    assert!(
        noted >= answered_before,
        "each answered request is recognised: {replay:#?}"
    );
    assert!(again.ledger.archived_by(&contract_id).is_some());
    assert_eq!(again.ledger.in_flight(), 0);
    assert!(again.cursor() >= end);
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn an_answer_that_would_reach_the_mediator_after_its_deadline_is_not_sent() {
    let run = runtime_follows_p1(&unique("r-loop-late"));
    let LoopRun {
        identity,
        mut connection,
        token,
        runtime,
        contract_id,
        party,
        p1_keys,
        mediator_keys,
        state_dir,
        start,
        ..
    } = run;
    drop(runtime);
    // a participant that starts from scratch with a synchronizer whose deadlines are one second: everything it reads is old
    let tiny = canton_participant::view_acs::Timeouts {
        confirmation_response_micros: 1_000_000,
        mediator_reaction_micros: 1_000_000,
    };
    let fresh_state = state_dir.with_extension("late");
    let _ = std::fs::remove_dir_all(&fresh_state);
    let mut late = rt::Runtime::open(
        runtime_config(&identity, &party, p1_keys, mediator_keys, tiny),
        rust_engine(),
        Some(&fresh_state),
        start,
    )
    .unwrap();
    let end = {
        let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
        connection
            .sequencer_time(&identity.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let steps = run_until(
        &mut late,
        &mut connection,
        &token,
        &identity.signing_key,
        30,
        |rt| rt.cursor() >= end,
    );
    assert!(steps.iter().all(|s| s.to_send.is_empty()), "{steps:#?}");
    let too_late = steps
        .iter()
        .flat_map(|s| &s.notes)
        .filter(|n| n.contains("too late"))
        .count();
    assert!(
        too_late >= 1,
        "the old requests were decided but not answered: {steps:#?}"
    );
    // what it decided is still recorded: it does not answer them later either
    assert!(late.ledger.knows_request(
        steps
            .iter()
            .flat_map(|s| &s.notes)
            .find_map(|n| n
                .strip_prefix("the answer to ")
                .and_then(|r| r.split(' ').next())
                .and_then(|t| t.parse::<i64>().ok()))
            .expect("a request time in a note")
    ));
    assert!(
        !late.ledger.is_active(&contract_id) || late.ledger.archived_by(&contract_id).is_some()
    );
    let _ = std::fs::remove_dir_all(&state_dir);
    let _ = std::fs::remove_dir_all(&fresh_state);
}

#[test]
fn a_runtime_that_is_given_nothing_learns_what_it_hosts_and_whom_to_trust_from_the_topology() {
    use canton_participant::confirmation_wire::Outcome;
    let run = runtime_follows_p1_with(&unique("r-loop-topo"), true);
    // what it learned is the topology's: the party it hosts, the mediator's and p1's keys (it was given none)
    assert_eq!(run.runtime.config.hosted_parties, vec![run.party.clone()]);
    assert_eq!(run.runtime.config.mediator_keys, run.mediator_keys);
    assert!(
        run.p1_keys
            .iter()
            .all(|k| run.runtime.config.submitter_keys.contains(k)),
        "p1's keys are among the keys it trusts"
    );
    assert!(
        !run.runtime.config.submitter_keys.is_empty()
            && !run
                .runtime
                .config
                .submitter_keys
                .iter()
                .any(|k| k.id == run.identity.signing_key.fingerprint),
        "its own key is not one it trusts a request to be signed with"
    );
    // and it acted on it: followed the creation, answered the settle (necessary at threshold 2), the mediator approved
    let archived_by = run
        .runtime
        .ledger
        .archived_by(&run.contract_id)
        .expect("the contract is archived by the settle");
    let answer = run
        .steps
        .iter()
        .flat_map(|s| &s.to_send)
        .find(|a| a.request_time == archived_by)
        .expect("the runtime answered the settle");
    assert_eq!(answer.decision().outcome, Outcome::Approve);
    assert!(finalized_at(archived_by).contains("with verdict Approve"));
    assert!(
        run.steps.iter().any(|s| s.topology_changed),
        "it saw the topology changes (hosting, threshold) go by"
    );
    let _ = std::fs::remove_dir_all(&run.state_dir);
}

#[test]
fn the_runtime_follows_a_hosting_only_when_it_is_authorized_in_the_right_namespaces() {
    use canton_participant::topology_wire as tw;
    let (r, mut c, token) = authenticated(&unique("r-loop-auth"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let dir = state_dir("auth");
    let mut config = runtime_config(
        &r,
        "",
        vec![],
        vec![],
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![];
    config.follow_topology = true;
    let mut runtime = rt::Runtime::open(config, rust_engine(), Some(&dir), start).unwrap();
    // dave: signed by the participant's protocol key, which no delegation authorizes; carol: signed by the party's namespace,
    // which is also the namespace of the only participant that hosts her
    let dave = tw::party_to_participant(&r.party_id("dave"), &r.uid());
    let forged = tw::signed(dave.clone(), vec![r.signing_key.sign_transaction(&dave)]);
    let carol = tw::party_to_participant(&r.party_id("carol"), &r.uid());
    let proper = tw::signed(
        carol.clone(),
        vec![r.namespace_key.sign_transaction(&carol)],
    );
    broadcast(&r, &mut c, &token, &[forged, proper]);
    let steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 40, |rt| {
        rt.config.hosted_parties.contains(&r.party_id("carol"))
    });
    assert_eq!(
        runtime.config.hosted_parties,
        vec![r.party_id("carol")],
        "carol is followed, dave is not: {steps:#?}"
    );
    let notes: Vec<&String> = steps.iter().flat_map(|s| &s.notes).collect();
    assert!(
        // T-6: an unauthorized transaction that is not a proposal is refused, not kept waiting (`TopologyStateProcessor`)
        notes
            .iter()
            .any(|n| n.contains(&r.party_id("dave")) && n.contains("not authorized")),
        "dave's transaction is refused as unauthorized: {notes:#?}"
    );
    assert!(notes
        .iter()
        .any(|n| n.contains(&r.party_id("carol")) && n.contains("is in force")));
    // the broadcasts are in the journal, so a restart follows the same topology without reading the events again
    let journal = std::fs::read_to_string(dir.join("topology.journal")).unwrap();
    assert!(journal.lines().count() >= 2, "{journal}");
    let mut again = rt::Runtime::open(
        {
            let mut cfg = runtime_config(
                &r,
                "",
                vec![],
                vec![],
                canton_participant::view_acs::Timeouts::default(),
            );
            cfg.hosted_parties = vec![];
            cfg.follow_topology = true;
            cfg
        },
        rust_engine(),
        Some(&dir),
        start,
    )
    .unwrap();
    again.load_topology(&mut c, &token).unwrap();
    assert_eq!(again.config.hosted_parties, vec![r.party_id("carol")]);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------------------------------------
// S-NET-025 (G5 5.6q): the Rust participant **submits an exercise**. It built creates since S-NET-011; here it builds the view of a
// consuming exercise of a contract it created, and p1 (which hosts the signatory with it, and the observer) has to accept it.
// ---------------------------------------------------------------------------------------------------------------------

/// Sends a request whose one root view has `vpd` as its participant data, as the submitting participant for `erin`, and answers it
/// for the admin party (p1 confirms `erin`). Returns the sequencing time of the request and its root hash.
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn rust_sends_a_root_view_to_p1(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    parties: &[&str],
    vpd: &canton_participant::merkle_wire::LeafNode,
    uuid: &str,
    now: Option<i64>,
    created_signatories: &[&str],
) -> (i64, Vec<u8>) {
    use canton_participant::{
        confirmation_wire as cw, merkle_wire as mw, sequencing_wire as sw, view_message as vm,
    };
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let p1_key = p1_encryption_key(c, r, token);
    let now = now.unwrap_or_else(|| {
        c.sequencer_time(&r.member(), &synchronizer, Some(token))
            .unwrap()
            .unwrap()
    });
    let uid = r.member().trim_start_matches("PAR::").to_string();
    let common = mw::common_metadata(&synchronizer, 0, &fresh("cm"), uuid);
    let participant = mw::participant_metadata(now, now, None, &fresh("pm"));
    let submitter = mw::submitter_metadata(
        &mw::SubmitterInfo {
            act_as: parties.to_vec(),
            user_id: "rust-user",
            command_id: &unique("cmd"),
            submitting_participant_uid: &uid,
            submission_id: None,
            dedup_duration: (300, 0),
            max_sequencing_time_micros: now + 60_000_000,
        },
        &fresh("sm"),
    );
    let admin = r.uid();
    let mut informees: Vec<String> = parties.iter().map(|p| p.to_string()).collect();
    informees.push(alice.clone());
    informees.push(admin.clone());
    informees.sort();
    informees.dedup();
    let informee_refs: Vec<&str> = informees.iter().map(String::as_str).collect();
    let mut confirmers: Vec<(&str, i32)> = parties.iter().map(|p| (*p, 1)).collect();
    confirmers.push((admin.as_str(), 1));
    confirmers.sort();
    let threshold = confirmers.len() as i32;
    // [CANTON-NOTE: SEMANTICS] Measured on a `Transfer` p1 submitted: an exercise that **creates contracts in its view** has a
    // **second quorum** after the one of the parties that authorize the action (actors, signatories of the input, the admin
    // party): the **signatories of the created contracts**, each weight 1, without the admin party.
    let mut quorums = vec![mw::QuorumSpec {
        confirmers,
        threshold,
    }];
    if !created_signatories.is_empty() {
        let mut created: Vec<(&str, i32)> = created_signatories.iter().map(|p| (*p, 1)).collect();
        created.sort();
        let threshold = created.len() as i32;
        quorums.push(mw::QuorumSpec {
            confirmers: created,
            threshold,
        });
    }
    let vcd = mw::view_common_data(&informee_refs, &quorums, &fresh("vcd"));
    let view = |participant_data: &mw::Tree| {
        mw::view_node(
            &mw::Tree::leaf(&vcd),
            participant_data,
            &mw::merkle_seq(&[]),
        )
    };
    let full_view = view(&mw::Tree::leaf(vpd));
    let full = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::leaf(&participant),
        &mw::merkle_seq(std::slice::from_ref(&full_view)),
    );
    let informee = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::blinded(participant.root_hash()),
        &mw::merkle_seq(&[view(&mw::Tree::blinded(vpd.root_hash()))]),
    );
    assert_eq!(full.root_hash, informee.root_hash);
    let encrypted = vm::encrypted_view_message(
        &vm::light_view_tree(&full),
        &full_view.hash,
        &fresh("randomness")[..16].try_into().unwrap(),
        &fresh("gcm-iv")[..12].try_into().unwrap(),
        &[
            vm::Recipient {
                encryption_spki: &p1_key,
                fingerprint: &var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
                ecies_iv: fresh("ecies-iv")[..16].try_into().unwrap(),
                ecies_ephemeral_scalar: fresh("ecies-eph"),
            },
            vm::Recipient {
                encryption_spki: r.encryption_spki(),
                fingerprint: &r.encryption_fingerprint(),
                ecies_iv: fresh("ecies-iv2")[..16].try_into().unwrap(),
                ecies_ephemeral_scalar: fresh("ecies-eph2"),
            },
        ],
        &synchronizer,
        r.signing_key.sign_bytes(&full.root_hash),
    );
    let mediator = cw::mediator_group(0);
    let message_id = unique("exercise");
    let request = sw::submission_request_to_groups(
        &r.member(),
        &message_id,
        &[
            (
                vec![mediator.clone()],
                cw::informee_message(&informee, &r.signing_key),
            ),
            (
                vec![mediator.clone(), var("CANTON_RS_MEMBER_P1")],
                cw::root_hash_message(&full.root_hash, &synchronizer, now),
            ),
            (
                vec![mediator, r.member()],
                cw::root_hash_message(&full.root_hash, &synchronizer, now),
            ),
            (vec![var("CANTON_RS_MEMBER_P1"), r.member()], encrypted),
        ],
        now + 60_000_000,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        token,
        sw::signed_submission_request(request, &r.signing_key),
    )
    .expect("the sequencer accepts the request");
    let mut from = now + 1;
    let request_id = loop {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                token,
                Some(from),
                1,
                std::time::Duration::from_secs(10),
            )
            .expect("subscribe");
        let d = sw::decode_delivered(events.first().expect("our request comes back")).unwrap();
        from = d.timestamp_micros + 1;
        if d.message_id.as_deref() == Some(message_id.as_str()) {
            break d.timestamp_micros;
        }
    };
    let (content, signatures) = cw::confirmation_responses(
        request_id,
        &full.root_hash,
        &synchronizer,
        &r.member(),
        &[cw::ViewResponse {
            view_position: &[vec![]],
            outcome: cw::Outcome::Approve,
            confirming_parties: std::slice::from_ref(&admin),
        }],
        &r.signing_key,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        token,
        sw::signed_submission_request(
            sw::submission_request_signed(
                &r.member(),
                &unique("resp"),
                &[(vec![cw::mediator_group(0)], content, signatures)],
                request_id + 30_000_000,
            ),
            &r.signing_key,
        ),
    )
    .expect("the sequencer accepts the responses");
    (request_id, full.root_hash.clone())
}

/// The participant data of a consuming `Settle` of the contract `created`, exercised by `erin`.
fn settle_view_of(
    created: &SampleCreated,
    erin: &str,
) -> canton_participant::merkle_wire::LeafNode {
    settle_view_by(created, &[erin])
}

/// Like [`settle_view_of`], with the actors the view names (a view whose actors are not the choice's controllers is wrong).
fn settle_view_by(
    created: &SampleCreated,
    actors: &[&str],
) -> canton_participant::merkle_wire::LeafNode {
    use canton_participant::merkle_wire as mw;
    // [CANTON-NOTE: SEMANTICS] `Settle` takes no argument: its chosen value is the versioned unit (`version "2.1"`, `Value.unit`).
    let chosen_value = [10, 3, b'2', b'.', b'1', 18, 2, 106, 0];
    mw::view_participant_data_exercise(
        &created.instance,
        true,
        &[],
        &mw::ExerciseSpec {
            interface_id: None,
            package_preference: &[],
            contract_id_hex: &created.id_hex,
            template_id: &format!(
                "{}:AssetHolding:AssetHolding",
                var("CANTON_RS_SAMPLE_PACKAGE")
            ),
            choice: "Settle",
            chosen_value: &chosen_value,
            actors,
            node_seed: &fresh("exercise-node-seed"),
        },
        &fresh("vpd-salt"),
    )
}

#[test]
fn p1_accepts_a_consuming_exercise_that_the_rust_participant_submitted_and_the_mediator_approves_it(
) {
    let (r, mut c, token) = authenticated(&unique("r-submit-settle"));
    let erin = host_party_and_vet_sample(&r, &mut c, &token, "erin", true);
    let created = rust_creates_sample(&r, &mut c, &token, &erin, &erin, "100.0", false, true);
    let create_verdict = finalized_at(created.request_id);
    assert!(
        create_verdict.contains("with verdict Approve"),
        "{create_verdict}"
    );
    let (request_id, _) = rust_sends_a_root_view_to_p1(
        &r,
        &mut c,
        &token,
        &[&erin],
        &settle_view_of(&created, &erin),
        &fresh_uuid(),
        None,
        &[],
    );
    let finalized = finalized_block_at(request_id);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn p1_rejects_a_second_exercise_of_a_contract_the_first_one_consumed() {
    let (r, mut c, token) = authenticated(&unique("r-submit-twice"));
    let erin = host_party_and_vet_sample(&r, &mut c, &token, "erin", true);
    let created = rust_creates_sample(&r, &mut c, &token, &erin, &erin, "100.0", false, true);
    assert!(finalized_at(created.request_id).contains("with verdict Approve"));
    let (first, _) = rust_sends_a_root_view_to_p1(
        &r,
        &mut c,
        &token,
        &[&erin],
        &settle_view_of(&created, &erin),
        &fresh_uuid(),
        None,
        &[],
    );
    assert!(finalized_block_at(first).contains("with verdict Approve"));
    // the same contract again: p1's contract store no longer has it active
    let (second, _) = rust_sends_a_root_view_to_p1(
        &r,
        &mut c,
        &token,
        &[&erin],
        &settle_view_of(&created, &erin),
        &fresh_uuid(),
        None,
        &[],
    );
    let finalized = finalized_block_at(second);
    assert!(
        finalized.contains("ParticipantReject")
            && finalized.contains("LOCAL_VERDICT_INACTIVE_CONTRACTS")
            && finalized.contains(&created.id_hex),
        "{finalized}"
    );
}

#[test]
fn p1_rejects_an_exercise_whose_actor_is_not_the_controller_of_the_choice() {
    let (r, mut c, token) = authenticated(&unique("r-submit-actor"));
    let erin = host_party_and_vet_sample(&r, &mut c, &token, "erin", true);
    let created = rust_creates_sample(&r, &mut c, &token, &erin, &erin, "100.0", false, true);
    assert!(finalized_at(created.request_id).contains("with verdict Approve"));
    // `Settle` is controlled by the bank (erin); the view names alice instead
    let alice = var("CANTON_RS_ALICE");
    let (request_id, _) = rust_sends_a_root_view_to_p1(
        &r,
        &mut c,
        &token,
        &[&erin],
        &settle_view_by(&created, &[alice.as_str()]),
        &fresh_uuid(),
        None,
        &[],
    );
    let finalized = finalized_block_at(request_id);
    // p1 cannot reconstruct what the view says (the actors are not the controllers its engine computes): a malformed request,
    // reported without detail ("a security-sensitive error")
    assert!(
        finalized.contains("ParticipantReject")
            && finalized.contains("isMalformed = true")
            && finalized.contains("reported by PAR::p1"),
        "{finalized}"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// S-NET-026 (G5 5.6r): the discriminator of every contract id a view creates is checked against the node seed, the preparation
// time and the stakeholders — for a root create and for a contract created inside an exercise.
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn the_discriminator_of_a_contract_p1_creates_is_the_one_its_node_seed_gives() {
    use canton_participant::view_conformance::{check_discriminators, Nonconformance as N};
    use canton_participant::view_receive as vr;
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    let got = rust_receives_a_view_from_p1(&unique("r-disc-create"));
    let r = &got.identity;
    let views = vr::decrypt_views(
        &got.view_envelope,
        &r.encryption_fingerprint(),
        r.encryption_secret(),
    )
    .unwrap();
    let tree = views.view_trees[0].tree.as_ref().unwrap();
    let view = vr::revealed_root_views(tree).unwrap().remove(0);
    let prepared = vr::revealed_participant_metadata(tree)
        .expect("a participant that gets the view sees the participant metadata")
        .preparation_time;
    assert_eq!(check_discriminators(&view, prepared), Ok(()));
    // the preparation time is part of what the discriminator commits to
    assert!(matches!(
        check_discriminators(&view, prepared + 1),
        Err(N::DiscriminatorDiffers { .. })
    ));
    // so is the node seed of the create node
    let mut other_seed = view.clone();
    let Some(Description::Create(c)) = other_seed
        .participant_data
        .action_description
        .as_mut()
        .and_then(|a| a.description.as_mut())
    else {
        panic!("a create")
    };
    c.node_seed[0] ^= 1;
    assert!(matches!(
        check_discriminators(&other_seed, prepared),
        Err(N::DiscriminatorDiffers { .. })
    ));
    // and the stakeholders: the same id with an observer added is another discriminator
    let other_stakeholders = with_changed_contract(&view, |fci, _| {
        fci.non_signatory_stakeholders
            .push(format!("zed::1220{}", "ee".repeat(32)))
    });
    assert!(matches!(
        check_discriminators(&other_stakeholders, prepared),
        Err(N::DiscriminatorDiffers { .. })
    ));
    // the discriminator itself: one bit of it
    let other_id = with_changed_contract(&view, |fci, _| fci.contract_id[1] ^= 1);
    assert!(matches!(
        check_discriminators(&other_id, prepared),
        Err(N::DiscriminatorDiffers { .. })
    ));
}

#[test]
fn the_discriminator_of_a_contract_created_inside_an_exercise_comes_from_a_seed_derived_from_the_exercises(
) {
    use canton_participant::view_conformance::{check_discriminators, Nonconformance as N};
    use canton_participant::view_receive as vr;
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    let alice = var("CANTON_RS_ALICE");
    let got =
        rust_receives_an_exercise_from_p1(&unique("r-disc-xfer"), "Transfer", true, Some(&alice));
    let r = &got.identity;
    let views = vr::decrypt_views(
        &got.view_envelope,
        &r.encryption_fingerprint(),
        r.encryption_secret(),
    )
    .unwrap();
    let tree = views.view_trees[0].tree.as_ref().unwrap();
    let view = vr::revealed_root_views(tree).unwrap().remove(0);
    assert_eq!(view.participant_data.created_core.len(), 1);
    let prepared = vr::revealed_participant_metadata(tree)
        .unwrap()
        .preparation_time;
    assert_eq!(check_discriminators(&view, prepared), Ok(()));
    assert!(matches!(
        check_discriminators(&view, prepared - 1),
        Err(N::DiscriminatorDiffers { .. })
    ));
    let mut other_seed = view.clone();
    let Some(Description::Exercise(e)) = other_seed
        .participant_data
        .action_description
        .as_mut()
        .and_then(|a| a.description.as_mut())
    else {
        panic!("an exercise")
    };
    e.node_seed[0] ^= 1;
    assert!(matches!(
        check_discriminators(&other_seed, prepared),
        Err(N::DiscriminatorDiffers { .. })
    ));
}

// ---------------------------------------------------------------------------------------------------------------------
// S-NET-028 (G5 5.7b): the ACS commitment p1 sends the Rust participant is the one the Rust participant computes from the contract
// they share.
// ---------------------------------------------------------------------------------------------------------------------

/// Waits for the wall clock to pass the next full minute (the reconciliation interval is 60 s) by `margin_secs` and returns that
/// boundary in microseconds. [CANTON-NOTE: SEMANTICS] The sandbox's nodes and this host share the clock.
fn wait_past_next_minute(margin_secs: u64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let boundary = (now / 60 + 1) * 60;
    std::thread::sleep(std::time::Duration::from_secs(boundary + margin_secs - now));
    boundary as i64 * 1_000_000
}

/// A Rust participant that shares a contract with p1 and the first commitment p1 sent it for that contract.
struct CommitmentRun {
    identity: canton_participant::topology_wire::ParticipantIdentity,
    connection: SequencerConnect,
    token: canton_participant::sequencer_connect::Token,
    erin: String,
    /// The first shared contract (the only one unless the run asked for more).
    contract_id: String,
    /// Every shared contract the run created, in order.
    contract_ids: Vec<String>,
    received: canton_participant::acs_commitment::ReceivedCommitment,
    /// The sequencing time of the request that made the **last** change of the shared set before the period ended.
    request_time: i64,
}

fn rust_gets_a_commitment(name: &str) -> CommitmentRun {
    rust_gets_a_commitment_for(name, 1)
}

/// Like [`rust_gets_a_commitment`], with `count` shared contracts created one after the other **within one reconciliation period**.
fn rust_gets_a_commitment_for(name: &str, count: usize) -> CommitmentRun {
    use canton_participant::{acs_commitment, sequencing_wire as sw};
    let (r, mut c, token) = authenticated(name);
    let erin = host_consortium_party(&r, &mut c, &token, "erin");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |extension: &str, content: String| {
        let name = format!("{}.{extension}", unique(extension));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let mut at = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    // the contract p1 and this participant share: both host `erin`, and `alice` (p1's) is the bank and the observer
    // [CANTON-NOTE: SEMANTICS] The changes have to fall into one reconciliation period (60 s): a period boundary between two of them
    // gives p1 a commitment that covers only the first. Several changes therefore start just after a boundary, which leaves the
    // rest of the minute for them even when the tests run in parallel against one node (a single change needs no alignment).
    if count > 1 {
        wait_past_next_minute(2);
    }
    let mut contract_ids = Vec::new();
    for i in 0..count {
        let created = command("submit", format!("{alice},{erin},{alice},{}.0", 100 + i));
        let line = log_line_with(&["SCF created=", &created]).expect("p1 creates the contract");
        contract_ids.push(line.rsplit('=').next().unwrap().trim().to_string());
    }
    let contract_id = contract_ids[0].clone();
    // a commitment is made when an event crosses a reconciliation boundary: wait past one, then give p1 an event that is not shared
    wait_past_next_minute(3);
    command("submit", format!("{alice},{alice},{alice},1.0"));
    let mut commitments = Vec::new();
    let mut times: Vec<(i64, &str)> = Vec::new();
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(150);
    while std::time::Instant::now() < patience && commitments.is_empty() {
        let got = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(at),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default();
        let Some(event) = got.first() else { continue };
        let d = sw::decode_delivered(event).expect("every event decodes");
        at = d.timestamp_micros + 1;
        commitments.extend(d.envelopes.iter().filter_map(|e| acs_commitment::decode(e)));
        // the sequencing times of what the contract's creation caused: the request and the mediator's verdict
        for e in &d.envelopes {
            if canton_participant::view_acs::decode_verdict(e).is_some() {
                times.push((d.timestamp_micros, "verdict"));
            } else if canton_participant::view_receive::root_hash_of_message(e).is_some() {
                times.push((d.timestamp_micros, "request"));
            }
        }
    }
    // the first commitment p1 sends after the contract exists covers the period that ends on the boundary after its creation
    let received = commitments
        .first()
        .unwrap_or_else(|| panic!("p1 sent no commitment"));
    let received = received.clone();
    let requests: Vec<i64> = times
        .iter()
        .filter(|(_, kind)| *kind == "request")
        .map(|(t, _)| *t)
        .collect();
    assert_eq!(
        requests.len(),
        count,
        "one request per shared contract came through this participant: {times:?}"
    );
    let request_time = *requests.iter().max().expect("a creation request");
    CommitmentRun {
        identity: r,
        connection: c,
        token,
        erin,
        contract_id,
        contract_ids,
        received,
        request_time,
    }
}

#[test]
fn p1_sends_the_rust_participant_the_commitment_the_rust_participant_computes_from_their_shared_contract(
) {
    use canton_participant::lthash;
    let run = rust_gets_a_commitment(&unique("r-cmt"));
    let (r, erin, contract_id, received) =
        (&run.identity, &run.erin, &run.contract_id, &run.received);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    assert_eq!(received.physical_synchronizer_id, synchronizer);
    assert_eq!(
        received.sender,
        var("CANTON_RS_MEMBER_P1").trim_start_matches("PAR::")
    );
    assert_eq!(received.counterparticipant, r.uid());
    assert_eq!(
        received.to_inclusive % 60_000_000,
        0,
        "the period ends on a reconciliation boundary"
    );
    // signed by p1: over `HashPurpose.AcsCommitment` (22) of the versioned commitment, with one of p1's signing keys
    let mut connection = run.connection;
    let p1_keys = p1_signing_keys(&mut connection, &run.identity, &run.token);
    let signature = received
        .signature
        .as_ref()
        .expect("the commitment is signed");
    assert!(
        verifies_with_any(
            &p1_keys,
            signature,
            &canton_participant::acs_commitment::signing_hash(&received.commitment_bytes)
        ),
        "p1's signature does not verify"
    );
    // what this participant computes: p1 hosts alice and erin, this participant hosts erin; the contract's stakeholders are both.
    // The digest p1 sends has an element for every pair of a party p1 hosts and a party this participant hosts.
    let mut set = lthash::LtHash16::empty();
    for local in [&alice, erin] {
        let (a, b) = lthash::ordered_pair(local, erin);
        set.add(&lthash::digest_element(contract_id, 0, a, b));
    }
    eprintln!(
        "COMMITMENT received={} computed={}",
        hex::encode(&received.digest),
        hex::encode(lthash::commitment_digest(&set))
    );
    assert_eq!(received.digest, lthash::commitment_digest(&set));
    // not the commitment of another contract set
    let mut other = lthash::LtHash16::empty();
    let (a, b) = lthash::ordered_pair(&alice, erin);
    other.add(&lthash::digest_element(contract_id, 0, a, b));
    assert_ne!(received.digest, lthash::commitment_digest(&other));
}

/// The Rust participant sends p1 a commitment for the period p1 used, with `digest`.
fn rust_sends_its_commitment(
    run: &mut CommitmentRun,
    digest: &[u8],
    from_exclusive: i64,
    to_inclusive: i64,
) {
    use canton_participant::{acs_commitment, sequencing_wire as sw};
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let r = &run.identity;
    let now = run
        .connection
        .sequencer_time(&r.member(), &synchronizer, Some(&run.token))
        .unwrap()
        .unwrap();
    let message = acs_commitment::commitment_message(
        &synchronizer,
        &r.uid(),
        run.received.sender.as_str(),
        from_exclusive,
        to_inclusive,
        digest,
        &r.signing_key,
    );
    run.connection
        .send_async(
            &r.member(),
            &synchronizer,
            &run.token,
            sw::signed_submission_request(
                sw::submission_request_to_groups(
                    &r.member(),
                    &unique("acs-commitment"),
                    &[(vec![var("CANTON_RS_MEMBER_P1")], message)],
                    now + 60_000_000,
                ),
                &r.signing_key,
            ),
        )
        .expect("the sequencer accepts the commitment");
}

/// What p1 logs about the commitment of `run`'s Rust participant once it has computed its own for the period: its line from the
/// commitment matcher. A checkpoint is made by an event after the next reconciliation boundary, so this gives p1 such an event.
fn p1_verdict_on_rusts_commitment(run: &CommitmentRun) -> Vec<String> {
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    wait_past_next_minute(3);
    let name = format!("{}.submit", unique("submit"));
    std::fs::write(
        dir.join(format!("{name}.tmp")),
        format!("{alice},{alice},{alice},1.0"),
    )
    .unwrap();
    std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
    let uid = run.identity.uid();
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let log = node_log();
        let mut lines: Vec<String> = log
            .lines()
            .filter(|l| l.contains("participant=p1") && l.contains(&uid) && l.contains("ommitment"))
            .map(str::to_string)
            .collect();
        // a mismatch is an alarm whose line does not necessarily name the sender
        let from = iso_micros(run.received.from_exclusive);
        let all: Vec<&str> = log.lines().collect();
        for (i, l) in all.iter().enumerate() {
            if l.contains("ACS_COMMITMENT_MISMATCH")
                && all[i..(i + 12).min(all.len())]
                    .iter()
                    .any(|x| x.contains(from.trim_end_matches('Z')))
            {
                lines.push(all[i..(i + 12).min(all.len())].join("\n"));
            }
        }
        // the matcher's line names the sender; the validator's "Checking commitment signature" line is only the first step
        if lines.iter().any(|l| {
            l.contains("ReceivedAcsCommitmentMatcher") || l.contains("ACS_COMMITMENT_MISMATCH")
        }) || std::time::Instant::now() > patience
        {
            return lines;
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}

fn iso(micros: i64) -> String {
    iso_micros(micros)
}

#[test]
fn p1_finds_the_commitment_the_rust_participant_sends_correct() {
    use canton_participant::lthash;
    let mut run = rust_gets_a_commitment(&unique("r-cmt-right"));
    let alice = var("CANTON_RS_ALICE");
    let mut set = lthash::LtHash16::empty();
    for local in [&alice, &run.erin] {
        let (a, b) = lthash::ordered_pair(local, &run.erin);
        set.add(&lthash::digest_element(&run.contract_id, 0, a, b));
    }
    // this participant derives the period itself, from the request it saw: it has to be the one p1 used
    let (from, to) = canton_participant::acs_commitment::period_after(run.request_time, 60_000_000);
    assert_eq!(
        (from, to),
        (run.received.from_exclusive, run.received.to_inclusive),
        "the period this participant derives is p1's"
    );
    rust_sends_its_commitment(&mut run, &lthash::commitment_digest(&set), from, to);
    let lines = p1_verdict_on_rusts_commitment(&run);
    let period = format!(
        "CommitmentPeriod(fromExclusive = {}, toInclusive = {})",
        iso(run.received.from_exclusive)
            .replace("000Z", "Z")
            .trim_end_matches('Z')
            .to_string()
            + "Z",
        iso(run.received.to_inclusive).replace(".000000Z", "Z"),
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Checking commitment signature") && l.contains(&period)),
        "p1 checked the signature: {period}\n{lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Commitment correct for sender") && l.contains(&period)),
        "p1 found it correct: {period}\n{lines:#?}"
    );
}

/// Several changes in one period: p1 created two contracts shared with this participant before the period ended. The digest is the sum
/// of the elements of both; the period is the one after the **last** change (`period_after` of the later request), which is the one
/// p1 used.
#[test]
fn p1_finds_the_commitment_for_two_contracts_created_in_one_period_correct() {
    use canton_participant::lthash;
    let mut run = rust_gets_a_commitment_for(&unique("r-cmt-two"), 2);
    let alice = var("CANTON_RS_ALICE");
    assert_eq!(run.contract_ids.len(), 2);
    let sum_of = |ids: &[String]| {
        let mut set = lthash::LtHash16::empty();
        for id in ids {
            for local in [&alice, &run.erin] {
                let (a, b) = lthash::ordered_pair(local, &run.erin);
                set.add(&lthash::digest_element(id, 0, a, b));
            }
        }
        lthash::commitment_digest(&set)
    };
    let both = sum_of(&run.contract_ids);
    // the sum is not the digest of either contract alone (so the check below can fail)
    assert_ne!(both, sum_of(&run.contract_ids[..1]));
    assert_ne!(both, sum_of(&run.contract_ids[1..]));
    // the received digest (p1's own computation) is the sum of both
    assert_eq!(
        run.received.digest, both,
        "p1's digest covers both contracts"
    );
    let (from, to) = canton_participant::acs_commitment::period_after(run.request_time, 60_000_000);
    assert_eq!(
        (from, to),
        (run.received.from_exclusive, run.received.to_inclusive),
        "the period after the last change is p1's"
    );
    rust_sends_its_commitment(&mut run, &both, from, to);
    let lines = p1_verdict_on_rusts_commitment(&run);
    let uid = run.identity.uid();
    assert!(
        lines
            .iter()
            // [CANTON-NOTE: WHY] one log line at a time: a mismatch alarm is gathered as a block of the lines after it, and that block can hold
            // another sender's "Commitment correct" line next to this sender's uid (the cause of this test's old intermittent failure)
            .flat_map(|l| l.lines())
            .any(|l| l.contains("Commitment correct for sender") && l.contains(&uid[..30])),
        "p1 found the two-contract commitment correct: {lines:#?}"
    );
}

#[test]
fn p1_flags_a_commitment_the_rust_participant_sends_for_another_contract_set() {
    use canton_participant::lthash;
    let mut run = rust_gets_a_commitment(&unique("r-cmt-wrong"));
    // a participant that thinks it shares nothing with p1
    let (from, to) = (run.received.from_exclusive, run.received.to_inclusive);
    rust_sends_its_commitment(
        &mut run,
        &lthash::commitment_digest(&lthash::LtHash16::empty()),
        from,
        to,
    );
    let lines = p1_verdict_on_rusts_commitment(&run);
    let uid = run.identity.uid();
    // p1 raises the alarm and names the sender
    let alarm = lines
        .iter()
        .find(|l| l.contains("ACS_COMMITMENT_MISMATCH"))
        .unwrap_or_else(|| panic!("p1 raised no mismatch alarm: {lines:#?}"));
    assert!(
        alarm.contains("The local commitment does not match the remote commitment"),
        "{alarm}"
    );
    assert!(
        alarm.contains(&uid[..30]),
        "the alarm names the sender: {alarm}"
    );
    assert!(
        !lines
            .iter()
            // [CANTON-NOTE: WHY] one log line at a time: a mismatch alarm is gathered as a block of the lines after it, and that block can hold
            // another sender's "Commitment correct" line next to this sender's uid (the cause of this test's old intermittent failure)
            .flat_map(|l| l.lines())
            .any(|l| l.contains("Commitment correct for sender") && l.contains(&uid[..30])),
        "a wrong commitment is not found correct: {lines:#?}"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// S-NET-029 (G5 5.6s): the Rust participant submits an exercise that **creates a contract in its view** (`Transfer`). The id of
// the new contract has to carry the discriminator derived from the exercise's node seed, and p1 re-derives it.
// ---------------------------------------------------------------------------------------------------------------------

/// Hosts the party `name` with p1 (this participant submits, p1 confirms) without vetting the sample package again.
fn host_party_only(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    name: &str,
) -> String {
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let hosting = r.shared_party_proposal(name, &p1_uid);
    let hash = tx_hash_in_log(&hosting.transaction);
    let full_hash = canton_participant::topology_wire::transaction_hash(&hosting.transaction);
    broadcast(r, c, token, &[hosting]);
    log_line_with(&[
        "participant=p1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{hash}"),
    ])
    .expect("p1 stores the transaction");
    have_p1_authorize(&full_hash);
    let p1_ns = p1_uid.split("::").nth(1).unwrap()[..12].to_string();
    log_line_with(&[
        "sequencer=s1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{hash}"),
        &r.namespace()[..12],
        &p1_ns,
    ])
    .expect("the synchronizer stores the party signed by both participants");
    std::thread::sleep(std::time::Duration::from_secs(2));
    r.party_id(name)
}

/// The participant data of `owner` exercising `Transfer` of the contract `created` (bank `bank`, owner `owner`) to `new_owner`,
/// with the contract the transfer creates in the core of the view. `flip_discriminator` damages the new contract's discriminator.
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn transfer_view_of(
    created: &SampleCreated,
    bank: &str,
    owner: &str,
    new_owner: &str,
    now: i64,
    uuid: &str,
    flip_discriminator: bool,
) -> canton_participant::merkle_wire::LeafNode {
    use canton_participant::contract_id as ci;
    use canton_participant::contract_wire::{authentication_data, ContractInstance, LfValue};
    use canton_participant::merkle_wire as mw;
    use canton_proto::com::digitalasset::daml::lf::transaction::Versioned;
    use canton_proto::com::digitalasset::daml::lf::value::{
        value::{record::Field, Record, Sum},
        Value,
    };
    use prost::Message;
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let package_id = var("CANTON_RS_SAMPLE_PACKAGE");
    let vpd_salt = fresh("vpd-salt");
    let exercise_seed = fresh("exercise-node-seed");
    // the new holding: the same bank, the new owner, the same auditor and amount (`create this with owner = newOwner`)
    let mut signatories = vec![bank.to_string(), new_owner.to_string()];
    signatories.sort();
    signatories.dedup();
    let mut stakeholders = vec![bank.to_string(), new_owner.to_string(), alice.clone()];
    stakeholders.sort();
    stakeholders.dedup();
    let salt = ci::contract_salt(&ci::SaltInputs {
        view_participant_data_salt: &vpd_salt,
        create_index: 0,
        view_position: &[vec![]],
        transaction_uuid: uuid,
        synchronizer_id: &synchronizer,
        mediator: "MGR::0",
    });
    let contract_hash = ci::lf_contract_hash(
        "sample-contract",
        &["AssetHolding".into()],
        &["AssetHolding".into()],
        &ci::HashValue::Record {
            module: vec!["AssetHolding".into()],
            name: vec!["AssetHolding".into()],
            fields: vec![
                ("bank".into(), ci::HashValue::Party(bank.to_string())),
                ("owner".into(), ci::HashValue::Party(new_owner.to_string())),
                ("auditor".into(), ci::HashValue::Party(alice.clone())),
                ("assetSymbol".into(), ci::HashValue::Text("USD".into())),
                ("amount".into(), ci::HashValue::Numeric(1_000_000_000_000)),
            ],
        },
    );
    let unicum = ci::unicum(
        &salt,
        &ci::UnicumInputs {
            created_at_micros: now,
            signatories: &signatories,
            stakeholders: &stakeholders,
            key: None,
            contract_hash: &contract_hash,
        },
    );
    // [CANTON-NOTE: SEMANTICS] The contract the exercise creates is the exercise node's first child: its node seed is
    // `deriveNodeSeed(exercise seed, 0)`, and its discriminator `HMAC(that seed, preparation time ++ stakeholders)`.
    let child_seed = ci::derive_node_seed(&exercise_seed, 0);
    let mut discriminator = ci::derive_contract_discriminator(&child_seed, now, &stakeholders);
    if flip_discriminator {
        discriminator[0] ^= 1;
    }
    let child_id = ci::contract_id(&discriminator, &unicum);
    let child = ContractInstance {
        contract_id: hex::decode(&child_id).unwrap(),
        package_name: "sample-contract".into(),
        package_id,
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        arg: LfValue::Record(vec![
            LfValue::Party(bank.to_string()),
            LfValue::Party(new_owner.to_string()),
            LfValue::Party(alice),
            LfValue::Text("USD".into()),
            LfValue::Numeric("100.0000000000".into()),
        ]),
        signatories: signatories.iter().cloned().collect(),
        stakeholders: stakeholders.iter().cloned().collect(),
        created_at_micros: now,
        authentication_data: authentication_data(&salt),
        key: None,
    }
    .encode();
    // the chosen value: the versioned record `{ newOwner }`
    let chosen_value = Versioned {
        version: "2.1".into(),
        payload: Value {
            sum: Some(Sum::Record(Record {
                fields: vec![Field {
                    value: Some(Value {
                        sum: Some(Sum::Party(new_owner.to_string())),
                    }),
                }],
            })),
        }
        .encode_to_vec(),
    }
    .encode_to_vec();
    mw::view_participant_data_exercise(
        &created.instance,
        true,
        &[(child.as_slice(), false)],
        &mw::ExerciseSpec {
            interface_id: None,
            package_preference: &[],
            contract_id_hex: &created.id_hex,
            template_id: &format!(
                "{}:AssetHolding:AssetHolding",
                var("CANTON_RS_SAMPLE_PACKAGE")
            ),
            choice: "Transfer",
            chosen_value: &chosen_value,
            actors: &[owner],
            node_seed: &exercise_seed,
        },
        &vpd_salt,
    )
}

/// `bank` (erin) and `owner` (fay) are both hosted by the Rust participant and p1; the Rust participant created the holding, and
/// p1 has it. Returns what is needed to exercise it.
fn rust_holds_a_two_party_holding(
    name: &str,
) -> (
    canton_participant::topology_wire::ParticipantIdentity,
    SequencerConnect,
    canton_participant::sequencer_connect::Token,
    String,
    String,
    SampleCreated,
) {
    let (r, mut c, token) = authenticated(name);
    let erin = host_party_and_vet_sample(&r, &mut c, &token, "erin", true);
    let fay = host_party_only(&r, &mut c, &token, "fay");
    let created = rust_creates_sample(&r, &mut c, &token, &erin, &fay, "100.0", false, true);
    let verdict = finalized_at(created.request_id);
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
    (r, c, token, erin, fay, created)
}

#[test]
fn p1_accepts_a_transfer_the_rust_participant_submitted_with_the_new_contract_in_the_view() {
    let (r, mut c, token, erin, fay, created) =
        rust_holds_a_two_party_holding(&unique("r-xfer-ok"));
    let now = c
        .sequencer_time(
            &r.member(),
            &var("CANTON_RS_EXPECT_SYNCHRONIZER"),
            Some(&token),
        )
        .unwrap()
        .unwrap();
    let uuid = fresh_uuid();
    let leaf = transfer_view_of(&created, &erin, &fay, &erin, now, &uuid, false);
    // what this participant's own receiver (the model of p1's check) says about the view before it is sent
    {
        use canton_participant::{view_conformance as vc, view_receive::RevealedView};
        use canton_proto::com::digitalasset::canton::protocol::v30::{
            CommonMetadata, ViewCommonData,
        };
        use canton_proto::com::digitalasset::canton::protocol::v32::ViewParticipantData;
        use prost::Message;
        let (data, _) = canton_participant::topology_wire::unversioned(&leaf.bytes).unwrap();
        let view = RevealedView {
            view_hash: vec![],
            common_data: ViewCommonData {
                informees: vec![erin.clone(), fay.clone(), var("CANTON_RS_ALICE"), r.uid()],
                ..Default::default()
            },
            participant_data: ViewParticipantData::decode(data.as_slice()).unwrap(),
            position: vec![vec![]],
            has_subviews: false,
        };
        let common = CommonMetadata {
            uuid: uuid.clone(),
            physical_synchronizer_id: var("CANTON_RS_EXPECT_SYNCHRONIZER"),
            mediator_group: 0,
            ..Default::default()
        };
        let engine = rust_engine();
        assert!(vc::check_exercise_view(&engine, &view, &common).is_ok());
        assert_eq!(vc::check_discriminators(&view, now), Ok(()));
    }
    let (request_id, _) = rust_sends_a_root_view_to_p1(
        &r,
        &mut c,
        &token,
        &[&erin, &fay],
        &leaf,
        &uuid,
        Some(now),
        &[&erin],
    );
    let finalized = finalized_block_at(request_id);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn p1_rejects_a_transfer_whose_new_contract_has_a_discriminator_that_is_not_derived_from_the_exercises_seed(
) {
    let (r, mut c, token, erin, fay, created) =
        rust_holds_a_two_party_holding(&unique("r-xfer-bad"));
    let now = c
        .sequencer_time(
            &r.member(),
            &var("CANTON_RS_EXPECT_SYNCHRONIZER"),
            Some(&token),
        )
        .unwrap()
        .unwrap();
    let uuid = fresh_uuid();
    let (request_id, _) = rust_sends_a_root_view_to_p1(
        &r,
        &mut c,
        &token,
        &[&erin, &fay],
        &transfer_view_of(&created, &erin, &fay, &erin, now, &uuid, true),
        &uuid,
        Some(now),
        &[&erin],
    );
    let finalized = finalized_block_at(request_id);
    // p1 re-derives the discriminator from the exercise's seed and cannot reconstruct the view: malformed
    assert!(
        finalized.contains("ParticipantReject") && finalized.contains("isMalformed = true"),
        "{finalized}"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// S-NET-030 (G5 5.6t): the receiver checks the quorums of a view's common data (who must confirm it) against its action and contracts.
// ---------------------------------------------------------------------------------------------------------------------

/// The first revealed view of `envelope` as the participant `r` receives it, and the admin party of the participant that submitted it.
fn view_and_admin(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    envelope: &[u8],
) -> (canton_participant::view_receive::RevealedView, String) {
    use canton_participant::view_receive as vr;
    let views =
        vr::decrypt_views(envelope, &r.encryption_fingerprint(), r.encryption_secret()).unwrap();
    let tree = views.view_trees[0].tree.as_ref().unwrap();
    let admin = vr::revealed_submitter_metadata(tree)
        .expect("a root view's submitter metadata is revealed")
        .submitting_participant_uid;
    (vr::revealed_root_views(tree).unwrap().remove(0), admin)
}

fn assert_quorums_checked(view: &canton_participant::view_receive::RevealedView, admin: &str) {
    use canton_participant::view_conformance::{check_quorums, Nonconformance as N};
    assert_eq!(
        check_quorums(view, Some(admin)),
        Ok(()),
        "the view p1 made has the quorums its contents give"
    );
    // a quorum that asks for more or fewer confirmations than it has members
    let mut lower = view.clone();
    lower.common_data.quorums[0].threshold -= 1;
    assert!(matches!(
        check_quorums(&lower, Some(admin)),
        Err(N::QuorumsDiffer(_))
    ));
    // the submitting participant's admin party is not among those who have to confirm
    assert!(matches!(
        check_quorums(view, Some("someone-else::1220aa")),
        Err(N::QuorumsDiffer(_))
    ));
    // a member left out
    let mut fewer = view.clone();
    let q = &mut fewer.common_data.quorums[0];
    q.party_index_and_weight.pop();
    q.threshold -= 1;
    assert!(matches!(
        check_quorums(&fewer, Some(admin)),
        Err(N::QuorumsDiffer(_))
    ));
    // a quorum nobody asked for
    let mut more = view.clone();
    let extra = more.common_data.quorums[0].clone();
    more.common_data.quorums.push(extra);
    assert!(matches!(
        check_quorums(&more, Some(admin)),
        Err(N::QuorumsDiffer(_))
    ));
}

#[test]
fn the_quorums_of_the_views_p1_makes_are_the_ones_the_receiver_derives_from_their_contents() {
    let created = rust_receives_a_view_from_p1(&unique("r-quorum-create"));
    let (view, admin) = view_and_admin(&created.identity, &created.view_envelope);
    assert_quorums_checked(&view, &admin);
    let settle =
        rust_receives_an_exercise_from_p1(&unique("r-quorum-settle"), "Settle", false, None);
    let (view, admin) = view_and_admin(&settle.identity, &settle.view_envelope);
    assert_eq!(
        view.common_data.quorums.len(),
        1,
        "an exercise that creates nothing has one quorum"
    );
    assert_quorums_checked(&view, &admin);
    let alice = var("CANTON_RS_ALICE");
    let transfer =
        rust_receives_an_exercise_from_p1(&unique("r-quorum-xfer"), "Transfer", true, Some(&alice));
    let (view, admin) = view_and_admin(&transfer.identity, &transfer.view_envelope);
    assert_eq!(
        view.common_data.quorums.len(),
        2,
        "an exercise that creates a contract has a second quorum"
    );
    assert_quorums_checked(&view, &admin);
    // dropping the second quorum of the transfer is not the view its contents give
    let mut without_second = view.clone();
    without_second.common_data.quorums.pop();
    assert!(matches!(
        canton_participant::view_conformance::check_quorums(&without_second, Some(&admin)),
        Err(canton_participant::view_conformance::Nonconformance::QuorumsDiffer(_))
    ));
}

// ---------------------------------------------------------------------------------------------------------------------
// S-NET-032 (G5 5.6u): a request whose view needs **two parties' confirmations from the Rust participant** (`Pact`: signatories erin
// and fay, controller alice; both signatories are hosted by p1 and the Rust participant with a threshold of 2).
// ---------------------------------------------------------------------------------------------------------------------

fn fetch_engine() -> canton_participant::view_conformance::Engine {
    canton_participant::view_conformance::Engine::load(std::path::Path::new(&var(
        "CANTON_RS_FETCH_DAR",
    )))
    .unwrap()
}

/// Raises the confirmation threshold of `party` (hosted by p1 and this participant) to 2: both hosts have to confirm from now on.
fn raise_threshold_to_two(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    party: &str,
) {
    use canton_participant::topology_wire as tw;
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let bytes = tw::party_to_participant_at_serial(party, &[(&p1_uid, 1), (&r.uid(), 2)], 2, 2);
    let raise = tw::signed(
        bytes.clone(),
        vec![r.namespace_key.sign_transaction(&bytes)],
    );
    let hash = tx_hash_in_log(&raise.transaction);
    broadcast(r, c, token, &[raise]);
    log_line_with(&[
        "participant=p1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{hash}"),
    ])
    .expect("p1 stores the new threshold");
}

/// The verdict of a `Pact` that p1 executes while the Rust participant's runtime confirms for `hosted` parties only.
/// Returns the runtime's steps, the request time of the execution, and the two parties.
fn rust_runtime_confirms_a_pact(
    name: &str,
    confirms_for_both: bool,
) -> (Vec<rt::Step>, i64, String, String) {
    let (r, mut c, token) = authenticated(name);
    let packages = [var("CANTON_RS_FETCH_PACKAGE")];
    let erin = host_consortium_party_vetting(&r, &mut c, &token, "erin", &packages);
    let fay = host_consortium_party_vetting(&r, &mut c, &token, "fay", &[]);
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |content: String| {
        let name = format!("{}.fetchcmd", unique("fc"));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = if confirms_for_both {
        vec![erin.clone(), fay.clone()]
    } else {
        vec![erin.clone()]
    };
    let dir_state = state_dir(name);
    let mut runtime = rt::Runtime::open(config, fetch_engine(), Some(&dir_state), start).unwrap();
    // p1 creates the pact (both signatories confirm through p1 while their thresholds are 1); the runtime follows it
    let created = command(format!("pact,{erin},{fay},{alice}"));
    let line = log_line_with(&["SCF fetchcmd_done=", &created]).expect("p1 creates the pact");
    let pact_id = line.rsplit('=').next().unwrap().trim().to_string();
    assert_ne!(pact_id, "-", "{line}");
    let mut steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 90, |rt| {
        rt.ledger.is_active(&pact_id)
    });
    assert!(
        runtime.ledger.is_active(&pact_id),
        "the runtime follows the creation: {steps:#?}"
    );
    // from now on both hosts of each signatory have to confirm; alice (the controller) executes
    raise_threshold_to_two(&r, &mut c, &token, &erin);
    raise_threshold_to_two(&r, &mut c, &token, &fay);
    std::thread::sleep(std::time::Duration::from_secs(2));
    command(format!("execute,{alice},{pact_id}"));
    let before = steps.len();
    steps.extend(run_until(
        &mut runtime,
        &mut c,
        &token,
        &r.signing_key,
        60,
        |rt| rt.ledger.in_flight() > 0 || rt.ledger.archived_by(&pact_id).is_some(),
    ));
    let answered = steps[before..]
        .iter()
        .flat_map(|s| &s.to_send)
        .next()
        .map(|a| a.request_time)
        .expect("the runtime answered the execution");
    let _ = std::fs::remove_dir_all(&dir_state);
    (steps, answered, erin, fay)
}

#[test]
fn the_mediator_approves_when_the_rust_participant_confirms_for_both_signatories_in_one_response() {
    let (steps, request, erin, fay) = rust_runtime_confirms_a_pact(&unique("r-pact-both"), true);
    let answer = steps
        .iter()
        .flat_map(|s| &s.to_send)
        .find(|a| a.request_time == request)
        .unwrap();
    let mut expected = vec![erin, fay];
    expected.sort();
    assert_eq!(answer.decision().confirming_parties, expected);
    assert_eq!(
        answer.decision().outcome,
        canton_participant::confirmation_wire::Outcome::Approve
    );
    let finalized = finalized_block_at(request);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
}

#[test]
fn the_mediator_times_out_a_request_when_the_rust_participant_confirms_for_only_one_signatory() {
    let (steps, request, erin, fay) = rust_runtime_confirms_a_pact(&unique("r-pact-one"), false);
    let answer = steps
        .iter()
        .flat_map(|s| &s.to_send)
        .find(|a| a.request_time == request)
        .unwrap();
    assert_eq!(answer.decision().confirming_parties, vec![erin]);
    let finalized = finalized_block_at(request);
    assert!(
        finalized.contains("MEDIATOR_SAYS_TX_TIMED_OUT") || finalized.contains("timed out"),
        "{finalized}"
    );
    assert!(
        finalized.contains(&fay[..20]),
        "the unresponsive signatory is named: {finalized}"
    );
}

#[test]
fn the_rust_participant_replays_a_choice_that_fetches_another_contract_and_the_mediator_approves() {
    let (r, mut c, token) = authenticated(&unique("r-fetch"));
    let packages = [var("CANTON_RS_FETCH_PACKAGE")];
    let erin = host_consortium_party_vetting(&r, &mut c, &token, "erin", &packages);
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |content: String| {
        let name = format!("{}.fetchcmd", unique("fc"));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![erin.clone()];
    let dir_state = state_dir("fetch");
    let mut runtime = rt::Runtime::open(config, fetch_engine(), Some(&dir_state), start).unwrap();
    let id_of = |name: &str| {
        let l = log_line_with(&["SCF fetchcmd_done=", name]).expect("done");
        l.rsplit('=').next().unwrap().trim().to_string()
    };
    let v1 = id_of(&command(format!("vault,{erin},one,first")));
    let v2 = id_of(&command(format!("vault,{erin},two,second")));
    let steps0 = run_until(&mut runtime, &mut c, &token, &r.signing_key, 60, |rt| {
        rt.ledger.is_active(&v1) && rt.ledger.is_active(&v2)
    });
    assert!(
        runtime.ledger.is_active(&v1) && runtime.ledger.is_active(&v2),
        "{steps0:#?}"
    );
    command(format!("look,{erin},{v1},{v2}"));
    let steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 40, |_| false);
    // the third answer is the `Look`: a non-consuming exercise of one vault that fetches the other
    let answers: Vec<&rt::ToSend> = steps0
        .iter()
        .chain(steps.iter())
        .flat_map(|s| &s.to_send)
        .collect();
    let look = answers.last().expect("the runtime answered the look");
    assert_eq!(
        look.decision().outcome,
        canton_participant::confirmation_wire::Outcome::Approve,
        "{look:?}"
    );
    assert_eq!(look.decision().confirming_parties, vec![erin]);
    assert!(finalized_block_at(look.request_time).contains("with verdict Approve"));
    // nothing was consumed: both vaults are still active
    assert!(runtime.ledger.is_active(&v1) && runtime.ledger.is_active(&v2));
    let _ = std::fs::remove_dir_all(&dir_state);
}

fn keyed_engine() -> canton_participant::view_conformance::Engine {
    canton_participant::view_conformance::Engine::load(std::path::Path::new(&var(
        "CANTON_RS_KEYED_DAR",
    )))
    .unwrap()
}

/// U-21 (contract keys), the first slice: p1 creates a `Registry` entry (a contract with a key) whose only stakeholder is the consortium
/// party `erin` that this participant hosts, then submits `ReadByKey` (a fetch BY KEY inside a choice). The runtime confirms both views and
/// the mediator approves them.
///
/// [CANTON-NOTE: LIMITATION] What this proves: the contract's stated signatories (key maintainers included), key maintainers and Unicum
/// (which commits to the key hash and the maintainers) are the ones the engine derives, the choice replays with the key lookup
/// resolved among the view's inputs, and the view's `resolved_keys` equal the replay's key lookups (S-NET-034, 2nd step). The key hash is
/// the stated one, not recomputed.
#[test]
fn the_rust_participant_replays_a_choice_that_fetches_by_key_and_the_mediator_approves() {
    let (r, mut c, token) = authenticated(&unique("r-key"));
    let packages = [var("CANTON_RS_KEYED_PACKAGE")];
    let erin = host_consortium_party_vetting(&r, &mut c, &token, "erin", &packages);
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |content: String| {
        let name = format!("{}.keycmd", unique("kc"));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![erin.clone()];
    let dir_state = state_dir("key");
    let mut runtime = rt::Runtime::open(config, keyed_engine(), Some(&dir_state), start).unwrap();
    let id_of = |name: &str| {
        let l = log_line_with(&["SCF keycmd_done=", name]).expect("done");
        l.rsplit('=').next().unwrap().trim().to_string()
    };
    let registry = id_of(&command(format!("registry,{erin},entry,hello")));
    let steps0 = run_until(&mut runtime, &mut c, &token, &r.signing_key, 60, |rt| {
        rt.ledger.is_active(&registry)
    });
    assert!(runtime.ledger.is_active(&registry), "{steps0:#?}");
    command(format!("readbykey,{erin},{registry},{erin},entry"));
    let steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 40, |_| false);
    let answers: Vec<&rt::ToSend> = steps0
        .iter()
        .chain(steps.iter())
        .flat_map(|s| &s.to_send)
        .collect();
    // the first answer is the create of the keyed contract, the last the by-key fetch
    for (what, answer) in [("create", answers.first()), ("read by key", answers.last())] {
        let answer = answer.unwrap_or_else(|| panic!("the runtime answered the {what}"));
        assert_eq!(
            answer.decision().outcome,
            canton_participant::confirmation_wire::Outcome::Approve,
            "{what}: {answer:?}"
        );
        assert_eq!(
            answer.decision().confirming_parties,
            vec![erin.clone()],
            "{what}"
        );
        assert!(
            finalized_block_at(answer.request_time).contains("with verdict Approve"),
            "{what}"
        );
    }
    // a non-consuming exercise: the entry is still active
    assert!(runtime.ledger.is_active(&registry));
    let _ = std::fs::remove_dir_all(&dir_state);
}

/// U-21: `Rename` consumes a keyed contract and creates one under another key (the old key is archived, the new one created). The view
/// has a consumed keyed input and a created keyed contract: its `resolved_keys` list the new key as free, the engine replays the
/// consumption, and the runtime's ledger follows (old entry gone, a new one active).
#[test]
fn the_rust_participant_replays_a_choice_that_renames_a_keyed_contract_and_the_mediator_approves() {
    let (r, mut c, token) = authenticated(&unique("r-rename"));
    let packages = [var("CANTON_RS_KEYED_PACKAGE")];
    let erin = host_consortium_party_vetting(&r, &mut c, &token, "erin", &packages);
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |content: String| {
        let name = format!("{}.keycmd", unique("kc"));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![erin.clone()];
    let dir_state = state_dir("rename");
    let mut runtime = rt::Runtime::open(config, keyed_engine(), Some(&dir_state), start).unwrap();
    let id_of = |name: &str| {
        let l = log_line_with(&["SCF keycmd_done=", name]).expect("done");
        l.rsplit('=').next().unwrap().trim().to_string()
    };
    let old = id_of(&command(format!("registry,{erin},before,hello")));
    let steps0 = run_until(&mut runtime, &mut c, &token, &r.signing_key, 60, |rt| {
        rt.ledger.is_active(&old)
    });
    assert!(runtime.ledger.is_active(&old), "{steps0:#?}");
    let renamed = id_of(&command(format!("rename,{erin},{old},after")));
    let steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 60, |rt| {
        rt.ledger.is_active(&renamed)
    });
    let answers: Vec<&rt::ToSend> = steps0
        .iter()
        .chain(steps.iter())
        .flat_map(|s| &s.to_send)
        .collect();
    let last = answers.last().expect("the runtime answered the rename");
    assert_eq!(
        last.decision().outcome,
        canton_participant::confirmation_wire::Outcome::Approve,
        "{last:?}"
    );
    assert!(finalized_block_at(last.request_time).contains("with verdict Approve"));
    // the consuming exercise archived the old entry and the new one is active
    assert!(!runtime.ledger.is_active(&old));
    assert!(runtime.ledger.is_active(&renamed), "{steps:#?}");
    let _ = std::fs::remove_dir_all(&dir_state);
}

/// U-21: a keyed contract with TWO signatories (`a` maintains the key, `b` does not): both hosts have to confirm its execution. The key
/// maintainer is stated apart from the other signatory (`non_maintainer_signatories` = `b`), so the quorum of the exercise has to join them.
#[test]
fn the_mediator_approves_a_keyed_pact_when_the_rust_participant_confirms_for_both_signatories() {
    let name = unique("r-kpact");
    let (r, mut c, token) = authenticated(&name);
    let packages = [var("CANTON_RS_KEYED_PACKAGE")];
    let erin = host_consortium_party_vetting(&r, &mut c, &token, "erin", &packages);
    let fay = host_consortium_party_vetting(&r, &mut c, &token, "fay", &[]);
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |content: String| {
        let name = format!("{}.keycmd", unique("kc"));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![erin.clone(), fay.clone()];
    let dir_state = state_dir(&name);
    let mut runtime = rt::Runtime::open(config, keyed_engine(), Some(&dir_state), start).unwrap();
    // p1 creates the pact (both signatories confirm through p1 while their thresholds are 1); the runtime follows it
    let created = command(format!("kpact,{erin},{fay},{alice},tag"));
    let line = log_line_with(&["SCF keycmd_done=", &created]).expect("p1 creates the keyed pact");
    let pact_id = line.rsplit('=').next().unwrap().trim().to_string();
    assert_ne!(pact_id, "-", "{line}");
    let mut steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 90, |rt| {
        rt.ledger.is_active(&pact_id)
    });
    assert!(
        runtime.ledger.is_active(&pact_id),
        "the runtime follows the creation: {steps:#?}"
    );
    // from now on both hosts of each signatory have to confirm; alice (the controller) executes
    raise_threshold_to_two(&r, &mut c, &token, &erin);
    raise_threshold_to_two(&r, &mut c, &token, &fay);
    std::thread::sleep(std::time::Duration::from_secs(2));
    command(format!("kexecute,{alice},{pact_id}"));
    let before = steps.len();
    steps.extend(run_until(
        &mut runtime,
        &mut c,
        &token,
        &r.signing_key,
        60,
        |rt| rt.ledger.in_flight() > 0 || rt.ledger.archived_by(&pact_id).is_some(),
    ));
    let answer = steps[before..]
        .iter()
        .flat_map(|s| &s.to_send)
        .next()
        .expect("the runtime answered the execution");
    let mut expected = vec![erin, fay];
    expected.sort();
    assert_eq!(answer.decision().confirming_parties, expected);
    assert_eq!(
        answer.decision().outcome,
        canton_participant::confirmation_wire::Outcome::Approve,
        "{answer:?}"
    );
    let finalized = finalized_block_at(answer.request_time);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
    let _ = std::fs::remove_dir_all(&dir_state);
}

/// G5 (subview confirmers): p1 exercises `Driver.Run`, whose child exercise `Touch` consumes a `Held` signed by `erin`, a party this participant
/// hosts. The child exercise is a SUBVIEW this participant receives without the parent, and `erin`, a signatory of the consumed contract, has to
/// confirm it: with the thresholds at two, the mediator waits for this participant's answer for the subview.
#[test]
fn the_mediator_approves_a_subview_that_the_rust_participant_confirms_as_a_signatory() {
    let name = unique("r-subconfirm");
    let (r, mut c, token) = authenticated(&name);
    let packages = [var("CANTON_RS_CONFIRM_PACKAGE")];
    let erin = host_consortium_party_vetting(&r, &mut c, &token, "erin", &packages);
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |content: String| {
        let name = format!("{}.confcmd", unique("cc"));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![erin.clone()];
    let dir_state = state_dir(&name);
    let engine = canton_participant::view_conformance::Engine::load(std::path::Path::new(&var(
        "CANTON_RS_CONFIRM_DAR",
    )))
    .unwrap();
    let mut runtime = rt::Runtime::open(config, engine, Some(&dir_state), start).unwrap();
    let id_of = |name: &str| {
        let l = log_line_with(&["SCF confcmd_done=", name]).expect("done");
        l.rsplit('=').next().unwrap().trim().to_string()
    };
    let held = id_of(&command(format!("held,{erin},{alice}")));
    let driver = id_of(&command(format!("driver,{alice}")));
    let mut steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 90, |rt| {
        rt.ledger.is_active(&held)
    });
    assert!(runtime.ledger.is_active(&held), "{steps:#?}");
    raise_threshold_to_two(&r, &mut c, &token, &erin);
    std::thread::sleep(std::time::Duration::from_secs(2));
    command(format!("run,{alice},{driver},{held}"));
    let before = steps.len();
    steps.extend(run_until(
        &mut runtime,
        &mut c,
        &token,
        &r.signing_key,
        60,
        |rt| rt.ledger.archived_by(&held).is_some(),
    ));
    let answered: Vec<&rt::ToSend> = steps[before..].iter().flat_map(|s| &s.to_send).collect();
    eprintln!("SUBCONFIRM answers={answered:#?}");
    let answer = answered.first().expect("the runtime answered the subview");
    assert_eq!(
        answer.decision().outcome,
        canton_participant::confirmation_wire::Outcome::Approve,
        "{answer:?}"
    );
    assert_eq!(answer.decision().confirming_parties, vec![erin.clone()]);
    let finalized = finalized_block_at(answer.request_time);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
    // the child exercise consumed the held contract
    assert!(runtime.ledger.archived_by(&held).is_some() || !runtime.ledger.is_active(&held));
    // negative controls on the very view the runtime approved: read the event again and break the view in the ways a wrong
    // request could differ from the right one
    let subview = subview_received_at(&mut c, &token, &r, answer.request_time);
    assert_subview_checks_reject_what_differs(&subview);
    let _ = std::fs::remove_dir_all(&dir_state);
}

/// The one revealed view (a subview: its position is below the root) that the participant `r` receives in the event at `time`.
fn subview_received_at(
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    r: &canton_participant::topology_wire::ParticipantIdentity,
    time: i64,
) -> canton_participant::view_receive::RevealedView {
    use canton_participant::view_receive as vr;
    let events = c
        .subscribe(
            &r.member(),
            &var("CANTON_RS_EXPECT_SYNCHRONIZER"),
            token,
            Some(time),
            1,
            std::time::Duration::from_secs(5),
        )
        .unwrap();
    let event = canton_participant::sequencing_wire::decode_delivered(&events[0]).unwrap();
    assert_eq!(event.timestamp_micros, time, "the event of the request");
    let mut found = Vec::new();
    for envelope in &event.envelopes {
        let Ok(views) =
            vr::decrypt_views(envelope, &r.encryption_fingerprint(), r.encryption_secret())
        else {
            continue;
        };
        for v in &views.view_trees {
            let tree = v.tree.as_ref().unwrap();
            found.extend(vr::revealed_views(tree).unwrap());
        }
    }
    assert_eq!(
        found.len(),
        1,
        "exactly the subview is revealed to this participant"
    );
    found.remove(0)
}

/// What the subview's checks accept and what they refuse: the genuine view passes (a subview has no admin party in its quorum), and a
/// view that differs in its quorum, its contract or its recorded input does not.
fn assert_subview_checks_reject_what_differs(
    view: &canton_participant::view_receive::RevealedView,
) {
    use canton_participant::view_conformance::{check_quorums, Nonconformance as N};
    assert!(
        view.position.len() > 1,
        "a subview sits below the root: {:?}",
        view.position
    );
    assert_eq!(
        check_quorums(view, None),
        Ok(()),
        "the quorum p1 wrote for a subview is the one its contents give"
    );
    // a subview's quorum has no admin party: asking for one is a difference
    assert!(matches!(
        check_quorums(view, Some("someone::1220aa")),
        Err(N::QuorumsDiffer(_))
    ));
    // a threshold that is not the number of members
    for delta in [-1i32, 1] {
        let mut changed = view.clone();
        let t = &mut changed.common_data.quorums[0].threshold;
        *t += delta;
        assert!(
            matches!(check_quorums(&changed, None), Err(N::QuorumsDiffer(_))),
            "threshold {delta:+}"
        );
    }
    // a member left out of the quorum
    let mut fewer = view.clone();
    let q = &mut fewer.common_data.quorums[0];
    q.party_index_and_weight.pop();
    q.threshold -= 1;
    assert!(matches!(
        check_quorums(&fewer, None),
        Err(N::QuorumsDiffer(_))
    ));
    // [CANTON-NOTE: SEMANTICS] Whether the input is consumed does not change the quorum: the confirming parties of a node are its contract's
    // signatories and its acting parties either way (`TransactionViewDecompositionFactory`), so there is no control on the consumed flag here.
}

/// The root view of an `Archive` of the keyed pact `created` (the consuming choice every template has, controlled by the signatories).
/// [CANTON-NOTE: SEMANTICS] The chosen value of `Archive` is a record with no fields (`106 0`, the same as `Settle`'s), versioned as the
/// package is: the LF 2.3 keyed fixture uses `version "2"` (the sample's LF 2.1 uses `"2.1"`). Measured on p1's reconstruction, which
/// refused `"2.1"` here (`V1` against `V2`), and `10 0` (a `Unit`) before that (`TypeMismatch` against `DA.Internal.Template:Archive`).
fn keyed_archive_view_by(
    created: &SampleCreated,
    actors: &[&str],
    resolved_keys: Vec<
        canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers,
    >,
) -> canton_participant::merkle_wire::LeafNode {
    use canton_participant::merkle_wire as mw;
    let chosen_value = [10, 1, b'2', 18, 2, 106, 0];
    mw::view_participant_data_exercise_with_keys(
        &created.instance,
        true,
        &[],
        &mw::ExerciseSpec {
            interface_id: None,
            package_preference: &[],
            contract_id_hex: &created.id_hex,
            template_id: &format!("{}:Keyed:KeyedPact", var("CANTON_RS_KEYED_PACKAGE")),
            choice: "Archive",
            chosen_value: &chosen_value,
            actors,
            node_seed: &fresh("exercise-node-seed"),
        },
        &fresh("vpd-salt"),
        resolved_keys,
    )
}

/// The `resolved_keys` entry of the key `(erin, tag)` of a `KeyedPact` that an exercise by contract id consumes: the key and the
/// maintainer.
fn keyed_pact_key_of(
    erin: &str,
    tag: &str,
) -> canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers{
    use canton_participant::contract_id as ci;
    use canton_participant::contract_wire::LfValue;
    use canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers;
    use canton_proto::com::digitalasset::canton::protocol::v31::GlobalKey;
    use canton_proto::com::digitalasset::daml::lf::transaction::Versioned as LfVersioned;
    use canton_proto::com::digitalasset::daml::lf::value::Identifier;
    use prost::Message;
    let key_value = LfValue::Record(vec![
        LfValue::Party(erin.to_string()),
        LfValue::Text(tag.into()),
    ]);
    let key_hash = ci::lf_contract_key_hash(
        "keyed-vault",
        &["Keyed".into()],
        &["KeyedPact".into()],
        &ci::HashValue::Record {
            module: vec!["DA".into(), "Types".into()],
            name: vec!["Tuple2".into()],
            fields: vec![
                ("_1".into(), ci::HashValue::Party(erin.to_string())),
                ("_2".into(), ci::HashValue::Text(tag.into())),
            ],
        },
    );
    KeyResolutionWithMaintainers {
        key: Some(GlobalKey {
            template_id: Identifier {
                package_id: var("CANTON_RS_KEYED_PACKAGE"),
                module_name: vec!["Keyed".into()],
                name: vec!["KeyedPact".into()],
            }
            .encode_to_vec(),
            key: LfVersioned {
                version: "2".into(),
                payload: key_value.encode(),
            }
            .encode_to_vec(),
            package_name: "keyed-vault".into(),
            hash: key_hash.to_vec(),
        }),
        maintainers: vec![erin.to_string()],
        // [CANTON-NOTE: SEMANTICS] Measured (p1's reconstruction of this view): no contract id, as in the view that creates the key; the
        // id of the contract that holds it would be listed only by a lookup of the key.
        contract_ids: vec![],
    }
}

/// G5 (U-21 8th step): this participant **submits an exercise** of a keyed contract it created: p1 validates the view (the consumed
/// input carries its key) and the mediator approves.
#[test]
fn p1_accepts_an_archive_of_a_keyed_contract_that_the_rust_participant_submitted() {
    let (r, mut c, token) = authenticated(&unique("r-karchive"));
    let erin = host_party_and_vet(
        &r,
        &mut c,
        &token,
        "erin",
        true,
        &var("CANTON_RS_KEYED_PACKAGE"),
    );
    let created = rust_creates_keyed_pact(&r, &mut c, &token, &erin, "to-archive", false);
    assert!(
        finalized_at(created.request_id).contains("with verdict Approve"),
        "the keyed contract exists"
    );
    let (request_id, _) = rust_sends_a_root_view_to_p1(
        &r,
        &mut c,
        &token,
        &[&erin],
        &keyed_archive_view_by(
            &created,
            &[&erin],
            vec![keyed_pact_key_of(&erin, "to-archive")],
        ),
        &fresh_uuid(),
        None,
        &[],
    );
    let finalized = finalized_block_at(request_id);
    assert!(
        finalized.contains("with verdict Approve"),
        "{finalized}\n{}",
        p1_reason_for(request_id)
    );
}

/// p1's own log of the request sequenced at `request_id`: the lines from its verdict (with the multi-line reason that follows).
fn p1_reason_for(request_id: i64) -> String {
    std::thread::sleep(std::time::Duration::from_secs(5));
    let log = node_log();
    let t = iso_micros(request_id);
    let tid = log
        .lines()
        .find(|l| l.contains("participant=p1") && l.contains(&format!("ts={t}")))
        .and_then(|l| l.split("tid:").nth(1))
        .and_then(|l| l.split(' ').next())
        .map(String::from);
    let lines: Vec<&str> = log.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if let Some(tid) = &tid {
            if l.contains(tid.as_str()) && l.contains("LOCAL_VERDICT") {
                out.extend(
                    lines[i..(i + 150).min(lines.len())]
                        .iter()
                        .map(|m| m.to_string()),
                );
            }
        }
    }
    out.join("\n")
}

/// Negative control: the same archive naming `alice` as the actor. `Archive` is controlled by the signatories, so p1 cannot
/// reconstruct the view and the request is malformed.
#[test]
fn p1_rejects_an_archive_of_a_keyed_contract_whose_actor_is_not_a_signatory() {
    let (r, mut c, token) = authenticated(&unique("r-karchive-bad"));
    let erin = host_party_and_vet(
        &r,
        &mut c,
        &token,
        "erin",
        true,
        &var("CANTON_RS_KEYED_PACKAGE"),
    );
    let created = rust_creates_keyed_pact(&r, &mut c, &token, &erin, "wrong-actor", false);
    assert!(finalized_at(created.request_id).contains("with verdict Approve"));
    let alice = var("CANTON_RS_ALICE");
    let (request_id, _) = rust_sends_a_root_view_to_p1(
        &r,
        &mut c,
        &token,
        &[&erin],
        &keyed_archive_view_by(
            &created,
            &[alice.as_str()],
            vec![keyed_pact_key_of(&erin, "wrong-actor")],
        ),
        &fresh_uuid(),
        None,
        &[],
    );
    let finalized = finalized_block_at(request_id);
    assert!(!finalized.contains("with verdict Approve"), "{finalized}");
}

/// G5 (S-NET-035): two sibling subviews in one request. `RunTwo` exercises `Touch` on two `Held` contracts of the Rust participant's
/// party; each child is its own view, the participant receives both in one event, and with the confirmation threshold of the party at 2
/// the mediator approves only if the participant answers **both** (one response per view).
#[test]
fn the_mediator_approves_two_sibling_subviews_that_the_rust_participant_confirms() {
    let name = unique("r-subtwo");
    let (r, mut c, token) = authenticated(&name);
    let packages = [var("CANTON_RS_CONFIRM_PACKAGE")];
    let erin = host_consortium_party_vetting(&r, &mut c, &token, "erin", &packages);
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |content: String| {
        let name = format!("{}.confcmd", unique("cc"));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![erin.clone()];
    let dir_state = state_dir(&name);
    let engine = canton_participant::view_conformance::Engine::load(std::path::Path::new(&var(
        "CANTON_RS_CONFIRM_DAR",
    )))
    .unwrap();
    let mut runtime = rt::Runtime::open(config, engine, Some(&dir_state), start).unwrap();
    let id_of = |name: &str| {
        let l = log_line_with(&["SCF confcmd_done=", name]).expect("done");
        l.rsplit('=').next().unwrap().trim().to_string()
    };
    let first = id_of(&command(format!("held,{erin},{alice}")));
    let second = id_of(&command(format!("held,{erin},{alice}")));
    let driver = id_of(&command(format!("twodriver,{alice}")));
    let mut steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 90, |rt| {
        rt.ledger.is_active(&first) && rt.ledger.is_active(&second)
    });
    assert!(
        runtime.ledger.is_active(&first) && runtime.ledger.is_active(&second),
        "{steps:#?}"
    );
    raise_threshold_to_two(&r, &mut c, &token, &erin);
    std::thread::sleep(std::time::Duration::from_secs(2));
    command(format!("runtwo,{alice},{driver},{first},{second}"));
    let before = steps.len();
    steps.extend(run_until(
        &mut runtime,
        &mut c,
        &token,
        &r.signing_key,
        60,
        |rt| rt.ledger.archived_by(&first).is_some() && rt.ledger.archived_by(&second).is_some(),
    ));
    let answered: Vec<&rt::ToSend> = steps[before..].iter().flat_map(|s| &s.to_send).collect();
    // one answer for the request with one response per view: two views at different positions, both approving for the party
    assert_eq!(
        answered.len(),
        1,
        "one answer carries the responses: {answered:#?}"
    );
    let answer = answered[0];
    assert_eq!(answer.decisions.len(), 2, "{answer:?}");
    for d in &answer.decisions {
        assert_eq!(
            d.outcome,
            canton_participant::confirmation_wire::Outcome::Approve,
            "{answer:?}"
        );
        assert_eq!(d.confirming_parties, vec![erin.clone()]);
        assert_eq!(d.view_position.len(), 2, "a subview: {d:?}");
    }
    assert_ne!(
        answer.decisions[0].view_position, answer.decisions[1].view_position,
        "the two subviews sit at different positions"
    );
    let finalized = finalized_block_at(answer.request_time);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
    // both Held contracts are consumed by this one request
    assert!(runtime.ledger.archived_by(&first).is_some());
    assert!(runtime.ledger.archived_by(&second).is_some());
    let _ = std::fs::remove_dir_all(&dir_state);
}

/// G5 (U-22, synchronizer parameters): the synchronizer's confirmation response timeout is changed on the node while this runtime follows the
/// topology; the runtime's timeouts follow.
#[test]
fn the_runtime_follows_a_change_of_the_synchronizers_confirmation_timeout() {
    // the change is visible to every participant of the synchronizer: wait until no other test is running against the node
    let _writer = PARAMS.write().unwrap_or_else(|e| e.into_inner());
    PARAMS_WRITER.with(|w| w.set(true));
    let name = unique("r-params");
    let (r, mut c, token) = authenticated(&name);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let state = state_dir("params");
    let mut config = runtime_config(
        &r,
        "",
        vec![],
        vec![],
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![];
    config.follow_topology = true;
    let mut runtime = rt::Runtime::open(config, rust_engine(), Some(&state), start).unwrap();
    let before = runtime.config.timeouts.confirmation_response_micros;
    assert_ne!(before, 47_000_000, "the test needs a change to observe");
    let file = format!("{}.paramscmd", unique("pc"));
    std::fs::write(dir.join(format!("{file}.tmp")), "confirmation,47").unwrap();
    std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
    let steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 40, |rt| {
        rt.config.timeouts.confirmation_response_micros == 47_000_000
    });
    assert!(
        steps
            .iter()
            .flat_map(|s| s.notes.iter())
            .any(|n| n.contains("are in force")),
        "the runtime must note that the new parameters are in force"
    );
    assert_eq!(
        runtime.config.timeouts.confirmation_response_micros,
        47_000_000
    );
    // put the synchronizer back before the lock is released: the other tests expect the original value
    let file = format!("{}.paramscmd", unique("pc"));
    std::fs::write(
        dir.join(format!("{file}.tmp")),
        format!("confirmation,{}", before / 1_000_000),
    )
    .unwrap();
    std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
    run_until(&mut runtime, &mut c, &token, &r.signing_key, 40, |rt| {
        rt.config.timeouts.confirmation_response_micros == before
    });
    assert_eq!(runtime.config.timeouts.confirmation_response_micros, before);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn the_runtime_learns_the_keys_of_a_participant_that_joins_and_refuses_keys_nobody_authorized() {
    use canton_participant::topology_wire as tw;
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        public_key::Key, PublicKey, SigningKeyUsage,
    };
    let (a, mut c, token) = authenticated(&unique("r-join-a"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let start = c
        .sequencer_time(&a.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let dir = state_dir("join");
    let mut config = runtime_config(
        &a,
        "",
        vec![],
        vec![],
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![];
    config.follow_topology = true;
    let mut runtime = rt::Runtime::open(config, rust_engine(), Some(&dir), start).unwrap();
    // a participant joins the synchronizer after the runtime started, and two key mappings are broadcast: one signed in the
    // member's namespace (the namespace key), one signed with a key no delegation authorizes
    let (b, _cb) = registered_participant(&unique("r-join-b"));
    let has = |keys: &[SigningKey], k: &tw::Ed25519Key| keys.iter().any(|x| x.id == k.fingerprint);
    let mapping_for = |member: String, key: &tw::Ed25519Key| {
        tw::owner_to_key_mapping(
            &member,
            vec![
                PublicKey {
                    key: Some(Key::SigningPublicKey(
                        // T-8: a key that proves its possession carries the ProofOfOwnership usage (`assignExpectedUsageToKeys`)
                        key.public_key(&[
                            SigningKeyUsage::Protocol,
                            SigningKeyUsage::ProofOfOwnership,
                        ]),
                    )),
                },
                // T-12: a participant's key mapping has an encryption key too (`checkOwnerToKeyMappingReplace`)
                tw::p256_encryption_key(tw::ParticipantIdentity::generate("enc").encryption_spki()),
            ],
        )
    };
    let carol_key = tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(
        &fresh("carol-key"),
    ));
    let mallory_key = tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(
        &fresh("mallory-key"),
    ));
    let carol = mapping_for(format!("PAR::carol::{}", a.namespace()), &carol_key);
    let mallory = mapping_for(format!("PAR::mallory::{}", a.namespace()), &mallory_key);
    broadcast(
        &a,
        &mut c,
        &token,
        &[
            tw::signed(
                carol.clone(),
                // the member's namespace key and the key the mapping names (proof of possession)
                vec![
                    a.namespace_key.sign_transaction(&carol),
                    carol_key.sign_transaction(&carol),
                ],
            ),
            tw::signed(
                mallory.clone(),
                vec![a.signing_key.sign_transaction(&mallory)],
            ),
        ],
    );
    let steps = run_until(&mut runtime, &mut c, &token, &a.signing_key, 60, |rt| {
        has(&rt.config.submitter_keys, &b.signing_key)
            && has(&rt.config.submitter_keys, &carol_key)
            && rt.config.peer_encryption_keys.contains_key(&b.member())
    });
    let keys = &runtime.config.submitter_keys;
    assert!(
        has(keys, &b.signing_key),
        "the joining participant's key is trusted: {steps:#?}"
    );
    assert!(
        has(keys, &carol_key),
        "a mapping signed in the member's namespace is followed"
    );
    assert!(
        !has(keys, &mallory_key),
        "a mapping signed by a key no delegation authorizes is not"
    );
    assert!(
        !has(keys, &a.signing_key),
        "its own key is not one it trusts a request to be signed with"
    );
    let notes: Vec<&String> = steps.iter().flat_map(|s| &s.notes).collect();
    assert!(
        notes
            .iter()
            // T-6: an unauthorized transaction that is not a proposal is refused, not kept waiting
            .any(|n| n.contains("mallory") && n.contains("not authorized")),
        "{notes:#?}"
    );
    // the encryption keys follow the same mappings: the joiner's key is what the requests' randomness is encrypted for, and p1's
    // (from the downloaded state) is the key and fingerprint the node reports
    let encryption = &runtime.config.peer_encryption_keys;
    let joiner = &encryption[&b.member()];
    assert_eq!(joiner.len(), 1, "{joiner:?}");
    assert_eq!(joiner[0].spki, b.encryption_spki());
    assert_eq!(joiner[0].fingerprint, b.encryption_fingerprint());
    let p1 = &encryption[&var("CANTON_RS_MEMBER_P1")];
    assert_eq!(p1.len(), 1, "{p1:?}");
    assert_eq!(p1[0].spki, p1_encryption_key(&mut c, &a, &token));
    assert_eq!(
        p1[0].fingerprint,
        var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT")
    );
    assert!(
        !encryption.contains_key(&a.member()),
        "a participant does not encrypt for itself"
    );
    assert!(
        !encryption.keys().any(|m| m.contains("mallory")),
        "a mapping nobody authorized brings no encryption key either"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------------------------------------
// G5 (TLS): the client connects over TLS. The sandbox's public API is plaintext; a TLS terminator (rustls, ALPN h2) in front of it
// forwards the decrypted HTTP/2 to the real sequencer, so the calls below are answered by the node.
// ---------------------------------------------------------------------------------------------------------------------

/// A TLS terminator on an ephemeral local port that forwards every connection to the sequencer's plaintext port. Returns its port.
fn tls_terminator() -> u16 {
    use std::sync::Arc;
    let cert_pem = std::fs::read(var("CANTON_RS_TLS_CERT")).unwrap();
    let key_pem = std::fs::read(var("CANTON_RS_TLS_KEY")).unwrap();
    let ca_pem = std::fs::read(var("CANTON_RS_TLS_CA")).unwrap();
    let upstream = var("CANTON_RS_SEQUENCER_URL")
        .trim_start_matches("http://")
        .to_string();
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
            // the leaf, then the CA that signed it (the chain a server presents)
            let mut chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
                .map(|c| c.unwrap())
                .collect();
            chain.extend(CertificateDer::pem_slice_iter(&ca_pem).map(|c| c.unwrap()));
            let key = PrivateKeyDer::from_pem_slice(&key_pem).unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap();
            config.alpn_protocols = vec![b"h2".to_vec()];
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            port_tx.send(listener.local_addr().unwrap().port()).unwrap();
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let acceptor = acceptor.clone();
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut plain) = tokio::net::TcpStream::connect(&upstream).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
                });
            }
        });
    });
    port_rx.recv().unwrap()
}

#[test]
fn the_client_authenticates_and_calls_the_sequencer_over_tls() {
    use canton_participant::sequencer_connect::AuthKey;
    let ca = std::fs::read_to_string(var("CANTON_RS_TLS_CA")).unwrap();
    let port = tls_terminator();
    let url = format!("https://localhost:{port}");
    // a participant registered over the plaintext port, then everything else over TLS
    let (r, _plain) = registered_participant(&unique("r-tls"));
    let mut c = SequencerConnect::connect_tls(&url, &ca, "localhost").expect("connect over TLS");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    // unauthenticated calls, answered by the node
    assert_eq!(
        c.synchronizer_id().unwrap().physical_synchronizer_id,
        synchronizer
    );
    // the challenge-and-signature authentication of the member, and an authenticated call with its token
    let challenge = c.challenge(&r.member(), &[37]).expect("challenge over TLS");
    let signature = r
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &synchronizer).unwrap());
    let token = c
        .authenticate(&r.member(), &challenge.nonce, signature)
        .expect("authenticate over TLS");
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap();
    assert!(
        now.is_some(),
        "the node answered an authenticated call over TLS"
    );
}

/// Negative controls: a client that does not trust the server's certificate, one that expects another name, and a plaintext client on
/// the TLS port all fail to connect or to call.
#[test]
fn the_client_refuses_a_server_it_cannot_authenticate_and_plaintext_on_a_tls_port() {
    let ca = std::fs::read_to_string(var("CANTON_RS_TLS_CA")).unwrap();
    let port = tls_terminator();
    // the name does not match the certificate (it is valid for localhost and 127.0.0.1)
    let wrong_name =
        SequencerConnect::connect_tls(&format!("https://localhost:{port}"), &ca, "other.example");
    assert!(
        wrong_name.is_err() || wrong_name.unwrap().synchronizer_id().is_err(),
        "a certificate for another name is refused"
    );
    // a CA that did not sign the server's certificate
    let other_ca = std::fs::read_to_string(var("CANTON_RS_TLS_OTHER_CA")).unwrap();
    let untrusted =
        SequencerConnect::connect_tls(&format!("https://localhost:{port}"), &other_ca, "localhost");
    assert!(
        untrusted.is_err() || untrusted.unwrap().synchronizer_id().is_err(),
        "a certificate that does not chain to the trusted CA is refused"
    );
    // plaintext HTTP/2 to the TLS port does not get an answer
    let plain = SequencerConnect::connect(&format!("http://127.0.0.1:{port}"));
    assert!(
        plain.is_err() || plain.unwrap().synchronizer_id().is_err(),
        "no plaintext on the TLS port"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// G5 (U-22): the node's own view of the topology (`.topocmd`) is the oracle for the effective time of a change and for the removal of a
// namespace delegation.
// ---------------------------------------------------------------------------------------------------------------------

/// The entries of the node's list of `kind` (`o2k`, `nsd`, `p2p`) in force now: each is the `|`-separated fields the console handler prints.
fn node_topology(kind: &str) -> Vec<Vec<String>> {
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let name = format!("{}.topocmd", unique("topo"));
    std::fs::write(dir.join(format!("{name}.tmp")), kind).unwrap();
    std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
    let line = log_line_with(&["SCF topocmd_done=", &name]).expect("the node listed its topology");
    let listed = line
        .split_once(&format!("{name}={kind}="))
        .map(|(_, rest)| rest.trim().to_string())
        .unwrap_or_default();
    listed
        .split(';')
        .filter(|e| !e.is_empty())
        .map(|e| e.split('|').map(str::to_string).collect())
        .collect()
}

/// Microseconds since the epoch of `2026-11-13T02:00:52.290620Z`.
#[test]
fn a_topology_change_is_effective_after_the_topology_change_delay_the_static_parameters_state() {
    let (r, mut c) = registered_participant(&unique("r-effective"));
    // the delay is in the static synchronizer parameters (not the dynamic ones), which this client reads
    let (_version, params) = c.synchronizer_parameters().unwrap();
    assert!(
        params.contains("topology_change_delay: Some(Duration { seconds: 0, nanos: 250000000 })"),
        "{params}"
    );
    let mapping = node_topology("o2k")
        .into_iter()
        .find(|e| e[0] == r.member())
        .expect("the node holds the new participant's key mapping");
    let (valid_from, sequenced) = (micros_of_iso(&mapping[1]), micros_of_iso(&mapping[2]));
    assert_eq!(
        valid_from - sequenced,
        250_000,
        "valid from = sequenced + the topology change delay: {mapping:?}"
    );
}

/// The removal of a namespace delegation, as the node does it: a REMOVE signed in the namespace takes the delegation out of force; the same
/// REMOVE signed by a key that does not speak for the namespace leaves it.
#[test]
fn the_node_takes_a_namespace_delegation_out_of_force_when_the_namespace_removes_it() {
    use canton_proto::com::digitalasset::canton::crypto::v30::SigningKeyUsage;
    let (a, mut c, token) = authenticated(&unique("r-nsd-remove"));
    let (stranger, _) = registered_participant(&unique("r-nsd-stranger"));
    let namespace = a.namespace().to_string();
    let in_force = || node_topology("nsd").iter().any(|e| e[0] == namespace);
    assert!(
        in_force(),
        "the delegation of the participant's namespace is in force"
    );
    let removal = canton_participant::topology_wire::namespace_delegation_removal(
        &namespace,
        a.namespace_key.public_key(&[SigningKeyUsage::Namespace]),
    );
    // signed by a key that does not speak for the namespace: not taken
    broadcast(
        &a,
        &mut c,
        &token,
        &[canton_participant::topology_wire::signed(
            removal.clone(),
            vec![stranger.namespace_key.sign_transaction(&removal)],
        )],
    );
    std::thread::sleep(std::time::Duration::from_secs(4));
    assert!(
        in_force(),
        "a removal signed outside the namespace changes nothing"
    );
    // signed in the namespace: taken
    broadcast(
        &a,
        &mut c,
        &token,
        &[canton_participant::topology_wire::signed(
            removal.clone(),
            vec![a.namespace_key.sign_transaction(&removal)],
        )],
    );
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while in_force() && std::time::Instant::now() < patience {
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    assert!(
        !in_force(),
        "the removal signed in the namespace takes the delegation out of force"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// F1 (S-SUBMIT-001): the library's submitting code (`submit::build_create`, `submit::build_exercise`), not the hand-written test code above,
// builds a create and a Settle of the sample contract; the official mediator approves both.
// ---------------------------------------------------------------------------------------------------------------------

/// Sends `request` as the submitting participant, finds its sequencing time, and answers for the admin party (p1 confirms the rest).
fn send_and_answer_as_admin(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    built: &canton_participant::submit::Built,
    now: i64,
) -> i64 {
    use canton_participant::{confirmation_wire as cw, sequencing_wire as sw};
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    c.send_async(&r.member(), &synchronizer, token, built.request.clone())
        .expect("the sequencer accepts the request");
    let mut from = now + 1;
    let request_id = loop {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                token,
                Some(from),
                1,
                std::time::Duration::from_secs(10),
            )
            .expect("subscribe");
        let d = sw::decode_delivered(events.first().expect("our request comes back")).unwrap();
        from = d.timestamp_micros + 1;
        if d.message_id.as_deref() == Some(built.message_id.as_str()) {
            break d.timestamp_micros;
        }
    };
    let admin = r.uid();
    let (content, signatures) = cw::confirmation_responses(
        request_id,
        &built.root_hash,
        &synchronizer,
        &r.member(),
        &[cw::ViewResponse {
            view_position: &[vec![]],
            outcome: cw::Outcome::Approve,
            confirming_parties: std::slice::from_ref(&admin),
        }],
        &r.signing_key,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        token,
        sw::signed_submission_request(
            sw::submission_request_signed(
                &r.member(),
                &unique("resp"),
                &[(vec![cw::mediator_group(0)], content, signatures)],
                request_id + 30_000_000,
            ),
            &r.signing_key,
        ),
    )
    .expect("the sequencer accepts the responses");
    request_id
}

#[test]
fn the_official_mediator_approves_a_create_and_a_settle_the_submit_module_built() {
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::forms;
    let (r, mut c, token) = authenticated(&unique("r-submit-module"));
    let erin = host_party_and_vet_sample(&r, &mut c, &token, "erin", true);
    let alice = var("CANTON_RS_ALICE");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let package_id = var("CANTON_RS_SAMPLE_PACKAGE");
    let world = lf_eval::World::open(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar"),
    )
    .unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let ty = types
        .template(world.main_package_id(), "AssetHolding:AssetHolding")
        .unwrap();
    let value = lf_eval::Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), lf_eval::Value::Party(erin.clone())),
            ("owner".into(), lf_eval::Value::Party(erin.clone())),
            ("auditor".into(), lf_eval::Value::Party(alice.clone())),
            ("assetSymbol".into(), lf_eval::Value::Text("USD".into())),
            (
                "amount".into(),
                lf_eval::Value::Numeric {
                    coeff: 1_000_000_000_000,
                    scale: 10,
                },
            ),
        ],
    };
    let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut random = Os;
    let created = build_create(
        &ctx,
        &Create {
            package_name: "sample-contract",
            package_id: &package_id,
            module: vec!["AssetHolding".into()],
            name: vec!["AssetHolding".into()],
            arg,
            hash_arg,
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone(), alice.clone()],
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("create"),
            key: None,
        },
        now,
        &mut random,
    )
    .unwrap();
    let create_id = send_and_answer_as_admin(&r, &mut c, &token, &created, now);
    let verdict = finalized_at(create_id);
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
    let stored = StoredContract {
        contract_id_hex: created.contract_id_hex.clone(),
        instance: created.instance.clone(),
        package_id: package_id.clone(),
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        signatories: vec![erin.clone()],
        stakeholders: vec![erin.clone(), alice.clone()],
    };
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let settle = tree_request(
        &ctx,
        vec![exercise_node(
            &stored,
            "Settle",
            canton_participant::contract_wire::LfValue::Record(vec![]),
            true,
            &[erin.clone()],
            vec![],
        )],
        &[p1, me],
        &[erin.clone()],
        &unique("settle"),
        now,
        None,
    );
    let settle_id = send_and_answer_as_admin(&r, &mut c, &token, &settle, now);
    let verdict = finalized_block_at(settle_id);
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// An exercise that creates contracts, submitted by the Rust participant and **confirmed by the official participant p1** (it co-hosts both
/// signatories) and judged by the official mediator (F1 extension, S-SUBMIT-006): p1 re-interprets `Transfer`, derives the id of the contract
/// it creates from the exercise's seed, the view's salt and the index, and checks the quorums, so an approval means that the view this module
/// builds (created contract, ids, authentication data, second quorum) is what the official model expects.
#[test]
fn the_official_participant_confirms_an_exercise_that_creates_a_contract() {
    use canton_participant::submit::{
        build_create, plan_created, Context, Create, ExercisePlan, NewInView, Os, Peer,
    };
    use canton_participant::value_forms::forms;
    let (r, mut c, token) = authenticated(&unique("r-submit-xfer"));
    let erin = host_party_and_vet_sample(&r, &mut c, &token, "erin", true);
    let gwen = host_party_and_vet_sample(&r, &mut c, &token, "gwen", true);
    let alice = var("CANTON_RS_ALICE");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let package_id = var("CANTON_RS_SAMPLE_PACKAGE");
    let world = lf_eval::World::open(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar"),
    )
    .unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let ty = types
        .template(world.main_package_id(), "AssetHolding:AssetHolding")
        .unwrap();
    let holding = |bank: &str, owner: &str| lf_eval::Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), lf_eval::Value::Party(bank.into())),
            ("owner".into(), lf_eval::Value::Party(owner.into())),
            ("auditor".into(), lf_eval::Value::Party(alice.clone())),
            ("assetSymbol".into(), lf_eval::Value::Text("USD".into())),
            (
                "amount".into(),
                lf_eval::Value::Numeric {
                    coeff: 1_000_000_000_000,
                    scale: 10,
                },
            ),
        ],
    };
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let mut random = Os;
    let sorted2 = |a: &str, b: &str| {
        let mut v = vec![a.to_string(), b.to_string()];
        v.sort();
        v.dedup();
        v
    };
    // erin (bank) and gwen (owner) hold the asset; alice observes
    let (arg, hash_arg) = forms(&types, &ty, &holding(&erin, &gwen)).unwrap();
    let mut stakeholders = sorted2(&erin, &gwen);
    stakeholders.push(alice.clone());
    stakeholders.sort();
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let created = build_create(
        &ctx,
        &Create {
            package_name: "sample-contract",
            package_id: &package_id,
            module: vec!["AssetHolding".into()],
            name: vec!["AssetHolding".into()],
            arg,
            hash_arg,
            signatories: sorted2(&erin, &gwen),
            stakeholders: stakeholders.clone(),
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("xfer-create"),
            key: None,
        },
        now,
        &mut random,
    )
    .unwrap();
    let create_id = send_and_answer_as_admin(&r, &mut c, &token, &created, now);
    let verdict = finalized_at(create_id);
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
    let stored = canton_participant::submit::StoredContract {
        contract_id_hex: created.contract_id_hex.clone(),
        instance: created.instance.clone(),
        package_id: package_id.clone(),
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        signatories: sorted2(&erin, &gwen),
        stakeholders,
    };
    // gwen transfers it to erin: erin becomes bank and owner of the contract the exercise creates
    let moved = holding(&erin, &erin);
    let (moved_arg, moved_hash) = forms(&types, &ty, &moved).unwrap();
    let moved_signatories = vec![erin.clone()];
    let mut moved_stakeholders = vec![erin.clone(), alice.clone()];
    moved_stakeholders.sort();
    let module = vec!["AssetHolding".to_string()];
    let name = vec!["AssetHolding".to_string()];
    let new_in_view = || NewInView {
        package_name: "sample-contract",
        package_id: &package_id,
        module: &module,
        name: &name,
        arg: &moved_arg,
        hash_arg: &moved_hash,
        signatories: &moved_signatories,
        stakeholders: &moved_stakeholders,
        key: None,
        path: &[],
    };
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let plan = ExercisePlan::draw(&mut random, now);
    let promised = plan_created(&ctx, &plan, 0, &new_in_view()).unwrap();
    let transfer = tree_request(
        &ctx,
        vec![
            exercise_node(
                &stored,
                "Transfer",
                canton_participant::contract_wire::LfValue::Record(vec![
                    canton_participant::contract_wire::LfValue::Party(erin.clone()),
                ]),
                true,
                &[gwen.clone()],
                vec![1],
            ),
            canton_participant::view_tree::Action::Create(
                canton_participant::view_tree::NewContract {
                    package_name: "sample-contract".into(),
                    package_id: package_id.clone(),
                    module: module.clone(),
                    name: name.clone(),
                    arg: moved_arg.clone(),
                    hash_arg: moved_hash.clone(),
                    signatories: moved_signatories.clone(),
                    stakeholders: moved_stakeholders.clone(),
                    key: None,
                },
            ),
        ],
        &[p1, me],
        &[gwen.clone()],
        &unique("xfer-transfer"),
        now,
        Some(&plan),
    );
    assert_eq!(
        transfer.created[0].contract_id_hex,
        promised.contract_id_hex
    );
    let transfer_id = send_and_answer_as_admin(&r, &mut c, &token, &transfer, now);
    let verdict = finalized_block_at(transfer_id);
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// A choice whose body exercises a choice of another contract (a **nested exercise**) in the same view, built by the Rust participant and
/// **confirmed by the official participant p1** (G8 P0, S-SPL-002). Both parties are co-hosted by p1 and the Rust participant, so every
/// participant that must see the child already sees the root and the child needs no view of its own. p1 re-interprets `Driver.Run`, which
/// exercises `Touch` on a `Held` that `erin` signs: the view must list `Held` as a consumed core input and put `erin`, a signatory of what
/// the subtree consumes, into the first quorum.
///
/// The first request leaves `Held` out of the view's inputs (the negative control): p1 has to refuse it. The second is complete.
#[test]
fn the_official_participant_confirms_a_nested_exercise_in_one_view() {
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::forms;
    let package_id = var("CANTON_RS_CONFIRM_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-nested"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let gwen = host_party_and_vet(&r, &mut c, &token, "gwen", true, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_CONFIRM_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let mut random = Os;
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let mut create = |c: &mut SequencerConnect,
                      template: &str,
                      value: lf_eval::Value,
                      signatories: Vec<String>,
                      stakeholders: Vec<String>| {
        let ty = types.template(world.main_package_id(), template).unwrap();
        let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
        let (module, name) = template.split_once(':').unwrap();
        let at = now(c);
        let built = build_create(
            &ctx,
            &Create {
                package_name: "confirm-subview",
                package_id: &package_id,
                module: vec![module.into()],
                name: vec![name.into()],
                arg,
                hash_arg,
                signatories: signatories.clone(),
                stakeholders: stakeholders.clone(),
                hosts: vec![p1.clone(), me.clone()],
                command_id: unique("nested-create"),
                key: None,
            },
            at,
            &mut random,
        )
        .unwrap();
        let id = send_and_answer_as_admin(&r, c, &token, &built, at);
        let verdict = finalized_at(id);
        assert!(verdict.contains("with verdict Approve"), "{verdict}");
        StoredContract {
            contract_id_hex: built.contract_id_hex.clone(),
            instance: built.instance.clone(),
            package_id: package_id.clone(),
            module: vec![module.into()],
            name: vec![name.into()],
            signatories,
            stakeholders,
        }
    };
    let record = |template: &str, fields: Vec<(&str, &str)>| lf_eval::Value::Record {
        tycon: Some(template.into()),
        fields: fields
            .into_iter()
            .map(|(k, v)| (k.into(), lf_eval::Value::Party(v.into())))
            .collect(),
    };
    let mut both = vec![erin.clone(), gwen.clone()];
    both.sort();
    let held = create(
        &mut c,
        "Confirm:Held",
        record("Confirm:Held", vec![("r", &erin), ("a", &gwen)]),
        vec![erin.clone()],
        both.clone(),
    );
    let driver = create(
        &mut c,
        "Confirm:Driver",
        record("Confirm:Driver", vec![("a", &gwen)]),
        vec![gwen.clone()],
        vec![gwen.clone()],
    );
    let run = |c: &mut SequencerConnect, touch_consumes: bool| {
        let at = now(c);
        let built = tree_request(
            &ctx,
            vec![
                exercise_node(
                    &driver,
                    "Run",
                    canton_participant::contract_wire::LfValue::Record(vec![
                        canton_participant::contract_wire::LfValue::ContractId(
                            held.contract_id_hex.clone(),
                        ),
                    ]),
                    false,
                    &[gwen.clone()],
                    vec![1],
                ),
                exercise_node(
                    &held,
                    "Touch",
                    canton_participant::contract_wire::LfValue::Record(vec![]),
                    touch_consumes,
                    &[gwen.clone()],
                    vec![],
                ),
            ],
            &[p1.clone(), me.clone()],
            &[gwen.clone()],
            &unique("nested-run"),
            at,
            None,
        );
        let id = send_and_answer_as_admin(&r, c, &token, &built, at);
        finalized_block_at(id)
    };
    // negative control: the nested exercise is said not to consume `Held` (the view's input would be a read), which p1 finds out when it
    // re-interprets the view
    let wrong = run(&mut c, false);
    assert!(wrong.contains("ParticipantReject"), "{wrong}");
    let right = run(&mut c, true);
    assert!(right.contains("with verdict Approve"), "{right}");
}

/// A one-root request built by `view_tree` with every party hosted by all of `hosts` (so the whole tree stays in one view).
fn tree_request(
    ctx: &canton_participant::submit::Context,
    nodes: Vec<canton_participant::view_tree::Action>,
    hosts: &[canton_participant::submit::Peer],
    actors: &[String],
    command_id: &str,
    now: i64,
    plan: Option<&canton_participant::submit::ExercisePlan>,
) -> canton_participant::submit::Built {
    let members: std::collections::BTreeSet<String> =
        hosts.iter().map(|h| h.member.clone()).collect();
    canton_participant::view_tree::build_transaction(
        ctx,
        &canton_participant::view_tree::Transaction {
            nodes,
            roots: vec![0],
            keys: Vec::new(),
            temp_ids: Default::default(),
            package_preference: Default::default(),
            ledger_time: None,
        },
        hosts,
        &|_: &str| members.clone(),
        actors,
        command_id,
        now,
        plan,
        &mut canton_participant::submit::Os,
    )
    .unwrap()
}

/// A consuming or non-consuming exercise node without children and with a known chosen value.
fn exercise_node(
    contract: &canton_participant::submit::StoredContract,
    choice: &str,
    argument: canton_participant::contract_wire::LfValue,
    consuming: bool,
    actors: &[String],
    children: Vec<usize>,
) -> canton_participant::view_tree::Action {
    canton_participant::view_tree::Action::Exercise {
        contract: contract.clone(),
        choice: choice.into(),
        argument: Some(argument),
        consuming,
        actors: actors.to_vec(),
        choice_observers: vec![],
        children,
        interface_id: None,
    }
}

/// A subtree with a **fetch**, a **nested exercise that creates**, and a create after them, all in one view, built by the Rust participant and
/// confirmed by the official participant p1 (G8 P0, S-SPL-002). p1 re-derives the id of every created contract from the seed of the node it
/// sits at, so an approval means the Rust participant numbers the nodes of the tree the way the official model does.
///
/// `Driver.Run` fetches `peer`, exercises `Touch` on `held` (which creates a `Receipt`) and creates a `Log`. The same request is built with
/// the numbering and the quorums `view_tree` derives (a fetch takes a child index: measured in S-SPL-002, kept in `node_seeds`); the negative
/// control says the nested exercise does not consume.
#[test]
fn the_official_participant_confirms_a_subtree_with_a_fetch_and_a_nested_create() {
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::forms;
    let package_id = var("CANTON_RS_TREE_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-tree"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let gwen = host_party_and_vet(&r, &mut c, &token, "gwen", true, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_TREE_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let record = |template: &str, fields: Vec<(&str, &str)>| lf_eval::Value::Record {
        tycon: Some(template.into()),
        fields: fields
            .into_iter()
            .map(|(k, v)| (k.into(), lf_eval::Value::Party(v.into())))
            .collect(),
    };
    let sorted_pair = |a: &str, b: &str| {
        let mut v = vec![a.to_string(), b.to_string()];
        v.sort();
        v
    };
    let create = |c: &mut SequencerConnect,
                  template: &str,
                  value: lf_eval::Value,
                  signatories: Vec<String>,
                  stakeholders: Vec<String>| {
        let ty = types.template(world.main_package_id(), template).unwrap();
        let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
        let (module, name) = template.split_once(':').unwrap();
        let at = now(c);
        let built = build_create(
            &ctx,
            &Create {
                package_name: "tree-view",
                package_id: &package_id,
                module: vec![module.into()],
                name: vec![name.into()],
                arg,
                hash_arg,
                signatories: signatories.clone(),
                stakeholders: stakeholders.clone(),
                hosts: vec![p1.clone(), me.clone()],
                command_id: unique("tree-create"),
                key: None,
            },
            at,
            &mut Os,
        )
        .unwrap();
        let id = send_and_answer_as_admin(&r, c, &token, &built, at);
        let verdict = finalized_at(id);
        assert!(verdict.contains("with verdict Approve"), "{verdict}");
        StoredContract {
            contract_id_hex: built.contract_id_hex.clone(),
            instance: built.instance.clone(),
            package_id: package_id.clone(),
            module: vec![module.into()],
            name: vec![name.into()],
            signatories,
            stakeholders,
        }
    };
    let both = sorted_pair(&erin, &gwen);
    let held = |c: &mut SequencerConnect| {
        create(
            c,
            "Tree:Held",
            record("Tree:Held", vec![("r", &erin), ("a", &gwen)]),
            vec![erin.clone()],
            both.clone(),
        )
    };
    let driver = create(
        &mut c,
        "Tree:Driver",
        record("Tree:Driver", vec![("a", &gwen), ("r", &erin)]),
        vec![gwen.clone()],
        both.clone(),
    );
    let peer = held(&mut c);
    // the contracts the subtree creates
    let receipt_value = record("Tree:Receipt", vec![("r", &erin), ("a", &gwen)]);
    let log_value = record("Tree:Log", vec![("a", &gwen), ("r", &erin)]);
    let receipt_ty = types
        .template(world.main_package_id(), "Tree:Receipt")
        .unwrap();
    let log_ty = types.template(world.main_package_id(), "Tree:Log").unwrap();
    let (receipt_arg, receipt_hash) = forms(&types, &receipt_ty, &receipt_value).unwrap();
    let (log_arg, log_hash) = forms(&types, &log_ty, &log_value).unwrap();
    let receipt_module = vec!["Tree".to_string()];
    let receipt_name = vec!["Receipt".to_string()];
    let log_name = vec!["Log".to_string()];
    let log_signatories = vec![gwen.clone()];
    let new_contract = |name: &[String],
                        arg: &LfValue,
                        hash: &canton_participant::contract_id::HashValue,
                        signatories: &[String]| {
        canton_participant::view_tree::Action::Create(canton_participant::view_tree::NewContract {
            package_name: "tree-view".into(),
            package_id: package_id.clone(),
            module: receipt_module.clone(),
            name: name.to_vec(),
            arg: arg.clone(),
            hash_arg: hash.clone(),
            signatories: signatories.to_vec(),
            stakeholders: both.clone(),
            key: None,
        })
    };
    // the node numbering (a fetch takes a child index), the quorums and the views all come from the port of Canton's decomposition: the request
    // is `Run` with a fetch, a nested exercise that creates, and a create
    let run = |c: &mut SequencerConnect, touched: &StoredContract, touch_consumes: bool| {
        let at = now(c);
        let built = tree_request(
            &ctx,
            vec![
                exercise_node(
                    &driver,
                    "Run",
                    LfValue::Record(vec![
                        LfValue::ContractId(peer.contract_id_hex.clone()),
                        LfValue::ContractId(touched.contract_id_hex.clone()),
                    ]),
                    false,
                    &[gwen.clone()],
                    vec![1, 2, 4],
                ),
                canton_participant::view_tree::Action::Fetch {
                    contract: peer.clone(),
                    actors: vec![gwen.clone()],
                    interface_id: None,
                },
                exercise_node(
                    touched,
                    "Touch",
                    LfValue::Record(vec![]),
                    touch_consumes,
                    &[gwen.clone()],
                    vec![3],
                ),
                new_contract(&receipt_name, &receipt_arg, &receipt_hash, &both),
                new_contract(&log_name, &log_arg, &log_hash, &log_signatories),
            ],
            &[p1.clone(), me.clone()],
            &[gwen.clone()],
            &unique("tree-run"),
            at,
            None,
        );
        let id = send_and_answer_as_admin(&r, c, &token, &built, at);
        finalized_block_at(id)
    };
    let first = held(&mut c);
    let second = held(&mut c);
    // negative control: the nested exercise is said not to consume what it consumes
    let wrong = run(&mut c, &first, false);
    assert!(wrong.contains("ParticipantReject"), "{wrong}");
    let right = run(&mut c, &second, true);
    assert!(right.contains("with verdict Approve"), "{right}");
}

/// G8 P0 (S-SPL-003), the receiving side: **p1 submits** `Driver.Run` of the tree fixture (a fetch, a nested exercise that creates a `Receipt`, a
/// create of a `Log`, all in one view because `erin`, the Rust participant's party, is an informee of the root) and this participant, which
/// hosts `erin`, confirms it. The creates sit below the root exercise, so their node seeds are derived through the tree, which the view does not
/// state: the discriminator check needs the positions the engine's replay gives. The negative controls run on the very view the runtime approved:
/// the old rule (every create a direct child) refuses it, and so do positions that are not the replay's.
#[test]
fn the_rust_participant_confirms_a_tree_p1_submits_as_a_fetch_view_and_a_touch_view() {
    use canton_participant::view_conformance as vc;
    use canton_participant::view_receive as vr;
    let name = unique("r-tree-recv");
    let (r, mut c, token) = authenticated(&name);
    let packages = [var("CANTON_RS_TREE_PACKAGE")];
    let erin = host_consortium_party_vetting(&r, &mut c, &token, "erin", &packages);
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |content: String| {
        let name = format!("{}.treecmd", unique("tc"));
        std::fs::write(dir.join(format!("{name}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        name
    };
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![erin.clone()];
    let dir_state = state_dir(&name);
    let engine = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_TREE_DAR"))).unwrap();
    let mut runtime = rt::Runtime::open(config, engine, Some(&dir_state), start).unwrap();
    let id_of = |name: &str| {
        let l = log_line_with(&["SCF treecmd_done=", name]).expect("done");
        l.rsplit('=').next().unwrap().trim().to_string()
    };
    let peer = id_of(&command(format!("held,{erin},{alice}")));
    let held = id_of(&command(format!("held,{erin},{alice}")));
    let driver = id_of(&command(format!("driver,{alice},{erin}")));
    let mut steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 90, |rt| {
        rt.ledger.is_active(&held) && rt.ledger.is_active(&peer)
    });
    assert!(runtime.ledger.is_active(&held), "{steps:#?}");
    raise_threshold_to_two(&r, &mut c, &token, &erin);
    std::thread::sleep(std::time::Duration::from_secs(2));
    command(format!("run,{alice},{driver},{peer},{held}"));
    let before = steps.len();
    steps.extend(run_until(
        &mut runtime,
        &mut c,
        &token,
        &r.signing_key,
        60,
        |rt| rt.ledger.archived_by(&held).is_some(),
    ));
    let answered: Vec<&rt::ToSend> = steps[before..].iter().flat_map(|s| &s.to_send).collect();
    for a in &answered {
        eprintln!(
            "TREE answer at {} decisions={:?}",
            a.request_time, a.decisions
        );
    }
    let answer = answered.first().expect("the runtime answered the tree");
    assert_eq!(
        answer.decision().outcome,
        canton_participant::confirmation_wire::Outcome::Approve,
        "{answer:?}"
    );
    let finalized = finalized_block_at(answer.request_time);
    assert!(finalized.contains("with verdict Approve"), "{finalized}");
    // negative controls on the view the runtime approved
    let events = c
        .subscribe(
            &r.member(),
            &synchronizer,
            &token,
            Some(answer.request_time),
            1,
            std::time::Duration::from_secs(5),
        )
        .unwrap();
    let event = canton_participant::sequencing_wire::decode_delivered(&events[0]).unwrap();
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    let mut touch = None;
    let mut fetch = None;
    for e in &event.envelopes {
        let Ok(views) = vr::decrypt_views(e, &r.encryption_fingerprint(), r.encryption_secret())
        else {
            continue;
        };
        for v in &views.view_trees {
            let tree = v.tree.clone().unwrap();
            for view in vr::revealed_views(&tree).unwrap() {
                if matches!(
                    view.participant_data
                        .action_description
                        .as_ref()
                        .and_then(|a| a.description.as_ref()),
                    Some(Description::Exercise(_))
                ) {
                    touch = Some((tree.clone(), view));
                } else if matches!(
                    view.participant_data
                        .action_description
                        .as_ref()
                        .and_then(|a| a.description.as_ref()),
                    Some(Description::Fetch(_))
                ) {
                    fetch = Some(view);
                }
            }
        }
    }
    let fetch = fetch.expect("the fetch view is revealed to this participant");
    let fetch_engine = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_TREE_DAR"))).unwrap();
    assert!(vc::check_fetch_view(&fetch_engine, &fetch).is_ok());
    // negative controls: an actor that is no stakeholder, and a fetch that also consumes
    let mut stranger = fetch.clone();
    if let Some(Description::Fetch(f)) = stranger
        .participant_data
        .action_description
        .as_mut()
        .and_then(|a| a.description.as_mut())
    {
        f.actors = vec!["nobody::0000".into()];
    }
    assert!(matches!(
        vc::check_fetch_view(&fetch_engine, &stranger),
        Err(vc::Nonconformance::ActionDiffers(_))
    ));
    let mut consuming = fetch.clone();
    consuming.participant_data.core_inputs[0].consumed = true;
    assert!(matches!(
        vc::check_fetch_view(&fetch_engine, &consuming),
        Err(vc::Nonconformance::ActionDiffers(_))
    ));
    let (tree, view) = touch.expect("the Touch view is revealed to this participant");
    let prepared = vr::revealed_participant_metadata(&tree)
        .unwrap()
        .preparation_time;
    let common = vr::revealed_common_metadata(&tree).unwrap();
    let engine = vc::Engine::load(std::path::Path::new(&var("CANTON_RS_TREE_DAR"))).unwrap();
    let (_, positions) = vc::check_exercise_view_placed(&engine, &view, &common).unwrap();
    assert_eq!(
        positions,
        vec![vec![0]],
        "the Receipt is the first child of Touch"
    );
    assert_eq!(
        vc::check_discriminators_at(&view, prepared, Some(&positions)),
        Ok(())
    );
    // negative controls: another preparation time, and a position that is not the replay's
    assert!(matches!(
        vc::check_discriminators_at(&view, prepared + 1, Some(&positions)),
        Err(vc::Nonconformance::DiscriminatorDiffers { .. })
    ));
    assert!(matches!(
        vc::check_discriminators_at(&view, prepared, Some(&[vec![1]])),
        Err(vc::Nonconformance::DiscriminatorDiffers { .. })
    ));
    let _ = std::fs::remove_dir_all(&dir_state);
}

/// Like `send_and_answer_as_admin`, with the participant's answer for each view it confirms: `(position, confirming parties)`.
fn send_and_answer_views(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    built: &canton_participant::submit::Built,
    now: i64,
    views: &[(Vec<Vec<bool>>, Vec<String>)],
) -> i64 {
    use canton_participant::{confirmation_wire as cw, sequencing_wire as sw};
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    c.send_async(&r.member(), &synchronizer, token, built.request.clone())
        .expect("the sequencer accepts the request");
    let mut from = now + 1;
    let request_id = loop {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                token,
                Some(from),
                1,
                std::time::Duration::from_secs(10),
            )
            .expect("subscribe");
        let d = sw::decode_delivered(events.first().expect("our request comes back")).unwrap();
        from = d.timestamp_micros + 1;
        if d.message_id.as_deref() == Some(built.message_id.as_str()) {
            break d.timestamp_micros;
        }
    };
    let responses: Vec<cw::ViewResponse> = views
        .iter()
        .filter(|(_, parties)| !parties.is_empty())
        .map(|(position, parties)| cw::ViewResponse {
            view_position: position,
            outcome: cw::Outcome::Approve,
            confirming_parties: parties,
        })
        .collect();
    if !responses.is_empty() {
        let (content, signatures) = cw::confirmation_responses(
            request_id,
            &built.root_hash,
            &synchronizer,
            &r.member(),
            &responses,
            &r.signing_key,
        );
        c.send_async(
            &r.member(),
            &synchronizer,
            token,
            sw::signed_submission_request(
                sw::submission_request_signed(
                    &r.member(),
                    &unique("resp"),
                    &[(vec![cw::mediator_group(0)], content, signatures)],
                    request_id + 30_000_000,
                ),
                &r.signing_key,
            ),
        )
        .expect("the sequencer accepts the responses");
    }
    request_id
}

/// G8 P1: a root exercise whose child exercise has a **view of its own**, built by the Rust participant and confirmed by the official participant
/// p1. `Driver.Run` (actor `gwen`, hosted by the Rust participant only) exercises `Touch` on a `Held` that `erin` signs; `erin` is co-hosted by
/// p1, so the child's informees are hosted by a participant the root's are not and the child is a subview that only p1 and this participant read.
/// p1 has to re-interpret the subview without seeing the root.
#[test]
fn the_official_participant_confirms_a_subview_the_rust_participant_built() {
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::forms;
    let package_id = var("CANTON_RS_CONFIRM_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-subview"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let gwen = host_party_and_vet(&r, &mut c, &token, "gwen", false, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_CONFIRM_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let admin = r.uid();
    let create = |c: &mut SequencerConnect,
                  template: &str,
                  fields: Vec<(&str, &str)>,
                  signatories: Vec<String>,
                  stakeholders: Vec<String>,
                  hosts: Vec<Peer>| {
        let value = lf_eval::Value::Record {
            tycon: Some(template.into()),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.into(), lf_eval::Value::Party(v.into())))
                .collect(),
        };
        let ty = types.template(world.main_package_id(), template).unwrap();
        let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
        let (module, name) = template.split_once(':').unwrap();
        let at = now(c);
        let built = build_create(
            &ctx,
            &Create {
                package_name: "confirm-subview",
                package_id: &package_id,
                module: vec![module.into()],
                name: vec![name.into()],
                arg,
                hash_arg,
                signatories: signatories.clone(),
                stakeholders: stakeholders.clone(),
                hosts,
                command_id: unique("subview-create"),
                key: None,
            },
            at,
            &mut Os,
        )
        .unwrap();
        // gwen is hosted by this participant alone, so it confirms for her itself
        let mut parties = vec![admin.clone()];
        parties.extend(signatories.iter().filter(|p| **p == gwen).cloned());
        let id = send_and_answer_views(&r, c, &token, &built, at, &[(vec![vec![]], parties)]);
        assert!(finalized_at(id).contains("with verdict Approve"));
        StoredContract {
            contract_id_hex: built.contract_id_hex.clone(),
            instance: built.instance.clone(),
            package_id: package_id.clone(),
            module: vec![module.into()],
            name: vec![name.into()],
            signatories,
            stakeholders,
        }
    };
    let mut both = vec![erin.clone(), gwen.clone()];
    both.sort();
    let held = create(
        &mut c,
        "Confirm:Held",
        vec![("r", &erin), ("a", &gwen)],
        vec![erin.clone()],
        both,
        vec![p1.clone(), me.clone()],
    );
    let driver = create(
        &mut c,
        "Confirm:Driver",
        vec![("a", &gwen)],
        vec![gwen.clone()],
        vec![gwen.clone()],
        vec![me.clone()],
    );
    use canton_participant::contract_wire::LfValue;
    use canton_participant::view_tree::{build_transaction, view_positions, Action, Transaction};
    let make_tx = |touch_consumes: bool| Transaction {
        nodes: vec![
            Action::Exercise {
                contract: driver.clone(),
                choice: "Run".into(),
                argument: Some(LfValue::Record(vec![LfValue::ContractId(
                    held.contract_id_hex.clone(),
                )])),
                consuming: false,
                actors: vec![gwen.clone()],
                choice_observers: vec![],
                children: vec![1],
                interface_id: None,
            },
            Action::Exercise {
                contract: held.clone(),
                choice: "Touch".into(),
                argument: Some(LfValue::Record(vec![])),
                consuming: touch_consumes,
                actors: vec![gwen.clone()],
                choice_observers: vec![],
                children: vec![],
                interface_id: None,
            },
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |party: &str| -> std::collections::BTreeSet<String> {
        if party == erin {
            [p1.member.clone(), me.member.clone()].into()
        } else {
            [me.member.clone()].into()
        }
    };
    let mut submit = |tx: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            tx,
            &[p1.clone(), me.clone()],
            &hosting,
            &[gwen.clone()],
            &unique("subview-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        // this participant answers for the parties it alone confirms for: the admin party and gwen
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(tx, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties
                        .into_iter()
                        .filter(|p| *p == admin || *p == gwen)
                        .collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    // negative control: the child says it does not consume `Held`, which p1 finds out when it re-interprets the subview
    let wrong = submit(&make_tx(false));
    assert!(wrong.contains("ParticipantReject"), "{wrong}");
    let verdict = submit(&make_tx(true));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

#[test]
fn the_official_participant_confirms_a_third_level_subview_the_rust_participant_built() {
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::forms;
    let package_id = var("CANTON_RS_DEPTH_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-depth"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let gwen = host_party_and_vet(&r, &mut c, &token, "gwen", false, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_DEPTH_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let admin = r.uid();
    let create = |c: &mut SequencerConnect,
                  template: &str,
                  fields: Vec<(&str, &str)>,
                  signatories: Vec<String>,
                  stakeholders: Vec<String>,
                  hosts: Vec<Peer>| {
        let value = lf_eval::Value::Record {
            tycon: Some(template.into()),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.into(), lf_eval::Value::Party(v.into())))
                .collect(),
        };
        let ty = types.template(world.main_package_id(), template).unwrap();
        let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
        let (module, name) = template.split_once(':').unwrap();
        let at = now(c);
        let built = build_create(
            &ctx,
            &Create {
                package_name: "depth-view",
                package_id: &package_id,
                module: vec![module.into()],
                name: vec![name.into()],
                arg,
                hash_arg,
                signatories: signatories.clone(),
                stakeholders: stakeholders.clone(),
                hosts,
                command_id: unique("subview-create"),
                key: None,
            },
            at,
            &mut Os,
        )
        .unwrap();
        // gwen is hosted by this participant alone, so it confirms for her itself
        let mut parties = vec![admin.clone()];
        parties.extend(signatories.iter().filter(|p| **p == gwen).cloned());
        let id = send_and_answer_views(&r, c, &token, &built, at, &[(vec![vec![]], parties)]);
        assert!(finalized_at(id).contains("with verdict Approve"));
        StoredContract {
            contract_id_hex: built.contract_id_hex.clone(),
            instance: built.instance.clone(),
            package_id: package_id.clone(),
            module: vec![module.into()],
            name: vec![name.into()],
            signatories,
            stakeholders,
        }
    };
    let mut both = vec![erin.clone(), gwen.clone()];
    both.sort();
    let held = create(
        &mut c,
        "Depth:Held",
        vec![("r", &erin), ("a", &gwen)],
        vec![erin.clone()],
        both,
        vec![p1.clone(), me.clone()],
    );
    let driver = create(
        &mut c,
        "Depth:Driver",
        vec![("a", &gwen)],
        vec![gwen.clone()],
        vec![gwen.clone()],
        vec![me.clone()],
    );
    let mid = create(
        &mut c,
        "Depth:Mid",
        vec![("a", &gwen)],
        vec![gwen.clone()],
        vec![gwen.clone()],
        vec![me.clone()],
    );
    use canton_participant::contract_wire::LfValue;
    use canton_participant::view_tree::{build_transaction, view_positions, Action, Transaction};
    // depth three: Driver.Run (gwen, this participant alone) -> Mid.Step (same view) -> Held.Touch (erin's host p1 too: a view of its own)
    let make_tx = |touch_consumes: bool| Transaction {
        nodes: vec![
            Action::Exercise {
                contract: driver.clone(),
                choice: "Run".into(),
                argument: Some(LfValue::Record(vec![
                    LfValue::ContractId(mid.contract_id_hex.clone()),
                    LfValue::ContractId(held.contract_id_hex.clone()),
                ])),
                consuming: false,
                actors: vec![gwen.clone()],
                choice_observers: vec![],
                children: vec![1],
                interface_id: None,
            },
            Action::Exercise {
                contract: mid.clone(),
                choice: "Step".into(),
                argument: Some(LfValue::Record(vec![LfValue::ContractId(
                    held.contract_id_hex.clone(),
                )])),
                consuming: false,
                actors: vec![gwen.clone()],
                choice_observers: vec![],
                children: vec![2],
                interface_id: None,
            },
            Action::Exercise {
                contract: held.clone(),
                choice: "Touch".into(),
                argument: Some(LfValue::Record(vec![])),
                consuming: touch_consumes,
                actors: vec![gwen.clone()],
                choice_observers: vec![],
                children: vec![],
                interface_id: None,
            },
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |party: &str| -> std::collections::BTreeSet<String> {
        if party == erin {
            [p1.member.clone(), me.member.clone()].into()
        } else {
            [me.member.clone()].into()
        }
    };
    let mut submit = |tx: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            tx,
            &[p1.clone(), me.clone()],
            &hosting,
            &[gwen.clone()],
            &unique("subview-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        // this participant answers for the parties it alone confirms for: the admin party and gwen
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(tx, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties
                        .into_iter()
                        .filter(|p| *p == admin || *p == gwen)
                        .collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    // negative control: the child says it does not consume `Held`, which p1 finds out when it re-interprets the subview
    let wrong = submit(&make_tx(false));
    assert!(wrong.contains("ParticipantReject"), "{wrong}");
    let verdict = submit(&make_tx(true));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// G8 P4 (S-SPL-013): the official participant confirms a create of a template **with a key** that the Rust participant built: the instance
/// states the key and its maintainers, the contract id commits to the key hash, and the view resolves the key. A key whose hash is not the
/// hash of its value is refused.
#[test]
fn the_official_participant_confirms_a_keyed_create_the_rust_participant_built() {
    use canton_participant::contract_id::HashValue;
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{build_create, Context, Create, NewKey, Os, Peer};
    use canton_participant::value_forms::forms;
    let package_id = var("CANTON_RS_KEYED_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-keyed"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_KEYED_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let value = lf_eval::Value::Record {
        tycon: Some("Keyed:Registry".into()),
        fields: vec![
            ("owner".into(), lf_eval::Value::Party(erin.clone())),
            ("name".into(), lf_eval::Value::Text("entry".into())),
            ("payload".into(), lf_eval::Value::Text("kept".into())),
        ],
    };
    let ty = types
        .template(world.main_package_id(), "Keyed:Registry")
        .unwrap();
    let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
    let tuple = |name: &str| HashValue::Record {
        module: vec!["DA".into(), "Types".into()],
        name: vec!["Tuple2".into()],
        fields: vec![
            ("_1".into(), HashValue::Party(erin.clone())),
            ("_2".into(), HashValue::Text(name.into())),
        ],
    };
    let key_value = LfValue::Record(vec![
        LfValue::Party(erin.clone()),
        LfValue::Text("entry".into()),
    ]);
    let send = |c: &mut SequencerConnect, hash_of: &str| -> String {
        let now = c
            .sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap();
        let built = build_create(
            &ctx,
            &Create {
                package_name: "keyed-vault",
                package_id: &package_id,
                module: vec!["Keyed".into()],
                name: vec!["Registry".into()],
                arg: arg.clone(),
                hash_arg: hash_arg.clone(),
                signatories: vec![erin.clone()],
                stakeholders: vec![erin.clone()],
                hosts: vec![p1.clone(), me.clone()],
                command_id: unique("keyed-create"),
                key: Some(NewKey {
                    value: key_value.clone(),
                    hash_value: tuple(hash_of),
                    maintainers: vec![erin.clone()],
                }),
            },
            now,
            &mut Os,
        )
        .unwrap();
        let id = send_and_answer_as_admin(&r, c, &token, &built, now);
        finalized_at(id)
    };
    // negative control: the hash states another key than the value does
    let wrong = send(&mut c, "other");
    assert!(!wrong.contains("with verdict Approve"), "{wrong}");
    let verdict = send(&mut c, "entry");
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// G8 P4 (S-SPL-014): the official participant confirms an exercise whose choice **fetches by key** (`ReadByKey`), built by the Rust
/// participant: the view's `resolved_keys` states the key and the contract it resolved to. A key that resolves to nothing is refused.
#[test]
fn the_official_participant_confirms_an_exercise_that_fetches_by_key_the_rust_participant_built() {
    use canton_participant::contract_id::HashValue;
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{
        build_create, Context, Create, NewKey, Os, Peer, StoredContract,
    };
    use canton_participant::value_forms::forms;
    use canton_participant::view_tree::{
        build_transaction, view_positions, Action, KeyUse, Transaction,
    };
    let package_id = var("CANTON_RS_KEYED_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-bykey"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_KEYED_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let value = lf_eval::Value::Record {
        tycon: Some("Keyed:Registry".into()),
        fields: vec![
            ("owner".into(), lf_eval::Value::Party(erin.clone())),
            ("name".into(), lf_eval::Value::Text("entry".into())),
            ("payload".into(), lf_eval::Value::Text("kept".into())),
        ],
    };
    let ty = types
        .template(world.main_package_id(), "Keyed:Registry")
        .unwrap();
    let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
    let key_hash = HashValue::Record {
        module: vec!["DA".into(), "Types".into()],
        name: vec!["Tuple2".into()],
        fields: vec![
            ("_1".into(), HashValue::Party(erin.clone())),
            ("_2".into(), HashValue::Text("entry".into())),
        ],
    };
    let key_value = LfValue::Record(vec![
        LfValue::Party(erin.clone()),
        LfValue::Text("entry".into()),
    ]);
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let at = now(&mut c);
    let created = build_create(
        &ctx,
        &Create {
            package_name: "keyed-vault",
            package_id: &package_id,
            module: vec!["Keyed".into()],
            name: vec!["Registry".into()],
            arg,
            hash_arg,
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone()],
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("bykey-create"),
            key: Some(NewKey {
                value: key_value.clone(),
                hash_value: key_hash.clone(),
                maintainers: vec![erin.clone()],
            }),
        },
        at,
        &mut Os,
    )
    .unwrap();
    let id = send_and_answer_as_admin(&r, &mut c, &token, &created, at);
    assert!(finalized_at(id).contains("with verdict Approve"));
    let registry = StoredContract {
        contract_id_hex: created.contract_id_hex.clone(),
        instance: created.instance.clone(),
        package_id: package_id.clone(),
        module: vec!["Keyed".into()],
        name: vec!["Registry".into()],
        signatories: vec![erin.clone()],
        stakeholders: vec![erin.clone()],
    };
    let tx = |resolves_to: Option<String>| Transaction {
        nodes: vec![
            Action::Exercise {
                contract: registry.clone(),
                choice: "ReadByKey".into(),
                argument: Some(LfValue::Record(vec![key_value.clone()])),
                consuming: false,
                actors: vec![erin.clone()],
                choice_observers: vec![],
                children: vec![1],
                interface_id: None,
            },
            Action::Fetch {
                contract: registry.clone(),
                actors: vec![erin.clone()],
                interface_id: None,
            },
        ],
        roots: vec![0],
        keys: vec![(
            1,
            KeyUse {
                package_name: "keyed-vault".into(),
                package_id: package_id.clone(),
                module: vec!["Keyed".into()],
                name: vec!["Registry".into()],
                value: key_value.clone(),
                hash_value: key_hash.clone(),
                maintainers: vec![erin.clone()],
                contract_id: resolves_to,
            },
        )],
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |_: &str| -> std::collections::BTreeSet<String> {
        [p1.member.clone(), me.member.clone()].into()
    };
    let admin = r.uid();
    let mut submit = |t: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            t,
            &[p1.clone(), me.clone()],
            &hosting,
            &[erin.clone()],
            &unique("bykey-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(t, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties.into_iter().filter(|p| *p == admin).collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    // negative control: the key is said to resolve to nothing, which p1 finds out when it re-interprets the choice
    let wrong = submit(&tx(None));
    assert!(!wrong.contains("with verdict Approve"), "{wrong}");
    let verdict = submit(&tx(Some(registry.contract_id_hex.clone())));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// G8 P5 (S-SPL-015): the official participant confirms an exercise of a choice **through an interface** that the Rust participant built:
/// the view's action description names the interface. Without it, or with another interface, p1 refuses.
#[test]
fn the_official_participant_confirms_an_exercise_through_an_interface_the_rust_participant_built() {
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::forms;
    use canton_participant::view_tree::{build_transaction, view_positions, Action, Transaction};
    let package_id = var("CANTON_RS_IFACE_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-iface"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_IFACE_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let value = lf_eval::Value::Record {
        tycon: Some("Iface:Holding".into()),
        fields: vec![("owner".into(), lf_eval::Value::Party(erin.clone()))],
    };
    let ty = types
        .template(world.main_package_id(), "Iface:Holding")
        .unwrap();
    let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let at = now(&mut c);
    let created = build_create(
        &ctx,
        &Create {
            package_name: "iface-view",
            package_id: &package_id,
            module: vec!["Iface".into()],
            name: vec!["Holding".into()],
            arg,
            hash_arg,
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone()],
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("iface-create"),
            key: None,
        },
        at,
        &mut Os,
    )
    .unwrap();
    let id = send_and_answer_as_admin(&r, &mut c, &token, &created, at);
    assert!(finalized_at(id).contains("with verdict Approve"));
    let holding = StoredContract {
        contract_id_hex: created.contract_id_hex.clone(),
        instance: created.instance.clone(),
        package_id: package_id.clone(),
        module: vec!["Iface".into()],
        name: vec!["Holding".into()],
        signatories: vec![erin.clone()],
        stakeholders: vec![erin.clone()],
    };
    let tx = |interface: Option<String>| Transaction {
        nodes: vec![Action::Exercise {
            contract: holding.clone(),
            choice: "Poke".into(),
            argument: Some(LfValue::Record(vec![])),
            // `Poke` is a consuming choice of the interface (no `nonconsuming`)
            consuming: true,
            actors: vec![erin.clone()],
            choice_observers: vec![],
            interface_id: interface,
            children: vec![],
        }],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |_: &str| -> std::collections::BTreeSet<String> {
        [p1.member.clone(), me.member.clone()].into()
    };
    let admin = r.uid();
    let mut submit = |t: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            t,
            &[p1.clone(), me.clone()],
            &hosting,
            &[erin.clone()],
            &unique("iface-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(t, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties.into_iter().filter(|p| *p == admin).collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    // negative control: the choice belongs to the interface, so a view that does not name it is not what p1 rebuilds
    let wrong = submit(&tx(None));
    assert!(!wrong.contains("with verdict Approve"), "{wrong}");
    let verdict = submit(&tx(Some(format!("{package_id}:Iface:IHolding"))));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// G8 U-37 (S-SPL-016): the official participant confirms a **Splice** exercise the Rust participant built from the official LocalNet's own
/// record: `DsoRules_OnboardValidator` (an exercise of the DSO rules by an SV that creates a `ValidatorLicense`). The `DsoRules` contract and the
/// exercise are the recorded ones with the party ids swapped for parties this test hosts, and the times set to the request's ledger time.
#[test]
fn the_official_participant_confirms_a_splice_exercise_the_rust_participant_built() {
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::{forms, lf_form};
    use canton_participant::view_tree::{
        build_transaction, view_positions, Action, NewContract, Transaction,
    };
    let dar = var("CANTON_RS_SPLICE_DAR");
    let updates: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(std::path::Path::new(&var("CANTON_RS_SPLICE_UPDATES"))).unwrap(),
    )
    .unwrap();
    let updates = updates["transactions"].as_array().unwrap();
    let world = lf_eval::World::open(std::path::Path::new(&dar)).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let (r, mut c, token) = authenticated(&unique("r-submit-splice"));
    let all_packages = world.package_ids();
    let dso = host_party_and_vet_all(&r, &mut c, &token, "dso", true, &all_packages);
    let sv = host_party_and_vet_all(&r, &mut c, &token, "sv", true, &all_packages);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    // the recorded events: the DsoRules the bootstrap created, and the OnboardValidator exercise with the license it created
    let created_dso_rules = updates[0]["events_by_id"]
        .as_object()
        .unwrap()
        .values()
        .find(|e| {
            e["event_type"] == "created_event"
                && e["template_id"]
                    .as_str()
                    .unwrap()
                    .ends_with(":Splice.DsoRules:DsoRules")
        })
        .unwrap()
        .clone();
    let onboard = &updates[2]["events_by_id"];
    let exercise_event = onboard
        .as_object()
        .unwrap()
        .values()
        .find(|e| e["event_type"] == "exercised_event")
        .unwrap()
        .clone();
    let license_event = onboard
        .as_object()
        .unwrap()
        .values()
        .find(|e| e["event_type"] == "created_event")
        .unwrap()
        .clone();
    let official_dso = created_dso_rules["signatories"][0]
        .as_str()
        .unwrap()
        .to_string();
    let official_sv = exercise_event["acting_parties"][0]
        .as_str()
        .unwrap()
        .to_string();
    let swap = |json: &serde_json::Value, at_micros: Option<i64>| -> serde_json::Value {
        let mut text = json
            .to_string()
            .replace(&official_dso, &dso)
            .replace(&official_sv, &sv);
        if let Some(at) = at_micros {
            // the recorded times are the ledger time of the recorded request: here, this request's
            let recorded = exercise_event["created_at"]
                .as_str()
                .map(String::from)
                .or_else(|| license_event["created_at"].as_str().map(String::from));
            if let Some(recorded) = recorded {
                text = text.replace(&recorded, &lf_eval::typed_json::format_timestamp_micros(at));
            }
        }
        serde_json::from_str(&text).unwrap()
    };
    let split = |id: &str| -> (String, String, Vec<String>, Vec<String>) {
        let (package, template) = id.split_once(':').unwrap();
        let (module, name) = template.split_once(':').unwrap();
        (
            package.to_string(),
            types.package_name(package).unwrap(),
            module.split('.').map(String::from).collect(),
            name.split('.').map(String::from).collect(),
        )
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let swapped = |parties: &serde_json::Value| -> Vec<String> {
        parties
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                p.as_str()
                    .unwrap()
                    .replace(&official_dso, &dso)
                    .replace(&official_sv, &sv)
            })
            .collect()
    };

    // 1. the DsoRules contract (a root create, signed by the DSO party)
    let dso_template_id = created_dso_rules["template_id"].as_str().unwrap();
    let (dso_package, dso_package_name, dso_module, dso_name) = split(dso_template_id);
    let dso_local = dso_template_id.split_once(':').unwrap().1;
    let dso_ty = types.template(&dso_package, dso_local).unwrap();
    let dso_payload = swap(&created_dso_rules["create_arguments"], None);
    let dso_value = types.decode(&dso_ty, &dso_payload).unwrap();
    let (dso_arg, dso_hash) = forms(&types, &dso_ty, &dso_value).unwrap();
    let at = now(&mut c);
    let signatories = swapped(&created_dso_rules["signatories"]);
    let mut stakeholders = signatories.clone();
    stakeholders.extend(swapped(&created_dso_rules["observers"]));
    stakeholders.sort();
    let built = build_create(
        &ctx,
        &Create {
            package_name: &dso_package_name,
            package_id: &dso_package,
            module: dso_module.clone(),
            name: dso_name.clone(),
            arg: dso_arg,
            hash_arg: dso_hash,
            signatories: signatories.clone(),
            stakeholders: stakeholders.clone(),
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("splice-dso-rules"),
            key: None,
        },
        at,
        &mut Os,
    )
    .unwrap();
    let id = send_and_answer_as_admin(&r, &mut c, &token, &built, at);
    let verdict = finalized_at(id);
    assert!(
        verdict.contains("with verdict Approve"),
        "the DsoRules create: {verdict}"
    );
    let dso_rules = StoredContract {
        contract_id_hex: built.contract_id_hex.clone(),
        instance: built.instance.clone(),
        package_id: dso_package.clone(),
        module: dso_module,
        name: dso_name,
        signatories,
        stakeholders,
    };

    // 2. the OnboardValidator exercise and the license it creates
    let choice = exercise_event["choice"].as_str().unwrap();
    let choice_types = types.choice(&dso_package, dso_local, choice).unwrap();
    let license_template_id = license_event["template_id"].as_str().unwrap();
    let (lic_package, lic_package_name, lic_module, lic_name) = split(license_template_id);
    let lic_local = license_template_id.split_once(':').unwrap().1;
    let lic_ty = types.template(&lic_package, lic_local).unwrap();
    let hosting = |_: &str| -> std::collections::BTreeSet<String> {
        [p1.member.clone(), me.member.clone()].into()
    };
    let admin = r.uid();
    let mut run = |label: &str, choice_argument: &serde_json::Value| -> String {
        let at = now(&mut c);
        let lic_payload = swap(&license_event["create_arguments"], Some(at));
        let lic_value = types.decode(&lic_ty, &lic_payload).unwrap();
        let (lic_arg, lic_hash) = forms(&types, &lic_ty, &lic_value).unwrap();
        let lic_signatories = swapped(&license_event["signatories"]);
        let mut lic_stakeholders = lic_signatories.clone();
        lic_stakeholders.extend(swapped(&license_event["observers"]));
        lic_stakeholders.sort();
        let argument_value = types
            .decode(&choice_types.argument, choice_argument)
            .unwrap();
        let argument = lf_form(&types, &choice_types.argument, &argument_value).unwrap();
        let tx = Transaction {
            nodes: vec![
                Action::Exercise {
                    contract: dso_rules.clone(),
                    choice: choice.to_string(),
                    argument: Some(argument),
                    consuming: choice_types.consuming,
                    actors: swapped(&exercise_event["acting_parties"]),
                    choice_observers: vec![],
                    interface_id: None,
                    children: vec![1],
                },
                Action::Create(NewContract {
                    package_name: lic_package_name.clone(),
                    package_id: lic_package.clone(),
                    module: lic_module.clone(),
                    name: lic_name.clone(),
                    arg: lic_arg,
                    hash_arg: lic_hash,
                    signatories: lic_signatories,
                    stakeholders: lic_stakeholders,
                    key: None,
                }),
            ],
            roots: vec![0],
            keys: Vec::new(),
            temp_ids: Default::default(),
            package_preference: Default::default(),
            ledger_time: None,
        };
        let built = build_transaction(
            &ctx,
            &tx,
            &[p1.clone(), me.clone()],
            &hosting,
            &swapped(&exercise_event["acting_parties"]),
            &unique(label),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(&tx, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties.into_iter().filter(|p| *p == admin).collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    let argument = swap(&exercise_event["choice_argument"], None);
    // negative control: another contact point is not what the choice body creates
    let mut wrong_argument = argument.clone();
    wrong_argument["contactPoint"] = serde_json::json!("somewhere else");
    let wrong = run("splice-wrong", &wrong_argument);
    assert!(!wrong.contains("with verdict Approve"), "{wrong}");
    let verdict = run("splice-onboard", &argument);
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// G8 U-37 (S-SPL-017): the recorded transactions of the official Splice LocalNet, replayed through the Rust participant in order. The contracts of the
/// bootstrap are created first (each a root create); then each recorded transaction with one root whose parties are the two hosted ones, whose
/// inputs are contracts this test created, and whose values the protocol forms can write, is built by the Rust participant and judged by the
/// official one. The test prints what became of every transaction and asserts that a floor of them is approved.
#[test]
fn the_official_participant_confirms_recorded_splice_transactions_the_rust_participant_built() {
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::{forms, lf_form};
    use canton_participant::view_tree::{
        build_transaction, view_positions, Action, NewContract, Transaction,
    };
    use std::collections::BTreeMap;
    let dar = var("CANTON_RS_SPLICE_DAR");
    let updates: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(std::path::Path::new(&var("CANTON_RS_SPLICE_UPDATES"))).unwrap(),
    )
    .unwrap();
    let updates = updates["transactions"].as_array().unwrap();
    let world = lf_eval::World::open(std::path::Path::new(&dar)).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let (r, mut c, token) = authenticated(&unique("r-submit-replay"));
    let all_packages = world.package_ids();
    let dso = host_party_and_vet_all(&r, &mut c, &token, "dso", true, &all_packages);
    let sv = host_party_and_vet_all(&r, &mut c, &token, "sv", true, &all_packages);
    let provider = host_party_and_vet_all(&r, &mut c, &token, "app-provider", true, &all_packages);
    let user = host_party_and_vet_all(&r, &mut c, &token, "app-user", true, &all_packages);
    // the other parties of the recorded network, found in the history by their names
    let party_named = |prefix: &str| -> String {
        let pattern = format!("\"{prefix}");
        let text = updates
            .iter()
            .map(|u| u.to_string())
            .find(|t| t.contains(&pattern))
            .expect("the history names the party");
        let start = text.find(&pattern).unwrap() + 1;
        text[start..].chars().take_while(|c| *c != '"').collect()
    };
    let official_provider = party_named("app_provider_");
    let official_user = party_named("app_user_");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let first = updates[0]["events_by_id"].as_object().unwrap();
    let official_dso = first
        .values()
        .find(|e| {
            e["event_type"] == "created_event"
                && e["template_id"]
                    .as_str()
                    .unwrap()
                    .ends_with(":Splice.DsoRules:DsoRules")
        })
        .unwrap()["signatories"][0]
        .as_str()
        .unwrap()
        .to_string();
    let official_sv = updates[2]["events_by_id"]
        .as_object()
        .unwrap()
        .values()
        .find(|e| e["event_type"] == "exercised_event")
        .unwrap()["acting_parties"][0]
        .as_str()
        .unwrap()
        .to_string();
    let hosting = |_: &str| -> std::collections::BTreeSet<String> {
        [p1.member.clone(), me.member.clone()].into()
    };
    let admin = r.uid();
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    // the replay moves its own clock: each recorded transaction happens at its recorded time plus a constant, which runs up to an hour ahead of the
    // sequencer's. The synchronizer has to allow that difference between a request's ledger time and its record time
    {
        let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
        let file = format!("{}.paramscmd", unique("pc"));
        std::fs::write(dir.join(format!("{file}.tmp")), "ledgertime,7200").unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        log_line_with(&["SCF paramscmd_done=", &file]).expect("the tolerance is changed");
        std::thread::sleep(std::time::Duration::from_secs(4));
    }
    let recorded_start =
        lf_eval::scan_state::parse_micros(updates[0]["effective_at"].as_str().unwrap()).unwrap();
    let clock_start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    // a margin that outlasts the seeding: a request may not use a contract created after its ledger time
    let delta = clock_start + 120_000_000 - recorded_start;
    // every recorded time in a value, moved onto the replay's clock
    let shift_times = |text: &str| -> String {
        let bytes = text.as_bytes();
        let mut out = String::new();
        let mut i = 0;
        while i < bytes.len() {
            let starts = i + 20 <= bytes.len()
                && bytes[i..i + 4].iter().all(u8::is_ascii_digit)
                && bytes[i + 4] == b'-'
                && bytes[i + 10] == b'T'
                && bytes[i + 13] == b':';
            if starts {
                if let Some(end) = text[i..].find('Z') {
                    let candidate = &text[i..i + end + 1];
                    if let Ok(micros) = lf_eval::scan_state::parse_micros(candidate) {
                        out.push_str(&lf_eval::typed_json::format_timestamp_micros(
                            micros + delta,
                        ));
                        i += end + 1;
                        continue;
                    }
                }
            }
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    };
    // our id of each contract the official network made; its template (`Module:Entity`) too
    let mut ours: BTreeMap<String, StoredContract> = BTreeMap::new();
    // the same contracts by our id, and as the engine holds them
    let mut ours_by_id: BTreeMap<String, StoredContract> = BTreeMap::new();
    let mut state: BTreeMap<String, lf_eval::Contract> = BTreeMap::new();
    let mut report: Vec<String> = Vec::new();
    fn engine_consumed(tx: &canton_participant::view_tree::Transaction) -> Vec<String> {
        tx.nodes
            .iter()
            .filter_map(|n| match n {
                canton_participant::view_tree::Action::Exercise {
                    contract,
                    consuming: true,
                    ..
                } => Some(contract.contract_id_hex.clone()),
                _ => None,
            })
            .collect()
    }
    let mut approved = 0usize;

    // the text of a recorded value for this network: the two parties swapped, the ids of contracts replaced by ours, the tx's time by ours;
    // `None` when it names a contract this test does not have
    let render = |json: &serde_json::Value,
                  ours: &BTreeMap<String, StoredContract>,
                  effective: &str,
                  at: i64|
     -> Option<serde_json::Value> {
        let mut text = json
            .to_string()
            .replace(&official_dso, &dso)
            .replace(&official_sv, &sv)
            .replace(&official_provider, &provider)
            .replace(&official_user, &user);
        let _ = (effective, at);
        text = shift_times(&text);
        for (official, mine) in ours {
            text = text.replace(official, &mine.contract_id_hex);
        }
        serde_json::from_str(&text).ok()
    };
    let hosted = |p: &str| {
        p == official_dso || p == official_sv || p == official_provider || p == official_user
    };

    let mut send_create = |c: &mut SequencerConnect,
                           event: &serde_json::Value|
     -> Result<(StoredContract, lf_eval::Contract), String> {
        let template_id = event["template_id"].as_str().unwrap();
        let (package, local) = template_id.split_once(':').unwrap();
        let (module, name) = local.split_once(':').unwrap();
        let ty = types.template(package, local)?;
        let at = now(c);
        let payload = render(
            &event["create_arguments"],
            &BTreeMap::new(),
            "<no recorded time>",
            at,
        )
        .ok_or("payload")?;
        let value = types.decode(&ty, &payload)?;
        let (arg, hash_arg) = forms(&types, &ty, &value)?;
        let parties = |key: &str| -> Vec<String> {
            event[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    p.as_str()
                        .unwrap()
                        .replace(&official_dso, &dso)
                        .replace(&official_sv, &sv)
                        .replace(&official_provider, &provider)
                        .replace(&official_user, &user)
                })
                .collect()
        };
        let signatories = parties("signatories");
        let mut stakeholders = signatories.clone();
        stakeholders.extend(parties("observers"));
        stakeholders.sort();
        stakeholders.dedup();
        let built = build_create(
            &ctx,
            &Create {
                package_name: &types.package_name(package)?,
                package_id: package,
                module: module.split('.').map(String::from).collect(),
                name: name.split('.').map(String::from).collect(),
                arg,
                hash_arg,
                signatories: signatories.clone(),
                stakeholders: stakeholders.clone(),
                hosts: vec![p1.clone(), me.clone()],
                command_id: unique("replay-seed"),
                key: None,
            },
            at,
            &mut Os,
        )?;
        let id = send_and_answer_as_admin(&r, c, &token, &built, at);
        let verdict = finalized_at(id);
        if !verdict.contains("with verdict Approve") {
            return Err(format!(
                "not approved: {}",
                verdict.lines().next().unwrap_or("")
            ));
        }
        let engine_contract = lf_eval::Contract {
            contract_id: built.contract_id_hex.clone(),
            package_id: package.to_string(),
            template_id: local.to_string(),
            payload: value,
            signatories: signatories.clone(),
            observers: stakeholders
                .iter()
                .filter(|s| !signatories.contains(s))
                .cloned()
                .collect(),
            active: true,
            key: None,
        };
        Ok((
            StoredContract {
                contract_id_hex: built.contract_id_hex.clone(),
                instance: built.instance.clone(),
                package_id: package.to_string(),
                module: module.split('.').map(String::from).collect(),
                name: name.split('.').map(String::from).collect(),
                signatories,
                stakeholders,
            },
            engine_contract,
        ))
    };

    // the contracts the bootstrap left active, each created on its own
    let consumed_in_first: std::collections::BTreeSet<&str> = first
        .values()
        .filter(|e| e["event_type"] == "exercised_event" && e["consuming"] == true)
        .map(|e| e["contract_id"].as_str().unwrap())
        .collect();
    let mut seeds: Vec<(&String, &serde_json::Value)> = first.iter().collect();
    seeds.sort_by_key(|(id, _)| {
        id.rsplit(':')
            .next()
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0)
    });
    for (_, event) in seeds {
        if event["event_type"] != "created_event"
            || consumed_in_first.contains(event["contract_id"].as_str().unwrap())
        {
            continue;
        }
        let kind = event["template_id"]
            .as_str()
            .unwrap()
            .rsplit(':')
            .next()
            .unwrap()
            .to_string();
        let involved = ["signatories", "observers"].iter().all(|k| {
            event[*k]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| hosted(p.as_str().unwrap()))
        });
        if !involved {
            report.push(format!("seed {kind}: skipped (a party that is not hosted)"));
            continue;
        }
        match send_create(&mut c, event) {
            Ok((stored, contract)) => {
                state.insert(stored.contract_id_hex.clone(), contract);
                ours_by_id.insert(stored.contract_id_hex.clone(), stored.clone());
                ours.insert(event["contract_id"].as_str().unwrap().to_string(), stored);
                report.push(format!("seed {kind}: approved"));
            }
            Err(e) => report.push(format!("seed {kind}: {e}")),
        }
    }

    // the recorded transactions in order, **run by the engine**: the official history leaves fetches out, so the tree the protocol needs (fetch
    // nodes included) is the engine's, from the recorded root command
    for (index, update) in updates.iter().enumerate().skip(1) {
        let label = format!("tx {index}");
        let events = update["events_by_id"].as_object().unwrap();
        let roots = update["root_event_ids"].as_array().unwrap();
        let root_events: Vec<&serde_json::Value> =
            roots.iter().map(|r| &events[r.as_str().unwrap()]).collect();
        let effective = update["effective_at"].as_str().unwrap().to_string();
        if let Some(why) = root_events.iter().find_map(|e| {
            if e["event_type"] != "exercised_event" {
                return Some("a root create".to_string());
            }
            if e["acting_parties"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| !hosted(p.as_str().unwrap()))
            {
                return Some("a party that is not hosted".to_string());
            }
            if !ours.contains_key(e["contract_id"].as_str().unwrap()) {
                return Some(format!(
                    "input {} is not a contract this test has",
                    e["template_id"]
                        .as_str()
                        .unwrap()
                        .rsplit(':')
                        .next()
                        .unwrap()
                ));
            }
            None
        }) {
            report.push(format!("{label}: skipped ({why})"));
            continue;
        }
        let root_event = root_events[0];
        let choice = root_event["choice"].as_str().unwrap();
        // the transaction's ledger time on the replay's clock; the sequencer's time is the real one
        let at_real = now(&mut c);
        let at = lf_eval::scan_state::parse_micros(&effective).unwrap() + delta;
        let attempt = (|| -> Result<(Transaction, Vec<usize>, BTreeMap<usize, lf_eval::Contract>), String> {
            let mut engine = lf_eval::Engine::new(&world);
            engine.set_time_micros(at);
            for (id, contract) in &state {
                engine.import_contract(contract.clone()).map_err(|e| format!("import {id}: {e}"))?;
                engine.disclose(id);
            }
            // every root command runs in the one engine session: the transaction has them as its roots, in order
            let mut executed = 0usize;
            // the contracts earlier roots of this transaction created, by their recorded id: a later root names them in its argument
            let mut made_here: BTreeMap<String, StoredContract> = BTreeMap::new();
            for root_event in &root_events {
                let step = (|| -> Result<(), String> {
                    let template_id = root_event["template_id"].as_str().unwrap();
                    let (package, local) = template_id.split_once(':').unwrap();
                    let choice = root_event["choice"].as_str().unwrap();
                    let mine = ours[root_event["contract_id"].as_str().unwrap()].clone();
                    let choice_types = types.choice(package, local, choice)?;
                    let mut known = ours.clone();
                    known.extend(made_here.clone());
                    let json = render(&root_event["choice_argument"], &known, &effective, at).ok_or("the argument names a contract this test does not have")?;
                    let argument = types.decode(&choice_types.argument, &json)?;
                    let actors: Vec<String> = root_event["acting_parties"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().replace(&official_dso, &dso).replace(&official_sv, &sv).replace(&official_provider, &provider).replace(&official_user, &user)).collect();
                    let actor_refs: Vec<&str> = actors.iter().map(String::as_str).collect();
                    let created_before = engine.events().iter().filter(|e| matches!(e, lf_eval::EngineEvent::Create { .. })).count();
                    engine.exercise_as(&actor_refs, &mine.contract_id_hex, choice, &argument).map_err(|e| format!("the engine refuses: {e}"))?;
                    // the recorded ids of what this root created, in event order, stand for the engine's ids of the same contracts
                    let engine_new: Vec<String> = engine
                        .events()
                        .iter()
                        .filter_map(|e| match e {
                            lf_eval::EngineEvent::Create { contract_id, .. } => Some(contract_id.clone()),
                            _ => None,
                        })
                        .skip(created_before)
                        .collect();
                    fn official_creates(id: &str, events: &serde_json::Map<String, serde_json::Value>, out: &mut Vec<String>) {
                        let e = &events[id];
                        if e["event_type"] == "created_event" {
                            out.push(e["contract_id"].as_str().unwrap().to_string());
                        }
                        for k in e["child_event_ids"].as_array().into_iter().flatten() {
                            official_creates(k.as_str().unwrap(), events, out);
                        }
                    }
                    let mut official_new = Vec::new();
                    official_creates(root_event["event_id"].as_str().unwrap(), events, &mut official_new);
                    for (official, engine_id) in official_new.into_iter().zip(engine_new) {
                        made_here.insert(
                            official,
                            StoredContract { contract_id_hex: engine_id, instance: Vec::new(), package_id: String::new(), module: Vec::new(), name: Vec::new(), signatories: Vec::new(), stakeholders: Vec::new() },
                        );
                    }
                    Ok(())
                })();
                match step {
                    Ok(()) => executed += 1,
                    // a later root that needs what an earlier root of the same transaction created cannot be built yet (the builder promises
                    // no ids): the transaction is sent with the roots that ran
                    Err(why) if executed > 0 => {
                        eprintln!("SPLICE REPLAY {label}: root {} cut: {}", executed + 1, why.chars().take(300).collect::<String>());
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
            // the engine's journal as a protocol transaction
            let journal = engine.events().to_vec();
            let mut nodes: Vec<Action> = Vec::new();
            let mut open: Vec<usize> = Vec::new();
            let mut created_contracts: BTreeMap<usize, lf_eval::Contract> = BTreeMap::new();
            let mut temp_ids: BTreeMap<String, usize> = BTreeMap::new();
            let stored_of = |id: &str, temp_ids: &BTreeMap<String, usize>, created: &BTreeMap<usize, lf_eval::Contract>| -> Result<StoredContract, String> {
                if let Some(c) = ours_by_id.get(id) {
                    return Ok(c.clone());
                }
                // a contract this transaction creates: its instance is known once the first build has made it
                let node = temp_ids.get(id).ok_or_else(|| format!("{id} is a contract this test did not create"))?;
                let c = &created[node];
                let (module, name) = c.template_id.split_once(':').unwrap();
                let mut stakeholders = c.signatories.clone();
                stakeholders.extend(c.observers.clone());
                stakeholders.sort();
                stakeholders.dedup();
                Ok(StoredContract {
                    contract_id_hex: id.to_string(),
                    instance: Vec::new(),
                    package_id: c.package_id.clone(),
                    module: module.split('.').map(String::from).collect(),
                    name: name.split('.').map(String::from).collect(),
                    signatories: c.signatories.clone(),
                    stakeholders,
                })
            };
            for event in &journal {
                let depth = match event {
                    lf_eval::EngineEvent::Create { depth, .. } | lf_eval::EngineEvent::Exercise { depth, .. } | lf_eval::EngineEvent::Fetch { depth, .. } => *depth,
                };
                open.truncate(depth);
                let node = match event {
                    lf_eval::EngineEvent::Exercise { contract_id, choice, consuming, actors, argument, interface_id, .. } => {
                        let contract = stored_of(contract_id, &temp_ids, &created_contracts)?;
                        let (p, l) = (contract.package_id.clone(), format!("{}:{}", contract.module.join("."), contract.name.join(".")));
                        let ct = match interface_id {
                            None => types.choice(&p, &l, choice)?,
                            Some(id) => {
                                let (ip, il) = id.split_once(':').unwrap();
                                types.interface_choice(ip, il, choice)?
                            }
                        };
                        Action::Exercise {
                            contract,
                            choice: choice.clone(),
                            argument: Some(lf_form(&types, &ct.argument, argument)?),
                            consuming: *consuming,
                            actors: actors.clone(),
                            choice_observers: vec![],
                            interface_id: interface_id.clone(),
                            children: Vec::new(),
                        }
                    }
                    lf_eval::EngineEvent::Fetch { contract_id, authorizers, .. } => Action::Fetch { contract: stored_of(contract_id, &temp_ids, &created_contracts)?, actors: authorizers.clone(), interface_id: None },
                    lf_eval::EngineEvent::Create { contract_id, .. } => {
                        let contract = engine.contract(contract_id).ok_or("a created contract the engine does not know")?.clone();
                        let ty = types.template(&contract.package_id, &contract.template_id)?;
                        let (arg, hash_arg) = forms(&types, &ty, &contract.payload)?;
                        let (module, name) = contract.template_id.split_once(':').unwrap();
                        let mut stakeholders = contract.signatories.clone();
                        stakeholders.extend(contract.observers.clone());
                        stakeholders.sort();
                        stakeholders.dedup();
                        let node = Action::Create(NewContract {
                            package_name: types.package_name(&contract.package_id)?,
                            package_id: contract.package_id.clone(),
                            module: module.split('.').map(String::from).collect(),
                            name: name.split('.').map(String::from).collect(),
                            arg,
                            hash_arg,
                            signatories: contract.signatories.clone(),
                            stakeholders,
                        key: None,
});
                        temp_ids.insert(contract_id.clone(), nodes.len());
                        created_contracts.insert(nodes.len(), contract);
                        node
                    }
                };
                let index = nodes.len();
                nodes.push(node);
                if let Some(parent) = open.last() {
                    if let Action::Exercise { children, .. } = &mut nodes[*parent] {
                        children.push(index);
                    }
                }
                if matches!(event, lf_eval::EngineEvent::Exercise { .. }) {
                    open.push(index);
                }
            }
            for node in &nodes {
                let parties: Vec<&String> = match node {
                    Action::Create(c) => c.signatories.iter().chain(c.stakeholders.iter()).collect(),
                    Action::Exercise { actors, contract, .. } => actors.iter().chain(contract.stakeholders.iter()).collect(),
                    Action::Fetch { actors, contract, .. } => actors.iter().chain(contract.stakeholders.iter()).collect(),
                    Action::Lookup(k, _) => k.maintainers.iter().collect(),
                    Action::Rollback { .. } => Vec::new(),
                };
                if parties.iter().any(|p| **p != dso && **p != sv && **p != provider && **p != user) {
                    return Err("a party that is not hosted".into());
                }
            }
            let consumed: Vec<usize> = journal
                .iter()
                .enumerate()
                .filter_map(|(_, e)| match e {
                    lf_eval::EngineEvent::Exercise { consuming: true, .. } => Some(0),
                    _ => None,
                })
                .collect();
            let roots: Vec<usize> = journal.iter().enumerate().filter_map(|(i, e)| match e { lf_eval::EngineEvent::Create { depth: 0, .. } | lf_eval::EngineEvent::Exercise { depth: 0, .. } | lf_eval::EngineEvent::Fetch { depth: 0, .. } => Some(i), _ => None }).collect();
            Ok((Transaction { nodes, roots, keys: Vec::new(), temp_ids,
package_preference: Default::default(),
ledger_time: None,
}, consumed, created_contracts))
        })();
        let (tx, _, created_contracts) = match attempt {
            Ok(t) => t,
            Err(why) => {
                report.push(format!("{label}: skipped ({why})"));
                continue;
            }
        };
        let root_actors: Vec<String> = root_event["acting_parties"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                p.as_str()
                    .unwrap()
                    .replace(&official_dso, &dso)
                    .replace(&official_sv, &sv)
                    .replace(&official_provider, &provider)
                    .replace(&official_user, &user)
            })
            .collect();
        let mut tx = tx;
        tx.ledger_time = Some(at);
        let outcome: Result<(canton_participant::submit::Built, String), String> = loop {
            let built = match build_transaction(
                &ctx,
                &tx,
                &[p1.clone(), me.clone()],
                &hosting,
                &root_actors,
                &unique("replay"),
                at_real,
                None,
                &mut Os,
            ) {
                Ok(b) => b,
                Err(why) => break Err(format!("the builder: {why}")),
            };
            let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(&tx, &admin, &hosting)
                .into_iter()
                .map(|(position, parties)| {
                    (
                        position,
                        parties.into_iter().filter(|p| *p == admin).collect(),
                    )
                })
                .collect();
            let before = node_log().len();
            let id = send_and_answer_views(&r, &mut c, &token, &built, at_real, &answers);
            let verdict = finalized_block_at(id);
            if verdict.contains("with verdict Approve") {
                break Ok((built, verdict));
            }
            // a body that resolves a package name needs the view to say which package the name stands for: the official participant names
            // the name it could not resolve, and the packages of that name among the transaction's are stated
            let fresh_log = node_log()[before..].to_string();
            let mut names: Vec<String> = Vec::new();
            let mut rest = fresh_log.as_str();
            while let Some(i) = rest.find("UnresolvedPackageName(\"") {
                rest = &rest[i + "UnresolvedPackageName(\"".len()..];
                if let Some(j) = rest.find('"') {
                    names.push(rest[..j].to_string());
                }
            }
            // the command whose body resolved the name is the one p1 names ("in exercise command <package>:<module>:<template>:<choice>")
            let mut failing: Vec<String> = Vec::new();
            let mut rest = fresh_log.as_str();
            while let Some(i) = rest.find("in exercise command ") {
                rest = &rest[i + "in exercise command ".len()..];
                let words: Vec<&str> = rest.split_whitespace().take(1).collect();
                if let Some(path) = words.first() {
                    failing.push(path.rsplit(':').next().unwrap_or_default().to_string());
                }
            }
            let mut ids: Vec<String> = tx
                .nodes
                .iter()
                .map(|n| match n {
                    Action::Create(c) => c.package_id.clone(),
                    Action::Exercise { contract, .. } | Action::Fetch { contract, .. } => {
                        contract.package_id.clone()
                    }
                    Action::Lookup(k, _) => k.package_id.clone(),
                    Action::Rollback { .. } => String::new(),
                })
                .filter(|id| types.package_name(id).is_ok_and(|n| names.contains(&n)))
                .collect();
            ids.sort();
            ids.dedup();
            let nodes_to_set: Vec<usize> = tx
                .roots
                .iter()
                .copied()
                .filter(|r| matches!(&tx.nodes[*r], Action::Exercise { choice, .. } if failing.contains(choice)))
                .collect();
            if ids.is_empty()
                || nodes_to_set.is_empty()
                || nodes_to_set
                    .iter()
                    .all(|n| tx.package_preference.get(n) == Some(&ids))
            {
                break Ok((built, verdict));
            }
            for n in nodes_to_set {
                tx.package_preference.insert(n, ids.clone());
            }
        };
        let (built, verdict) = match outcome {
            Ok(done) => done,
            Err(why) => {
                report.push(format!("{label}: skipped ({why})"));
                continue;
            }
        };
        if verdict.contains("with verdict Approve") {
            approved += 1;
            report.push(format!("{label}: APPROVED ({choice})"));
            // what the transaction left: its created contracts under our ids, minus what it consumed
            for (k, node) in built.created_nodes.iter().enumerate() {
                let created = built.created[k].clone();
                let mut contract = created_contracts[node].clone();
                contract.contract_id = created.contract_id_hex.clone();
                state.insert(created.contract_id_hex.clone(), contract);
                ours_by_id.insert(created.contract_id_hex.clone(), created);
            }
            // the recorded official ids of the created contracts, in event order, name ours (their payloads may be named in later arguments)
            let official_created: Vec<&str> = {
                let mut order: Vec<(u64, &str)> = events
                    .iter()
                    .filter(|(_, e)| e["event_type"] == "created_event")
                    .map(|(id, e)| {
                        (
                            id.rsplit(':')
                                .next()
                                .and_then(|n| n.parse::<u64>().ok())
                                .unwrap_or(0),
                            e["contract_id"].as_str().unwrap(),
                        )
                    })
                    .collect();
                order.sort();
                order.into_iter().map(|(_, c)| c).collect()
            };
            let ours_created: Vec<&StoredContract> = built
                .created_nodes
                .iter()
                .enumerate()
                .map(|(k, _)| &built.created[k])
                .collect();
            for (official, mine) in official_created.iter().zip(ours_created.iter()) {
                ours.insert(official.to_string(), (*mine).clone());
            }
            // consumed contracts leave both views of the state
            for event in engine_consumed(&tx) {
                state.remove(&event);
                ours_by_id.remove(&event);
            }
            for e in events.values() {
                if e["event_type"] == "exercised_event" && e["consuming"] == true {
                    ours.remove(e["contract_id"].as_str().unwrap());
                }
            }
        } else {
            let shape: Vec<String> = tx
                .nodes
                .iter()
                .map(|n| match n {
                    Action::Create(c) => format!("create {}", c.name.join(".")),
                    Action::Lookup(k, _) => format!("lookup {}", k.name.join(".")),
                    Action::Rollback { .. } => "rollback".to_string(),
                    Action::Exercise {
                        choice,
                        actors,
                        contract,
                        ..
                    } => format!(
                        "exercise {}.{choice} by {}",
                        contract.name.join("."),
                        actors
                            .iter()
                            .map(|a| a.split("::").next().unwrap().to_string())
                            .collect::<Vec<_>>()
                            .join("+")
                    ),
                    Action::Fetch {
                        contract, actors, ..
                    } => format!(
                        "fetch {} by {}",
                        contract.name.join("."),
                        actors
                            .iter()
                            .map(|a| a.split("::").next().unwrap().to_string())
                            .collect::<Vec<_>>()
                            .join("+")
                    ),
                })
                .collect();
            report.push(format!(
                "{label}: REJECTED ({choice}) nodes: {}",
                shape.join(" | ")
            ));
        }
    }
    // the tolerance back to the synchronizer's default: the other tests expect it
    {
        let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
        let file = format!("{}.paramscmd", unique("pc"));
        std::fs::write(dir.join(format!("{file}.tmp")), "ledgertime,60").unwrap();
        std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
        log_line_with(&["SCF paramscmd_done=", &file]).expect("the tolerance is put back");
    }
    eprintln!("SPLICE REPLAY\n{}", report.join("\n"));
    eprintln!("SPLICE REPLAY approved {approved} of {}", updates.len() - 1);
    assert!(
        !report.iter().any(|l| l.contains("REJECTED")),
        "the official participant rejected a transaction the Rust participant built"
    );
    assert!(
        approved >= 60,
        "only {approved} recorded transactions were approved"
    );
}

/// G8 U-39 (S-SPL-020): the other half of the Splice check. **p1** submits Splice commands (the recorded `DsoRules` create and the recorded
/// `DsoRules_OnboardValidator` exercise, over its JSON Ledger API); the **Rust participant** is the confirmer of the parties (a consortium: both
/// hosts must confirm), replays the Splice choice with its own engine on the official DAR, and answers. The mediator approves only if it does.
#[test]
fn the_rust_participant_confirms_splice_transactions_the_official_participant_submits() {
    use canton_participant::value_forms::forms;
    let _ = forms;
    let dar = var("CANTON_RS_SPLICE_DAR");
    let updates: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(var("CANTON_RS_SPLICE_UPDATES")).unwrap())
            .unwrap();
    let updates = updates["transactions"].as_array().unwrap();
    let world = lf_eval::World::open(std::path::Path::new(&dar)).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let (r, mut c, token) = authenticated(&unique("r-recv-splice"));
    let packages = world.package_ids();
    let dso = host_consortium_party_vetting(&r, &mut c, &token, "dso", &packages);
    let sv = host_consortium_party_vetting(&r, &mut c, &token, "sv", &packages);
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut config = runtime_config(
        &r,
        &dso,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = vec![dso.clone(), sv.clone()];
    let dir_state = state_dir("recv-splice");
    let engine =
        canton_participant::view_conformance::Engine::load(std::path::Path::new(&dar)).unwrap();
    let mut runtime = rt::Runtime::open(config, engine, Some(&dir_state), start).unwrap();

    // the recorded events, for this network's parties
    let first = updates[0]["events_by_id"].as_object().unwrap();
    let dso_rules_event = first
        .values()
        .find(|e| {
            e["event_type"] == "created_event"
                && e["template_id"]
                    .as_str()
                    .unwrap()
                    .ends_with(":Splice.DsoRules:DsoRules")
        })
        .unwrap()
        .clone();
    let official_dso = dso_rules_event["signatories"][0]
        .as_str()
        .unwrap()
        .to_string();
    let exercise_event = updates[2]["events_by_id"]
        .as_object()
        .unwrap()
        .values()
        .find(|e| e["event_type"] == "exercised_event")
        .unwrap()
        .clone();
    let official_sv = exercise_event["acting_parties"][0]
        .as_str()
        .unwrap()
        .to_string();
    let swap = |json: &serde_json::Value| -> serde_json::Value {
        serde_json::from_str(
            &json
                .to_string()
                .replace(&official_dso, &dso)
                .replace(&official_sv, &sv),
        )
        .unwrap()
    };
    // p1's JSON API takes the values as the Daml JSON codec writes them (a numeric `0.0`, not the scan's `0E-10`)
    let api_json = |template_id: &str, json: &serde_json::Value| -> serde_json::Value {
        let (package, local) = template_id.split_once(':').unwrap();
        let ty = types.template(package, local).unwrap();
        let value = types.decode(&ty, json).unwrap();
        types.encode_contract(&ty, &value).unwrap()
    };

    // the thread submits through p1 while this one lets the runtime answer
    let done = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, u16, String)>::new()));
    let worker = {
        let done = std::sync::Arc::clone(&done);
        let (dso, sv) = (dso.clone(), sv.clone());
        let dso_rules_template = dso_rules_event["template_id"].as_str().unwrap().to_string();
        let create_payload = api_json(
            &dso_rules_template,
            &swap(&dso_rules_event["create_arguments"]),
        );
        let choice_template = exercise_event["template_id"].as_str().unwrap().to_string();
        let choice = exercise_event["choice"].as_str().unwrap().to_string();
        let (package, local) = choice_template.split_once(':').unwrap();
        let ct = types.choice(package, local, &choice).unwrap();
        let argument = {
            let json = swap(&exercise_event["choice_argument"]);
            let value = types.decode(&ct.argument, &json).unwrap();
            types.encode_contract(&ct.argument, &value).unwrap()
        };
        std::thread::spawn(move || {
            let submit = |label: &str,
                          command: serde_json::Value,
                          act_as: &str,
                          read_as: &str|
             -> (u16, serde_json::Value) {
                let filter = serde_json::json!({act_as: {"cumulative": [{"identifierFilter": {"WildcardFilter": {"value": {"includeCreatedEventBlob": false}}}}]}});
                let body = serde_json::json!({
                    "commands": {"commands": [command], "commandId": format!("{label}-{}", std::process::id()), "actAs": [act_as], "readAs": [read_as], "userId": "participant_admin"},
                    "transactionFormat": {"eventFormat": {"filtersByParty": filter, "verbose": true}, "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"}
                });
                p1_http(
                    "POST",
                    "/v2/commands/submit-and-wait-for-transaction",
                    Some(&body),
                )
            };
            // the admin user may act as the parties
            let rights: Vec<serde_json::Value> = [&dso, &sv]
                .iter()
                .map(|p| serde_json::json!({"kind": {"CanActAs": {"value": {"party": p}}}}))
                .collect();
            let (status, answer) = p1_http(
                "POST",
                "/v2/users/participant_admin/rights",
                Some(
                    &serde_json::json!({"userId": "participant_admin", "identityProviderId": "", "rights": rights}),
                ),
            );
            done.lock().unwrap().push((
                "rights".into(),
                status,
                answer.to_string().chars().take(200).collect(),
            ));
            let (status, answer) = submit(
                "create-dso-rules",
                serde_json::json!({"CreateCommand": {"templateId": dso_rules_template, "createArguments": create_payload}}),
                &dso,
                &dso,
            );
            let created = answer
                .pointer("/transaction/events/0/CreatedEvent/contractId")
                .and_then(|v| v.as_str())
                .map(String::from);
            done.lock().unwrap().push((
                "create".into(),
                status,
                answer.to_string().chars().take(400).collect(),
            ));
            if let Some(cid) = created {
                let (status, answer) = submit(
                    "onboard",
                    serde_json::json!({"ExerciseCommand": {"templateId": choice_template, "contractId": cid, "choice": choice, "choiceArgument": argument}}),
                    &sv,
                    // the DsoRules is the DSO's contract: the SV reads it as the DSO party to exercise it
                    &dso,
                );
                done.lock().unwrap().push((
                    "exercise".into(),
                    status,
                    answer.to_string().chars().take(400).collect(),
                ));
            }
        })
    };
    let finished = |_: &rt::Runtime| worker.is_finished();
    let steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 120, finished);
    let _ = worker.join();
    let results = done.lock().unwrap().clone();
    eprintln!("RECEIVE SPLICE {results:#?}");
    let answers: Vec<&rt::ToSend> = steps.iter().flat_map(|s| &s.to_send).collect();
    eprintln!(
        "RECEIVE SPLICE the runtime answered {} request(s)",
        answers.len()
    );
    for answer in &answers {
        eprintln!("RECEIVE SPLICE answer {:?}", answer.decision().outcome);
    }
    assert!(
        results.iter().any(|(l, s, _)| l == "create" && *s == 200),
        "p1 created the DsoRules: {results:?}"
    );
    assert!(
        results.iter().any(|(l, s, _)| l == "exercise" && *s == 200),
        "p1 exercised OnboardValidator: {results:?}"
    );
    assert!(
        answers.iter().all(
            |a| a.decision().outcome == canton_participant::confirmation_wire::Outcome::Approve
        ),
        "the Rust participant approves what p1 submitted: {answers:?}"
    );
    let _ = std::fs::remove_dir_all(&dir_state);
}

/// G8 U-39 (S-SPL-021): the recorded transactions of the official Splice LocalNet, **submitted by p1** one after another over its JSON Ledger API
/// (the recorded commands with this network's party ids and p1's contract ids), with the Rust participant as the confirmer of every party. A transaction
/// the mediator approves was replayed and approved by the Rust engine. p1 refuses what depends on the clock it does not control (a round that is not open
/// yet), and a transaction the Rust participant rejects shows as an error answer of p1 with the Rust reason in the runtime's answers.
#[test]
fn the_rust_participant_confirms_the_recorded_splice_transactions_the_official_participant_submits()
{
    let ReceiveReplay {
        results, rejects, ..
    } = receive_replay("recv-replay", 1500, ReplayOptions::default(), |_, _| {});
    assert!(
        rejects.is_empty(),
        "the Rust participant rejected what p1 submitted: {rejects:?}"
    );
    let approved = results.iter().filter(|l| l.contains("APPROVED")).count();
    assert!(
        approved >= 35,
        "only {approved} recorded transactions were approved: {results:?}"
    );
}

/// G8 P4 (S-SPL-022): the official participant confirms `Rename` the Rust participant built: a consuming exercise of a keyed contract whose body
/// creates a contract under **another key** (the key of the created contract is stated in the view, free, and the new contract's id commits to it).
#[test]
fn the_official_participant_confirms_a_rename_of_a_keyed_contract_the_rust_participant_built() {
    use canton_participant::contract_id::HashValue;
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{
        build_create, Context, Create, NewKey, Os, Peer, StoredContract,
    };
    use canton_participant::value_forms::forms;
    use canton_participant::view_tree::{
        build_transaction, view_positions, Action, NewContract, Transaction,
    };
    let package_id = var("CANTON_RS_KEYED_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-rename"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_KEYED_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let ty = types
        .template(world.main_package_id(), "Keyed:Registry")
        .unwrap();
    let registry_value = |name: &str| lf_eval::Value::Record {
        tycon: Some("Keyed:Registry".into()),
        fields: vec![
            ("owner".into(), lf_eval::Value::Party(erin.clone())),
            ("name".into(), lf_eval::Value::Text(name.into())),
            ("payload".into(), lf_eval::Value::Text("kept".into())),
        ],
    };
    let key_hash = |name: &str| HashValue::Record {
        module: vec!["DA".into(), "Types".into()],
        name: vec!["Tuple2".into()],
        fields: vec![
            ("_1".into(), HashValue::Party(erin.clone())),
            ("_2".into(), HashValue::Text(name.into())),
        ],
    };
    let key_value = |name: &str| {
        LfValue::Record(vec![
            LfValue::Party(erin.clone()),
            LfValue::Text(name.into()),
        ])
    };
    let new_key = |name: &str| NewKey {
        value: key_value(name),
        hash_value: key_hash(name),
        maintainers: vec![erin.clone()],
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let (arg, hash_arg) = forms(&types, &ty, &registry_value("entry")).unwrap();
    let at = now(&mut c);
    let created = build_create(
        &ctx,
        &Create {
            package_name: "keyed-vault",
            package_id: &package_id,
            module: vec!["Keyed".into()],
            name: vec!["Registry".into()],
            arg,
            hash_arg,
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone()],
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("rename-create"),
            key: Some(new_key("entry")),
        },
        at,
        &mut Os,
    )
    .unwrap();
    let id = send_and_answer_as_admin(&r, &mut c, &token, &created, at);
    assert!(finalized_at(id).contains("with verdict Approve"));
    let registry = StoredContract {
        contract_id_hex: created.contract_id_hex.clone(),
        instance: created.instance.clone(),
        package_id: package_id.clone(),
        module: vec!["Keyed".into()],
        name: vec!["Registry".into()],
        signatories: vec![erin.clone()],
        stakeholders: vec![erin.clone()],
    };
    let (new_arg, new_hash_arg) = forms(&types, &ty, &registry_value("renamed")).unwrap();
    let tx = |stated_key: Option<&str>| Transaction {
        nodes: vec![
            Action::Exercise {
                contract: registry.clone(),
                choice: "Rename".into(),
                argument: Some(LfValue::Record(vec![LfValue::Text("renamed".into())])),
                consuming: true,
                actors: vec![erin.clone()],
                choice_observers: vec![],
                interface_id: None,
                children: vec![1],
            },
            Action::Create(NewContract {
                package_name: "keyed-vault".into(),
                package_id: package_id.clone(),
                module: vec!["Keyed".into()],
                name: vec!["Registry".into()],
                arg: new_arg.clone(),
                hash_arg: new_hash_arg.clone(),
                signatories: vec![erin.clone()],
                stakeholders: vec![erin.clone()],
                key: stated_key.map(new_key),
            }),
        ],
        roots: vec![0],
        // the consumed contract's key is free once the exercise has archived it (measured: p1 rebuilds the view with both keys free)
        keys: vec![(
            0,
            canton_participant::view_tree::KeyUse {
                package_name: "keyed-vault".into(),
                package_id: package_id.clone(),
                module: vec!["Keyed".into()],
                name: vec!["Registry".into()],
                value: key_value("entry"),
                hash_value: key_hash("entry"),
                maintainers: vec![erin.clone()],
                contract_id: None,
            },
        )],
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |_: &str| -> std::collections::BTreeSet<String> {
        [p1.member.clone(), me.member.clone()].into()
    };
    let admin = r.uid();
    let mut submit = |t: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            t,
            &[p1.clone(), me.clone()],
            &hosting,
            &[erin.clone()],
            &unique("rename-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(t, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties.into_iter().filter(|p| *p == admin).collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    // negative control: the created contract states no key although its template has one
    let wrong = submit(&tx(None));
    assert!(!wrong.contains("with verdict Approve"), "{wrong}");
    let verdict = submit(&tx(Some("renamed")));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// G8 P4 (S-SPL-023): the official participant confirms an exercise whose choice **looks a key up and finds nothing** (`lookupByKey`), built by the
/// Rust participant: the view's `resolved_keys` states the key with its maintainers and no contract.
#[test]
fn the_official_participant_confirms_an_exercise_that_looks_a_key_up_the_rust_participant_built() {
    use canton_participant::contract_id::HashValue;
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{
        build_create, Context, Create, NewKey, Os, Peer, StoredContract,
    };
    use canton_participant::value_forms::forms;
    use canton_participant::view_tree::{
        build_transaction, view_positions, Action, KeyUse, Transaction,
    };
    let package_id = var("CANTON_RS_LOOKUP_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-lookup"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_LOOKUP_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let ty = types
        .template(world.main_package_id(), "Lookup:Entry")
        .unwrap();
    let value = lf_eval::Value::Record {
        tycon: Some("Lookup:Entry".into()),
        fields: vec![
            ("owner".into(), lf_eval::Value::Party(erin.clone())),
            ("name".into(), lf_eval::Value::Text("held".into())),
        ],
    };
    let key_hash = |name: &str| HashValue::Record {
        module: vec!["DA".into(), "Types".into()],
        name: vec!["Tuple2".into()],
        fields: vec![
            ("_1".into(), HashValue::Party(erin.clone())),
            ("_2".into(), HashValue::Text(name.into())),
        ],
    };
    let key_value = |name: &str| {
        LfValue::Record(vec![
            LfValue::Party(erin.clone()),
            LfValue::Text(name.into()),
        ])
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
    let at = now(&mut c);
    let created = build_create(
        &ctx,
        &Create {
            package_name: "lookup-view",
            package_id: &package_id,
            module: vec!["Lookup".into()],
            name: vec!["Entry".into()],
            arg,
            hash_arg,
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone()],
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("lookup-create"),
            key: Some(NewKey {
                value: key_value("held"),
                hash_value: key_hash("held"),
                maintainers: vec![erin.clone()],
            }),
        },
        at,
        &mut Os,
    )
    .unwrap();
    let id = send_and_answer_as_admin(&r, &mut c, &token, &created, at);
    assert!(finalized_at(id).contains("with verdict Approve"));
    let entry = StoredContract {
        contract_id_hex: created.contract_id_hex.clone(),
        instance: created.instance.clone(),
        package_id: package_id.clone(),
        module: vec!["Lookup".into()],
        name: vec!["Entry".into()],
        signatories: vec![erin.clone()],
        stakeholders: vec![erin.clone()],
    };
    // the lookup finds ANOTHER contract than the exercised one (S-SPL-023, second half)
    let other_value = lf_eval::Value::Record {
        tycon: Some("Lookup:Entry".into()),
        fields: vec![
            ("owner".into(), lf_eval::Value::Party(erin.clone())),
            ("name".into(), lf_eval::Value::Text("other".into())),
        ],
    };
    let (oarg, ohash) = forms(&types, &ty, &other_value).unwrap();
    let at = now(&mut c);
    let other_built = build_create(
        &ctx,
        &Create {
            package_name: "lookup-view",
            package_id: &package_id,
            module: vec!["Lookup".into()],
            name: vec!["Entry".into()],
            arg: oarg,
            hash_arg: ohash,
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone()],
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("lookup-create-other"),
            key: Some(NewKey {
                value: key_value("other"),
                hash_value: key_hash("other"),
                maintainers: vec![erin.clone()],
            }),
        },
        at,
        &mut Os,
    )
    .unwrap();
    let id = send_and_answer_as_admin(&r, &mut c, &token, &other_built, at);
    assert!(finalized_at(id).contains("with verdict Approve"));
    let key_use = |name: &str| KeyUse {
        package_name: "lookup-view".into(),
        package_id: package_id.clone(),
        module: vec!["Lookup".into()],
        name: vec!["Entry".into()],
        value: key_value(name),
        hash_value: key_hash(name),
        maintainers: vec![erin.clone()],
        contract_id: None,
    };
    let tx = |states_the_lookup: bool| Transaction {
        nodes: {
            let mut nodes = vec![Action::Exercise {
                contract: entry.clone(),
                choice: "Probe".into(),
                argument: Some(LfValue::Record(vec![key_value("missing")])),
                consuming: false,
                actors: vec![erin.clone()],
                choice_observers: vec![],
                interface_id: None,
                children: if states_the_lookup { vec![1] } else { vec![] },
            }];
            if states_the_lookup {
                nodes.push(Action::Lookup(key_use("missing"), Vec::new()));
            }
            nodes
        },
        roots: vec![0],
        // the input contract's own key is stated too, free (measured: the official participant adds it to the resolved keys)
        keys: vec![(0, key_use("held"))],
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |_: &str| -> std::collections::BTreeSet<String> {
        [p1.member.clone(), me.member.clone()].into()
    };
    let admin = r.uid();
    let mut submit = |t: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            t,
            &[p1.clone(), me.clone()],
            &hosting,
            &[erin.clone()],
            &unique("lookup-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(t, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties.into_iter().filter(|p| *p == admin).collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    // negative control: the view does not state the lookup the choice makes
    let wrong = submit(&tx(false));
    assert!(!wrong.contains("with verdict Approve"), "{wrong}");
    let verdict = submit(&tx(true));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
    let found = Transaction {
        nodes: vec![
            Action::Exercise {
                contract: entry.clone(),
                choice: "Probe".into(),
                argument: Some(LfValue::Record(vec![key_value("other")])),
                consuming: false,
                actors: vec![erin.clone()],
                choice_observers: vec![],
                interface_id: None,
                children: vec![1],
            },
            Action::Lookup(
                KeyUse {
                    contract_id: Some(other_built.contract_id_hex.clone()),
                    ..key_use("other")
                },
                vec![StoredContract {
                    contract_id_hex: other_built.contract_id_hex.clone(),
                    instance: other_built.instance.clone(),
                    package_id: package_id.clone(),
                    module: vec!["Lookup".into()],
                    name: vec!["Entry".into()],
                    signatories: vec![erin.clone()],
                    stakeholders: vec![erin.clone()],
                }],
            ),
        ],
        roots: vec![0],
        keys: vec![(0, key_use("held"))],
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let found_verdict = submit(&found);
    assert!(
        found_verdict.contains("with verdict Approve"),
        "{found_verdict}"
    );
    // measured: the same lookup stated as finding nothing is approved too. The key resolution a view states is taken as given by the
    // official participant's model conformance check (a stale resolution is not caught there), so this half has no negative control
    // except the missing input above (`Failed to find key resolution contract`).
    let mut denied = found.clone();
    denied.nodes[1] = Action::Lookup(key_use("other"), Vec::new());
    let denied_verdict = submit(&denied);
    assert!(
        denied_verdict.contains("with verdict Approve"),
        "{denied_verdict}"
    );
    let entry_found = vec![entry.clone()];
    let same = |keys: Vec<(usize, KeyUse)>| Transaction {
        nodes: vec![
            Action::Exercise {
                contract: entry.clone(),
                choice: "Probe".into(),
                argument: Some(LfValue::Record(vec![key_value("held")])),
                consuming: false,
                actors: vec![erin.clone()],
                choice_observers: vec![],
                interface_id: None,
                children: vec![1],
            },
            Action::Lookup(
                KeyUse {
                    contract_id: Some(entry.contract_id_hex.clone()),
                    ..key_use("held")
                },
                entry_found.clone(),
            ),
        ],
        roots: vec![0],
        keys,
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    // the lookup finds the very contract being exercised (S-SPL-023; before, this was refused with only the root hash differing: the chosen
    // value went out as version "2.1", not the "2" of a package with keys, because the transaction stated no key of its own)
    let same_verdict = submit(&same(Vec::new()));
    assert!(
        same_verdict.contains("with verdict Approve"),
        "{same_verdict}"
    );
}

/// G8 P6 (S-SPL-024): the official participant confirms an exercise whose choice **catches an exception** (a rollback node holding a fetch), built by
/// the Rust participant.
#[test]
fn the_official_participant_confirms_an_exercise_whose_try_block_rolled_back_a_create_the_rust_participant_built(
) {
    use canton_participant::contract_id::HashValue;
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{
        build_create, Context, Create, NewKey, Os, Peer, StoredContract,
    };
    use canton_participant::value_forms::forms;
    use canton_participant::view_tree::{
        build_transaction, view_positions, Action, KeyUse, Transaction,
    };
    let package_id = var("CANTON_RS_LOOKUP_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-lookup"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_LOOKUP_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let ty = types
        .template(world.main_package_id(), "Lookup:Scratch")
        .unwrap();
    let value = lf_eval::Value::Record {
        tycon: Some("Lookup:Scratch".into()),
        fields: vec![("owner".into(), lf_eval::Value::Party(erin.clone()))],
    };
    let key_hash = |name: &str| HashValue::Record {
        module: vec!["DA".into(), "Types".into()],
        name: vec!["Tuple2".into()],
        fields: vec![
            ("_1".into(), HashValue::Party(erin.clone())),
            ("_2".into(), HashValue::Text(name.into())),
        ],
    };
    let key_value = |name: &str| {
        LfValue::Record(vec![
            LfValue::Party(erin.clone()),
            LfValue::Text(name.into()),
        ])
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
    let at = now(&mut c);
    let created = build_create(
        &ctx,
        &Create {
            package_name: "lookup-view",
            package_id: &package_id,
            module: vec!["Lookup".into()],
            name: vec!["Scratch".into()],
            arg,
            hash_arg,
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone()],
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("lookup-create"),
            key: None,
        },
        at,
        &mut Os,
    )
    .unwrap();
    let id = send_and_answer_as_admin(&r, &mut c, &token, &created, at);
    assert!(finalized_at(id).contains("with verdict Approve"));
    let scratch = StoredContract {
        contract_id_hex: created.contract_id_hex.clone(),
        instance: created.instance.clone(),
        package_id: package_id.clone(),
        module: vec!["Lookup".into()],
        name: vec!["Scratch".into()],
        signatories: vec![erin.clone()],
        stakeholders: vec![erin.clone()],
    };
    let tx = |states_the_rollback: bool| Transaction {
        nodes: {
            let mut nodes = vec![Action::Exercise {
                contract: scratch.clone(),
                choice: "Attempt".into(),
                argument: Some(LfValue::Record(vec![])),
                consuming: false,
                actors: vec![erin.clone()],
                choice_observers: vec![],
                interface_id: None,
                children: if states_the_rollback { vec![1] } else { vec![] },
            }];
            if states_the_rollback {
                nodes.push(Action::Rollback { children: vec![2] });
                nodes.push(Action::Fetch {
                    contract: scratch.clone(),
                    actors: vec![erin.clone()],
                    interface_id: None,
                });
            }
            nodes
        },
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |_: &str| -> std::collections::BTreeSet<String> {
        [p1.member.clone(), me.member.clone()].into()
    };
    let admin = r.uid();
    let mut submit = |t: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            t,
            &[p1.clone(), me.clone()],
            &hosting,
            &[erin.clone()],
            &unique("rollback-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(t, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties.into_iter().filter(|p| *p == admin).collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    // negative control: the view does not state the rolled-back fetch
    let wrong = submit(&tx(false));
    assert!(!wrong.contains("with verdict Approve"), "{wrong}");
    let verdict = submit(&tx(true));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

#[test]
fn the_official_participant_confirms_a_view_inside_a_rollback_the_rust_participant_built() {
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::forms;
    let package_id = var("CANTON_RS_LOOKUP_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-rbview"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let gwen = host_party_and_vet(&r, &mut c, &token, "gwen", false, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_LOOKUP_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let admin = r.uid();
    let create = |c: &mut SequencerConnect,
                  template: &str,
                  fields: Vec<(&str, &str)>,
                  signatories: Vec<String>,
                  stakeholders: Vec<String>,
                  hosts: Vec<Peer>| {
        let value = lf_eval::Value::Record {
            tycon: Some(template.into()),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.into(), lf_eval::Value::Party(v.into())))
                .collect(),
        };
        let ty = types.template(world.main_package_id(), template).unwrap();
        let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
        let (module, name) = template.split_once(':').unwrap();
        let at = now(c);
        let built = build_create(
            &ctx,
            &Create {
                package_name: "lookup-view",
                package_id: &package_id,
                module: vec![module.into()],
                name: vec![name.into()],
                arg,
                hash_arg,
                signatories: signatories.clone(),
                stakeholders: stakeholders.clone(),
                hosts,
                command_id: unique("subview-create"),
                key: None,
            },
            at,
            &mut Os,
        )
        .unwrap();
        // gwen is hosted by this participant alone, so it confirms for her itself
        let mut parties = vec![admin.clone()];
        parties.extend(signatories.iter().filter(|p| **p == gwen).cloned());
        let id = send_and_answer_views(&r, c, &token, &built, at, &[(vec![vec![]], parties)]);
        assert!(finalized_at(id).contains("with verdict Approve"));
        StoredContract {
            contract_id_hex: built.contract_id_hex.clone(),
            instance: built.instance.clone(),
            package_id: package_id.clone(),
            module: vec![module.into()],
            name: vec![name.into()],
            signatories,
            stakeholders,
        }
    };
    let mut both = vec![erin.clone(), gwen.clone()];
    both.sort();
    let held = create(
        &mut c,
        "Lookup:Held",
        vec![("r", &erin), ("a", &gwen)],
        vec![erin.clone()],
        both,
        vec![p1.clone(), me.clone()],
    );
    let driver = create(
        &mut c,
        "Lookup:Driver",
        vec![("a", &gwen)],
        vec![gwen.clone()],
        vec![gwen.clone()],
        vec![me.clone()],
    );
    use canton_participant::contract_wire::LfValue;
    use canton_participant::view_tree::{build_transaction, view_positions, Action, Transaction};
    let make_tx = |rolled_back: bool| Transaction {
        nodes: vec![
            Action::Exercise {
                contract: driver.clone(),
                choice: "Try".into(),
                argument: Some(LfValue::Record(vec![LfValue::ContractId(
                    held.contract_id_hex.clone(),
                )])),
                consuming: false,
                actors: vec![gwen.clone()],
                choice_observers: vec![],
                children: vec![1],
                interface_id: None,
            },
            if rolled_back {
                Action::Rollback { children: vec![2] }
            } else {
                // a fetch that is not under the rollback the choice puts it under
                Action::Fetch {
                    contract: held.clone(),
                    actors: vec![gwen.clone()],
                    interface_id: None,
                }
            },
            Action::Fetch {
                contract: held.clone(),
                actors: vec![gwen.clone()],
                interface_id: None,
            },
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |party: &str| -> std::collections::BTreeSet<String> {
        if party == erin {
            [p1.member.clone(), me.member.clone()].into()
        } else {
            [me.member.clone()].into()
        }
    };
    let mut submit = |tx: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            tx,
            &[p1.clone(), me.clone()],
            &hosting,
            &[gwen.clone()],
            &unique("subview-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        // this participant answers for the parties it alone confirms for: the admin party and gwen
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(tx, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties
                        .into_iter()
                        .filter(|p| *p == admin || *p == gwen)
                        .collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    let verdict = submit(&make_tx(true));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
    // measured: a fetch the Rust side states without the rollback (`rolled_back = false`) is approved too. The official participant
    // re-derives the fetch from the view's own action description and does not compare the flag, so there is no negative control here.
    let unflagged = submit(&make_tx(false));
    assert!(unflagged.contains("with verdict Approve"), "{unflagged}");
}

#[test]
fn the_official_participant_confirms_a_fetch_through_an_interface_the_rust_participant_built() {
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::forms;
    let package_id = var("CANTON_RS_LOOKUP_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-ifetch"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let gwen = host_party_and_vet(&r, &mut c, &token, "gwen", false, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_LOOKUP_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let admin = r.uid();
    let create = |c: &mut SequencerConnect,
                  template: &str,
                  fields: Vec<(&str, &str)>,
                  signatories: Vec<String>,
                  stakeholders: Vec<String>,
                  hosts: Vec<Peer>| {
        let value = lf_eval::Value::Record {
            tycon: Some(template.into()),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.into(), lf_eval::Value::Party(v.into())))
                .collect(),
        };
        let ty = types.template(world.main_package_id(), template).unwrap();
        let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
        let (module, name) = template.split_once(':').unwrap();
        let at = now(c);
        let built = build_create(
            &ctx,
            &Create {
                package_name: "lookup-view",
                package_id: &package_id,
                module: vec![module.into()],
                name: vec![name.into()],
                arg,
                hash_arg,
                signatories: signatories.clone(),
                stakeholders: stakeholders.clone(),
                hosts,
                command_id: unique("subview-create"),
                key: None,
            },
            at,
            &mut Os,
        )
        .unwrap();
        // gwen is hosted by this participant alone, so it confirms for her itself
        let mut parties = vec![admin.clone()];
        parties.extend(signatories.iter().filter(|p| **p == gwen).cloned());
        let id = send_and_answer_views(&r, c, &token, &built, at, &[(vec![vec![]], parties)]);
        assert!(finalized_at(id).contains("with verdict Approve"));
        StoredContract {
            contract_id_hex: built.contract_id_hex.clone(),
            instance: built.instance.clone(),
            package_id: package_id.clone(),
            module: vec![module.into()],
            name: vec![name.into()],
            signatories,
            stakeholders,
        }
    };
    let mut both = vec![erin.clone(), gwen.clone()];
    both.sort();
    let held = create(
        &mut c,
        "Lookup:Held",
        vec![("r", &erin), ("a", &gwen)],
        vec![erin.clone()],
        both,
        vec![p1.clone(), me.clone()],
    );
    let driver = create(
        &mut c,
        "Lookup:Driver",
        vec![("a", &gwen)],
        vec![gwen.clone()],
        vec![gwen.clone()],
        vec![me.clone()],
    );
    use canton_participant::contract_wire::LfValue;
    use canton_participant::view_tree::{build_transaction, view_positions, Action, Transaction};
    let make_tx = |names_interface: bool| Transaction {
        nodes: vec![
            Action::Exercise {
                contract: driver.clone(),
                choice: "ViaInterface".into(),
                argument: Some(LfValue::Record(vec![LfValue::ContractId(
                    held.contract_id_hex.clone(),
                )])),
                consuming: false,
                actors: vec![gwen.clone()],
                choice_observers: vec![],
                children: vec![1],
                interface_id: None,
            },
            Action::Fetch {
                contract: held.clone(),
                actors: vec![gwen.clone()],
                interface_id: names_interface.then(|| format!("{package_id}:Lookup:IHeld")),
            },
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |party: &str| -> std::collections::BTreeSet<String> {
        if party == erin {
            [p1.member.clone(), me.member.clone()].into()
        } else {
            [me.member.clone()].into()
        }
    };
    let mut submit = |tx: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            tx,
            &[p1.clone(), me.clone()],
            &hosting,
            &[gwen.clone()],
            &unique("subview-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        // this participant answers for the parties it alone confirms for: the admin party and gwen
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(tx, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties
                        .into_iter()
                        .filter(|p| *p == admin || *p == gwen)
                        .collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    let verdict = submit(&make_tx(true));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
    // measured: a fetch description that does not name the interface is approved too, so there is no negative control: the official
    // participant re-interprets the fetch and does not compare the description's `interface_id` (S-SPL-026)
    let unnamed = submit(&make_tx(false));
    assert!(unnamed.contains("with verdict Approve"), "{unnamed}");
}

#[test]
fn the_official_participant_confirms_a_create_that_comes_after_a_rollback_the_rust_participant_built(
) {
    use canton_participant::contract_id::HashValue;
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{
        build_create, Context, Create, NewKey, Os, Peer, StoredContract,
    };
    use canton_participant::value_forms::forms;
    use canton_participant::view_tree::{
        build_transaction, view_positions, Action, KeyUse, Transaction,
    };
    let package_id = var("CANTON_RS_LOOKUP_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-rbseq"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_LOOKUP_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let ty = types
        .template(world.main_package_id(), "Lookup:Scratch")
        .unwrap();
    let value = lf_eval::Value::Record {
        tycon: Some("Lookup:Scratch".into()),
        fields: vec![("owner".into(), lf_eval::Value::Party(erin.clone()))],
    };
    let key_hash = |name: &str| HashValue::Record {
        module: vec!["DA".into(), "Types".into()],
        name: vec!["Tuple2".into()],
        fields: vec![
            ("_1".into(), HashValue::Party(erin.clone())),
            ("_2".into(), HashValue::Text(name.into())),
        ],
    };
    let key_value = |name: &str| {
        LfValue::Record(vec![
            LfValue::Party(erin.clone()),
            LfValue::Text(name.into()),
        ])
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
    let at = now(&mut c);
    let created = build_create(
        &ctx,
        &Create {
            package_name: "lookup-view",
            package_id: &package_id,
            module: vec!["Lookup".into()],
            name: vec!["Scratch".into()],
            arg,
            hash_arg,
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone()],
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("lookup-create"),
            key: None,
        },
        at,
        &mut Os,
    )
    .unwrap();
    let id = send_and_answer_as_admin(&r, &mut c, &token, &created, at);
    assert!(finalized_at(id).contains("with verdict Approve"));
    let scratch = StoredContract {
        contract_id_hex: created.contract_id_hex.clone(),
        instance: created.instance.clone(),
        package_id: package_id.clone(),
        module: vec!["Lookup".into()],
        name: vec!["Scratch".into()],
        signatories: vec![erin.clone()],
        stakeholders: vec![erin.clone()],
    };
    let new_scratch = canton_participant::view_tree::NewContract {
        package_name: "lookup-view".into(),
        package_id: package_id.clone(),
        module: vec!["Lookup".into()],
        name: vec!["Scratch".into()],
        arg: forms(&types, &ty, &value).unwrap().0,
        hash_arg: forms(&types, &ty, &value).unwrap().1,
        signatories: vec![erin.clone()],
        stakeholders: vec![erin.clone()],
        key: None,
    };
    let tx = |_unused: bool| Transaction {
        nodes: vec![
            Action::Exercise {
                contract: scratch.clone(),
                choice: "AttemptThenCreate".into(),
                argument: Some(LfValue::Record(vec![])),
                consuming: false,
                actors: vec![erin.clone()],
                choice_observers: vec![],
                interface_id: None,
                children: vec![1, 4],
            },
            Action::Rollback {
                children: vec![2, 3],
            },
            Action::Fetch {
                contract: scratch.clone(),
                actors: vec![erin.clone()],
                interface_id: None,
            },
            Action::Fetch {
                contract: scratch.clone(),
                actors: vec![erin.clone()],
                interface_id: None,
            },
            Action::Create(new_scratch.clone()),
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |_: &str| -> std::collections::BTreeSet<String> {
        [p1.member.clone(), me.member.clone()].into()
    };
    let admin = r.uid();
    let mut submit = |t: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            t,
            &[p1.clone(), me.clone()],
            &hosting,
            &[erin.clone()],
            &unique("rollback-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(t, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties.into_iter().filter(|p| *p == admin).collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    // the create after the rollback takes the child index 2: the two fetches in the rollback took 0 and 1, the rollback itself none (S-SPL-027)
    let verdict = submit(&tx(true));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// G8 P5 (S-SPL-035): an interface of ANOTHER package. `XIface:Gadget` (package `xiface-view`) implements `Iface:IHolding` of `iface-view`,
/// as Splice's Amulet implements the token-standard interfaces of the splice-api packages. The official participant confirms `Poke` exercised
/// on a gadget through that interface, named with the interface's own package, and refuses it unnamed or named with the template's package;
/// it also confirms `Driver.Peek`, whose body fetches the gadget through the foreign interface.
#[test]
fn the_official_participant_confirms_an_interface_of_another_package_the_rust_participant_built() {
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::forms;
    use canton_participant::view_tree::{build_transaction, view_positions, Action, Transaction};
    let package_id = var("CANTON_RS_XIFACE_PACKAGE");
    let iface_package = var("CANTON_RS_IFACE_PACKAGE");
    let (r, mut c, token) = authenticated(&unique("r-submit-xiface"));
    let erin = host_party_and_vet_all(
        &r,
        &mut c,
        &token,
        "erin",
        true,
        &[package_id.clone(), iface_package.clone()],
    );
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_XIFACE_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    let mut create = |c: &mut SequencerConnect, template: &str| -> StoredContract {
        let value = lf_eval::Value::Record {
            tycon: Some(format!("XIface:{template}")),
            fields: vec![("owner".into(), lf_eval::Value::Party(erin.clone()))],
        };
        let ty = types
            .template(world.main_package_id(), &format!("XIface:{template}"))
            .unwrap();
        let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
        let at = now(c);
        let created = build_create(
            &ctx,
            &Create {
                package_name: "xiface-view",
                package_id: &package_id,
                module: vec!["XIface".into()],
                name: vec![template.into()],
                arg,
                hash_arg,
                signatories: vec![erin.clone()],
                stakeholders: vec![erin.clone()],
                hosts: vec![p1.clone(), me.clone()],
                command_id: unique("xiface-create"),
                key: None,
            },
            at,
            &mut Os,
        )
        .unwrap();
        let id = send_and_answer_as_admin(&r, c, &token, &created, at);
        assert!(finalized_at(id).contains("with verdict Approve"));
        StoredContract {
            contract_id_hex: created.contract_id_hex.clone(),
            instance: created.instance.clone(),
            package_id: package_id.clone(),
            module: vec!["XIface".into()],
            name: vec![template.into()],
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone()],
        }
    };
    let gadget = create(&mut c, "Gadget");
    let driver = create(&mut c, "Driver");
    let hosting = |_: &str| -> std::collections::BTreeSet<String> {
        [p1.member.clone(), me.member.clone()].into()
    };
    let admin = r.uid();
    let mut submit = |t: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            t,
            &[p1.clone(), me.clone()],
            &hosting,
            &[erin.clone()],
            &unique("xiface-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(t, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties.into_iter().filter(|p| *p == admin).collect(),
                )
            })
            .collect();
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    let one = |nodes: Vec<Action>| Transaction {
        nodes,
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    // the driver's choice fetches the gadget through the foreign interface (a node of the same view)
    let peek = one(vec![
        Action::Exercise {
            contract: driver.clone(),
            choice: "Peek".into(),
            argument: Some(LfValue::Record(vec![LfValue::ContractId(
                gadget.contract_id_hex.clone(),
            )])),
            consuming: false,
            actors: vec![erin.clone()],
            choice_observers: vec![],
            interface_id: None,
            children: vec![1],
        },
        Action::Fetch {
            contract: gadget.clone(),
            actors: vec![erin.clone()],
            interface_id: Some(format!("{iface_package}:Iface:IHolding")),
        },
    ]);
    // measured: without a preference p1 refuses with `UnresolvedPackageName("xiface-view")`: a fetch through an interface resolves the
    // contract's template by package name, so the view of the command names the package it resolved to (as in S-SPL-018)
    let mut peek = peek;
    peek.package_preference.insert(0, vec![package_id.clone()]);
    let peeked = submit(&peek);
    assert!(peeked.contains("with verdict Approve"), "{peeked}");
    // `Poke` on the gadget through the interface: named with the interface's package; refused unnamed, or named with the template's package
    let poke = |interface: Option<String>| {
        one(vec![Action::Exercise {
            contract: gadget.clone(),
            choice: "Poke".into(),
            argument: Some(LfValue::Record(vec![])),
            consuming: true,
            actors: vec![erin.clone()],
            choice_observers: vec![],
            interface_id: interface,
            children: vec![],
        }])
    };
    let unnamed = submit(&poke(None));
    assert!(!unnamed.contains("with verdict Approve"), "{unnamed}");
    let wrong_package = submit(&poke(Some(format!("{package_id}:Iface:IHolding"))));
    assert!(
        !wrong_package.contains("with verdict Approve"),
        "{wrong_package}"
    );
    let verdict = submit(&poke(Some(format!("{iface_package}:Iface:IHolding"))));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// The encryption key (DER) of the participant whose member id starts with `prefix` (`PAR::p2::`), from the topology state.
fn encryption_key_of(
    c: &mut SequencerConnect,
    r: &canton_participant::topology_wire::ParticipantIdentity,
    token: &canton_participant::sequencer_connect::Token,
    prefix: &str,
) -> (String, Vec<u8>) {
    use canton_proto::com::digitalasset::canton::crypto::v30::public_key::Key;
    let state = c
        .download_topology_state(&r.member(), &var("CANTON_RS_EXPECT_SYNCHRONIZER"), token)
        .unwrap();
    downloaded::decode(&state)
        .iter()
        .find_map(|e| match downloaded::mapping(e) {
            downloaded::Mapping::OwnerToKeyMapping(m) if m.member.starts_with(prefix) => {
                m.public_keys.iter().find_map(|k| match &k.key {
                    Some(Key::EncryptionPublicKey(e)) => {
                        Some((m.member.clone(), e.public_key.clone()))
                    }
                    _ => None,
                })
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("the encryption key of {prefix} is in the topology state"))
}

/// G11 B4 (S-G11-001, S-NET-041): a key used **inside a subview** is stated in the parent view's `resolved_keys` too. `Prober.Peek`
/// (erin, hosted by p1 and this participant) fetches by id a keyed `Shared` whose signatory dave is hosted by p2: the fetch is a
/// subview (p2 is a new participant), and p1, an informee of both views, rebuilds the parent with the subview's key in it
/// (`NextGenTransactionTreeFactory`: a child view's `keyResolution` is added to its parent's).
#[test]
fn the_official_participant_confirms_a_parent_view_that_states_the_key_of_its_subview() {
    use canton_participant::contract_id::HashValue;
    use canton_participant::contract_wire::LfValue;
    use canton_participant::submit::{build_create, Context, Create, Os, Peer, StoredContract};
    use canton_participant::value_forms::forms;
    use canton_participant::view_tree::{
        build_transaction, view_positions, Action, KeyUse, Transaction,
    };
    let package_id = var("CANTON_RS_KEYSUB_PACKAGE");
    let dave = var("CANTON_RS_DAVE");
    let (r, mut c, token) = authenticated(&unique("r-keysub"));
    let erin = host_party_and_vet(&r, &mut c, &token, "erin", true, &package_id);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let world = lf_eval::World::open(std::path::Path::new(&var("CANTON_RS_KEYSUB_DAR"))).unwrap();
    let types = lf_eval::typed_json::Types::new(&world);
    let p1 = Peer {
        member: var("CANTON_RS_MEMBER_P1"),
        encryption_spki: p1_encryption_key(&mut c, &r, &token),
        fingerprint: var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT"),
    };
    let (p2_member, p2_spki) = encryption_key_of(&mut c, &r, &token, "PAR::p2::");
    let p2 = Peer {
        member: p2_member,
        fingerprint: canton_participant::topology_wire::fingerprint(&p2_spki),
        encryption_spki: p2_spki,
    };
    let me = Peer {
        member: r.member(),
        encryption_spki: r.encryption_spki().to_vec(),
        fingerprint: r.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &r,
        synchronizer: &synchronizer,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let now = |c: &mut SequencerConnect| {
        c.sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap()
    };
    // erin's Prober, created by this participant
    let ty = types
        .template(world.main_package_id(), "KeySub:Prober")
        .unwrap();
    let value = lf_eval::Value::Record {
        tycon: Some("KeySub:Prober".into()),
        fields: vec![("w".into(), lf_eval::Value::Party(erin.clone()))],
    };
    let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
    let at = now(&mut c);
    let created = build_create(
        &ctx,
        &Create {
            package_name: "key-subview",
            package_id: &package_id,
            module: vec!["KeySub".into()],
            name: vec!["Prober".into()],
            arg,
            hash_arg,
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone()],
            hosts: vec![p1.clone(), me.clone()],
            command_id: unique("keysub-create"),
            key: None,
        },
        at,
        &mut Os,
    )
    .unwrap();
    let id = send_and_answer_as_admin(&r, &mut c, &token, &created, at);
    assert!(finalized_at(id).contains("with verdict Approve"));
    let prober = StoredContract {
        contract_id_hex: created.contract_id_hex.clone(),
        instance: created.instance.clone(),
        package_id: package_id.clone(),
        module: vec!["KeySub".into()],
        name: vec!["Prober".into()],
        signatories: vec![erin.clone()],
        stakeholders: vec![erin.clone()],
    };
    // dave's Shared (observer erin), created by p2; its created event blob is the instance the view carries
    let tag = unique("tag");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let file = format!("{}.keysubcmd", unique("keysub"));
    std::fs::write(
        dir.join(format!("{file}.tmp")),
        format!("shared,{dave},{erin},{tag}"),
    )
    .unwrap();
    std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
    let done = log_line_with(&[&format!("SCF keysub_done={file}=")]).unwrap_or_else(|| {
        panic!(
            "p2 did not create the Shared: {:?}",
            log_line_with(&[&format!("keysub_failed={file}")])
        )
    });
    let shared_id = done.rsplit('=').next().unwrap().trim().to_string();
    let blob_line = log_line_with(&[&format!("SCF keysub_blob={file}=")]).unwrap();
    let blob = hex::decode(blob_line.rsplit('=').next().unwrap().trim()).unwrap();
    let mut stakeholders = vec![dave.clone(), erin.clone()];
    stakeholders.sort();
    let shared = StoredContract {
        contract_id_hex: shared_id,
        instance: blob,
        package_id: package_id.clone(),
        module: vec!["KeySub".into()],
        name: vec!["Shared".into()],
        signatories: vec![dave.clone()],
        stakeholders,
    };
    let key_use = KeyUse {
        package_name: "key-subview".into(),
        package_id: package_id.clone(),
        module: vec!["KeySub".into()],
        name: vec!["Shared".into()],
        value: LfValue::Record(vec![
            LfValue::Party(dave.clone()),
            LfValue::Text(tag.clone()),
        ]),
        hash_value: HashValue::Record {
            module: vec!["DA".into(), "Types".into()],
            name: vec!["Tuple2".into()],
            fields: vec![
                ("_1".into(), HashValue::Party(dave.clone())),
                ("_2".into(), HashValue::Text(tag.clone())),
            ],
        },
        maintainers: vec![dave.clone()],
        // fetched by id: the key is stated with no contract
        contract_id: None,
    };
    let tx = |states_the_key: bool| Transaction {
        nodes: vec![
            Action::Exercise {
                contract: prober.clone(),
                choice: "Peek".into(),
                argument: Some(LfValue::Record(vec![LfValue::ContractId(
                    shared.contract_id_hex.clone(),
                )])),
                consuming: false,
                actors: vec![erin.clone()],
                choice_observers: vec![],
                interface_id: None,
                children: vec![1],
            },
            Action::Fetch {
                contract: shared.clone(),
                actors: vec![erin.clone()],
                interface_id: None,
            },
        ],
        roots: vec![0],
        keys: if states_the_key {
            vec![(1, key_use.clone())]
        } else {
            Vec::new()
        },
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let hosting = |party: &str| -> std::collections::BTreeSet<String> {
        if party == dave {
            [p2.member.clone()].into()
        } else {
            [p1.member.clone(), me.member.clone()].into()
        }
    };
    let admin = r.uid();
    let mut submit = |t: &Transaction| -> String {
        let at = now(&mut c);
        let built = build_transaction(
            &ctx,
            t,
            &[p1.clone(), me.clone(), p2.clone()],
            &hosting,
            &[erin.clone()],
            &unique("keysub-run"),
            at,
            None,
            &mut Os,
        )
        .unwrap();
        // this participant answers for its admin party only: erin's confirmation has to come from p1, dave's from p2
        let answers: Vec<(Vec<Vec<bool>>, Vec<String>)> = view_positions(t, &admin, &hosting)
            .into_iter()
            .map(|(position, parties)| {
                (
                    position,
                    parties.into_iter().filter(|p| *p == admin).collect(),
                )
            })
            .collect();
        assert_eq!(answers.len(), 2, "the fetch is a subview of its own");
        let id = send_and_answer_views(&r, &mut c, &token, &built, at, &answers);
        finalized_block_at(id)
    };
    // negative control: the fetch's key is stated nowhere
    let wrong = submit(&tx(false));
    assert!(!wrong.contains("with verdict Approve"), "{wrong}");
    let verdict = submit(&tx(true));
    assert!(verdict.contains("with verdict Approve"), "{verdict}");
}

/// U-31 (S-G11-001), the JVM reference: what an official participant reports when **another official participant vetoes** its command. `fay`
/// (p1) owns an `AssetHolding` whose bank `gus` signed while p1 hosted him; then `gus` is re-hosted so that only p2 confirms for him, and p2
/// never saw the contract. p1 submits `fay`'s `Transfer` over its JSON API; p2 refuses (it does not know the contract), the mediator rejects,
/// and p1 answers the HTTP call with an error and records a failed completion. Both are printed and written to `CANTON_RS_WORK_DIR/u31-jvm.json`.
#[test]
fn an_official_participant_reports_the_veto_of_another_as_a_failed_completion() {
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let file = format!("{}.vetocmd", unique("veto"));
    std::fs::write(
        dir.join(format!("{file}.tmp")),
        format!("setup,{},{}", unique("fay"), unique("gus")),
    )
    .unwrap();
    std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
    let done = log_line_with(&[&format!("SCF vetocmd_done={file}=")]).unwrap_or_else(|| {
        panic!(
            "the console did not set the veto up: {:?}",
            node_log()
                .lines()
                .filter(|l| l.contains(&format!("vetocmd_failed={file}")))
                .collect::<Vec<_>>()
        )
    });
    println!(
        "U31 note={:?}",
        log_line_with(&[&format!("SCF vetocmd_note={file}=")])
    );
    // rsplitn: [hosting, contract id, gus, fay, prefix]
    let parts: Vec<&str> = done.trim().rsplitn(5, '=').collect();
    let (hosting, cid, gus, fay) = (
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
        parts[3].to_string(),
    );
    println!("U31 hosting={hosting}");
    assert!(
        hosting.contains("p2/Confirmation") && hosting.contains("p1/Observation"),
        "gus is confirmed by p2 alone: {hosting}"
    );
    let rights = serde_json::json!({"userId": "participant_admin", "identityProviderId": "", "rights": [{"kind": {"CanActAs": {"value": {"party": fay}}}}]});
    let (status, answer) = p1_http("POST", "/v2/users/participant_admin/rights", Some(&rights));
    assert_eq!(status, 200, "{answer}");
    let command_id = unique("u31-transfer");
    let body = serde_json::json!({
        "commands": [{"ExerciseCommand": {"templateId": format!("{}:AssetHolding:AssetHolding", var("CANTON_RS_SAMPLE_PACKAGE")), "contractId": cid, "choice": "Transfer", "choiceArgument": {"newOwner": gus}}}],
        "commandId": command_id, "actAs": [fay], "userId": "participant_admin"
    });
    let (status, error) = p1_http("POST", "/v2/commands/submit-and-wait", Some(&body));
    println!("U31 submit status={status} body={error}");
    assert_ne!(status, 200, "p2's veto refuses the command: {error}");
    let (cstatus, completions) = p1_http(
        "POST",
        "/v2/commands/command-completions",
        Some(&serde_json::json!({"parties": [fay], "beginExclusive": 0})),
    );
    println!("U31 completions status={cstatus} body={completions}");
    let ours: Vec<&serde_json::Value> = completions
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|c| {
                    c.pointer("/completionResponse/Completion/value/commandId")
                        .and_then(|v| v.as_str())
                        == Some(command_id.as_str())
                })
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        ours.len(),
        1,
        "one completion for the vetoed command: {completions}"
    );
    let record = serde_json::json!({"submit": {"status": status, "body": error}, "completion": ours[0], "hosting": hosting});
    std::fs::write(
        std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("u31-jvm.json"),
        serde_json::to_string_pretty(&record).unwrap(),
    )
    .unwrap();
    assert!(
        log_line_with(&["participant=p2", "Phase 4: Sending", "rejected=1"]).is_some(),
        "p2 rejected the request"
    );
}

/// The next commitment p1 sends `run`'s participant whose period ends after `after` (micros), with its envelope and the sequencing times
/// of the requests delivered on the way. Reads from `from`.
fn next_commitment(
    run: &mut CommitmentRun,
    from: i64,
    after: i64,
) -> (
    canton_participant::acs_commitment::ReceivedCommitment,
    Vec<u8>,
    Vec<i64>,
) {
    use canton_participant::{acs_commitment, sequencing_wire as sw};
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let mut at = from;
    let mut requests = Vec::new();
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(150);
    while std::time::Instant::now() < patience {
        let got = run
            .connection
            .subscribe_patiently(
                &run.identity.member(),
                &synchronizer,
                &run.token,
                Some(at),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default();
        let Some(event) = got.first() else { continue };
        let d = sw::decode_delivered(event).expect("every event decodes");
        at = d.timestamp_micros + 1;
        for e in &d.envelopes {
            if canton_participant::view_receive::root_hash_of_message(e).is_some() {
                requests.push(d.timestamp_micros);
            }
            if let Some(c) = acs_commitment::decode(e) {
                if c.to_inclusive > after {
                    return (c, e.clone(), requests);
                }
            }
        }
    }
    panic!("p1 sent no commitment for a period after {after}");
}

/// Whether p1's matcher logged `run`'s commitment for the period `(from, to)` as correct (or raised a mismatch for it), polling up to
/// two minutes; gives p1 the event after the next boundary that makes its checkpoint.
fn p1_judged_period(run: &CommitmentRun, from: i64, to: i64) -> Option<bool> {
    let alice = var("CANTON_RS_ALICE");
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    wait_past_next_minute(3);
    let name = format!("{}.submit", unique("submit"));
    std::fs::write(
        dir.join(format!("{name}.tmp")),
        format!("{alice},{alice},{alice},1.0"),
    )
    .unwrap();
    std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
    let uid = run.identity.uid();
    // as `p1_finds_the_commitment_the_rust_participant_sends_correct` writes the period the node logs
    let period = format!(
        "CommitmentPeriod(fromExclusive = {}, toInclusive = {})",
        iso(from)
            .replace("000Z", "Z")
            .trim_end_matches('Z')
            .to_string()
            + "Z",
        iso(to).replace(".000000Z", "Z")
    );
    let patience = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while std::time::Instant::now() < patience {
        let log = node_log();
        for l in log
            .lines()
            .filter(|l| l.contains("participant=p1") && l.contains(&uid[..30]))
        {
            if l.contains("Commitment correct for sender") && l.contains(&period) {
                return Some(true);
            }
        }
        let all: Vec<&str> = log.lines().collect();
        for (i, l) in all.iter().enumerate() {
            if l.contains("ACS_COMMITMENT_MISMATCH")
                && all[i..(i + 12).min(all.len())]
                    .iter()
                    .any(|x| x.contains(&uid[..30]) && x.contains(&period))
            {
                return Some(false);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    None
}

/// G11 B4 / C4, U-20 (S-G11-001): ACS commitments over **two consecutive reconciliation periods**, live with p1, in both directions. Period
/// A covers one shared contract, period B a second one created later. For each period: p1's commitment equals what this participant
/// computes, this participant's commitment is found correct by p1, and the tracker (`AcsCommitmentTracker`) matches the two. A period runs
/// from just before the last change of the shared set to the tick, so periods overlap while nothing changes (measured on the first run:
/// p1's next commitment after period A had period A's start).
#[test]
fn commitments_over_two_periods_agree_with_p1_in_both_directions() {
    use canton_participant::acs_commitment::{AcsCommitmentTracker, PeriodVerdict};
    use canton_participant::lthash;
    let mut run = rust_gets_a_commitment(&unique("r-cmt-periods"));
    let alice = var("CANTON_RS_ALICE");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let p1 = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let keys = p1_signing_keys(&mut run.connection, &run.identity, &run.token);
    let digest_of = |ids: &[String], erin: &str| {
        let mut set = lthash::LtHash16::empty();
        for id in ids {
            for local in [alice.as_str(), erin] {
                let (a, b) = lthash::ordered_pair(local, erin);
                set.add(&lthash::digest_element(id, 0, a, b));
            }
        }
        lthash::commitment_digest(&set)
    };
    let raw32 = |d: &[u8]| -> [u8; 32] { d[d.len() - 32..].try_into().unwrap() };
    let mut tracker = AcsCommitmentTracker::new();
    let receive = |tracker: &mut AcsCommitmentTracker, envelope: &[u8]| -> PeriodVerdict {
        tracker
            .receive_signed(envelope, &synchronizer, &keys)
            .expect("p1's commitment verifies with one of its keys")
    };
    // period A: the first contract
    let start = run.request_time + 1;
    let (a, a_envelope, _) = next_commitment(&mut run, start, 0);
    let digest_a = digest_of(&run.contract_ids, &run.erin);
    assert_eq!(a.digest, digest_a, "p1's period A digest is ours");
    assert_eq!(
        tracker.record_local(&p1, a.from_exclusive, a.to_inclusive, raw32(&digest_a)),
        Ok(PeriodVerdict::Pending)
    );
    assert_eq!(receive(&mut tracker, &a_envelope), PeriodVerdict::Matched);
    rust_sends_its_commitment(&mut run, &digest_a, a.from_exclusive, a.to_inclusive);
    assert_eq!(
        p1_judged_period(&run, a.from_exclusive, a.to_inclusive),
        Some(true),
        "p1 finds the period A commitment correct"
    );
    // period B: a second shared contract, created after period A ended
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let name = format!("{}.submit", unique("submit"));
    std::fs::write(
        dir.join(format!("{name}.tmp")),
        format!("{alice},{},{alice},200.0", run.erin),
    )
    .unwrap();
    std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
    let line = log_line_with(&["SCF created=", &name]).expect("p1 creates the second contract");
    run.contract_ids
        .push(line.rsplit('=').next().unwrap().trim().to_string());
    // the second contract's request, as this participant sees it: the change period B starts at
    let now = run
        .connection
        .sequencer_time(&run.identity.member(), &synchronizer, Some(&run.token))
        .unwrap()
        .unwrap();
    wait_past_next_minute(3);
    let name = format!("{}.submit", unique("submit"));
    std::fs::write(
        dir.join(format!("{name}.tmp")),
        format!("{alice},{alice},{alice},1.0"),
    )
    .unwrap();
    std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
    // the first commitment whose tick is after the second contract: ticks in between still cover period A's set
    let (b, b_envelope, requests) = next_commitment(&mut run, a.to_inclusive, now);
    let change = *requests
        .iter()
        .filter(|t| **t > a.to_inclusive)
        .max()
        .expect("the second contract's request came through this participant");
    assert_eq!(
        (b.from_exclusive, b.to_inclusive),
        canton_participant::acs_commitment::period_after(change, 60_000_000),
        "period B runs from just before the second contract's request to the next tick"
    );
    println!(
        "PERIODS A=({}, {}] B=({}, {}]",
        a.from_exclusive, a.to_inclusive, b.from_exclusive, b.to_inclusive
    );
    let digest_b = digest_of(&run.contract_ids, &run.erin);
    assert_eq!(
        b.digest, digest_b,
        "p1's period B digest covers both contracts"
    );
    // the tracker takes p1's periods as they are: the tick advances, the start is the last change
    assert_eq!(
        tracker.record_local(&p1, b.from_exclusive, b.to_inclusive, raw32(&digest_b)),
        Ok(PeriodVerdict::Pending)
    );
    assert_eq!(receive(&mut tracker, &b_envelope), PeriodVerdict::Matched);
    assert_eq!(tracker.safe_to_prune_timestamp(), Some(b.to_inclusive));
    rust_sends_its_commitment(&mut run, &digest_b, b.from_exclusive, b.to_inclusive);
    assert_eq!(
        p1_judged_period(&run, b.from_exclusive, b.to_inclusive),
        Some(true),
        "p1 finds the period B commitment correct"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// Bundle 1 (P-9): Runtime-path ACS commitment oracle against official p1.
// ---------------------------------------------------------------------------------------------------------------------

fn log_has_p1_uid_mismatch(log: &str, uid_prefix: &str) -> bool {
    let all: Vec<&str> = log.lines().collect();
    for (i, line) in all.iter().enumerate() {
        if !line.contains("participant=p1") || !line.contains("ACS_COMMITMENT_MISMATCH") {
            continue;
        }
        for follow in all.iter().skip(i + 1).take(8) {
            let trimmed = follow.trim();
            if trimmed.starts_with("20") {
                break;
            }
            if (trimmed.starts_with("sender =") || trimmed.starts_with("counterparticipant ="))
                && trimmed.contains(uid_prefix)
            {
                return true;
            }
            if trimmed.contains("synchronizerId=") {
                break;
            }
        }
    }
    false
}

/// P-9 runtime path: [`rt::Runtime`] opens a live synchronizer loop with topology following, observes p1 creating a shared
/// `AssetHolding`, crosses a 60 s reconciliation boundary, emits its own commitment in `Step::commitments` (sent by `poll`),
/// matches p1's commitment without mismatch, and p1 logs `"Commitment correct for sender"` for the Rust participant.
#[test]
fn runtime_acs_commitment_matches_official_p1() {
    use canton_participant::acs_commitment::PeriodVerdict;
    let name = unique("r-cmt-rt");
    let (r, mut c, token) = authenticated(&name);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let before_hosting = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let erin = host_consortium_party(&r, &mut c, &token, "erin");
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let alice = var("CANTON_RS_ALICE");
    let dir_state = state_dir(&name);
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.follow_topology = true;
    let mut runtime =
        rt::Runtime::open(config, rust_engine(), Some(&dir_state), before_hosting).unwrap();
    runtime.load_topology(&mut c, &token).unwrap();
    let mut steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 30, |rt| {
        !rt.hosts_of(&erin).is_empty()
    });
    assert!(
        !runtime.hosts_of(&erin).is_empty(),
        "runtime learned consortium hosting for {erin}: {steps:#?}"
    );

    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let command = |extension: &str, content: String| {
        let fname = format!("{}.{extension}", unique(extension));
        std::fs::write(dir.join(format!("{fname}.tmp")), content).unwrap();
        std::fs::rename(dir.join(format!("{fname}.tmp")), dir.join(&fname)).unwrap();
        fname
    };
    let created = command("submit", format!("{alice},{erin},{alice},100.0"));
    let line = log_line_with(&["SCF created=", &created]).expect("p1 creates the contract");
    let contract_id = line.rsplit('=').next().unwrap().trim().to_string();
    assert_ne!(contract_id, "?", "{line}");

    let creation_steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 90, |rt| {
        rt.ledger.is_active(&contract_id)
    });
    steps.extend(creation_steps);
    assert!(
        runtime.ledger.is_active(&contract_id),
        "runtime activates the shared contract: {steps:#?}"
    );

    // Cross a 60 s reconciliation boundary and emit a non-shared event on p1 so p1 triggers a tick and sends its commitment.
    wait_past_next_minute(3);
    command("submit", format!("{alice},{alice},{alice},1.0"));

    let patience = std::time::Instant::now() + std::time::Duration::from_secs(150);
    while std::time::Instant::now() < patience {
        steps.extend(
            runtime
                .poll(
                    &mut c,
                    &token,
                    &r.signing_key,
                    std::time::Duration::from_secs(3),
                )
                .expect("runtime keeps polling"),
        );
        let sent_to_p1 = steps
            .iter()
            .flat_map(|s| &s.commitments)
            .any(|o| o.counter_participant == p1_uid);
        let matched_p1 = runtime
            .commitment_periods()
            .iter()
            .any(|p| p.counter_participant == p1_uid && p.verdict == PeriodVerdict::Matched);
        if sent_to_p1 && matched_p1 {
            break;
        }
    }

    assert!(
        steps
            .iter()
            .flat_map(|s| &s.commitments)
            .any(|o| o.counter_participant == p1_uid),
        "runtime emitted an outgoing commitment to p1: {steps:#?}"
    );
    let periods = runtime.commitment_periods();
    assert!(
        periods
            .iter()
            .any(|p| p.counter_participant == p1_uid && p.verdict == PeriodVerdict::Matched),
        "runtime matched p1's commitment: {periods:#?}"
    );
    assert!(
        !periods
            .iter()
            .any(|p| matches!(p.verdict, PeriodVerdict::Mismatched { .. })),
        "runtime saw unexpected ACS commitment mismatch: {periods:#?}"
    );
    let all_notes: Vec<&str> = steps
        .iter()
        .flat_map(|s| s.notes.iter().map(String::as_str))
        .collect();
    assert!(
        !all_notes
            .iter()
            .any(|n| n.contains("the ACS commitments were not sent")
                || n.contains("ACS_COMMITMENT_MISMATCH")),
        "runtime commitment send/compare notes reported an error: {all_notes:#?}"
    );

    // Verify official p1 logs "Commitment correct for sender" for this Rust participant.
    let uid_prefix = &r.uid()[..30.min(r.uid().len())];
    let has_p1_correct = |log: &str| {
        log.lines().any(|l| {
            l.contains("participant=p1")
                && l.contains("Commitment correct for sender")
                && l.contains(uid_prefix)
        })
    };
    let fast_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < fast_deadline && !has_p1_correct(&node_log()) {
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    if !has_p1_correct(&node_log()) {
        wait_past_next_minute(3);
        command("submit", format!("{alice},{alice},{alice},1.0"));
        let slow_deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        while std::time::Instant::now() < slow_deadline && !has_p1_correct(&node_log()) {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
    let log = node_log();
    assert!(
        has_p1_correct(&log),
        "p1 did not log 'Commitment correct for sender' for {uid_prefix}"
    );
    assert!(
        !log_has_p1_uid_mismatch(&log, uid_prefix),
        "p1 logged ACS_COMMITMENT_MISMATCH involving {uid_prefix}"
    );

    // Negative control (R-17 / P-9): cross a second 60s boundary, intercept runtime's period-2 Outgoing commitment before sending,
    // corrupt its last byte by 1 bit (preserving multihash prefix 0x1220), and verify official p1 logs ACS_COMMITMENT_MISMATCH.
    {
        use canton_participant::sequencing_wire as sw;
        wait_past_next_minute(3);
        command("submit", format!("{alice},{alice},{alice},1.0"));
        let mut p2_out: Option<canton_participant::acs_commitment_runtime::Outgoing> = None;
        let mut sub_from = runtime.cursor() + 1;
        let p2_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while std::time::Instant::now() < p2_deadline && p2_out.is_none() {
            let events = c
                .subscribe(
                    &r.member(),
                    &synchronizer,
                    &token,
                    Some(sub_from),
                    1,
                    std::time::Duration::from_secs(3),
                )
                .unwrap_or_default();
            for raw in events {
                let d = sw::decode_delivered(&raw).expect("delivered event");
                sub_from = d.timestamp_micros + 1;
                let step = runtime.step(&d).expect("runtime step period-2");
                if let Some(out) = step
                    .commitments
                    .into_iter()
                    .find(|o| o.counter_participant == p1_uid)
                {
                    p2_out = Some(out);
                    break;
                }
            }
            if p2_out.is_none() {
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        }
        let p2_out = p2_out.expect("runtime emitted period-2 Outgoing commitment for p1");
        let mut bad_digest = p2_out.digest.clone();
        let last = bad_digest.len() - 1;
        bad_digest[last] ^= 0x01;
        let now_ts = c
            .sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap();
        let msg = canton_participant::acs_commitment::commitment_message(
            &synchronizer,
            &r.uid(),
            &p1_uid,
            p2_out.from_exclusive,
            p2_out.to_inclusive,
            &bad_digest,
            &r.signing_key,
        );
        c.send_async(
            &r.member(),
            &synchronizer,
            &token,
            sw::signed_submission_request(
                sw::submission_request_to_groups(
                    &r.member(),
                    &unique("acs-cmt-bad"),
                    &[(vec![var("CANTON_RS_MEMBER_P1")], msg)],
                    now_ts + 60_000_000,
                ),
                &r.signing_key,
            ),
        )
        .expect("send corrupted period-2 commitment");
        let mismatch_deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
        let mut kicked = false;
        while std::time::Instant::now() < mismatch_deadline
            && !log_has_p1_uid_mismatch(&node_log(), uid_prefix)
        {
            if !kicked
                && std::time::Instant::now() + std::time::Duration::from_secs(30)
                    >= mismatch_deadline
            {
                command("submit", format!("{alice},{alice},{alice},1.0"));
                kicked = true;
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        assert!(
            log_has_p1_uid_mismatch(&node_log(), uid_prefix),
            "expected official p1 to log ACS_COMMITMENT_MISMATCH after 1-byte period-2 corruption for {uid_prefix}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir_state);
}

// ---------------------------------------------------------------------------------------------------------------------
// Bundle 1 (P-1..P-11): Differential mutated-request oracle against official p1/m1 and Rust Runtime.
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum DifferentialMutation {
    Valid,
    OutOfBoundsLedgerTime,
    WrongSubmitterSignature,
    UnauthorizedActAs,
    ExtraForgedInformee,
}

struct BuiltSampleSubmission {
    envelopes: Vec<(Vec<String>, Vec<u8>)>,
    uuid: String,
    contract_id_hex: String,
    max_sequencing_time_micros: i64,
}

fn build_sample_create_envelopes(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    erin: &str,
    mutation: DifferentialMutation,
) -> BuiltSampleSubmission {
    let alice = var("CANTON_RS_ALICE");
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    build_sample_create_envelopes_for(r, c, token, erin, &alice, &p1_uid, true, mutation)
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper builds customized envelopes for both shared and r-only differential passes"
)]
fn build_sample_create_envelopes_for(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    bank_owner: &str,
    auditor: &str,
    forged_informee: &str,
    include_p1_recipient: bool,
    mutation: DifferentialMutation,
) -> BuiltSampleSubmission {
    use canton_participant::contract_id as ci;
    use canton_participant::contract_wire::{authentication_data, ContractInstance, LfValue};
    use canton_participant::{confirmation_wire as cw, merkle_wire as mw, view_message as vm};
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let alice = var("CANTON_RS_ALICE");
    let package_id = var("CANTON_RS_SAMPLE_PACKAGE");
    let p1_key = include_p1_recipient.then(|| p1_encryption_key(c, r, token));
    let p1_fp = var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT");
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(token))
        .unwrap()
        .unwrap();
    let preparation_time = now;
    let ledger_time = match mutation {
        DifferentialMutation::OutOfBoundsLedgerTime => now - 120_000_000,
        _ => now,
    };
    let uuid = fresh_uuid();
    let vpd_salt = fresh("vpd-salt");
    let salt = ci::contract_salt(&ci::SaltInputs {
        view_participant_data_salt: &vpd_salt,
        create_index: 0,
        view_position: &[vec![]],
        transaction_uuid: &uuid,
        synchronizer_id: &synchronizer,
        mediator: "MGR::0",
    });
    let signatories = vec![bank_owner.to_string()];
    let hash_arg = ci::HashValue::Record {
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        fields: vec![
            ("bank".into(), ci::HashValue::Party(bank_owner.to_string())),
            ("owner".into(), ci::HashValue::Party(bank_owner.to_string())),
            ("auditor".into(), ci::HashValue::Party(auditor.to_string())),
            ("assetSymbol".into(), ci::HashValue::Text("USD".into())),
            (
                "amount".into(),
                ci::HashValue::Numeric(100 * 10_000_000_000),
            ),
        ],
    };
    let contract_hash = ci::lf_contract_hash(
        "sample-contract",
        &["AssetHolding".into()],
        &["AssetHolding".into()],
        &hash_arg,
    );
    let mut stakeholders = vec![bank_owner.to_string(), auditor.to_string()];
    stakeholders.sort();
    stakeholders.dedup();
    let unicum = ci::unicum(
        &salt,
        &ci::UnicumInputs {
            created_at_micros: ledger_time,
            signatories: &signatories,
            stakeholders: &stakeholders,
            key: None,
            contract_hash: &contract_hash,
        },
    );
    let node_seed = fresh("node-seed");
    let discriminator =
        ci::derive_contract_discriminator(&node_seed, preparation_time, &stakeholders);
    let id_hex = ci::contract_id(&discriminator, &unicum);
    let instance = ContractInstance {
        contract_id: hex::decode(&id_hex).unwrap(),
        package_name: "sample-contract".into(),
        package_id,
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        arg: LfValue::Record(vec![
            LfValue::Party(bank_owner.to_string()),
            LfValue::Party(bank_owner.to_string()),
            LfValue::Party(auditor.to_string()),
            LfValue::Text("USD".into()),
            LfValue::Numeric("100.0000000000".into()),
        ]),
        signatories: signatories.iter().cloned().collect(),
        stakeholders: stakeholders.iter().cloned().collect(),
        created_at_micros: ledger_time,
        authentication_data: authentication_data(&salt),
        key: None,
    };
    let instance_bytes = instance.encode();
    let vpd = mw::view_participant_data_create(&instance_bytes, &id_hex, &node_seed, &vpd_salt);
    let uid = r.uid();
    let common = mw::common_metadata(&synchronizer, 0, &fresh("cm"), &uuid);
    let participant = mw::participant_metadata(ledger_time, preparation_time, None, &fresh("pm"));
    let max_sequencing_time_micros = now + 60_000_000;
    let act_as: Vec<&str> = match mutation {
        DifferentialMutation::UnauthorizedActAs => vec![alice.as_str(), bank_owner],
        _ => vec![bank_owner],
    };
    let submitter = mw::submitter_metadata(
        &mw::SubmitterInfo {
            act_as,
            user_id: "rust-user",
            command_id: &unique("cmd"),
            submitting_participant_uid: &uid,
            submission_id: None,
            dedup_duration: (300, 0),
            max_sequencing_time_micros,
        },
        &fresh("sm"),
    );
    let mut informees = stakeholders;
    informees.push(uid.clone());
    if matches!(mutation, DifferentialMutation::ExtraForgedInformee) {
        informees.push(forged_informee.to_string());
    }
    informees.sort();
    informees.dedup();
    let informee_refs: Vec<&str> = informees.iter().map(String::as_str).collect();
    let mut confirmers: Vec<(&str, i32)> = vec![(bank_owner, 1), (uid.as_str(), 1)];
    confirmers.sort();
    let vcd = mw::view_common_data(
        &informee_refs,
        &[mw::QuorumSpec {
            confirmers,
            threshold: 2,
        }],
        &fresh("vcd"),
    );
    let view = |participant_data: &mw::Tree| {
        mw::view_node(
            &mw::Tree::leaf(&vcd),
            participant_data,
            &mw::merkle_seq(&[]),
        )
    };
    let full_view = view(&mw::Tree::leaf(&vpd));
    let full = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::leaf(&participant),
        &mw::merkle_seq(std::slice::from_ref(&full_view)),
    );
    let informee = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::blinded(participant.root_hash()),
        &mw::merkle_seq(&[view(&mw::Tree::blinded(vpd.root_hash()))]),
    );
    assert_eq!(full.root_hash, informee.root_hash);
    let wrong_key = canton_participant::topology_wire::Ed25519Key::from_seed([0x42; 32]);
    let view_sig = match mutation {
        DifferentialMutation::WrongSubmitterSignature => wrong_key.sign_bytes(&full.root_hash),
        _ => r.signing_key.sign_bytes(&full.root_hash),
    };
    let r_fp = r.encryption_fingerprint();
    let mut view_recipients = vec![vm::Recipient {
        encryption_spki: r.encryption_spki(),
        fingerprint: &r_fp,
        ecies_iv: fresh("ecies-iv2")[..16].try_into().unwrap(),
        ecies_ephemeral_scalar: fresh("ecies-eph2"),
    }];
    if let Some(p1_spki) = &p1_key {
        view_recipients.push(vm::Recipient {
            encryption_spki: p1_spki,
            fingerprint: &p1_fp,
            ecies_iv: fresh("ecies-iv")[..16].try_into().unwrap(),
            ecies_ephemeral_scalar: fresh("ecies-eph"),
        });
    }
    let encrypted = vm::encrypted_view_message(
        &vm::light_view_tree(&full),
        &full_view.hash,
        &fresh("randomness")[..16].try_into().unwrap(),
        &fresh("gcm-iv")[..12].try_into().unwrap(),
        &view_recipients,
        &synchronizer,
        view_sig,
    );
    let mediator = cw::mediator_group(0);
    let mut envelopes = vec![
        (
            vec![mediator.clone()],
            cw::informee_message(&informee, &r.signing_key),
        ),
        (
            vec![mediator.clone(), r.member()],
            cw::root_hash_message(&full.root_hash, &synchronizer, now),
        ),
    ];
    let mut enc_targets = vec![r.member()];
    if include_p1_recipient {
        envelopes.push((
            vec![mediator, var("CANTON_RS_MEMBER_P1")],
            cw::root_hash_message(&full.root_hash, &synchronizer, now),
        ));
        enc_targets.push(var("CANTON_RS_MEMBER_P1"));
    }
    envelopes.push((enc_targets, encrypted));
    BuiltSampleSubmission {
        envelopes,
        uuid,
        contract_id_hex: id_hex,
        max_sequencing_time_micros,
    }
}

fn send_and_receive_runtime_steps(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    runtime: &mut rt::Runtime,
    mut observer: Option<&mut rt::Runtime>,
    cursor: &mut i64,
    envelopes: &[(Vec<String>, Vec<u8>)],
    max_sequencing_time_micros: i64,
) -> (i64, rt::Step, Option<rt::Step>) {
    use canton_participant::sequencing_wire as sw;
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let message_id = unique("diff");
    let req = sw::submission_request_to_groups(
        &r.member(),
        &message_id,
        envelopes,
        max_sequencing_time_micros,
    );
    c.send_async(
        &r.member(),
        &synchronizer,
        token,
        sw::signed_submission_request(req, &r.signing_key),
    )
    .expect("sequencer accepts differential test submission");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        let events = c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                token,
                Some(*cursor),
                1,
                std::time::Duration::from_secs(10),
            )
            .unwrap_or_default();
        for raw in &events {
            let d = sw::decode_delivered(raw).unwrap();
            *cursor = d.timestamp_micros + 1;
            let step = runtime.receive(raw).unwrap();
            let obs_step = match observer.as_deref_mut() {
                Some(obs) => obs.receive(raw).unwrap(),
                None => None,
            };
            if d.message_id.as_deref() == Some(message_id.as_str()) {
                return (
                    d.timestamp_micros,
                    step.expect("our submission produced a Runtime step"),
                    obs_step,
                );
            }
        }
    }
    panic!("timed out waiting for differential request {message_id}");
}

/// R-15 Differential oracle (P-1..P-11): sends one valid and five mutated confirmation requests simultaneously to official p1/m1
/// (with `erin` hosted at threshold 1 on `r` [Submission] and `p1` [Confirmation]) and to live Rust [`rt::Runtime`] instances
/// (submitting `r` plus a non-submitting observer with the same role as `p1`), asserting exact value parity of `LOCAL_VERDICT_*`
/// error codes and sending Rust's actual `Decision` (Reject/Malformed) to `m1`.
#[test]
fn mutated_requests_match_official_p1_verdicts() {
    use canton_participant::confirmation_wire::{self as cw, Outcome};
    use canton_participant::sequencing_wire as sw;
    let name = unique("r-diff");
    let (r, mut c, token) = authenticated(&name);
    let r_member = r.member();
    let (r_prefix, r_fp) = r_member.rsplit_once("::").unwrap();
    let r_log_name = format!("{r_prefix}::{}...", &r_fp[..r_fp.len().min(12)]);
    let wait_m1_phase5_responses = |req_id: i64, min_count: usize, label: &str| -> usize {
        let req_iso = iso_micros(req_id);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut count = 0usize;
        while std::time::Instant::now() < deadline {
            let log = node_log();
            count = log
                .lines()
                .filter(|l| {
                    l.contains("mediator=m1")
                        && l.contains("Phase 5: Received")
                        && l.contains(&format!("request={req_iso}"))
                })
                .count();
            if count >= min_count {
                return count;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        panic!(
            "{label}: m1 logged {count} Phase 5 response(s) for request={req_iso}, expected >= {min_count}"
        );
    };
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let before_hosting = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let erin = host_party_and_vet_sample(&r, &mut c, &token, "erin", true);
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let dir_state = state_dir(&name);
    let mut config = runtime_config(
        &r,
        &erin,
        p1_keys.clone(),
        mediator_keys.clone(),
        canton_participant::view_acs::Timeouts::default(),
    );
    config.follow_topology = true;
    let mut runtime =
        rt::Runtime::open(config, rust_engine(), Some(&dir_state), before_hosting).unwrap();
    runtime.load_topology(&mut c, &token).unwrap();
    let sync_info = c.synchronizer_id().unwrap();
    runtime.connected_to(&sync_info.sequencer_uid);
    runtime.trust_own_submissions(
        canton_algo::member_signature::own_ed25519_key(&r.signing_key.spki_der).unwrap(),
        &r.uid(),
    );
    // Non-submitting Rust observer (`amSubmitter = false`, standing in `p1`'s protocol identity) to differentially compare Case 6 replay.
    let obs_dir_state = state_dir(&format!("{name}-obs"));
    let mut obs_config = runtime_config(
        &r,
        &erin,
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    obs_config.follow_topology = true;
    obs_config
        .submitter_keys
        .push(canton_algo::member_signature::own_ed25519_key(&r.signing_key.spki_der).unwrap());
    let mut observer_rt = rt::Runtime::open(
        obs_config,
        rust_engine(),
        Some(&obs_dir_state),
        before_hosting,
    )
    .unwrap();
    observer_rt.load_topology(&mut c, &token).unwrap();
    observer_rt.connected_to(&sync_info.sequencer_uid);

    // Advance both runtimes together over the exact same stream from `before_hosting + 1` so neither
    // pulls ahead on concurrent sandbox events before Case 1/Case 6.
    let mut init_cursor = before_hosting + 1;
    let init_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < init_deadline
        && (runtime.hosts_of(&erin).is_empty() || observer_rt.hosts_of(&erin).is_empty())
    {
        for raw in c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(init_cursor),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default()
        {
            let d = sw::decode_delivered(&raw).unwrap();
            init_cursor = d.timestamp_micros + 1;
            let _ = runtime.receive(&raw).unwrap();
            let _ = observer_rt.receive(&raw).unwrap();
        }
    }
    assert!(
        !runtime.hosts_of(&erin).is_empty() && !observer_rt.hosts_of(&erin).is_empty(),
        "both runtime and observer_rt must learn party hosting for {erin}"
    );
    // Switch observer identity to official `p1` (co-host of `erin`, non-submitter for `r`'s requests) after sequencer download.
    observer_rt.config.member = var("CANTON_RS_MEMBER_P1");

    let mut cursor = runtime.cursor() + 1;

    fn extract_rust_verdict_code(outcome: &Outcome) -> (&str, bool) {
        let (msg, malformed) = match outcome {
            Outcome::Approve => return ("Approve", false),
            Outcome::Abstain(why) => (why.as_str(), false),
            Outcome::Reject(why) => (why.as_str(), false),
            Outcome::Malformed(why) => (why.as_str(), true),
        };
        let code = msg
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .find(|tok| !tok.is_empty())
            .unwrap_or(msg);
        (code, malformed)
    }

    let wait_p1_verdict_log = |req_id: i64| -> (String, String) {
        let needle_req = format!("requestId=RequestId({})", iso_micros(req_id));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            let log = node_log();
            let all: Vec<&str> = log.lines().collect();
            for i in 0..all.len() {
                if !all[i].contains("TransactionConfirmationResponsesFactory")
                    || !all[i].contains("participant=p1")
                {
                    continue;
                }
                let end = all[(i + 1)..(i + 120).min(all.len())]
                    .iter()
                    .position(|l| is_canton_log_entry_start(l))
                    .map_or((i + 120).min(all.len()), |off| i + 1 + off);
                let block = all[i..end].join("\n");
                if block.contains(&needle_req) {
                    if let Some(pos) = block.find("LOCAL_VERDICT_") {
                        let code: String = block[pos..]
                            .chars()
                            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                            .collect();
                        return (code, block);
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        panic!(
            "timed out waiting for p1 TransactionConfirmationResponsesFactory log for {needle_req}"
        );
    };

    let send_r_decision =
        |c: &mut SequencerConnect,
         req_id: i64,
         root_hash: &[u8],
         decision: &canton_participant::view_decision::Decision| {
            let (resp_content, resp_sigs) = cw::confirmation_responses(
                req_id,
                root_hash,
                &synchronizer,
                &r.member(),
                &[cw::ViewResponse {
                    view_position: &decision.view_position,
                    outcome: decision.outcome.clone(),
                    confirming_parties: &decision.confirming_parties,
                }],
                &r.signing_key,
            );
            c.send_async(
                &r.member(),
                &synchronizer,
                &token,
                sw::signed_submission_request(
                    sw::submission_request_signed(
                        &r.member(),
                        &unique("diff-resp"),
                        &[(vec![cw::mediator_group(0)], resp_content, resp_sigs)],
                        req_id + 30_000_000,
                    ),
                    &r.signing_key,
                ),
            )
            .expect("sequencer accepts confirmation decision");
        };

    // 1. Positive control (valid create): both p1 and Rust Runtimes approve.
    let valid =
        build_sample_create_envelopes(&r, &mut c, &token, &erin, DifferentialMutation::Valid);
    let (valid_req_id, valid_step, valid_obs_step) = send_and_receive_runtime_steps(
        &r,
        &mut c,
        &token,
        &mut runtime,
        Some(&mut observer_rt),
        &mut cursor,
        &valid.envelopes,
        valid.max_sequencing_time_micros,
    );
    assert_eq!(valid_step.to_send.len(), 1, "{:#?}", valid_step.notes);
    assert_eq!(valid_step.to_send[0].decision().outcome, Outcome::Approve);
    let valid_obs_step = valid_obs_step.expect("observer_rt received Case 1 request");
    assert_eq!(
        valid_obs_step.to_send[0].decision().outcome,
        Outcome::Approve
    );
    send_r_decision(
        &mut c,
        valid_req_id,
        &valid_step.to_send[0].root_hash,
        valid_step.to_send[0].decision(),
    );
    let finalized_ok = finalized_block_at(valid_req_id);
    assert!(
        finalized_ok.contains("with verdict Approve"),
        "{finalized_ok}"
    );
    let drain_until = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < drain_until
        && (!runtime.ledger.is_active(&valid.contract_id_hex)
            || !observer_rt.ledger.is_active(&valid.contract_id_hex))
    {
        for raw in c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(cursor),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default()
        {
            let d = sw::decode_delivered(&raw).unwrap();
            cursor = d.timestamp_micros + 1;
            let _ = runtime.receive(&raw).unwrap();
            let _ = observer_rt.receive(&raw).unwrap();
        }
    }
    assert!(runtime.ledger.is_active(&valid.contract_id_hex));
    assert!(observer_rt.ledger.is_active(&valid.contract_id_hex));

    // 6 (run right after 1 while within max_sequencing_time): Replay identical request envelopes (P-3).
    // Submitting `runtime` (`amSubmitter=true`) emits `LOCAL_VERDICT_MALFORMED_REQUEST`;
    // non-submitting `observer_rt` and official `p1` (`amSubmitter=false`) both emit `LOCAL_VERDICT_CREATES_EXISTING_CONTRACTS`;
    // mediator `m1` logs `DUPLICATE_CONFIRMATION_REQUEST_UUID`.
    let now_replay = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let (replay_req_id, replay_step, replay_obs_step) = send_and_receive_runtime_steps(
        &r,
        &mut c,
        &token,
        &mut runtime,
        Some(&mut observer_rt),
        &mut cursor,
        &valid.envelopes,
        now_replay + 60_000_000,
    );
    assert_eq!(replay_step.to_send.len(), 1, "{:#?}", replay_step.notes);
    let (r_replay_code, r_replay_mal) =
        extract_rust_verdict_code(&replay_step.to_send[0].decision().outcome);
    assert!(r_replay_mal, "{:#?}", replay_step.to_send[0].decision());
    assert_eq!(r_replay_code, "LOCAL_VERDICT_MALFORMED_REQUEST");
    assert!(
        matches!(
            &replay_step.to_send[0].decision().outcome,
            Outcome::Malformed(why) if why.contains("replayed")
        ),
        "expected Rust submitter Runtime to reject replayed root hash as replayed Malformed: {:#?}",
        replay_step.to_send[0].decision()
    );

    let replay_obs_step = replay_obs_step.expect("observer_rt received Case 6 replay");
    assert_eq!(
        replay_obs_step.to_send.len(),
        1,
        "{:#?}",
        replay_obs_step.notes
    );
    let (obs_replay_code, obs_replay_mal) =
        extract_rust_verdict_code(&replay_obs_step.to_send[0].decision().outcome);
    let (p1_replay_code, p1_replay_block) = wait_p1_verdict_log(replay_req_id);
    assert!(
        obs_replay_mal,
        "observer_rt must mark committed replay create as Malformed: {:#?}",
        replay_obs_step.to_send[0].decision()
    );
    assert_eq!(
        obs_replay_code,
        "LOCAL_VERDICT_CREATES_EXISTING_CONTRACTS",
        "{:#?}",
        replay_obs_step.to_send[0].decision()
    );
    assert_eq!(
        obs_replay_code, p1_replay_code,
        "Case 6 non-submitter replay verdict code parity: rust_obs={obs_replay_code} vs p1={p1_replay_code}\n{p1_replay_block}"
    );

    send_r_decision(
        &mut c,
        replay_req_id,
        &replay_step.to_send[0].root_hash,
        replay_step.to_send[0].decision(),
    );
    let replay_iso = iso_micros(replay_req_id);
    let dup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let dup_logged = loop {
        let log = node_log();
        if log.lines().any(|l| {
            l.contains("mediator=m1")
                && l.contains(&valid.uuid)
                && l.contains("DUPLICATE_CONFIRMATION_REQUEST_UUID")
        }) {
            break true;
        }
        if std::time::Instant::now() >= dup_deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };
    assert!(
        dup_logged,
        "m1 did not log DUPLICATE_CONFIRMATION_REQUEST_UUID for uuid {} (req {replay_req_id})",
        valid.uuid
    );
    wait_m1_phase5_responses(replay_req_id, 2, "case6_erin_replay");
    let log_after_replay = node_log();
    assert!(
        !log_after_replay.lines().any(|l| l.contains("mediator=m1")
            && l.contains(&replay_iso)
            && (l.contains("MalformedMessage") || l.contains("InvalidMessage"))),
        "m1 flagged r's replay response as MalformedMessage/InvalidMessage for {replay_iso}"
    );

    // 2. Out-of-bounds ledger time (P-2): both p1 and Rust Runtime issue LocalReject with LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND.
    let bad_time = build_sample_create_envelopes(
        &r,
        &mut c,
        &token,
        &erin,
        DifferentialMutation::OutOfBoundsLedgerTime,
    );
    let (time_req_id, time_step, _) = send_and_receive_runtime_steps(
        &r,
        &mut c,
        &token,
        &mut runtime,
        None,
        &mut cursor,
        &bad_time.envelopes,
        bad_time.max_sequencing_time_micros,
    );
    let time_decision = time_step.to_send[0].decision();
    let (rust_time_code, rust_time_mal) = extract_rust_verdict_code(&time_decision.outcome);
    assert!(!rust_time_mal, "{time_decision:#?}");
    assert_eq!(rust_time_code, "LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND");
    let (p1_time_code, p1_time_block) = wait_p1_verdict_log(time_req_id);
    assert_eq!(
        rust_time_code, p1_time_code,
        "Case 2 verdict code parity: rust={rust_time_code} vs p1={p1_time_code}\n{p1_time_block}"
    );
    send_r_decision(
        &mut c,
        time_req_id,
        &time_step.to_send[0].root_hash,
        time_decision,
    );
    let finalized_time = finalized_block_at(time_req_id);
    assert!(
        finalized_time.contains("ParticipantReject")
            && (finalized_time.contains("reported by PAR::p1")
                || finalized_time.contains(&format!("reported by {r_log_name}")))
            && finalized_time.contains("isMalformed = false")
            && finalized_time.contains("LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND"),
        "{finalized_time}"
    );
    wait_m1_phase5_responses(time_req_id, 2, "case2_out_of_bounds_time");
    let time_iso = iso_micros(time_req_id);
    let log_after_time = node_log();
    assert!(
        !log_after_time.lines().any(|l| l.contains("mediator=m1")
            && l.contains(&time_iso)
            && (l.contains("MalformedMessage") || l.contains("InvalidMessage"))),
        "m1 flagged r's Case 2 response as MalformedMessage/InvalidMessage for {time_iso}"
    );

    // 3..5. Malformed mutations: WrongSubmitterSignature (P-3), UnauthorizedActAs (P-1), ExtraForgedInformee (P-10).
    for (label, mutation, expected_code, expected_p1_detail) in [
        (
            "wrong_sig",
            DifferentialMutation::WrongSubmitterSignature,
            "LOCAL_VERDICT_MALFORMED_REQUEST",
            "not correctly authenticated",
        ),
        (
            "unauth_act_as",
            DifferentialMutation::UnauthorizedActAs,
            "LOCAL_VERDICT_MALFORMED_REQUEST",
            "not correctly authorized",
        ),
        (
            "extra_informee",
            DifferentialMutation::ExtraForgedInformee,
            "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK",
            "Reconstructed view differs",
        ),
    ] {
        let built = build_sample_create_envelopes(&r, &mut c, &token, &erin, mutation);
        let (req_id, step, _) = send_and_receive_runtime_steps(
            &r,
            &mut c,
            &token,
            &mut runtime,
            None,
            &mut cursor,
            &built.envelopes,
            built.max_sequencing_time_micros,
        );
        let decision = step.to_send[0].decision();
        let (rust_code, rust_malformed) = extract_rust_verdict_code(&decision.outcome);
        assert!(
            rust_malformed,
            "{label}: expected Malformed from Rust Runtime, got {decision:#?}"
        );
        assert_eq!(rust_code, expected_code, "{label}: {decision:#?}");
        // Wait for p1's Phase 3 log before sending r's decision so r does not abort p1's check mid-flight.
        let (p1_code, p1_block) = wait_p1_verdict_log(req_id);
        assert!(
            p1_block.contains(expected_p1_detail),
            "{label}: expected detail {expected_p1_detail:?} in p1 log:\n{p1_block}"
        );
        assert_eq!(
            rust_code, p1_code,
            "{label}: Rust vs p1 verdict code mismatch ({rust_code} != {p1_code}):\n{p1_block}"
        );

        send_r_decision(&mut c, req_id, &step.to_send[0].root_hash, decision);
        let finalized = finalized_block_at(req_id);
        assert!(
            finalized.contains("ParticipantReject")
                && (finalized.contains("reported by PAR::p1")
                    || finalized.contains(&format!("reported by {r_log_name}")))
                && finalized.contains("isMalformed = true"),
            "{label}: expected Malformed ParticipantReject from m1, got:\n{finalized}"
        );
        wait_m1_phase5_responses(req_id, 2, label);
        let req_iso = iso_micros(req_id);
        let log_after = node_log();
        assert!(
            !log_after.lines().any(|l| l.contains("mediator=m1")
                && l.contains(&req_iso)
                && (l.contains("MalformedMessage") || l.contains("InvalidMessage"))),
            "{label}: m1 flagged r's response as MalformedMessage/InvalidMessage for {req_iso}"
        );
    }

    // Pass B (R-15): r-only party `fiona` (p1 is neither informee nor recipient), proving m1 finalizes
    // STRICTLY from r's Decision (`reported by {r_log_name}`, never `PAR::p1`).
    let fiona = host_party_and_vet_sample(&r, &mut c, &token, "fiona", false);
    let gwen = host_party_and_vet_sample(&r, &mut c, &token, "gwen", false);
    let fiona_steps = run_until(&mut runtime, &mut c, &token, &r.signing_key, 30, |rt| {
        !rt.hosts_of(&fiona).is_empty() && !rt.hosts_of(&gwen).is_empty()
    });
    assert!(
        !runtime.hosts_of(&fiona).is_empty() && !runtime.hosts_of(&gwen).is_empty(),
        "runtime learned r-only party hostings for fiona/gwen: {fiona_steps:#?}"
    );
    cursor = runtime.cursor() + 1;

    // Pass B Case 1 + Case 6 (r-only replay): create active fiona/gwen contract first, then replay its envelopes.
    let valid_fiona = build_sample_create_envelopes_for(
        &r,
        &mut c,
        &token,
        &fiona,
        &fiona,
        &gwen,
        false,
        DifferentialMutation::Valid,
    );
    let (fiona_valid_req_id, fiona_valid_step, _) = send_and_receive_runtime_steps(
        &r,
        &mut c,
        &token,
        &mut runtime,
        None,
        &mut cursor,
        &valid_fiona.envelopes,
        valid_fiona.max_sequencing_time_micros,
    );
    assert_eq!(
        fiona_valid_step.to_send[0].decision().outcome,
        Outcome::Approve
    );
    send_r_decision(
        &mut c,
        fiona_valid_req_id,
        &fiona_valid_step.to_send[0].root_hash,
        fiona_valid_step.to_send[0].decision(),
    );
    let fiona_ok = finalized_block_at(fiona_valid_req_id);
    assert!(fiona_ok.contains("with verdict Approve"), "{fiona_ok}");
    let fiona_drain_until = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < fiona_drain_until
        && !runtime.ledger.is_active(&valid_fiona.contract_id_hex)
    {
        for raw in c
            .subscribe_patiently(
                &r.member(),
                &synchronizer,
                &token,
                Some(cursor),
                1,
                std::time::Duration::from_secs(5),
            )
            .unwrap_or_default()
        {
            let d = sw::decode_delivered(&raw).unwrap();
            cursor = d.timestamp_micros + 1;
            let _ = runtime.receive(&raw).unwrap();
        }
    }
    assert!(runtime.ledger.is_active(&valid_fiona.contract_id_hex));

    let now_fiona_replay = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let (fiona_replay_req_id, fiona_replay_step, _) = send_and_receive_runtime_steps(
        &r,
        &mut c,
        &token,
        &mut runtime,
        None,
        &mut cursor,
        &valid_fiona.envelopes,
        now_fiona_replay + 60_000_000,
    );
    let fiona_replay_dec = fiona_replay_step.to_send[0].decision();
    let (r_fiona_replay_code, r_fiona_replay_mal) =
        extract_rust_verdict_code(&fiona_replay_dec.outcome);
    assert!(r_fiona_replay_mal, "{fiona_replay_dec:#?}");
    assert_eq!(r_fiona_replay_code, "LOCAL_VERDICT_MALFORMED_REQUEST");
    assert!(
        matches!(&fiona_replay_dec.outcome, Outcome::Malformed(why) if why.contains("replayed")),
        "expected r-only replay Malformed: {fiona_replay_dec:#?}"
    );
    send_r_decision(
        &mut c,
        fiona_replay_req_id,
        &fiona_replay_step.to_send[0].root_hash,
        fiona_replay_dec,
    );
    let fiona_replay_iso = iso_micros(fiona_replay_req_id);
    let fiona_dup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let fiona_dup_logged = loop {
        let log = node_log();
        if log.lines().any(|l| {
            l.contains("mediator=m1")
                && l.contains(&valid_fiona.uuid)
                && l.contains("DUPLICATE_CONFIRMATION_REQUEST_UUID")
        }) {
            break true;
        }
        if std::time::Instant::now() >= fiona_dup_deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };
    assert!(
        fiona_dup_logged,
        "m1 did not log DUPLICATE_CONFIRMATION_REQUEST_UUID for fiona uuid {} (req {fiona_replay_req_id})",
        valid_fiona.uuid
    );
    wait_m1_phase5_responses(fiona_replay_req_id, 1, "r_only_case6_replay");
    let log_after_fiona_replay = node_log();
    assert!(
        !log_after_fiona_replay.lines().any(|l| l.contains("mediator=m1")
            && l.contains(&fiona_replay_iso)
            && (l.contains("MalformedMessage") || l.contains("InvalidMessage"))),
        "m1 flagged r's r-only replay response as MalformedMessage/InvalidMessage for {fiona_replay_iso}"
    );

    for (label, mutation, expected_code, expected_malformed_flag, check_code_in_finalized) in [
        (
            "r_only_out_of_bounds_time",
            DifferentialMutation::OutOfBoundsLedgerTime,
            "LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND",
            false,
            true,
        ),
        (
            "r_only_wrong_sig",
            DifferentialMutation::WrongSubmitterSignature,
            "LOCAL_VERDICT_MALFORMED_REQUEST",
            true,
            false,
        ),
        (
            "r_only_unauth_act_as",
            DifferentialMutation::UnauthorizedActAs,
            "LOCAL_VERDICT_MALFORMED_REQUEST",
            true,
            false,
        ),
        (
            "r_only_extra_informee",
            DifferentialMutation::ExtraForgedInformee,
            "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK",
            true,
            true,
        ),
    ] {
        let built = build_sample_create_envelopes_for(
            &r, &mut c, &token, &fiona, &fiona, &gwen, false, mutation,
        );
        let (req_id, step, _) = send_and_receive_runtime_steps(
            &r,
            &mut c,
            &token,
            &mut runtime,
            None,
            &mut cursor,
            &built.envelopes,
            built.max_sequencing_time_micros,
        );
        let decision = step.to_send[0].decision();
        let (rust_code, rust_malformed) = extract_rust_verdict_code(&decision.outcome);
        assert_eq!(
            rust_malformed, expected_malformed_flag,
            "{label}: unexpected malformed flag in {decision:#?}"
        );
        assert_eq!(rust_code, expected_code, "{label}: {decision:#?}");
        send_r_decision(&mut c, req_id, &step.to_send[0].root_hash, decision);

        let finalized = finalized_block_at(req_id);
        let expected_mal_str = format!("isMalformed = {expected_malformed_flag}");
        assert!(
            finalized.contains("ParticipantReject")
                && finalized.contains(&format!("reported by {r_log_name}"))
                && !finalized.contains("reported by PAR::p1")
                && finalized.contains(&expected_mal_str)
                && (!check_code_in_finalized || finalized.contains(expected_code)),
            "{label}: expected strict r-only ParticipantReject from m1, got:\n{finalized}"
        );
        wait_m1_phase5_responses(req_id, 1, label);
        let req_iso = iso_micros(req_id);
        let log_after = node_log();
        assert!(
            !log_after.lines().any(|l| l.contains("mediator=m1")
                && l.contains(&req_iso)
                && (l.contains("MalformedMessage") || l.contains("InvalidMessage"))),
            "{label}: m1 flagged r's response as MalformedMessage/InvalidMessage for {req_iso}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir_state);
    let _ = std::fs::remove_dir_all(&obs_dir_state);
}
