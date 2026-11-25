//! The sequencer judges a member by the topology in force (`MemberAuthenticationService`): a key the member's `OwnerToKeyMapping` no longer
//! names neither authenticates nor signs, a participant whose trust certificate is removed loses its token, its subscription and its
//! access, and a restart on the journal gives the same members.
#![allow(clippy::unwrap_used, reason = "integration test")]
mod common;
use canton_participant::sequencer_connect::{AuthKey, ConnectError, SequencerConnect, Token};
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::{self as tw, Ed25519Key, ParticipantIdentity};
use canton_proto::com::digitalasset::canton::crypto::v30::{
    public_key::Key, PublicKey, SigningKeyUsage,
};
use canton_proto::com::digitalasset::canton::protocol::v30::{
    SignedTopologyTransaction, TopologyTransaction,
};
use canton_sequencer_server::SynchronizerConfig;
use prost::Message as _;
use std::time::{Duration, Instant};

fn refused(e: ConnectError) -> String {
    match e {
        ConnectError::Status(s) => s,
        other => panic!("expected a refusal by the sequencer, got {other}"),
    }
}

fn synchronizer_uid(config: &SynchronizerConfig) -> String {
    format!("{}::{}", config.name, config.namespace_fingerprint)
}

/// `m` broadcasts `transactions` to every member and waits until the state took them.
fn broadcast(m: &mut common::Member, physical: &str, id: &str, txs: &[SignedTopologyTransaction]) {
    m.send(
        physical,
        &[(
            vec![tw::ALL_MEMBERS.to_string()],
            tw::topology_broadcast(physical, txs),
        )],
        id,
        common::far_future(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(800));
}

/// The key mapping of `identity` at serial 2 with `signing` and `authentication` in place of its keys, signed by its namespace and the new keys.
fn rotation(
    identity: &ParticipantIdentity,
    signing: &Ed25519Key,
    authentication: &Ed25519Key,
) -> SignedTopologyTransaction {
    use SigningKeyUsage::{ProofOfOwnership, Protocol, SequencerAuthentication};
    let signing_key = |k: &Ed25519Key, usages: &[SigningKeyUsage]| PublicKey {
        key: Some(Key::SigningPublicKey(k.public_key(usages))),
    };
    let mapping = tw::owner_to_key_mapping_at(
        &identity.member(),
        vec![
            signing_key(signing, &[Protocol, ProofOfOwnership]),
            signing_key(authentication, &[SequencerAuthentication, ProofOfOwnership]),
            tw::p256_encryption_key(identity.encryption_spki()),
        ],
        2,
        1,
    );
    tw::signed(
        mapping.clone(),
        vec![
            identity.namespace_key.sign_transaction(&mapping),
            signing.sign_transaction(&mapping),
            authentication.sign_transaction(&mapping),
        ],
    )
}

/// The removal (serial 2) of `identity`'s trust certificate, signed by its namespace: the participant leaves the synchronizer.
fn offboarding(
    identity: &ParticipantIdentity,
    synchronizer_uid: &str,
) -> SignedTopologyTransaction {
    let certificate =
        tw::synchronizer_trust_certificate(&identity.uid(), synchronizer_uid, vec![2]);
    let (data, version) = tw::unversioned(&certificate).unwrap();
    let mut tx = TopologyTransaction::decode(data.as_slice()).unwrap();
    tx.operation = 2;
    tx.serial = 2;
    let removal = tw::versioned(tx.encode_to_vec(), version);
    tw::signed(
        removal.clone(),
        vec![identity.namespace_key.sign_transaction(&removal)],
    )
}

fn authenticate_with(
    client: &mut SequencerConnect,
    member: &str,
    key: &Ed25519Key,
    physical: &str,
) -> Result<Token, ConnectError> {
    let challenge = client.challenge(member, &[37])?;
    let signature = key.sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, physical).unwrap());
    client.authenticate(member, &challenge.nonce, signature)
}

fn send_signed_by(
    m: &mut common::Member,
    physical: &str,
    token: &Token,
    key: &Ed25519Key,
    id: &str,
) -> Result<(), ConnectError> {
    let member = m.identity.member();
    let request = sw::submission_request_to_groups(
        &member,
        id,
        &[(vec![member.clone()], vec![1, 2, 3])],
        common::far_future(),
    );
    m.client.send_async(
        &member,
        physical,
        token,
        sw::signed_submission_request(request, key),
    )
}

#[test]
fn a_rotated_key_no_longer_authenticates_or_signs_and_the_new_one_does() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut a = common::join(&url, &config, "rotating");
    let member = a.identity.member();
    let next = ParticipantIdentity::generate("rotating-next");
    let rotated = rotation(&a.identity, &next.signing_key, &next.sequencer_auth_key);
    broadcast(&mut a, &physical, "rotate", &[rotated]);
    // the token given for the key that left the mapping is revoked (`invalidateTokensByFingerprint`)
    let why = refused(
        a.client
            .sequencer_time(&member, &physical, Some(&a.token))
            .expect_err("the old key's token"),
    );
    assert!(why.contains("not valid for this member"), "{why}");
    // the challenge names the new authentication key only, the old one is refused and the new one gives a token
    let challenge = a.client.challenge(&member, &[37]).unwrap();
    assert_eq!(
        challenge.fingerprints,
        vec![next.sequencer_auth_key.fingerprint.clone()]
    );
    let why = refused(
        authenticate_with(
            &mut a.client,
            &member,
            &a.identity.sequencer_auth_key,
            &physical,
        )
        .expect_err("the old authentication key"),
    );
    assert!(why.contains("not signed by a key registered"), "{why}");
    let token = authenticate_with(&mut a.client, &member, &next.sequencer_auth_key, &physical)
        .expect("the new authentication key");
    // a submission signed by the old protocol key is refused, one signed by the new key is sequenced
    let old_key = Ed25519Key::from_seed(a.identity.signing_key.seed());
    let why = refused(
        send_signed_by(&mut a, &physical, &token, &old_key, "old")
            .expect_err("signed by the old key"),
    );
    assert!(why.contains("SignatureWithWrongKey"), "{why}");
    send_signed_by(&mut a, &physical, &token, &next.signing_key, "new")
        .expect("signed by the new key");
}

#[test]
fn an_offboarded_participant_loses_its_token_its_subscription_and_its_access() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut b = common::join(&url, &config, "leaving");
    let member = b.identity.member();
    // an open subscription, from after the member's setup, that would wait 10 s for events it never gets
    let subscription = {
        let (url, physical, member, token, from) = (
            url.clone(),
            physical.clone(),
            member.clone(),
            b.token.clone(),
            b.cursor + 1,
        );
        std::thread::spawn(move || {
            let started = Instant::now();
            let mut client = SequencerConnect::connect(&url).unwrap();
            let _ = client.subscribe(
                &member,
                &physical,
                &token,
                Some(from),
                1000,
                Duration::from_secs(10),
            );
            started.elapsed()
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    let leaving = offboarding(&b.identity, &synchronizer_uid(&config));
    broadcast(&mut b, &physical, "leave", &[leaving]);
    let open_for = subscription.join().unwrap();
    assert!(
        open_for < Duration::from_secs(5),
        "the sequencer ended the subscription of the member it no longer serves (open for {open_for:?})"
    );
    let mut c = SequencerConnect::connect(&url).unwrap();
    assert!(!c.is_active_as(&member, &physical, None).unwrap());
    let why = refused(
        b.client
            .sequencer_time(&member, &physical, Some(&b.token))
            .expect_err("the revoked token"),
    );
    assert!(why.contains("not valid for this member"), "{why}");
    let (token, key) = (
        b.token.clone(),
        Ed25519Key::from_seed(b.identity.signing_key.seed()),
    );
    let why = refused(
        send_signed_by(&mut b, &physical, &token, &key, "after")
            .expect_err("a submission with the revoked token"),
    );
    assert!(why.contains("not valid for this member"), "{why}");
    let why = refused(c.challenge(&member, &[37]).expect_err("no challenge"));
    assert!(
        why.contains(&format!("Member {member} access is disabled")),
        "{why}"
    );
}

struct Running {
    runtime: tokio::runtime::Runtime,
    config: SynchronizerConfig,
    url: String,
}

fn start_in(dir: &std::path::Path, port: u16) -> Running {
    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = canton_sequencer_server::new_synchronizer_in(dir, "regsync", "rs1", 1).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (served, state) = (config.clone(), dir.to_path_buf());
    runtime.spawn(async move {
        canton_sequencer_server::serve_with(
            address,
            served,
            canton_sequencer_server::ServeOptions {
                state_dir: Some(state),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Running {
        runtime,
        config,
        url: format!("http://{address}"),
    }
}

#[test]
fn a_restarted_sequencer_serves_the_members_the_topology_gives() {
    let dir = std::env::temp_dir().join(format!("canton-rs-registry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let running = start_in(&dir, port);
    let physical = running.config.physical_synchronizer_id();
    let mut a = common::join(&running.url, &running.config, "restart-rotating");
    let mut b = common::join(&running.url, &running.config, "restart-leaving");
    let next = ParticipantIdentity::generate("restart-next");
    let rotated = rotation(&a.identity, &next.signing_key, &next.sequencer_auth_key);
    broadcast(&mut a, &physical, "rotate", &[rotated]);
    let leaving = offboarding(&b.identity, &synchronizer_uid(&running.config));
    broadcast(&mut b, &physical, "leave", &[leaving]);
    running.runtime.shutdown_background();
    std::thread::sleep(Duration::from_millis(300));

    let running = start_in(&dir, port);
    let mut c = SequencerConnect::connect(&running.url).unwrap();
    let rotated = a.identity.member();
    let challenge = c.challenge(&rotated, &[37]).unwrap();
    assert_eq!(
        challenge.fingerprints,
        vec![next.sequencer_auth_key.fingerprint.clone()],
        "the rotated member's keys are the mapping in force after the restart"
    );
    authenticate_with(&mut c, &rotated, &a.identity.sequencer_auth_key, &physical)
        .expect_err("the old key after the restart");
    authenticate_with(&mut c, &rotated, &next.sequencer_auth_key, &physical)
        .expect("the new key after the restart");
    let left = b.identity.member();
    assert!(!c.is_active_as(&left, &physical, None).unwrap());
    let why = refused(
        c.challenge(&left, &[37])
            .expect_err("the offboarded member after the restart"),
    );
    assert!(why.contains("access is disabled"), "{why}");
    running.runtime.shutdown_background();
    let _ = std::fs::remove_dir_all(&dir);
}
