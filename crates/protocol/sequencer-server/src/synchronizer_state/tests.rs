use super::*;

fn store() -> (TopologyStore, SynchronizerKeys) {
    let keys = SynchronizerKeys::generate();
    (TopologyStore::initial("sync", "seq", "med", &keys), keys)
}

/// U-27: a sequencer's successor connection in the **same** broadcast as the announcement it depends on is refused, as the official
/// participant refused it (S-NET-038 part 12); in a broadcast of its own after the announcement it is in force.
#[test]
fn a_successor_connection_needs_an_announcement_from_before_its_broadcast() {
    let (store, keys) = store();
    let successor = format!("sync::{}::37-1", keys.synchronizer_namespace());
    let seq_uid = format!("seq::{}", keys.namespace.fingerprint);
    let [announcement, connection] = upgrade_transactions(
        &keys,
        &seq_uid,
        &successor,
        1,
        4_000_000_000_000_000,
        "http://x:1",
    );
    let psid = format!("sync::{}::37-0", keys.synchronizer_namespace());
    let together = tw::topology_broadcast(&psid, &[announcement, connection.clone()]);
    let outcomes = store.accept_broadcast(&together, 1_000).unwrap();
    assert!(outcomes[0].is_in_force(), "{}", outcomes[0].note());
    assert!(
        outcomes[1].note().contains("no LSU is announced"),
        "{}",
        outcomes[1].note()
    );
    let alone = tw::topology_broadcast(&psid, &[connection]);
    let outcomes = store.accept_broadcast(&alone, 2_000).unwrap();
    assert!(outcomes[0].is_in_force(), "{}", outcomes[0].note());
}

/// A participant of its own namespace, onboarded on the store's synchronizer: a hosting may name it (Canton's
/// `checkPartyToParticipant` refuses a host without a trust certificate and keys).
fn onboarded_participant(
    store: &TopologyStore,
    keys: &SynchronizerKeys,
) -> tw::ParticipantIdentity {
    let participant = tw::ParticipantIdentity::generate("p");
    let synchronizer = format!("sync::{}", keys.synchronizer_namespace());
    let onboarding =
        tw::topology_broadcast("sync", &participant.onboarding_transactions(&synchronizer));
    let outcomes = store.accept_broadcast(&onboarding, 500_000).unwrap();
    assert!(outcomes.iter().all(Outcome::is_in_force), "{outcomes:?}");
    participant
}

/// A broadcast with one `PartyToParticipant` of `carol` in the synchronizer's namespace, hosted by `host`, signed by the party's
/// namespace and the host's (the two whose authorization adding a host needs) or by nobody.
fn hosting_broadcast(
    keys: &SynchronizerKeys,
    host: &tw::ParticipantIdentity,
    sign: bool,
) -> Vec<u8> {
    let ns = keys.namespace.fingerprint.clone();
    let bytes =
        tw::party_to_participant_at_serial(&format!("carol::{ns}"), &[(&host.uid(), 1)], 1, 1);
    let signatures = if sign {
        vec![
            keys.namespace.sign_transaction(&bytes),
            host.namespace_key.sign_transaction(&bytes),
        ]
    } else {
        vec![]
    };
    tw::topology_broadcast("sync", &[tw::signed(bytes, signatures)])
}

/// An unauthorized transaction that is not a proposal is refused (Canton's `TopologyStateProcessor`: only a proposal waits for
/// signatures).
#[test]
fn a_hosting_nobody_verifiably_signed_is_neither_kept_nor_used() {
    let (store, keys) = store();
    let host = onboarded_participant(&store, &keys);
    let before = store.snapshot().len();
    let outcomes = store
        .accept_broadcast(&hosting_broadcast(&keys, &host, false), 1_000_000)
        .expect("a topology broadcast");
    assert!(
        matches!(outcomes[0], Outcome::Refused(_)),
        "{:?}",
        outcomes[0]
    );
    assert_eq!(
        store.snapshot().len(),
        before,
        "a member that joins later is not handed it"
    );
    assert!(store.hosting_at(i64::MAX).is_empty());
}

#[test]
fn a_signed_hosting_is_kept_for_later_members_and_counts_from_its_effective_time() {
    let (store, keys) = store();
    let host = onboarded_participant(&store, &keys);
    let before = store.snapshot().len();
    let outcomes = store
        .accept_broadcast(&hosting_broadcast(&keys, &host, true), 1_000_000)
        .unwrap();
    assert!(outcomes[0].is_in_force(), "{:?}", outcomes[0]);
    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), before + 1);
    let kept = snapshot.last().unwrap();
    assert_eq!(kept.sequenced_micros, 1_000_000);
    assert_eq!(
        kept.valid_from_micros,
        1_000_000 + TOPOLOGY_CHANGE_DELAY_MICROS
    );
    assert!(!kept.signed.proposal);
    let party = format!("carol::{}", keys.namespace.fingerprint);
    let effective = 1_000_000 + TOPOLOGY_CHANGE_DELAY_MICROS;
    assert!(
        !store.hosting_at(effective).contains_key(&party),
        "a request sequenced at the effective time itself still sees the old state"
    );
    let (threshold, hosts) = store.hosting_at(effective + 1)[&party].clone();
    assert_eq!(threshold, 1);
    assert_eq!(hosts, vec![host.uid()]);
    // the same transaction again only merges its signatures into the one in force (the node's `mergeSignatures`): not kept twice
    let again = store
        .accept_broadcast(&hosting_broadcast(&keys, &host, true), 2_000_000)
        .unwrap();
    assert!(
        again[0].note().contains("signatures merged"),
        "{:?}",
        again[0]
    );
    assert_eq!(store.snapshot().len(), before + 1);
}

/// The parameters' transaction at serial `serial` with a confirmation response timeout of `seconds`, signed by **both owners** of the
/// synchronizer's decentralized namespace.
fn parameters_broadcast(keys: &SynchronizerKeys, serial: u32, seconds: i64) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v31::TopologyTransaction;
    use prost::Message;
    let mut parameters = tw::default_dynamic_parameters();
    parameters.confirmation_response_timeout = Some(prost_types::Duration { seconds, nanos: 0 });
    let first = tw::synchronizer_parameters_state(
        &format!("sync::{}", keys.synchronizer_namespace()),
        parameters,
    );
    let (data, version) = tw::unversioned(&first).unwrap();
    let mut tx = TopologyTransaction::decode(data.as_slice()).unwrap();
    tx.serial = serial;
    let bytes = tw::versioned(tx.encode_to_vec(), version);
    let signatures = vec![
        keys.namespace.sign_transaction(&bytes),
        keys.mediator_namespace.sign_transaction(&bytes),
    ];
    tw::topology_broadcast("sync", &[tw::signed(bytes, signatures)])
}

#[test]
fn a_change_of_the_parameters_sets_the_timeout_from_its_effective_time_on() {
    let (store, keys) = store();
    assert_eq!(
        store.timeouts_at(i64::MAX).confirmation_response_micros,
        30_000_000,
        "the default parameters of the synchronizer"
    );
    let outcomes = store
        .accept_broadcast(&parameters_broadcast(&keys, 2, 5), 1_000_000)
        .unwrap();
    assert!(outcomes[0].is_in_force(), "{:?}", outcomes[0]);
    let effective = 1_000_000 + TOPOLOGY_CHANGE_DELAY_MICROS;
    assert_eq!(
        store.timeouts_at(effective).confirmation_response_micros,
        30_000_000,
        "a request inside the delay is still timed out by the old timeout"
    );
    assert_eq!(
        store
            .timeouts_at(effective + 1)
            .confirmation_response_micros,
        5_000_000
    );
    // a change that skips a serial is refused and changes nothing
    let refused = store
        .accept_broadcast(&parameters_broadcast(&keys, 4, 1), 2_000_000)
        .unwrap();
    assert!(
        matches!(refused[0], Outcome::Refused(_)),
        "{:?}",
        refused[0]
    );
    assert_eq!(
        store.timeouts_at(i64::MAX).confirmation_response_micros,
        5_000_000
    );
}

/// A topology broadcast with the upgrade announcement to `successor` at `upgrade_micros` (serial `serial`), signed by the namespace's key.
fn announcement(
    keys: &SynchronizerKeys,
    successor: &str,
    upgrade_micros: i64,
    serial: u32,
) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v30::LsuAnnouncement;
    use canton_proto::com::digitalasset::canton::protocol::v31::{
        topology_mapping, TopologyMapping, TopologyTransaction,
    };
    use prost::Message;
    // the version wrapper of a transaction as this tracker reads them: taken from one the synchronizer made
    let base = tw::synchronizer_parameters_state("x::y", tw::default_dynamic_parameters());
    let (data, version) = tw::unversioned(&base).unwrap();
    let mut tx = TopologyTransaction::decode(data.as_slice()).unwrap();
    tx.serial = serial;
    tx.mapping = Some(TopologyMapping {
        mapping: Some(topology_mapping::Mapping::SynchronizerUpgradeAnnouncement(
            LsuAnnouncement {
                successor_physical_synchronizer_id: successor.to_string(),
                upgrade_time: Some(prost_types::Timestamp {
                    seconds: upgrade_micros.div_euclid(1_000_000),
                    nanos: (upgrade_micros.rem_euclid(1_000_000) * 1000) as i32,
                }),
            },
        )),
    });
    let bytes = tw::versioned(tx.encode_to_vec(), version);
    let signatures = vec![
        keys.namespace.sign_transaction(&bytes),
        keys.mediator_namespace.sign_transaction(&bytes),
    ];
    tw::topology_broadcast("sync", &[tw::signed(bytes, signatures)])
}

/// AT-O08 (the announcement side): a logical synchronizer upgrade is announced by the synchronizer's owners with a successor that is
/// greater, an upgrade time after the announcement takes effect, and no protocol version downgrade.
#[test]
fn an_upgrade_announcement_is_taken_only_when_it_follows_the_upgrade_rules() {
    let (store, keys) = store();
    let sync = format!("sync::{}", keys.synchronizer_namespace());
    let at = 10_000_000_000i64; // sequenced at 10 000 s
    let after = at + 3_600_000_000; // an hour later
    let text = |o: &[Outcome]| o[0].note().to_string();

    // a downgrade: a higher serial on a lower protocol version
    let o = store
        .accept_broadcast(&announcement(&keys, &format!("{sync}::36-1"), after, 1), at)
        .unwrap();
    assert!(matches!(o[0], Outcome::Refused(_)), "{:?}", o[0]);
    assert!(
        text(&o).contains("has a lower protocol version than the current synchronizer")
            && text(&o).contains("Protocol version downgrades are not allowed."),
        "{}",
        text(&o)
    );
    // an upgrade time that is not after the time the announcement takes effect
    let o = store
        .accept_broadcast(&announcement(&keys, &format!("{sync}::37-1"), at, 1), at)
        .unwrap();
    assert!(
        text(&o).contains("must be after the effective"),
        "{}",
        text(&o)
    );
    // a successor that is not greater than the current synchronizer (same serial and version)
    assert!(
        store.announced_upgrade().is_none(),
        "nothing was announced so far"
    );
    // a good announcement: the next serial on the same protocol version
    let o = store
        .accept_broadcast(&announcement(&keys, &format!("{sync}::37-1"), after, 1), at)
        .unwrap();
    assert!(o[0].is_in_force(), "{:?}", o[0]);
    let lsu = store.announced_upgrade().expect("announced");
    assert_eq!(lsu.successor.to_string(), format!("{sync}::37-1"));
    assert_eq!(lsu.upgrade_micros, after);
    // the same announcement again is fine; a successor that is not greater than the announced one is not
    let again = store
        .accept_broadcast(
            &announcement(&keys, &format!("{sync}::37-1"), after, 1),
            at + 1_000_000,
        )
        .unwrap();
    assert!(again[0].is_in_force(), "{:?}", again[0]);
    let o = store
        .accept_broadcast(
            &announcement(&keys, &format!("{sync}::37-1"), after + 1_000_000, 2),
            at + 2_000_000,
        )
        .unwrap();
    assert!(
        text(&o).contains("is not greater than prior synchronizer"),
        "changing the time needs a greater successor: {}",
        text(&o)
    );
    // a later announcement with a greater successor replaces it
    let o = store
        .accept_broadcast(
            &announcement(&keys, &format!("{sync}::37-2"), after, 2),
            at + 3_000_000,
        )
        .unwrap();
    assert!(o[0].is_in_force(), "{:?}", o[0]);
    assert_eq!(store.announced_upgrade().unwrap().successor.serial, 2);
    // the announcement is part of the state a joining member downloads
    assert!(store.snapshot().len() > 1);
}

/// AT-O08 (the snapshot side): the successor starts from the predecessor's topology state, and only when it is that state.
#[test]
fn a_successor_imports_the_predecessors_snapshot_only_when_it_is_that_snapshot_and_no_downgrade() {
    use canton_participant::topology_state::Psid;
    let (store, keys) = store();
    let sync = format!("sync::{}", keys.synchronizer_namespace());
    store
        .accept_broadcast(
            &announcement(&keys, &format!("{sync}::37-1"), 20_000_000_000, 1),
            10_000_000_000,
        )
        .unwrap();
    let (snapshot, hash) = (store.snapshot(), store.hash());
    let (pred, succ) = (
        Psid::parse(&format!("{sync}::37-0")).unwrap(),
        Psid::parse(&format!("{sync}::37-1")).unwrap(),
    );
    let imported = TopologyStore::import_snapshot(snapshot.clone(), &hash, &pred, &succ, "med")
        .expect("imports");
    assert_eq!(imported.hash(), hash, "the same state: the same hash");
    assert_eq!(imported.snapshot().len(), snapshot.len());
    for (a, b) in imported.snapshot().iter().zip(&snapshot) {
        assert_eq!(
            (a.sequenced_micros, a.valid_from_micros),
            (b.sequenced_micros, b.valid_from_micros),
            "the same times"
        );
    }
    // the announcement is part of the successor's state, but not an upgrade the successor is under (it is the one that led to it)
    assert!(imported.announced_upgrade().is_none());
    // a snapshot that is not the one the hash is of
    let mut tampered = snapshot.clone();
    tampered.pop();
    let why = TopologyStore::import_snapshot(tampered, &hash, &pred, &succ, "med")
        .err()
        .unwrap();
    assert!(why.contains("does not have the hash"), "{why}");
    // a downgrade, a successor that is not greater, another logical synchronizer
    let down = Psid::parse(&format!("{sync}::36-1")).unwrap();
    let why = TopologyStore::import_snapshot(snapshot.clone(), &hash, &pred, &down, "med")
        .err()
        .unwrap();
    assert!(
        why.contains("Protocol version downgrades are not allowed."),
        "{why}"
    );
    let same = Psid::parse(&format!("{sync}::37-0")).unwrap();
    let why = TopologyStore::import_snapshot(snapshot.clone(), &hash, &pred, &same, "med")
        .err()
        .unwrap();
    assert!(why.contains("is not greater than"), "{why}");
    let other = Psid::parse("other::1220ff::37-1").unwrap();
    let why = TopologyStore::import_snapshot(snapshot, &hash, &pred, &other, "med")
        .err()
        .unwrap();
    assert!(why.contains("is not of the synchronizer"), "{why}");
}

#[test]
fn the_state_is_handed_out_in_sequencing_order_whatever_the_clock_says() {
    let (store, keys) = store();
    let host = onboarded_participant(&store, &keys);
    store
        .accept_broadcast(&hosting_broadcast(&keys, &host, true), 5_000_000)
        .unwrap();
    // a registration stamped earlier than the last entry is kept at the last entry's time
    store.append(&[tw::signed(vec![1], vec![])], 4_000_000);
    let snapshot = store.snapshot();
    let times: Vec<i64> = snapshot.iter().map(|e| e.sequenced_micros).collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]), "{times:?}");
}

#[test]
fn bft_genesis_builds_multi_owner_store_and_members() {
    let s1 = crate::sequencer_identity::SequencerIdentity::generate("sequencer1");
    let s2 = crate::sequencer_identity::SequencerIdentity::generate("sequencer2");
    let m1 = crate::mediator_identity::MediatorIdentity::generate("mediator1");
    let m2 = crate::mediator_identity::MediatorIdentity::generate("mediator2");
    let (ns, txs) = build_bft_genesis(
        "da",
        &[&s1, &s2],
        &[&m1, &m2],
        &["sequencer1".into(), "sequencer2".into()],
        2,
    )
    .expect("bft genesis");
    let uid = format!("da::{ns}");
    let store = TopologyStore::from_genesis(&uid, 0, &s1.member(), txs).expect("store");
    assert_eq!(store.synchronizer_uid(), uid);
    let registered = store.registered_members();
    assert_eq!(registered.len(), 4);
    assert!(registered.iter().any(|r| r.member == s1.member()));
    assert!(registered.iter().any(|r| r.member == s2.member()));
    assert!(registered.iter().any(|r| r.member == m1.member()));
    assert!(registered.iter().any(|r| r.member == m2.member()));
    let groups = store.mediator_groups_at(i64::MAX);
    assert_eq!(groups[&0].active, vec![m1.uid(), m2.uid()]);
}

#[test]
fn r13g_sequencer_tracker_rejects_key_mapping_over_limit() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        public_key::Key as PublicKeyKind, PublicKey, SigningKeyUsage,
    };
    let (store, keys) = store();
    let p = tw::ParticipantIdentity::generate("r13g-over");
    let sync_uid = format!("sync::{}", keys.synchronizer_namespace());
    // Onboard only namespace delegation, then send an OwnerToKeyMapping with 20 signing + 1 encryption = 21 keys (> default 20).
    let extra_keys: Vec<tw::Ed25519Key> = (0..20u8)
        .map(|i| tw::Ed25519Key::from_seed([80 + i; 32]))
        .collect();
    let enc_key = tw::p256_encryption_key(p.encryption_spki());
    let mut keys_21: Vec<PublicKey> = extra_keys
        .iter()
        .map(|k| PublicKey {
            key: Some(PublicKeyKind::SigningPublicKey(k.public_key(&[
                SigningKeyUsage::Protocol,
                SigningKeyUsage::ProofOfOwnership,
            ]))),
        })
        .collect();
    keys_21.push(enc_key.clone());
    let otm_21 = tw::owner_to_key_mapping_at(&p.member(), keys_21.clone(), 1, 1);
    let mut sigs = vec![p.namespace_key.sign_transaction(&otm_21)];
    for k in &extra_keys {
        sigs.push(k.sign_transaction(&otm_21));
    }
    let onboarding_ns = &p.onboarding_transactions(&sync_uid)[..1];
    let o_ns = store
        .accept_broadcast(&tw::topology_broadcast("sync", onboarding_ns), 400_000)
        .unwrap();
    assert!(o_ns[0].is_in_force(), "{o_ns:?}");
    let o_21 = store
        .accept_broadcast(
            &tw::topology_broadcast("sync", &[tw::signed(otm_21, sigs)]),
            500_000,
        )
        .unwrap();
    assert!(
        matches!(&o_21[0], Outcome::Refused(msg) if msg.contains("At most 20 key(s)")),
        "expected sequencer TopologyStore to enforce default max_signing_keys_per_entity=20, got {:?}",
        o_21[0]
    );
    // Positive control: 19 signing + 1 encryption = 20 keys accepted.
    let mut keys_20 = keys_21[..19].to_vec();
    keys_20.push(enc_key);
    let otm_20 = tw::owner_to_key_mapping_at(&p.member(), keys_20, 1, 1);
    let mut sigs_20 = vec![p.namespace_key.sign_transaction(&otm_20)];
    for k in &extra_keys[..19] {
        sigs_20.push(k.sign_transaction(&otm_20));
    }
    let o_20 = store
        .accept_broadcast(
            &tw::topology_broadcast("sync", &[tw::signed(otm_20, sigs_20)]),
            600_000,
        )
        .unwrap();
    assert!(
        o_20[0].is_in_force(),
        "expected 20 keys accepted: {:?}",
        o_20[0]
    );
}

#[test]
fn r13g_load_topology_propagates_required_schemes_error() {
    use canton_participant::participant_runtime::{Config, Runtime};
    use canton_participant::sequencer_connect::{SequencerConnect, Token};
    use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_connect_service_server::{
        SequencerConnectService, SequencerConnectServiceServer,
    };
    use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_service_server::{
        SequencerService, SequencerServiceServer,
    };
    use canton_proto::com::digitalasset::canton::sequencer::api::v30::{
        sequencer_connect, AcknowledgeSignedRequest, AcknowledgeSignedResponse,
        DownloadTopologyStateForInitHashRequest, DownloadTopologyStateForInitHashResponse,
        DownloadTopologyStateForInitRequest, DownloadTopologyStateForInitResponse,
        GetTimeRequest, GetTimeResponse, GetTrafficStateForMemberRequest,
        GetTrafficStateForMemberResponse, SendAsyncRequest, SendAsyncResponse,
        SubscriptionRequest, SubscriptionResponse,
    };
    use canton_participant::view_conformance::Engine;
    use std::pin::Pin;
    use tokio_stream::Stream;
    use tonic::{Request, Response, Status};

    struct MockConnect;
    #[tonic::async_trait]
    impl SequencerConnectService for MockConnect {
        async fn handshake(
            &self,
            _: Request<sequencer_connect::HandshakeRequest>,
        ) -> Result<Response<sequencer_connect::HandshakeResponse>, Status> {
            Err(Status::unimplemented("unused"))
        }
        async fn get_synchronizer_id(
            &self,
            _: Request<sequencer_connect::GetSynchronizerIdRequest>,
        ) -> Result<Response<sequencer_connect::GetSynchronizerIdResponse>, Status> {
            Err(Status::unimplemented("unused"))
        }
        async fn get_synchronizer_parameters(
            &self,
            _: Request<sequencer_connect::GetSynchronizerParametersRequest>,
        ) -> Result<Response<sequencer_connect::GetSynchronizerParametersResponse>, Status>
        {
            Err(Status::unavailable("params down"))
        }
        async fn verify_active(
            &self,
            _: Request<sequencer_connect::VerifyActiveRequest>,
        ) -> Result<Response<sequencer_connect::VerifyActiveResponse>, Status> {
            Err(Status::unimplemented("unused"))
        }
        async fn register_onboarding_topology_transactions(
            &self,
            _: Request<sequencer_connect::RegisterOnboardingTopologyTransactionsRequest>,
        ) -> Result<
            Response<sequencer_connect::RegisterOnboardingTopologyTransactionsResponse>,
            Status,
        > {
            Err(Status::unimplemented("unused"))
        }
    }

    struct MockSeq;
    type S<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;
    #[tonic::async_trait]
    impl SequencerService for MockSeq {
        async fn get_time(
            &self,
            _: Request<GetTimeRequest>,
        ) -> Result<Response<GetTimeResponse>, Status> {
            Ok(Response::new(GetTimeResponse {
                sequencing_timestamp: Some(1_000),
            }))
        }
        async fn get_traffic_state_for_member(
            &self,
            _: Request<GetTrafficStateForMemberRequest>,
        ) -> Result<Response<GetTrafficStateForMemberResponse>, Status> {
            Err(Status::unimplemented("unused"))
        }
        async fn send_async(
            &self,
            _: Request<SendAsyncRequest>,
        ) -> Result<Response<SendAsyncResponse>, Status> {
            Ok(Response::new(SendAsyncResponse {}))
        }
        type SubscribeStream = S<SubscriptionResponse>;
        async fn subscribe(
            &self,
            _: Request<SubscriptionRequest>,
        ) -> Result<Response<Self::SubscribeStream>, Status> {
            Ok(Response::new(Box::pin(tokio_stream::empty())))
        }
        async fn acknowledge_signed(
            &self,
            _: Request<AcknowledgeSignedRequest>,
        ) -> Result<Response<AcknowledgeSignedResponse>, Status> {
            Ok(Response::new(AcknowledgeSignedResponse {}))
        }
        type DownloadTopologyStateForInitStream = S<DownloadTopologyStateForInitResponse>;
        async fn download_topology_state_for_init(
            &self,
            _: Request<DownloadTopologyStateForInitRequest>,
        ) -> Result<Response<Self::DownloadTopologyStateForInitStream>, Status> {
            Ok(Response::new(Box::pin(tokio_stream::empty())))
        }
        async fn download_topology_state_for_init_hash(
            &self,
            _: Request<DownloadTopologyStateForInitHashRequest>,
        ) -> Result<Response<DownloadTopologyStateForInitHashResponse>, Status> {
            Ok(Response::new(DownloadTopologyStateForInitHashResponse {
                topology_state_hash: Vec::new(),
            }))
        }
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let _server = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(
                tonic::transport::Server::builder()
                    .add_service(SequencerConnectServiceServer::new(MockConnect))
                    .add_service(SequencerServiceServer::new(MockSeq))
                    .serve(addr),
            )
    });
    let url = format!("http://{addr}");
    let mut client = None;
    for _ in 0..40 {
        if let Ok(c) = SequencerConnect::connect(&url) {
            client = Some(c);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let mut client = client.expect("connect to mock");
    let dar = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar");
    let id = tw::ParticipantIdentity::generate("r13g-err");
    let cfg = Config {
        member: id.member(),
        encryption_fingerprint: id.encryption_fingerprint(),
        encryption_secret: *id.encryption_secret(),
        submitter_keys: Vec::new(),
        mediator_keys: Vec::new(),
        peer_encryption_keys: BTreeMap::new(),
        hosted_parties: Vec::new(),
        timeouts: Default::default(),
        physical_synchronizer_id: "sync::1220ff::37-0".into(),
        follow_topology: true,
        topology_change_delay_micros: 250_000,
    };
    let mut rt = Runtime::open(cfg, Engine::load(&dar).unwrap(), None, 0).unwrap();
    let token = Token {
        token: vec![1, 2, 3],
        expires_at_seconds: i64::MAX / 2,
    };
    let err = rt.load_topology(&mut client, &token).unwrap_err();
    assert!(
        err.contains("params down"),
        "load_topology must not swallow required_schemes error: {err}"
    );
}
