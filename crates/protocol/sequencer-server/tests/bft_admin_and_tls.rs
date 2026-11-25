#![allow(clippy::unwrap_used, reason = "integration test")]
//! Integration tests for BFT Sequencer Administration & Pruning gRPC services (B7),
//! mutual-TLS P2P ordering, `Receive` stream shutdown (U-51), and fresh-join `CatchUp` from epoch 0 (U-52).

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use canton_participant::sequencer_connect::AuthKey;
use canton_participant::topology_wire::Ed25519Key;
use canton_proto::com::digitalasset::canton::admin::pruning::v30 as pruning_v30;
use canton_proto::com::digitalasset::canton::sequencer::admin::v30::{
    self as admin_v30, get_write_readiness_response::Readiness, peer_connection_status,
    peer_endpoint::Security, peer_endpoint_health_status,
    sequencer_bft_administration_service_client::SequencerBftAdministrationServiceClient,
    sequencer_bft_pruning_administration_service_client::SequencerBftPruningAdministrationServiceClient,
};
use canton_proto::com::digitalasset::canton::sequencer::api::v30::{
    sequencer_authentication::{AuthenticateRequest, ChallengeRequest},
    sequencer_authentication_service_client::SequencerAuthenticationServiceClient,
};
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft_v30;
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v31 as bft_v31;
use canton_sequencer_server::bft_admin::{BftAdminService, BftPruningAdminService};
use canton_sequencer_server::bft_p2p::{
    build_peer_manager, serve_with_options, BftClientTls, BftPeerConfig, BftServeOptions,
    BftServerTls, Consensus, OutputRequest,
};
use canton_sequencer_server::onboarding::Registry;
use canton_sequencer_server::sequencer_identity::SequencerIdentity;
use canton_sequencer_server::synchronizer_state::{
    build_bft_genesis, SynchronizerKeys, TopologyStore,
};
use canton_sequencer_server::{serve_connect_with_bft_admin, ConnectService, SynchronizerConfig};
use prost::Message as _;
use tokio::sync::{mpsc, Notify};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "canton-rs-{prefix}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

struct TestCertBundle {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_path: PathBuf,
    _dir: TempDir,
}

fn generate_mtls_certs(label: &str) -> TestCertBundle {
    let tmp = TempDir::new(label);
    let dir = &tmp.0;
    std::fs::write(
        dir.join("ca.cnf"),
        "[req]\ndistinguished_name = dn\nprompt = no\nx509_extensions = v3_ca\n[dn]\nCN = bft-test-ca\n[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("server.cnf"),
        "basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost,IP:127.0.0.1\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("client.cnf"),
        "basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = clientAuth\nsubjectAltName = DNS:localhost,IP:127.0.0.1\n",
    )
    .unwrap();

    let run = |args: &[&str]| {
        let out = std::process::Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("openssl must be installed to run BFT TLS integration tests");
        assert!(
            out.status.success(),
            "openssl {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };

    run(&[
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-config", "ca.cnf",
        "-keyout", "ca.key", "-out", "ca.crt",
    ]);
    run(&[
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=localhost",
        "-keyout",
        "server.key",
        "-out",
        "server.csr",
    ]);
    run(&[
        "x509",
        "-req",
        "-days",
        "2",
        "-in",
        "server.csr",
        "-CA",
        "ca.crt",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-extfile",
        "server.cnf",
        "-out",
        "server.crt",
    ]);
    run(&[
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=bft-peer",
        "-keyout",
        "client.key",
        "-out",
        "client.csr",
    ]);
    run(&[
        "x509",
        "-req",
        "-days",
        "2",
        "-in",
        "client.csr",
        "-CA",
        "ca.crt",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-extfile",
        "client.cnf",
        "-out",
        "client.crt",
    ]);

    TestCertBundle {
        ca_pem: std::fs::read_to_string(dir.join("ca.crt")).unwrap(),
        server_cert_pem: std::fs::read_to_string(dir.join("server.crt")).unwrap(),
        server_key_pem: std::fs::read_to_string(dir.join("server.key")).unwrap(),
        client_cert_pem: std::fs::read_to_string(dir.join("client.crt")).unwrap(),
        client_key_path: dir.join("client.key"),
        _dir: tmp,
    }
}

type TestClusterNode = (
    SequencerIdentity,
    SynchronizerConfig,
    Arc<Registry>,
    ConnectService,
);

fn setup_sequencer_cluster(names: &[&str]) -> (String, Vec<TestClusterNode>) {
    let identities: Vec<SequencerIdentity> = names
        .iter()
        .map(|n| SequencerIdentity::generate(n))
        .collect();
    let id_refs: Vec<&SequencerIdentity> = identities.iter().collect();
    let owner_names: Vec<String> = names.iter().map(|n| (*n).to_string()).collect();
    let (namespace, genesis_txs) =
        build_bft_genesis("bfttest", &id_refs, &[], &owner_names, 1).unwrap();

    let mut nodes = Vec::new();
    for id in identities {
        let keys = Arc::new(SynchronizerKeys::for_sequencer(
            id.namespace_key.seed(),
            id.signing_key.seed(),
            id.authentication_key.seed(),
        ));
        let cfg = SynchronizerConfig {
            name: "bfttest".into(),
            namespace_fingerprint: namespace.clone(),
            sequencer_name: id.name.clone(),
            sequencer_fingerprint: id.namespace().to_string(),
            keys,
            serial: 0,
        };
        let store = Arc::new(
            TopologyStore::from_genesis(
                &cfg.synchronizer_uid(),
                0,
                &id.member(),
                genesis_txs.clone(),
            )
            .unwrap(),
        );
        let registry = Arc::new(Registry::default());
        for member in store.registered_members() {
            registry.insert(member);
        }
        let connect =
            ConnectService::open_seeded(cfg.clone(), store, Arc::clone(&registry), None, None)
                .unwrap();
        nodes.push((id, cfg, registry, connect));
    }
    (namespace, nodes)
}

async fn connect_channel(addr: SocketAddr) -> Channel {
    let url = format!("http://{addr}");
    for _ in 0..40 {
        if let Ok(ch) = Channel::from_shared(url.clone()).unwrap().connect().await {
            return ch;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("admin server at {url} did not start in time");
}

#[tokio::test]
async fn bft_admin_peer_endpoints_topology_and_readiness() {
    let (_, mut nodes) = setup_sequencer_cluster(&["s1", "s2", "s3", "s4"]);
    let (id1, cfg1, reg1, connect1) = nodes.remove(0);
    let members: Vec<String> = reg1
        .members()
        .into_iter()
        .filter(|m| m.starts_with("SEQ::"))
        .collect();
    let consensus = Arc::new(Consensus::new(
        id1.member(),
        id1.signing_key.seed(),
        id1.signing_key.fingerprint.clone(),
        Some(4),
        Arc::clone(&reg1),
    ));
    consensus.set_nodes(members.clone());
    consensus.start_genesis_or_resume().unwrap();

    let stop = Arc::new(Notify::new());
    let peer_mgr = build_peer_manager(
        cfg1.physical_synchronizer_id(),
        Arc::clone(&reg1),
        &id1,
        ("127.0.0.1".into(), 39990, None),
        Some(Arc::clone(&consensus)),
        String::new(),
        None,
        Some(Arc::clone(&stop)),
    );
    let bft_admin = BftAdminService::new(Arc::clone(&peer_mgr), Arc::clone(&consensus), 4);
    let bft_pruning = BftPruningAdminService::new(None, Some(Arc::clone(&consensus)));

    let public_addr = free_addr();
    let admin_addr = free_addr();
    let srv_stop = Arc::clone(&stop);
    let srv_task = tokio::spawn(async move {
        serve_connect_with_bft_admin(
            public_addr,
            Some(admin_addr),
            cfg1,
            connect1,
            Some(srv_stop),
            Some((bft_admin, bft_pruning)),
        )
        .await
        .unwrap();
    });

    let channel = connect_channel(admin_addr).await;
    let mut client = SequencerBftAdministrationServiceClient::new(channel);

    // Initially no peers authenticated, while weak quorum for 4 nodes is 3 -> needs 2 other peers.
    let wr = client
        .get_write_readiness(admin_v30::GetWriteReadinessRequest {})
        .await
        .unwrap()
        .into_inner();
    match wr.readiness.unwrap() {
        Readiness::P2pNotReady(not_ready) => {
            let p2p = not_ready.p2p.unwrap();
            assert_eq!(p2p.authenticated_peers_count, 0);
            assert_eq!(p2p.required_quorum, 1);
        }
        other => panic!("expected P2pNotReady, got {other:?}"),
    }

    // Add + list + duplicate check + status + remove peer endpoint
    let unreachable_port = free_addr().port();
    let ep = admin_v30::PeerEndpoint {
        address: "127.0.0.1".into(),
        port: u32::from(unreachable_port),
        sequencer_id: None,
        security: Some(Security::PlainText(admin_v30::PlainTextPeerEndpoint {})),
    };
    let add1 = client
        .add_peer_endpoint(admin_v30::AddPeerEndpointRequest {
            endpoint: Some(ep.clone()),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(add1.added);
    let add_dup = client
        .add_peer_endpoint(admin_v30::AddPeerEndpointRequest { endpoint: Some(ep) })
        .await
        .unwrap()
        .into_inner();
    assert!(!add_dup.added);

    let list = client
        .list_configured_endpoints(admin_v30::ListConfiguredEndpointsRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(list.endpoints.len(), 1);
    assert_eq!(list.endpoints[0].port, u32::from(unreachable_port));

    let net_status = client
        .get_peer_network_status(admin_v30::GetPeerNetworkStatusRequest {
            endpoint_ids: vec![admin_v30::PeerEndpointId {
                address: "127.0.0.1".into(),
                port: 19999,
                tls: false,
            }],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(net_status.statuses.len(), 1);
    match net_status.statuses[0].status.as_ref().unwrap() {
        peer_connection_status::Status::PeerEndpointStatus(st) => {
            assert!(matches!(
                st.health.as_ref().unwrap().status.as_ref().unwrap().status,
                Some(peer_endpoint_health_status::Status::UnknownEndpoint(_))
            ));
        }
        other => panic!("unexpected status: {other:?}"),
    }

    let rem1 = client
        .remove_peer_endpoint(admin_v30::RemovePeerEndpointRequest {
            endpoint_id: Some(admin_v30::PeerEndpointId {
                address: "127.0.0.1".into(),
                port: u32::from(unreachable_port),
                tls: false,
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(rem1.removed);
    let rem2 = client
        .remove_peer_endpoint(admin_v30::RemovePeerEndpointRequest {
            endpoint_id: Some(admin_v30::PeerEndpointId {
                address: "127.0.0.1".into(),
                port: u32::from(unreachable_port),
                tls: false,
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!rem2.removed);

    // Ordering topology + performance metrics toggle
    let topo = client
        .get_ordering_topology(admin_v30::GetOrderingTopologyRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(topo.current_epoch, 0);
    assert_eq!(topo.sequencer_ids.len(), 4);
    assert_eq!(topo.leader_sequencer_ids.len(), 4);
    assert!(topo.blacklisted_sequencer_ids.is_empty());

    assert!(!consensus.performance_metrics_enabled());
    client
        .set_performance_metrics_enabled(admin_v30::SetPerformanceMetricsEnabledRequest {
            enabled: true,
        })
        .await
        .unwrap();
    assert!(consensus.performance_metrics_enabled());

    stop.notify_waiters();
    let _ = srv_task.await;
}

#[tokio::test]
async fn bft_pruning_admin_status_schedule_and_prune() {
    let (_, mut nodes) = setup_sequencer_cluster(&["s1"]);
    let (id1, cfg1, reg1, connect1) = nodes.remove(0);
    let consensus = Arc::new(Consensus::new(
        id1.member(),
        id1.signing_key.seed(),
        id1.signing_key.fingerprint.clone(),
        Some(4),
        Arc::clone(&reg1),
    ));
    let stop = Arc::new(Notify::new());
    let peer_mgr = build_peer_manager(
        cfg1.physical_synchronizer_id(),
        Arc::clone(&reg1),
        &id1,
        ("127.0.0.1".into(), 39991, None),
        Some(Arc::clone(&consensus)),
        String::new(),
        None,
        Some(Arc::clone(&stop)),
    );
    let bft_admin = BftAdminService::new(peer_mgr, Arc::clone(&consensus), 4);
    let bft_pruning = BftPruningAdminService::new(None, Some(Arc::clone(&consensus)));

    let public_addr = free_addr();
    let admin_addr = free_addr();
    let srv_stop = Arc::clone(&stop);
    let srv_task = tokio::spawn(async move {
        serve_connect_with_bft_admin(
            public_addr,
            Some(admin_addr),
            cfg1,
            connect1,
            Some(srv_stop),
            Some((bft_admin, bft_pruning)),
        )
        .await
        .unwrap();
    });

    let channel = connect_channel(admin_addr).await;
    let mut client = SequencerBftPruningAdministrationServiceClient::new(channel);

    // Modifying individual schedule fields before configuring a schedule fails cleanly.
    let err = client
        .set_cron(pruning_v30::SetCronRequest {
            cron: "0 0 * * * ?".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    client
        .set_bft_schedule(admin_v30::SetBftScheduleRequest {
            schedule: Some(admin_v30::BftOrdererPruningSchedule {
                schedule: Some(pruning_v30::PruningSchedule {
                    cron: "0 0 * * * ?".into(),
                    max_duration: Some(prost_types::Duration {
                        seconds: 30,
                        nanos: 0,
                    }),
                    retention: Some(prost_types::Duration {
                        seconds: 300,
                        nanos: 0,
                    }),
                }),
                min_blocks_to_keep: 50,
            }),
        })
        .await
        .unwrap();

    client
        .set_cron(pruning_v30::SetCronRequest {
            cron: "0 */10 * * * ?".into(),
        })
        .await
        .unwrap();
    client
        .set_max_duration(pruning_v30::SetMaxDurationRequest {
            max_duration: Some(prost_types::Duration {
                seconds: 45,
                nanos: 0,
            }),
        })
        .await
        .unwrap();
    client
        .set_retention(pruning_v30::SetRetentionRequest {
            retention: Some(prost_types::Duration {
                seconds: 600,
                nanos: 0,
            }),
        })
        .await
        .unwrap();
    client
        .set_min_blocks_to_keep(admin_v30::SetMinBlocksToKeepRequest {
            min_blocks_to_keep: 75,
        })
        .await
        .unwrap();

    let got_bft = client
        .get_bft_schedule(admin_v30::GetBftScheduleRequest {})
        .await
        .unwrap()
        .into_inner()
        .schedule
        .unwrap();
    assert_eq!(got_bft.min_blocks_to_keep, 75);
    assert_eq!(got_bft.schedule.as_ref().unwrap().cron, "0 */10 * * * ?");
    assert_eq!(
        got_bft
            .schedule
            .as_ref()
            .unwrap()
            .retention
            .unwrap()
            .seconds,
        600
    );

    client
        .clear_schedule(pruning_v30::ClearScheduleRequest {})
        .await
        .unwrap();
    assert!(client
        .get_schedule(pruning_v30::GetScheduleRequest {})
        .await
        .unwrap()
        .into_inner()
        .schedule
        .is_none());

    let st = client
        .bft_pruning_status(admin_v30::BftPruningStatusRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(st.latest_block, 0);
    let prune_resp = client
        .bft_prune(admin_v30::BftPruneRequest {
            retention: Some(prost_types::Duration {
                seconds: 10,
                nanos: 0,
            }),
            min_blocks_to_keep: 10,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!prune_resp.message.is_empty());

    stop.notify_waiters();
    let _ = srv_task.await;
}

#[tokio::test]
async fn bft_p2p_orders_blocks_over_mtls_and_closes_receive_stream_cleanly() {
    let certs = generate_mtls_certs("bft-mtls");
    let untrusted = generate_mtls_certs("bft-untrusted");

    let (_, mut nodes) = setup_sequencer_cluster(&["s1", "s2"]);
    let (id1, cfg1, reg1, connect1) = nodes.remove(0);
    let (id2, cfg2, reg2, _connect2) = nodes.remove(0);

    let members: Vec<String> = reg1
        .members()
        .into_iter()
        .filter(|m| m.starts_with("SEQ::"))
        .collect();
    let ordered1: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let ordered2: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let c1 = Arc::new(Consensus::new(
        id1.member(),
        id1.signing_key.seed(),
        id1.signing_key.fingerprint.clone(),
        Some(20),
        Arc::clone(&reg1),
    ));
    let c2 = Arc::new(Consensus::new(
        id2.member(),
        id2.signing_key.seed(),
        id2.signing_key.fingerprint.clone(),
        Some(20),
        Arc::clone(&reg2),
    ));
    c1.set_nodes(members.clone());
    c2.set_nodes(members.clone());
    {
        let out = Arc::clone(&ordered1);
        c1.set_sink(Arc::new(move |req: OutputRequest| {
            out.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&req.body).into_owned());
        }));
    }
    {
        let out = Arc::clone(&ordered2);
        c2.set_sink(Arc::new(move |req: OutputRequest| {
            out.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&req.body).into_owned());
        }));
    }
    c1.start_genesis_or_resume().unwrap();
    c2.start_genesis_or_resume().unwrap();

    let p2p_addr1 = free_addr();
    let p2p_addr2 = free_addr();
    let stop = Arc::new(Notify::new());

    let client_tls = BftClientTls {
        custom_server_trust_pem: Some(certs.ca_pem.as_bytes().to_vec()),
        client_cert_chain_pem: Some(certs.client_cert_pem.as_bytes().to_vec()),
        client_private_key_file: Some(certs.client_key_path.display().to_string()),
    };
    let server_tls = BftServerTls {
        cert_pem: certs.server_cert_pem.clone(),
        key_pem: certs.server_key_pem.clone(),
        client_ca_pem: Some(certs.ca_pem.clone()),
    };

    let pm1 = build_peer_manager(
        cfg1.physical_synchronizer_id(),
        Arc::clone(&reg1),
        &id1,
        (
            "127.0.0.1".into(),
            u32::from(p2p_addr1.port()),
            Some(client_tls.clone()),
        ),
        Some(Arc::clone(&c1)),
        String::new(),
        None,
        Some(Arc::clone(&stop)),
    );
    let pm2 = build_peer_manager(
        cfg2.physical_synchronizer_id(),
        Arc::clone(&reg2),
        &id2,
        (
            "127.0.0.1".into(),
            u32::from(p2p_addr2.port()),
            Some(client_tls.clone()),
        ),
        Some(Arc::clone(&c2)),
        String::new(),
        None,
        Some(Arc::clone(&stop)),
    );
    let bft_admin1 = BftAdminService::new(Arc::clone(&pm1), Arc::clone(&c1), 20);
    let bft_pruning1 = BftPruningAdminService::new(None, Some(Arc::clone(&c1)));
    let pub_addr1 = free_addr();
    let adm_addr1 = free_addr();

    let srv1_admin = tokio::spawn({
        let stop = Arc::clone(&stop);
        async move {
            serve_connect_with_bft_admin(
                pub_addr1,
                Some(adm_addr1),
                cfg1.clone(),
                connect1,
                Some(stop),
                Some((bft_admin1, bft_pruning1)),
            )
            .await
            .unwrap();
        }
    });

    let member1 = id1.member();
    let sign_seed1 = id1.signing_key.seed();
    let fp1 = id1.signing_key.fingerprint.clone();
    let member2 = id2.member();
    let auth_seed2 = id2.authentication_key.seed();
    let sign_seed2 = id2.signing_key.seed();
    let fp2 = id2.signing_key.fingerprint.clone();

    let p2p1 = tokio::spawn({
        let stop = Arc::clone(&stop);
        let reg1 = Arc::clone(&reg1);
        let c1 = Arc::clone(&c1);
        let pm1 = Arc::clone(&pm1);
        let server_tls = server_tls.clone();
        let client_tls = client_tls.clone();
        let physical = cfg2.physical_synchronizer_id();
        async move {
            serve_with_options(
                p2p_addr1,
                physical,
                reg1,
                &id1,
                (
                    "127.0.0.1".into(),
                    u32::from(p2p_addr1.port()),
                    Some(client_tls.clone()),
                ),
                Some(c1),
                String::new(),
                BftServeOptions {
                    peers: vec![BftPeerConfig {
                        address: "127.0.0.1".into(),
                        port: u32::from(p2p_addr2.port()),
                        tls: Some(client_tls.clone()),
                    }],
                    server_tls: Some(server_tls),
                    default_client_tls: Some(client_tls),
                    peer_manager: Some(pm1),
                    ord_store: None,
                    shutdown: Some(stop),
                },
            )
            .await
            .unwrap();
        }
    });

    let p2p2 = tokio::spawn({
        let stop = Arc::clone(&stop);
        let reg2 = Arc::clone(&reg2);
        let c2 = Arc::clone(&c2);
        let server_tls = server_tls.clone();
        let client_tls = client_tls.clone();
        let pm2_srv = Arc::clone(&pm2);
        let physical = cfg2.physical_synchronizer_id();
        async move {
            serve_with_options(
                p2p_addr2,
                physical,
                reg2,
                &id2,
                (
                    "127.0.0.1".into(),
                    u32::from(p2p_addr2.port()),
                    Some(client_tls.clone()),
                ),
                Some(c2),
                String::new(),
                BftServeOptions {
                    peers: vec![BftPeerConfig {
                        address: "127.0.0.1".into(),
                        port: u32::from(p2p_addr1.port()),
                        tls: Some(client_tls.clone()),
                    }],
                    server_tls: Some(server_tls),
                    default_client_tls: Some(client_tls),
                    peer_manager: Some(pm2_srv),
                    ord_store: None,
                    shutdown: Some(stop),
                },
            )
            .await
            .unwrap();
        }
    });

    // Wait for mutual TLS write readiness (`Ready`) and bidirectional mTLS authentication on both nodes.
    let admin_ch = connect_channel(adm_addr1).await;
    let mut admin_client = SequencerBftAdministrationServiceClient::new(admin_ch);
    let mut became_ready = false;
    for _ in 0..80 {
        let wr = admin_client
            .get_write_readiness(admin_v30::GetWriteReadinessRequest {})
            .await
            .unwrap()
            .into_inner();
        let net = admin_client
            .get_peer_network_status(admin_v30::GetPeerNetworkStatusRequest {
                endpoint_ids: vec![admin_v30::PeerEndpointId {
                    address: "127.0.0.1".into(),
                    port: u32::from(p2p_addr2.port()),
                    tls: true,
                }],
            })
            .await
            .unwrap()
            .into_inner();
        let outgoing_auth = net.statuses.iter().any(|s| {
            matches!(
                &s.status,
                Some(peer_connection_status::Status::PeerEndpointStatus(st))
                    if matches!(
                        st.health.as_ref().and_then(|h| h.status.as_ref()).and_then(|hs| hs.status.as_ref()),
                        Some(peer_endpoint_health_status::Status::Authenticated(_))
                    )
            )
        });
        if matches!(wr.readiness, Some(Readiness::Ready(_)))
            && outgoing_auth
            && pm2.authenticated_peers_count() >= 1
        {
            became_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(became_ready, "2-node mTLS cluster never reached Ready");

    // Verify untrusted client cert / CA is rejected on the P2P mTLS port.
    let bad_key = std::fs::read_to_string(&untrusted.client_key_path).unwrap();
    let bad_ep = Endpoint::from_shared(format!("https://127.0.0.1:{}", p2p_addr1.port()))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("127.0.0.1")
                .ca_certificate(Certificate::from_pem(&untrusted.ca_pem))
                .identity(Identity::from_pem(&untrusted.client_cert_pem, bad_key)),
        )
        .unwrap();
    assert!(bad_ep.connect().await.is_err());

    // Submit a request on s1 and verify both nodes decide & deliver it over mTLS!
    c1.order_request("send", "msg-mtls-1", b"mtls-payload-1".to_vec());
    let mut both_ordered = false;
    for _ in 0..80 {
        let l1 = ordered1.lock().unwrap().clone();
        let l2 = ordered2.lock().unwrap().clone();
        if l1.iter().any(|s| s == "mtls-payload-1") && l2.iter().any(|s| s == "mtls-payload-1") {
            both_ordered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        both_ordered,
        "mTLS BFT cluster did not order request to both sinks"
    );

    // Verify U-51: closing outbound `Receive` request stream immediately terminates server response stream.
    let client_key = std::fs::read_to_string(&certs.client_key_path).unwrap();
    let p2p_ch = Endpoint::from_shared(format!("https://127.0.0.1:{}", p2p_addr1.port()))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("127.0.0.1")
                .ca_certificate(Certificate::from_pem(&certs.ca_pem))
                .identity(Identity::from_pem(&certs.client_cert_pem, client_key)),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let physical = cfg2.physical_synchronizer_id();
    let auth_key2 = Ed25519Key::from_seed(auth_seed2);
    let mut auth_cli = SequencerAuthenticationServiceClient::new(p2p_ch.clone());
    let challenge = auth_cli
        .challenge(ChallengeRequest {
            member: member2.clone(),
            member_protocol_versions: vec![canton_sequencer_server::PROTOCOL_VERSION],
            client_version: "u51-test".into(),
        })
        .await
        .unwrap()
        .into_inner();
    let sig = auth_key2.sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = auth_cli
        .authenticate(AuthenticateRequest {
            member: member2.clone(),
            signature: Some(sig),
            nonce: challenge.nonce,
        })
        .await
        .unwrap()
        .into_inner()
        .token;

    let (req_tx, req_rx) = mpsc::channel::<bft_v30::BftOrderingMessage>(4);
    req_tx
        .send(bft_v30::BftOrderingMessage {
            trace_context: String::new(),
            body: Some(bft_v30::BftOrderingMessageBody {
                message: Some(
                    bft_v30::bft_ordering_message_body::Message::ConnectionOpened(
                        bft_v30::ConnectionOpened {},
                    ),
                ),
            }),
            sent_by: member2.clone(),
            sent_at: None,
        })
        .await
        .unwrap();
    let mut req = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(req_rx));
    let md = req.metadata_mut();
    md.insert("synchronizerid", physical.parse().unwrap());
    md.insert("memberid", member2.parse().unwrap());
    md.insert_bin(
        "authtoken-bin",
        tonic::metadata::MetadataValue::from_bytes(&token),
    );
    let adv_ep = BftPeerConfig {
        address: "127.0.0.1".into(),
        port: u32::from(p2p_addr2.port()),
        tls: Some(client_tls),
    }
    .to_proto(None);
    md.insert_bin(
        "cantonbft-p2p-endpoint-bin",
        tonic::metadata::MetadataValue::from_bytes(&adv_ep.encode_to_vec()),
    );

    let mut bft_cli = bft_v30::bft_ordering_service_client::BftOrderingServiceClient::new(p2p_ch);
    let mut resp_stream = bft_cli.receive(req).await.unwrap().into_inner();
    drop(req_tx);
    let closed_early = tokio::time::timeout(Duration::from_secs(2), resp_stream.message())
        .await
        .expect("U-51: server Receive stream must close promptly when client inbound ends")
        .unwrap();
    assert!(
        closed_early.is_none(),
        "expected clean EOF from closed Receive stream"
    );

    stop.notify_waiters();
    let _ = tokio::join!(srv1_admin, p2p1, p2p2);

    // Verify U-52: fresh node with NO persisted policy receiving epoch 2 PrePrepare enters CatchUp from epoch 0
    // and advances past pruned empty state-transfer responses to join epoch 2.
    let fresh = Consensus::new(member1, sign_seed1, fp1, Some(2), Arc::clone(&reg1));
    fresh.set_nodes(members.clone());
    assert!(!fresh.is_started());

    let sk2 = ed25519_dalek::SigningKey::from_bytes(&sign_seed2);
    let sign_consensus = |msg: bft_v30::ConsensusMessage| {
        let ev = canton_bft_orderer::wire::wrap_versioned(30, &msg.encode_to_vec());
        let sig = canton_bft_orderer::wire::sign_message(
            canton_bft_orderer::wire::AuthenticatedMessageType::BftSignedConsensusMessage,
            &member2,
            &ev,
            &sk2,
            &fp2,
        )
        .unwrap();
        bft_v30::SignedMessage {
            message: ev,
            from: member2.clone(),
            signature: Some(sig),
        }
    };
    let ep1_commit = sign_consensus(bft_v30::ConsensusMessage {
        block_metadata: Some(bft_v30::BlockMetadata {
            epoch_number: 1,
            block_number: 3,
        }),
        view_number: 0,
        from: member2.clone(),
        message: Some(bft_v30::consensus_message::Message::Commit(
            bft_v30::Commit::default(),
        )),
    });
    let ep2_pp = sign_consensus(bft_v30::ConsensusMessage {
        block_metadata: Some(bft_v30::BlockMetadata {
            epoch_number: 2,
            block_number: 4,
        }),
        view_number: 0,
        from: member2.clone(),
        message: Some(bft_v30::consensus_message::Message::PrePrepare(
            bft_v30::PrePrepare {
                block: Some(bft_v30::OrderingBlock { proofs: vec![] }),
                bft_time_canonical_commit_set: Some(bft_v30::CanonicalCommitSet {
                    canonical_commits: vec![ep1_commit],
                }),
            },
        )),
    });
    fresh.on_message(ep2_pp).unwrap();
    assert!(
        !fresh.is_started(),
        "must wait in CatchUp before epoch 2 starts"
    );

    // Advance epoch 0 -> 1 -> 2 via empty pruned state-transfer responses
    let empty_st_body = bft_v31::StateTransferMessage {
        message: Some(bft_v31::state_transfer_message::Message::BlockResponse(
            bft_v30::RetransmissionResponse {
                commit_certificates: vec![],
            },
        )),
    };
    let st_ev = canton_bft_orderer::wire::wrap_versioned(31, &empty_st_body.encode_to_vec());
    let st_sig = canton_bft_orderer::wire::sign_message(
        canton_bft_orderer::wire::AuthenticatedMessageType::BftSignedStateTransferMessage,
        &member2,
        &st_ev,
        &sk2,
        &fp2,
    )
    .unwrap();
    assert!(canton_sequencer_server::bft_p2p::verify_signed_message(
        &reg1,
        canton_bft_orderer::wire::AuthenticatedMessageType::BftSignedStateTransferMessage,
        &bft_v30::SignedMessage {
            message: st_ev,
            from: member2,
            signature: Some(st_sig),
        }
    )
    .is_ok());

    fresh.on_empty_transferred_epoch().unwrap();
    assert!(!fresh.is_started(), "epoch 1 still needs transfer");
    fresh.on_empty_transferred_epoch().unwrap();
    assert!(
        fresh.is_started(),
        "U-52: fresh node must join epoch 2 after empty catchup"
    );
    assert_eq!(fresh.ordering_topology().0, 2);
}
