//! The Rust sequencer's connect API, called by this repository's own client (the JVM participant's view of it is
//! `scripts/verify-rust-sequencer.sh`).
use canton_participant::sequencer_connect::SequencerConnect;
mod common;
use canton_sequencer_server::PROTOCOL_VERSION;

#[test]
fn the_server_answers_the_unauthenticated_calls_a_participant_makes_first() {
    let (config, url) = common::start();
    let mut c = SequencerConnect::connect(&url).unwrap();
    // the handshake: a client that speaks the server's version is accepted, one that does not is not
    let ok = c.handshake(&[PROTOCOL_VERSION], None).unwrap();
    assert_eq!(ok.server_protocol_version, PROTOCOL_VERSION);
    assert!(ok.success);
    let other = c.handshake(&[34, 35], None).unwrap();
    assert!(
        !other.success,
        "a client that does not speak the version is not accepted"
    );
    let too_new = c
        .handshake(&[PROTOCOL_VERSION], Some(PROTOCOL_VERSION + 1))
        .unwrap();
    assert!(
        !too_new.success,
        "a minimum above the server's version is not accepted"
    );
    // the identity
    let id = c.synchronizer_id().unwrap();
    assert_eq!(
        id.physical_synchronizer_id,
        config.physical_synchronizer_id()
    );
    assert_eq!(id.sequencer_uid, config.sequencer_uid());
    assert!(id.physical_synchronizer_id.ends_with("::37-0"));
    // the parameters: version 37 is the v32 form, with the required crypto and the topology change delay of the official node
    let (version, text) = c.synchronizer_parameters().unwrap();
    assert_eq!(version, "v32");
    for needed in [
        "protocol_version: 37",
        "required_hash_algorithms: [Sha256]",
        "required_symmetric_key_schemes: [Aes128gcm]",
        "topology_change_delay: Some(Duration { seconds: 0, nanos: 250000000 })",
    ] {
        assert!(text.contains(needed), "{needed} missing in {text}");
    }
    // an anonymous VerifyActive is refused like the official node does
    let why = c.is_active().unwrap_err().to_string();
    assert!(
        why.contains("Unable to find participant id in gRPC context"),
        "{why}"
    );
    // a member that names itself and that nobody onboarded is not active
    assert!(!c
        .is_active_as(
            "PAR::nobody::1220aa",
            &config.physical_synchronizer_id(),
            None
        )
        .unwrap());
}

/// C-2: the Rust sequencer requires of its members only the encryption schemes it can produce (no RSA-OAEP, no RSA-2048 keys),
/// and its parameters pass the crypto handshake a participant runs when it connects.
#[test]
fn the_required_encryption_schemes_are_the_ones_the_rust_nodes_can_produce() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        EncryptionAlgorithmSpec, EncryptionKeySpec,
    };
    let (_config, url) = common::start();
    let mut c = SequencerConnect::connect(&url).unwrap();
    let required = c.required_schemes().unwrap();
    assert_eq!(
        required.encryption_algorithms,
        [EncryptionAlgorithmSpec::EciesHkdfHmacSha256Aes128cbc as i32].into()
    );
    assert_eq!(
        required.encryption_keys,
        [EncryptionKeySpec::EcP256 as i32].into()
    );
    assert_eq!(
        canton_participant::crypto_handshake::validate(&required),
        Ok(())
    );
}

/// The health service tells the truth: SERVING while it runs, NOT_SERVING to the watchers once it is asked to stop, and NOT_FOUND for a
/// service it does not have.
#[test]
fn the_health_service_reports_serving_then_not_serving_when_the_server_is_asked_to_stop() {
    use canton_sequencer_server::{health, serve_with, ServeOptions};
    use health::health_check_response::ServingStatus;
    use health::health_client::HealthClient;
    use tokio_stream::StreamExt;
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = canton_sequencer_server::new_synchronizer("healthsync", "hs1");
    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let served = runtime.spawn(serve_with(
        address,
        config,
        ServeOptions {
            shutdown: Some(std::sync::Arc::clone(&stop)),
            ..Default::default()
        },
    ));
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    runtime.block_on(async {
        let channel = tonic::transport::Channel::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = HealthClient::new(channel);
        let check = |service: &str| health::HealthCheckRequest {
            service: service.to_string(),
        };
        assert_eq!(
            client.check(check("")).await.unwrap().into_inner().status,
            ServingStatus::Serving as i32
        );
        // the name the official participant's connection pool watches
        let watched = client
            .watch(check("sequencer-health-check-service"))
            .await
            .unwrap()
            .into_inner()
            .next()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(watched.status, ServingStatus::Serving as i32);
        let sequencer = "com.digitalasset.canton.sequencer.api.v30.SequencerService";
        assert_eq!(
            client
                .check(check(sequencer))
                .await
                .unwrap()
                .into_inner()
                .status,
            ServingStatus::Serving as i32
        );
        assert_eq!(
            client
                .check(check("no.such.Service"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
        let mut watch = client.watch(check("")).await.unwrap().into_inner();
        assert_eq!(
            watch.next().await.unwrap().unwrap().status,
            ServingStatus::Serving as i32
        );
        // asked to stop: the watcher is told, then the server ends
        stop.notify_one();
        let next = tokio::time::timeout(std::time::Duration::from_secs(3), watch.next())
            .await
            .expect("the watcher is told within a moment")
            .unwrap()
            .unwrap();
        assert_eq!(next.status, ServingStatus::NotServing as i32);
        tokio::time::timeout(std::time::Duration::from_secs(5), served)
            .await
            .expect("the server stops")
            .unwrap()
            .unwrap();
    });
    runtime.shutdown_background();
}
