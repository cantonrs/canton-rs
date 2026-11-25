//! The public API served over TLS (S-NET-037 part 18): a client that trusts the server's CA connects and a participant registers and
//! authenticates over it; a client that trusts another CA, or none, does not.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use canton_participant::topology_wire::ParticipantIdentity;
use canton_sequencer_server::{new_synchronizer, serve_with, ServeOptions};
use std::time::Duration;

/// A CA and a leaf certificate for `localhost` / 127.0.0.1 made with the `openssl` command (RSA: the rustls of this repository does not
/// read the explicit-parameter EC keys of LibreSSL). Returns `(ca, leaf certificate, leaf key)` as PEM, or `None` without `openssl`.
fn certificates(label: &str) -> Option<(String, String, String)> {
    let dir = std::env::temp_dir().join(format!("canton-rs-tls-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let write = |name: &str, text: &str| std::fs::write(dir.join(name), text).unwrap();
    write(
        "ca.cnf",
        "[req]\ndistinguished_name = dn\nprompt = no\nx509_extensions = v3_ca\n[dn]\nCN = canton-rs-test-ca\n[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n",
    );
    write(
        "leaf.cnf",
        "basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost,IP:127.0.0.1\n",
    );
    let run = |args: &[&str]| {
        std::process::Command::new("openssl")
            .args(args)
            .current_dir(&dir)
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca-key.pem",
        "-out",
        "ca.pem",
        "-days",
        "2",
        "-config",
        "ca.cnf",
    ])?;
    run(&[
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "tls-key.pem",
        "-out",
        "tls.csr",
        "-subj",
        "/CN=localhost",
    ])?;
    run(&[
        "pkcs8",
        "-topk8",
        "-nocrypt",
        "-in",
        "tls-key.pem",
        "-out",
        "tls-key8.pem",
    ])?;
    run(&[
        "x509",
        "-req",
        "-in",
        "tls.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca-key.pem",
        "-CAcreateserial",
        "-out",
        "tls-cert.pem",
        "-days",
        "2",
        "-extfile",
        "leaf.cnf",
    ])?;
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
    let out = (read("ca.pem"), read("tls-cert.pem"), read("tls-key8.pem"));
    let _ = std::fs::remove_dir_all(&dir);
    Some(out)
}

#[test]
fn a_participant_registers_and_authenticates_over_tls_and_a_client_that_does_not_trust_the_server_is_refused(
) {
    let Some((ca, certificate, key)) = certificates("a") else {
        eprintln!("NOT_RUN: openssl is not available");
        return;
    };
    let Some((other_ca, _, _)) = certificates("b") else {
        return;
    };
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = new_synchronizer("tlssync", "tl1");
    let served = config.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.spawn(async move {
        serve_with(
            address,
            served,
            ServeOptions {
                tls: Some((certificate, key)),
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
    let url = format!("https://localhost:{port}");
    let physical = config.physical_synchronizer_id();
    // a client that trusts the server's CA: handshake, onboarding, authentication
    let mut client =
        SequencerConnect::connect_tls(&url, &ca, "localhost").expect("connects over TLS");
    assert!(client.handshake(&[37], None).unwrap().success);
    let identity = ParticipantIdentity::generate("tls-member");
    client
        .register_onboarding(
            &identity.member(),
            &physical,
            identity.onboarding_transactions(&format!(
                "{}::{}",
                config.name, config.namespace_fingerprint
            )),
        )
        .unwrap();
    let challenge = client.challenge(&identity.member(), &[37]).unwrap();
    let signature = identity
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    client
        .authenticate(&identity.member(), &challenge.nonce, signature)
        .expect("the member authenticates over TLS");
    // a client that trusts only another CA refuses the server
    assert!(
        SequencerConnect::connect_tls(&url, &other_ca, "localhost").is_err(),
        "a certificate no trusted CA signed"
    );
    // a plain-text client does not get an answer from a TLS server
    assert!(
        SequencerConnect::connect(&format!("http://127.0.0.1:{port}"))
            .and_then(|mut c| c.handshake(&[37], None))
            .is_err(),
        "no plain-text calls on a TLS port"
    );
    drop(client);
    runtime.shutdown_background();
}

fn serve_tls(
    config: &canton_sequencer_server::SynchronizerConfig,
    certificate: String,
    key: String,
) -> (u16, tokio::runtime::Runtime) {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let served = config.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.spawn(async move {
        serve_with(
            address,
            served,
            ServeOptions {
                tls: Some((certificate, key)),
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
    (port, runtime)
}

/// AT-P04: a valid transport session is not a member's authority. Over TLS the server still wants the member's own proof.
#[test]
fn a_valid_tls_session_does_not_make_a_member_authenticated() {
    use canton_participant::sequencer_connect::ConnectError;
    let Some((ca, certificate, key)) = certificates("p04") else {
        eprintln!("NOT_RUN: openssl is not available");
        return;
    };
    let config = new_synchronizer("p04sync", "p4");
    let (port, runtime) = serve_tls(&config, certificate, key);
    let url = format!("https://localhost:{port}");
    let physical = config.physical_synchronizer_id();
    let uid = format!("{}::{}", config.name, config.namespace_fingerprint);
    let mut c = SequencerConnect::connect_tls(&url, &ca, "localhost").expect("a valid TLS session");
    let status = |e: ConnectError| match e {
        ConnectError::Status(s) => s,
        other => panic!("{other}"),
    };
    let honest = ParticipantIdentity::generate("p04-honest");
    c.register_onboarding(
        &honest.member(),
        &physical,
        honest.onboarding_transactions(&uid),
    )
    .unwrap();
    // 1. the session is valid, but a call that needs a member has none: no token
    let why = status(
        c.sequencer_time(&honest.member(), &physical, None)
            .expect_err("no token"),
    );
    assert!(why.contains("authentication token"), "{why}");
    // 2. a member nobody registered cannot get a token, however valid the session
    let nobody = ParticipantIdentity::generate("p04-nobody");
    let why = status(
        c.challenge(&nobody.member(), &[37])
            .expect_err("unregistered member"),
    );
    assert!(!why.is_empty(), "{why}");
    // 3. a registered member's identity with someone else's key: the challenge signature does not verify
    let challenge = c.challenge(&honest.member(), &[37]).unwrap();
    let forged = nobody
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let why = status(
        c.authenticate(&honest.member(), &challenge.nonce, forged)
            .expect_err("a forged proof"),
    );
    assert!(
        why.contains("Authentication failed")
            && why.contains("not signed by a key registered for sequencer authentication"),
        "{why}"
    );
    // 4. a challenge is used up by a wrong answer: the honest member asks again, proves itself, and its token is valid for it alone
    let challenge = c.challenge(&honest.member(), &[37]).unwrap();
    let signature = honest
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = c
        .authenticate(&honest.member(), &challenge.nonce, signature)
        .unwrap();
    assert!(c
        .sequencer_time(&honest.member(), &physical, Some(&token))
        .is_ok());
    let other = ParticipantIdentity::generate("p04-other");
    c.register_onboarding(
        &other.member(),
        &physical,
        other.onboarding_transactions(&uid),
    )
    .unwrap();
    let why = status(
        c.sequencer_time(&other.member(), &physical, Some(&token))
            .expect_err("another member's token"),
    );
    assert!(why.contains("not valid for this member"), "{why}");
    drop(c);
    runtime.shutdown_background();
}

/// AT-R03: a wrong hostname, a wrong CA or no TLS at all never falls back to a weaker session.
#[test]
fn a_wrong_hostname_ca_or_missing_tls_is_refused_without_a_fallback() {
    let Some((ca, certificate, key)) = certificates("r03") else {
        eprintln!("NOT_RUN: openssl is not available");
        return;
    };
    let Some((other_ca, _, _)) = certificates("r03b") else {
        return;
    };
    let config = new_synchronizer("r03sync", "r3");
    let (port, runtime) = serve_tls(&config, certificate, key);
    // the right CA and host: the session is made and the server answers
    let ok = SequencerConnect::connect_tls(&format!("https://localhost:{port}"), &ca, "localhost");
    assert!(ok.is_ok(), "{:?}", ok.err().map(|e| e.to_string()));
    // a hostname the certificate is not for
    let wrong_host =
        SequencerConnect::connect_tls(&format!("https://localhost:{port}"), &ca, "evil.example");
    assert!(
        wrong_host.is_err(),
        "a certificate for another name is refused"
    );
    // a CA that did not sign the certificate
    let wrong_ca =
        SequencerConnect::connect_tls(&format!("https://localhost:{port}"), &other_ca, "localhost");
    assert!(
        wrong_ca.is_err(),
        "a certificate no trusted CA signed is refused"
    );
    // no CA at all (the system's roots do not know the test CA)
    let no_ca =
        SequencerConnect::connect_tls(&format!("https://localhost:{port}"), "", "localhost");
    assert!(no_ca.is_err(), "no trusted CA: refused");
    // a plain-text client on the TLS port gets no answer, and the TLS client never retries in plain text
    let plain = SequencerConnect::connect(&format!("http://localhost:{port}"))
        .and_then(|mut c| c.handshake(&[37], None));
    assert!(plain.is_err(), "no plain-text answer on a TLS port");
    // a client certificate does not stand in for the member's proof: the server asks for none, and a session without the proof of a member
    // stays unauthenticated (see the AT-P04 test)
    drop(ok);
    runtime.shutdown_background();
}

struct MtlsCerts {
    ca: String,
    server_cert: String,
    server_key: String,
    client_cert: String,
    client_key: String,
}

fn mtls_certificates(label: &str) -> Option<MtlsCerts> {
    let dir = std::env::temp_dir().join(format!("canton-rs-mtls-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let write = |name: &str, text: &str| std::fs::write(dir.join(name), text).unwrap();
    write(
        "ca.cnf",
        "[req]\ndistinguished_name = dn\nprompt = no\nx509_extensions = v3_ca\n[dn]\nCN = canton-rs-mtls-ca\n[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n",
    );
    write(
        "server.cnf",
        "basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost,IP:127.0.0.1\n",
    );
    write(
        "client.cnf",
        "basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = clientAuth\n",
    );
    let run = |args: &[&str]| {
        std::process::Command::new("openssl")
            .args(args)
            .current_dir(&dir)
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca-key.pem",
        "-out",
        "ca.pem",
        "-days",
        "2",
        "-config",
        "ca.cnf",
    ])?;
    for (prefix, subj, cnf) in [
        ("server", "/CN=localhost", "server.cnf"),
        ("client", "/CN=participant-client", "client.cnf"),
    ] {
        run(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &format!("{prefix}-key.pem"),
            "-out",
            &format!("{prefix}.csr"),
            "-subj",
            subj,
        ])?;
        run(&[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            &format!("{prefix}-key.pem"),
            "-out",
            &format!("{prefix}-key8.pem"),
        ])?;
        run(&[
            "x509",
            "-req",
            "-in",
            &format!("{prefix}.csr"),
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca-key.pem",
            "-CAcreateserial",
            "-out",
            &format!("{prefix}-cert.pem"),
            "-days",
            "2",
            "-extfile",
            cnf,
        ])?;
    }
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
    let out = MtlsCerts {
        ca: read("ca.pem"),
        server_cert: read("server-cert.pem"),
        server_key: read("server-key8.pem"),
        client_cert: read("client-cert.pem"),
        client_key: read("client-key8.pem"),
    };
    let _ = std::fs::remove_dir_all(&dir);
    Some(out)
}

#[test]
fn mutual_tls_accepts_trusted_client_and_refuses_missing_or_untrusted_client_cert() {
    let Some(certs) = mtls_certificates("trusted") else {
        eprintln!("NOT_RUN: openssl is not available");
        return;
    };
    let Some(untrusted) = mtls_certificates("untrusted") else {
        return;
    };
    let config = new_synchronizer("mtlssync", "m1");
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let server_cert = certs.server_cert.clone();
    let server_key = certs.server_key.clone();
    let ca_for_server = certs.ca.clone();
    runtime.spawn(async move {
        serve_with(
            address,
            config,
            ServeOptions {
                tls: Some((server_cert, server_key)),
                tls_client_ca: Some(ca_for_server),
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
        std::thread::sleep(Duration::from_millis(50));
    }

    let endpoint = format!("https://localhost:{port}");
    // 1. Trusted client certificate succeeds and can complete sequencer handshake + onboarding.
    let mut ok = SequencerConnect::connect_mtls(
        &endpoint,
        &certs.ca,
        "localhost",
        &certs.client_cert,
        &certs.client_key,
    )
    .expect("mTLS connection with trusted client cert must succeed");
    let handshake = ok.handshake(&[37], None).expect("handshake over mTLS");
    assert!(handshake.success);

    // 2. Missing client certificate is refused by mTLS sequencer.
    let no_client_cert = SequencerConnect::connect_tls(&endpoint, &certs.ca, "localhost")
        .and_then(|mut c| c.handshake(&[37], None));
    assert!(
        no_client_cert.is_err(),
        "server-only TLS client without client cert must fail mTLS"
    );

    // 3. Untrusted client certificate signed by another CA is refused.
    let wrong_client_cert = SequencerConnect::connect_mtls(
        &endpoint,
        &certs.ca,
        "localhost",
        &untrusted.client_cert,
        &untrusted.client_key,
    )
    .and_then(|mut c| c.handshake(&[37], None));
    assert!(
        wrong_client_cert.is_err(),
        "client cert signed by untrusted CA must fail mTLS"
    );

    drop(ok);
    runtime.shutdown_background();
}
