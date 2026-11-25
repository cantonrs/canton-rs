//! S-NET-039: Ledger API v2 gRPC server TLS & mutual TLS (mTLS) verification.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::sync::Arc;

use ledger_grpc_api::dynamic::DynCodec;
use ledger_grpc_api::server::{serve_listener_tls, TlsServerOptions};
use ledger_json_api::ExecutionService;
use prost::Message;
use prost_reflect::prost_types::FileDescriptorSet;
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};

struct TestCerts {
    ca: String,
    server_cert: String,
    server_key: String,
    client_cert: String,
    client_key: String,
}

fn generate_certs(label: &str) -> Option<TestCerts> {
    let dir = std::env::temp_dir().join(format!("grpc-tls-test-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let write = |name: &str, text: &str| std::fs::write(dir.join(name), text).unwrap();
    write(
        "ca.cnf",
        "[req]\ndistinguished_name = dn\nprompt = no\nx509_extensions = v3_ca\n[dn]\nCN = grpc-test-ca\n[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n",
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
        ("client", "/CN=grpc-client", "client.cnf"),
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
    let out = TestCerts {
        ca: read("ca.pem"),
        server_cert: read("server-cert.pem"),
        server_key: read("server-key8.pem"),
        client_cert: read("client-cert.pem"),
        client_key: read("client-key8.pem"),
    };
    let _ = std::fs::remove_dir_all(&dir);
    Some(out)
}

async fn get_ledger_end(
    port: u16,
    ca_pem: &str,
    client_identity: Option<(&str, &str)>,
) -> Result<serde_json::Value, String> {
    let mut cfg = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(ca_pem))
        .domain_name("localhost");
    if let Some((cert, key)) = client_identity {
        cfg = cfg.identity(tonic::transport::Identity::from_pem(cert, key));
    }
    let channel = tonic::transport::Endpoint::from_shared(format!("https://localhost:{port}"))
        .map_err(|e| e.to_string())?
        .tls_config(cfg)
        .map_err(|e| e.to_string())?
        .connect()
        .await
        .map_err(|e| format!("{e:?}"))?;

    let fds = FileDescriptorSet::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("fds");
    let pool = DescriptorPool::from_file_descriptor_set(fds).expect("pool");
    let service = pool
        .get_service_by_name("com.daml.ledger.api.v2.StateService")
        .expect("StateService");
    let method = service
        .methods()
        .find(|m| m.name() == "GetLedgerEnd")
        .expect("GetLedgerEnd");
    let req = DynamicMessage::deserialize(method.input(), serde_json::json!({})).expect("req");
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.map_err(|e| e.to_string())?;
    let path: http::uri::PathAndQuery = "/com.daml.ledger.api.v2.StateService/GetLedgerEnd"
        .parse()
        .unwrap();
    let resp = grpc
        .unary(
            tonic::Request::new(req),
            path,
            DynCodec::new(method.output()),
        )
        .await
        .map_err(|e| e.to_string())?;
    let opts = SerializeOptions::new()
        .skip_default_fields(false)
        .stringify_64_bit_integers(false);
    resp.into_inner()
        .serialize_with_options(serde_json::value::Serializer, &opts)
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn grpc_server_tls_and_mtls_enforce_certificates() {
    let Some(certs) = generate_certs("primary") else {
        eprintln!("NOT_RUN: openssl is not available");
        return;
    };
    let Some(untrusted) = generate_certs("untrusted") else {
        return;
    };

    // 1. Server-only TLS mode accepts a client that trusts the server CA.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_port = listener.local_addr().unwrap().port();
    let ledger = Arc::new(ExecutionService::new());
    let server_opts = TlsServerOptions {
        cert_pem: certs.server_cert.clone(),
        key_pem: certs.server_key.clone(),
        client_ca_pem: None,
    };
    let _tls_task = tokio::spawn(async move {
        let _ = serve_listener_tls(ledger, listener, server_opts).await;
    });
    let end = get_ledger_end(tls_port, &certs.ca, None)
        .await
        .expect("server-only TLS GetLedgerEnd should succeed");
    assert!(end.get("offset").is_some(), "unexpected body: {end}");
    assert!(
        get_ledger_end(tls_port, &untrusted.ca, None).await.is_err(),
        "untrusted server CA must fail client verification"
    );

    // 2. Mutual TLS mode requires a client cert signed by client_ca_pem.
    let mtls_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mtls_port = mtls_listener.local_addr().unwrap().port();
    let ledger_mtls = Arc::new(ExecutionService::new());
    let mtls_opts = TlsServerOptions {
        cert_pem: certs.server_cert,
        key_pem: certs.server_key,
        client_ca_pem: Some(certs.ca.clone()),
    };
    let _mtls_task = tokio::spawn(async move {
        let _ = serve_listener_tls(ledger_mtls, mtls_listener, mtls_opts).await;
    });
    let ok = get_ledger_end(
        mtls_port,
        &certs.ca,
        Some((&certs.client_cert, &certs.client_key)),
    )
    .await
    .expect("mTLS GetLedgerEnd with trusted client cert must succeed");
    assert!(ok.get("offset").is_some(), "unexpected mTLS body: {ok}");
    assert!(
        get_ledger_end(mtls_port, &certs.ca, None).await.is_err(),
        "mTLS must reject client without client certificate"
    );
    assert!(
        get_ledger_end(
            mtls_port,
            &certs.ca,
            Some((&untrusted.client_cert, &untrusted.client_key))
        )
        .await
        .is_err(),
        "mTLS must reject client certificate signed by wrong CA"
    );
}
