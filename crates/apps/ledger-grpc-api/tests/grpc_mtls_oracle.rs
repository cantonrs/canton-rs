//! G11 B4 / C4 (S-G11-001): mutual TLS on the Ledger API compared with the official Canton 3.7.2 participant. `scripts/oracle-grpc-mtls.sh`
//! boots a participant whose Ledger API requires client certificates and sets `CANTON_RS_MTLS_PORT` and `CANTON_RS_MTLS_DIR` (the
//! certificates); this test starts the Rust gRPC Ledger API server with the same certificates and has the same clients call
//! `StateService/GetLedgerEnd` on both. Without the variables it does nothing (`NOT_RUN`).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::sync::Arc;

use ledger_grpc_api::dynamic::DynCodec;
use ledger_grpc_api::server::{serve_listener_tls, TlsServerOptions};
use ledger_json_api::ExecutionService;
use prost::Message;
use prost_reflect::prost_types::FileDescriptorSet;
use prost_reflect::{DescriptorPool, DynamicMessage};

/// How a call ended: `ok`, `connect-error` (the channel did not come up) or `rpc-error(<gRPC code>)`.
async fn outcome(port: u16, ca_pem: &str, client: Option<(&str, &str)>) -> String {
    let mut cfg = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(ca_pem))
        .domain_name("localhost");
    if let Some((cert, key)) = client {
        cfg = cfg.identity(tonic::transport::Identity::from_pem(cert, key));
    }
    let channel = match tonic::transport::Endpoint::from_shared(format!("https://localhost:{port}"))
        .unwrap()
        .tls_config(cfg)
        .unwrap()
        .connect()
        .await
    {
        Ok(c) => c,
        Err(_) => return "connect-error".into(),
    };
    let fds = FileDescriptorSet::decode(canton_proto::FILE_DESCRIPTOR_SET).unwrap();
    let pool = DescriptorPool::from_file_descriptor_set(fds).unwrap();
    let method = pool
        .get_service_by_name("com.daml.ledger.api.v2.StateService")
        .unwrap()
        .methods()
        .find(|m| m.name() == "GetLedgerEnd")
        .unwrap();
    let req = DynamicMessage::deserialize(method.input(), serde_json::json!({})).unwrap();
    let mut grpc = tonic::client::Grpc::new(channel);
    if grpc.ready().await.is_err() {
        return "connect-error".into();
    }
    let path: http::uri::PathAndQuery = "/com.daml.ledger.api.v2.StateService/GetLedgerEnd"
        .parse()
        .unwrap();
    match grpc
        .unary(
            tonic::Request::new(req),
            path,
            DynCodec::new(method.output()),
        )
        .await
    {
        Ok(_) => "ok".into(),
        Err(status) => format!("rpc-error({:?})", status.code()),
    }
}

#[tokio::test]
async fn the_rust_ledger_api_treats_client_certificates_as_the_official_participant_does() {
    let (Ok(official), Ok(dir)) = (
        std::env::var("CANTON_RS_MTLS_PORT"),
        std::env::var("CANTON_RS_MTLS_DIR"),
    ) else {
        eprintln!("NOT_RUN: CANTON_RS_MTLS_PORT is not set (scripts/oracle-grpc-mtls.sh)");
        return;
    };
    let official: u16 = official.parse().unwrap();
    let read = |name: &str| std::fs::read_to_string(std::path::Path::new(&dir).join(name)).unwrap();
    let (ca, other_ca) = (read("ca.pem"), read("other-ca.pem"));
    let (client_cert, client_key) = (read("client-cert.pem"), read("client-key8.pem"));
    let (stranger_cert, stranger_key) = (read("stranger-cert.pem"), read("stranger-key8.pem"));
    // the Rust server: the same server certificate, the same CA for clients, client certificates required
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rust = listener.local_addr().unwrap().port();
    let options = TlsServerOptions {
        cert_pem: read("server-cert.pem"),
        key_pem: read("server-key8.pem"),
        client_ca_pem: Some(ca.clone()),
    };
    tokio::spawn(async move {
        let _ = serve_listener_tls(Arc::new(ExecutionService::new()), listener, options).await;
    });
    #[allow(
        clippy::type_complexity,
        reason = "protocol or ledger hook signature uses an inline composite type"
    )] // [CANTON-NOTE: STYLE] a local table, typed once
    let cases: Vec<(&str, &str, Option<(&str, &str)>)> = vec![
        (
            "a client certificate the CA signed",
            &ca,
            Some((&client_cert, &client_key)),
        ),
        ("no client certificate", &ca, None),
        (
            "a client certificate another CA signed",
            &ca,
            Some((&stranger_cert, &stranger_key)),
        ),
        (
            "a server the client does not trust",
            &other_ca,
            Some((&client_cert, &client_key)),
        ),
    ];
    // the official participant may still be starting its Ledger API: wait until the trusted client gets through
    let mut first = String::new();
    for _ in 0..60 {
        first = outcome(official, &ca, Some((&client_cert, &client_key))).await;
        if first == "ok" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    assert_eq!(
        first, "ok",
        "the official participant answers a trusted client"
    );
    let mut differ = Vec::new();
    for (what, server_ca, client) in &cases {
        let theirs = outcome(official, server_ca, *client).await;
        let ours = outcome(rust, server_ca, *client).await;
        println!("MTLS {what}: official={theirs} rust={ours}");
        if theirs != ours {
            differ.push(format!("{what}: official {theirs}, rust {ours}"));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}
