//! The limits of the Ledger API's gRPC listener (internal review A-16, L-2): Canton's `ledger-api.max-inbound-message-size` (10 MiB, above
//! tonic's own 4 MiB) and protobuf's nesting bound (grpc-java parses a request with `CodedInputStream`'s default limit of 100).
#![allow(clippy::unwrap_used, reason = "integration test")]

use std::sync::Arc;

use ledger_grpc_api::{dynamic::DynCodec, server::serve_listener};
use ledger_json_api::ExecutionService;
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde_json::{json, Value};
use tonic::{client::Grpc, Code, Request};

const UPLOAD: (&str, &str) = (
    "com.daml.ledger.api.v2.admin.PackageManagementService",
    "UploadDarFile",
);
const SUBMIT: (&str, &str) = ("com.daml.ledger.api.v2.CommandService", "SubmitAndWait");

fn method((service, name): (&str, &str)) -> prost_reflect::MethodDescriptor {
    DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET)
        .unwrap()
        .get_service_by_name(service)
        .and_then(|s| s.methods().find(|m| m.name() == name))
        .unwrap()
}

async fn call(addr: std::net::SocketAddr, target: (&str, &str), body: Value) -> Status {
    let msg = DynamicMessage::deserialize(method(target).input(), body).unwrap();
    call_with(addr, target, msg).await
}

async fn call_with(
    addr: std::net::SocketAddr,
    (service, name): (&str, &str),
    msg: DynamicMessage,
) -> Status {
    let method = method((service, name));
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc = Grpc::new(channel);
    grpc.ready().await.unwrap();
    let path = format!("/{service}/{name}").parse().unwrap();
    match grpc
        .unary(Request::new(msg), path, DynCodec::new(method.output()))
        .await
    {
        Ok(_) => Status(Code::Ok, String::new()),
        Err(s) => Status(s.code(), s.message().to_string()),
    }
}

#[derive(Debug)]
struct Status(Code, String);

fn with_server<F: std::future::Future<Output = ()>>(test: impl FnOnce(std::net::SocketAddr) -> F) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = serve_listener(Arc::new(ExecutionService::new()), listener).await;
        });
        test(addr).await;
        server.abort();
    });
}

fn dar_of(len: usize) -> DynamicMessage {
    let mut msg = DynamicMessage::new(method(UPLOAD).input());
    msg.set_field_by_name(
        "dar_file",
        prost_reflect::Value::Bytes(vec![7u8; len].into()),
    );
    msg
}

#[test]
fn a_request_up_to_ten_mebibytes_is_read() {
    with_server(|addr| async move {
        let status = call_with(addr, UPLOAD, dar_of(6 * 1024 * 1024)).await;
        assert_ne!(status.0, Code::OutOfRange, "{status:?}");
        assert_ne!(status.0, Code::ResourceExhausted, "{status:?}");
    });
}

/// grpc-java's `MessageDeframer` refuses a frame over `maxInboundMessageSize` with RESOURCE_EXHAUSTED "gRPC message exceeds maximum size
/// <limit>: <length>" (Canton's `InvalidRequestSequencerIntegrationTest`: "RESOURCE_EXHAUSTED: gRPC message exceeds maximum size 30000").
#[test]
fn a_request_over_ten_mebibytes_is_refused() {
    with_server(|addr| async move {
        let status = call_with(addr, UPLOAD, dar_of(10 * 1024 * 1024 + 1)).await;
        assert_eq!(status.0, Code::ResourceExhausted, "{status:?}");
        assert_eq!(
            status.1, "gRPC message exceeds maximum size 10485760: 10485766",
            "{status:?}"
        );
    });
}

/// A create argument nested `levels` records deep (three protobuf messages a level: `Value`, `Record`, `RecordField`).
fn submit_nested(levels: usize) -> Value {
    let mut value = json!({ "text": "leaf" });
    for _ in 0..levels {
        value = json!({ "record": { "fields": [ { "label": "f", "value": value } ] } });
    }
    json!({
        "commands": {
            "command_id": "deep",
            "user_id": "u",
            "act_as": ["alice::1220"],
            "commands": [ { "create": {
                "template_id": { "package_id": "p", "module_name": "M", "entity_name": "T" },
                "create_arguments": { "fields": [ { "label": "f", "value": value } ] }
            } } ]
        }
    })
}

#[test]
fn a_request_nested_past_protobufs_bound_is_refused() {
    with_server(|addr| async move {
        // SubmitAndWaitRequest > Commands > Command > CreateCommand > Record > RecordField > Value: 6, then 3 a level
        let deep = call(addr, SUBMIT, submit_nested(32)).await;
        assert_eq!(deep.0, Code::Internal, "{deep:?}");
        assert!(deep.1.contains("recursion limit"), "{deep:?}");
        let shallow = call(addr, SUBMIT, submit_nested(30)).await;
        assert!(!shallow.1.contains("recursion limit"), "{shallow:?}");
    });
}
