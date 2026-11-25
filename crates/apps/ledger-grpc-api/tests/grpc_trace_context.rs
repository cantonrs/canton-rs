//! A command submitted over gRPC with a W3C `traceparent` in its metadata carries it in its transaction's `trace_context`, as the JSON API's
//! does (`ledger_json_api::trace_context`).
#![allow(clippy::unwrap_used, reason = "integration test")]

use std::collections::HashMap;
use std::sync::Arc;

use ledger_grpc_api::{dynamic::DynCodec, server::serve_listener};
use ledger_json_api::{dispatch_request, ExecutionService, HttpRequest};
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde_json::{json, Value};
use tonic::{client::Grpc, Request};

const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

fn post(svc: &ExecutionService, path: &str, body: Vec<u8>) -> Value {
    let resp = dispatch_request(
        svc,
        &HttpRequest {
            method: "POST".into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body,
        },
    );
    assert_eq!(resp.status, 200);
    serde_json::from_slice(&resp.body).unwrap()
}

#[test]
fn a_grpc_submissions_traceparent_is_its_transactions() {
    let svc = Arc::new(ExecutionService::new());
    let dar = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar"),
    )
    .unwrap();
    post(&svc, "/v2/dars", dar);
    let alice = post(
        &svc,
        "/v2/parties",
        json!({"partyIdHint": "alice", "identityProviderId": ""})
            .to_string()
            .into_bytes(),
    )["partyDetails"]["party"]
        .as_str()
        .unwrap()
        .to_string();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = Arc::clone(&svc);
        let server = tokio::spawn(async move {
            let _ = serve_listener(served, listener).await;
        });
        let method = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET)
            .unwrap()
            .get_service_by_name("com.daml.ledger.api.v2.CommandService")
            .and_then(|s| s.methods().find(|m| m.name() == "SubmitAndWaitForTransaction"))
            .unwrap();
        let body = json!({"commands": {
            "command_id": "traced",
            "user_id": "u",
            "act_as": [alice],
            "commands": [{"create": {
                "template_id": {"package_id": "#sample-contract", "module_name": "AssetHolding", "entity_name": "AssetHolding"},
                "create_arguments": {"fields": [
                    {"label": "bank", "value": {"party": alice}},
                    {"label": "owner", "value": {"party": alice}},
                    {"label": "auditor", "value": {"party": alice}},
                    {"label": "assetSymbol", "value": {"text": "USD"}},
                    {"label": "amount", "value": {"numeric": "1.0"}}
                ]}
            }}]
        }});
        let msg = DynamicMessage::deserialize(method.input(), body).unwrap();
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut grpc = Grpc::new(channel);
        grpc.ready().await.unwrap();
        let mut request = Request::new(msg);
        request
            .metadata_mut()
            .insert("traceparent", TRACE.parse().unwrap());
        let path = "/com.daml.ledger.api.v2.CommandService/SubmitAndWaitForTransaction"
            .parse()
            .unwrap();
        let response = grpc
            .unary(request, path, DynCodec::new(method.output()))
            .await
            .unwrap()
            .into_inner();
        let out: Value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            out["transaction"]["traceContext"]["traceparent"], TRACE,
            "{out}"
        );
        server.abort();
    });
}
