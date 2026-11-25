#![allow(clippy::unwrap_used, reason = "integration test")]
//! Integration tests for live `UpdateService/GetUpdates` tailing (`end_inclusive` unset or `> ledger_end`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ledger_grpc_api::admin_api::BUILTIN_PING_DAR;
use ledger_grpc_api::server::serve_listener;
use ledger_json_api::{dispatch_request, ExecutionService, HttpRequest};
use prost::Message as _;
use prost_reflect::prost_types::FileDescriptorSet;
use prost_reflect::{DescriptorPool, DynamicMessage};
use tokio::net::TcpListener;
use tonic::transport::Channel;

fn descriptor_pool() -> DescriptorPool {
    let fds = FileDescriptorSet::decode(canton_proto::FILE_DESCRIPTOR_SET)
        .expect("decode vendored descriptor set");
    DescriptorPool::from_file_descriptor_set(fds).expect("build descriptor pool")
}

fn dyn_from_json(
    pool: &DescriptorPool,
    full_name: &str,
    json: &serde_json::Value,
) -> DynamicMessage {
    let desc = pool.get_message_by_name(full_name).unwrap();
    let encoded = json.to_string();
    let mut de = serde_json::Deserializer::from_str(&encoded);
    DynamicMessage::deserialize(desc, &mut de).unwrap()
}

fn dyn_to_json(msg: &DynamicMessage) -> serde_json::Value {
    let opts = prost_reflect::SerializeOptions::new().stringify_64_bit_integers(true);
    msg.serialize_with_options(serde_json::value::Serializer, &opts)
        .unwrap()
}

fn build_updates_req(
    pool: &DescriptorPool,
    party: &str,
    begin_exclusive: i64,
    end_inclusive: Option<i64>,
) -> DynamicMessage {
    let mut json = serde_json::json!({
        "beginExclusive": begin_exclusive,
        "updateFormat": {
            "includeTransactions": {
                "eventFormat": {
                    "filtersByParty": {
                        (party): {
                            "cumulative": [{
                                "wildcardFilter": { "includeCreatedEventBlob": false }
                            }]
                        }
                    },
                    "verbose": true
                },
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        }
    });
    if let Some(end) = end_inclusive {
        json["endInclusive"] = serde_json::json!(end);
    }
    dyn_from_json(pool, "com.daml.ledger.api.v2.GetUpdatesRequest", &json)
}

async fn start_ledger_grpc() -> (Arc<ExecutionService>, Channel) {
    let service = Arc::new(ExecutionService::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = Arc::clone(&service);
    tokio::spawn(async move {
        let _ = serve_listener(srv, listener).await;
    });
    let channel = Channel::from_shared(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (service, channel)
}

fn upload_dar_and_party(service: &ExecutionService, hint: &str) -> (String, String) {
    let upload = dispatch_request(
        service,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/dars".into(),
            query_params: HashMap::new(),
            headers: [("content-type".into(), "application/octet-stream".into())].into(),
            body: BUILTIN_PING_DAR.to_vec(),
        },
    );
    assert!(upload.status < 300, "upload dar failed: {}", upload.status);

    let alloc = dispatch_request(
        service,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/parties".into(),
            query_params: HashMap::new(),
            headers: [("content-type".into(), "application/json".into())].into(),
            body: serde_json::to_vec(&serde_json::json!({
                "partyIdHint": hint,
                "identityProviderId": ""
            }))
            .unwrap(),
        },
    );
    assert!(alloc.status < 300, "allocate failed: {}", alloc.status);
    let alloc_json: serde_json::Value = serde_json::from_slice(&alloc.body).unwrap();
    let party = alloc_json["partyDetails"]["party"]
        .as_str()
        .unwrap()
        .to_string();
    let pkg_id = ledger_json_api::v2_packages::ADMIN_PING_PACKAGE_ID.to_string();
    (party, pkg_id)
}

fn create_ping_contract(
    service: &ExecutionService,
    party: &str,
    pkg_id: &str,
    cmd_id: &str,
) -> i64 {
    let body = serde_json::json!({
        "commands": {
            "commands": [{
                "CreateCommand": {
                    "templateId": format!("{pkg_id}:Canton.Internal.Ping:Ping"),
                    "createArguments": {
                        "id": cmd_id,
                        "initiator": party,
                        "responder": party
                    }
                }
            }],
            "commandId": cmd_id,
            "actAs": [party],
            "userId": "participant_admin"
        }
    });
    let resp = dispatch_request(
        service,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/commands/submit-and-wait-for-transaction".into(),
            query_params: HashMap::new(),
            headers: [("content-type".into(), "application/json".into())].into(),
            body: serde_json::to_vec(&body).unwrap(),
        },
    );
    assert!(
        resp.status < 300,
        "submit failed: {}",
        String::from_utf8_lossy(&resp.body)
    );
    let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    v["transaction"]["offset"]
        .as_str()
        .and_then(|s| s.parse::<i64>().ok())
        .or_else(|| v["transaction"]["offset"].as_i64())
        .unwrap()
}

#[tokio::test]
async fn get_updates_without_end_inclusive_streams_live_commits() {
    let pool = descriptor_pool();
    let m = pool
        .get_service_by_name("com.daml.ledger.api.v2.UpdateService")
        .unwrap()
        .methods()
        .find(|m| m.name() == "GetUpdates")
        .unwrap();
    let (service, channel) = start_ledger_grpc().await;
    let (party, pkg_id) = upload_dar_and_party(&service, "live-open");

    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.unwrap();
    let req = build_updates_req(&pool, &party, 0, None);
    let path: http::uri::PathAndQuery = "/com.daml.ledger.api.v2.UpdateService/GetUpdates"
        .parse()
        .unwrap();
    let mut stream = client
        .server_streaming(
            tonic::Request::new(req),
            path,
            ledger_grpc_api::dynamic::DynCodec::new(m.output()),
        )
        .await
        .unwrap()
        .into_inner();

    // Commit two transactions AFTER opening the open-ended live stream.
    let off1 = create_ping_contract(&service, &party, &pkg_id, "live-cmd-1");
    let msg1 = tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .expect("timed out waiting for first live update")
        .unwrap()
        .expect("expected update 1");
    let j1 = dyn_to_json(&msg1);
    assert_eq!(j1["transaction"]["commandId"], "live-cmd-1");
    assert_eq!(
        j1["transaction"]["offset"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap(),
        off1
    );

    let off2 = create_ping_contract(&service, &party, &pkg_id, "live-cmd-2");
    let msg2 = tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .expect("timed out waiting for second live update")
        .unwrap()
        .expect("expected update 2");
    let j2 = dyn_to_json(&msg2);
    assert_eq!(j2["transaction"]["commandId"], "live-cmd-2");
    assert_eq!(
        j2["transaction"]["offset"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap(),
        off2
    );
}

#[tokio::test]
async fn get_updates_with_future_end_inclusive_terminates_at_target_offset() {
    let pool = descriptor_pool();
    let m = pool
        .get_service_by_name("com.daml.ledger.api.v2.UpdateService")
        .unwrap()
        .methods()
        .find(|m| m.name() == "GetUpdates")
        .unwrap();
    let (service, channel) = start_ledger_grpc().await;
    let (party, pkg_id) = upload_dar_and_party(&service, "live-bounded");

    let start_end = service.v2_ledger_end() as i64;
    let target_end = start_end + 1;

    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.unwrap();
    let req = build_updates_req(&pool, &party, start_end, Some(target_end));
    let path: http::uri::PathAndQuery = "/com.daml.ledger.api.v2.UpdateService/GetUpdates"
        .parse()
        .unwrap();
    let mut stream = client
        .server_streaming(
            tonic::Request::new(req),
            path,
            ledger_grpc_api::dynamic::DynCodec::new(m.output()),
        )
        .await
        .unwrap()
        .into_inner();

    let committed_off = create_ping_contract(&service, &party, &pkg_id, "bounded-future-1");
    assert_eq!(committed_off, target_end);

    let msg = tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .expect("timed out waiting for future bounded update")
        .unwrap()
        .expect("expected bounded update");
    assert_eq!(
        dyn_to_json(&msg)["transaction"]["commandId"],
        "bounded-future-1"
    );

    let eof = tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .expect("timed out waiting for clean EOF after target offset")
        .unwrap();
    assert!(
        eof.is_none(),
        "expected stream to terminate cleanly at end_inclusive"
    );
}

#[tokio::test]
async fn get_updates_and_pointwise_lookups_deliver_topology_transactions() {
    let pool = descriptor_pool();
    let upd_svc = pool
        .get_service_by_name("com.daml.ledger.api.v2.UpdateService")
        .unwrap();
    let method_updates = upd_svc
        .methods()
        .find(|m| m.name() == "GetUpdates")
        .unwrap();
    let method_by_offset = upd_svc
        .methods()
        .find(|m| m.name() == "GetUpdateByOffset")
        .unwrap();
    let method_by_id = upd_svc
        .methods()
        .find(|m| m.name() == "GetUpdateById")
        .unwrap();

    let (service, channel) = start_ledger_grpc().await;
    let start_end = service.v2_ledger_end() as i64;
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.unwrap();

    let update_format = serde_json::json!({
        "includeTopologyEvents": {
            "includeParticipantAuthorizationEvents": { "parties": [] }
        }
    });
    let req = dyn_from_json(
        &pool,
        "com.daml.ledger.api.v2.GetUpdatesRequest",
        &serde_json::json!({
            "beginExclusive": start_end,
            "updateFormat": &update_format
        }),
    );
    let mut stream = client
        .server_streaming(
            tonic::Request::new(req),
            "/com.daml.ledger.api.v2.UpdateService/GetUpdates"
                .parse()
                .unwrap(),
            ledger_grpc_api::dynamic::DynCodec::new(method_updates.output()),
        )
        .await
        .unwrap()
        .into_inner();

    let (party, _pkg) = upload_dar_and_party(&service, "topo-grpc");
    let msg = tokio::time::timeout(Duration::from_secs(3), stream.message())
        .await
        .expect("timed out waiting for gRPC TopologyTransaction")
        .unwrap()
        .expect("expected gRPC TopologyTransaction message");
    let streamed = dyn_to_json(&msg);
    let topo = &streamed["topologyTransaction"];
    let update_id = topo["updateId"].as_str().unwrap().to_string();
    let offset: i64 = topo["offset"].as_str().unwrap().parse().unwrap();
    let added = &topo["events"][0]["participantAuthorizationAdded"];
    assert_eq!(added["partyId"], party);
    assert!(!added["participantId"].as_str().unwrap().is_empty());
    assert_eq!(
        added["participantPermission"],
        "PARTICIPANT_PERMISSION_SUBMISSION"
    );

    client.ready().await.unwrap();
    let by_off_req = dyn_from_json(
        &pool,
        "com.daml.ledger.api.v2.GetUpdateByOffsetRequest",
        &serde_json::json!({ "offset": offset, "updateFormat": &update_format }),
    );
    let by_off_resp = client
        .unary(
            tonic::Request::new(by_off_req),
            "/com.daml.ledger.api.v2.UpdateService/GetUpdateByOffset"
                .parse()
                .unwrap(),
            ledger_grpc_api::dynamic::DynCodec::new(method_by_offset.output()),
        )
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        dyn_to_json(&by_off_resp)["topologyTransaction"]["updateId"],
        update_id
    );

    client.ready().await.unwrap();
    let by_id_req = dyn_from_json(
        &pool,
        "com.daml.ledger.api.v2.GetUpdateByIdRequest",
        &serde_json::json!({ "updateId": &update_id, "updateFormat": &update_format }),
    );
    let by_id_resp = client
        .unary(
            tonic::Request::new(by_id_req),
            "/com.daml.ledger.api.v2.UpdateService/GetUpdateById"
                .parse()
                .unwrap(),
            ledger_grpc_api::dynamic::DynCodec::new(method_by_id.output()),
        )
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        dyn_to_json(&by_id_resp)["topologyTransaction"]["offset"]
            .as_str()
            .unwrap(),
        offset.to_string()
    );

    client.ready().await.unwrap();
    let omitted_req = dyn_from_json(
        &pool,
        "com.daml.ledger.api.v2.GetUpdateByIdRequest",
        &serde_json::json!({
            "updateId": &update_id,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": {
                        "filtersByParty": { (&party): {} },
                        "verbose": true
                    },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                }
            }
        }),
    );
    let err = client
        .unary(
            tonic::Request::new(omitted_req),
            "/com.daml.ledger.api.v2.UpdateService/GetUpdateById"
                .parse()
                .unwrap(),
            ledger_grpc_api::dynamic::DynCodec::new(method_by_id.output()),
        )
        .await
        .expect_err("expected NOT_FOUND when includeTopologyEvents omitted");
    assert_eq!(err.code(), tonic::Code::NotFound);
}
