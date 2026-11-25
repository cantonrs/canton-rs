//! Tests for the remaining `U-54` Participant Admin gRPC services (`PackageService`, `PingService` Bong,
//! `SynchronizerConnectivityService`, `StatusService`, `ParticipantInspectionService`,
//! `ParticipantRepairService`, and Participant `TopologyManager{Read,Write}Service`).
#![allow(clippy::unwrap_used, reason = "integration test")]

use std::{path::PathBuf, sync::Arc};

use ledger_grpc_api::{dynamic::DynCodec, server::serve_admin_listener};
use ledger_json_api::{
    dispatch_request, v2_packages::ADMIN_PING_PACKAGE_ID, ExecutionService, HttpRequest,
};
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};
use serde_json::{json, Value};
use tonic::{client::Grpc, Code, Request};

fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 0x3f) as usize] as char);
        out.push(T[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let Some(v) = T.iter().position(|&b| b == c) else {
            continue;
        };
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

fn pool() -> DescriptorPool {
    DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor")
}

fn sample_dar_bytes() -> Vec<u8> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    std::fs::read(root.join("contracts/target/sample-contract.dar")).expect("sample-contract.dar")
}

async fn boot_admin_server(service: Arc<ExecutionService>) -> tonic::transport::Channel {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_admin_listener(service, listener));
    tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

fn method_desc(
    pool: &DescriptorPool,
    service: &str,
    name: &str,
) -> prost_reflect::MethodDescriptor {
    pool.get_service_by_name(service)
        .and_then(|s| s.methods().find(|m| m.name() == name))
        .unwrap_or_else(|| panic!("unknown method {service}/{name}"))
}

fn dyn_to_json(msg: &DynamicMessage) -> Value {
    msg.serialize_with_options(
        serde_json::value::Serializer,
        &SerializeOptions::new()
            .skip_default_fields(false)
            .stringify_64_bit_integers(false),
    )
    .expect("serialize dynamic message")
}

async fn unary_res(
    channel: &tonic::transport::Channel,
    pool: &DescriptorPool,
    service: &str,
    name: &str,
    body: Value,
) -> Result<Value, tonic::Status> {
    let method = method_desc(pool, service, name);
    let msg = DynamicMessage::deserialize(method.input(), body).expect("request JSON");
    let mut grpc = Grpc::new(channel.clone());
    grpc.ready().await.expect("ready");
    let path = http::uri::PathAndQuery::try_from(format!("/{service}/{name}")).expect("path");
    let resp = grpc
        .unary(Request::new(msg), path, DynCodec::new(method.output()))
        .await?;
    Ok(dyn_to_json(resp.get_ref()))
}

async fn unary(
    channel: &tonic::transport::Channel,
    pool: &DescriptorPool,
    service: &str,
    name: &str,
    body: Value,
) -> Value {
    unary_res(channel, pool, service, name, body)
        .await
        .unwrap_or_else(|e| panic!("{service}/{name} failed: {e}"))
}

async fn server_stream(
    channel: &tonic::transport::Channel,
    pool: &DescriptorPool,
    service: &str,
    name: &str,
    body: Value,
) -> Vec<Value> {
    let method = method_desc(pool, service, name);
    let msg = DynamicMessage::deserialize(method.input(), body).expect("request JSON");
    let mut grpc = Grpc::new(channel.clone());
    grpc.ready().await.expect("ready");
    let path = http::uri::PathAndQuery::try_from(format!("/{service}/{name}")).expect("path");
    let mut stream = grpc
        .server_streaming(Request::new(msg), path, DynCodec::new(method.output()))
        .await
        .unwrap_or_else(|e| panic!("{service}/{name} stream failed: {e}"))
        .into_inner();
    let mut out = Vec::new();
    while let Some(item) = stream.message().await.expect("stream frame") {
        out.push(dyn_to_json(&item));
    }
    out
}

async fn client_stream(
    channel: &tonic::transport::Channel,
    pool: &DescriptorPool,
    service: &str,
    name: &str,
    bodies: Vec<Value>,
) -> Value {
    let method = method_desc(pool, service, name);
    let msgs: Vec<DynamicMessage> = bodies
        .into_iter()
        .map(|b| DynamicMessage::deserialize(method.input(), b).expect("request JSON"))
        .collect();
    let mut grpc = Grpc::new(channel.clone());
    grpc.ready().await.expect("ready");
    let path = http::uri::PathAndQuery::try_from(format!("/{service}/{name}")).expect("path");
    let resp = grpc
        .client_streaming(
            Request::new(tokio_stream::iter(msgs)),
            path,
            DynCodec::new(method.output()),
        )
        .await
        .unwrap_or_else(|e| panic!("{service}/{name} client stream failed: {e}"));
    dyn_to_json(resp.get_ref())
}

fn post_json(service: &ExecutionService, path: &str, body: Value) -> (u16, Value) {
    let resp = dispatch_request(
        service,
        &HttpRequest {
            method: "POST".into(),
            path: path.into(),
            query_params: Default::default(),
            headers: [("content-type".into(), "application/json".into())].into(),
            body: serde_json::to_vec(&body).unwrap(),
        },
    );
    let parsed = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
    (resp.status, parsed)
}

#[test]
fn package_service_validate_inspect_unvet_and_remove_lifecycle() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let channel = boot_admin_server(Arc::clone(&service)).await;
        let pool = pool();
        let pkg_svc = "com.digitalasset.canton.admin.participant.v30.PackageService";
        let dar_bytes = sample_dar_bytes();
        let dar_b64 = b64_encode(&dar_bytes);

        let before = unary(&channel, &pool, pkg_svc, "ListDars", json!({})).await;
        let initial_dars = before["dars"].as_array().unwrap().len();

        // ValidateDar must not mutate loaded DARs
        let val = unary(
            &channel,
            &pool,
            pkg_svc,
            "ValidateDar",
            json!({ "data": dar_b64, "filename": "sample-contract.dar" }),
        )
        .await;
        let main_id = val["mainPackageId"].as_str().unwrap().to_string();
        assert_eq!(main_id.len(), 64);
        let after_val = unary(&channel, &pool, pkg_svc, "ListDars", json!({})).await;
        assert_eq!(after_val["dars"].as_array().unwrap().len(), initial_dars);

        // UploadDar + inspect DAR/Package contents & references
        unary(
            &channel,
            &pool,
            pkg_svc,
            "UploadDar",
            json!({ "dars": [{ "bytes": dar_b64, "description": "sample-dar" }], "vetAllPackages": true }),
        )
        .await;
        let dar_contents = unary(
            &channel,
            &pool,
            pkg_svc,
            "GetDarContents",
            json!({ "mainPackageId": main_id }),
        )
        .await;
        assert_eq!(dar_contents["description"]["main"], main_id);
        let dar_pkgs = dar_contents["packages"].as_array().unwrap();
        assert!(!dar_pkgs.is_empty());

        let pkg_contents = unary(
            &channel,
            &pool,
            pkg_svc,
            "GetPackageContents",
            json!({ "packageId": main_id }),
        )
        .await;
        assert_eq!(pkg_contents["isUtilityPackage"], json!(false));
        assert!(!pkg_contents["languageVersion"].as_str().unwrap().is_empty());
        assert!(!pkg_contents["modules"].as_array().unwrap().is_empty());

        let refs = unary(
            &channel,
            &pool,
            pkg_svc,
            "GetPackageReferences",
            json!({ "packageId": main_id }),
        )
        .await;
        assert_eq!(refs["dars"].as_array().unwrap().len(), 1);
        assert_eq!(refs["dars"][0]["main"], main_id);

        // Admin builtin ping DAR/package cannot be removed even individually
        let rm_builtin = unary_res(
            &channel,
            &pool,
            pkg_svc,
            "RemovePackage",
            json!({ "packageId": ADMIN_PING_PACKAGE_ID, "force": false }),
        )
        .await
        .expect_err("builtin ping package must be protected");
        assert_eq!(rm_builtin.code(), Code::FailedPrecondition);

        // RemovePackage without force refuses while still referenced by DAR / vetted
        let rm_refused = unary_res(
            &channel,
            &pool,
            pkg_svc,
            "RemovePackage",
            json!({ "packageId": main_id, "force": false }),
        )
        .await
        .expect_err("referenced vetted package must refuse without force");
        assert_eq!(rm_refused.code(), Code::FailedPrecondition);

        // UnvetDar + RemoveDar
        unary(
            &channel,
            &pool,
            pkg_svc,
            "UnvetDar",
            json!({ "mainPackageId": main_id }),
        )
        .await;
        unary(
            &channel,
            &pool,
            pkg_svc,
            "RemoveDar",
            json!({ "mainPackageId": main_id }),
        )
        .await;
        let after_rm = unary(&channel, &pool, pkg_svc, "ListDars", json!({})).await;
        assert_eq!(after_rm["dars"].as_array().unwrap().len(), initial_dars);
    });
}

#[test]
fn ping_service_supports_multi_target_and_bong_levels() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let channel = boot_admin_server(Arc::clone(&service)).await;
        let pool = pool();
        let ping_svc = "com.digitalasset.canton.admin.participant.v30.PingService";

        let (_, p1) = post_json(&service, "/v2/parties", json!({ "partyIdHint": "bong1" }));
        let party1 = p1["partyDetails"]["party"].as_str().unwrap().to_string();
        let participant_party = service.participant_id();

        // Multi-level Bong (levels = 2) across two local target parties
        let res = unary(
            &channel,
            &pool,
            ping_svc,
            "Ping",
            json!({
                "targetParties": [participant_party, party1],
                "timeout": "10s",
                "levels": 2,
                "id": "bong-lvl2"
            }),
        )
        .await;
        assert!(
            res.get("success").is_some(),
            "expected PingSuccess for levels=2 Bong, got: {res}"
        );
        let winner = res["success"]["responder"].as_str().unwrap();
        assert!(!winner.is_empty());

        // Single-party non-zero level (levels = 1)
        let res1 = unary(
            &channel,
            &pool,
            ping_svc,
            "Ping",
            json!({
                "targetParties": [party1],
                "timeout": "10s",
                "levels": 1,
                "id": "bong-lvl1"
            }),
        )
        .await;
        assert!(res1.get("success").is_some(), "got: {res1}");

        // Over max level 10 fails cleanly
        let over = unary(
            &channel,
            &pool,
            ping_svc,
            "Ping",
            json!({
                "targetParties": [party1],
                "timeout": "5s",
                "levels": 11,
                "id": "bong-over"
            }),
        )
        .await;
        assert!(over["failure"]["reason"]
            .as_str()
            .unwrap()
            .contains("exceeds supported max level 10"));
    });
}

#[test]
fn synchronizer_connectivity_service_manages_lifecycle() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let channel = boot_admin_server(Arc::clone(&service)).await;
        let pool = pool();
        let conn_svc = "com.digitalasset.canton.admin.participant.v30.SynchronizerConnectivityService";

        let initial_conn = unary(&channel, &pool, conn_svc, "ListConnectedSynchronizers", json!({})).await;
        assert_eq!(initial_conn["connectedSynchronizers"].as_array().unwrap().len(), 1);
        let sync_id = unary(
            &channel,
            &pool,
            conn_svc,
            "GetSynchronizerId",
            json!({ "synchronizerAlias": "mysync" }),
        )
        .await;
        assert!(!sync_id["synchronizerId"].as_str().unwrap().is_empty());

        // Register a second synchronizer without connecting yet
        unary(
            &channel,
            &pool,
            conn_svc,
            "RegisterSynchronizer",
            json!({
                "config": {
                    "synchronizerAlias": "secondary",
                    "manualConnect": false,
                    "sequencerConnections": {
                        "sequencerTrustThreshold": 1,
                        "sequencerConnections": [{
                            "alias": "sec-seq",
                            "grpc": { "connections": ["http://127.0.0.1:5018"], "transportSecurity": false }
                        }]
                    }
                },
                "synchronizerConnection": "SYNCHRONIZER_CONNECTION_NONE"
            }),
        )
        .await;
        let reg = unary(&channel, &pool, conn_svc, "ListRegisteredSynchronizers", json!({})).await;
        assert_eq!(reg["results"].as_array().unwrap().len(), 2);

        // Disconnect mysync -> connected list becomes empty
        unary(
            &channel,
            &pool,
            conn_svc,
            "DisconnectSynchronizer",
            json!({ "synchronizerAlias": "mysync" }),
        )
        .await;
        let after_disc = unary(&channel, &pool, conn_svc, "ListConnectedSynchronizers", json!({})).await;
        assert!(after_disc["connectedSynchronizers"].as_array().unwrap().is_empty());

        // Reconnect mysync -> connected again; Modify secondary priority; ConnectSynchronizer on secondary
        unary(
            &channel,
            &pool,
            conn_svc,
            "ReconnectSynchronizer",
            json!({ "synchronizerAlias": "mysync", "retry": false }),
        )
        .await;
        unary(
            &channel,
            &pool,
            conn_svc,
            "ModifySynchronizer",
            json!({
                "newConfig": {
                    "synchronizerAlias": "secondary",
                    "priority": 7,
                    "sequencerConnections": {
                        "sequencerTrustThreshold": 1,
                        "sequencerConnections": [{
                            "alias": "sec-seq",
                            "grpc": { "connections": ["http://127.0.0.1:5019"], "transportSecurity": false }
                        }]
                    }
                }
            }),
        )
        .await;
        unary(
            &channel,
            &pool,
            conn_svc,
            "ReconnectSynchronizers",
            json!({ "ignoreFailures": false }),
        )
        .await;
        let after_reconn = unary(&channel, &pool, conn_svc, "ListConnectedSynchronizers", json!({})).await;
        assert_eq!(after_reconn["connectedSynchronizers"].as_array().unwrap().len(), 2);

        unary(
            &channel,
            &pool,
            conn_svc,
            "Logout",
            json!({ "synchronizerAlias": "secondary" }),
        )
        .await;
        unary(&channel, &pool, conn_svc, "DisconnectAllSynchronizers", json!({})).await;
        let after_all_disc = unary(&channel, &pool, conn_svc, "ListConnectedSynchronizers", json!({})).await;
        assert!(after_all_disc["connectedSynchronizers"].as_array().unwrap().is_empty());
    });
}

#[test]
fn status_service_health_dump_log_level_and_participant_status() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let channel = boot_admin_server(Arc::clone(&service)).await;
        let pool = pool();
        let status_svc = "com.digitalasset.canton.admin.health.v30.StatusService";
        let part_status_svc =
            "com.digitalasset.canton.admin.participant.v30.ParticipantStatusService";

        // Valid and invalid SetLogLevel
        unary(
            &channel,
            &pool,
            status_svc,
            "SetLogLevel",
            json!({ "level": "DEBUG" }),
        )
        .await;
        let bad = unary_res(
            &channel,
            &pool,
            status_svc,
            "SetLogLevel",
            json!({ "level": "BOGUS" }),
        )
        .await
        .expect_err("invalid log level must fail");
        assert_eq!(bad.code(), Code::InvalidArgument);

        // Streamed ZIP HealthDump
        let frames = server_stream(
            &channel,
            &pool,
            status_svc,
            "HealthDump",
            json!({ "chunkSize": 128 }),
        )
        .await;
        assert!(!frames.is_empty());
        let mut zip_bytes = Vec::new();
        for f in frames {
            let chunk_b64 = f["chunk"].as_str().unwrap();
            let decoded = b64_decode(chunk_b64);
            zip_bytes.extend_from_slice(&decoded);
        }
        assert!(
            zip_bytes.starts_with(b"PK\x03\x04"),
            "expected ZIP magic bytes"
        );
        let zip_str = String::from_utf8_lossy(&zip_bytes);
        assert!(zip_str.contains("canton-rs-health-dump.json"));
        assert!(zip_str.contains("\"logLevel\": \"DEBUG\""));

        // ParticipantStatus populates ports, topologyQueues, components
        let ps = unary(
            &channel,
            &pool,
            part_status_svc,
            "ParticipantStatus",
            json!({}),
        )
        .await;
        let common = &ps["status"]["commonStatus"];
        assert!(common["ports"].as_object().unwrap().contains_key("admin"));
        assert!(!common["components"].as_array().unwrap().is_empty());
        assert!(common["topologyQueues"]["clients"].is_number());
    });
}

#[test]
fn inspection_and_repair_export_purge_import_roundtrip() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let channel = boot_admin_server(Arc::clone(&service)).await;
        let pool = pool();
        let pkg_svc = "com.digitalasset.canton.admin.participant.v30.PackageService";
        let insp_svc = "com.digitalasset.canton.admin.participant.v30.ParticipantInspectionService";
        let rep_svc = "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService";

        let dar_b64 = b64_encode(&sample_dar_bytes());
        let up = unary(
            &channel,
            &pool,
            pkg_svc,
            "UploadDar",
            json!({ "dars": [{ "bytes": dar_b64 }], "vetAllPackages": true }),
        )
        .await;
        let pkg_id = up["darIds"][0].as_str().unwrap();

        let (_, pa) = post_json(&service, "/v2/parties", json!({ "partyIdHint": "repA" }));
        let party_a = pa["partyDetails"]["party"].as_str().unwrap().to_string();

        let (st, created) = post_json(
            &service,
            "/v2/commands/submit-and-wait-for-transaction",
            json!({
                "commands": {
                    "commands": [{
                        "CreateCommand": {
                            "templateId": format!("{pkg_id}:AssetHolding:AssetHolding"),
                            "createArguments": {
                                "bank": party_a,
                                "owner": party_a,
                                "auditor": party_a,
                                "assetSymbol": "USD",
                                "amount": "10.0"
                            }
                        }
                    }],
                    "commandId": "repair-create-1",
                    "actAs": [party_a],
                    "userId": "ledger-api-user"
                }
            }),
        );
        assert_eq!(st, 200, "create failed: {created}");
        let cid = created["transaction"]["events"][0]["CreatedEvent"]["contractId"]
            .as_str()
            .unwrap()
            .to_string();
        let sync_id = created["transaction"]["synchronizerId"].as_str().unwrap().to_string();
        let offset = created["transaction"]["offset"].as_i64().unwrap();

        // LookupOffsetByTime + CountInFlight + SlowCounterParticipant config
        let future_ts = "2099-01-01T00:00:00Z";
        let off = unary(
            &channel,
            &pool,
            insp_svc,
            "LookupOffsetByTime",
            json!({ "timestamp": future_ts }),
        )
        .await;
        assert_eq!(off["offset"], json!(offset));
        let epoch0 = unary(
            &channel,
            &pool,
            insp_svc,
            "LookupOffsetByTime",
            json!({ "timestamp": "1970-01-01T00:00:00Z" }),
        )
        .await;
        assert!(epoch0.get("offset").is_none() || epoch0["offset"].is_null());

        let inflight = unary(&channel, &pool, insp_svc, "CountInFlight", json!({})).await;
        assert_eq!(inflight["pendingTransactions"], json!(0));

        unary(
            &channel,
            &pool,
            insp_svc,
            "SetConfigForSlowCounterParticipants",
            json!({
                "configs": [{
                    "synchronizerIds": [sync_id],
                    "distinguishedParticipantUids": ["PAR::p2::1220aa"],
                    "thresholdDistinguished": 3,
                    "thresholdDefault": 5,
                    "participantUidsMetrics": []
                }]
            }),
        )
        .await;
        let got_cfg = unary(
            &channel,
            &pool,
            insp_svc,
            "GetConfigForSlowCounterParticipants",
            json!({ "synchronizerIds": [sync_id] }),
        )
        .await;
        assert_eq!(got_cfg["configs"][0]["thresholdDistinguished"], json!(3));

        // ExportAcs -> PurgeContracts -> ImportAcs roundtrip
        let export_frames = server_stream(
            &channel,
            &pool,
            rep_svc,
            "ExportAcs",
            json!({ "partyIds": [party_a], "synchronizerId": sync_id, "ledgerOffset": offset }),
        )
        .await;
        let mut exported = Vec::new();
        for f in export_frames {
            exported.extend_from_slice(&b64_decode(f["chunk"].as_str().unwrap()));
        }
        assert!(!exported.is_empty());

        unary(
            &channel,
            &pool,
            rep_svc,
            "PurgeContracts",
            json!({ "synchronizerAlias": "mysync", "contractIds": [cid], "ignoreAlreadyPurged": false }),
        )
        .await;
        assert!(service.v2_contract(&cid).is_some_and(|c| !c.active));

        client_stream(
            &channel,
            &pool,
            rep_svc,
            "ImportAcs",
            vec![json!({
                "acsSnapshot": b64_encode(&exported),
                "workflowIdPrefix": "wf-import",
                "contractImportMode": "CONTRACT_IMPORT_MODE_VALIDATION",
                "synchronizerId": sync_id
            })],
        )
        .await;
        assert!(
            service.v2_contract(&cid).is_some_and(|c| c.active),
            "ImportAcs must restore contract to ACS"
        );

        // IgnoreEvents + UnignoreEvents
        unary(
            &channel,
            &pool,
            rep_svc,
            "IgnoreEvents",
            json!({ "physicalSynchronizerId": sync_id, "fromInclusive": 1, "toInclusive": 2, "force": true }),
        )
        .await;
        unary(
            &channel,
            &pool,
            rep_svc,
            "UnignoreEvents",
            json!({ "physicalSynchronizerId": sync_id, "fromInclusive": 1, "toInclusive": 2, "force": true }),
        )
        .await;
    });
}

#[test]
fn topology_manager_read_and_write_services() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let channel = boot_admin_server(Arc::clone(&service)).await;
        let pool = pool();
        let topo_r = "com.digitalasset.canton.topology.admin.v30.TopologyManagerReadService";
        let topo_w = "com.digitalasset.canton.topology.admin.v30.TopologyManagerWriteService";

        let stores = unary(&channel, &pool, topo_r, "ListAvailableStores", json!({})).await;
        assert!(stores["storeIds"].as_array().unwrap().len() >= 2);

        let uid = service.participant_id();
        let nsd = unary(
            &channel,
            &pool,
            topo_r,
            "ListNamespaceDelegation",
            json!({}),
        )
        .await;
        assert_eq!(nsd["results"].as_array().unwrap().len(), 1);
        let otk = unary(&channel, &pool, topo_r, "ListOwnerToKeyMapping", json!({})).await;
        assert_eq!(otk["results"].as_array().unwrap().len(), 1);
        let stc = unary(
            &channel,
            &pool,
            topo_r,
            "ListSynchronizerTrustCertificate",
            json!({}),
        )
        .await;
        assert_eq!(stc["results"].as_array().unwrap().len(), 1);

        // Authorize PartyToParticipant on participant
        let auth = unary(
            &channel,
            &pool,
            topo_w,
            "Authorize",
            json!({
                "proposal": {
                    "change": "TOPOLOGY_CHANGE_OP_ADD_REPLACE",
                    "serial": 1,
                    "v30": {
                        "partyToParticipant": {
                            "party": "topoAlice",
                            "threshold": 1,
                            "participants": [{
                                "participantUid": uid,
                                "permission": "PARTICIPANT_PERMISSION_SUBMISSION"
                            }]
                        }
                    }
                },
                "mustFullyAuthorize": true,
                "store": { "authorized": {} }
            }),
        )
        .await;
        assert!(auth["transaction"]["transaction"].as_str().is_some());

        let ptp_default = unary(
            &channel,
            &pool,
            topo_r,
            "ListPartyToParticipant",
            json!({ "filterParty": "topoAlice" }),
        )
        .await;
        assert_eq!(
            ptp_default["results"].as_array().unwrap().len(),
            0,
            "Authorized-store staging must NOT appear in default synchronizer ListPartyToParticipant: {ptp_default}"
        );

        let ptp_auth = unary(
            &channel,
            &pool,
            topo_r,
            "ListPartyToParticipant",
            json!({
                "baseQuery": { "store": { "authorized": {} } },
                "filterParty": "topoAlice"
            }),
        )
        .await;
        assert_eq!(
            ptp_auth["results"].as_array().unwrap().len(),
            1,
            "Authorized store query must return staged topoAlice: {ptp_auth}"
        );

        // ExportTopologySnapshotV2 -> ImportTopologySnapshotV2 roundtrip
        let frames = server_stream(
            &channel,
            &pool,
            topo_r,
            "ExportTopologySnapshotV2",
            json!({}),
        )
        .await;
        let mut snap = Vec::new();
        for f in frames {
            snap.extend_from_slice(&b64_decode(f["chunk"].as_str().unwrap()));
        }
        assert!(!snap.is_empty());
        client_stream(
            &channel,
            &pool,
            topo_w,
            "ImportTopologySnapshotV2",
            vec![json!({
                "topologySnapshot": b64_encode(&snap),
                "store": { "authorized": {} }
            })],
        )
        .await;
    });
}

#[test]
fn admin_pruning_and_ledger_pruning_services_roundtrip() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let pool = pool();
        let service = Arc::new(ExecutionService::new());
        service
            .load_dar(
                &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../contracts/target/sample-contract.dar"),
            )
            .unwrap();
        service.set_max_dedup(std::time::Duration::from_secs(0));

        let admin_channel = boot_admin_server(Arc::clone(&service)).await;
        let lapi_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lapi_addr = lapi_listener.local_addr().unwrap();
        let lapi_svc = Arc::clone(&service);
        tokio::spawn(async move {
            let _ = ledger_grpc_api::server::serve_listener(lapi_svc, lapi_listener).await;
        });
        let lapi_channel = tonic::transport::Endpoint::from_shared(format!("http://{lapi_addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();

        let post = |path: &str, body: Value| -> Value {
            let mut headers = std::collections::HashMap::new();
            headers.insert("content-type".into(), "application/json".into());
            let resp = dispatch_request(
                &service,
                &HttpRequest {
                    method: "POST".into(),
                    path: path.into(),
                    query_params: Default::default(),
                    headers,
                    body: serde_json::to_vec(&body).unwrap(),
                },
            );
            assert_eq!(
                resp.status,
                200,
                "{}: {}",
                path,
                String::from_utf8_lossy(&resp.body)
            );
            serde_json::from_slice(&resp.body).unwrap()
        };

        let alice = post(
            "/v2/parties",
            json!({"partyIdHint": "pruneAlice", "identityProviderId": ""}),
        )["partyDetails"]["party"]
            .as_str()
            .unwrap()
            .to_string();

        let mut create_off = Vec::new();
        let mut create_cid = Vec::new();
        for i in 1..=3 {
            let b = post(
                "/v2/commands/submit-and-wait-for-transaction",
                json!({
                    "commands": {
                        "commands": [{
                            "CreateCommand": {
                                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                                "createArguments": {
                                    "bank": alice, "owner": alice, "auditor": alice,
                                    "assetSymbol": format!("P{i}"), "amount": "5.0"
                                }
                            }
                        }],
                        "commandId": format!("gp-{i}"),
                        "userId": "participant_admin",
                        "actAs": [alice]
                    }
                }),
            );
            create_off.push(
                b["transaction"]["offset"]
                    .as_str()
                    .or_else(|| b["transaction"]["offset"].as_u64().map(|_| ""))
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or_else(|| b["transaction"]["offset"].as_i64().unwrap()),
            );
            create_cid.push(
                b["transaction"]["events"][0]["CreatedEvent"]["contractId"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }
        let arch = post(
            "/v2/commands/submit-and-wait-for-transaction",
            json!({
                "commands": {
                    "commands": [{
                        "ExerciseCommand": {
                            "templateId": "#sample-contract:AssetHolding:AssetHolding",
                            "contractId": create_cid[0],
                            "choice": "Archive",
                            "choiceArgument": {}
                        }
                    }],
                    "commandId": "gp-arch-1",
                    "userId": "participant_admin",
                    "actAs": [alice]
                }
            }),
        );
        let arch_off = arch["transaction"]["offset"].as_i64().unwrap();
        let _tail = post(
            "/v2/commands/submit-and-wait-for-transaction",
            json!({
                "commands": {
                    "commands": [{
                        "CreateCommand": {
                            "templateId": "#sample-contract:AssetHolding:AssetHolding",
                            "createArguments": {
                                "bank": alice, "owner": alice, "auditor": alice,
                                "assetSymbol": "PTAIL", "amount": "5.0"
                            }
                        }
                    }],
                    "commandId": "gp-tail-1",
                    "userId": "participant_admin",
                    "actAs": [alice]
                }
            }),
        );
        let end = service.v2_ledger_end() as i64;

        let admin_pruning = "com.digitalasset.canton.admin.participant.v30.PruningService";
        let lapi_pruning = "com.daml.ledger.api.v2.admin.ParticipantPruningService";

        // 1) Negative ledger_end rejected
        let neg_err = unary_res(
            &admin_channel,
            &pool,
            admin_pruning,
            "GetSafePruningOffset",
            json!({ "ledgerEnd": -1 }),
        )
        .await
        .unwrap_err();
        assert_eq!(neg_err.code(), Code::InvalidArgument);

        // 2) Safe offset blocks under commitment gate unless state=ALL
        service.set_acs_safe_to_prune_micros(Some(0));
        let no_safe = unary(
            &admin_channel,
            &pool,
            admin_pruning,
            "GetSafePruningOffset",
            json!({ "ledgerEnd": end }),
        )
        .await;
        assert!(no_safe.get("noSafePruningOffset").is_some(), "{no_safe}");

        let safe_all = unary(
            &admin_channel,
            &pool,
            admin_pruning,
            "GetSafePruningOffset",
            json!({
                "ledgerEnd": end,
                "counterParticipantsCommitmentsState": "SAFE_TO_PRUNE_COMMITMENT_STATE_ALL"
            }),
        )
        .await;
        let safe_off = safe_all["safePruningOffset"]
            .as_i64()
            .or_else(|| safe_all["safePruningOffset"].as_str()?.parse().ok())
            .unwrap();
        assert!(safe_off >= arch_off && safe_off < end, "{safe_all}");

        // 3) Admin PruningService/Prune respects commitment gating, then passes with ALL
        let unsafe_err = unary_res(
            &admin_channel,
            &pool,
            admin_pruning,
            "Prune",
            json!({ "pruneUpTo": arch_off }),
        )
        .await
        .unwrap_err();
        assert_eq!(unsafe_err.code(), Code::FailedPrecondition);

        let admin_ok = unary(
            &admin_channel,
            &pool,
            admin_pruning,
            "Prune",
            json!({
                "pruneUpTo": create_off[0],
                "counterParticipantsCommitmentsState": "SAFE_TO_PRUNE_COMMITMENT_STATE_ALL"
            }),
        )
        .await;
        assert!(admin_ok.is_object(), "{admin_ok}");

        // 4) Ledger API ParticipantPruningService/Prune invalid & valid
        service.set_acs_safe_to_prune_micros(None);
        let zero_err = unary_res(
            &lapi_channel,
            &pool,
            lapi_pruning,
            "Prune",
            json!({ "pruneUpTo": 0 }),
        )
        .await
        .unwrap_err();
        assert_eq!(zero_err.code(), Code::InvalidArgument);

        let lapi_ok = unary(
            &lapi_channel,
            &pool,
            lapi_pruning,
            "Prune",
            json!({ "pruneUpTo": arch_off }),
        )
        .await;
        assert!(lapi_ok.is_object(), "{lapi_ok}");
        assert!(service.v2_contract(&create_cid[0]).is_none());
        assert!(service.v2_contract(&create_cid[1]).is_some());
    });
}

#[test]
fn r7_admin_import_and_authorized_store_do_not_emit_topology_events() {
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        enums::ParticipantPermission, enums::TopologyChangeOp,
        party_to_participant::HostingParticipant, topology_mapping::Mapping, PartyToParticipant,
        TopologyMapping, TopologyTransaction,
    };
    use ledger_json_api::{dispatch_request, HttpRequest};
    use prost::Message as _;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let pool = pool();
        let service = Arc::new(ExecutionService::new());
        let channel = boot_admin_server(Arc::clone(&service)).await;

        let topo_w = "com.digitalasset.canton.topology.admin.v30.TopologyManagerWriteService";
        let topo_r = "com.digitalasset.canton.topology.admin.v30.TopologyManagerReadService";
        let end_before = service.v2_ledger_end();

        // Authorize on Authorized store must not emit Ledger API TopologyTransaction updates.
        let uid = service.participant_id();
        let _auth = unary(
            &channel,
            &pool,
            topo_w,
            "Authorize",
            json!({
                "proposal": {
                    "change": "TOPOLOGY_CHANGE_OP_ADD_REPLACE",
                    "serial": 1,
                    "v30": {
                        "partyToParticipant": {
                            "party": "r7AuthorizedParty",
                            "threshold": 1,
                            "participants": [{
                                "participantUid": uid,
                                "permission": "PARTICIPANT_PERMISSION_SUBMISSION"
                            }]
                        }
                    }
                },
                "mustFullyAuthorize": true,
                "store": { "authorized": {} }
            }),
        )
        .await;
        assert_eq!(
            service.v2_ledger_end(),
            end_before,
            "Authorize in Authorized store must not advance ledger_end or emit topology events"
        );

        // ExportTopologySnapshotV2 -> ImportTopologySnapshotV2 (even into Synchronizer store) must not emit events.
        let frames = server_stream(
            &channel,
            &pool,
            topo_r,
            "ExportTopologySnapshotV2",
            json!({}),
        )
        .await;
        let mut snap = Vec::new();
        for f in frames {
            snap.extend_from_slice(&b64_decode(f["chunk"].as_str().unwrap()));
        }
        client_stream(
            &channel,
            &pool,
            topo_w,
            "ImportTopologySnapshotV2",
            vec![json!({
                "topologySnapshot": b64_encode(&snap),
                "store": { "synchronizer": { "id": "mysync::12207ba0" } }
            })],
        )
        .await;
        assert_eq!(
            service.v2_ledger_end(),
            end_before,
            "ImportTopologySnapshotV2 must not emit historical Ledger API topology events"
        );

        // Positive control: AddTransactions with signed effective tx to Synchronizer store emits 1 event.
        let ptp = PartyToParticipant {
            party: "r7SyncParty::1220aa".into(),
            threshold: 1,
            participants: vec![HostingParticipant {
                participant_uid: "p1::122011".into(),
                permission: ParticipantPermission::Submission as i32,
                onboarding: None,
            }],
            party_signing_keys: None,
        };
        let tx = TopologyTransaction {
            operation: TopologyChangeOp::AddReplace as i32,
            serial: 1,
            mapping: Some(TopologyMapping {
                mapping: Some(Mapping::PartyToParticipant(ptp)),
            }),
        };
        let _ = unary(
            &channel,
            &pool,
            topo_w,
            "AddTransactions",
            json!({
                "transactions": [{
                    "transaction": b64_encode(&tx.encode_to_vec()),
                    "signatures": [{
                        "format": 1,
                        "signature": b64_encode(&[0u8; 64]),
                        "signedBy": "k",
                        "signingAlgorithmSpec": 1
                    }],
                    "proposal": false
                }],
                "store": { "synchronizer": { "id": "mysync::12207ba0" } }
            }),
        )
        .await;
        let resp = dispatch_request(
            &service,
            &HttpRequest {
                method: "POST".into(),
                path: "/v2/updates".into(),
                query_params: Default::default(),
                headers: Default::default(),
                body: serde_json::to_vec(&json!({
                    "beginExclusive": 0,
                    "updateFormat": {
                        "includeTopologyEvents": {
                            "includeParticipantAuthorizationEvents": { "parties": ["r7SyncParty::1220aa"] }
                        }
                    }
                }))
                .unwrap(),
            },
        );
        assert_eq!(resp.status, 200);
        let arr: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 1, "{arr}");
    });
}

#[test]
fn r7_authorize_state_and_events_stay_in_sync_and_physical_id_normalizes_to_logical() {
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        enums::ParticipantPermission, enums::TopologyChangeOp,
        party_to_participant::HostingParticipant, topology_mapping::Mapping, PartyToParticipant,
        TopologyMapping, TopologyTransaction,
    };
    use ledger_json_api::{dispatch_request, HttpRequest};
    use prost::Message as _;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let pool = pool();
        let service = Arc::new(ExecutionService::new());
        let channel = boot_admin_server(Arc::clone(&service)).await;
        let topo_w = "com.digitalasset.canton.topology.admin.v30.TopologyManagerWriteService";
        let uid = service.participant_id();

        let is_hosted_party = |party_prefix: &str| -> bool {
            let resp = dispatch_request(
                &service,
                &HttpRequest {
                    method: "GET".into(),
                    path: "/v2/parties".into(),
                    query_params: Default::default(),
                    headers: Default::default(),
                    body: Vec::new(),
                },
            );
            assert_eq!(resp.status, 200);
            let v: Value = serde_json::from_slice(&resp.body).unwrap();
            v["partyDetails"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|p| p["party"].as_str())
                .any(|p| p.starts_with(party_prefix))
        };
        let topo_events_for = |party_prefix: &str| -> Vec<Value> {
            let fp = uid.split("::").nth(1).unwrap_or("1220rust");
            let full_party = if party_prefix.contains("::") {
                party_prefix.to_string()
            } else {
                format!("{party_prefix}::{fp}")
            };
            let resp = dispatch_request(
                &service,
                &HttpRequest {
                    method: "POST".into(),
                    path: "/v2/updates".into(),
                    query_params: Default::default(),
                    headers: Default::default(),
                    body: serde_json::to_vec(&json!({
                        "beginExclusive": 0,
                        "updateFormat": {
                            "includeTopologyEvents": {
                                "includeParticipantAuthorizationEvents": { "parties": [full_party] }
                            }
                        }
                    }))
                    .unwrap(),
                },
            );
            assert_eq!(resp.status, 200);
            serde_json::from_slice::<Value>(&resp.body)
                .unwrap()
                .as_array()
                .cloned()
                .unwrap_or_default()
        };

        // (a) Authorize on Authorized store: hosting state and emitted events must agree (neither or both).
        let _ = unary(
            &channel,
            &pool,
            topo_w,
            "Authorize",
            json!({
                "proposal": {
                    "change": "TOPOLOGY_CHANGE_OP_ADD_REPLACE",
                    "serial": 1,
                    "v30": {
                        "partyToParticipant": {
                            "party": "r7AuthSync",
                            "threshold": 1,
                            "participants": [{
                                "participantUid": uid,
                                "permission": "PARTICIPANT_PERMISSION_SUBMISSION"
                            }]
                        }
                    }
                },
                "mustFullyAuthorize": true,
                "store": { "authorized": {} }
            }),
        )
        .await;
        let hosted_auth = is_hosted_party("r7AuthSync::");
        let events_auth = topo_events_for("r7AuthSync");
        assert_eq!(
            hosted_auth,
            !events_auth.is_empty(),
            "Authorize on Authorized store drifted hosting state ({hosted_auth}) from emitted topology events ({})",
            events_auth.len()
        );

        // (b) Authorize on Synchronizer store with Canton console default `mustFullyAuthorize: false`:
        // state & emitted topology events must both update together.
        let _ = unary(
            &channel,
            &pool,
            topo_w,
            "Authorize",
            json!({
                "proposal": {
                    "change": "TOPOLOGY_CHANGE_OP_ADD_REPLACE",
                    "serial": 1,
                    "v30": {
                        "partyToParticipant": {
                            "party": "r7SyncDefaultAuth",
                            "threshold": 1,
                            "participants": [{
                                "participantUid": uid,
                                "permission": "PARTICIPANT_PERMISSION_SUBMISSION"
                            }]
                        }
                    }
                },
                "mustFullyAuthorize": false,
                "store": { "synchronizer": { "id": "mysync::12207ba0" } }
            }),
        )
        .await;
        let hosted_sync = is_hosted_party("r7SyncDefaultAuth::");
        let events_sync = topo_events_for("r7SyncDefaultAuth");
        assert!(
            hosted_sync && !events_sync.is_empty(),
            "Authorize with mustFullyAuthorize=false on Synchronizer store must both host ({hosted_sync}) and emit topology events ({}): {events_sync:?}",
            events_sync.len()
        );

        // (c) AddTransactions on physical synchronizer store ID must emit logical synchronizerId in TopologyTransaction.
        let ptp = PartyToParticipant {
            party: "r7PhysNorm::1220bb".into(),
            threshold: 1,
            participants: vec![HostingParticipant {
                participant_uid: "p1::122011".into(),
                permission: ParticipantPermission::Submission as i32,
                onboarding: None,
            }],
            party_signing_keys: None,
        };
        let tx = TopologyTransaction {
            operation: TopologyChangeOp::AddReplace as i32,
            serial: 1,
            mapping: Some(TopologyMapping {
                mapping: Some(Mapping::PartyToParticipant(ptp)),
            }),
        };
        let _ = unary(
            &channel,
            &pool,
            topo_w,
            "AddTransactions",
            json!({
                "transactions": [{
                    "transaction": b64_encode(&tx.encode_to_vec()),
                    "signatures": [{
                        "format": 1,
                        "signature": b64_encode(&[0u8; 64]),
                        "signedBy": "k",
                        "signingAlgorithmSpec": 1
                    }],
                    "proposal": false
                }],
                "store": { "synchronizer": { "physicalId": "mysync::12207ba0::1" } }
            }),
        )
        .await;
        let norm_events = topo_events_for("r7PhysNorm::1220bb");
        assert_eq!(norm_events.len(), 1, "{norm_events:?}");
        assert_eq!(
            norm_events[0]["update"]["TopologyTransaction"]["value"]["synchronizerId"],
            json!("mysync::12207ba0"),
            "TopologyTransaction must normalize physical synchronizerId to logical: {:?}",
            norm_events[0]
        );
    });
}

#[test]
fn r7b_import_topology_snapshot_does_not_emit_topology_events() {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        Signature, SignatureFormat, SigningAlgorithmSpec,
    };
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        enums::ParticipantPermission, enums::TopologyChangeOp,
        party_to_participant::HostingParticipant, topology_mapping::Mapping, PartyToParticipant,
        SignedTopologyTransaction, TopologyMapping, TopologyTransaction,
    };
    use canton_proto::com::digitalasset::canton::topology::admin::v30::{
        topology_transactions::Item, TopologyTransactions,
    };
    use ledger_json_api::{dispatch_request, HttpRequest};
    use prost::Message as _;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let pool = pool();
        let service = Arc::new(ExecutionService::new());
        let channel = boot_admin_server(Arc::clone(&service)).await;
        let topo_w = "com.digitalasset.canton.topology.admin.v30.TopologyManagerWriteService";
        let topo_r = "com.digitalasset.canton.topology.admin.v30.TopologyManagerReadService";

        // Build a standalone signed PartyToParticipant transaction directly in the snapshot
        // (without calling Authorize first) so reverting import event suppression fails loudly.
        let ptp = PartyToParticipant {
            party: "r7bSnapOnly::1220cc".into(),
            threshold: 1,
            participants: vec![HostingParticipant {
                participant_uid: "p1::122011".into(),
                permission: ParticipantPermission::Submission as i32,
                onboarding: None,
            }],
            party_signing_keys: None,
        };
        let tx = TopologyTransaction {
            operation: TopologyChangeOp::AddReplace as i32,
            serial: 1,
            mapping: Some(TopologyMapping {
                mapping: Some(Mapping::PartyToParticipant(ptp)),
            }),
        };
        let signed = SignedTopologyTransaction {
            transaction: tx.encode_to_vec(),
            signatures: vec![Signature {
                format: SignatureFormat::Raw as i32,
                signature: vec![0u8; 64],
                signed_by: "k".into(),
                signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
                signature_delegation: None,
            }],
            proposal: false,
            multi_transaction_signatures: Vec::new(),
        };
        let snap = TopologyTransactions {
            items: vec![Item {
                sequenced: None,
                valid_from: None,
                valid_until: None,
                transaction: signed.encode_to_vec(),
                rejection_reason: None,
            }],
        }
        .encode_to_vec();

        client_stream(
            &channel,
            &pool,
            topo_w,
            "ImportTopologySnapshotV2",
            vec![json!({
                "topologySnapshot": b64_encode(&snap),
                "store": { "synchronizer": { "id": "mysync::12207ba0" } }
            })],
        )
        .await;

        let all = unary(&channel, &pool, topo_r, "ListAllV2", json!({})).await;
        let imported_count = all["result"]["items"].as_array().map_or(0, Vec::len);
        assert!(imported_count >= 1, "snapshot tx must be stored: {all}");

        let updates = dispatch_request(
            &service,
            &HttpRequest {
                method: "POST".into(),
                path: "/v2/updates".into(),
                query_params: Default::default(),
                headers: Default::default(),
                body: serde_json::to_vec(&json!({
                    "beginExclusive": 0,
                    "updateFormat": {
                        "includeTopologyEvents": {
                            "includeParticipantAuthorizationEvents": { "parties": ["r7bSnapOnly::1220cc"] }
                        }
                    }
                }))
                .unwrap(),
            },
        );
        assert_eq!(updates.status, 200);
        let arr: Value = serde_json::from_slice(&updates.body).unwrap();
        assert_eq!(
            arr.as_array().unwrap().len(),
            0,
            "standalone ImportTopologySnapshotV2 must not emit TopologyTransaction updates: {arr}"
        );
    });
}
