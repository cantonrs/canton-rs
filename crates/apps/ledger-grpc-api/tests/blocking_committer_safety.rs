//! Regression tests verifying gRPC Unary, ServerStreaming (bounded + live-tail), and
//! ClientStreaming handlers offload synchronous `ExecutionService`/`ProtocolCommitter` work onto
//! blocking threads so nested `current_thread` `Runtime::block_on` never panics Tokio workers.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ledger_grpc_api::dynamic::DynCodec;
use ledger_grpc_api::server::serve_listener;
use ledger_json_api::service::{ApiError, ExecutionService, ProtocolCommitter, TransactionCommit};
use prost::Message as _;
use prost_reflect::prost_types::FileDescriptorSet;
use prost_reflect::{DescriptorPool, DynamicMessage, MethodDescriptor, SerializeOptions};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tonic::client::Grpc;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

fn run_nested_current_thread_runtime() {
    // [CANTON-NOTE: INVARIANT] Mimics `canton_participant::sequencer_connect`'s private
    // `current_thread` runtime `block_on(...)`, which panics on Tokio async worker threads.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build nested current_thread runtime");
    rt.block_on(async {
        tokio::task::yield_now().await;
    });
}

#[derive(Default)]
struct NestedRuntimeCommitter {
    reject_invalid: AtomicBool,
    commits: AtomicUsize,
    allocations: AtomicUsize,
    vets: AtomicUsize,
}

impl ProtocolCommitter for NestedRuntimeCommitter {
    fn allocate_party(&self, hint: &str) -> Option<Result<String, ApiError>> {
        run_nested_current_thread_runtime();
        let n = self.allocations.fetch_add(1, Ordering::SeqCst) + 1;
        Some(Ok(format!("{hint}::1220test{n:04x}")))
    }

    fn commit(&self, _commit: &TransactionCommit) -> Result<(), ApiError> {
        run_nested_current_thread_runtime();
        if self.reject_invalid.load(Ordering::SeqCst) {
            return Err(ApiError::InvalidArgument(
                "rejected by blocking committer".to_string(),
            ));
        }
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn vet_dar(&self, _dar_bytes: &[u8]) -> Result<(), ApiError> {
        run_nested_current_thread_runtime();
        self.vets.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn descriptor_pool() -> DescriptorPool {
    let fds = FileDescriptorSet::decode(canton_proto::FILE_DESCRIPTOR_SET)
        .expect("decode vendored descriptor set");
    DescriptorPool::from_file_descriptor_set(fds).expect("build descriptor pool")
}

fn method_desc(pool: &DescriptorPool, service: &str, name: &str) -> MethodDescriptor {
    pool.get_service_by_name(service)
        .and_then(|s| s.methods().find(|m| m.name() == name))
        .unwrap_or_else(|| panic!("missing method {service}/{name}"))
}

fn dyn_from_json(desc: prost_reflect::MessageDescriptor, body: &Value) -> DynamicMessage {
    let encoded = body.to_string();
    let mut de = serde_json::Deserializer::from_str(&encoded);
    DynamicMessage::deserialize(desc, &mut de).expect("deserialize dynamic message")
}

fn dyn_to_json(msg: &DynamicMessage) -> Value {
    let opts = SerializeOptions::new()
        .skip_default_fields(false)
        .stringify_64_bit_integers(true);
    msg.serialize_with_options(serde_json::value::Serializer, &opts)
        .expect("serialize dynamic message")
}

fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let Some(v) = TABLE.iter().position(|&b| b == c) else {
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

fn sample_dar_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn sample_dar_bytes() -> Vec<u8> {
    std::fs::read(sample_dar_path()).expect("read sample-contract.dar")
}

async fn start_grpc(service: Arc<ExecutionService>) -> Channel {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");
    tokio::spawn(async move {
        let _ = serve_listener(service, listener).await;
    });
    Channel::from_shared(format!("http://{addr}"))
        .expect("valid channel uri")
        .connect()
        .await
        .expect("connect to gRPC server")
}

async fn unary_call(
    channel: &Channel,
    pool: &DescriptorPool,
    service: &str,
    method_name: &str,
    body: &Value,
) -> Result<Value, Status> {
    let method = method_desc(pool, service, method_name);
    let msg = dyn_from_json(method.input(), body);
    let mut grpc = Grpc::new(channel.clone());
    grpc.ready().await.expect("grpc ready");
    let path = http::uri::PathAndQuery::try_from(format!("/{service}/{method_name}"))
        .expect("valid grpc path");
    let resp = grpc
        .unary(Request::new(msg), path, DynCodec::new(method.output()))
        .await?;
    Ok(dyn_to_json(resp.get_ref()))
}

async fn server_stream_call(
    channel: &Channel,
    pool: &DescriptorPool,
    service: &str,
    method_name: &str,
    body: &Value,
) -> Vec<Value> {
    let method = method_desc(pool, service, method_name);
    let msg = dyn_from_json(method.input(), body);
    let mut grpc = Grpc::new(channel.clone());
    grpc.ready().await.expect("grpc ready");
    let path = http::uri::PathAndQuery::try_from(format!("/{service}/{method_name}"))
        .expect("valid grpc path");
    let mut stream = grpc
        .server_streaming(Request::new(msg), path, DynCodec::new(method.output()))
        .await
        .expect("server streaming call")
        .into_inner();
    let mut out = Vec::new();
    while let Some(item) = stream.message().await.expect("stream frame") {
        out.push(dyn_to_json(&item));
    }
    out
}

async fn client_stream_call(
    channel: &Channel,
    pool: &DescriptorPool,
    service: &str,
    method_name: &str,
    bodies: &[Value],
) -> Value {
    let method = method_desc(pool, service, method_name);
    let msgs: Vec<DynamicMessage> = bodies
        .iter()
        .map(|b| dyn_from_json(method.input(), b))
        .collect();
    let mut grpc = Grpc::new(channel.clone());
    grpc.ready().await.expect("grpc ready");
    let path = http::uri::PathAndQuery::try_from(format!("/{service}/{method_name}"))
        .expect("valid grpc path");
    let resp = grpc
        .client_streaming(
            Request::new(tokio_stream::iter(msgs)),
            path,
            DynCodec::new(method.output()),
        )
        .await
        .expect("client streaming call");
    dyn_to_json(resp.get_ref())
}

fn create_asset_holding_req(party: &str, cmd_id: &str) -> Value {
    json!({
        "commands": {
            "commandId": cmd_id,
            "actAs": [party],
            "userId": "participant_admin",
            "commands": [{
                "create": {
                    "templateId": {
                        "packageId": "#sample-contract",
                        "moduleName": "AssetHolding",
                        "entityName": "AssetHolding"
                    },
                    "createArguments": {
                        "fields": [
                            { "label": "bank", "value": { "party": party } },
                            { "label": "owner", "value": { "party": party } },
                            { "label": "auditor", "value": { "party": party } },
                            { "label": "assetSymbol", "value": { "text": "USD" } },
                            { "label": "amount", "value": { "numeric": "42.0" } }
                        ]
                    }
                }
            }]
        },
        "transactionFormat": {
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
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_handlers_isolate_nested_runtime_committer() {
    let committer = Arc::new(NestedRuntimeCommitter::default());
    let service = Arc::new(ExecutionService::new());
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");
    service.set_committer(Arc::clone(&committer) as Arc<dyn ProtocolCommitter>);

    let pool = descriptor_pool();
    let channel = start_grpc(Arc::clone(&service)).await;

    // 1) Unary: AllocateParty (hits `ProtocolCommitter::allocate_party`).
    let alloc = unary_call(
        &channel,
        &pool,
        "com.daml.ledger.api.v2.admin.PartyManagementService",
        "AllocateParty",
        &json!({ "partyIdHint": "bank", "identityProviderId": "" }),
    )
    .await
    .expect("AllocateParty over gRPC must succeed");
    let party = alloc["partyDetails"]["party"]
        .as_str()
        .expect("allocated party")
        .to_string();
    assert!(party.starts_with("bank::1220test"), "{party}");

    // 2) Unary: Admin PackageService/UploadDar (hits `ProtocolCommitter::vet_dar`).
    let dar_b64 = b64_encode(&sample_dar_bytes());
    let up = unary_call(
        &channel,
        &pool,
        "com.digitalasset.canton.admin.participant.v30.PackageService",
        "UploadDar",
        &json!({ "dars": [{ "bytes": dar_b64 }], "vetAllPackages": true }),
    )
    .await
    .expect("Admin UploadDar over gRPC must succeed");
    assert!(!up["darIds"].as_array().expect("darIds").is_empty());

    // 3) Unary: CommandService/SubmitAndWaitForTransaction (hits `ProtocolCommitter::commit`).
    let tx1 = unary_call(
        &channel,
        &pool,
        "com.daml.ledger.api.v2.CommandService",
        "SubmitAndWaitForTransaction",
        &create_asset_holding_req(&party, "grpc-cmd-1"),
    )
    .await
    .expect("SubmitAndWaitForTransaction over gRPC must succeed");
    assert_eq!(tx1["transaction"]["commandId"], "grpc-cmd-1");
    let offset1: i64 = tx1["transaction"]["offset"]
        .as_str()
        .expect("offset")
        .parse()
        .expect("numeric offset");

    // 4) Bounded ServerStreaming: StateService/GetActiveContracts.
    let acs = server_stream_call(
        &channel,
        &pool,
        "com.daml.ledger.api.v2.StateService",
        "GetActiveContracts",
        &json!({
            "eventFormat": {
                "filtersByParty": {
                    (party.clone()): {
                        "cumulative": [{ "wildcardFilter": { "includeCreatedEventBlob": false } }]
                    }
                },
                "verbose": true
            },
            "activeAtOffset": offset1.to_string()
        }),
    )
    .await;
    assert_eq!(acs.len(), 1);

    // 5) Live-tail ServerStreaming: open GetUpdates without endInclusive and commit a second tx.
    let get_updates_method =
        method_desc(&pool, "com.daml.ledger.api.v2.UpdateService", "GetUpdates");
    let live_req = dyn_from_json(
        get_updates_method.input(),
        &json!({
            "beginExclusive": offset1.to_string(),
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": {
                        "filtersByParty": {
                            (party.clone()): {
                                "cumulative": [{ "wildcardFilter": { "includeCreatedEventBlob": false } }]
                            }
                        },
                        "verbose": true
                    },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                }
            }
        }),
    );
    let mut live_grpc = Grpc::new(channel.clone());
    live_grpc.ready().await.expect("live grpc ready");
    let live_path: http::uri::PathAndQuery = "/com.daml.ledger.api.v2.UpdateService/GetUpdates"
        .parse()
        .expect("updates path");
    let mut live_stream = live_grpc
        .server_streaming(
            Request::new(live_req),
            live_path,
            DynCodec::new(get_updates_method.output()),
        )
        .await
        .expect("live GetUpdates start")
        .into_inner();

    let tx2 = unary_call(
        &channel,
        &pool,
        "com.daml.ledger.api.v2.CommandService",
        "SubmitAndWaitForTransaction",
        &create_asset_holding_req(&party, "grpc-cmd-2"),
    )
    .await
    .expect("second SubmitAndWaitForTransaction must succeed");
    assert_eq!(tx2["transaction"]["commandId"], "grpc-cmd-2");

    let live_item = tokio::time::timeout(Duration::from_secs(3), live_stream.message())
        .await
        .expect("timed out waiting for live gRPC update")
        .expect("live stream frame result")
        .expect("expected live update item");
    assert_eq!(
        dyn_to_json(&live_item)["transaction"]["commandId"],
        "grpc-cmd-2"
    );

    // 6) ClientStreaming: ExportTopologySnapshotV2 -> ImportTopologySnapshotV2 via spawn_blocking.
    let exported = server_stream_call(
        &channel,
        &pool,
        "com.digitalasset.canton.topology.admin.v30.TopologyManagerReadService",
        "ExportTopologySnapshotV2",
        &json!({}),
    )
    .await;
    let mut snap = Vec::new();
    for frame in exported {
        snap.extend_from_slice(&b64_decode(frame["chunk"].as_str().expect("chunk")));
    }
    let _ = client_stream_call(
        &channel,
        &pool,
        "com.digitalasset.canton.topology.admin.v30.TopologyManagerWriteService",
        "ImportTopologySnapshotV2",
        &[json!({
            "topologySnapshot": b64_encode(&snap),
            "store": { "authorized": {} }
        })],
    )
    .await;

    assert!(committer.allocations.load(Ordering::SeqCst) >= 1);
    assert!(committer.vets.load(Ordering::SeqCst) >= 1);
    assert_eq!(committer.commits.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_committer_rejection_returns_typed_status_not_panic_negative_control() {
    let committer = Arc::new(NestedRuntimeCommitter::default());
    let service = Arc::new(ExecutionService::new());
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");
    service.set_committer(Arc::clone(&committer) as Arc<dyn ProtocolCommitter>);

    let pool = descriptor_pool();
    let channel = start_grpc(Arc::clone(&service)).await;
    let alloc = unary_call(
        &channel,
        &pool,
        "com.daml.ledger.api.v2.admin.PartyManagementService",
        "AllocateParty",
        &json!({ "partyIdHint": "bank_neg", "identityProviderId": "" }),
    )
    .await
    .expect("AllocateParty");
    let party = alloc["partyDetails"]["party"]
        .as_str()
        .expect("allocated party")
        .to_string();

    committer.reject_invalid.store(true, Ordering::SeqCst);
    let err = unary_call(
        &channel,
        &pool,
        "com.daml.ledger.api.v2.CommandService",
        "SubmitAndWaitForTransaction",
        &create_asset_holding_req(&party, "grpc-neg-cmd"),
    )
    .await
    .expect_err("rejected commit must fail with typed gRPC status");
    assert_eq!(
        err.code(),
        Code::InvalidArgument,
        "unexpected status: {err}"
    );
    assert!(
        err.message().contains("rejected by blocking committer"),
        "{err}"
    );
}
