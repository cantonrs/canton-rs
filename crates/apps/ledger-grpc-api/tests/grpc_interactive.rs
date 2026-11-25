//! S-API-024: External party onboarding and InteractiveSubmissionService V2/V3 over gRPC.
use std::{path::PathBuf, sync::Arc};

use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
use ledger_grpc_api::{dynamic::DynCodec, server::serve_listener};
use ledger_json_api::ExecutionService;
use prost_reflect::{DescriptorPool, DeserializeOptions, DynamicMessage, SerializeOptions};
use serde_json::{json, Value as Json};
use tonic::{client::Grpc, transport::Channel, Request, Status};

const PACKAGE: &str = "com.daml.ledger.api.v2.";

fn b64_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(text: &str) -> Vec<u8> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.trim_end_matches('=').bytes() {
        let Some(v) = B64.iter().position(|b| *b == c) else {
            continue;
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

async fn call_unary(
    channel: &Channel,
    pool: &DescriptorPool,
    rpc: &str,
    body: Json,
) -> Result<Json, Status> {
    let (svc, name) = rpc.split_once('/').expect("Service/Method");
    let method = pool
        .get_service_by_name(&format!("{PACKAGE}{svc}"))
        .and_then(|s| s.methods().find(|m| m.name() == name))
        .unwrap_or_else(|| panic!("unknown method {rpc}"));
    let opts_in = DeserializeOptions::new().deny_unknown_fields(false);
    let req_msg = DynamicMessage::deserialize_with_options(method.input(), body, &opts_in)
        .unwrap_or_else(|e| panic!("deserialize {rpc}: {e}"));
    let mut grpc = Grpc::new(channel.clone());
    grpc.ready().await.expect("ready");
    let path = http::uri::PathAndQuery::try_from(format!("/{PACKAGE}{svc}/{name}")).expect("path");
    let resp = grpc
        .unary(Request::new(req_msg), path, DynCodec::new(method.output()))
        .await?;
    let opts_out = SerializeOptions::new()
        .skip_default_fields(true)
        .stringify_64_bit_integers(false);
    Ok(resp
        .into_inner()
        .serialize_with_options(serde_json::value::Serializer, &opts_out)
        .expect("serialize response"))
}

fn sign_hash_b64(sk: &SigningKey, fp: &str, hash_b64: &str) -> Json {
    let digest = b64_decode(hash_b64);
    let sig = sk.sign(&digest);
    json!({
        "format": "SIGNATURE_FORMAT_CONCAT",
        "signature": b64_encode(&sig.to_bytes()),
        "signedBy": fp,
        "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
    })
}

fn setup_service() -> ExecutionService {
    let service = ExecutionService::new();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    service
        .load_dar(&root.join("tests/oracle/tx-corpus/tx-corpus.dar"))
        .expect("tx-corpus.dar");
    service
        .load_dar(&root.join("tests/oracle/key-diff/key-diff.dar"))
        .expect("key-diff.dar");
    service
}

#[test]
fn grpc_external_party_and_interactive_prepare_execute_roundtrip() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(setup_service());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_listener(std::sync::Arc::clone(&service), listener));

        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();

        let syncs = call_unary(
            &channel,
            &pool,
            "StateService/GetConnectedSynchronizers",
            json!({}),
        )
        .await
        .expect("GetConnectedSynchronizers");
        let sync_id = syncs["connectedSynchronizers"][0]["synchronizerId"]
            .as_str()
            .unwrap()
            .to_string();

        let mut sk_bytes = [0u8; 32];
        sk_bytes[0] = 17;
        let sk = SigningKey::from_bytes(&sk_bytes);
        let spki = sk.verifying_key().to_public_key_der().unwrap();

        let gen = call_unary(
            &channel,
            &pool,
            "admin.PartyManagementService/GenerateExternalPartyTopology",
            json!({
                "synchronizer": sync_id,
                "partyHint": "grpc_ext",
                "publicKey": {
                    "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
                    "keyData": b64_encode(spki.as_bytes()),
                    "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"
                }
            }),
        )
        .await
        .expect("GenerateExternalPartyTopology");
        let party_id = gen["partyId"].as_str().unwrap().to_string();
        let fp = gen["publicKeyFingerprint"].as_str().unwrap().to_string();
        let topo0 = gen["topologyTransactions"][0].as_str().unwrap().to_string();
        let multi_hash = gen["multiHash"].as_str().unwrap().to_string();
        assert_eq!(b64_decode(&multi_hash).len(), 34);

        let alloc = call_unary(
            &channel,
            &pool,
            "admin.PartyManagementService/AllocateExternalParty",
            json!({
                "synchronizer": sync_id,
                "onboardingTransactions": [{ "transaction": topo0, "signatures": [] }],
                "multiHashSignatures": [sign_hash_b64(&sk, &fp, &multi_hash)]
            }),
        )
        .await
        .expect("AllocateExternalParty");
        assert_eq!(alloc["partyId"], party_id);

        // Prepare + ExecuteAndWaitForTransaction with V3 (keyed Item create)
        let prep = call_unary(
            &channel,
            &pool,
            "interactive.InteractiveSubmissionService/PrepareSubmission",
            json!({
                "userId": "participant_admin",
                "commandId": "grpc-v3-create",
                "actAs": [party_id],
                "synchronizerId": sync_id,
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3",
                "commands": [{
                    "create": {
                        "templateId": {
                            "packageId": "#key-diff",
                            "moduleName": "Keys",
                            "entityName": "Item"
                        },
                        "createArguments": {
                            "fields": [
                                { "label": "owner", "value": { "party": party_id } },
                                { "label": "label", "value": { "text": "grpc-k1" } },
                                { "label": "note", "value": { "text": "v1" } }
                            ]
                        }
                    }
                }]
            }),
        )
        .await
        .expect("PrepareSubmission");
        assert!(
            prep["preparedTransaction"]["transaction"]["nodes"]
                .as_array()
                .is_some_and(|n| !n.is_empty()),
            "expected populated PreparedTransaction message: {prep}"
        );
        let prep_hash = prep["preparedTransactionHash"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(b64_decode(&prep_hash).len(), 32);

        let exec_tx = call_unary(
            &channel,
            &pool,
            "interactive.InteractiveSubmissionService/ExecuteSubmissionAndWaitForTransaction",
            json!({
                "userId": "participant_admin",
                "preparedTransaction": prep["preparedTransaction"],
                "partySignatures": {
                    "signatures": [{
                        "party": party_id,
                        "signatures": [sign_hash_b64(&sk, &fp, &prep_hash)]
                    }]
                },
                "deduplicationDuration": "30s",
                "submissionId": "sub-grpc-v3-create",
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3"
            }),
        )
        .await
        .expect("ExecuteSubmissionAndWaitForTransaction");
        let ext_hash_hex = exec_tx["transaction"]["externalTransactionHash"]
            .as_str()
            .unwrap();
        assert_eq!(ext_hash_hex.len(), 64);

        // Verify GetCompletionByHash and GetUpdateByHash over gRPC
        let comp = call_unary(
            &channel,
            &pool,
            "CommandCompletionService/GetCompletionByHash",
            json!({
                "transactionHash": prep_hash,
                "parties": [party_id]
            }),
        )
        .await
        .expect("GetCompletionByHash");
        assert_eq!(comp["acceptedCompletion"]["commandId"], "grpc-v3-create");

        let upd = call_unary(
            &channel,
            &pool,
            "UpdateService/GetUpdateByHash",
            json!({
                "transactionHash": prep_hash,
                "updateFormat": {
                    "includeTransactions": {
                        "eventFormat": {
                            "filtersByParty": { (party_id.clone()): {} }
                        },
                        "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                    }
                }
            }),
        )
        .await
        .expect("GetUpdateByHash");
        assert_eq!(
            upd["transaction"]["externalTransactionHash"],
            json!(ext_hash_hex)
        );

        // ExerciseByKey over interactive PrepareSubmission -> ExecuteSubmissionAndWait
        let key_prep = call_unary(
            &channel,
            &pool,
            "interactive.InteractiveSubmissionService/PrepareSubmission",
            json!({
                "userId": "participant_admin",
                "commandId": "grpc-v3-exkey",
                "actAs": [party_id],
                "synchronizerId": sync_id,
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3",
                "commands": [{
                    "exerciseByKey": {
                        "templateId": {
                            "packageId": "#key-diff",
                            "moduleName": "Keys",
                            "entityName": "Item"
                        },
                        "contractKey": {
                            "record": {
                                "fields": [
                                    { "label": "_1", "value": { "party": party_id } },
                                    { "label": "_2", "value": { "text": "grpc-k1" } }
                                ]
                            }
                        },
                        "choice": "Rename",
                        "choiceArgument": {
                            "record": {
                                "fields": [
                                    { "label": "newLabel", "value": { "text": "grpc-k2" } }
                                ]
                            }
                        }
                    }
                }]
            }),
        )
        .await
        .expect("PrepareSubmission ExerciseByKey");
        let key_hash = key_prep["preparedTransactionHash"]
            .as_str()
            .unwrap()
            .to_string();
        let key_wait = call_unary(
            &channel,
            &pool,
            "interactive.InteractiveSubmissionService/ExecuteSubmissionAndWait",
            json!({
                "userId": "participant_admin",
                "preparedTransaction": key_prep["preparedTransaction"],
                "partySignatures": {
                    "signatures": [{
                        "party": party_id,
                        "signatures": [sign_hash_b64(&sk, &fp, &key_hash)]
                    }]
                },
                "submissionId": "sub-grpc-v3-exkey",
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3"
            }),
        )
        .await
        .expect("ExecuteSubmissionAndWait");
        assert!(key_wait["updateId"].as_str().unwrap().starts_with("1220"));

        server.abort();
    });
}

#[test]
fn grpc_oracle_canton_signature_replay() {
    let raw = include_str!(
        "../../../../tests/oracle/interactive-prepare/canton-3.7.2-interactive-matrix.json"
    );
    let m: Json = serde_json::from_str(raw).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(setup_service());
        service
            .v2_state()
            .set_synchronizer_id_for_test(m["synchronizerId"].as_str().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_listener(std::sync::Arc::clone(&service), listener));

        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        let pt_desc = pool
            .get_message_by_name("com.daml.ledger.api.v2.interactive.PreparedTransaction")
            .unwrap();
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();

        let alloc = call_unary(
            &channel,
            &pool,
            "admin.PartyManagementService/AllocateExternalParty",
            m["externalPartyOnboarding"]["allocateRequest"].clone(),
        )
        .await
        .expect("oracle AllocateExternalParty over gRPC");
        assert_eq!(
            alloc["partyId"],
            m["externalPartyOnboarding"]["allocateResponse"]["partyId"]
        );

        let c1 = &m["cases"]["v2CreateNoteAndExecuteTx"];
        let pt_bytes = b64_decode(
            c1["executeRequest"]["preparedTransaction"]
                .as_str()
                .unwrap(),
        );
        let pt_msg = DynamicMessage::decode(pt_desc, pt_bytes.as_slice()).unwrap();
        let pt_json = pt_msg
            .serialize_with_options(
                serde_json::value::Serializer,
                &SerializeOptions::new()
                    .skip_default_fields(true)
                    .stringify_64_bit_integers(false),
            )
            .unwrap();

        let mut exec_req = c1["executeRequest"].clone();
        exec_req["preparedTransaction"] = pt_json;
        exec_req
            .as_object_mut()
            .unwrap()
            .remove("deduplicationPeriod");

        let exec_resp = call_unary(
            &channel,
            &pool,
            "interactive.InteractiveSubmissionService/ExecuteSubmissionAndWaitForTransaction",
            exec_req,
        )
        .await
        .expect("oracle ExecuteSubmissionAndWaitForTransaction over gRPC");
        assert_eq!(
            exec_resp["transaction"]["externalTransactionHash"],
            c1["executeResponse"]["transaction"]["externalTransactionHash"]
        );

        server.abort();
    });
}

#[test]
fn grpc_synchronizer_rejected_completions_stream_and_by_hash() {
    use ledger_json_api::service::{ApiError, ProtocolCommitter, TransactionCommit};

    struct AlwaysTimeout;
    impl ProtocolCommitter for AlwaysTimeout {
        fn commit(&self, _commit: &TransactionCommit) -> Result<(), ApiError> {
            Err(ApiError::SynchronizerRejected {
                code: "MEDIATOR_SAYS_TX_TIMED_OUT".into(),
                cause: "no verdict within timeout".into(),
                grpc_code: 10,
                http_status: 409,
                category: 2,
                details: None,
            })
        }
    }

    async fn call_stream_one(
        channel: &Channel,
        pool: &DescriptorPool,
        rpc: &str,
        body: Json,
    ) -> Json {
        let (svc, name) = rpc.split_once('/').expect("Service/Method");
        let method = pool
            .get_service_by_name(&format!("{PACKAGE}{svc}"))
            .and_then(|s| s.methods().find(|m| m.name() == name))
            .unwrap();
        let opts_in = DeserializeOptions::new().deny_unknown_fields(false);
        let req_msg =
            DynamicMessage::deserialize_with_options(method.input(), body, &opts_in).unwrap();
        let mut grpc = Grpc::new(channel.clone());
        grpc.ready().await.unwrap();
        let path = http::uri::PathAndQuery::try_from(format!("/{PACKAGE}{svc}/{name}")).unwrap();
        let mut stream = grpc
            .server_streaming(Request::new(req_msg), path, DynCodec::new(method.output()))
            .await
            .unwrap()
            .into_inner();
        let item = stream
            .message()
            .await
            .unwrap()
            .expect("one completion item");
        let opts_out = SerializeOptions::new()
            .skip_default_fields(true)
            .stringify_64_bit_integers(false);
        item.serialize_with_options(serde_json::value::Serializer, &opts_out)
            .unwrap()
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(setup_service());
        service.set_committer(Arc::new(AlwaysTimeout));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_listener(std::sync::Arc::clone(&service), listener));

        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();

        let syncs = call_unary(
            &channel,
            &pool,
            "StateService/GetConnectedSynchronizers",
            json!({}),
        )
        .await
        .unwrap();
        let sync_id = syncs["connectedSynchronizers"][0]["synchronizerId"]
            .as_str()
            .unwrap()
            .to_string();

        let mut sk_bytes = [0u8; 32];
        sk_bytes[0] = 91;
        let sk = SigningKey::from_bytes(&sk_bytes);
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        let gen = call_unary(
            &channel,
            &pool,
            "admin.PartyManagementService/GenerateExternalPartyTopology",
            json!({
                "synchronizer": sync_id,
                "partyHint": "grpc_rej",
                "publicKey": {
                    "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
                    "keyData": b64_encode(spki.as_bytes()),
                    "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"
                }
            }),
        )
        .await
        .unwrap();
        let party_id = gen["partyId"].as_str().unwrap().to_string();
        let fp = gen["publicKeyFingerprint"].as_str().unwrap().to_string();
        let topo0 = gen["topologyTransactions"][0].as_str().unwrap().to_string();
        let multi_hash = gen["multiHash"].as_str().unwrap().to_string();
        call_unary(
            &channel,
            &pool,
            "admin.PartyManagementService/AllocateExternalParty",
            json!({
                "synchronizer": sync_id,
                "onboardingTransactions": [{ "transaction": topo0, "signatures": [] }],
                "multiHashSignatures": [sign_hash_b64(&sk, &fp, &multi_hash)]
            }),
        )
        .await
        .unwrap();

        let prep = call_unary(
            &channel,
            &pool,
            "interactive.InteractiveSubmissionService/PrepareSubmission",
            json!({
                "commandId": "grpc-rej-cmd",
                "userId": "u-grpc-rej",
                "actAs": [party_id],
                "synchronizerId": sync_id,
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3",
                "commands": [{
                    "create": {
                        "templateId": { "packageId": "#key-diff", "moduleName": "Keys", "entityName": "Item" },
                        "createArguments": { "fields": [
                            { "label": "owner", "value": { "party": party_id } },
                            { "label": "label", "value": { "text": "grpc-rej-k" } },
                            { "label": "note", "value": { "text": "rejected" } }
                        ] }
                    }
                }]
            }),
        )
        .await
        .unwrap();
        let prep_tx = prep["preparedTransaction"].clone();
        let prep_hash = prep["preparedTransactionHash"].as_str().unwrap().to_string();

        let err = call_unary(
            &channel,
            &pool,
            "interactive.InteractiveSubmissionService/ExecuteSubmissionAndWait",
            json!({
                "userId": "u-grpc-rej",
                "preparedTransaction": prep_tx,
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3",
                "deduplicationDuration": "60s",
                "submissionId": "sub-grpc-rej",
                "partySignatures": {
                    "signatures": [{
                        "party": party_id,
                        "signatures": [sign_hash_b64(&sk, &fp, &prep_hash)]
                    }]
                }
            }),
        )
        .await
        .expect_err("ExecuteSubmissionAndWait should fail on synchronizer timeout");
        assert_eq!(err.code(), tonic::Code::Aborted, "{err}");
        assert!(err.message().contains("MEDIATOR_SAYS_TX_TIMED_OUT"), "{err}");

        let stream_item = call_stream_one(
            &channel,
            &pool,
            "CommandCompletionService/GetCompletions",
            json!({ "userId": "u-grpc-rej", "parties": [party_id], "beginExclusive": 0 }),
        )
        .await;
        let comp = &stream_item["completion"];
        assert_eq!(comp["commandId"], "grpc-rej-cmd");
        assert_eq!(comp["status"]["code"], 10);
        assert!(
            comp["status"]["message"]
                .as_str()
                .unwrap()
                .starts_with("MEDIATOR_SAYS_TX_TIMED_OUT(2,0): "),
            "{stream_item}"
        );

        let by_hash = call_unary(
            &channel,
            &pool,
            "CommandCompletionService/GetCompletionByHash",
            json!({ "transactionHash": prep_hash, "parties": [party_id] }),
        )
        .await
        .expect("GetCompletionByHash");
        assert!(by_hash.get("acceptedCompletion").is_none());
        let rej = by_hash["lastRejectedCompletions"].as_array().unwrap();
        assert_eq!(rej.len(), 1);
        assert_eq!(rej[0]["commandId"], "grpc-rej-cmd");
        assert_eq!(rej[0]["status"]["code"], 10);

        server.abort();
    });
}
