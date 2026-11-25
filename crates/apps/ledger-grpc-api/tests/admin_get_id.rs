//! The Admin API's `IdentityInitializationService.GetId` (the console's `participant.id`) answers the participant id the Ledger API reports.
use std::sync::Arc;

use ledger_grpc_api::{dynamic::DynCodec, server::serve_listener};
use ledger_json_api::ExecutionService;
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};
use tonic::{client::Grpc, Request};

async fn unary(
    channel: &tonic::transport::Channel,
    pool: &DescriptorPool,
    service: &str,
    name: &str,
) -> serde_json::Value {
    let method = pool
        .get_service_by_name(service)
        .and_then(|s| s.methods().find(|m| m.name() == name))
        .unwrap_or_else(|| panic!("unknown method {service}/{name}"));
    let mut grpc = Grpc::new(channel.clone());
    grpc.ready().await.expect("ready");
    let path = http::uri::PathAndQuery::try_from(format!("/{service}/{name}")).expect("path");
    let response = grpc
        .unary(
            Request::new(DynamicMessage::new(method.input())),
            path,
            DynCodec::new(method.output()),
        )
        .await
        .unwrap_or_else(|e| panic!("{service}/{name}: {e}"));
    response
        .into_inner()
        .serialize_with_options(
            serde_json::value::Serializer,
            &SerializeOptions::new()
                .skip_default_fields(false)
                .stringify_64_bit_integers(false),
        )
        .expect("serialize")
}

#[test]
fn get_id_answers_the_participant_id_of_the_ledger_api() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(service, listener));
        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let ledger = unary(
            &channel,
            &pool,
            "com.daml.ledger.api.v2.admin.PartyManagementService",
            "GetParticipantId",
        )
        .await;
        let admin = unary(
            &channel,
            &pool,
            "com.digitalasset.canton.topology.admin.v30.IdentityInitializationService",
            "GetId",
        )
        .await;
        let id = ledger["participantId"].as_str().expect("a participant id");
        assert!(!id.is_empty());
        assert_eq!(admin["uniqueIdentifier"].as_str(), Some(id));
        assert_eq!(admin["initialized"], serde_json::Value::Bool(true));
    });
}

#[test]
fn the_health_check_of_the_admin_api_says_serving() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(service, listener));
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        // the pool of the test knows the health service only through the server, so the request is built from the same descriptor the server adds
        let mut pool =
            DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        pool.add_file_descriptor_proto(ledger_grpc_api::server::health_descriptor())
            .expect("health descriptor");
        let health = unary(&channel, &pool, "grpc.health.v1.Health", "Check").await;
        assert_eq!(health["status"], serde_json::json!("SERVING"));
    });
}

#[test]
fn list_connected_synchronizers_matches_the_ledger_api() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(service, listener));
        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let ledger = unary(
            &channel,
            &pool,
            "com.daml.ledger.api.v2.StateService",
            "GetConnectedSynchronizers",
        )
        .await;
        let admin = unary(
            &channel,
            &pool,
            "com.digitalasset.canton.admin.participant.v30.SynchronizerConnectivityService",
            "ListConnectedSynchronizers",
        )
        .await;
        let from_ledger = &ledger["connectedSynchronizers"][0];
        let from_admin = &admin["connectedSynchronizers"][0];
        assert_eq!(
            from_admin["synchronizerAlias"],
            from_ledger["synchronizerAlias"]
        );
        assert_eq!(from_admin["synchronizerId"], from_ledger["synchronizerId"]);
        assert_eq!(
            from_admin["physicalSynchronizerId"],
            from_ledger["synchronizerId"]
        );
        assert_eq!(from_admin["healthy"], serde_json::Value::Bool(true));
    });
}

async fn unary_with(
    channel: &tonic::transport::Channel,
    pool: &DescriptorPool,
    service: &str,
    name: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let method = pool
        .get_service_by_name(service)
        .and_then(|s| s.methods().find(|m| m.name() == name))
        .unwrap_or_else(|| panic!("unknown method {service}/{name}"));
    let message = DynamicMessage::deserialize(method.input(), body).expect("request");
    let mut grpc = Grpc::new(channel.clone());
    grpc.ready().await.expect("ready");
    let path = http::uri::PathAndQuery::try_from(format!("/{service}/{name}")).expect("path");
    grpc.unary(Request::new(message), path, DynCodec::new(method.output()))
        .await
        .unwrap_or_else(|e| panic!("{service}/{name}: {e}"))
        .into_inner()
        .serialize_with_options(
            serde_json::value::Serializer,
            &SerializeOptions::new()
                .skip_default_fields(false)
                .stringify_64_bit_integers(false),
        )
        .expect("serialize")
}

#[test]
fn list_packages_gives_name_version_and_size_with_the_prefix_filter_and_limit() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = ExecutionService::new();
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        service
            .load_dar(&root.join("tests/oracle/tx-corpus/tx-corpus.dar"))
            .expect("tx-corpus.dar");
        let service = Arc::new(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(std::sync::Arc::clone(&service), listener));
        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let admin = "com.digitalasset.canton.admin.participant.v30.PackageService";
        let all = unary_with(
            &channel,
            &pool,
            admin,
            "ListPackages",
            serde_json::json!({}),
        )
        .await;
        let listed: Vec<&serde_json::Value> = all["packageDescriptions"]
            .as_array()
            .unwrap()
            .iter()
            .collect();
        let ledger_ids = service.package_ids();
        assert_eq!(
            listed.len(),
            ledger_ids.len(),
            "every package of the ledger is listed"
        );
        assert!(
            listed
                .iter()
                .any(|p| p["name"] == "tx-corpus" && p["version"] == "0.0.1"),
            "the loaded package has its name and version"
        );
        // the size is the payload of a package that was uploaded through the API; one loaded from a file has no payload kept
        assert!(listed.iter().all(|p| p["size"].is_number()));
        let name = listed
            .iter()
            .find_map(|p| p["name"].as_str().filter(|n| !n.is_empty()))
            .unwrap()
            .to_string();
        let by_prefix = unary_with(
            &channel,
            &pool,
            admin,
            "ListPackages",
            serde_json::json!({ "filterName": &name[..1] }),
        )
        .await;
        assert!(by_prefix["packageDescriptions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["name"].as_str().unwrap().starts_with(&name[..1])));
        let none = unary_with(
            &channel,
            &pool,
            admin,
            "ListPackages",
            serde_json::json!({ "filterName": "no-such-package" }),
        )
        .await;
        assert!(none["packageDescriptions"].as_array().unwrap().is_empty());
        let one = unary_with(
            &channel,
            &pool,
            admin,
            "ListPackages",
            serde_json::json!({ "limit": 1 }),
        )
        .await;
        assert!(one["packageDescriptions"].as_array().unwrap().len() <= 1);
    });
}

#[test]
fn participant_status_reports_the_id_version_and_connected_synchronizers() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(service, listener));
        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let id = unary(
            &channel,
            &pool,
            "com.daml.ledger.api.v2.admin.PartyManagementService",
            "GetParticipantId",
        )
        .await;
        let status = unary(
            &channel,
            &pool,
            "com.digitalasset.canton.admin.participant.v30.ParticipantStatusService",
            "ParticipantStatus",
        )
        .await;
        let common = &status["status"]["commonStatus"];
        assert_eq!(common["uid"], id["participantId"]);
        assert_eq!(common["version"], "3.7.2");
        assert_eq!(status["status"]["active"], serde_json::Value::Bool(true));
        assert_eq!(
            status["status"]["connectedSynchronizers"][0]["health"],
            "HEALTH_HEALTHY"
        );
        assert_eq!(status["status"]["supportedProtocolVersions"][0], 37);
    });
}

#[test]
fn list_dars_gives_the_main_package_of_each_loaded_dar() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = ExecutionService::new();
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let info = service
            .load_dar(&root.join("tests/oracle/tx-corpus/tx-corpus.dar"))
            .expect("tx-corpus.dar");
        let service = Arc::new(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(service, listener));
        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let admin = "com.digitalasset.canton.admin.participant.v30.PackageService";
        let all = unary_with(&channel, &pool, admin, "ListDars", serde_json::json!({})).await;
        let dars = all["dars"].as_array().unwrap();
        assert_eq!(dars.len(), 1, "one DAR is loaded: {all}");
        assert_eq!(
            dars[0]["main"].as_str(),
            Some(info.main_package_id.as_str())
        );
        assert_eq!(dars[0]["name"], "tx-corpus");
        let other = unary_with(
            &channel,
            &pool,
            admin,
            "ListDars",
            serde_json::json!({ "filterName": "zzz" }),
        )
        .await;
        assert!(other["dars"].as_array().unwrap().is_empty());
    });
}

async fn unary_typed<Req: prost::Message, Resp: prost::Message + Default>(
    channel: &tonic::transport::Channel,
    pool: &DescriptorPool,
    service: &str,
    name: &str,
    req: &Req,
) -> Result<Resp, tonic::Status> {
    let method = pool
        .get_service_by_name(service)
        .and_then(|s| s.methods().find(|m| m.name() == name))
        .unwrap_or_else(|| panic!("unknown method {service}/{name}"));
    let dyn_req =
        DynamicMessage::decode(method.input(), req.encode_to_vec().as_slice()).expect("encode req");
    let mut grpc = Grpc::new(channel.clone());
    grpc.ready().await.expect("ready");
    let path = http::uri::PathAndQuery::try_from(format!("/{service}/{name}")).expect("path");
    let resp = grpc
        .unary(Request::new(dyn_req), path, DynCodec::new(method.output()))
        .await?;
    Ok(Resp::decode(resp.into_inner().encode_to_vec().as_slice()).expect("decode resp"))
}

#[test]
fn upload_get_vet_and_remove_dar_follow_the_admin_package_lifecycle() {
    use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(std::sync::Arc::clone(&service), listener));
        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let dar_bytes = std::fs::read(root.join("tests/oracle/tx-corpus/tx-corpus.dar")).unwrap();
        let pkg_svc = "com.digitalasset.canton.admin.participant.v30.PackageService";
        let up: p30::UploadDarResponse = unary_typed(
            &channel,
            &pool,
            pkg_svc,
            "UploadDar",
            &p30::UploadDarRequest {
                dars: vec![p30::upload_dar_request::UploadDarData {
                    bytes: dar_bytes.clone(),
                    description: Some("my-tx-corpus".into()),
                    expected_main_package_id: None,
                }],
                vet_all_packages: false,
                synchronize_vetting: false,
                synchronizer_id: None,
            },
        )
        .await
        .expect("upload dar");
        assert_eq!(up.dar_ids.len(), 1);
        let main_id = up.dar_ids[0].clone();

        let listed = unary_with(&channel, &pool, pkg_svc, "ListDars", serde_json::json!({})).await;
        assert_eq!(listed["dars"][0]["main"], main_id);
        assert_eq!(listed["dars"][0]["description"], "my-tx-corpus");

        let got: p30::GetDarResponse = unary_typed(
            &channel,
            &pool,
            pkg_svc,
            "GetDar",
            &p30::GetDarRequest {
                main_package_id: main_id.clone(),
            },
        )
        .await
        .expect("get dar");
        assert_eq!(got.payload, dar_bytes);
        let desc = got.data.expect("dar description");
        assert_eq!(desc.main, main_id);
        assert_eq!(desc.name, "tx-corpus");
        assert_eq!(desc.description, "my-tx-corpus");

        let unvetted = unary_with(
            &channel,
            &pool,
            "com.daml.ledger.api.v2.PackageService",
            "ListVettedPackages",
            serde_json::json!({}),
        )
        .await;
        assert!(unvetted["vettedPackages"].as_array().unwrap().is_empty());

        let _: p30::VetDarResponse = unary_typed(
            &channel,
            &pool,
            pkg_svc,
            "VetDar",
            &p30::VetDarRequest {
                main_package_id: main_id.clone(),
                synchronize: false,
                synchronizer_id: None,
            },
        )
        .await
        .expect("vet dar");
        let vetted = unary_with(
            &channel,
            &pool,
            "com.daml.ledger.api.v2.PackageService",
            "ListVettedPackages",
            serde_json::json!({}),
        )
        .await;
        let vetted_ids: Vec<&str> = vetted["vettedPackages"][0]["packages"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["packageId"].as_str())
            .collect();
        assert!(
            vetted_ids.contains(&main_id.as_str()),
            "main package should be vetted"
        );

        let _: p30::RemoveDarResponse = unary_typed(
            &channel,
            &pool,
            pkg_svc,
            "RemoveDar",
            &p30::RemoveDarRequest {
                main_package_id: main_id.clone(),
            },
        )
        .await
        .expect("remove dar");
        let after = unary_with(&channel, &pool, pkg_svc, "ListDars", serde_json::json!({})).await;
        assert!(after["dars"].as_array().unwrap().is_empty());
        let missing = unary_typed::<_, p30::GetDarResponse>(
            &channel,
            &pool,
            pkg_svc,
            "GetDar",
            &p30::GetDarRequest {
                main_package_id: main_id,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);
        assert!(missing.message().contains("DAR_NOT_FOUND"), "{missing}");
    });
}

#[test]
fn upload_and_remove_dar_refuse_mismatch_unknown_synchronizer_and_active_contract() {
    use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
    use ledger_json_api::{dispatch_request, HttpRequest};
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = Arc::new(ExecutionService::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_listener(std::sync::Arc::clone(&service), listener));
        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor");
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let sample_bytes = std::fs::read(root.join("contracts/target/sample-contract.dar")).unwrap();
        let pkg_svc = "com.digitalasset.canton.admin.participant.v30.PackageService";

        // 1. expected_main_package_id mismatch is rejected before loading
        let mismatch = unary_typed::<_, p30::UploadDarResponse>(
            &channel,
            &pool,
            pkg_svc,
            "UploadDar",
            &p30::UploadDarRequest {
                dars: vec![p30::upload_dar_request::UploadDarData {
                    bytes: sample_bytes.clone(),
                    description: None,
                    expected_main_package_id: Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
                }],
                vet_all_packages: false,
                synchronize_vetting: false,
                synchronizer_id: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(mismatch.code(), tonic::Code::InvalidArgument);
        assert!(mismatch.message().contains("MAIN_PACKAGE_IN_DAR_DOES_NOT_MATCH_EXPECTED"));

        // 2. unknown synchronizer_id is rejected
        let unknown_sync = unary_typed::<_, p30::UploadDarResponse>(
            &channel,
            &pool,
            pkg_svc,
            "UploadDar",
            &p30::UploadDarRequest {
                dars: vec![p30::upload_dar_request::UploadDarData {
                    bytes: sample_bytes.clone(),
                    description: None,
                    expected_main_package_id: None,
                }],
                vet_all_packages: true,
                synchronize_vetting: false,
                synchronizer_id: Some("unknown::1220deadbeef".into()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(unknown_sync.code(), tonic::Code::FailedPrecondition);
        assert!(unknown_sync.message().contains("PACKAGE_SERVICE_NOT_CONNECTED_TO_SYNCHRONIZER"));

        // 3. upload + create an active contract -> RemoveDar must refuse
        let up: p30::UploadDarResponse = unary_typed(
            &channel,
            &pool,
            pkg_svc,
            "UploadDar",
            &p30::UploadDarRequest {
                dars: vec![p30::upload_dar_request::UploadDarData {
                    bytes: sample_bytes,
                    description: None,
                    expected_main_package_id: None,
                }],
                vet_all_packages: true,
                synchronize_vetting: false,
                synchronizer_id: None,
            },
        )
        .await
        .unwrap();
        let main_id = up.dar_ids[0].clone();
        let party_resp = dispatch_request(
            &service,
            &HttpRequest {
                method: "POST".into(),
                path: "/v2/parties".into(),
                query_params: Default::default(),
                headers: [("content-type".into(), "application/json".into())].into(),
                body: br#"{"partyIdHint":"dar-holder"}"#.to_vec(),
            },
        );
        assert_eq!(party_resp.status, 200);
        let party_json: serde_json::Value = serde_json::from_slice(&party_resp.body).unwrap();
        let party = party_json["partyDetails"]["party"].as_str().unwrap();
        let create_body = serde_json::json!({
            "commands": [{
                "CreateCommand": {
                    "templateId": format!("{main_id}:AssetHolding:AssetHolding"),
                    "createArguments": { "bank": party, "owner": party, "auditor": party, "assetSymbol": "USD", "amount": "1.0" }
                }
            }],
            "commandId": "hold-dar",
            "actAs": [party],
            "userId": "ledger-api-user"
        });
        let create_resp = dispatch_request(
            &service,
            &HttpRequest {
                method: "POST".into(),
                path: "/v2/commands/submit-and-wait".into(),
                query_params: Default::default(),
                headers: [("content-type".into(), "application/json".into())].into(),
                body: serde_json::to_vec(&create_body).unwrap(),
            },
        );
        assert_eq!(create_resp.status, 200, "{}", String::from_utf8_lossy(&create_resp.body));

        let in_use = unary_typed::<_, p30::RemoveDarResponse>(
            &channel,
            &pool,
            pkg_svc,
            "RemoveDar",
            &p30::RemoveDarRequest { main_package_id: main_id.clone() },
        )
        .await
        .unwrap_err();
        assert_eq!(in_use.code(), tonic::Code::FailedPrecondition);
        assert!(in_use.message().contains("PACKAGE_OR_DAR_REMOVAL_ERROR"), "{in_use}");
    });
}

#[test]
fn ping_service_pings_local_party_archives_contract_and_guards_builtin_dar() {
    use std::time::Duration;

    use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
    use ledger_json_api::v2_packages::ADMIN_PING_PACKAGE_ID;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let service = Arc::new(ExecutionService::new());
        let server_service = Arc::clone(&service);
        tokio::spawn(async move {
            let _ = ledger_grpc_api::server::serve_admin_listener(server_service, listener).await;
        });

        let endpoint = format!("http://{addr}");
        let mut channel = None;
        for _ in 0..20 {
            if let Ok(ch) = tonic::transport::Endpoint::from_shared(endpoint.clone())
                .unwrap()
                .connect()
                .await
            {
                channel = Some(ch);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let channel = channel.expect("server responds");
        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).unwrap();
        let ping_svc = "com.digitalasset.canton.admin.participant.v30.PingService";
        let pkg_svc = "com.digitalasset.canton.admin.participant.v30.PackageService";

        let self_party = service.participant_id();
        let ok = unary_typed::<_, p30::PingResponse>(
            &channel,
            &pool,
            ping_svc,
            "Ping",
            &p30::PingRequest {
                target_parties: vec![self_party.clone()],
                validators: vec![],
                timeout: Some(prost_reflect::prost_types::Duration {
                    seconds: 5,
                    nanos: 0,
                }),
                levels: 0,
                synchronizer_id: String::new(),
                workflow_id: String::new(),
                id: "local-ping-1".into(),
            },
        )
        .await
        .unwrap();
        match ok.response.expect("ping response variant") {
            p30::ping_response::Response::Success(s) => {
                assert_eq!(s.responder, self_party);
                assert!(s.ping_time < 5_000, "unexpected ping_time={}", s.ping_time);
            }
            p30::ping_response::Response::Failure(f) => {
                panic!("unexpected PingFailure: {}", f.reason)
            }
        }
        assert!(
            service
                .v2_active_contracts()
                .iter()
                .all(|c| c.template_id.entity_name != "Ping"),
            "responded Ping contract must be archived from ACS"
        );

        // Negative control: empty target_parties -> PingFailure
        let empty = unary_typed::<_, p30::PingResponse>(
            &channel,
            &pool,
            ping_svc,
            "Ping",
            &p30::PingRequest {
                target_parties: vec![],
                validators: vec![],
                timeout: Some(prost_reflect::prost_types::Duration {
                    seconds: 2,
                    nanos: 0,
                }),
                levels: 0,
                synchronizer_id: String::new(),
                workflow_id: String::new(),
                id: String::new(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            empty.response,
            Some(p30::ping_response::Response::Failure(p30::PingFailure { ref reason }))
                if reason.contains("No target parties")
        ));

        // Negative control: missing timeout -> InvalidArgument
        let missing_timeout = unary_typed::<_, p30::PingResponse>(
            &channel,
            &pool,
            ping_svc,
            "Ping",
            &p30::PingRequest {
                target_parties: vec![self_party.clone()],
                validators: vec![],
                timeout: None,
                levels: 0,
                synchronizer_id: String::new(),
                workflow_id: String::new(),
                id: String::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(missing_timeout.code(), tonic::Code::InvalidArgument);

        // Negative control: remote/silent responder without a Nanobot -> PingFailure timeout
        let timed_out = unary_typed::<_, p30::PingResponse>(
            &channel,
            &pool,
            ping_svc,
            "Ping",
            &p30::PingRequest {
                target_parties: vec!["silent::deadbeef".into()],
                validators: vec![],
                timeout: Some(prost_reflect::prost_types::Duration {
                    seconds: 0,
                    nanos: 200_000_000,
                }),
                levels: 0,
                synchronizer_id: String::new(),
                workflow_id: String::new(),
                id: "timeout-ping".into(),
            },
        )
        .await
        .unwrap();
        assert!(
            matches!(
                timed_out.response,
                Some(p30::ping_response::Response::Failure(p30::PingFailure { ref reason }))
                    if reason.starts_with("Timeout:")
            ),
            "expected Timeout PingFailure, got {:?}",
            timed_out.response
        );

        // Negative control: RemoveDar refuses deleting the built-in admin Ping DAR
        let remove_builtin = unary_typed::<_, p30::RemoveDarResponse>(
            &channel,
            &pool,
            pkg_svc,
            "RemoveDar",
            &p30::RemoveDarRequest {
                main_package_id: ADMIN_PING_PACKAGE_ID.to_string(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(remove_builtin.code(), tonic::Code::FailedPrecondition);
        assert!(
            remove_builtin
                .message()
                .contains("PACKAGE_OR_DAR_REMOVAL_ERROR"),
            "{remove_builtin}"
        );
    });
}

#[cfg(feature = "official")]
#[test]
fn ping_service_pings_remote_protocol_participant_and_receives_nanobot_response() {
    use std::time::Duration;

    use canton_participant::node::Node;
    use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
    use ledger_json_api::protocol::NodeCommitter;

    let sample_dar = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar");

    // 1. Start an in-process synchronizer (sequencer + mediator).
    let seq_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let seq_addr = seq_listener.local_addr().unwrap();
    drop(seq_listener);
    let seq_cfg = canton_sequencer_server::new_synchronizer_with_groups("pingsync", "ps1", 1);
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(canton_sequencer_server::serve(seq_addr, seq_cfg))
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(seq_addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let seq_url = format!("http://{seq_addr}");

    let connect_participant = |name: &str| {
        let node = Node::connect(&seq_url, name, &sample_dar).expect("participant connects");
        let service = Arc::new(ExecutionService::new());
        service.load_dar(&sample_dar).expect("load sample DAR");
        let committer = Arc::new(NodeCommitter::new(
            node,
            "sample-contract",
            Duration::from_secs(30),
        ));
        committer.show_remote_transactions_in(Arc::clone(&service));
        service.set_committer(committer);
        service
    };

    let alpha = connect_participant("alpha");
    let beta = connect_participant("beta");
    let alpha_uid = alpha.participant_id();
    let beta_uid = beta.participant_id();
    assert!(alpha_uid.starts_with("alpha::"), "{alpha_uid}");
    assert!(beta_uid.starts_with("beta::"), "{beta_uid}");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = l1.local_addr().unwrap();
        let a_srv = Arc::clone(&alpha);
        tokio::spawn(async move {
            let _ = ledger_grpc_api::server::serve_admin_listener(a_srv, l1).await;
        });

        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_srv = Arc::clone(&beta);
        tokio::spawn(async move {
            let _ = ledger_grpc_api::server::serve_admin_listener(b_srv, l2).await;
        });

        // Wait until beta's Ping DAR vetting has reached alpha's topology state as well as Admin listener readiness.
        let endpoint = format!("http://{addr1}");
        let mut channel = None;
        for _ in 0..40 {
            if let Ok(ch) = tonic::transport::Endpoint::from_shared(endpoint.clone())
                .unwrap()
                .connect()
                .await
            {
                channel = Some(ch);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let channel = channel.expect("alpha Admin gRPC connects");
        let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).unwrap();
        let ping_svc = "com.digitalasset.canton.admin.participant.v30.PingService";

        // Ensure both participants have vetted the built-in ping DAR and learned each other's keys/vetting.
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let resp = unary_typed::<_, p30::PingResponse>(
                &channel,
                &pool,
                ping_svc,
                "Ping",
                &p30::PingRequest {
                    target_parties: vec![beta_uid.clone()],
                    validators: vec![],
                    timeout: Some(prost_reflect::prost_types::Duration {
                        seconds: 5,
                        nanos: 0,
                    }),
                    levels: 0,
                    synchronizer_id: String::new(),
                    workflow_id: String::new(),
                    id: "cross-ping".into(),
                },
            )
            .await
            .unwrap();
            match resp.response.expect("ping response") {
                p30::ping_response::Response::Success(s) => {
                    assert_eq!(s.responder, beta_uid);
                    break;
                }
                p30::ping_response::Response::Failure(f) => {
                    if std::time::Instant::now() >= deadline {
                        panic!("2-participant protocol ping failed: {}", f.reason);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
}
