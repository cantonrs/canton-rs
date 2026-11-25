#![allow(clippy::unwrap_used, reason = "integration test")]
//! Open gRPC streams: `CompletionStream` tails the ledger and sends `OffsetCheckpoint`s (`IndexServiceImpl.getCompletions`), and a
//! stream ends with `ABORTED` when its token expires or its user's rights change (`UserBasedOngoingAuthorization`, Canton 3.7.2).
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ledger_grpc_api::admin_api::BUILTIN_PING_DAR;
use ledger_grpc_api::server::serve_listener;
use ledger_json_api::{
    auth::sign_token, dispatch_request, AuthConfig, ExecutionService, HttpRequest,
};
use prost::Message as _;
use prost_reflect::prost_types::FileDescriptorSet;
use prost_reflect::{DescriptorPool, DynamicMessage, MethodDescriptor};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tonic::transport::Channel;
use tonic::Streaming;

const SECRET: &str = "testsecret";

fn method() -> MethodDescriptor {
    let fds = FileDescriptorSet::decode(canton_proto::FILE_DESCRIPTOR_SET).unwrap();
    DescriptorPool::from_file_descriptor_set(fds)
        .unwrap()
        .get_service_by_name("com.daml.ledger.api.v2.CommandCompletionService")
        .unwrap()
        .methods()
        .find(|m| m.name() == "CompletionStream")
        .unwrap()
}

fn token(sub: &str, lifetime: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sign_token(
        SECRET,
        &json!({ "sub": sub, "scope": "daml_ledger_api", "exp": now + lifetime }),
    )
}

fn http(
    service: &ExecutionService,
    method: &str,
    path: &str,
    body: Vec<u8>,
    bearer: Option<&str>,
) -> Value {
    let mut headers = HashMap::new();
    if let Some(t) = bearer {
        headers.insert("authorization".to_string(), format!("Bearer {t}"));
    }
    let resp = dispatch_request(
        service,
        &HttpRequest {
            method: method.into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers,
            body,
        },
    );
    assert!(
        resp.status < 300,
        "{path}: {}",
        String::from_utf8_lossy(&resp.body)
    );
    serde_json::from_slice(&resp.body).unwrap_or(Value::Null)
}

/// The ping DAR, a party `alice`, and (with authentication) a user `alice_user` who acts as her.
fn ledger(service: &ExecutionService, admin: Option<&str>) -> String {
    http(
        service,
        "POST",
        "/v2/dars",
        BUILTIN_PING_DAR.to_vec(),
        admin,
    );
    let party = http(
        service,
        "POST",
        "/v2/parties",
        json!({"partyIdHint": "alice", "identityProviderId": ""})
            .to_string()
            .into_bytes(),
        admin,
    )["partyDetails"]["party"]
        .as_str()
        .unwrap()
        .to_string();
    if admin.is_some() {
        http(
            service,
            "POST",
            "/v2/users",
            json!({"user": {"id": "alice_user"}, "rights": [
                {"kind": {"CanActAs": {"value": {"party": &party}}}},
                {"kind": {"CanReadAs": {"value": {"party": &party}}}}
            ]})
            .to_string()
            .into_bytes(),
            admin,
        );
    }
    party
}

fn ping(service: &ExecutionService, party: &str, id: &str, user: &str, bearer: Option<&str>) {
    let pkg = ledger_json_api::v2_packages::ADMIN_PING_PACKAGE_ID;
    http(
        service,
        "POST",
        "/v2/commands/submit-and-wait",
        json!({"commands": [{"CreateCommand": {
            "templateId": format!("{pkg}:Canton.Internal.Ping:Ping"),
            "createArguments": {"id": id, "initiator": party, "responder": party}}}],
            "commandId": id, "actAs": [party], "userId": user})
        .to_string()
        .into_bytes(),
        bearer,
    );
}

async fn serve(service: Arc<ExecutionService>) -> Channel {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = serve_listener(service, listener).await;
    });
    Channel::from_shared(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

async fn completion_stream(
    channel: Channel,
    request: Value,
    bearer: Option<&str>,
) -> Streaming<DynamicMessage> {
    let m = method();
    let msg = DynamicMessage::deserialize(m.input(), request).unwrap();
    let mut req = tonic::Request::new(msg);
    if let Some(t) = bearer {
        req.metadata_mut()
            .insert("authorization", format!("Bearer {t}").parse().unwrap());
    }
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.unwrap();
    client
        .server_streaming(
            req,
            "/com.daml.ledger.api.v2.CommandCompletionService/CompletionStream"
                .parse()
                .unwrap(),
            ledger_grpc_api::dynamic::DynCodec::new(m.output()),
        )
        .await
        .unwrap()
        .into_inner()
}

/// The next message as protobuf JSON, `None` when the stream ended normally, the status when it failed.
async fn next(
    stream: &mut Streaming<DynamicMessage>,
    within: Duration,
) -> Result<Option<Value>, tonic::Status> {
    let msg = tokio::time::timeout(within, stream.message())
        .await
        .expect("a message or the end of the stream in time")?;
    let opts = prost_reflect::SerializeOptions::new().stringify_64_bit_integers(false);
    Ok(msg.map(|m| {
        m.serialize_with_options(serde_json::value::Serializer, &opts)
            .unwrap()
    }))
}

#[tokio::test]
async fn a_completion_stream_stays_open_and_sends_a_checkpoint_once_caught_up() {
    let service = Arc::new(ExecutionService::new());
    let party = ledger(&service, None);
    ping(&service, &party, "before", "participant_admin", None);
    let end = service.v2_ledger_end();
    let channel = serve(Arc::clone(&service)).await;
    let mut stream = completion_stream(
        channel,
        json!({"userId": "participant_admin", "parties": [&party], "beginExclusive": end}),
        None,
    )
    .await;
    let checkpoint = next(&mut stream, Duration::from_secs(3))
        .await
        .unwrap()
        .expect("the stream is open");
    assert_eq!(
        checkpoint["offsetCheckpoint"]["offset"].as_i64(),
        Some(end as i64),
        "{checkpoint}"
    );
    ping(&service, &party, "live", "participant_admin", None);
    let live = next(&mut stream, Duration::from_secs(3))
        .await
        .unwrap()
        .expect("the stream is open");
    assert_eq!(live["completion"]["commandId"], "live", "{live}");
}

#[tokio::test]
async fn an_open_stream_ends_when_its_users_rights_change() {
    let service = Arc::new(ExecutionService::new());
    service.set_auth(AuthConfig::hmac(SECRET));
    let admin = token("participant_admin", 120);
    let party = ledger(&service, Some(&admin));
    let channel = serve(Arc::clone(&service)).await;
    let user = token("alice_user", 120);
    let mut stream = completion_stream(
        channel,
        json!({"userId": "alice_user", "parties": [&party], "beginExclusive": 0}),
        Some(&user),
    )
    .await;
    http(
        &service,
        "PATCH",
        "/v2/users/alice_user/rights",
        json!({"userId": "alice_user", "rights": [{"kind": {"CanReadAs": {"value": {"party": &party}}}}]})
            .to_string()
            .into_bytes(),
        Some(&admin),
    );
    let ended = loop {
        match next(&mut stream, Duration::from_secs(12)).await {
            Ok(Some(_)) => continue,
            other => break other,
        }
    };
    let status = ended.expect_err("the stream fails");
    assert_eq!(status.code(), tonic::Code::Aborted, "{status:?}");
    assert!(
        status.message().starts_with("STALE_STREAM_AUTHORIZATION"),
        "{status:?}"
    );
}

#[tokio::test]
async fn an_open_stream_ends_at_its_first_element_after_the_token_expired() {
    let service = Arc::new(ExecutionService::new());
    service.set_auth(AuthConfig::hmac(SECRET));
    let admin = token("participant_admin", 120);
    let party = ledger(&service, Some(&admin));
    let channel = serve(Arc::clone(&service)).await;
    let short = token("alice_user", 2);
    let end = service.v2_ledger_end();
    let mut stream = completion_stream(
        channel,
        json!({"userId": "alice_user", "parties": [&party], "beginExclusive": end}),
        Some(&short),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    ping(
        &service,
        &party,
        "after-expiry",
        "alice_user",
        Some(&token("alice_user", 120)),
    );
    let ended = loop {
        match next(&mut stream, Duration::from_secs(4)).await {
            Ok(Some(_)) => continue,
            other => break other,
        }
    };
    let status = ended.expect_err("the stream fails");
    assert_eq!(status.code(), tonic::Code::Aborted, "{status:?}");
    assert!(
        status.message().starts_with("ACCESS_TOKEN_EXPIRED"),
        "{status:?}"
    );
}
