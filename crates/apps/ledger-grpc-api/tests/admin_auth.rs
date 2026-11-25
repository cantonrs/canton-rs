//! The participant's Admin API services behind an authenticated server: with an auth service configured, an administration call needs
//! the token of a participant administrator on every entry of the server (unary, server streaming, client streaming, `Ping`).
//!
//! A Canton node keeps the Admin API on a port of its own with its own `auth-services` (`AdminServerConfig`); this server answers the
//! Admin services on the Ledger API's listener, so they must not be reachable around the Ledger API's authentication.
#![allow(clippy::unwrap_used, reason = "integration test")]

use std::sync::Arc;

use ledger_grpc_api::{
    dynamic::DynCodec,
    server::{serve_admin_listener, serve_admin_listener_with, serve_listener},
};
use ledger_json_api::{
    admin_api_auth::{AdminApiAuth, AdminAuthService},
    auth::sign_token,
    dispatch_request, AuthConfig, ExecutionService, HttpRequest,
};
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde_json::{json, Value};
use tonic::{client::Grpc, Code, Request};

const SECRET: &str = "testsecret";
const IDENTITY: &str = "com.digitalasset.canton.topology.admin.v30.IdentityInitializationService";
const REPAIR: &str = "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService";
const TOPOLOGY_READ: &str = "com.digitalasset.canton.topology.admin.v30.TopologyManagerReadService";
const PRUNING: &str = "com.digitalasset.canton.admin.participant.v30.PruningService";
const PING: &str = "com.digitalasset.canton.admin.participant.v30.PingService";

fn token(sub: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sign_token(
        SECRET,
        &json!({ "sub": sub, "scope": "daml_ledger_api", "exp": now + 120 }),
    )
}

/// A service with the HMAC auth service on and a user `nobody` that has no rights.
fn authenticated_service() -> Arc<ExecutionService> {
    let service = Arc::new(ExecutionService::new());
    service.set_auth(AuthConfig::hmac(SECRET));
    let resp = dispatch_request(
        &service,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/users".into(),
            query_params: Default::default(),
            headers: [(
                "authorization".to_string(),
                format!("Bearer {}", token("participant_admin")),
            )]
            .into(),
            body: json!({"user": {"id": "nobody"}, "rights": []})
                .to_string()
                .into_bytes(),
        },
    );
    assert_eq!(resp.status, 200);
    service
}

fn with_token<T>(message: T, token: Option<&str>) -> Request<T> {
    let mut request = Request::new(message);
    if let Some(t) = token {
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {t}").parse().unwrap());
    }
    request
}

struct Client {
    channel: tonic::transport::Channel,
    pool: DescriptorPool,
}

impl Client {
    async fn connect(addr: std::net::SocketAddr) -> Self {
        Client {
            channel: tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
                .unwrap()
                .connect()
                .await
                .unwrap(),
            pool: DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).unwrap(),
        }
    }

    fn method(&self, service: &str, name: &str) -> prost_reflect::MethodDescriptor {
        self.pool
            .get_service_by_name(service)
            .and_then(|s| s.methods().find(|m| m.name() == name))
            .unwrap_or_else(|| panic!("unknown method {service}/{name}"))
    }

    async fn grpc(&self) -> Grpc<tonic::transport::Channel> {
        let mut grpc = Grpc::new(self.channel.clone());
        grpc.ready().await.unwrap();
        grpc
    }

    async fn unary(&self, service: &str, name: &str, body: Value, token: Option<&str>) -> Code {
        let method = self.method(service, name);
        let msg = DynamicMessage::deserialize(method.input(), body).unwrap();
        let path = format!("/{service}/{name}").parse().unwrap();
        self.grpc()
            .await
            .unary(with_token(msg, token), path, DynCodec::new(method.output()))
            .await
            .map_or_else(|status| status.code(), |_| Code::Ok)
    }

    /// The code the stream ends with (the first item's, or the call's).
    async fn server_stream(
        &self,
        service: &str,
        name: &str,
        body: Value,
        token: Option<&str>,
    ) -> Code {
        let method = self.method(service, name);
        let msg = DynamicMessage::deserialize(method.input(), body).unwrap();
        let path = format!("/{service}/{name}").parse().unwrap();
        match self
            .grpc()
            .await
            .server_streaming(with_token(msg, token), path, DynCodec::new(method.output()))
            .await
        {
            Err(status) => status.code(),
            Ok(response) => {
                let mut stream = response.into_inner();
                loop {
                    match stream.message().await {
                        Ok(Some(_)) => {}
                        Ok(None) => return Code::Ok,
                        Err(status) => return status.code(),
                    }
                }
            }
        }
    }

    async fn client_stream(&self, service: &str, name: &str, token: Option<&str>) -> Code {
        let method = self.method(service, name);
        let path = format!("/{service}/{name}").parse().unwrap();
        self.grpc()
            .await
            .client_streaming(
                with_token(tokio_stream::iter(Vec::<DynamicMessage>::new()), token),
                path,
                DynCodec::new(method.output()),
            )
            .await
            .map_or_else(|status| status.code(), |_| Code::Ok)
    }
}

/// Every way into the Admin services, as one call each: what the call answers for `token`.
async fn admin_calls(client: &Client, token: Option<&str>) -> Vec<(&'static str, Code)> {
    vec![
        (
            "unary GetId",
            client.unary(IDENTITY, "GetId", json!({}), token).await,
        ),
        (
            "unary PurgeContracts",
            client
                .unary(
                    REPAIR,
                    "PurgeContracts",
                    json!({"synchronizerAlias": "sync0", "contractIds": ["00"], "ignoreAlreadyPurged": true}),
                    token,
                )
                .await,
        ),
        (
            "unary Prune",
            client
                .unary(PRUNING, "Prune", json!({"pruneUpTo": 1}), token)
                .await,
        ),
        (
            "server-streaming ExportTopologySnapshotV2",
            client
                .server_stream(TOPOLOGY_READ, "ExportTopologySnapshotV2", json!({}), token)
                .await,
        ),
        (
            "client-streaming ImportAcs",
            client.client_stream(REPAIR, "ImportAcs", token).await,
        ),
        (
            "Ping",
            client
                .unary(
                    PING,
                    "Ping",
                    json!({"targetParties": [], "validators": [], "timeout": "1s", "levels": 0}),
                    token,
                )
                .await,
        ),
    ]
}

/// The Admin services on the Ledger API port: with the Ledger API's auth service on, they need an administrator's token.
#[test]
fn admin_services_on_the_ledger_api_port_need_an_administrators_token() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = authenticated_service();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = serve_listener(service, listener).await;
        });
        let client = Client::connect(addr).await;

        for (call, code) in admin_calls(&client, None).await {
            assert_eq!(code, Code::Unauthenticated, "{call} without a token");
        }
        for (call, code) in admin_calls(&client, Some("not-a-token")).await {
            assert_eq!(code, Code::Unauthenticated, "{call} with a malformed token");
        }
        for (call, code) in admin_calls(&client, Some(&token("nobody"))).await {
            assert_eq!(
                code,
                Code::PermissionDenied,
                "{call} as a user without rights"
            );
        }
        // an administrator gets past the authentication: whatever the call then answers, it is not an authentication failure
        for (call, code) in admin_calls(&client, Some(&token("participant_admin"))).await {
            assert!(
                code != Code::Unauthenticated && code != Code::PermissionDenied,
                "{call} as the administrator answered {code:?}"
            );
        }
        server.abort();
    });
}

/// The Admin API port is the operator's: the Ledger API's auth service does not guard it (a Canton node configures the two ports'
/// `auth-services` separately, and `scripts/verify-official-takeover.sh` calls this port without a token next to a JWT-checked
/// Ledger API). The Ledger API calls on the same port stay authenticated.
#[test]
fn the_admin_api_port_answers_admin_calls_without_the_ledger_apis_token() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let service = authenticated_service();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = serve_admin_listener(service, listener).await;
        });
        let client = Client::connect(addr).await;
        for (call, code) in admin_calls(&client, None).await {
            // `Prune` runs as the JSON API's `/v2/admin/prune`, which authenticates the call itself
            if call == "unary Prune" {
                assert_eq!(code, Code::Unauthenticated, "{call}");
                continue;
            }
            assert!(
                code != Code::Unauthenticated && code != Code::PermissionDenied,
                "{call} without a token answered {code:?}"
            );
        }
        assert_eq!(
            client
                .unary(
                    "com.daml.ledger.api.v2.admin.UserManagementService",
                    "ListUsers",
                    json!({}),
                    None
                )
                .await,
            Code::Unauthenticated,
            "a Ledger API call on the Admin API port without a token"
        );
        server.abort();
    });
}

#[test]
fn admin_services_stay_open_when_no_authentication_is_configured() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_admin_listener(
            Arc::new(ExecutionService::new()),
            listener,
        ));
        let client = Client::connect(addr).await;
        assert_eq!(
            client.unary(IDENTITY, "GetId", json!({}), None).await,
            Code::Ok
        );
        server.abort();
    });
}

fn signed(secret: &str, claims: Value) -> String {
    sign_token(secret, &claims)
}

fn admin_api_auth(admin_claim: bool) -> AdminApiAuth {
    AdminApiAuth {
        services: vec![
            AdminAuthService {
                verifier: AuthConfig::hmac("adminsecret").with_audience("https://admin.example"),
                privileged: true,
            },
            AdminAuthService {
                verifier: AuthConfig::hmac("usersecret"),
                privileged: false,
            },
        ],
        fixed_admin_token: Some("fixed-token".into()),
        admin_claim,
    }
}

/// An `admin-api` with `auth-services` (internal review A-20): a call needs the admin claim, which a privileged service's token or the
/// admin token (with `admin-claim`) carries; a user's token of an ordinary service is refused (`UserBasedAuthenticationIsDisabled`).
#[test]
fn the_admin_api_port_authenticates_as_its_auth_services_say() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let privileged = signed(
            "adminsecret",
            json!({ "sub": "operator", "aud": "https://admin.example", "exp": now + 120 }),
        );
        let user = signed(
            "usersecret",
            json!({ "sub": "participant_admin", "scope": "daml_ledger_api", "exp": now + 120 }),
        );
        let mut addrs = Vec::new();
        let mut servers = Vec::new();
        for admin_claim in [true, false] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            addrs.push(listener.local_addr().unwrap());
            servers.push(tokio::spawn(serve_admin_listener_with(
                Arc::new(ExecutionService::new()),
                listener,
                Some(admin_api_auth(admin_claim)),
            )));
        }
        let client = Client::connect(addrs[0]).await;
        for (call, code) in admin_calls(&client, None).await {
            assert_eq!(code, Code::Unauthenticated, "{call} without a token");
        }
        for (call, code) in admin_calls(&client, Some(&user)).await {
            assert_eq!(code, Code::Unauthenticated, "{call} with a user's token");
        }
        for (call, code) in admin_calls(&client, Some(&privileged)).await {
            assert!(
                code != Code::Unauthenticated && code != Code::PermissionDenied,
                "{call} with a privileged token answered {code:?}"
            );
        }
        assert_eq!(
            client
                .unary(IDENTITY, "GetId", json!({}), Some("fixed-token"))
                .await,
            Code::Ok
        );
        let without_claim = Client::connect(addrs[1]).await;
        assert_eq!(
            without_claim
                .unary(IDENTITY, "GetId", json!({}), Some("fixed-token"))
                .await,
            Code::PermissionDenied,
            "the admin token without `admin-claim` lacks the admin claim"
        );
        for s in servers {
            s.abort();
        }
    });
}
