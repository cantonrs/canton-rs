//! The gRPC server: one dynamic service that answers every covered Ledger API v2 method from the descriptor set, by turning
//! the request into a JSON API request (`table`), running it on the shared `ExecutionService`, and turning the JSON API
//! answer into the response message or a gRPC status.
use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use ledger_json_api::{
    admin_api_auth::AdminApiAuth, dispatch_request, ExecutionService, HttpRequest,
};
use prost_reflect::{
    DescriptorPool, DeserializeOptions, DynamicMessage, MessageDescriptor, MethodDescriptor,
    SerializeOptions,
};
use serde_json::Value as Json;
use tokio_stream::Stream;
use tonic::{
    server::{ClientStreamingService, Grpc, ServerStreamingService, UnaryService},
    Code, Request, Response, Status,
};

use crate::{
    convert::{canton_to_proto, proto_to_canton},
    dynamic::DynCodec,
    limits::GrpcLimits,
    table::{self, Body},
};

const PACKAGE: &str = "com.daml.ledger.api.v2.";

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type BoxStream = Pin<Box<dyn Stream<Item = Result<DynamicMessage, Status>> + Send>>;

/// The descriptor of the standard gRPC health service (`grpc.health.v1`, the proto of the official Canton jar), which a node's Admin API serves: the descriptor set
/// of the vendored Canton protos does not carry it.
pub fn health_descriptor() -> prost_reflect::prost_types::FileDescriptorProto {
    use prost_reflect::prost_types::{
        field_descriptor_proto::{Label, Type},
        DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
        FileDescriptorProto, MethodDescriptorProto, ServiceDescriptorProto,
    };
    let field =
        |name: &str, number: i32, kind: Type, type_name: Option<&str>| FieldDescriptorProto {
            name: Some(name.into()),
            number: Some(number),
            label: Some(Label::Optional as i32),
            r#type: Some(kind as i32),
            type_name: type_name.map(String::from),
            json_name: Some(name.into()),
            ..Default::default()
        };
    let value = |name: &str, number: i32| EnumValueDescriptorProto {
        name: Some(name.into()),
        number: Some(number),
        ..Default::default()
    };
    let method = |name: &str, streaming: bool| MethodDescriptorProto {
        name: Some(name.into()),
        input_type: Some(".grpc.health.v1.HealthCheckRequest".into()),
        output_type: Some(".grpc.health.v1.HealthCheckResponse".into()),
        server_streaming: Some(streaming),
        ..Default::default()
    };
    FileDescriptorProto {
        name: Some("grpc/health/v1/health.proto".into()),
        package: Some("grpc.health.v1".into()),
        syntax: Some("proto3".into()),
        message_type: vec![
            DescriptorProto {
                name: Some("HealthCheckRequest".into()),
                field: vec![field("service", 1, Type::String, None)],
                ..Default::default()
            },
            DescriptorProto {
                name: Some("HealthCheckResponse".into()),
                field: vec![field(
                    "status",
                    1,
                    Type::Enum,
                    Some(".grpc.health.v1.HealthCheckResponse.ServingStatus"),
                )],
                enum_type: vec![EnumDescriptorProto {
                    name: Some("ServingStatus".into()),
                    value: vec![
                        value("UNKNOWN", 0),
                        value("SERVING", 1),
                        value("NOT_SERVING", 2),
                        value("SERVICE_UNKNOWN", 3),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        service: vec![ServiceDescriptorProto {
            name: Some("Health".into()),
            method: vec![method("Check", false), method("Watch", true)],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// The shared state of the gRPC service.
pub struct State {
    pub ledger: Arc<ExecutionService>,
    pub pool: DescriptorPool,
    /// Which of the node's two gRPC endpoints this service answers on.
    pub listener: Listener,
    /// The participant's offset checkpoint cache (`crate::live::CheckpointCache`).
    pub(crate) checkpoints: crate::live::CheckpointCache,
    /// The transport limits of the listener.
    pub limits: GrpcLimits,
    /// The Admin API port's authentication (`admin-api.auth-services`); `None` takes every call, as Canton does without auth services.
    pub admin_auth: Option<AdminApiAuth>,
}

/// The gRPC endpoint of the node a service answers on. Both answer every service this server has; they differ in who may call the
/// Admin API services (see [`authorize_admin`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// The Ledger API port (`ledger-api` of a Canton configuration): what applications reach.
    LedgerApi,
    /// The Admin API port (`admin-api`): what the node's operator reaches.
    AdminApi,
}

#[derive(Clone)]
pub struct GrpcService {
    state: Arc<State>,
}

impl GrpcService {
    /// The service of the Ledger API port.
    pub fn new(ledger: Arc<ExecutionService>) -> Self {
        Self::on(ledger, Listener::LedgerApi)
    }

    /// The service of the Admin API port, open to every call (an `admin-api` without `auth-services`).
    pub fn for_admin_api(ledger: Arc<ExecutionService>) -> Self {
        Self::for_admin_api_with(ledger, None)
    }

    /// The service of the Admin API port with its authentication.
    pub fn for_admin_api_with(ledger: Arc<ExecutionService>, auth: Option<AdminApiAuth>) -> Self {
        Self::on_with(ledger, Listener::AdminApi, auth)
    }

    fn on(ledger: Arc<ExecutionService>, listener: Listener) -> Self {
        Self::on_with(ledger, listener, None)
    }

    fn on_with(
        ledger: Arc<ExecutionService>,
        listener: Listener,
        admin_auth: Option<AdminApiAuth>,
    ) -> Self {
        let mut pool =
            DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor set");
        pool.add_file_descriptor_proto(health_descriptor())
            .expect("the health service descriptor");
        started_at();
        Self {
            state: Arc::new(State {
                checkpoints: crate::live::CheckpointCache::new(ledger.v2_ledger_end()),
                ledger,
                pool,
                listener,
                limits: GrpcLimits::of(listener),
                admin_auth,
            }),
        }
    }
}

/// The gRPC status for a failed command submission. The JSON API reports an unknown template from its own lookup
/// (`TEMPLATES_OR_INTERFACES_NOT_FOUND`, 404); the gRPC command preprocessor reports `COMMAND_PREPROCESSING_FAILED`
/// (INVALID_ARGUMENT) with `unknown template <id>` (measured).
fn submit_status(http_status: u16, body: &[u8], submission_id: Option<&str>) -> Status {
    if let Ok(j) = serde_json::from_slice::<Json>(body) {
        if j["code"] == "TEMPLATES_OR_INTERFACES_NOT_FOUND" {
            if let Some(id) = j.pointer("/resources/0/1").and_then(Json::as_str) {
                return Status::new(
                    Code::InvalidArgument,
                    format!("COMMAND_PREPROCESSING_FAILED(8,00000000): unknown template {id}"),
                );
            }
        }
    }
    status_correlated(http_status, body, submission_id)
}

/// The submission id a command, reassignment or execute request names: the correlation id of its errors in Canton
/// (`ApiCommandService.errorLoggingContext`: `ErrorLoggingContext.fromOption(.., request.commands.map(_.submissionId))`).
fn submission_id(req: &Json) -> Option<&str> {
    [
        "/commands/submissionId",
        "/reassignmentCommands/submissionId",
        "/submissionId",
    ]
    .iter()
    .find_map(|p| req.pointer(p).and_then(Json::as_str))
    .filter(|s| !s.is_empty())
}

/// The gRPC status Canton's error body maps to: the gRPC code, `CODE(category,correlation): cause` as the message
/// (Canton's own format), and the error's `google.rpc.Status` details.
pub fn status_of(http_status: u16, body: &[u8]) -> Status {
    status_correlated(http_status, body, None)
}

fn status_correlated(http_status: u16, body: &[u8], correlation_id: Option<&str>) -> Status {
    let Ok(j) = serde_json::from_slice::<Json>(body) else {
        return Status::invalid_argument(String::from_utf8_lossy(body).into_owned());
    };
    let (Some(code), Some(cause)) = (
        j.get("code").and_then(Json::as_str),
        j.get("cause").and_then(Json::as_str),
    ) else {
        return Status::new(Code::Unknown, format!("HTTP {http_status}: {j}"));
    };
    let grpc = j.get("grpcCodeValue").and_then(Json::as_i64).unwrap_or(2) as i32;
    // authentication and permission failures are reported without a reason (measured): an opaque message naming the request
    let message = if code == "NA" {
        let id = j.get("correlationId").and_then(Json::as_str).unwrap_or("0");
        format!("An error occurred. Please contact the operator and inquire about the request {id} with tid {id}")
    } else {
        let category = j.get("errorCategory").and_then(Json::as_i64).unwrap_or(0);
        let corr: String = correlation_id
            .or_else(|| j.get("correlationId").and_then(Json::as_str))
            .or_else(|| j.get("traceId").and_then(Json::as_str))
            .unwrap_or("00000000")
            .chars()
            .take(8)
            .collect();
        format!("{code}({category},{corr}): {cause}")
    };
    let details = crate::status_details::encode(grpc, &message, &j, correlation_id);
    Status::with_details(Code::from_i32(grpc), message, details.into())
}

fn wants_verbose(v: &Json) -> bool {
    match v {
        Json::Object(m) => m
            .iter()
            .any(|(k, x)| (k == "verbose" && x == &Json::Bool(true)) || wants_verbose(x)),
        Json::Array(a) => a.iter().any(wants_verbose),
        _ => false,
    }
}

fn to_json(msg: &DynamicMessage) -> Json {
    let opts = SerializeOptions::new()
        .skip_default_fields(true)
        .stringify_64_bit_integers(false);
    msg.serialize_with_options(serde_json::value::Serializer, &opts)
        .unwrap_or(Json::Null)
}

fn from_json(desc: &MessageDescriptor, v: Json) -> Result<DynamicMessage, Status> {
    let opts = DeserializeOptions::new().deny_unknown_fields(false);
    DynamicMessage::deserialize_with_options(desc.clone(), v, &opts)
        .map_err(|e| Status::internal(format!("response conversion: {e}")))
}

/// The package prefix of every Canton Admin API service this server answers (participant, topology, health: `crate::admin_api`).
const ADMIN_PACKAGE: &str = "com.digitalasset.canton.";

/// The authentication of a call to an Admin API service; a call to any other service passes (the Ledger API authenticates its own
/// calls in `dispatch_request`, and `grpc.health.v1` is public).
///
/// [CANTON-NOTE: SEMANTICS] A Canton node authenticates its two ports separately (`ledger-api.auth-services` and
/// `admin-api.auth-services`), and serves the Admin API on the admin port only. Here both ports answer every service, so:
/// - on the **Ledger API port**, an Admin call needs the token of a participant administrator whenever the Ledger API has an auth
///   service: repair, package and topology calls are not reachable around the Ledger API's authentication;
/// - on the **Admin API port**, an Admin call is checked as the port's `admin-api.auth-services` say ([`AdminApiAuth`]); without them it
///   passes, as Canton's default `admin-api` passes it.
///
/// [CANTON-NOTE: LIMITATION] The Admin API port's TLS is not read, and `grpc.health.v1` stays public on it.
///
/// [CANTON-NOTE: INVARIANT] Every entry of the server that reaches `crate::admin_api` calls this first: `invoke` (unary and
/// server streaming), the `Ping` branch of [`Unary`] and [`ClientStreaming`]. The Admin handlers themselves take no token.
fn authorize_admin(
    state: &State,
    method: &MethodDescriptor,
    authorization: Option<&str>,
) -> Result<(), Status> {
    if !method
        .parent_service()
        .full_name()
        .starts_with(ADMIN_PACKAGE)
    {
        return Ok(());
    }
    if state.listener == Listener::AdminApi {
        return match &state.admin_auth {
            None => Ok(()),
            Some(auth) => auth
                .check(authorization)
                .map_err(|denied| status_of(denied.status, &denied.body)),
        };
    }
    match ledger_json_api::auth::check_admin(&state.ledger, authorization) {
        None => Ok(()),
        Some(denied) => Err(status_of(denied.status, &denied.body)),
    }
}

/// Runs one RPC: the response messages (one for a unary method, any number for a server-streaming one).
fn invoke(
    state: &State,
    method: &MethodDescriptor,
    request: &DynamicMessage,
    authorization: Option<String>,
    traceparent: Option<String>,
) -> Result<Vec<DynamicMessage>, Status> {
    authorize_admin(state, method, authorization.as_deref())?;
    let short = method
        .parent_service()
        .full_name()
        .trim_start_matches(PACKAGE)
        .to_string()
        + "/"
        + method.name();
    if method.is_server_streaming() {
        if let Some(res) = crate::admin_api::handle_admin_server_streaming(
            &state.ledger,
            method,
            request,
            started_at(),
        ) {
            return res;
        }
    } else if let Some(res) = crate::admin_api::handle_admin_unary(
        &state.ledger,
        method,
        request,
        started_at(),
        authorization.as_deref(),
    ) {
        return res;
    }
    // [CANTON-NOTE: SEMANTICS] `grpc.health.v1.Health/Check`: this node is up and serving (what the health probes of a container ask the Admin API of a Canton node).
    if method.parent_service().full_name() == "grpc.health.v1.Health" && method.name() == "Check" {
        let out = serde_json::json!({ "status": "SERVING" });
        return Ok(vec![from_json(&method.output(), out)?]);
    }
    let proto_req = to_json(request);
    let canton_req = proto_to_canton(&method.input(), &proto_req);
    if short == "admin.PartyManagementService/GetParties" {
        return get_parties(state, method, &canton_req, &authorization);
    }
    let plan = table::plan(&short, &canton_req, &proto_req).ok_or_else(|| {
        Status::unimplemented(format!("{short} is not implemented by this server"))
    })?;
    let mut query_params = HashMap::new();
    for (k, v) in &plan.query {
        query_params.insert(k.clone(), v.clone());
    }
    let mut headers = HashMap::new();
    headers.insert(
        ledger_json_api::observability::VIA_GRPC_HEADER.to_string(),
        "1".to_string(),
    );
    if let Some(a) = authorization {
        headers.insert("authorization".to_string(), a);
    }
    if let Some(t) = traceparent {
        headers.insert("traceparent".to_string(), t);
    }
    let body = match plan.body {
        Body::None => Vec::new(),
        Body::Json(j) => {
            headers.insert("content-type".to_string(), "application/json".to_string());
            serde_json::to_vec(&j).unwrap_or_default()
        }
        Body::Bytes(b) => {
            headers.insert(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            );
            b
        }
    };
    let http = HttpRequest {
        method: plan.method.to_string(),
        path: plan.path,
        query_params,
        headers,
        body,
    };
    // values come back as `Value`/`Record` messages; labels and record ids only when the request asks for `verbose`
    let verbose = wants_verbose(&canton_req)
        || (short
            == "interactive.InteractiveSubmissionService/ExecuteSubmissionAndWaitForTransaction"
            && canton_req.get("transactionFormat").is_none());
    let resp = ledger_json_api::v2_updates::with_unbounded_stream_list(|| {
        ledger_json_api::v2_commands::with_proto_values(verbose, || {
            dispatch_request(&state.ledger, &http)
        })
    });
    if resp.status >= 400 {
        return Err(
            if short.starts_with("CommandService/")
                || short.starts_with("CommandSubmissionService/")
                || short.starts_with("interactive.InteractiveSubmissionService/")
            {
                submit_status(resp.status, &resp.body, submission_id(&canton_req))
            } else {
                status_of(resp.status, &resp.body)
            },
        );
    }
    response_messages(method, &short, &resp.body, &resp.headers)
}

/// The response messages of the JSON API answer `body` to `short` (the method within its package).
pub(crate) fn response_messages(
    method: &MethodDescriptor,
    short: &str,
    body: &[u8],
    headers: &HashMap<String, String>,
) -> Result<Vec<DynamicMessage>, Status> {
    table::response_items(short, body, headers)
        .iter()
        .map(|item| from_json(&method.output(), canton_to_proto(&method.output(), item)))
        .collect()
}

/// When this process started serving (for the uptime of `ParticipantStatus`).
fn started_at() -> std::time::Instant {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    *START.get_or_init(std::time::Instant::now)
}

/// `GetParties` asks for several parties at once; the JSON API answers one party per request.
fn get_parties(
    state: &State,
    method: &MethodDescriptor,
    req: &Json,
    authorization: &Option<String>,
) -> Result<Vec<DynamicMessage>, Status> {
    let mut details: Vec<Json> = Vec::new();
    for p in req
        .get("parties")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
    {
        let party = p.as_str().unwrap_or("");
        let http = HttpRequest {
            method: "GET".into(),
            path: format!("/v2/parties/{}", table::encode(party)),
            query_params: HashMap::new(),
            headers: authorization
                .iter()
                .map(|a| ("authorization".to_string(), a.clone()))
                .chain(std::iter::once((
                    ledger_json_api::observability::VIA_GRPC_HEADER.to_string(),
                    "1".to_string(),
                )))
                .collect(),
            body: Vec::new(),
        };
        let resp = dispatch_request(&state.ledger, &http);
        if resp.status >= 400 {
            return Err(status_of(resp.status, &resp.body));
        }
        let parsed: Json = serde_json::from_slice(&resp.body).unwrap_or(Json::Null);
        details.extend(
            parsed["partyDetails"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
        );
    }
    let out = serde_json::json!({ "partyDetails": details });
    Ok(vec![from_json(
        &method.output(),
        canton_to_proto(&method.output(), &out),
    )?])
}

// [CANTON-NOTE: INVARIANT] Synchronous ledger/admin dispatch can enter `ProtocolCommitter` (which runs its own
// Tokio `current_thread` runtime via `block_on`) or synchronous `postgres::Client` sinks; always isolate off Tokio worker threads.
pub(crate) async fn invoke_blocking(
    state: Arc<State>,
    method: MethodDescriptor,
    request: DynamicMessage,
    authorization: Option<String>,
    traceparent: Option<String>,
) -> Result<Vec<DynamicMessage>, Status> {
    tokio::task::spawn_blocking(move || {
        invoke(&state, &method, &request, authorization, traceparent)
    })
    .await
    .map_err(|e| Status::internal(format!("gRPC blocking worker failed: {e}")))?
}

struct Unary {
    state: Arc<State>,
    method: MethodDescriptor,
}

impl UnaryService<DynamicMessage> for Unary {
    type Response = DynamicMessage;
    type Future = BoxFuture<Result<Response<DynamicMessage>, Status>>;

    fn call(&mut self, request: Request<DynamicMessage>) -> Self::Future {
        let (state, method) = (std::sync::Arc::clone(&self.state), self.method.clone());
        let started = std::time::Instant::now();
        Box::pin(async move {
            let authorization = request
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let (name, peer, client_trace) = call_identity(&method, &request);
            let trace = ledger_json_api::http::call_traceparent(client_trace.as_deref());
            ledger_json_api::http::log_call(&name, &peer, trace.as_deref(), None);
            let items = if method.parent_service().full_name()
                == "com.digitalasset.canton.admin.participant.v30.PingService"
                && method.name() == "Ping"
            {
                match authorize_admin(&state, &method, authorization.as_deref()) {
                    Ok(()) => {
                        crate::admin_api::handle_ping(&state.ledger, &method, request.get_ref())
                            .await
                            .map(|msg| vec![msg])
                    }
                    Err(denied) => Err(denied),
                }
            } else {
                invoke_blocking(
                    Arc::clone(&state),
                    method,
                    request.into_inner(),
                    authorization,
                    client_trace,
                )
                .await
            };
            finish_call(&state, &name, &peer, trace.as_deref(), &items, started);
            let items = items?;
            items
                .into_iter()
                .next()
                .map(Response::new)
                .ok_or_else(|| Status::internal("no response"))
        })
    }
}

/// The call's name (`com.daml.ledger.api.v2.UpdateService/GetUpdates`), who made it (`grpc:/172.24.0.4:59484`) and its `traceparent`, for the request log.
fn call_identity(
    method: &MethodDescriptor,
    request: &Request<DynamicMessage>,
) -> (String, String, Option<String>) {
    (
        format!("{}/{}", method.parent_service().full_name(), method.name()),
        format!(
            "grpc:/{}",
            request
                .remote_addr()
                .map_or_else(|| "unknown".to_string(), |a| a.to_string())
        ),
        request
            .metadata()
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .map(String::from),
    )
}

/// How the answer of a call ends in the request log: Canton's `sending response ` for an answer, the status code of a refusal.
/// Writes the request log's line for the end of a call and counts the call (`daml_grpc_server_handled_total`, see
/// `ledger_json_api::metrics_compat`).
fn finish_call<T>(
    state: &State,
    name: &str,
    peer: &str,
    trace: Option<&str>,
    result: &Result<T, Status>,
    started: std::time::Instant,
) {
    ledger_json_api::http::log_call(name, peer, trace, Some(&call_outcome(result)));
    let code = match result {
        Ok(_) => tonic::Code::Ok,
        Err(status) => status.code(),
    };
    state.ledger.observability.record_request(
        "grpc",
        name,
        u16::try_from(i32::from(code)).unwrap_or(2),
        started.elapsed(),
    );
}

fn call_outcome<T>(result: &Result<T, Status>) -> String {
    match result {
        Ok(_) => "sending response ".to_string(),
        Err(status) => format!("failed with {:?}", status.code()),
    }
}

struct Streaming {
    state: Arc<State>,
    method: MethodDescriptor,
}

impl ServerStreamingService<DynamicMessage> for Streaming {
    type Response = DynamicMessage;
    type ResponseStream = BoxStream;
    type Future = BoxFuture<Result<Response<BoxStream>, Status>>;

    fn call(&mut self, request: Request<DynamicMessage>) -> Self::Future {
        let (state, method) = (std::sync::Arc::clone(&self.state), self.method.clone());
        let started = std::time::Instant::now();
        Box::pin(async move {
            let authorization = request
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let (name, peer, client_trace) = call_identity(&method, &request);
            let trace = ledger_json_api::http::call_traceparent(client_trace.as_deref());
            ledger_json_api::http::log_call(&name, &peer, trace.as_deref(), None);

            let is_get_updates = method.parent_service().full_name()
                == "com.daml.ledger.api.v2.UpdateService"
                && method.name() == "GetUpdates";
            let current_end = i64::try_from(state.ledger.v2_ledger_end()).unwrap_or(i64::MAX);
            let req_msg = request.get_ref();
            let begin_exclusive = req_msg
                .get_field_by_name("begin_exclusive")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let has_end = req_msg.has_field_by_name("end_inclusive");
            let end_val = has_end.then(|| {
                req_msg
                    .get_field_by_name("end_inclusive")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0)
            });
            let descending = req_msg
                .get_field_by_name("descending_order")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if method.parent_service().full_name()
                == "com.daml.ledger.api.v2.CommandCompletionService"
                && method.name() == "CompletionStream"
            {
                let request = request.into_inner();
                let initial = invoke_blocking(
                    Arc::clone(&state),
                    method.clone(),
                    request.clone(),
                    authorization.clone(),
                    None,
                )
                .await;
                finish_call(&state, &name, &peer, trace.as_deref(), &initial, started);
                let (tx, rx) = tokio::sync::mpsc::channel::<Result<DynamicMessage, Status>>(64);
                crate::live::tail_completions(state, method, request, authorization, initial?, tx);
                let stream: BoxStream = Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx));
                return Ok(Response::new(stream));
            }
            let live_tail = is_get_updates
                && !descending
                && begin_exclusive >= 0
                && begin_exclusive <= current_end
                && end_val.is_none_or(|e| e > current_end && e >= begin_exclusive);

            if !live_tail {
                let items = invoke_blocking(
                    Arc::clone(&state),
                    method.clone(),
                    request.into_inner(),
                    authorization,
                    None,
                )
                .await;
                finish_call(&state, &name, &peer, trace.as_deref(), &items, started);
                let items = items?;
                let stream: BoxStream = Box::pin(tokio_stream::iter(items.into_iter().map(Ok)));
                return Ok(Response::new(stream));
            }

            let mut init_req = req_msg.clone();
            init_req.set_field_by_name("end_inclusive", prost_reflect::Value::I64(current_end));
            let initial_items = invoke_blocking(
                Arc::clone(&state),
                method.clone(),
                init_req,
                authorization.clone(),
                None,
            )
            .await;
            finish_call(
                &state,
                &name,
                &peer,
                trace.as_deref(),
                &initial_items,
                started,
            );
            let initial_items = initial_items?;
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<DynamicMessage, Status>>(64);
            let base_req = request.into_inner();
            let mut auth = ledger_json_api::auth_stream::StreamAuthorization::capture(
                &state.ledger,
                authorization.as_deref(),
            );
            tokio::spawn(async move {
                for item in initial_items {
                    if !crate::live::send_checked(&tx, &auth, item).await {
                        return;
                    }
                }
                let mut cursor = current_end.max(begin_exclusive);
                loop {
                    if tx.is_closed()
                        || !crate::live::still_authorized(&tx, &mut auth, &state).await
                    {
                        break;
                    }
                    let now_end = i64::try_from(state.ledger.v2_ledger_end()).unwrap_or(i64::MAX);
                    if now_end > cursor {
                        let batch_end = end_val.map_or(now_end, |target| now_end.min(target));
                        let mut batch_req = base_req.clone();
                        batch_req.set_field_by_name(
                            "begin_exclusive",
                            prost_reflect::Value::I64(cursor),
                        );
                        batch_req.set_field_by_name(
                            "end_inclusive",
                            prost_reflect::Value::I64(batch_end),
                        );
                        match invoke_blocking(
                            Arc::clone(&state),
                            method.clone(),
                            batch_req,
                            authorization.clone(),
                            None,
                        )
                        .await
                        {
                            Ok(items) => {
                                for item in items {
                                    if !crate::live::send_checked(&tx, &auth, item).await {
                                        return;
                                    }
                                }
                                cursor = batch_end;
                            }
                            Err(status) => {
                                let status = crate::live::read_failure(&mut auth, &state, status);
                                let _ = tx.send(Err(status)).await;
                                return;
                            }
                        }
                    }
                    if end_val.is_some_and(|target| cursor >= target) {
                        break;
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                        _ = tx.closed() => break,
                    }
                }
            });
            let stream: BoxStream = Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx));
            Ok(Response::new(stream))
        })
    }
}

struct ClientStreaming {
    state: Arc<State>,
    method: MethodDescriptor,
}

impl ClientStreamingService<DynamicMessage> for ClientStreaming {
    type Response = DynamicMessage;
    type Future = BoxFuture<Result<Response<DynamicMessage>, Status>>;

    fn call(&mut self, request: Request<tonic::Streaming<DynamicMessage>>) -> Self::Future {
        let (state, method) = (std::sync::Arc::clone(&self.state), self.method.clone());
        let started = std::time::Instant::now();
        Box::pin(async move {
            let service_name = format!("{}/{}", method.parent_service().full_name(), method.name());
            let peer = format!(
                "grpc:/{}",
                request
                    .remote_addr()
                    .map_or_else(|| "unknown".to_string(), |a| a.to_string())
            );
            let trace = request
                .metadata()
                .get("traceparent")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| ledger_json_api::http::call_traceparent(Some(s)));
            ledger_json_api::http::log_call(&service_name, &peer, trace.as_deref(), None);

            // before a frame of the stream is read: an unauthenticated caller does not get to upload
            let authorization = request
                .metadata()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            if let Err(denied) = authorize_admin(&state, &method, authorization.as_deref()) {
                let result: Result<DynamicMessage, Status> = Err(denied);
                finish_call(
                    &state,
                    &service_name,
                    &peer,
                    trace.as_deref(),
                    &result,
                    started,
                );
                return result.map(Response::new);
            }

            let mut stream = request.into_inner();
            let mut frames = Vec::new();
            while let Some(msg) = stream.message().await? {
                frames.push(msg);
            }
            let ledger = std::sync::Arc::clone(&state.ledger);
            let worker_method = method.clone();
            let result = tokio::task::spawn_blocking(move || {
                crate::admin_api::handle_admin_client_streaming(&ledger, &worker_method, frames)
            })
            .await
            .map_err(|e| Status::internal(format!("gRPC client-streaming worker failed: {e}")))?
            .unwrap_or_else(|| {
                Err(Status::unimplemented(format!(
                    "{service_name} is not implemented by this server"
                )))
            });
            finish_call(
                &state,
                &service_name,
                &peer,
                trace.as_deref(),
                &result,
                started,
            );
            result.map(Response::new)
        })
    }
}

impl tower::Service<http::Request<tonic::body::Body>> for GrpcService {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let state = std::sync::Arc::clone(&self.state);
        Box::pin(async move {
            let path = req.uri().path().to_string();
            let method = path
                .strip_prefix('/')
                .and_then(|p| p.split_once('/'))
                .and_then(|(svc, m)| {
                    state
                        .pool
                        .get_service_by_name(svc)
                        .and_then(|s| s.methods().find(|x| x.name() == m))
                });
            let Some(method) = method else {
                return Ok(Status::unimplemented(format!("unknown method {path}")).into_http());
            };
            let limit = state.limits.max_inbound_message_size;
            let mut grpc =
                Grpc::new(DynCodec::new(method.input())).max_decoding_message_size(limit);
            let response = if method.is_server_streaming() {
                grpc.server_streaming(Streaming { state, method }, req)
                    .await
            } else if method.is_client_streaming() {
                grpc.client_streaming(ClientStreaming { state, method }, req)
                    .await
            } else {
                grpc.unary(Unary { state, method }, req).await
            };
            Ok(crate::limits::as_resource_exhausted(response, limit))
        })
    }
}

/// TLS/mTLS server identity and optional client CA bundle for [`serve_tls`] / [`serve_listener_tls`].
#[derive(Clone, Debug, Default)]
pub struct TlsServerOptions {
    pub cert_pem: String,
    pub key_pem: String,
    pub client_ca_pem: Option<String>,
}

fn build_tls_config(tls: TlsServerOptions) -> tonic::transport::ServerTlsConfig {
    let mut cfg = tonic::transport::ServerTlsConfig::new().identity(
        tonic::transport::Identity::from_pem(tls.cert_pem, tls.key_pem),
    );
    if let Some(ca) = tls.client_ca_pem {
        cfg = cfg.client_ca_root(tonic::transport::Certificate::from_pem(ca));
    }
    cfg
}

/// Serves gRPC on `addr` until the process ends.
pub async fn serve(
    ledger: Arc<ExecutionService>,
    addr: SocketAddr,
) -> Result<(), tonic::transport::Error> {
    GrpcLimits::LEDGER_API
        .server()
        .serve(addr, GrpcService::new(ledger))
        .await
}

/// Serves the Admin API port on `addr` (see [`Listener::AdminApi`]) with its authentication.
pub async fn serve_admin(
    ledger: Arc<ExecutionService>,
    addr: SocketAddr,
    auth: Option<AdminApiAuth>,
) -> Result<(), tonic::transport::Error> {
    GrpcLimits::ADMIN_API
        .server()
        .serve(addr, GrpcService::for_admin_api_with(ledger, auth))
        .await
}

/// Serves gRPC over TLS (and optional mTLS when `tls.client_ca_pem` is set) on `addr`.
pub async fn serve_tls(
    ledger: Arc<ExecutionService>,
    addr: SocketAddr,
    tls: TlsServerOptions,
) -> Result<(), tonic::transport::Error> {
    GrpcLimits::LEDGER_API
        .server()
        .tls_config(build_tls_config(tls))?
        .serve(addr, GrpcService::new(ledger))
        .await
}

/// Serves gRPC on an already bound listener (tests bind port 0).
pub async fn serve_listener(
    ledger: Arc<ExecutionService>,
    listener: tokio::net::TcpListener,
) -> Result<(), tonic::transport::Error> {
    if !ledger.admin_ports().contains_key("ledger") && !ledger.admin_ports().contains_key("admin") {
        if let Ok(a) = listener.local_addr() {
            ledger.set_admin_port("ledger", a.port());
        }
    }
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    GrpcLimits::LEDGER_API
        .server()
        .serve_with_incoming(GrpcService::new(ledger), incoming)
        .await
}

/// Like [`serve_listener`], for the Admin API endpoint: eagerly loads and vets the built-in ping DAR and starts
/// the Ping Nanobot responder before serving requests.
pub async fn serve_admin_listener(
    ledger: Arc<ExecutionService>,
    listener: tokio::net::TcpListener,
) -> Result<(), Status> {
    serve_admin_listener_with(ledger, listener, None).await
}

/// [`serve_admin_listener`] with the port's authentication.
pub async fn serve_admin_listener_with(
    ledger: Arc<ExecutionService>,
    listener: tokio::net::TcpListener,
    auth: Option<AdminApiAuth>,
) -> Result<(), Status> {
    if let Ok(a) = listener.local_addr() {
        ledger.set_admin_port("admin", a.port());
    }
    let setup = Arc::clone(&ledger);
    tokio::task::spawn_blocking(move || crate::admin_api::ensure_ping_workflow(&setup))
        .await
        .map_err(|e| Status::internal(format!("admin setup task panicked: {e}")))??;
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    GrpcLimits::ADMIN_API
        .server()
        .serve_with_incoming(GrpcService::for_admin_api_with(ledger, auth), incoming)
        .await
        .map_err(|e| Status::internal(e.to_string()))
}

/// Serves gRPC over TLS (and optional mTLS when `tls.client_ca_pem` is set) on an already bound listener.
pub async fn serve_listener_tls(
    ledger: Arc<ExecutionService>,
    listener: tokio::net::TcpListener,
    tls: TlsServerOptions,
) -> Result<(), tonic::transport::Error> {
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    GrpcLimits::LEDGER_API
        .server()
        .tls_config(build_tls_config(tls))?
        .serve_with_incoming(GrpcService::new(ledger), incoming)
        .await
}
