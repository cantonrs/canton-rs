use crate::http::HttpResponse;
use crate::models::ledger_api::TemplateId;
use crate::service::{ApiError, ExecutionService};
use serde_json::{json, Map, Value as Json};

/// The kinds of Canton error body this module writes; they differ in the keys of `context`, in `correlationId` and in
/// `definiteAnswer` (all measured on the sandbox).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Daml interpretation errors raised while a command runs: `commands`, and for a failure `error_id` and `exercise_trace`.
    Interpretation { failure: bool },
    /// Errors found before the command runs (unknown template, missing field of the request).
    Request,
    /// A request error that carries a correlation id (an invalid field of a submitted command).
    RequestCorrelated,
    /// A request whose mandatory field is absent: as `Request`, plus `field_name` in `context`.
    MissingField {
        name: &'static str,
        /// Whether the body carries a correlation id (the empty `commands` list does, a missing `event_format` does not).
        correlated: bool,
    },
    /// The command preprocessor's own error: an empty `context` and `definiteAnswer: false`.
    Preprocessing,
    /// `NON_POSITIVE_OFFSET`: a request error whose `context` has no `definite_answer`.
    BadOffset,
    /// User management and paging errors: `context` carries `submissionId` for the mutating calls, `definite_answer` unless
    /// `definite` is false, `field_name` when `field` is set; `retry` is the `retryInfo` text.
    Ctx {
        submission: bool,
        definite: bool,
        field: Option<&'static str>,
        retry: Option<&'static str>,
    },
}

/// Canton's JSON error body (`JsCantonError`).
pub(crate) fn canton_error(
    kind: Kind,
    status: u16,
    code: &str,
    cause: String,
    category: u64,
    grpc: u64,
    resources: Json,
) -> HttpResponse {
    let mut context = Map::new();
    let mut corr = Json::Null;
    let mut definite = Json::Null;
    match kind {
        Kind::Preprocessing => {
            corr = json!("0000000000000000");
            definite = json!(false);
        }
        Kind::Interpretation { failure } => {
            corr = json!("00000000-0000-0000-0000-000000000000");
            context.insert("participant".into(), json!("'rust'"));
            context.insert("category".into(), json!(category.to_string()));
            context.insert("tid".into(), json!("0000000000000000"));
            context.insert("definite_answer".into(), json!("false"));
            context.insert("commands".into(), json!("{}"));
            if failure {
                context.insert(
                    "error_id".into(),
                    json!(cause
                        .split(" (error category")
                        .next()
                        .and_then(|c| c.rsplit("User failure: ").next())
                        .unwrap_or("")),
                );
                context.insert("exercise_trace".into(), json!(""));
            }
        }
        Kind::Ctx {
            submission,
            definite: with_definite,
            field,
            ..
        } => {
            context.insert("participant".into(), json!("rust"));
            context.insert("category".into(), json!(category.to_string()));
            context.insert("tid".into(), json!("0000000000000000"));
            if submission {
                context.insert(
                    "submissionId".into(),
                    json!("00000000-0000-0000-0000-000000000000"),
                );
            }
            if with_definite {
                context.insert("definite_answer".into(), json!("false"));
            }
            if let Some(f) = field {
                context.insert("field_name".into(), json!(f));
            }
        }
        Kind::BadOffset => {
            context.insert("participant".into(), json!("rust"));
            context.insert("category".into(), json!(category.to_string()));
            context.insert("tid".into(), json!("0000000000000000"));
        }
        Kind::Request | Kind::RequestCorrelated | Kind::MissingField { .. } => {
            if kind == Kind::RequestCorrelated {
                corr = json!("00000000-0000-0000-0000-000000000000");
            }
            if let Kind::MissingField { name, correlated } = kind {
                context.insert("field_name".into(), json!(name));
                if correlated {
                    corr = json!("00000000-0000-0000-0000-000000000000");
                }
            }
            context.insert("participant".into(), json!("rust"));
            context.insert("category".into(), json!(category.to_string()));
            context.insert("tid".into(), json!("0000000000000000"));
            context.insert("definite_answer".into(), json!("false"));
        }
    }
    HttpResponse::json(
        status,
        &json!({
            "code": code,
            "cause": cause,
            "correlationId": corr,
            "traceId": "0000000000000000",
            "context": context,
            "resources": resources,
            "errorCategory": category,
            "grpcCodeValue": grpc,
            "retryInfo": match kind {
                Kind::Ctx { retry: Some(r), .. } => json!(r),
                _ => Json::Null,
            },
            "definiteAnswer": definite
        }),
    )
}

/// A 400 with Canton's plain-text body for a request body that does not parse.
pub(crate) fn bad_body(text: String) -> HttpResponse {
    let mut resp = HttpResponse::json(400, &Json::Null);
    resp.body = text.into_bytes();
    resp.headers
        .insert("Content-Type".into(), "text/plain; charset=UTF-8".into());
    resp.headers
        .insert("Content-Length".into(), resp.body.len().to_string());
    resp
}

/// `2026-11-10T06:49:21.680765Z` from the system clock (civil-from-days, no time crate).
pub(crate) fn now_rfc3339() -> String {
    rfc3339_from_micros(crate::clock::now_micros())
}

/// The RFC 3339 text of a time given in microseconds since the epoch.
pub(crate) fn rfc3339_from_micros(micros: i64) -> String {
    let now = micros.max(0);
    let (secs, micros) = (now / 1_000_000, (now % 1_000_000) as u32);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{micros:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// An update id: `1220` and 64 hex digits, unique per call.
pub(crate) fn update_id(n: u64) -> String {
    format!("1220{n:064x}")
}

/// Parses `#package-name:Module:Entity` or `<package-id>:Module:Entity`.
pub(crate) fn parse_template(service: &ExecutionService, s: &str) -> Result<TemplateId, ApiError> {
    let mut it = s.splitn(3, ':');
    let (first, module, entity) = (
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
    );
    if module.is_empty() || entity.is_empty() {
        return Err(ApiError::InvalidArgument(format!(
            "Invalid template id: {s}"
        )));
    }
    let package_id = match first.strip_prefix('#') {
        Some(name) => service
            .v2_package_id_for_name(name)
            .unwrap_or_else(|| first.to_string()),
        None => first.to_string(),
    };
    Ok(TemplateId::new(package_id, module, entity))
}

/// A contract id this ledger could have issued: `00`, a 32-byte discriminator (64 hex digits) and the 36-byte suffix `ca12`
/// + a `1220` multihash (138 hex digits in all).
///
/// [CANTON-NOTE: SEMANTICS] Measured on the node (AT-U04): an id of any other shape is `UNSUPPORTED_CONTRACT_ID` (404) on the
/// exercise path even when it is long and hex; only an id of this shape that no contract has is `CONTRACT_NOT_FOUND`.
/// What Daml-LF accepts as a contract id string: `00` and hex pairs (lower case), at most 95 bytes.
pub(crate) fn parseable_contract_id(id: &str) -> bool {
    id.len() >= 2
        && id.len() <= 190
        && id.len().is_multiple_of(2)
        && id.starts_with("00")
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn well_formed_contract_id(id: &str) -> bool {
    id.len() == 138
        && id.starts_with("00")
        && id.chars().all(|c| c.is_ascii_hexdigit())
        && id[66..].starts_with("ca121220")
}

pub(crate) fn map_error(
    err: ApiError,
    contract_id: Option<&str>,
    service: &ExecutionService,
) -> HttpResponse {
    match err {
        ApiError::TemplateNotFound(id) => canton_error(
            Kind::Request,
            404,
            "TEMPLATES_OR_INTERFACES_NOT_FOUND",
            format!("Templates do not exist: [{id}]."),
            11,
            5,
            json!([["TEMPLATE_ID", id]]),
        ),
        ApiError::Unauthorized(msg) => {
            let text = msg.strip_prefix("Left Authorization failure: ").unwrap_or(&msg);
            canton_error(Kind::Interpretation { failure: false }, 400, "DAML_AUTHORIZATION_ERROR", format!("Interpretation error: Error: {text}"), 8, 3, json!([]))
        }
        ApiError::PreconditionFailed(msg) => canton_error(
            Kind::Interpretation { failure: true },
            400,
            "DAML_FAILURE",
            format!("Interpretation error: Error: User failure: UNHANDLED_EXCEPTION/DA.Exception.PreconditionFailed:PreconditionFailed (error category 9): {msg}"),
            9,
            9,
            json!([]),
        ),
        ApiError::InvalidArgument(msg) if msg.starts_with("UNHANDLED_EXCEPTION/") => {
            let (id, text) = msg.split_once(": ").unwrap_or((&msg, ""));
            canton_error(Kind::Interpretation { failure: true }, 400, "DAML_FAILURE", format!("Interpretation error: Error: User failure: {id} (error category 9): {text}"), 9, 9, json!([]))
        }
        // two submissions that overlap in time on one contract: the one that loses is refused while the winner holds it
        ApiError::ContractNotActive(id)
            if service.consumed_during(&id, crate::service::arrival()) =>
        {
            canton_error(
                Kind::Interpretation { failure: false },
                409,
                "LOCAL_VERDICT_LOCKED_CONTRACTS",
                format!("Local verdict: the contract {id} is locked by a concurrent submission"),
                2,
                10,
                json!([["CONTRACT_ID", id]]),
            )
        }
        ApiError::ContractNotActive(id) => {
            let known = contract_id.is_some_and(|c| service.v2_contract(c).is_some());
            if known || well_formed_contract_id(&id) {
                canton_error(Kind::Interpretation { failure: false }, 404, "CONTRACT_NOT_FOUND", format!("Contract could not be found with id {id}"), 11, 5, json!([["CONTRACT_ID", id]]))
            } else {
                canton_error(
                    Kind::Interpretation { failure: false },
                    404,
                    "UNSUPPORTED_CONTRACT_ID",
                    format!("Interpretation error: Error: Update failed due to a unsupported contract ID {id}"),
                    11,
                    5,
                    json!([["CONTRACT_ID", id]]),
                )
            }
        }
        // [CANTON-NOTE: SEMANTICS] A caught exception whose `try` body created or consumed contracts is a ledger error,
        // `DAML_EFFECTFUL_ROLLBACK_ERROR` (measured on the sandbox, AT-T05); the whole command fails and nothing is committed.
        ApiError::Ledger(msg) if msg.starts_with("INTERPRETATION_UPGRADE_ERROR_TRANSLATION_FAILED") => canton_error(
            Kind::Interpretation { failure: false },
            400,
            "INTERPRETATION_UPGRADE_ERROR_TRANSLATION_FAILED",
            format!("Interpretation error: Error: Translation of contract failed: {msg}"),
            8,
            3,
            json!([]),
        ),
        ApiError::Ledger(msg) if msg.starts_with("contract key not found for template ") => {
            let tpl = msg.trim_start_matches("contract key not found for template ");
            canton_error(
                Kind::Interpretation { failure: false },
                404,
                "CONTRACT_KEY_NOT_FOUND",
                format!("Interpretation error: Error: dependency error: couldn't find key: {tpl}"),
                11,
                5,
                json!([]),
            )
        }
        ApiError::Ledger(msg) if msg.starts_with("Tried to rollback side-effectful") => canton_error(
            Kind::Interpretation { failure: false },
            400,
            "DAML_EFFECTFUL_ROLLBACK_ERROR",
            format!("Interpretation error: Error: {msg}"),
            8,
            3,
            json!([]),
        ),
        ApiError::SynchronizerRejected {
            code,
            cause,
            grpc_code,
            http_status,
            category,
            details,
        } => match details.as_deref().and_then(refusal_context) {
            // what a participant's refusal carries: the official participant reports its error with the confirming parties, the
            // participant that reported it, the synchronizer and the contracts (`Verdict.ParticipantReject.keyErrorDetails`)
            Some((context, resources)) => HttpResponse::json(
                http_status,
                &json!({
                    "code": code,
                    "cause": cause,
                    "correlationId": Json::Null,
                    "traceId": context.get("tid").cloned().unwrap_or(Json::Null),
                    "context": context,
                    "resources": resources,
                    "errorCategory": category,
                    "grpcCodeValue": grpc_code,
                    "retryInfo": Json::Null,
                    "definiteAnswer": Json::Null
                }),
            ),
            None => canton_error(
                Kind::Interpretation { failure: false },
                http_status,
                &code,
                cause,
                category,
                grpc_code as u64,
                json!([]),
            ),
        },
        other => canton_error(Kind::Preprocessing, 400, "COMMAND_PREPROCESSING_FAILED", other.to_string(), 8, 3, json!([])),
    }
}

/// `name::1220abcdef012345...::37-0` as the official errors print a synchronizer id: the fingerprint cut to 12 characters.
pub(crate) fn shorten_id(id: &str) -> String {
    match id.split_once("::") {
        Some((name, rest)) => match rest.split_once("::") {
            Some((fingerprint, suffix)) => format!(
                "{name}::{}...::{suffix}",
                &fingerprint[..fingerprint.len().min(12)]
            ),
            None => format!("{name}::{}...", &rest[..rest.len().min(12)]),
        },
        None => id.to_string(),
    }
}

/// The `context` and `resources` of the error a refusing participant's reason makes (`details` of `ApiError::SynchronizerRejected`:
/// JSON with `parties`, `reported_by`, `metadata`, `psid`). The error's own context (the contract ids, the category) comes first; the
/// reporting participant, its confirming parties, this participant and the synchronizer are added, as in the recording of the official
/// participant (`tests/oracle/u31-veto/jvm-veto.json`). The `tid` is a trace id: this service makes none.
pub(crate) fn refusal_context(details: &str) -> Option<(Map<String, Json>, Json)> {
    let details: Json = serde_json::from_str(details).ok()?;
    let mut context = Map::new();
    for (k, v) in details["metadata"].as_object()? {
        context.insert(k.clone(), v.clone());
    }
    let parties: Vec<&str> = details["parties"]
        .as_array()?
        .iter()
        .filter_map(Json::as_str)
        .collect();
    context.insert("confirming_parties".into(), json!(parties.join(", ")));
    context.insert(
        "reported_by_participant_id".into(),
        details["reported_by"].clone(),
    );
    context.insert("participant".into(), json!("rust"));
    if let Some(psid) = details["psid"].as_str() {
        context.insert("psid".into(), json!(shorten_id(psid)));
    }
    context.entry("definite_answer").or_insert(json!("false"));
    context.insert("tid".into(), json!("00000000000000000000000000000000"));
    // `CONTRACT_ID` is `List(a, b)` in the context and one `[CONTRACT_ID, id]` resource each
    let resources: Vec<Json> = context
        .get("CONTRACT_ID")
        .and_then(Json::as_str)
        .and_then(|l| l.strip_prefix("List(")?.strip_suffix(')'))
        .map(|ids| {
            ids.split(", ")
                .map(|id| json!(["CONTRACT_ID", id]))
                .collect()
        })
        .unwrap_or_default();
    Some((context, Json::Array(resources)))
}

/// The `details` of the status of a completion a participant's refusal made: the `ErrorInfo` (the error code as the reason, the context
/// as the metadata), the `RequestInfo` (the trace id) and one `ResourceInfo` per contract, as the official participant sends them
/// (`tests/oracle/u31-veto/jvm-veto.json`). Empty for a completion without a refusal.
pub(crate) fn refusal_status_details(refusal: Option<&str>, message: &str) -> Vec<Json> {
    fn field(number: u8, bytes: &[u8], out: &mut Vec<u8>) {
        out.push(number << 3 | 2);
        let mut len = bytes.len();
        while len >= 0x80 {
            out.push((len & 0x7f) as u8 | 0x80);
            len >>= 7;
        }
        out.push(len as u8);
        out.extend_from_slice(bytes);
    }
    let any = |type_url: &str, value: Vec<u8>, decoded: Json| {
        json!({
            "typeUrl": format!("type.googleapis.com/{type_url}"),
            "unknownFields": {"fields": {}},
            "value": crate::v2::base64(&value),
            "valueDecoded": decoded,
        })
    };
    let Some((context, resources)) = refusal.and_then(refusal_context) else {
        return Vec::new();
    };
    let reason = message.split('(').next().unwrap_or_default();
    let tid = context
        .get("tid")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let mut error_info = Vec::new();
    field(1, reason.as_bytes(), &mut error_info);
    for (k, v) in &context {
        let mut entry = Vec::new();
        field(1, k.as_bytes(), &mut entry);
        field(2, v.as_str().unwrap_or_default().as_bytes(), &mut entry);
        field(3, &entry, &mut error_info);
    }
    let mut request_info = Vec::new();
    field(1, tid.as_bytes(), &mut request_info);
    let mut details = vec![
        any(
            "google.rpc.ErrorInfo",
            error_info,
            json!({"domain": "", "metadata": context, "reason": reason, "unknownFields": {"fields": {}}}),
        ),
        any(
            "google.rpc.RequestInfo",
            request_info,
            json!({"requestId": tid, "servingData": "", "unknownFields": {"fields": {}}}),
        ),
    ];
    for resource in resources.as_array().into_iter().flatten() {
        let name = resource[1].as_str().unwrap_or_default();
        let mut info = Vec::new();
        field(1, b"CONTRACT_ID", &mut info);
        field(2, name.as_bytes(), &mut info);
        details.push(any(
            "google.rpc.ResourceInfo",
            info,
            json!({"description": "", "owner": "", "resourceName": name, "resourceType": "CONTRACT_ID", "unknownFields": {"fields": {}}}),
        ));
    }
    details
}
