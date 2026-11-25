//! S-API-011: the remaining small JSON API v2 endpoints whose Canton answers this server can match without the parts it
//! does not have: JWKS of a party's signing keys (no external parties here), the validation errors of the
//! interactive-submission endpoints (the prepare/execute success path needs transaction hashing and signatures, which
//! this server does not implement), and the traffic endpoints (disabled in the 3.7.2 sandbox: Canton answers its generic
//! 404, which the router already gives).
use serde_json::{json, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2::percent_decode;
use crate::v2_commands::{bad_body, canton_error, Kind};

fn ctx_error(
    status: u16,
    code: &str,
    cause: String,
    category: u64,
    grpc: u64,
    resources: Json,
) -> HttpResponse {
    canton_error(
        Kind::Ctx {
            submission: false,
            definite: true,
            field: None,
            retry: None,
        },
        status,
        code,
        cause,
        category,
        grpc,
        resources,
    )
}

/// `GET /v2/jose/jwks/synchronizer/{synchronizer}/party/{party}`: returns JWK keys for onboarded external parties.
pub fn jwks(service: &ExecutionService, path: &str) -> Option<HttpResponse> {
    let rest = path.strip_prefix("/v2/jose/jwks/synchronizer/")?;
    let (sync, party) = rest.split_once("/party/")?;
    let (sync, party) = (percent_decode(sync), percent_decode(party));
    for (field, id) in [("synchronizerId", &sync), ("partyId", &party)] {
        if !id.contains("::") {
            return Some(ctx_error(
                400,
                "INVALID_ARGUMENT",
                format!("The submitted request has invalid arguments: Unable to convert field `{field}`: Invalid unique identifier `{id}` with missing namespace."),
                8,
                3,
                json!([]),
            ));
        }
    }
    let state = service.v2_state();
    let keys: Vec<Json> = state
        .external_parties
        .lock()
        .ok()
        .and_then(|map| map.get(&party).cloned())
        .filter(|info| info.synchronizer_id == sync || sync == state.synchronizer_id())
        .map(|info| {
            info.keys
                .iter()
                .filter_map(|pk| crate::auth_jwks::public_key_to_jwk(pk).ok())
                .collect()
        })
        .unwrap_or_default();
    if !keys.is_empty() {
        return Some(HttpResponse::json(200, &json!({ "keys": keys })));
    }
    Some(ctx_error(
        404,
        "PARTY_SIGNING_KEYS_NOT_FOUND",
        "Could not find signing keys for the requested party.".into(),
        11,
        5,
        json!([["PARTY", party]]),
    ))
}

/// `GET /docs/openapi` and `GET /docs/asyncapi`.
pub fn docs(kind: &str) -> Option<HttpResponse> {
    let body = match kind {
        "openapi" => {
            "openapi: 3.0.3\ninfo:\n  title: JSON Ledger API\n  version: 3.7.2\npaths:\n  /v2/version:\n    get:\n      summary: Get API version\n  /v2/state/ledger-end:\n    get:\n      summary: Get ledger end\n  /v2/updates:\n    post:\n      summary: Query updates\n"
        }
        "asyncapi" => {
            "asyncapi: 2.6.0\ninfo:\n  title: JSON Ledger API WebSocket endpoints\n  version: 3.7.2\nchannels:\n  /v2/updates: {}\n  /v2/state/active-contracts: {}\n  /v2/commands/completions: {}\n  /v2/commands/command-completions: {}\n"
        }
        _ => return None,
    };
    let mut resp = HttpResponse::json(200, &Json::Null);
    resp.body = body.as_bytes().to_vec();
    resp.headers
        .insert("Content-Type".into(), "text/plain; charset=UTF-8".into());
    resp.headers
        .insert("Content-Length".into(), resp.body.len().to_string());
    Some(resp)
}

/// The interactive-submission endpoints that take a request body. They report the missing required fields the way the
/// HTTP layer of Canton does; a complete request is not supported (no transaction hashing or party signatures here).
pub fn interactive(
    service: &ExecutionService,
    req: &HttpRequest,
    endpoint: &str,
) -> Option<HttpResponse> {
    let required: &[&str] = match endpoint {
        "prepare" => &[
            "commandId",
            "commands",
            "actAs",
            "synchronizerId",
            "packageIdSelectionPreference",
        ],
        "execute" | "executeAndWait" | "executeAndWaitForTransaction" => &[
            "preparedTransaction",
            "partySignatures",
            "deduplicationPeriod",
            "submissionId",
            "hashingSchemeVersion",
        ],
        _ => return None,
    };
    let body: Json = serde_json::from_slice(&req.body).unwrap_or(Json::Null);
    let missing: Vec<String> = required
        .iter()
        .filter(|k| body.get(**k).is_none())
        .map(|k| format!("Missing required field at '{k}'"))
        .collect();
    if !missing.is_empty() {
        return Some(bad_body(format!(
            "Invalid value for: body ({})",
            missing.join(", ")
        )));
    }
    match endpoint {
        "prepare" => Some(crate::v2_interactive::prepare(service, &body)),
        "execute" | "executeAndWait" | "executeAndWaitForTransaction" => {
            Some(crate::v2_interactive::execute(service, &body, endpoint))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use canton_algo::signing::{create_public_key, KeyFormat, KeySpec, Usage};

    use super::*;
    use crate::http::{dispatch_request, HttpRequest};
    use crate::v2_interactive::ExternalPartyInfo;
    use crate::AuthConfig;

    #[test]
    fn jwks_serves_external_party_keys_publicly_and_handles_missing_or_invalid() {
        let svc = ExecutionService::new();
        svc.set_auth(AuthConfig::hmac("secret-should-not-block-jwks"));
        let sync = svc.v2_state().synchronizer_id();
        let raw_ed25519 = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        let mut usage = BTreeSet::new();
        usage.insert(Usage::Protocol);
        let pk = create_public_key(KeyFormat::Raw, &raw_ed25519, KeySpec::EcCurve25519, usage)
            .expect("valid Ed25519 basepoint");
        let party = format!("ext::{}", pk.id);
        svc.v2_state()
            .external_parties
            .lock()
            .expect("lock")
            .insert(
                party.clone(),
                ExternalPartyInfo {
                    party_id: party.clone(),
                    fingerprint: pk.id.clone(),
                    keys: vec![pk],
                    threshold: 1,
                    synchronizer_id: sync.clone(),
                },
            );

        // Public JWKS access with no Authorization header succeeds for onboarded external party.
        let resp = dispatch_request(
            &svc,
            &HttpRequest {
                method: "GET".into(),
                path: format!("/v2/jose/jwks/synchronizer/{sync}/party/{party}"),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: Vec::new(),
            },
        );
        assert_eq!(resp.status, 200);
        let body: Json = serde_json::from_slice(&resp.body).expect("json");
        assert_eq!(body["keys"][0]["kty"], "OKP");
        assert_eq!(body["keys"][0]["crv"], "Ed25519");

        // Unknown party returns 404 PARTY_SIGNING_KEYS_NOT_FOUND.
        let missing = dispatch_request(
            &svc,
            &HttpRequest {
                method: "GET".into(),
                path: format!("/v2/jose/jwks/synchronizer/{sync}/party/nobody::1220abcd"),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: Vec::new(),
            },
        );
        assert_eq!(missing.status, 404);

        // Missing namespace returns 400 INVALID_ARGUMENT.
        let bad = dispatch_request(
            &svc,
            &HttpRequest {
                method: "GET".into(),
                path: "/v2/jose/jwks/synchronizer/bad/party/alsobad".into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: Vec::new(),
            },
        );
        assert_eq!(bad.status, 400);
    }
}
