//! S-API-007: identity provider configuration of the JSON API v2 (`/v2/idps`, `/v2/idps/{id}`) and the move of a user
//! between providers (`PATCH /v2/users/{id}/identity-provider-id`), checked against the Canton 3.7.2 sandbox by
//! `scripts/verify-json-api.sh`.
//!
//! [CANTON-NOTE: SEMANTICS] A provider is an id, an issuer, a JWKS URL and an audience. Ids and issuers are unique. This
//! server stores and serves them; it never fetches the JWKS or validates a token (there is no authentication yet).
use std::collections::BTreeMap;

use serde_json::{json, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2_commands::{bad_body, canton_error, Kind};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct IdpRec {
    deactivated: bool,
    issuer: String,
    jwks_url: String,
    audience: String,
}

/// Replaces the identity provider configurations by those of an official participant's database (U-47): `(id, issuer, JWKS URL, audience,
/// deactivated)`.
pub(crate) fn adopt_official_idps(
    state: &crate::v2::V2State,
    idps: &[(String, String, String, String, bool)],
) {
    let adopted = idps
        .iter()
        .map(|(id, issuer, jwks_url, audience, deactivated)| {
            (
                id.clone(),
                IdpRec {
                    deactivated: *deactivated,
                    issuer: issuer.clone(),
                    jwks_url: jwks_url.clone(),
                    audience: audience.clone(),
                },
            )
        })
        .collect();
    if let Ok(mut i) = state.idps.lock() {
        *i = adopted;
    }
}

/// The identity providers as the official table holds them: `(id, issuer, JWKS URL, audience, deactivated)`.
pub(crate) fn official_rows(idps: &Idps) -> Vec<(String, String, String, String, bool)> {
    idps.iter()
        .map(|(id, c)| {
            (
                id.clone(),
                c.issuer.clone(),
                c.jwks_url.clone(),
                c.audience.clone(),
                c.deactivated,
            )
        })
        .collect()
}

fn config_json(id: &str, c: &IdpRec) -> Json {
    json!({
        "identityProviderId": id,
        "isDeactivated": c.deactivated,
        "issuer": c.issuer,
        "jwksUrl": c.jwks_url,
        "audience": c.audience
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn err(
    definite: bool,
    field: Option<&'static str>,
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
            definite,
            field,
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

fn not_found(verb: &str, id: &str) -> HttpResponse {
    err(
        true,
        None,
        404,
        "IDP_CONFIG_NOT_FOUND",
        format!("{verb} identity provider config failed for unknown identity provider id=\"{id}\""),
        11,
        5,
        json!([["IDENTITY_PROVIDER_CONFIG", id]]),
    )
}

fn missing(field: &'static str) -> HttpResponse {
    err(
        true,
        Some(field),
        400,
        "MISSING_FIELD",
        format!("The submitted command is missing a mandatory field: {field}"),
        8,
        3,
        json!([]),
    )
}

fn invalid_field(field: &str, why: &str) -> HttpResponse {
    err(
        true,
        None,
        400,
        "INVALID_FIELD",
        format!(
            "The submitted command has a field with invalid value: Invalid field {field}: {why}"
        ),
        8,
        3,
        json!([]),
    )
}

/// The first character a Daml-LF ledger string does not allow.
fn bad_ledger_char(s: &str) -> Option<char> {
    s.chars()
        .find(|c| !(c.is_ascii_alphanumeric() || "._:-#/ ".contains(*c)))
}

/// A Java `URL`-style check for the cases measured: a space is an illegal character in the path.
fn bad_url(url: &str) -> Option<String> {
    url.find(' ')
        .map(|i| format!("Malformed URL: Illegal character in path at index {i}: {url}"))
}

/// Routes `/v2/idps...`; `None` when the path is not one of them.
pub fn route(
    service: &ExecutionService,
    req: &HttpRequest,
    method: &str,
    path: &str,
) -> Option<HttpResponse> {
    let rest = path.strip_prefix("/v2/idps")?;
    let id = rest.strip_prefix('/').map(crate::v2::percent_decode);
    match (method, id) {
        ("GET", None) => Some(list(service)),
        ("POST", None) => Some(create(service, req)),
        ("GET", Some(id)) => Some(get(service, &id)),
        ("DELETE", Some(id)) => Some(delete(service, &id)),
        ("PATCH", Some(id)) => Some(update(service, req, &id)),
        _ => None,
    }
}

fn list(service: &ExecutionService) -> HttpResponse {
    let idps = service.v2_state().idps.lock().expect("idps lock");
    HttpResponse::json(
        200,
        &json!({ "identityProviderConfigs": idps.iter().map(|(id, c)| config_json(id, c)).collect::<Vec<_>>() }),
    )
}

fn get(service: &ExecutionService, id: &str) -> HttpResponse {
    let idps = service.v2_state().idps.lock().expect("idps lock");
    match idps.get(id) {
        Some(c) => HttpResponse::json(
            200,
            &json!({ "identityProviderConfig": config_json(id, c) }),
        ),
        None => not_found("getting", id),
    }
}

fn delete(service: &ExecutionService, id: &str) -> HttpResponse {
    let mut idps = service.v2_state().idps.lock().expect("idps lock");
    if idps.remove(id).is_some() {
        HttpResponse::json(200, &json!({}))
    } else {
        not_found("deleting", id)
    }
}

fn create(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let Ok(body) = serde_json::from_slice::<Json>(&req.body) else {
        return bad_body("Invalid value for: body".to_string());
    };
    let Some(cfg) = body.get("identityProviderConfig").filter(|c| c.is_object()) else {
        return missing("identity_provider_config");
    };
    let text = |k: &str| cfg.get(k).and_then(Json::as_str).unwrap_or("").to_string();
    let id = text("identityProviderId");
    if id.is_empty() {
        return missing("identity_provider_id");
    }
    if let Some(c) = bad_ledger_char(&id) {
        return invalid_field(
            "identity_provider_id",
            &format!(
                "non expected character 0x{:x} in Daml-LF Ledger String \"{id}\"",
                c as u32
            ),
        );
    }
    let rec = IdpRec {
        deactivated: cfg
            .get("isDeactivated")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        issuer: text("issuer"),
        jwks_url: text("jwksUrl"),
        audience: text("audience"),
    };
    if rec.issuer.is_empty() {
        return missing("issuer");
    }
    if let Some(why) = bad_url(&rec.jwks_url) {
        return invalid_field("jwks_url", &why);
    }
    let mut idps = service.v2_state().idps.lock().expect("idps lock");
    if idps.contains_key(&id) {
        return err(
            true,
            None,
            409,
            "IDP_CONFIG_ALREADY_EXISTS",
            format!(
                "creating identity provider config failed, as identity provider \"{id}\" already exists"
            ),
            10,
            6,
            json!([["IDENTITY_PROVIDER_CONFIG", id]]),
        );
    }
    if idps.values().any(|c| c.issuer == rec.issuer) {
        return err(
            true,
            None,
            409,
            "IDP_CONFIG_ISSUER_ALREADY_EXISTS",
            format!(
                "creating identity provider config failed, as identity provider with issuer \"{}\" already exists",
                rec.issuer
            ),
            10,
            6,
            json!([["IDENTITY_PROVIDER_CONFIG", rec.issuer]]),
        );
    }
    let out = config_json(&id, &rec);
    idps.insert(id, rec);
    HttpResponse::json(200, &json!({ "identityProviderConfig": out }))
}

fn update(service: &ExecutionService, req: &HttpRequest, id: &str) -> HttpResponse {
    let Ok(body) = serde_json::from_slice::<Json>(&req.body) else {
        return bad_body("Invalid value for: body".to_string());
    };
    let cfg = body.get("identityProviderConfig").filter(|c| c.is_object());
    let text = |k: &str| {
        cfg.and_then(|c| c.get(k))
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string()
    };
    let body_id = text("identityProviderId");
    if body_id != id {
        // Canton renders the body's config as a Scala case class inside an `Option`
        let shown = cfg.map_or("None".to_string(), |c| {
            format!(
                "Some(IdentityProviderConfig({},{},{},{},{}))",
                body_id,
                c.get("isDeactivated")
                    .and_then(Json::as_bool)
                    .unwrap_or(false),
                text("issuer"),
                text("jwksUrl"),
                text("audience")
            )
        });
        return canton_error(
            Kind::Preprocessing,
            400,
            "INVALID_ARGUMENT",
            format!("The submitted request has invalid arguments: {id} does not match idp in body: {shown}"),
            8,
            3,
            json!([]),
        );
    }
    let Some(mask) = body.get("updateMask").filter(|m| m.is_object()) else {
        return missing("update_mask");
    };
    let paths: Vec<&str> = mask
        .get("paths")
        .and_then(Json::as_array)
        .map(|a| a.iter().filter_map(Json::as_str).collect())
        .unwrap_or_default();
    let invalid = |why: &str| {
        err(
            false,
            None,
            400,
            "INVALID_IDENTITY_PROVIDER_UPDATE_REQUEST",
            format!("Update operation for identity provider config '{id}' failed due to: {why}"),
            8,
            3,
            json!([["IDENTITY_PROVIDER_CONFIG", id]]),
        )
    };
    if paths.is_empty() {
        return invalid("The update mask contains no entries");
    }
    const KNOWN: [&str; 4] = ["is_deactivated", "issuer", "jwks_url", "audience"];
    if let Some(bad) = paths.iter().find(|p| !KNOWN.contains(p)) {
        return invalid(&format!(
            "The update path: '{bad}' points to an unknown field."
        ));
    }
    let mut idps = service.v2_state().idps.lock().expect("idps lock");
    let Some(rec) = idps.get_mut(id) else {
        return not_found("updating", id);
    };
    for p in paths {
        match p {
            "is_deactivated" => {
                rec.deactivated = cfg
                    .and_then(|c| c.get("isDeactivated"))
                    .and_then(Json::as_bool)
                    .unwrap_or(false)
            }
            "issuer" => rec.issuer = text("issuer"),
            "jwks_url" => rec.jwks_url = text("jwksUrl"),
            "audience" => rec.audience = text("audience"),
            _ => {}
        }
    }
    HttpResponse::json(
        200,
        &json!({ "identityProviderConfig": config_json(id, rec) }),
    )
}

/// Whether a provider id names a configured provider (the default provider, the empty id, always exists).
pub(crate) fn exists(service: &ExecutionService, id: &str) -> bool {
    id.is_empty()
        || service
            .v2_state()
            .idps
            .lock()
            .expect("idps lock")
            .contains_key(id)
}

pub(crate) type Idps = BTreeMap<String, IdpRec>;

/// Public snapshot of an identity provider config for JWT verification in `auth`.
#[derive(Clone, Debug)]
pub(crate) struct IdpSnapshot {
    pub id: String,
    pub deactivated: bool,
    pub jwks_url: String,
    pub audience: String,
}

/// Finds a registered identity provider matching the token's `iss` claim.
pub(crate) fn idp_for_issuer(state: &crate::v2::V2State, issuer: &str) -> Option<IdpSnapshot> {
    if issuer.is_empty() {
        return None;
    }
    let idps = state.idps.lock().ok()?;
    idps.iter()
        .find(|(_, rec)| rec.issuer == issuer)
        .map(|(id, rec)| IdpSnapshot {
            id: id.clone(),
            deactivated: rec.deactivated,
            jwks_url: rec.jwks_url.clone(),
            audience: rec.audience.clone(),
        })
}
