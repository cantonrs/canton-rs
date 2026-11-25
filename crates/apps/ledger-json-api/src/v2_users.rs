//! S-API-005: user management of the JSON API v2 (`/v2/users`, `/v2/users/{id}`, `/v2/users/{id}/rights`,
//! `/v2/authenticated-user`), checked against the Canton 3.7.2 sandbox by `scripts/verify-json-api.sh`.
//!
//! [CANTON-NOTE: SEMANTICS] Users are stored per participant, ordered by id. Rights are kept as the JSON `kind` objects
//! Canton exchanges (`CanActAs`, `CanReadAs`, `ParticipantAdmin`, ...); a right is granted or revoked by equality.
//! No right or primary party is checked against the allocated parties (Canton accepts unknown parties, measured).
use std::collections::BTreeMap;

use serde_json::{json, Map, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2::{decode_page_token, page_token, percent_decode};
use crate::v2_commands::{bad_body, canton_error, Kind};

/// What the participant keeps for a user besides the id.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct UserRec {
    idp: String,
    primary_party: String,
    deactivated: bool,
    resource_version: u64,
    annotations: BTreeMap<String, String>,
    rights: Vec<Json>,
}

/// The participant starts with `participant_admin`, who holds `ParticipantAdmin`.
pub(crate) fn default_users() -> BTreeMap<String, UserRec> {
    let mut m = BTreeMap::new();
    m.insert(
        "participant_admin".to_string(),
        UserRec {
            idp: String::new(),
            primary_party: String::new(),
            deactivated: false,
            resource_version: 0,
            annotations: BTreeMap::new(),
            rights: vec![json!({ "ParticipantAdmin": { "value": {} } })],
        },
    );
    m
}

/// The users as the official tables hold them: `(id, primary party, deactivated, resource version, identity provider, annotations, rights as
/// (code, party))` (the inverse of [`adopt_official_users`]; a right of a kind this server does not know has no code and is left out).
#[allow(
    clippy::type_complexity,
    reason = "protocol or ledger hook signature uses an inline composite type"
)]
pub(crate) fn official_rows(
    users: &BTreeMap<String, UserRec>,
) -> Vec<(
    String,
    String,
    bool,
    u64,
    String,
    BTreeMap<String, String>,
    Vec<(i32, Option<String>)>,
)> {
    users
        .iter()
        .map(|(id, u)| {
            let rights = u
                .rights
                .iter()
                .filter_map(|r| {
                    let (kind, body) = r.as_object()?.iter().next()?;
                    let code = match kind.as_str() {
                        "ParticipantAdmin" => 1,
                        "CanActAs" => 2,
                        "CanReadAs" => 3,
                        "IdentityProviderAdmin" => 4,
                        "CanReadAsAnyParty" => 5,
                        "CanExecuteAs" => 6,
                        "CanExecuteAsAnyParty" => 7,
                        _ => return None,
                    };
                    let party = body["value"]["party"].as_str().map(String::from);
                    Some((code, party))
                })
                .collect();
            (
                id.clone(),
                u.primary_party.clone(),
                u.deactivated,
                u.resource_version,
                u.idp.clone(),
                u.annotations.clone(),
                rights,
            )
        })
        .collect()
}

/// Replaces the users by those of an official participant's database (U-47): `(id, primary party, deactivated, resource version, identity
/// provider, annotations, rights as (code, party))`. The right codes are those of `lapi_user_rights.user_right`.
#[allow(
    clippy::type_complexity,
    reason = "protocol or ledger hook signature uses an inline composite type"
)]
pub(crate) fn adopt_official_users(
    state: &crate::v2::V2State,
    users: &[(
        String,
        String,
        bool,
        u64,
        String,
        BTreeMap<String, String>,
        Vec<(i32, String)>,
    )],
) {
    let right_json = |code: i32, party: &str| -> Option<Json> {
        let named = |kind: &str| json!({ kind: { "value": { "party": party } } });
        let unnamed = |kind: &str| json!({ kind: { "value": {} } });
        Some(match code {
            1 => unnamed("ParticipantAdmin"),
            2 => named("CanActAs"),
            3 => named("CanReadAs"),
            4 => unnamed("IdentityProviderAdmin"),
            5 => unnamed("CanReadAsAnyParty"),
            6 => named("CanExecuteAs"),
            7 => unnamed("CanExecuteAsAnyParty"),
            _ => return None,
        })
    };
    let adopted = users
        .iter()
        .map(
            |(id, primary, deactivated, version, idp, annotations, rights)| {
                (
                    id.clone(),
                    UserRec {
                        idp: idp.clone(),
                        primary_party: primary.clone(),
                        deactivated: *deactivated,
                        resource_version: *version,
                        annotations: annotations.clone(),
                        rights: rights
                            .iter()
                            .filter_map(|(c, p)| right_json(*c, p))
                            .collect(),
                    },
                )
            },
        )
        .collect();
    if let Ok(mut u) = state.users.lock() {
        *u = adopted;
    }
}

fn user_json(id: &str, u: &UserRec) -> Json {
    json!({
        "id": id,
        "primaryParty": u.primary_party,
        "isDeactivated": u.deactivated,
        "metadata": { "resourceVersion": u.resource_version.to_string(), "annotations": u.annotations },
        "identityProviderId": u.idp,
        "primaryPartyAuthentication": false
    })
}

fn rights_json(rights: &[Json]) -> Vec<Json> {
    rights.iter().map(|k| json!({ "kind": k })).collect()
}

fn ok(body: Json) -> HttpResponse {
    HttpResponse::json(200, &body)
}

/// A request error. `submission`: the context carries a `submissionId` (the mutating calls); `definite`: it carries
/// `definite_answer`; `field` adds `field_name`.
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn err(
    submission: bool,
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
            submission,
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

fn user_not_found(verb: &str, id: &str, submission: bool) -> HttpResponse {
    err(
        submission,
        true,
        None,
        404,
        "USER_NOT_FOUND",
        format!("{verb} failed for unknown user \"{id}\""),
        11,
        5,
        json!([["USER", id]]),
    )
}

fn missing(field: &'static str) -> HttpResponse {
    err(
        true,
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

fn invalid_argument(submission: bool, why: &str) -> HttpResponse {
    err(
        submission,
        true,
        None,
        400,
        "INVALID_ARGUMENT",
        format!("The submitted request has invalid arguments: {why}"),
        8,
        3,
        json!([]),
    )
}

/// The path id must equal the id in the body; Canton renders the body's id as a Scala `Option`.
fn id_mismatch(path_id: &str, body_id: Option<&str>) -> HttpResponse {
    let shown = body_id.map_or("None".to_string(), |b| format!("Some({b})"));
    canton_error(
        Kind::Preprocessing,
        400,
        "INVALID_ARGUMENT",
        format!(
            "The submitted request has invalid arguments: {path_id} does not match user in body: {shown} "
        ),
        8,
        3,
        json!([]),
    )
}

fn valid_user_id(id: &str) -> bool {
    (1..=128).contains(&id.chars().count())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@^$.!`-#+'~_|:()".contains(c))
}

/// The distinct `kind` objects of a `rights` array, in order.
fn kinds(rights: Option<&Json>) -> Vec<Json> {
    let mut out: Vec<Json> = Vec::new();
    for r in rights.and_then(Json::as_array).into_iter().flatten() {
        if let Some(k) = r.get("kind") {
            if !out.contains(k) {
                out.push(k.clone());
            }
        }
    }
    out
}

/// Routes the user-management paths; `None` when the path is not one of them.
pub fn route(
    service: &ExecutionService,
    req: &HttpRequest,
    method: &str,
    path: &str,
) -> Option<HttpResponse> {
    if path == "/v2/authenticated-user" && method == "GET" {
        // [CANTON-NOTE: SEMANTICS] The user the bearer token names (its `sub`): the official participant answers with that user, as `GET
        // /v2/users/{sub}` does (the Wallet SDK asks for it first, tests/oracle/wallet-sdk). Without a token there is no authenticated user.
        if let Some(subject) = crate::auth::token_subject(req) {
            return Some(get(service, req, &subject));
        }
        return Some(err(
            false,
            true,
            None,
            400,
            "INVALID_TOKEN",
            "The submitted request is missing a user-id: requests with an empty user-id are only supported if there is an authenticated user".into(),
            8,
            3,
            json!([]),
        ));
    }
    let rest = path.strip_prefix("/v2/users")?;
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    if path == "/v2/users" {
        return match method {
            "GET" => Some(list(service, req)),
            "POST" => Some(create(service, req)),
            _ => None,
        };
    }
    let mut parts = rest.splitn(2, '/');
    let id = percent_decode(parts.next().unwrap_or(""));
    match (method, parts.next()) {
        ("GET", None) => Some(get(service, req, &id)),
        ("DELETE", None) => Some(delete(service, &id)),
        ("PATCH", None) => Some(update(service, req, &id)),
        ("GET", Some("rights")) => Some(list_rights(service, req, &id)),
        ("PATCH", Some("identity-provider-id")) => Some(move_user(service, req, &id)),
        ("POST", Some("rights")) => Some(change_rights(service, req, &id, true)),
        ("PATCH", Some("rights")) => Some(change_rights(service, req, &id, false)),
        _ => None,
    }
}

fn list(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let size = match req.query_params.get("pageSize").map(|s| s.parse::<i64>()) {
        Some(Ok(n)) if n < 0 => {
            return invalid_argument(false, "Max page size must be non-negative")
        }
        Some(Ok(n)) if n > 0 => n as usize,
        _ => 1000,
    };
    let after = match req.query_params.get("pageToken").filter(|t| !t.is_empty()) {
        Some(t) => match decode_page_token(t) {
            Some(a) => Some(a),
            None => return invalid_argument(false, "Invalid page token"),
        },
        None => None,
    };
    let Ok(users) = service.v2_state().users.lock() else {
        return invalid_argument(false, "users unavailable");
    };
    let rest: Vec<(&String, &UserRec)> = users
        .iter()
        .filter(|(_, u)| u.idp.is_empty())
        .filter(|(id, _)| after.as_ref().is_none_or(|a| id.as_str() > a.as_str()))
        .collect();
    let page: Vec<&(&String, &UserRec)> = rest.iter().take(size).collect();
    let next = match page.last() {
        Some((last, _)) if rest.len() > size => page_token(last),
        _ => String::new(),
    };
    ok(json!({
        "users": page.iter().map(|(id, u)| user_json(id, u)).collect::<Vec<_>>(),
        "nextPageToken": next
    }))
}

fn create(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let Ok(body) = serde_json::from_slice::<Json>(&req.body) else {
        return bad_body("Invalid value for: body".to_string());
    };
    let Some(user) = body.get("user").filter(|u| u.is_object()) else {
        return missing("user");
    };
    let id = user.get("id").and_then(Json::as_str).unwrap_or("");
    if id.is_empty() {
        return missing("id");
    }
    if !valid_user_id(id) {
        return err(
            true,
            true,
            None,
            400,
            "INVALID_FIELD",
            format!(
                "The submitted command has a field with invalid value: Invalid field id: User ID \"{id}\" does not match regex \"[a-zA-Z0-9@^$.!`\\-#+'~_|:\\(\\)]{{1,128}}\""
            ),
            8,
            3,
            json!([]),
        );
    }
    let meta = user.get("metadata").cloned().unwrap_or(Json::Null);
    if meta
        .get("resourceVersion")
        .and_then(Json::as_str)
        .is_some_and(|v| !v.is_empty())
    {
        return invalid_argument(true, "field user.metadata.resource_version must be not set");
    }
    let idp = user
        .get("identityProviderId")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string();
    if !crate::v2_idps::exists(service, &idp) {
        return invalid_argument(
            true,
            &format!("Provided identity_provider_id Id({idp}) has not been found."),
        );
    }
    let rec = UserRec {
        idp,
        primary_party: user["primaryParty"].as_str().unwrap_or("").to_string(),
        deactivated: user["isDeactivated"].as_bool().unwrap_or(false),
        resource_version: 0,
        annotations: annotations_of(&meta),
        rights: kinds(body.get("rights")),
    };
    let Ok(mut users) = service.v2_state().users.lock() else {
        return invalid_argument(true, "users unavailable");
    };
    if users.contains_key(id) {
        return err(
            true,
            true,
            None,
            409,
            "USER_ALREADY_EXISTS",
            format!("creating user failed, as user \"{id}\" already exists"),
            10,
            6,
            json!([["USER", id]]),
        );
    }
    let out = user_json(id, &rec);
    users.insert(id.to_string(), rec);
    ok(json!({ "user": out }))
}

fn annotations_of(meta: &Json) -> BTreeMap<String, String> {
    meta.get("annotations")
        .and_then(Json::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .filter(|(_, v)| !v.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn get(service: &ExecutionService, req: &HttpRequest, id: &str) -> HttpResponse {
    let Ok(users) = service.v2_state().users.lock() else {
        return invalid_argument(false, "users unavailable");
    };
    match users.get(id) {
        Some(u) if u.idp != scope(req) => security_error(),
        Some(u) => ok(json!({ "user": user_json(id, u) })),
        None => user_not_found("getting user", id, false),
    }
}

fn delete(service: &ExecutionService, id: &str) -> HttpResponse {
    let Ok(mut users) = service.v2_state().users.lock() else {
        return invalid_argument(true, "users unavailable");
    };
    if users.remove(id).is_some() {
        ok(json!({}))
    } else {
        user_not_found("deleting user", id, true)
    }
}

fn list_rights(service: &ExecutionService, req: &HttpRequest, id: &str) -> HttpResponse {
    let Ok(users) = service.v2_state().users.lock() else {
        return invalid_argument(false, "users unavailable");
    };
    match users.get(id) {
        Some(u) if u.idp != scope(req) => security_error(),
        Some(u) => ok(json!({ "rights": rights_json(&u.rights) })),
        None => user_not_found("list user rights", id, false),
    }
}

/// `POST` grants and `PATCH` revokes; the response lists the rights that actually changed.
fn change_rights(
    service: &ExecutionService,
    req: &HttpRequest,
    id: &str,
    grant: bool,
) -> HttpResponse {
    let Ok(body) = serde_json::from_slice::<Json>(&req.body) else {
        return bad_body("Invalid value for: body".to_string());
    };
    let body_id = body.get("userId").and_then(Json::as_str);
    if body_id != Some(id) {
        return id_mismatch(id, body_id);
    }
    let wanted = kinds(body.get("rights"));
    let Ok(mut users) = service.v2_state().users.lock() else {
        return invalid_argument(true, "users unavailable");
    };
    let verb = if grant {
        "grant user rights"
    } else {
        "revoke user rights"
    };
    let Some(user) = users.get_mut(id) else {
        return user_not_found(verb, id, true);
    };
    let mut changed = Vec::new();
    for k in wanted {
        let held = user.rights.contains(&k);
        if grant && !held {
            user.rights.push(k.clone());
            changed.push(k);
        } else if !grant && held {
            user.rights.retain(|r| r != &k);
            changed.push(k);
        }
    }
    let key = if grant {
        "newlyGrantedRights"
    } else {
        "newlyRevokedRights"
    };
    let mut out = Map::new();
    out.insert(key.into(), Json::Array(rights_json(&changed)));
    ok(Json::Object(out))
}

fn update(service: &ExecutionService, req: &HttpRequest, id: &str) -> HttpResponse {
    let Ok(body) = serde_json::from_slice::<Json>(&req.body) else {
        return bad_body("Invalid value for: body".to_string());
    };
    let user = body.get("user").filter(|u| u.is_object());
    let body_id = user.and_then(|u| u.get("id")).and_then(Json::as_str);
    if body_id != Some(id) {
        return id_mismatch(id, body_id);
    }
    let user = user.cloned().unwrap_or(Json::Null);
    let Some(mask) = body.get("updateMask").filter(|m| m.is_object()) else {
        return missing("update_mask");
    };
    let paths: Vec<&str> = mask
        .get("paths")
        .and_then(Json::as_array)
        .map(|a| a.iter().filter_map(Json::as_str).collect())
        .unwrap_or_default();
    let invalid_update = |why: &str| {
        err(
            true,
            false,
            None,
            400,
            "INVALID_USER_UPDATE_REQUEST",
            format!("Update operation for user id '{id}' failed due to: {why}"),
            8,
            3,
            json!([["USER", id]]),
        )
    };
    if paths.is_empty() {
        return invalid_update("The update mask contains no entries");
    }
    // `id` and `identity_provider_id` name fields that cannot change here; Canton accepts them (measured for `id`)
    const KNOWN: [&str; 5] = [
        "id",
        "primary_party",
        "is_deactivated",
        "metadata.annotations",
        "identity_provider_id",
    ];
    if let Some(bad) = paths.iter().find(|p| !KNOWN.contains(p)) {
        return invalid_update(&format!(
            "The update path: '{bad}' points to an unknown field."
        ));
    }
    let Ok(mut users) = service.v2_state().users.lock() else {
        return invalid_argument(true, "users unavailable");
    };
    let Some(rec) = users.get_mut(id) else {
        return user_not_found("updating user", id, true);
    };
    let sent_version = user
        .pointer("/metadata/resourceVersion")
        .and_then(Json::as_str)
        .unwrap_or("");
    if !sent_version.is_empty() && sent_version != rec.resource_version.to_string() {
        return canton_error(
            Kind::Ctx {
                submission: true,
                definite: false,
                field: None,
                retry: Some("1 second"),
            },
            409,
            "CONCURRENT_USER_UPDATE_DETECTED",
            format!("Update operation for user '{id}' failed due to a concurrent update to the same user"),
            2,
            10,
            json!([["USER", id]]),
        );
    }
    for p in &paths {
        match *p {
            "primary_party" => {
                rec.primary_party = user["primaryParty"].as_str().unwrap_or("").to_string();
            }
            "is_deactivated" => rec.deactivated = user["isDeactivated"].as_bool().unwrap_or(false),
            // annotations merge: a key with an empty value is removed, the others are set; the rest stay
            "metadata.annotations" => {
                for (k, v) in user
                    .pointer("/metadata/annotations")
                    .and_then(Json::as_object)
                    .into_iter()
                    .flatten()
                {
                    match v.as_str() {
                        Some("") | None => {
                            rec.annotations.remove(k);
                        }
                        Some(s) => {
                            rec.annotations.insert(k.clone(), s.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    rec.resource_version += 1;
    ok(json!({ "user": user_json(id, rec) }))
}

/// The identity provider a request is scoped to (`identity-provider-id` query parameter, default the empty provider).
fn scope(req: &HttpRequest) -> String {
    req.query_params
        .get("identity-provider-id")
        .cloned()
        .unwrap_or_default()
}

/// Canton hides whether a user exists in another provider: a scope mismatch is a generic "security-sensitive" 403.
fn security_error() -> HttpResponse {
    HttpResponse::json(
        403,
        &json!({
            "code": "NA",
            "cause": "A security-sensitive error has been received",
            "correlationId": "00000000000000000000000000000000",
            "traceId": "00000000000000000000000000000000",
            "context": {},
            "resources": [],
            "errorCategory": -1,
            "grpcCodeValue": 7,
            "retryInfo": null,
            "definiteAnswer": null
        }),
    )
}

/// `PATCH /v2/users/{id}/identity-provider-id`: moves a user from one identity provider to another.
fn move_user(service: &ExecutionService, req: &HttpRequest, id: &str) -> HttpResponse {
    let Ok(body) = serde_json::from_slice::<Json>(&req.body) else {
        return bad_body("Invalid value for: body".to_string());
    };
    let body_id = body.get("userId").and_then(Json::as_str);
    if body_id != Some(id) {
        return id_mismatch(id, body_id);
    }
    let text = |k: &str| body.get(k).and_then(Json::as_str).unwrap_or("").to_string();
    let (source, target) = (
        text("sourceIdentityProviderId"),
        text("targetIdentityProviderId"),
    );
    let Ok(mut users) = service.v2_state().users.lock() else {
        return invalid_argument(false, "users unavailable");
    };
    let Some(user) = users.get_mut(id) else {
        return user_not_found("update user identity provider", id, false);
    };
    if !crate::v2_idps::exists(service, &target) {
        return invalid_argument(
            false,
            &format!("Provided identity_provider_id Id({target}) has not been found."),
        );
    }
    if user.idp != source {
        return security_error();
    }
    user.idp = target;
    ok(json!({}))
}

impl crate::v2::V2State {
    /// The rights (as the JSON `kind` objects) of a user, `None` when there is no such user.
    pub(crate) fn user_rights(&self, id: &str) -> Option<Vec<Json>> {
        self.users.lock().ok()?.get(id).map(|u| u.rights.clone())
    }

    /// The identity provider id and active status (`!deactivated`) of a user, `None` when unknown.
    pub(crate) fn user_idp_and_active(&self, id: &str) -> Option<(String, bool)> {
        self.users
            .lock()
            .ok()?
            .get(id)
            .map(|u| (u.idp.clone(), !u.deactivated))
    }
}
