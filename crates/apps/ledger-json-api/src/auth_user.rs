//! `RequiredClaim.MatchUserId` (Canton 3.7.2 `Authorizer.authorizeRequiredClaim`): the user id a submission, a prepare, an
//! execute or a completion stream names is checked against the token's user, and an empty one becomes the token's user.
//!
//! [CANTON-NOTE: SEMANTICS] `Authorizer.scala`:
//! `defaultUserId(userIdL.get(req), claims).flatMap(defaultedUserId => ... .getOrElse(claims.validForUser(defaultedUserId)) .map(_ => userIdL.set(defaultedUserId)(req)))`,
//! with `validForUser` failing `InvalidUser` (a `PERMISSION_DENIED`, so the generic security body) when the claims carry a user
//! other than the request's. The completion stream skips the comparison for a reader of any party
//! (`skipUserIdValidationForAnyPartyReaders = true` in `CommandCompletionServiceAuthorization`).
//!
//! [CANTON-NOTE: LIMITATION] Only a user token carries a user here. A wildcard token (and a server without authentication) gives
//! Canton `Claims.Wildcard` without a user, where an empty user id is `INVALID_TOKEN`; this server leaves that case to the
//! handlers as before (the completion stream answers `INVALID_TOKEN`, a submission runs with an empty user id).
use serde_json::{json, Value as Json};

use crate::http::{HttpRequest, HttpResponse};

/// Where a call carries the user id `MatchUserId` reads.
struct UserIdField {
    /// The object of the body holding `userId` when it is an object (`commands`, `reassignmentCommands`); else the body itself.
    container: Option<&'static str>,
    skip_for_any_party_readers: bool,
}

fn field_of(method: &str, path: &str) -> Option<UserIdField> {
    if method != "POST" {
        return None;
    }
    let (container, skip) = match path {
        "/v2/commands/submit-and-wait"
        | "/v2/commands/submit-and-wait-for-transaction"
        | "/v2/commands/submit-and-wait-for-transaction-tree"
        | "/v2/commands/async/submit" => (Some("commands"), false),
        "/v2/commands/async/submit-reassignment"
        | "/v2/commands/submit-and-wait-for-reassignment" => (Some("reassignmentCommands"), false),
        "/v2/interactive-submission/prepare"
        | "/v2/interactive-submission/execute"
        | "/v2/interactive-submission/executeAndWait"
        | "/v2/interactive-submission/executeAndWaitForTransaction" => (None, false),
        "/v2/commands/completions" => (None, true),
        _ => return None,
    };
    Some(UserIdField {
        container,
        skip_for_any_party_readers: skip,
    })
}

/// The token's side of the check.
pub(crate) struct TokenUser<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) reads_any_party: bool,
}

/// `Err`: the refusal. `Ok(Some(req))`: the request with the token's user filled in. `Ok(None)`: the request as it is.
pub(crate) fn match_user_id(
    req: &HttpRequest,
    token: &TokenUser<'_>,
) -> Result<Option<HttpRequest>, HttpResponse> {
    let Some(field) = field_of(&req.method, req.path.trim_end_matches('/')) else {
        return Ok(None);
    };
    // a body that is not a JSON object is the handler's to refuse
    let Ok(mut body) = serde_json::from_slice::<Json>(&req.body) else {
        return Ok(None);
    };
    let holder = match field.container {
        Some(key) if body.get(key).is_some_and(Json::is_object) => body.get_mut(key),
        _ => Some(&mut body),
    };
    let Some(holder) = holder.and_then(Json::as_object_mut) else {
        return Ok(None);
    };
    let requested = holder
        .get("userId")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string();
    let skip = field.skip_for_any_party_readers && token.reads_any_party;
    if !requested.is_empty() {
        return if skip || requested == token.user_id {
            Ok(None)
        } else {
            Err(crate::auth::security_error(403))
        };
    }
    holder.insert("userId".into(), json!(token.user_id));
    let mut filled = req.clone();
    filled.body = serde_json::to_vec(&body).map_err(|_| crate::auth::security_error(403))?;
    Ok(Some(filled))
}
