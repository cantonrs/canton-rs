//! The authorization of a stream while it stays open (Canton 3.7.2 `UserBasedOngoingAuthorization`).
//!
//! [CANTON-NOTE: SEMANTICS] Two checks end an open stream with gRPC `ABORTED`:
//! - before each element is sent, the token's `exp` (less the `expires-at` leeway) must lie ahead (`checkClaimsExpiry`):
//!   `ACCESS_TOKEN_EXPIRED`. An idle stream is not ended by its token's expiry.
//! - every `userRightsCheckIntervalInSeconds` (the user-management cache expiry, 5 s by default) the user is read again; a user
//!   that is gone, deactivated, or whose rights differ from those the stream started with ends it (`UserRightsChangeAsyncChecker`):
//!   `STALE_STREAM_AUTHORIZATION`.
//!
//! [CANTON-NOTE: LIMITATION] The deactivation of the user's identity provider and `token-expiry-grace-period-for-streams` are not
//! looked at.
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde_json::{json, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2_commands::{canton_error, Kind};

/// `UserManagementServiceConfig.DefaultCacheExpiryAfterWriteInSeconds`.
pub const USER_RIGHTS_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// The user a stream was opened as, and its rights then.
struct OpenedAs {
    user_id: String,
    rights: BTreeSet<String>,
}

/// What a stream re-checks while open; nothing for a server without authentication or a wildcard token.
pub struct StreamAuthorization {
    /// The token's `exp` less its leeway, in seconds.
    expires_at: Option<i64>,
    user: Option<OpenedAs>,
    last_rights_check: Instant,
}

fn rights_of(service: &ExecutionService, user_id: &str) -> Option<BTreeSet<String>> {
    let (_, active) = service.v2_state().user_idp_and_active(user_id)?;
    if !active {
        return None;
    }
    let rights = service.v2_state().user_rights(user_id)?;
    Some(rights.iter().map(Json::to_string).collect())
}

fn aborted(code: &str, cause: &str, retry: &'static str) -> HttpResponse {
    canton_error(
        Kind::Ctx {
            submission: false,
            definite: true,
            field: None,
            retry: Some(retry),
        },
        409,
        code,
        cause.into(),
        2,
        10,
        json!([]),
    )
}

impl StreamAuthorization {
    /// Captured once the stream's opening call was admitted; `authorization` is its `Authorization` header.
    pub fn capture(service: &ExecutionService, authorization: Option<&str>) -> Self {
        let req = HttpRequest {
            method: "GET".into(),
            path: "/".into(),
            query_params: Default::default(),
            headers: authorization
                .map(|a| ("authorization".to_string(), a.to_string()))
                .into_iter()
                .collect(),
            body: Vec::new(),
        };
        Self::capture_request(service, &req)
    }

    /// [`StreamAuthorization::capture`] for the opening request `req` (its token in a header or a WebSocket protocol).
    pub fn capture_request(service: &ExecutionService, req: &HttpRequest) -> Self {
        let mut out = StreamAuthorization {
            expires_at: None,
            user: None,
            last_rights_check: Instant::now(),
        };
        let (Some(cfg), Some(claims)) = (service.auth_config(), crate::auth::token_claims(req))
        else {
            return out;
        };
        let leeway = cfg.expires_at_leeway_secs.unwrap_or(cfg.leeway_secs);
        out.expires_at = claims["exp"].as_i64().map(|exp| exp + leeway);
        if let Some(user_id) = claims["sub"].as_str() {
            if let Some(rights) = rights_of(service, user_id) {
                out.user = Some(OpenedAs {
                    user_id: user_id.to_string(),
                    rights,
                });
            }
        }
        out
    }

    /// The check before an element is sent.
    pub fn before_element(&self) -> Result<(), HttpResponse> {
        match self.expires_at {
            Some(exp) if crate::clock::now_secs() as i64 >= exp => Err(aborted(
                "ACCESS_TOKEN_EXPIRED",
                "JWT token has expired",
                "1 second",
            )),
            _ => Ok(()),
        }
    }

    /// The periodic check of the user's rights: due every [`USER_RIGHTS_CHECK_INTERVAL`].
    pub fn periodic(&mut self, service: &ExecutionService) -> Result<(), HttpResponse> {
        if self.last_rights_check.elapsed() < USER_RIGHTS_CHECK_INTERVAL {
            return Ok(());
        }
        self.rights_unchanged(service)
    }

    /// Why a read the stream makes for its next elements was refused, as this stream reports it: the stream re-reads with the
    /// token it was opened with, which the participant does not authenticate again (`None`: the refusal is not this stream's).
    pub fn refusal_of_next_read(&mut self, service: &ExecutionService) -> Option<HttpResponse> {
        self.before_element()
            .and_then(|()| self.rights_unchanged(service))
            .err()
    }

    fn rights_unchanged(&mut self, service: &ExecutionService) -> Result<(), HttpResponse> {
        let Some(user) = &self.user else {
            return Ok(());
        };
        self.last_rights_check = Instant::now();
        if rights_of(service, &user.user_id).as_ref() == Some(&user.rights) {
            Ok(())
        } else {
            Err(aborted(
                "STALE_STREAM_AUTHORIZATION",
                "Stale stream authorization. Retry quickly.",
                "0 seconds",
            ))
        }
    }
}
