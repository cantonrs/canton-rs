//! The authentication of a node's Admin API port, as its `admin-api` block configures it (internal review A-20).
//!
//! [CANTON-NOTE: SEMANTICS] `GrpcAuthInterceptorFactory.createInterceptor`: without `auth-services` every call passes
//! (`AuthServiceWildcard`, Canton's default); with them, a call passes the node's admin token (`CantonAdminTokenAuthService`: the
//! `admin-token-config.fixed-admin-token`, carrying the admin claim only with `admin-token-config.admin-claim = true`) or a token of one
//! of the services, and must then hold the admin claim (`RequiringAdminClaimResolver`). A JWT service grants it only when it is
//! `privileged` with a `target-audience` or `target-scope` (`AuthServicePrivilegedJWT`); an ordinary token authenticates a user, which
//! the Admin API refuses (`UserBasedAuthenticationIsDisabled`). A `wildcard` service grants every claim.
use crate::auth::{security_error, AuthConfig};
use crate::http::HttpResponse;

/// One of the `auth-services` of an `admin-api`.
#[derive(Clone)]
pub struct AdminAuthService {
    pub verifier: AuthConfig,
    /// `privileged = true` with a target audience or scope: its tokens carry the admin claim.
    pub privileged: bool,
}

/// The authentication of an Admin API port that has `auth-services` (one without them takes every call).
#[derive(Clone)]
pub struct AdminApiAuth {
    pub services: Vec<AdminAuthService>,
    /// `admin-token-config.fixed-admin-token`.
    pub fixed_admin_token: Option<String>,
    /// `admin-token-config.admin-claim`: whether the admin token carries the admin claim.
    pub admin_claim: bool,
}

impl AdminApiAuth {
    /// `Ok` when the call may proceed, else the security error it is answered with (401 unauthenticated, 403 lacking the admin claim).
    pub fn check(&self, authorization: Option<&str>) -> Result<(), HttpResponse> {
        let token = authorization
            .and_then(|h| {
                h.strip_prefix("Bearer ")
                    .or_else(|| h.strip_prefix("bearer "))
            })
            .map(str::trim)
            .filter(|t| !t.is_empty());
        if let (Some(t), Some(fixed)) = (token, self.fixed_admin_token.as_deref()) {
            if constant_time_eq(t.as_bytes(), fixed.as_bytes()) {
                return if self.admin_claim {
                    Ok(())
                } else {
                    Err(security_error(403))
                };
            }
        }
        for service in &self.services {
            match crate::auth::verify_token(&service.verifier, token) {
                Ok(verified) if verified.is_wildcard || service.privileged => return Ok(()),
                // a user's token: user-based authentication is disabled on the Admin API
                Ok(_) => return Err(security_error(401)),
                Err(_) => {}
            }
        }
        Err(security_error(401))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
