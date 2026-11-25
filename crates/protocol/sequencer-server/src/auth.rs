//! A member authenticates to the sequencer (`SequencerAuthenticationService`): the server gives it a nonce (`Challenge`), the member
//! signs the nonce and the synchronizer's id with its sequencer-authentication key (`Authenticate`), and the server hands out a token.
//!
//! [CANTON-NOTE: SEMANTICS] What the member signs is the one hash `AuthKey::challenge_hash` computes (purpose 14, `AuthenticationToken`:
//! the nonce without a length prefix and the physical synchronizer id), as Ed25519 `r || s` signed by the key's fingerprint. The server
//! accepts a signature only from a key the member registered **for sequencer authentication** (the usage of the key in its mapping).
//!
//! [CANTON-NOTE: SEMANTICS] `MemberAuthenticationService` with the `PublicServerConfig` defaults: a member has **one pending nonce**, and
//! a `Challenge` while it is pending returns the same one (`fetchOrGenerateNonce`: an unauthenticated caller cannot knock out another
//! member's nonce); it expires after a minute (`nonceExpirationInterval`) and is consumed only by an answer whose signature verifies
//! (`removeNonceIfMatches` after the verification). A token expires after an hour (`maxTokenExpirationInterval`), and a subscription made
//! with it ends then (`SubscriptionPool`: `UNAVAILABLE` "Subscription token has expired").
//!
//! [CANTON-NOTE: SEMANTICS] A token holds only while the topology in force keeps its member and the key it was given for
//! (`MemberAuthenticationService.observed`: `invalidateAndExpire`, `invalidateTokensByFingerprint`): it is checked against the [`Registry`]
//! at every call, so a member the topology disables, or a key its mapping no longer names, loses its tokens at once. A disabled member is
//! refused a challenge as `MemberAccessDisabled` (`PERMISSION_DENIED`).
//!
//! [CANTON-NOTE: LIMITATION] Tokens live in memory (a restart forgets them: a member authenticates again).
use crate::onboarding::Registry;
use canton_participant::sequencer_connect::AuthKey;
use canton_algo::member_signature::{
    sequencer_authentication_only, verify_by_keys, SignatureCheckError,
};
use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_authentication::{
    AuthenticateRequest, AuthenticateResponse, ChallengeRequest, ChallengeResponse,
    LogoutRequest, LogoutResponse,
};
use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_authentication_service_server::SequencerAuthenticationService;
use rand::RngCore;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

/// How long a nonce may be answered (`PublicServerConfig.defaultNonceExpirationInterval`: one minute).
const NONCE_LIFETIME_MICROS: i64 = 60 * 1_000_000;

/// How long a token is good for (`PublicServerConfig.defaultMaxTokenExpirationInterval`: one hour).
const TOKEN_LIFETIME_MICROS: i64 = 3600 * 1_000_000;

/// The authentication service: it knows the members the [`Registry`] holds, and the challenges and tokens it handed out.
#[derive(Clone)]
pub struct Authentication {
    inner: Arc<Inner>,
    nonce_lifetime_micros: i64,
    token_lifetime_micros: i64,
}

struct Inner {
    physical_synchronizer_id: String,
    registry: Arc<Registry>,
    /// Member -> its pending nonce and when it expires (microseconds).
    challenges: Mutex<BTreeMap<String, (Vec<u8>, i64)>>,
    /// Token -> the member, the fingerprint of the key it authenticated with, and when the token expires (microseconds).
    tokens: Mutex<BTreeMap<Vec<u8>, (String, String, i64)>>,
}

impl Authentication {
    pub fn new(physical_synchronizer_id: String, registry: Arc<Registry>) -> Self {
        Self {
            inner: Arc::new(Inner {
                physical_synchronizer_id,
                registry,
                challenges: Default::default(),
                tokens: Default::default(),
            }),
            nonce_lifetime_micros: NONCE_LIFETIME_MICROS,
            token_lifetime_micros: TOKEN_LIFETIME_MICROS,
        }
    }

    /// The same service with other lifetimes for the nonces and tokens it hands out from now on (microseconds).
    pub fn with_lifetimes(self, nonce_micros: i64, token_micros: i64) -> Self {
        Self {
            nonce_lifetime_micros: nonce_micros,
            token_lifetime_micros: token_micros,
            ..self
        }
    }

    /// The member that an **authenticated call** is made as: the `memberid` header must be the member the `authtoken-bin` token was given
    /// to. Without either, or with a token that is not this member's (or has expired), the call is refused.
    pub fn authenticated_member<T>(&self, request: &Request<T>) -> Result<String, Status> {
        self.authenticated_member_until(request)
            .map(|(member, _)| member)
    }

    /// Like [`Self::authenticated_member`], with when the token expires (microseconds): a subscription ends then.
    pub fn authenticated_member_until<T>(
        &self,
        request: &Request<T>,
    ) -> Result<(String, i64), Status> {
        let metadata = request.metadata();
        let member = metadata
            .get("memberid")
            .and_then(|m| m.to_str().ok())
            .ok_or_else(|| {
                Status::unauthenticated("Unable to find participant id in gRPC context")
            })?;
        let token = metadata
            .get_bin("authtoken-bin")
            .and_then(|t| t.to_bytes().ok())
            .ok_or_else(|| {
                Status::unauthenticated("Unable to find an authentication token in gRPC context")
            })?;
        match self.member_until(&token) {
            Some((m, expires)) if m == member => Ok((m, expires)),
            _ => Err(Status::unauthenticated(
                "The authentication token is not valid for this member",
            )),
        }
    }

    /// The member a token belongs to, if it is a token this server gave, it has not expired, and the member still authenticates with the
    /// key the token was given for.
    pub fn member_of(&self, token: &[u8]) -> Option<String> {
        self.member_until(token).map(|(member, _)| member)
    }

    fn member_until(&self, token: &[u8]) -> Option<(String, i64)> {
        let now = now_micros();
        let (member, fingerprint, expires) = self
            .inner
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(token)
            .filter(|(_, _, expires)| *expires > now)
            .cloned()?;
        self.inner
            .registry
            .authenticates_with(&member, &fingerprint)
            .then_some((member, expires))
    }

    /// `MemberAccessDisabled`: the topology took the member away.
    fn refuse_disabled(&self, member: &str) -> Result<(), Status> {
        if self.inner.registry.is_disabled(member) {
            return Err(Status::permission_denied(format!(
                "Member {member} access is disabled"
            )));
        }
        Ok(())
    }
}

fn now_micros() -> i64 {
    crate::sequencing::wall_micros()
}

#[tonic::async_trait]
impl SequencerAuthenticationService for Authentication {
    async fn challenge(
        &self,
        request: Request<ChallengeRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
        let r = request.into_inner();
        crate::diag::diag_eprintln!("RPC Challenge member={}", r.member);
        self.refuse_disabled(&r.member)?;
        let Some(registered) = self.inner.registry.get(&r.member) else {
            return Err(Status::failed_precondition(format!(
                "Member {} is not registered",
                r.member
            )));
        };
        let now = now_micros();
        let nonce = {
            let mut challenges = self
                .inner
                .challenges
                .lock()
                .map_err(|_| Status::internal("challenge state lock poisoned"))?;
            match challenges.get(&r.member) {
                Some((pending, expires)) if *expires > now => pending.clone(),
                _ => {
                    let mut nonce = vec![0u8; 20];
                    rand::rngs::OsRng.fill_bytes(&mut nonce);
                    challenges.insert(r.member, (nonce.clone(), now + self.nonce_lifetime_micros));
                    nonce
                }
            }
        };
        Ok(Response::new(ChallengeResponse {
            nonce,
            fingerprints: registered
                .authentication_keys
                .iter()
                .map(|k| k.id.clone())
                .collect(),
        }))
    }

    async fn authenticate(
        &self,
        request: Request<AuthenticateRequest>,
    ) -> Result<Response<AuthenticateResponse>, Status> {
        let r = request.into_inner();
        crate::diag::diag_eprintln!("RPC Authenticate member={}", r.member);
        let denied = |why: &str| Status::unauthenticated(format!("Authentication failed: {why}"));
        self.refuse_disabled(&r.member)?;
        let Some(registered) = self.inner.registry.get(&r.member) else {
            return Err(denied("the member is not registered"));
        };
        let pending = self
            .inner
            .challenges
            .lock()
            .map_err(|_| Status::internal("challenge state lock poisoned"))?
            .get(&r.member)
            .cloned();
        let now = now_micros();
        match pending {
            Some((nonce, _)) if nonce != r.nonce => {
                return Err(denied("not the nonce this member was given"))
            }
            None => return Err(denied("not the nonce this member was given")),
            Some((_, expires)) if expires <= now => {
                return Err(denied("the nonce has expired"));
            }
            Some(_) => {}
        }
        let signature = r.signature.ok_or_else(|| denied("no signature"))?;
        let hash = AuthKey::challenge_hash(&r.nonce, &self.inner.physical_synchronizer_id)
            .map_err(|e| Status::internal(format!("the challenge hash: {e:?}")))?;
        // [CANTON-NOTE: SEMANTICS] `MemberAuthentication` verifies with `SequencerAuthenticationOnly`: the key the signature names among the
        // member's keys with that usage, then the check of its key spec and the signature's format.
        match verify_by_keys(
            &registered.authentication_keys,
            &hash,
            &signature,
            &sequencer_authentication_only(),
        ) {
            Ok(()) => {}
            Err(
                SignatureCheckError::SignerHasNoValidKeys
                | SignatureCheckError::SignatureWithWrongKey(_),
            ) => {
                return Err(denied(
                    "not signed by a key registered for sequencer authentication",
                ))
            }
            Err(_) => return Err(denied("the signature does not verify")),
        }
        // the nonce is consumed only by an answer that verifies: junk answers cannot knock it out
        let consumed = {
            let mut challenges = self
                .inner
                .challenges
                .lock()
                .map_err(|_| Status::internal("challenge state lock poisoned"))?;
            let matches = challenges
                .get(&r.member)
                .is_some_and(|(nonce, _)| *nonce == r.nonce);
            matches && challenges.remove(&r.member).is_some()
        };
        if !consumed {
            return Err(denied("not the nonce this member was given"));
        }
        let mut token = vec![0u8; 20];
        rand::rngs::OsRng.fill_bytes(&mut token);
        let expires = now + self.token_lifetime_micros;
        {
            let mut tokens = self
                .inner
                .tokens
                .lock()
                .map_err(|_| Status::internal("token state lock poisoned"))?;
            tokens.retain(|_, (_, _, until)| *until > now);
            tokens.insert(
                token.clone(),
                (r.member.clone(), signature.signed_by, expires),
            );
        }
        crate::diag::diag_eprintln!("RPC authenticated {}", r.member);
        Ok(Response::new(AuthenticateResponse {
            token,
            expires_at: Some(prost_types::Timestamp {
                seconds: expires.div_euclid(1_000_000),
                nanos: (expires.rem_euclid(1_000_000) * 1000) as i32,
            }),
        }))
    }

    async fn logout(
        &self,
        request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        crate::diag::diag_eprintln!("RPC Logout");
        self.inner
            .tokens
            .lock()
            .map_err(|_| Status::internal("token state lock poisoned"))?
            .remove(&request.into_inner().token);
        Ok(Response::new(LogoutResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onboarding::Registered;
    use canton_participant::topology_wire::Ed25519Key;

    const PSID: &str = "da::1220aa::37-0";

    fn service() -> (Authentication, String, Ed25519Key) {
        let key = Ed25519Key::from_seed([5; 32]);
        let member = format!("PAR::p::{}", key.fingerprint);
        let raw = canton_algo::member_signature::own_ed25519_key(&key.spki_der).unwrap();
        let registry = Arc::new(Registry::default());
        registry.insert(Registered {
            member: member.clone(),
            signing_keys: vec![raw.clone()],
            authentication_keys: vec![raw],
            encryption_keys: Vec::new(),
        });
        (Authentication::new(PSID.to_string(), registry), member, key)
    }

    async fn challenge(auth: &Authentication, member: &str) -> Vec<u8> {
        auth.challenge(Request::new(ChallengeRequest {
            member: member.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .nonce
    }

    async fn answer(
        auth: &Authentication,
        member: &str,
        nonce: &[u8],
        key: &Ed25519Key,
    ) -> Result<AuthenticateResponse, Status> {
        let signature = key.sign_bytes(&AuthKey::challenge_hash(nonce, PSID).unwrap());
        auth.authenticate(Request::new(AuthenticateRequest {
            member: member.to_string(),
            nonce: nonce.to_vec(),
            signature: Some(signature),
        }))
        .await
        .map(Response::into_inner)
    }

    #[tokio::test]
    async fn a_second_challenge_gets_the_pending_nonce_and_a_wrong_answer_does_not_consume_it() {
        let (auth, member, key) = service();
        let first = challenge(&auth, &member).await;
        assert_eq!(
            challenge(&auth, &member).await,
            first,
            "a challenge does not replace the pending nonce: anyone may ask for one"
        );
        let stranger = Ed25519Key::from_seed([6; 32]);
        assert!(answer(&auth, &member, &first, &stranger).await.is_err());
        // negative control: the member's own answer still gets a token, and consumes the nonce
        assert!(answer(&auth, &member, &first, &key).await.is_ok());
        assert!(answer(&auth, &member, &first, &key).await.is_err());
    }

    #[tokio::test]
    async fn an_expired_nonce_is_refused_and_a_token_says_when_it_expires() {
        let (auth, member, key) = service();
        let auth = auth.with_lifetimes(0, TOKEN_LIFETIME_MICROS);
        let nonce = challenge(&auth, &member).await;
        let why = answer(&auth, &member, &nonce, &key).await.unwrap_err();
        assert!(why.message().contains("expired"), "{}", why.message());
        // negative control: within its lifetime the nonce is answered, and the token expires an hour later
        let auth = auth.with_lifetimes(NONCE_LIFETIME_MICROS, TOKEN_LIFETIME_MICROS);
        let nonce = challenge(&auth, &member).await;
        let before = now_micros();
        let token = answer(&auth, &member, &nonce, &key).await.unwrap();
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("memberid", member.parse().unwrap());
        request.metadata_mut().insert_bin(
            "authtoken-bin",
            tonic::metadata::MetadataValue::from_bytes(&token.token),
        );
        let (who, expires) = auth.authenticated_member_until(&request).unwrap();
        assert_eq!(who, member);
        assert!(expires >= before + TOKEN_LIFETIME_MICROS);
    }
}
