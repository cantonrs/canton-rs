//! A real gRPC client of the official Canton 3.7.2 sequencer's `SequencerConnectService` (G5, S-NET-001).
//!
//! The messages and the client stub are the ones generated from the vendored official `.proto` files (`canton-proto`, feature
//! `grpc`); this module only connects, calls and decodes.
//!
//! [CANTON-NOTE: SEMANTICS] The sequencer's public API answers four calls without authentication: `Handshake` (protocol version
//! negotiation: the client lists the versions it speaks, the server answers the one it picked or refuses), `GetSynchronizerId`
//! (the physical synchronizer id and the sequencer's UID), `GetSynchronizerParameters` (the static synchronizer parameters of the
//! protocol version in force) and `VerifyActive` (whether the sequencer is active). Everything after it (authentication with a
//! participant's keys) needs the participant's identity: [`SequencerConnect::challenge`] and [`SequencerConnect::authenticate`] do it
//! with a key exported from the node; the topology onboarding and sending submission requests are not done here.
//!
//! [CANTON-NOTE: LIMITATION] No retry, a blocking wrapper over a private runtime. Plaintext HTTP/2 by [`SequencerConnect::connect`], TLS (rustls,
//! a given CA, server authentication only) by [`SequencerConnect::connect_tls`].
use std::time::Duration;

use canton_proto::com::digitalasset::canton::crypto::v30::{
    Signature, SignatureFormat, SigningAlgorithmSpec, SigningPrivateKey,
};
use canton_proto::com::digitalasset::canton::sequencer::api::v30::{
    sequencer_authentication::{AuthenticateRequest, ChallengeRequest},
    sequencer_authentication_service_client::SequencerAuthenticationServiceClient,
    sequencer_connect::{
        get_synchronizer_parameters_response::Parameters, GetSynchronizerIdRequest,
        GetSynchronizerParametersRequest, HandshakeRequest,
        RegisterOnboardingTopologyTransactionsRequest, VerifyActiveRequest,
    },
    sequencer_connect_service_client::SequencerConnectServiceClient,
    // (the API-info service of `connection::v30` is imported where it is used)
    sequencer_service_client::SequencerServiceClient,
    DownloadTopologyStateForInitRequest,
    GetTimeRequest,
    SendAsyncRequest,
    SubscriptionRequest,
};
use tonic::transport::Channel;

#[derive(Debug)]
pub enum ConnectError {
    Transport(String),
    Status(String),
    /// The answer has a shape this client does not understand.
    Unexpected(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Status(e) => write!(f, "the sequencer answered with an error: {e}"),
            Self::Unexpected(e) => write!(f, "unexpected answer: {e}"),
        }
    }
}

impl std::error::Error for ConnectError {}

impl ConnectError {
    /// Whether the sequencer answered that the caller is not authenticated (no token, or one it does not know).
    pub fn is_unauthenticated(&self) -> bool {
        match self {
            Self::Status(text) => {
                text.contains("valid authentication credentials")
                    || text.contains("Unauthenticated")
            }
            _ => false,
        }
    }
}

impl From<tonic::Status> for ConnectError {
    fn from(s: tonic::Status) -> Self {
        Self::Status(format!("{}: {}", s.code(), s.message()))
    }
}

/// What a handshake with the sequencer settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// The protocol version the server picked (a major version number, 34 for the 3.7 line's newest).
    pub server_protocol_version: i32,
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynchronizerId {
    pub physical_synchronizer_id: String,
    pub sequencer_uid: String,
}

/// The challenge the sequencer gives a member that wants to authenticate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: Vec<u8>,
    /// The fingerprints of the signing keys the sequencer will accept the answer from.
    pub fingerprints: Vec<String>,
}

/// The Ed25519 key a member authenticates with (its `sequencer-auth` key).
pub struct AuthKey {
    /// The fingerprint the key is registered under (`1220...`).
    pub fingerprint: String,
    key: ed25519_dalek::SigningKey,
}

impl AuthKey {
    /// From a serialized `SigningPrivateKey` (the message the node's key export holds): a DER PKCS#8 Ed25519 key.
    pub fn from_private_key_proto(bytes: &[u8]) -> Result<Self, ConnectError> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        use prost::Message;
        let pk = SigningPrivateKey::decode(bytes)
            .map_err(|e| ConnectError::Unexpected(format!("private key proto: {e}")))?;
        let key = ed25519_dalek::SigningKey::from_pkcs8_der(&pk.private_key)
            .map_err(|e| ConnectError::Unexpected(format!("PKCS#8 key: {e}")))?;
        Ok(Self {
            fingerprint: pk.id,
            key,
        })
    }

    /// What the member signs to answer a challenge: the multihash (`1220` + SHA-256) of the `AuthenticationToken` hash purpose,
    /// the nonce (without a length prefix) and the physical synchronizer id (a length-prefixed string).
    pub fn challenge_hash(
        nonce: &[u8],
        synchronizer_id: &str,
    ) -> Result<Vec<u8>, canton_algo::HashBuildError> {
        // HashPurpose 14 is `AuthenticationToken` (canton-algo's table)
        let mut h = canton_algo::hash::PurposeHash::new(14);
        h.add_without_length_prefix(nonce)?;
        h.add_string(synchronizer_id)?;
        let digest = h.finish()?;
        let mut out = vec![0x12, 0x20];
        out.extend_from_slice(&digest);
        Ok(out)
    }

    /// The signature message the sequencer checks: Ed25519 over the challenge hash, `r || s` (the format the node itself
    /// produced for this key, measured), signed by this key's fingerprint.
    pub fn sign_challenge(
        &self,
        nonce: &[u8],
        synchronizer_id: &str,
    ) -> Result<Signature, canton_algo::HashBuildError> {
        use ed25519_dalek::Signer;
        let signature = self
            .key
            .sign(&Self::challenge_hash(nonce, synchronizer_id)?);
        Ok(Signature {
            format: SignatureFormat::Concat as i32,
            signature: signature.to_bytes().to_vec(),
            signed_by: self.fingerprint.clone(),
            signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
            signature_delegation: None,
        })
    }
}

/// The token a sequencer gave a member that authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub token: Vec<u8>,
    /// Seconds since the epoch.
    pub expires_at_seconds: i64,
}

/// An error with every cause below it (`transport error: ...: invalid peer certificate: UnknownIssuer`): tonic's own text for a failed TLS
/// handshake is only "transport error", and the reason is in the sources.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// A member's traffic state: extra traffic purchased, extra traffic consumed, base traffic remainder, last consumed cost, the time, the serial.
pub type TrafficFigures = (i64, i64, i64, u64, i64, Option<u32>);

/// A client of one sequencer's public API.
pub struct SequencerConnect {
    runtime: tokio::runtime::Runtime,
    client: SequencerConnectServiceClient<Channel>,
    authentication: SequencerAuthenticationServiceClient<Channel>,
    service: SequencerServiceClient<Channel>,
    api_info: canton_proto::com::digitalasset::canton::connection::v30::api_info_service_client::ApiInfoServiceClient<Channel>,
    /// How to authenticate again when the sequencer stops accepting the token (see [`SequencerConnect::set_reauth`]).
    reauth: Option<Reauth>,
    /// The token this client got for itself after the sequencer refused the one it was given; it takes the given one's place.
    refreshed: Option<Token>,
}

/// What a client needs to authenticate again by itself: who it is and how it signs the sequencer's challenge.
struct Reauth {
    member: String,
    synchronizer: String,
    sign: Box<dyn Fn(&[u8]) -> Signature + Send + Sync>,
}

impl SequencerConnect {
    /// Connects to `http://host:port` (the sequencer's public API, plaintext).
    pub fn connect(endpoint: &str) -> Result<Self, ConnectError> {
        Self::open(endpoint, None)
    }

    /// Connects to `https://host:port` over TLS (rustls). `ca_pem` is the PEM of the certificate (chain) the server's certificate
    /// has to chain to, and `domain` the name the certificate has to be valid for (the server name of the handshake).
    ///
    /// [CANTON-NOTE: SEMANTICS] The sequencer's public API uses TLS when its config gives `public-api.tls` (a certificate chain and
    /// a private key); the client then has to trust that certificate (a custom CA, or none for a public CA). Only the **server** is
    /// authenticated this way: members still authenticate with the challenge-and-signature of [`SequencerConnect::authenticate`].
    pub fn connect_tls(endpoint: &str, ca_pem: &str, domain: &str) -> Result<Self, ConnectError> {
        Self::open(endpoint, Some((ca_pem, domain, None)))
    }

    /// Connects to `https://host:port` over mutual TLS (rustls), presenting a client certificate and PKCS#8 private key.
    pub fn connect_mtls(
        endpoint: &str,
        ca_pem: &str,
        domain: &str,
        client_cert_pem: &str,
        client_key_pem: &str,
    ) -> Result<Self, ConnectError> {
        Self::open(
            endpoint,
            Some((ca_pem, domain, Some((client_cert_pem, client_key_pem)))),
        )
    }

    fn open(
        endpoint: &str,
        tls: Option<(&str, &str, Option<(&str, &str)>)>,
    ) -> Result<Self, ConnectError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| ConnectError::Transport(e.to_string()))?;
        let channel = runtime
            .block_on(async {
                let mut builder = Channel::from_shared(endpoint.to_string())
                    .map_err(|e| e.to_string())?
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(Duration::from_secs(30));
                if let Some((ca_pem, domain, client_identity)) = tls {
                    let mut cfg = tonic::transport::ClientTlsConfig::new()
                        .ca_certificate(tonic::transport::Certificate::from_pem(ca_pem))
                        .domain_name(domain);
                    if let Some((client_cert, client_key)) = client_identity {
                        cfg = cfg.identity(tonic::transport::Identity::from_pem(
                            client_cert,
                            client_key,
                        ));
                    }
                    builder = builder.tls_config(cfg).map_err(|e| e.to_string())?;
                }
                builder.connect().await.map_err(|e| error_chain(&e))
            })
            .map_err(ConnectError::Transport)?;
        Ok(Self {
            runtime,
            client: SequencerConnectServiceClient::new(channel.clone()),
            authentication: SequencerAuthenticationServiceClient::new(channel.clone()),
            service: SequencerServiceClient::new(channel.clone()),
            api_info: canton_proto::com::digitalasset::canton::connection::v30::api_info_service_client::ApiInfoServiceClient::new(channel),
            reauth: None,
            refreshed: None,
        })
    }

    /// Second step: answers the challenge with a signature (see [`AuthKey::sign_challenge`]) and gets the member's token.
    pub fn authenticate(
        &mut self,
        member: &str,
        nonce: &[u8],
        signature: Signature,
    ) -> Result<Token, ConnectError> {
        // a token the caller asks for is the one it will use: the one this client got for itself is no longer wanted
        self.refreshed = None;
        self.authenticate_for_reuse(member, nonce, signature)
    }

    fn authenticate_for_reuse(
        &mut self,
        member: &str,
        nonce: &[u8],
        signature: Signature,
    ) -> Result<Token, ConnectError> {
        let r = self
            .runtime
            .block_on(self.authentication.authenticate(AuthenticateRequest {
                member: member.to_string(),
                signature: Some(signature),
                nonce: nonce.to_vec(),
            }))?
            .into_inner();
        Ok(Token {
            token: r.token,
            expires_at_seconds: r.expires_at.map_or(0, |t| t.seconds),
        })
    }

    /// First step of authenticating as `member` (`PAR::name::fingerprint`, ...): the sequencer's nonce and the fingerprints of the
    /// keys it will accept a signature from. The second step (`Authenticate`, signing the nonce) is not done here.
    pub fn challenge(&mut self, member: &str, versions: &[i32]) -> Result<Challenge, ConnectError> {
        let r = self
            .runtime
            .block_on(self.authentication.challenge(ChallengeRequest {
                member: member.to_string(),
                member_protocol_versions: versions.to_vec(),
                client_version: concat!("canton-rs-", env!("CARGO_PKG_VERSION")).into(),
            }))?
            .into_inner();
        Ok(Challenge {
            nonce: r.nonce,
            fingerprints: r.fingerprints,
        })
    }

    /// Offers `versions` (protocol major versions) and the minimum acceptable one.
    pub fn handshake(
        &mut self,
        versions: &[i32],
        minimum: Option<i32>,
    ) -> Result<Handshake, ConnectError> {
        let request = HandshakeRequest {
            client_protocol_versions: versions.to_vec(),
            minimum_protocol_version: minimum,
            client_version: concat!("canton-rs-", env!("CARGO_PKG_VERSION")).into(),
        };
        let response = self
            .runtime
            .block_on(self.client.handshake(request))?
            .into_inner();
        Ok(Handshake {
            server_protocol_version: response.server_protocol_version,
            success: response.value.is_some(),
        })
    }

    /// The name the endpoint gives itself (`ApiInfoService.GetApiInfo`): a participant calls it first, to learn which API it reached.
    pub fn api_name(&mut self) -> Result<String, ConnectError> {
        use canton_proto::com::digitalasset::canton::connection::v30::GetApiInfoRequest;
        Ok(self
            .runtime
            .block_on(self.api_info.get_api_info(GetApiInfoRequest {}))?
            .into_inner()
            .name)
    }

    pub fn synchronizer_id(&mut self) -> Result<SynchronizerId, ConnectError> {
        let r = self
            .runtime
            .block_on(self.client.get_synchronizer_id(GetSynchronizerIdRequest {}))?
            .into_inner();
        Ok(SynchronizerId {
            physical_synchronizer_id: r.physical_synchronizer_id,
            sequencer_uid: r.sequencer_uid,
        })
    }

    /// The static synchronizer parameters, as the `Debug` text of the version the server chose (`v31` or `v32` of the
    /// message) together with which one it is.
    pub fn synchronizer_parameters(&mut self) -> Result<(String, String), ConnectError> {
        let r = self
            .runtime
            .block_on(
                self.client
                    .get_synchronizer_parameters(GetSynchronizerParametersRequest {}),
            )?
            .into_inner();
        match r.parameters {
            Some(Parameters::V31(p)) => Ok(("v31".into(), format!("{p:?}"))),
            Some(Parameters::V32(p)) => Ok(("v32".into(), format!("{p:?}"))),
            None => Err(ConnectError::Unexpected(
                "no parameters in the answer".into(),
            )),
        }
    }

    /// The schemes the synchronizer's static parameters require of a member (see [`crate::crypto_handshake`]).
    pub fn required_schemes(&mut self) -> Result<crate::crypto_handshake::Required, ConnectError> {
        use crate::crypto_handshake::required_schemes_of;
        let r = self
            .runtime
            .block_on(
                self.client
                    .get_synchronizer_parameters(GetSynchronizerParametersRequest {}),
            )?
            .into_inner();
        match r.parameters {
            Some(Parameters::V31(p)) => Ok(required_schemes_of!(&p)),
            Some(Parameters::V32(p)) => {
                let max_keys = p
                    .synchronizer_limits
                    .as_ref()
                    .and_then(|l| l.topology_limits.as_ref())
                    .map(|t| t.max_signing_keys_per_entity)
                    .filter(|&n| n > 0);
                Ok(required_schemes_of!(&p, max_keys))
            }
            None => Err(ConnectError::Unexpected(
                "no parameters in the answer".into(),
            )),
        }
    }

    fn with_auth<T>(
        message: T,
        member: &str,
        synchronizer_id: &str,
        token: Option<&Token>,
    ) -> Result<tonic::Request<T>, ConnectError> {
        use tonic::metadata::{AsciiMetadataValue, BinaryMetadataKey, BinaryMetadataValue};
        let mut request = tonic::Request::new(message);
        let ascii = |v: &str| {
            AsciiMetadataValue::try_from(v)
                .map_err(|e| ConnectError::Unexpected(format!("header value: {e}")))
        };
        request
            .metadata_mut()
            .insert("synchronizerid", ascii(synchronizer_id)?);
        request.metadata_mut().insert("memberid", ascii(member)?);
        if let Some(token) = token {
            request.metadata_mut().insert_bin(
                BinaryMetadataKey::from_bytes(b"authtoken-bin")
                    .map_err(|e| ConnectError::Unexpected(format!("header key: {e}")))?,
                BinaryMetadataValue::from_bytes(&token.token),
            );
        }
        Ok(request)
    }

    /// `SequencerConnectService.RegisterOnboardingTopologyTransactions`: tells the synchronizer who a new member is (its signed
    /// identity transactions), before the member authenticates.
    pub fn register_onboarding(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        transactions: Vec<
            canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction,
        >,
    ) -> Result<(), ConnectError> {
        // like `VerifyActive`, the call reads the member from the headers (no token: the member is not known yet)
        let request = Self::with_auth(
            RegisterOnboardingTopologyTransactionsRequest {
                topology_transactions: transactions,
            },
            member,
            synchronizer_id,
            None,
        )?;
        self.runtime.block_on(
            self.client
                .register_onboarding_topology_transactions(request),
        )?;
        Ok(())
    }

    /// `SequencerService.DownloadTopologyStateForInit` (authenticated): the synchronizer's topology state as the stored form of
    /// each signed transaction with the time it became valid (microseconds since the epoch), in the order the sequencer sends.
    /// The hash of the topology state the sequencer would give `member` (`DownloadTopologyStateForInitHash`): what a participant compares
    /// the state it downloaded with.
    fn download_topology_state_hash_once(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
    ) -> Result<Vec<u8>, ConnectError> {
        use canton_proto::com::digitalasset::canton::sequencer::api::v30::DownloadTopologyStateForInitHashRequest;
        let request = Self::with_auth(
            DownloadTopologyStateForInitHashRequest {
                member: member.to_string(),
            },
            member,
            synchronizer_id,
            Some(token),
        )?;
        Ok(self
            .runtime
            .block_on(self.service.download_topology_state_for_init_hash(request))?
            .into_inner()
            .topology_state_hash)
    }

    fn download_topology_state_once(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
        rejected: Rejected,
    ) -> Result<Vec<(i64, Vec<u8>)>, ConnectError> {
        let request = Self::with_auth(
            DownloadTopologyStateForInitRequest {
                member: member.to_string(),
            },
            member,
            synchronizer_id,
            Some(token),
        )?;
        self.runtime
            .block_on(async {
                let mut stream = self
                    .service
                    .download_topology_state_for_init(request)
                    .await?
                    .into_inner();
                let mut out = Vec::new();
                while let Some(message) = stream.message().await? {
                    out.extend(served(
                        message
                            .topology_transactions
                            .map(|t| t.items)
                            .unwrap_or_default(),
                        rejected,
                    ));
                }
                Ok::<_, tonic::Status>(out)
            })
            .map_err(ConnectError::from)
    }

    /// `SequencerService.SendAsync` (authenticated): hands a signed submission request (see `sequencing_wire`) to the sequencer.
    /// An `Ok` only says the sequencer accepted the request for sequencing; the delivery arrives on a subscription.
    fn send_async_once(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
        signed_submission_request: Vec<u8>,
    ) -> Result<(), ConnectError> {
        let request = Self::with_auth(
            SendAsyncRequest {
                signed_submission_request,
            },
            member,
            synchronizer_id,
            Some(token),
        )?;
        self.runtime.block_on(self.service.send_async(request))?;
        Ok(())
    }

    /// `SequencerService.AcknowledgeSigned` (authenticated): the member has read every event up to `signed_acknowledge_request`'s
    /// timestamp (see `sequencing_wire::signed_acknowledge_request`) and will not read them again, so the sequencer may forget them.
    fn acknowledge_signed_once(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
        signed_acknowledge_request: Vec<u8>,
    ) -> Result<(), ConnectError> {
        use canton_proto::com::digitalasset::canton::sequencer::api::v30::AcknowledgeSignedRequest;
        let request = Self::with_auth(
            AcknowledgeSignedRequest {
                signed_acknowledge_request,
            },
            member,
            synchronizer_id,
            Some(token),
        )?;
        self.runtime
            .block_on(self.service.acknowledge_signed(request))?;
        Ok(())
    }

    /// `SequencerService.Subscribe` (authenticated): the events for `member` after `after_micros` (`None`: from the beginning),
    /// collected until `count` arrived or `wait` passed without reaching it. Each is the `signed_sequenced_event` bytes.
    fn subscribe_once(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
        after_micros: Option<i64>,
        count: usize,
        wait: Duration,
    ) -> Result<Vec<Vec<u8>>, ConnectError> {
        let request = Self::with_auth(
            SubscriptionRequest {
                member: member.to_string(),
                timestamp: after_micros,
            },
            member,
            synchronizer_id,
            Some(token),
        )?;
        self.runtime
            .block_on(async {
                let deadline = tokio::time::Instant::now() + wait;
                // [CANTON-NOTE: WHY] The wait bounds the opening of the stream too, not only the reading of it. The official sequencer sends
                // the response headers with its first event, so while it has none the call does not return until the channel's own deadline
                // (30 s); a node that read in 2 ms slices held its lock that long, and the first submission after an idle time waited for it
                // (measured on a Rust participant on the official 3.7.2 synchronizer: a create took 40 s, EQUAL-CONDITIONS step C3).
                let mut stream = match tokio::time::timeout_at(
                    deadline,
                    self.service.subscribe(request),
                )
                .await
                {
                    Ok(opened) => opened?.into_inner(),
                    Err(_) => return Ok(Vec::new()), // no event within the wait: the call is dropped, which cancels it
                };
                let mut out = Vec::new();
                while out.len() < count {
                    match tokio::time::timeout_at(deadline, stream.message()).await {
                        Ok(Ok(Some(m))) => out.push(m.signed_sequenced_event),
                        Ok(Ok(None)) => break,
                        Ok(Err(status)) => return Err(status),
                        Err(_) => break, // nothing more within the wait
                    }
                }
                Ok::<_, tonic::Status>(out)
            })
            .map_err(ConnectError::from)
    }

    /// `SequencerService.GetTime` (an authenticated service): the sequencer's own clock, as microseconds since the epoch
    /// (`None` while it is still initializing).
    /// The traffic state the sequencer keeps for `of` at `timestamp` (`GetTrafficStateForMember`), as the `Debug` text of the message.
    pub fn traffic_state(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
        of: &str,
        timestamp: i64,
    ) -> Result<TrafficFigures, ConnectError> {
        use canton_proto::com::digitalasset::canton::sequencer::api::v30::GetTrafficStateForMemberRequest;
        let request = Self::with_auth(
            GetTrafficStateForMemberRequest {
                member: of.to_string(),
                timestamp,
            },
            member,
            synchronizer_id,
            Some(token),
        )?;
        let r = self
            .runtime
            .block_on(self.service.get_traffic_state_for_member(request))?
            .into_inner();
        let t = r
            .traffic_state
            .ok_or_else(|| ConnectError::Unexpected("no traffic state".into()))?;
        Ok((
            t.extra_traffic_purchased,
            t.extra_traffic_consumed,
            t.base_traffic_remainder,
            t.last_consumed_cost,
            t.timestamp,
            t.serial,
        ))
    }

    fn sequencer_time_once(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: Option<&Token>,
    ) -> Result<Option<i64>, ConnectError> {
        let request = Self::with_auth(GetTimeRequest {}, member, synchronizer_id, token)?;
        let r = self
            .runtime
            .block_on(self.service.get_time(request))?
            .into_inner();
        Ok(r.sequencing_timestamp)
    }

    /// `VerifyActive` as an authenticated member: the three headers the node's own clients send (`synchronizerId`, `memberId` and
    /// the binary `authToken-bin`).
    pub fn is_active_as(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: Option<&Token>,
    ) -> Result<bool, ConnectError> {
        use tonic::metadata::{AsciiMetadataValue, BinaryMetadataKey, BinaryMetadataValue};
        let mut request = tonic::Request::new(VerifyActiveRequest {});
        let ascii = |v: &str| {
            AsciiMetadataValue::try_from(v)
                .map_err(|e| ConnectError::Unexpected(format!("header value: {e}")))
        };
        request
            .metadata_mut()
            .insert("synchronizerid", ascii(synchronizer_id)?);
        request.metadata_mut().insert("memberid", ascii(member)?);
        if let Some(token) = token {
            request.metadata_mut().insert_bin(
                BinaryMetadataKey::from_bytes(b"authtoken-bin")
                    .map_err(|e| ConnectError::Unexpected(format!("header key: {e}")))?,
                BinaryMetadataValue::from_bytes(&token.token),
            );
        }
        let r = self
            .runtime
            .block_on(self.client.verify_active(request))?
            .into_inner();
        Self::active_of(r)
    }

    pub fn is_active(&mut self) -> Result<bool, ConnectError> {
        let r = self
            .runtime
            .block_on(self.client.verify_active(VerifyActiveRequest {}))?
            .into_inner();
        Self::active_of(r)
    }

    fn active_of(
        r: canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_connect::VerifyActiveResponse,
    ) -> Result<bool, ConnectError> {
        r.value
            .map(|v| {
                use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_connect::verify_active_response::Value;
                let Value::Success(s) = v;
                s.is_active
            })
            .ok_or_else(|| ConnectError::Unexpected("VerifyActive without a value".into()))
    }
}

impl SequencerConnect {
    /// Lets this client authenticate again **by itself** when the sequencer stops accepting its token (a sequencer that restarted keeps no
    /// tokens): `sign` signs the sequencer's challenge hash with the member's authentication key. A call the sequencer answers as
    /// unauthenticated then gets a new challenge, a new token and one more try; the new token replaces the one the caller holds.
    ///
    /// [CANTON-NOTE: SEMANTICS] Only an **unauthenticated** answer is retried: a transport error (the sequencer is down) is the caller's to
    /// retry, as before, and the next call after it comes back finds the old token refused and authenticates again.
    pub fn set_reauth(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        sign: Box<dyn Fn(&[u8]) -> Signature + Send + Sync>,
    ) {
        self.reauth = Some(Reauth {
            member: member.to_string(),
            synchronizer: synchronizer_id.to_string(),
            sign,
        });
    }

    /// Authenticates again as the member `set_reauth` was told about, and keeps the token as the one to use.
    fn refresh(&mut self) -> Result<Token, ConnectError> {
        let (member, synchronizer) = match &self.reauth {
            Some(r) => (r.member.clone(), r.synchronizer.clone()),
            None => {
                return Err(ConnectError::Unexpected(
                    "no way to authenticate again".into(),
                ))
            }
        };
        let challenge = self.challenge(&member, &[37])?;
        let hash = AuthKey::challenge_hash(&challenge.nonce, &synchronizer)
            .map_err(|e| ConnectError::Unexpected(format!("the challenge hash: {e:?}")))?;
        let signature = (self.reauth.as_ref().expect("checked above").sign)(&hash);
        let token = self.authenticate_for_reuse(&member, &challenge.nonce, signature)?;
        self.refreshed = Some(token.clone());
        Ok(token)
    }

    /// Runs `call` with the token that is good now (the one this client got for itself, else the caller's), and once more with a new one when the
    /// sequencer answers as unauthenticated.
    fn authed<T>(
        &mut self,
        token: &Token,
        mut call: impl FnMut(&mut Self, &Token) -> Result<T, ConnectError>,
    ) -> Result<T, ConnectError> {
        let current = self.refreshed.clone().unwrap_or_else(|| token.clone());
        match call(self, &current) {
            Err(e) if self.reauth.is_some() && e.is_unauthenticated() => {
                let fresh = self.refresh()?;
                call(self, &fresh)
            }
            other => other,
        }
    }

    pub fn download_topology_state_hash(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
    ) -> Result<Vec<u8>, ConnectError> {
        self.authed(token, |c, t| {
            c.download_topology_state_hash_once(member, synchronizer_id, t)
        })
    }

    pub fn download_topology_state(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
    ) -> Result<Vec<(i64, Vec<u8>)>, ConnectError> {
        self.authed(token, |c, t| {
            c.download_topology_state_once(member, synchronizer_id, t, Rejected::Kept)
        })
    }

    /// The state a node starts to follow: [`SequencerConnect::download_topology_state`] without the transactions the synchronizer rejected
    /// (they carry a rejection reason and never took effect).
    pub fn download_topology_state_in_force(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
    ) -> Result<Vec<(i64, Vec<u8>)>, ConnectError> {
        self.authed(token, |c, t| {
            c.download_topology_state_once(member, synchronizer_id, t, Rejected::Left)
        })
    }

    pub fn send_async(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
        signed_submission_request: Vec<u8>,
    ) -> Result<(), ConnectError> {
        self.authed(token, |c, t| {
            c.send_async_once(
                member,
                synchronizer_id,
                t,
                signed_submission_request.clone(),
            )
        })
    }

    pub fn acknowledge_signed(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
        signed_acknowledge_request: Vec<u8>,
    ) -> Result<(), ConnectError> {
        self.authed(token, |c, t| {
            c.acknowledge_signed_once(
                member,
                synchronizer_id,
                t,
                signed_acknowledge_request.clone(),
            )
        })
    }

    pub fn subscribe(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: &Token,
        after_micros: Option<i64>,
        count: usize,
        wait: Duration,
    ) -> Result<Vec<Vec<u8>>, ConnectError> {
        self.authed(token, |c, t| {
            c.subscribe_once(member, synchronizer_id, t, after_micros, count, wait)
        })
    }

    pub fn sequencer_time(
        &mut self,
        member: &str,
        synchronizer_id: &str,
        token: Option<&Token>,
    ) -> Result<Option<i64>, ConnectError> {
        match token {
            Some(token) => self.authed(token, |c, t| {
                c.sequencer_time_once(member, synchronizer_id, Some(t))
            }),
            None => self.sequencer_time_once(member, synchronizer_id, None),
        }
    }
}

/// What a download does with the transactions the synchronizer rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejected {
    /// Kept: the download is what the sequencer serves, the transactions `DownloadTopologyStateForInitHash` hashes.
    Kept,
    /// Left out: a rejected transaction never took effect, so the state a node follows does not have it.
    Left,
}

/// The downloaded transactions `(valid from, stored bytes)`, with or without the rejected ones (see [`Rejected`]).
fn served(
    items: Vec<
        canton_proto::com::digitalasset::canton::topology::admin::v30::topology_transactions::Item,
    >,
    rejected: Rejected,
) -> impl Iterator<Item = (i64, Vec<u8>)> {
    items
        .into_iter()
        .filter(move |item| rejected == Rejected::Kept || item.rejection_reason.is_none())
        .map(|item| {
            let valid_from = item
                .valid_from
                .map_or(0, |t| t.seconds * 1_000_000 + i64::from(t.nanos) / 1_000);
            (valid_from, item.transaction)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// T-6: a rejected transaction of a downloaded state is not part of it.
    #[test]
    fn a_rejected_transaction_is_left_out_of_the_downloaded_state() {
        use canton_proto::com::digitalasset::canton::topology::admin::v30::topology_transactions::Item;
        let item = |bytes: u8, rejection_reason: Option<&str>| Item {
            transaction: vec![bytes],
            rejection_reason: rejection_reason.map(str::to_string),
            ..Default::default()
        };
        let items = || vec![item(1, None), item(2, Some("NotAuthorized")), item(3, None)];
        let in_force: Vec<(i64, Vec<u8>)> = served(items(), Rejected::Left).collect();
        assert_eq!(in_force, vec![(0, vec![1]), (0, vec![3])]);
        // what the sequencer serves and hashes keeps it
        assert_eq!(served(items(), Rejected::Kept).count(), 3);
    }

    /// [CANTON-NOTE: WHY] The official sequencer answers a subscription with no event to deliver only when its channel deadline ends (it sends
    /// the response headers with the first event), so the wait of `subscribe_once` has to cover the opening of the stream as well. A server that
    /// accepts the connection and never answers stands in for it: the call must give the stream back on time with nothing, not hold the node
    /// for the channel's 30 s (U-43: a create on a Rust participant took 40 s on the official 3.7.2 synchronizer).
    #[test]
    fn a_subscription_that_is_never_answered_ends_with_the_wait() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            // accept and keep every connection open without a byte of answer
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        let mut client = SequencerConnect::connect(&format!("http://127.0.0.1:{port}"))
            .expect("the connection is made lazily");
        let token = Token {
            token: vec![1],
            expires_at_seconds: i64::MAX,
        };
        let started = Instant::now();
        let events = client
            .subscribe_once(
                "PAR::p::1220",
                "sync::1220",
                &token,
                Some(1),
                1,
                Duration::from_millis(300),
            )
            .expect("an empty wait is not an error");
        assert!(events.is_empty());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait of 300 ms took {:?}",
            started.elapsed()
        );
    }
}
