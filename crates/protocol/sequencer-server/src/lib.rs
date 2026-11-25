//! A Rust sequencer server (G6, S-NET-037): the public API a participant connects to.
//!
//! This module serves the **unauthenticated** `SequencerConnectService` calls a participant makes when it connects to a synchronizer:
//! `Handshake`, `GetSynchronizerId`, `GetSynchronizerParameters` and `VerifyActive`. The synchronizer's identity and parameters come from
//! a [`SynchronizerConfig`] (its own namespace key, the protocol version, the crypto it requires), not from a recording of another node.
//! Authentication is `auth`, topology onboarding `onboarding`, and `SendAsync`/`Subscribe` are `sequencer_service` over `sequencing`.
//!
//! [CANTON-NOTE: LIMITATION] The administration services (`SequencerAdministrationService`, the BFT administration and the topology
//! manager) are registered on the same listener as the public API and take no token: whoever reaches the port can call them.
// [CANTON-NOTE: STYLE] Wire builders take the parts of one Canton message as separate arguments and a few long tuple types are named once; neither is
// clearer behind a parameter struct or an alias, so these two lints are allowed in this crate.
#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    reason = "wire builders take individual message components and protocol tuple types"
)]

use canton_proto::com::digitalasset::canton::crypto::v30::{
    CryptoKeyFormat, EncryptionAlgorithmSpec, EncryptionKeySpec, HashAlgorithm,
    RequiredEncryptionSpecs, RequiredSigningSpecs, SignatureFormat, SigningAlgorithmSpec,
    SigningKeySpec, SymmetricKeyScheme,
};
use canton_proto::com::digitalasset::canton::protocol::v32::{
    AcsCommitmentLimits, StaticSynchronizerParameters, SynchronizerLimits, TopologyLimits,
    TransactionProtocolLimits,
};
use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_connect::{
    get_synchronizer_parameters_response::Parameters, handshake_response::Success,
    GetSynchronizerIdRequest, GetSynchronizerIdResponse, GetSynchronizerParametersRequest,
    GetSynchronizerParametersResponse, HandshakeRequest, HandshakeResponse,
    RegisterOnboardingTopologyTransactionsRequest, RegisterOnboardingTopologyTransactionsResponse,
    VerifyActiveRequest, VerifyActiveResponse,
};
use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_connect_service_server::{
    SequencerConnectService, SequencerConnectServiceServer,
};
pub mod admin;
pub(crate) mod aggregation;
pub mod auth;
pub mod bft_admin;
pub mod bft_p2p;
pub mod cli;
pub(crate) mod diag;
pub mod mediator;
pub(crate) mod mediator_clock;
pub(crate) mod mediator_events;
pub mod mediator_identity;
pub mod mediator_node;
pub mod membership;
pub mod onboarding;
pub mod ord_store;
pub mod ordering;
pub mod persistence;
pub mod probe;
pub mod pruning_admin;
pub mod rate_limit;
pub mod sequencer_identity;
pub mod sequencer_service;
pub mod sequencing;
pub(crate) mod submission;
pub(crate) mod submission_validator;
pub mod synchronizer_state;
pub mod topology_admin;
pub mod traffic;
pub mod transport;

use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

/// The generated gRPC health service (`grpc.health.v1`).
#[allow(
    clippy::allow_attributes_without_reason,
    clippy::clone_on_ref_ptr,
    reason = "tonic generated grpc.health.v1 proto"
)]
pub mod health {
    tonic::include_proto!("grpc.health.v1");
}

use canton_proto::com::digitalasset::canton::connection::v30::{
    api_info_service_server::{ApiInfoService, ApiInfoServiceServer},
    GetApiInfoRequest, GetApiInfoResponse,
};

/// The name the sequencer's public API gives itself (`ApiInfoService.GetApiInfo`), as the official sequencer does (measured,
/// S-NET-037): a participant checks it before it uses the endpoint as a sequencer.
pub const SEQUENCER_API_NAME: &str = "sequencer-public-api";

/// The protocol version this synchronizer runs (Canton 3.7: 37).
pub const PROTOCOL_VERSION: i32 = 37;

/// Who the synchronizer is and what it requires of its members.
#[derive(Debug, Clone)]
pub struct SynchronizerConfig {
    /// The synchronizer's name (`mysync`).
    pub name: String,
    /// The fingerprint of the synchronizer's namespace key (`1220...`).
    pub namespace_fingerprint: String,
    /// The sequencer's name; its uid is `name::fingerprint` in the namespace of its own key.
    pub sequencer_name: String,
    pub sequencer_fingerprint: String,
    /// The keys the synchronizer's own topology transactions are signed with (the sequencer's and the mediator's namespace keys own the
    /// synchronizer's decentralized namespace, `namespace_fingerprint`).
    pub keys: std::sync::Arc<synchronizer_state::SynchronizerKeys>,
    /// The physical synchronizer's serial: 0 for a new synchronizer, one more for each logical upgrade (the successor of serial `n` is
    /// `n + 1`).
    pub serial: u32,
}

impl SynchronizerConfig {
    /// `name::fingerprint::37-<serial>`: the physical synchronizer id (protocol version 37).
    pub fn physical_synchronizer_id(&self) -> String {
        format!(
            "{}::{}::{PROTOCOL_VERSION}-{}",
            self.name, self.namespace_fingerprint, self.serial
        )
    }

    /// The logical synchronizer id this physical synchronizer belongs to (`name::fingerprint`).
    pub fn synchronizer_uid(&self) -> String {
        format!("{}::{}", self.name, self.namespace_fingerprint)
    }

    pub fn sequencer_uid(&self) -> String {
        format!("{}::{}", self.sequencer_name, self.sequencer_fingerprint)
    }
}

/// The static parameters of a synchronizer that requires what Canton 3.7 requires of every member (the signing, encryption, hash and
/// symmetric schemes and the formats a participant has to support), less what the Rust nodes cannot produce, and the default limits.
pub fn static_parameters(serial: u32) -> StaticSynchronizerParameters {
    StaticSynchronizerParameters {
        required_signing_specs: Some(RequiredSigningSpecs {
            algorithms: vec![
                SigningAlgorithmSpec::Ed25519 as i32,
                SigningAlgorithmSpec::EcDsaSha256 as i32,
                SigningAlgorithmSpec::EcDsaSha384 as i32,
            ],
            keys: vec![
                SigningKeySpec::EcSecp256k1 as i32,
                SigningKeySpec::EcP384 as i32,
                SigningKeySpec::EcCurve25519 as i32,
                SigningKeySpec::EcP256 as i32,
            ],
        }),
        // [CANTON-NOTE: LIMITATION] The official default also requires RSA-OAEP-SHA256 and RSA-2048 keys; the Rust nodes cannot encrypt
        // with them (no RSA implementation), and "required" means every member has to support it, so they are not required here (C-2).
        // A JVM participant still passes its handshake: its default (ECIES on P-256) is required.
        required_encryption_specs: Some(RequiredEncryptionSpecs {
            algorithms: vec![EncryptionAlgorithmSpec::EciesHkdfHmacSha256Aes128cbc as i32],
            keys: vec![EncryptionKeySpec::EcP256 as i32],
        }),
        required_symmetric_key_schemes: vec![SymmetricKeyScheme::Aes128gcm as i32],
        required_hash_algorithms: vec![HashAlgorithm::Sha256 as i32],
        required_crypto_key_formats: vec![
            CryptoKeyFormat::Raw as i32,
            CryptoKeyFormat::DerX509SubjectPublicKeyInfo as i32,
            CryptoKeyFormat::DerPkcs8PrivateKeyInfo as i32,
        ],
        required_signature_formats: vec![
            SignatureFormat::Der as i32,
            SignatureFormat::Concat as i32,
        ],
        protocol_version: PROTOCOL_VERSION,
        serial: serial as i32,
        enable_transparency_checks: false,
        topology_change_delay: Some(prost_types_duration(0, 250_000_000)),
        synchronizer_limits: Some(SynchronizerLimits {
            transaction_protocol_limits: Some(TransactionProtocolLimits {
                max_act_as: 1000,
                max_envelopes: 10000,
                max_recipients_per_batch: 10000,
                max_recipients_trees: 10000,
                max_recipients_per_recipients_tree_level: 10000,
                max_children_per_recipients_tree_level: 10000,
                max_recipients_per_envelope: 10000,
                max_recipients_tree_depth: 100,
                max_transaction_root_views: 1_000_000,
                max_transaction_sub_views: 10_000_000,
                max_transaction_tree_depth: i32::MAX as u32,
                max_signatures_per_envelope: 1000,
                max_quorum_size: 100_000_000,
            }),
            topology_limits: Some(TopologyLimits {
                max_signing_keys_per_entity: 20,
                max_owners_per_decentralized_namespace: 100,
                max_hosting_participants_per_party: 100,
            }),
            acs_commitment_limits: Some(AcsCommitmentLimits {
                max_acs_commitment_size_bytes: 10240,
                max_acs_commitment_summary_size_bytes: 1_048_576,
                max_addressed_counterparticipants: 10000,
                max_unsent_digests: 10000,
            }),
        }),
    }
}

fn prost_types_duration(seconds: i64, nanos: i32) -> prost_types::Duration {
    prost_types::Duration { seconds, nanos }
}

/// The unauthenticated part of the sequencer's public API.
#[derive(Clone)]
pub struct ConnectService {
    journal: Option<std::sync::Arc<persistence::Journal>>,
    config: SynchronizerConfig,
    registry: std::sync::Arc<onboarding::Registry>,
    store: std::sync::Arc<synchronizer_state::TopologyStore>,
    sequencer: sequencing::Sequencer,
}

impl ConnectService {
    pub fn new(config: SynchronizerConfig) -> Self {
        Self::open(config, None).expect("a server without a state directory opens")
    }

    /// The service with its state in `state_dir` when given: what the journal there holds is replayed (the members that registered,
    /// the topology state, the events every member was sent), and what happens from now on is journaled.
    pub fn open(
        config: SynchronizerConfig,
        state_dir: Option<&std::path::Path>,
    ) -> std::io::Result<Self> {
        let opened = match state_dir {
            Some(dir) => Some(persistence::Journal::open(dir)?),
            None => None,
        };
        Self::open_journaled(config, opened)
    }

    /// Like [`ConnectService::open`], with the state kept in `store` (a database, say): what its journal holds is replayed, and what happens
    /// from now on is journaled there.
    pub fn open_in_store(
        config: SynchronizerConfig,
        store: std::sync::Arc<dyn canton_participant::state_store::StateStore>,
    ) -> std::io::Result<Self> {
        Self::open_journaled(config, Some(persistence::Journal::open_in(store, None)?))
    }

    /// A service around a sequencer, registry and topology store that exist already (a sequencer that serves a synchronizer it joined: the members and the topology
    /// come from the synchronizer, not from this node).
    pub fn from_parts(
        config: SynchronizerConfig,
        registry: std::sync::Arc<onboarding::Registry>,
        store: std::sync::Arc<synchronizer_state::TopologyStore>,
        sequencer: sequencing::Sequencer,
    ) -> Self {
        Self {
            journal: None,
            config,
            registry,
            store,
            sequencer,
        }
    }

    /// Opens a seeded topology store and member registry with optional durable journal replay (`state_store` or `state_dir`).
    pub fn open_seeded(
        config: SynchronizerConfig,
        store: std::sync::Arc<synchronizer_state::TopologyStore>,
        registry: std::sync::Arc<onboarding::Registry>,
        state_store: Option<std::sync::Arc<dyn canton_participant::state_store::StateStore>>,
        state_dir: Option<&std::path::Path>,
    ) -> std::io::Result<Self> {
        let opened = match (state_store, state_dir) {
            (Some(s), _) => Some(persistence::Journal::open_in(s, None)?),
            (None, Some(d)) => Some(persistence::Journal::open(d)?),
            (None, None) => None,
        };
        Self::open_with_parts(config, store, registry, opened)
    }

    fn open_journaled(
        config: SynchronizerConfig,
        opened: Option<(std::sync::Arc<persistence::Journal>, Vec<String>)>,
    ) -> std::io::Result<Self> {
        let store = std::sync::Arc::new(synchronizer_state::TopologyStore::initial(
            &config.name,
            &config.sequencer_name,
            "rm1",
            &config.keys,
        ));
        let registry: std::sync::Arc<onboarding::Registry> = Default::default();
        Self::open_with_parts(config, store, registry, opened)
    }

    fn open_with_parts(
        config: SynchronizerConfig,
        store: std::sync::Arc<synchronizer_state::TopologyStore>,
        registry: std::sync::Arc<onboarding::Registry>,
        opened: Option<(std::sync::Arc<persistence::Journal>, Vec<String>)>,
    ) -> std::io::Result<Self> {
        let sequencer = sequencing::Sequencer::new(
            config.physical_synchronizer_id(),
            std::sync::Arc::clone(&config.keys),
            std::sync::Arc::clone(&registry),
            std::sync::Arc::clone(&store),
        );
        let journal = match opened {
            None => None,
            Some((journal, lines)) => {
                let synchronizer_uid = format!("{}::{}", config.name, config.namespace_fingerprint);
                let (mut members, mut appended, mut events) = (0, 0, 0);
                for line in &lines {
                    let damaged = || {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "a journal line that does not replay: {}",
                                &line[..line.len().min(60)]
                            ),
                        )
                    };
                    match line.as_bytes().first() {
                        Some(b'R') => {
                            let (member, transactions) =
                                persistence::decode_registration(line).ok_or_else(damaged)?;
                            let registered =
                                onboarding::validate(&member, &synchronizer_uid, &transactions)
                                    .map_err(|_| damaged())?;
                            registry.insert(registered);
                            members += 1;
                        }
                        Some(b'A') => {
                            let mut f = line[2..].split(' ');
                            let at: i64 =
                                f.next().and_then(|t| t.parse().ok()).ok_or_else(damaged)?;
                            let signed = f
                                .next()
                                .and_then(persistence::unhex)
                                .and_then(|b| {
                                    <canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction as prost::Message>::decode(b.as_slice()).ok()
                                })
                                .ok_or_else(damaged)?;
                            store.append(&[signed], at);
                            appended += 1;
                        }
                        Some(b'B') => {
                            let mut f = line[2..].split(' ');
                            let at: i64 =
                                f.next().and_then(|t| t.parse().ok()).ok_or_else(damaged)?;
                            let content =
                                f.next().and_then(persistence::unhex).ok_or_else(damaged)?;
                            let _ = onboarding::register_onboarding_in_broadcast(
                                &content,
                                &config.physical_synchronizer_id(),
                                &registry,
                                None,
                            );
                            if let Some(outcomes) = store.accept_broadcast(&content, at) {
                                membership::follow_broadcast(
                                    &registry, &store, &content, &outcomes,
                                );
                            }
                        }
                        Some(b'H') => {
                            let (at, sender, envelopes) =
                                persistence::decode_mediator_input(line).ok_or_else(damaged)?;
                            let seen: Vec<mediator::SeenEnvelope> = envelopes
                                .into_iter()
                                .map(|e| (e.recipients, e.content, e.signatures))
                                .collect();
                            sequencer.replay_mediator_input(at, &sender, &seen);
                        }
                        Some(b'X') => {
                            let at: i64 = line[2..].trim().parse().map_err(|_| damaged())?;
                            sequencer.replay_expiry(at);
                        }
                        Some(b'K') => {
                            let mut f = line[2..].split(' ');
                            let member = f.next().ok_or_else(damaged)?.to_string();
                            let at: i64 =
                                f.next().and_then(|t| t.parse().ok()).ok_or_else(damaged)?;
                            sequencer.restore_ack(member, at);
                        }
                        Some(b'S') => {
                            let serial: u32 = line[2..].trim().parse().map_err(|_| damaged())?;
                            store.set_serial(serial);
                        }
                        Some(b'G') => {
                            sequencer.restore_aggregation(line).ok_or_else(damaged)?;
                        }
                        Some(b'T' | b'P') => {
                            sequencer.restore_traffic(line).ok_or_else(damaged)?;
                        }
                        Some(b'E') => {
                            let (member, event) =
                                persistence::decode_event(line).ok_or_else(damaged)?;
                            sequencer.restore_event(member, event);
                            events += 1;
                        }
                        _ => return Err(damaged()),
                    }
                }
                // the mediators onboarded after genesis are members because the topology names them
                sequencer.follow_mediators();
                crate::diag::diag_eprintln!(
                    "REPLAYED {members} member(s), {appended} onboarding transaction(s), {events} event(s)"
                );
                // what every member has acknowledged is forgotten, and the journal is rewritten without what no longer matters
                let forgotten = sequencer.forget_acknowledged();
                let compacted = sequencer.compact(&lines);
                if compacted.len() < lines.len() {
                    journal.replace(&compacted)?;
                }
                crate::diag::diag_eprintln!(
                    "COMPACTED {forgotten} event(s) forgotten, journal {} -> {} line(s)",
                    lines.len(),
                    compacted.len().min(lines.len())
                );
                // from here on what happens is journaled
                store.attach(std::sync::Arc::clone(&journal));
                sequencer.attach(std::sync::Arc::clone(&journal));
                Some(journal)
            }
        };
        Ok(Self {
            journal,
            config,
            registry,
            store,
            sequencer,
        })
    }

    /// Registers the mediator of every group as a member that runs elsewhere (see [`ServeOptions::external_mediator`]).
    pub fn use_external_mediators(&self) {
        let keys = &self.config.keys;
        for group in 0..keys.groups() {
            let member = mediator_member(&self.config, group);
            let key = keys.mediator_key(group);
            let own = match canton_algo::member_signature::own_ed25519_key(&key.spki_der) {
                Ok(own) => own,
                Err(e) => {
                    crate::diag::diag_eprintln!("MEDIATOR {member}: its key does not parse: {e:?}");
                    continue;
                }
            };
            self.sequencer.use_external_mediator(
                group as u32,
                onboarding::Registered {
                    member,
                    signing_keys: vec![own.clone()],
                    authentication_keys: vec![own],
                    encryption_keys: Vec::new(),
                },
            );
        }
    }

    /// The sequencer the members' submissions go through.
    pub fn sequencer(&self) -> sequencing::Sequencer {
        self.sequencer.clone()
    }

    /// The topology state this server hands out.
    pub fn store(&self) -> std::sync::Arc<synchronizer_state::TopologyStore> {
        std::sync::Arc::clone(&self.store)
    }

    /// The members that registered with this server.
    pub fn registry(&self) -> std::sync::Arc<onboarding::Registry> {
        std::sync::Arc::clone(&self.registry)
    }

    pub fn into_server(self) -> SequencerConnectServiceServer<Self> {
        SequencerConnectServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl SequencerConnectService for ConnectService {
    async fn handshake(
        &self,
        request: Request<HandshakeRequest>,
    ) -> Result<Response<HandshakeResponse>, Status> {
        let r = request.into_inner();
        crate::diag::diag_eprintln!(
            "RPC Handshake versions={:?} minimum={:?} client={}",
            r.client_protocol_versions,
            r.minimum_protocol_version,
            r.client_version
        );
        // [CANTON-NOTE: SEMANTICS] The server answers the protocol version it runs; the client accepts the answer when it speaks that
        // version (the success marker), and a client that does not gets an answer without it.
        let speaks = r.client_protocol_versions.contains(&PROTOCOL_VERSION);
        let acceptable = r
            .minimum_protocol_version
            .is_none_or(|minimum| minimum <= PROTOCOL_VERSION);
        Ok(Response::new(HandshakeResponse {
            server_protocol_version: PROTOCOL_VERSION,
            value: (speaks && acceptable).then_some(
                canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_connect::handshake_response::Value::Success(Success {}),
            ),
        }))
    }

    async fn get_synchronizer_id(
        &self,
        _request: Request<GetSynchronizerIdRequest>,
    ) -> Result<Response<GetSynchronizerIdResponse>, Status> {
        crate::diag::diag_eprintln!("RPC GetSynchronizerId");
        Ok(Response::new(GetSynchronizerIdResponse {
            physical_synchronizer_id: self.config.physical_synchronizer_id(),
            sequencer_uid: self.config.sequencer_uid(),
        }))
    }

    async fn get_synchronizer_parameters(
        &self,
        _request: Request<GetSynchronizerParametersRequest>,
    ) -> Result<Response<GetSynchronizerParametersResponse>, Status> {
        crate::diag::diag_eprintln!("RPC GetSynchronizerParameters");
        Ok(Response::new(GetSynchronizerParametersResponse {
            parameters: Some(Parameters::V32(static_parameters(self.config.serial))),
        }))
    }

    async fn verify_active(
        &self,
        request: Request<VerifyActiveRequest>,
    ) -> Result<Response<VerifyActiveResponse>, Status> {
        // [CANTON-NOTE: SEMANTICS] A participant names itself in the `memberid` header before it has authenticated (measured: p2 sends
        // `PAR::p2::...`); without it the call has no participant (the official sequencer's answer for an anonymous caller, S-NET-001).
        // The answer says whether that member is active on the synchronizer: a member nobody onboarded is not, and it then registers its
        // identity with `RegisterOnboardingTopologyTransactions`.
        let member = request
            .metadata()
            .get("memberid")
            .and_then(|m| m.to_str().ok())
            .map(str::to_string);
        crate::diag::diag_eprintln!("RPC VerifyActive member={member:?}");
        let Some(member) = member else {
            return Err(Status::unauthenticated(
                "Unable to find participant id in gRPC context",
            ));
        };
        let active = self.registry.is_registered(&member);
        Ok(Response::new(VerifyActiveResponse {
            value: Some(
                canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_connect::verify_active_response::Value::Success(
                    canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_connect::verify_active_response::Success {
                        is_active: active,
                    },
                ),
            ),
        }))
    }

    async fn register_onboarding_topology_transactions(
        &self,
        request: Request<RegisterOnboardingTopologyTransactionsRequest>,
    ) -> Result<Response<RegisterOnboardingTopologyTransactionsResponse>, Status> {
        let member = request
            .metadata()
            .get("memberid")
            .and_then(|m| m.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| {
                Status::unauthenticated("Unable to find participant id in gRPC context")
            })?;
        crate::diag::diag_eprintln!("RPC RegisterOnboardingTopologyTransactions member={member}");
        let synchronizer_uid = format!(
            "{}::{}",
            self.config.name, self.config.namespace_fingerprint
        );
        // [CANTON-NOTE: WHY] A new member's identity is a topology change, and the topology is frozen once an upgrade is announced (the
        // successor starts from the state at the announcement). The wording is the topology freeze's; what the official sequencer answers
        // a registration then was not measured.
        // [CANTON-NOTE: SEMANTICS] a successor onboards no one before the upgrade time (`GrpcSequencerConnectService`, read from the source:
        // its sequencer could not sequence the onboarding transactions before then)
        if let Some(upgrade) = self.store.upgrade_time_here() {
            let now = sequencing::wall_micros();
            if now <= upgrade {
                return Err(Status::failed_precondition(format!(
                    "Onboarding is possible only after {} but current time is {}. Aborting...",
                    canton_participant::topology_state::iso_utc(upgrade),
                    canton_participant::topology_state::iso_utc(now)
                )));
            }
        }
        if let Some(lsu) = self.store.announced_upgrade() {
            return Err(Status::failed_precondition(format!(
                "The topology state of synchronizer {} is frozen due to an announced LSU. No more topology changes are allowed until upgrade completion.",
                lsu.successor.logical
            )));
        }
        let transactions = request.into_inner().topology_transactions;
        let registered = onboarding::validate(&member, &synchronizer_uid, &transactions)?;
        if self.sequencer.has_orderer() {
            self.sequencer
                .order_topology_broadcast(&transactions)
                .await?;
            crate::diag::diag_eprintln!("RPC registered {member} (BFT ordered)");
            return Ok(Response::new(
                RegisterOnboardingTopologyTransactionsResponse {},
            ));
        }
        // journaled before it takes effect: a member the journal does not know is not one a restart can bring back
        if let Some(journal) = &self.journal {
            journal.write(&persistence::registration_line(&member, &transactions));
        }
        crate::diag::diag_eprintln!("RPC registered {member}");
        self.registry.insert(registered);
        // the registered topology is broadcast to every member (the new one included): its first event. The state keeps it as sequenced
        // then, so that a member that downloads the state and a member that read the broadcast agree on when it takes effect
        let sequenced =
            self.sequencer
                .broadcast(canton_participant::topology_wire::topology_broadcast(
                    &self.config.physical_synchronizer_id(),
                    &transactions,
                ));
        self.store.append(&transactions, sequenced);
        // ... and, once the change has taken effect, a tick so that every member's clock passes the effective time
        self.sequencer.tick_after_topology_change();
        Ok(Response::new(
            RegisterOnboardingTopologyTransactionsResponse {},
        ))
    }
}

/// Answers `ApiInfoService.GetApiInfo` with the sequencer API's name.
pub struct ApiInfo;

#[tonic::async_trait]
impl ApiInfoService for ApiInfo {
    async fn get_api_info(
        &self,
        _request: Request<GetApiInfoRequest>,
    ) -> Result<Response<GetApiInfoResponse>, Status> {
        crate::diag::diag_eprintln!("RPC GetApiInfo");
        Ok(Response::new(GetApiInfoResponse {
            name: SEQUENCER_API_NAME.to_string(),
        }))
    }
}

/// The service names the server answers health checks for (besides the empty name, the server as a whole).
const HEALTH_SERVICES: &[&str] = &[
    // the name the official participant's connection pool watches (measured: S-NET-037 part 21)
    "sequencer-health-check-service",
    "com.digitalasset.canton.sequencer.api.v30.SequencerConnectService",
    "com.digitalasset.canton.sequencer.api.v30.SequencerAuthenticationService",
    "com.digitalasset.canton.sequencer.api.v30.SequencerService",
];

/// The health service (`grpc.health.v1`). The server is `SERVING` while it runs and `NOT_SERVING` once it was asked to stop, which a
/// watcher is told as a status change; a service name the server does not have is `NOT_FOUND`, as the protocol says.
#[derive(Clone)]
pub struct Health {
    status: tokio::sync::watch::Sender<health::health_check_response::ServingStatus>,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            status: tokio::sync::watch::channel(
                health::health_check_response::ServingStatus::Serving,
            )
            .0,
        }
    }
}

impl Health {
    /// From now on the server is not serving (watchers are told).
    pub fn set_not_serving(&self) {
        self.status
            .send_replace(health::health_check_response::ServingStatus::NotServing);
    }

    fn known(service: &str) -> bool {
        service.is_empty() || HEALTH_SERVICES.contains(&service)
    }
}

#[tonic::async_trait]
impl health::health_server::Health for Health {
    async fn check(
        &self,
        request: Request<health::HealthCheckRequest>,
    ) -> Result<Response<health::HealthCheckResponse>, Status> {
        let service = request.into_inner().service;
        crate::diag::diag_eprintln!("RPC Health.Check");
        if !Self::known(&service) {
            return Err(Status::not_found(format!("unknown service {service}")));
        }
        Ok(Response::new(health::HealthCheckResponse {
            status: *self.status.borrow() as i32,
        }))
    }

    type WatchStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<health::HealthCheckResponse, Status>> + Send>,
    >;

    async fn watch(
        &self,
        request: Request<health::HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let service = request.into_inner().service;
        crate::diag::diag_eprintln!("RPC Health.Watch service={service:?}");
        if !Self::known(&service) {
            // the protocol: a watch of an unknown service reports SERVICE_UNKNOWN and stays open
            let unknown = health::HealthCheckResponse {
                status: health::health_check_response::ServingStatus::ServiceUnknown as i32,
            };
            return Ok(Response::new(Box::pin(
                tokio_stream::iter([Ok(unknown)]).chain(tokio_stream::pending()),
            )));
        }
        // the current status, then every change of it
        let stream =
            tokio_stream::wrappers::WatchStream::new(self.status.subscribe()).map(|status| {
                Ok(health::HealthCheckResponse {
                    status: status as i32,
                })
            });
        Ok(Response::new(Box::pin(stream)))
    }
}

/// Serves the connect service on `address` until the future is dropped.
/// The member id of the mediator of `group`: `MED::rm<group + 1>::<the mediator namespace>` (what the synchronizer's own topology names).
pub fn mediator_member(config: &SynchronizerConfig, group: usize) -> String {
    format!(
        "MED::rm{}::{}",
        group + 1,
        config.keys.mediator_namespace.fingerprint
    )
}

/// A synchronizer with fresh keys for its namespace and its sequencer: the identity a new Rust synchronizer starts with.
pub fn new_synchronizer(name: &str, sequencer_name: &str) -> SynchronizerConfig {
    new_synchronizer_with_groups(name, sequencer_name, 1)
}

/// Like [`new_synchronizer`], with `mediator_groups` mediator groups (`MGR::0` ... `MGR::<n-1>`), each served by its own mediator with its
/// own key.
pub fn new_synchronizer_with_groups(
    name: &str,
    sequencer_name: &str,
    mediator_groups: usize,
) -> SynchronizerConfig {
    let keys = synchronizer_state::SynchronizerKeys::generate_with_groups(mediator_groups);
    SynchronizerConfig {
        name: name.to_string(),
        // the sequencer has its own namespace; the synchronizer's is decentralized, owned by the sequencer's and the mediator's
        sequencer_fingerprint: keys.namespace.fingerprint.clone(),
        namespace_fingerprint: keys.synchronizer_namespace(),
        sequencer_name: sequencer_name.to_string(),
        keys: std::sync::Arc::new(keys),
        serial: 0,
    }
}

/// Like [`new_synchronizer`], with the synchronizer's keys kept in `state_dir` (created there the first time): the same directory
/// is the same synchronizer after a restart.
pub fn new_synchronizer_in(
    state_dir: &std::path::Path,
    name: &str,
    sequencer_name: &str,
    mediator_groups: usize,
) -> std::io::Result<SynchronizerConfig> {
    // an existing directory keeps the number of groups it was made with
    let keys = synchronizer_state::SynchronizerKeys::load_or_create(state_dir, mediator_groups)?;
    Ok(SynchronizerConfig {
        name: name.to_string(),
        sequencer_fingerprint: keys.namespace.fingerprint.clone(),
        namespace_fingerprint: keys.synchronizer_namespace(),
        sequencer_name: sequencer_name.to_string(),
        keys: std::sync::Arc::new(keys),
        // a successor's directory names its serial (see `persistence::seed_successor`)
        serial: persistence::serial_in(state_dir)?,
    })
}

/// Like [`new_synchronizer_in`], with the synchronizer's keys (and its serial, from its journal) kept in `store`, a directory or a database.
pub fn new_synchronizer_in_store(
    store: &dyn canton_participant::state_store::StateStore,
    name: &str,
    sequencer_name: &str,
    mediator_groups: usize,
) -> std::io::Result<SynchronizerConfig> {
    let keys = synchronizer_state::SynchronizerKeys::load_or_create_in(store, mediator_groups)?;
    let journal = store.read("journal").map_err(std::io::Error::other)?;
    Ok(SynchronizerConfig {
        name: name.to_string(),
        sequencer_fingerprint: keys.namespace.fingerprint.clone(),
        namespace_fingerprint: keys.synchronizer_namespace(),
        sequencer_name: sequencer_name.to_string(),
        keys: std::sync::Arc::new(keys),
        serial: persistence::serial_of(&journal.unwrap_or_default())?,
    })
}

/// How a server runs.
#[derive(Default, Clone)]
pub struct ServeOptions {
    /// Where the keys, the members, the topology and the events are kept when it is not a directory (a database): the same as `state_dir`,
    /// which this takes the place of.
    pub state_store: Option<std::sync::Arc<dyn canton_participant::state_store::StateStore>>,
    /// Every interval a tick (an event with an empty batch) goes to every registered member, so that the members' clocks keep moving
    /// without anyone sending anything.
    pub tick_interval: Option<std::time::Duration>,
    /// Where the keys, the members, the topology and the events are kept (see [`ConnectService::open`]); in memory when `None`.
    pub state_dir: Option<std::path::PathBuf>,
    /// The server's TLS identity: a PEM certificate chain and a PEM private key (PKCS#8). The public API is then served over TLS.
    ///
    /// [CANTON-NOTE: SEMANTICS] Only the **server** is authenticated this way (the sequencer's `public-api.tls` of the official node):
    /// members still authenticate with the challenge-and-signature of the authentication service.
    pub tls: Option<(String, String)>,
    /// PEM certificate authority bundle used to verify client TLS certificates (mutual TLS) when [`Self::tls`] is set.
    pub tls_client_ca: Option<String>,
    /// A stop request: when it is notified the server reports `NOT_SERVING` to the health watchers, waits a moment for them to read it
    /// and stops accepting calls ([`serve_with`] then returns).
    pub shutdown: Option<std::sync::Arc<tokio::sync::Notify>>,
    /// BFT ordering mode: the order of the submissions is decided by `3f + 1` ordering nodes (see [`ordering`]); `f` is given here.
    pub bft_f: Option<usize>,
    /// A file the operator writes commands to, one per line; it is read about twice a second and emptied. `upgrade <seconds> <endpoint>`
    /// announces the synchronizer's logical upgrade to its successor (serial + 1) that many seconds from now, with this sequencer's
    /// connection on the successor at `endpoint`; in BFT mode `crash 0`, `restart 0`, `partition 0,0,0,1`, `heal` and `status` hurt and
    /// heal the ordering nodes.
    pub control: Option<std::path::PathBuf>,
    /// How often the running server shortens its journal and forgets the events every member acknowledged (see
    /// [`sequencing::Sequencer::compact_running`]); only with a state directory. Without it the journal is shortened when the server starts.
    pub compact_every: Option<std::time::Duration>,
    /// The mediators run as processes of their own (`canton-rs mediator run --state-dir`, the same directory): the mediators inside the
    /// sequencer are switched off and each group is served by the member `MED::rm<group + 1>::<namespace>`, which authenticates with the
    /// mediator's key kept in the state directory. Needs `state_dir`.
    pub external_mediator: bool,
    /// Optional HTTP status & Prometheus `/metrics` listener address (`--metrics-port`).
    pub metrics_address: Option<std::net::SocketAddr>,
    /// Where the administration services (traffic, topology, BFT administration) are served; without it they are not served (the public
    /// API serves what members call, as Canton's does).
    pub admin_address: Option<std::net::SocketAddr>,
}

pub async fn serve(
    address: std::net::SocketAddr,
    config: SynchronizerConfig,
) -> Result<(), tonic::transport::Error> {
    serve_with_ticks(address, config, None).await
}

/// Like [`serve`], with the server's state kept in `state_dir` (see [`ConnectService::open`]).
pub async fn serve_in(
    address: std::net::SocketAddr,
    config: SynchronizerConfig,
    state_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_with(
        address,
        config,
        ServeOptions {
            state_dir: Some(state_dir.to_path_buf()),
            ..Default::default()
        },
    )
    .await
}

/// Like [`serve`], and every `tick_interval` a tick goes to every registered member (what a participant's event validator needs to
/// learn the topology at the time of the events it has received).
pub async fn serve_with_ticks(
    address: std::net::SocketAddr,
    config: SynchronizerConfig,
    tick_interval: Option<std::time::Duration>,
) -> Result<(), tonic::transport::Error> {
    let connect = ConnectService::new(config.clone());
    serve_service(
        address,
        config,
        connect,
        tick_interval,
        None,
        None,
        None,
        ServeBft::default(),
    )
    .await
}

/// Serves a pre-seeded `ConnectService` (such as one adopted from an official sequencer DB) on `address` and optional `admin_address`.
pub async fn serve_seeded_with(
    address: std::net::SocketAddr,
    admin_address: Option<std::net::SocketAddr>,
    config: SynchronizerConfig,
    connect: ConnectService,
    options: ServeOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_service(
        address,
        config,
        connect,
        options.tick_interval,
        options.tls,
        options.tls_client_ca,
        options.shutdown,
        ServeBft {
            f: options.bft_f,
            control: options.control,
            compact_every: options.compact_every,
            admin_address,
            bft_admin: None,
        },
    )
    .await?;
    Ok(())
}

/// Spawns a non-blocking HTTP `/livez`, `/readyz`, `/status`, and `/metrics` server for a sequencer.
pub fn spawn_status_http(
    address: std::net::SocketAddr,
    config: SynchronizerConfig,
    sequencer: sequencing::Sequencer,
    peer_manager: Option<std::sync::Arc<bft_p2p::BftPeerManager>>,
    bft_total_peers: usize,
    shutdown: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    let listener = std::net::TcpListener::bind(address)
        .map_err(|e| format!("cannot bind sequencer metrics HTTP on {address}: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot configure sequencer metrics listener: {e}"))?;
    let stop_flag = std::sync::Arc::new(AtomicBool::new(false));
    if let Some(notify) = shutdown {
        let stop_watch = std::sync::Arc::clone(&stop_flag);
        tokio::spawn(async move {
            notify.notified().await;
            stop_watch.store(true, Ordering::SeqCst);
        });
    }
    let physical = config.physical_synchronizer_id();
    let sync_uid = config.synchronizer_uid();
    let seq_uid = config.sequencer_uid();
    let seq_name = config.sequencer_name;
    std::thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req.split_whitespace().nth(1).unwrap_or("/");
                    let path = path.split('?').next().unwrap_or(path);
                    let head_offset = sequencer.head_offset();
                    let members = sequencer.connected_member_count();
                    let bft_quorum = peer_manager.as_ref().map(|pm| {
                        let connected = pm.authenticated_peers_count() as u32;
                        let total = bft_total_peers.max(connected as usize) as u32;
                        (connected, total)
                    });
                    let (status, ctype, body) = match path {
                        "/_quiesce/pause" | "/_quiesce_pause" => {
                            sequencer.set_quiesced(true);
                            (
                                "200 OK",
                                "application/json",
                                format!(
                                    "{{\"quiesced\":true,\"in_flight\":{}}}",
                                    sequencer.in_flight_submissions()
                                ),
                            )
                        }
                        "/_quiesce/resume" | "/_resume" => {
                            sequencer.set_quiesced(false);
                            (
                                "200 OK",
                                "application/json",
                                format!(
                                    "{{\"quiesced\":false,\"in_flight\":{}}}",
                                    sequencer.in_flight_submissions()
                                ),
                            )
                        }
                        "/_quiesce" => (
                            "200 OK",
                            "application/json",
                            format!(
                                "{{\"quiesced\":{},\"in_flight\":{}}}",
                                sequencer.is_quiesced(),
                                sequencer.in_flight_submissions()
                            ),
                        ),
                        "/livez" | "/readyz" => (
                            "200 OK",
                            "application/json",
                            r#"{"status":"ok"}"#.to_string(),
                        ),
                        "/status" => {
                            let bft_field = match bft_quorum {
                                Some((c, t)) => format!("[{c},{t}]"),
                                None => "null".to_string(),
                            };
                            let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
                            (
                                "200 OK",
                                "application/json",
                                format!(
                                    "{{\"sequencer_uid\":\"{}\",\"synchronizer\":\"{}\",\"physical_synchronizer_id\":\"{}\",\"head_offset\":{head_offset},\"connected_members\":{members},\"bft_quorum_peers\":{bft_field}}}",
                                    esc(&seq_uid),
                                    esc(&sync_uid),
                                    esc(&physical),
                                ),
                            )
                        }
                        "/metrics" => {
                            let mut body = format!(
                                "# HELP canton_rs_node_up Sequencer availability (1 = Serving)\n\
                                 # TYPE canton_rs_node_up gauge\n\
                                 canton_rs_node_up{{synchronizer=\"{sync_uid}\",role=\"sequencer\",node=\"{seq_name}\"}} 1\n\
                                 # HELP canton_rs_sequencer_head_offset Sequencer current head offset\n\
                                 # TYPE canton_rs_sequencer_head_offset gauge\n\
                                 canton_rs_sequencer_head_offset{{synchronizer=\"{sync_uid}\",node=\"{seq_name}\"}} {head_offset}\n\
                                 # HELP canton_rs_sequencer_connected_members Registered member count\n\
                                 # TYPE canton_rs_sequencer_connected_members gauge\n\
                                 canton_rs_sequencer_connected_members{{synchronizer=\"{sync_uid}\",node=\"{seq_name}\"}} {members}\n"
                            );
                            if let Some((connected, _)) = bft_quorum {
                                body.push_str(&format!(
                                    "# HELP canton_rs_bft_quorum_peers Active BFT consensus peers\n\
                                     # TYPE canton_rs_bft_quorum_peers gauge\n\
                                     canton_rs_bft_quorum_peers{{synchronizer=\"{sync_uid}\",node=\"{seq_name}\"}} {connected}\n"
                                ));
                            }
                            ("200 OK", "text/plain; version=0.0.4; charset=utf-8", body)
                        }
                        _ => ("404 Not Found", "application/json", "{}".to_string()),
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(_) => break,
            }
        }
    });
    Ok(())
}

/// Serves as `options` say.
pub async fn serve_with(
    address: std::net::SocketAddr,
    config: SynchronizerConfig,
    options: ServeOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connect = match &options.state_store {
        Some(store) => ConnectService::open_in_store(config.clone(), std::sync::Arc::clone(store))?,
        None => ConnectService::open(config.clone(), options.state_dir.as_deref())?,
    };
    if options.external_mediator {
        if options.state_dir.is_none() && options.state_store.is_none() {
            return Err("external mediators need a state directory or a database: it holds the keys they use".into());
        }
        connect.use_external_mediators();
    }
    if let Some(metrics_addr) = options.metrics_address {
        let _ = spawn_status_http(
            metrics_addr,
            config.clone(),
            connect.sequencer(),
            None,
            0,
            options.shutdown.clone(),
        );
    }
    serve_service(
        address,
        config,
        connect,
        options.tick_interval,
        options.tls,
        options.tls_client_ca,
        options.shutdown,
        ServeBft {
            f: options.bft_f,
            control: options.control,
            compact_every: options.compact_every,
            admin_address: options.admin_address,
            bft_admin: None,
        },
    )
    .await?;
    Ok(())
}

/// Serves the public API of a sequencer built by [`ConnectService::from_parts`] (authentication, subscriptions, the connect service): the events it hands out come
/// from what is applied to its `Sequencer`, there is no clock tick of its own.
pub async fn serve_connect(
    address: std::net::SocketAddr,
    config: SynchronizerConfig,
    connect: ConnectService,
) -> Result<(), tonic::transport::Error> {
    serve_connect_with_admin(address, None, config, connect, None).await
}

/// Like [`serve_connect`], optionally also binding an admin-api listener and graceful shutdown trigger.
pub async fn serve_connect_with_admin(
    address: std::net::SocketAddr,
    admin_address: Option<std::net::SocketAddr>,
    config: SynchronizerConfig,
    connect: ConnectService,
    shutdown: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> Result<(), tonic::transport::Error> {
    serve_connect_with_bft_admin(address, admin_address, config, connect, shutdown, None).await
}

/// Like [`serve_connect_with_admin`], optionally also serving BFT administration & BFT pruning administration gRPC services.
pub async fn serve_connect_with_bft_admin(
    address: std::net::SocketAddr,
    admin_address: Option<std::net::SocketAddr>,
    config: SynchronizerConfig,
    connect: ConnectService,
    shutdown: Option<std::sync::Arc<tokio::sync::Notify>>,
    bft_admin: Option<(
        bft_admin::BftAdminService,
        bft_admin::BftPruningAdminService,
    )>,
) -> Result<(), tonic::transport::Error> {
    serve_service(
        address,
        config,
        connect,
        None,
        None,
        None,
        shutdown,
        ServeBft {
            admin_address,
            bft_admin,
            ..Default::default()
        },
    )
    .await
}

/// What the BFT ordering mode needs besides the service (see [`ServeOptions::bft_f`]).
#[derive(Default)]
struct ServeBft {
    f: Option<usize>,
    control: Option<std::path::PathBuf>,
    compact_every: Option<std::time::Duration>,
    admin_address: Option<std::net::SocketAddr>,
    bft_admin: Option<(
        bft_admin::BftAdminService,
        bft_admin::BftPruningAdminService,
    )>,
}

async fn serve_service(
    address: std::net::SocketAddr,
    config: SynchronizerConfig,
    connect: ConnectService,
    tick_interval: Option<std::time::Duration>,
    tls: Option<(String, String)>,
    tls_client_ca: Option<String>,
    shutdown: Option<std::sync::Arc<tokio::sync::Notify>>,
    bft: ServeBft,
) -> Result<(), tonic::transport::Error> {
    let health = Health::default();
    if let Some(every) = bft.compact_every {
        let sequencer = connect.sequencer();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(every);
            timer.tick().await;
            loop {
                timer.tick().await;
                if let Some((forgotten, before, after)) = sequencer.compact_running() {
                    if after < before || forgotten > 0 {
                        crate::diag::diag_eprintln!("COMPACTED running: {forgotten} event(s) forgotten, journal {before} -> {after} line(s)");
                    }
                }
            }
        });
    }
    let ordering = bft.f.map(|f| {
        // the ordering nodes decide the order of the submissions: a tick every few milliseconds, and what they commit is sequenced
        let ordering = std::sync::Arc::new(ordering::BftOrdering::new(f));
        connect
            .sequencer()
            .use_ordering(std::sync::Arc::clone(&ordering));
        let sequencer = connect.sequencer();
        crate::diag::diag_eprintln!("ORDERING BFT mode with {} ordering nodes", 3 * f + 1);
        let stepping = std::sync::Arc::clone(&ordering);
        tokio::spawn(async move {
            let mut every = tokio::time::interval(std::time::Duration::from_millis(5));
            loop {
                every.tick().await;
                for (member, request) in stepping.step() {
                    sequencer.apply_ordered(&member, &request);
                }
            }
        });
        ordering
    });
    if let Some(path) = bft.control {
        let (sequencer, config) = (connect.sequencer(), config.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                if text.trim().is_empty() {
                    continue;
                }
                let _ = std::fs::write(&path, "");
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    crate::diag::diag_eprintln!(
                        "{}",
                        control(line, &sequencer, &config, ordering.as_deref()).await
                    );
                }
            }
        });
    }
    // every call is logged by its path (`RPC <service>/<method>`), also the ones no service here implements: the next unit of G6 is the
    // first call a participant makes that is not served
    let log_paths = tower::layer::layer_fn(|inner| LogPaths { inner });
    {
        let watching = connect.sequencer();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                watching.expire_requests();
                watching.close_after_upgrade();
            }
        });
    }
    if let Some(interval) = tick_interval {
        let ticking = connect.sequencer();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                ticking.tick();
            }
        });
    }
    let (grace, force) = (
        std::sync::Arc::new(tokio::sync::Notify::new()),
        std::sync::Arc::new(tokio::sync::Notify::new()),
    );
    if let Some(stop) = shutdown {
        let (health, grace, force) = (
            health.clone(),
            std::sync::Arc::clone(&grace),
            std::sync::Arc::clone(&force),
        );
        tokio::spawn(async move {
            stop.notified().await;
            health.set_not_serving();
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            grace.notify_one();
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            force.notify_one();
        });
    }
    // [CANTON-NOTE: SEMANTICS] The public API serves what members call (`SequencerNode`: the sequencer, authentication, connect, API-info
    // and health services); traffic purchases, topology writes and reads and the BFT administration are `admin-api` services, served on
    // the admin port only.
    // [CANTON-NOTE: LIMITATION] A server started without an admin port (a Canton node always has one) keeps them on the public port, where
    // the operator commands that name only `--sequencer-url` (`canton-rs sequencer add-mediator`) reach them; it says so at start.
    let limit = crate::transport::MAX_INBOUND_MESSAGE_SIZE;
    macro_rules! public_services {
        ($router:expr, $config:expr, $connect:expr) => {{
            let authentication =
                auth::Authentication::new($config.physical_synchronizer_id(), $connect.registry());
            let service = sequencer_service::SequencerServiceImpl::new(
                authentication.clone(),
                $connect.store(),
                $connect.sequencer(),
            );
            $router
                .add_service($connect.into_server().max_decoding_message_size(limit))
                .add_service(
                    canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_authentication_service_server::SequencerAuthenticationServiceServer::new(authentication).max_decoding_message_size(limit),
                )
                .add_service(
                    canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_service_server::SequencerServiceServer::new(service).max_decoding_message_size(limit),
                )
        }};
    }
    macro_rules! admin_services {
        ($router:expr, $config:expr, $connect:expr, $bft_admin:expr) => {{
            let topology_admin = topology_admin::TopologyAdmin::new($config, $connect.sequencer());
            $router
                .add_service(
                    canton_proto::com::digitalasset::canton::sequencer::admin::v30::sequencer_administration_service_server::SequencerAdministrationServiceServer::new(admin::AdminService::new($connect.registry(), $connect.sequencer())).max_decoding_message_size(limit),
                )
                .add_service(
                    canton_proto::com::digitalasset::canton::sequencer::admin::v30::sequencer_pruning_administration_service_server::SequencerPruningAdministrationServiceServer::new(pruning_admin::SequencerPruning::new($connect.sequencer())).max_decoding_message_size(limit),
                )
                .add_service(
                    canton_proto::com::digitalasset::canton::mediator::admin::v30::mediator_administration_service_server::MediatorAdministrationServiceServer::new(pruning_admin::MediatorPruning::new($connect.sequencer())).max_decoding_message_size(limit),
                )
                .add_optional_service($bft_admin.as_ref().map(|(a, _)| {
                    canton_proto::com::digitalasset::canton::sequencer::admin::v30::sequencer_bft_administration_service_server::SequencerBftAdministrationServiceServer::new(a.clone()).max_decoding_message_size(limit)
                }))
                .add_optional_service($bft_admin.as_ref().map(|(_, p)| {
                    canton_proto::com::digitalasset::canton::sequencer::admin::v30::sequencer_bft_pruning_administration_service_server::SequencerBftPruningAdministrationServiceServer::new(p.clone()).max_decoding_message_size(limit)
                }))
                .add_service(
                    canton_proto::com::digitalasset::canton::topology::admin::v30::topology_manager_write_service_server::TopologyManagerWriteServiceServer::new(topology_admin.clone()).max_decoding_message_size(limit),
                )
                .add_service(
                    canton_proto::com::digitalasset::canton::topology::admin::v30::topology_manager_read_service_server::TopologyManagerReadServiceServer::new(topology_admin).max_decoding_message_size(limit),
                )
        }};
    }
    let mut server = crate::transport::server();
    if let Some((certificate, key)) = tls {
        let mut tls_config = tonic::transport::ServerTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(certificate, key));
        if let Some(ca) = tls_client_ca {
            tls_config = tls_config.client_ca_root(tonic::transport::Certificate::from_pem(ca));
        }
        server = server.tls_config(tls_config)?;
    }
    let one_port = bft.admin_address.is_none_or(|a| a == address);
    if bft.admin_address.is_none() {
        crate::diag::diag_eprintln!(
            "ADMIN the administration services (traffic, topology, BFT) are served on the public port {address}: give the sequencer an admin port (CANTON_RS_SEQUENCER_ADMIN_BIND, or --admin-bind on run-bft) to serve them apart"
        );
    }
    if let Some(admin_addr) = bft.admin_address.filter(|a| *a != address) {
        let admin_router = admin_services!(
            crate::transport::server()
                .add_service(
                    health::health_server::HealthServer::new(health.clone())
                        .max_decoding_message_size(limit)
                )
                .add_service(ApiInfoServiceServer::new(ApiInfo).max_decoding_message_size(limit)),
            config.clone(),
            connect.clone(),
            bft.bft_admin
        );
        let admin_grace = std::sync::Arc::clone(&grace);
        tokio::spawn(async move {
            let _ = admin_router
                .serve_with_shutdown(admin_addr, async move { admin_grace.notified().await })
                .await;
        });
    }
    let public_router = public_services!(
        server
            .layer(log_paths)
            .add_service(
                health::health_server::HealthServer::new(health).max_decoding_message_size(limit)
            )
            .add_service(ApiInfoServiceServer::new(ApiInfo).max_decoding_message_size(limit)),
        config.clone(),
        connect.clone()
    );
    let public_router = if one_port {
        admin_services!(public_router, config, connect, bft.bft_admin)
    } else {
        public_router
    };
    let serving = public_router.serve_with_shutdown(address, async move { grace.notified().await });
    tokio::select! {
        result = serving => result,
        _ = force.notified() => Ok(()),
    }
}

/// Carries out one line of the operator's control file (see [`ServeOptions::control`]) and says what became of it.
async fn control(
    line: &str,
    sequencer: &sequencing::Sequencer,
    config: &SynchronizerConfig,
    ordering: Option<&ordering::BftOrdering>,
) -> String {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["upgrade", seconds, endpoint] => {
            let Ok(seconds) = seconds.parse::<i64>() else {
                return format!("CONTROL upgrade: {seconds} is no number of seconds");
            };
            let at = sequencing::wall_micros() + seconds * 1_000_000;
            let successor = SynchronizerConfig {
                serial: config.serial + 1,
                ..config.clone()
            }
            .physical_synchronizer_id();
            let [announcement, connection] = synchronizer_state::upgrade_transactions(
                &config.keys,
                &config.sequencer_uid(),
                &successor,
                config.serial + 1,
                at,
                endpoint,
            );
            // [CANTON-NOTE: SEMANTICS] the connection on the successor is sequenced only once the announcement is in force: in one broadcast
            // with the announcement the official participant rejects it ("The operation cannot be performed because no LSU is announced",
            // measured: its checks do not see the announcement of the same batch) and its upgrade then fails for want of a successor
            let announced = sequencer.sequence_topology(&[announcement]);
            tokio::time::sleep(std::time::Duration::from_micros(
                synchronizer_state::TOPOLOGY_CHANGE_DELAY_MICROS as u64 + 500_000,
            ))
            .await;
            let connected = sequencer.sequence_topology(&[connection]);
            format!(
                "CONTROL upgrade to {successor} at {}: {}",
                canton_participant::topology_state::iso_utc(at),
                announced
                    .into_iter()
                    .chain(connected)
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        }
        // `traffic <max base traffic> <read vs write scaling> <base event cost>` turns traffic control on (base traffic refilled over 10
        // minutes), `traffic off` turns it off: the owners change the dynamic parameters
        ["traffic", rest @ ..] => {
            use canton_proto::com::digitalasset::canton::protocol::v30::TrafficControlParameters;
            let traffic = match rest {
                ["off"] => None,
                [base, scaling, cost] => match (base.parse(), scaling.parse(), cost.parse()) {
                    (Ok(base), Ok(scaling), Ok(cost)) => Some(TrafficControlParameters {
                        max_base_traffic_amount: base,
                        max_base_traffic_accumulation_duration: Some(prost_types_duration(600, 0)),
                        read_vs_write_scaling_factor: scaling,
                        set_balance_request_submission_window_size: Some(prost_types_duration(
                            120, 0,
                        )),
                        enforce_rate_limiting: true,
                        base_event_cost: Some(cost),
                        free_confirmation_responses: false,
                    }),
                    _ => return format!("CONTROL traffic: not numbers: {line}"),
                },
                _ => return format!("CONTROL traffic: say `traffic <base> <scaling> <cost>` or `traffic off`, not {line}"),
            };
            let Some((serial, mut parameters)) = sequencer.store().parameters() else {
                return "CONTROL traffic: the synchronizer has no parameters".to_string();
            };
            parameters.traffic_control = traffic;
            let change = synchronizer_state::parameters_transaction(
                &config.keys,
                &config.synchronizer_uid(),
                serial + 1,
                parameters,
            );
            format!(
                "CONTROL traffic: {}",
                sequencer.sequence_topology(&[change]).join("; ")
            )
        }
        _ => match ordering {
            Some(ordering) => ordering.control(line),
            None => format!("CONTROL unknown command: {line}"),
        },
    }
}

/// Logs the path of every HTTP/2 request before the service sees it.
#[derive(Clone)]
struct LogPaths<S> {
    inner: S,
}

impl<S, B> tower::Service<tonic::codegen::http::Request<B>> for LogPaths<S>
where
    S: tower::Service<tonic::codegen::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: tonic::codegen::http::Request<B>) -> Self::Future {
        let path = request.uri().path();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() % 1_000_000)
            .unwrap_or(0);
        if path.ends_with("/Subscribe") || path.ends_with("/GetTime") {
            crate::diag::diag_poll_eprintln!("PATH {path} at {now}");
        } else {
            crate::diag::diag_eprintln!("PATH {path} at {now}");
        }
        self.inner.call(request)
    }
}
