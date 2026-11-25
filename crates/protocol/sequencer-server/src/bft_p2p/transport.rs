//! gRPC BFT P2P service (`BftOrderingService`), inbound/outbound bidirectional streams, and message signature verification.

use std::pin::Pin;
use std::sync::Arc;

use canton_proto::com::digitalasset::canton::sequencer::admin::v30::PeerEndpoint;
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
    bft_ordering_service_server::BftOrderingService, BftOrderingMessage,
};
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use crate::auth::Authentication;
use crate::onboarding::Registry;

use super::{
    sequencer_registry, BftClientTls, BftPeerConfig, BftPeerManager, BftServerTls, Consensus,
    SignedMessage,
};

async fn connect_p2p_channel(
    address: &str,
    port: u32,
    tls: Option<&BftClientTls>,
    fallback: Option<&BftClientTls>,
) -> Result<tonic::transport::Channel, String> {
    let scheme = if tls.is_some() { "https" } else { "http" };
    let url = if address.contains(':') {
        format!("{scheme}://[{address}]:{port}")
    } else {
        format!("{scheme}://{address}:{port}")
    };
    let mut endpoint = tonic::transport::Endpoint::from_shared(url.clone())
        .map_err(|e| e.to_string())?
        .connect_timeout(std::time::Duration::from_secs(10));
    if let Some(cfg) = tls {
        let mut client_tls =
            tonic::transport::ClientTlsConfig::new().domain_name(address.to_string());
        let ca_pem = cfg
            .custom_server_trust_pem
            .as_ref()
            .or_else(|| fallback.and_then(|f| f.custom_server_trust_pem.as_ref()));
        if let Some(ca) = ca_pem {
            client_tls = client_tls.ca_certificate(tonic::transport::Certificate::from_pem(ca));
        }
        let cert_pem = cfg
            .client_cert_chain_pem
            .as_ref()
            .or_else(|| fallback.and_then(|f| f.client_cert_chain_pem.as_ref()));
        let key_file = cfg
            .client_private_key_file
            .as_ref()
            .or_else(|| fallback.and_then(|f| f.client_private_key_file.as_ref()));
        if let (Some(cert), Some(key_path)) = (cert_pem, key_file) {
            let key_pem = std::fs::read_to_string(key_path)
                .map_err(|e| format!("reading P2P client key {key_path}: {e}"))?;
            client_tls =
                client_tls.identity(tonic::transport::Identity::from_pem(cert.clone(), key_pem));
        }
        endpoint = endpoint.tls_config(client_tls).map_err(|e| e.to_string())?;
    }
    endpoint.connect().await.map_err(|e| format!("{url}: {e}"))
}

/// The `BftOrderingService` of a Rust node.
pub struct P2pService {
    pub authentication: Arc<Authentication>,
    /// The sequencers of the synchronizer and their keys (the signatures of their messages are checked against these).
    pub registry: Arc<Registry>,
    /// This node: `SEQ::name::namespace`, the key it answers an authentication challenge with and the synchronizer it is a peer of.
    pub member: String,
    pub authentication_key: Arc<canton_participant::topology_wire::Ed25519Key>,
    pub physical_synchronizer_id: String,
    /// The consensus, when the node takes part in it.
    pub consensus: Option<Arc<Consensus>>,
    /// The admin API the sequencers' keys and nodes are read from.
    pub admin_url: String,
    /// Default client TLS credentials (for `token_at` back-authentication over TLS/mTLS).
    pub default_client_tls: Option<BftClientTls>,
    /// Optional peer manager for tracking authenticated incoming connections.
    pub peer_manager: Option<Arc<BftPeerManager>>,
    /// Shutdown signal so inbound reader tasks drop server response streams cleanly.
    pub shutdown: Option<Arc<tokio::sync::Notify>>,
}

/// Checks the signature of a `SignedMessage` a peer sent, the way the official node signs it (`CryptoProvider.hashForMessage`): Ed25519 over the multi-hash of
/// `Hash.build(<purpose of the kind>).addString(from).addByteString(<the message bytes as sent>)`, by one of the sender's keys in the topology.
pub fn verify_signed_message(
    registry: &Registry,
    kind: canton_bft_orderer::wire::AuthenticatedMessageType,
    signed: &canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::SignedMessage,
) -> Result<(), String> {
    let registered = registry
        .get(&signed.from)
        .ok_or_else(|| format!("{} is not a known sequencer", signed.from))?;
    let signature = signed.signature.as_ref().ok_or("no signature")?;
    let key = registered
        .signing_keys
        .iter()
        .find(|k| k.id == signature.signed_by)
        .ok_or_else(|| format!("{} is not a key of {}", signature.signed_by, signed.from))?;
    if std::env::var_os("BFT_P2P_DUMP").is_some() {
        crate::diag::diag_eprintln!(
            "DUMP kind={kind:?} from={} message={} signature={} key={}",
            signed.from,
            crate::persistence::hex(&signed.message),
            crate::persistence::hex(&signature.signature),
            crate::persistence::hex(&key.key)
        );
    }
    canton_bft_orderer::wire::verify_message_signature(
        kind,
        &signed.from,
        &signed.message,
        signature,
        key,
    )
}

type Messages = Pin<Box<dyn Stream<Item = Result<BftOrderingMessage, Status>> + Send>>;

impl P2pService {
    /// Authenticates this node to the peer that connected, at the endpoint the peer named in its call (`cantonbft-p2p-endpoint-bin`): the peer's own
    /// authentication service gives this node a token, which goes into the headers of the answer. A peer checks that token against its own service before it
    /// accepts the stream (`P2PCheckAuthenticationGrpcClientInterceptor`).
    async fn token_at(&self, endpoint: &PeerEndpoint) -> Result<Vec<u8>, Status> {
        use canton_participant::sequencer_connect::AuthKey;
        use canton_proto::com::digitalasset::canton::sequencer::api::v30::{
            sequencer_authentication::{AuthenticateRequest, ChallengeRequest},
            sequencer_authentication_service_client::SequencerAuthenticationServiceClient,
        };
        let cfg = BftPeerConfig::from_proto(endpoint).map_err(Status::invalid_argument)?;
        let channel = connect_p2p_channel(
            &cfg.address,
            cfg.port,
            cfg.tls.as_ref(),
            self.default_client_tls.as_ref(),
        )
        .await
        .map_err(Status::unavailable)?;
        let mut client = SequencerAuthenticationServiceClient::new(channel);
        let challenge = client
            .challenge(ChallengeRequest {
                member: self.member.clone(),
                member_protocol_versions: vec![crate::PROTOCOL_VERSION],
                client_version: concat!("canton-rs-", env!("CARGO_PKG_VERSION")).into(),
            })
            .await?
            .into_inner();
        let hash = AuthKey::challenge_hash(&challenge.nonce, &self.physical_synchronizer_id)
            .map_err(|e| Status::internal(format!("the challenge hash: {e:?}")))?;
        let signature = self.authentication_key.sign_bytes(&hash);
        let answer = client
            .authenticate(AuthenticateRequest {
                member: self.member.clone(),
                signature: Some(signature),
                nonce: challenge.nonce,
            })
            .await?
            .into_inner();
        Ok(answer.token)
    }
}

#[tonic::async_trait]
impl BftOrderingService for P2pService {
    type ReceiveStream = Messages;

    async fn receive(
        &self,
        request: Request<Streaming<BftOrderingMessage>>,
    ) -> Result<Response<Self::ReceiveStream>, Status> {
        let member = self.authentication.authenticated_member(&request)?;
        if !member.starts_with("SEQ::") {
            return Err(Status::permission_denied(
                "P2P connections require a sequencer identity",
            ));
        }
        // the peer says where its authentication service is: no endpoint, no stream (the official node answers `INTERNAL`)
        let endpoint = request
            .metadata()
            .get_bin("cantonbft-p2p-endpoint-bin")
            .and_then(|v| v.to_bytes().ok())
            .and_then(|b| <PeerEndpoint as prost::Message>::decode(b.as_ref()).ok())
            .ok_or_else(|| Status::internal("No authenticated endpoint header found"))?;
        crate::diag::diag_eprintln!(
            "P2P peer {member} authenticated; its endpoint is {}:{}",
            endpoint.address,
            endpoint.port
        );
        let token = match self.token_at(&endpoint).await {
            Ok(t) => t,
            Err(e) => {
                crate::diag::diag_eprintln!(
                    "P2P this node could not authenticate to {member}: {}",
                    e.message()
                );
                return Err(e);
            }
        };
        crate::diag::diag_eprintln!("P2P this node authenticated to {member}");
        if let Some(pm) = &self.peer_manager {
            pm.record_incoming(member.clone());
        }
        // what the peer reads: the same headers as a client's call; holding `resp_tx` in the inbound reader task
        // guarantees the outbound stream closes immediately once the peer disconnects (`U-51`).
        let mut inbound = request.into_inner();
        let (resp_tx, resp_rx) =
            tokio::sync::mpsc::channel::<Result<BftOrderingMessage, Status>>(1);
        let registry = std::sync::Arc::clone(&self.registry);
        let consensus = self.consensus.clone();
        let admin_url = self.admin_url.clone();
        let physical = self.physical_synchronizer_id.clone();
        let peer_manager = self.peer_manager.clone();
        let peer_member = member.clone();
        let srv_shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let _keep_open = resp_tx;
            let wait_stop = async {
                match &srv_shutdown {
                    Some(s) => s.notified().await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::pin!(wait_stop);
            loop {
                tokio::select! {
                    msg = inbound.message() => match msg {
                        Ok(Some(message)) => {
                            dispatch(&registry, &consensus, &admin_url, &physical, message).await;
                        }
                        _ => break,
                    },
                    _ = &mut wait_stop => break,
                }
            }
            if let Some(pm) = &peer_manager {
                pm.remove_incoming(&peer_member);
            }
            crate::diag::diag_eprintln!("P2P the stream of the peer ended");
        });
        let mut response = Response::new(Box::pin(tokio_stream::wrappers::ReceiverStream::new(
            resp_rx,
        )) as Messages);
        let metadata = response.metadata_mut();
        for (key, value) in [
            ("synchronizerid", self.physical_synchronizer_id.as_str()),
            ("memberid", self.member.as_str()),
        ] {
            if let Ok(v) = value.parse() {
                metadata.insert(key, v);
            }
        }
        metadata.insert_bin(
            "authtoken-bin",
            tonic::metadata::MetadataValue::from_bytes(&token),
        );
        Ok(response)
    }
}

/// Prints the availability acks of a `PrePrepare` with proofs (what a golden test of the ack hash is made from).
fn dump_acks(registry: &Registry, signed: &SignedMessage) {
    use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
        consensus_message::Message, ConsensusMessage,
    };
    use prost::Message as _;
    let Some(pp) = canton_bft_orderer::wire::unwrap_versioned(&signed.message, 30)
        .ok()
        .and_then(|i| ConsensusMessage::decode(i.as_slice()).ok())
    else {
        return;
    };
    let Some(Message::PrePrepare(body)) = pp.message else {
        return;
    };
    for proof in body.block.map(|b| b.proofs).unwrap_or_default() {
        for ack in &proof.acks {
            let Some(sig) = ack.signature.as_ref() else {
                continue;
            };
            let key = registry.get(&ack.from).and_then(|r| {
                r.signing_keys
                    .iter()
                    .find(|k| k.id == sig.signed_by)
                    .cloned()
            });
            crate::diag::diag_eprintln!(
                "ACKDUMP batch={} epoch={} from={} signature={} key={}",
                crate::persistence::hex(&proof.batch_id),
                proof.epoch_number,
                ack.from,
                crate::persistence::hex(&sig.signature),
                key.map(|k| crate::persistence::hex(&k.key))
                    .unwrap_or_default()
            );
        }
    }
}

/// What a node does with a message a peer sent it, on a stream the peer opened or on the answer side of one this node opened.
async fn dispatch(
    registry: &Registry,
    consensus: &Option<Arc<Consensus>>,
    admin_url: &str,
    physical: &str,
    message: BftOrderingMessage,
) {
    use canton_bft_orderer::wire::AuthenticatedMessageType as Kind;
    use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
        bft_ordering_message_body::Message, retransmission_message,
    };
    let sent_by = message.sent_by.clone();
    match message.body.and_then(|b| b.message) {
        Some(Message::ConnectionOpened(_)) => {
            crate::diag::diag_eprintln!("P2P {sent_by}: connection opened")
        }
        Some(Message::RetransmissionMessage(m)) => match m.message {
            Some(retransmission_message::Message::RetransmissionRequest(signed)) => {
                if let (Some(c), Ok(())) = (
                    &consensus,
                    verify_signed_message(registry, Kind::BftSignedRetransmissionMessage, &signed),
                ) {
                    if !c.is_started() && !admin_url.is_empty() {
                        if let Ok(r) = sequencer_registry(admin_url, physical).await {
                            c.set_nodes(r.members());
                        }
                    }
                    c.on_status(&signed);
                }
                crate::diag::diag_eprintln!(
                    "P2P {sent_by}: epoch status, signature {}",
                    match verify_signed_message(
                        registry,
                        Kind::BftSignedRetransmissionMessage,
                        &signed
                    ) {
                        Ok(()) => "VERIFIED".to_string(),
                        Err(e) => format!("NOT verified: {e}"),
                    }
                );
            }
            Some(retransmission_message::Message::RetransmissionResponse(response)) => {
                // [CANTON-NOTE: RETRANSMISSION] A node that answers a status sends the commit certificates (the pre-prepare and the commits) of the blocks
                // the requester lacks. A running node takes a certificate only whole, after the consensus node verified every signature in it and that its
                // commits are a strong quorum of distinct nodes for the pre-prepare's hash (`RetransmissionMessageValidator`); one that has not started
                // checks each message's signature here and takes it as a single consensus message.
                let mut taken = 0usize;
                for certificate in response.commit_certificates {
                    // a node that is running orders the block from the certificate (it may be of a later view); one that has not started learns its epoch from
                    // the messages in it
                    if let Some(c) = consensus.as_ref().filter(|c| c.is_started()) {
                        match c.on_commit_certificate(certificate) {
                            Ok(()) => taken += 1,
                            Err(e) => crate::diag::diag_eprintln!(
                                "P2P {sent_by}: a retransmitted commit certificate NOT taken: {e}"
                            ),
                        }
                        continue;
                    }
                    let messages = certificate
                        .pre_prepare
                        .into_iter()
                        .chain(certificate.commits);
                    for signed in messages {
                        if verify_signed_message(registry, Kind::BftSignedConsensusMessage, &signed)
                            .is_err()
                        {
                            continue;
                        }
                        if let Some(c) = &consensus {
                            if !c.is_started() && !admin_url.is_empty() {
                                if let Ok(r) = sequencer_registry(admin_url, physical).await {
                                    c.set_nodes(r.members());
                                }
                            }
                            if let Err(err) = c.on_message(signed) {
                                crate::diag::diag_eprintln!(
                                    "P2P {sent_by}: consensus halted on poisoned state during certificate retransmission: {err}"
                                );
                                break;
                            }
                            taken += 1;
                        }
                    }
                }
                crate::diag::diag_eprintln!(
                    "P2P {sent_by}: a retransmission response, {taken} consensus messages taken"
                );
            }
            None => {}
        },
        Some(Message::ConsensusMessage(signed)) => {
            if std::env::var_os("BFT_ACK_DUMP").is_some() {
                dump_acks(registry, &signed);
            }
            match verify_signed_message(registry, Kind::BftSignedConsensusMessage, &signed) {
                Ok(()) => {
                    if let Some(c) = &consensus {
                        if !c.is_started() && !admin_url.is_empty() {
                            // the nodes of the synchronizer now (this node is among them once it has been onboarded)
                            if let Ok(r) = sequencer_registry(admin_url, physical).await {
                                c.set_nodes(r.members());
                            }
                        }
                        if let Err(err) = c.on_message(signed) {
                            crate::diag::diag_eprintln!(
                                "P2P {sent_by}: consensus halted on poisoned state: {err}"
                            );
                        }
                    }
                }
                Err(e) => {
                    crate::diag::diag_eprintln!(
                        "P2P {sent_by}: consensus message NOT verified: {e}"
                    )
                }
            }
        }
        Some(Message::StateTransferMessage(signed)) => {
            use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::{v30, v31};
            use prost::Message as _;
            // the answer to a block transfer request: commit certificates of the blocks of an epoch (version 31: a list; version 30: one certificate at a time)
            let mut certificates: Vec<v30::CommitCertificate> = Vec::new();
            if let Ok(inner) = canton_bft_orderer::wire::unwrap_versioned(&signed.message, 31) {
                if let Ok(v31::StateTransferMessage {
                    message: Some(v31::state_transfer_message::Message::BlockResponse(r)),
                }) = v31::StateTransferMessage::decode(inner.as_slice())
                {
                    certificates = r.commit_certificates;
                }
            } else if let Ok(inner) =
                canton_bft_orderer::wire::unwrap_versioned(&signed.message, 30)
            {
                if let Ok(v30::StateTransferMessage {
                    message: Some(v30::state_transfer_message::Message::BlockResponse(r)),
                }) = v30::StateTransferMessage::decode(inner.as_slice())
                {
                    certificates.extend(r.commit_certificate);
                }
            }
            crate::diag::diag_eprintln!(
                "P2P {sent_by}: a state transfer message, {} commit certificate(s)",
                certificates.len()
            );
            if let Some(c) = &consensus {
                let outer_verified = verify_signed_message(
                    registry,
                    canton_bft_orderer::wire::AuthenticatedMessageType::BftSignedStateTransferMessage,
                    &signed,
                )
                .is_ok();
                if certificates.is_empty() {
                    if outer_verified {
                        if let Err(err) = c.on_empty_transferred_epoch() {
                            crate::diag::diag_eprintln!(
                                "P2P {sent_by}: state transfer halted on poisoned state: {err}"
                            );
                        }
                    }
                } else if let Err(err) = c.on_block_transfer_response(&sent_by, certificates) {
                    crate::diag::diag_eprintln!(
                        "P2P {sent_by}: block transfer halted on poisoned state: {err}"
                    );
                }
            }
        }
        Some(Message::AvailabilityMessage(signed)) => {
            use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{availability_message, AvailabilityMessage};
            use prost::Message as _;
            let verified =
                verify_signed_message(registry, Kind::BftSignedAvailabilityMessage, &signed);
            crate::diag::diag_eprintln!(
                "P2P {sent_by}: availability message, signature {}",
                match &verified {
                    Ok(()) => "VERIFIED".to_string(),
                    Err(e) => format!("NOT verified: {e}"),
                }
            );
            // [CANTON-NOTE: AVAILABILITY] A peer asks this node to store a batch: the node stores it and acks (the weak quorum of acks a proposal needs counts it).
            // (`BFT_NO_STORE_ACK` turns the answer off: a way to tell what the acks change)
            if verified.is_ok() && std::env::var_os("BFT_NO_STORE_ACK").is_none() {
                if let Some(c) = &consensus {
                    match canton_bft_orderer::wire::unwrap_versioned(&signed.message, 30)
                        .ok()
                        .and_then(|i| AvailabilityMessage::decode(i.as_slice()).ok())
                        .and_then(|m| m.message)
                    {
                        Some(availability_message::Message::StoreRequest(request)) => {
                            if let Err(err) = c.on_store_request(&signed.from, request) {
                                crate::diag::diag_eprintln!(
                                    "P2P {sent_by}: store_request halted on poisoned state: {err}"
                                );
                            }
                        }
                        Some(availability_message::Message::BatchRequest(request)) => {
                            c.on_batch_request(&signed.from, request)
                        }
                        Some(availability_message::Message::BatchResponse(response)) => {
                            if let Err(err) = c.on_batch_response(response) {
                                crate::diag::diag_eprintln!(
                                    "P2P {sent_by}: batch_response halted on poisoned state: {err}"
                                );
                            }
                        }
                        Some(availability_message::Message::StoreResponse(response)) => {
                            if let Err(err) = c.on_store_response(&signed.from, response) {
                                crate::diag::diag_eprintln!(
                                    "P2P {sent_by}: store_response halted on poisoned state: {err}"
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        None => crate::diag::diag_eprintln!("P2P {sent_by}: no body"),
    }
}

/// Serves the p2p endpoint on `bind` until the process stops: the authentication service (for the sequencers in `registry`) and the BFT ordering service.
pub async fn serve(
    bind: std::net::SocketAddr,
    physical_synchronizer_id: String,
    registry: Arc<Registry>,
    identity: &crate::sequencer_identity::SequencerIdentity,
    peers: Vec<String>,
    own_endpoint: (String, u32),
    consensus: Option<Arc<Consensus>>,
    admin_url: String,
) -> Result<(), String> {
    serve_with_shutdown(
        bind,
        physical_synchronizer_id,
        registry,
        identity,
        peers,
        own_endpoint,
        consensus,
        admin_url,
        None,
    )
    .await
}

/// Builds a [`BftPeerManager`] before starting the P2P and Admin listeners so both share live peer state.
#[allow(clippy::too_many_arguments, reason = "BFT P2P peer manager setup")]
pub fn build_peer_manager(
    physical_synchronizer_id: String,
    registry: Arc<Registry>,
    identity: &crate::sequencer_identity::SequencerIdentity,
    own_endpoint: (String, u32, Option<BftClientTls>),
    consensus: Option<Arc<Consensus>>,
    admin_url: String,
    ord_store: Option<Arc<crate::ord_store::OrdStore>>,
    shutdown: Option<Arc<tokio::sync::Notify>>,
) -> Arc<BftPeerManager> {
    let authentication_key = Arc::new(canton_participant::topology_wire::Ed25519Key::from_seed(
        identity.authentication_key.seed(),
    ));
    let outgoing = Arc::new(Outgoing {
        member: identity.member(),
        authentication_key,
        physical_synchronizer_id,
        own_address: own_endpoint.0,
        own_port: own_endpoint.1,
        own_tls: own_endpoint.2,
        registry,
        consensus: consensus.clone(),
        admin_url,
    });
    BftPeerManager::new(outgoing, consensus, ord_store, shutdown)
}

/// Optional TLS and peer-manager configuration for [`serve_with_options`].
#[derive(Clone, Default)]
pub struct BftServeOptions {
    pub peers: Vec<BftPeerConfig>,
    pub server_tls: Option<BftServerTls>,
    pub default_client_tls: Option<BftClientTls>,
    pub peer_manager: Option<Arc<BftPeerManager>>,
    pub ord_store: Option<Arc<crate::ord_store::OrdStore>>,
    pub shutdown: Option<Arc<tokio::sync::Notify>>,
}

/// Like [`serve`], stopping cleanly when `shutdown` is notified.
#[allow(
    clippy::too_many_arguments,
    reason = "public compatibility signature for existing BFT callers"
)]
pub async fn serve_with_shutdown(
    bind: std::net::SocketAddr,
    physical_synchronizer_id: String,
    registry: Arc<Registry>,
    identity: &crate::sequencer_identity::SequencerIdentity,
    peers: Vec<String>,
    own_endpoint: (String, u32),
    consensus: Option<Arc<Consensus>>,
    admin_url: String,
    shutdown: Option<Arc<tokio::sync::Notify>>,
) -> Result<(), String> {
    let parsed_peers = peers
        .iter()
        .map(|u| BftPeerConfig::from_url(u))
        .collect::<Result<Vec<_>, _>>()?;
    serve_with_options(
        bind,
        physical_synchronizer_id,
        registry,
        identity,
        (own_endpoint.0, own_endpoint.1, None),
        consensus,
        admin_url,
        BftServeOptions {
            peers: parsed_peers,
            shutdown,
            ..Default::default()
        },
    )
    .await
}

/// Serves the BFT P2P endpoint with full TLS/mTLS, dynamic [`BftPeerManager`], and graceful shutdown.
#[allow(clippy::too_many_arguments, reason = "BFT P2P server options wrapper")]
pub async fn serve_with_options(
    bind: std::net::SocketAddr,
    physical_synchronizer_id: String,
    registry: Arc<Registry>,
    identity: &crate::sequencer_identity::SequencerIdentity,
    own_endpoint: (String, u32, Option<BftClientTls>),
    consensus: Option<Arc<Consensus>>,
    admin_url: String,
    options: BftServeOptions,
) -> Result<(), String> {
    use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_authentication_service_server::SequencerAuthenticationServiceServer;
    use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::bft_ordering_service_server::BftOrderingServiceServer;
    let members = registry.members();
    let authentication = Arc::new(Authentication::new(
        physical_synchronizer_id.clone(),
        std::sync::Arc::clone(&registry),
    ));
    let authentication_key = Arc::new(canton_participant::topology_wire::Ed25519Key::from_seed(
        identity.authentication_key.seed(),
    ));
    crate::diag::diag_eprintln!(
        "P2P endpoint on {bind}: {} sequencer(s) known ({})",
        members.len(),
        members.join(", ")
    );
    let peer_manager = options.peer_manager.unwrap_or_else(|| {
        build_peer_manager(
            physical_synchronizer_id.clone(),
            Arc::clone(&registry),
            identity,
            own_endpoint,
            consensus.clone(),
            admin_url.clone(),
            options.ord_store.clone(),
            options.shutdown.clone(),
        )
    });
    if let (Some(c), false) = (&consensus, admin_url.is_empty()) {
        let c = std::sync::Arc::clone(c);
        let stop = options.shutdown.clone();
        let admin_url = admin_url.clone();
        let physical = physical_synchronizer_id.clone();
        tokio::spawn(async move {
            loop {
                match &stop {
                    Some(stop) => tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                        _ = stop.notified() => break,
                    },
                    None => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
                }
                if !c.is_started() {
                    continue;
                }
                match sequencer_registry(&admin_url, &physical).await {
                    Ok(sequencers) => c.refresh_topology(&sequencers),
                    Err(e) => crate::diag::diag_eprintln!("CONSENSUS topology not refreshed: {e}"),
                }
            }
        });
    }
    if let Some(c) = &consensus {
        let c = std::sync::Arc::clone(c);
        let tick_stop = options.shutdown.clone();
        tokio::spawn(async move {
            loop {
                match &tick_stop {
                    Some(stop) => tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
                        _ = stop.notified() => break,
                    },
                    None => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                }
                if let Err(err) = c.tick() {
                    crate::diag::diag_eprintln!(
                        "BFT_P2P halting tick loop on poisoned state: {err}"
                    );
                    break;
                }
            }
        });
    }
    let initial_delay = if admin_url.is_empty() {
        std::time::Duration::from_millis(300)
    } else {
        std::time::Duration::from_secs(2)
    };
    peer_manager.spawn_initial(options.peers, initial_delay);
    // `P2PServerConfig`: Canton's `ServerConfig` defaults (10 MiB messages, keepalive)
    let mut server = crate::transport::server();
    if let Some(tls) = options.server_tls {
        let mut tls_config = tonic::transport::ServerTlsConfig::new().identity(
            tonic::transport::Identity::from_pem(tls.cert_pem, tls.key_pem),
        );
        if let Some(ca) = tls.client_ca_pem {
            tls_config = tls_config.client_ca_root(tonic::transport::Certificate::from_pem(ca));
        }
        server = server.tls_config(tls_config).map_err(|e| e.to_string())?;
    }
    let router = server
        .add_service(SequencerAuthenticationServiceServer::from_arc(
            std::sync::Arc::clone(&authentication),
        ))
        .add_service(
            BftOrderingServiceServer::new(P2pService {
                authentication,
                registry,
                member: identity.member(),
                authentication_key,
                physical_synchronizer_id,
                consensus,
                admin_url,
                default_client_tls: options.default_client_tls,
                peer_manager: Some(peer_manager),
                shutdown: options.shutdown.clone(),
            })
            .max_decoding_message_size(crate::transport::MAX_INBOUND_MESSAGE_SIZE),
        );
    match options.shutdown {
        Some(stop) => {
            let grace = Arc::new(tokio::sync::Notify::new());
            let force = Arc::new(tokio::sync::Notify::new());
            let g_sig = Arc::clone(&grace);
            let f_sig = Arc::clone(&force);
            tokio::spawn(async move {
                stop.notified().await;
                g_sig.notify_waiters();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                f_sig.notify_waiters();
            });
            let serving = router.serve_with_shutdown(bind, async move { grace.notified().await });
            tokio::select! {
                result = serving => result.map_err(|e| e.to_string()),
                _ = force.notified() => Ok(()),
            }
        }
        None => router.serve(bind).await.map_err(|e| e.to_string()),
    }
}

/// What this node tells a peer about itself when it connects to it: the address the peer reaches this node's own endpoint at, to authenticate back (the
/// endpoint header, `P2PAddEndpointHeaderGrpcClientInterceptor`).
pub struct Outgoing {
    pub member: String,
    pub authentication_key: Arc<canton_participant::topology_wire::Ed25519Key>,
    pub physical_synchronizer_id: String,
    /// This node's endpoint as the peers reach it.
    pub own_address: String,
    pub own_port: u32,
    /// Security advertised in `cantonbft-p2p-endpoint-bin` for back-authentication.
    pub own_tls: Option<BftClientTls>,
    /// What the answers of the peers are dispatched with (they send on the answer side of the streams this node opens as well).
    pub registry: Arc<Registry>,
    pub consensus: Option<Arc<Consensus>>,
    pub admin_url: String,
}

impl Outgoing {
    /// Connects to a plaintext `http://` URL (legacy convenience wrapper around [`Self::connect_endpoint`]).
    pub async fn connect(
        &self,
        url: &str,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<BftOrderingMessage>,
            tokio::sync::oneshot::Receiver<()>,
        ),
        String,
    > {
        let ep = BftPeerConfig::from_url(url)?;
        let (tx, _peer, closed) = self.connect_endpoint(&ep).await?;
        Ok((tx, closed))
    }

    /// Connects to a plain-text or TLS/mTLS peer endpoint, authenticates bidirectionally, and keeps the ordering stream open
    /// until either side closes (`U-51` drops outbound wire stream immediately on inbound EOF).
    pub async fn connect_endpoint(
        &self,
        endpoint_cfg: &BftPeerConfig,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<BftOrderingMessage>,
            Option<String>,
            tokio::sync::oneshot::Receiver<()>,
        ),
        String,
    > {
        self.connect_endpoint_with_cancel(endpoint_cfg, None).await
    }

    /// Like [`Self::connect_endpoint`], closing both outbound and inbound stream tasks immediately when `cancel` is notified.
    pub async fn connect_endpoint_with_cancel(
        &self,
        endpoint_cfg: &BftPeerConfig,
        cancel: Option<Arc<tokio::sync::Notify>>,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<BftOrderingMessage>,
            Option<String>,
            tokio::sync::oneshot::Receiver<()>,
        ),
        String,
    > {
        use canton_participant::sequencer_connect::AuthKey;
        use canton_proto::com::digitalasset::canton::sequencer::api::v30::{
            sequencer_authentication::{AuthenticateRequest, ChallengeRequest},
            sequencer_authentication_service_client::SequencerAuthenticationServiceClient,
        };
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            bft_ordering_message_body::Message, bft_ordering_service_client::BftOrderingServiceClient,
            BftOrderingMessageBody, ConnectionOpened,
        };
        let url = endpoint_cfg.url();
        let channel = connect_p2p_channel(
            &endpoint_cfg.address,
            endpoint_cfg.port,
            endpoint_cfg.tls.as_ref(),
            self.own_tls.as_ref(),
        )
        .await?;
        let mut auth = SequencerAuthenticationServiceClient::new(channel.clone());
        let challenge = auth
            .challenge(ChallengeRequest {
                member: self.member.clone(),
                member_protocol_versions: vec![crate::PROTOCOL_VERSION],
                client_version: concat!("canton-rs-", env!("CARGO_PKG_VERSION")).into(),
            })
            .await
            .map_err(|e| format!("challenge at {url}: {}", e.message()))?
            .into_inner();
        let hash = AuthKey::challenge_hash(&challenge.nonce, &self.physical_synchronizer_id)
            .map_err(|e| format!("the challenge hash at {url}: {e:?}"))?;
        let signature = self.authentication_key.sign_bytes(&hash);
        let token = auth
            .authenticate(AuthenticateRequest {
                member: self.member.clone(),
                signature: Some(signature),
                nonce: challenge.nonce,
            })
            .await
            .map_err(|e| format!("authenticate at {url}: {}", e.message()))?
            .into_inner()
            .token;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<BftOrderingMessage>(1024);
        let (wire_tx, wire_rx) = tokio::sync::mpsc::channel::<BftOrderingMessage>(1024);
        let stop_outbound = Arc::new(tokio::sync::Notify::new());
        let opened = BftOrderingMessage {
            trace_context: String::new(),
            body: Some(BftOrderingMessageBody {
                message: Some(Message::ConnectionOpened(ConnectionOpened {})),
            }),
            sent_by: self.member.clone(),
            sent_at: None,
        };
        wire_tx.send(opened).await.map_err(|e| e.to_string())?;
        let stop_watch = Arc::clone(&stop_outbound);
        let bridge_cancel = cancel.clone();
        tokio::spawn(async move {
            let wait_ext = async {
                match &bridge_cancel {
                    Some(c) => c.notified().await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::pin!(wait_ext);
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        let Some(m) = msg else { break };
                        if wire_tx.send(m).await.is_err() {
                            break;
                        }
                    }
                    _ = stop_watch.notified() => break,
                    _ = &mut wait_ext => break,
                }
            }
        });
        let mut request = Request::new(tokio_stream::wrappers::ReceiverStream::new(wire_rx));
        let metadata = request.metadata_mut();
        for (key, value) in [
            ("synchronizerid", self.physical_synchronizer_id.as_str()),
            ("memberid", self.member.as_str()),
        ] {
            if let Ok(v) = value.parse() {
                metadata.insert(key, v);
            }
        }
        metadata.insert_bin(
            "authtoken-bin",
            tonic::metadata::MetadataValue::from_bytes(&token),
        );
        let advertised = BftPeerConfig {
            address: self.own_address.clone(),
            port: self.own_port,
            tls: self.own_tls.clone(),
        };
        let endpoint = advertised.to_proto(None);
        metadata.insert_bin(
            "cantonbft-p2p-endpoint-bin",
            tonic::metadata::MetadataValue::from_bytes(&prost::Message::encode_to_vec(&endpoint)),
        );
        let mut client = BftOrderingServiceClient::new(channel);
        let response = client.receive(request).await.map_err(|e| {
            stop_outbound.notify_waiters();
            format!("opening the stream at {url}: {}", e.message())
        })?;
        crate::diag::diag_eprintln!("P2P connected to {url}: the stream is open");
        // who answers on this stream: the member id in its headers; replies to that peer go through the stream this node opened
        let peer_member = response
            .metadata()
            .get("memberid")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if let (Some(member), Some(c)) = (&peer_member, &self.consensus) {
            c.register_peer(member, tx.clone());
        }
        let mut inbound = response.into_inner();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let registry = std::sync::Arc::clone(&self.registry);
        let consensus = self.consensus.clone();
        let admin_url = self.admin_url.clone();
        let physical = self.physical_synchronizer_id.clone();
        tokio::spawn(async move {
            let wait_ext = async {
                match &cancel {
                    Some(c) => c.notified().await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::pin!(wait_ext);
            loop {
                tokio::select! {
                    msg = inbound.message() => match msg {
                        Ok(Some(m)) => {
                            dispatch(&registry, &consensus, &admin_url, &physical, m).await;
                        }
                        _ => break,
                    },
                    _ = &mut wait_ext => break,
                }
            }
            stop_outbound.notify_waiters();
            if let Some(c) = &consensus {
                c.prune_closed_senders();
            }
            crate::diag::diag_eprintln!("P2P the stream of {url} ended");
            let _ = closed_tx.send(());
        });
        Ok((tx, peer_member, closed_rx))
    }
}
