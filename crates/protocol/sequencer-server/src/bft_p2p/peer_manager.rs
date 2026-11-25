//! TLS configuration, dynamic BFT P2P peer endpoint management, and connection health tracking.

use std::sync::Arc;

use canton_proto::com::digitalasset::canton::sequencer::admin::v30::PeerEndpoint;

use super::transport::Outgoing;
use super::{lock_or_recover, Consensus};

/// Server-side TLS / mutual-TLS configuration for the BFT P2P gRPC listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BftServerTls {
    pub cert_pem: String,
    pub key_pem: String,
    pub client_ca_pem: Option<String>,
}

/// Client-side TLS / mutual-TLS settings used when dialing a BFT peer's P2P gRPC endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BftClientTls {
    pub custom_server_trust_pem: Option<Vec<u8>>,
    pub client_cert_chain_pem: Option<Vec<u8>>,
    pub client_private_key_file: Option<String>,
}

/// Configured BFT P2P peer endpoint (`http://` plain-text or `https://` TLS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BftPeerConfig {
    pub address: String,
    pub port: u32,
    pub tls: Option<BftClientTls>,
}

impl BftPeerConfig {
    pub fn from_url(url: &str) -> Result<Self, String> {
        let (is_tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!(
                "BFT peer URL must start with http:// or https://: {url}"
            ));
        };
        let host_port = rest.split('/').next().unwrap_or(rest);
        let (addr, port_str) = host_port
            .rsplit_once(':')
            .ok_or_else(|| format!("BFT peer URL missing port: {url}"))?;
        let port: u32 = port_str
            .parse()
            .map_err(|_| format!("invalid port in BFT peer URL: {url}"))?;
        Ok(Self {
            address: addr
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
            port,
            tls: is_tls.then(BftClientTls::default),
        })
    }

    pub fn url(&self) -> String {
        let scheme = if self.tls.is_some() { "https" } else { "http" };
        if self.address.contains(':') {
            format!("{scheme}://[{}]:{}", self.address, self.port)
        } else {
            format!("{scheme}://{}:{}", self.address, self.port)
        }
    }

    pub fn endpoint_id(&self) -> (String, u32, bool) {
        (self.address.clone(), self.port, self.tls.is_some())
    }

    pub fn to_proto_security(
        &self,
    ) -> canton_proto::com::digitalasset::canton::sequencer::admin::v30::peer_endpoint::Security
    {
        use canton_proto::com::digitalasset::canton::sequencer::admin::v30 as admin_v30;
        match &self.tls {
            None => {
                admin_v30::peer_endpoint::Security::PlainText(admin_v30::PlainTextPeerEndpoint {})
            }
            Some(t) => admin_v30::peer_endpoint::Security::Tls(admin_v30::TlsPeerEndpoint {
                custom_server_trust_certificate: t.custom_server_trust_pem.clone(),
                client_certificate: match (&t.client_cert_chain_pem, &t.client_private_key_file) {
                    (Some(chain), Some(key_file)) => Some(admin_v30::TlsClientCertificate {
                        certificate_chain: chain.clone(),
                        private_key_file: key_file.clone(),
                    }),
                    _ => None,
                },
            }),
        }
    }

    pub fn to_proto(&self, sequencer_id: Option<String>) -> PeerEndpoint {
        PeerEndpoint {
            address: self.address.clone(),
            port: self.port,
            security: Some(self.to_proto_security()),
            sequencer_id,
        }
    }

    pub fn from_proto(ep: &PeerEndpoint) -> Result<Self, String> {
        use canton_proto::com::digitalasset::canton::sequencer::admin::v30::peer_endpoint::Security;
        if ep.port == 0 || ep.port > u32::from(u16::MAX) {
            return Err(format!("invalid endpoint port: {}", ep.port));
        }
        if ep.address.is_empty() {
            return Err("endpoint address cannot be empty".into());
        }
        let tls = match &ep.security {
            Some(Security::PlainText(_)) | None => None,
            Some(Security::Tls(t)) => Some(BftClientTls {
                custom_server_trust_pem: t.custom_server_trust_certificate.clone(),
                client_cert_chain_pem: t
                    .client_certificate
                    .as_ref()
                    .map(|c| c.certificate_chain.clone()),
                client_private_key_file: t
                    .client_certificate
                    .as_ref()
                    .map(|c| c.private_key_file.clone()),
            }),
        };
        Ok(Self {
            address: ep.address.clone(),
            port: ep.port,
            tls,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerConnState {
    Disconnected,
    Unauthenticated,
    Authenticated(String),
}

#[derive(Clone, Debug)]
pub struct PeerEndpointStatusView {
    pub address: String,
    pub port: u32,
    pub tls: bool,
    pub is_outgoing: bool,
    pub state: PeerConnState,
    pub description: Option<String>,
}

struct ManagedPeer {
    config: BftPeerConfig,
    state: PeerConnState,
    description: Option<String>,
    shutdown: Arc<tokio::sync::Notify>,
}

/// Manages outgoing BFT P2P peer connections, health states, incoming authenticated peers, and optional `ord_p2p_endpoints` persistence.
pub struct BftPeerManager {
    outgoing: Arc<Outgoing>,
    consensus: Option<Arc<Consensus>>,
    ord_store: Option<Arc<crate::ord_store::OrdStore>>,
    endpoints: std::sync::Mutex<std::collections::BTreeMap<(String, u32, bool), ManagedPeer>>,
    incoming_members: std::sync::Mutex<std::collections::BTreeSet<String>>,
    global_shutdown: Option<Arc<tokio::sync::Notify>>,
}

impl BftPeerManager {
    pub fn new(
        outgoing: Arc<Outgoing>,
        consensus: Option<Arc<Consensus>>,
        ord_store: Option<Arc<crate::ord_store::OrdStore>>,
        global_shutdown: Option<Arc<tokio::sync::Notify>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            outgoing,
            consensus,
            ord_store,
            endpoints: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            incoming_members: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            global_shutdown,
        })
    }

    pub fn spawn_initial(
        self: &Arc<Self>,
        peers: Vec<BftPeerConfig>,
        initial_delay: std::time::Duration,
    ) {
        let mut initial = peers;
        if let Some(store) = &self.ord_store {
            if let Ok(saved) = store.list_endpoints() {
                for ep in saved {
                    if let Ok(port) = u32::try_from(ep.port) {
                        let tls = ep.transport_security.then_some(BftClientTls {
                            custom_server_trust_pem: ep.custom_server_trust_certificates,
                            client_cert_chain_pem: ep.client_certificate_chain,
                            client_private_key_file: ep.client_private_key_file,
                        });
                        initial.push(BftPeerConfig {
                            address: ep.address,
                            port,
                            tls,
                        });
                    }
                }
            }
        }
        for cfg in initial {
            let _ = self.add_endpoint_inner(cfg, initial_delay, false);
        }
    }

    pub fn add_endpoint(self: &Arc<Self>, config: BftPeerConfig) -> Result<bool, String> {
        self.add_endpoint_inner(config, std::time::Duration::ZERO, true)
    }

    fn add_endpoint_inner(
        self: &Arc<Self>,
        config: BftPeerConfig,
        initial_delay: std::time::Duration,
        persist: bool,
    ) -> Result<bool, String> {
        let key = config.endpoint_id();
        let peer_shutdown = Arc::new(tokio::sync::Notify::new());
        {
            let mut guard = self.endpoints.lock().map_err(|e| e.to_string())?;
            if guard.contains_key(&key) {
                return Ok(false);
            }
            if persist {
                if let Some(store) = &self.ord_store {
                    let _ = store.add_endpoint(crate::ord_store::OrdP2pEndpoint {
                        address: config.address.clone(),
                        port: config.port as i32,
                        transport_security: config.tls.is_some(),
                        custom_server_trust_certificates: config
                            .tls
                            .as_ref()
                            .and_then(|t| t.custom_server_trust_pem.clone()),
                        client_certificate_chain: config
                            .tls
                            .as_ref()
                            .and_then(|t| t.client_cert_chain_pem.clone()),
                        client_private_key_file: config
                            .tls
                            .as_ref()
                            .and_then(|t| t.client_private_key_file.clone()),
                        node_id: None,
                    });
                }
            }
            guard.insert(
                key.clone(),
                ManagedPeer {
                    config: config.clone(),
                    state: PeerConnState::Disconnected,
                    description: None,
                    shutdown: Arc::clone(&peer_shutdown),
                },
            );
        }
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            if !initial_delay.is_zero() {
                tokio::select! {
                    _ = tokio::time::sleep(initial_delay) => {}
                    _ = peer_shutdown.notified() => return,
                }
            }
            loop {
                let stop_requested =
                    !lock_or_recover(&mgr.endpoints, "endpoints").contains_key(&key);
                if stop_requested {
                    break;
                }
                if let Some(p) = lock_or_recover(&mgr.endpoints, "endpoints").get_mut(&key) {
                    p.state = PeerConnState::Unauthenticated;
                }
                let conn_cancel = Arc::new(tokio::sync::Notify::new());
                match mgr
                    .outgoing
                    .connect_endpoint_with_cancel(&config, Some(Arc::clone(&conn_cancel)))
                    .await
                {
                    Ok((sender, peer_member, closed)) => {
                        if let Some(c) = &mgr.consensus {
                            c.add_sender(sender.clone());
                        }
                        if let Some(p) = lock_or_recover(&mgr.endpoints, "endpoints").get_mut(&key)
                        {
                            p.state = match &peer_member {
                                Some(id) => PeerConnState::Authenticated(id.clone()),
                                None => PeerConnState::Unauthenticated,
                            };
                            p.description = None;
                        }
                        if let (Some(store), Some(id)) = (&mgr.ord_store, &peer_member) {
                            let _ = store.set_endpoint_node_id(
                                key.0.clone(),
                                key.1 as i32,
                                key.2,
                                Some(id.clone()),
                            );
                        }
                        let _keep = sender;
                        let wait_global = async {
                            match &mgr.global_shutdown {
                                Some(s) => s.notified().await,
                                None => std::future::pending::<()>().await,
                            }
                        };
                        tokio::select! {
                            _ = closed => {}
                            _ = peer_shutdown.notified() => {
                                conn_cancel.notify_waiters();
                                break;
                            }
                            _ = wait_global => {
                                conn_cancel.notify_waiters();
                                if let Some(c) = &mgr.consensus {
                                    c.clear_senders();
                                }
                                break;
                            }
                        }
                        if let Some(p) = lock_or_recover(&mgr.endpoints, "endpoints").get_mut(&key)
                        {
                            p.state = PeerConnState::Disconnected;
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {}
                            _ = peer_shutdown.notified() => break,
                        }
                    }
                    Err(e) => {
                        crate::diag::diag_eprintln!("P2P cannot connect to {}: {e}", config.url());
                        if let Some(p) = lock_or_recover(&mgr.endpoints, "endpoints").get_mut(&key)
                        {
                            p.state = PeerConnState::Disconnected;
                            p.description = Some(e);
                        }
                        let wait_global = async {
                            match &mgr.global_shutdown {
                                Some(s) => s.notified().await,
                                None => std::future::pending::<()>().await,
                            }
                        };
                        tokio::select! {
                            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                            _ = peer_shutdown.notified() => break,
                            _ = wait_global => break,
                        }
                    }
                }
            }
        });
        Ok(true)
    }

    pub fn remove_endpoint(&self, address: &str, port: u32, tls: bool) -> Result<bool, String> {
        let key = (address.to_string(), port, tls);
        let removed = {
            let mut guard = self.endpoints.lock().map_err(|e| e.to_string())?;
            guard.remove(&key)
        };
        if let Some(peer) = removed {
            peer.shutdown.notify_waiters();
            if let Some(store) = &self.ord_store {
                let _ = store.remove_endpoint(address.to_string(), port as i32, tls);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn list_configured_endpoints(&self) -> Vec<(BftPeerConfig, Option<String>)> {
        lock_or_recover(&self.endpoints, "endpoints")
            .values()
            .map(|p| {
                let id = match &p.state {
                    PeerConnState::Authenticated(m) => Some(m.clone()),
                    _ => None,
                };
                (p.config.clone(), id)
            })
            .collect()
    }

    pub fn network_status(
        &self,
        filter: Option<&[(String, u32, bool)]>,
    ) -> (Vec<PeerEndpointStatusView>, Vec<String>) {
        let mut known_auth = std::collections::BTreeSet::new();
        let mut views = Vec::new();
        {
            let guard = lock_or_recover(&self.endpoints, "endpoints");
            for (k, p) in &*guard {
                if let PeerConnState::Authenticated(m) = &p.state {
                    known_auth.insert(m.clone());
                }
                if filter.is_none_or(|f| f.is_empty() || f.contains(k)) {
                    views.push(PeerEndpointStatusView {
                        address: k.0.clone(),
                        port: k.1,
                        tls: k.2,
                        is_outgoing: true,
                        state: p.state.clone(),
                        description: p.description.clone(),
                    });
                }
            }
        }
        let incoming = if filter.is_none_or(|f| f.is_empty()) {
            lock_or_recover(&self.incoming_members, "incoming_members")
                .iter()
                .filter(|id| !known_auth.contains(*id))
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        (views, incoming)
    }

    pub fn authenticated_peers_count(&self) -> usize {
        let mut set = std::collections::BTreeSet::new();
        for p in lock_or_recover(&self.endpoints, "endpoints").values() {
            if let PeerConnState::Authenticated(m) = &p.state {
                set.insert(m.clone());
            }
        }
        for m in &*lock_or_recover(&self.incoming_members, "incoming_members") {
            set.insert(m.clone());
        }
        set.len()
    }

    pub fn record_incoming(&self, member: String) {
        lock_or_recover(&self.incoming_members, "incoming_members").insert(member);
    }

    pub fn remove_incoming(&self, member: &str) {
        lock_or_recover(&self.incoming_members, "incoming_members").remove(member);
    }
}
