//! The BFT part of a sequencer's `canton.conf`: `canton.sequencers.<name>.sequencer.config.initial-network` as the official nodes read it, turned into what the
//! `sequencer bft-peer` command needs (where to listen, how the peers reach this node, which peers to open streams to).
use std::collections::BTreeMap;
use std::path::PathBuf;

use canton_participant::hocon::Hocon;

/// PEM certificate/key file paths for the BFT P2P server listener (`server-endpoint.{tls,tls-config,external-tls-config}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BftServerTlsFiles {
    pub cert_chain_file: PathBuf,
    pub private_key_file: PathBuf,
    pub trust_collection_file: Option<PathBuf>,
}

/// Client TLS / mTLS file paths for outbound BFT P2P peer connections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BftClientTlsFiles {
    pub trust_collection_file: Option<PathBuf>,
    pub client_cert_file: Option<PathBuf>,
    pub client_key_file: Option<PathBuf>,
}

/// What `initial-network` (and peer ordering overrides) say about one BFT sequencer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BftNetwork {
    /// `server-endpoint.address` and `.port`: where this node listens for its peers.
    pub bind: String,
    /// `server-endpoint.external-address` and `.external-port` (the listen address and port when they are not given): where the peers reach this node.
    pub external: String,
    /// `peer-endpoints`, each as `http://address:port` or `https://address:port`.
    pub peers: Vec<String>,
    /// `sequencer.config.view-change-timeout-override` in milliseconds, when set.
    pub view_change_timeout_ms: Option<u64>,
    /// `sequencer.config.epoch-length`, when set.
    pub epoch_length: Option<i64>,
    /// Optional server TLS configuration for the P2P endpoint.
    pub server_tls: Option<BftServerTlsFiles>,
    /// Optional per-peer client TLS / mTLS settings keyed by `https://host:port`.
    pub peer_tls: BTreeMap<String, BftClientTlsFiles>,
}

impl BftNetwork {
    /// Shifts every port in `bind`, `external`, `peers`, and `peer_tls` keys by `+ offset`.
    pub fn with_port_offset(mut self, offset: u16) -> Result<Self, String> {
        if offset == 0 {
            return Ok(self);
        }
        let shift_host_port = |s: &str| -> Result<String, String> {
            let (host, port_s) = s
                .rsplit_once(':')
                .ok_or_else(|| format!("invalid endpoint {s}: expected host:port"))?;
            let port: u16 = port_s
                .parse()
                .map_err(|_| format!("invalid port in endpoint {s}"))?;
            let shifted = super::supervisor::doctor::shift_port(port, offset)
                .ok_or_else(|| format!("port {port} + offset {offset} overflows u16"))?;
            Ok(format!("{host}:{shifted}"))
        };
        let shift_url = |url: &str| -> Result<String, String> {
            if let Some(rest) = url.strip_prefix("https://") {
                Ok(format!("https://{}", shift_host_port(rest)?))
            } else if let Some(rest) = url.strip_prefix("http://") {
                Ok(format!("http://{}", shift_host_port(rest)?))
            } else {
                Err(format!("unexpected BFT peer URL {url}"))
            }
        };
        self.bind = shift_host_port(&self.bind)?;
        self.external = shift_host_port(&self.external)?;
        self.peers = self
            .peers
            .into_iter()
            .map(|url| shift_url(&url))
            .collect::<Result<Vec<_>, String>>()?;
        let old_tls = std::mem::take(&mut self.peer_tls);
        for (url, cfg) in old_tls {
            self.peer_tls.insert(shift_url(&url)?, cfg);
        }
        Ok(self)
    }
}

/// Parses a Canton/HOCON duration string (`"20 minutes"`, `"15 seconds"`, `"500 ms"`, `"1s"`) into positive milliseconds.
fn parse_duration_ms(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("duration {raw:?} is missing a unit (expected ms, s, m, h)"))?;
    let (num_str, unit_str) = (&s[..split], s[split..].trim());
    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("duration {raw:?} has invalid number"))?;
    if num == 0 {
        return Err(format!("duration {raw:?} must be positive"));
    }
    let mult: u64 = match unit_str.to_ascii_lowercase().as_str() {
        "ms" | "millis" | "millisecond" | "milliseconds" => 1,
        "s" | "sec" | "secs" | "second" | "seconds" => 1_000,
        "m" | "min" | "mins" | "minute" | "minutes" => 60_000,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000,
        other => return Err(format!("unknown duration unit {other:?} in {raw:?}")),
    };
    num.checked_mul(mult)
        .ok_or_else(|| format!("duration {raw:?} overflows u64 milliseconds"))
}

fn tls_leaf_supported(tail: &str) -> bool {
    matches!(
        tail,
        "enabled"
            | "cert-chain-file"
            | "cert-chain-file.pem-file"
            | "private-key-file"
            | "private-key-file.pem-file"
            | "trust-collection-file"
            | "trust-collection-file.pem-file"
            | "custom-server-trust-certificate"
            | "custom-server-trust-certificate.pem-file"
            | "minimum-server-protocol-version"
            | "client-auth.type"
            | "client-auth.admin-client.cert-chain-file"
            | "client-auth.admin-client.private-key-file"
            | "client-cert.certificate-chain-file"
            | "client-cert.certificate-chain-file.pem-file"
            | "client-cert.private-key-file"
            | "client-cert.private-key-file.pem-file"
            | "client-certificate.certificate-chain-file"
            | "client-certificate.certificate-chain-file.pem-file"
            | "client-certificate.private-key-file"
            | "client-certificate.private-key-file.pem-file"
    )
}

/// Whether `rest` (the path below `canton.sequencers.<name>.`) is a BFT setting read and applied by canton-rs.
pub fn bft_applied_leaf(rest: &str) -> bool {
    if matches!(
        rest,
        "sequencer.type"
            | "sequencer.config.view-change-timeout-override"
            | "sequencer.config.epoch-length"
            | "sequencer.config.initial-network.overwrite-stored-endpoints"
            | "sequencer.config.initial-network.server-endpoint.address"
            | "sequencer.config.initial-network.server-endpoint.port"
            | "sequencer.config.initial-network.server-endpoint.external-address"
            | "sequencer.config.initial-network.server-endpoint.external-port"
            | "sequencer.config.initial-network.peer-endpoints"
            | "sequencer.config.initial-network.endpoint-authentication"
            | "sequencer.config.initial-network.endpoint-authentication.enabled"
            | "sequencer.config.initial-network.endpoint-authentication.auth-token"
    ) {
        return true;
    }
    if let Some(server_tail) =
        rest.strip_prefix("sequencer.config.initial-network.server-endpoint.")
    {
        for prefix in ["tls.", "tls-config.", "external-tls-config."] {
            if let Some(inner) = server_tail.strip_prefix(prefix) {
                return tls_leaf_supported(inner);
            }
        }
    }
    if let Some(tail) = rest.strip_prefix("sequencer.config.initial-network.peer-endpoints[") {
        if tail.ends_with("].address") || tail.ends_with("].port") {
            return true;
        }
        if let Some((_, after)) = tail.split_once("].") {
            for prefix in ["tls-config.", "tls."] {
                if let Some(inner) = after.strip_prefix(prefix) {
                    return tls_leaf_supported(inner);
                }
            }
        }
    }
    false
}

fn hocon_pem_path(node: &Hocon, key: &str) -> Option<PathBuf> {
    let sub = node.get(key)?;
    sub.get("pem-file")
        .and_then(Hocon::text)
        .or_else(|| sub.text())
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
}

fn tls_block_flag(block: &Hocon) -> Option<bool> {
    block
        .get("enabled")
        .and_then(Hocon::text)
        .map(|s| s.eq_ignore_ascii_case("true"))
}

/// Reads the network of the sequencer `name` (including optional P2P server/client TLS settings).
pub fn bft_network(conf: &Hocon, name: &str) -> Result<BftNetwork, String> {
    let base = format!("canton.sequencers.{name}.sequencer");
    match conf.get(&format!("{base}.type")).and_then(Hocon::text) {
        Some(t) if t.eq_ignore_ascii_case("BFT") => {}
        other => return Err(format!("{base}.type is {other:?}, not BFT")),
    }
    let network = format!("{base}.config.initial-network");
    if let Some(enabled) = conf
        .get(&format!("{network}.endpoint-authentication.enabled"))
        .and_then(Hocon::text)
    {
        if enabled.eq_ignore_ascii_case("false") {
            return Err(format!(
                "{network}.endpoint-authentication.enabled = false is not supported"
            ));
        }
    }
    let view_change_timeout_ms =
        match conf.get(&format!("{base}.config.view-change-timeout-override")) {
            Some(v) => {
                let s = v.text().ok_or_else(|| {
                    format!("{base}.config.view-change-timeout-override must be a duration string")
                })?;
                Some(parse_duration_ms(&s)?)
            }
            None => None,
        };
    let epoch_length = match conf.get(&format!("{base}.config.epoch-length")) {
        Some(v) => {
            let s = v
                .text()
                .ok_or_else(|| format!("{base}.config.epoch-length must be an integer"))?;
            let n: i64 = s
                .trim()
                .parse()
                .map_err(|_| format!("{base}.config.epoch-length={s:?} is not an integer"))?;
            if n < 1 {
                return Err(format!("{base}.config.epoch-length must be >= 1, got {n}"));
            }
            Some(n)
        }
        None => None,
    };
    let server = conf
        .get(&format!("{network}.server-endpoint"))
        .ok_or_else(|| format!("{network}.server-endpoint is missing"))?;
    let text = |path: &str| server.get(path).and_then(Hocon::text);

    let mut server_tls = None;
    for key in ["external-tls-config", "tls-config", "tls"] {
        if let Some(block) = server.get(key) {
            let explicit = tls_block_flag(block);
            let cert = hocon_pem_path(block, "cert-chain-file");
            let priv_key = hocon_pem_path(block, "private-key-file");
            let trust = hocon_pem_path(block, "trust-collection-file");
            let enabled = explicit.unwrap_or_else(|| cert.is_some() || priv_key.is_some());
            if enabled {
                let cert_chain_file = cert.ok_or_else(|| {
                    format!("{network}.server-endpoint.{key}.cert-chain-file is required when TLS is enabled")
                })?;
                let private_key_file = priv_key.ok_or_else(|| {
                    format!("{network}.server-endpoint.{key}.private-key-file is required when TLS is enabled")
                })?;
                server_tls = Some(BftServerTlsFiles {
                    cert_chain_file,
                    private_key_file,
                    trust_collection_file: trust,
                });
                break;
            }
        }
    }

    let address = text("address").unwrap_or_else(|| "127.0.0.1".to_string());
    let port = server
        .get("port")
        .and_then(Hocon::as_u16)
        .ok_or_else(|| format!("{network}.server-endpoint.port is missing"))?;
    let external_address = text("external-address").unwrap_or_else(|| address.clone());
    let external_port = server
        .get("external-port")
        .and_then(Hocon::as_u16)
        .unwrap_or(port);
    let mut peers = Vec::new();
    let mut peer_tls = BTreeMap::new();
    if let Some(Hocon::Array(items)) = conf.get(&format!("{network}.peer-endpoints")) {
        for (i, peer) in items.iter().enumerate() {
            let host = peer
                .get("address")
                .and_then(Hocon::text)
                .ok_or_else(|| format!("{network}.peer-endpoints[{i}].address is missing"))?;
            let port = peer
                .get("port")
                .and_then(Hocon::as_u16)
                .ok_or_else(|| format!("{network}.peer-endpoints[{i}].port is missing"))?;
            let mut client_tls: Option<BftClientTlsFiles> = None;
            for key in ["tls-config", "tls"] {
                if let Some(block) = peer.get(key) {
                    let trust = hocon_pem_path(block, "custom-server-trust-certificate")
                        .or_else(|| hocon_pem_path(block, "trust-collection-file"));
                    let cert_block = block
                        .get("client-cert")
                        .or_else(|| block.get("client-certificate"));
                    let client_cert = cert_block
                        .and_then(|c| hocon_pem_path(c, "certificate-chain-file"))
                        .or_else(|| hocon_pem_path(block, "cert-chain-file"));
                    let client_key = cert_block
                        .and_then(|c| hocon_pem_path(c, "private-key-file"))
                        .or_else(|| hocon_pem_path(block, "private-key-file"));
                    let enabled = tls_block_flag(block)
                        .unwrap_or_else(|| trust.is_some() || client_cert.is_some());
                    if enabled {
                        client_tls = Some(BftClientTlsFiles {
                            trust_collection_file: trust,
                            client_cert_file: client_cert,
                            client_key_file: client_key,
                        });
                        break;
                    }
                }
            }
            let url = if client_tls.is_some() {
                format!("https://{host}:{port}")
            } else {
                format!("http://{host}:{port}")
            };
            if let Some(cfg) = client_tls {
                peer_tls.insert(url.clone(), cfg);
            }
            peers.push(url);
        }
    }
    Ok(BftNetwork {
        bind: format!("{address}:{port}"),
        external: format!("{external_address}:{external_port}"),
        peers,
        view_change_timeout_ms,
        epoch_length,
        server_tls,
        peer_tls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_participant::hocon::parse;

    /// The configuration of the BFT oracle's first official sequencer (`scripts/bft-oracle/three-peers.conf`).
    #[test]
    fn reads_the_network_of_an_official_sequencer() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../scripts/bft-oracle/three-peers.conf"
        ))
        .expect("the oracle configuration");
        let conf = parse(&text, &|_| None).expect("parses");
        let network = bft_network(&conf, "sequencer1").expect("a BFT network");
        assert_eq!(network.bind, "0.0.0.0:31030");
        assert_eq!(network.external, "127.0.0.1:31030");
        assert_eq!(
            network.peers,
            vec!["http://127.0.0.1:31031", "http://127.0.0.1:31033"]
        );
        assert_eq!(network.view_change_timeout_ms, None);
        assert_eq!(network.epoch_length, None);

        let with_timeout = parse(
            &text.replace(
                "initial-network {",
                "view-change-timeout-override = \"20 minutes\"\n          initial-network {",
            ),
            &|_| None,
        )
        .expect("parses with timeout");
        assert_eq!(
            bft_network(&with_timeout, "sequencer1")
                .expect("with timeout")
                .view_change_timeout_ms,
            Some(1_200_000)
        );
    }

    #[test]
    fn reads_official_two_peers_conf_and_port_offset() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../references/canton-3.7.2/dist/examples/11-bft-sequencer/two-peers.conf"
        ))
        .expect("two-peers.conf");
        let conf = parse(&text, &|_| None).expect("parses");
        let s1 = bft_network(&conf, "sequencer1")
            .expect("sequencer1")
            .with_port_offset(18_000)
            .unwrap();
        let s2 = bft_network(&conf, "sequencer2")
            .expect("sequencer2")
            .with_port_offset(18_000)
            .unwrap();
        assert_eq!(s1.bind, "0.0.0.0:49030");
        assert_eq!(s1.external, "127.0.0.1:49030");
        assert_eq!(s1.peers, vec!["http://127.0.0.1:49031"]);
        assert_eq!(s2.bind, "0.0.0.0:49031");
        assert_eq!(s2.peers, vec!["http://127.0.0.1:49030"]);
    }

    #[test]
    fn bft_applied_leaf_accepts_known_and_rejects_unknown_keys() {
        assert!(bft_applied_leaf("sequencer.type"));
        assert!(bft_applied_leaf(
            "sequencer.config.view-change-timeout-override"
        ));
        assert!(bft_applied_leaf("sequencer.config.epoch-length"));
        assert!(bft_applied_leaf(
            "sequencer.config.initial-network.server-endpoint.port"
        ));
        assert!(bft_applied_leaf(
            "sequencer.config.initial-network.server-endpoint.tls-config.cert-chain-file"
        ));
        assert!(bft_applied_leaf(
            "sequencer.config.initial-network.server-endpoint.external-tls-config.trust-collection-file"
        ));
        assert!(bft_applied_leaf(
            "sequencer.config.initial-network.peer-endpoints[].address"
        ));
        assert!(bft_applied_leaf(
            "sequencer.config.initial-network.peer-endpoints[].tls-config.enabled"
        ));
        assert!(!bft_applied_leaf("sequencer.config.unknown-knob"));
    }

    #[test]
    fn external_defaults_to_the_listen_address_and_invalid_fields_are_refused() {
        let plain = parse(
            r#"canton.sequencers.s.sequencer { type = BFT, config { epoch-length = 20, view-change-timeout-override = "15 seconds", initial-network.server-endpoint { address = "10.0.0.1", port = 9000 } } }"#,
            &|_| None,
        )
        .unwrap();
        let network = bft_network(&plain, "s").unwrap();
        assert_eq!(
            (network.bind.as_str(), network.external.as_str()),
            ("10.0.0.1:9000", "10.0.0.1:9000")
        );
        assert!(network.peers.is_empty());
        assert_eq!(network.view_change_timeout_ms, Some(15_000));
        assert_eq!(network.epoch_length, Some(20));

        let bad_dur = parse(
            r#"canton.sequencers.s.sequencer { type = BFT, config { view-change-timeout-override = "0 seconds", initial-network.server-endpoint { port = 9000 } } }"#,
            &|_| None,
        )
        .unwrap();
        assert!(bft_network(&bad_dur, "s").unwrap_err().contains("positive"));

        let bad_timeout = parse(
            r#"canton.sequencers.s.sequencer { type = BFT, config { view-change-timeout-override = "soon", initial-network.server-endpoint { port = 9000 } } }"#,
            &|_| None,
        )
        .unwrap();
        assert!(bft_network(&bad_timeout, "s").is_err());

        let tls = parse(
            r#"canton.sequencers.s.sequencer {
                type = BFT,
                config.initial-network {
                    server-endpoint {
                        port = 9000,
                        tls-config {
                            enabled = true,
                            cert-chain-file = "/tmp/s.crt",
                            private-key-file = "/tmp/s.key",
                            trust-collection-file = "/tmp/ca.crt"
                        }
                    },
                    peer-endpoints = [{
                        address = "h",
                        port = 9001,
                        tls-config {
                            enabled = true,
                            custom-server-trust-certificate = "/tmp/ca.crt"
                        }
                    }]
                }
            }"#,
            &|_| None,
        )
        .unwrap();
        let tls_net = bft_network(&tls, "s")
            .unwrap()
            .with_port_offset(100)
            .unwrap();
        assert_eq!(tls_net.bind, "127.0.0.1:9100");
        assert_eq!(tls_net.peers, vec!["https://h:9101"]);
        assert!(tls_net.server_tls.is_some());
        assert!(tls_net.peer_tls.contains_key("https://h:9101"));

        let not_bft = parse(r#"canton.sequencers.s.sequencer.type = reference"#, &|_| {
            None
        })
        .unwrap();
        assert!(bft_network(&not_bft, "s").is_err());
    }
}
