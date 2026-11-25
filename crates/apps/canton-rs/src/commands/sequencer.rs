//! Sequencer CLI subcommand: the real Rust sequencer (`canton_sequencer_server`), in the one executable (G11).
//!
//! `run` serves the sequencer's public API (the connect, authentication and sequencer services, the mediator, the topology state) until it
//! is stopped; `status` asks a running one over its API. Nothing here prints a state it did not read from a server.

use clap::{Args, Subcommand};
use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Args, Debug)]
pub struct SequencerArgs {
    #[command(subcommand)]
    pub action: SequencerAction,
}

#[derive(Subcommand, Debug)]
pub enum SequencerAction {
    /// Serve the sequencer's public API until stopped (SIGINT or SIGTERM). The environment variables `RUST_SEQUENCER_*` (state directory, TLS,
    /// mediator groups, BFT ordering, control file, compaction, tick) configure what the options below do not.
    Run(SequencerRunArgs),
    /// Ask a running sequencer for its identity over its API.
    Status(SequencerStatusArgs),
    /// Prune the sequencer's event journal (not served by the Rust sequencer yet: it forgets what every member acknowledged instead).
    Prune(SequencerPruneArgs),
    /// As the synchronizer's operator, onboard a mediator after genesis: load its onboarding transactions (`mediator onboarding --out`) and
    /// name it in a mediator group, through the sequencer's topology administration (a Rust sequencer, or an official one's admin API).
    AddMediator(SequencerAddMediatorArgs),
    /// Make the identity of a new sequencer (keys and the topology transactions that make it known to a synchronizer): written to `--identity` (kept) and `--out`
    /// (the file the synchronizer's owners load with `add-sequencer`).
    Identity(SequencerIdentityArgs),
    /// As the owners of a synchronizer other sequencers already run, onboard a new sequencer: load its identity transactions (`identity --out`) and propose a
    /// sequencer state that names it to the admin API of each owner's sequencer (U-49).
    AddSequencer(SequencerAddSequencerArgs),
    /// Load topology transactions (a file of `identity --signing-key-out`) into the synchronizer's store through an owner's sequencer admin API: the second step of
    /// onboarding a sequencer, which gives it its protocol signing key.
    LoadTransactions(SequencerLoadArgs),
    /// Serve the p2p endpoint of a BFT orderer node the sequencers of an official synchronizer connect to (U-49 B2b): the authentication service and the BFT
    /// ordering service, for the sequencers whose keys the synchronizer's topology lists.
    BftPeer(SequencerBftPeerArgs),
    /// Run a BFT synchronizer sequencer launched by `daemon` (public API, optional admin API, P2P BFT consensus, and optional `ord_*` persistence).
    #[command(hide = true)]
    RunBft(Box<SequencerRunBftArgs>),
    /// Sends the same aggregated request twice to an official sequencer as this node's own member and prints the events it gets back (what the second one is answered
    /// with): how the official nodes build an error event, to copy it.
    ProbeDedup(SequencerProbeArgs),
}

#[derive(Debug, clap::Args)]
pub struct SequencerRunBftArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub synchronizer: String,
    #[arg(long)]
    pub namespace: String,
    #[arg(long)]
    pub genesis_file: std::path::PathBuf,
    #[arg(long)]
    pub public_bind: String,
    #[arg(long)]
    pub admin_bind: Option<String>,
    #[arg(long)]
    pub p2p_bind: String,
    #[arg(long)]
    pub external: String,
    #[arg(long)]
    pub peer: Vec<String>,
    #[arg(long)]
    pub epoch_length: Option<i64>,
    #[arg(long)]
    pub view_change_timeout_ms: Option<u64>,
    #[arg(long)]
    pub state_dir: Option<std::path::PathBuf>,
    #[arg(long, env = "CANTON_RS_STATE_PG_URL")]
    pub state_pg_url: Option<String>,
    #[arg(long, default_value = "sequencer")]
    pub state_name: String,
    #[arg(long, env = "CANTON_RS_ORD_PG_URL", hide = true)]
    pub ord_pg_url: Option<String>,
    #[arg(long)]
    pub p2p_tls_cert: Option<std::path::PathBuf>,
    #[arg(long)]
    pub p2p_tls_key: Option<std::path::PathBuf>,
    #[arg(long)]
    pub p2p_tls_ca: Option<std::path::PathBuf>,
    #[arg(long)]
    pub peer_tls_ca: Option<std::path::PathBuf>,
    #[arg(long)]
    pub peer_tls_cert: Option<std::path::PathBuf>,
    #[arg(long)]
    pub peer_tls_key: Option<std::path::PathBuf>,
    #[arg(long, default_value = "127.0.0.1")]
    pub metrics_bind: String,
    #[arg(long)]
    pub metrics_port: Option<u16>,
}

#[derive(Args, Debug)]
pub struct SequencerLoadArgs {
    #[arg(long)]
    pub sequencer_url: String,
    #[arg(long)]
    pub admin_url: String,
    #[arg(long)]
    pub transactions: std::path::PathBuf,
}

#[derive(Args, Debug)]
pub struct SequencerProbeArgs {
    /// The official sequencer's public API.
    #[arg(long)]
    pub sequencer_url: String,
    /// This node's identity (`sequencer identity --identity`), already part of the synchronizer.
    #[arg(long)]
    pub identity: std::path::PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct SequencerBftPeerArgs {
    /// The address and port to serve on (default `0.0.0.0:31032`, or what `--config` says).
    #[arg(long)]
    pub bind: Option<String>,

    /// A `canton.conf` whose `canton.sequencers.<--node>.sequencer.config.initial-network` gives the p2p network (listen address, external address, peers); what the
    /// flags `--bind`, `--external` and `--peer` set is used instead of the same part of the file.
    #[arg(long, requires = "node")]
    pub config: Option<std::path::PathBuf>,

    /// The sequencer of `--config` this node is.
    #[arg(long, requires = "config")]
    pub node: Option<String>,

    /// An existing sequencer's public API (where the synchronizer's id is read).
    #[arg(long)]
    pub sequencer_url: String,

    /// An existing sequencer's admin API (where the sequencers' keys are read).
    #[arg(long)]
    pub admin_url: String,

    /// This node's identity (`sequencer identity --identity`): the keys it authenticates to its peers with.
    #[arg(long)]
    pub identity: std::path::PathBuf,

    /// The p2p endpoints of the peers to open this node's own streams to (`http://host:port`), one per peer.
    #[arg(long)]
    pub peer: Vec<String>,

    /// This node's endpoint as the peers reach it (`host:port`), where they authenticate back to.
    #[arg(long)]
    pub external: Option<String>,

    /// Take part in the consensus: the node starts in the epoch the peers are in when it sees their first block proposal of an epoch, and proposes in its own
    /// segment from then on.
    #[arg(long)]
    pub join: bool,

    /// The number of blocks of an epoch (default: ten per node, the official `segmentLength`).
    #[arg(long)]
    pub epoch_length: Option<i64>,

    /// Run a sequencer of this node's own that applies the requests of the blocks the orderer decides, at the times it gives them (the member registry is read from
    /// the topology at `--admin-url`). Its events are traced (`SEQUENCED …`) so that they can be compared with what the participants of the official nodes log.
    #[arg(long)]
    pub observe_sequencing: bool,

    /// With `--observe-sequencing`: also serve the public API of that sequencer here (`host:port`), so that a participant can read its events.
    #[arg(long)]
    pub public_api: Option<String>,

    /// The view change timeout the official sequencers run with, in milliseconds (their `view-change-timeout-override`): a segment that makes no progress for this
    /// long moves to a new view. Without it the defaults of the official nodes apply (10 s and 2 s per view).
    #[arg(long)]
    pub view_change_timeout_ms: Option<u64>,

    /// A file the node keeps what it signed in (proposals and votes), so that a restart does not sign anything different for a block it already signed.
    #[arg(long)]
    pub state_file: Option<std::path::PathBuf>,

    /// PostgreSQL URL for `ord_*` BFT persistence (`ord_epochs`, `ord_availability_batch`, `ord_pbft_messages_*`, `ord_leader_selection_state`, `ord_metadata_output_*`).
    #[arg(long, env = "CANTON_RS_ORD_PG_URL", hide = true)]
    pub ord_pg_url: Option<String>,
}

#[derive(Args, Debug)]
pub struct SequencerIdentityArgs {
    /// The sequencer's name.
    #[arg(long, default_value = "rs1")]
    pub name: String,

    /// Where the identity is kept: an existing file is read (the same sequencer again), a missing one is made.
    #[arg(long)]
    pub identity: std::path::PathBuf,

    /// Write the onboarding transactions here, one hex line each.
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,

    /// Write the onboarding in two steps instead (`--out` gets the first: the authentication key only; this file the second: the protocol signing key), so that
    /// the node can be authenticated by its peers before the ordering waits for its votes.
    #[arg(long)]
    pub signing_key_out: Option<std::path::PathBuf>,
}

#[derive(Args, Debug)]
pub struct SequencerAddSequencerArgs {
    /// An existing sequencer's public API (where the synchronizer's id is read).
    #[arg(long)]
    pub sequencer_url: String,

    /// The topology administration of an owner's sequencer (an official one's admin API); one per owner of the synchronizer's namespace, the first also loads
    /// the identity.
    #[arg(long, required = true)]
    pub admin_url: Vec<String>,

    /// The new sequencer's onboarding transactions (`canton-rs sequencer identity --out`).
    #[arg(long)]
    pub onboarding: std::path::PathBuf,

    /// How long to wait for the owners' signatures to put the state in force, in seconds.
    #[arg(long, default_value_t = 60)]
    pub timeout_seconds: u64,
}

#[derive(Args, Debug)]
pub struct SequencerAddMediatorArgs {
    /// The sequencer's public API (where the synchronizer's id is read).
    #[arg(long, default_value = "http://127.0.0.1:5018")]
    pub sequencer_url: String,

    /// The sequencer's topology administration, when it is not the public API (an official sequencer's admin API).
    #[arg(long)]
    pub admin_url: Option<String>,

    /// The mediator's onboarding transactions (`canton-rs mediator onboarding --out`).
    #[arg(long)]
    pub onboarding: std::path::PathBuf,

    /// The mediator group to name it in.
    #[arg(long, default_value_t = 0)]
    pub group: u32,

    /// Make it the group's only active mediator (threshold 1) instead of adding it.
    #[arg(long, default_value_t = false)]
    pub replace: bool,
}

#[derive(Args, Debug)]
pub struct SequencerRunArgs {
    /// Bind address for the sequencer's public API.
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,

    /// Bind port.
    #[arg(short, long, default_value_t = 5018)]
    pub port: u16,

    /// The synchronizer's name (its id is `<name>::<fingerprint>::37-<serial>`).
    #[arg(long, default_value = "rustsync")]
    pub name: String,

    /// Where the keys, members, topology and events are kept (in memory when absent).
    #[arg(long, conflicts_with = "state_pg_url")]
    pub state_dir: Option<std::path::PathBuf>,

    /// Keep them in PostgreSQL instead (a libpq-style URL; prefer the environment variable, a command line is visible to other users of the
    /// machine). One sequencer of a name runs at a time.
    #[arg(long, env = "CANTON_RS_STATE_PG_URL")]
    pub state_pg_url: Option<String>,

    /// The name of the sequencer's state inside the database.
    #[arg(long, default_value = "sequencer")]
    pub state_name: String,

    /// Bind address for optional HTTP `/metrics` & `/status` endpoint.
    #[arg(long, default_value = "127.0.0.1")]
    pub metrics_bind: String,

    /// Port for optional HTTP `/metrics`, `/status`, `/livez`, and `/readyz` endpoint.
    #[arg(long)]
    pub metrics_port: Option<u16>,
}

#[derive(Args, Debug)]
pub struct SequencerStatusArgs {
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    #[arg(short, long, default_value_t = 5018)]
    pub port: u16,
}

#[derive(Args, Debug)]
pub struct SequencerPruneArgs {
    /// Microsecond timestamp cutoff.
    #[arg(long)]
    pub before_or_at: i64,

    #[arg(short, long, default_value_t = 5018)]
    pub port: u16,
}

fn address(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("{host}:{port}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host}:{port} names no address"))
}

pub fn execute_sequencer(args: SequencerArgs) -> Result<(), String> {
    match args.action {
        SequencerAction::Run(run) => {
            if let Some(metrics_port) = run.metrics_port {
                let metrics_addr = address(&run.metrics_bind, metrics_port)?;
                std::env::set_var("CANTON_RS_SEQUENCER_METRICS_BIND", metrics_addr.to_string());
            }
            let store: Option<std::sync::Arc<dyn canton_participant::state_store::StateStore>> =
                match (&run.state_pg_url, &run.state_dir) {
                    (Some(url), None) => Some(
                        canton_participant::state_store::PgStore::connect(url, &run.state_name)
                            .map_err(|e| format!("cannot open the sequencer's state in PostgreSQL: {e}"))?,
                    ),
                    _ => None,
                };
            canton_sequencer_server::cli::run_in(
                address(&run.bind, run.port)?,
                &run.name,
                run.state_dir,
                store,
                &|line| println!("{line}"),
            )
        }
        SequencerAction::Status(status) => {
            let url = format!("http://{}:{}", status.host, status.port);
            let mut client = canton_participant::sequencer_connect::SequencerConnect::connect(&url)
                .map_err(|e| format!("no sequencer answers at {url}: {e}"))?;
            let api = client.api_name().map_err(|e| e.to_string())?;
            let id = client.synchronizer_id().map_err(|e| e.to_string())?;
            println!("Sequencer at {url}: {api}");
            println!("Synchronizer ID: {}", id.physical_synchronizer_id);
            println!("Sequencer ID:    {}", id.sequencer_uid);
            Ok(())
        }
        SequencerAction::AddMediator(args) => {
            let text = std::fs::read_to_string(&args.onboarding)
                .map_err(|e| format!("{}: {e}", args.onboarding.display()))?;
            let transactions = canton_sequencer_server::mediator_identity::read_onboarding_file(&text)?;
            let member = canton_sequencer_server::mediator_identity::mediator_of(&transactions)
                .ok_or("the onboarding transactions have no key mapping of a mediator")?;
            let mut client = canton_participant::sequencer_connect::SequencerConnect::connect(&args.sequencer_url)
                .map_err(|e| format!("{}: {e}", args.sequencer_url))?;
            let physical = client
                .synchronizer_id()
                .map_err(|e| e.to_string())?
                .physical_synchronizer_id;
            let admin_url = args.admin_url.clone().unwrap_or_else(|| args.sequencer_url.clone());
            let uid = member.trim_start_matches("MED::").to_string();
            let done = canton_sequencer_server::topology_admin::onboard_mediator(
                &admin_url,
                &physical,
                transactions,
                &uid,
                args.group,
                args.replace,
            )?;
            println!(
                "ONBOARDED {member} in mediator group {} (serial {}, active {:?}, signed by {:?})",
                done.group,
                done.serial,
                done.active,
                done.transaction.signatures.iter().map(|s| s.signed_by.clone()).collect::<Vec<_>>()
            );
            Ok(())
        }
        SequencerAction::Identity(args) => {
            let identity = match std::fs::read_to_string(&args.identity) {
                Ok(text) => canton_sequencer_server::sequencer_identity::SequencerIdentity::from_text(&text)
                    .ok_or_else(|| format!("{}: not a sequencer identity", args.identity.display()))?,
                Err(_) => {
                    let identity = canton_sequencer_server::sequencer_identity::SequencerIdentity::generate(&args.name);
                    std::fs::write(&args.identity, identity.to_text())
                        .map_err(|e| format!("{}: {e}", args.identity.display()))?;
                    identity
                }
            };
            let two_steps = args.signing_key_out.is_some();
            let transactions = if two_steps {
                identity.authentication_only_transactions()
            } else {
                identity.onboarding_transactions()
            };
            if let Some(out) = &args.out {
                std::fs::write(out, canton_sequencer_server::mediator_identity::onboarding_file(&transactions))
                    .map_err(|e| format!("{}: {e}", out.display()))?;
            }
            if let Some(out) = &args.signing_key_out {
                std::fs::write(out, canton_sequencer_server::mediator_identity::onboarding_file(&identity.signing_key_transactions()))
                    .map_err(|e| format!("{}: {e}", out.display()))?;
            }
            println!("SEQUENCER {}", identity.member());
            println!("Namespace key: {}", identity.namespace());
            println!("Onboarding transactions: {}", transactions.len());
            Ok(())
        }
        SequencerAction::AddSequencer(args) => {
            let text = std::fs::read_to_string(&args.onboarding)
                .map_err(|e| format!("{}: {e}", args.onboarding.display()))?;
            let transactions = canton_sequencer_server::mediator_identity::read_onboarding_file(&text)?;
            let member = canton_sequencer_server::sequencer_identity::sequencer_of(&transactions)
                .ok_or("the onboarding transactions have no key mapping of a sequencer")?;
            let mut client = canton_participant::sequencer_connect::SequencerConnect::connect(&args.sequencer_url)
                .map_err(|e| format!("{}: {e}", args.sequencer_url))?;
            let physical = client
                .synchronizer_id()
                .map_err(|e| e.to_string())?
                .physical_synchronizer_id;
            let uid = member.trim_start_matches("SEQ::").to_string();
            let done = canton_sequencer_server::topology_admin::onboard_sequencer(
                &args.admin_url,
                &physical,
                transactions,
                &uid,
                std::time::Duration::from_secs(args.timeout_seconds),
            )?;
            println!("ONBOARDED {member} (sequencer state serial {}, active {:?})", done.serial, done.active);
            Ok(())
        }
        SequencerAction::LoadTransactions(args) => {
            let text = std::fs::read_to_string(&args.transactions)
                .map_err(|e| format!("{}: {e}", args.transactions.display()))?;
            let transactions = canton_sequencer_server::mediator_identity::read_onboarding_file(&text)?;
            let mut client = canton_participant::sequencer_connect::SequencerConnect::connect(&args.sequencer_url)
                .map_err(|e| format!("{}: {e}", args.sequencer_url))?;
            let physical = client
                .synchronizer_id()
                .map_err(|e| e.to_string())?
                .physical_synchronizer_id;
            canton_sequencer_server::topology_admin::load_transactions(&args.admin_url, &physical, transactions)?;
            println!("LOADED");
            Ok(())
        }
        SequencerAction::ProbeDedup(args) => {
            let text = std::fs::read_to_string(&args.identity).map_err(|e| format!("{}: {e}", args.identity.display()))?;
            let identity = canton_sequencer_server::sequencer_identity::SequencerIdentity::from_text(&text)
                .ok_or_else(|| format!("{}: not a sequencer identity", args.identity.display()))?;
            canton_sequencer_server::probe::dedup(&identity, &args.sequencer_url, &|line| println!("{line}"))
        }
        SequencerAction::BftPeer(args) => {
            let mut client = canton_participant::sequencer_connect::SequencerConnect::connect(&args.sequencer_url)
                .map_err(|e| format!("{}: {e}", args.sequencer_url))?;
            let physical = client
                .synchronizer_id()
                .map_err(|e| e.to_string())?
                .physical_synchronizer_id;
            let from_config = match (&args.config, &args.node) {
                (Some(path), Some(node)) => {
                    let conf = canton_participant::hocon::parse_file(path, &|k| {
                        std::env::var(k).ok()
                    })?;
                    Some(super::bft_config::bft_network(&conf, node)?)
                }
                _ => None,
            };
            let bind_text = args
                .bind
                .clone()
                .or_else(|| from_config.as_ref().map(|n| n.bind.clone()))
                .unwrap_or_else(|| "0.0.0.0:31032".to_string());
            let external_text = args
                .external
                .clone()
                .or_else(|| from_config.as_ref().map(|n| n.external.clone()))
                .unwrap_or_else(|| "host.docker.internal:31032".to_string());
            let peers: Vec<String> = if args.peer.is_empty() {
                from_config.as_ref().map(|n| n.peers.clone()).unwrap_or_default()
            } else {
                args.peer.clone()
            };
            let bind: SocketAddr = bind_text.parse().map_err(|e| format!("--bind: {e}"))?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let text = std::fs::read_to_string(&args.identity)
                .map_err(|e| format!("{}: {e}", args.identity.display()))?;
            let identity = canton_sequencer_server::sequencer_identity::SequencerIdentity::from_text(&text)
                .ok_or_else(|| format!("{}: not a sequencer identity", args.identity.display()))?;
            let epoch_length = args
                .epoch_length
                .or_else(|| from_config.as_ref().and_then(|n| n.epoch_length));
            let view_change_timeout_ms = args
                .view_change_timeout_ms
                .or_else(|| from_config.as_ref().and_then(|n| n.view_change_timeout_ms));
            runtime.block_on(async move {
                let registry = std::sync::Arc::new(canton_sequencer_server::bft_p2p::sequencer_registry(&args.admin_url, &physical).await?);
                let (host, port) = external_text
                    .rsplit_once(':')
                    .and_then(|(h, p)| Some((h.to_string(), p.parse::<u32>().ok()?)))
                    .ok_or("--external is host:port")?;
                let mut observed: Option<canton_sequencer_server::sequencing::Sequencer> = None;
                let mut ord_store: Option<std::sync::Arc<canton_sequencer_server::ord_store::OrdStore>> = None;
                let consensus = if args.join {
                    let mut c = canton_sequencer_server::bft_p2p::Consensus::new(
                        identity.member(),
                        identity.signing_key.seed(),
                        identity.signing_key.fingerprint.clone(),
                        epoch_length,
                        std::sync::Arc::clone(&registry),
                    );
                    c.set_nodes(registry.members());
                    if args.observe_sequencing {
                        // a sequencer that takes what the orderer decides: the members of the synchronizer (participants, mediators, sequencers) and their keys from the topology
                        let members = canton_sequencer_server::onboarding::Registry::default();
                        for kind in ["PAR", "MED", "SEQ"] {
                            let part = canton_sequencer_server::bft_p2p::registry_of(&args.admin_url, &physical, kind).await?;
                            for m in part.members() {
                                if let Some(r) = part.get(&m) {
                                    members.insert(r);
                                }
                            }
                        }
                        eprintln!("SEQUENCING members: {:?}", members.members());
                        // the synchronizer is the official one (its id from the handshake), the sequencer is this node: its keys sign what it hands out
                        let keys = std::sync::Arc::new(canton_sequencer_server::synchronizer_state::SynchronizerKeys::for_sequencer(
                            identity.namespace_key.seed(),
                            identity.signing_key.seed(),
                            identity.authentication_key.seed(),
                        ));
                        let store = std::sync::Arc::new(canton_sequencer_server::synchronizer_state::TopologyStore::initial("observed", "observed", "observed", &keys));
                        // the store above is a placeholder of this node's keys: the mediator groups, which decide who sends a group's verdict, are the official synchronizer's
                        let groups = canton_sequencer_server::bft_p2p::mediator_groups_of(&args.admin_url, &physical).await?;
                        eprintln!(
                            "SEQUENCING mediator groups: {:?}",
                            groups.iter().map(|(g, m)| format!("{g}: threshold {} of {:?}", m.threshold, m.active)).collect::<Vec<_>>()
                        );
                        store.observe_mediator_groups(groups);
                        let members = std::sync::Arc::new(members);
                        let sequencer = canton_sequencer_server::sequencing::Sequencer::new(physical.clone(), std::sync::Arc::clone(&keys), std::sync::Arc::clone(&members), std::sync::Arc::clone(&store));
                        sequencer.set_observer();
                        sequencer.set_self_member(&identity.member());
                        if let Some(address) = &args.public_api {
                            let parts: Vec<&str> = physical.split("::").collect();
                            let serial = parts.get(2).and_then(|p| p.rsplit('-').next()).and_then(|n| n.parse::<u32>().ok()).unwrap_or(0);
                            let config = canton_sequencer_server::SynchronizerConfig {
                                name: parts.first().copied().unwrap_or("da").to_string(),
                                namespace_fingerprint: parts.get(1).copied().unwrap_or_default().to_string(),
                                sequencer_name: identity.name.clone(),
                                sequencer_fingerprint: identity.namespace_key.fingerprint.clone(),
                                keys,
                                serial,
                            };
                            let connect = canton_sequencer_server::ConnectService::from_parts(config.clone(), members, store, sequencer.clone());
                            let address: SocketAddr = address.parse().map_err(|e| format!("--public-api: {e}"))?;
                            eprintln!("SEQUENCING public API on {address}");
                            tokio::spawn(async move {
                                if let Err(e) = canton_sequencer_server::serve_connect(address, config, connect).await {
                                    eprintln!("SEQUENCING public API stopped: {e}");
                                }
                            });
                        }
                        let applying = sequencer.clone();
                        c.set_sink(std::sync::Arc::new(move |request: canton_sequencer_server::bft_p2p::OutputRequest| {
                            if request.tag == "send" {
                                if let Some((sender, _)) = canton_sequencer_server::sequencing::read_submission(&request.body) {
                                    applying.apply_ordered_at(&sender, &request.body, request.time_micros);
                                }
                            } else if request.tag == "acknowledge" {
                                applying.apply_ordered_acknowledgement(&request.body);
                            }
                        }));
                        let applying_end = sequencer.clone();
                        c.set_block_end_sink(std::sync::Arc::new(
                            move |block: i64, base_block_time: i64, tick_at_least: Option<i64>| {
                                let (ticked, pending) = applying_end.finish_ordered_block(
                                    block,
                                    base_block_time,
                                    tick_at_least,
                                );
                                if let Some((scope, ts)) = ticked {
                                    eprintln!("TOPOLOGY-TICK block {block} scope {scope} ts {ts}");
                                }
                                pending
                            },
                        ));
                        observed = Some(sequencer);
                    }
                    if let Some(millis) = view_change_timeout_ms {
                        c.set_view_change_timeout_ms(millis);
                    }
                    if let Some(url) = &args.ord_pg_url {
                        let store = std::sync::Arc::new(canton_sequencer_server::ord_store::OrdStore::connect(url)?);
                        let n = c.persist_ord(std::sync::Arc::clone(&store))?;
                        eprintln!("CONSENSUS ord_* database: {n} earlier message(s)");
                        ord_store = Some(store);
                    } else if let Some(path) = &args.state_file {
                        let n = c.persist_to(path)?;
                        eprintln!("CONSENSUS state file {}: {n} earlier message(s)", path.display());
                    }
                    let c = std::sync::Arc::new(c);
                    // what the observer sequencer is sent goes to the orderer's mempool (`BftBlockOrderer.send`), and the cluster decides where it goes in the order
                    if let Some(sequencer) = &observed {
                        let ordering = std::sync::Arc::clone(&c);
                        sequencer.set_orderer(std::sync::Arc::new(move |_member: &str, bytes: &[u8]| {
                            match canton_sequencer_server::sequencing::read_submission(bytes) {
                                Some((_, message_id)) => mempool(&ordering, &message_id, bytes),
                                None => Ok(()),
                            }
                        }));
                    }
                    Some(c)
                } else {
                    None
                };
                let served = canton_sequencer_server::bft_p2p::serve(bind, physical, registry, &identity, peers, (host, port), consensus, args.admin_url.clone()).await;
                if let Some(store) = ord_store {
                    let _ = store.flush();
                }
                served
            })
        }
        SequencerAction::RunBft(args) => run_bft_sequencer(*args),
        SequencerAction::Prune(_) => Err(
            "the Rust sequencer does not prune on request: what every member acknowledged is forgotten at the start and while it runs (RUST_SEQUENCER_COMPACT_SECONDS)".into(),
        ),
    }
}

fn resolve_socket(spec: &str, label: &str) -> Result<SocketAddr, String> {
    spec.to_socket_addrs()
        .map_err(|e| format!("{label} ({spec}): {e}"))?
        .next()
        .ok_or_else(|| format!("{label} ({spec}) names no socket address"))
}

fn run_bft_sequencer(args: SequencerRunBftArgs) -> Result<(), String> {
    let public_bind = resolve_socket(&args.public_bind, "--public-bind")?;
    let admin_bind = args
        .admin_bind
        .as_deref()
        .map(|s| resolve_socket(s, "--admin-bind"))
        .transpose()?;
    let p2p_bind = resolve_socket(&args.p2p_bind, "--p2p-bind")?;
    let (ext_host, ext_port) = args
        .external
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h.to_string(), p.parse::<u32>().ok()?)))
        .ok_or("--external must be host:port")?;

    let pg_store: Option<std::sync::Arc<dyn canton_participant::state_store::StateStore>> =
        match (&args.state_pg_url, &args.state_dir) {
            (Some(url), None) => Some(
                canton_participant::state_store::PgStore::connect(url, &args.state_name)
                    .map_err(|e| format!("cannot open the sequencer's state in PostgreSQL: {e}"))?,
            ),
            _ => None,
        };
    let identity = match (&pg_store, &args.state_dir) {
        (Some(store), _) => {
            canton_sequencer_server::sequencer_identity::SequencerIdentity::load_or_create_in(
                store.as_ref(),
                &args.name,
            )?
        }
        (None, Some(dir)) => {
            let file_store = canton_participant::state_store::FileStore::new(dir)
                .map_err(|e| format!("cannot open state directory {}: {e}", dir.display()))?;
            canton_sequencer_server::sequencer_identity::SequencerIdentity::load_or_create_in(
                file_store.as_ref(),
                &args.name,
            )?
        }
        (None, None) => {
            canton_sequencer_server::sequencer_identity::SequencerIdentity::generate(&args.name)
        }
    };
    let genesis_text = std::fs::read_to_string(&args.genesis_file)
        .map_err(|e| format!("{}: {e}", args.genesis_file.display()))?;
    let genesis_txs =
        canton_sequencer_server::mediator_identity::read_onboarding_file(&genesis_text)?;
    let keys = std::sync::Arc::new(
        canton_sequencer_server::synchronizer_state::SynchronizerKeys::for_sequencer(
            identity.namespace_key.seed(),
            identity.signing_key.seed(),
            identity.authentication_key.seed(),
        ),
    );
    let config = canton_sequencer_server::SynchronizerConfig {
        name: args.synchronizer.clone(),
        namespace_fingerprint: args.namespace.clone(),
        sequencer_name: identity.name.clone(),
        sequencer_fingerprint: identity.namespace().to_string(),
        keys,
        serial: 0,
    };
    let store = std::sync::Arc::new(
        canton_sequencer_server::synchronizer_state::TopologyStore::from_genesis(
            &config.synchronizer_uid(),
            0,
            &identity.member(),
            genesis_txs,
        )?,
    );
    let registry = std::sync::Arc::new(canton_sequencer_server::onboarding::Registry::default());
    for member in store.registered_members() {
        registry.insert(member);
    }
    let connect = canton_sequencer_server::ConnectService::open_seeded(
        config.clone(),
        store,
        std::sync::Arc::clone(&registry),
        pg_store,
        args.state_dir.as_deref(),
    )
    .map_err(|e| format!("cannot open seeded sequencer service: {e}"))?;
    let sequencer = connect.sequencer();
    sequencer.set_observer();
    sequencer.set_self_member(&identity.member());
    println!("READY synchronizer={}", config.physical_synchronizer_id());
    println!("READY sequencer={}", config.sequencer_uid());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    {
        let stop = std::sync::Arc::clone(&stop);
        runtime.spawn(async move {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = async {
                    match term.as_mut() {
                        Some(t) => { t.recv().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {}
            }
            stop.notify_waiters();
        });
    }

    runtime.block_on(async move {
        let mut c = canton_sequencer_server::bft_p2p::Consensus::new(
            identity.member(),
            identity.signing_key.seed(),
            identity.signing_key.fingerprint.clone(),
            args.epoch_length,
            std::sync::Arc::clone(&registry),
        );
        if let Some(millis) = args.view_change_timeout_ms {
            c.set_view_change_timeout_ms(millis);
        }
        let seq_nodes: Vec<String> = registry
            .members()
            .into_iter()
            .filter(|m| m.starts_with("SEQ::"))
            .collect();
        c.set_nodes(seq_nodes);

        let mut ord_store: Option<std::sync::Arc<canton_sequencer_server::ord_store::OrdStore>> =
            None;
        if let Some(url) = &args.ord_pg_url {
            let store =
                std::sync::Arc::new(canton_sequencer_server::ord_store::OrdStore::connect(url)?);
            c.persist_ord(std::sync::Arc::clone(&store))?;
            ord_store = Some(store);
        } else if let Some(dir) = &args.state_dir {
            c.persist_to(&dir.join("bft.state"))?;
        }
        if let Some(ts) = c.restored_last_bft_time() {
            sequencer.advance_bft_time_to(ts);
        }

        let applying = sequencer.clone();
        c.set_sink(std::sync::Arc::new(
            move |request: canton_sequencer_server::bft_p2p::OutputRequest| {
                if request.tag == "send" {
                    if let Some((sender, _)) =
                        canton_sequencer_server::sequencing::read_submission(&request.body)
                    {
                        applying.apply_ordered_at(&sender, &request.body, request.time_micros);
                    }
                } else if request.tag == "acknowledge" {
                    applying.apply_ordered_acknowledgement(&request.body);
                }
            },
        ));
        let applying_end = sequencer.clone();
        c.set_block_end_sink(std::sync::Arc::new(
            move |block: i64, base_block_time: i64, tick_at_least: Option<i64>| {
                applying_end
                    .finish_ordered_block(block, base_block_time, tick_at_least)
                    .1
            },
        ));
        let c = std::sync::Arc::new(c);
        {
            let ordering = std::sync::Arc::clone(&c);
            sequencer.set_orderer(std::sync::Arc::new(move |_member: &str, bytes: &[u8]| {
                match canton_sequencer_server::sequencing::read_submission(bytes) {
                    Some((_, message_id)) => mempool(&ordering, &message_id, bytes),
                    None => Ok(()),
                }
            }));
        }
        c.start_genesis_or_resume()?;

        let server_tls = match (&args.p2p_tls_cert, &args.p2p_tls_key) {
            (Some(cert), Some(key)) => Some(canton_sequencer_server::bft_p2p::BftServerTls {
                cert_pem: std::fs::read_to_string(cert)
                    .map_err(|e| format!("{}: {e}", cert.display()))?,
                key_pem: std::fs::read_to_string(key)
                    .map_err(|e| format!("{}: {e}", key.display()))?,
                client_ca_pem: args
                    .p2p_tls_ca
                    .as_ref()
                    .map(|p| {
                        std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
                    })
                    .transpose()?,
            }),
            (None, None) => None,
            _ => return Err("--p2p-tls-cert and --p2p-tls-key must be specified together".into()),
        };

        let peer_ca_bytes = args
            .peer_tls_ca
            .as_ref()
            .map(|p| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display())))
            .transpose()?;
        let peer_cert_bytes = args
            .peer_tls_cert
            .as_ref()
            .map(|p| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display())))
            .transpose()?;
        let peer_key_file = args.peer_tls_key.as_ref().map(|p| p.display().to_string());
        let default_client_tls = (peer_ca_bytes.is_some()
            || peer_cert_bytes.is_some()
            || peer_key_file.is_some())
        .then(|| canton_sequencer_server::bft_p2p::BftClientTls {
            custom_server_trust_pem: peer_ca_bytes.clone(),
            client_cert_chain_pem: peer_cert_bytes.clone(),
            client_private_key_file: peer_key_file.clone(),
        });

        let parsed_peers = args
            .peer
            .iter()
            .map(|u| {
                let mut cfg = canton_sequencer_server::bft_p2p::BftPeerConfig::from_url(u)?;
                if cfg.tls.is_some() {
                    cfg.tls = default_client_tls.clone().or(cfg.tls);
                }
                Ok::<_, String>(cfg)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let own_tls_for_endpoint =
            server_tls
                .as_ref()
                .map(|_| canton_sequencer_server::bft_p2p::BftClientTls {
                    custom_server_trust_pem: args
                        .p2p_tls_ca
                        .as_ref()
                        .and_then(|p| std::fs::read(p).ok())
                        .or_else(|| peer_ca_bytes.clone()),
                    client_cert_chain_pem: peer_cert_bytes.clone(),
                    client_private_key_file: peer_key_file.clone(),
                });

        let physical = config.physical_synchronizer_id();
        let peer_manager = canton_sequencer_server::bft_p2p::build_peer_manager(
            physical.clone(),
            std::sync::Arc::clone(&registry),
            &identity,
            (ext_host.clone(), ext_port, own_tls_for_endpoint.clone()),
            Some(std::sync::Arc::clone(&c)),
            String::new(),
            ord_store.clone(),
            Some(std::sync::Arc::clone(&stop)),
        );
        if let Some(metrics_port) = args.metrics_port {
            let metrics_addr = address(&args.metrics_bind, metrics_port)?;
            canton_sequencer_server::spawn_status_http(
                metrics_addr,
                config.clone(),
                sequencer.clone(),
                Some(std::sync::Arc::clone(&peer_manager)),
                args.peer.len(),
                Some(std::sync::Arc::clone(&stop)),
            )
            .map_err(|e| format!("metrics HTTP listener on {metrics_addr}: {e}"))?;
        }
        let epoch_len = args
            .epoch_length
            .unwrap_or_else(|| 10 * registry.members().len().max(1) as i64);
        let bft_admin = canton_sequencer_server::bft_admin::BftAdminService::new(
            std::sync::Arc::clone(&peer_manager),
            std::sync::Arc::clone(&c),
            epoch_len,
        );
        let bft_pruning = canton_sequencer_server::bft_admin::BftPruningAdminService::new(
            ord_store.clone(),
            Some(std::sync::Arc::clone(&c)),
        );

        let connect_stop = std::sync::Arc::clone(&stop);
        let connect_task = tokio::spawn(async move {
            if let Err(e) = canton_sequencer_server::serve_connect_with_bft_admin(
                public_bind,
                admin_bind,
                config,
                connect,
                Some(std::sync::Arc::clone(&connect_stop)),
                Some((bft_admin, bft_pruning)),
            )
            .await
            {
                eprintln!("BFT sequencer public API stopped: {e}");
                connect_stop.notify_waiters();
            }
        });
        let p2p_res = canton_sequencer_server::bft_p2p::serve_with_options(
            p2p_bind,
            physical,
            registry,
            &identity,
            (ext_host, ext_port, own_tls_for_endpoint),
            Some(c),
            String::new(),
            canton_sequencer_server::bft_p2p::BftServeOptions {
                peers: parsed_peers,
                server_tls,
                default_client_tls,
                peer_manager: Some(peer_manager),
                ord_store: ord_store.clone(),
                shutdown: Some(stop),
            },
        )
        .await;
        let _ = connect_task.await;
        if let Some(store) = ord_store {
            let _ = store.flush();
        }
        p2p_res
    })
}

/// Puts a submission into the BFT orderer's mempool, or says why the mempool refused it (`MempoolModule`: `RequestRejected.QueueFull`).
fn mempool(
    ordering: &canton_sequencer_server::bft_p2p::Consensus,
    message_id: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if ordering.order_request("send", message_id, bytes.to_vec()) {
        Ok(())
    } else {
        Err(format!(
            "Mempool received client request but the queue is full ({}), rejecting",
            canton_sequencer_server::bft_p2p::MAX_MEMPOOL_QUEUE_SIZE
        ))
    }
}
