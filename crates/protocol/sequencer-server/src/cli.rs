//! The command line of the Rust sequencer, shared by the `rust-sequencer` binary and `canton-rs sequencer run` (G11: one executable with
//! the real role in it). Everything but the three positional values is read from the `RUST_SEQUENCER_*` environment variables.
/// Serves the sequencer on `address` as the synchronizer `name` until it is stopped (SIGINT or SIGTERM). With a state directory (or
/// `RUST_SEQUENCER_STATE_DIR`) the keys, the members, the topology and the events survive a restart. The `READY ...` lines go to `out`.
///
/// [CANTON-NOTE: WHY] Library crates print nothing themselves (`S-QUAL-003`): the binary passes a sink that writes to stdout, where
/// supervisors and scripts read the `READY ...` lines.
pub fn run(
    address: std::net::SocketAddr,
    name: &str,
    state_dir: Option<std::path::PathBuf>,
    out: &dyn Fn(&str),
) -> Result<(), String> {
    run_in(address, name, state_dir, None, out)
}

/// Like [`run`], with the state kept in `state_store` (a database) instead of a directory when given.
pub fn run_in(
    address: std::net::SocketAddr,
    name: &str,
    state_dir: Option<std::path::PathBuf>,
    state_store: Option<std::sync::Arc<dyn canton_participant::state_store::StateStore>>,
    out: &dyn Fn(&str),
) -> Result<(), String> {
    let name = name.to_string();
    let state_dir = state_dir.or_else(|| {
        std::env::var("RUST_SEQUENCER_STATE_DIR")
            .ok()
            .map(std::path::PathBuf::from)
    });
    // mediator groups, each with its own mediator (RUST_SEQUENCER_MEDIATOR_GROUPS, one by default)
    let groups = std::env::var("RUST_SEQUENCER_MEDIATOR_GROUPS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    // a logical upgrade's successor (RUST_SEQUENCER_SUCCESSOR_OF = the predecessor's state directory): the state directory starts as the
    // predecessor's keys, members and topology one serial on, without its events
    if let Ok(predecessor) = std::env::var("RUST_SEQUENCER_SUCCESSOR_OF") {
        let dir = state_dir
            .as_ref()
            .ok_or("a successor needs its own state directory")?;
        let serial = crate::persistence::seed_successor(std::path::Path::new(&predecessor), dir)
            .map_err(|e| format!("the predecessor's state directory: {e}"))?;
        out(&format!("READY successor serial={serial} of {predecessor}"));
    }
    let admin_address = std::env::var("CANTON_RS_SEQUENCER_ADMIN_BIND")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|s| {
            s.parse::<std::net::SocketAddr>()
                .map_err(|e| format!("CANTON_RS_SEQUENCER_ADMIN_BIND ({s}): {e}"))
        })
        .transpose()?;
    let official_pg_url = std::env::var("CANTON_RS_OFFICIAL_SEQUENCER_PG_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let seeded_official = match &official_pg_url {
        Some(url) => {
            let target =
                canton_participant::pgconn::PgTarget::from_url_or_jdbc(url, None, None, None)
                    .map_err(|e| format!("CANTON_RS_OFFICIAL_SEQUENCER_PG_URL: {e}"))?;
            let mut client = canton_participant::pgconn::connect(&target)
                .map_err(|e| format!("official sequencer database: {e}"))?;
            client
                .batch_execute("SET default_transaction_read_only = on")
                .map_err(|e| e.to_string())?;
            let sync =
                canton_participant::official_state::read_official_synchronizer(&mut client, None)?;
            // `SynchronizerKeys::for_sequencer` gives an unused placeholder mediator namespace so external `MED::...`
            // members in the adopted topology serve confirmation requests as separate processes rather than an embedded mediator.
            let keys =
                std::sync::Arc::new(crate::synchronizer_state::SynchronizerKeys::for_sequencer(
                    sync.keys.namespace_seed,
                    sync.keys.signing_seed,
                    sync.keys.sequencer_auth_seed,
                ));
            let config = crate::SynchronizerConfig {
                name: sync.synchronizer_name.clone(),
                namespace_fingerprint: sync.synchronizer_namespace.clone(),
                sequencer_name: sync.keys.name.clone(),
                sequencer_fingerprint: sync.keys.namespace_fingerprint.clone(),
                keys,
                serial: sync.serial,
            };
            let self_member = format!("SEQ::{}", config.sequencer_uid());
            let store =
                std::sync::Arc::new(crate::synchronizer_state::TopologyStore::from_official(
                    &config.synchronizer_uid(),
                    config.serial,
                    &self_member,
                    sync.topology_transactions,
                )?);
            let registry = std::sync::Arc::new(crate::onboarding::Registry::default());
            for member in store.registered_members() {
                registry.insert(member);
            }
            let connect = crate::ConnectService::open_seeded(
                config.clone(),
                store,
                registry,
                state_store.clone(),
                state_dir.as_deref(),
            )
            .map_err(|e| format!("the seeded sequencer state: {e}"))?;
            connect.sequencer().follow_mediators();
            connect
                .sequencer()
                .advance_clock_to_floor(sync.clock_floor_micros);
            Some((config, connect))
        }
        None => None,
    };
    let config = match (&seeded_official, &state_store, &state_dir) {
        (Some((config, _)), _, _) => config.clone(),
        (None, Some(store), _) => {
            crate::new_synchronizer_in_store(store.as_ref(), &name, "rs1", groups)
                .map_err(|e| format!("the keys kept in the {}: {e}", store.describe()))?
        }
        (None, None, Some(dir)) => crate::new_synchronizer_in(dir, &name, "rs1", groups)
            .map_err(|e| format!("the state directory's keys: {e}"))?,
        (None, None, None) => crate::new_synchronizer_with_groups(&name, "rs1", groups),
    };
    out(&format!(
        "READY synchronizer={}",
        config.physical_synchronizer_id()
    ));
    out(&format!("READY sequencer={}", config.sequencer_uid()));
    // optional TLS: files with the PEM certificate chain and the PEM private key (RUST_SEQUENCER_TLS_CERT, RUST_SEQUENCER_TLS_KEY)
    let tls = match (
        std::env::var("RUST_SEQUENCER_TLS_CERT"),
        std::env::var("RUST_SEQUENCER_TLS_KEY"),
    ) {
        (Ok(cert), Ok(key)) => Some((
            std::fs::read_to_string(cert).map_err(|e| format!("the TLS certificate file: {e}"))?,
            std::fs::read_to_string(key).map_err(|e| format!("the TLS key file: {e}"))?,
        )),
        _ => None,
    };
    let tls_client_ca = match std::env::var("RUST_SEQUENCER_TLS_CLIENT_CA") {
        Ok(ca) => {
            Some(std::fs::read_to_string(ca).map_err(|e| format!("the TLS client CA file: {e}"))?)
        }
        Err(_) => None,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    // SIGINT or SIGTERM: the health watchers are told NOT_SERVING and the server stops (the journal needs nothing more: every line is synced)
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
            stop.notify_one();
        });
    }
    let options = crate::ServeOptions {
        // optional periodic ticks (RUST_SEQUENCER_TICK_MS, none by default: a tick follows every topology change)
        tick_interval: std::env::var("RUST_SEQUENCER_TICK_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|ms| *ms > 0)
            .map(std::time::Duration::from_millis),
        state_dir,
        state_store,
        tls,
        tls_client_ca,
        // how often the running server shortens its journal (RUST_SEQUENCER_COMPACT_SECONDS; with a state directory)
        compact_every: std::env::var("RUST_SEQUENCER_COMPACT_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(std::time::Duration::from_secs),
        // BFT ordering mode (RUST_SEQUENCER_BFT_F = f, 3f + 1 ordering nodes)
        bft_f: std::env::var("RUST_SEQUENCER_BFT_F")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|f| *f >= 1),
        // the operator's control file (RUST_SEQUENCER_CONTROL): an upgrade announcement, traffic control on or off, and in BFT mode
        // the ordering nodes' faults
        control: std::env::var("RUST_SEQUENCER_CONTROL")
            .ok()
            .map(std::path::PathBuf::from),
        // the mediators as processes of their own (RUST_SEQUENCER_EXTERNAL_MEDIATOR=1; needs the state directory)
        external_mediator: std::env::var("RUST_SEQUENCER_EXTERNAL_MEDIATOR")
            .is_ok_and(|v| v == "1"),
        shutdown: Some(stop),
        metrics_address: std::env::var("CANTON_RS_SEQUENCER_METRICS_BIND")
            .ok()
            .and_then(|s| s.parse().ok()),
        // the administration services (CANTON_RS_SEQUENCER_ADMIN_BIND): not on the public port
        admin_address,
    };
    runtime
        .block_on(async move {
            match seeded_official {
                Some((_, connect)) => {
                    crate::serve_seeded_with(address, admin_address, config, connect, options).await
                }
                None => crate::serve_with(address, config, options).await,
            }
        })
        .map_err(|e| e.to_string())
}
