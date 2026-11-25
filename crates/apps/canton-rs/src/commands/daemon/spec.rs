use std::collections::BTreeMap;

use canton_participant::hocon::{parse_file, Hocon};
use ledger_json_api::canton_log::emit;

use super::super::supervisor::manifest::{
    append_mode_b_extra_services, check_port_collisions, ModeBManifestConfig,
};
use super::super::supervisor::{
    DaemonServiceSpec, DaemonSpec, NodePorts, NodeRole, RestartPolicy, TokenSource,
    DEFAULT_SHUTDOWN_TIMEOUT_SECS,
};
use super::bootstrap::parse_bootstrap;
use super::official::{
    default_dar_for_participant, open_backend_store, probe_official_sequencer, resolve_connect_url,
    seed_identity, seed_mediator_identity,
};
use super::{
    check_port_offset, configuration_coverage, log_encoder_str, node_unapplied_keys,
    participant_auth_mode, Backend, DaemonArgs,
};

/// Normalizes a legacy `canton.conf` + optional `bootstrap.sc` (+ Mode B extra services) into a single [`DaemonSpec`].
pub(crate) fn build_daemon_spec(
    args: &DaemonArgs,
    mode_b: Option<&ModeBManifestConfig>,
) -> Result<DaemonSpec, String> {
    let config_path = args.config.as_ref().ok_or_else(|| {
        "give '-c canton.conf' or a supervisor subcommand such as 'canton-rs daemon up -f canton-daemon.yaml' (see 'canton-rs daemon --help')".to_string()
    })?;
    let cli_token = match (&args.token_env, &args.token_file) {
        (Some(_), Some(_)) => {
            return Err("give either '--token-env' or '--token-file', not both".to_string());
        }
        (Some(var), None) => Some(TokenSource::Env(var.clone())),
        (None, Some(path)) => Some(TokenSource::File(path.clone())),
        (None, None) => None,
    };
    let conf = parse_file(config_path, &|n| std::env::var(n).ok())
        .map_err(|e| format!("Cannot read {}: {e}", config_path.display()))?;
    let (applied, harmless, not_applied) = configuration_coverage(&conf);
    let say = |level: &str, context: &str, message: &str| {
        if !args.worker && mode_b.is_none() {
            emit(
                args.log_encoder,
                level,
                "canton-rs.daemon",
                context,
                message,
            );
        }
    };
    say(
        "INFO",
        "",
        &format!(
            " Configuration {}: {applied} keys applied, {harmless} ignored without effect, {} not applied by canton-rs",
            config_path.display(),
            not_applied.len()
        ),
    );
    // [CANTON-NOTE: SEMANTICS] A key the daemon does not apply is said out loud; with `--strict-config` it stops the start instead, so a deployment that
    // relies on such a key (TLS, a parameter, the sequencer type) is never run without it unnoticed.
    if args.strict_config && !not_applied.is_empty() {
        return Err(format!(
            "--strict-config: {} configuration key(s) are not applied by canton-rs: {}",
            not_applied.len(),
            not_applied.join(", ")
        ));
    }
    for path in not_applied.iter().take(12) {
        say("WARN", "", &format!("   not applied: {path}"));
    }
    if not_applied.len() > 12 {
        say(
            "WARN",
            "",
            &format!("   ... and {} more", not_applied.len() - 12),
        );
    }

    let names = |kind: &str| -> Vec<String> {
        conf.get(&format!("canton.{kind}"))
            .map(|h| h.keys().into_iter().map(String::from).collect())
            .unwrap_or_default()
    };
    let (sequencers, mediators, participants) = (
        names("sequencers"),
        names("mediators"),
        names("participants"),
    );
    let all_nodes: Vec<&str> = sequencers
        .iter()
        .chain(&mediators)
        .chain(&participants)
        .map(String::as_str)
        .collect();
    let offset = args.port_offset;
    check_port_offset(&conf, offset)?;
    let port_of = |kind: &str, name: &str, tail: &str| -> Option<u16> {
        conf.get(&format!("canton.{kind}.{name}.{tail}"))
            .and_then(Hocon::as_u16)
            .and_then(|p| super::super::supervisor::doctor::shift_port(p, offset))
    };
    let bootstrap = match &args.bootstrap {
        Some(path) => {
            let script = std::fs::read_to_string(path)
                .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
            Some(parse_bootstrap(&script, &all_nodes)?)
        }
        None => None,
    };
    let mut synchronizer = bootstrap
        .as_ref()
        .map_or_else(|| "canton".to_string(), |b| b.synchronizer_name.clone());
    std::fs::create_dir_all(&args.state_dir).map_err(|e| e.to_string())?;
    let state = std::fs::canonicalize(&args.state_dir).map_err(|e| e.to_string())?;
    super::super::supervisor::engine::mark_state_dir_if_empty(&state);

    let mut bft_nets: BTreeMap<String, super::super::bft_config::BftNetwork> = BTreeMap::new();
    for seq in &sequencers {
        if conf
            .get(&format!("canton.sequencers.{seq}.sequencer.config"))
            .is_some()
            || sequencers.len() > 1
        {
            let net =
                super::super::bft_config::bft_network(&conf, seq)?.with_port_offset(offset)?;
            bft_nets.insert(seq.clone(), net);
        }
    }
    let is_bft = sequencers.len() > 1 || !bft_nets.is_empty();
    let global_no_restart = args.no_restart || mode_b.is_some_and(|m| m.no_restart);
    let restart = if global_no_restart {
        RestartPolicy::No
    } else {
        RestartPolicy::UnlessStopped
    };
    let enc_str = mode_b
        .map(|m| m.log_encoder.as_str())
        .unwrap_or_else(|| log_encoder_str(args.log_encoder))
        .to_string();

    let mut seq_endpoints: Vec<(String, u16, String)> = Vec::new();
    let mut services: Vec<DaemonServiceSpec> = Vec::new();

    if is_bft {
        let mut seq_backends = Vec::new();
        let mut seq_identities = Vec::new();
        for seq in &sequencers {
            let backend = Backend::of(config_path, args, &state, "sequencers", seq)?;
            let store = open_backend_store(&backend)?;
            let id =
                canton_sequencer_server::sequencer_identity::SequencerIdentity::load_or_create_in(
                    store.as_ref(),
                    seq,
                )?;
            seq_backends.push((seq.clone(), backend));
            seq_identities.push(id);
        }
        let mut med_backends = Vec::new();
        let mut med_identities = Vec::new();
        for med in &mediators {
            let backend = Backend::of(config_path, args, &state, "mediators", med)?;
            let store = open_backend_store(&backend)?;
            let id = canton_sequencer_server::mediator_identity::MediatorIdentity::load_or_create(
                store.as_ref(),
                med,
            )?;
            med_backends.push((med.clone(), backend));
            med_identities.push(id);
        }
        let seq_refs: Vec<_> = seq_identities.iter().collect();
        let med_refs: Vec<_> = med_identities.iter().collect();
        let (owners, threshold) = match &bootstrap {
            Some(b) => (b.owners.clone(), b.threshold),
            None => (sequencers.clone(), sequencers.len().max(1) as i32),
        };
        let (namespace, genesis_txs) =
            canton_sequencer_server::synchronizer_state::build_bft_genesis(
                &synchronizer,
                &seq_refs,
                &med_refs,
                &owners,
                threshold,
            )?;
        let genesis_path = state.join("bft-genesis.tx");
        std::fs::write(
            &genesis_path,
            canton_sequencer_server::mediator_identity::onboarding_file(&genesis_txs),
        )
        .map_err(|e| format!("{}: {e}", genesis_path.display()))?;

        let bft_peer_count = Some(seq_backends.len());
        for (sequencer, seq_state) in &seq_backends {
            let raw_public = conf
                .get(&format!("canton.sequencers.{sequencer}.public-api.port"))
                .and_then(Hocon::as_u16)
                .ok_or_else(|| format!("the sequencer {sequencer} has no public-api.port"))?;
            let public = super::super::supervisor::doctor::shift_port(raw_public, offset)
                .ok_or_else(|| format!("port {raw_public} + offset {offset} overflows u16"))?;
            let net = bft_nets
                .get(sequencer)
                .ok_or_else(|| format!("missing BFT network config for {sequencer}"))?;
            let url = format!("http://127.0.0.1:{public}");
            let admin = port_of("sequencers", sequencer, "admin-api.port");
            let mport = port_of("sequencers", sequencer, "metrics.port");
            let p2p_port = net
                .bind
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok());

            let mut argv = vec![
                "sequencer".into(),
                "run-bft".into(),
                "--name".into(),
                sequencer.clone(),
                "--synchronizer".into(),
                synchronizer.clone(),
                "--namespace".into(),
                namespace.clone(),
                "--genesis-file".into(),
                genesis_path.display().to_string(),
                "--public-bind".into(),
                format!("127.0.0.1:{public}"),
                "--p2p-bind".into(),
                net.bind.clone(),
                "--external".into(),
                net.external.clone(),
            ];
            if let Some(adm) = admin {
                argv.extend(["--admin-bind".into(), format!("127.0.0.1:{adm}")]);
            }
            for peer in &net.peers {
                argv.extend(["--peer".into(), peer.clone()]);
            }
            if let Some(stls) = &net.server_tls {
                argv.extend([
                    "--p2p-tls-cert".into(),
                    stls.cert_chain_file.display().to_string(),
                    "--p2p-tls-key".into(),
                    stls.private_key_file.display().to_string(),
                ]);
                if let Some(ca) = &stls.trust_collection_file {
                    argv.extend(["--p2p-tls-ca".into(), ca.display().to_string()]);
                }
            }
            if let Some(ptls) = net.peer_tls.values().next() {
                if let Some(ca) = &ptls.trust_collection_file {
                    argv.extend(["--peer-tls-ca".into(), ca.display().to_string()]);
                }
                if let Some(cert) = &ptls.client_cert_file {
                    argv.extend(["--peer-tls-cert".into(), cert.display().to_string()]);
                }
                if let Some(key) = &ptls.client_key_file {
                    argv.extend(["--peer-tls-key".into(), key.display().to_string()]);
                }
            }
            if let Some(len) = net.epoch_length {
                argv.extend(["--epoch-length".into(), len.to_string()]);
            }
            if let Some(ms) = net.view_change_timeout_ms {
                argv.extend(["--view-change-timeout-ms".into(), ms.to_string()]);
            }
            if let Some(mp) = mport {
                argv.extend(["--metrics-port".into(), mp.to_string()]);
            }
            let mut env = BTreeMap::new();
            seq_state.give_args_env(&mut argv, &mut env);
            if let Backend::Database { url: db_url, .. } = seq_state {
                env.insert("CANTON_RS_ORD_PG_URL".into(), db_url.clone());
            }

            let (health_url, readiness_url, status_url, metrics_url) = match mport {
                Some(mp) => (
                    Some(format!("http://127.0.0.1:{mp}/livez")),
                    Some(format!("http://127.0.0.1:{mp}/readyz")),
                    Some(format!("http://127.0.0.1:{mp}/status")),
                    Some(format!("http://127.0.0.1:{mp}/metrics")),
                ),
                None => (None, None, None, None),
            };
            services.push(DaemonServiceSpec {
                slot_id: services.len(),
                name: sequencer.clone(),
                role: NodeRole::Sequencer,
                ports: NodePorts {
                    public: Some(public),
                    http_json: None,
                    grpc_ledger: None,
                    admin,
                    metrics: mport,
                    p2p: p2p_port,
                },
                restart,
                depends_on: Vec::new(),
                dars: Vec::new(),
                dar_dir: None,
                ledger_of: None,
                ledger_url: None,
                automation_interval_ms: None,
                storage: seq_state.to_storage_spec(),
                argv,
                env,
                health_url,
                readiness_url,
                status_url,
                metrics_url,
                xray_url: None,
                xray_override: None,
                state_dir: seq_state.node_state_dir(&state, sequencer),
                auth_mode: "open".to_string(),
                config_path: Some(config_path.clone()),
                bootstrap_path: args.bootstrap.clone(),
                port_offset: offset,
                same_identity: args.same_identity,
                official_write: args.official_write,
                config_applied_count: applied,
                config_not_applied_keys: node_unapplied_keys(&not_applied, "sequencers", sequencer),
                ready_line_prefix: Some("READY sequencer=".to_string()),
                bft_peer_count,
                group: Some("synchronizer".to_string()),
                profiles: Vec::new(),
                synchronizer_domain: Some(synchronizer.clone()),
                also_synchronizers: Vec::new(),
                limits: None,
                token: None,
                bind_host: Some("127.0.0.1".to_string()),
            });
            seq_endpoints.push((sequencer.clone(), raw_public, url));
        }

        for (idx, (mediator, med_state)) in med_backends.iter().enumerate() {
            let (seq_name, _, seq_url) = &seq_endpoints[idx % seq_endpoints.len()];
            let status = port_of("mediators", mediator, "admin-api.port").unwrap_or(0);
            let mut argv = vec![
                "mediator".into(),
                "run".into(),
                "--sequencer-url".into(),
                seq_url.clone(),
            ];
            let mut env = BTreeMap::new();
            med_state.give_args_env(&mut argv, &mut env);
            if status != 0 {
                argv.extend(["--port".into(), status.to_string()]);
            }
            let (health_url, readiness_url, status_url, metrics_url, admin_port) = if status != 0 {
                (
                    Some(format!("http://127.0.0.1:{status}/livez")),
                    Some(format!("http://127.0.0.1:{status}/readyz")),
                    Some(format!("http://127.0.0.1:{status}/status")),
                    Some(format!("http://127.0.0.1:{status}/metrics")),
                    Some(status),
                )
            } else {
                (None, None, None, None, None)
            };
            services.push(DaemonServiceSpec {
                slot_id: services.len(),
                name: mediator.clone(),
                role: NodeRole::Mediator,
                ports: NodePorts {
                    public: None,
                    http_json: None,
                    grpc_ledger: None,
                    admin: admin_port,
                    metrics: admin_port,
                    p2p: None,
                },
                restart,
                depends_on: vec![seq_name.clone()],
                dars: Vec::new(),
                dar_dir: None,
                ledger_of: None,
                ledger_url: None,
                automation_interval_ms: None,
                storage: med_state.to_storage_spec(),
                argv,
                env,
                health_url,
                readiness_url,
                status_url,
                metrics_url,
                xray_url: None,
                xray_override: None,
                state_dir: med_state.node_state_dir(&state, mediator),
                auth_mode: "open".to_string(),
                // [CANTON-NOTE: INVARIANT] BFT genesis already carries mediator onboarding txs,
                // so `config_path = Some(...)` tells the supervisor not to run `sequencer add-mediator`.
                config_path: Some(config_path.clone()),
                bootstrap_path: args.bootstrap.clone(),
                port_offset: offset,
                same_identity: args.same_identity,
                official_write: args.official_write,
                config_applied_count: applied,
                config_not_applied_keys: node_unapplied_keys(&not_applied, "mediators", mediator),
                ready_line_prefix: Some("READY mediator=".to_string()),
                bft_peer_count: None,
                group: Some("synchronizer".to_string()),
                profiles: Vec::new(),
                synchronizer_domain: Some(synchronizer.clone()),
                also_synchronizers: Vec::new(),
                limits: None,
                token: None,
                bind_host: Some("127.0.0.1".to_string()),
            });
        }
    } else {
        let [sequencer] = sequencers.as_slice() else {
            return Err(format!(
                "the daemon starts one synchronizer: the configuration has {} sequencers ({})",
                sequencers.len(),
                sequencers.join(", ")
            ));
        };
        let raw_public = conf
            .get(&format!("canton.sequencers.{sequencer}.public-api.port"))
            .and_then(Hocon::as_u16)
            .ok_or_else(|| format!("the sequencer {sequencer} has no public-api.port"))?;
        let public = super::super::supervisor::doctor::shift_port(raw_public, offset)
            .ok_or_else(|| format!("port {raw_public} + offset {offset} overflows u16"))?;
        let url = format!("http://127.0.0.1:{public}");
        let official_seq = if args.same_identity {
            probe_official_sequencer(config_path, args, sequencer)?
        } else {
            None
        };
        if bootstrap.is_none() {
            if let Some((_, sync)) = &official_seq {
                synchronizer = sync.synchronizer_name.clone();
            }
        }
        let adopted_store = match &official_seq {
            Some((_, sync)) => Some(
                canton_sequencer_server::synchronizer_state::TopologyStore::from_official(
                    &sync.synchronizer_uid,
                    sync.serial,
                    &format!("SEQ::{}", sync.keys.uid()),
                    sync.topology_transactions.clone(),
                )?,
            ),
            None => None,
        };
        let seq_state = Backend::of(config_path, args, &state, "sequencers", sequencer)?;
        let admin = port_of("sequencers", sequencer, "admin-api.port");
        let mport = port_of("sequencers", sequencer, "metrics.port");
        let mut seq_argv = vec![
            "sequencer".into(),
            "run".into(),
            "--bind".into(),
            "127.0.0.1".into(),
            "--port".into(),
            public.to_string(),
            "--name".into(),
            synchronizer.clone(),
        ];
        if let Some(mp) = mport {
            seq_argv.extend(["--metrics-port".into(), mp.to_string()]);
        }
        let mut seq_env = BTreeMap::new();
        if let Some(adm) = admin {
            seq_env.insert(
                "CANTON_RS_SEQUENCER_ADMIN_BIND".into(),
                format!("127.0.0.1:{adm}"),
            );
        }
        if let Some((official_url, _)) = &official_seq {
            seq_env.insert(
                "CANTON_RS_OFFICIAL_SEQUENCER_PG_URL".into(),
                official_url.clone(),
            );
        }
        seq_state.give_args_env(&mut seq_argv, &mut seq_env);

        let (health_url, readiness_url, status_url, metrics_url) = match mport {
            Some(mp) => (
                Some(format!("http://127.0.0.1:{mp}/livez")),
                Some(format!("http://127.0.0.1:{mp}/readyz")),
                Some(format!("http://127.0.0.1:{mp}/status")),
                Some(format!("http://127.0.0.1:{mp}/metrics")),
            ),
            None => (None, None, None, None),
        };
        services.push(DaemonServiceSpec {
            slot_id: services.len(),
            name: sequencer.clone(),
            role: NodeRole::Sequencer,
            ports: NodePorts {
                public: Some(public),
                http_json: None,
                grpc_ledger: None,
                admin,
                metrics: mport,
                p2p: None,
            },
            restart,
            depends_on: Vec::new(),
            dars: Vec::new(),
            dar_dir: None,
            ledger_of: None,
            ledger_url: None,
            automation_interval_ms: None,
            storage: seq_state.to_storage_spec(),
            argv: seq_argv,
            env: seq_env,
            health_url,
            readiness_url,
            status_url,
            metrics_url,
            xray_url: None,
            xray_override: None,
            state_dir: seq_state.node_state_dir(&state, sequencer),
            auth_mode: "open".to_string(),
            config_path: Some(config_path.clone()),
            bootstrap_path: args.bootstrap.clone(),
            port_offset: offset,
            same_identity: args.same_identity,
            official_write: args.official_write,
            config_applied_count: applied,
            config_not_applied_keys: node_unapplied_keys(&not_applied, "sequencers", sequencer),
            ready_line_prefix: Some("READY sequencer=".to_string()),
            bft_peer_count: None,
            group: Some("synchronizer".to_string()),
            profiles: Vec::new(),
            synchronizer_domain: Some(synchronizer.clone()),
            also_synchronizers: Vec::new(),
            limits: None,
            token: None,
            bind_host: Some("127.0.0.1".to_string()),
        });
        seq_endpoints.push((sequencer.clone(), raw_public, url.clone()));

        for mediator in &mediators {
            let med_state = Backend::of(config_path, args, &state, "mediators", mediator)?;
            let seeded_uid = if args.same_identity {
                seed_mediator_identity(config_path, args, mediator, &med_state)?
            } else {
                None
            };
            let already_active = seeded_uid
                .as_deref()
                .zip(adopted_store.as_ref())
                .is_some_and(|(uid, store)| store.has_active_mediator(uid));

            let status = port_of("mediators", mediator, "admin-api.port").unwrap_or(0);
            let mut med_argv = vec![
                "mediator".into(),
                "run".into(),
                "--sequencer-url".into(),
                url.clone(),
            ];
            let mut med_env = BTreeMap::new();
            med_state.give_args_env(&mut med_argv, &mut med_env);
            if status != 0 {
                med_argv.extend(["--port".into(), status.to_string()]);
            }
            let (health_url, readiness_url, status_url, metrics_url, admin_port) = if status != 0 {
                (
                    Some(format!("http://127.0.0.1:{status}/livez")),
                    Some(format!("http://127.0.0.1:{status}/readyz")),
                    Some(format!("http://127.0.0.1:{status}/status")),
                    Some(format!("http://127.0.0.1:{status}/metrics")),
                    Some(status),
                )
            } else {
                (None, None, None, None, None)
            };
            services.push(DaemonServiceSpec {
                slot_id: services.len(),
                name: mediator.clone(),
                role: NodeRole::Mediator,
                ports: NodePorts {
                    public: None,
                    http_json: None,
                    grpc_ledger: None,
                    admin: admin_port,
                    metrics: admin_port,
                    p2p: None,
                },
                restart,
                depends_on: vec![sequencer.clone()],
                dars: Vec::new(),
                dar_dir: None,
                ledger_of: None,
                ledger_url: None,
                automation_interval_ms: None,
                storage: med_state.to_storage_spec(),
                argv: med_argv,
                env: med_env,
                health_url,
                readiness_url,
                status_url,
                metrics_url,
                xray_url: None,
                xray_override: None,
                state_dir: med_state.node_state_dir(&state, mediator),
                auth_mode: "open".to_string(),
                // [CANTON-NOTE: INVARIANT] When not yet onboarded onto a freshly started single sequencer,
                // keep `config_path: None` so `engine::spawn_slot_blocking` runs `mediator init` -> `onboarding`
                // -> `sequencer add-mediator` after the sequencer slot opens its port.
                config_path: if already_active {
                    Some(config_path.clone())
                } else {
                    None
                },
                bootstrap_path: args.bootstrap.clone(),
                port_offset: offset,
                same_identity: args.same_identity,
                official_write: args.official_write,
                config_applied_count: applied,
                config_not_applied_keys: node_unapplied_keys(&not_applied, "mediators", mediator),
                ready_line_prefix: Some("READY mediator=".to_string()),
                bft_peer_count: None,
                group: Some("synchronizer".to_string()),
                profiles: Vec::new(),
                synchronizer_domain: Some(synchronizer.clone()),
                also_synchronizers: Vec::new(),
                limits: None,
                token: None,
                bind_host: Some("127.0.0.1".to_string()),
            });
        }
    }

    // Participants: `json-api` with protocol node, gRPC Ledger API, and optional Admin API.
    let enable_xray = args.xray || mode_b.is_some_and(|m| m.xray);
    for (part_idx, participant) in participants.iter().enumerate() {
        let conn = bootstrap
            .as_ref()
            .and_then(|b| b.connections.iter().find(|(n, _, _)| n == participant));
        if bootstrap.is_some() && conn.is_none() {
            say(
                "WARN",
                &format!("participant={participant}"),
                &format!(" Participant {participant}: not connected to a synchronizer by the bootstrap script, not started"),
            );
            continue;
        }
        let (seq_dep, url) = match conn {
            Some((_, seq_or_url, _))
                if seq_or_url.starts_with("http://") || seq_or_url.starts_with("https://") =>
            {
                let chosen = resolve_connect_url(seq_or_url, &seq_endpoints)
                    .unwrap_or_else(|| seq_or_url.clone());
                let dep = seq_endpoints
                    .iter()
                    .find(|(_, _, u)| u == &chosen)
                    .map(|(n, _, _)| n.clone());
                (dep, chosen)
            }
            Some((_, seq_name, _)) if !seq_name.is_empty() => {
                let found = seq_endpoints.iter().find(|(name, _, _)| name == seq_name);
                match found {
                    Some((n, _, u)) => (Some(n.clone()), u.clone()),
                    None => {
                        let (n, _, u) = &seq_endpoints[part_idx % seq_endpoints.len()];
                        (Some(n.clone()), u.clone())
                    }
                }
            }
            _ => {
                let (n, _, u) = &seq_endpoints[part_idx % seq_endpoints.len()];
                (Some(n.clone()), u.clone())
            }
        };
        let sync_alias = conn
            .and_then(|(_, _, a)| (!a.is_empty()).then_some(a.clone()))
            .unwrap_or_else(|| synchronizer.clone());
        let dar = match &args.dar {
            Some(d) => d.clone(),
            None => default_dar_for_participant(config_path, args, participant, &state)?,
        };
        let http = port_of("participants", participant, "http-ledger-api.port");
        let grpc_port = port_of("participants", participant, "ledger-api.port");
        let admin_port = port_of("participants", participant, "admin-api.port");

        let mut argv = vec![
            "json-api".into(),
            "--canton-conf".into(),
            config_path.display().to_string(),
            "--conf-participant".into(),
            participant.clone(),
            "--sequencer".into(),
            url,
            "--participant-name".into(),
            participant.clone(),
            "--sequencer-alias".into(),
            sync_alias,
            "--dar".into(),
            dar.display().to_string(),
        ];
        if http.is_some() {
            argv.push("--conf-port".into());
        } else {
            argv.extend(["--port".into(), "0".into()]);
        }
        let participant_state =
            Backend::of(config_path, args, &state, "participants", participant)?;
        if args.same_identity {
            seed_identity(config_path, args, participant, &participant_state)?;
            argv.push("--host-adopted-parties".into());
        }
        let mut env = BTreeMap::new();
        participant_state.give_args_env(&mut argv, &mut env);
        if args.official_write {
            argv.push("--official-write".into());
        }
        if offset != 0 {
            argv.extend(["--conf-port-offset".into(), offset.to_string()]);
        }
        if enc_str != "text" {
            argv.extend(["--log-encoder".into(), enc_str.clone()]);
        }
        if grpc_port.is_some() {
            argv.push("--with-grpc".into());
        }
        if admin_port.is_some() {
            argv.push("--with-admin-api".into());
        }
        if let Some(addr) = &args.official_pg_addr {
            argv.extend(["--official-pg-addr".into(), addr.clone()]);
        }
        if args.official_write {
            // The URLs hold database passwords: they go to the child's environment, not its argv (visible in `ps`).
            let mut topology_urls = Vec::new();
            for (kind, names) in [("sequencers", &sequencers), ("mediators", &mediators)] {
                for name in names {
                    if let Ok(Some(target)) = ledger_json_api::canton_conf::node_database(
                        config_path,
                        kind,
                        name,
                        args.official_pg_addr.as_deref(),
                    ) {
                        topology_urls.push(ledger_json_api::canton_conf::pg_url(&target));
                    }
                }
            }
            if !topology_urls.is_empty() {
                env.insert(
                    "CANTON_RS_OFFICIAL_TOPOLOGY_URLS".into(),
                    topology_urls.join("\n"),
                );
            }
        }
        if let Some(cert) = &args.conf_auth_cert {
            argv.extend(["--conf-auth-cert".into(), cert.display().to_string()]);
        }
        if enable_xray {
            argv.push("--xray".into());
        }

        let mut deps = Vec::new();
        if let Some(s) = seq_dep {
            deps.push(s);
        }
        for med in &mediators {
            deps.push(med.clone());
        }

        let (health_url, readiness_url, status_url, metrics_url, xray_url) = match http {
            Some(hp) => (
                Some(format!("http://127.0.0.1:{hp}/livez")),
                Some(format!("http://127.0.0.1:{hp}/readyz")),
                Some(format!("http://127.0.0.1:{hp}/_telemetry")),
                Some(format!("http://127.0.0.1:{hp}/metrics")),
                enable_xray.then(|| format!("http://127.0.0.1:{hp}/_xray")),
            ),
            None => (None, None, None, None, None),
        };

        services.push(DaemonServiceSpec {
            slot_id: services.len(),
            name: participant.clone(),
            role: NodeRole::Participant,
            ports: NodePorts {
                public: None,
                http_json: http,
                grpc_ledger: grpc_port,
                admin: admin_port,
                metrics: http,
                p2p: None,
            },
            restart,
            depends_on: deps,
            dars: vec![dar],
            dar_dir: None,
            ledger_of: None,
            ledger_url: None,
            automation_interval_ms: None,
            storage: participant_state.to_storage_spec(),
            argv,
            env,
            health_url,
            readiness_url,
            status_url,
            metrics_url,
            xray_url,
            xray_override: None,
            state_dir: participant_state.node_state_dir(&state, participant),
            auth_mode: participant_auth_mode(&conf, participant, args.conf_auth_cert.as_deref()),
            config_path: Some(config_path.clone()),
            bootstrap_path: args.bootstrap.clone(),
            port_offset: offset,
            same_identity: args.same_identity,
            official_write: args.official_write,
            config_applied_count: applied,
            config_not_applied_keys: node_unapplied_keys(&not_applied, "participants", participant),
            ready_line_prefix: None,
            bft_peer_count: None,
            group: Some("participants".to_string()),
            profiles: Vec::new(),
            synchronizer_domain: Some(synchronizer.clone()),
            also_synchronizers: Vec::new(),
            limits: None,
            token: cli_token
                .clone()
                .or_else(|| mode_b.and_then(|m| m.token.clone())),
            bind_host: Some("127.0.0.1".to_string()),
        });
    }

    let mut ping_participants = Vec::new();
    if let Some(b) = &bootstrap {
        for (from, to) in &b.pings {
            let _from_port = port_of("participants", from, "admin-api.port").ok_or_else(|| {
                format!("{from}.health.ping({to}) requires admin-api.port on {from}")
            })?;
            let _to_port = port_of("participants", to, "admin-api.port").ok_or_else(|| {
                format!("{from}.health.ping({to}) requires admin-api.port on {to}")
            })?;
            ping_participants.push((from.clone(), to.clone()));
        }
    }

    if let Some(mb) = mode_b {
        append_mode_b_extra_services(&mut services, mb, &synchronizer, global_no_restart)?;
    }

    let logging = match mode_b {
        Some(mb) => mb.logging.clone(),
        None => super::super::supervisor::log_policy::LogPolicy {
            encoder: enc_str.clone(),
            max_bytes: args.log_max_bytes,
            max_files: args.log_max_files,
            ..super::super::supervisor::log_policy::LogPolicy::default()
        },
    };
    for svc in &mut services {
        logging.apply_child_env(&svc.name, &mut svc.env);
    }

    check_port_collisions(&services)?;

    let stack_name = mode_b
        .map(|m| m.name.clone())
        .unwrap_or_else(|| synchronizer.clone());

    let mut spec = DaemonSpec {
        name: stack_name,
        synchronizer,
        state_dir: state,
        metrics_port: args
            .metrics_port
            .or_else(|| mode_b.and_then(|m| m.metrics_port)),
        metrics_bind: mode_b
            .map(|m| m.metrics_bind.clone())
            .filter(|_| args.metrics_bind == "127.0.0.1")
            .unwrap_or_else(|| args.metrics_bind.clone()),
        log_encoder: enc_str,
        log_max_bytes: logging.max_bytes,
        log_max_files: logging.max_files,
        logging,
        trace_rate_limit_per_sec: mode_b
            .map(|m| m.trace_rate_limit_per_sec)
            .unwrap_or(args.trace_rate_limit),
        xray: enable_xray,
        no_restart: global_no_restart,
        max_restarts: mode_b.and_then(|m| m.max_restarts),
        shadow_verify: args.shadow_verify || mode_b.is_some_and(|m| m.shadow_verify),
        shadow_jvm_url: args
            .shadow_jvm_url
            .clone()
            .or_else(|| mode_b.and_then(|m| m.shadow_jvm_url.clone())),
        foreground_legacy_banner: false,
        shutdown_timeout_secs: DEFAULT_SHUTDOWN_TIMEOUT_SECS,
        manifest_path: None,
        canton_conf: Some(config_path.clone()),
        bootstrap: args.bootstrap.clone(),
        port_offset: offset,
        same_identity: args.same_identity,
        official_write: args.official_write,
        official_pg_addr: args.official_pg_addr.clone(),
        auth_cert: args.conf_auth_cert.clone(),
        strict_config: args.strict_config,
        wait_for_deps_secs: 60,
        cells: mode_b.map(|m| m.cells.clone()).unwrap_or_default(),
        remote_clusters: mode_b
            .map(|m| m.remote_clusters.clone())
            .unwrap_or_default(),
        scenarios: mode_b.map(|m| m.scenarios.clone()).unwrap_or_default(),
        services,
        ping_participants,
        dev_auth: false,
        observability: false,
        bind_addresses: Vec::new(),
    };
    spec.bind_addresses = super::super::supervisor::creds::collect_spec_bind_addresses(&spec);
    Ok(spec)
}
