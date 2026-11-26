use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::super::topology::{
    assign_cell_base_ports, CellIsolation, CellSpec, SynchronizerDomainSpec,
};
use super::super::{DaemonServiceSpec, NodeRole, RestartPolicy, StorageSpec};
use super::{parse_host_port, ModeBManifestConfig, RawServiceDecl};

pub(super) fn topo_sort_services(
    decls: Vec<RawServiceDecl>,
    pre_placed: &BTreeSet<String>,
) -> Result<Vec<RawServiceDecl>, String> {
    let mut names = pre_placed.clone();
    for d in &decls {
        if !names.insert(d.name.clone()) {
            return Err(format!("duplicate service name '{}'", d.name));
        }
    }
    for decl in &decls {
        for dep in &decl.depends_on {
            if !names.contains(dep) {
                return Err(format!(
                    "service '{}' depends_on unknown service '{dep}'",
                    decl.name
                ));
            }
            if dep == &decl.name {
                return Err(format!("service '{}' cannot depend on itself", decl.name));
            }
        }
    }

    let mut remaining = decls;
    let mut placed = pre_placed.clone();
    let mut ordered = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let mut progressed = false;
        let mut next_round = Vec::new();
        for decl in remaining {
            if decl.depends_on.iter().all(|d| placed.contains(d)) {
                placed.insert(decl.name.clone());
                ordered.push(decl);
                progressed = true;
            } else {
                next_round.push(decl);
            }
        }
        if !progressed {
            let stuck: Vec<String> = next_round.into_iter().map(|d| d.name).collect();
            return Err(format!(
                "cyclic dependency detected among services: {}",
                stuck.join(", ")
            ));
        }
        remaining = next_round;
    }
    Ok(ordered)
}

pub(super) struct ResolveServicesContext<'a> {
    pub(super) root_state_dir: &'a Path,
    pub(super) default_synchronizer: &'a str,
    pub(super) synchronizers: &'a BTreeMap<String, SynchronizerDomainSpec>,
    pub(super) cells: &'a BTreeMap<String, CellSpec>,
    pub(super) log_encoder: &'a str,
    pub(super) global_no_restart: bool,
    pub(super) xray: bool,
    pub(super) port_offset: u16,
    pub(super) default_bind: Option<&'a str>,
}

pub(crate) fn connect_host_for_bind(bind: &str) -> &str {
    match bind.trim() {
        "" | "0.0.0.0" => "127.0.0.1",
        "::" | "[::]" | "::1" | "[::1]" => "[::1]",
        other => other,
    }
}

pub(crate) fn format_bind_host_port(host: &str, port: u16) -> String {
    let h = host.trim();
    if h.contains(':') && !h.starts_with('[') {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

/// One resolved logical listener slot produced by `plan_raw_service_ports` (`label`, `base`,
/// `base + offset` if in `u16` range).
#[derive(Clone, Debug)]
pub(crate) struct ShiftedPortSlot {
    pub(crate) label: String,
    pub(crate) base: u16,
    pub(crate) resolved: Option<u16>,
}

/// Computes effective logical ports for one raw service after cell `base_port` allocation
/// and `port_offset` shifting via `doctor::shift_port`, without short-circuiting on overflow.
pub(crate) fn plan_raw_service_ports(
    raw: &RawServiceDecl,
    cells: &BTreeMap<String, CellSpec>,
    idx_in_cell: u16,
    offset: u16,
) -> Result<(super::super::NodePorts, Vec<ShiftedPortSlot>), String> {
    let mut base = raw.ports.clone();
    if let Some(g) = &raw.group {
        assign_cell_base_ports(cells, Some(g.as_str()), raw.role, idx_in_cell, &mut base)?;
    }

    let mut out = super::super::NodePorts::default();
    let mut slots = Vec::new();
    let shift_slot = |kind: &str, port: u16, slots: &mut Vec<ShiftedPortSlot>| -> Option<u16> {
        let resolved = super::super::doctor::shift_port(port, offset);
        slots.push(ShiftedPortSlot {
            label: format!("{}.{kind}", raw.name),
            base: port,
            resolved,
        });
        resolved
    };

    match raw.role {
        NodeRole::Sequencer => {
            let base_pub = base.public.unwrap_or(5018);
            out.public = shift_slot("public", base_pub, &mut slots);
            if raw.bft_group.is_some() {
                let base_p2p = base.p2p.unwrap_or_else(|| base_pub.saturating_add(2));
                out.p2p = shift_slot("p2p", base_p2p, &mut slots);
                if let Some(adm) = base.admin {
                    out.admin = shift_slot("admin", adm, &mut slots);
                }
                if let Some(m) = base.metrics {
                    out.metrics = if Some(m) == base.admin || m == base_pub || m == base_p2p {
                        super::super::doctor::shift_port(m, offset)
                    } else {
                        shift_slot("metrics", m, &mut slots)
                    };
                }
            } else {
                if let Some(adm) = base.admin {
                    out.admin = shift_slot("admin", adm, &mut slots);
                }
                if let Some(m) = base.metrics {
                    out.metrics = if Some(m) == base.admin || m == base_pub {
                        super::super::doctor::shift_port(m, offset)
                    } else {
                        shift_slot("metrics", m, &mut slots)
                    };
                } else {
                    out.metrics = out.admin;
                }
            }
        }
        NodeRole::Mediator => {
            let base_adm = base
                .admin
                .or(base.http_json)
                .or(base.public)
                .unwrap_or(5017);
            out.admin = shift_slot("admin", base_adm, &mut slots);
            if let Some(m) = base.metrics {
                out.metrics = if m == base_adm {
                    out.admin
                } else {
                    shift_slot("metrics", m, &mut slots)
                };
            }
        }
        NodeRole::Participant => {
            let base_json = base.http_json.or(base.public).unwrap_or(7575);
            out.http_json = shift_slot("json", base_json, &mut slots);
            if let Some(grpc) = base.grpc_ledger {
                out.grpc_ledger = shift_slot("grpc", grpc, &mut slots);
            }
            if let Some(adm) = base.admin {
                out.admin = shift_slot("admin", adm, &mut slots);
            }
            if let Some(m) = base.metrics {
                out.metrics =
                    if m == base_json || Some(m) == base.grpc_ledger || Some(m) == base.admin {
                        super::super::doctor::shift_port(m, offset)
                    } else {
                        shift_slot("metrics", m, &mut slots)
                    };
            }
        }
        NodeRole::Splice | NodeRole::Scan => {
            let default_port = if raw.role == NodeRole::Splice {
                5020
            } else {
                5012
            };
            let base_json = base.http_json.or(base.public).unwrap_or(default_port);
            out.http_json = shift_slot("json", base_json, &mut slots);
        }
        NodeRole::Pqs => {
            if let Some(json) = base.http_json {
                out.http_json = shift_slot("json", json, &mut slots);
            }
        }
    }

    Ok((out, slots))
}

/// Appends Mode B `services:` declarations (`splice`, `scan`, `pqs`, etc.) onto slots built from `canton.conf`.
pub(crate) fn append_mode_b_extra_services(
    services: &mut Vec<DaemonServiceSpec>,
    mode_b: &ModeBManifestConfig,
    synchronizer: &str,
    global_no_restart: bool,
) -> Result<(), String> {
    if mode_b.extra_services.is_empty() {
        return Ok(());
    }
    let pre_placed: BTreeSet<String> = services.iter().map(|s| s.name.clone()).collect();
    let ordered = topo_sort_services(mode_b.extra_services.clone(), &pre_placed)?;
    let has_scan_or_splice = ordered
        .iter()
        .any(|d| matches!(d.role, NodeRole::Splice | NodeRole::Scan));
    if has_scan_or_splice {
        let shared_scan_history = mode_b.state_dir.join("scan-history.jsonl");
        let scan_arg = shared_scan_history.display().to_string();
        if let Some(first_p) = services
            .iter_mut()
            .find(|s| s.role == NodeRole::Participant)
        {
            if !first_p.argv.iter().any(|a| a == "--scan-history") {
                first_p.argv.extend(["--scan-history".into(), scan_arg]);
            }
        }
    }
    let empty_syncs = BTreeMap::new();
    let ctx = ResolveServicesContext {
        root_state_dir: &mode_b.state_dir,
        default_synchronizer: synchronizer,
        synchronizers: &empty_syncs,
        cells: &mode_b.cells,
        log_encoder: &mode_b.log_encoder,
        global_no_restart,
        xray: mode_b.xray,
        port_offset: 0,
        default_bind: None,
    };
    append_resolved_services(services, ordered, &ctx)
}

/// Converts topologically sorted declarations into runnable `DaemonServiceSpec` slots.
pub(super) fn append_resolved_services(
    resolved: &mut Vec<DaemonServiceSpec>,
    ordered: Vec<RawServiceDecl>,
    ctx: &ResolveServicesContext<'_>,
) -> Result<(), String> {
    let shared_scan_history = ctx.root_state_dir.join("scan-history.jsonl");

    // Pre-compute cell-adjusted and offset-shifted ports via the single shared `plan_raw_service_ports` helper.
    let mut cell_slot_counts: BTreeMap<String, u16> = BTreeMap::new();
    let mut planned_ports = Vec::with_capacity(ordered.len());
    for raw in &ordered {
        let idx_in_cell = if let Some(g) = &raw.group {
            let entry = cell_slot_counts.entry(g.clone()).or_insert(0);
            let cur = *entry;
            *entry = entry.saturating_add(1);
            cur
        } else {
            0
        };
        let (ports, slots) = plan_raw_service_ports(raw, ctx.cells, idx_in_cell, ctx.port_offset)?;
        for s in &slots {
            if s.resolved.is_none() {
                return Err(format!(
                    "port overflow for {} ({} + {} > 65535)",
                    s.label, s.base, ctx.port_offset
                ));
            }
        }
        planned_ports.push(ports);
    }

    // Pre-collect BFT sequencer P2P mesh endpoints per `bft_group`.
    let mut bft_meshes: BTreeMap<String, Vec<(String, u16)>> = BTreeMap::new();
    for (raw, ports) in ordered.iter().zip(&planned_ports) {
        if raw.role == NodeRole::Sequencer {
            if let Some(bg) = &raw.bft_group {
                if let Some(p2p_port) = ports.p2p {
                    bft_meshes
                        .entry(bg.clone())
                        .or_default()
                        .push((raw.name.clone(), p2p_port));
                }
            }
        }
    }

    for (raw, mut ports) in ordered.into_iter().zip(planned_ports) {
        if raw.auth_cert.is_some() && raw.role != NodeRole::Participant {
            return Err(format!(
                "service '{}': auth_cert is only honoured on a participant (its Ledger API); a {:?} would run without it",
                raw.name, raw.role
            ));
        }
        let slot_id = resolved.len();
        let is_strict_cell = raw
            .group
            .as_deref()
            .and_then(|g| ctx.cells.get(g))
            .is_some_and(|c| c.isolation == CellIsolation::Strict);
        let node_state_dir = match (is_strict_cell, raw.group.as_deref()) {
            (true, Some(g)) => ctx.root_state_dir.join("cells").join(g).join(&raw.name),
            _ => ctx.root_state_dir.join(&raw.name),
        };
        let restart = if ctx.global_no_restart {
            RestartPolicy::No
        } else {
            raw.restart
        };
        let mut env = raw.extra_env.clone();
        let mut argv: Vec<String> = Vec::new();

        let eff_sync = raw
            .synchronizer
            .clone()
            .or_else(|| {
                raw.group
                    .as_deref()
                    .and_then(|g| ctx.cells.get(g))
                    .and_then(|c| c.synchronizer.clone())
            })
            .unwrap_or_else(|| ctx.default_synchronizer.to_string());

        let eff_bind = raw
            .bind_host
            .as_deref()
            .or(ctx.default_bind)
            .unwrap_or("127.0.0.1");
        let eff_connect = connect_host_for_bind(eff_bind);

        let mut health_url = None;
        let mut readiness_url = None;
        let mut status_url = None;
        let mut metrics_url = None;
        let mut xray_url = None;
        let mut ready_line_prefix = None;
        let mut bft_peer_count = None;

        // Resolve primary sequencer URL: explicit `sequencer_url` -> `depends_on` sequencer ->
        // domain-matched local sequencer -> external `synchronizers.<alias>.sequencer_url` -> first local sequencer.
        let seq_url = raw
            .sequencer_url
            .clone()
            .or_else(|| {
                raw.depends_on
                    .iter()
                    .find_map(|dep| {
                        resolved.iter().find(|s| {
                            &s.name == dep
                                && s.role == NodeRole::Sequencer
                                && s.synchronizer_domain.as_deref() == Some(eff_sync.as_str())
                        })
                    })
                    .or_else(|| {
                        raw.depends_on.iter().find_map(|dep| {
                            resolved
                                .iter()
                                .find(|s| &s.name == dep && s.role == NodeRole::Sequencer)
                        })
                    })
                    .or_else(|| {
                        resolved.iter().find(|s| {
                            s.role == NodeRole::Sequencer
                                && s.synchronizer_domain.as_deref() == Some(eff_sync.as_str())
                        })
                    })
                    .and_then(|s| {
                        let ch =
                            connect_host_for_bind(s.bind_host.as_deref().unwrap_or("127.0.0.1"));
                        s.ports.public.map(|p| format!("http://{ch}:{p}"))
                    })
            })
            .or_else(|| {
                ctx.synchronizers
                    .get(&eff_sync)
                    .and_then(|d| d.external_sequencer_url.clone())
            })
            .or_else(|| {
                resolved
                    .iter()
                    .find(|s| s.role == NodeRole::Sequencer)
                    .and_then(|s| {
                        let ch =
                            connect_host_for_bind(s.bind_host.as_deref().unwrap_or("127.0.0.1"));
                        s.ports.public.map(|p| format!("http://{ch}:{p}"))
                    })
            });

        // Find ledger JSON API port for Splice / Scan / PQS if `ledger_of` is given or inferred.
        let target_participant = raw
            .ledger_of
            .as_deref()
            .and_then(|name| {
                resolved
                    .iter()
                    .find(|s| s.name == name && s.role == NodeRole::Participant)
            })
            .or_else(|| resolved.iter().find(|s| s.role == NodeRole::Participant));
        let mut effective_token = raw.token;

        match raw.role {
            NodeRole::Sequencer => {
                let pub_port = ports.public.unwrap_or(5018);
                ports.public = Some(pub_port);
                if let Some(bg) = &raw.bft_group {
                    if let Some(adm) = ports.admin {
                        if ports.metrics.is_none_or(|m| m == adm) {
                            return Err(format!(
                                "BFT sequencer '{}': admin port {adm} is its gRPC admin bind; give a separate 'metrics' port for its status HTTP",
                                raw.name
                            ));
                        }
                    }
                    // [CANTON-NOTE: INVARIANT] The genesis identity is made in the node's file store (topology.rs); run-bft on other
                    // storage would load or create different keys.
                    if !matches!(raw.storage, StorageSpec::Files) {
                        return Err(format!(
                            "BFT sequencer '{}': only 'files' storage is supported (its genesis identity lives in the file store)",
                            raw.name
                        ));
                    }
                    let p2p_port = ports.p2p.unwrap_or_else(|| pub_port.saturating_add(2));
                    ports.p2p = Some(p2p_port);
                    let genesis_file = ctx
                        .root_state_dir
                        .join(format!("bft-{eff_sync}-genesis.tx"));
                    argv.extend([
                        "sequencer".into(),
                        "run-bft".into(),
                        "--name".into(),
                        raw.name.clone(),
                        "--synchronizer".into(),
                        eff_sync.clone(),
                        "--namespace".into(),
                        "pending-genesis".into(),
                        "--genesis-file".into(),
                        genesis_file.display().to_string(),
                        "--public-bind".into(),
                        format_bind_host_port(eff_bind, pub_port),
                        "--p2p-bind".into(),
                        format_bind_host_port(eff_bind, p2p_port),
                        "--external".into(),
                        format_bind_host_port(eff_connect, p2p_port),
                        "--metrics-bind".into(),
                        eff_bind.to_string(),
                    ]);
                    if let Some(adm) = ports.admin {
                        argv.extend(["--admin-bind".into(), format_bind_host_port(eff_bind, adm)]);
                    }
                    if let Some(mesh) = bft_meshes.get(bg) {
                        bft_peer_count = Some(mesh.len());
                        for (peer_name, peer_p2p) in mesh {
                            if peer_name != &raw.name {
                                argv.extend([
                                    "--peer".into(),
                                    format!("http://{eff_connect}:{peer_p2p}"),
                                ]);
                            }
                        }
                    }
                } else {
                    argv.extend([
                        "sequencer".into(),
                        "run".into(),
                        "--bind".into(),
                        eff_bind.to_string(),
                        "--metrics-bind".into(),
                        eff_bind.to_string(),
                        "--port".into(),
                        pub_port.to_string(),
                        "--name".into(),
                        eff_sync.clone(),
                    ]);
                }
                match &raw.storage {
                    StorageSpec::Postgres { url, name } => {
                        env.insert("CANTON_RS_STATE_PG_URL".into(), url.clone());
                        argv.extend([
                            "--state-name".into(),
                            name.clone().unwrap_or_else(|| raw.name.clone()),
                        ]);
                    }
                    StorageSpec::Files => {
                        argv.extend(["--state-dir".into(), node_state_dir.display().to_string()]);
                    }
                    StorageSpec::Memory => {}
                }
                if let Some(mport) = ports.metrics.or(ports.admin) {
                    ports.metrics = Some(ports.metrics.unwrap_or(mport));
                    argv.extend(["--metrics-port".into(), mport.to_string()]);
                    health_url = Some(format!("http://{eff_connect}:{mport}/livez"));
                    readiness_url = Some(format!("http://{eff_connect}:{mport}/readyz"));
                    status_url = Some(format!("http://{eff_connect}:{mport}/status"));
                    metrics_url = Some(format!("http://{eff_connect}:{mport}/metrics"));
                }
                ready_line_prefix = Some("READY sequencer=".to_string());
            }
            NodeRole::Mediator => {
                let admin_port = ports
                    .admin
                    .or(ports.http_json)
                    .or(ports.public)
                    .unwrap_or(5017);
                ports.admin = Some(admin_port);
                let url = seq_url.ok_or_else(|| {
                    format!(
                        "mediator '{}' requires a sequencer in dependencies, 'sequencer_url', or earlier in 'services'",
                        raw.name
                    )
                })?;
                argv.extend([
                    "mediator".into(),
                    "run".into(),
                    "--bind".into(),
                    eff_bind.to_string(),
                    "--sequencer-url".into(),
                    url,
                    "--port".into(),
                    admin_port.to_string(),
                ]);
                match &raw.storage {
                    StorageSpec::Postgres { url, name } => {
                        env.insert("CANTON_RS_STATE_PG_URL".into(), url.clone());
                        argv.extend([
                            "--state-name".into(),
                            name.clone().unwrap_or_else(|| raw.name.clone()),
                        ]);
                    }
                    StorageSpec::Files | StorageSpec::Memory => {
                        argv.extend(["--state-dir".into(), node_state_dir.display().to_string()]);
                    }
                }
                health_url = Some(format!("http://{eff_connect}:{admin_port}/livez"));
                readiness_url = Some(format!("http://{eff_connect}:{admin_port}/readyz"));
                status_url = Some(format!("http://{eff_connect}:{admin_port}/status"));
                metrics_url = Some(format!("http://{eff_connect}:{admin_port}/metrics"));
                ready_line_prefix = Some("READY mediator=".to_string());
            }
            NodeRole::Participant => {
                let http_port = ports.http_json.or(ports.public).unwrap_or(7575);
                ports.http_json = Some(http_port);
                argv.extend([
                    "json-api".into(),
                    "--host".into(),
                    eff_bind.to_string(),
                    "--port".into(),
                    http_port.to_string(),
                    "--participant-name".into(),
                    raw.name.clone(),
                    "--participant-id-file".into(),
                    node_state_dir
                        .join(super::super::creds::PARTICIPANT_ID_FILE)
                        .display()
                        .to_string(),
                ]);
                // [CANTON-NOTE: SEMANTICS] Do not silently inject `contracts/target/sample-contract.dar`
                // when `dars: []` is configured (M-001): zero-DAR manifests must behave identically inside
                // and outside the source repository.
                if let Some(dar) = raw.dars.first() {
                    argv.extend(["--dar".into(), dar.display().to_string()]);
                }
                if let Some(url) = seq_url {
                    argv.extend([
                        "--sequencer".into(),
                        url,
                        "--sequencer-alias".into(),
                        eff_sync.clone(),
                    ]);
                }
                for extra_sync in &raw.also_synchronizers {
                    let extra_url = resolved
                        .iter()
                        .find(|s| {
                            s.role == NodeRole::Sequencer
                                && s.synchronizer_domain.as_deref() == Some(extra_sync.as_str())
                        })
                        .and_then(|s| {
                            let ch =
                                connect_host_for_bind(s.bind_host.as_deref().unwrap_or("127.0.0.1"));
                            s.ports.public.map(|p| format!("http://{ch}:{p}"))
                        })
                        .or_else(|| {
                            ctx.synchronizers
                                .get(extra_sync)
                                .and_then(|d| d.external_sequencer_url.clone())
                        })
                        .ok_or_else(|| {
                            format!(
                                "participant '{}' references unknown also_synchronizers domain '{extra_sync}'",
                                raw.name
                            )
                        })?;
                    argv.extend([
                        "--also-sequencer".into(),
                        format!("{extra_sync}={extra_url}"),
                    ]);
                }
                if let Some(grpc) = ports.grpc_ledger {
                    argv.extend(["--grpc-port".into(), grpc.to_string()]);
                }
                if let Some(adm) = ports.admin {
                    argv.extend(["--admin-port".into(), adm.to_string()]);
                }
                if let Some(cert) = &raw.auth_cert {
                    argv.extend(["--auth-cert".into(), cert.display().to_string()]);
                }
                let enable_xray = raw.xray.unwrap_or(ctx.xray);
                if enable_xray {
                    argv.push("--xray".into());
                }
                if ctx.log_encoder != "text" {
                    argv.extend(["--log-encoder".into(), ctx.log_encoder.to_string()]);
                }
                if target_participant.is_none() && has_splice_or_scan(resolved) {
                    argv.extend([
                        "--scan-history".into(),
                        shared_scan_history.display().to_string(),
                    ]);
                }
                match &raw.storage {
                    StorageSpec::Postgres { url, name } => {
                        env.insert("CANTON_RS_STATE_PG_URL".into(), url.clone());
                        argv.extend([
                            "--state-name".into(),
                            name.clone().unwrap_or_else(|| raw.name.clone()),
                        ]);
                    }
                    StorageSpec::Files => {
                        argv.extend(["--state-dir".into(), node_state_dir.display().to_string()]);
                    }
                    StorageSpec::Memory => {}
                }
                if raw.ledger_of.is_none()
                    && !argv.iter().any(|a| a == "--scan-history")
                    && resolved.iter().all(|s| s.role != NodeRole::Participant)
                {
                    argv.extend([
                        "--scan-history".into(),
                        shared_scan_history.display().to_string(),
                    ]);
                }
                health_url = Some(format!("http://{eff_connect}:{http_port}/livez"));
                readiness_url = Some(format!("http://{eff_connect}:{http_port}/readyz"));
                status_url = Some(format!("http://{eff_connect}:{http_port}/_telemetry"));
                metrics_url = Some(format!("http://{eff_connect}:{http_port}/metrics"));
                xray_url = enable_xray.then(|| format!("http://{eff_connect}:{http_port}/_xray"));
            }
            NodeRole::Splice => {
                let http_port = ports.http_json.or(ports.public).unwrap_or(5020);
                ports.http_json = Some(http_port);
                argv.extend([
                    "splice".into(),
                    "serve".into(),
                    "--host".into(),
                    eff_bind.to_string(),
                    "--port".into(),
                    http_port.to_string(),
                ]);
                let dar_dir = raw
                    .dar_dir
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("tests/oracle/splice-dars"));
                argv.extend(["--dar-dir".into(), dar_dir.display().to_string()]);
                if let Some(tp) = target_participant {
                    if let Some(p) = tp.ports.http_json {
                        let ch =
                            connect_host_for_bind(tp.bind_host.as_deref().unwrap_or("127.0.0.1"));
                        argv.extend([
                            "--ledger-host".into(),
                            ch.to_string(),
                            "--ledger-port".into(),
                            p.to_string(),
                        ]);
                    }
                } else if let Some(lurl) = &raw.ledger_url {
                    if let Some((h, p)) = parse_host_port(lurl) {
                        argv.extend([
                            "--ledger-host".into(),
                            h,
                            "--ledger-port".into(),
                            p.to_string(),
                        ]);
                    }
                }
                if let Some(ms) = raw.automation_interval_ms {
                    argv.extend(["--automation-interval-ms".into(), ms.to_string()]);
                }
                health_url = Some(format!("http://{eff_connect}:{http_port}/livez"));
                readiness_url = Some(format!("http://{eff_connect}:{http_port}/readyz"));
                status_url = Some(format!("http://{eff_connect}:{http_port}/status"));
                metrics_url = Some(format!("http://{eff_connect}:{http_port}/metrics"));
            }
            NodeRole::Scan => {
                let http_port = ports.http_json.or(ports.public).unwrap_or(5012);
                ports.http_json = Some(http_port);
                let history = raw
                    .history
                    .clone()
                    .unwrap_or_else(|| shared_scan_history.clone());
                argv.extend([
                    "scan".into(),
                    "serve".into(),
                    "--host".into(),
                    eff_bind.to_string(),
                    "--port".into(),
                    http_port.to_string(),
                    "--history".into(),
                    history.display().to_string(),
                ]);
                if let Some(dar) = raw.dars.first() {
                    argv.extend(["--dar".into(), dar.display().to_string()]);
                }
                ready_line_prefix = Some("SCAN listening".to_string());
            }
            NodeRole::Pqs => {
                let json_api_url = target_participant
                    .and_then(|tp| {
                        let ch =
                            connect_host_for_bind(tp.bind_host.as_deref().unwrap_or("127.0.0.1"));
                        tp.ports.http_json.map(|p| format!("http://{ch}:{p}"))
                    })
                    .or_else(|| raw.ledger_url.clone())
                    .ok_or_else(|| {
                        format!(
                            "pqs service '{}' requires 'ledger_of: <participant>' or 'ledger_url'",
                            raw.name
                        )
                    })?;
                let pg_url = match &raw.storage {
                    StorageSpec::Postgres { url, .. } => url.clone(),
                    _ => env.get("CANTON_RS_PQS_PG_URL").cloned().ok_or_else(|| {
                        format!(
                            "pqs service '{}' requires 'storage: {{ type: postgres, url: ... }}'",
                            raw.name
                        )
                    })?,
                };
                env.insert("CANTON_RS_PQS_PG_URL".into(), pg_url);
                argv.extend([
                    "pqs".into(),
                    "sync".into(),
                    "--json-api-url".into(),
                    json_api_url,
                    "--follow".into(),
                ]);
                // Its own token source, else the one the supervisor uses for the participant it reads.
                if effective_token.is_none() {
                    effective_token = target_participant.and_then(|p| p.token.clone());
                }
                if let Some(super::super::TokenSource::File(path)) = &effective_token {
                    argv.extend(["--token-file".into(), path.display().to_string()]);
                }
            }
        }

        let auth_mode = match &raw.auth_cert {
            Some(c) => format!("jwt-rs-256-crt ({})", c.display()),
            None => "open".to_string(),
        };

        resolved.push(DaemonServiceSpec {
            slot_id,
            name: raw.name,
            role: raw.role,
            ports,
            restart,
            depends_on: raw.depends_on,
            dars: raw.dars,
            dar_dir: raw.dar_dir,
            ledger_of: raw.ledger_of,
            ledger_url: raw.ledger_url,
            automation_interval_ms: raw.automation_interval_ms,
            storage: raw.storage,
            argv,
            env,
            health_url,
            readiness_url,
            status_url,
            metrics_url,
            xray_url,
            xray_override: raw.xray,
            state_dir: node_state_dir,
            auth_mode,
            config_path: None,
            bootstrap_path: None,
            port_offset: ctx.port_offset,
            same_identity: false,
            official_write: false,
            config_applied_count: 0,
            config_not_applied_keys: Vec::new(),
            ready_line_prefix,
            bft_peer_count,
            group: raw.group,
            profiles: raw.profiles,
            synchronizer_domain: Some(eff_sync),
            also_synchronizers: raw.also_synchronizers,
            limits: raw.limits,
            token: effective_token,
            bind_host: Some(eff_bind.to_string()),
        });
    }

    Ok(())
}

fn has_splice_or_scan(services: &[DaemonServiceSpec]) -> bool {
    services
        .iter()
        .any(|s| matches!(s.role, NodeRole::Splice | NodeRole::Scan))
}

/// Validates that no two slots bind the exact same loopback TCP port.
pub fn check_port_collisions(services: &[DaemonServiceSpec]) -> Result<(), String> {
    let mut seen: BTreeMap<u16, String> = BTreeMap::new();
    for svc in services {
        for port in svc.ports.all_ports() {
            if let Some(owner) = seen.get(&port) {
                return Err(format!(
                    "port collision on {port}: claimed by both '{owner}' and '{}'",
                    svc.name
                ));
            }
            seen.insert(port, svc.name.clone());
        }
    }
    Ok(())
}
