use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ledger_json_api::canton_log::LogEncoder;

use super::super::super::exit_code::{exit_with_message, silent_exit, EXIT_PREFLIGHT};
use super::super::creds;
use super::super::doctor::{
    render_json, render_text, resolve_doctor_plan, run_doctor, CheckStatus, DoctorHost,
};
use super::super::engine::{run_supervisor, spawn_detached_and_wait, READY_HANDSHAKE_FILE};
use super::super::ipc::{
    call_unary, open_stream, resolve_client_state_dir, socket_path, DownProgressEvent, IpcRequest,
    IpcResponse, IpcStreamEvent,
};
use super::super::manifest::{
    connect_host_for_bind, format_bind_host_port, load_yaml_manifest_with_options_and_pg,
    ParsedYamlManifest,
};
use super::super::registry::{
    build_dry_run_report, compute_manifest_hash, execute_instance_remove, instances_root,
    is_instance_alive, plan_instance_remove, read_instance_record, render_remove_json,
    render_remove_text, resolve_target_state_dir, resolve_up_port_offset, write_instance_record,
    InstanceRecord,
};
use super::super::snapshot::{ensure_pg_schema_exists, save_startup_recipe, scope_pg_url};
use super::super::{
    now_unix_secs, DaemonSpec, NodeRole, StorageSpec, TokenSource, DEFAULT_LOG_MAX_BYTES,
    DEFAULT_LOG_MAX_FILES, DEFAULT_SHUTDOWN_TIMEOUT_SECS, DEFAULT_TRACE_RATE_LIMIT,
};
use super::{
    DoctorArgs, DoctorFormatArg, DownArgs, RemoveArgs, RestartArgs, SlotTargetsArgs, StartOrUpArgs,
    StatusFormatArg, UpArgs, DEFAULT_STATE_DIR,
};

pub(super) fn resolve_spec_for_up(args: &UpArgs) -> Result<DaemonSpec, String> {
    let manifest_path = match (&args.file, &args.config) {
        (Some(f), _) => Some(f.clone()),
        (None, Some(_)) => None,
        (None, None) => {
            let default_yaml = PathBuf::from("canton-daemon.yaml");
            if default_yaml.exists() {
                Some(default_yaml)
            } else {
                return Err(
                    "give '-f canton-daemon.yaml' or '-c canton.conf' (or generate one with 'canton-rs daemon init')"
                        .to_string(),
                );
            }
        }
    };

    let eff_name = args.name.clone().or_else(|| {
        args.state_dir
            .as_deref()
            .and_then(|d| read_instance_record(d).ok().flatten())
            .map(|r| r.name)
    });
    let scoped_pg_url = if !args.state_in_files {
        args.pg_url.as_ref().map(|pg| {
            eff_name
                .as_deref()
                .map_or_else(|| pg.clone(), |n| scope_pg_url(pg, &format!("{n}-state")))
        })
    } else {
        None
    };

    let mut spec = if let Some(yaml_path) = manifest_path {
        match load_yaml_manifest_with_options_and_pg(
            &yaml_path,
            args.port_offset.unwrap_or(0),
            args.metrics_port,
            scoped_pg_url.as_deref(),
            args.state_in_files,
        )? {
            ParsedYamlManifest::ModeA(mut spec) => {
                if let Some(sd) = &args.state_dir {
                    rebase_mode_a_state_dir(&mut spec, sd);
                }
                if let Some(mp) = args.metrics_port {
                    spec.metrics_port = if mp == 0 { None } else { Some(mp) };
                }
                if args.metrics_bind != "127.0.0.1" {
                    spec.metrics_bind = args.metrics_bind.clone();
                }
                if args.no_restart {
                    spec.no_restart = true;
                    for s in &mut spec.services {
                        s.restart = super::super::RestartPolicy::No;
                    }
                }
                if args.shadow_verify {
                    spec.shadow_verify = true;
                }
                if args.xray {
                    spec.xray = true;
                    for s in &mut spec.services {
                        if s.role == super::super::NodeRole::Participant
                            && s.xray_override != Some(false)
                        {
                            if !s.argv.iter().any(|a| a == "--xray") {
                                s.argv.push("--xray".into());
                            }
                            if s.xray_url.is_none() {
                                s.xray_url = s
                                    .ports
                                    .http_json
                                    .map(|hp| format!("http://127.0.0.1:{hp}/_xray"));
                            }
                        }
                    }
                }
                if let Some(u) = &args.shadow_jvm_url {
                    spec.shadow_jvm_url = Some(u.clone());
                }
                if args.log_max_bytes != DEFAULT_LOG_MAX_BYTES {
                    spec.log_max_bytes = args.log_max_bytes;
                    spec.logging.max_bytes = args.log_max_bytes;
                }
                if args.log_max_files != DEFAULT_LOG_MAX_FILES {
                    spec.log_max_files = args.log_max_files;
                    spec.logging.max_files = args.log_max_files;
                }
                if args.trace_rate_limit != DEFAULT_TRACE_RATE_LIMIT {
                    spec.trace_rate_limit_per_sec = args.trace_rate_limit;
                }
                apply_cli_logging_overrides(args, &mut spec)?;
                super::super::topology::filter_spec_services(
                    &mut spec,
                    &args.profile,
                    &args.group,
                )?;
                spec
            }
            ParsedYamlManifest::ModeB(mode_b) => {
                let mut merged = crate::commands::daemon::DaemonArgs {
                    action: None,
                    config: Some(mode_b.canton_conf.clone()),
                    bootstrap: args.bootstrap.clone().or_else(|| mode_b.bootstrap.clone()),
                    state_dir: args
                        .state_dir
                        .clone()
                        .unwrap_or_else(|| mode_b.state_dir.clone()),
                    official_pg_addr: args
                        .official_pg_addr
                        .clone()
                        .or_else(|| mode_b.official_pg_addr.clone()),
                    conf_auth_cert: args
                        .conf_auth_cert
                        .clone()
                        .or_else(|| mode_b.auth_cert.clone()),
                    dar: args.dar.clone().or_else(|| mode_b.dar.clone()),
                    state_in_files: args.state_in_files || mode_b.state_in_files,
                    port_offset: args
                        .port_offset
                        .filter(|&o| o != 0)
                        .unwrap_or(mode_b.port_offset),
                    same_identity: args.same_identity || mode_b.same_identity,
                    log_encoder: args.log_encoder,
                    strict_config: args.strict_config || mode_b.strict_config,
                    no_tty: false,
                    log_profile: None,
                    log_file_appender: None,
                    official_write: args.official_write || mode_b.official_write,
                    no_restart: args.no_restart || mode_b.no_restart,
                    metrics_port: args.metrics_port.or(mode_b.metrics_port),
                    metrics_bind: mode_b.metrics_bind.clone(),
                    shadow_verify: args.shadow_verify || mode_b.shadow_verify,
                    shadow_jvm_url: args
                        .shadow_jvm_url
                        .clone()
                        .or_else(|| mode_b.shadow_jvm_url.clone()),
                    trace_rate_limit: args.trace_rate_limit,
                    xray: args.xray || mode_b.xray,
                    log_max_bytes: mode_b.log_max_bytes,
                    log_max_files: mode_b.log_max_files,
                    token_env: args.token_env.clone(),
                    token_file: args.token_file.clone(),
                    worker: args.worker,
                };
                if args.metrics_bind != "127.0.0.1" {
                    merged.metrics_bind = args.metrics_bind.clone();
                }
                let mut spec = crate::commands::daemon::build_daemon_spec(&merged, Some(&mode_b))?;
                spec.manifest_path = Some(yaml_path);
                if args.log_max_bytes != DEFAULT_LOG_MAX_BYTES {
                    spec.log_max_bytes = args.log_max_bytes;
                    spec.logging.max_bytes = args.log_max_bytes;
                }
                if args.log_max_files != DEFAULT_LOG_MAX_FILES {
                    spec.log_max_files = args.log_max_files;
                    spec.logging.max_files = args.log_max_files;
                }
                apply_cli_logging_overrides(args, &mut spec)?;
                super::super::topology::filter_spec_services(
                    &mut spec,
                    &args.profile,
                    &args.group,
                )?;
                spec
            }
        }
    } else {
        let legacy_args = crate::commands::daemon::DaemonArgs {
            action: None,
            config: args.config.clone(),
            bootstrap: args.bootstrap.clone(),
            state_dir: args
                .state_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR)),
            official_pg_addr: args.official_pg_addr.clone(),
            conf_auth_cert: args.conf_auth_cert.clone(),
            dar: args.dar.clone(),
            state_in_files: args.state_in_files,
            port_offset: args.port_offset.unwrap_or(0),
            same_identity: args.same_identity,
            log_encoder: args.log_encoder,
            strict_config: args.strict_config,
            no_tty: false,
            log_profile: None,
            log_file_appender: None,
            official_write: args.official_write,
            no_restart: args.no_restart,
            metrics_port: args.metrics_port,
            metrics_bind: args.metrics_bind.clone(),
            shadow_verify: args.shadow_verify,
            shadow_jvm_url: args.shadow_jvm_url.clone(),
            trace_rate_limit: args.trace_rate_limit,
            xray: args.xray,
            log_max_bytes: args.log_max_bytes,
            log_max_files: args.log_max_files,
            token_env: args.token_env.clone(),
            token_file: args.token_file.clone(),
            worker: args.worker,
        };
        let mut spec = crate::commands::daemon::build_daemon_spec(&legacy_args, None)?;
        apply_cli_logging_overrides(args, &mut spec)?;
        spec
    };

    if args.bind != "127.0.0.1" {
        apply_bind_override(&mut spec, &args.bind);
    }
    for svc in &mut spec.services {
        if svc.role == NodeRole::Participant {
            let pid_file = svc.state_dir.join(creds::PARTICIPANT_ID_FILE);
            set_flag_value(
                &mut svc.argv,
                "--participant-id-file",
                &pid_file.display().to_string(),
            );
        }
    }
    spec.observability = args.observability;
    if spec.observability {
        if args.metrics_port == Some(0) {
            return Err(exit_with_message(
                EXIT_PREFLIGHT,
                "--observability requires metrics_port != 0",
            ));
        }
        if spec.metrics_port.is_none() {
            spec.metrics_port =
                Some(super::super::DEFAULT_METRICS_PORT.saturating_add(spec.port_offset));
        }
    }
    spec.bind_addresses = creds::collect_spec_bind_addresses(&spec);
    Ok(spec)
}

fn set_flag_value(argv: &mut Vec<String>, flag: &str, value: &str) {
    let prefix = format!("{flag}=");
    let mut i = 0usize;
    while i < argv.len() {
        if argv[i] == flag {
            if i + 1 < argv.len() {
                argv[i + 1] = value.to_string();
            } else {
                argv.push(value.to_string());
            }
            return;
        }
        if argv[i].starts_with(&prefix) {
            argv[i] = format!("{prefix}{value}");
            return;
        }
        i += 1;
    }
    argv.push(flag.to_string());
    argv.push(value.to_string());
}

fn apply_bind_override(spec: &mut DaemonSpec, bind: &str) {
    let eff = bind.trim();
    let connect = connect_host_for_bind(eff);
    for svc in &mut spec.services {
        svc.bind_host = Some(eff.to_string());
        match svc.role {
            NodeRole::Sequencer => {
                if svc.argv.iter().any(|a| a == "run-bft") {
                    if let Some(pub_port) = svc.ports.public {
                        set_flag_value(
                            &mut svc.argv,
                            "--public-bind",
                            &format_bind_host_port(eff, pub_port),
                        );
                    }
                    if let Some(p2p_port) = svc.ports.p2p {
                        set_flag_value(
                            &mut svc.argv,
                            "--p2p-bind",
                            &format_bind_host_port(eff, p2p_port),
                        );
                        set_flag_value(
                            &mut svc.argv,
                            "--external",
                            &format_bind_host_port(connect, p2p_port),
                        );
                    }
                    if let Some(adm_port) = svc.ports.admin {
                        set_flag_value(
                            &mut svc.argv,
                            "--admin-bind",
                            &format_bind_host_port(eff, adm_port),
                        );
                    }
                    set_flag_value(&mut svc.argv, "--metrics-bind", eff);
                } else {
                    set_flag_value(&mut svc.argv, "--bind", eff);
                    set_flag_value(&mut svc.argv, "--metrics-bind", eff);
                }
            }
            NodeRole::Mediator => {
                set_flag_value(&mut svc.argv, "--bind", eff);
            }
            NodeRole::Participant | NodeRole::Splice | NodeRole::Scan => {
                set_flag_value(&mut svc.argv, "--host", eff);
            }
            NodeRole::Pqs => {}
        }
        if connect != "127.0.0.1" {
            let from = "://127.0.0.1:";
            let to = format!("://{connect}:");
            for opt in [
                &mut svc.health_url,
                &mut svc.readiness_url,
                &mut svc.status_url,
                &mut svc.metrics_url,
                &mut svc.xray_url,
            ]
            .into_iter()
            .flatten()
            {
                *opt = opt.replace(from, &to);
            }
            for arg in &mut svc.argv {
                if arg.contains(from) {
                    *arg = arg.replace(from, &to);
                }
            }
            if svc.role == NodeRole::Splice {
                set_flag_value(&mut svc.argv, "--ledger-host", connect);
            }
        }
    }
}

fn configure_dev_auth_for_up(
    spec: &mut DaemonSpec,
    requested_dev_auth: bool,
    is_worker: bool,
) -> Result<(), String> {
    let bad = creds::non_loopback_addresses(&spec.bind_addresses);
    if !bad.is_empty() {
        spec.dev_auth = false;
        if requested_dev_auth && !is_worker {
            eprintln!(
                "WARN: --dev-auth disabled because listening address(es) are non-loopback: {}",
                bad.join(", ")
            );
        }
        return Ok(());
    }

    let key_file = creds::ensure_dev_jwt_key(&spec.state_dir)?;
    if !requested_dev_auth {
        spec.dev_auth = false;
        return Ok(());
    }

    spec.dev_auth = true;
    for svc in &mut spec.services {
        if svc.role != NodeRole::Participant {
            continue;
        }
        let has_explicit_auth = svc.argv.iter().any(|a| {
            a == "--auth-cert"
                || a == "--jwt-hmac-secret"
                || a == "--jwt-hmac-secret-file"
                || a.starts_with("--auth-cert=")
                || a.starts_with("--jwt-hmac-secret=")
                || a.starts_with("--jwt-hmac-secret-file=")
        });
        if has_explicit_auth {
            continue;
        }
        svc.argv.extend([
            "--jwt-hmac-secret-file".into(),
            key_file.display().to_string(),
            "--jwt-audience-self".into(),
            "--jwt-max-lifetime-seconds".into(),
            creds::DEV_JWT_MAX_TTL_SECS.to_string(),
        ]);
        svc.auth_mode = "dev-hs256 (loopback-only)".to_string();
        if svc.token.is_none() {
            svc.token = Some(TokenSource::DevJwt {
                key_file: key_file.clone(),
                participant_id_file: svc.state_dir.join(creds::PARTICIPANT_ID_FILE),
            });
        }
    }
    Ok(())
}

fn rebase_mode_a_state_dir(spec: &mut DaemonSpec, new_root: &Path) {
    let old_root = spec.state_dir.clone();
    let old_prefix = old_root.display().to_string();
    let new_prefix = new_root.display().to_string();
    spec.state_dir = new_root.to_path_buf();
    for svc in &mut spec.services {
        if let Ok(rel) = svc.state_dir.strip_prefix(&old_root) {
            svc.state_dir = new_root.join(rel);
        }
        for arg in &mut svc.argv {
            if let Some(suffix) = arg.strip_prefix(&old_prefix) {
                *arg = format!("{new_prefix}{suffix}");
            }
        }
    }
}

fn apply_cli_logging_overrides(args: &UpArgs, spec: &mut DaemonSpec) -> Result<(), String> {
    let mut changed = false;
    if let Some(lvl) = &args.log_level {
        spec.logging.level = super::super::log_policy::LogFilterLevel::parse(lvl)?;
        changed = true;
    }
    if let Some(diag) = &args.log_diagnostics {
        spec.logging.diagnostics = super::super::log_policy::DiagnosticsMode::parse(diag)?;
        changed = true;
    }
    if let Some(sup) = args.suppress_idle_polls {
        spec.logging.suppress_idle_polls = sup;
        changed = true;
    }
    if changed {
        for svc in &mut spec.services {
            svc.env.remove("CANTON_RS_LOG");
            spec.logging.apply_child_env(&svc.name, &mut svc.env);
        }
    }
    Ok(())
}

fn build_worker_argv(args: &UpArgs, state_dir: &Path) -> Vec<String> {
    let mut out = vec![
        "daemon".into(),
        "up".into(),
        "--daemon-supervisor-worker".into(),
        "--state-dir".into(),
        state_dir.display().to_string(),
        "--metrics-bind".into(),
        args.metrics_bind.clone(),
        "--log-max-bytes".into(),
        args.log_max_bytes.to_string(),
        "--log-max-files".into(),
        args.log_max_files.to_string(),
        "--trace-rate-limit".into(),
        args.trace_rate_limit.to_string(),
    ];
    if let Some(f) = &args.file {
        out.extend(["--file".into(), f.display().to_string()]);
    }
    if let Some(c) = &args.config {
        out.extend(["--config".into(), c.display().to_string()]);
    }
    if let Some(b) = &args.bootstrap {
        out.extend(["--bootstrap".into(), b.display().to_string()]);
    }
    if let Some(a) = &args.official_pg_addr {
        out.extend(["--official-pg-addr".into(), a.clone()]);
    }
    if let Some(c) = &args.conf_auth_cert {
        out.extend(["--conf-auth-cert".into(), c.display().to_string()]);
    }
    if let Some(d) = &args.dar {
        out.extend(["--dar".into(), d.display().to_string()]);
    }
    if args.state_in_files {
        out.push("--state-in-files".into());
    }
    if let Some(pg) = &args.pg_url {
        out.extend(["--pg-url".into(), pg.clone()]);
    }
    if let Some(off) = args.port_offset.filter(|&o| o != 0) {
        out.extend(["--port-offset".into(), off.to_string()]);
    }
    if args.same_identity {
        out.push("--same-identity".into());
    }
    if args.official_write {
        out.push("--official-write".into());
    }
    if args.strict_config {
        out.push("--strict-config".into());
    }
    if args.no_restart {
        out.push("--no-restart".into());
    }
    if args.xray {
        out.push("--xray".into());
    }
    if args.shadow_verify {
        out.push("--shadow-verify".into());
    }
    if let Some(u) = &args.shadow_jvm_url {
        out.extend(["--shadow-jvm-url".into(), u.clone()]);
    }
    if let Some(mp) = args.metrics_port {
        out.extend(["--metrics-port".into(), mp.to_string()]);
    }
    if let Some(lvl) = &args.log_level {
        out.extend(["--log-level".into(), lvl.clone()]);
    }
    if let Some(diag) = &args.log_diagnostics {
        out.extend(["--log-diagnostics".into(), diag.clone()]);
    }
    if let Some(sup) = args.suppress_idle_polls {
        out.extend(["--suppress-idle-polls".into(), sup.to_string()]);
    }
    if !args.profile.is_empty() {
        out.extend(["--profile".into(), args.profile.join(",")]);
    }
    if !args.group.is_empty() {
        out.extend(["--group".into(), args.group.join(",")]);
    }
    if args.dev_auth {
        out.push("--dev-auth".into());
    }
    if args.observability {
        out.push("--observability".into());
    }
    if args.bind != "127.0.0.1" {
        out.extend(["--bind".into(), args.bind.clone()]);
    }
    out
}

#[inline]
fn should_run_up_preflight(worker: bool) -> bool {
    !worker
}

fn doctor_args_to_up_args(args: DoctorArgs) -> UpArgs {
    UpArgs {
        file: args.file,
        config: args.config,
        bootstrap: args.bootstrap,
        detach: false,
        name: args.name,
        state_dir: args.state_dir,
        official_pg_addr: None,
        conf_auth_cert: None,
        dar: args.dar,
        state_in_files: args.state_in_files,
        port_offset: (args.port_offset != 0).then_some(args.port_offset),
        same_identity: false,
        official_write: false,
        strict_config: false,
        log_encoder: LogEncoder::Text,
        log_level: None,
        log_diagnostics: None,
        suppress_idle_polls: None,
        no_restart: false,
        metrics_port: args.metrics_port,
        metrics_bind: "127.0.0.1".into(),
        observability: false,
        dev_auth: false,
        bind: "127.0.0.1".into(),
        log_max_bytes: DEFAULT_LOG_MAX_BYTES,
        log_max_files: DEFAULT_LOG_MAX_FILES,
        xray: false,
        trace_rate_limit: DEFAULT_TRACE_RATE_LIMIT,
        shadow_verify: false,
        shadow_jvm_url: None,
        profile: args.profile,
        group: args.group,
        token_env: None,
        token_file: None,
        pg_url: args.pg_url,
        worker: false,
    }
}

pub(super) fn cmd_doctor(mut args: DoctorArgs) -> Result<(), String> {
    if args.name.is_some() {
        let resolved_dir =
            resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
        args.state_dir = Some(resolved_dir);
        args.name = None;
    }
    let format = args.format;
    let pg_url = args.pg_url.clone();
    let up = doctor_args_to_up_args(args);
    let plan = resolve_doctor_plan(&up, pg_url.as_deref())?;
    let report = run_doctor(&plan, &DoctorHost::live());
    match format {
        DoctorFormatArg::Json => println!("{}", render_json(&report)?),
        DoctorFormatArg::Text => print!("{}", render_text(&report)),
    }
    if report.exit_code == 0 {
        Ok(())
    } else {
        Err(silent_exit(report.exit_code))
    }
}

pub(super) fn cmd_up(mut args: UpArgs) -> Result<(), String> {
    let mut pending_record: Option<(PathBuf, String)> = None;
    if should_run_up_preflight(args.worker) {
        if let Some(inst_name) = args.name.clone() {
            let target_dir = resolve_target_state_dir(Some(&inst_name), args.state_dir.as_deref())?;
            if is_instance_alive(&target_dir) {
                return Err(exit_with_message(
                    EXIT_PREFLIGHT,
                    format!(
                        "instance '{inst_name}' is already running at {}",
                        target_dir.display()
                    ),
                ));
            }
            let root = instances_root().map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
            let (eff_offset, _existing) =
                resolve_up_port_offset(&root, &inst_name, args.port_offset)?;
            args.state_dir = Some(target_dir.clone());
            args.port_offset = Some(eff_offset);
            pending_record = Some((target_dir, inst_name));
        }

        let plan = resolve_doctor_plan(&args, args.pg_url.as_deref())?;
        let report = run_doctor(&plan, &DoctorHost::live());
        if report.exit_code != 0 {
            for c in &report.checks {
                if c.status == CheckStatus::Fail {
                    eprintln!("[{}] FAIL: {}", c.id, c.message);
                    if let Some(fix) = &c.fix {
                        eprintln!("     fix: {fix}");
                    }
                }
            }
            return Err(silent_exit(report.exit_code));
        }

        if !args.state_in_files {
            if let (Some(pg), Some((_, ref inst_name))) =
                (args.pg_url.as_deref(), pending_record.as_ref())
            {
                ensure_pg_schema_exists(pg, &format!("{inst_name}-state"))?;
            }
        }
    }
    let mut spec = resolve_spec_for_up(&args)?;
    std::fs::create_dir_all(&spec.state_dir)
        .map_err(|e| format!("cannot create {}: {e}", spec.state_dir.display()))?;
    super::super::engine::mark_state_dir_if_empty(&spec.state_dir);
    let eff_pg_schema = if !args.state_in_files && args.pg_url.is_some() {
        pending_record
            .as_ref()
            .map(|(_, inst_name)| format!("{inst_name}-state"))
    } else {
        None
    };
    let inst_name_for_recipe = pending_record.as_ref().map(|(_, n)| n.clone());
    if let Some((target_dir, inst_name)) = pending_record {
        let detected_pg_url = args.pg_url.clone().or_else(|| {
            spec.services.iter().find_map(|s| match &s.storage {
                StorageSpec::Postgres { url, .. } => Some(url.clone()),
                _ => None,
            })
        });
        let rec = InstanceRecord {
            name: inst_name.clone(),
            port_offset: args.port_offset.unwrap_or(0),
            created_at_unix_secs: now_unix_secs(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            manifest_hash: compute_manifest_hash(args.file.as_deref(), args.config.as_deref()),
            pg_url: detected_pg_url,
            pg_prefix: Some(inst_name),
        };
        write_instance_record(&target_dir, &rec)?;
    }
    configure_dev_auth_for_up(&mut spec, args.dev_auth, args.worker)?;
    if should_run_up_preflight(args.worker) {
        save_startup_recipe(
            &args,
            &spec,
            &spec.state_dir,
            inst_name_for_recipe.as_deref(),
            args.pg_url.as_deref(),
            eff_pg_schema.as_deref(),
        )?;
    }
    if args.worker {
        return run_supervisor(spec, true);
    }
    if args.detach {
        let worker_args = build_worker_argv(&args, &spec.state_dir);
        let detach_wait_secs = std::env::var("CANTON_RS_DETACH_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(120);
        let ack = spawn_detached_and_wait(&spec.state_dir, &worker_args, detach_wait_secs)?;
        let _ = READY_HANDSHAKE_FILE;
        println!(
            "[+] Running {}/{} ({})",
            ack.nodes.len(),
            ack.nodes.len(),
            ack.stack_name
        );
        println!(" * Synchronizer {:<20} Ready", ack.synchronizer);
        for n in &ack.nodes {
            println!(
                " + {:<12} {:<18} Healthy ({}) {:.1}s",
                n.role.as_str(),
                n.name,
                n.summary,
                (n.elapsed_ms as f64) / 1000.0
            );
        }
        println!(
            "IPC socket: {} | Attach: canton-rs console attach --state-dir {}",
            socket_path(&spec.state_dir).display(),
            spec.state_dir.display()
        );
        return Ok(());
    }
    run_supervisor(spec, false)
}

pub(super) fn cmd_down(args: DownArgs) -> Result<(), String> {
    let mut out = io::stdout();
    cmd_down_with_writer(&args, &mut out)
}

pub(crate) fn cmd_down_with_writer<W: Write>(args: &DownArgs, out: &mut W) -> Result<(), String> {
    let raw_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    let eff_state_dir = resolve_client_state_dir(&raw_dir);
    let sock = socket_path(&eff_state_dir);
    if args.verbose {
        let _ = writeln!(
            out,
            "[down] Connecting to supervisor socket {}...",
            sock.display()
        );
        let _ = out.flush();
    }

    let req = IpcRequest::Down {
        timeout_secs: Some(args.timeout_secs),
        clean_files: Some(args.clean_files),
        stream_progress: true,
    };
    let read_timeout = Duration::from_secs(args.timeout_secs.saturating_add(15));
    let mut reader = open_stream(&eff_state_dir, &req, Some(read_timeout))?;

    let mut completed: Option<(usize, u64, bool)> = None;
    let mut fallback_stopped: Option<usize> = None;
    let mut clean_refused: Option<String> = None;
    let mut raw = String::new();
    loop {
        raw.clear();
        let n = super::super::ipc::read_stream_line(
            &mut reader,
            &mut raw,
            "reading supervisor down progress",
            Some(read_timeout),
        )?;
        if n == 0 {
            break;
        }
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(IpcStreamEvent::DownProgress { data }) =
            serde_json::from_str::<IpcStreamEvent>(trimmed)
        {
            if let DownProgressEvent::CleaningFiles {
                refused: Some(ref why),
                ..
            } = data
            {
                clean_refused = Some(why.clone());
            }
            if let Some(done) =
                write_down_progress_event(out, &data, args.verbose).map_err(|e| e.to_string())?
            {
                completed = Some(done);
            }
            continue;
        }
        if let Ok(resp) = serde_json::from_str::<IpcResponse>(trimmed) {
            match resp {
                IpcResponse::Error { ok: false, error } => return Err(error),
                IpcResponse::DownAck { stopped, .. } => {
                    fallback_stopped = Some(stopped);
                    break;
                }
                other => return Err(format!("unexpected response from supervisor: {other:?}")),
            }
        }
    }

    let wait_secs = if fallback_stopped.is_some() {
        args.timeout_secs.saturating_add(3)
    } else {
        3
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(wait_secs);
    while std::time::Instant::now() < deadline && sock.symlink_metadata().is_ok() {
        std::thread::sleep(Duration::from_millis(25));
    }
    if args.verbose {
        let _ = writeln!(
            out,
            "[down] IPC socket {} unlinked; supervisor exited.",
            sock.display()
        );
    }

    let (stopped, elapsed_suffix) = match completed {
        Some((count, ms, _)) => (count, format!(" ({:.1}s)", (ms as f64) / 1000.0)),
        None => (
            fallback_stopped.ok_or_else(|| {
                "supervisor closed IPC socket before completing shutdown".to_string()
            })?,
            String::new(),
        ),
    };
    let clean_note = if args.clean_files && clean_refused.is_none() {
        " and removed local state files (PostgreSQL tables untouched)"
    } else {
        ""
    };
    let _ = writeln!(
        out,
        "Stopped {stopped} supervised service(s){clean_note}{elapsed_suffix}."
    );
    let _ = out.flush();
    if let Some(why) = clean_refused {
        return Err(format!("--clean-files refused: {why}"));
    }
    Ok(())
}

pub(super) fn write_down_progress_event<W: Write>(
    out: &mut W,
    ev: &DownProgressEvent,
    verbose: bool,
) -> io::Result<Option<(usize, u64, bool)>> {
    let mut done = None;
    if verbose {
        match ev {
            DownProgressEvent::Started {
                stack_name,
                synchronizer,
                storage_mode,
                state_dir,
                timeout_secs,
                clean_files,
                order,
            } => {
                writeln!(
                    out,
                    "[down] Stack '{stack_name}' (synchronizer={synchronizer}, storage={storage_mode}, state_dir={state_dir}, timeout={timeout_secs}s, clean_files={clean_files})"
                )?;
                let order_str = if order.is_empty() {
                    "-".to_string()
                } else {
                    order.join(" -> ")
                };
                writeln!(
                    out,
                    "[down] Reverse shutdown order ({} slot(s)): {order_str}",
                    order.len()
                )?;
            }
            DownProgressEvent::StoppingSlot {
                step,
                total,
                name,
                role,
                pid,
                ports,
                timeout_secs,
            } => {
                writeln!(
                    out,
                    "[down] [{step}/{total}] {name} (role={role}, pid={pid}, ports={ports}): sending SIGTERM (timeout {timeout_secs}s)..."
                )?;
            }
            DownProgressEvent::SlotStopped {
                step,
                total,
                name,
                pid,
                elapsed_ms,
                forced_kill,
                ..
            } => {
                if *forced_kill {
                    writeln!(
                        out,
                        "[down] [{step}/{total}] {name} (pid={pid}): grace timeout elapsed -> escalated to SIGKILL ({elapsed_ms} ms)"
                    )?;
                } else {
                    writeln!(
                        out,
                        "[down] [{step}/{total}] {name} (pid={pid}): exited cleanly via SIGTERM ({elapsed_ms} ms)"
                    )?;
                }
            }
            DownProgressEvent::SlotSkipped {
                step,
                total,
                name,
                role,
            } => {
                writeln!(
                    out,
                    "[down] [{step}/{total}] {name} (role={role}, pid=-): already stopped; skipping signal"
                )?;
            }
            DownProgressEvent::CleaningFiles {
                state_dir,
                clean_files,
                removed_entries,
                refused,
            } => {
                if let Some(why) = refused {
                    writeln!(out, "[down] Removed PID manifest; --clean-files {why}")?;
                } else if *clean_files {
                    writeln!(
                        out,
                        "[down] Removed PID manifest & {removed_entries} local state/log item(s) under {state_dir} (PostgreSQL untouched)"
                    )?;
                } else {
                    writeln!(
                        out,
                        "[down] Removed PID manifest; preserving state directory {state_dir} (pass --clean-files to delete local files)"
                    )?;
                }
            }
            DownProgressEvent::Completed {
                stopped,
                elapsed_ms,
                clean_files,
            } => {
                done = Some((*stopped, *elapsed_ms, *clean_files));
            }
        }
    } else {
        match ev {
            DownProgressEvent::Started {
                stack_name, order, ..
            } => {
                writeln!(
                    out,
                    "[-] Stopping {} service(s) in '{stack_name}'...",
                    order.len()
                )?;
            }
            DownProgressEvent::StoppingSlot {
                step,
                total,
                role,
                name,
                ..
            } => {
                write!(
                    out,
                    " - [{step}/{total}] {role:<12} {name:<18} stopping... "
                )?;
            }
            DownProgressEvent::SlotStopped {
                elapsed_ms,
                forced_kill,
                ..
            } => {
                let secs = (*elapsed_ms as f64) / 1000.0;
                if *forced_kill {
                    writeln!(out, "killed after timeout ({secs:.1}s)")?;
                } else {
                    writeln!(out, "stopped ({secs:.1}s)")?;
                }
            }
            DownProgressEvent::SlotSkipped {
                step,
                total,
                role,
                name,
            } => {
                writeln!(
                    out,
                    " - [{step}/{total}] {role:<12} {name:<18} already stopped"
                )?;
            }
            DownProgressEvent::CleaningFiles {
                clean_files,
                removed_entries,
                refused,
                ..
            } => {
                if let Some(why) = refused {
                    writeln!(out, " - Local files kept: {why}")?;
                } else if *clean_files {
                    writeln!(
                        out,
                        " - Cleaning local state & logs ({removed_entries} item(s) removed)"
                    )?;
                }
            }
            DownProgressEvent::Completed {
                stopped,
                elapsed_ms,
                clean_files,
            } => {
                done = Some((*stopped, *elapsed_ms, *clean_files));
            }
        }
    }
    out.flush()?;
    Ok(done)
}

pub(super) fn cmd_stop(args: SlotTargetsArgs) -> Result<(), String> {
    let state_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    match call_unary(
        &state_dir,
        &IpcRequest::StopNodes {
            targets: args.targets,
        },
    )? {
        IpcResponse::StoppedNodes { stopped, .. } => {
            println!(
                "Stopped slot(s): {} (auto-restart paused; slot preserved)",
                stopped.join(", ")
            );
            Ok(())
        }
        other => Err(format!("unexpected IPC response: {other:?}")),
    }
}

pub(super) fn cmd_start(args: StartOrUpArgs) -> Result<(), String> {
    if args.targets.is_empty() || args.file.is_some() || args.config.is_some() {
        return cmd_up(UpArgs {
            file: args.file,
            config: args.config,
            bootstrap: None,
            detach: args.detach,
            name: args.name,
            state_dir: args.state_dir,
            official_pg_addr: None,
            conf_auth_cert: None,
            dar: None,
            state_in_files: false,
            port_offset: None,
            same_identity: false,
            official_write: false,
            strict_config: false,
            log_encoder: LogEncoder::Text,
            log_level: None,
            log_diagnostics: None,
            suppress_idle_polls: None,
            no_restart: false,
            metrics_port: None,
            metrics_bind: "127.0.0.1".into(),
            observability: false,
            dev_auth: false,
            bind: "127.0.0.1".into(),
            log_max_bytes: DEFAULT_LOG_MAX_BYTES,
            log_max_files: DEFAULT_LOG_MAX_FILES,
            trace_rate_limit: DEFAULT_TRACE_RATE_LIMIT,
            xray: false,
            shadow_verify: false,
            shadow_jvm_url: None,
            profile: Vec::new(),
            group: Vec::new(),
            token_env: None,
            token_file: None,
            pg_url: None,
            worker: false,
        });
    }
    let state_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    match call_unary(
        &state_dir,
        &IpcRequest::StartNodes {
            targets: args.targets,
        },
    )? {
        IpcResponse::StartedNodes { started, .. } => {
            for item in started {
                println!("Started {} (pid {})", item.node, item.pid);
            }
            Ok(())
        }
        other => Err(format!("unexpected IPC response: {other:?}")),
    }
}

pub(super) fn cmd_restart(args: RestartArgs) -> Result<(), String> {
    let state_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    match call_unary(
        &state_dir,
        &IpcRequest::Restart {
            target: args.target,
        },
    )? {
        IpcResponse::Restarted { restarted, .. } => {
            println!("Restarted: {}", restarted.join(", "));
            Ok(())
        }
        other => Err(format!("unexpected IPC response: {other:?}")),
    }
}

pub(super) fn cmd_remove(args: RemoveArgs) -> Result<(), String> {
    let root = instances_root().map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    let plan = plan_instance_remove(&root, &args.name, args.pg_url.as_deref())?;
    if args.dry_run {
        let report = build_dry_run_report(&plan);
        match args.format {
            StatusFormatArg::Json => println!("{}", render_remove_json(&report)?),
            StatusFormatArg::Text => print!("{}", render_remove_text(&report)),
        }
        return Ok(());
    }

    if plan.alive && !args.force {
        if !io::stdin().is_terminal() {
            return Err(exit_with_message(
                EXIT_PREFLIGHT,
                format!(
                    "instance '{}' is still running; pass --force when no TTY is attached",
                    args.name
                ),
            ));
        }
        let mut stderr = io::stderr();
        let _ = write!(
            stderr,
            "Stop running instance '{}' and remove {}? [y/N]: ",
            args.name,
            plan.target_dir.display()
        );
        let _ = stderr.flush();
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("failed to read confirmation: {e}"))?;
        let trimmed = line.trim().to_ascii_lowercase();
        if !matches!(trimmed.as_str(), "y" | "yes") {
            return Err(exit_with_message(
                EXIT_PREFLIGHT,
                format!("removal of instance '{}' aborted", args.name),
            ));
        }
    }

    if plan.alive {
        cmd_down_with_writer(
            &DownArgs {
                name: None,
                state_dir: Some(plan.target_dir.clone()),
                timeout_secs: DEFAULT_SHUTDOWN_TIMEOUT_SECS,
                clean_files: false,
                verbose: false,
            },
            &mut io::sink(),
        )?;
    }

    let report = execute_instance_remove(&root, &plan)?;
    match args.format {
        StatusFormatArg::Json => println!("{}", render_remove_json(&report)?),
        StatusFormatArg::Text => print!("{}", render_remove_text(&report)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_xray_respects_per_service_xray_false_override() {
        let dir = std::env::temp_dir().join(format!(
            "crs-cli-xray-override-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let yaml_path = dir.join("canton-daemon.yaml");
        std::fs::write(
            &yaml_path,
            "\
services:
  p1:
    role: participant
    ports: [\"7575:json-api\"]
  p2:
    role: participant
    ports: [\"7576:json-api\"]
    xray: false
",
        )
        .expect("write manifest");

        let args = UpArgs {
            file: Some(yaml_path),
            config: None,
            bootstrap: None,
            detach: false,
            name: None,
            state_dir: Some(dir.join("state")),
            official_pg_addr: None,
            conf_auth_cert: None,
            dar: None,
            state_in_files: false,
            port_offset: None,
            same_identity: false,
            official_write: false,
            strict_config: false,
            log_encoder: LogEncoder::Text,
            log_level: None,
            log_diagnostics: None,
            suppress_idle_polls: None,
            no_restart: false,
            metrics_port: None,
            metrics_bind: "127.0.0.1".into(),
            observability: false,
            dev_auth: false,
            bind: "127.0.0.1".into(),
            log_max_bytes: DEFAULT_LOG_MAX_BYTES,
            log_max_files: DEFAULT_LOG_MAX_FILES,
            xray: true,
            trace_rate_limit: DEFAULT_TRACE_RATE_LIMIT,
            shadow_verify: false,
            shadow_jvm_url: None,
            profile: Vec::new(),
            group: Vec::new(),
            token_env: None,
            token_file: None,
            pg_url: None,
            worker: false,
        };
        let spec = resolve_spec_for_up(&args).expect("resolve_spec_for_up");
        let p1 = spec
            .services
            .iter()
            .find(|s| s.name == "p1")
            .expect("p1 service");
        let p2 = spec
            .services
            .iter()
            .find(|s| s.name == "p2")
            .expect("p2 service");
        assert!(
            p1.argv.iter().any(|a| a == "--xray") && p1.xray_url.is_some(),
            "p1 (no per-service override) must enable --xray from CLI flag: argv={:?}, xray_url={:?}",
            p1.argv,
            p1.xray_url
        );
        assert!(
            !p2.argv.iter().any(|a| a == "--xray") && p2.xray_url.is_none(),
            "p2 with per-service xray: false must NOT have CLI --xray forced on: argv={:?}, xray_url={:?}",
            p2.argv,
            p2.xray_url
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_xray_handles_per_service_xray_true_with_and_without_cli_flag() {
        let dir = std::env::temp_dir().join(format!(
            "crs-cli-xray-per-svc-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let yaml_path = dir.join("canton-daemon.yaml");
        std::fs::write(
            &yaml_path,
            "\
services:
  p1:
    role: participant
    ports: [\"7575:json-api\"]
    xray: true
  p2:
    role: participant
    ports: [\"7576:json-api\"]
",
        )
        .expect("write manifest");

        let make_args = |cli_xray: bool| UpArgs {
            file: Some(yaml_path.clone()),
            config: None,
            bootstrap: None,
            detach: false,
            name: None,
            state_dir: Some(dir.join("state")),
            official_pg_addr: None,
            conf_auth_cert: None,
            dar: None,
            state_in_files: false,
            port_offset: None,
            same_identity: false,
            official_write: false,
            strict_config: false,
            log_encoder: LogEncoder::Text,
            log_level: None,
            log_diagnostics: None,
            suppress_idle_polls: None,
            no_restart: false,
            metrics_port: None,
            metrics_bind: "127.0.0.1".into(),
            observability: false,
            dev_auth: false,
            bind: "127.0.0.1".into(),
            log_max_bytes: DEFAULT_LOG_MAX_BYTES,
            log_max_files: DEFAULT_LOG_MAX_FILES,
            xray: cli_xray,
            trace_rate_limit: DEFAULT_TRACE_RATE_LIMIT,
            shadow_verify: false,
            shadow_jvm_url: None,
            profile: Vec::new(),
            group: Vec::new(),
            token_env: None,
            token_file: None,
            pg_url: None,
            worker: false,
        };

        let spec_without_cli = resolve_spec_for_up(&make_args(false)).expect("resolve xray=false");
        let p1_no_cli = spec_without_cli
            .services
            .iter()
            .find(|s| s.name == "p1")
            .expect("p1");
        let p2_no_cli = spec_without_cli
            .services
            .iter()
            .find(|s| s.name == "p2")
            .expect("p2");
        assert!(
            p1_no_cli.argv.iter().any(|a| a == "--xray")
                && p1_no_cli.xray_url.as_deref() == Some("http://127.0.0.1:7575/_xray"),
            "p1 with per-service xray: true must enable --xray even without CLI --xray: {:?}",
            p1_no_cli.argv
        );
        assert!(
            !p2_no_cli.argv.iter().any(|a| a == "--xray") && p2_no_cli.xray_url.is_none(),
            "p2 without xray override must remain disabled when CLI --xray is false: {:?}",
            p2_no_cli.argv
        );

        let spec_with_cli = resolve_spec_for_up(&make_args(true)).expect("resolve xray=true");
        let p1_cli = spec_with_cli
            .services
            .iter()
            .find(|s| s.name == "p1")
            .expect("p1");
        let p2_cli = spec_with_cli
            .services
            .iter()
            .find(|s| s.name == "p2")
            .expect("p2");
        assert_eq!(
            p1_cli
                .argv
                .iter()
                .filter(|a| a.as_str() == "--xray")
                .count(),
            1,
            "p1 with per-service xray: true + CLI --xray must not duplicate --xray flag: {:?}",
            p1_cli.argv
        );
        assert!(p1_cli.xray_url.as_deref() == Some("http://127.0.0.1:7575/_xray"));
        assert!(
            p2_cli.argv.iter().any(|a| a == "--xray")
                && p2_cli.xray_url.as_deref() == Some("http://127.0.0.1:7576/_xray"),
            "p2 must enable --xray when CLI --xray is true: {:?}",
            p2_cli.argv
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
