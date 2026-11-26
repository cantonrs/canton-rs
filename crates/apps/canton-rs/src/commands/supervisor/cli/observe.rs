use std::io::BufRead;
use std::path::PathBuf;
use std::time::Duration;

use ledger_json_api::canton_log::LogEncoder;

use super::super::ipc::{
    call_unary, open_stream, socket_path, IpcRequest, IpcResponse, IpcStreamEvent,
};
use super::super::log_rotate::LogLevel;
use super::super::manifest::{
    format_masked_config_summary, render_init_yaml_with_options, InitTemplate, EMBEDDED_SAMPLE_DAR,
    SAMPLE_DAR_FILENAME,
};
use super::super::metrics::{render_markdown_report, render_stats_table};
use super::super::proc_sampler::{scan_host_canton_processes, OsProcSampler};
use super::super::registry::{
    collect_instance_list, instances_root, render_instance_list_json, render_instance_list_text,
    resolve_target_state_dir,
};
use super::super::service_unit::{install_service_file, InstallServiceOptions, ServiceFormat};
use super::super::status::{
    collect_daemon_status, render_env_exports, render_status_json, render_status_text,
};
use super::super::wiretap::render_trace_text;
use super::super::{
    format_bytes, format_uptime, now_unix_ms, NodeLifecycleState, DEFAULT_LOG_MAX_BYTES,
    DEFAULT_LOG_MAX_FILES, DEFAULT_TRACE_RATE_LIMIT,
};
use super::lifecycle::resolve_spec_for_up;
use super::{
    ConfigCheckArgs, EnvArgs, InitArgs, InspectArgs, InstallServiceCliArgs, ListArgs, LogsArgs,
    PsArgs, ServiceFormatArg, StatsArgs, StatusArgs, StatusFormatArg, TemplateArg, UpArgs,
};

pub(super) fn cmd_ps(args: PsArgs) -> Result<(), String> {
    let state_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    let snapshot_opt = if args.scan_host
        && !socket_path(&state_dir).exists()
        && socket_path(&state_dir).symlink_metadata().is_err()
    {
        None
    } else {
        match call_unary(&state_dir, &IpcRequest::GetSnapshot)? {
            IpcResponse::Snapshot { snapshot, .. } => Some(snapshot),
            _ => None,
        }
    };

    let unmanaged = if args.scan_host {
        let managed_pids: Vec<u32> = snapshot_opt
            .as_ref()
            .map(|s| s.nodes.iter().filter_map(|n| n.pid).collect())
            .unwrap_or_default();
        let mut sampler = OsProcSampler::new();
        scan_host_canton_processes(&managed_pids, &mut sampler)
    } else {
        Vec::new()
    };

    if args.json {
        let val = serde_json::json!({
            "snapshot": snapshot_opt,
            "unmanaged": unmanaged,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&val).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    if args.report {
        let snap = snapshot_opt.ok_or("no running supervisor snapshot for --report")?;
        println!("{}", render_markdown_report(&snap));
        return Ok(());
    }

    if let Some(snap) = &snapshot_opt {
        println!(
            "{:<3} {:<15} {:<11} {:<7} {:<24} {:<26} {:<7} MEM",
            "ID", "NAME", "ROLE", "PID", "STATUS", "PORTS", "CPU"
        );
        for n in &snap.nodes {
            if !args.all
                && matches!(
                    n.state,
                    NodeLifecycleState::Stopped | NodeLifecycleState::Failed
                )
            {
                continue;
            }
            let pid = n.pid.map_or_else(|| "-".into(), |p| p.to_string());
            let status = match n.state {
                NodeLifecycleState::Online => {
                    format!("Up {} (healthy)", format_uptime(n.uptime_secs))
                }
                NodeLifecycleState::Stopped => {
                    let ago = n
                        .stopped_at_unix_ms
                        .map(|ms| {
                            format!(
                                " {} ago",
                                format_uptime(now_unix_ms().saturating_sub(ms) / 1000)
                            )
                        })
                        .unwrap_or_default();
                    format!("Exited (0){ago}")
                }
                other => other.display_label().to_string(),
            };
            let cpu = if n.pid.is_some() {
                format!("{:.1}%", n.resources.cpu_percent)
            } else {
                "-".into()
            };
            let mem = if n.pid.is_some() {
                format_bytes(n.resources.rss_bytes)
            } else {
                "-".into()
            };
            println!(
                "{:<3} {:<15} {:<11} {:<7} {:<24} {:<26} {:<7} {}",
                n.slot_id,
                n.name,
                n.role.as_str(),
                pid,
                status,
                n.ports.summary(),
                cpu,
                mem
            );
        }
    }

    if args.scan_host {
        println!("\nUNMANAGED HOST CANTON-RS PROCESSES:");
        if unmanaged.is_empty() {
            println!("  (none)");
        } else {
            println!(
                "  {:<7} {:<18} {:<16} {:<7} {:<10} CMDLINE",
                "PID", "ROLE", "PORTS", "CPU", "MEM"
            );
            for p in &unmanaged {
                let ports: String = if p.ports.is_empty() {
                    "-".into()
                } else {
                    p.ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                };
                println!(
                    "  {:<7} {:<18} {:<16} {:<6.1}% {:<10} {}",
                    p.pid,
                    p.role_hint,
                    ports,
                    p.resources.cpu_percent,
                    format_bytes(p.resources.rss_bytes),
                    p.sanitized_cmdline
                );
            }
        }
    }
    Ok(())
}

pub(super) fn cmd_logs(args: LogsArgs) -> Result<(), String> {
    let state_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    let min_level = LogLevel::parse_filter(&args.level);
    let req = IpcRequest::SubscribeLogs {
        node: args.node,
        min_level: Some(args.level),
        tail: Some(args.tail),
    };
    let timeout = if args.follow {
        None
    } else {
        Some(Duration::from_millis(250))
    };
    let reader = open_stream(&state_dir, &req, timeout)?;
    let grep_lc = args.grep.as_deref().map(str::to_ascii_lowercase);
    for line in reader.lines() {
        match line {
            Ok(raw) => {
                if let Ok(IpcStreamEvent::Log {
                    node, level, line, ..
                }) = serde_json::from_str::<IpcStreamEvent>(&raw)
                {
                    if level < min_level {
                        continue;
                    }
                    if grep_lc
                        .as_deref()
                        .is_some_and(|g| !line.to_ascii_lowercase().contains(g))
                    {
                        continue;
                    }
                    println!("{node:<14} | {:<5} {line}", level.as_str());
                }
            }
            Err(e)
                if !args.follow
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    Ok(())
}

pub(super) fn cmd_stats(args: StatsArgs) -> Result<(), String> {
    let state_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    if args.no_stream {
        let IpcResponse::Snapshot { snapshot, .. } =
            call_unary(&state_dir, &IpcRequest::GetSnapshot)?
        else {
            return Err("unexpected snapshot response".into());
        };
        println!("{}", render_stats_table(&snapshot));
        return Ok(());
    }
    let reader = open_stream(
        &state_dir,
        &IpcRequest::SubscribeSnapshots {
            interval_ms: Some(1000),
        },
        None,
    )?;
    for line in reader.lines().map_while(Result::ok) {
        if let Ok(IpcStreamEvent::Snapshot { data }) = serde_json::from_str::<IpcStreamEvent>(&line)
        {
            println!("\n{}", render_stats_table(&data));
        }
    }
    Ok(())
}

pub(super) fn cmd_inspect(args: InspectArgs) -> Result<(), String> {
    let state_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    if let Some(root_hash) = args.trace {
        let IpcResponse::Trace { trace, .. } =
            call_unary(&state_dir, &IpcRequest::TraceXray { root_hash })?
        else {
            return Err("unexpected trace_xray response".into());
        };
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&trace).map_err(|e| e.to_string())?
            );
        } else {
            println!("{}", render_trace_text(&trace));
        }
        return Ok(());
    }

    let node = args.node.ok_or_else(|| {
        "specify '<service>' or '--trace <root-hash>' for 'canton-rs daemon inspect'".to_string()
    })?;
    let IpcResponse::Inspection { inspection, .. } =
        call_unary(&state_dir, &IpcRequest::Inspect { node })?
    else {
        return Err("unexpected inspect response".into());
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection).map_err(|e| e.to_string())?
        );
    } else {
        println!("Node        : {} ({})", inspection.name, inspection.role);
        println!(
            "PID / State : {:?} / {}",
            inspection.pid,
            inspection.state.display_label()
        );
        println!("State Dir   : {}", inspection.state_dir);
        println!(
            "Config      : {} (applied={}, not_applied={})",
            inspection.config_path.as_deref().unwrap_or("-"),
            inspection.config_applied_count,
            inspection.config_not_applied_keys.len()
        );
        if !inspection.config_not_applied_keys.is_empty() {
            println!(
                "Not Applied : {}",
                inspection
                    .config_not_applied_keys
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        println!(
            "Log File    : {} ({}, {} gen, encoder={})",
            inspection.log_file_path,
            format_bytes(inspection.log_file_bytes),
            inspection.log_generations,
            inspection.log_encoder
        );
        println!("Storage     : {}", inspection.storage_summary);
        println!("Auth Mode   : {}", inspection.auth_mode);
        println!("Ports       : {}", inspection.ports.summary());
        println!(
            "Canton UID  : {} | Sync: {} | DARs: {} | Parties: {} | Users: {:?}",
            inspection.node_uid.as_deref().unwrap_or("-"),
            inspection
                .physical_synchronizer_id
                .as_deref()
                .unwrap_or("-"),
            inspection.loaded_dars.len(),
            inspection.hosted_parties.len(),
            inspection.user_count
        );
        println!(
            "Restarts    : {} | Last Exit: {:?}",
            inspection.restarts_total, inspection.last_exit_reason
        );
        println!("Argv        : {}", inspection.sanitized_argv.join(" "));
    }
    Ok(())
}

pub(super) fn cmd_init(args: InitArgs) -> Result<(), String> {
    let sample_dar_path = args
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(
            || PathBuf::from(SAMPLE_DAR_FILENAME),
            |dir| dir.join(SAMPLE_DAR_FILENAME),
        );
    if args.output.exists() && !args.force {
        return Err(format!(
            "{} already exists (pass --force to overwrite)",
            args.output.display()
        ));
    }
    if args.with_sample_dar && sample_dar_path.exists() && !args.force {
        return Err(format!(
            "{} already exists (pass --force to overwrite)",
            sample_dar_path.display()
        ));
    }
    let tmpl = match args.template {
        TemplateArg::Default => InitTemplate::Default,
        TemplateArg::Localnet => InitTemplate::Localnet,
        TemplateArg::EnterpriseDvp => InitTemplate::EnterpriseDvp,
        TemplateArg::BftCluster => InitTemplate::BftCluster,
        TemplateArg::MultiDomain => InitTemplate::MultiDomain,
        TemplateArg::OrgProduction => InitTemplate::OrgProduction,
    };
    let yaml = render_init_yaml_with_options(
        tmpl,
        args.from_canton_conf.as_deref(),
        args.bootstrap.as_deref(),
        args.with_sample_dar,
    );
    if args.with_sample_dar {
        std::fs::write(&sample_dar_path, EMBEDDED_SAMPLE_DAR)
            .map_err(|e| format!("cannot write {}: {e}", sample_dar_path.display()))?;
        println!("Extracted {}", sample_dar_path.display());
    }
    std::fs::write(&args.output, yaml)
        .map_err(|e| format!("cannot write {}: {e}", args.output.display()))?;
    println!("Created {}", args.output.display());
    Ok(())
}

pub(super) fn cmd_config(args: ConfigCheckArgs) -> Result<(), String> {
    let up = UpArgs {
        file: args.file,
        config: args.config,
        bootstrap: args.bootstrap,
        detach: false,
        name: None,
        state_dir: args.state_dir,
        official_pg_addr: None,
        conf_auth_cert: None,
        dar: None,
        state_in_files: false,
        port_offset: (args.port_offset != 0).then_some(args.port_offset),
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
    };
    let spec = resolve_spec_for_up(&up)?;
    println!("{}", format_masked_config_summary(&spec));
    Ok(())
}

pub(super) fn cmd_install_service(args: InstallServiceCliArgs) -> Result<(), String> {
    let exe_path = std::env::current_exe().map_err(|e| e.to_string())?;
    let workdir = std::env::current_dir().map_err(|e| e.to_string())?;
    let format = match args.format {
        ServiceFormatArg::Auto => ServiceFormat::host_default(),
        ServiceFormatArg::Systemd => ServiceFormat::Systemd,
        ServiceFormatArg::Launchd => ServiceFormat::Launchd,
    };
    let mut daemon_args = vec!["--state-dir".into(), args.state_dir.display().to_string()];
    if let Some(f) = args.file {
        daemon_args.extend(["-f".into(), f.display().to_string()]);
    } else if let Some(c) = args.config {
        daemon_args.extend(["-c".into(), c.display().to_string()]);
    }
    let system_wide = args.system && !args.user;
    let opts = InstallServiceOptions {
        service_name: args.name,
        state_dir: args.state_dir,
        workdir,
        exe_path,
        daemon_args,
        system_wide,
        format,
        output_path: args.output,
        apply: args.apply,
    };
    let (path, hint) = install_service_file(&opts)?;
    println!("Wrote service definition: {}", path.display());
    println!("To activate: {hint}");
    Ok(())
}

pub(super) fn cmd_list(args: ListArgs) -> Result<(), String> {
    let root = instances_root()?;
    let report = collect_instance_list(&root)?;
    match args.format {
        StatusFormatArg::Json => println!("{}", render_instance_list_json(&report)?),
        StatusFormatArg::Text => print!("{}", render_instance_list_text(&report)),
    }
    Ok(())
}

pub(super) fn cmd_status(args: StatusArgs) -> Result<(), String> {
    let state_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    let report = collect_daemon_status(&state_dir)?;
    match args.format {
        StatusFormatArg::Json => println!("{}", render_status_json(&report)?),
        StatusFormatArg::Text => print!("{}", render_status_text(&report)),
    }
    Ok(())
}

pub(super) fn cmd_env(args: EnvArgs) -> Result<(), String> {
    let state_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    let report = collect_daemon_status(&state_dir)?;
    let exports = render_env_exports(&report)?;
    print!("{exports}");
    Ok(())
}
