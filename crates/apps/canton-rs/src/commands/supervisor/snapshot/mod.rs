//! Cluster-consistent snapshot and restore (`daemon snapshot`, `daemon restore`, `S-DX-004`).
//!
//! [CANTON-NOTE: INVARIANT] Before stopping nodes for snapshotting, all participants, mediators,
//! and sequencers enter `/_quiesce/pause` and drain in-flight operations to zero within the quiesce
//! timeout (`30s` default); timeout resumes every paused node and aborts with `exit = 3` (`S-10`)
//! without creating any bundle. Restore verifies version (`exit = 2`, `S-07`), component SHA-256
//! hashes (`exit = 3`, `S-05`), and post-start identities/ledger ends (`exit = 3`, `S-06`), rolling
//! back backup state on any error.

pub mod bundle;
pub mod quiesce;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use canton_participant::pgconn::{connect as pg_connect, PgTarget};
use serde::{Deserialize, Serialize};

use super::cli::{
    cmd_down_with_writer, DaemonRestoreArgs, DaemonSnapshotArgs, DownArgs, StatusFormatArg, UpArgs,
};
use super::ipc::socket_path;
use super::registry::{
    compute_manifest_hash, instances_root, is_instance_alive, read_instance_record,
    resolve_target_state_dir, resolve_up_port_offset, write_instance_record, InstanceRecord,
};
use super::status::{collect_daemon_status, EndpointState};
use super::{now_unix_ms, now_unix_secs, DaemonSpec, StorageSpec};
use crate::commands::exit_code::{exit_with_message, EXIT_MISMATCH, EXIT_PREFLIGHT};

/// Snapshot bundle format version (`snapshot.json`).
pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;
/// Startup recipe persisted inside `<state_dir>` for self-contained snapshot restart and restore.
pub const RECIPE_FILE: &str = "daemon.recipe.json";
/// JSON manifest file embedded at root of every `.tar` snapshot bundle.
pub const SNAPSHOT_MANIFEST_FILE: &str = "snapshot.json";
/// Default maximum wait for in-flight requests to drain during quiesce.
pub const DEFAULT_QUIESCE_TIMEOUT_SECS: u64 = 30;

/// Per-service metadata recorded inside [`DaemonRecipe`] so `Stores(I)` is deterministic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotServiceInfo {
    pub name: String,
    pub role: String,
    pub state_dir_rel: String,
    pub storage_kind: String,
    #[serde(default)]
    pub state_name: Option<String>,
    #[serde(default)]
    pub has_bft_group: bool,
    #[serde(default)]
    pub synchronizer: String,
}

/// Persisted supervisor launch recipe stored alongside `instance.json` (`0600`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonRecipe {
    pub schema: String,
    pub mode: String,
    pub manifest_file: String,
    #[serde(default)]
    pub canton_conf_file: Option<String>,
    #[serde(default)]
    pub bootstrap_file: Option<String>,
    pub launch_cwd: PathBuf,
    pub instance_name: String,
    pub port_offset: u16,
    #[serde(default)]
    pub pg_url: Option<String>,
    #[serde(default)]
    pub pg_schema: Option<String>,
    pub state_in_files: bool,
    #[serde(default)]
    pub metrics_port: Option<u16>,
    #[serde(default)]
    pub metrics_bind: String,
    #[serde(default)]
    pub profile: Vec<String>,
    #[serde(default)]
    pub group: Vec<String>,
    #[serde(default)]
    pub dar: Option<PathBuf>,
    #[serde(default)]
    pub xray: bool,
    #[serde(default)]
    pub no_restart: bool,
    #[serde(default)]
    pub strict_config: bool,
    #[serde(default)]
    pub same_identity: bool,
    #[serde(default)]
    pub official_write: bool,
    #[serde(default)]
    pub official_pg_addr: Option<String>,
    #[serde(default)]
    pub conf_auth_cert: Option<PathBuf>,
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    pub log_encoder: String,
    #[serde(default)]
    pub dev_auth: bool,
    #[serde(default)]
    pub observability: bool,
    #[serde(default = "default_loopback_bind")]
    pub bind: String,
    #[serde(default)]
    pub bind_addresses: Vec<String>,
    pub services: Vec<SnapshotServiceInfo>,
}

fn default_loopback_bind() -> String {
    "127.0.0.1".to_string()
}

/// One persisted store file entry recorded in [`SnapshotManifest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFileEntry {
    pub bundle_rel_path: String,
    pub store_rel_path: String,
    pub sha256: String,
    pub size: u64,
}

/// Logical store component included in a snapshot bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotComponent {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub service: Option<String>,
    pub files: Vec<SnapshotFileEntry>,
    pub sha256: String,
}

/// Top-level `snapshot.json` manifest written into every bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub format_version: u32,
    pub canton_rs_version: String,
    pub created_at_unix_secs: u64,
    pub source_name: String,
    pub storage_mode: String,
    #[serde(default)]
    pub pg_schema: Option<String>,
    pub source_manifest_hash: String,
    pub manifest_hash: String,
    pub components: Vec<SnapshotComponent>,
    pub ledger_ends: BTreeMap<String, u64>,
    pub node_identities: BTreeMap<String, String>,
    #[serde(default)]
    pub scan_history_lines: Option<usize>,
}

/// Machine-readable report emitted by `canton-rs daemon snapshot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotReport {
    pub schema: String,
    pub name: String,
    pub out: String,
    pub storage_mode: String,
    pub component_count: usize,
    pub manifest_hash: String,
    pub ledger_ends: BTreeMap<String, u64>,
}

/// Machine-readable report emitted by `canton-rs daemon restore`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    pub schema: String,
    pub name: String,
    pub source_name: String,
    pub from: String,
    pub port_offset: u16,
    pub storage_mode: String,
    pub ledger_ends: BTreeMap<String, u64>,
}

/// Appends or replaces `?currentSchema=<schema>` on a PostgreSQL connection URL.
pub fn scope_pg_url(pg_url: &str, schema: &str) -> String {
    let Some((base, query)) = pg_url.split_once('?') else {
        return format!("{pg_url}?currentSchema={schema}");
    };
    let mut kept: Vec<String> = query
        .split('&')
        .filter(|part| !part.is_empty() && !part.starts_with("currentSchema="))
        .map(String::from)
        .collect();
    kept.push(format!("currentSchema={schema}"));
    format!("{base}?{}", kept.join("&"))
}

/// Strips `currentSchema=...` and converts `jdbc:postgresql://` to `postgres://` for `pg_dump`/`psql`.
pub fn strip_pg_schema_param(pg_url: &str) -> String {
    let normalized = pg_url
        .strip_prefix("jdbc:postgresql://")
        .map(|rest| format!("postgres://{rest}"))
        .unwrap_or_else(|| pg_url.to_string());
    let Some((base, query)) = normalized.split_once('?') else {
        return normalized;
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|part| !part.is_empty() && !part.starts_with("currentSchema="))
        .collect();
    if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    }
}

/// Ensures PostgreSQL schema `schema` exists using a dedicated non-Tokio thread.
pub fn ensure_pg_schema_exists(base_pg_url: &str, schema: &str) -> Result<(), String> {
    let url = strip_pg_schema_param(base_pg_url);
    let quoted = format!("\"{}\"", schema.replace('"', "\"\""));
    let handle = thread::spawn(move || -> Result<(), String> {
        let target = PgTarget::from_url_or_jdbc(&url, None, None, None)?;
        let mut client = pg_connect(&target)?;
        client
            .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {quoted}"))
            .map_err(|e| format!("create PostgreSQL schema {quoted}: {e}"))?;
        Ok(())
    });
    handle
        .join()
        .map_err(|_| "PostgreSQL schema setup worker panicked".to_string())?
}

/// Atomically writes `bytes` to `path` with mode `0600` (`0700` parent directory).
pub fn atomic_write_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("missing parent directory for {}", path.display()))?;
    if !parent.exists() {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder
            .create(parent)
            .map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let tmp = parent.join(format!(".{fname}.tmp.{}", std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("open {}: {e}", tmp.display()))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename {} -> {}: {e}", tmp.display(), path.display())
    })
}

/// Persists `daemon.recipe.json` and copies source manifest files into `state_dir` during `daemon up`.
pub fn save_startup_recipe(
    args: &UpArgs,
    spec: &DaemonSpec,
    state_dir: &Path,
    inst_name: Option<&str>,
    base_pg_url: Option<&str>,
    pg_schema: Option<&str>,
) -> Result<(), String> {
    let launch_cwd = std::env::current_dir()
        .and_then(|p| p.canonicalize())
        .unwrap_or_else(|_| PathBuf::from("."));

    let (mode, manifest_file, canton_conf_file) = if let Some(ref f) = args.file {
        let bytes = fs::read(f).map_err(|e| format!("read manifest {}: {e}", f.display()))?;
        atomic_write_0600(&state_dir.join("manifest.yaml"), &bytes)?;
        let dotenv_path = f.parent().map(|p| p.join(".env"));
        if let Some(envp) = dotenv_path.filter(|p| p.is_file()) {
            if let Ok(eb) = fs::read(envp) {
                let _ = atomic_write_0600(&state_dir.join(".env"), &eb);
            }
        }
        if let Some(ref conf) = spec.canton_conf {
            let cb =
                fs::read(conf).map_err(|e| format!("read canton.conf {}: {e}", conf.display()))?;
            atomic_write_0600(&state_dir.join("canton.conf"), &cb)?;
            (
                "mode_b".to_string(),
                "manifest.yaml".to_string(),
                Some("canton.conf".to_string()),
            )
        } else {
            ("mode_a".to_string(), "manifest.yaml".to_string(), None)
        }
    } else if let Some(ref conf) = args.config {
        let cb = fs::read(conf).map_err(|e| format!("read canton.conf {}: {e}", conf.display()))?;
        atomic_write_0600(&state_dir.join("canton.conf"), &cb)?;
        (
            "mode_b".to_string(),
            "canton.conf".to_string(),
            Some("canton.conf".to_string()),
        )
    } else {
        let default_yaml = Path::new("canton-daemon.yaml");
        let bytes = fs::read(default_yaml)
            .map_err(|e| format!("read manifest {}: {e}", default_yaml.display()))?;
        atomic_write_0600(&state_dir.join("manifest.yaml"), &bytes)?;
        ("mode_a".to_string(), "manifest.yaml".to_string(), None)
    };

    let bootstrap_file = match args.bootstrap.as_ref().or(spec.bootstrap.as_ref()) {
        Some(boot) if boot.is_file() => {
            let bytes =
                fs::read(boot).map_err(|e| format!("read bootstrap {}: {e}", boot.display()))?;
            atomic_write_0600(&state_dir.join("bootstrap.sc"), &bytes)?;
            Some("bootstrap.sc".to_string())
        }
        _ => None,
    };

    let mut services = Vec::with_capacity(spec.services.len());
    for svc in &spec.services {
        let rel = svc
            .state_dir
            .strip_prefix(&spec.state_dir)
            .unwrap_or_else(|_| Path::new(&svc.name))
            .display()
            .to_string();
        let (storage_kind, state_name) = match &svc.storage {
            StorageSpec::Files => ("files".to_string(), None),
            StorageSpec::Postgres { name, .. } => (
                "postgres".to_string(),
                Some(name.clone().unwrap_or_else(|| svc.name.clone())),
            ),
            StorageSpec::Memory => ("memory".to_string(), None),
        };
        services.push(SnapshotServiceInfo {
            name: svc.name.clone(),
            role: svc.role.as_str().to_string(),
            state_dir_rel: rel,
            storage_kind,
            state_name,
            has_bft_group: svc.bft_peer_count.is_some(),
            synchronizer: svc.synchronizer_domain.clone().unwrap_or_default(),
        });
    }

    let recipe = DaemonRecipe {
        schema: "canton-rs.daemon-recipe/1".to_string(),
        mode,
        manifest_file,
        canton_conf_file,
        bootstrap_file,
        launch_cwd,
        instance_name: inst_name.unwrap_or(&spec.name).to_string(),
        port_offset: args.port_offset.unwrap_or(spec.port_offset),
        pg_url: base_pg_url.map(String::from),
        pg_schema: pg_schema.map(String::from),
        state_in_files: args.state_in_files,
        metrics_port: args.metrics_port,
        metrics_bind: args.metrics_bind.clone(),
        profile: args.profile.clone(),
        group: args.group.clone(),
        dar: args.dar.clone(),
        xray: args.xray,
        no_restart: args.no_restart,
        strict_config: args.strict_config,
        same_identity: args.same_identity,
        official_write: args.official_write,
        official_pg_addr: args.official_pg_addr.clone(),
        conf_auth_cert: args.conf_auth_cert.clone(),
        token_env: args.token_env.clone(),
        token_file: args.token_file.clone(),
        log_encoder: match args.log_encoder {
            ledger_json_api::canton_log::LogEncoder::Text => "text",
            ledger_json_api::canton_log::LogEncoder::Plain => "plain",
            ledger_json_api::canton_log::LogEncoder::Json => "json",
        }
        .to_string(),
        dev_auth: spec.dev_auth,
        observability: spec.observability,
        bind: args.bind.clone(),
        bind_addresses: spec.bind_addresses.clone(),
        services,
    };
    let encoded = serde_json::to_vec_pretty(&recipe).map_err(|e| e.to_string())?;
    atomic_write_0600(&state_dir.join(RECIPE_FILE), &encoded)
}

/// Reads `<state_dir>/daemon.recipe.json`.
pub fn read_daemon_recipe(state_dir: &Path) -> Result<DaemonRecipe, String> {
    let path = state_dir.join(RECIPE_FILE);
    let raw = fs::read_to_string(&path).map_err(|e| {
        format!(
            "missing or unreadable startup recipe {} (recreate instance via `daemon up`): {e}",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid {}: {e}", path.display()))
}

fn wait_instance_stopped(state_dir: &Path, timeout: Duration) {
    let sock = socket_path(state_dir);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline && (sock.exists() || is_instance_alive(state_dir)) {
        thread::sleep(Duration::from_millis(50));
    }
}

fn relaunch_from_recipe(
    state_dir: &Path,
    recipe: &DaemonRecipe,
    inst_name: &str,
    port_offset: u16,
    pg_url: Option<&str>,
    detach_timeout_secs: u64,
) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut cmd = Command::new(&exe);
    if recipe.launch_cwd.is_dir() {
        cmd.current_dir(&recipe.launch_cwd);
    }
    cmd.args(["daemon", "up"]);
    let is_named_dir =
        resolve_target_state_dir(Some(inst_name), None).is_ok_and(|named| named == state_dir);
    if is_named_dir {
        cmd.args(["--name", inst_name]);
    } else {
        cmd.args(["--state-dir"]).arg(state_dir);
    }
    cmd.arg("-d");
    if recipe.mode == "mode_b" && recipe.manifest_file == "canton.conf" {
        cmd.args(["-c"]).arg(state_dir.join("canton.conf"));
    } else {
        cmd.args(["-f"]).arg(state_dir.join(&recipe.manifest_file));
    }
    if let Some(boot) = &recipe.bootstrap_file {
        let bp = state_dir.join(boot);
        if bp.is_file() {
            cmd.args(["--bootstrap"]).arg(bp);
        }
    }
    cmd.args(["--port-offset", &port_offset.to_string()]);
    if recipe.state_in_files {
        cmd.arg("--state-in-files");
    }
    if let Some(url) = pg_url {
        cmd.args(["--pg-url", url]);
    }
    if let Some(mp) = recipe.metrics_port {
        cmd.args(["--metrics-port", &mp.to_string()]);
    }
    if !recipe.metrics_bind.is_empty() && recipe.metrics_bind != "127.0.0.1" {
        cmd.args(["--metrics-bind", &recipe.metrics_bind]);
    }
    if !recipe.profile.is_empty() {
        cmd.args(["--profile", &recipe.profile.join(",")]);
    }
    if !recipe.group.is_empty() {
        cmd.args(["--group", &recipe.group.join(",")]);
    }
    if let Some(dar) = &recipe.dar {
        cmd.args(["--dar"]).arg(dar);
    }
    if recipe.xray {
        cmd.arg("--xray");
    }
    if recipe.no_restart {
        cmd.arg("--no-restart");
    }
    if recipe.strict_config {
        cmd.arg("--strict-config");
    }
    if recipe.same_identity {
        cmd.arg("--same-identity");
    }
    if recipe.official_write {
        cmd.arg("--official-write");
    }
    if let Some(addr) = &recipe.official_pg_addr {
        cmd.args(["--official-pg-addr", addr]);
    }
    if let Some(cert) = &recipe.conf_auth_cert {
        cmd.args(["--conf-auth-cert"]).arg(cert);
    }
    if let Some(te) = &recipe.token_env {
        cmd.args(["--token-env", te]);
    }
    if let Some(tf) = &recipe.token_file {
        cmd.args(["--token-file"]).arg(tf);
    }
    if !recipe.log_encoder.is_empty() && recipe.log_encoder != "text" {
        cmd.args(["--log-encoder", &recipe.log_encoder]);
    }
    if recipe.dev_auth {
        cmd.arg("--dev-auth");
    }
    if recipe.observability {
        cmd.arg("--observability");
    }
    if !recipe.bind.is_empty() && recipe.bind != "127.0.0.1" {
        cmd.args(["--bind", &recipe.bind]);
    }
    cmd.env(
        "CANTON_RS_DETACH_TIMEOUT_SECS",
        detach_timeout_secs.to_string(),
    )
    .stdin(Stdio::null());

    let out = cmd.output().map_err(|e| format!("spawn daemon up: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "daemon up failed ({}):\nstdout:\n{}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let deadline = Instant::now() + Duration::from_secs(detach_timeout_secs.max(15));
    while Instant::now() < deadline {
        if let Ok(status) = collect_daemon_status(state_dir) {
            let core_up = status
                .endpoints
                .iter()
                .filter(|(k, _)| {
                    k.ends_with(".public") || k.ends_with(".admin") || k.ends_with(".json")
                })
                .all(|(_, ep)| ep.state == EndpointState::Up);
            if core_up && !status.endpoints.is_empty() {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(150));
    }
    Err(format!(
        "restarted instance '{inst_name}' endpoints did not report ready within {detach_timeout_secs}s"
    ))
}

fn stop_instance_quietly(state_dir: &Path, timeout_secs: u64) -> Result<(), String> {
    let down = DownArgs {
        name: None,
        state_dir: Some(state_dir.to_path_buf()),
        timeout_secs,
        clean_files: false,
        verbose: false,
    };
    let mut sink = io::sink();
    cmd_down_with_writer(&down, &mut sink)?;
    wait_instance_stopped(state_dir, Duration::from_secs(5));
    Ok(())
}

/// Implements `canton-rs daemon snapshot`.
pub fn cmd_daemon_snapshot(args: DaemonSnapshotArgs) -> Result<(), String> {
    let target_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())?;
    if !is_instance_alive(&target_dir) {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!("instance at {} is not running", target_dir.display()),
        ));
    }
    let recipe =
        read_daemon_recipe(&target_dir).map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    let existing_rec = read_instance_record(&target_dir)?;
    let eff_name = args
        .name
        .clone()
        .or_else(|| existing_rec.as_ref().map(|r| r.name.clone()))
        .unwrap_or_else(|| recipe.instance_name.clone());
    let manifest_hash = existing_rec
        .as_ref()
        .map(|r| r.manifest_hash.clone())
        .unwrap_or_else(|| {
            compute_manifest_hash(Some(&target_dir.join(&recipe.manifest_file)), None)
        });

    let status = collect_daemon_status(&target_dir)?;
    let ctrl_nodes = quiesce::resolve_control_nodes(&recipe, &status.endpoints)?;
    quiesce::quiesce_and_drain(
        &ctrl_nodes,
        Duration::from_secs(args.quiesce_timeout_secs.max(1)),
    )?;
    let expectations = quiesce::collect_live_expectations(&target_dir, &ctrl_nodes)?;

    stop_instance_quietly(&target_dir, args.shutdown_timeout_secs)?;

    let spec = bundle::BuildBundleSpec {
        state_dir: &target_dir,
        recipe: &recipe,
        source_name: &eff_name,
        manifest_hash: &manifest_hash,
        created_at_unix_secs: now_unix_secs(),
        ledger_ends: &expectations.ledger_ends,
        node_identities: &expectations.node_identities,
        scan_history_lines: expectations.scan_history_lines,
        out_tar: &args.out,
    };

    let bundle_res = bundle::create_snapshot_bundle(&spec);
    let restart_res = relaunch_from_recipe(
        &target_dir,
        &recipe,
        &eff_name,
        recipe.port_offset,
        recipe.pg_url.as_deref(),
        120,
    );

    let manifest = match bundle_res {
        Ok(m) => {
            restart_res?;
            m
        }
        Err(err) => {
            let _ = restart_res;
            return Err(err);
        }
    };

    let report = SnapshotReport {
        schema: "canton-rs.snapshot/1".to_string(),
        name: eff_name,
        out: args.out.display().to_string(),
        storage_mode: manifest.storage_mode,
        component_count: manifest.components.len(),
        manifest_hash: manifest.manifest_hash,
        ledger_ends: manifest.ledger_ends,
    };
    match args.format {
        StatusFormatArg::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        }
        StatusFormatArg::Text => {
            println!(
                "Snapshot '{}' written to {} ({} components, mode={}).",
                report.name, report.out, report.component_count, report.storage_mode
            );
        }
    }
    Ok(())
}

struct RestoreContext<'a> {
    target_dir: &'a Path,
    target_name: &'a str,
    eff_offset: u16,
    eff_pg_url: Option<&'a str>,
    eff_pg_schema: Option<&'a str>,
    unpacked: &'a bundle::UnpackedBundle,
    unpacked_recipe: &'a DaemonRecipe,
    unpacked_rec: &'a InstanceRecord,
}

fn perform_restore_attempt(ctx: &RestoreContext<'_>) -> Result<DaemonRecipe, String> {
    // 1. Copy unpacked filesystem stores into target_dir (all symlinks/path escapes blocked).
    bundle::apply_unpacked_files(&ctx.unpacked.manifest, &ctx.unpacked.dir, ctx.target_dir)?;

    // Ensure transient runtime markers are absent before boot.
    for transient in ["daemon.sock", "daemon.pids.json", "daemon.ready.json"] {
        let p = ctx.target_dir.join(transient);
        if p.exists() || p.symlink_metadata().is_ok() {
            let _ = fs::remove_file(&p);
        }
    }

    // 2. Rewrite registry + recipe for target instance M while keeping all node identities untouched.
    let updated_rec = InstanceRecord {
        name: ctx.target_name.to_string(),
        port_offset: ctx.eff_offset,
        created_at_unix_secs: now_unix_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        manifest_hash: ctx.unpacked_rec.manifest_hash.clone(),
        pg_url: ctx.eff_pg_url.map(String::from),
        pg_prefix: Some(ctx.target_name.to_string()),
    };
    write_instance_record(ctx.target_dir, &updated_rec)?;

    let mut updated_recipe = ctx.unpacked_recipe.clone();
    updated_recipe.instance_name = ctx.target_name.to_string();
    updated_recipe.port_offset = ctx.eff_offset;
    updated_recipe.pg_url = ctx.eff_pg_url.map(String::from);
    updated_recipe.pg_schema = ctx.eff_pg_schema.map(String::from);
    let recipe_bytes = serde_json::to_vec_pretty(&updated_recipe).map_err(|e| e.to_string())?;
    atomic_write_0600(&ctx.target_dir.join(RECIPE_FILE), &recipe_bytes)?;

    // 3. Restore PostgreSQL schema if Postgres mode.
    if ctx.unpacked.manifest.storage_mode == "postgres" {
        let pg_url = ctx
            .eff_pg_url
            .ok_or_else(|| "missing --pg-url for postgres snapshot restore".to_string())?;
        let target_schema = ctx
            .eff_pg_schema
            .ok_or_else(|| "missing target pg_schema".to_string())?;
        let src_schema = ctx
            .unpacked
            .manifest
            .pg_schema
            .as_deref()
            .ok_or_else(|| "snapshot manifest missing pg_schema".to_string())?;
        bundle::restore_pg_schema(
            pg_url,
            src_schema,
            target_schema,
            &ctx.unpacked.manifest,
            &ctx.unpacked.dir,
        )?;
    }

    // 4. Launch M from the restored state directory.
    relaunch_from_recipe(
        ctx.target_dir,
        &updated_recipe,
        ctx.target_name,
        ctx.eff_offset,
        ctx.eff_pg_url,
        120,
    )?;

    // 5. Post-start completeness & consistency checks (`S-A6`, ledger_end, identities).
    let status = collect_daemon_status(ctx.target_dir)?;
    let ctrl_nodes = quiesce::resolve_control_nodes(&updated_recipe, &status.endpoints)?;
    quiesce::verify_restored_node_identities(&ctrl_nodes, &ctx.unpacked.manifest.node_identities)?;
    quiesce::verify_restored_ledger_ends(&ctrl_nodes, &ctx.unpacked.manifest.ledger_ends)?;
    quiesce::verify_scan_history(ctx.target_dir, ctx.unpacked.manifest.scan_history_lines)?;

    Ok(updated_recipe)
}

struct RollbackSpec<'a> {
    target_dir: &'a Path,
    bak_dir: Option<&'a Path>,
    pg_url: Option<&'a str>,
    target_schema: Option<&'a str>,
    bak_schema: Option<&'a str>,
    was_alive: bool,
    prev_recipe: Option<&'a DaemonRecipe>,
    target_name: &'a str,
}

fn rollback_restore(spec: &RollbackSpec<'_>) {
    if is_instance_alive(spec.target_dir) {
        let _ = stop_instance_quietly(spec.target_dir, 10);
    }
    if let Ok(exe) = std::env::current_exe() {
        let _ = super::process::cleanup_stale_pids(spec.target_dir, &exe, Duration::from_secs(3));
    }
    if spec.target_dir.exists() {
        let _ = fs::remove_dir_all(spec.target_dir);
    }
    if let Some(bak) = spec.bak_dir {
        if bak.exists() {
            let _ = fs::rename(bak, spec.target_dir);
        }
    }
    if let (Some(url), Some(t_schema)) = (spec.pg_url, spec.target_schema) {
        let drop_sql = format!(
            "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
            t_schema.replace('"', "\"\"")
        );
        let _ = bundle::exec_pg_ddl(url, drop_sql);
        if let Some(b_schema) = spec.bak_schema {
            if bundle::pg_schema_exists(url, b_schema).unwrap_or(false) {
                let rename_sql = format!(
                    "ALTER SCHEMA \"{}\" RENAME TO \"{}\"",
                    b_schema.replace('"', "\"\""),
                    t_schema.replace('"', "\"\"")
                );
                let _ = bundle::exec_pg_ddl(url, rename_sql);
            }
        }
    }
    if spec.was_alive {
        if let Some(rec) = spec.prev_recipe {
            if let Err(err) = relaunch_from_recipe(
                spec.target_dir,
                rec,
                spec.target_name,
                rec.port_offset,
                rec.pg_url.as_deref(),
                120,
            ) {
                eprintln!("rollback relaunch of '{}' failed: {err}", spec.target_name);
            }
        }
    }
}

/// Implements `canton-rs daemon restore`.
pub fn cmd_daemon_restore(args: DaemonRestoreArgs) -> Result<(), String> {
    let target_dir = resolve_target_state_dir(Some(&args.name), args.state_dir.as_deref())?;

    // Step 1-2: Unpack bundle, verify version (`exit=2`), verify SHA-256 hashes (`exit=3`).
    let unpacked = bundle::unpack_and_verify_bundle(&args.from)?;
    let has_registry = unpacked
        .manifest
        .components
        .iter()
        .any(|c| c.kind == "registry");
    let has_recipe = unpacked
        .manifest
        .components
        .iter()
        .any(|c| c.kind == "recipe");
    if !has_registry || !has_recipe {
        return Err(exit_with_message(
            EXIT_MISMATCH,
            "snapshot bundle is missing required registry or recipe component",
        ));
    }

    let unpacked_recipe_path = unpacked.dir.join("stores/recipe").join(RECIPE_FILE);
    let unpacked_recipe: DaemonRecipe = fs::read_to_string(&unpacked_recipe_path)
        .map_err(|e| exit_with_message(EXIT_MISMATCH, format!("read recipe in bundle: {e}")))
        .and_then(|s| {
            serde_json::from_str(&s).map_err(|e| {
                exit_with_message(EXIT_MISMATCH, format!("parse recipe in bundle: {e}"))
            })
        })?;
    let unpacked_rec_path = unpacked.dir.join("stores/registry/instance.json");
    let unpacked_rec: InstanceRecord = fs::read_to_string(&unpacked_rec_path)
        .map_err(|e| exit_with_message(EXIT_MISMATCH, format!("read instance.json in bundle: {e}")))
        .and_then(|s| {
            serde_json::from_str(&s).map_err(|e| {
                exit_with_message(EXIT_MISMATCH, format!("parse instance.json in bundle: {e}"))
            })
        })?;

    // Check target liveness and record prior state BEFORE mutating anything (`S-A5`, `S-05`, `S-07`).
    let was_alive = is_instance_alive(&target_dir);
    if was_alive && !args.force {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!(
                "instance '{}' is running; pass --force to stop and restore over it",
                args.name
            ),
        ));
    }

    let prev_rec = read_instance_record(&target_dir).ok().flatten();
    let prev_recipe = read_daemon_recipe(&target_dir).ok();

    let eff_offset = if let Some(off) = args.port_offset {
        off
    } else if let Some(rec) = &prev_rec {
        rec.port_offset
    } else if args.state_dir.is_none() {
        let root = instances_root().map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
        let (off, _) = resolve_up_port_offset(&root, &args.name, None)?;
        off
    } else {
        unpacked_recipe.port_offset
    };

    let is_pg = unpacked.manifest.storage_mode == "postgres";
    let eff_pg_url = if is_pg {
        Some(
            args.pg_url
                .clone()
                .or_else(|| prev_rec.as_ref().and_then(|r| r.pg_url.clone()))
                .or_else(|| unpacked_recipe.pg_url.clone())
                .ok_or_else(|| {
                    exit_with_message(
                        EXIT_PREFLIGHT,
                        "postgres snapshot restore requires --pg-url (not saved in recipe)",
                    )
                })?,
        )
    } else {
        None
    };
    let eff_pg_schema = is_pg.then(|| format!("{}-state", args.name));

    if was_alive {
        stop_instance_quietly(&target_dir, 10)?;
    }

    let stamp = now_unix_ms();
    let bak_dir = if target_dir.exists() {
        let parent = target_dir
            .parent()
            .ok_or_else(|| format!("missing parent for {}", target_dir.display()))?;
        let bak = parent.join(format!("{}.bak-{stamp}", args.name));
        fs::rename(&target_dir, &bak)
            .map_err(|e| format!("backup {} -> {}: {e}", target_dir.display(), bak.display()))?;
        Some(bak)
    } else {
        None
    };

    let mut bak_schema: Option<String> = None;
    if let (Some(url), Some(schema)) = (eff_pg_url.as_deref(), eff_pg_schema.as_deref()) {
        if bundle::pg_schema_exists(url, schema)? {
            let b_schema = format!("{schema}-bak-{stamp}");
            let sql = format!(
                "ALTER SCHEMA \"{}\" RENAME TO \"{}\"",
                schema.replace('"', "\"\""),
                b_schema.replace('"', "\"\"")
            );
            bundle::exec_pg_ddl(url, sql)?;
            bak_schema = Some(b_schema);
        }
    }

    let ctx = RestoreContext {
        target_dir: &target_dir,
        target_name: &args.name,
        eff_offset,
        eff_pg_url: eff_pg_url.as_deref(),
        eff_pg_schema: eff_pg_schema.as_deref(),
        unpacked: &unpacked,
        unpacked_recipe: &unpacked_recipe,
        unpacked_rec: &unpacked_rec,
    };

    if let Err(err) = perform_restore_attempt(&ctx) {
        rollback_restore(&RollbackSpec {
            target_dir: &target_dir,
            bak_dir: bak_dir.as_deref(),
            pg_url: eff_pg_url.as_deref(),
            target_schema: eff_pg_schema.as_deref(),
            bak_schema: bak_schema.as_deref(),
            was_alive,
            prev_recipe: prev_recipe.as_ref(),
            target_name: &args.name,
        });
        return Err(exit_with_message(EXIT_MISMATCH, err));
    }

    // Success: clean up backups only after post-start verification passed.
    if let Some(bak) = bak_dir {
        let _ = fs::remove_dir_all(bak);
    }
    if let (Some(url), Some(b_schema)) = (eff_pg_url.as_deref(), bak_schema.as_deref()) {
        let drop_sql = format!(
            "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
            b_schema.replace('"', "\"\"")
        );
        let _ = bundle::exec_pg_ddl(url, drop_sql);
    }

    let report = RestoreReport {
        schema: "canton-rs.restore/1".to_string(),
        name: args.name,
        source_name: unpacked.manifest.source_name,
        from: args.from.display().to_string(),
        port_offset: eff_offset,
        storage_mode: unpacked.manifest.storage_mode,
        ledger_ends: unpacked.manifest.ledger_ends,
    };
    match args.format {
        StatusFormatArg::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        }
        StatusFormatArg::Text => {
            println!(
                "Restored '{}' from {} (source='{}', port_offset={}, mode={}).",
                report.name,
                report.from,
                report.source_name,
                report.port_offset,
                report.storage_mode
            );
        }
    }
    Ok(())
}
