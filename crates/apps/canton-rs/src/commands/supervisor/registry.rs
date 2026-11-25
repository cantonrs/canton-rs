//! Named supervisor instance registry (`<root>/instances/<name>/instance.json`),
//! non-overlapping auto port-offset allocation (`off = k * W`), listing (`daemon list`),
//! and boundary-safe deletion (`daemon remove`) (`S-DX-003`).
//!
//! [CANTON-NOTE: INVARIANT] Deletion never follows symbolic links (`I-A4`, `I-06`), never touches
//! `canton-rs-state` (`I-07`), and guarantees dry-run parity (`list(dry-run) == deleted(remove)`).

use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use canton_participant::pgconn::{connect as pg_connect, PgTarget};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::exit_code::{exit_with_message, EXIT_PREFLIGHT};
use super::super::port_plan::port_window;
use super::cli::DEFAULT_STATE_DIR;
use super::ipc::{call_unary_with_timeout, socket_path, IpcRequest, IpcResponse};

/// Filename inside each named instance's directory holding its metadata (`0600`).
pub const INSTANCE_FILE: &str = "instance.json";
/// JSON schema identifier for `canton-rs daemon list --format json`.
pub const INSTANCES_JSON_SCHEMA: &str = "canton-rs.instances/1";
/// JSON schema identifier for `canton-rs daemon remove --format json`.
pub const REMOVE_JSON_SCHEMA: &str = "canton-rs.remove/1";

/// Persisted registry record stored at `<root>/instances/<name>/instance.json` (`0600`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceRecord {
    pub name: String,
    pub port_offset: u16,
    pub created_at_unix_secs: u64,
    pub version: String,
    pub manifest_hash: String,
    #[serde(default)]
    pub pg_url: Option<String>,
    #[serde(default)]
    pub pg_prefix: Option<String>,
}

/// Summary row emitted by `canton-rs daemon list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceListItem {
    pub name: String,
    pub state: String,
    pub port_offset: u16,
    pub state_dir: String,
    pub version: String,
    pub created_at_unix_secs: u64,
    pub manifest_hash: String,
}

/// Canonical machine-readable report emitted by `canton-rs daemon list --format json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceListReport {
    pub schema: String,
    pub root: String,
    pub instances: Vec<InstanceListItem>,
}

/// Filesystem node kind captured without traversing symlinks (`I-A4`, `I-A5`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoveEntryKind {
    File,
    Symlink,
    Dir,
}

/// One filesystem item queued for post-order removal inside `<root>/instances/<name>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveEntry {
    pub path: PathBuf,
    pub kind: RemoveEntryKind,
}

/// Complete dry-run/execution plan for `canton-rs daemon remove`.
#[derive(Clone, Debug)]
pub struct RemovePlan {
    pub name: String,
    pub target_dir: PathBuf,
    pub alive: bool,
    pub entries: Vec<RemoveEntry>,
    pub pg_url: Option<String>,
    pub pg_prefix: String,
    pub pg_schemas: Vec<String>,
    pub pg_state_names: Vec<String>,
}

/// Deterministic machine-readable report for `canton-rs daemon remove [--dry-run] --format json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveReport {
    pub schema: String,
    pub name: String,
    pub dry_run: bool,
    pub paths: Vec<String>,
    pub pg_schemas: Vec<String>,
    pub pg_state_names: Vec<String>,
}

/// Enforces `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` on named instance identifiers (`I-A6`).
pub fn validate_instance_name(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return Err(format!(
            "invalid instance name '{name}': must match ^[a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?$ (1..=63 chars)"
        ));
    }
    let is_lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_lower_alnum(bytes[0]) || !is_lower_alnum(bytes[bytes.len() - 1]) {
        return Err(format!(
            "invalid instance name '{name}': must start and end with [a-z0-9]"
        ));
    }
    if !bytes.iter().all(|&b| is_lower_alnum(b) || b == b'-') {
        return Err(format!(
            "invalid instance name '{name}': only [a-z0-9-] characters are permitted"
        ));
    }
    Ok(())
}

/// Resolves `<root>` (`$XDG_STATE_HOME/canton-rs`, fallback `~/.local/state/canton-rs`).
pub fn instances_root() -> Result<PathBuf, String> {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        let trimmed = xdg.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed).join("canton-rs"));
        }
    }
    let home = std::env::var("HOME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .ok_or_else(|| "neither XDG_STATE_HOME nor HOME is set".to_string())?;
    Ok(PathBuf::from(home).join(".local/state/canton-rs"))
}

/// Returns `<root>/instances`.
pub fn instances_dir(root: &Path) -> PathBuf {
    root.join("instances")
}

/// Returns `<root>/instances/<name>`.
pub fn instance_dir(root: &Path, name: &str) -> PathBuf {
    instances_dir(root).join(name)
}

/// Returns `true` if `path` names or traverses the protected default `canton-rs-state` directory.
pub fn is_protected_state_dir(path: &Path) -> bool {
    path == Path::new(DEFAULT_STATE_DIR)
        || path.file_name().and_then(|s| s.to_str()) == Some(DEFAULT_STATE_DIR)
        || path.components().any(|comp| {
            matches!(comp, Component::Normal(part) if part.to_str() == Some(DEFAULT_STATE_DIR))
        })
}

/// Resolves the target state directory from `--name` and/or `--state-dir` (`I-A3`, `I-07`).
pub fn resolve_target_state_dir(
    name: Option<&str>,
    explicit_state_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let Some(raw_name) = name else {
        return Ok(
            explicit_state_dir.map_or_else(|| PathBuf::from(DEFAULT_STATE_DIR), Path::to_path_buf)
        );
    };
    validate_instance_name(raw_name).map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    if let Some(explicit) = explicit_state_dir {
        if is_protected_state_dir(explicit) {
            return Err(exit_with_message(
                EXIT_PREFLIGHT,
                format!(
                    "refusing --state-dir {} with --name {raw_name}: '{DEFAULT_STATE_DIR}' is a protected path",
                    explicit.display()
                ),
            ));
        }
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!(
                "cannot combine --name {raw_name} with --state-dir {}",
                explicit.display()
            ),
        ));
    }
    let root = instances_root().map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    let dir = instance_dir(&root, raw_name);
    if is_protected_state_dir(&dir) {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!("refusing protected directory {}", dir.display()),
        ));
    }
    Ok(dir)
}

/// Reads `<dir>/instance.json` when present (returning `None` if not yet registered).
pub fn read_instance_record(dir: &Path) -> Result<Option<InstanceRecord>, String> {
    let path = dir.join(INSTANCE_FILE);
    match fs::symlink_metadata(&path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "refusing symlinked instance file {}",
                    path.display()
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot stat {}: {e}", path.display())),
    }
    let raw =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let rec: InstanceRecord =
        serde_json::from_str(&raw).map_err(|e| format!("invalid {}: {e}", path.display()))?;
    Ok(Some(rec))
}

/// Atomically writes `<dir>/instance.json` with mode `0o600` (creating `<dir>` as `0o700` if new).
pub fn write_instance_record(dir: &Path, rec: &InstanceRecord) -> Result<(), String> {
    if is_protected_state_dir(dir) {
        return Err(format!(
            "refusing to register protected dir {}",
            dir.display()
        ));
    }
    if !dir.exists() {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder
            .create(dir)
            .map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let payload = serde_json::to_vec_pretty(rec).map_err(|e| e.to_string())?;
    let target = dir.join(INSTANCE_FILE);
    let tmp = dir.join(format!(".{INSTANCE_FILE}.tmp.{}", std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts
        .open(&tmp)
        .map_err(|e| format!("open {}: {e}", tmp.display()))?;
    file.write_all(&payload)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &target).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename {} -> {}: {e}", tmp.display(), target.display())
    })
}

/// Computes `sha256:<hex>` of the manifest or HOCON config backing a named instance.
pub fn compute_manifest_hash(file: Option<&Path>, config: Option<&Path>) -> String {
    let target = file.or(config).map(Path::to_path_buf).or_else(|| {
        let default = PathBuf::from("canton-daemon.yaml");
        default.exists().then_some(default)
    });
    let Some(path) = target else {
        return "none".to_string();
    };
    let Ok(bytes) = fs::read(&path) else {
        return "unreadable".to_string();
    };
    let digest = Sha256::digest(&bytes);
    format!("sha256:{}", hex::encode(digest))
}

/// Checks live IPC reachability of a supervised instance (`alive(N)`).
pub fn is_instance_alive(dir: &Path) -> bool {
    let sock = socket_path(dir);
    if !sock.exists() && sock.symlink_metadata().is_err() {
        return false;
    }
    matches!(
        call_unary_with_timeout(dir, &IpcRequest::GetSnapshot, Some(Duration::from_secs(2))),
        Ok(IpcResponse::Snapshot { ok: true, .. })
    )
}

/// Selects the smallest non-overlapping multiple `off = k * window` (`I-A2`).
pub fn select_auto_port_offset(used_offsets: &[u16], window: u16) -> Result<u16, String> {
    if window == 0 {
        return Err("port window must be positive".to_string());
    }
    let mut k = 0u16;
    loop {
        let Some(cand_start) = k.checked_mul(window) else {
            return Err("exhausted u16 port-offset windows while allocating instance".to_string());
        };
        let cand_end = cand_start.saturating_add(window);
        let overlaps = used_offsets.iter().any(|&used_start| {
            let used_end = used_start.saturating_add(window);
            cand_start < used_end && used_start < cand_end
        });
        if !overlaps {
            return Ok(cand_start);
        }
        k = k.saturating_add(1);
    }
}

/// Resolves the port offset for `daemon up --name N` and returns any pre-existing record.
pub fn resolve_up_port_offset(
    root: &Path,
    name: &str,
    explicit_offset: Option<u16>,
) -> Result<(u16, Option<InstanceRecord>), String> {
    let target_dir = instance_dir(root, name);
    let existing = read_instance_record(&target_dir)?;
    if let Some(off) = explicit_offset {
        return Ok((off, existing));
    }
    if let Some(ref rec) = existing {
        return Ok((rec.port_offset, existing));
    }
    let mut used = Vec::new();
    let parent = instances_dir(root);
    if parent.is_dir() {
        let entries =
            fs::read_dir(&parent).map_err(|e| format!("cannot read {}: {e}", parent.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() || !meta.is_dir() {
                continue;
            }
            if entry.file_name().to_str() == Some(name) {
                continue;
            }
            if let Ok(Some(rec)) = read_instance_record(&path) {
                used.push(rec.port_offset);
            }
        }
    }
    let offset = select_auto_port_offset(&used, port_window())?;
    Ok((offset, existing))
}

/// Scans `<root>/instances/*` and returns sorted summary rows for `daemon list`.
pub fn collect_instance_list(root: &Path) -> Result<InstanceListReport, String> {
    let dir = instances_dir(root);
    let mut items = Vec::new();
    if dir.is_dir() {
        let read = fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in read.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() || !meta.is_dir() {
                continue;
            }
            let Ok(Some(rec)) = read_instance_record(&path) else {
                continue;
            };
            let state = if is_instance_alive(&path) {
                "running"
            } else {
                "stopped"
            };
            let abs = fs::canonicalize(&path).unwrap_or(path);
            items.push(InstanceListItem {
                name: rec.name,
                state: state.to_string(),
                port_offset: rec.port_offset,
                state_dir: abs.display().to_string(),
                version: rec.version,
                created_at_unix_secs: rec.created_at_unix_secs,
                manifest_hash: rec.manifest_hash,
            });
        }
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(InstanceListReport {
        schema: INSTANCES_JSON_SCHEMA.to_string(),
        root: root.display().to_string(),
        instances: items,
    })
}

/// Renders [`InstanceListReport`] as deterministic pretty JSON.
pub fn render_instance_list_json(report: &InstanceListReport) -> Result<String, String> {
    serde_json::to_string_pretty(report).map_err(|e| e.to_string())
}

/// Renders [`InstanceListReport`] as a human-readable table.
pub fn render_instance_list_text(report: &InstanceListReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("canton-rs instances (root={})\n", report.root));
    if report.instances.is_empty() {
        out.push_str("  (none)\n");
        return out;
    }
    out.push_str(&format!(
        "  {:<18} {:<10} {:>6}  {}\n",
        "NAME", "STATE", "OFFSET", "STATE DIR"
    ));
    for item in &report.instances {
        out.push_str(&format!(
            "  {:<18} {:<10} {:>6}  {}\n",
            item.name, item.state, item.port_offset, item.state_dir
        ));
    }
    out
}

/// Verifies `target_dir` is strictly a direct, non-symlink child of `<root>/instances/` and not `canton-rs-state`.
pub fn ensure_instance_delete_boundary(root: &Path, name: &str) -> Result<PathBuf, String> {
    validate_instance_name(name).map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    let parent = instances_dir(root);
    let target = parent.join(name);
    if is_protected_state_dir(&target) {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!(
                "refusing to remove protected directory {}",
                target.display()
            ),
        ));
    }
    if target.parent() != Some(parent.as_path())
        || target.file_name().and_then(|s| s.to_str()) != Some(name)
    {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!(
                "target {} escapes instances root {}",
                target.display(),
                parent.display()
            ),
        ));
    }
    let meta = fs::symlink_metadata(&target).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            exit_with_message(EXIT_PREFLIGHT, format!("unknown instance '{name}'"))
        } else {
            format!("cannot inspect {}: {e}", target.display())
        }
    })?;
    if meta.file_type().is_symlink() {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!(
                "refusing symlinked instance path {} outside boundary",
                target.display()
            ),
        ));
    }
    if !meta.is_dir() {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!("instance path {} is not a directory", target.display()),
        ));
    }
    Ok(target)
}

fn collect_tree_inner(dir: &Path, out: &mut Vec<RemoveEntry>) -> Result<(), String> {
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("cannot read directory {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|entry| entry.path()))
        .collect();
    children.sort();
    for child in children {
        let meta = fs::symlink_metadata(&child)
            .map_err(|e| format!("cannot stat {}: {e}", child.display()))?;
        if meta.file_type().is_symlink() {
            // [CANTON-NOTE: INVARIANT] Record the symlink itself and never traverse into its target.
            out.push(RemoveEntry {
                path: child,
                kind: RemoveEntryKind::Symlink,
            });
        } else if meta.is_dir() {
            collect_tree_inner(&child, out)?;
        } else {
            out.push(RemoveEntry {
                path: child,
                kind: RemoveEntryKind::File,
            });
        }
    }
    out.push(RemoveEntry {
        path: dir.to_path_buf(),
        kind: RemoveEntryKind::Dir,
    });
    Ok(())
}

/// Traverses `root_dir` in deterministic post-order without ever following symbolic links (`I-A4`, `I-A5`).
pub fn collect_tree_entries_no_follow(root_dir: &Path) -> Result<Vec<RemoveEntry>, String> {
    let meta = fs::symlink_metadata(root_dir)
        .map_err(|e| format!("cannot stat {}: {e}", root_dir.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "refusing to traverse symlink root {}",
            root_dir.display()
        ));
    }
    if !meta.is_dir() {
        return Err(format!("not a directory: {}", root_dir.display()));
    }
    let mut entries = Vec::new();
    collect_tree_inner(root_dir, &mut entries)?;
    Ok(entries)
}

/// Deletes post-order [`RemoveEntry`] items without following symlinks and returns deleted paths.
pub fn execute_remove_tree_no_follow(entries: &[RemoveEntry]) -> Result<Vec<PathBuf>, String> {
    let mut deleted = Vec::with_capacity(entries.len());
    for entry in entries {
        match entry.kind {
            RemoveEntryKind::File | RemoveEntryKind::Symlink => {
                fs::remove_file(&entry.path)
                    .map_err(|e| format!("remove file {}: {e}", entry.path.display()))?;
            }
            RemoveEntryKind::Dir => {
                fs::remove_dir(&entry.path)
                    .map_err(|e| format!("remove dir {}: {e}", entry.path.display()))?;
            }
        }
        deleted.push(entry.path.clone());
    }
    Ok(deleted)
}

fn escape_pg_like(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

fn quote_pg_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

fn query_or_drop_pg_targets(
    pg_url: &str,
    pg_prefix: &str,
    drop: bool,
) -> Result<(Vec<String>, Vec<String>), String> {
    let url = pg_url.to_string();
    let prefix_like = format!("{}-%", escape_pg_like(pg_prefix));
    let handle = std::thread::spawn(move || -> Result<(Vec<String>, Vec<String>), String> {
        let target = PgTarget::from_url_or_jdbc(&url, None, None, None)?;
        let mut client = pg_connect(&target)?;
        let schema_rows = client
            .query(
                "SELECT nspname FROM pg_namespace \
                 WHERE nspname LIKE $1 ESCAPE '\\' \
                   AND nspname NOT LIKE 'pg\\_%' ESCAPE '\\' \
                   AND nspname <> 'information_schema' \
                   AND nspname <> 'public' \
                 ORDER BY nspname",
                &[&prefix_like],
            )
            .map_err(|e| format!("query pg_namespace: {e}"))?;
        let schemas: Vec<String> = schema_rows.into_iter().map(|r| r.get(0)).collect();

        let state_table_exists: bool = client
            .query_one("SELECT to_regclass('canton_rs_state') IS NOT NULL", &[])
            .map(|r| r.get(0))
            .unwrap_or(false);
        let state_names: Vec<String> = if state_table_exists {
            let rows = client
                .query(
                    "SELECT DISTINCT name FROM canton_rs_state \
                     WHERE name LIKE $1 ESCAPE '\\' ORDER BY name",
                    &[&prefix_like],
                )
                .map_err(|e| format!("query canton_rs_state: {e}"))?;
            rows.into_iter().map(|r| r.get(0)).collect()
        } else {
            Vec::new()
        };

        if drop {
            for schema in &schemas {
                let stmt = format!("DROP SCHEMA IF EXISTS {} CASCADE", quote_pg_ident(schema));
                client
                    .batch_execute(&stmt)
                    .map_err(|e| format!("drop schema {schema}: {e}"))?;
            }
            if state_table_exists && !state_names.is_empty() {
                client
                    .execute(
                        "DELETE FROM canton_rs_state WHERE name LIKE $1 ESCAPE '\\'",
                        &[&prefix_like],
                    )
                    .map_err(|e| format!("delete canton_rs_state rows: {e}"))?;
            }
        }
        Ok((schemas, state_names))
    });
    handle
        .join()
        .map_err(|_| "PostgreSQL cleanup worker thread panicked".to_string())?
}

/// Computes what `daemon remove --name N` would delete without mutating filesystem or PG (`I-A5`).
pub fn plan_instance_remove(
    root: &Path,
    name: &str,
    pg_url_override: Option<&str>,
) -> Result<RemovePlan, String> {
    let target_dir = ensure_instance_delete_boundary(root, name)?;
    let record = read_instance_record(&target_dir)?;
    let alive = is_instance_alive(&target_dir);
    let entries = collect_tree_entries_no_follow(&target_dir)?;
    let pg_prefix = record
        .as_ref()
        .and_then(|r| r.pg_prefix.clone())
        .unwrap_or_else(|| name.to_string());
    let pg_url = pg_url_override
        .map(str::to_string)
        .or_else(|| record.as_ref().and_then(|r| r.pg_url.clone()));
    let (pg_schemas, pg_state_names) = match &pg_url {
        Some(url) => query_or_drop_pg_targets(url, &pg_prefix, false)?,
        None => (Vec::new(), Vec::new()),
    };
    Ok(RemovePlan {
        name: name.to_string(),
        target_dir,
        alive,
        entries,
        pg_url,
        pg_prefix,
        pg_schemas,
        pg_state_names,
    })
}

/// Executes filesystem (no symlink following) and PG cleanup for `plan`.
pub fn execute_instance_remove(root: &Path, plan: &RemovePlan) -> Result<RemoveReport, String> {
    let verified = ensure_instance_delete_boundary(root, &plan.name)?;
    if verified != plan.target_dir {
        return Err(format!(
            "instance directory boundary changed during removal: {}",
            verified.display()
        ));
    }
    let fresh_entries = collect_tree_entries_no_follow(&verified)?;
    let deleted = execute_remove_tree_no_follow(&fresh_entries)?;
    let mut dropped_schemas = Vec::new();
    let mut dropped_states = Vec::new();
    if let Some(ref url) = plan.pg_url {
        let (schemas, states) = query_or_drop_pg_targets(url, &plan.pg_prefix, true)?;
        dropped_schemas = schemas;
        dropped_states = states;
    }
    let mut all_paths: BTreeSet<String> = deleted
        .into_iter()
        .map(|p| p.display().to_string())
        .collect();
    if let Some(shared_target) = super::observability::remove_shared_target(root, &plan.name)? {
        all_paths.insert(shared_target.display().to_string());
    }
    for e in &plan.entries {
        if !e.path.exists() && fs::symlink_metadata(&e.path).is_err() {
            all_paths.insert(e.path.display().to_string());
        }
    }
    Ok(RemoveReport {
        schema: REMOVE_JSON_SCHEMA.to_string(),
        name: plan.name.clone(),
        dry_run: false,
        paths: all_paths.into_iter().collect(),
        pg_schemas: dropped_schemas,
        pg_state_names: dropped_states,
    })
}

/// Builds a pure dry-run [`RemoveReport`] matching what [`execute_instance_remove`] deletes.
pub fn build_dry_run_report(plan: &RemovePlan) -> RemoveReport {
    let paths: BTreeSet<String> = plan
        .entries
        .iter()
        .map(|e| e.path.display().to_string())
        .collect();
    RemoveReport {
        schema: REMOVE_JSON_SCHEMA.to_string(),
        name: plan.name.clone(),
        dry_run: true,
        paths: paths.into_iter().collect(),
        pg_schemas: plan.pg_schemas.clone(),
        pg_state_names: plan.pg_state_names.clone(),
    }
}

/// Renders [`RemoveReport`] as pretty JSON.
pub fn render_remove_json(report: &RemoveReport) -> Result<String, String> {
    serde_json::to_string_pretty(report).map_err(|e| e.to_string())
}

/// Renders [`RemoveReport`] as human-readable lines.
pub fn render_remove_text(report: &RemoveReport) -> String {
    let mut out = String::new();
    let verb = if report.dry_run {
        "Would remove"
    } else {
        "Removed"
    };
    out.push_str(&format!(
        "{verb} instance '{}' ({} filesystem path(s), {} PG schema(s), {} PG state row group(s)):\n",
        report.name,
        report.paths.len(),
        report.pg_schemas.len(),
        report.pg_state_names.len()
    ));
    for p in &report.paths {
        out.push_str(&format!("  path: {p}\n"));
    }
    for s in &report.pg_schemas {
        out.push_str(&format!("  pg_schema: {s}\n"));
    }
    for s in &report.pg_state_names {
        out.push_str(&format!("  pg_state: {s}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        build_dry_run_report, collect_instance_list, execute_instance_remove,
        is_protected_state_dir, plan_instance_remove, read_instance_record, resolve_up_port_offset,
        select_auto_port_offset, validate_instance_name, write_instance_record, InstanceRecord,
    };

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_root(tag: &str) -> PathBuf {
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("crs-reg-{tag}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp root");
        dir
    }

    #[test]
    fn validate_name_enforces_exact_regex() {
        for valid in ["a", "0", "dev-1", "a-b-c", &"a".repeat(63)] {
            assert!(
                validate_instance_name(valid).is_ok(),
                "should accept {valid}"
            );
        }
        for invalid in [
            "",
            "A",
            "a_b",
            "-a",
            "a-",
            "foo/bar",
            "a.b",
            &"a".repeat(64),
        ] {
            assert!(
                validate_instance_name(invalid).is_err(),
                "should reject {invalid:?}"
            );
        }
    }

    #[test]
    fn registry_0600_auto_offset_and_reuse() {
        let root = temp_root("auto-off");
        assert_eq!(select_auto_port_offset(&[], 1000).expect("first"), 0);
        assert_eq!(select_auto_port_offset(&[0], 1000).expect("second"), 1000);
        assert_eq!(
            select_auto_port_offset(&[0, 1000], 1000).expect("third"),
            2000
        );
        assert_eq!(
            select_auto_port_offset(&[1000], 1000).expect("gap reuse"),
            0
        );
        assert_eq!(
            select_auto_port_offset(&[500], 1000).expect("manual overlap"),
            2000
        );

        let (off_a, prev_a) = resolve_up_port_offset(&root, "alpha", None).expect("alpha offset");
        assert_eq!(off_a, 0);
        assert!(prev_a.is_none());
        let dir_a = root.join("instances/alpha");
        write_instance_record(
            &dir_a,
            &InstanceRecord {
                name: "alpha".into(),
                port_offset: off_a,
                created_at_unix_secs: 100,
                version: "1.0.0".into(),
                manifest_hash: "sha256:aaa".into(),
                pg_url: None,
                pg_prefix: None,
            },
        )
        .expect("write alpha");

        #[cfg(unix)]
        {
            let mode = fs::metadata(dir_a.join("instance.json"))
                .expect("stat instance.json")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let (off_b, _) = resolve_up_port_offset(&root, "beta", None).expect("beta offset");
        assert_eq!(off_b, 1000);
        assert_eq!(
            resolve_up_port_offset(&root, "alpha", None)
                .expect("preserve")
                .0,
            0
        );
        let parsed = read_instance_record(&dir_a).expect("read").expect("some");
        assert_eq!(parsed.name, "alpha");

        let list = collect_instance_list(&root).expect("list");
        assert_eq!(list.instances.len(), 1);
        assert_eq!(list.instances[0].state, "stopped");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn remove_dry_run_and_symlink_boundary() {
        let root = temp_root("remove-boundary");
        let outside = temp_root("outside-target");
        fs::write(outside.join("keep.txt"), "safe").expect("write canary");

        let dir_a = root.join("instances/alpha");
        write_instance_record(
            &dir_a,
            &InstanceRecord {
                name: "alpha".into(),
                port_offset: 0,
                created_at_unix_secs: 100,
                version: "1.0.0".into(),
                manifest_hash: "none".into(),
                pg_url: None,
                pg_prefix: None,
            },
        )
        .expect("write alpha");
        fs::create_dir_all(dir_a.join("logs")).expect("mkdir logs");
        fs::write(dir_a.join("logs/s1.log"), "hello").expect("write log");
        #[cfg(unix)]
        {
            symlink(&outside, dir_a.join("escape-dir")).expect("symlink dir");
            symlink(outside.join("keep.txt"), dir_a.join("escape-file")).expect("symlink file");
        }

        let plan = plan_instance_remove(&root, "alpha", None).expect("plan remove");
        let dry = build_dry_run_report(&plan);
        assert!(dir_a.exists());

        let actual = execute_instance_remove(&root, &plan).expect("execute remove");
        assert_eq!(dry.paths, actual.paths, "dry-run must equal deleted paths");
        assert!(!dir_a.exists());
        assert!(outside.join("keep.txt").is_file());
        assert_eq!(
            fs::read_to_string(outside.join("keep.txt")).expect("read canary"),
            "safe"
        );

        assert!(is_protected_state_dir(Path::new("canton-rs-state")));
        assert!(is_protected_state_dir(Path::new("/tmp/canton-rs-state")));
        assert!(!is_protected_state_dir(&dir_a));

        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }
}
