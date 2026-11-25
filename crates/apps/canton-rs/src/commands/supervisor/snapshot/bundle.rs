//! Snapshot bundle creation, tarball packing/unpacking, SHA-256 verification,
//! and Files / PostgreSQL store collection and rollback (`S-DX-004`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use canton_participant::pgconn::{connect as pg_connect, PgTarget};
use sha2::{Digest, Sha256};

use super::{
    atomic_write_0600, strip_pg_schema_param, DaemonRecipe, SnapshotComponent, SnapshotFileEntry,
    SnapshotManifest, SNAPSHOT_FORMAT_VERSION, SNAPSHOT_MANIFEST_FILE,
};
use crate::commands::exit_code::{exit_with_message, EXIT_MISMATCH, EXIT_PREFLIGHT};

const SEQUENCER_STORE_FILES: &[&str] = &["keys", "journal", "sequencer.identity"];
const MEDIATOR_IDENTITY_FILE: &str = "mediator.identity";
const PARTICIPANT_IDENTITY_FILE: &str = "identity";
const PARTICIPANT_SYNCHRONIZER_FILE: &str = "synchronizer";
const PARTICIPANT_JOURNAL_FILES: &[&str] = &[
    "cursor",
    "ledger.journal",
    "topology.journal",
    "requests.journal",
    "in-flight.journal",
    "commitments.journal",
    "submissions.journal",
    "applied.journal",
    "contracts.journal",
    "unassigned.journal",
    "stored-unassignments.journal",
    "updates.journal",
    "completions.journal",
    "dedup.journal",
    "pruned.journal",
    "dars.journal",
    "admin.journal",
];

/// Parameters captured while building a snapshot bundle.
pub struct BuildBundleSpec<'a> {
    pub state_dir: &'a Path,
    pub recipe: &'a DaemonRecipe,
    pub source_name: &'a str,
    pub manifest_hash: &'a str,
    pub created_at_unix_secs: u64,
    pub ledger_ends: &'a BTreeMap<String, u64>,
    pub node_identities: &'a BTreeMap<String, String>,
    pub scan_history_lines: Option<usize>,
    pub out_tar: &'a Path,
}

/// Validates that a relative path inside a bundle has only normal components (`..` and root forbidden).
pub fn validate_safe_rel_path(rel: &str) -> Result<PathBuf, String> {
    let p = Path::new(rel);
    if rel.is_empty() || p.is_absolute() {
        return Err(format!("unsafe bundle path '{rel}'"));
    }
    for comp in p.components() {
        match comp {
            Component::Normal(_) => {}
            _ => return Err(format!("unsafe bundle path component in '{rel}'")),
        }
    }
    Ok(p.to_path_buf())
}

/// Computes lowercase hex SHA-256 over `bytes`.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Computes lowercase hex SHA-256 of a regular file without following symlinks.
pub fn sha256_file_no_follow(path: &Path) -> Result<(String, u64), String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(format!(
            "refusing non-regular or symlinked store file {}",
            path.display()
        ));
    }
    let mut f = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Computes canonical SHA-256 digest over a slice of sorted snapshot components.
pub fn compute_components_digest(components: &[SnapshotComponent]) -> Result<String, String> {
    let json = serde_json::to_vec(components).map_err(|e| e.to_string())?;
    Ok(sha256_bytes(&json))
}

/// Computes aggregate SHA-256 over a component's sorted file entries `(store_rel_path, sha256, size)`.
pub fn compute_component_digest(files: &[SnapshotFileEntry]) -> String {
    let mut hasher = Sha256::new();
    for entry in files {
        hasher.update(entry.store_rel_path.as_bytes());
        hasher.update(b":");
        hasher.update(entry.sha256.as_bytes());
        hasher.update(b":");
        hasher.update(entry.size.to_string().as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

fn ensure_dir_0700(dir: &Path) -> Result<(), String> {
    if dir.exists() {
        return Ok(());
    }
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(dir)
        .map_err(|e| format!("create {}: {e}", dir.display()))
}

fn copy_store_file(
    src_path: &Path,
    store_rel_path: String,
    component_id: &str,
    staging_root: &Path,
) -> Result<SnapshotFileEntry, String> {
    let safe_store = validate_safe_rel_path(&store_rel_path)?;
    let bundle_rel = format!("stores/{component_id}/{}", safe_store.display());
    let dest = staging_root.join(&bundle_rel);
    if let Some(parent) = dest.parent() {
        ensure_dir_0700(parent)?;
    }
    let bytes = fs::read(src_path).map_err(|e| format!("read {}: {e}", src_path.display()))?;
    let sha = sha256_bytes(&bytes);
    let size = bytes.len() as u64;
    atomic_write_0600(&dest, &bytes)?;
    Ok(SnapshotFileEntry {
        bundle_rel_path: bundle_rel,
        store_rel_path,
        sha256: sha,
        size,
    })
}

fn push_if_file(
    state_dir: &Path,
    rel: &str,
    component_id: &str,
    staging_root: &Path,
    entries: &mut Vec<SnapshotFileEntry>,
) -> Result<bool, String> {
    let full = state_dir.join(rel);
    match fs::symlink_metadata(&full) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(format!("refusing symlink/non-file {}", full.display()));
            }
            entries.push(copy_store_file(
                &full,
                rel.to_string(),
                component_id,
                staging_root,
            )?);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("stat {}: {e}", full.display())),
    }
}

fn sorted_matching_files(
    dir: &Path,
    predicate: impl Fn(&str) -> bool,
) -> Result<Vec<String>, String> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    let rd = fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for item in rd {
        let entry = item.map_err(|e| e.to_string())?;
        let fname = entry.file_name();
        let Some(name_str) = fname.to_str() else {
            continue;
        };
        if !predicate(name_str) {
            continue;
        }
        let meta = fs::symlink_metadata(entry.path())
            .map_err(|e| format!("stat {}: {e}", entry.path().display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("refusing symlink {}", entry.path().display()));
        }
        if meta.is_file() {
            names.push(name_str.to_string());
        }
    }
    names.sort();
    Ok(names)
}

fn push_component(
    id: String,
    kind: &str,
    service: Option<String>,
    mut entries: Vec<SnapshotFileEntry>,
    out: &mut Vec<SnapshotComponent>,
) {
    entries.sort_by(|a, b| a.store_rel_path.cmp(&b.store_rel_path));
    let digest = compute_component_digest(&entries);
    out.push(SnapshotComponent {
        id,
        kind: kind.to_string(),
        service,
        files: entries,
        sha256: digest,
    });
}

fn collect_sequencer_store(
    state_dir: &Path,
    svc: &super::SnapshotServiceInfo,
    staging: &Path,
    components: &mut Vec<SnapshotComponent>,
) -> Result<(), String> {
    let cid = format!("sequencer-{}", svc.name);
    let mut entries = Vec::new();
    for f in SEQUENCER_STORE_FILES {
        let rel = format!("{}/{f}", svc.state_dir_rel);
        push_if_file(state_dir, &rel, &cid, staging, &mut entries)?;
    }
    let svc_dir = state_dir.join(&svc.state_dir_rel);
    for bft in sorted_matching_files(&svc_dir, |n| n.starts_with("bft.") && !n.ends_with(".tmp"))? {
        let rel = format!("{}/{bft}", svc.state_dir_rel);
        push_if_file(state_dir, &rel, &cid, staging, &mut entries)?;
    }
    for root_bft in
        sorted_matching_files(state_dir, |n| n.starts_with("bft-") && n.ends_with(".tx"))?
    {
        push_if_file(state_dir, &root_bft, &cid, staging, &mut entries)?;
    }
    if svc.storage_kind == "files" && entries.is_empty() {
        return Err(format!(
            "sequencer '{}' has no persisted files under {}",
            svc.name,
            svc_dir.display()
        ));
    }
    if !entries.is_empty() {
        push_component(
            cid,
            "sequencer",
            Some(svc.name.clone()),
            entries,
            components,
        );
    }
    Ok(())
}

fn collect_mediator_store(
    state_dir: &Path,
    svc: &super::SnapshotServiceInfo,
    staging: &Path,
    components: &mut Vec<SnapshotComponent>,
) -> Result<(), String> {
    let cid = format!("mediator-{}", svc.name);
    let mut entries = Vec::new();
    let svc_dir = state_dir.join(&svc.state_dir_rel);
    if svc.storage_kind == "files" || svc_dir.is_dir() {
        push_if_file(
            state_dir,
            &format!("{}/{MEDIATOR_IDENTITY_FILE}", svc.state_dir_rel),
            &cid,
            staging,
            &mut entries,
        )?;
        for extra in sorted_matching_files(&svc_dir, |n| {
            n.starts_with("mediator-")
                && (n.ends_with(".state") || n.ends_with(".topology.journal"))
        })? {
            let rel = format!("{}/{extra}", svc.state_dir_rel);
            push_if_file(state_dir, &rel, &cid, staging, &mut entries)?;
        }
    }
    let onboarding_rel = format!("{}-onboarding.txt", svc.name);
    push_if_file(state_dir, &onboarding_rel, &cid, staging, &mut entries)?;
    if entries.is_empty() {
        return Err(format!(
            "mediator '{}' has no persisted state under {}",
            svc.name,
            state_dir.display()
        ));
    }
    push_component(cid, "mediator", Some(svc.name.clone()), entries, components);
    Ok(())
}

fn collect_participant_stores(
    state_dir: &Path,
    svc: &super::SnapshotServiceInfo,
    staging: &Path,
    components: &mut Vec<SnapshotComponent>,
) -> Result<(), String> {
    if svc.storage_kind != "files" {
        return Ok(());
    }
    let id_cid = format!("participant-{}-identity", svc.name);
    let mut id_entries = Vec::new();
    for fixed in [PARTICIPANT_IDENTITY_FILE, PARTICIPANT_SYNCHRONIZER_FILE] {
        let rel = format!("{}/{fixed}", svc.state_dir_rel);
        push_if_file(state_dir, &rel, &id_cid, staging, &mut id_entries)?;
    }

    let j_cid = format!("participant-{}-journals", svc.name);
    let mut j_entries = Vec::new();
    let known_journals: BTreeSet<&str> = PARTICIPANT_JOURNAL_FILES.iter().copied().collect();
    let svc_dir = state_dir.join(&svc.state_dir_rel);
    for fname in sorted_matching_files(&svc_dir, |n| known_journals.contains(n))? {
        let rel = format!("{}/{fname}", svc.state_dir_rel);
        push_if_file(state_dir, &rel, &j_cid, staging, &mut j_entries)?;
    }

    if svc_dir.is_dir() {
        let sub_rd =
            fs::read_dir(&svc_dir).map_err(|e| format!("read_dir {}: {e}", svc_dir.display()))?;
        let mut sync_dirs = Vec::new();
        for item in sub_rd {
            let entry = item.map_err(|e| e.to_string())?;
            if let Some(s) = entry.file_name().to_str() {
                if s.starts_with("sync-") && entry.path().is_dir() {
                    sync_dirs.push(s.to_string());
                }
            }
        }
        sync_dirs.sort();
        for sync_sub in sync_dirs {
            let sync_rel = format!(
                "{}/{sync_sub}/{PARTICIPANT_SYNCHRONIZER_FILE}",
                svc.state_dir_rel
            );
            push_if_file(state_dir, &sync_rel, &id_cid, staging, &mut id_entries)?;
            for fname in
                sorted_matching_files(&svc_dir.join(&sync_sub), |n| known_journals.contains(n))?
            {
                let rel = format!("{}/{sync_sub}/{fname}", svc.state_dir_rel);
                push_if_file(state_dir, &rel, &j_cid, staging, &mut j_entries)?;
            }
        }
    }

    if id_entries.is_empty() {
        return Err(format!(
            "participant '{}' missing identity store under {}",
            svc.name,
            svc_dir.display()
        ));
    }
    push_component(
        id_cid,
        "participant-identity",
        Some(svc.name.clone()),
        id_entries,
        components,
    );
    if j_entries.is_empty() {
        return Err(format!(
            "participant '{}' missing journal stores under {}",
            svc.name,
            svc_dir.display()
        ));
    }
    push_component(
        j_cid,
        "participant-journals",
        Some(svc.name.clone()),
        j_entries,
        components,
    );
    Ok(())
}

/// Resolves PostgreSQL CLI binaries (`pg_dump` or `psql`), checking PATH then Homebrew paths.
pub fn find_pg_tool(name: &str) -> Result<PathBuf, String> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let cand = dir.join(name);
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    for fallback_dir in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        let cand = Path::new(fallback_dir).join(name);
        if cand.is_file() {
            return Ok(cand);
        }
    }
    Err(format!(
        "required PostgreSQL CLI tool '{name}' not found on PATH"
    ))
}

/// Filters `SET transaction_timeout ...;` emitted by `pg_dump 17+` so PG <= 16 restores succeed.
pub fn normalize_pg_dump_sql(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for line in raw.lines() {
        if line.trim_start().starts_with("SET transaction_timeout") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Rewrites schema identifiers in a normalized `pg_dump` SQL script when `src_schema != dst_schema`.
pub fn rewrite_dump_schema(sql: &str, src_schema: &str, dst_schema: &str) -> String {
    if src_schema == dst_schema {
        return sql.to_string();
    }
    let from = format!("\"{src_schema}\"");
    let to = format!("\"{dst_schema}\"");
    sql.replace(&from, &to)
}

fn collect_pg_schema_component(
    pg_url: &str,
    schema: &str,
    staging: &Path,
    components: &mut Vec<SnapshotComponent>,
) -> Result<(), String> {
    let pg_dump = find_pg_tool("pg_dump")?;
    let clean_url = strip_pg_schema_param(pg_url);
    let schema_arg = format!("--schema=\"{}\"", schema.replace('"', "\"\""));
    let output = Command::new(&pg_dump)
        .args([
            &schema_arg,
            "--no-owner",
            "--no-privileges",
            "--inserts",
            "--dbname",
            &clean_url,
        ])
        .output()
        .map_err(|e| format!("invoke {}: {e}", pg_dump.display()))?;
    if !output.status.success() {
        return Err(format!(
            "pg_dump failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let raw_sql = String::from_utf8(output.stdout)
        .map_err(|e| format!("pg_dump output was not valid UTF-8: {e}"))?;
    let normalized = normalize_pg_dump_sql(&raw_sql);
    let cid = "pg-schema".to_string();
    let bundle_rel = format!("stores/{cid}/schema.sql");
    let dest = staging.join(&bundle_rel);
    if let Some(parent) = dest.parent() {
        ensure_dir_0700(parent)?;
    }
    let bytes = normalized.into_bytes();
    let sha = sha256_bytes(&bytes);
    let size = bytes.len() as u64;
    atomic_write_0600(&dest, &bytes)?;
    let entry = SnapshotFileEntry {
        bundle_rel_path: bundle_rel,
        store_rel_path: "schema.sql".to_string(),
        sha256: sha,
        size,
    };
    push_component(cid, "pg-schema", None, vec![entry], components);
    Ok(())
}

/// Collects every component of `Stores(I)` into `staging` and writes the `0600` snapshot `.tar`.
pub fn create_snapshot_bundle(spec: &BuildBundleSpec<'_>) -> Result<SnapshotManifest, String> {
    let stage = TempDirGuard::new("sdx004-snap-stage")?;
    let mut components = Vec::new();

    // 1. Registry metadata
    let mut reg_entries = Vec::new();
    if !push_if_file(
        spec.state_dir,
        "instance.json",
        "registry",
        stage.path(),
        &mut reg_entries,
    )? {
        return Err("missing instance.json in target state directory".to_string());
    }
    push_component(
        "registry".into(),
        "registry",
        None,
        reg_entries,
        &mut components,
    );

    // 2. Startup recipe & manifest files
    let mut recipe_entries = Vec::new();
    for rel in [super::RECIPE_FILE, &spec.recipe.manifest_file, ".env"] {
        push_if_file(
            spec.state_dir,
            rel,
            "recipe",
            stage.path(),
            &mut recipe_entries,
        )?;
    }
    if let Some(conf) = &spec.recipe.canton_conf_file {
        if conf != &spec.recipe.manifest_file {
            push_if_file(
                spec.state_dir,
                conf,
                "recipe",
                stage.path(),
                &mut recipe_entries,
            )?;
        }
    }
    if let Some(boot) = &spec.recipe.bootstrap_file {
        push_if_file(
            spec.state_dir,
            boot,
            "recipe",
            stage.path(),
            &mut recipe_entries,
        )?;
    }
    push_component(
        "recipe".into(),
        "recipe",
        None,
        recipe_entries,
        &mut components,
    );

    // 3. Per-node persistent stores (`sequencer`, `mediator`, `participant`)
    let mut sorted_services = spec.recipe.services.clone();
    sorted_services.sort_by(|a, b| a.name.cmp(&b.name));
    let is_pg_mode = spec.recipe.pg_url.is_some() && !spec.recipe.state_in_files;

    if is_pg_mode {
        let pg_url = spec
            .recipe
            .pg_url
            .as_deref()
            .ok_or_else(|| "missing pg_url in postgres recipe".to_string())?;
        let pg_schema = spec
            .recipe
            .pg_schema
            .as_deref()
            .ok_or_else(|| "missing pg_schema in postgres recipe".to_string())?;
        collect_pg_schema_component(pg_url, pg_schema, stage.path(), &mut components)?;
    }

    for svc in &sorted_services {
        match svc.role.as_str() {
            "sequencer" => {
                collect_sequencer_store(spec.state_dir, svc, stage.path(), &mut components)?
            }
            "mediator" => {
                collect_mediator_store(spec.state_dir, svc, stage.path(), &mut components)?
            }
            "participant" => {
                collect_participant_stores(spec.state_dir, svc, stage.path(), &mut components)?
            }
            _ => {}
        }
    }

    // 4. Optional `scan-history.jsonl` and `.auth`
    let mut scan_entries = Vec::new();
    push_if_file(
        spec.state_dir,
        "scan-history.jsonl",
        "scan-history",
        stage.path(),
        &mut scan_entries,
    )?;
    push_if_file(
        spec.state_dir,
        "scan-history.jsonl.auth",
        "scan-history",
        stage.path(),
        &mut scan_entries,
    )?;
    if !scan_entries.is_empty() {
        push_component(
            "scan-history".into(),
            "scan-history",
            None,
            scan_entries,
            &mut components,
        );
    }

    components.sort_by(|a, b| a.id.cmp(&b.id));
    let components_digest = compute_components_digest(&components)?;

    let manifest = SnapshotManifest {
        format_version: SNAPSHOT_FORMAT_VERSION,
        canton_rs_version: env!("CARGO_PKG_VERSION").to_string(),
        created_at_unix_secs: spec.created_at_unix_secs,
        source_name: spec.source_name.to_string(),
        storage_mode: if is_pg_mode { "postgres" } else { "files" }.to_string(),
        pg_schema: spec.recipe.pg_schema.clone(),
        source_manifest_hash: spec.manifest_hash.to_string(),
        manifest_hash: components_digest,
        components,
        ledger_ends: spec.ledger_ends.clone(),
        node_identities: spec.node_identities.clone(),
        scan_history_lines: spec.scan_history_lines,
    };

    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    atomic_write_0600(&stage.path().join(SNAPSHOT_MANIFEST_FILE), &manifest_bytes)?;

    if let Some(parent) = spec.out_tar.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let tmp_tar = spec
        .out_tar
        .with_extension(format!("tmp.{}", std::process::id()));
    let tar_out = Command::new("tar")
        .arg("-cf")
        .arg(&tmp_tar)
        .arg("-C")
        .arg(stage.path())
        .arg(".")
        .output()
        .map_err(|e| format!("run tar -cf: {e}"))?;
    if !tar_out.status.success() {
        let _ = fs::remove_file(&tmp_tar);
        return Err(format!(
            "tar -cf failed ({}): {}",
            tar_out.status,
            String::from_utf8_lossy(&tar_out.stderr)
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(&tmp_tar, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 0600 {}: {e}", tmp_tar.display()))?;
    fs::rename(&tmp_tar, spec.out_tar).map_err(|e| {
        let _ = fs::remove_file(&tmp_tar);
        format!(
            "rename {} -> {}: {e}",
            tmp_tar.display(),
            spec.out_tar.display()
        )
    })?;
    #[cfg(unix)]
    fs::set_permissions(spec.out_tar, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 0600 {}: {e}", spec.out_tar.display()))?;
    Ok(manifest)
}

/// Result of extracting and verifying a snapshot `.tar` archive into a temporary workspace.
pub struct UnpackedBundle {
    _temp: TempDirGuard,
    pub dir: PathBuf,
    pub manifest: SnapshotManifest,
}

/// Unpacks a `.tar` snapshot, enforces version (`exit=2`), and verifies every SHA-256 hash (`exit=3`).
pub fn unpack_and_verify_bundle(tar_path: &Path) -> Result<UnpackedBundle, String> {
    if !tar_path.is_file() {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!("snapshot bundle does not exist: {}", tar_path.display()),
        ));
    }
    let temp = TempDirGuard::new("sdx004-restore-unpack")?;
    let out = Command::new("tar")
        .arg("-xf")
        .arg(tar_path)
        .arg("-C")
        .arg(temp.path())
        .output()
        .map_err(|e| exit_with_message(EXIT_MISMATCH, format!("run tar -xf: {e}")))?;
    if !out.status.success() {
        return Err(exit_with_message(
            EXIT_MISMATCH,
            format!(
                "corrupt snapshot archive ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ),
        ));
    }
    let manifest_path = temp.path().join(SNAPSHOT_MANIFEST_FILE);
    let raw_manifest = fs::read_to_string(&manifest_path).map_err(|e| {
        exit_with_message(
            EXIT_MISMATCH,
            format!("missing or unreadable {SNAPSHOT_MANIFEST_FILE}: {e}"),
        )
    })?;
    let manifest: SnapshotManifest = serde_json::from_str(&raw_manifest).map_err(|e| {
        exit_with_message(
            EXIT_MISMATCH,
            format!("invalid {SNAPSHOT_MANIFEST_FILE}: {e}"),
        )
    })?;

    if manifest.format_version != SNAPSHOT_FORMAT_VERSION {
        return Err(exit_with_message(
            EXIT_MISMATCH,
            format!(
                "unsupported snapshot format_version {} (expected {SNAPSHOT_FORMAT_VERSION})",
                manifest.format_version
            ),
        ));
    }

    let current_ver = env!("CARGO_PKG_VERSION");
    if manifest.canton_rs_version != current_ver {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!(
                "snapshot canton-rs version '{}' does not match binary version '{current_ver}'",
                manifest.canton_rs_version
            ),
        ));
    }

    verify_bundle_hashes(&manifest, temp.path())?;

    let dir = temp.path().to_path_buf();
    Ok(UnpackedBundle {
        _temp: temp,
        dir,
        manifest,
    })
}

/// Verifies `manifest_hash` and every component + file SHA-256 hash in the unpacked snapshot (`exit=3`).
pub fn verify_bundle_hashes(manifest: &SnapshotManifest, unpack_dir: &Path) -> Result<(), String> {
    let expected_comp_digest = compute_components_digest(&manifest.components)
        .map_err(|e| exit_with_message(EXIT_MISMATCH, e))?;
    if expected_comp_digest != manifest.manifest_hash {
        return Err(exit_with_message(
            EXIT_MISMATCH,
            format!(
                "snapshot manifest hash mismatch: expected {}, computed {expected_comp_digest}",
                manifest.manifest_hash
            ),
        ));
    }
    for comp in &manifest.components {
        let comp_digest = compute_component_digest(&comp.files);
        if comp_digest != comp.sha256 {
            return Err(exit_with_message(
                EXIT_MISMATCH,
                format!("component '{}' hash mismatch", comp.id),
            ));
        }
        for file in &comp.files {
            let safe_rel = validate_safe_rel_path(&file.bundle_rel_path)
                .map_err(|e| exit_with_message(EXIT_MISMATCH, e))?;
            let path = unpack_dir.join(safe_rel);
            let (actual_hash, actual_size) =
                sha256_file_no_follow(&path).map_err(|e| exit_with_message(EXIT_MISMATCH, e))?;
            if actual_hash != file.sha256 || actual_size != file.size {
                return Err(exit_with_message(
                    EXIT_MISMATCH,
                    format!(
                        "integrity failure for {} ({}): expected hash {} ({}B), got {} ({}B)",
                        file.bundle_rel_path,
                        comp.id,
                        file.sha256,
                        file.size,
                        actual_hash,
                        actual_size
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Copies all non-SQL store files from unpacked components into `target_dir`.
pub fn apply_unpacked_files(
    manifest: &SnapshotManifest,
    unpack_dir: &Path,
    target_dir: &Path,
) -> Result<(), String> {
    ensure_dir_0700(target_dir)?;
    for comp in &manifest.components {
        if comp.kind == "pg-schema" {
            continue;
        }
        for file in &comp.files {
            let safe_bundle = validate_safe_rel_path(&file.bundle_rel_path)?;
            let safe_store = validate_safe_rel_path(&file.store_rel_path)?;
            let src = unpack_dir.join(safe_bundle);
            let dst = target_dir.join(safe_store);
            if let Some(parent) = dst.parent() {
                ensure_dir_0700(parent)?;
            }
            let bytes = fs::read(&src).map_err(|e| format!("read {}: {e}", src.display()))?;
            atomic_write_0600(&dst, &bytes)?;
        }
    }
    Ok(())
}

/// Checks if PostgreSQL schema `schema` exists on `pg_url`.
pub fn pg_schema_exists(base_pg_url: &str, schema: &str) -> Result<bool, String> {
    let url = strip_pg_schema_param(base_pg_url);
    let target_schema = schema.to_string();
    let handle = std::thread::spawn(move || -> Result<bool, String> {
        let target = PgTarget::from_url_or_jdbc(&url, None, None, None)?;
        let mut client = pg_connect(&target)?;
        let row = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = $1)",
                &[&target_schema],
            )
            .map_err(|e| format!("query pg_namespace: {e}"))?;
        Ok(row.get::<_, bool>(0))
    });
    handle
        .join()
        .map_err(|_| "PostgreSQL worker panicked".to_string())?
}

/// Renames or drops a PostgreSQL schema cleanly on a dedicated OS thread.
pub fn exec_pg_ddl(base_pg_url: &str, sql: String) -> Result<(), String> {
    let url = strip_pg_schema_param(base_pg_url);
    let handle = std::thread::spawn(move || -> Result<(), String> {
        let target = PgTarget::from_url_or_jdbc(&url, None, None, None)?;
        let mut client = pg_connect(&target)?;
        client
            .batch_execute(&sql)
            .map_err(|e| format!("execute PG DDL failed: {e}"))?;
        Ok(())
    });
    handle
        .join()
        .map_err(|_| "PostgreSQL DDL worker panicked".to_string())?
}

/// Restores `stores/pg-schema/schema.sql` into `target_schema` via `psql --set=ON_ERROR_STOP=1`.
pub fn restore_pg_schema(
    base_pg_url: &str,
    src_schema: &str,
    target_schema: &str,
    manifest: &SnapshotManifest,
    unpack_dir: &Path,
) -> Result<(), String> {
    let pg_comp = manifest
        .components
        .iter()
        .find(|c| c.kind == "pg-schema")
        .ok_or_else(|| {
            exit_with_message(
                EXIT_MISMATCH,
                "postgres snapshot bundle is missing required 'pg-schema' component",
            )
        })?;
    let sql_entry = pg_comp
        .files
        .iter()
        .find(|f| f.store_rel_path == "schema.sql")
        .ok_or_else(|| {
            exit_with_message(
                EXIT_MISMATCH,
                "postgres snapshot bundle 'pg-schema' is missing schema.sql",
            )
        })?;
    let sql_path = unpack_dir.join(validate_safe_rel_path(&sql_entry.bundle_rel_path)?);
    let raw_sql =
        fs::read_to_string(&sql_path).map_err(|e| format!("read {}: {e}", sql_path.display()))?;
    let rewritten =
        rewrite_dump_schema(&normalize_pg_dump_sql(&raw_sql), src_schema, target_schema);

    let tmp_sql = unpack_dir.join(format!("restore-{}.sql", std::process::id()));
    atomic_write_0600(&tmp_sql, rewritten.as_bytes())?;

    let psql = find_pg_tool("psql")?;
    let clean_url = strip_pg_schema_param(base_pg_url);
    let out = Command::new(&psql)
        .args(["--set=ON_ERROR_STOP=1", "--dbname", &clean_url, "--file"])
        .arg(&tmp_sql)
        .output()
        .map_err(|e| format!("run {}: {e}", psql.display()))?;
    if !out.status.success() {
        return Err(format!(
            "psql restore into schema '{target_schema}' failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// RAII wrapper creating and cleaning up a temporary `0700` directory.
pub struct TempDirGuard(PathBuf);

impl TempDirGuard {
    pub fn new(prefix: &str) -> Result<Self, String> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{id}", std::process::id()));
        ensure_dir_0700(&path)?;
        Ok(Self(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
