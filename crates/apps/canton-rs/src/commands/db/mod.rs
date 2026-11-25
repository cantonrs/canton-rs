//! PostgreSQL Storage Engine, Cold Archive Segments, Staged Replay, and DB TUI (`canton-rs db`).

use std::fs;
use std::path::{Path, PathBuf};

use canton_participant::{
    cold_archive::{
        build_cold_segment, collect_pg_storage_stats, ensure_existing_segments_prunable_provenance,
        ensure_prunable_coverage_dir_streaming, export_pg_range_to_segment, list_segment_paths,
        parse_jsonl_history_reader, populate_cold_stats_from_dir, read_pg_archive_identity,
        staged_replay_dir_streaming, verify_archive_dir_streaming, write_segment_to_dir,
        BuildSegmentSpec, ColdArchiveEventKind, ColdArchiveSourceKind, PruneCoverageSpec,
        StorageOverviewStats,
    },
    compute_flyway_checksum,
    migrate::{
        check_and_migrate_for_role, embedded_official, flyway_summary, load_official,
        writer_lock_holder, Migration, NodeRole, Startup, StartupMode, WriterLock, PLACEHOLDERS,
    },
    official_prune::{
        check_prune_safety, check_safe_to_prune, load_prune_safety_inputs, PruneVerdict,
    },
    pgconn::{connect, PgTarget},
    takeover::{
        active_contracts, ensure_existing_canton_db, ledger_end, TakeoverArchive, TakeoverTx,
        TakeoverWriter,
    },
};
use clap::{Args, Subcommand};

use super::db_tui::run_db_tui;
use super::supervisor::format_bytes;

#[derive(Args, Debug)]
pub struct DbArgs {
    #[command(subcommand)]
    pub action: DbAction,
}

#[derive(Subcommand, Debug)]
pub enum DbAction {
    /// Validate or apply official Flyway SQL migrations on a real PostgreSQL connection.
    Migrate(DbMigrateArgs),
    /// Verify WriterLock and inspect/take over an official JVM Canton PostgreSQL database.
    Takeover(DbTakeoverArgs),
    /// Compute the exact Flyway CRC32 checksum of a SQL statement or migration string.
    Checksum(DbChecksumArgs),
    /// Query live Flyway schema history, ledger end, and writer lock status from PostgreSQL.
    Status(DbStatusArgs),
    /// Inspect PostgreSQL table row/byte footprints, prunable headroom, and Cold Archive chain stats.
    Stats(DbStatsArgs),
    /// Export an immutable, hash-chained (and optionally Ed25519-signed) Cold Archive segment before pruning.
    Archive(DbArchiveArgs),
    /// Verify cryptographic SHA-256 hash-chaining and Ed25519 signatures across a Cold Archive directory.
    VerifyArchive(DbVerifyArchiveArgs),
    /// Execute deterministic 4-stage ACS catch-up replay from Cold Archive segments.
    Replay(DbReplayArgs),
    /// Launch the interactive theme-safe `ratatui` Storage, Cold Archive & 4-Stage Replay TUI (`db top`).
    #[command(visible_alias = "top")]
    Tui(DbTuiArgs),
}

#[derive(Args, Debug)]
pub struct DbMigrateArgs {
    /// JDBC or PostgreSQL URL.
    #[arg(
        long,
        default_value = "jdbc:postgresql://127.0.0.1:5432/canton?currentSchema=public"
    )]
    pub jdbc_url: String,

    /// Explicitly apply pending migrations before starting node (`--migrate-and-start`).
    #[arg(long, default_value_t = false)]
    pub migrate_and_start: bool,

    /// Node role for schema initialization (`participant`, `sequencer`, `mediator`).
    #[arg(long, default_value = "participant")]
    pub role: String,

    /// Path to unpacked Canton SQL migrations directory (`db/migration/canton/postgres`).
    #[arg(long)]
    pub migrations_dir: Option<PathBuf>,

    /// PostgreSQL user (when omitted from the URL).
    #[arg(long)]
    pub user: Option<String>,

    /// PostgreSQL password (when omitted from the URL; prefer PGPASSWORD or --password-file).
    #[arg(long)]
    pub password: Option<String>,

    /// File holding the PostgreSQL password (trimmed of trailing newline; keeps secrets out of `ps`).
    #[arg(long, conflicts_with = "password")]
    pub password_file: Option<PathBuf>,

    /// Optional SQL executed on every newly opened PostgreSQL connection (`connectionInitSql`).
    #[arg(long)]
    pub connection_init_sql: Option<String>,

    /// Treat unsupported/older PostgreSQL versions as warnings (`non-standard-config`).
    #[arg(long, default_value_t = false)]
    pub non_standard_config: bool,
}

#[derive(Args, Debug)]
pub struct DbTakeoverArgs {
    /// JDBC or PostgreSQL URL of the existing official JVM Canton database.
    #[arg(
        long,
        default_value = "jdbc:postgresql://127.0.0.1:5432/participant_db?currentSchema=public"
    )]
    pub jdbc_url: String,

    /// Path to unpacked Canton SQL migrations directory (`db/migration/canton/postgres`).
    #[arg(long)]
    pub migrations_dir: Option<PathBuf>,

    /// Optional party identifier to inspect active contracts for from the official schema.
    #[arg(long)]
    pub party: Option<String>,

    /// PostgreSQL user (when omitted from the URL).
    #[arg(long)]
    pub user: Option<String>,

    /// PostgreSQL password (when omitted from the URL; prefer PGPASSWORD or --password-file).
    #[arg(long)]
    pub password: Option<String>,

    /// File holding the PostgreSQL password (trimmed of trailing newline; keeps secrets out of `ps`).
    #[arg(long, conflicts_with = "password")]
    pub password_file: Option<PathBuf>,

    /// Optional SQL executed on connection (`connectionInitSql`).
    #[arg(long)]
    pub connection_init_sql: Option<String>,

    /// Contract ID (hex) to mark archived directly in the database, outside the protocol; needs `--unsafe-offline-archive`.
    #[arg(long)]
    pub archive_cid: Option<String>,

    /// Accept that `--archive-cid` bypasses Daml authorization, the sequencer and mediator, and every other participant.
    #[arg(long, default_value_t = false)]
    pub unsafe_offline_archive: bool,

    /// Command ID used when `--archive-cid` writes a transaction.
    #[arg(long, default_value = "canton-rs-takeover-archive")]
    pub command_id: String,

    /// Submitter party used with `--archive-cid` (defaults to `--party` when omitted).
    #[arg(long)]
    pub submitter: Option<String>,

    /// Offset to physically prune up to; refused past the participant's safe point (ACS digest checkpoint, commitment
    /// matching, deduplication duration), as the participant's own pruning refuses it.
    #[arg(long)]
    pub prune_offset: Option<u64>,
}

#[derive(Args, Debug)]
pub struct DbChecksumArgs {
    /// Raw SQL content to hash with Flyway CRC32 algorithm.
    #[arg(long)]
    pub sql: String,
}

#[derive(Args, Debug)]
pub struct DbStatusArgs {
    /// JDBC or PostgreSQL URL.
    #[arg(
        long,
        default_value = "jdbc:postgresql://127.0.0.1:5432/canton?currentSchema=public"
    )]
    pub jdbc_url: String,

    /// PostgreSQL user (when omitted from the URL).
    #[arg(long)]
    pub user: Option<String>,

    /// PostgreSQL password (when omitted from the URL; prefer PGPASSWORD or --password-file).
    #[arg(long)]
    pub password: Option<String>,

    /// File holding the PostgreSQL password (trimmed of trailing newline; keeps secrets out of `ps`).
    #[arg(long, conflicts_with = "password")]
    pub password_file: Option<PathBuf>,

    /// Optional SQL executed on connection (`connectionInitSql`).
    #[arg(long)]
    pub connection_init_sql: Option<String>,
}

#[derive(Args, Debug)]
pub struct DbStatsArgs {
    /// Optional JDBC or PostgreSQL URL (omit for offline Cold Archive inspection only).
    #[arg(long)]
    pub jdbc_url: Option<String>,

    /// Optional Cold Archive directory containing `.crs-seg.json` segments.
    #[arg(long)]
    pub archive_dir: Option<PathBuf>,

    /// PostgreSQL user (when omitted from the URL).
    #[arg(long)]
    pub user: Option<String>,

    /// PostgreSQL password (when omitted from the URL; prefer PGPASSWORD or --password-file).
    #[arg(long)]
    pub password: Option<String>,

    /// File holding the PostgreSQL password (trimmed of trailing newline; keeps secrets out of `ps`).
    #[arg(long, conflicts_with = "password")]
    pub password_file: Option<PathBuf>,

    /// Optional SQL executed on connection (`connectionInitSql`).
    #[arg(long)]
    pub connection_init_sql: Option<String>,

    /// Emit machine-readable JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DbArchiveArgs {
    /// Directory where immutable `.crs-seg.json` segments are stored.
    #[arg(long, default_value = "./cold-archive")]
    pub archive_dir: PathBuf,

    /// Optional starting offset (defaults to `prev_segment.to_offset + 1` or `1`).
    #[arg(long)]
    pub from_offset: Option<i64>,

    /// Inclusive ending offset to export into this Cold Archive segment.
    #[arg(long, visible_alias = "to-offset")]
    pub up_to_offset: i64,

    /// Optional JSONL history file (`--scan-history` / `--exex-jsonl` format) for offline export without PostgreSQL.
    #[arg(long)]
    pub from_history: Option<PathBuf>,

    /// Optional JDBC or PostgreSQL URL when exporting directly from `lapi_events_*` tables.
    #[arg(long)]
    pub jdbc_url: Option<String>,

    /// Synchronizer ID recorded in the segment header when exporting from JSONL history.
    #[arg(long, default_value = "canton-rs::sync")]
    pub synchronizer_id: String,

    /// Participant ID recorded in the segment header when exporting from JSONL history.
    #[arg(long, default_value = "participant1")]
    pub participant_id: String,

    /// Redact plaintext contract payloads (`payload_json = null`) while preserving `payload_sha256` digests.
    #[arg(long, default_value_t = false)]
    pub zero_payload: bool,

    /// File holding the 32-byte Ed25519 signing secret key (64 hex chars) that signs the segment.
    #[arg(long, conflicts_with = "signing_key_hex")]
    pub signing_key_file: Option<PathBuf>,

    /// The signing secret key as 64 hex chars (visible in `ps` and shell history; prefer --signing-key-file).
    #[arg(long)]
    pub signing_key_hex: Option<String>,

    /// Sign the segment with a freshly generated ephemeral Ed25519 key when `--signing-key-hex` is omitted.
    #[arg(long, default_value_t = false)]
    pub sign_ephemeral: bool,

    /// Physically prune PostgreSQL up to `--up-to-offset` after the segment is written and verified. Refused unless the
    /// archive covers offsets 1..=up-to with contract bodies (no --zero-payload, no --from-history) and the participant's
    /// safe point (ACS digest checkpoint, commitment matching, deduplication duration) allows the offset.
    #[arg(long, default_value_t = false)]
    pub prune_after_archive: bool,

    /// PostgreSQL user (when omitted from the URL).
    #[arg(long)]
    pub user: Option<String>,

    /// PostgreSQL password (when omitted from the URL; prefer PGPASSWORD or --password-file).
    #[arg(long)]
    pub password: Option<String>,

    /// File holding the PostgreSQL password (trimmed of trailing newline; keeps secrets out of `ps`).
    #[arg(long, conflicts_with = "password")]
    pub password_file: Option<PathBuf>,

    /// Optional SQL executed on connection (`connectionInitSql`).
    #[arg(long)]
    pub connection_init_sql: Option<String>,

    /// Emit machine-readable JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DbVerifyArchiveArgs {
    /// Directory containing `.crs-seg.json` Cold Archive segments.
    #[arg(long, default_value = "./cold-archive")]
    pub archive_dir: PathBuf,

    /// Ed25519 public key (64 hex chars) every segment must be signed with; without it a signature shows integrity only.
    #[arg(long)]
    pub expected_signer_hex: Option<String>,

    /// Emit machine-readable JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DbReplayArgs {
    /// Directory containing `.crs-seg.json` Cold Archive segments.
    #[arg(long, default_value = "./cold-archive")]
    pub archive_dir: PathBuf,

    /// Optional target offset ceiling for 4-stage replay (defaults to chain head).
    #[arg(long)]
    pub up_to_offset: Option<i64>,

    /// Emit machine-readable JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DbTuiArgs {
    /// Optional JDBC or PostgreSQL URL (omit for offline Cold Archive TUI mode).
    #[arg(long)]
    pub jdbc_url: Option<String>,

    /// Optional Cold Archive directory containing `.crs-seg.json` segments.
    #[arg(long)]
    pub archive_dir: Option<PathBuf>,

    /// PostgreSQL user (when omitted from the URL).
    #[arg(long)]
    pub user: Option<String>,

    /// PostgreSQL password (when omitted from the URL; prefer PGPASSWORD or --password-file).
    #[arg(long)]
    pub password: Option<String>,

    /// File holding the PostgreSQL password (trimmed of trailing newline; keeps secrets out of `ps`).
    #[arg(long, conflicts_with = "password")]
    pub password_file: Option<PathBuf>,

    /// Optional SQL executed on connection (`connectionInitSql`).
    #[arg(long)]
    pub connection_init_sql: Option<String>,
}

/// Reads a secret file (`--signing-key-file` / `--password-file`) after opening it and verifying
/// Unix mode `0600` (no group/other access) on the opened file descriptor.
pub(crate) fn read_secret_file(path: &Path, flag: &str) -> Result<String, String> {
    use std::io::Read;
    let mut file = fs::File::open(path)
        .map_err(|e| format!("failed to read {flag} '{}': {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("failed to inspect {flag} '{}': {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "refusing to read {flag} '{}': permissions {:04o} are too broad \
                 (must be 0600 or stricter; run `chmod 600 '{}'`)",
                path.display(),
                mode,
                path.display()
            ));
        }
    }
    let _ = &meta;
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .map_err(|e| format!("failed to read {flag} '{}': {e}", path.display()))?;
    Ok(buf)
}

fn jdbc_url_contains_password(url: &str) -> bool {
    PgTarget::from_url_or_jdbc(url, None, None, None).is_ok_and(|t| !t.password.is_empty())
}

fn parse_signing_key_opt(
    signing_key_file: Option<&Path>,
    signing_key_hex: Option<&str>,
    sign_ephemeral: bool,
) -> Result<Option<[u8; 32]>, String> {
    let (flag, hex_str) = match signing_key_file {
        Some(path) => (
            "--signing-key-file",
            read_secret_file(path, "--signing-key-file")?,
        ),
        None => match signing_key_hex {
            Some(h) => ("--signing-key-hex", h.to_string()),
            None => {
                if sign_ephemeral {
                    let key: [u8; 32] = rand::random();
                    return Ok(Some(key));
                }
                return Ok(None);
            }
        },
    };
    let raw = hex::decode(hex_str.trim())
        .map_err(|e| format!("invalid {flag} (expected 64 hex chars): {e}"))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| format!("{flag} must decode to exactly 32 bytes"))?;
    Ok(Some(arr))
}

fn resolve_migrations(explicit: Option<&Path>) -> Result<Vec<Migration>, String> {
    if let Some(p) = explicit {
        if !p.exists() {
            return Err(format!("migrations directory not found: {}", p.display()));
        }
        return load_official(p).map_err(|e| e.to_string());
    }
    embedded_official().map_err(|e| e.to_string())
}

fn parse_target(
    jdbc_url: &str,
    user: Option<&str>,
    password: Option<&str>,
    password_file: Option<&Path>,
    init_sql: Option<&str>,
) -> Result<PgTarget, String> {
    let file_password = match password_file {
        Some(path) => {
            let raw = read_secret_file(path, "--password-file")?;
            Some(raw.trim_end_matches(&['\r', '\n'][..]).to_string())
        }
        None => None,
    };
    let effective_password = password.or(file_password.as_deref());
    let mut target = PgTarget::from_url_or_jdbc(jdbc_url, user, effective_password, init_sql)?;
    // libpq's convention: a password given neither as a flag nor in the URL comes from the environment, not argv
    if target.password.is_empty() {
        if let Ok(env_password) = std::env::var("PGPASSWORD") {
            target.password = env_password;
        }
    }
    Ok(target)
}

/// What `db takeover --archive-cid` skips, said before anything is written.
///
/// [CANTON-NOTE: SEMANTICS] Canton's only way to change a participant's ACS outside the protocol is the repair service
/// (`RepairService.purgeContracts`), which needs the participant disconnected from the synchronizer and leaves the other
/// stakeholders' participants to be repaired the same way.
const OFFLINE_ARCHIVE_REFUSAL: &str = "--archive-cid writes an archive straight into this database, outside the \
Canton protocol: no Daml authorization check (the actor is only the --submitter argument), no sequencer, no mediator, \
and no other participant is told. Every counter-participant keeps the contract active, so the ledgers diverge and ACS \
commitments will mismatch until each of them purges it too (Canton: repair.purge_contracts, with the participant \
disconnected). Pass --unsafe-offline-archive to write it anyway.";

pub fn execute_db(args: DbArgs) -> Result<(), String> {
    match args.action {
        DbAction::Migrate(m_args) => {
            let role = NodeRole::parse(&m_args.role).ok_or_else(|| {
                format!(
                    "unknown node role '{}' (expected participant|sequencer|mediator)",
                    m_args.role
                )
            })?;
            let target = parse_target(
                &m_args.jdbc_url,
                m_args.user.as_deref(),
                m_args.password.as_deref(),
                m_args.password_file.as_deref(),
                m_args.connection_init_sql.as_deref(),
            )?;
            let migrations = resolve_migrations(m_args.migrations_dir.as_deref())?;
            // the writer lock comes first: a running official node holds it, and migrating under it is what must not happen
            let lock = WriterLock::take(connect(&target)?, &target.database)?;
            let mut client = connect(&target)?;
            let mode = if m_args.migrate_and_start {
                StartupMode::MigrateAndStart
            } else {
                StartupMode::CheckPending
            };
            let startup = check_and_migrate_for_role(
                &mut client,
                &target.database,
                &migrations,
                &PLACEHOLDERS,
                mode,
                role,
                !m_args.non_standard_config,
            )
            .map_err(|e| e.to_string())?;
            let applied = match &startup {
                Startup::Migrated(rows) => rows.len(),
                Startup::UpToDate => 0,
            };
            let (total_rows, max_version) = flyway_summary(&mut client)?;
            let lock_id = lock.id();
            drop(lock);

            println!("============================================================");
            println!(" Canton PostgreSQL Flyway Migration Engine (Real PG)");
            println!("============================================================");
            println!(" Database Host:        {}:{}", target.host, target.port);
            println!(" Database Name:        {}", target.database);
            println!(
                " Search Path Schema:   {}",
                target.schema.as_deref().unwrap_or("public")
            );
            println!(" Node Role:            {:?}", role);
            println!(" Applied Migrations:   {}", applied);
            println!(" Total History Rows:   {}", total_rows);
            println!(" Schema Version:       {}", max_version);
            println!(" Purpose 33 Lock ID:   {}", lock_id);
            println!(" Migration Status:     SUCCESS");
            println!("============================================================");
            Ok(())
        }
        DbAction::Takeover(t_args) => {
            if t_args.archive_cid.is_some() && !t_args.unsafe_offline_archive {
                return Err(OFFLINE_ARCHIVE_REFUSAL.to_string());
            }
            let archive_submitter = t_args
                .archive_cid
                .as_deref()
                .map(|cid| {
                    let submitter = t_args
                        .submitter
                        .as_deref()
                        .or(t_args.party.as_deref())
                        .ok_or_else(|| {
                            "--archive-cid requires --submitter (or --party) to identify acting party"
                                .to_string()
                        })?;
                    Ok::<_, String>((cid, submitter))
                })
                .transpose()?;
            let prune_i64 = match t_args.prune_offset {
                Some(o) => {
                    if t_args.password.is_some() {
                        return Err(
                            "refusing --password on pruning command (`db takeover --prune-offset`): \
                             CLI passwords leak via `ps`; use PGPASSWORD or --password-file (mode 0600)"
                                .to_string(),
                        );
                    }
                    if jdbc_url_contains_password(&t_args.jdbc_url) {
                        return Err(
                            "refusing password embedded in --jdbc-url on pruning command \
                             (`db takeover --prune-offset`); use PGPASSWORD or --password-file (mode 0600)"
                                .to_string(),
                        );
                    }
                    Some(i64::try_from(o).map_err(|_| {
                        format!("invalid --prune-offset {o}: exceeds signed 64-bit ledger offset")
                    })?)
                }
                None => None,
            };
            let target = parse_target(
                &t_args.jdbc_url,
                t_args.user.as_deref(),
                t_args.password.as_deref(),
                t_args.password_file.as_deref(),
                t_args.connection_init_sql.as_deref(),
            )?;
            let migrations = resolve_migrations(t_args.migrations_dir.as_deref())?;
            let mut client = connect(&target)?;
            ensure_existing_canton_db(&mut client, &target.database)?;
            // Hold the writer lock before running any migration checks so a live JVM writer blocks us immediately.
            let lock = WriterLock::take(connect(&target)?, &target.database)?;
            let startup = check_and_migrate_for_role(
                &mut client,
                &target.database,
                &migrations,
                &PLACEHOLDERS,
                StartupMode::CheckPending,
                NodeRole::Participant,
                true,
            )
            .map_err(|e| e.to_string())?;
            let pending = match startup {
                Startup::UpToDate => 0,
                Startup::Migrated(rows) => rows.len(),
            };
            let lock_id = lock.id();
            let (total_rows, max_version) = flyway_summary(&mut client)?;
            let mut writer = TakeoverWriter::from_parts(client, lock);
            // [CANTON-NOTE: INVARIANT] Check prune safety BEFORE committing any `--archive-cid` transaction so a
            // prune refusal leaves PostgreSQL untouched rather than partially mutated.
            if let Some(p) = prune_i64 {
                check_safe_to_prune(writer.client_mut(), p)?;
            }
            let receipt = if let Some((cid, submitter)) = archive_submitter {
                writer.append_transaction(&TakeoverTx {
                    user_id: "canton-rs-db-takeover".to_string(),
                    command_id: t_args.command_id.clone(),
                    submission_id: None,
                    workflow_id: None,
                    submitters: vec![submitter.to_string()],
                    synchronizer_id: None,
                    record_time_micros: None,
                    creates: Vec::new(),
                    archives: vec![TakeoverArchive::archive(
                        cid,
                        vec![submitter.to_string()],
                        0,
                    )],
                })?
            } else {
                let pre_end = ledger_end(writer.client_mut()).map_err(|e| e.to_string())?;
                canton_participant::takeover::TakeoverWriteReceipt {
                    offset: pre_end.as_ref().map(|e| e.offset).unwrap_or(0),
                    sequential_id_first: None,
                    sequential_id_last: None,
                    update_id_hex: None,
                    change_id_hash: String::new(),
                }
            };
            let prune_report = match (t_args.prune_offset, prune_i64) {
                (Some(prune_offset), Some(p)) => Some((prune_offset, writer.prune_up_to(p)?)),
                _ => None,
            };
            let end = ledger_end(writer.client_mut()).map_err(|e| e.to_string())?;
            let party_acs = match (&t_args.party, &end) {
                (Some(party), Some(e)) => Some(
                    active_contracts(writer.client_mut(), party, e)
                        .map_err(|err| err.to_string())?
                        .len(),
                ),
                _ => None,
            };
            drop(writer);

            println!("============================================================");
            println!(" Canton PostgreSQL DB Takeover Verification (Real PG)");
            println!("============================================================");
            println!(
                " Target Schema:        {}",
                target.schema.as_deref().unwrap_or("public")
            );
            println!(" Flyway History Rows:  {} (v{})", total_rows, max_version);
            println!(" Applied Migrations:   {}", pending);
            println!(" Writer Lock Acquired: {} (Purpose 33 DbLockId)", lock_id);
            if t_args.archive_cid.is_some() {
                println!(
                    " Archived CID Written: offset {} (update_id {}), outside the protocol: not confirmed by the synchronizer",
                    receipt.offset,
                    receipt.update_id_hex.as_deref().unwrap_or("-")
                );
            }
            if let Some((offset, report)) = &prune_report {
                println!(
                    " Pruned Up To Offset:  {} ({} contracts removed)",
                    offset, report.pruned_contracts
                );
            }
            match &end {
                Some(e) => {
                    println!(" Participant ID:       {}", e.participant_id);
                    println!(
                        " Ledger End Offset:    {} (seq {})",
                        e.offset, e.sequential_id
                    );
                }
                None => println!(" Ledger End Offset:    none (empty ledger)"),
            }
            if let Some(count) = party_acs {
                println!(" Party Active Rows:    {}", count);
            }
            println!(" DB Takeover Status:   ONLINE (writer lock held, schema verified)");
            println!("============================================================");
            Ok(())
        }
        DbAction::Checksum(c_args) => {
            let checksum = compute_flyway_checksum(&c_args.sql);
            println!("Flyway CRC32 Checksum: {}", checksum);
            Ok(())
        }
        DbAction::Status(s_args) => {
            let target = parse_target(
                &s_args.jdbc_url,
                s_args.user.as_deref(),
                s_args.password.as_deref(),
                s_args.password_file.as_deref(),
                s_args.connection_init_sql.as_deref(),
            )?;
            let mut client = connect(&target)?;
            let (total_rows, max_version) = flyway_summary(&mut client)?;
            let (lock_id, holder) = writer_lock_holder(&mut client, &target.database)?;
            let end = if total_rows > 0 {
                ledger_end(&mut client).map_err(|e| e.to_string())?
            } else {
                None
            };

            println!("Database Storage Status: ONLINE");
            println!(
                "Schema:                  {}",
                target.schema.as_deref().unwrap_or("public")
            );
            println!("Flyway History Count:    {} (v{})", total_rows, max_version);
            println!(
                "Writer Lock ({lock_id}): {}",
                holder.map_or("FREE".into(), |p| format!("HELD by pid {p}"))
            );
            match end {
                Some(e) => println!(
                    "Ledger End Offset:       {} (seq {}, participant {})",
                    e.offset, e.sequential_id, e.participant_id
                ),
                None => println!("Ledger End Offset:       none"),
            }
            Ok(())
        }
        DbAction::Stats(st_args) => execute_db_stats(st_args),
        DbAction::Archive(ar_args) => execute_db_archive(ar_args),
        DbAction::VerifyArchive(va_args) => execute_db_verify_archive(va_args),
        DbAction::Replay(rp_args) => execute_db_replay(rp_args),
        DbAction::Tui(tui_args) => execute_db_tui_cmd(tui_args),
    }
}

fn collect_unified_stats(
    jdbc_url: Option<&str>,
    user: Option<&str>,
    password: Option<&str>,
    password_file: Option<&Path>,
    init_sql: Option<&str>,
    archive_dir: Option<&Path>,
) -> Result<(String, StorageOverviewStats), String> {
    if let Some(url) = jdbc_url {
        let target = parse_target(url, user, password, password_file, init_sql)?;
        let label = format!("{}:{}/{}", target.host, target.port, target.database);
        let mut client = connect(&target)?;
        let stats = collect_pg_storage_stats(&mut client, archive_dir)?;
        Ok((label, stats))
    } else {
        let mut stats = StorageOverviewStats {
            cold_chain_valid: true,
            ..StorageOverviewStats::default()
        };
        if let Some(dir) = archive_dir {
            populate_cold_stats_from_dir(dir, &mut stats);
        }
        let label = archive_dir
            .map(|d| format!("cold-only:{}", d.display()))
            .unwrap_or_else(|| "cold-only:(none)".to_string());
        Ok((label, stats))
    }
}

fn execute_db_stats(args: DbStatsArgs) -> Result<(), String> {
    let (label, stats) = collect_unified_stats(
        args.jdbc_url.as_deref(),
        args.user.as_deref(),
        args.password.as_deref(),
        args.password_file.as_deref(),
        args.connection_init_sql.as_deref(),
        args.archive_dir.as_deref(),
    )?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&stats).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    println!("============================================================");
    println!(" Canton Storage & Cold Archive Diagnostics ({label})");
    println!("============================================================");
    println!(" Ledger End Offset:      #{}", stats.ledger_end);
    println!(" Pruned Up To Offset:    #{}", stats.pruned_up_to);
    println!(" Prunable Activations:   {}", stats.prunable_activations);
    println!(" Prunable Deactivations: {}", stats.prunable_deactivations);
    println!(
        " Total Relation Size:    {}",
        format_bytes(stats.total_db_bytes)
    );
    println!(
        " Cold Archive Segments:  {} ({} events, max={:?}, chain_ok={})",
        stats.cold_segments_count,
        stats.cold_events_count,
        stats.cold_max_offset,
        stats.cold_chain_valid
    );
    if !stats.tables.is_empty() {
        println!("------------------------------------------------------------");
        println!(
            " {:<14} {:<32} {:>8} {:>10}",
            "CATEGORY", "TABLE", "ROWS", "SIZE"
        );
        for t in &stats.tables {
            println!(
                " {:<14} {:<32} {:>8} {:>10}",
                t.category,
                t.table_name,
                t.row_count,
                format_bytes(t.total_bytes)
            );
        }
    }
    println!("============================================================");
    Ok(())
}

fn execute_db_archive(args: DbArchiveArgs) -> Result<(), String> {
    if args.from_history.is_none() && args.jdbc_url.is_none() {
        return Err(
            "canton-rs db archive requires either --jdbc-url <PG_URL> or --from-history <FILE.jsonl>"
                .to_string(),
        );
    }
    if args.prune_after_archive {
        if args.jdbc_url.is_none() {
            return Err("--prune-after-archive requires --jdbc-url <PG_URL>".to_string());
        }
        if args.from_history.is_some() {
            return Err("--prune-after-archive deletes from the --jdbc-url database, but a --from-history \
                        segment is not read from it: nothing shows the segment holds what the prune deletes"
                .to_string());
        }
        if args.zero_payload {
            return Err(
                "--prune-after-archive deletes contract bodies that --zero-payload leaves out of \
                        the segment: they could not be restored"
                    .to_string(),
            );
        }
        if args.signing_key_hex.is_some() {
            return Err(
                "refusing --signing-key-hex with --prune-after-archive: CLI hex keys leak in \
                 process lists (`ps`); use --signing-key-file (mode 0600)"
                    .to_string(),
            );
        }
        if args.signing_key_file.is_none() {
            return Err(
                "--prune-after-archive requires a persistent Ed25519 signing key \
                 via --signing-key-file (mode 0600); unsigned, --sign-ephemeral, or \
                 --signing-key-hex segments are refused"
                    .to_string(),
            );
        }
        if args.password.is_some() {
            return Err(
                "refusing --password with --prune-after-archive: CLI passwords leak in process \
                 lists (`ps`); use PGPASSWORD or --password-file (mode 0600)"
                    .to_string(),
            );
        }
        if args
            .jdbc_url
            .as_deref()
            .is_some_and(jdbc_url_contains_password)
        {
            return Err(
                "refusing password embedded in --jdbc-url with --prune-after-archive; \
                 use PGPASSWORD or --password-file (mode 0600)"
                    .to_string(),
            );
        }
    }

    let (existing_report, _) =
        verify_archive_dir_streaming(&args.archive_dir, None).map_err(|e| {
            format!("refusing to append onto corrupted existing cold archive chain: {e}")
        })?;
    let prev_sha = existing_report.head_segment_sha256.clone();
    let next_from = existing_report.max_offset.map_or(1, |to| to + 1);

    let sign_key = parse_signing_key_opt(
        args.signing_key_file.as_deref(),
        args.signing_key_hex.as_deref(),
        args.sign_ephemeral,
    )?;

    // [CANTON-NOTE: INVARIANT] A prune holds the writer lock from before the export until after the delete, and is
    // refused before anything is written when the participant would refuse it (safe point) or the archive would not
    // hold what it deletes (PG-sourced, DB-identity & expected-signer verified coverage from expected_start).
    let (mut pruner, expected_prune_start) = match (&args.jdbc_url, args.prune_after_archive) {
        (Some(jdbc), true) => {
            let key_bytes = sign_key.as_ref().ok_or_else(|| {
                "--prune-after-archive requires --signing-key-file (mode 0600)".to_string()
            })?;
            let expected_signer_pk = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(key_bytes)
                    .verifying_key()
                    .to_bytes(),
            );
            let target = parse_target(
                jdbc,
                args.user.as_deref(),
                args.password.as_deref(),
                args.password_file.as_deref(),
                args.connection_init_sql.as_deref(),
            )?;
            let lock = WriterLock::take(connect(&target)?, &target.database)?;
            let mut writer = TakeoverWriter::from_parts(connect(&target)?, lock);
            let safety = load_prune_safety_inputs(writer.client_mut())?;
            if check_prune_safety(args.up_to_offset, &safety).map_err(|e| e.to_string())?
                == PruneVerdict::AlreadyPruned
            {
                return Err(format!(
                    "the database is already pruned at or beyond offset {}: its events can no longer be archived",
                    args.up_to_offset
                ));
            }
            let target_id =
                read_pg_archive_identity(writer.client_mut()).map_err(|e| e.to_string())?;
            let expected_start = safety.pruned_up_to.saturating_add(1).max(1);
            if existing_report.segments_verified > 0 {
                let coverage_spec = PruneCoverageSpec {
                    expected_start,
                    prune_up_to: args.up_to_offset,
                    expected_participant_id: &target_id.participant_id,
                    expected_synchronizer_id: &target_id.synchronizer_id,
                    expected_signer_public_key_hex: &expected_signer_pk,
                };
                ensure_existing_segments_prunable_provenance(&args.archive_dir, &coverage_spec)
                    .map_err(|e| e.to_string())?;
            }
            (
                Some((writer, safety.pruned_up_to, target_id, expected_signer_pk)),
                expected_start,
            )
        }
        _ => (None, 1),
    };

    let derived_from = match args.from_offset {
        Some(f) => f,
        None if pruner.is_some() && existing_report.segments_verified == 0 => expected_prune_start,
        None => next_from,
    };

    if existing_report.segments_verified > 0 && derived_from != next_from {
        return Err(if derived_from > next_from {
            format!(
                "invalid --from-offset {derived_from}: a gap after the last archived offset {}; \
                 offsets {next_from}..={} would never be archived",
                next_from - 1,
                derived_from - 1
            )
        } else {
            format!(
                "invalid --from-offset {derived_from}: must be > last archived offset {}",
                next_from - 1
            )
        });
    }
    if let Some((_, already_pruned, _, _)) = pruner.as_ref() {
        if derived_from <= *already_pruned {
            return Err(format!(
                "invalid --from-offset {derived_from}: PostgreSQL is already pruned up to offset {already_pruned}; \
                 earlier offsets can no longer be exported"
            ));
        }
        if existing_report.segments_verified == 0 && derived_from > expected_prune_start {
            return Err(format!(
                "invalid --from-offset {derived_from}: with --prune-after-archive and an empty archive directory, \
                 export must start at offset {expected_prune_start} (gap {expected_prune_start}..={} would be deleted unarchived)",
                derived_from - 1
            ));
        }
    }

    let segment = if let Some(hist_path) = &args.from_history {
        let file = fs::File::open(hist_path).map_err(|e| {
            format!(
                "failed to open --from-history '{}': {e}",
                hist_path.display()
            )
        })?;
        let reader = std::io::BufReader::new(file);
        let events =
            parse_jsonl_history_reader(reader, derived_from, args.up_to_offset, args.zero_payload)
                .map_err(|e| e.to_string())?;
        build_cold_segment(BuildSegmentSpec {
            synchronizer_id: &args.synchronizer_id,
            participant_id: &args.participant_id,
            source_kind: Some(ColdArchiveSourceKind::Jsonl),
            from_offset: derived_from,
            to_offset: args.up_to_offset,
            prev_segment_sha256: prev_sha,
            events,
            signing_key_bytes: sign_key.as_ref(),
        })
        .map_err(|e| e.to_string())?
    } else {
        let mut own_client = None;
        let client = match pruner.as_mut() {
            Some((writer, _, _, _)) => writer.client_mut(),
            None => {
                let jdbc = args.jdbc_url.as_deref().unwrap_or_default();
                let target = parse_target(
                    jdbc,
                    args.user.as_deref(),
                    args.password.as_deref(),
                    args.password_file.as_deref(),
                    args.connection_init_sql.as_deref(),
                )?;
                own_client.insert(connect(&target)?)
            }
        };
        export_pg_range_to_segment(
            client,
            derived_from,
            args.up_to_offset,
            prev_sha,
            args.zero_payload,
            sign_key.as_ref(),
        )
        .map_err(|e| e.to_string())?
    };

    if pruner.is_some() {
        if let Some(ev) = segment
            .events
            .iter()
            .find(|e| e.kind == ColdArchiveEventKind::Activate && e.payload_json.is_none())
        {
            return Err(format!(
                "refusing to prune: activation of {} at offset {} has no contract body",
                ev.contract_id, ev.offset
            ));
        }
    }

    // [CANTON-NOTE: INVARIANT] `write_segment_to_dir` fsyncs, re-reads and verifies the segment before returning `Ok`;
    // the prune runs only after full streaming provenance/signer/coverage verification of the directory chain.
    let written_path =
        write_segment_to_dir(&args.archive_dir, &segment).map_err(|e| e.to_string())?;
    if let Some((_, _, ref target_id, ref expected_signer_pk)) = pruner {
        let coverage_spec = PruneCoverageSpec {
            expected_start: expected_prune_start,
            prune_up_to: args.up_to_offset,
            expected_participant_id: &target_id.participant_id,
            expected_synchronizer_id: &target_id.synchronizer_id,
            expected_signer_public_key_hex: expected_signer_pk,
        };
        ensure_prunable_coverage_dir_streaming(&args.archive_dir, &coverage_spec)
            .map_err(|e| e.to_string())?;
    }

    let mut pruned_contracts = None;
    if let Some((writer, _, _, _)) = pruner.as_mut() {
        let rep = writer.prune_up_to(args.up_to_offset)?;
        pruned_contracts = Some(rep.pruned_contracts);
    }

    if args.json {
        let out = serde_json::json!({
            "segment_file": written_path.display().to_string(),
            "from_offset": segment.from_offset,
            "to_offset": segment.to_offset,
            "events_count": segment.events_count,
            "segment_sha256": segment.segment_sha256,
            "prev_segment_sha256": segment.prev_segment_sha256,
            "acs_state_root_sha256": segment.acs_state_root_sha256,
            "signed": segment.ed25519_signature_hex.is_some(),
            "signer_public_key_hex": segment.signer_public_key_hex,
            "pruned_contracts": pruned_contracts,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    } else {
        println!("Cold Archive Segment Exported: {}", written_path.display());
        println!(
            "Offset Window:                 [{} ..= {}] ({} events)",
            segment.from_offset, segment.to_offset, segment.events_count
        );
        println!("Segment SHA-256:               {}", segment.segment_sha256);
        println!(
            "ACS State Root SHA-256:        {}",
            segment.acs_state_root_sha256
        );
        println!(
            "Ed25519 Signed:                {}",
            segment.ed25519_signature_hex.is_some()
        );
        if let Some(pk) = segment.signer_public_key_hex.as_deref() {
            println!("Signer Public Key:             {pk}");
        }
        if let Some(cnt) = pruned_contracts {
            println!("Post-Archive PG Pruned:        {cnt} contract(s) physically removed");
        }
    }
    Ok(())
}

fn execute_db_verify_archive(args: DbVerifyArchiveArgs) -> Result<(), String> {
    let (report, _) =
        verify_archive_dir_streaming(&args.archive_dir, args.expected_signer_hex.as_deref())
            .map_err(|e| e.to_string())?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!("Cold Archive Verification:     VALID");
        println!(
            "Signer:                        {}",
            args.expected_signer_hex.as_deref().map_or(
                "not checked (pass --expected-signer-hex to check who signed)".to_string(),
                |k| format!("every segment signed by {k}")
            )
        );
        println!(
            "Verified Segments:             {}",
            report.segments_verified
        );
        println!("Ed25519 Signed Segments:       {}", report.signed_segments);
        println!("Total Archived Events:         {}", report.total_events);
        println!(
            "Offset Span:                   {:?} ..= {:?}",
            report.min_offset, report.max_offset
        );
        println!(
            "Head Segment SHA-256:          {}",
            report.head_segment_sha256.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn execute_db_replay(args: DbReplayArgs) -> Result<(), String> {
    if list_segment_paths(&args.archive_dir)
        .map_err(|e| e.to_string())?
        .is_empty()
    {
        return Err(format!(
            "no '.crs-seg.json' segments found in '{}'",
            args.archive_dir.display()
        ));
    }
    let report = staged_replay_dir_streaming(&args.archive_dir, args.up_to_offset)
        .map_err(|e| e.to_string())?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        // a chain that does not start at offset 1 misses every contract created before it
        if report.is_partial {
            println!(
                "4-Stage Deterministic Replay:  PARTIAL (archive starts at offset {}; earlier contracts are missing)",
                report.from_offset
            );
        } else {
            println!("4-Stage Deterministic Replay:  COMPLETE");
        }
        println!(
            "Replayed Segments / Events:    {} / {}",
            report.replayed_segments, report.replayed_events
        );
        println!("Target Offset:                 #{}", report.up_to_offset);
        println!(
            "Reconstructed Active Contracts:{}",
            report.active_contracts_count
        );
        println!(
            "ACS State SHA-256:             {} (canton-rs hash, not a Canton ACS commitment)",
            report.acs_commitment_sha256
        );
        for st in &report.stages {
            println!(
                "  stage {:<26} {:>7} us ({} items)",
                st.stage, st.elapsed_us, st.items_processed
            );
        }
    }
    Ok(())
}

fn execute_db_tui_cmd(args: DbTuiArgs) -> Result<(), String> {
    let (label, stats) = collect_unified_stats(
        args.jdbc_url.as_deref(),
        args.user.as_deref(),
        args.password.as_deref(),
        args.password_file.as_deref(),
        args.connection_init_sql.as_deref(),
        args.archive_dir.as_deref(),
    )?;
    let (segments, initial_replay) = match &args.archive_dir {
        Some(dir) => {
            let (_, metas) = verify_archive_dir_streaming(dir, None).map_err(|e| e.to_string())?;
            let rep = if !metas.is_empty() {
                staged_replay_dir_streaming(dir, None).ok()
            } else {
                None
            };
            (metas, rep)
        }
        None => (Vec::new(), None),
    };
    run_db_tui(
        label,
        args.archive_dir.as_deref(),
        stats,
        segments,
        initial_replay,
    )
}

#[cfg(test)]
mod tests;
