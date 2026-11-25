//! The official Canton 3.7.2 PostgreSQL migrations, applied the way Flyway applies them (R5 step 1, S-STORE-008).
//!
//! The migrations are the files of the Canton jar (`db/migration/canton/postgres/{stable,table_settings}`), read from the
//! fetched references and never copied or re-written: the schema a participant database has is the schema these files create,
//! and what this module adds is only the *application* of them (order, Flyway placeholders, the history table, the one
//! migration that is Java code, a repeatable migration at the end).
//!
//! [CANTON-NOTE: SEMANTICS] Flyway versions the files by name: `V<major>_<minor>__<description>.sql` is version `major.minor`
//! with the description's underscores as spaces; `R__<description>.sql` is repeatable and runs after every versioned migration,
//! which gives it a description that starts with a space when the file is named `R___...` (three underscores). Versioned
//! migrations run in numeric version order. The history row of a SQL migration carries the CRC-32 of its lines
//! ([`crate::storage::compute_flyway_checksum`]); a Java migration has type `JDBC`, the class name as its script and no checksum.
//!
//! [CANTON-NOTE: LIMITATION] Only the stable PostgreSQL migrations are applied, not `dev`.
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use postgres::Client;

use crate::storage::compute_flyway_checksum;

/// Node role for role-specific post-migration schema initialization (`U-18 ②`).
///
/// Participant and Mediator schemas are identical; Sequencer adds the initial
/// BFT orderer lower-bound check constraint `ord_metadata_output_blocks_p0_lb`
/// (`PartitionManager.scala`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Participant,
    Sequencer,
    Mediator,
}

impl NodeRole {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "participant" | "par" => Some(Self::Participant),
            "sequencer" | "seq" => Some(Self::Sequencer),
            "mediator" | "med" => Some(Self::Mediator),
            _ => None,
        }
    }
}

/// The Flyway placeholders Canton sets (see [`crate::storage::FLYWAY_PLACEHOLDERS`]).
pub const PLACEHOLDERS: [(&str, &str); 1] = crate::storage::FLYWAY_PLACEHOLDERS;

#[derive(Debug)]
pub enum MigrateError {
    Io(std::io::Error),
    Db(String),
    /// A migration this module cannot apply faithfully.
    Unsupported(String),
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read the migrations: {e}"),
            Self::Db(e) => write!(f, "database error: {e}"),
            Self::Unsupported(e) => write!(f, "unsupported migration: {e}"),
        }
    }
}

impl std::error::Error for MigrateError {}

impl From<postgres::Error> for MigrateError {
    fn from(e: postgres::Error) -> Self {
        Self::Db(e.as_db_error().map_or_else(
            || e.to_string(),
            |d| format!("{}: {}", d.code().code(), d.message()),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// `V<version>__...`: runs once, in version order.
    Versioned(Vec<u32>),
    /// `R__...`: runs after the versioned ones.
    Repeatable,
}

#[derive(Debug, Clone)]
pub struct Migration {
    pub kind: Kind,
    /// `1.1`, `6.0` ... (empty for a repeatable migration)
    pub version: String,
    pub description: String,
    /// The file name, or for a Java migration its class name.
    pub script: String,
    /// `None` for the Java migration.
    pub sql: Option<String>,
}

/// One row of `flyway_schema_history` (without the installation time and duration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    pub rank: i32,
    pub version: Option<String>,
    pub description: String,
    pub kind: String,
    pub script: String,
    pub checksum: Option<i32>,
    pub success: bool,
}

fn push_versioned_sql(
    out: &mut Vec<Migration>,
    name: &str,
    sql: String,
) -> Result<(), MigrateError> {
    let stem = name
        .strip_suffix(".sql")
        .ok_or_else(|| MigrateError::Unsupported(format!("file name {name}")))?;
    let (version, description) = parse_versioned(stem)
        .ok_or_else(|| MigrateError::Unsupported(format!("file name {name}")))?;
    let numbers = version
        .split('.')
        .map(|n| {
            n.parse::<u32>()
                .map_err(|_| MigrateError::Unsupported(format!("version of {name}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    out.push(Migration {
        kind: Kind::Versioned(numbers),
        version,
        description,
        script: name.to_string(),
        sql: Some(sql),
    });
    Ok(())
}

fn push_java_migration(out: &mut Vec<Migration>, stem: &str) -> Result<(), MigrateError> {
    let (version, description) = parse_versioned(stem)
        .ok_or_else(|| MigrateError::Unsupported(format!("class name {stem}.class")))?;
    let numbers = version
        .split('.')
        .filter_map(|n| n.parse::<u32>().ok())
        .collect();
    out.push(Migration {
        kind: Kind::Versioned(numbers),
        version,
        description,
        script: format!("db.migration.canton.postgres.stable.{stem}"),
        sql: None,
    });
    Ok(())
}

fn push_repeatable_sql(
    out: &mut Vec<Migration>,
    name: &str,
    sql: String,
) -> Result<(), MigrateError> {
    let stem = name
        .strip_suffix(".sql")
        .ok_or_else(|| MigrateError::Unsupported(format!("file name {name}")))?;
    let description = stem
        .strip_prefix("R__")
        .ok_or_else(|| MigrateError::Unsupported(format!("file name {name}")))?
        .replace('_', " ");
    out.push(Migration {
        kind: Kind::Repeatable,
        version: String::new(),
        description,
        script: name.to_string(),
        sql: Some(sql),
    });
    Ok(())
}

fn sort_migrations(out: &mut [Migration]) {
    out.sort_by(|a, b| match (&a.kind, &b.kind) {
        (Kind::Versioned(x), Kind::Versioned(y)) => x.cmp(y),
        (Kind::Versioned(_), Kind::Repeatable) => std::cmp::Ordering::Less,
        (Kind::Repeatable, Kind::Versioned(_)) => std::cmp::Ordering::Greater,
        (Kind::Repeatable, Kind::Repeatable) => a.script.cmp(&b.script),
    });
}

/// Returns the bundled official Canton 3.7.2 PostgreSQL migrations without external disk lookups.
pub fn embedded_official() -> Result<Vec<Migration>, MigrateError> {
    let mut out = Vec::new();
    for (name, sql) in crate::embedded_migrations::STABLE_SQL_FILES {
        push_versioned_sql(&mut out, name, (*sql).to_string())?;
    }
    for stem in crate::embedded_migrations::JAVA_CLASS_STEMS {
        push_java_migration(&mut out, stem)?;
    }
    for (name, sql) in crate::embedded_migrations::REPEATABLE_SQL_FILES {
        push_repeatable_sql(&mut out, name, (*sql).to_string())?;
    }
    sort_migrations(&mut out);
    Ok(out)
}

/// Reads the migrations of the unpacked Canton jar: `root` is `db/migration/canton/postgres`.
pub fn load_official(root: &Path) -> Result<Vec<Migration>, MigrateError> {
    let mut out = Vec::new();
    let stable = root.join("stable");
    let mut names: Vec<String> = std::fs::read_dir(&stable)
        .map_err(MigrateError::Io)?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    names.sort();
    for name in &names {
        if name.ends_with(".sql") {
            let sql = std::fs::read_to_string(stable.join(name)).map_err(MigrateError::Io)?;
            push_versioned_sql(&mut out, name, sql)?;
        } else if let Some(stem) = name.strip_suffix(".class") {
            // a Java migration: the class is in the jar, its code is not; the module knows the ones it implements
            push_java_migration(&mut out, stem)?;
        }
    }
    let settings = root.join("table_settings");
    if let Ok(rd) = std::fs::read_dir(&settings) {
        for e in rd.flatten() {
            let name = e.file_name().into_string().unwrap_or_default();
            if name.ends_with(".sql") {
                let sql = std::fs::read_to_string(e.path()).map_err(MigrateError::Io)?;
                push_repeatable_sql(&mut out, &name, sql)?;
            }
        }
    }
    sort_migrations(&mut out);
    Ok(out)
}

/// `V1_1__initial_views` -> (`1.1`, `initial views`).
fn parse_versioned(stem: &str) -> Option<(String, String)> {
    let rest = stem.strip_prefix('V')?;
    let (version, description) = rest.split_once("__")?;
    Some((version.replace('_', "."), description.replace('_', " ")))
}

const HISTORY_DDL: &str = r#"
CREATE TABLE "{schema}"."flyway_schema_history" (
    "installed_rank" INT NOT NULL,
    "version" VARCHAR(50),
    "description" VARCHAR(200) NOT NULL,
    "type" VARCHAR(20) NOT NULL,
    "script" VARCHAR(1000) NOT NULL,
    "checksum" INTEGER,
    "installed_by" VARCHAR(100) NOT NULL,
    "installed_on" TIMESTAMP NOT NULL DEFAULT now(),
    "execution_time" INTEGER NOT NULL,
    "success" BOOLEAN NOT NULL
);
ALTER TABLE "{schema}"."flyway_schema_history" ADD CONSTRAINT "flyway_schema_history_pk" PRIMARY KEY ("installed_rank");
CREATE INDEX "flyway_schema_history_s_idx" ON "{schema}"."flyway_schema_history" ("success");
"#;

/// Applies `migrations` to the (empty) database `client` is connected to and records them in `flyway_schema_history`.
pub fn migrate(
    client: &mut Client,
    migrations: &[Migration],
    placeholders: &[(&str, &str)],
) -> Result<Vec<HistoryRow>, MigrateError> {
    let schema = current_schema(client)?;
    client.batch_execute(&HISTORY_DDL.replace("{schema}", &schema))?;
    apply(client, migrations, placeholders, 1)
}

/// Applies `migrations` and initializes any role-specific constraints (`NodeRole::Sequencer`).
pub fn migrate_for_role(
    client: &mut Client,
    migrations: &[Migration],
    placeholders: &[(&str, &str)],
    role: NodeRole,
) -> Result<Vec<HistoryRow>, MigrateError> {
    let rows = migrate(client, migrations, placeholders)?;
    init_role_schema(client, role)?;
    Ok(rows)
}

/// Applies Canton's role-specific post-migration schema initialization (`U-18 ②`).
///
/// For `NodeRole::Sequencer`, `PartitionManager` attaches `ord_metadata_output_blocks_p0_lb`
/// (`CHECK (((bft_ts >= 1000) AND (block_number >= 0)))`) on partition `p0`.
pub fn init_role_schema(client: &mut Client, role: NodeRole) -> Result<(), MigrateError> {
    if role != NodeRole::Sequencer {
        return Ok(());
    }
    let has_partition: bool = client
        .query_one(
            "SELECT to_regclass('ord_metadata_output_blocks_p0') IS NOT NULL",
            &[],
        )?
        .get(0);
    if !has_partition {
        return Ok(());
    }
    let exists: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_constraint \
             WHERE conname = 'ord_metadata_output_blocks_p0_lb' \
             AND conrelid = 'ord_metadata_output_blocks_p0'::regclass)",
            &[],
        )?
        .get(0);
    if !exists {
        client.batch_execute(
            "ALTER TABLE ord_metadata_output_blocks_p0 \
             ADD CONSTRAINT ord_metadata_output_blocks_p0_lb \
             CHECK (bft_ts >= 1000 AND block_number >= 0)",
        )?;
    }
    Ok(())
}

/// Applies `migrations` in order, each in its own transaction with its history row, the first at rank `first_rank`.
fn apply(
    client: &mut Client,
    migrations: &[Migration],
    placeholders: &[(&str, &str)],
    first_rank: i32,
) -> Result<Vec<HistoryRow>, MigrateError> {
    let user: String = client.query_one("SELECT current_user::text", &[])?.get(0);
    let insert = format!(
        r#"INSERT INTO "{}"."flyway_schema_history"
           (installed_rank, version, description, type, script, checksum, installed_by, execution_time, success)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)"#,
        current_schema(client)?
    );
    let mut rows = Vec::new();
    for (i, m) in migrations.iter().enumerate() {
        let started = std::time::Instant::now();
        let mut tx = client.transaction()?;
        match &m.sql {
            Some(sql) => {
                tx.batch_execute(&crate::storage::replace_placeholders(sql, placeholders))?
            }
            None => apply_java(&mut tx, m)?,
        }
        let rank = first_rank + i as i32;
        let checksum = checksum_of(m, placeholders);
        let version = (!m.version.is_empty()).then(|| m.version.clone());
        let kind = if m.sql.is_some() { "SQL" } else { "JDBC" };
        tx.execute(
            &insert,
            &[
                &rank,
                &version,
                &m.description,
                &kind,
                &m.script,
                &checksum,
                &user,
                &(started.elapsed().as_millis() as i32),
            ],
        )?;
        tx.commit()?;
        rows.push(HistoryRow {
            rank,
            version,
            description: m.description.clone(),
            kind: kind.to_string(),
            script: m.script.clone(),
            checksum,
            success: true,
        });
    }
    Ok(rows)
}

/// How a node treats migrations it has not applied yet (`storage.parameters.migrate-and-start`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupMode {
    /// The default: a fresh database is migrated, anything else with a pending versioned migration is refused.
    CheckPending,
    /// `migrate-and-start = yes`: pending migrations are applied before the node starts.
    MigrateAndStart,
}

/// What a node's start did to its database.
#[derive(Debug, PartialEq, Eq)]
pub enum Startup {
    /// Migrations were applied (all of them on a fresh database).
    Migrated(Vec<HistoryRow>),
    /// Nothing to apply.
    UpToDate,
}

/// Why a node does not start on its database. The texts are the official node's (`tests/oracle/db-startup/outcomes.tsv`).
#[derive(Debug)]
pub enum StartupError {
    /// `DbMigrations.PendingMigrationError`.
    Pending(String),
    /// What Flyway refused (`FlywayException`), with its message.
    Flyway(String),
    /// The session that holds the lock could not be set up (`Failed to initialize new connection: ...`).
    LockSession(String),
    /// `DbMigrations.DatabaseVersionError`.
    Version(String),
    Migrate(MigrateError),
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending(m) | Self::Flyway(m) | Self::Version(m) => f.write_str(m),
            Self::LockSession(m) => write!(f, "Failed to initialize new connection: {m}"),
            Self::Migrate(e) => write!(f, "{e}"),
        }
    }
}

impl From<MigrateError> for StartupError {
    fn from(e: MigrateError) -> Self {
        Self::Migrate(e)
    }
}

impl From<postgres::Error> for StartupError {
    fn from(e: postgres::Error) -> Self {
        Self::Migrate(e.into())
    }
}

/// An applied history row as Flyway reads it.
struct Applied {
    rank: i32,
    version: Option<String>,
    description: String,
    checksum: Option<i32>,
    success: bool,
}

/// `1.10` > `1.9`: versions compare by their numbers.
fn version_numbers(v: &str) -> Vec<u32> {
    v.split('.').filter_map(|n| n.parse().ok()).collect()
}

/// What a node does with its database when it starts (`DbMigrations.checkAndMigrate`), on the database named `scope`.
///
/// [CANTON-NOTE: SEMANTICS] Measured on the official 3.7.2 participant (`scripts/oracle-db-startup.sh`) and read from `DbMigrations`:
/// - the whole check holds the advisory lock `NODE_MIGRATIONS` (37) of the database, so nodes that share it migrate one at a time;
/// - a database without applied migrations is migrated, unless its schema holds anything without a history table (Flyway refuses);
/// - otherwise a pending **versioned** migration refuses the start, unless `migrate-and-start` applies it;
/// - a repeatable migration whose checksum changed is applied again (a new history row), in either mode;
/// - a changed checksum or a failed row of a versioned migration is **not** looked at unless Flyway migrates (it validates then).
pub fn check_and_migrate(
    client: &mut Client,
    scope: &str,
    migrations: &[Migration],
    placeholders: &[(&str, &str)],
    mode: StartupMode,
) -> Result<Startup, StartupError> {
    check_and_migrate_as(client, scope, migrations, placeholders, mode, true)
}

/// [`check_and_migrate`] with explicit [`NodeRole`] post-initialization.
pub fn check_and_migrate_for_role(
    client: &mut Client,
    scope: &str,
    migrations: &[Migration],
    placeholders: &[(&str, &str)],
    mode: StartupMode,
    role: NodeRole,
    standard_config: bool,
) -> Result<Startup, StartupError> {
    let startup = check_and_migrate_as(
        client,
        scope,
        migrations,
        placeholders,
        mode,
        standard_config,
    )?;
    init_role_schema(client, role)?;
    Ok(startup)
}

/// [`check_and_migrate`] with the node's config said: `standard_config` is false under `canton.parameters.non-standard-config = yes`,
/// where a PostgreSQL version Canton does not expect is noted instead of refused.
pub fn check_and_migrate_as(
    client: &mut Client,
    scope: &str,
    migrations: &[Migration],
    placeholders: &[(&str, &str)],
    mode: StartupMode,
    standard_config: bool,
) -> Result<Startup, StartupError> {
    // the session that holds the lock is set up as Canton sets its lock sessions up; a server that does not know a setting is one the
    // official node does not start on either
    lock_session(client).map_err(StartupError::LockSession)?;
    let lock = crate::storage::db_lock_id(scope, crate::storage::lock_counters::NODE_MIGRATIONS);
    client.execute("SELECT pg_advisory_lock($1::int8)", &[&i64::from(lock)])?;
    let version: String = client.query_one("SHOW server_version", &[])?.get(0);
    let result = match crate::storage::check_postgres_version(&version, standard_config) {
        Err(why) => Err(StartupError::Version(why)),
        Ok(note) => {
            if let Some(note) = note {
                // [CANTON-NOTE: WHY] Routed through the crate's diagnostic sink (`S-QUAL-003`); it prints to stderr as before unless
                // `CANTON_RS_LOG` turns diagnostics off.
                crate::diag::diag_eprintln!(
                    "{} {note}",
                    if standard_config { "WARN" } else { "INFO" }
                );
            }
            check_and_migrate_locked(client, migrations, placeholders, mode)
        }
    };
    client.execute("SELECT pg_advisory_unlock($1::int8)", &[&i64::from(lock)])?;
    result
}

fn check_and_migrate_locked(
    client: &mut Client,
    migrations: &[Migration],
    placeholders: &[(&str, &str)],
    mode: StartupMode,
) -> Result<Startup, StartupError> {
    // Flyway works in the connection's current schema (`currentSchema` of the data source, the first of its search path)
    let schema = current_schema(client)?;
    let has_history: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'flyway_schema_history')",
            &[&schema],
        )?
        .get(0);
    let applied: Vec<Applied> = if has_history {
        client
            .query(
                &format!(r#"SELECT installed_rank, version, description, checksum, success FROM "{schema}"."flyway_schema_history" ORDER BY installed_rank"#),
                &[],
            )?
            .iter()
            .map(|r| Applied {
                rank: r.get(0),
                version: r.get(1),
                description: r.get(2),
                checksum: r.get(3),
                success: r.get(4),
            })
            .collect()
    } else {
        Vec::new()
    };
    if applied.is_empty() {
        if !has_history && schema_has_objects(client, &schema)? {
            return Err(StartupError::Flyway(format!(
                "Found non-empty schema(s) \"{schema}\" but no schema history table. Use baseline() or set baselineOnMigrate to true to initialize the schema history table."
            )));
        }
        if has_history {
            return Ok(Startup::Migrated(apply(
                client,
                migrations,
                placeholders,
                1,
            )?));
        }
        return Ok(Startup::Migrated(migrate(
            client,
            migrations,
            placeholders,
        )?));
    }
    // Flyway's view: the current version is the highest applied one; a versioned migration above it is pending (one below it that was
    // never applied is ignored), and a repeatable one is pending when its last applied checksum is not the file's
    let current = applied
        .iter()
        .filter_map(|a| a.version.as_deref())
        .max_by_key(|v| version_numbers(v))
        .map(str::to_string);
    let pending_versioned: Vec<&Migration> = migrations
        .iter()
        .filter(|m| matches!(m.kind, Kind::Versioned(_)))
        .filter(|m| {
            current
                .as_deref()
                .is_none_or(|c| version_numbers(&m.version) > version_numbers(c))
        })
        .collect();
    let pending_repeatable: Vec<&Migration> = migrations
        .iter()
        .filter(|m| m.kind == Kind::Repeatable)
        .filter(|m| {
            let last = applied
                .iter()
                .rev()
                .find(|a| a.version.is_none() && a.description == m.description);
            last.and_then(|a| a.checksum) != checksum_of(m, placeholders)
        })
        .collect();
    let to_apply: Vec<&Migration> = match mode {
        StartupMode::CheckPending => {
            if let Some(last) = pending_versioned.last() {
                let pending = format!(
                    "There are {} pending migrations to get to database schema version {}",
                    pending_versioned.len(),
                    last.version
                );
                return Err(StartupError::Pending(match &current {
                    Some(v) => format!("{pending}. Currently on version {v}."),
                    None => format!("No migrations have been applied yet. {pending}."),
                }));
            }
            pending_repeatable
        }
        StartupMode::MigrateAndStart => pending_versioned
            .into_iter()
            .chain(pending_repeatable)
            .collect(),
    };
    if to_apply.is_empty() {
        return Ok(Startup::UpToDate);
    }
    // Flyway validates what was applied before it migrates
    validate(&applied, migrations, placeholders)?;
    let next = applied.iter().map(|a| a.rank).max().unwrap_or(0) + 1;
    let list: Vec<Migration> = to_apply.into_iter().cloned().collect();
    Ok(Startup::Migrated(apply(client, &list, placeholders, next)?))
}

/// The checksum Flyway records for `m`: a repeatable migration's with its placeholders replaced, a versioned one's as written (see
/// [`crate::storage::flyway_file_checksum`]); none for a Java migration.
fn checksum_of(m: &Migration, placeholders: &[(&str, &str)]) -> Option<i32> {
    let sql = m.sql.as_deref()?;
    Some(match m.kind {
        Kind::Repeatable => {
            compute_flyway_checksum(&crate::storage::replace_placeholders(sql, placeholders))
        }
        Kind::Versioned(_) => compute_flyway_checksum(sql),
    })
}

/// Sets the session up as a lock session (see [`crate::storage::LOCK_SESSION_SETTINGS`]); the server's refusal as it words it.
fn lock_session(client: &mut Client) -> Result<(), String> {
    for setting in crate::storage::LOCK_SESSION_SETTINGS {
        client.batch_execute(setting).map_err(|e| {
            e.as_db_error()
                .map_or_else(|| e.to_string(), |d| format!("ERROR: {}", d.message()))
        })?;
    }
    Ok(())
}

/// Whether `schema` holds anything of someone's: a table, view, sequence or function.
fn schema_has_objects(client: &mut Client, schema: &str) -> Result<bool, postgres::Error> {
    Ok(client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1) \
             OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = $1)",
            &[&schema],
        )?
        .get(0))
}

/// The connection's current schema: where Flyway keeps its history and the unqualified objects of the migrations go.
fn current_schema(client: &mut Client) -> Result<String, postgres::Error> {
    Ok(client
        .query_one("SELECT current_schema()::text", &[])?
        .get(0))
}

/// Flyway's validation of the applied migrations against the files (before it migrates).
fn validate(
    applied: &[Applied],
    migrations: &[Migration],
    placeholders: &[(&str, &str)],
) -> Result<(), StartupError> {
    let mut problems = Vec::new();
    for a in applied {
        let Some(version) = &a.version else { continue };
        if !a.success {
            problems.push(format!(
                "Detected failed migration to version {version} ({}).\nPlease remove any half-completed changes then run repair to fix the schema history.",
                a.description
            ));
            continue;
        }
        if let Some(m) = migrations.iter().find(|m| &m.version == version) {
            let resolved = checksum_of(m, placeholders);
            if resolved != a.checksum {
                problems.push(format!(
                    "Migration checksum mismatch for migration version {version}\n-> Applied to database : {}\n-> Resolved locally    : {}\nEither revert the changes to the migration, or run repair to update the schema history.",
                    a.checksum.map_or("null".into(), |c| c.to_string()),
                    resolved.map_or("null".into(), |c| c.to_string())
                ));
            }
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(StartupError::Flyway(format!(
        "Validate failed: Migrations have failed validation\n{}\nNeed more flexibility with validation rules? Learn more: https://rd.gt/3AbJUZE",
        problems.join("\n")
    )))
}

/// The writer lock of a participant on its database (`PARTICIPANT_WRITE`): held by the session for as long as the node writes, so that two
/// nodes never write one database. Released when it is dropped (or the session ends).
///
/// [CANTON-NOTE: SEMANTICS] The official participant holds this advisory lock while it runs (measured with `scripts/oracle-db-writer.sh`,
/// `tests/oracle/db-startup/writer.tsv`); a Rust node that takes over a database takes the same lock, so it cannot write next to a JVM node.
pub struct WriterLock {
    client: Client,
    id: i32,
}

impl WriterLock {
    /// Takes the lock on the database `scope` without waiting; the refusal names who holds it.
    pub fn take(mut client: Client, scope: &str) -> Result<Self, String> {
        let id =
            crate::storage::db_lock_id(scope, crate::storage::lock_counters::PARTICIPANT_WRITE);
        lock_session(&mut client)
            .map_err(|e| format!("Failed to initialize new connection: {e}"))?;
        let took: bool = client
            .query_one("SELECT pg_try_advisory_lock($1::int8)", &[&i64::from(id)])
            .map_err(|e| e.to_string())?
            .get(0);
        if took {
            return Ok(Self { client, id });
        }
        let holder: Option<i32> = client
            .query_opt(
                "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND objid = $1::int8::oid AND granted",
                &[&i64::from(id)],
            )
            .map_err(|e| e.to_string())?
            .map(|r| r.get(0));
        Err(format!(
            "the database {scope} has a writer already: its lock {id} (PARTICIPANT_WRITE) is held by the session {}",
            holder.map_or("?".into(), |p| p.to_string())
        ))
    }

    pub fn id(&self) -> i32 {
        self.id
    }

    /// Whether this session still holds the lock. [CANTON-NOTE: SEMANTICS] Measured on the official participant across a database
    /// outage (`scripts/oracle-db-failover.sh`, `tests/oracle/db-failover/outcome.tsv`): when the locked connection fails the node
    /// logs `Failed to check database lock status ..., assuming lost` and `Lock <id> was lost`, treats the lock as gone (it must not write
    /// any more) and later rebuilds the connection. A check that cannot be answered is therefore "lost", never "still held".
    pub fn check(&mut self) -> LockState {
        match self.client.query_opt(
            "SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = $1::int8::oid AND pid = pg_backend_pid() AND granted",
            &[&i64::from(self.id)],
        ) {
            Ok(Some(_)) => LockState::Held,
            Ok(None) | Err(_) => LockState::Lost,
        }
    }

    /// Takes the lock again on a new session after it was lost (`Locked connection was lost, trying to rebuild`). Fails, naming the new
    /// holder, when another writer took the database in the meantime; this lock then stays lost.
    pub fn rebuild(&mut self, client: Client, scope: &str) -> Result<(), String> {
        let again = Self::take(client, scope)?;
        // the replaced session is gone or dead: forget its lock without trying to release it on a broken connection
        let old = std::mem::replace(self, again);
        std::mem::forget(old);
        Ok(())
    }
}

/// Returns `(successful_row_count, latest_version)` from `flyway_schema_history` in `current_schema()`.
pub fn flyway_summary(client: &mut Client) -> Result<(i64, String), String> {
    let schema = current_schema(client).map_err(|e| e.to_string())?;
    let exists: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'flyway_schema_history')",
            &[&schema],
        )
        .map_err(|e| e.to_string())?
        .get(0);
    if !exists {
        return Ok((0, "-".to_string()));
    }
    let row = client
        .query_one(
            &format!(
                "SELECT count(*), coalesce(max(version), '-') FROM \"{schema}\".\"flyway_schema_history\" WHERE success"
            ),
            &[],
        )
        .map_err(|e| e.to_string())?;
    Ok((row.get(0), row.get(1)))
}

/// Returns `(lock_id, holding_pid_if_any)` for `PARTICIPANT_WRITE` on `scope`.
pub fn writer_lock_holder(client: &mut Client, scope: &str) -> Result<(i32, Option<i32>), String> {
    let id = crate::storage::db_lock_id(scope, crate::storage::lock_counters::PARTICIPANT_WRITE);
    let holder: Option<i32> = client
        .query_opt(
            "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND objid = $1::int8::oid AND granted",
            &[&i64::from(id)],
        )
        .map_err(|e| e.to_string())?
        .map(|r| r.get(0));
    Ok((id, holder))
}

/// The state of a [`WriterLock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    Held,
    Lost,
}

impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = self.client.execute(
            "SELECT pg_advisory_unlock($1::int8)",
            &[&i64::from(self.id)],
        );
    }
}

/// The Java migrations the module implements (`S-STORE-008`, `U-18 ③`): `V6_0__reassignment_store_stakeholders`.
///
/// Matches `ReassignmentStoreStakeholdersMigration.scala`: adds `stakeholders varchar array` and
/// backfills every existing `par_reassignments` row by decoding its `Versioned(FatContractInstance)`
/// blobs into the deduplicated stakeholder party set (`maintainers ∪ non_maintainer_signatories ∪ non_signatory_stakeholders`).
fn apply_java(tx: &mut postgres::Transaction<'_>, m: &Migration) -> Result<(), MigrateError> {
    if !m.script.ends_with("V6_0__reassignment_store_stakeholders") {
        return Err(MigrateError::Unsupported(format!(
            "the Java migration {} is not implemented",
            m.script
        )));
    }
    tx.batch_execute("alter table par_reassignments add column stakeholders varchar array")?;
    let rows = tx.query(
        "SELECT target_synchronizer_idx, reassignment_id, contracts FROM par_reassignments",
        &[],
    )?;
    if rows.is_empty() {
        return Ok(());
    }
    for row in rows {
        let target_idx: i32 = row.get(0);
        let reassignment_id: String = row.get(1);
        let contracts: Vec<Vec<u8>> = row.get(2);
        let mut stakeholders: BTreeSet<String> = BTreeSet::new();
        for blob in &contracts {
            let raw = lf_eval::fat_contract::decode_fat_contract_blob(blob).map_err(|e| {
                MigrateError::Unsupported(format!(
                    "{}: failed to decode reassigned contract for reassignmentId {reassignment_id}: {e}",
                    m.script
                ))
            })?;
            if let Some(key) = &raw.key {
                stakeholders.extend(key.maintainers.iter().cloned());
            }
            stakeholders.extend(raw.non_maintainer_signatories.iter().cloned());
            stakeholders.extend(raw.non_signatory_stakeholders.iter().cloned());
        }
        let stakeholder_list: Vec<String> = stakeholders.into_iter().collect();
        tx.execute(
            "UPDATE par_reassignments SET stakeholders = $1 \
             WHERE target_synchronizer_idx = $2 AND reassignment_id = $3",
            &[&stakeholder_list, &target_idx, &reassignment_id],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_become_versions_and_descriptions() {
        assert_eq!(
            parse_versioned("V1_2__initial_views"),
            Some(("1.2".into(), "initial views".into()))
        );
        assert_eq!(
            parse_versioned("V6_0__reassignment_store_stakeholders")
                .unwrap()
                .0,
            "6.0"
        );
        assert!(parse_versioned("R__x").is_none());
    }

    #[test]
    fn placeholders_are_replaced_in_the_script_only() {
        let sql = "partition_size bigint := ${initialBftOrdererTablesPartitionSize};";
        assert_eq!(
            crate::storage::replace_placeholders(sql, &PLACEHOLDERS),
            "partition_size bigint := 1500;"
        );
    }
}
