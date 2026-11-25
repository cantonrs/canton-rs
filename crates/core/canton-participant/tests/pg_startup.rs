//! G9 (AT-D01..D05, AT-D12): a node's start on a PostgreSQL database in a given state, by `canton_participant::migrate::check_and_migrate`,
//! against what the official 3.7.2 participant did on the same states (`tests/oracle/db-startup/outcomes.tsv` and `messages/`, recorded by
//! `scripts/oracle-db-startup.sh`): whether the node starts, what the database holds afterwards (the history's tail, whether migration 7.1's
//! table exists) and the words of the refusal.
//!
//! Needs a PostgreSQL server (`CANTON_RS_PG_URL`) and the fetched Canton references: `scripts/verify-pg-migrate.sh`.
#![cfg(feature = "pg-tests")]

use std::path::{Path, PathBuf};

use canton_participant::migrate::{
    check_and_migrate, embedded_official, migrate, Startup, StartupError, StartupMode, PLACEHOLDERS,
};
use postgres::{Client, NoTls};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn url() -> String {
    std::env::var("CANTON_RS_PG_URL").expect("CANTON_RS_PG_URL must point at a PostgreSQL server")
}

fn connect(db: &str) -> Client {
    let base = url();
    let (head, _) = base.rsplit_once('/').expect("a url with a database");
    Client::connect(&format!("{head}/{db}"), NoTls).expect("connection")
}

fn admin(sql: &str) {
    connect("postgres").batch_execute(sql).expect(sql);
}

const DROP_71: &str = "DROP VIEW debug.par_traffic_enforcement_correlations; DROP TABLE par_traffic_enforcement_correlations; DELETE FROM flyway_schema_history WHERE version = '7.1';";

/// How a recorded scenario prepares its database (the same as `scripts/oracle-db-startup.sh`).
enum Prep {
    /// A copy of the template (a database the node migrated), changed by the SQL.
    Template(Option<&'static str>),
    /// An empty database, changed by the SQL.
    Empty(Option<&'static str>),
    /// An empty database the node was killed on in the middle of its first migration: the migrations up to the version its history
    /// ended with (the recording says which).
    Interrupted,
    /// The database of the scenario before (the interrupted one), as that left it.
    Again,
    /// An empty database with the node's own schema `ledger` and someone else's table in `public`; the node's connection uses `ledger`.
    OwnSchema,
}

fn scenario(name: &str) -> (Prep, StartupMode) {
    use Prep::*;
    use StartupMode::*;
    let set_71 = "UPDATE flyway_schema_history SET checksum = checksum + 1 WHERE version = '7.1';";
    let fail_71 = "UPDATE flyway_schema_history SET success = false WHERE version = '7.1';";
    let set_r = "UPDATE flyway_schema_history SET checksum = checksum + 1 WHERE version IS NULL;";
    match name {
        "fresh" => (Empty(None), CheckPending),
        "pending" => (Template(Some(DROP_71)), CheckPending),
        "pending_migrate" => (Template(Some(DROP_71)), MigrateAndStart),
        "checksum" => (Template(Some(set_71)), CheckPending),
        "checksum_migrate" => (Template(Some(set_71)), MigrateAndStart),
        "failed" => (Template(Some(fail_71)), CheckPending),
        "failed_migrate" => (Template(Some(fail_71)), MigrateAndStart),
        "foreign" => (Empty(Some("CREATE TABLE someone_elses (id int);")), CheckPending),
        "repeatable" => (Template(Some(set_r)), CheckPending),
        "checksum_repeatable" => (
            Template(Some("UPDATE flyway_schema_history SET checksum = checksum + 1 WHERE version = '7.1' OR version IS NULL;")),
            CheckPending,
        ),
        "failed_repeatable" => (
            Template(Some("UPDATE flyway_schema_history SET success = false WHERE version = '7.1'; UPDATE flyway_schema_history SET checksum = checksum + 1 WHERE version IS NULL;")),
            CheckPending,
        ),
        "interrupted" => (Interrupted, CheckPending),
        "interrupted_restart" => (Again, CheckPending),
        "interrupted_migrate" => (Again, MigrateAndStart),
        "schema" => (OwnSchema, CheckPending),
        other => panic!("a recorded scenario this test does not know: {other}"),
    }
}

/// `history=` and the last 80 characters of `<version:success:checksum,...>;in=<the schemas that have a history table>`, as the recording has it.
fn history_tail(client: &mut Client) -> String {
    // a database without a history table: the recording says `no-history`
    let text: String = client
        .query_one(
            "SELECT string_agg(coalesce(version,'R') || ':' || success::text || ':' || coalesce(checksum::text,'-'), ',' ORDER BY installed_rank) FROM flyway_schema_history",
            &[],
        )
        .map(|r| r.get::<_, Option<String>>(0).unwrap_or_default())
        .unwrap_or_else(|_| "no-history".into());
    let schemas: Option<String> = client
        .query_one(
            "SELECT string_agg(table_schema, ',') FROM information_schema.tables WHERE table_name = 'flyway_schema_history'",
            &[],
        )
        .unwrap()
        .get(0);
    // the recording keeps the last 80 characters of `<history>;in=<schemas>`
    let whole = format!("{};in={}", text, schemas.unwrap_or_else(|| "none".into()));
    let tail: String = whole
        .chars()
        .rev()
        .take(80)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("history={tail}")
}

/// A connection whose current schema is `schema` (the data source's `currentSchema`).
fn connect_in(db: &str, schema: &str) -> Client {
    let base = url();
    let (head, _) = base.rsplit_once('/').expect("a url with a database");
    Client::connect(
        &format!("{head}/{db}?options=-c%20search_path%3D{schema}"),
        NoTls,
    )
    .expect("connection")
}

#[test]
fn a_node_starts_or_refuses_on_each_database_state_as_the_official_participant_did() {
    let migrations = embedded_official().expect("embedded official migrations");
    let run = format!("st{}", std::process::id());
    let tmpl = format!("{run}_tmpl");
    admin(&format!("CREATE DATABASE {tmpl}"));
    {
        let mut c = connect(&tmpl);
        match check_and_migrate(
            &mut c,
            &tmpl,
            &migrations,
            &PLACEHOLDERS,
            StartupMode::CheckPending,
        ) {
            Ok(Startup::Migrated(rows)) => assert_eq!(rows.len(), migrations.len()),
            other => panic!("an empty database is migrated: {other:?}"),
        }
    }
    let oracle = root().join("tests/oracle/db-startup");
    let recorded = std::fs::read_to_string(oracle.join("outcomes.tsv")).expect("the recording");
    let mut checked = 0;
    let mut kept: Option<String> = None;
    for line in recorded.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        let (name, state, words, history, table71) = (f[0], f[1], f[2], f[3], f[4]);
        let (prep, mode) = scenario(name);
        let mut db = format!("{run}_{name}");
        let mut c = match prep {
            Prep::Template(sql) | Prep::Empty(sql) => {
                if matches!(prep, Prep::Template(_)) {
                    admin(&format!("CREATE DATABASE {db} TEMPLATE {tmpl}"));
                } else {
                    admin(&format!("CREATE DATABASE {db}"));
                }
                let mut c = connect(&db);
                if let Some(sql) = sql {
                    c.batch_execute(sql).expect(sql);
                }
                c
            }
            Prep::Interrupted => {
                // the node was killed between two migrations: each migration is a transaction of its own, so the history ends with the last
                // one that committed and nothing of the next one is there
                let last = history
                    .split(";in=")
                    .next()
                    .unwrap()
                    .rsplit(',')
                    .next()
                    .unwrap()
                    .split(':')
                    .next()
                    .unwrap();
                let upto = migrations
                    .iter()
                    .position(|m| m.version == last)
                    .expect("a recorded version")
                    + 1;
                admin(&format!("CREATE DATABASE {db}"));
                let mut c = connect(&db);
                migrate(&mut c, &migrations[..upto], &PLACEHOLDERS)
                    .expect("the migrations before the kill");
                assert_eq!(history_tail(&mut c), history, "{name}");
                assert_eq!(state, "down", "the node was killed");
                kept = Some(db.clone());
                checked += 1;
                continue;
            }
            Prep::Again => {
                db = kept.clone().expect("the interrupted database");
                connect(&db)
            }
            Prep::OwnSchema => {
                admin(&format!("CREATE DATABASE {db}"));
                connect(&db)
                    .batch_execute(
                        "CREATE SCHEMA ledger; CREATE TABLE public.someone_elses (id int);",
                    )
                    .unwrap();
                connect_in(&db, "ledger")
            }
        };
        let outcome = check_and_migrate(&mut c, &db, &migrations, &PLACEHOLDERS, mode);
        let ours = if outcome.is_ok() { "up" } else { "down" };
        assert_eq!(ours, state, "{name}: {outcome:?}");
        // the refusal says what the node said
        match &outcome {
            Err(StartupError::Pending(m)) => assert!(
                words.contains(m.as_str()),
                "{name}: ours {m:?}, the node's {words:?}"
            ),
            Err(StartupError::Flyway(m)) => {
                let file = if name == "foreign" {
                    "foreign_db"
                } else {
                    name
                };
                let theirs =
                    std::fs::read_to_string(oracle.join("messages").join(format!("{file}.txt")))
                        .expect("Flyway's message");
                assert_eq!(m.trim_end(), theirs.trim_end(), "{name}");
            }
            Err(e) => panic!("{name}: {e}"),
            Ok(_) => {}
        }
        // and the database afterwards is what the node left
        assert_eq!(history_tail(&mut c), history, "{name}");
        let tables: i64 = c
            .query_one("SELECT count(*) FROM pg_tables WHERE tablename = 'par_traffic_enforcement_correlations'", &[])
            .unwrap()
            .get(0);
        assert_eq!(format!("table71={tables}"), table71, "{name}");
        drop(c);
        if !matches!(prep, Prep::Again) || name == "interrupted_migrate" {
            admin(&format!("DROP DATABASE {db}"));
        }
        checked += 1;
    }
    admin(&format!("DROP DATABASE {tmpl}"));
    assert!(checked >= 15, "every recorded scenario: {checked}");
}

/// AT-D01: two nodes that start on one empty database at once migrate it once; the second one waits for the first one's migration lock and
/// then finds nothing to do.
#[test]
fn two_nodes_starting_together_on_an_empty_database_migrate_it_once() {
    let migrations = embedded_official().expect("embedded official migrations");
    let db = format!("st{}_together", std::process::id());
    admin(&format!("CREATE DATABASE {db}"));
    let starts: Vec<_> = (0..2)
        .map(|_| {
            let (db, migrations) = (db.clone(), migrations.clone());
            std::thread::spawn(move || {
                let mut c = connect(&db);
                check_and_migrate(
                    &mut c,
                    &db,
                    &migrations,
                    &PLACEHOLDERS,
                    StartupMode::CheckPending,
                )
                .map(|s| matches!(s, Startup::Migrated(_)))
                .map_err(|e| e.to_string())
            })
        })
        .collect();
    let results: Vec<_> = starts.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        results.iter().filter(|r| matches!(r, Ok(true))).count(),
        1,
        "exactly one migrated: {results:?}"
    );
    assert!(results.iter().all(|r| r.is_ok()), "{results:?}");
    let rows: i64 = connect(&db)
        .query_one("SELECT count(*) FROM flyway_schema_history", &[])
        .unwrap()
        .get(0);
    assert_eq!(rows as usize, migrations.len());
    admin(&format!("DROP DATABASE {db}"));
}

/// AT-D06: on the PostgreSQL server of `CANTON_RS_PG_URL` (major version `CANTON_RS_PG_MAJOR`) a start on an empty database comes up or not
/// as the official participant did on that version, with the standard config and without (`tests/oracle/db-startup/versions.tsv`). Run by
/// `scripts/verify-pg-versions.sh`, once for each server.
#[test]
fn a_node_starts_on_a_postgres_version_as_the_official_participant_did() {
    let Ok(major) = std::env::var("CANTON_RS_PG_MAJOR") else {
        eprintln!("not run: scripts/verify-pg-versions.sh names the server's version");
        return;
    };
    let migrations = embedded_official().expect("embedded official migrations");
    let recorded = std::fs::read_to_string(root().join("tests/oracle/db-startup/versions.tsv"))
        .expect("the recording");
    let mut checked = 0;
    for line in recorded.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f[0] != major {
            continue;
        }
        let standard = f[1] == "yes";
        let db = format!("ver{}_{}", std::process::id(), f[1]);
        admin(&format!("CREATE DATABASE {db}"));
        let mut c = connect(&db);
        let outcome = canton_participant::migrate::check_and_migrate_as(
            &mut c,
            &db,
            &migrations,
            &PLACEHOLDERS,
            StartupMode::CheckPending,
            standard,
        );
        let ours = if outcome.is_ok() { "up" } else { "down" };
        println!(
            "VERSION {major} standard={} {ours} {}",
            f[1],
            outcome
                .as_ref()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
        );
        assert_eq!(
            ours, f[2],
            "PostgreSQL {major}, standard config {}: {outcome:?}",
            f[1]
        );
        if major == "13" {
            // what stops the official node there is what stops this one
            let why = outcome.unwrap_err().to_string();
            assert!(
                why.contains(
                    "unrecognized configuration parameter \"client_connection_check_interval\""
                ),
                "{why}"
            );
        }
        drop(c);
        admin(&format!("DROP DATABASE {db}"));
        checked += 1;
    }
    assert_eq!(
        checked, 2,
        "the recording has both configs for PostgreSQL {major}"
    );
}
