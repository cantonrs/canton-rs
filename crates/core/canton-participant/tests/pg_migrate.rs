//! S-STORE-008 (R5 step 1): the official Canton 3.7.2 PostgreSQL migrations, applied by `canton_participant::migrate` to an empty
//! database, must give what a Canton participant that started on an empty database gave: the same Flyway history (versions,
//! descriptions, checksums, scripts) and the same schema objects (tables with their column counts, views, functions, indexes).
//! The recordings are `tests/oracle/provenance/postgres-flyway-history.tsv` and `postgres-schema-objects.tsv` (`participant_db`),
//! made from a JVM run (`scripts/oracle-up.sh`).
//!
//! Needs a PostgreSQL server (`CANTON_RS_PG_URL`, a role that may create databases) and the fetched Canton references; a missing
//! input panics. Compiled only with the `pg-tests` feature: `scripts/verify-pg-migrate.sh`.
#![cfg(feature = "pg-tests")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use canton_participant::migrate::{
    check_and_migrate, embedded_official, migrate, migrate_for_role, HistoryRow, NodeRole,
    StartupMode, PLACEHOLDERS,
};
use lf_eval::fat_contract::{encode_fat_contract, format_v12_contract_id, FatContractInput};
use lf_eval::{Value, World};
use postgres::{Client, NoTls};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn url() -> String {
    std::env::var("CANTON_RS_PG_URL").expect("CANTON_RS_PG_URL must point at a PostgreSQL server")
}

/// The recorded rows of one role, from a tsv whose first column is the role.
fn recorded(file: &str, role: &str) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(root().join("tests/oracle/provenance").join(file))
        .expect("baseline");
    text.lines()
        .skip(1)
        .map(|l| l.split('\t').map(String::from).collect::<Vec<_>>())
        .filter(|c| c[0] == role)
        .collect()
}

/// A scratch database of its own, dropped at the end.
struct Scratch {
    admin: Client,
    name: String,
}

impl Scratch {
    fn new() -> (Self, Client) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // the clock alone does not tell two tests apart (on macOS it ticks in microseconds): a counter does
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let name = format!("migtest_{}_{nanos}_{n}", std::process::id());
        let mut admin = Client::connect(&url(), NoTls).expect("admin connection");
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .expect("create database");
        // the same role and server, the scratch database
        let base = url();
        let (head, _) = base.rsplit_once('/').expect("a url with a database");
        let client = Client::connect(&format!("{head}/{name}"), NoTls).expect("scratch connection");
        (Self { admin, name }, client)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = self
            .admin
            .batch_execute(&format!("DROP DATABASE IF EXISTS {}", self.name));
    }
}

fn official() -> Vec<canton_participant::migrate::Migration> {
    embedded_official().expect("embedded official Canton 3.7.2 PG migrations")
}

#[test]
fn the_flyway_history_matches_the_recorded_participant() {
    let (_scratch, mut client) = Scratch::new();
    let rows = migrate(&mut client, &official(), &PLACEHOLDERS).expect("migrate");
    let want = recorded("postgres-flyway-history.tsv", "participant_db");
    assert_eq!(rows.len(), want.len(), "number of migrations");
    for (got, w) in rows.iter().zip(&want) {
        // role, rank, version, description, type, script, checksum, installed_by, success, run2_identical
        let expected = HistoryRow {
            rank: w[1].parse().unwrap(),
            version: (w[2] != "-").then(|| w[2].clone()),
            description: w[3].clone(),
            kind: w[4].clone(),
            script: w[5].clone(),
            checksum: (w[6] != "-").then(|| w[6].parse().unwrap()),
            success: w[8] == "t",
        };
        assert_eq!(got, &expected);
    }
    // and the table itself says the same
    let stored: Vec<(i32, Option<String>, bool)> = client
        .query("SELECT installed_rank, version, success FROM flyway_schema_history ORDER BY installed_rank", &[])
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    assert_eq!(stored.len(), want.len());
    assert!(stored.iter().all(|(_, _, ok)| *ok));
}

#[test]
fn the_schema_matches_what_a_canton_participant_created() {
    let (_scratch, mut client) = Scratch::new();
    migrate(&mut client, &official(), &PLACEHOLDERS).expect("migrate");
    // the same query as scripts/oracle-up.sh
    let rows = client
        .query(
            "SELECT 'TABLE', table_schema::text, table_name::text,
                    'columns=' || (SELECT count(*) FROM information_schema.columns c WHERE c.table_schema = t.table_schema AND c.table_name = t.table_name)
             FROM information_schema.tables t
             WHERE table_schema NOT IN ('pg_catalog', 'information_schema') AND table_type = 'BASE TABLE'
             UNION ALL
             SELECT 'VIEW', table_schema::text, table_name::text, 'view'
             FROM information_schema.views
             WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
             UNION ALL
             SELECT 'FUNCTION', routine_schema::text, routine_name::text, data_type::text
             FROM information_schema.routines
             WHERE routine_schema NOT IN ('pg_catalog', 'information_schema')
             UNION ALL
             SELECT 'INDEX', schemaname::text, indexname::text, 'table=' || tablename
             FROM pg_indexes
             WHERE schemaname NOT IN ('pg_catalog', 'information_schema')",
            &[],
        )
        .unwrap();
    let got: BTreeSet<Vec<String>> = rows
        .iter()
        .map(|r| (0..4).map(|i| r.get::<_, String>(i)).collect())
        .collect();
    let want: BTreeSet<Vec<String>> = recorded("postgres-schema-objects.tsv", "participant_db")
        .into_iter()
        .map(|c| c[1..].to_vec())
        .collect();
    assert_eq!(want.len(), 492, "the recording shrank");
    let missing: Vec<_> = want.difference(&got).take(10).collect();
    let extra: Vec<_> = got.difference(&want).take(10).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "schema differs from the participant's: {} recorded objects missing, {} extra\n  missing: {missing:?}\n  extra: {extra:?}",
        want.difference(&got).count(),
        got.difference(&want).count()
    );
}

/// `pg_dump -s` of the database `name`, the way `scripts/collect-pg-schema.sh` writes the recordings: without owners, privileges
/// or comments, with the dump's own noise dropped and runs of blank lines squeezed to one.
fn dump_schema(name: &str) -> String {
    let container = std::env::var("CANTON_RS_PG_CONTAINER")
        .expect("CANTON_RS_PG_CONTAINER names the postgres container (scripts/verify-pg-migrate.sh sets it)");
    let out = std::process::Command::new("docker")
        .args([
            "exec",
            &container,
            "pg_dump",
            "-U",
            "canton",
            "-s",
            "--no-owner",
            "--no-privileges",
            "--no-comments",
            "-d",
            name,
        ])
        .output()
        .expect("docker exec pg_dump");
    assert!(
        out.status.success(),
        "pg_dump failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut lines: Vec<&str> = Vec::new();
    let text = String::from_utf8(out.stdout).unwrap();
    for line in text.lines() {
        let dropped = line.starts_with("--")
            || line.starts_with("SET ")
            || line.starts_with("SELECT pg_catalog.set_config")
            || line.starts_with("\\restrict ")
            || line.starts_with("\\unrestrict ");
        if dropped || (line.is_empty() && lines.last().is_some_and(|l| l.is_empty())) {
            continue;
        }
        lines.push(line);
    }
    lines.join("\n") + "\n"
}

#[test]
fn the_full_schema_dump_equals_the_one_a_participant_created() {
    let (scratch, mut client) = Scratch::new();
    migrate(&mut client, &official(), &PLACEHOLDERS).expect("migrate");
    let got = dump_schema(&scratch.name);
    let want =
        std::fs::read_to_string(root().join("tests/oracle/provenance/pg-schema/participant.sql"))
            .expect("the recording (scripts/collect-pg-schema.sh --update)");
    if got != want {
        let at = got
            .lines()
            .zip(want.lines())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| got.lines().count().min(want.lines().count()));
        panic!(
            "the schema dump differs from the participant's at line {}:\n  rust: {:?}\n  jvm:  {:?}",
            at + 1,
            got.lines().nth(at),
            want.lines().nth(at)
        );
    }
}

#[test]
fn the_sequencer_and_mediator_schema_dumps_equal_the_recorded_ones() {
    for (role, file) in [
        (NodeRole::Sequencer, "sequencer.sql"),
        (NodeRole::Mediator, "mediator.sql"),
    ] {
        let (scratch, mut client) = Scratch::new();
        migrate_for_role(&mut client, &official(), &PLACEHOLDERS, role).expect("migrate_for_role");
        let got = dump_schema(&scratch.name);
        let want =
            std::fs::read_to_string(root().join("tests/oracle/provenance/pg-schema").join(file))
                .expect("role schema baseline");
        if got != want {
            let at = got
                .lines()
                .zip(want.lines())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| got.lines().count().min(want.lines().count()));
            panic!(
                "the {file} dump differs at line {}:\n  rust: {:?}\n  jvm:  {:?}",
                at + 1,
                got.lines().nth(at),
                want.lines().nth(at)
            );
        }
    }
}

#[test]
fn v6_0_backfills_reassignment_stakeholders_from_stored_fat_contract_blobs() {
    let dar = root().join("contracts/target/sample-contract.dar");
    let world = World::open(&dar).expect("open sample-contract.dar");
    let dar_meta = lf_archive::parse_dar_file(&dar).expect("parse dar");
    let pkg_id = dar_meta.main_package_id.as_str();
    let pkg_name = dar_meta
        .package_name
        .as_deref()
        .unwrap_or("sample-contract");
    let alice =
        "alice::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let bob =
        "bob::1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    let payload = Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party(alice.clone())),
            ("owner".into(), Value::Party(alice.clone())),
            ("auditor".into(), Value::Party(bob.clone())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            (
                "amount".into(),
                Value::Numeric {
                    coeff: 1_000_000_000_000_i128,
                    scale: 10,
                },
            ),
        ],
    };
    let signatories = vec![alice.clone()];
    let observers = vec![bob.clone()];
    let created_at_micros = 1_762_955_032_416_621_i64;
    let salt = [0x33u8; 32];
    let cid = format_v12_contract_id(&[0x22u8; 32], &[0x44u8; 32]);
    let blob = encode_fat_contract(
        &world,
        &FatContractInput {
            contract_id: &cid,
            package_id: pkg_id,
            package_name: pkg_name,
            module_name: "AssetHolding",
            entity_name: "AssetHolding",
            payload: &payload,
            signatories: &signatories,
            observers: &observers,
            created_at_micros,
            salt: &salt,
            key: None,
            key_maintainers: &[],
            key_hash: None,
        },
    )
    .expect("encode_fat_contract");

    let migrations = official();
    let pre_v6: Vec<_> = migrations
        .iter()
        .take_while(|m| !m.script.ends_with("V6_0__reassignment_store_stakeholders"))
        .cloned()
        .collect();
    let (scratch, mut client) = Scratch::new();
    migrate(&mut client, &pre_v6, &PLACEHOLDERS).expect("migrate pre-6.0");
    client
        .execute(
            "INSERT INTO par_reassignments \
             (target_synchronizer_idx, source_synchronizer_idx, reassignment_id, unassignment_timestamp, contracts) \
             VALUES (1, 2, 'reassignment-backfill-1', 1762955032416621, $1)",
            &[&vec![blob]],
        )
        .expect("insert pre-6.0 reassignment row");

    check_and_migrate(
        &mut client,
        &scratch.name,
        &migrations,
        &PLACEHOLDERS,
        StartupMode::MigrateAndStart,
    )
    .expect("V6_0 backfill and remaining migrations succeed");

    let stored: Vec<String> = client
        .query_one(
            "SELECT stakeholders FROM par_reassignments WHERE reassignment_id = 'reassignment-backfill-1'",
            &[],
        )
        .expect("query backfilled row")
        .get(0);
    assert_eq!(stored, vec![alice, bob]);
}

#[test]
fn official_prune_physically_deletes_paired_inactive_and_preserves_active_contracts() {
    let migrations = official();
    let (scratch, mut client) = Scratch::new();
    check_and_migrate(
        &mut client,
        &scratch.name,
        &migrations,
        &PLACEHOLDERS,
        StartupMode::MigrateAndStart,
    )
    .expect("migrations");

    let empty: &[u8] = &[];
    let trace: &[u8] = &[0x0a, 0x02, b'0', b'0'];
    let parties: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x01];
    client
        .execute(
            "INSERT INTO lapi_parameters (ledger_end, participant_id, participant_pruned_up_to_inclusive, ledger_end_sequential_id, ledger_end_string_interning_id, ledger_end_publication_time) \
             VALUES (10, 'p1', NULL, 10, 10, 1000)",
            &[],
        )
        .expect("insert lapi_parameters");

    // Three contracts: c1 archived at 4 (paired <= 5), c2 never archived (active), c3 archived at 8 (> 5)
    let c1: &[u8] = b"\x00\x01c1";
    let c2: &[u8] = b"\x00\x01c2";
    let c3: &[u8] = b"\x00\x01c3";
    let mut internals = Vec::new();
    for (idx, raw) in [c1, c2, c3].iter().enumerate() {
        let internal_id: i64 = client
            .query_one(
                "INSERT INTO par_contracts (contract_id, instance, package_id, template_id) VALUES ($1, $2, 'pkg1', 'M:T') RETURNING internal_contract_id",
                &[raw, &b"inst".as_slice()],
            )
            .expect("insert par_contracts")
            .get(0);
        internals.push(internal_id);
        client
            .execute(
                "INSERT INTO par_active_contracts (synchronizer_idx, contract_id, change, operation, ts, repair_counter) \
                 VALUES (1, $1, 'activation'::public.change_type, 'create'::public.operation_type, 100, $2)",
                &[raw, &(i64::MIN + idx as i64)],
            )
            .expect("insert par_active_contracts");
    }
    for (seq, off, internal_id, upd) in [
        (1i64, 1i64, internals[0], b"u1".as_slice()),
        (2i64, 2i64, internals[1], b"u2".as_slice()),
        (3i64, 3i64, internals[2], b"u3".as_slice()),
    ] {
        client
            .execute(
                "INSERT INTO lapi_events_activate_contract \
                 (event_offset, update_id, record_time, synchronizer_id, trace_context, event_type, event_sequential_id, node_id, additional_witnesses, representative_package_id, internal_contract_id) \
                 VALUES ($1, $2, 100, 1, $3, 1, $4, 0, $5, 1, $6)",
                &[&off, &upd, &trace, &seq, &empty, &internal_id],
            )
            .expect("insert activate");
        client
            .execute(
                "INSERT INTO lapi_filter_activate_stakeholder (event_sequential_id, template_id, party_id, first_per_sequential_id) VALUES ($1, 1, 1, true)",
                &[&seq],
            )
            .expect("insert filter_activate");
        client
            .execute(
                "INSERT INTO lapi_update_meta (update_id, event_offset, publication_time, record_time, synchronizer_id, event_sequential_id_first, event_sequential_id_last) \
                 VALUES ($1, $2, 100, 100, 1, $3, $3)",
                &[&upd, &off, &seq],
            )
            .expect("insert update_meta");
    }
    // c1 deactivated at offset 4 (seq 4), c3 deactivated at offset 8 (seq 5)
    for (seq, off, deact_seq, raw, internal_id, upd) in [
        (4i64, 4i64, 1i64, c1, internals[0], b"u4".as_slice()),
        (5i64, 8i64, 3i64, c3, internals[2], b"u5".as_slice()),
    ] {
        client
            .execute(
                "INSERT INTO lapi_events_deactivate_contract \
                 (event_offset, update_id, record_time, synchronizer_id, trace_context, event_type, event_sequential_id, node_id, deactivated_event_sequential_id, additional_witnesses, contract_id, internal_contract_id, template_id, package_id, stakeholders) \
                 VALUES ($1, $2, 100, 1, $3, 3, $4, 0, $5, $6, $7, $8, 1, 1, $9)",
                &[&off, &upd, &trace, &seq, &deact_seq, &empty, &raw, &internal_id, &parties],
            )
            .expect("insert deactivate");
        client
            .execute(
                "INSERT INTO lapi_filter_deactivate_stakeholder (event_sequential_id, template_id, party_id, first_per_sequential_id) VALUES ($1, 1, 1, true)",
                &[&seq],
            )
            .expect("insert filter_deactivate");
        client
            .execute(
                "INSERT INTO lapi_update_meta (update_id, event_offset, publication_time, record_time, synchronizer_id, event_sequential_id_first, event_sequential_id_last) \
                 VALUES ($1, $2, 100, 100, 1, $3, $3)",
                &[&upd, &off, &seq],
            )
            .expect("insert deact meta");
    }
    // Witnessed + completion + dedup at offsets 4 and 8
    for (seq, off, internal_id, raw, upd) in [
        (6i64, 4i64, internals[0], c1, b"w4".as_slice()),
        (7i64, 8i64, internals[1], c2, b"w8".as_slice()),
    ] {
        client
            .execute(
                "INSERT INTO lapi_events_various_witnessed \
                 (event_offset, update_id, record_time, synchronizer_id, trace_context, event_type, event_sequential_id, node_id, additional_witnesses, contract_id, internal_contract_id) \
                 VALUES ($1, $2, 100, 1, $3, 5, $4, 0, $5, $6, $7)",
                &[&off, &upd, &trace, &seq, &parties, &raw, &internal_id],
            )
            .expect("insert witnessed");
        client
            .execute(
                "INSERT INTO lapi_filter_various_witness (event_sequential_id, template_id, party_id, first_per_sequential_id) VALUES ($1, 1, 1, true)",
                &[&seq],
            )
            .expect("insert filter_various");
    }
    for (off, cih) in [(4i64, "hash-4"), (8i64, "hash-8")] {
        client
            .execute(
                "INSERT INTO lapi_command_completions (completion_offset, record_time, publication_time, user_id, submitters, command_id, synchronizer_id, is_transaction, trace_context) \
                 VALUES ($1, 100, 100, 1, $2, 'cmd', 1, true, $3)",
                &[&off, &parties, &trace],
            )
            .expect("insert completion");
        client
            .execute(
                "INSERT INTO par_command_deduplication (change_id_hash, user_id, command_id, act_as, offset_definite_answer, publication_time_definite_answer, trace_context_definite_answer) \
                 VALUES ($1, 'u', 'cmd', $2, $3, 100, $4)",
                &[&cih, &parties, &off, &trace],
            )
            .expect("insert dedup");
    }

    // Negative controls
    assert!(
        canton_participant::official_prune::prune_up_to(&mut client, 0)
            .expect_err("zero rejected")
            .contains("INVALID_ARGUMENT")
    );
    assert!(
        canton_participant::official_prune::prune_up_to(&mut client, 10)
            .expect_err("end rejected")
            .contains("OFFSET_OUT_OF_RANGE")
    );

    // Prune up to 5
    let report =
        canton_participant::official_prune::prune_up_to(&mut client, 5).expect("prune to 5");
    assert_eq!(report.pruned_activations, 1);
    assert_eq!(report.pruned_deactivations, 1);
    assert_eq!(report.pruned_witnessed, 1);
    assert_eq!(report.pruned_meta, 4);
    assert_eq!(report.pruned_completions, 1);
    assert_eq!(report.pruned_dedup, 1);
    assert_eq!(report.pruned_contracts, 1);
    assert_eq!(report.pruned_active_contracts, 1);

    let remaining_contracts: Vec<Vec<u8>> = client
        .query(
            "SELECT contract_id FROM par_contracts ORDER BY internal_contract_id",
            &[],
        )
        .expect("query par_contracts")
        .into_iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(remaining_contracts, vec![c2.to_vec(), c3.to_vec()]);
    let pruned_to: Option<i64> = client
        .query_one(
            "SELECT participant_pruned_up_to_inclusive FROM lapi_parameters",
            &[],
        )
        .expect("query lapi_parameters")
        .get(0);
    assert_eq!(pruned_to, Some(5));

    // Re-pruning <= 5 is a no-op; pruning at 9 under TakeoverWriter removes c3 as well while keeping c2
    let noop = canton_participant::official_prune::prune_up_to(&mut client, 5).expect("noop");
    assert_eq!(
        noop,
        canton_participant::official_prune::OfficialPruneReport::default()
    );

    let lock =
        canton_participant::migrate::WriterLock::take(client, &scratch.name).expect("writer lock");
    let base = url();
    let (head, _) = base.rsplit_once('/').expect("url base");
    let client2 = Client::connect(&format!("{head}/{}", scratch.name), NoTls).expect("reconnect");
    let mut writer = canton_participant::takeover::TakeoverWriter::from_parts(client2, lock);
    let r2 = writer.prune_up_to(9).expect("prune to 9");
    assert_eq!(r2.pruned_activations, 1);
    assert_eq!(r2.pruned_contracts, 1);
    let survivors: i64 = writer
        .client_mut()
        .query_one("SELECT COUNT(*) FROM par_contracts", &[])
        .expect("count survivors")
        .get(0);
    assert_eq!(survivors, 1);
}
