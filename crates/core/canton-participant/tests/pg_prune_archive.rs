//! Real-PG integration tests for Cold Archive provenance (R-3), complete `FirstUnsafeOffsetComputation`
//! pruning safety (R-4), and `db takeover` check-before-commit ordering (R-18f).
//!
//! Needs a PostgreSQL server (`CANTON_RS_PG_URL`) and the built `canton-rs` binary for CLI takeover/archive tests.
//! Compiled only with `--features pg-tests` and executed by `scripts/verify-pg-migrate.sh`.
#![cfg(feature = "pg-tests")]

use std::path::{Path, PathBuf};
use std::process::Command;

use canton_participant::migrate::{
    check_and_migrate, embedded_official, StartupMode, PLACEHOLDERS,
};
use canton_participant::official_prune::{check_safe_to_prune, PruneVerdict};
use lf_eval::fat_contract::{encode_fat_contract, format_v12_contract_id, FatContractInput};
use lf_eval::{Value, World};
use postgres::{Client, NoTls};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn pg_url() -> String {
    std::env::var("CANTON_RS_PG_URL").expect("CANTON_RS_PG_URL must point at a PostgreSQL server")
}

fn canton_rs_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let target_debug = exe
        .parent()
        .and_then(|p| p.parent())
        .expect("target/debug dir");
    let bin = target_debug.join("canton-rs");
    assert!(
        bin.exists(),
        "canton-rs binary not found at {}; run `cargo build -p canton-rs` before running pg_prune_archive",
        bin.display()
    );
    bin
}

struct Scratch {
    admin: Client,
    name: String,
    url: String,
}

impl Scratch {
    fn new() -> (Self, Client) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let name = format!("prunetest_{}_{nanos}_{n}", std::process::id());
        let mut admin = Client::connect(&pg_url(), NoTls).expect("admin connection");
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .expect("create scratch db");
        let base = pg_url();
        let (head, _) = base.rsplit_once('/').expect("url with database");
        let url = format!("{head}/{name}");
        let mut client = Client::connect(&url, NoTls).expect("scratch connection");
        let migrations = embedded_official().expect("official migrations");
        check_and_migrate(
            &mut client,
            &name,
            &migrations,
            &PLACEHOLDERS,
            StartupMode::MigrateAndStart,
        )
        .expect("migrate scratch db");
        (Self { admin, name, url }, client)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = self
            .admin
            .batch_execute(&format!("DROP DATABASE IF EXISTS {}", self.name));
    }
}

struct SeedIds {
    lsid: &'static str,
    lsid_idx: i32,
    psid_idx: i32,
    topo_store_id: i32,
    lapi_sync_id: i32,
}

fn seed_safe_canton_db(client: &mut Client, pv: u32) -> SeedIds {
    let lsid = "sync1::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let psid = format!("{lsid}::{pv}-0");

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
    let make_blob = |salt_byte: u8, disc: u8| -> (Vec<u8>, Vec<u8>) {
        let cid_hex = format_v12_contract_id(&[salt_byte; 32], &[disc; 32]);
        let cid_bytes = hex::decode(&cid_hex).expect("hex cid");
        let blob = encode_fat_contract(
            &world,
            &FatContractInput {
                contract_id: &cid_hex,
                package_id: pkg_id,
                package_name: pkg_name,
                module_name: "AssetHolding",
                entity_name: "AssetHolding",
                payload: &payload,
                signatories: std::slice::from_ref(&alice),
                observers: std::slice::from_ref(&bob),
                created_at_micros: 1_000,
                salt: &[salt_byte; 32],
                key: None,
                key_maintainers: &[],
                key_hash: None,
            },
        )
        .expect("encode fat contract");
        (cid_bytes, blob)
    };

    // Ledger end = 6, ledger_end_publication_time = 1_000_000_000 (1000s); max_dedup = 10s
    client
        .execute(
            "INSERT INTO lapi_parameters (ledger_end, participant_id, participant_pruned_up_to_inclusive, ledger_end_sequential_id, ledger_end_string_interning_id, ledger_end_publication_time) \
             VALUES (6, 'participant1', NULL, 4, 20, 1000000000)",
            &[],
        )
        .expect("insert lapi_parameters");

    let lapi_sync_id = 1i32;
    let d_ext = format!("d|{lsid}");
    for (id, ext) in [
        (lapi_sync_id, d_ext.as_str()),
        (2, &format!("p|{alice}")),
        (3, &format!("k|{pkg_id}")),
        (4, "t|AssetHolding:AssetHolding"),
        (5, "u|user"),
    ] {
        client
            .execute(
                "INSERT INTO lapi_string_interning (internal_id, external_string) VALUES ($1, $2)",
                &[&id, &ext],
            )
            .expect("insert string_interning");
    }

    let lsid_idx: i32 = client
        .query_one(
            "INSERT INTO common_static_strings (string, source) VALUES ($1, 1) RETURNING id",
            &[&lsid],
        )
        .expect("insert static string lsid")
        .get(0);
    let psid_idx: i32 = client
        .query_one(
            "INSERT INTO common_static_strings (string, source) VALUES ($1, 2) RETURNING id",
            &[&psid],
        )
        .expect("insert static string psid")
        .get(0);
    let topo_store_id: i32 = client
        .query_one(
            "INSERT INTO common_static_strings (string, source) VALUES ($1, 3) RETURNING id",
            &[&psid],
        )
        .expect("insert static string topo store")
        .get(0);

    client
        .execute(
            "INSERT INTO par_synchronizer_connection_configs (synchronizer_alias, physical_synchronizer_id, config, status) \
             VALUES ('sync1', $1, $2, 'A')",
            &[&psid, &b"\x08\x01".as_slice()],
        )
        .expect("insert sync config");

    client
        .execute(
            "INSERT INTO par_settings (client, max_deduplication_duration) VALUES (0, $1)",
            &[&[0x08u8, 0x0A].as_slice()], // 10s
        )
        .expect("insert par_settings");

    client
        .execute(
            "INSERT INTO par_acs_running_digests_checkpoint (synchronizer_idx, change_offset, ts, checkpoint_type) \
             VALUES ($1, 6, 100000000, 0)",
            &[&lsid_idx],
        )
        .expect("insert digest checkpoint");
    client
        .execute(
            "INSERT INTO par_acs_commitment_period_watermark (synchronizer_idx, watermark_matching) VALUES ($1, 6)",
            &[&lsid_idx],
        )
        .expect("insert commitment watermark");
    client
        .execute(
            "INSERT INTO par_last_computed_acs_commitments (synchronizer_idx, ts) VALUES ($1, 100000000)",
            &[&lsid_idx],
        )
        .expect("insert last computed acs commitment");

    let empty: &[u8] = &[];
    let trace: &[u8] = &[0x0a, 0x02, b'0', b'0'];
    let parties: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x02];
    let c1_bytes = make_blob(0x11, 0x01).0;
    let c1_blob = make_blob(0x11, 0x01).1;
    let (c2_bytes, c2_blob) = make_blob(0x22, 0x02);

    let id1: i64 = client
        .query_one(
            "INSERT INTO par_contracts (contract_id, instance, package_id, template_id) VALUES ($1, $2, $3, 'AssetHolding:AssetHolding') RETURNING internal_contract_id",
            &[&c1_bytes, &c1_blob, &pkg_id],
        )
        .expect("insert c1")
        .get(0);
    let id2: i64 = client
        .query_one(
            "INSERT INTO par_contracts (contract_id, instance, package_id, template_id) VALUES ($1, $2, $3, 'AssetHolding:AssetHolding') RETURNING internal_contract_id",
            &[&c2_bytes, &c2_blob, &pkg_id],
        )
        .expect("insert c2")
        .get(0);

    client
        .execute(
            "INSERT INTO par_active_contracts (synchronizer_idx, contract_id, change, operation, ts, repair_counter) VALUES ($1, $2, 'activation'::public.change_type, 'create'::public.operation_type, 1000, -9223372036854775808)",
            &[&lsid_idx, &c1_bytes],
        )
        .expect("active c1");
    client
        .execute(
            "INSERT INTO par_active_contracts (synchronizer_idx, contract_id, change, operation, ts, repair_counter) VALUES ($1, $2, 'activation'::public.change_type, 'create'::public.operation_type, 2000, -9223372036854775807)",
            &[&lsid_idx, &c2_bytes],
        )
        .expect("active c2");

    // Offsets 1 (c1 create), 2 (c2 create), 3 (c1 deactivate), 4..=6 metadata at old record/pub times (1000..=6000)
    for (seq, off, iid, upd, rt) in [
        (1i64, 1i64, id1, b"u1".as_slice(), 1_000i64),
        (2i64, 2i64, id2, b"u2".as_slice(), 2_000i64),
    ] {
        client
            .execute(
                "INSERT INTO lapi_events_activate_contract (event_offset, update_id, record_time, synchronizer_id, trace_context, event_type, event_sequential_id, node_id, additional_witnesses, representative_package_id, internal_contract_id) \
                 VALUES ($1, $2, $3, $4, $5, 1, $6, 0, $7, 3, $8)",
                &[&off, &upd, &rt, &lapi_sync_id, &trace, &seq, &empty, &iid],
            )
            .expect("insert activate");
        client
            .execute(
                "INSERT INTO lapi_filter_activate_stakeholder (event_sequential_id, template_id, party_id, first_per_sequential_id) VALUES ($1, 4, 2, true)",
                &[&seq],
            )
            .expect("insert filter activate");
        client
            .execute(
                "INSERT INTO lapi_update_meta (update_id, event_offset, publication_time, record_time, synchronizer_id, event_sequential_id_first, event_sequential_id_last) \
                 VALUES ($1, $2, $3, $3, $4, $5, $5)",
                &[&upd, &off, &rt, &lapi_sync_id, &seq],
            )
            .expect("insert meta");
    }

    client
        .execute(
            "INSERT INTO lapi_events_deactivate_contract (event_offset, update_id, record_time, synchronizer_id, trace_context, event_type, event_sequential_id, node_id, deactivated_event_sequential_id, additional_witnesses, contract_id, internal_contract_id, template_id, package_id, stakeholders) \
             VALUES (3, $1, 3000, $2, $3, 3, 3, 0, 1, $4, $5, $6, 4, 3, $7)",
            &[&b"u3".as_slice(), &lapi_sync_id, &trace, &empty, &c1_bytes, &id1, &parties],
        )
        .expect("insert deactivate");
    client
        .execute(
            "INSERT INTO lapi_filter_deactivate_stakeholder (event_sequential_id, template_id, party_id, first_per_sequential_id) VALUES (3, 4, 2, true)",
            &[],
        )
        .expect("insert filter deactivate");
    client
        .execute(
            "INSERT INTO lapi_update_meta (update_id, event_offset, publication_time, record_time, synchronizer_id, event_sequential_id_first, event_sequential_id_last) \
             VALUES ($1, 3, 3000, 3000, $2, 3, 3)",
            &[&b"u3".as_slice(), &lapi_sync_id],
        )
        .expect("insert deact meta");

    for (seq, off, rt, upd) in [
        (4i64, 4i64, 4_000i64, b"u4".as_slice()),
        (4i64, 5i64, 5_000i64, b"u5".as_slice()),
        (4i64, 6i64, 6_000i64, b"u6".as_slice()),
    ] {
        client
            .execute(
                "INSERT INTO lapi_update_meta (update_id, event_offset, publication_time, record_time, synchronizer_id, event_sequential_id_first, event_sequential_id_last) \
                 VALUES ($1, $2, $3, $3, $4, $5, $5)",
                &[&upd, &off, &rt, &lapi_sync_id, &seq],
            )
            .expect("insert tail meta");
    }

    SeedIds {
        lsid,
        lsid_idx,
        psid_idx,
        topo_store_id,
        lapi_sync_id,
    }
}

#[test]
fn r4_criterion1_hard_migration_refuses_pruning() {
    let (_s, mut c) = Scratch::new();
    seed_safe_canton_db(&mut c, 36);
    assert_eq!(check_safe_to_prune(&mut c, 5), Ok(PruneVerdict::Safe));

    c.execute(
        "UPDATE par_synchronizer_connection_configs SET status = 'S'",
        &[],
    )
    .expect("set migrating status");
    let err = check_safe_to_prune(&mut c, 5)
        .expect_err("hard-migrating synchronizer must refuse pruning");
    assert!(err.contains("UNSAFE_TO_PRUNE"), "{err}");
}

#[test]
fn r4_criterion2_rejected_completion_in_dedup_window_blocks_pruning() {
    let (_s, mut c) = Scratch::new();
    let ids = seed_safe_canton_db(&mut c, 36);
    // publication_time = 995_000_000 >= ledger_end_publication_time(1_000_000_000) - 10_000_000 (990_000_000)
    c.execute(
        "INSERT INTO lapi_command_completions (completion_offset, record_time, publication_time, user_id, submitters, command_id, synchronizer_id, is_transaction, trace_context) \
         VALUES (2, 2500, 995000000, 5, $1, 'rej-cmd', $2, false, $3)",
        &[&[0x01u8].as_slice(), &ids.lapi_sync_id, &[0x0au8, 0x02, b'0', b'0'].as_slice()],
    )
    .expect("insert completion");
    let err = check_safe_to_prune(&mut c, 5)
        .expect_err("recent rejected completion in dedup window must block prune <= 2");
    assert!(err.contains("UNSAFE_TO_PRUNE"), "{err}");
    assert_eq!(check_safe_to_prune(&mut c, 1), Ok(PruneVerdict::Safe));
}

#[test]
fn r4_criterion5_legacy_outstanding_commitment_on_pv34_blocks_pruning() {
    let (_s, mut c) = Scratch::new();
    let ids = seed_safe_canton_db(&mut c, 34);
    c.execute(
        "INSERT INTO par_outstanding_acs_commitments (synchronizer_idx, from_exclusive, to_inclusive, counter_participant, matching_state) \
         VALUES ($1, 2000, 6000, 'PAR::counter::1220cc', 1)",
        &[&ids.lsid_idx],
    )
    .expect("insert outstanding commitment");
    // safeTick = 2000 -> first offset >= 2000 is offset 2 -> pruning at 5 must refuse
    let err = check_safe_to_prune(&mut c, 5)
        .expect_err("outstanding commitment on PV 34 must block pruning");
    assert!(err.contains("UNSAFE_TO_PRUNE"), "{err}");
    assert_eq!(check_safe_to_prune(&mut c, 1), Ok(PruneVerdict::Safe));
}

#[test]
fn r4_criterion6_in_flight_submission_blocks_pruning() {
    let (_s, mut c) = Scratch::new();
    let ids = seed_safe_canton_db(&mut c, 36);
    c.execute(
        "INSERT INTO par_in_flight_submission (change_id_hash, submission_synchronizer_id, message_id, sequencing_timeout, sequencing_time, trace_context) \
         VALUES ('h1', $1, 'm1', 2500, NULL, $2)",
        &[&ids.lsid, &[0x0au8, 0x02, b'0', b'0'].as_slice()],
    )
    .expect("insert in-flight submission");
    // earliest = 2500 -> first offset with record_time >= 2500 is offset 3 -> pruning at 5 must refuse
    let err = check_safe_to_prune(&mut c, 5)
        .expect_err("in-flight submission at 2500 must block pruning at 5");
    assert!(err.contains("UNSAFE_TO_PRUNE"), "{err}");
    assert_eq!(check_safe_to_prune(&mut c, 2), Ok(PruneVerdict::Safe));
}

#[test]
fn r4_criterion7_synchronizer_index_sequencer_timestamp_blocks_pruning() {
    let (_s, mut c) = Scratch::new();
    let ids = seed_safe_canton_db(&mut c, 36);
    c.execute(
        "INSERT INTO lapi_ledger_end_synchronizer_index (synchronizer_id, sequencer_timestamp, repair_timestamp, repair_counter, record_time) \
         VALUES ($1, 2500, NULL, NULL, 6000)",
        &[&ids.lapi_sync_id],
    )
    .expect("insert synchronizer index");
    let err = check_safe_to_prune(&mut c, 5)
        .expect_err("synchronizer index sequencer_timestamp must block pruning");
    assert!(err.contains("UNSAFE_TO_PRUNE"), "{err}");
    assert_eq!(check_safe_to_prune(&mut c, 2), Ok(PruneVerdict::Safe));
}

#[test]
fn r4_criterion8_request_journal_clean_replay_ts_blocks_pruning() {
    let (_s, mut c) = Scratch::new();
    let ids = seed_safe_canton_db(&mut c, 36);
    c.execute(
        "INSERT INTO lapi_ledger_end_synchronizer_index (synchronizer_id, sequencer_timestamp, repair_timestamp, repair_counter, record_time) \
         VALUES ($1, 5500, NULL, NULL, 5500)",
        &[&ids.lapi_sync_id],
    )
    .expect("insert sync index at 5500");
    c.execute(
        "INSERT INTO par_journal_requests (physical_synchronizer_idx, request_counter, request_state_index, request_timestamp, commit_time) \
         VALUES ($1, 1, 1, 2000, 2100), ($1, 2, 0, 3000, 6000)",
        &[&ids.psid_idx],
    )
    .expect("insert journal requests");
    let err = check_safe_to_prune(&mut c, 5)
        .expect_err("request journal cleanReplayTs must block pruning at 5");
    assert!(err.contains("UNSAFE_TO_PRUNE"), "{err}");
    assert_eq!(check_safe_to_prune(&mut c, 2), Ok(PruneVerdict::Safe));
}

#[test]
fn r4_criterion9_topology_event_crash_recovery_blocks_pruning() {
    let (_s, mut c) = Scratch::new();
    let ids = seed_safe_canton_db(&mut c, 36);
    c.execute(
        "INSERT INTO lapi_ledger_end_synchronizer_index (synchronizer_id, sequencer_timestamp, repair_timestamp, repair_counter, record_time) \
         VALUES ($1, 5500, NULL, NULL, 5500)",
        &[&ids.lapi_sync_id],
    )
    .expect("insert sync index");
    // Topology tx effective at valid_from=6000 >= rt=5500 whose sequenced time was 2500 -> offset 3
    c.execute(
        "INSERT INTO common_topology_transactions \
         (store_id, sequenced, transaction_type, namespace, identifier, mapping_key_hash, serial_counter, valid_from, batch_idx, valid_until, operation, instance, tx_hash, representative_protocol_version, is_proposal, hash_of_signatures, rejection_reason) \
         VALUES ($1, 2500, 1, 'ns', '', $2, 1, 6000, 0, NULL, 2, $2, $2, 36, false, $2, NULL)",
        &[&ids.topo_store_id, &b"hash".as_slice()],
    )
    .expect("insert topology tx");
    let err = check_safe_to_prune(&mut c, 5)
        .expect_err("not-yet-effective topology tx sequenced at 2500 must block pruning at 5");
    assert!(err.contains("UNSAFE_TO_PRUNE"), "{err}");
    assert_eq!(check_safe_to_prune(&mut c, 2), Ok(PruneVerdict::Safe));
}

fn write_secret_0600(path: &Path, content: &str) {
    std::fs::write(path, content).expect("write secret file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }
}

/// Strips URL-embedded credentials into `(redacted_url, password)` so pruning CLI calls satisfy R-18g.
fn strip_url_password(url: &str) -> (String, String) {
    let (scheme, rest) = url.split_once("://").expect("pg scheme");
    let (creds, host_db) = rest.split_once('@').expect("user:pw@host");
    let (user, pw) = creds.split_once(':').expect("user:pw");
    (format!("{scheme}://{user}@{host_db}"), pw.to_string())
}

#[test]
fn r18f_takeover_checks_prune_safety_before_committing_archive_cid() {
    let bin = canton_rs_bin();
    let (scratch, mut client) = Scratch::new();
    let _ids = seed_safe_canton_db(&mut client, 36);

    // Lower checkpoint to 2 while ledger_end is 6, so prune_offset=5 is UNSAFE_TO_PRUNE.
    client
        .execute(
            "UPDATE par_acs_running_digests_checkpoint SET change_offset = 2",
            &[],
        )
        .expect("lower digest checkpoint");
    // Ensure contract id in par_contracts exists; seed_safe_canton_db has c2 still active!
    let c2_hex: String = client
        .query_one(
            "SELECT ENCODE(contract_id, 'hex') FROM par_contracts ORDER BY internal_contract_id DESC LIMIT 1",
            &[],
        )
        .expect("c2 hex")
        .get(0);
    let alice = "alice::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    drop(client);

    let tmp = std::env::temp_dir().join(format!("canton_rs_r18f_pw_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let (redacted_url, pw) = strip_url_password(&scratch.url);
    let pw_file = tmp.join("pg.pw");
    write_secret_0600(&pw_file, &format!("{pw}\n"));

    let out = Command::new(&bin)
        .args([
            "db",
            "takeover",
            "--jdbc-url",
            &redacted_url,
            "--password-file",
            &pw_file.display().to_string(),
            "--archive-cid",
            &c2_hex,
            "--unsafe-offline-archive",
            "--submitter",
            alice,
            "--prune-offset",
            "5",
        ])
        .output()
        .expect("run canton-rs db takeover");

    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        !out.status.success(),
        "takeover with unsafe --prune-offset must fail; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("UNSAFE_TO_PRUNE"), "stderr: {stderr}");

    let mut verify = Client::connect(&scratch.url, NoTls).expect("reconnect");
    let end: i64 = verify
        .query_one("SELECT ledger_end FROM lapi_parameters", &[])
        .expect("ledger_end")
        .get(0);
    let deact_count: i64 = verify
        .query_one("SELECT COUNT(*) FROM lapi_events_deactivate_contract", &[])
        .expect("deact count")
        .get(0);
    assert_eq!(
        end, 6,
        "R-18f: ledger_end must remain 6 (not commit --archive-cid when prune check fails)"
    );
    assert_eq!(
        deact_count, 1,
        "R-18f: deactivation count must remain 1 (archive-cid must not commit)"
    );
}

#[test]
fn r3_two_step_jsonl_then_pg_prune_archive_refuses_mixed_archive_dir() {
    let bin = canton_rs_bin();
    let (scratch, mut client) = Scratch::new();
    let ids = seed_safe_canton_db(&mut client, 36);
    drop(client);

    let tmp = std::env::temp_dir().join(format!("canton_rs_r3_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let arch_dir = tmp.join("cold");
    let hist = tmp.join("history.jsonl");
    let lines: Vec<String> = (1..=2)
        .map(|o| {
            format!(
                r#"{{"offset":{o},"update_id":"u{o}","events":[{{"CreatedEvent":{{"contractId":"00{o:02}","templateId":"M:T","signatories":["Alice"],"createArgument":{{"v":{o}}}}}}}]}}"#
            )
        })
        .collect();
    std::fs::write(&hist, lines.join("\n")).expect("write history");

    let key_file = tmp.join("signer.key");
    write_secret_0600(&key_file, &"44".repeat(32));
    let (redacted_url, pw) = strip_url_password(&scratch.url);
    let pw_file = tmp.join("pg.pw");
    write_secret_0600(&pw_file, &format!("{pw}\n"));

    // Step 1: Write JSONL segment 1..=2 signed by our key with matching ids
    let st1 = Command::new(&bin)
        .args([
            "db",
            "archive",
            "--archive-dir",
            &arch_dir.display().to_string(),
            "--from-history",
            &hist.display().to_string(),
            "--up-to-offset",
            "2",
            "--participant-id",
            "participant1",
            "--synchronizer-id",
            ids.lsid,
            "--signing-key-file",
            &key_file.display().to_string(),
        ])
        .output()
        .expect("step 1 jsonl archive");
    assert!(
        st1.status.success(),
        "step 1 must succeed: {}",
        String::from_utf8_lossy(&st1.stderr)
    );

    // Step 2: Attempt --prune-after-archive up to offset 5 reusing arch_dir
    let st2 = Command::new(&bin)
        .args([
            "db",
            "archive",
            "--archive-dir",
            &arch_dir.display().to_string(),
            "--jdbc-url",
            &redacted_url,
            "--password-file",
            &pw_file.display().to_string(),
            "--up-to-offset",
            "5",
            "--prune-after-archive",
            "--signing-key-file",
            &key_file.display().to_string(),
        ])
        .output()
        .expect("step 2 pg prune archive");
    assert!(
        !st2.status.success(),
        "step 2 must refuse JSONL segment in archive dir; stdout={}",
        String::from_utf8_lossy(&st2.stdout)
    );
    let stderr2 = String::from_utf8_lossy(&st2.stderr);
    assert!(
        stderr2.contains("JSONL"),
        "expected JSONL provenance refusal, got: {stderr2}"
    );
    let segs = std::fs::read_dir(&arch_dir)
        .expect("read arch_dir")
        .filter(|e| {
            e.as_ref()
                .ok()
                .and_then(|e| e.file_name().to_str().map(|s| s.ends_with(".crs-seg.json")))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(segs, 1, "must refuse before writing a second PG segment");

    let mut verify = Client::connect(&scratch.url, NoTls).expect("reconnect");
    let pruned: Option<i64> = verify
        .query_one(
            "SELECT participant_pruned_up_to_inclusive FROM lapi_parameters",
            &[],
        )
        .expect("pruned_to")
        .get(0);
    assert_eq!(pruned, None, "PG must remain unpruned on refusal");

    // Positive control: fresh directory D2 allows PG-sourced archive & prune to offset 5 (with chained segment)
    let arch_ok = tmp.join("cold_ok");
    let ok1 = Command::new(&bin)
        .args([
            "db",
            "archive",
            "--archive-dir",
            &arch_ok.display().to_string(),
            "--jdbc-url",
            &redacted_url,
            "--password-file",
            &pw_file.display().to_string(),
            "--up-to-offset",
            "5",
            "--prune-after-archive",
            "--signing-key-file",
            &key_file.display().to_string(),
        ])
        .output()
        .expect("positive control pg prune archive");
    assert!(
        ok1.status.success(),
        "fresh PG archive + prune must succeed: stderr={}",
        String::from_utf8_lossy(&ok1.stderr)
    );
    let seg_json =
        std::fs::read_to_string(arch_ok.join("seg-000000000001-000000000005.crs-seg.json"))
            .expect("read pg segment");
    assert!(
        seg_json.contains("\"source_kind\": \"pg\""),
        "exported PG segment must commit source_kind=pg"
    );
    let pruned_after: Option<i64> = verify
        .query_one(
            "SELECT participant_pruned_up_to_inclusive FROM lapi_parameters",
            &[],
        )
        .expect("pruned_after")
        .get(0);
    assert_eq!(pruned_after, Some(5));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn r4_missing_record_time_on_pv36_refuses_pruning() {
    let (_s, mut c) = Scratch::new();
    seed_safe_canton_db(&mut c, 36);
    // Remove update metadata and completions so `lastRecordTimeBeforeOrAtSynchronizerOffset`
    // is None even on PV >= 36 with no unmatched legacy commitment rows.
    c.execute("DELETE FROM lapi_update_meta", &[])
        .expect("delete update meta");
    let err = check_safe_to_prune(&mut c, 5).expect_err(
        "missing record time at or before ledger_end on PV 36 must refuse pruning (FirstUnsafeOffsetComputation.scala:327-337)",
    );
    assert!(err.contains("UNSAFE_TO_PRUNE"), "{err}");
}

#[test]
fn r4_clean_request_journal_none_and_pv36_legacy_rows_follow_scala() {
    let (_s, mut c) = Scratch::new();
    let ids = seed_safe_canton_db(&mut c, 36);
    c.execute(
        "INSERT INTO lapi_ledger_end_synchronizer_index (synchronizer_id, sequencer_timestamp, repair_timestamp, repair_counter, record_time) \
         VALUES ($1, 5500, NULL, NULL, 5500)",
        &[&ids.lapi_sync_id],
    )
    .expect("insert sync index at 5500");
    // All request journal rows are strictly newer than record_time 5500 -> cleanRequestTimestamp = None
    // -> Ordering[Option[Ts]].min(None, _) = None (no cleanReplayTs restriction).
    c.execute(
        "INSERT INTO par_journal_requests (physical_synchronizer_idx, request_counter, request_state_index, request_timestamp, commit_time) \
         VALUES ($1, 1, 1, 6000, 6100)",
        &[&ids.psid_idx],
    )
    .expect("insert request newer than record_time");
    // Stale legacy unmatched commitment on PV >= 36 is ignored under OnNewProtocolVersions.
    c.execute(
        "INSERT INTO par_outstanding_acs_commitments (synchronizer_idx, from_exclusive, to_inclusive, counter_participant, matching_state) \
         VALUES ($1, 2000, 6000, 'PAR::counter::1220cc', 1)",
        &[&ids.lsid_idx],
    )
    .expect("insert stale legacy row on pv 36");
    assert_eq!(
        check_safe_to_prune(&mut c, 5),
        Ok(PruneVerdict::Safe),
        "PV 36 with clean_ts=None in request journal and stale legacy row must allow safe prune"
    );
}
