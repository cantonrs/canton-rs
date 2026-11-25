//! Real PostgreSQL integration tests for `enable_official_writes` auxiliary tables
//! (`par_dar_packages`, `par_command_deduplication`, `deduplication_offset`,
//! `par_fresh_submitted_transaction`, monotonic `par_active_contracts.repair_counter`)
//! and `official_prune` integration via `POST /v2/admin/prune` (`U-17`, `U-30`, `U-50`).
#![cfg(all(feature = "pg-tests", feature = "protocol"))]
#![allow(clippy::unwrap_used, reason = "PG integration test")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use canton_participant::migrate::{check_and_migrate, StartupMode, PLACEHOLDERS};
use canton_participant::node::Node;
use canton_participant::pgconn::{self, PgTarget};
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use canton_participant::topology_wire::ParticipantIdentity;
use ledger_json_api::protocol::NodeCommitter;
use ledger_json_api::{dispatch_request, ExecutionService, HttpRequest};
use postgres::{Client, NoTls};
use serde_json::{json, Value};

fn pg_url() -> String {
    std::env::var("CANTON_RS_PG_URL").expect("CANTON_RS_PG_URL must point at a PostgreSQL server")
}

struct ScratchDb {
    admin_url: String,
    name: String,
    target: PgTarget,
}

impl ScratchDb {
    fn create_db(seed_official_rows: bool, run_migrations: bool) -> Self {
        let base = pg_url();
        let (head, _) = base.rsplit_once('/').expect("url with db");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("offprune_{}_{nanos}", std::process::id());
        let mut admin = Client::connect(&base, NoTls).expect("admin pg connect");
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .expect("create db");
        let db_url = format!("{head}/{name}");
        if run_migrations {
            let mut client = Client::connect(&db_url, NoTls).expect("scratch pg connect");
            let migrations = canton_participant::migrate::embedded_official().expect("migrations");
            check_and_migrate(
                &mut client,
                &name,
                &migrations,
                &PLACEHOLDERS,
                StartupMode::MigrateAndStart,
            )
            .expect("migrate");
            if seed_official_rows {
                client
                    .execute(
                        "INSERT INTO lapi_parameters (ledger_end, participant_id, ledger_end_sequential_id, ledger_end_string_interning_id, ledger_end_publication_time) \
                         VALUES (NULL, 'rust-test-par::1220aa', NULL, 0, NULL)",
                        &[],
                    )
                    .unwrap();
                client
                    .execute(
                        "INSERT INTO lapi_post_processing_end (post_processing_end) VALUES (0)",
                        &[],
                    )
                    .unwrap();
                client
                    .execute(
                        "INSERT INTO common_static_strings (string, source) VALUES ('testsync::1220bb', 1)",
                        &[],
                    )
                    .unwrap();
            }
        }
        let target = PgTarget::from_url_or_jdbc(&db_url, None, None, None).unwrap();
        Self {
            admin_url: base,
            name,
            target,
        }
    }

    fn new() -> Self {
        Self::create_db(true, true)
    }

    fn new_unseeded() -> Self {
        Self::create_db(false, true)
    }

    fn new_blank() -> Self {
        Self::create_db(false, false)
    }
}

impl Drop for ScratchDb {
    fn drop(&mut self) {
        if let Ok(mut admin) = Client::connect(&self.admin_url, NoTls) {
            let _ = admin.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ));
        }
    }
}

fn boot_node(dar: &Path) -> Node {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = canton_sequencer_server::new_synchronizer_with_groups("testsync", "ts1", 1);
    let served = config.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(canton_sequencer_server::serve(address, served))
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let url = format!("http://{address}");
    let physical = config.physical_synchronizer_id();
    let identity = ParticipantIdentity::generate("offpg");
    let mut client = SequencerConnect::connect(&url).unwrap();
    client
        .register_onboarding(
            &identity.member(),
            &physical,
            identity.onboarding_transactions(&format!(
                "{}::{}",
                config.name, config.namespace_fingerprint
            )),
        )
        .unwrap();
    let challenge = client.challenge(&identity.member(), &[37]).unwrap();
    let sig = identity
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = client
        .authenticate(&identity.member(), &challenge.nonce, sig)
        .unwrap();
    std::thread::sleep(Duration::from_millis(600));
    let setup = client
        .subscribe(
            &identity.member(),
            &physical,
            &token,
            Some(0),
            8,
            Duration::from_secs(5),
        )
        .unwrap();
    let cursor = canton_participant::sequencing_wire::decode_delivered(setup.last().unwrap())
        .unwrap()
        .timestamp_micros;
    Node::open(identity, client, token, &physical, dar, cursor).expect("open node")
}

#[test]
fn official_writes_populate_auxiliary_tables_and_prune_physically_deletes_rows() {
    let scratch = ScratchDb::new();
    let dar_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar");
    let dar_bytes = std::fs::read(&dar_path).unwrap();

    let svc = Arc::new(ExecutionService::new());
    svc.set_max_dedup(Duration::from_secs(0));
    svc.set_committer(Arc::new(NodeCommitter::new(
        boot_node(&dar_path),
        "sample-contract",
        Duration::from_secs(20),
    )));
    ledger_json_api::official::enable_official_writes(&svc, &scratch.target, &[])
        .expect("enable official writes");

    let post_json = |path: &str, body: Value| -> (u16, Value) {
        let mut headers = HashMap::new();
        headers.insert("content-type".into(), "application/json".into());
        let resp = dispatch_request(
            &svc,
            &HttpRequest {
                method: "POST".into(),
                path: path.into(),
                query_params: HashMap::new(),
                headers,
                body: serde_json::to_vec(&body).unwrap(),
            },
        );
        (
            resp.status,
            serde_json::from_slice(&resp.body).unwrap_or(Value::Null),
        )
    };

    // Upload DAR via /v2/dars -> par_dar_packages must be populated
    let dar_resp = dispatch_request(
        &svc,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/dars".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: dar_bytes,
        },
    );
    assert_eq!(dar_resp.status, 200);

    let (st_p, party_resp) = post_json(
        "/v2/parties",
        json!({"partyIdHint": "offAlice", "identityProviderId": ""}),
    );
    assert_eq!(st_p, 200, "{party_resp}");
    let alice = party_resp["partyDetails"]["party"]
        .as_str()
        .unwrap()
        .to_string();

    let mut cids = Vec::new();
    let mut offsets = Vec::new();
    for sym in ["USD", "EUR"] {
        let (st, b) = post_json(
            "/v2/commands/submit-and-wait-for-transaction",
            json!({
                "commands": {
                    "commands": [{
                        "CreateCommand": {
                            "templateId": "#sample-contract:AssetHolding:AssetHolding",
                            "createArguments": {
                                "bank": alice, "owner": alice, "auditor": alice,
                                "assetSymbol": sym, "amount": "10.0"
                            }
                        }
                    }],
                    "commandId": format!("aux-{sym}"),
                    "userId": "participant_admin",
                    "actAs": [alice]
                }
            }),
        );
        assert_eq!(st, 200, "{b}");
        cids.push(
            b["transaction"]["events"][0]["CreatedEvent"]["contractId"]
                .as_str()
                .unwrap()
                .to_string(),
        );
        offsets.push(b["transaction"]["offset"].as_i64().unwrap());
    }
    // Archive first contract and trigger a duplicate command rejection for deduplication_offset check
    let (st_arch, b_arch) = post_json(
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "ExerciseCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "contractId": cids[0],
                        "choice": "Archive",
                        "choiceArgument": {}
                    }
                }],
                "commandId": "aux-arch",
                "userId": "participant_admin",
                "actAs": [alice]
            }
        }),
    );
    assert_eq!(st_arch, 200, "{b_arch}");
    let arch_off = b_arch["transaction"]["offset"].as_i64().unwrap();

    // Verify PG auxiliary writes
    let mut check_client = pgconn::connect(&scratch.target).unwrap();
    let dar_pkg_cnt: i64 = check_client
        .query_one("SELECT COUNT(*) FROM par_dar_packages", &[])
        .unwrap()
        .get(0);
    assert!(dar_pkg_cnt >= 1, "par_dar_packages must be populated");

    let dedup_cnt: i64 = check_client
        .query_one("SELECT COUNT(*) FROM par_command_deduplication", &[])
        .unwrap()
        .get(0);
    assert_eq!(dedup_cnt, 3);

    let fresh_cnt: i64 = check_client
        .query_one("SELECT COUNT(*) FROM par_fresh_submitted_transaction", &[])
        .unwrap()
        .get(0);
    assert_eq!(fresh_cnt, 3);

    let counters: Vec<i64> = check_client
        .query(
            "SELECT repair_counter FROM par_active_contracts ORDER BY repair_counter ASC",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(counters, vec![i64::MIN, i64::MIN + 1, i64::MIN + 2]);

    // Re-submit the same commandId once outside the dedup window (max_dedup = 0):
    // lapi_command_completions.deduplication_offset must carry prior offset_definite_answer.
    let (st_dup, dup_body) = post_json(
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": {
                            "bank": alice, "owner": alice, "auditor": alice,
                            "assetSymbol": "USD2", "amount": "10.0"
                        }
                    }
                }],
                "commandId": "aux-USD",
                "userId": "participant_admin",
                "actAs": [alice],
                "deduplicationPeriod": { "DeduplicationOffset": { "value": offsets[0] } }
            }
        }),
    );
    assert_eq!(st_dup, 200, "{dup_body}");
    let dup_off: i64 = check_client
        .query_one(
            "SELECT deduplication_offset FROM lapi_command_completions WHERE command_id = 'aux-USD' ORDER BY completion_offset DESC LIMIT 1",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        dup_off, offsets[0],
        "resubmitted completion must record prior definite answer offset"
    );

    // Trigger one more create so arch_off < ledger_end, then prune up to arch_off
    let (st_tail, _) = post_json(
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": {
                            "bank": alice, "owner": alice, "auditor": alice,
                            "assetSymbol": "GBP", "amount": "1.0"
                        }
                    }
                }],
                "commandId": "aux-tail",
                "userId": "participant_admin",
                "actAs": [alice]
            }
        }),
    );
    assert_eq!(st_tail, 200);

    let (st_prune, prune_body) = post_json("/v2/admin/prune", json!({ "pruneUpTo": arch_off }));
    assert_eq!(st_prune, 200, "{prune_body}");

    let surviving_cids: i64 = check_client
        .query_one("SELECT COUNT(*) FROM par_contracts", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        surviving_cids, 3,
        "only cids[0] is evicted while EUR, USD2, and GBP survive"
    );
    let evicted_present: bool = check_client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM par_contracts WHERE contract_id = $1)",
            &[&hex::decode(&cids[0]).unwrap()],
        )
        .unwrap()
        .get(0);
    assert!(
        !evicted_present,
        "cids[0] must be physically evicted from PG"
    );
    let pruned_param: Option<i64> = check_client
        .query_one(
            "SELECT participant_pruned_up_to_inclusive FROM lapi_parameters",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(pruned_param, Some(arch_off));
}

#[test]
fn official_writes_bootstrap_empty_migrated_database_and_roundtrips_adopt() {
    let blank = ScratchDb::new_blank();
    assert!(
        !ledger_json_api::official::has_official_schema(&blank.target).unwrap(),
        "blank unmigrated DB must not report official schema"
    );

    let unseeded = ScratchDb::new_unseeded();
    assert!(
        ledger_json_api::official::has_official_schema(&unseeded.target).unwrap(),
        "migrated empty DB must report official schema"
    );
    assert!(
        !ledger_json_api::official::has_official_database(&unseeded.target).unwrap(),
        "migrated empty DB must not yet report populated lapi_parameters"
    );

    // Negative control: read-only adopt must still reject an unpopulated migrated DB.
    let ro_svc = Arc::new(ExecutionService::new());
    let ro_err = ledger_json_api::official::adopt_official_database(&ro_svc, &unseeded.target)
        .err()
        .expect("read-only adopt on unseeded DB must fail");
    assert!(
        ro_err.contains("lapi_parameters has no row"),
        "unexpected error: {ro_err}"
    );

    let dar_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar");
    let svc = Arc::new(ExecutionService::new());
    svc.load_dar(&dar_path).expect("preload --dar");
    svc.set_committer(Arc::new(NodeCommitter::new(
        boot_node(&dar_path),
        "sample-contract",
        Duration::from_secs(20),
    )));
    ledger_json_api::official::enable_official_writes(&svc, &unseeded.target, &[])
        .expect("enable official writes on unseeded DB");
    assert!(
        ledger_json_api::official::has_official_database(&unseeded.target).unwrap(),
        "enable_official_writes must bootstrap lapi_parameters"
    );

    let post_json = |path: &str, body: Value| -> (u16, Value) {
        let mut headers = HashMap::new();
        headers.insert("content-type".into(), "application/json".into());
        let resp = dispatch_request(
            &svc,
            &HttpRequest {
                method: "POST".into(),
                path: path.into(),
                query_params: HashMap::new(),
                headers,
                body: serde_json::to_vec(&body).unwrap(),
            },
        );
        (
            resp.status,
            serde_json::from_slice(&resp.body).unwrap_or(Value::Null),
        )
    };

    let (st_p, p_body) = post_json(
        "/v2/parties",
        json!({ "partyIdHint": "emptyAlice", "identityProviderId": "" }),
    );
    assert_eq!(st_p, 200, "{p_body}");
    let alice = p_body["partyDetails"]["party"]
        .as_str()
        .unwrap()
        .to_string();

    let (st_c, c_body) = post_json(
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": {
                            "bank": alice, "owner": alice, "auditor": alice,
                            "assetSymbol": "USD", "amount": "25.0"
                        }
                    }
                }],
                "commandId": "empty-create-1",
                "userId": "participant_admin",
                "actAs": [alice]
            }
        }),
    );
    assert_eq!(st_c, 200, "{c_body}");

    // Read-only adopt into a brand-new ExecutionService must recover party, DAR, and contract.
    let restarted = Arc::new(ExecutionService::new());
    let adopted = ledger_json_api::official::adopt_official_database(&restarted, &unseeded.target)
        .expect("read-only adopt after --official-write");
    assert!(!adopted.dars.is_empty(), "preloaded DAR must be persisted");
    assert!(
        !adopted.instances.is_empty(),
        "created contract must be persisted"
    );
    let parties_resp = dispatch_request(
        &restarted,
        &HttpRequest {
            method: "GET".into(),
            path: "/v2/parties".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        },
    );
    assert_eq!(parties_resp.status, 200);
    let pj: Value = serde_json::from_slice(&parties_resp.body).unwrap();
    let party_ids: Vec<&str> = pj["partyDetails"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["party"].as_str())
        .collect();
    assert!(party_ids.contains(&alice.as_str()), "{pj}");
}
