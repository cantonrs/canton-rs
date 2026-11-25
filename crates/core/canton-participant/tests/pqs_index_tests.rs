#![cfg(feature = "postgres")]
#![allow(clippy::unwrap_used, reason = "integration test")]
//! PostgreSQL integration tests for `canton_participant::pqs_index::PqsStore` (`REQ-PQS-SCRIBE-001`).

use std::process::Command;
use std::time::{Duration, Instant};

use canton_participant::pqs_index::PqsStore;
use serde_json::json;

struct DisposablePg {
    name: Option<String>,
    url: String,
}

impl DisposablePg {
    fn start_or_env() -> Self {
        if let Ok(url) = std::env::var("CANTON_RS_PQS_PG_TEST_URL") {
            return Self { name: None, url };
        }
        let name = format!(
            "canton-pqs-pg-test-{}-{}",
            std::process::id(),
            rand_suffix()
        );
        let run = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &name,
                "-e",
                "POSTGRES_PASSWORD=postgres",
                "-p",
                "0:5432",
                "postgres:16",
            ])
            .output()
            .expect("docker must be installed to run pqs_index_tests");
        assert!(
            run.status.success(),
            "docker run postgres:16 failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let port_out = Command::new("docker")
            .args(["port", &name, "5432/tcp"])
            .output()
            .expect("docker port");
        let port_str = String::from_utf8_lossy(&port_out.stdout);
        let host_port = port_str
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .expect("mapped postgres port")
            .trim()
            .to_string();

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let ready = Command::new("docker")
                .args(["exec", &name, "pg_isready", "-U", "postgres"])
                .output();
            if ready.is_ok_and(|o| o.status.success()) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "postgres:16 did not become ready"
            );
            std::thread::sleep(Duration::from_millis(250));
        }

        Self {
            name: Some(name),
            url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        }
    }
}

impl Drop for DisposablePg {
    fn drop(&mut self) {
        if let Some(name) = &self.name {
            let _ = Command::new("docker").args(["rm", "-fv", name]).output();
        }
    }
}

fn rand_suffix() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |d| d.as_nanos() as u64)
        % 1_000_000_007;
    nanos.wrapping_mul(131).wrapping_add(seq) % 1_000_000_007
}

fn parties() -> Vec<String> {
    vec!["bank::1".to_string()]
}

fn seed_sample_updates(store: &mut PqsStore) -> Vec<serde_json::Value> {
    store
        .ingest_packages(&[(
            "pkg-sample-1".into(),
            "sample-contract".into(),
            "1.0.0".into(),
            1,
        )])
        .unwrap();

    let u1 = json!({
        "update": {
            "Transaction": {
                "value": {
                    "updateId": "upd-1",
                    "offset": "1",
                    "recordTime": "2026-11-19T00:00:01Z",
                    "events": [{
                        "CreatedEvent": {
                            "offset": "1",
                            "contractId": "00cid1",
                            "templateId": "pkg-sample-1:AssetHolding:AssetHolding",
                            "createArgument": {
                                "bank": "bank::1",
                                "owner": "owner::1",
                                "auditor": "bank::1",
                                "assetSymbol": "USD",
                                "amount": "100.0"
                            },
                            "signatories": ["bank::1", "owner::1"],
                            "observers": ["auditor::1"]
                        }
                    }]
                }
            }
        }
    });
    assert!(store.ingest_update_json(&u1, &parties()).unwrap());

    let u2 = json!({
        "update": {
            "Transaction": {
                "value": {
                    "updateId": "upd-2",
                    "offset": "2",
                    "recordTime": "2026-11-19T00:00:02Z",
                    "events": [{
                        "CreatedEvent": {
                            "offset": "2",
                            "contractId": "00cid2",
                            "templateId": "pkg-sample-1:AssetHolding:AssetHolding",
                            "createArgument": {
                                "bank": "bank::1",
                                "owner": "owner::2",
                                "auditor": "bank::1",
                                "assetSymbol": "EUR",
                                "amount": "250.5"
                            },
                            "signatories": ["bank::1", "owner::2"],
                            "observers": []
                        }
                    }]
                }
            }
        }
    });
    assert!(store.ingest_update_json(&u2, &parties()).unwrap());

    let u3 = json!({
        "update": {
            "Transaction": {
                "value": {
                    "updateId": "upd-3",
                    "offset": "3",
                    "recordTime": "2026-11-19T00:00:03Z",
                    "events": [{
                        "ExercisedEvent": {
                            "offset": "3",
                            "nodeId": 0,
                            "contractId": "00cid1",
                            "templateId": "pkg-sample-1:AssetHolding:AssetHolding",
                            "choice": "Settle",
                            "choiceArgument": {},
                            "exerciseResult": {},
                            "actingParties": ["bank::1"],
                            "consuming": true
                        }
                    }]
                }
            }
        }
    });
    assert!(store.ingest_update_json(&u3, &parties()).unwrap());
    vec![u1, u2, u3]
}

#[test]
fn pqs_store_ingests_creates_exercises_archives_idempotently() {
    let pg = DisposablePg::start_or_env();
    let mut store = PqsStore::connect(&pg.url).unwrap();
    let seeded = seed_sample_updates(&mut store);

    // Replay at offsets <= watermark is an idempotent no-op.
    assert!(!store.ingest_update_json(&seeded[0], &parties()).unwrap());
    assert!(!store.ingest_update_json(&seeded[2], &parties()).unwrap());

    let st = store.status().unwrap();
    assert_eq!(st.watermark, 3);
    assert_eq!(st.active_contracts, 1);
    assert_eq!(st.archived_contracts, 1);
    assert_eq!(st.exercises, 1);
    assert_eq!(st.packages, 1);

    // Filter active contracts by template suffix, party, and JSONB containment.
    let active_eur = store
        .query_active(
            Some("AssetHolding:AssetHolding"),
            Some("owner::2"),
            Some(&json!({"assetSymbol": "EUR"})),
        )
        .unwrap();
    assert_eq!(active_eur.len(), 1);
    assert_eq!(active_eur[0].contract_id, "00cid2");
    assert_eq!(active_eur[0].payload["amount"], "250.5");

    let empty_usd = store
        .query_active(None, None, Some(&json!({"assetSymbol": "USD"})))
        .unwrap();
    assert!(empty_usd.is_empty());

    let history = store.query_contracts_history(Some("AssetHolding")).unwrap();
    assert_eq!(history.len(), 2);

    let exercises = store.query_exercises(None, Some("Settle")).unwrap();
    assert_eq!(exercises.len(), 1);
    assert_eq!(exercises[0].contract_id, "00cid1");
    assert!(exercises[0].consuming);
}

#[test]
fn pqs_store_prunes_archived_contracts_while_preserving_active() {
    let pg = DisposablePg::start_or_env();
    let mut store = PqsStore::connect(&pg.url).unwrap();
    seed_sample_updates(&mut store);

    let (pruned_contracts, pruned_exercises) = store.prune_archived_before(3).unwrap();
    assert_eq!(pruned_contracts, 1);
    assert_eq!(pruned_exercises, 1);

    let st = store.status().unwrap();
    assert_eq!(st.active_contracts, 1);
    assert_eq!(st.archived_contracts, 0);
    assert_eq!(st.exercises, 0);

    let remaining = store.query_active(None, None, None).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].contract_id, "00cid2");
}

#[test]
fn pqs_template_filter_matches_whole_names_only() {
    let pg = DisposablePg::start_or_env();
    let mut store = PqsStore::connect(&pg.url).unwrap();
    seed_sample_updates(&mut store);
    assert_eq!(
        store
            .query_contracts_history(Some("AssetHolding:AssetHolding"))
            .unwrap()
            .len(),
        2
    );
    assert!(store
        .query_contracts_history(Some("Asset_olding:AssetHolding"))
        .unwrap()
        .is_empty());
    assert!(store
        .query_contracts_history(Some("Holding:AssetHolding"))
        .unwrap()
        .is_empty());
}

#[test]
fn pqs_unassigned_contract_is_not_active_until_assigned() {
    let pg = DisposablePg::start_or_env();
    let mut store = PqsStore::connect(&pg.url).unwrap();
    seed_sample_updates(&mut store);
    let unassign = json!({"update": {"Reassignment": {"value": {"offset": 4, "events": [
        {"JsUnassignedEvent": {"value": {"contractId": "00cid2", "offset": 4}}}]}}}});
    assert!(store.ingest_update_json(&unassign, &parties()).unwrap());
    assert!(store.query_active(None, None, None).unwrap().is_empty());
    let created = store.query_contracts_history(None).unwrap();
    let cid2 = created.iter().find(|c| c.contract_id == "00cid2").unwrap();
    let assign = json!({"update": {"Reassignment": {"value": {"offset": 5, "events": [
        {"JsAssignmentEvent": {"createdEvent": {"contractId": "00cid2", "templateId": cid2.template_id,
            "createArgument": cid2.payload, "signatories": cid2.signatories, "observers": []}}}]}}}});
    assert!(store.ingest_update_json(&assign, &parties()).unwrap());
    assert_eq!(store.query_active(None, None, None).unwrap().len(), 1);
}
