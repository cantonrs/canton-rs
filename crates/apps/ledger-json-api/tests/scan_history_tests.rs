//! S-SPL-007: the transactions a node commits end up in the scan update history, and the scan app's HTTP API answers from it.
//!
//! The history is written as the node commits (`--scan-history`), the scan side reads the file (`canton_participant::scan_api`). The expected
//! values come from what the same commits returned through the ledger API (update ids, contract ids, template, acting parties), not from the
//! history code under test.

use canton_participant::scan_api::UpdateHistory;
use ledger_json_api::history::UpdateRecorder;
use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::service::ExecutionService;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn sample_dar_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn history_of(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("one JSON update per line"))
        .collect()
}

fn service_with_history(path: &Path) -> ExecutionService {
    let service = ExecutionService::new();
    service.load_dar(&sample_dar_path()).expect("load dar");
    service.set_update_recorder(Arc::new(UpdateRecorder::new(path, "sync::test", 0)));
    service
}

#[test]
fn a_create_and_an_exercise_are_written_as_scan_updates_and_served_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("history.jsonl");
    let service = service_with_history(&file);
    let act_as = vec!["Bank".to_string(), "Alice".to_string()];

    let created = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank":"Bank","owner":"Alice","auditor":"Auditor","assetSymbol":"USD","amount":"100.0"}),
                meta: None,
            },
        )
        .expect("create")
        .result;
    let exercised = service
        .json_exercise(
            &act_as,
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: created.contract_id.clone(),
                choice: "Transfer".into(),
                argument: json!({"newOwner":"Bank"}),
                meta: None,
            },
        )
        .expect("exercise");

    let updates = history_of(&file);
    assert_eq!(updates.len(), 2, "one update per committed transaction");

    // the create: one created event, the contract the ledger API returned
    let create = &updates[0];
    let root = create["root_event_ids"][0].as_str().unwrap();
    let event = &create["events_by_id"][root];
    assert_eq!(event["event_type"], "created_event");
    assert_eq!(event["contract_id"], created.contract_id);
    assert_eq!(event["create_arguments"]["owner"], "Alice");
    assert_eq!(event["signatories"], json!(["Alice", "Bank"]));
    assert_eq!(create["synchronizer_id"], "sync::test");

    // the exercise: the root exercised event, then the contract the choice created below it
    let exercise = &updates[1];
    let root = exercise["root_event_ids"][0].as_str().unwrap();
    let event = &exercise["events_by_id"][root];
    assert_eq!(event["event_type"], "exercised_event");
    assert_eq!(event["choice"], "Transfer");
    assert_eq!(event["contract_id"], created.contract_id);
    assert_eq!(event["consuming"], true);
    assert_eq!(event["choice_argument"]["newOwner"], "Bank");
    let child = event["child_event_ids"][0].as_str().unwrap();
    assert_eq!(
        exercise["events_by_id"][child]["event_type"],
        "created_event"
    );
    assert_eq!(
        exercise["events_by_id"][child]["create_arguments"]["owner"],
        "Bank"
    );
    let _ = exercised;

    // record times strictly increase, so the scan order is the commit order
    assert!(create["record_time"].as_str().unwrap() < exercise["record_time"].as_str().unwrap());

    // the scan app's HTTP API over that file
    let scan = UpdateHistory::new(updates.clone());
    let page = scan.handle("POST", "/api/scan/v2/updates", r#"{"page_size":10}"#);
    assert_eq!(page.status, 200, "{}", page.body);
    let page: Value = serde_json::from_str(&page.body).unwrap();
    let ids: Vec<&Value> = page["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| &u["update_id"])
        .collect();
    assert_eq!(ids, vec![&create["update_id"], &exercise["update_id"]]);
    let one = scan.handle(
        "GET",
        &format!(
            "/api/scan/v2/updates/{}",
            exercise["update_id"].as_str().unwrap()
        ),
        "",
    );
    assert_eq!(one.status, 200);
    let one: Value = serde_json::from_str(&one.body).unwrap();
    assert_eq!(&one, exercise);
}

#[test]
fn a_rejected_command_leaves_no_update_in_the_history() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("history.jsonl");
    let service = service_with_history(&file);
    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let result = service.json_exercise(
        &act_as,
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: "#999:0".into(),
            choice: "Transfer".into(),
            argument: json!({"newOwner":"Bank"}),
            meta: None,
        },
    );
    assert!(result.is_err());
    assert!(history_of(&file).is_empty());
}

#[test]
fn a_service_without_a_recorder_writes_no_history() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("history.jsonl");
    let service = ExecutionService::new();
    service.load_dar(&sample_dar_path()).expect("load dar");
    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({"bank":"Bank","owner":"Alice","auditor":"Auditor","assetSymbol":"USD","amount":"100.0"}),
                meta: None,
            },
        )
        .expect("create");
    assert!(!file.exists());
}
