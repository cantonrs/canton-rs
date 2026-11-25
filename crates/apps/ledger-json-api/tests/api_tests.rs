use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use ledger_json_api::http::start_test_server;
use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::service::{ApiError, ExecutionService};

fn sample_holding_payload() -> serde_json::Value {
    serde_json::json!({
        "bank": "Bank",
        "owner": "Alice",
        "auditor": "Auditor",
        "assetSymbol": "USD",
        "amount": "100.0"
    })
}

#[test]
fn test_template_id_parsing_and_display() {
    let tid = TemplateId::asset_holding();
    assert_eq!(
        tid.to_string(),
        "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2:AssetHolding:AssetHolding"
    );

    let parsed: TemplateId = tid.to_string().parse().expect("parse template id");
    assert_eq!(parsed, tid);

    let parsed_short: TemplateId = "AssetHolding:AssetHolding".parse().expect("parse short");
    assert_eq!(parsed_short.package_id, "");
    assert_eq!(parsed_short.module_name, "AssetHolding");
    assert_eq!(parsed_short.entity_name, "AssetHolding");
    assert_eq!(parsed_short.to_string(), "AssetHolding:AssetHolding");

    let parsed_entity: TemplateId = "Registry".parse().expect("parse entity");
    assert_eq!(parsed_entity.package_id, "");
    assert_eq!(parsed_entity.module_name, "");
    assert_eq!(parsed_entity.entity_name, "Registry");
    assert_eq!(parsed_entity.to_string(), "Registry");
}

#[test]
fn test_create_asset_holding_via_json_api() {
    let service = ExecutionService::new();
    let req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(),
        meta: None,
    };

    // Both Bank and Alice must be in act_as
    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let res = service.json_create(&act_as, req).expect("create success");

    assert_eq!(res.status, 200);
    assert_eq!(res.result.contract_id, "#0:0");
    assert_eq!(res.result.signatories, vec!["Bank", "Alice"]);
    assert_eq!(res.result.observers, vec!["Auditor"]);
    assert_eq!(
        res.result.payload.get("amount").unwrap().as_str().unwrap(),
        "100.0"
    );
}

#[test]
fn test_create_unauthorized_rejection() {
    let service = ExecutionService::new();
    let req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(),
        meta: None,
    };

    // Only Alice authorized, missing Bank -> MUST FAIL
    let act_as = vec!["Alice".to_string()];
    let err = service
        .json_create(&act_as, req.clone())
        .expect_err("should fail authorization");

    match err {
        ApiError::Unauthorized(msg) => {
            assert!(msg.contains("requires authorizers"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }

    // Only Bank authorized, missing Alice -> MUST FAIL
    let act_as_bank = vec!["Bank".to_string()];
    let err_bank = service
        .json_create(&act_as_bank, req)
        .expect_err("should fail authorization");
    match err_bank {
        ApiError::Unauthorized(_) => {}
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[test]
fn test_create_precondition_violation() {
    let service = ExecutionService::new();
    let mut payload = sample_holding_payload();
    payload["amount"] = serde_json::json!("0.0");

    let req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload,
        meta: None,
    };

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let err = service
        .json_create(&act_as, req)
        .expect_err("zero amount must violate precondition");

    match err {
        ApiError::PreconditionFailed(_) => {}
        other => panic!("expected PreconditionFailed, got {other:?}"),
    }
}

#[test]
fn test_exercise_transfer_choice() {
    let service = ExecutionService::new();
    let create_req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(),
        meta: None,
    };

    let act_as_create = vec!["Bank".to_string(), "Alice".to_string()];
    let create_resp = service
        .json_create(&act_as_create, create_req)
        .expect("create");
    let cid = create_resp.result.contract_id;

    // Alice transfers back to Bank (custodian redemption) -> Valid authorizers
    let exercise_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid.clone(),
        choice: "Transfer".to_string(),
        argument: serde_json::json!({ "newOwner": "Bank" }),
        meta: None,
    };

    let act_as_alice = vec!["Alice".to_string()];
    let exercise_resp = service
        .json_exercise(&act_as_alice, exercise_req)
        .expect("exercise transfer");

    assert_eq!(exercise_resp.status, 200);
    assert_eq!(exercise_resp.result.events.len(), 2);

    match &exercise_resp.result.events[0] {
        JsonEvent::Archived(archived) => {
            assert_eq!(archived.contract_id, cid);
        }
        _ => panic!("first event should be archived"),
    }

    match &exercise_resp.result.events[1] {
        JsonEvent::Created(created) => {
            assert_eq!(created.contract_id, "#1:0");
            assert_eq!(
                created.payload.get("owner").unwrap().as_str().unwrap(),
                "Bank"
            );
            assert_eq!(
                created.payload.get("amount").unwrap().as_str().unwrap(),
                "100.0"
            );
            assert_eq!(created.signatories, vec!["Bank", "Bank"]);
        }
        _ => panic!("second event should be created"),
    }

    // Attempting to consume old contract again must return ContractNotActive
    let re_exercise = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid,
        choice: "Transfer".to_string(),
        argument: serde_json::json!({ "newOwner": "Bank" }),
        meta: None,
    };
    let err = service
        .json_exercise(&act_as_alice, re_exercise)
        .expect_err("double spend should fail");
    match err {
        ApiError::ContractNotActive(_) => {}
        other => panic!("expected ContractNotActive, got {other:?}"),
    }
}

#[test]
fn test_exercise_transfer_unauthorized_controller() {
    let service = ExecutionService::new();
    let create_req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(),
        meta: None,
    };

    let act_as_create = vec!["Bank".to_string(), "Alice".to_string()];
    let create_resp = service
        .json_create(&act_as_create, create_req)
        .expect("create");
    let cid = create_resp.result.contract_id;

    // Bank tries to exercise Transfer (only Alice is controller) -> MUST FAIL
    let exercise_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid.clone(),
        choice: "Transfer".to_string(),
        argument: serde_json::json!({ "newOwner": "Bank" }),
        meta: None,
    };

    let act_as_bank = vec!["Bank".to_string()];
    let err = service
        .json_exercise(&act_as_bank, exercise_req)
        .expect_err("bank is not controller of transfer");
    match err {
        ApiError::Unauthorized(msg) => {
            assert!(msg.contains("requires controller Alice"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }

    // Alice tries to transfer to Auditor (Auditor did not authorize new contract creation) -> MUST FAIL
    let exercise_auditor = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid,
        choice: "Transfer".to_string(),
        argument: serde_json::json!({ "newOwner": "Auditor" }),
        meta: None,
    };
    let act_as_alice = vec!["Alice".to_string()];
    let err_auditor = service
        .json_exercise(&act_as_alice, exercise_auditor)
        .expect_err("transfer to non-authorizer must fail");
    assert!(matches!(err_auditor, ApiError::Ledger(_)));
}

#[test]
fn test_exercise_split_transfer_choice() {
    let service = ExecutionService::new();
    let create_req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(), // 100.0
        meta: None,
    };

    let act_as_create = vec!["Bank".to_string(), "Alice".to_string()];
    let create_resp = service
        .json_create(&act_as_create, create_req)
        .expect("create");
    let cid = create_resp.result.contract_id;

    // Alice split-transfers 25.0 to Bank (custodian)
    let exercise_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid,
        choice: "SplitTransfer".to_string(),
        argument: serde_json::json!({
            "recipient": "Bank",
            "transferAmount": "25.0"
        }),
        meta: None,
    };

    let act_as_alice = vec!["Alice".to_string()];
    let exercise_resp = service
        .json_exercise(&act_as_alice, exercise_req)
        .expect("split transfer");

    assert_eq!(exercise_resp.result.events.len(), 3); // 1 archived, 2 created

    // Check moved contract (to Bank, 25.0)
    match &exercise_resp.result.events[1] {
        JsonEvent::Created(moved) => {
            assert_eq!(moved.contract_id, "#1:0");
            assert_eq!(moved.payload["owner"], "Bank");
            assert_eq!(moved.payload["amount"], "25.0");
        }
        _ => panic!("event 1 should be created"),
    }

    // Check remaining contract (left for Alice, 75.0)
    match &exercise_resp.result.events[2] {
        JsonEvent::Created(left) => {
            assert_eq!(left.contract_id, "#2:0");
            assert_eq!(left.payload["owner"], "Alice");
            assert_eq!(left.payload["amount"], "75.0");
        }
        _ => panic!("event 2 should be created"),
    }

    // Split to Auditor should fail authorization
    let split_auditor = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: "#2:0".to_string(),
        choice: "SplitTransfer".to_string(),
        argument: serde_json::json!({
            "recipient": "Auditor",
            "transferAmount": "10.0"
        }),
        meta: None,
    };
    let err = service
        .json_exercise(&act_as_alice, split_auditor)
        .expect_err("split to non-authorizer must fail");
    assert!(matches!(err, ApiError::Ledger(_)));
}

#[test]
fn test_exercise_settle_choice() {
    let service = ExecutionService::new();
    let create_req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(),
        meta: None,
    };

    let act_as_create = vec!["Bank".to_string(), "Alice".to_string()];
    let create_resp = service
        .json_create(&act_as_create, create_req)
        .expect("create");
    let cid = create_resp.result.contract_id;

    // Alice cannot settle (controller is Bank) -> MUST FAIL
    let exercise_alice = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid.clone(),
        choice: "Settle".to_string(),
        argument: serde_json::json!({}),
        meta: None,
    };
    let act_as_alice = vec!["Alice".to_string()];
    let err = service
        .json_exercise(&act_as_alice, exercise_alice)
        .expect_err("alice cannot settle");
    assert!(matches!(err, ApiError::Unauthorized(_)));

    // Bank settles -> SUCCESS
    let exercise_bank = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid.clone(),
        choice: "Settle".to_string(),
        argument: serde_json::json!({}),
        meta: None,
    };
    let act_as_bank = vec!["Bank".to_string()];
    let res = service
        .json_exercise(&act_as_bank, exercise_bank)
        .expect("bank settles");
    assert_eq!(res.result.events.len(), 1);
    match &res.result.events[0] {
        JsonEvent::Archived(a) => assert_eq!(a.contract_id, cid),
        _ => panic!("expected archived"),
    }
}

#[test]
fn test_query_active_contracts_and_party_visibility() {
    let service = ExecutionService::new();

    // Create holding 1 for Alice
    let mut p1 = sample_holding_payload();
    p1["owner"] = serde_json::json!("Alice");
    service
        .json_create(
            &["Bank".to_string(), "Alice".to_string()],
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: p1,
                meta: None,
            },
        )
        .expect("create 1");

    // Create holding 2 for Bob
    let mut p2 = sample_holding_payload();
    p2["owner"] = serde_json::json!("Bob");
    service
        .json_create(
            &["Bank".to_string(), "Bob".to_string()],
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: p2,
                meta: None,
            },
        )
        .expect("create 2");

    // Query as Alice: should only see Alice's holding (1 contract)
    let alice_view = service
        .json_contracts(&["Alice".to_string()], None)
        .expect("contracts");
    assert_eq!(alice_view.result.len(), 1);
    assert_eq!(alice_view.result[0].payload["owner"], "Alice");

    // Query as Bob: should only see Bob's holding (1 contract)
    let bob_view = service
        .json_contracts(&["Bob".to_string()], None)
        .expect("contracts");
    assert_eq!(bob_view.result.len(), 1);
    assert_eq!(bob_view.result[0].payload["owner"], "Bob");

    // Query as Bank: signatory on both, should see 2 contracts
    let bank_view = service
        .json_contracts(&["Bank".to_string()], None)
        .expect("contracts");
    assert_eq!(bank_view.result.len(), 2);

    // Query as Auditor: observer on both, should see 2 contracts
    let auditor_view = service
        .json_contracts(&["Auditor".to_string()], None)
        .expect("contracts");
    assert_eq!(auditor_view.result.len(), 2);

    // Query as outsider Eve: should see 0 contracts
    let eve_view = service
        .json_contracts(&["Eve".to_string()], None)
        .expect("contracts");
    assert_eq!(eve_view.result.len(), 0);
}

#[test]
fn test_ledger_api_submit_and_wait_and_acs() {
    let service = ExecutionService::new();

    let submit_req = SubmitAndWaitRequest {
        commands: Commands {
            workflow_id: Some("wf-001".into()),
            application_id: "test-app".into(),
            command_id: "cmd-100".into(),
            act_as: vec!["Bank".into(), "Alice".into()],
            read_as: vec!["Auditor".into()],
            submission_id: Some("sub-100".into()),
            deduplication_period: Some(DeduplicationPeriod::DurationInSeconds(30)),
            commands: vec![Command::Create(CreateCommand {
                template_id: TemplateId::asset_holding(),
                create_arguments: sample_holding_payload(),
            })],
        },
    };

    let tree = service
        .submit_and_wait(submit_req)
        .expect("submit_and_wait");
    assert_eq!(tree.command_id, "cmd-100");
    assert_eq!(tree.workflow_id, "wf-001");
    assert_eq!(tree.root_event_ids.len(), 1);

    let acs = service
        .get_active_contracts(&["Alice".into()])
        .expect("get acs");
    assert_eq!(acs.active_contracts.len(), 1);
    assert_eq!(acs.active_contracts[0].contract_id, "#0:0");
}

#[test]
fn test_full_http_end_to_end_server() {
    let service = Arc::new(ExecutionService::new());
    let (port, shutdown) = start_test_server(service);

    // Helper to send HTTP request
    let send_http = |method: &str,
                     path: &str,
                     headers: &[(&str, &str)],
                     body: &str|
     -> (u16, serde_json::Value) {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
        let req_text = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\n{}\r\n{body}",
            body.len(),
            headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}\r\n"))
                .collect::<Vec<_>>()
                .join("")
        );
        stream
            .write_all(req_text.as_bytes())
            .expect("write request");

        let mut resp_bytes = Vec::new();
        stream.read_to_end(&mut resp_bytes).expect("read response");
        let resp_str = String::from_utf8_lossy(&resp_bytes);

        let (head, body_str) = resp_str.split_once("\r\n\r\n").expect("split headers/body");
        let status_code: u16 = head
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();

        let json_val: serde_json::Value =
            serde_json::from_str(body_str).unwrap_or(serde_json::Value::Null);
        (status_code, json_val)
    };

    // 1. Health check: Canton answers `/livez` with status 200 and an empty body (S-API-001, tests/oracle/json-api)
    let (status, health) = send_http("GET", "/livez", &[], "");
    assert_eq!(status, 200);
    assert!(health.is_null(), "an empty body is not JSON");

    // 2. Create contract via HTTP POST /v1/create
    let create_body = serde_json::to_string(&CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(),
        meta: None,
    })
    .unwrap();

    let (status, created) = send_http(
        "POST",
        "/v1/create",
        &[("X-Daml-Act-As", "Bank,Alice")],
        &create_body,
    );
    assert_eq!(status, 200);
    assert_eq!(created["result"]["contractId"], "#0:0");

    // 3. Query contracts via HTTP GET /v1/contracts
    let (status, query) = send_http(
        "GET",
        "/v1/contracts?party=Alice",
        &[("X-Daml-Read-As", "Alice")],
        "",
    );
    assert_eq!(status, 200);
    assert_eq!(query["result"].as_array().unwrap().len(), 1);

    // 4. Exercise transfer via HTTP POST /v1/exercise
    let exercise_body = serde_json::to_string(&ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: "#0:0".into(),
        choice: "Transfer".into(),
        argument: serde_json::json!({ "newOwner": "Bank" }),
        meta: None,
    })
    .unwrap();

    let (status, exercised) = send_http(
        "POST",
        "/v1/exercise",
        &[("X-Daml-Act-As", "Alice")],
        &exercise_body,
    );
    assert_eq!(status, 200);
    assert_eq!(exercised["result"]["events"].as_array().unwrap().len(), 2);

    // 5. Test unauthorized rejection via HTTP
    let (status, unauth) = send_http(
        "POST",
        "/v1/create",
        &[("X-Daml-Act-As", "Alice")], // Missing Bank
        &create_body,
    );
    assert_eq!(status, 403);
    assert!(unauth["errors"][0]
        .as_str()
        .unwrap()
        .contains("requires authorizers"));

    // Cleanup
    shutdown.store(true, Ordering::SeqCst);
}

#[test]
fn test_load_dar_sample_contract() {
    let service = Arc::new(ExecutionService::new());
    let dar_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar");

    // 1. Verify loading the real sample-contract.dar
    let info = service
        .load_dar(&dar_path)
        .expect("load_dar should succeed on sample-contract.dar");

    assert_eq!(
        info.main_package_id,
        "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"
    );
    assert_eq!(info.dalfs.len(), 31);
    assert_eq!(info.modules, vec!["AssetHolding".to_string()]);
    assert_eq!(info.package_name.as_deref(), Some("sample-contract"));
    assert_eq!(info.package_version.as_deref(), Some("0.1.0"));
    assert_eq!(info.lf_version, "2.1");
    assert!(!info.module_surfaces.is_empty());
    assert_eq!(info.module_surfaces[0].templates[0].name, "AssetHolding");

    // 2. Verify /v1/packages HTTP response
    let (port, shutdown) = start_test_server(Arc::clone(&service));

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    let req_text = format!("GET /v1/packages HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    stream.write_all(req_text.as_bytes()).expect("write");

    let mut resp_bytes = Vec::new();
    stream.read_to_end(&mut resp_bytes).expect("read");
    let resp_str = String::from_utf8_lossy(&resp_bytes);
    let (head, body_str) = resp_str.split_once("\r\n\r\n").expect("split headers/body");
    let status_code: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();

    assert_eq!(status_code, 200);
    let body: serde_json::Value = serde_json::from_str(body_str).expect("parse json");
    assert_eq!(
        body["main_package_id"],
        "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"
    );
    let packages_arr = body["packages"].as_array().expect("packages array");
    assert_eq!(packages_arr.len(), 31);
    assert_eq!(
        packages_arr[0],
        "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"
    );

    shutdown.store(true, Ordering::SeqCst);

    // 3. Verify error on non-existent DAR file
    let bad_service = ExecutionService::new();
    let err = bad_service.load_dar(std::path::Path::new("non_existent_file.dar"));
    assert!(matches!(err, Err(ApiError::Dar(_))));
}

#[test]
fn test_command_deduplication_window_rejection() {
    let service = ExecutionService::new();
    let cmd = Command::Create(CreateCommand {
        template_id: TemplateId::asset_holding(),
        create_arguments: sample_holding_payload(),
    });
    let req = SubmitAndWaitRequest {
        commands: Commands {
            workflow_id: None,
            application_id: "dedup-test-app".into(),
            command_id: "cmd-unique-123".into(),
            act_as: vec!["Bank".into(), "Alice".into()],
            read_as: vec!["Auditor".into()],
            submission_id: Some("sub-1".into()),
            deduplication_period: Some(DeduplicationPeriod::DurationInSeconds(60)),
            commands: vec![cmd],
        },
    };

    let tx1 = service
        .submit_and_wait(req.clone())
        .expect("first submission ok");
    assert_eq!(tx1.command_id, "cmd-unique-123");

    // Second submission with same application_id and command_id within deduplication window -> REJECTED
    let err = service
        .submit_and_wait(req)
        .expect_err("must be rejected as duplicate");
    match err {
        ApiError::PreconditionFailed(msg) => {
            assert!(msg.contains("Command deduplication rejection"));
        }
        other => panic!("expected PreconditionFailed, got {other:?}"),
    }
}

#[test]
fn test_transaction_update_stream_and_pruning() {
    let service = ExecutionService::new();
    for i in 1..=5 {
        let cmd = Command::Create(CreateCommand {
            template_id: TemplateId::asset_holding(),
            create_arguments: sample_holding_payload(),
        });
        let req = SubmitAndWaitRequest {
            commands: Commands {
                workflow_id: None,
                application_id: "stream-app".into(),
                command_id: format!("cmd-stream-{i}"),
                act_as: vec!["Bank".into(), "Alice".into()],
                read_as: vec!["Auditor".into()],
                submission_id: None,
                deduplication_period: None,
                commands: vec![cmd],
            },
        };
        service.submit_and_wait(req).expect("submit ok");
    }

    // Query stream between offset 2 and 4
    let updates = service.get_updates(2, Some(4), &["Alice".into()]);
    assert_eq!(updates.len(), 3);
    assert_eq!(updates[0].offset, 2);
    assert_eq!(updates[2].offset, 4);

    // Prune up to offset 3
    let pruned = service.prune_stream(3).expect("prune ok");
    assert_eq!(pruned, 3);

    // After pruning, stream starts from offset 4
    let remaining = service.get_updates(1, None, &[]);
    assert_eq!(remaining.len(), 2);
    assert_eq!(remaining[0].offset, 4);
    assert_eq!(remaining[1].offset, 5);
}

#[test]
fn test_active_ledger_state_and_journal_sync() {
    let service = ExecutionService::new();
    let cmd = Command::Create(CreateCommand {
        template_id: TemplateId::asset_holding(),
        create_arguments: sample_holding_payload(),
    });
    let req = SubmitAndWaitRequest {
        commands: Commands {
            workflow_id: None,
            application_id: "journal-app".into(),
            command_id: "cmd-journal-01".into(),
            act_as: vec!["Bank".into(), "Alice".into()],
            read_as: vec![],
            submission_id: None,
            deduplication_period: None,
            commands: vec![cmd],
        },
    };
    service.submit_and_wait(req).expect("submit ok");

    // Check lf_eval ActiveLedgerState
    let state = service.active_ledger_state();
    assert_eq!(state.active_contracts.len(), 1);

    // Check lf_eval LedgerJournal
    let journal = service.ledger_journal();
    assert_eq!(journal.len(), 1);
    assert_eq!(journal.entries()[0].offset, 1);
}

#[test]
fn test_submit_and_wait_exercise_transfer_sync() {
    let service = ExecutionService::new();
    let create_cmd = Command::Create(CreateCommand {
        template_id: TemplateId::asset_holding(),
        create_arguments: sample_holding_payload(),
    });
    let create_req = SubmitAndWaitRequest {
        commands: Commands {
            workflow_id: None,
            application_id: "tx-app".into(),
            command_id: "cmd-create-01".into(),
            act_as: vec!["Bank".into(), "Alice".into()],
            read_as: vec![],
            submission_id: None,
            deduplication_period: None,
            commands: vec![create_cmd],
        },
    };
    service.submit_and_wait(create_req).expect("create ok");

    // Exercise Transfer: Alice transfers #0:0 back to Bank
    let transfer_cmd = Command::Exercise(ExerciseCommand {
        template_id: TemplateId::asset_holding(),
        contract_id: "#0:0".into(),
        choice: "Transfer".into(),
        choice_argument: serde_json::json!({ "newOwner": "Bank" }),
    });
    let transfer_req = SubmitAndWaitRequest {
        commands: Commands {
            workflow_id: None,
            application_id: "tx-app".into(),
            command_id: "cmd-transfer-01".into(),
            act_as: vec!["Alice".into()],
            read_as: vec![],
            submission_id: None,
            deduplication_period: None,
            commands: vec![transfer_cmd],
        },
    };
    service.submit_and_wait(transfer_req).expect("transfer ok");

    // Active ledger state MUST contain the newly created contract (#1:0), NOT be empty!
    let state = service.active_ledger_state();
    assert_eq!(state.active_contracts.len(), 1);
    let new_cid = lf_eval::tx_model::ContractId("#1:0".into());
    assert!(state.active_contracts.contains_key(&new_cid));

    // Journal must record 2 transactions
    let journal = service.ledger_journal();
    assert_eq!(journal.len(), 2);
}

#[test]
fn test_json_api_create_and_exercise_syncs_with_active_state_and_journal() {
    let service = ExecutionService::new();

    // 1. Create via JSON API POST /v1/create
    let create_resp = service
        .json_create(
            &["Bank".into(), "Alice".into()],
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("json create");
    assert_eq!(create_resp.result.contract_id, "#0:0");

    let state1 = service.active_ledger_state();
    assert_eq!(state1.active_contracts.len(), 1);
    assert_eq!(service.ledger_journal().len(), 1);
    assert_eq!(service.get_updates(1, None, &[]).len(), 1);

    // 2. SplitTransfer via JSON API POST /v1/exercise
    let split_resp = service
        .json_exercise(
            &["Alice".into()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: "#0:0".into(),
                choice: "SplitTransfer".into(),
                argument: serde_json::json!({
                    "recipient": "Bank",
                    "transferAmount": "30.0"
                }),
                meta: None,
            },
        )
        .expect("json split transfer");
    assert_eq!(split_resp.result.events.len(), 3);

    // Active ledger state now has 2 active contracts (#1:0, #2:0) and #0:0 is consumed!
    let state2 = service.active_ledger_state();
    assert_eq!(state2.active_contracts.len(), 2);
    assert_eq!(service.ledger_journal().len(), 2);
    assert_eq!(service.get_updates(1, None, &[]).len(), 2);

    // 3. Settle #1:0 via JSON API POST /v1/exercise
    service
        .json_exercise(
            &["Bank".into()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: "#1:0".into(),
                choice: "Settle".into(),
                argument: serde_json::json!({}),
                meta: None,
            },
        )
        .expect("json settle");

    let state3 = service.active_ledger_state();
    assert_eq!(state3.active_contracts.len(), 1); // only #2:0 remaining
    assert_eq!(service.ledger_journal().len(), 3);
}

fn sample_dar_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar")
}

#[test]
fn test_generic_execution_create_and_transfer() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load_dar must succeed");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let create_req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: serde_json::json!({
            "bank": "Bank",
            "owner": "Alice",
            "auditor": "Auditor",
            "assetSymbol": "USD",
            "amount": "100.0",
        }),
        meta: None,
    };

    // 1. Create contract via generic lf-eval Engine
    let create_res = service
        .json_create(&act_as, create_req)
        .expect("create via engine");
    assert_eq!(create_res.status, 200);
    assert_eq!(create_res.result.contract_id, "#0:0");
    assert!(create_res.result.signatories.contains(&"Bank".to_string()));
    assert!(create_res.result.signatories.contains(&"Alice".to_string()));
    assert_eq!(create_res.result.signatories.len(), 2);
    assert_eq!(create_res.result.observers, vec!["Auditor"]);

    // Verify ActiveLedgerState and LedgerJournal synchronisation
    let state1 = service.active_ledger_state();
    assert_eq!(state1.active_contracts.len(), 1);
    assert_eq!(service.ledger_journal().len(), 1);

    // 2. Transfer choice executed by Alice to Bank
    // In Daml: Bank is already a signatory, so Bank does not need to separately authorize the nested create
    let exercise_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: "#0:0".into(),
        choice: "Transfer".into(),
        argument: serde_json::json!({
            "newOwner": "Bank"
        }),
        meta: None,
    };
    let exercise_res = service
        .json_exercise(&["Alice".into()], exercise_req)
        .expect("transfer via engine");
    assert_eq!(exercise_res.status, 200);
    assert_eq!(exercise_res.result.events.len(), 2);

    match &exercise_res.result.events[0] {
        JsonEvent::Archived(arch) => {
            assert_eq!(arch.contract_id, "#0:0");
        }
        other => panic!("expected Archived event, got {other:?}"),
    }
    match &exercise_res.result.events[1] {
        JsonEvent::Created(created) => {
            assert_eq!(created.contract_id, "#1:0");
            assert_eq!(created.payload["owner"], "Bank");
        }
        other => panic!("expected Created event, got {other:?}"),
    }

    // 3. Query contracts: Alice now sees 0 active contracts, Bank sees 1
    let alice_view = service
        .json_contracts(&["Alice".into()], None)
        .expect("alice query");
    assert_eq!(alice_view.result.len(), 0);

    let bank_view = service
        .json_contracts(&["Bank".into()], None)
        .expect("bank query");
    assert_eq!(bank_view.result.len(), 1);
    assert_eq!(bank_view.result[0].contract_id, "#1:0");

    let state2 = service.active_ledger_state();
    assert_eq!(state2.active_contracts.len(), 1);
    assert_eq!(service.ledger_journal().len(), 2);
}

#[test]
fn test_generic_execution_submit_and_wait_create_and_exercise() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load_dar must succeed");

    // 1. SubmitAndWait Create
    let create_cmd = Command::Create(CreateCommand {
        template_id: TemplateId::asset_holding(),
        create_arguments: serde_json::json!({
            "bank": "Bank",
            "owner": "Alice",
            "auditor": "Auditor",
            "assetSymbol": "USD",
            "amount": "100.0",
        }),
    });
    let create_req = SubmitAndWaitRequest {
        commands: Commands {
            workflow_id: None,
            application_id: "generic-app".into(),
            command_id: "cmd-g-create-01".into(),
            act_as: vec!["Bank".into(), "Alice".into()],
            read_as: vec!["Auditor".into()],
            submission_id: Some("sub-g1".into()),
            deduplication_period: None,
            commands: vec![create_cmd],
        },
    };
    let tx1 = service
        .submit_and_wait(create_req)
        .expect("submit create ok");
    assert_eq!(tx1.root_event_ids.len(), 1);
    let c_event = &tx1.events_by_id[&tx1.root_event_ids[0]];
    match c_event {
        TreeEvent::Created(c) => {
            assert_eq!(c.contract_id, "#0:0");
            assert!(c.signatories.contains(&"Bank".to_string()));
            assert!(c.signatories.contains(&"Alice".to_string()));
            assert_eq!(c.signatories.len(), 2);
            assert_eq!(c.observers, vec!["Auditor"]);
        }
        _ => panic!("expected Created tree event"),
    }

    // 2. SubmitAndWait SplitTransfer choice
    let split_cmd = Command::Exercise(ExerciseCommand {
        template_id: TemplateId::asset_holding(),
        contract_id: "#0:0".into(),
        choice: "SplitTransfer".into(),
        choice_argument: serde_json::json!({
            "transferAmount": "35.0",
            "recipient": "Bank",
        }),
    });
    let split_req = SubmitAndWaitRequest {
        commands: Commands {
            workflow_id: None,
            application_id: "generic-app".into(),
            command_id: "cmd-g-split-02".into(),
            act_as: vec!["Alice".into()],
            read_as: vec![],
            submission_id: Some("sub-g2".into()),
            deduplication_period: None,
            commands: vec![split_cmd],
        },
    };
    let tx2 = service.submit_and_wait(split_req).expect("submit split ok");
    assert_eq!(tx2.root_event_ids.len(), 1);
    let ex_event = &tx2.events_by_id[&tx2.root_event_ids[0]];
    match ex_event {
        TreeEvent::Exercised(e) => {
            assert_eq!(e.contract_id, "#0:0");
            assert_eq!(e.choice, "SplitTransfer");
            assert_eq!(e.child_event_ids.len(), 2);
        }
        _ => panic!("expected Exercised tree event"),
    }

    // Both resulting contracts (#1:0 and #2:0) must be active
    let acs = service.get_active_contracts(&[]).expect("get active");
    assert_eq!(acs.active_contracts.len(), 2);
    assert!(acs.active_contracts.iter().any(|c| c.contract_id == "#1:0"));
    assert!(acs.active_contracts.iter().any(|c| c.contract_id == "#2:0"));
}

#[test]
fn test_generic_execution_unauthorized_rejection() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load_dar must succeed");

    let req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: serde_json::json!({
            "bank": "Bank",
            "owner": "Alice",
            "auditor": "Auditor",
            "assetSymbol": "USD",
            "amount": "100.0",
        }),
        meta: None,
    };

    // 1. Missing Bank authorization on create -> MUST FAIL with 403
    let err = service
        .json_create(&["Alice".into()], req.clone())
        .expect_err("bank is missing");
    assert_eq!(err.status_code(), 403);
    match err {
        ApiError::Unauthorized(msg) => {
            assert!(msg.contains("requires authorization"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }

    // 2. Create valid contract
    service
        .json_create(&["Bank".into(), "Alice".into()], req)
        .expect("valid create");

    // 3. Exercise Transfer by Bank instead of owner Alice -> MUST FAIL with 403
    let bad_transfer = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: "#0:0".into(),
        choice: "Transfer".into(),
        argument: serde_json::json!({ "newOwner": "Bank" }),
        meta: None,
    };
    let err_trans = service
        .json_exercise(&["Bank".into()], bad_transfer)
        .expect_err("owner is required controller");
    assert_eq!(err_trans.status_code(), 403);
    match err_trans {
        ApiError::Unauthorized(msg) => {
            assert!(msg.contains("requires authorization"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }

    // 4. Exercise Settle by Alice instead of bank -> MUST FAIL with 403
    let bad_settle = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: "#0:0".into(),
        choice: "Settle".into(),
        argument: serde_json::json!({}),
        meta: None,
    };
    let err_settle = service
        .json_exercise(&["Alice".into()], bad_settle)
        .expect_err("bank is required controller");
    assert_eq!(err_settle.status_code(), 403);
    match err_settle {
        ApiError::Unauthorized(msg) => {
            assert!(msg.contains("requires authorization"));
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[test]
fn test_generic_execution_precondition_violation() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load_dar must succeed");

    // In AssetHolding.daml: `ensure amount > 0.0`
    // Attempt create with amount = 0.0
    let zero_req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: serde_json::json!({
            "bank": "Bank",
            "owner": "Alice",
            "auditor": "Auditor",
            "assetSymbol": "USD",
            "amount": "0.0",
        }),
        meta: None,
    };
    let err_zero = service
        .json_create(&["Bank".into(), "Alice".into()], zero_req)
        .expect_err("amount zero must fail ensure");
    assert_eq!(err_zero.status_code(), 400);
    match err_zero {
        ApiError::PreconditionFailed(msg) => {
            assert!(msg.contains("precondition violated") || msg.contains("Precondition"));
        }
        other => panic!("expected PreconditionFailed, got {other:?}"),
    }

    // Attempt create with negative amount
    let neg_req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: serde_json::json!({
            "bank": "Bank",
            "owner": "Alice",
            "auditor": "Auditor",
            "assetSymbol": "USD",
            "amount": "-50.0",
        }),
        meta: None,
    };
    let err_neg = service
        .json_create(&["Bank".into(), "Alice".into()], neg_req)
        .expect_err("negative amount must fail ensure");
    assert_eq!(err_neg.status_code(), 400);
    match err_neg {
        ApiError::PreconditionFailed(_) => {}
        other => panic!("expected PreconditionFailed, got {other:?}"),
    }
}

#[test]
fn test_generic_execution_unknown_choice_and_assertion_rejection() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load_dar must succeed");

    service
        .json_create(
            &["Bank".into(), "Alice".into()],
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: serde_json::json!({
                    "bank": "Bank",
                    "owner": "Alice",
                    "auditor": "Auditor",
                    "assetSymbol": "USD",
                    "amount": "100.0",
                }),
                meta: None,
            },
        )
        .expect("create ok");

    // 1. Unknown choice on template -> MUST FAIL with InvalidArgument
    let unknown_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: "#0:0".into(),
        choice: "NonExistentChoice".into(),
        argument: serde_json::json!({}),
        meta: None,
    };
    let err_unknown = service
        .json_exercise(&["Alice".into()], unknown_req)
        .expect_err("unknown choice");
    assert_eq!(err_unknown.status_code(), 400);
    match err_unknown {
        ApiError::InvalidArgument(msg) => {
            assert!(msg.contains("Unknown choice 'NonExistentChoice'"));
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    // 2. Transfer with newOwner == owner violates Daml assertMsg:
    // assertMsg "New owner cannot be the same as current owner" (newOwner /= owner)
    let same_owner_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: "#0:0".into(),
        choice: "Transfer".into(),
        argument: serde_json::json!({ "newOwner": "Alice" }),
        meta: None,
    };
    let err_same = service
        .json_exercise(&["Alice".into()], same_owner_req)
        .expect_err("same owner violates assertMsg");
    assert_eq!(err_same.status_code(), 400);
    match err_same {
        ApiError::InvalidArgument(msg) => {
            assert!(msg.contains("New owner cannot be the same as current owner"));
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    // 3. SplitTransfer with transferAmount >= current balance violates Daml assertMsg:
    // assertMsg "Transfer amount must be less than current balance" (transferAmount < amount)
    let too_large_split = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: "#0:0".into(),
        choice: "SplitTransfer".into(),
        argument: serde_json::json!({
            "transferAmount": "150.0",
            "recipient": "Bank",
        }),
        meta: None,
    };
    let err_large = service
        .json_exercise(&["Alice".into()], too_large_split)
        .expect_err("oversized split violates assertMsg");
    assert_eq!(err_large.status_code(), 400);
    match err_large {
        ApiError::InvalidArgument(msg) => {
            assert!(msg.contains("Transfer amount must be less than current balance"));
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
}

// =============================================================================
// Step 1 (G3 잔여) Proof & Pinning Tests:
// Loaded DAR Request Lockout & Unloaded Fallback Pinning
// =============================================================================

// [CANTON-NOTE: INVARIANT] Loaded DAR requests must be evaluated exclusively by lf-eval::Engine
// and must NEVER reach the legacy "Transfer"/"SplitTransfer" string arms. If the target contract
// does not exist or is inactive in generic_contracts, it must immediately fail with ContractNotActive.
// [CANTON-NOTE: WHY] In Daml-LF semantics, once a package is loaded, choice execution is governed
// by compiled bytecode and type schemas, not static host string dispatch.
#[test]
fn test_loaded_dar_missing_contract_never_reaches_legacy_choice_arms() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load_dar must succeed");

    // Attempt exercise on non-existent contract with choice "Transfer"
    let req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: "#999:0".into(),
        choice: "Transfer".into(),
        argument: serde_json::json!({ "newOwner": "Bank" }),
        meta: None,
    };

    // MUST return ContractNotActive (HTTP 404), never falling through to SingleContractLedger
    let err = service
        .json_exercise(&["Alice".into()], req)
        .expect_err("nonexistent contract must fail");
    assert_eq!(err.status_code(), 404);
    assert_eq!(err, ApiError::ContractNotActive("#999:0".into()));

    // Verify SingleContractLedger was completely untouched (zero active contracts)
    let legacy = service.active_ledger_state();
    assert_eq!(legacy.active_contracts.len(), 0);
}

// [CANTON-NOTE: SEMANTICS] When a template resolves to Generic, non-existent or consumed contracts
// must immediately fail with ContractNotActive (HTTP 404) rather than attempting legacy ledger fallback.
#[test]
fn test_loaded_dar_arbitrary_contract_id_format_fails_contract_not_active() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load_dar must succeed");

    // Non-numeric string contract ID that would fail Self::parse_contract_id
    let req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: "opaque-hash-cid-42".into(),
        choice: "Transfer".into(),
        argument: serde_json::json!({ "newOwner": "Bank" }),
        meta: None,
    };

    // Under the lock, this fails with ContractNotActive (404), proving it NEVER reaches parse_contract_id (which returns 400 InvalidArgument)
    let err = service
        .json_exercise(&["Alice".into()], req)
        .expect_err("opaque string contract id must fail ContractNotActive");
    assert_eq!(err.status_code(), 404);
    assert_eq!(
        err,
        ApiError::ContractNotActive("opaque-hash-cid-42".into())
    );
}

// [CANTON-NOTE: INVARIANT] Once a DAR is loaded, unregistered templates must resolve to NotFound;
// they must never fall back to LegacyAssetHolding.
#[test]
fn test_loaded_dar_rejects_unknown_template_without_legacy_fallback() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load_dar must succeed");

    let unknown_tmpl = TemplateId {
        package_id: "unknown_pkg".into(),
        module_name: "AssetHolding".into(),
        entity_name: "AssetHolding".into(),
    };

    let req = CreateRequest {
        template_id: unknown_tmpl,
        payload: sample_holding_payload(),
        meta: None,
    };

    // In loaded DAR mode, unregistered templates MUST fail TemplateNotFound, not LegacyAssetHolding
    let err = service
        .json_create(&["Bank".into(), "Alice".into()], req)
        .expect_err("unregistered template must fail with TemplateNotFound");
    assert_eq!(err.status_code(), 404);
    match err {
        ApiError::TemplateNotFound(t) => assert!(t.contains("unknown_pkg")),
        other => panic!("expected TemplateNotFound, got {other:?}"),
    }
}

// [CANTON-NOTE: INVARIANT] Loaded DAR requests must execute exclusively via Daml-LF bytecode
// in lf_eval::Engine and must NEVER hit the legacy string-matching choice arms in service.rs.
// [CANTON-NOTE: WHY] Prevents semantic leakage where missing, invalid, or edge-case contracts
// fall back into legacy hardcoded fixtures instead of adhering to Daml-LF ledger rules.
#[test]
fn test_loaded_dar_conclusively_proves_no_legacy_fallback_on_exercise() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");
    assert!(service.dar_info().is_some());

    // 1. Create contract under loaded DAR
    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let create_res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: serde_json::json!({
                    "bank": "Bank",
                    "owner": "Alice",
                    "auditor": "Auditor",
                    "assetSymbol": "USD",
                    "amount": "100.0",
                }),
                meta: None,
            },
        )
        .expect("generic create");
    let cid = create_res.result.contract_id;

    // PROOF VECTOR 1: exercise_result populated by Daml bytecode return value
    // Legacy string arm hardcodes exercise_result to None.
    let transfer_res = service
        .json_exercise(
            &["Alice".into()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid,
                choice: "Transfer".into(),
                argument: serde_json::json!({ "newOwner": "Bank" }),
                meta: None,
            },
        )
        .expect("generic transfer");

    assert!(
        transfer_res.result.exercise_result.is_some(),
        "CRITICAL: exercise_result must be Some(cid) from Daml-LF bytecode; None indicates legacy arm was hit"
    );
    let new_cid = transfer_res.result.exercise_result.unwrap();
    assert_eq!(new_cid, serde_json::Value::String("#1:0".into()));

    // PROOF VECTOR 2: Storage Isolation
    let active_res = service.get_active_contracts(&[]).expect("get acs");
    assert_eq!(active_res.active_contracts.len(), 1);
    assert_eq!(active_res.active_contracts[0].contract_id, "#1:0");

    // PROOF VECTOR 3: Authorization Error Fingerprint Discrimination
    // The Auditor (an observer, so it sees the contract) attempts Transfer on the contract owned by Bank (#1:0).
    // (Alice, the previous owner, is no longer a stakeholder and would get a not-found answer instead.)
    let bad_auth_res = service.json_exercise(
        &["Auditor".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: "#1:0".into(),
            choice: "Transfer".into(),
            argument: serde_json::json!({ "newOwner": "Alice" }),
            meta: None,
        },
    );
    match bad_auth_res {
        Err(ApiError::Unauthorized(msg)) => {
            // Must contain generic engine CEK error format:
            assert!(
                msg.contains("requires authorization of [\"Bank\"]"),
                "Must originate from generic Engine: {msg}"
            );
            assert!(
                msg.contains("authorized:"),
                "Must originate from generic Engine: {msg}"
            );
            // Must NOT contain legacy arm format:
            assert!(
                !msg.contains("were given"),
                "LEAK DETECTED: hit legacy string arm: {msg}"
            );
        }
        other => panic!("expected Unauthorized from generic engine, got {other:?}"),
    }

    // PROOF VECTOR 4: CEK Runtime Assertion Error Fingerprint
    // Bank transfers to Bank (violates Daml assertMsg "New owner cannot be the same as current owner")
    let same_owner_res = service.json_exercise(
        &["Bank".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: "#1:0".into(),
            choice: "Transfer".into(),
            argument: serde_json::json!({ "newOwner": "Bank" }),
            meta: None,
        },
    );
    match same_owner_res {
        Err(ApiError::InvalidArgument(msg)) => {
            // Generic engine CEK unhandled exception
            assert!(
                msg.contains("UNHANDLED_EXCEPTION") || msg.contains("AssertionFailed"),
                "Must originate from Daml CEK unhandled exception: {msg}"
            );
            assert!(
                msg.contains("New owner cannot be the same as current owner"),
                "Must contain Daml assertMsg: {msg}"
            );
        }
        other => panic!("expected InvalidArgument with assertion failure, got {other:?}"),
    }

    // PROOF VECTOR 5: Non-existent contract ID on loaded DAR returns 404 without legacy fallback
    let bad_cid_res = service.json_exercise(
        &["Alice".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: "#999:0".into(),
            choice: "Transfer".into(),
            argument: serde_json::json!({ "newOwner": "Bank" }),
            meta: None,
        },
    );
    assert_eq!(
        bad_cid_res.unwrap_err(),
        ApiError::ContractNotActive("#999:0".into()),
        "Non-existent contract ID on loaded DAR must return ContractNotActive without hitting legacy ledger"
    );
}

// [CANTON-NOTE: INVARIANT] SubmitAndWait ExercisedEvent.exercise_result must be Some in generic path
// and must never fall back to legacy arm which hardcodes exercise_result: None.
#[test]
fn test_loaded_dar_submit_and_wait_proves_no_legacy_fallback() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    // 1. SubmitAndWait Create
    let tx1 = service
        .submit_and_wait(SubmitAndWaitRequest {
            commands: Commands {
                workflow_id: None,
                application_id: "test-app".into(),
                command_id: "cmd-1".into(),
                act_as: vec!["Bank".into(), "Alice".into()],
                read_as: vec![],
                submission_id: None,
                deduplication_period: None,
                commands: vec![Command::Create(CreateCommand {
                    template_id: TemplateId::asset_holding(),
                    create_arguments: serde_json::json!({
                        "bank": "Bank",
                        "owner": "Alice",
                        "auditor": "Auditor",
                        "assetSymbol": "USD",
                        "amount": "100.0",
                    }),
                })],
            },
        })
        .expect("create tx");
    assert_eq!(tx1.root_event_ids.len(), 1);

    // 2. SubmitAndWait Transfer
    let tx2 = service
        .submit_and_wait(SubmitAndWaitRequest {
            commands: Commands {
                workflow_id: None,
                application_id: "test-app".into(),
                command_id: "cmd-2".into(),
                act_as: vec!["Alice".into()],
                read_as: vec![],
                submission_id: None,
                deduplication_period: None,
                commands: vec![Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: "#0:0".into(),
                    choice: "Transfer".into(),
                    choice_argument: serde_json::json!({
                        "newOwner": "Bank",
                    }),
                })],
            },
        })
        .expect("transfer tx");

    let ex_event = match &tx2.events_by_id[&tx2.root_event_ids[0]] {
        TreeEvent::Exercised(e) => e,
        _ => panic!("expected Exercised event"),
    };

    // TreeEvent exercise_result MUST be populated by generic Engine
    // (Legacy arm hardcodes exercise_result: None)
    assert!(
        ex_event.exercise_result.is_some(),
        "CRITICAL: submit_and_wait ExercisedEvent.exercise_result must be Some in generic path"
    );
    assert_eq!(
        ex_event.exercise_result,
        Some(serde_json::Value::String("#1:0".into()))
    );
}

// [CANTON-NOTE: LIMITATION] This test explicitly pins down the legacy fallback behavior
// of SingleContractLedger in ExecutionService. This fallback exists solely for legacy
// Stage 07 test fixtures when NO DAR file has been loaded.
// [CANTON-NOTE: INVARIANT] Once a DAR is loaded into ExecutionService, this legacy path
// is strictly unreachable.
#[test]
fn test_unloaded_dar_fallback_strictly_pinned_to_unloaded_state() {
    let service = ExecutionService::new();
    assert!(service.dar_info().is_none(), "Must be in unloaded DAR mode");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let create_res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: serde_json::json!({
                    "bank": "Bank",
                    "owner": "Alice",
                    "auditor": "Auditor",
                    "assetSymbol": "USD",
                    "amount": "100.0",
                }),
                meta: None,
            },
        )
        .expect("unloaded create");
    let cid = create_res.result.contract_id;
    assert_eq!(cid, "#0:0");

    // PINNED FACT 1: Legacy arm ALWAYS returns exercise_result: None
    let transfer_res = service
        .json_exercise(
            &["Alice".into(), "Bank".into()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid,
                choice: "Transfer".into(),
                argument: serde_json::json!({ "newOwner": "Bank" }),
                meta: None,
            },
        )
        .expect("legacy transfer");
    assert_eq!(
        transfer_res.result.exercise_result, None,
        "Legacy fallback arm strictly returns None for exercise_result"
    );

    // PINNED FACT 2: Legacy arm error string uses exact format "requires controller X, but only Y were given"
    let bad_auth = service.json_exercise(
        &["Alice".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: "#1:0".into(),
            choice: "Transfer".into(),
            argument: serde_json::json!({ "newOwner": "Alice" }),
            meta: None,
        },
    );
    assert_eq!(
        bad_auth.unwrap_err(),
        ApiError::Unauthorized(
            "Transfer choice requires controller Bank, but only Alice were given".into()
        )
    );

    // PINNED FACT 3: Legacy arm choice validation error string format (unqualified template name)
    let bad_choice = service.json_exercise(
        &["Bank".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: "#1:0".into(),
            choice: "UnknownLegacyChoice".into(),
            argument: serde_json::json!({}),
            meta: None,
        },
    );
    assert_eq!(
        bad_choice.unwrap_err(),
        ApiError::InvalidArgument(
            "Unknown choice 'UnknownLegacyChoice' on template AssetHolding".into()
        )
    );

    // PINNED FACT 4: Non-AssetHolding template strictly rejected in unloaded fallback
    let bad_req = CreateRequest {
        template_id: TemplateId {
            package_id: "".into(),
            module_name: "OtherModule".into(),
            entity_name: "OtherEntity".into(),
        },
        payload: serde_json::json!({}),
        meta: None,
    };
    let bad_err = service
        .json_create(&["Alice".into()], bad_req)
        .expect_err("non-AssetHolding must fail TemplateNotFound");
    assert_eq!(bad_err.status_code(), 404);
}

// [CANTON-NOTE: SEMANTICS] Edge case coverage on loaded DAR:
// unknown choice, empty choice, malformed argument types, missing fields, template mismatch, double spend.
#[test]
fn test_loaded_dar_edge_cases_unknown_choice_bad_args_and_template_mismatch() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let create_res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: serde_json::json!({
                    "bank": "Bank",
                    "owner": "Alice",
                    "auditor": "Auditor",
                    "assetSymbol": "USD",
                    "amount": "100.0",
                }),
                meta: None,
            },
        )
        .expect("create");
    let cid = create_res.result.contract_id;

    // EDGE CASE 1: Unknown choice on loaded DAR
    // Must fail at RecordSchema::choice_arg with qualified template name and 400 Bad Request
    let err_unknown = service
        .json_exercise(
            &["Alice".into()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "NoSuchChoiceOnDamlTemplate".into(),
                argument: serde_json::json!({}),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err_unknown.status_code(), 400);
    match err_unknown {
        ApiError::InvalidArgument(msg) => {
            assert!(msg.contains(
                "Unknown choice 'NoSuchChoiceOnDamlTemplate' on template AssetHolding:AssetHolding"
            ));
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    // EDGE CASE 2: Empty choice string on loaded DAR
    let err_empty_choice = service
        .json_exercise(
            &["Alice".into()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "".into(),
                argument: serde_json::json!({}),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err_empty_choice.status_code(), 400);

    // EDGE CASE 3: Bad argument type (integer instead of Party string for newOwner)
    let err_bad_arg_type = service
        .json_exercise(
            &["Alice".into()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".into(),
                argument: serde_json::json!({ "newOwner": 99999 }),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err_bad_arg_type.status_code(), 400);
    match err_bad_arg_type {
        ApiError::InvalidArgument(msg) => {
            assert!(msg.contains("Invalid choice argument"));
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    // EDGE CASE 4: Missing required argument field (missing transferAmount in SplitTransfer)
    let err_missing_arg = service
        .json_exercise(
            &["Alice".into()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "SplitTransfer".into(),
                argument: serde_json::json!({ "recipient": "Bank" }),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err_missing_arg.status_code(), 400);
    match err_missing_arg {
        ApiError::InvalidArgument(msg) => {
            assert!(msg.contains("Invalid choice argument") || msg.contains("missing field"));
        }
        other => panic!("expected InvalidArgument, got {other:?}"),
    }

    // EDGE CASE 5: Wrong template ID on exercise (template does not exist in loaded DAR)
    let err_wrong_tmpl = service
        .json_exercise(
            &["Alice".into()],
            ExerciseRequest {
                template_id: TemplateId {
                    package_id: "".into(),
                    module_name: "AssetHolding".into(),
                    entity_name: "NonExistentTemplate".into(),
                },
                contract_id: cid.clone(),
                choice: "Transfer".into(),
                argument: serde_json::json!({ "newOwner": "Bank" }),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err_wrong_tmpl.status_code(), 404);
    assert!(matches!(err_wrong_tmpl, ApiError::TemplateNotFound(_)));

    // EDGE CASE 6: Double spend attempt after consumption
    service
        .json_exercise(
            &["Alice".into()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".into(),
                argument: serde_json::json!({ "newOwner": "Bank" }),
                meta: None,
            },
        )
        .expect("consume contract");

    let err_double_spend = service
        .json_exercise(
            &["Alice".into()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".into(),
                argument: serde_json::json!({ "newOwner": "Bank" }),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err_double_spend, ApiError::ContractNotActive(cid));
}

#[test]
fn test_non_sample_dar_resolves_short_and_package_name_template_ids() {
    let service = ExecutionService::new();
    let dar_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/fixtures/keyed/target/keyed-vault.dar");
    let info = service.load_dar(&dar_path).expect("load keyed-vault.dar");

    let short_req = CreateRequest {
        template_id: "Keyed:Registry".parse().expect("parse short template id"),
        payload: serde_json::json!({
            "owner": "Alice",
            "name": "k-short",
            "payload": "v1"
        }),
        meta: None,
    };
    let short_res = service
        .json_create(&["Alice".to_string()], short_req)
        .expect("create with 2-part Module:Entity template id");
    assert_eq!(
        short_res.result.template_id.package_id,
        info.main_package_id
    );

    let named_req = CreateRequest {
        template_id: "#keyed-vault:Keyed:Registry"
            .parse()
            .expect("parse #pkg-name template id"),
        payload: serde_json::json!({
            "owner": "Alice",
            "name": "k-named",
            "payload": "v2"
        }),
        meta: None,
    };
    let named_res = service
        .json_create(&["Alice".to_string()], named_req)
        .expect("create with #package-name:Module:Entity template id");
    assert_eq!(
        named_res.result.template_id.package_id,
        info.main_package_id
    );
}
