//! S-SPL-032: End-to-end 2-participant protocol tests over the JSON API path for:
//! - P4: Contract keys (create keyed contract, `ReadByKey`, `Rename`, HTTP `ExerciseByKeyCommand`, `Probe` `lookupByKey`).
//! - P5: Interface exercise (`Iface:IHolding.Poke` via `json_exercise` and HTTP `/v2/commands/submit-and-wait`).
//! - P6 / U-7: Rollback nodes (`Scratch.Attempt`, `Scratch.AttemptThenCreate`) and cross-participant rollback subview (`Driver.Try`).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "protocol")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use canton_participant::node::Node;
use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::protocol::NodeCommitter;
use ledger_json_api::service::ExecutionService;
use ledger_json_api::{dispatch_request, HttpRequest, HttpResponse};
use serde_json::json;

fn dar_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn synchronizer(name: &str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = canton_sequencer_server::new_synchronizer_with_groups(name, "ss1", 1);
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(canton_sequencer_server::serve(address, config))
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    format!("http://{address}")
}

fn participant(url: &str, name: &str) -> Arc<ExecutionService> {
    let sample = dar_path("../../../contracts/target/sample-contract.dar");
    let node = Node::connect(url, name, &sample).expect("join synchronizer");
    let service = Arc::new(ExecutionService::new());
    service.load_dar(&sample).expect("load boot DAR");
    let committer = Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(30),
    ));
    committer.show_remote_transactions_in(Arc::clone(&service));
    service.set_committer(committer);
    service
}

fn post(service: &ExecutionService, path: &str, body: Vec<u8>) -> HttpResponse {
    dispatch_request(
        service,
        &HttpRequest {
            method: "POST".into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body,
        },
    )
}

fn post_json(
    service: &ExecutionService,
    path: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let resp = post(service, path, serde_json::to_vec(&body).unwrap());
    let json = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&resp.body).to_string() }));
    (resp.status, json)
}

fn upload_dar_both(alpha: &ExecutionService, beta: &ExecutionService, rel_dar: &str) -> String {
    let path = dar_path(rel_dar);
    let bytes = std::fs::read(&path).unwrap();
    let pkg_id = lf_archive::parse_dar_file(&path).unwrap().main_package_id;
    for (label, svc) in [("alpha", alpha), ("beta", beta)] {
        let resp = post(svc, "/v2/packages", bytes.clone());
        assert_eq!(
            resp.status,
            200,
            "{label} DAR upload failed for {rel_dar}: {}",
            String::from_utf8_lossy(&resp.body)
        );
    }
    // Brief yield so topology broadcasts propagate cleanly between participants.
    std::thread::sleep(Duration::from_millis(80));
    pkg_id
}

fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ok() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn p4_contract_keys_read_by_key_rename_and_lookup_probe_over_protocol() {
    let url = synchronizer("p4sync");
    let alpha = participant(&url, "alpha");
    let beta = participant(&url, "beta");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let _bob = beta.protocol_party("bob").unwrap().unwrap();

    let keyed_pkg = upload_dar_both(
        &alpha,
        &beta,
        "../../../contracts/fixtures/keyed/target/keyed-vault.dar",
    );
    let lookup_pkg = upload_dar_both(
        &alpha,
        &beta,
        "../../../contracts/fixtures/lookup/target/lookup-view.dar",
    );

    // 1. Create Keyed:Registry
    let reg_cid = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::new(&keyed_pkg, "Keyed", "Registry"),
                payload: json!({
                    "owner": alice,
                    "name": "k1",
                    "payload": "secret-v1"
                }),
                meta: None,
            },
        )
        .expect("Keyed:Registry create")
        .result
        .contract_id;

    // 2. Exercise ReadByKey (performs fetchByKey inside choice)
    let read_res = alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::new(&keyed_pkg, "Keyed", "Registry"),
                contract_id: reg_cid.clone(),
                choice: "ReadByKey".into(),
                argument: json!({
                    "wanted": { "_1": alice, "_2": "k1" }
                }),
                meta: None,
            },
        )
        .expect("Keyed:Registry.ReadByKey");
    assert_eq!(
        read_res.result.result_value,
        Some(ValueBox(lf_eval::Value::Text("secret-v1".into())))
    );

    // 3. Exercise Rename via HTTP POST /v2/commands/submit-and-wait ExerciseByKeyCommand
    let (status, rename_resp) = post_json(
        &alpha,
        "/v2/commands/submit-and-wait",
        json!({
            "commands": [{
                "ExerciseByKeyCommand": {
                    "templateId": format!("{keyed_pkg}:Keyed:Registry"),
                    "contractKey": { "_1": alice, "_2": "k1" },
                    "choice": "Rename",
                    "choiceArgument": { "newName": "k2" }
                }
            }],
            "commandId": "p4-rename-by-key",
            "userId": "participant_admin",
            "actAs": [alice]
        }),
    );
    assert_eq!(status, 200, "ExerciseByKeyCommand failed: {rename_resp}");

    // Old contract archived; new contract active with key ("k2")
    assert!(alpha.v2_contract(&reg_cid).is_some_and(|c| !c.active));
    let new_reg_cid = alpha
        .get_active_contracts(&[])
        .unwrap()
        .active_contracts
        .into_iter()
        .find(|c| c.template_id.entity_name == "Registry")
        .expect("new Registry contract after Rename")
        .contract_id;

    let read_renamed = alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::new(&keyed_pkg, "Keyed", "Registry"),
                contract_id: new_reg_cid,
                choice: "ReadByKey".into(),
                argument: json!({
                    "wanted": { "_1": alice, "_2": "k2" }
                }),
                meta: None,
            },
        )
        .expect("ReadByKey on renamed Registry");
    assert_eq!(
        read_renamed.result.result_value,
        Some(ValueBox(lf_eval::Value::Text("secret-v1".into())))
    );

    // 4. Lookup:Entry.Probe -> lookupByKey missing (false) and present (true)
    let entry_cid = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::new(&lookup_pkg, "Lookup", "Entry"),
                payload: json!({
                    "owner": alice,
                    "name": "present"
                }),
                meta: None,
            },
        )
        .expect("Lookup:Entry create")
        .result
        .contract_id;

    let probe_missing = alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::new(&lookup_pkg, "Lookup", "Entry"),
                contract_id: entry_cid.clone(),
                choice: "Probe".into(),
                argument: json!({
                    "wanted": { "_1": alice, "_2": "missing" }
                }),
                meta: None,
            },
        )
        .expect("Probe missing key");
    assert_eq!(
        probe_missing.result.result_value,
        Some(ValueBox(lf_eval::Value::Bool(false)))
    );

    let probe_present = alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::new(&lookup_pkg, "Lookup", "Entry"),
                contract_id: entry_cid,
                choice: "Probe".into(),
                argument: json!({
                    "wanted": { "_1": alice, "_2": "present" }
                }),
                meta: None,
            },
        )
        .expect("Probe present key");
    assert_eq!(
        probe_present.result.result_value,
        Some(ValueBox(lf_eval::Value::Bool(true)))
    );
}

#[test]
fn p5_interface_exercise_over_protocol_and_v2_http() {
    let url = synchronizer("p5sync");
    let alpha = participant(&url, "alpha");
    let beta = participant(&url, "beta");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let _bob = beta.protocol_party("bob").unwrap().unwrap();

    let iface_pkg = upload_dar_both(
        &alpha,
        &beta,
        "../../../contracts/fixtures/iface/target/iface-view.dar",
    );

    // 1. Direct json_exercise through Iface:IHolding.Poke
    let holding1 = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::new(&iface_pkg, "Iface", "Holding"),
                payload: json!({ "owner": alice }),
                meta: None,
            },
        )
        .expect("create Iface:Holding 1")
        .result
        .contract_id;

    alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::new(&iface_pkg, "Iface", "IHolding"),
                contract_id: holding1.clone(),
                choice: "Poke".into(),
                argument: json!({}),
                meta: None,
            },
        )
        .expect("json_exercise Iface:IHolding.Poke");
    assert!(
        alpha.v2_contract(&holding1).is_some_and(|c| !c.active),
        "Poke is consuming"
    );

    // 2. HTTP POST /v2/commands/submit-and-wait ExerciseCommand targeting Iface:IHolding
    let holding2 = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::new(&iface_pkg, "Iface", "Holding"),
                payload: json!({ "owner": alice }),
                meta: None,
            },
        )
        .expect("create Iface:Holding 2")
        .result
        .contract_id;

    let (status, resp) = post_json(
        &alpha,
        "/v2/commands/submit-and-wait",
        json!({
            "commands": [{
                "ExerciseCommand": {
                    "templateId": format!("{iface_pkg}:Iface:IHolding"),
                    "contractId": holding2,
                    "choice": "Poke",
                    "choiceArgument": {}
                }
            }],
            "commandId": "p5-iface-http",
            "userId": "participant_admin",
            "actAs": [alice]
        }),
    );
    assert_eq!(status, 200, "HTTP interface ExerciseCommand failed: {resp}");
    assert!(
        alpha.v2_contract(&holding2).is_some_and(|c| !c.active),
        "holding2 must be archived"
    );
}

#[test]
fn p6_rollback_and_cross_participant_rollback_subview_over_protocol() {
    let url = synchronizer("p6sync");
    let alpha = participant(&url, "alpha");
    let beta = participant(&url, "beta");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let bob = beta.protocol_party("bob").unwrap().unwrap();

    let lookup_pkg = upload_dar_both(
        &alpha,
        &beta,
        "../../../contracts/fixtures/lookup/target/lookup-view.dar",
    );

    // 1. Local Scratch.Attempt and Scratch.AttemptThenCreate (create positioned after rolled-back fetches)
    let scratch_cid = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::new(&lookup_pkg, "Lookup", "Scratch"),
                payload: json!({ "owner": alice }),
                meta: None,
            },
        )
        .expect("create Lookup:Scratch")
        .result
        .contract_id;

    alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::new(&lookup_pkg, "Lookup", "Scratch"),
                contract_id: scratch_cid.clone(),
                choice: "Attempt".into(),
                argument: json!({}),
                meta: None,
            },
        )
        .expect("Lookup:Scratch.Attempt");

    let attempt_create_res = alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::new(&lookup_pkg, "Lookup", "Scratch"),
                contract_id: scratch_cid,
                choice: "AttemptThenCreate".into(),
                argument: json!({}),
                meta: None,
            },
        )
        .expect("Lookup:Scratch.AttemptThenCreate");
    let created_after_rb = match attempt_create_res.result.result_value {
        Some(ValueBox(lf_eval::Value::ContractId(cid))) => cid,
        other => panic!("expected ContractId from AttemptThenCreate, got {other:?}"),
    };
    assert!(
        alpha.v2_contract(&created_after_rb).is_some(),
        "created contract after rollback must be active"
    );

    // 2. Cross-participant rollback subview: beta hosts Lookup:Held{r: bob, a: alice}, alpha fetches it inside try/catch
    let held_cid = beta
        .json_create(
            std::slice::from_ref(&bob),
            CreateRequest {
                template_id: TemplateId::new(&lookup_pkg, "Lookup", "Held"),
                payload: json!({ "r": bob, "a": alice }),
                meta: None,
            },
        )
        .expect("beta creates Lookup:Held")
        .result
        .contract_id;

    eventually("alpha never received Lookup:Held from beta", || {
        alpha.v2_contract(&held_cid).is_some()
    });

    let driver_cid = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::new(&lookup_pkg, "Lookup", "Driver"),
                payload: json!({ "a": alice }),
                meta: None,
            },
        )
        .expect("alpha creates Lookup:Driver")
        .result
        .contract_id;

    alpha
        .json_exercise(
            std::slice::from_ref(&alice),
            ExerciseRequest {
                template_id: TemplateId::new(&lookup_pkg, "Lookup", "Driver"),
                contract_id: driver_cid,
                choice: "Try".into(),
                argument: json!({ "held": held_cid }),
                meta: None,
            },
        )
        .expect("Lookup:Driver.Try cross-participant rollback subview");

    // Held was only fetched inside a rolled-back block and must remain active on both participants.
    assert!(alpha.v2_contract(&held_cid).is_some());
    assert!(beta.v2_contract(&held_cid).is_some());
}

#[test]
fn two_participant_explicit_disclosure_blob_roundtrip() {
    let url = synchronizer("dx2sync");
    let alpha = participant(&url, "alpha");
    let beta = participant(&url, "beta");
    let own = alpha.protocol_party("own").unwrap().unwrap();
    let tak = beta.protocol_party("tak").unwrap().unwrap();

    let disc_pkg = upload_dar_both(
        &alpha,
        &beta,
        "../../../tests/oracle/disclosure/disc-1.0.0.dar",
    );

    let (status, create_resp) = post_json(
        &alpha,
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": format!("{disc_pkg}:Main:Offer"),
                        "createArguments": { "owner": own, "price": "42" }
                    }
                }],
                "commandId": "dx-2p-create",
                "actAs": [own],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": {
                    "filtersByParty": {
                        own: {
                            "cumulative": [{
                                "identifierFilter": {
                                    "WildcardFilter": {
                                        "value": { "includeCreatedEventBlob": true }
                                    }
                                }
                            }]
                        }
                    },
                    "verbose": true
                },
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        }),
    );
    assert_eq!(status, 200, "Alpha create Offer failed: {create_resp}");
    let offer_ev = &create_resp["transaction"]["events"][0]["CreatedEvent"];
    let offer_cid = offer_ev["contractId"].as_str().unwrap().to_string();
    let offer_blob = offer_ev["createdEventBlob"].as_str().unwrap().to_string();
    assert!(!offer_blob.is_empty(), "createdEventBlob must be present");
    assert!(
        beta.v2_contract(&offer_cid).is_none(),
        "Beta is not an informee and must not hold Offer locally"
    );

    // Beta (hosting `tak`) exercises `Take` on the unseen foreign Offer using `disclosedContracts`.
    let (take_status, take_resp) = post_json(
        &beta,
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "ExerciseCommand": {
                        "templateId": format!("{disc_pkg}:Main:Offer"),
                        "contractId": offer_cid,
                        "choice": "Take",
                        "choiceArgument": { "taker": tak }
                    }
                }],
                "commandId": "dx-2p-take",
                "actAs": [tak],
                "userId": "participant_admin",
                "disclosedContracts": [{
                    "templateId": format!("{disc_pkg}:Main:Offer"),
                    "contractId": offer_cid,
                    "createdEventBlob": offer_blob
                }]
            },
            "transactionFormat": {
                "eventFormat": {
                    "filtersByParty": {
                        tak: {
                            "cumulative": [{
                                "identifierFilter": {
                                    "WildcardFilter": {
                                        "value": { "includeCreatedEventBlob": false }
                                    }
                                }
                            }]
                        }
                    },
                    "verbose": true
                },
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        }),
    );
    assert_eq!(take_status, 200, "Beta disclosed Take failed: {take_resp}");
    let taken_cid = take_resp["transaction"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|ev| ev.get("CreatedEvent"))
        .and_then(|ce| ce["contractId"].as_str())
        .expect("CreatedEvent for Main:Taken")
        .to_string();

    assert!(beta.v2_contract(&taken_cid).is_some_and(|c| c.active));
    eventually("Alpha did not observe Taken and Offer archival", || {
        alpha.v2_contract(&taken_cid).is_some_and(|c| c.active)
            && alpha.v2_contract(&offer_cid).is_some_and(|c| !c.active)
    });
}

#[test]
fn two_participant_smart_contract_upgrade_exercise() {
    let url = synchronizer("ug2sync");
    let alpha = participant(&url, "alpha");
    let beta = participant(&url, "beta");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let _bob = beta.protocol_party("bob").unwrap().unwrap();

    let v1_pkg = upload_dar_both(&alpha, &beta, "../../../tests/oracle/upgrade/upg-1.0.0.dar");
    let v2_pkg = upload_dar_both(&alpha, &beta, "../../../tests/oracle/upgrade/upg-2.0.0.dar");

    let (create_status, create_resp) = post_json(
        &alpha,
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": format!("{v1_pkg}:Main:Account"),
                        "createArguments": { "owner": alice, "balance": "1" }
                    }
                }],
                "commandId": "ug-v1-create",
                "actAs": [alice],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": {
                    "filtersByParty": {
                        alice.clone(): {
                            "cumulative": [{
                                "identifierFilter": {
                                    "WildcardFilter": {
                                        "value": { "includeCreatedEventBlob": false }
                                    }
                                }
                            }]
                        }
                    },
                    "verbose": true
                },
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
            }
        }),
    );
    assert_eq!(
        create_status, 200,
        "v1 Account create failed: {create_resp}"
    );
    let v1_cid = create_resp["transaction"]["events"][0]["CreatedEvent"]["contractId"]
        .as_str()
        .unwrap()
        .to_string();

    let (upg_status, upg_resp) = post_json(
        &alpha,
        "/v2/commands/submit-and-wait-for-transaction",
        json!({
            "commands": {
                "commands": [{
                    "ExerciseCommand": {
                        "templateId": "#upg:Main:Account",
                        "contractId": v1_cid,
                        "choice": "Rebuild",
                        "choiceArgument": {}
                    }
                }],
                "commandId": "ug-v2-rebuild",
                "actAs": [alice],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": {
                    "filtersByParty": {
                        alice: {
                            "cumulative": [{
                                "identifierFilter": {
                                    "WildcardFilter": {
                                        "value": { "includeCreatedEventBlob": false }
                                    }
                                }
                            }]
                        }
                    },
                    "verbose": true
                },
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
            }
        }),
    );
    assert_eq!(
        upg_status, 200,
        "upgraded Rebuild exercise failed: {upg_resp}"
    );
    let events = upg_resp["transaction"]["events"].as_array().unwrap();
    let created_ev = events
        .iter()
        .find_map(|ev| ev.get("CreatedEvent"))
        .expect("v2 CreatedEvent from Rebuild");
    assert_eq!(created_ev["templateId"], format!("{v2_pkg}:Main:Account"));
    assert_eq!(created_ev["createArgument"]["balance"], "21");
    assert_eq!(created_ev["createArgument"]["note"], "v2");
    assert!(alpha.v2_contract(&v1_cid).is_some_and(|c| !c.active));
}
