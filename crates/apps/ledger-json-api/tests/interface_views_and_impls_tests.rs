//! S-API-026: `implementedInterfaces` on consuming `ExercisedEvent`/`ArchivedEvent`,
//! typed `interfaceViews` encoding (`Time` RFC 3339, fixed-scale `Numeric`, `TextMap`, `removeTrailingNonesInRecords`: trailing `None` omitted, non-trailing `None` as `null`),
//! `#pkg-name:Mod:Ent` and `<pkg_id>:Mod:Ent` `InterfaceFilter` view extraction across read/submit paths,
//! and `filtersForAnyParty` expansion.

use std::path::{Path, PathBuf};

use ledger_json_api::service::ExecutionService;
use ledger_json_api::{dispatch_request, HttpRequest};
use serde_json::{json, Value as Json};

fn events_dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/events-dar/events-oracle.dar")
}

fn amulet_dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/splice-dars/splice-amulet-0.1.25.dar")
}

fn post_json(service: &ExecutionService, path: &str, body: &Json) -> (u16, Json) {
    let req = HttpRequest {
        method: "POST".into(),
        path: path.into(),
        query_params: Default::default(),
        headers: Default::default(),
        body: serde_json::to_vec(body).expect("json body"),
    };
    let resp = dispatch_request(service, &req);
    let parsed = serde_json::from_slice(&resp.body).unwrap_or(Json::Null);
    (resp.status, parsed)
}

fn post_bytes(service: &ExecutionService, path: &str, bytes: Vec<u8>) -> (u16, Json) {
    let req = HttpRequest {
        method: "POST".into(),
        path: path.into(),
        query_params: Default::default(),
        headers: Default::default(),
        body: bytes,
    };
    let resp = dispatch_request(service, &req);
    let parsed = serde_json::from_slice(&resp.body).unwrap_or(Json::Null);
    (resp.status, parsed)
}

fn alloc_party(service: &ExecutionService, hint: &str) -> String {
    let (status, body) = post_json(
        service,
        "/v2/parties",
        &json!({ "partyIdHint": hint, "identityProviderId": "" }),
    );
    assert_eq!(status, 200, "allocate {hint}: {body}");
    body["partyDetails"]["party"]
        .as_str()
        .expect("party string")
        .to_string()
}

fn iface_filter(party: &str, iface_id: &str, include_view: bool) -> Json {
    json!({
        "filtersByParty": {
            (party): {
                "cumulative": [{
                    "identifierFilter": {
                        "InterfaceFilter": {
                            "value": {
                                "interfaceId": iface_id,
                                "includeInterfaceView": include_view,
                                "includeCreatedEventBlob": false
                            }
                        }
                    }
                }]
            }
        },
        "verbose": true
    })
}

fn wildcard_filter(party: &str) -> Json {
    json!({
        "filtersByParty": {
            (party): {
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
    })
}

#[test]
fn implemented_interfaces_populated_only_for_consuming_events_matched_by_view_filter() {
    let service = ExecutionService::new();
    let dar = std::fs::read(events_dar()).expect("read events-oracle.dar");
    let (status, _) = post_bytes(&service, "/v2/dars", dar);
    assert_eq!(status, 200);

    let owner = alloc_party(&service, "owner");
    let pkg_id = service
        .v2_package_id_for_name("events-oracle")
        .expect("events-oracle package id");
    let iface_by_name = "#events-oracle:Events:Labeled";
    let iface_by_id = format!("{pkg_id}:Events:Labeled");

    // 1. Create Tag (implements Labeled) & Inspector & Gift (does NOT implement Labeled)
    let (st, tag_resp) = post_json(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#events-oracle:Events:Tag",
                        "createArguments": { "owner": owner, "watcher": owner, "text": "hello" }
                    }
                }],
                "commandId": "create-tag",
                "actAs": [owner],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": iface_filter(&owner, iface_by_name, true),
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        }),
    );
    assert_eq!(st, 200, "create Tag: {tag_resp}");
    let tag_cid = tag_resp["transaction"]["events"][0]["CreatedEvent"]["contractId"]
        .as_str()
        .expect("tag cid")
        .to_string();
    assert_eq!(
        tag_resp["transaction"]["events"][0]["CreatedEvent"]["interfaceViews"][0]["viewValue"],
        json!({ "text": "hello" })
    );

    let (st, gift_resp) = post_json(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#events-oracle:Events:Gift",
                        "createArguments": { "owner": owner, "watcher": owner }
                    }
                }],
                "commandId": "create-gift",
                "actAs": [owner],
                "userId": "participant_admin"
            }
        }),
    );
    assert_eq!(st, 200, "create Gift: {gift_resp}");
    let gift_cid = gift_resp["transaction"]["events"][0]["CreatedEvent"]["contractId"]
        .as_str()
        .expect("gift cid")
        .to_string();

    // 2. Non-consuming exercise through interface (`GetLabel`): implementedInterfaces must be []
    let (st, insp_resp) = post_json(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({
            "commands": {
                "commands": [{
                    "CreateAndExerciseCommand": {
                        "templateId": "#events-oracle:Events:Inspector",
                        "createArguments": { "owner": owner },
                        "choice": "Inspect",
                        "choiceArgument": { "tag": tag_cid }
                    }
                }],
                "commandId": "inspect-tag",
                "actAs": [owner],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": iface_filter(&owner, iface_by_name, true),
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
            }
        }),
    );
    assert_eq!(st, 200, "inspect Tag: {insp_resp}");
    let insp_events = insp_resp["transaction"]["events"].as_array().unwrap();
    let get_label_ev = insp_events
        .iter()
        .find(|e| e.pointer("/ExercisedEvent/choice").and_then(Json::as_str) == Some("GetLabel"))
        .expect("GetLabel exercised event");
    assert_eq!(
        get_label_ev["ExercisedEvent"]["consuming"],
        json!(false),
        "GetLabel is non-consuming"
    );
    assert_eq!(
        get_label_ev["ExercisedEvent"]["implementedInterfaces"],
        json!([]),
        "non-consuming ExercisedEvent must have empty implementedInterfaces"
    );

    // 3. Consuming archive on Tag and Gift
    let (st, arch_tag_resp) = post_json(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({
            "commands": {
                "commands": [{
                    "ExerciseCommand": {
                        "templateId": "#events-oracle:Events:Tag",
                        "contractId": tag_cid,
                        "choice": "Archive",
                        "choiceArgument": {}
                    }
                }],
                "commandId": "archive-tag",
                "actAs": [owner],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": iface_filter(&owner, iface_by_name, true),
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        }),
    );
    assert_eq!(st, 200, "archive Tag: {arch_tag_resp}");
    assert_eq!(
        arch_tag_resp["transaction"]["events"][0]["ArchivedEvent"]["implementedInterfaces"],
        json!([iface_by_id]),
        "submit-and-wait-for-transaction must populate ArchivedEvent.implementedInterfaces"
    );
    let archive_update_id = arch_tag_resp["transaction"]["updateId"]
        .as_str()
        .unwrap()
        .to_string();
    let archive_offset = arch_tag_resp["transaction"]["offset"].as_u64().unwrap();

    let (st, _) = post_json(
        &service,
        "/v2/commands/submit-and-wait",
        &json!({
            "commands": [{
                "ExerciseCommand": {
                    "templateId": "#events-oracle:Events:Gift",
                    "contractId": gift_cid,
                    "choice": "Archive",
                    "choiceArgument": {}
                }
            }],
            "commandId": "archive-gift",
            "actAs": [owner],
            "userId": "participant_admin"
        }),
    );
    assert_eq!(st, 200);

    // 4. /v2/updates with WildcardFilter only -> empty implementedInterfaces & interfaceViews
    let (st, wc_updates) = post_json(
        &service,
        "/v2/updates",
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": wildcard_filter(&owner),
                    "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                }
            }
        }),
    );
    assert_eq!(st, 200);
    for u in wc_updates.as_array().unwrap() {
        for ev in u["update"]["Transaction"]["value"]["events"]
            .as_array()
            .unwrap()
        {
            if let Some(ex) = ev.get("ExercisedEvent") {
                assert_eq!(ex["implementedInterfaces"], json!([]));
            }
            if let Some(cr) = ev.get("CreatedEvent") {
                assert_eq!(cr["interfaceViews"], json!([]));
            }
        }
    }

    // 5. /v2/updates with <pkg_id> InterfaceFilter (includeInterfaceView: true) + Wildcard
    let (st, id_updates) = post_json(
        &service,
        "/v2/updates",
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": iface_filter(&owner, &iface_by_id, true),
                    "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                }
            }
        }),
    );
    assert_eq!(st, 200, "updates with pkg_id filter: {id_updates}");
    let arch_tx = id_updates
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["update"]["Transaction"]["value"]["updateId"] == archive_update_id)
        .expect("archive update in stream");
    let ex_archive = &arch_tx["update"]["Transaction"]["value"]["events"][0]["ExercisedEvent"];
    assert_eq!(ex_archive["implementedInterfaces"], json!([iface_by_id]));

    // Gift archive does NOT implement Labeled -> implementedInterfaces must remain []
    let gift_arch_tx = id_updates
        .as_array()
        .unwrap()
        .iter()
        .find(|u| {
            u["update"]["Transaction"]["value"]["events"][0]["ExercisedEvent"]["contractId"]
                == gift_cid
        })
        .expect("gift archive tx");
    assert_eq!(
        gift_arch_tx["update"]["Transaction"]["value"]["events"][0]["ExercisedEvent"]
            ["implementedInterfaces"],
        json!([])
    );

    // 6. InterfaceFilter with includeInterfaceView: false -> implementedInterfaces is []
    let (st, no_view_updates) = post_json(
        &service,
        "/v2/updates",
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": iface_filter(&owner, iface_by_name, false),
                    "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                }
            }
        }),
    );
    assert_eq!(st, 200);
    let arch_no_view = no_view_updates
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["update"]["Transaction"]["value"]["updateId"] == archive_update_id)
        .unwrap();
    assert_eq!(
        arch_no_view["update"]["Transaction"]["value"]["events"][0]["ExercisedEvent"]
            ["implementedInterfaces"],
        json!([])
    );

    // 7. update-by-id, update-by-offset, events-by-contract-id, and filtersForAnyParty
    for (path, payload) in [
        (
            "/v2/updates/update-by-id",
            json!({
                "updateId": archive_update_id,
                "updateFormat": {
                    "includeTransactions": {
                        "eventFormat": iface_filter(&owner, &iface_by_id, true),
                        "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                    }
                }
            }),
        ),
        (
            "/v2/updates/update-by-offset",
            json!({
                "offset": archive_offset,
                "updateFormat": {
                    "includeTransactions": {
                        "eventFormat": {
                            "filtersByParty": {},
                            "filtersForAnyParty": {
                                "cumulative": [{
                                    "identifierFilter": {
                                        "InterfaceFilter": {
                                            "value": {
                                                "interfaceId": iface_by_id,
                                                "includeInterfaceView": true,
                                                "includeCreatedEventBlob": false
                                            }
                                        }
                                    }
                                }]
                            }
                        },
                        "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                    }
                }
            }),
        ),
    ] {
        let (st, body) = post_json(&service, path, &payload);
        assert_eq!(st, 200, "{path}: {body}");
        assert_eq!(
            body["update"]["Transaction"]["value"]["events"][0]["ArchivedEvent"]
                ["implementedInterfaces"],
            json!([iface_by_id]),
            "{path} must populate implementedInterfaces"
        );
    }

    let (st, by_cid) = post_json(
        &service,
        "/v2/events/events-by-contract-id",
        &json!({
            "contractId": tag_cid,
            "eventFormat": iface_filter(&owner, &iface_by_id, true)
        }),
    );
    assert_eq!(st, 200, "events-by-contract-id: {by_cid}");
    assert_eq!(
        by_cid["created"]["createdEvent"]["interfaceViews"][0]["viewValue"],
        json!({ "text": "hello" })
    );
    assert_eq!(
        by_cid["archived"]["archivedEvent"]["implementedInterfaces"],
        json!([iface_by_id])
    );
}

#[test]
fn holding_interface_view_encodes_time_numeric_and_textmap_correctly() {
    let service = ExecutionService::new();
    let dar = std::fs::read(amulet_dar()).expect("read splice-amulet.dar");
    let (status, _) = post_bytes(&service, "/v2/dars", dar);
    assert_eq!(status, 200);

    let dso = alloc_party(&service, "DSO");
    let alice = alloc_party(&service, "alice");
    let holding_pkg = service
        .packages_named("splice-api-token-holding-v1")
        .into_iter()
        .next()
        .expect("splice-api-token-holding-v1 loaded");
    let holding_iface_id = format!("{holding_pkg}:Splice.Api.Token.HoldingV1:Holding");

    let (st, create_resp) = post_json(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#splice-amulet:Splice.Amulet:LockedAmulet",
                        "createArguments": {
                            "amulet": {
                                "dso": dso,
                                "owner": alice,
                                "amount": {
                                    "initialAmount": "100",
                                    "createdAt": { "number": "0" },
                                    "ratePerRound": { "rate": "0.0001" }
                                }
                            },
                            "lock": {
                                "holders": [dso],
                                "expiresAt": "2026-12-01T00:00:00Z",
                                "optContext": null
                            }
                        }
                    }
                }],
                "commandId": "create-locked-amulet",
                "actAs": [dso, alice],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": iface_filter(&alice, &holding_iface_id, true),
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        }),
    );
    assert_eq!(st, 200, "create LockedAmulet: {create_resp}");

    let view = &create_resp["transaction"]["events"][0]["CreatedEvent"]["interfaceViews"][0];
    assert_eq!(view["interfaceId"], json!(holding_iface_id));
    let vv = &view["viewValue"];
    assert_eq!(vv["amount"], json!("100.0000000000"));
    assert_eq!(
        vv["lock"]["expiresAt"],
        json!("2026-12-01T00:00:00Z"),
        "Time inside interfaceView must be RFC 3339 string, not microseconds"
    );
    assert!(
        vv["lock"].get("expiresAfter").is_none(),
        "trailing None Optional fields in interfaceView records must be omitted (Canton 3.7.2 removeTrailingNonesInRecords = true), got: {}",
        vv["lock"]
    );
    assert!(
        vv["lock"].get("context").is_none(),
        "trailing None Optional fields in interfaceView records must be omitted (Canton 3.7.2 removeTrailingNonesInRecords = true), got: {}",
        vv["lock"]
    );
    assert!(
        vv["meta"]["values"].is_object(),
        "TextMap in interfaceView must be a JSON object, got: {}",
        vv["meta"]
    );

    // Also verify /v2/state/active-contracts with #splice-api-token-holding-v1 & filtersForAnyParty
    let (st, acs) = post_json(
        &service,
        "/v2/state/active-contracts",
        &json!({
            "eventFormat": {
                "filtersByParty": {},
                "filtersForAnyParty": {
                    "cumulative": [{
                        "identifierFilter": {
                            "InterfaceFilter": {
                                "value": {
                                    "interfaceId": "#splice-api-token-holding-v1:Splice.Api.Token.HoldingV1:Holding",
                                    "includeInterfaceView": true,
                                    "includeCreatedEventBlob": false
                                }
                            }
                        }
                    }]
                },
                "verbose": true
            }
        }),
    );
    assert_eq!(st, 200, "ACS with filtersForAnyParty: {acs}");
    let acs_arr = acs.as_array().expect("ACS array");
    assert_eq!(acs_arr.len(), 1);
    let acs_view = &acs_arr[0]["contractEntry"]["JsActiveContract"]["createdEvent"]
        ["interfaceViews"][0]["viewValue"];
    assert_eq!(acs_view["amount"], json!("100.0000000000"));
    assert_eq!(acs_view["lock"]["expiresAt"], json!("2026-12-01T00:00:00Z"));
    assert!(acs_view["meta"]["values"].is_object());

    // Non-trailing None (expiresAfter = None followed by optContext = Some("escrow")) must stay explicit JSON null
    let (st, create_ctx_resp) = post_json(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#splice-amulet:Splice.Amulet:LockedAmulet",
                        "createArguments": {
                            "amulet": {
                                "dso": dso,
                                "owner": alice,
                                "amount": {
                                    "initialAmount": "100",
                                    "createdAt": { "number": "0" },
                                    "ratePerRound": { "rate": "0.0001" }
                                }
                            },
                            "lock": {
                                "holders": [dso],
                                "expiresAt": "2026-12-01T00:00:00Z",
                                "optContext": "escrow"
                            }
                        }
                    }
                }],
                "commandId": "create-locked-amulet-with-context",
                "actAs": [dso, alice],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": iface_filter(&alice, &holding_iface_id, true),
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        }),
    );
    assert_eq!(
        st, 200,
        "create LockedAmulet with context: {create_ctx_resp}"
    );
    let vv2 = &create_ctx_resp["transaction"]["events"][0]["CreatedEvent"]["interfaceViews"][0]
        ["viewValue"];
    assert_eq!(
        vv2["lock"].get("expiresAfter"),
        Some(&Json::Null),
        "non-trailing None Optional fields in interfaceView records must encode as JSON null (Canton 3.7.2)"
    );
    assert_eq!(
        vv2["lock"].get("context"),
        Some(&json!("escrow")),
        "trailing Some(context) must preserve preceding None expiresAfter as JSON null"
    );
}

#[test]
fn choice_observers_and_fetch_node_numbering_propagate() {
    let service = ExecutionService::new();
    let dar = std::fs::read(events_dar()).expect("read events-oracle.dar");
    let (status, _) = post_bytes(&service, "/v2/dars", dar);
    assert_eq!(status, 200);

    let owner = alloc_party(&service, "owner");
    let watcher = alloc_party(&service, "watcher");
    let other = alloc_party(&service, "other");
    let stranger = alloc_party(&service, "stranger");

    // 1. Gift.Share has `observer other` (not a contract stakeholder)
    let (st, gift_resp) = post_json(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({
            "commands": {
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#events-oracle:Events:Gift",
                        "createArguments": { "owner": owner, "watcher": watcher }
                    }
                }],
                "commandId": "gift-obs-create",
                "actAs": [owner],
                "userId": "participant_admin"
            }
        }),
    );
    assert_eq!(st, 200);
    let gift_cid = gift_resp["transaction"]["events"][0]["CreatedEvent"]["contractId"]
        .as_str()
        .unwrap()
        .to_string();

    let (st, share_resp) = post_json(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({
            "commands": {
                "commands": [{
                    "ExerciseCommand": {
                        "templateId": "#events-oracle:Events:Gift",
                        "contractId": gift_cid,
                        "choice": "Share",
                        "choiceArgument": { "other": other }
                    }
                }],
                "commandId": "gift-obs-share",
                "actAs": [owner],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": wildcard_filter(&other),
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
            }
        }),
    );
    assert_eq!(st, 200, "Share exercise: {share_resp}");
    let share_events = share_resp["transaction"]["events"].as_array().unwrap();
    assert_eq!(
        share_events.len(),
        1,
        "choice observer `other` must see Exercised(Share)"
    );
    assert_eq!(
        share_events[0]["ExercisedEvent"]["witnessParties"],
        json!([other])
    );

    // Stranger cannot see Exercised(Share) in /v2/updates
    let (st, stranger_upd) = post_json(
        &service,
        "/v2/updates",
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": wildcard_filter(&stranger),
                    "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                }
            }
        }),
    );
    assert_eq!(st, 200);
    assert!(stranger_upd.as_array().unwrap().is_empty());

    // 2. Inspector.Inspect fetches Tag via Labeled interface then exercises GetLabel:
    // node 0 = Exercised(Inspect), node 1 = Fetch(Tag, hidden from events), node 2 = Exercised(GetLabel)
    let (st, tag_resp) = post_json(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({
            "commands": {
                "commands": [
                    {
                        "CreateCommand": {
                            "templateId": "#events-oracle:Events:Tag",
                            "createArguments": { "owner": owner, "watcher": watcher, "text": "v" }
                        }
                    },
                    {
                        "CreateCommand": {
                            "templateId": "#events-oracle:Events:Inspector",
                            "createArguments": { "owner": owner }
                        }
                    }
                ],
                "commandId": "create-tag-inspector",
                "actAs": [owner],
                "userId": "participant_admin"
            }
        }),
    );
    assert_eq!(st, 200);
    let tag_cid = tag_resp["transaction"]["events"][0]["CreatedEvent"]["contractId"]
        .as_str()
        .unwrap()
        .to_string();
    let insp_cid = tag_resp["transaction"]["events"][1]["CreatedEvent"]["contractId"]
        .as_str()
        .unwrap()
        .to_string();

    let (st, inspect_resp) = post_json(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({
            "commands": {
                "commands": [{
                    "ExerciseCommand": {
                        "templateId": "#events-oracle:Events:Inspector",
                        "contractId": insp_cid,
                        "choice": "Inspect",
                        "choiceArgument": { "tag": tag_cid }
                    }
                }],
                "commandId": "inspect-fetch-num",
                "actAs": [owner],
                "userId": "participant_admin"
            },
            "transactionFormat": {
                "eventFormat": wildcard_filter(&owner),
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
            }
        }),
    );
    assert_eq!(st, 200, "Inspect response: {inspect_resp}");
    let evs = inspect_resp["transaction"]["events"].as_array().unwrap();
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[0]["ExercisedEvent"]["nodeId"], json!(0));
    assert_eq!(evs[0]["ExercisedEvent"]["lastDescendantNodeId"], json!(2));
    assert_eq!(evs[1]["ExercisedEvent"]["choice"], json!("GetLabel"));
    assert_eq!(evs[1]["ExercisedEvent"]["nodeId"], json!(2));
}
