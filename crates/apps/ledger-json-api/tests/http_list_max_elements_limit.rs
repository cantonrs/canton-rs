//! Regression tests for `?limit=` query parameter and `http-ledger-api.websocket-config.http-list-max-elements-limit`
//! across HTTP blocking stream-list routes matching Canton 3.7.2 (`Endpoints.scala` / `JsonApiErrors.scala`).

use std::collections::HashMap;
use std::path::PathBuf;

use ledger_json_api::v2_updates::with_unbounded_stream_list;
use ledger_json_api::{dispatch_request, ExecutionService, HttpRequest, HttpResponse};
use serde_json::{json, Value};

fn sample_dar_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn post_with_query(
    service: &ExecutionService,
    path: &str,
    query: &[(&str, &str)],
    body: &Value,
) -> HttpResponse {
    let query_params: HashMap<String, String> = query
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    dispatch_request(
        service,
        &HttpRequest {
            method: "POST".to_string(),
            path: path.to_string(),
            query_params,
            headers: [("content-type".to_string(), "application/json".to_string())].into(),
            body: serde_json::to_vec(body).expect("serialize request JSON"),
        },
    )
}

fn parse_body(resp: &HttpResponse) -> Value {
    serde_json::from_slice(&resp.body).expect("parse response JSON")
}

fn setup_service_with_contracts(count: usize) -> (ExecutionService, String) {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");
    let alloc = post_with_query(
        &service,
        "/v2/parties",
        &[],
        &json!({ "partyIdHint": "bank", "identityProviderId": "" }),
    );
    assert_eq!(alloc.status, 200, "allocate party failed");
    let party = parse_body(&alloc)["partyDetails"]["party"]
        .as_str()
        .expect("party id")
        .to_string();
    for i in 0..count {
        let resp = post_with_query(
            &service,
            "/v2/commands/submit-and-wait-for-transaction",
            &[],
            &json!({
                "commands": {
                    "commands": [{
                        "CreateCommand": {
                            "templateId": "#sample-contract:AssetHolding:AssetHolding",
                            "createArguments": {
                                "bank": party,
                                "owner": party,
                                "auditor": party,
                                "assetSymbol": "USD",
                                "amount": "10.0"
                            }
                        }
                    }],
                    "commandId": format!("limit-cmd-{i}"),
                    "userId": "participant_admin",
                    "actAs": [party]
                }
            }),
        );
        assert_eq!(resp.status, 200, "create #{i} failed: {:?}", resp.body);
    }
    (service, party)
}

fn assert_payload_too_large(resp: &HttpResponse, expected_limit: usize) {
    assert_eq!(
        resp.status,
        413,
        "expected 413 Payload Too Large, got {}: {}",
        resp.status,
        String::from_utf8_lossy(&resp.body)
    );
    let err = parse_body(resp);
    assert_eq!(err["code"], "JSON_API_MAXIMUM_LIST_ELEMENTS_NUMBER_REACHED");
    assert_eq!(err["errorCategory"], 2);
    assert_eq!(err["grpcCodeValue"], 10);
    assert_eq!(
        err["cause"],
        format!(
            "The number of matching elements ({}) is greater than the node limit ({expected_limit}).",
            expected_limit + 1
        )
    );
}

#[test]
fn blocking_list_endpoints_honor_limit_and_enforce_node_cap() {
    let (service, party) = setup_service_with_contracts(6);
    let wildcard_event_format = json!({
        "filtersByParty": {
            (party.clone()): {
                "cumulative": [{
                    "WildcardFilter": { "value": { "includeCreatedEventBlob": false } }
                }]
            }
        },
        "verbose": true
    });
    let acs_req = json!({ "eventFormat": wildcard_event_format });
    let updates_req = json!({
        "beginExclusive": 0,
        "updateFormat": {
            "includeTransactions": {
                "eventFormat": wildcard_event_format,
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        }
    });
    let flats_req = json!({
        "beginExclusive": 0,
        "filter": wildcard_event_format
    });
    let completions_req = json!({
        "userId": "participant_admin",
        "parties": [party],
        "beginExclusive": 0
    });

    // 1) Default standalone mode (`http_list_max_elements_limit == None`) returns all 6 items,
    //    and `?limit=3` truncates to 3 on every list endpoint including active-contracts.
    assert_eq!(service.http_list_max_elements_limit(), None);
    for (path, req) in [
        ("/v2/state/active-contracts", &acs_req),
        ("/v2/updates", &updates_req),
        ("/v2/updates/flats", &flats_req),
        ("/v2/updates/trees", &updates_req),
    ] {
        let all = post_with_query(&service, path, &[], req);
        assert_eq!(all.status, 200, "{path} without cap");
        assert_eq!(parse_body(&all).as_array().expect("array").len(), 6);

        let limited = post_with_query(&service, path, &[("limit", "3")], req);
        assert_eq!(limited.status, 200, "{path} ?limit=3");
        assert_eq!(parse_body(&limited).as_array().expect("array").len(), 3);
    }

    let comp_limited = post_with_query(
        &service,
        "/v2/commands/completions",
        &[("limit", "3")],
        &completions_req,
    );
    assert_eq!(comp_limited.status, 200);
    assert_eq!(
        parse_body(&comp_limited).as_array().expect("array").len(),
        3
    );

    // 2) Configured node cap (`http_list_max_elements_limit = Some(5)`).
    service.set_http_list_max_elements_limit(Some(5));

    // `?limit=3` and `?limit=5` (equal to node cap) succeed with 200.
    for (path, req) in [
        ("/v2/state/active-contracts", &acs_req),
        ("/v2/updates", &updates_req),
        ("/v2/updates/flats", &flats_req),
        ("/v2/updates/trees", &updates_req),
        ("/v2/commands/completions", &completions_req),
    ] {
        let ok_below = post_with_query(&service, path, &[("limit", "3")], req);
        assert_eq!(ok_below.status, 200, "{path} ?limit=3 under cap");
        assert_eq!(parse_body(&ok_below).as_array().expect("array").len(), 3);

        let ok_equal = post_with_query(&service, path, &[("limit", "5")], req);
        assert_eq!(ok_equal.status, 200, "{path} ?limit=5 == cap");
        assert_eq!(parse_body(&ok_equal).as_array().expect("array").len(), 5);

        // Negative control 1: omitting `?limit=` or asking `?limit=6` triggers 413.
        let over_unbounded = post_with_query(&service, path, &[], req);
        assert_payload_too_large(&over_unbounded, 5);

        let over_explicit = post_with_query(&service, path, &[("limit", "6")], req);
        assert_payload_too_large(&over_explicit, 5);

        // Negative control 2: malformed/negative `?limit=` returns 400.
        let bad_neg = post_with_query(&service, path, &[("limit", "-1")], req);
        assert_eq!(bad_neg.status, 400, "{path} ?limit=-1");
        let bad_text = post_with_query(&service, path, &[("limit", "abc")], req);
        assert_eq!(bad_text.status, 400, "{path} ?limit=abc");
    }

    // 3) Streaming transport bypass (`with_unbounded_stream_list`) allows > cap.
    let ws_style = with_unbounded_stream_list(|| {
        post_with_query(&service, "/v2/state/active-contracts", &[], &acs_req)
    });
    assert_eq!(ws_style.status, 200);
    assert_eq!(parse_body(&ws_style).as_array().expect("array").len(), 6);
}

#[cfg(feature = "protocol")]
#[test]
fn canton_conf_reads_websocket_list_limits_and_rejects_invalid_values() {
    let dir = std::env::temp_dir().join(format!(
        "canton-conf-ws-limit-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let valid_conf = dir.join("valid.conf");
    std::fs::write(
        &valid_conf,
        r#"
        canton.participants.p1 {
          http-ledger-api {
            port = 7575
            websocket-config {
              http-list-max-elements-limit = 200
              http-list-wait-time = 500ms
            }
          }
        }
        "#,
    )
    .expect("write valid.conf");
    let parsed = ledger_json_api::canton_conf::read(&valid_conf, Some("p1"), None, None)
        .expect("parse websocket-config");
    assert_eq!(parsed.http_list_max_elements_limit, Some(200));
    assert_eq!(parsed.http_list_wait_time_ms, Some(500));

    // Negative control: negative http-list-max-elements-limit is rejected.
    let invalid_conf = dir.join("invalid.conf");
    std::fs::write(
        &invalid_conf,
        r#"
        canton.participants.p1 {
          http-ledger-api.websocket-config.http-list-max-elements-limit = -5
        }
        "#,
    )
    .expect("write invalid.conf");
    let err = ledger_json_api::canton_conf::read(&invalid_conf, Some("p1"), None, None)
        .err()
        .expect("negative limit must fail");
    assert!(err.contains("negative http-ledger-api"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
