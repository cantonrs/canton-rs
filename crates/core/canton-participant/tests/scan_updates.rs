//! G8 (AT-S06): the Rust scan answers page requests and cursors over a network's update history as the official Splice 0.10.1 scan app
//! answered them over the same history (`tests/oracle/splice-replay/updates.json` and `scan-cases.jsonl`, recorded by
//! `scripts/verify-splice-replay.sh --update` from the official LocalNet): the status, the update ids of each page in order, the JSON of
//! each error and the text of each malformed-request answer.
use canton_participant::scan_api::{Answer, UpdateHistory};
use serde_json::Value as Json;

fn oracle(file: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/splice-replay")
        .join(file);
    std::fs::read_to_string(path).expect("the recording")
}

fn ids(updates: &[Json]) -> Vec<&str> {
    updates
        .iter()
        .filter_map(|u| u["update_id"].as_str())
        .collect()
}

#[test]
fn the_rust_scan_answers_page_requests_as_the_official_scan_did() {
    let history: Json = serde_json::from_str(&oracle("updates.json")).unwrap();
    let history = UpdateHistory::new(history["transactions"].as_array().unwrap().clone());
    let mut checked = 0;
    for line in oracle("scan-cases.jsonl").lines() {
        let case: Json = serde_json::from_str(line).unwrap();
        let name = case["name"].as_str().unwrap();
        let ours = match case["method"].as_str().unwrap() {
            "POST" => history.updates(case["body"].as_str().unwrap()),
            _ => history.update(
                case["path"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("/v2/updates/"),
            ),
        };
        assert_eq!(
            u64::from(ours.status()),
            case["status"].as_u64().unwrap(),
            "{name}: {ours:?}"
        );
        let theirs = &case["answer"];
        match &ours {
            Answer::Page(updates) => {
                let expected: Vec<&str> = theirs["ids"]
                    .as_array()
                    .expect(name)
                    .iter()
                    .filter_map(Json::as_str)
                    .collect();
                assert_eq!(ids(updates), expected, "{name}");
            }
            Answer::Update(update) => assert_eq!(theirs["ids"][0], update["update_id"], "{name}"),
            Answer::Error(_, text) => assert_eq!(
                theirs["json"]["error"].as_str(),
                Some(text.as_str()),
                "{name}"
            ),
            Answer::Malformed(text) => {
                assert_eq!(theirs["text"].as_str(), Some(text.as_str()), "{name}")
            }
        }
        checked += 1;
    }
    assert!(checked >= 29, "every recorded case: {checked}");
}

/// Paging to the end with any page size gives every update once, in the history's order (no update lost or repeated at a page boundary).
#[test]
fn paging_through_the_history_gives_every_update_once() {
    let history: Json = serde_json::from_str(&oracle("updates.json")).unwrap();
    let all = history["transactions"].as_array().unwrap().clone();
    let expected = ids(&all).into_iter().map(String::from).collect::<Vec<_>>();
    let history = UpdateHistory::new(all);
    for page_size in [1, 2, 7, 1000] {
        let (mut seen, mut after) = (Vec::new(), None::<(i64, String)>);
        loop {
            let body = match &after {
                None => serde_json::json!({"page_size": page_size}),
                Some((m, t)) => {
                    serde_json::json!({"page_size": page_size, "after": {"after_migration_id": m, "after_record_time": t}})
                }
            };
            let Answer::Page(page) = history.updates(&body.to_string()) else {
                panic!("a page")
            };
            let Some(last) = page.last() else { break };
            after = Some((
                last["migration_id"].as_i64().unwrap(),
                last["record_time"].as_str().unwrap().to_string(),
            ));
            seen.extend(ids(&page).into_iter().map(String::from));
        }
        assert_eq!(seen, expected, "page size {page_size}");
    }
}

/// The same recorded cases through the HTTP layer: the `/api/scan` prefix, a page as `{"transactions": [...]}`, errors as JSON, malformed
/// requests as plain text.
#[test]
fn the_http_layer_answers_the_recorded_cases() {
    let history: Json = serde_json::from_str(&oracle("updates.json")).unwrap();
    let history = UpdateHistory::new(history["transactions"].as_array().unwrap().clone());
    let mut checked = 0;
    for line in oracle("scan-cases.jsonl").lines() {
        let case: Json = serde_json::from_str(line).unwrap();
        let name = case["name"].as_str().unwrap();
        let path = format!("/api/scan{}", case["path"].as_str().unwrap());
        let response = history.handle(
            case["method"].as_str().unwrap(),
            &path,
            case["body"].as_str().unwrap_or(""),
        );
        assert_eq!(
            u64::from(response.status),
            case["status"].as_u64().unwrap(),
            "{name}"
        );
        let theirs = &case["answer"];
        if let Some(text) = theirs["text"].as_str() {
            assert_eq!(response.body, text, "{name}");
            assert!(response.content_type.starts_with("text/plain"), "{name}");
        } else {
            let body: Json = serde_json::from_str(&response.body).unwrap();
            if let Some(ids) = theirs["ids"].as_array() {
                let got: Vec<&str> = match body["transactions"].as_array() {
                    Some(page) => page
                        .iter()
                        .filter_map(|u| u["update_id"].as_str())
                        .collect(),
                    None => body["update_id"].as_str().into_iter().collect(),
                };
                let want: Vec<&str> = ids.iter().filter_map(Json::as_str).collect();
                assert_eq!(got, want, "{name}");
            } else {
                assert_eq!(body, theirs["json"], "{name}");
            }
        }
        checked += 1;
    }
    assert!(checked >= 29, "{checked}");
    // paths the recording does not cover
    assert_eq!(
        history.handle("POST", "/v2/updates", "{}").status,
        404,
        "no prefix"
    );
    assert_eq!(
        history.handle("GET", "/api/scan/v2/updates", "").status,
        405
    );
    assert_eq!(history.handle("GET", "/api/scan/nope", "").status, 404);
}
