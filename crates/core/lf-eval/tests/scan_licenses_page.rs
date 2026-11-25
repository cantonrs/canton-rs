//! S-SPL-029: the page token of `GET /v0/admin/validator/licenses` is the scan store's event number, which the update history alone gives.
//!
//! `tests/oracle/splice-scan-fresh/` holds what the official Splice 0.10.1 scan app answered on a freshly started LocalNet next to the update
//! history it answered from (`scripts/splice-scan-state.py`, both taken in one round). Docker-free.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_eval::scan_state::Acs;
use std::path::Path;

fn load(name: &str) -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/splice-scan-fresh")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn the_license_page_and_its_token_follow_from_the_history() {
    let history = load("updates.json");
    let updates = history
        .get("transactions")
        .unwrap_or(&history)
        .as_array()
        .unwrap()
        .clone();
    let acs = Acs::from_updates(&updates).unwrap();
    let answers = load("answers.json");
    let official = &answers["validator-licenses"]["answer"];
    let (page, token) = acs.page_descending("Splice.ValidatorLicense:ValidatorLicense", None, 100);
    let ids: Vec<&str> = page.iter().map(|c| c.contract_id.as_str()).collect();
    let official_ids: Vec<&str> = official["validator_licenses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["contract_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, official_ids, "newest first, the active ones");
    assert_eq!(token, official["next_page_token"].as_u64());
    // the next page starts below the token: nothing is left, and an empty page has no token
    let (rest, none) = acs.page_descending("Splice.ValidatorLicense:ValidatorLicense", token, 100);
    assert!(rest.is_empty() && none.is_none());
    // a page of one: the newest, with its own number as the token
    let (one, one_token) = acs.page_descending("Splice.ValidatorLicense:ValidatorLicense", None, 1);
    assert_eq!(one[0].contract_id, official_ids[0]);
    assert_eq!(one_token, Some(one[0].event_number));
}

/// The older capture (`tests/oracle/splice-scan`, 65 updates, with transient contracts) has the token 36 for its three licenses.
#[test]
fn the_token_of_the_older_capture_counts_no_transient_contract() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/splice-scan");
    let history: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(base.join("updates.json")).unwrap()).unwrap();
    let updates = history
        .get("transactions")
        .unwrap_or(&history)
        .as_array()
        .unwrap()
        .clone();
    let answers: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(base.join("answers.json")).unwrap()).unwrap();
    let official = &answers["validator-licenses"]["answer"];
    let acs = Acs::from_updates(&updates).unwrap();
    let (page, token) = acs.page_descending("Splice.ValidatorLicense:ValidatorLicense", None, 100);
    let ids: Vec<&str> = page.iter().map(|c| c.contract_id.as_str()).collect();
    let official_ids: Vec<&str> = official["validator_licenses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["contract_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, official_ids);
    assert_eq!(token, official["next_page_token"].as_u64());
}
