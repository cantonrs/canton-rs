//! U-47: the service started on the parties of an official participant's database lists them as the official API does
//! (`scripts/oracle-party-parity.sh` compares the real thing): its uid as the participant id, remote parties with `isLocal: false`, a party without
//! a metadata record with an empty resource version, one with a record with its version and annotations.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use ledger_json_api::service::ExecutionService;
use ledger_json_api::{dispatch_request, HttpRequest};
use serde_json::Value;
use std::collections::BTreeMap;

fn get(service: &ExecutionService, path: &str) -> Value {
    let resp = dispatch_request(
        service,
        &HttpRequest {
            method: "GET".into(),
            path: path.into(),
            query_params: Default::default(),
            headers: Default::default(),
            body: Vec::new(),
        },
    );
    assert_eq!(resp.status, 200);
    serde_json::from_slice(&resp.body).unwrap()
}

#[test]
fn the_parties_of_an_official_database_are_listed_as_the_official_api_lists_them() {
    let service = ExecutionService::new();
    let annotations: BTreeMap<String, String> = [("role".to_string(), "probe".to_string())]
        .into_iter()
        .collect();
    service.adopt_official_parties(
        "participant1::1220aa",
        &[
            ("Holder::1220aa".into(), true),
            ("HubProbe::1220aa".into(), true),
            ("Remote::1220bb".into(), false),
            ("participant1::1220aa".into(), true),
        ],
        &[("HubProbe::1220aa".into(), 1, annotations, String::new())],
    );
    let id = get(&service, "/v2/parties/participant-id");
    assert_eq!(id["participantId"], "participant1::1220aa");
    let list = get(&service, "/v2/parties");
    let parties = list["partyDetails"].as_array().unwrap();
    let names: Vec<&str> = parties
        .iter()
        .map(|p| p["party"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "Holder::1220aa",
            "HubProbe::1220aa",
            "Remote::1220bb",
            "participant1::1220aa"
        ]
    );
    let by = |name: &str| parties.iter().find(|p| p["party"] == name).unwrap();
    assert_eq!(by("Holder::1220aa")["localMetadata"]["resourceVersion"], "");
    assert_eq!(
        by("HubProbe::1220aa")["localMetadata"]["resourceVersion"],
        "1"
    );
    assert_eq!(
        by("HubProbe::1220aa")["localMetadata"]["annotations"]["role"],
        "probe"
    );
    assert_eq!(by("Remote::1220bb")["isLocal"], false);
    assert_eq!(by("Holder::1220aa")["isLocal"], true);
}
