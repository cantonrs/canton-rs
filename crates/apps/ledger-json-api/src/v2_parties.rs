//! S-API-008: `PATCH /v2/parties/{party}` (update of a party's local metadata), checked against the Canton 3.7.2 sandbox
//! by `scripts/verify-json-api.sh`.
//!
//! [CANTON-NOTE: SEMANTICS] The only mutable part of a party is its local metadata (annotations). The update mask names
//! the parts to change; every successful update raises the resource version, also when the named path changes nothing
//! (`is_local`, `party`, `identity_provider_id` are accepted and only bump the version, measured).
use serde_json::{json, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2::party_json;
use crate::v2_commands::{bad_body, canton_error, Kind};

#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn err(
    definite: bool,
    field: Option<&'static str>,
    status: u16,
    code: &str,
    cause: String,
    category: u64,
    grpc: u64,
    resources: Json,
    retry: Option<&'static str>,
) -> HttpResponse {
    canton_error(
        Kind::Ctx {
            submission: false,
            definite,
            field,
            retry,
        },
        status,
        code,
        cause,
        category,
        grpc,
        resources,
    )
}

/// `PATCH /v2/parties/{party}`.
pub fn update(service: &ExecutionService, req: &HttpRequest, party: &str) -> HttpResponse {
    let Ok(body) = serde_json::from_slice::<Json>(&req.body) else {
        return bad_body("Invalid value for: body".to_string());
    };
    let details = body.get("partyDetails").filter(|d| d.is_object());
    let body_party = details.and_then(|d| d.get("party")).and_then(Json::as_str);
    if body_party != Some(party) {
        // Canton renders the body as a Scala `Option[PartyDetails(party, isLocal, Option[meta], identityProviderId)]`;
        // only a body without local metadata was measured
        let shown = details.map_or("None".to_string(), |d| {
            format!(
                "Some(PartyDetails({},{},None,{}))",
                body_party.unwrap_or(""),
                d.get("isLocal").and_then(Json::as_bool).unwrap_or(false),
                d.get("identityProviderId")
                    .and_then(Json::as_str)
                    .unwrap_or("")
            )
        });
        return canton_error(
            Kind::Preprocessing,
            400,
            "INVALID_ARGUMENT",
            format!(
                "The submitted request has invalid arguments: {party} does not match party in body {shown}"
            ),
            8,
            3,
            json!([]),
        );
    }
    let details = details.cloned().unwrap_or(Json::Null);
    let Some(mask) = body.get("updateMask").filter(|m| m.is_object()) else {
        return err(
            true,
            Some("update_mask"),
            400,
            "MISSING_FIELD",
            "The submitted command is missing a mandatory field: update_mask".into(),
            8,
            3,
            json!([]),
            None,
        );
    };
    let paths: Vec<&str> = mask
        .get("paths")
        .and_then(Json::as_array)
        .map(|a| a.iter().filter_map(Json::as_str).collect())
        .unwrap_or_default();
    let invalid = |why: &str| {
        err(
            false,
            None,
            400,
            "INVALID_PARTY_DETAILS_UPDATE_REQUEST",
            format!("Update operation for party '{party}' failed due to: {why}"),
            8,
            3,
            json!([["PARTY", party]]),
            None,
        )
    };
    if paths.is_empty() {
        return invalid("The update mask contains no entries");
    }
    const KNOWN: [&str; 5] = [
        "local_metadata.annotations",
        "local_metadata",
        "is_local",
        "party",
        "identity_provider_id",
    ];
    if let Some(bad) = paths.iter().find(|p| !KNOWN.contains(p)) {
        return invalid(&format!(
            "The update path: '{bad}' points to an unknown field."
        ));
    }
    let state = service.v2_state();
    let known = state
        .parties
        .lock()
        .map(|p| p.iter().any(|x| x == party))
        .unwrap_or(false);
    if !known {
        return err(
            true,
            None,
            404,
            "PARTY_NOT_FOUND",
            format!("Party: '{party}' was not found when updating a party record"),
            11,
            5,
            json!([["PARTY", party]]),
            None,
        );
    }
    let mut metas = state.party_meta.lock().expect("party meta lock");
    let own = party == state.participant_id();
    let (version, annotations) = metas
        .entry(party.to_string())
        .or_insert_with(|| (0, Default::default()));
    let sent = details
        .pointer("/localMetadata/resourceVersion")
        .and_then(Json::as_str)
        .unwrap_or("");
    let current = if own && *version == 0 {
        String::new()
    } else {
        version.to_string()
    };
    if !sent.is_empty() && sent != current {
        return err(
            false,
            None,
            409,
            "CONCURRENT_PARTY_DETAILS_UPDATE_DETECTED",
            format!("Update operation for party '{party}' failed due to a concurrent update to the same party"),
            2,
            10,
            json!([["PARTY", party]]),
            Some("1 second"),
        );
    }
    if paths
        .iter()
        .any(|p| *p == "local_metadata.annotations" || *p == "local_metadata")
    {
        // annotations merge: a key with an empty value is removed, the others are set; the rest stay
        for (k, v) in details
            .pointer("/localMetadata/annotations")
            .and_then(Json::as_object)
            .into_iter()
            .flatten()
        {
            match v.as_str() {
                Some("") | None => {
                    annotations.remove(k);
                }
                Some(s) => {
                    annotations.insert(k.clone(), s.to_string());
                }
            }
        }
    }
    *version += 1;
    drop(metas);
    HttpResponse::json(
        200,
        &json!({ "partyDetails": party_json(state, party, own) }),
    )
}
