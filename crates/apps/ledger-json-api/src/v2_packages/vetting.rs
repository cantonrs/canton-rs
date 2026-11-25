//! Package vetting and preference queries (`vetting_list`, `vetting_update`, `preferred_packages`).

use serde_json::{json, Map, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2_commands::{canton_error, Kind, SYNCHRONIZER};

#[cfg(feature = "protocol")]
use super::PackageRec;
use super::{vetted_json, vetted_packages, Packages};

/// `POST /v2/package-vetting/list`: the packages the participant has vetted on its synchronizer, optionally filtered by
/// package id or by package-name prefix.
pub fn vetting_list(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = serde_json::from_slice(&req.body).unwrap_or(Json::Null);
    let filter = body.get("packageMetadataFilter").unwrap_or(&Json::Null);
    let strings = |key: &str| -> Vec<String> {
        filter
            .get(key)
            .and_then(Json::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let (ids, prefixes) = (strings("packageIds"), strings("packageNamePrefixes"));
    let known = service.v2_state().packages.lock().expect("packages lock");
    let packages: Vec<Json> = known
        .iter()
        .filter(|(id, rec)| {
            rec.vetted
                && (ids.is_empty() || ids.contains(id))
                && (prefixes.is_empty()
                    || prefixes.iter().any(|p| rec.name.starts_with(p.as_str())))
        })
        .map(|(id, rec)| vetted_json(id, rec))
        .collect();
    if packages.is_empty() {
        return HttpResponse::json(200, &json!({ "vettedPackages": [], "nextPageToken": "" }));
    }
    let serial = *service
        .v2_state()
        .vetting_serial
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let sync_id = service
        .connected_synchronizers()
        .into_iter()
        .next()
        .map_or_else(|| SYNCHRONIZER.to_string(), |(_, id)| id);
    HttpResponse::json(
        200,
        &json!({
            "vettedPackages": [{
                "packages": packages,
                "participantId": service.v2_state().participant_id(),
                "synchronizerId": sync_id,
                "topologySerial": serial
            }],
            "nextPageToken": ""
        }),
    )
}

/// Registers DALF packages from an adopted official participant DAR into `v2_state().packages`
/// so `/v2/packages/{id}` and `/v2/package-vetting/list` expose pre-existing vetted packages.
#[cfg(feature = "protocol")]
pub(crate) fn adopt_dar_packages(
    service: &ExecutionService,
    info: &crate::service::DarPackageInfo,
    bytes: &[u8],
) {
    let Ok(payloads) = lf_archive::dalf_payloads(bytes) else {
        return;
    };
    let mut known = service
        .v2_state()
        .packages
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for (id, payload) in payloads {
        if known.contains_key(&id) {
            continue;
        }
        let meta = info.dalfs.iter().find(|d| d.package_id == id);
        known.insert(
            id,
            PackageRec {
                payload,
                name: meta
                    .and_then(|d| d.package_name.clone())
                    .unwrap_or_default(),
                version: meta
                    .and_then(|d| d.package_version.clone())
                    .unwrap_or_default(),
                vetted: true,
                valid_from: None,
                valid_until: None,
            },
        );
    }
}

/// A response whose `context` is exactly the given entries (the errors below each name their own keys).
fn error_with_context(
    status: u16,
    code: &str,
    cause: String,
    category: u64,
    grpc: u64,
    context: &[(&str, String)],
) -> HttpResponse {
    let mut ctx = Map::new();
    for (k, v) in context {
        ctx.insert((*k).to_string(), json!(v));
    }
    ctx.insert("participant".into(), json!("rust"));
    ctx.insert("category".into(), json!(category.to_string()));
    ctx.insert("tid".into(), json!("0000000000000000"));
    HttpResponse::json(
        status,
        &json!({
            "code": code,
            "cause": cause,
            "correlationId": null,
            "traceId": "0000000000000000",
            "context": ctx,
            "resources": [],
            "errorCategory": category,
            "grpcCodeValue": grpc,
            "retryInfo": null,
            "definiteAnswer": null
        }),
    )
}

/// The ids of the packages a vetting reference (`packageId`, or `packageName` and optionally `packageVersion`) names.
fn resolve(known: &Packages, reference: &Json) -> Result<Vec<String>, HttpResponse> {
    let text = |k: &str| reference.get(k).and_then(Json::as_str).unwrap_or("");
    let (id, name, version) = (
        text("packageId"),
        text("packageName"),
        text("packageVersion"),
    );
    let hits: Vec<String> = known
        .iter()
        .filter(|(pid, r)| {
            if id.is_empty() {
                r.name == name && (version.is_empty() || r.version == version)
            } else {
                pid.as_str() == id
            }
        })
        .map(|(pid, _)| pid.clone())
        .collect();
    if !hits.is_empty() {
        return Ok(hits);
    }
    let (reference, reason) = if id.is_empty() {
        (
            format!("package-name: '{name}'"),
            format!("No packages with package name {name}"),
        )
    } else {
        (
            format!("package-id: '{id}'"),
            format!("No packages with package ID {id}"),
        )
    };
    let resp = error_with_context(
        404,
        "UNRESOLVED_VETTING_REFERENCE",
        format!("The vetted package reference {reference} does not match any package in the package store. Reason: {reason}"),
        11,
        5,
        &[("reason", reason), ("reference", reference)],
    );
    Err(resp)
}

/// `POST /v2/package-vetting/update`: vets or unvets packages; the topology serial moves on when the vetted set changes.
pub fn vetting_update(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = serde_json::from_slice(&req.body).unwrap_or(Json::Null);
    let state = service.v2_state();
    let mut known = state.packages.lock().expect("packages lock");
    let mut serial_guard = state.vetting_serial.lock().expect("serial lock");
    let serial = *serial_guard;
    if let Some(expected) = body
        .pointer("/expectedTopologySerial/serial/Prior/value")
        .and_then(Json::as_u64)
    {
        if expected != serial {
            return error_with_context(
                400,
                "TOPOLOGY_SERIAL_MISMATCH",
                format!("The provided serial Some({serial}) did not match the expected serial Some({expected})."),
                9,
                9,
                &[
                    ("expected", format!("Some({expected})")),
                    ("actual", format!("Some({serial})")),
                ],
            );
        }
    }
    let past = vetted_packages(service, &known, serial);
    let mut next = known.clone();
    for change in body
        .get("changes")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
    {
        let Some(op) = change.get("operation").and_then(Json::as_object) else {
            return error_with_context(
                400,
                "PROTO_DESERIALIZATION_FAILURE",
                "Deserialization of protobuf message failed".into(),
                8,
                3,
                &[("reason", "FieldNotSet(operation)".into())],
            );
        };
        let (kind, value) = op
            .iter()
            .next()
            .map(|(k, v)| (k.as_str(), &v["value"]))
            .unwrap_or(("", &Json::Null));
        match kind {
            "Vet" | "Unvet" => {
                let vet = kind == "Vet";
                for reference in value
                    .get("packages")
                    .and_then(Json::as_array)
                    .into_iter()
                    .flatten()
                {
                    let ids = match resolve(&known, reference) {
                        Ok(ids) => ids,
                        Err(r) => return r,
                    };
                    for id in ids {
                        if let Some(rec) = next.get_mut(&id) {
                            rec.vetted = vet;
                            rec.valid_from = vet
                                .then(|| {
                                    value
                                        .get("newValidFromInclusive")
                                        .and_then(Json::as_str)
                                        .map(String::from)
                                })
                                .flatten();
                            rec.valid_until = vet
                                .then(|| {
                                    value
                                        .get("newValidUntilExclusive")
                                        .and_then(Json::as_str)
                                        .map(String::from)
                                })
                                .flatten();
                        }
                    }
                }
            }
            _ => {
                return error_with_context(
                    400,
                    "PROTO_DESERIALIZATION_FAILURE",
                    "Deserialization of protobuf message failed".into(),
                    8,
                    3,
                    &[("reason", "FieldNotSet(operation)".into())],
                )
            }
        }
    }
    let changed = vetted_packages(service, &next, serial)["packages"] != past["packages"];
    let new_serial = if changed { serial + 1 } else { serial };
    let new = vetted_packages(service, &next, new_serial);
    let dry_run = body.get("dryRun").and_then(Json::as_bool).unwrap_or(false);
    if changed && !dry_run {
        *known = next;
        *serial_guard = new_serial;
    }
    HttpResponse::json(
        200,
        &json!({ "pastVettedPackages": past, "newVettedPackages": new }),
    )
}

fn missing(field: &str) -> HttpResponse {
    canton_error(
        Kind::Ctx {
            submission: false,
            definite: true,
            field: None,
            retry: None,
        },
        400,
        "MISSING_FIELD",
        format!("The submitted command is missing a mandatory field: {field}"),
        8,
        3,
        json!([]),
    )
    .with_field(field)
}

trait WithField {
    fn with_field(self, field: &str) -> Self;
}

impl WithField for HttpResponse {
    /// Adds `field_name` to the context of a `MISSING_FIELD` body.
    fn with_field(mut self, field: &str) -> Self {
        if let Ok(mut j) = serde_json::from_slice::<Json>(&self.body) {
            j["context"]["field_name"] = json!(field);
            self.body = j.to_string().into_bytes();
            self.headers
                .insert("Content-Length".into(), self.body.len().to_string());
        }
        self
    }
}

/// `POST /v2/interactive-submission/preferred-packages`: the highest vetted version of each requested package name.
pub fn preferred_packages(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = serde_json::from_slice(&req.body).unwrap_or(Json::Null);
    let reqs: Vec<Json> = body
        .get("packageVettingRequirements")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    if reqs.is_empty() {
        return missing("package_vetting_requirements/packageVettingRequirements");
    }
    for r in &reqs {
        if r.get("parties")
            .and_then(Json::as_array)
            .is_none_or(|p| p.is_empty())
        {
            return missing("parties");
        }
        if r.get("packageName")
            .and_then(Json::as_str)
            .is_none_or(str::is_empty)
        {
            return missing("package_name/packageName");
        }
    }
    if let Some(sync) = body
        .get("synchronizerId")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
    {
        if sync != SYNCHRONIZER {
            let reason = format!(
                "cannot resolve to physical synchronizer; ensure the node is connected to {sync}"
            );
            return error_with_context(
                400,
                "INVALID_PRESCRIBED_SYNCHRONIZER_ID",
                format!("Cannot submit transaction to prescribed synchronizer `{sync}` because: {reason}"),
                9,
                9,
                &[("reason", reason), ("synchronizerId", sync.to_string())],
            );
        }
    }
    let state = service.v2_state();
    let allocated = state.parties.lock().expect("parties lock").clone();
    let unknown: Vec<String> = reqs
        .iter()
        .flat_map(|r| r["parties"].as_array().cloned().unwrap_or_default())
        .filter_map(|p| p.as_str().map(String::from))
        .filter(|p| !allocated.contains(p))
        .collect();
    if !unknown.is_empty() {
        return error_with_context(
            404,
            "UNKNOWN_INFORMEES",
            "The participant is not connected to any synchronizer where the given informees are known.".into(),
            11,
            5,
            &[
                ("unknownInformees", format!("Set({})", unknown.join(", "))),
                ("definite_answer", "false".into()),
            ],
        );
    }
    let known = state.packages.lock().expect("packages lock");
    let names: Vec<String> = reqs
        .iter()
        .filter_map(|r| r["packageName"].as_str().map(String::from))
        .collect();
    let missing_names: Vec<&String> = names
        .iter()
        .filter(|n| !known.values().any(|r| &r.name == *n))
        .collect();
    if !missing_names.is_empty() {
        return canton_error(
            Kind::Ctx { submission: false, definite: true, field: None, retry: None },
            404,
            "PACKAGE_NAMES_NOT_FOUND",
            format!(
                "The following package names do not match upgradable packages uploaded on this participant: [{}].",
                missing_names.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(", ")
            ),
            11,
            5,
            json!([]),
        );
    }
    let mut refs = Vec::new();
    for name in &names {
        let best = known
            .iter()
            .filter(|(_, r)| r.vetted && &r.name == name)
            .max_by(|a, b| a.1.version.cmp(&b.1.version));
        let Some((id, rec)) = best else {
            return canton_error(
                Kind::Ctx { submission: false, definite: true, field: None, retry: None },
                400,
                "NO_PREFERRED_PACKAGES_FOUND",
                format!("Failed to compute package preferences. Reason: No synchronizer satisfies the vetting requirements. Discarded synchronizers: List(({SYNCHRONIZER},No package with package-name '{name}' is consistently vetted by all hosting participants of the requested parties.))"),
                9,
                9,
                json!([]),
            );
        };
        refs.push(
            json!({ "packageId": id, "packageName": rec.name, "packageVersion": rec.version }),
        );
    }
    HttpResponse::json(
        200,
        &json!({ "synchronizerId": SYNCHRONIZER, "packageReferences": refs }),
    )
}

/// `GET` / `POST /v2/package-vetting`: lists vetted packages (`GET`) or updates vetting (`POST`).
pub fn vetting_root(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    if req.method == "POST" {
        return vetting_update(service, req);
    }
    if req.body.is_empty() {
        let mut filter = Map::new();
        if let Some(pkgs) = req.query_params.get("packageIds") {
            let ids: Vec<&str> = pkgs
                .split(['\x1f', ','])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if !ids.is_empty() {
                filter.insert("packageIds".into(), json!(ids));
            }
        }
        let mut list_req = Map::new();
        if !filter.is_empty() {
            list_req.insert("packageMetadataFilter".into(), Json::Object(filter));
        }
        let mut cloned = req.clone();
        cloned.body =
            serde_json::to_vec(&Json::Object(list_req)).unwrap_or_else(|_| b"{}".to_vec());
        vetting_list(service, &cloned)
    } else {
        vetting_list(service, req)
    }
}

/// `GET` / `POST /v2/interactive-submission/preferred-package-version`.
pub fn preferred_package_version(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = if req.body.is_empty() {
        Json::Null
    } else {
        serde_json::from_slice(&req.body).unwrap_or(Json::Null)
    };
    let package_name = req
        .query_params
        .get("package-name")
        .or_else(|| req.query_params.get("packageName"))
        .cloned()
        .or_else(|| {
            body.get("packageName")
                .and_then(Json::as_str)
                .map(String::from)
        })
        .unwrap_or_default();
    if package_name.is_empty() {
        return missing("package-name");
    }
    let sync_param = req
        .query_params
        .get("synchronizer-id")
        .or_else(|| req.query_params.get("synchronizerId"))
        .cloned()
        .or_else(|| {
            body.get("synchronizerId")
                .and_then(Json::as_str)
                .map(String::from)
        })
        .filter(|s| !s.is_empty());
    let state = service.v2_state();
    let active_sync = state.synchronizer_id();
    if let Some(ref sync) = sync_param {
        if sync != &active_sync && sync != SYNCHRONIZER {
            let reason = format!(
                "cannot resolve to physical synchronizer; ensure the node is connected to {sync}"
            );
            return error_with_context(
                400,
                "INVALID_PRESCRIBED_SYNCHRONIZER_ID",
                format!(
                    "Cannot submit transaction to prescribed synchronizer `{sync}` because: {reason}"
                ),
                9,
                9,
                &[("reason", reason), ("synchronizerId", sync.clone())],
            );
        }
    }
    let parties: Vec<String> = req
        .query_params
        .get("parties")
        .map(|raw| {
            raw.split(['\x1f', ','])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_else(|| {
            body.get("parties")
                .and_then(Json::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        });
    if !parties.is_empty() {
        let allocated = state.parties.lock().expect("parties lock").clone();
        let unknown: Vec<String> = parties
            .into_iter()
            .filter(|p| !allocated.contains(p))
            .collect();
        if !unknown.is_empty() {
            return error_with_context(
                404,
                "UNKNOWN_INFORMEES",
                "The participant is not connected to any synchronizer where the given informees are known.".into(),
                11,
                5,
                &[
                    ("unknownInformees", format!("Set({})", unknown.join(", "))),
                    ("definite_answer", "false".into()),
                ],
            );
        }
    }
    let known = state.packages.lock().expect("packages lock");
    let best = known
        .iter()
        .filter(|(_, r)| r.vetted && r.name == package_name)
        .max_by(|a, b| a.1.version.cmp(&b.1.version));
    match best {
        Some((id, rec)) => HttpResponse::json(
            200,
            &json!({
                "packagePreference": {
                    "packageReference": {
                        "packageId": id,
                        "packageName": rec.name,
                        "packageVersion": rec.version
                    },
                    "synchronizerId": sync_param.unwrap_or(active_sync)
                }
            }),
        ),
        None => HttpResponse::json(200, &json!({})),
    }
}
