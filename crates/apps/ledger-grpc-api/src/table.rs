//! The map from a Ledger API v2 gRPC method to the JSON API request that answers it. Every method of the covered services is
//! a thin adapter: the request message becomes a JSON API request (path, query, body), the JSON API response (or error)
//! becomes the response message (or status).
use serde_json::{json, Value as Json};

pub enum Body {
    None,
    Json(Json),
    Bytes(Vec<u8>),
}

pub struct Plan {
    pub method: &'static str,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Body,
}

fn s(req: &Json, key: &str) -> String {
    req.get(key)
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string()
}

fn q(pairs: &[(&str, String)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

fn num(req: &Json, key: &str) -> String {
    req.get(key)
        .map(|v| match v {
            Json::String(t) => t.clone(),
            other => other.to_string(),
        })
        .filter(|t| t != "0")
        .unwrap_or_default()
}

fn get(path: String, query: Vec<(String, String)>) -> Plan {
    Plan {
        method: "GET",
        path,
        query,
        body: Body::None,
    }
}

fn post(path: &str, body: Json) -> Plan {
    Plan {
        method: "POST",
        path: path.to_string(),
        query: vec![],
        body: Body::Json(body),
    }
}

fn with(method: &'static str, path: String, body: Json) -> Plan {
    Plan {
        method,
        path,
        query: vec![],
        body: Body::Json(body),
    }
}

pub fn encode(part: &str) -> String {
    part.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

/// The JSON API request that answers `rpc` (`Service/Method`, the service without its package) for `req` (the request
/// message in the Canton JSON encoding), or `None` for a method this server does not answer.
pub fn plan(rpc: &str, req: &Json, proto: &Json) -> Option<Plan> {
    let idp = |p: &str| {
        q(&[
            ("identity-provider-id", s(req, "identityProviderId")),
            (p, String::new()),
        ])
    };
    Some(match rpc {
        "VersionService/GetLedgerApiVersion" => get("/v2/version".into(), vec![]),
        "StateService/GetLedgerEnd" => get("/v2/state/ledger-end".into(), vec![]),
        "StateService/GetConnectedSynchronizers" => {
            get("/v2/state/connected-synchronizers".into(), vec![])
        }
        "StateService/GetLatestPrunedOffsets" => {
            get("/v2/state/latest-pruned-offsets".into(), vec![])
        }
        "StateService/ConvertRecordTimeToOffset" => get(
            "/v2/state/convert-record-time-to-offset".into(),
            q(&[
                ("record-time", s(req, "recordTime")),
                ("synchronizer-id", s(req, "synchronizerId")),
            ]),
        ),
        "StateService/GetActiveContractsPage" => {
            post("/v2/state/active-contracts-page", req.clone())
        }
        "PackageService/ListPackages" => get("/v2/packages".into(), vec![]),
        "PackageService/GetPackage" => get(
            format!("/v2/packages/{}", encode(&s(req, "packageId"))),
            vec![],
        ),
        "PackageService/GetPackageStatus" => get(
            format!("/v2/packages/{}/status", encode(&s(req, "packageId"))),
            vec![],
        ),
        "PackageService/ListVettedPackages" => post("/v2/package-vetting/list", req.clone()),
        "admin.PackageManagementService/UploadDarFile" => Plan {
            method: "POST",
            path: "/v2/dars".into(),
            query: vec![],
            body: Body::Bytes(decode_bytes(req.get("darFile"))),
        },
        "admin.PackageManagementService/ValidateDarFile" => Plan {
            method: "POST",
            path: "/v2/dars/validate".into(),
            query: vec![],
            body: Body::Bytes(decode_bytes(req.get("darFile"))),
        },
        "admin.PackageManagementService/UpdateVettedPackages" => {
            post("/v2/package-vetting/update", req.clone())
        }
        "admin.PartyManagementService/GetParticipantId" => {
            get("/v2/parties/participant-id".into(), vec![])
        }
        "admin.PartyManagementService/ListKnownParties" => get(
            "/v2/parties".into(),
            q(&[
                ("pageSize", num(req, "pageSize")),
                ("pageToken", s(req, "pageToken")),
            ]),
        ),
        "admin.PartyManagementService/AllocateParty" => post("/v2/parties", req.clone()),
        "admin.PartyManagementService/GenerateExternalPartyTopology" => {
            post("/v2/parties/external/generate-topology", req.clone())
        }
        "admin.PartyManagementService/AllocateExternalParty" => {
            post("/v2/parties/external/allocate", req.clone())
        }
        "admin.PartyManagementService/UpdatePartyDetails" => with(
            "PATCH",
            format!(
                "/v2/parties/{}",
                encode(
                    req.pointer("/partyDetails/party")
                        .and_then(Json::as_str)
                        .unwrap_or("")
                )
            ),
            req.clone(),
        ),
        "admin.UserManagementService/CreateUser" => post("/v2/users", req.clone()),
        "admin.UserManagementService/GetUser" => {
            get(format!("/v2/users/{}", encode(&s(req, "userId"))), idp(""))
        }
        "admin.UserManagementService/UpdateUser" => with(
            "PATCH",
            format!(
                "/v2/users/{}",
                encode(req.pointer("/user/id").and_then(Json::as_str).unwrap_or(""))
            ),
            req.clone(),
        ),
        "admin.UserManagementService/DeleteUser" => Plan {
            method: "DELETE",
            path: format!("/v2/users/{}", encode(&s(req, "userId"))),
            query: idp(""),
            body: Body::None,
        },
        "admin.UserManagementService/ListUsers" => get(
            "/v2/users".into(),
            q(&[
                ("pageSize", num(req, "pageSize")),
                ("pageToken", s(req, "pageToken")),
            ]),
        ),
        "admin.UserManagementService/GrantUserRights" => with(
            "POST",
            format!("/v2/users/{}/rights", encode(&s(req, "userId"))),
            req.clone(),
        ),
        "admin.UserManagementService/RevokeUserRights" => with(
            "PATCH",
            format!("/v2/users/{}/rights", encode(&s(req, "userId"))),
            req.clone(),
        ),
        "admin.UserManagementService/ListUserRights" => get(
            format!("/v2/users/{}/rights", encode(&s(req, "userId"))),
            idp(""),
        ),
        "admin.UserManagementService/UpdateUserIdentityProviderId" => with(
            "PATCH",
            format!(
                "/v2/users/{}/identity-provider-id",
                encode(&s(req, "userId"))
            ),
            req.clone(),
        ),
        "admin.IdentityProviderConfigService/CreateIdentityProviderConfig" => {
            post("/v2/idps", req.clone())
        }
        "admin.IdentityProviderConfigService/GetIdentityProviderConfig" => get(
            format!("/v2/idps/{}", encode(&s(req, "identityProviderId"))),
            vec![],
        ),
        "admin.IdentityProviderConfigService/UpdateIdentityProviderConfig" => with(
            "PATCH",
            format!(
                "/v2/idps/{}",
                encode(
                    req.pointer("/identityProviderConfig/identityProviderId")
                        .and_then(Json::as_str)
                        .unwrap_or("")
                )
            ),
            req.clone(),
        ),
        "admin.IdentityProviderConfigService/ListIdentityProviderConfigs" => {
            get("/v2/idps".into(), vec![])
        }
        "admin.IdentityProviderConfigService/DeleteIdentityProviderConfig" => Plan {
            method: "DELETE",
            path: format!("/v2/idps/{}", encode(&s(req, "identityProviderId"))),
            query: vec![],
            body: Body::None,
        },
        "admin.ParticipantPruningService/Prune" => post(
            "/v2/admin/prune",
            json!({ "pruneUpTo": req.get("pruneUpTo").cloned().unwrap_or(Json::Null) }),
        ),
        "CommandService/SubmitAndWait" => post(
            "/v2/commands/submit-and-wait",
            js_commands(&proto["commands"]),
        ),
        "CommandService/SubmitAndWaitForTransaction" => post(
            "/v2/commands/submit-and-wait-for-transaction",
            json!({ "commands": js_commands(&proto["commands"]), "transactionFormat": req.get("transactionFormat").cloned().unwrap_or(Json::Null) }),
        ),
        "CommandSubmissionService/Submit" => {
            post("/v2/commands/async/submit", js_commands(&proto["commands"]))
        }
        "ContractService/GetContract" => post("/v2/contracts/contract-by-id", req.clone()),
        "EventQueryService/GetEventsByContractId" => {
            post("/v2/events/events-by-contract-id", req.clone())
        }
        "StateService/GetActiveContracts" => post("/v2/state/active-contracts", req.clone()),
        "UpdateService/GetUpdates" => post("/v2/updates", req.clone()),
        "UpdateService/GetUpdatesPage" => post("/v2/updates/get-updates-page", req.clone()),
        "UpdateService/GetUpdateById" => post("/v2/updates/update-by-id", req.clone()),
        "UpdateService/GetUpdateByOffset" => post("/v2/updates/update-by-offset", req.clone()),
        "UpdateService/GetUpdateByHash" => post("/v2/updates/update-by-hash", req.clone()),
        "CommandCompletionService/CompletionStream" => {
            post("/v2/commands/completions", req.clone())
        }
        "CommandCompletionService/GetCompletions" => {
            post("/v2/commands/command-completions", req.clone())
        }
        "CommandCompletionService/GetCompletionByHash" => {
            post("/v2/commands/completion-by-hash", req.clone())
        }
        "interactive.InteractiveSubmissionService/PrepareSubmission" => {
            let mut body = js_commands(proto);
            if let Some(m) = body.as_object_mut() {
                m.entry("commandId").or_insert_with(|| json!(""));
                m.entry("actAs").or_insert_with(|| json!([]));
                m.entry("synchronizerId").or_insert_with(|| json!(""));
                m.entry("packageIdSelectionPreference")
                    .or_insert_with(|| json!([]));
            }
            post("/v2/interactive-submission/prepare", body)
        }
        "interactive.InteractiveSubmissionService/ExecuteSubmission"
        | "interactive.InteractiveSubmissionService/ExecuteSubmissionAndWait"
        | "interactive.InteractiveSubmissionService/ExecuteSubmissionAndWaitForTransaction" => {
            let path = match rpc {
                "interactive.InteractiveSubmissionService/ExecuteSubmission" => {
                    "/v2/interactive-submission/execute"
                }
                "interactive.InteractiveSubmissionService/ExecuteSubmissionAndWait" => {
                    "/v2/interactive-submission/executeAndWait"
                }
                _ => "/v2/interactive-submission/executeAndWaitForTransaction",
            };
            let mut body = req.clone();
            let period = deduplication_period(req).unwrap_or_else(|| json!({ "Empty": {} }));
            if let Some(m) = body.as_object_mut() {
                m.remove("deduplicationDuration");
                m.remove("deduplicationOffset");
                m.entry("deduplicationPeriod").or_insert(period);
            }
            post(path, body)
        }
        _ => return None,
    })
}

pub(crate) fn decode_base64_str(text: &str) -> Vec<u8> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.trim_end_matches('=').bytes() {
        let Some(v) = B64.iter().position(|b| *b == c) else {
            continue;
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

/// A `bytes` field in protobuf JSON is base64.
fn decode_bytes(v: Option<&Json>) -> Vec<u8> {
    decode_base64_str(v.and_then(Json::as_str).unwrap_or(""))
}

/// The JSON API answer as the response message(s) in Canton JSON encoding: a list for a server-streaming method.
pub fn response_items(
    rpc: &str,
    body: &[u8],
    headers: &std::collections::HashMap<String, String>,
) -> Vec<Json> {
    if rpc == "admin.ParticipantPruningService/Prune" {
        return vec![json!({})];
    }
    if rpc == "PackageService/GetPackage" {
        let hash = headers
            .get("Canton-Package-Hash")
            .cloned()
            .unwrap_or_default();
        return vec![json!({
            "hashFunction": "HASH_FUNCTION_SHA256",
            "hash": hash,
            "archivePayload": encode_base64(body)
        })];
    }
    let parsed: Json = serde_json::from_slice(body).unwrap_or(Json::Null);
    match parsed {
        Json::Array(items) => items,
        Json::Null => vec![json!({})],
        other => vec![other],
    }
}

pub(crate) fn encode_base64(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// A `Value` message (protobuf JSON) as the Canton JSON API writes a Daml value: records as objects, numerics, 64-bit
/// integers and timestamps as strings, optionals as the value or `null`.
pub fn value_to_json(v: &Json) -> Json {
    let Some(obj) = v.as_object() else {
        return v.clone();
    };
    let Some((kind, x)) = obj.iter().next() else {
        return Json::Null;
    };
    match kind.as_str() {
        "unit" => json!({}),
        "int64" | "numeric" | "text" | "party" | "contractId" | "bool" | "timestamp" | "date" => {
            match x {
                Json::Number(n) if kind == "int64" => Json::String(n.to_string()),
                other => other.clone(),
            }
        }
        "list" => Json::Array(
            x.get("elements")
                .and_then(Json::as_array)
                .map(|a| a.iter().map(value_to_json).collect())
                .unwrap_or_default(),
        ),
        "optional" => x.get("value").map(value_to_json).unwrap_or(Json::Null),
        "record" => record_to_json(x),
        "textMap" => Json::Object(
            x.get("entries")
                .and_then(Json::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|e| {
                            Some((
                                e.get("key")?.as_str()?.to_string(),
                                value_to_json(e.get("value")?),
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default(),
        ),
        "variant" => {
            json!({ "tag": x.get("constructor").cloned().unwrap_or(Json::Null), "value": x.get("value").map(value_to_json).unwrap_or(Json::Null) })
        }
        "enum" => x.get("constructor").cloned().unwrap_or(Json::Null),
        _ => x.clone(),
    }
}

/// A `Record` message as a JSON object keyed by field label.
pub fn record_to_json(r: &Json) -> Json {
    Json::Object(
        r.get("fields")
            .and_then(Json::as_array)
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(|f| {
                        Some((
                            f.get("label")?.as_str()?.to_string(),
                            value_to_json(f.get("value")?),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    )
}

fn template_id(t: &Json) -> String {
    let g = |k: &str| t.get(k).and_then(Json::as_str).unwrap_or("");
    format!("{}:{}:{}", g("packageId"), g("moduleName"), g("entityName"))
}

/// The `deduplication_period` oneof of a `Commands` or `ExecuteSubmissionRequest` message (protobuf JSON:
/// `deduplicationDuration` a `"1.5s"` string, `deduplicationOffset` an integer) as the JSON API's tagged `deduplicationPeriod`.
fn deduplication_period(m: &Json) -> Option<Json> {
    if let Some(d) = m.get("deduplicationDuration").and_then(duration_json) {
        return Some(json!({ "DeduplicationDuration": { "value": d } }));
    }
    let offset = m.get("deduplicationOffset")?;
    let offset = offset.as_i64().or_else(|| offset.as_str()?.parse().ok())?;
    Some(json!({ "DeduplicationOffset": { "value": offset } }))
}

/// A protobuf JSON `google.protobuf.Duration` (`"-1.000000500s"`) as the JSON API's `{seconds, nanos}`.
fn duration_json(v: &Json) -> Option<Json> {
    let text = v.as_str()?.strip_suffix('s')?;
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
    if fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seconds: i64 = whole.parse().ok()?;
    let nanos: i64 = format!("{fraction:0<9}").parse().ok()?;
    let sign = if negative { -1 } else { 1 };
    Some(json!({ "seconds": sign * seconds, "nanos": sign * nanos }))
}

/// The `Commands` message (protobuf JSON) as the flat `JsCommands` the JSON API takes.
pub fn js_commands(c: &Json) -> Json {
    let mut out = serde_json::Map::new();
    for key in [
        "commandId",
        "actAs",
        "readAs",
        "userId",
        "workflowId",
        "submissionId",
        "synchronizerId",
        "packageIdSelectionPreference",
        "maxRecordTime",
        "minLedgerTime",
        "minLedgerTimeAbs",
        "verboseHashing",
        "hashingSchemeVersion",
        "prefetchContractKeys",
        "estimateTrafficCost",
        "tapsMaxPasses",
    ] {
        if let Some(v) = c.get(key) {
            out.insert(key.to_string(), v.clone());
        }
    }
    if let Some(rel) = c.get("minLedgerTimeRel").and_then(duration_json) {
        out.insert("minLedgerTimeRel".into(), rel);
    }
    if let Some(period) = deduplication_period(c) {
        out.insert("deduplicationPeriod".into(), period);
    }
    if let Some(dcs) = c.get("disclosedContracts").and_then(Json::as_array) {
        let converted: Vec<Json> = dcs
            .iter()
            .map(|d| {
                let mut m = d.as_object().cloned().unwrap_or_default();
                if let Some(tid) = m.get("templateId").filter(|t| t.is_object()) {
                    m.insert("templateId".into(), Json::String(template_id(tid)));
                }
                Json::Object(m)
            })
            .collect();
        out.insert("disclosedContracts".into(), Json::Array(converted));
    }
    let commands: Vec<Json> = c
        .get("commands")
        .and_then(Json::as_array)
        .map(|cs| {
            cs.iter()
                .filter_map(|cmd| {
                    if let Some(x) = cmd.get("create") {
                        Some(json!({ "CreateCommand": {
                            "templateId": template_id(&x["templateId"]),
                            "createArguments": record_to_json(&x["createArguments"]) } }))
                    } else if let Some(x) = cmd.get("exercise") {
                        Some(json!({ "ExerciseCommand": {
                            "templateId": template_id(&x["templateId"]),
                            "contractId": x["contractId"],
                            "choice": x["choice"],
                            "choiceArgument": value_to_json(&x["choiceArgument"]) } }))
                    } else if let Some(x) = cmd.get("exerciseByKey") {
                        Some(json!({ "ExerciseByKeyCommand": {
                            "templateId": template_id(&x["templateId"]),
                            "contractKey": value_to_json(&x["contractKey"]),
                            "choice": x["choice"],
                            "choiceArgument": value_to_json(&x["choiceArgument"]) } }))
                    } else {
                        cmd.get("createAndExercise").map(|x| {
                            json!({ "CreateAndExerciseCommand": {
                                "templateId": template_id(&x["templateId"]),
                                "createArguments": record_to_json(&x["createArguments"]),
                                "choice": x["choice"],
                                "choiceArgument": value_to_json(&x["choiceArgument"]) } })
                        })
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    out.insert("commands".into(), Json::Array(commands));
    Json::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_deduplication_period_and_ledger_time_bounds_reach_the_json_api_in_its_shape() {
        let by_duration = js_commands(&json!({
            "commandId": "c", "workflowId": "w", "deduplicationDuration": "1.5s",
            "minLedgerTimeAbs": "2030-01-01T00:00:00Z", "minLedgerTimeRel": "10s"
        }));
        assert_eq!(
            by_duration["deduplicationPeriod"],
            json!({ "DeduplicationDuration": { "value": { "seconds": 1, "nanos": 500_000_000 } } })
        );
        assert_eq!(by_duration["workflowId"], "w");
        assert_eq!(by_duration["minLedgerTimeAbs"], "2030-01-01T00:00:00Z");
        assert_eq!(
            by_duration["minLedgerTimeRel"],
            json!({ "seconds": 10, "nanos": 0 })
        );
        assert!(by_duration.get("deduplicationDuration").is_none());
        let by_offset = js_commands(&json!({ "commandId": "c", "deduplicationOffset": 42 }));
        assert_eq!(
            by_offset["deduplicationPeriod"],
            json!({ "DeduplicationOffset": { "value": 42 } })
        );
        let execute = plan(
            "interactive.InteractiveSubmissionService/ExecuteSubmission",
            &json!({ "submissionId": "s", "deduplicationDuration": "60s" }),
            &json!({}),
        )
        .expect("execute is mapped");
        let Body::Json(body) = execute.body else {
            panic!("execute posts JSON");
        };
        assert_eq!(
            body["deduplicationPeriod"],
            json!({ "DeduplicationDuration": { "value": { "seconds": 60, "nanos": 0 } } })
        );
    }
}
