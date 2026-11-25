//! HTTP routing of the Splice app APIs (`handle_splice_http`) and request helpers.

use std::sync::Mutex;

use lf_eval::typed_json::format_timestamp_micros;
use serde_json::{json, Value as Json};

use crate::scan_api::Response;

use super::{SpliceAppError, SpliceAppRuntime};

/// Handle an HTTP request targeting any Splice application service (`SV`, `Validator`, `Wallet`,
/// `Automation`, `Scan`, or health checks).
pub fn handle_splice_http(
    runtime: &Mutex<SpliceAppRuntime>,
    method: &str,
    raw_path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Response {
    let mut rt = match runtime.lock() {
        Ok(guard) => guard,
        Err(e) => {
            return json_response(
                500,
                &json!({ "error": format!("runtime lock poisoned: {e}") }),
            )
        }
    };

    let (full_route, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));
    let body_str = std::str::from_utf8(body).unwrap_or("");

    // Token Standard Registry routing (`/registry/*` and `/api/scan/registry/*`)
    if full_route.starts_with("/registry/") {
        return rt.scan_response(method, raw_path, body_str);
    }
    if full_route.starts_with("/api/scan/registry/") {
        let stripped = &raw_path["/api/scan".len()..];
        return rt.scan_response(method, stripped, body_str);
    }

    // Direct Scan delegation for `/api/scan/*`
    if full_route == "/api/scan" || full_route.starts_with("/api/scan/") {
        return rt.scan_response(method, raw_path, body_str);
    }

    let route = strip_service_prefix(full_route);
    if method == "GET" && route == "/livez" {
        return json_response(200, &json!({ "status": "ok" }));
    }
    if method == "GET" && route == "/metrics" {
        let round = rt
            .latest_open_round_number()
            .ok()
            .map(|r| r.to_string())
            .unwrap_or_default();
        let updates = rt.updates().len();
        let node = escape_prom_label(&rt.config().sv_party);
        let mut body = String::from(
            "# HELP canton_rs_splice_open_round Current OpenMiningRound number observed by Splice\n\
             # TYPE canton_rs_splice_open_round gauge\n",
        );
        if !round.is_empty() {
            body.push_str(&format!(
                "canton_rs_splice_open_round{{node=\"{node}\"}} {round}\n"
            ));
        }
        body.push_str(
            "# HELP canton_rs_scan_updates_ingested_total Cumulative ledger updates ingested by Scan / Splice apps\n\
             # TYPE canton_rs_scan_updates_ingested_total counter\n",
        );
        body.push_str(&format!(
            "canton_rs_scan_updates_ingested_total{{node=\"{node}\"}} {updates}\n"
        ));
        return Response {
            status: 200,
            content_type: "text/plain; version=0.0.4; charset=utf-8",
            body,
        };
    }
    if method == "GET" && route == "/readyz" {
        return match rt.sync_ledger() {
            Ok(()) => json_response(200, &json!({ "status": "ok" })),
            Err(err) => json_response(
                503,
                &json!({ "status": "not_ready", "reason": err.to_string() }),
            ),
        };
    }

    let route_with_query = if query.is_empty() {
        route.to_string()
    } else {
        format!("{route}?{query}")
    };

    // Bare Scan endpoints without `/api/scan` prefix
    if is_scan_route(route) {
        return rt.scan_response(method, &format!("/api/scan{route_with_query}"), body_str);
    }

    if let Err(err) = rt.sync_ledger() {
        return err.to_response();
    }

    match dispatch_app_route(&mut rt, method, route, query, headers, body_str) {
        Ok(resp) => resp,
        Err(err) => err.to_response(),
    }
}

fn dispatch_app_route(
    rt: &mut SpliceAppRuntime,
    method: &str,
    route: &str,
    query: &str,
    headers: &[(String, String)],
    body_str: &str,
) -> Result<Response, SpliceAppError> {
    let parse_body = || -> Result<Json, SpliceAppError> {
        if body_str.trim().is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_str::<Json>(body_str)
            .map_err(|e| SpliceAppError::BadRequest(format!("invalid JSON body: {e}")))
    };

    match (method, route) {
        // Health & status
        ("GET", "/livez") | ("GET", "/readyz") => {
            Ok(json_response(200, &json!({ "status": "ok" })))
        }
        // the official 0.10.1 validator app's answer (measured, S-G11-001 A5): the release and its commit time
        ("GET", "/version") => Ok(json_response(
            200,
            &json!({ "version": "0.10.1", "commit_ts": "2026-11-05T13:54:19Z" }),
        )),
        ("GET", "/status") => Ok(json_response(
            200,
            &json!({
                "dso_party": rt.config().dso_party,
                "sv_party": rt.config().sv_party,
                "validator_party": rt.config().validator_party,
                "now_micros": rt.now_micros(),
                "now": format_timestamp_micros(rt.now_micros()),
                "active_contracts": rt.active_contract_count(),
                "updates": rt.updates().len(),
                "open_round": rt.latest_open_round_number().ok(),
                "ledger_backend_connected": true,
            }),
        )),

        // Admin automation & time
        ("POST", "/v0/admin/automation/tick") => {
            let report = rt.run_automation_tick()?;
            Ok(json_response(
                200,
                &serde_json::to_value(report).unwrap_or_default(),
            ))
        }
        ("POST", "/v0/admin/time/advance") => {
            let json = parse_body()?;
            let delta = if let Some(us) = json.get("microseconds").and_then(|v| v.as_i64()) {
                us
            } else if let Some(secs) = json.get("seconds").and_then(|v| v.as_i64()) {
                secs.saturating_mul(1_000_000)
            } else {
                return Err(SpliceAppError::BadRequest(
                    "missing 'microseconds' or 'seconds'".into(),
                ));
            };
            let now = rt.advance_time(delta)?;
            let report = if json.get("tick").and_then(|v| v.as_bool()) == Some(true) {
                Some(rt.run_automation_tick()?)
            } else {
                None
            };
            Ok(json_response(
                200,
                &json!({
                    "now_micros": now,
                    "now": format_timestamp_micros(now),
                    "tick_report": report,
                }),
            ))
        }

        // SV endpoints
        ("POST", "/v0/admin/bootstrap") | ("POST", "/v0/admin/Bootstrap") => {
            let out = rt.bootstrap()?;
            Ok(json_response(200, &out))
        }
        ("POST", "/v0/admin/validator/onboarding/prepare") => {
            let json = parse_body()?;
            let expires_in = json["expires_in"].as_u64().unwrap_or(3600);
            let party_hint = json["party_hint"].as_str().map(String::from);
            let secret_override = json["secret"].as_str().map(String::from);
            let secret =
                rt.prepare_validator_onboarding(expires_in, party_hint, secret_override)?;
            Ok(json_response(200, &json!({ "secret": secret })))
        }
        ("POST", "/v0/onboard/validator") | ("POST", "/v0/validator/onboarding") => {
            let json = parse_body()?;
            let party_id = require_str(&json, "party_id")?;
            let secret = require_str(&json, "secret")?;
            let version = json["version"].as_str().unwrap_or("0.10.1");
            let contact_point = json["contact_point"].as_str().unwrap_or("");
            let license_cid = rt.onboard_validator(party_id, secret, version, contact_point)?;
            Ok(json_response(
                200,
                &json!({ "validator_license_contract_id": license_cid }),
            ))
        }
        ("POST", "/v0/admin/sv/voterequest/create") | ("POST", "/v0/admin/sv/voterequests") => {
            let json = parse_body()?;
            let requester = json["requester"].as_str();
            let action = json
                .get("action")
                .cloned()
                .ok_or_else(|| SpliceAppError::BadRequest("missing 'action'".into()))?;
            let url = json["url"].as_str().unwrap_or("");
            let description = json["description"].as_str().unwrap_or("");
            let expiration_micros = json["expiration"]["microseconds"]
                .as_str()
                .and_then(|s| s.parse::<i64>().ok())
                .or_else(|| json["expiration_micros"].as_i64());
            let effective_at = json["effectiveTime"].as_str();
            let cid = rt.request_vote(
                requester,
                action,
                url,
                description,
                expiration_micros,
                effective_at,
            )?;
            Ok(json_response(
                200,
                &json!({ "vote_request_contract_id": cid }),
            ))
        }
        ("GET", "/v0/admin/sv/voterequests") => {
            let reqs = rt.list_vote_requests()?;
            Ok(json_response(
                200,
                &json!({ "dso_rules_vote_requests": reqs }),
            ))
        }
        ("POST", "/v0/admin/sv/votes") => {
            let json = parse_body()?;
            let request_cid = require_str(&json, "vote_request_contract_id")?;
            let accept = json["is_accepted"].as_bool().unwrap_or(true);
            let sv = json["sv"].as_str();
            let url = json["reason_url"].as_str().unwrap_or("");
            let body = json["reason_description"].as_str().unwrap_or("");
            let cid = rt.cast_vote(request_cid, sv, accept, url, body)?;
            Ok(json_response(
                200,
                &json!({ "vote_request_contract_id": cid }),
            ))
        }

        // Validator endpoints
        ("GET", "/v0/validator-user") => {
            let validator = rt.config().validator_party.clone();
            let featured = rt
                .find_contracts("Splice.Amulet:FeaturedAppRight")
                .into_iter()
                .any(|c| {
                    rt.encoded_payload(c)
                        .ok()
                        .and_then(|p| p["provider"].as_str().map(|s| s == validator))
                        .unwrap_or(false)
                });
            Ok(json_response(
                200,
                &json!({
                    "party_id": validator,
                    "user_name": "validator",
                    "featured": featured,
                }),
            ))
        }
        ("POST", "/v0/register") => {
            let json = parse_body()?;
            let user_name = json["username"]
                .as_str()
                .or_else(|| json["name"].as_str())
                .map(String::from)
                .or_else(|| caller_from_request(headers, query, &json))
                .ok_or_else(|| SpliceAppError::BadRequest("missing user identity".into()))?;
            let party_id = rt.register_user(&user_name, json["party_id"].as_str())?;
            Ok(json_response(200, &json!({ "party_id": party_id })))
        }
        ("POST", "/v0/admin/users") => {
            let json = parse_body()?;
            let name = json["name"]
                .as_str()
                .or_else(|| json["username"].as_str())
                .ok_or_else(|| SpliceAppError::BadRequest("missing 'name'".into()))?;
            let party_id = rt.register_user(name, json["party_id"].as_str())?;
            Ok(json_response(200, &json!({ "party_id": party_id })))
        }
        ("GET", "/v0/admin/users") => {
            let usernames = rt.list_users()?;
            Ok(json_response(200, &json!({ "usernames": usernames })))
        }
        ("POST", "/v0/admin/users/offboard") => {
            let json = parse_body()?;
            let username = query_param(query, "username")
                .or_else(|| json["username"].as_str().map(String::from))
                .ok_or_else(|| SpliceAppError::BadRequest("missing 'username'".into()))?;
            rt.offboard_user(&username)?;
            Ok(json_response(200, &json!({})))
        }
        ("POST", "/v0/admin/liveness") => {
            let json = parse_body()?;
            let license_cid = rt.record_validator_liveness(json["validator_party"].as_str())?;
            Ok(json_response(
                200,
                &json!({ "validator_license_contract_id": license_cid }),
            ))
        }
        ("POST", "/v0/admin/transfer-preapprovals") => {
            let json = parse_body()?;
            let receiver = json["receiver_party_id"]
                .as_str()
                .or_else(|| json["receiver"].as_str())
                .ok_or_else(|| SpliceAppError::BadRequest("missing 'receiver_party_id'".into()))?;
            let provider = json["provider_party_id"].as_str();
            let expires_in = json["expires_in_micros"]
                .as_i64()
                .unwrap_or(30 * 24 * 3600 * 1_000_000);
            let cid = rt.create_transfer_preapproval(receiver, provider, expires_in)?;
            Ok(json_response(
                200,
                &json!({ "transfer_preapproval_contract_id": cid }),
            ))
        }
        ("GET", "/v0/admin/transfer-preapprovals") => {
            let mut contracts = Vec::new();
            for c in rt.find_contracts("Splice.AmuletRules:TransferPreapproval") {
                contracts.push(rt.contract_json(c)?);
            }
            Ok(json_response(200, &json!({ "contracts": contracts })))
        }
        ("GET", "/v0/admin/external-party/balance") => {
            let party = query_param(query, "party_id")
                .ok_or_else(|| SpliceAppError::BadRequest("missing 'party_id'".into()))?;
            let bal = rt.external_party_balance(&party)?;
            Ok(json_response(200, &bal))
        }

        // Wallet endpoints
        ("GET", "/v0/wallet/user-status") => {
            let caller = wallet_caller(rt, headers, query, None)?;
            let status = rt.user_status(&caller);
            Ok(json_response(200, &status))
        }
        ("POST", "/v0/wallet/tap") => {
            let json = parse_body()?;
            let amount = require_str(&json, "amount")?;
            let caller = wallet_caller(rt, headers, query, Some(&json))?;
            let cid = rt.tap(&caller, amount)?;
            Ok(json_response(200, &json!({ "contract_id": cid })))
        }
        ("GET", "/v0/wallet/balance") => {
            let caller = wallet_caller(rt, headers, query, None)?;
            let bal = rt.get_balance(&caller)?;
            Ok(json_response(200, &bal))
        }
        ("GET", "/v0/wallet/amulets") => {
            let caller = wallet_caller(rt, headers, query, None)?;
            let res = rt.list_amulets(&caller)?;
            Ok(json_response(200, &res))
        }
        ("POST", "/v0/wallet/transfer-offers") => {
            let json = parse_body()?;
            let caller = wallet_caller(rt, headers, query, Some(&json))?;
            let receiver = require_str(&json, "receiver_party_id")?;
            let amount = require_str(&json, "amount")?;
            let description = json["description"].as_str().unwrap_or("");
            let expires_at = json["expires_at"]
                .as_i64()
                .unwrap_or_else(|| rt.now_micros() + 3600 * 1_000_000);
            let tracking_id = require_str(&json, "tracking_id")?;
            let cid = rt.create_transfer_offer(
                &caller,
                receiver,
                amount,
                description,
                expires_at,
                tracking_id,
            )?;
            Ok(json_response(200, &json!({ "offer_contract_id": cid })))
        }
        ("GET", "/v0/wallet/transfer-offers") => {
            let caller = wallet_caller(rt, headers, query, None)?;
            let offers = rt.list_transfer_offers(&caller)?;
            Ok(json_response(200, &json!({ "offers": offers })))
        }
        ("POST", "/v0/wallet/buy-traffic-requests") => {
            let json = parse_body()?;
            let caller = wallet_caller(rt, headers, query, Some(&json))?;
            let receiving_validator = require_str(&json, "receiving_validator_party_id")?;
            let domain_id = json["domain_id"].as_str();
            let migration_id = json["migration_id"].as_i64().unwrap_or(0);
            let traffic_amount = json["traffic_amount"].as_i64().ok_or_else(|| {
                SpliceAppError::BadRequest("missing integer 'traffic_amount'".into())
            })?;
            let expires_at = json["expires_at"]
                .as_i64()
                .unwrap_or_else(|| rt.now_micros() + 3600 * 1_000_000);
            let tracking_id = require_str(&json, "tracking_id")?;
            let cid = rt.create_buy_traffic_request(
                &caller,
                receiving_validator,
                domain_id,
                migration_id,
                traffic_amount,
                expires_at,
                tracking_id,
            )?;
            Ok(json_response(200, &json!({ "request_contract_id": cid })))
        }
        ("POST", "/v0/wallet/transactions") => {
            let json = parse_body()?;
            let caller = wallet_caller(rt, headers, query, Some(&json))?;
            let begin_after = json["begin_after_id"].as_str();
            let page_size = json["page_size"].as_u64().unwrap_or(100) as usize;
            let items = rt.list_transactions(&caller, begin_after, page_size)?;
            Ok(json_response(200, &json!({ "items": items })))
        }

        // Parameterized paths
        _ => dispatch_parameterized_route(rt, method, route, query, headers, &parse_body),
    }
}

fn dispatch_parameterized_route(
    rt: &mut SpliceAppRuntime,
    method: &str,
    route: &str,
    query: &str,
    headers: &[(String, String)],
    parse_body: &dyn Fn() -> Result<Json, SpliceAppError>,
) -> Result<Response, SpliceAppError> {
    if let Some(rest) = route.strip_prefix("/v0/admin/sv/voterequest/") {
        if let Some(cid) = rest.strip_suffix("/close") {
            if method == "POST" {
                let json = parse_body()?;
                let cid = percent_decode(cid);
                let out = rt.close_vote_request(&cid, json["sv"].as_str())?;
                return Ok(json_response(200, &out));
            }
        } else if method == "GET" {
            let cid = percent_decode(rest);
            let req = rt.lookup_vote_request(&cid)?;
            return Ok(json_response(200, &req));
        }
    }

    if let Some(party_raw) = route.strip_prefix("/v0/admin/transfer-preapprovals/by-party/") {
        let party = percent_decode(party_raw);
        match method {
            "GET" => return Ok(json_response(200, &rt.lookup_transfer_preapproval(&party)?)),
            "DELETE" => {
                rt.cancel_transfer_preapproval(&party, None)?;
                return Ok(json_response(200, &json!({})));
            }
            _ => {}
        }
    }

    if let Some(rest) = route.strip_prefix("/v0/wallet/transfer-offers/") {
        if let Some(cid) = rest.strip_suffix("/accept") {
            if method == "POST" {
                let json = parse_body()?;
                let caller = wallet_caller(rt, headers, query, Some(&json))?;
                let accepted_cid = rt.accept_transfer_offer(&caller, &percent_decode(cid))?;
                return Ok(json_response(
                    200,
                    &json!({ "accepted_offer_contract_id": accepted_cid }),
                ));
            }
        } else if let Some(cid) = rest.strip_suffix("/reject") {
            if method == "POST" {
                let json = parse_body()?;
                let caller = wallet_caller(rt, headers, query, Some(&json))?;
                rt.reject_transfer_offer(&caller, &percent_decode(cid))?;
                return Ok(json_response(200, &json!({})));
            }
        } else if let Some(cid) = rest.strip_suffix("/withdraw") {
            if method == "POST" {
                let json = parse_body()?;
                let caller = wallet_caller(rt, headers, query, Some(&json))?;
                let reason = json["reason"].as_str().unwrap_or("");
                rt.withdraw_transfer_offer(&caller, &percent_decode(cid), reason)?;
                return Ok(json_response(200, &json!({})));
            }
        } else if let Some(tid) = rest.strip_suffix("/status") {
            if matches!(method, "GET" | "POST") {
                let st = rt.transfer_offer_status(&percent_decode(tid))?;
                return Ok(json_response(200, &st));
            }
        }
    }

    if let Some(rest) = route.strip_prefix("/v0/wallet/buy-traffic-requests/") {
        if let Some(tid) = rest.strip_suffix("/status") {
            if matches!(method, "GET" | "POST") {
                let st = rt.buy_traffic_status(&percent_decode(tid))?;
                return Ok(json_response(200, &st));
            }
        }
    }

    Err(SpliceAppError::NotFound(format!(
        "no route for {method} {route}"
    )))
}

fn strip_service_prefix(path: &str) -> &str {
    for prefix in ["/api/sv", "/api/validator", "/api/wallet"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            if rest.is_empty() {
                return "/";
            }
            if rest.starts_with('/') {
                return rest;
            }
        }
    }
    path
}

fn is_scan_route(route: &str) -> bool {
    matches!(
        route,
        "/v2/updates"
            | "/v0/dso"
            | "/v0/dso-party-id"
            | "/v0/amulet-rules"
            | "/v0/ans-rules"
            | "/v0/external-party-amulet-rules"
            | "/v0/amulet-price/votes"
            | "/v0/unclaimed-development-fund-coupons"
            | "/v0/open-and-issuing-mining-rounds"
            | "/v0/closed-rounds"
            | "/v0/admin/validator/licenses"
            | "/v0/featured-apps"
            | "/v0/state/acs"
            | "/v2/state/acs"
    ) || route.starts_with("/v2/updates/")
        || route.starts_with("/v0/events/")
}

pub(super) fn json_response(status: u16, body: &Json) -> Response {
    Response {
        status,
        content_type: "application/json",
        body: body.to_string(),
    }
}

fn escape_prom_label(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn require_str<'a>(json: &'a Json, field: &str) -> Result<&'a str, SpliceAppError> {
    json.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| SpliceAppError::BadRequest(format!("missing string field '{field}'")))
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| percent_decode(v))
}

fn caller_from_request(headers: &[(String, String)], query: &str, body: &Json) -> Option<String> {
    if let Some(p) = query_param(query, "party") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    if let Some(u) = query_param(query, "user") {
        if !u.is_empty() {
            return Some(u);
        }
    }
    if let Some(p) = body.get("party_id").and_then(|v| v.as_str()) {
        if !p.is_empty() {
            return Some(p.to_string());
        }
    }
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("x-wallet-user") || k.eq_ignore_ascii_case("x-user") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        if k.eq_ignore_ascii_case("authorization") {
            let token = v
                .trim()
                .strip_prefix("Bearer ")
                .or_else(|| v.trim().strip_prefix("bearer "))
                .map(str::trim)?;
            if !token.is_empty() {
                if let Some(sub) = extract_jwt_sub(token) {
                    return Some(sub);
                }
                return Some(token.to_string());
            }
        }
    }
    None
}

fn wallet_caller(
    rt: &SpliceAppRuntime,
    headers: &[(String, String)],
    query: &str,
    body: Option<&Json>,
) -> Result<String, SpliceAppError> {
    let empty = json!({});
    let b = body.unwrap_or(&empty);
    let raw = caller_from_request(headers, query, b)
        .unwrap_or_else(|| rt.config().validator_party.clone());
    Ok(rt.resolve_party_or_user(&raw))
}

fn extract_jwt_sub(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let _sig = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let decoded = decode_base64_url(payload_b64)?;
    let json: Json = serde_json::from_slice(&decoded).ok()?;
    json.get("sub")?.as_str().map(String::from)
}

fn decode_base64_url(input: &str) -> Option<Vec<u8>> {
    let mut std = input.replace('-', "+").replace('_', "/");
    while !std.len().is_multiple_of(4) {
        std.push('=');
    }
    lf_eval::fat_contract::decode_strict_base64(&std).ok()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
