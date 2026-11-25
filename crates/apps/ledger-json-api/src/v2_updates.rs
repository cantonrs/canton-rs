//! S-API-010: the update and active-contract reads that return many items (`POST /v2/updates`,
//! `/v2/updates/get-updates-page`, `/v2/state/active-contracts-page`), `update-by-hash` and
//! `convert-record-time-to-offset`, checked against the Canton 3.7.2 sandbox by `scripts/verify-json-api.sh`.
//!
//! [CANTON-NOTE: SEMANTICS] The HTTP list endpoints are blocking reads over what the ledger holds: this server answers
//! at once from the committed updates (no waiting for new ones). A page token is opaque to the client; here it is the
//! base64 of a small text (`offset,bound,order` / `index`), not Canton's protobuf. Only transactions in the default
//! ACS_DELTA shape are produced.
use std::sync::atomic::Ordering;

use serde_json::{json, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2::{base64, unbase64};
use crate::v2_commands::{
    bad_body, canton_error, enter_want_blob_for, expand_event_format_filters, Kind, StoredUpdate,
    SYNCHRONIZER,
};
use crate::v2_queries::{
    body_of, missing_field, selected_update_json, update_response, update_selection,
    UpdateSelection,
};

fn ctx_error(
    status: u16,
    code: &str,
    cause: String,
    category: u64,
    grpc: u64,
    retry: Option<&'static str>,
    resources: Json,
) -> HttpResponse {
    canton_error(
        Kind::Ctx {
            submission: false,
            definite: true,
            field: None,
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

thread_local! {
    static UNBOUNDED_STREAM_LIST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Bypasses HTTP `http-list-max-elements-limit` for streaming transports (WebSocket, gRPC)
/// that delegate to blocking HTTP snapshot/list handlers.
pub fn with_unbounded_stream_list<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            UNBOUNDED_STREAM_LIST.with(|c| c.set(self.0));
        }
    }
    let prev = UNBOUNDED_STREAM_LIST.with(|c| c.replace(true));
    let _reset = Reset(prev);
    f()
}

/// Parses the optional `?limit=` non-negative integer query parameter on blocking stream-list routes.
pub(crate) fn parse_stream_list_limit(req: &HttpRequest) -> Result<Option<usize>, HttpResponse> {
    let Some(raw) = req.query_params.get("limit") else {
        return Ok(None);
    };
    let parsed = raw.trim().parse::<usize>().map_err(|_| {
        bad_body(format!(
            "Invalid value for: query parameter limit (Cannot parse {raw:?} as non-negative integer)"
        ))
    })?;
    Ok(Some(parsed))
}

/// Applies `?limit=` and configured `http-list-max-elements-limit` matching Canton `Endpoints.asList`.
///
/// [CANTON-NOTE: SEMANTICS] When `http-list-max-elements-limit` (`L`) is configured on the node, the effective
/// row cap is `min(limit, L + 1)`: returning at most `L` items (including when `limit == L`), or answering
/// `413 Payload Too Large` (`JSON_API_MAXIMUM_LIST_ELEMENTS_NUMBER_REACHED`) when more than `L` items match.
pub(crate) fn finish_stream_list(
    service: &ExecutionService,
    request_limit: Option<usize>,
    mut elements: Vec<Json>,
) -> HttpResponse {
    let unbounded = UNBOUNDED_STREAM_LIST.with(std::cell::Cell::get);
    let sys_limit = if unbounded {
        None
    } else {
        service.http_list_max_elements_limit()
    };
    match sys_limit {
        Some(limit) => {
            let cap = limit.saturating_add(1);
            let take = request_limit.map_or(cap, |rl| rl.min(cap));
            elements.truncate(take);
            if elements.len() > limit {
                return ctx_error(
                    413,
                    "JSON_API_MAXIMUM_LIST_ELEMENTS_NUMBER_REACHED",
                    format!(
                        "The number of matching elements ({}) is greater than the node limit ({limit}).",
                        elements.len()
                    ),
                    2,
                    10,
                    Some("1 second"),
                    json!([]),
                );
            }
            HttpResponse::json(200, &Json::Array(elements))
        }
        None => {
            if let Some(rl) = request_limit {
                elements.truncate(rl);
            }
            HttpResponse::json(200, &Json::Array(elements))
        }
    }
}

fn offset_after_end(label: &str, offset: u64, end: u64) -> HttpResponse {
    ctx_error(
        400,
        "OFFSET_AFTER_LEDGER_END",
        format!("{label} ({offset}) is after ledger end ({end})"),
        12,
        11,
        Some("1 second"),
        json!([]),
    )
}

/// The update under `selection` (`None` when none of its events is visible).
fn visible(
    service: &ExecutionService,
    u: &StoredUpdate,
    selection: &UpdateSelection,
) -> Option<Json> {
    selected_update_json(service, u, selection)
}

fn offset_of(v: &Json) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}

/// `POST /v2/updates`: the updates in `(beginExclusive, endInclusive]` the parties can see.
pub fn updates(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body = match body_of(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let selection = match update_selection(service, &body) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let state = service.v2_state();
    let ledger_end = state.ledger_end.load(Ordering::SeqCst);
    let begin = body.get("beginExclusive").and_then(offset_of).unwrap_or(0);
    let end = body.get("endInclusive").and_then(offset_of);
    if begin > ledger_end {
        return offset_after_end("Begin offset", begin, ledger_end);
    }
    let pruned = state.pruned_up_to.load(Ordering::SeqCst);
    if begin < pruned {
        return crate::v2_prune::pruned_error(
            format!(
                "Transactions request for offset range [{}, {}] precedes pruned offset {pruned}",
                begin + 1,
                end.unwrap_or(ledger_end)
            ),
            pruned,
            None,
        );
    }
    if let Some(e) = end {
        if e < begin {
            return ctx_error(
                400,
                "OFFSET_OUT_OF_RANGE",
                format!("End offset {e} is before begin offset {begin}."),
                9,
                9,
                None,
                json!([]),
            );
        }
    }
    let limit = match parse_stream_list_limit(req) {
        Ok(l) => l,
        Err(resp) => return resp,
    };
    // [CANTON-NOTE: SEMANTICS] A read that finds nothing after its begin offset WAITS for a new update (measured on the node,
    // AT-T07): with `stream_idle_timeout_ms` it returns the first update that arrives, or an empty list once that time has
    // passed without one; a read that finds updates returns them at once. Without the parameter this server waits
    // `http-list-wait-time` if configured in `--canton-conf`, otherwise does not wait.
    let idle = req
        .query_params
        .get("stream_idle_timeout_ms")
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| service.http_list_wait_time_ms())
        .unwrap_or(0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(idle);
    let _blob_guard = enter_want_blob_for(&body);
    let collect = || -> Vec<Json> {
        state
            .updates()
            .iter()
            .filter(|u| u.offset > begin && end.is_none_or(|e| u.offset <= e))
            .filter_map(|u| visible(service, u, &selection))
            .collect()
    };
    let mut out = collect();
    // a bounded read (`endInclusive` already reached) has nothing more to wait for
    let bounded_done = end.is_some_and(|e| e <= ledger_end);
    while out.is_empty() && !bounded_done && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
        out = collect();
    }
    finish_stream_list(service, limit, out)
}

fn token_error() -> impl Fn(&str) -> HttpResponse {
    |token: &str| {
        bad_body(format!(
            "Invalid value for: body (The string is not a valid Base64: {token} at 'pageToken')"
        ))
    }
}

fn page_size(body: &Json, key: &str, default: usize) -> Result<usize, HttpResponse> {
    match body.get(key).and_then(Json::as_i64) {
        Some(n) if n <= 0 => Err(ctx_error(
            400,
            "INVALID_ARGUMENT",
            format!("The submitted request has invalid arguments: Requested page size must be positive, but got {n}"),
            8,
            3,
            None,
            json!([]),
        )),
        Some(n) => Ok(n as usize),
        None => Ok(default),
    }
}

fn valid_base64(s: &str) -> bool {
    !s.is_empty()
        && unbase64(s).is_some()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
}

/// `POST /v2/updates/get-updates-page`.
pub fn updates_page(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body = match body_of(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let token = body
        .get("pageToken")
        .and_then(Json::as_str)
        .filter(|t| !t.is_empty());
    if let Some(t) = token {
        if !valid_base64(t) {
            return token_error()(t);
        }
    }
    let selection = match update_selection(service, &body) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let size = match page_size(&body, "maxPageSize", 100) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let state = service.v2_state();
    let ledger_end = state.ledger_end.load(Ordering::SeqCst);
    let mut begin = body
        .get("beginOffsetExclusive")
        .and_then(offset_of)
        .unwrap_or(0);
    // without an end bound the page window is open: a token always continues it (measured), even when this page
    // reaches the ledger end
    let mut open_ended = body.get("endOffsetInclusive").is_none();
    let mut end = body
        .get("endOffsetInclusive")
        .and_then(offset_of)
        .unwrap_or(ledger_end)
        .min(ledger_end);
    let descending = body
        .get("descendingOrder")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    if begin > end {
        return ctx_error(
            400,
            "INVALID_ARGUMENT",
            "The submitted request has invalid arguments: beginOffsetExclusive is after endOffsetInclusive"
                .into(),
            8,
            3,
            None,
            json!([]),
        );
    }
    // a later page continues inside the window the token remembers: `begin,end`
    if let Some(t) = token {
        let text = String::from_utf8_lossy(&unbase64(t).unwrap_or_default()).into_owned();
        let mut parts = text.split(',');
        if let (Some(b), Some(e)) = (
            parts.next().and_then(|p| p.parse::<u64>().ok()),
            parts.next(),
        ) {
            begin = b;
            open_ended = e == "open";
            end = e.parse::<u64>().unwrap_or(ledger_end).min(ledger_end);
        }
    }
    let _blob_guard = enter_want_blob_for(&body);
    let mut all: Vec<StoredUpdate> = state.updates();
    all.retain(|u| u.offset > begin && u.offset <= end);
    let mut shown: Vec<(u64, Json)> = all
        .iter()
        .filter_map(|u| visible(service, u, &selection).map(|j| (u.offset, j)))
        .collect();
    if descending {
        shown.reverse();
    }
    // the first update that does not fit the page, if any
    let hidden = shown.get(size).map(|(o, _)| *o);
    shown.truncate(size);
    let last = shown.last().map(|(o, _)| *o);
    // asc: the page ends at its last update and the next one starts after it; desc: the page starts below the first
    // hidden update and the next one ends before the last shown one (measured: lowest = offset of the first hidden)
    let (low, high, next) = match (hidden, last, descending) {
        (Some(_), Some(l), false) => (
            begin,
            l,
            Some(base64(
                format!(
                    "{l},{}",
                    if open_ended {
                        "open".to_string()
                    } else {
                        end.to_string()
                    }
                )
                .as_bytes(),
            )),
        ),
        (Some(h), Some(l), true) => (
            h,
            end,
            Some(base64(format!("{begin},{}", l - 1).as_bytes())),
        ),
        (None, _, false) if open_ended => {
            (begin, end, Some(base64(format!("{end},open").as_bytes())))
        }
        _ => (begin, end, None),
    };
    HttpResponse::json(
        200,
        &json!({
            "updates": shown.into_iter().map(|(_, j)| j).collect::<Vec<_>>(),
            "lowestPageOffsetExclusive": low,
            "highestPageOffsetInclusive": high,
            "nextPageToken": next
        }),
    )
}

/// `POST /v2/updates/update-by-hash`: looks up an interactive update by `transactionHash` (base64 of 32 bytes).
pub fn update_by_hash(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body = match body_of(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let selection = match update_selection(service, &body) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let Some(hash) = body
        .get("transactionHash")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
    else {
        return missing_field("transaction_hash");
    };
    // Canton echoes the hash as hex of its base64 decoding (measured)
    let shown: String = unbase64(hash)
        .unwrap_or_default()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let pruned = service.v2_state().pruned_up_to.load(Ordering::SeqCst);
    let update = (!shown.is_empty())
        .then(|| {
            service.v2_state().updates().into_iter().rev().find(|u| {
                u.offset > pruned && u.external_transaction_hash.as_deref() == Some(shown.as_str())
            })
        })
        .flatten();
    let _blob_guard = enter_want_blob_for(&body);
    update_response(service, update, &selection, || {
        ctx_error(
            404,
            "UPDATE_NOT_FOUND",
            "Update not found, or not visible.".into(),
            11,
            5,
            None,
            json!([["TRANSACTION_HASH", shown]]),
        )
    })
}

pub(crate) fn offset_after_ledger_end_error(
    at: u64,
    end: u64,
    parties: &[String],
    max_page_size: Option<usize>,
) -> HttpResponse {
    let shown: Vec<String> = parties
        .iter()
        .map(|p| {
            format!(
                "{p}: {{templates: [], interfaces: [], all-templates, created_event_blob: false}}"
            )
        })
        .collect();
    let mut resp = ctx_error(
        400,
        "OFFSET_AFTER_LEDGER_END",
        format!("active_at_offset offset ({at}) is after ledger end ({end})"),
        12,
        11,
        Some("1 second"),
        json!([]),
    );
    // this error's context names the request: maxPageSize (when paginated), activeAtOffset and the filters
    if let Ok(mut j) = serde_json::from_slice::<Json>(&resp.body) {
        if let Some(size) = max_page_size {
            j["context"]["maxPageSize"] = json!(size.to_string());
        }
        j["context"]["activeAtOffset"] = json!(at.to_string());
        j["context"]["filters"] = json!(format!("{{{}}}", shown.join(", ")));
        resp.body = j.to_string().into_bytes();
        resp.headers
            .insert("Content-Length".into(), resp.body.len().to_string());
    }
    resp
}

/// `POST /v2/state/active-contracts-page`: one page of the active contracts the event format's parties can see.
pub fn active_contracts_page(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body = match body_of(req) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let token = body
        .get("pageToken")
        .and_then(Json::as_str)
        .filter(|t| !t.is_empty());
    if let Some(t) = token {
        if !valid_base64(t) {
            return token_error()(t);
        }
    }
    let Some(filters) = body
        .get("eventFormat")
        .and_then(|ef| expand_event_format_filters(service, ef))
    else {
        return missing_field("event_format");
    };
    let size = match page_size(&body, "maxPageSize", 2000) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let parties: Vec<String> = filters.keys().cloned().collect();
    let end = service.v2_state().ledger_end.load(Ordering::SeqCst);
    let at = body
        .get("activeAtOffset")
        .and_then(offset_of)
        .unwrap_or(end);
    if at > end {
        return offset_after_ledger_end_error(at, end, &parties, Some(size));
    }
    if let Err(resp) = crate::v2_prune::check_active_at_not_pruned(service, at, &parties) {
        return resp;
    }
    let start = token
        .and_then(|t| String::from_utf8(unbase64(t)?).ok())
        .and_then(|t| t.parse::<usize>().ok())
        .unwrap_or(0);
    let _blob_guard = enter_want_blob_for(&body);
    let all = match crate::v2_commands::acs_entries_filtered(service, &filters, &parties, Some(at))
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let page: Vec<Json> = all.iter().skip(start).take(size).cloned().collect();
    let next = (start + size < all.len()).then(|| base64((start + size).to_string().as_bytes()));
    HttpResponse::json(
        200,
        &json!({ "activeContracts": page, "activeAtOffset": at, "nextPageToken": next }),
    )
}

/// Microseconds since the epoch of an RFC 3339 UTC time (`2026-11-10T06:49:21.680765Z`).
pub(crate) fn parse_micros(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.split(':').map(|p| p.parse::<i64>().ok());
    let (h, mi, sec) = (t.next()??, t.next()??, t.next()??);
    let micros: i64 = format!("{frac:0<6}")[..6].parse().ok()?;
    // days from civil (Howard Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + mi * 60 + sec) * 1_000_000) + micros)
}

/// `GET /v2/state/convert-record-time-to-offset`: the offset of the last update recorded at or before the time.
pub fn convert_record_time(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let Some(time) = req.query_params.get("record-time") else {
        return bad_body("Invalid value for: query parameter record-time (missing)".into());
    };
    let Some(micros) = parse_micros(time) else {
        return bad_body("Invalid value for: query parameter record-time".into());
    };
    let Some(sync) = req.query_params.get("synchronizer-id") else {
        return missing_field("synchronizer_id");
    };
    if sync != SYNCHRONIZER {
        return ctx_error(
            400,
            "INVALID_FIELD",
            format!("The submitted command has a field with invalid value: Invalid field synchronizer_id: Synchronizer id '{sync}' is not initialized on this participant."),
            8,
            3,
            None,
            json!([]),
        );
    }
    let updates = service.v2_state().updates();
    let times: Vec<(i64, u64)> = updates
        .iter()
        .filter_map(|u| Some((parse_micros(&u.effective_at)?, u.offset)))
        .collect();
    let latest = times.iter().map(|t| t.0).max();
    if latest.is_none_or(|l| micros > l) {
        let shown = updates
            .last()
            .map_or_else(crate::v2_commands::now_rfc3339, |u| u.effective_at.clone());
        return ctx_error(
            400,
            "RECORD_TIME_NOT_OBSERVED_YET",
            format!("The requested record time ({time}) is after the most recent observed update for this synchronizer ({shown})"),
            12,
            11,
            Some("1 second"),
            json!([["SYNCHRONIZER_ID", sync], ["RECORD_TIME", time]]),
        );
    }
    let offset = times
        .iter()
        .filter(|t| t.0 <= micros)
        .map(|t| t.1)
        .max()
        .unwrap_or(1);
    HttpResponse::json(200, &json!({ "offset": offset }))
}

/// `POST /v2/updates/flats` (`trees == false`) and `POST /v2/updates/trees` (`trees == true`).
pub fn updates_with_default_shape(
    service: &ExecutionService,
    req: &HttpRequest,
    trees: bool,
) -> HttpResponse {
    let body: Json = match serde_json::from_slice(&req.body) {
        Ok(b) => b,
        Err(_) => {
            return ctx_error(
                400,
                "INVALID_ARGUMENT",
                "Invalid value for: body".into(),
                8,
                3,
                None,
                json!([]),
            );
        }
    };
    if !trees {
        let mut normalized = body;
        if let Some(obj) = normalized.as_object_mut() {
            if obj.get("updateFormat").is_none() {
                if let Some(filter) = obj.remove("filter") {
                    obj.insert(
                        "updateFormat".into(),
                        json!({
                            "includeTransactions": {
                                "eventFormat": filter,
                                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                            }
                        }),
                    );
                }
            }
        }
        let mut fwd = req.clone();
        fwd.body = serde_json::to_vec(&normalized).unwrap_or_else(|_| req.body.clone());
        return updates(service, &fwd);
    }

    let state = service.v2_state();
    let end = state.ledger_end.load(Ordering::SeqCst);
    let begin = body.get("beginExclusive").and_then(offset_of).unwrap_or(0);
    if begin > end {
        return offset_after_end("Begin", begin, end);
    }
    let pruned = state.pruned_up_to.load(Ordering::SeqCst);
    if begin < pruned {
        return crate::v2_prune::pruned_error(
            format!(
                "Updates request for offset range [{}, {end}] overlaps with pruned offset {pruned}",
                begin + 1
            ),
            pruned,
            None,
        );
    }
    let end_limit = match body.get("endInclusive").and_then(offset_of) {
        Some(inclusive) if inclusive > end => return offset_after_end("End", inclusive, end),
        Some(inclusive) => Some(inclusive),
        None => None,
    };
    let event_format = body
        .pointer("/updateFormat/includeTransactions/eventFormat")
        .or_else(|| body.get("filter"))
        .unwrap_or(&Json::Null);
    let parties = if event_format.is_null() {
        Vec::new()
    } else {
        crate::v2_queries::format_parties(service, event_format)
    };
    let limit = match parse_stream_list_limit(req) {
        Ok(l) => l,
        Err(resp) => return resp,
    };
    let _blob_guard = enter_want_blob_for(&body);
    let mut out = Vec::new();
    for u in state.updates() {
        if u.offset <= begin || end_limit.is_some_and(|e| u.offset > e) {
            continue;
        }
        if u.topology.is_some() {
            continue;
        }
        if let Some(ref r) = u.reassignment {
            if let Some(j) = crate::v2_reassign::reassignment_json(service, &u, r) {
                if parties.is_empty() || r.witnesses.iter().any(|w| parties.contains(w)) {
                    out.push(json!({ "update": { "Reassignment": { "value": j } } }));
                }
            }
            continue;
        }
        if let Some(tree) = crate::v2_commands::transaction_tree_json(service, &u, &parties) {
            out.push(json!({ "update": { "TransactionTree": { "value": tree } } }));
        }
    }
    finish_stream_list(service, limit, out)
}
