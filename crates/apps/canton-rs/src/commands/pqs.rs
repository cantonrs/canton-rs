//! Pure-Rust PQS (Participant Query Store) PostgreSQL projection CLI (`REQ-PQS-SCRIBE-001`).
//!
//! Synchronizes committed updates from a Ledger JSON API v2 endpoint (`/v2/updates`, `/v2/packages`, `/v2/state/ledger-end`)
//! into PostgreSQL (`pqs_contracts`, `pqs_exercises`, `pqs_packages`, `pqs_watermark`) and queries active/exercise projections.

use std::path::PathBuf;
use std::time::Duration;

use canton_participant::pqs_index::{parse_offset_field, parse_update, PqsStore};
use clap::{Args, Subcommand};
use serde_json::{json, Value};

use super::json_http;

#[derive(Args, Debug)]
pub struct PqsArgs {
    #[command(subcommand)]
    pub action: PqsAction,
}

#[derive(Subcommand, Debug)]
pub enum PqsAction {
    /// Synchronize Ledger API v2 updates and packages into PQS PostgreSQL tables.
    Sync(PqsSyncArgs),
    /// Report current watermark and projected row counts in PQS PostgreSQL.
    Status(PqsStatusArgs),
    /// Query currently active contracts (`archive_offset IS NULL`) from PQS PostgreSQL.
    Active(PqsActiveArgs),
    /// Query recorded choice exercises (`pqs_exercises`) from PQS PostgreSQL.
    Exercises(PqsExercisesArgs),
    /// Prune archived contracts and exercises at or before a given ledger offset.
    Prune(PqsPruneArgs),
}

#[derive(Args, Debug)]
pub struct PqsSyncArgs {
    /// Ledger JSON API base URL (e.g. `http://127.0.0.1:7575`).
    #[arg(long)]
    pub json_api_url: String,
    /// PostgreSQL URL or JDBC URL for PQS tables.
    #[arg(long, env = "CANTON_RS_PQS_PG_URL")]
    pub pg_url: String,
    /// Specific party IDs to subscribe for (defaults to all known parties on the participant).
    #[arg(long)]
    pub party: Vec<String>,
    /// Stop as soon as the current ledger end is reached (default unless `--follow` is passed).
    #[arg(long, default_value_t = false)]
    pub stop_at_latest: bool,
    /// Continuously tail new updates past the current ledger end until interrupted.
    #[arg(long, default_value_t = false, conflicts_with = "stop_at_latest")]
    pub follow: bool,
    /// Bearer JWT for authenticated Ledger JSON API endpoints. Prefer the environment variable or `--token-file`: a command-line
    /// argument is visible to every user of the host (`ps`).
    #[arg(
        long,
        env = "CANTON_RS_PQS_TOKEN",
        hide_env_values = true,
        conflicts_with = "token_file"
    )]
    pub token: Option<String>,
    /// A file holding the bearer JWT, read again before every sync round (a token renewed in the file is used while `--follow` runs).
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    /// Updates asked for per `/v2/updates` request; halved while the node answers 413 (its list element limit).
    #[arg(long, default_value_t = 500)]
    pub page_size: usize,
}

#[derive(Args, Debug)]
pub struct PqsStatusArgs {
    #[arg(long, env = "CANTON_RS_PQS_PG_URL")]
    pub pg_url: String,
}

#[derive(Args, Debug)]
pub struct PqsActiveArgs {
    #[arg(long, env = "CANTON_RS_PQS_PG_URL")]
    pub pg_url: String,
    /// Optional template ID or suffix (`Module:Entity` or full `pkg:Module:Entity`).
    #[arg(long)]
    pub template: Option<String>,
    /// Optional party filter matching signatories or observers.
    #[arg(long)]
    pub party: Option<String>,
    /// Optional JSON object containment filter (`payload @> filter::jsonb`).
    #[arg(long)]
    pub filter_json: Option<String>,
}

#[derive(Args, Debug)]
pub struct PqsExercisesArgs {
    #[arg(long, env = "CANTON_RS_PQS_PG_URL")]
    pub pg_url: String,
    #[arg(long)]
    pub template: Option<String>,
    #[arg(long)]
    pub choice: Option<String>,
}

#[derive(Args, Debug)]
pub struct PqsPruneArgs {
    #[arg(long, env = "CANTON_RS_PQS_PG_URL")]
    pub pg_url: String,
    #[arg(long)]
    pub before_offset: i64,
}

fn parse_http_host_port(base_url: &str) -> Result<(String, u16, String), String> {
    let stripped = base_url
        .trim_end_matches('/')
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// JSON API URLs are supported here: {base_url}"))?;
    let (host_port, prefix) = match stripped.split_once('/') {
        Some((hp, rest)) => (hp, format!("/{rest}")),
        None => (stripped, String::new()),
    };
    let (host, port_str) = host_port
        .rsplit_once(':')
        .ok_or_else(|| format!("JSON API URL missing port: {base_url}"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port in URL: {base_url}"))?;
    Ok((host.to_string(), port, prefix))
}

fn json_api_req(
    host: &str,
    port: u16,
    prefix: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> Result<Value, String> {
    let full_path = format!("{prefix}{path}");
    let body_bytes = body.map(|b| b.to_string().into_bytes());
    let payload_ref = body_bytes.as_deref().map(|b| (b, "application/json"));
    let (status, resp) =
        json_http::call_with_token(host, port, method, &full_path, payload_ref, token)?;
    if status >= 400 {
        return Err(format!(
            "{method} {full_path} returned HTTP {status}: {resp}"
        ));
    }
    Ok(resp)
}

fn resolve_parties(
    host: &str,
    port: u16,
    prefix: &str,
    configured: &[String],
    token: Option<&str>,
) -> Result<Vec<String>, String> {
    if !configured.is_empty() {
        return Ok(configured.to_vec());
    }
    let mut parties = Vec::new();
    let mut page_token = String::new();
    loop {
        let path = if page_token.is_empty() {
            "/v2/parties".to_string()
        } else {
            format!("/v2/parties?pageToken={}", query_escape(&page_token))
        };
        let resp = json_api_req(host, port, prefix, "GET", &path, None, token)?;
        let list = resp
            .get("partyDetails")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("unexpected /v2/parties payload: {resp}"))?;
        parties.extend(list.iter().filter_map(|d| {
            d.get("party")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        }));
        match resp.get("nextPageToken").and_then(Value::as_str) {
            Some(next) if !next.is_empty() && next != page_token => page_token = next.to_string(),
            _ => return Ok(parties),
        }
    }
}

fn query_escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn sync_packages(
    store: &mut PqsStore,
    host: &str,
    port: u16,
    prefix: &str,
    at_offset: i64,
    token: Option<&str>,
) -> Result<(), String> {
    let ids = json_api_req(host, port, prefix, "GET", "/v2/packages", None, token)?;
    // names and versions come from the vetting list; a node that does not answer it leaves them empty
    let vetting = json_api_req(
        host,
        port,
        prefix,
        "POST",
        "/v2/package-vetting/list",
        Some(&json!({})),
        token,
    )
    .ok();
    let rows = package_rows(&ids, vetting.as_ref(), at_offset);
    if !rows.is_empty() {
        store.ingest_packages(&rows)?;
    }
    Ok(())
}

/// `(package id, name, version, offset)` of each package `/v2/packages` lists, named from `/v2/package-vetting/list`.
fn package_rows(
    ids: &Value,
    vetting: Option<&Value>,
    at_offset: i64,
) -> Vec<(String, String, String, i64)> {
    let mut names = std::collections::BTreeMap::new();
    for pkg in vetting
        .and_then(|v| v.get("vettedPackages"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.get("packages").and_then(Value::as_array))
        .flatten()
    {
        let text = |k: &str| pkg.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        names.insert(
            text("packageId"),
            (text("packageName"), text("packageVersion")),
        );
    }
    ids.get("packageIds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|id| {
            let (name, version) = names.get(id).cloned().unwrap_or_default();
            (id.to_string(), name, version, at_offset)
        })
        .collect()
}

fn event_format(parties: &[String]) -> Value {
    let mut filters_by_party = serde_json::Map::new();
    for p in parties {
        filters_by_party.insert(
            p.clone(),
            json!({
                "cumulative": [{
                    "identifierFilter": {
                        "WildcardFilter": {
                            "value": { "includeCreatedEventBlob": true }
                        }
                    }
                }]
            }),
        );
    }
    json!({"filtersByParty": Value::Object(filters_by_party), "verbose": true})
}

fn build_updates_filter(begin: i64, end: i64, parties: &[String]) -> Value {
    json!({
        "beginExclusive": begin,
        "endInclusive": end,
        "updateFormat": {
            "includeTransactions": {
                "eventFormat": event_format(parties),
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
            },
            "includeReassignments": event_format(parties)
        }
    })
}

/// How a page of `/v2/updates` was refused.
#[derive(Debug)]
enum FetchError {
    /// 413: more items than the node's list element limit.
    TooMany,
    Other(String),
}

/// Outcome of paging `(begin, end]` from `/v2/updates`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncPagesOutcome {
    last_received_offset: Option<i64>,
    projected: u64,
}

/// Reads `(begin, end]` in pages of at most `page` items, halving `page` while the node refuses it as too many, and hands each item to
/// `ingest`, which answers whether it was projected and its offset.
fn sync_pages(
    begin: i64,
    end: i64,
    mut page: usize,
    mut fetch: impl FnMut(i64, i64, usize) -> Result<Vec<Value>, FetchError>,
    mut ingest: impl FnMut(&Value) -> Result<(bool, i64), String>,
) -> Result<SyncPagesOutcome, String> {
    let (mut cursor, mut projected) = (begin, 0_u64);
    let mut last_received_offset = None;
    loop {
        if page == 0 {
            return Err("the node refuses even one update per request (413)".into());
        }
        let items = match fetch(cursor, end, page) {
            Ok(items) => items,
            Err(FetchError::TooMany) => {
                page /= 2;
                continue;
            }
            Err(FetchError::Other(e)) => return Err(e),
        };
        let full = items.len() >= page;
        for item in &items {
            let (done, offset) = ingest(item)?;
            if offset <= cursor {
                return Err(format!(
                    "/v2/updates answered offset {offset} after {cursor}"
                ));
            }
            cursor = offset;
            last_received_offset = Some(offset);
            projected += u64::from(done);
        }
        // [CANTON-NOTE: SEMANTICS] A page smaller than `page` only means no more updates are returned right now;
        // do not treat it as having reached `end` unless `last_received_offset == Some(end)`.
        if !full || cursor >= end {
            return Ok(SyncPagesOutcome {
                last_received_offset,
                projected,
            });
        }
    }
}

/// Where a sync round starts from.
#[derive(Debug, PartialEq, Eq)]
enum Start {
    /// The updates after the watermark.
    Replay,
    /// An empty store behind the participant's pruning: the active contracts at the ledger end.
    BootstrapAcs,
}

fn start_from(watermark: i64, pruned: i64) -> Result<Start, String> {
    if watermark >= pruned {
        Ok(Start::Replay)
    } else if watermark == 0 {
        Ok(Start::BootstrapAcs)
    } else {
        Err(format!(
            "the PQS store is at offset {watermark} and the participant has pruned up to {pruned}: the updates between are gone; \
             an empty PQS database starts from the participant's active contracts"
        ))
    }
}

/// `pqs prune` removes history the store has projected only.
fn check_prune(before_offset: i64, watermark: i64) -> Result<(), String> {
    if before_offset > watermark {
        return Err(format!(
            "--before-offset {before_offset} is past the PQS watermark {watermark}"
        ));
    }
    Ok(())
}

fn current_token(args: &PqsSyncArgs) -> Result<Option<String>, String> {
    match &args.token_file {
        Some(path) => std::fs::read_to_string(path)
            .map(|t| Some(t.trim().to_string()))
            .map_err(|e| format!("cannot read --token-file {}: {e}", path.display())),
        None => Ok(args.token.clone()),
    }
}

fn sync_once(
    store: &mut PqsStore,
    host: &str,
    port: u16,
    prefix: &str,
    args: &PqsSyncArgs,
) -> Result<(i64, u64), String> {
    let token = current_token(args)?;
    let token = token.as_deref();
    let end_resp = json_api_req(
        host,
        port,
        prefix,
        "GET",
        "/v2/state/ledger-end",
        None,
        token,
    )?;
    let ledger_end = parse_offset_field(end_resp.get("offset"))
        .ok_or_else(|| format!("missing offset in /v2/state/ledger-end: {end_resp}"))?;
    sync_packages(store, host, port, prefix, ledger_end, token)?;

    let begin = store.watermark()?;
    if ledger_end <= begin {
        return Ok((begin, 0));
    }
    let parties = resolve_parties(host, port, prefix, &args.party, token)?;
    if parties.is_empty() {
        store.bump_watermark(ledger_end)?;
        return Ok((ledger_end, 0));
    }
    let pruned_resp = json_api_req(
        host,
        port,
        prefix,
        "GET",
        "/v2/state/latest-pruned-offsets",
        None,
        token,
    )?;
    let pruned = parse_offset_field(pruned_resp.get("participantPrunedUpToInclusive")).unwrap_or(0);
    if start_from(begin, pruned)? == Start::BootstrapAcs {
        let created = bootstrap_acs_pages(args.page_size, |page_token, limit| {
            let mut req_body = json!({
                "eventFormat": event_format(&parties),
                "activeAtOffset": ledger_end,
                "maxPageSize": limit,
            });
            if let Some(tok) = page_token {
                req_body["pageToken"] = Value::String(tok.to_string());
            }
            let raw = req_body.to_string();
            let path = format!("{prefix}/v2/state/active-contracts-page");
            let (status, resp) = json_http::call_with_token(
                host,
                port,
                "POST",
                &path,
                Some((raw.as_bytes(), "application/json")),
                token,
            )
            .map_err(FetchError::Other)?;
            match status {
                413 => Err(FetchError::TooMany),
                s if s >= 400 => Err(FetchError::Other(format!(
                    "POST {path} returned HTTP {s}: {resp}"
                ))),
                _ => Ok(resp),
            }
        })?;
        let loaded = store.bootstrap_acs(ledger_end, &created)?;
        return Ok((ledger_end, loaded));
    }

    let fetch = |from: i64, to: i64, page: usize| -> Result<Vec<Value>, FetchError> {
        let body = build_updates_filter(from, to, &parties).to_string();
        let path = format!("{prefix}/v2/updates?limit={page}");
        let (status, resp) = json_http::call_with_token(
            host,
            port,
            "POST",
            &path,
            Some((body.as_bytes(), "application/json")),
            token,
        )
        .map_err(FetchError::Other)?;
        match status {
            413 => Err(FetchError::TooMany),
            s if s >= 400 => Err(FetchError::Other(format!(
                "POST {path} returned HTTP {s}: {resp}"
            ))),
            _ => resp.as_array().cloned().ok_or_else(|| {
                FetchError::Other(format!("expected array from POST /v2/updates, got {resp}"))
            }),
        }
    };
    let mut live_target = LivePqsSyncTarget {
        store,
        parties: &parties,
    };
    run_sync_cycle(begin, ledger_end, args.page_size, fetch, &mut live_target)
}

trait PqsSyncTarget {
    fn ingest_value(&mut self, item: &Value) -> Result<(bool, i64), String>;
    fn bump_watermark(&mut self, offset: i64) -> Result<(), String>;
}

struct LivePqsSyncTarget<'a> {
    store: &'a mut PqsStore,
    parties: &'a [String],
}

impl PqsSyncTarget for LivePqsSyncTarget<'_> {
    fn ingest_value(&mut self, item: &Value) -> Result<(bool, i64), String> {
        let update = parse_update(item, self.parties)?;
        Ok((self.store.ingest_update(&update)?, update.offset))
    }

    fn bump_watermark(&mut self, offset: i64) -> Result<(), String> {
        if self.store.watermark()? < offset {
            self.store.bump_watermark(offset)?;
        }
        Ok(())
    }
}

fn run_sync_cycle<T: PqsSyncTarget>(
    begin: i64,
    ledger_end: i64,
    page: usize,
    fetch: impl FnMut(i64, i64, usize) -> Result<Vec<Value>, FetchError>,
    target: &mut T,
) -> Result<(i64, u64), String> {
    let outcome = sync_pages(begin, ledger_end, page, fetch, |item| {
        target.ingest_value(item)
    })?;
    let watermark = match outcome.last_received_offset {
        Some(offset) if offset == ledger_end => {
            target.bump_watermark(ledger_end)?;
            ledger_end
        }
        Some(offset) => offset,
        None => begin,
    };
    Ok((watermark, outcome.projected))
}

fn bootstrap_acs_pages(
    page_size: usize,
    mut fetch_page: impl FnMut(Option<&str>, usize) -> Result<Value, FetchError>,
) -> Result<Vec<Value>, String> {
    let mut created = Vec::new();
    let mut page_token: Option<String> = None;
    let mut limit = page_size.max(1);
    loop {
        match fetch_page(page_token.as_deref(), limit) {
            Ok(resp) => {
                let items = resp
                    .get("activeContracts")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        format!(
                            "expected activeContracts array from POST /v2/state/active-contracts-page, got {resp}"
                        )
                    })?;
                for entry in items {
                    if let Some(ce) = entry
                        .pointer("/contractEntry/JsActiveContract/createdEvent")
                        .or_else(|| entry.get("createdEvent"))
                    {
                        created.push(ce.clone());
                    }
                }
                match resp
                    .get("nextPageToken")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    Some(tok) => page_token = Some(tok.to_string()),
                    None => break,
                }
            }
            Err(FetchError::TooMany) if limit > 1 => {
                limit = (limit / 2).max(1);
            }
            Err(FetchError::TooMany) => {
                return Err("ACS page exceeded limit even with maxPageSize=1".to_string());
            }
            Err(FetchError::Other(e)) => return Err(e),
        }
    }
    Ok(created)
}

pub fn execute_pqs(args: PqsArgs) -> Result<(), String> {
    match args.action {
        PqsAction::Sync(sync_args) => {
            let (host, port, prefix) = parse_http_host_port(&sync_args.json_api_url)?;
            let mut store = PqsStore::connect(&sync_args.pg_url)?;
            loop {
                let (wm, projected) = sync_once(&mut store, &host, port, &prefix, &sync_args)?;
                if !sync_args.follow || sync_args.stop_at_latest {
                    let st = store.status()?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "syncedToOffset": wm,
                            "updatesProjected": projected,
                            "status": st
                        }))
                        .map_err(|e| e.to_string())?
                    );
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        PqsAction::Status(st_args) => {
            let mut store = PqsStore::connect(&st_args.pg_url)?;
            let st = store.status()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        PqsAction::Active(act_args) => {
            let mut store = PqsStore::connect(&act_args.pg_url)?;
            let filter_val: Option<Value> = act_args
                .filter_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|e| format!("invalid --filter-json: {e}"))?;
            let rows = store.query_active(
                act_args.template.as_deref(),
                act_args.party.as_deref(),
                filter_val.as_ref(),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        PqsAction::Exercises(ex_args) => {
            let mut store = PqsStore::connect(&ex_args.pg_url)?;
            let rows =
                store.query_exercises(ex_args.template.as_deref(), ex_args.choice.as_deref())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        PqsAction::Prune(prune_args) => {
            let mut store = PqsStore::connect(&prune_args.pg_url)?;
            check_prune(prune_args.before_offset, store.watermark()?)?;
            let (pruned_contracts, pruned_exercises) =
                store.prune_archived_before(prune_args.before_offset)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "prunedContracts": pruned_contracts,
                    "prunedExercises": pruned_exercises
                }))
                .map_err(|e| e.to_string())?
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(offset: i64) -> Value {
        json!({"update": {"Transaction": {"value": {"offset": offset, "events": []}}}})
    }

    /// A node with `limit` list elements: more is 413, as `http-list-max-elements-limit` answers.
    fn node(
        offsets: &[i64],
        limit: usize,
    ) -> impl FnMut(i64, i64, usize) -> Result<Vec<Value>, FetchError> + '_ {
        move |from, to, page| {
            let all: Vec<Value> = offsets
                .iter()
                .filter(|o| **o > from && **o <= to)
                .map(|o| update(*o))
                .collect();
            if all.len().min(page) > limit {
                return Err(FetchError::TooMany);
            }
            Ok(all.into_iter().take(page).collect())
        }
    }

    #[test]
    fn a_backlog_past_the_node_limit_is_read_in_pages() {
        let offsets: Vec<i64> = (1..=25).map(|i| i * 2).collect();
        let mut seen = Vec::new();
        let outcome = sync_pages(0, 60, 500, node(&offsets, 4), |item| {
            let offset = parse_update(item, &[])?.offset;
            seen.push(offset);
            Ok((true, offset))
        })
        .unwrap();
        assert_eq!(outcome.projected, 25);
        assert_eq!(outcome.last_received_offset, Some(50));
        assert_eq!(seen, offsets);
    }

    #[test]
    fn an_empty_store_behind_pruning_starts_from_the_acs_and_a_behind_one_stops() {
        assert_eq!(start_from(0, 0).unwrap(), Start::Replay);
        assert_eq!(start_from(9, 5).unwrap(), Start::Replay);
        assert_eq!(start_from(0, 5).unwrap(), Start::BootstrapAcs);
        let err = start_from(3, 5).unwrap_err();
        assert!(err.contains("pruned up to 5"), "{err}");
    }

    #[test]
    fn prune_stops_at_the_watermark() {
        assert!(check_prune(10, 10).is_ok());
        assert!(check_prune(11, 10).is_err());
    }

    #[test]
    fn packages_are_named_from_the_vetting_list() {
        let ids = json!({"packageIds": ["p1", "p2"]});
        let vetting = json!({"vettedPackages": [{"packages": [
            {"packageId": "p1", "packageName": "sample-contract", "packageVersion": "0.1.0"}]}]});
        assert_eq!(
            package_rows(&ids, Some(&vetting), 3),
            [
                ("p1".into(), "sample-contract".into(), "0.1.0".into(), 3),
                ("p2".into(), String::new(), String::new(), 3)
            ]
        );
    }

    #[test]
    fn a_token_file_is_read_again_each_round() {
        let dir = std::env::temp_dir().join(format!("pqs-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("token");
        std::fs::write(&file, "first\n").unwrap();
        let args = PqsSyncArgs {
            json_api_url: String::new(),
            pg_url: String::new(),
            party: Vec::new(),
            stop_at_latest: false,
            follow: true,
            token: None,
            token_file: Some(file.clone()),
            page_size: 1,
        };
        assert_eq!(current_token(&args).unwrap().as_deref(), Some("first"));
        std::fs::write(&file, "renewed").unwrap();
        assert_eq!(current_token(&args).unwrap().as_deref(), Some("renewed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootstrap_acs_paginates_and_backs_off_on_413() {
        let all: Vec<Value> = (0..5)
            .map(|i| json!({"contractEntry": {"JsActiveContract": {"createdEvent": {"contractId": format!("00{i}")}}}}))
            .collect();
        let got = bootstrap_acs_pages(10, |tok, limit| {
            if limit > 2 {
                return Err(FetchError::TooMany);
            }
            let start: usize = tok.and_then(|t| t.parse().ok()).unwrap_or(0);
            let slice: Vec<Value> = all.iter().skip(start).take(limit).cloned().collect();
            let next = (start + slice.len() < all.len()).then(|| (start + slice.len()).to_string());
            Ok(json!({ "activeContracts": slice, "nextPageToken": next }))
        })
        .expect("paginated bootstrap");
        assert_eq!(got.len(), 5);
        assert_eq!(got[4]["contractId"], "004");
    }

    struct MockPqsSyncTarget {
        watermark: i64,
        seen: Vec<i64>,
        bumped: Vec<i64>,
    }

    impl PqsSyncTarget for MockPqsSyncTarget {
        fn ingest_value(&mut self, item: &Value) -> Result<(bool, i64), String> {
            let offset = parse_update(item, &[])?.offset;
            self.seen.push(offset);
            self.watermark = self.watermark.max(offset);
            Ok((true, offset))
        }

        fn bump_watermark(&mut self, offset: i64) -> Result<(), String> {
            self.bumped.push(offset);
            self.watermark = self.watermark.max(offset);
            Ok(())
        }
    }

    #[test]
    fn partial_page_advances_watermark_only_to_last_received_offset() {
        let offsets: Vec<i64> = (1..=200).collect();
        let mut target = MockPqsSyncTarget {
            watermark: 0,
            seen: Vec::new(),
            bumped: Vec::new(),
        };

        // Cycle 1: limit=100 requested, mock node caps answer to 30 items while ledger_end=200.
        let (wm1, count1) = run_sync_cycle(
            target.watermark,
            200,
            100,
            |from, to, page| {
                Ok(offsets
                    .iter()
                    .filter(|o| **o > from && **o <= to)
                    .take(page.min(30))
                    .map(|o| update(*o))
                    .collect())
            },
            &mut target,
        )
        .expect("cycle 1");

        assert_eq!(count1, 30);
        assert_eq!(
            wm1, 30,
            "partial page stopping at offset 30 must NOT jump watermark to ledger_end 200"
        );
        assert_eq!(target.watermark, 30);
        assert!(target.bumped.is_empty());

        // Subsequent cycles catch up from the actual watermark until offset 200 arrives.
        let mut total = count1;
        while target.watermark < 200 {
            let (wm, cnt) = run_sync_cycle(
                target.watermark,
                200,
                100,
                |from, to, page| {
                    Ok(offsets
                        .iter()
                        .filter(|o| **o > from && **o <= to)
                        .take(page.min(30))
                        .map(|o| update(*o))
                        .collect())
                },
                &mut target,
            )
            .expect("catchup cycle");
            total += cnt;
            assert_eq!(wm, target.watermark);
        }
        assert_eq!(total, 200);
        assert_eq!(target.seen, offsets);
        assert_eq!(
            target.bumped,
            vec![200],
            "positive control: bump_watermark(ledger_end) called once offset == ledger_end"
        );

        // Empty page must leave watermark at `begin` (10), never advance to ledger_end (200).
        let mut empty_target = MockPqsSyncTarget {
            watermark: 10,
            seen: Vec::new(),
            bumped: Vec::new(),
        };
        let (wm_empty, cnt_empty) = run_sync_cycle(
            empty_target.watermark,
            200,
            100,
            |_from, _to, _page| Ok(Vec::new()),
            &mut empty_target,
        )
        .expect("empty cycle");
        assert_eq!(wm_empty, 10);
        assert_eq!(cnt_empty, 0);
        assert_eq!(empty_target.watermark, 10);
        assert!(empty_target.bumped.is_empty());
    }
}
