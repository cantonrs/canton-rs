//! The scan app's update history API (G8, AT-S06): pages of the updates a network committed, by cursor.
//!
//! [CANTON-NOTE: SEMANTICS] Measured on the official Splice 0.10.1 scan app (`scripts/splice-scan-cases.py`,
//! `tests/oracle/splice-replay/scan-cases.jsonl`), `POST /v2/updates`:
//! - the request is read field by field in the order `after`, `page_size`, `daml_value_encoding`, and the first field that does not read
//!   answers `400` with the plain text `The request content was malformed:` and `DecodingFailure at .<path>: <why>`. A number may be given
//!   as text (`"3"`); unknown fields are ignored; a body that is no object fails at `.after`;
//! - then the cursor's time is read (`400` `{"error": "Invalid timestamp: Text '<t>' could not be parsed at index <n>"}`), **then** the
//!   limit is checked (`Limit must be at least 1.`, `Exceeded limit maximum (<n> > 1000).`);
//! - the page is the updates **strictly after** the cursor in the order (migration id, record time), at most `page_size` of them. The
//!   cursor's time may have no fraction, an offset or nanoseconds; a cursor of an earlier migration is before every update of a later one.
//!
//! `GET /v2/updates/{id}` answers the update or `404` `{"error": "Transaction with id <id> not found"}`.
//!
//! [CANTON-NOTE: LIMITATION] The history is given to this module (the updates as the official scan answers them); ingesting a ledger into
//! such a history, pruning it and the other encodings of the values are not here. A body that is not JSON at all is answered `400`
//! with this module's own words after the first line (the official app prints its parser's).
use serde_json::Value as Json;

/// What the scan answers.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// `200`: a page of updates.
    Page(Vec<Json>),
    /// `200`: one update.
    Update(Json),
    /// `{"error": <text>}` with the status.
    Error(u16, String),
    /// `400` with a plain text body.
    Malformed(String),
}

impl Answer {
    pub fn status(&self) -> u16 {
        match self {
            Self::Page(_) | Self::Update(_) => 200,
            Self::Error(status, _) => *status,
            Self::Malformed(_) => 400,
        }
    }
}

/// An HTTP answer: status, content type and body.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl Response {
    fn json(status: u16, body: &Json) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.to_string(),
        }
    }
}

/// The updates of a network in the order (migration id, record time).
pub struct UpdateHistory {
    updates: Vec<((i64, (i64, u32)), Json)>,
    contracts: Option<ContractState>,
    forced_snapshots: std::sync::Mutex<std::collections::BTreeMap<(i64, (i64, u32)), String>>,
}

/// What the contract endpoints answer from (S-SPL-009): the active contracts the history leaves, the official DARs the blobs are encoded on,
/// and the contract salt of each contract (hex contract id to `authentication_data`).
struct ContractState {
    acs: lf_eval::scan_state::Acs,
    worlds: Vec<lf_eval::World>,
    authentication_data: std::collections::HashMap<String, Vec<u8>>,
    dso_info: DsoInfoConfig,
}

impl ContractState {
    /// A contract as the scan app prints it with its synchronizer (`ContractWithState`), its blob encoded on the loaded DARs.
    fn render(&self, c: &lf_eval::scan_state::ActiveContract) -> Result<Json, String> {
        let (package, template) = c.template_id.split_once(':').ok_or("no package")?;
        let auth = self
            .authentication_data
            .get(&c.contract_id)
            .ok_or_else(|| format!("no contract salt for {}", c.contract_id))?;
        for world in &self.worlds {
            let types = lf_eval::typed_json::Types::new(world);
            if types.template(package, template).is_ok() {
                return lf_eval::scan_state::contract_with_state(&types, c, auth);
            }
        }
        Err(format!("no loaded package has {}", c.template_id))
    }
}

mod registry;

/// What `GET /v0/dso` states that no update does: the scan app's configuration (its SV user, its SV party, the first round).
#[derive(Clone)]
pub struct DsoInfoConfig {
    pub sv_user: String,
    /// `None`: the first SV of the `DsoRules`.
    pub sv_party: Option<String>,
    pub initial_round: String,
}

impl Default for DsoInfoConfig {
    fn default() -> Self {
        Self {
            sv_user: "ledger-api-user".into(),
            sv_party: None,
            initial_round: "0".into(),
        }
    }
}

const MAX_PAGE_SIZE: i64 = 1000;

fn malformed(path: &str, why: &str) -> Answer {
    Answer::Malformed(format!(
        "The request content was malformed:\nDecodingFailure at {path}: {why}"
    ))
}

/// A whole number given as a JSON number or as text (the official decoder takes both).
fn integer(json: &Json) -> Option<i64> {
    match json {
        Json::Number(n) => n.as_i64(),
        Json::String(s) => s.parse().ok(),
        _ => None,
    }
}

impl UpdateHistory {
    /// The history of `updates` (each with its `migration_id`, `record_time` and `update_id`); an update without them is left out.
    pub fn new(updates: Vec<Json>) -> Self {
        let mut keyed: Vec<_> = updates
            .into_iter()
            .filter_map(|u| {
                let key = (
                    u["migration_id"].as_i64()?,
                    parse_instant(u["record_time"].as_str()?).ok()?,
                );
                Some((key, u))
            })
            .collect();
        keyed.sort_by_key(|(key, _)| *key);
        Self {
            updates: keyed,
            contracts: None,
            forced_snapshots: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// Also answers the contract endpoints (`/v0/amulet-rules`, `/v0/dso-party-id`, ...) from the contracts the history leaves active.
    pub fn with_contracts(
        mut self,
        worlds: Vec<lf_eval::World>,
        authentication_data: std::collections::HashMap<String, Vec<u8>>,
    ) -> Result<Self, String> {
        let updates: Vec<Json> = self.updates.iter().map(|(_, u)| u.clone()).collect();
        self.contracts = Some(ContractState {
            acs: lf_eval::scan_state::Acs::from_updates(&updates)?,
            worlds,
            authentication_data,
            dso_info: DsoInfoConfig::default(),
        });
        Ok(self)
    }

    /// The configuration `GET /v0/dso` states (after [`UpdateHistory::with_contracts`]).
    pub fn with_dso_info(mut self, info: DsoInfoConfig) -> Self {
        if let Some(state) = self.contracts.as_mut() {
            state.dso_info = info;
        }
        self
    }

    /// `POST /v2/updates` with `body`.
    pub fn updates(&self, body: &str) -> Answer {
        let Ok(request) = serde_json::from_str::<Json>(body) else {
            return Answer::Malformed("The request content was malformed:\nnot JSON".into());
        };
        let Some(object) = request.as_object() else {
            return malformed(".after", "Missing required field");
        };
        let after = match object.get("after").filter(|a| !a.is_null()) {
            None => None,
            Some(after) => {
                let Some(migration) = after.get("after_migration_id") else {
                    return malformed(".after.after_migration_id", "Missing required field");
                };
                let Some(migration) = integer(migration) else {
                    return malformed(".after.after_migration_id", "Long");
                };
                let Some(time) = after.get("after_record_time") else {
                    return malformed(".after.after_record_time", "Missing required field");
                };
                let Some(time) = time.as_str() else {
                    return malformed(".after.after_record_time", "String");
                };
                Some((migration, time))
            }
        };
        let Some(page_size) = object.get("page_size") else {
            return malformed(".page_size", "Missing required field");
        };
        let Some(page_size) = integer(page_size) else {
            return malformed(".page_size", "Int");
        };
        if let Some(encoding) = object.get("daml_value_encoding").filter(|e| !e.is_null()) {
            match encoding.as_str() {
                Some("compact_json" | "protobuf_json") => {}
                Some(other) => {
                    return malformed(
                        ".daml_value_encoding",
                        &format!("{other} not a member of DamlValueEncoding"),
                    )
                }
                None => return malformed(".daml_value_encoding", "String"),
            }
        }
        // the cursor's time is read before the limit is looked at
        let after = match after {
            None => None,
            Some((migration, text)) => match parse_instant(text) {
                Ok(time) => Some((migration, time)),
                Err(index) => {
                    return Answer::Error(
                        400,
                        format!(
                            "Invalid timestamp: Text '{text}' could not be parsed at index {index}"
                        ),
                    )
                }
            },
        };
        if page_size < 1 {
            return Answer::Error(400, "Limit must be at least 1.".into());
        }
        if page_size > MAX_PAGE_SIZE {
            return Answer::Error(
                400,
                format!("Exceeded limit maximum ({page_size} > {MAX_PAGE_SIZE})."),
            );
        }
        Answer::Page(
            self.updates
                .iter()
                .filter(|(key, _)| after.is_none_or(|cursor| *key > cursor))
                .take(page_size as usize)
                .map(|(_, u)| u.clone())
                .collect(),
        )
    }

    /// The answer to an HTTP request: `path` as it reaches the scan app, with the `/api/scan` prefix.
    ///
    /// [CANTON-NOTE: SEMANTICS] The scan's OpenAPI (`apps/scan/src/main/openapi/scan.yaml`, `getUpdateHistoryV2`) answers a page as
    /// `{"transactions": [...]}` and a single update as the update itself; the errors are the ones [`Answer`] describes.
    ///
    /// [CANTON-NOTE: LIMITATION] Another path or method is answered `404` `{"error": "Not found"}` and `405` `{"error": "Method not allowed"}`:
    /// the official app's words for them were not recorded.
    pub fn handle(&self, method: &str, path: &str, body: &str) -> Response {
        // the Token Standard registry is served at the root of the scan app, beside `/api/scan` (the official app does the same)
        if let Some(route) = path.strip_prefix("/registry/") {
            let (route, query) = route.split_once('?').unwrap_or((route, ""));
            return self.registry_endpoint(method, route, query, body);
        }
        let Some(route) = path.strip_prefix("/api/scan") else {
            return Response::json(404, &serde_json::json!({"error": "Not found"}));
        };
        let (route, query) = route.split_once('?').unwrap_or((route, ""));
        let answer = match (method, route) {
            ("POST", "/v2/updates") => self.updates(body),
            (_, "/v2/updates") => {
                return Response::json(405, &serde_json::json!({"error": "Method not allowed"}))
            }
            ("GET", id) if id.starts_with("/v2/updates/") => {
                self.update(id.trim_start_matches("/v2/updates/"))
            }
            ("GET", "/v0/state/acs/snapshot-timestamp") => return self.snapshot_timestamp(query),
            ("GET", "/v0/state/acs/snapshot-timestamp-after") => {
                return self.snapshot_timestamp_after(query)
            }
            ("POST", "/v0/state/acs/force") => return self.force_acs_snapshot(),
            ("POST", "/v2/state/acs") | ("POST", "/v0/state/acs") => return self.state_acs(body),
            _ => {
                return self
                    .contract_endpoint(method, route, query, body)
                    .unwrap_or_else(|| {
                        Response::json(404, &serde_json::json!({"error": "Not found"}))
                    })
            }
        };
        match answer {
            Answer::Page(updates) => {
                Response::json(200, &serde_json::json!({ "transactions": updates }))
            }
            Answer::Update(update) => Response::json(200, &update),
            Answer::Error(status, text) => {
                Response::json(status, &serde_json::json!({ "error": text }))
            }
            Answer::Malformed(text) => Response {
                status: 400,
                content_type: "text/plain; charset=UTF-8",
                body: text,
            },
        }
    }

    /// The endpoints that answer with contracts, over the active set (S-SPL-009); `None` for a path that is not one of them.
    ///
    /// [CANTON-NOTE: SEMANTICS] Source: `HttpScanHandler` (`getAmuletRules`, `getAnsRules`, `getExternalPartyAmuletRules`, `getDsoPartyId`,
    /// `listAmuletPriceVotes`, `listUnclaimedDevelopmentFundCoupons`). A rules endpoint leaves the contract out when the request's cached
    /// contract id is the active one. The lists are in creation order.
    fn contract_endpoint(
        &self,
        method: &str,
        route: &str,
        query: &str,
        body: &str,
    ) -> Option<Response> {
        let state = self.contracts.as_ref()?;
        let render = |c: &lf_eval::scan_state::ActiveContract| state.render(c);
        let failed = |e: String| Response::json(500, &serde_json::json!({ "error": e }));
        let rules = |template: &str, cached_key: &str, answer_key: &str| -> Response {
            let request: Json = serde_json::from_str(body).unwrap_or(Json::Null);
            let Some(active) = state.acs.of_template(template).into_iter().next() else {
                return Response::json(
                    404,
                    &serde_json::json!({"error": format!("found no {template} instance")}),
                );
            };
            let mut update = match render(active) {
                Ok(v) => v,
                Err(e) => return failed(e),
            };
            if request[cached_key].as_str() == Some(active.contract_id.as_str()) {
                update.as_object_mut().map(|o| o.remove("contract"));
            }
            Response::json(200, &serde_json::json!({ answer_key: update }))
        };
        Some(match (method, route) {
            ("GET", "/v0/dso-party-id") => {
                let dso = ["Splice.AmuletRules:AmuletRules", "Splice.DsoRules:DsoRules"]
                    .iter()
                    .find_map(|t| {
                        state
                            .acs
                            .of_template(t)
                            .first()
                            .map(|c| c.payload["dso"].clone())
                    });
                match dso {
                    Some(dso) => Response::json(200, &serde_json::json!({ "dso_party_id": dso })),
                    None => {
                        Response::json(404, &serde_json::json!({"error": "found no DSO party"}))
                    }
                }
            }
            ("POST", "/v0/amulet-rules") => rules(
                "Splice.AmuletRules:AmuletRules",
                "cached_amulet_rules_contract_id",
                "amulet_rules_update",
            ),
            ("POST", "/v0/ans-rules") => rules(
                "Splice.Ans:AnsRules",
                "cached_ans_rules_contract_id",
                "ans_rules_update",
            ),
            ("POST", "/v0/external-party-amulet-rules") => rules(
                "Splice.ExternalPartyAmuletRules:ExternalPartyAmuletRules",
                "cached_external_party_amulet_rules_contract_id",
                "external_party_amulet_rules_update",
            ),
            ("GET", "/v0/amulet-price/votes") => {
                let votes: Result<Vec<Json>, String> = state
                    .acs
                    .of_template("Splice.DSO.AmuletPrice:AmuletPriceVote")
                    .into_iter()
                    .map(|c| render(c).map(|v| v["contract"].clone()))
                    .collect();
                match votes {
                    Ok(v) => Response::json(200, &serde_json::json!({ "amulet_price_votes": v })),
                    Err(e) => failed(e),
                }
            }
            ("GET", "/v0/unclaimed-development-fund-coupons") => {
                let coupons: Result<Vec<Json>, String> = state
                    .acs
                    .of_template("Splice.Amulet:UnclaimedDevelopmentFundCoupon")
                    .into_iter()
                    .map(render)
                    .collect();
                match coupons {
                    Ok(v) => Response::json(
                        200,
                        &serde_json::json!({ "unclaimed-development-fund-coupons": v }),
                    ),
                    Err(e) => failed(e),
                }
            }
            ("POST", "/v0/open-and-issuing-mining-rounds") => {
                let request: Json = serde_json::from_str(body).unwrap_or(Json::Null);
                let cached = |key: &str| -> Vec<String> {
                    request[key]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|c| c.as_str().map(String::from))
                        .collect()
                };
                let (cached_open, cached_issuing) = (
                    cached("cached_open_mining_round_contract_ids"),
                    cached("cached_issuing_round_contract_ids"),
                );
                let select = |template: &str,
                              cached: &[String]|
                 -> Result<serde_json::Map<String, Json>, String> {
                    let mut map = serde_json::Map::new();
                    for c in state.acs.of_template(template) {
                        let mut with_state = render(c)?;
                        if cached.contains(&c.contract_id) {
                            with_state.as_object_mut().map(|o| o.remove("contract"));
                        }
                        map.insert(c.contract_id.clone(), with_state);
                    }
                    Ok(map)
                };
                // the time to live: the smallest tick duration of the non-closed rounds, and half the open time of an issuing round
                let micros =
                    |c: &lf_eval::scan_state::ActiveContract, field: &str| -> Option<i64> {
                        c.payload[field]["microseconds"].as_str()?.parse().ok()
                    };
                let mut ttl: Vec<i64> = Vec::new();
                for t in [
                    "Splice.Round:OpenMiningRound",
                    "Splice.Round:SummarizingMiningRound",
                ] {
                    ttl.extend(
                        state
                            .acs
                            .of_template(t)
                            .iter()
                            .filter_map(|c| micros(c, "tickDuration")),
                    );
                }
                for c in state.acs.of_template("Splice.Round:IssuingMiningRound") {
                    let at = |f: &str| {
                        c.payload[f]
                            .as_str()
                            .and_then(|t| lf_eval::scan_state::parse_micros(t).ok())
                    };
                    if let (Some(closes), Some(opens)) = (at("targetClosesAt"), at("opensAt")) {
                        ttl.push((closes - opens) / 2);
                    }
                }
                let (Some(ttl), Ok(open), Ok(issuing)) = (
                    ttl.iter().min().copied(),
                    select("Splice.Round:OpenMiningRound", &cached_open),
                    select("Splice.Round:IssuingMiningRound", &cached_issuing),
                ) else {
                    return Some(failed("the rounds cannot be rendered".into()));
                };
                Response::json(
                    200,
                    &serde_json::json!({
                        "time_to_live_in_microseconds": ttl,
                        "open_mining_rounds": open,
                        "issuing_mining_rounds": issuing,
                    }),
                )
            }
            ("GET", "/v0/dso") => {
                // Source: `HttpScanHandler.lookupDsoInfo`: the latest open round, the amulet rules, the DSO rules and the SV nodes' states
                let Some(dso_rules) = state
                    .acs
                    .of_template("Splice.DsoRules:DsoRules")
                    .into_iter()
                    .next()
                else {
                    return Some(Response::json(
                        404,
                        &serde_json::json!({"error": "found no DsoRules instance"}),
                    ));
                };
                let Some(amulet_rules) = state
                    .acs
                    .of_template("Splice.AmuletRules:AmuletRules")
                    .into_iter()
                    .next()
                else {
                    return Some(Response::json(
                        404,
                        &serde_json::json!({"error": "found no amuletrules instance"}),
                    ));
                };
                let latest = state
                    .acs
                    .of_template("Splice.Round:OpenMiningRound")
                    .into_iter()
                    .max_by_key(|c| {
                        c.payload["round"]["number"]
                            .as_str()
                            .and_then(|n| n.parse::<i64>().ok())
                    });
                let Some(latest) = latest else {
                    return Some(Response::json(
                        404,
                        &serde_json::json!({"error": "No active OpenMiningRound contract"}),
                    ));
                };
                let svs: Vec<String> = dso_rules.payload["svs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e[0].as_str().map(String::from))
                    .collect();
                // `Thresholds.requiredNumVotes`: with n SVs, f = floor((n - 1) / 3) and the threshold ceil((n + f + 1) / 2)
                let n = svs.len() as i64;
                let f = (n - 1).div_euclid(3);
                let threshold = (n + f + 2) / 2;
                let node_states: Result<Vec<Json>, String> = svs
                    .iter()
                    .filter_map(|sv| {
                        state
                            .acs
                            .of_template("Splice.DSO.SvState:SvNodeState")
                            .into_iter()
                            .find(|c| c.payload["sv"].as_str() == Some(sv))
                    })
                    .map(&render)
                    .collect();
                let parts = (
                    render(latest),
                    render(amulet_rules),
                    render(dso_rules),
                    node_states,
                );
                let (Ok(latest), Ok(amulet), Ok(dso), Ok(nodes)) = parts else {
                    return Some(failed("the DSO info cannot be rendered".into()));
                };
                let info = &state.dso_info;
                Response::json(
                    200,
                    &serde_json::json!({
                        "sv_user": info.sv_user,
                        "sv_party_id": info.sv_party.clone().or_else(|| svs.first().cloned()),
                        "dso_party_id": dso_rules.payload["dso"],
                        "voting_threshold": threshold,
                        "latest_mining_round": latest,
                        "amulet_rules": amulet,
                        "dso_rules": dso,
                        "sv_node_states": nodes,
                        "initial_round": info.initial_round,
                    }),
                )
            }
            ("GET", "/v0/closed-rounds") => {
                let mut closed = state.acs.of_template("Splice.Round:ClosedMiningRound");
                closed.sort_by_key(|c| {
                    c.payload["round"]["number"]
                        .as_str()
                        .and_then(|n| n.parse::<i64>().ok())
                });
                let rounds: Result<Vec<Json>, String> = closed
                    .into_iter()
                    .map(|c| render(c).map(|v| v["contract"].clone()))
                    .collect();
                match rounds {
                    Ok(v) => Response::json(200, &serde_json::json!({ "rounds": v })),
                    Err(e) => failed(e),
                }
            }
            ("GET", "/v0/admin/validator/licenses") => {
                // [CANTON-NOTE: SEMANTICS] Source: `HttpValidatorLicensesHandler` and `DbMultiDomainAcsStore.listContractsPaginated`: newest
                // first by the store's event number, `after` is a token from an earlier answer (the contracts below it follow), and the answer's
                // `next_page_token` is the event number of the page's last contract (S-SPL-029).
                let param = |name: &str| -> Option<u64> {
                    query
                        .split('&')
                        .filter_map(|kv| kv.split_once('='))
                        .find(|(k, _)| *k == name)
                        .and_then(|(_, v)| v.parse().ok())
                };
                let (page, token) = state.acs.page_descending(
                    "Splice.ValidatorLicense:ValidatorLicense",
                    param("after"),
                    param("limit").map_or(1000, |l| l as usize),
                );
                let licenses: Result<Vec<Json>, String> = page
                    .into_iter()
                    .map(|c| render(c).map(|v| v["contract"].clone()))
                    .collect();
                match licenses {
                    Ok(v) => {
                        let mut answer = serde_json::json!({ "validator_licenses": v });
                        if let Some(token) = token {
                            answer["next_page_token"] = Json::from(token);
                        }
                        Response::json(200, &answer)
                    }
                    Err(e) => failed(e),
                }
            }
            ("GET", "/v0/featured-apps") => {
                let apps: Result<Vec<Json>, String> = state
                    .acs
                    .of_template("Splice.Amulet:FeaturedAppRight")
                    .into_iter()
                    .map(|c| render(c).map(|v| v["contract"].clone()))
                    .collect();
                match apps {
                    Ok(v) => Response::json(200, &serde_json::json!({ "featured_apps": v })),
                    Err(e) => failed(e),
                }
            }
            _ => return None,
        })
    }

    /// `GET /v2/updates/{id}`.
    pub fn update(&self, id: &str) -> Answer {
        self.updates
            .iter()
            .find(|(_, u)| u["update_id"].as_str() == Some(id))
            .map_or_else(
                || Answer::Error(404, format!("Transaction with id {id} not found")),
                |(_, u)| Answer::Update(u.clone()),
            )
    }

    fn available_snapshots(&self) -> Vec<(i64, (i64, u32), String)> {
        let mut map = std::collections::BTreeMap::new();
        for ((m, ts), u) in &self.updates {
            if let Some(rt) = u["record_time"].as_str() {
                map.insert((*m, *ts), rt.to_string());
            }
        }
        if let Ok(forced) = self.forced_snapshots.lock() {
            for (k, rt) in forced.iter() {
                map.entry(*k).or_insert_with(|| rt.clone());
            }
        }
        map.into_iter().map(|((m, ts), rt)| (m, ts, rt)).collect()
    }

    /// `GET /v0/state/acs/snapshot-timestamp?before=<iso>&migration_id=<i64>`.
    fn snapshot_timestamp(&self, query: &str) -> Response {
        let Some(before_raw) = query_param(query, "before") else {
            return Response::json(
                400,
                &serde_json::json!({ "error": "Missing required query parameter: before" }),
            );
        };
        let Some(mig_raw) = query_param(query, "migration_id") else {
            return Response::json(
                400,
                &serde_json::json!({ "error": "Missing required query parameter: migration_id" }),
            );
        };
        let Ok(migration_id) = mig_raw.parse::<i64>() else {
            return Response::json(
                400,
                &serde_json::json!({ "error": format!("Invalid migration_id: {mig_raw}") }),
            );
        };
        let before_ts = match parse_instant(&before_raw) {
            Ok(ts) => ts,
            Err(index) => {
                return Response::json(
                    400,
                    &serde_json::json!({
                        "error": format!("Invalid timestamp: Text '{before_raw}' could not be parsed at index {index}")
                    }),
                )
            }
        };
        let found = self
            .available_snapshots()
            .into_iter()
            .filter(|(m, ts, _)| *m == migration_id && *ts <= before_ts)
            .max_by_key(|(_, ts, _)| *ts);
        match found {
            Some((_, _, rt)) => Response::json(200, &serde_json::json!({ "record_time": rt })),
            None => Response::json(
                404,
                &serde_json::json!({ "error": format!("No snapshots found before {before_raw}") }),
            ),
        }
    }

    /// `GET /v0/state/acs/snapshot-timestamp-after?after=<iso>&migration_id=<i64>`.
    fn snapshot_timestamp_after(&self, query: &str) -> Response {
        let Some(after_raw) = query_param(query, "after") else {
            return Response::json(
                400,
                &serde_json::json!({ "error": "Missing required query parameter: after" }),
            );
        };
        let Some(mig_raw) = query_param(query, "migration_id") else {
            return Response::json(
                400,
                &serde_json::json!({ "error": "Missing required query parameter: migration_id" }),
            );
        };
        let Ok(migration_id) = mig_raw.parse::<i64>() else {
            return Response::json(
                400,
                &serde_json::json!({ "error": format!("Invalid migration_id: {mig_raw}") }),
            );
        };
        let after_ts = match parse_instant(&after_raw) {
            Ok(ts) => ts,
            Err(index) => {
                return Response::json(
                    400,
                    &serde_json::json!({
                        "error": format!("Invalid timestamp: Text '{after_raw}' could not be parsed at index {index}")
                    }),
                )
            }
        };
        let found = self
            .available_snapshots()
            .into_iter()
            .filter(|(m, ts, _)| (*m == migration_id && *ts > after_ts) || *m > migration_id)
            .min_by_key(|(_, ts, _)| *ts);
        match found {
            Some((_, _, rt)) => Response::json(200, &serde_json::json!({ "record_time": rt })),
            None => Response::json(
                404,
                &serde_json::json!({ "error": format!("No snapshots found after {after_raw}") }),
            ),
        }
    }

    /// `POST /v0/state/acs/force`.
    fn force_acs_snapshot(&self) -> Response {
        let Some(((m, ts), u)) = self.updates.last() else {
            return Response::json(
                400,
                &serde_json::json!({ "error": "No updates ever happened for a snapshot." }),
            );
        };
        let rt = u["record_time"].as_str().unwrap_or_default().to_string();
        if let Ok(mut forced) = self.forced_snapshots.lock() {
            forced.insert((*m, *ts), rt.clone());
        }
        Response::json(
            200,
            &serde_json::json!({
                "record_time": rt,
                "migration_id": *m,
            }),
        )
    }

    /// `POST /v2/state/acs` and `POST /v0/state/acs`.
    fn state_acs(&self, body: &str) -> Response {
        let Ok(req) = serde_json::from_str::<Json>(body) else {
            return Response {
                status: 400,
                content_type: "text/plain; charset=UTF-8",
                body: "The request content was malformed:\nnot JSON".into(),
            };
        };
        let Some(obj) = req.as_object() else {
            return Response {
                status: 400,
                content_type: "text/plain; charset=UTF-8",
                body: "The request content was malformed:\nDecodingFailure at .migration_id: Missing required field".into(),
            };
        };
        let Some(migration_id) = obj.get("migration_id").and_then(integer) else {
            return Response::json(
                400,
                &serde_json::json!({ "error": "Missing or invalid field: migration_id" }),
            );
        };
        let Some(record_time_raw) = obj.get("record_time").and_then(Json::as_str) else {
            return Response::json(
                400,
                &serde_json::json!({ "error": "Missing or invalid field: record_time" }),
            );
        };
        let req_ts = match parse_instant(record_time_raw) {
            Ok(ts) => ts,
            Err(index) => {
                return Response::json(
                    400,
                    &serde_json::json!({
                        "error": format!("Invalid timestamp: Text '{record_time_raw}' could not be parsed at index {index}")
                    }),
                )
            }
        };
        let match_mode = match obj.get("record_time_match").filter(|&v| !v.is_null()) {
            None => "exact",
            Some(v) => match v.as_str() {
                Some(s @ ("exact" | "at_or_before")) => s,
                _ => {
                    return Response::json(
                        400,
                        &serde_json::json!({ "error": "Invalid record_time_match, expected 'exact' or 'at_or_before'" }),
                    )
                }
            },
        };
        let Some(page_size) = obj.get("page_size").and_then(integer) else {
            return Response::json(
                400,
                &serde_json::json!({ "error": "Missing or invalid field: page_size" }),
            );
        };
        if page_size < 1 {
            return Response::json(
                400,
                &serde_json::json!({ "error": "Limit must be at least 1." }),
            );
        }
        if page_size > MAX_PAGE_SIZE {
            return Response::json(
                400,
                &serde_json::json!({
                    "error": format!("Exceeded limit maximum ({page_size} > {MAX_PAGE_SIZE}).")
                }),
            );
        }
        let after_offset: usize = match obj.get("after").filter(|&v| !v.is_null()) {
            None => 0,
            Some(v) => match integer(v).and_then(|n| usize::try_from(n).ok()) {
                Some(n) => n,
                None => {
                    return Response::json(
                        400,
                        &serde_json::json!({ "error": "Invalid pagination token: after" }),
                    )
                }
            },
        };
        let party_filter: Vec<String> =
            match obj
                .get("party_ids")
                .and_then(|v| if v.is_null() { None } else { v.as_array() })
            {
                None => Vec::new(),
                Some(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
            };
        let mut template_filters: Vec<(String, String)> = Vec::new();
        if let Some(arr) =
            obj.get("templates")
                .and_then(|v| if v.is_null() { None } else { v.as_array() })
        {
            for item in arr {
                let Some(s) = item.as_str() else {
                    return Response::json(
                        400,
                        &serde_json::json!({
                            "error": "Malformed template_id, expected 'package_name:module_name:entity_name'"
                        }),
                    );
                };
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
                    return Response::json(
                        400,
                        &serde_json::json!({
                            "error": "Malformed template_id, expected 'package_name:module_name:entity_name'"
                        }),
                    );
                }
                template_filters.push((parts[0].to_string(), format!("{}:{}", parts[1], parts[2])));
            }
        }
        let snaps = self.available_snapshots();
        let target = match match_mode {
            "exact" => snaps
                .into_iter()
                .find(|(m, ts, _)| *m == migration_id && *ts == req_ts),
            "at_or_before" => snaps
                .into_iter()
                .filter(|(m, ts, _)| *m == migration_id && *ts <= req_ts)
                .max_by_key(|(_, ts, _)| *ts),
            _ => unreachable!(),
        };
        let Some((snap_m, snap_ts, snap_rt)) = target else {
            return Response::json(
                404,
                &serde_json::json!({
                    "error": format!("No snapshots found before {record_time_raw}")
                }),
            );
        };
        let slice: Vec<Json> = self
            .updates
            .iter()
            .filter(|(key, _)| *key <= (snap_m, snap_ts))
            .map(|(_, u)| u.clone())
            .collect();
        let acs = match lf_eval::scan_state::Acs::all_from_updates(&slice) {
            Ok(acs) => acs,
            Err(e) => return Response::json(500, &serde_json::json!({ "error": e })),
        };
        let mut matching = Vec::new();
        for c in acs.contracts() {
            if !party_filter.is_empty()
                && !c
                    .signatories
                    .iter()
                    .chain(c.observers.iter())
                    .any(|p| party_filter.contains(p))
            {
                continue;
            }
            let (package, local_template) = c
                .template_id
                .split_once(':')
                .unwrap_or(("", &c.template_id));
            let resolved_world_types = self.contracts.as_ref().and_then(|state| {
                state
                    .worlds
                    .iter()
                    .map(lf_eval::typed_json::Types::new)
                    .find(|t| t.template(package, local_template).is_ok())
            });
            let resolved_pkg_name = if !c.package_name.is_empty() {
                c.package_name.clone()
            } else {
                resolved_world_types
                    .as_ref()
                    .and_then(|t| t.package_name(package).ok())
                    .unwrap_or_default()
            };
            if !template_filters.is_empty()
                && !template_filters
                    .iter()
                    .any(|(pn, tmpl)| pn == &resolved_pkg_name && tmpl == local_template)
            {
                continue;
            }
            let auth = self
                .contracts
                .as_ref()
                .and_then(|s| s.authentication_data.get(&c.contract_id).map(Vec::as_slice));
            match lf_eval::scan_state::active_contract_event_json(
                resolved_world_types.as_ref(),
                c,
                auth,
                snap_m,
            ) {
                Ok(ev) => matching.push(ev),
                Err(e) => return Response::json(500, &serde_json::json!({ "error": e })),
            }
        }
        let total = matching.len();
        let start = after_offset.min(total);
        let end = (start + page_size as usize).min(total);
        let page = matching[start..end].to_vec();
        let mut resp = serde_json::json!({
            "record_time": snap_rt,
            "migration_id": snap_m,
            "created_events": page,
        });
        if end < total {
            resp["next_page_token"] = Json::String(end.to_string());
        }
        Response::json(200, &resp)
    }
}

fn query_param(query: &str, name: &str) -> Option<String> {
    let raw = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)?
        .1;
    let mut bytes = Vec::with_capacity(raw.len());
    let src = raw.as_bytes();
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'%' && i + 2 < src.len() {
            if let Ok(hex_str) = std::str::from_utf8(&src[i + 1..i + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex_str, 16) {
                    bytes.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        bytes.push(src[i]);
        i += 1;
    }
    String::from_utf8(bytes).ok()
}

/// An instant as (seconds, nanoseconds) since the epoch, from `YYYY-MM-DDTHH:MM[:SS[.fraction]]` followed by `Z` or `±HH:MM`; `Err` is
/// the index of the first character that does not fit (what the official app reports).
pub fn parse_instant(text: &str) -> Result<(i64, u32), usize> {
    let bytes = text.as_bytes();
    let mut at = 0;
    let digits = |at: &mut usize, n: usize| -> Result<i64, usize> {
        let mut value = 0i64;
        for _ in 0..n {
            match bytes.get(*at) {
                Some(c) if c.is_ascii_digit() => value = value * 10 + i64::from(c - b'0'),
                _ => return Err(*at),
            }
            *at += 1;
        }
        Ok(value)
    };
    let expect = |at: &mut usize, c: u8| -> Result<(), usize> {
        if bytes.get(*at) == Some(&c) {
            *at += 1;
            Ok(())
        } else {
            Err(*at)
        }
    };
    let year = digits(&mut at, 4)?;
    expect(&mut at, b'-')?;
    let month = digits(&mut at, 2)?;
    expect(&mut at, b'-')?;
    let day = digits(&mut at, 2)?;
    expect(&mut at, b'T')?;
    let hour = digits(&mut at, 2)?;
    expect(&mut at, b':')?;
    let minute = digits(&mut at, 2)?;
    let (mut second, mut nanos) = (0, 0u32);
    if bytes.get(at) == Some(&b':') {
        at += 1;
        second = digits(&mut at, 2)?;
        if bytes.get(at) == Some(&b'.') {
            at += 1;
            let start = at;
            while at - start < 9 && bytes.get(at).is_some_and(u8::is_ascii_digit) {
                nanos = nanos * 10 + u32::from(bytes[at] - b'0');
                at += 1;
            }
            if at == start {
                return Err(at);
            }
            nanos *= 10u32.pow(9 - (at - start) as u32);
        }
    }
    let offset_seconds = match bytes.get(at) {
        Some(b'Z') => {
            at += 1;
            0
        }
        Some(sign @ (b'+' | b'-')) => {
            let sign = if *sign == b'+' { 1 } else { -1 };
            at += 1;
            let hours = digits(&mut at, 2)?;
            expect(&mut at, b':')?;
            let minutes = digits(&mut at, 2)?;
            sign * (hours * 3600 + minutes * 60)
        }
        _ => return Err(at),
    };
    if at != bytes.len() {
        return Err(at);
    }
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(0);
    }
    // days since the epoch of a civil date (the proleptic Gregorian calendar)
    let y = if month <= 2 { year - 1 } else { year };
    let (era, yoe) = (y.div_euclid(400), y.rem_euclid(400));
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Ok((
        days * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds,
        nanos,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_are_read_with_fractions_and_offsets_and_failures_say_where() {
        assert_eq!(parse_instant("1970-01-01T00:00:00Z"), Ok((0, 0)));
        assert_eq!(
            parse_instant("1970-01-01T00:00:01.5Z"),
            Ok((1, 500_000_000))
        );
        assert_eq!(parse_instant("1970-01-01T01:00:00+01:00"), Ok((0, 0)));
        assert_eq!(
            parse_instant("2026-11-14T01:35:03.504972999Z"),
            Ok((1_794_620_103, 504_972_999))
        );
        assert_eq!(parse_instant("yesterday"), Err(0));
        assert_eq!(parse_instant("2026-11-14T01:35:03000000Z"), Err(19));
        assert_eq!(parse_instant("2026-11-14T01:35:03."), Err(20));
    }

    #[test]
    fn acs_snapshot_timestamps_force_and_paginated_filtered_state_acs() {
        let empty = UpdateHistory::new(vec![]);
        let force_empty = empty.handle("POST", "/api/scan/v0/state/acs/force", "");
        assert_eq!(force_empty.status, 400);
        let err_json: Json = serde_json::from_str(&force_empty.body).unwrap();
        assert_eq!(
            err_json["error"],
            "No updates ever happened for a snapshot."
        );

        let updates = vec![
            serde_json::json!({
                "update_id": "#u1",
                "migration_id": 0,
                "record_time": "2026-11-16T01:00:00Z",
                "synchronizer_id": "sync::0",
                "root_event_ids": ["e1"],
                "events_by_id": {
                    "#u1:0": {
                        "event_type": "created_event",
                        "event_id": "#u1:0",
                        "contract_id": "c1",
                        "template_id": "pkg1:Mod:Amulet",
                        "package_name": "splice-amulet",
                        "create_arguments": { "owner": "alice" },
                        "created_at": "2026-11-16T01:00:00Z",
                        "signatories": ["alice"],
                        "observers": []
                    }
                }
            }),
            serde_json::json!({
                "update_id": "#u2",
                "migration_id": 0,
                "record_time": "2026-11-16T02:00:00Z",
                "synchronizer_id": "sync::0",
                "root_event_ids": ["e2", "e3"],
                "events_by_id": {
                    "#u2:0": {
                        "event_type": "created_event",
                        "event_id": "#u2:0",
                        "contract_id": "c2",
                        "template_id": "pkg1:Mod:Amulet",
                        "package_name": "splice-amulet",
                        "create_arguments": { "owner": "bob" },
                        "created_at": "2026-11-16T02:00:00Z",
                        "signatories": ["bob"],
                        "observers": ["carol"]
                    },
                    "#u2:1": {
                        "event_type": "created_event",
                        "event_id": "#u2:1",
                        "contract_id": "c3",
                        "template_id": "pkg2:Other:Vote",
                        "package_name": "splice-governance",
                        "create_arguments": { "voter": "dso" },
                        "created_at": "2026-11-16T02:00:00Z",
                        "signatories": ["dso"],
                        "observers": []
                    }
                }
            }),
            serde_json::json!({
                "update_id": "#u3",
                "migration_id": 0,
                "record_time": "2026-11-16T03:00:00Z",
                "synchronizer_id": "sync::0",
                "root_event_ids": ["e4"],
                "events_by_id": {
                    "#u3:0": {
                        "event_type": "exercised_event",
                        "event_id": "#u3:0",
                        "contract_id": "c1",
                        "consuming": true
                    }
                }
            }),
        ];
        let scan = UpdateHistory::new(updates);

        // snapshot-timestamp before
        let before_t2 = scan.handle(
            "GET",
            "/api/scan/v0/state/acs/snapshot-timestamp?before=2026-11-16T02%3A30%3A00Z&migration_id=0",
            "",
        );
        assert_eq!(before_t2.status, 200, "{}", before_t2.body);
        assert_eq!(
            serde_json::from_str::<Json>(&before_t2.body).unwrap()["record_time"],
            "2026-11-16T02:00:00Z"
        );
        let before_none = scan.handle(
            "GET",
            "/api/scan/v0/state/acs/snapshot-timestamp?before=2026-11-16T00:00:00Z&migration_id=0",
            "",
        );
        assert_eq!(before_none.status, 404);
        assert!(before_none.body.contains("No snapshots found before"));

        // snapshot-timestamp-after (strictly > after)
        let after_t1 = scan.handle(
            "GET",
            "/api/scan/v0/state/acs/snapshot-timestamp-after?after=2026-11-16T01:00:00Z&migration_id=0",
            "",
        );
        assert_eq!(after_t1.status, 200, "{}", after_t1.body);
        assert_eq!(
            serde_json::from_str::<Json>(&after_t1.body).unwrap()["record_time"],
            "2026-11-16T02:00:00Z"
        );
        let after_none = scan.handle(
            "GET",
            "/api/scan/v0/state/acs/snapshot-timestamp-after?after=2026-11-16T03:00:00Z&migration_id=0",
            "",
        );
        assert_eq!(after_none.status, 404);
        assert!(after_none.body.contains("No snapshots found after"));

        // force snapshot
        let forced = scan.handle("POST", "/api/scan/v0/state/acs/force", "");
        assert_eq!(forced.status, 200, "{}", forced.body);
        assert_eq!(
            serde_json::from_str::<Json>(&forced.body).unwrap(),
            serde_json::json!({ "record_time": "2026-11-16T03:00:00Z", "migration_id": 0 })
        );

        // /v2/state/acs exact at t2 -> c1, c2, c3 in creation order, created_in_update_id without leading '#'
        let exact_t2 = scan.handle(
            "POST",
            "/api/scan/v2/state/acs",
            r#"{"migration_id":0,"record_time":"2026-11-16T02:00:00Z","page_size":10}"#,
        );
        assert_eq!(exact_t2.status, 200, "{}", exact_t2.body);
        let body_t2: Json = serde_json::from_str(&exact_t2.body).unwrap();
        let cids_t2: Vec<&str> = body_t2["created_events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["contract_id"].as_str().unwrap())
            .collect();
        assert_eq!(cids_t2, vec!["c1", "c2", "c3"]);
        assert_eq!(body_t2["created_events"][0]["created_in_update_id"], "u1");
        assert!(body_t2.get("next_page_token").is_none());

        // at_or_before at 03:30 -> snapshot t3 where c1 was archived
        let at_t3 = scan.handle(
            "POST",
            "/api/scan/v0/state/acs",
            r#"{"migration_id":0,"record_time":"2026-11-16T03:30:00Z","record_time_match":"at_or_before","page_size":1}"#,
        );
        assert_eq!(at_t3.status, 200, "{}", at_t3.body);
        let page1: Json = serde_json::from_str(&at_t3.body).unwrap();
        assert_eq!(page1["created_events"][0]["contract_id"], "c2");
        assert_eq!(page1["next_page_token"], "1");

        let page2_resp = scan.handle(
            "POST",
            "/api/scan/v2/state/acs",
            r#"{"migration_id":0,"record_time":"2026-11-16T03:30:00Z","record_time_match":"at_or_before","after":"1","page_size":1}"#,
        );
        assert_eq!(page2_resp.status, 200);
        let page2: Json = serde_json::from_str(&page2_resp.body).unwrap();
        assert_eq!(page2["created_events"][0]["contract_id"], "c3");
        assert!(page2.get("next_page_token").is_none());

        // filters: party_ids and templates
        let filtered = scan.handle(
            "POST",
            "/api/scan/v2/state/acs",
            r#"{"migration_id":0,"record_time":"2026-11-16T02:00:00Z","page_size":10,"party_ids":["carol"],"templates":["splice-amulet:Mod:Amulet"]}"#,
        );
        assert_eq!(filtered.status, 200);
        let filtered_json: Json = serde_json::from_str(&filtered.body).unwrap();
        assert_eq!(filtered_json["created_events"].as_array().unwrap().len(), 1);
        assert_eq!(filtered_json["created_events"][0]["contract_id"], "c2");

        // malformed template filter -> 400
        let bad_tmpl = scan.handle(
            "POST",
            "/api/scan/v2/state/acs",
            r#"{"migration_id":0,"record_time":"2026-11-16T02:00:00Z","page_size":10,"templates":["BadTemplate"]}"#,
        );
        assert_eq!(bad_tmpl.status, 400);
        assert!(bad_tmpl.body.contains("Malformed template_id"));
    }
}
