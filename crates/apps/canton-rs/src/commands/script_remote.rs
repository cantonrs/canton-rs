//! The ledger a remote `canton-rs script --ledger-host/--ledger-port` runs against: a participant's JSON Ledger API v2 (S-SCRIPT-002).
//!
//! [CANTON-NOTE: SEMANTICS] Each script question becomes the JSON API call a client would make:
//! - `allocateParty` → `POST /v2/parties` (`partyIdHint`), `listKnownParties` → `GET /v2/parties`;
//! - a submission → one `POST /v2/commands/submit-and-wait-for-transaction` with the commands in order (`CreateCommand`,
//!   `ExerciseCommand`, `CreateAndExerciseCommand`), shape `LEDGER_EFFECTS`; the results are read from the transaction's **root** events
//!   (an event whose node lies inside an earlier exercise's `lastDescendantNodeId` is a consequence, not a command's result);
//!   a non-2xx answer is the ledger refusing the submission (`Left` for `submitMustFail`/`trySubmit`);
//! - `query`/`queryContractId` → `GET /v2/state/ledger-end` then `POST /v2/state/active-contracts` with a template filter by package
//!   **name** (`#name:Module:Entity`, what the API takes), keeping the contracts of the asked package id.
//!
//! Values cross as the Daml-LF JSON encoding, typed by the DAR the script was compiled with (`lf_eval::typed_json::Types`).
//!
//! [CANTON-NOTE: LIMITATION] Plain HTTP only (no TLS, no auth token, [`super::json_http`]). The time a script reads is the runner's clock (the JSON API has no
//! time service); `setTime`, keys (`queryByKey`, `exerciseByKey`), explicit disclosures and user management are refused by the host.
use lf_eval::script::{LedgerCommand, LedgerResult, ScriptLedger};
use lf_eval::typed_json::Types;
use lf_eval::World;
use serde_json::{json, Value as Json};

pub struct JsonApiLedger<'w> {
    host: String,
    port: u16,
    user_id: String,
    types: Types<'w>,
    next_command: u64,
}

impl<'w> JsonApiLedger<'w> {
    pub fn new(host: &str, port: u16, user_id: &str, world: &'w World) -> Result<Self, String> {
        let ledger = Self {
            host: host.to_string(),
            port,
            user_id: user_id.to_string(),
            types: Types::new(world),
            next_command: 1,
        };
        // fail early, with the address, when nothing answers there
        let (status, _) = ledger.call("GET", "/v2/state/ledger-end", None)?;
        if status != 200 {
            return Err(format!(
                "the JSON Ledger API at {host}:{port} answered {status} to GET /v2/state/ledger-end"
            ));
        }
        Ok(ledger)
    }

    fn call(&self, method: &str, path: &str, body: Option<&Json>) -> Result<(u16, Json), String> {
        super::json_http::call_json(&self.host, self.port, method, path, body)
    }

    fn template_id(package_id: &str, template: &str) -> String {
        format!("{package_id}:{template}")
    }

    fn command_json(&self, command: &LedgerCommand) -> Result<Json, String> {
        Ok(match command {
            LedgerCommand::Create {
                package_id,
                template,
                argument,
            } => {
                let ty = self.types.template(package_id, template)?;
                json!({ "CreateCommand": {
                    "templateId": Self::template_id(package_id, template),
                    "createArguments": self.types.encode(&ty, argument)?,
                }})
            }
            LedgerCommand::Exercise {
                package_id,
                template,
                contract_id,
                choice,
                argument,
            } => {
                let ty = self.types.choice(package_id, template, choice)?.argument;
                json!({ "ExerciseCommand": {
                    "templateId": Self::template_id(package_id, template),
                    "contractId": contract_id,
                    "choice": choice,
                    "choiceArgument": self.types.encode(&ty, argument)?,
                }})
            }
            LedgerCommand::CreateAndExercise {
                package_id,
                template,
                argument,
                choice,
                choice_argument,
            } => {
                let tty = self.types.template(package_id, template)?;
                let cty = self.types.choice(package_id, template, choice)?.argument;
                json!({ "CreateAndExerciseCommand": {
                    "templateId": Self::template_id(package_id, template),
                    "createArguments": self.types.encode(&tty, argument)?,
                    "choice": choice,
                    "choiceArgument": self.types.encode(&cty, choice_argument)?,
                }})
            }
        })
    }

    fn wildcard(parties: &[String]) -> Json {
        let mut by_party = serde_json::Map::new();
        for p in parties {
            by_party.insert(
                p.clone(),
                json!({ "cumulative": [{ "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": false } } } }] }),
            );
        }
        Json::Object(by_party)
    }
}

use super::json_http::error_cause;

impl ScriptLedger for JsonApiLedger<'_> {
    fn allocate_party(&mut self, hint: &str) -> Result<String, String> {
        let (status, body) = self.call(
            "POST",
            "/v2/parties",
            Some(&json!({ "partyIdHint": hint, "identityProviderId": "" })),
        )?;
        if status != 200 {
            return Err(format!("allocateParty {hint}: {}", error_cause(&body)));
        }
        body.pointer("/partyDetails/party")
            .and_then(Json::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("allocateParty {hint}: no party in {body}"))
    }

    fn known_parties(&mut self) -> Result<Vec<(String, bool)>, String> {
        let (status, body) = self.call("GET", "/v2/parties", None)?;
        if status != 200 {
            return Err(format!("listKnownParties: {}", error_cause(&body)));
        }
        Ok(body["partyDetails"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        Some((
                            p["party"].as_str()?.to_string(),
                            p["isLocal"].as_bool().unwrap_or(true),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn submit(
        &mut self,
        act_as: &[String],
        read_as: &[String],
        commands: &[LedgerCommand],
    ) -> Result<Result<Vec<LedgerResult>, String>, String> {
        let encoded = commands
            .iter()
            .map(|c| self.command_json(c))
            .collect::<Result<Vec<_>, _>>()?;
        let command_id = format!(
            "canton-rs-script-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            self.next_command
        );
        self.next_command += 1;
        let body = json!({
            "commands": {
                "commands": encoded,
                "commandId": command_id,
                "actAs": act_as,
                "readAs": read_as,
                "userId": self.user_id,
            },
            "transactionFormat": {
                "eventFormat": { "filtersByParty": Self::wildcard(act_as), "verbose": true },
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS",
            }
        });
        let (status, answer) = self.call(
            "POST",
            "/v2/commands/submit-and-wait-for-transaction",
            Some(&body),
        )?;
        if !(200..300).contains(&status) {
            return Ok(Err(error_cause(&answer)));
        }
        // the root events, in node order: one result per create, one per exercise
        let mut events: Vec<&Json> = answer
            .pointer("/transaction/events")
            .and_then(Json::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        let node = |e: &Json| -> i64 {
            e.as_object()
                .and_then(|o| o.values().next())
                .and_then(|v| v["nodeId"].as_i64())
                .unwrap_or(0)
        };
        events.sort_by_key(|e| node(e));
        let mut roots: Vec<&Json> = Vec::new();
        let mut covered_until = -1i64;
        for e in events {
            let n = node(e);
            if n <= covered_until {
                continue;
            }
            if let Some(last) = e
                .pointer("/ExercisedEvent/lastDescendantNodeId")
                .and_then(Json::as_i64)
            {
                covered_until = last;
            }
            roots.push(e);
        }
        // the shapes the commands expect, in order
        #[allow(
            clippy::type_complexity,
            reason = "protocol or ledger hook signature uses an inline composite type"
        )] // [CANTON-NOTE: STYLE] a local list, typed once
        let mut expected: Vec<(&str, Option<(String, String, String)>)> = Vec::new();
        for c in commands {
            match c {
                LedgerCommand::Create { .. } => expected.push(("create", None)),
                LedgerCommand::Exercise {
                    package_id,
                    template,
                    choice,
                    ..
                } => expected.push((
                    "exercise",
                    Some((package_id.clone(), template.clone(), choice.clone())),
                )),
                LedgerCommand::CreateAndExercise {
                    package_id,
                    template,
                    choice,
                    ..
                } => {
                    expected.push(("create", None));
                    expected.push((
                        "exercise",
                        Some((package_id.clone(), template.clone(), choice.clone())),
                    ));
                }
            }
        }
        if roots.len() != expected.len() {
            return Err(format!(
                "the transaction has {} root events for {} expected results: {answer}",
                roots.len(),
                expected.len()
            ));
        }
        let mut results = Vec::new();
        for (event, (kind, target)) in roots.into_iter().zip(expected) {
            match (kind, event.get("CreatedEvent"), event.get("ExercisedEvent")) {
                ("create", Some(created), _) => results.push(LedgerResult::Created(
                    created["contractId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                )),
                ("exercise", _, Some(exercised)) => {
                    let (package_id, template, choice) = target.expect("set for exercises");
                    let ty = self.types.choice(&package_id, &template, &choice)?.result;
                    let value = self
                        .types
                        .decode(&ty, exercised.get("exerciseResult").unwrap_or(&Json::Null))?;
                    results.push(LedgerResult::Exercised(value));
                }
                _ => return Err(format!("unexpected root event {event} for a {kind}")),
            }
        }
        Ok(Ok(results))
    }

    fn active_contracts(
        &mut self,
        parties: &[String],
        package_id: &str,
        template: &str,
    ) -> Result<Vec<(String, lf_eval::Value)>, String> {
        let (_, end) = self.call("GET", "/v2/state/ledger-end", None)?;
        let offset = end["offset"].clone();
        let name = self.types.package_name(package_id)?;
        let filter_id = format!("#{name}:{template}");
        let mut by_party = serde_json::Map::new();
        for p in parties {
            by_party.insert(
                p.clone(),
                json!({ "cumulative": [{ "identifierFilter": { "TemplateFilter": { "value": {
                    "templateId": filter_id, "includeCreatedEventBlob": false } } } }] }),
            );
        }
        let (status, answer) = self.call(
            "POST",
            "/v2/state/active-contracts",
            Some(&json!({
                "eventFormat": { "filtersByParty": by_party, "verbose": true },
                "activeAtOffset": offset,
            })),
        )?;
        if status != 200 {
            return Err(format!("query {filter_id}: {}", error_cause(&answer)));
        }
        let ty = self.types.template(package_id, template)?;
        let mut out: Vec<(String, lf_eval::Value)> = Vec::new();
        for entry in answer.as_array().cloned().unwrap_or_default() {
            let Some(created) = entry.pointer("/contractEntry/JsActiveContract/createdEvent")
            else {
                continue;
            };
            let tid = created["templateId"].as_str().unwrap_or_default();
            if !tid.starts_with(&format!("{package_id}:")) {
                continue;
            }
            let cid = created["contractId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if out.iter().any(|(c, _)| *c == cid) {
                continue;
            }
            let value = self
                .types
                .decode(&ty, created.get("createArgument").unwrap_or(&Json::Null))?;
            out.push((cid, value));
        }
        Ok(out)
    }

    fn now_micros(&mut self) -> Result<i64, String> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0))
    }
}
