//! The Token Standard registry of the scan app (`/registry/metadata/v1/*`, `/registry/transfer-instruction/v1/*`): the endpoints a wallet
//! asks for the instruments an admin issues and for the contracts a transfer has to disclose (U-25, the Wallet SDK's `amulet.tap`).
//!
//! [CANTON-NOTE: SEMANTICS] Measured on the official Splice 0.10.1 scan of the LocalNet (`GET /registry/metadata/v1/{info,instruments}`,
//! `POST /registry/transfer-instruction/v1/transfer-factory`): the registry is at the root of the scan app, not under `/api/scan`; the
//! admin of the only instrument `Amulet` is the DSO party; the transfer factory is the active `ExternalPartyAmuletRules`, its
//! `choiceContext` names the `amulet-rules`, the `open-round` and the `external-party-config-state` contracts, and the contracts
//! disclosed are those three and the factory, in the order `AmuletRules`, `OpenMiningRound`, `ExternalPartyConfigState`,
//! `ExternalPartyAmuletRules`. The kind is `self` when sender and receiver are the same party, else `offer`.
//! [CANTON-NOTE: LIMITATION] A receiver with a `TransferPreapproval` makes the official kind `direct` (its context carries the preapproval and
//! the featured app right); this answers `offer` for it. The `total supply` is the sum of the active `Amulet` contracts' initial amounts,
//! not the official aggregate of the round, which also nets the holding fees. The choice contexts of an existing transfer instruction
//! (`accept`, `reject`, `withdraw`) and the allocation endpoints are not served (`404`).
use super::{query_param, ContractState, Response, UpdateHistory};
use serde_json::{json, Value as Json};

fn not_found(what: &str) -> Response {
    Response::json(404, &json!({ "error": what }))
}

fn bad_request(what: &str) -> Response {
    Response::json(400, &json!({ "error": what }))
}

const SUPPORTED_APIS: [&str; 10] = [
    "splice-api-token-transfer-instruction-v2",
    "splice-api-token-allocation-v1",
    "splice-api-token-holding-v2",
    "splice-api-token-allocation-instruction-v2",
    "splice-api-token-metadata-v1",
    "splice-api-token-allocation-v2",
    "splice-api-token-transfer-events-v2",
    "splice-api-token-transfer-instruction-v1",
    "splice-api-token-holding-v1",
    "splice-api-token-allocation-instruction-v1",
];

impl ContractState {
    /// The synchronizer the amulet configuration names as the active one (where the contracts of a transfer are disclosed for).
    fn active_synchronizer(&self) -> Option<String> {
        self.acs
            .of_template("Splice.AmuletRules:AmuletRules")
            .first()
            .and_then(|c| {
                c.payload["configSchedule"]["initialValue"]["decentralizedSynchronizer"]
                    ["activeSynchronizer"]
                    .as_str()
                    .map(String::from)
            })
    }

    /// A contract as a `DisclosedContract` of a registry answer (its blob, the synchronizer it is on; the debug fields only on request).
    fn disclosed(
        &self,
        c: &lf_eval::scan_state::ActiveContract,
        synchronizer: Option<&str>,
        with_debug: bool,
    ) -> Result<Json, String> {
        let rendered = self.render(c)?;
        let contract = &rendered["contract"];
        Ok(json!({
            "templateId": contract["template_id"],
            "contractId": contract["contract_id"],
            "createdEventBlob": contract["created_event_blob"],
            "synchronizerId": synchronizer.map_or_else(|| c.synchronizer_id.clone(), String::from),
            "debugPackageName": if with_debug { json!(c.package_name) } else { Json::Null },
            "debugPayload": if with_debug { contract["payload"].clone() } else { Json::Null },
            "debugCreatedAt": if with_debug { contract["created_at"].clone() } else { Json::Null },
        }))
    }

    /// The DSO party: the admin of the instrument.
    fn dso(&self) -> Option<String> {
        ["Splice.AmuletRules:AmuletRules", "Splice.DsoRules:DsoRules"]
            .iter()
            .find_map(|t| {
                self.acs
                    .of_template(t)
                    .first()
                    .and_then(|c| c.payload["dso"].as_str().map(String::from))
            })
    }

    /// The sum of the initial amounts of the active `Amulet` contracts, as a `Numeric 10` text.
    fn total_supply(&self) -> String {
        let mut tenth_billionths: i128 = 0;
        for c in self.acs.of_template("Splice.Amulet:Amulet") {
            if let Some((coeff, scale)) = c.payload["amount"]["initialAmount"]
                .as_str()
                .and_then(|t| lf_eval::typed_json::numeric(t, 10))
            {
                tenth_billionths += coeff * 10i128.pow(10u32.saturating_sub(scale as u32));
            }
        }
        // a plain decimal with 10 fraction digits (the scan prints `12664199.0414640000`, not the Java text `0E-10`)
        format!(
            "{}.{:010}",
            tenth_billionths / 10_000_000_000,
            tenth_billionths % 10_000_000_000
        )
    }

    /// The open round a transfer is made in: the round open now with the latest opening, else the highest round.
    fn open_round(&self, now_micros: i64) -> Option<&lf_eval::scan_state::ActiveContract> {
        let rounds = self.acs.of_template("Splice.Round:OpenMiningRound");
        let at = |c: &lf_eval::scan_state::ActiveContract, f: &str| {
            c.payload[f]
                .as_str()
                .and_then(|t| lf_eval::scan_state::parse_micros(t).ok())
        };
        let number = |c: &lf_eval::scan_state::ActiveContract| {
            c.payload["round"]["number"]
                .as_str()
                .and_then(|n| n.parse::<i64>().ok())
        };
        rounds
            .iter()
            .copied()
            .filter(|c| {
                at(c, "opensAt").is_some_and(|o| o <= now_micros)
                    && at(c, "targetClosesAt").is_none_or(|t| now_micros < t)
            })
            .max_by_key(|c| (at(c, "opensAt"), number(c)))
            .or_else(|| rounds.into_iter().max_by_key(|c| number(c)))
    }
}

impl UpdateHistory {
    /// The answer to a request under `/registry/` (`route` is what follows it).
    pub(super) fn registry_endpoint(
        &self,
        method: &str,
        route: &str,
        query: &str,
        body: &str,
    ) -> Response {
        let Some(state) = self.contracts.as_ref() else {
            return not_found(
                "the scan serves no contracts (start it with the DARs of the history)",
            );
        };
        let Some(dso) = state.dso() else {
            return not_found("found no DSO party");
        };
        let instrument = |as_of: &str| {
            json!({
                "id": "Amulet",
                "name": "Amulet",
                "symbol": "AMT",
                "totalSupply": state.total_supply(),
                "totalSupplyAsOf": as_of,
                "decimals": 10,
                "paused": false,
                "pauseInfo": null,
                "supportedApis": SUPPORTED_APIS.iter().map(|a| (a.to_string(), json!(1))).collect::<serde_json::Map<_, _>>(),
                "showAccountInputFields": false,
                "accountInputFieldsToShow": null,
            })
        };
        let as_of = self
            .updates
            .last()
            .and_then(|(_, u)| u["record_time"].as_str().map(String::from))
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
        match (method, route) {
            ("GET", "metadata/v1/info") => Response::json(
                200,
                &json!({ "adminId": dso, "supportedApis": { "splice-api-token-metadata-v1": 1 } }),
            ),
            ("GET", "metadata/v1/instruments") => {
                let _ = query_param(query, "pageSize");
                Response::json(
                    200,
                    &json!({ "instruments": [instrument(&as_of)], "nextPageToken": null }),
                )
            }
            ("GET", id) if id.starts_with("metadata/v1/instruments/") => {
                if id.trim_start_matches("metadata/v1/instruments/") == "Amulet" {
                    Response::json(200, &instrument(&as_of))
                } else {
                    not_found("no such instrument")
                }
            }
            ("POST", "transfer-instruction/v1/transfer-factory") => {
                self.transfer_factory(state, &dso, body)
            }
            ("POST", other)
                if other.starts_with("transfer-instruction/v1/")
                    && other.contains("/choice-contexts/") =>
            {
                let rest = other.trim_start_matches("transfer-instruction/v1/");
                let (cid, choice) = rest.split_once("/choice-contexts/").unwrap_or((rest, ""));
                self.instruction_choice_context(state, cid, choice, body)
            }
            _ => not_found("Not found"),
        }
    }

    /// The choice context of `accept` (and `reject`, `withdraw`) of the transfer instruction `cid`: the contexts of a transfer plus the lock.
    ///
    /// [CANTON-NOTE: SEMANTICS] Measured on the official scan for `accept` of an `AmuletTransferInstruction`: the values are `amulet-rules`,
    /// `open-round`, `external-party-config-state` (contract ids) and `expire-lock` (`AV_Bool`, `true`), and the contracts disclosed are
    /// `AmuletRules`, `OpenMiningRound`, `ExternalPartyConfigState` and the `LockedAmulet` the instruction holds. `reject` and `withdraw`
    /// are answered the same way (not measured).
    fn instruction_choice_context(
        &self,
        state: &ContractState,
        cid: &str,
        choice: &str,
        body: &str,
    ) -> Response {
        if !["accept", "reject", "withdraw"].contains(&choice) {
            return not_found("Not found");
        }
        let Some(instruction) = state
            .acs
            .of_template("Splice.AmuletTransferInstruction:AmuletTransferInstruction")
            .into_iter()
            .find(|c| c.contract_id == cid)
        else {
            return not_found(&format!("no transfer instruction {cid}"));
        };
        let Some(locked) = instruction.payload["lockedAmulet"].as_str().and_then(|l| {
            state
                .acs
                .of_template("Splice.Amulet:LockedAmulet")
                .into_iter()
                .find(|c| c.contract_id == l)
        }) else {
            return not_found("the transfer instruction's locked amulet is not active");
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros() as i64);
        let (Some(rules), Some(round), Some(config)) = (
            state
                .acs
                .of_template("Splice.AmuletRules:AmuletRules")
                .last()
                .copied(),
            state.open_round(now),
            state
                .acs
                .of_template("Splice.ExternalPartyConfigState:ExternalPartyConfigState")
                .last()
                .copied(),
        ) else {
            return not_found(
                "the ledger has no AmuletRules, open round or external party config state yet",
            );
        };
        let with_debug = serde_json::from_str::<Json>(body)
            .map(|r| r["excludeDebugFields"] == json!(false))
            .unwrap_or(false);
        let sync = state.active_synchronizer();
        let mut disclosed = Vec::new();
        for c in [rules, round, config, locked] {
            match state.disclosed(c, sync.as_deref(), with_debug) {
                Ok(d) => disclosed.push(d),
                Err(e) => return Response::json(500, &json!({ "error": e })),
            }
        }
        let id = |c: &lf_eval::scan_state::ActiveContract| json!({ "tag": "AV_ContractId", "value": c.contract_id });
        Response::json(
            200,
            &json!({
                "choiceContextData": { "values": {
                    "expire-lock": { "tag": "AV_Bool", "value": true },
                    "open-round": id(round),
                    "external-party-config-state": id(config),
                    "amulet-rules": id(rules),
                } },
                "disclosedContracts": disclosed,
            }),
        )
    }

    fn transfer_factory(&self, state: &ContractState, dso: &str, body: &str) -> Response {
        let Ok(request) = serde_json::from_str::<Json>(body) else {
            return bad_request("The request content was malformed: not JSON");
        };
        let args = &request["choiceArguments"];
        if args["expectedAdmin"].as_str() != Some(dso) {
            return bad_request("expectedAdmin is not the admin of this registry");
        }
        let transfer = &args["transfer"];
        let kind = if transfer["sender"] == transfer["receiver"] {
            "self"
        } else {
            "offer"
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros() as i64);
        let (Some(rules), Some(round), Some(config), Some(factory)) = (
            state
                .acs
                .of_template("Splice.AmuletRules:AmuletRules")
                .last()
                .copied(),
            state.open_round(now),
            state
                .acs
                .of_template("Splice.ExternalPartyConfigState:ExternalPartyConfigState")
                .last()
                .copied(),
            state
                .acs
                .of_template("Splice.ExternalPartyAmuletRules:ExternalPartyAmuletRules")
                .last()
                .copied(),
        ) else {
            return not_found("the ledger has no AmuletRules, open round, external party config state or ExternalPartyAmuletRules yet");
        };
        let with_debug = request["excludeDebugFields"] == json!(false);
        let sync = state.active_synchronizer();
        let mut disclosed = Vec::new();
        for c in [rules, round, config, factory] {
            match state.disclosed(c, sync.as_deref(), with_debug) {
                Ok(d) => disclosed.push(d),
                Err(e) => return Response::json(500, &json!({ "error": e })),
            }
        }
        let value = |c: &lf_eval::scan_state::ActiveContract| json!({ "tag": "AV_ContractId", "value": c.contract_id });
        Response::json(
            200,
            &json!({
                "factoryId": factory.contract_id,
                "transferKind": kind,
                "choiceContext": {
                    "choiceContextData": { "values": {
                        "open-round": value(round),
                        "external-party-config-state": value(config),
                        "amulet-rules": value(rules),
                    } },
                    "disclosedContracts": disclosed,
                },
            }),
        )
    }
}
