//! The state of the network as the Splice scan app serves it (G8, S-SPL-009): the active contracts an update history leaves, and a contract as
//! the scan prints it with its `created_event_blob` (`ContractWithState`).
//!
//! [CANTON-NOTE: SEMANTICS] The active set is built from the update items alone: a created event adds its contract, a consuming exercised
//! event removes it, in the order of the history (migration id, record time) and of the event numbers inside an update. The scan app keeps
//! its own store; this is what that store holds when it has ingested exactly these updates.
//!
//! [CANTON-NOTE: LIMITATION] The contract salt in a blob (`authentication_data`) is not part of any update: the caller supplies it per contract.
use crate::scan_update::{created_event_blob, BlobContract};
use crate::typed_json::{format_timestamp_micros, Types};
use serde_json::{json, Value as Json};

/// A contract an update history leaves active.
#[derive(Clone, Debug)]
pub struct ActiveContract {
    pub contract_id: String,
    /// `<package id>:<Module>:<Entity>`.
    pub template_id: String,
    pub package_name: String,
    pub payload: Json,
    pub created_at_micros: i64,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    pub synchronizer_id: String,
    /// Update id where this contract was created (without leading `#`).
    pub created_in_update_id: Option<String>,
    /// Migration id of the update that created this contract.
    pub created_in_migration_id: i64,
    /// The number the scan app's store gives the contract: its position among the created events of the templates the scan store ingests
    /// ([`SCAN_ACS_TEMPLATES`]), counted from 1 in history order; 0 for a template the store does not ingest. Pagination tokens are these
    /// numbers (S-SPL-029).
    pub event_number: u64,
}

/// The templates `ScanStore.contractFilter` ingests into the scan app's ACS store (Splice 0.10.1), by entity name. Each created event of one
/// of them takes the next `event_number` of the table (an identity column; measured: the license of a fresh LocalNet whose history holds
/// 11 such created events before it has `next_page_token` 13 = 11 + the two the first count missed, `SvNodeState` and `AmuletPriceVote`).
pub const SCAN_ACS_TEMPLATES: &[&str] = &[
    "Amulet",
    "AmuletAllocation",
    "AmuletPriceVote",
    "AmuletRules",
    "AmuletTransferInstruction",
    "AnsEntry",
    "AnsRules",
    "ClosedMiningRound",
    "DsoRules",
    "ExternalPartyAmuletRules",
    "ExternalPartyConfigState",
    "FeaturedAppRight",
    "GovernanceLock",
    "GovernanceLockSubstitution",
    "GovernanceLockTransfer",
    "IssuingMiningRound",
    "LockedAmulet",
    "MemberTraffic",
    "OpenMiningRound",
    "SummarizingMiningRound",
    "SvNodeState",
    "TransferCommandCounter",
    "TransferPreapproval",
    "UnclaimedDevelopmentFundCoupon",
    "ValidatorLicense",
    "VoteRequest",
];

/// The active contracts in creation order.
#[derive(Clone, Debug, Default)]
pub struct Acs {
    contracts: Vec<ActiveContract>,
}

impl Acs {
    /// The active set after `updates` (already in history order), tracking `SCAN_ACS_TEMPLATES` event numbers.
    pub fn from_updates(updates: &[Json]) -> Result<Self, String> {
        Self::build_acs(updates, true)
    }

    /// The full active set after `updates` across all templates (used by `/v2/state/acs` snapshot queries).
    pub fn all_from_updates(updates: &[Json]) -> Result<Self, String> {
        Self::build_acs(updates, false)
    }

    /// All active contracts in creation order.
    pub fn contracts(&self) -> &[ActiveContract] {
        &self.contracts
    }

    fn build_acs(updates: &[Json], only_ingested: bool) -> Result<Self, String> {
        let mut contracts: Vec<ActiveContract> = Vec::new();
        let mut next_event_number: u64 = 1;
        for update in updates {
            let Some(events) = update["events_by_id"].as_object() else {
                continue;
            };
            let update_id = update["update_id"]
                .as_str()
                .map(|s| s.strip_prefix('#').unwrap_or(s).to_string());
            let migration_id = update["migration_id"].as_i64().unwrap_or(0);
            // a contract created and archived inside one update is never ingested by the scan store, so it takes no event number
            // (measured on two LocalNet captures: the 4 transient `Amulet`s of the older one account for the difference between the token
            // 36 and the count 40, S-SPL-029)
            let archived_here: std::collections::BTreeSet<&str> = events
                .values()
                .filter(|e| e["event_type"] == "exercised_event" && e["consuming"] == true)
                .filter_map(|e| e["contract_id"].as_str())
                .collect();
            let mut ordered: Vec<(&String, &Json)> = events.iter().collect();
            ordered.sort_by_key(|(id, _)| {
                id.rsplit(':')
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(u64::MAX)
            });
            for (_, event) in ordered {
                let id = event["contract_id"].as_str().unwrap_or_default();
                match event["event_type"].as_str() {
                    Some("created_event") => {
                        let strings = |key: &str| -> Vec<String> {
                            event[key]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|p| p.as_str().map(String::from))
                                .collect()
                        };
                        let template_id = event["template_id"]
                            .as_str()
                            .ok_or("a created event without a template id")?
                            .to_string();
                        let ingested = !only_ingested
                            || template_id
                                .rsplit(':')
                                .next()
                                .is_some_and(|entity| SCAN_ACS_TEMPLATES.contains(&entity));
                        let event_number = if ingested && !archived_here.contains(id) {
                            next_event_number += 1;
                            next_event_number - 1
                        } else {
                            0
                        };
                        contracts.push(ActiveContract {
                            contract_id: id.to_string(),
                            template_id,
                            package_name: event["package_name"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string(),
                            event_number,
                            payload: event["create_arguments"].clone(),
                            created_at_micros: parse_micros(
                                event["created_at"].as_str().ok_or("no created_at")?,
                            )?,
                            signatories: strings("signatories"),
                            observers: strings("observers"),
                            synchronizer_id: update["synchronizer_id"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string(),
                            created_in_update_id: update_id.clone(),
                            created_in_migration_id: migration_id,
                        });
                    }
                    Some("exercised_event") if event["consuming"] == true => {
                        contracts.retain(|c| c.contract_id != id);
                    }
                    _ => {}
                }
            }
        }
        Ok(Self { contracts })
    }

    /// One page of `listContractsPaginated` in descending order: the active contracts of a template with an `event_number` below `after`
    /// (all when `None`), newest first, at most `limit`, and the next page token, which is the `event_number` of the page's last contract
    /// (`DbMultiDomainAcsStore.listContractsPaginated`: `limited.lastOption.map(_.acsRow.eventNumber)`; `None` for an empty page).
    pub fn page_descending(
        &self,
        module_entity: &str,
        after: Option<u64>,
        limit: usize,
    ) -> (Vec<&ActiveContract>, Option<u64>) {
        let mut found: Vec<&ActiveContract> = self
            .of_template(module_entity)
            .into_iter()
            .filter(|c| after.is_none_or(|a| c.event_number < a))
            .collect();
        found.sort_by_key(|c| std::cmp::Reverse(c.event_number));
        found.truncate(limit);
        let token = found.last().map(|c| c.event_number);
        (found, token)
    }

    /// The active contracts of a template (`Module:Entity`, any package version), in creation order.
    pub fn of_template(&self, module_entity: &str) -> Vec<&ActiveContract> {
        self.contracts
            .iter()
            .filter(|c| c.template_id.split_once(':').map(|t| t.1) == Some(module_entity))
            .collect()
    }
}

/// A contract as the scan app prints it: `{template_id, contract_id, payload, created_event_blob, created_at}`.
pub fn contract_json(
    types: &Types<'_>,
    contract: &ActiveContract,
    authentication_data: &[u8],
) -> Result<Json, String> {
    let (package, template) = contract
        .template_id
        .split_once(':')
        .ok_or("a template id without a package")?;
    let ty = types.template(package, template)?;
    let value = types.decode(&ty, &contract.payload)?;
    let arg = types.to_wire(&ty, &value)?;
    let package_name = types.package_name(package)?;
    // the payload is encoded again (not taken from the update): a contract's payload has other numerics than an update's
    let payload = types.encode_contract(&ty, &value)?;
    let blob = created_event_blob(&BlobContract {
        contract_id: &contract.contract_id,
        package_id: package,
        package_name: &package_name,
        template_id: template,
        create_arg: &arg,
        signatories: &contract.signatories,
        observers: &contract.observers,
        created_at_micros: contract.created_at_micros,
        authentication_data,
    })?;
    Ok(json!({
        "template_id": contract.template_id,
        "contract_id": contract.contract_id,
        "payload": payload,
        "created_event_blob": base64(&blob),
        "created_at": format_timestamp_micros(contract.created_at_micros),
    }))
}

/// A contract with the synchronizer it is assigned to (`ContractWithState`).
pub fn contract_with_state(
    types: &Types<'_>,
    contract: &ActiveContract,
    authentication_data: &[u8],
) -> Result<Json, String> {
    Ok(json!({
        "contract": contract_json(types, contract, authentication_data)?,
        "domain_id": contract.synchronizer_id,
    }))
}

/// Renders an [`ActiveContract`] as a Splice `/v2/state/acs` `ActiveContract` JSON object.
pub fn active_contract_event_json(
    types: Option<&Types<'_>>,
    contract: &ActiveContract,
    authentication_data: Option<&[u8]>,
    query_migration_id: i64,
) -> Result<Json, String> {
    let (package, _) = contract
        .template_id
        .split_once(':')
        .unwrap_or(("", &contract.template_id));
    let mut pkg_name = contract.package_name.clone();
    let mut create_arguments = contract.payload.clone();
    let mut blob_b64: Option<String> = None;
    if let (Some(types), Some(auth)) = (types, authentication_data) {
        if let Ok(full) = contract_json(types, contract, auth) {
            create_arguments = full["payload"].clone();
            if let Some(b) = full["created_event_blob"].as_str() {
                blob_b64 = Some(b.to_string());
            }
        }
        if pkg_name.is_empty() {
            if let Ok(name) = types.package_name(package) {
                pkg_name = name;
            }
        }
    } else if pkg_name.is_empty() {
        if let Some(types) = types {
            if let Ok(name) = types.package_name(package) {
                pkg_name = name;
            }
        }
    }
    let mut obj = serde_json::Map::new();
    obj.insert("contract_id".into(), json!(contract.contract_id));
    obj.insert("template_id".into(), json!(contract.template_id));
    obj.insert("package_name".into(), json!(pkg_name));
    obj.insert("create_arguments".into(), create_arguments);
    obj.insert(
        "created_at".into(),
        json!(format_timestamp_micros(contract.created_at_micros)),
    );
    obj.insert("signatories".into(), json!(contract.signatories));
    obj.insert("observers".into(), json!(contract.observers));
    if contract.created_in_migration_id == query_migration_id {
        if let Some(ref update_id) = contract.created_in_update_id {
            obj.insert("created_in_update_id".into(), json!(update_id));
        }
    }
    if let Some(b64) = blob_b64 {
        obj.insert("created_event_blob".into(), json!(b64));
    }
    Ok(Json::Object(obj))
}

/// Standard base64 with padding.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The microseconds since the epoch of `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`.
pub fn parse_micros(text: &str) -> Result<i64, String> {
    let bad = || format!("{text} is no timestamp");
    let body = text.strip_suffix('Z').ok_or_else(bad)?;
    let (date, time) = body.split_once('T').ok_or_else(bad)?;
    let d: Vec<i64> = date.split('-').filter_map(|p| p.parse().ok()).collect();
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let t: Vec<i64> = clock.split(':').filter_map(|p| p.parse().ok()).collect();
    let [y, m, day] = d.as_slice() else {
        return Err(bad());
    };
    let [h, mi, s] = t.as_slice() else {
        return Err(bad());
    };
    // days from civil (Howard Hinnant)
    let y = if *m <= 2 { y - 1 } else { *y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if *m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let micros: i64 = format!("{fraction:0<6}")[..6].parse().map_err(|_| bad())?;
    Ok(((days * 24 + h) * 60 + mi) * 60_000_000 + s * 1_000_000 + micros)
}
