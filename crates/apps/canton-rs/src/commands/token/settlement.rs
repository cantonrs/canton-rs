//! CIP-0112 Token Standard V2 DvP allocations and atomic batch settlement (`S-DX-008`, `T-07`, `T-08`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value as Json};

use super::client::{
    rfc3339_offset, unique_command_id, ActiveContract, DisclosedContract, TokenClient,
};
use super::decimal::DamlDecimal;
use super::v2::{
    find_exercised_result, find_token_rules, first_interface_view, holding_owner, holding_view,
    resolve_admin_rules, to_disclosed, FLT_ALLOC_FAC_V2, FLT_ALLOC_V2, FLT_HOLD_V2,
    FLT_SETTLE_FAC_V2,
};

/// One transfer-leg side inside an allocation (`<leg_id>:<sender|receiver>:<otherside>:<inst>:<amount>`).
#[derive(Clone, Debug)]
pub struct LegSideInput {
    pub transfer_leg_id: String,
    pub is_sender: bool,
    pub otherside: String,
    pub instrument: String,
    pub amount: DamlDecimal,
}

impl LegSideInput {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let Some((leg_id, rest)) = raw.split_once(':') else {
            return Err(format!(
                "invalid --leg '{raw}': expected <leg_id>:<sender|receiver>:<otherside>:<instrument>:<amount>"
            ));
        };
        let Some((side, rest)) = rest.split_once(':') else {
            return Err(format!(
                "invalid --leg '{raw}': expected <leg_id>:<sender|receiver>:<otherside>:<instrument>:<amount>"
            ));
        };
        let Some((rest, amt)) = rest.rsplit_once(':') else {
            return Err(format!(
                "invalid --leg '{raw}': expected <leg_id>:<sender|receiver>:<otherside>:<instrument>:<amount>"
            ));
        };
        let Some((otherside, instrument)) = rest.rsplit_once(':') else {
            return Err(format!(
                "invalid --leg '{raw}': expected <leg_id>:<sender|receiver>:<otherside>:<instrument>:<amount>"
            ));
        };
        let leg_id = leg_id.trim();
        let side = side.trim();
        let otherside = otherside.trim();
        let instrument = instrument.trim();
        let amt = amt.trim();
        if leg_id.is_empty() || otherside.is_empty() || instrument.is_empty() {
            return Err(format!("empty field in --leg '{raw}'"));
        }
        let is_sender = match side.to_ascii_lowercase().as_str() {
            "sender" | "senderside" => true,
            "receiver" | "receiverside" => false,
            other => {
                return Err(format!(
                    "invalid side '{other}' in --leg '{raw}': expected sender or receiver"
                ))
            }
        };
        let amount = DamlDecimal::parse(amt)?;
        if !amount.is_positive() {
            return Err(format!("leg amount must be > 0 in --leg '{raw}'"));
        }
        Ok(Self {
            transfer_leg_id: leg_id.to_string(),
            is_sender,
            otherside: otherside.to_string(),
            instrument: instrument.to_string(),
            amount,
        })
    }
}

/// Full transfer leg passed to `token settle` (`<leg_id>:<sender>:<receiver>:<instrument>:<amount>`).
#[derive(Clone, Debug)]
pub struct SettleLegInput {
    pub transfer_leg_id: String,
    pub sender: String,
    pub receiver: String,
    pub instrument: String,
    pub amount: DamlDecimal,
}

impl SettleLegInput {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let Some((leg_id, rest)) = raw.split_once(':') else {
            return Err(format!(
                "invalid settle --leg '{raw}': expected <leg_id>:<sender>:<receiver>:<instrument>:<amount>"
            ));
        };
        let Some((rest, amt)) = rest.rsplit_once(':') else {
            return Err(format!(
                "invalid settle --leg '{raw}': expected <leg_id>:<sender>:<receiver>:<instrument>:<amount>"
            ));
        };
        let Some((parties_mid, instrument)) = rest.rsplit_once(':') else {
            return Err(format!(
                "invalid settle --leg '{raw}': expected <leg_id>:<sender>:<receiver>:<instrument>:<amount>"
            ));
        };
        // Split `<sender>:<receiver>` on the unique single `:` that is not part of a Canton `Hint::1220...` party ID.
        let (sender, receiver) = split_two_parties(parties_mid).ok_or_else(|| {
            format!(
                "invalid settle --leg '{raw}': expected <leg_id>:<sender>:<receiver>:<instrument>:<amount>"
            )
        })?;
        let leg_id = leg_id.trim();
        let sender = sender.trim();
        let receiver = receiver.trim();
        let instrument = instrument.trim();
        let amt = amt.trim();
        if leg_id.is_empty() || sender.is_empty() || receiver.is_empty() || instrument.is_empty() {
            return Err(format!("empty field in settle --leg '{raw}'"));
        }
        let amount = DamlDecimal::parse(amt)?;
        if !amount.is_positive() {
            return Err(format!("leg amount must be > 0 in settle --leg '{raw}'"));
        }
        Ok(Self {
            transfer_leg_id: leg_id.to_string(),
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            instrument: instrument.to_string(),
            amount,
        })
    }
}

fn split_two_parties(mid: &str) -> Option<(&str, &str)> {
    let bytes = mid.as_bytes();
    let mut found: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b':' {
            let prev_colon = i > 0 && bytes[i - 1] == b':';
            let next_colon = i + 1 < bytes.len() && bytes[i + 1] == b':';
            if !prev_colon && !next_colon {
                if found.is_some() {
                    return None;
                }
                found = Some(i);
            }
        }
    }
    found.map(|idx| (&mid[..idx], &mid[idx + 1..]))
}

/// Parameters for `token allocation create`.
#[derive(Clone, Debug)]
pub struct AllocationCreateSpec<'a> {
    pub settlement_id: &'a str,
    pub executor: &'a str,
    pub authorizer: &'a str,
    pub admin_opt: Option<&'a str>,
    pub raw_legs: &'a [String],
    pub deadline_secs: u64,
    pub dar_override: Option<&'a Path>,
}

/// Executes `token allocation create`.
pub fn cmd_allocation_create(
    client: &TokenClient,
    spec: &AllocationCreateSpec<'_>,
) -> Result<Json, String> {
    if spec.raw_legs.is_empty() {
        return Err("allocation create requires at least one --leg".to_string());
    }
    let executor = client.resolve_party(spec.executor)?;
    let authorizer = client.resolve_party(spec.authorizer)?;
    let (admin, rules, rules_disc, ctx) = resolve_admin_rules(client, spec.admin_opt)?;

    let mut legs = Vec::with_capacity(spec.raw_legs.len());
    let mut needed_by_inst: BTreeMap<String, DamlDecimal> = BTreeMap::new();
    for raw in spec.raw_legs {
        let mut parsed = LegSideInput::parse(raw)?;
        parsed.otherside = client.resolve_party(&parsed.otherside)?;
        if parsed.is_sender {
            let cur = needed_by_inst
                .entry(parsed.instrument.clone())
                .or_insert(DamlDecimal::ZERO);
            *cur = cur.checked_add(parsed.amount)?;
        }
        legs.push(parsed);
    }

    let mut selected_cids: Vec<String> = Vec::new();
    if !needed_by_inst.is_empty() {
        let holdings = client.active_interface_contracts(
            std::slice::from_ref(&authorizer),
            FLT_HOLD_V2,
            false,
        )?;
        let mut by_inst: BTreeMap<String, Vec<(String, DamlDecimal)>> = BTreeMap::new();
        for c in holdings {
            let Some(view) = holding_view(&c) else {
                continue;
            };
            if holding_owner(view) != Some(authorizer.as_str()) {
                continue;
            }
            if !view["lock"].is_null() {
                continue;
            }
            if view["instrumentId"]["admin"].as_str() != Some(admin.as_str()) {
                continue;
            }
            let inst_id = view["instrumentId"]["id"].as_str().unwrap_or_default();
            let amt = DamlDecimal::parse(view["amount"].as_str().unwrap_or("0"))?;
            by_inst
                .entry(inst_id.to_string())
                .or_default()
                .push((c.contract_id, amt));
        }

        for (inst, req_amt) in needed_by_inst {
            let mut candidates = by_inst.remove(&inst).unwrap_or_default();
            candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let mut acc = DamlDecimal::ZERO;
            for (cid, amt) in &candidates {
                selected_cids.push(cid.clone());
                acc = acc.checked_add(*amt)?;
                if acc >= req_amt {
                    break;
                }
            }
            if acc < req_amt {
                return Err(format!(
                    "insufficient unlocked '{inst}' balance for authorizer '{authorizer}': available {acc}, required {req_amt}"
                ));
            }
        }
    }

    let _ = spec.dar_override;

    let leg_json: Vec<Json> = legs
        .iter()
        .map(|l| {
            json!({
                "transferLegId": l.transfer_leg_id,
                "side": if l.is_sender { "SenderSide" } else { "ReceiverSide" },
                "otherside": { "owner": l.otherside, "provider": null, "id": "" },
                "amount": l.amount.to_fixed10(),
                "instrumentId": l.instrument,
                "meta": { "values": {} }
            })
        })
        .collect();

    let tx = client.submit_tx(
        &unique_command_id("alloc"),
        std::slice::from_ref(&authorizer),
        &[],
        vec![json!({
            "ExerciseCommand": {
                "templateId": FLT_ALLOC_FAC_V2,
                "contractId": rules.contract_id,
                "choice": "AllocationFactory_Allocate",
                "choiceArgument": {
                    "settlement": {
                        "executors": [executor],
                        "id": spec.settlement_id,
                        "cid": null,
                        "meta": { "values": {} }
                    },
                    "allocation": {
                        "admin": admin,
                        "authorizer": { "owner": authorizer, "provider": null, "id": "" },
                        "transferLegSides": leg_json,
                        "settlementDeadline": rfc3339_offset(i64::try_from(spec.deadline_secs).unwrap_or(3600)),
                        "nextIterationFunding": null,
                        "committed": false,
                        "meta": { "values": {} }
                    },
                    "requestedAt": rfc3339_offset(-30),
                    "inputHoldingCids": selected_cids,
                    "extraArgs": ctx,
                    "actors": [authorizer]
                }
            }
        })],
        &[rules_disc],
    )?;

    let alloc_cid = find_exercised_result(&tx, "AllocationFactory_Allocate")
        .and_then(|v| v["output"]["value"]["allocationCid"].as_str())
        .map(String::from)
        .ok_or_else(|| {
            format!("missing allocationCid in AllocationFactory_Allocate result: {tx}")
        })?;

    Ok(json!({
        "action": "allocation create",
        "settlement_id": spec.settlement_id,
        "authorizer": authorizer,
        "executor": executor,
        "admin": admin,
        "allocation_cid": alloc_cid,
        "update_id": tx["updateId"],
        "offset": tx["offset"],
    }))
}

/// Executes `token allocation list [--party <p>]`.
pub fn cmd_allocation_list(client: &TokenClient, party_opt: Option<&str>) -> Result<Json, String> {
    let parties = match party_opt {
        Some(p) => vec![client.resolve_party(p)?],
        None => client.readable_parties()?,
    };
    let rows = client.active_interface_contracts(&parties, FLT_ALLOC_V2, false)?;
    let mut items = Vec::new();
    for c in rows {
        let Some(view) = first_interface_view(&c) else {
            continue;
        };
        items.push(json!({
            "allocation_cid": c.contract_id,
            "settlement_id": view["settlement"]["id"],
            "executors": view["settlement"]["executors"],
            "admin": view["allocation"]["admin"],
            "authorizer": view["allocation"]["authorizer"]["owner"],
            "holding_cids": view["holdingCids"],
            "transfer_leg_sides": view["allocation"]["transferLegSides"],
        }));
    }
    items.sort_by(|a, b| {
        a["settlement_id"]
            .as_str()
            .cmp(&b["settlement_id"].as_str())
            .then_with(|| {
                a["allocation_cid"]
                    .as_str()
                    .cmp(&b["allocation_cid"].as_str())
            })
    });
    Ok(json!({
        "action": "allocation list",
        "allocations": items,
    }))
}

/// Executes `token allocation withdraw|cancel <allocation>`.
pub fn cmd_allocation_abort(
    client: &TokenClient,
    action: &str,
    allocation_cid: &str,
    actor_opt: Option<&str>,
    dar_override: Option<&Path>,
) -> Result<Json, String> {
    let choice = match action {
        "withdraw" => "Allocation_Withdraw",
        "cancel" => "Allocation_Cancel",
        other => return Err(format!("unknown allocation abort action '{other}'")),
    };
    let readable = client.readable_parties()?;
    let mut readers = Vec::new();
    if let Some(a) = actor_opt {
        readers.push(client.resolve_party(a)?);
    }
    for p in &readable {
        if !readers.contains(p) {
            readers.push(p.clone());
        }
    }
    let rows = client.active_interface_contracts(&readers, FLT_ALLOC_V2, true)?;
    let alloc = rows
        .into_iter()
        .find(|c| c.contract_id == allocation_cid)
        .ok_or_else(|| format!("active Allocation '{allocation_cid}' not found"))?;
    let view = first_interface_view(&alloc)
        .ok_or_else(|| format!("Allocation '{allocation_cid}' missing interfaceView"))?;

    let admin = view["allocation"]["admin"]
        .as_str()
        .ok_or_else(|| "Allocation missing allocation.admin".to_string())?
        .to_string();
    let authorizer = view["allocation"]["authorizer"]["owner"]
        .as_str()
        .ok_or_else(|| "Allocation missing allocation.authorizer.owner".to_string())?
        .to_string();
    let default_executor = view["settlement"]["executors"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(Json::as_str)
        .map(String::from)
        .unwrap_or_else(|| admin.clone());
    let actor = match actor_opt {
        Some(a) => client.resolve_party(a)?,
        None if action == "cancel" => default_executor,
        None => authorizer.clone(),
    };

    let holding_cids: Vec<String> = view["holdingCids"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let (_, rules_disc, ctx) = find_token_rules(client, &admin)?;
    let mut disclosed = vec![rules_disc];
    if !holding_cids.is_empty() {
        let mut h_readers = vec![actor.clone()];
        if client.has_explicit_token() {
            for p in [authorizer, admin] {
                if readable.iter().any(|rp| rp == &p) && !h_readers.contains(&p) {
                    h_readers.push(p);
                }
            }
        } else {
            if !h_readers.contains(&authorizer) {
                h_readers.push(authorizer);
            }
            if readable.iter().any(|p| p == &admin) && !h_readers.contains(&admin) {
                h_readers.push(admin);
            }
        }
        let holdings = client.active_interface_contracts(&h_readers, FLT_HOLD_V2, true)?;
        for h_cid in &holding_cids {
            if let Some(h) = holdings.iter().find(|c| &c.contract_id == h_cid) {
                disclosed.push(to_disclosed(h));
            }
        }
    }
    if !alloc.created_event_blob.is_empty() {
        disclosed.push(to_disclosed(&alloc));
    }

    let _ = dar_override;

    let tx = client.submit_tx(
        &unique_command_id(action),
        std::slice::from_ref(&actor),
        &[],
        vec![json!({
            "ExerciseCommand": {
                "templateId": FLT_ALLOC_V2,
                "contractId": allocation_cid,
                "choice": choice,
                "choiceArgument": {
                    "actors": [actor],
                    "extraArgs": ctx
                }
            }
        })],
        &disclosed,
    )?;

    Ok(json!({
        "action": format!("allocation {action}"),
        "choice": choice,
        "actor": actor,
        "allocation_cid": allocation_cid,
        "update_id": tx["updateId"],
        "offset": tx["offset"],
    }))
}

/// Executes `token settle <batch>`.
pub fn cmd_settle(
    client: &TokenClient,
    batch_id: &str,
    executor_opt: Option<&str>,
    alloc_cids_arg: &[String],
    raw_legs: &[String],
    admin_opt: Option<&str>,
    dar_override: Option<&Path>,
) -> Result<Json, String> {
    let mut readers = Vec::new();
    if let Some(ex) = executor_opt {
        readers.push(client.resolve_party(ex)?);
    }
    for p in client.readable_parties()? {
        if !readers.contains(&p) {
            readers.push(p);
        }
    }
    let all_allocs = client.active_interface_contracts(&readers, FLT_ALLOC_V2, true)?;
    let mut by_cid: BTreeMap<String, ActiveContract> = BTreeMap::new();
    for a in all_allocs {
        by_cid.insert(a.contract_id.clone(), a);
    }

    let target_alloc_cids: Vec<String> = if alloc_cids_arg.is_empty() {
        by_cid
            .values()
            .filter(|a| {
                first_interface_view(a).and_then(|v| v["settlement"]["id"].as_str())
                    == Some(batch_id)
            })
            .map(|a| a.contract_id.clone())
            .collect()
    } else {
        alloc_cids_arg.to_vec()
    };

    if target_alloc_cids.is_empty() {
        return Err(format!(
            "no active allocations found for batch '{batch_id}'"
        ));
    }

    let mut active_selected: Vec<&ActiveContract> = Vec::new();
    let mut missing_cids: Vec<String> = Vec::new();
    for cid in &target_alloc_cids {
        match by_cid.get(cid) {
            Some(c) => active_selected.push(c),
            None => missing_cids.push(cid.clone()),
        }
    }

    // Resolve admin/executor from active allocations or explicit flags.
    let first_view = active_selected
        .first()
        .and_then(|a| first_interface_view(a));
    let resolved_admin = match admin_opt {
        Some(a) => client.resolve_party(a)?,
        None => first_view
            .and_then(|v| v["allocation"]["admin"].as_str())
            .map(String::from)
            .ok_or_else(|| "cannot resolve admin (pass --admin)".to_string())?,
    };
    let executor = match executor_opt {
        Some(ex) => client.resolve_party(ex)?,
        None => first_view
            .and_then(|v| v["settlement"]["executors"].as_array())
            .and_then(|arr| arr.first())
            .and_then(Json::as_str)
            .map(String::from)
            .unwrap_or_else(|| resolved_admin.clone()),
    };

    // Derive `transferLegs` from `--leg` flags or automatically from active AllocationViews.
    let transfer_legs: Vec<Json> = if !raw_legs.is_empty() {
        let mut out = Vec::with_capacity(raw_legs.len());
        for raw in raw_legs {
            let leg = SettleLegInput::parse(raw)?;
            let sender = client.resolve_party(&leg.sender)?;
            let receiver = client.resolve_party(&leg.receiver)?;
            out.push(json!({
                "transferLegId": leg.transfer_leg_id,
                "sender": { "owner": sender, "provider": null, "id": "" },
                "receiver": { "owner": receiver, "provider": null, "id": "" },
                "amount": leg.amount.to_fixed10(),
                "instrumentId": leg.instrument,
                "meta": { "values": {} }
            }));
        }
        out
    } else {
        derive_legs_from_allocations(&active_selected)?
    };

    let (_, rules_disc, ctx) = find_token_rules(client, &resolved_admin)?;
    let mut disclosed: Vec<DisclosedContract> = vec![rules_disc];
    let mut seen_disclosed: BTreeSet<String> =
        disclosed.iter().map(|d| d.contract_id.clone()).collect();
    let mut holding_ids: BTreeSet<String> = BTreeSet::new();
    let mut alloc_stakeholders: Vec<String> = vec![executor.clone(), resolved_admin];

    for a in &active_selected {
        if seen_disclosed.insert(a.contract_id.clone()) && !a.created_event_blob.is_empty() {
            disclosed.push(to_disclosed(a));
        }
        if let Some(view) = first_interface_view(a) {
            if let Some(auth) = view["allocation"]["authorizer"]["owner"].as_str() {
                if !alloc_stakeholders.iter().any(|p| p == auth) {
                    alloc_stakeholders.push(auth.to_string());
                }
            }
            if let Some(hids) = view["holdingCids"].as_array() {
                for h in hids {
                    if let Some(s) = h.as_str() {
                        holding_ids.insert(s.to_string());
                    }
                }
            }
        }
    }
    if !holding_ids.is_empty() {
        let mut holding_readers = Vec::new();
        if client.has_explicit_token() {
            let readable = client.readable_parties()?;
            for p in &alloc_stakeholders {
                if readable.contains(p) && !holding_readers.contains(p) {
                    holding_readers.push(p.clone());
                }
            }
            if holding_readers.is_empty() {
                holding_readers.push(executor.clone());
            }
        } else {
            holding_readers = alloc_stakeholders;
        }
        let holdings = client.active_interface_contracts(&holding_readers, FLT_HOLD_V2, true)?;
        for h in holdings {
            if holding_ids.contains(&h.contract_id) && seen_disclosed.insert(h.contract_id.clone())
            {
                disclosed.push(to_disclosed(&h));
            }
        }
    }

    let _ = dar_override;
    let (_, _, rules_cid_str) = (
        &missing_cids,
        &transfer_legs,
        disclosed[0].contract_id.as_str(),
    );

    let alloc_entries: Vec<Json> = target_alloc_cids
        .iter()
        .map(|cid| {
            json!({
                "allocationCid": cid,
                "extraTransferLegSides": [],
                "nextIterationFunding": null
            })
        })
        .collect();

    let tx = client.submit_tx(
        &unique_command_id("settle"),
        std::slice::from_ref(&executor),
        &[],
        vec![json!({
            "ExerciseCommand": {
                "templateId": FLT_SETTLE_FAC_V2,
                "contractId": rules_cid_str,
                "choice": "SettlementFactory_SettleBatch",
                "choiceArgument": {
                    "settlement": {
                        "executors": [executor],
                        "id": batch_id,
                        "cid": null,
                        "meta": { "values": {} }
                    },
                    "transferLegs": transfer_legs,
                    "allocations": alloc_entries,
                    "actors": [executor],
                    "extraArgs": ctx
                }
            }
        })],
        &disclosed,
    )?;

    Ok(json!({
        "action": "settle",
        "batch": batch_id,
        "executor": executor,
        "allocations": target_alloc_cids,
        "update_id": tx["updateId"],
        "offset": tx["offset"],
    }))
}

fn derive_legs_from_allocations(allocs: &[&ActiveContract]) -> Result<Vec<Json>, String> {
    let mut map: BTreeMap<String, Json> = BTreeMap::new();
    for a in allocs {
        let Some(view) = first_interface_view(a) else {
            continue;
        };
        let Some(auth_owner) = view["allocation"]["authorizer"]["owner"].as_str() else {
            continue;
        };
        let Some(sides) = view["allocation"]["transferLegSides"].as_array() else {
            continue;
        };
        for s in sides {
            let Some(leg_id) = s["transferLegId"].as_str() else {
                continue;
            };
            let Some(otherside) = s["otherside"]["owner"].as_str() else {
                continue;
            };
            let Some(inst) = s["instrumentId"].as_str() else {
                continue;
            };
            let Some(amt_str) = s["amount"].as_str() else {
                continue;
            };
            let side_str = s["side"].as_str().unwrap_or_default();
            let (sender, receiver) = if side_str == "SenderSide" {
                (auth_owner, otherside)
            } else {
                (otherside, auth_owner)
            };
            let candidate = json!({
                "transferLegId": leg_id,
                "sender": { "owner": sender, "provider": null, "id": "" },
                "receiver": { "owner": receiver, "provider": null, "id": "" },
                "amount": DamlDecimal::parse(amt_str)?.to_fixed10(),
                "instrumentId": inst,
                "meta": { "values": {} }
            });
            map.entry(leg_id.to_string()).or_insert(candidate);
        }
    }
    if map.is_empty() {
        return Err("could not derive any transferLegs from allocations (pass --leg)".to_string());
    }
    Ok(map.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::{LegSideInput, SettleLegInput};

    #[test]
    fn parse_leg_inputs_preserve_canton_party_colons() {
        let side = LegSideInput::parse("leg1:sender:Bob::1220deadbeef:USDX:10.0")
            .expect("leg side with party id");
        assert_eq!(side.transfer_leg_id, "leg1");
        assert!(side.is_sender);
        assert_eq!(side.otherside, "Bob::1220deadbeef");
        assert_eq!(side.instrument, "USDX");
        assert_eq!(side.amount.to_string(), "10.0");

        let settle = SettleLegInput::parse("leg2:Bob::1220abcd:Alice::1220ef01:USDY:5.5")
            .expect("settle leg with party ids");
        assert_eq!(settle.transfer_leg_id, "leg2");
        assert_eq!(settle.sender, "Bob::1220abcd");
        assert_eq!(settle.receiver, "Alice::1220ef01");
        assert_eq!(settle.instrument, "USDY");
        assert_eq!(settle.amount.to_string(), "5.5");
    }
}
