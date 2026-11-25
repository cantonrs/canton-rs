//! CIP-0112 Token Standard V2 operations for `canton-rs token` (`S-DX-008`).
//!
//! Covers DAR upload & vetting (`create`), minting (`mint`), one/two-step transfers
//! (`transfer`, `transfer accept|reject|withdraw`), exact 10-decimal holdings aggregation
//! (`balance`, `balances`), and `EventLog` activity queries (`activity`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value as Json};

use super::amulet::{amulet_instruction_context, amulet_transfer_factory_context};
use super::client::{
    package_map_from_dar, rfc3339_offset, unique_command_id, ActiveContract, DisclosedContract,
    TokenClient,
};
use super::decimal::{BalanceBucket, DamlDecimal};

pub const FLT_TOKEN_RULES: &str =
    "#splice-test-token-v2:Splice.Testing.Tokens.TestTokenV2:TokenRules";
pub const FLT_HOLD_V2: &str = "#splice-api-token-holding-v2:Splice.Api.Token.HoldingV2:Holding";
pub const FLT_XFER_FAC_V2: &str =
    "#splice-api-token-transfer-instruction-v2:Splice.Api.Token.TransferInstructionV2:TransferFactory";
pub const FLT_XFER_INST_V2: &str =
    "#splice-api-token-transfer-instruction-v2:Splice.Api.Token.TransferInstructionV2:TransferInstruction";
pub const FLT_ALLOC_FAC_V2: &str =
    "#splice-api-token-allocation-instruction-v2:Splice.Api.Token.AllocationInstructionV2:AllocationFactory";
pub const FLT_ALLOC_V2: &str =
    "#splice-api-token-allocation-v2:Splice.Api.Token.AllocationV2:Allocation";
pub const FLT_SETTLE_FAC_V2: &str =
    "#splice-api-token-allocation-v2:Splice.Api.Token.AllocationV2:SettlementFactory";
pub const FLT_EVENT_LOG_V2: &str =
    "#splice-api-token-transfer-events-v2:Splice.Api.Token.TransferEventsV2:EventLog";

const DEFAULT_TEST_TOKEN_DAR_REL: &str =
    "references/splice/daml/dars/splice-test-token-v2-1.0.2.dar";

/// Finds `references/splice/daml/dars/splice-test-token-v2-1.0.2.dar` walking up from current directory.
pub fn default_test_token_dar_path() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    for _ in 0..8 {
        let candidate = dir.join(DEFAULT_TEST_TOKEN_DAR_REL);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Resolves the active `TokenRules` contract and builds TestTokenV2 `ExtraArgs`.
pub fn find_token_rules(
    client: &TokenClient,
    admin: &str,
) -> Result<(ActiveContract, DisclosedContract, Json), String> {
    let rows = client.active_template_contracts(&[admin.to_string()], FLT_TOKEN_RULES, true)?;
    let rules = rows
        .into_iter()
        .find(|c| c.create_argument["admin"].as_str() == Some(admin))
        .ok_or_else(|| {
            format!("active TokenRules not found for admin '{admin}' (run `token create` first)")
        })?;
    let disc = to_disclosed(&rules);
    let ctx = test_token_extra_args(&rules.contract_id);
    Ok((rules, disc, ctx))
}

/// Builds TestTokenV2 `ExtraArgs` pointing at `rules_cid`.
pub fn test_token_extra_args(rules_cid: &str) -> Json {
    json!({
        "context": {
            "values": {
                "testTokenV2/tokenRules": { "tag": "AV_ContractId", "value": rules_cid },
                "testTokenV2/accountConfigs": { "tag": "AV_List", "value": [] }
            }
        },
        "meta": { "values": {} }
    })
}

/// Builds `ExtraArgs` from a map of `ChoiceContext` key-values.
pub fn extra_args_from_map(values: BTreeMap<String, Json>) -> Json {
    let mut obj = serde_json::Map::new();
    for (k, v) in values {
        obj.insert(k, v);
    }
    json!({
        "context": { "values": obj },
        "meta": { "values": {} }
    })
}

/// Executes `token create --instrument <I> --admin <party> [--dar <path>]`.
pub fn cmd_create(
    client: &TokenClient,
    instrument: &str,
    admin_raw: &str,
    dar_override: Option<&Path>,
) -> Result<Json, String> {
    if instrument.trim().is_empty() {
        return Err("--instrument cannot be empty".to_string());
    }
    let dar_path = match dar_override {
        Some(p) => p.to_path_buf(),
        None => default_test_token_dar_path()
            .ok_or_else(|| "cannot locate default V2 DAR (pass --dar <path>)".to_string())?,
    };
    client.upload_dar(&dar_path)?;
    let pkg_map = package_map_from_dar(&dar_path)?;
    let test_token_pkg = pkg_map
        .get("splice-test-token-v2")
        .cloned()
        .ok_or_else(|| format!("DAR '{}' lacks splice-test-token-v2", dar_path.display()))?;
    let check_ids: Vec<String> = pkg_map.values().cloned().collect();
    let vetted = client.list_vetted_packages(&check_ids).unwrap_or_default();
    let loaded = client.list_packages()?;
    if !loaded.iter().any(|p| p == &test_token_pkg) {
        return Err(format!(
            "uploaded package '{test_token_pkg}' missing from /v2/packages"
        ));
    }

    let admin = client.resolve_party(admin_raw)?;
    let existing =
        client.active_template_contracts(std::slice::from_ref(&admin), FLT_TOKEN_RULES, false)?;
    if let Some(rules) = existing
        .into_iter()
        .find(|c| c.create_argument["admin"].as_str() == Some(admin.as_str()))
    {
        return Ok(json!({
            "action": "create",
            "instrument": instrument,
            "admin": admin,
            "rules_cid": rules.contract_id,
            "reused_rules": true,
            "package_id": test_token_pkg,
            "vetted_count": vetted.len(),
        }));
    }

    let tmpl = format!("{test_token_pkg}:Splice.Testing.Tokens.TestTokenV2:TokenRules");
    let tx = client.submit_tx(
        &unique_command_id("create"),
        std::slice::from_ref(&admin),
        &[],
        vec![json!({
            "CreateCommand": {
                "templateId": tmpl,
                "createArguments": { "admin": admin }
            }
        })],
        &[],
    )?;
    let rules_cid = first_created_cid(&tx)
        .ok_or_else(|| format!("TokenRules creation returned no CreatedEvent: {tx}"))?;

    Ok(json!({
        "action": "create",
        "instrument": instrument,
        "admin": admin,
        "rules_cid": rules_cid,
        "reused_rules": false,
        "package_id": test_token_pkg,
        "vetted_count": vetted.len(),
        "update_id": tx["updateId"],
        "offset": tx["offset"],
    }))
}

/// Executes `token mint <instrument> <party> <amount>`.
pub fn cmd_mint(
    client: &TokenClient,
    instrument: &str,
    party_raw: &str,
    amount_raw: &str,
    admin_opt: Option<&str>,
    _dar_override: Option<&Path>,
) -> Result<Json, String> {
    let amount = DamlDecimal::parse(amount_raw)?;
    if !amount.is_positive() {
        return Err(format!("mint amount must be > 0, got '{amount_raw}'"));
    }
    let receiver = client.resolve_party(party_raw)?;
    let (admin, rules, rules_disc, ctx) = resolve_admin_rules(client, admin_opt)?;
    let rules_tmpl = if rules.template_id.is_empty() {
        FLT_TOKEN_RULES
    } else {
        rules.template_id.as_str()
    };

    let tx_offer = client.submit_tx(
        &unique_command_id("offer-mint"),
        std::slice::from_ref(&admin),
        &[],
        vec![json!({
            "ExerciseCommand": {
                "templateId": rules_tmpl,
                "contractId": rules.contract_id,
                "choice": "TokenRules_OfferMint",
                "choiceArgument": {
                    "receiver": { "owner": receiver, "provider": null, "id": "" },
                    "amount": amount.to_fixed10(),
                    "instrumentId": { "admin": admin, "id": instrument },
                    "offeredAt": rfc3339_offset(-30),
                    "receiverConfig": {
                        "admin": admin,
                        "account": { "owner": receiver, "provider": null, "id": "" },
                        "ownerConfig": { "canInitiate": true, "mustApprove": true },
                        "providerConfig": { "canInitiate": false, "mustApprove": false }
                    }
                }
            }
        })],
        &[],
    )?;
    let offer_cid = find_exercised_result(&tx_offer, "TokenRules_OfferMint")
        .and_then(|v| v["offerCid"].as_str())
        .map(String::from)
        .ok_or_else(|| format!("missing offerCid in TokenRules_OfferMint result: {tx_offer}"))?;

    let tx_acc = client.submit_tx(
        &unique_command_id("mint-accept"),
        std::slice::from_ref(&receiver),
        &[],
        vec![json!({
            "ExerciseCommand": {
                "templateId": FLT_XFER_INST_V2,
                "contractId": offer_cid,
                "choice": "TransferInstruction_Accept",
                "choiceArgument": {
                    "actors": [receiver],
                    "extraArgs": ctx
                }
            }
        })],
        &[rules_disc],
    )?;

    Ok(json!({
        "action": "mint",
        "instrument": instrument,
        "admin": admin,
        "party": receiver,
        "amount": amount.to_string(),
        "offer_cid": offer_cid,
        "holding_cid": first_created_cid(&tx_acc),
        "update_id": tx_acc["updateId"],
        "offset": tx_acc["offset"],
    }))
}

/// Parameters for `token transfer <instrument> <from> <to> <amount>`.
#[derive(Clone, Debug)]
pub struct TransferSpec<'a> {
    pub instrument: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub amount: &'a str,
    pub auto_accept: bool,
    pub admin_opt: Option<&'a str>,
    pub expires_secs: u64,
    pub dar_override: Option<&'a Path>,
}

/// Executes `token transfer <instrument> <from> <to> <amount> [--auto-accept]`.
pub fn cmd_transfer(client: &TokenClient, spec: &TransferSpec<'_>) -> Result<Json, String> {
    let _ = spec.dar_override;
    let instrument = spec.instrument;
    let amount = DamlDecimal::parse(spec.amount)?;
    if !amount.is_positive() {
        return Err(format!(
            "transfer amount must be > 0, got '{}'",
            spec.amount
        ));
    }
    let sender = client.resolve_party(spec.from)?;
    let receiver = client.resolve_party(spec.to)?;

    let holdings =
        client.active_interface_contracts(std::slice::from_ref(&sender), FLT_HOLD_V2, false)?;
    let mut matching: Vec<(String, String, DamlDecimal)> = Vec::new();
    for c in holdings {
        let Some(view) = holding_view(&c) else {
            continue;
        };
        if view["instrumentId"]["id"].as_str() != Some(instrument) {
            continue;
        }
        if !view["lock"].is_null() {
            continue;
        }
        let Some(h_admin) = view["instrumentId"]["admin"].as_str() else {
            continue;
        };
        if let Some(wanted_admin) = spec.admin_opt {
            let resolved_admin = client.resolve_party(wanted_admin)?;
            if h_admin != resolved_admin {
                continue;
            }
        }
        let amt_str = view["amount"].as_str().unwrap_or("0");
        let parsed = DamlDecimal::parse(amt_str)?;
        let admin_owned = h_admin.to_string();
        matching.push((c.contract_id, admin_owned, parsed));
    }

    let admin = if let Some(a) = spec.admin_opt {
        client.resolve_party(a)?
    } else if let Some((_, a, _)) = matching.first() {
        a.clone()
    } else if instrument != "Amulet" {
        let (a, _, _, _) = resolve_admin_rules(client, None)?;
        a
    } else {
        return Err(format!(
            "no '{instrument}' holdings found for '{sender}' (pass --admin)"
        ));
    };

    let mut candidate_inputs: Vec<(String, DamlDecimal)> = matching
        .into_iter()
        .filter(|(_, a, _)| a == &admin)
        .map(|(cid, _, amt)| (cid, amt))
        .collect();
    // Deterministic descending amount, ascending cid selection.
    candidate_inputs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    if candidate_inputs.is_empty() {
        return Err(format!(
            "insufficient unlocked balance for {sender} ({instrument}): available 0.0, requested {amount}"
        ));
    }

    let mut total_avail = DamlDecimal::ZERO;
    for (_, amt) in &candidate_inputs {
        total_avail = total_avail.checked_add(*amt)?;
    }

    let selected_cids: Vec<String> = if total_avail < amount {
        // Pass all unlocked holdings so Daml ledger rejects insufficient input balances too (`T-06`/`T-A5`).
        candidate_inputs.into_iter().map(|(cid, _)| cid).collect()
    } else {
        let mut acc = DamlDecimal::ZERO;
        let mut chosen = Vec::new();
        for (cid, amt) in candidate_inputs {
            chosen.push(cid);
            acc = acc.checked_add(amt)?;
            if acc >= amount {
                break;
            }
        }
        chosen
    };

    let (factory_cid, ctx, disclosed, is_amulet) = if instrument == "Amulet" {
        let am_ctx = amulet_transfer_factory_context(
            client,
            &sender,
            &receiver,
            &admin,
            &selected_cids,
            amount,
        )?;
        let factory = am_ctx.external_rules_cid.ok_or_else(|| {
            "ExternalPartyAmuletRules contract ID missing for Amulet transfer".to_string()
        })?;
        (
            factory,
            extra_args_from_map(am_ctx.context_values),
            am_ctx.disclosed,
            true,
        )
    } else {
        let (_, disc, extra) = find_token_rules(client, &admin)?;
        (disc.contract_id.clone(), extra, vec![disc], false)
    };

    let tx = client.submit_tx(
        &unique_command_id("transfer"),
        std::slice::from_ref(&sender),
        &[],
        vec![json!({
            "ExerciseCommand": {
                "templateId": FLT_XFER_FAC_V2,
                "contractId": factory_cid,
                "choice": "TransferFactory_Transfer",
                "choiceArgument": {
                    "transfer": {
                        "sender": { "owner": sender, "provider": null, "id": "" },
                        "receiver": { "owner": receiver, "provider": null, "id": "" },
                        "amount": amount.to_fixed10(),
                        "instrumentId": { "admin": admin, "id": instrument },
                        "requestedAt": rfc3339_offset(-30),
                        "executeBefore": rfc3339_offset(i64::try_from(spec.expires_secs).unwrap_or(3600)),
                        "inputHoldingCids": selected_cids,
                        "meta": { "values": {} }
                    },
                    "actors": [sender],
                    "extraArgs": ctx
                }
            }
        })],
        &disclosed,
    )?;

    let res_obj = find_exercised_result(&tx, "TransferFactory_Transfer").cloned();
    let tag = res_obj
        .as_ref()
        .and_then(|v| v["output"]["tag"].as_str())
        .unwrap_or("unknown");
    let instr_cid = res_obj
        .as_ref()
        .and_then(|v| v["output"]["value"]["transferInstructionCid"].as_str())
        .map(String::from);

    if spec.auto_accept {
        if let Some(ref pending_cid) = instr_cid {
            let acc = cmd_transfer_action(
                client,
                "accept",
                pending_cid,
                Some(&receiver),
                Some(&admin),
                spec.dar_override,
            )?;
            return Ok(json!({
                "action": "transfer",
                "status": "accepted",
                "instrument": instrument,
                "is_amulet": is_amulet,
                "from": sender,
                "to": receiver,
                "amount": amount.to_string(),
                "instruction_cid": pending_cid,
                "accept_update_id": acc["update_id"],
                "offset": acc["offset"],
            }));
        }
    }

    Ok(json!({
        "action": "transfer",
        "status": tag,
        "instrument": instrument,
        "is_amulet": is_amulet,
        "from": sender,
        "to": receiver,
        "amount": amount.to_string(),
        "instruction_cid": instr_cid,
        "update_id": tx["updateId"],
        "offset": tx["offset"],
    }))
}

/// Executes `token transfer accept|reject|withdraw <instruction>`.
pub fn cmd_transfer_action(
    client: &TokenClient,
    action: &str,
    instruction_cid: &str,
    actor_opt: Option<&str>,
    admin_opt: Option<&str>,
    _dar_override: Option<&Path>,
) -> Result<Json, String> {
    let choice = match action {
        "accept" => "TransferInstruction_Accept",
        "reject" => "TransferInstruction_Reject",
        "withdraw" => "TransferInstruction_Withdraw",
        other => return Err(format!("unknown transfer action '{other}'")),
    };

    let mut search_parties = Vec::new();
    let readable = client.readable_parties()?;
    if let Some(a) = actor_opt {
        search_parties.push(client.resolve_party(a)?);
    }
    if let Some(adm) = admin_opt {
        let p = client.resolve_party(adm)?;
        if !search_parties.contains(&p)
            && (!client.has_explicit_token() || readable.iter().any(|rp| rp == &p))
        {
            search_parties.push(p);
        }
    }

    let mut instrs = if search_parties.is_empty() {
        Vec::new()
    } else {
        client.active_interface_contracts(&search_parties, FLT_XFER_INST_V2, true)?
    };
    if !instrs.iter().any(|c| c.contract_id == instruction_cid) {
        for p in &readable {
            if !search_parties.contains(p) {
                search_parties.push(p.clone());
            }
        }
        instrs = client.active_interface_contracts(&search_parties, FLT_XFER_INST_V2, true)?;
    }
    let instr = instrs
        .into_iter()
        .find(|c| c.contract_id == instruction_cid)
        .ok_or_else(|| {
            format!("active TransferInstruction '{instruction_cid}' not found in participant ACS")
        })?;

    let view = first_interface_view(&instr)
        .ok_or_else(|| format!("TransferInstruction '{instruction_cid}' missing interfaceView"))?;
    let sender = view["transfer"]["sender"]["owner"]
        .as_str()
        .ok_or_else(|| "TransferInstruction missing transfer.sender.owner".to_string())?
        .to_string();
    let receiver = view["transfer"]["receiver"]["owner"]
        .as_str()
        .ok_or_else(|| "TransferInstruction missing transfer.receiver.owner".to_string())?
        .to_string();
    let admin = view["transfer"]["instrumentId"]["admin"]
        .as_str()
        .ok_or_else(|| "TransferInstruction missing transfer.instrumentId.admin".to_string())?
        .to_string();
    let input_cids: Vec<String> = view["transfer"]["inputHoldingCids"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let actor = match actor_opt {
        Some(a) => client.resolve_party(a)?,
        None => match action {
            "accept" | "reject" => receiver.clone(),
            "withdraw" => sender.clone(),
            _ => receiver.clone(),
        },
    };

    let is_amulet = instr.template_id.contains("AmuletTransferInstruction");
    let (ctx, mut disclosed) = if is_amulet {
        let am_ctx =
            amulet_instruction_context(client, instruction_cid, choice, &actor, Some(&admin))?;
        (extra_args_from_map(am_ctx.context_values), am_ctx.disclosed)
    } else {
        let (_, rules_disc, extra) = find_token_rules(client, &admin)?;
        let mut blobs = vec![rules_disc];
        if !input_cids.is_empty() {
            let mut readers = vec![actor.clone()];
            if client.has_explicit_token() {
                for p in [sender, receiver, admin] {
                    if readable.iter().any(|rp| rp == &p) && !readers.contains(&p) {
                        readers.push(p);
                    }
                }
            } else {
                for p in [sender, receiver] {
                    if !readers.contains(&p) {
                        readers.push(p);
                    }
                }
                if readable.iter().any(|p| p == &admin) && !readers.contains(&admin) {
                    readers.push(admin);
                }
            }
            let holdings = client.active_interface_contracts(&readers, FLT_HOLD_V2, true)?;
            for cid in &input_cids {
                if let Some(h) = holdings.iter().find(|c| &c.contract_id == cid) {
                    blobs.push(to_disclosed(h));
                }
            }
        }
        (extra, blobs)
    };

    // Disclose the instruction itself when a non-stakeholder actor relies on authority transfer.
    if !instr.created_event_blob.is_empty()
        && !disclosed.iter().any(|d| d.contract_id == instr.contract_id)
    {
        disclosed.push(to_disclosed(&instr));
    }

    let tx = client.submit_tx(
        &unique_command_id(action),
        std::slice::from_ref(&actor),
        &[],
        vec![json!({
            "ExerciseCommand": {
                "templateId": FLT_XFER_INST_V2,
                "contractId": instruction_cid,
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
        "action": action,
        "choice": choice,
        "actor": actor,
        "instruction_cid": instruction_cid,
        "update_id": tx["updateId"],
        "offset": tx["offset"],
    }))
}

/// Executes `token balance <party> [instrument]`.
pub fn cmd_balance(
    client: &TokenClient,
    party_raw: &str,
    instrument_opt: Option<&str>,
) -> Result<Json, String> {
    let party = client.resolve_party(party_raw)?;
    let rows =
        client.active_interface_contracts(std::slice::from_ref(&party), FLT_HOLD_V2, false)?;
    let mut by_inst: BTreeMap<(String, String), BalanceBucket> = BTreeMap::new();
    for c in rows {
        let Some(view) = holding_view(&c) else {
            continue;
        };
        if holding_owner(view) != Some(party.as_str()) {
            continue;
        }
        let inst_id = view["instrumentId"]["id"].as_str().unwrap_or_default();
        if let Some(wanted) = instrument_opt {
            if inst_id != wanted {
                continue;
            }
        }
        let admin = view["instrumentId"]["admin"].as_str().unwrap_or_default();
        let amt = DamlDecimal::parse(view["amount"].as_str().unwrap_or("0"))?;
        let bucket = by_inst
            .entry((inst_id.to_string(), admin.to_string()))
            .or_default();
        if view["lock"].is_null() {
            bucket.avail = bucket.avail.checked_add(amt)?;
        } else {
            bucket.locked = bucket.locked.checked_add(amt)?;
        }
    }

    let mut entries = Vec::new();
    for ((inst_id, admin), b) in by_inst {
        entries.push(json!({
            "party": party,
            "instrument": inst_id,
            "admin": admin,
            "available": b.avail.to_string(),
            "locked": b.locked.to_string(),
            "total": b.total()?.to_string(),
        }));
    }
    Ok(json!({
        "action": "balance",
        "party": party,
        "balances": entries,
    }))
}

/// Executes `token balances [--party <p>...]`.
pub fn cmd_balances(
    client: &TokenClient,
    party_filters: &[String],
    instrument_opt: Option<&str>,
) -> Result<Json, String> {
    let parties: Vec<String> = if party_filters.is_empty() {
        client.readable_parties()?
    } else {
        let mut out = Vec::new();
        for raw in party_filters {
            let p = client.resolve_party(raw)?;
            if !out.contains(&p) {
                out.push(p);
            }
        }
        out
    };

    let mut agg: BTreeMap<(String, String, String), BalanceBucket> = BTreeMap::new();
    for party in &parties {
        let rows =
            client.active_interface_contracts(std::slice::from_ref(party), FLT_HOLD_V2, false)?;
        for c in rows {
            let Some(view) = holding_view(&c) else {
                continue;
            };
            if holding_owner(view) != Some(party.as_str()) {
                continue;
            }
            let inst_id = view["instrumentId"]["id"].as_str().unwrap_or_default();
            if let Some(wanted) = instrument_opt {
                if inst_id != wanted {
                    continue;
                }
            }
            let admin = view["instrumentId"]["admin"].as_str().unwrap_or_default();
            let amt = DamlDecimal::parse(view["amount"].as_str().unwrap_or("0"))?;
            let bucket = agg
                .entry((party.clone(), inst_id.to_string(), admin.to_string()))
                .or_default();
            if view["lock"].is_null() {
                bucket.avail = bucket.avail.checked_add(amt)?;
            } else {
                bucket.locked = bucket.locked.checked_add(amt)?;
            }
        }
    }

    let mut balances = Vec::new();
    let mut supplies: BTreeMap<(String, String), DamlDecimal> = BTreeMap::new();
    for ((party, inst_id, admin), b) in agg {
        let total = b.total()?;
        let cur = supplies
            .entry((inst_id.clone(), admin.clone()))
            .or_insert(DamlDecimal::ZERO);
        *cur = cur.checked_add(total)?;
        balances.push(json!({
            "party": party,
            "instrument": inst_id,
            "admin": admin,
            "available": b.avail.to_string(),
            "locked": b.locked.to_string(),
            "total": total.to_string(),
        }));
    }

    let supply_rows: Vec<Json> = supplies
        .into_iter()
        .map(|((inst, admin), total)| {
            json!({
                "instrument": inst,
                "admin": admin,
                "supply": total.to_string(),
            })
        })
        .collect();

    Ok(json!({
        "action": "balances",
        "balances": balances,
        "supplies": supply_rows,
    }))
}

/// Executes `token activity <party> [--from <u64>] [--to <u64>]`.
pub fn cmd_activity(
    client: &TokenClient,
    party_raw: &str,
    from_offset: Option<u64>,
    to_offset: Option<u64>,
) -> Result<Json, String> {
    let party = client.resolve_party(party_raw)?;
    let end = match to_offset {
        Some(t) => t,
        None => client.ledger_end()?,
    };
    let begin = from_offset.unwrap_or(0);
    let updates = if end > begin {
        client.query_updates(
            begin,
            end,
            std::slice::from_ref(&party),
            &[
                FLT_EVENT_LOG_V2,
                FLT_XFER_INST_V2,
                FLT_ALLOC_V2,
                FLT_HOLD_V2,
            ],
        )?
    } else {
        Vec::new()
    };

    let mut activities = Vec::new();
    for upd in updates {
        let Some(tx) = upd["update"]["Transaction"]["value"].as_object() else {
            continue;
        };
        let update_id = tx
            .get("updateId")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string();
        let offset = tx.get("offset").and_then(Json::as_u64).unwrap_or(0);
        let Some(events) = tx.get("events").and_then(Json::as_array) else {
            continue;
        };
        for ev in events {
            let Some(ex) = ev.get("ExercisedEvent") else {
                continue;
            };
            let choice = ex["choice"].as_str().unwrap_or_default();
            if choice == "EventLog_HoldingsChange"
                || choice.starts_with("TransferFactory_")
                || choice.starts_with("TransferInstruction_")
                || choice.starts_with("AllocationFactory_")
                || choice.starts_with("Allocation_")
                || choice.starts_with("SettlementFactory_")
            {
                let node_id = ex["nodeId"].as_u64().unwrap_or(0);
                activities.push((
                    offset,
                    node_id,
                    json!({
                        "offset": offset,
                        "node_id": node_id,
                        "update_id": update_id,
                        "choice": choice,
                        "contract_id": ex["contractId"],
                        "template_id": ex["templateId"],
                        "acting_parties": ex["actingParties"],
                        "choice_argument": ex["choiceArgument"],
                    }),
                ));
            }
        }
    }
    activities.sort_by_key(|(off, nid, _)| (*off, *nid));
    let items: Vec<Json> = activities.into_iter().map(|(_, _, item)| item).collect();
    Ok(json!({
        "action": "activity",
        "party": party,
        "from_offset": begin,
        "to_offset": end,
        "events": items,
    }))
}

pub(super) fn resolve_admin_rules(
    client: &TokenClient,
    admin_opt: Option<&str>,
) -> Result<(String, ActiveContract, DisclosedContract, Json), String> {
    if let Some(adm_raw) = admin_opt {
        let admin = client.resolve_party(adm_raw)?;
        let (rules, disc, ctx) = find_token_rules(client, &admin)?;
        return Ok((admin, rules, disc, ctx));
    }
    let locals = client.readable_parties()?;
    let all_rules = client.active_template_contracts(&locals, FLT_TOKEN_RULES, true)?;
    match all_rules.as_slice() {
        [] => Err(
            "no active TokenRules found on ledger (pass --admin or run `token create`)".to_string(),
        ),
        [one] => {
            let admin = one.create_argument["admin"]
                .as_str()
                .ok_or_else(|| "TokenRules missing admin field".to_string())?
                .to_string();
            let disc = to_disclosed(one);
            let ctx = test_token_extra_args(&one.contract_id);
            Ok((admin, one.clone(), disc, ctx))
        }
        many => Err(format!(
            "multiple TokenRules ({}) active; specify --admin explicitly",
            many.len()
        )),
    }
}

pub(super) fn to_disclosed(c: &ActiveContract) -> DisclosedContract {
    DisclosedContract {
        contract_id: c.contract_id.clone(),
        template_id: c.template_id.clone(),
        created_event_blob: c.created_event_blob.clone(),
        synchronizer_id: c.synchronizer_id.clone(),
    }
}

pub(super) fn holding_view(c: &ActiveContract) -> Option<&Json> {
    first_interface_view(c)
}

pub(super) fn holding_owner(view: &Json) -> Option<&str> {
    view["account"]["owner"]
        .as_str()
        .or_else(|| view["owner"].as_str())
}

pub(super) fn first_interface_view(c: &ActiveContract) -> Option<&Json> {
    c.interface_views.first().and_then(|v| {
        let vv = &v["viewValue"];
        (!vv.is_null()).then_some(vv)
    })
}

pub(super) fn first_created_cid(tx: &Json) -> Option<String> {
    tx["events"]
        .as_array()?
        .iter()
        .find_map(|ev| ev["CreatedEvent"]["contractId"].as_str().map(String::from))
}

pub(super) fn find_exercised_result<'a>(tx: &'a Json, choice: &str) -> Option<&'a Json> {
    tx["events"].as_array()?.iter().find_map(|ev| {
        let ex = &ev["ExercisedEvent"];
        (ex["choice"].as_str() == Some(choice)).then_some(&ex["exerciseResult"])
    })
}
