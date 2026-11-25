//! Amulet (Splice 0.10.1) faucet and CIP-0112 V2 context helpers (`S-DX-008`, `T-11`).
//!
//! Supports both:
//! - Live Splice Scan (`--scan-url`), querying `/api/scan/v0/dso` and `/registry/transfer-instruction/v1/*`
//! - Local participant ACS (`#splice-amulet:Splice.AmuletRules:AmuletRules`, `OpenMiningRound`,
//!   `ExternalPartyConfigState`, `ExternalPartyAmuletRules`, `LockedAmulet`).

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value as Json};

use super::client::{
    rfc3339_offset, unique_command_id, ActiveContract, DisclosedContract, TokenClient,
};
use super::decimal::DamlDecimal;

pub const FLT_AMULET_RULES: &str = "#splice-amulet:Splice.AmuletRules:AmuletRules";
pub const FLT_OPEN_ROUND: &str = "#splice-amulet:Splice.Round:OpenMiningRound";
pub const FLT_EXT_AMULET_RULES: &str =
    "#splice-amulet:Splice.ExternalPartyAmuletRules:ExternalPartyAmuletRules";
pub const FLT_EXT_CONFIG_STATE: &str =
    "#splice-amulet:Splice.ExternalPartyConfigState:ExternalPartyConfigState";
pub const FLT_LOCKED_AMULET: &str = "#splice-amulet:Splice.Amulet:LockedAmulet";
pub const FLT_AMULET_XFER_INST: &str =
    "#splice-amulet:Splice.AmuletTransferInstruction:AmuletTransferInstruction";

/// Resolved Amulet factory & disclosure context for V2 transfers and instruction lifecycle choices.
#[derive(Clone, Debug)]
pub struct AmuletContext {
    pub context_values: BTreeMap<String, Json>,
    pub disclosed: Vec<DisclosedContract>,
    pub external_rules_cid: Option<String>,
}

/// Executes `token faucet <party> <amount>` via `AmuletRules_DevNet_Tap`.
pub fn cmd_faucet(
    client: &TokenClient,
    party_raw: &str,
    amount_raw: &str,
    dso_hint: Option<&str>,
    _dar_override: Option<&Path>,
) -> Result<Json, String> {
    let amount = DamlDecimal::parse(amount_raw)?;
    if !amount.is_positive() {
        return Err(format!("faucet amount must be > 0, got '{amount_raw}'"));
    }
    let receiver = client.resolve_party(party_raw)?;

    let (rules_disc, round_disc) = resolve_rules_and_round(client, dso_hint, &receiver)?;
    let rules_template_id = if rules_disc.template_id.is_empty() {
        FLT_AMULET_RULES
    } else {
        rules_disc.template_id.as_str()
    };

    let tx = client.submit_tx(
        &unique_command_id("faucet"),
        std::slice::from_ref(&receiver),
        &[],
        vec![json!({
            "ExerciseCommand": {
                "templateId": rules_template_id,
                "contractId": rules_disc.contract_id,
                "choice": "AmuletRules_DevNet_Tap",
                "choiceArgument": {
                    "receiver": receiver,
                    "amount": amount.to_fixed10(),
                    "openRound": round_disc.contract_id,
                }
            }
        })],
        &[rules_disc, round_disc],
    )?;

    let created_cid = extract_faucet_amulet_cid(&tx);
    Ok(json!({
        "action": "faucet",
        "instrument": "Amulet",
        "receiver": receiver,
        "amount": amount.to_string(),
        "contract_id": created_cid,
        "update_id": tx["updateId"],
        "offset": tx["offset"],
    }))
}

/// Resolves `ExternalPartyAmuletRules` CID, context values, and disclosures for `Amulet` `TransferFactory_Transfer`.
pub fn amulet_transfer_factory_context(
    client: &TokenClient,
    sender: &str,
    receiver: &str,
    admin_dso: &str,
    input_cids: &[String],
    amount: DamlDecimal,
) -> Result<AmuletContext, String> {
    if let Some(ctx) =
        try_scan_transfer_factory(client, sender, receiver, admin_dso, input_cids, amount)?
    {
        return Ok(ctx);
    }

    let reader = find_reader_party(client, Some(admin_dso), sender)?;
    let ext_rules = find_single_active(
        client,
        &reader,
        FLT_EXT_AMULET_RULES,
        "ExternalPartyAmuletRules",
    )?;
    let rules = find_single_active(client, &reader, FLT_AMULET_RULES, "AmuletRules")?;
    let round = find_single_active(client, &reader, FLT_OPEN_ROUND, "OpenMiningRound")?;
    let ext_cfg = find_single_active(
        client,
        &reader,
        FLT_EXT_CONFIG_STATE,
        "ExternalPartyConfigState",
    )?;

    let mut context_values = BTreeMap::new();
    context_values.insert(
        "open-round".to_string(),
        json!({ "tag": "AV_ContractId", "value": round.contract_id }),
    );
    context_values.insert(
        "external-party-config-state".to_string(),
        json!({ "tag": "AV_ContractId", "value": ext_cfg.contract_id }),
    );
    context_values.insert(
        "amulet-rules".to_string(),
        json!({ "tag": "AV_ContractId", "value": rules.contract_id }),
    );

    let disclosed = vec![
        to_disclosed(&ext_rules),
        to_disclosed(&rules),
        to_disclosed(&round),
        to_disclosed(&ext_cfg),
    ];

    Ok(AmuletContext {
        context_values,
        disclosed,
        external_rules_cid: Some(ext_rules.contract_id),
    })
}

/// Resolves context and disclosures for `AmuletTransferInstruction` accept/reject/withdraw.
pub fn amulet_instruction_context(
    client: &TokenClient,
    instruction_cid: &str,
    choice: &str,
    actor: &str,
    admin_dso: Option<&str>,
) -> Result<AmuletContext, String> {
    let verb = match choice {
        "TransferInstruction_Accept" => "accept",
        "TransferInstruction_Reject" => "reject",
        "TransferInstruction_Withdraw" => "withdraw",
        other => {
            return Err(format!(
                "unsupported Amulet transfer instruction choice '{other}'"
            ))
        }
    };
    if let Some(ctx) = try_scan_instruction_context(client, instruction_cid, verb)? {
        return Ok(ctx);
    }

    let reader = find_reader_party(client, admin_dso, actor)?;
    let rules = find_single_active(client, &reader, FLT_AMULET_RULES, "AmuletRules")?;
    let round = find_single_active(client, &reader, FLT_OPEN_ROUND, "OpenMiningRound")?;
    let ext_cfg = find_single_active(
        client,
        &reader,
        FLT_EXT_CONFIG_STATE,
        "ExternalPartyConfigState",
    )?;

    let mut context_values = BTreeMap::new();
    context_values.insert(
        "open-round".to_string(),
        json!({ "tag": "AV_ContractId", "value": round.contract_id }),
    );
    context_values.insert(
        "external-party-config-state".to_string(),
        json!({ "tag": "AV_ContractId", "value": ext_cfg.contract_id }),
    );
    context_values.insert(
        "amulet-rules".to_string(),
        json!({ "tag": "AV_ContractId", "value": rules.contract_id }),
    );
    context_values.insert(
        "expire-lock".to_string(),
        json!({ "tag": "AV_Bool", "value": true }),
    );

    let mut disclosed = vec![
        to_disclosed(&rules),
        to_disclosed(&round),
        to_disclosed(&ext_cfg),
    ];
    // Disclose LockedAmulet held by the AmuletTransferInstruction when visible in ACS.
    let instrs = client.active_template_contracts(
        &[reader.clone(), actor.to_string()],
        FLT_AMULET_XFER_INST,
        true,
    )?;
    if let Some(instr) = instrs.iter().find(|c| c.contract_id == instruction_cid) {
        if let Some(locked_cid) = instr.create_argument["lockedAmulet"].as_str() {
            let locked_rows = client.active_template_contracts(
                &[reader, actor.to_string()],
                FLT_LOCKED_AMULET,
                true,
            )?;
            if let Some(locked) = locked_rows.iter().find(|c| c.contract_id == locked_cid) {
                disclosed.push(to_disclosed(locked));
            }
        }
        disclosed.push(to_disclosed(instr));
    }

    Ok(AmuletContext {
        context_values,
        disclosed,
        external_rules_cid: None,
    })
}

fn resolve_rules_and_round(
    client: &TokenClient,
    dso_hint: Option<&str>,
    receiver: &str,
) -> Result<(DisclosedContract, DisclosedContract), String> {
    if let Some(ref scan) = client.scan {
        let dso = match client.scan_call("GET", "/v0/dso", None) {
            Ok(d) => d,
            Err(first_err) => {
                if scan.prefix.is_empty() {
                    let (st, body) = crate::commands::json_http::call_with_token(
                        &scan.host,
                        scan.port,
                        "GET",
                        "/api/scan/v0/dso",
                        None,
                        None,
                    )?;
                    if (200..300).contains(&st) {
                        body
                    } else {
                        return Err(first_err);
                    }
                } else {
                    return Err(first_err);
                }
            }
        };
        let rules = scan_contract_with_state_to_disclosed(&dso["amulet_rules"])?;
        let round = scan_contract_with_state_to_disclosed(&dso["latest_mining_round"])?;
        return Ok((rules, round));
    }
    let reader = find_reader_party(client, dso_hint, receiver)?;
    let rules = find_single_active(client, &reader, FLT_AMULET_RULES, "AmuletRules")?;
    let round = find_single_active(client, &reader, FLT_OPEN_ROUND, "OpenMiningRound")?;
    Ok((to_disclosed(&rules), to_disclosed(&round)))
}

fn try_scan_transfer_factory(
    client: &TokenClient,
    sender: &str,
    receiver: &str,
    admin_dso: &str,
    input_cids: &[String],
    amount: DamlDecimal,
) -> Result<Option<AmuletContext>, String> {
    let Some(ref scan) = client.scan else {
        return Ok(None);
    };
    let req_body = json!({
        "choiceArguments": {
            "expectedAdmin": admin_dso,
            "transfer": {
                "sender": sender,
                "receiver": receiver,
                "amount": amount.to_fixed10(),
                "instrumentId": { "admin": admin_dso, "id": "Amulet" },
                "requestedAt": rfc3339_offset(-30),
                "executeBefore": rfc3339_offset(3600),
                "inputHoldingCids": input_cids,
                "meta": { "values": {} }
            },
            "extraArgs": {
                "context": { "values": {} },
                "meta": { "values": {} }
            }
        },
        "excludeDebugFields": false
    });
    let res = call_scan_registry(
        scan,
        "/registry/transfer-instruction/v1/transfer-factory",
        &req_body,
    )?;
    let factory_id = res["factoryId"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| format!("missing factoryId from Scan transfer-factory: {res}"))?;
    let ctx = parse_scan_choice_context(&res["choiceContext"], Some(factory_id))?;
    Ok(Some(ctx))
}

fn try_scan_instruction_context(
    client: &TokenClient,
    instruction_cid: &str,
    verb: &str,
) -> Result<Option<AmuletContext>, String> {
    let Some(ref scan) = client.scan else {
        return Ok(None);
    };
    let path =
        format!("/registry/transfer-instruction/v1/{instruction_cid}/choice-contexts/{verb}");
    let res = call_scan_registry(scan, &path, &json!({ "excludeDebugFields": false }))?;
    let ctx = parse_scan_choice_context(&res, None)?;
    Ok(Some(ctx))
}

fn call_scan_registry(
    scan: &super::client::HttpTarget,
    registry_path: &str,
    payload: &Json,
) -> Result<Json, String> {
    let bytes = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    let (st1, b1) = crate::commands::json_http::call_with_token(
        &scan.host,
        scan.port,
        "POST",
        registry_path,
        Some((&bytes, "application/json")),
        None,
    )?;
    if (200..300).contains(&st1) {
        return Ok(b1);
    }
    let prefixed = scan.full_path(registry_path);
    if prefixed != registry_path && st1 == 404 {
        let (st2, b2) = crate::commands::json_http::call_with_token(
            &scan.host,
            scan.port,
            "POST",
            &prefixed,
            Some((&bytes, "application/json")),
            None,
        )?;
        if (200..300).contains(&st2) {
            return Ok(b2);
        }
        return Err(format!(
            "Scan {prefixed} failed (HTTP {st2}): {}",
            crate::commands::json_http::error_cause(&b2)
        ));
    }
    Err(format!(
        "Scan {registry_path} failed (HTTP {st1}): {}",
        crate::commands::json_http::error_cause(&b1)
    ))
}

fn parse_scan_choice_context(
    ctx_obj: &Json,
    external_rules_cid: Option<String>,
) -> Result<AmuletContext, String> {
    let mut context_values = BTreeMap::new();
    if let Some(map) = ctx_obj["choiceContextData"]["values"].as_object() {
        for (k, v) in map {
            context_values.insert(k.clone(), v.clone());
        }
    }
    let mut disclosed = Vec::new();
    if let Some(arr) = ctx_obj["disclosedContracts"].as_array() {
        for item in arr {
            let cid = item["contractId"]
                .as_str()
                .ok_or_else(|| "scan disclosedContract missing contractId".to_string())?;
            let tid = item["templateId"]
                .as_str()
                .ok_or_else(|| "scan disclosedContract missing templateId".to_string())?;
            let blob = item["createdEventBlob"]
                .as_str()
                .ok_or_else(|| "scan disclosedContract missing createdEventBlob".to_string())?;
            let sync = item["synchronizerId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            disclosed.push(DisclosedContract {
                contract_id: cid.to_string(),
                template_id: tid.to_string(),
                created_event_blob: blob.to_string(),
                synchronizer_id: sync,
            });
        }
    }
    Ok(AmuletContext {
        context_values,
        disclosed,
        external_rules_cid,
    })
}

fn scan_contract_with_state_to_disclosed(node: &Json) -> Result<DisclosedContract, String> {
    let contract = &node["contract"];
    let cid = contract["contract_id"]
        .as_str()
        .or_else(|| contract["contractId"].as_str())
        .ok_or_else(|| format!("missing contract_id in scan response: {node}"))?;
    let tid = contract["template_id"]
        .as_str()
        .or_else(|| contract["templateId"].as_str())
        .ok_or_else(|| format!("missing template_id in scan response: {node}"))?;
    let blob = contract["created_event_blob"]
        .as_str()
        .or_else(|| contract["createdEventBlob"].as_str())
        .ok_or_else(|| format!("missing created_event_blob in scan response: {node}"))?;
    let sync = node["domain_id"]
        .as_str()
        .or_else(|| node["synchronizerId"].as_str())
        .unwrap_or_default();
    Ok(DisclosedContract {
        contract_id: cid.to_string(),
        template_id: tid.to_string(),
        created_event_blob: blob.to_string(),
        synchronizer_id: sync.to_string(),
    })
}

fn find_reader_party(
    client: &TokenClient,
    dso_hint: Option<&str>,
    fallback: &str,
) -> Result<String, String> {
    if let Some(hint) = dso_hint {
        return client.resolve_party(hint);
    }
    let locals = client.readable_parties()?;
    if let Some(dso) = locals
        .iter()
        .find(|p| p.starts_with("DSO::") || p.starts_with("Dso::") || p.starts_with("dso"))
    {
        return Ok(dso.clone());
    }
    Ok(fallback.to_string())
}

fn find_single_active(
    client: &TokenClient,
    party: &str,
    template_filter: &str,
    label: &str,
) -> Result<ActiveContract, String> {
    let mut parties = Vec::new();
    let readable = client.readable_parties()?;
    if !client.has_explicit_token() || readable.iter().any(|rp| rp == party) {
        parties.push(party.to_string());
    }
    for p in readable {
        if !parties.contains(&p) {
            parties.push(p);
        }
    }
    let rows = client.active_template_contracts(&parties, template_filter, true)?;
    rows.into_iter()
        .next()
        .ok_or_else(|| format!("active {label} contract not found on ledger"))
}

fn to_disclosed(c: &ActiveContract) -> DisclosedContract {
    DisclosedContract {
        contract_id: c.contract_id.clone(),
        template_id: c.template_id.clone(),
        created_event_blob: c.created_event_blob.clone(),
        synchronizer_id: c.synchronizer_id.clone(),
    }
}

fn extract_faucet_amulet_cid(tx: &Json) -> Option<String> {
    let events = tx["events"].as_array()?;
    for ev in events {
        if let Some(cid) = ev["CreatedEvent"]["contractId"].as_str() {
            return Some(cid.to_string());
        }
        if let Some(cid) = ev["ExercisedEvent"]["exerciseResult"]["amuletSum"]["amulet"].as_str() {
            return Some(cid.to_string());
        }
    }
    None
}
