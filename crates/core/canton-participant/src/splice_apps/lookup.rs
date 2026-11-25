//! Runtime lookups shared by the operations: parties, wallets, licenses, open rounds and balances.

use lf_eval::scan_state::parse_micros;
use lf_eval::Contract;
use serde_json::{json, Value as Json};

use super::sv_ops::dso_bootstrap_payload;
use super::util::{amulet_value_and_fee, deterministic_party, format_decimal_10};
use super::wallet::BalanceSummary;
use super::{SpliceAppError, SpliceAppRuntime, SpliceBackend, TransferTrackingState};

impl SpliceAppRuntime {
    pub(super) fn required_num_votes(&self) -> i64 {
        let sv_count = self
            .find_contracts("Splice.DsoRules:DsoRules")
            .first()
            .and_then(|c| self.encoded_payload(c).ok())
            .and_then(|p| p["svs"].as_array().map(|a| a.len() as i64))
            .unwrap_or(1)
            .max(1);
        let f = (sv_count - 1).div_euclid(3);
        (sv_count + f + 2) / 2
    }

    pub(super) fn resolve_party_or_user(&self, input: &str) -> String {
        if input.contains("::") {
            return input.to_string();
        }
        if let Some(c) = self.find_wallet_install_by_user(input) {
            if let Ok(p) = self.encoded_payload(c) {
                if let Some(party) = p["endUserParty"].as_str() {
                    return party.to_string();
                }
            }
        }
        if input == self.config.sv_name || input == self.config.sv_user {
            return self.config.sv_party.clone();
        }
        if input == "validator" {
            return self.config.validator_party.clone();
        }
        if input.eq_ignore_ascii_case("dso") {
            return self.config.dso_party.clone();
        }
        if let SpliceBackend::ParticipantLedger(client) = &self.backend {
            if let Some(known) = client.lookup_known_party(input) {
                return known.to_string();
            }
        }
        deterministic_party(input)
    }

    pub(super) fn resolve_or_allocate_party(
        &mut self,
        input: &str,
    ) -> Result<String, SpliceAppError> {
        let existing = if input.contains("::") {
            Some(input.to_string())
        } else if let Some(c) = self.find_wallet_install_by_user(input) {
            self.encoded_payload(c)
                .ok()
                .and_then(|p| p["endUserParty"].as_str().map(String::from))
        } else if input == self.config.sv_name || input == self.config.sv_user {
            Some(self.config.sv_party.clone())
        } else if input == "validator" {
            Some(self.config.validator_party.clone())
        } else if input.eq_ignore_ascii_case("dso") {
            Some(self.config.dso_party.clone())
        } else {
            None
        };

        match &mut self.backend {
            SpliceBackend::InProcess => {
                Ok(existing.unwrap_or_else(|| self.resolve_party_or_user(input)))
            }
            SpliceBackend::ParticipantLedger(client) => {
                let target = existing.as_deref().unwrap_or(input);
                if input.eq_ignore_ascii_case("dso") {
                    return Ok(self.config.dso_party.clone());
                }
                client.ensure_party_and_grant(target)
            }
        }
    }

    pub(super) fn find_wallet_install_by_user(&self, user_name: &str) -> Option<&Contract> {
        self.find_contracts("Splice.Wallet.Install:WalletAppInstall")
            .into_iter()
            .find(|c| {
                self.encoded_payload(c)
                    .ok()
                    .and_then(|p| p["endUserName"].as_str().map(|n| n == user_name))
                    .unwrap_or(false)
            })
    }

    pub(super) fn find_wallet_install_for_party(&self, party: &str) -> Option<(String, String)> {
        self.find_contracts("Splice.Wallet.Install:WalletAppInstall")
            .into_iter()
            .find_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                if p["endUserParty"].as_str() == Some(party) {
                    Some((
                        c.contract_id.clone(),
                        p["validatorParty"].as_str()?.to_string(),
                    ))
                } else {
                    None
                }
            })
    }

    pub(super) fn find_validator_license(&self, validator: &str) -> Option<(String, Option<i64>)> {
        self.find_contracts("Splice.ValidatorLicense:ValidatorLicense")
            .into_iter()
            .find_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                if p["validator"].as_str() == Some(validator) {
                    let last = p["faucetState"]["lastReceivedFor"]["number"]
                        .as_str()
                        .and_then(|n| n.parse::<i64>().ok());
                    Some((c.contract_id.clone(), last))
                } else {
                    None
                }
            })
    }

    pub(super) fn require_singleton_cid(
        &self,
        template_id: &str,
    ) -> Result<String, SpliceAppError> {
        self.find_contracts(template_id)
            .first()
            .map(|c| c.contract_id.clone())
            .ok_or_else(|| {
                SpliceAppError::NotFound(format!("found no active {template_id} contract"))
            })
    }

    pub(super) fn latest_active_open_round(&self) -> Result<(i64, String), SpliceAppError> {
        let mut active = Vec::new();
        for c in self.find_contracts("Splice.Round:OpenMiningRound") {
            let p = self.encoded_payload(c)?;
            let opens_at = parse_micros(p["opensAt"].as_str().ok_or_else(|| {
                SpliceAppError::Internal("OpenMiningRound missing opensAt".into())
            })?)
            .map_err(SpliceAppError::Internal)?;
            if opens_at <= self.now_micros {
                let num = p["round"]["number"]
                    .as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                active.push((num, c.contract_id.clone()));
            }
        }
        active
            .into_iter()
            .max_by_key(|(num, _)| *num)
            .ok_or_else(|| {
                SpliceAppError::NotFound("no open mining round active at current time".into())
            })
    }

    pub(super) fn next_open_round_for_min_num(
        &self,
        min_round: i64,
    ) -> Result<Option<String>, SpliceAppError> {
        let mut candidates = Vec::new();
        for c in self.find_contracts("Splice.Round:OpenMiningRound") {
            let p = self.encoded_payload(c)?;
            let opens_at = parse_micros(p["opensAt"].as_str().ok_or_else(|| {
                SpliceAppError::Internal("OpenMiningRound missing opensAt".into())
            })?)
            .map_err(SpliceAppError::Internal)?;
            if opens_at <= self.now_micros {
                let num = p["round"]["number"]
                    .as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                if num >= min_round {
                    candidates.push((num, c.contract_id.clone()));
                }
            }
        }
        candidates.sort_by_key(|(n, _)| *n);
        Ok(candidates.into_iter().next().map(|(_, cid)| cid))
    }

    pub(super) fn latest_open_round_number(&self) -> Result<i64, SpliceAppError> {
        self.latest_active_open_round().map(|(n, _)| n)
    }

    pub(super) fn amulet_inputs_for(&self, owner: &str) -> Vec<Json> {
        self.find_contracts("Splice.Amulet:Amulet")
            .into_iter()
            .filter_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                if p["owner"].as_str() == Some(owner) {
                    Some(json!({
                        "tag": "InputAmulet",
                        "value": c.contract_id,
                    }))
                } else {
                    None
                }
            })
            .collect()
    }

    pub(super) fn payment_transfer_context(
        &self,
        amulet_rules_cid: &str,
        user_party: &str,
    ) -> Result<Json, SpliceAppError> {
        let (_, open_round_cid) = self.latest_active_open_round()?;
        let mut issuing_rounds = Vec::new();
        for c in self.find_contracts("Splice.Round:IssuingMiningRound") {
            let p = self.encoded_payload(c)?;
            issuing_rounds.push(json!([p["round"], c.contract_id]));
        }
        let validator_rights: Vec<Json> = Vec::new();
        let featured = self
            .find_contracts("Splice.Amulet:FeaturedAppRight")
            .into_iter()
            .find_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                if p["provider"].as_str() == Some(user_party) {
                    Some(c.contract_id.clone())
                } else {
                    None
                }
            });
        Ok(json!({
            "amuletRules": amulet_rules_cid,
            "context": {
                "openMiningRound": open_round_cid,
                "issuingMiningRounds": issuing_rounds,
                "validatorRights": validator_rights,
                "featuredAppRight": featured,
            }
        }))
    }

    pub(super) fn compute_balance_summary(
        &self,
        party: &str,
    ) -> Result<BalanceSummary, SpliceAppError> {
        let current_round = self.latest_open_round_number().unwrap_or(0);
        let mut unlocked_qty: i128 = 0;
        let mut unlocked_fees: i128 = 0;
        let mut locked_qty: i128 = 0;
        let mut locked_fees: i128 = 0;
        let mut total_initial: i128 = 0;

        for c in self.find_contracts("Splice.Amulet:Amulet") {
            let p = self.encoded_payload(c)?;
            if p["owner"].as_str() != Some(party) {
                continue;
            }
            let (init, fee) = amulet_value_and_fee(&p, current_round);
            total_initial = total_initial.saturating_add(init);
            unlocked_fees = unlocked_fees.saturating_add(fee);
            unlocked_qty = unlocked_qty.saturating_add((init - fee).max(0));
        }

        for c in self.find_contracts("Splice.Amulet:LockedAmulet") {
            let p = self.encoded_payload(c)?;
            if p["amulet"]["owner"].as_str() != Some(party) {
                continue;
            }
            let (init, fee) = amulet_value_and_fee(&p["amulet"], current_round);
            total_initial = total_initial.saturating_add(init);
            locked_fees = locked_fees.saturating_add(fee);
            locked_qty = locked_qty.saturating_add((init - fee).max(0));
        }

        let total_fees = unlocked_fees.saturating_add(locked_fees);
        Ok(BalanceSummary {
            round: current_round,
            unlocked_qty: format_decimal_10(unlocked_qty),
            locked_qty: format_decimal_10(locked_qty),
            total_initial: format_decimal_10(total_initial),
            unlocked_fees: format_decimal_10(unlocked_fees),
            locked_fees: format_decimal_10(locked_fees),
            total_fees: format_decimal_10(total_fees),
        })
    }

    pub(super) fn update_transfer_tracking_by_cid(
        &mut self,
        offer_cid: &str,
        next: TransferTrackingState,
    ) {
        for entry in self.transfer_tracking.values_mut() {
            if let TransferTrackingState::Created { offer_cid: cid, .. } = &entry.state {
                if cid == offer_cid {
                    entry.state = next;
                    break;
                }
            }
        }
    }

    pub(super) fn user_status(&self, party_or_user: &str) -> Json {
        let (onboarded, party) = if !party_or_user.contains("::") {
            if let Some(c) = self.find_wallet_install_by_user(party_or_user) {
                let p = self.encoded_payload(c).ok();
                (
                    true,
                    p.and_then(|v| v["endUserParty"].as_str().map(String::from))
                        .unwrap_or_else(|| deterministic_party(party_or_user)),
                )
            } else {
                (false, self.resolve_party_or_user(party_or_user))
            }
        } else {
            let found = self.find_wallet_install_for_party(party_or_user).is_some();
            (found, party_or_user.to_string())
        };
        let featured = self
            .find_contracts("Splice.Amulet:FeaturedAppRight")
            .into_iter()
            .any(|c| {
                self.encoded_payload(c)
                    .ok()
                    .and_then(|p| p["provider"].as_str().map(|s| s == party))
                    .unwrap_or(false)
            });
        json!({
            "party_id": party,
            "user_onboarded": onboarded,
            "user_wallet_installed": onboarded,
            "has_featured_app_right": featured,
        })
    }

    pub(super) fn dso_bootstrap_payload(&self) -> Json {
        dso_bootstrap_payload(&self.config, self.now_micros)
    }
}
