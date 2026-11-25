//! The runtime's automation tick: expiring offers, completing transfers and traffic requests, and SV rounds.

use lf_eval::scan_state::parse_micros;
use serde_json::json;

use super::util::{dedup_actors, last_recorded_or};
use super::{
    AutomationTickReport, SpliceAppError, SpliceAppRuntime, TrafficTrackingState,
    TransferTrackingState,
};

impl SpliceAppRuntime {
    /// Run one pass of background automation:
    /// 1) Expire overdue `TransferOffer` and `BuyTrafficRequest` contracts,
    /// 2) Complete `AcceptedTransferOffer`s and `BuyTrafficRequest`s using active Amulets,
    /// 3) Record validator liveness (`ValidatorLicense_RecordValidatorLivenessActivity`),
    /// 4) Collect SV reward coupons (`DsoRules_ReceiveSvRewardCoupon`),
    /// 5) Advance `OpenMiningRound`s when `now >= targetClosesAt`,
    /// 6) Close ready/expired governance `VoteRequest`s (`DsoRules_CloseVoteRequest`).
    pub fn run_automation_tick(&mut self) -> Result<AutomationTickReport, SpliceAppError> {
        self.sync_ledger()?;
        let mut report = AutomationTickReport::default();

        self.expire_stale_offers(&mut report);
        self.expire_stale_traffic_requests(&mut report);
        self.complete_accepted_offers(&mut report);
        self.complete_traffic_requests(&mut report);
        self.automate_validator_liveness(&mut report);
        self.automate_sv_reward_coupons(&mut report);
        self.automate_round_advancement(&mut report);
        self.automate_vote_closings(&mut report);

        Ok(report)
    }

    fn expire_stale_offers(&mut self, report: &mut AutomationTickReport) {
        let candidates: Vec<(String, String, Option<String>)> = self
            .find_contracts("Splice.Wallet.TransferOffer:TransferOffer")
            .into_iter()
            .filter_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                let exp = parse_micros(p["expiresAt"].as_str()?).ok()?;
                if self.now_micros >= exp {
                    Some((
                        c.contract_id.clone(),
                        p["sender"].as_str()?.to_string(),
                        p["trackingId"].as_str().map(String::from),
                    ))
                } else {
                    None
                }
            })
            .collect();

        for (cid, sender, tracking_id) in candidates {
            let res = self.run_exercise(
                &[sender.as_str()],
                &cid,
                "TransferOffer_Expire",
                &json!({ "actor": sender }),
                "automation-expire-transfer-offer",
            );
            match res {
                Ok(_) => {
                    report.offers_expired += 1;
                    if let Some(tid) = tracking_id {
                        if let Some(entry) = self.transfer_tracking.get_mut(&tid) {
                            entry.state = TransferTrackingState::Failed {
                                failure_kind: "expired".into(),
                                withdrawn_reason: None,
                            };
                        }
                    }
                }
                Err(e) => report.errors.push(format!("expire offer {cid}: {e}")),
            }
        }
    }

    fn expire_stale_traffic_requests(&mut self, report: &mut AutomationTickReport) {
        let candidates: Vec<(String, String, Option<String>)> = self
            .find_contracts("Splice.Wallet.BuyTrafficRequest:BuyTrafficRequest")
            .into_iter()
            .filter_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                let exp = parse_micros(p["expiresAt"].as_str()?).ok()?;
                if self.now_micros >= exp {
                    Some((
                        c.contract_id.clone(),
                        p["endUserParty"].as_str()?.to_string(),
                        p["trackingId"].as_str().map(String::from),
                    ))
                } else {
                    None
                }
            })
            .collect();

        for (cid, buyer, tracking_id) in candidates {
            let res = self.run_exercise(
                &[buyer.as_str()],
                &cid,
                "BuyTrafficRequest_Expire",
                &json!({}),
                "automation-expire-buy-traffic",
            );
            match res {
                Ok(_) => {
                    report.traffic_requests_expired += 1;
                    if let Some(tid) = tracking_id {
                        if let Some(entry) = self.traffic_tracking.get_mut(&tid) {
                            entry.state = TrafficTrackingState::Failed {
                                failure_reason: "expired".into(),
                                rejection_reason: Some("request expired".into()),
                            };
                        }
                    }
                }
                Err(e) => report.errors.push(format!("expire traffic {cid}: {e}")),
            }
        }
    }

    fn complete_accepted_offers(&mut self, report: &mut AutomationTickReport) {
        let accepted: Vec<(String, String, Option<String>)> = self
            .find_contracts("Splice.Wallet.TransferOffer:AcceptedTransferOffer")
            .into_iter()
            .filter_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                let exp = parse_micros(p["expiresAt"].as_str()?).ok()?;
                if self.now_micros < exp {
                    Some((
                        c.contract_id.clone(),
                        p["sender"].as_str()?.to_string(),
                        p["trackingId"].as_str().map(String::from),
                    ))
                } else {
                    None
                }
            })
            .collect();

        for (accepted_cid, sender, tracking_id) in accepted {
            let Ok(amulet_rules_cid) = self.require_singleton_cid("Splice.AmuletRules:AmuletRules")
            else {
                break;
            };
            let inputs = self.amulet_inputs_for(&sender);
            if inputs.is_empty() {
                continue;
            }
            let Ok(context) = self.payment_transfer_context(&amulet_rules_cid, &sender) else {
                continue;
            };
            let validator_party = self.config.validator_party.clone();
            let outcome =
                if let Some((install_cid, vp)) = self.find_wallet_install_for_party(&sender) {
                    self.run_exercise(
                        &[vp.as_str()],
                        &install_cid,
                        "WalletAppInstall_ExecuteBatch",
                        &json!({
                            "context": context,
                            "inputs": inputs,
                            "operations": [{
                                "tag": "CO_CompleteAcceptedTransfer",
                                "value": accepted_cid,
                            }],
                        }),
                        "automation-complete-transfer-batch",
                    )
                } else {
                    let actors = dedup_actors(&[sender.as_str(), validator_party.as_str()]);
                    self.run_exercise(
                        &actors,
                        &accepted_cid,
                        "AcceptedTransferOffer_Complete",
                        &json!({
                            "inputs": inputs,
                            "transferContext": context,
                            "walletProvider": validator_party,
                        }),
                        "automation-complete-transfer",
                    )
                };

            match outcome {
                Ok(tx) => {
                    report.transfers_completed += 1;
                    let created_amulet = tx
                        .created
                        .iter()
                        .find(|c| c.template_id == "Splice.Amulet:Amulet")
                        .map(|c| c.contract_id.clone())
                        .unwrap_or_else(|| accepted_cid.clone());
                    if let Some(tid) = tracking_id {
                        if let Some(entry) = self.transfer_tracking.get_mut(&tid) {
                            entry.state = TransferTrackingState::Completed {
                                amulet_cid: created_amulet,
                                tx_id: tx.update_id,
                            };
                        }
                    }
                }
                Err(e) => report
                    .errors
                    .push(format!("complete offer {accepted_cid}: {e}")),
            }
        }
    }

    fn complete_traffic_requests(&mut self, report: &mut AutomationTickReport) {
        let requests: Vec<(String, String, Option<String>)> = self
            .find_contracts("Splice.Wallet.BuyTrafficRequest:BuyTrafficRequest")
            .into_iter()
            .filter_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                let exp = parse_micros(p["expiresAt"].as_str()?).ok()?;
                if self.now_micros < exp {
                    Some((
                        c.contract_id.clone(),
                        p["endUserParty"].as_str()?.to_string(),
                        p["trackingId"].as_str().map(String::from),
                    ))
                } else {
                    None
                }
            })
            .collect();

        for (req_cid, buyer, tracking_id) in requests {
            let Ok(amulet_rules_cid) = self.require_singleton_cid("Splice.AmuletRules:AmuletRules")
            else {
                break;
            };
            let inputs = self.amulet_inputs_for(&buyer);
            if inputs.is_empty() {
                continue;
            }
            let Ok(context) = self.payment_transfer_context(&amulet_rules_cid, &buyer) else {
                continue;
            };
            let validator_party = self.config.validator_party.clone();
            let outcome =
                if let Some((install_cid, vp)) = self.find_wallet_install_for_party(&buyer) {
                    self.run_exercise(
                        &[vp.as_str()],
                        &install_cid,
                        "WalletAppInstall_ExecuteBatch",
                        &json!({
                            "context": context,
                            "inputs": inputs,
                            "operations": [{
                                "tag": "CO_CompleteBuyTrafficRequest",
                                "value": { "trafficRequestCid": req_cid },
                            }],
                        }),
                        "automation-complete-buy-traffic-batch",
                    )
                } else {
                    let actors = dedup_actors(&[buyer.as_str(), validator_party.as_str()]);
                    self.run_exercise(
                        &actors,
                        &req_cid,
                        "BuyTrafficRequest_Complete",
                        &json!({
                            "inputs": inputs,
                            "context": context,
                            "walletProvider": validator_party,
                        }),
                        "automation-complete-buy-traffic",
                    )
                };

            match outcome {
                Ok(tx) => {
                    report.traffic_requests_completed += 1;
                    let traffic_cid = tx
                        .created
                        .iter()
                        .find(|c| c.template_id == "Splice.DecentralizedSynchronizer:MemberTraffic")
                        .map(|c| c.contract_id.clone())
                        .unwrap_or_else(|| req_cid.clone());
                    if let Some(tid) = tracking_id {
                        if let Some(entry) = self.traffic_tracking.get_mut(&tid) {
                            entry.state = TrafficTrackingState::Completed {
                                traffic_cid,
                                tx_id: tx.update_id,
                            };
                        }
                    }
                }
                Err(e) => report
                    .errors
                    .push(format!("complete buy traffic {req_cid}: {e}")),
            }
        }
    }

    fn automate_validator_liveness(&mut self, report: &mut AutomationTickReport) {
        let licenses: Vec<(String, String, Option<i64>)> = self
            .find_contracts("Splice.ValidatorLicense:ValidatorLicense")
            .into_iter()
            .filter_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                let validator = p["validator"].as_str()?.to_string();
                let last_received = p["faucetState"]["lastReceivedFor"]["number"]
                    .as_str()
                    .and_then(|n| n.parse::<i64>().ok());
                Some((
                    c.contract_id.clone(),
                    validator,
                    last_recorded_or(last_received),
                ))
            })
            .collect();

        for (license_cid, validator, last_received) in licenses {
            let min_round = last_received.map(|r| r + 1).unwrap_or(0);
            let Ok(Some(open_round_cid)) = self.next_open_round_for_min_num(min_round) else {
                continue;
            };
            match self.run_exercise(
                &[validator.as_str()],
                &license_cid,
                "ValidatorLicense_RecordValidatorLivenessActivity",
                &json!({ "openRoundCid": open_round_cid }),
                "automation-validator-liveness",
            ) {
                Ok(_) => report.validator_liveness_recorded += 1,
                Err(e) => report.errors.push(format!("liveness {validator}: {e}")),
            }
        }
    }

    fn automate_sv_reward_coupons(&mut self, report: &mut AutomationTickReport) {
        let Some((state_cid, sv_name, last_collected)) = self
            .find_contracts("Splice.DSO.SvState:SvRewardState")
            .into_iter()
            .find_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                if p["svName"].as_str() != Some(self.config.sv_name.as_str()) {
                    return None;
                }
                let last = p["state"]["lastRoundCollected"]["number"]
                    .as_str()?
                    .parse::<i64>()
                    .ok()?;
                Some((c.contract_id.clone(), self.config.sv_name.clone(), last))
            })
        else {
            return;
        };
        let _ = sv_name;
        let Ok(Some(open_round_cid)) = self.next_open_round_for_min_num(last_collected + 1) else {
            return;
        };
        let Ok(dso_rules_cid) = self.require_singleton_cid("Splice.DsoRules:DsoRules") else {
            return;
        };
        let sv = self.config.sv_party.clone();
        match self.run_exercise(
            &[sv.as_str()],
            &dso_rules_cid,
            "DsoRules_ReceiveSvRewardCoupon",
            &json!({
                "sv": sv,
                "openRoundCid": open_round_cid,
                "rewardStateCid": state_cid,
                "beneficiaries": [{ "_1": sv, "_2": "10000" }],
            }),
            "automation-sv-reward-coupon",
        ) {
            Ok(_) => report.sv_reward_coupons_collected += 1,
            Err(e) => report.errors.push(format!("sv reward coupon: {e}")),
        }
    }

    fn automate_round_advancement(&mut self, report: &mut AutomationTickReport) {
        let mut rounds: Vec<(i64, i64, String)> = self
            .find_contracts("Splice.Round:OpenMiningRound")
            .into_iter()
            .filter_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                let num = p["round"]["number"].as_str()?.parse::<i64>().ok()?;
                let closes_at = parse_micros(p["targetClosesAt"].as_str()?).ok()?;
                Some((num, closes_at, c.contract_id.clone()))
            })
            .collect();
        rounds.sort_by_key(|(num, _, _)| *num);
        if rounds.len() < 3 || self.now_micros < rounds[0].1 {
            return;
        }
        let Ok(dso_rules_cid) = self.require_singleton_cid("Splice.DsoRules:DsoRules") else {
            return;
        };
        let Ok(amulet_rules_cid) = self.require_singleton_cid("Splice.AmuletRules:AmuletRules")
        else {
            return;
        };
        let price_votes: Vec<String> = self
            .find_contracts("Splice.DSO.AmuletPrice:AmuletPriceVote")
            .into_iter()
            .map(|c| c.contract_id.clone())
            .collect();
        if price_votes.is_empty() {
            return;
        }
        let sv = self.config.sv_party.clone();
        match self.run_exercise(
            &[sv.as_str()],
            &dso_rules_cid,
            "DsoRules_AdvanceOpenMiningRounds",
            &json!({
                "amuletRulesCid": amulet_rules_cid,
                "roundToArchiveCid": rounds[0].2,
                "middleRoundCid": rounds[1].2,
                "latestRoundCid": rounds[2].2,
                "amuletPriceVoteCids": price_votes,
                "sv": sv,
            }),
            "automation-advance-rounds",
        ) {
            Ok(_) => report.mining_rounds_advanced += 1,
            Err(e) => report.errors.push(format!("advance rounds: {e}")),
        }
    }

    fn automate_vote_closings(&mut self, report: &mut AutomationTickReport) {
        let required_votes = self.required_num_votes();
        let ready: Vec<String> = self
            .find_contracts("Splice.DsoRules:VoteRequest")
            .into_iter()
            .filter_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                let vote_before = parse_micros(p["voteBefore"].as_str()?).ok()?;
                let target_eff = p["targetEffectiveAt"]
                    .as_str()
                    .and_then(|s| parse_micros(s).ok());
                let votes = p["votes"].as_array().map(|a| a.len()).unwrap_or(0) as i64;
                let yays = p["votes"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter(|v| v[1]["accept"].as_bool() == Some(true))
                            .count() as i64
                    })
                    .unwrap_or(0);
                let ready_now = match target_eff {
                    Some(eff) => self.now_micros >= eff || self.now_micros >= vote_before,
                    None => {
                        yays >= required_votes
                            || votes >= required_votes
                            || self.now_micros >= vote_before
                    }
                };
                if ready_now {
                    Some(c.contract_id.clone())
                } else {
                    None
                }
            })
            .collect();

        for req_cid in ready {
            match self.close_vote_request(&req_cid, None) {
                Ok(_) => report.vote_requests_closed += 1,
                Err(e) => report.errors.push(format!("close vote {req_cid}: {e}")),
            }
        }
    }
}
