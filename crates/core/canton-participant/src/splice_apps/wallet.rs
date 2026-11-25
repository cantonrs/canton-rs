//! Wallet operations: transfer preapprovals, taps, balances, transfer offers, traffic purchases and history.

use lf_eval::typed_json::format_timestamp_trimmed;
use serde_json::{json, Value as Json};

use super::util::{dedup_actors, event_touches_party, normalize_decimal_10};
use super::{
    SpliceAppError, SpliceAppRuntime, TrafficTrackingEntry, TrafficTrackingSpec,
    TrafficTrackingState, TransferTrackingEntry, TransferTrackingSpec, TransferTrackingState,
};

impl SpliceAppRuntime {
    /// Create a `TransferPreapproval` through `AmuletRules_CreateTransferPreapproval`.
    pub fn create_transfer_preapproval(
        &mut self,
        receiver: &str,
        provider_opt: Option<&str>,
        expires_in_micros: i64,
    ) -> Result<String, SpliceAppError> {
        if expires_in_micros <= 0 {
            return Err(SpliceAppError::BadRequest(
                "expires_in_micros must be positive".into(),
            ));
        }
        let receiver_party = self.resolve_or_allocate_party(receiver)?;
        let provider_party = match provider_opt {
            Some(p) => self.resolve_or_allocate_party(p)?,
            None => self.config.validator_party.clone(),
        };
        let amulet_rules_cid = self.require_singleton_cid("Splice.AmuletRules:AmuletRules")?;
        let context = self.payment_transfer_context(&amulet_rules_cid, &receiver_party)?;
        let expires_at =
            format_timestamp_trimmed(self.now_micros.saturating_add(expires_in_micros));
        let created_at = format_timestamp_trimmed(self.now_micros);

        let actors = dedup_actors(&[receiver_party.as_str(), provider_party.as_str()]);
        let outcome = self.run_exercise(
            &actors,
            &amulet_rules_cid,
            "AmuletRules_CreateTransferPreapproval",
            &json!({
                "context": context,
                "inputs": [],
                "receiver": receiver_party,
                "provider": provider_party,
                "expiresAt": expires_at,
                "expectedDso": self.config.dso_party,
                "optCreatedAt": created_at,
            }),
            "validator-create-transfer-preapproval",
        )?;
        outcome.result["transferPreapprovalCid"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| SpliceAppError::Internal("missing transferPreapprovalCid result".into()))
    }

    pub fn lookup_transfer_preapproval(&self, receiver: &str) -> Result<Json, SpliceAppError> {
        let receiver_party = self.resolve_party_or_user(receiver);
        for c in self.find_contracts("Splice.AmuletRules:TransferPreapproval") {
            let payload = self.encoded_payload(c)?;
            if payload["receiver"].as_str() == Some(receiver_party.as_str()) {
                return Ok(json!({
                    "transfer_preapproval": self.contract_json(c)?,
                }));
            }
        }
        Err(SpliceAppError::NotFound(format!(
            "TransferPreapproval for {receiver_party} not found"
        )))
    }

    pub fn cancel_transfer_preapproval(
        &mut self,
        receiver: &str,
        actor_opt: Option<&str>,
    ) -> Result<(), SpliceAppError> {
        let receiver_party = self.resolve_party_or_user(receiver);
        let (cid, provider_party) = self
            .find_contracts("Splice.AmuletRules:TransferPreapproval")
            .into_iter()
            .find_map(|c| {
                let p = self.encoded_payload(c).ok()?;
                if p["receiver"].as_str() == Some(receiver_party.as_str()) {
                    Some((c.contract_id.clone(), p["provider"].as_str()?.to_string()))
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                SpliceAppError::NotFound(format!(
                    "TransferPreapproval for {receiver_party} not found"
                ))
            })?;
        let actor = match actor_opt {
            Some(a) => self.resolve_or_allocate_party(a)?,
            None => provider_party,
        };
        self.run_exercise(
            &[actor.as_str()],
            &cid,
            "TransferPreapproval_Cancel",
            &json!({ "p": actor }),
            "validator-cancel-transfer-preapproval",
        )?;
        Ok(())
    }

    pub fn external_party_balance(&self, party_or_user: &str) -> Result<Json, SpliceAppError> {
        let party = self.resolve_party_or_user(party_or_user);
        let summary = self.compute_balance_summary(&party)?;
        Ok(json!({
            "party_id": party,
            "total_unlocked_coin": summary.unlocked_qty,
            "total_locked_coin": summary.locked_qty,
            "total_coin_holdings": summary.total_initial,
            "accumulated_holding_fees_unlocked": summary.unlocked_fees,
            "accumulated_holding_fees_locked": summary.locked_fees,
            "accumulated_holding_fees_total": summary.total_fees,
            "total_available_coin": summary.unlocked_qty,
            "computed_as_of_round": summary.round,
        }))
    }

    /// Mint DevNet Amulets for `party_or_user` using `AmuletRules_DevNet_Tap`.
    pub fn tap(&mut self, party_or_user: &str, amount: &str) -> Result<String, SpliceAppError> {
        let party = self.resolve_or_allocate_party(party_or_user)?;
        let formatted_amount = normalize_decimal_10(amount)?;
        let amulet_rules_cid = self.require_singleton_cid("Splice.AmuletRules:AmuletRules")?;
        let (_, open_round_cid) = self.latest_active_open_round()?;
        let outcome = self.run_exercise(
            &[party.as_str()],
            &amulet_rules_cid,
            "AmuletRules_DevNet_Tap",
            &json!({
                "receiver": party,
                "amount": formatted_amount,
                "openRound": open_round_cid,
            }),
            "wallet-tap",
        )?;
        outcome.result["amuletSum"]["amulet"]
            .as_str()
            .or_else(|| outcome.created.first().map(|c| c.contract_id.as_str()))
            .map(String::from)
            .ok_or_else(|| SpliceAppError::Internal("tap produced no amulet contract id".into()))
    }

    pub fn get_balance(&self, party_or_user: &str) -> Result<Json, SpliceAppError> {
        let party = self.resolve_party_or_user(party_or_user);
        let summary = self.compute_balance_summary(&party)?;
        Ok(json!({
            "round": summary.round,
            "effective_unlocked_qty": summary.unlocked_qty,
            "effective_locked_qty": summary.locked_qty,
            "total_holding_fees": summary.total_fees,
        }))
    }

    pub fn list_amulets(&self, party_or_user: &str) -> Result<Json, SpliceAppError> {
        let party = self.resolve_party_or_user(party_or_user);
        let mut amulets = Vec::new();
        for c in self.find_contracts("Splice.Amulet:Amulet") {
            let p = self.encoded_payload(c)?;
            if p["owner"].as_str() == Some(party.as_str()) {
                amulets.push(json!({
                    "contract": self.contract_json(c)?,
                    "round": self.latest_open_round_number().unwrap_or(0),
                }));
            }
        }
        let mut locked = Vec::new();
        for c in self.find_contracts("Splice.Amulet:LockedAmulet") {
            let p = self.encoded_payload(c)?;
            if p["amulet"]["owner"].as_str() == Some(party.as_str()) {
                locked.push(json!({
                    "contract": self.contract_json(c)?,
                    "round": self.latest_open_round_number().unwrap_or(0),
                }));
            }
        }
        Ok(json!({
            "amulets": amulets,
            "locked_amulets": locked,
        }))
    }

    /// Create a P2P `TransferOffer` with `tracking_id` idempotency (`200` on identical retry, `409` on mismatch).
    pub fn create_transfer_offer(
        &mut self,
        sender_or_user: &str,
        receiver_or_user: &str,
        amount: &str,
        description: &str,
        expires_at_micros: i64,
        tracking_id: &str,
    ) -> Result<String, SpliceAppError> {
        let sender = self.resolve_or_allocate_party(sender_or_user)?;
        let receiver = self.resolve_or_allocate_party(receiver_or_user)?;
        let normalized_amount = normalize_decimal_10(amount)?;
        let spec = TransferTrackingSpec {
            sender: sender.clone(),
            receiver: receiver.clone(),
            amount: normalized_amount.clone(),
            description: description.to_string(),
        };

        if let Some(existing) = self.transfer_tracking.get(tracking_id) {
            if existing.spec != spec {
                return Err(SpliceAppError::Conflict(format!(
                    "transfer offer with tracking_id '{tracking_id}' already exists with different parameters"
                )));
            }
            return match &existing.state {
                TransferTrackingState::Created { offer_cid, .. } => Ok(offer_cid.clone()),
                _ => Err(SpliceAppError::Conflict(format!(
                    "transfer offer with tracking_id '{tracking_id}' already exists"
                ))),
            };
        }

        let expires_at = format_timestamp_trimmed(expires_at_micros);
        let amount_json = json!({
            "amount": normalized_amount,
            "unit": "AmuletUnit",
        });

        let outcome = if let Some((install_cid, validator_party)) =
            self.find_wallet_install_for_party(&sender)
        {
            self.run_exercise(
                &[validator_party.as_str()],
                &install_cid,
                "WalletAppInstall_CreateTransferOffer",
                &json!({
                    "receiver": receiver,
                    "amount": amount_json,
                    "description": description,
                    "expiresAt": expires_at,
                    "trackingId": tracking_id,
                }),
                "wallet-create-transfer-offer",
            )?
        } else {
            self.run_create(
                &[sender.as_str()],
                "Splice.Wallet.TransferOffer:TransferOffer",
                &json!({
                    "sender": sender,
                    "receiver": receiver,
                    "dso": self.config.dso_party,
                    "amount": amount_json,
                    "description": description,
                    "expiresAt": expires_at,
                    "trackingId": tracking_id,
                }),
                "wallet-create-transfer-offer",
            )?
        };

        let offer_cid = outcome
            .result
            .get("transferOffer")
            .or_else(|| outcome.result.get("contract_id"))
            .and_then(|v| v.as_str())
            .or_else(|| outcome.created.first().map(|c| c.contract_id.as_str()))
            .map(String::from)
            .ok_or_else(|| SpliceAppError::Internal("missing TransferOffer contract id".into()))?;

        self.transfer_tracking.insert(
            tracking_id.to_string(),
            TransferTrackingEntry {
                spec,
                state: TransferTrackingState::Created {
                    offer_cid: offer_cid.clone(),
                    tx_id: outcome.update_id,
                },
            },
        );
        Ok(offer_cid)
    }

    pub fn list_transfer_offers(&self, party_or_user: &str) -> Result<Vec<Json>, SpliceAppError> {
        let party = self.resolve_party_or_user(party_or_user);
        let mut offers = Vec::new();
        for c in self.find_contracts("Splice.Wallet.TransferOffer:TransferOffer") {
            let p = self.encoded_payload(c)?;
            if p["sender"].as_str() == Some(party.as_str())
                || p["receiver"].as_str() == Some(party.as_str())
            {
                offers.push(self.contract_json(c)?);
            }
        }
        Ok(offers)
    }

    pub fn accept_transfer_offer(
        &mut self,
        party_or_user: &str,
        offer_cid: &str,
    ) -> Result<String, SpliceAppError> {
        let receiver = self.resolve_or_allocate_party(party_or_user)?;
        let outcome = if let Some((install_cid, validator_party)) =
            self.find_wallet_install_for_party(&receiver)
        {
            self.run_exercise(
                &[validator_party.as_str()],
                &install_cid,
                "WalletAppInstall_TransferOffer_Accept",
                &json!({ "cid": offer_cid }),
                "wallet-accept-transfer-offer",
            )?
        } else {
            self.run_exercise(
                &[receiver.as_str()],
                offer_cid,
                "TransferOffer_Accept",
                &json!({}),
                "wallet-accept-transfer-offer",
            )?
        };
        let accepted_cid = outcome.result["acceptedTransferOffer"]
            .as_str()
            .or_else(|| outcome.created.first().map(|c| c.contract_id.as_str()))
            .map(String::from)
            .ok_or_else(|| {
                SpliceAppError::Internal("missing AcceptedTransferOffer contract id".into())
            })?;

        self.update_transfer_tracking_by_cid(
            offer_cid,
            TransferTrackingState::Accepted {
                accepted_cid: accepted_cid.clone(),
                tx_id: outcome.update_id,
            },
        );
        Ok(accepted_cid)
    }

    pub fn reject_transfer_offer(
        &mut self,
        party_or_user: &str,
        offer_cid: &str,
    ) -> Result<(), SpliceAppError> {
        let receiver = self.resolve_or_allocate_party(party_or_user)?;
        let outcome = if let Some((install_cid, validator_party)) =
            self.find_wallet_install_for_party(&receiver)
        {
            self.run_exercise(
                &[validator_party.as_str()],
                &install_cid,
                "WalletAppInstall_TransferOffer_Reject",
                &json!({ "cid": offer_cid }),
                "wallet-reject-transfer-offer",
            )?
        } else {
            self.run_exercise(
                &[receiver.as_str()],
                offer_cid,
                "TransferOffer_Reject",
                &json!({}),
                "wallet-reject-transfer-offer",
            )?
        };
        if let Some(tid) = outcome.result["trackingInfo"]["trackingId"].as_str() {
            if let Some(entry) = self.transfer_tracking.get_mut(tid) {
                entry.state = TransferTrackingState::Failed {
                    failure_kind: "rejected".into(),
                    withdrawn_reason: None,
                };
            }
        }
        Ok(())
    }

    pub fn withdraw_transfer_offer(
        &mut self,
        party_or_user: &str,
        offer_cid: &str,
        reason: &str,
    ) -> Result<(), SpliceAppError> {
        let sender = self.resolve_or_allocate_party(party_or_user)?;
        let outcome = if let Some((install_cid, validator_party)) =
            self.find_wallet_install_for_party(&sender)
        {
            self.run_exercise(
                &[validator_party.as_str()],
                &install_cid,
                "WalletAppInstall_TransferOffer_Withdraw",
                &json!({ "cid": offer_cid, "reason": reason }),
                "wallet-withdraw-transfer-offer",
            )?
        } else {
            self.run_exercise(
                &[sender.as_str()],
                offer_cid,
                "TransferOffer_Withdraw",
                &json!({ "reason": reason }),
                "wallet-withdraw-transfer-offer",
            )?
        };
        if let Some(tid) = outcome.result["trackingInfo"]["trackingId"].as_str() {
            if let Some(entry) = self.transfer_tracking.get_mut(tid) {
                entry.state = TransferTrackingState::Failed {
                    failure_kind: "withdrawn".into(),
                    withdrawn_reason: Some(reason.to_string()),
                };
            }
        }
        Ok(())
    }

    pub fn transfer_offer_status(&self, tracking_id: &str) -> Result<Json, SpliceAppError> {
        let entry = self.transfer_tracking.get(tracking_id).ok_or_else(|| {
            SpliceAppError::NotFound(format!(
                "transfer offer tracking_id {tracking_id} not found"
            ))
        })?;
        Ok(match &entry.state {
            TransferTrackingState::Created { offer_cid, tx_id } => json!({
                "status": "created",
                "transaction_id": tx_id,
                "contract_id": offer_cid,
            }),
            TransferTrackingState::Accepted {
                accepted_cid,
                tx_id,
            } => json!({
                "status": "accepted",
                "transaction_id": tx_id,
                "contract_id": accepted_cid,
            }),
            TransferTrackingState::Completed { amulet_cid, tx_id } => json!({
                "status": "completed",
                "transaction_id": tx_id,
                "contract_id": amulet_cid,
            }),
            TransferTrackingState::Failed {
                failure_kind,
                withdrawn_reason,
            } => {
                let mut body = json!({
                    "status": "failed",
                    "failure_kind": failure_kind,
                });
                if let Some(reason) = withdrawn_reason {
                    body["withdrawn_reason"] = Json::String(reason.clone());
                }
                body
            }
        })
    }

    /// Create a `BuyTrafficRequest` with `tracking_id` idempotency (`200` on match, `409` on conflict).
    pub fn create_buy_traffic_request(
        &mut self,
        buyer_or_user: &str,
        receiving_validator_party_or_user: &str,
        synchronizer_id: Option<&str>,
        migration_id: i64,
        traffic_amount: i64,
        expires_at_micros: i64,
        tracking_id: &str,
    ) -> Result<String, SpliceAppError> {
        let buyer = self.resolve_or_allocate_party(buyer_or_user)?;
        let validator = self.resolve_or_allocate_party(receiving_validator_party_or_user)?;
        let member_id = format!("PAR::{validator}");
        let sync_id = synchronizer_id
            .unwrap_or(&self.config.synchronizer_id)
            .to_string();
        let spec = TrafficTrackingSpec {
            buyer: buyer.clone(),
            member_id: member_id.clone(),
            synchronizer_id: sync_id.clone(),
            traffic_amount,
        };

        if let Some(existing) = self.traffic_tracking.get(tracking_id) {
            if existing.spec != spec {
                return Err(SpliceAppError::Conflict(format!(
                    "buy traffic request with tracking_id '{tracking_id}' already exists with different parameters"
                )));
            }
            return match &existing.state {
                TrafficTrackingState::Created { request_cid } => Ok(request_cid.clone()),
                _ => Err(SpliceAppError::Conflict(format!(
                    "buy traffic request with tracking_id '{tracking_id}' already exists"
                ))),
            };
        }

        let expires_at = format_timestamp_trimmed(expires_at_micros);
        let outcome = if let Some((install_cid, validator_party)) =
            self.find_wallet_install_for_party(&buyer)
        {
            self.run_exercise(
                &[validator_party.as_str()],
                &install_cid,
                "WalletAppInstall_CreateBuyTrafficRequest",
                &json!({
                    "memberId": member_id,
                    "synchronizerId": sync_id,
                    "migrationId": migration_id.to_string(),
                    "trafficAmount": traffic_amount.to_string(),
                    "expiresAt": expires_at,
                    "trackingId": tracking_id,
                }),
                "wallet-create-buy-traffic",
            )?
        } else {
            self.run_create(
                &[buyer.as_str()],
                "Splice.Wallet.BuyTrafficRequest:BuyTrafficRequest",
                &json!({
                    "dso": self.config.dso_party,
                    "endUserParty": buyer,
                    "expiresAt": expires_at,
                    "trackingId": tracking_id,
                    "trafficAmount": traffic_amount.to_string(),
                    "memberId": member_id,
                    "synchronizerId": sync_id,
                    "migrationId": migration_id.to_string(),
                }),
                "wallet-create-buy-traffic",
            )?
        };

        let request_cid = outcome
            .result
            .get("buyTrafficRequest")
            .or_else(|| outcome.result.get("contract_id"))
            .and_then(|v| v.as_str())
            .or_else(|| outcome.created.first().map(|c| c.contract_id.as_str()))
            .map(String::from)
            .ok_or_else(|| {
                SpliceAppError::Internal("missing BuyTrafficRequest contract id".into())
            })?;

        self.traffic_tracking.insert(
            tracking_id.to_string(),
            TrafficTrackingEntry {
                spec,
                state: TrafficTrackingState::Created {
                    request_cid: request_cid.clone(),
                },
            },
        );
        Ok(request_cid)
    }

    pub fn buy_traffic_status(&self, tracking_id: &str) -> Result<Json, SpliceAppError> {
        let entry = self.traffic_tracking.get(tracking_id).ok_or_else(|| {
            SpliceAppError::NotFound(format!("buy traffic tracking_id {tracking_id} not found"))
        })?;
        Ok(match &entry.state {
            TrafficTrackingState::Created { request_cid } => json!({
                "status": "created",
                "contract_id": request_cid,
            }),
            TrafficTrackingState::Completed { traffic_cid, tx_id } => json!({
                "status": "completed",
                "transaction_id": tx_id,
                "purchased_traffic_contract_id": traffic_cid,
            }),
            TrafficTrackingState::Failed {
                failure_reason,
                rejection_reason,
            } => {
                let mut body = json!({
                    "status": "failed",
                    "failure_reason": failure_reason,
                });
                if let Some(reason) = rejection_reason {
                    body["rejection_reason"] = Json::String(reason.clone());
                }
                body
            }
        })
    }

    pub fn list_transactions(
        &self,
        party_or_user: &str,
        begin_after_id: Option<&str>,
        page_size: usize,
    ) -> Result<Vec<Json>, SpliceAppError> {
        let party = self.resolve_party_or_user(party_or_user);
        let limit = page_size.clamp(1, 1000);
        let mut items = Vec::new();
        let mut past_cursor = begin_after_id.is_none();

        for tx in &self.updates {
            let root_ids = tx["root_event_ids"].as_array().cloned().unwrap_or_default();
            for root_id_val in root_ids {
                let Some(event_id) = root_id_val.as_str() else {
                    continue;
                };
                if !past_cursor {
                    if Some(event_id) == begin_after_id {
                        past_cursor = true;
                    }
                    continue;
                }
                let Some(ev) = tx["events_by_id"].get(event_id) else {
                    continue;
                };
                if !event_touches_party(ev, &party) {
                    continue;
                }
                let template_id = ev["template_id"].as_str().unwrap_or_default();
                let choice = ev["choice"].as_str().unwrap_or_default();
                let tx_type = if choice == "AmuletRules_DevNet_Tap" {
                    "balance_change"
                } else if choice.contains("Transfer") || choice.contains("BuyTraffic") {
                    "transfer"
                } else {
                    "notification"
                };
                items.push(json!({
                    "transaction_type": tx_type,
                    "transaction_subtype": {
                        "template_id": template_id,
                        "choice": choice,
                    },
                    "event_id": event_id,
                    "update_id": tx["update_id"],
                    "date": tx["effective_at"],
                }));
                if items.len() >= limit {
                    return Ok(items);
                }
            }
        }
        Ok(items)
    }
}

pub(super) struct BalanceSummary {
    pub(super) round: i64,
    pub(super) unlocked_qty: String,
    pub(super) locked_qty: String,
    pub(super) total_initial: String,
    pub(super) unlocked_fees: String,
    pub(super) locked_fees: String,
    pub(super) total_fees: String,
}
