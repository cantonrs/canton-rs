//! DSO and SV operations: bootstrap, validator onboarding, votes, users and validator liveness.

use std::collections::BTreeSet;

use lf_eval::typed_json::format_timestamp_trimmed;
use serde_json::{json, Value as Json};

use super::util::{dedup_actors, sha256_hex};
use super::{
    OnboardingSecret, SpliceAppError, SpliceAppRuntime, SpliceBootstrapConfig, VotedOutcome,
};

impl SpliceAppRuntime {
    /// Bootstrap `DsoBootstrap` -> `DsoRules`, `AmuletRules`, initial `OpenMiningRound`s (0..2),
    /// `AnsRules`, `SvRewardState`, `AmuletPriceVote`, and onboard the primary SV validator.
    pub fn bootstrap(&mut self) -> Result<Json, SpliceAppError> {
        self.sync_ledger()?;
        if let Some(dso_rules) = self.find_contracts("Splice.DsoRules:DsoRules").first() {
            return Ok(json!({
                "already_bootstrapped": true,
                "dso_rules_contract_id": dso_rules.contract_id,
                "dso_party": self.config.dso_party,
            }));
        }

        let payload = self.dso_bootstrap_payload();
        let dso = self.config.dso_party.clone();
        let created = self.run_create(
            &[dso.as_str()],
            "Splice.DsoBootstrap:DsoBootstrap",
            &payload,
            "dso-bootstrap-create",
        )?;
        let bootstrap_cid = created
            .created
            .first()
            .ok_or_else(|| SpliceAppError::Internal("bootstrap create yielded no contract".into()))?
            .contract_id
            .clone();

        let _boot = self.run_exercise(
            &[dso.as_str()],
            &bootstrap_cid,
            "DsoBootstrap_Bootstrap",
            &json!({}),
            "dso-bootstrap",
        )?;

        // Onboard the validator operator party as a licensed validator on DevNet.
        let dso_rules_cid = self.require_singleton_cid("Splice.DsoRules:DsoRules")?;
        let sv = self.config.sv_party.clone();
        let validator = self.config.validator_party.clone();
        let onboard = self.run_exercise(
            &[sv.as_str()],
            &dso_rules_cid,
            "DsoRules_OnboardValidator",
            &json!({
                "sponsor": sv,
                "validator": validator,
                "version": "0.10.1",
                "contactPoint": "",
            }),
            "onboard-primary-validator",
        )?;

        Ok(json!({
            "already_bootstrapped": false,
            "dso_party": dso,
            "sv_party": self.config.sv_party,
            "validator_party": self.config.validator_party,
            "dso_rules_contract_id": dso_rules_cid,
            "validator_license_contract_id": onboard.result["validatorLicense"],
        }))
    }

    /// Generate a one-time secret for onboarding a validator via `POST /v0/onboard/validator`.
    pub fn prepare_validator_onboarding(
        &mut self,
        expires_in_secs: u64,
        party_hint: Option<String>,
        secret_override: Option<String>,
    ) -> Result<String, SpliceAppError> {
        let _ = self.require_singleton_cid("Splice.DsoRules:DsoRules")?;
        let expires_in_secs = expires_in_secs.max(1);
        let secret = secret_override.unwrap_or_else(|| {
            let seed = format!(
                "validator-secret:{}:{}",
                self.now_micros,
                self.onboarding_secrets.len()
            );
            sha256_hex(&seed)[..32].to_string()
        });
        let expires_at_micros = self
            .now_micros
            .saturating_add((expires_in_secs as i64).saturating_mul(1_000_000));
        self.onboarding_secrets.insert(
            secret.clone(),
            OnboardingSecret {
                expires_at_micros,
                party_hint,
                used: false,
            },
        );
        Ok(secret)
    }

    /// Redeem an onboarding secret to issue a `ValidatorLicense` on `DsoRules`.
    pub fn onboard_validator(
        &mut self,
        party_id: &str,
        secret: &str,
        version: &str,
        contact_point: &str,
    ) -> Result<String, SpliceAppError> {
        let now = self.now_micros;
        let entry = self
            .onboarding_secrets
            .get_mut(secret)
            .ok_or_else(|| SpliceAppError::Unauthorized("invalid onboarding secret".into()))?;
        if entry.used {
            return Err(SpliceAppError::Unauthorized(
                "onboarding secret has already been used".into(),
            ));
        }
        if now >= entry.expires_at_micros {
            return Err(SpliceAppError::Unauthorized(
                "onboarding secret has expired".into(),
            ));
        }
        if let Some(hint) = &entry.party_hint {
            if !party_id.starts_with(hint) {
                return Err(SpliceAppError::BadRequest(format!(
                    "party_id {party_id} does not match expected hint {hint}"
                )));
            }
        }
        entry.used = true;

        let dso_rules_cid = self.require_singleton_cid("Splice.DsoRules:DsoRules")?;
        let sv = self.config.sv_party.clone();
        let validator = self.resolve_or_allocate_party(party_id)?;
        let outcome = self.run_exercise(
            &[sv.as_str()],
            &dso_rules_cid,
            "DsoRules_OnboardValidator",
            &json!({
                "sponsor": sv,
                "validator": validator,
                "version": version,
                "contactPoint": contact_point,
            }),
            "onboard-validator",
        )?;
        outcome.result["validatorLicense"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| SpliceAppError::Internal("missing validatorLicense result".into()))
    }

    /// Submit a `DsoRules_RequestVote` governance proposal.
    pub fn request_vote(
        &mut self,
        requester: Option<&str>,
        action: Json,
        reason_url: &str,
        reason_body: &str,
        vote_request_timeout_micros: Option<i64>,
        target_effective_at: Option<&str>,
    ) -> Result<String, SpliceAppError> {
        let dso_rules_cid = self.require_singleton_cid("Splice.DsoRules:DsoRules")?;
        let sv = match requester {
            Some(r) => self.resolve_or_allocate_party(r)?,
            None => self.config.sv_party.clone(),
        };
        let timeout = vote_request_timeout_micros.map(|m| json!({ "microseconds": m.to_string() }));
        let arg = json!({
            "requester": sv,
            "action": action,
            "reason": {
                "url": reason_url,
                "body": reason_body,
            },
            "voteRequestTimeout": timeout,
            "targetEffectiveAt": target_effective_at,
        });
        let outcome = self.run_exercise(
            &[sv.as_str()],
            &dso_rules_cid,
            "DsoRules_RequestVote",
            &arg,
            "sv-request-vote",
        )?;
        outcome.result["voteRequest"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| SpliceAppError::Internal("missing voteRequest result".into()))
    }

    pub fn list_vote_requests(&self) -> Result<Vec<Json>, SpliceAppError> {
        self.find_contracts("Splice.DsoRules:VoteRequest")
            .into_iter()
            .map(|c| self.contract_json(c))
            .collect()
    }

    pub fn lookup_vote_request(&self, request_cid: &str) -> Result<Json, SpliceAppError> {
        if let Some(c) = self.active_contracts.get(request_cid) {
            if c.template_id == "Splice.DsoRules:VoteRequest" {
                return self.contract_json(c);
            }
        }
        if let Some(voted) = self.vote_outcomes.get(request_cid) {
            return Ok(json!({
                "request_cid": voted.request_cid,
                "update_id": voted.update_id,
                "outcome": voted.outcome,
            }));
        }
        Err(SpliceAppError::NotFound(format!(
            "vote request {request_cid} not found"
        )))
    }

    /// Cast or update an SV vote via `DsoRules_CastVote`.
    pub fn cast_vote(
        &mut self,
        request_cid: &str,
        sv: Option<&str>,
        accept: bool,
        reason_url: &str,
        reason_body: &str,
    ) -> Result<String, SpliceAppError> {
        let dso_rules_cid = self.require_singleton_cid("Splice.DsoRules:DsoRules")?;
        let voter = match sv {
            Some(s) => self.resolve_or_allocate_party(s)?,
            None => self.config.sv_party.clone(),
        };
        let outcome = self.run_exercise(
            &[voter.as_str()],
            &dso_rules_cid,
            "DsoRules_CastVote",
            &json!({
                "requestCid": request_cid,
                "vote": {
                    "sv": voter,
                    "accept": accept,
                    "reason": {
                        "url": reason_url,
                        "body": reason_body,
                    },
                    "optCastAt": Json::Null,
                },
            }),
            "sv-cast-vote",
        )?;
        outcome.result["voteRequest"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| SpliceAppError::Internal("missing voteRequest result".into()))
    }

    /// Close a `VoteRequest` via `DsoRules_CloseVoteRequest`.
    pub fn close_vote_request(
        &mut self,
        request_cid: &str,
        sv: Option<&str>,
    ) -> Result<Json, SpliceAppError> {
        let dso_rules_cid = self.require_singleton_cid("Splice.DsoRules:DsoRules")?;
        let amulet_rules_cid = self.require_singleton_cid("Splice.AmuletRules:AmuletRules")?;
        let closer = match sv {
            Some(s) => self.resolve_or_allocate_party(s)?,
            None => self.config.sv_party.clone(),
        };
        let outcome = self.run_exercise(
            &[closer.as_str()],
            &dso_rules_cid,
            "DsoRules_CloseVoteRequest",
            &json!({
                "requestCid": request_cid,
                "amuletRulesCid": amulet_rules_cid,
                "sv": closer,
            }),
            "sv-close-vote",
        )?;
        let close_outcome = outcome.result["outcome"].clone();
        self.vote_outcomes.insert(
            request_cid.to_string(),
            VotedOutcome {
                request_cid: request_cid.to_string(),
                update_id: outcome.update_id.clone(),
                outcome: close_outcome,
            },
        );
        Ok(outcome.result)
    }

    /// Onboard an end-user onto this validator by creating `WalletAppInstall` and `ValidatorRight`.
    pub fn register_user(
        &mut self,
        user_name: &str,
        user_party_opt: Option<&str>,
    ) -> Result<String, SpliceAppError> {
        if user_name.trim().is_empty() {
            return Err(SpliceAppError::BadRequest(
                "username must not be empty".into(),
            ));
        }
        if let Some(existing) = self.find_wallet_install_by_user(user_name) {
            let payload = self.encoded_payload(existing)?;
            if let Some(party) = payload["endUserParty"].as_str() {
                return Ok(party.to_string());
            }
        }
        let dso_party = self.config.dso_party.clone();
        let validator_party = self.config.validator_party.clone();
        let end_user_party = match user_party_opt.filter(|s| !s.is_empty()) {
            Some(p) => self.resolve_or_allocate_party(p)?,
            None => self.resolve_or_allocate_party(user_name)?,
        };

        let actors = dedup_actors(&[end_user_party.as_str(), validator_party.as_str()]);
        let _ = self.run_create(
            &actors,
            "Splice.Wallet.Install:WalletAppInstall",
            &json!({
                "dsoParty": dso_party,
                "validatorParty": validator_party,
                "endUserName": user_name,
                "endUserParty": end_user_party,
            }),
            "validator-register-user",
        )?;

        let _ = self.run_create(
            &actors,
            "Splice.Amulet:ValidatorRight",
            &json!({
                "dso": dso_party,
                "user": end_user_party,
                "validator": validator_party,
            }),
            "validator-create-right",
        )?;

        Ok(end_user_party)
    }

    pub fn list_users(&self) -> Result<Vec<String>, SpliceAppError> {
        let mut names = BTreeSet::new();
        for install in self.find_contracts("Splice.Wallet.Install:WalletAppInstall") {
            let payload = self.encoded_payload(install)?;
            if let Some(name) = payload["endUserName"].as_str() {
                names.insert(name.to_string());
            }
        }
        Ok(names.into_iter().collect())
    }

    pub fn offboard_user(&mut self, user_name: &str) -> Result<(), SpliceAppError> {
        let (install_cid, user_party, validator_party) = self
            .find_wallet_install_by_user(user_name)
            .and_then(|c| {
                let p = self.encoded_payload(c).ok()?;
                Some((
                    c.contract_id.clone(),
                    p["endUserParty"].as_str()?.to_string(),
                    p["validatorParty"].as_str()?.to_string(),
                ))
            })
            .ok_or_else(|| SpliceAppError::NotFound(format!("user {user_name} not found")))?;

        let actors = dedup_actors(&[user_party.as_str(), validator_party.as_str()]);
        self.run_exercise(
            &actors,
            &install_cid,
            "Archive",
            &json!({}),
            "validator-offboard-user",
        )?;
        Ok(())
    }

    /// Record validator liveness for the validator's active `ValidatorLicense` on the current open round.
    pub fn record_validator_liveness(
        &mut self,
        validator_party_opt: Option<&str>,
    ) -> Result<String, SpliceAppError> {
        let validator = match validator_party_opt {
            Some(v) => self.resolve_or_allocate_party(v)?,
            None => self.config.validator_party.clone(),
        };
        let (license_cid, last_recorded) =
            self.find_validator_license(&validator).ok_or_else(|| {
                SpliceAppError::NotFound(format!("ValidatorLicense for {validator} not found"))
            })?;
        let open_round_cid = self
            .next_open_round_for_min_num(last_recorded.map(|r| r + 1).unwrap_or(0))?
            .ok_or_else(|| {
                SpliceAppError::Conflict(format!(
                    "no open mining round newer than {:?}",
                    last_recorded
                ))
            })?;

        let outcome = self.run_exercise(
            &[validator.as_str()],
            &license_cid,
            "ValidatorLicense_RecordValidatorLivenessActivity",
            &json!({ "openRoundCid": open_round_cid }),
            "validator-record-liveness",
        )?;
        Ok(outcome.result["validatorLicense"]
            .as_str()
            .unwrap_or(&license_cid)
            .to_string())
    }
}

/// The `DsoBootstrap` create argument of the Splice 0.10.1 DAR for `config` at the ledger time `now_micros`.
///
/// [CANTON-NOTE: SEMANTICS] Pure JSON (the Daml-LF JSON encoding), so the same value feeds the in-process engine of `SpliceAppRuntime`
/// and a `CreateCommand` sent to a Ledger API JSON v2 server (`canton-rs splice bootstrap-ledger`).
pub fn dso_bootstrap_payload(config: &SpliceBootstrapConfig, now_micros: i64) -> Json {
    let sync = &config.synchronizer_id;
    let tick = json!({ "microseconds": config.round_tick_duration_micros.to_string() });
    let sync_avail = format_timestamp_trimmed(now_micros);
    let amulet_config = json!({
        "transferConfig": {
            "createFee": { "fee": "0E-10" },
            "holdingFee": { "rate": "0.0000190259" },
            "transferFee": { "initialRate": "0E-10", "steps": [] },
            "lockHolderFee": { "fee": "0E-10" },
            "extraFeaturedAppRewardAmount": "1.0000000000",
            "maxNumInputs": "100",
            "maxNumOutputs": "100",
            "maxNumLockHolders": "50",
            "tokenStandardMaxTTL": null
        },
        "issuanceCurve": {
            "initialValue": {
                "amuletToIssuePerYear": "40000000000.0000000000",
                "validatorRewardPercentage": "0.0500000000",
                "appRewardPercentage": "0.1500000000",
                "validatorRewardCap": "0.2000000000",
                "featuredAppRewardCap": "100.0000000000",
                "unfeaturedAppRewardCap": "0.6000000000",
                "optValidatorFaucetCap": "2.8500000000",
                "optDevelopmentFundPercentage": null
            },
            "futureValues": []
        },
        "decentralizedSynchronizer": {
            "requiredSynchronizers": { "map": [[sync, {}]] },
            "activeSynchronizer": sync,
            "fees": {
                "baseRateTrafficLimits": {
                    "burstAmount": "400000",
                    "burstWindow": { "microseconds": "1200000000" }
                },
                "extraTrafficPrice": "16.6700000000",
                "readVsWriteScalingFactor": "4",
                "minTopupAmount": "200000"
            }
        },
        "tickDuration": tick,
        "packageConfig": {
            "amulet": "0.1.25",
            "amuletNameService": "0.1.26",
            "dsoGovernance": "0.1.31",
            "validatorLifecycle": "0.1.10",
            "wallet": "0.1.26",
            "walletPayments": "0.1.25"
        },
        "transferPreapprovalFee": null,
        "featuredAppActivityMarkerAmount": "1.0000000000",
        "optDevelopmentFundManager": null,
        "externalPartyConfigStateTickDuration": null,
        "rewardConfig": {
            "mintingVersion": "RewardVersion_FeaturedAppMarkers",
            "dryRunVersion": "RewardVersion_TrafficBasedAppRewards",
            "batchSize": "100",
            "rewardCouponTimeToLive": { "microseconds": "129600000000" },
            "appRewardCouponThreshold": "0.5000000000",
            "extraFeaturedAssetActivityWeight": null,
            "maxExtraFeaturedAssetActivityWeightPerAsset": null,
            "dsoAppActivityWeight": null
        },
        "transferPreapprovalBaseDuration": null,
        "developmentFundManagerBlacklist": null,
        "minDevelopmentFundMintingDelay": null,
        "amuletSwitchOverTimes": null,
        "governanceLockConfig": null
    });
    json!({
        "dso": config.dso_party,
        "sv1Party": config.sv_party,
        "sv1Name": config.sv_name,
        "sv1RewardWeight": "10000",
        "sv1ParticipantId": config.sv_participant_id,
        "sv1SynchronizerNodes": [[sync, {
            "cometBft": {
                "nodes": [],
                "governanceKeys": [],
                "sequencingKeys": []
            },
            "sequencer": null,
            "mediator": { "mediatorId": config.mediator_id },
            "scan": { "publicUrl": config.scan_url },
            "legacySequencerConfig": null,
            "sequencerIdentity": {
                "sequencerId": config.sequencer_id,
                "availableAfter": sync_avail
            },
            "physicalSynchronizers": [["0", {
                "sequencer": { "url": config.sequencer_url }
            }]]
        }]],
        "round0Duration": tick,
        "amuletConfig": amulet_config,
        "amuletPrice": config.amulet_price,
        "ansRulesConfig": {
            "renewalDuration": { "microseconds": "2592000000000" },
            "entryLifetime": { "microseconds": "7776000000000" },
            "entryFee": "1.0000000000",
            "descriptionPrefix": "ANS entry: "
        },
        "config": {
            "numUnclaimedRewardsThreshold": "10",
            "numMemberTrafficContractsThreshold": "5",
            "actionConfirmationTimeout": { "microseconds": "3600000000" },
            "svOnboardingRequestTimeout": { "microseconds": "3600000000" },
            "svOnboardingConfirmedTimeout": { "microseconds": "3600000000" },
            "voteRequestTimeout": { "microseconds": "604800000000" },
            "dsoDelegateInactiveTimeout": { "microseconds": "70000000" },
            "synchronizerNodeConfigLimits": {
                "cometBft": {
                    "maxNumCometBftNodes": "2",
                    "maxNumGovernanceKeys": "2",
                    "maxNumSequencingKeys": "2",
                    "maxNodeIdLength": "50",
                    "maxPubKeyLength": "256"
                }
            },
            "maxTextLength": "1024",
            "decentralizedSynchronizer": {
                "synchronizers": [[sync, {
                    "state": "DS_Operational",
                    "cometBftGenesisJson": "canton-rs devnet",
                    "acsCommitmentReconciliationInterval": "1800"
                }]],
                "lastSynchronizerId": sync,
                "activeSynchronizerId": sync
            },
            "nextScheduledSynchronizerUpgrade": null,
            "voteCooldownTime": null,
            "nextScheduledLogicalSynchronizerUpgrade": null,
            "svOperationsSwitchOverTimes": {
                "no-featured-app-choice-context": "0001-01-01T00:00:00Z"
            }
        },
        "initialTrafficState": [
            [config.mediator_id, { "consumedTraffic": "0" }],
            [config.sv_participant_id, { "consumedTraffic": "0" }]
        ],
        "isDevNet": true,
        "initialRound": "0"
    })
}
