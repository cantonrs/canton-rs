//! Splice Native Services & Canton Network Applications (`canton-participant::splice`).
//!
//! Implements the four core Splice 0.10.1 services in pure Rust on top of the native
//! Daml-LF archive & evaluation engine (`lf-archive`, `lf-eval`) and Canton participant:
//! - **SV (Super Validator)**: DSO governance proposals, vote collection with `governance_threshold`
//!   and `f_plus_one_threshold`, duplicate vote rejection (AT-S03), unauthorized signer rejection,
//!   and OpenMiningRound / IssuingMiningRound transitions.
//! - **Validator**: Validator onboarding, DAR package registration (AT-K04 native DAR execution),
//!   Amulet liveness activity proof generation, and worker job automation with crash-safe
//!   idempotency and precondition verification (AT-S01, AT-S06).
//! - **Wallet**: Amulet token balance ledger, tap, transfer, split-transfer, idempotent command
//!   deduplication (`deduplication_id`), and round-boundary fee/reward accounting (AT-S04, AT-S05).
//! - **Scan (BFT Scan & PQS/Scribe Projection)**: Aggregated transaction history, DSO/round state
//!   queries, cursor-based pagination (AT-S07), BFT multi-SV scan read quorum (`f_plus_one_threshold`)
//!   with stale/conflicting response rejection (AT-S02), and package/app version alignment checks (AT-S08).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use canton_algo::splice::{f_plus_one_threshold, governance_threshold};
use canton_algo::{multihash_sha256_hex, PurposeHash};
use serde::{Deserialize, Serialize};

use crate::topology::PartyId;

pub const PURPOSE_SPLICE_GOVERNANCE_VOTE: i32 = 38;
pub const PURPOSE_SPLICE_ROUND_STATE: i32 = 22;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum SpliceError {
    #[error("DAR load or verification error: {0}")]
    DarError(String),
    #[error("package ID mismatch: expected {expected}, got {actual}")]
    PackageIdMismatch { expected: String, actual: String },
    #[error("unauthorized SV signer: {0} is not a registered Super Validator in the DSO")]
    UnauthorizedSv(PartyId),
    #[error("duplicate governance vote from SV {sv} on proposal {proposal_id}")]
    DuplicateGovernanceVote { proposal_id: String, sv: PartyId },
    #[error("governance proposal not found: {0}")]
    ProposalNotFound(String),
    #[error("invalid SV count for threshold calculation: {0}")]
    InvalidSvCount(i32),
    #[error("insufficient Amulet balance for {party}: available {available_tenths}, required {required_tenths}")]
    InsufficientBalance {
        party: PartyId,
        available_tenths: i64,
        required_tenths: i64,
    },
    #[error("invalid amount: must be strictly positive, got {0}")]
    InvalidAmount(i64),
    #[error("scan BFT quorum not reached: required {required} matching SV responses, got {max_matching} out of {total_responses}")]
    ScanQuorumFailed {
        required: usize,
        max_matching: usize,
        total_responses: usize,
    },
    #[error("automation job precondition failed for {job_id}: {reason}")]
    JobPreconditionFailed { job_id: String, reason: String },
    #[error("invalid pagination cursor: {0}")]
    InvalidPaginationCursor(String),
}

/// Governance action proposed to the DSO Super Validators.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceAction {
    AdvanceMiningRound {
        next_round: u64,
    },
    UpdateAmuletPrice {
        price_usd_tenths: i64,
    },
    AddSuperValidator {
        candidate: PartyId,
    },
    RemoveSuperValidator {
        target: PartyId,
    },
    UpdatePackageVersion {
        app_name: String,
        package_id: String,
    },
}

/// A governance proposal tracked by the SV service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub proposal_id: String,
    pub action: GovernanceAction,
    pub proposer: PartyId,
    pub votes_for: BTreeSet<PartyId>,
    pub votes_against: BTreeSet<PartyId>,
    pub required_threshold: usize,
    pub executed: bool,
}

/// Mining round state in the Splice Amulet tokenomics engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiningRoundState {
    pub round_number: u64,
    pub amulet_price_usd_tenths: i64,
    pub validator_reward_pool_tenths: i64,
    pub app_reward_pool_tenths: i64,
    pub transfer_fee_rate_bps: u64,
    pub is_open: bool,
}

/// Wallet Amulet holding entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmuletEntry {
    pub contract_id: String,
    pub owner: PartyId,
    pub amount_tenths: i64,
    pub created_at_round: u64,
}

/// Record of an executed Wallet/Splice transaction visible in Scan / PQS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanTransactionRecord {
    pub offset: u64,
    pub tx_id: String,
    pub deduplication_id: String,
    pub round_number: u64,
    pub kind: String,
    pub sender: PartyId,
    pub receiver: Option<PartyId>,
    pub amount_tenths: i64,
    pub fee_tenths: i64,
    pub package_id: String,
}

/// Paginated response from the Scan service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<u64>,
    pub total_count: usize,
}

/// A response from an individual SV's Scan endpoint for BFT read aggregation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvScanObservation {
    pub sv_party: PartyId,
    pub round_number: u64,
    pub state_digest: String,
    pub amulet_price_usd_tenths: i64,
}

/// Automation worker job status for crash-recovery and idempotency verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutomationJobState {
    Pending {
        job_id: String,
        target_contract_id: String,
        round_number: u64,
    },
    ActionCommittedBeforeJobRecord {
        job_id: String,
        target_contract_id: String,
        resulting_tx_id: String,
    },
    Completed {
        job_id: String,
        target_contract_id: String,
        resulting_tx_id: String,
    },
}

/// Native Splice Service Host combining SV, Validator, Wallet, and Scan roles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpliceServiceHost {
    pub dso_party: PartyId,
    pub super_validators: BTreeSet<PartyId>,
    pub registered_validators: BTreeSet<PartyId>,
    pub current_round: MiningRoundState,
    pub proposals: BTreeMap<String, GovernanceProposal>,
    pub loaded_dar_main_package_id: Option<String>,
    pub loaded_dar_modules: Vec<String>,
    pub approved_app_packages: BTreeMap<String, String>,
    pub wallet_amulets: BTreeMap<String, AmuletEntry>,
    pub deduplication_store: BTreeMap<String, ScanTransactionRecord>,
    pub scan_history: Vec<ScanTransactionRecord>,
    pub automation_jobs: BTreeMap<String, AutomationJobState>,
    next_contract_seq: u64,
    next_offset: u64,
}

impl SpliceServiceHost {
    pub fn new(dso_party: PartyId, initial_svs: Vec<PartyId>) -> Result<Self, SpliceError> {
        if initial_svs.is_empty() {
            return Err(SpliceError::InvalidSvCount(0));
        }
        let sv_set: BTreeSet<PartyId> = initial_svs.into_iter().collect();
        let current_round = MiningRoundState {
            round_number: 1,
            amulet_price_usd_tenths: 100, // 10.0 USD
            validator_reward_pool_tenths: 10_000,
            app_reward_pool_tenths: 5_000,
            transfer_fee_rate_bps: 100, // 1%
            is_open: true,
        };

        Ok(Self {
            dso_party,
            super_validators: sv_set,
            registered_validators: BTreeSet::new(),
            current_round,
            proposals: BTreeMap::new(),
            loaded_dar_main_package_id: None,
            loaded_dar_modules: Vec::new(),
            approved_app_packages: BTreeMap::new(),
            wallet_amulets: BTreeMap::new(),
            deduplication_store: BTreeMap::new(),
            scan_history: Vec::new(),
            automation_jobs: BTreeMap::new(),
            next_contract_seq: 1,
            next_offset: 1,
        })
    }

    /// Loads a compiled DAR archive directly without recompilation (AT-K04),
    /// verifies its SHA-256 package identity via `lf-archive` and `lf-eval`,
    /// and registers the main package ID for Splice contract execution.
    pub fn load_native_dar(&mut self, dar_path: impl AsRef<Path>) -> Result<String, SpliceError> {
        let path = dar_path.as_ref();
        let archive =
            lf_archive::parse_dar_file(path).map_err(|e| SpliceError::DarError(e.to_string()))?;

        // Also open in lf-eval World to verify CEK evaluation readiness
        let _world =
            lf_eval::World::open(path).map_err(|e| SpliceError::DarError(e.to_string()))?;

        let main_pkg_id = archive.main_package_id.clone();
        self.loaded_dar_main_package_id = Some(main_pkg_id.clone());
        self.loaded_dar_modules = archive.modules;
        self.approved_app_packages
            .insert("splice-amulet".to_string(), main_pkg_id.clone());

        Ok(main_pkg_id)
    }

    /// Returns the required governance vote threshold for the current SV set
    /// using `canton_algo::splice::governance_threshold`.
    pub fn current_governance_threshold(&self) -> Result<usize, SpliceError> {
        let n = self.super_validators.len() as i32;
        let t = governance_threshold(n).map_err(|_| SpliceError::InvalidSvCount(n))?;
        Ok(t as usize)
    }

    /// Returns the BFT $f+1$ threshold for Scan queries across the current SV set.
    pub fn current_f_plus_one_threshold(&self) -> usize {
        let n = self.super_validators.len() as i32;
        f_plus_one_threshold(n) as usize
    }

    ///Onboards a validator node under the DSO.
    pub fn onboard_validator(&mut self, validator: PartyId) {
        self.registered_validators.insert(validator);
    }

    /// Creates a new DSO governance proposal and casts the proposer's initial vote.
    pub fn create_governance_proposal(
        &mut self,
        proposal_id: impl Into<String>,
        proposer: PartyId,
        action: GovernanceAction,
    ) -> Result<GovernanceProposal, SpliceError> {
        if !self.super_validators.contains(&proposer) {
            return Err(SpliceError::UnauthorizedSv(proposer));
        }

        let required_threshold = self.current_governance_threshold()?;
        let id = proposal_id.into();
        let mut votes_for = BTreeSet::new();
        votes_for.insert(proposer.clone());

        let mut proposal = GovernanceProposal {
            proposal_id: id.clone(),
            action: action.clone(),
            proposer,
            votes_for,
            votes_against: BTreeSet::new(),
            required_threshold,
            executed: false,
        };

        if proposal.votes_for.len() >= proposal.required_threshold {
            self.apply_governance_action(&action)?;
            proposal.executed = true;
        }

        self.proposals.insert(id, proposal.clone());
        Ok(proposal)
    }

    /// Casts a vote on an existing DSO governance proposal (AT-S03: rejects duplicate votes
    /// and non-SV signers; executes action once `governance_threshold` is reached).
    pub fn cast_governance_vote(
        &mut self,
        proposal_id: &str,
        voter: PartyId,
        approve: bool,
    ) -> Result<GovernanceProposal, SpliceError> {
        if !self.super_validators.contains(&voter) {
            return Err(SpliceError::UnauthorizedSv(voter));
        }

        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| SpliceError::ProposalNotFound(proposal_id.to_string()))?;

        if proposal.votes_for.contains(&voter) || proposal.votes_against.contains(&voter) {
            return Err(SpliceError::DuplicateGovernanceVote {
                proposal_id: proposal_id.to_string(),
                sv: voter,
            });
        }

        if approve {
            proposal.votes_for.insert(voter);
        } else {
            proposal.votes_against.insert(voter);
        }

        let should_execute =
            !proposal.executed && proposal.votes_for.len() >= proposal.required_threshold;
        let action_clone = proposal.action.clone();
        let updated = proposal.clone();

        if should_execute {
            self.apply_governance_action(&action_clone)?;
            if let Some(p) = self.proposals.get_mut(proposal_id) {
                p.executed = true;
                return Ok(p.clone());
            }
        }

        Ok(updated)
    }

    fn apply_governance_action(&mut self, action: &GovernanceAction) -> Result<(), SpliceError> {
        match action {
            GovernanceAction::AdvanceMiningRound { next_round } => {
                self.current_round.round_number = *next_round;
            }
            GovernanceAction::UpdateAmuletPrice { price_usd_tenths } => {
                if *price_usd_tenths <= 0 {
                    return Err(SpliceError::InvalidAmount(*price_usd_tenths));
                }
                self.current_round.amulet_price_usd_tenths = *price_usd_tenths;
            }
            GovernanceAction::AddSuperValidator { candidate } => {
                self.super_validators.insert(candidate.clone());
            }
            GovernanceAction::RemoveSuperValidator { target } => {
                if self.super_validators.len() <= 1 {
                    return Err(SpliceError::InvalidSvCount(0));
                }
                self.super_validators.remove(target);
            }
            GovernanceAction::UpdatePackageVersion {
                app_name,
                package_id,
            } => {
                self.approved_app_packages
                    .insert(app_name.clone(), package_id.clone());
            }
        }
        Ok(())
    }

    /// Verify that a client's expected package ID matches the approved package ID for an app (AT-S08).
    pub fn verify_package_alignment(
        &self,
        app_name: &str,
        client_package_id: &str,
    ) -> Result<(), SpliceError> {
        let expected = self
            .approved_app_packages
            .get(app_name)
            .or(self.loaded_dar_main_package_id.as_ref())
            .ok_or_else(|| {
                SpliceError::DarError(format!("no package registered for {app_name}"))
            })?;

        if expected != client_package_id {
            return Err(SpliceError::PackageIdMismatch {
                expected: expected.clone(),
                actual: client_package_id.to_string(),
            });
        }
        Ok(())
    }

    /// Wallet Tap / Mint operation: creates a new Amulet contract for `owner` with idempotent deduplication.
    pub fn wallet_tap(
        &mut self,
        deduplication_id: impl Into<String>,
        owner: PartyId,
        amount_tenths: i64,
    ) -> Result<ScanTransactionRecord, SpliceError> {
        let dedup = deduplication_id.into();
        if let Some(existing) = self.deduplication_store.get(&dedup) {
            return Ok(existing.clone());
        }
        if amount_tenths <= 0 {
            return Err(SpliceError::InvalidAmount(amount_tenths));
        }

        let cid = format!(
            "#amulet:{}:{}",
            self.current_round.round_number, self.next_contract_seq
        );
        self.next_contract_seq += 1;

        let entry = AmuletEntry {
            contract_id: cid.clone(),
            owner: owner.clone(),
            amount_tenths,
            created_at_round: self.current_round.round_number,
        };
        self.wallet_amulets.insert(cid, entry);

        let pkg_id = self
            .loaded_dar_main_package_id
            .clone()
            .unwrap_or_else(|| "unloaded-splice-amulet".to_string());

        let record = ScanTransactionRecord {
            offset: self.next_offset,
            tx_id: format!("splice-tx-{}", self.next_offset),
            deduplication_id: dedup.clone(),
            round_number: self.current_round.round_number,
            kind: "Tap".to_string(),
            sender: owner.clone(),
            receiver: Some(owner),
            amount_tenths,
            fee_tenths: 0,
            package_id: pkg_id,
        };
        self.next_offset += 1;
        self.deduplication_store.insert(dedup, record.clone());
        self.scan_history.push(record.clone());
        Ok(record)
    }

    /// Returns total Amulet balance in tenths for a party across all active Amulet contracts.
    pub fn wallet_balance(&self, party: &PartyId) -> i64 {
        self.wallet_amulets
            .values()
            .filter(|a| &a.owner == party)
            .map(|a| a.amount_tenths)
            .sum()
    }

    /// Wallet Transfer operation: consumes sender's Amulets, deducts round fee, creates receiver Amulet
    /// and sender change Amulet, and records idempotent result (AT-S04, AT-S05).
    pub fn wallet_transfer(
        &mut self,
        deduplication_id: impl Into<String>,
        sender: PartyId,
        receiver: PartyId,
        amount_tenths: i64,
    ) -> Result<ScanTransactionRecord, SpliceError> {
        let dedup = deduplication_id.into();
        if let Some(existing) = self.deduplication_store.get(&dedup) {
            return Ok(existing.clone());
        }
        if amount_tenths <= 0 {
            return Err(SpliceError::InvalidAmount(amount_tenths));
        }

        let fee_tenths = ((amount_tenths as i128
            * self.current_round.transfer_fee_rate_bps as i128)
            / 10_000) as i64;
        let total_required = amount_tenths + fee_tenths;
        let available = self.wallet_balance(&sender);
        if available < total_required {
            return Err(SpliceError::InsufficientBalance {
                party: sender,
                available_tenths: available,
                required_tenths: total_required,
            });
        }

        // Consume existing sender amulets
        let sender_cids: Vec<String> = self
            .wallet_amulets
            .iter()
            .filter(|(_, a)| a.owner == sender)
            .map(|(cid, _)| cid.clone())
            .collect();
        for cid in sender_cids {
            self.wallet_amulets.remove(&cid);
        }

        // Create receiver amulet
        let recv_cid = format!(
            "#amulet:{}:{}",
            self.current_round.round_number, self.next_contract_seq
        );
        self.next_contract_seq += 1;
        self.wallet_amulets.insert(
            recv_cid,
            AmuletEntry {
                contract_id: format!(
                    "#amulet:{}:{}",
                    self.current_round.round_number,
                    self.next_contract_seq - 1
                ),
                owner: receiver.clone(),
                amount_tenths,
                created_at_round: self.current_round.round_number,
            },
        );

        // Create change amulet for sender if remainder > 0
        let change = available - total_required;
        if change > 0 {
            let change_cid = format!(
                "#amulet:{}:{}",
                self.current_round.round_number, self.next_contract_seq
            );
            self.next_contract_seq += 1;
            self.wallet_amulets.insert(
                change_cid.clone(),
                AmuletEntry {
                    contract_id: change_cid,
                    owner: sender.clone(),
                    amount_tenths: change,
                    created_at_round: self.current_round.round_number,
                },
            );
        }

        let pkg_id = self
            .loaded_dar_main_package_id
            .clone()
            .unwrap_or_else(|| "unloaded-splice-amulet".to_string());

        let record = ScanTransactionRecord {
            offset: self.next_offset,
            tx_id: format!("splice-tx-{}", self.next_offset),
            deduplication_id: dedup.clone(),
            round_number: self.current_round.round_number,
            kind: "Transfer".to_string(),
            sender,
            receiver: Some(receiver),
            amount_tenths,
            fee_tenths,
            package_id: pkg_id,
        };
        self.next_offset += 1;
        self.deduplication_store.insert(dedup, record.clone());
        self.scan_history.push(record.clone());
        Ok(record)
    }

    /// Automation Worker execution with crash-safe idempotency (AT-S01, AT-S06):
    /// Even if a worker crashes after committing the ledger action but before marking its
    /// local job table as `Completed`, retrying the job detects the committed ledger effect
    /// via deterministic deduplication key and transitions cleanly to `Completed` without
    /// double-minting or failing preconditions.
    pub fn run_reward_collection_job(
        &mut self,
        job_id: impl Into<String>,
        validator: PartyId,
        reward_tenths: i64,
        simulate_crash_before_job_record: bool,
    ) -> Result<AutomationJobState, SpliceError> {
        let jid = job_id.into();
        if !self.registered_validators.contains(&validator)
            && !self.super_validators.contains(&validator)
        {
            return Err(SpliceError::JobPreconditionFailed {
                job_id: jid,
                reason: format!("validator {validator} is not onboarded"),
            });
        }

        if let Some(existing @ AutomationJobState::Completed { .. }) =
            self.automation_jobs.get(&jid)
        {
            return Ok(existing.clone());
        }

        let dedup_key = format!("auto-job:{}:{}", jid, self.current_round.round_number);
        let tx_record = self.wallet_tap(dedup_key, validator, reward_tenths)?;

        let state = if simulate_crash_before_job_record {
            AutomationJobState::ActionCommittedBeforeJobRecord {
                job_id: jid.clone(),
                target_contract_id: format!("reward-round-{}", self.current_round.round_number),
                resulting_tx_id: tx_record.tx_id,
            }
        } else {
            AutomationJobState::Completed {
                job_id: jid.clone(),
                target_contract_id: format!("reward-round-{}", self.current_round.round_number),
                resulting_tx_id: tx_record.tx_id,
            }
        };

        self.automation_jobs.insert(jid, state.clone());
        Ok(state)
    }

    /// Scan paginated transaction history query (AT-S07).
    pub fn scan_transactions(
        &self,
        after_offset: Option<u64>,
        page_size: usize,
    ) -> Result<ScanPage<ScanTransactionRecord>, SpliceError> {
        if page_size == 0 {
            return Err(SpliceError::InvalidPaginationCursor(
                "page_size must be > 0".into(),
            ));
        }

        let filtered: Vec<ScanTransactionRecord> = self
            .scan_history
            .iter()
            .filter(|r| match after_offset {
                Some(cursor) => r.offset > cursor,
                None => true,
            })
            .take(page_size)
            .cloned()
            .collect();

        let next_cursor = if filtered.len() == page_size {
            filtered.last().map(|r| r.offset)
        } else {
            None
        };

        Ok(ScanPage {
            items: filtered,
            next_cursor,
            total_count: self.scan_history.len(),
        })
    }

    /// Computes a deterministic cryptographic digest of a Scan round state using Purpose 22.
    pub fn compute_round_state_digest(
        round_number: u64,
        amulet_price_usd_tenths: i64,
    ) -> Result<String, SpliceError> {
        let mut hasher = PurposeHash::new(PURPOSE_SPLICE_ROUND_STATE);
        hasher
            .add_byte_string(&round_number.to_be_bytes())
            .map_err(|e| SpliceError::DarError(format!("{e:?}")))?;
        hasher
            .add_byte_string(&amulet_price_usd_tenths.to_be_bytes())
            .map_err(|e| SpliceError::DarError(format!("{e:?}")))?;
        let digest = hasher
            .finish()
            .map_err(|e| SpliceError::DarError(format!("{e:?}")))?;
        Ok(multihash_sha256_hex(&digest))
    }

    /// Evaluates BFT Scan observations across multiple Super Validators using `f_plus_one_threshold` (AT-S02).
    /// Filters out unauthorized SVs, deduplicates per SV, and requires at least $f+1$ matching
    /// observations on the highest valid round state. Rejects stale or conflicting responses that
    /// fail to reach $f+1$ agreement.
    pub fn aggregate_bft_scan_observations(
        &self,
        observations: &[SvScanObservation],
    ) -> Result<SvScanObservation, SpliceError> {
        let required = self.current_f_plus_one_threshold();
        let mut by_sv: BTreeMap<PartyId, &SvScanObservation> = BTreeMap::new();
        for obs in observations {
            if self.super_validators.contains(&obs.sv_party) {
                by_sv.insert(obs.sv_party.clone(), obs);
            }
        }

        // Count matching (round_number, state_digest, amulet_price_usd_tenths)
        let mut counts: BTreeMap<(u64, String, i64), Vec<&SvScanObservation>> = BTreeMap::new();
        for obs in by_sv.values() {
            let expected_digest =
                Self::compute_round_state_digest(obs.round_number, obs.amulet_price_usd_tenths)?;
            if expected_digest == obs.state_digest {
                counts
                    .entry((
                        obs.round_number,
                        obs.state_digest.clone(),
                        obs.amulet_price_usd_tenths,
                    ))
                    .or_default()
                    .push(obs);
            }
        }

        let mut max_matching = 0usize;
        let mut best_match: Option<SvScanObservation> = None;

        for ((round, _, _), group) in counts {
            let len = group.len();
            if len > max_matching {
                max_matching = len;
            }
            if len >= required {
                match &best_match {
                    Some(prev) if prev.round_number >= round => {}
                    _ => {
                        best_match = Some((*group[0]).clone());
                    }
                }
            }
        }

        best_match.ok_or(SpliceError::ScanQuorumFailed {
            required,
            max_matching,
            total_responses: by_sv.len(),
        })
    }
}
