//! Sample-template command ledger backed by `lf-eval` (`World` + `CekMachine`).
//!
//! Evaluates `AssetHolding`'s Daml-LF 2.1 `precond` (`ensure`), `signatories`,
//! `observers`, choice `controllers`, and choice `Update` bodies directly from
//! `contracts/target/sample-contract.dar`, and reproduces `daml script --ide-ledger`
//! party suffixes and V1 `SValueHash` contract IDs without scrubbing.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use crate::cek::{CekMachine, ExecutionStatus, HostResponse, Need};
use crate::engine::{ContractIdAllocator, NewContract};
use crate::{EvalError, UpdateHost, Value, World};

pub const PACKAGE: &str = "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2";
pub const PACKAGE_ID: &str = PACKAGE;

/// Deterministic party IDs allocated by `daml script --ide-ledger` for the
/// first three `allocateParty` calls (`"Bank"`, `"Owner"`, `"Auditor"`).
pub const BANK_PARTY: &str = "Bank-d4d95138";
pub const OWNER_PARTY: &str = "Owner-9b3970be";
pub const AUDITOR_PARTY: &str = "Auditor-4f1df03a";

/// `com.digitalasset.daml.lf.data.Time.Timestamp.MinValue` (`0001-01-01T00:00:00Z` in microseconds)
/// used by `IdeLedgerRunner` as the initial `submissionTime` / `preparationTime`.
pub const PREPARATION_TIME_MIN_MICROS: i64 = -62_135_596_800_000_000;

/// Deterministic party suffix generator reproducing `daml-script`'s
/// `ScriptF$.globalRandom = new java.util.Random(0L)` and `ConverterMethods.toPartyIdHint`.
#[derive(Clone, Debug)]
pub struct IdePartyAllocator {
    seed: u64,
}

impl Default for IdePartyAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl IdePartyAllocator {
    const MULTIPLIER: u64 = 0x5DEE_CE66D;
    const ADDEND: u64 = 0xB;
    const MASK: u64 = (1u64 << 48) - 1;

    /// Initializes `java.util.Random(0L)`.
    pub fn new() -> Self {
        Self::with_seed(0)
    }

    pub fn with_seed(initial_seed: i64) -> Self {
        Self {
            seed: ((initial_seed as u64) ^ Self::MULTIPLIER) & Self::MASK,
        }
    }

    fn next_bits(&mut self, bits: u32) -> i32 {
        self.seed = (self
            .seed
            .wrapping_mul(Self::MULTIPLIER)
            .wrapping_add(Self::ADDEND))
            & Self::MASK;
        (self.seed >> (48 - bits)) as i32
    }

    /// Reproduces `java.util.Random.nextLong()`.
    pub fn next_long(&mut self) -> i64 {
        let hi = i64::from(self.next_bits(32)) << 32;
        let lo = i64::from(self.next_bits(32));
        hi.wrapping_add(lo)
    }

    /// Reproduces `IdeLedgerClient.allocateParty(hint)`:
    /// `format!("{hint}-{:08x}", rand.nextLong() as i32)`.
    pub fn allocate_party(&mut self, hint: &str) -> String {
        let suffix = self.next_long() as u32;
        format!("{hint}-{suffix:08x}")
    }
}

fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let candidates = [
            PathBuf::from("contracts/target/sample-contract.dar"),
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../contracts/target/sample-contract.dar"),
        ];
        for path in &candidates {
            if path.exists() {
                return World::open(path).expect("open sample-contract.dar");
            }
        }
        panic!("contracts/target/sample-contract.dar not found");
    })
}

/// Returns the main package ID of the bundled `contracts/target/sample-contract.dar`.
pub fn sample_package_id() -> &'static str {
    world().main_package_id()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holding {
    pub bank: String,
    pub owner: String,
    pub auditor: String,
    pub symbol: String,
    pub tenths: i64,
}

impl Holding {
    pub fn new(
        bank: impl Into<String>,
        owner: impl Into<String>,
        auditor: impl Into<String>,
        symbol: impl Into<String>,
        tenths: i64,
    ) -> Self {
        Self {
            bank: bank.into(),
            owner: owner.into(),
            auditor: auditor.into(),
            symbol: symbol.into(),
            tenths,
        }
    }

    pub fn to_lf_record(&self) -> Value {
        Value::Record {
            tycon: Some("AssetHolding:AssetHolding".to_string()),
            fields: vec![
                ("bank".to_string(), Value::Party(self.bank.clone())),
                ("owner".to_string(), Value::Party(self.owner.clone())),
                ("auditor".to_string(), Value::Party(self.auditor.clone())),
                ("assetSymbol".to_string(), Value::Text(self.symbol.clone())),
                (
                    "amount".to_string(),
                    Value::Numeric {
                        coeff: i128::from(self.tenths) * 1_000_000_000,
                        scale: 10,
                    },
                ),
            ],
        }
    }

    pub fn from_lf_record(value: &Value) -> Result<Self, EvalError> {
        let fields = match value {
            Value::Record { fields, .. } | Value::Struct(fields) => fields,
            _ => return Err(EvalError::unsupported()),
        };
        let get_party = |name: &str| -> Result<String, EvalError> {
            fields
                .iter()
                .find_map(|(k, v)| match (k.as_str(), v) {
                    (k, Value::Party(p)) if k == name => Some(p.clone()),
                    _ => None,
                })
                .ok_or(EvalError::unsupported())
        };
        let symbol = fields
            .iter()
            .find_map(|(k, v)| match (k.as_str(), v) {
                ("assetSymbol", Value::Text(s)) => Some(s.clone()),
                _ => None,
            })
            .ok_or(EvalError::unsupported())?;
        let tenths = fields
            .iter()
            .find_map(|(k, v)| match (k.as_str(), v) {
                ("amount", Value::Numeric { coeff, scale: 10 }) => {
                    Some((*coeff / 1_000_000_000) as i64)
                }
                _ => None,
            })
            .ok_or(EvalError::unsupported())?;

        Ok(Self {
            bank: get_party("bank")?,
            owner: get_party("owner")?,
            auditor: get_party("auditor")?,
            symbol,
            tenths,
        })
    }
}

pub type Ledger = SingleContractLedger;

#[derive(Clone, Debug, Default)]
pub struct SingleContractLedger {
    pub contracts: Vec<Option<Holding>>,
    pub contract_ids: Vec<String>,
    pub submission_count: u64,
}

pub fn run_case(name: &str) -> Result<String, String> {
    match name {
        "createOk" => create_ok(),
        "ensureFail" => Ok(ensure(0)),
        "ensureNeg" => Ok(ensure(-10)),
        "authFail" => Ok(auth_create(10)),
        "authBeforeEnsure" => Ok(auth_create(0)),
        "transferOk" => transfer_ok(),
        "transferToAuditor" => Ok(transfer_to_auditor()),
        "transferByBank" => Ok(transfer_by_bank()),
        "transferSame" => Ok(transfer_same()),
        "transferKeeps" => transfer_keeps(),
        "assertKeeps" => assert_keeps(),
        "doubleConsume" => Ok(double_consume()),
        "settleOk" => settle_ok(),
        "settleByOwner" => Ok(settle_by_owner()),
        "observerTransfer" => Ok(observer_transfer()),
        "splitOk" => split_ok(),
        "splitToAuditor" => Ok(split_to_auditor()),
        "splitTooMuch" => Ok(split_amount(100, BANK_PARTY)),
        "splitZero" => Ok(split_amount(0, BANK_PARTY)),
        "splitSelf" => Ok(split_amount(10, OWNER_PARTY)),
        "ownerIsObserverTransfer" => owner_is_observer_transfer(),
        "ownerIsObserverReadAsOnly" => Ok(owner_is_observer_read_as_only()),
        "bankIsObserverSettle" => bank_is_observer_settle(),
        "auditorOnlySettle" => Ok(auditor_only_settle()),
        _ => Err(format!("unknown case {name}")),
    }
}

fn fresh() -> (SingleContractLedger, Holding) {
    let mut allocator = IdePartyAllocator::new();
    let bank = allocator.allocate_party("Bank");
    let owner = allocator.allocate_party("Owner");
    let auditor = allocator.allocate_party("Auditor");
    (
        SingleContractLedger::new(),
        Holding {
            bank,
            owner,
            auditor,
            symbol: "USD".to_string(),
            tenths: 100,
        },
    )
}

/// [CANTON-NOTE: SEMANTICS] Constructs a fresh SingleContractLedger and standard 10.0 USD AssetHolding.
pub fn fresh_sample_holding() -> (SingleContractLedger, Holding) {
    fresh()
}

fn create_ok() -> Result<String, String> {
    let (mut ledger, holding) = fresh();
    ledger.create(&[BANK_PARTY, OWNER_PARTY], holding)?;
    Ok(ledger.summary(OWNER_PARTY))
}

fn ensure(tenths: i64) -> String {
    let (mut ledger, mut holding) = fresh();
    holding.tenths = tenths;
    match ledger.create(&[BANK_PARTY, OWNER_PARTY], holding) {
        Ok(_) => "unexpected success".to_string(),
        Err(err) => err,
    }
}

fn auth_create(tenths: i64) -> String {
    let (mut ledger, mut holding) = fresh();
    holding.tenths = tenths;
    match ledger.create(&[OWNER_PARTY], holding) {
        Ok(_) => "unexpected success".to_string(),
        Err(err) => err,
    }
}

fn transfer_ok() -> Result<String, String> {
    let (mut ledger, holding) = fresh();
    let id = ledger.create(&[BANK_PARTY, OWNER_PARTY], holding)?;
    ledger.exercise_transfer(id, &[OWNER_PARTY], BANK_PARTY)?;
    Ok(format!(
        "{}|{}",
        ledger.summary(OWNER_PARTY),
        ledger.summary(BANK_PARTY)
    ))
}

fn transfer_to_auditor() -> String {
    let (mut ledger, holding) = fresh();
    let id = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], holding)
        .expect("create");
    ledger
        .exercise_transfer(id, &[OWNER_PARTY], AUDITOR_PARTY)
        .expect_err("auth")
}

fn transfer_by_bank() -> String {
    let (mut ledger, holding) = fresh();
    let id = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], holding)
        .expect("create");
    ledger
        .exercise_transfer(id, &[BANK_PARTY], AUDITOR_PARTY)
        .expect_err("controller")
}

fn transfer_same() -> String {
    let (mut ledger, holding) = fresh();
    let id = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], holding)
        .expect("create");
    ledger
        .exercise_transfer(id, &[OWNER_PARTY], OWNER_PARTY)
        .expect_err("assert")
}

fn transfer_keeps() -> Result<String, String> {
    let (mut ledger, holding) = fresh();
    let id = ledger.create(&[BANK_PARTY, OWNER_PARTY], holding)?;
    let _ = ledger.exercise_transfer(id, &[OWNER_PARTY], AUDITOR_PARTY);
    Ok(ledger.summary(OWNER_PARTY))
}

fn assert_keeps() -> Result<String, String> {
    let (mut ledger, holding) = fresh();
    let id = ledger.create(&[BANK_PARTY, OWNER_PARTY], holding)?;
    let _ = ledger.exercise_transfer(id, &[OWNER_PARTY], OWNER_PARTY);
    Ok(ledger.summary(OWNER_PARTY))
}

fn double_consume() -> String {
    let (mut ledger, holding) = fresh();
    let id = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], holding)
        .expect("create");
    ledger
        .exercise_transfer(id, &[OWNER_PARTY], BANK_PARTY)
        .expect("transfer");
    ledger
        .exercise_transfer(id, &[OWNER_PARTY], AUDITOR_PARTY)
        .expect_err("inactive")
}

fn settle_ok() -> Result<String, String> {
    let (mut ledger, holding) = fresh();
    let id = ledger.create(&[BANK_PARTY, OWNER_PARTY], holding)?;
    ledger.exercise_settle(id, &[BANK_PARTY])?;
    Ok(ledger.summary(OWNER_PARTY))
}

fn settle_by_owner() -> String {
    let (mut ledger, holding) = fresh();
    let id = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], holding)
        .expect("create");
    ledger
        .exercise_settle(id, &[OWNER_PARTY])
        .expect_err("controller")
}

fn observer_transfer() -> String {
    let (mut ledger, holding) = fresh();
    let id = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], holding)
        .expect("create");
    ledger
        .exercise_transfer(id, &[AUDITOR_PARTY], BANK_PARTY)
        .expect_err("observer")
}

/// [CANTON-NOTE: SEMANTICS] AT-U03: one party in two roles. The owner is also the auditor (an observer): the owner still is the
/// controller of Transfer, so the exercise succeeds.
fn owner_is_observer_transfer() -> Result<String, String> {
    let (mut ledger, mut holding) = fresh();
    holding.auditor = OWNER_PARTY.to_string();
    let id = ledger.create(&[BANK_PARTY, OWNER_PARTY], holding)?;
    ledger.exercise_transfer(id, &[OWNER_PARTY], BANK_PARTY)?;
    Ok(format!(
        "{}|{}",
        ledger.summary(OWNER_PARTY),
        ledger.summary(BANK_PARTY)
    ))
}

/// [CANTON-NOTE: SEMANTICS] `readAs` gives visibility, never authority: the bank acting with `readAs owner` is still not the
/// controller of Transfer. The model has no read-only party list, so the call passes only the acting party.
fn owner_is_observer_read_as_only() -> String {
    let (mut ledger, mut holding) = fresh();
    holding.auditor = OWNER_PARTY.to_string();
    let id = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], holding)
        .expect("create");
    ledger
        .exercise_transfer(id, &[BANK_PARTY], BANK_PARTY)
        .expect_err("readAs is not authority")
}

/// The bank is also the auditor: as the controller of Settle it may archive the holding.
fn bank_is_observer_settle() -> Result<String, String> {
    let (mut ledger, mut holding) = fresh();
    holding.auditor = BANK_PARTY.to_string();
    let id = ledger.create(&[BANK_PARTY, OWNER_PARTY], holding)?;
    ledger.exercise_settle(id, &[BANK_PARTY])?;
    Ok(ledger.summary(OWNER_PARTY))
}

/// The auditor, only an observer, cannot Settle.
fn auditor_only_settle() -> String {
    let (mut ledger, holding) = fresh();
    let id = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], holding)
        .expect("create");
    ledger
        .exercise_settle(id, &[AUDITOR_PARTY])
        .expect_err("observer")
}

fn split_ok() -> Result<String, String> {
    let (mut ledger, holding) = fresh();
    let id = ledger.create(&[BANK_PARTY, OWNER_PARTY], holding)?;
    ledger.exercise_split(id, &[OWNER_PARTY], 25, BANK_PARTY)?;
    Ok(format!(
        "{}|{}",
        ledger.summary(OWNER_PARTY),
        ledger.summary(BANK_PARTY)
    ))
}

fn split_to_auditor() -> String {
    let (mut ledger, holding) = fresh();
    let id = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], holding)
        .expect("create");
    ledger
        .exercise_split(id, &[OWNER_PARTY], 25, AUDITOR_PARTY)
        .expect_err("auth")
}

fn split_amount(tenths: i64, recipient: &str) -> String {
    let (mut ledger, holding) = fresh();
    let id = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], holding)
        .expect("create");
    ledger
        .exercise_split(id, &[OWNER_PARTY], tenths, recipient)
        .expect_err("assert")
}

struct ChoiceExecutionHost {
    cek: CekMachine,
    authorizers: Vec<String>,
    exercise_node_seed: [u8; 32],
    next_node_id: u32,
    next_child_idx: i32,
    created: Vec<(Holding, String)>,
}

impl UpdateHost for ChoiceExecutionHost {
    fn create_contract(&mut self, template_id: &str, payload: &Value) -> Result<String, EvalError> {
        let status = self.cek.request_need(Need::Create {
            template_id: template_id.to_string(),
            payload: payload.to_lf_value(),
        });
        let ExecutionStatus::NeedHost { token, .. } = status else {
            return Err(EvalError::Host("CEK did not emit NeedHost".to_string()));
        };

        let (module, template) = template_id
            .split_once(':')
            .unwrap_or(("AssetHolding", "AssetHolding"));

        match world().eval_template_precond(module, template, payload) {
            Ok(true) => {}
            Ok(false) => {
                let _ = self.cek.cancel(token);
                let holding = Holding::from_lf_record(payload)?;
                return Err(EvalError::UnhandledException {
                    error_id:
                        "UNHANDLED_EXCEPTION/DA.Exception.PreconditionFailed:PreconditionFailed"
                            .to_string(),
                    message: format!(
                        "Template precondition violated: AssetHolding {{bank = '{}', owner = '{}', auditor = '{}', assetSymbol = \"{}\", amount = {}}}",
                        holding.bank,
                        holding.owner,
                        holding.auditor,
                        holding.symbol,
                        show_amount(holding.tenths)
                    ),
                });
            }
            Err(err) => {
                let _ = self.cek.cancel(token);
                return Err(err);
            }
        }

        let signatories = world().eval_template_signatories(module, template, payload)?;
        let sig_refs: Vec<&str> = signatories.iter().map(String::as_str).collect();
        let auth_refs: Vec<&str> = self.authorizers.iter().map(String::as_str).collect();
        if !covers(&auth_refs, &sig_refs) {
            let _ = self.cek.cancel(token);
            return Err(EvalError::Host(auth(
                self.next_node_id,
                &sig_refs,
                &auth_refs,
            )));
        }

        let observers = world().eval_template_observers(module, template, payload)?;
        let mut stakeholders = signatories;
        stakeholders.extend(observers);

        let child_node_seed = derive_node_seed(&self.exercise_node_seed, self.next_child_idx);
        let discriminator = derive_contract_discriminator(
            &child_node_seed,
            PREPARATION_TIME_MIN_MICROS,
            &stakeholders,
        );
        let holding = Holding::from_lf_record(payload)?;
        let cid = compute_v1_contract_id_from_discriminator(&discriminator, payload);
        let cid_bytes = hex::decode(&cid).unwrap_or_else(|_| cid.as_bytes().to_vec());
        let resumed = self
            .cek
            .resume(token, HostResponse::Created(cid_bytes))
            .map_err(|e| EvalError::Host(e.to_string()))?;
        if !matches!(resumed, ExecutionStatus::Finished(_)) {
            return Err(EvalError::Host(
                "CEK did not finish Need::Create".to_string(),
            ));
        }

        self.next_node_id += 1;
        self.next_child_idx += 1;
        self.created.push((holding, cid.clone()));
        Ok(cid)
    }
}

impl SingleContractLedger {
    pub fn new() -> Self {
        Self {
            contracts: Vec::new(),
            contract_ids: Vec::new(),
            submission_count: 0,
        }
    }

    pub fn create(&mut self, act: &[&str], holding: Holding) -> Result<usize, String> {
        let tx_seed = derive_submission_seed(self.submission_count);
        self.submission_count += 1;
        let node_seed = derive_node_seed(&tx_seed, 0);

        let this_val = holding.to_lf_record();
        let mut cek = CekMachine::new(10_000);
        let ExecutionStatus::NeedHost { token, .. } = cek.request_need(Need::Create {
            template_id: "AssetHolding:AssetHolding".to_string(),
            payload: this_val.to_lf_value(),
        }) else {
            return Err("CEK failed to emit NeedHost".to_string());
        };

        match world().eval_template_precond("AssetHolding", "AssetHolding", &this_val) {
            Ok(true) => {}
            Ok(false) => {
                let _ = cek.cancel(token);
                return Err(failure_status(
                    "UNHANDLED_EXCEPTION/DA.Exception.PreconditionFailed:PreconditionFailed",
                    &format!(
                        "Template precondition violated: AssetHolding {{bank = '{}', owner = '{}', auditor = '{}', assetSymbol = \"{}\", amount = {}}}",
                        holding.bank,
                        holding.owner,
                        holding.auditor,
                        holding.symbol,
                        show_amount(holding.tenths)
                    ),
                ));
            }
            Err(EvalError::UnhandledException { error_id, message }) => {
                let _ = cek.cancel(token);
                return Err(failure_status(&error_id, &message));
            }
            Err(err) => {
                let _ = cek.cancel(token);
                return Err(err.to_string());
            }
        }

        let signatories = world()
            .eval_template_signatories("AssetHolding", "AssetHolding", &this_val)
            .map_err(|e| e.to_string())?;
        let required: Vec<&str> = signatories.iter().map(String::as_str).collect();
        if !covers(act, &required) {
            let _ = cek.cancel(token);
            return Err(auth(0, &required, act));
        }

        let observers = world()
            .eval_template_observers("AssetHolding", "AssetHolding", &this_val)
            .map_err(|e| e.to_string())?;
        let mut stakeholders = signatories;
        stakeholders.extend(observers);

        let discriminator =
            derive_contract_discriminator(&node_seed, PREPARATION_TIME_MIN_MICROS, &stakeholders);
        let cid = compute_v1_contract_id_from_discriminator(&discriminator, &this_val);
        let cid_bytes = hex::decode(&cid).unwrap_or_else(|_| cid.as_bytes().to_vec());
        cek.resume(token, HostResponse::Created(cid_bytes))
            .map_err(|e| e.to_string())?;

        self.contracts.push(Some(holding));
        self.contract_ids.push(cid);
        Ok(self.contracts.len() - 1)
    }

    pub fn exercise_transfer(
        &mut self,
        id: usize,
        act: &[&str],
        new_owner: &str,
    ) -> Result<usize, String> {
        let arg_val = Value::Record {
            tycon: Some("AssetHolding:Transfer".to_string()),
            fields: vec![("newOwner".to_string(), Value::Party(new_owner.to_string()))],
        };
        let created = self.exercise_choice(id, act, "Transfer", &arg_val)?;
        created
            .first()
            .copied()
            .ok_or_else(|| "Transfer did not create a contract".to_string())
    }

    pub fn exercise_settle(&mut self, id: usize, act: &[&str]) -> Result<(), String> {
        let arg_val = Value::Record {
            tycon: Some("AssetHolding:Settle".to_string()),
            fields: Vec::new(),
        };
        let _ = self.exercise_choice(id, act, "Settle", &arg_val)?;
        Ok(())
    }

    pub fn exercise_split(
        &mut self,
        id: usize,
        act: &[&str],
        transfer: i64,
        recipient: &str,
    ) -> Result<(usize, usize), String> {
        let arg_val = Value::Record {
            tycon: Some("AssetHolding:SplitTransfer".to_string()),
            fields: vec![
                (
                    "transferAmount".to_string(),
                    Value::Numeric {
                        coeff: i128::from(transfer) * 1_000_000_000,
                        scale: 10,
                    },
                ),
                ("recipient".to_string(), Value::Party(recipient.to_string())),
            ],
        };
        let created = self.exercise_choice(id, act, "SplitTransfer", &arg_val)?;
        if created.len() != 2 {
            return Err(format!(
                "SplitTransfer expected 2 created contracts, got {}",
                created.len()
            ));
        }
        Ok((created[0], created[1]))
    }

    fn exercise_choice(
        &mut self,
        id: usize,
        act: &[&str],
        choice_name: &str,
        arg_val: &Value,
    ) -> Result<Vec<usize>, String> {
        let holding = self.fetch(id)?;
        let tx_seed = derive_submission_seed(self.submission_count);
        self.submission_count += 1;
        let exercise_node_seed = derive_node_seed(&tx_seed, 0);

        let self_cid = self.contract_id(id);
        let this_val = holding.to_lf_record();

        let controllers = world()
            .eval_choice_controllers(
                "AssetHolding",
                "AssetHolding",
                choice_name,
                &this_val,
                arg_val,
            )
            .map_err(|e| e.to_string())?;
        let controller_refs: Vec<&str> = controllers.iter().map(String::as_str).collect();
        if !covers(act, &controller_refs) {
            return Err(auth(0, &controller_refs, act));
        }

        let signatories = world()
            .eval_template_signatories("AssetHolding", "AssetHolding", &this_val)
            .map_err(|e| e.to_string())?;
        let mut authorizers = signatories;
        for c in controllers {
            if !authorizers.contains(&c) {
                authorizers.push(c);
            }
        }

        let mut host = ChoiceExecutionHost {
            cek: CekMachine::new(10_000),
            authorizers,
            exercise_node_seed,
            next_node_id: 1,
            next_child_idx: 0,
            created: Vec::new(),
        };

        match world().eval_choice_update(
            "AssetHolding",
            "AssetHolding",
            choice_name,
            &self_cid,
            &this_val,
            arg_val,
            &mut host,
        ) {
            Ok(_) => {
                self.contracts[id] = None;
                let mut indices = Vec::with_capacity(host.created.len());
                for (created_holding, created_cid) in host.created {
                    self.contracts.push(Some(created_holding));
                    self.contract_ids.push(created_cid);
                    indices.push(self.contracts.len() - 1);
                }
                Ok(indices)
            }
            Err(EvalError::UnhandledException { error_id, message }) => {
                Err(failure_status(&error_id, &message))
            }
            Err(EvalError::Host(msg)) => Err(msg),
            Err(err) => Err(err.to_string()),
        }
    }

    pub fn contract_id(&self, id: usize) -> String {
        self.contract_ids
            .get(id)
            .cloned()
            .unwrap_or_else(|| format!("{id:0130x}"))
    }

    pub fn fetch(&self, id: usize) -> Result<Holding, String> {
        let cid = self.contract_id(id);
        self.contracts
            .get(id)
            .and_then(|slot| slot.clone())
            .ok_or_else(|| inactive(&cid))
    }

    pub fn active_contracts(&self, who: Option<&str>) -> Vec<(usize, Holding)> {
        self.contracts
            .iter()
            .enumerate()
            .filter_map(|(id, slot)| {
                slot.as_ref().and_then(|holding| {
                    if let Some(w) = who {
                        if visible(holding, w) {
                            Some((id, holding.clone()))
                        } else {
                            None
                        }
                    } else {
                        Some((id, holding.clone()))
                    }
                })
            })
            .collect()
    }

    pub fn is_active(&self, id: usize) -> bool {
        self.contracts.get(id).is_some_and(|slot| slot.is_some())
    }

    pub fn summary(&self, who: &str) -> String {
        let rows: Vec<String> = self
            .contracts
            .iter()
            .filter_map(|slot| slot.as_ref())
            .filter(|holding| visible(holding, who))
            .map(show_row)
            .collect();
        format!("[{}]", rows.join(","))
    }
}

pub fn visible(holding: &Holding, who: &str) -> bool {
    who == holding.bank || who == holding.owner || who == holding.auditor
}

fn covers(act: &[&str], required: &[&str]) -> bool {
    required.iter().all(|party| act.contains(party))
}

fn sorted_parties(parties: &[&str]) -> String {
    let mut unique: Vec<&str> = parties.to_vec();
    unique.sort_unstable();
    unique.dedup();
    unique.join(",")
}

fn auth(node: u32, required: &[&str], given: &[&str]) -> String {
    let pkg = sample_package_id();
    format!(
        "Left Authorization failure: node NodeId({node}) ({pkg}:AssetHolding:AssetHolding) requires authorizers {required}, but only {given} were given",
        required = sorted_parties(required),
        given = sorted_parties(given),
    )
}

fn show_amount(tenths: i64) -> String {
    let sign = if tenths < 0 { "-" } else { "" };
    let abs = tenths.abs();
    format!("{sign}{}.{}", abs / 10, abs % 10)
}

fn show_row(holding: &Holding) -> String {
    format!(
        "(\"{symbol}\",{amount},'{owner}','{bank}')",
        symbol = holding.symbol,
        amount = show_amount(holding.tenths),
        owner = holding.owner,
        bank = holding.bank,
    )
}

fn failure_status(error_id: &str, message: &str) -> String {
    let escaped_msg = message.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "Left Failed with Status: FailureStatus {{errorId = \"{error_id}\", category = InvalidGivenCurrentSystemStateOther, message = \"{escaped_msg}\", meta = TextMap []}}"
    )
}

/// [CANTON-NOTE: SEMANTICS] Reproduces the canonical Daml IDE ledger / Haskell failure envelope
/// for an inactive or unallocated contract ID, matching expected.tsv row 12 verbatim.
pub fn format_not_active_error(cid: &str) -> String {
    format!(
        "Left Could not find contract with ID(s) {cid}. Additional debugging info: NotActive {{additionalInfoCid = AnyContractId {cid}}}"
    )
}

fn inactive(cid: &str) -> String {
    format_not_active_error(cid)
}

/// Standard RFC 2104 HMAC-SHA256 used by `com.digitalasset.daml.lf.crypto.Hash`.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = Sha256::digest(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// Reproduces `com.digitalasset.daml.lf.crypto.Hash.hashPrivateKey(s)` (`Hash.scala` L994-L996):
/// `Builder(Version.TypedNormalForm = 1, Purpose.PrivateKey = 3).add(s).build`.
pub fn hash_private_key(s: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01, 0x03]);
    hash_string(&mut hasher, s);
    hasher.finalize().into()
}

/// Reproduces `IdeLedgerRunner.nextSeed = Hash.secureRandom(Hash.hashPrivateKey("script-service"))`
/// (`IdeLedgerRunner.scala` L282, `Hash.scala` L1085-L1088).
pub fn derive_submission_seed(submission_idx: u64) -> [u8; 32] {
    let key = hash_private_key("script-service");
    hmac_sha256(&key, &(submission_idx as i64).to_be_bytes())
}

/// Reproduces `com.digitalasset.daml.lf.crypto.Hash.deriveNodeSeed(parentDiscriminator, childIdx)`
/// (`Hash.scala` L1073-L1074).
pub fn derive_node_seed(parent_seed: &[u8; 32], child_idx: i32) -> [u8; 32] {
    hmac_sha256(parent_seed, &child_idx.to_be_bytes())
}

/// Reproduces `com.digitalasset.daml.lf.crypto.Hash.deriveContractDiscriminator(nodeSeed, time, fs)`
/// (`Hash.scala` L1076-L1082).
pub fn derive_contract_discriminator(
    node_seed: &[u8; 32],
    submission_time_micros: i64,
    stakeholders: &[String],
) -> [u8; 32] {
    let mut sorted_unique: Vec<&str> = stakeholders.iter().map(String::as_str).collect();
    sorted_unique.sort_unstable();
    sorted_unique.dedup();

    let mut msg = Vec::with_capacity(12 + sorted_unique.len() * 20);
    msg.extend_from_slice(&submission_time_micros.to_be_bytes());
    msg.extend_from_slice(&(sorted_unique.len() as i32).to_be_bytes());
    for party in sorted_unique {
        msg.extend_from_slice(&(party.len() as i32).to_be_bytes());
        msg.extend_from_slice(party.as_bytes());
    }
    hmac_sha256(node_seed, &msg)
}

/// [CANTON-NOTE: SEMANTICS] Computes the 65-byte (130-hex-char) Daml-LF V1 `ContractId` (`00` + 32-byte discriminator +
/// 32-byte `SValueHash` TypedNormalForm contract instance hash) parameterized by package name and template ID.
pub fn compute_v1_contract_id_full(
    discriminator: &[u8; 32],
    package_name: &str,
    template_id: &str,
    record: &Value,
) -> String {
    let suffix = hash_contract_instance(package_name, template_id, record);
    let mut bytes = Vec::with_capacity(65);
    bytes.push(0x00);
    bytes.extend_from_slice(discriminator);
    bytes.extend_from_slice(&suffix);
    hex::encode(bytes)
}

/// Computes the 65-byte (130-hex-char) Daml-LF V1 `ContractId` (`00` + 32-byte discriminator +
/// 32-byte `SValueHash` TypedNormalForm contract instance hash).
pub fn compute_v1_contract_id_from_discriminator(
    discriminator: &[u8; 32],
    record: &Value,
) -> String {
    compute_v1_contract_id_full(
        discriminator,
        "sample-contract",
        "AssetHolding:AssetHolding",
        record,
    )
}

/// [CANTON-NOTE: SEMANTICS] Deterministic Daml-LF V1 cryptographic contract ID allocator.
/// Reproduces 130-char Daml-LF V1 contract IDs (`00` + 32-byte discriminator + 32-byte `SValueHash` suffix)
/// for `Engine` executions matching official `daml script --ide-ledger` output.
#[derive(Clone, Debug)]
pub struct IdeContractIdAllocator {
    pub package_name: String,
    pub submission_idx: usize,
    pub preparation_time_micros: i64,
}

impl Default for IdeContractIdAllocator {
    fn default() -> Self {
        Self::new("sample-contract")
    }
}

impl IdeContractIdAllocator {
    /// Creates a new allocator for `package_name` with `submission_idx = 0` and `PREPARATION_TIME_MIN_MICROS`.
    pub fn new(package_name: impl Into<String>) -> Self {
        Self {
            package_name: package_name.into(),
            submission_idx: 0,
            preparation_time_micros: PREPARATION_TIME_MIN_MICROS,
        }
    }

    /// Creates an allocator with an explicit starting submission index.
    pub fn with_submission(package_name: impl Into<String>, submission_idx: usize) -> Self {
        Self {
            package_name: package_name.into(),
            submission_idx,
            preparation_time_micros: PREPARATION_TIME_MIN_MICROS,
        }
    }

    /// Sets the current submission index (0-based transaction sequence index).
    pub fn set_submission_idx(&mut self, idx: usize) {
        self.submission_idx = idx;
    }

    /// Increments the submission index for the next transaction.
    pub fn advance_submission(&mut self) {
        self.submission_idx += 1;
    }
}

impl ContractIdAllocator for IdeContractIdAllocator {
    fn allocate(&mut self, new: &NewContract<'_>) -> String {
        let mut stakeholders: Vec<String> = new.signatories.to_vec();
        stakeholders.extend(new.observers.iter().cloned());
        let tx_seed = derive_submission_seed(self.submission_idx as u64);
        let node_seed = if new.depth == 0 {
            derive_node_seed(&tx_seed, new.creation_index as i32)
        } else {
            let mut current_seed = derive_node_seed(&tx_seed, 0);
            for _ in 1..new.depth {
                current_seed = derive_node_seed(&current_seed, 0);
            }
            derive_node_seed(&current_seed, new.creation_index as i32)
        };
        let discriminator =
            derive_contract_discriminator(&node_seed, self.preparation_time_micros, &stakeholders);
        compute_v1_contract_id_full(
            &discriminator,
            &self.package_name,
            new.template_id,
            new.payload,
        )
    }

    fn set_submission_idx(&mut self, idx: usize) {
        self.submission_idx = idx;
    }
}

/// Computes the Daml-LF V1 `ContractId` for root `Create` submission `submission_idx`
/// (`00` + 32-byte discriminator derived via `Hash.deriveContractDiscriminator` + 32-byte `SValueHash`).
pub fn compute_v1_contract_id(submission_idx: usize, record: &Value) -> String {
    let tx_seed = derive_submission_seed(submission_idx as u64);
    let node_seed = derive_node_seed(&tx_seed, 0);
    let stakeholders = match Holding::from_lf_record(record) {
        Ok(h) => vec![h.bank, h.owner, h.auditor],
        Err(_) => Vec::new(),
    };
    let discriminator =
        derive_contract_discriminator(&node_seed, PREPARATION_TIME_MIN_MICROS, &stakeholders);
    compute_v1_contract_id_from_discriminator(&discriminator, record)
}

/// Computes `com.digitalasset.daml.lf.speedy.SValueHash.hashContractInstance`
/// (`Version.TypedNormalForm = 3`, `Purpose.ThinContractInstance = 5`).
pub fn hash_contract_instance(
    package_name: &str,
    template_qual_name: &str,
    record: &Value,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    // Builder(Version.TypedNormalForm = 3, Purpose.ThinContractInstance = 5)
    hasher.update([0x03, 0x05]);
    hash_string(&mut hasher, package_name);
    hash_qualified_name(&mut hasher, template_qual_name);
    hash_svalue(&mut hasher, record);
    hasher.finalize().into()
}

fn hash_int(hasher: &mut Sha256, value: i32) {
    hasher.update(value.to_be_bytes());
}

fn hash_long(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_be_bytes());
}

fn hash_string(hasher: &mut Sha256, s: &str) {
    hash_int(hasher, s.len() as i32);
    hasher.update(s.as_bytes());
}

fn hash_dotted_name(hasher: &mut Sha256, name: &str) {
    let segments: Vec<&str> = name.split('.').collect();
    hash_int(hasher, segments.len() as i32);
    for seg in segments {
        hash_string(hasher, seg);
    }
}

fn hash_qualified_name(hasher: &mut Sha256, qual_name: &str) {
    let (module, name) = qual_name.split_once(':').unwrap_or((qual_name, ""));
    hash_dotted_name(hasher, module);
    hash_dotted_name(hasher, name);
}

fn hash_svalue(hasher: &mut Sha256, value: &Value) {
    match value {
        Value::Int64(n) => {
            hasher.update([0x00]);
            hash_long(hasher, *n);
        }
        Value::Numeric { coeff, scale: _ } => {
            // Constants.NUMERIC_TAG = 1, BigInteger.unscaledValue.toByteArray (bigIntNumericToBytes)
            hasher.update([0x01]);
            let unscaled_bytes = i128_to_twos_complement_be(*coeff);
            hash_int(hasher, unscaled_bytes.len() as i32);
            hasher.update(&unscaled_bytes);
        }
        Value::Text(s) => {
            hasher.update([0x02]);
            hash_string(hasher, s);
        }
        Value::Party(p) => {
            hasher.update([0x04]);
            hash_string(hasher, p);
        }
        Value::Bool(b) => hasher.update([0x05, u8::from(*b)]),
        Value::Unit => hasher.update([0x06]),
        Value::Record { tycon, fields } => {
            // Constants.RECORD_TAG = 8
            // [CANTON-NOTE: LIMITATION] A record without a type constructor is hashed as `AssetHolding:AssetHolding` (the sample
            // template this module was written for). Payloads built by the codec or the engine carry `tycon`; a hand-built
            // `tycon: None` record of another template silently gets a WRONG id (found with TxNote:Note, S-TX-005).
            hasher.update([0x08]);
            hash_qualified_name(
                hasher,
                tycon.as_deref().unwrap_or("AssetHolding:AssetHolding"),
            );
            let non_trailing_len = fields
                .iter()
                .rposition(|(_, v)| !matches!(v, Value::Optional(None)))
                .map_or(0, |idx| idx + 1);
            for (label, field_val) in &fields[..non_trailing_len] {
                hash_string(hasher, label);
                hash_svalue(hasher, field_val);
            }
            // Constants.END_OF_RECORD = 0xff
            hasher.update([0xff]);
        }
        Value::List(items) => {
            hasher.update([0x0b]);
            hash_int(hasher, items.len() as i32);
            for item in items {
                hash_svalue(hasher, item);
            }
        }
        Value::Optional(opt) => {
            hasher.update([0x0c]);
            match opt {
                None => hasher.update([0x00]),
                Some(inner) => {
                    hasher.update([0x01]);
                    hash_svalue(hasher, inner);
                }
            }
        }
        _ => {}
    }
}

/// Converts a signed `i128` to minimal big-endian two's-complement bytes,
/// matching Java's `BigInteger.toByteArray()`.
fn i128_to_twos_complement_be(val: i128) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let bytes = val.to_be_bytes();
    let mut start = 0;
    if val > 0 {
        while start < 15 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0 {
            start += 1;
        }
    } else {
        while start < 15 && bytes[start] == 0xff && (bytes[start + 1] & 0x80) != 0 {
            start += 1;
        }
    }
    bytes[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ide_party_allocator_matches_daml_script_global_random() {
        let mut alloc = IdePartyAllocator::new();
        assert_eq!(alloc.allocate_party("Bank"), BANK_PARTY);
        assert_eq!(alloc.allocate_party("Owner"), OWNER_PARTY);
        assert_eq!(alloc.allocate_party("Auditor"), AUDITOR_PARTY);

        // Also verify the 8-party `seqProbe` sequence from `tests/oracle/tx-corpus/daml/Tx.daml`
        let mut probe_alloc = IdePartyAllocator::new();
        let probe: Vec<String> = ["A", "B", "C", "D", "E", "F", "G", "H"]
            .into_iter()
            .map(|h| probe_alloc.allocate_party(h))
            .collect();
        assert_eq!(
            probe.join(","),
            "A-d4d95138,B-9b3970be,C-4f1df03a,D-1df42503,E-c812a76d,F-40b5f04b,G-9cefe94d,H-fb9a0f58"
        );
    }

    #[test]
    fn test_ide_ledger_seed_and_v1_contract_id_derivation_root_and_child() {
        let (mut ledger, holding) = fresh();
        let c0 = ledger
            .create(&[BANK_PARTY, OWNER_PARTY], holding)
            .expect("root create");
        assert_eq!(
            ledger.contract_id(c0),
            "006cdb7b6b9252f4767b0a9cdaa4b073b2457034d1f440a9ccca1028c3f722a2bd695411b234fd0b1bf66c1b8f872b9ba6e5831d67763c83f3d7d60196aab2a50e"
        );

        let c1 = ledger
            .exercise_transfer(c0, &[OWNER_PARTY], BANK_PARTY)
            .expect("transfer exercise");
        // Verify child Create inside Transfer derives node seed from exercise_node_seed
        let tx1_seed = derive_submission_seed(1);
        let ex1_seed = derive_node_seed(&tx1_seed, 0);
        let child0_seed = derive_node_seed(&ex1_seed, 0);
        let expected_disc = derive_contract_discriminator(
            &child0_seed,
            PREPARATION_TIME_MIN_MICROS,
            &[
                BANK_PARTY.to_string(),
                BANK_PARTY.to_string(),
                AUDITOR_PARTY.to_string(),
            ],
        );
        let transferred_holding = ledger.fetch(c1).expect("transferred holding active");
        let expected_c1_cid = compute_v1_contract_id_from_discriminator(
            &expected_disc,
            &transferred_holding.to_lf_record(),
        );
        assert_eq!(ledger.contract_id(c1), expected_c1_cid);
        assert_eq!(expected_c1_cid.len(), 130);
    }

    #[test]
    fn test_ide_contract_id_allocator_engine_root_and_child() {
        use crate::engine::Engine;
        let mut eng = Engine::new(world());
        eng.set_contract_id_allocator(IdeContractIdAllocator::new("sample-contract"));
        let holding = Holding {
            bank: BANK_PARTY.to_string(),
            owner: OWNER_PARTY.to_string(),
            auditor: AUDITOR_PARTY.to_string(),
            symbol: "USD".to_string(),
            tenths: 100,
        };
        let c0 = eng
            .execute_create(
                &[BANK_PARTY, OWNER_PARTY],
                "AssetHolding:AssetHolding",
                &holding.to_lf_record(),
            )
            .expect("engine execute_create");
        assert_eq!(
            c0.contract_id,
            "006cdb7b6b9252f4767b0a9cdaa4b073b2457034d1f440a9ccca1028c3f722a2bd695411b234fd0b1bf66c1b8f872b9ba6e5831d67763c83f3d7d60196aab2a50e"
        );

        // Advance to submission 1 for exercise
        eng.set_submission_idx(1);
        let arg = Value::Record {
            tycon: Some("AssetHolding:Transfer".to_string()),
            fields: vec![("newOwner".to_string(), Value::Party(BANK_PARTY.to_string()))],
        };
        let outcome = eng
            .execute_exercise(&[OWNER_PARTY], &c0.contract_id, "Transfer", &arg)
            .expect("engine execute_exercise transfer");
        assert_eq!(outcome.created.len(), 1);
        let c1_cid = &outcome.created[0].contract_id;
        assert_eq!(c1_cid.len(), 130);
        assert!(c1_cid.starts_with("00"));
        let (mut ledger, ledger_holding) = fresh();
        let l0 = ledger
            .create(&[BANK_PARTY, OWNER_PARTY], ledger_holding)
            .expect("ledger create");
        let l1 = ledger
            .exercise_transfer(l0, &[OWNER_PARTY], BANK_PARTY)
            .expect("ledger transfer");
        assert_eq!(c1_cid, &ledger.contract_id(l1));
    }
}
