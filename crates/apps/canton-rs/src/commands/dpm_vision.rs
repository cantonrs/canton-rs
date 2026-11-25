//! Selective Audit Capsule (`.audit-pack`), AI Coding Agent `.dar` Verification MCP (`dpm mcp`),
//! Static Privacy Surface Auditor, and Multi-Party Deterministic `.dar` Fuzzer (`dpm fuzz`).
//!
//! [CANTON-NOTE: INVARIANT] All outputs use `BTreeMap` / `BTreeSet` and a deterministic `SplitMix64`
//! PRNG so fuzz seeds, privacy findings, and MCP JSON-RPC responses are 100% reproducible across OSes.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use canton_participant::audit_capsule::{
    create_audit_capsule, verify_audit_capsule, AuditCapsule, AuditVerificationSummary,
    DisclosedViewPayload, SignerCheck, SignerTrust,
};
use clap::{Args, Subcommand};
use ledger_json_api::http::{dispatch_request, HttpRequest};
use ledger_json_api::node_builder::{CantonEmbeddedNode, CantonNodeBuilder};
use lf_archive::{DarArchive, SurfaceType, TemplateSurface};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};

// ─────────────────────────────────────────────────────────────────────────────
// CLI Argument Definitions
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct AuditPackArgs {
    #[command(subcommand)]
    pub action: AuditPackAction,
}

#[derive(Subcommand, Debug)]
pub enum AuditPackAction {
    /// Package a selective sub-transaction view + Blinded Merkle siblings + Sequencer signature into `.audit-pack`.
    Create(AuditPackCreateArgs),
    /// Offline-verify an `.audit-pack` file (zero DB or node connection required).
    Verify(AuditPackVerifyArgs),
}

#[derive(Args, Debug)]
pub struct AuditPackCreateArgs {
    /// Path to JSON file containing an array of `DisclosedViewPayload` transaction views.
    #[arg(long)]
    pub views_json: PathBuf,

    /// Zero-based index of the single sub-transaction view to disclose in plaintext (all siblings are blinded).
    #[arg(long, default_value_t = 0)]
    pub disclose_index: usize,

    /// Physical or logical Synchronizer ID ordering the transaction.
    #[arg(long, default_value = "global-sync::1220cantonrs")]
    pub synchronizer_id: String,

    /// Ledger offset assigned to the transaction.
    #[arg(long, default_value_t = 1)]
    pub offset: i64,

    /// Sequencer record time in microseconds since Unix epoch.
    #[arg(long, default_value_t = 1_763_500_000_000_000)]
    pub record_time_micros: i64,

    /// File holding the 32-byte Ed25519 signing secret key as 64 hex chars. Without it an ephemeral key
    /// is generated and discarded, so the capsule's signer can never be pinned by a verifier.
    #[arg(long)]
    pub signing_key_file: Option<PathBuf>,

    /// Output `.audit-pack` file path.
    #[arg(short, long)]
    pub output: PathBuf,

    /// Emit machine-readable JSON summary.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct AuditPackVerifyArgs {
    /// Path to the `.audit-pack` file to verify offline.
    pub pack_path: PathBuf,

    /// Expected signer Ed25519 public key (64 hex chars). Without it only integrity is checked: the
    /// signature is verified under the key the capsule itself carries.
    #[arg(long)]
    pub expected_signer_key_hex: Option<String>,

    /// Emit machine-readable JSON summary.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct FuzzDarArgs {
    /// Path to the compiled `.dar` archive to fuzz.
    pub dar_path: PathBuf,

    /// Initial deterministic PRNG seed (`SplitMix64`).
    #[arg(long, default_value_t = 0xCA47_0425_2026_0001)]
    pub seed: u64,

    /// Number of independent deterministic fuzz campaigns (seeds) to execute.
    #[arg(long, default_value_t = 4)]
    pub seeds: usize,

    /// Number of multi-party create/exercise/attack steps per seed.
    #[arg(long, default_value_t = 8)]
    pub steps: usize,

    /// Emit machine-readable JSON report.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Vision 3: Selective Audit Capsule (`.audit-pack`) CLI Execution
// ─────────────────────────────────────────────────────────────────────────────

/// Largest `.audit-pack` file the verifier reads.
const MAX_PACK_BYTES: u64 = 1 << 20;

fn read_signing_key_file(path: &Path) -> Result<[u8; 32], String> {
    let raw = super::db::read_secret_file(path, "--signing-key-file")?;
    let decoded =
        hex::decode(raw.trim()).map_err(|e| format!("invalid hex in --signing-key-file: {e}"))?;
    decoded
        .try_into()
        .map_err(|_| "--signing-key-file must hold 32 bytes (64 hex chars)".to_string())
}

pub(crate) fn parse_signer_trust(expected_key_hex: Option<&str>) -> Result<SignerTrust, String> {
    let Some(hex_str) = expected_key_hex else {
        return Ok(SignerTrust::EmbeddedKey);
    };
    let decoded =
        hex::decode(hex_str.trim()).map_err(|e| format!("invalid expected signer key: {e}"))?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "expected signer key must be 32 bytes (64 hex chars)".to_string())?;
    Ok(SignerTrust::Pinned(key))
}

pub(crate) fn read_and_verify_pack(
    pack_path: &Path,
    trust: SignerTrust,
) -> Result<AuditVerificationSummary, String> {
    let mut raw = String::new();
    fs::File::open(pack_path)
        .and_then(|f| f.take(MAX_PACK_BYTES + 1).read_to_string(&mut raw))
        .map_err(|e| format!("failed to read '{}': {e}", pack_path.display()))?;
    if raw.len() as u64 > MAX_PACK_BYTES {
        return Err(format!(
            "'{}' exceeds the {MAX_PACK_BYTES}-byte .audit-pack limit",
            pack_path.display()
        ));
    }
    let capsule: AuditCapsule = serde_json::from_str(&raw)
        .map_err(|e| format!("malformed .audit-pack JSON '{}': {e}", pack_path.display()))?;
    verify_audit_capsule(&capsule, trust).map_err(|e| e.to_string())
}

pub fn execute_audit_pack(args: AuditPackArgs) -> Result<(), String> {
    match args.action {
        AuditPackAction::Create(c) => {
            let raw = fs::read_to_string(&c.views_json).map_err(|e| {
                format!(
                    "failed to read --views-json '{}': {e}",
                    c.views_json.display()
                )
            })?;
            let views: Vec<DisclosedViewPayload> = serde_json::from_str(&raw).map_err(|e| {
                format!(
                    "invalid JSON array of DisclosedViewPayload in '{}': {e}",
                    c.views_json.display()
                )
            })?;
            let ephemeral = c.signing_key_file.is_none();
            let key_bytes: [u8; 32] = match &c.signing_key_file {
                Some(path) => read_signing_key_file(path)?,
                None => rand::random(),
            };
            let capsule = create_audit_capsule(
                &c.synchronizer_id,
                c.offset,
                c.record_time_micros,
                &views,
                c.disclose_index,
                &key_bytes,
            )
            .map_err(|e| e.to_string())?;

            if let Some(parent) = c.output.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
            }
            let encoded = serde_json::to_string_pretty(&capsule).map_err(|e| e.to_string())?;
            fs::write(&c.output, encoded)
                .map_err(|e| format!("failed to write '{}': {e}", c.output.display()))?;

            if c.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "output": c.output.display().to_string(),
                        "root_hash": capsule.root_hash,
                        "disclosed_view_index": c.disclose_index,
                        "total_views_in_tx": capsule.total_views_in_tx,
                        "blinded_views_redacted": capsule.blinded_views_redacted,
                        "signer_public_key_hex": capsule.sequencer_public_key_hex,
                        "ephemeral_signing_key": ephemeral,
                        "scope_note": canton_participant::audit_capsule::CAPSULE_SCOPE_NOTE,
                    }))
                    .map_err(|e| e.to_string())?
                );
            } else {
                println!("Selective Audit Capsule Created: {}", c.output.display());
                println!("Capsule Merkle Root:             {}", capsule.root_hash);
                println!(
                    "Views (caller-supplied):         {} total ({} blinded, 1 disclosed)",
                    capsule.total_views_in_tx, capsule.blinded_views_redacted
                );
                println!(
                    "Signer Public Key (Ed25519):     {}{}",
                    capsule.sequencer_public_key_hex,
                    if ephemeral {
                        " (ephemeral key, discarded: verifiers cannot pin this signer)"
                    } else {
                        ""
                    }
                );
                println!(
                    "Scope:                           {}",
                    canton_participant::audit_capsule::CAPSULE_SCOPE_NOTE
                );
            }
            Ok(())
        }
        AuditPackAction::Verify(v) => {
            let trust = parse_signer_trust(v.expected_signer_key_hex.as_deref())?;
            let summary = read_and_verify_pack(&v.pack_path, trust)?;
            if v.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?
                );
            } else {
                let verdict = match summary.signer {
                    SignerCheck::PinnedKey => "VERIFIED (signed by the expected key)",
                    SignerCheck::EmbeddedKeyOnly => {
                        "INTEGRITY ONLY (signature checked against the key inside the capsule; signer identity NOT verified, pass --expected-signer-key-hex)"
                    }
                };
                println!("Audit Capsule Verification:      {verdict}");
                println!(
                    "Synchronizer / Offset (claimed): {} @ #{}",
                    summary.synchronizer_id, summary.offset
                );
                println!("Capsule Merkle Root:             {}", summary.root_hash);
                println!(
                    "Disclosed Template / Contract:   {} ({})",
                    summary.disclosed_template_id, summary.disclosed_contract_id
                );
                println!(
                    "Blinded Sibling Views:           {} of {}",
                    summary.blinded_views_redacted, summary.total_views_in_tx
                );
                println!(
                    "Signer Public Key (Ed25519):     {}",
                    summary.sequencer_public_key_hex
                );
                println!("Scope:                           {}", summary.scope_note);
            }
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vision 4A: Static `.dar` Privacy & Authorization Surface Auditor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyAuditFinding {
    pub severity: String,
    pub code: String,
    pub target: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarPrivacyAuditReport {
    pub dar_path: String,
    pub main_package_id: String,
    pub lf_version: String,
    pub dalf_packages_verified: usize,
    pub templates_count: usize,
    pub choices_count: usize,
    pub status: String,
    pub findings: Vec<PrivacyAuditFinding>,
}

/// Runs the checks `POST /v2/dars` applies before accepting a DAR (manifest, dependencies, LF
/// typecheck). Package upgrade compatibility needs the node's vetted packages and is not checked.
pub fn check_dar_like_upload(dar_path: &Path) -> Result<(), String> {
    let bytes = fs::read(dar_path)
        .map_err(|e| format!("failed to read DAR '{}': {e}", dar_path.display()))?;
    let loaded = lf_archive::parse_loaded_dar(std::io::Cursor::new(&bytes))
        .map_err(|e| format!("DAR would be refused by upload: {e}"))?;
    lf_archive::check_dar_for_upload(&loaded, &HashSet::new())
        .map_err(|e| format!("DAR would be refused by upload: {e}"))
}

/// Audits a compiled `.dar` archive for cryptographic integrity, signatory/controller coverage,
/// and observer broadcast surfaces.
pub fn audit_dar_privacy(dar_path: &Path) -> Result<DarPrivacyAuditReport, String> {
    check_dar_like_upload(dar_path)?;
    let archive: DarArchive = lf_archive::parse_dar_file(dar_path)
        .map_err(|e| format!("DAR parse/SHA-256 check failed: {e}"))?;
    let _world = lf_eval::World::open(dar_path)
        .map_err(|e| format!("Daml-LF package graph check failed: {e}"))?;

    let mut findings = Vec::new();
    let mut templates_count = 0usize;
    let mut choices_count = 0usize;
    let mut has_critical_or_high = false;

    for module in &archive.module_surfaces {
        for tpl in &module.templates {
            templates_count += 1;
            let qualified = format!("{}:{}", module.name, tpl.name);

            if tpl.signatories.is_empty() {
                has_critical_or_high = true;
                findings.push(PrivacyAuditFinding {
                    severity: "CRITICAL".to_string(),
                    code: "MISSING_TEMPLATE_SIGNATORY".to_string(),
                    target: qualified.clone(),
                    detail: "Template declares zero static signatory projections; verify dynamic signatory logic.".to_string(),
                });
            }

            // Flag `List Party` fields that could cause wide stakeholder broadcast if bound to observers.
            for field in &tpl.fields {
                if matches!(&field.ty, SurfaceType::List(inner) if matches!(inner.as_ref(), SurfaceType::Party))
                    && tpl.observers.iter().any(|o| o.contains(&field.name))
                {
                    findings.push(PrivacyAuditFinding {
                        severity: "WARN".to_string(),
                        code: "OBSERVER_LIST_BROADCAST_SURFACE".to_string(),
                        target: format!("{qualified}.{}", field.name),
                        detail: "Observer projection references a `List Party` field; sub-transaction payload scales with list cardinality.".to_string(),
                    });
                }
            }

            if !tpl.ensure.present {
                findings.push(PrivacyAuditFinding {
                    severity: "INFO".to_string(),
                    code: "NO_ENSURE_INVARIANT".to_string(),
                    target: qualified.clone(),
                    detail: "Template has no `ensure` precondition clause; value range invariants rely on choice guards.".to_string(),
                });
            }

            for ch in &tpl.choices {
                if ch.name == "Archive" {
                    continue;
                }
                choices_count += 1;
                let choice_target = format!("{qualified}:{}", ch.name);
                if ch.controllers.is_empty() {
                    has_critical_or_high = true;
                    findings.push(PrivacyAuditFinding {
                        severity: "HIGH".to_string(),
                        code: "DYNAMIC_OR_EMPTY_CONTROLLER".to_string(),
                        target: choice_target.clone(),
                        detail: "Choice declares no static field controller projection; fuzz dynamic controller expressions.".to_string(),
                    });
                }
                if !ch.consuming && !ch.observers.is_empty() {
                    findings.push(PrivacyAuditFinding {
                        severity: "WARN".to_string(),
                        code: "NONCONSUMING_OBSERVER_DISCLOSURE".to_string(),
                        target: choice_target,
                        detail: "Non-consuming choice adds choice observers, disclosing view metadata without archiving contract.".to_string(),
                    });
                }
            }
        }
    }

    let status = if has_critical_or_high {
        "REVIEW_REQUIRED".to_string()
    } else {
        "PASS".to_string()
    };

    Ok(DarPrivacyAuditReport {
        dar_path: dar_path.display().to_string(),
        main_package_id: archive.main_package_id,
        lf_version: archive.lf_version,
        dalf_packages_verified: archive.dalfs.len(),
        templates_count,
        choices_count,
        status,
        findings,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Vision 4B: Deterministic Multi-Party `.dar` Authorization & Privacy Fuzzer
// ─────────────────────────────────────────────────────────────────────────────

/// Deterministic 64-bit SplitMix64 PRNG for cross-platform reproducible DAR fuzzing.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            let idx = (self.next_u64() as usize) % items.len();
            items.get(idx)
        }
    }
}

/// Upper bounds on one fuzz run, so a request cannot exhaust memory or hold the MCP loop indefinitely.
pub const MAX_FUZZ_SEEDS: usize = 256;
pub const MAX_FUZZ_STEPS: usize = 1024;

/// The only rejection code that proves an attempt was stopped by Daml authorization.
const AUTHORIZATION_ERROR_CODE: &str = "DAML_AUTHORIZATION_ERROR";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzSeedTrace {
    pub seed: u64,
    pub authorized_creates_ok: usize,
    pub authorized_choices_exercised: usize,
    pub unauthorized_creates_rejected: usize,
    pub unauthorized_choices_rejected: usize,
    pub invariant_violations: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarFuzzReport {
    pub dar_path: String,
    pub main_package_id: String,
    pub seeds_executed: usize,
    pub steps_per_seed: usize,
    pub templates_discovered: usize,
    pub authorized_creates_ok: usize,
    pub authorized_choices_exercised: usize,
    pub unauthorized_attempts_total: usize,
    /// Attempts rejected with `DAML_AUTHORIZATION_ERROR`.
    pub unauthorized_attempts_rejected: usize,
    /// Attempts rejected for another reason; they prove nothing about authorization.
    pub unauthorized_attempts_inconclusive: usize,
    pub inconclusive_rejection_codes: BTreeMap<String, usize>,
    /// Ledger API ACS queries for the attacker whose positive control (a stakeholder query) saw the contract.
    pub isolation_checks: usize,
    pub stakeholder_isolation_violations: usize,
    pub authorization_bypasses: usize,
    /// `PASS`, `FAIL`, or `INCONCLUSIVE` when the run proved nothing either way.
    pub verdict: String,
    pub verdict_reason: String,
    pub seed_traces: Vec<FuzzSeedTrace>,
    pub violations: Vec<String>,
}

enum AttackOutcome {
    Blocked,
    RejectedOther(String),
    Accepted,
}

fn classify_attack<T>(result: &Result<T, String>) -> AttackOutcome {
    let Err(err) = result else {
        return AttackOutcome::Accepted;
    };
    let code = err
        .split_once("): ")
        .and_then(|(_, body)| serde_json::from_str::<Json>(body).ok())
        .and_then(|body| body.get("code").and_then(Json::as_str).map(String::from))
        .unwrap_or_else(|| "UNCLASSIFIED".to_string());
    if code == AUTHORIZATION_ERROR_CODE {
        AttackOutcome::Blocked
    } else {
        AttackOutcome::RejectedOther(code)
    }
}

/// Whether `contract_id` is in the ACS that `POST /v2/state/active-contracts` returns for `parties`.
pub fn ledger_api_acs_contains(
    node: &CantonEmbeddedNode,
    parties: &[String],
    contract_id: &str,
) -> Result<bool, String> {
    let wildcard = json!({ "cumulative": [{ "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": false } } } }] });
    let filters: serde_json::Map<String, Json> = parties
        .iter()
        .map(|p| (p.clone(), wildcard.clone()))
        .collect();
    let req = HttpRequest::json_post(
        "/v2/state/active-contracts",
        &json!({
            "eventFormat": { "filtersByParty": filters, "verbose": false },
            "activeAtOffset": node.ledger_end(),
        }),
    );
    let resp = dispatch_request(node.execution_service(), &req);
    if resp.status != 200 {
        return Err(format!(
            "ACS query failed (HTTP {}): {}",
            resp.status,
            String::from_utf8_lossy(&resp.body)
        ));
    }
    let entries: Json = serde_json::from_slice(&resp.body).map_err(|e| e.to_string())?;
    let arr = entries
        .as_array()
        .ok_or_else(|| "ACS response is not an array".to_string())?;
    Ok(arr.iter().any(|entry| {
        entry
            .pointer("/contractEntry/JsActiveContract/createdEvent/contractId")
            .and_then(Json::as_str)
            == Some(contract_id)
    }))
}

#[derive(Default)]
struct FuzzTally {
    auth_creates: usize,
    auth_choices: usize,
    attempts: usize,
    blocked: usize,
    inconclusive: usize,
    inconclusive_codes: BTreeMap<String, usize>,
    isolation_checks: usize,
    isolation_violations: usize,
    bypasses: usize,
    violations: Vec<String>,
}

impl FuzzTally {
    /// Records an attacker attempt; returns whether it was blocked by authorization.
    fn record_attack(
        &mut self,
        outcome: AttackOutcome,
        on_bypass: impl FnOnce() -> String,
    ) -> bool {
        self.attempts += 1;
        match outcome {
            AttackOutcome::Blocked => {
                self.blocked += 1;
                true
            }
            AttackOutcome::RejectedOther(code) => {
                self.inconclusive += 1;
                *self.inconclusive_codes.entry(code).or_insert(0) += 1;
                false
            }
            AttackOutcome::Accepted => {
                self.bypasses += 1;
                self.violations.push(on_bypass());
                false
            }
        }
    }

    fn verdict(&self) -> (&'static str, String) {
        if self.bypasses > 0 || self.isolation_violations > 0 {
            return (
                "FAIL",
                format!(
                    "{} authorization bypass(es), {} isolation leak(s)",
                    self.bypasses, self.isolation_violations
                ),
            );
        }
        let mut gaps = Vec::new();
        if self.auth_creates == 0 {
            gaps.push("no authorized create succeeded");
        }
        if self.blocked == 0 {
            gaps.push("no attempt was rejected with DAML_AUTHORIZATION_ERROR");
        }
        if self.isolation_checks == 0 {
            gaps.push("no Ledger API isolation check ran");
        }
        if gaps.is_empty() {
            (
                "PASS",
                format!(
                    "{} attempt(s) blocked by authorization, {} isolation check(s); {} attempt(s) rejected for other reasons were not counted",
                    self.blocked, self.isolation_checks, self.inconclusive
                ),
            )
        } else {
            ("INCONCLUSIVE", gaps.join("; "))
        }
    }
}

/// Executes deterministic multi-party authorization and Stakeholder-isolation fuzzing against `dar_path`
/// using an in-memory `CantonNodeBuilder` (`lf-eval` Daml-LF 2 engine).
pub fn fuzz_dar_authorization(
    dar_path: &Path,
    base_seed: u64,
    seeds: usize,
    steps_per_seed: usize,
) -> Result<DarFuzzReport, String> {
    if seeds > MAX_FUZZ_SEEDS || steps_per_seed > MAX_FUZZ_STEPS {
        return Err(format!(
            "fuzz size {seeds} seeds x {steps_per_seed} steps exceeds the limit of {MAX_FUZZ_SEEDS} seeds x {MAX_FUZZ_STEPS} steps"
        ));
    }
    let archive = lf_archive::parse_dar_file(dar_path)
        .map_err(|e| format!("failed to parse DAR '{}': {e}", dar_path.display()))?;
    let dar_bytes = fs::read(dar_path)
        .map_err(|e| format!("failed to read DAR '{}': {e}", dar_path.display()))?;

    let mut templates: Vec<(String, TemplateSurface)> = Vec::new();
    for m in &archive.module_surfaces {
        for t in &m.templates {
            templates.push((
                format!("{}:{}:{}", archive.main_package_id, m.name, t.name),
                t.clone(),
            ));
        }
    }

    let run_seeds = seeds.max(1);
    let run_steps = steps_per_seed.max(1);

    let mut tally = FuzzTally::default();
    let mut seed_traces = Vec::with_capacity(run_seeds);

    for s_idx in 0..run_seeds {
        let seed = base_seed.wrapping_add(s_idx as u64);
        let mut rng = SplitMix64::new(seed);

        let node = CantonNodeBuilder::new()
            .synchronizer_id(format!("fuzz-sync::{seed:016x}"))
            .with_dar_bytes(dar_bytes.clone())
            .build()?;

        let alice = node.allocate_party("Alice")?;
        let bob = node.allocate_party("Bob")?;
        let charlie = node.allocate_party("Charlie")?;
        // [CANTON-NOTE: INVARIANT] `eve` is never placed into synthesized Party fields, so she is never
        // a stakeholder; her attempts must be refused and her ACS must not show honest contracts.
        let eve = node.allocate_party("AttackerEve")?;
        let honest_pool = [alice, bob, charlie];

        let before = (
            tally.auth_creates,
            tally.auth_choices,
            tally.bypasses + tally.isolation_violations,
        );
        let mut seed_creates_blocked = 0usize;
        let mut seed_choices_blocked = 0usize;
        let mut live_cids: Vec<(String, TemplateSurface, String)> = Vec::new();

        if !templates.is_empty() {
            for step in 0..run_steps {
                let Some((tmpl_id, tmpl)) = rng.pick(&templates).cloned() else {
                    break;
                };
                let create_args = synthesize_record_fields(&tmpl.fields, &mut rng, &honest_pool);

                // 1. Attack: `AttackerEve` creates without signatory authority.
                if !tmpl.signatories.is_empty() {
                    let unauth_cmd = format!("fuzz-unauth-create-{seed}-{step}");
                    let res = node.submit_create(
                        std::slice::from_ref(&eve),
                        &unauth_cmd,
                        &tmpl_id,
                        create_args.clone(),
                    );
                    let bypass = match &res {
                        Ok((off, cid)) => format!(
                            "seed {seed:#x} step {step}: unauthorized AttackerEve created {tmpl_id} ({cid} @ #{off})"
                        ),
                        Err(_) => String::new(),
                    };
                    if tally.record_attack(classify_attack(&res), || bypass) {
                        seed_creates_blocked += 1;
                    }
                }

                // 2. Authorized submission by honest party pool (`Alice`, `Bob`, `Charlie`).
                let auth_cmd = format!("fuzz-auth-create-{seed}-{step}");
                if let Ok((_off, cid)) =
                    node.submit_create(&honest_pool, &auth_cmd, &tmpl_id, create_args)
                {
                    tally.auth_creates += 1;

                    // 3. Isolation through the Ledger API filter; the stakeholder query is the
                    //    positive control that shows the probe can see the contract at all.
                    let seen_by_pool = ledger_api_acs_contains(&node, &honest_pool, &cid)?;
                    let seen_by_eve =
                        ledger_api_acs_contains(&node, std::slice::from_ref(&eve), &cid)?;
                    if seen_by_eve {
                        tally.isolation_violations += 1;
                        tally.violations.push(format!(
                            "seed {seed:#x} step {step}: non-stakeholder AttackerEve observed {cid} ({tmpl_id})"
                        ));
                    } else if seen_by_pool {
                        tally.isolation_checks += 1;
                    }

                    live_cids.push((tmpl_id, tmpl, cid));
                }

                // 4. Exercise choice fuzzing (unauthorized attack + authorized controller execution).
                if let Some((c_tmpl_id, c_tmpl, cid)) = rng.pick(&live_cids).cloned() {
                    let non_archive: Vec<_> = c_tmpl
                        .choices
                        .iter()
                        .filter(|c| c.name != "Archive")
                        .cloned()
                        .collect();
                    if let Some(choice) = rng.pick(&non_archive) {
                        let choice_arg =
                            synthesize_choice_params(&choice.params, &mut rng, &honest_pool, &cid);

                        let unauth_ex_cmd = format!("fuzz-unauth-choice-{seed}-{step}");
                        let res = node.submit_exercise(
                            std::slice::from_ref(&eve),
                            &unauth_ex_cmd,
                            &c_tmpl_id,
                            &cid,
                            &choice.name,
                            choice_arg.clone(),
                        );
                        let bypass = match &res {
                            Ok(off) => format!(
                                "seed {seed:#x} step {step}: AttackerEve exercised {}:{} on {cid} @ #{off}",
                                c_tmpl.name, choice.name
                            ),
                            Err(_) => String::new(),
                        };
                        if tally.record_attack(classify_attack(&res), || bypass) {
                            seed_choices_blocked += 1;
                        }

                        let auth_ex_cmd = format!("fuzz-auth-choice-{seed}-{step}");
                        if node
                            .submit_exercise(
                                &honest_pool,
                                &auth_ex_cmd,
                                &c_tmpl_id,
                                &cid,
                                &choice.name,
                                choice_arg,
                            )
                            .is_ok()
                        {
                            tally.auth_choices += 1;
                            if choice.consuming {
                                live_cids.retain(|(_, _, existing)| existing != &cid);
                            }
                        }
                    }
                }
            }
        }

        seed_traces.push(FuzzSeedTrace {
            seed,
            authorized_creates_ok: tally.auth_creates - before.0,
            authorized_choices_exercised: tally.auth_choices - before.1,
            unauthorized_creates_rejected: seed_creates_blocked,
            unauthorized_choices_rejected: seed_choices_blocked,
            invariant_violations: tally.bypasses + tally.isolation_violations - before.2,
        });
    }

    let (verdict, verdict_reason) = tally.verdict();
    Ok(DarFuzzReport {
        dar_path: dar_path.display().to_string(),
        main_package_id: archive.main_package_id,
        seeds_executed: run_seeds,
        steps_per_seed: run_steps,
        templates_discovered: templates.len(),
        authorized_creates_ok: tally.auth_creates,
        authorized_choices_exercised: tally.auth_choices,
        unauthorized_attempts_total: tally.attempts,
        unauthorized_attempts_rejected: tally.blocked,
        unauthorized_attempts_inconclusive: tally.inconclusive,
        inconclusive_rejection_codes: tally.inconclusive_codes,
        isolation_checks: tally.isolation_checks,
        stakeholder_isolation_violations: tally.isolation_violations,
        authorization_bypasses: tally.bypasses,
        verdict: verdict.to_string(),
        verdict_reason,
        seed_traces,
        violations: tally.violations,
    })
}

fn synthesize_record_fields(
    fields: &[lf_archive::FieldDef],
    rng: &mut SplitMix64,
    parties: &[String],
) -> Json {
    let mut map = serde_json::Map::new();
    for f in fields {
        map.insert(
            f.name.clone(),
            synthesize_surface_value(&f.ty, rng, parties, "00deadbeef"),
        );
    }
    Json::Object(map)
}

fn synthesize_choice_params(
    params: &[lf_archive::ChoiceParam],
    rng: &mut SplitMix64,
    parties: &[String],
    sample_cid: &str,
) -> Json {
    let mut map = serde_json::Map::new();
    for p in params {
        if matches!(p.ty, SurfaceType::Unit) && params.len() == 1 {
            return json!({});
        }
        map.insert(
            p.name.clone(),
            synthesize_surface_value(&p.ty, rng, parties, sample_cid),
        );
    }
    Json::Object(map)
}

fn synthesize_surface_value(
    ty: &SurfaceType,
    rng: &mut SplitMix64,
    parties: &[String],
    sample_cid: &str,
) -> Json {
    match ty {
        SurfaceType::Party => {
            let p = rng
                .pick(parties)
                .cloned()
                .unwrap_or_else(|| "Alice".to_string());
            Json::String(p)
        }
        SurfaceType::Text => {
            const SYMBOLS: [&str; 4] = ["KRW_BOND", "USD_TBILL", "CANTON_NOTE", "REPO_2026"];
            let s = rng.pick(&SYMBOLS).copied().unwrap_or("ASSET");
            Json::String(format!("{s}_{}", rng.next_u64() % 100))
        }
        SurfaceType::Numeric(scale_opt) => {
            let scale = scale_opt.unwrap_or(10).min(10);
            let whole = (rng.next_u64() % 9_000) + 100;
            if scale == 0 {
                Json::String(whole.to_string())
            } else {
                Json::String(format!("{whole}.5"))
            }
        }
        SurfaceType::Int64 => Json::Number(((rng.next_u64() % 1_000) + 1).into()),
        SurfaceType::Bool => Json::Bool((rng.next_u64() & 1) == 0),
        SurfaceType::Date => Json::String("2026-11-19".to_string()),
        SurfaceType::Timestamp => Json::String("2026-11-19T12:00:00Z".to_string()),
        SurfaceType::Unit => json!({}),
        SurfaceType::ContractId(_) => Json::String(sample_cid.to_string()),
        SurfaceType::List(inner) => {
            if rng.next_u64().is_multiple_of(2) {
                json!([])
            } else {
                json!([synthesize_surface_value(inner, rng, parties, sample_cid)])
            }
        }
        SurfaceType::Optional(inner) => {
            if rng.next_u64().is_multiple_of(2) {
                Json::Null
            } else {
                synthesize_surface_value(inner, rng, parties, sample_cid)
            }
        }
        SurfaceType::GenMap { .. } | SurfaceType::TypeCon { .. } | SurfaceType::Other(_) => {
            json!({})
        }
        SurfaceType::Tuple(elems) => {
            let mut m = serde_json::Map::new();
            for (idx, e) in elems.iter().enumerate() {
                m.insert(
                    format!("_{}", idx + 1),
                    synthesize_surface_value(e, rng, parties, sample_cid),
                );
            }
            Json::Object(m)
        }
        SurfaceType::TypeVar(_) | SurfaceType::Arrow(_, _) => Json::Null,
    }
}

pub fn execute_fuzz_dar(args: FuzzDarArgs) -> Result<(), String> {
    let report = fuzz_dar_authorization(&args.dar_path, args.seed, args.seeds, args.steps)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!("============================================================");
        println!(" Canton Pure-Rust Multi-Party DAR Authorization Fuzzer");
        println!("============================================================");
        println!(" Archive:                       {}", report.dar_path);
        println!(" Main Package ID:               {}", report.main_package_id);
        println!(
            " Templates Discovered:          {}",
            report.templates_discovered
        );
        println!(
            " Campaigns Executed:            {} seeds × {} steps",
            report.seeds_executed, report.steps_per_seed
        );
        println!(
            " Authorized Creates Committed:  {}",
            report.authorized_creates_ok
        );
        println!(
            " Authorized Choices Exercised:  {}",
            report.authorized_choices_exercised
        );
        println!(
            " Unauthorized Attacks Blocked:  {} / {} ({} inconclusive)",
            report.unauthorized_attempts_rejected,
            report.unauthorized_attempts_total,
            report.unauthorized_attempts_inconclusive
        );
        println!(
            " Stakeholder Leaks Detected:    {} ({} isolation check(s))",
            report.stakeholder_isolation_violations, report.isolation_checks
        );
        println!(
            " Security Verdict:              {} ({})",
            report.verdict, report.verdict_reason
        );
        println!("============================================================");
    }
    if report.verdict != "PASS" {
        if report.violations.is_empty() {
            return Err(format!(
                "DAR fuzzing verdict {}: {}",
                report.verdict, report.verdict_reason
            ));
        }
        return Err(format!(
            "DAR fuzzing uncovered {} security violation(s) ({}): {}",
            report.violations.len(),
            report.verdict_reason,
            report.violations.join("; ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn sample_dar_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar")
    }

    #[test]
    fn audit_pack_cli_create_and_verify_rejects_tampered_payload() {
        let tmp = std::env::temp_dir().join(format!("canton_rs_audit_cli_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("mkdir");

        let views_file = tmp.join("views.json");
        let pack_file = tmp.join("tx1.audit-pack");

        let views = vec![
            DisclosedViewPayload {
                view_index: 0,
                template_id: "Sample:AssetHolding".into(),
                contract_id: "00aa11".into(),
                action: "Create".into(),
                informees: BTreeSet::from(["Alice".to_string(), "Auditor".to_string()]),
                view_salt_hex: "aa11bb22cc33aa11bb22cc33aa11bb22".into(),
                arguments_json: json!({"amount": "1000.0"}),
            },
            DisclosedViewPayload {
                view_index: 1,
                template_id: "Sample:PrivateFee".into(),
                contract_id: "00ff99".into(),
                action: "Create".into(),
                informees: BTreeSet::from(["SecretCounterparty".to_string()]),
                view_salt_hex: "dd44ee55ff66dd44ee55ff66dd44ee55".into(),
                arguments_json: json!({"secretSpread": "0.025"}),
            },
        ];
        fs::write(
            &views_file,
            serde_json::to_string_pretty(&views).expect("json"),
        )
        .expect("write views");

        execute_audit_pack(AuditPackArgs {
            action: AuditPackAction::Create(AuditPackCreateArgs {
                views_json: views_file,
                disclose_index: 0,
                synchronizer_id: "sync::1220".into(),
                offset: 7,
                record_time_micros: 1_763_500_000_000_000,
                signing_key_file: None,
                output: pack_file.clone(),
                json: true,
            }),
        })
        .expect("create .audit-pack");

        let pack_raw = fs::read_to_string(&pack_file).expect("read pack");
        assert!(
            !pack_raw.contains("SecretCounterparty") && !pack_raw.contains("secretSpread"),
            "sibling sub-view payload must NEVER appear in .audit-pack"
        );

        execute_audit_pack(AuditPackArgs {
            action: AuditPackAction::Verify(AuditPackVerifyArgs {
                pack_path: pack_file.clone(),
                expected_signer_key_hex: None,
                json: true,
            }),
        })
        .expect("verify valid .audit-pack");

        // Negative control: alter disclosed amount by 1 digit -> offline verifier must reject!
        fs::write(&pack_file, pack_raw.replace("1000.0", "9000.0")).expect("tamper");
        let err = execute_audit_pack(AuditPackArgs {
            action: AuditPackAction::Verify(AuditPackVerifyArgs {
                pack_path: pack_file.clone(),
                expected_signer_key_hex: None,
                json: true,
            }),
        })
        .expect_err("tampered .audit-pack must fail verification");
        assert!(err.contains("mismatch"), "got: {err}");

        // Key from a file; a verifier pinning another key refuses the capsule.
        let key_file = tmp.join("signer.key");
        fs::write(&key_file, "11".repeat(32)).expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).expect("chmod key");
        }
        execute_audit_pack(AuditPackArgs {
            action: AuditPackAction::Create(AuditPackCreateArgs {
                views_json: tmp.join("views.json"),
                disclose_index: 0,
                synchronizer_id: "sync::1220".into(),
                offset: 7,
                record_time_micros: 1,
                signing_key_file: Some(key_file),
                output: pack_file.clone(),
                json: true,
            }),
        })
        .expect("create with key file");
        let signer_pub = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[0x11; 32])
                .verifying_key()
                .to_bytes(),
        );
        let verify = |expected: String| {
            execute_audit_pack(AuditPackArgs {
                action: AuditPackAction::Verify(AuditPackVerifyArgs {
                    pack_path: pack_file.clone(),
                    expected_signer_key_hex: Some(expected),
                    json: true,
                }),
            })
        };
        verify(signer_pub).expect("pinned to the real signer");
        let err = verify("22".repeat(32)).expect_err("another pinned key must be refused");
        assert!(err.contains("not by the expected key"), "got: {err}");

        let _ = fs::remove_dir_all(&tmp);
    }

    fn oracle_dar(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(rel)
    }

    #[test]
    fn fuzzer_without_any_authorized_create_is_inconclusive() {
        let fuzz =
            fuzz_dar_authorization(&oracle_dar("tests/oracle/lf-corpus/lf-corpus.dar"), 1, 1, 4)
                .expect("fuzz runs");
        assert_eq!(fuzz.authorized_creates_ok, 0);
        assert_eq!(
            fuzz.verdict, "INCONCLUSIVE",
            "nothing was exercised, so nothing was proved"
        );
    }

    #[test]
    fn fuzzer_and_mcp_server_verify_sample_dar_with_zero_leaks() {
        let dar = sample_dar_path();
        let audit = audit_dar_privacy(&dar).expect("privacy audit");
        assert_eq!(audit.status, "PASS");
        assert!(audit.templates_count >= 1);

        let fuzz = fuzz_dar_authorization(&dar, 42, 2, 4).expect("fuzz dar");
        assert_eq!(fuzz.verdict, "PASS", "{}", fuzz.verdict_reason);
        assert!(fuzz.authorized_creates_ok >= 2);
        assert!(fuzz.unauthorized_attempts_rejected >= 1);
        assert!(fuzz.isolation_checks >= 1);
        assert_eq!(
            fuzz.unauthorized_attempts_rejected + fuzz.unauthorized_attempts_inconclusive,
            fuzz.unauthorized_attempts_total,
            "every attempt is either an authorization block or counted as inconclusive: {:?}",
            fuzz.inconclusive_rejection_codes
        );
        assert_eq!(fuzz.stakeholder_isolation_violations, 0);
    }

    #[test]
    fn classify_attack_and_fuzz_tally_verdict_cover_pass_inconclusive_and_fail() {
        let auth_err: Result<(), String> = Err(
            r#"submit failed (HTTP 400): {"code":"DAML_AUTHORIZATION_ERROR","cause":"missing auth"}"#
                .to_string(),
        );
        assert!(matches!(classify_attack(&auth_err), AttackOutcome::Blocked));

        let other_err: Result<(), String> = Err(
            r#"submit failed (HTTP 400): {"code":"CONTRACT_NOT_FOUND","cause":"missing"}"#
                .to_string(),
        );
        match classify_attack(&other_err) {
            AttackOutcome::RejectedOther(code) => assert_eq!(code, "CONTRACT_NOT_FOUND"),
            _ => panic!("expected RejectedOther"),
        }
        assert!(matches!(classify_attack(&Ok(())), AttackOutcome::Accepted));

        let empty = FuzzTally::default();
        assert_eq!(empty.verdict().0, "INCONCLUSIVE");

        let mut pass = FuzzTally {
            auth_creates: 1,
            isolation_checks: 1,
            ..Default::default()
        };
        pass.record_attack(classify_attack(&auth_err), || "unused".into());
        pass.record_attack(classify_attack(&other_err), || "unused".into());
        let (v, reason) = pass.verdict();
        assert_eq!(v, "PASS");
        assert!(
            reason.contains("1 attempt(s) rejected for other reasons"),
            "{reason}"
        );

        let mut fail = FuzzTally::default();
        fail.record_attack(classify_attack(&Ok(())), || "bypass".into());
        assert_eq!(fail.verdict().0, "FAIL");
    }

    #[cfg(unix)]
    #[test]
    fn audit_pack_signing_key_file_rejects_0644_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join(format!("canton_rs_audit_perm_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("mkdir");

        let views_file = tmp.join("views.json");
        let pack_file = tmp.join("tx1.audit-pack");
        let key_file = tmp.join("signer.key");
        let views = vec![DisclosedViewPayload {
            view_index: 0,
            template_id: "Sample:AssetHolding".into(),
            contract_id: "00aa11".into(),
            action: "Create".into(),
            informees: BTreeSet::from(["Alice".to_string()]),
            view_salt_hex: "aa11bb22cc33aa11bb22cc33aa11bb22".into(),
            arguments_json: json!({"amount": "100.0"}),
        }];
        fs::write(&views_file, serde_json::to_string(&views).expect("json")).expect("write views");
        fs::write(&key_file, "33".repeat(32)).expect("write key");
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).expect("chmod 0644");

        let err = execute_audit_pack(AuditPackArgs {
            action: AuditPackAction::Create(AuditPackCreateArgs {
                views_json: views_file.clone(),
                disclose_index: 0,
                synchronizer_id: "sync::1220".into(),
                offset: 1,
                record_time_micros: 1_763_500_000_000_000,
                signing_key_file: Some(key_path_clone(&key_file)),
                output: pack_file.clone(),
                json: true,
            }),
        })
        .expect_err("0644 signing key file must be refused");
        assert!(err.contains("0600"), "got: {err}");

        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
        execute_audit_pack(AuditPackArgs {
            action: AuditPackAction::Create(AuditPackCreateArgs {
                views_json: views_file,
                disclose_index: 0,
                synchronizer_id: "sync::1220".into(),
                offset: 1,
                record_time_micros: 1_763_500_000_000_000,
                signing_key_file: Some(key_file),
                output: pack_file,
                json: true,
            }),
        })
        .expect("0600 signing key file must succeed");

        let _ = fs::remove_dir_all(&tmp);
    }

    fn key_path_clone(p: &Path) -> PathBuf {
        p.to_path_buf()
    }
}
