//! Selective Audit Capsule (`.audit-pack`): a Merkle inclusion proof of one disclosed view plus an Ed25519
//! signature over the root (`canton-rs dpm audit-pack <create|verify>`).
//!
//! [CANTON-NOTE: LIMITATION] The views are caller-supplied JSON; nothing here extracts them from a ledger
//! transaction, and the Merkle layout and `root_hash` are this module's own, not Canton's transaction
//! root hash. The signature proves integrity under some Ed25519 key. It proves who signed only when the
//! verifier pins the expected public key ([`SignerTrust::Pinned`]); with [`SignerTrust::EmbeddedKey`] it
//! checks the key the capsule carries, which anyone can choose.

use std::collections::BTreeSet;

use canton_algo::sha256_with_purpose;
use ed25519_dalek::{Signature, Signer, SigningKey as EdSigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::topology::PURPOSE_SIGNED_PROTOCOL_MESSAGE;

const AUDIT_CAPSULE_VERSION: u32 = 2;
const LEAF_DOMAIN_PREFIX: u8 = 0x00;
const NODE_DOMAIN_PREFIX: u8 = 0x01;
const CAPSULE_SIGN_TAG: &[u8] = b"CANTON_RS_SELECTIVE_AUDIT_CAPSULE_V2:";
/// Minimum decoded length of `view_salt_hex`. Randomness itself cannot be checked.
pub const MIN_VIEW_SALT_BYTES: usize = 16;

/// What a successful verification does not establish, stated in every summary.
pub const CAPSULE_SCOPE_NOTE: &str =
    "views are caller-supplied, not extracted from a ledger transaction; \
root_hash is a canton-rs capsule hash, not a Canton transaction root hash";

/// Domain error enum for `.audit-pack` creation and offline verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuditCapsuleError {
    #[error("cannot create audit capsule from an empty transaction view list")]
    EmptyViews,

    #[error("disclosed view index {index} out of bounds for {total} view(s)")]
    ViewIndexOutOfBounds { index: usize, total: usize },

    #[error("unsupported audit capsule version {0}")]
    UnsupportedVersion(u32),

    #[error(
        "Blinded Merkle proof root mismatch: capsule states {expected}, proof recomputed {actual}"
    )]
    MerkleRootMismatch { expected: String, actual: String },

    #[error("disclosed view hash mismatch: expected {expected}, computed {actual}")]
    ViewHashMismatch { expected: String, actual: String },

    #[error("capsule Ed25519 signature verification failed: {0}")]
    InvalidSequencerSignature(String),

    #[error("capsule is signed by {actual}, not by the expected key {expected}")]
    UnexpectedSigner { expected: String, actual: String },

    #[error(
        "view {view_index}: salt must decode to at least {MIN_VIEW_SALT_BYTES} bytes, got {detail}"
    )]
    WeakSalt { view_index: usize, detail: String },

    #[error("inconsistent view counts: {total} total, {blinded} blinded (expected total - 1)")]
    InconsistentViewCounts { total: usize, blinded: usize },

    #[error("malformed hex field '{field}': {reason}")]
    MalformedHex { field: &'static str, reason: String },
}

/// Plaintext sub-transaction view disclosed to a specific auditor party.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosedViewPayload {
    pub view_index: usize,
    pub template_id: String,
    pub contract_id: String,
    pub action: String,
    pub informees: BTreeSet<String>,
    /// Random blinding salt (hex, at least [`MIN_VIEW_SALT_BYTES`] bytes) against guessing low-entropy fields.
    pub view_salt_hex: String,
    pub arguments_json: serde_json::Value,
}

/// Direction of a blinded sibling hash along a binary Merkle authentication path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiblingPosition {
    Left,
    Right,
}

/// Blinded sibling hash in the Merkle proof (contains zero bytes of the sibling's business payload).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedMerkleSibling {
    pub position: SiblingPosition,
    pub sibling_hash_hex: String,
}

/// Self-contained `.audit-pack` selective disclosure proof file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCapsule {
    pub capsule_version: u32,
    pub synchronizer_id: String,
    pub offset: i64,
    pub record_time_micros: i64,
    pub total_views_in_tx: usize,
    pub blinded_views_redacted: usize,
    pub root_hash: String,
    pub disclosed_view_hash: String,
    pub disclosed_view: DisclosedViewPayload,
    pub merkle_proof: Vec<BlindedMerkleSibling>,
    pub sequencer_public_key_hex: String,
    pub sequencer_signature_hex: String,
}

/// Which key the verifier accepts as the capsule signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerTrust {
    /// Accept the key embedded in the capsule: proves integrity only, not who signed.
    EmbeddedKey,
    /// Require this Ed25519 public key.
    Pinned([u8; 32]),
}

/// What the signature check established.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerCheck {
    /// Signature is valid under the capsule's own key; the signer's identity is unverified.
    EmbeddedKeyOnly,
    /// Signature is valid under the verifier's pinned key.
    PinnedKey,
}

/// Result returned when an `.audit-pack` passes the Merkle proof and signature checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditVerificationSummary {
    pub verified: bool,
    pub signer: SignerCheck,
    pub synchronizer_id: String,
    pub offset: i64,
    pub root_hash: String,
    pub disclosed_template_id: String,
    pub disclosed_contract_id: String,
    pub total_views_in_tx: usize,
    pub blinded_views_redacted: usize,
    pub sequencer_public_key_hex: String,
    pub scope_note: String,
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Computes the domain-separated leaf hash `SHA256(0x00 || fields)`, each field length-prefixed.
pub fn compute_view_leaf_hash(view: &DisclosedViewPayload) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_DOMAIN_PREFIX]);
    hasher.update((view.view_index as u64).to_be_bytes());
    hash_len_prefixed(&mut hasher, view.template_id.as_bytes());
    hash_len_prefixed(&mut hasher, view.contract_id.as_bytes());
    hash_len_prefixed(&mut hasher, view.action.as_bytes());
    hasher.update((view.informees.len() as u64).to_be_bytes());
    for inf in &view.informees {
        hash_len_prefixed(&mut hasher, inf.as_bytes());
    }
    hash_len_prefixed(&mut hasher, view.view_salt_hex.as_bytes());
    let args_bytes = crate::cold_archive::hash_payload_json(Some(&view.arguments_json));
    hash_len_prefixed(&mut hasher, args_bytes.as_bytes());
    hasher.finalize().into()
}

fn check_salt(view: &DisclosedViewPayload) -> Result<(), AuditCapsuleError> {
    let weak = |detail: String| AuditCapsuleError::WeakSalt {
        view_index: view.view_index,
        detail,
    };
    let salt = hex::decode(&view.view_salt_hex).map_err(|e| weak(format!("invalid hex ({e})")))?;
    if salt.len() < MIN_VIEW_SALT_BYTES {
        return Err(weak(format!("{} byte(s)", salt.len())));
    }
    Ok(())
}

fn hash_internal_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_DOMAIN_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

struct SignedFields<'a> {
    synchronizer_id: &'a str,
    offset: i64,
    record_time_micros: i64,
    total_views: usize,
    blinded_views: usize,
    root_hash_hex: &'a str,
}

fn build_envelope_signing_digest(f: &SignedFields<'_>) -> [u8; 32] {
    let mut payload = Vec::with_capacity(160);
    payload.extend_from_slice(CAPSULE_SIGN_TAG);
    payload.extend_from_slice(&(f.synchronizer_id.len() as u64).to_be_bytes());
    payload.extend_from_slice(f.synchronizer_id.as_bytes());
    payload.extend_from_slice(&f.offset.to_be_bytes());
    payload.extend_from_slice(&f.record_time_micros.to_be_bytes());
    payload.extend_from_slice(&(f.total_views as u64).to_be_bytes());
    payload.extend_from_slice(&(f.blinded_views as u64).to_be_bytes());
    payload.extend_from_slice(f.root_hash_hex.as_bytes());
    sha256_with_purpose(PURPOSE_SIGNED_PROTOCOL_MESSAGE, &payload)
}

/// Builds a selective [`AuditCapsule`] disclosing ONLY `views[disclosed_index]` while blinding all
/// remaining views into sibling hashes, signed by `signing_key_bytes`.
pub fn create_audit_capsule(
    synchronizer_id: &str,
    offset: i64,
    record_time_micros: i64,
    views: &[DisclosedViewPayload],
    disclosed_index: usize,
    signing_key_bytes: &[u8; 32],
) -> Result<AuditCapsule, AuditCapsuleError> {
    if views.is_empty() {
        return Err(AuditCapsuleError::EmptyViews);
    }
    if disclosed_index >= views.len() {
        return Err(AuditCapsuleError::ViewIndexOutOfBounds {
            index: disclosed_index,
            total: views.len(),
        });
    }
    for view in views {
        check_salt(view)?;
    }

    let leaf_hashes: Vec<[u8; 32]> = views.iter().map(compute_view_leaf_hash).collect();
    let disclosed_view_hash = hex::encode(leaf_hashes[disclosed_index]);

    let mut level = leaf_hashes;
    let mut idx = disclosed_index;
    let mut merkle_proof = Vec::new();

    // [CANTON-NOTE: INVARIANT] A lone last node is promoted unchanged to the next level rather than
    // paired with itself, so [A,B,C] and [A,B,C,C] get different roots.
    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        for (pair_idx, pair) in level.chunks(2).enumerate() {
            let pair_start = pair_idx * 2;
            match pair {
                [left, right] => {
                    if idx == pair_start {
                        merkle_proof.push(BlindedMerkleSibling {
                            position: SiblingPosition::Right,
                            sibling_hash_hex: hex::encode(right),
                        });
                    } else if idx == pair_start + 1 {
                        merkle_proof.push(BlindedMerkleSibling {
                            position: SiblingPosition::Left,
                            sibling_hash_hex: hex::encode(left),
                        });
                    }
                    next_level.push(hash_internal_node(left, right));
                }
                [lone] => next_level.push(*lone),
                _ => {}
            }
        }
        idx /= 2;
        level = next_level;
    }

    let root_hash = hex::encode(level[0]);
    let total_views = views.len();
    let blinded_views = total_views - 1;
    let signing_digest = build_envelope_signing_digest(&SignedFields {
        synchronizer_id,
        offset,
        record_time_micros,
        total_views,
        blinded_views,
        root_hash_hex: &root_hash,
    });
    let signing_key = EdSigningKey::from_bytes(signing_key_bytes);
    let verifying_key = signing_key.verifying_key();
    let sig = signing_key.sign(&signing_digest);

    Ok(AuditCapsule {
        capsule_version: AUDIT_CAPSULE_VERSION,
        synchronizer_id: synchronizer_id.to_string(),
        offset,
        record_time_micros,
        total_views_in_tx: total_views,
        blinded_views_redacted: blinded_views,
        root_hash,
        disclosed_view_hash,
        disclosed_view: views[disclosed_index].clone(),
        merkle_proof,
        sequencer_public_key_hex: hex::encode(verifying_key.to_bytes()),
        sequencer_signature_hex: hex::encode(sig.to_bytes()),
    })
}

/// Offline verifier: recomputes the disclosed view leaf, folds `BlindedMerkleSibling`s up to
/// `root_hash`, and verifies the Ed25519 signature under the key `trust` selects.
pub fn verify_audit_capsule(
    capsule: &AuditCapsule,
    trust: SignerTrust,
) -> Result<AuditVerificationSummary, AuditCapsuleError> {
    if capsule.capsule_version != AUDIT_CAPSULE_VERSION {
        return Err(AuditCapsuleError::UnsupportedVersion(
            capsule.capsule_version,
        ));
    }
    if capsule.total_views_in_tx == 0
        || capsule.blinded_views_redacted != capsule.total_views_in_tx - 1
    {
        return Err(AuditCapsuleError::InconsistentViewCounts {
            total: capsule.total_views_in_tx,
            blinded: capsule.blinded_views_redacted,
        });
    }
    check_salt(&capsule.disclosed_view)?;

    let leaf = compute_view_leaf_hash(&capsule.disclosed_view);
    let leaf_hex = hex::encode(leaf);
    if leaf_hex != capsule.disclosed_view_hash {
        return Err(AuditCapsuleError::ViewHashMismatch {
            expected: capsule.disclosed_view_hash.clone(),
            actual: leaf_hex,
        });
    }

    let mut cur = leaf;
    for step in &capsule.merkle_proof {
        let sib_vec =
            hex::decode(&step.sibling_hash_hex).map_err(|e| AuditCapsuleError::MalformedHex {
                field: "sibling_hash_hex",
                reason: e.to_string(),
            })?;
        let sib: [u8; 32] = sib_vec
            .try_into()
            .map_err(|_| AuditCapsuleError::MalformedHex {
                field: "sibling_hash_hex",
                reason: "must be 32 bytes".to_string(),
            })?;
        cur = match step.position {
            SiblingPosition::Left => hash_internal_node(&sib, &cur),
            SiblingPosition::Right => hash_internal_node(&cur, &sib),
        };
    }

    let computed_root = hex::encode(cur);
    if computed_root != capsule.root_hash {
        return Err(AuditCapsuleError::MerkleRootMismatch {
            expected: capsule.root_hash.clone(),
            actual: computed_root,
        });
    }

    let pk_vec = hex::decode(&capsule.sequencer_public_key_hex).map_err(|e| {
        AuditCapsuleError::MalformedHex {
            field: "sequencer_public_key_hex",
            reason: e.to_string(),
        }
    })?;
    let pk_arr: [u8; 32] = pk_vec
        .try_into()
        .map_err(|_| AuditCapsuleError::MalformedHex {
            field: "sequencer_public_key_hex",
            reason: "must be 32 bytes".to_string(),
        })?;
    let signer = match trust {
        SignerTrust::EmbeddedKey => SignerCheck::EmbeddedKeyOnly,
        SignerTrust::Pinned(expected) if expected == pk_arr => SignerCheck::PinnedKey,
        SignerTrust::Pinned(expected) => {
            return Err(AuditCapsuleError::UnexpectedSigner {
                expected: hex::encode(expected),
                actual: capsule.sequencer_public_key_hex.clone(),
            })
        }
    };
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| AuditCapsuleError::InvalidSequencerSignature(e.to_string()))?;

    let sig_vec = hex::decode(&capsule.sequencer_signature_hex).map_err(|e| {
        AuditCapsuleError::MalformedHex {
            field: "sequencer_signature_hex",
            reason: e.to_string(),
        }
    })?;
    let sig_arr: [u8; 64] = sig_vec
        .try_into()
        .map_err(|_| AuditCapsuleError::MalformedHex {
            field: "sequencer_signature_hex",
            reason: "must be 64 bytes".to_string(),
        })?;
    let sig = Signature::from_bytes(&sig_arr);
    let digest = build_envelope_signing_digest(&SignedFields {
        synchronizer_id: &capsule.synchronizer_id,
        offset: capsule.offset,
        record_time_micros: capsule.record_time_micros,
        total_views: capsule.total_views_in_tx,
        blinded_views: capsule.blinded_views_redacted,
        root_hash_hex: &capsule.root_hash,
    });
    vk.verify_strict(&digest, &sig)
        .map_err(|e| AuditCapsuleError::InvalidSequencerSignature(e.to_string()))?;

    Ok(AuditVerificationSummary {
        verified: true,
        signer,
        synchronizer_id: capsule.synchronizer_id.clone(),
        offset: capsule.offset,
        root_hash: capsule.root_hash.clone(),
        disclosed_template_id: capsule.disclosed_view.template_id.clone(),
        disclosed_contract_id: capsule.disclosed_view.contract_id.clone(),
        total_views_in_tx: capsule.total_views_in_tx,
        blinded_views_redacted: capsule.blinded_views_redacted,
        sequencer_public_key_hex: capsule.sequencer_public_key_hex.clone(),
        scope_note: CAPSULE_SCOPE_NOTE.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_three_views() -> Vec<DisclosedViewPayload> {
        let mut p1 = BTreeSet::new();
        p1.insert("BankA".to_string());
        p1.insert("Regulator".to_string());

        let mut p2 = BTreeSet::new();
        p2.insert("BankB".to_string());
        p2.insert("SecretCounterpartyX".to_string());

        let mut p3 = BTreeSet::new();
        p3.insert("ClearingHouse".to_string());

        vec![
            DisclosedViewPayload {
                view_index: 0,
                template_id: "Sto:BondIssuance".to_string(),
                contract_id: "00aa11".to_string(),
                action: "Create".to_string(),
                informees: p1,
                view_salt_hex: "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4".to_string(),
                arguments_json: serde_json::json!({ "isin": "KR1234567890", "par": "1000000" }),
            },
            DisclosedViewPayload {
                view_index: 1,
                template_id: "PrivateRepo:BilateralLeg".to_string(),
                contract_id: "00bb22".to_string(),
                action: "Exercise:Settle".to_string(),
                informees: p2,
                view_salt_hex: "f0e1d2c3f0e1d2c3f0e1d2c3f0e1d2c3".to_string(),
                arguments_json: serde_json::json!({ "secretRateBps": "485", "collateral": "TOP_SECRET_TREASURY" }),
            },
            DisclosedViewPayload {
                view_index: 2,
                template_id: "Clearing:FeeReceipt".to_string(),
                contract_id: "00cc33".to_string(),
                action: "Create".to_string(),
                informees: p3,
                view_salt_hex: "99887766998877669988776699887766".to_string(),
                arguments_json: serde_json::json!({ "fee": "12.50" }),
            },
        ]
    }

    #[test]
    fn selective_capsule_verifies_offline_with_zero_sibling_payload_leakage() {
        let views = sample_three_views();
        let seq_key = [42u8; 32];
        let capsule = create_audit_capsule("sto-sync", 108, 1_700_000_108_000, &views, 0, &seq_key)
            .expect("create capsule");

        let serialized = serde_json::to_string_pretty(&capsule).expect("serialize capsule");
        // Sub-transaction privacy invariant: ZERO bytes of View #1 or View #2 appear in serialized capsule!
        assert!(!serialized.contains("TOP_SECRET_TREASURY"));
        assert!(!serialized.contains("SecretCounterpartyX"));
        assert!(!serialized.contains("PrivateRepo:BilateralLeg"));
        assert_eq!(capsule.blinded_views_redacted, 2);

        let summary =
            verify_audit_capsule(&capsule, SignerTrust::EmbeddedKey).expect("verify valid capsule");
        assert!(summary.verified);
        assert_eq!(summary.disclosed_template_id, "Sto:BondIssuance");

        // Negative control 1: Altering disclosed payload amount fails ViewHashMismatch.
        let mut tampered_view = capsule.clone();
        tampered_view.disclosed_view.arguments_json =
            serde_json::json!({ "isin": "KR1234567890", "par": "9999999" });
        assert!(matches!(
            verify_audit_capsule(&tampered_view, SignerTrust::EmbeddedKey),
            Err(AuditCapsuleError::ViewHashMismatch { .. })
        ));

        // Negative control 2: Altering blinded sibling hash fails MerkleRootMismatch.
        let mut tampered_merkle = capsule.clone();
        tampered_merkle.merkle_proof[0].sibling_hash_hex = "11".repeat(32);
        assert!(matches!(
            verify_audit_capsule(&tampered_merkle, SignerTrust::EmbeddedKey),
            Err(AuditCapsuleError::MerkleRootMismatch { .. })
        ));

        // Negative control 3: Altering sequencer signature fails InvalidSequencerSignature.
        let mut tampered_sig = capsule;
        tampered_sig.sequencer_signature_hex = "22".repeat(64);
        assert!(matches!(
            verify_audit_capsule(&tampered_sig, SignerTrust::EmbeddedKey),
            Err(AuditCapsuleError::InvalidSequencerSignature(_))
        ));
    }

    #[test]
    fn view_counts_are_signed_and_odd_leaf_is_not_duplicated() {
        let views = sample_three_views();
        let key = [42u8; 32];
        let capsule = create_audit_capsule("sto-sync", 108, 1, &views, 0, &key).expect("create");

        let mut more_views = capsule.clone();
        more_views.total_views_in_tx = 9;
        more_views.blinded_views_redacted = 8;
        assert!(
            verify_audit_capsule(&more_views, SignerTrust::EmbeddedKey).is_err(),
            "a capsule whose view counts were edited must not verify"
        );

        let mut dup = views.clone();
        dup.push(views[2].clone());
        let dup_capsule = create_audit_capsule("sto-sync", 108, 1, &dup, 0, &key).expect("create");
        assert_ne!(
            capsule.root_hash, dup_capsule.root_hash,
            "[A,B,C] and [A,B,C,C] must not share a root"
        );
    }

    #[test]
    fn leaf_encoding_is_unambiguous_and_short_salts_are_refused() {
        let mut views = sample_three_views();
        views[0].informees = BTreeSet::from(["a,b".to_string()]);
        let joined = compute_view_leaf_hash(&views[0]);
        views[0].informees = BTreeSet::from(["a".to_string(), "b".to_string()]);
        assert_ne!(joined, compute_view_leaf_hash(&views[0]));

        let mut short = sample_three_views();
        short[1].view_salt_hex = "a1".to_string();
        assert!(matches!(
            create_audit_capsule("s", 1, 1, &short, 0, &[1u8; 32]),
            Err(AuditCapsuleError::WeakSalt { .. })
        ));
    }

    #[test]
    fn verifier_reports_whether_the_signer_was_pinned() {
        let views = sample_three_views();
        let real = [42u8; 32];
        let forger = [7u8; 32];
        let real_pub = EdSigningKey::from_bytes(&real).verifying_key().to_bytes();
        let forged = create_audit_capsule("s", 1, 1, &views, 0, &forger).expect("create");

        let self_check =
            verify_audit_capsule(&forged, SignerTrust::EmbeddedKey).expect("integrity");
        assert_eq!(self_check.signer, SignerCheck::EmbeddedKeyOnly);

        assert!(matches!(
            verify_audit_capsule(&forged, SignerTrust::Pinned(real_pub)),
            Err(AuditCapsuleError::UnexpectedSigner { .. })
        ));

        let genuine = create_audit_capsule("s", 1, 1, &views, 0, &real).expect("create");
        let pinned = verify_audit_capsule(&genuine, SignerTrust::Pinned(real_pub)).expect("pinned");
        assert_eq!(pinned.signer, SignerCheck::PinnedKey);
    }
}
