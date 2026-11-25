use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey as EdSigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use super::{
    ArchiveVerifyReport, BuildSegmentSpec, ColdArchiveError, ColdArchiveEvent,
    ColdArchiveEventKind, ColdArchiveSegment, ColdArchiveSourceKind, PruneCoverageSpec,
};

const COLD_ARCHIVE_FORMAT_VERSION: u32 = 1;
const DOMAIN_TAG_COLD_SEGMENT: &[u8] = b"CANTON_RS_COLD_ARCHIVE_SEGMENT_V1:";
const DOMAIN_TAG_ACS_ROOT: &[u8] = b"CANTON_RS_COLD_ARCHIVE_ACS_ROOT_V1:";

/// Computes canonical SHA-256 hex of an arbitrary JSON payload value.
pub fn hash_payload_json(payload: Option<&serde_json::Value>) -> String {
    let mut hasher = Sha256::new();
    match payload {
        Some(v) => {
            let canonical = canonical_json_bytes(v);
            hasher.update(&canonical);
        }
        None => hasher.update(b"NONE"),
    }
    hex::encode(hasher.finalize())
}

fn canonical_json_bytes(val: &serde_json::Value) -> Vec<u8> {
    match val {
        serde_json::Value::Object(map) => {
            let mut sorted: BTreeMap<&str, &serde_json::Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.as_str(), v);
            }
            let mut out = Vec::from(b"{".as_slice());
            for (idx, (k, v)) in sorted.into_iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                if let Ok(kb) = serde_json::to_vec(k) {
                    out.extend_from_slice(&kb);
                }
                out.push(b':');
                out.extend_from_slice(&canonical_json_bytes(v));
            }
            out.push(b'}');
            out
        }
        serde_json::Value::Array(arr) => {
            let mut out = Vec::from(b"[".as_slice());
            for (idx, item) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(&canonical_json_bytes(item));
            }
            out.push(b']');
            out
        }
        other => serde_json::to_vec(other).unwrap_or_default(),
    }
}

/// Computes the deterministic SHA-256 ACS root over an active contract map (`contract_id -> event`).
pub fn compute_acs_state_root(active: &BTreeMap<String, ColdArchiveEvent>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_TAG_ACS_ROOT);
    hasher.update((active.len() as u64).to_be_bytes());
    for (cid, ev) in active {
        hasher.update(cid.as_bytes());
        hasher.push_sep();
        hasher.update(ev.template_id.as_bytes());
        hasher.push_sep();
        hasher.update(ev.payload_sha256.as_bytes());
        hasher.push_sep();
        for p in &ev.stakeholders {
            hasher.update(p.as_bytes());
            hasher.update(b",");
        }
        hasher.update(b";");
    }
    hex::encode(hasher.finalize())
}

trait HasherSepExt {
    fn push_sep(&mut self);
}

impl HasherSepExt for Sha256 {
    fn push_sep(&mut self) {
        self.update([0x1f]);
    }
}

struct SegmentDigestInput<'a> {
    format_version: u32,
    synchronizer_id: &'a str,
    participant_id: &'a str,
    source_kind: Option<ColdArchiveSourceKind>,
    from_offset: i64,
    to_offset: i64,
    prev_segment_sha256: Option<&'a str>,
    events: &'a [ColdArchiveEvent],
    acs_state_root_sha256: &'a str,
    signer_public_key_hex: Option<&'a str>,
}

fn compute_segment_digest(input: &SegmentDigestInput<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_TAG_COLD_SEGMENT);
    hasher.update(input.format_version.to_be_bytes());
    hasher.update(input.synchronizer_id.as_bytes());
    hasher.push_sep();
    hasher.update(input.participant_id.as_bytes());
    hasher.push_sep();
    hasher.update(input.from_offset.to_be_bytes());
    hasher.update(input.to_offset.to_be_bytes());
    hasher.update(input.prev_segment_sha256.unwrap_or("GENESIS").as_bytes());
    hasher.push_sep();
    hasher.update((input.events.len() as u64).to_be_bytes());
    for ev in input.events {
        hasher.update(ev.offset.to_be_bytes());
        hasher.update(ev.update_id.as_bytes());
        hasher.push_sep();
        hasher.update(ev.synchronizer_id.as_bytes());
        hasher.push_sep();
        hasher.update(ev.record_time_micros.to_be_bytes());
        let kind_byte = match ev.kind {
            ColdArchiveEventKind::Activate => 1u8,
            ColdArchiveEventKind::Deactivate => 2u8,
        };
        hasher.update([kind_byte]);
        hasher.update(ev.contract_id.as_bytes());
        hasher.push_sep();
        hasher.update(ev.template_id.as_bytes());
        hasher.push_sep();
        for s in &ev.stakeholders {
            hasher.update(s.as_bytes());
            hasher.update(b",");
        }
        hasher.push_sep();
        hasher.update(ev.payload_sha256.as_bytes());
        if let Some(pj) = &ev.payload_json {
            hasher.update(canonical_json_bytes(pj));
        }
        hasher.update(b"\n");
    }
    hasher.update(input.acs_state_root_sha256.as_bytes());
    hasher.push_sep();
    hasher.update(input.signer_public_key_hex.unwrap_or("UNSIGNED").as_bytes());
    // [CANTON-NOTE: INVARIANT] Append `0x1f || source_kind` ONLY when present so legacy segments lacking
    // `source_kind` keep their exact historical digest while newer segments commit provenance tamper-proofly.
    if let Some(source) = input.source_kind {
        hasher.push_sep();
        hasher.update(source.as_str().as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn validate_segment_events_and_root(
    from_offset: i64,
    to_offset: i64,
    events: &[ColdArchiveEvent],
) -> Result<String, ColdArchiveError> {
    if from_offset < 1 || from_offset > to_offset {
        return Err(ColdArchiveError::InvalidOffsetRange {
            from: from_offset,
            to: to_offset,
        });
    }
    let mut prev_off: Option<i64> = None;
    let mut active_in_seg: BTreeMap<String, ColdArchiveEvent> = BTreeMap::new();
    for ev in events {
        if ev.offset < from_offset || ev.offset > to_offset {
            return Err(ColdArchiveError::EventOutOfRange {
                offset: ev.offset,
                from: from_offset,
                to: to_offset,
            });
        }
        if let Some(po) = prev_off {
            if ev.offset < po {
                return Err(ColdArchiveError::NonMonotonicEventOffsets {
                    prev: po,
                    next: ev.offset,
                });
            }
        }
        prev_off = Some(ev.offset);
        match ev.kind {
            ColdArchiveEventKind::Activate => {
                active_in_seg.insert(ev.contract_id.clone(), ev.clone());
            }
            ColdArchiveEventKind::Deactivate => {
                active_in_seg.remove(&ev.contract_id);
            }
        }
    }
    Ok(compute_acs_state_root(&active_in_seg))
}

/// Builds, hashes, and optionally Ed25519-signs an immutable [`ColdArchiveSegment`].
pub fn build_cold_segment(
    spec: BuildSegmentSpec<'_>,
) -> Result<ColdArchiveSegment, ColdArchiveError> {
    let acs_state_root_sha256 =
        validate_segment_events_and_root(spec.from_offset, spec.to_offset, &spec.events)?;
    let signing_key = spec.signing_key_bytes.map(EdSigningKey::from_bytes);
    let signer_public_key_hex = signing_key
        .as_ref()
        .map(|sk| hex::encode(sk.verifying_key().to_bytes()));

    let segment_sha256 = compute_segment_digest(&SegmentDigestInput {
        format_version: COLD_ARCHIVE_FORMAT_VERSION,
        synchronizer_id: spec.synchronizer_id,
        participant_id: spec.participant_id,
        source_kind: spec.source_kind,
        from_offset: spec.from_offset,
        to_offset: spec.to_offset,
        prev_segment_sha256: spec.prev_segment_sha256.as_deref(),
        events: &spec.events,
        acs_state_root_sha256: &acs_state_root_sha256,
        signer_public_key_hex: signer_public_key_hex.as_deref(),
    });

    let ed25519_signature_hex =
        signing_key.map(|sk| hex::encode(sk.sign(segment_sha256.as_bytes()).to_bytes()));

    Ok(ColdArchiveSegment {
        format_version: COLD_ARCHIVE_FORMAT_VERSION,
        synchronizer_id: spec.synchronizer_id.to_string(),
        participant_id: spec.participant_id.to_string(),
        source_kind: spec.source_kind,
        from_offset: spec.from_offset,
        to_offset: spec.to_offset,
        prev_segment_sha256: spec.prev_segment_sha256,
        events_count: spec.events.len(),
        events: spec.events,
        acs_state_root_sha256,
        segment_sha256,
        signer_public_key_hex,
        ed25519_signature_hex,
    })
}

/// Verifies a single segment's SHA-256 digest, local ACS state root, and optional Ed25519 signature.
pub fn verify_single_segment(seg: &ColdArchiveSegment) -> Result<(), ColdArchiveError> {
    let recomputed_acs =
        validate_segment_events_and_root(seg.from_offset, seg.to_offset, &seg.events)?;
    let recomputed = compute_segment_digest(&SegmentDigestInput {
        format_version: seg.format_version,
        synchronizer_id: &seg.synchronizer_id,
        participant_id: &seg.participant_id,
        source_kind: seg.source_kind,
        from_offset: seg.from_offset,
        to_offset: seg.to_offset,
        prev_segment_sha256: seg.prev_segment_sha256.as_deref(),
        events: &seg.events,
        acs_state_root_sha256: &seg.acs_state_root_sha256,
        signer_public_key_hex: seg.signer_public_key_hex.as_deref(),
    });
    if recomputed != seg.segment_sha256
        || recomputed_acs != seg.acs_state_root_sha256
        || seg.events_count != seg.events.len()
    {
        return Err(ColdArchiveError::IntegrityMismatch {
            from: seg.from_offset,
            to: seg.to_offset,
            expected: seg.segment_sha256.clone(),
            actual: recomputed,
        });
    }

    match (&seg.signer_public_key_hex, &seg.ed25519_signature_hex) {
        (Some(pk_hex), Some(sig_hex)) => {
            let pk_bytes = hex::decode(pk_hex).map_err(|e| ColdArchiveError::SignatureInvalid {
                from: seg.from_offset,
                to: seg.to_offset,
                reason: format!("invalid public key hex: {e}"),
            })?;
            let pk_arr: [u8; 32] =
                pk_bytes
                    .try_into()
                    .map_err(|_| ColdArchiveError::SignatureInvalid {
                        from: seg.from_offset,
                        to: seg.to_offset,
                        reason: "Ed25519 public key must be 32 bytes".to_string(),
                    })?;
            let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| {
                ColdArchiveError::SignatureInvalid {
                    from: seg.from_offset,
                    to: seg.to_offset,
                    reason: format!("malformed Ed25519 public key: {e}"),
                }
            })?;
            let sig_bytes =
                hex::decode(sig_hex).map_err(|e| ColdArchiveError::SignatureInvalid {
                    from: seg.from_offset,
                    to: seg.to_offset,
                    reason: format!("invalid signature hex: {e}"),
                })?;
            let sig_arr: [u8; 64] =
                sig_bytes
                    .try_into()
                    .map_err(|_| ColdArchiveError::SignatureInvalid {
                        from: seg.from_offset,
                        to: seg.to_offset,
                        reason: "Ed25519 signature must be 64 bytes".to_string(),
                    })?;
            let sig = Signature::from_bytes(&sig_arr);
            vk.verify(seg.segment_sha256.as_bytes(), &sig)
                .map_err(|e| ColdArchiveError::SignatureInvalid {
                    from: seg.from_offset,
                    to: seg.to_offset,
                    reason: format!("signature check failed: {e}"),
                })?;
        }
        (None, None) => {}
        _ => {
            return Err(ColdArchiveError::SignatureInvalid {
                from: seg.from_offset,
                to: seg.to_offset,
                reason: "incomplete signer_public_key_hex / ed25519_signature_hex pair".to_string(),
            });
        }
    }
    Ok(())
}

/// Verifies hash-chain continuity, offset monotonicity, digests, and signatures across `segments`.
pub fn verify_archive_chain(
    segments: &[ColdArchiveSegment],
) -> Result<ArchiveVerifyReport, ColdArchiveError> {
    let mut expected_prev: Option<String> = None;
    let mut prev_to: Option<i64> = None;
    let mut total_events = 0usize;
    let mut signed_segments = 0usize;

    for seg in segments {
        verify_single_segment(seg)?;
        // the first segment must be the genesis one too: one pointing at a predecessor means the front was cut off
        if seg.prev_segment_sha256 != expected_prev {
            return Err(ColdArchiveError::BrokenHashChain {
                from: seg.from_offset,
                to: seg.to_offset,
                expected: expected_prev,
                actual: seg.prev_segment_sha256.clone(),
            });
        }
        if let Some(pt) = prev_to {
            if seg.from_offset != pt.saturating_add(1) {
                return Err(ColdArchiveError::DisjointOrOverlappingRange {
                    prev_to: pt,
                    next_from: seg.from_offset,
                });
            }
        }
        if seg.ed25519_signature_hex.is_some() {
            signed_segments += 1;
        }
        total_events += seg.events.len();
        expected_prev = Some(seg.segment_sha256.clone());
        prev_to = Some(seg.to_offset);
    }

    Ok(ArchiveVerifyReport {
        segments_verified: segments.len(),
        signed_segments,
        total_events,
        min_offset: segments.first().map(|s| s.from_offset),
        max_offset: segments.last().map(|s| s.to_offset),
        head_segment_sha256: expected_prev,
    })
}

/// Checks that every segment is signed by `expected_public_key_hex`, on top of [`verify_archive_chain`].
///
/// [CANTON-NOTE: WHY] A segment carries its own public key, so a valid signature alone only shows integrity; the
/// signer is known only when the verifier names the key it trusts.
pub fn verify_archive_signer(
    segments: &[ColdArchiveSegment],
    expected_public_key_hex: &str,
) -> Result<(), ColdArchiveError> {
    if segments.is_empty() {
        return Err(ColdArchiveError::SignatureInvalid {
            from: 0,
            to: 0,
            reason: "archive contains no segments to verify expected signer".to_string(),
        });
    }
    let expected = expected_public_key_hex.trim();
    for seg in segments {
        if !seg
            .signer_public_key_hex
            .as_deref()
            .is_some_and(|pk| pk.eq_ignore_ascii_case(expected))
        {
            return Err(ColdArchiveError::SignatureInvalid {
                from: seg.from_offset,
                to: seg.to_offset,
                reason: format!(
                    "not signed by the expected key {expected} (signer {:?})",
                    seg.signer_public_key_hex
                ),
            });
        }
    }
    Ok(())
}

/// Checks that `seg` carries verified PostgreSQL provenance, matches the target participant/synchronizer,
/// is signed by `spec.expected_signer_public_key_hex`, and contains non-redacted activation payloads.
pub(super) fn check_segment_prunable_provenance(
    seg: &ColdArchiveSegment,
    spec: &PruneCoverageSpec<'_>,
) -> Result<(), ColdArchiveError> {
    let refuse = |reason: String| Err(ColdArchiveError::NotPrunable { reason });
    match seg.source_kind {
        Some(ColdArchiveSourceKind::Pg) => {}
        Some(ColdArchiveSourceKind::Jsonl) => {
            return refuse(format!(
                "segment [{}..={}] was exported from JSONL rather than PostgreSQL",
                seg.from_offset, seg.to_offset
            ));
        }
        None => {
            return refuse(format!(
                "segment [{}..={}] has no source_kind provenance (legacy segment)",
                seg.from_offset, seg.to_offset
            ));
        }
    }
    if seg.participant_id != spec.expected_participant_id {
        return refuse(format!(
            "segment [{}..={}] participant_id '{}' does not match target participant '{}'",
            seg.from_offset, seg.to_offset, seg.participant_id, spec.expected_participant_id
        ));
    }
    if seg.synchronizer_id != spec.expected_synchronizer_id {
        return refuse(format!(
            "segment [{}..={}] synchronizer_id '{}' does not match target synchronizer '{}'",
            seg.from_offset, seg.to_offset, seg.synchronizer_id, spec.expected_synchronizer_id
        ));
    }
    if let Err(e) = verify_archive_signer(
        std::slice::from_ref(seg),
        spec.expected_signer_public_key_hex,
    ) {
        return refuse(format!(
            "segment [{}..={}] {e}",
            seg.from_offset, seg.to_offset
        ));
    }
    if let Some(ev) = seg
        .events
        .iter()
        .find(|e| e.kind == ColdArchiveEventKind::Activate && e.payload_json.is_none())
    {
        return refuse(format!(
            "activation of {} at offset {} has no contract body (zero-payload archive)",
            ev.contract_id, ev.offset
        ));
    }
    Ok(())
}

/// Refuses pruning up to `spec.prune_up_to` unless `segments` hold everything the prune deletes: a verified
/// PG-sourced chain covering `spec.expected_start..=spec.prune_up_to`, matching DB identity and expected signer,
/// whose every activation carries its contract body.
pub fn ensure_prunable_coverage_from(
    segments: &[ColdArchiveSegment],
    spec: &PruneCoverageSpec<'_>,
) -> Result<(), ColdArchiveError> {
    let refuse = |reason: String| Err(ColdArchiveError::NotPrunable { reason });
    let report = verify_archive_chain(segments)?;
    let start = spec.expected_start.max(1);
    // [CANTON-NOTE: INVARIANT] Pruning deletes every archived contract at or below the offset whatever segment window
    // asked for it, so the archive must start at `start` (offset 1, or the previously pruned boundary + 1) and every
    // overlapping segment must originate from the target PostgreSQL database under the trusted signing key.
    match (report.min_offset, report.max_offset) {
        (Some(min), Some(max)) if min <= start && max >= spec.prune_up_to => {}
        (min, max) => {
            return refuse(format!(
                "the archive covers {min:?}..={max:?}, not {start}..={}",
                spec.prune_up_to
            ))
        }
    }
    for seg in segments {
        if seg.to_offset >= start && seg.from_offset <= spec.prune_up_to {
            check_segment_prunable_provenance(seg, spec)?;
        }
    }
    Ok(())
}

/// Compatibility helper requiring coverage from offset `1..=spec.prune_up_to`.
pub fn ensure_prunable_coverage(
    segments: &[ColdArchiveSegment],
    spec: &PruneCoverageSpec<'_>,
) -> Result<(), ColdArchiveError> {
    let from_one = PruneCoverageSpec {
        expected_start: 1,
        ..*spec
    };
    ensure_prunable_coverage_from(segments, &from_one)
}
