use std::collections::BTreeSet;
use std::fs;

use ed25519_dalek::SigningKey as EdSigningKey;

use super::*;

fn sample_event(offset: i64, kind: ColdArchiveEventKind, cid: &str) -> ColdArchiveEvent {
    let mut stakeholders = BTreeSet::new();
    stakeholders.insert("Alice::1220abcd".to_string());
    let payload = match kind {
        ColdArchiveEventKind::Activate => {
            Some(serde_json::json!({ "amount": "100.0000000000", "owner": "Alice" }))
        }
        ColdArchiveEventKind::Deactivate => None,
    };
    let payload_sha256 = hash_payload_json(payload.as_ref());
    ColdArchiveEvent {
        offset,
        update_id: format!("tx-{offset}"),
        synchronizer_id: "sync-1".to_string(),
        record_time_micros: offset * 1_000,
        kind,
        contract_id: cid.to_string(),
        template_id: "Sample:Asset".to_string(),
        stakeholders,
        payload_json: payload,
        payload_sha256,
    }
}

#[test]
fn builds_verifies_and_replays_signed_cold_archive_chain() {
    let key = [7u8; 32];
    let seg1 = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 1,
        to_offset: 2,
        prev_segment_sha256: None,
        events: vec![
            sample_event(1, ColdArchiveEventKind::Activate, "cid-1"),
            sample_event(2, ColdArchiveEventKind::Activate, "cid-2"),
        ],
        signing_key_bytes: Some(&key),
    })
    .expect("build seg1");

    let seg2 = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 3,
        to_offset: 4,
        prev_segment_sha256: Some(seg1.segment_sha256.clone()),
        events: vec![
            sample_event(3, ColdArchiveEventKind::Deactivate, "cid-1"),
            sample_event(4, ColdArchiveEventKind::Activate, "cid-3"),
        ],
        signing_key_bytes: Some(&key),
    })
    .expect("build seg2");

    let chain = [seg1, seg2];
    let verify = verify_archive_chain(&chain).expect("chain must verify");
    assert_eq!(verify.segments_verified, 2);
    assert_eq!(verify.signed_segments, 2);
    assert_eq!(verify.total_events, 4);

    let replay = staged_replay(&chain, None).expect("staged replay");
    assert_eq!(replay.stages.len(), 4);
    // cid-1 was archived at offset 3; cid-2 and cid-3 remain active!
    assert_eq!(replay.active_contracts_count, 2);
    assert_eq!(replay.up_to_offset, 4);

    // Partial replay up to offset 2 must show cid-1 and cid-2 active (different commitment!).
    let partial = staged_replay(&chain, Some(2)).expect("partial replay");
    assert_eq!(partial.active_contracts_count, 2);
    assert_ne!(partial.acs_commitment_sha256, replay.acs_commitment_sha256);
}

#[test]
fn negative_controls_reject_tampered_digest_signature_chain_and_offsets() {
    let key = [9u8; 32];
    let seg1 = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 1,
        to_offset: 2,
        prev_segment_sha256: None,
        events: vec![sample_event(1, ColdArchiveEventKind::Activate, "cid-1")],
        signing_key_bytes: Some(&key),
    })
    .expect("seg1");

    // Negative control 1: Tampering with contract_id must fail IntegrityMismatch.
    let mut tampered_event = seg1.clone();
    tampered_event.events[0].contract_id = "cid-evil".to_string();
    assert!(matches!(
        verify_single_segment(&tampered_event),
        Err(ColdArchiveError::IntegrityMismatch { .. })
    ));

    // Negative control 2: Corrupting Ed25519 signature must fail SignatureInvalid.
    let mut tampered_sig = seg1.clone();
    tampered_sig.ed25519_signature_hex = Some("00".repeat(64));
    assert!(matches!(
        verify_single_segment(&tampered_sig),
        Err(ColdArchiveError::SignatureInvalid { .. })
    ));

    // Negative control 3: Wrong prev_segment_sha256 in seg2 must fail BrokenHashChain.
    let bad_seg2 = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 3,
        to_offset: 4,
        prev_segment_sha256: Some("deadbeef".repeat(8)),
        events: vec![sample_event(3, ColdArchiveEventKind::Activate, "cid-2")],
        signing_key_bytes: Some(&key),
    })
    .expect("bad_seg2");
    assert!(matches!(
        verify_archive_chain(&[seg1.clone(), bad_seg2]),
        Err(ColdArchiveError::BrokenHashChain { .. })
    ));

    // Negative control 4: a gap between segments (2 -> 5) and a chain whose first segment points at a missing one.
    let gap_seg = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 5,
        to_offset: 6,
        prev_segment_sha256: Some(seg1.segment_sha256.clone()),
        events: vec![sample_event(5, ColdArchiveEventKind::Activate, "cid-5")],
        signing_key_bytes: Some(&key),
    })
    .expect("gap_seg");
    assert!(matches!(
        verify_archive_chain(&[seg1, gap_seg.clone()]),
        Err(ColdArchiveError::DisjointOrOverlappingRange { .. })
    ));
    assert!(matches!(
        verify_archive_chain(std::slice::from_ref(&gap_seg)),
        Err(ColdArchiveError::BrokenHashChain { .. })
    ));

    // Negative control 5: Invalid offset range (from > to) rejected before side effects.
    assert!(matches!(
        build_cold_segment(BuildSegmentSpec {
            synchronizer_id: "sync-1",
            participant_id: "p1",
            source_kind: None,
            from_offset: 10,
            to_offset: 5,
            prev_segment_sha256: None,
            events: vec![],
            signing_key_bytes: None,
        }),
        Err(ColdArchiveError::InvalidOffsetRange { .. })
    ));
}

const CHAIN_TEST_KEY: [u8; 32] = [0x55u8; 32];

fn chain_test_pk_hex() -> String {
    hex::encode(
        EdSigningKey::from_bytes(&CHAIN_TEST_KEY)
            .verifying_key()
            .to_bytes(),
    )
}

fn chain_segment(
    from: i64,
    to: i64,
    prev: Option<&ColdArchiveSegment>,
    events: Vec<ColdArchiveEvent>,
) -> ColdArchiveSegment {
    build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: from,
        to_offset: to,
        prev_segment_sha256: prev.map(|p| p.segment_sha256.clone()),
        events,
        signing_key_bytes: Some(&CHAIN_TEST_KEY),
    })
    .expect("segment")
}

#[test]
fn expected_signer_rejects_other_keys_and_stripped_signatures() {
    let ours = [7u8; 32];
    let theirs = [8u8; 32];
    let ours_pk = hex::encode(EdSigningKey::from_bytes(&ours).verifying_key().to_bytes());
    let signed = |key: Option<&[u8; 32]>| {
        build_cold_segment(BuildSegmentSpec {
            synchronizer_id: "sync-1",
            participant_id: "p1",
            source_kind: Some(ColdArchiveSourceKind::Pg),
            from_offset: 1,
            to_offset: 1,
            prev_segment_sha256: None,
            events: vec![sample_event(1, ColdArchiveEventKind::Activate, "cid-1")],
            signing_key_bytes: key,
        })
        .expect("segment")
    };
    assert!(verify_archive_signer(&[], &ours_pk).is_err());
    verify_archive_signer(&[signed(Some(&ours))], &ours_pk).expect("our key");
    assert!(verify_archive_signer(&[signed(Some(&theirs))], &ours_pk).is_err());

    // Stripping both signature fields must invalidate the committed segment digest (`signer_public_key_hex` bound).
    let mut stripped = signed(Some(&ours));
    stripped.signer_public_key_hex = None;
    stripped.ed25519_signature_hex = None;
    assert!(matches!(
        verify_archive_chain(std::slice::from_ref(&stripped)),
        Err(ColdArchiveError::IntegrityMismatch { .. })
    ));
    assert!(verify_archive_signer(&[stripped], &ours_pk).is_err());
}

#[test]
fn streaming_verify_and_partial_replay_match_and_flag_incomplete_chains() {
    let dir = std::env::temp_dir().join(format!("canton_rs_cold_stream_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let key = [5u8; 32];
    let pk = hex::encode(EdSigningKey::from_bytes(&key).verifying_key().to_bytes());

    // Chain starting at offset 3 (missing 1..=2) must verify chain integrity yet flag replay as PARTIAL!
    let seg1 = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 3,
        to_offset: 4,
        prev_segment_sha256: None,
        events: vec![sample_event(3, ColdArchiveEventKind::Activate, "cid-3")],
        signing_key_bytes: Some(&key),
    })
    .expect("seg1");
    let seg2 = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 5,
        to_offset: 6,
        prev_segment_sha256: Some(seg1.segment_sha256.clone()),
        events: vec![sample_event(5, ColdArchiveEventKind::Activate, "cid-5")],
        signing_key_bytes: Some(&key),
    })
    .expect("seg2");
    write_segment_to_dir(&dir, &seg1).expect("write seg1");
    write_segment_to_dir(&dir, &seg2).expect("write seg2");

    let (rep, metas) = verify_archive_dir_streaming(&dir, Some(&pk)).expect("stream verify");
    assert_eq!(rep.segments_verified, 2);
    assert_eq!(metas.len(), 2);
    let stream_replay = staged_replay_dir_streaming(&dir, None).expect("stream replay");
    let mem_replay = staged_replay(&[seg1, seg2], None).expect("mem replay");
    assert!(stream_replay.is_partial);
    assert_eq!(stream_replay.from_offset, 3);
    assert_eq!(
        stream_replay.acs_commitment_sha256,
        mem_replay.acs_commitment_sha256
    );
    assert!(ensure_prunable_coverage_dir_streaming(
        &dir,
        &PruneCoverageSpec {
            expected_start: 1,
            prune_up_to: 6,
            expected_participant_id: "p1",
            expected_synchronizer_id: "sync-1",
            expected_signer_public_key_hex: &pk,
        }
    )
    .is_err());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn jsonl_history_without_offset_or_contract_id_is_refused() {
    let no_offset = r#"{"update_id":"u1","events":[{"CreatedEvent":{"contractId":"00aa","templateId":"M:T"}}]}"#;
    assert!(parse_jsonl_history_events(no_offset, 1, 10, false).is_err());
    let no_cid =
        r#"{"offset":1,"update_id":"u1","events":[{"ArchivedEvent":{"templateId":"M:T"}}]}"#;
    assert!(parse_jsonl_history_events(no_cid, 1, 10, false).is_err());
}

#[test]
fn pruning_needs_a_chain_from_offset_one_to_the_prune_offset_with_contract_bodies() {
    let seg1 = chain_segment(
        1,
        2,
        None,
        vec![sample_event(1, ColdArchiveEventKind::Activate, "cid-1")],
    );
    let seg2 = chain_segment(
        3,
        4,
        Some(&seg1),
        vec![sample_event(3, ColdArchiveEventKind::Deactivate, "cid-1")],
    );
    let pk = chain_test_pk_hex();
    let spec = |expected_start: i64, prune_up_to: i64| PruneCoverageSpec {
        expected_start,
        prune_up_to,
        expected_participant_id: "p1",
        expected_synchronizer_id: "sync-1",
        expected_signer_public_key_hex: &pk,
    };
    ensure_prunable_coverage(&[seg1.clone(), seg2.clone()], &spec(1, 4)).expect("full coverage");

    // the chain stops short of the prune offset
    assert!(ensure_prunable_coverage(std::slice::from_ref(&seg1), &spec(1, 4)).is_err());
    // when earlier offsets were not pruned yet, missing 1..=2 must be rejected even if start > 1
    assert!(ensure_prunable_coverage_from(std::slice::from_ref(&seg2), &spec(1, 4)).is_err());
    // when offsets 1..=2 were already archived/pruned, starting at offset 3 satisfies expected_start = 3
    let late = chain_segment(
        3,
        4,
        None,
        vec![sample_event(3, ColdArchiveEventKind::Activate, "cid-3")],
    );
    assert!(ensure_prunable_coverage(std::slice::from_ref(&late), &spec(1, 4)).is_err());
    ensure_prunable_coverage_from(&[late], &spec(3, 4)).expect("expected_start = 3");
    // an activation without its contract body (zero-payload) cannot be restored after pruning
    let mut bodiless = sample_event(1, ColdArchiveEventKind::Activate, "cid-1");
    bodiless.payload_json = None;
    let zero = chain_segment(1, 2, None, vec![bodiless]);
    let err = ensure_prunable_coverage(&[zero], &spec(1, 2)).expect_err("bodiless activation");
    assert!(err.to_string().contains("cid-1"), "{err}");
}

#[test]
fn prune_coverage_rejects_jsonl_participant_unsigned_and_other_signer() {
    let key_a = [0x11u8; 32];
    let key_b = [0x22u8; 32];
    let pk_a = hex::encode(EdSigningKey::from_bytes(&key_a).verifying_key().to_bytes());
    let spec = PruneCoverageSpec {
        expected_start: 1,
        prune_up_to: 4,
        expected_participant_id: "p1",
        expected_synchronizer_id: "sync-1",
        expected_signer_public_key_hex: &pk_a,
    };
    let tmp = std::env::temp_dir().join(format!("canton_rs_r3_prov_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);

    // 1. Unsigned PG segment refused (in-memory & streaming dir)
    let unsigned_dir = tmp.join("unsigned");
    let unsigned = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 1,
        to_offset: 4,
        prev_segment_sha256: None,
        events: vec![sample_event(1, ColdArchiveEventKind::Activate, "cid-1")],
        signing_key_bytes: None,
    })
    .expect("build unsigned");
    write_segment_to_dir(&unsigned_dir, &unsigned).expect("write unsigned");
    let err = ensure_prunable_coverage_dir_streaming(&unsigned_dir, &spec)
        .expect_err("unsigned segment must be refused for pruning");
    assert!(
        matches!(err, ColdArchiveError::NotPrunable { .. }),
        "{err:?}"
    );

    // 2. JSONL segment covering [1..=2] + PG segment covering [3..=4], both signed by key_a
    let jsonl_dir = tmp.join("jsonl_mixed");
    let seg_jsonl = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Jsonl),
        from_offset: 1,
        to_offset: 2,
        prev_segment_sha256: None,
        events: vec![sample_event(1, ColdArchiveEventKind::Activate, "cid-1")],
        signing_key_bytes: Some(&key_a),
    })
    .expect("build jsonl seg");
    let seg_pg2 = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 3,
        to_offset: 4,
        prev_segment_sha256: Some(seg_jsonl.segment_sha256.clone()),
        events: vec![sample_event(3, ColdArchiveEventKind::Activate, "cid-3")],
        signing_key_bytes: Some(&key_a),
    })
    .expect("build pg seg2");
    write_segment_to_dir(&jsonl_dir, &seg_jsonl).expect("write jsonl");
    assert!(matches!(
        ensure_existing_segments_prunable_provenance(&jsonl_dir, &spec),
        Err(ColdArchiveError::NotPrunable { .. })
    ));
    write_segment_to_dir(&jsonl_dir, &seg_pg2).expect("write pg2");
    assert!(matches!(
        ensure_prunable_coverage_dir_streaming(&jsonl_dir, &spec),
        Err(ColdArchiveError::NotPrunable { .. })
    ));

    // Tamper JSONL -> "pg" in serialized JSON must fail digest check
    let mut forged_jsonl = seg_jsonl;
    forged_jsonl.source_kind = Some(ColdArchiveSourceKind::Pg);
    assert!(matches!(
        verify_single_segment(&forged_jsonl),
        Err(ColdArchiveError::IntegrityMismatch { .. })
    ));

    // 3. Mismatched participant_id (PG, signed by key_a)
    let other_p = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "other-p",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 1,
        to_offset: 4,
        prev_segment_sha256: None,
        events: vec![sample_event(1, ColdArchiveEventKind::Activate, "cid-1")],
        signing_key_bytes: Some(&key_a),
    })
    .expect("other participant");
    assert!(matches!(
        ensure_prunable_coverage(&[other_p], &spec),
        Err(ColdArchiveError::NotPrunable { .. })
    ));

    // 4. Mismatched synchronizer_id (PG, signed by key_a)
    let other_sync = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "other-sync",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 1,
        to_offset: 4,
        prev_segment_sha256: None,
        events: vec![sample_event(1, ColdArchiveEventKind::Activate, "cid-1")],
        signing_key_bytes: Some(&key_a),
    })
    .expect("other sync");
    assert!(matches!(
        ensure_prunable_coverage(&[other_sync], &spec),
        Err(ColdArchiveError::NotPrunable { .. })
    ));

    // 5. Signed by another key (key_b) when expecting key_a
    let other_signer = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 1,
        to_offset: 4,
        prev_segment_sha256: None,
        events: vec![sample_event(1, ColdArchiveEventKind::Activate, "cid-1")],
        signing_key_bytes: Some(&key_b),
    })
    .expect("other signer");
    assert!(matches!(
        ensure_prunable_coverage(&[other_signer], &spec),
        Err(ColdArchiveError::NotPrunable { .. })
    ));

    // 6. Legacy segment without `source_kind`: verify succeeds for read/replay compatibility, prune refuses
    let legacy_dir = tmp.join("legacy");
    let legacy_seg = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: None,
        from_offset: 1,
        to_offset: 4,
        prev_segment_sha256: None,
        events: vec![sample_event(1, ColdArchiveEventKind::Activate, "cid-1")],
        signing_key_bytes: Some(&key_a),
    })
    .expect("legacy");
    write_segment_to_dir(&legacy_dir, &legacy_seg).expect("write legacy");
    let (legacy_rep, _) = verify_archive_dir_streaming(&legacy_dir, Some(&pk_a))
        .expect("legacy segment lacking source_kind must still pass verification");
    assert_eq!(legacy_rep.segments_verified, 1);
    assert!(matches!(
        ensure_prunable_coverage_dir_streaming(&legacy_dir, &spec),
        Err(ColdArchiveError::NotPrunable { .. })
    ));

    // 7. Positive control: two chained PG segments matching identity + key_a pass both checks
    let good_dir = tmp.join("good_pg");
    let good1 = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 1,
        to_offset: 2,
        prev_segment_sha256: None,
        events: vec![sample_event(1, ColdArchiveEventKind::Activate, "cid-1")],
        signing_key_bytes: Some(&key_a),
    })
    .expect("good1");
    let good2 = build_cold_segment(BuildSegmentSpec {
        synchronizer_id: "sync-1",
        participant_id: "p1",
        source_kind: Some(ColdArchiveSourceKind::Pg),
        from_offset: 3,
        to_offset: 4,
        prev_segment_sha256: Some(good1.segment_sha256.clone()),
        events: vec![sample_event(3, ColdArchiveEventKind::Deactivate, "cid-1")],
        signing_key_bytes: Some(&key_a),
    })
    .expect("good2");
    write_segment_to_dir(&good_dir, &good1).expect("write good1");
    ensure_existing_segments_prunable_provenance(&good_dir, &spec)
        .expect("good existing PG segment passes preflight");
    write_segment_to_dir(&good_dir, &good2).expect("write good2");
    ensure_prunable_coverage_dir_streaming(&good_dir, &spec)
        .expect("positive control PG chain must be prunable");

    let _ = fs::remove_dir_all(&tmp);
}
