use std::path::PathBuf;

use canton_participant::{
    AutomationJobState, Fingerprint, GovernanceAction, Namespace, PartyId, SpliceError,
    SpliceServiceHost, SvScanObservation,
};

fn sample_dar_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../../contracts/target/sample-contract.dar")
}

fn setup_splice_host(sv_count: usize) -> (SpliceServiceHost, Vec<PartyId>) {
    let ns = Namespace::new(Fingerprint::new(
        "1220abcd00001111222233334444555566667777888899990000111122223333",
    ));
    let dso = PartyId::new("DSO", ns.clone());
    let mut svs = Vec::new();
    for i in 1..=sv_count {
        svs.push(PartyId::new(format!("SV{i}"), ns.clone()));
    }
    let host = SpliceServiceHost::new(dso, svs.clone()).expect("create splice host");
    (host, svs)
}

#[test]
fn test_splice_native_dar_loading_and_package_alignment_at_k04_s08() {
    let (mut host, _) = setup_splice_host(4);
    let dar_path = sample_dar_path();

    let main_pkg_id = host
        .load_native_dar(&dar_path)
        .expect("load pinned sample-contract.dar without recompilation");

    assert_eq!(
        main_pkg_id,
        "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"
    );
    assert_eq!(host.loaded_dar_modules, vec!["AssetHolding".to_string()]);

    // AT-S08: Package alignment verification passes for exact package ID
    assert!(host
        .verify_package_alignment("splice-amulet", &main_pkg_id)
        .is_ok());

    // AT-S08: Mismatched package ID is rejected with PackageIdMismatch
    let mismatch = host.verify_package_alignment(
        "splice-amulet",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    assert!(matches!(
        mismatch,
        Err(SpliceError::PackageIdMismatch { .. })
    ));
}

#[test]
fn test_splice_sv_governance_voting_threshold_and_duplicate_rejection_at_s03() {
    // 4 SVs -> f = 1, governance_threshold(4) = ceil((4 + 1 + 1)/2) = 3
    let (mut host, svs) = setup_splice_host(4);
    assert_eq!(host.current_governance_threshold().unwrap(), 3);
    assert_eq!(host.current_f_plus_one_threshold(), 2);

    let prop = host
        .create_governance_proposal(
            "prop-round-2",
            svs[0].clone(),
            GovernanceAction::AdvanceMiningRound { next_round: 2 },
        )
        .unwrap();
    assert!(!prop.executed);
    assert_eq!(host.current_round.round_number, 1);

    // AT-S03: Duplicate vote by SV1 must be rejected
    let dup = host.cast_governance_vote("prop-round-2", svs[0].clone(), true);
    assert!(matches!(
        dup,
        Err(SpliceError::DuplicateGovernanceVote { .. })
    ));

    // AT-S03: Non-SV voter must be rejected
    let outsider = PartyId::new("Outsider", svs[0].namespace.clone());
    let unauth = host.cast_governance_vote("prop-round-2", outsider, true);
    assert!(matches!(unauth, Err(SpliceError::UnauthorizedSv(_))));

    // SV2 votes -> 2/3 votes, not yet executed
    let prop2 = host
        .cast_governance_vote("prop-round-2", svs[1].clone(), true)
        .unwrap();
    assert!(!prop2.executed);
    assert_eq!(host.current_round.round_number, 1);

    // SV3 votes -> 3/3 votes reaches threshold 3, executes round advancement to 2!
    let prop3 = host
        .cast_governance_vote("prop-round-2", svs[2].clone(), true)
        .unwrap();
    assert!(prop3.executed);
    assert_eq!(host.current_round.round_number, 2);
}

#[test]
fn test_splice_wallet_tap_transfer_deduplication_and_fees_at_s04_s05() {
    let (mut host, svs) = setup_splice_host(4);
    let ns = svs[0].namespace.clone();
    let alice = PartyId::new("Alice", ns.clone());
    let bob = PartyId::new("Bob", ns);

    // Tap 1,000.0 Amulet (10,000 tenths)
    let tap1 = host
        .wallet_tap("dedup-tap-1", alice.clone(), 10_000)
        .unwrap();
    assert_eq!(host.wallet_balance(&alice), 10_000);

    // AT-S05: Re-submitting the same deduplication_id returns the exact same tx without double-minting
    let tap1_retry = host
        .wallet_tap("dedup-tap-1", alice.clone(), 10_000)
        .unwrap();
    assert_eq!(tap1.tx_id, tap1_retry.tx_id);
    assert_eq!(host.wallet_balance(&alice), 10_000);

    // Transfer 2,000 tenths from Alice to Bob (1% fee = 20 tenths -> Alice pays 2,020 tenths)
    let xfer = host
        .wallet_transfer("dedup-xfer-1", alice.clone(), bob.clone(), 2_000)
        .unwrap();
    assert_eq!(xfer.fee_tenths, 20);
    assert_eq!(host.wallet_balance(&bob), 2_000);
    assert_eq!(host.wallet_balance(&alice), 7_980);

    // Retry transfer with same deduplication_id is idempotent
    let xfer_retry = host
        .wallet_transfer("dedup-xfer-1", alice.clone(), bob.clone(), 2_000)
        .unwrap();
    assert_eq!(xfer.tx_id, xfer_retry.tx_id);
    assert_eq!(host.wallet_balance(&bob), 2_000);
    assert_eq!(host.wallet_balance(&alice), 7_980);

    // Insufficient balance check
    let over_xfer = host.wallet_transfer("dedup-xfer-over", alice, bob, 8_000);
    assert!(matches!(
        over_xfer,
        Err(SpliceError::InsufficientBalance { .. })
    ));
}

#[test]
fn test_splice_validator_automation_crash_recovery_and_scan_pagination_bft_at_s01_s02_s06_s07() {
    let (mut host, svs) = setup_splice_host(4);
    let ns = svs[0].namespace.clone();
    let val1 = PartyId::new("Validator1", ns);
    host.onboard_validator(val1.clone());

    // AT-S01 & AT-S06: Simulate worker crash after ledger action commits but before job record completes
    let crashed_state = host
        .run_reward_collection_job("job-reward-r1", val1.clone(), 500, true)
        .unwrap();
    assert!(matches!(
        crashed_state,
        AutomationJobState::ActionCommittedBeforeJobRecord { .. }
    ));
    assert_eq!(host.wallet_balance(&val1), 500);

    // Worker restarts and retries the same job: idempotent deduplication recovers the tx and marks Completed without double-crediting
    let recovered_state = host
        .run_reward_collection_job("job-reward-r1", val1.clone(), 500, false)
        .unwrap();
    assert!(matches!(
        recovered_state,
        AutomationJobState::Completed { .. }
    ));
    assert_eq!(host.wallet_balance(&val1), 500);

    // Add two more wallet taps to test Scan pagination (AT-S07)
    host.wallet_tap("tap-p2", val1.clone(), 100).unwrap();
    host.wallet_tap("tap-p3", val1, 200).unwrap();

    let page1 = host.scan_transactions(None, 2).unwrap();
    assert_eq!(page1.items.len(), 2);
    assert_eq!(page1.total_count, 3);
    assert!(page1.next_cursor.is_some());

    let page2 = host.scan_transactions(page1.next_cursor, 2).unwrap();
    assert_eq!(page2.items.len(), 1);
    assert!(page2.next_cursor.is_none());

    // AT-S02: BFT Scan observation aggregation (4 SVs -> f+1 = 2 required)
    let valid_digest_r2 = SpliceServiceHost::compute_round_state_digest(2, 100).unwrap();
    let stale_digest_r1 = SpliceServiceHost::compute_round_state_digest(1, 100).unwrap();

    // 1 stale SV (round 1), 2 honest SVs on round 2, 1 Byzantine SV with forged digest
    let observations = vec![
        SvScanObservation {
            sv_party: svs[0].clone(),
            round_number: 1,
            state_digest: stale_digest_r1,
            amulet_price_usd_tenths: 100,
        },
        SvScanObservation {
            sv_party: svs[1].clone(),
            round_number: 2,
            state_digest: valid_digest_r2.clone(),
            amulet_price_usd_tenths: 100,
        },
        SvScanObservation {
            sv_party: svs[2].clone(),
            round_number: 2,
            state_digest: valid_digest_r2.clone(),
            amulet_price_usd_tenths: 100,
        },
        SvScanObservation {
            sv_party: svs[3].clone(),
            round_number: 99,
            state_digest: "1220deadbeef".to_string(),
            amulet_price_usd_tenths: 999,
        },
    ];

    let consensus_scan = host.aggregate_bft_scan_observations(&observations).unwrap();
    assert_eq!(consensus_scan.round_number, 2);
    assert_eq!(consensus_scan.state_digest, valid_digest_r2);

    // If all SVs conflict and no state reaches f+1 = 2, ScanQuorumFailed is returned
    let conflicting = vec![
        SvScanObservation {
            sv_party: svs[0].clone(),
            round_number: 1,
            state_digest: SpliceServiceHost::compute_round_state_digest(1, 100).unwrap(),
            amulet_price_usd_tenths: 100,
        },
        SvScanObservation {
            sv_party: svs[1].clone(),
            round_number: 2,
            state_digest: SpliceServiceHost::compute_round_state_digest(2, 110).unwrap(),
            amulet_price_usd_tenths: 110,
        },
    ];
    let failed = host.aggregate_bft_scan_observations(&conflicting);
    assert!(matches!(failed, Err(SpliceError::ScanQuorumFailed { .. })));
}
