//! PostgreSQL integration test for `ord_*` persistence and recovery (`OrdStore`).
//!
//! Runs when `CANTON_RS_ORD_PG_TEST_URL` points at a reachable PostgreSQL database; returns immediately when unset so default unit runs stay offline.

use std::collections::BTreeMap;

use canton_bft_orderer::blacklist::{PolicyState, Status};
use canton_sequencer_server::ord_store::{
    OrdEpoch, OrdOutputBlock, OrdP2pEndpoint, OrdPruningSchedule, OrdStore,
};

static PG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn truncate_ord_tables(url: &str) {
    let target = canton_participant::pgconn::PgTarget::from_url_or_jdbc(url, None, None, None)
        .expect("target");
    let mut client = canton_participant::pgconn::connect_with_retry(
        &target,
        canton_participant::pgconn::RetryPolicy::from_env(),
    )
    .expect("direct pg");
    client
        .batch_execute(
            "TRUNCATE ord_epochs, ord_availability_batch, ord_pbft_messages_in_progress, \
             ord_pbft_messages_completed, ord_metadata_output_blocks, ord_metadata_output_epochs, \
             ord_leader_selection_state, ord_output_lower_bound, ord_pruning_schedules, ord_p2p_endpoints;",
        )
        .expect("truncate");
}

#[test]
fn ord_store_round_trips_epochs_batches_pbft_policy_and_output_in_postgres() {
    let Ok(url) = std::env::var("CANTON_RS_ORD_PG_TEST_URL") else {
        return;
    };
    let _guard = PG_TEST_LOCK.lock().expect("pg lock");
    {
        let _ensure = OrdStore::connect(&url).expect("connect OrdStore");
    }
    truncate_ord_tables(&url);
    let nodes = vec![
        "SEQ::seq1::1220aa".to_string(),
        "SEQ::seq2::1220bb".to_string(),
        "SEQ::seq3::1220cc".to_string(),
        "SEQ::seq4::1220dd".to_string(),
    ];

    {
        let store = OrdStore::connect(&url).expect("connect OrdStore");
        store.start_epoch(OrdEpoch {
            epoch_number: 0,
            start_block_number: 0,
            epoch_length: 20,
            topology_ts: 1_000,
            in_progress: true,
        });
        store.save_batch(b"\x01\x02\x03", 0, b"batch-0".to_vec());
        store.save_pbft_in_progress(0, 0, 0, 0, nodes[0].clone(), b"pp-0".to_vec());
        store.save_pbft_completed(0, 0, 0, nodes[0].clone(), b"pp-0".to_vec());
        store.save_pbft_completed(0, 0, 2, nodes[1].clone(), b"c-0-1".to_vec());
        store.save_output_block(0, 0, 2_000);
        store.save_output_epoch(0, false);
        store.complete_epoch(0);

        store.start_epoch(OrdEpoch {
            epoch_number: 1,
            start_block_number: 20,
            epoch_length: 20,
            topology_ts: 3_000,
            in_progress: true,
        });
        let mut blacklist = BTreeMap::new();
        blacklist.insert(
            nodes[2].clone(),
            Status::Blacklisted {
                failed_attempts_before: 1,
                epochs_left_until_new_trial: 2,
            },
        );
        store.save_leader_policy(&PolicyState {
            epoch_number: 1,
            start_block: 20,
            blacklist,
            nodes: nodes.clone(),
            epoch_length: 20,
        });
        store.save_batch(b"\x04\x05\x06", 1, b"batch-1".to_vec());
        store.save_pbft_in_progress(20, 1, 0, 0, nodes[0].clone(), b"pp-20".to_vec());
        store.save_output_block(1, 20, 4_000);
        store.save_output_epoch(1, true);
        store.flush().expect("flush ord_* writes");
    }

    let reopened = OrdStore::connect(&url).expect("reconnect OrdStore");
    let rec = reopened
        .load_recovery_state(nodes.clone(), 20)
        .expect("load recovery state");

    assert_eq!(
        rec.latest_epoch,
        Some(OrdEpoch {
            epoch_number: 1,
            start_block_number: 20,
            epoch_length: 20,
            topology_ts: 3_000,
            in_progress: true,
        })
    );
    let policy = rec.leader_policy.expect("leader policy");
    assert_eq!(policy.epoch_number, 1);
    assert_eq!(policy.start_block, 20);
    assert_eq!(
        policy.blacklist.get(&nodes[2]),
        Some(&Status::Blacklisted {
            failed_attempts_before: 1,
            epochs_left_until_new_trial: 2,
        })
    );
    assert_eq!(
        rec.pbft_messages,
        vec![b"pp-0".to_vec(), b"c-0-1".to_vec(), b"pp-20".to_vec()]
    );
    assert_eq!(rec.batches.len(), 2);
    assert_eq!(
        rec.last_output_block,
        Some(OrdOutputBlock {
            epoch_number: 1,
            block_number: 20,
            bft_ts: 4_000,
        })
    );
    assert_eq!(rec.last_epoch_could_alter_topology, Some((1, true)));
}

#[test]
fn ord_store_pruning_schedules_and_p2p_endpoints_in_postgres() {
    let Ok(url) = std::env::var("CANTON_RS_ORD_PG_TEST_URL") else {
        return;
    };
    let _guard = PG_TEST_LOCK.lock().expect("pg lock");
    let store = OrdStore::connect(&url).expect("connect OrdStore");
    store.flush().expect("flush schema");

    truncate_ord_tables(&url);
    {
        let target = canton_participant::pgconn::PgTarget::from_url_or_jdbc(&url, None, None, None)
            .expect("target");
        let mut client = canton_participant::pgconn::connect_with_retry(
            &target,
            canton_participant::pgconn::RetryPolicy::from_env(),
        )
        .expect("direct pg");
        let hist: i64 = client
            .query_one("SELECT COUNT(*) FROM ord_partition_size_history", &[])
            .expect("partition history")
            .get(0);
        assert!(hist >= 1, "default partition history row must be seeded");
    }

    // Seed 3 epochs (0: blocks 0..=1 @ ts 1_000..=2_000, 1: blocks 2..=3 @ ts 3_000..=4_000, 2: blocks 4..=5 @ ts 10_000..=11_000)
    for ep in 0..=2_i64 {
        store.start_epoch(OrdEpoch {
            epoch_number: ep,
            start_block_number: ep * 2,
            epoch_length: 2,
            topology_ts: 1_000 * (ep + 1),
            in_progress: ep == 2,
        });
        if ep < 2 {
            store.complete_epoch(ep);
        }
        store.save_batch(&[ep as u8; 4], ep, format!("b-{ep}").into_bytes());
        store.save_pbft_completed(ep * 2, ep, 0, "SEQ::s1::1".into(), b"pp".to_vec());
        store.save_output_epoch(ep, false);
    }
    for (ep, blk, ts) in [
        (0, 0, 1_000),
        (0, 1, 2_000),
        (1, 2, 3_000),
        (1, 3, 4_000),
        (2, 4, 10_000),
        (2, 5, 11_000),
    ] {
        store.save_output_block(ep, blk, ts);
    }
    store.flush().expect("flush seed");

    let st0 = store.pruning_status().expect("status before prune");
    assert_eq!(st0.latest_block_epoch, 2);
    assert_eq!(st0.latest_block, 5);
    assert_eq!(st0.latest_block_ts_micros, Some(11_000));
    assert_eq!(st0.lower_bound_epoch, 0);

    // Retention = 7_500 us (cutoff = 3_500 -> block1 in epoch 1), min_blocks_to_keep = 3 (block2 = 2 -> epoch 1)
    let msg = store.prune(7_500, 3).expect("prune");
    assert!(
        msg.contains("Pruning at epoch 1 complete"),
        "unexpected msg: {msg}"
    );

    let st1 = store.pruning_status().expect("status after prune");
    assert_eq!(st1.lower_bound_epoch, 1);
    assert_eq!(st1.lower_bound_block, 2);

    // Too many min_blocks_to_keep refuses without mutating lower_bound
    let skip_msg = store.prune(7_500, 99).expect("prune refusal");
    assert!(skip_msg.contains("not enough blocks"));

    // Schedule CRUD
    assert_eq!(store.get_bft_schedule().expect("get empty"), None);
    store
        .set_bft_schedule(OrdPruningSchedule {
            cron: "0 0 * * * ?".into(),
            max_duration_secs: 60,
            retention_secs: 3600,
            min_blocks_to_keep: 100,
        })
        .expect("set schedule");
    store.update_cron("0 */5 * * * ?".into()).expect("cron");
    store.update_max_duration(120).expect("max_duration");
    store.update_retention(7200).expect("retention");
    store.update_min_blocks_to_keep(42).expect("min blocks");
    let sched = store
        .get_bft_schedule()
        .expect("get schedule")
        .expect("some");
    assert_eq!(
        sched,
        OrdPruningSchedule {
            cron: "0 */5 * * * ?".into(),
            max_duration_secs: 120,
            retention_secs: 7200,
            min_blocks_to_keep: 42,
        }
    );
    store.clear_schedule().expect("clear");
    assert_eq!(store.get_bft_schedule().expect("get cleared"), None);
    assert!(store.update_cron("0 0 * * * ?".into()).is_err());

    // P2P endpoints CRUD (incl. node_id)
    let ep = OrdP2pEndpoint {
        address: "127.0.0.1".into(),
        port: 31031,
        transport_security: true,
        custom_server_trust_certificates: Some(b"PEM-CA".to_vec()),
        client_certificate_chain: Some(b"PEM-CERT".to_vec()),
        client_private_key_file: Some("/tmp/client.key".into()),
        node_id: None,
    };
    assert!(store.add_endpoint(ep.clone()).expect("add 1"));
    assert!(!store.add_endpoint(ep).expect("duplicate"));
    store
        .set_endpoint_node_id(
            "127.0.0.1".into(),
            31031,
            true,
            Some("SEQ::s2::1220bb".into()),
        )
        .expect("set node_id");
    let listed = store.list_endpoints().expect("list endpoints");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].node_id.as_deref(), Some("SEQ::s2::1220bb"));
    assert!(store
        .remove_endpoint("127.0.0.1".into(), 31031, true)
        .expect("remove 1"));
    assert!(!store
        .remove_endpoint("127.0.0.1".into(), 31031, true)
        .expect("remove missing"));
}
