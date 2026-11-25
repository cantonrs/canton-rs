//! E2E integration tests for `S-DX-004` (`S-01`..`S-08`, `S-10` + `S-A1`..`S-A7`):
//! - `S-01`: Create 20 contracts, archive 5, snapshot (`0600`), create 10 more & archive 3, restore `--force` -> `obs(restore) == obs(t)` on BOTH `p1` and `p2`.
//! - `S-02`: `obs(Σ_after_snapshot) == obs(Σ_t)` (source invariance).
//! - `S-03`: Post-restore create, exercise (`Transfer`), and archive (`Settle`) succeed with zero CID overlap against `CIDs(Σ_t)`.
//! - `S-04`: Restore `a`'s snapshot into new instance `b` while `a` stays running -> `obs(b) == obs(a_t)` and `ports(a) ∩ ports(b) == ∅`.
//! - `S-05`: 1-byte corruption in `stores/registry/instance.json` (`manifest_hash`) OR `stores/participant-p1-journals/updates.journal` -> `exit = 3` and `M` unchanged.
//! - `S-06`: Removing each component in `Stores(I)` one at a time (with recomputed valid `manifest_hash`) causes restore `exit != 0` and rolls back `M` intact.
//! - `S-07`: Version mismatch in `snapshot.json` -> `exit = 2` and `M` unchanged.
//! - `S-08`: Restoring the same bundle twice yields identical `obs`.
//! - `S-10`: In-flight command exceeding `--quiesce-timeout-secs` aborts snapshot with `exit = 3`, resumes every node (`quiesced == false`), writes no bundle, and resumes command processing.

#![allow(clippy::unwrap_used, reason = "integration test")]

mod helpers;

use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use helpers::{
    allocate_party, capture_obs, confirm_dar, create_holding, http_json, http_send,
    repack_tar_from, seed_rich_workload, settle_holding, strip_component_from_bundle, submit_tx,
    unpack_tar_to, wait_acs_len, wait_topology_settle, InstancesGuard, MirrorManifest,
    ASSET_TEMPLATE, HELD_TEMPLATE, SNAPSHOT_TEST_LOCK,
};

#[test]
fn s01_basic_roundtrip() {
    let _lock = SNAPSHOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = InstancesGuard::new("s01");
    let ep = g.start_stack("a", None);
    let (alice, _auditor, bob, remaining) = seed_rich_workload(&ep);

    let obs_t = capture_obs(&ep);
    assert_eq!(obs_t.p1.acs.len(), 15);
    assert_eq!(obs_t.p2.acs.len(), 15);
    assert!(obs_t.p1.users.iter().any(|(id, _, _)| id == "dev-user"));
    assert!(obs_t.p2.users.iter().any(|(id, _, _)| id == "dev-user"));

    let snap = g.root.join("s01-snap.tar");
    let snap_out = g.run_checked(&[
        "daemon",
        "snapshot",
        "--name",
        "a",
        "--out",
        snap.to_str().expect("snap str"),
        "--format",
        "json",
    ]);
    let report: Value = serde_json::from_slice(&snap_out.stdout).expect("snapshot report json");
    assert!(report["component_count"].as_u64().unwrap_or(0) >= 8);
    assert!(snap.is_file());
    #[cfg(unix)]
    {
        let mode = fs::metadata(&snap).expect("snap stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "snapshot tar must have mode 0600");
    }

    let ep_after_snap = g.wait_ready("a");
    for i in 0..10 {
        let _ = create_holding(
            &ep_after_snap.p1_url,
            &format!("drift-c-{i}"),
            &alice,
            &alice,
            &bob,
            "77.0",
        );
    }
    for (idx, cid) in remaining.iter().take(3).enumerate() {
        settle_holding(
            &ep_after_snap.p1_url,
            &format!("drift-a-{idx}"),
            &alice,
            cid,
        );
    }
    wait_acs_len(&ep_after_snap.p1_url, &alice, 22);
    wait_acs_len(&ep_after_snap.p2_url, &bob, 22);
    assert_ne!(capture_obs(&ep_after_snap), obs_t);

    g.run_checked(&[
        "daemon",
        "restore",
        "--name",
        "a",
        "--from",
        snap.to_str().expect("snap str"),
        "--force",
        "--format",
        "json",
    ]);
    let ep_restored = g.wait_ready("a");
    let obs_restored = capture_obs(&ep_restored);
    assert_eq!(
        obs_restored, obs_t,
        "S-A1 failed across p1/p2 after restore"
    );
}

#[test]
fn s02_source_invariant() {
    let _lock = SNAPSHOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = InstancesGuard::new("s02");
    let ep = g.start_stack("a", None);
    let alice = allocate_party(&ep.p1_url, "Alice");
    let bob = allocate_party(&ep.p2_url, "Bob");
    wait_topology_settle();

    let mut cids = Vec::new();
    for i in 0..5 {
        cids.push(create_holding(
            &ep.p1_url,
            &format!("s02-c-{i}"),
            &alice,
            &alice,
            &bob,
            "10.0",
        ));
    }
    settle_holding(&ep.p1_url, "s02-a-0", &alice, &cids[0]);
    settle_holding(&ep.p1_url, "s02-a-1", &alice, &cids[1]);
    wait_acs_len(&ep.p1_url, &alice, 3);
    wait_acs_len(&ep.p2_url, &bob, 3);

    let obs_before = capture_obs(&ep);
    let snap = g.root.join("s02-snap.tar");
    g.run_checked(&[
        "daemon",
        "snapshot",
        "--name",
        "a",
        "--out",
        snap.to_str().expect("snap str"),
    ]);
    let ep_after = g.wait_ready("a");
    let obs_after = capture_obs(&ep_after);
    assert_eq!(obs_after, obs_before, "S-A2 source invariance failed");
}

#[test]
fn s03_post_restore_progress() {
    let _lock = SNAPSHOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = InstancesGuard::new("s03");
    let ep = g.start_stack("a", None);
    let alice = allocate_party(&ep.p1_url, "Alice");
    let alice2 = allocate_party(&ep.p1_url, "AliceTwo");
    let bob = allocate_party(&ep.p2_url, "Bob");
    wait_topology_settle();

    let mut cids_t = BTreeSet::new();
    for i in 0..5 {
        let cid = create_holding(
            &ep.p1_url,
            &format!("s03-c-{i}"),
            &alice,
            &alice,
            &bob,
            "20.0",
        );
        cids_t.insert(cid);
    }
    let first_cid = cids_t.iter().next().expect("first cid").clone();
    settle_holding(&ep.p1_url, "s03-a-0", &alice, &first_cid);
    wait_acs_len(&ep.p1_url, &alice, 4);
    wait_acs_len(&ep.p2_url, &bob, 4);

    let snap = g.root.join("s03-snap.tar");
    g.run_checked(&[
        "daemon",
        "snapshot",
        "--name",
        "a",
        "--out",
        snap.to_str().expect("snap str"),
    ]);

    let ep_live = g.wait_ready("a");
    let _ = create_holding(&ep_live.p1_url, "s03-drift-1", &alice, &alice, &bob, "5.0");
    let _ = create_holding(&ep_live.p1_url, "s03-drift-2", &alice, &alice, &bob, "6.0");

    g.run_checked(&[
        "daemon",
        "restore",
        "--name",
        "a",
        "--from",
        snap.to_str().expect("snap str"),
        "--force",
    ]);
    let ep_res = g.wait_ready("a");

    let new_cid = create_holding(
        &ep_res.p1_url,
        "s03-post-create",
        &alice,
        &alice2,
        &bob,
        "99.0",
    );
    assert!(!cids_t.contains(&new_cid), "new created cid overlapped Σ_t");

    let transfer_req = json!({
        "commands": {
            "commands": [{
                "ExerciseCommand": {
                    "templateId": ASSET_TEMPLATE,
                    "contractId": new_cid,
                    "choice": "Transfer",
                    "choiceArgument": { "newOwner": alice }
                }
            }],
            "commandId": "s03-post-transfer",
            "actAs": [&alice2],
            "userId": "participant_admin"
        },
        "transactionFormat": {
            "eventFormat": {
                "filtersByParty": {
                    &alice: {
                        "cumulative": [{
                            "identifierFilter": {
                                "WildcardFilter": {"value": {"includeCreatedEventBlob": false}}
                            }
                        }]
                    }
                },
                "verbose": false
            },
            "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
        }
    });
    let (t_code, t_resp) = http_json(
        &ep_res.p1_url,
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        Some(&transfer_req),
    );
    assert_eq!(t_code, 200, "s03 Transfer failed ({t_code}): {t_resp}");
    let transferred_cid = t_resp["transaction"]["events"]
        .as_array()
        .expect("Transfer events")
        .iter()
        .find_map(|e| {
            e.pointer("/CreatedEvent/contractId")
                .and_then(Value::as_str)
        })
        .expect("Transfer created cid")
        .to_string();
    assert!(
        !cids_t.contains(&transferred_cid),
        "exercised cid overlapped Σ_t"
    );

    settle_holding(&ep_res.p1_url, "s03-post-settle", &alice, &transferred_cid);
    wait_acs_len(&ep_res.p1_url, &alice, 4);
    wait_acs_len(&ep_res.p2_url, &bob, 4);
}

#[test]
fn s04_restore_to_different_name() {
    let _lock = SNAPSHOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = InstancesGuard::new("s04");
    let ep_a = g.start_stack("a", None);
    let alice = allocate_party(&ep_a.p1_url, "Alice");
    let bob = allocate_party(&ep_a.p2_url, "Bob");
    wait_topology_settle();

    let mut cids = Vec::new();
    for i in 0..4 {
        cids.push(create_holding(
            &ep_a.p1_url,
            &format!("s04-c-{i}"),
            &alice,
            &alice,
            &bob,
            "15.0",
        ));
    }
    settle_holding(&ep_a.p1_url, "s04-a-0", &alice, &cids[0]);
    wait_acs_len(&ep_a.p1_url, &alice, 3);
    wait_acs_len(&ep_a.p2_url, &bob, 3);

    let obs_a_t = capture_obs(&ep_a);
    let snap = g.root.join("s04-snap.tar");
    g.run_checked(&[
        "daemon",
        "snapshot",
        "--name",
        "a",
        "--out",
        snap.to_str().expect("snap str"),
    ]);
    let ep_a_after = g.wait_ready("a");

    g.track("b");
    g.run_checked(&[
        "daemon",
        "restore",
        "--name",
        "b",
        "--from",
        snap.to_str().expect("snap str"),
    ]);
    let ep_b = g.wait_ready("b");

    let status_a = g.status_json("a");
    let status_b = g.status_json("b");
    assert_eq!(status_a["instance"], "a");
    assert_eq!(status_b["instance"], "b");
    for ep_key in ["s1.public", "s1.metrics", "m1.admin", "p1.json", "p2.json"] {
        assert_eq!(status_a["endpoints"][ep_key]["state"], "up", "a.{ep_key}");
        assert_eq!(status_b["endpoints"][ep_key]["state"], "up", "b.{ep_key}");
    }

    assert_eq!(capture_obs(&ep_b), obs_a_t, "obs(b) != obs(a_t)");
    assert!(!ep_a_after.ports.is_empty() && !ep_b.ports.is_empty());
    let overlap: Vec<u16> = ep_a_after
        .ports
        .intersection(&ep_b.ports)
        .copied()
        .collect();
    assert!(overlap.is_empty(), "ports(a) ∩ ports(b) != ∅: {overlap:?}");
}

#[test]
fn s05_corrupt_bundle_rejected() {
    let _lock = SNAPSHOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = InstancesGuard::new("s05");
    let ep = g.start_stack("a", None);
    let alice = allocate_party(&ep.p1_url, "Alice");
    let bob = allocate_party(&ep.p2_url, "Bob");
    wait_topology_settle();
    let _ = create_holding(&ep.p1_url, "s05-seed", &alice, &alice, &bob, "10.0");
    wait_acs_len(&ep.p2_url, &bob, 1);

    let snap = g.root.join("s05-snap.tar");
    g.run_checked(&[
        "daemon",
        "snapshot",
        "--name",
        "a",
        "--out",
        snap.to_str().expect("snap str"),
    ]);

    let ep_live = g.wait_ready("a");
    let _ = create_holding(
        &ep_live.p1_url,
        "s05-live-extra",
        &alice,
        &alice,
        &bob,
        "50.0",
    );
    wait_acs_len(&ep_live.p2_url, &bob, 2);
    let obs_live = capture_obs(&ep_live);

    // 1. Corrupt 1 hex digit of manifest_hash in stores/registry/instance.json (valid JSON)
    let unpack1 = g.root.join("unpack-reg");
    unpack_tar_to(&snap, &unpack1);
    let reg_path = unpack1.join("stores/registry/instance.json");
    let mut reg_json: Value =
        serde_json::from_str(&fs::read_to_string(&reg_path).expect("read instance.json"))
            .expect("parse instance.json");
    let mh = reg_json["manifest_hash"]
        .as_str()
        .expect("manifest_hash")
        .to_string();
    let flipped_char = if mh.starts_with('0') { '1' } else { '0' };
    reg_json["manifest_hash"] = Value::String(format!("{flipped_char}{}", &mh[1..]));
    fs::write(
        &reg_path,
        serde_json::to_vec_pretty(&reg_json).expect("reg vec"),
    )
    .expect("write tampered instance.json");
    let corrupt_reg = g.root.join("s05-corrupt-reg.tar");
    repack_tar_from(&unpack1, &corrupt_reg);

    let out1 = g
        .cmd(&[
            "daemon",
            "restore",
            "--name",
            "a",
            "--from",
            corrupt_reg.to_str().expect("corrupt_reg"),
            "--force",
        ])
        .output()
        .expect("restore corrupt_reg");
    assert_eq!(
        out1.status.code(),
        Some(3),
        "expected exit=3 for corrupt_reg"
    );
    let ep_after1 = g.wait_ready("a");
    assert_eq!(capture_obs(&ep_after1), obs_live);

    // 2. Flip 1 byte in stores/participant-p1-journals/updates.journal
    let unpack2 = g.root.join("unpack-jnl");
    unpack_tar_to(&snap, &unpack2);
    let upd_path = unpack2.join("stores/participant-p1-journals/p1/updates.journal");
    let mut bytes = fs::read(&upd_path).expect("read p1 updates.journal");
    assert!(!bytes.is_empty(), "p1 updates.journal should be non-empty");
    bytes[0] ^= 0x01;
    fs::write(&upd_path, bytes).expect("write tampered p1 updates.journal");
    let corrupt_jnl = g.root.join("s05-corrupt-jnl.tar");
    repack_tar_from(&unpack2, &corrupt_jnl);

    let out2 = g
        .cmd(&[
            "daemon",
            "restore",
            "--name",
            "a",
            "--from",
            corrupt_jnl.to_str().expect("corrupt_jnl"),
            "--force",
        ])
        .output()
        .expect("restore corrupt_jnl");
    assert_eq!(
        out2.status.code(),
        Some(3),
        "expected exit=3 for corrupt_jnl"
    );
    let ep_after2 = g.wait_ready("a");
    assert_eq!(capture_obs(&ep_after2), obs_live);
}

#[test]
fn s06_missing_component_rejected() {
    let _lock = SNAPSHOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = InstancesGuard::new("s06");
    let ep = g.start_stack("a", None);
    let alice = allocate_party(&ep.p1_url, "Alice");
    let bob = allocate_party(&ep.p2_url, "Bob");
    wait_topology_settle();
    for i in 0..4 {
        let _ = create_holding(
            &ep.p1_url,
            &format!("s06-c-{i}"),
            &alice,
            &alice,
            &bob,
            "25.0",
        );
    }
    wait_acs_len(&ep.p1_url, &alice, 4);
    wait_acs_len(&ep.p2_url, &bob, 4);

    let snap = g.root.join("s06-snap.tar");
    g.run_checked(&[
        "daemon",
        "snapshot",
        "--name",
        "a",
        "--out",
        snap.to_str().expect("snap str"),
    ]);

    let ep_live = g.wait_ready("a");
    let _ = create_holding(
        &ep_live.p1_url,
        "s06-live-extra",
        &alice,
        &alice,
        &bob,
        "88.0",
    );
    wait_acs_len(&ep_live.p2_url, &bob, 5);
    let obs_live = capture_obs(&ep_live);

    let unpack_meta = g.root.join("s06-meta");
    unpack_tar_to(&snap, &unpack_meta);
    let manifest: MirrorManifest = serde_json::from_str(
        &fs::read_to_string(unpack_meta.join("snapshot.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    assert!(
        manifest.components.len() >= 8,
        "expected >= 8 components in Stores(I), got {}",
        manifest.components.len()
    );

    for comp in &manifest.components {
        eprintln!("[s06] stripping component '{}'", comp.id);
        let missing_tar = g.root.join(format!("s06-minus-{}.tar", comp.id));
        strip_component_from_bundle(&snap, &comp.id, &missing_tar);
        let out = g
            .cmd(&[
                "daemon",
                "restore",
                "--name",
                "a",
                "--from",
                missing_tar.to_str().expect("missing tar"),
                "--force",
            ])
            .output()
            .expect("restore B minus component");
        eprintln!(
            "[s06] restore without '{}' -> status={:?}\nstderr: {}",
            comp.id,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !out.status.success(),
            "S-A6 violated: restore succeeded after stripping '{}'",
            comp.id
        );
        let ep_after = g.wait_ready("a");
        assert_eq!(
            capture_obs(&ep_after),
            obs_live,
            "target instance mutated after failing restore of B\\{{{}}}",
            comp.id
        );
    }
}

#[test]
fn s07_version_mismatch_rejected() {
    let _lock = SNAPSHOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = InstancesGuard::new("s07");
    let ep = g.start_stack("a", None);
    let alice = allocate_party(&ep.p1_url, "Alice");
    let bob = allocate_party(&ep.p2_url, "Bob");
    wait_topology_settle();
    let _ = create_holding(&ep.p1_url, "s07-seed", &alice, &alice, &bob, "10.0");
    wait_acs_len(&ep.p2_url, &bob, 1);

    let snap = g.root.join("s07-snap.tar");
    g.run_checked(&[
        "daemon",
        "snapshot",
        "--name",
        "a",
        "--out",
        snap.to_str().expect("snap str"),
    ]);

    let ep_live = g.wait_ready("a");
    let _ = create_holding(
        &ep_live.p1_url,
        "s07-live-extra",
        &alice,
        &alice,
        &bob,
        "33.0",
    );
    wait_acs_len(&ep_live.p2_url, &bob, 2);
    let obs_live = capture_obs(&ep_live);

    let unpack = g.root.join("s07-unpack");
    unpack_tar_to(&snap, &unpack);
    let mpath = unpack.join("snapshot.json");
    let mut m: MirrorManifest =
        serde_json::from_str(&fs::read_to_string(&mpath).expect("read manifest"))
            .expect("parse manifest");
    m.canton_rs_version = "9.9.9-incompatible".to_string();
    fs::write(&mpath, serde_json::to_vec_pretty(&m).expect("vec")).expect("write manifest");
    let bad_ver = g.root.join("s07-bad-ver.tar");
    repack_tar_from(&unpack, &bad_ver);

    let out = g
        .cmd(&[
            "daemon",
            "restore",
            "--name",
            "a",
            "--from",
            bad_ver.to_str().expect("bad ver"),
            "--force",
        ])
        .output()
        .expect("restore bad_ver");
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit=2 for version mismatch"
    );
    let ep_after = g.wait_ready("a");
    assert_eq!(capture_obs(&ep_after), obs_live);
}

#[test]
fn s08_restore_idempotent() {
    let _lock = SNAPSHOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = InstancesGuard::new("s08");
    let ep = g.start_stack("a", None);
    let alice = allocate_party(&ep.p1_url, "Alice");
    let bob = allocate_party(&ep.p2_url, "Bob");
    wait_topology_settle();
    for i in 0..3 {
        let _ = create_holding(
            &ep.p1_url,
            &format!("s08-c-{i}"),
            &alice,
            &alice,
            &bob,
            "40.0",
        );
    }
    wait_acs_len(&ep.p2_url, &bob, 3);
    let obs_t = capture_obs(&ep);

    let snap = g.root.join("s08-snap.tar");
    g.run_checked(&[
        "daemon",
        "snapshot",
        "--name",
        "a",
        "--out",
        snap.to_str().expect("snap str"),
    ]);

    let ep_live = g.wait_ready("a");
    let _ = create_holding(&ep_live.p1_url, "s08-drift", &alice, &alice, &bob, "12.0");

    g.run_checked(&[
        "daemon",
        "restore",
        "--name",
        "a",
        "--from",
        snap.to_str().expect("snap str"),
        "--force",
    ]);
    let obs_1 = capture_obs(&g.wait_ready("a"));
    assert_eq!(obs_1, obs_t);

    g.run_checked(&[
        "daemon",
        "restore",
        "--name",
        "a",
        "--from",
        snap.to_str().expect("snap str"),
        "--force",
    ]);
    let obs_2 = capture_obs(&g.wait_ready("a"));
    assert_eq!(obs_2, obs_1, "S-A4 idempotency failed");
}

#[test]
fn s10_quiesce_timeout_aborts_and_resumes() {
    let _lock = SNAPSHOT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut g = InstancesGuard::new("s10");
    let cdar = confirm_dar();
    let ep = g.start_stack("a", Some(&cdar));

    let alice = allocate_party(&ep.p1_url, "Alice");
    let bob = allocate_party(&ep.p2_url, "Bob");
    wait_topology_settle();

    // Bob (hosted on p2) creates Confirm:Held with signatory r = Bob, observer a = Alice.
    let (_, held_cids) = submit_tx(
        &ep.p2_url,
        &[&bob],
        "s10-held-create",
        json!({
            "CreateCommand": {
                "templateId": HELD_TEMPLATE,
                "createArguments": { "r": bob, "a": alice }
            }
        }),
    );
    let held_cid = held_cids.into_iter().next().expect("Held cid");
    wait_acs_len(&ep.p1_url, &alice, 1);

    // Stop p2 cleanly so Touch cannot collect p2's confirmation verdict.
    g.run_checked(&["daemon", "stop", "--name", "a", "p2"]);

    // Hold a genuine Touch exercise in flight on p1 while p2 is offline.
    let p1_url_bg = ep.p1_url.clone();
    let alice_bg = alice.clone();
    let held_bg = held_cid;
    let bg = std::thread::spawn(move || {
        let body = json!({
            "commands": [{
                "ExerciseCommand": {
                    "templateId": HELD_TEMPLATE,
                    "contractId": held_bg,
                    "choice": "Touch",
                    "choiceArgument": {}
                }
            }],
            "commandId": "s10-held-touch",
            "actAs": [alice_bg],
            "userId": "participant_admin"
        });
        let _ = http_send(
            &p1_url_bg,
            "POST",
            "/v2/commands/submit-and-wait",
            "application/json",
            body.to_string().as_bytes(),
            Duration::from_secs(15),
        );
    });

    // Wait until p1 genuinely reports in_flight >= 1.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_in_flight = false;
    while Instant::now() < deadline {
        let (code, qv) = http_json(&ep.p1_url, "GET", "/_quiesce", None);
        if code == 200 && qv["in_flight"].as_u64().unwrap_or(0) >= 1 {
            saw_in_flight = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(saw_in_flight, "Touch request did not enter in_flight on p1");

    let snap_out = g.root.join("s10-aborted.tar");
    let res = g
        .cmd(&[
            "daemon",
            "snapshot",
            "--name",
            "a",
            "--out",
            snap_out.to_str().expect("snap_out"),
            "--quiesce-timeout-secs",
            "2",
        ])
        .output()
        .expect("run timed-out snapshot");
    assert_eq!(
        res.status.code(),
        Some(3),
        "expected exit=3 on quiesce timeout, got {:?}\nstderr: {}",
        res.status,
        String::from_utf8_lossy(&res.stderr)
    );
    assert!(
        !snap_out.exists(),
        "aborted snapshot must not leave bundle behind"
    );

    for url in [&ep.p1_url, &ep.s1_metrics_url, &ep.m1_admin_url] {
        let (code, qv) = http_json(url, "GET", "/_quiesce", None);
        assert_eq!(code, 200, "GET {url}/_quiesce failed: {qv}");
        assert_eq!(
            qv["quiesced"],
            Value::Bool(false),
            "node {url} remained quiesced after abort: {qv}"
        );
    }

    // Prove p1 accepts new single-party commands immediately after abort-resume.
    let new_cid = create_holding(
        &ep.p1_url,
        "s10-after-abort",
        &alice,
        &alice,
        &alice,
        "10.0",
    );
    assert!(!new_cid.is_empty());

    drop(g);
    let _ = bg.join();
}
