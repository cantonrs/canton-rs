//! Unit tests for `S-DX-004` snapshot URL scoping, SQL normalization, bundle creation,
//! `0600` file permissions, hash tamper rejection (`exit=3`), and version check (`exit=2`).

use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use super::super::super::exit_code::{decode_exit, EXIT_MISMATCH, EXIT_PREFLIGHT};
use super::super::registry::{write_instance_record, InstanceRecord};
use super::bundle::{
    create_snapshot_bundle, normalize_pg_dump_sql, rewrite_dump_schema, unpack_and_verify_bundle,
    BuildBundleSpec, TempDirGuard,
};
use super::{
    atomic_write_0600, scope_pg_url, strip_pg_schema_param, DaemonRecipe, SnapshotManifest,
    SnapshotServiceInfo, SNAPSHOT_MANIFEST_FILE,
};

fn seed_file_instance(root: &Path) -> DaemonRecipe {
    let rec = InstanceRecord {
        name: "inst-a".to_string(),
        port_offset: 0,
        created_at_unix_secs: 100,
        version: env!("CARGO_PKG_VERSION").to_string(),
        manifest_hash: "sha256:abc".to_string(),
        pg_url: None,
        pg_prefix: Some("inst-a".to_string()),
    };
    write_instance_record(root, &rec).expect("write instance");
    atomic_write_0600(&root.join("manifest.yaml"), b"name: inst-a\nservices: {}\n")
        .expect("write manifest");

    // Seed Stores(I): sequencer, mediator, participant p1 (excluding transient lock / *.tmp / logs)
    atomic_write_0600(&root.join("s1/keys"), b"seq-keys-v1").expect("seq keys");
    atomic_write_0600(&root.join("s1/journal"), b"seq-journal-v1").expect("seq journal");
    atomic_write_0600(&root.join("s1/lock"), b"lock").expect("seq lock");
    atomic_write_0600(&root.join("m1/mediator.identity"), b"med-id-v1").expect("med id");
    atomic_write_0600(&root.join("m1/mediator-0.state"), b"med-state").expect("med state");
    atomic_write_0600(&root.join("m1/mediator-0.topology.journal"), b"med-topo").expect("med topo");
    atomic_write_0600(&root.join("m1-onboarding.txt"), b"onboard").expect("med onboard");
    atomic_write_0600(&root.join("p1/identity"), b"p1-id").expect("p1 id");
    atomic_write_0600(&root.join("p1/synchronizer"), b"sync-1").expect("p1 sync");
    atomic_write_0600(&root.join("p1/updates.journal"), b"upd-1\n").expect("p1 upd");
    atomic_write_0600(&root.join("p1/ledger.journal"), b"led-1\n").expect("p1 led");
    atomic_write_0600(&root.join("p1/cursor"), b"5\n").expect("p1 cur");
    atomic_write_0600(&root.join("p1/dars.journal"), b"").expect("p1 dars");
    atomic_write_0600(&root.join("logs/p1.log"), b"ignored-log").expect("log");

    let recipe = DaemonRecipe {
        schema: "canton-rs.daemon-recipe/1".to_string(),
        mode: "mode_a".to_string(),
        manifest_file: "manifest.yaml".to_string(),
        canton_conf_file: None,
        bootstrap_file: None,
        launch_cwd: root.to_path_buf(),
        instance_name: "inst-a".to_string(),
        port_offset: 0,
        pg_url: None,
        pg_schema: None,
        state_in_files: true,
        metrics_port: None,
        metrics_bind: "127.0.0.1".to_string(),
        profile: Vec::new(),
        group: Vec::new(),
        dar: None,
        xray: false,
        no_restart: false,
        strict_config: false,
        same_identity: false,
        official_write: false,
        official_pg_addr: None,
        conf_auth_cert: None,
        token_env: None,
        token_file: None,
        log_encoder: "text".to_string(),
        dev_auth: false,
        observability: false,
        bind: "127.0.0.1".to_string(),
        bind_addresses: vec!["127.0.0.1".to_string()],
        services: vec![
            SnapshotServiceInfo {
                name: "s1".to_string(),
                role: "sequencer".to_string(),
                state_dir_rel: "s1".to_string(),
                storage_kind: "files".to_string(),
                state_name: None,
                has_bft_group: false,
                synchronizer: "sync".to_string(),
            },
            SnapshotServiceInfo {
                name: "m1".to_string(),
                role: "mediator".to_string(),
                state_dir_rel: "m1".to_string(),
                storage_kind: "files".to_string(),
                state_name: None,
                has_bft_group: false,
                synchronizer: "sync".to_string(),
            },
            SnapshotServiceInfo {
                name: "p1".to_string(),
                role: "participant".to_string(),
                state_dir_rel: "p1".to_string(),
                storage_kind: "files".to_string(),
                state_name: None,
                has_bft_group: false,
                synchronizer: "sync".to_string(),
            },
        ],
    };
    let rb = serde_json::to_vec_pretty(&recipe).expect("serialize recipe");
    atomic_write_0600(&root.join("daemon.recipe.json"), &rb).expect("write recipe");
    recipe
}

#[test]
fn pg_url_scoping_and_sql_normalization() {
    assert_eq!(
        scope_pg_url("postgres://u:p@127.0.0.1:5432/canton", "inst-a-state"),
        "postgres://u:p@127.0.0.1:5432/canton?currentSchema=inst-a-state"
    );
    assert_eq!(
        scope_pg_url(
            "postgres://u:p@127.0.0.1:5432/canton?sslmode=disable&currentSchema=old",
            "inst-b-state"
        ),
        "postgres://u:p@127.0.0.1:5432/canton?sslmode=disable&currentSchema=inst-b-state"
    );
    assert_eq!(
        strip_pg_schema_param(
            "jdbc:postgresql://127.0.0.1:5432/canton?currentSchema=foo&sslmode=disable"
        ),
        "postgres://127.0.0.1:5432/canton?sslmode=disable"
    );
    assert_eq!(
        strip_pg_schema_param("postgres://127.0.0.1:5432/canton?currentSchema=foo"),
        "postgres://127.0.0.1:5432/canton"
    );

    let normalized = normalize_pg_dump_sql(
        "SET statement_timeout = 0;\nSET transaction_timeout = 0;\nCREATE SCHEMA \"inst-a-state\";\n",
    );
    assert!(!normalized.contains("transaction_timeout"));
    let rewritten = rewrite_dump_schema(&normalized, "inst-a-state", "inst-b-state");
    assert!(rewritten.contains("CREATE SCHEMA \"inst-b-state\";"));
}

#[test]
fn snapshot_bundle_permissions_hash_tamper_and_version_check() {
    let dir = TempDirGuard::new("sdx004-unit").expect("temp dir");
    let inst_dir = dir.path().join("inst-a");
    let recipe = seed_file_instance(&inst_dir);
    let out_tar = dir.path().join("snap.tar");

    let mut ends = BTreeMap::new();
    ends.insert("p1".to_string(), 5);
    let mut ids = BTreeMap::new();
    ids.insert("p1".to_string(), "p1::1220aa".to_string());

    let manifest = create_snapshot_bundle(&BuildBundleSpec {
        state_dir: &inst_dir,
        recipe: &recipe,
        source_name: "inst-a",
        manifest_hash: "sha256:abc",
        created_at_unix_secs: 200,
        ledger_ends: &ends,
        node_identities: &ids,
        scan_history_lines: None,
        out_tar: &out_tar,
    })
    .expect("create snapshot bundle");

    // Verify transient lock/logs excluded and expected Stores(I) present.
    let comp_ids: Vec<&str> = manifest.components.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        comp_ids,
        vec![
            "mediator-m1",
            "participant-p1-identity",
            "participant-p1-journals",
            "recipe",
            "registry",
            "sequencer-s1",
        ]
    );
    for c in &manifest.components {
        for f in &c.files {
            assert!(!f.store_rel_path.ends_with("/lock"));
            assert!(!f.store_rel_path.starts_with("logs/"));
        }
    }

    #[cfg(unix)]
    {
        let mode = fs::metadata(&out_tar)
            .expect("tar meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "bundle tarball must be 0600, got {mode:o}");
    }

    // Valid bundle unpacks cleanly.
    assert!(unpack_and_verify_bundle(&out_tar).is_ok());

    // Tamper 1 byte in a stored file -> exit = 3 (EXIT_MISMATCH).
    let work_tamper = dir.path().join("work-tamper");
    fs::create_dir_all(&work_tamper).expect("mkdir tamper");
    assert!(Command::new("tar")
        .arg("-xf")
        .arg(&out_tar)
        .arg("-C")
        .arg(&work_tamper)
        .status()
        .expect("untar")
        .success());
    let upd_path = work_tamper.join("stores/participant-p1-journals/p1/updates.journal");
    fs::write(&upd_path, b"upd-X\n").expect("tamper byte");
    let tampered_tar = dir.path().join("tampered.tar");
    assert!(Command::new("tar")
        .arg("-cf")
        .arg(&tampered_tar)
        .arg("-C")
        .arg(&work_tamper)
        .arg(".")
        .status()
        .expect("retar")
        .success());
    let err_tamper = unpack_and_verify_bundle(&tampered_tar)
        .err()
        .expect("tamper fail");
    assert_eq!(decode_exit(&err_tamper).0, EXIT_MISMATCH);

    // Bump canton_rs_version in snapshot.json -> exit = 2 (EXIT_PREFLIGHT).
    let work_ver = dir.path().join("work-ver");
    fs::create_dir_all(&work_ver).expect("mkdir ver");
    assert!(Command::new("tar")
        .arg("-xf")
        .arg(&out_tar)
        .arg("-C")
        .arg(&work_ver)
        .status()
        .expect("untar")
        .success());
    let mpath = work_ver.join(SNAPSHOT_MANIFEST_FILE);
    let mut mf: SnapshotManifest =
        serde_json::from_slice(&fs::read(&mpath).expect("read manifest")).expect("parse manifest");
    mf.canton_rs_version = "99.99.99".to_string();
    fs::write(&mpath, serde_json::to_vec_pretty(&mf).expect("ser")).expect("write manifest");
    let ver_tar = dir.path().join("ver-mismatch.tar");
    assert!(Command::new("tar")
        .arg("-cf")
        .arg(&ver_tar)
        .arg("-C")
        .arg(&work_ver)
        .arg(".")
        .status()
        .expect("retar ver")
        .success());
    let err_ver = unpack_and_verify_bundle(&ver_tar).err().expect("ver fail");
    assert_eq!(decode_exit(&err_ver).0, EXIT_PREFLIGHT);
}
