use super::*;

#[test]
fn cli_archive_verify_and_replay_from_jsonl_with_tamper_negative_control() {
    let tmp = std::env::temp_dir().join(format!("canton_rs_db_cli_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("mkdir");
    let hist = tmp.join("history.jsonl");
    let arch_dir = tmp.join("cold");

    let jsonl = concat!(
        r#"{"offset":1,"update_id":"u1","synchronizer_id":"sync::1","events":[{"CreatedEvent":{"contractId":"00aa","templateId":"M:T","signatories":["Alice"],"createArgument":{"v":10}}}]}"#,
        "\n",
        r#"{"offset":2,"update_id":"u2","synchronizer_id":"sync::1","events":[{"CreatedEvent":{"contractId":"00bb","templateId":"M:T","signatories":["Bob"],"createArgument":{"v":20}}}]}"#,
        "\n",
        r#"{"offset":3,"update_id":"u3","synchronizer_id":"sync::1","events":[{"ArchivedEvent":{"contractId":"00aa","templateId":"M:T","witnessParties":["Alice"]}}]}"#,
        "\n"
    );
    fs::write(&hist, jsonl).expect("write history");

    execute_db(DbArgs {
        action: DbAction::Archive(DbArchiveArgs {
            archive_dir: arch_dir.clone(),
            from_offset: Some(1),
            up_to_offset: 2,
            from_history: Some(hist.clone()),
            jdbc_url: None,
            synchronizer_id: "sync::1".into(),
            participant_id: "p1".into(),
            zero_payload: false,
            signing_key_file: None,
            signing_key_hex: None,
            sign_ephemeral: true,
            prune_after_archive: false,
            user: None,
            password: None,
            password_file: None,
            connection_init_sql: None,
            json: true,
        }),
    })
    .expect("archive seg 1..=2");

    // Second chained segment (auto-derives from_offset = 3 and zero_payload = true)
    execute_db(DbArgs {
        action: DbAction::Archive(DbArchiveArgs {
            archive_dir: arch_dir.clone(),
            from_offset: None,
            up_to_offset: 3,
            from_history: Some(hist),
            jdbc_url: None,
            synchronizer_id: "sync::1".into(),
            participant_id: "p1".into(),
            zero_payload: true,
            signing_key_file: None,
            signing_key_hex: None,
            sign_ephemeral: true,
            prune_after_archive: false,
            user: None,
            password: None,
            password_file: None,
            connection_init_sql: None,
            json: true,
        }),
    })
    .expect("archive seg 3..=3");

    execute_db(DbArgs {
        action: DbAction::VerifyArchive(DbVerifyArchiveArgs {
            archive_dir: arch_dir.clone(),
            expected_signer_hex: None,
            json: true,
        }),
    })
    .expect("verify intact chain");

    execute_db(DbArgs {
        action: DbAction::Replay(DbReplayArgs {
            archive_dir: arch_dir.clone(),
            up_to_offset: None,
            json: true,
        }),
    })
    .expect("4-stage replay");

    // Negative control: tamper with segment file and confirm VerifyArchive rejects loudly!
    let seg1_path = arch_dir.join("seg-000000000001-000000000002.crs-seg.json");
    let raw = fs::read_to_string(&seg1_path).expect("read seg1");
    fs::write(&seg1_path, raw.replace("00aa", "00ff")).expect("tamper seg1");
    let err = execute_db(DbArgs {
        action: DbAction::VerifyArchive(DbVerifyArchiveArgs {
            archive_dir: arch_dir,
            expected_signer_hex: None,
            json: true,
        }),
    })
    .expect_err("tampered cold archive must fail verification");
    assert!(
        err.contains("mismatch") || err.contains("signature"),
        "got: {err}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

// a closed loopback port: a test that reaches PostgreSQL fails with a connection error instead of the refusal it expects
const NO_PG: &str = "postgres://nobody@127.0.0.1:1/none";

fn archive_args(dir: &Path, hist: Option<&Path>, from: Option<i64>, to: i64) -> DbArchiveArgs {
    DbArchiveArgs {
        archive_dir: dir.to_path_buf(),
        from_offset: from,
        up_to_offset: to,
        from_history: hist.map(Path::to_path_buf),
        jdbc_url: None,
        synchronizer_id: "sync::1".into(),
        participant_id: "p1".into(),
        zero_payload: false,
        signing_key_file: None,
        signing_key_hex: None,
        sign_ephemeral: false,
        prune_after_archive: false,
        user: None,
        password: None,
        password_file: None,
        connection_init_sql: None,
        json: true,
    }
}

fn history_fixture(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let tmp = std::env::temp_dir().join(format!("canton_rs_db_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("mkdir");
    let hist = tmp.join("history.jsonl");
    let lines: Vec<String> = (1..=6)
        .map(|o| {
            format!(
                r#"{{"offset":{o},"update_id":"u{o}","events":[{{"CreatedEvent":{{"contractId":"00{o:02}","templateId":"M:T","signatories":["Alice"],"createArgument":{{"v":{o}}}}}}}]}}"#
            )
        })
        .collect();
    fs::write(&hist, lines.join("\n")).expect("write history");
    let dir = tmp.join("cold");
    (tmp, hist, dir)
}

fn segment_files(dir: &Path) -> usize {
    fs::read_dir(dir).map_or(0, |d| d.count())
}

#[cfg(unix)]
#[test]
fn secret_file_rejects_permissions_broader_than_0600() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = std::env::temp_dir().join(format!("canton_rs_r18g_perm_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("mkdir");

    let key_path = tmp.join("signer.key");
    fs::write(&key_path, "11".repeat(32)).expect("write key");
    let pw_path = tmp.join("pg.pw");
    fs::write(&pw_path, "topsecret\n").expect("write pw");

    for bad_mode in [0o644, 0o640, 0o604] {
        fs::set_permissions(&key_path, fs::Permissions::from_mode(bad_mode)).expect("chmod key");
        let err = parse_signing_key_opt(Some(&key_path), None, false)
            .expect_err("broad signing key file permissions must be refused");
        assert!(
            err.contains("0600"),
            "expected 0600 guidance for mode {bad_mode:04o}, got: {err}"
        );

        fs::set_permissions(&pw_path, fs::Permissions::from_mode(bad_mode)).expect("chmod pw");
        let err = parse_target(
            "postgres://canton@127.0.0.1:5432/canton",
            None,
            None,
            Some(&pw_path),
            None,
        )
        .expect_err("broad password file permissions must be refused");
        assert!(
            err.contains("0600"),
            "expected 0600 guidance for mode {bad_mode:04o}, got: {err}"
        );
    }

    // Positive controls: 0600 and 0400 must succeed
    for ok_mode in [0o600, 0o400] {
        fs::set_permissions(&key_path, fs::Permissions::from_mode(ok_mode)).expect("chmod key");
        let parsed = parse_signing_key_opt(Some(&key_path), None, false)
            .expect("0600/0400 key file must succeed");
        assert_eq!(parsed, Some([0x11u8; 32]));

        fs::set_permissions(&pw_path, fs::Permissions::from_mode(ok_mode)).expect("chmod pw");
        let target = parse_target(
            "postgres://canton@127.0.0.1:5432/canton",
            None,
            None,
            Some(&pw_path),
            None,
        )
        .expect("0600/0400 password file must succeed");
        assert_eq!(target.password, "topsecret");
    }

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn prune_paths_reject_argv_secrets() {
    let tmp = std::env::temp_dir().join(format!("canton_rs_r18g_argv_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("mkdir");
    let dir = tmp.join("cold");
    let key_path = tmp.join("signer.key");
    fs::write(&key_path, "22".repeat(32)).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod key");
    }

    // 1. db archive --prune-after-archive with --signing-key-hex
    let mut a1 = archive_args(&dir, None, Some(1), 2);
    a1.jdbc_url = Some(NO_PG.into());
    a1.prune_after_archive = true;
    a1.signing_key_hex = Some("22".repeat(32));
    let err = execute_db(DbArgs {
        action: DbAction::Archive(a1),
    })
    .expect_err("prune-after-archive must reject --signing-key-hex");
    assert!(err.contains("--signing-key-hex"), "got: {err}");

    // 2. db archive --prune-after-archive with --password
    let mut a2 = archive_args(&dir, None, Some(1), 2);
    a2.jdbc_url = Some(NO_PG.into());
    a2.prune_after_archive = true;
    a2.signing_key_file = Some(key_path.clone());
    a2.password = Some("secret-argv-pw".into());
    let err = execute_db(DbArgs {
        action: DbAction::Archive(a2),
    })
    .expect_err("prune-after-archive must reject --password");
    assert!(err.contains("--password"), "got: {err}");

    // 3. db archive --prune-after-archive with password in --jdbc-url
    let mut a3 = archive_args(&dir, None, Some(1), 2);
    a3.jdbc_url = Some("postgres://canton:secret-in-url@127.0.0.1:1/none".into());
    a3.prune_after_archive = true;
    a3.signing_key_file = Some(key_path);
    let err = execute_db(DbArgs {
        action: DbAction::Archive(a3),
    })
    .expect_err("prune-after-archive must reject URL password");
    assert!(
        err.contains("PGPASSWORD") || err.contains("--password-file"),
        "got: {err}"
    );

    // 4. db takeover --prune-offset with --password
    let err = execute_db(DbArgs {
        action: DbAction::Takeover(DbTakeoverArgs {
            jdbc_url: NO_PG.into(),
            migrations_dir: None,
            party: Some("Alice".into()),
            user: None,
            password: Some("secret-argv-pw".into()),
            password_file: None,
            connection_init_sql: None,
            archive_cid: None,
            unsafe_offline_archive: false,
            command_id: "c".into(),
            submitter: None,
            prune_offset: Some(5),
        }),
    })
    .expect_err("takeover --prune-offset must reject --password");
    assert!(err.contains("--password"), "got: {err}");

    // 5. db takeover --prune-offset with password in --jdbc-url
    let err = execute_db(DbArgs {
        action: DbAction::Takeover(DbTakeoverArgs {
            jdbc_url: "postgres://canton:secret-in-url@127.0.0.1:1/none".into(),
            migrations_dir: None,
            party: Some("Alice".into()),
            user: None,
            password: None,
            password_file: None,
            connection_init_sql: None,
            archive_cid: None,
            unsafe_offline_archive: false,
            command_id: "c".into(),
            submitter: None,
            prune_offset: Some(5),
        }),
    })
    .expect_err("takeover --prune-offset must reject URL password");
    assert!(
        err.contains("PGPASSWORD") || err.contains("--password-file"),
        "got: {err}"
    );

    // 6. R-18f: invalid prune_offset (> i64::MAX) rejected before touching PG
    let err = execute_db(DbArgs {
        action: DbAction::Takeover(DbTakeoverArgs {
            jdbc_url: NO_PG.into(),
            migrations_dir: None,
            party: Some("Alice".into()),
            user: None,
            password: None,
            password_file: None,
            connection_init_sql: None,
            archive_cid: Some("00aa".into()),
            unsafe_offline_archive: true,
            command_id: "c".into(),
            submitter: Some("Alice".into()),
            prune_offset: Some(u64::MAX),
        }),
    })
    .expect_err("overflowing prune_offset must fail before connecting to PG");
    assert!(err.contains("--prune-offset"), "got: {err}");

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn archive_refuses_a_gap_after_the_last_segment() {
    let (tmp, hist, dir) = history_fixture("gap");
    execute_db(DbArgs {
        action: DbAction::Archive(archive_args(&dir, Some(&hist), Some(1), 2)),
    })
    .expect("segment 1..=2");
    let err = execute_db(DbArgs {
        action: DbAction::Archive(archive_args(&dir, Some(&hist), Some(5), 6)),
    })
    .expect_err("offsets 3..=4 would be skipped");
    assert!(err.contains("gap"), "got: {err}");
    assert_eq!(segment_files(&dir), 1, "no segment written for the gap");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn prune_after_archive_refuses_sources_that_cannot_restore_what_it_deletes() {
    let (tmp, hist, dir) = history_fixture("prune_src");
    // a JSONL history is not the database being pruned
    let mut from_history = archive_args(&dir, Some(&hist), Some(1), 2);
    from_history.jdbc_url = Some(NO_PG.into());
    from_history.prune_after_archive = true;
    let err = execute_db(DbArgs {
        action: DbAction::Archive(from_history),
    })
    .expect_err("history source with prune");
    assert!(err.contains("--from-history"), "got: {err}");
    // zero-payload drops the contract bodies the prune deletes
    let mut zero = archive_args(&dir, None, Some(1), 2);
    zero.jdbc_url = Some(NO_PG.into());
    zero.prune_after_archive = true;
    zero.zero_payload = true;
    let err = execute_db(DbArgs {
        action: DbAction::Archive(zero),
    })
    .expect_err("zero-payload with prune");
    assert!(err.contains("--zero-payload"), "got: {err}");
    // unsigned / ephemeral-key segments cannot prove archive origin when deleting PG rows
    let mut unsigned = archive_args(&dir, None, Some(1), 2);
    unsigned.jdbc_url = Some(NO_PG.into());
    unsigned.prune_after_archive = true;
    unsigned.sign_ephemeral = true;
    let err = execute_db(DbArgs {
        action: DbAction::Archive(unsigned),
    })
    .expect_err("ephemeral signature with prune");
    assert!(err.contains("--signing-key-file"), "got: {err}");
    assert_eq!(segment_files(&dir), 0, "refused before writing a segment");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn password_file_sets_password_without_cli_argument() {
    let tmp = std::env::temp_dir().join(format!("canton_rs_pwfile_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("mkdir");
    let pw_file = tmp.join("pg.pw");
    fs::write(&pw_file, "s3cret-from-file\n").expect("write pw");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pw_file, fs::Permissions::from_mode(0o600)).expect("chmod pw");
    }
    let target = parse_target(
        "postgres://canton@127.0.0.1:5432/canton",
        None,
        None,
        Some(&pw_file),
        None,
    )
    .expect("parse target");
    assert_eq!(target.password, "s3cret-from-file");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn takeover_archive_cid_is_refused_without_the_unsafe_flag() {
    let err = execute_db(DbArgs {
        action: DbAction::Takeover(DbTakeoverArgs {
            jdbc_url: NO_PG.into(),
            migrations_dir: None,
            party: Some("Alice".into()),
            user: None,
            password: None,
            password_file: None,
            connection_init_sql: None,
            archive_cid: Some("00aa".into()),
            unsafe_offline_archive: false,
            command_id: "c".into(),
            submitter: None,
            prune_offset: None,
        }),
    })
    .expect_err("protocol bypass needs the explicit flag");
    assert!(
        err.contains("sequencer") && err.contains("--unsafe-offline-archive"),
        "got: {err}"
    );
}
