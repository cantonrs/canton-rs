use super::super::ipc::{bind_socket, DownProgressEvent, IpcRequest, IpcResponse, IpcStreamEvent};
use super::lifecycle::{cmd_down_with_options, cmd_down_with_writer, write_down_progress_event};
use super::observe::cmd_init;
use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

#[test]
fn formats_down_progress_concisely_and_verbosely() {
    let events = vec![
        DownProgressEvent::Started {
            stack_name: "localnet-dev".into(),
            synchronizer: "localnet-sync".into(),
            storage_mode: "files".into(),
            state_dir: "/tmp/crs-state".into(),
            timeout_secs: 10,
            clean_files: true,
            order: vec![
                "participant1".into(),
                "mediator1".into(),
                "sequencer1".into(),
            ],
        },
        DownProgressEvent::StoppingSlot {
            step: 1,
            total: 3,
            name: "participant1".into(),
            role: "participant".into(),
            pid: 41001,
            ports: "7575->json, 7576->admin".into(),
            timeout_secs: 10,
        },
        DownProgressEvent::SlotStopped {
            step: 1,
            total: 3,
            name: "participant1".into(),
            role: "participant".into(),
            pid: 41001,
            elapsed_ms: 150,
            forced_kill: false,
        },
        DownProgressEvent::SlotSkipped {
            step: 2,
            total: 3,
            name: "mediator1".into(),
            role: "mediator".into(),
        },
        DownProgressEvent::StoppingSlot {
            step: 3,
            total: 3,
            name: "sequencer1".into(),
            role: "sequencer".into(),
            pid: 41003,
            ports: "5018->public".into(),
            timeout_secs: 10,
        },
        DownProgressEvent::SlotStopped {
            step: 3,
            total: 3,
            name: "sequencer1".into(),
            role: "sequencer".into(),
            pid: 41003,
            elapsed_ms: 10020,
            forced_kill: true,
        },
        DownProgressEvent::CleaningFiles {
            state_dir: "/tmp/crs-state".into(),
            clean_files: true,
            removed_entries: 4,
            refused: None,
        },
        DownProgressEvent::Completed {
            stopped: 3,
            elapsed_ms: 10180,
            clean_files: true,
        },
    ];

    let mut concise_buf = Vec::new();
    for ev in &events {
        let _ = write_down_progress_event(&mut concise_buf, ev, false).expect("write concise");
    }
    let concise = String::from_utf8(concise_buf).expect("utf8");
    assert!(concise.contains("[-] Stopping 3 service(s) in 'localnet-dev'..."));
    assert!(concise.contains("[1/3] participant  participant1       stopping... stopped (0.1s)"));
    assert!(concise.contains("[2/3] mediator     mediator1          already stopped"));
    assert!(concise.contains(
        "[3/3] sequencer    sequencer1         stopping... killed after timeout (10.0s)"
    ));
    assert!(concise.contains("Cleaning local state & logs (4 item(s) removed)"));

    let mut verbose_buf = Vec::new();
    for ev in &events {
        let _ = write_down_progress_event(&mut verbose_buf, ev, true).expect("write verbose");
    }
    let verbose = String::from_utf8(verbose_buf).expect("utf8");
    assert!(verbose.contains("synchronizer=localnet-sync, storage=files"));
    assert!(verbose
        .contains("Reverse shutdown order (3 slot(s)): participant1 -> mediator1 -> sequencer1"));
    assert!(verbose.contains("pid=41001, ports=7575->json, 7576->admin): sending SIGTERM"));
    assert!(verbose.contains("exited cleanly via SIGTERM (150 ms)"));
    assert!(verbose.contains("escalated to SIGKILL (10020 ms)"));
    assert!(
        verbose.contains("4 local state/log item(s) under /tmp/crs-state (PostgreSQL untouched)")
    );
}

#[test]
fn cmd_down_streams_live_progress_over_unix_ipc() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio rt");
    let state_dir = std::env::temp_dir().join(format!("crs-down-prog-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);

    let (listener, cleanup) = rt.block_on(async {
        bind_socket(&state_dir)
            .expect("bind test sock")
            .into_parts()
    });
    let srv = std::thread::spawn(move || {
        rt.block_on(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (r, mut w) = stream.into_split();
                let mut lines = TokioBufReader::new(r).lines();
                if let Ok(Some(line)) = lines.next_line().await {
                    let req: IpcRequest = serde_json::from_str(&line).expect("parse req");
                    assert!(matches!(
                        req,
                        IpcRequest::Down {
                            stream_progress: true,
                            clean_files: Some(false),
                            ..
                        }
                    ));
                    for ev in [
                        DownProgressEvent::Started {
                            stack_name: "demo".into(),
                            synchronizer: "dev-sync".into(),
                            storage_mode: "files".into(),
                            state_dir: "/tmp/demo".into(),
                            timeout_secs: 5,
                            clean_files: false,
                            order: vec!["sequencer1".into()],
                        },
                        DownProgressEvent::StoppingSlot {
                            step: 1,
                            total: 1,
                            name: "sequencer1".into(),
                            role: "sequencer".into(),
                            pid: 9999,
                            ports: "5018->public".into(),
                            timeout_secs: 5,
                        },
                        DownProgressEvent::SlotStopped {
                            step: 1,
                            total: 1,
                            name: "sequencer1".into(),
                            role: "sequencer".into(),
                            pid: 9999,
                            elapsed_ms: 42,
                            forced_kill: false,
                        },
                        DownProgressEvent::CleaningFiles {
                            state_dir: "/tmp/demo".into(),
                            clean_files: false,
                            removed_entries: 0,
                            refused: None,
                        },
                        DownProgressEvent::Completed {
                            stopped: 1,
                            elapsed_ms: 50,
                            clean_files: false,
                        },
                    ] {
                        let wire =
                            serde_json::to_string(&IpcStreamEvent::DownProgress { data: ev })
                                .expect("ser ev");
                        let _ = w.write_all(format!("{wire}\n").as_bytes()).await;
                    }
                    let _ = w.shutdown().await;
                }
            }
            drop(cleanup);
        });
    });

    let args = DownArgs {
        name: None,
        state_dir: Some(state_dir.clone()),
        timeout_secs: 5,
        clean_files: false,
        verbose: true,
    };
    let mut out = Vec::new();
    cmd_down_with_writer(&args, &mut out).expect("cmd_down_with_writer");
    let _ = srv.join();
    let _ = std::fs::remove_dir_all(&state_dir);

    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("Connecting to supervisor socket"));
    assert!(text.contains("exited cleanly via SIGTERM (42 ms)"));
    assert!(text.contains("IPC socket"));
    assert!(text.contains("Stopped 1 supervised service(s) (0.1s)."));
}

#[test]
fn parses_contracts_and_tx_subcommands() {
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        action: DaemonAction,
    }

    let c_ls = TestCli::try_parse_from([
        "daemon",
        "contracts",
        "ls",
        "--name",
        "dev",
        "--party",
        "Alice::1220",
        "--template",
        "#events-oracle:Events:Box",
        "--at",
        "12",
        "--format",
        "json",
    ])
    .expect("parse contracts ls");
    assert!(matches!(
        c_ls.action,
        DaemonAction::Contracts(ContractsCliArgs {
            action: ContractsAction::Ls(_)
        })
    ));

    let c_watch = TestCli::try_parse_from([
        "daemon",
        "contracts",
        "watch",
        "--url",
        "http://127.0.0.1:7575",
        "--party",
        "Alice::1220",
        "--from",
        "5",
    ])
    .expect("parse contracts watch");
    assert!(matches!(
        c_watch.action,
        DaemonAction::Contracts(ContractsCliArgs {
            action: ContractsAction::Watch(_)
        })
    ));

    let t_ls = TestCli::try_parse_from([
        "daemon",
        "tx",
        "ls",
        "--name",
        "dev",
        "--party",
        "Alice::1220",
        "--from",
        "1",
        "--to",
        "9",
    ])
    .expect("parse tx ls");
    assert!(matches!(
        t_ls.action,
        DaemonAction::Tx(TxCliArgs {
            action: TxAction::Ls(_)
        })
    ));

    let t_replay = TestCli::try_parse_from([
        "daemon",
        "tx",
        "replay",
        "--name",
        "dev",
        "--id",
        "abcdef",
        "--party",
        "Alice::1220",
        "--interface",
        "#splice-amulet:Splice.Api.Token.HoldingV1:Holding",
        "--format",
        "json",
    ])
    .expect("parse tx replay");
    assert!(matches!(
        t_replay.action,
        DaemonAction::Tx(TxCliArgs {
            action: TxAction::Replay(_)
        })
    ));

    let t_diff = TestCli::try_parse_from([
        "daemon",
        "tx",
        "diff",
        "left.json",
        "right.json",
        "--format",
        "json",
    ])
    .expect("parse tx diff");
    assert!(matches!(
        t_diff.action,
        DaemonAction::Tx(TxCliArgs {
            action: TxAction::Diff(_)
        })
    ));

    let d_watch = TestCli::try_parse_from([
        "daemon",
        "dar",
        "watch",
        "--name",
        "dev",
        "contracts/target/sample-contract.dar",
    ])
    .expect("parse dar watch");
    assert!(matches!(
        d_watch.action,
        DaemonAction::Dar(DaemonDarCliArgs {
            action: DaemonDarAction::Watch(_)
        })
    ));

    let d_snap = TestCli::try_parse_from([
        "daemon",
        "snapshot",
        "--name",
        "dev",
        "--out",
        "/tmp/snap.tar",
        "--quiesce-timeout-secs",
        "15",
        "--format",
        "json",
    ])
    .expect("parse snapshot");
    assert!(matches!(d_snap.action, DaemonAction::Snapshot(_)));

    let d_rest = TestCli::try_parse_from([
        "daemon",
        "restore",
        "--name",
        "dev-copy",
        "--from",
        "/tmp/snap.tar",
        "--force",
        "--port-offset",
        "2000",
        "--format",
        "json",
    ])
    .expect("parse restore");
    assert!(matches!(d_rest.action, DaemonAction::Restore(_)));

    let d_init = TestCli::try_parse_from([
        "daemon",
        "init",
        "--with-sample-dar",
        "-o",
        "canton-daemon.yaml",
    ])
    .expect("parse init --with-sample-dar");
    assert!(matches!(
        d_init.action,
        DaemonAction::Init(InitArgs {
            with_sample_dar: true,
            ..
        })
    ));
}

#[test]
fn cmd_init_with_sample_dar_extracts_dar_and_respects_force() {
    let dir = std::env::temp_dir().join(format!(
        "crs-init-sample-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let out_yaml = dir.join("canton-daemon.yaml");
    let out_dar = dir.join(super::super::manifest::SAMPLE_DAR_FILENAME);

    let make_args = |force: bool| InitArgs {
        template: TemplateArg::Default,
        from_canton_conf: None,
        bootstrap: None,
        output: out_yaml.clone(),
        with_sample_dar: true,
        force,
    };

    cmd_init(make_args(false)).expect("first init --with-sample-dar must succeed");
    assert!(out_yaml.is_file(), "manifest created");
    assert!(out_dar.is_file(), "sample DAR extracted next to manifest");
    assert_eq!(
        std::fs::read(&out_dar).expect("read extracted dar"),
        super::super::manifest::EMBEDDED_SAMPLE_DAR
    );
    let yaml_text = std::fs::read_to_string(&out_yaml).expect("read yaml");
    assert!(yaml_text.contains(r#"dars: ["./sample-contract.dar"]"#));

    // Negative control: refusing overwrite when manifest or sample DAR already exists without --force.
    let err_both = cmd_init(make_args(false)).expect_err("must refuse overwriting existing files");
    assert!(err_both.contains("already exists"), "{err_both}");

    std::fs::remove_file(&out_yaml).expect("remove yaml only");
    let err_dar = cmd_init(make_args(false)).expect_err("must refuse overwriting existing dar");
    assert!(err_dar.contains("sample-contract.dar"), "{err_dar}");
    assert!(
        !out_yaml.exists(),
        "failed init must not leave partial manifest"
    );

    // Positive control: --force overwrites both cleanly.
    cmd_init(make_args(true)).expect("init --with-sample-dar --force must overwrite");
    assert!(out_yaml.is_file() && out_dar.is_file());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cmd_down_force_remove_handles_ipc_eof_and_already_shutting_down() {
    let run_case = |mode: &str, allow_eof: bool| -> Result<(), String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");
        let state_dir = std::env::temp_dir().join(format!(
            "crs-down-eof-{mode}-{allow_eof}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&state_dir);

        let (listener, cleanup) = rt.block_on(async {
            bind_socket(&state_dir)
                .expect("bind test sock")
                .into_parts()
        });
        let mode_owned = mode.to_string();
        let srv = std::thread::spawn(move || {
            rt.block_on(async move {
                if let Ok((stream, _)) = listener.accept().await {
                    let (r, mut w) = stream.into_split();
                    let mut lines = TokioBufReader::new(r).lines();
                    let _ = lines.next_line().await;
                    if mode_owned == "in-progress" {
                        let wire = serde_json::to_string(&IpcResponse::err(
                            "supervisor shutdown already in progress",
                        ))
                        .expect("ser err");
                        let _ = w.write_all(format!("{wire}\n").as_bytes()).await;
                    }
                    // Close socket without sending DownProgressEvent::Completed (EOF).
                    drop(w);
                }
                drop(cleanup);
            });
        });

        let args = DownArgs {
            name: None,
            state_dir: Some(state_dir.clone()),
            timeout_secs: 2,
            clean_files: false,
            verbose: false,
        };
        let mut out = Vec::new();
        let res = cmd_down_with_options(&args, &mut out, allow_eof);
        let _ = srv.join();
        let _ = std::fs::remove_dir_all(&state_dir);
        res
    };

    // Negative control: normal `daemon down` rejects premature IPC EOF.
    let err = run_case("eof", false).expect_err("normal daemon down must report premature EOF");
    assert!(
        err.contains("closed IPC socket"),
        "expected closed IPC socket error, got: {err}"
    );

    // Positive controls for `daemon remove --force` (M-005): EOF & already-shutting-down both succeed.
    run_case("eof", true).expect("force remove must tolerate IPC EOF while shutting down");
    run_case("in-progress", true)
        .expect("force remove must tolerate shutdown-already-in-progress response");
}
