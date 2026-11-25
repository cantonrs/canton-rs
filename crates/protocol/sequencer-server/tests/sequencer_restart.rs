//! G11 / S-LOCAL-008: the sequencer alone is stopped and started again (same state directory, same address) and its clients carry on without
//! being restarted. A sequencer keeps no authentication tokens, so every client's token is refused after the restart; a client that was told how
//! authenticates again by itself and the call goes through.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
mod common;

use canton_participant::node::{Node, SharedNode, Verdict};
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use canton_sequencer_server::{mediator_node, serve_with, ServeOptions};
use lf_eval::Value;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/fixtures/confirm/target/confirm-subview.dar")
}

/// A sequencer on `address` with its state in `dir` and the mediators outside, stopped when this is dropped.
struct Running {
    stop: Arc<tokio::sync::Notify>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    fn start(address: std::net::SocketAddr, dir: &std::path::Path) -> Self {
        let config =
            canton_sequencer_server::new_synchronizer_in(dir, "testsync", "ts1", 1).unwrap();
        let stop = Arc::new(tokio::sync::Notify::new());
        let (state, notify) = (dir.to_path_buf(), std::sync::Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            let _ = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(serve_with(
                    address,
                    config,
                    ServeOptions {
                        state_dir: Some(state),
                        external_mediator: true,
                        shutdown: Some(notify),
                        ..Default::default()
                    },
                ));
        });
        for _ in 0..100 {
            if std::net::TcpStream::connect(address).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Running {
            stop,
            handle: Some(handle),
        }
    }

    fn stop(mut self) {
        self.stop.notify_one();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn free_address() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

fn dir(label: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sequencer-restart-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A client with a token, after the sequencer restarted: without a way to authenticate again its call is refused as unauthenticated, with one
/// it goes through (and the sequencer's time is read).
#[test]
fn a_client_that_can_authenticate_again_survives_a_sequencer_restart() {
    let state = dir("client");
    let address = free_address();
    let url = format!("http://{address}");
    let server = Running::start(address, &state);
    let config =
        canton_sequencer_server::new_synchronizer_in(&state, "testsync", "ts1", 1).unwrap();
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "alpha");
    let member = m.identity.member();
    let auth_seed = m.identity.sequencer_auth_key.seed();
    // before the restart the token works
    assert!(m
        .client
        .sequencer_time(&member, &physical, Some(&m.token))
        .unwrap()
        .is_some());
    let mut with = SequencerConnect::connect(&url).unwrap();
    let challenge = with.challenge(&member, &[37]).unwrap();
    let token = with
        .authenticate(
            &member,
            &challenge.nonce,
            m.identity
                .sequencer_auth_key
                .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap()),
        )
        .unwrap();
    with.set_reauth(
        &member,
        &physical,
        Box::new(move |hash| {
            canton_participant::topology_wire::Ed25519Key::from_seed(auth_seed).sign_bytes(hash)
        }),
    );
    assert!(with
        .sequencer_time(&member, &physical, Some(&token))
        .unwrap()
        .is_some());

    server.stop();
    let server = Running::start(address, &state);
    // without a way to authenticate again: refused, and the refusal says why
    let refused = m
        .client
        .sequencer_time(&member, &physical, Some(&m.token))
        .expect_err("the restarted sequencer keeps no tokens");
    assert!(refused.is_unauthenticated(), "{refused}");
    // with one: the same call goes through, with the token the client got for itself
    assert!(
        with.sequencer_time(&member, &physical, Some(&token))
            .unwrap()
            .is_some(),
        "the client authenticated again by itself"
    );
    server.stop();
    let _ = std::fs::remove_dir_all(&state);
}

/// Two participants and a mediator process run through a restart of the sequencer alone: nobody is restarted, and the next request is judged.
#[test]
fn participants_and_the_mediator_carry_on_after_the_sequencer_alone_restarts() {
    let state = dir("net");
    let address = free_address();
    let url = format!("http://{address}");
    let server = Running::start(address, &state);
    let config =
        canton_sequencer_server::new_synchronizer_in(&state, "testsync", "ts1", 1).unwrap();
    let physical = config.physical_synchronizer_id();
    let mediator = mediator_node::start(&url, &state, 0).expect("the mediator joins");
    let mut m1 = common::join(&url, &config, "alpha");
    let mut m2 = common::join(&url, &config, "beta");
    let alice = common::host(&mut m1, &physical, "alice");
    let bob = common::host(&mut m2, &physical, "bob");
    let one = Node::open(
        m1.identity,
        m1.client,
        m1.token,
        &physical,
        &dar(),
        m1.cursor,
    )
    .unwrap();
    let two = Node::open(
        m2.identity,
        m2.client,
        m2.token,
        &physical,
        &dar(),
        m2.cursor,
    )
    .unwrap();
    let (one, two) = (
        Arc::new(SharedNode::new(one)),
        Arc::new(SharedNode::new(two)),
    );
    let (_r1, _r2) = (one.start_reader(), two.start_reader());
    let timeout = Duration::from_secs(40);
    // bob (beta) signs a contract alice (alpha) observes; alice's `Touch` consumes it, which bob's participant confirms
    let create = |label: &str| {
        let held = Value::Record {
            tycon: Some("Confirm:Held".into()),
            fields: vec![
                ("r".into(), Value::Party(bob.clone())),
                ("a".into(), Value::Party(alice.clone())),
            ],
        };
        let (id, verdict) = two
            .with(|n| n.submit_create("confirm-subview", "Confirm:Held", &held, label, timeout))
            .unwrap()
            .expect("the create is judged");
        assert_eq!(verdict, Verdict::Approved, "{label}");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while one.with(|n| n.instance_bytes(&id)).unwrap().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "alpha never learned {label}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        id
    };
    let touch = |id: &str, label: &str| {
        one.submit_exercise(
            "confirm-subview",
            id,
            "Touch",
            &Value::Record {
                tycon: None,
                fields: vec![],
            },
            std::slice::from_ref(&alice),
            label,
            None,
            &[],
            timeout,
        )
    };
    let first = create("held-before");
    let second = create("held-after");
    // both participants and the mediator take part
    let (verdict, notes) = touch(&first, "before").unwrap();
    assert_eq!(verdict, Verdict::Approved, "{notes:?}");

    server.stop();
    let server = Running::start(address, &state);
    // nobody was restarted: every token is refused, and every client authenticates again on its own
    let (verdict, notes) =
        touch(&second, "after").expect("the request is judged after the sequencer restarted");
    assert_eq!(verdict, Verdict::Approved, "{notes:?}");
    drop(mediator);
    server.stop();
    let _ = std::fs::remove_dir_all(&state);
}
