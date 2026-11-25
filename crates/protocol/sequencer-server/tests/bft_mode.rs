//! The sequencer in BFT ordering mode: the order of the submissions is decided by an ordering cluster, and it survives the loss of ordering
//! nodes (S-NET-038 part 2).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
mod common;
use canton_sequencer_server::{new_synchronizer, serve_with, ServeOptions};
use std::time::Duration;

fn start_bft(
    control: &std::path::Path,
) -> (
    canton_sequencer_server::SynchronizerConfig,
    String,
    tokio::runtime::Runtime,
) {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = new_synchronizer("bftsync", "bs1");
    let served = config.clone();
    let control = control.to_path_buf();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.spawn(async move {
        serve_with(
            address,
            served,
            ServeOptions {
                bft_f: Some(1),
                control: Some(control),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    (config, format!("http://{address}"), runtime)
}

fn texts(events: &[canton_participant::sequencing_wire::Delivered]) -> Vec<String> {
    events
        .iter()
        .flat_map(|e| e.envelopes.iter())
        .filter_map(|c| String::from_utf8(c.clone()).ok())
        .filter(|t| t.starts_with("m-"))
        .collect()
}

fn far_future() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
        + 60_000_000
}

#[test]
fn submissions_are_ordered_by_the_cluster_also_after_the_leader_crashes() {
    let control =
        std::env::temp_dir().join(format!("canton-rs-bft-{}.control", std::process::id()));
    let _ = std::fs::write(&control, "");
    let (config, url, runtime) = start_bft(&control);
    let physical = config.physical_synchronizer_id();
    let mut a = common::join(&url, &config, "bft-a");
    let mut b = common::join(&url, &config, "bft-b");
    a.settle(&physical);
    b.settle(&physical);
    let b_member = b.identity.member();
    let send = |a: &mut common::Member, from: usize, to: usize| {
        for i in from..to {
            a.send(
                &physical,
                &[(vec![b_member.clone()], format!("m-{i}").into_bytes())],
                &format!("id-{i}"),
                far_future(),
            )
            .unwrap();
        }
    };
    let wait_for = |b: &mut common::Member, count: usize, seconds: u64| -> Vec<String> {
        let limit = std::time::Instant::now() + Duration::from_secs(seconds);
        loop {
            let got = texts(&b.events(&physical, Some(0), 80));
            if got.len() >= count || std::time::Instant::now() > limit {
                return got;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    };
    let want = |n: usize| (0..n).map(|i| format!("m-{i}")).collect::<Vec<_>>();

    // the cluster orders what the members send
    send(&mut a, 0, 4);
    assert_eq!(
        wait_for(&mut b, 4, 15),
        want(4),
        "in the order they were sent, once each"
    );

    // the leader of the ordering cluster is crashed: a view change replaces it and the submissions still get ordered
    std::fs::write(&control, "crash 0\n").unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    send(&mut a, 4, 8);
    assert_eq!(
        wait_for(&mut b, 8, 20),
        want(8),
        "ordered with the leader down"
    );

    // a second node down is more than f: nothing is ordered until one is back
    std::fs::write(&control, "crash 1\n").unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    send(&mut a, 8, 10);
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        texts(&b.events(&physical, Some(0), 80)),
        want(8),
        "no quorum: nothing is sequenced (safety)"
    );
    std::fs::write(&control, "restart 1\nrestart 0\n").unwrap();
    assert_eq!(
        wait_for(&mut b, 10, 30),
        want(10),
        "with the nodes back the submissions are ordered, none lost or twice"
    );
    runtime.shutdown_background();
    let _ = std::fs::remove_file(&control);
}
