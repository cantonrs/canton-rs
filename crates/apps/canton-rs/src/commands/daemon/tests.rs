use super::bootstrap::parse_bootstrap;
use super::*;
use canton_participant::hocon::parse;

/// The script of `deploy/hub/canton/bootstrap.sc`.
const HUB: &str = r#"
val connected = participant1.synchronizers.list_connected()
if (connected.isEmpty) {
  bootstrap.synchronizer(
    synchronizerName = "hub-sync",
    sequencers = Seq(sequencer1),
    mediators = Seq(mediator1),
    synchronizerOwners = Seq(sequencer1),
    synchronizerThreshold = PositiveInt.one,
    staticSynchronizerParameters = StaticSynchronizerParameters.defaultsWithoutKMS(ProtocolVersion.forSynchronizer)
  )
  participant1.synchronizers.connect_local(sequencer1, "hub-sync")
}
"#;

/// A configuration says out loud what the daemon does not apply (the keys of a node it reads are applied, a connection pool setting changes nothing a
/// client sees, the rest is listed).
#[test]
fn the_configuration_coverage_counts_applied_harmless_and_unapplied_keys() {
    let conf = parse(
        r#"canton {
              participants.p1 {
                storage { type = postgres, config { properties { serverName = "db", portNumber = 5432 } }, parameters.max-connections = 8 }
                ledger-api { port = 6501, auth-services = [{ type = jwt-rs-256-crt, certificate = "x.crt" }], tls.cert-chain-file = "chain.crt" }
                http-ledger-api.port = 6575
                parameters.enable-preview-commands = yes
              }
              sequencers.s1.sequencer.type = BFT
              monitoring.logging.api.message-payloads = true
            }"#,
        &|_| None,
    )
    .unwrap();
    let (applied, harmless, not_applied) = configuration_coverage(&conf);
    // the storage type, its two properties, the Ledger API's port and the auth service's two keys, the HTTP port
    assert_eq!(applied, 7);
    // the connection pool setting and the lone `sequencer.type = BFT`
    assert_eq!(harmless, 2);
    assert_eq!(
        not_applied,
        vec![
            "canton.participants.p1.ledger-api.tls.cert-chain-file",
            "canton.participants.p1.parameters.enable-preview-commands",
            "canton.monitoring.logging.api.message-payloads",
        ]
    );
    // valid BFT network config counts its supported leaves as applied
    let peers = parse(
        r#"canton { sequencers.s1.sequencer { type = BFT, config.initial-network.server-endpoint.port = 31030 } }"#,
        &|_| None,
    )
    .unwrap();
    let (bft_applied, _, not_applied) = configuration_coverage(&peers);
    assert!(not_applied.is_empty(), "{not_applied:?}");
    assert_eq!(bft_applied, 2);

    // BFT TLS or an unknown BFT knob keeps unapplied entries so `--strict-config` rejects it
    let tls_peers = parse(
        r#"canton { sequencers.s1.sequencer { type = BFT, config { unknown-knob = 1, initial-network.server-endpoint { port = 31030, external-tls-config.enabled = true } } } }"#,
        &|_| None,
    )
    .unwrap();
    let (_, _, not_applied) = configuration_coverage(&tls_peers);
    assert!(
        !not_applied.is_empty(),
        "expected TLS/unknown BFT keys in not_applied"
    );
}

/// A port offset that pushes a configured port past 65535 is refused instead of wrapping.
#[test]
fn port_offset_overflow_is_refused() {
    let conf = parse(
        r#"canton { sequencers.s1.public-api.port = 65000 }"#,
        &|_| None,
    )
    .unwrap();
    assert!(check_port_offset(&conf, 500).is_ok());
    let err = check_port_offset(&conf, 600).expect_err("overflow refused");
    assert!(err.contains("overflows"), "{err}");
}

/// The daemon applies a participant's auth services, but a sequencer's or mediator's are not implemented: they are listed as not applied,
/// so `--strict-config` refuses them.
#[test]
fn sequencer_and_mediator_auth_services_are_not_applied() {
    let conf = parse(
        r#"canton {
              sequencers.s1 { public-api.port = 4401, admin-api { port = 4402, auth-services = [{ type = wildcard }] } }
              mediators.m1.admin-api { port = 4602, admin-token-config.fixed-admin-token = "t" }
            }"#,
        &|_| None,
    )
    .unwrap();
    let (_, _, not_applied) = configuration_coverage(&conf);
    assert!(
        not_applied
            .iter()
            .any(|k| k.starts_with("canton.sequencers.s1.admin-api.auth-services")),
        "{not_applied:?}"
    );
    assert!(
        not_applied
            .iter()
            .any(|k| k.starts_with("canton.mediators.m1.admin-api.admin-token-config")),
        "{not_applied:?}"
    );
}

#[test]
fn the_hub_bootstrap_script_is_read() {
    let b = parse_bootstrap(HUB, &["sequencer1", "mediator1", "participant1"]).unwrap();
    assert_eq!(b.synchronizer_name, "hub-sync");
    assert_eq!(
        b.connections,
        [(
            "participant1".to_string(),
            "sequencer1".to_string(),
            "hub-sync".to_string()
        )]
    );
    assert_eq!(b.owners, vec!["sequencer1".to_string()]);
    assert_eq!(b.threshold, 1);
    assert!(b.pings.is_empty());
}

#[test]
fn two_peers_conf_has_only_wildcard_addresses_unapplied() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../references/canton-3.7.2/dist/examples/11-bft-sequencer/two-peers.conf"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let conf = parse(&text, &|_| None).unwrap();
    let (applied, _, not_applied) = configuration_coverage(&conf);
    assert!(applied > 0);
    assert_eq!(
        not_applied,
        vec![
            "canton.sequencers.sequencer1.public-api.address",
            "canton.sequencers.sequencer1.admin-api.address",
            "canton.sequencers.sequencer2.public-api.address",
            "canton.sequencers.sequencer2.admin-api.address",
        ],
        "only 0.0.0.0 addresses should be reported as unapplied"
    );
}

#[test]
fn address_coverage_marks_non_loopback_binds_as_not_applied() {
    let conf = parse(
        r#"canton {
              participants.p1 {
                http-ledger-api { address = "127.0.0.1", port = 7575 }
                ledger-api { address = "10.0.0.5", port = 6501 }
              }
              sequencers.s1.public-api { address = "0.0.0.0", port = 4401 }
            }"#,
        &|_| None,
    )
    .unwrap();
    let (applied, _, not_applied) = configuration_coverage(&conf);
    assert_eq!(applied, 4);
    assert_eq!(
        not_applied,
        vec![
            "canton.participants.p1.ledger-api.address",
            "canton.sequencers.s1.public-api.address",
        ]
    );
}

#[test]
fn two_peers_ping_bootstrap_is_read() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../references/canton-3.7.2/dist/examples/11-bft-sequencer/two-peers-ping.canton"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let b = parse_bootstrap(
        &text,
        &[
            "sequencer1",
            "sequencer2",
            "mediator1",
            "mediator2",
            "participant1",
            "participant2",
        ],
    )
    .unwrap();
    assert_eq!(b.synchronizer_name, "da");
    assert_eq!(
        b.owners,
        vec!["sequencer1".to_string(), "sequencer2".to_string()]
    );
    assert_eq!(b.threshold, 2);
    assert_eq!(b.connections.len(), 2);
    assert_eq!(
        b.connections[0],
        ("participant1".into(), "sequencer1".into(), "da".into())
    );
    assert_eq!(
        b.connections[1],
        (
            "participant2".into(),
            "http://localhost:4411".into(),
            "da".into()
        )
    );
    assert_eq!(
        b.pings,
        vec![("participant2".into(), "participant1".into())]
    );
}

#[test]
fn a_call_the_daemon_does_not_run_is_an_error() {
    let script = format!("{HUB}\nparticipant1.parties.enable(\"alice\")\n");
    let e = parse_bootstrap(&script, &["participant1", "sequencer1", "mediator1"]).unwrap_err();
    assert!(e.contains("participant1.parties.enable"), "{e}");
    assert!(
        parse_bootstrap("val x = 1", &[]).is_err(),
        "no bootstrap.synchronizer"
    );
}
