//! Shared by the tests: a Rust sequencer on a free local port.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![allow(
    dead_code,
    reason = "helper or sentinel retained for protocol/test binary compatibility"
)]
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect, Token};
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::ParticipantIdentity;
use canton_sequencer_server::{serve, SynchronizerConfig};
use std::time::Duration;

pub fn start() -> (SynchronizerConfig, String) {
    start_with_groups(1)
}

/// A Rust sequencer with an admin port: its configuration, public URL and admin URL.
pub fn start_with_admin() -> (SynchronizerConfig, String, String) {
    let free = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    };
    let (address, admin) = (free(), free());
    let config = canton_sequencer_server::new_synchronizer_with_groups("testsync", "ts1", 1);
    let served = config.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(canton_sequencer_server::serve_with(
                address,
                served,
                canton_sequencer_server::ServeOptions {
                    admin_address: Some(admin),
                    ..Default::default()
                },
            ))
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok()
            && std::net::TcpStream::connect(admin).is_ok()
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    (
        config,
        format!("http://{address}"),
        format!("http://{admin}"),
    )
}

/// A Rust sequencer with `groups` mediator groups.
pub fn start_with_groups(groups: usize) -> (SynchronizerConfig, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = canton_sequencer_server::new_synchronizer_with_groups("testsync", "ts1", groups);
    let served = config.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(serve(address, served))
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    (config, format!("http://{address}"))
}

pub struct Member {
    pub identity: ParticipantIdentity,
    pub client: SequencerConnect,
    pub token: Token,
    /// The timestamp of the last event of the member's setup (its registration broadcast and the tick after it): what the tests read after.
    pub cursor: i64,
}

pub fn join(url: &str, config: &SynchronizerConfig, label: &str) -> Member {
    let identity = ParticipantIdentity::generate(label);
    let physical = config.physical_synchronizer_id();
    let mut client = SequencerConnect::connect(url).unwrap();
    client
        .register_onboarding(
            &identity.member(),
            &physical,
            identity.onboarding_transactions(&format!(
                "{}::{}",
                config.name, config.namespace_fingerprint
            )),
        )
        .unwrap();
    let challenge = client.challenge(&identity.member(), &[37]).unwrap();
    let signature = identity
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap());
    let token = client
        .authenticate(&identity.member(), &challenge.nonce, signature)
        .unwrap();
    let mut member = Member {
        identity,
        client,
        token,
        cursor: 0,
    };
    // the registration is broadcast to every member and a tick follows once it has taken effect: wait for both
    std::thread::sleep(Duration::from_millis(700));
    let setup = member.events(&physical, Some(0), 8);
    assert!(
        setup.len() >= 2,
        "the broadcast and the tick reached the member: {}",
        setup.len()
    );
    member.cursor = setup.last().unwrap().timestamp_micros;
    member
}

impl Member {
    /// Moves the cursor to the end of everything the member was sent so far (members that joined later broadcast their registration too).
    pub fn settle(&mut self, physical: &str) {
        std::thread::sleep(Duration::from_millis(700));
        let all = self.events(physical, Some(0), 40);
        self.cursor = all.last().unwrap().timestamp_micros;
    }

    pub fn send(
        &mut self,
        physical: &str,
        groups: &[(Vec<String>, Vec<u8>)],
        id: &str,
        max: i64,
    ) -> Result<(), canton_participant::sequencer_connect::ConnectError> {
        let request = sw::submission_request_to_groups(&self.identity.member(), id, groups, max);
        self.client.send_async(
            &self.identity.member(),
            physical,
            &self.token,
            sw::signed_submission_request(request, &self.identity.signing_key),
        )
    }

    /// The events of the member after its setup (`from` counts from the setup's end; `Some(t)` is an absolute time as the protocol has it).
    pub fn events(
        &mut self,
        physical: &str,
        from: Option<i64>,
        count: usize,
    ) -> Vec<sw::Delivered> {
        let from = match from {
            None => Some(self.cursor + 1),
            other => other,
        };
        self.client
            .subscribe(
                &self.identity.member(),
                physical,
                &self.token,
                from,
                count,
                Duration::from_secs(5),
            )
            .unwrap()
            .iter()
            .map(|e| sw::decode_delivered(e).expect("an event this client decodes"))
            .collect()
    }
}

pub fn far_future() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
        + 60_000_000
}

/// The informee tree of a request with one root view (the `informees` confirm with weight 1 each, the quorum needs `threshold`; the first
/// informee is the party the request acts as), built in Rust.
pub fn request_tree(
    r: &ParticipantIdentity,
    informees: &[&str],
    threshold: i32,
    group: u32,
    now: i64,
    synchronizer: &str,
) -> canton_participant::merkle_wire::GenTree {
    let informee = informees[0];
    use canton_participant::merkle_wire as mw;
    let fresh = |label: &str| -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(label.as_bytes());
        h.update(now.to_be_bytes());
        h.update(informee.as_bytes());
        h.finalize().to_vec()
    };
    let uid = r.member().trim_start_matches("PAR::").to_string();
    let common = mw::common_metadata(
        synchronizer,
        group as i32,
        &fresh("cm"),
        &format!("{:032x}", now),
    );
    let participant = mw::participant_metadata(now, now, None, &fresh("pm"));
    let submitter = mw::submitter_metadata(
        &mw::SubmitterInfo {
            act_as: vec![informee],
            user_id: "rust-user",
            command_id: "cmd",
            submitting_participant_uid: &uid,
            submission_id: None,
            dedup_duration: (300, 0),
            max_sequencing_time_micros: now + 60_000_000,
        },
        &fresh("sm"),
    );
    let vcd = mw::view_common_data(
        informees,
        &[mw::QuorumSpec {
            confirmers: informees.iter().map(|i| (*i, 1)).collect(),
            threshold,
        }],
        &fresh("vcd"),
    );
    let mut vpd_hash = vec![0x12, 0x20];
    vpd_hash.extend_from_slice(&fresh("vpd"));
    let view = mw::view_node(
        &mw::Tree::leaf(&vcd),
        &mw::Tree::blinded(vpd_hash),
        &mw::merkle_seq(&[]),
    );
    mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::blinded(participant.root_hash()),
        &mw::merkle_seq(&[view]),
    )
}

/// `m` broadcasts that it hosts its own party `name` and waits until that is in force. Returns the party's id.
pub fn host(m: &mut Member, physical: &str, name: &str) -> String {
    let hosting = m.identity.party_hosting_transaction(name);
    let request = sw::submission_request_to_groups(
        &m.identity.member(),
        &format!("hosting-{name}"),
        &[(
            vec![canton_participant::topology_wire::ALL_MEMBERS.to_string()],
            canton_participant::topology_wire::topology_broadcast(physical, &[hosting]),
        )],
        far_future(),
    );
    m.client
        .send_async(
            &m.identity.member(),
            physical,
            &m.token,
            sw::signed_submission_request(request, &m.identity.signing_key),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(800));
    m.identity.party_id(name)
}

/// A topology broadcast that sets the synchronizer's `confirmation_response_timeout` to `seconds` (parameters at serial `serial`), signed by
/// the synchronizer's namespace key: what the owner of a synchronizer does to change its dynamic parameters.
pub fn parameters_broadcast(config: &SynchronizerConfig, serial: u32, seconds: i64) -> Vec<u8> {
    parameters_broadcast_with(config, serial, |p| {
        p.confirmation_response_timeout = Some(prost_types::Duration { seconds, nanos: 0 })
    })
}

/// A topology broadcast of the synchronizer's dynamic parameters at serial `serial`: the defaults as `change` leaves them, signed by both owners
/// of the synchronizer's namespace.
pub fn parameters_broadcast_with(
    config: &SynchronizerConfig,
    serial: u32,
    change: impl FnOnce(
        &mut canton_proto::com::digitalasset::canton::protocol::v30::DynamicSynchronizerParameters,
    ),
) -> Vec<u8> {
    use canton_participant::topology_wire as tw;
    use canton_proto::com::digitalasset::canton::protocol::v31::TopologyTransaction;
    use prost::Message;
    let mut parameters = tw::default_dynamic_parameters();
    change(&mut parameters);
    let first = tw::synchronizer_parameters_state(
        &format!("{}::{}", config.name, config.namespace_fingerprint),
        parameters,
    );
    let (data, version) = tw::unversioned(&first).unwrap();
    let mut tx = TopologyTransaction::decode(data.as_slice()).unwrap();
    tx.serial = serial;
    let bytes = tw::versioned(tx.encode_to_vec(), version);
    // the synchronizer's namespace is owned by the sequencer's and the mediator's together: both sign
    let signatures = vec![
        config.keys.namespace.sign_transaction(&bytes),
        config.keys.mediator_namespace.sign_transaction(&bytes),
    ];
    tw::topology_broadcast(
        &config.physical_synchronizer_id(),
        &[tw::signed(bytes, signatures)],
    )
}

/// A topology broadcast announcing the upgrade of the synchronizer to serial `serial` at `upgrade_micros`, signed by both owners of its namespace.
pub fn announcement_broadcast(
    config: &SynchronizerConfig,
    serial: u32,
    upgrade_micros: i64,
) -> Vec<u8> {
    use canton_participant::topology_wire as tw;
    use canton_proto::com::digitalasset::canton::protocol::v30::LsuAnnouncement;
    use canton_proto::com::digitalasset::canton::protocol::v31::{
        topology_mapping, TopologyMapping, TopologyTransaction,
    };
    use prost::Message;
    let base = tw::synchronizer_parameters_state("x::y", tw::default_dynamic_parameters());
    let (data, version) = tw::unversioned(&base).unwrap();
    let mut tx = TopologyTransaction::decode(data.as_slice()).unwrap();
    tx.serial = 1;
    tx.mapping = Some(TopologyMapping {
        mapping: Some(topology_mapping::Mapping::SynchronizerUpgradeAnnouncement(
            LsuAnnouncement {
                successor_physical_synchronizer_id: format!(
                    "{}::{}::37-{serial}",
                    config.name, config.namespace_fingerprint
                ),
                upgrade_time: Some(prost_types::Timestamp {
                    seconds: upgrade_micros.div_euclid(1_000_000),
                    nanos: (upgrade_micros.rem_euclid(1_000_000) * 1000) as i32,
                }),
            },
        )),
    });
    let bytes = tw::versioned(tx.encode_to_vec(), version);
    let signatures = vec![
        config.keys.namespace.sign_transaction(&bytes),
        config.keys.mediator_namespace.sign_transaction(&bytes),
    ];
    tw::topology_broadcast(
        &config.physical_synchronizer_id(),
        &[tw::signed(bytes, signatures)],
    )
}

/// A Rust sequencer whose mediators run as processes of their own: its state directory holds the keys they use (kept under `dir`).
pub fn start_external_mediator(dir: &std::path::Path) -> (SynchronizerConfig, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = canton_sequencer_server::new_synchronizer_in(dir, "testsync", "ts1", 1).unwrap();
    let served = config.clone();
    let state = dir.to_path_buf();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(canton_sequencer_server::serve_with(
                address,
                served,
                canton_sequencer_server::ServeOptions {
                    state_dir: Some(state),
                    external_mediator: true,
                    ..Default::default()
                },
            ))
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    (config, format!("http://{address}"))
}
