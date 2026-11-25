//! What the tests against an official Canton 3.7.2 sandbox share: the environment the harness script exports, a Rust-made
//! participant registered and authenticated on the official sequencer, parties hosted together with p1, the participant runtime's
//! loop and p1's JSON Ledger API. Used by `tests/sequencer_connect.rs` (`scripts/verify-sequencer-connect.sh`) and by
//! `tests/receive_simclock.rs` (`scripts/verify-receive-simclock.sh`, the sandbox on a simulated clock, S-SPL-036).
#![allow(
    dead_code,
    reason = "helper or sentinel retained for protocol/test binary compatibility"
)] // each test target uses a different subset

pub use canton_algo::signing::PublicKey as SigningKey;
use canton_participant::participant_runtime as rt;
use canton_participant::sequencer_connect::SequencerConnect;

pub fn var(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set (scripts/verify-sequencer-connect.sh or scripts/verify-receive-simclock.sh)"))
}

pub fn client() -> SequencerConnect {
    SequencerConnect::connect(&var("CANTON_RS_SEQUENCER_URL")).expect("connect to the sequencer")
}

pub fn synchronizer_uid() -> String {
    let physical = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    physical
        .rsplit_once("::")
        .map(|(uid, _)| uid.to_string())
        .expect("a physical synchronizer id")
}

/// Registers a new Rust-made participant and waits until the sequencer lets it ask for a challenge (measured: about a second).
pub fn registered_participant(
    name: &str,
) -> (
    canton_participant::topology_wire::ParticipantIdentity,
    SequencerConnect,
) {
    use canton_participant::topology_wire::ParticipantIdentity;
    let identity = ParticipantIdentity::generate(name);
    let mut c = client();
    c.register_onboarding(
        &identity.member(),
        &var("CANTON_RS_EXPECT_SYNCHRONIZER"),
        identity.onboarding_transactions(&synchronizer_uid()),
    )
    .expect("the synchronizer accepts the identity transactions");
    for _ in 0..60 {
        match c.challenge(&identity.member(), &[37]) {
            Ok(_) => return (identity, c),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(500)),
        }
    }
    panic!("the registered participant never became a member");
}

/// An authenticated Rust-made participant: its identity, the client and the token.
pub fn authenticated(
    name: &str,
) -> (
    canton_participant::topology_wire::ParticipantIdentity,
    SequencerConnect,
    canton_participant::sequencer_connect::Token,
) {
    use canton_participant::sequencer_connect::AuthKey;
    let (r, mut c) = registered_participant(name);
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let challenge = c.challenge(&r.member(), &[37]).expect("challenge");
    let signature = r
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &synchronizer).unwrap());
    let token = c
        .authenticate(&r.member(), &challenge.nonce, signature)
        .expect("authenticate");
    (r, c, token)
}

pub mod downloaded {
    use canton_participant::topology_wire as tw;
    use canton_proto::com::digitalasset::canton::crypto::v30::public_key::Key;
    // the node writes the transactions of protocol version 37 as v31 messages (party hosting changed from v30)
    use canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction;
    pub use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
    use canton_proto::com::digitalasset::canton::protocol::v31::TopologyTransaction;
    use prost::Message;

    pub struct Entry {
        pub valid_from: i64,
        pub signed: SignedTopologyTransaction,
        pub tx: TopologyTransaction,
    }

    pub fn decode(items: &[(i64, Vec<u8>)]) -> Vec<Entry> {
        items
            .iter()
            .map(|(valid_from, stored)| {
                let (data, version) = tw::unversioned(stored).expect("versioned");
                assert_eq!(version, tw::SIGNED_TOPOLOGY_TRANSACTION_VERSION);
                let signed = SignedTopologyTransaction::decode(data.as_slice()).expect("signed");
                let (inner, v) = tw::unversioned(&signed.transaction).unwrap_or_else(|| {
                    panic!(
                        "versioned transaction: {} bytes {}",
                        signed.transaction.len(),
                        hex::encode(&signed.transaction)
                    )
                });
                assert_eq!(v, tw::TOPOLOGY_TRANSACTION_VERSION);
                let tx = TopologyTransaction::decode(inner.as_slice()).expect("transaction");
                Entry {
                    valid_from: *valid_from,
                    signed,
                    tx,
                }
            })
            .collect()
    }

    pub fn mapping(e: &Entry) -> &Mapping {
        e.tx.mapping
            .as_ref()
            .and_then(|m| m.mapping.as_ref())
            .expect("a mapping")
    }

    pub fn name(m: &Mapping) -> &'static str {
        match m {
            Mapping::NamespaceDelegation(_) => "NamespaceDelegation",
            Mapping::DecentralizedNamespaceDefinition(_) => "DecentralizedNamespaceDefinition",
            Mapping::OwnerToKeyMapping(_) => "OwnerToKeyMapping",
            Mapping::SynchronizerTrustCertificate(_) => "SynchronizerTrustCertificate",
            Mapping::ParticipantPermission(_) => "ParticipantSynchronizerPermission",
            Mapping::PartyHostingLimits(_) => "PartyHostingLimits",
            Mapping::VettedPackages(_) => "VettedPackages",
            Mapping::PartyToParticipant(_) => "PartyToParticipant",
            Mapping::SynchronizerParametersState(_) => "SynchronizerParametersState",
            Mapping::MediatorSynchronizerState(_) => "MediatorSynchronizerState",
            Mapping::SequencerSynchronizerState(_) => "SequencerSynchronizerState",
            Mapping::SequencingDynamicParametersState(_) => "DynamicSequencingParametersState",
            _ => "other",
        }
    }

    /// Every Ed25519 key the state itself registers (namespace delegations and owner-to-key mappings), by fingerprint.
    pub fn keys(
        entries: &[Entry],
    ) -> std::collections::HashMap<String, ed25519_dalek::VerifyingKey> {
        let mut out = std::collections::HashMap::new();
        let mut add = |der: &[u8], spec: i32| {
            // only Ed25519 (EC-Curve25519 = 1): its fingerprint data is the raw key
            if spec == 1 && der.len() >= 32 {
                let raw: [u8; 32] = der[der.len() - 32..].try_into().unwrap();
                if let Ok(k) = ed25519_dalek::VerifyingKey::from_bytes(&raw) {
                    out.insert(tw::fingerprint(&raw), k);
                }
            }
        };
        for e in entries {
            match mapping(e) {
                Mapping::NamespaceDelegation(d) => {
                    if let Some(k) = &d.target_key {
                        add(&k.public_key, k.key_spec);
                    }
                }
                Mapping::OwnerToKeyMapping(m) => {
                    for k in &m.public_keys {
                        if let Some(Key::SigningPublicKey(k)) = &k.key {
                            add(&k.public_key, k.key_spec);
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }
}

pub fn unique(prefix: &str) -> String {
    // [CANTON-NOTE: SEMANTICS] The clock of the test host ticks in microseconds, and the tests run in parallel: two names made at the
    // same instant were equal, so two tests wrote and renamed the *same* command file (one `rename` then found nothing). A counter
    // makes every name different.
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % 1000;
    format!("{prefix}-{nanos}{n:03}")
}

/// The log of the sandbox container (the mediator's lines included).
pub fn node_log() -> String {
    let out = std::process::Command::new("docker")
        .args(["logs", &var("CANTON_RS_CONTAINER")])
        .output()
        .expect("docker logs");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Waits (up to 60 s: the tests run in parallel against one sandbox, and a slow round can take over half a minute) for a log
/// line containing every needle, and returns it.
pub fn log_line_with(needles: &[&str]) -> Option<String> {
    for _ in 0..60 {
        if let Some(l) = node_log()
            .lines()
            .find(|l| needles.iter().all(|n| l.contains(n)))
        {
            return Some(l.to_string());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    None
}

/// Broadcasts `transactions` to every member of the synchronizer as participant `r` does.
pub fn broadcast(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    transactions: &[canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction],
) {
    use canton_participant::{sequencing_wire as sw, topology_wire as tw};
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let now = c
        .sequencer_time(&r.member(), &synchronizer, Some(token))
        .unwrap()
        .unwrap();
    let envelopes = vec![(
        vec![tw::ALL_MEMBERS.to_string()],
        tw::topology_broadcast(&synchronizer, transactions),
    )];
    c.send_async(
        &r.member(),
        &synchronizer,
        token,
        sw::signed_submission_request(
            sw::submission_request_to_groups(
                &r.member(),
                &unique("topo"),
                &envelopes,
                now + 60_000_000,
            ),
            &r.signing_key,
        ),
    )
    .expect("the sequencer accepts the submission");
}

/// The first 12 hex digits of a transaction's hash, as the node's log writes `TxHash(SHA-256:...)`.
pub fn tx_hash_in_log(transaction_bytes: &[u8]) -> String {
    hex::encode(&canton_participant::topology_wire::transaction_hash(transaction_bytes)[2..])[..12]
        .to_string()
}

/// Asks p1 (through the sandbox's watcher) to co-sign the topology transaction with this hash.
pub fn have_p1_authorize(tx_hash_multihash: &[u8]) {
    let dir = std::path::Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let name = format!("{}.req", unique("authorize"));
    // written under another name first and renamed: the watcher must not read half a file
    std::fs::write(
        dir.join(format!("{name}.tmp")),
        hex::encode(tx_hash_multihash),
    )
    .unwrap();
    std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(name)).unwrap();
}

/// p1's signing keys as the topology state lists them.
pub fn p1_signing_keys(
    c: &mut SequencerConnect,
    r: &canton_participant::topology_wire::ParticipantIdentity,
    token: &canton_participant::sequencer_connect::Token,
) -> Vec<SigningKey> {
    signing_keys_of(c, r, token, &var("CANTON_RS_MEMBER_P1"))
}

/// The signing keys the topology state lists for `member`.
pub fn signing_keys_of(
    c: &mut SequencerConnect,
    r: &canton_participant::topology_wire::ParticipantIdentity,
    token: &canton_participant::sequencer_connect::Token,
    member: &str,
) -> Vec<SigningKey> {
    use canton_proto::com::digitalasset::canton::crypto::v30::public_key::Key;
    let state = c
        .download_topology_state(&r.member(), &var("CANTON_RS_EXPECT_SYNCHRONIZER"), token)
        .unwrap();
    downloaded::decode(&state)
        .iter()
        .filter_map(|e| match downloaded::mapping(e) {
            downloaded::Mapping::OwnerToKeyMapping(m) if m.member == member => {
                Some(m.public_keys.clone())
            }
            _ => None,
        })
        .flatten()
        .filter_map(|k| match k.key {
            Some(Key::SigningPublicKey(s)) => {
                Some(canton_algo::signing::parse_public_key(&s).unwrap())
            }
            _ => None,
        })
        .collect()
}

pub fn runtime_config(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    party: &str,
    p1_keys: Vec<SigningKey>,
    mediator_keys: Vec<SigningKey>,
    timeouts: canton_participant::view_acs::Timeouts,
) -> rt::Config {
    rt::Config {
        member: r.member(),
        encryption_fingerprint: r.encryption_fingerprint(),
        encryption_secret: *r.encryption_secret(),
        hosted_parties: vec![party.to_string()],
        timeouts,
        submitter_keys: p1_keys,
        mediator_keys,
        physical_synchronizer_id: var("CANTON_RS_EXPECT_SYNCHRONIZER"),
        peer_encryption_keys: Default::default(),
        topology_change_delay_micros: 250_000,
        follow_topology: false,
    }
}

/// Lets the runtime read events (in windows of a few seconds) until `done` holds or `seconds` are up. Returns every step it took.
pub fn run_until(
    runtime: &mut rt::Runtime,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    key: &canton_participant::topology_wire::Ed25519Key,
    seconds: u64,
    mut done: impl FnMut(&rt::Runtime) -> bool,
) -> Vec<rt::Step> {
    let mut steps = Vec::new();
    let limit = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < limit && !done(runtime) {
        steps.extend(
            runtime
                .poll(c, token, key, std::time::Duration::from_secs(3))
                .expect("the runtime keeps going"),
        );
    }
    steps
}

pub fn state_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("canton-rs-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Hosts the consortium party `name` (p1 submits, this participant confirms) and vets `packages` for this participant.
pub fn host_consortium_party_vetting(
    r: &canton_participant::topology_wire::ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &canton_participant::sequencer_connect::Token,
    name: &str,
    packages: &[String],
) -> String {
    let p1_uid = var("CANTON_RS_MEMBER_P1")
        .trim_start_matches("PAR::")
        .to_string();
    let proposal = r.shared_party_proposal_with(name, &p1_uid, 2, 1, 1);
    let mut transactions = vec![proposal.clone()];
    if !packages.is_empty() {
        transactions.push(r.vetting_transaction(packages));
    }
    let hashes: Vec<String> = transactions
        .iter()
        .map(|t| tx_hash_in_log(&t.transaction))
        .collect();
    let proposal_hash = canton_participant::topology_wire::transaction_hash(&proposal.transaction);
    broadcast(r, c, token, &transactions);
    for hash in &hashes {
        log_line_with(&[
            "participant=p1",
            "Storing topology transaction",
            &format!("TxHash(SHA-256:{hash}"),
        ])
        .expect("p1 stores the transaction");
    }
    have_p1_authorize(&proposal_hash);
    let p1_ns = p1_uid.split("::").nth(1).unwrap()[..12].to_string();
    log_line_with(&[
        "sequencer=s1",
        "Storing topology transaction",
        &format!("TxHash(SHA-256:{}", hashes[0]),
        &r.namespace()[..12],
        &p1_ns,
    ])
    .expect("the synchronizer stores the party signed by both participants");
    std::thread::sleep(std::time::Duration::from_secs(2));
    r.party_id(name)
}

/// One HTTP/1.1 request to p1's JSON Ledger API (no client library: a raw connection).
pub fn p1_http(
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> (u16, serde_json::Value) {
    use std::io::{Read, Write};
    let addr = var("CANTON_RS_P1_HTTP");
    let mut stream = std::net::TcpStream::connect(&addr).expect("p1's JSON API is reachable");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(120)))
        .unwrap();
    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body_text = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut out = String::new();
        let mut cursor = rest;
        while let Some((size_line, after)) = cursor.split_once("\r\n") {
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 || after.len() < size {
                break;
            }
            out.push_str(&after[..size]);
            cursor = after[size..].trim_start_matches("\r\n");
        }
        out
    } else {
        rest.to_string()
    };
    (
        status,
        serde_json::from_str(&body_text).unwrap_or(serde_json::Value::String(body_text)),
    )
}

/// How a receive replay ([`receive_replay`]) runs. The wall-clock replay of `sequencer_connect.rs` uses none of these.
#[derive(Default, Clone, Copy)]
pub struct ReplayOptions {
    /// Wait, before each move of the clock, until the Rust participant has answered p1's last committed request.
    pub settle: bool,
    /// Split a submission where a root names a contract an earlier root of the same transaction creates.
    pub split_roots: bool,
    /// Create, before a transfer, the `ValidatorRight` contracts it names that the recorded history never created.
    pub reconstruct_rights: bool,
    /// Pair the recorded creates of a transaction with p1's per template (`Module:Entity`), in order, instead of by position alone.
    pub match_by_template: bool,
}

/// What a receive replay ([`receive_replay`]) ended with: the replayer's notes (one line per seed and transaction), the reasons of the
/// Rust participant's rejections and how many requests its runtime answered.
pub struct ReceiveReplay {
    pub results: Vec<String>,
    pub rejects: Vec<String>,
    pub answered: usize,
}

/// G8 U-39 (S-SPL-021): the recorded transactions of the official Splice LocalNet, **submitted by p1** one after another over its JSON Ledger
/// API (the recorded root commands with this network's party ids and p1's contract ids), with the Rust participant's runtime as the confirmer
/// of every party. `before` runs before the seeds (`None`, with the recorded bootstrap's effective time) and before each submitted
/// transaction (its index and recorded effective time): the simulated-clock harness moves p1's clock there (S-SPL-036). With `settle`, the
/// replay first waits until the Rust participant has answered p1's last committed request.
/// [CANTON-NOTE: WHY] p1 hosts every party too, and its own confirmation can be enough for the mediator: p1's submission may complete
/// while the Rust answer is still on its way. On a held clock that is harmless, but moving the clock past the answer's max sequencing time
/// (the request time and the confirmation timeout) has the sequencer refuse it (`MAX_SEQUENCING_TIME_EXCEEDED`, measured on the first run).
pub fn receive_replay(
    label: &str,
    seconds: u64,
    options: ReplayOptions,
    before: impl Fn(Option<usize>, &str) + Send + 'static,
) -> ReceiveReplay {
    let ReplayOptions {
        settle,
        split_roots,
        reconstruct_rights,
        match_by_template,
    } = options;
    let dar = var("CANTON_RS_SPLICE_DAR");
    let updates_path = var("CANTON_RS_SPLICE_UPDATES");
    let world = lf_eval::World::open(std::path::Path::new(&dar)).unwrap();
    let (r, mut c, token) = authenticated(&unique(&format!("r-{label}")));
    let packages = world.package_ids();
    let names = ["dso", "sv", "app-provider", "app-user"];
    let parties: Vec<String> = names
        .iter()
        .map(|n| host_consortium_party_vetting(&r, &mut c, &token, n, &packages))
        .collect();
    let p1_keys = p1_signing_keys(&mut c, &r, &token);
    let mediator_keys = signing_keys_of(&mut c, &r, &token, &var("CANTON_RS_MEMBER_M1"));
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let start = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();
    let mut config = runtime_config(
        &r,
        &parties[0],
        p1_keys,
        mediator_keys,
        canton_participant::view_acs::Timeouts::default(),
    );
    config.hosted_parties = parties.clone();
    let dir_state = state_dir(label);
    let engine =
        canton_participant::view_conformance::Engine::load(std::path::Path::new(&dar)).unwrap();
    let mut runtime = rt::Runtime::open(config, engine, Some(&dir_state), start).unwrap();

    let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    // the request times the runtime has answered
    let progress = std::sync::Arc::new(std::sync::Mutex::new(
        std::collections::BTreeSet::<i64>::new(),
    ));
    let worker = {
        let results = std::sync::Arc::clone(&results);
        let progress = std::sync::Arc::clone(&progress);
        let parties = parties.clone();
        std::thread::spawn(move || {
            // the record time of p1's last committed transaction
            let last_record = std::cell::Cell::new(None::<i64>);
            let caught_up = || {
                let Some(record) = last_record.get().filter(|_| settle) else {
                    return;
                };
                let limit = std::time::Instant::now() + std::time::Duration::from_secs(120);
                while std::time::Instant::now() < limit {
                    if progress.lock().unwrap().contains(&record) {
                        // an answer the verdict did not need may still be in the sequencer's queue
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            };
            let committed = |answer: &serde_json::Value| {
                if let Some(t) = answer["transaction"]["recordTime"].as_str() {
                    last_record.set(Some(micros_of_iso(t)));
                }
            };
            use serde_json::{json, Value as J};
            let updates: J =
                serde_json::from_str(&std::fs::read_to_string(updates_path).unwrap()).unwrap();
            let updates = updates["transactions"].as_array().unwrap().clone();
            let world = lf_eval::World::open(std::path::Path::new(&dar)).unwrap();
            let types = lf_eval::typed_json::Types::new(&world);
            let note = |line: String| results.lock().unwrap().push(line);
            // the recorded party ids, found by their names, and the parties of this run in the same order
            let first = updates[0]["events_by_id"].as_object().unwrap();
            let official: Vec<String> = {
                let text = updates
                    .iter()
                    .map(|u| u.to_string())
                    .collect::<Vec<_>>()
                    .join("");
                let find = |prefix: &str| -> String {
                    let pattern = format!("\"{prefix}");
                    let start = text.find(&pattern).expect("the history names the party") + 1;
                    text[start..].chars().take_while(|c| *c != '"').collect()
                };
                let dso = first
                    .values()
                    .find(|e| {
                        e["template_id"]
                            .as_str()
                            .unwrap()
                            .ends_with(":Splice.DsoRules:DsoRules")
                    })
                    .unwrap()["signatories"][0]
                    .as_str()
                    .unwrap()
                    .to_string();
                let sv = updates[2]["events_by_id"]
                    .as_object()
                    .unwrap()
                    .values()
                    .find(|e| e["event_type"] == "exercised_event")
                    .unwrap()["acting_parties"][0]
                    .as_str()
                    .unwrap()
                    .to_string();
                vec![dso, sv, find("app_provider_"), find("app_user_")]
            };
            let swap = |text: &str| -> String {
                let mut out = text.to_string();
                for (o, p) in official.iter().zip(parties.iter()) {
                    out = out.replace(o, p);
                }
                out
            };
            let hosted = |p: &str| official.iter().any(|o| o == p);
            let rights: Vec<J> = parties
                .iter()
                .map(|p| json!({"kind": {"CanActAs": {"value": {"party": p}}}}))
                .collect();
            let (status, _) = p1_http(
                "POST",
                "/v2/users/participant_admin/rights",
                Some(
                    &json!({"userId": "participant_admin", "identityProviderId": "", "rights": rights}),
                ),
            );
            note(format!("rights {status}"));
            caught_up();
            before(
                None,
                updates[0]["effective_at"].as_str().unwrap_or_default(),
            );
            let submit = |label: &str, commands: Vec<J>, act_as: Vec<String>| -> (u16, J) {
                let filter: serde_json::Map<String, J> = parties
                    .iter()
                    .map(|p| (p.clone(), json!({"cumulative": [{"identifierFilter": {"WildcardFilter": {"value": {"includeCreatedEventBlob": false}}}}]})))
                    .collect();
                let body = json!({
                    "commands": {"commands": commands, "commandId": format!("{label}-{}", std::process::id()), "actAs": act_as, "readAs": parties, "userId": "participant_admin"},
                    "transactionFormat": {"eventFormat": {"filtersByParty": filter, "verbose": true}, "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"}
                });
                p1_http(
                    "POST",
                    "/v2/commands/submit-and-wait-for-transaction",
                    Some(&body),
                )
            };
            // the JSON the Daml JSON codec writes for a value read from the recorded scan JSON
            let api = |ty: &lf_eval::typed_json::LfType, json: &J| -> Result<J, String> {
                let value = types.decode(ty, json)?;
                types.encode_contract(ty, &value)
            };
            let mut ids: std::collections::BTreeMap<String, String> = Default::default();
            // every contract id the recorded history creates
            let recorded_creates: std::collections::BTreeSet<String> = updates
                .iter()
                .flat_map(|u| u["events_by_id"].as_object().unwrap().values())
                .filter(|e| e["event_type"] == "created_event")
                .filter_map(|e| e["contract_id"].as_str().map(String::from))
                .collect();
            let ids_in = |text: &str, ids: &std::collections::BTreeMap<String, String>| -> String {
                let mut out = text.to_string();
                for (o, mine) in ids {
                    out = out.replace(o, mine);
                }
                out
            };
            let created_ids = |answer: &J| -> Vec<String> {
                let mut found: Vec<(u64, String)> = answer["transaction"]["events"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| {
                        let c = e.get("CreatedEvent")?;
                        Some((c["nodeId"].as_u64()?, c["contractId"].as_str()?.to_string()))
                    })
                    .collect();
                found.sort();
                found.into_iter().map(|(_, id)| id).collect()
            };
            let order_of = |id: &str| {
                id.rsplit(':')
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(0)
            };
            // the contracts the bootstrap left active
            let consumed_first: std::collections::BTreeSet<&str> = first
                .values()
                .filter(|e| e["event_type"] == "exercised_event" && e["consuming"] == true)
                .map(|e| e["contract_id"].as_str().unwrap())
                .collect();
            let mut seeds: Vec<(&String, &J)> = first.iter().collect();
            seeds.sort_by_key(|(id, _)| order_of(id));
            let mut seeded = 0;
            let mut seeded_or_skipped = 0;
            for (_, e) in seeds {
                if e["event_type"] != "created_event"
                    || consumed_first.contains(e["contract_id"].as_str().unwrap())
                {
                    continue;
                }
                if !["signatories", "observers"].iter().all(|k| {
                    e[*k]
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|p| hosted(p.as_str().unwrap()))
                }) {
                    continue;
                }
                seeded_or_skipped += 1;
                let template_id = e["template_id"].as_str().unwrap();
                let (package, local) = template_id.split_once(':').unwrap();
                let ty = match types.template(package, local) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                let payload: J =
                    serde_json::from_str(&swap(&e["create_arguments"].to_string())).unwrap();
                let Ok(args) = api(&ty, &payload) else {
                    continue;
                };
                let act_as: Vec<String> = e["signatories"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| swap(p.as_str().unwrap()))
                    .collect();
                let (status, answer) = submit(
                    &format!("seed{seeded_or_skipped}"),
                    vec![
                        json!({"CreateCommand": {"templateId": template_id, "createArguments": args}}),
                    ],
                    act_as,
                );
                if status == 200 {
                    committed(&answer);
                    if let Some(id) = created_ids(&answer).first() {
                        note(format!("seed {local} -> {}", &id[..16]));
                        ids.insert(e["contract_id"].as_str().unwrap().to_string(), id.clone());
                        seeded += 1;
                    }
                } else {
                    note(format!(
                        "seed {local}: {status} {}",
                        answer.to_string().chars().take(200).collect::<String>()
                    ));
                }
            }
            note(format!("seeded {seeded}"));
            let (mut approved, mut refused_by_p1) = (0, 0);
            for (index, update) in updates.iter().enumerate().skip(1) {
                let events = update["events_by_id"].as_object().unwrap();
                let roots: Vec<&J> = update["root_event_ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| &events[r.as_str().unwrap()])
                    .collect();
                // [CANTON-NOTE: LIMITATION] The scan history is the DSO's: a `ValidatorRight` (signatories the user and its validator, the
                // DSO only a field) is never in it, yet a transfer names one in its context (`validatorRights`) and fetches it. The source fixes
                // its contents (`AmuletRules`: `requireMatchingContract rightCid (ValidatorRight with dso; validator = sender; user)`), so with
                // `reconstruct_rights` p1 creates that contract at the transaction's recorded time and its id stands for the recorded one.
                if reconstruct_rights {
                    let mut missing: Vec<(String, String, String, String)> = Vec::new();
                    for e in events.values() {
                        if e["choice"] != "AmuletRules_Transfer" {
                            continue;
                        }
                        let argument = &e["choice_argument"];
                        let sender = argument["transfer"]["sender"].as_str().unwrap_or_default();
                        let package = e["template_id"]
                            .as_str()
                            .unwrap()
                            .split(':')
                            .next()
                            .unwrap();
                        for pair in argument["context"]["validatorRights"]
                            .as_array()
                            .into_iter()
                            .flatten()
                        {
                            let (Some(user), Some(right)) = (pair[0].as_str(), pair[1].as_str())
                            else {
                                continue;
                            };
                            if !ids.contains_key(right) && !recorded_creates.contains(right) {
                                missing.push((
                                    package.to_string(),
                                    user.to_string(),
                                    sender.to_string(),
                                    right.to_string(),
                                ));
                            }
                        }
                    }
                    if !missing.is_empty() {
                        caught_up();
                        before(
                            Some(index),
                            update["effective_at"].as_str().unwrap_or_default(),
                        );
                    }
                    for (package, user, validator, right) in missing {
                        let template_id = format!("{package}:Splice.Amulet:ValidatorRight");
                        let Ok(ty) = types.template(&package, "Splice.Amulet:ValidatorRight")
                        else {
                            note(format!(
                                "tx {index}: no ValidatorRight template in {package}"
                            ));
                            continue;
                        };
                        let payload: J = serde_json::from_str(&swap(
                            &json!({"dso": official[0], "user": user, "validator": validator})
                                .to_string(),
                        ))
                        .unwrap();
                        let Ok(args) = api(&ty, &payload) else {
                            note(format!("tx {index}: the ValidatorRight does not encode"));
                            continue;
                        };
                        let act_as: Vec<String> = [&user, &validator].iter().map(|p| swap(p)).fold(
                            Vec::new(),
                            |mut v, p| {
                                if !v.contains(&p) {
                                    v.push(p);
                                }
                                v
                            },
                        );
                        let (status, answer) = submit(
                            &format!("tx{index}-right"),
                            vec![
                                json!({"CreateCommand": {"templateId": template_id, "createArguments": args}}),
                            ],
                            act_as,
                        );
                        match (status, created_ids(&answer).first()) {
                            (200, Some(mine)) => {
                                committed(&answer);
                                note(format!(
                                    "tx {index}: reconstructed ValidatorRight {} -> {}",
                                    &right[..16],
                                    &mine[..16]
                                ));
                                ids.insert(right, mine.clone());
                            }
                            _ => note(format!(
                                "tx {index}: the ValidatorRight was refused: {status} {}",
                                answer.to_string().chars().take(200).collect::<String>()
                            )),
                        }
                    }
                }
                // the recorded contract ids created under each root (its subtree)
                let created_under = |root: &J| -> Vec<(u64, String)> {
                    let mut found = Vec::new();
                    let mut stack = vec![root];
                    while let Some(e) = stack.pop() {
                        if e["event_type"] == "created_event" {
                            let id = e["event_id"].as_str().unwrap_or_default();
                            found.push((
                                order_of(id),
                                e["contract_id"].as_str().unwrap().to_string(),
                            ));
                        }
                        for child in e["child_event_ids"].as_array().into_iter().flatten() {
                            stack.push(&events[child.as_str().unwrap()]);
                        }
                    }
                    found
                };
                // [CANTON-NOTE: LIMITATION] p1's command interface cannot name a contract that an earlier command of the same submission
                // creates. With `split_roots`, a root whose argument names such a contract starts a second submission (at the same
                // recorded time), after the first one's created contracts are known; the recording had them in one transaction.
                let mut batches: Vec<Vec<&J>> = vec![Vec::new()];
                for root in &roots {
                    let current = batches.last().unwrap();
                    let argument = root["choice_argument"].to_string();
                    if split_roots
                        && !current.is_empty()
                        && current
                            .iter()
                            .flat_map(|r| created_under(r))
                            .any(|(_, id)| argument.contains(&id))
                    {
                        batches.push(Vec::new());
                    }
                    batches.last_mut().unwrap().push(root);
                }
                let mut outcome: Result<usize, String> = Ok(0);
                for (part, batch) in batches.iter().enumerate() {
                    // the commands of the roots: an exercise of a contract p1 has, by the recorded id mapped to p1's
                    let mut commands = Vec::new();
                    let mut act_as: Vec<String> = Vec::new();
                    let mut why: Option<String> = None;
                    for root in batch {
                        if root["event_type"] != "exercised_event" {
                            why = Some("a root create".into());
                            break;
                        }
                        if !root["acting_parties"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|p| hosted(p.as_str().unwrap()))
                        {
                            why = Some("a party that is not hosted".into());
                            break;
                        }
                        let Some(mine) = ids.get(root["contract_id"].as_str().unwrap()) else {
                            why = Some("the input is not a contract p1 has".into());
                            break;
                        };
                        let template_id = root["template_id"].as_str().unwrap();
                        let (package, local) = template_id.split_once(':').unwrap();
                        let choice = root["choice"].as_str().unwrap();
                        let Ok(ct) = types.choice(package, local, choice) else {
                            why = Some("the choice is unknown".into());
                            break;
                        };
                        let arg_text = ids_in(&swap(&root["choice_argument"].to_string()), &ids);
                        let arg: J = serde_json::from_str(&arg_text).unwrap();
                        let Ok(arg) = api(&ct.argument, &arg) else {
                            why = Some("the argument does not encode".into());
                            break;
                        };
                        note(format!(
                            "tx {index} root {choice} on {} ({})",
                            &mine[..16],
                            local
                        ));
                        commands.push(json!({"ExerciseCommand": {"templateId": template_id, "contractId": mine, "choice": choice, "choiceArgument": arg}}));
                        for p in root["acting_parties"].as_array().unwrap() {
                            let p = swap(p.as_str().unwrap());
                            if !act_as.contains(&p) {
                                act_as.push(p);
                            }
                        }
                    }
                    if let Some(why) = why {
                        outcome = Err(format!("skipped ({why})"));
                        break;
                    }
                    caught_up();
                    before(
                        Some(index),
                        update["effective_at"].as_str().unwrap_or_default(),
                    );
                    let label = if part == 0 {
                        format!("tx{index}")
                    } else {
                        format!("tx{index}-{part}")
                    };
                    let (status, answer) = submit(&label, commands, act_as);
                    if status != 200 {
                        outcome = Err(format!(
                            "p1 answered {status} ({}) {}",
                            batch[0]["choice"].as_str().unwrap(),
                            answer.to_string().chars().take(260).collect::<String>()
                        ));
                        break;
                    }
                    committed(&answer);
                    // the contracts this submission created, in the recorded order, are p1's from now on; what it consumed is gone
                    let mut official_created: Vec<(u64, String)> = if batches.len() == 1 {
                        events
                            .iter()
                            .filter(|(_, e)| e["event_type"] == "created_event")
                            .map(|(id, e)| {
                                (order_of(id), e["contract_id"].as_str().unwrap().to_string())
                            })
                            .collect()
                    } else {
                        batch.iter().flat_map(|r| created_under(r)).collect()
                    };
                    official_created.sort();
                    if match_by_template {
                        // [CANTON-NOTE: WHY] The scan history is the DSO's view: p1's transaction can create contracts the history never
                        // lists (measured: a split tap submission's `MemberTraffic` took the place of the `ValidatorRewardCoupon` that a later
                        // transfer spends, and p1 refused the transfer with `WRONGLY_TYPED_CONTRACT`). Pairing within a template keeps the
                        // order of each kind and skips what only p1 has.
                        let entity = |template: &str| -> String {
                            template
                                .rsplitn(3, ':')
                                .take(2)
                                .collect::<Vec<_>>()
                                .into_iter()
                                .rev()
                                .collect::<Vec<_>>()
                                .join(":")
                        };
                        let template_of: std::collections::BTreeMap<&str, String> = events
                            .values()
                            .filter(|e| e["event_type"] == "created_event")
                            .map(|e| {
                                (
                                    e["contract_id"].as_str().unwrap(),
                                    entity(e["template_id"].as_str().unwrap()),
                                )
                            })
                            .collect();
                        let mut mine_by_template: std::collections::BTreeMap<
                            String,
                            std::collections::VecDeque<String>,
                        > = Default::default();
                        let mut found: Vec<(u64, String, String)> = answer["transaction"]["events"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|e| {
                                let c = e.get("CreatedEvent")?;
                                Some((
                                    c["nodeId"].as_u64()?,
                                    entity(c["templateId"].as_str()?),
                                    c["contractId"].as_str()?.to_string(),
                                ))
                            })
                            .collect();
                        found.sort();
                        for (_, template, id) in found {
                            mine_by_template.entry(template).or_default().push_back(id);
                        }
                        for (_, o) in official_created {
                            let Some(template) = template_of.get(o.as_str()) else {
                                continue;
                            };
                            if let Some(mine) = mine_by_template
                                .get_mut(template)
                                .and_then(|q| q.pop_front())
                            {
                                ids.insert(o, mine);
                            }
                        }
                    } else {
                        for ((_, o), mine) in official_created.into_iter().zip(created_ids(&answer))
                        {
                            ids.insert(o, mine);
                        }
                    }
                    outcome = outcome.map(|n| n + 1);
                }
                match outcome {
                    Ok(_) => {
                        approved += 1;
                        let split = if batches.len() > 1 {
                            format!(" in {} submissions", batches.len())
                        } else {
                            String::new()
                        };
                        note(format!(
                            "tx {index}: APPROVED ({}){split}",
                            roots[0]["choice"].as_str().unwrap()
                        ));
                        for e in events.values() {
                            if e["event_type"] == "exercised_event" && e["consuming"] == true {
                                ids.remove(e["contract_id"].as_str().unwrap());
                            }
                        }
                    }
                    Err(why) if why.starts_with("skipped") && batches.len() == 1 => {
                        note(format!("tx {index}: {why}"));
                    }
                    Err(why) => {
                        refused_by_p1 += 1;
                        note(format!("tx {index}: {why}"));
                    }
                }
            }
            note(format!(
                "approved {approved}, p1 answered an error to {refused_by_p1}"
            ));
        })
    };
    let mut steps = Vec::new();
    let limit = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < limit && !worker.is_finished() {
        let polled = runtime
            .poll(
                &mut c,
                &token,
                &r.signing_key,
                std::time::Duration::from_secs(3),
            )
            .expect("the runtime keeps going");
        progress.lock().unwrap().extend(
            polled
                .iter()
                .flat_map(|s| s.to_send.iter().map(|a| a.request_time)),
        );
        steps.extend(polled);
    }
    let _ = worker.join();
    let results = results.lock().unwrap().clone();
    eprintln!("RECEIVE REPLAY\n{}", results.join("\n"));
    let answers: Vec<&rt::ToSend> = steps.iter().flat_map(|s| &s.to_send).collect();
    let rejects: Vec<String> = answers
        .iter()
        .filter_map(|a| match &a.decision().outcome {
            canton_participant::confirmation_wire::Outcome::Reject(why) => {
                Some(why.chars().take(400).collect::<String>())
            }
            _ => None,
        })
        .collect();
    eprintln!(
        "RECEIVE REPLAY the runtime answered {} request(s), {} rejected",
        answers.len(),
        rejects.len()
    );
    for why in &rejects {
        eprintln!("RECEIVE REPLAY rejected: {why}");
    }
    let _ = std::fs::remove_dir_all(&dir_state);
    ReceiveReplay {
        results,
        rejects,
        answered: answers.len(),
    }
}

/// A UTC instant as the nodes write it (`2026-11-15T00:12:21.97631Z`), in microseconds since the epoch.
pub fn micros_of_iso(iso: &str) -> i64 {
    let (date, time) = iso
        .trim_end_matches('Z')
        .split_once('T')
        .expect("an ISO time");
    let d: Vec<i64> = date.split('-').map(|x| x.parse().unwrap()).collect();
    let (hms, frac) = time.split_once('.').unwrap_or((time, "0"));
    let t: Vec<i64> = hms.split(':').map(|x| x.parse().unwrap()).collect();
    let micros: i64 = format!("{frac:0<6}")[..6].parse().unwrap();
    // days from civil (Howard Hinnant)
    let (y, m, day) = (if d[1] <= 2 { d[0] - 1 } else { d[0] }, d[1], d[2]);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    ((days * 24 + t[0]) * 60 + t[1]) * 60_000_000 + t[2] * 1_000_000 + micros
}
