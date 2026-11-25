//! S-17: Standalone Rust mediator (`mediator_node::start_own`) connected directly to the official
//! Canton 3.7.2 JVM sequencer (`s1`) of `scripts/verify-sequencer-connect.sh`.
//!
//! Exercises live onboarding via `MediatorIdentity`, mediator group assignment (`MGR::1`), live
//! topology tracking after `start_own` (hosting consortium party `erin` + package vetting), and three
//! end-to-end verdict scenarios judged alongside official JVM participant `p1`:
//! 1. Positive control (`Approve`): verified Ed25519 verdict signature from the Rust mediator AND
//!    observed contract commitment on `p1`'s JSON Ledger API (`/v2/state/active-contracts`).
//! 2. Negative control (`ParticipantReject`): out-of-bounds ledger time rejected by `p1` with
//!    `LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND` and forwarded in the Rust mediator's signed verdict.
//! 3. Negative control (`MediatorReject` timeout): unresponsive participant timed out by the Rust
//!    mediator using `s1`'s synchronizer clock (`ask_for_time` time proof).
#![cfg(feature = "jvm-mediator-tests")]
#![allow(clippy::unwrap_used, reason = "integration oracle test")]

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use canton_algo::member_signature::own_ed25519_key;
use canton_participant::confirmation_wire as cw;
use canton_participant::contract_id as ci;
use canton_participant::contract_wire::{authentication_data, ContractInstance, LfValue};
use canton_participant::merkle_wire as mw;
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect, Token};
use canton_participant::sequencing_wire as sw;
use canton_participant::state_store::FileStore;
use canton_participant::topology_state::decode as decode_topology_state;
use canton_participant::topology_wire::{self as tw, ParticipantIdentity};
use canton_participant::view_acs::{decode_verdict, mediator_signed, Verdict, VerdictKind};
use canton_participant::view_message as vm;
use canton_proto::com::digitalasset::canton::crypto::v30::public_key::Key;
use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
use canton_sequencer_server::mediator_identity::MediatorIdentity;
use canton_sequencer_server::mediator_node::{start_own, start_own_with_options, MediatorOptions};
use canton_sequencer_server::persistence::{hex, unhex};

fn var(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set (scripts/verify-sequencer-connect.sh)"))
}

fn unique(prefix: &str) -> String {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst) % 1000;
    format!("{prefix}-{nanos}{n:03}")
}

fn fresh(label: &str) -> [u8; 32] {
    canton_algo::hash::sha256_with_purpose(1, unique(label).as_bytes())
}

fn fresh_uuid() -> String {
    let h = fresh("med-uuid");
    format!(
        "{}-{}-4{}-8{}-{}",
        hex(&h[0..4]),
        hex(&h[4..6]),
        &hex(&h[6..8])[1..],
        &hex(&h[8..10])[1..],
        hex(&h[10..16])
    )
}

fn node_log() -> String {
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

fn log_line_with(needles: &[&str], timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(line) = node_log()
            .lines()
            .find(|l| needles.iter().all(|n| l.contains(n)))
        {
            return Some(line.to_string());
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[derive(Debug, PartialEq, Eq)]
enum MemberAckStatus {
    NotRegistered,
    RegisteredUnacked,
    Acknowledged(i64),
}

fn query_s1_last_acknowledged(member: &str) -> MemberAckStatus {
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    let fname = format!("{}.pruningstatus", unique("pruning"));
    std::fs::write(dir.join(format!("{fname}.tmp")), member).unwrap();
    std::fs::rename(dir.join(format!("{fname}.tmp")), dir.join(&fname)).unwrap();
    let line = log_line_with(
        &["SCF pruningstatus_done=", &fname],
        Duration::from_secs(15),
    )
    .unwrap_or_else(|| {
        panic!(
            "s1 never answered pruningstatus for {fname}:\n{}",
            node_log()
        )
    });
    let prefix = format!("SCF pruningstatus_done={fname}=");
    let payload = line.split_once(&prefix).map(|(_, p)| p).unwrap_or("");
    for entry in payload.split(';') {
        if let Some((m, ts)) = entry.split_once('=') {
            if m == member {
                return if ts == "none" {
                    MemberAckStatus::RegisteredUnacked
                } else {
                    MemberAckStatus::Acknowledged(
                        ts.parse::<i64>().expect("valid lastAcknowledged micros"),
                    )
                };
            }
        }
    }
    MemberAckStatus::NotRegistered
}

fn tx_hash_in_log(transaction_bytes: &[u8]) -> String {
    let digest = hex(&tw::transaction_hash(transaction_bytes)[2..]);
    digest[..12].to_string()
}

fn authenticated_participant(name: &str) -> (ParticipantIdentity, SequencerConnect, Token) {
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let logical = synchronizer
        .rsplit_once("::")
        .map(|(uid, _)| uid.to_string())
        .expect("physical synchronizer id");
    let identity = ParticipantIdentity::generate(name);
    let mut client = SequencerConnect::connect(&var("CANTON_RS_SEQUENCER_URL"))
        .expect("connect to official sequencer");
    client
        .register_onboarding(
            &identity.member(),
            &synchronizer,
            identity.onboarding_transactions(&logical),
        )
        .expect("official sequencer accepts helper participant onboarding");
    for _ in 0..60 {
        if let Ok(challenge) = client.challenge(&identity.member(), &[37]) {
            let sig = identity
                .sequencer_auth_key
                .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &synchronizer).unwrap());
            let token = client
                .authenticate(&identity.member(), &challenge.nonce, sig)
                .expect("authenticate helper participant");
            return (identity, client, token);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!(
        "helper participant {} never became active on s1",
        identity.member()
    );
}

fn broadcast(
    r: &ParticipantIdentity,
    c: &mut SequencerConnect,
    token: &Token,
    synchronizer: &str,
    transactions: &[canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction],
) {
    let now = c
        .sequencer_time(&r.member(), synchronizer, Some(token))
        .unwrap()
        .unwrap();
    let envelopes = vec![(
        vec![tw::ALL_MEMBERS.to_string()],
        tw::topology_broadcast(synchronizer, transactions),
    )];
    c.send_async(
        &r.member(),
        synchronizer,
        token,
        sw::signed_submission_request(
            sw::submission_request_to_groups(
                &r.member(),
                &unique("med-topo"),
                &envelopes,
                now + 60_000_000,
            ),
            &r.signing_key,
        ),
    )
    .expect("s1 accepts topology broadcast");
}

fn have_p1_authorize(tx_hash_multihash: &[u8]) {
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let hex_hash = hex(tx_hash_multihash);
    let count = |what: &str| {
        node_log()
            .lines()
            .filter(|l| l.contains(&format!("SCF {what}={hex_hash}")))
            .count()
    };
    for _ in 0..30 {
        let failed_before = count("authorize_failed");
        let name = format!("{}.req", unique("med-auth"));
        std::fs::write(dir.join(format!("{name}.tmp")), &hex_hash).unwrap();
        std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();
        for _ in 0..30 {
            if count("authorized") > 0 {
                return;
            }
            if count("authorize_failed") > failed_before {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("p1 never authorized {hex_hash}");
}

fn register_mediator_group_on_s1(group: u32, med_uid: &str) {
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let name = format!("{}.medgroup", unique("rust-medgroup"));
    let done_needle = format!("SCF medgroup_done={name}={group}");
    let fail_needle = format!("SCF medgroup_failed={name} ");
    std::fs::write(
        dir.join(format!("{name}.tmp")),
        format!("{group},{med_uid}"),
    )
    .unwrap();
    std::fs::rename(dir.join(format!("{name}.tmp")), dir.join(&name)).unwrap();

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let log = node_log();
        if let Some(line) = log.lines().find(|l| l.contains(&fail_needle)) {
            panic!("s1 rejected mediator group {group} for {med_uid}: {line}");
        }
        if log.lines().any(|l| l.contains(&done_needle)) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for s1 to register mediator group {group} for {med_uid}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn subscribe_until(
    c: &mut SequencerConnect,
    member: &str,
    synchronizer: &str,
    token: &Token,
    after_micros: i64,
    wait: Duration,
) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Vec::new();
        }
        match c.subscribe(
            member,
            synchronizer,
            token,
            Some(after_micros),
            1,
            remaining.min(Duration::from_secs(5)),
        ) {
            Ok(events) if !events.is_empty() => return events,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    }
}

fn p1_http_raw(method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    use std::io::{Read, Write};
    let addr = var("CANTON_RS_P1_HTTP");
    let mut stream = std::net::TcpStream::connect(&addr).expect("p1 JSON API is reachable");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let payload = body.unwrap_or("");
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
    (status, body_text)
}

fn parse_offset_from_ledger_end(body: &str) -> Option<u64> {
    let idx = body.find("\"offset\"")?;
    let after = &body[idx + "\"offset\"".len()..];
    let colon = after.find(':')?;
    let trimmed = after[colon + 1..].trim_start();
    let digits_start = trimmed.strip_prefix('"').unwrap_or(trimmed);
    let digits: String = digits_start
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

struct M1Create {
    envelopes: Vec<(Vec<String>, Vec<u8>)>,
    root_hash: Vec<u8>,
    contract_id_hex: String,
    max_sequencing_time_micros: i64,
}

struct CreateTarget<'a> {
    r: &'a ParticipantIdentity,
    synchronizer: &'a str,
    p1_member: &'a str,
    p1_enc_spki: &'a [u8],
    p1_enc_fp: &'a str,
    erin: &'a str,
    alice: &'a str,
    sample_package: &'a str,
}

fn build_create_for_mediator_group(
    target: &CreateTarget<'_>,
    now_micros: i64,
    ledger_time_offset_micros: i64,
) -> M1Create {
    let CreateTarget {
        r,
        synchronizer,
        p1_member,
        p1_enc_spki,
        p1_enc_fp,
        erin,
        alice,
        sample_package,
    } = *target;
    let preparation_time = now_micros;
    let ledger_time = now_micros + ledger_time_offset_micros;
    let uuid = fresh_uuid();
    let vpd_salt = fresh("med-vpd");
    let salt = ci::contract_salt(&ci::SaltInputs {
        view_participant_data_salt: &vpd_salt,
        create_index: 0,
        view_position: &[vec![]],
        transaction_uuid: &uuid,
        synchronizer_id: synchronizer,
        mediator: "MGR::1",
    });
    let signatories = vec![erin.to_string()];
    let hash_arg = ci::HashValue::Record {
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        fields: vec![
            ("bank".into(), ci::HashValue::Party(erin.to_string())),
            ("owner".into(), ci::HashValue::Party(erin.to_string())),
            ("auditor".into(), ci::HashValue::Party(alice.to_string())),
            ("assetSymbol".into(), ci::HashValue::Text("USD".into())),
            (
                "amount".into(),
                ci::HashValue::Numeric(100 * 10_000_000_000),
            ),
        ],
    };
    let contract_hash = ci::lf_contract_hash(
        "sample-contract",
        &["AssetHolding".into()],
        &["AssetHolding".into()],
        &hash_arg,
    );
    let mut stakeholders = vec![erin.to_string(), alice.to_string()];
    stakeholders.sort();
    stakeholders.dedup();
    let unicum = ci::unicum(
        &salt,
        &ci::UnicumInputs {
            created_at_micros: ledger_time,
            signatories: &signatories,
            stakeholders: &stakeholders,
            key: None,
            contract_hash: &contract_hash,
        },
    );
    let node_seed = fresh("med-seed");
    let discriminator =
        ci::derive_contract_discriminator(&node_seed, preparation_time, &stakeholders);
    let id_hex = ci::contract_id(&discriminator, &unicum);
    let instance = ContractInstance {
        contract_id: unhex(&id_hex).unwrap(),
        package_name: "sample-contract".into(),
        package_id: sample_package.to_string(),
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        arg: LfValue::Record(vec![
            LfValue::Party(erin.to_string()),
            LfValue::Party(erin.to_string()),
            LfValue::Party(alice.to_string()),
            LfValue::Text("USD".into()),
            LfValue::Numeric("100.0000000000".into()),
        ]),
        signatories: signatories.iter().cloned().collect(),
        stakeholders: stakeholders.iter().cloned().collect(),
        created_at_micros: ledger_time,
        authentication_data: authentication_data(&salt),
        key: None,
    };
    let vpd = mw::view_participant_data_create(&instance.encode(), &id_hex, &node_seed, &vpd_salt);
    let uid = r.uid();
    let common = mw::common_metadata(synchronizer, 1, &fresh("med-cm"), &uuid);
    let participant =
        mw::participant_metadata(ledger_time, preparation_time, None, &fresh("med-pm"));
    let max_sequencing_time_micros = now_micros + 60_000_000;
    let submitter = mw::submitter_metadata(
        &mw::SubmitterInfo {
            act_as: vec![erin],
            user_id: "rust-med-oracle",
            command_id: &unique("med-cmd"),
            submitting_participant_uid: &uid,
            submission_id: None,
            dedup_duration: (300, 0),
            max_sequencing_time_micros,
        },
        &fresh("med-sm"),
    );
    let mut informees = stakeholders;
    informees.push(uid.clone());
    informees.sort();
    informees.dedup();
    let informee_refs: Vec<&str> = informees.iter().map(String::as_str).collect();
    let mut confirmers: Vec<(&str, i32)> = vec![(erin, 1), (uid.as_str(), 1)];
    confirmers.sort();
    let vcd = mw::view_common_data(
        &informee_refs,
        &[mw::QuorumSpec {
            confirmers,
            threshold: 2,
        }],
        &fresh("med-vcd"),
    );
    let view = |participant_data: &mw::Tree| {
        mw::view_node(
            &mw::Tree::leaf(&vcd),
            participant_data,
            &mw::merkle_seq(&[]),
        )
    };
    let full_view = view(&mw::Tree::leaf(&vpd));
    let full = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::leaf(&participant),
        &mw::merkle_seq(std::slice::from_ref(&full_view)),
    );
    let informee = mw::gen_transaction_tree(
        &mw::Tree::leaf(&submitter),
        &mw::Tree::leaf(&common),
        &mw::Tree::blinded(participant.root_hash()),
        &mw::merkle_seq(&[view(&mw::Tree::blinded(vpd.root_hash()))]),
    );
    assert_eq!(full.root_hash, informee.root_hash);
    let view_sig = r.signing_key.sign_bytes(&full.root_hash);
    let encrypted = vm::encrypted_view_message(
        &vm::light_view_tree(&full),
        &full_view.hash,
        &fresh("med-rand")[..16].try_into().unwrap(),
        &fresh("med-iv")[..12].try_into().unwrap(),
        &[
            vm::Recipient {
                encryption_spki: p1_enc_spki,
                fingerprint: p1_enc_fp,
                ecies_iv: fresh("med-eiv1")[..16].try_into().unwrap(),
                ecies_ephemeral_scalar: fresh("med-eeph1"),
            },
            vm::Recipient {
                encryption_spki: r.encryption_spki(),
                fingerprint: &r.encryption_fingerprint(),
                ecies_iv: fresh("med-eiv2")[..16].try_into().unwrap(),
                ecies_ephemeral_scalar: fresh("med-eeph2"),
            },
        ],
        synchronizer,
        view_sig,
    );
    let med = cw::mediator_group(1);
    let envelopes = vec![
        (
            vec![med.clone()],
            cw::informee_message(&informee, &r.signing_key),
        ),
        (
            vec![med.clone(), p1_member.to_string()],
            cw::root_hash_message(&full.root_hash, synchronizer, now_micros),
        ),
        (
            vec![med, r.member()],
            cw::root_hash_message(&full.root_hash, synchronizer, now_micros),
        ),
        (vec![p1_member.to_string(), r.member()], encrypted),
    ];
    M1Create {
        envelopes,
        root_hash: full.root_hash,
        contract_id_hex: id_hex,
        max_sequencing_time_micros,
    }
}

/// One console command of the sandbox (`<n>.trafficcmd`), answered with what the console printed.
fn traffic_command(command: &str) -> String {
    let dir = Path::new(&var("CANTON_RS_WORK_DIR")).join("authorize");
    std::fs::create_dir_all(&dir).unwrap();
    let file = format!("{}.trafficcmd", unique("u58"));
    std::fs::write(dir.join(format!("{file}.tmp")), command).unwrap();
    std::fs::rename(dir.join(format!("{file}.tmp")), dir.join(&file)).unwrap();
    log_line_with(&["SCF trafficcmd_done=", &file], Duration::from_secs(60))
        .unwrap_or_else(|| panic!("the console never finished {command}"))
}

/// Turns traffic control off again however the test ends.
struct TrafficOff;
impl Drop for TrafficOff {
    fn drop(&mut self) {
        println!("U58 traffic disable: {}", traffic_command("disable"));
    }
}

/// Traffic control the U-58 test turns on: max base traffic, read-vs-write scaling factor, base event cost.
const U58_TRAFFIC: (u64, u64, u64) = (1_000_000, 200, 7);

#[test]
fn standalone_rust_mediator_decides_requests_on_official_jvm_sequencer() {
    standalone(false);
}

/// U-58: the same three verdicts with traffic control on. The official sequencer refuses any submission of a participant or a mediator that
/// carries no cost (`IncorrectEventCost`), so the verdicts (and the time proofs the timeout needs) reach the participants only when the
/// Rust mediator pays for them. **It turns traffic control on for the shared sandbox (and off at the end): run it alone.**
#[test]
#[ignore = "turns traffic control on for the shared sandbox; run it alone"]
fn standalone_rust_mediator_pays_its_traffic_on_official_jvm_sequencer() {
    standalone(true);
}

fn standalone(traffic: bool) {
    let sequencer_url = var("CANTON_RS_SEQUENCER_URL");
    let synchronizer = var("CANTON_RS_EXPECT_SYNCHRONIZER");
    let p1_member = var("CANTON_RS_MEMBER_P1");
    let p1_uid = p1_member.trim_start_matches("PAR::").to_string();
    let p1_enc_fp = var("CANTON_RS_P1_ENCRYPTION_FINGERPRINT");
    let alice = var("CANTON_RS_ALICE");
    let sample_pkg = var("CANTON_RS_SAMPLE_PACKAGE");

    let state_dir = std::env::temp_dir().join(unique("canton-rs-jvm-med"));
    let _ = std::fs::remove_dir_all(&state_dir);
    let store: Arc<dyn canton_participant::state_store::StateStore> =
        FileStore::new(&state_dir).unwrap();
    let identity = MediatorIdentity::load_or_create(store.as_ref(), "rust-med").unwrap();
    let med_pub_key =
        own_ed25519_key(&identity.signing_key.spki_der).expect("mediator signing public key");

    let (r, mut c, token) = authenticated_participant(&unique("r-med"));

    // Read p1's encryption key SPKI and the synchronizer confirmation response timeout from official topology state.
    let topo_items = c
        .download_topology_state(&r.member(), &synchronizer, &token)
        .expect("download topology state");
    let decoded = decode_topology_state(&topo_items).expect("decode topology state");
    let p1_enc_spki = decoded
        .iter()
        .find_map(|e| match e.tx.mapping.as_ref()?.mapping.as_ref()? {
            Mapping::OwnerToKeyMapping(m) if m.member == p1_member => {
                m.public_keys.iter().find_map(|k| match &k.key {
                    Some(Key::EncryptionPublicKey(enc)) => Some(enc.public_key.clone()),
                    _ => None,
                })
            }
            _ => None,
        })
        .expect("p1 encryption key in topology state");
    let confirmation_timeout_secs = decoded
        .iter()
        .find_map(|e| match e.tx.mapping.as_ref()?.mapping.as_ref()? {
            Mapping::SynchronizerParametersState(s) => {
                let dur = s
                    .synchronizer_parameters
                    .as_ref()?
                    .confirmation_response_timeout
                    .as_ref()?;
                Some(u64::try_from(dur.seconds.max(1)).unwrap_or(30))
            }
            _ => None,
        })
        .unwrap_or(30);

    // 1. Broadcast mediator identity transactions to ALL members and assign MGR::1 via official s1 owner.
    let onboarding = identity.onboarding_transactions();
    let onboarding_hashes: Vec<String> = onboarding
        .iter()
        .map(|tx| tx_hash_in_log(&tx.transaction))
        .collect();
    broadcast(&r, &mut c, &token, &synchronizer, &onboarding);
    for h in &onboarding_hashes {
        log_line_with(
            &[
                "sequencer=s1",
                "Storing topology transaction",
                &format!("TxHash(SHA-256:{h}"),
            ],
            Duration::from_secs(60),
        )
        .unwrap_or_else(|| panic!("s1 never stored mediator identity tx {h}"));
    }
    std::thread::sleep(Duration::from_secs(1));

    register_mediator_group_on_s1(1, &identity.uid());
    let p1_ns = &p1_uid.split("::").nth(1).unwrap()[..12];
    let _ = log_line_with(
        &["participant=p1", "MediatorSynchronizerState", p1_ns],
        Duration::from_secs(10),
    );
    std::thread::sleep(Duration::from_secs(2));

    // 2. Phase 1 negative control: start standalone Rust mediator with acknowledge_enabled=false on JVM s1.
    let med_no_ack = start_own_with_options(
        &sequencer_url,
        Arc::clone(&store),
        MediatorOptions {
            acknowledge_enabled: false,
        },
    )
    .expect("standalone Rust mediator connects to official JVM s1 (no-ack Phase 1)");
    assert_eq!(med_no_ack.group, 1);
    assert_eq!(med_no_ack.member, identity.member());
    assert!(med_no_ack.telemetry.connected.load(Ordering::SeqCst));

    // 3. Host consortium party `erin` (r Submission + p1 Confirmation, threshold 1) and vet `sample-contract`
    //    AFTER starting `med_no_ack` so live topology tracking from JVM s1 broadcasts is proven.
    let hosting = r.shared_party_proposal("erin", &p1_uid);
    let hosting_hash_raw = tw::transaction_hash(&hosting.transaction);
    let hosting_log_hash = tx_hash_in_log(&hosting.transaction);
    let vetting = r.vetting_transaction(std::slice::from_ref(&sample_pkg));
    let vetting_log_hash = tx_hash_in_log(&vetting.transaction);
    broadcast(&r, &mut c, &token, &synchronizer, &[hosting, vetting]);
    for h in [&hosting_log_hash, &vetting_log_hash] {
        log_line_with(
            &[
                "participant=p1",
                "Storing topology transaction",
                &format!("TxHash(SHA-256:{h}"),
            ],
            Duration::from_secs(60),
        )
        .unwrap_or_else(|| panic!("p1 never stored {h}"));
    }
    have_p1_authorize(&hosting_hash_raw);
    log_line_with(
        &[
            "sequencer=s1",
            "Storing topology transaction",
            &format!("TxHash(SHA-256:{hosting_log_hash}"),
            &r.namespace()[..12],
            p1_ns,
        ],
        Duration::from_secs(60),
    )
    .expect("s1 stored co-signed erin hosting");
    std::thread::sleep(Duration::from_secs(2));
    let erin = r.party_id("erin");

    let mut cursor = c
        .sequencer_time(&r.member(), &synchronizer, Some(&token))
        .unwrap()
        .unwrap();

    // U-58: traffic control goes on while the Rust mediator runs, so it must read the parameters from the live topology.
    let _off = traffic.then(|| {
        let (max, factor, base) = U58_TRAFFIC;
        let enabled = traffic_command(&format!("enable,{max},{factor},{base}"));
        assert!(
            enabled.contains("=ok"),
            "traffic control turned on: {enabled}"
        );
        TrafficOff
    });
    // The helper participant pays as the official sequencer client does: every envelope to `MGR::1` (the Rust mediator alone) or to one member.
    let pay = |signed: Vec<u8>| -> Vec<u8> {
        if !traffic {
            return signed;
        }
        let (_, factor, base) = U58_TRAFFIC;
        let envelopes: Vec<(usize, usize)> = sw::submission_envelopes(&signed)
            .expect("own submission decodes")
            .into_iter()
            .map(|(size, addresses)| (size, addresses.len()))
            .collect();
        let cost = canton_algo::traffic_cost::event_cost(factor, base, &envelopes);
        sw::with_submission_cost(&signed, i64::try_from(cost).unwrap(), &r.signing_key)
            .expect("own submission takes its cost")
    };
    if traffic {
        // Negative control on the sequencer: an unpaid submission is refused (at submission time) once the parameters are in force.
        let mut refusal = None;
        for _ in 0..60 {
            let now = c
                .sequencer_time(&r.member(), &synchronizer, Some(&token))
                .unwrap()
                .unwrap();
            let sent = c.send_async(
                &r.member(),
                &synchronizer,
                &token,
                sw::signed_time_proof_request(
                    &r.member(),
                    &unique("u58-unpaid"),
                    now + 30_000_000,
                    &r.signing_key,
                ),
            );
            if let Err(e) = sent {
                refusal = Some(format!("{e:?}"));
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let refusal =
            refusal.expect("s1 never refused an unpaid submission with traffic control on");
        println!("U58 unpaid refusal: {refusal}");
        assert!(
            refusal.contains("IncorrectEventCost"),
            "an unpaid submission is refused for its cost: {refusal}"
        );
        // the Rust mediator applies the same topology change at the same effective time; give it a moment to process it
        std::thread::sleep(Duration::from_secs(2));
    }

    let send_create_and_get_req_id = |c: &mut SequencerConnect,
                                      cursor: &mut i64,
                                      ledger_time_offset_micros: i64|
     -> (i64, M1Create) {
        let now = c
            .sequencer_time(&r.member(), &synchronizer, Some(&token))
            .unwrap()
            .unwrap();
        let built = build_create_for_mediator_group(
            &CreateTarget {
                r: &r,
                synchronizer: &synchronizer,
                p1_member: &p1_member,
                p1_enc_spki: &p1_enc_spki,
                p1_enc_fp: &p1_enc_fp,
                erin: &erin,
                alice: &alice,
                sample_package: &sample_pkg,
            },
            now,
            ledger_time_offset_micros,
        );
        let msg_id = unique("med-submit");
        let req = sw::submission_request_to_groups(
            &r.member(),
            &msg_id,
            &built.envelopes,
            built.max_sequencing_time_micros,
        );
        c.send_async(
            &r.member(),
            &synchronizer,
            &token,
            pay(sw::signed_submission_request(req, &r.signing_key)),
        )
        .expect("s1 accepts request targeting MGR::1");
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let events = subscribe_until(
                c,
                &r.member(),
                &synchronizer,
                &token,
                *cursor + 1,
                Duration::from_secs(5),
            );
            for raw in &events {
                let d = sw::decode_delivered(raw).unwrap();
                *cursor = d.timestamp_micros;
                if d.message_id.as_deref() == Some(msg_id.as_str()) {
                    assert!(
                        d.error.is_none(),
                        "s1 refused own submission {msg_id}: {:?}",
                        d.error
                    );
                    return (d.timestamp_micros, built);
                }
            }
        }
        panic!("timed out waiting for own submission {msg_id}");
    };

    let send_r_approval = |c: &mut SequencerConnect, req_id: i64, root_hash: &[u8]| {
        let uid = r.uid();
        let (resp_content, resp_sigs) = cw::confirmation_responses(
            req_id,
            root_hash,
            &synchronizer,
            &r.member(),
            &[cw::ViewResponse {
                view_position: &[vec![]],
                outcome: cw::Outcome::Approve,
                // Confirm ONLY r.uid() so official JVM p1 MUST confirm erin for the quorum to settle.
                confirming_parties: std::slice::from_ref(&uid),
            }],
            &r.signing_key,
        );
        c.send_async(
            &r.member(),
            &synchronizer,
            &token,
            pay(sw::signed_submission_request(
                sw::submission_request_signed(
                    &r.member(),
                    &unique("med-resp"),
                    &[(vec![cw::mediator_group(1)], resp_content, resp_sigs)],
                    req_id + 30_000_000,
                ),
                &r.signing_key,
            )),
        )
        .expect("s1 accepts confirmation response to MGR::1");
    };

    let wait_for_signed_verdict =
        |c: &mut SequencerConnect, cursor: &mut i64, req_id: i64, timeout: Duration| -> Verdict {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let events = subscribe_until(
                    c,
                    &r.member(),
                    &synchronizer,
                    &token,
                    *cursor + 1,
                    remaining,
                );
                for raw in &events {
                    let d = sw::decode_delivered(raw).unwrap();
                    *cursor = d.timestamp_micros;
                    for (i, content) in d.envelopes.iter().enumerate() {
                        if let Some((verdict, signed_hash)) = decode_verdict(content) {
                            if verdict.request_id == req_id {
                                let sigs =
                                    d.envelope_signatures.get(i).cloned().unwrap_or_default();
                                assert!(
                                    sigs.iter()
                                        .any(|s| s.signed_by == identity.signing_key.fingerprint),
                                    "verdict not signed by rust mediator key {}: {sigs:?}",
                                    identity.signing_key.fingerprint
                                );
                                assert!(
                                mediator_signed(
                                    &sigs,
                                    &signed_hash,
                                    std::slice::from_ref(&med_pub_key)
                                ),
                                "verdict signature failed Ed25519 verification under mediator key"
                            );
                                return verdict;
                            }
                        }
                    }
                }
            }
            panic!("timed out waiting for verdict on request {req_id}");
        };

    // Phase 1 negative control execution: verify mediator judges req0 while keeping lastAcknowledged unacked (`none`).
    let (req0, create0) = send_create_and_get_req_id(&mut c, &mut cursor, 0);
    send_r_approval(&mut c, req0, &create0.root_hash);
    let verdict0 = wait_for_signed_verdict(&mut c, &mut cursor, req0, Duration::from_secs(30));
    assert_eq!(verdict0.kind, VerdictKind::Approve, "{verdict0:?}");
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        query_s1_last_acknowledged(&med_no_ack.member),
        MemberAckStatus::RegisteredUnacked,
        "mediator with acknowledge_enabled=false must stay RegisteredUnacked on s1"
    );
    drop(med_no_ack);

    // Phase 2: restart standalone Rust mediator (`mediator_node::start_own`) with default acknowledging enabled.
    let mediator = start_own(&sequencer_url, Arc::clone(&store))
        .expect("standalone Rust mediator connects to official JVM s1");
    assert_eq!(mediator.group, 1);
    assert_eq!(mediator.member, identity.member());
    assert!(mediator.telemetry.connected.load(Ordering::SeqCst));

    // Scenario A (positive control): Approve — p1 commits the contract after verifying our Rust mediator's verdict.
    let (req_ok, create_ok) = send_create_and_get_req_id(&mut c, &mut cursor, 0);
    send_r_approval(&mut c, req_ok, &create_ok.root_hash);
    let verdict_ok = wait_for_signed_verdict(&mut c, &mut cursor, req_ok, Duration::from_secs(30));
    assert_eq!(verdict_ok.kind, VerdictKind::Approve, "{verdict_ok:?}");
    assert!(
        mediator.telemetry.verdicts_approved.load(Ordering::Relaxed) >= 1,
        "expected verdicts_approved >= 1"
    );

    let acs_deadline = Instant::now() + Duration::from_secs(20);
    let mut p1_committed = false;
    let mut last_debug = String::new();
    while Instant::now() < acs_deadline {
        let (st_end, body_end) = p1_http_raw("GET", "/v2/state/ledger-end", None);
        if st_end == 200 {
            if let Some(end_off) = parse_offset_from_ledger_end(&body_end) {
                let end_str = end_off.to_string();
                let acs_req = [
                    r#"{"activeAtOffset":"#,
                    end_str.as_str(),
                    r#","eventFormat":{"filtersByParty":{""#,
                    alice.as_str(),
                    r#"":{"cumulative":[{"identifierFilter":{"WildcardFilter":{"value":{"includeCreatedEventBlob":false}}}}]}},"verbose":true}}"#,
                ]
                .concat();
                let (st_acs, body_acs) =
                    p1_http_raw("POST", "/v2/state/active-contracts", Some(&acs_req));
                if st_acs == 200 && body_acs.contains(&create_ok.contract_id_hex) {
                    p1_committed = true;
                    break;
                }
                last_debug = format!(
                    "end=({st_end},{body_end}) acs=({st_acs},{})",
                    &body_acs[..body_acs.len().min(600)]
                );
            } else {
                last_debug = format!("end=({st_end},{body_end}) [unparsed offset]");
            }
        } else {
            last_debug = format!("end=({st_end},{body_end})");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if !p1_committed {
        let full_log = node_log();
        let relevant_log: Vec<&str> = full_log
            .lines()
            .filter(|l| {
                l.contains("participant=p1")
                    && (l.contains("WARN")
                        || l.contains("ERROR")
                        || l.contains("Alarm")
                        || l.contains(&req_ok.to_string())
                        || l.contains("Mediator"))
            })
            .rev()
            .take(25)
            .collect();
        panic!(
            "official p1 never committed {} approved by standalone Rust mediator MGR::1; last_debug={last_debug}\np1 log tail:\n{}",
            create_ok.contract_id_hex,
            relevant_log.into_iter().rev().collect::<Vec<_>>().join("\n")
        );
    }

    // Scenario B (negative control): ParticipantReject (out-of-bounds ledger time rejected by official JVM p1).
    let rejected_before = mediator.telemetry.verdicts_rejected.load(Ordering::Relaxed);
    let (req_rej, create_rej) = send_create_and_get_req_id(&mut c, &mut cursor, -120_000_000);
    send_r_approval(&mut c, req_rej, &create_rej.root_hash);
    let verdict_rej =
        wait_for_signed_verdict(&mut c, &mut cursor, req_rej, Duration::from_secs(30));
    assert_eq!(
        verdict_rej.kind,
        VerdictKind::ParticipantReject,
        "{verdict_rej:?}"
    );
    assert!(
        verdict_rej
            .reason
            .contains("LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND"),
        "expected out-of-bounds rejection reason, got {:?}",
        verdict_rej
    );
    assert_eq!(
        mediator.telemetry.verdicts_rejected.load(Ordering::Relaxed),
        rejected_before + 1
    );

    // Scenario C (negative control): MediatorReject timeout via sequencer clock (`ask_for_time` time proof).
    let (req_to, _create_to) = send_create_and_get_req_id(&mut c, &mut cursor, 0);
    let verdict_to = wait_for_signed_verdict(
        &mut c,
        &mut cursor,
        req_to,
        Duration::from_secs(confirmation_timeout_secs + 45),
    );
    assert_eq!(
        verdict_to.kind,
        VerdictKind::MediatorReject { malformed: false },
        "{verdict_to:?}"
    );
    assert_eq!(
        mediator.telemetry.verdicts_rejected.load(Ordering::Relaxed),
        rejected_before + 2
    );

    // R-17 (S-17): verify official JVM s1 recorded AcknowledgeSigned from the standalone Rust mediator (>= req_ok),
    // and negative controls: non-acking `r` is RegisteredUnacked and an absent member is NotRegistered.
    let ack_deadline = Instant::now() + Duration::from_secs(65);
    let mut med_status = query_s1_last_acknowledged(&mediator.member);
    while !matches!(med_status, MemberAckStatus::Acknowledged(ts) if ts >= req_ok)
        && Instant::now() < ack_deadline
    {
        std::thread::sleep(Duration::from_secs(2));
        med_status = query_s1_last_acknowledged(&mediator.member);
    }
    let MemberAckStatus::Acknowledged(med_ack) = med_status else {
        panic!(
            "official JVM s1 never recorded AcknowledgeSigned >= {req_ok} from Rust mediator {}: {med_status:?}",
            mediator.member
        );
    };
    assert!(
        med_ack >= req_ok,
        "expected lastAcknowledged >= req_ok ({req_ok}), got {med_ack}"
    );
    assert_eq!(
        query_s1_last_acknowledged(&r.member()),
        MemberAckStatus::RegisteredUnacked,
        "helper participant {} never sends AcknowledgeSigned so s1 status must be RegisteredUnacked",
        r.member()
    );
    assert_eq!(
        query_s1_last_acknowledged(
            "MED::unregistered::1220000000000000000000000000000000000000000000000000000000000000"
        ),
        MemberAckStatus::NotRegistered,
        "unregistered mediator ID must return MemberAckStatus::NotRegistered"
    );

    drop(mediator);
    let _ = std::fs::remove_dir_all(&state_dir);
}
