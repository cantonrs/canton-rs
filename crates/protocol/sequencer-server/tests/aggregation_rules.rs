//! Aggregation rules as 3.7.2 reads them (`AggregationRule.fromProtoV30`: a mediator group, the sequencer group, or none) and in-flight
//! aggregations that a restart does not forget (`InFlightAggregations` are part of the block sequencer's persisted state).
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::collections::BTreeMap;
use std::sync::Arc;

use canton_participant::sequencing_wire as sw;
use canton_participant::topology_state::MediatorGroup;
use canton_participant::topology_wire::{self as tw, unversioned, versioned, Ed25519Key};
use canton_proto::com::digitalasset::canton::protocol::v30::AggregationRule;
use canton_proto::com::digitalasset::canton::protocol::v33::SubmissionRequest;
use canton_sequencer_server::onboarding::{Registered, Registry};
use canton_sequencer_server::sequencing::Sequencer;
use canton_sequencer_server::synchronizer_state::{signed_by_owners, TopologyStore};
use canton_sequencer_server::{ConnectService, SynchronizerConfig};
use prost::Message as _;
use tokio_stream::StreamExt as _;

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn member(kind: &str, name: &str, seed: u8) -> (String, Ed25519Key, Registered) {
    let key = Ed25519Key::from_seed([seed; 32]);
    let id = format!("{kind}::{name}::{}", key.fingerprint);
    let raw = canton_algo::member_signature::own_ed25519_key(&key.spki_der).unwrap();
    let registered = Registered {
        member: id.clone(),
        signing_keys: vec![raw.clone()],
        authentication_keys: vec![raw],
        encryption_keys: Vec::new(),
    };
    (id, key, registered)
}

fn aggregated(
    sender: &str,
    key: &Ed25519Key,
    id: &str,
    to: &str,
    rule: &[&str],
    max: i64,
) -> Vec<u8> {
    let plain = sw::submission_request_to_groups(
        sender,
        id,
        &[(vec![to.to_string()], b"verdict".to_vec())],
        max,
    );
    let (data, version) = unversioned(&plain).unwrap();
    let mut request = SubmissionRequest::decode(data.as_slice()).unwrap();
    request.aggregation_rule = Some(AggregationRule {
        eligible_members: rule.iter().map(|m| m.to_string()).collect(),
        threshold: 0,
    });
    sw::signed_submission_request(versioned(request.encode_to_vec(), version), key)
}

async fn events(sequencer: &Sequencer, member: &str) -> Vec<sw::Delivered> {
    let mut stream = sequencer.subscribe(member.to_string(), None);
    let mut out = Vec::new();
    while let Ok(Some(Ok(response))) =
        tokio::time::timeout(std::time::Duration::from_millis(300), stream.next()).await
    {
        out.push(sw::decode_delivered(&response.signed_sequenced_event).unwrap());
    }
    out
}

/// A sequencer with its state in `dir`, the `members` registered and mediator group 0 made of `mediators` with threshold two.
fn open(
    config: &SynchronizerConfig,
    dir: Option<&std::path::Path>,
    members: &[Registered],
    mediators: &[&str],
) -> ConnectService {
    let store = Arc::new(TopologyStore::initial(
        &config.name,
        &config.sequencer_name,
        "rm1",
        &config.keys,
    ));
    store.observe_mediator_groups(BTreeMap::from([(
        0,
        MediatorGroup {
            serial: 1,
            threshold: 2,
            active: mediators
                .iter()
                .map(|m| m.trim_start_matches("MED::").to_string())
                .collect(),
            observers: Vec::new(),
        },
    )]));
    let registry = Arc::new(Registry::default());
    for m in members {
        registry.insert(m.clone());
    }
    ConnectService::open_seeded(config.clone(), store, registry, None, dir).unwrap()
}

#[test]
fn a_restart_remembers_who_contributed_to_an_aggregation_in_flight() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let dir =
            std::env::temp_dir().join(format!("seq5-aggregation-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = canton_sequencer_server::new_synchronizer("aggsync", "aggseq");
        let (m1, m1_key, m1_reg) = member("MED", "m1", 71);
        let (m2, m2_key, m2_reg) = member("MED", "m2", 72);
        let (p, _, p_reg) = member("PAR", "p", 73);
        let members = [m1_reg, m2_reg, p_reg];
        let max = now_micros() + 600_000_000;
        let at = now_micros();
        {
            // nothing subscribes here: a subscription would keep the sequencer, and its journal's lock, alive
            let service = open(&config, Some(&dir), &members, &[&m1, &m2]);
            service.sequencer().apply_ordered_at(
                &m1,
                &aggregated(&m1, &m1_key, "v1", &p, &["MGR::0"], max),
                at,
            );
        }
        let service = open(&config, Some(&dir), &members, &[&m1, &m2]);
        let sequencer = service.sequencer();
        sequencer.apply_ordered_at(
            &m1,
            &aggregated(&m1, &m1_key, "v1-again", &p, &["MGR::0"], max),
            at + 1,
        );
        let answers = events(&sequencer, &m1).await;
        let again = answers
            .iter()
            .find(|e| e.message_id.as_deref() == Some("v1-again"))
            .expect("an answer to the second request");
        let why = again
            .error
            .clone()
            .expect("the second contribution of the same sender is refused");
        assert!(why.contains("STUBBORN_SENDER"), "{why}");
        // negative control: the other mediator completes the aggregation begun before the restart
        sequencer.apply_ordered_at(
            &m2,
            &aggregated(&m2, &m2_key, "v2", &p, &["MGR::0"], max),
            at + 2,
        );
        let got = events(&sequencer, &p).await;
        assert_eq!(got.len(), 1, "two of two deliver: {got:?}");
        assert_eq!(got[0].envelopes, vec![b"verdict".to_vec()]);
        drop(service);
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// `sender`'s verdict whose envelope carries `sender`'s own signature of it.
fn signed_verdict(sender: &str, key: &Ed25519Key, id: &str, to: &str, max: i64) -> Vec<u8> {
    let mut hash = vec![0x12, 0x20];
    hash.extend_from_slice(&canton_algo::hash::sha256_with_purpose(38, b"verdict"));
    let plain = sw::submission_request_signed(
        sender,
        id,
        &[(
            vec![to.to_string()],
            b"verdict".to_vec(),
            vec![key.sign_bytes(&hash)],
        )],
        max,
    );
    let (data, version) = unversioned(&plain).unwrap();
    let mut request = SubmissionRequest::decode(data.as_slice()).unwrap();
    request.aggregation_rule = Some(AggregationRule {
        eligible_members: vec!["MGR::0".to_string()],
        threshold: 0,
    });
    sw::signed_submission_request(versioned(request.encode_to_vec(), version), key)
}

#[test]
fn the_delivered_envelope_carries_the_signatures_of_both_mediators_ordered_by_sender() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let config = canton_sequencer_server::new_synchronizer("aggsigs", "as");
        let (m1, m1_key, m1_reg) = member("MED", "m1", 75);
        let (m2, m2_key, m2_reg) = member("MED", "m2", 76);
        let (p, _, p_reg) = member("PAR", "p", 77);
        let service = open(&config, None, &[m1_reg, m2_reg, p_reg], &[&m1, &m2]);
        let sequencer = service.sequencer();
        let max = now_micros() + 600_000_000;
        let at = now_micros();
        // m2 sends first and m1 second: the signatures are still in the order of the senders, not of the sequencing
        sequencer.apply_ordered_at(&m2, &signed_verdict(&m2, &m2_key, "from-m2", &p, max), at);
        sequencer.apply_ordered_at(
            &m1,
            &signed_verdict(&m1, &m1_key, "from-m1", &p, max),
            at + 1,
        );
        let got = events(&sequencer, &p).await;
        assert_eq!(got.len(), 1, "the recipient gets the delivery once");
        let signed_by: Vec<&str> = got[0].envelope_signatures[0]
            .iter()
            .map(|s| s.signed_by.as_str())
            .collect();
        let mut expected = [
            (m1.as_str(), m1_key.fingerprint.as_str()),
            (m2.as_str(), m2_key.fingerprint.as_str()),
        ];
        expected.sort();
        assert_eq!(
            signed_by,
            expected.map(|(_, fp)| fp),
            "both senders' signatures, ordered by sender"
        );
    });
}

#[test]
fn the_sequencer_group_rule_takes_only_the_sequencers_the_topology_names() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let config = canton_sequencer_server::new_synchronizer("seqgroup", "sg");
        let (s1, s1_key, s1_reg) = member("SEQ", "s1", 81);
        let (s2, s2_key, s2_reg) = member("SEQ", "s2", 82);
        let (p, _, p_reg) = member("PAR", "p", 83);
        let store = Arc::new(TopologyStore::initial(
            &config.name,
            &config.sequencer_name,
            "rm1",
            &config.keys,
        ));
        let registry = Arc::new(Registry::default());
        for m in [s1_reg, s2_reg, p_reg] {
            registry.insert(m);
        }
        let sequencer = Sequencer::new(
            config.physical_synchronizer_id(),
            Arc::clone(&config.keys),
            registry,
            Arc::clone(&store),
        );
        let max = now_micros() + 600_000_000;
        let at = now_micros();
        // the synchronizer's own group names its own sequencer, not s1
        sequencer.apply_ordered_at(
            &s1,
            &aggregated(&s1, &s1_key, "early", &p, &["SOD::"], max),
            at,
        );
        let early = events(&sequencer, &s1).await;
        let why = early[0].error.clone().expect("refused outside the group");
        assert!(why.contains("not part of the sequencer group"), "{why}");
        // the group names s1 alone from now on, threshold one (serial 2: the genesis group is serial 1)
        let first = tw::sequencer_synchronizer_state(
            &store.synchronizer_uid(),
            1,
            &[s1.trim_start_matches("SEQ::")],
        );
        let (data, version) = unversioned(&first).unwrap();
        let mut tx =
            canton_proto::com::digitalasset::canton::protocol::v31::TopologyTransaction::decode(
                data.as_slice(),
            )
            .unwrap();
        tx.serial = 2;
        let group = versioned(tx.encode_to_vec(), version);
        // the tracker does not follow sequencer group changes in broadcasts: the store takes it as it takes onboarding transactions
        store.append(&[signed_by_owners(&config.keys, group)], at);
        let later = at + 1_000_000;
        sequencer.apply_ordered_at(
            &s2,
            &aggregated(&s2, &s2_key, "outsider", &p, &["SOD::"], max),
            later,
        );
        let outsider = events(&sequencer, &s2).await;
        let why = outsider[0]
            .error
            .clone()
            .expect("a sequencer outside the group is refused");
        assert!(why.contains("not part of the sequencer group"), "{why}");
        // negative control: a sequencer of the group is delivered at once
        sequencer.apply_ordered_at(
            &s1,
            &aggregated(&s1, &s1_key, "member", &p, &["SOD::"], max),
            later + 1,
        );
        assert_eq!(events(&sequencer, &p).await.len(), 1);
    });
}

#[test]
fn a_rule_that_lists_members_is_not_one_3_7_2_reads() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let config = canton_sequencer_server::new_synchronizer("listed", "ls");
        let (a, a_key, a_reg) = member("PAR", "a", 91);
        let (p, _, p_reg) = member("PAR", "p", 92);
        let store = Arc::new(TopologyStore::initial(
            &config.name,
            &config.sequencer_name,
            "rm1",
            &config.keys,
        ));
        let registry = Arc::new(Registry::default());
        for m in [a_reg, p_reg] {
            registry.insert(m);
        }
        let sequencer = Sequencer::new(
            config.physical_synchronizer_id(),
            Arc::clone(&config.keys),
            registry,
            store,
        );
        let at = now_micros();
        sequencer.apply_ordered_at(
            &a,
            &aggregated(&a, &a_key, "listed", &p, &[&a], at + 60_000_000),
            at,
        );
        let answer = events(&sequencer, &a).await;
        let why = answer[0].error.clone().expect("refused");
        assert!(
            why.contains("SEQUENCER_SUBMISSION_REQUEST_MALFORMED_REJECTED"),
            "{why}"
        );
        assert!(events(&sequencer, &p).await.is_empty());
        // negative control: the empty rule deduplicates the sender's own requests and delivers the first
        sequencer.apply_ordered_at(
            &a,
            &aggregated(&a, &a_key, "dedup", &p, &[], at + 60_000_000),
            at + 1,
        );
        assert_eq!(events(&sequencer, &p).await.len(), 1);
    });
}
