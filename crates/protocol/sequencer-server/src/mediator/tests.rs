use super::aggregation::{decide as aggregate_decide, Decision, LocalVote, QuorumState, ViewState};
use super::*;
use canton_participant::view_acs::{decode_verdict, mediator_signed, VerdictKind};

fn pending(views: Vec<ViewState>) -> Pending {
    Pending {
        view_type: ViewType::Transaction,
        response_timeout: RESPONSE_TIMEOUT_MICROS,
        hosting: BTreeMap::new(),
        root_hash: vec![1, 2, 3],
        informee_participants: vec!["PAR::a::1220aa".into(), "PAR::b::1220bb".into()],
        views,
        answered: Default::default(),
    }
}

/// One view whose single quorum asks for `threshold` of the parties (each weight 1).
fn view(parties: &[&str], threshold: u32) -> ViewState {
    ViewState {
        position: vec![vec![]],
        quorums: vec![QuorumState::new(
            parties.iter().map(|p| (p.to_string(), 1)),
            threshold,
        )],
        consortium_voting: BTreeMap::new(),
        rejections: Vec::new(),
    }
}

fn hosting(entries: &[(&str, u32, &[&str])]) -> BTreeMap<String, (u32, Vec<String>)> {
    entries
        .iter()
        .map(|(party, threshold, hosts)| {
            (
                party.to_string(),
                (*threshold, hosts.iter().map(|h| h.to_string()).collect()),
            )
        })
        .collect()
}

fn vote_view(
    p: &mut Pending,
    view_idx: usize,
    h: &BTreeMap<String, (u32, Vec<String>)>,
    party: &str,
    participant_uid: &str,
    vote: LocalVote,
) {
    let member = format!("PAR::{participant_uid}");
    let authorized = BTreeSet::from([party.to_string()]);
    p.views[view_idx].apply_response(h, &member, participant_uid, &authorized, &vote);
}

fn approve(p: &mut Pending, h: &BTreeMap<String, (u32, Vec<String>)>, party: &str, uid: &str) {
    vote_view(p, 0, h, party, uid, LocalVote::Approve);
}

fn reject(p: &mut Pending, h: &BTreeMap<String, (u32, Vec<String>)>, party: &str, uid: &str) {
    vote_view(p, 0, h, party, uid, LocalVote::Reject("rejected".into()));
}

fn abstain(p: &mut Pending, h: &BTreeMap<String, (u32, Vec<String>)>, party: &str, uid: &str) {
    vote_view(p, 0, h, party, uid, LocalVote::Abstain("abstain".into()));
}

#[test]
fn a_quorum_is_met_when_enough_parties_are_confirmed_and_not_before() {
    let h = hosting(&[("alice", 1, &["a::1220aa"]), ("bob", 1, &["b::1220bb"])]);
    let mut p = pending(vec![view(&["alice", "bob"], 2)]);
    assert!(aggregate_decide(&p.views).is_none(), "nobody answered yet");
    approve(&mut p, &h, "alice", "a::1220aa");
    assert!(aggregate_decide(&p.views).is_none(), "one of two");
    approve(&mut p, &h, "bob", "b::1220bb");
    assert!(matches!(
        aggregate_decide(&p.views),
        Some(Decision::Approve)
    ));
}

#[test]
fn a_party_with_a_hosting_threshold_needs_that_many_of_its_hosts() {
    // carol is hosted by two participants and needs both
    let h = hosting(&[("carol", 2, &["a::1220aa", "b::1220bb"])]);
    let mut p = pending(vec![view(&["carol"], 1)]);
    approve(&mut p, &h, "carol", "a::1220aa");
    assert!(aggregate_decide(&p.views).is_none(), "one of the two hosts");
    approve(&mut p, &h, "carol", "b::1220bb");
    assert!(matches!(
        aggregate_decide(&p.views),
        Some(Decision::Approve)
    ));
    // the same host twice is one host
    let mut q = pending(vec![view(&["carol"], 1)]);
    approve(&mut q, &h, "carol", "a::1220aa");
    approve(&mut q, &h, "carol", "a::1220aa");
    assert!(aggregate_decide(&q.views).is_none());
}

#[test]
fn a_rejection_that_makes_a_quorum_unreachable_decides_the_request_at_once() {
    let h = hosting(&[("alice", 1, &["a::1220aa"]), ("bob", 1, &["b::1220bb"])]);
    let mut p = pending(vec![view(&["alice", "bob"], 2)]);
    reject(&mut p, &h, "bob", "b::1220bb");
    assert!(
        matches!(aggregate_decide(&p.views), Some(Decision::Reject(_))),
        "bob cannot confirm any more"
    );
    // Canton 3.7.2 ConsortiumVotingState:
    // threshold = 1, 2 hosts -> 1 LocalReject rejects at once (`rejected >= threshold`), while 1 LocalAbstain leaves it reachable.
    let h2 = hosting(&[("carol", 1, &["a::1220aa", "b::1220bb"])]);
    let mut p_rej = pending(vec![view(&["carol"], 1)]);
    reject(&mut p_rej, &h2, "carol", "a::1220aa");
    assert!(
        matches!(aggregate_decide(&p_rej.views), Some(Decision::Reject(_))),
        "rejected >= consortium threshold decides immediately"
    );
    let mut p_abs = pending(vec![view(&["carol"], 1)]);
    abstain(&mut p_abs, &h2, "carol", "a::1220aa");
    assert!(
        aggregate_decide(&p_abs.views).is_none(),
        "one abstain on 2 hosts with threshold 1 leaves quorum reachable"
    );
    abstain(&mut p_abs, &h2, "carol", "b::1220bb");
    assert!(
        matches!(aggregate_decide(&p_abs.views), Some(Decision::Reject(_))),
        "two abstains make threshold 1 unreachable"
    );

    // threshold = 2, 3 hosts -> 1 LocalReject keeps threshold reachable, 2 LocalRejects reject immediately.
    let h3 = hosting(&[("carol", 2, &["a::1220aa", "b::1220bb", "c::1220cc"])]);
    let mut p3 = pending(vec![view(&["carol"], 1)]);
    reject(&mut p3, &h3, "carol", "a::1220aa");
    assert!(aggregate_decide(&p3.views).is_none());
    reject(&mut p3, &h3, "carol", "b::1220bb");
    assert!(matches!(
        aggregate_decide(&p3.views),
        Some(Decision::Reject(_))
    ));

    // threshold = 2, 4 hosts -> 2 LocalRejects reject immediately (`2 >= 2`), while 2 LocalAbstains stay reachable (`0+2+2 <= 4`).
    let h4 = hosting(&[(
        "carol",
        2,
        &["a::1220aa", "b::1220bb", "c::1220cc", "d::1220dd"],
    )]);
    let mut p4_rej = pending(vec![view(&["carol"], 1)]);
    reject(&mut p4_rej, &h4, "carol", "a::1220aa");
    assert!(aggregate_decide(&p4_rej.views).is_none());
    reject(&mut p4_rej, &h4, "carol", "b::1220bb");
    assert!(matches!(
        aggregate_decide(&p4_rej.views),
        Some(Decision::Reject(_))
    ));
    let mut p4_abs = pending(vec![view(&["carol"], 1)]);
    abstain(&mut p4_abs, &h4, "carol", "a::1220aa");
    abstain(&mut p4_abs, &h4, "carol", "b::1220bb");
    assert!(
        aggregate_decide(&p4_abs.views).is_none(),
        "2 abstains out of 4 hosts leave 2 hosts to meet threshold 2"
    );
}

#[test]
fn every_view_has_to_be_met() {
    let h = hosting(&[("alice", 1, &["a::1220aa"]), ("bob", 1, &["b::1220bb"])]);
    let mut second = view(&["bob"], 1);
    second.position = vec![vec![], vec![true]];
    let mut p = pending(vec![view(&["alice"], 1), second]);
    approve(&mut p, &h, "alice", "a::1220aa");
    assert!(
        aggregate_decide(&p.views).is_none(),
        "the second view has no confirmation"
    );
    vote_view(&mut p, 1, &h, "bob", "b::1220bb", LocalVote::Approve);
    assert!(matches!(
        aggregate_decide(&p.views),
        Some(Decision::Approve)
    ));
}

fn mediator() -> (Mediator, Arc<SynchronizerKeys>) {
    let keys = Arc::new(SynchronizerKeys::generate());
    (
        Mediator::new(
            0,
            "sync::1220ff::37-0".into(),
            std::sync::Arc::clone(&keys),
            Default::default(),
            Arc::new(TopologyStore::initial("sync", "seq", "med", &keys)),
        ),
        keys,
    )
}

#[test]
fn a_request_that_is_not_signed_by_its_submitter_or_not_readable_is_answered_with_a_signed_malformed_verdict(
) {
    let (mediator, keys) = mediator();
    let informee = canton_participant::confirmation_wire::mediator_group(0);
    // an informee message with no tree, to the mediator group alone, and a root hash message for one participant
    let content = tw::versioned(
        EnvelopeContent {
            some_envelope_content: Some(SomeEnvelopeContent::InformeeMessage(Default::default())),
        }
        .encode_to_vec(),
        ENVELOPE_CONTENT_VERSION,
    );
    let root_hash_message =
        canton_participant::confirmation_wire::root_hash_message(&[0; 34], "sync::1220ff::37-0", 0);
    let out = mediator.handle(
        42,
        "PAR::a::1220aa",
        &[
            (vec![vec![informee.clone()]], content, vec![]),
            (
                vec![vec![informee, "PAR::a::1220aa".into()]],
                root_hash_message,
                vec![],
            ),
        ],
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, vec!["PAR::a::1220aa".to_string()]);
    // a participant reads it as the official mediator's verdict: a malformed rejection, signed by the mediator
    let (verdict, signed_hash) = decode_verdict(&out[0].content).expect("a verdict message");
    assert_eq!(verdict.request_id, 42);
    assert!(
        matches!(
            verdict.kind,
            VerdictKind::MediatorReject { malformed: true }
        ),
        "{:?}",
        verdict.kind
    );
    assert!(!verdict.approved);
    let raw =
        canton_algo::member_signature::own_ed25519_key(&keys.mediator_signing.spki_der).unwrap();
    assert!(mediator_signed(&out[0].signatures, &signed_hash, &[raw]));
    // control: another key's signature is not the mediator's
    let other = canton_algo::member_signature::own_ed25519_key(
        &tw::Ed25519Key::from_seed([9; 32]).spki_der,
    )
    .unwrap();
    assert!(!mediator_signed(&out[0].signatures, &signed_hash, &[other]));
}

#[test]
fn a_timed_out_request_is_finalized_until_pruned() {
    let (mediator, _, _) = mediator_with_pending_request();
    assert_eq!(mediator.clean_time(), None);
    assert_eq!(mediator.expire(1_000 + 30_000_001).len(), 1);
    assert_eq!(mediator.finalized_requests(), vec![1_000]);
    assert_eq!(mediator.clean_time(), Some(1_000 + 30_000_001));
    assert_eq!(
        mediator.prune_finalized(999),
        0,
        "pruning before it keeps it"
    );
    assert_eq!(mediator.prune_finalized(1_000), 1);
    assert!(mediator.finalized_requests().is_empty());
}

/// A view of the synchronizer that knows two participants' signing keys and nothing else.
struct KeysOnly(BTreeMap<String, PublicKey>);

impl MediatorView for KeysOnly {
    fn signing_keys(&self, member: &str) -> Option<Vec<PublicKey>> {
        self.0.get(member).map(|key| vec![key.clone()])
    }
    fn member_with_key(&self, _: &str) -> Option<String> {
        None
    }
    fn hosts_at(&self, _: i64) -> BTreeMap<String, Vec<String>> {
        BTreeMap::new()
    }
    fn hosting_at(&self, _: i64) -> BTreeMap<String, Hosting> {
        BTreeMap::new()
    }
    fn timeouts_at(&self, _: i64) -> Timeouts {
        Timeouts::default()
    }
}

/// A mediator with one pending request at 1_000: one view where alice (hosted for confirmation by `a` alone) has to confirm, sent to
/// `a` and to `b` (which hosts no confirming party). Returns the mediator and the two participants' keys.
fn mediator_with_pending_request() -> (Mediator, tw::Ed25519Key, tw::Ed25519Key) {
    let a = tw::Ed25519Key::from_seed([1; 32]);
    let b = tw::Ed25519Key::from_seed([2; 32]);
    let raw =
        |k: &tw::Ed25519Key| canton_algo::member_signature::own_ed25519_key(&k.spki_der).unwrap();
    let keys = KeysOnly(BTreeMap::from([
        ("PAR::a::1220aa".to_string(), raw(&a)),
        ("PAR::b::1220bb".to_string(), raw(&b)),
    ]));
    let mediator = Mediator::with_view(
        0,
        "sync::1220ff::37-0".into(),
        Arc::new(tw::Ed25519Key::from_seed([3; 32])),
        Arc::new(keys),
    );
    let mut p = pending(vec![view(&["alice"], 1)]);
    p.hosting = hosting(&[("alice", 1, &["a::1220aa"])]);
    mediator.state.lock().unwrap().pending.insert(1_000, p);
    (mediator, a, b)
}

/// `member` answers request 1_000 with `outcome` for alice's view.
fn answer(
    mediator: &Mediator,
    member: &str,
    key: &tw::Ed25519Key,
    outcome: canton_participant::confirmation_wire::Outcome,
) -> Vec<Outgoing> {
    answer_at(mediator, 2_000, member, key, outcome)
}

/// Like [`answer`], with the answer sequenced at `time`.
fn answer_at(
    mediator: &Mediator,
    time: i64,
    member: &str,
    key: &tw::Ed25519Key,
    outcome: canton_participant::confirmation_wire::Outcome,
) -> Vec<Outgoing> {
    let position = vec![vec![]];
    let parties = vec!["alice".to_string()];
    let (content, signatures) = canton_participant::confirmation_wire::confirmation_responses(
        1_000,
        &[1, 2, 3],
        "sync::1220ff::37-0",
        member,
        &[canton_participant::confirmation_wire::ViewResponse {
            view_position: &position,
            outcome,
            confirming_parties: &parties,
        }],
        key,
    );
    mediator.handle(
        time,
        member,
        &[(vec![vec![mediator_group(0)]], content, signatures)],
    )
}

#[test]
fn an_answer_sequenced_after_the_response_deadline_finds_the_request_timed_out() {
    use canton_participant::confirmation_wire::Outcome;
    let deadline = 1_000 + RESPONSE_TIMEOUT_MICROS;
    let (mediator, a, _) = mediator_with_pending_request();
    assert_eq!(mediator.next_deadline(), Some(deadline));
    let out = answer_at(
        &mediator,
        deadline + 1,
        "PAR::a::1220aa",
        &a,
        Outcome::Approve,
    );
    assert_eq!(out.len(), 1, "one verdict: the time-out");
    let (verdict, _) = decode_verdict(&out[0].content).unwrap();
    assert!(
        verdict.reason.contains("MEDIATOR_SAYS_TX_TIMED_OUT"),
        "{:?} {}",
        verdict.kind,
        verdict.reason
    );
    assert_eq!(mediator.next_deadline(), None);
    // control: an answer sequenced at the deadline itself is still counted
    let (mediator, a, _) = mediator_with_pending_request();
    let out = answer_at(&mediator, deadline, "PAR::a::1220aa", &a, Outcome::Approve);
    assert_eq!(out.len(), 1);
    let (verdict, _) = decode_verdict(&out[0].content).unwrap();
    assert!(
        matches!(verdict.kind, VerdictKind::Approve),
        "{:?}",
        verdict.kind
    );
}

#[test]
fn a_malformed_answer_rejects_only_for_the_confirming_parties_its_sender_hosts() {
    use canton_participant::confirmation_wire::Outcome;
    // b hosts no confirming party: its malformed answer decides nothing, and a's approval still approves
    let (mediator, a, b) = mediator_with_pending_request();
    let out = answer(
        &mediator,
        "PAR::b::1220bb",
        &b,
        Outcome::Malformed("cannot read".into()),
    );
    assert!(
        out.is_empty(),
        "a participant hosting no confirmer cannot veto"
    );
    let out = answer(&mediator, "PAR::a::1220aa", &a, Outcome::Approve);
    assert_eq!(out.len(), 1);
    let (verdict, _) = decode_verdict(&out[0].content).unwrap();
    assert!(
        matches!(verdict.kind, VerdictKind::Approve),
        "{:?}",
        verdict.kind
    );
    // control: alice's own confirming participant answering malformed makes her quorum unreachable
    let (mediator, a, _) = mediator_with_pending_request();
    let out = answer(
        &mediator,
        "PAR::a::1220aa",
        &a,
        Outcome::Malformed("cannot read".into()),
    );
    assert_eq!(out.len(), 1);
    let (verdict, _) = decode_verdict(&out[0].content).unwrap();
    assert!(
        matches!(verdict.kind, VerdictKind::ParticipantReject),
        "{:?}",
        verdict.kind
    );
}

#[test]
fn a_request_nobody_answers_times_out_after_the_response_time_with_a_signed_verdict() {
    let (mediator, keys) = mediator();
    mediator
        .state
        .lock()
        .unwrap()
        .pending
        .insert(1_000, pending(vec![view(&["alice"], 1)]));
    assert!(
        mediator.expire(1_000 + RESPONSE_TIMEOUT_MICROS).is_empty(),
        "still inside the response time"
    );
    let out = mediator.expire(1_001 + RESPONSE_TIMEOUT_MICROS);
    assert_eq!(out.len(), 1);
    let (verdict, signed_hash) = decode_verdict(&out[0].content).unwrap();
    assert_eq!(verdict.request_id, 1_000);
    assert!(matches!(
        verdict.kind,
        VerdictKind::MediatorReject { malformed: false }
    ));
    assert!(
        verdict.reason.contains("MEDIATOR_SAYS_TX_TIMED_OUT"),
        "{}",
        verdict.reason
    );
    let raw =
        canton_algo::member_signature::own_ed25519_key(&keys.mediator_signing.spki_der).unwrap();
    assert!(mediator_signed(&out[0].signatures, &signed_hash, &[raw]));
    assert!(
        mediator.expire(10 * RESPONSE_TIMEOUT_MICROS).is_empty(),
        "a request is decided once"
    );
}

#[test]
fn an_abstain_answer_preserves_abstain_code_and_blocks_only_when_quorum_is_unreachable() {
    use canton_participant::confirmation_wire::Outcome;
    // alice hosted by both `a` and `b` with consortium threshold 1 -> `b` abstaining lets `a` approve
    let a = tw::Ed25519Key::from_seed([1; 32]);
    let b = tw::Ed25519Key::from_seed([2; 32]);
    let raw =
        |k: &tw::Ed25519Key| canton_algo::member_signature::own_ed25519_key(&k.spki_der).unwrap();
    let keys = KeysOnly(BTreeMap::from([
        ("PAR::a::1220aa".to_string(), raw(&a)),
        ("PAR::b::1220bb".to_string(), raw(&b)),
    ]));
    let mediator = Mediator::with_view(
        0,
        "sync::1220ff::37-0".into(),
        Arc::new(tw::Ed25519Key::from_seed([3; 32])),
        Arc::new(keys),
    );
    let mut p = pending(vec![view(&["alice"], 1)]);
    p.view_type = ViewType::Unassignment;
    p.informee_participants = vec!["PAR::a::1220aa".to_string(), "PAR::b::1220bb".to_string()];
    p.hosting = hosting(&[("alice", 1, &["a::1220aa", "b::1220bb"])]);
    mediator.state.lock().unwrap().pending.insert(1_000, p);
    let out = answer(
        &mediator,
        "PAR::b::1220bb",
        &b,
        Outcome::Abstain("not reassigning".into()),
    );
    assert!(out.is_empty(), "quorum for alice is still reachable via a");
    let out = answer(&mediator, "PAR::a::1220aa", &a, Outcome::Approve);
    assert_eq!(out.len(), 1);
    let (verdict, _) = decode_verdict(&out[0].content).unwrap();
    assert!(
        matches!(verdict.kind, VerdictKind::Approve),
        "{:?}",
        verdict.kind
    );

    // threshold 1 with only `a` hosting -> `a` abstaining makes the quorum unreachable and preserves `LocalAbstain`
    let (mediator2, a2, _) = mediator_with_pending_request();
    let out2 = answer(
        &mediator2,
        "PAR::a::1220aa",
        &a2,
        Outcome::Abstain("not reassigning".into()),
    );
    assert_eq!(out2.len(), 1);
    let (verdict2, _) = decode_verdict(&out2[0].content).unwrap();
    assert!(matches!(verdict2.kind, VerdictKind::ParticipantReject));
    assert!(
        verdict2.reason.contains("not reassigning"),
        "{}",
        verdict2.reason
    );
    // Verify raw protobuf preserves `VerdictCode::LocalAbstain`.
    let (typed_bytes, _) = tw::unversioned(&out2[0].content).unwrap();
    let typed = TypedSignedProtocolMessageContent::decode(typed_bytes.as_slice()).unwrap();
    let Some(SomeSignedProtocolMessage::ConfirmationResult(res_bytes)) =
        typed.some_signed_protocol_message
    else {
        panic!("ConfirmationResult")
    };
    let (msg_bytes, _) = tw::unversioned(&res_bytes).unwrap();
    let msg = ConfirmationResultMessage::decode(msg_bytes.as_slice()).unwrap();
    let Some(SomeVerdict::ParticipantReject(pr)) = msg.verdict.and_then(|v| v.some_verdict) else {
        panic!("ParticipantReject")
    };
    assert_eq!(
        pr.reasons[0].reject.as_ref().map(|r| r.code),
        Some(VerdictCode::LocalAbstain as i32)
    );
}

fn custom_pending_mediator(
    parties_and_weights: &[(&str, u32)],
    quorum_threshold: u32,
    host_map: BTreeMap<String, (u32, Vec<String>)>,
    informee_participants: Vec<&str>,
) -> (Mediator, BTreeMap<String, tw::Ed25519Key>) {
    let mut key_map = BTreeMap::new();
    let mut raw_map = BTreeMap::new();
    for (i, p) in informee_participants.iter().enumerate() {
        let k = tw::Ed25519Key::from_seed([20 + i as u8; 32]);
        let raw = canton_algo::member_signature::own_ed25519_key(&k.spki_der).unwrap();
        raw_map.insert((*p).to_string(), raw);
        key_map.insert((*p).to_string(), k);
    }
    let mediator = Mediator::with_view(
        0,
        "sync::1220ff::37-0".into(),
        Arc::new(tw::Ed25519Key::from_seed([99; 32])),
        Arc::new(KeysOnly(raw_map)),
    );
    let mut p = pending(vec![ViewState {
        position: vec![vec![]],
        quorums: vec![QuorumState::new(
            parties_and_weights
                .iter()
                .map(|(party, w)| ((*party).to_string(), *w)),
            quorum_threshold,
        )],
        consortium_voting: BTreeMap::new(),
        rejections: Vec::new(),
    }]);
    p.informee_participants = informee_participants
        .into_iter()
        .map(ToString::to_string)
        .collect();
    p.hosting = host_map;
    mediator.state.lock().unwrap().pending.insert(1_000, p);
    (mediator, key_map)
}

fn answer_parties_at(
    mediator: &Mediator,
    time: i64,
    member: &str,
    key: &tw::Ed25519Key,
    entries: Vec<(canton_participant::confirmation_wire::Outcome, Vec<String>)>,
) -> Vec<Outgoing> {
    let position = vec![vec![]];
    let responses: Vec<canton_participant::confirmation_wire::ViewResponse<'_>> = entries
        .iter()
        .map(
            |(outcome, parties)| canton_participant::confirmation_wire::ViewResponse {
                view_position: &position,
                outcome: outcome.clone(),
                confirming_parties: parties,
            },
        )
        .collect();
    let (content, signatures) = canton_participant::confirmation_wire::confirmation_responses(
        1_000,
        &[1, 2, 3],
        "sync::1220ff::37-0",
        member,
        &responses,
        key,
    );
    mediator.handle(
        time,
        member,
        &[(vec![vec![mediator_group(0)]], content, signatures)],
    )
}

#[test]
fn r1_approved_party_is_locked_against_later_rejection() {
    use canton_participant::confirmation_wire::Outcome;
    let h = hosting(&[
        ("alice", 1, &["a::1220aa", "b::1220bb"]),
        ("bob", 1, &["c::1220cc"]),
    ]);
    let (m, keys) = custom_pending_mediator(
        &[("alice", 1), ("bob", 1)],
        2,
        h,
        vec!["PAR::a::1220aa", "PAR::b::1220bb", "PAR::c::1220cc"],
    );
    let out1 = answer_parties_at(
        &m,
        2_000,
        "PAR::a::1220aa",
        &keys["PAR::a::1220aa"],
        vec![(Outcome::Approve, vec!["alice".into()])],
    );
    assert!(out1.is_empty(), "bob has not answered yet");
    let out2 = answer_parties_at(
        &m,
        2_001,
        "PAR::b::1220bb",
        &keys["PAR::b::1220bb"],
        vec![(Outcome::Reject("late-reject".into()), vec!["alice".into()])],
    );
    assert!(
        out2.is_empty(),
        "alice was already fully approved and locked out of confirmers; later rejection from b must be ignored"
    );
    let out3 = answer_parties_at(
        &m,
        2_002,
        "PAR::c::1220cc",
        &keys["PAR::c::1220cc"],
        vec![(Outcome::Approve, vec!["bob".into()])],
    );
    assert_eq!(out3.len(), 1);
    let (verdict, _) = decode_verdict(&out3[0].content).unwrap();
    assert!(
        matches!(verdict.kind, VerdictKind::Approve),
        "expected Approve after locked alice + bob approval, got {:?}",
        verdict.kind
    );
}

#[test]
fn r1_rejected_party_is_locked_against_later_approval() {
    use canton_participant::confirmation_wire::Outcome;
    // (1) alice + bob, quorum threshold 2: a rejects alice (threshold 1) -> immediate Reject.
    let h1 = hosting(&[
        ("alice", 1, &["a::1220aa", "b::1220bb"]),
        ("bob", 1, &["c::1220cc"]),
    ]);
    let (m1, keys1) = custom_pending_mediator(
        &[("alice", 1), ("bob", 1)],
        2,
        h1,
        vec!["PAR::a::1220aa", "PAR::b::1220bb", "PAR::c::1220cc"],
    );
    let out = answer_parties_at(
        &m1,
        2_000,
        "PAR::a::1220aa",
        &keys1["PAR::a::1220aa"],
        vec![(Outcome::Reject("veto".into()), vec!["alice".into()])],
    );
    assert_eq!(out.len(), 1);
    let (v1, _) = decode_verdict(&out[0].content).unwrap();
    assert!(matches!(v1.kind, VerdictKind::ParticipantReject));
    // B approving afterwards cannot resurrect finalized request.
    assert!(answer_parties_at(
        &m1,
        2_001,
        "PAR::b::1220bb",
        &keys1["PAR::b::1220bb"],
        vec![(Outcome::Approve, vec!["alice".into()])],
    )
    .is_empty());

    // (2) alice + bob + carol, quorum threshold 2:
    // a rejects alice -> alice locked out (confirmers {bob, carol}, sum 2 >= 2, still pending).
    // b approves alice -> ignored because alice was already fully rejected and removed.
    // c approves bob -> threshold still unmet (bob=1 < 2).
    // d rejects carol -> quorum unreachable -> Reject.
    let h2 = hosting(&[
        ("alice", 1, &["a::1220aa", "b::1220bb"]),
        ("bob", 1, &["c::1220cc"]),
        ("carol", 1, &["d::1220dd"]),
    ]);
    let (m2, keys2) = custom_pending_mediator(
        &[("alice", 1), ("bob", 1), ("carol", 1)],
        2,
        h2,
        vec![
            "PAR::a::1220aa",
            "PAR::b::1220bb",
            "PAR::c::1220cc",
            "PAR::d::1220dd",
        ],
    );
    assert!(answer_parties_at(
        &m2,
        2_000,
        "PAR::a::1220aa",
        &keys2["PAR::a::1220aa"],
        vec![(Outcome::Reject("veto".into()), vec!["alice".into()])],
    )
    .is_empty());
    assert!(answer_parties_at(
        &m2,
        2_001,
        "PAR::b::1220bb",
        &keys2["PAR::b::1220bb"],
        vec![(Outcome::Approve, vec!["alice".into()])],
    )
    .is_empty());
    let after_bob = answer_parties_at(
        &m2,
        2_002,
        "PAR::c::1220cc",
        &keys2["PAR::c::1220cc"],
        vec![(Outcome::Approve, vec!["bob".into()])],
    );
    assert!(
        after_bob.is_empty(),
        "rejected alice's later approval from b must be ignored; bob alone cannot meet threshold 2"
    );
    let after_carol = answer_parties_at(
        &m2,
        2_003,
        "PAR::d::1220dd",
        &keys2["PAR::d::1220dd"],
        vec![(Outcome::Reject("veto-carol".into()), vec!["carol".into()])],
    );
    assert_eq!(after_carol.len(), 1);
    let (v2, _) = decode_verdict(&after_carol[0].content).unwrap();
    assert!(matches!(v2.kind, VerdictKind::ParticipantReject));
}

#[test]
fn r1_same_participant_second_conflicting_response_is_ignored() {
    use canton_participant::confirmation_wire::Outcome;
    // Same participant sending conflicting entries in one batch (Approve then Reject for consortium th=2) keeps first Approve.
    let h = hosting(&[("alice", 2, &["a::1220aa", "b::1220bb"])]);
    let (m, keys) = custom_pending_mediator(
        &[("alice", 1)],
        1,
        h,
        vec!["PAR::a::1220aa", "PAR::b::1220bb"],
    );
    let out1 = answer_parties_at(
        &m,
        2_000,
        "PAR::a::1220aa",
        &keys["PAR::a::1220aa"],
        vec![
            (Outcome::Approve, vec!["alice".into()]),
            (Outcome::Reject("equivocation".into()), vec!["alice".into()]),
        ],
    );
    assert!(
        out1.is_empty(),
        "second response from a in same batch must be ignored (hasAlreadyResponded)"
    );
    let out2 = answer_parties_at(
        &m,
        2_001,
        "PAR::b::1220bb",
        &keys["PAR::b::1220bb"],
        vec![(Outcome::Approve, vec!["alice".into()])],
    );
    assert_eq!(out2.len(), 1);
    let (v1, _) = decode_verdict(&out2[0].content).unwrap();
    assert!(matches!(v1.kind, VerdictKind::Approve));
}

#[test]
fn r1_same_participant_separate_message_conflicting_response_is_ignored() {
    use canton_participant::confirmation_wire::Outcome;
    // Scenario A: same participant sends Approve first, then a separate message containing a conflicting Reject(alice) + Approve(bob).
    // The second conflicting vote for alice must be ignored while bob's first vote is accepted.
    let h_both = hosting(&[
        ("alice", 2, &["a::1220aa", "b::1220bb"]),
        ("bob", 1, &["a::1220aa"]),
    ]);
    let (m_a, keys_a) = custom_pending_mediator(
        &[("alice", 1), ("bob", 1)],
        2,
        h_both,
        vec!["PAR::a::1220aa", "PAR::b::1220bb"],
    );
    assert!(answer_parties_at(
        &m_a,
        2_000,
        "PAR::a::1220aa",
        &keys_a["PAR::a::1220aa"],
        vec![(Outcome::Approve, vec!["alice".into()])],
    )
    .is_empty());
    assert!(answer_parties_at(
        &m_a,
        2_001,
        "PAR::a::1220aa",
        &keys_a["PAR::a::1220aa"],
        vec![
            (Outcome::Reject("late-flip".into()), vec!["alice".into()]),
            (Outcome::Approve, vec!["bob".into()]),
        ],
    )
    .is_empty());
    let out_a = answer_parties_at(
        &m_a,
        2_002,
        "PAR::b::1220bb",
        &keys_a["PAR::b::1220bb"],
        vec![(Outcome::Approve, vec!["alice".into()])],
    );
    assert_eq!(out_a.len(), 1);
    let (v_a, _) = decode_verdict(&out_a[0].content).unwrap();
    assert!(matches!(v_a.kind, VerdictKind::Approve));

    // Scenario B (R-1(c) discriminator): 3-host th=2 where `a` flips Reject -> Approve in a separate message.
    // Ignoring `a`'s second Approve means `b`'s single Approve still cannot satisfy th=2 until `c` also approves;
    // without `has_already_responded` filtering in `aggregation.rs`, {a, b} reaches th=2 and falsely emits Approve early.
    let h_three = hosting(&[("alice", 2, &["a::1220aa", "b::1220bb", "c::1220cc"])]);
    let (m_b, keys_b) = custom_pending_mediator(
        &[("alice", 1)],
        1,
        h_three,
        vec!["PAR::a::1220aa", "PAR::b::1220bb", "PAR::c::1220cc"],
    );
    assert!(answer_parties_at(
        &m_b,
        2_000,
        "PAR::a::1220aa",
        &keys_b["PAR::a::1220aa"],
        vec![(Outcome::Reject("first-reject".into()), vec!["alice".into()])],
    )
    .is_empty());
    assert!(answer_parties_at(
        &m_b,
        2_001,
        "PAR::a::1220aa",
        &keys_b["PAR::a::1220aa"],
        vec![(Outcome::Approve, vec!["alice".into()])],
    )
    .is_empty());
    let out_b = answer_parties_at(
        &m_b,
        2_002,
        "PAR::b::1220bb",
        &keys_b["PAR::b::1220bb"],
        vec![(Outcome::Approve, vec!["alice".into()])],
    );
    assert!(
        out_b.is_empty(),
        "a's second Approve in a separate message must be ignored so b alone cannot satisfy th=2"
    );
    let out_c = answer_parties_at(
        &m_b,
        2_003,
        "PAR::c::1220cc",
        &keys_b["PAR::c::1220cc"],
        vec![(Outcome::Approve, vec!["alice".into()])],
    );
    assert_eq!(out_c.len(), 1);
    let (v_b, _) = decode_verdict(&out_c[0].content).unwrap();
    assert!(matches!(v_b.kind, VerdictKind::Approve));
}

#[test]
fn r1_participant_reject_reasons_filter_authorized_parties_not_newly_responded() {
    use canton_participant::confirmation_wire::Outcome;
    // Quorum {alice, bob, carol} th=2; alice hosted on {a, b} (th=1), bob on {b}, carol on {c}.
    // 1. a rejects alice -> alice is fully rejected and removed from quorums (view still pending).
    // 2. b rejects {alice, bob} in one response -> newly_responded={bob}, authorized_parties={alice, bob}.
    // Per ResponseAggregation.scala:258-261, RejectionReason.parties must filter authorized_parties -> [alice, bob].
    let h = hosting(&[
        ("alice", 1, &["a::1220aa", "b::1220bb"]),
        ("bob", 1, &["b::1220bb"]),
        ("carol", 1, &["c::1220cc"]),
    ]);
    let (m, keys) = custom_pending_mediator(
        &[("alice", 1), ("bob", 1), ("carol", 1)],
        2,
        h,
        vec!["PAR::a::1220aa", "PAR::b::1220bb", "PAR::c::1220cc"],
    );
    assert!(answer_parties_at(
        &m,
        2_000,
        "PAR::a::1220aa",
        &keys["PAR::a::1220aa"],
        vec![(Outcome::Reject("reason-a".into()), vec!["alice".into()])],
    )
    .is_empty());
    let out = answer_parties_at(
        &m,
        2_001,
        "PAR::b::1220bb",
        &keys["PAR::b::1220bb"],
        vec![(
            Outcome::Reject("reason-b".into()),
            vec!["alice".into(), "bob".into()],
        )],
    );
    assert_eq!(out.len(), 1);
    let (typed_bytes, _) = tw::unversioned(&out[0].content).unwrap();
    let typed = TypedSignedProtocolMessageContent::decode(typed_bytes.as_slice()).unwrap();
    let Some(SomeSignedProtocolMessage::ConfirmationResult(res_bytes)) =
        typed.some_signed_protocol_message
    else {
        panic!("ConfirmationResult")
    };
    let (msg_bytes, _) = tw::unversioned(&res_bytes).unwrap();
    let msg = ConfirmationResultMessage::decode(msg_bytes.as_slice()).unwrap();
    let Some(SomeVerdict::ParticipantReject(pr)) = msg.verdict.and_then(|v| v.some_verdict) else {
        panic!("ParticipantReject")
    };
    assert_eq!(pr.reasons.len(), 2, "reasons={:?}", pr.reasons);
    assert_eq!(
        pr.reasons[0].parties,
        vec!["alice".to_string(), "bob".to_string()],
        "b's rejection reason must filter authorizedParties (ResponseAggregation.scala:258-261)"
    );
}

#[test]
fn r1_abstain_tipping_rejection_preserves_prior_local_reject_reason() {
    use canton_participant::confirmation_wire::Outcome;
    let h = hosting(&[("alice", 2, &["a::1220aa", "b::1220bb", "c::1220cc"])]);
    let (m, keys) = custom_pending_mediator(
        &[("alice", 1)],
        1,
        h,
        vec!["PAR::a::1220aa", "PAR::b::1220bb", "PAR::c::1220cc"],
    );
    assert!(answer_parties_at(
        &m,
        2_000,
        "PAR::a::1220aa",
        &keys["PAR::a::1220aa"],
        vec![(Outcome::Reject("prior-reason".into()), vec!["alice".into()])],
    )
    .is_empty());
    let out = answer_parties_at(
        &m,
        2_001,
        "PAR::b::1220bb",
        &keys["PAR::b::1220bb"],
        vec![(
            Outcome::Abstain("abstain-reason".into()),
            vec!["alice".into()],
        )],
    );
    assert_eq!(out.len(), 1);
    let (typed_bytes, _) = tw::unversioned(&out[0].content).unwrap();
    let typed = TypedSignedProtocolMessageContent::decode(typed_bytes.as_slice()).unwrap();
    let Some(SomeSignedProtocolMessage::ConfirmationResult(res_bytes)) =
        typed.some_signed_protocol_message
    else {
        panic!("ConfirmationResult")
    };
    let (msg_bytes, _) = tw::unversioned(&res_bytes).unwrap();
    let msg = ConfirmationResultMessage::decode(msg_bytes.as_slice()).unwrap();
    let Some(SomeVerdict::ParticipantReject(pr)) = msg.verdict.and_then(|v| v.some_verdict) else {
        panic!("ParticipantReject")
    };
    assert_eq!(
        pr.reasons.len(),
        1,
        "only the prior LocalReject reason should remain for alice (ResponseAggregation.scala:268-297)"
    );
    let rej = pr.reasons[0].reject.as_ref().unwrap();
    assert_eq!(rej.code, VerdictCode::LocalReject as i32);
    assert_eq!(
        rej.reason.as_ref().map(|s| s.message.as_str()),
        Some("prior-reason")
    );
}
