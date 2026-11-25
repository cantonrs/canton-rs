//! `rust-reassign-participant <syncA url> <syncB url> <command dir> <sample dar> <state dir>`: a Rust participant on **two** synchronizers
//! that confirms a reassignment the official JVM participant `p1` submits (G7 B1, S-NET-040 part 3; `scripts/verify-rust-reassignment.sh`
//! with `RA_RUST_PARTICIPANT=1`).
//!
//! One participant identity joins both synchronizers (as a Canton participant does: one uid, one key set, a connection per synchronizer),
//! and an event loop (`participant_runtime::Runtime`) runs on each. Talking to the JVM's console script through files in the command
//! directory:
//! 1. reads `p1.info` (p1's uid and the sample package id), proposes on **both** synchronizers the party `erin` hosted by itself
//!    (confirmation) and p1 (submission), vets the sample package on both, and writes the proposal's hash to `erin.req` for p1 to co-sign;
//! 2. once both loops host erin, writes `erin.ready`; p1 creates a contract erin signs on syncA and writes its id to `created`;
//! 3. follows the creation, raises erin's hosting threshold to 2 on both synchronizers (its own answer becomes **necessary** for the
//!    mediators) and writes `raised`; p1 then unassigns the contract to syncB and assigns it there;
//! 4. follows the unassignment on syncA (the contract leaves, unarchived, counter 1) and the assignment on syncB (the contract arrives,
//!    counter 1), answering both, and prints what it did as `RP <key>=<value>` lines.
use canton_participant::participant_runtime as rt;
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect, Token};
use canton_participant::topology_wire::{self as tw, ParticipantIdentity};
use canton_participant::{confirmation_wire::Outcome, sequencing_wire as sw};
use std::path::Path;
use std::time::{Duration, Instant};

fn wait_for(dir: &Path, name: &str, seconds: u64) -> Result<String, String> {
    let limit = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < limit {
        if let Ok(text) = std::fs::read_to_string(dir.join(name)) {
            if !text.trim().is_empty() {
                return Ok(text);
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    Err(format!("{name} did not appear within {seconds} s"))
}

fn put(dir: &Path, name: &str, content: &str) -> Result<(), String> {
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, content).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dir.join(name)).map_err(|e| e.to_string())
}

/// One synchronizer this participant is connected to, with its event loop.
struct Connected {
    connection: SequencerConnect,
    token: Token,
    physical: String,
    runtime: Option<rt::Runtime>,
    steps: Vec<rt::Step>,
}

impl Connected {
    fn now(&mut self, identity: &ParticipantIdentity) -> Result<i64, String> {
        self.connection
            .sequencer_time(&identity.member(), &self.physical, Some(&self.token))
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "the sequencer has no time yet".to_string())
    }

    fn broadcast(
        &mut self,
        identity: &ParticipantIdentity,
        id: &str,
        transactions: &[canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction],
    ) -> Result<(), String> {
        let now = self.now(identity)?;
        let envelopes = vec![(
            vec![tw::ALL_MEMBERS.to_string()],
            tw::topology_broadcast(&self.physical, transactions),
        )];
        self.connection
            .send_async(
                &identity.member(),
                &self.physical,
                &self.token,
                sw::signed_submission_request(
                    sw::submission_request_to_groups(
                        &identity.member(),
                        id,
                        &envelopes,
                        now + 60_000_000,
                    ),
                    &identity.signing_key,
                ),
            )
            .map_err(|e| e.to_string())
    }

    fn poll(&mut self, identity: &ParticipantIdentity, wait: Duration) -> Result<(), String> {
        let runtime = self.runtime.as_mut().ok_or("no event loop yet")?;
        let steps = runtime.poll(
            &mut self.connection,
            &self.token,
            &identity.signing_key,
            wait,
        )?;
        self.steps.extend(steps);
        Ok(())
    }

    fn runtime(&self) -> &rt::Runtime {
        self.runtime.as_ref().expect("the event loop is open")
    }
}

/// Joins the synchronizer at `url` as `identity` (the same identity on every synchronizer).
fn join(identity: &ParticipantIdentity, url: &str) -> Result<Connected, String> {
    let mut connection = SequencerConnect::connect(url).map_err(|e| e.to_string())?;
    let physical = connection
        .synchronizer_id()
        .map_err(|e| e.to_string())?
        .physical_synchronizer_id;
    let synchronizer_uid = physical
        .rsplit_once("::")
        .map(|x| x.0)
        .ok_or("a physical synchronizer id of an unexpected form")?
        .to_string();
    connection
        .register_onboarding(
            &identity.member(),
            &physical,
            identity.onboarding_transactions(&synchronizer_uid),
        )
        .map_err(|e| e.to_string())?;
    let challenge = connection
        .challenge(&identity.member(), &[37])
        .map_err(|e| e.to_string())?;
    let signature = identity.sequencer_auth_key.sign_bytes(
        &AuthKey::challenge_hash(&challenge.nonce, &physical)
            .map_err(|e| format!("the challenge hash: {e:?}"))?,
    );
    let token = connection
        .authenticate(&identity.member(), &challenge.nonce, signature)
        .map_err(|e| e.to_string())?;
    Ok(Connected {
        connection,
        token,
        physical,
        runtime: None,
        steps: Vec::new(),
    })
}

/// Polls both synchronizers in turn until `done` holds or `seconds` are up.
fn run_until(
    identity: &ParticipantIdentity,
    syncs: &mut [Connected; 2],
    seconds: u64,
    mut done: impl FnMut(&[Connected; 2]) -> bool,
) -> Result<bool, String> {
    let limit = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < limit {
        if done(syncs) {
            return Ok(true);
        }
        for s in syncs.iter_mut() {
            // short waits: the events of the two synchronizers are taken close to the order they happened in, so the verdict of an
            // unassignment on one is in before its assignment arrives on the other (a participant reads its connections concurrently)
            s.poll(identity, Duration::from_millis(40))?;
        }
    }
    Ok(done(syncs))
}

fn notes(syncs: &[Connected; 2]) -> Vec<String> {
    syncs
        .iter()
        .enumerate()
        .flat_map(|(i, s)| {
            s.steps
                .iter()
                .flat_map(|st| st.notes.iter())
                .map(move |n| format!("{}: {n}", ["A", "B"][i]))
        })
        .collect()
}

fn run(urls: [&str; 2], dir: &Path, dar: &Path, state_dir: &Path) -> Result<(), String> {
    let info = wait_for(dir, "p1.info", 240)?;
    let mut lines = info.lines();
    let p1_uid = lines
        .next()
        .ok_or("p1.info has no uid")?
        .trim_start_matches("PAR::")
        .to_string();
    let package = lines.next().ok_or("p1.info has no package id")?.to_string();
    let identity = ParticipantIdentity::generate("rustpar");
    let mut syncs = [join(&identity, urls[0])?, join(&identity, urls[1])?];
    let unassignments = rt::SharedUnassignments::default();
    println!("RP member={}", identity.member());
    std::thread::sleep(Duration::from_millis(800));
    let erin = identity.party_id("erin");
    let proposal = identity.shared_party_proposal_with("erin", &p1_uid, 1, 1, 1);
    let proposal_hash = tw::transaction_hash(&proposal.transaction);
    for (i, s) in syncs.iter_mut().enumerate() {
        let start = s.now(&identity)?;
        let config = rt::Config {
            member: identity.member(),
            encryption_fingerprint: identity.encryption_fingerprint(),
            encryption_secret: *identity.encryption_secret(),
            hosted_parties: vec![],
            timeouts: Default::default(),
            submitter_keys: vec![],
            mediator_keys: vec![],
            peer_encryption_keys: Default::default(),
            physical_synchronizer_id: s.physical.clone(),
            topology_change_delay_micros: 250_000,
            follow_topology: true,
        };
        let engine = canton_participant::view_conformance::Engine::load(dar)?;
        let state = state_dir.join(["a", "b"][i]);
        std::fs::create_dir_all(&state).map_err(|e| e.to_string())?;
        let mut runtime = rt::Runtime::open(config, engine, Some(&state), start)?;
        // its own requests come back as events: trust its signature and host its admin party (see `node.rs`)
        runtime.trust_own_submissions(
            canton_algo::member_signature::own_ed25519_key(&identity.signing_key.spki_der)
                .map_err(|e| format!("not an Ed25519 key: {e:?}"))?,
            &identity.uid(),
        );
        // one reassignment store for the participant: the unassignment the runtime on the source synchronizer sees approved is what
        // the runtime on the target synchronizer judges the assignment by, whoever submitted it (U-60)
        runtime.share_unassignments(unassignments.clone());
        s.runtime = Some(runtime);
        let vetting = identity.vetting_transaction(std::slice::from_ref(&package));
        s.broadcast(&identity, "erin-proposal", &[proposal.clone(), vetting])?;
    }
    put(dir, "erin.req", &hex(&proposal_hash))?;
    let hosted = run_until(&identity, &mut syncs, 120, |s| {
        s.iter()
            .all(|c| c.runtime().config.hosted_parties.contains(&erin))
    })?;
    println!("RP hosts_erin_on_both={hosted}");
    if !hosted {
        return Err(format!(
            "erin is not hosted on both synchronizers: {:?}",
            notes(&syncs)
        ));
    }
    put(dir, "erin.ready", &erin)?;
    let contract_id = wait_for(dir, "created", 180)?.trim().to_string();
    let active = run_until(&identity, &mut syncs, 90, |s| {
        s[0].runtime().ledger.is_active(&contract_id)
    })?;
    println!("RP contract_active_on_a={active}");
    if !active {
        return Err(format!(
            "the creation of {contract_id} was not followed: {:?}",
            notes(&syncs)
        ));
    }
    // erin needs both hosts from now on, on both synchronizers: the mediators approve only on this participant's answer
    let bytes =
        tw::party_to_participant_at_serial(&erin, &[(&p1_uid, 1), (&identity.uid(), 1)], 2, 2);
    let raise = tw::signed(
        bytes.clone(),
        vec![identity.namespace_key.sign_transaction(&bytes)],
    );
    for s in syncs.iter_mut() {
        s.broadcast(&identity, "erin-threshold", std::slice::from_ref(&raise))?;
    }
    run_until(&identity, &mut syncs, 4, |_| false)?;
    put(dir, "raised", "2")?;
    let moved = run_until(&identity, &mut syncs, 180, |s| {
        s[0].runtime().ledger.unassigned_by(&contract_id).is_some()
            && s[1].runtime().ledger.is_active(&contract_id)
    })?;
    let (a, b) = (syncs[0].runtime(), syncs[1].runtime());
    println!(
        "RP on_a: active={} archived={:?} unassigned_by={:?} counter={}",
        a.ledger.is_active(&contract_id),
        a.ledger.archived_by(&contract_id),
        a.ledger.unassigned_by(&contract_id),
        a.ledger.counter_of(&contract_id)
    );
    println!(
        "RP on_b: active={} counter={}",
        b.ledger.is_active(&contract_id),
        b.ledger.counter_of(&contract_id)
    );
    let answers: Vec<(usize, &rt::ToSend)> = syncs
        .iter()
        .enumerate()
        .flat_map(|(i, s)| {
            s.steps
                .iter()
                .flat_map(|st| &st.to_send)
                .map(move |t| (i, t))
        })
        .collect();
    for (i, t) in &answers {
        println!(
            "RP answer sync={} request={} outcome={} parties={:?}",
            ["A", "B"][*i],
            t.request_time,
            match &t.decision().outcome {
                Outcome::Approve => "approve".to_string(),
                other => format!("{other:?}"),
            },
            t.decision().confirming_parties
        );
    }
    let verdicts: Vec<(usize, i64, bool)> = syncs
        .iter()
        .enumerate()
        .flat_map(|(i, s)| {
            s.steps
                .iter()
                .flat_map(|st| st.verdicts.clone())
                .map(move |(t, ok)| (i, t, ok))
        })
        .collect();
    println!("RP verdicts={verdicts:?}");
    for n in notes(&syncs).iter().filter(|n| n.contains("reassignment")) {
        println!("RP note {n}");
    }
    let unassign_at = a.ledger.unassigned_by(&contract_id);
    let approved_on = |sync: usize, at: Option<i64>| {
        at.is_some_and(|t| {
            verdicts
                .iter()
                .any(|(i, v, ok)| *i == sync && *v == t && *ok)
        })
    };
    let answered_on = |sync: usize| {
        answers.iter().any(|(i, t)| {
            *i == sync
                && t.decision().outcome == Outcome::Approve
                && t.decision().confirming_parties == vec![erin.clone()]
                && verdicts
                    .iter()
                    .any(|(j, v, ok)| *j == sync && *v == t.request_time && *ok)
        })
    };
    if !moved
        || a.ledger.archived_by(&contract_id).is_some()
        || a.ledger.counter_of(&contract_id) != 1
        || b.ledger.counter_of(&contract_id) != 1
        || !approved_on(0, unassign_at)
        || !answered_on(0)
        || !answered_on(1)
        || a.ledger.in_flight() != 0
        || b.ledger.in_flight() != 0
    {
        return Err(format!(
            "the reassignment was not followed and approved on this participant's answers: {:?}",
            notes(&syncs)
        ));
    }
    println!("RP round1=ok");
    submit_back(&identity, &mut syncs, &erin, &p1_uid, &contract_id, dir)?;
    rust_round_trip(&identity, &mut syncs, &erin, &p1_uid, &contract_id, dir)?;
    println!("RP result=ok");
    Ok(())
}

/// Round 2: this participant builds and submits the unassignment syncB -> syncA as erin; p1 (the only host of alice, a signatory) has to
/// confirm it. Then p1 assigns it on syncA with the reassignment id this participant derived, and this participant follows that too.
fn submit_back(
    identity: &ParticipantIdentity,
    syncs: &mut [Connected; 2],
    erin: &str,
    p1_uid: &str,
    contract_id: &str,
    dir: &Path,
) -> Result<(), String> {
    use canton_participant::reassignment_submit as rs;
    use canton_participant::reassignment_wire::reassignment_id;
    use canton_participant::submit::{Os, Peer};
    // erin back to threshold 1: a party with a threshold above 1 cannot submit
    let bytes =
        tw::party_to_participant_at_serial(erin, &[(p1_uid, 1), (&identity.uid(), 1)], 1, 3);
    let lower = tw::signed(
        bytes.clone(),
        vec![identity.namespace_key.sign_transaction(&bytes)],
    );
    for s in syncs.iter_mut() {
        s.broadcast(identity, "erin-lower", std::slice::from_ref(&lower))?;
    }
    run_until(identity, syncs, 4, |_| false)?;
    // the instance as it arrived on syncB with the assignment
    let instance = syncs[1]
        .steps
        .iter()
        .flat_map(|st| &st.applied)
        .flat_map(|a| &a.created)
        .find(|(id, _)| id == contract_id)
        .map(|(_, i)| i.clone())
        .ok_or("the assignment on syncB did not bring the contract's instance")?;
    let p1_member = format!("PAR::{p1_uid}");
    let p1_key = syncs[1]
        .runtime()
        .config
        .peer_encryption_keys
        .get(&p1_member)
        .and_then(|k| k.first().cloned())
        .ok_or("p1's encryption key is not known on syncB")?;
    let recipients = vec![
        Peer {
            member: p1_member,
            encryption_spki: p1_key.spki,
            fingerprint: p1_key.fingerprint,
        },
        Peer {
            member: identity.member(),
            encryption_spki: identity.encryption_spki().to_vec(),
            fingerprint: identity.encryption_fingerprint(),
        },
    ];
    let mut reassigning = vec![p1_uid.to_string(), identity.uid()];
    reassigning.sort();
    let target_time = syncs[0].now(identity)?;
    let now = syncs[1].now(identity)?;
    let counter = syncs[1].runtime().ledger.counter_of(contract_id);
    let (source, target) = (syncs[1].physical.clone(), syncs[0].physical.clone());
    let built = rs::unassignment(
        identity,
        &rs::Unassignment {
            source: &source,
            target: &target,
            target_time_micros: target_time,
            instance: &instance,
            current_counter: counter,
            submitter: erin,
            command_id: "rust-unassign-1",
            user_id: "rust-participant",
            reassigning_participant_uids: &reassigning,
            recipients: &recipients,
            now_micros: now,
        },
        &mut Os,
    )?;
    println!("RP rust_unassign_root_hash={}", hex(&built.root_hash));
    let b = &mut syncs[1];
    b.connection
        .send_async(
            &identity.member(),
            &b.physical,
            &b.token,
            sw::signed_submission_request(
                built.submission_request(&identity.member(), now + 60_000_000),
                &identity.signing_key,
            ),
        )
        .map_err(|e| e.to_string())?;
    let left = run_until(identity, syncs, 90, |s| {
        s[1].runtime().ledger.unassigned_by(contract_id).is_some()
    })?;
    let request = syncs[1].runtime().ledger.unassigned_by(contract_id);
    let verdict = syncs[1]
        .steps
        .iter()
        .flat_map(|st| st.verdicts.iter().chain(st.unresolved_verdicts.iter()))
        .find(|(t, _)| Some(*t) == request)
        .copied();
    println!("RP rust_unassign: left_b={left} request={request:?} verdict={verdict:?}");
    let Some(request) = request.filter(|_| left) else {
        return Err(format!(
            "the Rust-built unassignment was not approved: {:?}",
            notes(syncs)
        ));
    };
    // the reassignment id over the logical ids (the physical ones without the `::37-0` suffix)
    let logical = |p: &str| {
        p.rsplit_once("::")
            .map(|x| x.0.to_string())
            .unwrap_or_default()
    };
    let rid = reassignment_id(
        &logical(&source),
        &logical(&target),
        request,
        &[(contract_id, counter + 1)],
    );
    println!("RP rust_reassignment_id={rid}");
    put(dir, "rust_unassigned", &format!("{rid}\n{request}\n"))?;
    // p1 assigns it on syncA: this participant answers that too
    let back = run_until(identity, syncs, 120, |s| {
        s[0].runtime().ledger.is_active(contract_id)
    })?;
    println!(
        "RP back_on_a={back} counter_a={} counter_b={}",
        syncs[0].runtime().ledger.counter_of(contract_id),
        syncs[1].runtime().ledger.counter_of(contract_id)
    );
    if !back || syncs[0].runtime().ledger.counter_of(contract_id) != counter + 1 {
        return Err(format!(
            "the assignment of the Rust-built unassignment was not followed: {:?}",
            notes(syncs)
        ));
    }
    Ok(())
}

/// The view's recipients on synchronizer `i`: p1 (its key as the topology there says) and this participant.
fn peers(
    identity: &ParticipantIdentity,
    sync: &Connected,
    p1_uid: &str,
) -> Result<Vec<canton_participant::submit::Peer>, String> {
    let p1_member = format!("PAR::{p1_uid}");
    let p1_key = sync
        .runtime()
        .config
        .peer_encryption_keys
        .get(&p1_member)
        .and_then(|k| k.first().cloned())
        .ok_or("p1's encryption key is not known")?;
    Ok(vec![
        canton_participant::submit::Peer {
            member: p1_member,
            encryption_spki: p1_key.spki,
            fingerprint: p1_key.fingerprint,
        },
        canton_participant::submit::Peer {
            member: identity.member(),
            encryption_spki: identity.encryption_spki().to_vec(),
            fingerprint: identity.encryption_fingerprint(),
        },
    ])
}

fn send(
    identity: &ParticipantIdentity,
    sync: &mut Connected,
    built: &canton_participant::reassignment_submit::Built,
    now: i64,
) -> Result<(), String> {
    sync.connection
        .send_async(
            &identity.member(),
            &sync.physical,
            &sync.token,
            sw::signed_submission_request(
                built.submission_request(&identity.member(), now + 60_000_000),
                &identity.signing_key,
            ),
        )
        .map_err(|e| e.to_string())
}

/// The serialized instance of `contract_id` as it last arrived on synchronizer `sync` (created or assigned there).
fn last_instance(sync: &Connected, contract_id: &str) -> Option<Vec<u8>> {
    sync.steps
        .iter()
        .flat_map(|st| &st.applied)
        .flat_map(|a| &a.created)
        .rfind(|(id, _)| id == contract_id)
        .map(|(_, i)| i.clone())
}

/// Round 3: this participant does a whole reassignment itself, syncA -> syncB: the unassignment and then the **assignment** it builds from
/// it. p1, alice's only host, has to confirm both.
fn rust_round_trip(
    identity: &ParticipantIdentity,
    syncs: &mut [Connected; 2],
    erin: &str,
    p1_uid: &str,
    contract_id: &str,
    dir: &Path,
) -> Result<(), String> {
    use canton_participant::reassignment_submit as rs;
    use canton_participant::reassignment_wire::reassignment_id;
    use canton_participant::submit::Os;
    let instance = last_instance(&syncs[0], contract_id)
        .ok_or("the assignment on syncA did not bring the contract's instance")?;
    let mut reassigning = vec![p1_uid.to_string(), identity.uid()];
    reassigning.sort();
    let (source, target) = (syncs[0].physical.clone(), syncs[1].physical.clone());
    let counter = syncs[0].runtime().ledger.counter_of(contract_id);
    let recipients_a = peers(identity, &syncs[0], p1_uid)?;
    let target_time = syncs[1].now(identity)?;
    let now = syncs[0].now(identity)?;
    let unassign = rs::unassignment(
        identity,
        &rs::Unassignment {
            source: &source,
            target: &target,
            target_time_micros: target_time,
            instance: &instance,
            current_counter: counter,
            submitter: erin,
            command_id: "rust-unassign-2",
            user_id: "rust-participant",
            reassigning_participant_uids: &reassigning,
            recipients: &recipients_a,
            now_micros: now,
        },
        &mut Os,
    )?;
    send(identity, &mut syncs[0], &unassign, now)?;
    let left = run_until(identity, syncs, 90, |s| {
        s[0].runtime().ledger.unassigned_by(contract_id).is_some()
    })?;
    let Some(request) = syncs[0]
        .runtime()
        .ledger
        .unassigned_by(contract_id)
        .filter(|_| left)
    else {
        return Err(format!(
            "round 3: the unassignment was not approved: {:?}",
            notes(syncs)
        ));
    };
    let logical = |p: &str| {
        p.rsplit_once("::")
            .map(|x| x.0.to_string())
            .unwrap_or_default()
    };
    let rid = reassignment_id(
        &logical(&source),
        &logical(&target),
        request,
        &[(contract_id, counter + 1)],
    );
    println!("RP round3_unassign request={request} reassignment_id={rid}");
    let recipients_b = peers(identity, &syncs[1], p1_uid)?;
    let now_b = syncs[1].now(identity)?;
    let assign = rs::assignment(
        identity,
        &rs::Assignment {
            source: &source,
            target: &target,
            unassignment_time_micros: request,
            reassignment_id: &rid,
            instance: &instance,
            counter: counter + 1,
            submitter: erin,
            command_id: "rust-assign-1",
            user_id: "rust-participant",
            reassigning_participant_uids: &reassigning,
            recipients: &recipients_b,
            now_micros: now_b,
        },
        &mut Os,
    )?;
    println!("RP round3_assign_root_hash={}", hex(&assign.root_hash));
    send(identity, &mut syncs[1], &assign, now_b)?;
    let arrived = run_until(identity, syncs, 90, |s| {
        s[1].runtime().ledger.is_active(contract_id)
    })?;
    let counter_b = syncs[1].runtime().ledger.counter_of(contract_id);
    println!("RP round3_assign arrived_b={arrived} counter_b={counter_b}");
    if !arrived || counter_b != counter + 1 {
        return Err(format!(
            "round 3: the Rust-built assignment was not approved: {:?}",
            notes(syncs)
        ));
    }
    put(dir, "rust_round3", &format!("{rid}\n"))?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!("usage: rust-reassign-participant <syncA url> <syncB url> <command dir> <sample dar> <state dir>");
        std::process::exit(2);
    }
    if let Err(why) = run(
        [&args[1], &args[2]],
        Path::new(&args[3]),
        Path::new(&args[4]),
        Path::new(&args[5]),
    ) {
        println!("RP result=failed: {why}");
        std::process::exit(1);
    }
}
