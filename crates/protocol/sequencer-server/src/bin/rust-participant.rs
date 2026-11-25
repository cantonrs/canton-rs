//! `rust-participant <sequencer url> <command dir> <sample dar> <state dir>`: a Rust participant whose event loop (G5,
//! `canton_participant::participant_runtime`) runs against a sequencer, here the Rust one (G6, S-NET-037 part 13).
//!
//! It plays one fixed scenario with an official JVM participant `p2` (`scripts/verify-rust-sequencer.sh`, `JVM_SUBMIT=4`), talking to the
//! JVM's console script through files in the command directory:
//! 1. reads `p2.info` (p2's uid and the sample package id), joins the synchronizer, proposes the party `erin` hosted by itself
//!    (confirmation) and p2 (submission), vets the sample package, and writes the proposal's hash to `erin.req` for p2 to co-sign;
//! 2. opens a runtime that is given **nothing** (it learns what it hosts and whom to trust from the topology) and, once it hosts erin,
//!    writes erin's id to `erin.ready`; p2 then creates a contract erin signs and writes its id to `created`;
//! 3. follows the creation until the contract is active, raises erin's hosting threshold to 2 (so that its own answer becomes
//!    **necessary** for the mediator) and writes `raised`; p2 then settles the contract;
//! 4. follows the settle until the contract is archived, and prints what it did as `RP <key>=<value>` lines.
//!
//! [CANTON-NOTE: WHY] A binary and not a cargo test: the scenario needs the JVM node the harness script starts in Docker.
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
    // written beside and renamed: the reader never sees half a file
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, content).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dir.join(name)).map_err(|e| e.to_string())
}

struct Joined {
    identity: ParticipantIdentity,
    connection: SequencerConnect,
    token: Token,
    physical: String,
}

impl Joined {
    fn now(&mut self) -> Result<i64, String> {
        self.connection
            .sequencer_time(&self.identity.member(), &self.physical, Some(&self.token))
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "the sequencer has no time yet".to_string())
    }

    fn broadcast(
        &mut self,
        id: &str,
        transactions: &[canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction],
    ) -> Result<(), String> {
        let now = self.now()?;
        let envelopes = vec![(
            vec![tw::ALL_MEMBERS.to_string()],
            tw::topology_broadcast(&self.physical, transactions),
        )];
        self.connection
            .send_async(
                &self.identity.member(),
                &self.physical,
                &self.token,
                sw::signed_submission_request(
                    sw::submission_request_to_groups(
                        &self.identity.member(),
                        id,
                        &envelopes,
                        now + 60_000_000,
                    ),
                    &self.identity.signing_key,
                ),
            )
            .map_err(|e| e.to_string())
    }
}

fn join(url: &str) -> Result<Joined, String> {
    let identity = ParticipantIdentity::generate("rustpar");
    let mut connection = SequencerConnect::connect(url).map_err(|e| e.to_string())?;
    let id = connection.synchronizer_id().map_err(|e| e.to_string())?;
    let physical = id.physical_synchronizer_id;
    // the synchronizer's uid is the physical id without its protocol suffix (`name::namespace::37-0`)
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
    Ok(Joined {
        identity,
        connection,
        token,
        physical,
    })
}

/// Lets the runtime read events until `done` holds or `seconds` are up; the steps it took are added to `steps`.
fn run_until(
    runtime: &mut rt::Runtime,
    j: &mut Joined,
    seconds: u64,
    steps: &mut Vec<rt::Step>,
    mut done: impl FnMut(&rt::Runtime) -> bool,
) -> Result<bool, String> {
    let limit = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < limit {
        if done(runtime) {
            return Ok(true);
        }
        steps.extend(runtime.poll(
            &mut j.connection,
            &j.token,
            &j.identity.signing_key,
            Duration::from_secs(2),
        )?);
    }
    Ok(done(runtime))
}

fn run(url: &str, dir: &Path, dar: &Path, state_dir: &Path) -> Result<(), String> {
    let info = wait_for(dir, "p2.info", 240)?;
    let mut lines = info.lines();
    let p2_uid = lines
        .next()
        .ok_or("p2.info has no uid")?
        .trim_start_matches("PAR::")
        .to_string();
    let package = lines.next().ok_or("p2.info has no package id")?.to_string();
    let mut j = join(url)?;
    println!("RP member={}", j.identity.member());
    // the runtime starts before the party exists: everything about erin reaches it as events
    std::thread::sleep(Duration::from_millis(800));
    let start = j.now()?;
    let erin = j.identity.party_id("erin");
    let proposal = j
        .identity
        .shared_party_proposal_with("erin", &p2_uid, 2, 1, 1);
    let proposal_hash = tw::transaction_hash(&proposal.transaction);
    let vetting = j.identity.vetting_transaction(&[package]);
    j.broadcast("erin-proposal", &[proposal, vetting])?;
    put(dir, "erin.req", &hex(&proposal_hash))?;
    let config = rt::Config {
        member: j.identity.member(),
        encryption_fingerprint: j.identity.encryption_fingerprint(),
        encryption_secret: *j.identity.encryption_secret(),
        hosted_parties: vec![],
        timeouts: Default::default(),
        submitter_keys: vec![],
        mediator_keys: vec![],
        peer_encryption_keys: Default::default(),
        physical_synchronizer_id: j.physical.clone(),
        topology_change_delay_micros: 250_000,
        follow_topology: true,
    };
    let engine = canton_participant::view_conformance::Engine::load(dar)?;
    let mut runtime = rt::Runtime::open(config, engine, Some(state_dir), start)?;
    let mut steps = Vec::new();
    let hosted = run_until(&mut runtime, &mut j, 90, &mut steps, |r| {
        r.config.hosted_parties.contains(&erin)
    })?;
    println!("RP hosts_erin={hosted}");
    if !hosted {
        return Err(format!(
            "the runtime never learned that it hosts erin: {:?}",
            steps.iter().flat_map(|s| &s.notes).collect::<Vec<_>>()
        ));
    }
    println!(
        "RP learned_keys=submitter:{} mediator:{}",
        runtime.config.submitter_keys.len(),
        runtime.config.mediator_keys.len()
    );
    put(dir, "erin.ready", &erin)?;
    let contract_id = wait_for(dir, "created", 120)?.trim().to_string();
    let active = run_until(&mut runtime, &mut j, 90, &mut steps, |r| {
        r.ledger.is_active(&contract_id)
    })?;
    println!("RP contract_active={active}");
    if !active {
        return Err(format!(
            "the runtime did not follow the creation of {contract_id}: {steps:#?}"
        ));
    }
    // erin needs both hosts from now on: only this participant's own answer can make the mediator approve the settle
    let bytes =
        tw::party_to_participant_at_serial(&erin, &[(&p2_uid, 1), (&j.identity.uid(), 2)], 2, 2);
    let raise = tw::signed(
        bytes.clone(),
        vec![j.identity.namespace_key.sign_transaction(&bytes)],
    );
    j.broadcast("erin-threshold", &[raise])?;
    // the runtime reads the change like any other event; p2 needs it in force before it settles
    run_until(&mut runtime, &mut j, 4, &mut steps, |_| false)?;
    put(dir, "raised", "2")?;
    let archived = run_until(&mut runtime, &mut j, 120, &mut steps, |r| {
        r.ledger.archived_by(&contract_id).is_some()
    })?;
    println!("RP contract_archived={archived}");
    let Some(archived_by) = runtime.ledger.archived_by(&contract_id) else {
        return Err(format!(
            "the runtime did not follow the settle of {contract_id}: {:?}",
            steps.iter().flat_map(|s| &s.notes).collect::<Vec<_>>()
        ));
    };
    let answers: Vec<&rt::ToSend> = steps.iter().flat_map(|s| &s.to_send).collect();
    let settle = answers
        .iter()
        .find(|a| a.request_time == archived_by)
        .ok_or("the runtime did not answer the settle")?;
    println!(
        "RP settle_answer={} for {:?}",
        match &settle.decision().outcome {
            Outcome::Approve => "approve".to_string(),
            other => format!("{other:?}"),
        },
        settle.decision().confirming_parties
    );
    let verdicts: Vec<(i64, bool)> = steps.iter().flat_map(|s| s.verdicts.clone()).collect();
    println!(
        "RP verdicts={} settle_approved={}",
        verdicts.len(),
        verdicts.iter().any(|(t, ok)| *t == archived_by && *ok)
    );
    println!("RP in_flight={}", runtime.ledger.in_flight());
    println!("RP answers={}", answers.len());
    if settle.decision().outcome != Outcome::Approve
        || settle.decision().confirming_parties != vec![erin]
        || !verdicts.iter().any(|(t, ok)| *t == archived_by && *ok)
        || runtime.ledger.in_flight() != 0
    {
        return Err("the settle was not approved on this participant's answer".into());
    }
    println!("RP result=ok");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: rust-participant <sequencer url> <command dir> <sample dar> <state dir>");
        std::process::exit(2);
    }
    if let Err(why) = run(
        &args[1],
        Path::new(&args[2]),
        Path::new(&args[3]),
        Path::new(&args[4]),
    ) {
        println!("RP result=failed: {why}");
        std::process::exit(1);
    }
}
