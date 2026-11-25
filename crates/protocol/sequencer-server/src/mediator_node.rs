//! The mediator as a process of its own (G11, S-LOCAL-004): it joins the synchronizer **as a member**, like a participant. The sequencer
//! delivers it what is addressed to its group (the informee message and the root hash messages of a request, the participants' responses),
//! it decides with the same logic the mediator inside the sequencer uses ([`crate::mediator::Mediator`]), and its verdicts and time-outs
//! travel back through the sequencer as submissions it signs, to the participants that have to learn them.
//!
//! [CANTON-NOTE: SEMANTICS] What the mediator knows of the synchronizer it **learns the way a participant does**: the topology state the
//! sequencer hands out, then the topology broadcasts it is sent, each in force from its sequencing time plus the topology change delay. A
//! request is judged by the state in force before it. The inside mediator reads the sequencer's own store instead.
//!
//! [CANTON-NOTE: SEMANTICS] A mediator that is stopped and started again **continues**: after every event it keeps how far it read and the
//! time of the oldest request it still waits to decide (`mediator-<group>.state` in the state directory). It starts again from that request and
//! reads the events since silently (what it would send was sent before, or is a duplicate the participants ignore), which rebuilds the pending
//! requests exactly; from the first event past what it had read it answers again. A request that ran out of time while it was down is then
//! timed out like any other.
//!
//! [CANTON-NOTE: SEMANTICS] A mediator with an identity of its own ([`start_own`], S-LOCAL-011) shares nothing with the sequencer: its keys
//! are in its own state, and it is a member because the synchronizer's owners loaded its identity and named it in a mediator group (see
//! [`crate::mediator_identity`]). [`start_with`] is the older way, a mediator of the synchronizer's own mediator namespace whose key is read
//! from the sequencer's state (`RUST_SEQUENCER_EXTERNAL_MEDIATOR=1`).
//!
//! [CANTON-NOTE: SEMANTICS] It decides by the synchronizer's time only, as the official mediator: a request times out at the first event it
//! reads past the request's deadline, and when no event comes it asks the sequencer for a time proof ([`canton_participant::sequencer_time`])
//! rather than reading the sequencer's clock. Every event is checked as a participant checks it ([`crate::mediator_events`]); a refused one
//! stops the reading.
//!
//! [CANTON-NOTE: LIMITATION] When a saved cursor exists, `DownloadTopologyStateForInit` only returns topology up to the
//! mediator's onboarding time; topology broadcasts received since then are persisted to `mediator-<group>.topology.journal`
//! and replayed onto the initial tracker on restart (following `participant_runtime/topology_journal.rs`).
use crate::mediator::{Mediator, MediatorView, Outgoing, SeenEnvelope};
use crate::mediator_events::Reader;
use crate::synchronizer_state::{Hosting, SynchronizerKeys};
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use canton_participant::sequencer_time::{TimeKeeper, TIME_PROOF_EXPIRY_MICROS};
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_state::{
    broadcast_transactions, decode, is_addressed_to_all, Tracker,
};
use canton_participant::topology_wire::Ed25519Key;
use canton_participant::view_acs::Timeouts;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The synchronizer as the mediator follows it.
struct FollowedView {
    tracker: Mutex<Tracker>,
}

impl FollowedView {
    /// `signed_request` carrying its traffic cost under the traffic control in force, signed again by `key` (U-58).
    ///
    /// [CANTON-NOTE: SEMANTICS] A sequencer with traffic control on makes mediators pay for their submissions as it does participants
    /// (`SequencerRateLimitManagerImpl`: participants and mediators pay); one reading of the cost for both
    /// (`canton_participant::participant_runtime::pay_with`).
    fn pay(&self, signed_request: Vec<u8>, key: &Ed25519Key) -> Vec<u8> {
        canton_participant::participant_runtime::pay_with(
            &self
                .tracker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            signed_request,
            key,
        )
    }
}

impl MediatorView for FollowedView {
    fn signing_keys(&self, member: &str) -> Option<Vec<canton_algo::signing::PublicKey>> {
        self.tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .signing_keys_of(member)
    }
    fn member_with_key(&self, fingerprint: &str) -> Option<String> {
        self.tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .member_with_key(fingerprint)
    }
    // what is in force now: the mediator processes the events in order, so "now" is the state before the event it is judging
    fn hosts_at(&self, _at: i64) -> BTreeMap<String, Vec<String>> {
        self.tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .hosts_now()
    }
    fn hosting_at(&self, _at: i64) -> BTreeMap<String, Hosting> {
        self.tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .hosting_now()
    }
    fn timeouts_at(&self, _at: i64) -> Timeouts {
        self.tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .learned()
            .timeouts
            .unwrap_or_default()
    }
}

/// The topology change delay of the synchronizer's static parameters (measured on the official node: 250 000 micros).
const TOPOLOGY_CHANGE_DELAY_MICROS: i64 = 250_000;

/// Shared runtime counters and sequencer connectivity state observed by `mediator run` health/metrics HTTP endpoints.
#[derive(Default)]
pub struct MediatorTelemetry {
    pub connected: AtomicBool,
    pub verdicts_approved: std::sync::atomic::AtomicU64,
    pub verdicts_rejected: std::sync::atomic::AtomicU64,
    pub pending_quorums: std::sync::atomic::AtomicU64,
    pub last_error: std::sync::Mutex<Option<String>>,
}

/// A running mediator; dropping it stops it.
pub struct MediatorProcess {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    pub member: String,
    /// The mediator group it serves.
    pub group: u32,
    pub telemetry: Arc<MediatorTelemetry>,
}

impl Drop for MediatorProcess {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Starts the mediator of `group` on the synchronizer whose sequencer is at `url`, with the keys of `state_dir`. Returns once it is
/// connected and has the topology; the loop runs on a thread.
pub fn start(url: &str, state_dir: &Path, group: u32) -> Result<MediatorProcess, String> {
    let store = canton_participant::state_store::FileStore::new(state_dir)?;
    start_with(url, store.as_ref(), Arc::clone(&store) as Arc<_>, group)
}

/// Like [`start`], with the synchronizer's keys read from `keys` and the mediator's own state (how far it read, what it still waits for) kept
/// in `own`. They are one directory for a mediator beside its sequencer; for a database they are two states of it: the sequencer's (read, never
/// written, by every mediator) and the mediator's.
pub fn start_with(
    url: &str,
    keys: &dyn canton_participant::state_store::StateStore,
    own: Arc<dyn canton_participant::state_store::StateStore>,
    group: u32,
) -> Result<MediatorProcess, String> {
    let keys = SynchronizerKeys::load_or_create_in(keys, 1)
        .map_err(|e| format!("the synchronizer's keys: {e}"))?;
    if group as usize >= keys.groups() {
        return Err(format!(
            "the synchronizer has {} mediator group(s), not {group}",
            keys.groups()
        ));
    }
    let key = keys.mediator_key(group as usize);
    let who = Who {
        member: format!(
            "MED::rm{}::{}",
            group + 1,
            keys.mediator_namespace.fingerprint
        ),
        signing: Arc::new(Ed25519Key::from_seed(key.seed())),
        authentication: key.seed(),
        group: Some(group),
    };
    start_as(url, who, own)
}

/// Configuration options for [`start_own_with_options`].
#[derive(Clone, Copy, Debug)]
pub struct MediatorOptions {
    /// Whether periodic `AcknowledgeSigned` requests are sent to the sequencer (`true` in production).
    pub acknowledge_enabled: bool,
}

impl Default for MediatorOptions {
    fn default() -> Self {
        Self {
            acknowledge_enabled: true,
        }
    }
}

/// Starts the mediator whose identity is kept in its own state `own` (see [`crate::mediator_identity`]): it shares nothing with the
/// sequencer. It serves the group the synchronizer's topology names it in; one it is in no group of yet is refused by the sequencer.
pub fn start_own(
    url: &str,
    own: Arc<dyn canton_participant::state_store::StateStore>,
) -> Result<MediatorProcess, String> {
    start_own_with_options(url, own, MediatorOptions::default())
}

/// Like [`start_own`], with explicit [`MediatorOptions`].
pub fn start_own_with_options(
    url: &str,
    own: Arc<dyn canton_participant::state_store::StateStore>,
    options: MediatorOptions,
) -> Result<MediatorProcess, String> {
    let identity =
        crate::mediator_identity::MediatorIdentity::load(own.as_ref())?.ok_or_else(|| {
            format!(
                "no mediator identity in {} (`canton-rs mediator init` makes one)",
                own.describe()
            )
        })?;
    let who = Who {
        member: identity.member(),
        signing: Arc::new(Ed25519Key::from_seed(identity.signing_key.seed())),
        authentication: identity.sequencer_auth_key.seed(),
        group: None,
    };
    start_as_with_options(url, who, own, options)
}

/// Who the mediator is: its member id, the key it signs its verdicts and submissions with, the seed of the key it answers the
/// authentication challenge with, and its group (`None`: the one the topology names it in).
struct Who {
    member: String,
    signing: Arc<Ed25519Key>,
    authentication: [u8; 32],
    group: Option<u32>,
}

fn start_as(
    url: &str,
    who: Who,
    own: Arc<dyn canton_participant::state_store::StateStore>,
) -> Result<MediatorProcess, String> {
    start_as_with_options(url, who, own, MediatorOptions::default())
}

fn start_as_with_options(
    url: &str,
    who: Who,
    own: Arc<dyn canton_participant::state_store::StateStore>,
    options: MediatorOptions,
) -> Result<MediatorProcess, String> {
    let member = who.member.clone();
    let mut client = SequencerConnect::connect(url).map_err(|e| e.to_string())?;
    let synchronizer = client.synchronizer_id().map_err(|e| e.to_string())?;
    let physical = synchronizer.physical_synchronizer_id;
    // authenticate: the challenge answered with the mediator's authentication key (the key mapping the sequencer knows lists it)
    let challenge = client.challenge(&member, &[37]).map_err(|e| {
        format!(
            "the sequencer does not know the mediator {member} (is it in a mediator group? `canton-rs mediator onboarding` prints what \
             the synchronizer's operator has to authorize): {e}"
        )
    })?;
    let auth_seed = who.authentication;
    let signature = Ed25519Key::from_seed(auth_seed).sign_bytes(
        &AuthKey::challenge_hash(&challenge.nonce, &physical)
            .map_err(|e| format!("the challenge hash: {e:?}"))?,
    );
    let token = client
        .authenticate(&member, &challenge.nonce, signature)
        .map_err(|e| e.to_string())?;
    // a sequencer that restarted keeps no tokens: the mediator authenticates again by itself when its token is refused
    client.set_reauth(
        &member,
        &physical,
        Box::new(move |hash| Ed25519Key::from_seed(auth_seed).sign_bytes(hash)),
    );
    let state = client
        .download_topology_state_in_force(&member, &physical, &token)
        .map_err(|e| e.to_string())?;
    let entries = decode(&state)?;
    let uid = member.trim_start_matches("MED::").to_string();
    let specs = client.required_schemes().map_err(|e| e.to_string())?;
    let mut tracker = Tracker::for_synchronizer(&entries, &uid, &physical)?;
    tracker.set_crypto_specs(specs);
    let group = match who.group {
        Some(g) => g,
        None => tracker
            .mediator_groups()
            .iter()
            .find(|(_, g)| g.active.contains(&uid) || g.observers.contains(&uid))
            .map(|(g, _)| *g)
            .ok_or_else(|| {
                format!("{member} is in no mediator group of the synchronizer's topology")
            })?,
    };
    let topo_key = format!("mediator-{group}.topology.journal");
    for stored in load_mediator_topology_journal(own.as_ref(), &topo_key) {
        tracker.apply_stored(&stored);
    }
    let view = Arc::new(FollowedView {
        tracker: Mutex::new(tracker),
    });
    let mediator = Mediator::with_view(
        group,
        physical.clone(),
        Arc::clone(&who.signing),
        Arc::clone(&view) as Arc<_>,
    );
    let state_key = format!("mediator-{group}.state");
    // where it stopped: (how far it had read, the oldest request it still waited for), else the sequencer's current time
    let kept: Option<(i64, i64)> = own.read(&state_key).ok().flatten().and_then(|t| {
        let mut f = t.split_whitespace();
        Some((f.next()?.parse().ok()?, f.next()?.parse().ok()?))
    });
    let (cursor, silent_until, persisted_cursor) = match kept {
        // one before the oldest pending request: the next event read is that request
        Some((read, replay_from)) => (replay_from - 1, read, read),
        None => {
            let init_cursor = client
                .sequencer_time(&member, &physical, Some(&token))
                .map_err(|e| e.to_string())?
                .unwrap_or(-1);
            (init_cursor, 0, init_cursor)
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = std::sync::Arc::clone(&stop);
    let telemetry = Arc::new(MediatorTelemetry::default());
    telemetry.connected.store(true, Ordering::SeqCst);
    let loop_telemetry = Arc::clone(&telemetry);
    let name = member.clone();
    let handle = std::thread::spawn(move || {
        let mut node = Loop {
            client,
            token,
            reader: Reader::new(cursor, &physical),
            persisted_cursor,
            physical,
            sequencer: format!("SEQ::{}", synchronizer.sequencer_uid),
            member: name,
            signing: who.signing,
            view,
            mediator,
            clock: TimeKeeper::new(Instant::now(), cursor),
            silent_until,
            own,
            state_key,
            topo_key,
            pending_topology: Vec::new(),
            subscribe_healthy: true,
            acknowledge_enabled: options.acknowledge_enabled,
            telemetry: Arc::clone(&loop_telemetry),
        };
        while !stop_flag.load(Ordering::SeqCst) {
            match node.step() {
                Ok(()) => {
                    loop_telemetry.connected.store(true, Ordering::Relaxed);
                    let mut err = loop_telemetry
                        .last_error
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if err
                        .as_deref()
                        .is_none_or(|msg| !msg.starts_with("mediator ack failed:"))
                    {
                        *err = None;
                    }
                }
                Err(e) => {
                    loop_telemetry.connected.store(false, Ordering::Relaxed);
                    *loop_telemetry
                        .last_error
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(e.clone());
                    crate::diag::diag_eprintln!("MEDIATOR {}: {e}", node.member);
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    });
    Ok(MediatorProcess {
        stop,
        handle: Some(handle),
        member,
        group,
        telemetry,
    })
}

/// Puts into force the topology changes of `pending` that took effect before `now`.
fn apply_due_topology(pending: &mut Vec<(i64, Vec<u8>)>, view: &FollowedView, now: i64) {
    if pending.iter().all(|(at, _)| *at >= now) {
        return;
    }
    let (due, later): (Vec<_>, Vec<_>) = std::mem::take(pending)
        .into_iter()
        .partition(|(at, _)| *at < now);
    *pending = later;
    let mut tracker = view
        .tracker
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut batch_at = None;
    for (at, stored) in &due {
        if batch_at != Some(*at) {
            tracker.end_batch();
            tracker.begin_batch();
            batch_at = Some(*at);
        }
        tracker.apply_stored(stored);
    }
    tracker.end_batch();
}

fn wall_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
}

/// Appends `stored` to `topo_key` once (deduplicating replayed broadcasts), mirroring `participant_runtime/topology_journal.rs`.
fn journal_mediator_topology(
    own: &dyn canton_participant::state_store::StateStore,
    key: &str,
    stored: &[u8],
) -> Result<(), String> {
    let line = crate::persistence::hex(stored);
    if own
        .read(key)?
        .unwrap_or_default()
        .lines()
        .any(|kept| kept.trim() == line)
    {
        return Ok(());
    }
    own.append(key, &line)
}

/// Loads journaled topology broadcasts from `topo_key` in first-seen order without duplicates.
fn load_mediator_topology_journal(
    own: &dyn canton_participant::state_store::StateStore,
    key: &str,
) -> Vec<Vec<u8>> {
    let Some(journal) = own.read(key).ok().flatten() else {
        return Vec::new();
    };
    let mut seen = std::collections::BTreeSet::new();
    journal
        .lines()
        .filter_map(|line| crate::persistence::unhex(line.trim()))
        .filter(|stored| seen.insert(stored.clone()))
        .collect()
}

struct Loop {
    client: SequencerConnect,
    token: canton_participant::sequencer_connect::Token,
    physical: String,
    member: String,
    signing: Arc<Ed25519Key>,
    /// The sequencer this mediator reads from (`SEQ::<uid>`): whose keys sign its events.
    sequencer: String,
    view: Arc<FollowedView>,
    mediator: Mediator,
    reader: Reader,
    /// Last cursor durably written by [`Self::keep`]; acknowledgements never overtake persisted state.
    persisted_cursor: i64,
    /// When to ask for a time proof.
    clock: TimeKeeper,
    /// Events up to this time are read again only to rebuild the pending requests: nothing is sent for them.
    silent_until: i64,
    own: Arc<dyn canton_participant::state_store::StateStore>,
    state_key: String,
    topo_key: String,
    /// Topology changes seen and not yet in force: (the time they take effect, the stored transaction).
    pending_topology: Vec<(i64, Vec<u8>)>,
    /// Tracks whether the sequencer stream is healthy (`PeriodicAcknowledgements.scala:40-44, 60-87`).
    subscribe_healthy: bool,
    /// When `false`, skips periodic `AcknowledgeSigned` transmissions (negative control in oracle tests).
    acknowledge_enabled: bool,
    telemetry: Arc<MediatorTelemetry>,
}

struct AckInput {
    now: Instant,
    cursor: i64,
    earliest_pending: Option<i64>,
    healthy: bool,
}

fn clean_for_ack(cursor: i64, earliest_pending: Option<i64>) -> i64 {
    earliest_pending.map_or(cursor, |t| t.saturating_sub(1))
}

fn try_acknowledge<F, L>(
    clock: &mut TimeKeeper,
    input: AckInput,
    send_ack: F,
    mut log_err: L,
) -> Option<i64>
where
    F: FnOnce(i64) -> Result<(), String>,
    L: FnMut(&str),
{
    let clean = clean_for_ack(input.cursor, input.earliest_pending);
    if clean <= 0 {
        return None;
    }
    let at = clock.acknowledgement(input.now, clean, input.healthy)?;
    if let Err(err) = send_ack(at) {
        log_err(&err);
        return None;
    }
    Some(at)
}

impl Loop {
    fn send(&mut self, outgoing: Vec<Outgoing>) -> Result<(), String> {
        if outgoing.is_empty() {
            return Ok(());
        }
        // Wait briefly if a newly started BFT cluster is still in epoch-0 blocks 0..N-1 whose BFT timestamps have not yet reached wall time.
        let mut now = self.reader.cursor();
        for _ in 0..200 {
            if let Some(t) = self
                .client
                .sequencer_time(&self.member, &self.physical, Some(&self.token))
                .map_err(|e| e.to_string())?
            {
                now = t;
                if t >= 1_000_000_000 {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        for (n, o) in outgoing.into_iter().enumerate() {
            // one envelope for each member it is for: each is told only about itself, as the verdict of the inside mediator is
            let envelopes: Vec<(Vec<String>, Vec<u8>, Vec<_>)> =
                o.to.iter()
                    .map(|m| (vec![m.clone()], o.content.clone(), o.signatures.clone()))
                    .collect();
            // [CANTON-NOTE: SEMANTICS] A message id is at most 73 characters (`MessageId`, a `String73`): the official sequencer refused the
            // verdict of a Rust mediator whose id named the participants ("SEQUENCER_SUBMISSION_REQUEST_MALFORMED ... maximum length of
            // 73", measured, S-LOCAL-011). The time and the place in the batch keep it unique.
            let message_id = format!("verdict-{now}-{n}");
            let request = sw::submission_request_signed(
                &self.member,
                &message_id,
                &envelopes,
                now + 60_000_000,
            );
            self.client
                .send_async(
                    &self.member,
                    &self.physical,
                    &self.token,
                    self.view.pay(
                        sw::signed_submission_request(request, &self.signing),
                        &self.signing,
                    ),
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Asks the sequencer for a time proof when a pending request waits for a time no event has brought (`SynchronizerTimeTracker`).
    fn ask_for_time(&mut self) -> Result<(), String> {
        let wall = wall_micros();
        let wanted = self.mediator.next_deadline().map(|d| d.saturating_add(1));
        if !self
            .clock
            .ask_for_time(Instant::now(), wall, self.reader.cursor(), wanted)
        {
            return Ok(());
        }
        let message_id = format!("{}{:032x}", sw::TIME_PROOF_PREFIX, rand::random::<u128>());
        let request = self.view.pay(
            sw::signed_time_proof_request(
                &self.member,
                &message_id,
                wall.saturating_add(TIME_PROOF_EXPIRY_MICROS),
                &self.signing,
            ),
            &self.signing,
        );
        self.client
            .send_async(&self.member, &self.physical, &self.token, request)
            .map_err(|e| e.to_string())
    }

    /// Periodically acknowledges clean events before any pending request so the sequencer can prune delivered items.
    ///
    /// [CANTON-NOTE: SEMANTICS] Aligns with `PeriodicAcknowledgements.scala:40-44, 60-87`, `SequencerClient.scala:1640, 2251`,
    /// and `VerdictSender.scala:169-174`: skip while the sequencer subscription is unhealthy (`!self.subscribe_healthy`), log errors
    /// instead of silently dropping them, and advance strictly from the clean processed cursor (never capped permanently by a
    /// transient verdict send failure).
    fn maybe_acknowledge(&mut self) {
        let input = AckInput {
            now: Instant::now(),
            cursor: self.persisted_cursor,
            earliest_pending: self.mediator.earliest_pending(),
            healthy: self.subscribe_healthy,
        };
        let (client, member, physical, token, signing, telemetry) = (
            &mut self.client,
            &self.member,
            &self.physical,
            &self.token,
            &self.signing,
            &self.telemetry,
        );
        if try_acknowledge(
            &mut self.clock,
            input,
            |at| {
                let request = sw::signed_acknowledge_request(member, at, signing);
                client
                    .acknowledge_signed(member, physical, token, request)
                    .map_err(|e| e.to_string())
            },
            |err| {
                let msg = format!("mediator ack failed: {err}");
                crate::diag::diag_eprintln!("{msg}");
                *telemetry
                    .last_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(msg);
            },
        )
        .is_some()
        {
            let mut last = telemetry
                .last_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if last
                .as_deref()
                .is_some_and(|m| m.starts_with("mediator ack failed:"))
            {
                *last = None;
            }
        }
    }

    /// Reads one event (or waits a moment for one), judges what it holds and sends what the mediator decides.
    fn step(&mut self) -> Result<(), String> {
        if let Some(refused) = self.reader.halted() {
            return Err(format!("stopped reading the sequencer: {refused}"));
        }
        // a wait that ends without an event is reported as an error of the stream: the next subscription checks the last event again
        let events = match self.client.subscribe(
            &self.member,
            &self.physical,
            &self.token,
            Some(self.reader.subscribe_from()),
            1,
            Duration::from_millis(300),
        ) {
            Ok(events) => {
                self.subscribe_healthy = true;
                events
            }
            Err(_) => {
                self.subscribe_healthy = false;
                self.reader.broken();
                Vec::new()
            }
        };
        let Some(raw) = events.first() else {
            if self.acknowledge_enabled && self.persisted_cursor > self.silent_until {
                self.maybe_acknowledge();
            }
            return self.ask_for_time();
        };
        let (view, sequencer, pending) = (&self.view, &self.sequencer, &mut self.pending_topology);
        let event = match self.reader.receive(raw, |at| {
            apply_due_topology(pending, view, at);
            view.tracker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .signing_keys_of(sequencer)
        }) {
            Ok(Some(event)) => event,
            Ok(None) => return Ok(()),
            Err(refused) => return Err(format!("stopped reading the sequencer: {refused}")),
        };
        self.clock.observed(Instant::now(), event.timestamp_micros);
        let trees = sw::decode_recipient_trees(raw).unwrap_or_default();
        let mut seen: Vec<SeenEnvelope> = Vec::new();
        for (i, content) in event.envelopes.iter().enumerate() {
            if let Some(transactions) = broadcast_transactions(content) {
                let recipients: Vec<String> = trees
                    .get(i)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .cloned()
                    .collect();
                if !is_addressed_to_all(&recipients) {
                    crate::diag::diag_eprintln!(
                        "MEDIATOR {}: discarding a topology broadcast at {} with invalid recipients: {recipients:?}",
                        self.member, event.timestamp_micros
                    );
                    continue;
                }
                for stored in transactions {
                    if let Err(err) =
                        journal_mediator_topology(self.own.as_ref(), &self.topo_key, &stored)
                    {
                        crate::diag::diag_eprintln!(
                            "MEDIATOR {}: failed to journal topology broadcast: {err}",
                            self.member
                        );
                    }
                    self.pending_topology.push((
                        event.timestamp_micros + TOPOLOGY_CHANGE_DELAY_MICROS,
                        stored,
                    ));
                }
                continue;
            }
            let tree = trees.get(i).cloned().unwrap_or_default();
            if tree.iter().flatten().any(|a| a.starts_with("MGR::")) {
                seen.push((
                    tree,
                    content.clone(),
                    event
                        .envelope_signatures
                        .get(i)
                        .cloned()
                        .unwrap_or_default(),
                ));
            }
        }
        let out = self.mediator.handle(event.timestamp_micros, "", &seen);
        let replaying = event.timestamp_micros <= self.silent_until;
        let sent = if replaying {
            Ok(())
        } else {
            let mut approved = 0u64;
            let mut rejected = 0u64;
            for item in &out {
                if item.approved {
                    approved += 1;
                } else {
                    rejected += 1;
                }
            }
            let res = self.send(out);
            match &res {
                Ok(()) => {
                    if approved > 0 {
                        self.telemetry
                            .verdicts_approved
                            .fetch_add(approved, Ordering::Relaxed);
                    }
                    if rejected > 0 {
                        self.telemetry
                            .verdicts_rejected
                            .fetch_add(rejected, Ordering::Relaxed);
                    }
                }
                Err(err) => {
                    let msg = format!("verdict send failed at {}: {err}", event.timestamp_micros);
                    crate::diag::diag_eprintln!("MEDIATOR {}: {msg}", self.member);
                    *self
                        .telemetry
                        .last_error
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(msg);
                }
            }
            res
        };
        self.telemetry
            .pending_quorums
            .store(self.mediator.pending_count() as u64, Ordering::Relaxed);
        // after the sending: a restart in between sends the event's answers again, which the participants ignore, rather than never
        if !replaying && sent.is_ok() {
            self.keep();
            if self.acknowledge_enabled {
                self.maybe_acknowledge();
            }
        }
        sent
    }

    /// Keeps how far the mediator has read and the time of the oldest request it still waits for.
    fn keep(&mut self) {
        let cursor = self.reader.cursor();
        let replay_from = self.mediator.earliest_pending().unwrap_or(cursor);
        match self
            .own
            .write(&self.state_key, &format!("{cursor} {replay_from}\n"))
        {
            Ok(()) => self.persisted_cursor = cursor,
            Err(err) => crate::diag::diag_eprintln!(
                "MEDIATOR {}: failed to persist {}: {err}",
                self.member,
                self.state_key
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_participant::confirmation_wire::ENVELOPE_CONTENT_VERSION;
    use canton_participant::state_store::StateStore;
    use canton_participant::topology_wire as tw;
    use canton_proto::com::digitalasset::canton::protocol::v32::{
        envelope_content::SomeEnvelopeContent, EnvelopeContent, SequencedEvent,
    };
    use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_service_server::{
        SequencerService, SequencerServiceServer,
    };
    use canton_proto::com::digitalasset::canton::sequencer::api::v30::{
        AcknowledgeRequest, AcknowledgeSignedRequest, AcknowledgeSignedResponse,
        DownloadTopologyStateForInitHashRequest, DownloadTopologyStateForInitHashResponse,
        DownloadTopologyStateForInitRequest, DownloadTopologyStateForInitResponse, GetTimeRequest,
        GetTimeResponse, GetTrafficStateForMemberRequest, GetTrafficStateForMemberResponse,
        SendAsyncRequest, SendAsyncResponse, SubscriptionRequest, SubscriptionResponse,
    };
    use prost::Message;
    use std::pin::Pin;
    use std::sync::atomic::AtomicBool;
    use tokio_stream::Stream;
    use tonic::{Request, Response, Status};

    struct MemStore(Mutex<BTreeMap<String, String>>);

    impl StateStore for MemStore {
        fn read(&self, key: &str) -> Result<Option<String>, String> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn write(&self, key: &str, text: &str) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .insert(key.to_string(), text.to_string());
            Ok(())
        }
        fn append(&self, key: &str, line: &str) -> Result<(), String> {
            let mut m = self.0.lock().unwrap();
            let entry = m.entry(key.to_string()).or_default();
            entry.push_str(line);
            entry.push('\n');
            Ok(())
        }
        fn create_new(&self, key: &str, text: &str) -> Result<bool, String> {
            let mut m = self.0.lock().unwrap();
            if m.contains_key(key) {
                return Ok(false);
            }
            m.insert(key.to_string(), text.to_string());
            Ok(true)
        }
        fn describe(&self) -> String {
            "memory".into()
        }
    }

    #[derive(Default)]
    struct MockSequencer {
        fail_subscribe: AtomicBool,
        fail_send_async: AtomicBool,
        fail_ack: AtomicBool,
        sequencer_time: Mutex<i64>,
        queued_events: Mutex<Vec<Vec<u8>>>,
        ack_timestamps: Mutex<Vec<i64>>,
        send_calls: std::sync::atomic::AtomicUsize,
    }

    impl MockSequencer {
        fn ack_timestamps(&self) -> Vec<i64> {
            self.ack_timestamps.lock().unwrap().clone()
        }
    }

    type MockStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

    struct MockSvc(Arc<MockSequencer>);

    impl std::ops::Deref for MockSvc {
        type Target = MockSequencer;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[tonic::async_trait]
    impl SequencerService for MockSvc {
        async fn get_time(
            &self,
            _: Request<GetTimeRequest>,
        ) -> Result<Response<GetTimeResponse>, Status> {
            Ok(Response::new(GetTimeResponse {
                sequencing_timestamp: Some(*self.sequencer_time.lock().unwrap()),
            }))
        }
        async fn get_traffic_state_for_member(
            &self,
            _: Request<GetTrafficStateForMemberRequest>,
        ) -> Result<Response<GetTrafficStateForMemberResponse>, Status> {
            Err(Status::unimplemented("unused"))
        }
        async fn send_async(
            &self,
            _: Request<SendAsyncRequest>,
        ) -> Result<Response<SendAsyncResponse>, Status> {
            self.send_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_send_async.load(Ordering::SeqCst) {
                return Err(Status::unavailable("verdict send failed"));
            }
            Ok(Response::new(SendAsyncResponse {}))
        }
        type SubscribeStream = MockStream<SubscriptionResponse>;
        async fn subscribe(
            &self,
            _: Request<SubscriptionRequest>,
        ) -> Result<Response<Self::SubscribeStream>, Status> {
            if self.fail_subscribe.load(Ordering::SeqCst) {
                return Err(Status::unavailable("subscribe stream broken"));
            }
            let events: Vec<Result<SubscriptionResponse, Status>> =
                std::mem::take(&mut *self.queued_events.lock().unwrap())
                    .into_iter()
                    .map(|bytes| {
                        Ok(SubscriptionResponse {
                            signed_sequenced_event: bytes,
                            trace_context: None,
                        })
                    })
                    .collect();
            Ok(Response::new(Box::pin(tokio_stream::iter(events))))
        }
        async fn acknowledge_signed(
            &self,
            request: Request<AcknowledgeSignedRequest>,
        ) -> Result<Response<AcknowledgeSignedResponse>, Status> {
            if self.fail_ack.load(Ordering::SeqCst) {
                return Err(Status::unavailable("ack refused"));
            }
            let bytes = request.into_inner().signed_acknowledge_request;
            if let Some((content_bytes, _)) = tw::unversioned(&bytes) {
                if let Ok(sc) =
                    canton_proto::com::digitalasset::canton::protocol::v30::SignedContent::decode(
                        content_bytes.as_slice(),
                    )
                {
                    if let Some((ack_bytes, _)) = sc.content.as_deref().and_then(tw::unversioned) {
                        if let Ok(ack) = AcknowledgeRequest::decode(ack_bytes.as_slice()) {
                            self.ack_timestamps.lock().unwrap().push(ack.timestamp);
                        }
                    }
                }
            }
            Ok(Response::new(AcknowledgeSignedResponse {}))
        }
        type DownloadTopologyStateForInitStream = MockStream<DownloadTopologyStateForInitResponse>;
        async fn download_topology_state_for_init(
            &self,
            _: Request<DownloadTopologyStateForInitRequest>,
        ) -> Result<Response<Self::DownloadTopologyStateForInitStream>, Status> {
            Ok(Response::new(Box::pin(tokio_stream::empty())))
        }
        async fn download_topology_state_for_init_hash(
            &self,
            _: Request<DownloadTopologyStateForInitHashRequest>,
        ) -> Result<Response<DownloadTopologyStateForInitHashResponse>, Status> {
            Ok(Response::new(DownloadTopologyStateForInitHashResponse {
                topology_state_hash: Vec::new(),
            }))
        }
    }

    fn setup_loop() -> (Loop, Arc<MockSequencer>, Ed25519Key, String, String) {
        let mock = Arc::new(MockSequencer::default());
        *mock.sequencer_time.lock().unwrap() = 2_000_000_000;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let svc = MockSvc(Arc::clone(&mock));
        let _server = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(
                    tonic::transport::Server::builder()
                        .add_service(SequencerServiceServer::new(svc))
                        .serve(addr),
                )
        });
        let url = format!("http://{addr}");
        let mut client = None;
        for _ in 0..40 {
            if let Ok(c) = SequencerConnect::connect(&url) {
                client = Some(c);
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let client = client.expect("connect to mock sequencer");
        let keys = SynchronizerKeys::generate();
        let sync_uid = format!("sync::{}", keys.synchronizer_namespace());
        let physical = format!("{sync_uid}::37-0");
        let store = crate::synchronizer_state::TopologyStore::initial("sync", "seq", "med", &keys);
        let state: Vec<(i64, Vec<u8>)> = store
            .snapshot()
            .iter()
            .map(|e| (e.valid_from_micros, tw::stored_form(&e.signed)))
            .collect();
        let entries = decode(&state).unwrap();
        let sequencer_member = format!("SEQ::seq::{}", keys.namespace.fingerprint);
        let member = format!("MED::med::{}", keys.mediator_namespace.fingerprint);
        let med_key = keys.mediator_key(0);
        let med_uid = member.trim_start_matches("MED::").to_string();
        let tracker = Tracker::for_synchronizer(&entries, &med_uid, &physical).unwrap();
        let view = Arc::new(FollowedView {
            tracker: Mutex::new(tracker),
        });
        let signing = Arc::new(Ed25519Key::from_seed(med_key.seed()));
        let mediator = Mediator::with_view(
            0,
            physical.clone(),
            Arc::clone(&signing),
            Arc::clone(&view) as Arc<_>,
        );
        let own: Arc<dyn StateStore> = Arc::new(MemStore(Mutex::new(BTreeMap::new())));
        let mut l = Loop {
            client,
            token: canton_participant::sequencer_connect::Token {
                token: vec![1, 2, 3],
                expires_at_seconds: i64::MAX / 2,
            },
            physical: physical.clone(),
            member: member.clone(),
            signing,
            sequencer: sequencer_member,
            view,
            mediator,
            reader: Reader::new(100, &physical),
            persisted_cursor: 100,
            clock: TimeKeeper::new(Instant::now(), 100),
            silent_until: 0,
            own,
            state_key: "mediator-0.state".into(),
            topo_key: "mediator-0.topology.journal".into(),
            pending_topology: Vec::new(),
            subscribe_healthy: true,
            acknowledge_enabled: true,
            telemetry: Arc::new(MediatorTelemetry::default()),
        };
        l.clock.observed(Instant::now(), 100);
        (l, mock, keys.sequencer_signing, physical, member)
    }

    #[test]
    fn r13e_ack_send_failure_is_logged() {
        let (mut l, mock, _, _, _) = setup_loop();
        mock.fail_ack.store(true, Ordering::SeqCst);
        l.maybe_acknowledge();
        let err = l.telemetry.last_error.lock().unwrap().clone();
        assert!(
            err.as_deref().is_some_and(|e| e.contains("ack")),
            "ack failure must be recorded/logged instead of silently dropped, got: {err:?}"
        );
    }

    #[test]
    fn r13e_broken_subscription_skips_ack() {
        let (mut l, mock, _, _, _) = setup_loop();
        mock.fail_subscribe.store(true, Ordering::SeqCst);
        let _ = l.step();
        assert!(
            mock.ack_timestamps().is_empty(),
            "broken subscription must skip sending AcknowledgeSigned, sent: {:?}",
            mock.ack_timestamps()
        );
    }

    #[test]
    fn r13e_try_acknowledge_logs_failure_to_callback() {
        let mut clock = TimeKeeper::new(Instant::now(), 100);
        clock.observed(Instant::now(), 500);
        let mut logged = Vec::new();
        let res = try_acknowledge(
            &mut clock,
            AckInput {
                now: Instant::now(),
                cursor: 500,
                earliest_pending: None,
                healthy: true,
            },
            |_| Err("simulated rpc failure".to_string()),
            |msg| logged.push(msg.to_string()),
        );
        assert!(res.is_none());
        assert_eq!(logged, vec!["simulated rpc failure".to_string()]);
    }

    #[test]
    fn r13e_transient_verdict_send_failure_does_not_freeze_future_acks() {
        let (mut l, mock, seq_key, physical, _) = setup_loop();
        let group = canton_participant::confirmation_wire::mediator_group(0);
        let informee = tw::versioned(
            EnvelopeContent {
                some_envelope_content: Some(SomeEnvelopeContent::InformeeMessage(
                    Default::default(),
                )),
            }
            .encode_to_vec(),
            ENVELOPE_CONTENT_VERSION,
        );
        let root_hash_msg =
            canton_participant::confirmation_wire::root_hash_message(&[0; 34], &physical, 0);
        let ts = 10_000_000i64;
        let event = SequencedEvent {
            previous_timestamp: None,
            timestamp: ts,
            physical_synchronizer_id: physical.clone(),
            message_id: None,
            batch: Some(sw::compressed_batch_to_groups(&[
                (vec![group.clone()], informee.clone()),
                (
                    vec![group.clone(), "PAR::a::1220aa".to_string()],
                    root_hash_msg.clone(),
                ),
            ])),
            deliver_error_reason: None,
            topology_timestamp: None,
            traffic_receipt: None,
        };
        mock.queued_events
            .lock()
            .unwrap()
            .push(sw::signed_sequenced_event(&event, &seq_key));
        mock.fail_send_async.store(true, Ordering::SeqCst);
        let _ = l.step();
        mock.fail_send_async.store(false, Ordering::SeqCst);

        // Idle poll before any later keep() must NOT advance acks past persisted_cursor.
        let _ = l.step();
        let idle_acks = mock.ack_timestamps();
        assert!(
            idle_acks.iter().all(|&a| a < ts),
            "idle poll must not acknowledge unpersisted cursor >= {ts}, got: {idle_acks:?}"
        );

        // Once sending succeeds on a subsequent event and keep() persists ts2 (and the next ack window arrives), acks are not frozen below ts.
        l.clock = TimeKeeper::new(Instant::now(), l.persisted_cursor);
        let ts2 = 20_000_000i64;
        let event2 = SequencedEvent {
            previous_timestamp: Some(ts),
            timestamp: ts2,
            physical_synchronizer_id: physical,
            message_id: None,
            batch: Some(sw::compressed_batch_to_groups(&[
                (vec![group.clone()], informee),
                (vec![group, "PAR::a::1220aa".to_string()], root_hash_msg),
            ])),
            deliver_error_reason: None,
            topology_timestamp: None,
            traffic_receipt: None,
        };
        mock.queued_events
            .lock()
            .unwrap()
            .push(sw::signed_sequenced_event(&event2, &seq_key));
        l.step().expect("recovered send persists ts2");
        let _ = l.step();
        let acks = mock.ack_timestamps();
        assert!(
            acks.iter().any(|&a| a >= ts),
            "transient verdict send failure must not permanently freeze acks below {ts}, got: {acks:?}"
        );
    }

    #[test]
    fn idle_poll_does_not_ack_past_persisted_cursor_when_keep_skipped() {
        let (mut l, mock, seq_key, physical, _) = setup_loop();
        let group = canton_participant::confirmation_wire::mediator_group(0);
        let informee = tw::versioned(
            EnvelopeContent {
                some_envelope_content: Some(SomeEnvelopeContent::InformeeMessage(
                    Default::default(),
                )),
            }
            .encode_to_vec(),
            ENVELOPE_CONTENT_VERSION,
        );
        let root_hash_msg =
            canton_participant::confirmation_wire::root_hash_message(&[0; 34], &physical, 0);
        let ts1 = 10_000_000i64;
        let event1 = SequencedEvent {
            previous_timestamp: None,
            timestamp: ts1,
            physical_synchronizer_id: physical.clone(),
            message_id: None,
            batch: Some(sw::compressed_batch_to_groups(&[
                (vec![group.clone()], informee.clone()),
                (
                    vec![group.clone(), "PAR::a::1220aa".to_string()],
                    root_hash_msg.clone(),
                ),
            ])),
            deliver_error_reason: None,
            topology_timestamp: None,
            traffic_receipt: None,
        };
        mock.queued_events
            .lock()
            .unwrap()
            .push(sw::signed_sequenced_event(&event1, &seq_key));
        mock.fail_send_async.store(true, Ordering::SeqCst);
        let _ = l.step();
        mock.fail_send_async.store(false, Ordering::SeqCst);

        // Idle poll before any later event was kept must NOT ack unpersisted `ts1` (would let sequencer prune ahead of disk).
        let _ = l.step();
        let acks_before_keep = mock.ack_timestamps();
        assert!(
            acks_before_keep.iter().all(|&a| a < ts1),
            "idle poll must not acknowledge unpersisted cursor >= {ts1} while keep() was skipped; got: {acks_before_keep:?}"
        );

        // Once a later event succeeds and keep() persists (and the next ack window arrives), acknowledgements advance cleanly.
        l.clock = TimeKeeper::new(Instant::now(), l.persisted_cursor);
        let ts2 = 20_000_000i64;
        let event2 = SequencedEvent {
            previous_timestamp: Some(ts1),
            timestamp: ts2,
            physical_synchronizer_id: physical,
            message_id: None,
            batch: Some(sw::compressed_batch_to_groups(&[
                (vec![group.clone()], informee),
                (vec![group, "PAR::a::1220aa".to_string()], root_hash_msg),
            ])),
            deliver_error_reason: None,
            topology_timestamp: None,
            traffic_receipt: None,
        };
        mock.queued_events
            .lock()
            .unwrap()
            .push(sw::signed_sequenced_event(&event2, &seq_key));
        l.step().expect("second event succeeds and persists cursor");
        let _ = l.step();
        let acks_after_keep = mock.ack_timestamps();
        assert!(
            acks_after_keep.iter().any(|&a| a >= ts2),
            "after keep() persists {ts2}, acks must advance to >= {ts2}: {acks_after_keep:?}"
        );
    }

    #[test]
    fn mediator_topology_journal_roundtrips_and_deduplicates() {
        let store = MemStore(Mutex::new(BTreeMap::new()));
        let tx_a = b"stored-tx-alpha".to_vec();
        let tx_b = b"stored-tx-beta".to_vec();
        journal_mediator_topology(&store, "mediator-1.topology.journal", &tx_a).unwrap();
        journal_mediator_topology(&store, "mediator-1.topology.journal", &tx_a).unwrap();
        journal_mediator_topology(&store, "mediator-1.topology.journal", &tx_b).unwrap();
        journal_mediator_topology(&store, "mediator-1.topology.journal", &tx_a).unwrap();
        assert_eq!(
            load_mediator_topology_journal(&store, "mediator-1.topology.journal"),
            vec![tx_a, tx_b]
        );
    }
}
