use super::{
    contract_line, parse_dar_package_names, replay_contracts, replay_unassignments,
    split_qualified, stored_from, Board, LateFate, Node, ReassignmentDone,
};
use crate::participant_runtime::{Config, Runtime};
use crate::sequencer_connect::{SequencerConnect, Token};
use crate::state_store::{FileStore, StateStore};
use crate::submit::{Context, Peer, StoredContract};
use crate::topology_wire::{Ed25519Key, ParticipantIdentity};
use crate::view_acs::Timeouts;
use crate::view_conformance::{open_instance, Engine, OpenedContract};
use lf_eval::World;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a joining node waits for its boot packages' vetting to take effect in the topology it follows.
const BOOT_VETTING_TIMEOUT: Duration = Duration::from_secs(30);

impl Node {
    /// A node that continues from `start_cursor` (the sequencing time after which it reads events) on the synchronizer `physical`, running the
    /// package of `dar`. The topology is downloaded and followed.
    pub fn open(
        identity: ParticipantIdentity,
        client: SequencerConnect,
        token: Token,
        physical: &str,
        dar: &Path,
        start_cursor: i64,
    ) -> Result<Self, String> {
        Self::open_in(identity, client, token, physical, dar, start_cursor, None)
    }

    /// Like [`Node::open`], with the node's state kept in `state_dir` when given (see [`Node::open_with`]).
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn open_in(
        identity: ParticipantIdentity,
        client: SequencerConnect,
        token: Token,
        physical: &str,
        dar: &Path,
        start_cursor: i64,
        state_dir: Option<&Path>,
    ) -> Result<Self, String> {
        let store = match state_dir {
            Some(dir) => Some(FileStore::new(dir)? as Arc<dyn StateStore>),
            None => None,
        };
        Self::open_with(identity, client, token, physical, dar, start_cursor, store)
    }

    /// Like [`Node::open`], with the node's state kept in `store` when given (a directory or a database): the runtime's contract set, the cursor in
    /// the sequencer's events and the topology it followed (`Runtime::open_in`), and the contracts this node can exercise. A store that holds state
    /// continues where that state stopped (`start_cursor` is then not used).
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn open_with(
        identity: ParticipantIdentity,
        client: SequencerConnect,
        token: Token,
        physical: &str,
        dar: &Path,
        start_cursor: i64,
        store: Option<Arc<dyn StateStore>>,
    ) -> Result<Self, String> {
        Self::open_with_opt_dar(
            identity,
            client,
            token,
            physical,
            Some(dar),
            start_cursor,
            store,
        )
    }

    /// Like [`Node::open_with`], allowing `dar` to be `None` so a participant can join a synchronizer
    /// with an empty package store and accept DAR uploads dynamically (`M-001`).
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn open_with_opt_dar(
        identity: ParticipantIdentity,
        client: SequencerConnect,
        token: Token,
        physical: &str,
        dar: Option<&Path>,
        start_cursor: i64,
        store: Option<Arc<dyn StateStore>>,
    ) -> Result<Self, String> {
        let config = Config {
            member: identity.member(),
            encryption_fingerprint: identity.encryption_fingerprint(),
            encryption_secret: *identity.encryption_secret(),
            hosted_parties: Vec::new(),
            timeouts: Timeouts::default(),
            submitter_keys: Vec::new(),
            mediator_keys: Vec::new(),
            peer_encryption_keys: Default::default(),
            physical_synchronizer_id: physical.to_string(),
            follow_topology: true,
            topology_change_delay_micros: 250_000,
        };
        let (engine, world, boot_package_ids, package_names_by_id) = match dar {
            Some(dar_path) => {
                let engine = Engine::load(dar_path)?;
                let world = World::open(dar_path).map_err(|e| e.to_string())?;
                let boot_package_ids: BTreeSet<String> = world.package_ids().into_iter().collect();
                let mut package_names_by_id = BTreeMap::new();
                parse_dar_package_names(dar_path, &mut package_names_by_id)?;
                (engine, world, boot_package_ids, package_names_by_id)
            }
            None => (
                Engine::empty(),
                World::empty(),
                BTreeSet::new(),
                BTreeMap::new(),
            ),
        };
        // [CANTON-NOTE: SEMANTICS] The state is the state **of one synchronizer**: its cursor is a time of that synchronizer's events and its
        // contracts are the ones it judged. State kept for another synchronizer is refused rather than mixed with this one's.
        if let Some(store) = &store {
            match store.read("synchronizer")?.map(|t| t.trim().to_string()) {
                Some(kept) if kept != physical => {
                    return Err(format!(
                        "the state in the {} belongs to the synchronizer {kept}, not {physical}",
                        store.describe()
                    ))
                }
                Some(_) => {}
                None => store.write("synchronizer", &format!("{physical}\n"))?,
            }
        }
        // a sequencer that restarted keeps no tokens: the node authenticates again by itself when its token is refused
        let mut client = client;
        let auth_seed = identity.sequencer_auth_key.seed();
        client.set_reauth(
            &identity.member(),
            physical,
            Box::new(move |hash| Ed25519Key::from_seed(auth_seed).sign_bytes(hash)),
        );
        let mut runtime = Runtime::open_in(config, engine, store.clone(), start_cursor)?;
        runtime.trust_own_submissions(
            canton_algo::member_signature::own_ed25519_key(&identity.signing_key.spki_der)
                .map_err(|e| format!("the signing key is not an Ed25519 key: {e:?}"))?,
            &identity.uid(),
        );
        let mut node = Node {
            runtime,
            last_notes: Vec::new(),
            identity,
            client,
            token,
            physical: physical.to_string(),
            mediator_group: 0,
            user_id: "rust-user".to_string(),
            world,
            vetted_package_ids: boot_package_ids,
            package_names_by_id,
            contracts: BTreeMap::new(),
            unassigned: BTreeMap::new(),
            store: None,
            directory: BTreeMap::new(),
            board: Arc::new(Board::default()),
            most_in_flight: 0,
            remote: Vec::new(),
            late: Vec::new(),
            clock: crate::sequencer_time::TimeKeeper::new(Instant::now(), start_cursor),
        };
        if let Some(store) = store {
            node.contracts =
                replay_contracts(&store.read("contracts.journal")?.unwrap_or_default());
            node.unassigned =
                replay_unassignments(&store.read("unassigned.journal")?.unwrap_or_default());
            node.store = Some(store);
            node.reconcile_contracts();
        }
        node.clock = crate::sequencer_time::TimeKeeper::new(Instant::now(), node.runtime.cursor());
        // [CANTON-NOTE: SEMANTICS] The fates decided before a restart and not handed over yet are handed over now: nobody waits for them.
        // [CANTON-NOTE: SEMANTICS] P-13: an approval whose transaction was applied and not shown before the restart is handed over with it.
        let mut unshown: BTreeMap<i64, crate::view_acs::Applied> = node
            .runtime
            .unshown_applied()
            .into_iter()
            .map(|a| (a.request_id, a))
            .collect();
        for settled in node.runtime.in_flight.settled_unawaited() {
            let transaction = settled
                .request_id
                .and_then(|r| unshown.remove(&r))
                .map(|a| node.show(a));
            node.late.push(LateFate {
                settled,
                transaction,
            });
        }
        node.runtime.load_topology(&mut node.client, &node.token)?;
        // [CANTON-NOTE: SEMANTICS] Once this participant has published a `VettedPackages` mapping on this synchronizer
        // (`vetted_serial_of.is_some()`, including after a `REMOVE` where `vetted_packages_of` is `None`), topology state is
        // authoritative across restarts (U-61 review R1-F3). Replacing `vetted_package_ids` rather than unioning with
        // `boot_package_ids` ensures operator unvetting survives restart AND later `upload_and_vet_loaded_dar` calls.
        if node
            .runtime
            .vetted_serial_of(&node.identity.uid())
            .is_some()
        {
            node.vetted_package_ids = node
                .runtime
                .vetted_packages_of(&node.identity.uid())
                .unwrap_or_default();
        }
        // [CANTON-NOTE: INVARIANT] A node opening on a synchronizer for the first time (`vetted_serial_of == None`) publishes the
        // packages it was started with (U-61). Holding a package is not vetting it: every participant judges a request by the
        // `VettedPackages` the topology holds for its informee participants (`UsableSynchronizers.checkPackagesVetted`,
        // `ModelConformanceChecker`: `UnvettedPackages`). A restart never alters operator-managed vetting (U-61 C3).
        // [CANTON-NOTE: LIMITATION] Unlike official Canton, `Node::open_with` waits up to `BOOT_VETTING_TIMEOUT` for the first-join
        // vetting transaction to become effective in topology state and returns `Err` on timeout (fail-closed).
        if node.runtime.topology().is_some() {
            node.vet_loaded_packages(BOOT_VETTING_TIMEOUT)?;
        }
        Ok(node)
    }

    /// Adds a contract this node can exercise (and keeps it, when the node has a state directory).
    pub(super) fn remember(&mut self, stored: StoredContract) {
        if let Some(store) = &self.store {
            let _ = store.append("contracts.journal", &contract_line(&stored));
        }
        self.contracts
            .insert(stored.contract_id_hex.clone(), stored);
    }

    /// Makes a contract that was created elsewhere (on an official participant's database: `--official-pg-url`) one this node can exercise. It is not written
    /// to the node's journal: the official database is read again at every start.
    ///
    /// [CANTON-NOTE: SEMANTICS] The node judges a view that exercises the contract by the instance it holds, with the salt the contract was created with, so
    /// the contract id's authentication (`Unicum`) is checked as for any contract; the synchronizer never saw its creation, which a Canton synchronizer
    /// does not need to (a contract can arrive by an assignment).
    pub fn adopt_instance(&mut self, instance: &[u8]) -> Result<(), String> {
        let opened = open_instance(&self.runtime.engine, instance)?;
        self.contracts
            .entry(opened.contract_id.clone())
            .or_insert_with(|| stored_from(&opened, instance));
        Ok(())
    }

    /// Keeps an approved unassignment until its assignment is approved (and across a restart of the node).
    pub(super) fn remember_unassignment(&mut self, done: &ReassignmentDone, target: &str) {
        if let Some(store) = &self.store {
            let _ = store.append(
                "unassigned.journal",
                &format!(
                    "+\t{}\t{}\t{}\t{}\t{}\t{}",
                    done.reassignment_id,
                    self.physical,
                    target,
                    done.request_id.map(|t| t.to_string()).unwrap_or_default(),
                    done.counter,
                    hex::encode(&done.instance)
                ),
            );
        }
        self.unassigned.insert(
            done.reassignment_id.clone(),
            (done.clone(), self.physical.clone(), target.to_string()),
        );
    }

    /// The assignment of `reassignment_id` was approved on the target: the unassignment is no longer pending.
    pub fn forget_unassignment(&mut self, reassignment_id: &str) {
        if self.unassigned.remove(reassignment_id).is_some() {
            if let Some(store) = &self.store {
                let _ = store.append("unassigned.journal", &format!("-\t{reassignment_id}"));
            }
        }
    }

    /// The unassignments this node submitted that no assignment has completed (kept across a restart): each with this node's synchronizer (the
    /// source) and the synchronizer it was unassigned to (the target).
    pub fn pending_unassignments(&self) -> Vec<(ReassignmentDone, String, String)> {
        self.unassigned.values().cloned().collect()
    }

    /// Drops a contract that was consumed.
    pub(super) fn forget(&mut self, id: &str) {
        if self.contracts.remove(id).is_some() {
            if let Some(store) = &self.store {
                let _ = store.append("contracts.journal", &format!("-\t{id}"));
            }
        }
    }

    /// The serialized instance of a contract this node created or was told of (as its views carry it), by hex contract id.
    pub fn instance_bytes(&self, contract_id_hex: &str) -> Option<Vec<u8>> {
        self.contracts
            .get(contract_id_hex)
            .map(|c| c.instance.clone())
    }

    /// The contracts this node knows to be active, read for display: what a service rebuilds its view from after a restart.
    pub fn known_contracts(&self) -> Vec<OpenedContract> {
        self.contracts
            .values()
            .filter_map(|c| open_instance(&self.runtime.engine, &c.instance).ok())
            .collect()
    }

    /// A node with new keys named `name` that registers with the synchronizer behind the sequencer at `url`, authenticates, waits for its
    /// registration to be broadcast and opens from there. The synchronizer's uid is the physical id without its protocol suffix.
    pub fn connect(url: &str, name: &str, dar: &Path) -> Result<Self, String> {
        Self::connect_in(url, name, dar, None)
    }

    /// Like [`Node::connect`], with the node's state kept in `state_dir` (see [`Node::open_in`]).
    ///
    /// [CANTON-NOTE: SEMANTICS] The identity is kept in `state_dir/identity`: a process that is started again with the same directory is the **same
    /// participant**: it authenticates with its old keys (the synchronizer already knows it, so it does not register again) and continues from
    /// the state the directory holds. A directory without an identity starts a new participant.
    pub fn connect_in(
        url: &str,
        name: &str,
        dar: &Path,
        state_dir: Option<&Path>,
    ) -> Result<Self, String> {
        let store = match state_dir {
            Some(dir) => Some(FileStore::new(dir)? as Arc<dyn StateStore>),
            None => None,
        };
        Self::connect_with(url, name, dar, store)
    }

    /// Like [`Node::connect`], with the node's state (and its identity) kept in `store`, a directory or a database.
    pub fn connect_with(
        url: &str,
        name: &str,
        dar: &Path,
        store: Option<Arc<dyn StateStore>>,
    ) -> Result<Self, String> {
        Self::connect_with_opt_dar(url, name, Some(dar), store)
    }

    /// Like [`Node::connect_with`], allowing `dar` to be `None` for zero-DAR participant boot (`M-001`).
    pub fn connect_with_opt_dar(
        url: &str,
        name: &str,
        dar: Option<&Path>,
        store: Option<Arc<dyn StateStore>>,
    ) -> Result<Self, String> {
        let (identity, restored) = match &store {
            Some(store) => {
                let kept = store
                    .read("identity")?
                    .and_then(|t| ParticipantIdentity::from_text(&t));
                match kept {
                    Some(identity) => (identity, true),
                    None => {
                        let identity = ParticipantIdentity::generate(name);
                        if !store.create_new("identity", &identity.to_text())? {
                            return Err(format!(
                                "the identity kept in the {} is damaged",
                                store.describe()
                            ));
                        }
                        (identity, false)
                    }
                }
            }
            None => (ParticipantIdentity::generate(name), false),
        };
        Self::connect_as_opt_dar(identity, restored, url, dar, store)
    }

    /// Joins the synchronizer at `url` as `identity` (`restored`: the identity was a member before, it may already be registered there) and
    /// opens a node with its state in `store`. One identity can join several synchronizers, one node each ([`crate::multi_node`]).
    pub fn connect_as(
        identity: ParticipantIdentity,
        restored: bool,
        url: &str,
        dar: &Path,
        store: Option<Arc<dyn StateStore>>,
    ) -> Result<Self, String> {
        Self::connect_as_opt_dar(identity, restored, url, Some(dar), store)
    }

    /// Like [`Node::connect_as`], allowing `dar` to be `None` for zero-DAR participant boot (`M-001`).
    pub fn connect_as_opt_dar(
        identity: ParticipantIdentity,
        restored: bool,
        url: &str,
        dar: Option<&Path>,
        store: Option<Arc<dyn StateStore>>,
    ) -> Result<Self, String> {
        use crate::sequencer_connect::AuthKey;
        let mut client = SequencerConnect::connect(url).map_err(|e| e.to_string())?;
        let synchronizer = client.synchronizer_id().map_err(|e| e.to_string())?;
        // the crypto handshake comes before the participant tells the synchronizer who it is (`GrpcSynchronizerRegistry`)
        let required = client.required_schemes().map_err(|e| e.to_string())?;
        crate::crypto_handshake::validate(&required)?;
        let physical = synchronizer.physical_synchronizer_id;
        let uid = physical
            .rsplit_once("::")
            .map(|(uid, _)| uid.to_string())
            .ok_or_else(|| format!("not a physical synchronizer id: {physical}"))?;
        // an identity that was kept is a member already; a synchronizer that does not know it (a new one) is told who it is
        let known = restored && client.challenge(&identity.member(), &[37]).is_ok();
        if !known {
            client
                .register_onboarding(
                    &identity.member(),
                    &physical,
                    identity.onboarding_transactions(&uid),
                )
                .map_err(|e| e.to_string())?;
        }
        // [CANTON-NOTE: SEMANTICS] The registration is processed by the synchronizer after the call returns: until then the sequencer answers a
        // challenge with "access is disabled". The official synchronizer needs a moment (measured: the tests of `sequencer_connect.rs` ask for
        // the challenge again every half second for up to 30 seconds); the Rust one is instant.
        let mut challenge = None;
        let mut last = String::new();
        for _ in 0..60 {
            match client.challenge(&identity.member(), &[37]) {
                Ok(c) => {
                    challenge = Some(c);
                    break;
                }
                Err(e) => {
                    last = e.to_string();
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
        let challenge =
            challenge.ok_or_else(|| format!("the member never became a member: {last}"))?;
        let signature = identity.sequencer_auth_key.sign_bytes(
            &AuthKey::challenge_hash(&challenge.nonce, &physical)
                .map_err(|e| format!("the challenge hash: {e:?}"))?,
        );
        let token = client
            .authenticate(&identity.member(), &challenge.nonce, signature)
            .map_err(|e| e.to_string())?;
        // [CANTON-NOTE: SEMANTICS] The node reads on from the sequencer's current time: the official sequencer cannot serve a subscription from at or
        // before the member's registration (`EventsUnavailableForTimestamp`, measured), so the registration's own events are not read; what
        // they changed is in the topology state the node downloads when it opens.
        let cursor = client
            .sequencer_time(&identity.member(), &physical, Some(&token))
            .map_err(|e| e.to_string())?
            .unwrap_or(-1);
        Node::open_with_opt_dar(identity, client, token, &physical, dar, cursor, store)
    }

    /// The participant that hosts `party` when it is not this one (its member id and encryption key).
    pub fn add_peer(&mut self, party: &str, peer: Peer) {
        self.directory.insert(party.to_string(), peer);
    }

    /// The parties this node hosts, as the topology says.
    pub fn hosted(&self) -> &[String] {
        &self.runtime.config.hosted_parties
    }

    /// Whether this node's view of the ledger has the contract active.
    pub fn is_active(&self, contract_id_hex: &str) -> bool {
        self.runtime.ledger.is_active(contract_id_hex)
    }

    pub(super) fn me(&self) -> Peer {
        Peer {
            member: self.identity.member(),
            encryption_spki: self.identity.encryption_spki().to_vec(),
            fingerprint: self.identity.encryption_fingerprint(),
        }
    }

    /// The participants that must receive a request about `parties`: the node itself for those it hosts, the directory for the rest.
    /// The participants that host `party`, with their encryption keys (the submitter itself for a party it hosts).
    pub(super) fn peers_of_party(&self, party: &String) -> Result<Vec<Peer>, String> {
        let me = self.identity.member();
        let mut found: Vec<Peer> = if self.runtime.config.hosted_parties.contains(party) {
            vec![self.me()]
        } else if let Some(peer) = self.directory.get(party) {
            vec![peer.clone()]
        } else {
            Vec::new()
        };
        // [CANTON-NOTE: SEMANTICS] The participants that host a party are found in the topology the node follows, with their encryption
        // keys. Every host receives the request, whatever its permission, because an observing participant has to learn the contract as
        // well. That holds for a party this node hosts **together with another participant** too: a view's recipients are every active
        // participant of its informees (`Witnesses.toRecipients` → `activeParticipantsOfParties`; `RecipientsValidator` checks the same),
        // so the co-host receives the view and confirms its share of the party (S-G11-001: p1 confirms JSON API transactions this way).
        for (member, _, key) in self.runtime.hosts_of(party) {
            if member == me || found.iter().any(|p| p.member == member) {
                continue;
            }
            if let Some(k) = key {
                found.push(Peer {
                    member,
                    encryption_spki: k.spki,
                    fingerprint: k.fingerprint,
                });
            }
        }
        if found.is_empty() {
            return Err(format!("no participant is known to host {party}"));
        }
        Ok(found)
    }

    /// Refuses to submit for `act_as` unless this participant may ([`crate::routing::check_submitters`]).
    ///
    /// [CANTON-NOTE: LIMITATION] A node that follows no topology (configured by hand) does not know the hosting and lets it through.
    /// Canton leaves the parties that signed externally out of this check (`TransactionRoutingProcessor`: `actAs` minus the external
    /// signatures' parties); a node sends no external authorization, so a party hosted here without submission permission is refused.
    pub(super) fn check_submitters(&self, act_as: &[String]) -> Result<(), String> {
        match self.runtime.topology() {
            Some(tracker) => crate::routing::check_submitters(act_as, &self.identity.uid(), &|p| {
                tracker.hosts_of(p)
            }),
            None if self.runtime.config.follow_topology => Err(
                "topology tracking is enabled (follow_topology=true) but topology state has not been loaded"
                    .to_string(),
            ),
            None => Ok(()),
        }
    }

    pub(super) fn hosts_of(&self, parties: &[String]) -> Result<Vec<Peer>, String> {
        let mut hosts: Vec<Peer> = Vec::new();
        for party in parties {
            for peer in self.peers_of_party(party)? {
                if !hosts.iter().any(|h| h.member == peer.member) {
                    hosts.push(peer);
                }
            }
        }
        // the submitter always receives its own request: its admin party has to confirm it
        if !hosts.iter().any(|h| h.member == self.identity.member()) {
            hosts.push(self.me());
        }
        Ok(hosts)
    }

    pub(super) fn context(&self) -> Context<'_> {
        Context {
            identity: &self.identity,
            synchronizer: &self.physical,
            mediator_group: self.mediator_group,
            user_id: &self.user_id,
        }
    }

    pub(super) fn now(&mut self) -> Result<i64, String> {
        // During BFT epoch 0 blocks 0..N-1 (before any canonical commit set carries a wall-clock timestamp), wait briefly for wall-clock BFT time so `max_sequencing_time` is valid.
        for _ in 0..200 {
            if let Some(t) = self
                .client
                .sequencer_time(&self.identity.member(), &self.physical, Some(&self.token))
                .map_err(|e| e.to_string())?
            {
                if t >= 1_000_000_000 {
                    return Ok(t);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err("the sequencer reports no wall-clock time".to_string())
    }

    /// The sequencer's current time (microseconds).
    pub fn current_time(&mut self) -> Result<i64, String> {
        self.now()
    }

    /// Sends the requests built from now on to mediator group `group` (0 unless set).
    pub fn use_mediator_group(&mut self, group: u32) {
        self.mediator_group = group;
    }

    /// Returns the known package name for `package_id` (populated from boot and uploaded DARs).
    pub fn package_name_of(&self, package_id: &str) -> Option<&str> {
        self.package_names_by_id.get(package_id).map(String::as_str)
    }

    pub(super) fn resolve_template<'a>(
        &self,
        template: &'a str,
    ) -> Result<(String, &'a str, &'a str), String> {
        let (hint, module, name) = split_qualified(template)?;
        let package_id = match hint {
            Some(pkg) => {
                if !self.world.has_package(pkg) {
                    return Err(format!("unknown package id {pkg}"));
                }
                pkg.to_string()
            }
            None => self
                .world
                .template_package(None, module, name)
                .ok_or_else(|| format!("unknown template {module}:{name}"))?,
        };
        Ok((package_id, module, name))
    }
}
