use super::{register_loaded_dar_package_names, Node};
use crate::submit::{Os, Peer, Randomness};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

impl Node {
    pub(super) fn check_peers_vetted(
        &mut self,
        package_id: &str,
        peers: &[Peer],
        ledger_time_micros: i64,
    ) -> Result<(), String> {
        // [CANTON-NOTE: SEMANTICS] every participant that hosts an informee, this one included, must have the package vetted in the
        // topology snapshot at `ledger_time_micros` (`UsableSynchronizers.checkPackagesVetted`: `PackageUnknownTo(package, participant)`).
        // A participant without a `VettedPackages` mapping has vetted nothing, and a package this node merely holds is not vetted until
        // the topology says so (U-61, U-61-R1 F5).
        // a runtime configured by hand (`follow_topology: false`) follows no topology: there is nothing to judge vetting by;
        // a runtime configured with `follow_topology: true` whose topology was never loaded fails closed (Group B audit).
        if self.runtime.topology().is_none() {
            if self.runtime.config.follow_topology {
                return Err(
                    "topology tracking is enabled (follow_topology=true) but topology state has not been loaded"
                        .to_string(),
                );
            }
            return Ok(());
        }
        let unvetted = |this: &Self| -> Option<String> {
            for peer in peers {
                let uid = peer.member.strip_prefix("PAR::").unwrap_or(&peer.member);
                let ok = this
                    .runtime
                    .vetted_packages_of_at(uid, ledger_time_micros)
                    .is_some_and(|set| set.contains(package_id));
                if !ok {
                    return Some(uid.to_string());
                }
            }
            None
        };
        if unvetted(self).is_some() {
            let _ = self.poll_slice(Duration::from_millis(20));
        }
        if let Some(uid) = unvetted(self) {
            return Err(format!(
                "PACKAGE_NOT_VETTED_BY_RECIPIENTS: participant {uid} has not vetted package {package_id}"
            ));
        }
        Ok(())
    }

    /// Broadcasts the participant's current `vetted_package_ids` as a signed `VettedPackages`
    /// topology transaction and waits until `self.runtime` reflects the exact set.
    #[allow(
        deprecated,
        reason = "populates legacy/deprecated Canton protobuf or pinned crypto fields for wire compatibility"
    )]
    pub(super) fn broadcast_vetted_packages(&mut self, timeout: Duration) -> Result<(), String> {
        use canton_proto::com::digitalasset::canton::protocol::v30::vetted_packages::VettedPackage;
        use canton_proto::com::digitalasset::canton::protocol::v30::VettedPackages;
        use canton_proto::com::digitalasset::canton::protocol::v31;
        use prost::Message;

        let next_serial = self
            .runtime
            .vetted_serial_of(&self.identity.uid())
            .map_or(1, |s| s + 1);
        let tx = v31::TopologyTransaction {
            operation: 1,
            serial: next_serial,
            mapping: Some(v31::TopologyMapping {
                mapping: Some(v31::topology_mapping::Mapping::VettedPackages(
                    VettedPackages {
                        participant_uid: self.identity.uid(),
                        package_ids: Vec::new(),
                        packages: self
                            .vetted_package_ids
                            .iter()
                            .map(|id| VettedPackage {
                                package_id: id.clone(),
                                valid_from_inclusive: None,
                                valid_until_exclusive: None,
                            })
                            .collect(),
                    },
                )),
            }),
        };
        let tx_bytes = crate::topology_wire::versioned(
            tx.encode_to_vec(),
            crate::topology_wire::TOPOLOGY_TRANSACTION_VERSION,
        );
        let vetting = crate::topology_wire::signed(
            tx_bytes.clone(),
            vec![self.identity.namespace_key.sign_transaction(&tx_bytes)],
        );
        let max_sequencing_time = self.now()? + 60_000_000;
        let request = crate::sequencing_wire::submission_request_to_groups(
            &self.identity.member(),
            &format!("vetting-{}", hex::encode(&Os.fresh("vetting")[..6])),
            &[(
                vec![crate::topology_wire::ALL_MEMBERS.to_string()],
                crate::topology_wire::topology_broadcast(&self.physical, &[vetting]),
            )],
            max_sequencing_time,
        );
        self.client
            .send_async(
                &self.identity.member(),
                &self.physical,
                &self.token,
                self.runtime.pay(
                    crate::sequencing_wire::signed_submission_request(
                        request,
                        &self.identity.signing_key,
                    ),
                    &self.identity.signing_key,
                ),
            )
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + timeout;
        while self
            .runtime
            .vetted_packages_of(&self.identity.uid())
            .as_ref()
            != Some(&self.vetted_package_ids)
        {
            if Instant::now() >= deadline {
                return Err(format!(
                    "the topology did not reflect vetted packages {:?} within {timeout:?}",
                    self.vetted_package_ids
                ));
            }
            self.poll_slice(Duration::from_millis(200))?;
        }
        Ok(())
    }

    /// Replaces the participant's vetted package set and broadcasts the updated `VettedPackages` topology transaction.
    pub fn sync_vetted_packages(
        &mut self,
        vetted_ids: &[String],
        timeout: Duration,
    ) -> Result<(), String> {
        let next: BTreeSet<String> = vetted_ids.iter().cloned().collect();
        if self.vetted_package_ids == next
            && self
                .runtime
                .vetted_packages_of(&self.identity.uid())
                .as_ref()
                == Some(&next)
        {
            return Ok(());
        }
        self.vetted_package_ids = next;
        self.broadcast_vetted_packages(timeout)
    }

    /// Broadcasts boot `VettedPackages` only on first join when this participant has never published a `VettedPackages` mapping on this
    /// synchronizer (`vetted_serial_of == None`, `R-6b`, U-61 review R1-F3). A restart preserves operator unvetting/revocation.
    pub fn vet_loaded_packages(&mut self, timeout: Duration) -> Result<(), String> {
        // [CANTON-NOTE: SEMANTICS] A zero-DAR participant starts with an empty package store and
        // publishes `VettedPackages` once its first DAR is uploaded (matching Canton 3.7.2).
        if self.vetted_package_ids.is_empty() {
            return Ok(());
        }
        if self
            .runtime
            .vetted_serial_of(&self.identity.uid())
            .is_some()
        {
            return Ok(());
        }
        self.broadcast_vetted_packages(timeout)
    }

    /// Returns the stored summary of an approved unassignment targeting this node's synchronizer (`P-14`, U-60 C1/F4).
    pub fn stored_unassignment(
        &self,
        reassignment_id: &str,
    ) -> Option<crate::reassignment_receive::StoredUnassignment> {
        self.runtime.known_unassignment(reassignment_id)
    }

    /// Makes this node one of a participant's nodes that share `shared` (see [`crate::participant_runtime::SharedUnassignments`]).
    pub fn share_unassignments(&mut self, shared: crate::participant_runtime::SharedUnassignments) {
        self.runtime.share_unassignments(shared);
    }

    /// Records a stored unassignment from the source synchronizer node for cross-checking an assignment (`R-6e`).
    pub fn remember_stored_unassignment(
        &mut self,
        reassignment_id: String,
        unassignment: crate::reassignment_receive::StoredUnassignment,
    ) -> Result<(), String> {
        self.runtime
            .remember_unassignment(reassignment_id, unassignment)
    }

    /// Loads packages from `dar` into this participant's engine and broadcasts a signed `VettedPackages`
    /// topology transaction, waiting until the update is effective in topology state.
    pub fn upload_and_vet_dar(
        &mut self,
        dar: &Path,
        timeout: Duration,
    ) -> Result<Vec<String>, String> {
        let loaded = lf_archive::load_dar_file(dar).map_err(|e| e.to_string())?;
        self.upload_and_vet_loaded_dar(&loaded, timeout)
    }

    /// Loads packages from a pre-parsed [`lf_archive::LoadedDar`] into this participant's engine
    /// and broadcasts a signed `VettedPackages` topology transaction if any package is not yet vetted.
    pub fn upload_and_vet_loaded_dar(
        &mut self,
        loaded: &lf_archive::LoadedDar,
        timeout: Duration,
    ) -> Result<Vec<String>, String> {
        register_loaded_dar_package_names(&loaded.archive, &mut self.package_names_by_id);
        let ids = self.world.add_loaded_dar(loaded);
        self.runtime.engine.add_loaded_dar(loaded);
        self.vetted_package_ids.extend(ids.iter().cloned());
        if self
            .runtime
            .vetted_packages_of(&self.identity.uid())
            .is_some_and(|cur| ids.iter().all(|id| cur.contains(id)))
        {
            return Ok(ids);
        }
        self.broadcast_vetted_packages(timeout)?;
        Ok(ids)
    }

    /// Makes this node host the party `name` (its own party in this participant's namespace) and waits until the topology says so. Returns the
    /// party's id.
    pub fn host_party(&mut self, name: &str, timeout: Duration) -> Result<String, String> {
        let party = self.identity.party_id(name);
        if self.runtime.config.hosted_parties.contains(&party) {
            return Ok(party);
        }
        let hosting = self.identity.party_hosting_transaction(name);
        self.broadcast_topology(&format!("hosting-{name}"), hosting)?;
        self.wait_until_hosted(&party, timeout)?;
        Ok(party)
    }

    /// Makes this node host its party `name` **together with** the participant `other_uid` (this node with submission permission, the other
    /// with confirmation, threshold 1) and waits until the topology says so. Returns the party's id.
    ///
    /// [CANTON-NOTE: SEMANTICS] Adding a participant of another namespace needs that namespace's signature: the transaction is broadcast as a
    /// **proposal** signed by this node, `co_sign` is handed its hash (the other participant's operator authorizes it, e.g. with
    /// `topology.transactions.authorize` on the official console) and the synchronizer stores it once both signatures are in.
    pub fn host_shared_party(
        &mut self,
        name: &str,
        other_uid: &str,
        co_sign: &mut dyn FnMut(&[u8]),
        timeout: Duration,
    ) -> Result<String, String> {
        let party = self.identity.party_id(name);
        if self.runtime.config.hosted_parties.contains(&party) {
            return Ok(party);
        }
        let proposal = self.identity.shared_party_proposal(name, other_uid);
        let hash = crate::topology_wire::transaction_hash(&proposal.transaction);
        self.broadcast_topology(&format!("shared-{name}"), proposal)?;
        co_sign(&hash);
        self.wait_until_hosted(&party, timeout)?;
        Ok(party)
    }

    /// Changes the hosts of this node's party `name` to `hosts` (`(participant uid, permission)`: 1 submission, 2 confirmation, 3 observation),
    /// threshold 1, as the transaction after the one in force (`serial`), and waits until the topology names exactly those hosts. A host of
    /// another namespace co-signs through `co_sign` (see [`Node::host_shared_party`]).
    pub fn rehost_party(
        &mut self,
        name: &str,
        hosts: &[(&str, i32)],
        serial: u32,
        co_sign: &mut dyn FnMut(&[u8]),
        timeout: Duration,
    ) -> Result<String, String> {
        let party = self.identity.party_id(name);
        let bytes = crate::topology_wire::party_to_participant_at_serial(&party, hosts, 1, serial);
        let proposal = crate::topology_wire::signed_proposal(
            bytes.clone(),
            vec![self.identity.namespace_key.sign_transaction(&bytes)],
        );
        let hash = crate::topology_wire::transaction_hash(&proposal.transaction);
        self.broadcast_topology(&format!("rehost-{name}"), proposal)?;
        co_sign(&hash);
        let wanted: BTreeSet<String> = hosts.iter().map(|(uid, _)| format!("PAR::{uid}")).collect();
        let deadline = Instant::now() + timeout;
        loop {
            let now: BTreeSet<String> = self
                .runtime
                .hosts_of(&party)
                .into_iter()
                .map(|(member, _, _)| member)
                .collect();
            if now == wanted {
                return Ok(party);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "the topology did not re-host {party} on {wanted:?} within {timeout:?} (now {now:?})"
                ));
            }
            self.poll_slice(Duration::from_millis(300))?;
        }
    }

    /// Sends a topology transaction to every member of the synchronizer.
    pub(super) fn broadcast_topology(
        &mut self,
        label: &str,
        transaction: canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction,
    ) -> Result<(), String> {
        // [CANTON-NOTE: SEMANTICS] The official sequencer refuses a maximum sequencing time past the timestamps it can represent: one minute ahead.
        let max_sequencing_time = self.now()? + 60_000_000;
        let request = crate::sequencing_wire::submission_request_to_groups(
            &self.identity.member(),
            &format!("{label}-{}", hex::encode(&Os.fresh("hosting")[..6])),
            &[(
                vec![crate::topology_wire::ALL_MEMBERS.to_string()],
                crate::topology_wire::topology_broadcast(&self.physical, &[transaction]),
            )],
            max_sequencing_time,
        );
        self.client
            .send_async(
                &self.identity.member(),
                &self.physical,
                &self.token,
                self.runtime.pay(
                    crate::sequencing_wire::signed_submission_request(
                        request,
                        &self.identity.signing_key,
                    ),
                    &self.identity.signing_key,
                ),
            )
            .map_err(|e| e.to_string())
    }

    /// Reads events until the topology says this node hosts `party`.
    pub(super) fn wait_until_hosted(
        &mut self,
        party: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let party = party.to_string();
        let deadline = Instant::now() + timeout;
        while !self.runtime.config.hosted_parties.contains(&party) {
            if Instant::now() >= deadline {
                return Err(format!(
                    "the topology did not say that this node hosts {party} within {timeout:?}"
                ));
            }
            // through `poll_slice`, not `Runtime::poll`: a verdict read here belongs to a request that is waiting
            self.poll_slice(Duration::from_millis(300))?;
        }
        Ok(())
    }

    /// The physical synchronizer id this node is connected to.
    pub fn physical_synchronizer_id(&self) -> &str {
        &self.physical
    }

    /// The participants (uids) that host one of `parties` here, by the topology this node follows (this node included when it hosts one).
    pub fn hosting_participants(&self, parties: &[String]) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for party in parties {
            if self.runtime.config.hosted_parties.contains(party) {
                out.insert(self.identity.uid());
            }
            for (member, _, _) in self.runtime.hosts_of(party) {
                out.insert(member.trim_start_matches("PAR::").to_string());
            }
        }
        out
    }

    /// Whether `party` is active on this node's synchronizer: some participant hosts it there.
    pub fn party_is_active(&self, party: &str) -> bool {
        self.runtime
            .config
            .hosted_parties
            .iter()
            .any(|p| p == party)
            || !self.runtime.hosts_of(party).is_empty()
    }

    /// This node's participant as a synchronizer member (`PAR::<name>::<fingerprint>`).
    pub fn identity_member(&self) -> String {
        self.identity.member()
    }

    /// Whether this node's participant has vetted `package_id` on its synchronizer, as the topology says (holding the package, or
    /// meaning to vet it, is not having vetted it: U-61).
    pub fn has_vetted(&self, package_id: &str) -> bool {
        self.runtime
            .vetted_packages_of(&self.identity.uid())
            .is_some_and(|set| set.contains(package_id))
    }
}

#[cfg(test)]
mod tests {
    use super::Node;
    use crate::node::{parse_dar_package_names, Board};
    use crate::participant_runtime::{Config, Runtime};
    use crate::sequencer_connect::{SequencerConnect, Token};
    use crate::sequencer_time::TimeKeeper;
    use crate::submit::Peer;
    use crate::topology_wire::ParticipantIdentity;
    use crate::view_acs::Timeouts;
    use crate::view_conformance::Engine;
    use lf_eval::World;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;
    use std::time::Instant;

    /// U-61 review R1-F2 (C2): `check_peers_vetted` checks this node itself against the topology snapshot rather than skipping self or
    /// trusting local `vetted_package_ids`. Reintroducing the old `if peer.member == this.identity.member() { continue; }` shortcut breaks
    /// this test even when boot vetting is otherwise published.
    #[test]
    fn check_peers_vetted_refuses_self_when_topology_has_no_vetted_packages_for_self() {
        let dar = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        let identity = ParticipantIdentity::generate("u61-c2-unit");
        let alice = format!("alice::{}", identity.namespace());
        let physical = "sync::1220aa::37-0".to_string();
        let engine = Engine::load(&dar).expect("load sample dar");
        let world = World::open(&dar).expect("open sample world");
        let boot_package_ids: BTreeSet<String> = world.package_ids().into_iter().collect();
        let main_pkg = world.main_package_id().to_string();
        let mut package_names_by_id = BTreeMap::new();
        parse_dar_package_names(&dar, &mut package_names_by_id).expect("parse package names");
        let config = Config {
            member: identity.member(),
            encryption_fingerprint: identity.encryption_fingerprint(),
            encryption_secret: *identity.encryption_secret(),
            hosted_parties: vec![alice],
            timeouts: Timeouts::default(),
            submitter_keys: Vec::new(),
            mediator_keys: Vec::new(),
            peer_encryption_keys: Default::default(),
            physical_synchronizer_id: physical.clone(),
            follow_topology: true,
            topology_change_delay_micros: 250_000,
        };
        let mut runtime = Runtime::open_in(config, engine, None, 0).expect("open runtime");
        runtime
            .load_topology_state(&[])
            .expect("load empty topology state");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind dummy port");
        let port = listener.local_addr().expect("local addr").port();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let accept_thread = std::thread::spawn(move || {
            let stream = listener.accept().ok();
            let _ = done_rx.recv();
            drop(stream);
        });
        let client =
            SequencerConnect::connect(&format!("http://127.0.0.1:{port}")).expect("lazy connect");
        let _ = done_tx.send(());
        let _ = accept_thread.join();
        let token = Token {
            token: vec![1],
            expires_at_seconds: i64::MAX,
        };
        let self_member = identity.member();
        let self_uid = identity.uid();
        let self_fp = identity.encryption_fingerprint();
        let mut node = Node {
            runtime,
            last_notes: Vec::new(),
            identity,
            client,
            token,
            physical,
            mediator_group: 0,
            user_id: "u-u61-c2".to_string(),
            world,
            vetted_package_ids: boot_package_ids,
            package_names_by_id,
            contracts: BTreeMap::new(),
            unassigned: BTreeMap::new(),
            store: None,
            directory: BTreeMap::new(),
            board: std::sync::Arc::new(Board::default()),
            most_in_flight: 0,
            remote: Vec::new(),
            late: Vec::new(),
            clock: TimeKeeper::new(Instant::now(), 0),
        };
        assert!(
            node.runtime.topology().is_some(),
            "follow_topology=true runtime has a topology tracker"
        );
        assert!(
            !node.has_vetted(&main_pkg),
            "holding boot packages locally must not count as vetted before topology confirms it"
        );
        let self_peer = Peer {
            member: self_member,
            encryption_spki: Vec::new(),
            fingerprint: self_fp,
        };
        let refused = node
            .check_peers_vetted(&main_pkg, &[self_peer], 1_000_000)
            .expect_err("self without topology VettedPackages must be refused");
        assert!(
            refused.contains("PACKAGE_NOT_VETTED_BY_RECIPIENTS")
                && refused.contains(&self_uid)
                && refused.contains(&main_pkg),
            "expected PACKAGE_NOT_VETTED_BY_RECIPIENTS naming self uid ({self_uid}) and pkg ({main_pkg}), got: {refused}"
        );
    }

    fn make_unit_node(
        name: &str,
        entries: &[crate::topology_state::Entry],
    ) -> (Node, String, Peer) {
        let dar = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        let identity = ParticipantIdentity::generate(name);
        let alice = format!("alice::{}", identity.namespace());
        let physical = "sync::1220aa::37-0".to_string();
        let engine = Engine::load(&dar).expect("load sample dar");
        let world = World::open(&dar).expect("open sample world");
        let boot_package_ids: BTreeSet<String> = world.package_ids().into_iter().collect();
        let main_pkg = world.main_package_id().to_string();
        let mut package_names_by_id = BTreeMap::new();
        parse_dar_package_names(&dar, &mut package_names_by_id).expect("parse package names");
        let config = Config {
            member: identity.member(),
            encryption_fingerprint: identity.encryption_fingerprint(),
            encryption_secret: *identity.encryption_secret(),
            hosted_parties: vec![alice],
            timeouts: Timeouts::default(),
            submitter_keys: Vec::new(),
            mediator_keys: Vec::new(),
            peer_encryption_keys: Default::default(),
            physical_synchronizer_id: physical.clone(),
            follow_topology: true,
            topology_change_delay_micros: 250_000,
        };
        let mut runtime = Runtime::open_in(config, engine, None, 0).expect("open runtime");
        runtime
            .load_topology_state(entries)
            .expect("load topology state");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind dummy port");
        let port = listener.local_addr().expect("local addr").port();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let accept_thread = std::thread::spawn(move || {
            let stream = listener.accept().ok();
            let _ = done_rx.recv();
            drop(stream);
        });
        let client =
            SequencerConnect::connect(&format!("http://127.0.0.1:{port}")).expect("lazy connect");
        let _ = done_tx.send(());
        let _ = accept_thread.join();
        let token = Token {
            token: vec![1],
            expires_at_seconds: i64::MAX,
        };
        let self_peer = Peer {
            member: identity.member(),
            encryption_spki: Vec::new(),
            fingerprint: identity.encryption_fingerprint(),
        };
        let node = Node {
            runtime,
            last_notes: Vec::new(),
            identity,
            client,
            token,
            physical,
            mediator_group: 0,
            user_id: format!("u-{name}"),
            world,
            vetted_package_ids: boot_package_ids,
            package_names_by_id,
            contracts: BTreeMap::new(),
            unassigned: BTreeMap::new(),
            store: None,
            directory: BTreeMap::new(),
            board: std::sync::Arc::new(Board::default()),
            most_in_flight: 0,
            remote: Vec::new(),
            late: Vec::new(),
            clock: TimeKeeper::new(Instant::now(), 0),
        };
        (node, main_pkg, self_peer)
    }

    fn signed_vetting_entry(
        identity: &ParticipantIdentity,
        operation: i32,
        serial: u32,
        packages: Vec<(String, Option<i64>, Option<i64>)>,
    ) -> crate::topology_state::Entry {
        use canton_proto::com::digitalasset::canton::protocol::v30::vetted_packages::VettedPackage;
        use canton_proto::com::digitalasset::canton::protocol::v30::VettedPackages;
        use canton_proto::com::digitalasset::canton::protocol::v31;
        use prost::Message;
        #[allow(
            deprecated,
            reason = "populates protobuf VettedPackages wire message for unit test"
        )]
        let tx = v31::TopologyTransaction {
            operation,
            serial,
            mapping: Some(v31::TopologyMapping {
                mapping: Some(v31::topology_mapping::Mapping::VettedPackages(
                    VettedPackages {
                        participant_uid: identity.uid(),
                        package_ids: Vec::new(),
                        packages: packages
                            .into_iter()
                            .map(|(package_id, from_s, until_s)| VettedPackage {
                                package_id,
                                valid_from_inclusive: from_s
                                    .map(|seconds| prost_types::Timestamp { seconds, nanos: 0 }),
                                valid_until_exclusive: until_s
                                    .map(|seconds| prost_types::Timestamp { seconds, nanos: 0 }),
                            })
                            .collect(),
                    },
                )),
            }),
        };
        let tx_bytes = crate::topology_wire::versioned(
            tx.encode_to_vec(),
            crate::topology_wire::TOPOLOGY_TRANSACTION_VERSION,
        );
        let signed = crate::topology_wire::signed(
            tx_bytes.clone(),
            vec![identity.namespace_key.sign_transaction(&tx_bytes)],
        );
        crate::topology_state::Entry {
            valid_from: 0,
            signed,
            tx,
        }
    }

    /// U-61 review R1-F5: sender-side `check_peers_vetted` enforces `validFrom <= ledger_time < validUntil`, matching receiver-side U-62.
    #[test]
    fn check_peers_vetted_enforces_validity_window_at_ledger_time() {
        let (mut node, main_pkg, self_peer) = make_unit_node("u61-f5", &[]);
        let entry = signed_vetting_entry(
            &node.identity,
            1,
            1,
            vec![(main_pkg.clone(), Some(100), Some(200))],
        );
        node.runtime
            .load_topology_state(&[entry])
            .expect("load windowed vetting");
        // Before valid_from (100s = 100_000_000us) -> refused
        assert!(node
            .check_peers_vetted(&main_pkg, std::slice::from_ref(&self_peer), 99_999_999)
            .is_err());
        // Inside [100s, 200s) -> accepted
        assert_eq!(
            node.check_peers_vetted(&main_pkg, std::slice::from_ref(&self_peer), 100_000_000),
            Ok(())
        );
        assert_eq!(
            node.check_peers_vetted(&main_pkg, std::slice::from_ref(&self_peer), 199_999_999),
            Ok(())
        );
        // At/after valid_until (200s = 200_000_000us) -> refused
        assert!(node
            .check_peers_vetted(&main_pkg, std::slice::from_ref(&self_peer), 200_000_000)
            .is_err());
    }

    /// U-61 review R1-F3 (C3): once a participant has published a `VettedPackages` mapping (including after a `REMOVE` operation where
    /// `vetted_packages_of` is `None`), `vet_loaded_packages` is a no-op and does not re-publish boot packages.
    #[test]
    fn vet_loaded_packages_is_a_noop_after_remove_mapping() {
        let (mut node, main_pkg, _) = make_unit_node("u61-c3-remove", &[]);
        let add = signed_vetting_entry(&node.identity, 1, 1, vec![(main_pkg.clone(), None, None)]);
        let remove = signed_vetting_entry(&node.identity, 2, 2, vec![(main_pkg, None, None)]);
        node.runtime
            .load_topology_state(&[add, remove])
            .expect("load add+remove vetting");
        assert_eq!(node.runtime.vetted_serial_of(&node.identity.uid()), Some(2));
        assert_eq!(node.runtime.vetted_packages_of(&node.identity.uid()), None);
        // Must return Ok(()) without attempting to contact the closed dummy sequencer.
        assert_eq!(
            node.vet_loaded_packages(std::time::Duration::from_millis(50)),
            Ok(())
        );
    }
}
