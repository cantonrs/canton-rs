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
    ) -> Result<(), String> {
        // [CANTON-NOTE: SEMANTICS] every participant that hosts an informee, this one included, must have the package vetted in the
        // topology snapshot (`UsableSynchronizers.checkPackagesVetted`: `PackageUnknownTo(package, participant)`). A participant without a
        // `VettedPackages` mapping has vetted nothing, and a package this node merely holds is not vetted until the topology says so
        // (U-61: it used to skip itself and to take a boot package as vetted by a peer without a mapping)
        // a runtime configured by hand follows no topology: there is nothing to judge the vetting by (as for its hosting checks)
        if self.runtime.topology().is_none() {
            return Ok(());
        }
        let unvetted = |this: &Self| -> Option<String> {
            for peer in peers {
                let uid = peer.member.strip_prefix("PAR::").unwrap_or(&peer.member);
                let ok = this
                    .runtime
                    .vetted_packages_of(uid)
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

    /// Broadcasts `VettedPackages` when any boot package id is not yet in topology state for this node (`R-6b`).
    pub fn vet_loaded_packages(&mut self, timeout: Duration) -> Result<(), String> {
        if self
            .runtime
            .vetted_packages_of(&self.identity.uid())
            .is_some_and(|cur| self.boot_package_ids.is_subset(&cur))
        {
            return Ok(());
        }
        self.broadcast_vetted_packages(timeout)
    }

    /// Returns the stored summary of an approved unassignment held by this node's runtime (`P-14`).
    pub fn stored_unassignment(
        &self,
        reassignment_id: &str,
    ) -> Option<&crate::reassignment_receive::StoredUnassignment> {
        self.runtime.stored_unassignment(reassignment_id)
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
