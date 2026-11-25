//! The upgrade mappings' own checks (`TopologyMappingChecks`, with the node's texts; the others are in `checks`) and what each followed
//! mapping changes once it is authorized.
use std::collections::BTreeSet;

use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
use canton_proto::com::digitalasset::canton::protocol::v31::TopologyTransaction;

use super::graph::Decentralized;
use super::keys::Delegation;
use super::psid::{decentralized_namespace_of, is_forbidden_protocol_version_downgrade, Lsu, Psid};
use super::tracker::{mediator_group_of, timeouts_of, Outcome, Refusal, Tracker};
use super::{
    encryption_keys_of, iso_utc, signing_keys_of, vetted_entries_of, vetted_ids_of, REMOVE,
};

impl Tracker {
    /// A mapping of another synchronizer than the one followed is none of this one's business.
    fn of_this_synchronizer(&self, what: &str, synchronizer_id: &str) -> Result<(), Refusal> {
        match &self.current_psid {
            Some(current) if synchronizer_id != current.logical => Err(Refusal::Check(format!(
                "{what} {synchronizer_id} while following {}",
                current.logical
            ))),
            _ => Ok(()),
        }
    }

    /// The checks of `mapping` against the state, before its authorization is looked at.
    pub(super) fn check(
        &self,
        mapping: &Mapping,
        operation: i32,
        previous: Option<&TopologyTransaction>,
        effective: Option<i64>,
    ) -> Result<(), Refusal> {
        match mapping {
            // [CANTON-NOTE: SEMANTICS] a first definition's namespace is the one derived from its owners (`computeNamespace`)
            Mapping::DecentralizedNamespaceDefinition(d) if previous.is_none() => {
                let owners: BTreeSet<String> = d.owners.iter().cloned().collect();
                match decentralized_namespace_of(&owners).map_err(Refusal::Check)? {
                    derived if derived == d.decentralized_namespace => Ok(()),
                    _ => Err(Refusal::Check(format!(
                        "The decentralized namespace {} is not derived from the owners {owners:?}",
                        d.decentralized_namespace
                    ))),
                }
            }
            Mapping::SynchronizerUpgradeAnnouncement(a) => {
                let successor =
                    Psid::parse(&a.successor_physical_synchronizer_id).map_err(|e| {
                        Refusal::Check(format!(
                            "a synchronizer upgrade announcement that does not parse: {e}"
                        ))
                    })?;
                self.of_this_synchronizer(
                    "a synchronizer upgrade announcement for",
                    &successor.logical,
                )?;
                if operation == REMOVE {
                    return Ok(());
                }
                self.check_announcement(&successor, upgrade_micros(a), effective)
            }
            Mapping::SequencerConnectionSuccessor(c) if operation != REMOVE => {
                let given = Psid::parse(&c.successor_physical_synchronizer_id).map_err(|e| {
                    Refusal::Check(format!("a sequencer successor that does not parse: {e}"))
                })?;
                match self.lsu_for_checks() {
                    None => Err(Refusal::Check(
                        "The operation cannot be performed because no LSU is announced".into(),
                    )),
                    Some(lsu) if lsu.successor != given => Err(Refusal::Check(format!(
                        "Lsu sequencer successor for sequencer {} is invalid because it mentions successor {given} but the current LSU announcement mentions {}",
                        c.sequencer_id, lsu.successor
                    ))),
                    Some(_) => Ok(()),
                }
            }
            _ => Ok(()),
        }
    }

    /// `TopologyMappingChecks.checkLsuAnnouncement`: a new announcement has a **greater** successor id than the one in force (the same
    /// announcement again, with more signatures, is merged before any check); its **upgrade time is after the time it takes effect**; and
    /// the successor does not **downgrade the protocol version** (a higher serial with a lower version, when the current synchronizer is
    /// on version 37 or later).
    fn check_announcement(
        &self,
        successor: &Psid,
        upgrade_micros: i64,
        effective: Option<i64>,
    ) -> Result<(), Refusal> {
        if let Some(previous) = &self.lsu {
            if *successor <= previous.successor {
                return Err(Refusal::Check(format!(
                    "The declared successor {successor} is not greater than prior synchronizer {}.",
                    previous.successor
                )));
            }
        }
        if let Some(effective) = effective {
            if upgrade_micros <= effective {
                return Err(Refusal::Check(format!(
                    "The upgrade time {} must be after the effective {} of the synchronizer upgrade announcement for synchronizer {}.",
                    iso_utc(upgrade_micros),
                    iso_utc(effective),
                    successor.logical
                )));
            }
        }
        if let Some(current) = &self.current_psid {
            if is_forbidden_protocol_version_downgrade(current, successor) {
                return Err(Refusal::Check(format!(
                    "The declared successor {successor} has a lower protocol version than the current synchronizer {current}. Protocol version downgrades are not allowed."
                )));
            }
        }
        Ok(())
    }

    /// What an authorized `tx` changes. `signed_by`: the keys that authorized it (a delegation's edges); `delegation`: a namespace
    /// delegation, parsed.
    pub(super) fn effect(
        &mut self,
        mapping: &Mapping,
        tx: &TopologyTransaction,
        signed_by: BTreeSet<String>,
        delegation: Option<Delegation>,
    ) -> Outcome {
        let (serial, removed) = (tx.serial, tx.operation == REMOVE);
        match mapping {
            Mapping::NamespaceDelegation(d) => {
                let Some(delegation) = delegation else {
                    return Outcome::Unfollowed("a delegation that does not parse".into());
                };
                // [CANTON-NOTE: SEMANTICS] A REMOVE revokes the delegation and, with it, every key only it chained to the root.
                if removed {
                    self.auth
                        .remove(&delegation.namespace, &delegation.target_fingerprint);
                    return Outcome::InForce(format!(
                        "the key of namespace {} is revoked",
                        d.namespace
                    ));
                }
                self.auth.replace(delegation, signed_by);
                Outcome::InForce(format!("the key of namespace {} is in force", d.namespace))
            }
            Mapping::DecentralizedNamespaceDefinition(d) => {
                let namespace = &d.decentralized_namespace;
                if removed {
                    self.auth.remove_decentralized(namespace);
                    return Outcome::InForce(format!(
                        "decentralized namespace {namespace} is removed"
                    ));
                }
                self.auth.define_decentralized(
                    namespace,
                    Decentralized {
                        threshold: usize::try_from(d.threshold).unwrap_or(usize::MAX),
                        owners: d.owners.iter().cloned().collect(),
                    },
                );
                Outcome::InForce(format!("decentralized namespace {namespace} is in force"))
            }
            Mapping::OwnerToKeyMapping(m) => {
                if removed {
                    self.members.remove(&m.member);
                } else {
                    self.members.insert(
                        m.member.clone(),
                        (serial, signing_keys_of(m), encryption_keys_of(m)),
                    );
                }
                Outcome::InForce(format!(
                    "{}: keys at serial {serial} are in force",
                    m.member
                ))
            }
            Mapping::SynchronizerParametersState(p) => {
                if removed {
                    return Outcome::Unfollowed(
                        "a removal of the synchronizer parameters is not followed".into(),
                    );
                }
                let Some(timeouts) = p.synchronizer_parameters.as_ref().and_then(timeouts_of)
                else {
                    return Outcome::Unfollowed(
                        "synchronizer parameters without the timeouts this participant follows"
                            .into(),
                    );
                };
                self.params_serial = Some(serial);
                self.parameters = p.synchronizer_parameters;
                self.base.timeouts = Some(timeouts);
                Outcome::InForce(format!(
                    "synchronizer parameters at serial {serial} are in force (confirmation response timeout {} micros)",
                    timeouts.confirmation_response_micros
                ))
            }
            Mapping::MediatorSynchronizerState(m) => {
                if removed {
                    self.mediator_groups.remove(&m.group);
                    return Outcome::InForce(format!("mediator group {} is removed", m.group));
                }
                self.mediator_groups
                    .insert(m.group, mediator_group_of(m, serial));
                Outcome::InForce(format!(
                    "mediator group {} at serial {serial}: active {:?}, threshold {}",
                    m.group, m.active, m.threshold
                ))
            }
            Mapping::SequencerSynchronizerState(s) => {
                if removed {
                    self.sequencer_group = None;
                    return Outcome::InForce("the sequencer group is removed".into());
                }
                self.sequencer_group = Some(super::tracker::sequencer_group_of(s, serial));
                Outcome::InForce(format!(
                    "sequencer group at serial {serial}: active {:?}, threshold {}",
                    s.active, s.threshold
                ))
            }
            Mapping::SynchronizerUpgradeAnnouncement(a) => {
                if removed {
                    self.lsu = None;
                    return Outcome::InForce(
                        "the synchronizer upgrade announcement is withdrawn".into(),
                    );
                }
                let Ok(successor) = Psid::parse(&a.successor_physical_synchronizer_id) else {
                    return Outcome::Unfollowed("an announcement that does not parse".into());
                };
                let upgrade_micros = upgrade_micros(a);
                let note = format!(
                    "the synchronizer announced its upgrade to {successor} at {}",
                    iso_utc(upgrade_micros)
                );
                self.lsu = Some(Lsu {
                    successor,
                    upgrade_micros,
                    serial,
                });
                Outcome::InForce(note)
            }
            Mapping::SequencerConnectionSuccessor(c) => Outcome::InForce(if removed {
                format!("the successor connection of {} is removed", c.sequencer_id)
            } else {
                format!("the successor connection of {} is in force", c.sequencer_id)
            }),
            Mapping::VettedPackages(v) => {
                if removed {
                    self.vetted_packages.remove(&v.participant_uid);
                    self.vetted_package_windows.remove(&v.participant_uid);
                } else {
                    self.vetted_packages
                        .insert(v.participant_uid.clone(), vetted_ids_of(v));
                    self.vetted_package_windows
                        .insert(v.participant_uid.clone(), vetted_entries_of(v));
                }
                Outcome::InForce(format!(
                    "vetted packages of {}: serial {serial} is in force{}",
                    v.participant_uid,
                    if removed { " (removed)" } else { "" }
                ))
            }
            Mapping::ParticipantPermission(p) => Outcome::InForce(format!(
                "the synchronizer permission of {}: serial {serial} is in force{}",
                p.participant_uid,
                if removed { " (removed)" } else { "" }
            )),
            Mapping::SynchronizerTrustCertificate(c) => Outcome::InForce(format!(
                "trust certificate of {}: serial {serial} is in force{}",
                c.participant_uid,
                if removed { " (removed)" } else { "" }
            )),
            Mapping::PartyToParticipant(p) => {
                if removed {
                    self.parties.remove(&p.party);
                    self.party_thresholds.remove(&p.party);
                } else {
                    self.party_thresholds
                        .insert(p.party.clone(), p.threshold.max(1));
                    self.parties.insert(
                        p.party.clone(),
                        (
                            serial,
                            p.participants
                                .iter()
                                .map(|h| (h.participant_uid.clone(), h.permission))
                                .collect(),
                        ),
                    );
                }
                Outcome::InForce(format!("{}: serial {serial} is in force", p.party))
            }
            #[expect(
                deprecated,
                reason = "PartyToKeyMapping is a deprecated v31 variant still read by party_signing_keys"
            )]
            Mapping::PartyToKeyMapping(p) => Outcome::InForce(format!(
                "{}: party key mapping at serial {serial} is in force{}",
                p.party,
                if removed { " (removed)" } else { "" }
            )),
            _ => Outcome::Unfollowed("a transaction this participant does not follow".into()),
        }
    }
}

fn upgrade_micros(
    a: &canton_proto::com::digitalasset::canton::protocol::v30::LsuAnnouncement,
) -> i64 {
    a.upgrade_time
        .as_ref()
        .map_or(0, |t| t.seconds * 1_000_000 + i64::from(t.nanos) / 1_000)
}
