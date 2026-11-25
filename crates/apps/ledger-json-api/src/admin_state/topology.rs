use std::collections::BTreeMap;

use canton_proto::com::digitalasset::canton::crypto::v30 as c30;
use canton_proto::com::digitalasset::canton::protocol::v30 as proto30;
use prost::Message as _;

use super::AdminErr;
use crate::service::ExecutionService;

/// Parameters for `TopologyManagerWriteService/Authorize` on a `PartyToParticipant` mapping (`4.3`).
pub struct PartyAuthorizeSpec<'a> {
    pub party: &'a str,
    /// `(participant_uid, permission, is_onboarding)` entries; empty defaults to self-hosting on this participant.
    pub participants: Vec<(String, i32, bool)>,
    pub threshold: u32,
    pub serial: u32,
    pub operation: i32,
    pub signed_by: Vec<String>,
    pub must_fully_authorize: bool,
    pub apply_to_synchronizer: bool,
    pub synchronizer_id: Option<&'a str>,
}

/// Lists effective `(party, participant_uid, permission)` mappings from a specific topology store (`"Authorized"`,
/// a synchronizer ID, or `None` for connected/synchronizer stores only), or pending proposals when `proposals_only` is true.
pub fn topology_party_mappings_in_store(
    service: &ExecutionService,
    store_filter: Option<&str>,
    proposals_only: bool,
) -> Result<Vec<(String, String, u32)>, AdminErr> {
    let uid = service.participant_id();
    let remote = service
        .v2_state()
        .remote_parties
        .lock()
        .map_err(|_| (13, "remote_parties lock poisoned".to_string()))?
        .clone();
    let parties = service
        .v2_state()
        .parties
        .lock()
        .map_err(|_| (13, "parties lock poisoned".to_string()))?
        .clone();
    let extra = service
        .v2_state()
        .extra_topology_txs
        .lock()
        .map_err(|_| (13, "extra_topology_txs lock poisoned".to_string()))?
        .clone();

    let is_authorized_store = store_filter == Some("Authorized");
    let mut merged: BTreeMap<(String, String), u32> = BTreeMap::new();
    if !is_authorized_store && !proposals_only {
        for p in parties {
            if !remote.contains(&p) {
                merged.insert((p, uid.clone()), 1);
            }
        }
    }

    for (store, bytes) in &extra {
        if is_authorized_store {
            if store != "Authorized" {
                continue;
            }
        } else {
            if store.is_empty() || store == "Authorized" {
                continue;
            }
            if let Some(target) = store_filter {
                if !target.is_empty()
                    && canton_algo::member_signature::logical_synchronizer_id(store)
                        != canton_algo::member_signature::logical_synchronizer_id(target)
                {
                    continue;
                }
            }
        }
        if let Some((party, hosting)) = party_hosting_map_with_mode(bytes, proposals_only) {
            if hosting.is_empty() {
                merged.retain(|(p, _), _| p != &party);
            } else {
                for (part_uid, (perm, _)) in hosting {
                    merged.insert((party.clone(), part_uid), u32::try_from(perm).unwrap_or(1));
                }
            }
        }
    }

    Ok(merged
        .into_iter()
        .map(|((party, part_uid), perm)| (party, part_uid, perm))
        .collect())
}

pub fn topology_party_mappings(service: &ExecutionService) -> Vec<(String, String, u32)> {
    topology_party_mappings_in_store(service, None, false).unwrap_or_default()
}

pub fn topology_vetted_packages(
    service: &ExecutionService,
) -> (
    String,
    String,
    u64,
    Vec<(String, Option<String>, Option<String>)>,
) {
    let uid = service.participant_id();
    let sync = service.v2_state().synchronizer_id();
    let serial = *service
        .v2_state()
        .vetting_serial
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let known: Vec<(String, Option<String>, Option<String>)> = service
        .v2_state()
        .packages
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|(_, rec)| rec.vetted)
        .map(|(id, rec)| (id.clone(), rec.valid_from.clone(), rec.valid_until.clone()))
        .collect();
    let list = if known.is_empty() {
        service
            .package_ids()
            .into_iter()
            .map(|id| (id, None, None))
            .collect()
    } else {
        known
    };
    (uid, sync, serial, list)
}

pub fn authorize_party_to_participant(
    service: &ExecutionService,
    party: &str,
    signing_key_override: Option<&str>,
) -> Result<(String, Vec<u8>), AdminErr> {
    authorize_party_to_participant_in_store(service, party, signing_key_override, false, None)
}

/// Authorizes `PartyToParticipant` on `service`, enforcing `must_fully_authorize` and keeping hosted
/// `/v2/parties` and Ledger API `TopologyTransaction` updates atomic and store-scoped (`4.3`).
pub fn authorize_party_to_participant_spec(
    service: &ExecutionService,
    spec: PartyAuthorizeSpec<'_>,
) -> Result<(String, Vec<u8>), AdminErr> {
    let uid = service.participant_id();
    let own_bare = bare_participant_uid(&uid);
    let own_ns = uid.split("::").nth(1).unwrap_or("1220rust");
    let hint = spec.party.split("::").next().unwrap_or(spec.party);
    let resolved_participants = if spec.participants.is_empty() {
        vec![(
            uid.clone(),
            proto30::enums::ParticipantPermission::Submission as i32,
            false,
        )]
    } else {
        spec.participants
    };

    // [CANTON-NOTE: SEMANTICS] `PartyToParticipant.requiredAuth` (`TopologyMapping.scala:2203-2260`):
    // both the party's namespace key (if foreign) and every hosting participant must authorize.
    let foreign_party_ns = spec
        .party
        .split("::")
        .nth(1)
        .is_some_and(|ns| !ns.is_empty() && ns != own_ns);
    let has_remote_participant = resolved_participants
        .iter()
        .any(|(p_uid, _, _)| bare_participant_uid(p_uid) != own_bare);
    let missing_authorizers = foreign_party_ns || has_remote_participant;

    let allocated = if !missing_authorizers
        && spec.apply_to_synchronizer
        && spec.operation != proto30::enums::TopologyChangeOp::Remove as i32
    {
        if let Some(res) = service.protocol_party(hint) {
            res.map_err(|e| (e.status_code() as i32, e.to_string()))?
        } else if spec.party.contains("::") {
            spec.party.to_string()
        } else {
            format!("{hint}::{own_ns}")
        }
    } else if spec.party.contains("::") {
        spec.party.to_string()
    } else {
        format!("{hint}::{own_ns}")
    };

    if missing_authorizers && spec.must_fully_authorize {
        return Err((
            9,
            format!(
                "FAILED_PRECONDITION: NOT_FULLY_AUTHORIZED: missing required authorizer signatures for {allocated}"
            ),
        ));
    }

    let op = if spec.operation == 0 {
        proto30::enums::TopologyChangeOp::AddReplace as i32
    } else {
        spec.operation
    };
    let mapping = proto30::PartyToParticipant {
        party: allocated.clone(),
        threshold: spec.threshold.max(1),
        participants: resolved_participants
            .iter()
            .map(
                |(p_uid, perm, onboarding)| proto30::party_to_participant::HostingParticipant {
                    participant_uid: p_uid.clone(),
                    permission: *perm,
                    onboarding: (*onboarding).then_some(
                        proto30::party_to_participant::hosting_participant::Onboarding {},
                    ),
                },
            )
            .collect(),
        party_signing_keys: None,
    };
    let tx = proto30::TopologyTransaction {
        operation: op,
        serial: spec.serial.max(1),
        mapping: Some(proto30::TopologyMapping {
            mapping: Some(proto30::topology_mapping::Mapping::PartyToParticipant(
                mapping,
            )),
        }),
    };
    let signed_by = spec
        .signed_by
        .first()
        .cloned()
        .unwrap_or_else(|| own_ns.to_string());
    let signed = proto30::SignedTopologyTransaction {
        transaction: tx.encode_to_vec(),
        signatures: vec![c30::Signature {
            format: c30::SignatureFormat::Raw as i32,
            signature: vec![0; 64],
            signed_by,
            signing_algorithm_spec: c30::SigningAlgorithmSpec::Ed25519 as i32,
            signature_delegation: None,
        }],
        proposal: missing_authorizers,
        multi_transaction_signatures: Vec::new(),
    };
    let encoded = signed.encode_to_vec();
    let store_label = spec
        .synchronizer_id
        .filter(|s| !s.is_empty())
        .map(canton_algo::member_signature::logical_synchronizer_id)
        .unwrap_or("Authorized");

    {
        let mut extra = service
            .v2_state()
            .extra_topology_txs
            .lock()
            .map_err(|_| (13, "extra_topology_txs lock poisoned".to_string()))?;
        if spec.apply_to_synchronizer && !missing_authorizers {
            let mut p_lock = service
                .v2_state()
                .parties
                .lock()
                .map_err(|_| (13, "parties lock poisoned".to_string()))?;
            let changed = if op == proto30::enums::TopologyChangeOp::Remove as i32 {
                let before = p_lock.len();
                p_lock.retain(|p| p != &allocated);
                p_lock.len() != before
            } else if !p_lock.contains(&allocated) {
                p_lock.push(allocated.clone());
                true
            } else {
                false
            };
            if !extra
                .iter()
                .any(|(s, existing)| s == store_label && existing == &encoded)
            {
                extra.push((store_label.to_string(), encoded.clone()));
            }
            drop(p_lock);
            drop(extra);
            if changed {
                let kind = if op == proto30::enums::TopologyChangeOp::Remove as i32 {
                    crate::v2_topology_events::TopologyAuthorizationKind::Revoked
                } else {
                    let perm = resolved_participants
                        .iter()
                        .find(|(p_uid, _, _)| bare_participant_uid(p_uid) == own_bare)
                        .map_or(1, |(_, perm, _)| *perm);
                    crate::v2_topology_events::TopologyAuthorizationKind::Added(perm)
                };
                crate::v2_topology_events::record_party_authorization(
                    service,
                    Some(store_label),
                    vec![crate::v2_topology_events::StoredTopologyEvent {
                        party_id: allocated.clone(),
                        participant_id: own_bare,
                        kind,
                    }],
                    u64::from(spec.serial.max(1)),
                );
            }
        } else if !extra
            .iter()
            .any(|(s, existing)| s == store_label && existing == &encoded)
        {
            extra.push((store_label.to_string(), encoded.clone()));
        }
    }
    Ok((allocated, encoded))
}

/// Authorizes `PartyToParticipant` on `service`, keeping hosted `/v2/parties` state and Ledger API
/// `TopologyTransaction` updates in lockstep: `Synchronizer` store authorizations host the party and emit an
/// update when fully authorized, while `Authorized` store authorizations or partial proposals stay staged.
///
/// [CANTON-NOTE: LIMITATION] Admin API topology handlers here approximate full namespace-delegation signature
/// verification (`!proposal && !signatures.is_empty()`) for local participant authorizations and do not run full
/// cryptographic signature validation against root/delegation certs.
pub fn authorize_party_to_participant_in_store(
    service: &ExecutionService,
    party: &str,
    signing_key_override: Option<&str>,
    apply_to_synchronizer: bool,
    synchronizer_id: Option<&str>,
) -> Result<(String, Vec<u8>), AdminErr> {
    authorize_party_to_participant_spec(
        service,
        PartyAuthorizeSpec {
            party,
            participants: Vec::new(),
            threshold: 1,
            serial: 1,
            operation: proto30::enums::TopologyChangeOp::AddReplace as i32,
            signed_by: signing_key_override
                .into_iter()
                .map(str::to_string)
                .collect(),
            must_fully_authorize: false,
            apply_to_synchronizer,
            synchronizer_id,
        },
    )
}

#[allow(
    deprecated,
    reason = "populates legacy/deprecated Canton protobuf fields for wire compatibility"
)]
pub fn authorize_vetted_packages(
    service: &ExecutionService,
    pkg_ids: &[String],
    serial_opt: Option<u32>,
) -> Result<Vec<u8>, AdminErr> {
    let uid = service.participant_id();
    let serial = {
        let mut s = service
            .v2_state()
            .vetting_serial
            .lock()
            .map_err(|_| (13, "vetting_serial lock poisoned".to_string()))?;
        *s = serial_opt.map_or(*s + 1, u64::from);
        *s as u32
    };
    {
        let mut known = service
            .v2_state()
            .packages
            .lock()
            .map_err(|_| (13, "packages lock poisoned".to_string()))?;
        for id in pkg_ids {
            if let Some(rec) = known.get_mut(id) {
                rec.vetted = true;
            }
        }
    }
    service
        .sync_vetted_packages(None, pkg_ids)
        .map_err(|e| (9, format!("TOPOLOGY_AUTHORIZE_FAILED: {e}")))?;

    let mapping = proto30::VettedPackages {
        participant_uid: uid.clone(),
        package_ids: Vec::new(),
        packages: pkg_ids
            .iter()
            .map(|id| proto30::vetted_packages::VettedPackage {
                package_id: id.clone(),
                valid_from_inclusive: None,
                valid_until_exclusive: None,
            })
            .collect(),
    };
    let tx = proto30::TopologyTransaction {
        operation: proto30::enums::TopologyChangeOp::AddReplace as i32,
        serial,
        mapping: Some(proto30::TopologyMapping {
            mapping: Some(proto30::topology_mapping::Mapping::VettedPackages(mapping)),
        }),
    };
    let signed = proto30::SignedTopologyTransaction {
        transaction: tx.encode_to_vec(),
        signatures: vec![c30::Signature {
            format: c30::SignatureFormat::Raw as i32,
            signature: vec![0; 64],
            signed_by: uid.split("::").nth(1).unwrap_or("key").to_string(),
            signing_algorithm_spec: c30::SigningAlgorithmSpec::Ed25519 as i32,
            signature_delegation: None,
        }],
        proposal: false,
        multi_transaction_signatures: Vec::new(),
    };
    Ok(signed.encode_to_vec())
}

/// Normalizes a `participant_uid` from protobuf (`PAR::<uid>` or `<uid>`) to the bare Ledger API UID (`Member.scala:467-477`).
fn bare_participant_uid(uid: &str) -> String {
    uid.strip_prefix("PAR::").unwrap_or(uid).to_string()
}

/// Extracts `(party, canHost map participant_uid -> (permission, is_onboarding))` for effective non-proposal
/// `PartyToParticipant` transactions (v30 and v31).
fn party_hosting_map(bytes: &[u8]) -> Option<(String, BTreeMap<String, (i32, bool)>)> {
    party_hosting_map_with_mode(bytes, false)
}

/// Extracts `(party, canHost map participant_uid -> (permission, is_onboarding))` for either effective
/// non-proposal transactions (`want_proposal == false`) or pending proposals (`want_proposal == true`).
///
/// [CANTON-NOTE: SEMANTICS] `ParticipantTopologyTerminateProcessing.scala:103-144`, `TopologyTransactionProcessor.scala:378-380`,
/// `TopologyTransactionDiff.scala:170-198`, and `TopologyMapping.scala:1936-2088`: proposals and unsigned txs never emit
/// Ledger API events; v31 `Nominated`/`Freezing` (`!canHost`) are excluded; `PAR::` prefixes strip to bare UID.
///
/// [CANTON-NOTE: LIMITATION] Authority and signature presence are approximated here as
/// `(!signed.signatures.is_empty() || !signed.multi_transaction_signatures.is_empty())`;
/// cryptographic signature/namespace verification is enforced by the synchronizer runtime (`topology_state`), not in-memory Admin API mocks.
fn party_hosting_map_with_mode(
    bytes: &[u8],
    want_proposal: bool,
) -> Option<(String, BTreeMap<String, (i32, bool)>)> {
    use canton_proto::com::digitalasset::canton::protocol::v31 as proto31;
    let signed = proto30::SignedTopologyTransaction::decode(bytes).ok()?;
    if signed.proposal != want_proposal
        || (signed.signatures.is_empty() && signed.multi_transaction_signatures.is_empty())
    {
        return None;
    }
    if let Ok(tx) = proto30::TopologyTransaction::decode(signed.transaction.as_slice()) {
        if let Some(proto30::TopologyMapping {
            mapping: Some(proto30::topology_mapping::Mapping::PartyToParticipant(ptp)),
        }) = tx.mapping
        {
            let map = if tx.operation == proto30::enums::TopologyChangeOp::Remove as i32 {
                BTreeMap::new()
            } else {
                ptp.participants
                    .into_iter()
                    .map(|hp| {
                        (
                            bare_participant_uid(&hp.participant_uid),
                            (hp.permission, hp.onboarding.is_some()),
                        )
                    })
                    .collect()
            };
            return Some((ptp.party, map));
        }
    }
    if let Ok(tx31) = proto31::TopologyTransaction::decode(signed.transaction.as_slice()) {
        if let Some(proto31::TopologyMapping {
            mapping: Some(proto31::topology_mapping::Mapping::PartyToParticipant(ptp)),
        }) = tx31.mapping
        {
            const STATE_ONBOARDING: i32 = 3;
            const STATE_ACTIVE: i32 = 4;
            let map = if tx31.operation == proto30::enums::TopologyChangeOp::Remove as i32 {
                BTreeMap::new()
            } else {
                ptp.participants
                    .into_iter()
                    .filter_map(|hp| match hp.state {
                        STATE_ONBOARDING => Some((
                            bare_participant_uid(&hp.participant_uid),
                            (hp.permission, true),
                        )),
                        STATE_ACTIVE | 0 => Some((
                            bare_participant_uid(&hp.participant_uid),
                            (hp.permission, false),
                        )),
                        _ => None,
                    })
                    .collect()
            };
            return Some((ptp.party, map));
        }
    }
    None
}

pub fn add_topology_txs(
    service: &ExecutionService,
    store_id: &str,
    tx_bytes: Vec<Vec<u8>>,
) -> Result<(), AdminErr> {
    let is_sync_store = !store_id.is_empty() && store_id != "Authorized";
    add_topology_txs_in_store(service, store_id, is_sync_store, tx_bytes)
}

/// Adds topology transactions into `store_id`; emits Ledger API `TopologyTransaction` diffs only when
/// `is_synchronizer_store` is true and the incoming transactions represent effective non-proposal changes.
///
/// [CANTON-NOTE: LIMITATION] Store acceptance relies on `party_hosting_map`'s signature-presence approximation rather than full delegation verification.
pub fn add_topology_txs_in_store(
    service: &ExecutionService,
    store_id: &str,
    is_synchronizer_store: bool,
    tx_bytes: Vec<Vec<u8>>,
) -> Result<(), AdminErr> {
    let logical_store = if is_synchronizer_store {
        canton_algo::member_signature::logical_synchronizer_id(store_id)
    } else {
        store_id
    };
    let own_bare = bare_participant_uid(&service.participant_id());
    let emitted = {
        let mut guard = service
            .v2_state()
            .extra_topology_txs
            .lock()
            .map_err(|_| (13, "extra_topology_txs lock poisoned".to_string()))?;
        let mut p_lock = service
            .v2_state()
            .parties
            .lock()
            .map_err(|_| (13, "parties lock poisoned".to_string()))?;
        let remote = service
            .v2_state()
            .remote_parties
            .lock()
            .map_err(|_| (13, "remote_parties lock poisoned".to_string()))?
            .clone();

        let mut current: BTreeMap<String, BTreeMap<String, (i32, bool)>> = BTreeMap::new();
        if is_synchronizer_store {
            // Seed parties already hosted via `/v2/parties` so subsequent `AddTransactions` changes emit `Changed` instead of `Added`.
            for party in p_lock.iter() {
                if !remote.contains(party) {
                    current
                        .entry(party.clone())
                        .or_default()
                        .insert(own_bare.clone(), (1, false));
                }
            }
            for (s, existing) in guard.iter() {
                if canton_algo::member_signature::logical_synchronizer_id(s) == logical_store {
                    if let Some((party, map)) = party_hosting_map(existing) {
                        current.insert(party, map);
                    }
                }
            }
        }
        let mut events = Vec::new();
        let mut own_updates: Vec<(String, bool)> = Vec::new();
        for bytes in tx_bytes {
            if guard
                .iter()
                .any(|(s, existing)| s == logical_store && existing == &bytes)
            {
                continue;
            }
            if is_synchronizer_store {
                if let Some((party, after)) = party_hosting_map(&bytes) {
                    let before = current.get(&party).cloned().unwrap_or_default();
                    let diff =
                        crate::v2_topology_events::diff_party_hosting(&before, &after, &party);
                    let was_local = before.contains_key(&own_bare);
                    let now_local = after.contains_key(&own_bare);
                    if was_local != now_local {
                        own_updates.push((party.clone(), now_local));
                    }
                    current.insert(party, after);
                    events.extend(diff);
                }
            }
            guard.push((logical_store.to_string(), bytes));
        }
        for (party, now_local) in own_updates {
            if now_local && !p_lock.contains(&party) {
                p_lock.push(party);
            } else if !now_local {
                p_lock.retain(|p| p != &party);
            }
        }
        events
    };
    if !emitted.is_empty() {
        crate::v2_topology_events::record_party_authorization(
            service,
            (!logical_store.is_empty()).then_some(logical_store),
            emitted,
            1,
        );
    }
    Ok(())
}

/// Imports historical topology snapshot transactions into `store_id` without replaying Ledger API events.
pub fn import_topology_txs(
    service: &ExecutionService,
    store_id: &str,
    tx_bytes: Vec<Vec<u8>>,
) -> Result<(), AdminErr> {
    let mut guard = service
        .v2_state()
        .extra_topology_txs
        .lock()
        .map_err(|_| (13, "extra_topology_txs lock poisoned".to_string()))?;
    for bytes in tx_bytes {
        if !guard
            .iter()
            .any(|(s, existing)| s == store_id && existing == &bytes)
        {
            guard.push((store_id.to_string(), bytes));
        }
    }
    Ok(())
}

pub fn extra_topology_txs(service: &ExecutionService, store_filter: Option<&str>) -> Vec<Vec<u8>> {
    service
        .v2_state()
        .extra_topology_txs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|(store, _)| store_filter.is_none_or(|f| f.is_empty() || store == f))
        .map(|(_, b)| b.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{add_topology_txs_in_store, c30, proto30};
    use crate::service::ExecutionService;
    use prost::Message as _;
    use std::sync::Arc;

    #[test]
    fn r7_add_topology_txs_propagates_parties_lock_poison_before_emitting_events() {
        let svc = Arc::new(ExecutionService::try_new().expect("service"));
        let svc_poison = Arc::clone(&svc);
        let res = std::thread::spawn(move || {
            let _g = svc_poison
                .v2_state()
                .parties
                .lock()
                .expect("lock parties to poison");
            panic!("deliberate test poison of v2.parties");
        })
        .join();
        assert!(res.is_err());

        let uid = svc.participant_id();
        let fp = uid.split("::").nth(1).unwrap_or("1220rust").to_string();
        let party = format!("poisoned-r7::{fp}");
        let mapping = proto30::PartyToParticipant {
            party,
            threshold: 1,
            participants: vec![proto30::party_to_participant::HostingParticipant {
                participant_uid: uid,
                permission: proto30::enums::ParticipantPermission::Submission as i32,
                onboarding: None,
            }],
            party_signing_keys: None,
        };
        let tx = proto30::TopologyTransaction {
            operation: proto30::enums::TopologyChangeOp::AddReplace as i32,
            serial: 1,
            mapping: Some(proto30::TopologyMapping {
                mapping: Some(proto30::topology_mapping::Mapping::PartyToParticipant(
                    mapping,
                )),
            }),
        };
        let signed = proto30::SignedTopologyTransaction {
            transaction: tx.encode_to_vec(),
            signatures: vec![c30::Signature {
                format: c30::SignatureFormat::Raw as i32,
                signature: vec![1; 64],
                signed_by: fp,
                signing_algorithm_spec: c30::SigningAlgorithmSpec::Ed25519 as i32,
                signature_delegation: None,
            }],
            proposal: false,
            multi_transaction_signatures: Vec::new(),
        };
        let err = add_topology_txs_in_store(
            &svc,
            "mysync::1220sync",
            true,
            vec![signed.encode_to_vec()],
        )
        .expect_err(
            "poisoned parties lock must return AdminErr(13) instead of emitting partial events",
        );
        assert_eq!(err.0, 13, "{err:?}");
        assert_eq!(
            svc.v2_state().updates().len(),
            0,
            "poisoned parties lock must emit 0 Ledger API topology updates"
        );
    }
}
