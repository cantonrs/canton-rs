//! Streaming and pointwise `TopologyTransaction` updates (`UpdateFormat.includeTopologyEvents`, A-8).
//!
//! [CANTON-NOTE: SEMANTICS] Aligns with Canton `3.7.2` `topology_transaction.proto`, `JsUpdateService.scala`,
//! `TransactionLogUpdatesConversions.scala`, and `RequiredClaims.scala` (`updateFormatClaims`):
//! - Each `PartyToParticipant` authorization change records a `StoredUpdate { topology: Some(...), .. }` at its assigned offset.
//! - `includeTopologyEvents.includeParticipantAuthorizationEvents.parties` filters emitted `TopologyEvent` entries per party;
//!   empty/absent `parties` matches all parties and requires `ReadAsAnyParty`.
//! - When filtered events are empty, the `TopologyTransaction` update is omitted from the stream / lookup response.
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};

use crate::service::ExecutionService;
use crate::v2_commands::{now_rfc3339, update_id, StoredUpdate, SYNCHRONIZER};

/// Authorization change variant carried inside `TopologyEvent.event`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum TopologyAuthorizationKind {
    Added(i32),
    Changed(i32),
    Revoked,
    Onboarding(i32),
}

/// One participant authorization change for a party on a synchronizer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredTopologyEvent {
    pub(crate) party_id: String,
    pub(crate) participant_id: String,
    pub(crate) kind: TopologyAuthorizationKind,
}

/// Persisted metadata for a `TopologyTransaction` update.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredTopologyTransaction {
    pub(crate) synchronizer_id: String,
    pub(crate) record_time: String,
    pub(crate) events: Vec<StoredTopologyEvent>,
}

/// Requested `UpdateFormat.includeTopologyEvents` filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TopologyFilter {
    /// `includeTopologyEvents` or `includeParticipantAuthorizationEvents` is unset.
    None,
    /// `parties` is empty or omitted: match all parties.
    AllParties,
    /// Match events whose `partyId` is in this list.
    Parties(Vec<String>),
}

/// Parses `TopologyFormat` from a Ledger API v2 JSON request body (`updateFormat.includeTopologyEvents`).
///
/// [CANTON-NOTE: SEMANTICS] `JsUpdateService.scala:244-247` (`deriveRelaxedCodec` + `CirceRelaxedCodec.scala:59-60, 92-99`,
/// `transaction_filter.proto:177-183`): omitted `parties` defaults to `Seq.empty`, while a non-array `parties` or any
/// non-string element fails JSON decoding (HTTP 400) rather than being silently dropped or widening to `AllParties`.
pub(crate) fn parse_topology_filter(body: &Json) -> Result<TopologyFilter, String> {
    let Some(pa) =
        body.pointer("/updateFormat/includeTopologyEvents/includeParticipantAuthorizationEvents")
    else {
        return Ok(TopologyFilter::None);
    };
    if pa.is_null() {
        return Ok(TopologyFilter::None);
    }
    let Some(obj) = pa.as_object() else {
        return Err(
            "Invalid value for: body (Expected object at 'updateFormat.includeTopologyEvents.includeParticipantAuthorizationEvents')"
                .to_string(),
        );
    };
    let Some(raw_parties) = obj.get("parties") else {
        return Ok(TopologyFilter::AllParties);
    };
    let Some(arr) = raw_parties.as_array() else {
        return Err(
            "Invalid value for: body (Got value with wrong type, expecting array at 'updateFormat.includeTopologyEvents.includeParticipantAuthorizationEvents.parties')"
                .to_string(),
        );
    };
    let mut parties = Vec::with_capacity(arr.len());
    for (idx, val) in arr.iter().enumerate() {
        let Some(party) = val.as_str() else {
            return Err(format!(
                "Invalid value for: body (Got value with wrong type, expecting string at 'updateFormat.includeTopologyEvents.includeParticipantAuthorizationEvents.parties[{idx}]')"
            ));
        };
        parties.push(party.to_string());
    }
    if parties.is_empty() {
        Ok(TopologyFilter::AllParties)
    } else {
        Ok(TopologyFilter::Parties(parties))
    }
}

/// Returns the Canton proto enum JSON name for a `ParticipantPermission` numeric code.
pub(crate) fn permission_name(code: i32) -> &'static str {
    match code {
        1 => "PARTICIPANT_PERMISSION_SUBMISSION",
        2 => "PARTICIPANT_PERMISSION_CONFIRMATION",
        3 => "PARTICIPANT_PERMISSION_OBSERVATION",
        _ => "PARTICIPANT_PERMISSION_UNSPECIFIED",
    }
}

fn event_json(ev: &StoredTopologyEvent) -> Json {
    match ev.kind {
        TopologyAuthorizationKind::Added(perm) => json!({
            "event": {
                "ParticipantAuthorizationAdded": {
                    "value": {
                        "partyId": ev.party_id,
                        "participantId": ev.participant_id,
                        "participantPermission": permission_name(perm),
                    }
                }
            }
        }),
        TopologyAuthorizationKind::Changed(perm) => json!({
            "event": {
                "ParticipantAuthorizationChanged": {
                    "value": {
                        "partyId": ev.party_id,
                        "participantId": ev.participant_id,
                        "participantPermission": permission_name(perm),
                    }
                }
            }
        }),
        TopologyAuthorizationKind::Revoked => json!({
            "event": {
                "ParticipantAuthorizationRevoked": {
                    "value": {
                        "partyId": ev.party_id,
                        "participantId": ev.participant_id,
                    }
                }
            }
        }),
        TopologyAuthorizationKind::Onboarding(perm) => json!({
            "event": {
                "ParticipantAuthorizationOnboarding": {
                    "value": {
                        "partyId": ev.party_id,
                        "participantId": ev.participant_id,
                        "participantPermission": permission_name(perm),
                    }
                }
            }
        }),
    }
}

/// Renders a `StoredUpdate` with `TopologyTransaction` under `filter`, matching Canton 3.7.2 JSON/gRPC `oneof` layout.
pub(crate) fn topology_json(
    u: &StoredUpdate,
    topo: &StoredTopologyTransaction,
    filter: &TopologyFilter,
) -> Option<Json> {
    let events: Vec<Json> = match filter {
        TopologyFilter::None => return None,
        TopologyFilter::AllParties => topo.events.iter().map(event_json).collect(),
        TopologyFilter::Parties(parties) => topo
            .events
            .iter()
            .filter(|ev| parties.contains(&ev.party_id))
            .map(event_json)
            .collect(),
    };
    if events.is_empty() {
        return None;
    }
    let sync_id = if topo.synchronizer_id.is_empty() {
        SYNCHRONIZER
    } else {
        topo.synchronizer_id.as_str()
    };
    let trace_context = crate::trace_context::json(
        u.official.as_ref().map(|o| o.trace_parent.as_deref()),
        u.trace_parent.as_deref(),
    );
    Some(json!({
        "update": {
            "TopologyTransaction": {
                "value": {
                    "updateId": u.update_id,
                    "offset": u.offset,
                    "synchronizerId": sync_id,
                    "recordTime": topo.record_time,
                    "events": events,
                    "traceContext": trace_context,
                }
            }
        }
    }))
}

/// Advances `ledger_end` by `offset_step` and records a `TopologyTransaction` update atomically under `commit_publish_lock`.
pub(crate) fn record_party_authorization(
    service: &ExecutionService,
    synchronizer_id: Option<&str>,
    events: Vec<StoredTopologyEvent>,
    offset_step: u64,
) -> Option<u64> {
    if events.is_empty() || offset_step == 0 {
        return None;
    }
    let state = service.v2_state();
    // [CANTON-NOTE: SEMANTICS] `ParticipantTopologyTerminateProcessing.scala:536-543`: Ledger API
    // TopologyTransaction updates always report the logical synchronizer ID, never a physical upgrade suffix.
    let sync = synchronizer_id
        .filter(|s| !s.is_empty())
        .map(canton_algo::member_signature::logical_synchronizer_id)
        .map(str::to_string)
        .unwrap_or_else(|| {
            let raw = state.synchronizer_id();
            canton_algo::member_signature::logical_synchronizer_id(&raw).to_string()
        });
    let now_iso = now_rfc3339();
    let at_micros = crate::clock::now_micros();
    let _publish_guard = state
        .commit_publish_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let offset = state.ledger_end.load(Ordering::SeqCst) + offset_step;
    let update = StoredUpdate {
        update_id: update_id(offset),
        offset,
        command_id: String::new(),
        effective_at: now_iso.clone(),
        events: Vec::new(),
        at_micros,
        external_transaction_hash: None,
        reassignment: None,
        topology: Some(Box::new(StoredTopologyTransaction {
            synchronizer_id: sync,
            record_time: now_iso,
            events,
        })),
        official: None,
        trace_parent: crate::trace_context::current(),
        act_as: Vec::new(),
    };
    state.record_update(update);
    state.ledger_end.store(offset, Ordering::SeqCst);
    Some(offset)
}

/// Computes deterministic `Added`, `Onboarding`, `Changed`, and `Revoked` authorization events across two `canHost` snapshots
/// (`participant_uid -> (permission, is_onboarding)`) for `party_id`.
///
/// [CANTON-NOTE: SEMANTICS] Mirrors `TopologyTransactionDiff.scala:48-74, 170-198` and `Member.scala:467-477`:
/// - `before` and `after` contain only `canHost` participants (`Active`/`Onboarding`, excluding `Nominated`/`Freezing`), keyed by
///   bare UID without `PAR::`.
/// - Entering `Active` from absent OR from `Onboarding` emits `Added`; entering `Onboarding` from absent emits `Onboarding`;
///   changing `permission` while present in both emits `Changed` (even alongside `Onboarding -> Active`); removal emits `Revoked`.
pub(crate) fn diff_party_hosting(
    before: &BTreeMap<String, (i32, bool)>,
    after: &BTreeMap<String, (i32, bool)>,
    party_id: &str,
) -> Vec<StoredTopologyEvent> {
    let mut events = Vec::new();
    for (participant_id, &(new_perm, onboarding_after)) in after {
        match before.get(participant_id) {
            None => events.push(StoredTopologyEvent {
                party_id: party_id.to_string(),
                participant_id: participant_id.clone(),
                kind: if onboarding_after {
                    TopologyAuthorizationKind::Onboarding(new_perm)
                } else {
                    TopologyAuthorizationKind::Added(new_perm)
                },
            }),
            Some(&(old_perm, onboarding_before)) => {
                if !onboarding_after && onboarding_before {
                    events.push(StoredTopologyEvent {
                        party_id: party_id.to_string(),
                        participant_id: participant_id.clone(),
                        kind: TopologyAuthorizationKind::Added(new_perm),
                    });
                }
                if old_perm != new_perm {
                    events.push(StoredTopologyEvent {
                        party_id: party_id.to_string(),
                        participant_id: participant_id.clone(),
                        kind: TopologyAuthorizationKind::Changed(new_perm),
                    });
                }
            }
        }
    }
    for participant_id in before.keys() {
        if !after.contains_key(participant_id) {
            events.push(StoredTopologyEvent {
                party_id: party_id.to_string(),
                participant_id: participant_id.clone(),
                kind: TopologyAuthorizationKind::Revoked,
            });
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_update(offset: u64, events: Vec<StoredTopologyEvent>) -> StoredUpdate {
        StoredUpdate {
            update_id: update_id(offset),
            offset,
            command_id: String::new(),
            effective_at: "2026-11-21T00:00:00.000000Z".into(),
            events: Vec::new(),
            at_micros: 1_795_000_000_000_000,
            external_transaction_hash: None,
            reassignment: None,
            topology: Some(Box::new(StoredTopologyTransaction {
                synchronizer_id: "mysync::1220aa".into(),
                record_time: "2026-11-21T00:00:00.000000Z".into(),
                events,
            })),
            official: None,
            trace_parent: None,
            act_as: Vec::new(),
        }
    }

    #[test]
    fn parses_topology_filter_and_filters_events_by_party() {
        assert_eq!(parse_topology_filter(&json!({})), Ok(TopologyFilter::None));
        assert_eq!(
            parse_topology_filter(&json!({
                "updateFormat": {
                    "includeTopologyEvents": {
                        "includeParticipantAuthorizationEvents": { "parties": [] }
                    }
                }
            })),
            Ok(TopologyFilter::AllParties)
        );
        let alice_only = parse_topology_filter(&json!({
            "updateFormat": {
                "includeTopologyEvents": {
                    "includeParticipantAuthorizationEvents": { "parties": ["alice::1220aa"] }
                }
            }
        }))
        .expect("valid topology filter");
        assert_eq!(
            alice_only,
            TopologyFilter::Parties(vec!["alice::1220aa".into()])
        );

        let events = vec![
            StoredTopologyEvent {
                party_id: "alice::1220aa".into(),
                participant_id: "p1::1220pp".into(),
                kind: TopologyAuthorizationKind::Added(1),
            },
            StoredTopologyEvent {
                party_id: "bob::1220bb".into(),
                participant_id: "p1::1220pp".into(),
                kind: TopologyAuthorizationKind::Changed(2),
            },
            StoredTopologyEvent {
                party_id: "alice::1220aa".into(),
                participant_id: "p2::1220qq".into(),
                kind: TopologyAuthorizationKind::Revoked,
            },
            StoredTopologyEvent {
                party_id: "carol::1220cc".into(),
                participant_id: "p3::1220rr".into(),
                kind: TopologyAuthorizationKind::Onboarding(3),
            },
        ];
        let u = sample_update(5, events);
        let topo = u.topology.as_deref().unwrap();
        assert!(topology_json(&u, topo, &TopologyFilter::None).is_none());

        let filtered = topology_json(&u, topo, &alice_only).expect("alice events present");
        let arr = filtered["update"]["TopologyTransaction"]["value"]["events"]
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[0]["event"]["ParticipantAuthorizationAdded"]["value"]["participantPermission"],
            "PARTICIPANT_PERMISSION_SUBMISSION"
        );
        assert!(arr[1]["event"]["ParticipantAuthorizationRevoked"]["value"].is_object());

        let all = topology_json(&u, topo, &TopologyFilter::AllParties).unwrap();
        let arr_all = all["update"]["TopologyTransaction"]["value"]["events"]
            .as_array()
            .unwrap();
        assert_eq!(arr_all.len(), 4);
        assert_eq!(
            arr_all[1]["event"]["ParticipantAuthorizationChanged"]["value"]
                ["participantPermission"],
            "PARTICIPANT_PERMISSION_CONFIRMATION"
        );
        assert_eq!(
            arr_all[3]["event"]["ParticipantAuthorizationOnboarding"]["value"]
                ["participantPermission"],
            "PARTICIPANT_PERMISSION_OBSERVATION"
        );
    }

    #[test]
    fn diff_party_hosting_emits_added_changed_and_revoked_in_sorted_order() {
        let before = BTreeMap::from([
            ("p1::1220aa".to_string(), (1, false)),
            ("p2::1220bb".to_string(), (2, false)),
        ]);
        let after = BTreeMap::from([
            ("p1::1220aa".to_string(), (2, false)),
            ("p3::1220cc".to_string(), (3, false)),
        ]);
        let diff = diff_party_hosting(&before, &after, "alice::1220xx");
        assert_eq!(
            diff,
            vec![
                StoredTopologyEvent {
                    party_id: "alice::1220xx".into(),
                    participant_id: "p1::1220aa".into(),
                    kind: TopologyAuthorizationKind::Changed(2),
                },
                StoredTopologyEvent {
                    party_id: "alice::1220xx".into(),
                    participant_id: "p3::1220cc".into(),
                    kind: TopologyAuthorizationKind::Added(3),
                },
                StoredTopologyEvent {
                    party_id: "alice::1220xx".into(),
                    participant_id: "p2::1220bb".into(),
                    kind: TopologyAuthorizationKind::Revoked,
                },
            ]
        );
    }
}
