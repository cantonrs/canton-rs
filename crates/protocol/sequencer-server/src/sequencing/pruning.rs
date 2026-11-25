//! Pruning on an operator's request (`SequencerPruningAdministrationService.Prune`, `MediatorAdministrationService.Prune`), on top of what
//! the acknowledgements already let the sequencer forget ([`super::compaction`]).
use super::{now_micros, Sequencer};
use canton_participant::topology_state::iso_utc;
use canton_proto::com::digitalasset::canton::sequencer::admin::v30::{
    SequencerMemberStatus, SequencerPruningStatus,
};
use std::collections::BTreeMap;

/// Why the mediators refuse to prune (`Mediator.PruningError`).
#[derive(Debug, PartialEq, Eq)]
pub enum MediatorPruneRefused {
    /// They have not processed any event yet.
    NoData,
    /// The requested time is past the earliest time they may prune at.
    TooLate { requested: i64, earliest: i64 },
}

impl MediatorPruneRefused {
    pub fn message(&self) -> String {
        match self {
            Self::NoData => "There is no mediator data available for pruning".to_string(),
            Self::TooLate {
                requested,
                earliest,
            } => format!(
                "Requested pruning timestamp [{}] is later than the earliest available pruning timestamp [{}]",
                iso_utc(*requested),
                iso_utc(*earliest)
            ),
        }
    }
}

impl Sequencer {
    /// The members, when each acknowledged last and how far the sequencer may prune (`SequencerPruningStatus`).
    ///
    /// [CANTON-NOTE: LIMITATION] The registry keeps no registration time: a member's `registered_at` is the time of its oldest stored event
    /// (now when it has none), which no event of its own precedes, so the safe pruning point it gives is the same.
    pub fn pruning_status(&self) -> SequencerPruningStatus {
        let now = now_micros();
        let acks = self
            .inner
            .acks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let first: BTreeMap<String, i64> = self
            .inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(|(m, log)| log.first().map(|e| (m.clone(), e.timestamp)))
            .collect();
        let members = self
            .inner
            .registry
            .members()
            .into_iter()
            .map(|member| SequencerMemberStatus {
                registered_at: first.get(&member).copied().unwrap_or(now),
                last_acknowledged: acks.get(&member).copied(),
                enabled: !self.inner.registry.is_disabled(&member),
                member,
            })
            .collect();
        SequencerPruningStatus {
            now,
            earliest_event_timestamp: first.values().copied().min().unwrap_or(now),
            members,
        }
    }

    /// Removes the events before `at` (`BlockSequencer.prune`): refused past the earliest safe pruning point, the earliest time an enabled
    /// member acknowledged (or registered at). Every member's last event stays, as in [`Self::forget_acknowledged`]. Returns what was
    /// removed. Blocking: the journal is rewritten.
    ///
    /// [CANTON-NOTE: SEMANTICS] `SequencerPruningStatus.safePruningTimestamp` is the minimum over the active members of
    /// `lastAcknowledged.getOrElse(registeredAt)`, `now` when there are none; `PruningError.UnsafePruningPoint` is its refusal.
    pub fn prune(&self, at: i64) -> Result<String, String> {
        let status = self.pruning_status();
        let safe = status
            .members
            .iter()
            .filter(|m| m.enabled)
            .map(|m| m.last_acknowledged.unwrap_or(m.registered_at))
            .min()
            .unwrap_or(status.now);
        if at > safe {
            return Err(format!(
                "Could not prune at [{}] as the earliest safe pruning point is [{}]",
                iso_utc(at),
                iso_utc(safe)
            ));
        }
        let removed = {
            let mut events = self
                .inner
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut removed = 0;
            for log in events.values_mut() {
                let last = log.last().map(|e| e.timestamp);
                let before = log.len();
                log.retain(|e| e.timestamp >= at || Some(e.timestamp) == last);
                removed += before - log.len();
            }
            removed
        };
        if let Some(journal) = self.inner.journal.get() {
            journal
                .rewrite(|lines| prune_lines(lines, at))
                .map_err(|e| format!("the journal could not be rewritten: {e}"))?;
        }
        Ok(format!("Removed {removed} events before {}", iso_utc(at)))
    }

    /// Prunes the finalized responses of the mediators inside up to `at` (`Mediator.prune`).
    ///
    /// [CANTON-NOTE: SEMANTICS] Aligns with Canton `3.7.2` `Mediator.latestSafePruningTsForSynchronizerParameters` and
    /// `Mediator.latestSafePruningTsBefore` (`Mediator.scala:499-529`):
    /// - Pruning past `clean` is refused.
    /// - Across every synchronizer parameter slice `(validFrom, validUntil, confirmationResponseTimeout)` known up to `clean`:
    ///   - slices strictly in the future (`clean <= validFrom`) allow up to `clean`;
    ///   - slices fully elapsed past their `validUntil + timeout <= clean` allow up to `clean`;
    ///   - active or still-unexpired slices cap at `validFrom.max(clean - timeout)` (never before `validFrom`, and respecting earlier
    ///     longer-timeout slices when timeout decreases).
    pub fn prune_mediators(&self, at: i64) -> Result<usize, MediatorPruneRefused> {
        let clean = self
            .inner
            .mediators
            .iter()
            .filter_map(|m| m.clean_time())
            .min()
            .ok_or(MediatorPruneRefused::NoData)?;
        if at > clean {
            return Err(MediatorPruneRefused::TooLate {
                requested: at,
                earliest: clean,
            });
        }
        let changes = self.inner.store.timeout_changes();
        let earliest = latest_safe_pruning_ts_before(&changes, clean);
        if at > earliest {
            return Err(MediatorPruneRefused::TooLate {
                requested: at,
                earliest,
            });
        }
        Ok(self
            .inner
            .mediators
            .iter()
            .map(|m| m.prune_finalized(at))
            .sum())
    }

    /// The request time of the finalized response at `skip` (0: the oldest) of the mediators inside (`FindPruningTimestamp`).
    pub fn mediator_pruning_timestamp(&self, skip: usize) -> Option<i64> {
        let mut all: Vec<i64> = self
            .inner
            .mediators
            .iter()
            .flat_map(|m| m.finalized_requests())
            .collect();
        all.sort_unstable();
        all.get(skip).copied()
    }
}

/// The journal without the events before `at`, except each member's last.
fn prune_lines(lines: Vec<String>, at: i64) -> Vec<String> {
    let mut last_event: BTreeMap<String, usize> = BTreeMap::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some(member) = line.strip_prefix("E ").and_then(|l| l.split(' ').next()) {
            last_event.insert(member.to_string(), i);
        }
    }
    lines
        .into_iter()
        .enumerate()
        .filter(|(i, line)| match crate::persistence::decode_event(line) {
            Some((member, event)) => event.timestamp >= at || last_event.get(&member) == Some(i),
            None => true,
        })
        .map(|(_, line)| line)
        .collect()
}

/// Safe mediator pruning timestamp for one parameter slice (`Mediator.scala:499-520`).
fn latest_safe_pruning_ts_for_params(
    valid_from: i64,
    valid_until: Option<i64>,
    timeout: i64,
    clean_ts: i64,
) -> i64 {
    if clean_ts <= valid_from {
        return clean_ts;
    }
    let capped = valid_from.max(clean_ts.saturating_sub(timeout));
    match valid_until {
        None => capped,
        Some(vu) if clean_ts <= vu => capped,
        Some(vu) if vu.saturating_add(timeout) <= clean_ts => clean_ts,
        Some(_) => capped,
    }
}

/// Minimum safe mediator pruning timestamp across all parameter slices (`Mediator.scala:522-529`).
fn latest_safe_pruning_ts_before(changes: &[(i64, Option<i64>, i64)], clean_ts: i64) -> i64 {
    changes
        .iter()
        .map(|&(valid_from, valid_until, timeout)| {
            latest_safe_pruning_ts_for_params(valid_from, valid_until, timeout, clean_ts)
        })
        .min()
        .unwrap_or(clean_ts)
}

#[cfg(test)]
mod tests {
    use crate::onboarding::Registry;
    use crate::sequencing::Sequencer;
    use crate::synchronizer_state::{SynchronizerKeys, TopologyStore};
    use canton_participant::topology_wire as tw;
    use canton_proto::com::digitalasset::canton::protocol::v31::TopologyTransaction;
    use prost::Message;
    use std::sync::Arc;

    fn param_broadcast(keys: &SynchronizerKeys, serial: u32, timeout_micros: i64) -> Vec<u8> {
        let mut params = tw::default_dynamic_parameters();
        params.confirmation_response_timeout = Some(prost_types::Duration {
            seconds: timeout_micros / 1_000_000,
            nanos: ((timeout_micros % 1_000_000) * 1_000) as i32,
        });
        let first = tw::synchronizer_parameters_state(
            &format!("sync::{}", keys.synchronizer_namespace()),
            params,
        );
        let (data, version) = tw::unversioned(&first).unwrap();
        let mut tx = TopologyTransaction::decode(data.as_slice()).unwrap();
        tx.serial = serial;
        let bytes = tw::versioned(tx.encode_to_vec(), version);
        let signatures = vec![
            keys.namespace.sign_transaction(&bytes),
            keys.mediator_namespace.sign_transaction(&bytes),
        ];
        tw::topology_broadcast("sync", &[tw::signed(bytes, signatures)])
    }

    #[test]
    fn r13c_mediator_pruning_allows_valid_from_right_after_change() {
        let keys = Arc::new(SynchronizerKeys::generate());
        let store = Arc::new(TopologyStore::initial("sync", "seq", "med", &keys));
        let seq = Sequencer::new(
            format!("sync::{}::37-0", keys.synchronizer_namespace()),
            Arc::clone(&keys),
            Arc::new(Registry::default()),
            Arc::clone(&store),
        );
        // Slice 2 starts at valid_from = 90_000_000 with timeout = 60_000_000.
        // At clean = 100_000_000, slice 1 (valid_until 90_000_000, timeout 30s -> expires 120s > 100s? Wait: give slice 1 valid_until=40s)
        // Put slice 2 at sequenced=39_750_000 (valid_from=40_000_000, timeout=1s) so slice 1 expires by 70s,
        // and slice 3 at sequenced=89_750_000 (valid_from=90_000_000, timeout=60s).
        let o2 = store
            .accept_broadcast(&param_broadcast(&keys, 2, 1_000_000), 39_750_000)
            .unwrap();
        assert!(o2[0].is_in_force(), "{o2:?}");
        let o3 = store
            .accept_broadcast(&param_broadcast(&keys, 3, 60_000_000), 89_750_000)
            .unwrap();
        assert!(o3[0].is_in_force(), "{o3:?}");
        // Mediator has observed clean_ts = 100_000_000.
        // Slice 1 [BOT, 40s) timeout 30s: 40s + 30s = 70s <= 100s -> 100s
        // Slice 2 [40s, 90s) timeout 1s: 90s + 1s = 91s <= 100s -> 100s
        // Slice 3 [90s, None) timeout 60s: validFrom.max(100s - 60s) = 90s!
        let clean = 100_000_000;
        let _ = seq.inner.mediators[0].expire(clean);
        let res = seq.prune_mediators(90_000_000);
        assert!(
            res.is_ok(),
            "Scala latestSafePruningTs caps at validFrom (90s), not 100s - 60s = 40s: {res:?}"
        );
    }

    #[test]
    fn r13c_mediator_pruning_respects_earlier_longer_timeout_slice() {
        let keys = Arc::new(SynchronizerKeys::generate());
        let store = Arc::new(TopologyStore::initial("sync", "seq", "med", &keys));
        let seq = Sequencer::new(
            format!("sync::{}::37-0", keys.synchronizer_namespace()),
            Arc::clone(&keys),
            Arc::new(Registry::default()),
            Arc::clone(&store),
        );
        // Slice 1 [BOT, 40s) has 30s (expires at 70s <= 220s).
        let o2 = store
            .accept_broadcast(&param_broadcast(&keys, 2, 1_000_000_000), 39_750_000)
            .unwrap();
        assert!(o2[0].is_in_force(), "{o2:?}");
        // Slice 2 [40s, 200s) has 1000s (expires at 1200s). Slice 3 [200s, None) drops to 10s.
        let o3 = store
            .accept_broadcast(&param_broadcast(&keys, 3, 10_000_000), 199_750_000)
            .unwrap();
        assert!(o3[0].is_in_force(), "{o3:?}");

        let clean = 220_000_000;
        let _ = seq.inner.mediators[0].expire(clean);
        // At clean=220s, slice 2 still has valid_until(200s) + 1000s > 220s, so min is valid_from=40s.
        // Pruning at 210s (clean - 10s) MUST be refused!
        assert!(
            matches!(
                seq.prune_mediators(210_000_000),
                Err(crate::sequencing::MediatorPruneRefused::TooLate {
                    earliest: 40_000_000,
                    ..
                })
            ),
            "pruning at 210s ignores earlier 1000s-timeout slice [40s, 200s): {:?}",
            seq.prune_mediators(210_000_000)
        );
        assert!(seq.prune_mediators(40_000_000).is_ok());

        // Positive control once slice 2 expires at 200s + 1000s = 1_200_000_000:
        let clean_after = 1_200_000_000;
        let _ = seq.inner.mediators[0].expire(clean_after);
        assert!(seq.prune_mediators(1_190_000_000).is_ok());
    }
}
