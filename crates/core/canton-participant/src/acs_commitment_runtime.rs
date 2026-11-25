//! The ACS commitments a running participant computes, sends and compares (P-9): what this participant shares with each counter-participant,
//! digested at every reconciliation tick that sequencer time passes, and the counter-participants' commitments checked against it.
//!
//! [CANTON-NOTE: SEMANTICS] Ported from Canton 3.7.2's digest processor (`participant/commitment/`, on by default:
//! `enableNewAcsCommitmentProcessor = true`), not from the legacy `pruning/AcsCommitmentProcessor`:
//! - an activation or deactivation of a contract adds or removes, **for each stakeholder `s`**, one element per locally hosted stakeholder
//!   `l`: `singleDigestByteArray(cid, rc, orderedPartyPair(l, s))` (`DigestOps.partyDeltasForSingleContractChange`); the digest for a
//!   counter-participant is the sum of the party digests of the parties it hosts (`DigestOps.computeDeltas`, `invertMap(partyHostings)`);
//! - a checkpoint is made at the boundary `b = t - t % interval` when an event at `t` passes it and the previous one was at or before it
//!   (`RunningDigestProcessor.determineCheckpointAtReconciliationBoundary`); the changes of requests sequenced up to `b` are in it, because
//!   the node publishes in record-time order (a tick here waits for the requests in flight up to it);
//! - at a checkpoint every non-empty digest is sent to its counter-participant with the period `(last change - 1 µs, b]`
//!   (`AcsCommitmentSender.commitmentFromDigest`: `fromExclusive = digest.timestamp.immediatePredecessor`), one envelope each, addressed
//!   to that participant alone (`Recipients.cc`).
//!
//! [CANTON-NOTE: LIMITATION] The hosting used is the topology at the tick (the node re-digests on a hosting change, which moves its period's
//! start; the digests still agree once the hosting has settled). The node's self-addressed `AcsCommitmentSummary` and its randomized send
//! delay are not reproduced. The digests survive a restart (journal `commitments.journal`); a tick crossed and not yet sent when the process
//! stops is not sent, and the comparisons are kept in memory only.
use crate::acs_commitment::{AcsCommitmentTracker, PeriodStatus, PeriodVerdict};
use crate::lthash::{commitment_digest, digest_element, ordered_pair, LtHash16};
use crate::state_store::StateStore;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The reconciliation interval of the default dynamic parameters (60 s), for a participant that does not follow the topology.
pub const DEFAULT_RECONCILIATION_INTERVAL_MICROS: i64 = 60_000_000;

const JOURNAL: &str = "commitments.journal";

/// A commitment to send: the digest of what this participant shares with `counter_participant` at the tick `to_inclusive`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub counter_participant: String,
    pub from_exclusive: i64,
    pub to_inclusive: i64,
    /// The multihash of the set digest (`AcsCommitment.digest`).
    pub digest: Vec<u8>,
}

/// What this participant keeps of a contract it hosts a stakeholder of.
#[derive(Debug, Clone)]
struct Held {
    counter: i64,
    stakeholders: BTreeSet<String>,
    /// The stakeholders this participant hosted when the contract became active: whose pairs it adds (and later removes).
    local: BTreeSet<String>,
    active_from: i64,
    archived_at: Option<i64>,
}

impl Held {
    /// What the contract adds to the digest of `stakeholder`'s party.
    fn party_digest(&self, contract_id: &str, stakeholder: &str) -> LtHash16 {
        let pairs: BTreeSet<(&str, &str)> = self
            .local
            .iter()
            .map(|l| ordered_pair(l, stakeholder))
            .collect();
        let mut digest = LtHash16::empty();
        for (a, b) in pairs {
            digest.add(&digest_element(contract_id, self.counter, a, b));
        }
        digest
    }
}

/// The commitment state of one participant on one synchronizer.
#[derive(Default)]
pub struct Commitments {
    held: BTreeMap<String, Held>,
    /// party -> the latest deactivation folded away (a removal is a change of the party's digest).
    removed: BTreeMap<String, i64>,
    /// Ticks passed and not yet sent because a request sequenced before them is still in flight.
    due: BTreeSet<i64>,
    last_tick: Option<i64>,
    compared: AcsCommitmentTracker,
    store: Option<Arc<dyn StateStore>>,
}

fn join(parties: &BTreeSet<String>) -> String {
    parties.iter().cloned().collect::<Vec<_>>().join(",")
}

fn split(field: &str) -> BTreeSet<String> {
    field
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

impl Commitments {
    /// The state kept in `store` (replayed), or an empty one in memory.
    pub fn open(store: Option<Arc<dyn StateStore>>) -> Result<Self, String> {
        let mut state = Commitments::default();
        if let Some(store) = &store {
            let text = store.read(JOURNAL)?.unwrap_or_default();
            for line in text.lines() {
                let fields: Vec<&str> = line.split('\t').collect();
                let number = |i: usize| -> Result<i64, String> {
                    fields.get(i).and_then(|f| f.parse().ok()).ok_or_else(|| {
                        format!("{JOURNAL}: a record that is not understood: {line:?}")
                    })
                };
                match fields.first() {
                    Some(&"A") if fields.len() == 6 => state.apply_activate(
                        fields[1],
                        number(2)?,
                        number(3)?,
                        split(fields[4]),
                        split(fields[5]),
                    ),
                    Some(&"D") if fields.len() == 3 => {
                        state.apply_deactivate(fields[1], number(2)?)
                    }
                    Some(&"T") if fields.len() == 2 => state.apply_tick(number(1)?),
                    // the process died while writing the last record
                    _ => {}
                }
            }
        }
        state.store = store;
        Ok(state)
    }

    fn write(&self, record: &str) -> Result<(), String> {
        match &self.store {
            Some(store) => store.append(JOURNAL, record),
            None => Ok(()),
        }
    }

    /// A contract became active at `at` (the sequencing time of the request that created or assigned it).
    pub fn activate(
        &mut self,
        id: &str,
        at: i64,
        counter: i64,
        stakeholders: BTreeSet<String>,
        local: BTreeSet<String>,
    ) -> Result<(), String> {
        self.write(&format!(
            "A\t{id}\t{at}\t{counter}\t{}\t{}",
            join(&stakeholders),
            join(&local)
        ))?;
        self.apply_activate(id, at, counter, stakeholders, local);
        Ok(())
    }

    fn apply_activate(
        &mut self,
        id: &str,
        at: i64,
        counter: i64,
        stakeholders: BTreeSet<String>,
        local: BTreeSet<String>,
    ) {
        match self.held.get(id) {
            Some(old) if old.archived_at.is_none() => return,
            // a contract that comes back (an assignment after an unassignment): its removal stays a change
            Some(_) => self.fold(id),
            None => {}
        }
        self.held.insert(
            id.to_string(),
            Held {
                counter,
                stakeholders,
                local,
                active_from: at,
                archived_at: None,
            },
        );
    }

    /// A contract stopped being active at `at` (archived, or unassigned from this synchronizer).
    pub fn deactivate(&mut self, id: &str, at: i64) -> Result<(), String> {
        if !self.held.get(id).is_some_and(|h| h.archived_at.is_none()) {
            return Ok(());
        }
        self.write(&format!("D\t{id}\t{at}"))?;
        self.apply_deactivate(id, at);
        Ok(())
    }

    fn apply_deactivate(&mut self, id: &str, at: i64) {
        if let Some(held) = self.held.get_mut(id) {
            held.archived_at.get_or_insert(at);
        }
    }

    /// Takes in what an approved request changed. `hosted_here` says whether this participant hosts a party now.
    pub fn apply(
        &mut self,
        applied: &crate::view_acs::Applied,
        hosted_here: &dyn Fn(&str) -> bool,
    ) -> Result<Vec<String>, String> {
        let counters: BTreeMap<&str, i64> = applied
            .reassignment
            .iter()
            .flat_map(|(_, counters)| counters.iter().map(|(id, n)| (id.as_str(), *n)))
            .collect();
        let mut notes = Vec::new();
        for (id, instance) in &applied.created {
            match crate::reassignment_submit::contract_parties(instance) {
                Ok(parties) => {
                    let stakeholders: BTreeSet<String> = parties.stakeholders.into_iter().collect();
                    let local = stakeholders
                        .iter()
                        .filter(|p| hosted_here(p))
                        .cloned()
                        .collect();
                    let counter = counters.get(id.as_str()).copied().unwrap_or(0);
                    self.activate(id, applied.request_id, counter, stakeholders, local)?;
                }
                Err(e) => notes.push(format!(
                    "the ACS commitments leave out {id}: its instance does not decode: {e}"
                )),
            }
        }
        for id in &applied.consumed {
            self.deactivate(id, applied.request_id)?;
        }
        Ok(notes)
    }

    /// Notes the reconciliation boundary the event at `now` passed, if any (the previous event was at `previous`).
    pub fn pass(&mut self, previous: i64, now: i64, interval_micros: i64) {
        if interval_micros <= 0 {
            return;
        }
        let boundary = now - now.rem_euclid(interval_micros);
        if previous <= boundary && boundary < now {
            self.due.insert(boundary);
        }
    }

    /// The commitments of the ticks passed whose requests are all decided: `earliest_in_flight` is the earliest request still waiting for
    /// its verdict. `hosts_of` names the participants (uids) that host a party now; `me` is this participant's uid. Returns what to send and
    /// what the comparisons found.
    pub fn take_due(
        &mut self,
        earliest_in_flight: Option<i64>,
        me: &str,
        hosts_of: &dyn Fn(&str) -> Vec<String>,
    ) -> Result<(Vec<Outgoing>, Vec<String>), String> {
        let mut outgoing = Vec::new();
        let mut notes = Vec::new();
        while let Some(&tick) = self.due.first() {
            if earliest_in_flight.is_some_and(|request| request <= tick) {
                break;
            }
            self.due.remove(&tick);
            if self.last_tick.is_some_and(|last| last >= tick) {
                continue;
            }
            for (counter_participant, (digest, changed)) in self.digests_at(tick, me, hosts_of) {
                if digest.is_empty() {
                    continue;
                }
                let from_exclusive = changed - 1;
                let multihash = commitment_digest(&digest);
                let mut raw = [0u8; 32];
                raw.copy_from_slice(&multihash[2..]);
                match self
                    .compared
                    .record_local(&counter_participant, from_exclusive, tick, raw)
                {
                    Ok(verdict) => notes.extend(verdict_note(
                        &verdict,
                        &counter_participant,
                        from_exclusive,
                        tick,
                    )),
                    Err(e) => notes.push(format!("ACS commitment not recorded: {e}")),
                }
                outgoing.push(Outgoing {
                    counter_participant,
                    from_exclusive,
                    to_inclusive: tick,
                    digest: multihash,
                });
            }
            self.write(&format!("T\t{tick}"))?;
            self.apply_tick(tick);
        }
        Ok((outgoing, notes))
    }

    fn apply_tick(&mut self, tick: i64) {
        self.last_tick = Some(self.last_tick.map_or(tick, |last| last.max(tick)));
        let gone: Vec<String> = self
            .held
            .iter()
            .filter(|(_, h)| h.archived_at.is_some_and(|a| a <= tick))
            .map(|(id, _)| id.clone())
            .collect();
        for id in gone {
            self.fold(&id);
        }
    }

    /// Drops a deactivated contract, keeping the time of its removal as a change of its parties' digests.
    fn fold(&mut self, id: &str) {
        let Some(held) = self.held.remove(id) else {
            return;
        };
        let (Some(at), false) = (held.archived_at, held.local.is_empty()) else {
            return;
        };
        for s in held.stakeholders {
            let latest = self.removed.entry(s).or_insert(at);
            *latest = (*latest).max(at);
        }
    }

    /// The digest for each counter-participant at `tick` and the time of its last change.
    fn digests_at(
        &self,
        tick: i64,
        me: &str,
        hosts_of: &dyn Fn(&str) -> Vec<String>,
    ) -> BTreeMap<String, (LtHash16, i64)> {
        let mut hosts: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        let others = |party: &str| -> Vec<String> {
            hosts_of(party).into_iter().filter(|p| p != me).collect()
        };
        let mut out: BTreeMap<String, (LtHash16, i64)> = BTreeMap::new();
        for (id, held) in &self.held {
            if held.local.is_empty() || held.active_from > tick {
                continue;
            }
            let gone = held.archived_at.filter(|a| *a <= tick);
            let changed = gone.unwrap_or(held.active_from);
            for s in &held.stakeholders {
                let participants = hosts.entry(s).or_insert_with(|| others(s));
                if participants.is_empty() {
                    continue;
                }
                let part = gone.is_none().then(|| held.party_digest(id, s));
                for p in participants.iter() {
                    let entry = out
                        .entry(p.clone())
                        .or_insert_with(|| (LtHash16::empty(), i64::MIN));
                    if let Some(part) = &part {
                        entry.0.union(part);
                    }
                    entry.1 = entry.1.max(changed);
                }
            }
        }
        for (s, at) in &self.removed {
            if *at > tick {
                continue;
            }
            for p in others(s) {
                if let Some(entry) = out.get_mut(&p) {
                    entry.1 = entry.1.max(*at);
                }
            }
        }
        out
    }

    /// Checks and compares a commitment a counter-participant sent (`envelope` delivered at `delivered_at`), as
    /// `ReceivedAcsCommitmentValidator` and `ReceivedAcsCommitmentMatcher` do. `keys_of` gives a member's signing keys. `None` when the
    /// envelope is no commitment; otherwise what the check found.
    pub fn receive(
        &mut self,
        envelope: &[u8],
        delivered_at: i64,
        me: &str,
        physical_synchronizer_id: &str,
        keys_of: &dyn Fn(&str) -> Option<Vec<canton_algo::signing::PublicKey>>,
    ) -> Option<String> {
        let message = crate::acs_commitment::decode(envelope)?;
        let alarm =
            |why: String| format!("ACS_COMMITMENT_ALARM: ACS commitment validation failed: {why}");
        if message.counterparticipant != me {
            return Some(alarm(format!(
                "At {delivered_at}, (purportedly) {} sent an ACS commitment to me, but the commitment lists {} as the counterparticipant",
                message.sender, message.counterparticipant
            )));
        }
        if message.to_inclusive > delivered_at {
            return Some(alarm(format!(
                "Received an ACS commitment with a future timestamp. (Purported) sender: {}. Timestamp: {}, receive timestamp: {delivered_at}",
                message.sender, message.to_inclusive
            )));
        }
        let keys = keys_of(&format!("PAR::{}", message.sender)).unwrap_or_default();
        Some(
            match self
                .compared
                .receive_signed(envelope, physical_synchronizer_id, &keys)
            {
                Ok(verdict) => verdict_note(
                    &verdict,
                    &message.sender,
                    message.from_exclusive,
                    message.to_inclusive,
                )
                .unwrap_or_else(|| {
                    format!(
                        "ACS commitment from {} for period ({}, {}] is waiting for the local one",
                        message.sender, message.from_exclusive, message.to_inclusive
                    )
                }),
                Err(e) => alarm(e),
            },
        )
    }

    /// The latest tick whose commitments were computed and sent: pruning must not go past it.
    ///
    /// [CANTON-NOTE: SEMANTICS] With the digest processor (protocol version 37 disables the legacy one: `OnNewProtocolVersions`),
    /// `FirstUnsafeOffsetComputation` bounds pruning by the latest ACS digest checkpoint ("ACS digest ingestion") and the matcher's
    /// watermark, not by outstanding or mismatched commitments (`noOutstandingCommitments` is the legacy processor's bound). Received
    /// commitments are matched as their event is handled, so the matcher's watermark is the cursor, which is past the last tick.
    pub fn safe_to_prune(&self) -> Option<i64> {
        self.last_tick
    }

    /// Every comparison so far, by counter-participant and tick.
    pub fn periods(&self) -> Vec<PeriodStatus> {
        self.compared.periods()
    }
}

/// The line a comparison that settled is reported with (`None` while one side is missing).
fn verdict_note(
    verdict: &PeriodVerdict,
    sender: &str,
    from_exclusive: i64,
    to_inclusive: i64,
) -> Option<String> {
    match verdict {
        PeriodVerdict::Pending => None,
        PeriodVerdict::Matched => Some(format!(
            "Commitment correct for sender {sender} and period ({from_exclusive}, {to_inclusive}]"
        )),
        PeriodVerdict::Mismatched { local, remote } => Some(format!(
            "ACS_COMMITMENT_MISMATCH: The local commitment does not match the remote commitment: sender {sender}, period \
             ({from_exclusive}, {to_inclusive}], remote digest {}, local digest {}",
            hex::encode(remote),
            hex::encode(local)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parties(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    /// Two participants that host the two stakeholders of a contract compute the same digest for each other, and a tick waits for the
    /// requests sequenced before it.
    #[test]
    fn both_sides_compute_the_same_digest_and_a_tick_waits_for_earlier_requests() {
        let hosts = |party: &str| -> Vec<String> {
            match party {
                "alice" => vec!["p1".to_string()],
                "bob" => vec!["p2".to_string()],
                _ => Vec::new(),
            }
        };
        let mut p1 = Commitments::open(None).unwrap();
        let mut p2 = Commitments::open(None).unwrap();
        p1.activate(
            "00aa",
            5,
            0,
            parties(&["alice", "bob"]),
            parties(&["alice"]),
        )
        .unwrap();
        p2.activate("00aa", 5, 0, parties(&["alice", "bob"]), parties(&["bob"]))
            .unwrap();
        p1.pass(5, 61, 60);
        assert_eq!(
            p1.take_due(Some(59), "p1", &hosts).unwrap().0,
            vec![],
            "a request sequenced before the tick is still in flight"
        );
        let (to_p2, _) = p1.take_due(None, "p1", &hosts).unwrap();
        p2.pass(5, 70, 60);
        let (to_p1, _) = p2.take_due(None, "p2", &hosts).unwrap();
        assert_eq!(to_p2.len(), 1);
        assert_eq!((to_p2[0].from_exclusive, to_p2[0].to_inclusive), (4, 60));
        assert_eq!(to_p2[0].digest, to_p1[0].digest);
        assert_eq!(to_p1[0].counter_participant, "p1");

        // archived at 70: the next tick has nothing to send, and the removal survives the fold
        p1.deactivate("00aa", 70).unwrap();
        p1.pass(61, 121, 60);
        assert_eq!(p1.take_due(None, "p1", &hosts).unwrap().0, vec![]);
        assert_eq!(p1.removed.get("bob"), Some(&70));
        assert_eq!(p1.safe_to_prune(), Some(120));
    }

    #[test]
    fn the_state_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("acs10-commitments-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store: Arc<dyn StateStore> = crate::state_store::FileStore::new(&dir).unwrap();
        let hosts = |party: &str| -> Vec<String> {
            if party == "bob" {
                vec!["p2".to_string()]
            } else {
                vec!["p1".to_string()]
            }
        };
        let mut before = Commitments::open(Some(Arc::clone(&store))).unwrap();
        before
            .activate(
                "00aa",
                5,
                0,
                parties(&["alice", "bob"]),
                parties(&["alice"]),
            )
            .unwrap();
        before.pass(5, 61, 60);
        let (sent, _) = before.take_due(None, "p1", &hosts).unwrap();
        let mut after = Commitments::open(Some(store)).unwrap();
        assert_eq!(after.safe_to_prune(), Some(60));
        after.pass(61, 121, 60);
        let (again, _) = after.take_due(None, "p1", &hosts).unwrap();
        assert_eq!(again[0].digest, sent[0].digest);
        assert_eq!(again[0].from_exclusive, sent[0].from_exclusive);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
