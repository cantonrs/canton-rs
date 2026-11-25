//! Acknowledgements, and what the journal and the event logs may forget once every member has read past it.
use super::{now_micros, Sequencer, LAST};
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::protocol::v30::SignedContent;
use prost::Message;
use std::collections::BTreeMap;
use tonic::Status;

impl Sequencer {
    /// An acknowledgement (`SignedContent[AcknowledgeRequest]`) from the authenticated `member`: its events up to the timestamp may be
    /// forgotten. Refused unless it names the member, is signed by one of its registered keys and is not ahead of the sequencer's time; one
    /// that goes back changes nothing.
    pub fn acknowledge(&self, member: &str, signed_request: &[u8]) -> Result<(), Status> {
        let bad = |why: &str| Status::invalid_argument(format!("Invalid acknowledgement: {why}"));
        let (data, version) =
            tw::unversioned(signed_request).ok_or_else(|| bad("not versioned"))?;
        if version != sw::SIGNED_CONTENT_VERSION {
            return Err(bad("a signed content of another version"));
        }
        let signed = SignedContent::decode(data.as_slice()).map_err(|e| bad(&e.to_string()))?;
        let content = signed.content.ok_or_else(|| bad("no content"))?;
        let (request_bytes, _) = tw::unversioned(&content).ok_or_else(|| bad("not versioned"))?;
        let request = canton_proto::com::digitalasset::canton::sequencer::api::v30::AcknowledgeRequest::decode(
            request_bytes.as_slice(),
        )
        .map_err(|e| bad(&e.to_string()))?;
        if request.member != member {
            return Err(Status::permission_denied(format!(
                "Authenticated member {member} just tried to acknowledge on behalf of {} without permission",
                request.member
            )));
        }
        let hash = sw::acknowledgement_hash(&content);
        let registered = self
            .inner
            .registry
            .get(member)
            .ok_or_else(|| bad("the member is not registered"))?;
        // [CANTON-NOTE: SEMANTICS] `SignatureVerifier.verifyAcknowledgeRequestSignature` verifies at the acknowledged timestamp, which also
        // follows a session key the member delegated to
        let physical = &self.inner.physical_synchronizer_id;
        let verified = signed.signatures.iter().any(|s| {
            crate::submission_validator::verifies_on(
                &registered.signing_keys,
                s,
                &hash,
                physical,
                request.timestamp,
            )
        });
        if !verified {
            return Err(bad("the signature of the member does not verify"));
        }
        // [CANTON-NOTE: SEMANTICS] `BlockChunkProcessor` refuses an acknowledgement after the last timestamp the sequencer has decided
        // (`InvalidAcknowledgementTimestamp`, an alarm: `INVALID_ARGUMENT`, its text redacted on the official node). Here every time up to the
        // clock is decided: the next event is after it, and `GetTime` answers it.
        let reached = LAST.load(std::sync::atomic::Ordering::SeqCst);
        if request.timestamp > reached {
            return Err(Status::invalid_argument(format!(
                "INVALID_ACKNOWLEDGEMENT_TIMESTAMP(5,0): Member {member} has acknowledged the timestamp {} when only events with timestamps at most {} have been delivered.",
                canton_participant::topology_state::iso_utc(request.timestamp),
                canton_participant::topology_state::iso_utc(reached)
            )));
        }
        let mut acks = self
            .inner
            .acks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // an acknowledgement that goes back is a no-op: the member said it is past it already
        if acks
            .get(member)
            .is_some_and(|known| *known >= request.timestamp)
        {
            return Ok(());
        }
        if let Some(journal) = self.inner.journal.get() {
            journal.write(&format!("K {member} {}", request.timestamp));
        }
        acks.insert(member.to_string(), request.timestamp);
        Ok(())
    }

    /// Takes a journaled acknowledgement back (no journaling).
    pub(crate) fn restore_ack(&self, member: String, timestamp: i64) {
        let mut acks = self
            .inner
            .acks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let known = acks.entry(member).or_insert(timestamp);
        *known = (*known).max(timestamp);
    }

    /// The events every member acknowledged are forgotten: each member's log loses what is up to its acknowledgement. The chain links of
    /// the events that stay are not changed (the next event still names the one before it).
    pub(crate) fn forget_acknowledged(&self) -> usize {
        let acks = self
            .inner
            .acks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut events = self
            .inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut forgotten = 0;
        for (member, until) in acks {
            if let Some(log) = events.get_mut(&member) {
                let before = log.len();
                // [CANTON-NOTE: INVARIANT] A member's last event stays: the next event names it as `previous_timestamp`, and a log
                // emptied here would start a new chain (`previous = None`) that the member refuses as a gap.
                let last = log.last().map(|e| e.timestamp);
                log.retain(|e| e.timestamp > until || Some(e.timestamp) == last);
                forgotten += before - log.len();
            }
        }
        forgotten
    }

    /// The oldest request any mediator still waits to decide.
    pub(crate) fn earliest_pending_request(&self) -> Option<i64> {
        self.inner
            .mediators
            .iter()
            .filter_map(|m| m.earliest_pending())
            .min()
    }

    /// The journal lines that describe the state as it is now, shorter than the journal that led to it: the registrations and the topology
    /// are kept whole; an event only while its member may still read it; an acknowledgement once (the latest); what the mediator handled only
    /// from the oldest request still pending (an earlier input cannot change a request that is waiting).
    pub(crate) fn compact(&self, lines: &[String]) -> Vec<String> {
        let acks = self
            .inner
            .acks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Self::compact_with(
            lines,
            &acks,
            self.earliest_pending_request(),
            LAST.load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    /// `reached` is the latest sequencing time: an aggregation whose maximum sequencing time is before it can take no more requests.
    pub(super) fn compact_with(
        lines: &[String],
        acks: &BTreeMap<String, i64>,
        earliest: Option<i64>,
        reached: i64,
    ) -> Vec<String> {
        // of each member's traffic lines only the last of each kind tells its state
        let mut last_traffic: BTreeMap<(u8, &str), usize> = BTreeMap::new();
        for (i, line) in lines.iter().enumerate() {
            if let (Some(kind @ (b'T' | b'P')), Some(member)) =
                (line.as_bytes().first(), crate::traffic::line_member(line))
            {
                last_traffic.insert((*kind, member), i);
            }
        }
        // each member's last event stays (see `forget_acknowledged`)
        let mut last_event: BTreeMap<&str, usize> = BTreeMap::new();
        for (i, line) in lines.iter().enumerate() {
            if let Some(member) = line.strip_prefix("E ").and_then(|l| l.split(' ').next()) {
                last_event.insert(member, i);
            }
        }
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let keep = match line.as_bytes().first() {
                Some(kind @ (b'T' | b'P')) => crate::traffic::line_member(line)
                    .is_none_or(|member| last_traffic.get(&(*kind, member)) == Some(&i)),
                Some(b'E') => crate::persistence::decode_event(line).is_none_or(|(member, e)| {
                    acks.get(&member).is_none_or(|until| e.timestamp > *until)
                        || last_event.get(member.as_str()) == Some(&i)
                }),
                Some(b'H') => crate::persistence::decode_mediator_input(line)
                    .is_none_or(|(at, _, _)| earliest.is_some_and(|e| at >= e)),
                Some(b'X') => line[2..]
                    .trim()
                    .parse::<i64>()
                    .ok()
                    .is_none_or(|at| earliest.is_some_and(|e| at >= e)),
                Some(b'K') => false,
                Some(b'G') => {
                    crate::aggregation::contribution_expiry(line).is_none_or(|max| max >= reached)
                }
                _ => true,
            };
            if keep {
                out.push(line.clone());
            }
        }
        for (member, ts) in acks {
            out.push(format!("K {member} {ts}"));
        }
        out
    }

    /// Shortens the running server's state and journal the way the start does: the events every member acknowledged are forgotten, and the
    /// journal loses what no longer matters. Returns `(events forgotten, journal lines before, after)`.
    ///
    /// [CANTON-NOTE: INVARIANT] What was journaled after this looked at the acknowledgements and the requests in flight is kept: the clock
    /// is read **before** the mediator's pending requests, and a mediator input is dropped only when it is older than both, so an input that
    /// belongs to a request registered in between (its time is later than the clock read first) survives. The acknowledgements only grow, so a
    /// stale copy keeps more, never less.
    pub fn compact_running(&self) -> Option<(usize, usize, usize)> {
        let journal = std::sync::Arc::clone(self.inner.journal.get()?);
        let reached = LAST.load(std::sync::atomic::Ordering::SeqCst);
        let clock = now_micros();
        let pending = self.earliest_pending_request();
        let keep_from = pending.map_or(clock, |p| p.min(clock));
        let acks = self
            .inner
            .acks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let forgotten = self.forget_acknowledged();
        let (before, after) = journal
            .rewrite(|lines| Self::compact_with(&lines, &acks, Some(keep_from), reached))
            .ok()?;
        Some((forgotten, before, after))
    }
}
