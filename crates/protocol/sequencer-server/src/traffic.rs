//! Traffic control (AT-O07, S-NET-038): what a submission costs, the base traffic every member accumulates, the extra traffic a member
//! is given by a purchase, and the refusal of a submission its sender cannot pay for.
//!
//! [CANTON-NOTE: SEMANTICS] Measured on the official 3.7.2 sequencer with traffic control on (`ORACLE_TRAFFIC_ON`, S-NET-038 part 11)
//! and read from `EventCostCalculator`, `TrafficConsumed` and `SequencerRateLimitManagerImpl`:
//! - the cost of an envelope is its plain (uncompressed) content size `w` plus `w * recipients * read_vs_write_scaling_factor / 10000`
//!   (integer division; a group address counts its members), the cost of a submission the sum over its envelopes plus `base_event_cost`;
//! - a member has base traffic that refills at `max_base_traffic_amount / max_base_traffic_accumulation_duration` up to
//!   `max_base_traffic_amount` (it starts full), and the extra traffic it was sold; a submission spends the base traffic first;
//! - a submission must carry its cost: none, or less than the cost, is refused (`IncorrectEventCost`), more is accepted and **the
//!   amount it carries is spent**; a cost above what the member has is refused (`SEQUENCER_NOT_ENOUGH_TRAFFIC_CREDIT`);
//! - only participants and mediators pay (not sequencers).
//!
//! What every member spent and was sold is journaled (`T` and `P` lines, see [`consumed_line`] and [`purchased_line`]): a restart does not
//! hand out the base traffic again.
use canton_proto::com::digitalasset::canton::protocol::v30::TrafficControlParameters;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// The traffic control parameters in force (the dynamic synchronizer parameters' `traffic_control`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficParams {
    pub max_base: u64,
    pub accumulation_micros: i64,
    pub scaling: u64,
    pub enforce: bool,
    pub base_event_cost: u64,
    pub free_confirmation_responses: bool,
    /// `set_balance_request_submission_window_size`: what the maximum sequencing time of a purchase is aligned to.
    pub submission_window_micros: i64,
}

impl TrafficParams {
    pub fn from_proto(p: &TrafficControlParameters) -> Self {
        let accumulation = p.max_base_traffic_accumulation_duration.unwrap_or_default();
        Self {
            max_base: p.max_base_traffic_amount,
            accumulation_micros: accumulation.seconds * 1_000_000
                + accumulation.nanos as i64 / 1000,
            scaling: p.read_vs_write_scaling_factor as u64,
            enforce: p.enforce_rate_limiting,
            base_event_cost: p.base_event_cost.unwrap_or(0),
            free_confirmation_responses: p.free_confirmation_responses,
            // `TrafficControlParameters.DefaultSetBalanceRequestSubmissionWindowSize`: two minutes
            submission_window_micros: p
                .set_balance_request_submission_window_size
                .map_or(120_000_000, |w| {
                    w.seconds * 1_000_000 + w.nanos as i64 / 1000
                }),
        }
    }

    /// The cost of a batch whose envelopes have these plain sizes and numbers of recipients.
    pub fn event_cost(&self, envelopes: &[(usize, usize)]) -> u64 {
        canton_algo::traffic_cost::event_cost(self.scaling, self.base_event_cost, envelopes)
    }
}

/// What a member has spent: its state at the time `at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consumed {
    pub at: i64,
    pub extra_consumed: u64,
    pub base_remainder: u64,
    /// What was spent at `at` (0 when the state was only moved on in time).
    pub last_cost: u64,
}

impl Consumed {
    /// The base traffic at `at`: what remained, refilled for the time since, up to the maximum.
    ///
    /// [CANTON-NOTE: SEMANTICS] The refill is `max_base / accumulation (bytes per microsecond, a double) * elapsed microseconds`, cut to
    /// a whole number (`TrafficConsumed.computeBaseTrafficAt`).
    pub fn base_at(&self, at: i64, p: &TrafficParams) -> u64 {
        let elapsed = (at - self.at).max(0) as f64;
        let rate = p.max_base as f64 / p.accumulation_micros.max(1) as f64;
        let refill = (rate * elapsed) as u64;
        p.max_base.min(self.base_remainder.saturating_add(refill))
    }

    /// Spends `cost` at `at`: base traffic first, the rest from the extra traffic.
    pub fn consume(&mut self, at: i64, p: &TrafficParams, cost: u64) {
        let base = self.base_at(at, p);
        let from_base = base.min(cost);
        *self = Consumed {
            at,
            extra_consumed: self.extra_consumed + (cost - from_base),
            base_remainder: base - from_base,
            last_cost: cost,
        };
    }
}

/// The extra traffic a member was sold: the latest purchase (by serial).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Purchased {
    pub serial: u32,
    pub extra_limit: u64,
    pub at: i64,
}

/// Why a submission is not paid for.
#[derive(Debug, PartialEq, Eq)]
pub enum Unpaid {
    /// No cost, or less than the cost.
    IncorrectCost { submitted: Option<u64>, cost: u64 },
    /// More than the member has.
    NotEnough {
        cost: u64,
        available: u64,
        state: String,
    },
}

/// The traffic of every member.
#[derive(Default)]
pub struct Traffic {
    members: Mutex<BTreeMap<String, (Consumed, Option<Purchased>)>>,
}

/// `TrafficState(...)` as the node prints it (the `serial` only when there was a purchase).
fn state_text(consumed: &Consumed, purchased: Option<&Purchased>, base: u64, at: i64) -> String {
    let limit = purchased.map_or(0, |p| p.extra_limit);
    let serial = purchased.map_or(String::new(), |p| format!(", serial = {}", p.serial));
    format!(
        "TrafficState(extraTrafficLimit = {limit}, extraTrafficConsumed = {}, baseTrafficRemainder = {base}, lastConsumedCost = {}, timestamp = {}{serial}, availableTraffic = {})",
        consumed.extra_consumed,
        consumed.last_cost,
        canton_participant::topology_state::iso_utc(at),
        (limit.saturating_sub(consumed.extra_consumed)) + base
    )
}

impl Traffic {
    fn entry<'a>(
        members: &'a mut BTreeMap<String, (Consumed, Option<Purchased>)>,
        member: &str,
        now: i64,
        p: &TrafficParams,
    ) -> &'a mut (Consumed, Option<Purchased>) {
        // a member first seen has its base traffic full (`TrafficConsumed.empty`)
        members.entry(member.to_string()).or_insert_with(|| {
            (
                Consumed {
                    at: now,
                    extra_consumed: 0,
                    base_remainder: p.max_base,
                    last_cost: 0,
                },
                None,
            )
        })
    }

    /// Checks that `member` pays for a submission costing `cost` with `submitted` at `now`: the amount it will spend, or why not.
    pub fn check(
        &self,
        member: &str,
        submitted: Option<u64>,
        cost: u64,
        now: i64,
        p: &TrafficParams,
    ) -> Result<u64, Unpaid> {
        let spend = match submitted {
            Some(s) if s >= cost => s,
            _ if cost == 0 => 0,
            _ => return Err(Unpaid::IncorrectCost { submitted, cost }),
        };
        let mut members = self
            .members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (consumed, purchased) = Self::entry(&mut members, member, now, p);
        let base = consumed.base_at(now.max(consumed.at), p);
        let extra_left = purchased
            .as_ref()
            .map_or(0, |b| b.extra_limit)
            .saturating_sub(consumed.extra_consumed);
        if base + extra_left < spend {
            return Err(Unpaid::NotEnough {
                cost: spend,
                available: base + extra_left,
                // the state the refusal shows is the member's last one, as it was then (measured: the node prints the time of the last spend)
                state: state_text(
                    consumed,
                    purchased.as_ref(),
                    consumed.base_remainder,
                    consumed.at,
                ),
            });
        }
        Ok(spend)
    }

    /// `member` spends `cost` at the sequencing time `at`.
    pub fn consume(&self, member: &str, cost: u64, at: i64, p: &TrafficParams) -> Consumed {
        let mut members = self
            .members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (consumed, _) = Self::entry(&mut members, member, at, p);
        consumed.consume(at.max(consumed.at), p, cost);
        consumed.clone()
    }

    /// A purchase: the extra traffic of `member` is `extra_limit` from now on, when `serial` is greater than the last purchase's.
    pub fn purchase(
        &self,
        member: &str,
        serial: u32,
        extra_limit: u64,
        now: i64,
        p: &TrafficParams,
    ) -> Result<(), u32> {
        let mut members = self
            .members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (_, purchased) = Self::entry(&mut members, member, now, p);
        if let Some(last) = purchased {
            if serial <= last.serial {
                return Err(last.serial);
            }
        }
        *purchased = Some(Purchased {
            serial,
            extra_limit,
            at: now,
        });
        Ok(())
    }

    /// The serial of the latest purchase applied for `member`.
    pub fn last_serial(&self, member: &str) -> Option<u32> {
        self.members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(member)
            .and_then(|(_, purchased)| purchased.as_ref().map(|p| p.serial))
    }

    /// The journal lines of what `member` has now: its `T` line, and its `P` line once it bought traffic.
    pub(crate) fn journal_lines(&self, member: &str) -> Vec<String> {
        let members = self
            .members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((consumed, purchased)) = members.get(member) else {
            return Vec::new();
        };
        let mut lines = vec![consumed_line(member, consumed)];
        lines.extend(purchased.as_ref().map(|p| purchased_line(member, p)));
        lines
    }

    /// Takes a journaled line back (`T` or `P`); `None` if it does not decode.
    pub(crate) fn restore(&self, line: &str) -> Option<()> {
        let mut f = line.get(2..)?.split(' ');
        let member = f.next()?.to_string();
        let mut numbers = f.map(|n| n.parse::<i64>().ok());
        let mut next = || numbers.next().flatten();
        let mut members = self
            .members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match line.as_bytes().first() {
            Some(b'T') => {
                let consumed = Consumed {
                    at: next()?,
                    extra_consumed: u64::try_from(next()?).ok()?,
                    base_remainder: u64::try_from(next()?).ok()?,
                    last_cost: u64::try_from(next()?).ok()?,
                };
                match members.get_mut(&member) {
                    Some((known, _)) => *known = consumed,
                    None => {
                        members.insert(member, (consumed, None));
                    }
                }
            }
            Some(b'P') => {
                let purchased = Purchased {
                    serial: u32::try_from(next()?).ok()?,
                    extra_limit: u64::try_from(next()?).ok()?,
                    at: next()?,
                };
                // [CANTON-NOTE: INVARIANT] Every purchase is journaled with the member's `T` line (see `journal_lines`), and the
                // compaction keeps the last of each: this placeholder is replaced by that line wherever it stands.
                let entry = members.entry(member).or_insert_with(|| {
                    (
                        Consumed {
                            at: purchased.at,
                            extra_consumed: 0,
                            base_remainder: 0,
                            last_cost: 0,
                        },
                        None,
                    )
                });
                entry.1 = Some(purchased);
            }
            _ => return None,
        }
        Some(())
    }

    /// The state of `member` at `now`: `(extra purchased, extra consumed, base remainder, last cost, timestamp, serial)`.
    pub fn state(
        &self,
        member: &str,
        now: i64,
        p: &TrafficParams,
    ) -> (u64, u64, u64, u64, i64, Option<u32>) {
        let mut members = self
            .members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (consumed, purchased) = Self::entry(&mut members, member, now, p);
        let at = now.max(consumed.at);
        (
            purchased.as_ref().map_or(0, |b| b.extra_limit),
            consumed.extra_consumed,
            consumed.base_at(at, p),
            // a state moved on in time has spent nothing at its time
            if at == consumed.at {
                consumed.last_cost
            } else {
                0
            },
            at,
            purchased.as_ref().map(|b| b.serial),
        )
    }
}

/// What `member` has spent, as of its last spend: `T <member> <at> <extra consumed> <base remainder> <last cost>`.
pub(crate) fn consumed_line(member: &str, c: &Consumed) -> String {
    format!(
        "T {member} {} {} {} {}",
        c.at, c.extra_consumed, c.base_remainder, c.last_cost
    )
}

/// The latest purchase of `member`: `P <member> <serial> <extra limit> <at>`.
pub(crate) fn purchased_line(member: &str, p: &Purchased) -> String {
    format!("P {member} {} {} {}", p.serial, p.extra_limit, p.at)
}

/// The member a `T` or `P` line is about.
pub(crate) fn line_member(line: &str) -> Option<&str> {
    line.get(2..)?.split(' ').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parameters of the oracle measurement: 1000 bytes of base traffic over 10 minutes, factor 200, base event cost 7.
    fn measured() -> TrafficParams {
        TrafficParams {
            max_base: 1000,
            accumulation_micros: 600_000_000,
            scaling: 200,
            enforce: true,
            base_event_cost: 7,
            free_confirmation_responses: false,
            submission_window_micros: 120_000_000,
        }
    }

    #[test]
    fn the_costs_and_spending_are_what_the_official_sequencer_measured() {
        let p = measured();
        // 100 bytes to one recipient: 100 + 2 + 7 (the node reported event cost 109, write 100, read 2)
        let cost = p.event_cost(&[(100, 1)]);
        assert_eq!(cost, 109);
        let t = Traffic::default();
        let start = 1_000_000_000;
        assert!(matches!(
            t.check("PAR::a", None, cost, start, &p),
            Err(Unpaid::IncorrectCost {
                submitted: None,
                cost: 109
            })
        ));
        assert!(matches!(
            t.check("PAR::a", Some(108), cost, start, &p),
            Err(Unpaid::IncorrectCost { .. })
        ));
        // too much is accepted and what was sent is spent: 1000 -> 886
        assert_eq!(t.check("PAR::a", Some(114), cost, start, &p), Ok(114));
        assert_eq!(t.consume("PAR::a", 114, start, &p).base_remainder, 886);
        // 2.6 s later the right cost: 886 + 4 (refill at 1000/600 s) - 109 = 781
        let later = start + 2_610_000;
        assert_eq!(t.check("PAR::a", Some(109), cost, later, &p), Ok(109));
        assert_eq!(t.consume("PAR::a", 109, later, &p).base_remainder, 781);
        // 5000 bytes cost 5107: more than there is
        let big = p.event_cost(&[(5000, 1)]);
        assert_eq!(big, 5107);
        match t.check("PAR::a", Some(big), big, later + 1, &p) {
            Err(Unpaid::NotEnough { state, .. }) => assert!(
                state.contains("baseTrafficRemainder = 781, lastConsumedCost = 109"),
                "{state}"
            ),
            other => panic!("{other:?}"),
        }
        // a purchase of 10000, then the 5107 spends the base traffic first and the rest from the extra traffic
        t.purchase("PAR::a", 1, 10_000, later + 3_400_000, &p)
            .unwrap();
        assert_eq!(
            t.purchase("PAR::a", 1, 20_000, later + 3_400_001, &p),
            Err(1)
        );
        let at = later + 8_400_000;
        let base = t.state("PAR::a", at, &p).2;
        assert_eq!(t.check("PAR::a", Some(big), big, at, &p), Ok(big));
        let after = t.consume("PAR::a", big, at, &p);
        assert_eq!(after.base_remainder, 0);
        assert_eq!(after.extra_consumed, big - base);
        let (limit, extra, _, _, _, serial) = t.state("PAR::a", at + 1, &p);
        assert_eq!((limit, extra, serial), (10_000, big - base, Some(1)));
    }

    #[test]
    fn a_group_address_counts_its_members_and_nothing_costs_nothing() {
        let p = measured();
        // 5000 bytes to a group of 500 members at factor 200: 5000 + 5000 * 500 * 200 / 10000 + 7
        assert_eq!(p.event_cost(&[(5000, 500)]), 5000 + 50_000 + 7);
        let free = TrafficParams {
            base_event_cost: 0,
            ..measured()
        };
        assert_eq!(free.event_cost(&[]), 0);
        assert_eq!(Traffic::default().check("PAR::a", None, 0, 1, &free), Ok(0));
    }
}
