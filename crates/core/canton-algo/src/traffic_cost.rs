//! The traffic cost of a batch, the one formula a sequencer charges by and a participant estimates with (S-SIM-001, S-NET-038).
//!
//! [CANTON-NOTE: SEMANTICS] Canton 3.7.2 `EventCostCalculator.computeEnvelopeCost`, measured on the official sequencer (S-NET-038 part
//! 11): an envelope costs its uncompressed content size `w` plus `w * recipients * read_vs_write_scaling_factor / 10000` (integer
//! division; a group address counts its members); a batch costs the sum over its envelopes plus `base_event_cost`.

/// The cost of a batch whose envelopes have these content sizes and numbers of recipients.
pub fn event_cost(
    read_vs_write_scaling: u64,
    base_event_cost: u64,
    envelopes: &[(usize, usize)],
) -> u64 {
    envelopes
        .iter()
        .map(|&(size, recipients)| {
            let write = size as u64;
            write + write * recipients as u64 * read_vs_write_scaling / 10_000
        })
        .sum::<u64>()
        + base_event_cost
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_measured_costs() {
        // 100 bytes to one recipient with factor 200 and base 7: the official node reported 109
        assert_eq!(event_cost(200, 7, &[(100, 1)]), 109);
        assert_eq!(event_cost(200, 7, &[(5000, 500)]), 5000 + 50_000 + 7);
        assert_eq!(event_cost(200, 0, &[]), 0);
    }
}
