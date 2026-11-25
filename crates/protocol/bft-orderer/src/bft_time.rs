//! BFT time (`core/modules/output/time/BftTime.scala`): how the time of a block and of the requests in it follow from the commits that ordered the block before it.
//! All times are microseconds since the epoch (`CantonTimestamp`; its granularity is one microsecond).
//!
//! [CANTON-NOTE: SEMANTICS] Every sequencer of the synchronizer computes the same times from the same blocks, so the events it hands to the participants carry the same
//! sequencing times (a participant that reads from two sequencers compares them).

/// The least time between two blocks (`MinimumBlockTimeGranularity`, one millisecond).
pub const MINIMUM_BLOCK_TIME_GRANULARITY_MICROS: i64 = 1_000;

/// The least time between two requests (`RequestTimeGranularity`, one microsecond).
pub const REQUEST_TIME_GRANULARITY_MICROS: i64 = 1;

/// `BftTime.MaxRequestsPerBlock`: a block holds at most as many requests as fit in a block time granularity, minus one slot for the topology tick.
pub const MAX_REQUESTS_PER_BLOCK: usize =
    (MINIMUM_BLOCK_TIME_GRANULARITY_MICROS / REQUEST_TIME_GRANULARITY_MICROS - 1) as usize;

/// `median`: the first of the upper half of the sorted times (the middle one for an odd count, the upper middle for an even count); the epoch (zero) when there
/// are none.
pub fn median(timestamps: &[i64]) -> i64 {
    let mut sorted = timestamps.to_vec();
    sorted.sort_unstable();
    sorted.get(sorted.len() / 2).copied().unwrap_or(0)
}

/// `blockBftTime`: the median of the times in the canonical commit set, and at least one millisecond after the block before. The block's time is the time of its first
/// request.
pub fn block_bft_time(canonical_commit_timestamps: &[i64], previous_block_bft_time: i64) -> i64 {
    median(canonical_commit_timestamps)
        .max(previous_block_bft_time + MINIMUM_BLOCK_TIME_GRANULARITY_MICROS)
}

/// `requestBftTime`: the time of the request at `transaction_index` in the block.
pub fn request_bft_time(block_bft_time: i64, transaction_index: usize) -> i64 {
    block_bft_time + REQUEST_TIME_GRANULARITY_MICROS * transaction_index as i64
}

/// `epochEndBftTime`: the time of the last request of the last block of an epoch, or the time of the block when it has none.
pub fn epoch_end_bft_time(epoch_last_block_bft_time: i64, epoch_last_block_request_count: usize) -> i64 {
    if epoch_last_block_request_count == 0 {
        epoch_last_block_bft_time
    } else {
        request_bft_time(epoch_last_block_bft_time, epoch_last_block_request_count - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_median_is_the_first_of_the_upper_half() {
        assert_eq!(median(&[]), 0);
        assert_eq!(median(&[5]), 5);
        assert_eq!(median(&[9, 1, 5]), 5);
        // an even count takes the upper middle
        assert_eq!(median(&[4, 1, 3, 2]), 3);
    }

    #[test]
    fn a_block_is_at_least_a_millisecond_after_the_one_before() {
        assert_eq!(block_bft_time(&[10_000, 11_000, 12_000], 0), 11_000);
        // the median is not enough: one millisecond after the previous block
        assert_eq!(block_bft_time(&[10_000, 10_100, 10_200], 10_000), 11_000);
        // no commits at all: only the previous block counts
        assert_eq!(block_bft_time(&[], 5_000), 6_000);
    }

    #[test]
    fn requests_follow_the_block_time_by_a_microsecond_each() {
        assert_eq!(request_bft_time(1_000_000, 0), 1_000_000);
        assert_eq!(request_bft_time(1_000_000, 7), 1_000_007);
        assert_eq!(epoch_end_bft_time(1_000_000, 0), 1_000_000);
        assert_eq!(epoch_end_bft_time(1_000_000, 3), 1_000_002);
        assert_eq!(MAX_REQUESTS_PER_BLOCK, 999);
    }
}
