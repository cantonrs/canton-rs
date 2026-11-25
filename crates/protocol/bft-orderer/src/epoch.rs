//! Leaders and segments of an epoch (B3), from `core/modules/consensus/iss/EpochState.scala` (`computeSegments`) and `core/modules/output/leaders`
//! (`LeaderSelectionPolicy.rotateLeaders`, `BlacklistLeaderSelectionPolicy.computeLeaders`). `doc/slices/BFT-CONSENSUS-SPEC.md` 1.2 and 1.3.
use crate::topology::EpochInfo;

/// `rotateLeaders(sorted, e) = sorted.drop(e % size) ++ sorted.take(e % size)`: the leaders of epoch `epoch` are the nodes (not blacklisted) in the order of their
/// ids, rotated left by `epoch mod n`.
pub fn leaders_of_epoch(nodes: &[String], epoch: i64) -> Vec<String> {
    let mut sorted: Vec<String> = nodes.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.is_empty() {
        return sorted;
    }
    let by = (epoch.rem_euclid(sorted.len() as i64)) as usize;
    sorted.rotate_left(by);
    sorted
}

/// The blocks one leader orders in an epoch, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub original_leader: String,
    pub slots: Vec<i64>,
}

/// `computeSegments`: leader `i` owns the blocks `start + i, start + i + n, …` below `start + length`, `n` being the number of leaders (not cut to the length). At
/// most `length` leaders get a segment (`leaders.take(epochLength)`).
pub fn compute_segments(leaders: &[String], start_block: i64, length: i64) -> Vec<Segment> {
    let step = leaders.len() as i64;
    leaders
        .iter()
        .take(length.max(0) as usize)
        .enumerate()
        .map(|(i, leader)| Segment {
            original_leader: leader.clone(),
            slots: (0..)
                .map(|k| start_block + i as i64 + k * step)
                .take_while(|b| *b < start_block + length)
                .collect(),
        })
        .collect()
}

/// An epoch as the consensus works in it: its info, its leaders and the segments of the leaders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Epoch {
    pub info: EpochInfo,
    pub leaders: Vec<String>,
    pub segments: Vec<Segment>,
}

impl Epoch {
    pub fn new(info: EpochInfo, nodes: &[String]) -> Self {
        let leaders = leaders_of_epoch(nodes, info.number);
        let segments = compute_segments(&leaders, info.start_block_number, info.length);
        Self {
            info,
            leaders,
            segments,
        }
    }

    /// An epoch whose leaders the leader selection policy chose (`BlacklistLeaderSelectionPolicy.getLeaders`).
    pub fn with_leaders(info: EpochInfo, leaders: Vec<String>) -> Self {
        let segments = compute_segments(&leaders, info.start_block_number, info.length);
        Self {
            info,
            leaders,
            segments,
        }
    }

    /// `blockToLeader`.
    pub fn leader_of(&self, block: i64) -> Option<&str> {
        self.segments
            .iter()
            .find(|s| s.slots.contains(&block))
            .map(|s| s.original_leader.as_str())
    }

    pub fn segment_of(&self, leader: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.original_leader == leader)
    }

    pub fn contains_block(&self, block: i64) -> bool {
        block >= self.info.start_block_number && block <= self.info.last_block_number()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes() -> Vec<String> {
        vec!["C".into(), "A".into(), "B".into()]
    }

    #[test]
    fn leaders_rotate_left_by_the_epoch_number() {
        let l = |e| leaders_of_epoch(&nodes(), e);
        assert_eq!(l(0), ["A", "B", "C"]);
        assert_eq!(l(1), ["B", "C", "A"]);
        assert_eq!(l(2), ["C", "A", "B"]);
        assert_eq!(l(3), ["A", "B", "C"]);
    }

    /// The spec's example 1: length 20, leaders [A, B, C], start S.
    #[test]
    fn the_segments_of_length_20_and_three_leaders() {
        let s = compute_segments(&leaders_of_epoch(&nodes(), 0), 100, 20);
        assert_eq!(s[0].slots, [100, 103, 106, 109, 112, 115, 118]);
        assert_eq!(s[1].slots, [101, 104, 107, 110, 113, 116, 119]);
        assert_eq!(s[2].slots, [102, 105, 108, 111, 114, 117]);
    }

    /// The official default: segment length 10 times 3 nodes is 30, ten slots each.
    #[test]
    fn the_segments_of_length_30_have_ten_slots_each() {
        let s = compute_segments(&leaders_of_epoch(&nodes(), 1), 60, 30);
        assert!(s.iter().all(|x| x.slots.len() == 10));
        assert_eq!(s[0].original_leader, "B");
        assert_eq!(s[2].slots.last(), Some(&89));
    }

    #[test]
    fn an_epoch_finds_the_leader_of_every_block() {
        let e = Epoch::new(
            EpochInfo {
                number: 3,
                start_block_number: 60,
                length: 20,
            },
            &nodes(),
        );
        // epoch 3 rotates by 0: [A, B, C]
        assert_eq!(e.leader_of(60), Some("A"));
        assert_eq!(e.leader_of(61), Some("B"));
        assert_eq!(e.leader_of(62), Some("C"));
        assert_eq!(e.leader_of(79), Some("B"));
        assert_eq!(e.leader_of(80), None);
        assert!(e.contains_block(79) && !e.contains_block(80) && !e.contains_block(59));
    }
}
