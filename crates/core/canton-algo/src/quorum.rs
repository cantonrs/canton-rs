#[derive(Debug, PartialEq, Eq)]
pub struct QuorumError;

pub fn tolerated_faults(nodes: i32) -> Result<i32, QuorumError> {
    if nodes < 1 {
        return Err(QuorumError);
    }
    Ok((nodes - 1) / 3)
}

pub fn weak_quorum_size(nodes: i32) -> Result<i32, QuorumError> {
    Ok(tolerated_faults(nodes)? + 1)
}

pub fn strong_quorum_size(nodes: i32) -> Result<i32, QuorumError> {
    if nodes < 1 {
        return Err(QuorumError);
    }
    if nodes <= 3 {
        return Ok(nodes);
    }
    Ok((nodes * 2 + 2) / 3)
}

pub fn strong_quorum_reached(nodes: i32, votes: i32) -> Result<bool, QuorumError> {
    if votes < 0 {
        return Err(QuorumError);
    }
    Ok(votes >= strong_quorum_size(nodes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_follow_the_canton_comment_for_small_networks() {
        let cases = [
            (1, 0, 1, 1),
            (2, 0, 1, 2),
            (3, 0, 1, 3),
            (4, 1, 2, 3),
            (5, 1, 2, 4),
            (6, 1, 2, 4),
            (7, 2, 3, 5),
            (10, 3, 4, 7),
        ];
        for (nodes, faults, weak, strong) in cases {
            assert_eq!(tolerated_faults(nodes).unwrap(), faults, "{nodes}");
            assert_eq!(weak_quorum_size(nodes).unwrap(), weak, "{nodes}");
            assert_eq!(strong_quorum_size(nodes).unwrap(), strong, "{nodes}");
        }
    }

    #[test]
    fn four_nodes_need_three_matching_votes() {
        assert!(!strong_quorum_reached(4, 2).unwrap());
        assert!(strong_quorum_reached(4, 3).unwrap());
    }

    #[test]
    fn zero_nodes_are_rejected() {
        assert_eq!(strong_quorum_size(0), Err(QuorumError));
        assert_eq!(weak_quorum_size(0), Err(QuorumError));
    }

    #[test]
    fn sizes_match_the_double_ceil_fixture_through_4096() {
        let text = include_str!("../../../../tests/oracle/canton-hash/quorum.tsv");
        let mut count = 0;
        for line in text.lines().filter(|line| !line.is_empty()) {
            let mut parts = line.split('\t');
            let nodes: i32 = parts.next().unwrap().parse().unwrap();
            let faults: i32 = parts.next().unwrap().parse().unwrap();
            let weak: i32 = parts.next().unwrap().parse().unwrap();
            let strong: i32 = parts.next().unwrap().parse().unwrap();
            assert_eq!(tolerated_faults(nodes).unwrap(), faults, "{nodes}");
            assert_eq!(weak_quorum_size(nodes).unwrap(), weak, "{nodes}");
            assert_eq!(strong_quorum_size(nodes).unwrap(), strong, "{nodes}");
            count += 1;
        }
        assert_eq!(count, 4096);
    }
}
