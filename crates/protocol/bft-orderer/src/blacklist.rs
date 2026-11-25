//! The leader selection policy of the official orderer: a leader whose segment needed a view change is kept off the leader list for a number of epochs.
//! From `core/modules/output/leaders` (`BlacklistLeaderSelectionPolicy`, `…State`, `BlacklistStatus`) and `framework/data/topology/BlacklistLeaderSelectionPolicyConfig`
//! with the defaults of `SequencingParameters` (linear penalty capped at 250 epochs, at most `f = (n - 1) / 3` nodes blacklisted at once). `doc/slices/UNRESOLVED.md` U-52.
use crate::epoch::leaders_of_epoch;
use crate::topology::EpochInfo;
use std::collections::{BTreeMap, BTreeSet};

/// `BlacklistStatus` without `Clean` (a clean node has no entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// It leads again, and one more failure blacklists it for longer (`numberOfConsecutiveFailedAttempts`).
    OnTrial(i64),
    Blacklisted {
        failed_attempts_before: i64,
        epochs_left_until_new_trial: i64,
    },
}

/// How an epoch went for a node (`BlacklistStatus.HowEpochWent`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HowEpochWent {
    Succeeded,
    ShouldBePunished,
    DidNotParticipate,
}

/// `HowLongToBlacklist.Linear(maximumEpochBlacklisted)`: `failedEpochSoFar` epochs, at most the maximum.
const DEFAULT_MAXIMUM_EPOCHS_BLACKLISTED: i64 = 250;

fn update_left_until_next_trial(left: i64) -> i64 {
    left.min(DEFAULT_MAXIMUM_EPOCHS_BLACKLISTED)
}

/// `Blacklisted.create`: no epochs left means on trial.
fn blacklisted(failed_attempts_before: i64, epochs_left: i64) -> Option<Status> {
    Some(if epochs_left <= 0 {
        Status::OnTrial(failed_attempts_before)
    } else {
        Status::Blacklisted {
            failed_attempts_before,
            epochs_left_until_new_trial: epochs_left,
        }
    })
}

fn punish(failed_epochs_so_far: i64) -> Option<Status> {
    blacklisted(
        failed_epochs_so_far,
        update_left_until_next_trial(failed_epochs_so_far),
    )
}

/// `BlacklistStatus.update` (`None` is `Clean`).
fn update_status(status: Option<Status>, went: HowEpochWent) -> Option<Status> {
    match (status, went) {
        (_, HowEpochWent::Succeeded) => None,
        (None, HowEpochWent::ShouldBePunished) => punish(1),
        (None, HowEpochWent::DidNotParticipate) => None,
        (Some(Status::OnTrial(n)), HowEpochWent::ShouldBePunished) => punish(n + 1),
        (Some(Status::OnTrial(n)), HowEpochWent::DidNotParticipate) => Some(Status::OnTrial(n)),
        (
            Some(Status::Blacklisted {
                failed_attempts_before,
                ..
            }),
            HowEpochWent::ShouldBePunished,
        ) => punish(failed_attempts_before + 1),
        (
            Some(Status::Blacklisted {
                failed_attempts_before,
                epochs_left_until_new_trial,
            }),
            HowEpochWent::DidNotParticipate,
        ) => blacklisted(
            failed_attempts_before,
            update_left_until_next_trial(epochs_left_until_new_trial) - 1,
        ),
    }
}

/// `BlacklistLeaderSelectionPolicyState` with the topology of the epoch (`…StateWithTopology`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyState {
    pub epoch_number: i64,
    pub start_block: i64,
    pub blacklist: BTreeMap<String, Status>,
    /// The nodes of the ordering topology of the epoch and its length.
    pub nodes: Vec<String>,
    pub epoch_length: i64,
}

impl PolicyState {
    pub fn first(nodes: &[String], epoch_length: i64) -> Self {
        Self {
            epoch_number: 0,
            start_block: 0,
            blacklist: BTreeMap::new(),
            nodes: sorted(nodes),
            epoch_length,
        }
    }

    /// `computeBlacklistedNodes`: the blacklisted nodes with the most epochs left first (ties: the greater id first), at most `f` of them, sorted by id.
    pub fn blacklisted_nodes(&self) -> Vec<String> {
        let mut all: Vec<(i64, &String)> = self
            .blacklist
            .iter()
            .filter_map(|(node, s)| match s {
                Status::Blacklisted {
                    epochs_left_until_new_trial,
                    ..
                } => Some((*epochs_left_until_new_trial, node)),
                Status::OnTrial(_) => None,
            })
            .collect();
        all.sort();
        all.reverse();
        let f = (self.nodes.len().saturating_sub(1)) / 3;
        let mut taken: Vec<String> = all.into_iter().take(f).map(|(_, n)| n.clone()).collect();
        taken.sort();
        taken
    }

    /// `computeLeaders`: the nodes that are not blacklisted, sorted and rotated left by the epoch number.
    pub fn leaders(&self) -> Vec<String> {
        let off: BTreeSet<String> = self.blacklisted_nodes().into_iter().collect();
        let eligible: Vec<String> = self
            .nodes
            .iter()
            .filter(|n| !off.contains(*n))
            .cloned()
            .collect();
        leaders_of_epoch(&eligible, self.epoch_number)
    }

    /// The state of the next epoch, from the blocks of this one as a state transfer delivers them: `(block number, view of its proposal)`. A block ordered in a view
    /// other than the first punishes the original leader of its segment (`BlacklistLeaderSelectionPolicy.addBlock`).
    pub fn after_blocks(&self, new_nodes: &[String], blocks: &[(i64, i64)]) -> Self {
        let epoch = crate::epoch::Epoch::with_leaders(self.epoch_info(), self.leaders());
        let punished: BTreeSet<String> = blocks
            .iter()
            .filter(|(_, view)| *view != 0)
            .filter_map(|(block, _)| epoch.leader_of(*block).map(str::to_string))
            .collect();
        self.next(new_nodes, &punished)
    }

    /// The state as text, for the file a node keeps beside its signed messages: `epoch`, `start`, `length`, `nodes` and a `blacklist` line per entry.
    pub fn to_text(&self) -> String {
        let mut t = format!(
            "epoch {}\nstart {}\nlength {}\nnodes {}\n",
            self.epoch_number,
            self.start_block,
            self.epoch_length,
            self.nodes.join(",")
        );
        for (node, status) in &self.blacklist {
            match status {
                Status::OnTrial(n) => t += &format!("blacklist {node} trial {n}\n"),
                Status::Blacklisted {
                    failed_attempts_before,
                    epochs_left_until_new_trial,
                } => t += &format!(
                    "blacklist {node} off {failed_attempts_before} {epochs_left_until_new_trial}\n"
                ),
            }
        }
        t
    }

    pub fn from_text(text: &str) -> Option<Self> {
        let mut state = Self {
            epoch_number: -1,
            start_block: -1,
            blacklist: BTreeMap::new(),
            nodes: Vec::new(),
            epoch_length: 0,
        };
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts.as_slice() {
                ["epoch", n] => state.epoch_number = n.parse().ok()?,
                ["start", n] => state.start_block = n.parse().ok()?,
                ["length", n] => state.epoch_length = n.parse().ok()?,
                ["nodes", list] => state.nodes = list.split(',').map(str::to_string).collect(),
                ["blacklist", node, "trial", n] => {
                    state
                        .blacklist
                        .insert(node.to_string(), Status::OnTrial(n.parse().ok()?));
                }
                ["blacklist", node, "off", a, b] => {
                    state.blacklist.insert(
                        node.to_string(),
                        Status::Blacklisted {
                            failed_attempts_before: a.parse().ok()?,
                            epochs_left_until_new_trial: b.parse().ok()?,
                        },
                    );
                }
                _ => {}
            }
        }
        (state.epoch_number >= 0 && state.epoch_length > 0 && !state.nodes.is_empty())
            .then_some(state)
    }

    pub fn epoch_info(&self) -> EpochInfo {
        EpochInfo {
            number: self.epoch_number,
            start_block_number: self.start_block,
            length: self.epoch_length,
        }
    }

    /// `update`: the state of the next epoch. `punished` are the original leaders of the blocks that were ordered in a view other than the first (a view change);
    /// a node that led a segment and was not punished succeeded; one that did not lead did not take part.
    pub fn next(&self, new_nodes: &[String], punished: &BTreeSet<String>) -> Self {
        let leaders: BTreeSet<String> = self.leaders().into_iter().collect();
        let mut blacklist: BTreeMap<String, Status> = self
            .blacklist
            .iter()
            .filter(|(n, _)| new_nodes.contains(n))
            .map(|(n, s)| (n.clone(), *s))
            .collect();
        for node in new_nodes {
            let went = if punished.contains(node) {
                HowEpochWent::ShouldBePunished
            } else if leaders.contains(node) {
                HowEpochWent::Succeeded
            } else {
                HowEpochWent::DidNotParticipate
            };
            match update_status(blacklist.get(node).copied(), went) {
                Some(s) => {
                    blacklist.insert(node.clone(), s);
                }
                None => {
                    blacklist.remove(node);
                }
            }
        }
        Self {
            epoch_number: self.epoch_number + 1,
            start_block: self.start_block + self.epoch_length,
            blacklist,
            nodes: sorted(new_nodes),
            epoch_length: self.epoch_length,
        }
    }
}

fn sorted(nodes: &[String]) -> Vec<String> {
    let mut v = nodes.to_vec();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        [
            "SEQ::sequencer1",
            "SEQ::sequencer2",
            "SEQ::sequencer3",
            "SEQ::rs1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn short(leaders: Vec<String>) -> Vec<String> {
        leaders
            .into_iter()
            .map(|l| l.replace("SEQ::", ""))
            .collect()
    }

    fn at_epoch(state: &PolicyState, epoch: i64) -> PolicyState {
        let mut s = state.clone();
        s.epoch_number = epoch;
        s
    }

    /// The leader lists the official nodes logged in the oracle (four nodes, `rs1` stopped; `view change after local timeout` for its segments): in the
    /// epochs 35 to 39 the leaders were [seq3 seq1 seq2], [rs1 seq1 seq2 seq3], [seq2 seq3 seq1], [seq3 seq1 seq2], [seq3 rs1 seq1 seq2].
    #[test]
    fn the_leaders_the_official_nodes_chose_while_rs1_was_away_are_reproduced() {
        let nodes = names();
        let none = BTreeSet::new();
        let rs1: BTreeSet<String> = ["SEQ::rs1".to_string()].into();
        // epoch 34: all four lead, rs1's segment needed a view change: it is punished
        let epoch34 = at_epoch(&PolicyState::first(&nodes, 40), 34);
        assert_eq!(
            short(epoch34.leaders()),
            ["sequencer2", "sequencer3", "rs1", "sequencer1"]
        );
        // epoch 35: rs1 is blacklisted
        let epoch35 = epoch34.next(&nodes, &rs1);
        assert_eq!(
            short(epoch35.leaders()),
            ["sequencer3", "sequencer1", "sequencer2"]
        );
        assert_eq!(epoch35.blacklisted_nodes(), ["SEQ::rs1"]);
        // epoch 36: it did not lead, so its penalty is served: it leads again, on trial
        let epoch36 = epoch35.next(&nodes, &none);
        assert_eq!(epoch36.blacklist["SEQ::rs1"], Status::OnTrial(1));
        assert_eq!(
            short(epoch36.leaders()),
            ["rs1", "sequencer1", "sequencer2", "sequencer3"]
        );
        // it failed again: two epochs off
        let epoch37 = epoch36.next(&nodes, &rs1);
        assert_eq!(
            epoch37.blacklist["SEQ::rs1"],
            Status::Blacklisted {
                failed_attempts_before: 2,
                epochs_left_until_new_trial: 2
            }
        );
        assert_eq!(
            short(epoch37.leaders()),
            ["sequencer2", "sequencer3", "sequencer1"]
        );
        let epoch38 = epoch37.next(&nodes, &none);
        assert_eq!(
            short(epoch38.leaders()),
            ["sequencer3", "sequencer1", "sequencer2"]
        );
        let epoch39 = epoch38.next(&nodes, &none);
        assert_eq!(epoch39.blacklist["SEQ::rs1"], Status::OnTrial(2));
        assert_eq!(
            short(epoch39.leaders()),
            ["sequencer3", "rs1", "sequencer1", "sequencer2"]
        );
        // a node that leads and is not punished is clean again
        let epoch40 = epoch39.next(&nodes, &none);
        assert!(epoch40.blacklist.is_empty());
        assert_eq!(epoch40.start_block, epoch39.start_block + 40);
    }

    #[test]
    fn the_state_of_a_later_epoch_follows_from_the_views_of_the_blocks() {
        // epoch 34: the blocks of rs1's segment were ordered in view 1 (a view change): rs1 sits out epoch 35, as the official nodes did
        let nodes = names();
        let epoch34 = at_epoch(&PolicyState::first(&nodes, 40), 34);
        let epoch = crate::epoch::Epoch::with_leaders(epoch34.epoch_info(), epoch34.leaders());
        let rs1_blocks = epoch.segment_of("SEQ::rs1").unwrap().slots.clone();
        let blocks: Vec<(i64, i64)> = (epoch34.start_block..epoch34.start_block + 40)
            .map(|b| (b, if rs1_blocks.contains(&b) { 1 } else { 0 }))
            .collect();
        let epoch35 = epoch34.after_blocks(&nodes, &blocks);
        assert_eq!(
            short(epoch35.leaders()),
            ["sequencer3", "sequencer1", "sequencer2"]
        );
    }

    #[test]
    fn a_state_survives_being_written_and_read() {
        let nodes = names();
        let rs1: BTreeSet<String> = ["SEQ::rs1".to_string()].into();
        let mut state = at_epoch(&PolicyState::first(&nodes, 40), 34).next(&nodes, &rs1);
        state = state.next(&nodes, &BTreeSet::new()).next(&nodes, &rs1);
        assert!(!state.blacklist.is_empty());
        assert_eq!(PolicyState::from_text(&state.to_text()), Some(state));
        assert_eq!(PolicyState::from_text("nonsense"), None);
    }

    #[test]
    fn at_most_f_nodes_are_blacklisted_at_once() {
        let nodes = names();
        let mut state = at_epoch(&PolicyState::first(&nodes, 40), 7);
        for n in ["SEQ::rs1", "SEQ::sequencer1"] {
            state.blacklist.insert(
                n.to_string(),
                Status::Blacklisted {
                    failed_attempts_before: 1,
                    epochs_left_until_new_trial: 3,
                },
            );
        }
        // four nodes tolerate one fault: only one of them is kept off (the greater id on a tie)
        assert_eq!(state.blacklisted_nodes(), ["SEQ::sequencer1"]);
    }
}
