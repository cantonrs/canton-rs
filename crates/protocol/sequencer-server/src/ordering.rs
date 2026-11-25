//! The BFT ordering mode of the sequencer (G7, S-NET-038 part 2): the order in which the submissions are sequenced is decided by a cluster
//! of `3f + 1` ordering nodes (`canton-ordering`) instead of by the order in which this process happens to receive them.
//!
//! [CANTON-NOTE: SEMANTICS] A submission is checked when it arrives (so the caller gets the same refusals as without BFT), handed to every
//! running ordering node as a request, and sequenced **when the cluster has committed it**: the committed blocks, in their order, are what
//! the sequencer applies. With up to `f` ordering nodes crashed or cut off the submissions are still ordered (a crashed leader is replaced by
//! a view change); with more, nothing is sequenced until enough nodes are back.
//!
//! [CANTON-NOTE: LIMITATION] The ordering nodes run **inside this process** on a simulated network driven by the real clock (one tick every
//! few milliseconds), so this shows the sequencer working on top of the engine and surviving the engine's node failures, not a deployment
//! over several machines: the process itself is still one failure domain. A submission that was accepted but not yet committed when the
//! process stops is lost (the participant's own timeout handles it), and the ordering log is not persisted (the sequenced events are).
use canton_ordering::Cluster;
use std::sync::Mutex;

pub struct BftOrdering {
    cluster: Mutex<Cluster>,
    /// How many committed blocks the sequencer has applied.
    applied: Mutex<usize>,
}

fn encode(member: &str, request: &[u8]) -> Vec<u8> {
    let mut out = (member.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(member.as_bytes());
    out.extend_from_slice(request);
    out
}

fn decode(payload: &[u8]) -> Option<(String, Vec<u8>)> {
    let len = u32::from_be_bytes(payload.get(..4)?.try_into().ok()?) as usize;
    let member = String::from_utf8(payload.get(4..4 + len)?.to_vec()).ok()?;
    Some((member, payload.get(4 + len..)?.to_vec()))
}

impl BftOrdering {
    /// An ordering cluster of `3f + 1` nodes.
    pub fn new(f: usize) -> Self {
        Self {
            cluster: Mutex::new(Cluster::new(f, rand_seed())),
            applied: Mutex::new(0),
        }
    }

    /// Gives a checked submission of `member` to the ordering nodes (all the running ones: a client that asks every node does not depend on
    /// the leader being up).
    pub fn order(&self, member: &str, signed_request: &[u8]) {
        let payload = encode(member, signed_request);
        let mut c = self
            .cluster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for node in 0..c.cfg.n {
            c.submit(node, &payload);
        }
    }

    /// One tick of the ordering cluster; returns the submissions committed since the last call, in the order they were committed.
    pub fn step(&self) -> Vec<(String, Vec<u8>)> {
        let mut c = self
            .cluster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        c.step();
        let mut applied = self
            .applied
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // the node that is furthest on: every running node's log is a prefix of the same chain
        let Some(best) = c
            .nodes
            .iter()
            .filter(|n| !c.net.down.contains(&n.id()))
            .max_by_key(|n| n.head_seq())
        else {
            return Vec::new();
        };
        let mut ready = Vec::new();
        for block in best.log().iter().skip(*applied) {
            for r in &block.pre_prepare.body.requests {
                if let Some(item) = decode(r) {
                    ready.push(item);
                }
            }
        }
        *applied = (*applied).max(best.log().len());
        ready
    }

    /// An operator's command: `crash <node>`, `restart <node>`, `partition <group of each node, e.g. 0,0,0,1>`, `heal`, `status`.
    /// Returns what to log.
    pub fn control(&self, line: &str) -> String {
        let mut c = self
            .cluster
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut words = line.split_whitespace();
        let node = |w: Option<&str>| {
            w.and_then(|v| v.parse::<usize>().ok())
                .filter(|n| *n < c.cfg.n)
        };
        match words.next() {
            Some("crash") => match node(words.next()) {
                Some(n) => {
                    c.crash(n);
                    format!("ORDERING crashed node {n}")
                }
                None => "ORDERING no such node".into(),
            },
            Some("restart") => match node(words.next()) {
                Some(n) => {
                    c.restart(n);
                    format!("ORDERING restarted node {n}")
                }
                None => "ORDERING no such node".into(),
            },
            Some("partition") => {
                let groups: Vec<usize> = words
                    .next()
                    .unwrap_or("")
                    .split(',')
                    .filter_map(|g| g.parse().ok())
                    .collect();
                if groups.len() == c.cfg.n {
                    c.partition(&groups);
                    format!("ORDERING partition {groups:?}")
                } else {
                    "ORDERING a partition names the group of every node".into()
                }
            }
            Some("heal") => {
                c.heal();
                "ORDERING healed".into()
            }
            Some("status") => format!(
                "ORDERING status heads={:?} views={:?} down={:?}",
                c.head_seqs(),
                c.nodes.iter().map(|n| n.view()).collect::<Vec<_>>(),
                c.net.down
            ),
            _ => "ORDERING unknown command".into(),
        }
    }
}

fn rand_seed() -> u64 {
    // keys of the ordering nodes: from the clock, so that two servers do not share them
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
}
