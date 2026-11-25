//! A deterministic network and a cluster of nodes on it: messages with delays, loss, duplication, reordering, partitions, crashes and
//! restarts, and nodes that are not driven (so a test can play a faulty one with its key). The same seed gives the same run.
use crate::node::{BftNode, Durable, Event, Out};
use crate::types::{Config, Msg, NodeId};
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;

pub struct Net {
    pub now: u64,
    queue: Vec<(u64, u64, NodeId, NodeId, Msg)>,
    next_id: u64,
    rng: u64,
    /// Which side of the partition each node is on; messages cross only between nodes of the same group.
    pub group: Vec<usize>,
    pub down: BTreeSet<NodeId>,
    /// Out of 100 sent messages, how many are lost and how many are delivered twice.
    pub drop_pct: u64,
    pub dup_pct: u64,
    /// A message takes `1 ..= max_delay` ticks.
    pub max_delay: u64,
    pub sent: u64,
    pub delivered: u64,
}

impl Net {
    fn new(n: usize, seed: u64) -> Self {
        Self {
            now: 0,
            queue: Vec::new(),
            next_id: 0,
            rng: seed | 1,
            group: vec![0; n],
            down: BTreeSet::new(),
            drop_pct: 0,
            dup_pct: 0,
            max_delay: 1,
            sent: 0,
            delivered: 0,
        }
    }

    fn random(&mut self) -> u64 {
        // xorshift64*: enough for a schedule, and the same everywhere
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn send(&mut self, from: NodeId, to: NodeId, msg: Msg) {
        self.sent += 1;
        if self.random() % 100 < self.drop_pct {
            return;
        }
        let copies = 1 + usize::from(self.random() % 100 < self.dup_pct);
        for _ in 0..copies {
            let delay = 1 + self.random() % self.max_delay.max(1);
            self.next_id += 1;
            self.queue
                .push((self.now + delay, self.next_id, from, to, msg.clone()));
        }
    }

    fn connected(&self, a: NodeId, b: NodeId) -> bool {
        self.group[a] == self.group[b] && !self.down.contains(&a) && !self.down.contains(&b)
    }
}

pub struct Cluster {
    pub cfg: Config,
    pub keys: Vec<SigningKey>,
    pub nodes: Vec<BftNode>,
    pub net: Net,
    /// Nodes that are not driven: a test plays them with `inject`.
    pub silent: BTreeSet<NodeId>,
}

impl Cluster {
    /// `3f + 1` nodes with keys made from the seed.
    pub fn new(f: usize, seed: u64) -> Self {
        let n = 3 * f + 1;
        let keys: Vec<SigningKey> = (0..n)
            .map(|i| {
                let mut s = [0u8; 32];
                s[..8].copy_from_slice(&seed.to_be_bytes());
                s[8] = i as u8;
                s[9] = 0x42;
                SigningKey::from_bytes(&s)
            })
            .collect();
        let cfg = Config::new(keys.iter().map(|k| k.verifying_key()).collect());
        let nodes = (0..n)
            .map(|i| BftNode::new(i, cfg.clone(), keys[i].clone()))
            .collect();
        Self {
            net: Net::new(n, seed),
            cfg,
            keys,
            nodes,
            silent: BTreeSet::new(),
        }
    }

    fn enqueue(&mut self, from: NodeId, outs: Vec<Out>) {
        for o in outs {
            match o {
                Out::Send { to, msg } => self.net.send(from, to, msg),
                Out::Broadcast(msg) => {
                    for to in 0..self.cfg.n {
                        if to != from {
                            self.net.send(from, to, msg.clone());
                        }
                    }
                }
            }
        }
    }

    /// A client gives `request` to `node`.
    pub fn submit(&mut self, node: NodeId, request: &[u8]) {
        if self.net.down.contains(&node) || self.silent.contains(&node) {
            return;
        }
        let outs = self.nodes[node].submit(request.to_vec());
        self.enqueue(node, outs);
    }

    /// A message as if `from` sent it (a faulty node, played by the test).
    pub fn inject(&mut self, from: NodeId, to: NodeId, msg: Msg) {
        self.net.send(from, to, msg);
    }

    /// Splits the cluster: `groups[i]` is the side of node `i`.
    pub fn partition(&mut self, groups: &[usize]) {
        self.net.group = groups.to_vec();
    }

    pub fn heal(&mut self) {
        self.net.group = vec![0; self.cfg.n];
    }

    pub fn crash(&mut self, node: NodeId) {
        self.net.down.insert(node);
    }

    /// The node comes back with what it had kept durable and nothing else.
    pub fn restart(&mut self, node: NodeId) {
        let durable: Durable = self.nodes[node].durable();
        self.nodes[node] =
            BftNode::recover(node, self.cfg.clone(), self.keys[node].clone(), durable);
        self.net.down.remove(&node);
    }

    /// One tick: the messages that are due are delivered, then every running node's clock moves.
    pub fn step(&mut self) {
        self.net.now += 1;
        let now = self.net.now;
        let mut due: Vec<_> = Vec::new();
        let mut rest = Vec::new();
        for m in std::mem::take(&mut self.net.queue) {
            if m.0 <= now {
                due.push(m);
            } else {
                rest.push(m);
            }
        }
        self.net.queue = rest;
        due.sort_by_key(|m| (m.0, m.1));
        for (_, _, from, to, msg) in due {
            if !self.net.connected(from, to) || self.silent.contains(&to) {
                continue;
            }
            self.net.delivered += 1;
            let outs = self.nodes[to].handle(from, msg);
            self.enqueue(to, outs);
        }
        for i in 0..self.cfg.n {
            if self.net.down.contains(&i) || self.silent.contains(&i) {
                continue;
            }
            let outs = self.nodes[i].tick();
            self.enqueue(i, outs);
        }
    }

    pub fn run(&mut self, ticks: u64) {
        for _ in 0..ticks {
            self.step();
        }
    }

    /// Runs until `done` holds or `max_ticks` passed. Returns whether it held.
    pub fn run_until(&mut self, max_ticks: u64, done: impl Fn(&Cluster) -> bool) -> bool {
        for _ in 0..max_ticks {
            if done(self) {
                return true;
            }
            self.step();
        }
        done(self)
    }

    pub fn head_seqs(&self) -> Vec<u64> {
        self.nodes.iter().map(|n| n.head_seq()).collect()
    }

    /// Everything the nodes saw (and forgot): drained.
    pub fn events(&mut self) -> Vec<(NodeId, Event)> {
        let mut all = Vec::new();
        for n in &mut self.nodes {
            let id = n.id();
            all.extend(n.take_events().into_iter().map(|e| (id, e)));
        }
        all
    }

    /// **Safety**: no two nodes (silent ones excepted) have different blocks in one slot, and each node's chain is what its blocks say.
    pub fn assert_safety(&self) {
        let running: Vec<&BftNode> = self
            .nodes
            .iter()
            .filter(|n| !self.silent.contains(&n.id()))
            .collect();
        for a in &running {
            let mut prev = [0u8; 32];
            for b in a.log() {
                prev =
                    crate::types::verify_committed_block(&self.cfg, b, &prev).unwrap_or_else(|e| {
                        panic!("node {} holds a block that does not verify: {e}", a.id())
                    });
            }
            assert_eq!(
                prev,
                a.head_hash(),
                "node {}: the chain hash is the blocks'",
                a.id()
            );
            for b in &running {
                let upto = a.log().len().min(b.log().len());
                for i in 0..upto {
                    assert_eq!(
                        a.log()[i].pre_prepare.body.digest(),
                        b.log()[i].pre_prepare.body.digest(),
                        "nodes {} and {} committed different blocks in slot {}",
                        a.id(),
                        b.id(),
                        i + 1
                    );
                }
            }
        }
    }
}
