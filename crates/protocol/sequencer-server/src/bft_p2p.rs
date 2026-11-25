//! The p2p endpoint of a Rust BFT orderer node (U-49 B2b): what the other sequencers of the synchronizer connect to.
//!
//! [CANTON-NOTE: SEMANTICS] Source: `BftBlockOrderer.scala` (the p2p server), `bindings/p2p/grpc/authentication/*`. The endpoint serves two services on one port: the
//! sequencer's `SequencerAuthenticationService` (so the orderers need not know the sequencers' API endpoints) and the `BftOrderingService` (`Receive`, a stream
//! each way). A peer that connects has to be authenticated as a **sequencer**: it answers the challenge of the authentication service with its sequencer
//! authentication key (the key its `OwnerToKeyMapping` in the synchronizer's topology lists) and sends the token with each call (`memberid`, `authtoken-bin`).
use crate::onboarding::Registry;
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::BftOrderingMessage;
use state_transfer::CatchUp;
use std::sync::Arc;

mod dissemination;
mod ordering;
mod peer_manager;
mod registry;
mod state_transfer;
mod storage;
#[cfg(test)]
mod tests;
mod transport;

pub use peer_manager::{
    BftClientTls, BftPeerConfig, BftPeerManager, BftServerTls, PeerConnState,
    PeerEndpointStatusView,
};
pub use registry::{mediator_groups_of, registry_of, sequencer_registry};
pub use transport::{
    build_peer_manager, serve, serve_with_options, serve_with_shutdown, verify_signed_message,
    BftServeOptions, Outgoing, P2pService,
};

/// [CANTON-NOTE: INVARIANT] Two mutex-poison tiers in `bft_p2p`:
/// - `lock_or_recover`: strictly for benign diagnostics/caches (`senders`, `peer_senders`,
///   `batches`, `recent_pbft`, `store_quota`, `last_status`, `last_prune`, `mempool`, `sink`,
///   `block_end_sink`, `nodes`, `BftPeerManager::{endpoints, incoming_members}`).
/// - `lock_critical`: invariant-critical consensus, catch-up, output, and persistence state
///   (`node`, `output`, `pending`, `replay`, `store`, `persisted_policy`, `persisted_epoch`,
///   `saved_epoch_started`, `ord_store`, `policy_file`, `last_policy_epoch`, `catchup`,
///   `ready_policy`, `disseminating`); poisoning MUST fail loudly rather than continue with torn state.
fn lock_or_recover<'a, T>(
    mutex: &'a std::sync::Mutex<T>,
    label: &str,
) -> std::sync::MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|e| {
        crate::diag::diag_eprintln!("BFT_P2P {label} lock poisoned; recovering inner state");
        e.into_inner()
    })
}

pub(super) fn lock_critical<'a, T>(
    mutex: &'a std::sync::Mutex<T>,
    label: &str,
) -> Result<std::sync::MutexGuard<'a, T>, String> {
    mutex.lock().map_err(|_| {
        let msg = format!("BFT_P2P {label} lock poisoned");
        crate::diag::diag_eprintln!("{msg}");
        msg
    })
}

/// A request of a block the orderer decided, in the order of the block, with the time the orderer gave it (what `BlockFormat.OrderedRequest` carries).
pub struct OutputRequest {
    pub block: i64,
    pub time_micros: i64,
    /// `send` or `acknowledge`.
    pub tag: String,
    pub body: Vec<u8>,
    /// The sequencer that led the block (the traffic of its requests is accounted to it).
    pub orderer: String,
}

/// Where the requests of the decided blocks go (a sequencer that applies them).
pub type OutputSink = Arc<dyn Fn(OutputRequest) + Send + Sync>;

/// Called after all requests of an ordered block are handed to [`OutputSink`] with `(block, base_block_time, tick_topology_at_least)`:
/// returns whether topology changes are still pending past epoch end for the next epoch.
pub type BlockEndSink = Arc<dyn Fn(i64, i64, Option<i64>) -> bool + Send + Sync>;

/// A batch this node made and has asked the others to store: the acks it has, until there are enough for a proof of availability (`DisseminationProtocolState`).
struct Dissemination {
    epoch: i64,
    acks: std::collections::BTreeMap<
        String,
        canton_proto::com::digitalasset::canton::crypto::v30::Signature,
    >,
    proof_queued: bool,
}

/// The output stage of the orderer (`OutputModule` and `OutputFetchProtocolState`): the blocks wait here until all the batches they name are at hand.
#[derive(Default)]
struct OutputState {
    waiting: std::collections::VecDeque<(
        i64,
        i64,
        i64,
        bool,
        String,
        Vec<canton_bft_orderer::node::BatchRef>,
    )>,
    asked: std::collections::BTreeMap<Vec<u8>, std::time::Instant>,
    current_epoch: Option<i64>,
    epoch_could_alter_topology: bool,
    pending_next_epoch_topology: bool,
    latest_topology_tx_ts: Option<i64>,
    /// Blocks up to this number were already emitted to `sink` before restart (`ord_metadata_output_blocks`).
    restored_last_output_block: Option<i64>,
    restored_last_bft_time: Option<i64>,
    epoch_boundary_bft_time: Option<i64>,
    /// Latest output block observed `(epoch_number, block_number, bft_ts_micros)` for pruning status.
    latest_output: Option<(i64, i64, i64)>,
}

/// The consensus of this node and the streams it sends on (B3, B4): what the incoming messages are given to and what the node sends goes out through.
///
/// [CANTON-NOTE: SEMANTICS] A node that joins a running cluster does not know which epoch the peers are in or where it started. It learns it from the first
/// `PrePrepare` of an epoch it sees: the canonical commit set of a leader's first block holds the commits of the **last block of the epoch before**
/// (`doc/slices/BFT-CONSENSUS-SPEC.md` 3.2), so the epoch starts one block after it. The epoch length is given or the default (`segmentLength` 10 per node).
pub struct Consensus {
    node: std::sync::Mutex<Option<canton_bft_orderer::node::ConsensusNode>>,
    senders: std::sync::Mutex<Vec<tokio::sync::mpsc::Sender<BftOrderingMessage>>>,
    member: String,
    signing_seed: [u8; 32],
    fingerprint: String,
    epoch_length: Option<i64>,
    /// The nodes of the synchronizer, refreshed from its topology before the node starts.
    nodes: Arc<std::sync::Mutex<Vec<String>>>,
    /// The keys of the sequencers, to check the acks of the batches a proposal carries.
    registry: Arc<Registry>,
    /// Messages that came before the node knew its epoch (a retransmission can start mid-epoch): they are replayed when it starts.
    pending: std::sync::Mutex<Vec<SignedMessage>>,
    /// Where this node writes what it signed (`persist_to`): one hex line per consensus message.
    store: std::sync::Mutex<Option<(std::path::PathBuf, std::fs::File, i64)>>,
    /// Optional PostgreSQL `ord_*` persistence store.
    ord_store: std::sync::Mutex<Option<Arc<crate::ord_store::OrdStore>>>,
    /// Epoch recovered from `ord_epochs`, when resuming from PostgreSQL.
    persisted_epoch: std::sync::Mutex<Option<crate::ord_store::OrdEpoch>>,
    saved_epoch_started: std::sync::Mutex<i64>,
    /// Recent PBFT messages cached by block number so `BlockOrdered` can promote PrePrepare + Commits into `ord_pbft_messages_completed`.
    recent_pbft: std::sync::Mutex<std::collections::BTreeMap<i64, Vec<SignedMessage>>>,
    /// What this node signed before it was restarted, put back when it starts.
    replay: std::sync::Mutex<Vec<SignedMessage>>,
    /// The leader selection state a node kept in its state file (`persist_to`), the file it is written to, and the epoch it was last written for.
    persisted_policy: std::sync::Mutex<Option<canton_bft_orderer::blacklist::PolicyState>>,
    policy_file: std::sync::Mutex<Option<std::path::PathBuf>>,
    last_policy_epoch: std::sync::Mutex<i64>,
    /// The stream to each peer by its identity (learned from the answer headers of the stream this node opened to it): a reply goes to the one that asked.
    peer_senders: std::sync::Mutex<std::collections::BTreeMap<String, tokio::sync::mpsc::Sender<BftOrderingMessage>>>,
    /// The batches this node stores for the others (`StoreRequest`), by batch id (`AvailabilityStore`).
    batches: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::Batch>>,
    /// When the stored batches were last pruned.
    last_prune: std::sync::Mutex<std::time::Instant>,
    /// The batches each peer had this node store that are not ordered yet (`DisseminationQuotas`), by peer.
    store_quota: std::sync::Mutex<std::collections::BTreeMap<String, std::collections::BTreeSet<Vec<u8>>>>,
    /// The requests this node's sequencer was sent and that wait to be made into a batch: `(tag, message id, payload)` (`Mempool`).
    mempool: std::sync::Mutex<Vec<(String, String, Vec<u8>)>>,
    /// The batches this node disseminates, by batch id.
    disseminating: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, Dissemination>>,
    /// The sequencer that takes the requests of the blocks, when this node has one.
    sink: std::sync::Mutex<Option<OutputSink>>,
    /// Called at the end of each decided block to emit any post-ordering topology ticks and report pending changes.
    block_end_sink: std::sync::Mutex<Option<BlockEndSink>>,
    /// The output stage: blocks whose batches are being collected, in block order, and when each batch was last asked for.
    output: std::sync::Mutex<OutputState>,
    /// A state transfer in progress: the node learned an epoch later than the one its state is for and fetches the epochs between (U-52).
    catchup: std::sync::Mutex<Option<CatchUp>>,
    /// The leader selection state a finished state transfer produced, for the node that starts next.
    ready_policy: std::sync::Mutex<Option<canton_bft_orderer::blacklist::PolicyState>>,
    /// The view change timeout of the official nodes (their `view-change-timeout-override`), in milliseconds; none means the defaults.
    view_change_timeout_ms: Option<u64>,
    started: std::time::Instant,
    last_status: std::sync::Mutex<Option<std::time::Instant>>,
    performance_metrics_enabled: std::sync::atomic::AtomicBool,
}

/// `BftBlockOrdererConfig.DefaultMaxMempoolQueueSize`: the requests waiting to be made into batches.
pub const MAX_MEMPOOL_QUEUE_SIZE: usize = 10 * 1_024;

/// `BftBlockOrdererConfig.DefaultAvailabilityMaxNonOrderedBatchesPerNode`: the batches a peer may have this node store before they are ordered.
pub const MAX_NON_ORDERED_BATCHES_PER_NODE: usize = 1_000;

type SignedMessage = canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::SignedMessage;

/// Decodes `(epoch_number, block_number, view_number, discriminator)` from a signed `ConsensusMessage`.
pub fn pbft_discriminator(signed: &SignedMessage) -> Option<(i64, i64, i64, i16)> {
    use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
        consensus_message::Message, ConsensusMessage,
    };
    use prost::Message as _;
    let inner = canton_bft_orderer::wire::unwrap_versioned(&signed.message, 30).ok()?;
    let msg = ConsensusMessage::decode(inner.as_slice()).ok()?;
    let meta = msg.block_metadata?;
    let disc = match msg.message? {
        Message::PrePrepare(_) => 0,
        Message::Prepare(_) => 1,
        Message::Commit(_) => 2,
        Message::ViewChange(_) => 3,
        Message::NewView(_) => 4,
    };
    Some((meta.epoch_number, meta.block_number, msg.view_number, disc))
}

impl Consensus {
    /// A node that starts when it sees the epoch the peers are in (`epoch_length`: the length of an epoch, `None` for ten blocks per node).
    pub fn new(
        member: String,
        signing_seed: [u8; 32],
        fingerprint: String,
        epoch_length: Option<i64>,
        registry: Arc<Registry>,
    ) -> Self {
        Self {
            node: std::sync::Mutex::new(None),
            senders: std::sync::Mutex::new(Vec::new()),
            member,
            signing_seed,
            fingerprint,
            epoch_length,
            nodes: Arc::new(std::sync::Mutex::new(Vec::new())),
            registry,
            pending: std::sync::Mutex::new(Vec::new()),
            persisted_policy: std::sync::Mutex::new(None),
            policy_file: std::sync::Mutex::new(None),
            last_policy_epoch: std::sync::Mutex::new(-1),
            peer_senders: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            batches: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            last_prune: std::sync::Mutex::new(std::time::Instant::now()),
            store_quota: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            mempool: std::sync::Mutex::new(Vec::new()),
            disseminating: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            sink: std::sync::Mutex::new(None),
            block_end_sink: std::sync::Mutex::new(None),
            output: std::sync::Mutex::new(OutputState::default()),
            catchup: std::sync::Mutex::new(None),
            ready_policy: std::sync::Mutex::new(None),
            view_change_timeout_ms: None,
            store: std::sync::Mutex::new(None),
            ord_store: std::sync::Mutex::new(None),
            persisted_epoch: std::sync::Mutex::new(None),
            saved_epoch_started: std::sync::Mutex::new(-1),
            recent_pbft: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            replay: std::sync::Mutex::new(Vec::new()),
            started: std::time::Instant::now(),
            last_status: std::sync::Mutex::new(None),
            performance_metrics_enabled: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn prune_closed_senders(&self) {
        lock_or_recover(&self.senders, "senders").retain(|x| !x.is_closed());
        lock_or_recover(&self.peer_senders, "peer_senders").retain(|_, x| !x.is_closed());
    }

    pub fn clear_senders(&self) {
        lock_or_recover(&self.senders, "senders").clear();
        lock_or_recover(&self.peer_senders, "peer_senders").clear();
    }

    pub fn set_performance_metrics_enabled(&self, enabled: bool) {
        self.performance_metrics_enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn performance_metrics_enabled(&self) -> bool {
        self.performance_metrics_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn ord_store_handle(&self) -> Option<Arc<crate::ord_store::OrdStore>> {
        lock_critical(&self.ord_store, "ord_store")
            .ok()
            .and_then(|g| g.clone())
    }

    fn lock_output(&self) -> Result<std::sync::MutexGuard<'_, OutputState>, String> {
        lock_critical(&self.output, "output")
    }

    fn lock_catchup(&self) -> Result<std::sync::MutexGuard<'_, Option<CatchUp>>, String> {
        lock_critical(&self.catchup, "catchup")
    }

    fn lock_ready_policy(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<canton_bft_orderer::blacklist::PolicyState>>, String>
    {
        lock_critical(&self.ready_policy, "ready_policy")
    }

    pub fn latest_output_info(&self) -> (i64, i64, Option<i64>) {
        let Ok(out) = self.lock_output() else {
            return (0, 0, None);
        };
        if let Some((ep, blk, ts)) = out.latest_output {
            return (ep, blk, Some(ts));
        }
        if let Some(blk) = out.restored_last_output_block {
            return (
                out.current_epoch.unwrap_or(0),
                blk,
                out.restored_last_bft_time,
            );
        }
        (0, 0, None)
    }

    pub fn ordering_topology(&self) -> (i64, Vec<String>, Vec<String>, Vec<String>) {
        let mut nodes = lock_or_recover(&self.nodes, "nodes").clone();
        if !nodes.contains(&self.member) {
            nodes.push(self.member.clone());
        }
        nodes.sort();
        nodes.dedup();
        let node_policy = lock_critical(&self.node, "node")
            .ok()
            .and_then(|g| g.as_ref().map(|n| n.policy_state().clone()));
        let active_policy = node_policy
            .or_else(|| self.lock_ready_policy().ok().and_then(|g| g.clone()))
            .or_else(|| {
                lock_critical(&self.persisted_policy, "persisted_policy")
                    .ok()
                    .and_then(|g| g.clone())
            });
        match active_policy {
            Some(p) => {
                let mut ep_nodes = p.nodes.clone();
                if ep_nodes.is_empty() {
                    ep_nodes = nodes;
                }
                ep_nodes.sort();
                (p.epoch_number, ep_nodes, p.leaders(), p.blacklisted_nodes())
            }
            None => (0, nodes.clone(), nodes, Vec::new()),
        }
    }
}
