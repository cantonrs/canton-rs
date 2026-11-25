//! Durable BFT orderer persistence on PostgreSQL (`ord_*` tables, O6 / U-49).
//!
//! [CANTON-NOTE: SEMANTICS] Official Canton 3.7.2 stores availability batches (`ord_availability_batch`), epochs (`ord_epochs`),
//! leader selection state (`ord_leader_selection_state`, v30 `BlacklistLeaderSelectionPolicyState`), PBFT messages
//! (`ord_pbft_messages_in_progress` and `ord_pbft_messages_completed`), and output metadata (`ord_metadata_output_blocks`,
//! `ord_metadata_output_epochs`) in PostgreSQL. Writes go through a dedicated OS worker thread so synchronous `postgres::Client`
//! I/O never runs on Tokio worker threads. Compatible with both unpartitioned (`V1_1`) and range-partitioned (`V5_2`) schemas.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{mpsc, Mutex};
use std::thread::JoinHandle;

use canton_bft_orderer::blacklist::{PolicyState, Status};
use canton_participant::pgconn::{connect_with_retry, PgTarget, RetryPolicy};
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::sequencer::admin::v30 as admin_v30;
use postgres::Client;
use prost::Message as _;

/// Wire version of `BlacklistLeaderSelectionPolicyState` stored in `ord_leader_selection_state.state` (measured in `hub_sequencer`).
const LEADER_POLICY_PROTO_VERSION: i32 = 30;

const PARTITIONED_TABLES: [&str; 7] = [
    "ord_epochs",
    "ord_availability_batch",
    "ord_pbft_messages_in_progress",
    "ord_pbft_messages_completed",
    "ord_metadata_output_blocks",
    "ord_metadata_output_epochs",
    "ord_leader_selection_state",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdEpoch {
    pub epoch_number: i64,
    pub start_block_number: i64,
    pub epoch_length: i64,
    pub topology_ts: i64,
    pub in_progress: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdOutputBlock {
    pub epoch_number: i64,
    pub block_number: i64,
    pub bft_ts: i64,
}

#[derive(Debug, Clone, Default)]
pub struct OrdRecoveryState {
    pub latest_epoch: Option<OrdEpoch>,
    pub leader_policy: Option<PolicyState>,
    pub pbft_messages: Vec<Vec<u8>>,
    pub batches: Vec<(Vec<u8>, Vec<u8>)>,
    pub last_output_block: Option<OrdOutputBlock>,
    pub epoch_boundary_bft_ts: Option<i64>,
    pub last_epoch_could_alter_topology: Option<(i64, bool)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrdPruningStatus {
    pub latest_block_epoch: i64,
    pub latest_block: i64,
    pub latest_block_ts_micros: Option<i64>,
    pub lower_bound_epoch: i64,
    pub lower_bound_block: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdPruningSchedule {
    pub cron: String,
    pub max_duration_secs: i64,
    pub retention_secs: i64,
    pub min_blocks_to_keep: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdP2pEndpoint {
    pub address: String,
    pub port: i32,
    pub transport_security: bool,
    pub custom_server_trust_certificates: Option<Vec<u8>>,
    pub client_certificate_chain: Option<Vec<u8>>,
    pub client_private_key_file: Option<String>,
    pub node_id: Option<String>,
}

/// Encodes `PolicyState` as versioned v30 `BlacklistLeaderSelectionPolicyState` (`UntypedVersionedMessage`).
pub fn encode_leader_policy_state(policy: &PolicyState) -> Vec<u8> {
    use admin_v30::blacklist_leader_selection_policy_state::{
        blacklist_status::{Blacklisted, OnTrial, Status as ProtoStatus},
        BlacklistStatus,
    };
    let blacklist = policy
        .blacklist
        .iter()
        .map(|(node, status)| {
            let s = match *status {
                Status::OnTrial(failed_attempts_before_trial) => ProtoStatus::OnTrial(OnTrial {
                    failed_attempts_before_trial,
                }),
                Status::Blacklisted {
                    failed_attempts_before,
                    epochs_left_until_new_trial,
                } => ProtoStatus::Blacklisted(Blacklisted {
                    failed_attempts_before,
                    epochs_left_until_new_trial,
                }),
            };
            (node.clone(), BlacklistStatus { status: Some(s) })
        })
        .collect();
    let msg = admin_v30::BlacklistLeaderSelectionPolicyState {
        epoch_number: policy.epoch_number,
        start_block_number: policy.start_block,
        blacklist,
    };
    tw::versioned(msg.encode_to_vec(), LEADER_POLICY_PROTO_VERSION)
}

/// Decodes versioned v30 `BlacklistLeaderSelectionPolicyState` bytes into `PolicyState`.
pub fn decode_leader_policy_state(
    bytes: &[u8],
    nodes: Vec<String>,
    epoch_length: i64,
) -> Result<PolicyState, String> {
    use admin_v30::blacklist_leader_selection_policy_state::blacklist_status::Status as ProtoStatus;
    let (inner, version) = tw::unversioned(bytes)
        .ok_or_else(|| "leader selection state is not an UntypedVersionedMessage".to_string())?;
    if version != LEADER_POLICY_PROTO_VERSION {
        return Err(format!(
            "unsupported BlacklistLeaderSelectionPolicyState version {version} (expected {LEADER_POLICY_PROTO_VERSION})"
        ));
    }
    let proto = admin_v30::BlacklistLeaderSelectionPolicyState::decode(inner.as_slice())
        .map_err(|e| format!("decode BlacklistLeaderSelectionPolicyState: {e}"))?;
    let mut blacklist = BTreeMap::new();
    for (node, entry) in proto.blacklist {
        let Some(status) = entry.status else { continue };
        let mapped = match status {
            ProtoStatus::OnTrial(t) => Status::OnTrial(t.failed_attempts_before_trial),
            ProtoStatus::Blacklisted(b) => Status::Blacklisted {
                failed_attempts_before: b.failed_attempts_before,
                epochs_left_until_new_trial: b.epochs_left_until_new_trial,
            },
        };
        blacklist.insert(node, mapped);
    }
    let mut sorted_nodes = nodes;
    sorted_nodes.sort();
    sorted_nodes.dedup();
    Ok(PolicyState {
        epoch_number: proto.epoch_number,
        start_block: proto.start_block_number,
        blacklist,
        nodes: sorted_nodes,
        epoch_length,
    })
}

enum Cmd {
    StartEpoch(OrdEpoch),
    CompleteEpoch(i64),
    SaveBatch {
        id_hex: String,
        epoch_number: i64,
        batch: Vec<u8>,
    },
    SavePbftInProgress {
        block_number: i64,
        epoch_number: i64,
        view_number: i64,
        discriminator: i16,
        from_sequencer_id: String,
        message: Vec<u8>,
    },
    SavePbftCompleted {
        block_number: i64,
        epoch_number: i64,
        discriminator: i16,
        from_sequencer_id: String,
        message: Vec<u8>,
    },
    SaveOutputBlock {
        epoch_number: i64,
        block_number: i64,
        bft_ts: i64,
    },
    SaveOutputEpoch {
        epoch_number: i64,
        could_alter_ordering_topology: bool,
    },
    SaveLeaderPolicy {
        epoch_number: i64,
        state: Vec<u8>,
    },
    LoadRecovery {
        nodes: Vec<String>,
        default_epoch_length: i64,
        reply: mpsc::SyncSender<Result<OrdRecoveryState, String>>,
    },
    PruningStatus(mpsc::SyncSender<Result<OrdPruningStatus, String>>),
    Prune {
        retention_micros: i64,
        min_blocks_to_keep: i32,
        reply: mpsc::SyncSender<Result<String, String>>,
    },
    SetBftSchedule {
        schedule: OrdPruningSchedule,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    GetBftSchedule(mpsc::SyncSender<Result<Option<OrdPruningSchedule>, String>>),
    ClearSchedule(mpsc::SyncSender<Result<(), String>>),
    SetCron {
        cron: String,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    SetMaxDuration {
        secs: i64,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    SetRetention {
        secs: i64,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    SetMinBlocksToKeep {
        min_blocks_to_keep: i32,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    AddEndpoint {
        endpoint: OrdP2pEndpoint,
        reply: mpsc::SyncSender<Result<bool, String>>,
    },
    RemoveEndpoint {
        address: String,
        port: i32,
        transport_security: bool,
        reply: mpsc::SyncSender<Result<bool, String>>,
    },
    SetEndpointNodeId {
        address: String,
        port: i32,
        transport_security: bool,
        node_id: Option<String>,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    ListEndpoints(mpsc::SyncSender<Result<Vec<OrdP2pEndpoint>, String>>),
    Flush(mpsc::SyncSender<Result<(), String>>),
}

/// Asynchronous-writer / dedicated-thread PostgreSQL store for `ord_*` BFT consensus and availability state.
pub struct OrdStore {
    tx: Mutex<Option<mpsc::Sender<Cmd>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl OrdStore {
    /// Connects to `url_or_jdbc` on a dedicated OS thread (safe to call inside Tokio runtimes), ensures `ord_*` tables exist, and starts the DB worker thread.
    pub fn connect(url_or_jdbc: &str) -> Result<Self, String> {
        let target = PgTarget::from_url_or_jdbc(url_or_jdbc, None, None, None)?;
        let (init_tx, init_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let (tx, rx) = mpsc::channel::<Cmd>();
        let worker = std::thread::Builder::new()
            .name("ord-store-pg".into())
            .spawn(move || {
                // Connect inside the OS worker thread so `postgres::Client` never hits an outer Tokio runtime.
                let mut client = match connect_with_retry(&target, RetryPolicy::from_env()) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = init_tx.send(Err(format!(
                            "cannot connect to ord_* PostgreSQL store: {e}"
                        )));
                        return;
                    }
                };
                if let Err(e) = ensure_schema(&mut client) {
                    let _ = init_tx.send(Err(e));
                    return;
                }
                let has_partition_fn: bool = client
                    .query_one(
                        "SELECT to_regproc('create_partitions_for_epoch_range') IS NOT NULL",
                        &[],
                    )
                    .map(|r| r.get(0))
                    .unwrap_or(false);
                let _ = init_tx.send(Ok(()));
                worker_loop(target, client, has_partition_fn, rx);
            })
            .map_err(|e| format!("cannot spawn ord-store-pg thread: {e}"))?;

        init_rx
            .recv()
            .map_err(|_| "ord-store-pg thread terminated during connect".to_string())??;

        Ok(Self {
            tx: Mutex::new(Some(tx)),
            worker: Mutex::new(Some(worker)),
        })
    }

    fn send(&self, cmd: Cmd) {
        if let Ok(guard) = self.tx.lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(cmd);
            }
        }
    }

    pub fn start_epoch(&self, epoch: OrdEpoch) {
        self.send(Cmd::StartEpoch(epoch));
    }

    pub fn complete_epoch(&self, epoch_number: i64) {
        self.send(Cmd::CompleteEpoch(epoch_number));
    }

    pub fn save_batch(&self, batch_id: &[u8], epoch_number: i64, batch: Vec<u8>) {
        self.send(Cmd::SaveBatch {
            id_hex: crate::persistence::hex(batch_id),
            epoch_number,
            batch,
        });
    }

    pub fn save_pbft_in_progress(
        &self,
        block_number: i64,
        epoch_number: i64,
        view_number: i64,
        discriminator: i16,
        from_sequencer_id: String,
        message: Vec<u8>,
    ) {
        self.send(Cmd::SavePbftInProgress {
            block_number,
            epoch_number,
            view_number,
            discriminator,
            from_sequencer_id,
            message,
        });
    }

    pub fn save_pbft_completed(
        &self,
        block_number: i64,
        epoch_number: i64,
        discriminator: i16,
        from_sequencer_id: String,
        message: Vec<u8>,
    ) {
        self.send(Cmd::SavePbftCompleted {
            block_number,
            epoch_number,
            discriminator,
            from_sequencer_id,
            message,
        });
    }

    pub fn save_output_block(&self, epoch_number: i64, block_number: i64, bft_ts: i64) {
        self.send(Cmd::SaveOutputBlock {
            epoch_number,
            block_number,
            bft_ts,
        });
    }

    pub fn save_output_epoch(&self, epoch_number: i64, could_alter_ordering_topology: bool) {
        self.send(Cmd::SaveOutputEpoch {
            epoch_number,
            could_alter_ordering_topology,
        });
    }

    pub fn save_leader_policy(&self, policy: &PolicyState) {
        self.send(Cmd::SaveLeaderPolicy {
            epoch_number: policy.epoch_number,
            state: encode_leader_policy_state(policy),
        });
    }

    fn sync_call<T>(
        &self,
        op: &str,
        build: impl FnOnce(mpsc::SyncSender<Result<T, String>>) -> Cmd,
    ) -> Result<T, String> {
        let (reply, rx) = mpsc::sync_channel(1);
        let sent = self
            .tx
            .lock()
            .map_err(|e| e.to_string())?
            .as_ref()
            .ok_or_else(|| "ord_* store worker is closed".to_string())?
            .send(build(reply));
        sent.map_err(|_| "ord_* store worker disconnected".to_string())?;
        rx.recv()
            .map_err(|_| format!("ord_* store worker terminated during {op}"))?
    }

    pub fn flush(&self) -> Result<(), String> {
        self.sync_call("flush", Cmd::Flush)
    }

    pub fn load_recovery_state(
        &self,
        nodes: Vec<String>,
        default_epoch_length: i64,
    ) -> Result<OrdRecoveryState, String> {
        self.sync_call("recovery load", |reply| Cmd::LoadRecovery {
            nodes,
            default_epoch_length,
            reply,
        })
    }

    pub fn pruning_status(&self) -> Result<OrdPruningStatus, String> {
        self.sync_call("pruning status", Cmd::PruningStatus)
    }

    pub fn prune(&self, retention_micros: i64, min_blocks_to_keep: i32) -> Result<String, String> {
        self.sync_call("bft prune", |reply| Cmd::Prune {
            retention_micros,
            min_blocks_to_keep,
            reply,
        })
    }

    pub fn set_bft_schedule(&self, schedule: OrdPruningSchedule) -> Result<(), String> {
        self.sync_call("set bft schedule", |reply| Cmd::SetBftSchedule {
            schedule,
            reply,
        })
    }

    pub fn get_bft_schedule(&self) -> Result<Option<OrdPruningSchedule>, String> {
        self.sync_call("get bft schedule", Cmd::GetBftSchedule)
    }

    pub fn clear_schedule(&self) -> Result<(), String> {
        self.sync_call("clear schedule", Cmd::ClearSchedule)
    }

    pub fn update_cron(&self, cron: String) -> Result<(), String> {
        self.sync_call("update cron", |reply| Cmd::SetCron { cron, reply })
    }

    pub fn update_max_duration(&self, secs: i64) -> Result<(), String> {
        self.sync_call("update max duration", |reply| Cmd::SetMaxDuration {
            secs,
            reply,
        })
    }

    pub fn update_retention(&self, secs: i64) -> Result<(), String> {
        self.sync_call("update retention", |reply| Cmd::SetRetention {
            secs,
            reply,
        })
    }

    pub fn update_min_blocks_to_keep(&self, min_blocks_to_keep: i32) -> Result<(), String> {
        self.sync_call("update min blocks to keep", |reply| {
            Cmd::SetMinBlocksToKeep {
                min_blocks_to_keep,
                reply,
            }
        })
    }

    pub fn add_endpoint(&self, endpoint: OrdP2pEndpoint) -> Result<bool, String> {
        self.sync_call("add endpoint", |reply| Cmd::AddEndpoint { endpoint, reply })
    }

    pub fn remove_endpoint(
        &self,
        address: String,
        port: i32,
        transport_security: bool,
    ) -> Result<bool, String> {
        self.sync_call("remove endpoint", |reply| Cmd::RemoveEndpoint {
            address,
            port,
            transport_security,
            reply,
        })
    }

    pub fn set_endpoint_node_id(
        &self,
        address: String,
        port: i32,
        transport_security: bool,
        node_id: Option<String>,
    ) -> Result<(), String> {
        self.sync_call("set endpoint node id", |reply| Cmd::SetEndpointNodeId {
            address,
            port,
            transport_security,
            node_id,
            reply,
        })
    }

    pub fn list_endpoints(&self) -> Result<Vec<OrdP2pEndpoint>, String> {
        self.sync_call("list endpoints", Cmd::ListEndpoints)
    }
}

impl Drop for OrdStore {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.tx.lock() {
            guard.take();
        }
        if let Ok(mut guard) = self.worker.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

fn ensure_schema(client: &mut Client) -> Result<(), String> {
    client
        .batch_execute(
            r#"
            CREATE TABLE IF NOT EXISTS ord_epochs (
                epoch_number bigint NOT NULL PRIMARY KEY,
                start_block_number bigint NOT NULL,
                epoch_length bigint NOT NULL,
                topology_ts bigint NOT NULL,
                in_progress bool NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ord_availability_batch (
                id varchar COLLATE "C" NOT NULL,
                batch bytea NOT NULL,
                epoch_number bigint NOT NULL,
                PRIMARY KEY (id)
            );
            CREATE TABLE IF NOT EXISTS ord_pbft_messages_in_progress (
                block_number bigint NOT NULL,
                epoch_number bigint NOT NULL,
                view_number bigint NOT NULL,
                message bytea NOT NULL,
                discriminator smallint NOT NULL,
                from_sequencer_id varchar COLLATE "C" NOT NULL,
                PRIMARY KEY (block_number, view_number, from_sequencer_id, discriminator)
            );
            CREATE TABLE IF NOT EXISTS ord_pbft_messages_completed (
                block_number bigint NOT NULL,
                epoch_number bigint NOT NULL,
                message bytea NOT NULL,
                discriminator smallint NOT NULL,
                from_sequencer_id varchar COLLATE "C" NOT NULL,
                PRIMARY KEY (block_number, epoch_number, from_sequencer_id, discriminator)
            );
            CREATE TABLE IF NOT EXISTS ord_metadata_output_blocks (
                epoch_number bigint NOT NULL,
                block_number bigint NOT NULL PRIMARY KEY,
                bft_ts bigint NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ord_metadata_output_epochs (
                epoch_number bigint NOT NULL PRIMARY KEY,
                could_alter_ordering_topology bool NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ord_leader_selection_state (
                epoch_number bigint NOT NULL PRIMARY KEY,
                state bytea NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ord_output_lower_bound (
                single_row_lock char(1) NOT NULL DEFAULT 'X' PRIMARY KEY CHECK (single_row_lock = 'X'),
                epoch_number bigint NOT NULL,
                block_number bigint NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ord_pruning_schedules (
                lock char(1) NOT NULL DEFAULT 'X' PRIMARY KEY CHECK (lock = 'X'),
                cron varchar COLLATE "C" NOT NULL,
                max_duration bigint NOT NULL,
                retention bigint NOT NULL,
                min_blocks_to_keep integer NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ord_p2p_endpoints (
                address varchar COLLATE "C" NOT NULL,
                port integer NOT NULL,
                transport_security bool NOT NULL,
                custom_server_trust_certificates bytea NULL,
                client_certificate_chain bytea NULL,
                client_private_key_file varchar COLLATE "C" NULL,
                PRIMARY KEY (address, port, transport_security)
            );
            ALTER TABLE ord_p2p_endpoints
                ADD COLUMN IF NOT EXISTS node_id varchar COLLATE "C" DEFAULT NULL;
            CREATE TABLE IF NOT EXISTS ord_partition_size_history (
                epoch_number bigint NOT NULL PRIMARY KEY,
                partition_number bigint NOT NULL,
                partition_size integer NOT NULL
            );
            INSERT INTO ord_partition_size_history (epoch_number, partition_number, partition_size)
            VALUES (0, 0, 10)
            ON CONFLICT (epoch_number) DO NOTHING;
            "#,
        )
        .map_err(|e| format!("failed to ensure ord_* tables: {e}"))
}

fn ensure_epoch_partitions(
    client: &mut Client,
    has_partition_fn: bool,
    ensured_epochs: &mut BTreeSet<i64>,
    epoch: i64,
) -> Result<(), String> {
    if !has_partition_fn || ensured_epochs.contains(&epoch) {
        return Ok(());
    }
    for tbl in PARTITIONED_TABLES {
        let sql = format!("SELECT create_partitions_for_epoch_range('{tbl}'::regclass, $1, $1)");
        client
            .execute(&sql, &[&epoch])
            .map_err(|e| format!("create_partitions_for_epoch_range({tbl}, {epoch}): {e}"))?;
    }
    ensured_epochs.insert(epoch);
    Ok(())
}

fn worker_loop(
    target: PgTarget,
    mut client: Client,
    has_partition_fn: bool,
    rx: mpsc::Receiver<Cmd>,
) {
    let mut ensured_epochs = BTreeSet::new();
    let mut sticky_err: Option<String> = None;

    for cmd in rx {
        if let Err(e) = handle_cmd(
            &target,
            &mut client,
            has_partition_fn,
            &mut ensured_epochs,
            cmd,
            &mut sticky_err,
        ) {
            crate::diag::diag_eprintln!("ORD_STORE error: {e}");
            sticky_err = Some(e);
        }
    }
}

fn run_with_reconnect_res<T, F>(
    target: &PgTarget,
    client: &mut Client,
    mut op: F,
) -> Result<T, String>
where
    F: FnMut(&mut Client) -> Result<T, postgres::Error>,
{
    match op(client) {
        Ok(val) => Ok(val),
        Err(first_err) => {
            if client.is_closed() || first_err.is_closed() {
                if let Ok(mut fresh) = connect_with_retry(target, RetryPolicy::from_env()) {
                    return match op(&mut fresh) {
                        Ok(val) => {
                            *client = fresh;
                            Ok(val)
                        }
                        Err(second) => {
                            *client = fresh;
                            Err(second.to_string())
                        }
                    };
                }
            }
            Err(first_err.to_string())
        }
    }
}

fn run_with_reconnect<F>(target: &PgTarget, client: &mut Client, op: F) -> Result<(), String>
where
    F: FnMut(&mut Client) -> Result<(), postgres::Error>,
{
    run_with_reconnect_res(target, client, op)
}

fn send_sync_reply<T>(
    target: &PgTarget,
    client: &mut Client,
    reply: mpsc::SyncSender<Result<T, String>>,
    op: impl FnMut(&mut Client) -> Result<T, String>,
) -> Result<(), String> {
    let mut op = op;
    let res = if client.is_closed() {
        match connect_with_retry(target, RetryPolicy::from_env()) {
            Ok(mut fresh) => {
                let r = op(&mut fresh);
                *client = fresh;
                r
            }
            Err(e) => Err(e),
        }
    } else {
        op(client)
    };
    let _ = reply.send(res);
    Ok(())
}

fn handle_cmd(
    target: &PgTarget,
    client: &mut Client,
    has_partition_fn: bool,
    ensured_epochs: &mut BTreeSet<i64>,
    cmd: Cmd,
    sticky_err: &mut Option<String>,
) -> Result<(), String> {
    match cmd {
        Cmd::StartEpoch(epoch) => {
            ensure_epoch_partitions(client, has_partition_fn, ensured_epochs, epoch.epoch_number)?;
            run_with_reconnect(target, client, |c| {
                c.execute(
                    "INSERT INTO ord_epochs (epoch_number, start_block_number, epoch_length, topology_ts, in_progress) \
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                    &[
                        &epoch.epoch_number,
                        &epoch.start_block_number,
                        &epoch.epoch_length,
                        &epoch.topology_ts,
                        &epoch.in_progress,
                    ],
                )?;
                Ok(())
            })
        }
        Cmd::CompleteEpoch(epoch_number) => run_with_reconnect(target, client, |c| {
            c.execute(
                "UPDATE ord_epochs SET in_progress = false WHERE epoch_number = $1",
                &[&epoch_number],
            )?;
            Ok(())
        }),
        Cmd::SaveBatch {
            id_hex,
            epoch_number,
            batch,
        } => {
            ensure_epoch_partitions(client, has_partition_fn, ensured_epochs, epoch_number)?;
            run_with_reconnect(target, client, |c| {
                c.execute(
                    "INSERT INTO ord_availability_batch (id, batch, epoch_number) \
                     VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    &[&id_hex, &batch, &epoch_number],
                )?;
                Ok(())
            })
        }
        Cmd::SavePbftInProgress {
            block_number,
            epoch_number,
            view_number,
            discriminator,
            from_sequencer_id,
            message,
        } => {
            ensure_epoch_partitions(client, has_partition_fn, ensured_epochs, epoch_number)?;
            run_with_reconnect(target, client, |c| {
                c.execute(
                    "INSERT INTO ord_pbft_messages_in_progress \
                     (block_number, epoch_number, view_number, message, discriminator, from_sequencer_id) \
                     VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                    &[
                        &block_number,
                        &epoch_number,
                        &view_number,
                        &message,
                        &discriminator,
                        &from_sequencer_id,
                    ],
                )?;
                Ok(())
            })
        }
        Cmd::SavePbftCompleted {
            block_number,
            epoch_number,
            discriminator,
            from_sequencer_id,
            message,
        } => {
            ensure_epoch_partitions(client, has_partition_fn, ensured_epochs, epoch_number)?;
            run_with_reconnect(target, client, |c| {
                c.execute(
                    "INSERT INTO ord_pbft_messages_completed \
                     (block_number, epoch_number, message, discriminator, from_sequencer_id) \
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                    &[
                        &block_number,
                        &epoch_number,
                        &message,
                        &discriminator,
                        &from_sequencer_id,
                    ],
                )?;
                c.execute(
                    "DELETE FROM ord_pbft_messages_in_progress WHERE block_number = $1",
                    &[&block_number],
                )?;
                Ok(())
            })
        }
        Cmd::SaveOutputBlock {
            epoch_number,
            block_number,
            bft_ts,
        } => {
            ensure_epoch_partitions(client, has_partition_fn, ensured_epochs, epoch_number)?;
            run_with_reconnect(target, client, |c| {
                c.execute(
                    "INSERT INTO ord_metadata_output_blocks (epoch_number, block_number, bft_ts) \
                     VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    &[&epoch_number, &block_number, &bft_ts],
                )?;
                Ok(())
            })
        }
        Cmd::SaveOutputEpoch {
            epoch_number,
            could_alter_ordering_topology,
        } => {
            ensure_epoch_partitions(client, has_partition_fn, ensured_epochs, epoch_number)?;
            run_with_reconnect(target, client, |c| {
                c.execute(
                    "INSERT INTO ord_metadata_output_epochs (epoch_number, could_alter_ordering_topology) \
                     VALUES ($1, $2) ON CONFLICT (epoch_number) DO UPDATE \
                     SET could_alter_ordering_topology = ord_metadata_output_epochs.could_alter_ordering_topology OR EXCLUDED.could_alter_ordering_topology",
                    &[&epoch_number, &could_alter_ordering_topology],
                )?;
                Ok(())
            })
        }
        Cmd::SaveLeaderPolicy {
            epoch_number,
            state,
        } => {
            ensure_epoch_partitions(client, has_partition_fn, ensured_epochs, epoch_number)?;
            run_with_reconnect(target, client, |c| {
                c.execute(
                    "INSERT INTO ord_leader_selection_state (epoch_number, state) \
                     VALUES ($1, $2) ON CONFLICT (epoch_number) DO UPDATE SET state = EXCLUDED.state",
                    &[&epoch_number, &state],
                )?;
                Ok(())
            })
        }
        Cmd::LoadRecovery {
            nodes,
            default_epoch_length,
            reply,
        } => send_sync_reply(target, client, reply, |c| {
            read_recovery_state(c, nodes.clone(), default_epoch_length)
        }),
        Cmd::PruningStatus(reply) => send_sync_reply(target, client, reply, read_pruning_status),
        Cmd::Prune {
            retention_micros,
            min_blocks_to_keep,
            reply,
        } => send_sync_reply(target, client, reply, |c| {
            perform_prune(c, retention_micros, min_blocks_to_keep)
        }),
        Cmd::SetBftSchedule { schedule, reply } => {
            send_sync_reply(target, client, reply, |c| db_set_bft_schedule(c, &schedule))
        }
        Cmd::GetBftSchedule(reply) => send_sync_reply(target, client, reply, db_get_bft_schedule),
        Cmd::ClearSchedule(reply) => send_sync_reply(target, client, reply, db_clear_schedule),
        Cmd::SetCron { cron, reply } => {
            send_sync_reply(target, client, reply, |c| db_update_cron(c, &cron))
        }
        Cmd::SetMaxDuration { secs, reply } => send_sync_reply(target, client, reply, |c| {
            db_update_schedule_i64(c, "max_duration", secs)
        }),
        Cmd::SetRetention { secs, reply } => send_sync_reply(target, client, reply, |c| {
            db_update_schedule_i64(c, "retention", secs)
        }),
        Cmd::SetMinBlocksToKeep {
            min_blocks_to_keep,
            reply,
        } => send_sync_reply(target, client, reply, |c| {
            db_update_min_blocks(c, min_blocks_to_keep)
        }),
        Cmd::AddEndpoint { endpoint, reply } => {
            send_sync_reply(target, client, reply, |c| db_add_endpoint(c, &endpoint))
        }
        Cmd::RemoveEndpoint {
            address,
            port,
            transport_security,
            reply,
        } => send_sync_reply(target, client, reply, |c| {
            db_remove_endpoint(c, &address, port, transport_security)
        }),
        Cmd::SetEndpointNodeId {
            address,
            port,
            transport_security,
            node_id,
            reply,
        } => send_sync_reply(target, client, reply, |c| {
            db_set_endpoint_node_id(c, &address, port, transport_security, node_id.as_deref())
        }),
        Cmd::ListEndpoints(reply) => send_sync_reply(target, client, reply, db_list_endpoints),
        Cmd::Flush(reply) => {
            let res = match sticky_err.take() {
                Some(err) => Err(err),
                None => client
                    .batch_execute("")
                    .map_err(|e| format!("ord_* flush check failed: {e}")),
            };
            let _ = reply.send(res);
            Ok(())
        }
    }
}

fn read_recovery_state(
    client: &mut Client,
    nodes: Vec<String>,
    default_epoch_length: i64,
) -> Result<OrdRecoveryState, String> {
    let mut state = OrdRecoveryState::default();
    if let Some(r) = client
        .query_opt(
            "SELECT epoch_number, start_block_number, epoch_length, topology_ts, in_progress \
             FROM ord_epochs ORDER BY epoch_number DESC LIMIT 1",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        state.latest_epoch = Some(OrdEpoch {
            epoch_number: r.get(0),
            start_block_number: r.get(1),
            epoch_length: r.get(2),
            topology_ts: r.get(3),
            in_progress: r.get(4),
        });
    }

    let epoch_len = state
        .latest_epoch
        .as_ref()
        .map(|e| e.epoch_length)
        .filter(|l| *l > 0)
        .unwrap_or(default_epoch_length);

    if let Some(r) = client
        .query_opt(
            "SELECT state FROM ord_leader_selection_state ORDER BY epoch_number DESC LIMIT 1",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        let raw: Vec<u8> = r.get(0);
        state.leader_policy = Some(decode_leader_policy_state(&raw, nodes, epoch_len)?);
    }

    let latest_num = state
        .latest_epoch
        .as_ref()
        .map(|e| e.epoch_number)
        .or_else(|| state.leader_policy.as_ref().map(|p| p.epoch_number))
        .unwrap_or(0);
    let keep_from = latest_num.saturating_sub(1);

    for r in client
        .query(
            "SELECT message FROM ord_pbft_messages_completed WHERE epoch_number >= $1 \
             ORDER BY block_number ASC, discriminator ASC",
            &[&keep_from],
        )
        .map_err(|e| e.to_string())?
    {
        state.pbft_messages.push(r.get(0));
    }
    for r in client
        .query(
            "SELECT message FROM ord_pbft_messages_in_progress WHERE epoch_number >= $1 \
             ORDER BY block_number ASC, view_number ASC, discriminator ASC",
            &[&keep_from],
        )
        .map_err(|e| e.to_string())?
    {
        state.pbft_messages.push(r.get(0));
    }

    for r in client
        .query(
            "SELECT id, batch FROM ord_availability_batch WHERE epoch_number >= $1",
            &[&keep_from],
        )
        .map_err(|e| e.to_string())?
    {
        let id_hex: String = r.get(0);
        if let Some(id_bytes) = crate::persistence::unhex(&id_hex) {
            state.batches.push((id_bytes, r.get(1)));
        }
    }

    if let Some(r) = client
        .query_opt(
            "SELECT epoch_number, block_number, bft_ts FROM ord_metadata_output_blocks \
             ORDER BY block_number DESC LIMIT 1",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        state.last_output_block = Some(OrdOutputBlock {
            epoch_number: r.get(0),
            block_number: r.get(1),
            bft_ts: r.get(2),
        });
    }

    if let Some(ep) = &state.latest_epoch {
        if ep.start_block_number > 0 {
            let boundary_block = ep.start_block_number - 1;
            if let Some(r) = client
                .query_opt(
                    "SELECT bft_ts FROM ord_metadata_output_blocks WHERE block_number = $1",
                    &[&boundary_block],
                )
                .map_err(|e| e.to_string())?
            {
                state.epoch_boundary_bft_ts = Some(r.get(0));
            }
        }
    }

    if let Some(r) = client
        .query_opt(
            "SELECT epoch_number, could_alter_ordering_topology FROM ord_metadata_output_epochs \
             ORDER BY epoch_number DESC LIMIT 1",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        state.last_epoch_could_alter_topology = Some((r.get(0), r.get(1)));
    }

    Ok(state)
}

fn read_pruning_status(client: &mut Client) -> Result<OrdPruningStatus, String> {
    let mut status = OrdPruningStatus::default();
    if let Some(r) = client
        .query_opt(
            "SELECT epoch_number, block_number, bft_ts FROM ord_metadata_output_blocks \
             ORDER BY block_number DESC LIMIT 1",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        status.latest_block_epoch = r.get(0);
        status.latest_block = r.get(1);
        status.latest_block_ts_micros = Some(r.get(2));
    }
    if let Some(r) = client
        .query_opt(
            "SELECT epoch_number, block_number FROM ord_output_lower_bound LIMIT 1",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        status.lower_bound_epoch = r.get(0);
        status.lower_bound_block = r.get(1);
    }
    Ok(status)
}

fn perform_prune(
    client: &mut Client,
    retention_micros: i64,
    min_blocks_to_keep: i32,
) -> Result<String, String> {
    let Some(latest) = client
        .query_opt(
            "SELECT epoch_number, block_number, bft_ts FROM ord_metadata_output_blocks \
             ORDER BY block_number DESC LIMIT 1",
            &[],
        )
        .map_err(|e| e.to_string())?
    else {
        return Ok("No latest block information available to start pruning".into());
    };
    let latest_epoch: i64 = latest.get(0);
    let latest_block: i64 = latest.get(1);
    let latest_ts: i64 = latest.get(2);
    let cutoff_ts = latest_ts.saturating_sub(retention_micros);
    let min_keep_block = latest_block - i64::from(min_blocks_to_keep.max(0));

    let block1 = client
        .query_opt(
            "SELECT epoch_number, block_number FROM ord_metadata_output_blocks \
             WHERE bft_ts <= $1 ORDER BY block_number DESC LIMIT 1",
            &[&cutoff_ts],
        )
        .map_err(|e| e.to_string())?
        .map(|r| (r.get::<_, i64>(0), r.get::<_, i64>(1)));

    let block2 = if min_keep_block >= 0 {
        client
            .query_opt(
                "SELECT epoch_number, block_number FROM ord_metadata_output_blocks \
                 WHERE block_number = $1",
                &[&min_keep_block],
            )
            .map_err(|e| e.to_string())?
            .map(|r| (r.get::<_, i64>(0), r.get::<_, i64>(1)))
    } else {
        None
    };

    let prune_epoch = match (block1, block2) {
        (Some((ep1, _)), Some((ep2, _))) => ep1.min(ep2).min(latest_epoch),
        (Some(_), None) => {
            return Ok(format!(
                "Pruning can't be performed because there are not enough blocks to keep the minimum amount of blocks {min_blocks_to_keep}"
            ));
        }
        (None, Some(_)) => {
            return Ok(
                "Pruning can't be performed because there are no blocks to be pruned outside the retention period"
                    .into(),
            );
        }
        (None, None) => {
            return Ok(format!(
                "No pruning point found from latest block {latest_block}"
            ));
        }
    };

    let existing_lower = client
        .query_opt(
            "SELECT epoch_number FROM ord_output_lower_bound LIMIT 1",
            &[],
        )
        .map_err(|e| e.to_string())?
        .map(|r| r.get::<_, i64>(0));

    if let Some(prev) = existing_lower {
        if prune_epoch < prev {
            return Err(format!(
                "Failed to save new pruning lower bound: requested epoch {prune_epoch} < existing {prev}"
            ));
        }
    }

    let lower_block: i64 = client
        .query_one(
            "SELECT COALESCE(MIN(block_number), 0) FROM ord_metadata_output_blocks WHERE epoch_number >= $1",
            &[&prune_epoch],
        )
        .map_err(|e| e.to_string())?
        .get(0);

    let batch_cutoff = prune_epoch - 1;
    let mut tx = client.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO ord_output_lower_bound (single_row_lock, epoch_number, block_number) \
         VALUES ('X', $1, $2) \
         ON CONFLICT (single_row_lock) DO UPDATE \
         SET epoch_number = EXCLUDED.epoch_number, block_number = EXCLUDED.block_number",
        &[&prune_epoch, &lower_block],
    )
    .map_err(|e| e.to_string())?;

    let pruned_blocks = tx
        .execute(
            "DELETE FROM ord_metadata_output_blocks WHERE epoch_number < $1",
            &[&prune_epoch],
        )
        .map_err(|e| e.to_string())?;
    let pruned_out_epochs = tx
        .execute(
            "DELETE FROM ord_metadata_output_epochs WHERE epoch_number < $1",
            &[&prune_epoch],
        )
        .map_err(|e| e.to_string())?;
    let pruned_epochs = tx
        .execute(
            "DELETE FROM ord_epochs WHERE epoch_number < $1",
            &[&prune_epoch],
        )
        .map_err(|e| e.to_string())?;
    let pruned_pbft = tx
        .execute(
            "DELETE FROM ord_pbft_messages_completed WHERE epoch_number < $1",
            &[&prune_epoch],
        )
        .map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM ord_pbft_messages_in_progress WHERE epoch_number < $1",
        &[&prune_epoch],
    )
    .map_err(|e| e.to_string())?;
    let pruned_batches = tx
        .execute(
            "DELETE FROM ord_availability_batch WHERE epoch_number < $1",
            &[&batch_cutoff],
        )
        .map_err(|e| e.to_string())?;
    tx.execute(
        "DELETE FROM ord_leader_selection_state WHERE epoch_number < $1",
        &[&batch_cutoff],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

    Ok(format!(
        "Pruning at epoch {prune_epoch} complete. EpochStore: pruned {pruned_epochs} epochs, {pruned_pbft} pbft messages. OutputStore: pruned {pruned_out_epochs} epochs and {pruned_blocks} blocks. AvailabilityStore: pruned {pruned_batches} batches."
    ))
}

fn db_set_bft_schedule(client: &mut Client, s: &OrdPruningSchedule) -> Result<(), String> {
    client
        .execute(
            "INSERT INTO ord_pruning_schedules (lock, cron, max_duration, retention, min_blocks_to_keep) \
             VALUES ('X', $1, $2, $3, $4) \
             ON CONFLICT (lock) DO UPDATE SET \
             cron = EXCLUDED.cron, \
             max_duration = EXCLUDED.max_duration, \
             retention = EXCLUDED.retention, \
             min_blocks_to_keep = EXCLUDED.min_blocks_to_keep",
            &[
                &s.cron,
                &s.max_duration_secs,
                &s.retention_secs,
                &s.min_blocks_to_keep,
            ],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn db_get_bft_schedule(client: &mut Client) -> Result<Option<OrdPruningSchedule>, String> {
    let row = client
        .query_opt(
            "SELECT cron, max_duration, retention, min_blocks_to_keep FROM ord_pruning_schedules WHERE lock = 'X'",
            &[],
        )
        .map_err(|e| e.to_string())?;
    Ok(row.map(|r| OrdPruningSchedule {
        cron: r.get(0),
        max_duration_secs: r.get(1),
        retention_secs: r.get(2),
        min_blocks_to_keep: r.get(3),
    }))
}

fn db_clear_schedule(client: &mut Client) -> Result<(), String> {
    client
        .execute("DELETE FROM ord_pruning_schedules WHERE lock = 'X'", &[])
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn db_update_cron(client: &mut Client, cron: &str) -> Result<(), String> {
    let updated = client
        .execute(
            "UPDATE ord_pruning_schedules SET cron = $1 WHERE lock = 'X'",
            &[&cron],
        )
        .map_err(|e| e.to_string())?;
    if updated == 0 {
        return Err("No pruning schedule configured".into());
    }
    Ok(())
}

fn db_update_schedule_i64(client: &mut Client, col: &str, secs: i64) -> Result<(), String> {
    let sql = match col {
        "max_duration" => "UPDATE ord_pruning_schedules SET max_duration = $1 WHERE lock = 'X'",
        "retention" => "UPDATE ord_pruning_schedules SET retention = $1 WHERE lock = 'X'",
        _ => return Err(format!("unknown schedule column: {col}")),
    };
    let updated = client.execute(sql, &[&secs]).map_err(|e| e.to_string())?;
    if updated == 0 {
        return Err("No pruning schedule configured".into());
    }
    Ok(())
}

fn db_update_min_blocks(client: &mut Client, min_blocks_to_keep: i32) -> Result<(), String> {
    let updated = client
        .execute(
            "UPDATE ord_pruning_schedules SET min_blocks_to_keep = $1 WHERE lock = 'X'",
            &[&min_blocks_to_keep],
        )
        .map_err(|e| e.to_string())?;
    if updated == 0 {
        return Err("No pruning schedule configured".into());
    }
    Ok(())
}

fn db_add_endpoint(client: &mut Client, ep: &OrdP2pEndpoint) -> Result<bool, String> {
    let rows = client
        .execute(
            "INSERT INTO ord_p2p_endpoints \
             (address, port, transport_security, custom_server_trust_certificates, client_certificate_chain, client_private_key_file, node_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (address, port, transport_security) DO NOTHING",
            &[
                &ep.address,
                &ep.port,
                &ep.transport_security,
                &ep.custom_server_trust_certificates,
                &ep.client_certificate_chain,
                &ep.client_private_key_file,
                &ep.node_id,
            ],
        )
        .map_err(|e| e.to_string())?;
    Ok(rows > 0)
}

fn db_remove_endpoint(
    client: &mut Client,
    address: &str,
    port: i32,
    transport_security: bool,
) -> Result<bool, String> {
    let rows = client
        .execute(
            "DELETE FROM ord_p2p_endpoints WHERE address = $1 AND port = $2 AND transport_security = $3",
            &[&address, &port, &transport_security],
        )
        .map_err(|e| e.to_string())?;
    Ok(rows > 0)
}

fn db_set_endpoint_node_id(
    client: &mut Client,
    address: &str,
    port: i32,
    transport_security: bool,
    node_id: Option<&str>,
) -> Result<(), String> {
    client
        .execute(
            "UPDATE ord_p2p_endpoints SET node_id = $4 \
             WHERE address = $1 AND port = $2 AND transport_security = $3",
            &[&address, &port, &transport_security, &node_id],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn db_list_endpoints(client: &mut Client) -> Result<Vec<OrdP2pEndpoint>, String> {
    let mut out = Vec::new();
    for r in client
        .query(
            "SELECT address, port, transport_security, custom_server_trust_certificates, client_certificate_chain, client_private_key_file, node_id \
             FROM ord_p2p_endpoints ORDER BY address ASC, port ASC, transport_security ASC",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        out.push(OrdP2pEndpoint {
            address: r.get(0),
            port: r.get(1),
            transport_security: r.get(2),
            custom_server_trust_certificates: r.get(3),
            client_certificate_chain: r.get(4),
            client_private_key_file: r.get(5),
            node_id: r.get(6),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leader_policy_state_matches_official_canton_v30_wire_bytes() {
        let mut policy = PolicyState::first(&["SEQ::sequencer1::1220aa".into()], 10);
        policy.epoch_number = 52760;
        policy.start_block = 527600;
        let encoded = encode_leader_policy_state(&policy);
        // Verified directly against hub_sequencer.ord_leader_selection_state for epoch 52760
        assert_eq!(
            crate::persistence::hex(&encoded),
            "0a0808989c0310f09920101e"
        );
        let decoded =
            decode_leader_policy_state(&encoded, vec!["SEQ::sequencer1::1220aa".into()], 10)
                .expect("decode");
        assert_eq!(decoded, policy);
    }

    #[test]
    fn leader_policy_state_round_trips_blacklist_statuses() {
        let mut policy =
            PolicyState::first(&["n1".into(), "n2".into(), "n3".into(), "n4".into()], 40);
        policy.epoch_number = 12;
        policy.start_block = 480;
        policy.blacklist.insert("n1".into(), Status::OnTrial(2));
        policy.blacklist.insert(
            "n2".into(),
            Status::Blacklisted {
                failed_attempts_before: 3,
                epochs_left_until_new_trial: 2,
            },
        );
        let bytes = encode_leader_policy_state(&policy);
        let back = decode_leader_policy_state(
            &bytes,
            vec!["n4".into(), "n1".into(), "n3".into(), "n2".into()],
            40,
        )
        .expect("round-trip");
        assert_eq!(back, policy);
    }
}
