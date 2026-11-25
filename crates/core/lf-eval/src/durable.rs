//! A minimal durable ledger: an append-only file of transactions with their command-deduplication records (S-STORE-001).
//!
//! What it promises (and what the tests in `tests/durable_crash.rs` check at every write boundary):
//! - **Atomic commit record.** A transaction and the deduplication entry of the command that made it are ONE record, framed as
//!   `[length u32 LE][crc32 u32 LE][body]`. A record is either fully there (length and checksum agree) or it does not exist; there
//!   is no state in which a transaction is durable without its dedup entry or the other way round.
//! - **Prefix recovery.** `open` reads records from the start and stops at the first one that is short or fails its checksum
//!   (a torn tail left by a crash), truncates the file there, and replays what is left into the active state. The recovered
//!   ledger is always a prefix of the committed history.
//! - **Durability point.** `commit` returns `Ok(offset)` only after the record was written AND synced (`sync_all`). A commit that
//!   returned `Ok` survives a crash; one that did not return may or may not (the caller must retry, and dedup makes the retry safe).
//!
//! [CANTON-NOTE: LIMITATION] This is a single-file journal, not the participant's database (R5/PostgreSQL is out of scope). The
//! crash points are simulated by writing part of a record or by truncating, not by killing a process or cutting power, and
//! "lost on power failure" is modelled by truncating back to the last synced length.
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value as Json};

use crate::tx_model::{ActiveLedgerState, ContractId, Node, NodeId, TransactionTree};

/// The identity of a command for deduplication: who submitted which command id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DedupKey {
    pub user_id: String,
    pub command_id: String,
    pub act_as: Vec<String>,
}

/// A deduplication entry stored with the transaction the command produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupEntry {
    pub key: DedupKey,
    /// The offset of the transaction (what a duplicate submission is answered with).
    pub offset: u64,
    /// The record time of the commit in microseconds (the start of the deduplication period).
    pub committed_at_micros: i64,
}

/// One committed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed {
    pub offset: u64,
    pub tx: TransactionTree,
    pub act_as: HashSet<String>,
    pub timestamp_micros: i64,
    pub dedup: Option<DedupKey>,
}

#[derive(Debug)]
pub enum DurableError {
    Io(std::io::Error),
    /// The transaction does not apply to the active state (nothing was written).
    Rejected(String),
    /// A crash was injected at the named point (the file is left as that crash would leave it).
    Crashed(CrashPoint),
}

impl From<std::io::Error> for DurableError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for DurableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Rejected(m) => write!(f, "transaction rejected: {m}"),
            Self::Crashed(p) => write!(f, "crashed at {p:?}"),
        }
    }
}

impl std::error::Error for DurableError {}

/// The write boundaries of a commit where a crash can be injected (S-STORE-001, AT-T04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CrashPoint {
    /// Nothing of the record reached the file.
    BeforeWrite,
    /// Only a part of the 8-byte header reached the file.
    MidHeader,
    /// The header and part of the body reached the file.
    MidBody,
    /// The whole record is in the file but was not synced: after a power failure it may be gone (see `lose_unsynced`).
    AfterWriteBeforeSync,
    /// The record is synced; the process dies before it can answer (the client never sees the result).
    AfterSyncBeforeReturn,
}

impl CrashPoint {
    pub const ALL: [CrashPoint; 5] = [
        Self::BeforeWrite,
        Self::MidHeader,
        Self::MidBody,
        Self::AfterWriteBeforeSync,
        Self::AfterSyncBeforeReturn,
    ];
}

fn set_json(s: &HashSet<String>) -> Json {
    let sorted: BTreeSet<&String> = s.iter().collect();
    json!(sorted)
}

fn set_from(v: &Json) -> HashSet<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn node_json(n: &Node) -> Json {
    match n {
        Node::Create {
            contract_id,
            template_id,
            payload,
            signatories,
            observers,
            key,
        } => json!({
            "t": "create", "cid": contract_id.0, "tpl": template_id, "payload": hex::encode(payload),
            "sig": set_json(signatories), "obs": set_json(observers), "key": key,
        }),
        Node::Exercise {
            contract_id,
            choice,
            acting_parties,
            consuming,
            children,
        } => json!({
            "t": "exercise", "cid": contract_id.0, "choice": choice, "act": set_json(acting_parties),
            "consuming": consuming, "children": children,
        }),
        Node::Fetch {
            contract_id,
            template_id,
            stakeholders,
        } => {
            json!({ "t": "fetch", "cid": contract_id.0, "tpl": template_id, "stk": set_json(stakeholders) })
        }
        Node::LookupByKey {
            template_id,
            key,
            found,
        } => {
            json!({ "t": "lookup", "tpl": template_id, "key": key, "found": found.as_ref().map(|c| c.0.clone()) })
        }
        Node::Rollback { children } => json!({ "t": "rollback", "children": children }),
    }
}

fn node_from(v: &Json) -> Option<Node> {
    let s = |k: &str| v.get(k).and_then(Json::as_str).map(str::to_string);
    let kids = |k: &str| -> Vec<NodeId> {
        v.get(k)
            .and_then(Json::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_u64().map(|n| n as NodeId))
                    .collect()
            })
            .unwrap_or_default()
    };
    Some(match v.get("t")?.as_str()? {
        "create" => Node::Create {
            contract_id: ContractId(s("cid")?),
            template_id: s("tpl")?,
            payload: hex::decode(s("payload")?).ok()?,
            signatories: set_from(v.get("sig")?),
            observers: set_from(v.get("obs")?),
            key: s("key"),
        },
        "exercise" => Node::Exercise {
            contract_id: ContractId(s("cid")?),
            choice: s("choice")?,
            acting_parties: set_from(v.get("act")?),
            consuming: v.get("consuming")?.as_bool()?,
            children: kids("children"),
        },
        "fetch" => Node::Fetch {
            contract_id: ContractId(s("cid")?),
            template_id: s("tpl")?,
            stakeholders: set_from(v.get("stk")?),
        },
        "lookup" => Node::LookupByKey {
            template_id: s("tpl")?,
            key: s("key")?,
            found: s("found").map(ContractId),
        },
        "rollback" => Node::Rollback {
            children: kids("children"),
        },
        _ => return None,
    })
}

fn tree_json(t: &TransactionTree) -> Json {
    let (roots, nodes, next) = t.parts();
    let mut ids: Vec<&NodeId> = nodes.keys().collect();
    ids.sort();
    json!({ "roots": roots, "next": next, "nodes": ids.iter().map(|i| json!([i, node_json(&nodes[i])])).collect::<Vec<_>>() })
}

fn tree_from(v: &Json) -> Option<TransactionTree> {
    let roots = v
        .get("roots")?
        .as_array()?
        .iter()
        .filter_map(|x| x.as_u64().map(|n| n as NodeId))
        .collect();
    let mut nodes = HashMap::new();
    for pair in v.get("nodes")?.as_array()? {
        let id = pair.get(0)?.as_u64()? as NodeId;
        nodes.insert(id, node_from(pair.get(1)?)?);
    }
    Some(TransactionTree::from_parts(
        roots,
        nodes,
        v.get("next")?.as_u64()? as NodeId,
    ))
}

fn encode(c: &Committed) -> Vec<u8> {
    let dedup = c
        .dedup
        .as_ref()
        .map(|d| json!({ "user": d.user_id, "command": d.command_id, "actAs": d.act_as }));
    let body = json!({
        "kind": "commit", "offset": c.offset, "ts": c.timestamp_micros, "actAs": set_json(&c.act_as),
        "tree": tree_json(&c.tx), "dedup": dedup,
    });
    serde_json::to_vec(&body).expect("a JSON value serializes")
}

/// One record of the file: a committed transaction or a prune marker.
enum Record {
    Commit(Box<Committed>),
    Prune { up_to: u64 },
}

fn decode(body: &[u8]) -> Option<Record> {
    let v: Json = serde_json::from_slice(body).ok()?;
    if v.get("kind")?.as_str()? == "prune" {
        return Some(Record::Prune {
            up_to: v.get("upTo")?.as_u64()?,
        });
    }
    decode_commit(&v).map(|c| Record::Commit(Box::new(c)))
}

fn decode_commit(v: &Json) -> Option<Committed> {
    let dedup = match v.get("dedup")? {
        Json::Null => None,
        d => Some(DedupKey {
            user_id: d.get("user")?.as_str()?.to_string(),
            command_id: d.get("command")?.as_str()?.to_string(),
            act_as: d
                .get("actAs")?
                .as_array()?
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
        }),
    };
    Some(Committed {
        offset: v.get("offset")?.as_u64()?,
        timestamp_micros: v.get("ts")?.as_i64()?,
        act_as: set_from(v.get("actAs")?),
        tx: tree_from(v.get("tree")?)?,
        dedup,
    })
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc32fast::hash(body).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// What `open` found in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    pub records: usize,
    /// Bytes cut off the end because they were a torn or corrupt tail (0 for a clean file).
    pub truncated_bytes: u64,
}

/// The durable ledger: the journal file, the live active state and the dedup table, kept equal to a replay of the file.
pub struct DurableLedger {
    path: PathBuf,
    file: File,
    /// Everything committed, in order (the replayable history).
    pub history: Vec<Committed>,
    pub state: ActiveLedgerState,
    pub dedup: HashMap<DedupKey, DedupEntry>,
    next_offset: u64,
    /// The file length at the last successful sync (what survives a power failure).
    synced_len: u64,
    pub recovery: Recovery,
    /// Offsets up to and including this one are pruned (0: nothing pruned).
    pruned_up_to: u64,
    /// The active state right after the last pruned offset: what an ACS read at the pruned boundary starts from.
    base_state: ActiveLedgerState,
}

/// A read below the pruned offset (Canton: `PARTICIPANT_PRUNED_DATA_ACCESSED`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    Pruned { requested: u64, pruned_up_to: u64 },
    BeyondLedgerEnd { requested: u64, ledger_end: u64 },
}

impl DurableLedger {
    /// Opens (creating if needed) the journal at `path`, recovering from a torn tail.
    pub fn open(path: &Path) -> Result<Self, DurableError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (mut at, mut history, mut pruned_up_to) = (0usize, Vec::new(), 0u64);
        while bytes.len() - at >= 8 {
            let len = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
                as usize;
            let crc =
                u32::from_le_bytes([bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7]]);
            let Some(body) = bytes.get(at + 8..at + 8 + len) else {
                break;
            };
            if crc32fast::hash(body) != crc {
                break;
            }
            let Some(rec) = decode(body) else { break };
            match rec {
                Record::Commit(c) => history.push(*c),
                Record::Prune { up_to } => pruned_up_to = pruned_up_to.max(up_to),
            }
            at += 8 + len;
        }
        let truncated = (bytes.len() - at) as u64;
        if truncated > 0 {
            file.set_len(at as u64)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        let mut state = ActiveLedgerState::new();
        let mut base_state = ActiveLedgerState::new();
        let mut dedup = HashMap::new();
        for c in &history {
            state
                .apply_transaction(&c.tx, &c.act_as)
                .map_err(|e| DurableError::Rejected(format!("replay: {e}")))?;
            if c.offset <= pruned_up_to {
                base_state = state.clone();
            }
            if let Some(k) = &c.dedup {
                dedup.insert(
                    k.clone(),
                    DedupEntry {
                        key: k.clone(),
                        offset: c.offset,
                        committed_at_micros: c.timestamp_micros,
                    },
                );
            }
        }
        let next_offset = history.last().map_or(pruned_up_to + 1, |c| c.offset + 1);
        history.retain(|c| c.offset > pruned_up_to);
        Ok(Self {
            path: path.to_path_buf(),
            file,
            recovery: Recovery {
                records: history.len(),
                truncated_bytes: truncated,
            },
            history,
            state,
            dedup,
            next_offset,
            synced_len: at as u64,
            pruned_up_to,
            base_state,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The pruned boundary: offsets up to and including it can no longer be read.
    pub fn pruned_up_to(&self) -> u64 {
        self.pruned_up_to
    }

    /// The ledger end: the offset of the last commit (0 for an empty ledger).
    pub fn ledger_end(&self) -> u64 {
        self.next_offset - 1
    }

    /// Prunes the history up to and including `up_to` (a durable prune marker; the data stays in the file until a compaction,
    /// which this engine does not have). Pruning never goes backwards and never past the ledger end.
    pub fn prune(&mut self, up_to: u64) -> Result<(), DurableError> {
        if up_to > self.ledger_end() {
            return Err(DurableError::Rejected(format!(
                "cannot prune past the ledger end {}",
                self.ledger_end()
            )));
        }
        if up_to <= self.pruned_up_to {
            return Ok(());
        }
        let record = frame(
            &serde_json::to_vec(&json!({ "kind": "prune", "upTo": up_to })).expect("serializes"),
        );
        self.file.write_all(&record)?;
        self.file.sync_all()?;
        self.synced_len += record.len() as u64;
        // the base state moves to the new boundary
        let mut st = self.base_state.clone();
        for c in self
            .history
            .iter()
            .filter(|c| c.offset > self.pruned_up_to && c.offset <= up_to)
        {
            st.apply_transaction(&c.tx, &c.act_as)
                .map_err(|e| DurableError::Rejected(format!("prune replay: {e}")))?;
        }
        self.base_state = st;
        self.history.retain(|c| c.offset > up_to);
        self.pruned_up_to = up_to;
        Ok(())
    }

    /// The active contract set as of `offset` (a consistent snapshot), or why it cannot be read.
    pub fn acs_at(&self, offset: u64) -> Result<ActiveLedgerState, ReadError> {
        if offset < self.pruned_up_to {
            return Err(ReadError::Pruned {
                requested: offset,
                pruned_up_to: self.pruned_up_to,
            });
        }
        if offset > self.ledger_end() {
            return Err(ReadError::BeyondLedgerEnd {
                requested: offset,
                ledger_end: self.ledger_end(),
            });
        }
        let mut st = self.base_state.clone();
        for c in self.history.iter().filter(|c| c.offset <= offset) {
            st.apply_transaction(&c.tx, &c.act_as)
                .expect("a committed history replays");
        }
        Ok(st)
    }

    /// The offset the next commit gets.
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// Commits a transaction durably. `crash` injects a crash at a write boundary: the file is left exactly as that crash would
    /// leave it and `Err(Crashed)` is returned (the in-memory ledger is then stale and must be dropped, as a dead process's is).
    pub fn commit(
        &mut self,
        tx: TransactionTree,
        act_as: HashSet<String>,
        timestamp_micros: i64,
        dedup: Option<DedupKey>,
        crash: Option<CrashPoint>,
    ) -> Result<u64, DurableError> {
        // validate against a copy first: a rejected transaction writes nothing
        let mut trial = self.state.clone();
        trial
            .apply_transaction(&tx, &act_as)
            .map_err(|e| DurableError::Rejected(e.to_string()))?;

        let offset = self.next_offset;
        let committed = Committed {
            offset,
            tx,
            act_as,
            timestamp_micros,
            dedup,
        };
        let record = frame(&encode(&committed));
        let crashed = |p| Err(DurableError::Crashed(p));
        if crash == Some(CrashPoint::BeforeWrite) {
            return crashed(CrashPoint::BeforeWrite);
        }
        if crash == Some(CrashPoint::MidHeader) {
            self.file.write_all(&record[..4])?;
            return crashed(CrashPoint::MidHeader);
        }
        if crash == Some(CrashPoint::MidBody) {
            self.file.write_all(&record[..8 + (record.len() - 8) / 2])?;
            return crashed(CrashPoint::MidBody);
        }
        self.file.write_all(&record)?;
        if crash == Some(CrashPoint::AfterWriteBeforeSync) {
            return crashed(CrashPoint::AfterWriteBeforeSync);
        }
        self.file.sync_all()?;
        self.synced_len += record.len() as u64;
        if crash == Some(CrashPoint::AfterSyncBeforeReturn) {
            return crashed(CrashPoint::AfterSyncBeforeReturn);
        }
        self.state = trial;
        if let Some(k) = &committed.dedup {
            self.dedup.insert(
                k.clone(),
                DedupEntry {
                    key: k.clone(),
                    offset,
                    committed_at_micros: timestamp_micros,
                },
            );
        }
        self.history.push(committed);
        self.next_offset += 1;
        Ok(offset)
    }

    /// Models a power failure after `AfterWriteBeforeSync`: the bytes that were written but never synced are gone.
    pub fn lose_unsynced(path: &Path, synced_len: u64) -> std::io::Result<()> {
        let f = OpenOptions::new().write(true).open(path)?;
        f.set_len(synced_len)
    }

    /// The file length that is known to be on disk (for `lose_unsynced`).
    pub fn synced_len(&self) -> u64 {
        self.synced_len
    }
}
