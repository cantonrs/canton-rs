//! What the Rust sequencer keeps across a restart (G6, S-NET-037 part 16): an append-only **journal** in the state directory, and the
//! synchronizer's keys.
//!
//! [CANTON-NOTE: SEMANTICS] The journal records what the server **produced**, not what it was asked: one line for each
//! - `R` member registration (the member and its onboarding transactions; replayed through the same validation),
//! - `A` appended onboarding transaction of the topology state (sequencing time, the signed transaction),
//! - `B` topology broadcast the state took (sequencing time, the envelope content; the tracker decides again what is in force),
//! - `K` acknowledgement of a member (`K <member> <timestamp>`: it will not read events up to then again),
//! - `H` submission the mediator handled (its sender, time and envelopes: replayed to rebuild the requests in flight),
//! - `X` time at which the mediator timed requests out (replayed the same way),
//! - `E` event stored for a member (its timestamp, the chain link to the previous one, message id, error, envelopes with recipients and
//!   signatures),
//! - `S` serial of the physical synchronizer from here on (a logical upgrade's successor, see [`seed_successor`]),
//! - `G` contribution to an aggregation in flight (`crate::aggregation::contribution_line`; dropped by the compaction once expired),
//! - `T` / `P` what a member spent / its latest traffic purchase (`crate::traffic::consumed_line`, `purchased_line`; the compaction keeps
//!   the last of each).
//!
//! A journal written before a line type existed has none of it and replays as before.
//!
//! Events are journaled as they are, so a member that reconnects after a restart reads **the same events with the same timestamps and
//! chain links** and resumes at its cursor; the topology state and the registry are rebuilt by replaying `R`, `A` and `B`. Every line is
//! written and synced before the server answers the call that caused it, under the lock that orders the events.
//!
//! [CANTON-NOTE: SEMANTICS] The mediator's requests **in flight** come back by replaying what it handled (`H`, `X`) with its outputs thrown
//! away (they are the `E` events already): a request whose verdict was pending at the restart is decided when its responses arrive, or
//! timed out. [CANTON-NOTE: LIMITATION] Authentication tokens are not kept: a member authenticates
//! again. A journal that ends in a half-written line (a crash in the middle of a write) loses that line only.
use crate::sequencing::{StoredEnvelope, StoredEvent};
use canton_participant::state_store::{FileStore, StateStore};
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::Recipients as ProtoRecipients;
use prost::Message;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// The key of the journal in a [`StateStore`].
const JOURNAL: &str = "journal";

fn io(e: String) -> std::io::Error {
    std::io::Error::other(e)
}

/// The sequencer's journal: the lines under the key `journal` of a state store (a file of a directory, or the lines of a database), open for
/// appending.
pub struct Journal {
    store: Arc<dyn StateStore>,
    /// Orders what is written and rewritten: a rewrite reads and replaces the whole journal, and no line may be written in between.
    order: Mutex<()>,
    /// The exclusive lock on the state directory (held as long as the journal is open): two servers on one directory would interleave
    /// their lines and each would replay a history the other made. A database store has its own lock.
    _lock: Option<std::fs::File>,
}

impl Journal {
    /// Opens (creating it) the journal in `dir` and returns it with the lines it already holds, in order. A last line that does not end
    /// in a newline was cut short by a crash and is dropped.
    pub fn open(dir: &Path) -> std::io::Result<(Arc<Journal>, Vec<String>)> {
        std::fs::create_dir_all(dir)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("lock"))?;
        lock.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!(
                    "the state directory {} is in use by another server",
                    dir.display()
                ),
            ),
            std::fs::TryLockError::Error(e) => e,
        })?;
        Self::open_in(FileStore::new(dir).map_err(io)?, Some(lock))
    }

    /// Opens the journal kept in `store` (see [`Journal::open`]).
    pub fn open_in(
        store: Arc<dyn StateStore>,
        lock: Option<std::fs::File>,
    ) -> std::io::Result<(Arc<Journal>, Vec<String>)> {
        let text = store.read(JOURNAL).map_err(io)?.unwrap_or_default();
        let mut lines = Vec::new();
        let mut keep = 0usize;
        for line in text.split_inclusive('\n') {
            if !line.ends_with('\n') {
                break;
            }
            keep += line.len();
            lines.push(line.trim_end().to_string());
        }
        // a cut-short last line is removed so that the next line starts cleanly
        if keep < text.len() {
            store.write(JOURNAL, &text[..keep]).map_err(io)?;
        }
        Ok((
            Arc::new(Journal {
                store,
                order: Mutex::new(()),
                _lock: lock,
            }),
            lines,
        ))
    }

    /// Replaces the journal by `lines` at once (a crash leaves the old journal or the new one) and goes on appending to the new one.
    pub fn replace(&self, lines: &[String]) -> std::io::Result<()> {
        let _order = self
            .order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut text = String::new();
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
        self.store.write(JOURNAL, &text).map_err(io)
    }

    /// Rewrites the journal **while it is in use**: its lines as they are now go through `shorten`, and what it returns replaces them. No
    /// line is written between the read and the replacement, so none is lost. Returns how many lines there were and how many there are.
    pub fn rewrite(
        &self,
        shorten: impl FnOnce(Vec<String>) -> Vec<String>,
    ) -> std::io::Result<(usize, usize)> {
        let _order = self
            .order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let text = self.store.read(JOURNAL).map_err(io)?.unwrap_or_default();
        // a half-written last line cannot be here: every line is written whole under this lock
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        let before = lines.len();
        let kept = shorten(lines);
        if kept.len() >= before {
            return Ok((before, before));
        }
        let mut out = String::new();
        for line in &kept {
            out.push_str(line);
            out.push('\n');
        }
        self.store.write(JOURNAL, &out).map_err(io)?;
        Ok((before, kept.len()))
    }

    /// Appends one line and makes it durable. A sequencer that cannot persist what it ordered must not go on answering.
    pub fn write(&self, line: &str) {
        let _order = self
            .order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.store
            .append(JOURNAL, line)
            .expect("the sequencer's journal is writable");
    }
}

/// The serial of the physical synchronizer in the lines of a journal: the last `S` line, 0 when there is none.
pub fn serial_of(text: &str) -> std::io::Result<u32> {
    match text.lines().rev().find_map(|l| l.strip_prefix("S ")) {
        None => Ok(0),
        Some(serial) => serial.trim().parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "a damaged serial line")
        }),
    }
}

/// The serial of the physical synchronizer kept in `dir`: the last `S` line of its journal, 0 when there is none (a synchronizer that was
/// never upgraded).
pub fn serial_in(dir: &Path) -> std::io::Result<u32> {
    let text = match std::fs::read_to_string(dir.join("journal")) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    match text.lines().rev().find_map(|l| l.strip_prefix("S ")) {
        None => Ok(0),
        Some(serial) => serial.trim().parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "a damaged serial line")
        }),
    }
}

/// Makes `dir` the state directory of the **successor** of the synchronizer kept in `predecessor` (a logical synchronizer upgrade) and
/// returns the successor's serial. Does nothing to a directory that already has a journal (the successor started before).
///
/// [CANTON-NOTE: SEMANTICS] The successor is the same synchronizer one serial on: the same keys (its sequencer has the **same id**, which
/// the participant checks against the predecessor's `LsuSequencerConnectionSuccessor`), the members that registered, and the topology
/// (`R`, `A`, `B` and `S` lines). It starts with **no events**: a member's first event there has no previous one, and nothing it
/// acknowledged before applies. The topology is frozen from the announcement on (see `topology_state::Tracker`), so the state taken when
/// the successor is seeded after the announcement is the state at the upgrade time.
///
/// [CANTON-NOTE: INVARIANT] The copied lines are followed by `S <serial>`: the replay decides them as the predecessor did (a change the
/// frozen predecessor refused is refused again) and only what comes after is decided as the successor.
pub fn seed_successor(predecessor: &Path, dir: &Path) -> std::io::Result<u32> {
    if dir.join("journal").exists() {
        return serial_in(dir);
    }
    std::fs::create_dir_all(dir)?;
    std::fs::copy(predecessor.join("keys"), dir.join("keys"))?;
    let serial = serial_in(predecessor)? + 1;
    let text = std::fs::read_to_string(predecessor.join("journal"))?;
    // a last line the predecessor is still writing has no newline yet: it is not taken
    let whole = match text.rfind('\n') {
        Some(end) => &text[..=end],
        None => "",
    };
    let tmp = dir.join("journal.tmp");
    {
        let mut out = std::fs::File::create(&tmp)?;
        for line in whole
            .lines()
            .filter(|l| matches!(l.as_bytes().first(), Some(b'R' | b'A' | b'B' | b'S')))
        {
            writeln!(out, "{line}")?;
        }
        writeln!(out, "S {serial}")?;
        out.sync_all()?;
    }
    // the journal is the last thing written: a directory with one is a complete successor
    std::fs::rename(&tmp, dir.join("journal"))?;
    Ok(serial)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// A member's journaled registration: `R <member> <hex of each signed transaction, comma separated>`.
pub fn registration_line(
    member: &str,
    transactions: &[canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction],
) -> String {
    format!(
        "R {member} {}",
        transactions
            .iter()
            .map(|t| hex(&t.encode_to_vec()))
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub fn decode_registration(
    line: &str,
) -> Option<(
    String,
    Vec<canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction>,
)> {
    let mut parts = line.strip_prefix("R ")?.split(' ');
    let member = parts.next()?.to_string();
    let transactions = parts
        .next()?
        .split(',')
        .map(|h| {
            canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction::decode(
                unhex(h)?.as_slice(),
            )
            .ok()
        })
        .collect::<Option<Vec<_>>>()?;
    Some((member, transactions))
}

fn optional(text: &str) -> Option<&str> {
    (text != "-").then_some(text)
}

/// The envelopes of an event or of a mediator input as one field: `-` for none, else the envelopes comma separated.
pub(crate) fn envelopes_field(envelopes: &[StoredEnvelope]) -> String {
    if envelopes.is_empty() {
        return "-".to_string();
    }
    envelopes
        .iter()
        .map(|env| {
            let recipients = env
                .recipients
                .iter()
                .map(|tree| tree.join("\t"))
                .collect::<Vec<_>>()
                .join("\n");
            let sigs = env
                .signatures
                .iter()
                .map(|s| hex(&s.encode_to_vec()))
                .collect::<Vec<_>>()
                .join("+");
            if env.recipient_trees.iter().any(|t| !t.children.is_empty()) {
                let tree_proto = ProtoRecipients {
                    recipients_tree: env.recipient_trees.clone(),
                };
                format!(
                    "{}.{}.{}.{}",
                    hex(recipients.as_bytes()),
                    hex(&env.content),
                    sigs,
                    hex(&tree_proto.encode_to_vec())
                )
            } else {
                format!(
                    "{}.{}.{}",
                    hex(recipients.as_bytes()),
                    hex(&env.content),
                    sigs
                )
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn parse_envelopes(field: &str) -> Option<Vec<StoredEnvelope>> {
    let mut envelopes = Vec::new();
    if let Some(all) = optional(field) {
        for env in all.split(',') {
            let mut f = env.split('.');
            let recipients = String::from_utf8(unhex(f.next()?)?).ok()?;
            let content = unhex(f.next()?)?;
            let signatures = match f.next()? {
                "" => Vec::new(),
                s => s
                    .split('+')
                    .map(|h| Signature::decode(unhex(h)?.as_slice()).ok())
                    .collect::<Option<Vec<_>>>()?,
            };
            let recipient_trees = match f.next() {
                Some(tree_hex) => {
                    ProtoRecipients::decode(unhex(tree_hex)?.as_slice())
                        .ok()?
                        .recipients_tree
                }
                None => Vec::new(),
            };
            envelopes.push(StoredEnvelope {
                recipients: recipients
                    .split('\n')
                    .map(|tree| tree.split('\t').map(str::to_string).collect())
                    .collect(),
                recipient_trees,
                content,
                signatures,
            });
        }
    }
    Some(envelopes)
}

/// A submission the mediator handled: `H <timestamp> <sender> <envelopes>`.
pub(crate) fn mediator_input_line(
    timestamp: i64,
    sender: &str,
    envelopes: &[StoredEnvelope],
) -> String {
    format!("H {timestamp} {sender} {}", envelopes_field(envelopes))
}

pub(crate) fn decode_mediator_input(line: &str) -> Option<(i64, String, Vec<StoredEnvelope>)> {
    let mut p = line.strip_prefix("H ")?.split(' ');
    let timestamp = p.next()?.parse().ok()?;
    let sender = p.next()?.to_string();
    Some((timestamp, sender, parse_envelopes(p.next()?)?))
}

/// An event stored for `member`: `E <member> <timestamp> <previous|-> <hex message id|-> <code:hex message|-> <envelopes|->` and, when
/// the sender paid for it, ` R<cost>:<extra consumed>:<base remaining>`; an envelope
/// is `<hex recipients>.<hex content>.<hex signature,...>` and envelopes are comma separated; recipients are trees separated by a line
/// feed and the addresses of a tree by a tab.
pub(crate) fn event_line(member: &str, e: &StoredEvent) -> String {
    let envelopes = envelopes_field(&e.envelopes);
    let receipt = e
        .receipt
        .map_or(String::new(), |(c, x, b)| format!(" R{c}:{x}:{b}"));
    format!(
        "E {member} {} {} {} {} {envelopes}{receipt}",
        e.timestamp,
        e.previous.map_or("-".to_string(), |p| p.to_string()),
        e.message_id
            .as_ref()
            .map_or("-".to_string(), |m| hex(m.as_bytes())),
        e.error.as_ref().map_or("-".to_string(), |(c, m)| format!(
            "{c}:{}",
            hex(m.as_bytes())
        )),
    )
}

pub(crate) fn decode_event(line: &str) -> Option<(String, StoredEvent)> {
    let mut p = line.strip_prefix("E ")?.split(' ');
    let member = p.next()?.to_string();
    let timestamp = p.next()?.parse().ok()?;
    let previous = match optional(p.next()?) {
        Some(t) => Some(t.parse().ok()?),
        None => None,
    };
    let message_id = match optional(p.next()?) {
        Some(h) => Some(String::from_utf8(unhex(h)?).ok()?),
        None => None,
    };
    let error = match optional(p.next()?) {
        Some(t) => {
            let (code, message) = t.split_once(':')?;
            Some((code.parse().ok()?, String::from_utf8(unhex(message)?).ok()?))
        }
        None => None,
    };
    let envelopes = parse_envelopes(p.next()?)?;
    let receipt = match p.next() {
        None => None,
        Some(r) => {
            let mut f = r.strip_prefix('R')?.split(':');
            Some((
                f.next()?.parse().ok()?,
                f.next()?.parse().ok()?,
                f.next()?.parse().ok()?,
            ))
        }
    };
    Some((
        member,
        StoredEvent {
            receipt,
            timestamp,
            previous,
            message_id,
            envelopes,
            error,
            // the details of an error status are not journaled: a replayed error event has the code and the message
            error_details: Vec::new(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_proto::com::digitalasset::canton::protocol::v30::RecipientsTree;

    #[test]
    fn an_event_survives_its_journal_line() {
        let event = StoredEvent {
            timestamp: 1_700_000_000_123_456,
            previous: Some(1_700_000_000_000_001),
            message_id: Some("m-1 with a space".into()),
            envelopes: vec![
                StoredEnvelope {
                    recipients: vec![
                        vec!["MGR::0".into(), "PAR::p::1220aa".into()],
                        vec!["ALL::All".into()],
                    ],
                    recipient_trees: Vec::new(),
                    content: vec![0, 1, 2, 255],
                    signatures: vec![Signature {
                        signature: vec![9; 64],
                        signed_by: "1220bb".into(),
                        ..Default::default()
                    }],
                },
                StoredEnvelope {
                    recipients: vec![vec!["PAR::q::1220cc".into()]],
                    recipient_trees: Vec::new(),
                    content: Vec::new(),
                    signatures: Vec::new(),
                },
            ],
            error: Some((9, "SEQUENCER_X: a message, with: punctuation".into())),
            error_details: Vec::new(),
            receipt: Some((109, 0, 777)),
        };
        let line = event_line("PAR::p::1220aa", &event);
        assert!(!line.contains('\n'));
        let (member, back) = decode_event(&line).expect("decodes");
        assert_eq!(member, "PAR::p::1220aa");
        assert_eq!(event_line(&member, &back), line);
        assert_eq!(back.envelopes[0].recipients, event.envelopes[0].recipients);
        assert_eq!(back.error, event.error);
        assert_eq!(back.receipt, Some((109, 0, 777)), "what the sender paid");
        // an event with nothing in it (a tick)
        let tick = StoredEvent {
            timestamp: 5,
            previous: None,
            message_id: None,
            envelopes: Vec::new(),
            error: None,
            error_details: Vec::new(),
            receipt: None,
        };
        let (_, back) = decode_event(&event_line("PAR::p::1220aa", &tick)).unwrap();
        assert!(back.envelopes.is_empty() && back.previous.is_none() && back.error.is_none());
        assert!(back.receipt.is_none());

        // nested recipient_trees survive roundtrip without losing hierarchy
        let nested_event = StoredEvent {
            timestamp: 42,
            previous: Some(41),
            message_id: Some("nested".into()),
            envelopes: vec![StoredEnvelope {
                recipients: vec![vec!["PAR::p1::1220aa".into(), "PAR::p2::1220bb".into()]],
                recipient_trees: vec![RecipientsTree {
                    recipients: vec!["PAR::p1::1220aa".into()],
                    children: vec![RecipientsTree {
                        recipients: vec!["PAR::p2::1220bb".into()],
                        children: Vec::new(),
                    }],
                }],
                content: vec![1, 2, 3],
                signatures: Vec::new(),
            }],
            error: None,
            error_details: Vec::new(),
            receipt: None,
        };
        let nested_line = event_line("PAR::p1::1220aa", &nested_event);
        let (_, nested_back) = decode_event(&nested_line).expect("decodes nested");
        assert_eq!(
            nested_back.envelopes[0].recipient_trees,
            nested_event.envelopes[0].recipient_trees
        );
    }

    #[test]
    fn a_state_directory_is_opened_by_one_server_at_a_time() {
        let dir = std::env::temp_dir().join(format!("canton-rs-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (first, _) = Journal::open(&dir).unwrap();
        let why = match Journal::open(&dir) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a second server opened the same directory"),
        };
        assert!(why.contains("in use by another server"), "{why}");
        drop(first);
        assert!(Journal::open(&dir).is_ok(), "the lock goes with the server");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_journal_cut_short_in_the_middle_of_a_line_loses_that_line_only() {
        let dir = std::env::temp_dir().join(format!("canton-rs-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (journal, lines) = Journal::open(&dir).unwrap();
        assert!(lines.is_empty());
        journal.write("A 1 aa");
        journal.write("A 2 bb");
        drop(journal);
        // a crash in the middle of the third line
        std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("journal"))
            .unwrap()
            .write_all(b"A 3 c")
            .unwrap();
        let (journal, lines) = Journal::open(&dir).unwrap();
        assert_eq!(lines, vec!["A 1 aa", "A 2 bb"]);
        journal.write("A 4 dd");
        drop(journal);
        let (_, lines) = Journal::open(&dir).unwrap();
        assert_eq!(lines, vec!["A 1 aa", "A 2 bb", "A 4 dd"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
