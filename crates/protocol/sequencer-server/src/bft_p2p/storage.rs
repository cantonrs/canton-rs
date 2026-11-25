//! Persistence (`ord_*` PostgreSQL recovery and state-file journaling) for [`Consensus`].

use std::sync::Arc;

use super::{lock_critical, lock_or_recover, pbft_discriminator, Consensus, SignedMessage};

impl Consensus {
    /// Attaches a PostgreSQL `ord_*` store and loads any saved epochs, PBFT messages, batches, output markers, and leader policy state.
    pub fn persist_ord(&self, store: Arc<crate::ord_store::OrdStore>) -> Result<usize, String> {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::Batch;
        use prost::Message as _;
        let mut nodes = self.nodes.lock().map_err(|e| e.to_string())?.clone();
        if !nodes.contains(&self.member) {
            nodes.push(self.member.clone());
        }
        let default_len = self
            .epoch_length
            .unwrap_or_else(|| 10 * nodes.len().max(1) as i64);
        let recovery = store.load_recovery_state(nodes, default_len)?;
        {
            let mut bmap = self.batches.lock().map_err(|e| e.to_string())?;
            for (id, raw) in recovery.batches {
                if let Ok(batch) = Batch::decode(raw.as_slice()) {
                    bmap.insert(id, batch);
                }
            }
        }
        let mut earlier = Vec::new();
        for raw in recovery.pbft_messages {
            if let Ok(m) = SignedMessage::decode(raw.as_slice()) {
                earlier.push(m);
            }
        }
        let count = earlier.len();
        self.record_pbft_messages(&earlier, false, false)?;
        *self.replay.lock().map_err(|e| e.to_string())? = earlier;
        *self.persisted_epoch.lock().map_err(|e| e.to_string())? = recovery.latest_epoch.clone();
        if let Some(ep) = &recovery.latest_epoch {
            *self.saved_epoch_started.lock().map_err(|e| e.to_string())? = ep.epoch_number;
        }
        if let Some(policy) = recovery.leader_policy {
            *self.last_policy_epoch.lock().map_err(|e| e.to_string())? = policy.epoch_number;
            *self.persisted_policy.lock().map_err(|e| e.to_string())? = Some(policy);
        }
        {
            let mut out = self.lock_output()?;
            if let Some(last) = &recovery.last_output_block {
                out.restored_last_output_block = Some(last.block_number);
                out.restored_last_bft_time = Some(last.bft_ts);
                out.latest_output = Some((last.epoch_number, last.block_number, last.bft_ts));
            }
            out.epoch_boundary_bft_time = recovery.epoch_boundary_bft_ts;
            if let Some((ep, alter)) = recovery.last_epoch_could_alter_topology {
                if recovery
                    .latest_epoch
                    .as_ref()
                    .is_none_or(|latest| latest.epoch_number == ep)
                {
                    out.current_epoch = Some(ep);
                    out.epoch_could_alter_topology = alter;
                }
            }
        }
        *self.ord_store.lock().map_err(|e| e.to_string())? = Some(store);
        Ok(count)
    }

    pub(super) fn record_pbft_messages(
        &self,
        messages: &[SignedMessage],
        write_to_db: bool,
        append_to_file: bool,
    ) -> Result<(), String> {
        use prost::Message as _;
        let store = if write_to_db {
            lock_critical(&self.ord_store, "ord_store")?.clone()
        } else {
            None
        };
        let mut to_append = Vec::new();
        {
            let mut cache = lock_or_recover(&self.recent_pbft, "recent_pbft");
            for m in messages {
                let Some((epoch, block, view, disc)) = pbft_discriminator(m) else {
                    continue;
                };
                let entry = cache.entry(block).or_default();
                let duplicate = entry.iter().any(|existing| {
                    pbft_discriminator(existing) == Some((epoch, block, view, disc))
                        && existing.from == m.from
                });
                if !duplicate {
                    entry.push(m.clone());
                    if append_to_file {
                        to_append.push(m.clone());
                    }
                    if let Some(s) = &store {
                        s.save_pbft_in_progress(
                            block,
                            epoch,
                            view,
                            disc,
                            m.from.clone(),
                            m.encode_to_vec(),
                        );
                    }
                }
            }
        }
        if !to_append.is_empty() {
            self.append_messages_to_file(&to_append)?;
        }
        Ok(())
    }

    pub(super) fn save_batch_to_ord(
        &self,
        id: &[u8],
        epoch: i64,
        batch: &canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::Batch,
    ) -> Result<(), String> {
        use prost::Message as _;
        let encoded = batch.encode_to_vec();
        if let Some(store) = lock_critical(&self.ord_store, "ord_store")?.clone() {
            store.save_batch(id, epoch, encoded.clone());
        }
        {
            let guard = lock_critical(&self.store, "store")?;
            if let Some((path, _, _)) = guard.as_ref() {
                use std::io::Write as _;
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path.with_extension("batches"))
                {
                    let _ = writeln!(
                        file,
                        "{} {}",
                        crate::persistence::hex(id),
                        crate::persistence::hex(&encoded)
                    );
                }
            }
        }
        Ok(())
    }

    /// [CANTON-NOTE: PERSISTENCE] Keeps signed consensus messages in `path` (alongside `.batches`, `.output`, `.output_epoch`, and `.policy`) and puts back what an earlier run saved. A restarted
    /// node then knows both its own signed votes and peer commits/proposals so blocks already output are not re-emitted.
    pub fn persist_to(&self, path: &std::path::Path) -> Result<usize, String> {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::Batch;
        use prost::Message as _;
        let mut earlier = Vec::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                if let Some(m) = crate::persistence::unhex(line.trim())
                    .and_then(|b| SignedMessage::decode(b.as_slice()).ok())
                {
                    earlier.push(m);
                }
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if let Ok(text) = std::fs::read_to_string(path.with_extension("batches")) {
            {
                let mut bmap = self.batches.lock().map_err(|e| e.to_string())?;
                for line in text.lines() {
                    let Some((id_hex, batch_hex)) = line.split_once(' ') else {
                        continue;
                    };
                    if let (Some(id), Some(batch)) = (
                        crate::persistence::unhex(id_hex.trim()),
                        crate::persistence::unhex(batch_hex.trim())
                            .and_then(|b| Batch::decode(b.as_slice()).ok()),
                    ) {
                        bmap.insert(id, batch);
                    }
                }
            }
        }
        let mut boundary_blocks = std::collections::BTreeMap::new();
        {
            let mut out = self.lock_output()?;
            if let Ok(text) = std::fs::read_to_string(path.with_extension("output")) {
                if let Some((block, ts)) = text
                    .trim()
                    .split_once(' ')
                    .and_then(|(b, t)| Some((b.parse::<i64>().ok()?, t.parse::<i64>().ok()?)))
                {
                    out.restored_last_output_block = Some(block);
                    out.restored_last_bft_time = Some(ts);
                    boundary_blocks.insert(block, ts);
                }
            }
            if let Ok(text) = std::fs::read_to_string(path.with_extension("output_boundary")) {
                for line in text.lines() {
                    if let Some((block, ts)) = line
                        .trim()
                        .split_once(' ')
                        .and_then(|(b, t)| Some((b.parse::<i64>().ok()?, t.parse::<i64>().ok()?)))
                    {
                        boundary_blocks.insert(block, ts);
                    }
                }
            }
            if let Ok(text) = std::fs::read_to_string(path.with_extension("output_epoch")) {
                if let Some((ep, alter)) = text
                    .trim()
                    .split_once(' ')
                    .and_then(|(e, a)| Some((e.parse::<i64>().ok()?, a.parse::<bool>().ok()?)))
                {
                    out.current_epoch = Some(ep);
                    out.epoch_could_alter_topology = alter;
                }
            }
        }
        let policy_path = path.with_extension("policy");
        if let Ok(text) = std::fs::read_to_string(&policy_path) {
            let policy = canton_bft_orderer::blacklist::PolicyState::from_text(&text);
            if let Some(p) = &policy {
                *self.last_policy_epoch.lock().map_err(|e| e.to_string())? = p.epoch_number;
                if p.start_block > 0 {
                    let mut out = self.lock_output()?;
                    out.epoch_boundary_bft_time =
                        boundary_blocks.get(&(p.start_block - 1)).copied();
                }
            }
            *self.persisted_policy.lock().map_err(|e| e.to_string())? = policy;
        }
        *self.policy_file.lock().map_err(|e| e.to_string())? = Some(policy_path);
        let count = earlier.len();
        self.record_pbft_messages(&earlier, false, false)?;
        *self.replay.lock().map_err(|e| e.to_string())? = earlier;
        *self.store.lock().map_err(|e| e.to_string())? = Some((path.to_path_buf(), file, 0));
        Ok(count)
    }

    pub(super) fn remember(&self, messages: &[SignedMessage]) -> Result<(), String> {
        self.append_messages_to_file(messages)?;
        self.record_pbft_messages(messages, true, false)
    }

    fn append_messages_to_file(&self, messages: &[SignedMessage]) -> Result<(), String> {
        use prost::Message as _;
        use std::io::Write as _;
        let epoch_of = |m: &SignedMessage| -> i64 {
            canton_bft_orderer::wire::unwrap_versioned(&m.message, 30)
                .ok()
                .and_then(|inner| {
                    canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::ConsensusMessage::decode(inner.as_slice()).ok()
                })
                .and_then(|c| c.block_metadata)
                .map(|b| b.epoch_number)
                .unwrap_or(0)
        };
        let hex_of = |m: &SignedMessage| -> String {
            m.encode_to_vec()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        let mut guard = lock_critical(&self.store, "store")?;
        {
            if let Some((path, file, highest)) = guard.as_mut() {
                let mut newest = *highest;
                for m in messages {
                    newest = newest.max(epoch_of(m));
                    let _ = writeln!(file, "{}", hex_of(m));
                }
                let _ = file.sync_data();
                // [CANTON-NOTE: PERSISTENCE] A new epoch makes what was signed two epochs ago useless (a node never goes back to them): the file keeps the epoch before and this one
                if newest > *highest {
                    let first_time = *highest == 0;
                    *highest = newest;
                    if !first_time {
                        let keep_from = newest - 1;
                        if let Ok(text) = std::fs::read_to_string(&*path) {
                            let kept: Vec<&str> = text
                                .lines()
                                .filter(|line| {
                                    let bytes: Option<Vec<u8>> = (0..line.len() / 2)
                                        .map(|i| {
                                            u8::from_str_radix(line.get(2 * i..2 * i + 2)?, 16).ok()
                                        })
                                        .collect();
                                    bytes
                                        .and_then(|b| SignedMessage::decode(b.as_slice()).ok())
                                        .is_some_and(|m| epoch_of(&m) >= keep_from)
                                })
                                .collect();
                            let tmp = path.with_extension("tmp");
                            if std::fs::write(&tmp, kept.join("\n") + "\n").is_ok()
                                && std::fs::rename(&tmp, &*path).is_ok()
                            {
                                if let Ok(reopened) =
                                    std::fs::OpenOptions::new().append(true).open(&*path)
                                {
                                    *file = reopened;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
