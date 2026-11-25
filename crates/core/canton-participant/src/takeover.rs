//! Taking over the database an official Canton participant wrote (G9, AT-D11): both reading the participant's index tables and
//! continuing writes with Canton 3.7.2-compatible wire/table formats after taking the writer lock.
//!
//! [CANTON-NOTE: SEMANTICS] The Ledger API index of a 3.7.2 participant (read from a database the official node wrote, `scripts/oracle-db-takeover.sh`):
//! - `lapi_parameters` holds `ledger_end`, `ledger_end_sequential_id`, `ledger_end_string_interning_id`, and `ledger_end_publication_time`;
//! - a create is a row of `lapi_events_activate_contract` (`event_type = 1`) paired with `lapi_filter_activate_stakeholder`, `par_contracts`, and
//!   `par_active_contracts` (`activation`/`create`, `repair_counter = i64::MIN`); an archive is `lapi_events_deactivate_contract` (`event_type = 3`)
//!   with `deactivated_event_sequential_id` pointing at its activation;
//! - `lapi_string_interning` uses prefixes `d|` (synchronizer), `p|` (party), `u|` (user), `i|` (package id), `t|#<pkg_name>:<Mod>:<Entity>`, and `c|` (choice);
//! - `par_command_deduplication` stores `change_id_hash` (SHA-256 of `[0x01, 0x06]` + length-prefixed strings) and `act_as` (`UntypedVersionedMessage` v30 `StoredParties`);
//! - `lapi_update_meta`, `lapi_command_completions`, `lapi_post_processing_end`, and `lapi_ledger_end_synchronizer_index` advance monotonically with each write.
//!
//! [CANTON-NOTE: LIMITATION] A takeover moves the Ledger API index and contract store only. In-flight submissions
//! (`par_in_flight_submission`) and ACS commitment state (`par_acs_*` digests, checkpoints, periods) are neither read nor
//! written; the Rust participant keeps its own (`in-flight.journal`, `commitments.journal`). Take over only after the
//! official participant has no submission in flight, and expect commitment periods to restart.
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use postgres::Client;
use sha2::{Digest, Sha256};

use crate::contract_id::derive_contract_discriminator;
use crate::migrate::{LockState, WriterLock};

/// Where a participant's ledger ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEnd {
    pub offset: i64,
    pub sequential_id: i64,
    pub participant_id: String,
}

/// Refuses a database that no Canton participant has migrated: taking it over would create a fresh schema or attach to the wrong role.
pub fn ensure_existing_canton_db(client: &mut Client, database: &str) -> Result<(), String> {
    let has_history: bool = client
        .query_one(
            "SELECT to_regclass('flyway_schema_history') IS NOT NULL",
            &[],
        )
        .map_err(|e| format!("inspect schema of '{database}': {e}"))?
        .get(0);
    let rows: i64 = if has_history {
        client
            .query_one("SELECT COUNT(*) FROM flyway_schema_history", &[])
            .map_err(|e| format!("read flyway_schema_history of '{database}': {e}"))?
            .get(0)
    } else {
        0
    };
    if rows == 0 {
        return Err(format!(
            "database '{database}' has no Flyway history: it is not an existing Canton participant database \
             (check --jdbc-url); `db takeover` does not create one"
        ));
    }
    let has_lapi_params: bool = client
        .query_one("SELECT to_regclass('lapi_parameters') IS NOT NULL", &[])
        .map_err(|e| format!("inspect participant schema of '{database}': {e}"))?
        .get(0);
    if !has_lapi_params {
        return Err(format!(
            "database '{database}' lacks 'lapi_parameters': it is not a Canton participant database \
             (check --jdbc-url); `db takeover` does not create one"
        ));
    }
    Ok(())
}

/// One active contract as the Ledger API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveContract {
    /// The contract id, hex.
    pub contract_id: String,
    /// `<package id>:<module>:<entity>`.
    pub template_id: String,
    /// The offset of its create.
    pub offset: i64,
}

/// The ledger end of the participant whose index the database holds (`None` for a participant that never published anything).
pub fn ledger_end(client: &mut Client) -> Result<Option<LedgerEnd>, postgres::Error> {
    let row = client.query_opt(
        "SELECT ledger_end, ledger_end_sequential_id, participant_id FROM lapi_parameters",
        &[],
    )?;
    Ok(row.and_then(|r| {
        Some(LedgerEnd {
            offset: r.get::<_, Option<i64>>(0)?,
            sequential_id: r.get::<_, Option<i64>>(1)?,
            participant_id: r.get(2),
        })
    }))
}

/// The contracts active for `party` at the ledger end `end`, in the order they were created.
pub fn active_contracts(
    client: &mut Client,
    party: &str,
    end: &LedgerEnd,
) -> Result<Vec<ActiveContract>, postgres::Error> {
    let rows = client.query(
        "SELECT encode(c.contract_id, 'hex'), c.package_id || ':' || c.template_id, a.event_offset \
         FROM lapi_events_activate_contract a \
         JOIN lapi_filter_activate_stakeholder f ON f.event_sequential_id = a.event_sequential_id \
         JOIN lapi_string_interning p ON p.internal_id = f.party_id AND p.external_string = 'p|' || $1 \
         JOIN par_contracts c ON c.internal_contract_id = a.internal_contract_id \
         WHERE a.event_sequential_id <= $2 \
           AND NOT EXISTS (SELECT 1 FROM lapi_events_deactivate_contract d \
                           WHERE d.deactivated_event_sequential_id = a.event_sequential_id AND d.event_sequential_id <= $2) \
         ORDER BY a.event_sequential_id",
        &[&party, &end.sequential_id],
    )?;
    Ok(rows
        .iter()
        .map(|r| ActiveContract {
            contract_id: r.get(0),
            template_id: r.get(1),
            offset: r.get(2),
        })
        .collect())
}

/// Canton 3.7.2 `ChangeId.hash` (`Version.UpgradeFriendly = 1`, `HashPurpose.ChangeId = 6`) as 64 lowercase hex chars.
pub fn change_id_hash(user_id: &str, command_id: &str, act_as: &[String]) -> String {
    let sorted: BTreeSet<&str> = act_as.iter().map(String::as_str).collect();
    let mut h = Sha256::new();
    h.update([0x01u8, 0x06u8]);
    h.update((user_id.len() as i32).to_be_bytes());
    h.update(user_id.as_bytes());
    h.update((command_id.len() as i32).to_be_bytes());
    h.update(command_id.as_bytes());
    h.update((sorted.len() as i32).to_be_bytes());
    for p in sorted {
        h.update((p.len() as i32).to_be_bytes());
        h.update(p.as_bytes());
    }
    hex::encode(h.finalize())
}

fn push_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn push_ld_field(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    push_varint(out, ((field as u64) << 3) | 2);
    push_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn push_varint_field(out: &mut Vec<u8>, field: u32, v: u64) {
    push_varint(out, (field as u64) << 3);
    push_varint(out, v);
}

/// Encodes `UntypedVersionedMessage { data = v30.StoredParties { parties }, version = 30 }` for `par_command_deduplication.act_as`.
pub fn encode_stored_parties_v30(parties: &[String]) -> Vec<u8> {
    let sorted: BTreeSet<&str> = parties.iter().map(String::as_str).collect();
    let mut inner = Vec::new();
    for party in sorted {
        push_ld_field(&mut inner, 1, party.as_bytes());
    }
    let mut wrapper = Vec::new();
    push_ld_field(&mut wrapper, 1, &inner);
    push_varint_field(&mut wrapper, 2, 30);
    wrapper
}

/// Encodes Canton `IntArrayDBSerialization`: empty -> `[]`; non-empty -> `[0x01] || be_i32...`.
pub fn encode_interned_int_array(ids: &[i32]) -> Vec<u8> {
    if ids.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(1 + ids.len() * 4);
    out.push(0x01);
    for id in ids {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out
}

/// Canonical `VersionedValue { version: "2.1", value: Record {} }` bytes (`exercise_argument` for `Archive`).
pub fn encode_versioned_empty_record() -> Vec<u8> {
    vec![0x0a, 0x03, b'2', b'.', b'1', 0x12, 0x02, 0x6a, 0x00]
}

/// Canonical `VersionedValue { version: "2.1", value: Unit }` bytes (`exercise_result` for `Archive`).
pub fn encode_versioned_unit() -> Vec<u8> {
    vec![0x0a, 0x03, b'2', b'.', b'1', 0x12, 0x02, 0x0a, 0x00]
}

/// A contract create prepared for post-takeover PostgreSQL persistence.
#[derive(Debug, Clone)]
pub struct TakeoverCreate {
    pub contract_id: String,
    pub contract_instance: Vec<u8>,
    pub package_id: String,
    pub package_name: String,
    pub module_name: String,
    pub entity_name: String,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    pub node_id: i32,
    pub create_key_hash: Option<String>,
}

/// Builds a Canton V12 contract ID + `Versioned(FatContractInstance)` from a DAR template and JSON payload.
pub fn build_v12_create_for_dar(
    dar_path: &Path,
    module_name: &str,
    entity_name: &str,
    payload_json: &serde_json::Value,
    signatories: &[String],
    observers: &[String],
    created_at_micros: i64,
    salt: &[u8; 32],
    node_id: i32,
) -> Result<TakeoverCreate, String> {
    let archive = lf_archive::parse_dar_file(dar_path).map_err(|e| format!("parse dar: {e}"))?;
    let world = lf_eval::World::open(dar_path).map_err(|e| format!("open world: {e}"))?;
    let types = lf_eval::typed_json::Types::new(&world);
    let local_tpl = format!("{module_name}:{entity_name}");
    let package_id = if types.template(&archive.main_package_id, &local_tpl).is_ok() {
        archive.main_package_id
    } else {
        archive
            .dalfs
            .iter()
            .map(|d| &d.package_id)
            .find(|pid| types.template(pid, &local_tpl).is_ok())
            .cloned()
            .ok_or_else(|| {
                format!(
                    "template {local_tpl} not found in DAR {}",
                    dar_path.display()
                )
            })?
    };
    let package_name = types.package_name(&package_id)?;
    let tpl_ty = types.template(&package_id, &local_tpl)?;
    let payload = types.decode(&tpl_ty, payload_json)?;

    let sig_set: BTreeSet<String> = signatories.iter().cloned().collect();
    if sig_set.is_empty() {
        return Err("create requires at least one signatory".into());
    }
    let mut stake_set = sig_set.clone();
    stake_set.extend(observers.iter().cloned());
    let non_sig: Vec<String> = stake_set.difference(&sig_set).cloned().collect();
    let sigs: Vec<String> = sig_set.into_iter().collect();
    let obs: Vec<String> = observers.to_vec();
    let all_stakeholders: Vec<String> = stake_set.into_iter().collect();

    let contract_hash = lf_eval::fat_contract::compute_contract_hash(
        &types,
        &package_name,
        &local_tpl,
        &tpl_ty,
        &payload,
    )?;
    let unicum = lf_eval::fat_contract::compute_unicum(
        salt,
        created_at_micros,
        &sigs,
        &non_sig,
        None,
        &[],
        &contract_hash,
    );
    let disc = derive_contract_discriminator(salt, created_at_micros, &all_stakeholders);
    let contract_id = lf_eval::fat_contract::format_v12_contract_id(&disc, &unicum);
    let contract_instance = lf_eval::fat_contract::encode_fat_contract(
        &world,
        &lf_eval::fat_contract::FatContractInput {
            contract_id: &contract_id,
            package_id: &package_id,
            package_name: &package_name,
            module_name,
            entity_name,
            payload: &payload,
            signatories: &sigs,
            observers: &obs,
            created_at_micros,
            salt,
            key: None,
            key_maintainers: &[],
            key_hash: None,
        },
    )?;

    Ok(TakeoverCreate {
        contract_id,
        contract_instance,
        package_id,
        package_name,
        module_name: module_name.to_string(),
        entity_name: entity_name.to_string(),
        signatories: sigs,
        observers: obs,
        node_id,
        create_key_hash: None,
    })
}

/// A consuming exercise (`Archive` or custom consuming choice) prepared for post-takeover persistence.
#[derive(Debug, Clone)]
pub struct TakeoverArchive {
    pub contract_id: String,
    pub choice_name: String,
    pub actors: Vec<String>,
    pub exercise_argument: Option<Vec<u8>>,
    pub exercise_result: Option<Vec<u8>>,
    pub node_id: i32,
}

impl TakeoverArchive {
    pub fn archive(contract_id: impl Into<String>, actors: Vec<String>, node_id: i32) -> Self {
        Self {
            contract_id: contract_id.into(),
            choice_name: "Archive".to_string(),
            actors,
            exercise_argument: None,
            exercise_result: None,
            node_id,
        }
    }
}

/// One accepted transaction appended after DB takeover.
#[derive(Debug, Clone)]
pub struct TakeoverTx {
    pub user_id: String,
    pub command_id: String,
    pub submission_id: Option<String>,
    pub workflow_id: Option<String>,
    pub submitters: Vec<String>,
    pub synchronizer_id: Option<String>,
    pub record_time_micros: Option<i64>,
    pub creates: Vec<TakeoverCreate>,
    pub archives: Vec<TakeoverArchive>,
}

/// One rejected command completion appended after DB takeover.
#[derive(Debug, Clone)]
pub struct TakeoverRejected {
    pub user_id: String,
    pub command_id: String,
    pub submission_id: Option<String>,
    pub submitters: Vec<String>,
    pub synchronizer_id: Option<String>,
    pub record_time_micros: Option<i64>,
    pub status_code: i32,
    pub status_message: String,
}

/// Receipt returned after committing a post-takeover write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakeoverWriteReceipt {
    pub offset: i64,
    pub sequential_id_first: Option<i64>,
    pub sequential_id_last: Option<i64>,
    pub update_id_hex: Option<String>,
    pub change_id_hash: String,
}

fn now_epoch_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

fn multihash_update_id(command_id: &str, offset: i64, record_time: i64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"canton-rs-takeover-update:");
    h.update(command_id.as_bytes());
    h.update(offset.to_be_bytes());
    h.update(record_time.to_be_bytes());
    let mut out = Vec::with_capacity(34);
    out.extend_from_slice(&[0x12, 0x20]);
    out.extend_from_slice(&h.finalize());
    out
}

struct InternAlloc<'a, 't> {
    tx: &'a mut postgres::Transaction<'t>,
    next_id: i32,
    cache: HashMap<String, i32>,
}

impl<'a, 't> InternAlloc<'a, 't> {
    fn new(tx: &'a mut postgres::Transaction<'t>, baseline_max: i32) -> Result<Self, String> {
        let db_max: i32 = tx
            .query_one(
                "SELECT COALESCE(MAX(internal_id), 0) FROM lapi_string_interning",
                &[],
            )
            .map_err(|e| format!("query lapi_string_interning max: {e}"))?
            .get(0);
        Ok(Self {
            tx,
            next_id: baseline_max.max(db_max) + 1,
            cache: HashMap::new(),
        })
    }

    fn intern(&mut self, external: &str) -> Result<i32, String> {
        if let Some(&id) = self.cache.get(external) {
            return Ok(id);
        }
        if let Some(row) = self
            .tx
            .query_opt(
                "SELECT internal_id FROM lapi_string_interning WHERE external_string = $1 ORDER BY internal_id LIMIT 1",
                &[&external],
            )
            .map_err(|e| format!("lookup string interning '{external}': {e}"))?
        {
            let id: i32 = row.get(0);
            self.cache.insert(external.to_string(), id);
            return Ok(id);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.tx
            .execute(
                "INSERT INTO lapi_string_interning (internal_id, external_string) VALUES ($1, $2)",
                &[&id, &external],
            )
            .map_err(|e| format!("insert string interning '{external}': {e}"))?;
        self.cache.insert(external.to_string(), id);
        Ok(id)
    }

    fn intern_many(&mut self, prefix: char, values: &[String]) -> Result<Vec<i32>, String> {
        let unique: BTreeSet<&str> = values.iter().map(String::as_str).collect();
        let mut ids = Vec::with_capacity(unique.len());
        for v in unique {
            let key = format!("{prefix}|{v}");
            ids.push(self.intern(&key)?);
        }
        Ok(ids)
    }

    fn max_id(&self) -> i32 {
        self.next_id - 1
    }
}

/// Fenced writer operating under a [`WriterLock`] against an official Canton PostgreSQL database.
pub struct TakeoverWriter {
    client: Client,
    lock: WriterLock,
}

impl TakeoverWriter {
    pub fn from_parts(client: Client, lock: WriterLock) -> Self {
        Self { client, lock }
    }

    pub fn client_mut(&mut self) -> &mut Client {
        &mut self.client
    }

    pub fn check_lock(&mut self) -> LockState {
        self.lock.check()
    }

    pub fn lock_id(&self) -> i32 {
        self.lock.id()
    }

    /// Physically prunes Ledger API and contract rows at or below `prune_offset` under the held writer lock.
    pub fn prune_up_to(
        &mut self,
        prune_offset: i64,
    ) -> Result<crate::official_prune::OfficialPruneReport, String> {
        if self.lock.check() != LockState::Held {
            return Err("writer lock is not held before prune".into());
        }
        crate::official_prune::prune_up_to(&mut self.client, prune_offset)
    }

    fn resolve_synchronizer(
        tx: &mut postgres::Transaction<'_>,
        requested: Option<&str>,
    ) -> Result<(String, i32), String> {
        if let Some(sync_id) = requested {
            if let Some(row) = tx
                .query_opt(
                    "SELECT id FROM common_static_strings WHERE string = $1 AND source = 1",
                    &[&sync_id],
                )
                .map_err(|e| format!("lookup common_static_strings: {e}"))?
            {
                return Ok((sync_id.to_string(), row.get(0)));
            }
            let next_id: i32 = tx
                .query_one(
                    "SELECT COALESCE(MAX(id), 0) + 1 FROM common_static_strings",
                    &[],
                )
                .map_err(|e| format!("max common_static_strings id: {e}"))?
                .get(0);
            tx.execute(
                "INSERT INTO common_static_strings (id, string, source) VALUES ($1, $2, 1)",
                &[&next_id, &sync_id],
            )
            .map_err(|e| format!("insert common_static_strings: {e}"))?;
            return Ok((sync_id.to_string(), next_id));
        }

        if let Some(row) = tx
            .query_opt(
                "SELECT id, string FROM common_static_strings WHERE source = 1 ORDER BY id LIMIT 1",
                &[],
            )
            .map_err(|e| format!("query default common_static_strings: {e}"))?
        {
            return Ok((row.get(1), row.get(0)));
        }

        if let Some(row) = tx
            .query_opt(
                "SELECT external_string FROM lapi_string_interning WHERE external_string LIKE 'd|%' ORDER BY internal_id LIMIT 1",
                &[],
            )
            .map_err(|e| format!("query default lapi_string_interning synchronizer: {e}"))?
        {
            let ext: String = row.get(0);
            let sync_id = ext.trim_start_matches("d|").to_string();
            let next_id: i32 = tx
                .query_one(
                    "SELECT COALESCE(MAX(id), 0) + 1 FROM common_static_strings",
                    &[],
                )
                .map_err(|e| format!("max common_static_strings id: {e}"))?
                .get(0);
            tx.execute(
                "INSERT INTO common_static_strings (id, string, source) VALUES ($1, $2, 1)",
                &[&next_id, &sync_id],
            )
            .map_err(|e| format!("insert common_static_strings: {e}"))?;
            return Ok((sync_id, next_id));
        }

        Err("no synchronizer found in common_static_strings or lapi_string_interning".into())
    }

    fn load_head(
        tx: &mut postgres::Transaction<'_>,
        requested_rt: Option<i64>,
    ) -> Result<(i64, i64, i32, i64, i64), String> {
        let row = tx
            .query_opt(
                "SELECT ledger_end, ledger_end_sequential_id, ledger_end_string_interning_id, ledger_end_publication_time \
                 FROM lapi_parameters LIMIT 1",
                &[],
            )
            .map_err(|e| format!("query lapi_parameters: {e}"))?
            .ok_or_else(|| "lapi_parameters has no initialized participant row".to_string())?;
        let cur_end: i64 = row.get::<_, Option<i64>>(0).unwrap_or(0);
        let cur_seq: i64 = row.get::<_, Option<i64>>(1).unwrap_or(0);
        let cur_intern: i32 = row.get::<_, Option<i32>>(2).unwrap_or(0);
        let cur_pub: i64 = row.get::<_, Option<i64>>(3).unwrap_or(0);
        let max_rt: i64 = tx
            .query_one(
                "SELECT COALESCE(MAX(record_time), 0) FROM lapi_command_completions",
                &[],
            )
            .map_err(|e| format!("query max record_time: {e}"))?
            .get(0);
        let now = now_epoch_micros();
        let pub_time = cur_pub.max(now);
        let record_time = requested_rt.unwrap_or_else(|| (max_rt + 1).max(now));
        Ok((cur_end + 1, cur_seq, cur_intern, pub_time, record_time))
    }

    fn advance_parameters(
        tx: &mut postgres::Transaction<'_>,
        new_offset: i64,
        new_seq: i64,
        new_intern: i32,
        pub_time: i64,
        sync_intern_id: i32,
        record_time: i64,
    ) -> Result<(), String> {
        tx.execute(
            "UPDATE lapi_parameters \
             SET ledger_end = $1, \
                 ledger_end_sequential_id = $2, \
                 ledger_end_string_interning_id = $3, \
                 ledger_end_publication_time = $4",
            &[&new_offset, &new_seq, &new_intern, &pub_time],
        )
        .map_err(|e| format!("update lapi_parameters: {e}"))?;

        let updated = tx
            .execute(
                "UPDATE lapi_post_processing_end SET post_processing_end = $1",
                &[&new_offset],
            )
            .map_err(|e| format!("update lapi_post_processing_end: {e}"))?;
        if updated == 0 {
            tx.execute(
                "INSERT INTO lapi_post_processing_end (post_processing_end) VALUES ($1)",
                &[&new_offset],
            )
            .map_err(|e| format!("insert lapi_post_processing_end: {e}"))?;
        }

        tx.execute(
            "INSERT INTO lapi_ledger_end_synchronizer_index \
             (synchronizer_id, sequencer_timestamp, repair_timestamp, repair_counter, record_time) \
             VALUES ($1, $2, NULL, NULL, $2) \
             ON CONFLICT (synchronizer_id) DO UPDATE SET \
               sequencer_timestamp = GREATEST(COALESCE(lapi_ledger_end_synchronizer_index.sequencer_timestamp, EXCLUDED.sequencer_timestamp), EXCLUDED.sequencer_timestamp), \
               record_time = GREATEST(lapi_ledger_end_synchronizer_index.record_time, EXCLUDED.record_time)",
            &[&sync_intern_id, &record_time],
        )
        .map_err(|e| format!("upsert lapi_ledger_end_synchronizer_index: {e}"))?;
        Ok(())
    }

    /// Appends one accepted transaction (creates and/or archives) with full `lapi_*` + `par_*` consistency.
    pub fn append_transaction(
        &mut self,
        spec: &TakeoverTx,
    ) -> Result<TakeoverWriteReceipt, String> {
        if spec.creates.is_empty() && spec.archives.is_empty() {
            return Err("TakeoverTx must include at least one create or archive".into());
        }
        if spec.submitters.is_empty() {
            return Err("TakeoverTx requires at least one submitter".into());
        }
        if self.lock.check() != LockState::Held {
            return Err("writer lock lost before transaction start".into());
        }

        let mut tx = self
            .client
            .transaction()
            .map_err(|e| format!("begin postgres tx: {e}"))?;

        let (new_offset, cur_seq, cur_intern, pub_time, record_time) =
            Self::load_head(&mut tx, spec.record_time_micros)?;
        let (sync_str, sync_idx) =
            Self::resolve_synchronizer(&mut tx, spec.synchronizer_id.as_deref())?;
        let update_id = multihash_update_id(&spec.command_id, new_offset, record_time);

        let mut intern = InternAlloc::new(&mut tx, cur_intern)?;
        let sync_intern_id = intern.intern(&format!("d|{sync_str}"))?;
        let user_intern_id = intern.intern(&format!("u|{}", spec.user_id))?;
        let submitter_ids = intern.intern_many('p', &spec.submitters)?;
        let submitter_bytes = encode_interned_int_array(&submitter_ids);

        let mut next_seq = cur_seq;
        let seq_first = cur_seq + 1;

        for create in &spec.creates {
            let cid_bytes = hex::decode(&create.contract_id)
                .map_err(|e| format!("decode create contract_id '{}': {e}", create.contract_id))?;
            let local_tpl = format!("{}:{}", create.module_name, create.entity_name);
            let pkg_intern_id = intern.intern(&format!("i|{}", create.package_id))?;
            let tpl_intern_id =
                intern.intern(&format!("t|#{}:{}", create.package_name, local_tpl))?;
            let mut stake_parties: BTreeSet<String> = create.signatories.iter().cloned().collect();
            stake_parties.extend(create.observers.iter().cloned());
            let stake_list: Vec<String> = stake_parties.into_iter().collect();
            let stake_ids = intern.intern_many('p', &stake_list)?;

            let internal_cid: i64 = if let Some(row) = intern
                .tx
                .query_opt(
                    "INSERT INTO par_contracts (contract_id, instance, package_id, template_id) \
                     VALUES ($1, $2, $3, $4) ON CONFLICT (contract_id) DO NOTHING RETURNING internal_contract_id",
                    &[&cid_bytes, &create.contract_instance, &create.package_id, &local_tpl],
                )
                .map_err(|e| format!("insert par_contracts: {e}"))?
            {
                row.get(0)
            } else {
                intern
                    .tx
                    .query_one(
                        "SELECT internal_contract_id FROM par_contracts WHERE contract_id = $1",
                        &[&cid_bytes],
                    )
                    .map_err(|e| format!("select existing par_contracts: {e}"))?
                    .get(0)
            };

            let repair_counter = i64::MIN;
            let genesis_reassignment_counter = 0i64;
            intern
                .tx
                .execute(
                    "INSERT INTO par_active_contracts \
                     (synchronizer_idx, contract_id, change, operation, ts, repair_counter, remote_synchronizer_idx, reassignment_counter) \
                     VALUES ($1, $2, 'activation'::public.change_type, 'create'::public.operation_type, $3, $4, NULL, $5) \
                     ON CONFLICT DO NOTHING",
                    &[&sync_idx, &cid_bytes, &record_time, &repair_counter, &genesis_reassignment_counter],
                )
                .map_err(|e| format!("insert par_active_contracts create: {e}"))?;

            next_seq += 1;
            let empty_bytes: &[u8] = &[];
            intern
                .tx
                .execute(
                    "INSERT INTO lapi_events_activate_contract \
                     (event_offset, update_id, workflow_id, command_id, submitters, record_time, synchronizer_id, \
                      trace_context, external_transaction_hash, event_type, event_sequential_id, node_id, \
                      additional_witnesses, source_synchronizer_id, reassignment_counter, reassignment_id, \
                      representative_package_id, internal_contract_id, create_key_hash, traffic_cost) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, 1, $9, $10, $11, NULL, NULL, NULL, $12, $13, $14, NULL)",
                    &[
                        &new_offset,
                        &update_id,
                        &spec.workflow_id,
                        &spec.command_id,
                        &submitter_bytes,
                        &record_time,
                        &sync_intern_id,
                        &empty_bytes,
                        &next_seq,
                        &create.node_id,
                        &empty_bytes,
                        &pkg_intern_id,
                        &internal_cid,
                        &create.create_key_hash,
                    ],
                )
                .map_err(|e| format!("insert lapi_events_activate_contract: {e}"))?;

            for (idx, party_id) in stake_ids.iter().enumerate() {
                let first: Option<bool> = (idx == 0).then_some(true);
                intern
                    .tx
                    .execute(
                        "INSERT INTO lapi_filter_activate_stakeholder \
                         (event_sequential_id, template_id, party_id, first_per_sequential_id) \
                         VALUES ($1, $2, $3, $4)",
                        &[&next_seq, &tpl_intern_id, party_id, &first],
                    )
                    .map_err(|e| format!("insert lapi_filter_activate_stakeholder: {e}"))?;
            }
        }

        for arch in &spec.archives {
            let cid_bytes = hex::decode(&arch.contract_id)
                .map_err(|e| format!("decode archive contract_id '{}': {e}", arch.contract_id))?;
            let contract_row = intern
                .tx
                .query_opt(
                    "SELECT c.internal_contract_id, c.package_id, c.template_id, c.instance, \
                            (SELECT a.event_sequential_id FROM lapi_events_activate_contract a \
                             WHERE a.internal_contract_id = c.internal_contract_id \
                               AND NOT EXISTS (SELECT 1 FROM lapi_events_deactivate_contract d \
                                               WHERE d.deactivated_event_sequential_id = a.event_sequential_id) \
                             ORDER BY a.event_sequential_id DESC LIMIT 1) AS active_seq \
                     FROM par_contracts c WHERE c.contract_id = $1",
                    &[&cid_bytes],
                )
                .map_err(|e| format!("query archive target '{}': {e}", arch.contract_id))?
                .ok_or_else(|| format!("contract '{}' not found in par_contracts", arch.contract_id))?;

            let internal_cid: i64 = contract_row.get(0);
            let pkg_id: String = contract_row.get(1);
            let local_tpl: String = contract_row.get(2);
            let instance: Vec<u8> = contract_row.get(3);
            let active_seq: i64 = contract_row.get::<_, Option<i64>>(4).ok_or_else(|| {
                format!("contract '{}' is not currently active", arch.contract_id)
            })?;

            let raw = lf_eval::fat_contract::decode_fat_contract_blob(&instance)
                .map_err(|e| format!("decode fat contract '{}': {e}", arch.contract_id))?;
            let mut stake_parties: BTreeSet<String> = BTreeSet::new();
            stake_parties.extend(raw.non_maintainer_signatories);
            stake_parties.extend(raw.non_signatory_stakeholders);
            if let Some(k) = raw.key {
                stake_parties.extend(k.maintainers);
            }
            let stake_list: Vec<String> = stake_parties.into_iter().collect();

            let pkg_intern_id = intern.intern(&format!("i|{pkg_id}"))?;
            let tpl_intern_id = intern.intern(&format!("t|#{}:{}", raw.package_name, local_tpl))?;
            let choice_intern_id = intern.intern(&format!("c|{}", arch.choice_name))?;
            let actor_ids = intern.intern_many('p', &arch.actors)?;
            let stake_ids = intern.intern_many('p', &stake_list)?;
            let actor_bytes = encode_interned_int_array(&actor_ids);
            let stake_bytes = encode_interned_int_array(&stake_ids);

            let repair_counter = i64::MIN;
            intern
                .tx
                .execute(
                    "INSERT INTO par_active_contracts \
                     (synchronizer_idx, contract_id, change, operation, ts, repair_counter, remote_synchronizer_idx, reassignment_counter) \
                     VALUES ($1, $2, 'deactivation'::public.change_type, 'archive'::public.operation_type, $3, $4, NULL, NULL) \
                     ON CONFLICT DO NOTHING",
                    &[&sync_idx, &cid_bytes, &record_time, &repair_counter],
                )
                .map_err(|e| format!("insert par_active_contracts archive: {e}"))?;

            next_seq += 1;
            let empty_bytes: &[u8] = &[];
            let arg_bytes = arch
                .exercise_argument
                .clone()
                .unwrap_or_else(encode_versioned_empty_record);
            let res_bytes = arch
                .exercise_result
                .clone()
                .unwrap_or_else(encode_versioned_unit);

            intern
                .tx
                .execute(
                    "INSERT INTO lapi_events_deactivate_contract \
                     (event_offset, update_id, workflow_id, command_id, submitters, record_time, synchronizer_id, \
                      trace_context, external_transaction_hash, event_type, event_sequential_id, node_id, \
                      deactivated_event_sequential_id, additional_witnesses, exercise_choice, exercise_choice_interface, \
                      exercise_argument, exercise_result, exercise_actors, exercise_last_descendant_node_id, \
                      exercise_argument_compression, exercise_result_compression, reassignment_id, assignment_exclusivity, \
                      target_synchronizer_id, reassignment_counter, contract_id, internal_contract_id, \
                      template_id, package_id, stakeholders, ledger_effective_time, traffic_cost) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, 3, $9, $10, $11, $12, $13, NULL, \
                             $14, $15, $16, $10, NULL, NULL, NULL, NULL, NULL, NULL, $17, $18, $19, $20, $21, $6, NULL)",
                    &[
                        &new_offset,
                        &update_id,
                        &spec.workflow_id,
                        &spec.command_id,
                        &submitter_bytes,
                        &record_time,
                        &sync_intern_id,
                        &empty_bytes,
                        &next_seq,
                        &arch.node_id,
                        &active_seq,
                        &empty_bytes,
                        &choice_intern_id,
                        &arg_bytes,
                        &res_bytes,
                        &actor_bytes,
                        &cid_bytes,
                        &internal_cid,
                        &tpl_intern_id,
                        &pkg_intern_id,
                        &stake_bytes,
                    ],
                )
                .map_err(|e| format!("insert lapi_events_deactivate_contract: {e}"))?;

            for (idx, party_id) in stake_ids.iter().enumerate() {
                let first: Option<bool> = (idx == 0).then_some(true);
                intern
                    .tx
                    .execute(
                        "INSERT INTO lapi_filter_deactivate_stakeholder \
                         (event_sequential_id, template_id, party_id, first_per_sequential_id) \
                         VALUES ($1, $2, $3, $4)",
                        &[&next_seq, &tpl_intern_id, party_id, &first],
                    )
                    .map_err(|e| format!("insert lapi_filter_deactivate_stakeholder: {e}"))?;
            }
        }

        let max_intern = intern.max_id();
        drop(intern);

        tx.execute(
            "INSERT INTO lapi_update_meta \
             (update_id, event_offset, publication_time, record_time, synchronizer_id, \
              event_sequential_id_first, event_sequential_id_last, transaction_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)",
            &[
                &update_id,
                &new_offset,
                &pub_time,
                &record_time,
                &sync_intern_id,
                &seq_first,
                &next_seq,
            ],
        )
        .map_err(|e| format!("insert lapi_update_meta: {e}"))?;

        let empty_bytes: &[u8] = &[];
        tx.execute(
            "INSERT INTO lapi_command_completions \
             (completion_offset, record_time, publication_time, user_id, submitters, command_id, update_id, \
              submission_id, deduplication_offset, deduplication_duration_seconds, deduplication_duration_nanos, \
              rejection_status_code, rejection_status_message, rejection_status_details, synchronizer_id, \
              message_uuid, is_transaction, trace_context, traffic_cost, transaction_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, NULL, NULL, NULL, NULL, $9, NULL, true, $10, NULL, NULL)",
            &[
                &new_offset,
                &record_time,
                &pub_time,
                &user_intern_id,
                &submitter_bytes,
                &spec.command_id,
                &update_id,
                &spec.submission_id,
                &sync_intern_id,
                &empty_bytes,
            ],
        )
        .map_err(|e| format!("insert lapi_command_completions: {e}"))?;

        let cih = change_id_hash(&spec.user_id, &spec.command_id, &spec.submitters);
        let stored_parties = encode_stored_parties_v30(&spec.submitters);
        tx.execute(
            "INSERT INTO par_command_deduplication \
             (change_id_hash, user_id, command_id, act_as, offset_definite_answer, publication_time_definite_answer, \
              submission_id_definite_answer, trace_context_definite_answer, offset_acceptance, publication_time_acceptance, \
              submission_id_acceptance, trace_context_acceptance) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $5, $6, $7, $8) \
             ON CONFLICT (change_id_hash) DO UPDATE SET \
               offset_definite_answer = EXCLUDED.offset_definite_answer, \
               publication_time_definite_answer = EXCLUDED.publication_time_definite_answer, \
               submission_id_definite_answer = EXCLUDED.submission_id_definite_answer, \
               offset_acceptance = EXCLUDED.offset_acceptance, \
               publication_time_acceptance = EXCLUDED.publication_time_acceptance, \
               submission_id_acceptance = EXCLUDED.submission_id_acceptance",
            &[
                &cih,
                &spec.user_id,
                &spec.command_id,
                &stored_parties,
                &new_offset,
                &pub_time,
                &spec.submission_id,
                &empty_bytes,
            ],
        )
        .map_err(|e| format!("upsert par_command_deduplication: {e}"))?;

        Self::advance_parameters(
            &mut tx,
            new_offset,
            next_seq,
            max_intern,
            pub_time,
            sync_intern_id,
            record_time,
        )?;

        if self.lock.check() != LockState::Held {
            let _ = tx.rollback();
            return Err("writer lock lost before commit; write rolled back".into());
        }
        tx.commit()
            .map_err(|e| format!("commit postgres tx: {e}"))?;

        Ok(TakeoverWriteReceipt {
            offset: new_offset,
            sequential_id_first: Some(seq_first),
            sequential_id_last: Some(next_seq),
            update_id_hex: Some(hex::encode(&update_id)),
            change_id_hash: cih,
        })
    }

    /// Appends one rejected command completion (`lapi_command_completions` + `par_command_deduplication` + ledger end).
    pub fn append_rejected_completion(
        &mut self,
        spec: &TakeoverRejected,
    ) -> Result<TakeoverWriteReceipt, String> {
        if spec.submitters.is_empty() {
            return Err("TakeoverRejected requires at least one submitter".into());
        }
        if self.lock.check() != LockState::Held {
            return Err("writer lock lost before rejected completion start".into());
        }

        let mut tx = self
            .client
            .transaction()
            .map_err(|e| format!("begin postgres tx: {e}"))?;

        let (new_offset, cur_seq, cur_intern, pub_time, record_time) =
            Self::load_head(&mut tx, spec.record_time_micros)?;
        let (sync_str, _) = Self::resolve_synchronizer(&mut tx, spec.synchronizer_id.as_deref())?;

        let mut intern = InternAlloc::new(&mut tx, cur_intern)?;
        let sync_intern_id = intern.intern(&format!("d|{sync_str}"))?;
        let user_intern_id = intern.intern(&format!("u|{}", spec.user_id))?;
        let submitter_ids = intern.intern_many('p', &spec.submitters)?;
        let submitter_bytes = encode_interned_int_array(&submitter_ids);
        let max_intern = intern.max_id();
        drop(intern);

        let empty_bytes: &[u8] = &[];
        tx.execute(
            "INSERT INTO lapi_command_completions \
             (completion_offset, record_time, publication_time, user_id, submitters, command_id, update_id, \
              submission_id, deduplication_offset, deduplication_duration_seconds, deduplication_duration_nanos, \
              rejection_status_code, rejection_status_message, rejection_status_details, synchronizer_id, \
              message_uuid, is_transaction, trace_context, traffic_cost, transaction_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, NULL, NULL, NULL, $8, $9, $10, $11, NULL, true, $12, NULL, NULL)",
            &[
                &new_offset,
                &record_time,
                &pub_time,
                &user_intern_id,
                &submitter_bytes,
                &spec.command_id,
                &spec.submission_id,
                &spec.status_code,
                &spec.status_message,
                &empty_bytes,
                &sync_intern_id,
                &empty_bytes,
            ],
        )
        .map_err(|e| format!("insert rejected lapi_command_completions: {e}"))?;

        let cih = change_id_hash(&spec.user_id, &spec.command_id, &spec.submitters);
        let stored_parties = encode_stored_parties_v30(&spec.submitters);
        tx.execute(
            "INSERT INTO par_command_deduplication \
             (change_id_hash, user_id, command_id, act_as, offset_definite_answer, publication_time_definite_answer, \
              submission_id_definite_answer, trace_context_definite_answer, offset_acceptance, publication_time_acceptance, \
              submission_id_acceptance, trace_context_acceptance) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, NULL, NULL) \
             ON CONFLICT (change_id_hash) DO UPDATE SET \
               offset_definite_answer = EXCLUDED.offset_definite_answer, \
               publication_time_definite_answer = EXCLUDED.publication_time_definite_answer, \
               submission_id_definite_answer = EXCLUDED.submission_id_definite_answer",
            &[
                &cih,
                &spec.user_id,
                &spec.command_id,
                &stored_parties,
                &new_offset,
                &pub_time,
                &spec.submission_id,
                &empty_bytes,
            ],
        )
        .map_err(|e| format!("upsert rejected par_command_deduplication: {e}"))?;

        Self::advance_parameters(
            &mut tx,
            new_offset,
            cur_seq,
            max_intern,
            pub_time,
            sync_intern_id,
            record_time,
        )?;

        if self.lock.check() != LockState::Held {
            let _ = tx.rollback();
            return Err("writer lock lost before rejected completion commit".into());
        }
        tx.commit()
            .map_err(|e| format!("commit postgres tx: {e}"))?;

        Ok(TakeoverWriteReceipt {
            offset: new_offset,
            sequential_id_first: None,
            sequential_id_last: None,
            update_id_hex: None,
            change_id_hash: cih,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_id_hash_matches_canton_372_live_vector() {
        let actual = change_id_hash(
            "CantonConsole",
            "6aef5763-b1d4-4dd9-8935-43ab4d03c4b6",
            &[
                "alice::1220d1536504bf4bc16e55c04340578c07570592ec472db8360a5a39a45f3dfd468a"
                    .to_string(),
            ],
        );
        assert_eq!(
            actual,
            "80a4ef13d834cae532e149f233d7687effe233788e6cd76d675414cc7700acd5"
        );
    }

    #[test]
    fn int_array_and_stored_parties_encodings_match_wire() {
        assert_eq!(encode_interned_int_array(&[]), Vec::<u8>::new());
        assert_eq!(
            encode_interned_int_array(&[4]),
            vec![0x01, 0x00, 0x00, 0x00, 0x04]
        );
        let sp = encode_stored_parties_v30(&[
            "alice::1220d1536504bf4bc16e55c04340578c07570592ec472db8360a5a39a45f3dfd468a"
                .to_string(),
        ]);
        // UntypedVersionedMessage { field 1 = StoredParties { field 1 = party }, field 2 = 30 }
        assert_eq!(sp[0], 0x0a);
        assert_eq!(&sp[sp.len() - 2..], &[0x10, 0x1e]);
        assert_eq!(
            encode_versioned_empty_record(),
            vec![0x0a, 0x03, b'2', b'.', b'1', 0x12, 0x02, 0x6a, 0x00]
        );
        assert_eq!(
            encode_versioned_unit(),
            vec![0x0a, 0x03, b'2', b'.', b'1', 0x12, 0x02, 0x0a, 0x00]
        );
    }
}
