//! Pure-Rust Participant Query Store (PQS) PostgreSQL projection (`REQ-PQS-SCRIBE-001`).
//!
//! Projects committed Canton Ledger API v2 updates (`CreatedEvent`, `ExercisedEvent`, `ArchivedEvent`, reassignments) and packages into
//! indexed PostgreSQL tables (`pqs_watermark`, `pqs_packages`, `pqs_contracts`, `pqs_exercises`) with idempotent
//! single-transaction offset commits. [`parse_update`] reads one `/v2/updates` item into a [`PqsUpdate`]; [`PqsStore::ingest_update`]
//! writes it.

use postgres::{Client, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pgconn::{connect_with_retry, PgTarget, RetryPolicy};

const PQS_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS pqs_watermark (
    id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    ledger_offset bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS pqs_packages (
    package_id text PRIMARY KEY,
    name text NOT NULL DEFAULT '',
    version text NOT NULL DEFAULT '',
    uploaded_at_offset bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS pqs_contracts (
    contract_id text PRIMARY KEY,
    template_id text NOT NULL,
    package_id text NOT NULL,
    module_name text NOT NULL,
    entity_name text NOT NULL,
    create_offset bigint NOT NULL,
    record_time text NULL,
    payload jsonb NOT NULL,
    contract_key jsonb NULL,
    signatories text[] NOT NULL,
    observers text[] NOT NULL,
    created_event_blob bytea NULL,
    archive_offset bigint NULL,
    archive_record_time text NULL
);
ALTER TABLE pqs_contracts ADD COLUMN IF NOT EXISTS unassign_offset bigint NULL;
CREATE INDEX IF NOT EXISTS idx_pqs_contracts_active_tpl
    ON pqs_contracts (template_id) WHERE archive_offset IS NULL AND unassign_offset IS NULL;
CREATE INDEX IF NOT EXISTS idx_pqs_contracts_payload_gin
    ON pqs_contracts USING GIN (payload);
CREATE TABLE IF NOT EXISTS pqs_exercises (
    offset_id bigint NOT NULL,
    node_id integer NOT NULL,
    update_id text NOT NULL,
    contract_id text NOT NULL,
    template_id text NOT NULL,
    interface_id text NULL,
    choice text NOT NULL,
    choice_argument jsonb NOT NULL,
    exercise_result jsonb NULL,
    acting_parties text[] NOT NULL,
    consuming boolean NOT NULL,
    record_time text NULL,
    PRIMARY KEY (offset_id, node_id)
);
"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqsStatus {
    pub watermark: i64,
    pub active_contracts: i64,
    pub archived_contracts: i64,
    pub exercises: i64,
    pub packages: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PqsContractRow {
    pub contract_id: String,
    pub template_id: String,
    pub package_id: String,
    pub module_name: String,
    pub entity_name: String,
    pub create_offset: i64,
    pub record_time: Option<String>,
    pub payload: Value,
    pub contract_key: Option<Value>,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    pub archive_offset: Option<i64>,
    pub archive_record_time: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PqsExerciseRow {
    pub offset_id: i64,
    pub node_id: i32,
    pub update_id: String,
    pub contract_id: String,
    pub template_id: String,
    pub interface_id: Option<String>,
    pub choice: String,
    pub choice_argument: Value,
    pub exercise_result: Option<Value>,
    pub acting_parties: Vec<String>,
    pub consuming: bool,
    pub record_time: Option<String>,
}

/// What one `/v2/updates` item does to the projection.
#[derive(Debug, Clone, PartialEq)]
pub struct PqsUpdate {
    pub offset: i64,
    pub update_id: String,
    pub record_time: Option<String>,
    pub events: Vec<PqsEvent>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PqsEvent {
    /// A `CreatedEvent` of a contract one of the subscribed parties is a stakeholder of.
    Created(Value),
    Archived(Value),
    /// An `ExercisedEvent` and the node id to use when it names none.
    Exercised(i32, Value),
    /// The contract left this participant's synchronizer: in no ACS until it is assigned.
    Unassigned(String),
    /// The `createdEvent` of an assignment.
    Assigned(Value),
}

/// Reads one `/v2/updates` item. Every item kind carries its offset (`{update: {<Kind>: {value: {offset}}}}`); an item without one is an
/// error, never a guess. A create none of `parties` is a stakeholder of (a contract only witnessed under `LEDGER_EFFECTS`) is dropped: its
/// archive would not be shown to them.
pub fn parse_update(item: &Value, parties: &[String]) -> Result<PqsUpdate, String> {
    let (kind, body) = update_body(item).ok_or_else(|| format!("not an update item: {item}"))?;
    let offset = parse_offset_field(body.get("offset"))
        .ok_or_else(|| format!("{kind} update without an offset: {item}"))?;
    let mut update = PqsUpdate {
        offset,
        update_id: body
            .get("updateId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        record_time: body
            .get("recordTime")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        events: Vec::new(),
    };
    let events = body.get("events").and_then(Value::as_array);
    let stakeholder = |ev: &Value| {
        ["signatories", "observers"]
            .iter()
            .flat_map(|k| string_vec(ev.get(*k)))
            .any(|p| parties.contains(&p))
    };
    match kind {
        "Transaction" => {
            for (idx, ev) in events.into_iter().flatten().enumerate() {
                if let Some(created) = ev.get("CreatedEvent").or_else(|| ev.get("created")) {
                    if stakeholder(created) {
                        update.events.push(PqsEvent::Created(created.clone()));
                    }
                }
                if let Some(archived) = ev.get("ArchivedEvent").or_else(|| ev.get("archived")) {
                    update.events.push(PqsEvent::Archived(archived.clone()));
                }
                if let Some(exercised) = ev.get("ExercisedEvent").or_else(|| ev.get("exercised")) {
                    let node = i32::try_from(idx).map_err(|e| e.to_string())?;
                    update
                        .events
                        .push(PqsEvent::Exercised(node, exercised.clone()));
                }
            }
        }
        "Reassignment" => {
            for ev in events.into_iter().flatten() {
                if let Some(cid) = ev
                    .pointer("/JsUnassignedEvent/value/contractId")
                    .and_then(Value::as_str)
                {
                    update.events.push(PqsEvent::Unassigned(cid.to_string()));
                }
                if let Some(created) = ev.pointer("/JsAssignmentEvent/createdEvent") {
                    if stakeholder(created) {
                        update.events.push(PqsEvent::Assigned(created.clone()));
                    }
                }
            }
        }
        _ => {}
    }
    Ok(update)
}

/// The kind and the body of an update item (`{update: {Transaction: {value: {...}}}}`, or the older shapes without `update` or `value`).
fn update_body(item: &Value) -> Option<(&str, &Value)> {
    let wrapper = item.get("update").unwrap_or(item).as_object()?;
    let (kind, inner) = wrapper.iter().next()?;
    let kind = match kind.as_str() {
        "transaction" => "Transaction",
        k => k,
    };
    Some((kind, inner.get("value").unwrap_or(inner)))
}

/// PostgreSQL-backed projection store for Ledger API v2 contract and exercise history.
pub struct PqsStore {
    target: PgTarget,
    client: Client,
}

impl PqsStore {
    pub fn connect(url_or_jdbc: &str) -> Result<Self, String> {
        let target = PgTarget::from_url_or_jdbc(url_or_jdbc, None, None, None)?;
        let mut client = connect_with_retry(&target, RetryPolicy::from_env())?;
        client
            .batch_execute(PQS_SCHEMA_SQL)
            .map_err(|e| format!("failed to initialize PQS schema: {e}"))?;
        Ok(Self { target, client })
    }

    fn ensure_connected(&mut self) -> Result<(), String> {
        if self.client.is_closed() {
            self.client = connect_with_retry(&self.target, RetryPolicy::from_env())?;
        }
        Ok(())
    }

    pub fn watermark(&mut self) -> Result<i64, String> {
        self.ensure_connected()?;
        let row = self
            .client
            .query_opt("SELECT ledger_offset FROM pqs_watermark WHERE id = 1", &[])
            .map_err(|e| e.to_string())?;
        Ok(row.map_or(0, |r| r.get(0)))
    }

    pub fn bump_watermark(&mut self, offset: i64) -> Result<(), String> {
        self.ensure_connected()?;
        self.client
            .execute(
                "INSERT INTO pqs_watermark (id, ledger_offset) VALUES (1, $1) \
                 ON CONFLICT (id) DO UPDATE SET ledger_offset = GREATEST(pqs_watermark.ledger_offset, EXCLUDED.ledger_offset)",
                &[&offset],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn ingest_packages(
        &mut self,
        pkgs: &[(String, String, String, i64)],
    ) -> Result<u64, String> {
        self.ensure_connected()?;
        let mut tx = self.client.transaction().map_err(|e| e.to_string())?;
        let mut count = 0_u64;
        for (pkg_id, name, version, offset) in pkgs {
            count += tx
                .execute(
                    "INSERT INTO pqs_packages (package_id, name, version, uploaded_at_offset) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (package_id) DO UPDATE SET \
                     name = CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE pqs_packages.name END, \
                     version = CASE WHEN EXCLUDED.version <> '' THEN EXCLUDED.version ELSE pqs_packages.version END",
                    &[pkg_id, name, version, offset],
                )
                .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(count)
    }

    /// Idempotently projects one `/v2/updates` item into PostgreSQL in a single transaction ([`parse_update`], then
    /// [`PqsStore::ingest_update`]).
    pub fn ingest_update_json(
        &mut self,
        update_item: &Value,
        parties: &[String],
    ) -> Result<bool, String> {
        self.ingest_update(&parse_update(update_item, parties)?)
    }

    /// Writes one update and moves the watermark to its offset, in one transaction.
    ///
    /// Returns `Ok(false)` without mutating state when `offset <= watermark`.
    pub fn ingest_update(&mut self, update: &PqsUpdate) -> Result<bool, String> {
        self.ensure_connected()?;
        let mut tx = self.client.transaction().map_err(|e| e.to_string())?;
        let current_watermark: i64 = tx
            .query_opt(
                "SELECT ledger_offset FROM pqs_watermark WHERE id = 1 FOR UPDATE",
                &[],
            )
            .map_err(|e| e.to_string())?
            .map_or(0, |r| r.get(0));
        if update.offset <= current_watermark {
            return Ok(false);
        }
        let (offset, record_time) = (update.offset, update.record_time.as_deref());
        for event in &update.events {
            match event {
                PqsEvent::Created(ev) => insert_created_event(&mut tx, offset, record_time, ev)?,
                PqsEvent::Archived(ev) => apply_archive_event(&mut tx, offset, record_time, ev)?,
                PqsEvent::Exercised(node, ev) => insert_exercised_event(
                    &mut tx,
                    offset,
                    *node,
                    &update.update_id,
                    record_time,
                    ev,
                )?,
                PqsEvent::Unassigned(cid) => {
                    tx.execute(
                        "UPDATE pqs_contracts SET unassign_offset = $2 \
                         WHERE contract_id = $1 AND archive_offset IS NULL",
                        &[cid, &offset],
                    )
                    .map_err(|e| e.to_string())?;
                }
                PqsEvent::Assigned(ev) => {
                    insert_created_event(&mut tx, offset, record_time, ev)?;
                    let cid = ev.get("contractId").and_then(Value::as_str).unwrap_or("");
                    tx.execute(
                        "UPDATE pqs_contracts SET unassign_offset = NULL WHERE contract_id = $1",
                        &[&cid],
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }

        tx.execute(
            "INSERT INTO pqs_watermark (id, ledger_offset) VALUES (1, $1) \
             ON CONFLICT (id) DO UPDATE SET ledger_offset = EXCLUDED.ledger_offset",
            &[&offset],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Starts an empty store from the active contracts at `offset` (`/v2/state/active-contracts` `createdEvent`s): their rows and the
    /// watermark at `offset`, in one transaction. The history before `offset` (exercises, archived contracts) is not there.
    pub fn bootstrap_acs(&mut self, offset: i64, created: &[Value]) -> Result<u64, String> {
        self.ensure_connected()?;
        let mut tx = self.client.transaction().map_err(|e| e.to_string())?;
        let current_watermark: i64 = tx
            .query_opt(
                "SELECT ledger_offset FROM pqs_watermark WHERE id = 1 FOR UPDATE",
                &[],
            )
            .map_err(|e| e.to_string())?
            .map_or(0, |r| r.get(0));
        if current_watermark != 0 {
            return Err(format!(
                "an ACS bootstrap needs an empty PQS store (watermark {current_watermark})"
            ));
        }
        for ev in created {
            insert_created_event(&mut tx, offset, None, ev)?;
        }
        tx.execute(
            "INSERT INTO pqs_watermark (id, ledger_offset) VALUES (1, $1) \
             ON CONFLICT (id) DO UPDATE SET ledger_offset = EXCLUDED.ledger_offset",
            &[&offset],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(created.len() as u64)
    }

    pub fn status(&mut self) -> Result<PqsStatus, String> {
        self.ensure_connected()?;
        let row = self
            .client
            .query_one(
                "SELECT \
                 COALESCE((SELECT ledger_offset FROM pqs_watermark WHERE id = 1), 0), \
                 (SELECT COUNT(*) FROM pqs_contracts WHERE archive_offset IS NULL AND unassign_offset IS NULL), \
                 (SELECT COUNT(*) FROM pqs_contracts WHERE archive_offset IS NOT NULL), \
                 (SELECT COUNT(*) FROM pqs_exercises), \
                 (SELECT COUNT(*) FROM pqs_packages)",
                &[],
            )
            .map_err(|e| e.to_string())?;
        Ok(PqsStatus {
            watermark: row.get(0),
            active_contracts: row.get(1),
            archived_contracts: row.get(2),
            exercises: row.get(3),
            packages: row.get(4),
        })
    }

    pub fn query_active(
        &mut self,
        template_suffix: Option<&str>,
        party: Option<&str>,
        payload_filter: Option<&Value>,
    ) -> Result<Vec<PqsContractRow>, String> {
        self.query_contracts_inner(true, template_suffix, party, payload_filter)
    }

    pub fn query_contracts_history(
        &mut self,
        template_suffix: Option<&str>,
    ) -> Result<Vec<PqsContractRow>, String> {
        self.query_contracts_inner(false, template_suffix, None, None)
    }

    fn query_contracts_inner(
        &mut self,
        active_only: bool,
        template_suffix: Option<&str>,
        party: Option<&str>,
        payload_filter: Option<&Value>,
    ) -> Result<Vec<PqsContractRow>, String> {
        self.ensure_connected()?;
        let filter_str = payload_filter.map(|v| v.to_string());
        let rows = self
            .client
            .query(
                "SELECT contract_id, template_id, package_id, module_name, entity_name, \
                 create_offset, record_time, payload::text, contract_key::text, \
                 signatories, observers, archive_offset, archive_record_time \
                 FROM pqs_contracts \
                 WHERE ($1::bool = false OR (archive_offset IS NULL AND unassign_offset IS NULL)) \
                 AND ($2::text IS NULL OR template_id = $2 OR right(template_id, length($2) + 1) = ':' || $2) \
                 AND ($3::text IS NULL OR $3 = ANY(signatories) OR $3 = ANY(observers)) \
                 AND ($4::text IS NULL OR payload @> ($4::text)::jsonb) \
                 ORDER BY create_offset ASC, contract_id ASC",
                &[&active_only, &template_suffix, &party, &filter_str],
            )
            .map_err(|e| e.to_string())?;
        rows.into_iter().map(row_to_contract).collect()
    }

    pub fn query_exercises(
        &mut self,
        template_suffix: Option<&str>,
        choice: Option<&str>,
    ) -> Result<Vec<PqsExerciseRow>, String> {
        self.ensure_connected()?;
        let rows = self
            .client
            .query(
                "SELECT offset_id, node_id, update_id, contract_id, template_id, interface_id, \
                 choice, choice_argument::text, exercise_result::text, acting_parties, consuming, record_time \
                 FROM pqs_exercises \
                 WHERE ($1::text IS NULL OR template_id = $1 OR right(template_id, length($1) + 1) = ':' || $1) \
                 AND ($2::text IS NULL OR choice = $2) \
                 ORDER BY offset_id ASC, node_id ASC",
                &[&template_suffix, &choice],
            )
            .map_err(|e| e.to_string())?;
        rows.into_iter().map(row_to_exercise).collect()
    }

    pub fn prune_archived_before(&mut self, max_offset: i64) -> Result<(u64, u64), String> {
        self.ensure_connected()?;
        let mut tx = self.client.transaction().map_err(|e| e.to_string())?;
        let pruned_contracts = tx
            .execute(
                "DELETE FROM pqs_contracts WHERE archive_offset IS NOT NULL AND archive_offset <= $1",
                &[&max_offset],
            )
            .map_err(|e| e.to_string())?;
        let pruned_exercises = tx
            .execute(
                "DELETE FROM pqs_exercises WHERE offset_id <= $1",
                &[&max_offset],
            )
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok((pruned_contracts, pruned_exercises))
    }
}

fn row_to_contract(r: Row) -> Result<PqsContractRow, String> {
    let payload_txt: String = r.get(7);
    let key_txt: Option<String> = r.get(8);
    Ok(PqsContractRow {
        contract_id: r.get(0),
        template_id: r.get(1),
        package_id: r.get(2),
        module_name: r.get(3),
        entity_name: r.get(4),
        create_offset: r.get(5),
        record_time: r.get(6),
        payload: serde_json::from_str(&payload_txt).map_err(|e| e.to_string())?,
        contract_key: key_txt
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| e.to_string())?,
        signatories: r.get(9),
        observers: r.get(10),
        archive_offset: r.get(11),
        archive_record_time: r.get(12),
    })
}

fn row_to_exercise(r: Row) -> Result<PqsExerciseRow, String> {
    let arg_txt: String = r.get(7);
    let res_txt: Option<String> = r.get(8);
    Ok(PqsExerciseRow {
        offset_id: r.get(0),
        node_id: r.get(1),
        update_id: r.get(2),
        contract_id: r.get(3),
        template_id: r.get(4),
        interface_id: r.get(5),
        choice: r.get(6),
        choice_argument: serde_json::from_str(&arg_txt).map_err(|e| e.to_string())?,
        exercise_result: res_txt
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| e.to_string())?,
        acting_parties: r.get(9),
        consuming: r.get(10),
        record_time: r.get(11),
    })
}

pub fn parse_offset_field(v: Option<&Value>) -> Option<i64> {
    let val = v?;
    val.as_i64()
        .or_else(|| val.as_str().and_then(|s| s.parse::<i64>().ok()))
}

fn split_template_id(v: Option<&Value>) -> (String, String, String, String) {
    let Some(val) = v else {
        return (String::new(), String::new(), String::new(), String::new());
    };
    if let Some(s) = val.as_str() {
        let mut parts = s.splitn(3, ':');
        let pkg = parts.next().unwrap_or("").to_string();
        let module_name = parts.next().unwrap_or("").to_string();
        let entity_name = parts.next().unwrap_or("").to_string();
        return (s.to_string(), pkg, module_name, entity_name);
    }
    let pkg = val
        .get("packageId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let module_name = val
        .get("moduleName")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let entity_name = val
        .get("entityName")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let full = format!("{pkg}:{module_name}:{entity_name}");
    (full, pkg, module_name, entity_name)
}

fn string_vec(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn decode_base64_opt(s: Option<&str>) -> Option<Vec<u8>> {
    let raw = s?.trim();
    if raw.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() * 3 / 4);
    let mut acc = 0_u32;
    let mut bits = 0_u8;
    for b in raw.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn insert_created_event(
    tx: &mut postgres::Transaction<'_>,
    offset: i64,
    record_time: Option<&str>,
    ev: &Value,
) -> Result<(), String> {
    let cid = ev
        .get("contractId")
        .and_then(Value::as_str)
        .ok_or("CreatedEvent missing contractId")?;
    let (template_id, package_id, module_name, entity_name) =
        split_template_id(ev.get("templateId"));
    let ev_offset = parse_offset_field(ev.get("offset")).unwrap_or(offset);
    let payload_str = ev
        .get("createArgument")
        .or_else(|| ev.get("createArguments"))
        .cloned()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()))
        .to_string();
    let key_str = ev
        .get("contractKey")
        .filter(|k| !k.is_null())
        .map(|k| k.to_string());
    let signatories = string_vec(ev.get("signatories"));
    let observers = string_vec(ev.get("observers"));
    let blob = decode_base64_opt(ev.get("createdEventBlob").and_then(Value::as_str));

    tx.execute(
        "INSERT INTO pqs_contracts \
         (contract_id, template_id, package_id, module_name, entity_name, create_offset, record_time, \
          payload, contract_key, signatories, observers, created_event_blob) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, ($8::text)::jsonb, ($9::text)::jsonb, $10, $11, $12) \
         ON CONFLICT (contract_id) DO NOTHING",
        &[
            &cid,
            &template_id,
            &package_id,
            &module_name,
            &entity_name,
            &ev_offset,
            &record_time,
            &payload_str,
            &key_str,
            &signatories,
            &observers,
            &blob,
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn apply_archive_event(
    tx: &mut postgres::Transaction<'_>,
    offset: i64,
    record_time: Option<&str>,
    ev: &Value,
) -> Result<(), String> {
    let Some(cid) = ev.get("contractId").and_then(Value::as_str) else {
        return Ok(());
    };
    let ev_offset = parse_offset_field(ev.get("offset")).unwrap_or(offset);
    tx.execute(
        "UPDATE pqs_contracts SET archive_offset = $2, archive_record_time = $3 \
         WHERE contract_id = $1 AND archive_offset IS NULL",
        &[&cid, &ev_offset, &record_time],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn insert_exercised_event(
    tx: &mut postgres::Transaction<'_>,
    offset: i64,
    fallback_node_id: i32,
    update_id: &str,
    record_time: Option<&str>,
    ev: &Value,
) -> Result<(), String> {
    let cid = ev
        .get("contractId")
        .and_then(Value::as_str)
        .ok_or("ExercisedEvent missing contractId")?;
    let node_id = ev
        .get("nodeId")
        .and_then(Value::as_i64)
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(fallback_node_id);
    let ev_offset = parse_offset_field(ev.get("offset")).unwrap_or(offset);
    let (template_id, _, _, _) = split_template_id(ev.get("templateId"));
    let interface_id = ev.get("interfaceId").and_then(|v| {
        if v.is_null() {
            None
        } else {
            let (full, _, _, _) = split_template_id(Some(v));
            (!full.is_empty()).then_some(full)
        }
    });
    let choice = ev.get("choice").and_then(Value::as_str).unwrap_or("");
    let choice_arg = ev
        .get("choiceArgument")
        .cloned()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()))
        .to_string();
    let ex_result = ev
        .get("exerciseResult")
        .filter(|v| !v.is_null())
        .map(|v| v.to_string());
    let acting = string_vec(ev.get("actingParties"));
    let consuming = ev
        .get("consuming")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    tx.execute(
        "INSERT INTO pqs_exercises \
         (offset_id, node_id, update_id, contract_id, template_id, interface_id, choice, \
          choice_argument, exercise_result, acting_parties, consuming, record_time) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, ($8::text)::jsonb, ($9::text)::jsonb, $10, $11, $12) \
         ON CONFLICT (offset_id, node_id) DO NOTHING",
        &[
            &ev_offset,
            &node_id,
            &update_id,
            &cid,
            &template_id,
            &interface_id,
            &choice,
            &choice_arg,
            &ex_result,
            &acting,
            &consuming,
            &record_time,
        ],
    )
    .map_err(|e| e.to_string())?;

    if consuming {
        tx.execute(
            "UPDATE pqs_contracts SET archive_offset = $2, archive_record_time = $3 \
             WHERE contract_id = $1 AND archive_offset IS NULL",
            &[&cid, &ev_offset, &record_time],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parties() -> Vec<String> {
        vec!["alice::1".to_string()]
    }

    #[test]
    fn an_update_without_an_offset_is_refused() {
        let item = json!({"update": {"Transaction": {"value": {"updateId": "u", "events": []}}}});
        let err = parse_update(&item, &parties()).unwrap_err();
        assert!(err.contains("without an offset"), "{err}");
    }

    #[test]
    fn every_update_kind_has_its_own_offset() {
        let reassignment = json!({"update": {"Reassignment": {"value": {"offset": 7, "updateId": "r", "events": []}}}});
        assert_eq!(parse_update(&reassignment, &parties()).unwrap().offset, 7);
        let checkpoint = json!({"update": {"OffsetCheckpoint": {"value": {"offset": "9", "synchronizerTimes": []}}}});
        let parsed = parse_update(&checkpoint, &parties()).unwrap();
        assert_eq!((parsed.offset, parsed.events.len()), (9, 0));
    }

    #[test]
    fn a_reassignment_unassigns_and_assigns_the_contract() {
        let created = json!({"contractId": "00c", "templateId": "p:M:T", "signatories": ["alice::1"], "observers": []});
        let unassign = json!({"update": {"Reassignment": {"value": {"offset": 4, "events": [
            {"JsUnassignedEvent": {"value": {"contractId": "00c", "offset": 4}}}]}}}});
        let assign = json!({"update": {"Reassignment": {"value": {"offset": 5, "events": [
            {"JsAssignmentEvent": {"createdEvent": created, "reassignmentCounter": 1}}]}}}});
        assert_eq!(
            parse_update(&unassign, &parties()).unwrap().events,
            [PqsEvent::Unassigned("00c".into())]
        );
        assert_eq!(
            parse_update(&assign, &parties()).unwrap().events,
            [PqsEvent::Assigned(created)]
        );
    }

    #[test]
    fn a_create_only_witnessed_is_not_projected() {
        let item = json!({"update": {"Transaction": {"value": {"offset": "3", "events": [
            {"CreatedEvent": {"contractId": "00own", "signatories": ["bank::1"], "observers": ["alice::1"]}},
            {"CreatedEvent": {"contractId": "00witnessed", "signatories": ["bank::1"], "observers": []}}]}}}});
        let events = parse_update(&item, &parties()).unwrap().events;
        let ids: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                PqsEvent::Created(c) => c["contractId"].as_str(),
                _ => None,
            })
            .collect();
        assert_eq!(ids, ["00own"]);
    }
}
