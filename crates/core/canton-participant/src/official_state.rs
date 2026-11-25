//! What an official Canton 3.7.2 participant keeps in its PostgreSQL database and its Ledger API shows, read back (U-47, AT-D11).
//!
//! [CANTON-NOTE: SEMANTICS] The party list of the official participant is not a table of its own. The parties are the **current
//! `PartyToParticipant` mappings of the topology** (`common_topology_transactions`, transaction type 9, not superseded, not a proposal, not
//! rejected), a party being *local* when the participant itself hosts it; the participant's own party (its uid) is listed besides. The
//! metadata a party was given through the Ledger API (resource version, annotations, identity provider) is in `lapi_party_records` and
//! `lapi_party_record_annotations`, and only for parties allocated through the API with metadata (a party the console enabled has none:
//! the official API lists it with an empty resource version). Measured on a Canton 3.7.2 participant on PostgreSQL
//! (`scripts/oracle-party-parity.sh`).
use std::collections::BTreeMap;

use postgres::Client;

use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;

use crate::topology_state::{decode, Entry};

/// One party of the participant's topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficialParty {
    /// `name::fingerprint`.
    pub party: String,
    /// Whether this participant hosts the party (as submitter, confirmer or observer).
    pub is_local: bool,
}

/// The metadata a party was given through the Ledger API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyRecord {
    pub party: String,
    pub resource_version: i64,
    pub annotations: BTreeMap<String, String>,
    /// The identity provider the party belongs to (empty: the default one).
    pub identity_provider_id: String,
}

/// The parties of an official participant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OfficialParties {
    /// The participant's uid (`name::fingerprint`), which is also its own party.
    pub participant_uid: String,
    /// Every current party of the topology, in the order of their ids.
    pub parties: Vec<OfficialParty>,
    pub records: Vec<PartyRecord>,
}

/// The `PartyToParticipant` mapping's transaction type in `common_topology_transactions`.
const PARTY_TO_PARTICIPANT: i32 = 9;

/// Returns `true` when `client` holds the core official Canton participant schema tables (even if empty).
pub fn has_official_schema(client: &mut Client) -> Result<bool, String> {
    let exists: bool = client
        .query_one(
            "SELECT to_regclass('lapi_parameters') IS NOT NULL \
             AND to_regclass('lapi_users') IS NOT NULL \
             AND to_regclass('common_static_strings') IS NOT NULL",
            &[],
        )
        .map_err(|e| e.to_string())?
        .get(0);
    Ok(exists)
}

/// Returns `true` when `client` points at a database that holds official Canton participant tables (`lapi_parameters` populated).
pub fn has_official_participant(client: &mut Client) -> Result<bool, String> {
    let exists: bool = client
        .query_one("SELECT to_regclass('lapi_parameters') IS NOT NULL", &[])
        .map_err(|e| e.to_string())?
        .get(0);
    if !exists {
        return Ok(false);
    }
    let populated: bool = client
        .query_one("SELECT EXISTS (SELECT 1 FROM lapi_parameters)", &[])
        .map_err(|e| e.to_string())?
        .get(0);
    Ok(populated)
}

/// Reads the parties of the participant whose database `client` is connected to.
pub fn read_parties(client: &mut Client) -> Result<OfficialParties, String> {
    let participant_id: String = client
        .query_opt("SELECT participant_id FROM lapi_parameters", &[])
        .map_err(|e| e.to_string())?
        .map(|r| r.get(0))
        .ok_or("lapi_parameters has no row: this database never ran an official participant")?;
    // `PAR::name::fingerprint` in the table of an older layout, `name::fingerprint` in a newer one
    let participant_uid = participant_id
        .strip_prefix("PAR::")
        .unwrap_or(&participant_id)
        .to_string();
    let rows = client
        .query(
            "SELECT valid_from, instance FROM common_topology_transactions \
             WHERE transaction_type = $1 AND valid_until IS NULL AND operation = 1 AND is_proposal = false \
               AND rejection_reason IS NULL \
             ORDER BY id",
            &[&PARTY_TO_PARTICIPANT],
        )
        .map_err(|e| e.to_string())?;
    let items: Vec<(i64, Vec<u8>)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    let entries: Vec<Entry> = decode(&items)?;
    // the current mapping of each party (the last one read), whatever store it came from
    let mut current: BTreeMap<String, bool> = BTreeMap::new();
    for entry in &entries {
        if let Some(Mapping::PartyToParticipant(p)) =
            entry.tx.mapping.as_ref().and_then(|m| m.mapping.as_ref())
        {
            let local = p
                .participants
                .iter()
                .any(|h| h.participant_uid == participant_uid);
            current.insert(p.party.clone(), local);
        }
    }
    // the participant's own party is always there and local
    current.insert(participant_uid.clone(), true);
    let mut records = Vec::new();
    for row in client
        .query(
            "SELECT internal_id, party, resource_version, identity_provider_id FROM lapi_party_records ORDER BY internal_id",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        let internal_id: i32 = row.get(0);
        let mut annotations = BTreeMap::new();
        for a in client
            .query(
                "SELECT name, val FROM lapi_party_record_annotations WHERE internal_id = $1",
                &[&internal_id],
            )
            .map_err(|e| e.to_string())?
        {
            annotations.insert(a.get::<_, String>(0), a.get::<_, Option<String>>(1).unwrap_or_default());
        }
        records.push(PartyRecord {
            party: row.get(1),
            resource_version: row.get(2),
            annotations,
            identity_provider_id: row.get::<_, Option<String>>(3).unwrap_or_default(),
        });
    }
    // [CANTON-NOTE: DEFENSIVE] Include parties recorded via `--official-write` when legacy
    // `lapi_party_entries` exists (Canton 3.7.2 drops `lapi_party_entries` in favor of
    // `lapi_events_party_to_participant`, so check `to_regclass` first).
    let has_party_entries: bool = client
        .query_one("SELECT to_regclass('lapi_party_entries') IS NOT NULL", &[])
        .map_err(|e| e.to_string())?
        .get(0);
    if has_party_entries {
        for row in client
            .query(
                "SELECT party, COALESCE(is_local, true) FROM lapi_party_entries \
                 WHERE typ = 'accept' AND party IS NOT NULL ORDER BY ledger_offset",
                &[],
            )
            .map_err(|e| e.to_string())?
        {
            current.entry(row.get(0)).or_insert_with(|| row.get(1));
        }
    }
    for r in &records {
        current.entry(r.party.clone()).or_insert(true);
    }
    let parties = current
        .into_iter()
        .map(|(party, is_local)| OfficialParty { party, is_local })
        .collect();
    Ok(OfficialParties {
        participant_uid,
        parties,
        records,
    })
}

/// A user of the participant's user management.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficialUser {
    pub id: String,
    pub primary_party: String,
    pub deactivated: bool,
    pub resource_version: i64,
    pub identity_provider_id: String,
    pub annotations: BTreeMap<String, String>,
    /// `(right code, party)`: the party is empty for the rights that name none.
    pub rights: Vec<(i32, String)>,
}

/// An identity provider configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficialIdp {
    pub id: String,
    pub issuer: String,
    pub jwks_url: String,
    pub audience: String,
    pub deactivated: bool,
}

/// A DAR the participant holds (`par_dars`): its main package and the archive itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficialDar {
    pub main_package_id: String,
    pub name: String,
    pub data: Vec<u8>,
}

/// Reads the users with their rights and annotations.
///
/// [CANTON-NOTE: SEMANTICS] The right codes of `lapi_user_rights.user_right` as measured on a Canton 3.7.2 participant
/// (`scripts/oracle-party-parity.sh`): 1 `ParticipantAdmin`, 2 `CanActAs`, 3 `CanReadAs`, 4 `IdentityProviderAdmin` (not allocated in that
/// run: the default provider refuses it), 5 `CanReadAsAnyParty`, 6 `CanExecuteAs`, 7 `CanExecuteAsAnyParty`.
pub fn read_users(client: &mut Client) -> Result<Vec<OfficialUser>, String> {
    let mut users = Vec::new();
    for row in client
        .query(
            "SELECT internal_id, user_id, primary_party, is_deactivated, resource_version, identity_provider_id \
             FROM lapi_users ORDER BY user_id",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        let internal_id: i32 = row.get(0);
        let mut annotations = BTreeMap::new();
        for a in client
            .query(
                "SELECT name, val FROM lapi_user_annotations WHERE internal_id = $1",
                &[&internal_id],
            )
            .map_err(|e| e.to_string())?
        {
            annotations.insert(
                a.get::<_, String>(0),
                a.get::<_, Option<String>>(1).unwrap_or_default(),
            );
        }
        let rights = client
            .query(
                "SELECT user_right, for_party FROM lapi_user_rights WHERE user_internal_id = $1 ORDER BY granted_at, user_right",
                &[&internal_id],
            )
            .map_err(|e| e.to_string())?
            .iter()
            .map(|r| (r.get::<_, i32>(0), r.get::<_, Option<String>>(1).unwrap_or_default()))
            .collect();
        users.push(OfficialUser {
            id: row.get(1),
            primary_party: row.get::<_, Option<String>>(2).unwrap_or_default(),
            deactivated: row.get(3),
            resource_version: row.get(4),
            identity_provider_id: row.get::<_, Option<String>>(5).unwrap_or_default(),
            annotations,
            rights,
        });
    }
    Ok(users)
}

/// Reads the identity provider configurations.
pub fn read_idps(client: &mut Client) -> Result<Vec<OfficialIdp>, String> {
    Ok(client
        .query(
            "SELECT identity_provider_id, issuer, jwks_url, audience, is_deactivated FROM lapi_identity_provider_config ORDER BY identity_provider_id",
            &[],
        )
        .map_err(|e| e.to_string())?
        .iter()
        .map(|r| OfficialIdp {
            id: r.get(0),
            issuer: r.get(1),
            jwks_url: r.get(2),
            audience: r.get::<_, Option<String>>(3).unwrap_or_default(),
            deactivated: r.get(4),
        })
        .collect())
}

/// The ids of every package the participant holds (`par_daml_packages`): the packages of its DARs, the standard library and the ones it
/// carries itself (the admin workflow packages). The Ledger API lists them all.
pub fn read_package_ids(client: &mut Client) -> Result<Vec<String>, String> {
    Ok(client
        .query(
            "SELECT package_id FROM par_daml_packages ORDER BY package_id",
            &[],
        )
        .map_err(|e| e.to_string())?
        .iter()
        .map(|r| r.get(0))
        .collect())
}

/// Reads the DARs the participant holds, in the order they were uploaded.
pub fn read_dars(client: &mut Client) -> Result<Vec<OfficialDar>, String> {
    Ok(client
        .query(
            "SELECT d.main_package_id, d.name, d.data FROM par_dars d \
             LEFT JOIN par_daml_packages p ON p.package_id = d.main_package_id \
             ORDER BY p.uploaded_at NULLS FIRST, d.name, d.main_package_id",
            &[],
        )
        .map_err(|e| e.to_string())?
        .iter()
        .map(|r| OfficialDar {
            main_package_id: r.get(0),
            name: r.get(1),
            data: r.get(2),
        })
        .collect())
}

/// A contract that is active in the participant's index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficialContract {
    /// The contract id, hex.
    pub contract_id: String,
    pub package_id: String,
    /// The versioned `FatContractInstance` bytes the participant stored (`par_contracts.instance`).
    pub instance: Vec<u8>,
    /// The offset of its create and the node it is in the creating transaction.
    pub offset: i64,
    pub node_id: i32,
    /// The synchronizer the contract is on (`name::fingerprint`).
    pub synchronizer: String,
}

/// Reads every contract that is active at the participant's ledger end, in the order of their creation, with the ledger end (`None` for a participant
/// that never published anything): the offset the Ledger API reports as `ledger-end`.
pub fn read_active_contracts(
    client: &mut Client,
) -> Result<(Option<i64>, Vec<OfficialContract>), String> {
    let end = client
        .query_opt("SELECT ledger_end FROM lapi_parameters", &[])
        .map_err(|e| e.to_string())?
        .and_then(|r| r.get::<_, Option<i64>>(0));
    let rows = client
        .query(
            "SELECT encode(c.contract_id, 'hex'), c.package_id, c.instance, a.event_offset, a.node_id, a.synchronizer_id \
             FROM lapi_events_activate_contract a \
             JOIN par_contracts c ON c.internal_contract_id = a.internal_contract_id \
             WHERE NOT EXISTS (SELECT 1 FROM lapi_events_deactivate_contract d \
                               WHERE d.deactivated_event_sequential_id = a.event_sequential_id) \
             ORDER BY a.event_sequential_id",
            &[],
        )
        .map_err(|e| e.to_string())?;
    let interned = interning(client)?;
    Ok((
        end,
        rows.iter()
            .map(|r| OfficialContract {
                contract_id: r.get(0),
                package_id: r.get(1),
                instance: r.get(2),
                offset: r.get(3),
                node_id: r.get(4),
                synchronizer: interned
                    .get(&r.get::<_, i32>(5))
                    .cloned()
                    .unwrap_or_default(),
            })
            .collect(),
    ))
}

/// The strings the Ledger API tables store as numbers (`lapi_string_interning`), by number, without the letter that names the kind.
fn interning(client: &mut Client) -> Result<BTreeMap<i32, String>, String> {
    let mut interned: BTreeMap<i32, String> = BTreeMap::new();
    for row in client
        .query(
            "SELECT internal_id, external_string FROM lapi_string_interning",
            &[],
        )
        .map_err(|e| e.to_string())?
    {
        let text: String = row.get(1);
        if let Some((_, value)) = text.split_once('|') {
            interned.insert(row.get(0), value.to_string());
        }
    }
    Ok(interned)
}

/// An exercise of an official update: the choice, who exercised it and what it was given and returned (versioned Daml values as stored).
#[derive(Debug, Clone)]
pub struct OfficialExercise {
    pub consuming: bool,
    pub choice: String,
    pub actors: Vec<String>,
    /// The node of its last descendant in the transaction.
    pub last_descendant: i32,
    pub argument: Vec<u8>,
    pub result: Vec<u8>,
}

/// One event of an official update: a creation or an exercise (consuming: the archival of the contract).
#[derive(Debug, Clone)]
pub struct OfficialEvent {
    /// The exercise this event is (`None` for a creation).
    pub exercise: Option<OfficialExercise>,
    pub node_id: i32,
    /// The contract id (hex) and the versioned `FatContractInstance` bytes the participant keeps for it (also after it is archived).
    pub contract_id: String,
    pub package_id: String,
    pub instance: Vec<u8>,
    /// The stakeholders of the event's contract (for an exercise that is not consuming: all the parties that see it), sorted by the party text.
    pub stakeholders: Vec<String>,
    /// The parties that see the event besides its stakeholders (the actors and stakeholders of the exercises above it), in the order stored.
    pub additional: Vec<String>,
    /// The ledger effective time of an exercise (microseconds since the epoch).
    pub effective_micros: Option<i64>,
}

/// An update (a transaction) of the participant's history.
#[derive(Debug, Clone)]
pub struct OfficialUpdate {
    pub offset: i64,
    /// Hex of the update id.
    pub update_id: String,
    pub command_id: String,
    pub workflow_id: String,
    pub record_time_micros: i64,
    pub synchronizer: String,
    /// `traceparent` of the trace context the participant recorded.
    pub trace_parent: Option<String>,
    pub external_transaction_hash: Option<String>,
    pub traffic_cost: i64,
    /// The parties that submitted the command.
    pub submitters: Vec<String>,
    pub events: Vec<OfficialEvent>,
}

/// The `traceparent` of a stored trace context (a protobuf message whose field 1 is the text).
fn trace_parent_of(bytes: &[u8]) -> Option<String> {
    let (&tag, rest) = bytes.split_first()?;
    if tag != 0x0a {
        return None;
    }
    // the length is a varint
    let (mut len, mut shift, mut at) = (0usize, 0, 0);
    loop {
        let b = *rest.get(at)?;
        len |= ((b & 0x7f) as usize) << shift;
        at += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    String::from_utf8(rest.get(at..at + len)?.to_vec()).ok()
}

/// Reads the transactions of the participant's history in the order of their offsets: the creations (`lapi_events_activate_contract`) and the
/// consuming exercises (`lapi_events_deactivate_contract`) and non-consuming ones (`lapi_events_various_witnessed`, which names its contract by id
/// instead of by the internal number) with their witnesses (the `lapi_filter_*` tables), the command and workflow ids,
/// record times, trace contexts and the contract instances (`par_contracts`). Reassignments and the topology events of the participant are not read.
///
/// [CANTON-NOTE: SEMANTICS] Parties, templates, choices and synchronizers are stored as numbers that `lapi_string_interning` resolves (the
/// first letter of the stored text names the kind: `p` party, `c` choice, `d` synchronizer).
pub fn read_updates(client: &mut Client) -> Result<Vec<OfficialUpdate>, String> {
    let interned = interning(client)?;
    let name = |id: i32| interned.get(&id).cloned().unwrap_or_default();
    let mut witnesses: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    // the parties that see an event: the stakeholders and the additional witnesses together (the latter are told apart by the columns of the event)
    for table in [
        "lapi_filter_activate_stakeholder",
        "lapi_filter_activate_witness",
        "lapi_filter_deactivate_stakeholder",
        "lapi_filter_deactivate_witness",
        "lapi_filter_various_witness",
    ] {
        for row in client
            .query(
                &format!("SELECT event_sequential_id, party_id FROM {table}"),
                &[],
            )
            .map_err(|e| e.to_string())?
        {
            let party = name(row.get(1));
            let seen = witnesses.entry(row.get(0)).or_default();
            if !seen.contains(&party) {
                seen.push(party);
            }
        }
    }
    let mut updates: BTreeMap<i64, OfficialUpdate> = BTreeMap::new();
    let creations = client
        .query(
            "SELECT a.event_sequential_id, a.event_offset, encode(a.update_id, 'hex'), a.workflow_id, a.command_id, a.record_time, \
                    a.synchronizer_id, a.trace_context, encode(a.external_transaction_hash, 'hex'), a.node_id, a.traffic_cost, \
                    encode(c.contract_id, 'hex'), c.package_id, c.instance, a.additional_witnesses, a.submitters \
             FROM lapi_events_activate_contract a JOIN par_contracts c ON c.internal_contract_id = a.internal_contract_id \
             WHERE a.event_type = 1",
            &[],
        )
        .map_err(|e| e.to_string())?;
    let archivals = client
        .query(
            "SELECT d.event_sequential_id, d.event_offset, encode(d.update_id, 'hex'), d.workflow_id, d.command_id, d.record_time, \
                    d.synchronizer_id, d.trace_context, encode(d.external_transaction_hash, 'hex'), d.node_id, d.traffic_cost, \
                    encode(c.contract_id, 'hex'), c.package_id, c.instance, d.exercise_choice, d.ledger_effective_time, d.exercise_actors, \
                    d.exercise_last_descendant_node_id, d.exercise_argument, d.exercise_result, d.additional_witnesses, d.submitters \
             FROM lapi_events_deactivate_contract d JOIN par_contracts c ON c.internal_contract_id = d.internal_contract_id \
             WHERE d.event_type = 3",
            &[],
        )
        .map_err(|e| e.to_string())?;
    let witnessed = client
        .query(
            "SELECT d.event_sequential_id, d.event_offset, encode(d.update_id, 'hex'), d.workflow_id, d.command_id, d.record_time, \
                    d.synchronizer_id, d.trace_context, encode(d.external_transaction_hash, 'hex'), d.node_id, d.traffic_cost, \
                    encode(c.contract_id, 'hex'), c.package_id, c.instance, d.exercise_choice, d.ledger_effective_time, d.exercise_actors, \
                    d.exercise_last_descendant_node_id, d.exercise_argument, d.exercise_result, d.additional_witnesses, d.submitters \
             FROM lapi_events_various_witnessed d JOIN par_contracts c ON c.contract_id = d.contract_id \
             WHERE d.event_type = 5 AND NOT d.consuming",
            &[],
        )
        .map_err(|e| e.to_string())?;
    for (kind, rows) in [(0, creations), (1, archivals), (2, witnessed)] {
        for r in rows {
            let sequential: i64 = r.get(0);
            let offset: i64 = r.get(1);
            let trace: Option<Vec<u8>> = r.get(7);
            let submitters = match r.get::<_, Option<Vec<u8>>>(if kind == 0 { 15 } else { 21 }) {
                Some(bytes) if !bytes.is_empty() => party_list(&bytes, &interned)?,
                _ => Vec::new(),
            };
            let update = updates.entry(offset).or_insert_with(|| OfficialUpdate {
                offset,
                update_id: r.get(2),
                workflow_id: r.get::<_, Option<String>>(3).unwrap_or_default(),
                command_id: r.get::<_, Option<String>>(4).unwrap_or_default(),
                record_time_micros: r.get(5),
                synchronizer: name(r.get(6)),
                trace_parent: trace.as_deref().and_then(trace_parent_of),
                external_transaction_hash: r.get::<_, Option<String>>(8).filter(|h| !h.is_empty()),
                traffic_cost: r.get::<_, Option<i64>>(10).unwrap_or(0),
                submitters,
                events: Vec::new(),
            });
            let mut stakeholders = witnesses.get(&sequential).cloned().unwrap_or_default();
            stakeholders.sort();
            let additional = match r.get::<_, Option<Vec<u8>>>(if kind == 0 { 14 } else { 20 }) {
                Some(bytes) if !bytes.is_empty() => party_list(&bytes, &interned)?,
                _ => Vec::new(),
            };
            // the additional witnesses are listed apart from the stakeholders
            stakeholders.retain(|p| !additional.contains(p));
            let exercise = if kind == 0 {
                None
            } else {
                Some(OfficialExercise {
                    consuming: kind == 1,
                    choice: name(r.get::<_, i32>(14)),
                    actors: party_list(&r.get::<_, Vec<u8>>(16), &interned)?,
                    last_descendant: r.get(17),
                    argument: r.get(18),
                    result: r.get(19),
                })
            };
            update.events.push(OfficialEvent {
                exercise,
                node_id: r.get(9),
                contract_id: r.get(11),
                package_id: r.get(12),
                instance: r.get(13),
                stakeholders,
                additional,
                effective_micros: (kind != 0).then(|| r.get::<_, i64>(15)),
            });
        }
    }
    let mut updates: Vec<OfficialUpdate> = updates.into_values().collect();
    for u in &mut updates {
        u.events.sort_by_key(|e| e.node_id);
    }
    Ok(updates)
}

/// A command completion of the participant's history (`lapi_command_completions`).
#[derive(Debug, Clone)]
pub struct OfficialCompletion {
    pub offset: i64,
    pub record_time_micros: i64,
    pub user_id: String,
    /// The parties the command acted as.
    pub submitters: Vec<String>,
    pub command_id: String,
    /// Hex of the update id (`None` for a rejection).
    pub update_id: Option<String>,
    pub submission_id: String,
    /// The deduplication offset of the command, or its duration `(seconds, nanos)` (one of the two is set).
    pub dedup_offset: Option<i64>,
    pub dedup_duration: Option<(i64, i32)>,
    /// The status of a rejection: its code, message and the `google.rpc.Status` details as protobuf bytes.
    pub rejection: Option<(i32, String, Vec<u8>)>,
    pub synchronizer: String,
    pub trace_parent: Option<String>,
    pub traffic_cost: i64,
    /// The hash of an externally signed transaction.
    pub transaction_hash: Option<Vec<u8>>,
}

/// The parties of a stored list of party numbers: a format byte (1), then each number as four bytes (big endian).
///
/// [CANTON-NOTE: SEMANTICS] Measured on the hub's participant: `01 00000004` is one party, `01 00000004 0000000b` two; the first byte is not a count.
fn party_list(bytes: &[u8], interned: &BTreeMap<i32, String>) -> Result<Vec<String>, String> {
    match bytes.split_first() {
        Some((1, rest)) if rest.len() % 4 == 0 => Ok(rest
            .chunks(4)
            .map(|c| {
                interned
                    .get(&i32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .cloned()
                    .unwrap_or_default()
            })
            .collect()),
        _ => Err("a list of submitters of an unknown layout".into()),
    }
}

/// Reads the command completions of the participant in the order of their offsets, with the record time of each synchronizer at the ledger end
/// (`lapi_ledger_end_synchronizer_index`: what the Ledger API reports as the time of an `OffsetCheckpoint`).
#[allow(
    clippy::type_complexity,
    reason = "protocol or ledger hook signature uses an inline composite type"
)]
pub fn read_completions(
    client: &mut Client,
) -> Result<(Vec<OfficialCompletion>, Vec<(String, i64)>), String> {
    let interned = interning(client)?;
    let rows = client
        .query(
            "SELECT completion_offset, record_time, user_id, submitters, command_id, encode(update_id, 'hex'), submission_id, \
                    deduplication_offset, deduplication_duration_seconds, deduplication_duration_nanos, rejection_status_code, \
                    rejection_status_message, rejection_status_details, synchronizer_id, trace_context, traffic_cost, transaction_hash \
             FROM lapi_command_completions ORDER BY completion_offset",
            &[],
        )
        .map_err(|e| e.to_string())?;
    let mut completions = Vec::new();
    for r in rows {
        let trace: Option<Vec<u8>> = r.get(14);
        let code: Option<i32> = r.get(10);
        let seconds: Option<i64> = r.get(8);
        completions.push(OfficialCompletion {
            offset: r.get(0),
            record_time_micros: r.get(1),
            user_id: interned
                .get(&r.get::<_, i32>(2))
                .cloned()
                .unwrap_or_default(),
            submitters: party_list(&r.get::<_, Vec<u8>>(3), &interned)?,
            command_id: r.get::<_, Option<String>>(4).unwrap_or_default(),
            update_id: r.get::<_, Option<String>>(5).filter(|u| !u.is_empty()),
            submission_id: r.get::<_, Option<String>>(6).unwrap_or_default(),
            dedup_offset: r.get(7),
            dedup_duration: seconds.map(|s| (s, r.get::<_, Option<i32>>(9).unwrap_or(0))),
            rejection: code.map(|c| {
                (
                    c,
                    r.get::<_, Option<String>>(11).unwrap_or_default(),
                    r.get::<_, Option<Vec<u8>>>(12).unwrap_or_default(),
                )
            }),
            synchronizer: interned
                .get(&r.get::<_, i32>(13))
                .cloned()
                .unwrap_or_default(),
            trace_parent: trace.as_deref().and_then(trace_parent_of),
            traffic_cost: r.get::<_, Option<i64>>(15).unwrap_or(0),
            transaction_hash: r.get(16),
        });
    }
    let times = client
        .query(
            "SELECT synchronizer_id, sequencer_timestamp FROM lapi_ledger_end_synchronizer_index",
            &[],
        )
        .map_err(|e| e.to_string())?
        .iter()
        .map(|r| {
            (
                interned
                    .get(&r.get::<_, i32>(0))
                    .cloned()
                    .unwrap_or_default(),
                r.get::<_, i64>(1),
            )
        })
        .collect();
    Ok((completions, times))
}

/// Unwrapped node signing keys (Ed25519) read from `common_node_id` + `common_crypto_private_keys` of an official sequencer/mediator DB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficialNodeKeys {
    pub name: String,
    pub namespace_fingerprint: String,
    pub namespace_seed: [u8; 32],
    pub signing_seed: [u8; 32],
    pub sequencer_auth_seed: [u8; 32],
}

impl OfficialNodeKeys {
    /// `<name>::<namespace_fingerprint>`.
    pub fn uid(&self) -> String {
        format!("{}::{}", self.name, self.namespace_fingerprint)
    }
}

/// Official synchronizer identity, static/dynamic topology state, and clock floor read from an official sequencer DB (`U-49`).
#[derive(Debug, Clone)]
pub struct OfficialSynchronizer {
    pub keys: OfficialNodeKeys,
    pub synchronizer_name: String,
    pub synchronizer_namespace: String,
    pub synchronizer_uid: String,
    pub physical_synchronizer_id: String,
    pub serial: u32,
    /// Active rows from `common_topology_transactions`: `(sequenced_micros, valid_from_micros, stored_bytes)`.
    pub topology_transactions: Vec<(i64, i64, Vec<u8>)>,
    pub clock_floor_micros: i64,
}

/// Versioned key wrapper stored in `common_crypto_private_keys.data` (`UntypedVersionedMessage`).
#[derive(Clone, PartialEq, prost::Message)]
struct StoredVersionedKey {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
    #[prost(int32, tag = "2")]
    version: i32,
}

const ED25519_PKCS8_HEADER: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

fn query_unwrapped_keys(
    client: &mut Client,
    prefix: &str,
) -> Result<Vec<(String, String, Vec<u8>)>, String> {
    use prost::Message;
    let rows = client
        .query(
            "SELECT name, key_id, wrapper_key_id, data FROM common_crypto_private_keys WHERE name LIKE $1",
            &[&format!("{prefix}-%")],
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let name: Option<String> = row.get(0);
        let Some(full_name) = name else {
            continue;
        };
        if row.get::<_, Option<String>>(2).is_some() {
            return Err(format!(
                "the key {full_name} is wrapped (encrypted): not read"
            ));
        }
        let wrapper = StoredVersionedKey::decode(row.get::<_, Vec<u8>>(3).as_slice())
            .map_err(|e| format!("the key {full_name} is not a versioned message: {e}"))?;
        out.push((full_name, row.get::<_, String>(1), wrapper.data));
    }
    Ok(out)
}

fn ed25519_seed_of(
    decoded: &[(String, String, Vec<u8>)],
    prefix: &str,
    suffix: &str,
) -> Result<([u8; 32], String), String> {
    use canton_proto::com::digitalasset::canton::crypto::v30 as crypto;
    use prost::Message;
    let wanted = format!("{prefix}-{suffix}");
    let (_, key_id, bytes) = decoded
        .iter()
        .find(|(n, _, _)| n == &wanted)
        .ok_or_else(|| format!("the database has no key named {wanted}"))?;
    let k = crypto::SigningPrivateKey::decode(bytes.as_slice())
        .map_err(|e| format!("the key {wanted} is not a signing key: {e}"))?;
    let der = k.private_key;
    if der.len() != 48 || der[..16] != ED25519_PKCS8_HEADER {
        return Err(format!("the key {wanted} is not an Ed25519 PKCS#8 key"));
    }
    Ok((der[16..].try_into().expect("32 bytes"), key_id.clone()))
}

fn parse_physical_synchronizer_id(psid: &str) -> Result<(String, String, u32), String> {
    let mut parts = psid.splitn(3, "::");
    let name = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("invalid physical_synchronizer_id {psid:?}: missing name"))?;
    let namespace = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("invalid physical_synchronizer_id {psid:?}: missing namespace"))?;
    let suffix = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("invalid physical_synchronizer_id {psid:?}: missing serial"))?;
    let serial_str = suffix.rsplit('-').next().unwrap_or(suffix);
    let serial = serial_str
        .parse::<u32>()
        .map_err(|e| format!("invalid serial in physical_synchronizer_id {psid:?}: {e}"))?;
    Ok((name.to_string(), namespace.to_string(), serial))
}

fn table_has_rows(
    client: &mut Client,
    table: &str,
    condition: Option<&str>,
) -> Result<bool, String> {
    let exists: bool = client
        .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
        .map_err(|e| e.to_string())?
        .get(0);
    if !exists {
        return Ok(false);
    }
    let sql = match condition {
        Some(cond) => format!("SELECT EXISTS (SELECT 1 FROM {table} WHERE {cond})"),
        None => format!("SELECT EXISTS (SELECT 1 FROM {table})"),
    };
    Ok(client
        .query_one(&sql, &[])
        .map_err(|e| e.to_string())?
        .get(0))
}

/// Returns `true` when `client` points at a database populated by an official Canton sequencer.
pub fn has_official_sequencer(client: &mut Client) -> Result<bool, String> {
    if !table_has_rows(client, "common_node_id", None)? {
        return Ok(false);
    }
    table_has_rows(
        client,
        "sequencer_synchronizer_configuration",
        Some("physical_synchronizer_id IS NOT NULL"),
    )
}

/// Returns `true` when `client` points at a database populated with an official Canton mediator identity.
pub fn has_official_mediator(client: &mut Client) -> Result<bool, String> {
    let has_keys_tbl: bool = client
        .query_one(
            "SELECT to_regclass('common_crypto_private_keys') IS NOT NULL",
            &[],
        )
        .map_err(|e| e.to_string())?
        .get(0);
    if !has_keys_tbl {
        return Ok(false);
    }
    table_has_rows(client, "common_node_id", None)
}

/// Reads an official sequencer or mediator node's unwrapped Ed25519 keys (`namespace`, `signing`, `sequencer-auth`).
pub fn read_node_keys(
    client: &mut Client,
    node_hint: Option<&str>,
) -> Result<OfficialNodeKeys, String> {
    let chosen: Option<(String, String)> = match node_hint {
        Some(hint) => client
            .query_opt(
                "SELECT identifier, namespace FROM common_node_id WHERE identifier = $1 LIMIT 1",
                &[&hint],
            )
            .map_err(|e| e.to_string())?
            .map(|r| (r.get(0), r.get(1))),
        None => None,
    };
    let (name, db_namespace) = match chosen {
        Some(pair) => pair,
        None => {
            let rows = client
                .query(
                    "SELECT identifier, namespace FROM common_node_id LIMIT 2",
                    &[],
                )
                .map_err(|e| e.to_string())?;
            match rows.as_slice() {
                [r] => (r.get(0), r.get(1)),
                [] => {
                    return Err(
                        "common_node_id has no row: database never ran an official node".into(),
                    )
                }
                _ => {
                    return Err(format!(
                        "common_node_id has multiple rows and none matched hint {:?}",
                        node_hint.unwrap_or("")
                    ))
                }
            }
        }
    };
    let decoded = query_unwrapped_keys(client, &name)?;
    let (namespace_seed, namespace_key_id) = ed25519_seed_of(&decoded, &name, "namespace")?;
    let (signing_seed, _) = ed25519_seed_of(&decoded, &name, "signing")?;
    let (sequencer_auth_seed, _) = ed25519_seed_of(&decoded, &name, "sequencer-auth")?;
    let computed_fp = crate::topology_wire::Ed25519Key::from_seed(namespace_seed).fingerprint;
    if computed_fp != db_namespace || computed_fp != namespace_key_id {
        return Err(
            "the namespace key read does not match the fingerprint in common_node_id / common_crypto_private_keys".into(),
        );
    }
    Ok(OfficialNodeKeys {
        name,
        namespace_fingerprint: computed_fp,
        namespace_seed,
        signing_seed,
        sequencer_auth_seed,
    })
}

/// Formats an official mediator DB's identity in `MediatorIdentity::to_text` layout (`<name>\n<ns>\n<signing>\n<auth>\n`).
pub fn read_mediator_identity_text(
    client: &mut Client,
    mediator_hint: Option<&str>,
) -> Result<String, String> {
    let keys = read_node_keys(client, mediator_hint)?;
    Ok(format!(
        "{}\n{}\n{}\n{}\n",
        keys.name,
        hex::encode(keys.namespace_seed),
        hex::encode(keys.signing_seed),
        hex::encode(keys.sequencer_auth_seed),
    ))
}

/// Reads synchronizer identity, active topology transactions, and sequencing clock floor from an official sequencer DB.
pub fn read_official_synchronizer(
    client: &mut Client,
    sequencer_hint: Option<&str>,
) -> Result<OfficialSynchronizer, String> {
    let keys = read_node_keys(client, sequencer_hint)?;
    let psid_row = client
        .query_opt(
            "SELECT physical_synchronizer_id FROM sequencer_synchronizer_configuration \
             WHERE physical_synchronizer_id IS NOT NULL LIMIT 1",
            &[],
        )
        .map_err(|e| e.to_string())?
        .ok_or("sequencer_synchronizer_configuration has no physical_synchronizer_id")?;
    let physical_synchronizer_id: String = psid_row.get(0);
    let (synchronizer_name, synchronizer_namespace, serial) =
        parse_physical_synchronizer_id(&physical_synchronizer_id)?;
    let synchronizer_uid = format!("{synchronizer_name}::{synchronizer_namespace}");

    // Prefer the static string ID that actually owns rows in `common_topology_transactions`
    // (Canton records both store-alias and synchronizer-uid entries in `common_static_strings`).
    let store_id: i32 = client
        .query_opt(
            "SELECT s.id FROM common_static_strings s \
             WHERE s.string IN ($1, $2) \
               AND EXISTS (SELECT 1 FROM common_topology_transactions t WHERE t.store_id = s.id) \
             ORDER BY (s.string = $1) DESC, s.id ASC LIMIT 1",
            &[&physical_synchronizer_id, &synchronizer_uid],
        )
        .map_err(|e| e.to_string())?
        .map(|r| r.get(0))
        .or_else(|| {
            client
                .query_opt(
                    "SELECT id FROM common_static_strings WHERE string IN ($1, $2) ORDER BY id ASC LIMIT 1",
                    &[&physical_synchronizer_id, &synchronizer_uid],
                )
                .ok()
                .flatten()
                .map(|r| r.get(0))
        })
        .ok_or_else(|| {
            format!("common_static_strings has no store id for {physical_synchronizer_id}")
        })?;

    let topo_rows = client
        .query(
            "SELECT sequenced, valid_from, instance FROM common_topology_transactions \
             WHERE store_id = $1 AND valid_until IS NULL AND is_proposal = false AND rejection_reason IS NULL \
             ORDER BY id",
            &[&store_id],
        )
        .map_err(|e| e.to_string())?;
    let topology_transactions: Vec<(i64, i64, Vec<u8>)> = topo_rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();

    let mut clock_floor_micros = topology_transactions
        .iter()
        .flat_map(|(seq, vf, _)| [*seq, *vf])
        .max()
        .unwrap_or(0);
    for (tbl, expr) in [
        ("sequencer_watermarks", "MAX(watermark_ts)"),
        ("seq_block_height", "MAX(latest_event_ts)"),
        ("ord_metadata_output_blocks", "MAX(bft_ts)"),
    ] {
        let has_tbl: bool = client
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[&tbl])
            .map_err(|e| e.to_string())?
            .get(0);
        if has_tbl {
            let val: Option<i64> = client
                .query_one(&format!("SELECT {expr} FROM {tbl}"), &[])
                .map_err(|e| e.to_string())?
                .get(0);
            if let Some(v) = val {
                clock_floor_micros = clock_floor_micros.max(v);
            }
        }
    }

    Ok(OfficialSynchronizer {
        keys,
        synchronizer_name,
        synchronizer_namespace,
        synchronizer_uid,
        physical_synchronizer_id,
        serial,
        topology_transactions,
        clock_floor_micros,
    })
}

/// The identity of an official participant, as `ParticipantIdentity::to_text` writes it, from the private keys its database keeps
/// (`common_crypto_private_keys`: the keys named `<participant>-namespace`, `-signing`, `-sequencer-auth` and `-encryption`). A node started on this
/// identity has the participant's namespace, so the parties it hosts are the official participant's parties (`Issuer::<namespace>`) and it signs the topology
/// that hosts them with the namespace key the official participant used.
///
/// [CANTON-NOTE: SEMANTICS] Measured on the hub's participant: four keys, each a `crypto.v30.PrivateKey` whose `private_key` is a PKCS#8 DER (Ed25519: a 16-byte
/// header and the 32-byte seed; the encryption key a P-256 key) and none wrapped (`wrapper_key_id` empty: no KMS, no encryption of the keys at rest). A wrapped
/// key is refused. The decoded namespace key must have the fingerprint the database names it by (its `key_id`): a decoding that is wrong never gives an
/// identity. The keys are read, never printed.
pub fn read_identity_text(client: &mut Client, participant: &str) -> Result<String, String> {
    use canton_proto::com::digitalasset::canton::crypto::v30 as crypto;
    use p256::pkcs8::DecodePrivateKey;
    use prost::Message;
    let decoded = query_unwrapped_keys(client, participant)?;
    let (namespace, namespace_id) = ed25519_seed_of(&decoded, participant, "namespace")?;
    let (signing, _) = ed25519_seed_of(&decoded, participant, "signing")?;
    let (sequencer_auth, _) = ed25519_seed_of(&decoded, participant, "sequencer-auth")?;
    let wanted_enc = format!("{participant}-encryption");
    let (_, _, encryption) = decoded
        .iter()
        .find(|(n, _, _)| n == &wanted_enc)
        .ok_or_else(|| format!("the database has no key named {wanted_enc}"))?;
    let e = crypto::EncryptionPrivateKey::decode(encryption.as_slice())
        .map_err(|e| format!("the key {participant}-encryption is not an encryption key: {e}"))?;
    let encryption_secret = p256::SecretKey::from_pkcs8_der(&e.private_key)
        .map_err(|err| {
            format!("the key {participant}-encryption is not a P-256 PKCS#8 key: {err}")
        })?
        .to_bytes();
    let mut text = format!("{participant}\n");
    for seed in [
        namespace.as_slice(),
        &signing,
        &sequencer_auth,
        encryption_secret.as_slice(),
    ] {
        text.push_str(&hex::encode(seed));
        text.push('\n');
    }
    let identity = crate::topology_wire::ParticipantIdentity::from_text(&text)
        .ok_or("the keys do not make an identity")?;
    if identity.namespace() != namespace_id {
        return Err(
            "the namespace key read does not have the fingerprint the database names it by".into(),
        );
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::{parse_physical_synchronizer_id, trace_parent_of};

    #[test]
    fn the_traceparent_of_a_stored_trace_context_is_read() {
        // the bytes the hub's participant stored for the first update (`lapi_events_activate_contract.trace_context`)
        let bytes = hex::decode(
            "0a3730302d66313861623261346461356337646339393230343635666462333063343233362d656539636265356436616265333831662d3033",
        )
        .unwrap();
        assert_eq!(
            trace_parent_of(&bytes).as_deref(),
            Some("00-f18ab2a4da5c7dc9920465fdb30c4236-ee9cbe5d6abe381f-03")
        );
        assert_eq!(trace_parent_of(&[]), None);
        assert_eq!(trace_parent_of(&[0x12, 0x01, b'x']), None);
        // a length that runs past the end
        assert_eq!(trace_parent_of(&[0x0a, 0x09, b'x']), None);
    }

    #[test]
    fn physical_synchronizer_id_is_parsed_into_uid_and_serial() {
        let (name, ns, serial) = parse_physical_synchronizer_id(
            "hub-sync::12204e8bfbed3eeab0b83c01cd54e16f1080f7d81cac124a28fd7ca260306e47f64b::37-2",
        )
        .expect("valid psid");
        assert_eq!(name, "hub-sync");
        assert_eq!(
            ns,
            "12204e8bfbed3eeab0b83c01cd54e16f1080f7d81cac124a28fd7ca260306e47f64b"
        );
        assert_eq!(serial, 2);
        assert!(parse_physical_synchronizer_id("missing-serial::1220abc").is_err());
        assert!(parse_physical_synchronizer_id("::1220abc::37-0").is_err());
    }
}
