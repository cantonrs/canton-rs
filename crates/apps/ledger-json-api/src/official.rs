//! Starting on an official participant's database and configuration, shared by `json-api` and `ledger-api` (U-47).
use std::sync::Arc;

use crate::service::ExecutionService;

/// Makes the parties, users, identity providers, DARs, active contracts and ledger end of the official participant database `target` the state of
/// `service`, reading it only (the connection cannot write). Prints what it took.
/// What the participant that serves the API needs of an official database to exercise its contracts: its DARs and the instances of its active contracts.
pub struct Adopted {
    pub dars: Vec<Vec<u8>>,
    pub instances: Vec<(String, Vec<u8>)>,
}

/// Checks whether `target` holds official Canton participant schema tables (`lapi_parameters`, `lapi_users`, `common_static_strings`).
/// Returns connection/TLS/auth errors rather than ignoring unreachable databases.
pub fn has_official_schema(target: &canton_participant::pgconn::PgTarget) -> Result<bool, String> {
    let mut client = canton_participant::pgconn::connect(target)
        .map_err(|e| format!("Cannot connect to the official database: {e}"))?;
    client
        .batch_execute("SET default_transaction_read_only = on")
        .map_err(|e| e.to_string())?;
    canton_participant::official_state::has_official_schema(&mut client)
}

/// Checks whether `target` already contains official Canton participant tables (`lapi_parameters` populated).
/// Returns connection/TLS/auth errors rather than ignoring unreachable databases.
pub fn has_official_database(
    target: &canton_participant::pgconn::PgTarget,
) -> Result<bool, String> {
    let mut client = canton_participant::pgconn::connect(target)
        .map_err(|e| format!("Cannot connect to the official database: {e}"))?;
    client
        .batch_execute("SET default_transaction_read_only = on")
        .map_err(|e| e.to_string())?;
    canton_participant::official_state::has_official_participant(&mut client)
}

pub fn adopt_official_database(
    service: &Arc<ExecutionService>,
    target: &canton_participant::pgconn::PgTarget,
) -> Result<Adopted, String> {
    let mut client = canton_participant::pgconn::connect(target)
        .map_err(|e| format!("Cannot connect to the official database: {e}"))?;
    // read-only: a transaction that cannot write, whatever the code below does
    client
        .batch_execute("SET default_transaction_read_only = on")
        .map_err(|e| e.to_string())?;
    let official = canton_participant::official_state::read_parties(&mut client)
        .map_err(|e| format!("Cannot read the parties of the official database: {e}"))?;
    let parties: Vec<(String, bool)> = official
        .parties
        .iter()
        .map(|p| (p.party.clone(), p.is_local))
        .collect();
    let records: Vec<_> = official
        .records
        .iter()
        .map(|r| {
            (
                r.party.clone(),
                r.resource_version.max(0) as u64,
                r.annotations.clone(),
                r.identity_provider_id.clone(),
            )
        })
        .collect();
    service.adopt_official_parties(&official.participant_uid, &parties, &records);
    let users: Vec<_> = canton_participant::official_state::read_users(&mut client)
        .map_err(|e| format!("Cannot read the users of the official database: {e}"))?
        .into_iter()
        .map(|u| {
            (
                u.id,
                u.primary_party,
                u.deactivated,
                u.resource_version.max(0) as u64,
                u.identity_provider_id,
                u.annotations,
                u.rights,
            )
        })
        .collect();
    let idps: Vec<_> = canton_participant::official_state::read_idps(&mut client)
        .map_err(|e| format!("Cannot read the identity providers of the official database: {e}"))?
        .into_iter()
        .map(|i| (i.id, i.issuer, i.jwks_url, i.audience, i.deactivated))
        .collect();
    service.adopt_official_users_and_idps(&users, &idps);
    let dars = canton_participant::official_state::read_dars(&mut client)
        .map_err(|e| format!("Cannot read the DARs of the official database: {e}"))?;
    for dar in &dars {
        let info = crate::v2_commands::load_dar_bytes(service, &dar.data).map_err(|e| {
            format!(
                "Cannot load the DAR {} of the official database: {e}",
                dar.name
            )
        })?;
        crate::v2_packages::adopt_dar_packages(service, &info, &dar.data);
    }
    let (ledger_end, contracts) =
        canton_participant::official_state::read_active_contracts(&mut client).map_err(|e| {
            format!("Cannot read the active contracts of the official database: {e}")
        })?;
    let instances: Vec<(String, Vec<u8>)> = contracts
        .iter()
        .map(|c| (c.contract_id.clone(), c.instance.clone()))
        .collect();
    let (shown, skipped) = crate::protocol::show_official_contracts_in(
        service,
        &dars.iter().map(|d| d.data.clone()).collect::<Vec<_>>(),
        &instances,
    )
    .map_err(|e| format!("Cannot show the active contracts of the official database: {e}"))?;
    let history = canton_participant::official_state::read_updates(&mut client)
        .map_err(|e| format!("Cannot read the updates of the official database: {e}"))?;
    let (updates_shown, updates_skipped) = crate::protocol::official_updates_in(
        service,
        &dars.iter().map(|d| d.data.clone()).collect::<Vec<_>>(),
        &history,
    )
    .map_err(|e| format!("Cannot show the updates of the official database: {e}"))?;
    for (offset, why) in updates_skipped.iter().take(3) {
        crate::diag::diag_eprintln!(
            " Official database: the update at offset {offset} is not shown: {why}"
        );
    }
    crate::diag::diag_println!(
        " Official database: {updates_shown} updates shown, {} skipped",
        updates_skipped.len()
    );
    let (history_completions, synchronizer_times) =
        canton_participant::official_state::read_completions(&mut client).map_err(|e| {
            format!("Cannot read the command completions of the official database: {e}")
        })?;
    let (completions_shown, completions_skipped) =
        show_completions(service, &history_completions, &synchronizer_times);
    for (offset, why) in completions_skipped.iter().take(3) {
        crate::diag::diag_eprintln!(
            " Official database: the completion at offset {offset} is not shown: {why}"
        );
    }
    crate::diag::diag_println!(
        " Official database: {completions_shown} command completions shown, {} skipped",
        completions_skipped.len()
    );
    for c in &contracts {
        service.note_created_offset(
            &c.contract_id,
            c.offset.max(0) as u64,
            c.node_id.max(0) as u64,
            &c.synchronizer,
        );
    }
    service.adopt_official_ledger_end(ledger_end.unwrap_or(0).max(0) as u64);
    for (id, why) in skipped.iter().take(3) {
        crate::diag::diag_eprintln!(
            " Official database: contract {}… not shown: {why}",
            &id[..id.len().min(16)]
        );
    }
    crate::diag::diag_println!(
        " Official database: {shown} active contracts shown, {} skipped, ledger end {}",
        skipped.len(),
        ledger_end.unwrap_or(0)
    );
    let package_ids = canton_participant::official_state::read_package_ids(&mut client)
        .map_err(|e| format!("Cannot read the packages of the official database: {e}"))?;
    service.note_known_packages(&package_ids);
    crate::diag::diag_println!(
        " Official database: {} parties of participant {}, {} users, {} identity providers, {} DARs",
        parties.len(),
        official.participant_uid,
        users.len(),
        idps.len(),
        dars.len()
    );
    Ok(Adopted {
        dars: dars.iter().map(|d| d.data.clone()).collect(),
        instances,
    })
}

/// Shows the command completions of the official history (`official_state::read_completions`) as the completions of `service`: the user, the parties the
/// command acted as, the ids, the status with its decoded details, the deduplication period, the trace context and the record time the participant
/// recorded. Returns how many were shown and, for each that could not be, its offset and why.
///
/// [CANTON-NOTE: LIMITATION] A completion whose deduplication period is a duration is not shown: the JSON of that variant was not measured (the hub's
/// participant has none).
fn show_completions(
    service: &ExecutionService,
    completions: &[canton_participant::official_state::OfficialCompletion],
    times: &[(String, i64)],
) -> (usize, Vec<(i64, String)>) {
    let (mut adopted, mut skipped) = (Vec::new(), Vec::new());
    for c in completions {
        let Some(dedup) = c.dedup_offset else {
            skipped.push((
                c.offset,
                "deduplication by duration is not read".to_string(),
            ));
            continue;
        };
        let details = match &c.rejection {
            Some((_, _, bytes)) if !bytes.is_empty() => {
                match crate::status_details::status_details(bytes) {
                    Ok(d) => d,
                    Err(why) => {
                        skipped.push((c.offset, why));
                        continue;
                    }
                }
            }
            _ => Vec::new(),
        };
        adopted.push(crate::v2_completions::Completion {
            offset: c.offset.max(0) as u64,
            update_id: c.update_id.clone().unwrap_or_default(),
            command_id: c.command_id.clone(),
            user_id: c.user_id.clone(),
            submission_id: c.submission_id.clone(),
            act_as: c.submitters.clone(),
            record_time: crate::v2_commands::rfc3339_from_micros(c.record_time_micros),
            transaction_hash: c.transaction_hash.as_deref().map(crate::v2::base64),
            status_code: c.rejection.as_ref().map_or(0, |(code, _, _)| *code),
            status_message: c
                .rejection
                .as_ref()
                .map(|(_, message, _)| message.clone())
                .unwrap_or_default(),
            refusal: None,
            official: Some(Box::new(crate::v2_completions::OfficialCompletionMeta {
                deduplication_period: serde_json::json!({ "DeduplicationOffset": { "value": dedup } }),
                trace_parent: c.trace_parent.clone(),
                synchronizer_id: c.synchronizer.clone(),
                traffic_cost: c.traffic_cost,
                details,
            })),
            trace_parent: None,
        });
    }
    let shown = adopted.len();
    let checkpoint = times
        .iter()
        .map(|(id, micros)| (id.clone(), crate::v2_commands::rfc3339_from_micros(*micros)))
        .collect();
    service.adopt_official_completions(adopted, checkpoint);
    (shown, skipped)
}

/// Writes what the Ledger API's administration changes to the official tables of the database the service started from (`--official-write`): the users with their
/// rights and annotations, the party records with their annotations, the identity providers, and the DARs with their packages. After this the database holds
/// them as the official participant keeps them, so the official participant (or a Rust one started on the database) finds them again.
///
/// [CANTON-NOTE: SEMANTICS] The tables written are `lapi_users`, `lapi_user_rights`, `lapi_user_annotations`, `lapi_party_records`,
/// `lapi_party_record_annotations`, `lapi_identity_provider_config`, `par_dars` and `par_daml_packages` (measured on the hub's participant: the layout of the
/// rows and the right codes). Every change rewrites the administration state in one transaction, keeping the internal id of a user or a party record that is
/// still there. The transactions, contracts and topology the official participant keeps (`lapi_events_*`, `par_contracts`, `common_topology_transactions`)
/// are **not** written: a party the Rust participant hosts has a record but no topology mapping of the official participant, and a contract it creates is in
/// its own state, not in `par_contracts`.
pub fn enable_official_writes(
    service: &Arc<ExecutionService>,
    target: &canton_participant::pgconn::PgTarget,
    topology_peers: &[canton_participant::pgconn::PgTarget],
) -> Result<Option<String>, String> {
    let mut client = canton_participant::pgconn::connect(target)
        .map_err(|e| format!("Cannot connect to the official database to write to it: {e}"))?;
    // the tables of an official participant must be there: a database of another system is not written to
    client
        .query_one("SELECT count(*) FROM lapi_users", &[])
        .map_err(|e| format!("The official database has no lapi_users table to write to: {e}"))?;
    let state = service.v2_state();
    ensure_official_bootstrap_rows(
        &mut client,
        &state.participant_id(),
        &state.synchronizer_id(),
        &state.official_admin_rows(),
    )?;
    if client
        .query_opt("SELECT 1 FROM par_dars LIMIT 1", &[])
        .map_err(pg_error)?
        .is_none()
    {
        let blobs = service
            .dar_blobs
            .read()
            .map(|b| b.clone())
            .unwrap_or_default();
        for dar in &blobs {
            write_dar(&mut client, dar)?;
        }
    }
    let client = Arc::new(std::sync::Mutex::new(client));
    let admin_client = Arc::clone(&client);
    let admin_client_for_sync = Arc::clone(&client);
    if let Ok(mut sink) = state.official_admin_sink.lock() {
        *sink = Some(Arc::new(move |rows: &crate::v2::OfficialAdminRows| {
            if let Ok(mut c) = admin_client.lock() {
                if let Err(e) = write_admin(&mut c, rows) {
                    crate::diag::diag_eprintln!(
                        "The administration state is not written to the official database: {e}"
                    );
                }
            }
        }));
    }
    if let Ok(mut sink) = state.official_dar_sink.lock() {
        let dar_service = Arc::downgrade(service);
        *sink = Some(Arc::new(move |dar: &[u8]| {
            if let Ok(mut c) = client.lock() {
                if let Err(e) = write_dar(&mut c, dar) {
                    crate::diag::diag_eprintln!(
                        "The DAR is not written to the official database: {e}"
                    );
                }
                if let Some(service) = dar_service.upgrade() {
                    if let Err(e) = write_vetting(&service, &mut c, dar) {
                        crate::diag::diag_eprintln!("The DAR's packages are not vetted in the official database's topology store: {e}");
                    }
                }
            }
        }));
    }
    // the topology transaction of each party this participant starts to host (U-50): the official participant lists a party its topology store has
    let topology_client = canton_participant::pgconn::connect(target)
        .map_err(|e| format!("Cannot connect to the official database to write to it: {e}"))?;
    let topology_client = Arc::new(std::sync::Mutex::new(topology_client));
    // [CANTON-NOTE: SEMANTICS] The requests of the official participant are judged by the synchronizer's topology too: the mediator refuses a request with
    // "informees not being hosted by an active participant" when its own store does not know the party. The topology of the synchronizer is in the stores of the
    // synchronizer's sequencer and mediator as well, so a party is written there as well.
    let peer_clients = topology_peers
        .iter()
        .map(|t| {
            canton_participant::pgconn::connect(t)
                .map_err(|e| format!("Cannot connect to a topology store to write to it: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let peer_clients = Arc::new(std::sync::Mutex::new(peer_clients));
    let topology_service = Arc::downgrade(service);
    if let Ok(mut sink) = state.official_topology_sink.lock() {
        *sink = Some(Arc::new(move |hosted: &crate::service::HostedParty| {
            let (Some(service), Ok(mut c)) = (topology_service.upgrade(), topology_client.lock())
            else {
                return;
            };
            {
                // the topology store first, then the update the official participant lists the party from; a party already there is not written twice
                let result =
                    write_party_topology(&mut c, hosted).and_then(|(written, record_time)| {
                        if !written {
                            return Ok(());
                        }
                        // the offset this allocation takes in the API (see `POST /v2/parties`: it moves the ledger end by three)
                        let offset = service
                            .v2_state()
                            .ledger_end
                            .load(std::sync::atomic::Ordering::SeqCst)
                            as i64
                            + 1;
                        let participant = service.v2_state().participant_id();
                        crate::official_events::write_party_added(
                            &service,
                            &mut c,
                            &hosted.party,
                            &participant,
                            offset,
                            record_time,
                        )
                    });
                // the same party mapping in the stores of the synchronizer's other nodes
                if let (Ok(true), Ok(mut peers)) =
                    (result.as_ref().map(|_| true), peer_clients.lock())
                {
                    for p in peers.iter_mut() {
                        if let Err(e) = write_party_topology(p, hosted) {
                            crate::diag::diag_eprintln!(
                                "The party {} is not written to a synchronizer node's topology store: {e}",
                                hosted.party
                            );
                        }
                    }
                }
                match result {
                    Ok(()) => {}
                    Err(e) => crate::diag::diag_eprintln!(
                        "The party {} is not written to the official database's topology store: {e}",
                        hosted.party
                    ),
                }
            }
        }));
    }
    // the transactions and command completions
    let events_client = canton_participant::pgconn::connect(target)
        .map_err(|e| format!("Cannot connect to the official database to write to it: {e}"))?;
    let events_client = Arc::new(std::sync::Mutex::new(events_client));
    let weak = Arc::downgrade(service);
    let update_client = Arc::clone(&events_client);
    let update_service = std::sync::Weak::clone(&weak);
    let prune_client = Arc::clone(&events_client);
    if let Ok(mut sink) = state.official_update_sink.lock() {
        *sink = Some(Arc::new(move |u, completion| {
            let (Some(service), Ok(mut c)) = (update_service.upgrade(), update_client.lock())
            else {
                return;
            };
            if let Err(e) =
                crate::official_events::write_transaction(&service, &mut c, u, completion)
            {
                crate::diag::diag_eprintln!(
                    "The update at offset {} is not written to the official database: {e}",
                    u.offset
                );
            }
        }));
    }
    if let Ok(mut sink) = state.official_rejection_sink.lock() {
        *sink = Some(Arc::new(move |completion| {
            let (Some(service), Ok(mut c)) = (weak.upgrade(), events_client.lock()) else {
                return;
            };
            if let Err(e) = crate::official_events::write_rejection(&mut c, &service, completion) {
                crate::diag::diag_eprintln!(
                    "The refusal at offset {} is not written to the official database: {e}",
                    completion.offset
                );
            }
        }));
    }
    if let Ok(mut sink) = state.official_prune_sink.lock() {
        *sink = Some(Arc::new(move |offset| {
            let Ok(mut c) = prune_client.lock() else {
                return Err("official prune connection lock poisoned".to_string());
            };
            let prune_i64 =
                i64::try_from(offset).map_err(|_| format!("prune_up_to out of range: {offset}"))?;
            canton_participant::official_prune::prune_up_to(&mut c, prune_i64).map(|_| ())
        }));
    }
    crate::diag::diag_println!(
        " Official database: the administration state, uploaded DARs, transactions and command completions are written to its tables"
    );
    // [CANTON-NOTE: SEMANTICS] What the official participant knows as the synchronizer of its updates and contracts is the one in its string interning (`d|`): the
    // rows are only found again (a deactivation looks up the activation of its contract on the same synchronizer) when they name that one, so the Ledger API says
    // that synchronizer as well, whatever synchronizer the daemon's own protocol runs on.
    let official_synchronizer: Option<String> = {
        let mut c = admin_client_for_sync.lock().map_err(|e| e.to_string())?;
        c.query_opt(
            "SELECT external_string FROM lapi_string_interning WHERE external_string LIKE 'd|%' ORDER BY internal_id LIMIT 1",
            &[],
        )
        .map_err(pg_error)?
        .map(|r| r.get::<_, String>(0)["d|".len()..].to_string())
    };
    Ok(official_synchronizer)
}

/// Writes the `PartyToParticipant` transaction that made this participant host `hosted.party` to the topology store of the official participant's database, in
/// the row form of a 3.7.2 participant, so that the official participant lists the party (U-50). Returns whether it wrote (`false`: the store already holds the party's
/// mapping, as for a hub party hosted again at start-up) and the row's `valid_from`, the record time of the party's update.
///
/// [CANTON-NOTE: SEMANTICS] The row form (checked against the rows of the hub's own parties, byte for byte where deterministic): `transaction_type` 9,
/// `mapping_key_hash` = multi-hash of `Hash.build(TopologyMappingUniqueKey, Sha256).addString(<party>).addInt(9)`, `tx_hash` = the multi-hash of the transaction
/// under purpose `TopologyTransactionSignature` with no length prefix, `hash_of_signatures` = that purpose over `addByteString(<each signature, in a version
/// 30 wrapper>)` sorted by the signing key, `instance` = the stored signed transaction; `valid_from` is a quarter of a second after `sequenced`.
fn write_party_topology(
    client: &mut postgres::Client,
    hosted: &crate::service::HostedParty,
) -> Result<(bool, i64), String> {
    const PARTY_TO_PARTICIPANT: i32 = 9;
    let (identifier, namespace) = hosted
        .party
        .split_once("::")
        .ok_or("a party id without `::`")?;
    let (mapping_key_hash, tx_hash, hash_of_signatures) = party_topology_hashes(hosted)?;
    let store: i32 = client
        .query_opt(
            "SELECT store_id FROM common_topology_transactions WHERE transaction_type = $1 ORDER BY id DESC LIMIT 1",
            &[&PARTY_TO_PARTICIPANT],
        )
        .map_err(pg_error)?
        .map(|r| r.get(0))
        .or_else(|| {
            client
                .query_opt(
                    "SELECT id FROM common_static_strings WHERE source = 1 ORDER BY id LIMIT 1",
                    &[],
                )
                .ok()
                .flatten()
                .map(|r| r.get(0))
        })
        .ok_or("the topology store holds no party mapping or synchronizer string to take its store from")?;
    let present = client
        .query_opt(
            "SELECT 1 FROM common_topology_transactions WHERE store_id = $1 AND mapping_key_hash = $2 AND valid_until IS NULL",
            &[&store, &mapping_key_hash],
        )
        .map_err(pg_error)?;
    if present.is_some() {
        return Ok((false, 0));
    }
    // [CANTON-NOTE: SEMANTICS] Sequenced right after everything the store holds, not at the wall clock: the official participant sees a topology row as in
    // force only once the time it has observed from its synchronizer (the index's record time) has passed the row's effective time, and while the synchronizer
    // is quiet that time stands still. A row placed at the clock of the writer would lie in the future of the participant that reads the database later.
    let latest: Option<i64> = client
        .query_one(
            "SELECT max(greatest(sequenced, valid_from)) FROM common_topology_transactions WHERE store_id = $1",
            &[&store],
        )
        .map_err(pg_error)?
        .get(0);
    let sequenced = latest.unwrap_or(0) + 1;
    let valid_from = sequenced + 250_000;
    client
        .execute(
            "INSERT INTO common_topology_transactions (store_id, sequenced, transaction_type, namespace, identifier, mapping_key_hash, serial_counter, valid_from, \
             valid_until, operation, instance, tx_hash, rejection_reason, is_proposal, representative_protocol_version, hash_of_signatures, batch_idx) \
             VALUES ($1, $2, $3, $4, $5, $6, 1, $7, NULL, 1, $8, $9, NULL, false, 37, $10, 0)",
            &[
                &store,
                &sequenced,
                &PARTY_TO_PARTICIPANT,
                &namespace,
                &identifier,
                &mapping_key_hash,
                &valid_from,
                &hosted.stored,
                &tx_hash,
                &hash_of_signatures,
            ],
        )
        .map_err(pg_error)?;
    Ok((true, valid_from))
}

/// The three hashes of a party mapping's row: `(mapping_key_hash, tx_hash, hash_of_signatures)` (see [`write_party_topology`]).
fn party_topology_hashes(
    hosted: &crate::service::HostedParty,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    topology_hashes(&hosted.party, 9, &hosted.transaction, &hosted.signatures)
}

/// The hashes of a topology row: the unique key of the mapping (`Hash.build(TopologyMappingUniqueKey, Sha256).addString(<key>).addInt(<code>)`: the party's id
/// for a party mapping, the member string `PAR::<participant>` for the vetted packages), the transaction's hash (purpose `TopologyTransactionSignature`, no
/// length prefix) and the hash of its signatures (the same purpose over each signature in a version 30 wrapper, sorted by the signing key).
fn topology_hashes(
    unique_key: &str,
    code: i32,
    transaction: &[u8],
    signatures: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    use canton_participant::topology_wire::{transaction_hash, versioned};
    use prost::Message;
    const TOPOLOGY_MAPPING_UNIQUE_KEY: i32 = 43;
    const TOPOLOGY_TRANSACTION_SIGNATURE: i32 = 11;
    let multihash = |digest: [u8; 32]| {
        let mut out = vec![0x12, 0x20];
        out.extend_from_slice(&digest);
        out
    };
    let mapping_key_hash = {
        let mut h = canton_algo::PurposeHash::new(TOPOLOGY_MAPPING_UNIQUE_KEY);
        h.add_string(unique_key)
            .and_then(|_| h.add_int(code))
            .map_err(|e| format!("{e:?}"))?;
        multihash(h.finish().map_err(|e| format!("{e:?}"))?)
    };
    let hash_of_signatures = {
        let mut sigs: Vec<(String, Vec<u8>)> = signatures
            .iter()
            .map(|bytes| {
                let signed_by =
                    canton_proto::com::digitalasset::canton::crypto::v30::Signature::decode(
                        bytes.as_slice(),
                    )
                    .map(|s| s.signed_by)
                    .map_err(|e| e.to_string())?;
                Ok((signed_by, bytes.clone()))
            })
            .collect::<Result<_, String>>()?;
        sigs.sort();
        let mut h = canton_algo::PurposeHash::new(TOPOLOGY_TRANSACTION_SIGNATURE);
        for (_, bytes) in &sigs {
            h.add_byte_string(&versioned(bytes.clone(), 30))
                .map_err(|e| format!("{e:?}"))?;
        }
        multihash(h.finish().map_err(|e| format!("{e:?}"))?)
    };
    Ok((
        mapping_key_hash,
        transaction_hash(transaction),
        hash_of_signatures,
    ))
}

/// Makes the official participant vet the packages of an uploaded DAR on its synchronizer (U-50): the packages of the DAR it does not vet yet are added to the
/// list of the `VettedPackages` mapping in force (type 8), as the transaction after it (`serial + 1`, signed by the namespace key), which ends the earlier one.
///
/// [CANTON-NOTE: SEMANTICS] Without this the official participant refuses a command that uses the DAR's packages
/// (`INVALID_PRESCRIBED_SYNCHRONIZER_ID`: "Participant … has not vetted …"), though it holds the DAR (`par_dars`).
#[allow(
    deprecated,
    reason = "populates legacy/deprecated Canton protobuf or pinned crypto fields for wire compatibility"
)] // `package_ids` of the mapping is deprecated but a row may still use it
fn write_vetting(
    service: &ExecutionService,
    client: &mut postgres::Client,
    dar: &[u8],
) -> Result<(), String> {
    use canton_participant::topology_wire::unversioned;
    use canton_proto::com::digitalasset::canton::protocol::{v30, v31};
    use prost::Message;
    const VETTED_PACKAGES: i32 = 8;
    let loaded =
        lf_archive::parse_loaded_dar(std::io::Cursor::new(dar)).map_err(|e| e.to_string())?;
    let in_dar: Vec<String> = loaded
        .archive
        .dalfs
        .iter()
        .map(|d| d.package_id.clone())
        .collect();
    let current = client
        .query_opt(
            "SELECT id, store_id, serial_counter, namespace, identifier, instance FROM common_topology_transactions \
             WHERE transaction_type = $1 AND valid_until IS NULL AND NOT is_proposal ORDER BY id DESC LIMIT 1",
            &[&VETTED_PACKAGES],
        )
        .map_err(pg_error)?
        .ok_or("the topology store holds no vetted packages to extend")?;
    let (id, store, serial): (i64, i32, i32) = (current.get(0), current.get(1), current.get(2));
    let (namespace, identifier): (String, String) = (current.get(3), current.get(4));
    let instance: Vec<u8> = current.get(5);
    // the list in force: stored form -> signed transaction -> transaction -> mapping
    let (signed_bytes, _) = unversioned(&instance).ok_or("an unreadable stored transaction")?;
    let signed = v30::SignedTopologyTransaction::decode(signed_bytes.as_slice())
        .map_err(|e| e.to_string())?;
    let (tx_bytes, _) =
        unversioned(&signed.transaction).ok_or("an unreadable topology transaction")?;
    let tx = v31::TopologyTransaction::decode(tx_bytes.as_slice()).map_err(|e| e.to_string())?;
    let Some(v31::topology_mapping::Mapping::VettedPackages(vetted)) =
        tx.mapping.and_then(|m| m.mapping)
    else {
        return Err("the row in force is not a vetted packages mapping".into());
    };
    let mut all: Vec<String> = vetted
        .packages
        .iter()
        .map(|p| p.package_id.clone())
        .chain(vetted.package_ids.iter().cloned())
        .collect();
    let before = all.len();
    for p in in_dar {
        if !all.contains(&p) {
            all.push(p);
        }
    }
    if all.len() == before {
        return Ok(());
    }
    let next_serial = serial as u32 + 1;
    let record = service
        .protocol_vetting(&all, next_serial)
        .ok_or("no participant behind the service to sign the vetting")?;
    let member = format!("PAR::{identifier}::{namespace}");
    let (mapping_key_hash, tx_hash, hash_of_signatures) = topology_hashes(
        &member,
        VETTED_PACKAGES,
        &record.transaction,
        &record.signatures,
    )?;
    let latest: Option<i64> = client
        .query_one(
            "SELECT max(greatest(sequenced, valid_from)) FROM common_topology_transactions WHERE store_id = $1",
            &[&store],
        )
        .map_err(pg_error)?
        .get(0);
    let sequenced = latest.unwrap_or(0) + 1;
    let valid_from = sequenced + 250_000;
    let mut tx = client.transaction().map_err(pg_error)?;
    tx.execute(
        "UPDATE common_topology_transactions SET valid_until = $2 WHERE id = $1",
        &[&id, &valid_from],
    )
    .map_err(pg_error)?;
    tx.execute(
        "INSERT INTO common_topology_transactions (store_id, sequenced, transaction_type, namespace, identifier, mapping_key_hash, serial_counter, valid_from, \
         valid_until, operation, instance, tx_hash, rejection_reason, is_proposal, representative_protocol_version, hash_of_signatures, batch_idx) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, 1, $9, $10, NULL, false, 37, $11, 0)",
        &[
            &store,
            &sequenced,
            &VETTED_PACKAGES,
            &namespace,
            &identifier,
            &mapping_key_hash,
            &(next_serial as i32),
            &valid_from,
            &record.stored,
            &tx_hash,
            &hash_of_signatures,
        ],
    )
    .map_err(pg_error)?;
    tx.commit().map_err(pg_error)
}

/// Seeds singleton metadata rows (`lapi_parameters`, `lapi_post_processing_end`, `common_static_strings`,
/// and default admin user) so `--official-write` can operate directly on an empty Flyway-migrated participant DB.
fn ensure_official_bootstrap_rows(
    client: &mut postgres::Client,
    participant_id: &str,
    synchronizer_id: &str,
    admin_rows: &crate::v2::OfficialAdminRows,
) -> Result<(), String> {
    let effective_participant = if participant_id.is_empty() {
        "participant::1220rust"
    } else {
        participant_id
    };
    let effective_sync = if synchronizer_id.is_empty() {
        crate::v2_commands::SYNCHRONIZER
    } else {
        synchronizer_id
    };
    let mut tx = client.transaction().map_err(pg_error)?;
    if tx
        .query_opt("SELECT 1 FROM lapi_parameters LIMIT 1", &[])
        .map_err(pg_error)?
        .is_none()
    {
        tx.execute(
            "INSERT INTO lapi_parameters (ledger_end, participant_id, participant_pruned_up_to_inclusive, \
             ledger_end_sequential_id, ledger_end_string_interning_id, ledger_end_publication_time) \
             VALUES (NULL, $1, NULL, NULL, 0, NULL)",
            &[&effective_participant],
        )
        .map_err(pg_error)?;
    }
    if tx
        .query_opt("SELECT 1 FROM lapi_post_processing_end LIMIT 1", &[])
        .map_err(pg_error)?
        .is_none()
    {
        tx.execute(
            "INSERT INTO lapi_post_processing_end (post_processing_end) VALUES (0)",
            &[],
        )
        .map_err(pg_error)?;
    }
    if tx
        .query_opt(
            "SELECT 1 FROM common_static_strings WHERE source = 1 LIMIT 1",
            &[],
        )
        .map_err(pg_error)?
        .is_none()
    {
        tx.execute(
            "INSERT INTO common_static_strings (string, source) VALUES ($1, 1) \
             ON CONFLICT (string, source) DO NOTHING",
            &[&effective_sync],
        )
        .map_err(pg_error)?;
    }
    tx.commit().map_err(pg_error)?;
    if client
        .query_opt("SELECT 1 FROM lapi_users LIMIT 1", &[])
        .map_err(pg_error)?
        .is_none()
    {
        write_admin(client, admin_rows)?;
    }
    Ok(())
}

/// The text of a database error: the server's message and detail, not the client's `db error`.
fn pg_error(e: postgres::Error) -> String {
    match e.as_db_error() {
        Some(d) => format!("{} ({})", d.message(), d.detail().unwrap_or("")),
        None => e.to_string(),
    }
}

fn now_micros() -> i64 {
    crate::clock::now_micros()
}

/// Brings the administration tables to `rows` in one transaction.
fn write_admin(
    client: &mut postgres::Client,
    rows: &crate::v2::OfficialAdminRows,
) -> Result<(), String> {
    use std::collections::BTreeMap;
    let mut tx = client.transaction().map_err(|e| e.to_string())?;
    let err = pg_error;
    let now = now_micros();
    // identity providers
    tx.execute("DELETE FROM lapi_identity_provider_config", &[])
        .map_err(err)?;
    for (id, issuer, jwks, audience, deactivated) in &rows.idps {
        tx.execute(
            "INSERT INTO lapi_identity_provider_config (identity_provider_id, issuer, jwks_url, is_deactivated, audience) VALUES ($1, $2, $3, $4, $5)",
            &[id, issuer, jwks, deactivated, audience],
        )
        .map_err(err)?;
    }
    // users: the internal id (an identity column) of a user that is still there stays
    let existing: BTreeMap<String, i32> = tx
        .query("SELECT user_id, internal_id FROM lapi_users", &[])
        .map_err(err)?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    for gone in existing
        .keys()
        .filter(|u| !rows.users.iter().any(|r| &r.0 == *u))
    {
        let id = existing[gone];
        for table in ["lapi_user_rights", "lapi_user_annotations"] {
            let column = if table == "lapi_user_rights" {
                "user_internal_id"
            } else {
                "internal_id"
            };
            tx.execute(&format!("DELETE FROM {table} WHERE {column} = $1"), &[&id])
                .map_err(err)?;
        }
        tx.execute("DELETE FROM lapi_users WHERE internal_id = $1", &[&id])
            .map_err(err)?;
    }
    for (user, primary, deactivated, version, idp, annotations, rights) in &rows.users {
        let primary: Option<&str> = (!primary.is_empty()).then_some(primary.as_str());
        let idp: Option<&str> = (!idp.is_empty()).then_some(idp.as_str());
        let version = *version as i64;
        let id = match existing.get(user) {
            Some(id) => {
                tx.execute(
                    "UPDATE lapi_users SET primary_party = $2, is_deactivated = $3, resource_version = $4, identity_provider_id = $5 WHERE internal_id = $1",
                    &[id, &primary, deactivated, &version, &idp],
                )
                .map_err(err)?;
                *id
            }
            None => tx
                .query_one(
                    "INSERT INTO lapi_users (user_id, primary_party, created_at, is_deactivated, resource_version, identity_provider_id, primary_party_authentication) VALUES ($1, $2, $3, $4, $5, $6, false) RETURNING internal_id",
                    &[user, &primary, &now, deactivated, &version, &idp],
                )
                .map_err(err)?
                .get(0),
        };
        tx.execute(
            "DELETE FROM lapi_user_rights WHERE user_internal_id = $1",
            &[&id],
        )
        .map_err(err)?;
        for (code, party) in rights {
            tx.execute(
                "INSERT INTO lapi_user_rights (user_internal_id, user_right, for_party, granted_at) VALUES ($1, $2, $3, $4)",
                &[&id, code, party, &now],
            )
            .map_err(err)?;
        }
        tx.execute(
            "DELETE FROM lapi_user_annotations WHERE internal_id = $1",
            &[&id],
        )
        .map_err(err)?;
        for (name, value) in annotations {
            tx.execute(
                "INSERT INTO lapi_user_annotations (internal_id, name, val, updated_at) VALUES ($1, $2, $3, $4)",
                &[&id, name, value, &now],
            )
            .map_err(err)?;
        }
    }
    // party records: only the ones this participant wrote are rewritten; the records of other parties stay as they are
    let existing: BTreeMap<String, i32> = tx
        .query("SELECT party, internal_id FROM lapi_party_records", &[])
        .map_err(err)?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    for (party, version, idp, annotations) in &rows.parties {
        let idp: Option<&str> = (!idp.is_empty()).then_some(idp.as_str());
        let version = *version as i64;
        let id = match existing.get(party) {
            Some(id) => {
                tx.execute(
                    "UPDATE lapi_party_records SET resource_version = $2, identity_provider_id = $3 WHERE internal_id = $1",
                    &[id, &version, &idp],
                )
                .map_err(err)?;
                *id
            }
            None => tx
                .query_one(
                    "INSERT INTO lapi_party_records (party, resource_version, created_at, identity_provider_id) VALUES ($1, $2, $3, $4) RETURNING internal_id",
                    &[party, &version, &now, &idp],
                )
                .map_err(err)?
                .get(0),
        };
        tx.execute(
            "DELETE FROM lapi_party_record_annotations WHERE internal_id = $1",
            &[&id],
        )
        .map_err(err)?;
        for (name, value) in annotations {
            tx.execute(
                "INSERT INTO lapi_party_record_annotations (internal_id, name, val, updated_at) VALUES ($1, $2, $3, $4)",
                &[&id, name, value, &now],
            )
            .map_err(err)?;
        }
    }
    tx.commit().map_err(err)
}

/// Writes an uploaded DAR and its packages (`par_dars`, `par_daml_packages`); what is already there stays.
fn write_dar(client: &mut postgres::Client, dar: &[u8]) -> Result<(), String> {
    let loaded =
        lf_archive::parse_loaded_dar(std::io::Cursor::new(dar)).map_err(|e| e.to_string())?;
    let entries = lf_archive::dalf_entries(dar).map_err(|e| e.to_string())?;
    let archive = &loaded.archive;
    let mut tx = client.transaction().map_err(|e| e.to_string())?;
    let err = pg_error;
    let now = now_micros();
    tx.execute(
        "INSERT INTO par_dars (main_package_id, data, description, name, version) \
         SELECT $1::varchar, $2::bytea, 'uploaded-via-ledger-api', $3::varchar, $4::varchar WHERE NOT EXISTS (SELECT 1 FROM par_dars WHERE main_package_id = $1::varchar)",
        &[
            &archive.main_package_id,
            &dar,
            &archive.package_name.clone().unwrap_or_default(),
            &archive.package_version.clone().unwrap_or_default(),
        ],
    )
    .map_err(err)?;
    for (id, data, payload) in entries {
        let info = archive.dalfs.iter().find(|d| d.package_id == id);
        let name = info
            .and_then(|d| d.package_name.clone())
            .unwrap_or_default();
        let version = info
            .and_then(|d| d.package_version.clone())
            .unwrap_or_default();
        let size = payload.len() as i64;
        tx.execute(
            "INSERT INTO par_daml_packages (package_id, data, name, version, uploaded_at, package_size) \
             SELECT $1::varchar, $2::bytea, $3::varchar, $4::varchar, $5::bigint, $6::bigint WHERE NOT EXISTS (SELECT 1 FROM par_daml_packages WHERE package_id = $1::varchar)",
            &[&id, &data, &name, &version, &now, &size],
        )
        .map_err(err)?;
        tx.execute(
            "INSERT INTO par_dar_packages (main_package_id, package_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&archive.main_package_id, &id],
        )
        .map_err(err)?;
    }
    tx.commit().map_err(err)
}

#[cfg(test)]
mod party_topology_tests {
    use super::*;

    /// The row of the party `test0000` in the hub participant's `common_topology_transactions` (id 35): its transaction, its one signature and the three hashes.
    fn stored() -> crate::service::HostedParty {
        crate::service::HostedParty {
            party: "test0000::12200312c1156c7964d0d07c1434e6d1f38d76087e4a033a2ffa45141391ea2e233b".into(),
            transaction: hex::decode("0ab601080110011aaf014aac010a4e74657374303030303a3a313232303033313263313135366337393634643064303763313433346536643166333864373630383765346130333361326666613435313431333931656132653233336210011a580a527061727469636970616e74313a3a313232303033313263313135366337393634643064303763313433346536643166333864373630383765346130333361326666613435313431333931656132653233336210011804101f").unwrap(),
            signatures: vec![hex::decode("080312403df2c3b70612346b870c0c1a86f06bbf5d5682649455f012feaf48a8a3808597e9372faa9281abc55533c4129b15a4a764c80306edaca9d8ae73ee38dd9412051a4431323230303331326331313536633739363464306430376331343334653664316633386437363038376534613033336132666661343531343133393165613265323333622001").unwrap()],
            stored: Vec::new(),
        }
    }

    #[test]
    fn the_hashes_of_a_party_row_are_the_ones_the_official_participant_stored() {
        let (mapping_key_hash, tx_hash, hash_of_signatures) =
            party_topology_hashes(&stored()).unwrap();
        assert_eq!(
            hex::encode(mapping_key_hash),
            "1220b0a92b742f71643b28663cba63351f0e622544c087b2d21cb87521d0d1c6d7f1"
        );
        assert_eq!(
            hex::encode(tx_hash),
            "12202d3a3ea3565a28fa1440e799edc6fb587f15ad16d6c91cd0d605199d3ad31e98"
        );
        assert_eq!(
            hex::encode(hash_of_signatures),
            "1220f0af011bdf74cf39f7f9c44c1486cba7bf00a1f856fb25fc11050b96d4545961"
        );
    }
    #[test]
    fn the_unique_key_of_a_vetting_row_is_the_member_string_of_the_participant() {
        // the `VettedPackages` row of the hub's participant (id 25): its mapping key hash is over `PAR::<uid>` and code 8
        let (key, _, _) = topology_hashes(
            "PAR::participant1::12200312c1156c7964d0d07c1434e6d1f38d76087e4a033a2ffa45141391ea2e233b",
            8,
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            hex::encode(key),
            "1220761a7d47bb97138536431d42db6beaa5e240b810d1a419ab7ccd5744afb515e9"
        );
    }
}
