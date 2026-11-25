use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use ledger_json_api::canton_log::emit;

use super::{Backend, DaemonArgs};

fn write_seeded_identity(
    store: &dyn canton_participant::state_store::StateStore,
    key: &str,
    text: &str,
    role: &str,
    name: &str,
) -> Result<(), String> {
    match store.read(key)? {
        Some(kept) if kept == text => Ok(()),
        Some(_) => Err(format!(
            "--same-identity: the state of {role} {name} ({}) holds another identity: start it with a new state",
            store.describe()
        )),
        None => {
            if !store.create_new(key, text)? {
                return Err(format!(
                    "--same-identity: the identity of {role} {name} could not be written"
                ));
            }
            Ok(())
        }
    }
}

pub(super) fn probe_official_sequencer(
    config_path: &Path,
    args: &DaemonArgs,
    sequencer: &str,
) -> Result<
    Option<(
        String,
        canton_participant::official_state::OfficialSynchronizer,
    )>,
    String,
> {
    let Some(target) = ledger_json_api::canton_conf::node_database(
        config_path,
        "sequencers",
        sequencer,
        args.official_pg_addr.as_deref(),
    )?
    else {
        return Ok(None);
    };
    let mut client = canton_participant::pgconn::connect(&target)?;
    client
        .batch_execute("SET default_transaction_read_only = on")
        .map_err(|e| e.to_string())?;
    if !canton_participant::official_state::has_official_sequencer(&mut client)? {
        return Ok(None);
    }
    let sync = canton_participant::official_state::read_official_synchronizer(
        &mut client,
        Some(sequencer),
    )?;
    emit(
        args.log_encoder,
        "INFO",
        "canton-rs.daemon",
        &format!("sequencer={sequencer}"),
        &format!(
            " Sequencer {sequencer}: adopted synchronizer {} ({} topology transactions)",
            sync.physical_synchronizer_id,
            sync.topology_transactions.len()
        ),
    );
    Ok(Some((ledger_json_api::canton_conf::pg_url(&target), sync)))
}

pub(super) fn seed_mediator_identity(
    config_path: &Path,
    args: &DaemonArgs,
    mediator: &str,
    state: &Backend,
) -> Result<Option<String>, String> {
    let Some(target) = ledger_json_api::canton_conf::node_database(
        config_path,
        "mediators",
        mediator,
        args.official_pg_addr.as_deref(),
    )?
    else {
        return Ok(None);
    };
    let mut client = canton_participant::pgconn::connect(&target)?;
    client
        .batch_execute("SET default_transaction_read_only = on")
        .map_err(|e| e.to_string())?;
    if !canton_participant::official_state::has_official_mediator(&mut client)? {
        return Ok(None);
    }
    let text = canton_participant::official_state::read_mediator_identity_text(
        &mut client,
        Some(mediator),
    )?;
    let store = open_backend_store(state)?;
    write_seeded_identity(
        store.as_ref(),
        canton_sequencer_server::mediator_identity::IDENTITY_KEY,
        &text,
        "mediator",
        mediator,
    )?;
    let id = canton_sequencer_server::mediator_identity::MediatorIdentity::from_text(&text)
        .ok_or("seeded mediator identity does not parse")?;
    emit(
        args.log_encoder,
        "INFO",
        "canton-rs.daemon",
        &format!("mediator={mediator}"),
        &format!(
            " Mediator {mediator}: the identity of the database's keys (namespace {})",
            id.namespace()
        ),
    );
    Ok(Some(id.uid()))
}

/// The DAR the participant runs: the last one uploaded to the official database of its storage (written under the state directory).
/// Puts the identity of the database's keys into the participant's state before it starts (the node keeps the identity it finds there). A state that holds
/// another identity is not overwritten.
pub(super) fn seed_identity(
    config_path: &Path,
    args: &DaemonArgs,
    participant: &str,
    state: &Backend,
) -> Result<(), String> {
    let target = ledger_json_api::canton_conf::database(
        config_path,
        Some(participant),
        args.official_pg_addr.as_deref(),
    )?
    .ok_or("--same-identity: the participant has no PostgreSQL storage to read the keys from")?;
    let mut client = canton_participant::pgconn::connect(&target)?;
    client
        .batch_execute("SET default_transaction_read_only = on")
        .map_err(|e| e.to_string())?;
    let text = canton_participant::official_state::read_identity_text(&mut client, participant)?;
    let store = open_backend_store(state)?;
    write_seeded_identity(
        store.as_ref(),
        "identity",
        &text,
        "participant",
        participant,
    )?;
    let namespace = canton_participant::topology_wire::ParticipantIdentity::from_text(&text)
        .map(|i| i.namespace().to_string())
        .unwrap_or_default();
    emit(
        args.log_encoder,
        "INFO",
        "canton-rs.daemon",
        &format!("participant={participant}"),
        &format!(
            " Participant {participant}: the identity of the database's keys (namespace {namespace})"
        ),
    );
    Ok(())
}

pub(super) fn open_backend_store(
    backend: &Backend,
) -> Result<std::sync::Arc<dyn canton_participant::state_store::StateStore>, String> {
    match backend {
        Backend::Files(dir) => canton_participant::state_store::FileStore::new(dir)
            .map(|s| s as std::sync::Arc<dyn canton_participant::state_store::StateStore>),
        Backend::Database { url, name } => {
            canton_participant::state_store::PgStore::connect(url, name)
                .map(|s| s as std::sync::Arc<dyn canton_participant::state_store::StateStore>)
        }
    }
}

pub(super) fn resolve_connect_url(
    url: &str,
    endpoints: &[(String, u16, String)],
) -> Option<String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let host_port = rest.split('/').next()?;
    let (host, port_s) = host_port.rsplit_once(':')?;
    let port: u16 = port_s.parse().ok()?;
    if matches!(host, "localhost" | "127.0.0.1" | "0.0.0.0") {
        if let Some((_, _, local_url)) = endpoints.iter().find(|(_, raw, _)| *raw == port) {
            return Some(local_url.clone());
        }
    }
    None
}

pub(super) fn default_dar_for_participant(
    config_path: &Path,
    args: &DaemonArgs,
    participant: &str,
    state: &Path,
) -> Result<PathBuf, String> {
    if let Ok(path) = dar_from_official_database(
        config_path,
        participant,
        args.official_pg_addr.as_deref(),
        state,
    ) {
        return Ok(path);
    }
    let sample = Path::new("contracts/target/sample-contract.dar");
    if sample.is_file() {
        return Ok(sample.to_path_buf());
    }
    let path = state.join("builtin-ping.dar");
    if !path.is_file() {
        std::fs::write(&path, ledger_grpc_api::admin_api::BUILTIN_PING_DAR)
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(path)
}

pub(crate) fn run_admin_ping(
    from: &super::super::supervisor::probe::PingEndpoint,
    to: &super::super::supervisor::probe::PingEndpoint,
) -> Result<u64, String> {
    let (from_port, to_port) = (from.admin_port, to.admin_port);
    let bearer = |token: &Option<String>| -> Result<
        Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
        String,
    > {
        token
            .as_ref()
            .map(|t| {
                format!("Bearer {t}")
                    .parse()
                    .map_err(|_| "the token is not a valid header value".to_string())
            })
            .transpose()
    };
    let (from_auth, to_auth) = (bearer(&from.token)?, bearer(&to.token)?);
    use canton_proto::com::digitalasset::canton::admin::participant::v30::{
        ping_response, ping_service_client::PingServiceClient, PingRequest,
    };
    use canton_proto::com::digitalasset::canton::topology::admin::v30::{
        identity_initialization_service_client::IdentityInitializationServiceClient, GetIdRequest,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let from_url = format!("http://127.0.0.1:{from_port}");
        let to_url = format!("http://127.0.0.1:{to_port}");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        let target_uid = loop {
            let attempt = async {
                let ch = tonic::transport::Channel::from_shared(to_url.clone())
                    .map_err(|e| e.to_string())?
                    .connect()
                    .await
                    .map_err(|e| e.to_string())?;
                let mut id_client = IdentityInitializationServiceClient::new(ch);
                let mut req = tonic::Request::new(GetIdRequest {});
                if let Some(v) = &to_auth {
                    req.metadata_mut().insert("authorization", v.clone());
                }
                let resp = id_client
                    .get_id(req)
                    .await
                    .map_err(|e| e.message().to_string())?
                    .into_inner();
                if !resp.initialized || resp.unique_identifier.is_empty() {
                    return Err("target participant is not initialized yet".to_string());
                }
                Ok::<_, String>(resp.unique_identifier)
            }
            .await;
            match attempt {
                Ok(uid) => break uid,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(e) => return Err(format!("GetId at {to_url}: {e}")),
            }
        };

        let ping_deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        loop {
            let ch = match tonic::transport::Channel::from_shared(from_url.clone())
                .map_err(|e| e.to_string())?
                .connect()
                .await
            {
                Ok(c) => c,
                Err(e) if tokio::time::Instant::now() < ping_deadline => {
                    let _ = e;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
                Err(e) => return Err(format!("connect {from_url}: {e}")),
            };
            let mut client = PingServiceClient::new(ch);
            let mut req = tonic::Request::new(PingRequest {
                target_parties: vec![target_uid.clone()],
                validators: Vec::new(),
                timeout: Some(prost_types::Duration {
                    seconds: 15,
                    nanos: 0,
                }),
                levels: 0,
                synchronizer_id: String::new(),
                workflow_id: String::new(),
                id: String::new(),
            });
            if let Some(v) = &from_auth {
                req.metadata_mut().insert("authorization", v.clone());
            }
            let resp = client.ping(req).await;
            match resp {
                Ok(r) => match r.into_inner().response {
                    Some(ping_response::Response::Success(s)) => return Ok(s.ping_time),
                    Some(ping_response::Response::Failure(f))
                        if (f.reason.contains("VETTED")
                            || f.reason.contains("vetted")
                            || f.reason.contains("host")
                            || f.reason.contains("Party")
                            || f.reason.contains("Unknown"))
                            && tokio::time::Instant::now() < ping_deadline =>
                    {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    Some(ping_response::Response::Failure(f)) => {
                        return Err(format!("PingFailure: {}", f.reason))
                    }
                    None => return Err("empty PingResponse".to_string()),
                },
                Err(status) if tokio::time::Instant::now() < ping_deadline => {
                    let _ = status;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                Err(status) => return Err(format!("PingService/Ping at {from_url}: {status}")),
            }
        }
    })
}

fn dar_from_official_database(
    config: &Path,
    participant: &str,
    pg_addr: Option<&str>,
    state: &Path,
) -> Result<PathBuf, String> {
    let target = ledger_json_api::canton_conf::database(config, Some(participant), pg_addr)?;
    let target =
        target.ok_or("the participant has no PostgreSQL storage to take a DAR from: give --dar")?;
    let mut client = canton_participant::pgconn::connect(&target)?;
    client
        .batch_execute("SET default_transaction_read_only = on")
        .map_err(|e| e.to_string())?;
    let dars = canton_participant::official_state::read_dars(&mut client)?;
    let last = dars
        .last()
        .ok_or("the official database holds no DAR: give --dar")?;
    let path = state.join(format!("{participant}-{}.dar", last.name));
    std::fs::write(&path, &last.data).map_err(|e| e.to_string())?;
    Ok(path)
}
