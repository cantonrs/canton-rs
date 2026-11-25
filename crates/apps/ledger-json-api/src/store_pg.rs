//! The request log in PostgreSQL (S-STORE-005): the same records as `FileLog`, one row per request.
//!
//! Schema (created on connect when missing):
//! ```sql
//! canton_rs_schema(version int)                       -- the layout version, checked on connect
//! canton_rs_ledger_log(
//!   ledger_id text, seq bigint, at_micros bigint,     -- (ledger_id, seq) is the primary key; seq counts 1, 2, 3 ... without gaps
//!   method text, path text, status integer,           -- readable copies for people looking at the table
//!   record bytea,                                     -- the encoded `LoggedRequest`: the source of truth
//!   PRIMARY KEY (ledger_id, seq))
//! ```
//!
//! [CANTON-NOTE: SEMANTICS] One writer per ledger id: the connection holds a session-level advisory lock for its whole life, so a
//! second service on the same ledger fails to start instead of interleaving records, and a dead process releases the lock with
//! its connection. An append is one auto-committed `INSERT`; `append` returns after PostgreSQL acknowledged the commit
//! (`synchronous_commit` on, the default). When the answer to an `INSERT` is lost (connection cut) the outcome is unknown: the
//! service stops taking writes and a restart replays what is in the table, exactly as after a crash of the file backend.
//!
//! [CANTON-NOTE: LIMITATION] No TLS (`NoTls`), no connection retry, no table partitioning or compaction, and durability is
//! PostgreSQL's (a server running with `fsync = off` or `synchronous_commit = off` weakens it; the tests do not change them).
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::{Duration, Instant};

use postgres::{Client, NoTls};

use crate::store::{LogSnapshot, LoggedRequest, RequestLog};

const SCHEMA_VERSION: i32 = 1;
/// Serializes the creation of the tables across services starting at the same moment.
const DDL_LOCK: i64 = 0x0043_414E_544F_4E01;

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn default_retry_window() -> Duration {
    let secs = std::env::var("CANTON_RS_STATE_PG_RETRY_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30);
    Duration::from_secs(secs)
}

fn is_transient_pg_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    const FATAL: [&str; 6] = [
        "password authentication failed",
        "no pg_hba.conf entry",
        "does not exist",
        "permission denied",
        "unique violation",
        "duplicate key",
    ];
    if FATAL.iter().any(|m| lower.contains(m)) {
        return false;
    }
    const TRANSIENT: [&str; 14] = [
        "error connecting to server",
        "connection refused",
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "connection closed",
        "closed",
        "terminating connection",
        "57p01",
        "57p02",
        "57p03",
        "in recovery",
        "shutting down",
        "starting up",
    ];
    TRANSIENT.iter().any(|m| lower.contains(m))
        || lower.contains("dns")
        || lower.contains("resolve")
        || lower.contains("timed out")
}

/// Connects to `url` performing fresh DNS resolution (`ToSocketAddrs`) per call when hostname is non-IP,
/// preventing stale IP pinning on RDS writer failover (`AT-D09`).
fn connect_fresh(url: &str) -> Result<Client, postgres::Error> {
    let cfg = postgres::Config::from_str(url)?;
    let hosts = cfg.get_hosts().to_vec();
    let ports = cfg.get_ports().to_vec();
    if let Some(postgres::config::Host::Tcp(host)) = hosts.first() {
        if host.parse::<IpAddr>().is_err() {
            let port = ports.first().copied().unwrap_or(5432);
            if let Ok(addrs) = (host.as_str(), port).to_socket_addrs() {
                for addr in addrs {
                    let mut attempt = cfg.clone();
                    attempt.hostaddr(addr.ip());
                    if let Ok(client) = attempt.connect(NoTls) {
                        return Ok(client);
                    }
                }
            }
        }
    }
    cfg.connect(NoTls)
}

/// Where a test can interrupt `append` (the real crashes are covered by killing the server process).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgCrash {
    /// The row never reaches the database.
    BeforeInsert,
    /// The row is committed; the answer is lost (the caller sees an error).
    AfterCommit,
}

pub struct PgLog {
    url: String,
    client: Client,
    ledger: String,
    next_seq: i64,
    cached_snapshot: Option<LogSnapshot>,
    preloaded_tail: Option<(u64, Vec<LoggedRequest>)>,
    crash: Option<PgCrash>,
    retry_window: Duration,
}

impl PgLog {
    /// Connects, creates the tables if needed, takes the writer lock of `ledger`, and validates any checkpoint/tail rows.
    pub fn connect(url: &str, ledger: &str) -> io::Result<Self> {
        let mut client = connect_fresh(url).map_err(io_err)?;
        client
            .execute("SELECT pg_advisory_lock($1)", &[&DDL_LOCK])
            .map_err(io_err)?;
        let ddl = Self::create_tables(&mut client);
        client
            .execute("SELECT pg_advisory_unlock($1)", &[&DDL_LOCK])
            .map_err(io_err)?;
        ddl?;

        Self::acquire_writer_lock(&mut client, ledger)?;
        let cached_snapshot = Self::query_snapshot(&mut client, ledger)?;
        let after_seq = cached_snapshot.as_ref().map_or(0, |s| s.seq);
        let tail = Self::query_rows_after(&mut client, ledger, after_seq)?;
        let next_seq = after_seq as i64 + tail.len() as i64 + 1;

        Ok(Self {
            url: url.to_string(),
            client,
            ledger: ledger.to_string(),
            next_seq,
            cached_snapshot,
            preloaded_tail: Some((after_seq, tail)),
            crash: None,
            retry_window: default_retry_window(),
        })
    }

    fn query_snapshot(client: &mut Client, ledger: &str) -> io::Result<Option<LogSnapshot>> {
        let row = client
            .query_opt(
                "SELECT seq, state FROM canton_rs_ledger_snapshot WHERE ledger_id = $1",
                &[&ledger],
            )
            .map_err(io_err)?;
        Ok(row.and_then(|r| {
            let seq: i64 = r.get(0);
            let payload: Vec<u8> = r.get(1);
            u64::try_from(seq)
                .ok()
                .map(|seq| LogSnapshot { seq, payload })
        }))
    }

    fn query_rows_after(
        client: &mut Client,
        ledger: &str,
        after_seq: u64,
    ) -> io::Result<Vec<LoggedRequest>> {
        let after_i64 = after_seq as i64;
        let rows = client
            .query(
                "SELECT seq, record FROM canton_rs_ledger_log WHERE ledger_id = $1 AND seq > $2 ORDER BY seq",
                &[&ledger, &after_i64],
            )
            .map_err(io_err)?;
        let mut loaded = Vec::with_capacity(rows.len());
        for (i, row) in rows.iter().enumerate() {
            let seq: i64 = row.get(0);
            let expected = after_i64 + i as i64 + 1;
            if seq != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the request log of {ledger:?} has a gap: expected seq {expected}, found {seq}",
                    ),
                ));
            }
            let record: Vec<u8> = row.get(1);
            loaded.push(LoggedRequest::decode(&record).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("undecodable record at seq {seq}"),
                )
            })?);
        }
        Ok(loaded)
    }

    fn acquire_writer_lock(client: &mut Client, ledger: &str) -> io::Result<()> {
        let locked: bool = client
            .query_one(
                "SELECT pg_try_advisory_lock(hashtextextended($1, 0))",
                &[&ledger],
            )
            .map_err(io_err)?
            .get(0);
        if !locked {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("ledger {ledger:?} is being written by another service"),
            ));
        }
        Ok(())
    }

    fn create_tables(client: &mut Client) -> io::Result<()> {
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS canton_rs_schema (version integer NOT NULL);
                 CREATE TABLE IF NOT EXISTS canton_rs_ledger_log (
                     ledger_id text   NOT NULL,
                     seq       bigint NOT NULL,
                     at_micros bigint NOT NULL,
                     method    text   NOT NULL,
                     path      text   NOT NULL,
                     status    integer NOT NULL,
                     record    bytea  NOT NULL,
                     PRIMARY KEY (ledger_id, seq)
                 );
                 CREATE TABLE IF NOT EXISTS canton_rs_ledger_snapshot (
                     ledger_id text   PRIMARY KEY,
                     seq       bigint NOT NULL,
                     state     bytea  NOT NULL
                 );",
            )
            .map_err(io_err)?;
        let found = client
            .query("SELECT version FROM canton_rs_schema", &[])
            .map_err(io_err)?;
        match found.first() {
            None => {
                client
                    .execute(
                        "INSERT INTO canton_rs_schema (version) VALUES ($1)",
                        &[&SCHEMA_VERSION],
                    )
                    .map_err(io_err)?;
            }
            Some(row) if row.get::<_, i32>(0) == SCHEMA_VERSION => {}
            Some(row) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the database has layout version {}, this build writes {SCHEMA_VERSION}",
                        row.get::<_, i32>(0)
                    ),
                ))
            }
        }
        Ok(())
    }

    /// Configures outage reconnect retry duration (`Duration::ZERO` disables retries).
    pub fn set_retry_window(&mut self, window: Duration) {
        self.retry_window = window;
    }

    /// Test hook: the next `append` is interrupted at `point` (once).
    pub fn inject_crash(&mut self, point: PgCrash) {
        self.crash = Some(point);
    }

    fn reconnect_and_lock(&mut self, deadline: Instant) -> io::Result<()> {
        let mut pause = Duration::from_millis(100);
        let mut last_err;
        loop {
            match connect_fresh(&self.url) {
                Ok(mut c) => match Self::acquire_writer_lock(&mut c, &self.ledger) {
                    Ok(()) => {
                        self.client = c;
                        return Ok(());
                    }
                    Err(e) if e.kind() == io::ErrorKind::AddrInUse => return Err(e),
                    Err(e) => last_err = Some(e),
                },
                Err(e) => {
                    let msg = e.to_string();
                    if !is_transient_pg_error(&msg) {
                        return Err(io_err(msg));
                    }
                    last_err = Some(io_err(msg));
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(last_err.unwrap_or_else(|| io_err("reconnect window exhausted")));
            }
            let remaining = deadline.saturating_duration_since(now);
            std::thread::sleep(pause.min(remaining));
            pause = (pause * 2).min(Duration::from_secs(2));
        }
    }

    fn load_rows_after(&mut self, after_seq: u64) -> io::Result<Vec<LoggedRequest>> {
        if let Some((cached_after, tail)) = self.preloaded_tail.take() {
            if cached_after == after_seq {
                self.next_seq = after_seq as i64 + tail.len() as i64 + 1;
                return Ok(tail);
            }
        }
        let loaded = Self::query_rows_after(&mut self.client, &self.ledger, after_seq)?;
        self.next_seq = after_seq as i64 + loaded.len() as i64 + 1;
        Ok(loaded)
    }
}

impl RequestLog for PgLog {
    fn load(&mut self) -> io::Result<Vec<LoggedRequest>> {
        self.load_rows_after(0)
    }

    fn append(&mut self, rec: &LoggedRequest) -> io::Result<()> {
        let crash = self.crash.take();
        if crash == Some(PgCrash::BeforeInsert) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "injected crash"));
        }
        let encoded = rec.encode();
        let insert_res = self.client.execute(
            "INSERT INTO canton_rs_ledger_log (ledger_id, seq, at_micros, method, path, status, record)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &self.ledger,
                &self.next_seq,
                &rec.at_micros,
                &rec.method,
                &rec.path,
                &i32::from(rec.status),
                &encoded,
            ],
        );
        match insert_res {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                let should_retry = crash.is_none()
                    && !self.retry_window.is_zero()
                    && (self.client.is_closed() || is_transient_pg_error(&msg));
                if !should_retry {
                    return Err(io_err(msg));
                }
                let deadline = Instant::now() + self.retry_window;
                loop {
                    self.reconnect_and_lock(deadline)?;
                    if let Ok(Some(row)) = self.client.query_opt(
                        "SELECT record FROM canton_rs_ledger_log WHERE ledger_id = $1 AND seq = $2",
                        &[&self.ledger, &self.next_seq],
                    ) {
                        let existing: Vec<u8> = row.get(0);
                        if existing == encoded {
                            break;
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "conflicting record already committed at seq {} during recovery",
                                self.next_seq
                            ),
                        ));
                    }
                    match self.client.execute(
                        "INSERT INTO canton_rs_ledger_log (ledger_id, seq, at_micros, method, path, status, record)
                         VALUES ($1, $2, $3, $4, $5, $6, $7)",
                        &[
                            &self.ledger,
                            &self.next_seq,
                            &rec.at_micros,
                            &rec.method,
                            &rec.path,
                            &i32::from(rec.status),
                            &encoded,
                        ],
                    ) {
                        Ok(_) => break,
                        Err(e2)
                            if (self.client.is_closed() || is_transient_pg_error(&e2.to_string()))
                                && Instant::now() < deadline =>
                        {
                            continue;
                        }
                        Err(e2) => return Err(io_err(e2)),
                    }
                }
            }
        }
        self.next_seq += 1;
        if crash == Some(PgCrash::AfterCommit) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "injected crash"));
        }
        Ok(())
    }

    fn load_snapshot(&mut self) -> io::Result<Option<LogSnapshot>> {
        if let Some(snap) = self.cached_snapshot.take() {
            return Ok(Some(snap));
        }
        Self::query_snapshot(&mut self.client, &self.ledger)
    }

    fn save_snapshot(&mut self, snap: &LogSnapshot) -> io::Result<()> {
        let seq_i64 = i64::try_from(snap.seq).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "snapshot seq exceeds i64::MAX")
        })?;
        let res = self.client.execute(
            "INSERT INTO canton_rs_ledger_snapshot (ledger_id, seq, state)
             VALUES ($1, $2, $3)
             ON CONFLICT (ledger_id) DO UPDATE SET seq = EXCLUDED.seq, state = EXCLUDED.state",
            &[&self.ledger, &seq_i64, &snap.payload],
        );
        match res {
            Ok(_) => Ok(()),
            Err(e)
                if !self.retry_window.is_zero()
                    && (self.client.is_closed() || is_transient_pg_error(&e.to_string())) =>
            {
                let deadline = Instant::now() + self.retry_window;
                self.reconnect_and_lock(deadline)?;
                self.client
                    .execute(
                        "INSERT INTO canton_rs_ledger_snapshot (ledger_id, seq, state)
                         VALUES ($1, $2, $3)
                         ON CONFLICT (ledger_id) DO UPDATE SET seq = EXCLUDED.seq, state = EXCLUDED.state",
                        &[&self.ledger, &seq_i64, &snap.payload],
                    )
                    .map(|_| ())
                    .map_err(io_err)
            }
            Err(e) => Err(io_err(e)),
        }
    }

    fn load_after(&mut self, after_seq: u64) -> io::Result<Vec<LoggedRequest>> {
        self.load_rows_after(after_seq)
    }

    fn compact_before(&mut self, seq: u64) -> io::Result<()> {
        let seq_i64 = i64::try_from(seq).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "compact seq exceeds i64::MAX")
        })?;
        self.client
            .execute(
                "DELETE FROM canton_rs_ledger_log WHERE ledger_id = $1 AND seq <= $2",
                &[&self.ledger, &seq_i64],
            )
            .map(|_| ())
            .map_err(io_err)
    }

    fn current_seq(&self) -> u64 {
        (self.next_seq - 1).max(0) as u64
    }
}
