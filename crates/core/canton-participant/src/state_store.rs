//! Where a node keeps what has to survive a restart (G11, S-LOCAL-006): its identity, the contract set journal, the topology journal, where it
//! stopped reading and the contracts it can exercise. The node asks a [`StateStore`] for four things and does not know whether the answer comes
//! from a directory or from a PostgreSQL database.
//!
//! [CANTON-NOTE: SEMANTICS] The unit is a **line of text** under a **key**: `append` adds one line durably (it has been written to disk, or the
//! database committed it, when it returns), `read` gives the lines back in the order they were appended, `write` replaces everything under the
//! key at once (a crash leaves the old content or the new one, never half of it), and `create_new` writes only if the key has nothing yet (an
//! identity is never overwritten). A file's incomplete last line (the process died while writing it) is the caller's to ignore: it has no
//! trailing newline in `read`'s text.
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub trait StateStore: Send + Sync {
    /// The text under `key` (each appended line ends with a newline), or `None` when nothing was ever written there.
    fn read(&self, key: &str) -> Result<Option<String>, String>;
    /// Replaces everything under `key` with `text` (which holds whole lines).
    fn write(&self, key: &str, text: &str) -> Result<(), String>;
    /// Adds one line (without its newline) under `key`, durably.
    fn append(&self, key: &str, line: &str) -> Result<(), String>;
    /// Writes `text` under `key` only if there is nothing under it; `Ok(false)` when there was.
    fn create_new(&self, key: &str, text: &str) -> Result<bool, String>;
    /// Where this store keeps things, for messages.
    fn describe(&self) -> String;
}

/// A directory: one file for each key.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(dir: &Path) -> Result<Arc<Self>, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(Arc::new(Self {
            dir: dir.to_path_buf(),
        }))
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }
}

impl StateStore for FileStore {
    fn read(&self, key: &str) -> Result<Option<String>, String> {
        match std::fs::read_to_string(self.path(key)) {
            Ok(t) => Ok(Some(t)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn write(&self, key: &str, text: &str) -> Result<(), String> {
        // written beside and renamed: a crash leaves the old content or the new one
        let path = self.path(key);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
    }

    fn append(&self, key: &str, line: &str) -> Result<(), String> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path(key))
            .map_err(|e| e.to_string())?;
        writeln!(file, "{line}").map_err(|e| e.to_string())?;
        file.sync_data().map_err(|e| e.to_string())
    }

    fn create_new(&self, key: &str, text: &str) -> Result<bool, String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // the keys of an identity are private: readable by the owner only
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.path(key))
        {
            Ok(mut file) => {
                file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
                file.sync_all().map_err(|e| e.to_string())?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }

    fn describe(&self) -> String {
        format!("directory {}", self.dir.display())
    }
}

#[cfg(feature = "postgres")]
pub use pg::PgStore;

#[cfg(feature = "postgres")]
mod pg {
    use super::StateStore;
    use postgres::{Client, NoTls};
    use std::sync::mpsc::{channel, Sender};
    use std::sync::{Arc, Mutex};

    /// What the connection's thread is asked to do, with where to send the answer.
    enum Op {
        Read(String, Sender<Result<Option<String>, String>>),
        Write(String, String, Sender<Result<(), String>>),
        Append(String, String, Sender<Result<(), String>>),
        CreateNew(String, String, Sender<Result<bool, String>>),
        Stop,
    }

    /// A PostgreSQL database: the lines of every key of one named node in the table `canton_rs_state` (name, key, sequence number, line).
    ///
    /// [CANTON-NOTE: SEMANTICS] One node of a name runs at a time: the store holds a **session advisory lock** on the name for as long as it
    /// lives, and a second process that opens the same name is refused (the database is one place, so two writers would interleave lines).
    /// The lock goes with the connection: a node that dies releases it.
    ///
    /// [CANTON-NOTE: WHY] The connection lives on a **thread of its own** and the store talks to it through a channel. The synchronous client
    /// runs a runtime of its own, and calling it from a thread that is already inside an asynchronous runtime (the sequencer's request handlers)
    /// panics; dropping it there panics too. A call waits for its answer, as a write to a file does.
    ///
    /// [CANTON-NOTE: LIMITATION] The connection is plain (no TLS); the node-wide `pgconn` settings of the official configuration are not read.
    pub struct PgStore {
        tx: Mutex<Sender<Op>>,
        handle: Mutex<Option<std::thread::JoinHandle<()>>>,
        target: String,
        name: String,
    }

    fn lock_key(name: &str) -> String {
        format!("canton_rs_state:{name}")
    }

    /// How long a call waits for the database to come back before it fails (`CANTON_RS_STATE_PG_RETRY_SECONDS`, 60 by default).
    ///
    /// [CANTON-NOTE: SEMANTICS] The official participant survives a 20-second outage of its database and answers again 12 to 14 seconds after the
    /// database is back (measured, `tests/oracle/db-failover`). A journal write cannot be dropped or answered later than the caller can wait,
    /// so a call **waits** for the connection, retrying with a growing pause, rather than failing at once.
    fn retry_policy() -> crate::pgconn::RetryPolicy {
        crate::pgconn::RetryPolicy::from_env()
    }

    /// Why a connection could not be made: the name is taken (the lock is gone for good) or the database is not there (try again).
    enum ConnectFailure {
        Taken(String),
        Unreachable(String),
    }

    fn open_connection(url: &str, name: &str, lock: bool) -> Result<Client, ConnectFailure> {
        let unreachable = |e: String| ConnectFailure::Unreachable(e);
        // Perform fresh per-attempt DNS resolution when the URL parses cleanly via PgTarget so RDS DNS flips are observed on every reconnect.
        let mut client = if let Ok(target) =
            crate::pgconn::PgTarget::from_url_or_jdbc(url, None, None, None)
        {
            let ips = crate::pgconn::resolve_fresh_hostaddrs(&target.host, target.port)
                .map_err(|e| unreachable(format!("cannot resolve the database: {e}")))?;
            let mut last_err = String::new();
            let mut connected = None;
            for ip in ips {
                let mut attempt = target.clone();
                attempt.hostaddr = Some(ip);
                match crate::pgconn::connect(&attempt) {
                    Ok(c) => {
                        connected = Some(c);
                        break;
                    }
                    Err(e) => last_err = e,
                }
            }
            connected
                .ok_or_else(|| unreachable(format!("cannot connect to the database: {last_err}")))?
        } else {
            Client::connect(url, NoTls)
                .map_err(|e| unreachable(format!("cannot connect to the database: {e}")))?
        };
        client
            // [CANTON-NOTE: WHY] Two nodes that start together both find the table missing and both create it; the second fails on the
            // catalog's unique index. The creation runs under a lock of its own.
            .batch_execute(
                "BEGIN;
                 SELECT pg_advisory_xact_lock(hashtext('canton_rs_state:schema'));
                 CREATE TABLE IF NOT EXISTS canton_rs_state (
                     name text NOT NULL,
                     key text NOT NULL,
                     seq bigserial,
                     line text NOT NULL,
                     PRIMARY KEY (name, key, seq));
                 COMMIT;",
            )
            .map_err(|e| unreachable(e.to_string()))?;
        // [CANTON-NOTE: INVARIANT] PostgreSQL advisory locks are database-wide, so qualifying the lock key
        // by `current_schema()` enforces single-writer exclusion within a schema while allowing isolated
        // instance schemas (`<name>-state`) to run concurrently on the same database.
        let held: bool = !lock
            || client
                .query_one(
                    "SELECT pg_try_advisory_lock(hashtext(COALESCE(current_schema(), 'public') || ':' || $1))",
                    &[&lock_key(name)],
                )
                .map_err(|e| unreachable(e.to_string()))?
                .get(0);
        if !held {
            return Err(ConnectFailure::Taken(format!(
                "another process holds the state {name:?} in this database: one node of a name runs at a time"
            )));
        }
        Ok(client)
    }

    /// The connection of a store and what it takes to keep it.
    struct Conn {
        client: Option<Client>,
        url: String,
        name: String,
        lock: bool,
        /// Set once the name was taken by another process while the connection was down: the state is not ours to write any more.
        lost: Option<String>,
    }

    impl Conn {
        /// A connection that is open, made again (with the name's lock taken again) if the database went away and came back.
        ///
        /// [CANTON-NOTE: SEMANTICS] The session lock goes with the connection, so after a reconnect it is taken again; a name another process
        /// took in between is **lost for good** (the official node treats a lock it cannot keep the same way): every later call fails with
        /// that reason instead of writing lines beside another node's.
        fn client(&mut self) -> Result<&mut Client, String> {
            if let Some(why) = &self.lost {
                return Err(why.clone());
            }
            if self.client.as_ref().is_some_and(|c| c.is_closed()) {
                self.client = None;
            }
            if self.client.is_none() {
                let policy = retry_policy();
                let deadline = std::time::Instant::now() + policy.max_elapsed;
                let mut pause = policy.initial_backoff;
                loop {
                    match open_connection(&self.url, &self.name, self.lock) {
                        Ok(client) => {
                            self.client = Some(client);
                            break;
                        }
                        Err(ConnectFailure::Taken(why)) => {
                            let why = format!("the state was taken by another process while the connection was down: {why}");
                            self.lost = Some(why.clone());
                            return Err(why);
                        }
                        Err(ConnectFailure::Unreachable(why)) => {
                            if std::time::Instant::now() >= deadline {
                                return Err(why);
                            }
                            let remaining =
                                deadline.saturating_duration_since(std::time::Instant::now());
                            std::thread::sleep(pause.min(remaining));
                            pause = policy.next_backoff(pause);
                        }
                    }
                }
            }
            Ok(self.client.as_mut().expect("connected above"))
        }

        /// Runs `f`, and again on a new connection when the connection went away under it.
        ///
        /// [CANTON-NOTE: LIMITATION] An `append` whose connection dies after the database committed it and before the answer arrived is run
        /// again and its line is there twice (at least once, not exactly once).
        fn with_retry<T>(
            &mut self,
            mut f: impl FnMut(&mut Client) -> Result<T, String>,
        ) -> Result<T, String> {
            let deadline = std::time::Instant::now() + retry_policy().max_elapsed;
            loop {
                let client = self.client()?;
                match f(client) {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        let gone = self.client.as_ref().is_none_or(|c| c.is_closed());
                        if !gone || std::time::Instant::now() >= deadline {
                            return Err(e);
                        }
                        self.client = None;
                    }
                }
            }
        }
    }

    fn run(conn: &mut Conn, op: Op) -> bool {
        let name = conn.name.clone();
        match op {
            Op::Read(key, reply) => {
                let _ = reply.send(conn.with_retry(|c| read(c, &name, &key)));
            }
            Op::Write(key, text, reply) => {
                let _ = reply.send(conn.with_retry(|c| write(c, &name, &key, &text)));
            }
            Op::Append(key, line, reply) => {
                let _ = reply.send(conn.with_retry(|c| {
                    c.execute(
                        "INSERT INTO canton_rs_state (name, key, line) VALUES ($1, $2, $3)",
                        &[&name, &key, &line],
                    )
                    .map(|_| ())
                    .map_err(|e| e.to_string())
                }));
            }
            Op::CreateNew(key, text, reply) => {
                let _ = reply.send(conn.with_retry(|c| create_new(c, &name, &key, &text)));
            }
            Op::Stop => return false,
        }
        true
    }

    fn read(client: &mut Client, name: &str, key: &str) -> Result<Option<String>, String> {
        let rows = client
            .query(
                "SELECT line FROM canton_rs_state WHERE name = $1 AND key = $2 ORDER BY seq",
                &[&name, &key],
            )
            .map_err(|e| e.to_string())?;
        if rows.is_empty() {
            return Ok(None);
        }
        let mut text = String::new();
        for row in rows {
            text.push_str(row.get::<_, &str>(0));
            text.push('\n');
        }
        Ok(Some(text))
    }

    fn write(client: &mut Client, name: &str, key: &str, text: &str) -> Result<(), String> {
        let mut tx = client.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM canton_rs_state WHERE name = $1 AND key = $2",
            &[&name, &key],
        )
        .map_err(|e| e.to_string())?;
        for line in text.lines() {
            tx.execute(
                "INSERT INTO canton_rs_state (name, key, line) VALUES ($1, $2, $3)",
                &[&name, &key, &line],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    fn create_new(client: &mut Client, name: &str, key: &str, text: &str) -> Result<bool, String> {
        let mut tx = client.transaction().map_err(|e| e.to_string())?;
        let exists: bool = tx
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM canton_rs_state WHERE name = $1 AND key = $2)",
                &[&name, &key],
            )
            .map_err(|e| e.to_string())?
            .get(0);
        if exists {
            return Ok(false);
        }
        for line in text.lines() {
            tx.execute(
                "INSERT INTO canton_rs_state (name, key, line) VALUES ($1, $2, $3)",
                &[&name, &key, &line],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    impl PgStore {
        pub fn connect(url: &str, name: &str) -> Result<Arc<Self>, String> {
            Self::open(url, name, true)
        }

        /// Opens the state `name` **without** taking its lock: for reading what another node of the name keeps (the synchronizer's keys, which
        /// the mediator reads from the sequencer's state), never for writing it.
        pub fn connect_unlocked(url: &str, name: &str) -> Result<Arc<Self>, String> {
            Self::open(url, name, false)
        }

        fn open(url: &str, name: &str, lock: bool) -> Result<Arc<Self>, String> {
            let (tx, rx) = channel::<Op>();
            let (ready_tx, ready_rx) = channel::<Result<(), String>>();
            let (url_owned, name_owned) = (url.to_string(), name.to_string());
            let handle = std::thread::spawn(move || {
                // the first connection is made at once: a database that is not there when the node starts is the operator's to see
                match open_connection(&url_owned, &name_owned, lock) {
                    Err(ConnectFailure::Taken(e)) | Err(ConnectFailure::Unreachable(e)) => {
                        let _ = ready_tx.send(Err(e));
                    }
                    Ok(client) => {
                        let _ = ready_tx.send(Ok(()));
                        let mut conn = Conn {
                            client: Some(client),
                            url: url_owned,
                            name: name_owned,
                            lock,
                            lost: None,
                        };
                        while let Ok(op) = rx.recv() {
                            if !run(&mut conn, op) {
                                break;
                            }
                        }
                    }
                }
            });
            ready_rx
                .recv()
                .map_err(|_| "the database thread stopped".to_string())??;
            Ok(Arc::new(Self {
                tx: Mutex::new(tx),
                handle: Mutex::new(Some(handle)),
                target: url.rsplit('@').next().unwrap_or(url).to_string(),
                name: name.to_string(),
            }))
        }

        fn ask<T>(&self, make: impl FnOnce(Sender<Result<T, String>>) -> Op) -> Result<T, String> {
            let (reply_tx, reply_rx) = channel();
            self.tx
                .lock()
                .map_err(|_| "the database connection is poisoned".to_string())?
                .send(make(reply_tx))
                .map_err(|_| "the database thread stopped".to_string())?;
            reply_rx
                .recv()
                .map_err(|_| "the database thread stopped".to_string())?
        }
    }

    impl Drop for PgStore {
        fn drop(&mut self) {
            if let Ok(tx) = self.tx.lock() {
                let _ = tx.send(Op::Stop);
            }
            if let Ok(mut h) = self.handle.lock() {
                if let Some(h) = h.take() {
                    let _ = h.join();
                }
            }
        }
    }

    impl StateStore for PgStore {
        fn read(&self, key: &str) -> Result<Option<String>, String> {
            self.ask(|r| Op::Read(key.to_string(), r))
        }

        fn write(&self, key: &str, text: &str) -> Result<(), String> {
            self.ask(|r| Op::Write(key.to_string(), text.to_string(), r))
        }

        fn append(&self, key: &str, line: &str) -> Result<(), String> {
            self.ask(|r| Op::Append(key.to_string(), line.to_string(), r))
        }

        fn create_new(&self, key: &str, text: &str) -> Result<bool, String> {
            self.ask(|r| Op::CreateNew(key.to_string(), text.to_string(), r))
        }

        fn describe(&self) -> String {
            format!("database {} (state {:?})", self.target, self.name)
        }
    }
}
