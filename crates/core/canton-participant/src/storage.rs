//! Canton's PostgreSQL conventions the real storage paths (`migrate`, `pgconn`, `takeover`) follow: the Flyway checksum, the placeholders,
//! the server version check, the lock session settings and the advisory lock ids (`DbLockId`).

pub const PURPOSE_DB_LOCK_ID: i32 = 33;

/// The checksum Flyway records for a SQL migration (`flyway_schema_history.checksum`): the CRC-32 of the file's lines as Java's
/// `BufferedReader.readLine` gives them, each encoded as UTF-8 without its line ending, with a byte order mark taken off the first line.
///
/// [CANTON-NOTE: SEMANTICS] Measured on the official 3.7.2 node with files it was given as repeatable migrations
/// (`scripts/oracle-flyway-checksum.sh`, `tests/oracle/db-startup/checksums.tsv`): LF, CRLF, CR and mixed line endings give the same
/// lines; a byte order mark counts only at the start; a final line without a newline counts like one with; trailing spaces and empty lines
/// count; a placeholder counts as written (it is replaced only when the script runs).
pub fn compute_flyway_checksum(sql_content: &str) -> i32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    let mut update = |bytes: &[u8]| {
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
    };
    for (n, line) in java_lines(sql_content).enumerate() {
        let line = if n == 0 {
            line.strip_prefix('\u{FEFF}').unwrap_or(line)
        } else {
            line
        };
        update(line.as_bytes());
    }
    !crc as i32
}

/// The checksum of a migration file's bytes, which Flyway reads as UTF-8: bytes that are not UTF-8 are refused, as the official node
/// refuses them ("Unable to calculate checksum of <file> ... MalformedInputException", measured).
///
/// [CANTON-NOTE: SEMANTICS] A **repeatable** migration (`R__…`) is summed with its placeholders replaced (so a new placeholder value
/// applies it again); a versioned one as written (measured: the repeatable fixture with `${initialBftOrdererTablesPartitionSize}` was
/// recorded with 1500 in its place, the official `V5_2__dabft_partitioning.sql`, which has the same placeholder, with it unreplaced).
pub fn flyway_file_checksum(
    name: &str,
    bytes: &[u8],
    placeholders: &[(&str, &str)],
) -> Result<i32, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        format!("Unable to calculate checksum of {name} java.nio.charset.MalformedInputException: Input length = 1")
    })?;
    Ok(if name.starts_with("R__") {
        compute_flyway_checksum(&replace_placeholders(text, placeholders))
    } else {
        compute_flyway_checksum(text)
    })
}

/// The Flyway placeholders Canton sets (`PartitionConfig` default for the partitioned BFT orderer tables).
pub const FLYWAY_PLACEHOLDERS: [(&str, &str); 1] =
    [("initialBftOrdererTablesPartitionSize", "1500")];

/// `${name}` replaced by its value, for each placeholder.
pub fn replace_placeholders(text: &str, placeholders: &[(&str, &str)]) -> String {
    placeholders.iter().fold(text.to_string(), |s, (k, v)| {
        s.replace(&format!("${{{k}}}"), v)
    })
}

/// The lines of `text` as `BufferedReader.readLine` returns them: ended by `\n`, `\r` or `\r\n`; a last line without an ending counts, an
/// empty one after the last ending does not.
fn java_lines(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match rest.find(['\n', '\r']) {
            None => {
                let line = rest;
                rest = "";
                Some(line)
            }
            Some(at) => {
                let line = &rest[..at];
                let skip = if rest[at..].starts_with("\r\n") { 2 } else { 1 };
                rest = &rest[at + skip..];
                Some(line)
            }
        }
    })
}

/// What the version of the PostgreSQL server means to a node (`DbVersionCheck`): `Ok(None)` for a version Canton expects, `Ok(Some(note))`
/// for one it goes on with after saying so, `Err` for one it does not start on.
///
/// [CANTON-NOTE: SEMANTICS] Canton 3.7.2 expects the majors 14 to 18. A higher major is accepted with a note (a warning with the standard
/// config, information otherwise). A lower one, or a version string whose part before the first `.` is no number, is an error with the
/// standard config and only a note with `non-standard-config`. Read from `DbVersionCheck.scala`. Measured on the official participant
/// (`scripts/oracle-db-version.sh`, `tests/oracle/db-startup/versions.tsv`): 14, 16 and 18 start silently in both configs; on **13 the node
/// never gets here** - its lock session fails first (see [`LOCK_SESSION_SETTINGS`]).
pub fn check_postgres_version(
    server_version: &str,
    standard_config: bool,
) -> Result<Option<String>, String> {
    const EXPECTED: std::ops::RangeInclusive<u32> = 14..=18;
    const EXPECTED_TEXT: &str = "14, 15, 16, 17, or 18";
    let problem = match server_version.split('.').next().unwrap_or_default().parse::<u32>() {
        Ok(major) if EXPECTED.contains(&major) => return Ok(None),
        Ok(major) if major > *EXPECTED.end() => {
            return Ok(Some(format!(
                "Expected Postgres version {EXPECTED_TEXT} but got higher version {server_version}"
            )))
        }
        Ok(_) => format!("Expected Postgres version {EXPECTED_TEXT} but got lower version {server_version}"),
        Err(_) => format!("Exception in parsing Postgres version string {server_version}: not a number before the first dot"),
    };
    if standard_config {
        Err(problem)
    } else {
        Ok(Some(problem))
    }
}

/// What Canton sets on the session that holds one of its database locks (`DbLockedConnection`, the `DbLockedConnectionConfig` defaults):
/// TCP keep-alives and the server's check that the client is still there.
///
/// [CANTON-NOTE: SEMANTICS] `client_connection_check_interval` exists from PostgreSQL 14 on. On 13 the server answers `unrecognized
/// configuration parameter "client_connection_check_interval"` and the official node retries its lock connection without end, with the
/// standard config and without (measured): PostgreSQL 13 is not a version a node starts on, whatever the version check would say.
pub const LOCK_SESSION_SETTINGS: [&str; 4] = [
    "SET tcp_keepalives_idle TO 10",
    "SET tcp_keepalives_interval TO 1",
    "SET tcp_keepalives_count TO 5",
    "SET client_connection_check_interval TO 5000",
];

/// The PostgreSQL advisory lock id Canton uses for the lock `counter` on the database `scope` (`DbLockId.create`; the scope is the
/// database's name).
///
/// [CANTON-NOTE: SEMANTICS] Bits 1-8 are `counter - 1`, bits 9-29 come from the first four bytes (big-endian) of the SHA-256 of
/// `HashPurpose.DbLockId` (33) over the scope without a length prefix, and bit 30 is set. Measured on the official 3.7.2 participant
/// (`tests/oracle/db-startup/lock-ids.tsv`: database `tmpl` gives 855874852 for the migration lock 37 and 855874816 for the writer lock 1).
pub fn db_lock_id(scope: &str, counter: u32) -> i32 {
    let digest = canton_algo::hash::sha256_with_purpose(PURPOSE_DB_LOCK_ID, scope.as_bytes());
    let head = i32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    (counter as i32 - 1) | (head & 0x1fff_ff00) | (1 << 29)
}

/// `DbLockCounters`: what a lock is for. A participant holds `PARTICIPANT_WRITE` while it runs (measured) and every node takes
/// `NODE_MIGRATIONS` while it checks and migrates its schema.
pub mod lock_counters {
    pub const PARTICIPANT_WRITE: u32 = 1;
    pub const INDEXER_MAIN: u32 = 2;
    pub const INDEXER_WORKER: u32 = 3;
    pub const NODE_MIGRATIONS: u32 = 37;
    pub const PARTICIPANT_WRITERS: u32 = 39;
}
