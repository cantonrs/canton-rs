//! A generic append-only record file with the commit discipline of `durable.rs` (S-STORE-004): `[length u32][crc32 u32][body]`
//! records, `open` stops at the first short or corrupt record and cuts the file there, `append` returns only after `sync_all`.
//! The bodies are opaque bytes; what they mean is the caller's (the JSON API's request log stores one logged request per record).
//!
//! [CANTON-NOTE: LIMITATION] Same as `durable.rs`: one file, simulated crash points, no compaction, one writer (the caller must
//! hold the file exclusively; `open` takes no lock).
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::durable::CrashPoint;

pub struct RecordFile {
    path: PathBuf,
    file: File,
    synced_len: u64,
    /// How many bytes `open` cut off the end (0 for a clean file).
    pub truncated_bytes: u64,
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc32fast::hash(body).to_le_bytes());
    out.extend_from_slice(body);
    out
}

impl RecordFile {
    /// Opens (creating if needed) the file and returns it with every intact record, recovering from a torn tail.
    pub fn open(path: &Path) -> std::io::Result<(Self, Vec<Vec<u8>>)> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (mut at, mut records) = (0usize, Vec::new());
        while bytes.len() - at >= 8 {
            let len = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
                as usize;
            let crc =
                u32::from_le_bytes([bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7]]);
            let Some(body) = bytes.get(at + 8..at + 8 + len) else {
                break;
            };
            if crc32fast::hash(body) != crc {
                break;
            }
            records.push(body.to_vec());
            at += 8 + len;
        }
        let truncated = (bytes.len() - at) as u64;
        if truncated > 0 {
            file.set_len(at as u64)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok((
            Self {
                path: path.to_path_buf(),
                file,
                synced_len: at as u64,
                truncated_bytes: truncated,
            },
            records,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The file length known to be on disk.
    pub fn synced_len(&self) -> u64 {
        self.synced_len
    }

    /// Appends one record durably. With `crash` the file is left as that crash would leave it and `Err(Interrupted)` is returned.
    pub fn append(&mut self, body: &[u8], crash: Option<CrashPoint>) -> std::io::Result<()> {
        let record = frame(body);
        let crashed = || {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "injected crash",
            ))
        };
        match crash {
            Some(CrashPoint::BeforeWrite) => return crashed(),
            Some(CrashPoint::MidHeader) => {
                self.file.write_all(&record[..4])?;
                return crashed();
            }
            Some(CrashPoint::MidBody) => {
                self.file.write_all(&record[..8 + (record.len() - 8) / 2])?;
                return crashed();
            }
            _ => {}
        }
        self.file.write_all(&record)?;
        if crash == Some(CrashPoint::AfterWriteBeforeSync) {
            return crashed();
        }
        self.file.sync_all()?;
        self.synced_len += record.len() as u64;
        if crash == Some(CrashPoint::AfterSyncBeforeReturn) {
            return crashed();
        }
        Ok(())
    }

    /// Models a power failure: what was written but never synced is gone.
    pub fn lose_unsynced(path: &Path, synced_len: u64) -> std::io::Result<()> {
        OpenOptions::new()
            .write(true)
            .open(path)?
            .set_len(synced_len)
    }
}
