use sha2::{Digest, Sha256};

pub use crate::purposes::{HashPurpose, PURPOSES};

pub fn purpose_by_description(description: &str) -> Option<&'static HashPurpose> {
    PURPOSES
        .iter()
        .find(|purpose| purpose.description == description)
}

#[derive(Debug, PartialEq, Eq)]
pub enum HashBuildError {
    Closed,
    Length,
}

pub struct PurposeHash {
    hasher: Option<Sha256>,
}

impl PurposeHash {
    pub fn new(purpose_id: i32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(purpose_id.to_be_bytes());
        Self {
            hasher: Some(hasher),
        }
    }

    pub fn add_without_length_prefix(&mut self, bytes: &[u8]) -> Result<(), HashBuildError> {
        let Some(hasher) = self.hasher.as_mut() else {
            return Err(HashBuildError::Closed);
        };
        hasher.update(bytes);
        Ok(())
    }

    pub fn add_int(&mut self, value: i32) -> Result<(), HashBuildError> {
        self.add_without_length_prefix(&value.to_be_bytes())
    }

    pub fn add_byte_string(&mut self, bytes: &[u8]) -> Result<(), HashBuildError> {
        let len = i32::try_from(bytes.len()).map_err(|_| HashBuildError::Length)?;
        self.add_int(len)?;
        self.add_without_length_prefix(bytes)
    }

    /// `addLong`: 8 bytes, big endian, no length prefix (Canton `DeterministicEncoding.encodeLong`).
    pub fn add_long(&mut self, value: i64) -> Result<(), HashBuildError> {
        self.add_without_length_prefix(&value.to_be_bytes())
    }

    /// `addString`: the UTF-8 bytes with a length prefix.
    pub fn add_string(&mut self, value: &str) -> Result<(), HashBuildError> {
        self.add_byte_string(value.as_bytes())
    }

    /// `addByte`: one byte.
    pub fn add_byte(&mut self, value: u8) -> Result<(), HashBuildError> {
        self.add_without_length_prefix(&[value])
    }

    /// `addBool`: one byte, 1 for true and 0 for false.
    pub fn add_bool(&mut self, value: bool) -> Result<(), HashBuildError> {
        self.add_byte(u8::from(value))
    }

    /// `addStringSet`: the element count as an int, then every element as `addString`, in the order of Scala's natural
    /// `String` ordering (UTF-16 code units, which differs from UTF-8 byte order for characters above U+FFFF).
    ///
    /// [CANTON-NOTE: SEMANTICS] `set.toSeq.sorted[String]` in HashBuilder.scala; measured against the node's own builder
    /// in tests/oracle/canton-crypto (`setUtf16Order`).
    pub fn add_string_set(&mut self, values: &[&str]) -> Result<(), HashBuildError> {
        let mut sorted: Vec<&str> = values.to_vec();
        sorted.sort_by_key(|s| s.encode_utf16().collect::<Vec<u16>>());
        sorted.dedup();
        self.add_int(i32::try_from(sorted.len()).map_err(|_| HashBuildError::Length)?)?;
        for v in sorted {
            self.add_string(v)?;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<[u8; 32], HashBuildError> {
        let hasher = self.hasher.take().ok_or(HashBuildError::Closed)?;
        Ok(hasher.finalize().into())
    }
}

pub fn sha256_with_purpose(purpose_id: i32, payload: &[u8]) -> [u8; 32] {
    let mut hasher = PurposeHash::new(purpose_id);
    hasher
        .add_without_length_prefix(payload)
        .expect("new builder is open");
    hasher.finish().expect("new builder is open")
}

pub fn multihash_sha256_hex(digest: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.push(0x12);
    bytes.push(0x20);
    bytes.extend_from_slice(digest);
    hex::encode(bytes)
}

/// `HashPurpose.MultiTopologyTransaction`.
const PURPOSE_MULTI_TOPOLOGY_TRANSACTION: i32 = 55;

/// The hash one signature over several topology transactions signs (`MultiTransactionSignature.computeCombinedHash`), as a 34-byte
/// multihash: the transactions' hashes (each a 34-byte multihash), each once, sorted.
///
/// [CANTON-NOTE: SEMANTICS] Purpose 55; the number of distinct hashes, then each hash in ascending order, each with its byte length.
pub fn multi_topology_transaction_hash(
    transaction_hashes: &[Vec<u8>],
) -> Result<Vec<u8>, HashBuildError> {
    let unique: std::collections::BTreeSet<&[u8]> =
        transaction_hashes.iter().map(Vec::as_slice).collect();
    let mut hasher = PurposeHash::new(PURPOSE_MULTI_TOPOLOGY_TRANSACTION);
    hasher.add_int(i32::try_from(unique.len()).unwrap_or(i32::MAX))?;
    for hash in unique {
        hasher.add_byte_string(hash)?;
    }
    let digest = hasher.finish()?;
    let mut out = Vec::with_capacity(34);
    out.extend([0x12, 0x20]);
    out.extend_from_slice(&digest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_table_matches_the_extracted_source_rows() {
        let text = include_str!("../../../../tests/oracle/canton-hash/purposes.tsv");
        let rows: Vec<_> = text.lines().filter(|line| !line.is_empty()).collect();
        assert_eq!(rows.len(), PURPOSES.len());
        for (row, purpose) in rows.iter().zip(PURPOSES.iter()) {
            let mut parts = row.split('\t');
            let id: i32 = parts.next().unwrap().parse().unwrap();
            let scala_name = parts.next().unwrap();
            let description = parts.next().unwrap();
            assert_eq!(purpose.id, id);
            assert_eq!(purpose.scala_name, scala_name);
            assert_eq!(purpose.description, description);
        }
        assert!(purpose_by_description("AcsCommitment").unwrap().id == 22);
        assert!(PURPOSES.iter().all(|purpose| purpose.id != 18));
    }

    #[test]
    fn length_prefix_matches_the_fixture_and_finish_closes() {
        let text = include_str!("../../../../tests/oracle/canton-hash/length.tsv");
        for line in text.lines().filter(|line| !line.is_empty()) {
            let mut parts = line.split('\t');
            let purpose: i32 = parts.next().unwrap().parse().unwrap();
            let payload = hex::decode(parts.next().unwrap()).unwrap();
            let digest = parts.next().unwrap();
            let mut hasher = PurposeHash::new(purpose);
            hasher.add_byte_string(&payload).unwrap();
            let actual = hasher.finish().unwrap();
            assert_eq!(hex::encode(actual), digest, "purpose {purpose}");
            assert_eq!(hasher.finish(), Err(HashBuildError::Closed));
        }
    }

    #[test]
    fn vectors_match_the_independent_sha256_fixture() {
        let text = include_str!("../../../../tests/oracle/canton-hash/vectors.tsv");
        for line in text.lines().filter(|line| !line.is_empty()) {
            let mut parts = line.split('\t');
            let purpose: i32 = parts.next().unwrap().parse().unwrap();
            let payload = hex::decode(parts.next().unwrap()).unwrap();
            let digest = parts.next().unwrap();
            let multi = parts.next().unwrap();
            let actual = sha256_with_purpose(purpose, &payload);
            assert_eq!(hex::encode(actual), digest, "purpose {purpose}");
            assert_eq!(multihash_sha256_hex(&actual), multi);
        }
    }

    #[test]
    fn different_purposes_do_not_collide_on_the_same_payload() {
        let left = sha256_with_purpose(1, b"");
        let right = sha256_with_purpose(22, b"");
        assert_ne!(left, right);
    }
}
