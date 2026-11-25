//! `LtHash16Blake3`: the homomorphic digest of a set of byte strings that Canton's ACS commitments are made of (G5 5.7, S-NET-027).
//!
//! [CANTON-NOTE: SEMANTICS] Read from `crypto/LtHash16Blake3.scala` (Canton 3.7.2) and compared with the node's class on fixed
//! inputs (`scripts/verify-merkle-views.sh`):
//! - the digest is a vector of **1024 unsigned 16-bit lanes** (2048 bytes, **little endian**);
//! - an element's contribution is `BLAKE3(element)` extended to **2048 bytes** (the XOF, not the 32-byte hash), read as the same
//!   lanes;
//! - `add` / `remove` / `union` / `remove_all` are lane-wise addition / subtraction **modulo 2^16**, so the digest of a set does not
//!   depend on the order the elements were added in, and removing an element undoes adding it.
//!
//! The caller has to make sure the collection really is a set: adding the same element twice changes the digest (and 2^16 times
//! rolls it over).

/// Number of 16-bit lanes.
pub const LANES: usize = 1024;
/// Size of the serialized digest in bytes.
pub const BYTES: usize = LANES * 2;

/// A set digest.
#[derive(Clone, PartialEq, Eq)]
pub struct LtHash16 {
    lanes: [u16; LANES],
}

impl std::fmt::Debug for LtHash16 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LtHash16({}…)", hex::encode(&self.to_bytes()[..8]))
    }
}

impl Default for LtHash16 {
    fn default() -> Self {
        Self::empty()
    }
}

impl LtHash16 {
    /// The digest of the empty set (all zero).
    pub fn empty() -> Self {
        LtHash16 { lanes: [0; LANES] }
    }

    /// The digest from its 2048 serialized bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BYTES {
            return None;
        }
        let mut lanes = [0u16; LANES];
        for (i, lane) in lanes.iter_mut().enumerate() {
            *lane = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
        }
        Some(LtHash16 { lanes })
    }

    /// The 2048 serialized bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.lanes.iter().flat_map(|l| l.to_le_bytes()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.lanes.iter().all(|l| *l == 0)
    }

    fn of_element(element: &[u8]) -> [u16; LANES] {
        let mut out = [0u8; BYTES];
        blake3::Hasher::new()
            .update(element)
            .finalize_xof()
            .fill(&mut out);
        Self::from_bytes(&out).expect("2048 bytes").lanes
    }

    /// Adds an element.
    pub fn add(&mut self, element: &[u8]) {
        let other = Self::of_element(element);
        for (lane, o) in self.lanes.iter_mut().zip(other) {
            *lane = lane.wrapping_add(o);
        }
    }

    /// Removes an element.
    pub fn remove(&mut self, element: &[u8]) {
        let other = Self::of_element(element);
        for (lane, o) in self.lanes.iter_mut().zip(other) {
            *lane = lane.wrapping_sub(o);
        }
    }

    /// Adds every element of `other` (the caller makes sure the two sets are disjoint).
    pub fn union(&mut self, other: &LtHash16) {
        for (lane, o) in self.lanes.iter_mut().zip(other.lanes) {
            *lane = lane.wrapping_add(o);
        }
    }

    /// Removes every element of `other` (the caller makes sure it is a subset).
    pub fn remove_all(&mut self, other: &LtHash16) {
        for (lane, o) in self.lanes.iter_mut().zip(other.lanes) {
            *lane = lane.wrapping_sub(o);
        }
    }
}

/// The bytes of one **digest element** of Canton 3.7.2's ACS commitment: a contract (`contract_id` as the node prints it, a hex
/// string), its reassignment counter and an **ordered pair of parties**.
///
/// [CANTON-NOTE: SEMANTICS] From `DigestOps.singleDigestByteArray`: `utf8(coid) ++ encodeLong(rc) ++ encodeString(party1) ++
/// encodeString(party2)`; `encodeLong` is 8 bytes big endian and `encodeString` a 4-byte big-endian length and the UTF-8 bytes.
pub fn digest_element(
    contract_id: &str,
    reassignment_counter: i64,
    party1: &str,
    party2: &str,
) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, s: &str) {
        out.extend((s.len() as i32).to_be_bytes());
        out.extend(s.as_bytes());
    }
    let mut out = contract_id.as_bytes().to_vec();
    out.extend(reassignment_counter.to_be_bytes());
    string(&mut out, party1);
    string(&mut out, party2);
    out
}

/// The two parties in the order `DigestOps.orderedPartyPair` puts them (the smaller first, by Scala's `String` comparison: UTF-16
/// code units).
pub fn ordered_pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    let key = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
    if key(a) < key(b) {
        (a, b)
    } else {
        (b, a)
    }
}

/// What a participant sends as the commitment (`AcsCommitment.digest`): the multihash of `HashPurpose.HashedAcsCommitment` (34) over
/// the 2048 bytes of the set digest. [CANTON-NOTE: SEMANTICS] The set digest itself never leaves the participant.
pub fn commitment_digest(set_digest: &LtHash16) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend(canton_algo::hash::sha256_with_purpose(
        34,
        &set_digest.to_bytes(),
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_of_a_set_does_not_depend_on_the_order() {
        let (mut ab, mut ba) = (LtHash16::empty(), LtHash16::empty());
        ab.add(b"a");
        ab.add(b"b");
        ba.add(b"b");
        ba.add(b"a");
        assert_eq!(ab, ba);
        assert!(!ab.is_empty());
    }

    #[test]
    fn removing_an_element_undoes_adding_it() {
        let mut h = LtHash16::empty();
        h.add(b"a");
        let just_a = h.clone();
        h.add(b"b");
        h.remove(b"b");
        assert_eq!(h, just_a);
        h.remove(b"a");
        assert!(h.is_empty());
    }

    #[test]
    fn the_serialized_form_round_trips_and_has_the_node_size() {
        let mut h = LtHash16::empty();
        h.add(b"contract");
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 2048);
        assert_eq!(LtHash16::from_bytes(&bytes), Some(h));
        assert_eq!(LtHash16::from_bytes(&bytes[..2047]), None);
    }

    #[test]
    fn adding_the_same_element_twice_changes_the_digest() {
        let mut once = LtHash16::empty();
        once.add(b"a");
        let mut twice = once.clone();
        twice.add(b"a");
        assert_ne!(once, twice, "the caller has to make sure it is a set");
    }
}
