//! A session signing key's delegation (`SignatureDelegation`): the hash its long-term key signs and the period it is valid in.
use crate::hash::{HashBuildError, PurposeHash};
use crate::signing::{Delegation, KeySpec, Usage};

/// `HashPurpose.SessionKeyDelegation`.
const SESSION_KEY_DELEGATION: i32 = 56;

/// `CryptoKeyFormat.DerX509Spki` as the proto numbers it: the only format a session key has.
const DER_X509_SPKI: i32 = 4;

/// `CantonTimestamp.MaxValue` in microseconds.
const TIMESTAMP_MAX: i64 = 253_402_300_799_999_999;

fn key_spec_value(spec: KeySpec) -> i32 {
    match spec {
        KeySpec::EcCurve25519 => 1,
        KeySpec::EcP256 => 2,
        KeySpec::EcP384 => 3,
        KeySpec::EcSecp256k1 => 4,
        KeySpec::MlDsa65 => 5,
    }
}

fn usage_value(usage: Usage) -> i32 {
    match usage {
        Usage::Namespace => 1,
        Usage::SequencerAuthentication => 3,
        Usage::Protocol => 4,
        Usage::ProofOfOwnership => 5,
    }
}

/// `SignatureDelegation.generateHash` as a multihash: the session key's fingerprint, key spec, format and usages
/// (`encodeUsageForHash`: the sorted proto numbers, count first), the validity period (`fromInclusive` micros, length in seconds)
/// and the logical synchronizer id.
pub fn delegation_hash(
    synchronizer_id: &str,
    delegation: &Delegation,
) -> Result<Vec<u8>, HashBuildError> {
    let mut usages: Vec<i32> = delegation
        .session_key
        .usage
        .iter()
        .copied()
        .map(usage_value)
        .collect();
    usages.sort_unstable();
    let count = i32::try_from(usages.len()).map_err(|_| HashBuildError::Length)?;
    let mut encoded_usages = count.to_be_bytes().to_vec();
    for usage in usages {
        encoded_usages.extend_from_slice(&usage.to_be_bytes());
    }
    let mut validity = delegation.valid_from_micros.to_be_bytes().to_vec();
    validity.extend_from_slice(&i64::from(delegation.duration_seconds).to_be_bytes());
    let mut h = PurposeHash::new(SESSION_KEY_DELEGATION);
    h.add_string(&delegation.session_key.id)?;
    h.add_int(key_spec_value(delegation.session_key_spec))?;
    h.add_int(DER_X509_SPKI)?;
    h.add_byte_string(&encoded_usages)?;
    h.add_byte_string(&validity)?;
    h.add_string(synchronizer_id)?;
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&h.finish()?);
    Ok(out)
}

/// `SignatureDelegationValidityPeriod.covers`: from `fromInclusive` to `toExclusive`, which is `CantonTimestamp.MaxValue` when the
/// period would end after it.
pub fn covers(delegation: &Delegation, at_micros: i64) -> bool {
    let to_exclusive = i64::from(delegation.duration_seconds)
        .checked_mul(1_000_000)
        .and_then(|length| delegation.valid_from_micros.checked_add(length))
        .filter(|end| *end <= TIMESTAMP_MAX)
        .unwrap_or(TIMESTAMP_MAX);
    delegation.valid_from_micros <= at_micros && at_micros < to_exclusive
}
