//! Cryptographic Package ID calculation and verification via SHA-256.

use crate::error::DecodeError;
use sha2::{Digest, Sha256};

/// Computes the Package ID as the SHA-256 digest of raw payload bytes,
/// formatted as a lowercase 64-character hexadecimal string.
pub fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest).to_ascii_lowercase()
}

/// Verifies that the computed SHA-256 of `payload` matches `declared_hash`.
/// Returns `Ok(computed)` on match, or `Err(DecodeError::PackageIdMismatch)` on discrepancy.
pub fn verify_package_id(payload: &[u8], declared_hash: &str) -> Result<String, DecodeError> {
    let computed = compute_sha256(payload);
    let declared_norm = declared_hash.trim().to_ascii_lowercase();

    if computed != declared_norm {
        return Err(DecodeError::PackageIdMismatch {
            declared: declared_hash.to_string(),
            computed,
        });
    }

    Ok(computed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256_known_vector() {
        let empty_hash = compute_sha256(b"");
        assert_eq!(
            empty_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_verify_package_id_success() {
        let payload = b"sample payload bytes";
        let expected = compute_sha256(payload);
        assert_eq!(verify_package_id(payload, &expected).unwrap(), expected);
    }

    #[test]
    fn test_verify_package_id_mismatch() {
        let payload = b"sample payload bytes";
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let res = verify_package_id(payload, wrong_hash);
        assert!(matches!(res, Err(DecodeError::PackageIdMismatch { .. })));
    }
}
