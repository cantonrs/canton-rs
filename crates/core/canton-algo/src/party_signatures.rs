//! Whether a party authorized a hash with its external signatures (`InteractiveSubmission.verifySignatures`, Canton 3.7.2): the one
//! check the executing participant (`execute`) and every confirming participant (`AuthenticationValidator`) run.
//!
//! [CANTON-NOTE: SEMANTICS] A party authorizes the hash when signatures from at least `threshold` **distinct** keys of its registered
//! signing keys are valid; a signature by a key that is not the party's, or one that does not verify, counts as invalid and does not
//! refuse the others. From protocol version 35 a party may not send more signatures than it has keys with protocol usage
//! (`InteractiveSubmission.scala:222-230`); that is checked first.
use crate::signing::{PublicKey, Usage};
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use std::collections::BTreeSet;

/// Why a party's signatures do not authorize a hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAuthorized {
    /// More signatures than the party has keys with protocol usage.
    TooManySignatures {
        provided: usize,
        protocol_keys: usize,
    },
    /// Fewer distinct valid keys than the threshold.
    BelowThreshold {
        /// Distinct keys with a valid signature.
        valid: usize,
        /// Signatures that are by an unknown key or do not verify.
        invalid: usize,
        threshold: usize,
    },
}

impl NotAuthorized {
    /// The official refusal for `party` (`InteractiveSubmission.verifySignatures`); `hash_hint` is appended to the threshold refusal (the
    /// executing participant names the hash to sign, a confirming participant does not).
    pub fn message(&self, party: &str, hash_hint: &str) -> String {
        match self {
            Self::TooManySignatures {
                provided,
                protocol_keys,
            } => format!(
                "{provided} external signatures were provided, which is more than the number of registered signing keys ({protocol_keys}) with protocol usage for {party}"
            ),
            Self::BelowThreshold {
                valid,
                invalid,
                threshold,
            } => format!(
                "Received {valid} valid signatures from distinct keys ({invalid} invalid), but expected at least {threshold} valid for {party}.{hash_hint}"
            ),
        }
    }
}

/// Checks `signatures` of one party against its `keys` and `threshold`; `verify` says whether one signature by one key is valid for the
/// hash (the caller decides which form of the hash is signed).
pub fn verify_party_signatures(
    keys: &[PublicKey],
    threshold: usize,
    signatures: &[Signature],
    verify: impl Fn(&PublicKey, &Signature) -> bool,
) -> Result<(), NotAuthorized> {
    let protocol_keys = keys
        .iter()
        .filter(|k| k.usage.contains(&Usage::Protocol))
        .count();
    if signatures.len() > protocol_keys {
        return Err(NotAuthorized::TooManySignatures {
            provided: signatures.len(),
            protocol_keys,
        });
    }
    let mut valid_keys: BTreeSet<&str> = BTreeSet::new();
    let mut invalid = 0;
    for signature in signatures {
        match keys
            .iter()
            .find(|k| !signature.signed_by.is_empty() && k.id == signature.signed_by)
        {
            Some(key) if verify(key, signature) => {
                valid_keys.insert(key.id.as_str());
            }
            _ => invalid += 1,
        }
    }
    if valid_keys.len() < threshold {
        return Err(NotAuthorized::BelowThreshold {
            valid: valid_keys.len(),
            invalid,
            threshold,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{KeyFormat, KeySpec};

    fn key(id: &str) -> PublicKey {
        PublicKey {
            key_spec: KeySpec::EcCurve25519,
            format: KeyFormat::Raw,
            usage: BTreeSet::from([Usage::Protocol]),
            key: Vec::new(),
            id: id.to_string(),
        }
    }

    fn signature(by: &str, good: bool) -> Signature {
        Signature {
            signed_by: by.to_string(),
            signature: vec![u8::from(good)],
            ..Default::default()
        }
    }

    /// A stand-in for the cryptographic check: a signature whose byte is 1 verifies.
    fn verify(_: &PublicKey, s: &Signature) -> bool {
        s.signature == [1]
    }

    #[test]
    fn a_threshold_of_distinct_keys_authorizes() {
        let keys = [key("k1"), key("k2"), key("k3")];
        let two = [signature("k1", true), signature("k3", true)];
        assert_eq!(verify_party_signatures(&keys, 2, &two, verify), Ok(()));
    }

    #[test]
    fn the_same_key_twice_counts_once_and_unknown_or_bad_signatures_count_as_invalid() {
        let keys = [key("k1"), key("k2"), key("k3"), key("k4"), key("k5")];
        let signatures = [
            signature("k1", true),
            signature("k1", true),
            signature("k2", false),
            signature("stranger", true),
            signature("", true),
        ];
        assert_eq!(
            verify_party_signatures(&keys, 2, &signatures, verify),
            Err(NotAuthorized::BelowThreshold {
                valid: 1,
                invalid: 3,
                threshold: 2
            })
        );
    }

    #[test]
    fn no_signatures_do_not_authorize() {
        assert_eq!(
            verify_party_signatures(&[key("k1")], 1, &[], verify),
            Err(NotAuthorized::BelowThreshold {
                valid: 0,
                invalid: 0,
                threshold: 1
            })
        );
    }

    /// U-56 review R1-F1: two keys (threshold 1) and three signatures, one valid: refused before any signature is checked, with the official
    /// text; keys without protocol usage do not count.
    #[test]
    fn more_signatures_than_protocol_keys_are_refused() {
        let keys = [key("k1"), key("k2")];
        let three = [
            signature("k1", true),
            signature("k2", false),
            signature("k2", false),
        ];
        let refused = verify_party_signatures(&keys, 1, &three, verify);
        assert_eq!(
            refused,
            Err(NotAuthorized::TooManySignatures {
                provided: 3,
                protocol_keys: 2
            })
        );
        assert_eq!(
            refused.unwrap_err().message("alice::1220ab", ""),
            "3 external signatures were provided, which is more than the number of registered signing keys (2) with protocol usage for alice::1220ab"
        );
        let mut namespace_only = key("k3");
        namespace_only.usage = BTreeSet::from([Usage::Namespace]);
        assert_eq!(
            verify_party_signatures(&[key("k1"), namespace_only], 1, &three[..2], verify),
            Err(NotAuthorized::TooManySignatures {
                provided: 2,
                protocol_keys: 1
            })
        );
        assert_eq!(
            verify_party_signatures(&keys, 1, &three[..2], verify),
            Ok(())
        );
    }
}
