//! S-TX-001 part 4b: `SECP256K1_BOOL`, `SECP256K1_WITH_ECDSA_BOOL`, `SECP256K1_VALIDATE_KEY`.
//!
//! The reference is the JVM 3.7.2 (`com.daml.crypto.MessageSignaturePrototype.Secp256k1`, whose source is not in the
//! pinned tree), so every rule below is checked by the differential on the vectors of
//! `tests/oracle/lf-vectors/secp256k1.tsv` (made by `bin/secp-vectors.rs`), not read off a specification.
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

use crate::{hex_bytes, EvalError};

fn crypto_err(what: &str, detail: impl std::fmt::Display) -> EvalError {
    EvalError::Arithmetic(format!("crypto: {what}: {detail}"))
}

/// One DER element: `(tag, value, rest)`; definite lengths only, at most 4 length bytes.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&l0, b) = b.split_first()?;
    let (len, b) = if l0 < 0x80 {
        (l0 as usize, b)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || b.len() < n {
            return None;
        }
        (
            b[..n].iter().fold(0usize, |a, x| (a << 8) | *x as usize),
            &b[n..],
        )
    };
    if b.len() < len {
        return None;
    }
    Some((tag, &b[..len], &b[len..]))
}

/// The DER bytes of a public key whose outer header passes Speedy's `ECPublicKeyUtil.checkDerHeader`: a SEQUENCE
/// whose length is canonical DER (short form below 0x80, else 1 to 3 length bytes without a leading zero) and
/// covers the rest of the key exactly. Anything else is `MalformedKey` before any parser sees it.
fn key_der(key_hex: &str) -> Result<Vec<u8>, EvalError> {
    let der = hex_bytes(key_hex)?;
    let malformed = |why: &str| Err(crypto_err("malformed key", why));
    let [tag, first, rest @ ..] = der.as_slice() else {
        return malformed("public key is too short to contain a DER header");
    };
    if *tag != 0x30 {
        return malformed("public key does not start with DER SEQUENCE tag 0x30");
    }
    let (header, content) = if *first < 0x80 {
        (2, usize::from(*first))
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 3 || rest.len() < n {
            return malformed("public key has an invalid DER length encoding");
        }
        if rest[0] == 0 {
            return malformed("public key has a non-canonical DER length");
        }
        let length = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        if length < 0x80 {
            return malformed("public key has a non-canonical DER length");
        }
        (2 + n, length)
    };
    if der.len() != header + content {
        return malformed("public key length does not match its declared DER length");
    }
    Ok(der)
}

/// A public key as the JVM accepts it: a secp256k1 key, or a well-formed key of another named curve (which can only fail to
/// verify).
enum ParsedKey {
    K1(VerifyingKey),
    ForeignCurve,
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_SECP256K1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];

/// A DER SubjectPublicKeyInfo holding a point on secp256k1, or a key of another named curve.
///
/// [CANTON-NOTE: SEMANTICS] Measured on the JVM (tests/oracle/lf-fatal, AT-C04), beyond the two failures below:
/// - a SubjectPublicKeyInfo whose algorithm is not `ecPublicKey` (an Ed25519 key) is `Malformed public key`;
/// - a secp256k1 key whose point has an unknown format byte (not 02, 03 or 04) is `Malformed public key`;
/// - the BIT STRING's "unused bits" byte is not checked (a key with it set to 1 verifies like the normal one);
/// - a valid key of another named curve (P-256) is accepted and the signature simply does not verify (`False`).
///
/// [CANTON-NOTE: LIMITATION] A point of another curve is not checked for being on that curve (no arithmetic for it here), so
/// an off-curve P-256 point is `False` here and unmeasured on the JVM.
fn parse_key(key_hex: &str) -> Result<ParsedKey, EvalError> {
    let der = key_der(key_hex)?;
    if let Some(parsed) = parse_spki_tolerant(&der) {
        return parsed;
    }
    VerifyingKey::from_public_key_der(&der)
        .map(ParsedKey::K1)
        .map_err(|e| {
            // [CANTON-NOTE: SEMANTICS] The JVM tells two failures apart (tests/oracle/lf-fatal): a DER SubjectPublicKeyInfo
            // that is well formed but holds a point off the curve is `Invalid byte encoding format`; anything else that
            // does not parse is `Malformed public key`.
            if k256::pkcs8::spki::SubjectPublicKeyInfoRef::try_from(der.as_slice()).is_ok() {
                crypto_err("invalid byte encoding format", e)
            } else {
                crypto_err("malformed key", e)
            }
        })
}

/// SEQUENCE { SEQUENCE { OID, params }, BIT STRING } that fills `der` exactly, or `None` (the strict decoder then decides).
fn parse_spki_tolerant(der: &[u8]) -> Option<Result<ParsedKey, EvalError>> {
    let (t, body, rest) = tlv(der)?;
    if t != 0x30 || !rest.is_empty() {
        return None;
    }
    let (t1, alg, after_alg) = tlv(body)?;
    let (t2, bits, tail) = tlv(after_alg)?;
    if t1 != 0x30 || t2 != 0x03 || !tail.is_empty() || bits.is_empty() {
        return None;
    }
    let (to, oid, params) = tlv(alg)?;
    if to != 0x06 {
        return None;
    }
    if oid != OID_EC_PUBLIC_KEY {
        return Some(Err(crypto_err(
            "malformed key",
            "algorithm is not ecPublicKey",
        )));
    }
    let (tp, curve, _) = tlv(params)?;
    if tp != 0x06 {
        return None;
    }
    if curve != OID_SECP256K1 {
        return Some(Ok(ParsedKey::ForeignCurve));
    }
    let point = &bits[1..]; // the unused-bits byte is ignored, as the JVM does
    let shaped = (point.len() == 65 && point[0] == 4)
        || (point.len() == 33 && (point[0] == 2 || point[0] == 3));
    if !shaped {
        return Some(Err(crypto_err("malformed key", "unknown point format")));
    }
    Some(
        VerifyingKey::from_sec1_bytes(point)
            .map(ParsedKey::K1)
            .map_err(|e| crypto_err("invalid byte encoding format", e)),
    )
}

/// `[CANTON-NOTE: SEMANTICS]` The digest is read as a big-endian integer: shorter than 32 bytes it is left-padded with
/// zeros, longer it is cut to its leftmost 32 bytes (the ECDSA `bits2int` rule for a 256-bit group order).
fn digest32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if bytes.len() >= 32 {
        out.copy_from_slice(&bytes[..32]);
    } else {
        out[32 - bytes.len()..].copy_from_slice(bytes);
    }
    out
}

/// The order n of secp256k1, big endian.
const ORDER_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// One DER element with the strictness of Bouncy Castle's `ASN1InputStream`: a definite length in its shortest form (the long
/// form only from 0x80 up, no leading zero length byte). `(tag, value, rest)`.
fn strict_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&l0, b) = b.split_first()?;
    let (len, b) = if l0 < 0x80 {
        (l0 as usize, b)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || b.len() < n || b[0] == 0 {
            return None;
        }
        let len = b[..n].iter().fold(0usize, |a, x| (a << 8) | *x as usize);
        if len < 0x80 {
            return None;
        }
        (len, &b[n..])
    };
    if b.len() < len {
        return None;
    }
    Some((tag, &b[..len], &b[len..]))
}

/// The two scalars `(r, s)` of a signature that the JVM's decoder accepts, as 32-byte big-endian values, or `None` when it
/// ends the script with `Malformed signature`.
///
/// [CANTON-NOTE: SEMANTICS] Measured on the JVM with the 476 Wycheproof vectors (tests/oracle/lf-vectors/wycheproof, U-8) and the
/// earlier AT-C05 cases: once the Daml wrapper has accepted the bytes as DER, the signature must be EXACTLY a SEQUENCE of two
/// INTEGERs that fills the bytes, every element in the shortest DER form (minimal length, no needless leading 00, no missing
/// sign byte), each integer non-negative and below the group order n. Anything else (another tag such as a BIT STRING, a
/// nested SEQUENCE or an OCTET STRING, one or three elements, an empty integer, a negative or out-of-range value) is the
/// uncatchable `Malformed signature`; the value zero is accepted by the decoder and simply does not verify.
fn decode_signature(sig: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let (0x30, body, rest) = strict_tlv(sig)? else {
        return None;
    };
    if !rest.is_empty() {
        return None;
    }
    let mut scalars: Vec<[u8; 32]> = Vec::new();
    let mut cur = body;
    while !cur.is_empty() {
        let (tag, v, after) = strict_tlv(cur)?;
        if tag != 0x02 || v.is_empty() || v[0] & 0x80 != 0 {
            return None;
        }
        if v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
            return None;
        }
        let mag = if v[0] == 0 { &v[1..] } else { v };
        if mag.len() > 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out[32 - mag.len()..].copy_from_slice(mag);
        if out >= ORDER_N {
            return None;
        }
        scalars.push(out);
        cur = after;
    }
    match scalars.as_slice() {
        [r, s] => Some((*r, *s)),
        _ => None,
    }
}

pub(crate) fn verify(
    sig_hex: &str,
    msg_hex: &str,
    key_hex: &str,
    hash_message: bool,
) -> Result<bool, EvalError> {
    let sig_der = hex_bytes(sig_hex)?;
    let message = hex_bytes(msg_hex)?;
    let parsed = parse_key(key_hex)?;
    // [CANTON-NOTE: SEMANTICS] For a signature the Daml wrapper has already accepted as DER, a signature the decoder rejects is the
    // uncatchable `Malformed signature` (see `decode_signature`); two valid INTEGERs that are not a valid ECDSA signature (zero)
    // are "does not verify" (`False`). A malformed KEY is an error (above).
    let Some((r, s)) = decode_signature(&sig_der) else {
        return Err(crypto_err("malformed signature", sig_hex));
    };
    let Ok(signature) = Signature::from_scalars(r, s) else {
        return Ok(false);
    };
    let digest = if hash_message {
        digest32(&Sha256::digest(&message))
    } else {
        digest32(&message)
    };
    // [CANTON-NOTE: SEMANTICS] The JVM accepts a "high-S" signature (s > n/2) as valid (measured: `sig_k1_digest_high`),
    // but k256 rejects it, so `s` is normalised first: (r, s) and (r, n - s) verify the same message.
    let signature = signature.normalize_s().unwrap_or(signature);
    match parsed {
        ParsedKey::K1(key) => Ok(key.verify_prehash(&digest, &signature).is_ok()),
        ParsedKey::ForeignCurve => Ok(false),
    }
}

/// The fixed DER prefixes of a secp256k1 SubjectPublicKeyInfo: `ecPublicKey` + `secp256k1` + a BIT STRING holding an
/// uncompressed (65-byte) or compressed (33-byte) point.
const SPKI_UNCOMPRESSED_PREFIX: &str = "3056301006072a8648ce3d020106052b8104000a034200";
const SPKI_COMPRESSED_PREFIX: &str = "3036301006072a8648ce3d020106052b8104000a032200";

/// `SECP256K1_VALIDATE_KEY`.
/// [CANTON-NOTE: SEMANTICS] Measured on JVM 3.7.2 (tests/oracle/key-diff `validateKey*`): a well-formed key is `True`
/// (compressed points too); a key whose DER is a secp256k1 SubjectPublicKeyInfo but whose point is NOT on the curve is
/// `False`; bytes that are not such a structure at all are a Crypto error.
pub(crate) fn validate_key(key_hex: &str) -> Result<bool, EvalError> {
    let der = key_der(key_hex)?;
    if VerifyingKey::from_public_key_der(&der).is_ok() {
        return Ok(true);
    }
    let shaped = (key_hex.starts_with(SPKI_UNCOMPRESSED_PREFIX) && der.len() == 88)
        || (key_hex.starts_with(SPKI_COMPRESSED_PREFIX) && der.len() == 56);
    if shaped {
        Ok(false)
    } else {
        Err(crypto_err("malformed key", key_hex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G_UNCOMPRESSED: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    const SIG_R1_S1: &str = "3006020101020101";

    /// Speedy `ECPublicKeyUtil.checkDerHeader`: the outer SEQUENCE length must be canonical DER and cover the key
    /// exactly, or the key is `MalformedKey`.
    #[test]
    fn a_key_with_a_non_canonical_der_header_is_malformed() {
        let body = &SPKI_UNCOMPRESSED_PREFIX[4..];
        let canonical = format!("3056{body}{G_UNCOMPRESSED}");
        assert!(!verify(SIG_R1_S1, "00", &canonical, true).unwrap());
        assert!(validate_key(&canonical).unwrap());
        for key in [
            format!("308156{body}{G_UNCOMPRESSED}"),
            format!("30820056{body}{G_UNCOMPRESSED}"),
            format!("3056{body}{G_UNCOMPRESSED}00"),
        ] {
            let err = verify(SIG_R1_S1, "00", &key, true).unwrap_err();
            assert!(err.to_string().contains("malformed key"), "{key}: {err}");
            let err = validate_key(&key).unwrap_err();
            assert!(err.to_string().contains("malformed key"), "{key}: {err}");
        }
    }
}
