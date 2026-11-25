//! The two ciphers a confirmation request's encrypted views use (G5 5.6e, S-NET-012): AES-128-GCM and the ECIES of the node.
//!
//! [CANTON-NOTE: SEMANTICS] Read from `JcePureCrypto` (and BouncyCastle's `IESEngine`, which the node's JCE provider is);
//! both are compared with the node's own implementation in `tests/view_crypto.rs`, in both directions:
//! - **Symmetric** (`SymmetricKeyScheme.Aes128Gcm`): AES-128-GCM with a 12-byte random IV, 128-bit tag; the ciphertext is
//!   `iv ++ ciphertext ++ tag`. The key of a view is the 16 bytes of *randomness* themselves (`createSymmetricKey` takes the
//!   raw bytes; there is no key derivation).
//! - **Asymmetric** (`EncryptionAlgorithmSpec.EciesHkdfHmacSha256Aes128Cbc`, the node's name for BouncyCastle's
//!   `ECIESwithSHA256andAES-CBC`, curve P-256): `iv(16) ++ V ++ C ++ T` with `V` the ephemeral public key as an uncompressed
//!   point (65 bytes), `C` the AES-128-CBC (PKCS#7) ciphertext and `T` the HMAC-SHA256 tag. The shared secret `Z` is the
//!   x-coordinate of the ECDH result; the keys come from KDF2 (SHA-256, counter from 1, no derivation vector) over `V ++ Z`:
//!   16 bytes of cipher key, then 64 bytes of MAC key. The tag covers `C ++ P2 ++ length of P2 in bits (8 bytes)`, with an empty `P2`.
//!
//! [CANTON-NOTE: LIMITATION] Only P-256 and these two schemes; the random inputs (IV, ephemeral key) are arguments so that the
//! tests can fix them, and the callers draw them from the operating system.
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// `iv ++ ciphertext ++ tag` of `plaintext` under the 16-byte `key`.
pub fn aes_gcm_encrypt(key: &[u8; 16], iv: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new(key.into());
    let mut out = iv.to_vec();
    out.extend(
        cipher
            .encrypt(Nonce::from_slice(iv), plaintext)
            .expect("AES-GCM encryption of an in-memory buffer"),
    );
    out
}

/// The plaintext of `iv ++ ciphertext ++ tag`, or `None` when the tag does not verify.
pub fn aes_gcm_decrypt(key: &[u8; 16], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 12 + 16 {
        return None;
    }
    let (iv, rest) = ciphertext.split_at(12);
    Aes128Gcm::new(key.into())
        .decrypt(Nonce::from_slice(iv), rest)
        .ok()
}

/// KDF2 (IEEE 1363a) with SHA-256: `SHA256(secret ++ counter ++ info)` for the counter 1, 2, ..., cut to `length`.
fn kdf2(secret: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 1u32;
    while out.len() < length {
        let mut h = Sha256::new();
        h.update(secret);
        h.update(counter.to_be_bytes());
        h.update(info);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

fn mac_over(mac_key: &[u8], ciphertext: &[u8]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("any HMAC key length");
    mac.update(ciphertext);
    // the (empty) encoding vector P2 and its length in bits, which BouncyCastle adds whenever an ephemeral key is sent
    mac.update(&0u64.to_be_bytes());
    mac
}

fn mac_tag(mac_key: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    mac_over(mac_key, ciphertext).finalize().into_bytes().into()
}

const POINT: usize = 65;
const TAG: usize = 32;

/// `iv ++ V ++ C ++ T`: `plaintext` for the owner of the public key `recipient_spki` (DER SubjectPublicKeyInfo, P-256).
pub fn ecies_encrypt(
    recipient_spki: &[u8],
    plaintext: &[u8],
    iv: &[u8; 16],
    ephemeral_scalar: &[u8; 32],
) -> Option<Vec<u8>> {
    let recipient = p256::PublicKey::from_public_key_der(recipient_spki).ok()?;
    let ephemeral = p256::SecretKey::from_slice(ephemeral_scalar).ok()?;
    let v = ephemeral.public_key().to_sec1_point(false);
    let z = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let mut vz = v.as_bytes().to_vec();
    vz.extend_from_slice(z.raw_secret_bytes());
    let keys = kdf2(&vz, &[], 16 + 64);
    let c =
        Aes128CbcEnc::new(keys[..16].into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let t = mac_tag(&keys[16..], &c);
    let mut out = iv.to_vec();
    out.extend_from_slice(v.as_bytes());
    out.extend_from_slice(&c);
    out.extend_from_slice(&t);
    Some(out)
}

/// The plaintext of an [`ecies_encrypt`] output for the owner of `recipient_scalar`, or `None` when it does not verify.
pub fn ecies_decrypt(recipient_scalar: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 16 + POINT + 16 + TAG {
        return None;
    }
    let secret = p256::SecretKey::from_slice(recipient_scalar).ok()?;
    let (iv, rest) = ciphertext.split_at(16);
    let (v, rest) = rest.split_at(POINT);
    let (c, t) = rest.split_at(rest.len() - TAG);
    let ephemeral = p256::PublicKey::from_sec1_bytes(v).ok()?;
    let z = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), ephemeral.as_affine());
    let mut vz = v.to_vec();
    vz.extend_from_slice(z.raw_secret_bytes());
    let keys = kdf2(&vz, &[], 16 + 64);
    // `verify_slice` compares in constant time
    mac_over(&keys[16..], c).verify_slice(t).ok()?;
    Aes128CbcDec::new(keys[..16].into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(c)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_round_trips_and_rejects_a_flipped_bit() {
        let key = [7u8; 16];
        let ct = aes_gcm_encrypt(&key, &[1; 12], b"a view");
        assert_eq!(aes_gcm_decrypt(&key, &ct).unwrap(), b"a view");
        let mut bad = ct;
        *bad.last_mut().unwrap() ^= 1;
        assert!(aes_gcm_decrypt(&key, &bad).is_none());
    }

    #[test]
    fn ecies_round_trips_and_rejects_a_flipped_bit() {
        use p256::pkcs8::EncodePublicKey;
        let scalar = [3u8; 32];
        let spki = p256::SecretKey::from_slice(&scalar)
            .unwrap()
            .public_key()
            .to_public_key_der()
            .unwrap();
        let ct = ecies_encrypt(spki.as_bytes(), b"randomness", &[9; 16], &[5; 32]).unwrap();
        assert_eq!(ecies_decrypt(&scalar, &ct).unwrap(), b"randomness");
        let mut bad = ct;
        bad[20] ^= 1;
        assert!(ecies_decrypt(&scalar, &bad).is_none());
    }
}
