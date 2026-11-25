//! Prints the secp256k1 test vectors used by the lf-diff pools (`scripts/gen-lf-diff.py` reads
//! `tests/oracle/lf-vectors/secp256k1.tsv`). Deterministic: fixed secret keys, RFC 6979 signatures.
//!
//! Each row is `name<TAB>kind<TAB>hex` with kind `pk` (DER SubjectPublicKeyInfo), `sig` (DER signature) or `msg`.
//! The names say what the vector is; whether the JVM accepts it is measured by the differential, not assumed here.
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

fn key(byte: u8) -> SigningKey {
    let mut secret = [0u8; 32];
    secret[31] = byte;
    SigningKey::from_bytes(&secret.into()).expect("valid secret")
}

/// SubjectPublicKeyInfo for secp256k1 with the 65-byte uncompressed point: a fixed 23-byte header
/// (`ecPublicKey`, `secp256k1`, BIT STRING of 66 bytes with no unused bits) followed by the point.
fn spki(sk: &SigningKey) -> Vec<u8> {
    let point = sk.verifying_key().to_encoded_point(false);
    let mut out = hex::decode("3056301006072a8648ce3d020106052b8104000a034200")
        .expect("static uncompressed SPKI header hex is valid");
    out.extend_from_slice(point.as_bytes());
    out
}

fn spki_compressed(sk: &SigningKey) -> Vec<u8> {
    // SubjectPublicKeyInfo for secp256k1 with a 33-byte compressed point
    let point = sk.verifying_key().to_encoded_point(true);
    let mut out = hex::decode("3036301006072a8648ce3d020106052b8104000a032200")
        .expect("static compressed SPKI header hex is valid");
    out.extend_from_slice(point.as_bytes());
    out
}

/// The same signature with `s` replaced by `n - s` (still valid for textbook ECDSA, rejected by "low-S" verifiers).
fn high_s(sig: &Signature) -> Signature {
    let (r, s) = sig.split_scalars();
    Signature::from_scalars(r, -*s).expect("scalars")
}

fn row(name: &str, kind: &str, bytes: &[u8]) {
    println!("{name}\t{kind}\t{}", hex::encode(bytes));
}

fn main() {
    let (k1, k2) = (key(1), key(2));
    row("pk_k1", "pk", &spki(&k1));
    row("pk_k2", "pk", &spki(&k2));
    row("pk_k1_compressed", "pk", &spki_compressed(&k1));
    let mut off_curve = spki(&k1);
    let last = off_curve.len() - 1;
    off_curve[last] ^= 0x01; // y no longer matches x
    row("pk_k1_off_curve", "pk", &off_curve);

    let digest = Sha256::digest(b"daml digest");
    row("msg_digest", "msg", &digest);
    row("msg_short", "msg", &[0xde, 0xad, 0xbe, 0xef]);
    row("msg_long", "msg", &[0x11; 40]);

    // signatures over a 32-byte digest taken as is (`secp256k1WithEcdsaOnly`)
    let low: Signature = k1.sign_prehash(&digest).expect("sign");
    row("sig_k1_digest_low", "sig", low.to_der().as_bytes());
    row(
        "sig_k1_digest_high",
        "sig",
        high_s(&low).to_der().as_bytes(),
    );
    let other: Signature = k2.sign_prehash(&digest).expect("sign");
    row("sig_k2_digest_low", "sig", other.to_der().as_bytes());
    // signature over sha256(msg_short) (`secp256k1` hashes the message first)
    let hashed: Signature = k1
        .sign_prehash(&Sha256::digest([0xde, 0xad, 0xbe, 0xef]))
        .expect("sign");
    row("sig_k1_sha256_short_low", "sig", hashed.to_der().as_bytes());
    // signatures over the short and the long message used directly as the "digest"
    // (a 4-byte digest read as an integer is the same as the digest left-padded with zeros to 32 bytes)
    let mut padded = [0u8; 32];
    padded[28..].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let short_direct: Signature = k1.sign_prehash(&padded).expect("sign");
    row(
        "sig_k1_short_leftpadded",
        "sig",
        short_direct.to_der().as_bytes(),
    );
    let long_direct: Signature = k1.sign_prehash(&[0x11; 32]).expect("sign");
    row(
        "sig_k1_long_first32",
        "sig",
        long_direct.to_der().as_bytes(),
    );

    // right length byte, wrong content
    let mut garbled = low.to_der().as_bytes().to_vec();
    garbled[4] = 0x03; // r tag becomes something else
    row("sig_garbled_inner", "sig", &garbled);
    let mut flipped = low.to_der().as_bytes().to_vec();
    let n = flipped.len();
    flipped[n - 1] ^= 0x01;
    row("sig_k1_digest_last_byte_flipped", "sig", &flipped);
}
