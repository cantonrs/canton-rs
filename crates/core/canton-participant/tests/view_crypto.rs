//! G5 5.6e (S-NET-012): AES-128-GCM and the ECIES of the node, in both directions against the node's own classes.
//! Run through `scripts/verify-merkle-views.sh`: the console encrypts (and prints) with its own ciphers and decrypts what
//! Rust wrote to `tests/oracle/view-crypto/rust-vectors.txt`; this file checks Rust against both.
#![cfg(feature = "sequencer-tests")]
use canton_participant::view_crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, ecies_decrypt, ecies_encrypt,
};
use p256::pkcs8::EncodePublicKey;

fn var(name: &str) -> String {
    std::env::var(format!("CANTON_RS_{name}")).unwrap_or_else(|_| {
        panic!("CANTON_RS_{name} is not set: run scripts/verify-merkle-views.sh")
    })
}

/// The recipient's key: the P-256 scalar 1, 2, ..., 32 (the console script holds the same key as DER).
fn scalar() -> [u8; 32] {
    std::array::from_fn(|i| 1 + i as u8)
}

fn spki() -> Vec<u8> {
    p256::SecretKey::from_slice(&scalar())
        .unwrap()
        .public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

/// The 16 bytes both sides encrypt: the randomness of a session key.
const PLAIN: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];

#[test]
fn the_console_key_is_the_key_rust_uses() {
    assert_eq!(hex::encode(spki()), var("VE_SPKI"));
}

#[test]
fn rust_decrypts_what_the_node_encrypted_with_ecies() {
    let ciphertext = hex::decode(var("VE_ECIES_CT")).unwrap();
    assert_eq!(ecies_decrypt(&scalar(), &ciphertext).unwrap(), PLAIN);
}

#[test]
fn rust_decrypts_what_the_node_encrypted_with_aes_gcm() {
    let ciphertext = hex::decode(var("VE_GCM_CT")).unwrap();
    // the console encrypted the 16 bytes of randomness under the key made from the same 16 bytes
    assert_eq!(aes_gcm_decrypt(&PLAIN, &ciphertext).unwrap(), PLAIN);
}

/// What Rust writes for the node to decrypt (fixed IV and ephemeral key, so the file is reproducible).
fn rust_vectors() -> String {
    let ecies = ecies_encrypt(
        &spki(),
        &PLAIN,
        &[0x31; 16],
        &std::array::from_fn(|i| 0x41 + i as u8),
    )
    .unwrap();
    let gcm = aes_gcm_encrypt(&PLAIN, &[0x51; 12], b"a light view tree");
    format!(
        "ecies_ct={}\necies_pt={}\ngcm_ct={}\ngcm_pt={}\n",
        hex::encode(ecies),
        hex::encode(PLAIN),
        hex::encode(gcm),
        hex::encode(b"a light view tree")
    )
}

fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/oracle/view-crypto/rust-vectors.txt")
}

#[test]
fn the_node_decrypts_what_rust_encrypted_and_the_file_it_read_is_current() {
    // the console decrypted the file's ciphertexts; what it found must be the plaintexts
    assert_eq!(
        var("VE_DEC_ECIES"),
        hex::encode(PLAIN),
        "ECIES, decrypted by the node"
    );
    assert_eq!(
        var("VE_DEC_GCM"),
        hex::encode(b"a light view tree"),
        "AES-GCM, decrypted by the node"
    );
    // and the file is what Rust produces now (a drift in the cipher shows here, not as a stale pass)
    if std::env::var("UPDATE_VIEW_VECTORS").is_ok() {
        std::fs::write(vectors_path(), rust_vectors()).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(vectors_path()).unwrap(),
        rust_vectors(),
        "tests/oracle/view-crypto/rust-vectors.txt is stale: regenerate it with UPDATE_VIEW_VECTORS=1"
    );
}
