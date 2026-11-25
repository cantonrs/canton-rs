//! The encrypted view message a participant sends to the participants that must confirm (G5 5.6e, S-NET-013).
//!
//! [CANTON-NOTE: SEMANTICS] Read from `EncryptedViewMessageFactory`, `EncryptedViewMessage` and `LightTransactionViewTree`:
//! - The plaintext of a view is a `LightTransactionViewTree` (v30, versioned 30): the transaction tree with only that view
//!   revealed, plus the hashes and key randomness of its direct subviews (none here). Several of them go in an
//!   `UncompressedViewTrees`, which is **Zstd**-compressed and then encrypted with **AES-128-GCM** under the *session key*, whose
//!   16 bytes are the randomness.
//! - The randomness is encrypted separately for every informee participant with their public encryption key (ECIES); the
//!   message lists these in `session_key_lookup`, each naming the fingerprint of the key it is for.
//! - `view_hashes` are the root hashes of the views; the submitting participant's signature over the transaction's root hash
//!   travels in the message for a top-level view. The message is an `EnvelopeContent` (v32) addressed to the participant.
//!
//! [CANTON-NOTE: LIMITATION] One view, no subviews, one recipient key per participant; the randomness, IVs and ephemeral keys
//! are arguments (the caller draws them from the operating system).
use crate::merkle_wire::GenTree;
use crate::topology_wire::versioned;
use crate::view_crypto::{aes_gcm_encrypt, ecies_encrypt};
use canton_proto::com::digitalasset::canton::crypto::v30::{
    AsymmetricEncrypted, EncryptionAlgorithmSpec, Signature, SymmetricKeyScheme,
};
use canton_proto::com::digitalasset::canton::protocol::v30::{
    LightTransactionViewTree, ViewHashAndKey, ViewType,
};
use canton_proto::com::digitalasset::canton::protocol::v32::{
    encrypted_multiple_views_message::UncompressedViewTrees, envelope_content::SomeEnvelopeContent,
    EncryptedMultipleViewsMessage, EnvelopeContent,
};
use prost::Message;

/// The version of `LightTransactionViewTree` (protocol version 37 uses the v30 message).
const LIGHT_VIEW_TREE_VERSION: i32 = 30;

/// The serialized `LightTransactionViewTree` of a tree that reveals exactly one view, without subviews.
pub fn light_view_tree(tree: &GenTree) -> Vec<u8> {
    versioned(
        LightTransactionViewTree {
            tree: Some(tree.proto.clone()),
            subview_hashes_and_keys: Vec::new(),
        }
        .encode_to_vec(),
        LIGHT_VIEW_TREE_VERSION,
    )
}

/// Like [`light_view_tree`], for a view that has subviews: each direct subview's hash and the randomness its message is encrypted with, so a
/// participant that reads this view can read the subview too.
pub fn light_view_tree_with_subviews(tree: &GenTree, subviews: &[(Vec<u8>, [u8; 16])]) -> Vec<u8> {
    versioned(
        LightTransactionViewTree {
            tree: Some(tree.proto.clone()),
            subview_hashes_and_keys: subviews
                .iter()
                .map(|(hash, key)| ViewHashAndKey {
                    view_hash: hash.clone(),
                    view_encryption_key_randomness: key.to_vec(),
                })
                .collect(),
        }
        .encode_to_vec(),
        LIGHT_VIEW_TREE_VERSION,
    )
}

/// A participant that must be able to read the view: its encryption key (DER SubjectPublicKeyInfo, P-256) and fingerprint.
pub struct Recipient<'a> {
    pub encryption_spki: &'a [u8],
    pub fingerprint: &'a str,
    /// The random inputs of the ECIES encryption of the randomness for this recipient.
    pub ecies_iv: [u8; 16],
    pub ecies_ephemeral_scalar: [u8; 32],
}

/// The envelope content of an encrypted view message for one view.
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
pub fn encrypted_view_message(
    light_tree_bytes: &[u8],
    view_hash: &[u8],
    randomness: &[u8; 16],
    aes_gcm_iv: &[u8; 12],
    recipients: &[Recipient],
    physical_synchronizer_id: &str,
    submitting_participant_signature: Signature,
) -> Vec<u8> {
    encrypted_view_message_signed(
        light_tree_bytes,
        view_hash,
        randomness,
        aes_gcm_iv,
        recipients,
        physical_synchronizer_id,
        Some(submitting_participant_signature),
    )
}

/// Like [`encrypted_view_message`]; a subview's message carries no signature (measured, S-NET-018).
pub fn encrypted_view_message_signed(
    light_tree_bytes: &[u8],
    view_hash: &[u8],
    randomness: &[u8; 16],
    aes_gcm_iv: &[u8; 12],
    recipients: &[Recipient],
    physical_synchronizer_id: &str,
    submitting_participant_signature: Option<Signature>,
) -> Vec<u8> {
    encrypted_view_message_of_type(
        ViewType::Transaction,
        light_tree_bytes,
        view_hash,
        randomness,
        aes_gcm_iv,
        recipients,
        physical_synchronizer_id,
        submitting_participant_signature,
    )
}

/// Like [`encrypted_view_message_signed`] for a view of any type: a reassignment's view carries its full `ReassignmentViewTree`
/// (versioned) as the one tree, with `view_type` `Unassignment` or `Assignment`.
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
pub fn encrypted_view_message_of_type(
    view_type: ViewType,
    light_tree_bytes: &[u8],
    view_hash: &[u8],
    randomness: &[u8; 16],
    aes_gcm_iv: &[u8; 12],
    recipients: &[Recipient],
    physical_synchronizer_id: &str,
    submitting_participant_signature: Option<Signature>,
) -> Vec<u8> {
    let uncompressed = UncompressedViewTrees {
        view_trees: vec![light_tree_bytes.to_vec()],
    }
    .encode_to_vec();
    let compressed = zstd::bulk::compress(&uncompressed, 0).expect("zstd compression in memory");
    let message = EncryptedMultipleViewsMessage {
        compressed_view_trees: aes_gcm_encrypt(randomness, aes_gcm_iv, &compressed),
        view_hashes: vec![view_hash.to_vec()],
        encryption_scheme: SymmetricKeyScheme::Aes128gcm as i32,
        submitting_participant_signature,
        session_key_lookup: recipients
            .iter()
            .map(|r| AsymmetricEncrypted {
                ciphertext: ecies_encrypt(
                    r.encryption_spki,
                    randomness,
                    &r.ecies_iv,
                    &r.ecies_ephemeral_scalar,
                )
                .expect("a valid P-256 key"),
                encryption_algorithm_spec: EncryptionAlgorithmSpec::EciesHkdfHmacSha256Aes128cbc
                    as i32,
                fingerprint: r.fingerprint.to_string(),
            })
            .collect(),
        physical_synchronizer_id: physical_synchronizer_id.to_string(),
        view_type: view_type as i32,
    };
    versioned(
        EnvelopeContent {
            some_envelope_content: Some(SomeEnvelopeContent::EncryptedMultipleViewsMessage(
                message,
            )),
        }
        .encode_to_vec(),
        32,
    )
}
