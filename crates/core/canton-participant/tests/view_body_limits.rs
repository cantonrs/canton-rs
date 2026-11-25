//! The bounds a participant applies to the encrypted view bodies it receives (internal review P-17): a few compressed bytes
//! must not decompress into more than the synchronizer's `max_request_size`.
#![allow(clippy::unwrap_used, reason = "integration test")]
#![cfg(feature = "sequencer-grpc")]
use canton_participant::reassignment_receive;
use canton_participant::sequencing_wire::MAX_DECOMPRESSED_BYTES;
use canton_participant::topology_wire::ParticipantIdentity;
use canton_participant::view_message::{encrypted_view_message_of_type, Recipient};
use canton_participant::view_receive::{decrypt_views, ReceiveError};
use canton_proto::com::digitalasset::canton::protocol::v30::ViewType;

fn envelope(view_type: ViewType, tree: &[u8], me: &ParticipantIdentity) -> Vec<u8> {
    let fingerprint = me.encryption_fingerprint();
    encrypted_view_message_of_type(
        view_type,
        tree,
        &[7u8; 34],
        &[1u8; 16],
        &[2u8; 12],
        &[Recipient {
            encryption_spki: me.encryption_spki(),
            fingerprint: &fingerprint,
            ecies_iv: [3u8; 16],
            ecies_ephemeral_scalar: [4u8; 32],
        }],
        "da::1220",
        None,
    )
}

#[test]
fn a_transaction_view_that_decompresses_past_the_bound_is_refused() {
    let me = ParticipantIdentity::generate("p17");
    let bomb = envelope(
        ViewType::Transaction,
        &vec![0u8; MAX_DECOMPRESSED_BYTES + 1],
        &me,
    );
    assert!(bomb.len() < 64 * 1024, "the bomb is small on the wire");
    let res = decrypt_views(&bomb, &me.encryption_fingerprint(), me.encryption_secret());
    assert_eq!(res.err(), Some(ReceiveError::NotDecompressible));
}

#[test]
fn a_reassignment_view_that_decompresses_past_the_bound_is_refused() {
    let me = ParticipantIdentity::generate("p17r");
    let bomb = envelope(
        ViewType::Assignment,
        &vec![0u8; MAX_DECOMPRESSED_BYTES + 1],
        &me,
    );
    let res =
        reassignment_receive::decrypt(&bomb, &me.encryption_fingerprint(), me.encryption_secret())
            .unwrap();
    assert_eq!(res.err().as_deref(), Some("the view does not decompress"));
}
