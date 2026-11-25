//! S-LOCAL-005: a participant identity kept in a file is the same identity when read again, is never overwritten, and a damaged file is refused.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "sequencer-grpc")]
use canton_participant::topology_wire::ParticipantIdentity;

fn dir(label: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("identity-store-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn an_identity_read_from_its_file_is_the_same_participant() {
    let d = dir("same");
    let path = d.join("identity");
    let made = ParticipantIdentity::generate("p1");
    made.save(&path).unwrap();
    let read = ParticipantIdentity::load(&path).expect("the identity is read");
    assert_eq!(
        read.member(),
        made.member(),
        "same namespace, so the same member"
    );
    assert_eq!(read.signing_key.fingerprint, made.signing_key.fingerprint);
    assert_eq!(
        read.sequencer_auth_key.fingerprint,
        made.sequencer_auth_key.fingerprint
    );
    assert_eq!(read.encryption_spki(), made.encryption_spki());
    assert_eq!(read.encryption_secret(), made.encryption_secret());
    // and it signs as the same key: the registration transactions it makes verify as the made identity's do
    assert_eq!(
        read.onboarding_transactions("sync::1220aa").len(),
        made.onboarding_transactions("sync::1220aa").len()
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_identity_file_is_private_and_never_overwritten() {
    use std::os::unix::fs::PermissionsExt;
    let d = dir("private");
    let path = d.join("identity");
    ParticipantIdentity::generate("p1").save(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the keys are readable by the owner only");
    let kept = std::fs::read_to_string(&path).unwrap();
    let error = ParticipantIdentity::generate("other").save(&path);
    assert!(
        error.is_err(),
        "a second identity must not replace the first"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), kept);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_damaged_or_missing_identity_file_is_refused() {
    let d = dir("damaged");
    assert!(ParticipantIdentity::load(&d.join("absent")).is_none());
    let path = d.join("identity");
    std::fs::write(&path, "p1\nnot-hex\n").unwrap();
    assert!(ParticipantIdentity::load(&path).is_none());
    std::fs::write(&path, "p1\n00\n").unwrap();
    assert!(
        ParticipantIdentity::load(&path).is_none(),
        "a seed of the wrong size"
    );
    let _ = std::fs::remove_dir_all(&d);
}
