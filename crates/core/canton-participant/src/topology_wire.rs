//! Canton's topology transactions as they go over the wire, built and signed the way the node builds them (G5 5.3, S-NET-002).
//!
//! The messages are the generated ones (`canton-proto`); this module is the part the `.proto` files do not say: how a
//! transaction is wrapped in a versioned message, what is hashed and signed, how a fingerprint is made. Each rule below was read
//! from the Canton 3.7.2 sources and then checked by rebuilding a participant's own identity transactions byte for byte
//! (`tests/sequencer_connect.rs`).
//!
//! [CANTON-NOTE: SEMANTICS]
//! - A **fingerprint** is the multihash (`1220` + SHA-256) of `HashPurpose.PublicKeyFingerprint` (12) over the key's
//!   *fingerprint data*: for an Ed25519 key that is the **raw 32-byte key**, not the DER SubjectPublicKeyInfo the key is stored
//!   in (Canton kept the old fingerprints when it changed the key format; `dataForFingerprintO`). A namespace *is* the
//!   fingerprint of its root key.
//! - A topology transaction travels as `UntypedVersionedMessage { data, version }` twice: the `TopologyTransaction` inside
//!   the `SignedTopologyTransaction.transaction` bytes with version 31, the `SignedTopologyTransaction` itself with version 30.
//! - A signature covers the multihash of `HashPurpose.TopologyTransactionSignature` over the *versioned transaction bytes*
//!   (the inner wrapper, not the bare `TopologyTransaction`); the signature is Ed25519 in `CONCAT` format.
//!
//! [CANTON-NOTE: LIMITATION] Only the mappings an onboarding needs (`NamespaceDelegation`, `OwnerToKeyMapping`), the
//! `PartyToParticipant` of a party hosted by its own participant (G5 5.6d-3), and Ed25519 signing keys are built here; versions 31/30 are the ones the node writes for protocol version 37.
use canton_proto::com::digitalasset::canton::crypto::v30::{
    public_key::Key as PublicKeyKind, CryptoKeyFormat, EncryptionKeySpec, EncryptionPublicKey,
    PublicKey, Signature, SignatureFormat, SigningAlgorithmSpec, SigningKeySpec, SigningKeyUsage,
    SigningPublicKey,
};
use canton_proto::com::digitalasset::canton::protocol::v30::{
    namespace_delegation::{CanSignAllMappings, Restriction},
    topology_mapping::Mapping,
    NamespaceDelegation, OwnerToKeyMapping, SignedTopologyTransaction,
    SynchronizerTrustCertificate, TopologyMapping, TopologyTransaction,
};
use canton_proto::com::digitalasset::canton::version::v1::{
    untyped_versioned_message::Wrapper, UntypedVersionedMessage,
};
use prost::Message;

/// `HashPurpose.PublicKeyFingerprint`.
const PURPOSE_PUBLIC_KEY_FINGERPRINT: i32 = 12;
/// `HashPurpose.TopologyTransactionSignature`.
const PURPOSE_TOPOLOGY_TRANSACTION_SIGNATURE: i32 = 11;
/// The version of the `TopologyTransaction` message inside a signed transaction (protocol version 37).
pub const TOPOLOGY_TRANSACTION_VERSION: i32 = 31;
/// The version of the `SignedTopologyTransaction` message (protocol version 37).
pub const SIGNED_TOPOLOGY_TRANSACTION_VERSION: i32 = 30;

fn multihash(digest: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&digest);
    out
}

/// The fingerprint of a key given its fingerprint data (the raw key for Ed25519, see the module documentation).
pub fn fingerprint(data: &[u8]) -> String {
    hex::encode(multihash(canton_algo::hash::sha256_with_purpose(
        PURPOSE_PUBLIC_KEY_FINGERPRINT,
        data,
    )))
}

/// `UntypedVersionedMessage { data, version }`, serialized.
pub fn versioned(data: Vec<u8>, version: i32) -> Vec<u8> {
    UntypedVersionedMessage {
        wrapper: Some(Wrapper::Data(data)),
        version,
    }
    .encode_to_vec()
}

/// The data of a serialized `UntypedVersionedMessage` and its version.
pub fn unversioned(bytes: &[u8]) -> Option<(Vec<u8>, i32)> {
    let m = UntypedVersionedMessage::decode(bytes).ok()?;
    match m.wrapper? {
        Wrapper::Data(d) => Some((d, m.version)),
    }
}

#[allow(deprecated)]
/// A signing public key of an Ed25519 key (DER SubjectPublicKeyInfo) with the given usages.
pub fn ed25519_public_key(spki_der: &[u8], usages: &[SigningKeyUsage]) -> SigningPublicKey {
    SigningPublicKey {
        format: CryptoKeyFormat::DerX509SubjectPublicKeyInfo as i32,
        public_key: spki_der.to_vec(),
        scheme: 0,
        usage: usages.iter().map(|u| *u as i32).collect(),
        key_spec: SigningKeySpec::EcCurve25519 as i32,
    }
}

#[allow(deprecated)]
/// An EC-P256 encryption public key (DER SubjectPublicKeyInfo).
pub fn p256_encryption_key(spki_der: &[u8]) -> PublicKey {
    PublicKey {
        key: Some(PublicKeyKind::EncryptionPublicKey(EncryptionPublicKey {
            format: CryptoKeyFormat::DerX509SubjectPublicKeyInfo as i32,
            public_key: spki_der.to_vec(),
            scheme: 0,
            key_spec: EncryptionKeySpec::EcP256 as i32,
        })),
    }
}

fn transaction_bytes(mapping: Mapping) -> Vec<u8> {
    transaction_bytes_at(mapping, 1, 1)
}

/// The versioned bytes of a transaction with `operation` (1 = ADD_REPLACE, 2 = REMOVE) and `serial`.
fn transaction_bytes_at(mapping: Mapping, operation: i32, serial: u32) -> Vec<u8> {
    let tx = TopologyTransaction {
        operation,
        serial,
        mapping: Some(TopologyMapping {
            mapping: Some(mapping),
        }),
    };
    versioned(tx.encode_to_vec(), TOPOLOGY_TRANSACTION_VERSION)
}

#[allow(deprecated)]
/// The (versioned) bytes of the root `NamespaceDelegation` of `namespace`, delegating to `target_key`.
pub fn namespace_delegation(namespace: &str, target_key: SigningPublicKey) -> Vec<u8> {
    transaction_bytes(Mapping::NamespaceDelegation(NamespaceDelegation {
        namespace: namespace.to_string(),
        target_key: Some(target_key),
        is_root_delegation: false,
        restriction: Some(Restriction::CanSignAllMappings(CanSignAllMappings {})),
    }))
}

/// The (versioned) bytes of the REMOVE (serial 2) of the `NamespaceDelegation` of `namespace` to `target_key`: the delegation is revoked.
/// `is_root_delegation` is deprecated in the proto but is still a field of the struct, so it is set explicitly.
#[allow(deprecated)]
pub fn namespace_delegation_removal(namespace: &str, target_key: SigningPublicKey) -> Vec<u8> {
    transaction_bytes_at(
        Mapping::NamespaceDelegation(NamespaceDelegation {
            namespace: namespace.to_string(),
            target_key: Some(target_key),
            is_root_delegation: false,
            restriction: Some(Restriction::CanSignAllMappings(CanSignAllMappings {})),
        }),
        2,
        2,
    )
}

/// The (versioned) bytes of the `OwnerToKeyMapping` of `member` (`PAR::name::namespace`) with its public keys.
pub fn owner_to_key_mapping(member: &str, keys: Vec<PublicKey>) -> Vec<u8> {
    transaction_bytes(Mapping::OwnerToKeyMapping(OwnerToKeyMapping {
        member: member.to_string(),
        public_keys: keys,
    }))
}

/// The (versioned) bytes of an `OwnerToKeyMapping` at a given `serial` and `operation` (1 = ADD_REPLACE, 2 = REMOVE).
pub fn owner_to_key_mapping_at(
    member: &str,
    keys: Vec<PublicKey>,
    serial: u32,
    operation: i32,
) -> Vec<u8> {
    transaction_bytes_at(
        Mapping::OwnerToKeyMapping(OwnerToKeyMapping {
            member: member.to_string(),
            public_keys: keys,
        }),
        operation,
        serial,
    )
}

/// The (versioned) bytes of the `SynchronizerTrustCertificate`: the participant (`name::namespace`) trusts the synchronizer
/// (`name::fingerprint`, the physical id without its `::protocol-serial` suffix).
pub fn synchronizer_trust_certificate(
    participant_uid: &str,
    synchronizer_uid: &str,
    feature_flags: Vec<i32>,
) -> Vec<u8> {
    transaction_bytes(Mapping::SynchronizerTrustCertificate(
        SynchronizerTrustCertificate {
            participant_uid: participant_uid.to_string(),
            synchronizer_id: synchronizer_uid.to_string(),
            feature_flags,
        },
    ))
}

/// What a signature of a topology transaction covers.
pub fn transaction_hash(transaction_bytes: &[u8]) -> Vec<u8> {
    multihash(canton_algo::hash::sha256_with_purpose(
        PURPOSE_TOPOLOGY_TRANSACTION_SIGNATURE,
        transaction_bytes,
    ))
}

/// The dynamic parameters of a synchronizer as the official 3.7.2 sandbox starts with them (the defaults; read with the console, S-NET-037).
pub fn default_dynamic_parameters(
) -> canton_proto::com::digitalasset::canton::protocol::v30::DynamicSynchronizerParameters {
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        AcsCommitmentsCatchUpConfig, DynamicSynchronizerParameters, OnboardingRestriction,
        ParticipantSynchronizerLimits,
    };
    let seconds = |s: i64| prost_types::Duration {
        seconds: s,
        nanos: 0,
    };
    DynamicSynchronizerParameters {
        confirmation_response_timeout: Some(seconds(30)),
        mediator_reaction_timeout: Some(seconds(30)),
        assignment_exclusivity_timeout: Some(seconds(60)),
        ledger_time_record_time_tolerance: Some(seconds(60)),
        reconciliation_interval: Some(seconds(60)),
        mediator_deduplication_timeout: Some(seconds(48 * 3600)),
        max_request_size: 10_485_760,
        onboarding_restriction: OnboardingRestriction::UnrestrictedOpen as i32,
        participant_synchronizer_limits: Some(ParticipantSynchronizerLimits {
            confirmation_requests_max_rate: 1_000_000,
        }),
        sequencer_aggregate_submission_timeout: Some(seconds(360)),
        traffic_control: None,
        acs_commitments_catchup: Some(AcsCommitmentsCatchUpConfig {
            catchup_interval_skip: 5,
            nr_intervals_to_trigger_catchup: 2,
        }),
        preparation_time_record_time_tolerance: Some(seconds(24 * 3600)),
    }
}

/// The (versioned) bytes of the `SynchronizerParametersState` of `synchronizer_id` (`name::fingerprint`).
pub fn synchronizer_parameters_state(
    synchronizer_id: &str,
    parameters: canton_proto::com::digitalasset::canton::protocol::v30::DynamicSynchronizerParameters,
) -> Vec<u8> {
    transaction_bytes(Mapping::SynchronizerParametersState(
        canton_proto::com::digitalasset::canton::protocol::v30::SynchronizerParametersState {
            synchronizer_id: synchronizer_id.to_string(),
            synchronizer_parameters: Some(parameters),
        },
    ))
}

/// The (versioned) bytes of the `MediatorSynchronizerState` of `synchronizer_id`: one mediator group with `active` mediators.
pub fn mediator_synchronizer_state(
    synchronizer_id: &str,
    group: u32,
    threshold: u32,
    active: &[&str],
) -> Vec<u8> {
    transaction_bytes(Mapping::MediatorSynchronizerState(
        canton_proto::com::digitalasset::canton::protocol::v30::MediatorSynchronizerState {
            synchronizer_id: synchronizer_id.to_string(),
            group,
            threshold,
            active: active.iter().map(|m| m.to_string()).collect(),
            observers: vec![],
        },
    ))
}

/// The (versioned) bytes of a `MediatorSynchronizerState` at `serial` (a group change after genesis): `active` and `observers` are uids
/// (`name::namespace`).
pub fn mediator_synchronizer_state_at(
    synchronizer_id: &str,
    group: u32,
    threshold: u32,
    active: &[String],
    observers: &[String],
    serial: u32,
) -> Vec<u8> {
    transaction_bytes_at(
        Mapping::MediatorSynchronizerState(
            canton_proto::com::digitalasset::canton::protocol::v30::MediatorSynchronizerState {
                synchronizer_id: synchronizer_id.to_string(),
                group,
                threshold,
                active: active.to_vec(),
                observers: observers.to_vec(),
            },
        ),
        1,
        serial,
    )
}

/// The (versioned) bytes of the `SequencerSynchronizerState` of `synchronizer_id` with `active` sequencers.
pub fn sequencer_synchronizer_state(
    synchronizer_id: &str,
    threshold: u32,
    active: &[&str],
) -> Vec<u8> {
    transaction_bytes(Mapping::SequencerSynchronizerState(
        canton_proto::com::digitalasset::canton::protocol::v30::SequencerSynchronizerState {
            synchronizer_id: synchronizer_id.to_string(),
            threshold,
            active: active.iter().map(|m| m.to_string()).collect(),
            observers: vec![],
        },
    ))
}

/// The hash a sequencer gives of the topology state it would hand a new member (`DownloadTopologyStateForInitHash`): SHA-256 over the 4-byte
/// big-endian hash purpose `InitialTopologyStateConsistency` (60) and then, **in the order of the state**, the transaction hash
/// (multihash bytes, [`transaction_hash`]) of every transaction; the result is a multihash again. A participant compares it with the
/// state it downloaded, so a sequencer cannot hand it a state other sequencers would not.
///
/// [CANTON-NOTE: SEMANTICS] From `TopologyStateHash` in the Canton source and checked against the official node's answer
/// (`the_state_hash_of_the_official_sequencer_is_the_hash_of_the_transactions_it_serves`).
pub fn topology_state_hash(signed_transactions: &[Vec<u8>]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(60u32.to_be_bytes());
    for transaction in signed_transactions {
        h.update(transaction_hash(transaction));
    }
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&h.finalize());
    out
}

/// An Ed25519 signing key with the fingerprint it is registered under.
pub struct Ed25519Key {
    pub fingerprint: String,
    pub spki_der: Vec<u8>,
    key: ed25519_dalek::SigningKey,
}

impl Ed25519Key {
    pub fn from_signing_key(key: ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::pkcs8::EncodePublicKey;
        let spki_der = key
            .verifying_key()
            .to_public_key_der()
            .map(|d| d.as_bytes().to_vec())
            .unwrap_or_default();
        Self {
            fingerprint: fingerprint(&key.verifying_key().to_bytes()),
            spki_der,
            key,
        }
    }

    /// The 32-byte seed of the private key (what is kept to have the same key after a restart).
    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// From the DER PKCS#8 private key of a node's key export.
    pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        ed25519_dalek::SigningKey::from_pkcs8_der(der)
            .ok()
            .map(Self::from_signing_key)
    }

    pub fn public_key(&self, usages: &[SigningKeyUsage]) -> SigningPublicKey {
        ed25519_public_key(&self.spki_der, usages)
    }

    /// The signature of a topology transaction (its versioned bytes) by this key.
    pub fn sign_transaction(&self, transaction_bytes: &[u8]) -> Signature {
        self.sign_bytes(&transaction_hash(transaction_bytes))
    }

    /// An Ed25519 signature over `bytes` (already a multihash), in the message the sequencer and the topology expect.
    pub fn sign_bytes(&self, bytes: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        let signature = self.key.sign(bytes);
        Signature {
            format: SignatureFormat::Concat as i32,
            signature: signature.to_bytes().to_vec(),
            signed_by: self.fingerprint.clone(),
            signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
            signature_delegation: None,
        }
    }
}

/// The `SignedTopologyTransaction` message of a transaction with its signatures.
pub fn signed(transaction_bytes: Vec<u8>, signatures: Vec<Signature>) -> SignedTopologyTransaction {
    SignedTopologyTransaction {
        transaction: transaction_bytes,
        signatures,
        proposal: false,
        multi_transaction_signatures: Vec::new(),
    }
}

/// How the node stores or exports a signed transaction: the message in its own versioned wrapper.
pub fn stored_form(signed: &SignedTopologyTransaction) -> Vec<u8> {
    versioned(signed.encode_to_vec(), SIGNED_TOPOLOGY_TRANSACTION_VERSION)
}

/// `n` random bytes from the operating system.
fn random_bytes<const N: usize>() -> [u8; N] {
    use std::io::Read;
    let mut out = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut out))
        .expect("the operating system's random source");
    out
}

/// A participant identity made here: its keys and the topology transactions that register it.
pub struct ParticipantIdentity {
    pub name: String,
    pub namespace_key: Ed25519Key,
    pub signing_key: Ed25519Key,
    pub sequencer_auth_key: Ed25519Key,
    encryption_spki: Vec<u8>,
    /// The P-256 scalar of the encryption key: what lets this participant read the views encrypted for it.
    encryption_secret: [u8; 32],
}

impl ParticipantIdentity {
    /// New keys and the identity `name::<namespace>` (the namespace is the fingerprint of the namespace key).
    pub fn generate(name: &str) -> Self {
        use p256::pkcs8::EncodePublicKey;
        let ed = || {
            Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(
                &random_bytes::<32>(),
            ))
        };
        let encryption_secret = random_bytes::<32>();
        let encryption =
            p256::SecretKey::from_slice(&encryption_secret).expect("a valid P-256 scalar");
        Self {
            name: name.to_string(),
            namespace_key: ed(),
            signing_key: ed(),
            sequencer_auth_key: ed(),
            encryption_secret,
            encryption_spki: encryption
                .public_key()
                .to_public_key_der()
                .expect("DER")
                .as_bytes()
                .to_vec(),
        }
    }

    /// The identity kept in `path` (written by [`ParticipantIdentity::save`]), or `None` when there is none.
    ///
    /// [CANTON-NOTE: SEMANTICS] The keys are the participant's identity: its namespace is the fingerprint of the namespace key, so a restart with
    /// other keys would be another participant that none of the others recognizes and that hosts none of the parties.
    pub fn load(path: &std::path::Path) -> Option<Self> {
        Self::from_text(&std::fs::read_to_string(path).ok()?)
    }

    /// The identity written by [`ParticipantIdentity::to_text`]; `None` for anything else (a damaged text, a seed of the wrong size).
    pub fn from_text(text: &str) -> Option<Self> {
        use p256::pkcs8::EncodePublicKey;
        let mut lines = text.lines();
        let name = lines.next()?.to_string();
        let mut seeds = [[0u8; 32]; 4];
        for seed in seeds.iter_mut() {
            *seed = hex::decode(lines.next()?).ok()?.try_into().ok()?;
        }
        let encryption = p256::SecretKey::from_slice(&seeds[3]).ok()?;
        Some(Self {
            name,
            namespace_key: Ed25519Key::from_seed(seeds[0]),
            signing_key: Ed25519Key::from_seed(seeds[1]),
            sequencer_auth_key: Ed25519Key::from_seed(seeds[2]),
            encryption_secret: seeds[3],
            encryption_spki: encryption
                .public_key()
                .to_public_key_der()
                .ok()?
                .as_bytes()
                .to_vec(),
        })
    }

    /// The private keys as text: the name, then the seeds of the namespace, signing and authentication keys and the encryption scalar (hex).
    pub fn to_text(&self) -> String {
        let mut text = format!("{}\n", self.name);
        for seed in [
            self.namespace_key.seed(),
            self.signing_key.seed(),
            self.sequencer_auth_key.seed(),
            self.encryption_secret,
        ] {
            text.push_str(&hex::encode(seed));
            text.push('\n');
        }
        text
    }

    /// Keeps this identity in `path` (the private keys: readable by the owner only). Fails if the file exists: an identity is never overwritten.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(self.to_text().as_bytes())?;
        file.sync_all()
    }

    /// The DER SubjectPublicKeyInfo of this participant's encryption key.
    pub fn encryption_spki(&self) -> &[u8] {
        &self.encryption_spki
    }

    /// The private scalar of this participant's encryption key.
    pub fn encryption_secret(&self) -> &[u8; 32] {
        &self.encryption_secret
    }

    /// The fingerprint of this participant's encryption key (the hash of the DER, see [`fingerprint`]).
    pub fn encryption_fingerprint(&self) -> String {
        fingerprint(&self.encryption_spki)
    }

    pub fn namespace(&self) -> &str {
        &self.namespace_key.fingerprint
    }

    /// `name::namespace`.
    pub fn uid(&self) -> String {
        format!("{}::{}", self.name, self.namespace())
    }

    /// `PAR::name::namespace`, the member id the sequencer knows the participant by.
    pub fn member(&self) -> String {
        format!("PAR::{}", self.uid())
    }

    /// The identity transactions plus the trust certificate for `synchronizer_uid`, signed as the node signs a participant's own.
    pub fn onboarding_transactions(
        &self,
        synchronizer_uid: &str,
    ) -> Vec<SignedTopologyTransaction> {
        use SigningKeyUsage::{Namespace, ProofOfOwnership, Protocol, SequencerAuthentication};
        let delegation = namespace_delegation(
            self.namespace(),
            self.namespace_key.public_key(&[Namespace]),
        );
        let delegation_signed = signed(
            delegation.clone(),
            vec![self.namespace_key.sign_transaction(&delegation)],
        );
        let keys = vec![
            PublicKey {
                key: Some(PublicKeyKind::SigningPublicKey(
                    self.signing_key.public_key(&[Protocol, ProofOfOwnership]),
                )),
            },
            PublicKey {
                key: Some(PublicKeyKind::SigningPublicKey(
                    self.sequencer_auth_key
                        .public_key(&[SequencerAuthentication, ProofOfOwnership]),
                )),
            },
            p256_encryption_key(&self.encryption_spki),
        ];
        let mapping = owner_to_key_mapping(&self.member(), keys);
        // the namespace key and the keys the mapping registers all sign it (proof of ownership)
        let mapping_signed = signed(
            mapping.clone(),
            vec![
                self.namespace_key.sign_transaction(&mapping),
                self.signing_key.sign_transaction(&mapping),
                self.sequencer_auth_key.sign_transaction(&mapping),
            ],
        );
        // the trust certificate is signed by the namespace key (measured: the node's p1 certificate has that one signature)
        let certificate = synchronizer_trust_certificate(&self.uid(), synchronizer_uid, vec![2]);
        let certificate_signed = signed(
            certificate.clone(),
            vec![self.namespace_key.sign_transaction(&certificate)],
        );
        vec![delegation_signed, mapping_signed, certificate_signed]
    }
}

/// The (versioned) bytes of a v31 `PartyToParticipant`: `party` (`name::namespace`) is hosted by the single participant
/// `participant_uid` with submission permission, in the `ACTIVE` hosting state, threshold 1.
///
/// [CANTON-NOTE: SEMANTICS] The node writes the transactions of protocol version 37 as **v31** messages: `PartyToParticipant`
/// changed from v30 (the `onboarding` flag became a hosting state). The version of the wrapper is 31, as for the other mappings.
pub fn party_to_participant(party: &str, participant_uid: &str) -> Vec<u8> {
    party_to_participant_hosted_by(party, &[(participant_uid, 1)])
}

/// Like [`party_to_participant`], with several hosting participants (`(uid, permission)`: 1 submission, 2 confirmation,
/// 3 observation), all `ACTIVE`, threshold 1.
pub fn party_to_participant_hosted_by(party: &str, hosts: &[(&str, i32)]) -> Vec<u8> {
    party_to_participant_with_threshold(party, hosts, 1)
}

/// Like [`party_to_participant_hosted_by`], with the confirmation threshold: how many of the hosting participants must confirm
/// for the party (more than one makes the party a consortium party; every hosting participant then has to approve).
pub fn party_to_participant_with_threshold(
    party: &str,
    hosts: &[(&str, i32)],
    threshold: u32,
) -> Vec<u8> {
    party_to_participant_at_serial(party, hosts, threshold, 1)
}

/// Like [`party_to_participant_with_threshold`], at a given `serial`: a transaction with serial `n + 1` **replaces** the mapping of
/// serial `n` (this is how participants are added to, or removed from, a party that is already hosted).
pub fn party_to_participant_at_serial(
    party: &str,
    hosts: &[(&str, i32)],
    threshold: u32,
    serial: u32,
) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v31;
    let tx = v31::TopologyTransaction {
        operation: 1, // ADD_REPLACE
        serial,
        mapping: Some(v31::TopologyMapping {
            mapping: Some(v31::topology_mapping::Mapping::PartyToParticipant(
                v31::PartyToParticipant {
                    party: party.to_string(),
                    threshold,
                    participants: hosts
                        .iter()
                        .map(
                            |(uid, permission)| v31::party_to_participant::HostingParticipant {
                                participant_uid: uid.to_string(),
                                permission: *permission,
                                state: 4, // HOSTING_STATE_ACTIVE
                            },
                        )
                        .collect(),
                    party_signing_keys: None,
                },
            )),
        }),
    };
    versioned(tx.encode_to_vec(), TOPOLOGY_TRANSACTION_VERSION)
}

impl ParticipantIdentity {
    /// The party `name::<namespace of this participant>`.
    pub fn party_id(&self, name: &str) -> String {
        format!("{name}::{}", self.namespace())
    }

    /// The proposal that this participant and `other_uid` (a participant of another namespace) both host this participant's
    /// party `name`: this one with submission, the other with confirmation permission. Signed by this participant's namespace key
    /// only; the other participant's authorization has to be added by that participant (it is the added hosting participant).
    ///
    /// [CANTON-NOTE: SEMANTICS] Adding a participant to a party needs the authorization of the party's namespace **and** of the
    /// added participant's namespace (`PartyToParticipant.requiredAuth`). A transaction with only one of them is a *proposal*; the
    /// other side co-signs it by its hash and the synchronizer then has the fully authorized transaction.
    pub fn shared_party_proposal(&self, name: &str, other_uid: &str) -> SignedTopologyTransaction {
        let bytes = party_to_participant_hosted_by(
            &self.party_id(name),
            &[(&self.uid(), 1), (other_uid, 2)],
        );
        signed_proposal(
            bytes.clone(),
            vec![self.namespace_key.sign_transaction(&bytes)],
        )
    }

    /// Like [`Self::shared_party_proposal`], with both participants' permissions (1 submission, 2 confirmation, 3 observation) and
    /// the confirmation threshold of the party. [CANTON-NOTE: SEMANTICS] A node refuses to submit for a party that has a threshold above 1
    /// (`DECENTRALIZED_PARTY_CANNOT_SUBMIT`), so a party another participant submits for has threshold 1.
    pub fn shared_party_proposal_with(
        &self,
        name: &str,
        other_uid: &str,
        own_permission: i32,
        other_permission: i32,
        threshold: u32,
    ) -> SignedTopologyTransaction {
        let bytes = party_to_participant_with_threshold(
            &self.party_id(name),
            &[(&self.uid(), own_permission), (other_uid, other_permission)],
            threshold,
        );
        signed_proposal(
            bytes.clone(),
            vec![self.namespace_key.sign_transaction(&bytes)],
        )
    }

    /// The transaction (serial `serial`) that sets the participants of this participant's party `name` to `hosts` (`(uid, permission)`),
    /// signed by the namespace key alone. It is complete when it only **adds this participant** (the party's namespace and the added
    /// participant's namespace are both this one's) or removes hosts; adding another namespace's participant needs a co-signature.
    pub fn party_hosting_at_serial(
        &self,
        name: &str,
        hosts: &[(&str, i32)],
        serial: u32,
    ) -> SignedTopologyTransaction {
        let bytes = party_to_participant_at_serial(&self.party_id(name), hosts, 1, serial);
        signed(
            bytes.clone(),
            vec![self.namespace_key.sign_transaction(&bytes)],
        )
    }

    /// The transaction that makes this participant host its own party `name`, signed by the namespace key (the party's
    /// namespace and the participant's namespace are the same, so one signature authorizes both sides).
    pub fn party_hosting_transaction(&self, name: &str) -> SignedTopologyTransaction {
        let bytes = party_to_participant(&self.party_id(name), &self.uid());
        signed(
            bytes.clone(),
            vec![self.namespace_key.sign_transaction(&bytes)],
        )
    }
}

/// A signed transaction that is only a **proposal**: the signatures so far are not all the ones it needs, and the node keeps it
/// pending until the others arrive.
pub fn signed_proposal(
    transaction_bytes: Vec<u8>,
    signatures: Vec<Signature>,
) -> SignedTopologyTransaction {
    SignedTopologyTransaction {
        proposal: true,
        ..signed(transaction_bytes, signatures)
    }
}

/// The envelope content of a `TopologyTransactionsBroadcast` (what a participant sends to every member to propose topology
/// transactions): the physical synchronizer id and the transactions in their stored (versioned) form.
///
/// [CANTON-NOTE: SEMANTICS] It is sent in an **unsigned** envelope to the group `ALL::All` (`AllMembersOfSynchronizer`); the
/// sequencer, the mediator and the participants each run it through their topology processor.
pub fn topology_broadcast(
    physical_synchronizer_id: &str,
    transactions: &[SignedTopologyTransaction],
) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        SignedTopologyTransactions, TopologyTransactionsBroadcast,
    };
    use canton_proto::com::digitalasset::canton::protocol::v32::{
        envelope_content::SomeEnvelopeContent, EnvelopeContent,
    };
    versioned(
        EnvelopeContent {
            some_envelope_content: Some(SomeEnvelopeContent::TopologyTransactionsBroadcast(
                TopologyTransactionsBroadcast {
                    physical_synchronizer_id: physical_synchronizer_id.to_string(),
                    signed_transactions: Some(SignedTopologyTransactions {
                        signed_transactions: transactions.iter().map(stored_form).collect(),
                    }),
                },
            )),
        }
        .encode_to_vec(),
        32,
    )
}

/// `AllMembersOfSynchronizer` as a recipient string.
pub const ALL_MEMBERS: &str = "ALL::All";

/// The (versioned) bytes of a v31 `VettedPackages`: `participant_uid` vets the packages `package_ids` for all time.
///
/// [CANTON-NOTE: SEMANTICS] A participant that hosts a stakeholder of a contract must have vetted the contract's package, or
/// the other participants refuse the transaction; vetting is a topology transaction signed by the participant's namespace.
#[allow(deprecated)]
pub fn vetted_packages(participant_uid: &str, package_ids: &[String]) -> Vec<u8> {
    vetted_packages_at_serial(participant_uid, package_ids, 1)
}

/// Like [`vetted_packages`], at `serial`: the transaction after the one in force replaces its list of packages.
#[allow(deprecated)]
pub fn vetted_packages_at_serial(
    participant_uid: &str,
    package_ids: &[String],
    serial: u32,
) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v30::vetted_packages::VettedPackage;
    use canton_proto::com::digitalasset::canton::protocol::v30::VettedPackages;
    use canton_proto::com::digitalasset::canton::protocol::v31;
    let tx = v31::TopologyTransaction {
        operation: 1,
        serial,
        mapping: Some(v31::TopologyMapping {
            mapping: Some(v31::topology_mapping::Mapping::VettedPackages(
                VettedPackages {
                    participant_uid: participant_uid.to_string(),
                    package_ids: Vec::new(),
                    packages: package_ids
                        .iter()
                        .map(|id| VettedPackage {
                            package_id: id.clone(),
                            valid_from_inclusive: None,
                            valid_until_exclusive: None,
                        })
                        .collect(),
                },
            )),
        }),
    };
    versioned(tx.encode_to_vec(), TOPOLOGY_TRANSACTION_VERSION)
}

impl ParticipantIdentity {
    /// The transaction at `serial` that makes this participant vet `package_ids` (the whole list), signed by its namespace key.
    pub fn vetting_transaction_at_serial(
        &self,
        package_ids: &[String],
        serial: u32,
    ) -> SignedTopologyTransaction {
        let bytes = vetted_packages_at_serial(&self.uid(), package_ids, serial);
        signed(
            bytes.clone(),
            vec![self.namespace_key.sign_transaction(&bytes)],
        )
    }

    /// The transaction that makes this participant vet `package_ids`, signed by its namespace key.
    pub fn vetting_transaction(&self, package_ids: &[String]) -> SignedTopologyTransaction {
        let bytes = vetted_packages(&self.uid(), package_ids);
        signed(
            bytes.clone(),
            vec![self.namespace_key.sign_transaction(&bytes)],
        )
    }
}

#[cfg(test)]
mod party_mapping_tests {
    use super::*;

    /// The unsigned bytes of the `PartyToParticipant` row of the party `test0000` in the hub participant's `common_topology_transactions` (id 35).
    const STORED: &str = "0ab601080110011aaf014aac010a4e74657374303030303a3a313232303033313263313135366337393634643064303763313433346536643166333864373630383765346130333361326666613435313431333931656132653233336210011a580a527061727469636970616e74313a3a313232303033313263313135366337393634643064303763313433346536643166333864373630383765346130333361326666613435313431333931656132653233336210011804101f";

    #[test]
    fn a_party_to_participant_transaction_is_what_the_official_participant_stores() {
        let namespace = "12200312c1156c7964d0d07c1434e6d1f38d76087e4a033a2ffa45141391ea2e233b";
        let bytes = party_to_participant(
            &format!("test0000::{namespace}"),
            &format!("participant1::{namespace}"),
        );
        assert_eq!(hex::encode(bytes), STORED);
    }
}
