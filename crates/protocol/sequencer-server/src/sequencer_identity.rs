//! A sequencer's identity of its own, to join a synchronizer that other sequencers already run (U-49 B2a): the keys a Rust sequencer generates for itself and the
//! topology transactions that make it known to that synchronizer.
//!
//! [CANTON-NOTE: SEMANTICS] The members of an official 3.7.2 synchronizer authenticate each other's sequencers through the synchronizer's topology: a sequencer
//! `SEQ::<name>::<namespace>` is a peer only when its `OwnerToKeyMapping` is in force and a `SequencerSynchronizerState` names it. The transactions are the ones the
//! founder's code builds for its own sequencer (`synchronizer_state.rs`, measured on the official node): the root `NamespaceDelegation` of the sequencer's
//! namespace, and the key mapping with a signing key (`protocol`, `proof-of-ownership`), an authentication key (`sequencer-auth`, `proof-of-ownership`) and a P-256
//! encryption key, signed by the namespace key and by both signing keys (proof of possession). The synchronizer's owners load them and change the state
//! (see `crate::topology_admin::onboard_sequencer`).
use canton_participant::state_store::StateStore;
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::crypto::v30::{
    public_key::Key, PublicKey, SigningKeyUsage,
};
use canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction;

/// Where the identity is kept in a BFT sequencer's state store.
pub const IDENTITY_KEY: &str = "sequencer.identity";

pub struct SequencerIdentity {
    pub name: String,
    pub namespace_key: tw::Ed25519Key,
    pub signing_key: tw::Ed25519Key,
    pub authentication_key: tw::Ed25519Key,
    /// The SPKI of the P-256 encryption key.
    encryption_spki: Vec<u8>,
}

impl SequencerIdentity {
    /// New keys for the sequencer `name`.
    pub fn generate(name: &str) -> Self {
        let ed = || tw::Ed25519Key::from_seed(rand::random::<[u8; 32]>());
        Self {
            name: name.to_string(),
            namespace_key: ed(),
            signing_key: ed(),
            authentication_key: ed(),
            // the participant identity generator makes a P-256 key, which is all of it that is used here
            encryption_spki: tw::ParticipantIdentity::generate(name)
                .encryption_spki()
                .to_vec(),
        }
    }

    /// The identity kept in `store`, if there is one.
    pub fn load(store: &dyn StateStore) -> Result<Option<Self>, String> {
        let Some(text) = store.read(IDENTITY_KEY)? else {
            return Ok(None);
        };
        Self::from_text(&text)
            .map(Some)
            .ok_or_else(|| format!("the sequencer identity in {} is damaged", store.describe()))
    }

    /// The identity kept in `store`, or a new one named `name` written there. An identity is never replaced.
    pub fn load_or_create_in(store: &dyn StateStore, name: &str) -> Result<Self, String> {
        if let Some(identity) = Self::load(store)? {
            return Ok(identity);
        }
        let identity = Self::generate(name);
        if !store.create_new(IDENTITY_KEY, &identity.to_text())? {
            return Self::load(store)?.ok_or_else(|| "the sequencer identity vanished".into());
        }
        Ok(identity)
    }

    pub fn namespace(&self) -> &str {
        &self.namespace_key.fingerprint
    }

    /// `name::namespace`: how a `SequencerSynchronizerState` names the sequencer.
    pub fn uid(&self) -> String {
        format!("{}::{}", self.name, self.namespace())
    }

    /// `SEQ::name::namespace`: the member the other sequencers know.
    pub fn member(&self) -> String {
        format!("SEQ::{}", self.uid())
    }

    /// The first step of joining a cluster whose ordering stops without the new node: the root delegation and a key mapping with the **authentication** key
    /// only. The peers' authentication service lets the sequencer in as soon as the synchronizer's sequencer state names it, but the ordering topology takes a
    /// sequencer in only when it has a protocol signing key, so the node can connect and authenticate **before** the cluster waits for its votes
    /// (see [`SequencerIdentity::signing_key_transactions`]). The mapping is serial 1.
    pub fn authentication_only_transactions(&self) -> Vec<SignedTopologyTransaction> {
        use SigningKeyUsage::{Namespace, ProofOfOwnership, SequencerAuthentication};
        let delegation = tw::namespace_delegation(
            self.namespace(),
            self.namespace_key.public_key(&[Namespace]),
        );
        let delegation_signed = tw::signed(
            delegation.clone(),
            vec![self.namespace_key.sign_transaction(&delegation)],
        );
        let mapping = tw::owner_to_key_mapping_at(
            &self.member(),
            vec![
                PublicKey {
                    key: Some(Key::SigningPublicKey(
                        self.authentication_key
                            .public_key(&[SequencerAuthentication, ProofOfOwnership]),
                    )),
                },
                tw::p256_encryption_key(&self.encryption_spki),
            ],
            1,
            1,
        );
        let mapping_signed = tw::signed(
            mapping.clone(),
            vec![
                self.namespace_key.sign_transaction(&mapping),
                self.authentication_key.sign_transaction(&mapping),
            ],
        );
        vec![delegation_signed, mapping_signed]
    }

    /// The second step: the key mapping at serial 2 with the protocol signing key as well, which makes the sequencer a member of the ordering topology from the
    /// next epoch on.
    pub fn signing_key_transactions(&self) -> Vec<SignedTopologyTransaction> {
        use SigningKeyUsage::{ProofOfOwnership, Protocol, SequencerAuthentication};
        let signing = |k: &tw::Ed25519Key, usages: &[SigningKeyUsage]| PublicKey {
            key: Some(Key::SigningPublicKey(k.public_key(usages))),
        };
        let mapping = tw::owner_to_key_mapping_at(
            &self.member(),
            vec![
                signing(&self.signing_key, &[Protocol, ProofOfOwnership]),
                signing(
                    &self.authentication_key,
                    &[SequencerAuthentication, ProofOfOwnership],
                ),
                tw::p256_encryption_key(&self.encryption_spki),
            ],
            2,
            1,
        );
        vec![tw::signed(
            mapping.clone(),
            vec![
                self.namespace_key.sign_transaction(&mapping),
                self.signing_key.sign_transaction(&mapping),
                self.authentication_key.sign_transaction(&mapping),
            ],
        )]
    }

    /// The transactions an operator loads into the synchronizer: the root delegation of the sequencer's namespace and its key mapping.
    pub fn onboarding_transactions(&self) -> Vec<SignedTopologyTransaction> {
        use SigningKeyUsage::{Namespace, ProofOfOwnership, Protocol, SequencerAuthentication};
        let delegation = tw::namespace_delegation(
            self.namespace(),
            self.namespace_key.public_key(&[Namespace]),
        );
        let delegation_signed = tw::signed(
            delegation.clone(),
            vec![self.namespace_key.sign_transaction(&delegation)],
        );
        let signing = |k: &tw::Ed25519Key, usages: &[SigningKeyUsage]| PublicKey {
            key: Some(Key::SigningPublicKey(k.public_key(usages))),
        };
        let mapping = tw::owner_to_key_mapping(
            &self.member(),
            vec![
                signing(&self.signing_key, &[Protocol, ProofOfOwnership]),
                signing(
                    &self.authentication_key,
                    &[SequencerAuthentication, ProofOfOwnership],
                ),
                tw::p256_encryption_key(&self.encryption_spki),
            ],
        );
        let mapping_signed = tw::signed(
            mapping.clone(),
            vec![
                self.namespace_key.sign_transaction(&mapping),
                self.signing_key.sign_transaction(&mapping),
                self.authentication_key.sign_transaction(&mapping),
            ],
        );
        vec![delegation_signed, mapping_signed]
    }

    /// The name, then the three Ed25519 seeds and the encryption SPKI (hex), one per line: what an operator keeps to onboard the same sequencer again.
    pub fn to_text(&self) -> String {
        let mut text = format!("{}\n", self.name);
        for key in [
            &self.namespace_key,
            &self.signing_key,
            &self.authentication_key,
        ] {
            text.push_str(&crate::persistence::hex(&key.seed()));
            text.push('\n');
        }
        text.push_str(&crate::persistence::hex(&self.encryption_spki));
        text.push('\n');
        text
    }

    pub fn from_text(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        let name = lines.next()?.to_string();
        let mut seed =
            || -> Option<[u8; 32]> { crate::persistence::unhex(lines.next()?)?.try_into().ok() };
        let (ns, signing, auth) = (seed()?, seed()?, seed()?);
        let encryption_spki = crate::persistence::unhex(lines.next()?)?;
        Some(Self {
            name,
            namespace_key: tw::Ed25519Key::from_seed(ns),
            signing_key: tw::Ed25519Key::from_seed(signing),
            authentication_key: tw::Ed25519Key::from_seed(auth),
            encryption_spki,
        })
    }
}

/// The sequencer (`SEQ::name::namespace`) whose key mapping is among `transactions`.
pub fn sequencer_of(transactions: &[SignedTopologyTransaction]) -> Option<String> {
    use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
    let stored: Vec<(i64, Vec<u8>)> = transactions
        .iter()
        .map(|t| (0, tw::stored_form(t)))
        .collect();
    canton_participant::topology_state::decode(&stored)
        .ok()?
        .iter()
        .find_map(
            |e| match e.tx.mapping.as_ref().and_then(|m| m.mapping.as_ref()) {
                Some(Mapping::OwnerToKeyMapping(m)) if m.member.starts_with("SEQ::") => {
                    Some(m.member.clone())
                }
                _ => None,
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_participant::topology_state::{decode, Tracker};

    /// The onboarding transactions authorize themselves: a tracker that knows nothing takes both into force, and the member has its two signing keys
    /// and the encryption key.
    #[test]
    fn the_onboarding_transactions_authorize_themselves() {
        let identity = SequencerIdentity::generate("rs9");
        let txs = identity.onboarding_transactions();
        let mut tracker = Tracker::from_state(&decode(&[]).unwrap(), "SEQ::other::x");
        for t in &txs {
            let applied = tracker.apply(&tw::stored_form(t));
            assert!(applied.outcome.is_in_force(), "{:?}", applied.outcome);
        }
        assert_eq!(
            tracker.signing_keys_of(&identity.member()).map(|k| k.len()),
            Some(2)
        );
        assert_eq!(
            sequencer_of(&txs).as_deref(),
            Some(identity.member().as_str())
        );
    }

    #[test]
    fn an_identity_is_kept_and_read_back_with_the_same_member() {
        let identity = SequencerIdentity::generate("rs9");
        let again = SequencerIdentity::from_text(&identity.to_text()).unwrap();
        assert_eq!(again.member(), identity.member());
        // the same keys sign the same bytes (Ed25519 is deterministic): the transactions are the same
        assert_eq!(
            again.onboarding_transactions(),
            identity.onboarding_transactions()
        );
    }
}
