//! A mediator's identity of its own (B2, S-LOCAL-011): the keys a mediator node generates for itself and the topology transactions that
//! make it known to a synchronizer, kept in the mediator's own state (never in the sequencer's).
//!
//! [CANTON-NOTE: SEMANTICS] What the official 3.7.2 mediator node has, measured on `m2` before it was onboarded: a **namespace** key (usage
//! `namespace`), a **signing** key (`signing`, `proof-of-ownership`) and a **sequencer authentication** key (`sequencer-auth`,
//! `proof-of-ownership`), all Ed25519, and **no encryption key**. Its onboarding transactions
//! (`topology.transactions.generate_onboarding_transactions`) are the root `NamespaceDelegation` signed by the namespace key, and the
//! `OwnerToKeyMapping` of `MED::<name>::<namespace>` with the two signing keys, signed by the namespace key and by both keys it names
//! (proof of possession).
//!
//! The synchronizer's owners then load those transactions into the synchronizer's store and change the `MediatorSynchronizerState` of a
//! group to name the mediator (see `crate::topology_admin`); nothing is shared between the two nodes but these transactions.
use canton_participant::state_store::StateStore;
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::crypto::v30::{
    public_key::Key, PublicKey, SigningKeyUsage,
};
use canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction;

/// Where the identity is kept in the mediator's state.
pub const IDENTITY_KEY: &str = "mediator.identity";

pub struct MediatorIdentity {
    pub name: String,
    pub namespace_key: tw::Ed25519Key,
    pub signing_key: tw::Ed25519Key,
    pub sequencer_auth_key: tw::Ed25519Key,
}

impl MediatorIdentity {
    /// New keys for the mediator `name`.
    pub fn generate(name: &str) -> Self {
        let ed = || tw::Ed25519Key::from_seed(rand::random::<[u8; 32]>());
        Self {
            name: name.to_string(),
            namespace_key: ed(),
            signing_key: ed(),
            sequencer_auth_key: ed(),
        }
    }

    /// The identity kept in `store`, if there is one.
    pub fn load(store: &dyn StateStore) -> Result<Option<Self>, String> {
        let Some(text) = store.read(IDENTITY_KEY)? else {
            return Ok(None);
        };
        Self::from_text(&text)
            .map(Some)
            .ok_or_else(|| format!("the mediator identity in {} is damaged", store.describe()))
    }

    /// The identity kept in `store`, or a new one named `name` written there. An identity is never replaced: a mediator with other keys
    /// would be another member.
    pub fn load_or_create(store: &dyn StateStore, name: &str) -> Result<Self, String> {
        if let Some(identity) = Self::load(store)? {
            return Ok(identity);
        }
        let identity = Self::generate(name);
        if !store.create_new(IDENTITY_KEY, &identity.to_text())? {
            // created at the same time by another process: that one wins
            return Self::load(store)?.ok_or_else(|| "the mediator identity vanished".into());
        }
        Ok(identity)
    }

    /// Decodes a mediator identity from text saved by [`Self::to_text`].
    pub fn from_text(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        let name = lines.next()?.to_string();
        let mut seed =
            || -> Option<[u8; 32]> { crate::persistence::unhex(lines.next()?)?.try_into().ok() };
        let (ns, signing, auth) = (seed()?, seed()?, seed()?);
        Some(Self {
            name,
            namespace_key: tw::Ed25519Key::from_seed(ns),
            signing_key: tw::Ed25519Key::from_seed(signing),
            sequencer_auth_key: tw::Ed25519Key::from_seed(auth),
        })
    }

    /// The name, then the seeds of the namespace, signing and authentication keys (hex), one per line.
    pub fn to_text(&self) -> String {
        let mut text = format!("{}\n", self.name);
        for key in [
            &self.namespace_key,
            &self.signing_key,
            &self.sequencer_auth_key,
        ] {
            text.push_str(&crate::persistence::hex(&key.seed()));
            text.push('\n');
        }
        text
    }

    pub fn namespace(&self) -> &str {
        &self.namespace_key.fingerprint
    }

    /// `name::namespace`: how a `MediatorSynchronizerState` names the mediator.
    pub fn uid(&self) -> String {
        format!("{}::{}", self.name, self.namespace())
    }

    /// `MED::name::namespace`: the member the sequencer knows.
    pub fn member(&self) -> String {
        format!("MED::{}", self.uid())
    }

    /// The transactions an operator loads into the synchronizer: the root delegation of the mediator's namespace and its key mapping.
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
                    &self.sequencer_auth_key,
                    &[SequencerAuthentication, ProofOfOwnership],
                ),
            ],
        );
        let mapping_signed = tw::signed(
            mapping.clone(),
            vec![
                self.namespace_key.sign_transaction(&mapping),
                self.signing_key.sign_transaction(&mapping),
                self.sequencer_auth_key.sign_transaction(&mapping),
            ],
        );
        vec![delegation_signed, mapping_signed]
    }
}

/// The onboarding transactions as a file an operator hands over: one hex-encoded `SignedTopologyTransaction` (v30 message) per line.
pub fn onboarding_file(transactions: &[SignedTopologyTransaction]) -> String {
    transactions
        .iter()
        .map(|t| {
            format!(
                "{}\n",
                crate::persistence::hex(&prost::Message::encode_to_vec(t))
            )
        })
        .collect()
}

/// The transactions of an onboarding file (see [`onboarding_file`]).
pub fn read_onboarding_file(text: &str) -> Result<Vec<SignedTopologyTransaction>, String> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            crate::persistence::unhex(l.trim())
                .and_then(|b| {
                    <SignedTopologyTransaction as prost::Message>::decode(b.as_slice()).ok()
                })
                .ok_or_else(|| format!("not a topology transaction: {}", &l[..l.len().min(40)]))
        })
        .collect()
}

/// The mediator (`MED::name::namespace`) whose key mapping is among `transactions`.
pub fn mediator_of(transactions: &[SignedTopologyTransaction]) -> Option<String> {
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
                Some(Mapping::OwnerToKeyMapping(m)) if m.member.starts_with("MED::") => {
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

    /// The onboarding transactions are authorized on their own: a tracker that knows nothing takes both into force, and the member's
    /// keys are the two signing keys.
    #[test]
    fn the_onboarding_transactions_authorize_themselves() {
        let identity = MediatorIdentity::generate("m9");
        let txs = identity.onboarding_transactions();
        let mut tracker = Tracker::from_state(&decode(&[]).unwrap(), "MED::other::x");
        for t in &txs {
            let applied = tracker.apply(&tw::stored_form(t));
            assert!(applied.outcome.is_in_force(), "{:?}", applied.outcome);
        }
        assert_eq!(
            tracker.signing_keys_of(&identity.member()).map(|k| k.len()),
            Some(2)
        );
        let back = read_onboarding_file(&onboarding_file(&txs)).unwrap();
        assert_eq!(back, txs);
        assert_eq!(mediator_of(&back), Some(identity.member()));
    }

    #[test]
    fn an_identity_is_kept_and_read_back() {
        let identity = MediatorIdentity::generate("m9");
        let again = MediatorIdentity::from_text(&identity.to_text()).unwrap();
        assert_eq!(again.member(), identity.member());
        assert_eq!(
            again.sequencer_auth_key.seed(),
            identity.sequencer_auth_key.seed()
        );
    }
}
