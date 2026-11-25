//! The synchronizer's own topology state, and the store the sequencer hands a new member from (`DownloadTopologyStateForInit`).
//!
//! The state starts with the transactions that make the synchronizer exist, all signed in **one namespace** (the synchronizer's, whose root
//! key is generated when the server starts; the official sandbox splits it over a decentralized namespace of the sequencer's and the mediator's,
//! which is not needed for a participant to accept the state): the root `NamespaceDelegation`, the key mappings of the sequencer
//! (`SEQ::...`) and the mediator (`MED::...`), the dynamic `SynchronizerParametersState`, and the `MediatorSynchronizerState` and
//! `SequencerSynchronizerState` that name who serves. A member that registers adds its own transactions after those, valid from the time it
//! registered plus the topology change delay (S-NET-037: the effective time measured on the official node, G5 U-22).
//!
//! The store is also the synchronizer's **authority on the topology**: every topology broadcast the sequencer orders goes through the same
//! `Tracker` a participant follows a synchronizer with (verified signatures, the namespaces that have to authorize, the next serial). What is in
//! force, and what is a well-formed proposal still waiting for a signature, is appended to the state in sequencing order, so a member that
//! joins **later** downloads it; what is refused is not kept. The mediator reads who hosts a party **at a request's time** from here.
//!
//! [CANTON-NOTE: SEMANTICS] A joining JVM participant replays the downloaded state through its own validator and compares the result entry by
//! entry (`InitialTopologySnapshotValidator`): sequencing time, effective time, the transaction and whether it is a proposal have to match
//! (signatures and the end of validity are not compared). So a proposal is kept as a proposal, and the broadcast that completes it is kept
//! as the full transaction with the signatures of both.
//!
//! [CANTON-NOTE: LIMITATION] In memory. Mappings the tracker does not follow (party-to-key mappings, hosting limits, a participant's
//! synchronizer permission) are not kept.
use canton_participant::topology_state::{
    broadcast_transactions, decode, MediatorGroup, Outcome, Tracker,
};
use canton_participant::topology_wire as tw;
use canton_participant::view_acs::Timeouts;
use canton_proto::com::digitalasset::canton::crypto::v30::{
    public_key::Key, PublicKey, SigningKeyUsage,
};
use canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction;
use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// The keys of a synchronizer's namespace, sequencer and mediator, generated when the server starts.
pub struct SynchronizerKeys {
    /// The **sequencer's namespace** key: one of the two owners of the synchronizer's decentralized namespace.
    pub namespace: tw::Ed25519Key,
    /// The **mediator's namespace** key: the other owner.
    pub mediator_namespace: tw::Ed25519Key,
    pub sequencer_signing: tw::Ed25519Key,
    pub sequencer_authentication: tw::Ed25519Key,
    pub mediator_signing: tw::Ed25519Key,
    sequencer_encryption: Vec<u8>,
    mediator_encryption: Vec<u8>,
    /// The seeds of the five Ed25519 keys (sequencer namespace, sequencer signing, sequencer authentication, mediator signing, mediator
    /// namespace): what is kept.
    seeds: [[u8; 32]; 5],
    /// The mediators of the groups after the first (group 1, 2, ...): their signing key, encryption key (SPKI) and seed.
    extra_mediators: Vec<(tw::Ed25519Key, Vec<u8>, [u8; 32])>,
}

impl std::fmt::Debug for SynchronizerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SynchronizerKeys({})", self.namespace.fingerprint)
    }
}

impl SynchronizerKeys {
    pub fn generate() -> Self {
        Self::generate_with_groups(1)
    }

    /// Keys for a synchronizer with `groups` mediator groups (at least one), each with its own mediator.
    pub fn generate_with_groups(groups: usize) -> Self {
        use rand::RngCore;
        let seed = || {
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            seed
        };
        let seeds = [seed(), seed(), seed(), seed(), seed()];
        // a P-256 encryption key for each: the identity generator makes one, which is all of it that is used here
        let encryption = |name: &str| {
            tw::ParticipantIdentity::generate(name)
                .encryption_spki()
                .to_vec()
        };
        let extra = (1..groups.max(1))
            .map(|g| (seed(), encryption(&format!("synchronizer-mediator-{g}"))))
            .collect();
        Self::from_parts(
            seeds,
            encryption("synchronizer-sequencer"),
            encryption("synchronizer-mediator"),
            extra,
        )
    }

    /// Keys for a sequencer that serves a synchronizer it does not own (an official one it joined): the events it hands out are signed with the sequencer's own
    /// protocol key (`signing_seed`, the key its topology mapping lists) and the members authenticate it with its authentication key. The synchronizer's
    /// namespace keys are not this node's: the ones here are placeholders that sign nothing.
    pub fn for_sequencer(
        namespace_seed: [u8; 32],
        signing_seed: [u8; 32],
        authentication_seed: [u8; 32],
    ) -> Self {
        use rand::RngCore;
        let seed = || {
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            seed
        };
        let encryption = |name: &str| {
            tw::ParticipantIdentity::generate(name)
                .encryption_spki()
                .to_vec()
        };
        Self::from_parts(
            [
                namespace_seed,
                signing_seed,
                authentication_seed,
                seed(),
                seed(),
            ],
            encryption("synchronizer-sequencer"),
            encryption("synchronizer-mediator"),
            Vec::new(),
        )
    }

    fn from_parts(
        seeds: [[u8; 32]; 5],
        sequencer_encryption: Vec<u8>,
        mediator_encryption: Vec<u8>,
        extra: Vec<([u8; 32], Vec<u8>)>,
    ) -> Self {
        let ed = |seed: &[u8; 32]| {
            tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(seed))
        };
        Self {
            namespace: ed(&seeds[0]),
            sequencer_signing: ed(&seeds[1]),
            sequencer_authentication: ed(&seeds[2]),
            mediator_signing: ed(&seeds[3]),
            mediator_namespace: ed(&seeds[4]),
            sequencer_encryption,
            mediator_encryption,
            seeds,
            extra_mediators: extra
                .into_iter()
                .map(|(seed, encryption)| (ed(&seed), encryption, seed))
                .collect(),
        }
    }

    /// Computes `DecentralizedNamespaceDefinition.computeNamespace`: sorted owner fingerprints hashed with purpose 37.
    pub fn synchronizer_namespace(&self) -> String {
        let owners = [
            self.namespace.fingerprint.as_str(),
            self.mediator_namespace.fingerprint.as_str(),
        ];
        decentralized_namespace(&owners)
    }

    /// How many mediator groups the synchronizer has.
    pub fn groups(&self) -> usize {
        1 + self.extra_mediators.len()
    }

    /// The signing key of the mediator of `group`.
    pub fn mediator_key(&self, group: usize) -> &tw::Ed25519Key {
        match group {
            0 => &self.mediator_signing,
            g => &self.extra_mediators[g - 1].0,
        }
    }

    /// The encryption key (SPKI) of the mediator of `group`.
    fn mediator_encryption_of(&self, group: usize) -> &[u8] {
        match group {
            0 => &self.mediator_encryption,
            g => &self.extra_mediators[g - 1].1,
        }
    }

    /// The keys kept in `dir` (file `keys`), or new ones written there when there are none yet.
    ///
    /// [CANTON-NOTE: SEMANTICS] The keys are the synchronizer's identity: its namespace is the fingerprint of the first, so a restart
    /// with other keys would be another synchronizer that no member of the old one recognizes.
    pub fn load_or_create(dir: &std::path::Path, groups: usize) -> std::io::Result<Self> {
        let store =
            canton_participant::state_store::FileStore::new(dir).map_err(std::io::Error::other)?;
        Self::load_or_create_in(store.as_ref(), groups)
    }

    /// Like [`SynchronizerKeys::load_or_create`], with the keys kept under the key `keys` of `store` (a directory or a database).
    pub fn load_or_create_in(
        store: &dyn canton_participant::state_store::StateStore,
        groups: usize,
    ) -> std::io::Result<Self> {
        use crate::persistence::{hex, unhex};
        if let Some(text) = store.read("keys").map_err(std::io::Error::other)? {
            let lines: Vec<&str> = text.lines().collect();
            let parsed = (|| {
                let mut seeds = [[0u8; 32]; 5];
                for (i, seed) in seeds.iter_mut().enumerate() {
                    *seed = unhex(lines.get(i)?)?.try_into().ok()?;
                }
                // the mediators of the groups after the first follow, each as `seed encryption` on one line
                let mut extra = Vec::new();
                for line in lines.iter().skip(7) {
                    let (seed, encryption) = line.split_once(' ')?;
                    extra.push((unhex(seed)?.try_into().ok()?, unhex(encryption)?));
                }
                Some(Self::from_parts(
                    seeds,
                    unhex(lines.get(5)?)?,
                    unhex(lines.get(6)?)?,
                    extra,
                ))
            })();
            return parsed.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "the keys are damaged")
            });
        }
        let keys = Self::generate_with_groups(groups);
        let mut text = String::new();
        for seed in &keys.seeds {
            text.push_str(&hex(seed));
            text.push('\n');
        }
        text.push_str(&hex(&keys.sequencer_encryption));
        text.push('\n');
        text.push_str(&hex(&keys.mediator_encryption));
        text.push('\n');
        for (_, encryption, seed) in &keys.extra_mediators {
            text.push_str(&format!("{} {}\n", hex(seed), hex(encryption)));
        }
        // created once and whole: a crash leaves no keys or all of them, and keys that were made are never replaced
        if !store
            .create_new("keys", &text)
            .map_err(std::io::Error::other)?
        {
            return Self::load_or_create_in(store, groups);
        }
        Ok(keys)
    }
}

/// The (versioned) bytes of an ADD_REPLACE topology transaction of `mapping` at `serial`.
fn transaction_of(mapping: topology_mapping_v31::Mapping, serial: u32) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v31::{
        TopologyMapping, TopologyTransaction,
    };
    use prost::Message;
    // the version wrapper of a transaction as the nodes write it: taken from one this crate already makes
    let probe = tw::namespace_delegation(
        "x",
        tw::Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[1; 32]))
            .public_key(&[SigningKeyUsage::Namespace]),
    );
    let (_, version) = tw::unversioned(&probe).expect("a versioned transaction");
    let tx = TopologyTransaction {
        operation: 1,
        serial,
        mapping: Some(TopologyMapping {
            mapping: Some(mapping),
        }),
    };
    tw::versioned(tx.encode_to_vec(), version)
}

use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping as topology_mapping_v31;

/// `DecentralizedNamespaceDefinition.computeNamespace`: sorted owner namespaces hashed with purpose 37 as a `1220...` multihash.
pub fn decentralized_namespace(owners: &[&str]) -> String {
    let mut sorted: Vec<&str> = owners.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut h = canton_algo::PurposeHash::new(37);
    for o in &sorted {
        let _ = h.add_byte_string(o.as_bytes());
    }
    let digest = h.finish().expect("purpose hash builder finish");
    let mut out = String::from("1220");
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Builds the genesis topology transactions of a multi-sequencer BFT synchronizer.
pub fn build_bft_genesis(
    name: &str,
    sequencers: &[&crate::sequencer_identity::SequencerIdentity],
    mediators: &[&crate::mediator_identity::MediatorIdentity],
    owner_names: &[String],
    threshold: i32,
) -> Result<(String, Vec<SignedTopologyTransaction>), String> {
    if sequencers.is_empty() {
        return Err("BFT genesis requires at least one sequencer".into());
    }
    let mut owner_pairs: Vec<(String, &tw::Ed25519Key)> = Vec::new();
    let names_to_find: Vec<String> = if owner_names.is_empty() {
        sequencers.iter().map(|s| s.name.clone()).collect()
    } else {
        owner_names.to_vec()
    };
    for owner in &names_to_find {
        if let Some(s) = sequencers.iter().find(|s| &s.name == owner) {
            owner_pairs.push((s.namespace().to_string(), &s.namespace_key));
        } else if let Some(m) = mediators.iter().find(|m| &m.name == owner) {
            owner_pairs.push((m.namespace().to_string(), &m.namespace_key));
        } else {
            return Err(format!("unknown synchronizer owner {owner} in BFT genesis"));
        }
    }
    let owner_ns_refs: Vec<&str> = owner_pairs.iter().map(|(ns, _)| ns.as_str()).collect();
    let namespace = decentralized_namespace(&owner_ns_refs);
    let synchronizer_uid = format!("{name}::{namespace}");

    let mut txs = Vec::new();
    for s in sequencers {
        txs.extend(s.onboarding_transactions());
    }
    for m in mediators {
        txs.extend(m.onboarding_transactions());
    }

    let sign_by_owners = |bytes: Vec<u8>| -> SignedTopologyTransaction {
        let signatures = owner_pairs
            .iter()
            .map(|(_, key)| key.sign_transaction(&bytes))
            .collect();
        tw::signed(bytes, signatures)
    };
    let eff_threshold = threshold.max(1);
    txs.push(sign_by_owners(decentralized_namespace_definition(
        &namespace,
        eff_threshold,
        &owner_ns_refs,
    )));
    txs.push(sign_by_owners(tw::synchronizer_parameters_state(
        &synchronizer_uid,
        tw::default_dynamic_parameters(),
    )));
    let mediator_uids: Vec<String> = mediators.iter().map(|m| m.uid()).collect();
    let mediator_refs: Vec<&str> = mediator_uids.iter().map(String::as_str).collect();
    // [CANTON-NOTE: SEMANTICS] a group needs at least one active mediator (`MediatorSynchronizerState.create`): none without mediators
    if !mediator_refs.is_empty() {
        txs.push(sign_by_owners(tw::mediator_synchronizer_state(
            &synchronizer_uid,
            0,
            1,
            &mediator_refs,
        )));
    }
    let sequencer_uids: Vec<String> = sequencers.iter().map(|s| s.uid()).collect();
    let sequencer_refs: Vec<&str> = sequencer_uids.iter().map(String::as_str).collect();
    txs.push(sign_by_owners(tw::sequencer_synchronizer_state(
        &synchronizer_uid,
        1,
        &sequencer_refs,
    )));

    Ok((namespace, txs))
}

/// The (versioned) bytes of the `DecentralizedNamespaceDefinition` of `namespace`: `threshold` of the `owners` have to sign what it controls.
fn decentralized_namespace_definition(namespace: &str, threshold: i32, owners: &[&str]) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v30::DecentralizedNamespaceDefinition;
    transaction_of(
        topology_mapping_v31::Mapping::DecentralizedNamespaceDefinition(
            DecentralizedNamespaceDefinition {
                decentralized_namespace: namespace.to_string(),
                threshold,
                owners: owners.iter().map(|o| o.to_string()).collect(),
            },
        ),
        1,
    )
}

/// The synchronizer's dynamic parameters `parameters` at topology serial `serial`, signed by both owners of the synchronizer's namespace: how
/// the owners change them (the traffic control, say).
/// `bytes` (a topology transaction) signed by the owners of the synchronizer's namespace: the sequencer's and the mediator's namespace keys.
pub fn signed_by_owners(keys: &SynchronizerKeys, bytes: Vec<u8>) -> SignedTopologyTransaction {
    let signatures = vec![
        keys.namespace.sign_transaction(&bytes),
        keys.mediator_namespace.sign_transaction(&bytes),
    ];
    tw::signed(bytes, signatures)
}

pub fn parameters_transaction(
    keys: &SynchronizerKeys,
    synchronizer_uid: &str,
    serial: u32,
    parameters: canton_proto::com::digitalasset::canton::protocol::v30::DynamicSynchronizerParameters,
) -> SignedTopologyTransaction {
    let bytes = transaction_of(
        topology_mapping_v31::Mapping::SynchronizerParametersState(
            canton_proto::com::digitalasset::canton::protocol::v30::SynchronizerParametersState {
                synchronizer_id: synchronizer_uid.to_string(),
                synchronizer_parameters: Some(parameters),
            },
        ),
        serial,
    );
    tw::signed(
        bytes.clone(),
        vec![
            keys.namespace.sign_transaction(&bytes),
            keys.mediator_namespace.sign_transaction(&bytes),
        ],
    )
}

/// The topology transactions of a **logical synchronizer upgrade** to `successor_psid` at `upgrade_micros`, at topology serial `serial`: the
/// announcement, signed by both owners of the synchronizer's namespace, and the sequencer's connection on the successor (`endpoint`, such
/// as `http://127.0.0.1:15994`), signed by the sequencer's namespace. The connection is valid only once the announcement is in force: they
/// are sequenced one after the other, not in one broadcast.
///
/// [CANTON-NOTE: SEMANTICS] A participant moves to the successor only through sequencers that published such a connection: it connects to
/// the endpoint and checks that the sequencer there has the **same sequencer id** (`LogicalSynchronizerUpgrade.prepareNewSynchronizerConnectionConfig`).
pub fn upgrade_transactions(
    keys: &SynchronizerKeys,
    sequencer_uid: &str,
    successor_psid: &str,
    serial: u32,
    upgrade_micros: i64,
    endpoint: &str,
) -> [SignedTopologyTransaction; 2] {
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        lsu_sequencer_connection_successor::SequencerConnection, LsuAnnouncement,
        LsuSequencerConnectionSuccessor,
    };
    let announcement = transaction_of(
        topology_mapping_v31::Mapping::SynchronizerUpgradeAnnouncement(LsuAnnouncement {
            successor_physical_synchronizer_id: successor_psid.to_string(),
            upgrade_time: Some(prost_types::Timestamp {
                seconds: upgrade_micros.div_euclid(1_000_000),
                nanos: (upgrade_micros.rem_euclid(1_000_000) * 1000) as i32,
            }),
        }),
        serial,
    );
    let connection = transaction_of(
        topology_mapping_v31::Mapping::SequencerConnectionSuccessor(
            LsuSequencerConnectionSuccessor {
                sequencer_id: format!("SEQ::{sequencer_uid}"),
                successor_physical_synchronizer_id: successor_psid.to_string(),
                connection: Some(SequencerConnection {
                    endpoints: vec![endpoint.to_string()],
                    custom_trust_certificates: None,
                }),
            },
        ),
        serial,
    );
    [
        tw::signed(
            announcement.clone(),
            vec![
                keys.namespace.sign_transaction(&announcement),
                keys.mediator_namespace.sign_transaction(&announcement),
            ],
        ),
        tw::signed(
            connection.clone(),
            vec![keys.namespace.sign_transaction(&connection)],
        ),
    ]
}

/// The time before which nothing was sequenced: the official node's `valid_from` of the synchronizer's own transactions.
pub const BEGINNING_OF_TIME_MICROS: i64 = -62_135_596_799_999_999;

/// The topology change delay (`topology_change_delay` of the static parameters: 250 ms).
pub const TOPOLOGY_CHANGE_DELAY_MICROS: i64 = 250_000;

/// One transaction of the state with the time it takes effect.
#[derive(Clone)]
pub struct StoredTransaction {
    pub signed: SignedTopologyTransaction,
    pub sequenced_micros: i64,
    pub valid_from_micros: i64,
}

/// The state, in the order it is handed out (the order the state hash is over).
pub struct TopologyStore {
    inner: Mutex<Inner>,
    /// Where the transactions the state takes are journaled (attached once the journal has been replayed).
    journal: std::sync::OnceLock<std::sync::Arc<crate::persistence::Journal>>,
    /// The mediator groups of a synchronizer this store only observes (see [`Self::observe_mediator_groups`]).
    observed_mediator_groups: std::sync::OnceLock<BTreeMap<u32, MediatorGroup>>,
}

/// A party's hosting: the threshold and every hosting participant with its permission (1 submission, 2 confirmation, 3 observation).
type Parties = (u32, Vec<(String, i32)>);

/// Who may confirm for a party and how many of them have to: (hosting threshold, the hosting participants' uids).
pub type Hosting = (u32, Vec<String>);

struct Inner {
    entries: Vec<StoredTransaction>,
    /// What the signatures and serials of the broadcasts are checked against.
    tracker: Tracker,
    /// Party -> its hostings in the order they took effect: (effective from, the threshold and every host with its permission; `None`
    /// once the party is removed).
    hosting: BTreeMap<String, Vec<(i64, Option<Parties>)>>,
    /// The synchronizer's timeouts in the order they took effect: (effective from, the timeouts).
    timeouts: Vec<(i64, Timeouts)>,
    /// The synchronizer's `max_request_size` in the order it took effect: (effective from, bytes).
    max_request_sizes: Vec<(i64, u32)>,
    /// The traffic control parameters in the order they took effect: (effective from, `None` while traffic control is off).
    traffic: Vec<(i64, Option<crate::traffic::TrafficParams>)>,
    /// The mediator groups in the order they took effect: (effective from, every group in force).
    mediator_groups: Vec<(i64, BTreeMap<u32, MediatorGroup>)>,
}

impl Inner {
    /// Appends `signed` as sequenced at `sequenced` (never before the last entry: the state is handed out in sequencing order).
    fn push(&mut self, signed: SignedTopologyTransaction, sequenced: i64) -> i64 {
        let sequenced = self
            .entries
            .last()
            .map_or(sequenced, |last| sequenced.max(last.sequenced_micros));
        let valid_from = if sequenced == BEGINNING_OF_TIME_MICROS {
            sequenced
        } else {
            sequenced + TOPOLOGY_CHANGE_DELAY_MICROS
        };
        self.entries.push(StoredTransaction {
            signed,
            sequenced_micros: sequenced,
            valid_from_micros: valid_from,
        });
        // [CANTON-NOTE: SEMANTICS] a change of the dynamic parameters takes effect like any topology change, after the delay: a request
        // sequenced before that is still timed out by the old timeouts
        if let Some(now) = self.tracker.learned().timeouts {
            if self.timeouts.last().map(|(_, t)| t) != Some(&now) {
                self.timeouts.push((valid_from, now));
            }
        }
        if let Some(size) = self.tracker.max_request_size() {
            if self.max_request_sizes.last().map(|(_, s)| *s) != Some(size) {
                self.max_request_sizes.push((valid_from, size));
            }
        }
        let traffic = self
            .tracker
            .traffic_control()
            .map(crate::traffic::TrafficParams::from_proto);
        if self
            .traffic
            .last()
            .map_or(traffic.is_some(), |(_, t)| *t != traffic)
        {
            self.traffic.push((valid_from, traffic));
        }
        let groups = self.tracker.mediator_groups();
        if self.mediator_groups.last().map(|(_, g)| g) != Some(groups) {
            self.mediator_groups.push((valid_from, groups.clone()));
        }
        valid_from
    }

    /// Takes one stored transaction: the tracker decides, the state keeps what is in force or waiting, and a hosting that came into
    /// force is remembered with its effective time.
    fn take(&mut self, stored: &[u8], sequenced: i64) -> Outcome {
        // the time the transaction takes effect: what an upgrade time has to be after
        let sequenced_at = self
            .entries
            .last()
            .map_or(sequenced, |last| sequenced.max(last.sequenced_micros));
        let applied = self
            .tracker
            .apply_at(stored, Some(sequenced_at + TOPOLOGY_CHANGE_DELAY_MICROS));
        // a proposal is kept only when somebody the state knows signed it: a transaction nobody verifiably signed is nothing
        let keep = match (&applied.outcome, &applied.merged) {
            (Outcome::InForce(_), _) => true,
            (Outcome::Waiting(_), Some(merged)) => !merged.signatures.is_empty(),
            _ => false,
        };
        let (Some(merged), true) = (applied.merged, keep) else {
            return applied.outcome;
        };
        let party = decode(&[(0, stored.to_vec())]).ok().and_then(|entries| {
            match entries[0]
                .tx
                .mapping
                .as_ref()
                .and_then(|m| m.mapping.as_ref())
            {
                Some(Mapping::PartyToParticipant(p)) => Some(p.party.clone()),
                _ => None,
            }
        });
        let valid_from = self.push(merged, sequenced);
        if let (Some(party), true) = (party, applied.outcome.is_in_force()) {
            let now = self.tracker.hosts_of(&party);
            self.hosting
                .entry(party)
                .or_default()
                .push((valid_from, now));
        }
        applied.outcome
    }
}

impl TopologyStore {
    /// The synchronizer's own transactions, signed with `keys`, for the synchronizer `name` (the namespace of `keys.namespace`).
    pub fn initial(
        name: &str,
        sequencer_name: &str,
        mediator_name: &str,
        keys: &SynchronizerKeys,
    ) -> Self {
        let sequencer_namespace = keys.namespace.fingerprint.clone();
        let mediator_namespace = keys.mediator_namespace.fingerprint.clone();
        let namespace = keys.synchronizer_namespace();
        let synchronizer_uid = format!("{name}::{namespace}");
        let sequencer = format!("SEQ::{sequencer_name}::{sequencer_namespace}");
        let mediator = format!("MED::{mediator_name}::{mediator_namespace}");
        let (seq_root, med_root) = (&keys.namespace, &keys.mediator_namespace);
        let mut transactions: Vec<SignedTopologyTransaction> = Vec::new();
        // what the owners of the synchronizer's namespace sign together
        let by_owners = |bytes: Vec<u8>| {
            let signatures = vec![
                seq_root.sign_transaction(&bytes),
                med_root.sign_transaction(&bytes),
            ];
            tw::signed(bytes, signatures)
        };
        // each owner's namespace: a root delegation signed by its own key
        for (ns, key) in [
            (&sequencer_namespace, seq_root),
            (&mediator_namespace, med_root),
        ] {
            let bytes = tw::namespace_delegation(ns, key.public_key(&[SigningKeyUsage::Namespace]));
            let signature = key.sign_transaction(&bytes);
            transactions.push(tw::signed(bytes, vec![signature]));
        }
        // the synchronizer's namespace: decentralized, owned by both, and every owner has to sign the definition
        transactions.push(by_owners(decentralized_namespace_definition(
            &namespace,
            2,
            &[&sequencer_namespace, &mediator_namespace],
        )));
        let signing = |k: &tw::Ed25519Key, usages: &[SigningKeyUsage]| PublicKey {
            key: Some(Key::SigningPublicKey(k.public_key(usages))),
        };
        use SigningKeyUsage::{ProofOfOwnership, Protocol, SequencerAuthentication};
        // a key mapping is signed in the member's namespace and by every signing key it names (proof of possession)
        let sequencer_mapping = tw::owner_to_key_mapping(
            &sequencer,
            vec![
                signing(&keys.sequencer_signing, &[Protocol, ProofOfOwnership]),
                signing(
                    &keys.sequencer_authentication,
                    &[SequencerAuthentication, ProofOfOwnership],
                ),
                tw::p256_encryption_key(&keys.sequencer_encryption),
            ],
        );
        transactions.push(tw::signed(
            sequencer_mapping.clone(),
            vec![
                seq_root.sign_transaction(&sequencer_mapping),
                keys.sequencer_signing.sign_transaction(&sequencer_mapping),
                keys.sequencer_authentication
                    .sign_transaction(&sequencer_mapping),
            ],
        ));
        // each mediator group has its own mediator: a key mapping for it and, below, the state that names who serves the group
        let mediator_names: Vec<String> = (0..keys.groups())
            .map(|g| {
                if g == 0 {
                    mediator_name.to_string()
                } else {
                    format!("rm{}", g + 1)
                }
            })
            .collect();
        for (g, name) in mediator_names.iter().enumerate() {
            let member = format!("MED::{name}::{mediator_namespace}");
            let mapping = tw::owner_to_key_mapping(
                &member,
                vec![
                    signing(keys.mediator_key(g), &[Protocol, ProofOfOwnership]),
                    tw::p256_encryption_key(keys.mediator_encryption_of(g)),
                ],
            );
            transactions.push(tw::signed(
                mapping.clone(),
                vec![
                    med_root.sign_transaction(&mapping),
                    keys.mediator_key(g).sign_transaction(&mapping),
                ],
            ));
        }
        transactions.push(by_owners(tw::synchronizer_parameters_state(
            &synchronizer_uid,
            tw::default_dynamic_parameters(),
        )));
        for (g, name) in mediator_names.iter().enumerate() {
            transactions.push(by_owners(tw::mediator_synchronizer_state(
                &synchronizer_uid,
                g as u32,
                1,
                // [CANTON-NOTE: SEMANTICS] the members of a mediator or sequencer state are **uids** (`name::fingerprint`), not member ids
                // (`MED::name::fingerprint`): the JVM refused the member id ("String contains reserved delimiter `::`", measured)
                &[&format!("{name}::{mediator_namespace}")],
            )));
        }
        transactions.push(by_owners(tw::sequencer_synchronizer_state(
            &synchronizer_uid,
            1,
            &[&format!("{sequencer_name}::{sequencer_namespace}")],
        )));
        let mut inner = Inner {
            entries: Vec::new(),
            tracker: {
                let mut t = Tracker::from_state(&[], &mediator);
                // what an upgrade announcement is checked against: this synchronizer
                t.set_current_psid(canton_participant::topology_state::Psid {
                    logical: synchronizer_uid,
                    serial: 0,
                    protocol_version: crate::PROTOCOL_VERSION,
                });
                t.set_crypto_specs(Self::default_crypto_specs_for(0, false));
                t
            },
            hosting: BTreeMap::new(),
            timeouts: Vec::new(),
            max_request_sizes: Vec::new(),
            traffic: Vec::new(),
            mediator_groups: Vec::new(),
        };
        for signed in transactions {
            // the synchronizer's own transactions are in force by construction; the tracker learns the keys from them
            inner.tracker.apply(&tw::stored_form(&signed));
            inner.push(signed, BEGINNING_OF_TIME_MICROS);
        }
        Self {
            inner: Mutex::new(inner),
            journal: std::sync::OnceLock::new(),
            observed_mediator_groups: std::sync::OnceLock::new(),
        }
    }

    /// Seeds a topology store from official `common_topology_transactions` rows `(sequenced, valid_from, stored_bytes)` (`U-49`).
    pub fn from_official(
        synchronizer_uid: &str,
        serial: u32,
        self_member: &str,
        rows: Vec<(i64, i64, Vec<u8>)>,
    ) -> Result<Self, String> {
        let items: Vec<(i64, Vec<u8>)> = rows
            .iter()
            .map(|(_, valid_from, stored)| (*valid_from, stored.clone()))
            .collect();
        let decoded = decode(&items)?;
        let mut tracker = Tracker::from_state(&decoded, self_member);
        tracker.set_current_psid(canton_participant::topology_state::Psid {
            logical: synchronizer_uid.to_string(),
            serial,
            protocol_version: crate::PROTOCOL_VERSION,
        });
        tracker.set_crypto_specs(Self::default_crypto_specs_for(serial, true));
        let entries: Vec<StoredTransaction> = decoded
            .into_iter()
            .zip(rows)
            .map(
                |(entry, (sequenced_micros, valid_from_micros, _))| StoredTransaction {
                    signed: entry.signed,
                    sequenced_micros,
                    valid_from_micros,
                },
            )
            .collect();
        let mut hosting: BTreeMap<String, Vec<(i64, Option<Parties>)>> = BTreeMap::new();
        for party in tracker.hosts_now().into_keys() {
            if let Some(h) = tracker.hosts_of(&party) {
                hosting.insert(party, vec![(BEGINNING_OF_TIME_MICROS, Some(h))]);
            }
        }
        let timeouts = tracker
            .learned()
            .timeouts
            .map(|t| vec![(BEGINNING_OF_TIME_MICROS, t)])
            .unwrap_or_default();
        let max_request_sizes = tracker
            .max_request_size()
            .map(|s| vec![(BEGINNING_OF_TIME_MICROS, s)])
            .unwrap_or_default();
        let traffic = tracker
            .traffic_control()
            .map(|tc| {
                vec![(
                    BEGINNING_OF_TIME_MICROS,
                    Some(crate::traffic::TrafficParams::from_proto(tc)),
                )]
            })
            .unwrap_or_default();
        let mediator_groups = vec![(BEGINNING_OF_TIME_MICROS, tracker.mediator_groups().clone())];
        Ok(Self {
            inner: Mutex::new(Inner {
                entries,
                tracker,
                hosting,
                timeouts,
                max_request_sizes,
                traffic,
                mediator_groups,
            }),
            journal: std::sync::OnceLock::new(),
            observed_mediator_groups: std::sync::OnceLock::new(),
        })
    }

    /// Returns `true` when `mediator_uid` (`name::fingerprint`) is active in any mediator group of this store.
    pub fn has_active_mediator(&self, mediator_uid: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tracker
            .mediator_groups()
            .values()
            .any(|g| g.active.iter().any(|u| u == mediator_uid))
    }

    /// Builds a topology store directly from pre-signed BFT genesis transactions.
    pub fn from_genesis(
        synchronizer_uid: &str,
        serial: u32,
        self_member: &str,
        transactions: Vec<SignedTopologyTransaction>,
    ) -> Result<Self, String> {
        let mut inner = Inner {
            entries: Vec::new(),
            tracker: {
                let mut t = Tracker::from_state(&[], self_member);
                t.set_current_psid(canton_participant::topology_state::Psid {
                    logical: synchronizer_uid.to_string(),
                    serial,
                    protocol_version: crate::PROTOCOL_VERSION,
                });
                t.set_crypto_specs(Self::default_crypto_specs_for(serial, false));
                t
            },
            hosting: BTreeMap::new(),
            timeouts: Vec::new(),
            max_request_sizes: Vec::new(),
            traffic: Vec::new(),
            mediator_groups: Vec::new(),
        };
        for signed in transactions {
            let applied = inner.tracker.apply(&tw::stored_form(&signed));
            if matches!(applied.outcome, Outcome::Refused(_) | Outcome::Waiting(_)) {
                return Err(format!(
                    "genesis topology transaction rejected: {}",
                    applied.outcome.note()
                ));
            }
            let merged = applied.merged.unwrap_or(signed);
            inner.push(merged, BEGINNING_OF_TIME_MICROS);
        }
        Ok(Self {
            inner: Mutex::new(inner),
            journal: std::sync::OnceLock::new(),
            observed_mediator_groups: std::sync::OnceLock::new(),
        })
    }

    /// This state is the physical synchronizer with serial `serial` (a successor after a logical upgrade): what an upgrade announcement is
    /// checked against. Called before the journal is replayed, so that the announcement that led **here** is not in force here.
    pub fn set_serial(&self, serial: u32) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let logical = inner
            .tracker
            .current_psid()
            .map(|p| p.logical.clone())
            .unwrap_or_default();
        inner
            .tracker
            .set_current_psid(canton_participant::topology_state::Psid {
                logical,
                serial,
                protocol_version: crate::PROTOCOL_VERSION,
            });
    }

    /// From now on what the state takes is journaled in `journal`.
    pub fn attach(&self, journal: std::sync::Arc<crate::persistence::Journal>) {
        let _ = self.journal.set(journal);
    }

    /// Adds the transactions of a member that registered (validated by the onboarding), sequenced at `sequenced`: they take effect
    /// after the topology change delay.
    pub fn append(&self, transactions: &[SignedTopologyTransaction], sequenced: i64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for signed in transactions {
            if let Some(journal) = self.journal.get() {
                journal.write(&format!(
                    "A {sequenced} {}",
                    crate::persistence::hex(&prost::Message::encode_to_vec(signed))
                ));
            }
            inner.tracker.apply(&tw::stored_form(signed));
            inner.push(signed.clone(), sequenced);
        }
    }

    /// Takes the transactions of a topology broadcast (`content` is the envelope's content) sequenced at `sequenced`. Returns what
    /// became of each; `None` when the content is no topology broadcast.
    pub fn accept_broadcast(&self, content: &[u8], sequenced: i64) -> Option<Vec<Outcome>> {
        let stored = broadcast_transactions(content)?;
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(journal) = self.journal.get() {
            journal.write(&format!(
                "B {sequenced} {}",
                crate::persistence::hex(content)
            ));
        }
        // one broadcast is one batch: its mapping checks read the state before it
        inner.tracker.begin_batch();
        let outcomes = stored.iter().map(|s| inner.take(s, sequenced)).collect();
        inner.tracker.end_batch();
        Some(outcomes)
    }

    /// Who hosts which party at the time `at`: the hostings whose effective time is **before** `at`.
    ///
    /// [CANTON-NOTE: SEMANTICS] A topology transaction sequenced at `t` is effective from `t + topology_change_delay`, and the state at a
    /// time is what became effective strictly before it (`TopologySnapshot` at a request's timestamp): a request sequenced inside the
    /// delay of a hosting change is still decided with the old hosting.
    pub fn hosting_at(&self, at: i64) -> BTreeMap<String, Hosting> {
        self.parties_at(at)
            .into_iter()
            .map(|(party, (threshold, hosts))| {
                (
                    party,
                    (
                        threshold,
                        hosts
                            .into_iter()
                            // permission 1 (submission) and 2 (confirmation) may confirm
                            .filter(|(_, permission)| matches!(permission, 1 | 2))
                            .map(|(uid, _)| uid)
                            .collect(),
                    ),
                )
            })
            .collect()
    }

    /// The topology state of a **successor** synchronizer: the predecessor's state, taken over whole when it is the state the predecessor says it
    /// is, and only for a successor that follows the upgrade rules.
    ///
    /// [CANTON-NOTE: SEMANTICS] A logical synchronizer upgrade starts the successor from the predecessor's topology: the same transactions with
    /// the same sequencing and effective times, so the state hash is the same and every member that trusted the predecessor's keys trusts the
    /// successor's. The import refuses a snapshot whose hash is not `expected_hash` (a changed or incomplete state), a successor of another
    /// logical synchronizer, a successor that is not greater than the predecessor, and a **protocol version downgrade**.
    pub fn import_snapshot(
        entries: Vec<StoredTransaction>,
        expected_hash: &[u8],
        predecessor: &canton_participant::topology_state::Psid,
        successor: &canton_participant::topology_state::Psid,
        name: &str,
    ) -> Result<Self, String> {
        use canton_participant::topology_state::is_forbidden_protocol_version_downgrade;
        if successor.logical != predecessor.logical {
            return Err(format!(
                "the successor {successor} is not of the synchronizer {}",
                predecessor.logical
            ));
        }
        if successor <= predecessor {
            return Err(format!(
                "the successor {successor} is not greater than {predecessor}"
            ));
        }
        if is_forbidden_protocol_version_downgrade(predecessor, successor) {
            return Err(format!(
                "The declared successor {successor} has a lower protocol version than the current synchronizer {predecessor}. Protocol version downgrades are not allowed."
            ));
        }
        let transactions: Vec<Vec<u8>> = entries
            .iter()
            .map(|e| e.signed.transaction.clone())
            .collect();
        if tw::topology_state_hash(&transactions) != expected_hash {
            return Err(
                "the snapshot does not have the hash of the predecessor's topology state".into(),
            );
        }
        let mut tracker = Tracker::from_state(&[], &format!("MED::{name}"));
        tracker.set_current_psid(successor.clone());
        tracker.set_crypto_specs(Self::default_crypto_specs_for(successor.serial, false));
        let mut inner = Inner {
            entries: Vec::new(),
            tracker,
            hosting: BTreeMap::new(),
            timeouts: Vec::new(),
            max_request_sizes: Vec::new(),
            traffic: Vec::new(),
            mediator_groups: Vec::new(),
        };
        for e in entries {
            let outcome = inner
                .tracker
                .apply_at(&tw::stored_form(&e.signed), Some(e.valid_from_micros));
            // the snapshot is what the predecessor had taken: a transaction the tracker would refuse now (an announcement that is not
            // allowed for the *successor*, say) is not part of it
            if matches!(outcome.outcome, Outcome::Refused(_)) {
                continue;
            }
            inner.entries.push(e);
        }
        let groups = inner.tracker.mediator_groups().clone();
        inner
            .mediator_groups
            .push((BEGINNING_OF_TIME_MICROS, groups));
        Ok(Self {
            inner: Mutex::new(inner),
            journal: std::sync::OnceLock::new(),
            observed_mediator_groups: std::sync::OnceLock::new(),
        })
    }

    /// Tells a store that only **observes** a synchronizer (`bft-peer --observe-sequencing`: the sequencer of this node makes events of
    /// what the official orderer decided) what that synchronizer's mediator groups are. The store's own topology is a placeholder of this
    /// node's keys, and who may send a group's aggregated verdict is decided from the groups (`Sequencer::submit_checked_at`).
    ///
    /// [CANTON-NOTE: LIMITATION] The groups are the ones read at the start, like the observer's members: a later change of a group on the
    /// observed synchronizer is not followed, and they are in force at every time. Set once; a second call is ignored.
    pub fn observe_mediator_groups(&self, groups: BTreeMap<u32, MediatorGroup>) {
        let _ = self.observed_mediator_groups.set(groups);
    }

    /// The mediator groups in force at the time `at`: what became effective strictly before it.
    ///
    /// [CANTON-NOTE: SEMANTICS] A mediator added to a group serves the requests sequenced after the change took effect (sequencing time +
    /// topology change delay), as the participants choose the group of a request from the topology at its time.
    pub fn mediator_groups_at(&self, at: i64) -> BTreeMap<u32, MediatorGroup> {
        if let Some(observed) = self.observed_mediator_groups.get() {
            return observed.clone();
        }
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .mediator_groups
            .iter()
            .rev()
            .find(|(from, _)| *from < at || *from == BEGINNING_OF_TIME_MICROS)
            .map(|(_, g)| g.clone())
            .unwrap_or_default()
    }

    /// The latest `MediatorSynchronizerState` of every group the state took (in force or not yet effective), with how it is stored.
    pub fn mediator_states(&self) -> Vec<(MediatorGroup, StoredTransaction)> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut latest: BTreeMap<u32, (MediatorGroup, StoredTransaction)> = BTreeMap::new();
        for e in &inner.entries {
            let Ok(entries) = decode(&[(0, tw::stored_form(&e.signed))]) else {
                continue;
            };
            let tx = &entries[0].tx;
            if let Some(Mapping::MediatorSynchronizerState(m)) =
                tx.mapping.as_ref().and_then(|m| m.mapping.as_ref())
            {
                if e.signed.proposal {
                    continue;
                }
                if tx.operation == 2 {
                    latest.remove(&m.group);
                    continue;
                }
                let group = MediatorGroup {
                    serial: tx.serial,
                    threshold: m.threshold,
                    active: m.active.clone(),
                    observers: m.observers.clone(),
                };
                latest.insert(
                    m.group,
                    (
                        group,
                        StoredTransaction {
                            signed: e.signed.clone(),
                            sequenced_micros: e.sequenced_micros,
                            valid_from_micros: e.valid_from_micros,
                        },
                    ),
                );
            }
        }
        latest.into_values().collect()
    }

    /// The sequencer group in force at the time `at`: its threshold and its active sequencers' uids, from the latest
    /// `SequencerSynchronizerState` that became effective strictly before `at`; `None` when there is none.
    pub fn sequencer_group_at(&self, at: i64) -> Option<(u32, Vec<String>)> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for e in inner.entries.iter().rev() {
            let effective =
                e.valid_from_micros < at || e.valid_from_micros == BEGINNING_OF_TIME_MICROS;
            if e.signed.proposal || !effective {
                continue;
            }
            let Ok(entries) = decode(&[(0, tw::stored_form(&e.signed))]) else {
                continue;
            };
            let Some(entry) = entries.first() else {
                continue;
            };
            if let Some(Mapping::SequencerSynchronizerState(s)) =
                entry.tx.mapping.as_ref().and_then(|m| m.mapping.as_ref())
            {
                return (entry.tx.operation != 2).then(|| (s.threshold, s.active.clone()));
            }
        }
        None
    }

    /// The signing keys of `member` (`MED::name::namespace`) as its key mapping the state took lists them.
    pub fn signing_keys_of(&self, member: &str) -> Option<Vec<canton_algo::signing::PublicKey>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tracker
            .signing_keys_of(member)
    }

    /// On a successor: the upgrade time of the upgrade that led here (microseconds). Before it, the successor onboards no one and sequences
    /// nothing but time proofs.
    pub fn upgrade_time_here(&self) -> Option<i64> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tracker
            .upgrade_into_current()
            .map(|lsu| lsu.upgrade_micros)
    }

    /// The upgrade the synchronizer announced, if any: where it goes and when (microseconds).
    pub fn announced_upgrade(&self) -> Option<canton_participant::topology_state::Lsu> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tracker
            .announced_upgrade()
            .cloned()
    }

    /// The dynamic parameters as they stand now (taken, possibly not yet in force) and their serial.
    pub fn parameters(
        &self,
    ) -> Option<(
        u32,
        canton_proto::com::digitalasset::canton::protocol::v30::DynamicSynchronizerParameters,
    )> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.tracker.parameters().map(|(serial, p)| (serial, *p))
    }

    /// The traffic control parameters in force at the time `at`: `None` while traffic control is off.
    pub fn traffic_at(&self, at: i64) -> Option<crate::traffic::TrafficParams> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .traffic
            .iter()
            .rev()
            .find(|(from, _)| *from < at)
            .and_then(|(_, t)| t.clone())
    }

    /// The `confirmation_requests_max_rate` of the parameters in force now (`getApproximateOrDefaultValue`: Canton's default before any).
    pub fn confirmation_requests_max_rate(&self) -> u32 {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .tracker
            .parameters()
            .and_then(|(_, p)| p.participant_synchronizer_limits.as_ref())
            .map_or(crate::rate_limit::DEFAULT_MAX_RATE, |l| {
                l.confirmation_requests_max_rate
            })
    }

    /// The `max_request_size` in force at the time `at` (bytes; the default 10 MiB before any parameters took effect).
    pub fn max_request_size_at(&self, at: i64) -> usize {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .max_request_sizes
            .iter()
            .rev()
            .find(|(from, _)| *from < at)
            .map_or(10_485_760, |(_, s)| *s as usize)
    }

    /// The timeouts in force at the time `at` (the defaults before any parameters took effect).
    pub fn timeouts_at(&self, at: i64) -> Timeouts {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .timeouts
            .iter()
            .rev()
            .find(|(from, _)| *from < at)
            .map(|(_, t)| *t)
            .unwrap_or_default()
    }

    /// All parameter validity slices `(valid_from, valid_until, confirmation_response_micros)` in chronological order.
    pub fn timeout_changes(&self) -> Vec<(i64, Option<i64>, i64)> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .timeouts
            .iter()
            .enumerate()
            .map(|(idx, (valid_from, timeouts))| {
                let valid_until = inner.timeouts.get(idx + 1).map(|(next_from, _)| *next_from);
                (
                    *valid_from,
                    valid_until,
                    timeouts.confirmation_response_micros,
                )
            })
            .collect()
    }

    /// Sets the static crypto schemes / key limits enforced by this store's [`Tracker`].
    pub fn set_crypto_specs(&self, specs: canton_participant::crypto_handshake::Required) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tracker
            .set_crypto_specs(specs);
    }

    fn default_crypto_specs_for(
        serial: u32,
        official: bool,
    ) -> canton_participant::crypto_handshake::Required {
        let mut specs = canton_participant::crypto_handshake::Required::from_v32(
            &crate::static_parameters(serial),
        );
        if official {
            specs.encryption_keys.insert(
                canton_proto::com::digitalasset::canton::crypto::v30::EncryptionKeySpec::Rsa2048
                    as i32,
            );
        }
        specs
    }

    /// Every participant that hosts a party at the time `at`, whatever its permission: who a request for the party has to reach.
    pub fn hosts_at(&self, at: i64) -> BTreeMap<String, Vec<String>> {
        self.parties_at(at)
            .into_iter()
            .map(|(party, (_, hosts))| (party, hosts.into_iter().map(|(uid, _)| uid).collect()))
            .collect()
    }

    fn parties_at(&self, at: i64) -> BTreeMap<String, Parties> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .hosting
            .iter()
            .filter_map(|(party, changes)| {
                let (_, hosting) = changes.iter().rev().find(|(from, _)| *from < at)?;
                Some((party.clone(), hosting.clone()?))
            })
            .collect()
    }

    pub fn snapshot(&self) -> Vec<StoredTransaction> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .clone()
    }

    /// Logical synchronizer UID (`name::namespace`) configured on this topology store.
    pub fn synchronizer_uid(&self) -> String {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tracker
            .current_psid()
            .map(|p| p.logical.clone())
            .unwrap_or_default()
    }

    /// Whether a non-proposal topology transaction with `tx_hash` has been appended to this store.
    pub fn contains_tx_hash(&self, tx_hash: &[u8]) -> bool {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .entries
            .iter()
            .any(|e| !e.signed.proposal && tw::transaction_hash(&e.signed.transaction) == tx_hash)
    }

    /// Every member the state in force serves (`SEQ::*`, `MED::*`, `PAR::*`) with its protocol, authentication and encryption keys: see
    /// [`crate::membership`].
    pub fn registered_members(&self) -> Vec<crate::onboarding::Registered> {
        crate::membership::in_force(self)
    }

    /// The P-256 encryption keys of the participant `member` as its key mapping in force lists them.
    pub fn encryption_keys_of(
        &self,
        member: &str,
    ) -> Vec<canton_participant::topology_state::EncryptionKey> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tracker
            .learned()
            .encryption_keys
            .remove(member)
            .unwrap_or_default()
    }

    /// The hash of the state (`DownloadTopologyStateForInitHash`).
    pub fn hash(&self) -> Vec<u8> {
        let transactions: Vec<Vec<u8>> = self
            .snapshot()
            .iter()
            .map(|e| e.signed.transaction.clone())
            .collect();
        tw::topology_state_hash(&transactions)
    }
}

#[cfg(test)]
mod tests;
