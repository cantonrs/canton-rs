//! What a participant learns from the synchronizer's topology state (G5 5.6p, S-NET-024): which parties it hosts, whose keys sign
//! what, and the synchronizer's time limits. Until now the event loop was given these by its configuration.
//!
//! [CANTON-NOTE: SEMANTICS] The state is a list of stored signed transactions, each with the time from which it is valid. Of every
//! unique key (a party's hosting, a member's keys, the parameters) the transaction with the **highest serial** is the current one;
//! if that one is a `REMOVE`, nothing is current. A participant *confirms* for a party only if its permission is `Submission` or
//! `Confirmation` (`Observation` receives and cannot answer).
//!
//! [CANTON-NOTE: LIMITATION] The state read is the **latest** the synchronizer holds, not the state as of a request's sequencing
//! time; the signatures on the transactions are not verified here (S-NET-003 does that) and neither is the delegation chain.
//!
//! The modules: `auth` (who has to authorize a mapping, its unique key), `keys` (fingerprints, key usages, a delegation parsed),
//! `graph` (the per-namespace authorization graphs), `tracker` (the order of the checks and the state followed), `mappings` (each
//! mapping's own checks and what it changes), `psid` (synchronizer ids and upgrades).
mod auth;
mod checks;
mod graph;
mod keys;
mod mappings;
mod psid;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_auth;
#[cfg(test)]
mod tests_rules;
mod tracker;

pub use auth::{required_auth, unique_key, Authorizers, Code, RequiredAuth, UniqueKey};
pub use psid::{decentralized_namespace_of, is_forbidden_protocol_version_downgrade, Lsu, Psid};
pub use tracker::{Applied, MediatorGroup, Outcome, Refusal, SequencerGroup, Tracker};

use crate::topology_wire as tw;
use crate::view_acs::Timeouts;
use canton_algo::signing::PublicKey;
use canton_proto::com::digitalasset::canton::crypto::v30::public_key::Key;
use canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction;
use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
use canton_proto::com::digitalasset::canton::protocol::v31::TopologyTransaction;
use keys::signing_key;
use prost::Message;
use std::collections::{BTreeMap, BTreeSet};

/// One stored transaction of the state, decoded.
#[derive(Clone)]
pub struct Entry {
    pub valid_from: i64,
    pub signed: SignedTopologyTransaction,
    pub tx: TopologyTransaction,
}

/// Decodes the stored transactions `(valid from, stored bytes)` a topology download returns. A transaction that does not decode is
/// an error: a state read half is not a state.
pub fn decode(items: &[(i64, Vec<u8>)]) -> Result<Vec<Entry>, String> {
    items
        .iter()
        .map(|(valid_from, stored)| {
            let (data, version) =
                tw::unversioned(stored).ok_or("a stored transaction is not versioned")?;
            if version != tw::SIGNED_TOPOLOGY_TRANSACTION_VERSION {
                return Err(format!("signed transaction of version {version}"));
            }
            let signed =
                SignedTopologyTransaction::decode(data.as_slice()).map_err(|e| e.to_string())?;
            let (inner, v) =
                tw::unversioned(&signed.transaction).ok_or("the transaction is not versioned")?;
            if v != tw::TOPOLOGY_TRANSACTION_VERSION {
                return Err(format!("transaction of version {v}"));
            }
            let tx = TopologyTransaction::decode(inner.as_slice()).map_err(|e| e.to_string())?;
            Ok(Entry {
                valid_from: *valid_from,
                signed,
                tx,
            })
        })
        .collect()
}

/// A vetted package entry with optional validity bounds `[valid_from_inclusive, valid_until_exclusive)` in microseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VettedPackageEntry {
    pub package_id: String,
    pub valid_from_inclusive: Option<i64>,
    pub valid_until_exclusive: Option<i64>,
}

impl VettedPackageEntry {
    /// `[CANTON-NOTE: SEMANTICS]` `TopologyMapping.scala:1760-1761` (`VettedPackage.validAt`): inclusive start, exclusive end.
    pub fn is_valid_at(&self, at_micros: i64) -> bool {
        self.valid_from_inclusive
            .is_none_or(|from| from <= at_micros)
            && self
                .valid_until_exclusive
                .is_none_or(|until| at_micros < until)
    }
}

/// What the participant `me` takes from the state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Learned {
    /// The parties `me` hosts with a permission that lets it confirm.
    pub hosted_parties: Vec<String>,
    /// The signing keys of every participant (`PAR::...`) except `me`: the keys a request's view may be signed with.
    pub submitter_keys: Vec<PublicKey>,
    /// The signing keys of the mediators (`MED::...`): the keys a verdict may be signed with.
    pub mediator_keys: Vec<PublicKey>,
    /// The P-256 encryption keys of every participant except `me`, by member: the keys a request's randomness is encrypted for.
    pub encryption_keys: BTreeMap<String, Vec<EncryptionKey>>,
    pub timeouts: Option<Timeouts>,
    /// Active vetted package IDs keyed by `participant_uid`.
    pub vetted_packages: BTreeMap<String, BTreeSet<String>>,
    /// Active vetted package entries with validity windows keyed by `participant_uid` (`R-6d`).
    pub vetted_package_windows: BTreeMap<String, Vec<VettedPackageEntry>>,
}

/// A member's keys in force: the serial of its mapping, its signing keys and its P-256 encryption keys.
type MemberKeys = (u32, Vec<PublicKey>, Vec<EncryptionKey>);

/// A participant's P-256 encryption key: the DER SubjectPublicKeyInfo and its fingerprint (the hash of the DER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKey {
    pub spki: Vec<u8>,
    pub fingerprint: String,
}

/// The P-256 encryption keys (DER SubjectPublicKeyInfo) of an owner-to-key mapping.
///
/// [CANTON-NOTE: SEMANTICS] A mapping needs a proof-of-possession signature only for its **signing** keys (an encryption key cannot
/// sign), so an encryption key is trusted because the member's namespace authorized the mapping, nothing more.
fn encryption_keys_of(
    m: &canton_proto::com::digitalasset::canton::protocol::v30::OwnerToKeyMapping,
) -> Vec<EncryptionKey> {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        CryptoKeyFormat, EncryptionKeySpec,
    };
    m.public_keys
        .iter()
        .filter_map(|k| match &k.key {
            Some(Key::EncryptionPublicKey(e))
                if e.key_spec == EncryptionKeySpec::EcP256 as i32
                    && e.format == CryptoKeyFormat::DerX509SubjectPublicKeyInfo as i32 =>
            {
                Some(EncryptionKey {
                    fingerprint: tw::fingerprint(&e.public_key),
                    spki: e.public_key.clone(),
                })
            }
            _ => None,
        })
        .collect()
}

/// The signing keys of an owner-to-key mapping.
fn signing_keys_of(
    m: &canton_proto::com::digitalasset::canton::protocol::v30::OwnerToKeyMapping,
) -> Vec<PublicKey> {
    m.public_keys
        .iter()
        .filter_map(|k| match &k.key {
            Some(Key::SigningPublicKey(s)) => signing_key(s),
            _ => None,
        })
        .collect()
}

fn mapping(e: &Entry) -> Option<&Mapping> {
    e.tx.mapping.as_ref().and_then(|m| m.mapping.as_ref())
}

/// `TopologyChangeOp.Remove` as the proto numbers it (`1` is `AddReplace`).
const REMOVE: i32 = 2;

/// Reads what `me` (a member string such as `PAR::name::fingerprint`) needs from `entries`.
pub fn learn(entries: &[Entry], me: &str) -> Learned {
    let me_uid = me.strip_prefix("PAR::").unwrap_or(me);
    // the current transaction of each unique key: the highest serial that is not a proposal; `None` once that one is a REMOVE
    fn current<'a, K: Ord>(
        entries: &'a [Entry],
        key_of: impl Fn(&'a Entry) -> Option<K>,
    ) -> BTreeMap<K, &'a Entry> {
        let mut best: BTreeMap<K, &Entry> = BTreeMap::new();
        for e in entries.iter().filter(|e| !e.signed.proposal) {
            let Some(k) = key_of(e) else { continue };
            match best.get(&k) {
                Some(old) if old.tx.serial >= e.tx.serial => {}
                _ => {
                    best.insert(k, e);
                }
            }
        }
        best.retain(|_, e| e.tx.operation != 2); // REMOVE
        best
    }
    let mut out = Learned::default();
    let parties = current(entries, |e| match mapping(e) {
        Some(Mapping::PartyToParticipant(p)) => Some(p.party.clone()),
        _ => None,
    });
    for (party, e) in parties {
        if let Some(Mapping::PartyToParticipant(p)) = mapping(e) {
            let confirms = p.participants.iter().any(|h| {
                h.participant_uid == me_uid && matches!(h.permission, 1 | 2) // Submission, Confirmation
            });
            if confirms {
                out.hosted_parties.push(party);
            }
        }
    }
    let members = current(entries, |e| match mapping(e) {
        Some(Mapping::OwnerToKeyMapping(m)) => Some(m.member.clone()),
        _ => None,
    });
    for (member, e) in members {
        let Some(Mapping::OwnerToKeyMapping(m)) = mapping(e) else {
            continue;
        };
        let keys = m.public_keys.iter().filter_map(|k| match &k.key {
            Some(Key::SigningPublicKey(s)) => signing_key(s),
            _ => None,
        });
        if member.starts_with("PAR::")
            && member != me
            && member.strip_prefix("PAR::") != Some(me_uid)
        {
            out.submitter_keys.extend(keys);
            out.encryption_keys
                .insert(member.clone(), encryption_keys_of(m));
        } else if member.starts_with("MED::") {
            out.mediator_keys.extend(keys);
        }
    }
    let params = current(entries, |e| match mapping(e) {
        Some(Mapping::SynchronizerParametersState(_)) => Some(()),
        _ => None,
    });
    if let Some(e) = params.get(&()) {
        if let Some(Mapping::SynchronizerParametersState(p)) = mapping(e) {
            let micros = |d: &Option<prost_types::Duration>| {
                d.as_ref()
                    .map(|d| d.seconds * 1_000_000 + i64::from(d.nanos) / 1_000)
            };
            if let Some((c, m)) = p.synchronizer_parameters.as_ref().and_then(|s| {
                Some((
                    micros(&s.confirmation_response_timeout)?,
                    micros(&s.mediator_reaction_timeout)?,
                ))
            }) {
                out.timeouts = Some(Timeouts {
                    confirmation_response_micros: c,
                    mediator_reaction_micros: m,
                });
            }
        }
    }
    let vetted = current(entries, |e| match mapping(e) {
        Some(Mapping::VettedPackages(v)) => Some(v.participant_uid.clone()),
        _ => None,
    });
    for (uid, e) in vetted {
        if let Some(Mapping::VettedPackages(v)) = mapping(e) {
            out.vetted_packages.insert(uid.clone(), vetted_ids_of(v));
            out.vetted_package_windows.insert(uid, vetted_entries_of(v));
        }
    }
    out
}

fn timestamp_micros(ts: &prost_types::Timestamp) -> i64 {
    ts.seconds
        .saturating_mul(1_000_000)
        .saturating_add(i64::from(ts.nanos) / 1_000)
}

#[expect(
    deprecated,
    reason = "reads legacy/deprecated VettedPackages.package_ids alongside versioned packages"
)]
fn vetted_ids_of(
    v: &canton_proto::com::digitalasset::canton::protocol::v30::VettedPackages,
) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = v.package_ids.iter().cloned().collect();
    ids.extend(v.packages.iter().map(|p| p.package_id.clone()));
    ids
}

#[expect(
    deprecated,
    reason = "reads legacy/deprecated package_ids alongside versioned packages list"
)]
fn vetted_entries_of(
    v: &canton_proto::com::digitalasset::canton::protocol::v30::VettedPackages,
) -> Vec<VettedPackageEntry> {
    let mut entries: Vec<VettedPackageEntry> = v
        .package_ids
        .iter()
        .map(|id| VettedPackageEntry {
            package_id: id.clone(),
            valid_from_inclusive: None,
            valid_until_exclusive: None,
        })
        .collect();
    entries.extend(v.packages.iter().map(|p| VettedPackageEntry {
        package_id: p.package_id.clone(),
        valid_from_inclusive: p.valid_from_inclusive.as_ref().map(timestamp_micros),
        valid_until_exclusive: p.valid_until_exclusive.as_ref().map(timestamp_micros),
    }));
    entries
}

/// The stored signed transactions a topology broadcast envelope carries (`None` if the envelope is not a broadcast).
pub fn broadcast_transactions(envelope_content: &[u8]) -> Option<Vec<Vec<u8>>> {
    use canton_proto::com::digitalasset::canton::protocol::v32::{
        envelope_content::SomeEnvelopeContent, EnvelopeContent,
    };
    let (data, _) = tw::unversioned(envelope_content)?;
    match EnvelopeContent::decode(data.as_slice())
        .ok()?
        .some_envelope_content?
    {
        SomeEnvelopeContent::TopologyTransactionsBroadcast(b) => {
            Some(b.signed_transactions?.signed_transactions)
        }
        _ => None,
    }
}

/// Whether a topology broadcast's recipients include the group of all members: only such a broadcast is taken.
///
/// [CANTON-NOTE: SEMANTICS] `TopologyTransactionProcessor.validateEnvelopes` discards any other broadcast ("invalid recipients"): one
/// addressed to some members only would let a sender give those members a topology the others never see. Containing the group is enough
/// (another member added as a recipient must not make the others discard what this one takes).
pub fn is_addressed_to_all(recipients: &[String]) -> bool {
    recipients.iter().any(|r| r == tw::ALL_MEMBERS)
}

/// Whether an envelope's content is a topology broadcast: the state the synchronizer holds may have changed.
pub fn is_topology_broadcast(envelope_content: &[u8]) -> bool {
    broadcast_transactions(envelope_content).is_some()
}

/// `2026-11-13T12:14:19.636366Z`, written as the node writes a time (Java's `Instant.toString`).
pub fn iso_utc(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let frac = micros.rem_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // civil date from days since 1970-01-01 (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    // as Java's `Instant.toString` (what the node writes): the fraction in groups of three digits, as many as needed, none when it is zero
    let fraction = if frac == 0 {
        String::new()
    } else if frac % 1000 == 0 {
        format!(".{:03}", frac / 1000)
    } else {
        format!(".{frac:06}")
    };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}{fraction}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}
