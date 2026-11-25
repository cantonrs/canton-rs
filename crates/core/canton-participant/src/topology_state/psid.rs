//! Synchronizer ids, their logical upgrades and the namespace a decentralized namespace is derived as.
use std::collections::BTreeSet;

/// A physical synchronizer id: `name::fingerprint::<protocol version>-<serial>`; `dev` is protocol version `i32::MAX`.
///
/// [CANTON-NOTE: SEMANTICS] The order of `OpaquePhysicalSynchronizerId` is the logical id as text, then the serial, then the protocol version
/// (the derived order of this struct, whose fields are in that order).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Psid {
    pub logical: String,
    pub serial: u32,
    pub protocol_version: i32,
}

impl Psid {
    pub fn parse(raw: &str) -> Result<Psid, String> {
        let parts: Vec<&str> = raw.split("::").collect();
        if parts.len() != 3 {
            return Err(format!(
                "Unable to parse `{raw}` as physical synchronizer id"
            ));
        }
        let suffix: Vec<&str> = parts[2].split('-').collect();
        if suffix.len() != 2 {
            return Err(format!(
                "Cannot parse {} as a physical synchronizer id suffix",
                parts[2]
            ));
        }
        let protocol_version = if suffix[0] == "dev" {
            i32::MAX
        } else {
            suffix[0]
                .parse()
                .map_err(|_| format!("Cannot parse {} to an int", suffix[0]))?
        };
        let serial = suffix[1]
            .parse()
            .map_err(|_| format!("Cannot parse {} to an int", suffix[1]))?;
        Ok(Psid {
            logical: format!("{}::{}", parts[0], parts[1]),
            serial,
            protocol_version,
        })
    }

    pub fn protocol_version_string(&self) -> String {
        if self.protocol_version == i32::MAX {
            "dev".into()
        } else {
            self.protocol_version.to_string()
        }
    }

    /// The namespace of the logical synchronizer (the fingerprint).
    pub fn namespace(&self) -> &str {
        self.logical.rsplit("::").next().unwrap_or_default()
    }
}

impl std::fmt::Display for Psid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}::{}-{}",
            self.logical,
            self.protocol_version_string(),
            self.serial
        )
    }
}

/// `DecentralizedNamespaceDefinition.computeNamespace`: the owners' namespaces in string order, each added as a string to a hash of purpose
/// 37 (`DecentralizedNamespaceNamespace`), as a SHA-256 multihash.
pub fn decentralized_namespace_of(owners: &BTreeSet<String>) -> Result<String, String> {
    let mut hash = canton_algo::PurposeHash::new(37);
    for owner in owners {
        hash.add_string(owner)
            .map_err(|e| format!("decentralized namespace of {owners:?}: {e:?}"))?;
    }
    let digest = hash
        .finish()
        .map_err(|e| format!("decentralized namespace of {owners:?}: {e:?}"))?;
    Ok(canton_algo::multihash_sha256_hex(&digest))
}

/// A protocol version downgrade the logical upgrade of a synchronizer does not allow: the successor has a higher serial but a lower protocol
/// version, and the current synchronizer already runs a protocol version that forbids it (37 and later).
pub fn is_forbidden_protocol_version_downgrade(current: &Psid, successor: &Psid) -> bool {
    successor.serial > current.serial
        && current.protocol_version >= 37
        && successor.protocol_version < current.protocol_version
}

/// What a synchronizer's upgrade announcement says: where it goes and when, and the serial of the transaction that said so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lsu {
    pub successor: Psid,
    pub upgrade_micros: i64,
    pub serial: u32,
}
