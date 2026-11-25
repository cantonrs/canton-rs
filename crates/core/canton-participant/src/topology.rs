//! Party identifiers of the in-process Splice services and the hash purpose of a signed protocol message.
//!
//! [CANTON-NOTE: WHY] The participant's topology state (authorization, serials, effective times) lives in `topology_state`; this module only
//! names parties (`identifier::namespace`) for `splice` and `canton-rs splice`.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const PURPOSE_SIGNED_PROTOCOL_MESSAGE: i32 = 38;

/// Cryptographic fingerprint of a key, represented in Canton multihash hex format.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fingerprint(pub String);

impl Fingerprint {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.0)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Canton cryptographic namespace identified by root key fingerprint.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Namespace(pub Fingerprint);

impl Namespace {
    pub fn new(fingerprint: Fingerprint) -> Self {
        Self(fingerprint)
    }

    pub fn fingerprint(&self) -> &Fingerprint {
        &self.0
    }
}

impl fmt::Debug for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Namespace({})", self.0)
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Canton party identifier: `identifier::namespace`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PartyId {
    pub identifier: String,
    pub namespace: Namespace,
}

impl PartyId {
    pub fn new(identifier: impl Into<String>, namespace: Namespace) -> Self {
        Self {
            identifier: identifier.into(),
            namespace,
        }
    }
}

impl fmt::Debug for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PartyId({}::{})", self.identifier, self.namespace)
    }
}

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.identifier, self.namespace)
    }
}
