//! The signing keys an external party's signatures on an interactive submission are checked against.
//!
//! [CANTON-NOTE: SEMANTICS] `InteractiveSubmission.verifySignatures` (Canton 3.7.2) reads the party's signing keys and threshold from
//! the synchronizer's topology (`PartyToParticipant.party_signing_keys`, or a `PartyToKeyMapping`). With a protocol node attached
//! that topology is the node's; without one (or while the node has no keys for the party yet) the keys this server recorded
//! when it allocated the party stand in.
use canton_algo::signing::{parse_public_key, PublicKey};

use crate::service::ExecutionService;
use crate::v2_interactive::ExternalPartyInfo;

/// The keys of `party` and how many of them must sign; `None` when neither the topology nor this server knows any.
pub(crate) fn signing_keys(
    service: &ExecutionService,
    party: &str,
    recorded: Option<&ExternalPartyInfo>,
) -> Option<(Vec<PublicKey>, u32)> {
    let committer = service.committer.read().ok().and_then(|c| c.clone());
    if let Some((threshold, keys)) = committer.and_then(|c| c.party_signing_keys(party)) {
        let keys: Vec<PublicKey> = keys
            .iter()
            .filter_map(|k| parse_public_key(k).ok())
            .collect();
        if !keys.is_empty() {
            return Some((keys, threshold.max(1)));
        }
    }
    recorded.map(|info| (info.keys.clone(), info.threshold))
}
