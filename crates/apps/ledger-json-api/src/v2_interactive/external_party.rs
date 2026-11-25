//! External parties: key and signature formats, topology generation and party allocation.

use std::collections::{BTreeSet, HashSet};

use canton_algo::hash::sha256_with_purpose;
use canton_algo::signing::{parse_public_key, parse_signature, verify_signature, PublicKey, Usage};
use canton_proto::com::daml::ledger::api::v2::interactive::HashingSchemeVersion;
use canton_proto::com::digitalasset::canton::crypto::v30 as crypto;
use canton_proto::com::digitalasset::canton::protocol::{v30 as proto_v30, v31 as proto_v31};
use canton_proto::com::digitalasset::canton::version::v1::{
    untyped_versioned_message, UntypedVersionedMessage,
};
use lf_eval::fat_contract::decode_strict_base64;
use prost::Message;
use serde_json::{json, Value as Json};

use crate::service::ExecutionService;
use crate::v2::base64;
use crate::v2_commands::bad_body;
use crate::{HttpRequest, HttpResponse};

use super::{
    compute_multi_hash_34, compute_topology_tx_hash_34, invalid_arg, logical_synchronizer,
    multihash_34, synchronizer_matches, ExternalPartyInfo, HASH_PURPOSE_TOPOLOGY_TX_SIG,
    PROTO_VERSION_TOPOLOGY_V31,
};

fn parse_key_format(v: &Json) -> Option<i32> {
    v.as_str()
        .and_then(|s| {
            crypto::CryptoKeyFormat::from_str_name(s)
                .map(|e| e as i32)
                .or_else(|| s.parse::<i32>().ok())
        })
        .or_else(|| v.as_i64().and_then(|n| i32::try_from(n).ok()))
}

fn parse_key_spec(v: &Json) -> Option<i32> {
    v.as_str()
        .and_then(|s| {
            crypto::SigningKeySpec::from_str_name(s)
                .map(|e| e as i32)
                .or_else(|| s.parse::<i32>().ok())
        })
        .or_else(|| v.as_i64().and_then(|n| i32::try_from(n).ok()))
}

fn parse_sig_format(v: &Json) -> Option<i32> {
    v.as_str()
        .and_then(|s| {
            crypto::SignatureFormat::from_str_name(s)
                .map(|e| e as i32)
                .or_else(|| s.parse::<i32>().ok())
        })
        .or_else(|| v.as_i64().and_then(|n| i32::try_from(n).ok()))
}

fn parse_sig_alg(v: &Json) -> Option<i32> {
    v.as_str()
        .and_then(|s| {
            crypto::SigningAlgorithmSpec::from_str_name(s)
                .map(|e| e as i32)
                .or_else(|| s.parse::<i32>().ok())
        })
        .or_else(|| v.as_i64().and_then(|n| i32::try_from(n).ok()))
}

fn pb_signing_public_key_from_json(v: &Json) -> Result<crypto::SigningPublicKey, HttpResponse> {
    let Some(obj) = v.as_object() else {
        return Err(invalid_arg("publicKey must be an object"));
    };
    let format = obj
        .get("format")
        .and_then(parse_key_format)
        .ok_or_else(|| invalid_arg("invalid or missing publicKey.format"))?;
    let key_data_str = obj
        .get("keyData")
        .or_else(|| obj.get("publicKey"))
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_arg("missing publicKey.keyData"))?;
    let public_key = decode_strict_base64(key_data_str)
        .map_err(|e| invalid_arg(format!("invalid publicKey.keyData base64: {e}")))?;
    let key_spec = obj
        .get("keySpec")
        .and_then(parse_key_spec)
        .unwrap_or(crypto::SigningKeySpec::EcCurve25519 as i32);
    let usage = match obj.get("usage").and_then(Json::as_array) {
        Some(arr) if !arr.is_empty() => arr
            .iter()
            .filter_map(|u| {
                u.as_str()
                    .and_then(|s| crypto::SigningKeyUsage::from_str_name(s).map(|e| e as i32))
                    .or_else(|| u.as_i64().and_then(|n| i32::try_from(n).ok()))
            })
            .collect(),
        _ => vec![
            crypto::SigningKeyUsage::Namespace as i32,
            crypto::SigningKeyUsage::ProofOfOwnership as i32,
            crypto::SigningKeyUsage::Protocol as i32,
        ],
    };
    #[allow(
        deprecated,
        reason = "populates legacy/deprecated Canton protobuf or pinned crypto fields for wire compatibility"
    )]
    Ok(crypto::SigningPublicKey {
        format,
        public_key,
        scheme: 0,
        usage,
        key_spec,
    })
}

pub(super) fn pb_signature_from_json(v: &Json) -> Result<crypto::Signature, String> {
    let Some(obj) = v.as_object() else {
        return Err("signature must be an object".into());
    };
    let format = obj
        .get("format")
        .and_then(parse_sig_format)
        .ok_or_else(|| "invalid signature.format".to_string())?;
    let sig_b64 = obj
        .get("signature")
        .and_then(Json::as_str)
        .ok_or_else(|| "missing signature.signature".to_string())?;
    let sig_bytes =
        decode_strict_base64(sig_b64).map_err(|e| format!("invalid signature base64: {e}"))?;
    let signed_by = obj
        .get("signedBy")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string();
    let signing_algorithm_spec = obj
        .get("signingAlgorithmSpec")
        .and_then(parse_sig_alg)
        .ok_or_else(|| "invalid signature.signingAlgorithmSpec".to_string())?;
    let signature_delegation = obj
        .get("signatureDelegation")
        .filter(|d| !d.is_null())
        .map(|d| {
            let sk = d
                .get("sessionKey")
                .and_then(Json::as_str)
                .map(decode_strict_base64)
                .transpose()
                .map_err(|e| format!("invalid delegation sessionKey: {e}"))?
                .unwrap_or_default();
            let d_sig = d
                .get("signature")
                .and_then(Json::as_str)
                .map(decode_strict_base64)
                .transpose()
                .map_err(|e| format!("invalid delegation signature: {e}"))?
                .unwrap_or_default();
            Ok::<_, String>(crypto::SignatureDelegation {
                session_key: sk,
                session_key_spec: d
                    .get("sessionKeySpec")
                    .and_then(parse_key_spec)
                    .unwrap_or(0),
                validity_period_from_inclusive: d
                    .get("validityPeriodFromInclusive")
                    .and_then(Json::as_i64)
                    .unwrap_or(0),
                validity_period_duration_seconds: d
                    .get("validityPeriodDurationSeconds")
                    .and_then(Json::as_u64)
                    .unwrap_or(0) as u32,
                format: d.get("format").and_then(parse_sig_format).unwrap_or(0),
                signature: d_sig,
                signing_algorithm_spec: d
                    .get("signingAlgorithmSpec")
                    .and_then(parse_sig_alg)
                    .unwrap_or(0),
            })
        })
        .transpose()?;
    Ok(crypto::Signature {
        format,
        signature: sig_bytes,
        signed_by,
        signing_algorithm_spec,
        signature_delegation,
    })
}

/// Checks a signature against either the 34-byte multihash (`0x1220...`) or 32-byte raw hash digest.
pub(super) fn verify_signature_hash_forms(
    hash_32: &[u8; 32],
    pk: &PublicKey,
    pb_sig: &crypto::Signature,
    required_usage: Usage,
) -> bool {
    let Ok(sig) = parse_signature(&pb_sig.encode_to_vec()) else {
        return false;
    };
    let mut allowed = BTreeSet::new();
    allowed.insert(required_usage);
    let mh = multihash_34(hash_32);
    verify_signature(&mh, pk, &sig, &allowed).is_ok()
        || verify_signature(hash_32, pk, &sig, &allowed).is_ok()
}

/// Whether `pb_sig` is a valid signature by `pk` over the raw 32-byte transaction hash (the form the official participant verifies:
/// `InteractiveSubmission.verifySignatures` over `hash.unwrap`).
pub(super) fn verify_transaction_hash_signature(
    hash_32: &[u8; 32],
    pk: &PublicKey,
    pb_sig: &crypto::Signature,
    required_usage: Usage,
) -> bool {
    let Ok(sig) = parse_signature(&pb_sig.encode_to_vec()) else {
        return false;
    };
    verify_signature(hash_32, pk, &sig, &BTreeSet::from([required_usage])).is_ok()
}

/// `POST /v2/parties/external/generate-topology`.
pub fn generate_topology(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return bad_body("Invalid value for: body".to_string()),
    };
    let missing: Vec<String> = ["synchronizer", "partyHint", "publicKey"]
        .into_iter()
        .filter(|k| body.get(*k).is_none())
        .map(|k| format!("Missing required field at '{k}'"))
        .collect();
    if !missing.is_empty() {
        return bad_body(format!("Invalid value for: body ({})", missing.join(", ")));
    }
    let synchronizer = body["synchronizer"].as_str().unwrap_or("");
    let party_hint = body["partyHint"].as_str().unwrap_or("");
    if synchronizer.is_empty() || party_hint.is_empty() {
        return invalid_arg("synchronizer and partyHint must be non-empty");
    }
    if !synchronizer_matches(&service.v2_state().synchronizer_id(), synchronizer) {
        return invalid_arg(format!("Unknown synchronizer '{synchronizer}'"));
    }
    let pb_pk = match pb_signing_public_key_from_json(&body["publicKey"]) {
        Ok(pk) => pk,
        Err(resp) => return resp,
    };
    let pk = match parse_public_key(&pb_pk) {
        Ok(k) => k,
        Err(e) => return invalid_arg(format!("Invalid publicKey: {e:?}")),
    };
    let fingerprint = pk.id;
    let party_id = format!("{party_hint}::{fingerprint}");
    let obs_only = body["localParticipantObservationOnly"]
        .as_bool()
        .unwrap_or(false);
    let local_perm = if obs_only {
        proto_v30::enums::ParticipantPermission::Observation as i32
    } else {
        proto_v30::enums::ParticipantPermission::Confirmation as i32
    };
    let mut participants = vec![proto_v31::party_to_participant::HostingParticipant {
        participant_uid: service.v2_state().participant_id(),
        permission: local_perm,
        state: proto_v31::party_to_participant::hosting_participant::HostingState::Active as i32,
    }];
    if let Some(other) = body["otherConfirmingParticipantUids"].as_array() {
        for uid in other.iter().filter_map(Json::as_str) {
            if !uid.is_empty() && !participants.iter().any(|p| p.participant_uid == uid) {
                participants.push(proto_v31::party_to_participant::HostingParticipant {
                    participant_uid: uid.to_string(),
                    permission: proto_v30::enums::ParticipantPermission::Confirmation as i32,
                    state:
                        proto_v31::party_to_participant::hosting_participant::HostingState::Active
                            as i32,
                });
            }
        }
    }
    if let Some(obs) = body["observingParticipantUids"].as_array() {
        for uid in obs.iter().filter_map(Json::as_str) {
            if !uid.is_empty() && !participants.iter().any(|p| p.participant_uid == uid) {
                participants.push(proto_v31::party_to_participant::HostingParticipant {
                    participant_uid: uid.to_string(),
                    permission: proto_v30::enums::ParticipantPermission::Observation as i32,
                    state:
                        proto_v31::party_to_participant::hosting_participant::HostingState::Active
                            as i32,
                });
            }
        }
    }
    let threshold = body["confirmationThreshold"]
        .as_u64()
        .map(|n| n as u32)
        .filter(|&n| n > 0)
        .unwrap_or(1);
    let ptp = proto_v31::PartyToParticipant {
        party: party_id.clone(),
        threshold,
        participants,
        party_signing_keys: Some(crypto::SigningKeysWithThreshold {
            keys: vec![pb_pk],
            threshold: 1,
        }),
    };
    let topo_tx = proto_v31::TopologyTransaction {
        operation: proto_v30::enums::TopologyChangeOp::AddReplace as i32,
        serial: 1,
        mapping: Some(proto_v31::TopologyMapping {
            mapping: Some(proto_v31::topology_mapping::Mapping::PartyToParticipant(
                ptp,
            )),
        }),
    };
    let versioned = UntypedVersionedMessage {
        wrapper: Some(untyped_versioned_message::Wrapper::Data(
            topo_tx.encode_to_vec(),
        )),
        version: PROTO_VERSION_TOPOLOGY_V31,
    };
    let tx_bytes = versioned.encode_to_vec();
    let tx_hash = compute_topology_tx_hash_34(&tx_bytes);
    let multi_hash = compute_multi_hash_34(&[tx_hash]);
    HttpResponse::json(
        200,
        &json!({
            "partyId": party_id,
            "publicKeyFingerprint": fingerprint,
            "topologyTransactions": [base64(&tx_bytes)],
            "multiHash": base64(&multi_hash),
        }),
    )
}

fn decode_topology_tx(raw: &[u8]) -> Result<proto_v31::TopologyTransaction, String> {
    let versioned =
        UntypedVersionedMessage::decode(raw).map_err(|e| format!("invalid versioned tx: {e}"))?;
    let Some(untyped_versioned_message::Wrapper::Data(data)) = versioned.wrapper else {
        return Err("missing TopologyTransaction data wrapper".into());
    };
    match versioned.version {
        31 => proto_v31::TopologyTransaction::decode(data.as_slice())
            .map_err(|e| format!("invalid v31 TopologyTransaction: {e}")),
        30 => {
            let v30_tx = proto_v30::TopologyTransaction::decode(data.as_slice())
                .map_err(|e| format!("invalid v30 TopologyTransaction: {e}"))?;
            let Some(proto_v30::TopologyMapping {
                mapping: Some(proto_v30::topology_mapping::Mapping::PartyToParticipant(ptp)),
            }) = v30_tx.mapping
            else {
                return Err("v30 TopologyTransaction missing PartyToParticipant".into());
            };
            let pb_keys = ptp
                .party_signing_keys
                .map(|sk| crypto::SigningKeysWithThreshold {
                    keys: sk.keys,
                    threshold: sk.threshold,
                });
            Ok(proto_v31::TopologyTransaction {
                operation: v30_tx.operation,
                serial: v30_tx.serial,
                mapping: Some(proto_v31::TopologyMapping {
                    mapping: Some(proto_v31::topology_mapping::Mapping::PartyToParticipant(
                        proto_v31::PartyToParticipant {
                            party: ptp.party,
                            threshold: ptp.threshold,
                            participants: ptp
                                .participants
                                .into_iter()
                                .map(|h| proto_v31::party_to_participant::HostingParticipant {
                                    participant_uid: h.participant_uid,
                                    permission: h.permission,
                                    state: if h.onboarding.is_some() {
                                        proto_v31::party_to_participant::hosting_participant::HostingState::Onboarding
                                            as i32
                                    } else {
                                        proto_v31::party_to_participant::hosting_participant::HostingState::Active
                                            as i32
                                    },
                                })
                                .collect(),
                            party_signing_keys: pb_keys,
                        },
                    )),
                }),
            })
        }
        other => Err(format!("unsupported TopologyTransaction version {other}")),
    }
}

/// `POST /v2/parties/external/allocate`.
pub fn allocate_external_party(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return bad_body("Invalid value for: body".to_string()),
    };
    let missing: Vec<String> = ["synchronizer", "onboardingTransactions"]
        .into_iter()
        .filter(|k| body.get(*k).is_none())
        .map(|k| format!("Missing required field at '{k}'"))
        .collect();
    if !missing.is_empty() {
        return bad_body(format!("Invalid value for: body ({})", missing.join(", ")));
    }
    let synchronizer = body["synchronizer"].as_str().unwrap_or("");
    if synchronizer.is_empty()
        || !synchronizer_matches(&service.v2_state().synchronizer_id(), synchronizer)
    {
        return invalid_arg(format!("Unknown synchronizer '{synchronizer}'"));
    }
    let Some(onboarding) = body["onboardingTransactions"].as_array() else {
        return invalid_arg("onboardingTransactions must be an array");
    };
    if onboarding.is_empty() {
        return invalid_arg("onboardingTransactions must not be empty");
    }

    let mut raw_txs: Vec<Vec<u8>> = Vec::with_capacity(onboarding.len());
    let mut per_tx_sigs: Vec<Vec<crypto::Signature>> = Vec::with_capacity(onboarding.len());
    let mut party_id: Option<String> = None;
    let mut host_events: Vec<(String, i32, bool)> = Vec::new();
    let mut parsed_keys: Vec<PublicKey> = Vec::new();
    let mut key_threshold: u32 = 1;

    for item in onboarding {
        let Some(tx_b64) = item.get("transaction").and_then(Json::as_str) else {
            return invalid_arg("onboardingTransactions entry missing transaction");
        };
        let raw = match decode_strict_base64(tx_b64) {
            Ok(b) => b,
            Err(e) => return invalid_arg(format!("invalid onboarding transaction base64: {e}")),
        };
        let tx = match decode_topology_tx(&raw) {
            Ok(t) => t,
            Err(e) => return invalid_arg(e),
        };
        if let Some(proto_v31::TopologyMapping {
            mapping: Some(proto_v31::topology_mapping::Mapping::PartyToParticipant(ptp)),
        }) = tx.mapping
        {
            party_id = Some(ptp.party);
            let local_uid = service.participant_id();
            for hp in &ptp.participants {
                let is_onboarding = hp.state
                    == proto_v31::party_to_participant::hosting_participant::HostingState::Onboarding
                        as i32;
                let is_active = hp.state
                    == proto_v31::party_to_participant::hosting_participant::HostingState::Active
                        as i32
                    || hp.state == 0;
                if !(is_onboarding || is_active) {
                    continue;
                }
                let raw_uid = if hp.participant_uid.is_empty() {
                    local_uid.as_str()
                } else {
                    hp.participant_uid.as_str()
                };
                let bare = raw_uid.strip_prefix("PAR::").unwrap_or(raw_uid).to_string();
                let perm = if hp.permission == 0 { 2 } else { hp.permission };
                host_events.push((bare, perm, is_onboarding));
            }
            if let Some(sk_wt) = ptp.party_signing_keys {
                key_threshold = sk_wt.threshold.max(1);
                for pb_k in &sk_wt.keys {
                    match parse_public_key(pb_k) {
                        Ok(k) => parsed_keys.push(k),
                        Err(e) => {
                            return invalid_arg(format!("invalid party signing key in tx: {e:?}"))
                        }
                    }
                }
            }
        }
        let mut sigs_for_tx = Vec::new();
        if let Some(arr) = item.get("signatures").and_then(Json::as_array) {
            for s in arr {
                match pb_signature_from_json(s) {
                    Ok(sig) => sigs_for_tx.push(sig),
                    Err(e) => return invalid_arg(e),
                }
            }
        }
        raw_txs.push(raw);
        per_tx_sigs.push(sigs_for_tx);
    }

    let Some(party_id) = party_id.filter(|p| !p.is_empty()) else {
        return invalid_arg("onboardingTransactions must include a PartyToParticipant mapping");
    };
    if parsed_keys.is_empty() {
        return invalid_arg("PartyToParticipant must declare party signing keys");
    }

    let tx_hashes_34: Vec<Vec<u8>> = raw_txs
        .iter()
        .map(|raw| compute_topology_tx_hash_34(raw))
        .collect();
    let multi_hash_34 = compute_multi_hash_34(&tx_hashes_34);
    let mut multi_digest = [0u8; 32];
    multi_digest.copy_from_slice(&multi_hash_34[2..34]);

    let mut multi_sigs: Vec<crypto::Signature> = Vec::new();
    if let Some(arr) = body["multiHashSignatures"].as_array() {
        for s in arr {
            match pb_signature_from_json(s) {
                Ok(sig) => multi_sigs.push(sig),
                Err(e) => return invalid_arg(e),
            }
        }
    }

    // Check authorization: either valid multiHashSignatures over all tx hashes or valid per-tx signatures.
    let mut authorized_fingerprints: HashSet<String> = HashSet::new();
    let expected_namespace = party_id
        .split_once("::")
        .map(|(_, fp)| fp.to_string())
        .unwrap_or_default();
    let multi_valid = !multi_sigs.is_empty()
        && multi_sigs.iter().any(|sig| {
            parsed_keys.iter().any(|pk| {
                (sig.signed_by.is_empty() || pk.id == sig.signed_by)
                    && (verify_signature_hash_forms(&multi_digest, pk, sig, Usage::Namespace)
                        || verify_signature_hash_forms(
                            &multi_digest,
                            pk,
                            sig,
                            Usage::ProofOfOwnership,
                        ))
            })
        });
    if multi_valid {
        for sig in &multi_sigs {
            for pk in &parsed_keys {
                if (sig.signed_by.is_empty() || pk.id == sig.signed_by)
                    && (verify_signature_hash_forms(&multi_digest, pk, sig, Usage::Namespace)
                        || verify_signature_hash_forms(
                            &multi_digest,
                            pk,
                            sig,
                            Usage::ProofOfOwnership,
                        ))
                {
                    authorized_fingerprints.insert(pk.id.clone());
                }
            }
        }
    } else {
        for (raw, sigs) in raw_txs.iter().zip(per_tx_sigs.iter()) {
            let tx_digest = sha256_with_purpose(HASH_PURPOSE_TOPOLOGY_TX_SIG, raw);
            let ok = sigs.iter().any(|sig| {
                parsed_keys.iter().any(|pk| {
                    (sig.signed_by.is_empty() || pk.id == sig.signed_by)
                        && verify_signature_hash_forms(&tx_digest, pk, sig, Usage::Namespace)
                })
            });
            if !ok {
                return invalid_arg(
                    "Invalid or missing topology transaction authorization signature",
                );
            }
            for sig in sigs {
                if let Some(pk) = parsed_keys.iter().find(|pk| pk.id == sig.signed_by) {
                    if verify_signature_hash_forms(&tx_digest, pk, sig, Usage::Namespace) {
                        authorized_fingerprints.insert(pk.id.clone());
                    }
                }
            }
        }
    }

    if authorized_fingerprints.is_empty()
        || (!expected_namespace.is_empty()
            && parsed_keys.iter().all(|k| k.id != expected_namespace))
    {
        return invalid_arg("External party signature failed authorization verification");
    }

    let fingerprint = parsed_keys[0].id.clone();
    let state = service.v2_state();
    let inserted_party = {
        let mut parties = state.parties.lock().expect("parties lock");
        if !parties.contains(&party_id) {
            parties.push(party_id.clone());
            true
        } else {
            false
        }
    };
    if inserted_party && !host_events.is_empty() {
        // [CANTON-NOTE: SEMANTICS] `TopologyTransactionDiff.scala:170-183` + `Member.scala:467-477`:
        // emit one event per `canHost` hosting participant with bare UID (no `PAR::`).
        let topo_events: Vec<_> = host_events
            .into_iter()
            .map(|(participant_id, perm, is_onboarding)| {
                crate::v2_topology_events::StoredTopologyEvent {
                    party_id: party_id.clone(),
                    participant_id,
                    kind: if is_onboarding {
                        crate::v2_topology_events::TopologyAuthorizationKind::Onboarding(perm)
                    } else {
                        crate::v2_topology_events::TopologyAuthorizationKind::Added(perm)
                    },
                }
            })
            .collect();
        crate::v2_topology_events::record_party_authorization(
            service,
            Some(logical_synchronizer(synchronizer)),
            topo_events,
            1,
        );
    }
    state
        .external_parties
        .lock()
        .expect("external_parties lock")
        .insert(
            party_id.clone(),
            ExternalPartyInfo {
                party_id: party_id.clone(),
                fingerprint,
                keys: parsed_keys,
                threshold: key_threshold,
                synchronizer_id: synchronizer.to_string(),
            },
        );
    HttpResponse::json(200, &json!({ "partyId": party_id }))
}

pub(super) fn parse_hashing_scheme(
    v: Option<&Json>,
    default_v2: bool,
) -> Result<HashingSchemeVersion, String> {
    let Some(val) = v.filter(|x| !x.is_null()) else {
        return if default_v2 {
            Ok(HashingSchemeVersion::V2)
        } else {
            Err("missing hashingSchemeVersion".into())
        };
    };
    if let Some(s) = val.as_str() {
        return match s {
            "HASHING_SCHEME_VERSION_UNSPECIFIED" | "" if default_v2 => Ok(HashingSchemeVersion::V2),
            "HASHING_SCHEME_VERSION_V2" | "V2" => Ok(HashingSchemeVersion::V2),
            "HASHING_SCHEME_VERSION_V3" | "V3" => Ok(HashingSchemeVersion::V3),
            other => Err(format!("unsupported hashingSchemeVersion '{other}'")),
        };
    }
    match val.as_i64() {
        Some(0) if default_v2 => Ok(HashingSchemeVersion::V2),
        Some(2) => Ok(HashingSchemeVersion::V2),
        Some(3) => Ok(HashingSchemeVersion::V3),
        other => Err(format!("unsupported hashingSchemeVersion '{other:?}'")),
    }
}
