//! S-SIM-001: traffic cost estimation for `prepare` (and, later, `simulate` and the X-Ray), one function for all callers.
//!
//! [CANTON-NOTE: SEMANTICS] Canton 3.7.2 (`SubmitRequestValidator.scala:68-71`, `CostEstimationHints.fromProto`,
//! `TrafficCostEstimator.doIfTrafficControlEnabled`):
//! - no `estimateTrafficCost` in the request means the default hints, so an estimate **is** made;
//! - `disabled = true` means no estimate: the JSON answer carries `"costEstimation": null` (measured on the official participant,
//!   `doc/evidence/2026-11-24-S-SIM-001/oracle/disabled.json`);
//! - the official JSON codec requires `expectedSignatures` whenever `estimateTrafficCost` is given (400 `Missing required field`);
//! - on a synchronizer without traffic control (`τ = ⊥`) the estimate is `(0, 0, 0)` and no request is built.
//!
//! [CANTON-NOTE: LIMITATION] With traffic control on (`τ ≠ ⊥`) the request is built without sending only for a transaction of one root (a
//! create or an exercise, [`crate::service::ProtocolCommitter::priced_confirmation_request`]), with mock signatures for external parties
//! ([`mock_external_authorization`]). A classic submission's estimate does not add the random workflow id the official estimator adds for
//! local parties (`TrafficCostEstimator`: a pessimistic estimate); Rust estimates the request as it will be sent. For other shapes no
//! estimate is answered (`"costEstimation": null`, [`Estimate::RequestNotBuilt`]) rather than a wrong one.
use serde_json::{json, Value as Json};
use sha2::Digest;

/// The cost hints of a request (`CostEstimationHints`), or `None` when the request disabled the estimate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CostHints {
    /// The signing algorithms the external signatures will use (`expectedSignatures`), in the order given; empty means "threshold-many
    /// keys of the party, in registration order".
    pub expected_signatures: Vec<String>,
}

/// A traffic cost estimate (`CostEstimation`): the confirmation request, the confirmation response, their sum, and the topology time it
/// was made at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostEstimate {
    pub request: u64,
    pub response: u64,
    pub total: u64,
    pub estimation_timestamp: String,
}

/// The names of the `SigningAlgorithmSpec` proto enum, in the order the official JSON codec lists them.
const SIGNING_ALGORITHM_SPECS: [&str; 5] = [
    "SIGNING_ALGORITHM_SPEC_UNSPECIFIED",
    "SIGNING_ALGORITHM_SPEC_ED25519",
    "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256",
    "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_384",
    "SIGNING_ALGORITHM_SPEC_ML_DSA_65",
];

/// The first `expectedSignatures` algorithm the official validator does not support, if any: it takes Ed25519 and EC-DSA SHA-256/384 only
/// (`CryptoValidator.validateSigningAlgorithmSpec`); `UNSPECIFIED` and `ML_DSA_65` are known names it refuses. The caller answers
/// `INVALID_FIELD` with [`unsupported_algorithm_cause`].
pub fn unsupported_algorithm(hints: &CostHints) -> Option<&str> {
    const SUPPORTED: [&str; 3] = [
        "SIGNING_ALGORITHM_SPEC_ED25519",
        "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256",
        "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_384",
    ];
    hints
        .expected_signatures
        .iter()
        .map(String::as_str)
        .find(|name| !SUPPORTED.contains(name))
}

/// The cause of the official `INVALID_FIELD` answer for an unsupported `expectedSignatures` algorithm (recorded on p1, S-SIM-001 K-07).
pub fn unsupported_algorithm_cause(name: &str) -> String {
    format!(
        "The submitted command has a field with invalid value: Invalid field estimate_traffic_cost: Signing algorithm spec {name} not supported"
    )
}

/// Reads `estimateTrafficCost` the way the official JSON API does: `Ok(Some(hints))` to estimate, `Ok(None)` when disabled, and `Err`
/// with the official 400 text when the hints are malformed.
pub fn parse_cost_hints(body: &Json) -> Result<Option<CostHints>, String> {
    let Some(hints) = body.get("estimateTrafficCost").filter(|h| !h.is_null()) else {
        return Ok(Some(CostHints::default()));
    };
    let Some(expected) = hints.get("expectedSignatures") else {
        return Err(
            "Invalid value for: body (Missing required field at 'estimateTrafficCost.expectedSignatures')"
                .to_string(),
        );
    };
    let expected_signatures = match expected {
        Json::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let name = v.as_str().ok_or_else(|| {
                    "Invalid value for: body (expected string at 'estimateTrafficCost.expectedSignatures')"
                        .to_string()
                })?;
                // [CANTON-NOTE: SEMANTICS] the JSON codec knows the proto enum's names only, and refuses any other before anything is
                // validated (S-SIM-001 review R1-F4, recorded on p1: `oracle .../K-07-hints.json`)
                if SIGNING_ALGORITHM_SPECS.contains(&name) {
                    Ok(name.to_string())
                } else {
                    Err(format!(
                        "Invalid value for: body (Unrecognized enum value {name}. Supported values: [{}] at 'estimateTrafficCost.expectedSignatures[{i}]')",
                        SIGNING_ALGORITHM_SPECS.join(", ")
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(
                "Invalid value for: body (expected array at 'estimateTrafficCost.expectedSignatures')".to_string(),
            )
        }
    };
    if hints
        .get("disabled")
        .and_then(Json::as_bool)
        .unwrap_or(false)
    {
        return Ok(None);
    }
    Ok(Some(CostHints {
        expected_signatures,
    }))
}

/// The mock external authorization an estimate builds its request with (S-SIM-001, U-56): for each `actAs` party with registered signing keys
/// (an external party), mock signatures of the sizes its real ones will have. `None` when no party has keys (a classic submission).
///
/// [CANTON-NOTE: SEMANTICS] `TrafficCostEstimator.mockSignatures`: one signature per `expectedSignatures` algorithm when the hints name any
/// (signed by a mock hash), else one per key of the party's first `threshold` keys, with the algorithm the key's spec allows (signed by the
/// key's fingerprint). A mock signature is random bytes of the algorithm's `approximateSignatureSize` in its first signature format; the
/// externally signed submission is version V2. Random, because the views are compressed before they are encrypted: zeros would make the
/// request smaller than a real one.
pub fn mock_external_authorization(
    hints: &CostHints,
    parties: &[(String, Option<(Vec<canton_algo::signing::PublicKey>, u32)>)],
) -> Option<canton_proto::com::digitalasset::canton::protocol::v32::ExternalAuthorization> {
    use canton_algo::signing::KeySpec;
    use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
    // (`SigningAlgorithmSpec` value, approximate size, `SignatureFormat` value): Ed25519 64 bytes CONCAT; ECDSA SHA-256 64, SHA-384 96 and
    // ML-DSA-65 3309 bytes, DER
    let by_name = |name: &str| match name {
        "SIGNING_ALGORITHM_SPEC_ED25519" => Some((1, 64, 3)),
        "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256" => Some((2, 64, 2)),
        "SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_384" => Some((3, 96, 2)),
        "SIGNING_ALGORITHM_SPEC_ML_DSA_65" => Some((4, 3309, 2)),
        _ => None,
    };
    let by_key = |spec: KeySpec| match spec {
        KeySpec::EcCurve25519 => (1, 64, 3),
        KeySpec::EcP256 | KeySpec::EcSecp256k1 => (2, 64, 2),
        KeySpec::EcP384 => (3, 96, 2),
        KeySpec::MlDsa65 => (4, 3309, 2),
    };
    // high-entropy bytes (a SHA-256 chain), distinct for every signature
    let random = |seed: &str, size: usize| {
        let mut out = Vec::with_capacity(size);
        let mut block = 0u32;
        while out.len() < size {
            out.extend(sha2::Sha256::digest(format!("{seed}/{block}").as_bytes()));
            block += 1;
        }
        out.truncate(size);
        out
    };
    let mock_hash =
        |seed: &str| format!("1220{}", hex::encode(sha2::Sha256::digest(seed.as_bytes())));
    let authentications: Vec<_> = parties
        .iter()
        .filter_map(|(party, keys)| {
            let (keys, threshold) = keys.as_ref()?;
            let seed = |i: usize| format!("canton-rs mock signature {party} {i}");
            let signatures: Vec<Signature> = if hints.expected_signatures.is_empty() {
                keys.iter()
                    .take(*threshold as usize)
                    .enumerate()
                    .map(|(i, key)| {
                        let (spec, size, format) = by_key(key.key_spec);
                        Signature {
                            format,
                            signature: random(&seed(i), size),
                            signed_by: key.id.clone(),
                            signing_algorithm_spec: spec,
                            signature_delegation: None,
                        }
                    })
                    .collect()
            } else {
                hints
                    .expected_signatures
                    .iter()
                    .filter_map(|name| by_name(name))
                    .enumerate()
                    .map(|(i, (spec, size, format))| Signature {
                        format,
                        signature: random(&seed(i), size),
                        signed_by: mock_hash(&seed(i)),
                        signing_algorithm_spec: spec,
                        signature_delegation: None,
                    })
                    .collect()
            };
            (!signatures.is_empty()).then(|| {
                canton_proto::com::digitalasset::canton::protocol::v30::ExternalPartyAuthorization {
                    party: party.clone(),
                    signatures,
                }
            })
        })
        .collect();
    (!authentications.is_empty()).then_some(
        canton_proto::com::digitalasset::canton::protocol::v32::ExternalAuthorization {
            authentications,
            // `ExternallySignedSubmission(version = V2, ...)`
            hashing_scheme_version: 2,
            max_record_time: None,
        },
    )
}

/// What the cost of a submission is estimated from on a synchronizer with traffic control on: the pricing in force
/// (`TrafficControlParameters`) and the confirmation response the executing participant would send, as `(content size, recipients)`
/// (`None` when it cannot be built, e.g. without mediator group 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficCostInputs {
    pub read_vs_write_scaling: u64,
    pub base_event_cost: u64,
    pub free_confirmation_responses: bool,
    pub response: Option<(usize, usize)>,
}

/// The outcome of an estimate (S-SIM-001 `est`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estimate {
    /// The hints disabled the estimate.
    Disabled,
    Made(CostEstimate),
    /// Traffic control is on but the confirmation request (or the response) could not be built (see the module LIMITATION).
    RequestNotBuilt {
        response: Option<u64>,
    },
}

/// The cost of the confirmation response: nothing when responses are free, otherwise the priced mock response.
pub fn response_cost(traffic: &TrafficCostInputs) -> Option<u64> {
    if traffic.free_confirmation_responses {
        return Some(0);
    }
    Some(canton_algo::traffic_cost::event_cost(
        traffic.read_vs_write_scaling,
        traffic.base_event_cost,
        &[traffic.response?],
    ))
}

/// Estimates the traffic cost of a submission whose confirmation request has these priced envelopes (`request`, when it was built).
/// Without traffic control (`traffic` is `None`, `τ = ⊥`) the estimate is zero and no request is built, as the official estimator does
/// (`doIfTrafficControlEnabled`); with it, the request and the response are priced by the one cost formula and the total is their sum.
pub fn estimate(
    hints: Option<&CostHints>,
    traffic: Option<&TrafficCostInputs>,
    request: Option<&[(usize, usize)]>,
    estimation_timestamp: String,
) -> Estimate {
    if hints.is_none() {
        return Estimate::Disabled;
    }
    let Some(t) = traffic else {
        return Estimate::Made(CostEstimate {
            request: 0,
            response: 0,
            total: 0,
            estimation_timestamp,
        });
    };
    let response = response_cost(t);
    match (request, response) {
        (Some(envelopes), Some(response)) => {
            let request = canton_algo::traffic_cost::event_cost(
                t.read_vs_write_scaling,
                t.base_event_cost,
                envelopes,
            );
            // [CANTON-NOTE: DEFENSIVE] S-SIM-001 C-A2: the total is the checked sum; a sum past `u64` is no estimate, not a wrapped one
            match request.checked_add(response) {
                Some(total) => Estimate::Made(CostEstimate {
                    request,
                    response,
                    total,
                    estimation_timestamp,
                }),
                None => Estimate::RequestNotBuilt {
                    response: Some(response),
                },
            }
        }
        _ => Estimate::RequestNotBuilt { response },
    }
}

/// The `costEstimation` value of a `prepare` answer: the estimate, or JSON `null` when none was made.
pub fn cost_estimation_json(estimate: &Estimate) -> Json {
    match estimate {
        Estimate::Disabled | Estimate::RequestNotBuilt { .. } => Json::Null,
        Estimate::Made(e) => json!({
            "estimationTimestamp": e.estimation_timestamp,
            "confirmationRequestTrafficCostEstimation": e.request,
            "confirmationResponseTrafficCostEstimation": e.response,
            "totalTrafficCostEstimation": e.total,
            "reassignmentCosts": []
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_hints_mean_the_default_hints() {
        assert_eq!(parse_cost_hints(&json!({})), Ok(Some(CostHints::default())));
    }

    #[test]
    fn disabled_hints_mean_no_estimate_and_a_null_field() {
        let hints = parse_cost_hints(
            &json!({"estimateTrafficCost": {"disabled": true, "expectedSignatures": []}}),
        );
        assert_eq!(hints, Ok(None));
        let made = estimate(None, None, None, "t".into());
        assert_eq!(made, Estimate::Disabled);
        assert_eq!(cost_estimation_json(&made), Json::Null);
    }

    #[test]
    fn hints_without_expected_signatures_are_refused_with_the_official_text() {
        assert_eq!(
            parse_cost_hints(&json!({"estimateTrafficCost": {"disabled": true}})),
            Err("Invalid value for: body (Missing required field at 'estimateTrafficCost.expectedSignatures')".into())
        );
    }

    #[test]
    fn without_traffic_control_the_estimate_is_zero() {
        let hints = CostHints {
            expected_signatures: vec!["SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256".into()],
        };
        let Estimate::Made(made) = estimate(Some(&hints), None, None, "t".into()) else {
            panic!("an estimate is made without traffic control");
        };
        assert_eq!((made.request, made.response, made.total), (0, 0, 0));
    }

    /// The pricing of the S-NET-038 oracle measurement: factor 200, base event cost 7.
    fn measured(response: Option<(usize, usize)>) -> TrafficCostInputs {
        TrafficCostInputs {
            read_vs_write_scaling: 200,
            base_event_cost: 7,
            free_confirmation_responses: false,
            response,
        }
    }

    #[test]
    fn the_response_is_priced_like_any_envelope_and_free_when_responses_are_free() {
        let mut traffic = measured(Some((100, 1)));
        // 100 + 100 * 1 * 200 / 10000 + 7, the measured cost of 100 bytes to one recipient
        assert_eq!(response_cost(&traffic), Some(109));
        traffic.free_confirmation_responses = true;
        assert_eq!(response_cost(&traffic), Some(0));
    }

    #[test]
    fn with_traffic_control_and_no_request_no_estimate_is_answered() {
        let traffic = measured(None);
        let made = estimate(
            Some(&CostHints::default()),
            Some(&traffic),
            None,
            "t".into(),
        );
        assert_eq!(made, Estimate::RequestNotBuilt { response: None });
        assert_eq!(cost_estimation_json(&made), Json::Null);
    }

    #[test]
    fn with_traffic_control_the_total_is_the_request_and_the_response() {
        let traffic = measured(Some((100, 1)));
        let made = estimate(
            Some(&CostHints::default()),
            Some(&traffic),
            Some(&[(1000, 2), (200, 1)]),
            "t".into(),
        );
        let Estimate::Made(made) = made else {
            panic!("an estimate is made when the request was built");
        };
        // request: 1000 + 40 + 200 + 4 + 7; response: 109
        assert_eq!((made.request, made.response, made.total), (1251, 109, 1360));
    }

    fn key(id: &str, spec: canton_algo::signing::KeySpec) -> canton_algo::signing::PublicKey {
        canton_algo::signing::PublicKey {
            key_spec: spec,
            format: canton_algo::signing::KeyFormat::Raw,
            usage: Default::default(),
            key: Vec::new(),
            id: id.to_string(),
        }
    }

    #[test]
    fn mock_signatures_follow_the_hints_else_the_threshold_first_keys() {
        use canton_algo::signing::KeySpec;
        let parties = vec![
            (
                "ext".to_string(),
                Some((
                    vec![
                        key("1220aa", KeySpec::EcCurve25519),
                        key("1220bb", KeySpec::EcP384),
                        key("1220cc", KeySpec::EcP256),
                    ],
                    2,
                )),
            ),
            ("local".to_string(), None),
        ];
        // no hints: the first two keys, by their specs
        let auth =
            mock_external_authorization(&CostHints::default(), &parties).expect("ext is external");
        let [only] = auth.authentications.as_slice() else {
            panic!("one external party: {auth:?}");
        };
        assert_eq!(only.party, "ext");
        let shapes: Vec<_> = only
            .signatures
            .iter()
            .map(|s| {
                (
                    s.signed_by.as_str(),
                    s.signing_algorithm_spec,
                    s.signature.len(),
                    s.format,
                )
            })
            .collect();
        assert_eq!(shapes, vec![("1220aa", 1, 64, 3), ("1220bb", 3, 96, 2)]);
        assert_eq!(auth.hashing_scheme_version, 2);
        // hints: one per named algorithm, signed by a 68-character mock hash
        let hinted = CostHints {
            expected_signatures: vec!["SIGNING_ALGORITHM_SPEC_EC_DSA_SHA_256".into()],
        };
        let auth = mock_external_authorization(&hinted, &parties).unwrap();
        let s = &auth.authentications[0].signatures;
        assert_eq!(
            (
                s.len(),
                s[0].signature.len(),
                s[0].signed_by.len(),
                s[0].format
            ),
            (1, 64, 68, 2)
        );
        // random, not zeros (the views are compressed before they are encrypted)
        assert!(s[0].signature.iter().any(|b| *b != 0));
        // a classic submission: no external party, no mock
        assert_eq!(
            mock_external_authorization(&CostHints::default(), &[("local".into(), None)]),
            None
        );
    }
}
