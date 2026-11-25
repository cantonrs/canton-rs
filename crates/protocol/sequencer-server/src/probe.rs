//! A probe of how the official sequencers answer a request (U-49): this node authenticates to an official sequencer as its own member, sends the same aggregated request
//! twice, and prints the events it gets back, the error event of the second one with the bytes of its status. What the official nodes build is what a Rust sequencer has to
//! build for a member that reads from both.
use crate::sequencer_identity::SequencerIdentity;
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::{unversioned, versioned};
use canton_proto::com::digitalasset::canton::protocol::v30::AggregationRule;
use canton_proto::com::digitalasset::canton::protocol::v32::SequencedEvent;
use canton_proto::com::digitalasset::canton::protocol::v33::SubmissionRequest;
use prost::Message as _;

/// Sends the same aggregated request (an envelope to this node itself, a rule that lets only this node send it) twice, and writes what
/// comes back to `out`, one line at a time.
///
/// [CANTON-NOTE: WHY] The report is user output of `canton-rs sequencer probe-dedup`; the library hands each line to the command's sink
/// instead of printing (`S-QUAL-003`), so lines still appear as they arrive.
pub fn dedup(
    identity: &SequencerIdentity,
    sequencer_url: &str,
    out: &dyn Fn(&str),
) -> Result<(), String> {
    let member = identity.member();
    let mut client =
        SequencerConnect::connect(sequencer_url).map_err(|e| format!("{sequencer_url}: {e}"))?;
    let physical = client
        .synchronizer_id()
        .map_err(|e| e.to_string())?
        .physical_synchronizer_id;
    let challenge = client
        .challenge(&member, &[37])
        .map_err(|e| e.to_string())?;
    let signature = identity.authentication_key.sign_bytes(
        &AuthKey::challenge_hash(&challenge.nonce, &physical)
            .map_err(|e| format!("the challenge hash: {e:?}"))?,
    );
    let token = client
        .authenticate(&member, &challenge.nonce, signature)
        .map_err(|e| e.to_string())?;
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as i64);
    let start = micros - 1_000_000;
    for (n, id) in ["probe-a", "probe-b"].iter().enumerate() {
        let plain = sw::submission_request_to_groups(
            &member,
            &format!("{id}-{micros}"),
            &[(vec![member.clone()], b"probe".to_vec())],
            micros + 60_000_000,
        );
        let (data, version) = unversioned(&plain).ok_or("a versioned request")?;
        let mut request = SubmissionRequest::decode(data.as_slice()).map_err(|e| e.to_string())?;
        request.aggregation_rule = Some(AggregationRule {
            // PV35 on: an empty list is the rule that only deduplicates what one sender sends (`AggregationRuleInput.SenderDedup`)
            eligible_members: Vec::new(),
            threshold: 1,
        });
        let signed = sw::signed_submission_request(
            versioned(request.encode_to_vec(), version),
            &identity.signing_key,
        );
        let sent = client.send_async(&member, &physical, &token, signed);
        out(&format!("send {n}: {sent:?}"));
    }
    let events = client
        .subscribe(
            &member,
            &physical,
            &token,
            Some(start),
            6,
            std::time::Duration::from_secs(8),
        )
        .map_err(|e| e.to_string())?;
    for e in &events {
        let Some(d) = sw::decode_delivered(e) else {
            out("an event this client does not decode");
            continue;
        };
        out(&format!(
            "EVENT ts={} previous={:?} id={:?} envelopes={} error={:?}",
            d.timestamp_micros,
            d.previous_timestamp_micros,
            d.message_id,
            d.envelopes.len(),
            d.error
        ));
        let Some((bytes, _)) = unversioned(&d.event_bytes) else {
            continue;
        };
        let Ok(event) = SequencedEvent::decode(bytes.as_slice()) else {
            continue;
        };
        if let Some(status) = event.deliver_error_reason {
            out(&format!(
                "  status code={} message={:?}",
                status.code, status.message
            ));
            for detail in &status.details {
                let hex: String = detail.value.iter().map(|b| format!("{b:02x}")).collect();
                out(&format!(
                    "  detail {} {} bytes: {hex}",
                    detail.type_url,
                    detail.value.len()
                ));
            }
            let whole: String = status
                .encode_to_vec()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            out(&format!("  status bytes: {whole}"));
        }
    }
    Ok(())
}
