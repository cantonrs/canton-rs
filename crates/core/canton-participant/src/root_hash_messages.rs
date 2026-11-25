//! Which request a sequenced event carries, from its root hash messages and its encrypted views (Canton's
//! `MessageDispatcher.checkRootHashMessageAndViews` and `processEncryptedViewsAndRootHashMessages`).
//!
//! [CANTON-NOTE: SEMANTICS] On the unsigned envelopes of one event:
//! 1. Only the root hash messages with a **mediator group** among their recipients count; the others raise an alarm.
//! 2. None of them: the views (if any) are not a request, and nothing is answered (`DoNotExpectMediatorResult`). More than one: the
//!    mediator rejects the request as malformed, so the participant drops it without answering
//!    (`ExpectMalformedMediatorConfirmationRequestResult`).
//! 3. The one message's recipients should be one group `{mediator group, participant}`; anything else only raises an alarm.
//! 4. The views of another view type than the message's are set aside with an alarm. If no view of its type is left, the participant
//!    answers malformed (`LOCAL_VERDICT_BAD_ROOT_HASH_MESSAGES`) to the message's mediator group and expects a verdict.
//! 5. A good request in a batch that also carries a topology broadcast (to all members) is dropped with an alarm: everyone who got the
//!    request got the broadcast too, so everyone drops it.
//!
//! The mediator the views declare is checked against the message's mediator group once the views are read (`view_decision`).
use crate::sequencing_wire::Delivered;
use crate::topology_wire::{unversioned, ALL_MEMBERS};
use canton_proto::com::digitalasset::canton::protocol::v30::{RootHashMessage, ViewType};
use canton_proto::com::digitalasset::canton::protocol::v32::{
    envelope_content::SomeEnvelopeContent, EnvelopeContent,
};
use prost::Message;

/// What the participant does with the request of an event.
#[derive(Debug, PartialEq, Eq)]
pub enum Request<'e> {
    /// The event carries no request: no view and no root hash message sent to a mediator.
    None,
    /// The request is not processed and nothing is answered, for the reason given.
    Dropped(String),
    /// The participant answers malformed to `mediator_group` and does nothing else with the request.
    BadRootHashMessages {
        root_hash: Vec<u8>,
        mediator_group: u32,
        why: String,
    },
    Good(Good<'e>),
}

/// A request whose root hash message and views fit together.
#[derive(Debug, PartialEq, Eq)]
pub struct Good<'e> {
    pub root_hash: Vec<u8>,
    pub view_type: ViewType,
    /// The mediator group the root hash message is sent to: the one the views must declare and the answer goes to.
    pub mediator_group: u32,
    /// The contents of the encrypted view messages of the root hash message's view type.
    pub views: Vec<&'e [u8]>,
}

/// The request of an event, and the alarms raised on the way that do not stop it.
#[derive(Debug, PartialEq, Eq)]
pub struct Checked<'e> {
    pub request: Request<'e>,
    pub alarms: Vec<String>,
}

/// The mediator group a recipient string names (`MGR::<group>`).
fn group_of(recipient: &str) -> Option<u32> {
    recipient.strip_prefix("MGR::")?.parse().ok()
}

struct RootHash<'e> {
    message: RootHashMessage,
    recipients: &'e [String],
}

/// Checks the root hash messages and the views of `event` (see the module documentation).
///
/// [CANTON-NOTE: LIMITATION] `Delivered::recipients` flattens an envelope's recipient trees, so the shape check of step 3 counts the
/// addresses (two, one of them a mediator group) instead of the trees. It only raises an alarm either way.
pub fn check(event: &Delivered) -> Checked<'_> {
    let mut alarms = Vec::new();
    let mut root_hashes: Vec<RootHash> = Vec::new();
    let mut views: Vec<(ViewType, &[u8])> = Vec::new();
    let mut has_topology = false;
    for (i, envelope) in event.envelopes.iter().enumerate() {
        // [CANTON-NOTE: SEMANTICS] A signed envelope holds a signed protocol message (a verdict, a traffic purchase), not an `EnvelopeContent`.
        if event
            .envelope_signatures
            .get(i)
            .is_some_and(|s| !s.is_empty())
        {
            continue;
        }
        let recipients = event.recipients.get(i).map_or(&[][..], Vec::as_slice);
        let Some(content) = unversioned(envelope)
            .and_then(|(inner, _)| EnvelopeContent::decode(inner.as_slice()).ok())
            .and_then(|c| c.some_envelope_content)
        else {
            continue;
        };
        match content {
            SomeEnvelopeContent::RootHashMessage(message) => root_hashes.push(RootHash {
                message,
                recipients,
            }),
            SomeEnvelopeContent::EncryptedMultipleViewsMessage(message) => views.push((
                ViewType::try_from(message.view_type).unwrap_or(ViewType::Unspecified),
                envelope.as_slice(),
            )),
            SomeEnvelopeContent::TopologyTransactionsBroadcast(_) => {
                has_topology |= recipients.iter().any(|r| r == ALL_MEMBERS)
            }
            _ => {}
        }
    }
    let (to_a_mediator, not_to_a_mediator): (Vec<RootHash>, Vec<RootHash>) = root_hashes
        .into_iter()
        .partition(|m| m.recipients.iter().any(|r| group_of(r).is_some()));
    if !not_to_a_mediator.is_empty() {
        alarms.push(format!(
            "Received {} root hash messages that were not sent to a mediator",
            not_to_a_mediator.len()
        ));
    }
    let mut groups: Vec<u32> = to_a_mediator
        .iter()
        .flat_map(|m| m.recipients.iter().filter_map(|r| group_of(r)))
        .collect();
    groups.sort_unstable();
    groups.dedup();
    let dropped = |why: String, mut alarms: Vec<String>| {
        alarms.push(why.clone());
        Checked {
            request: Request::Dropped(why),
            alarms,
        }
    };
    // [CANTON-NOTE: DEFENSIVE] Canton treats this as an internal error (the sequencer lets a participant address one mediator only).
    if groups.len() > 1 && !views.is_empty() {
        return dropped(
            format!("Received batch with encrypted views and root hash messages addressed to multiple mediators: {groups:?}"),
            alarms,
        );
    }
    let message = match to_a_mediator.as_slice() {
        [one] => one,
        [] if views.is_empty() => {
            return Checked {
                request: Request::None,
                alarms,
            }
        }
        [] => return dropped("No valid root hash message in batch".into(), alarms),
        many => {
            return dropped(
                format!("Multiple root hash messages in batch: {}", many.len()),
                alarms,
            )
        }
    };
    let Some(&group) = groups.first() else {
        return dropped("No mediator group recipient".into(), alarms);
    };
    // `RootHashMessageRecipients.validateRecipientsOnParticipant`: one group of two (the mediator group and this participant)
    if message.recipients.len() != 2 {
        alarms.push(format!(
            "The root hash message has invalid recipient groups: {:?}",
            message.recipients
        ));
    }
    let view_type = ViewType::try_from(message.message.view_type).unwrap_or(ViewType::Unspecified);
    let (good, bad): (Vec<_>, Vec<_>) = views.into_iter().partition(|(t, _)| *t == view_type);
    if !bad.is_empty() {
        let mut types: Vec<ViewType> = bad.iter().map(|(t, _)| *t).collect();
        types.dedup();
        alarms.push(format!(
            "Expected view type {view_type:?}, but received view types {types:?}"
        ));
    }
    let root_hash = message.message.root_hash.clone();
    if good.is_empty() {
        let why = format!("Received no encrypted view message of type {view_type:?}");
        alarms.push(why.clone());
        return Checked {
            request: Request::BadRootHashMessages {
                root_hash,
                mediator_group: group,
                why,
            },
            alarms,
        };
    }
    if has_topology {
        return dropped(
            "Invalid batch containing both a request and topology transaction".into(),
            alarms,
        );
    }
    Checked {
        request: Request::Good(Good {
            root_hash,
            view_type,
            mediator_group: group,
            views: good.into_iter().map(|(_, v)| v).collect(),
        }),
        alarms,
    }
}
