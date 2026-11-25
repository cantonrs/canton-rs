//! The approved transactions this participant applied that whoever shows them (the JSON API) has not recorded yet (P-13).
//!
//! [CANTON-NOTE: WHY] The contract set's journal and the cursor move past an approval before the API records its transaction. A crash in
//! between lost the transaction: its creations come back when the node reconciles its contracts at start, its consumptions do not, so the
//! API kept showing archived contracts as active. Once [`Runtime::keep_applied_until_shown`] is called, every [`Applied`] of an event is kept
//! (`applied.journal`, before the cursor moves past the event) until [`Runtime::applied_shown`] marks it recorded; after a restart the ones
//! not marked are [`Runtime::unshown_applied`]. Records: `A\t<request id>\t<consumed>\t<created>\t<reassignment>\t<root_hash_hex>\t<remote_events_hex>` and `D\t<request id>`.
use super::Runtime;
use crate::reassignment_wire::Kind;
use crate::state_store::StateStore;
use crate::view_acs::{Applied, RemoteEvent, RemoteExercise};
use lf_eval::{BigNumericValue, CtorRank, List, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

const JOURNAL: &str = "applied.journal";

#[derive(Default)]
pub(super) struct Outbox {
    store: Option<Arc<dyn StateStore>>,
    /// Whether the applied transactions are kept (see the module documentation).
    hold: bool,
    unshown: BTreeMap<i64, Applied>,
}

impl Outbox {
    /// What `store` keeps that was not marked shown; the journal is rewritten without the rest.
    pub(super) fn open(store: Option<Arc<dyn StateStore>>) -> Result<Self, String> {
        let Some(kept) = &store else {
            return Ok(Self::default());
        };
        let journal = kept.read(JOURNAL)?.unwrap_or_default();
        let mut unshown = BTreeMap::new();
        for line in journal.lines() {
            match line.split('\t').collect::<Vec<_>>().as_slice() {
                ["D", request] => {
                    if let Ok(request) = request.parse::<i64>() {
                        unshown.remove(&request);
                    }
                }
                ["A", ..] => {
                    if let Some(applied) = parse(line) {
                        unshown.insert(applied.request_id, applied);
                    }
                }
                _ => {}
            }
        }
        if unshown.len() < journal.lines().count() {
            let text: String = unshown.values().map(|a| record(a) + "\n").collect();
            kept.write(JOURNAL, &text)?;
        }
        Ok(Outbox {
            store,
            hold: false,
            unshown,
        })
    }

    pub(super) fn keep(&mut self, applied: &[Applied]) -> Result<(), String> {
        if !self.hold {
            return Ok(());
        }
        for a in applied {
            if self.unshown.contains_key(&a.request_id) {
                continue;
            }
            if let Some(store) = &self.store {
                store.append(JOURNAL, &record(a))?;
            }
            self.unshown.insert(a.request_id, a.clone());
        }
        Ok(())
    }
}

impl Runtime {
    /// From now on the approved transactions are kept until [`Runtime::applied_shown`] (see the module documentation).
    pub fn keep_applied_until_shown(&mut self) {
        self.outbox.hold = true;
    }

    /// The approved transactions kept and not marked shown, oldest request first: after a restart, the ones the crash kept from being recorded.
    pub fn unshown_applied(&self) -> Vec<Applied> {
        self.outbox.unshown.values().cloned().collect()
    }

    /// Whoever shows the transaction of `request_id` recorded it: it is not handed over again.
    pub fn applied_shown(&mut self, request_id: i64) -> Result<(), String> {
        if self.outbox.unshown.remove(&request_id).is_some() {
            if let Some(store) = &self.outbox.store {
                store.append(JOURNAL, &format!("D\t{request_id}"))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum StoredValue {
    Unit,
    Bool(bool),
    Int64(i64),
    Numeric {
        coeff: String,
        scale: u8,
    },
    BigNumeric {
        signed_bytes_le: Vec<u8>,
        scale: i32,
    },
    Text(String),
    Party(String),
    ContractId(String),
    List(Vec<StoredValue>),
    Optional(Option<Box<StoredValue>>),
    Record {
        tycon: Option<String>,
        fields: Vec<(String, StoredValue)>,
    },
    Variant {
        tycon: Option<String>,
        constructor: String,
        rank: Option<u32>,
        value: Box<StoredValue>,
    },
    Enum {
        tycon: Option<String>,
        constructor: String,
        rank: Option<u32>,
    },
    Struct(Vec<(String, StoredValue)>),
    AnyException {
        tycon: String,
        payload: Box<StoredValue>,
    },
    Any {
        key: String,
        payload: Box<StoredValue>,
    },
    TypeRep {
        key: String,
        tycon: Option<String>,
    },
    Map(Vec<(StoredValue, StoredValue)>),
    Iface {
        package_id: String,
        template: String,
        payload: Box<StoredValue>,
    },
}

impl StoredValue {
    fn from_value(val: &Value) -> Option<Self> {
        Some(match val {
            Value::Unit => Self::Unit,
            Value::Bool(b) => Self::Bool(*b),
            Value::Int64(n) => Self::Int64(*n),
            Value::Numeric { coeff, scale } => Self::Numeric {
                coeff: coeff.to_string(),
                scale: *scale,
            },
            Value::BigNumeric(bn) => {
                let (signed_bytes_le, scale) = bn.to_signed_bytes_le();
                Self::BigNumeric {
                    signed_bytes_le,
                    scale,
                }
            }
            Value::Text(s) => Self::Text(s.clone()),
            Value::Party(p) => Self::Party(p.clone()),
            Value::ContractId(cid) => Self::ContractId(cid.clone()),
            Value::List(list) => Self::List(
                list.iter()
                    .map(Self::from_value)
                    .collect::<Option<Vec<_>>>()?,
            ),
            Value::Optional(opt) => Self::Optional(match opt.as_ref() {
                Some(inner) => Some(Box::new(Self::from_value(inner)?)),
                None => None,
            }),
            Value::Record { tycon, fields } => Self::Record {
                tycon: tycon.clone(),
                fields: fields
                    .iter()
                    .map(|(k, v)| Some((k.clone(), Self::from_value(v)?)))
                    .collect::<Option<Vec<_>>>()?,
            },
            Value::Variant {
                tycon,
                constructor,
                rank,
                value,
            } => Self::Variant {
                tycon: tycon.clone(),
                constructor: constructor.clone(),
                rank: rank.0,
                value: Box::new(Self::from_value(value)?),
            },
            Value::Enum {
                tycon,
                constructor,
                rank,
            } => Self::Enum {
                tycon: tycon.clone(),
                constructor: constructor.clone(),
                rank: rank.0,
            },
            Value::Struct(fields) => Self::Struct(
                fields
                    .iter()
                    .map(|(k, v)| Some((k.clone(), Self::from_value(v)?)))
                    .collect::<Option<Vec<_>>>()?,
            ),
            Value::AnyException { tycon, payload } => Self::AnyException {
                tycon: tycon.clone(),
                payload: Box::new(Self::from_value(payload)?),
            },
            Value::Any { key, payload } => Self::Any {
                key: key.clone(),
                payload: Box::new(Self::from_value(payload)?),
            },
            Value::TypeRep { key, tycon } => Self::TypeRep {
                key: key.clone(),
                tycon: tycon.clone(),
            },
            Value::Map(entries) => Self::Map(
                entries
                    .iter()
                    .map(|(k, v)| Some((Self::from_value(k)?, Self::from_value(v)?)))
                    .collect::<Option<Vec<_>>>()?,
            ),
            Value::Iface {
                package_id,
                template,
                payload,
            } => Self::Iface {
                package_id: package_id.clone(),
                template: template.clone(),
                payload: Box::new(Self::from_value(payload)?),
            },
            Value::Partial { .. }
            | Value::Closure { .. }
            | Value::TyClosure { .. }
            | Value::Action { .. }
            | Value::KeyFn { .. }
            | Value::KeyAction { .. } => return None,
        })
    }

    fn into_value(self) -> Option<Value> {
        Some(match self {
            Self::Unit => Value::Unit,
            Self::Bool(b) => Value::Bool(b),
            Self::Int64(n) => Value::Int64(n),
            Self::Numeric { coeff, scale } => Value::Numeric {
                coeff: coeff.parse::<i128>().ok()?,
                scale,
            },
            Self::BigNumeric {
                signed_bytes_le,
                scale,
            } => Value::BigNumeric(
                BigNumericValue::from_signed_bytes_le(&signed_bytes_le, scale).ok()?,
            ),
            Self::Text(s) => Value::Text(s),
            Self::Party(p) => Value::Party(p),
            Self::ContractId(cid) => Value::ContractId(cid),
            Self::List(items) => {
                let mut vals = Vec::with_capacity(items.len());
                for item in items {
                    vals.push(item.into_value()?);
                }
                Value::List(
                    vals.into_iter()
                        .rev()
                        .fold(List::new(), |acc, v| List::cons(v, acc)),
                )
            }
            Self::Optional(opt) => Value::Optional(match opt {
                Some(v) => Some(Box::new(v.into_value()?)),
                None => None,
            }),
            Self::Record { tycon, fields } => Value::Record {
                tycon,
                fields: fields
                    .into_iter()
                    .map(|(k, v)| Some((k, v.into_value()?)))
                    .collect::<Option<Vec<_>>>()?,
            },
            Self::Variant {
                tycon,
                constructor,
                rank,
                value,
            } => Value::Variant {
                tycon,
                constructor,
                rank: CtorRank(rank),
                value: Box::new(value.into_value()?),
            },
            Self::Enum {
                tycon,
                constructor,
                rank,
            } => Value::Enum {
                tycon,
                constructor,
                rank: CtorRank(rank),
            },
            Self::Struct(fields) => Value::Struct(
                fields
                    .into_iter()
                    .map(|(k, v)| Some((k, v.into_value()?)))
                    .collect::<Option<Vec<_>>>()?,
            ),
            Self::AnyException { tycon, payload } => Value::AnyException {
                tycon,
                payload: Box::new(payload.into_value()?),
            },
            Self::Any { key, payload } => Value::Any {
                key,
                payload: Box::new(payload.into_value()?),
            },
            Self::TypeRep { key, tycon } => Value::TypeRep { key, tycon },
            Self::Map(entries) => Value::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| Some((k.into_value()?, v.into_value()?)))
                    .collect::<Option<Vec<_>>>()?,
            ),
            Self::Iface {
                package_id,
                template,
                payload,
            } => Value::Iface {
                package_id,
                template,
                payload: Box::new(payload.into_value()?),
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StoredRemoteExercise {
    depth: usize,
    contract_id: String,
    input_instance: Vec<u8>,
    choice: String,
    consuming: bool,
    actors: Vec<String>,
    observers: Vec<String>,
    interface_id: Option<String>,
    argument: StoredValue,
    result: Option<StoredValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum StoredRemoteEvent {
    Create {
        depth: usize,
        contract_id: String,
        instance: Vec<u8>,
    },
    Exercise(Box<StoredRemoteExercise>),
    Fetch {
        depth: usize,
    },
}

impl StoredRemoteEvent {
    fn from_remote(ev: &RemoteEvent) -> Option<Self> {
        Some(match ev {
            RemoteEvent::Create {
                depth,
                contract_id,
                instance,
            } => Self::Create {
                depth: *depth,
                contract_id: contract_id.clone(),
                instance: instance.clone(),
            },
            RemoteEvent::Exercise(ex) => Self::Exercise(Box::new(StoredRemoteExercise {
                depth: ex.depth,
                contract_id: ex.contract_id.clone(),
                input_instance: ex.input_instance.clone(),
                choice: ex.choice.clone(),
                consuming: ex.consuming,
                actors: ex.actors.clone(),
                observers: ex.observers.clone(),
                interface_id: ex.interface_id.clone(),
                argument: StoredValue::from_value(&ex.argument)?,
                result: match ex.result.as_ref() {
                    Some(r) => Some(StoredValue::from_value(r)?),
                    None => None,
                },
            })),
            RemoteEvent::Fetch { depth, .. } => Self::Fetch { depth: *depth },
        })
    }

    fn into_remote(self) -> Option<RemoteEvent> {
        Some(match self {
            Self::Create {
                depth,
                contract_id,
                instance,
            } => RemoteEvent::Create {
                depth,
                contract_id,
                instance,
            },
            Self::Exercise(ex) => RemoteEvent::Exercise(Box::new(RemoteExercise {
                depth: ex.depth,
                contract_id: ex.contract_id,
                input_instance: ex.input_instance,
                choice: ex.choice,
                consuming: ex.consuming,
                actors: ex.actors,
                observers: ex.observers,
                interface_id: ex.interface_id,
                argument: ex.argument.into_value()?,
                result: match ex.result {
                    Some(r) => Some(r.into_value()?),
                    None => None,
                },
            })),
            Self::Fetch { depth } => RemoteEvent::Fetch {
                depth,
                contract_id: String::new(),
                input_instance: Vec::new(),
                actors: Vec::new(),
                interface_id: None,
            },
        })
    }
}

fn encode_remote_events(events: &[RemoteEvent]) -> String {
    if events.is_empty() {
        return String::new();
    }
    let stored: Vec<StoredRemoteEvent> = events
        .iter()
        .filter_map(StoredRemoteEvent::from_remote)
        .collect();
    if stored.is_empty() {
        return String::new();
    }
    serde_json::to_vec(&stored).map_or_else(|_| String::new(), hex::encode)
}

fn decode_remote_events(hex_field: &str) -> Option<Vec<RemoteEvent>> {
    if hex_field.is_empty() {
        return Some(Vec::new());
    }
    let raw = hex::decode(hex_field).ok()?;
    let stored: Vec<StoredRemoteEvent> = serde_json::from_slice(&raw).ok()?;
    stored
        .into_iter()
        .map(StoredRemoteEvent::into_remote)
        .collect()
}

fn record(a: &Applied) -> String {
    let created: Vec<String> = a
        .created
        .iter()
        .map(|(id, bytes)| format!("{id}:{}", hex::encode(bytes)))
        .collect();
    let reassignment = match &a.reassignment {
        None => "-".to_string(),
        Some((kind, counters)) => {
            let counters: Vec<String> =
                counters.iter().map(|(id, c)| format!("{id}={c}")).collect();
            let kind = match kind {
                Kind::Unassignment => "U",
                Kind::Assignment => "S",
            };
            format!("{kind}{}", counters.join(","))
        }
    };
    format!(
        "A\t{}\t{}\t{}\t{reassignment}\t{}\t{}",
        a.request_id,
        a.consumed.join(","),
        created.join(","),
        hex::encode(&a.root_hash),
        encode_remote_events(&a.remote_events)
    )
}

fn parse(line: &str) -> Option<Applied> {
    let parts: Vec<&str> = line.split('\t').collect();
    let (request, consumed, created, reassignment, root_hash_hex, remote_events_hex) =
        match parts.as_slice() {
            ["A", request, consumed, created, reassignment] => {
                (*request, *consumed, *created, *reassignment, "", "")
            }
            ["A", request, consumed, created, reassignment, root_hash_hex] => (
                *request,
                *consumed,
                *created,
                *reassignment,
                *root_hash_hex,
                "",
            ),
            ["A", request, consumed, created, reassignment, root_hash_hex, remote_events_hex] => (
                *request,
                *consumed,
                *created,
                *reassignment,
                *root_hash_hex,
                *remote_events_hex,
            ),
            _ => return None,
        };
    let root_hash = if root_hash_hex.is_empty() {
        Vec::new()
    } else {
        hex::decode(root_hash_hex).ok()?
    };
    let list = |text: &str| -> Vec<String> {
        text.split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    };
    let created = list(created)
        .iter()
        .map(|entry| {
            let (id, bytes) = entry.split_once(':')?;
            Some((id.to_string(), hex::decode(bytes).ok()?))
        })
        .collect::<Option<Vec<_>>>()?;
    let reassignment = match reassignment.split_at_checked(1)? {
        ("-", "") => None,
        (kind, counters) => {
            let kind = match kind {
                "U" => Kind::Unassignment,
                "S" => Kind::Assignment,
                _ => return None,
            };
            let counters = list(counters)
                .iter()
                .map(|entry| {
                    let (id, counter) = entry.split_once('=')?;
                    Some((id.to_string(), counter.parse().ok()?))
                })
                .collect::<Option<Vec<_>>>()?;
            Some((kind, counters))
        }
    };
    let remote_events = decode_remote_events(remote_events_hex)?;
    Some(Applied {
        request_id: request.parse().ok()?,
        consumed: list(consumed),
        created,
        reassignment,
        root_hash,
        remote_events,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse, record};
    use crate::reassignment_wire::Kind;
    use crate::view_acs::{Applied, RemoteEvent, RemoteExercise};
    use lf_eval::{List, Value};

    #[test]
    fn a_kept_transaction_reads_back_as_it_was() {
        let rich_exercise = RemoteEvent::Exercise(Box::new(RemoteExercise {
            depth: 1,
            contract_id: "cid-1".into(),
            input_instance: vec![9, 8, 7],
            choice: "Transfer".into(),
            consuming: true,
            actors: vec!["alice::1".into()],
            observers: vec!["bob::2".into()],
            interface_id: Some("Iface:I".into()),
            argument: Value::Record {
                tycon: Some("M:Arg".into()),
                fields: vec![
                    (
                        "amount".into(),
                        Value::Numeric {
                            coeff: 123_450_000_000,
                            scale: 10,
                        },
                    ),
                    (
                        "tags".into(),
                        Value::List(List::cons(
                            Value::Text("a".into()),
                            List::cons(
                                Value::Optional(Some(Box::new(Value::Bool(true)))),
                                List::new(),
                            ),
                        )),
                    ),
                ],
            },
            result: Some(Value::ContractId("cid-2".into())),
        }));
        for applied in [
            Applied {
                request_id: 7,
                consumed: vec!["c1".into(), "c2".into()],
                created: vec![("n1".into(), vec![1, 2, 3])],
                reassignment: None,
                root_hash: vec![0x12, 0x20, 0xaa, 0xbb],
                remote_events: vec![
                    RemoteEvent::Create {
                        depth: 0,
                        contract_id: "n1".into(),
                        instance: vec![1, 2, 3],
                    },
                    rich_exercise,
                    RemoteEvent::Fetch {
                        depth: 2,
                        contract_id: String::new(),
                        input_instance: Vec::new(),
                        actors: Vec::new(),
                        interface_id: None,
                    },
                ],
            },
            Applied {
                request_id: 8,
                consumed: vec![],
                created: vec![],
                reassignment: Some((Kind::Assignment, vec![("n2".into(), 3)])),
                root_hash: vec![0x12, 0x20, 0xcc, 0xdd],
                remote_events: Vec::new(),
            },
        ] {
            assert_eq!(parse(&record(&applied)), Some(applied));
        }
        let legacy_5 = parse("A\t7\tc1\t\t-").expect("legacy 5-field line must remain readable");
        assert!(legacy_5.root_hash.is_empty());
        assert!(legacy_5.remote_events.is_empty());
        let legacy_6 =
            parse("A\t7\tc1\t\t-\t1220aa").expect("legacy 6-field line must remain readable");
        assert_eq!(legacy_6.root_hash, vec![0x12, 0x20, 0xaa]);
        assert!(legacy_6.remote_events.is_empty());
    }
}
