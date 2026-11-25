//! The informees of a view against the ones its action gives (internal review P-10; part of Canton's model conformance check).
//!
//! [CANTON-NOTE: SEMANTICS] `ModelConformanceChecker.checkView` rebuilds each view from the reinterpreted transaction and requires it to
//! equal the received one, so a view that names an informee its action does not give is refused. The conformance check
//! (`view_conformance`) replays the action; this module compares what the replay gives with what the view says.
use crate::view_conformance::{
    stated_signatories, stated_stakeholders, unversioned_fat, Nonconformance,
};
use crate::view_receive::RevealedView;
use crate::view_validation::HostsOf;
use canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers;
use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
use canton_proto::com::digitalasset::daml::lf::value::Identifier;
use lf_eval::engine::EngineEvent;
use prost::Message;
use std::collections::BTreeSet;

/// Context for deriving the informees of a replayed exercise view (`replayed_core_informees`).
#[derive(Default)]
pub(crate) struct InformeeContext<'a> {
    pub has_subviews: bool,
    /// Admin party (`submitting_participant_uid`) when decomposing a root view; `None` for a subview.
    pub root_admin: Option<&'a str>,
    pub hosts_of: Option<&'a HostsOf<'a>>,
    pub resolved_keys: &'a [KeyResolutionWithMaintainers],
}

/// The informees the nodes of a view's core give (`Node.informeesOfNode` and the confirming parties of each node), as far as the replay tells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreInformees {
    /// The core is the whole replayed subtree: these are its informees.
    Exact(BTreeSet<String>),
    /// The view has subviews, whose nodes the replay does not tell from the core's: the core's informees are among these.
    AtMost(BTreeSet<String>),
    /// The replay leaves out nodes (a rollback, a key lookup): no bound is known.
    Unknown,
}

/// Checks that a view's informees are the ones its core gives, plus the submitting participant's admin party (`admin`) for a root view.
///
/// [CANTON-NOTE: SEMANTICS] `ModelConformanceChecker.checkView` rebuilds the view from the reinterpreted transaction and requires it to equal
/// the received one; the informees of a view are those of the nodes of its core (`TransactionViewDecompositionFactory`: a subview's informees
/// stay in the subview), and a root node's confirming parties include the admin party. An informee no node gives is refused.
///
/// [CANTON-NOTE: LIMITATION] For a view with subviews, exact core decomposition requires `hosts_of` and no rollbacks or key lookups;
/// otherwise the replayed union (`AtMost`) or `Unknown` is checked.
pub fn check_informees(
    view: &RevealedView,
    core: &CoreInformees,
    admin: Option<&str>,
) -> Result<(), Nonconformance> {
    let stated: BTreeSet<String> = view.common_data.informees.iter().cloned().collect();
    let with_admin = |set: &BTreeSet<String>| {
        let mut set = set.clone();
        set.extend(admin.map(str::to_string));
        set
    };
    match core {
        CoreInformees::Exact(given) if stated != with_admin(given) => {
            Err(Nonconformance::InformeesDiffer(format!(
                "the view says {stated:?}, the action gives {:?}",
                with_admin(given)
            )))
        }
        CoreInformees::AtMost(bound) => match stated.difference(&with_admin(bound)).next() {
            Some(extra) => Err(Nonconformance::InformeesDiffer(format!(
                "{extra} is an informee of the view but of no node of its action"
            ))),
            None => Ok(()),
        },
        _ => Ok(()),
    }
}

/// The informees of a create or a fetch view's one node, from the contract it carries (authenticated by [`check_view`] or [`check_fetch_view`]):
/// a create's stakeholders, a fetch's signatories and actors.
pub fn single_node_informees(view: &RevealedView) -> Result<CoreInformees, Nonconformance> {
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    let contract_of = |bytes: &[u8]| -> Result<FatContractInstance, Nonconformance> {
        let (data, _) = unversioned_fat(bytes)?;
        FatContractInstance::decode(data.as_slice())
            .map_err(|e| Nonconformance::Malformed(e.to_string()))
    };
    let data = &view.participant_data;
    match data
        .action_description
        .as_ref()
        .and_then(|a| a.description.as_ref())
    {
        Some(Description::Create(_)) => {
            let mut out = BTreeSet::new();
            for created in &data.created_core {
                out.extend(stated_stakeholders(&contract_of(&created.contract)?));
            }
            Ok(CoreInformees::Exact(out))
        }
        Some(Description::Fetch(fetch)) => {
            let mut out: BTreeSet<String> = fetch.actors.iter().cloned().collect();
            for input in &data.core_inputs {
                out.extend(stated_signatories(&contract_of(&input.contract)?));
            }
            Ok(CoreInformees::Exact(out))
        }
        _ => Ok(CoreInformees::Unknown),
    }
}

fn event_depth(event: &EngineEvent) -> usize {
    match event {
        EngineEvent::Create { depth, .. }
        | EngineEvent::Fetch { depth, .. }
        | EngineEvent::Exercise { depth, .. } => *depth,
    }
}

fn event_tree(events: &[EngineEvent]) -> Vec<Vec<usize>> {
    let mut children = vec![Vec::new(); events.len()];
    let mut open_exercises: Vec<usize> = Vec::new();
    for (idx, event) in events.iter().enumerate() {
        let depth = event_depth(event);
        if let Some(parent_depth) = depth.checked_sub(1) {
            if let Some(&parent) = open_exercises.get(parent_depth) {
                children[parent].push(idx);
            }
        }
        if matches!(event, EngineEvent::Exercise { .. }) {
            if open_exercises.len() <= depth {
                open_exercises.resize(depth + 1, idx);
            }
            open_exercises[depth] = idx;
        }
    }
    children
}

fn node_informees(
    replay: &lf_eval::engine::Engine,
    event: &EngineEvent,
) -> Option<BTreeSet<String>> {
    let (id, consuming, parties): (&str, bool, Vec<String>) = match event {
        EngineEvent::Create { contract_id, .. } => (contract_id, true, Vec::new()),
        EngineEvent::Exercise {
            contract_id,
            consuming,
            actors,
            observers,
            ..
        } => (
            contract_id,
            *consuming,
            actors.iter().chain(observers).cloned().collect(),
        ),
        EngineEvent::Fetch {
            contract_id,
            authorizers,
            ..
        } => (contract_id, false, authorizers.clone()),
    };
    let contract = replay.contract(id)?;
    let mut out = BTreeSet::new();
    out.extend(contract.signatories.iter().cloned());
    if consuming {
        out.extend(contract.observers.iter().cloned());
    }
    out.extend(parties);
    Some(out)
}

fn lookup_maintainers(
    resolved_keys: &[KeyResolutionWithMaintainers],
    lookups: &[lf_eval::engine::KeyLookup],
) -> Option<BTreeSet<String>> {
    let mut decoded: Vec<(String, Vec<u8>, &[String])> = Vec::new();
    for r in resolved_keys {
        let key = r.key.as_ref()?;
        let id = Identifier::decode(key.template_id.as_slice()).ok()?;
        let versioned = Versioned::decode(key.key.as_slice()).ok()?;
        let template = format!("{}:{}", id.module_name.join("."), id.name.join("."));
        decoded.push((template, versioned.payload, &r.maintainers));
    }
    let mut out = BTreeSet::new();
    for kl in lookups {
        let payload = kl.key.to_lf_value().encode_to_vec();
        let (_, _, maintainers) = decoded
            .iter()
            .find(|(t, p, _)| *t == kl.template_id && *p == payload)?;
        out.extend(maintainers.iter().cloned());
    }
    Some(out)
}

/// `[CANTON-NOTE: SEMANTICS]` `TransactionViewDecompositionFactory.scala:131, 402-413`: resolve hosted participant UIDs for each
/// informee (unhosted informees map to an empty participant set instead of failing open with `AtMost`).
fn hosting_participants(
    informees: &BTreeSet<String>,
    hosts_of: &HostsOf<'_>,
    root_admin: Option<&str>,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for party in informees {
        if let Some((_, hosts)) = hosts_of(party) {
            if !hosts.is_empty() {
                out.extend(hosts.into_iter().map(|(uid, _)| uid));
                continue;
            }
        }
        if root_admin == Some(party.as_str()) {
            out.insert(party.clone());
        }
    }
    out
}

/// The informees of the view's own core (Canton `TransactionViewDecompositionFactory` when `hosts_of` is given and no rollbacks/key lookups
/// occurred) or the full upper bound across replayed nodes.
pub(crate) fn replayed_core_informees(
    replay: &lf_eval::engine::Engine,
    ctx: &InformeeContext<'_>,
) -> CoreInformees {
    let events = replay.events();
    let mut per_node = Vec::with_capacity(events.len());
    let mut all_informees = BTreeSet::new();
    for event in events {
        let Some(informees) = node_informees(replay, event) else {
            return CoreInformees::Unknown;
        };
        all_informees.extend(informees.iter().cloned());
        per_node.push(informees);
    }
    if !replay.key_lookups().is_empty() {
        let Some(maintainers) = lookup_maintainers(ctx.resolved_keys, replay.key_lookups()) else {
            return CoreInformees::Unknown;
        };
        all_informees.extend(maintainers);
    }
    if !replay.rolled_back().is_empty() {
        for group in replay.rolled_back() {
            for event in &group.events {
                let Some(informees) = node_informees(replay, event) else {
                    return CoreInformees::Unknown;
                };
                all_informees.extend(informees);
            }
        }
        return CoreInformees::AtMost(all_informees);
    }
    if !replay.key_lookups().is_empty() {
        return CoreInformees::AtMost(all_informees);
    }
    if !ctx.has_subviews {
        return CoreInformees::Exact(all_informees);
    }
    let Some(hosts) = ctx.hosts_of else {
        return CoreInformees::AtMost(all_informees);
    };
    if per_node.is_empty() {
        return CoreInformees::Exact(BTreeSet::new());
    }
    let children = event_tree(events);
    let nodes: Vec<crate::view_tree::DecompNode> = per_node
        .iter()
        .enumerate()
        .map(|(i, informees)| {
            let participants = if i == 0 {
                let mut root_with_admin = informees.clone();
                if let Some(admin) = ctx.root_admin {
                    root_with_admin.insert(admin.to_string());
                }
                hosting_participants(&root_with_admin, hosts, ctx.root_admin)
            } else {
                hosting_participants(informees, hosts, None)
            };
            crate::view_tree::DecompNode {
                informees: informees.clone(),
                participants,
                children: children[i].clone(),
                is_rollback: false,
            }
        })
        .collect();
    CoreInformees::Exact(crate::view_tree::core_informees_of_root(&nodes, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_tree_attaches_children_to_nearest_open_exercise() {
        let dummy_val = lf_eval::Value::Unit;
        let events = vec![
            EngineEvent::Exercise {
                contract_id: "root".into(),
                choice: "Start".into(),
                consuming: false,
                actors: vec!["alice".into()],
                depth: 0,
                argument: dummy_val.clone(),
                result: None,
                interface_id: None,
                observers: vec![],
            },
            EngineEvent::Create {
                contract_id: "hop".into(),
                template_id: "T".into(),
                depth: 1,
            },
            EngineEvent::Exercise {
                contract_id: "hop".into(),
                choice: "Forward".into(),
                consuming: true,
                actors: vec!["alice".into()],
                depth: 1,
                argument: dummy_val,
                result: None,
                interface_id: None,
                observers: vec![],
            },
            EngineEvent::Create {
                contract_id: "note".into(),
                template_id: "N".into(),
                depth: 2,
            },
        ];
        let tree = event_tree(&events);
        assert_eq!(tree[0], vec![1, 2]);
        assert!(tree[1].is_empty());
        assert_eq!(tree[2], vec![3]);
        assert!(tree[3].is_empty());
    }

    #[test]
    fn lookup_maintainers_extracts_maintainers_of_resolved_key_lookups() {
        let key_val = lf_eval::Value::Party("bank".into());
        let resolved = KeyResolutionWithMaintainers {
            key: Some(
                canton_proto::com::digitalasset::canton::protocol::v31::GlobalKey {
                    template_id: Identifier {
                        package_id: "pkg".into(),
                        module_name: vec!["Mod".into()],
                        name: vec!["Keyed".into()],
                    }
                    .encode_to_vec(),
                    key: Versioned {
                        version: "1".to_string(),
                        payload: key_val.to_lf_value().encode_to_vec(),
                    }
                    .encode_to_vec(),
                    hash: vec![1; 32],
                    package_name: "p".into(),
                },
            ),
            maintainers: vec!["bank::1220aa".into()],
            contract_ids: vec![],
        };
        let lookups = vec![lf_eval::engine::KeyLookup {
            template_id: "Mod:Keyed".into(),
            key: key_val,
            contract_ids: vec![],
        }];
        let got = lookup_maintainers(&[resolved], &lookups).unwrap();
        assert_eq!(got, ["bank::1220aa".to_string()].into_iter().collect());
    }
}
