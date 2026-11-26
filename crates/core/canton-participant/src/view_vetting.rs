//! Whether every participant that sees a part of a transaction has vetted the packages that part uses (U-62; part of Canton's model
//! conformance check).
//!
//! [CANTON-NOTE: SEMANTICS] `ModelConformanceChecker.checkView` runs, for protocol version 36 and later, `checkTxPackageVetting` on the
//! reinterpreted transaction of each view: `Blinding.partyPackages` gives, for every party that witnesses a node (its informees and those
//! of every exercise above it), the node's template package and, for an exercise through an interface, the interface's package.
//! `UsableSynchronizers.checkRequiredPackagesByParty` then asks every active participant hosting such a party (the confirming one
//! included) whether it vets those packages at the request's ledger time (`VettedPackage.validAt`). Dependencies are not checked
//! (`PackageDependencyResolverImpl` returns the asked packages as the main ones). A package left out is `UnvettedPackages`, a failed model
//! conformance check (`LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK`).
//!
//! [CANTON-NOTE: LIMITATION] Protocol versions before 36 check the view's informees against the packages the reinterpretation used
//! (`checkViewPackageVetting`); this module applies the rule of 36 and later to every version (the deployments measured run 37).
//! The package of a nested exercise is the one the replay holds the contract under: a nested exercise the engine runs under an upgraded
//! package is counted under the contract's own. The nodes of a rolled-back `try` body are not counted (the replay forgets their
//! contracts).
use crate::view_conformance::{stated_stakeholders, unversioned_fat, Nonconformance};
use crate::view_informees::{event_depth, node_informees};
use crate::view_receive::RevealedView;
use crate::view_validation::HostsOf;
use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
use canton_proto::com::digitalasset::daml::lf::transaction::FatContractInstance;
use lf_eval::engine::EngineEvent;
use prost::Message;
use std::collections::{BTreeMap, BTreeSet};

/// For each party, the packages it needs to interpret what it sees of a transaction (`Blinding.partyPackages`).
pub type PartyPackages = BTreeMap<String, BTreeSet<String>>;

/// The packages a participant (uid) vets at a time (microseconds since the epoch), `None` for a participant that vets nothing.
pub type VettedAt<'a> = dyn Fn(&str, i64) -> Option<BTreeSet<String>> + 'a;

fn package_of(qualified: &str) -> String {
    qualified
        .split_once(':')
        .map_or(qualified, |(package, _)| package)
        .to_string()
}

fn add(out: &mut PartyPackages, parties: &BTreeSet<String>, packages: &BTreeSet<String>) {
    for party in parties {
        out.entry(party.clone())
            .or_default()
            .extend(packages.iter().cloned());
    }
}

/// What the parties of a replayed exercise view need: every journaled node, witnessed by its informees and those of the exercises it
/// sits in. `Err` when the replay lost a contract a node names (it cannot happen for a replay that ran).
pub(crate) fn replayed_party_packages(
    replay: &lf_eval::engine::Engine,
) -> Result<PartyPackages, Nonconformance> {
    let mut out = PartyPackages::new();
    // `open[d]`: the witnesses of the exercise open at depth `d`
    let mut open: Vec<BTreeSet<String>> = Vec::new();
    for event in replay.events() {
        let depth = event_depth(event);
        open.truncate(depth);
        let (contract_id, interface_id) = match event {
            EngineEvent::Create { contract_id, .. } => (contract_id, None),
            EngineEvent::Exercise {
                contract_id,
                interface_id,
                ..
            } => (contract_id, interface_id.as_deref()),
            EngineEvent::Fetch { contract_id, .. } => (contract_id, None),
        };
        let lost = || {
            Nonconformance::Malformed(format!(
                "the replay does not hold the contract {contract_id} of one of its nodes"
            ))
        };
        let contract = replay.contract(contract_id).ok_or_else(lost)?;
        let mut witnesses = node_informees(replay, event).ok_or_else(lost)?;
        if let Some(above) = depth.checked_sub(1).and_then(|d| open.get(d)) {
            witnesses.extend(above.iter().cloned());
        }
        let mut packages = BTreeSet::from([contract.package_id.clone()]);
        // [CANTON-NOTE: SEMANTICS] `Blinding.partyPackages`: an exercise also needs its interface's package; a fetch (a leaf) only its
        // template's, even through an interface.
        packages.extend(interface_id.map(package_of));
        add(&mut out, &witnesses, &packages);
        if matches!(event, EngineEvent::Exercise { .. }) {
            if open.len() != depth {
                return Err(Nonconformance::Malformed(format!(
                    "the replay journals an exercise at depth {depth} below no exercise at depth {}",
                    open.len()
                )));
            }
            open.push(witnesses);
        }
    }
    Ok(out)
}

/// What the parties of a create or a fetch view need: the node's informees, its template's package.
pub(crate) fn single_node_party_packages(
    view: &RevealedView,
) -> Result<PartyPackages, Nonconformance> {
    let contract_of = |bytes: &[u8]| -> Result<FatContractInstance, Nonconformance> {
        let (data, _) = unversioned_fat(bytes)?;
        FatContractInstance::decode(data.as_slice())
            .map_err(|e| Nonconformance::Malformed(e.to_string()))
    };
    let template_package = |fci: &FatContractInstance| -> Result<String, Nonconformance> {
        fci.template_id
            .as_ref()
            .map(|t| t.package_id.clone())
            .ok_or_else(|| Nonconformance::Malformed("a contract without a template".into()))
    };
    let data = &view.participant_data;
    let mut out = PartyPackages::new();
    match data
        .action_description
        .as_ref()
        .and_then(|a| a.description.as_ref())
    {
        Some(Description::Create(_)) => {
            for created in &data.created_core {
                let fci = contract_of(&created.contract)?;
                let package = BTreeSet::from([template_package(&fci)?]);
                add(&mut out, &stated_stakeholders(&fci), &package);
            }
        }
        Some(Description::Fetch(fetch)) => {
            let mut witnesses: BTreeSet<String> = fetch.actors.iter().cloned().collect();
            let mut packages = BTreeSet::new();
            for input in &data.core_inputs {
                let fci = contract_of(&input.contract)?;
                witnesses.extend(crate::view_conformance::stated_signatories(&fci));
                packages.insert(template_package(&fci)?);
            }
            // the template the fetch node names (an upgraded package under the same name), when the description states one
            if !fetch.template_id.is_empty() {
                packages = BTreeSet::from([package_of(&fetch.template_id)]);
            }
            add(&mut out, &witnesses, &packages);
        }
        _ => {}
    }
    Ok(out)
}

/// Checks that every participant hosting a party of `needed` vets the packages that party needs at `ledger_time`
/// (`UsableSynchronizers.checkRequiredPackagesByParty`); `Err` names, per participant, the packages it does not vet.
pub fn check_vetted(
    needed: &PartyPackages,
    hosts_of: &HostsOf,
    vetted_at: &VettedAt,
    ledger_time: i64,
) -> Result<(), String> {
    let mut by_participant: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (party, packages) in needed {
        // [CANTON-NOTE: LIMITATION] Mirrors `UsableSynchronizers.checkRequiredPackagesByParty`, which checks only active
        // hosting participants returned by `activeParticipantsOfParties`; rejecting unhosted non-confirming informees
        // (`UnknownInformees`) is a separate validator not yet implemented on the receiving side.
        let Some((_, hosts)) = hosts_of(party) else {
            continue;
        };
        for (uid, _) in hosts {
            by_participant
                .entry(uid)
                .or_default()
                .extend(packages.iter().cloned());
        }
    }
    let mut unvetted: Vec<String> = Vec::new();
    for (uid, required) in &by_participant {
        let vetted = vetted_at(uid, ledger_time).unwrap_or_default();
        let missing: Vec<&str> = required
            .iter()
            .filter(|p| !vetted.contains(*p))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            unvetted.push(format!("PAR::{uid} has not vetted {}", missing.join(", ")));
        }
    }
    if unvetted.is_empty() {
        return Ok(());
    }
    Err(format!(
        "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK: Rejected transaction due to a failed model conformance check: UnvettedPackages({})",
        unvetted.join("\n")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn hosts(party: &str) -> Option<(u32, Vec<(String, i32)>)> {
        match party {
            "alice" => Some((1, vec![("p1::n".into(), 1)])),
            "bob" => Some((1, vec![("p2::n".into(), 2), ("p3::n".into(), 3)])),
            _ => None,
        }
    }

    #[test]
    fn every_host_of_a_witness_must_vet_what_the_witness_needs() {
        let needed = PartyPackages::from([
            ("alice".to_string(), set(&["a"])),
            ("bob".to_string(), set(&["a", "b"])),
            ("nobody-hosts".to_string(), set(&["z"])),
        ]);
        let all = |_: &str, _: i64| Some(set(&["a", "b"]));
        assert_eq!(check_vetted(&needed, &hosts, &all, 0), Ok(()));
        // the observing host of bob (permission 3) counts too, and a host that vets nothing misses everything
        let p3_lacks_b = |uid: &str, _: i64| match uid {
            "p3::n" => Some(set(&["a"])),
            _ => Some(set(&["a", "b"])),
        };
        let why = check_vetted(&needed, &hosts, &p3_lacks_b, 0).unwrap_err();
        assert!(
            why.starts_with("LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK"),
            "{why}"
        );
        assert!(
            why.contains("UnvettedPackages(PAR::p3::n has not vetted b)"),
            "{why}"
        );
        let p1_vets_nothing = |uid: &str, _: i64| (uid != "p1::n").then(|| set(&["a", "b"]));
        let why = check_vetted(&needed, &hosts, &p1_vets_nothing, 0).unwrap_err();
        assert!(why.contains("PAR::p1::n has not vetted a"), "{why}");
    }

    #[test]
    fn the_vetting_is_read_at_the_ledger_time() {
        let needed = PartyPackages::from([("alice".to_string(), set(&["a"]))]);
        let from_ten = |_: &str, t: i64| Some(if t >= 10 { set(&["a"]) } else { set(&[]) });
        assert!(check_vetted(&needed, &hosts, &from_ten, 9).is_err());
        assert_eq!(check_vetted(&needed, &hosts, &from_ten, 10), Ok(()));
    }
}
