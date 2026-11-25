//! Per-namespace authorization graphs (`AuthorizationGraph`, `DecentralizedNamespaceAuthorizationGraph`): the only place a key gains
//! the right to sign for a namespace.
//!
//! [CANTON-NOTE: SEMANTICS] A delegation is an edge from each key that signed it to its target key. The keys authorized for a namespace
//! are those reachable from the root certificate (the self-signed delegation to the key the namespace is the fingerprint of), descending
//! only through delegations whose restriction lets them sign further delegations. A key authorizes a mapping for the namespace only if
//! the delegation that reached it may sign that mapping's code. A decentralized namespace is authorized when the graphs of `threshold` of
//! its owners are.
use std::collections::{BTreeMap, BTreeSet};

use super::auth::Code;
use super::keys::Delegation;

/// The delegations of one namespace.
#[derive(Debug, Clone, Default)]
pub struct AuthorizationGraph {
    /// Target key fingerprint -> the delegation to it and the keys that signed it (the edges into the target).
    delegations: BTreeMap<String, (Delegation, BTreeSet<String>)>,
    /// The targets chained to the root certificate (recomputed on every change).
    authorized: BTreeSet<String>,
}

impl AuthorizationGraph {
    fn recompute(&mut self, namespace: &str) {
        self.authorized.clear();
        let root_signed_by_itself = self
            .delegations
            .get(namespace)
            .is_some_and(|(_, signed_by)| signed_by.contains(namespace));
        if !root_signed_by_itself {
            return;
        }
        let mut todo = vec![namespace.to_string()];
        self.authorized.insert(namespace.to_string());
        while let Some(key) = todo.pop() {
            let Some((delegation, _)) = self.delegations.get(&key) else {
                continue;
            };
            if !delegation.restriction.can_sign(Code::NamespaceDelegation) {
                continue;
            }
            for (target, (_, signed_by)) in &self.delegations {
                if signed_by.contains(&key) && self.authorized.insert(target.clone()) {
                    todo.push(target.clone());
                }
            }
        }
    }

    /// The keys among `signers` this namespace authorizes to sign a mapping of `code`.
    fn supporting<'a>(
        &'a self,
        signers: &'a BTreeSet<String>,
        code: Code,
    ) -> impl Iterator<Item = &'a String> + 'a {
        signers.iter().filter(move |fp| {
            self.authorized.contains(*fp)
                && self
                    .delegations
                    .get(*fp)
                    .is_some_and(|(d, _)| d.restriction.can_sign(code))
        })
    }
}

/// A decentralized namespace in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decentralized {
    pub threshold: usize,
    pub owners: BTreeSet<String>,
}

/// Every namespace's graph and every decentralized namespace in force.
#[derive(Debug, Clone, Default)]
pub struct Authorizations {
    graphs: BTreeMap<String, AuthorizationGraph>,
    decentralized: BTreeMap<String, Decentralized>,
}

impl Authorizations {
    /// `AuthorizationGraph.replace`: `delegation` signed by `signed_by` replaces any delegation to the same key in its namespace.
    pub fn replace(&mut self, delegation: Delegation, signed_by: BTreeSet<String>) {
        let namespace = delegation.namespace.clone();
        let graph = self.graphs.entry(namespace.clone()).or_default();
        graph.delegations.insert(
            delegation.target_fingerprint.clone(),
            (delegation, signed_by),
        );
        graph.recompute(&namespace);
    }

    /// `AuthorizationGraph.remove`: the delegation to `target` in `namespace` is revoked, and with it every key only it chained.
    pub fn remove(&mut self, namespace: &str, target: &str) {
        if let Some(graph) = self.graphs.get_mut(namespace) {
            graph.delegations.remove(target);
            graph.recompute(namespace);
        }
    }

    pub fn define_decentralized(&mut self, namespace: &str, definition: Decentralized) {
        self.decentralized.insert(namespace.to_string(), definition);
    }

    pub fn remove_decentralized(&mut self, namespace: &str) {
        self.decentralized.remove(namespace);
    }

    /// The keys among `signers` that count for `namespace` and `code` (`keysSupportingAuthorization`): for a decentralized namespace,
    /// those of any owner.
    pub fn supporting(
        &self,
        namespace: &str,
        signers: &BTreeSet<String>,
        code: Code,
    ) -> BTreeSet<String> {
        let owners: Vec<&str> = match self.decentralized.get(namespace) {
            Some(d) => d.owners.iter().map(String::as_str).collect(),
            None => vec![namespace],
        };
        owners
            .into_iter()
            .filter_map(|o| self.graphs.get(o))
            .flat_map(|g| g.supporting(signers, code))
            .cloned()
            .collect()
    }

    /// `existsAuthorizedKeyIn`: whether `signers` authorize a mapping of `code` for `namespace`.
    pub fn authorizes(&self, namespace: &str, signers: &BTreeSet<String>, code: Code) -> bool {
        let by_graph = |ns: &str| {
            self.graphs
                .get(ns)
                .is_some_and(|g| g.supporting(signers, code).next().is_some())
        };
        match self.decentralized.get(namespace) {
            Some(d) => d.owners.iter().filter(|o| by_graph(o)).count() >= d.threshold,
            None => by_graph(namespace),
        }
    }

    /// The key of `fingerprint`, if a delegation of any namespace names it: what a signature by it is verified with. Knowing a key
    /// gives it no right; [`Self::authorizes`] decides that.
    pub fn key(&self, fingerprint: &str) -> Option<&canton_algo::signing::PublicKey> {
        self.graphs
            .values()
            .find_map(|g| g.delegations.get(fingerprint))
            .map(|(d, _)| &d.target)
    }

    /// Whether `fingerprint` is chained to the root of `namespace` (whatever it may sign).
    #[cfg(test)]
    pub fn is_authorized_key(&self, namespace: &str, fingerprint: &str) -> bool {
        self.graphs
            .get(namespace)
            .is_some_and(|g| g.authorized.contains(fingerprint))
    }
}
