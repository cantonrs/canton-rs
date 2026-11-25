//! Daml Package Dependency Graph & Cycle Detection.
//!
//! Enforces:
//! - Package dependency resolution across multi-package DAR archives (AT-A03)
//! - Missing dependency detection and error reporting (AT-A03, AT-A07)
//! - Cycle detection in package import graphs via 3-color DFS (AT-A07)
//! - Topological ordering of packages for load/evaluation pipeline

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    CyclicDependency { cycle: Vec<String> },
    MissingPackageDependency { referrer: String, missing: String },
    UnknownPackage(String),
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CyclicDependency { cycle } => {
                write!(
                    f,
                    "cyclic package dependency detected: {}",
                    cycle.join(" -> ")
                )
            }
            Self::MissingPackageDependency { referrer, missing } => {
                write!(f, "package {referrer} depends on missing package {missing}")
            }
            Self::UnknownPackage(pkg) => write!(f, "unknown package id: {pkg}"),
        }
    }
}

impl std::error::Error for GraphError {}

/// Directed package dependency graph.
#[derive(Debug, Clone, Default)]
pub struct PackageDependencyGraph {
    /// Maps package_id to the set of package_ids it directly depends on.
    dependencies: HashMap<String, HashSet<String>>,
}

impl PackageDependencyGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a package and its direct dependencies.
    pub fn add_package(&mut self, package_id: impl Into<String>, deps: HashSet<String>) {
        self.dependencies.insert(package_id.into(), deps);
    }

    /// Checks if all referenced dependencies are present in the graph (AT-A03).
    pub fn validate_dependencies(&self) -> Result<(), GraphError> {
        for (pkg, deps) in &self.dependencies {
            for dep in deps {
                if !self.dependencies.contains_key(dep) {
                    return Err(GraphError::MissingPackageDependency {
                        referrer: pkg.clone(),
                        missing: dep.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Detects cycles using DFS (3-color marking) and validates DAG invariants (AT-A07).
    pub fn detect_cycles(&self) -> Result<(), GraphError> {
        // 0: Unvisited, 1: Visiting (in current recursion stack), 2: Visited
        let mut state: HashMap<&str, u8> = HashMap::new();
        let mut path: Vec<String> = Vec::new();

        for pkg in self.dependencies.keys() {
            if state.get(pkg.as_str()).copied().unwrap_or(0) == 0 {
                self.dfs_cycle(pkg, &mut state, &mut path)?;
            }
        }

        Ok(())
    }

    fn dfs_cycle<'a>(
        &'a self,
        node: &'a str,
        state: &mut HashMap<&'a str, u8>,
        path: &mut Vec<String>,
    ) -> Result<(), GraphError> {
        state.insert(node, 1);
        path.push(node.to_string());

        if let Some(deps) = self.dependencies.get(node) {
            for dep in deps {
                let dep_state = state.get(dep.as_str()).copied().unwrap_or(0);
                if dep_state == 1 {
                    // Cycle detected!
                    let mut cycle = path.clone();
                    cycle.push(dep.clone());
                    return Err(GraphError::CyclicDependency { cycle });
                } else if dep_state == 0 && self.dependencies.contains_key(dep) {
                    self.dfs_cycle(dep, state, path)?;
                }
            }
        }

        path.pop();
        state.insert(node, 2);
        Ok(())
    }

    /// Returns packages in topological order (dependencies first) (AT-A03).
    pub fn topological_sort(&self) -> Result<Vec<String>, GraphError> {
        self.validate_dependencies()?;
        self.detect_cycles()?;

        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        for pkg in self.dependencies.keys() {
            in_degree.entry(pkg.as_str()).or_insert(0);
        }

        // Count how many dependents each package has (or edges: u -> v where u depends on v)
        // For topological order where dependencies come first:
        // edge: dep -> pkg
        let mut dep_to_dependents: HashMap<&str, Vec<&str>> = HashMap::new();
        for (pkg, deps) in &self.dependencies {
            for dep in deps {
                dep_to_dependents
                    .entry(dep.as_str())
                    .or_default()
                    .push(pkg.as_str());
                *in_degree.entry(pkg.as_str()).or_insert(0) += 1;
            }
        }

        let mut queue: Vec<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&pkg, _)| pkg)
            .collect();
        queue.sort(); // Deterministic sort order

        let mut sorted = Vec::with_capacity(self.dependencies.len());
        while let Some(node) = queue.pop() {
            sorted.push(node.to_string());

            if let Some(dependents) = dep_to_dependents.get(node) {
                for &dependent in dependents {
                    if let Some(deg) = in_degree.get_mut(dependent) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(dependent);
                            queue.sort();
                        }
                    }
                }
            }
        }

        if sorted.len() != self.dependencies.len() {
            return Err(GraphError::CyclicDependency {
                cycle: vec!["unresolvable cycle".into()],
            });
        }

        Ok(sorted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_at_a03_valid_dag_topological_sort() {
        let mut graph = PackageDependencyGraph::new();
        // A -> B -> C
        let mut a_deps = HashSet::new();
        a_deps.insert("pkg_B".into());
        graph.add_package("pkg_A", a_deps);

        let mut b_deps = HashSet::new();
        b_deps.insert("pkg_C".into());
        graph.add_package("pkg_B", b_deps);

        graph.add_package("pkg_C", HashSet::new());

        let sorted = graph.topological_sort().expect("DAG should sort cleanly");
        assert_eq!(sorted, vec!["pkg_C", "pkg_B", "pkg_A"]);
    }

    #[test]
    fn test_at_a07_cycle_detection() {
        let mut graph = PackageDependencyGraph::new();
        // A -> B -> C -> A
        let mut a_deps = HashSet::new();
        a_deps.insert("pkg_B".into());
        graph.add_package("pkg_A", a_deps);

        let mut b_deps = HashSet::new();
        b_deps.insert("pkg_C".into());
        graph.add_package("pkg_B", b_deps);

        let mut c_deps = HashSet::new();
        c_deps.insert("pkg_A".into());
        graph.add_package("pkg_C", c_deps);

        let res = graph.detect_cycles();
        assert!(matches!(res, Err(GraphError::CyclicDependency { .. })));
    }

    #[test]
    fn test_at_a03_missing_dependency() {
        let mut graph = PackageDependencyGraph::new();
        let mut a_deps = HashSet::new();
        a_deps.insert("pkg_nonexistent".into());
        graph.add_package("pkg_A", a_deps);

        let res = graph.validate_dependencies();
        assert_eq!(
            res,
            Err(GraphError::MissingPackageDependency {
                referrer: "pkg_A".into(),
                missing: "pkg_nonexistent".into(),
            })
        );
    }
}
