//! Expression variable environments (`Env`, `EnvIter`) and type environments.

use crate::value::Value;

/// Term variable bindings, newest first: a persistent list whose tail is **shared**, so cloning an environment (every closure does)
/// costs O(1) and a value bound once is stored once.
///
/// [CANTON-NOTE: WHY] This used to be a `Vec<(String, Value)>` copied by value. A closure captures its environment, and the
/// environments of `Script`'s type-class dictionaries hold closures that hold each other's environments, so every copy duplicated
/// the whole graph: `mapA` over n elements cost about 4^n in time and memory (3 elements 0.13 s, 6 elements 8.6 s, 12 never ended).
/// Speedy shares values by pointer; so does this.
#[derive(Clone, Default)]
pub struct Env(Option<std::sync::Arc<EnvNode>>);

struct EnvNode {
    name: String,
    value: Value,
    next: Env,
}

impl Env {
    pub fn new() -> Self {
        Self(None)
    }

    /// Binds `name` to `value` in front of the existing bindings (it shadows an older binding of the same name).
    pub fn push(&mut self, (name, value): (String, Value)) {
        let next = std::mem::take(self);
        *self = Self(Some(std::sync::Arc::new(EnvNode { name, value, next })));
    }

    /// The bindings, newest first.
    pub fn iter(&self) -> EnvIter<'_> {
        EnvIter(self.0.as_deref())
    }

    pub fn clear(&mut self) {
        self.0 = None;
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    /// The value bound to `name` (the newest binding).
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.iter().find(|(n, _)| *n == name).map(|(_, v)| v)
    }
}

pub struct EnvIter<'a>(Option<&'a EnvNode>);

impl<'a> Iterator for EnvIter<'a> {
    type Item = (&'a str, &'a Value);
    fn next(&mut self) -> Option<Self::Item> {
        let node = self.0?;
        self.0 = node.next.0.as_deref();
        Some((node.name.as_str(), &node.value))
    }
}

impl From<Vec<(String, Value)>> for Env {
    /// Later elements shadow earlier ones, as in the vector the environment used to be.
    fn from(bindings: Vec<(String, Value)>) -> Self {
        let mut env = Env::new();
        for binding in bindings {
            env.push(binding);
        }
        env
    }
}

impl std::fmt::Debug for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl PartialEq for Env {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Some(a), Some(b)) if std::sync::Arc::ptr_eq(a, b) => true,
            _ => self.iter().eq(other.iter()),
        }
    }
}

impl Drop for Env {
    /// Drops a long chain iteratively: the recursive default would overflow the stack on a deep environment.
    fn drop(&mut self) {
        let mut next = self.0.take();
        while let Some(node) = next {
            match std::sync::Arc::try_unwrap(node) {
                Ok(mut node) => next = node.next.0.take(),
                Err(_) => break,
            }
        }
    }
}

/// Type variable bindings: variable name to the canonical key of the type bound to it (see `Machine::type_key`).
pub type TypeEnv = Vec<(String, String)>;
