//! The list value of the evaluator: an immutable singly linked list that shares its tails (U-15).
//!
//! [CANTON-NOTE: WHY] A Daml list is consumed and built one element at a time (`case xs of x :: tl`, `f x :: map f tl`). With
//! `Vec<Value>` both steps copied everything that remained, so a recursion over n elements cost O(n²) and a nested `map` over
//! 8,000 elements took 3 s. Here the tail of a list is the list itself behind a shared pointer (O(1)), and consing an element
//! onto a list is O(1) too. The price is that indexing is O(i) and `len` is O(1) only because each node keeps its length.
use std::sync::Arc;

use crate::Value;

struct Node {
    head: Value,
    tail: List,
    len: usize,
}

/// An immutable list of values; cloning it is O(1) and so is taking its tail.
#[derive(Clone, Default)]
pub struct List(Option<Arc<Node>>);

impl List {
    pub fn new() -> Self {
        Self(None)
    }

    /// `head :: tail`.
    pub fn cons(head: Value, tail: List) -> Self {
        let len = tail.len() + 1;
        Self(Some(Arc::new(Node { head, tail, len })))
    }

    pub fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |n| n.len)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    /// The first element and the rest (both O(1)), `None` for the empty list.
    pub fn uncons(&self) -> Option<(&Value, &List)> {
        self.0.as_ref().map(|n| (&n.head, &n.tail))
    }

    pub fn first(&self) -> Option<&Value> {
        self.uncons().map(|(h, _)| h)
    }

    /// The element at `index` (O(index)).
    pub fn get(&self, index: usize) -> Option<&Value> {
        self.iter().nth(index)
    }

    pub fn iter(&self) -> Iter<'_> {
        Iter {
            next: self.0.as_deref(),
        }
    }

    pub fn to_vec(&self) -> Vec<Value> {
        self.iter().cloned().collect()
    }

    /// `front ++ self` without copying `self`.
    pub fn prepend_all(self, front: Vec<Value>) -> List {
        front
            .into_iter()
            .rev()
            .fold(self, |tail, head| List::cons(head, tail))
    }
}

pub struct Iter<'a> {
    next: Option<&'a Node>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<&'a Value> {
        let node = self.next?;
        self.next = node.tail.0.as_deref();
        Some(&node.head)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.next.map_or(0, |n| n.len);
        (n, Some(n))
    }
}

impl ExactSizeIterator for Iter<'_> {}

impl<'a> IntoIterator for &'a List {
    type Item = &'a Value;
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl From<Vec<Value>> for List {
    fn from(items: Vec<Value>) -> Self {
        List::new().prepend_all(items)
    }
}

impl FromIterator<Value> for List {
    fn from_iter<I: IntoIterator<Item = Value>>(iter: I) -> Self {
        iter.into_iter().collect::<Vec<_>>().into()
    }
}

impl PartialEq for List {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl std::fmt::Debug for List {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl Drop for List {
    /// Dropping a long list must not recurse once per element (it would overflow the stack): unlink the nodes one by one for
    /// as long as this list is their only owner.
    fn drop(&mut self) {
        let mut next = self.0.take();
        while let Some(node) = next {
            match Arc::try_unwrap(node) {
                Ok(mut n) => next = n.tail.0.take(),
                Err(_) => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ints(n: i64) -> List {
        (0..n).map(Value::Int64).collect()
    }

    #[test]
    fn a_list_round_trips_and_shares_its_tail() {
        let xs = ints(5);
        assert_eq!(xs.len(), 5);
        assert_eq!(xs.to_vec(), (0..5).map(Value::Int64).collect::<Vec<_>>());
        let (head, tail) = xs.uncons().unwrap();
        assert_eq!(head, &Value::Int64(0));
        assert_eq!(tail.len(), 4);
        // consing onto a shared tail leaves the other list alone
        let ys = List::cons(Value::Int64(9), tail.clone());
        assert_eq!(ys.len(), 5);
        assert_eq!(xs.get(1), ys.get(1));
        assert_eq!(xs.get(0), Some(&Value::Int64(0)));
        assert!(List::new().is_empty() && List::new().uncons().is_none());
    }

    #[test]
    fn equality_is_elementwise() {
        assert_eq!(ints(3), ints(3));
        assert_ne!(ints(3), ints(4));
        assert_ne!(
            ints(3),
            List::from(vec![Value::Int64(0), Value::Int64(1), Value::Int64(5)])
        );
    }

    #[test]
    fn a_very_long_list_can_be_built_walked_and_dropped() {
        let xs = ints(1_000_000);
        assert_eq!(xs.len(), 1_000_000);
        assert_eq!(xs.iter().count(), 1_000_000);
        drop(xs); // must not overflow the stack
    }
}
