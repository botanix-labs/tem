//! # Sorted Data Structure
//!
//! This module provides a sorted collection type that maintain deterministic
//! ordering for cryptographic state commitments. The sorted invariant ensures
//! consistent hash computation and serialization across different executions.
use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// A wrapper around `Vec<T>` that maintains items in sorted order for
/// deterministic operations.
///
/// This type ensures that collections maintain a consistent ordering across
/// different executions, which is essential for cryptographic state commitments
/// and consensus operations. The sorted invariant enables deterministic hashing
/// and serialization of collections.
///
/// # Usage
///
/// This type is primarily used in commitment operations where the order of
/// elements affects cryptographic computations. By maintaining sorted order,
/// the same set of elements will always produce the same hash regardless of
/// insertion order.
///
/// # Requirements
///
/// The contained type `T` must implement `Ord` to maintain the sorted
/// invariant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sorted<T>(Vec<T>);

// IMPORTANT: this type should NOT implement data-manipulation methods such as
// `push` directly! We want that the data is properly sorted and considered "final".
impl<T> Sorted<T>
where
    T: Ord,
{
    pub fn new(list: Vec<T>) -> Self {
        Self::from(list)
    }
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.0.to_vec()
    }
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T> From<Sorted<T>> for Vec<T> {
    fn from(value: Sorted<T>) -> Self {
        value.0
    }
}

impl<T> Default for Sorted<T> {
    fn default() -> Self {
        Self(vec![])
    }
}

impl<T> From<Vec<T>> for Sorted<T>
where
    T: Ord,
{
    fn from(mut list: Vec<T>) -> Self {
        // IMPORTANT: Sorting the list!
        list.sort();

        Sorted(list)
    }
}

impl<T> Deref for Sorted<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> AsRef<[T]> for Sorted<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T> AsRef<Vec<T>> for Sorted<T> {
    fn as_ref(&self) -> &Vec<T> {
        &self.0
    }
}

impl<T: Ord> PartialEq for Sorted<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Ord> Eq for Sorted<T> {}

impl<T: Ord> PartialOrd for Sorted<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Ord> Ord for Sorted<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<T> IntoIterator for Sorted<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Sorted<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: Ord> FromIterator<T> for Sorted<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Sorted::from(iter.into_iter().collect::<Vec<T>>())
    }
}
