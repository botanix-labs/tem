//! # Low-Level Trie Operations
//!
//! This module provides the foundational trie operations with strong
//! consistency guarantees for the state commitment system. It implements
//! operations that ensure state transitions maintain cryptographic integrity
//! and prevent invalid modifications.
//!
//! ## Operation Types
//!
//! All operations require exact value matching to prevent state corruption:
//! - **Insert**: Add new entries that must not already exist
//! - **Update**: Modify existing entries with previous value verification
//! - **Remove**: Delete entries with exact value confirmation
//! - **Ensure**: Validate entry existence/absence without modification
//!
//! ## Consistency Guarantees
//!
//! The trie layer enforces strict consistency rules that prevent common attack
//! vectors in state management systems, including double-spending prevention
//! and unauthorized state modifications.
use super::{AliasFatDBMut, CommitSchema};
use trie_db::TrieMut;

/// Trie operation errors.
///
/// Distinguishes between logical constraint violations (which may indicate
/// malicious behavior) and backend infrastructure failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// State modification violated trie consistency constraints.
    ///
    /// These errors indicate the attempted operation would create an invalid
    /// state or violate expected preconditions.
    Mod {
        partition: &'static str,
        kind: ErrorKind,
    },
    /// Backend trie database failure.
    ///
    /// Represents infrastructure issues rather than logical errors.
    // TODO: Use alias
    Fatal(trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>),
}

/// Specific types of trie consistency violations.
///
/// Each variant represents a different type of precondition failure that
/// prevents the requested operation from completing safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Attempted to insert an entry that already exists.
    InsertDoesExist,
    /// Attempted to update an entry that doesn't exist.
    UpdateNotExist,
    /// Update operation specified wrong previous key.
    UpdateBadPrevKey,
    /// Update operation specified wrong previous value.
    UpdateBadPrevValue,
    /// Attempted to remove an entry that doesn't exist.
    RemoveNotExist,
    /// Remove operation specified wrong value for existing entry.
    RemoveBadValue,
    /// Expected entry to exist but it was not found.
    EnsureExistsNotExist,
    /// Expected entry exists but has wrong value.
    EnsureExistsBadValue,
    /// Expected entry to not exist but it was found.
    EnsureNotExistsDoesExist,
}

impl From<trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>> for Error {
    fn from(err: trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>) -> Self {
        Error::Fatal(err)
    }
}

impl From<Box<trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>>> for Error {
    fn from(err: Box<trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>>) -> Self {
        Error::Fatal(*err)
    }
}

pub trait EntryT {
    /// Computes the cryptographic commitment for this entry's key.
    ///
    /// Uses Merlin transcript with domain separation by entry type to ensure
    /// keys from different tables cannot collide even with identical input
    /// data.
    fn as_key(&self) -> StorageKey;
    /// Computes the cryptographic commitment for this entry's value.
    ///
    /// Creates a deterministic hash of the entry's value data that can be used
    /// for efficient equality comparisons in the trie.
    fn as_value(&self) -> StorageValue;
    /// Returns both the key and value commitments for this entry.
    fn as_key_value(&self) -> (StorageKey, StorageValue) {
        (self.as_key(), self.as_value())
    }
    fn partition_name(&self) -> &'static str;
}

/// 32-byte cryptographic commitment to a trie entry key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageKey([u8; 32]);

impl AsRef<[u8]> for StorageKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for StorageKey {
    fn from(value: [u8; 32]) -> Self {
        StorageKey(value)
    }
}

/// 32-byte cryptographic commitment to a trie entry value.  
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageValue([u8; 32]);

impl AsRef<[u8]> for StorageValue {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for StorageValue {
    fn from(value: [u8; 32]) -> Self {
        StorageValue(value)
    }
}

/// A 32-byte cryptographic commitment to a trie state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentStateRoot([u8; 32]);

impl AsRef<[u8; 32]> for CommitmentStateRoot {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Low-level interface to the cryptographic trie backend.
///
/// Provides operations with strong consistency guarantees. All modifications
/// require exact value matching to prevent unauthorized state changes and
/// ensure operation safety.
pub struct TrieLayer<'db> {
    /*PRIVATE*/ trie: AliasFatDBMut<'db>,
}

impl<'db> From<AliasFatDBMut<'db>> for TrieLayer<'db> {
    fn from(trie: AliasFatDBMut<'db>) -> Self {
        Self { trie }
    }
}

impl<'db> TrieLayer<'db> {
    /// Inserts a new entry that must not already exist.
    ///
    /// Checks for entry absence and inserts if safe. This prevents accidental
    /// overwrites and double-entry creation.
    ///
    /// # Errors
    ///
    /// Returns `InsertDoesExist` if an entry with the same key already exists.
    // TODO: Rename lifetime to 'a
    pub fn insert_non_existing<E: EntryT>(&mut self, entry: &E) -> Result<(), Error> {
        let (key, val) = entry.as_key_value();

        if self.trie.contains(key.as_ref())? {
            return Err(Error::Mod {
                partition: entry.partition_name(),
                kind: ErrorKind::InsertDoesExist,
            });
        }

        self.trie.insert(key.as_ref(), val.as_ref())?;

        Ok(())
    }
    /// Updates an existing entry with previous value verification.
    ///
    /// Performs mic read-verify-write to ensure the previous value matches
    /// expectations before applying the update.
    ///
    /// # Arguments
    ///
    /// * `new` - The new entry data to store
    /// * `previous` - The expected current entry data (must match exactly)
    ///
    /// # Errors
    ///
    /// - `UpdateBadPrevKey` if the keys don't match
    /// - `UpdateNotExist` if no entry exists at the key
    /// - `UpdateBadPrevValue` if the existing value doesn't match expected
    pub fn update_existing<E: EntryT>(&mut self, new: &E, previous: &E) -> Result<(), Error> {
        let (key, val) = new.as_key_value();
        let (prev_key, prev_val) = previous.as_key_value();

        if key != prev_key {
            return Err(Error::Mod {
                partition: new.partition_name(),
                // TODO: This is the wrong kind!
                kind: ErrorKind::UpdateBadPrevKey,
            });
        }

        let retrieved: [u8; 32] = self
            .trie
            .get(key.as_ref())?
            .ok_or(Error::Mod {
                partition: new.partition_name(),
                kind: ErrorKind::UpdateNotExist,
            })?
            .try_into()
            .expect("value must be 32 bytes");

        if retrieved != prev_val.as_ref() {
            return Err(Error::Mod {
                partition: new.partition_name(),
                kind: ErrorKind::UpdateBadPrevValue,
            });
        }

        // TODO: Check previous value here instead?
        let p = self.trie.insert(key.as_ref(), val.as_ref())?;
        debug_assert!(p.is_some());

        Ok(())
    }
    /// Removes an existing entry with exact value verification.
    ///
    /// Confirms the entry exists with the expected value before removal.
    ///
    /// # Errors
    ///
    /// - `RemoveNotExist` if no entry exists at the key
    /// - `RemoveBadValue` if the existing value doesn't match expected
    pub fn remove_existing<E: EntryT>(&mut self, entry: &E) -> Result<(), Error> {
        let (key, val) = entry.as_key_value();

        let retrieved: [u8; 32] = self
            .trie
            .get(key.as_ref())?
            .ok_or(Error::Mod {
                partition: entry.partition_name(),
                kind: ErrorKind::RemoveNotExist,
            })?
            .try_into()
            .expect("value must be 32-bytes");

        if retrieved != val.as_ref() {
            return Err(Error::Mod {
                partition: entry.partition_name(),
                kind: ErrorKind::RemoveBadValue,
            });
        }

        // TODO: Check previous value here instead?
        let p = self.trie.remove(key.as_ref())?;
        debug_assert!(p.is_some());

        Ok(())
    }
    /// Validates that an entry exists with the expected value.
    ///
    /// Non-mutating operation that confirms entry presence and correctness
    /// without making any changes.
    ///
    /// # Errors
    ///
    /// - `EnsureExistsNotExist` if no entry exists at the key
    /// - `EnsureExistsBadValue` if entry exists but has wrong value
    pub fn ensure_existing<E: EntryT>(&self, entry: &E) -> Result<(), Error> {
        let (key, val) = entry.as_key_value();

        let retrieved: [u8; 32] = self
            .trie
            .get(key.as_ref())?
            .ok_or(Error::Mod {
                partition: entry.partition_name(),
                kind: ErrorKind::EnsureExistsNotExist,
            })?
            .try_into()
            .expect("value must be 32-bytes");

        if retrieved == val.as_ref() {
            Ok(())
        } else {
            Err(Error::Mod {
                partition: entry.partition_name(),
                kind: ErrorKind::EnsureExistsBadValue,
            })
        }
    }
    /// Validates that an entry does not exist or has a different value.
    ///
    /// Non-mutating operation that confirms entry absence or ensures it
    /// doesn't match the specified value.
    ///
    /// # Errors
    ///
    /// Returns `EnsureNotExistsDoesExist` if an entry with the exact
    /// key and value already exists.
    pub fn ensure_non_existing<E: EntryT>(&self, entry: &E) -> Result<(), Error> {
        let (key, val) = entry.as_key_value();

        let Some(res) = self.trie.get(key.as_ref())? else {
            return Ok(());
        };

        let retrieved: [u8; 32] = res.try_into().expect("value must be 32-bytes");

        if retrieved == val.as_ref() {
            Err(Error::Mod {
                partition: entry.partition_name(),
                kind: ErrorKind::EnsureNotExistsDoesExist,
            })
        } else {
            Ok(())
        }
    }
    /// Returns the current trie root hash.
    ///
    /// The root hash represents the cryptographic commitment to all
    /// data in the trie and changes with any modification.
    pub fn root(&mut self) -> CommitmentStateRoot {
        let root: [u8; 32] = *self.trie.root();
        CommitmentStateRoot(root)
    }
}
