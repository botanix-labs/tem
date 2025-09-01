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

use super::{AliasFatDBMut, AliasMemoryDB, AliasTrieHash, CommitSchema, entry::Entry};
use trie_db::TrieMut;

/// Trie operation errors.
///
/// Distinguishes between logical constraint violations (which may indicate
/// malicious behavior) and backend infrastructure failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error<'a> {
    /// State modification violated trie consistency constraints.
    ///
    /// These errors indicate the attempted operation would create an invalid
    /// state or violate expected preconditions.
    Mod { entry: Entry<'a>, kind: ErrorKind },
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

impl<'a> From<trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>> for Error<'a> {
    fn from(err: trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>) -> Self {
        Error::Fatal(err)
    }
}

impl<'a> From<Box<trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>>> for Error<'a> {
    fn from(err: Box<trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>>) -> Self {
        Error::Fatal(*err)
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

impl<'db> From<(&'db mut AliasMemoryDB, &'db mut AliasTrieHash)> for TrieLayer<'db> {
    fn from(value: (&'db mut AliasMemoryDB, &'db mut AliasTrieHash)) -> Self {
        let (db, root) = value;
        let fat = AliasFatDBMut::from_existing(db, root);
        Self::from(fat)
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
    pub fn insert_non_existing<'b>(&mut self, entry: Entry<'b>) -> Result<(), Error<'b>> {
        let (key, val) = entry.as_key_value();

        if self.trie.contains(key.as_ref())? {
            return Err(Error::Mod {
                entry,
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
    pub fn update_existing<'b>(
        &mut self,
        new: Entry<'b>,
        previous: Entry<'b>,
    ) -> Result<(), Error<'b>> {
        let (key, val) = new.as_key_value();
        let (prev_key, prev_val) = previous.as_key_value();

        if key != prev_key {
            return Err(Error::Mod {
                entry: previous,
                kind: ErrorKind::UpdateBadPrevKey,
            });
        }

        let retrieved: [u8; 32] = self
            .trie
            .get(key.as_ref())?
            .ok_or(Error::Mod {
                entry: previous,
                kind: ErrorKind::UpdateNotExist,
            })?
            .try_into()
            .expect("value must be 32 bytes");

        if retrieved != prev_val.as_ref() {
            return Err(Error::Mod {
                entry: previous,
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
    pub fn remove_existing<'b>(&mut self, entry: Entry<'b>) -> Result<(), Error<'b>> {
        let (key, val) = entry.as_key_value();

        let retrieved: [u8; 32] = self
            .trie
            .get(key.as_ref())?
            .ok_or(Error::Mod {
                entry,
                kind: ErrorKind::RemoveNotExist,
            })?
            .try_into()
            .expect("value must be 32-bytes");

        if retrieved != val.as_ref() {
            return Err(Error::Mod {
                entry,
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
    pub fn ensure_existing<'b>(&self, entry: Entry<'b>) -> Result<(), Error<'b>> {
        let (key, val) = entry.as_key_value();

        let retrieved: [u8; 32] = self
            .trie
            .get(key.as_ref())?
            .ok_or(Error::Mod {
                entry,
                kind: ErrorKind::EnsureExistsNotExist,
            })?
            .try_into()
            .expect("value must be 32-bytes");

        if retrieved == val.as_ref() {
            Ok(())
        } else {
            Err(Error::Mod {
                entry,
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
    pub fn ensure_non_existing<'b>(&self, entry: Entry<'b>) -> Result<(), Error<'b>> {
        let (key, val) = entry.as_key_value();

        let Some(res) = self.trie.get(key.as_ref())? else {
            return Ok(());
        };

        let retrieved: [u8; 32] = res.try_into().expect("value must be 32-bytes");

        if retrieved == val.as_ref() {
            Err(Error::Mod {
                entry,
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
    pub fn root(&mut self) -> &AliasTrieHash {
        self.trie.root()
    }
}
