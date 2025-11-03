//! # Commitment Module
//!
//! Core state management primitives using cryptographic commitments and
//! trie-based storage.
//!
//! <img src="data:image/png;base64,
#![doc = include_str!("../../../docs/assets/foundation_module_system.base64")]
//! " alt="Validation Workflow Diagram" style="max-width: 100%; width: 1000px; height: auto; display: block; margin: 0 auto;">
use memory_db::{HashKey, MemoryDB};
use sha2::{Digest, Sha256};
use trie_db::{Hasher, TrieLayout};

pub mod atomic;
pub mod sorted;
pub mod trie;
//
mod node_codec;

// TODO: This should probably be somewhere else.
pub type MultisigId = u64;

/// Low-level alias for Parity's in-memory trie database.
type AliasMemoryDB = MemoryDB<CommitHasher, HashKey<CommitHasher>, Vec<u8>>;
/// Low-level alias for Parity's mutable database interface for state modifications.
type AliasFatDBMut<'db> = trie_db::FatDBMut<'db, CommitSchema>;

#[derive(Debug, Clone)]
pub struct CommitHasher {
    hasher: sha2::Sha256,
}

impl CommitHasher {
    /// The hashed null-node which Parity's `trie-db` requires to be inserted as
    /// a key pointing to the "null-node" into the database on initialization.
    /// This is essentially the _root_ of an empty database.
    ///
    /// ```rust
    /// // The null-node
    /// let value = [0u8];
    /// let key = CommitHahser::hash(&value);
    ///
    /// assert_eq!(key, CommitHasher::HASHED_NULL_NODE);
    /// ```
    //
    // See [`tests::commit_hasher_null_node`]
    pub const HASHED_NULL_NODE: [u8; 32] = [
        110, 52, 11, 156, 255, 179, 122, 152, 156, 165, 68, 230, 187, 120, 10, 44, 120, 144, 29,
        63, 179, 55, 56, 118, 133, 17, 163, 6, 23, 175, 160, 29,
    ];

    pub fn new(context: &[u8]) -> Self {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"botanix-foundation-layer-commit-hasher");
        hasher.update(context);

        CommitHasher { hasher }
    }
    pub fn append_message(&mut self, label: &[u8], msg: &[u8]) {
        self.hasher.update(label);
        self.hasher.update(msg);
    }
    pub fn append_u64(&mut self, label: &[u8], n: u64) {
        self.hasher.update(label);
        self.hasher.update(n.to_le_bytes());
    }
    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl Hasher for CommitHasher {
    type Out = [u8; 32];
    // We don't really need this:
    // > What to use to build `HashMap`s with this `Hasher`.
    type StdHasher = std::collections::hash_map::DefaultHasher;

    // The length in bytes of the `Hasher` output.
    const LENGTH: usize = 32;

    /// Compute the hash of the provided slice of bytes returning the `Out` type
    /// of the `Hasher`.
    // TODO: Use blake2?
    fn hash(data: &[u8]) -> Self::Out {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CommitSchema;

// Our default Trie layout.
impl TrieLayout for CommitSchema {
    const USE_EXTENSION: bool = false;
    const ALLOW_EMPTY: bool = true;
    // > Threshold above which an external node should be use to store a node value.
    const MAX_INLINE_VALUE: Option<u32> = None;

    type Hash = CommitHasher;
    type Codec = node_codec::NodeCodec<CommitHasher>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_hasher_null_node() {
        // The null-node
        let value = [0u8];
        let key = CommitHasher::hash(&value);

        assert_eq!(key, CommitHasher::HASHED_NULL_NODE);
    }
}
