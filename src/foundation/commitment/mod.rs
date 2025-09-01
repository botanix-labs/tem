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

pub mod botanix;
pub mod entry;
pub mod sorted;
pub mod storage;
pub mod trie;
//
mod node_codec;

// TODO: This should probably be somewhere else.
pub type MultisigId = u64;

/// Low-level alias for Parity's in-memory trie database.
pub type AliasMemoryDB = MemoryDB<CommitHasher, HashKey<CommitHasher>, Vec<u8>>;
/// Low-level alias for Parity's trie hash computation.
pub type AliasTrieHash = trie_db::TrieHash<CommitSchema>;
/// Low-level alias for Parity's mutable database interface for state modifications.
pub type AliasFatDBMut<'db> = trie_db::FatDBMut<'db, CommitSchema>;

/// A 32-byte cryptographic commitment to a trie state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentStateRoot([u8; 32]);

impl AsRef<[u8; 32]> for CommitmentStateRoot {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CommitHasher;

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
