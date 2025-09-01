//! # Commitment Entry System
//!
//! This module defines the entry types and cryptographic commitment scheme used
//! by the state trie. Each entry represents a specific type of state data with
//! domain-separated keys and cryptographically committed values.
//!
//! ## Entry Types
//!
//! The system tracks five distinct entry types, each with different key
//! structures:
//!
//! - **Initiated**: `(multisig_id, pegout_id) -> pegout_data` - Pegouts available for spending
//! - **Pending**: `pegout_id -> pegout_data` - Pegouts included in registered transactions
//! - **Delayed**: `pegout_id -> pegout_data` - Pegouts from orphaned blocks, respendable
//! - **Txid**: `block_hash -> [txid_list]` - Transaction IDs tracked per Bitcoin block
//! - **Register**: `txid -> [pegout_list]` - Pegouts associated with each transaction
//!
//! ## Cryptographic Commitment
//!
//! All keys and values are deterministically hashed using Merlin transcripts
//! with domain separation to prevent collision attacks between different entry
//! types. The commitment scheme ensures:
//!
//! - **Collision Resistance**: Different entry types cannot produce the same key
//! - **Deterministic Hashing**: Identical data always produces identical commitments
//! - **Cryptographic Security**: Based on transcript-based domain separation
use super::sorted::Sorted;
use crate::{
    foundation::commitment::MultisigId,
    validation::pegout::{PegoutData, PegoutId, PegoutWithId},
};
use bitcoin::{BlockHash, Txid, hashes::Hash};
use merlin::Transcript;
use std::fmt::Debug;

const T_INITIATED: &[u8] = b"initiated";
const T_PENDING: &[u8] = b"pending";
const T_DELAYED: &[u8] = b"delayed";
const T_BLOCK_TXIDS: &[u8] = b"block_txids";
const T_TXID_PEGOUTS: &[u8] = b"txid_pegouts";

/// Trie entry representing different types of Foundation state data.
///
/// Each variant corresponds to a specific state table in the commitment trie.
/// The key structure varies by entry type to support efficient lookups and
/// state transitions.
///
/// # Key Structures
///
/// - `Initiated`: Composite key of multisig ID and pegout ID for scoped pegout ownership
/// - `Pending`/`Delayed`: Simple pegout ID key for direct pegout lookups  
/// - `BlockTxids`: Block hash key for retrieving all Bitcoin transactions in a block
/// - `TxidPegouts`: Bitcoin transaction ID for retrieving associated pegouts
//
// TODO: Rethink the `multisig+pegout_id` approach; harder to do lookups.
// TODO: multisig->txid lookup?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry<'a> {
    Initiated {
        k: (&'a MultisigId, &'a PegoutId),
        v: &'a PegoutData,
    },
    Pending {
        k: &'a PegoutId,
        v: &'a PegoutData,
    },
    Delayed {
        k: &'a PegoutId,
        v: &'a PegoutData,
    },
    BlockTxids {
        k: &'a BlockHash,
        v: &'a Sorted<Txid>,
    },
    TxidPegouts {
        k: &'a Txid,
        v: &'a Sorted<PegoutWithId>,
    },
}

/// 32-byte cryptographic commitment to a trie entry key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageKey([u8; 32]);

impl AsRef<[u8]> for StorageKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
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

impl<'a> Entry<'a> {
    /// Computes the cryptographic commitment for this entry's key.
    ///
    /// Uses Merlin transcript with domain separation by entry type to ensure
    /// keys from different tables cannot collide even with identical input
    /// data.
    pub fn as_key(&self) -> StorageKey {
        let mut key = [0; 32];
        let mut t = Transcript::new(b"botanix-foundation-layer");

        match self {
            Entry::Initiated { k, .. } => {
                t.append_message(b"table", T_INITIATED);
                let (multisig, pegout_id) = k;
                multisig.append_to_transcript(&mut t);
                pegout_id.append_to_transcript(&mut t);
            }
            Entry::Pending { k, .. } => {
                t.append_message(b"table", T_PENDING);
                k.append_to_transcript(&mut t);
            }
            Entry::Delayed { k, .. } => {
                t.append_message(b"table", T_DELAYED);
                k.append_to_transcript(&mut t);
            }
            Entry::BlockTxids { k, .. } => {
                t.append_message(b"table", T_BLOCK_TXIDS);
                k.append_to_transcript(&mut t);
            }
            Entry::TxidPegouts { k, .. } => {
                t.append_message(b"table", T_TXID_PEGOUTS);
                k.append_to_transcript(&mut t);
            }
        }

        t.challenge_bytes(b"key", &mut key);
        debug_assert_ne!(key, [0; 32]);
        StorageKey(key)
    }

    /// Computes the cryptographic commitment for this entry's value.
    ///
    /// Creates a deterministic hash of the entry's value data that can be used
    /// for efficient equality comparisons in the trie.
    pub fn as_value(&self) -> StorageValue {
        let mut value = [0; 32];
        let mut t = Transcript::new(b"botanix-foundation-layer");

        match self {
            Entry::Initiated { v, .. } => v.append_to_transcript(&mut t),
            Entry::Pending { v, .. } => v.append_to_transcript(&mut t),
            Entry::Delayed { v, .. } => v.append_to_transcript(&mut t),
            Entry::BlockTxids { v, .. } => v.append_to_transcript(&mut t),
            Entry::TxidPegouts { v, .. } => v.append_to_transcript(&mut t),
        }

        t.challenge_bytes(b"value", &mut value);
        debug_assert_ne!(value, [0; 32]);
        StorageValue(value)
    }

    /// Returns both the key and value commitments for this entry.
    pub fn as_key_value(&self) -> (StorageKey, StorageValue) {
        (self.as_key(), self.as_value())
    }
}

/// Convenience trait for types that can be committed to a Merlin transcript.
pub trait ToTranscript {
    /// Appends this type's data to the given transcript.
    ///
    /// Must be deterministic - identical values must produce identical
    /// transcript modifications across all implementations.
    fn append_to_transcript(&self, t: &mut Transcript);
}

impl ToTranscript for MultisigId {
    fn append_to_transcript(&self, t: &mut Transcript) {
        t.append_u64(b"botanix:multisig_id", *self);
    }
}

impl ToTranscript for Txid {
    fn append_to_transcript(&self, t: &mut Transcript) {
        t.append_message(b"bitcoin:txid", self.as_raw_hash().as_byte_array());
    }
}

impl ToTranscript for bitcoin::BlockHash {
    fn append_to_transcript(&self, t: &mut Transcript) {
        t.append_message(b"bitcoin:block_hash", self.as_raw_hash().as_byte_array());
    }
}

impl ToTranscript for bitcoin::network::Network {
    fn append_to_transcript(&self, t: &mut Transcript) {
        let b: u64 = match self {
            bitcoin::Network::Bitcoin => 0,
            bitcoin::Network::Testnet => 1,
            bitcoin::Network::Signet => 2,
            bitcoin::Network::Regtest => 3,
            // From the `bitcoin` crate:
            //
            // > Bitcoin's testnet4 network. (In future versions this will be
            // > combined into a single variant containing the version)
            //
            // ¯\_(ツ)_/¯
            bitcoin::Network::Testnet4 => 4,
        };
        t.append_u64(b"bitcoin:network", b);
    }
}

impl ToTranscript for PegoutId {
    fn append_to_transcript(&self, t: &mut Transcript) {
        // Deconstruct so we do not miss anything accidentally.
        let PegoutId { tx_hash, log_idx } = self;

        t.append_message(b"pegout:tx_hash", tx_hash.as_slice());
        t.append_u64(b"pegout:log_idx", *log_idx as u64);
    }
}

impl ToTranscript for PegoutData {
    fn append_to_transcript(&self, t: &mut Transcript) {
        // Deconstruct so we do not miss anything accidentally.
        let PegoutData {
            amount,
            destination,
            network,
        } = self;

        t.append_u64(b"pegout:amount", amount.to_sat());
        t.append_message(b"pegout:dest", destination.script_pubkey().as_bytes());
        network.append_to_transcript(t);
    }
}

impl ToTranscript for PegoutWithId {
    fn append_to_transcript(&self, t: &mut Transcript) {
        // Deconstruct so we do not miss anything accidentally.
        let PegoutWithId { id, data } = self;

        id.append_to_transcript(t);
        data.append_to_transcript(t);
    }
}

impl<T> ToTranscript for Sorted<T>
where
    T: ToTranscript,
{
    fn append_to_transcript(&self, t: &mut Transcript) {
        t.append_u64(b"sorted_list:len", self.len() as u64);

        for i in self.iter() {
            i.append_to_transcript(t)
        }
    }
}
