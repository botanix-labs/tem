//! # Foundation Layer Cryptographic State Proofs
//!
//! This module implements the cryptographic proof system for the Foundation
//! Layer, providing deterministic state commitment and verification for Botanix
//! pegout operations. It ensures all validators compute identical state roots
//! during consensus by creating commitments over all state components.
//!
//! ## Core Components
//!
//! The proof system commits to four key state elements:
//! - **Context**: Version metadata enabling protocol upgrades
//! - **Commitments**: Root hash of the commitment trie containing pegout state
//! - **Bitcoin Headers**: Tracked Bitcoin block headers enabling state reconstruction
//! - **Auxiliary Events**: Per-block/per-commitment event log for efficient lookups
//!
//! ## State Reconstruction and Syncing
//!
//! Both `bitcoin_headers` and `aux_events` serve as efficient lookup mechanisms,
//! and allow syncing nodes to reconstruct commitment verification state
//! without running the full commitment validation process. This enables faster
//! state synchronization and efficient querying of historical state changes.
use crate::{
    foundation::{
        CommitHasher, CommitmentStateRoot,
        commitment::{MultisigId, sorted::Sorted},
        component::{ToCommit, pegout::ProposalEntry},
    },
    validation::pegout::PegoutId,
};
use bitcoin::{BlockHash, Txid};
use serde::{Deserialize, Serialize};

/// A 32-byte cryptographic commitment to the complete Foundation Layer state.
///
/// This root hash is computed over four components: context metadata,
/// commitment trie root, Bitcoin headers, and auxiliary events. All validators
/// must compute identical roots for consensus validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundationStateRoot([u8; 32]);

/// Context and metadata for Foundation Layer state format.
///
/// **Important**: This structure is primarily reserved for future extensions
/// and will likely be expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context {
    pub height: u64,
}

/// The complete Foundation Layer state proof containing all data needed for
/// consensus validation.
///
/// This structure represents the canonical state of the pegout system and can
/// be deterministically reconstructed by any validator performing the same
/// sequence of operations. The `bitcoin_headers` and `aux_events` fields serve
/// as efficient lookup mechanisms, enabling syncing nodes to reconstruct
/// commitment verification state without running the full commitment validation
/// process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundationStateProof {
    /// Context for this state format.
    pub context: Context,
    /// Cryptographic root of the commitment trie containing all pegout data.
    pub commitments: CommitmentStateRoot,
    /// Bitcoin block headers being tracked to enable state reconstruction.
    pub bitcoin_headers: Vec<BlockHash>,
    /// Per-block/per-commitment event log enabling efficient state lookups.
    pub aux_events: Vec<AuxEvent>,
}

impl FoundationStateProof {
    /// Computes the cryptographic commitment root for this state.
    ///
    /// Creates a deterministic Merlin-based commitment over all state
    /// components. The root uniquely identifies this state and must be
    /// identical across all validators for consensus.
    ///
    /// # Returns
    ///
    /// A 32-byte root hash representing the complete Foundation state
    pub fn compute_root(&self) -> FoundationStateRoot {
        let mut h = CommitHasher::new(b"botanix:foundation_state_proof");

        // Context
        h.append_u64(b"context:height", self.context.height); // Important!

        // Commitment layer.
        h.append_message(b"commitments_root", self.commitments.as_ref());

        // Tracked Bitcoin headers.
        self.bitcoin_headers
            .iter()
            .collect::<Sorted<_>>()
            .iter()
            .for_each(|block_hash| {
                block_hash.append_to_commit(&mut h);
            });

        // Auxiliary events.
        self.aux_events
            .iter()
            .collect::<Sorted<_>>()
            .iter()
            .for_each(|aux| {
                aux.append_to_commit(&mut h);
            });

        FoundationStateRoot(h.finalize())
    }
}

/// Per-block auxiliary events providing efficient lookups, useful for indexing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuxEvent {
    /// A new pegout has been initiated and is available for spending.
    ///
    /// Transitions the pegout to the "initiated" state where it can be included
    /// in Bitcoin transactions by the multisig federation.
    InitiatedPegout {
        pegout: PegoutId,
        candidates: Sorted<MultisigId>,
    },
    SubmittedProposal {
        proposal: ProposalEntry,
    },
    /// A new Bitcoin block header has been received and is being tracked.
    ///
    /// Adds the block to the fork detection system for monitoring transaction
    /// confirmations and handling potential reorganizations.
    NewBitcoinHeader {
        block_hash: BlockHash,
    },
    /// A Bitcoin transaction has been registered with its associated pegouts.
    ///
    /// Transitions included pegouts from "initiated" to "pending" state while
    /// the transaction awaits sufficient confirmations.
    RegisterBitcoinTx {
        block_hash: BlockHash,
        txid: Txid,
        pegouts: Sorted<PegoutId>,
    },
    /// A Bitcoin block has been finalized, making included pegouts unspendable.
    ///
    /// Permanently removes pegouts from the spendable set after sufficient
    /// confirmations, completing the pegout lifecycle successfully.
    FinalizedBitcoinHeader {
        block_hash: BlockHash,
        finalized: Sorted<PegoutId>,
    },
    /// A Bitcoin block has been orphaned, making included pegouts respendable.
    ///
    /// Moves pegouts from "pending" to "delayed" state, allowing them to be
    /// included in new transactions after the blockchain reorganization.
    OrphanedBitcoinHeader {
        block_hash: BlockHash,
        delayed: Sorted<PegoutId>,
    },
}

impl ToCommit for AuxEvent {
    fn append_to_commit(&self, h: &mut CommitHasher) {
        match self {
            AuxEvent::InitiatedPegout { pegout, candidates } => {
                h.append_message(b"aux_event:initiated_pegout", b"");
                pegout.append_to_commit(h);
                candidates.append_to_commit(h);
            }
            AuxEvent::SubmittedProposal { proposal } => {
                h.append_message(b"aux_event:submitted_proposal", b"");
                proposal.append_to_commit(h);
            }
            AuxEvent::NewBitcoinHeader { block_hash } => {
                h.append_message(b"aux_event:new_bitcoin_header", b"");
                block_hash.append_to_commit(h);
            }
            AuxEvent::RegisterBitcoinTx {
                block_hash,
                txid,
                pegouts,
            } => {
                h.append_message(b"aux_event:insert_bitcoin_tx", b"");
                block_hash.append_to_commit(h);
                txid.append_to_commit(h);
                pegouts.append_to_commit(h);
            }
            AuxEvent::FinalizedBitcoinHeader {
                block_hash,
                finalized,
            } => {
                h.append_message(b"aux_event:finalized_bitcoin_header", b"");
                block_hash.append_to_commit(h);
                finalized.append_to_commit(h);
            }
            AuxEvent::OrphanedBitcoinHeader {
                block_hash,
                delayed,
            } => {
                h.append_message(b"aux_event:orphaned_bitcoin_header", b"");
                block_hash.append_to_commit(h);
                delayed.append_to_commit(h);
            }
        }
    }
}

// TODO: Hide behind feature/cfg guard?
pub mod test_utils {
    use super::*;
    use rand::Rng;

    pub fn gen_foundation_state_root() -> FoundationStateRoot {
        let r = rand::rng().random::<[u8; 32]>();
        FoundationStateRoot(r)
    }
}
