//! # Foundation Layer
//!
//! The Foundation Layer serves as the core state management engine for
//! Botanix's cross-chain Bitcoin withdrawal (pegout) system. It coordinates the
//! lifecycle of pegout operations from initiation through finalization,
//! ensuring cryptographic integrity and consensus across the validator network.
//!
//! ## Core Responsibilities
//!
//! - **Pegout Lifecycle Management**: Tracks pegouts through initiated,
//!   pending, and delayed states with cryptographic commitments
//! - **Bitcoin Block Tree Coordination**: Manages fork detection, resolution
//!   and automatic pruning of finalized/orphaned blocks
//! - **Deterministic State Transitions**: Ensures all validators compute
//!   identical state roots for consensus validation
//! - **Bitcoin Transaction Registration**: Validates and tracks Bitcoin
//!   transactions with their associated pegouts
//!
//! ## Architecture Overview
//!
//! The Foundation Layer operates through two main phases:
//!
//! ### Proposal Phase ([`Foundation::propose_commitments`])
//!
//! Used during CometBFT's `prepare_proposal` and `process_proposal` phases.
//! Validates state changes and computes the resulting commitment root without
//! persisting changes. Returns a [`CheckedFoundationProof`] that must be shared
//! with the network for validation.
//!
//! ### Finalization Phase ([`Foundation::finalize_commitments`])
//!
//! Used during CometBFT's `finalize_block` phase. Re-executes the same state
//! changes and verifies they produce the expected root hash, then persists the
//! changes. This ensures deterministic state computation across all validators.
//!
//! ## State Commitment System
//!
//! The layer uses a cryptographic trie structure to commit to all state
//! changes, enabling:
//! - Efficient state synchronization between validators  
//! - Fraud-proof generation for invalid state transitions
//! - Atomic rollback on validation failures
//! - Preparation for future dynamic federation upgrades
//!
//! <img src="data:image/png;base64,
#![doc = include_str!("../../assets/foundation_overview.base64")]
//! " alt="Validation Workflow Diagram" style="max-width: 100%; width: 1000px; height: auto; display: block; margin: 0 auto;">
use crate::{
    foundation::{
        commitment::trie,
        proof::{AuxEvent, Context, FoundationStateProof, FoundationStateRoot},
    },
    structs::block_tree::{BlockFate, BlockTree, Error as BlockTreeError},
    validation::{
        bitcoin::verify_transaction_proof,
        pegout::{PegoutId, PegoutWithId},
    },
};
use bitcoin::{merkle_tree::PartialMerkleTree, BlockHash, Transaction, Txid};
use hash_db::HashDB;
use std::collections::{HashSet, VecDeque};
use trie_db::DBValue;

/* PRIVATE */
mod commitment;
mod component;
#[cfg(test)]
mod tests;

pub mod proof;

// Public re-exports.
pub use commitment::atomic::{AtomicError, AtomicErrorVariant, AtomicLayer};
pub use commitment::sorted::Sorted;
pub use commitment::trie::{CommitmentStateRoot, TrieLayer};
pub use commitment::{CommitHasher, MultisigId};
pub use component::pegout::{
    DataSource,
    // TODO: Those `E*` types should be named differently, probably.
    EOnchainHeader,
    EOnchainUtxo,
    EProposal,
    EUnassigned,
    //
    OnchainHeaderEntry,
    OnchainUtxoEntry,
    PegoutError,
    ProposalEntry,
    UnassignedEntry,
};
pub use component::Checked;
pub use component::{BotanixLayer, BotanixLayerError, DatabaseError};

// TODO: Expose those in crate root, maybe?
pub use bitcoin;
pub use hash_db;
pub use trie_db;

pub const MULTISIG: MultisigId = 0;

#[derive(Debug, PartialEq, Eq)]
pub enum Error<A, DS> {
    ValidationError(ValidationError),
    BackendError(BackendError<A, DS>),
}

impl<A, DS> From<ValidationError> for Error<A, DS> {
    fn from(err: ValidationError) -> Self {
        Error::ValidationError(err)
    }
}

impl<A, DS> From<BackendError<A, DS>> for Error<A, DS> {
    fn from(err: BackendError<A, DS>) -> Self {
        Error::BackendError(err)
    }
}

impl<A, DS> From<BotanixLayerError<DS>> for Error<A, DS> {
    fn from(err: BotanixLayerError<DS>) -> Self {
        match err {
            BotanixLayerError::Database(err) => Error::BackendError(BackendError::Database(err)),
            BotanixLayerError::Fatal(err) => Error::BackendError(BackendError::Fatal(err)),
            BotanixLayerError::NotExists => Error::ValidationError(ValidationError::InvalidState),
            BotanixLayerError::Validation { partition, kind } => {
                Error::ValidationError(ValidationError::StateError { partition, kind })
            }
        }
    }
}

impl<A, DS> From<PegoutError<DS>> for Error<A, DS> {
    fn from(err: PegoutError<DS>) -> Self {
        match err {
            PegoutError::ValidationError(err) => Error::ValidationError(err.into()),
            PegoutError::BackendError(err) => Error::BackendError(err.into()),
        }
    }
}

impl<A, DS> From<AtomicError<A>> for Error<A, DS> {
    fn from(err: AtomicError<A>) -> Self {
        Error::BackendError(err.into())
    }
}

impl<A, DS> From<DatabaseError<DS>> for Error<A, DS> {
    fn from(err: DatabaseError<DS>) -> Self {
        Error::BackendError(err.into())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    BadFoundationStateRoot,
    BadBitcoinHeader,
    BadAncestorMark,
    BadTxInclusionProof,
    EmptyPegoutList,
    UtxoNotMatchProposal,
    TxOutValueExceedsPegoutAmount,
    TxOutDestNotMatchingPegoutDest,
    PegoutIdReused,
    TxInputsRemainingUnchecked,
    TxOutReturnBadChange,
    TxOutputsRemainingUnchecked,
    PegoutListRemainingUnchecked,
    TxidAlreadyRegistered,
    //
    InvalidState,
    StateError {
        partition: &'static str,
        kind: trie::ErrorKind,
    },
    PegoutError(component::pegout::ValidationError),
}

impl From<component::pegout::ValidationError> for ValidationError {
    fn from(err: component::pegout::ValidationError) -> Self {
        ValidationError::PegoutError(err)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BackendError<A, DS> {
    /// Error in the atomic layer.
    AtomicLayer(AtomicError<A>),
    /// Error in the database layer.
    Database(DatabaseError<DS>),
    /// The block tree fork detection mechanism was incorrectly setup.
    BadBlockTree(BlockTreeError),
    /// The preloaded Bitcoin headers for initiation must not be empty. A
    /// genesis Foundation state should be initiated with
    /// [`Foundation::new_genesis`] instead.
    EmptyBitcoinHeaders,
    /// The computed root after an atomic operation (commit/rollback) on the
    /// commitment layer did not match some expected value.
    ///
    /// This generally implies a software bug.
    BadPostAtomicRoot,
    InvalidBlockMarking,
    /// Fatal error in the commitment layer.
    ///
    /// This generally implies corrupted database.
    Fatal(trie_db::TrieError<[u8; 32], trie_db::CError<commitment::CommitSchema>>),
}

impl<A, DS> From<AtomicError<A>> for BackendError<A, DS> {
    fn from(err: AtomicError<A>) -> Self {
        BackendError::AtomicLayer(err)
    }
}

impl<A, DS> From<DatabaseError<DS>> for BackendError<A, DS> {
    fn from(err: DatabaseError<DS>) -> Self {
        BackendError::Database(err)
    }
}

impl<A, DS> From<BlockTreeError> for BackendError<A, DS> {
    fn from(err: BlockTreeError) -> Self {
        BackendError::BadBlockTree(err)
    }
}

impl<A, DS> From<component::BackendError<DS>> for BackendError<A, DS> {
    fn from(err: component::BackendError<DS>) -> Self {
        match err {
            component::BackendError::Database(err) => BackendError::Database(err),
            component::BackendError::Fatal(err) => BackendError::Fatal(err),
        }
    }
}

/// The primary interface for Foundation Layer operations, providing a safe and
/// deterministic API for managing cross-chain Bitcoin withdrawal state.
///
/// The `Foundation` type orchestrates multi-chain operations while maintaining
/// cryptographic integrity and consensus safety. It abstracts low-level trie
/// operations, automatic Bitcoin block pruning, and pegout lifecycle management
/// behind a simple two-phase API.
///
/// ## Two-Phase Operation Model
///
/// The Foundation operates through a propose-then-finalize pattern that aligns
/// with CometBFT's consensus phases:
///
/// ### Proposal Phase
///
/// [`Foundation::propose_commitments`] validates state changes and computes the
/// resulting commitment root without persisting changes. Used during:
/// - `CometBFT::prepare_proposal`: Block proposers create state change proposals
/// - `CometBFT::process_proposal`: Validators verify proposed state changes
///
/// Returns a [`CheckedFoundationProof`] containing the computed state root
/// that must be included in the block for network consensus.
///
/// ### Finalization Phase  
///
/// [`Foundation::finalize_commitments`] re-executes the same state changes,
/// verifies they produce the expected root hash, then persists the results.
/// Used during:
/// - `CometBFT::finalize_block`: All validators commit the agreed-upon state
///   changes
///
/// ## Safety Guarantees
///
/// - **Deterministic Execution**: Identical inputs always produce identical
///   state roots across all validators
/// - **Atomic Operations**: Failed validations trigger automatic rollback,
///   preventing partial state corruption
/// - **Cryptographic Integrity**: All state changes are committed to a
///   cryptographic trie for efficient verification
/// - **Consensus Safety**: Invalid state transitions can result in slashing,
///   incentivizing correct behavior
///
/// ## Usage Pattern
///
/// ```rust,ignore
/// // Proposal phase - validate and compute new state root
/// let proof = foundation.propose_commitments(|pending| {
///     pending.insert_bitcoin_header(block_hash, parent_hash)?;
///     pending.insert_bitcoin_tx_unchecked(hash, tx, pegouts)?;
///     Ok(())
/// })?;
///
/// // Extract root for inclusion in block
/// let state_root = proof.compute_root();
///
/// // Finalization phase - verify and persist changes  
/// foundation.finalize_commitments(state_root, |pending| {
///     // Identical operations as proposal phase
///     pending.insert_bitcoin_header(block_hash, parent_hash)?;
///     pending.insert_bitcoin_tx_unchecked(hash, tx, pegouts)?;
///     Ok(())
/// })?;
/// ```
///
/// ## Type Parameters
///
/// - `D`: Data layer implementation providing access to Bitcoin headers,
///   pegout data, and transaction relationships
/// - `A`: Atomic layer implementation handling state persistence and rollback
///   capabilities
pub struct Foundation<A, DB> {
    /* PRIVATE! */
    atomic_layer: A,
    block_tree: BlockTree,
    height: u64,
    markings: HashSet<BlockHash>,
    _p: std::marker::PhantomData<DB>,
}

impl<A, DB> Foundation<A, DB>
where
    A: AtomicLayer<DB>,
    DB: HashDB<CommitHasher, DBValue> + DataSource,
{
    /// Creates a new Foundation instance with the specified data layer,
    /// commitment layer, and initial Bitcoin block.
    pub fn new_genesis(
        mut atomic_layer: A,
        header: bitcoin::block::Header,
        bitcoin_height: u64,
        botanix_height: u64,
        conf_depth: u64,
    ) -> Result<Self, Error<A::BackendError, <DB as DataSource>::Error>> {
        let mut tx = atomic_layer.start_tx()?;
        let block_hash = header.block_hash();

        // VALIDATE: The passed-on block header does NOT exist in the commitment
        // state yet.
        tx.insert_bitcoin_header(header, bitcoin_height)?;

        let block_tree = BlockTree::new(block_hash, conf_depth).map_err(BackendError::from)?;

        // COMMIT changes to the database.
        atomic_layer.commit()?;

        Ok(Foundation {
            atomic_layer,
            block_tree,
            height: botanix_height,
            markings: HashSet::new(),
            _p: std::marker::PhantomData,
        })
    }
    pub fn new(
        mut atomic_layer: A,
        bitcoin_headers: &[BlockHash],
        botanix_height: u64,
        conf_depth: u64,
    ) -> Result<Self, Error<A::BackendError, <DB as DataSource>::Error>> {
        if bitcoin_headers.is_empty() {
            return Err(BackendError::EmptyBitcoinHeaders)?;
        }

        let mut tx = atomic_layer.start_tx()?;

        // VALIDATE: All passed-on Bitcoin headers exist in the commitment state.
        let mut checked_headers: VecDeque<Checked<EOnchainHeader>> = bitcoin_headers
            .iter()
            .map(|h| tx.get_checked(|db| db.get_header(h)))
            .collect::<Result<VecDeque<_>, _>>()?;

        // Init the block tree with the extracted elder.
        let elder = checked_headers
            .pop_front()
            .expect("elder must exist")
            .consume()
            .v
            .block_hash;

        let mut block_tree = BlockTree::new(elder, conf_depth).map_err(BackendError::from)?;

        // Preload the block tree with all checked Bitcoin headers.
        while let Some(header) = checked_headers.pop_front() {
            let h = header.consume();

            block_tree
                .insert(h.v.block_hash, h.v.parent_hash)
                .map_err(BackendError::from)?;
        }

        // Nothing to commit.
        atomic_layer.rollback()?;

        Ok(Foundation {
            atomic_layer,
            block_tree,
            height: botanix_height,
            markings: HashSet::new(),
            _p: std::marker::PhantomData,
        })
    }
    // TODO: Provide more context for this.
    /// Marks a Bitcoin block header for special tracking.
    ///
    /// # Arguments
    /// * `hash` - The block hash to mark
    ///
    /// # Returns
    /// * `Ok(true)` - Block was successfully marked (newly added to markings)
    /// * `Ok(false)` - Block was already marked
    /// * `Err` - Block hash not found in the block tree
    ///
    /// # Errors
    /// Returns `BackendError::InvalidBlockMarking` if the block hash is not
    /// present in the block tree.
    pub fn mark_bitcoin_header(
        &mut self,
        hash: BlockHash,
    ) -> Result<bool, Error<A::BackendError, <DB as DataSource>::Error>> {
        if !self.block_tree.contains(&hash) {
            return Err(BackendError::InvalidBlockMarking)?;
        }

        Ok(self.markings.insert(hash))
    }
    /// Returns all tracked block hashes currently in the block tree.
    pub fn tracked_blocks(&self) -> Vec<BlockHash> {
        self.block_tree.blocks()
    }
    /// Returns the tracked set of chain tips in the block tree.
    ///
    /// Tips are blocks that have no children and represent the current
    /// frontier of the block tree. Multiple tips indicate active forks.
    pub fn tracked_block_tips(&self) -> Vec<BlockHash> {
        self.block_tree.tips()
    }
    /// Returns the tracked elder (oldest retained) block hash in the block
    /// tree.
    ///
    /// The elder is the oldest block still maintained in the tree structure.
    /// All blocks older than the elder have been pruned as finalized.
    pub fn tracked_block_elder(&self) -> BlockHash {
        self.block_tree.elder()
    }
    pub fn commitment_root(
        &mut self,
    ) -> Result<CommitmentStateRoot, Error<A::BackendError, <DB as DataSource>::Error>> {
        // TODO: Just keep an internal copy?
        let root = self.atomic_layer.start_tx()?.root();
        self.atomic_layer.rollback()?;
        Ok(root)
    }
    /// Validates a sequence of state changes and computes the resulting
    /// commitment root without persisting any modifications.
    ///
    /// This method is used during the proposal phase of consensus (CometBFT's
    /// `prepare_proposal` and `process_proposal`) to validate state changes
    /// and compute the commitment root that will be included in the proposed
    /// block.
    ///
    /// # Safety Guarantees
    ///
    /// - **Atomic Operations**: Either all succeed or all fail deterministically
    /// - **Deterministic Results**: Identical inputs produce identical roots
    ///   across all validators
    /// - **No Persistence**: Changes are never written to permanent storage
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that receives a [`CommitmentsDraft`] and performs
    ///   the desired state modifications
    ///
    /// # Returns
    ///
    /// A [`CheckedFoundationProof`] containing the computed state root and
    /// auxiliary data, or an error if validation fails.
    pub fn propose_commitments<F, R>(
        &mut self,
        f: F,
    ) -> Result<CheckedFoundationProof<R>, Error<A::BackendError, <DB as DataSource>::Error>>
    where
        F: FnOnce(
            &mut CommitmentsDraft<'_, A, DB>,
        ) -> Result<R, Error<A::BackendError, <DB as DataSource>::Error>>,
    {
        let mut draft = CommitmentsDraft {
            btx: self.atomic_layer.start_tx()?,
            // NOTE: We do a full copy of the block tree since it does not
            // implement a rollback mechanism natively. It's usually small
            // enough (~18 entries) such that a full copy is considered
            // inexpensive.
            block_tree: self.block_tree.clone(),
            markings: &self.markings,
            aux_msgs: Vec::new(),
            _p: std::marker::PhantomData,
        };

        let origin_root = draft.btx.root();

        // Handle the commitments within the closure, and acquire the
        // UPDATED state root.
        let res: Result<R, Error<_, _>> = f(&mut draft);
        let (_block_tree, foundation_state) = draft.into_foundation_state(self.height);

        // ROLLBACK: Always reset state after construction, on both success or
        // failure.
        let reset_root = self.atomic_layer.rollback()?;

        // Essentially a sanity check.
        if origin_root != reset_root {
            return Err(BackendError::BadPostAtomicRoot)?;
        }

        // If the inner logic of the closure failed, we return the error
        // directly to the caller. It's IMPORTANT that we always rollback the
        // database first!
        let extra_val: R = res?;

        // Operation succeeded; return checked commitment state proof.
        Ok(CheckedFoundationProof {
            _foundation_state: foundation_state,
            _extra_val: extra_val,
        })
    }
    /// Validates a sequence of state changes, validates they produce the
    /// expected commitment root, then persists the modifications.
    ///
    /// This method is used during the finalization phase of consensus
    /// (CometBFT's `finalize_block`) to verify that the proposed state changes
    /// are correctly reproduced and then commit them to permanent
    /// storage.
    ///
    /// # Safety Guarantees
    ///
    /// - **Atomic Operations**: Either all succeed or all fail
    ///   deterministically
    /// - **Deterministic Results**: Identical inputs produce identical roots
    ///   across all validators
    /// - **Root Verification**: Compares computed root against expected root
    /// - **Conditional Persistence**:
    ///    - **Match**: Commits changes to permanent storage
    ///    - **Mismatch**: Rolls back all changes and returns error
    ///
    /// # Arguments
    ///
    /// * `expected_root` - The commitment root that should result from applying
    ///   the state changes
    /// * `f` - Closure that receives a [`CommitmentsDraft`] and performs
    ///   the desired state modifications
    ///
    /// # Returns
    ///
    /// A [`CheckedFoundationProof`] containing the computed state root and
    /// auxiliary data, or an error if validation fails.
    pub fn finalize_commitments<F, R>(
        &mut self,
        expected_root: FoundationStateRoot,
        f: F,
    ) -> Result<CheckedFoundationProof<R>, Error<A::BackendError, <DB as DataSource>::Error>>
    where
        F: FnOnce(
            &mut CommitmentsDraft<'_, A, DB>,
        ) -> Result<R, Error<A::BackendError, <DB as DataSource>::Error>>,
    {
        let mut draft = CommitmentsDraft {
            btx: self.atomic_layer.start_tx()?,
            // NOTE: We do a full copy of the block tree since it does not
            // implement a rollback mechanism natively. It's usually small
            // enough (~18 entries) such that a full copy is considered
            // inexpensive.
            block_tree: self.block_tree.clone(),
            markings: &self.markings,
            aux_msgs: Vec::new(),
            _p: std::marker::PhantomData,
        };

        let origin_root = draft.btx.root();

        // Execute the commitments within the closure.
        let res: Result<R, _> = f(&mut draft);
        let (block_tree, foundation_state) = draft.into_foundation_state(self.height);

        // On error, we rollback the state and return!
        let extra_val = match res {
            Ok(extra_val) => extra_val,
            Err(err) => {
                // ROLLBACK: Operation failed; discard state!
                let reset_root = self.atomic_layer.rollback()?;

                // Essentially a sanity check.
                if reset_root != origin_root {
                    return Err(BackendError::BadPostAtomicRoot)?;
                }

                // Discard updated block tree.
                std::mem::drop(block_tree);

                return Err(err);
            }
        };

        // Compute the updated commitment root and validate it against the
        // provided foundation state root.
        let computed_root = foundation_state.compute_root();

        if computed_root == expected_root {
            // COMMIT: Operation succeeded and expected root is valid;
            // persist state!
            let updated_root = self.atomic_layer.commit()?;

            // Essentially a sanity check.
            if updated_root != foundation_state.commitments {
                return Err(BackendError::BadPostAtomicRoot)?;
            }

            // Increment height.
            self.height = self
                .height
                .checked_add(1)
                // The height is (should be) tied to Botanix block height,
                // occuring roughly every six seconds. This is not a limitation
                // to be concerned about.
                .expect("2^64 height space exhausted - FATAL");

            // Commit the updated block tree.
            self.block_tree = block_tree;

            // Update markings; cleanup any pruned blocks.
            for aux in &foundation_state.aux_events {
                match aux {
                    AuxEvent::FinalizedBitcoinHeader {
                        block_hash,
                        finalized: _,
                    } => {
                        self.markings.remove(block_hash);
                    }
                    AuxEvent::OrphanedBitcoinHeader {
                        block_hash,
                        delayed: _,
                    } => {
                        self.markings.remove(block_hash);
                    }
                    _ => {}
                }
            }

            Ok(CheckedFoundationProof {
                _foundation_state: foundation_state,
                _extra_val: extra_val,
            })
        } else {
            // ROLLBACK: Bad expected root; discard state!
            let reset_root = self.atomic_layer.rollback()?;

            // Essentially a sanity check.
            if reset_root != origin_root {
                return Err(BackendError::BadPostAtomicRoot)?;
            }

            // Discard updated block tree.
            std::mem::drop(block_tree);

            Err(ValidationError::BadFoundationStateRoot)?
        }
    }
}

/// A cryptographically verified foundation state proof with associated extra
/// data.
///
/// This type represents a foundation state proof that has been validated
/// through cryptographic verification and contains both the foundation state
/// and additional associated data. The private fields prevent direct
/// construction or modification, ensuring the contained state has passed
/// validation.
///
/// ## Type Safety
///
/// The `CheckedFoundationProof<T>` type serves as a "proof of validation" -
/// its existence guarantees that:
/// - The foundation state has been cryptographically verified
/// - The commitment proof is valid and can be trusted
/// - The associated extra data `T` is tied to the verified state
#[derive(Debug, PartialEq, Eq)]
pub struct CheckedFoundationProof<T> {
    /// The validated foundation state.
    /* PRIVATE */
    _foundation_state: FoundationStateProof,
    /// Additional validated data associated with the proof.
    _extra_val: T,
}

impl<T> CheckedFoundationProof<T> {
    /// Computes the state root hash for this commitment proof.
    ///
    /// Returns the cryptographic commitment representing the current state
    /// of the foundation layer.
    pub fn compute_root(&self) -> FoundationStateRoot {
        self.state().compute_root()
    }
    /// Returns a reference to the validated foundation state.
    pub fn state(&self) -> &FoundationStateProof {
        &self._foundation_state
    }
    /// Consumes the proof and returns the foundation state proof.
    pub fn into_state(self) -> FoundationStateProof {
        self._foundation_state
    }
    /// Returns a reference to the extra data associated with this proof.
    pub fn extra_val(&self) -> &T {
        &self._extra_val
    }
    /// Consumes the proof and returns the extra data.
    pub fn into_extra_val(self) -> T {
        self._extra_val
    }
}

/// A pending commitments draft that provides access to state modification
/// methods during the propose or finalize phases.
///
/// `CommitmentsDraft` is the primary interface for making state changes within
/// the Foundation Layer. It's obtained through
/// [`Foundation::propose_commitments`] or [`Foundation::finalize_commitments`]
/// and provides methods for pegout management, handling Bitcoin blocks and
/// transaction registrations while maintaining cryptographic integrity.
///
/// ## Automatic Block Tree Management
///
/// The pending operation maintains a [`BlockTree`] that automatically:
/// - Tracks competing Bitcoin forks
/// - Detects finalized blocks (part of the canonical chain)
/// - Identifies orphaned blocks (rejected forks)
/// - Manages pegout state transitions during reorganizations
///
/// ## Auxiliary Event Tracking
///
/// All state modifications generate [`AuxEvent`] that are collected and
/// included in the final [`FoundationStateProof`]. These events provide:
/// - Audit trail of all state changes
/// - Data for state synchronization between validators
/// - Information useful for external system integration
pub struct CommitmentsDraft<'db, A, DB> {
    btx: BotanixLayer<'db, DB>,
    block_tree: BlockTree,
    markings: &'db HashSet<BlockHash>,
    aux_msgs: Vec<AuxEvent>,
    _p: std::marker::PhantomData<A>,
}

impl<'db, A, DB> CommitmentsDraft<'db, A, DB>
where
    A: AtomicLayer<DB>,
    DB: HashDB<CommitHasher, DBValue> + DataSource,
{
    /// Initiates a new pegout, transitioning it to the "initiated" state.
    ///
    /// This method creates a new pegout entry in the commitment trie, making it
    /// available for spending by the multisig federation. The pegout moves from
    /// non-existent to the "initiated" state, where it can be included in
    /// Bitcoin transactions that fulfill withdrawal requests.
    ///
    /// ## Generated Events
    ///
    /// - [`AuxEvent::InitiatedPegout`] containing the multisig ID and the
    ///   pegout ID.
    ///
    /// ## Arguments
    ///
    /// * `multisig` - The multisig federation ID that should manage this pegout
    /// * `pegout` - Complete pegout data
    ///
    /// ## Errors
    ///
    /// This method can fail if:
    /// - The pegout already exists in initiated state
    /// - Database or trie operation failures
    pub fn insert_unassigned(
        &mut self,
        pegout: PegoutWithId,
        candidates: Vec<MultisigId>,
    ) -> Result<(), Error<A::BackendError, <DB as DataSource>::Error>> {
        let pegout_id = pegout.id;
        let candidates: Sorted<_> = candidates.into();

        // COMMIT: Insert unassigned pegout into the commitment layer.
        self.btx.insert_unassigned(pegout, candidates.clone())?;

        self.aux_msgs.push(AuxEvent::InitiatedPegout {
            pegout: pegout_id,
            candidates,
        });

        Ok(())
    }
    pub fn insert_pegout_proposal(
        &mut self,
        proposal: ProposalEntry,
        prev_proposal: Option<Txid>,
    ) -> Result<(), Error<A::BackendError, <DB as DataSource>::Error>> {
        // COMMIT: Insert pegout proposal into the commitment layer.
        self.btx
            .insert_pegout_proposal(proposal.clone(), prev_proposal)?;

        self.aux_msgs.push(AuxEvent::SubmittedProposal { proposal });

        Ok(())
    }
    /// Processes a new Bitcoin block header and handles any resulting chain
    /// reorganizations.
    ///
    /// This method integrates a new Bitcoin block into the Foundation's block
    /// tree, automatically detecting forks and triggering pruning of old blocks
    /// when they become sufficiently deep. The method handles three types of
    /// block events:
    ///
    /// ## Generated Events
    ///
    /// - [`AuxEvent::NewBitcoinHeader`] for each processed block
    /// - [`AuxEvent::FinalizedBitcoinHeader`] for blocks that become final
    /// - [`AuxEvent::OrphanedBitcoinHeader`] for blocks that are rejected
    ///
    /// # Arguments
    ///
    /// * `block_hash` - Hash of the new Bitcoin block to process
    /// * `parent_hash` - Hash of the parent block (must exist in the tree)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The parent block is not found in the block tree
    /// - Data layer queries fail
    /// - Commitment layer validation fails
    //
    // TODO: Update docs to describe the header marking mechanism.
    // TODO: The height should be verified against the parent height. Right now,
    // the block tree only tracks relative heights, not absolute heights.
    pub fn insert_bitcoin_header(
        &mut self,
        header: bitcoin::block::Header,
        height: u64,
    ) -> Result<(), Error<A::BackendError, <DB as DataSource>::Error>> {
        let block_hash = header.block_hash();
        let parent_hash = header.prev_blockhash;

        // COMMIT: Insert bitcoin header into the commitment layer.
        self.btx.insert_bitcoin_header(header, height)?;

        self.aux_msgs.push(AuxEvent::NewBitcoinHeader {
            block_hash: block_hash.into(),
        });

        // VALIDATE: Block header ancestor has been subjectively marked. This
        // ensures the chain doesn't progress beyond the thresh without at least
        // one subjectively validated ancestor (prevents building on potentially
        // invalid forks).
        let chain = self
            .block_tree
            .chain(&parent_hash)
            .map_err(|_| ValidationError::BadBitcoinHeader)?;

        let thresh = self.block_tree.conf_depth().div_ceil(3).max(1);

        // Traverse backwards, from the parent to the elder.
        for (idx, ancestor) in chain.iter().rev().enumerate() {
            if self.markings.contains(ancestor) {
                // Found a marked ancestor within threshold, validation passes
                break;
            }

            if idx as u64 >= thresh {
                // No marked ancestors found within acceptable depth, reject
                // block
                return Err(ValidationError::BadAncestorMark)?;
            }
        }

        // Insert the new Bitcoin header and retrieve any resulting prune events.
        let pruned = self
            .block_tree
            .insert(block_hash, parent_hash)
            .map_err(|_| ValidationError::BadBitcoinHeader)?;

        if pruned.is_empty() {
            // Nothing left to do.
            return Ok(());
        }

        // Retrieve all tracked Txids for that pruned block hash.
        for p in pruned {
            // Retrieve all Txids of the pruned block. We only require this for
            // the aux events.
            let txids: Sorted<Txid> = self
                .btx
                .get_checked(|db| db.get_header(p.block_hash()))
                .map(|e| e.consume().v.proposals)?;

            // Retrieve all pegouts for each Txid.
            let pegouts: Vec<Sorted<PegoutWithId>> = txids
                .iter()
                .map(|txid| {
                    self.btx
                        .get_checked(|db| db.get_proposal(&txid))
                        .map(|e| e.consume().v.pegouts)
                })
                .collect::<Result<_, _>>()?;

            // VALIDATE: Prune headers from the commitment layer.
            match p {
                BlockFate::Finalized(block_hash) => {
                    self.btx.finalize_bitcoin_header(block_hash)?;

                    let finalized: Sorted<PegoutId> = pegouts
                        .into_iter()
                        .flatten()
                        .map(|pegout| pegout.id)
                        .collect();

                    self.aux_msgs.push(AuxEvent::FinalizedBitcoinHeader {
                        block_hash,
                        finalized,
                    })
                }
                BlockFate::Orphaned(block_hash) => {
                    self.btx.orphan_bitcoin_header(block_hash)?;

                    let delayed: Sorted<PegoutId> = pegouts
                        .into_iter()
                        .flatten()
                        .map(|pegout| pegout.id)
                        .collect();

                    self.aux_msgs.push(AuxEvent::OrphanedBitcoinHeader {
                        block_hash,
                        delayed,
                    });
                }
            }
        }

        Ok(())
    }
    /// Registers a Bitcoin transaction with its associated pegout operations.
    ///
    /// This method validates and registers a Bitcoin transaction that fulfills
    /// multiple pegout requests. It performs comprehensive validation of the
    /// transaction structure, output values, and destination addresses before
    /// moving pegouts from the initiated state to the pending state.
    ///
    /// ## Generated Events
    ///
    /// - [`AuxEvent::RegisterBitcoinTx`] containing the transaction ID,
    ///   associated block hash, and list of included pegout IDs
    ///
    /// # Arguments
    ///
    /// * `block_hash` - Bitcoin block where this transaction will be included
    /// * `tx` - The Bitcoin transaction fulfilling the pegouts
    /// * `pegouts` - List of pegout IDs that this transaction fulfills
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Pegout list is empty or exceeds transaction output count
    /// - Any pegout is not in the initiated state (already spent/pending)
    /// - Transaction output value exceeds the pegout amount
    /// - Transaction destination doesn't match pegout destination
    /// - Pegout ID is duplicated in the request
    /// - Transaction ID is already registered for this block
    /// - Data layer queries fail
    // TODO: UTXO's are not checked against the proposal UTXOs. This SHOULD be checked!
    pub fn insert_bitcoin_tx(
        &mut self,
        block_hash: BlockHash,
        tx: Transaction,
        proof: PartialMerkleTree,
        proposal: ProposalEntry,
    ) -> Result<(), Error<A::BackendError, <DB as DataSource>::Error>> {
        // COMMIT: Insert Bitcoin transaction into the commitment layer.
        self.btx.insert_bitcoin_tx(block_hash, proposal.txid)?;

        // VALIDATE: Pegout list must not be empty.
        if proposal.pegouts.is_empty() {
            return Err(ValidationError::EmptyPegoutList)?;
        }

        // VALIDATE: The passed-on block hash exists.
        let header = self.btx.get_checked(|db| db.get_header(&block_hash))?;

        // VALIDATE: The passed-on transaction has a valid block inclusion proof.
        verify_transaction_proof(&tx, &proof, &header.v.merkle_root)
            .map_err(|_| ValidationError::BadTxInclusionProof)?;

        // TODO: Match Txid against the actual `proposal`. While we do check the
        // UTXOs and pegouts individually, this should be done anyway.
        let computed_txid = tx.compute_txid();

        // Convert input lists to `VecDeque` since it's easier to work with.
        let mut queue_tx_in: VecDeque<bitcoin::TxIn> = tx.input.to_vec().into();
        let mut queue_utxos: VecDeque<bitcoin::OutPoint> = proposal.utxos.to_vec().into();

        // VALIDATE: Each input in the transaction must match the proposed UTXO
        // in the proposal.
        while let Some((tx_in, utxo)) = queue_tx_in.pop_front().zip(queue_utxos.pop_front()) {
            if tx_in.previous_output != utxo {
                return Err(ValidationError::UtxoNotMatchProposal)?;
            }
        }

        // VALIDATE: All Bitcoin transaction inputs have been processed.
        if !queue_tx_in.is_empty() || !queue_utxos.is_empty() {
            return Err(ValidationError::TxInputsRemainingUnchecked)?;
        }

        // Used for PegoutId duplicate checking.
        let mut used_ids = HashSet::new();

        // Convert output lists to `VecDeque` since it's easier to work with.
        let mut queue_tx_out: VecDeque<bitcoin::TxOut> = VecDeque::from(tx.output.clone());
        let mut queue_pegouts: VecDeque<PegoutWithId> = VecDeque::from(proposal.pegouts.to_vec());

        // VALIDATE: Each output in the transaction must match the proposed
        // pegout in the proposal.
        while let Some((tx_out, pegout)) = queue_tx_out.pop_front().zip(queue_pegouts.pop_front()) {
            // VALIDATE: Output value must be equal or less (fee-adjustment)
            // then the pegout amount.
            if pegout.data.amount < tx_out.value {
                return Err(ValidationError::TxOutValueExceedsPegoutAmount)?;
            }

            // VALIDATE: Output scriptPubkey matches the pegout destination.
            if !pegout
                .data
                .destination
                .matches_script_pubkey(&tx_out.script_pubkey)
            {
                return Err(ValidationError::TxOutDestNotMatchingPegoutDest)?;
            }

            // VALIDATE: PegoutId may not be reused.
            if !used_ids.insert(pegout.id) {
                return Err(ValidationError::PegoutIdReused)?;
            }
        }

        // VALIDATE: Optional change address.
        if let Some(change) = queue_tx_out.pop_front() {
            // TODO: Validate change - right now we always return an error.
            return Err(ValidationError::TxOutReturnBadChange)?;
        }

        // VALIDATE: All Bitcoin transaction outputs have been processed.
        if !queue_tx_out.is_empty() {
            // Transaction contains more outputs.
            return Err(ValidationError::TxOutputsRemainingUnchecked)?;
        }

        // VALIDATE: All passed-on pegouts have been processed.
        if !queue_pegouts.is_empty() {
            return Err(ValidationError::PegoutListRemainingUnchecked)?;
        }

        let aux_pegouts: Sorted<PegoutId> =
            proposal.pegouts.iter().map(|pegout| pegout.id).collect();

        self.aux_msgs.push(AuxEvent::RegisterBitcoinTx {
            block_hash,
            txid: proposal.txid,
            pegouts: aux_pegouts,
        });

        debug_assert!(queue_utxos.is_empty());
        debug_assert!(queue_tx_in.is_empty());

        debug_assert!(queue_pegouts.is_empty());
        debug_assert!(queue_tx_out.is_empty());

        Ok(())
    }
    /// Consumes this pending operation into a [`FoundationStateProof`] containing the
    /// computed commitment root and all auxiliary events.
    ///
    /// This method is called **internally** when the pending operation
    /// completes, extracting the final state that includes:
    /// - The cryptographic commitment root from all state changes
    /// - List of tracked Bitcoin block headers
    /// - Chronological record of all auxiliary events generated
    ///
    /// The resulting state is used for consensus validation and can be
    /// reconstructed deterministically by any validator performing the
    /// same sequence of operations.
    fn into_foundation_state(mut self, height: u64) -> (BlockTree, FoundationStateProof) {
        let commitments = self.btx.root();
        let bitcoin_headers = self.block_tree.blocks().into_iter().collect();

        let state = FoundationStateProof {
            context: Context { height },
            commitments,
            bitcoin_headers,
            aux_events: std::mem::take(&mut self.aux_msgs),
        };

        (self.block_tree, state)
    }
}
