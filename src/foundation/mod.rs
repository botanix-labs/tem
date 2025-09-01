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
#![doc = include_str!("../../docs/assets/foundation_overview.base64")]
//! " alt="Validation Workflow Diagram" style="max-width: 100%; width: 1000px; height: auto; display: block; margin: 0 auto;">
use crate::{
    foundation::{
        commitment::{
            MultisigId,
            botanix::{BotanixLayer, ImplFatalKind},
            sorted::Sorted,
            trie::ErrorKind as TrieErrorKind,
        },
        proof::{AuxEvent, Context, FoundationStateProof, FoundationStateRoot},
    },
    structs::block_tree::{BlockFate, BlockTree},
    validation::pegout::{PegoutData, PegoutId, PegoutWithId},
};
use bitcoin::{BlockHash, TxOut, Txid};
use std::collections::{HashSet, VecDeque};

mod commitment;
pub mod proof;
#[cfg(test)]
mod tests;

// Public re-exports.
pub use commitment::CommitmentStateRoot;
pub use commitment::storage::{AtomicError, AtomicLayer, InMemoryCommitments};

pub trait DataLayer {
    type Error: std::fmt::Debug;

    fn get_bitcoin_header(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<bitcoin::block::Header>, Self::Error>;
    fn get_pegout_by_id(&self, id: &PegoutId) -> Result<Option<PegoutData>, Self::Error>;
    fn get_txids_by_block_hash(&self, hash: &BlockHash) -> Result<Vec<Txid>, Self::Error>;
    fn get_pegouts_by_txid(&self, txid: &Txid) -> Result<Vec<PegoutWithId>, Self::Error>;
}

pub const MULTISIG: MultisigId = 0;

#[derive(Debug, PartialEq, Eq)]
pub enum Error<D, A> {
    ValidationError(ValidationError),
    BackendError(BackendError<D, A>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    BadFoundationStateRoot,
    PegoutDoesNotExist,
    BadBitcoinHeader,
    EmptyPegoutList,
    TxOutValueExceedsPegoutAmount,
    TxOutDestNotMatchingPegoutDest,
    PegoutIdReused,
    TxOutReturnBadChange,
    TxOutputsRemainingUnchecked,
    PegoutListRemainingUnchecked,
    TxidAlreadyRegistered,
    /// Error caused in the trie layer caused by a bad trie operation. This
    /// implies malicious behavior.
    BadTrieOp(TrieErrorKind),
}

#[derive(Debug, PartialEq, Eq)]
pub enum BackendError<D, A> {
    /// The computed root after an atomic operation (commit/rollback) on the
    /// commitment layer did not match some expected value. This generally
    /// implies a software bug.
    BadPostAtomicRoot,
    /// Error in the data layer.
    DataLayerError(D),
    /// Error in the atomic commit/rollback mechanism.
    AtomicLayerError(AtomicError<A>),
    /// Error in trie layer caused by passing-on bad data. This generally
    /// implies a software bug.
    BadTrieData(ImplFatalKind),
    /// Error in the trie layer caused by a backend issue. This generally
    /// implies corrupted database.
    TrieLayerError(trie_db::TrieError<[u8; 32], trie_db::CError<commitment::CommitSchema>>),
}

impl<D, A> From<ValidationError> for Error<D, A> {
    fn from(value: ValidationError) -> Self {
        Error::ValidationError(value)
    }
}

impl<D, A> From<BackendError<D, A>> for Error<D, A> {
    fn from(value: BackendError<D, A>) -> Self {
        Error::BackendError(value)
    }
}

impl<'a, D, A> From<commitment::botanix::Error<'a>> for Error<D, A> {
    fn from(value: commitment::botanix::Error<'a>) -> Self {
        match value {
            commitment::botanix::Error::BadTrieOp { entry: _, kind } => {
                // TODO: Consider adding debug info on `entry`.
                Error::ValidationError(ValidationError::BadTrieOp(kind))
            }
            commitment::botanix::Error::ImplFatal(kind) => {
                Error::BackendError(BackendError::BadTrieData(kind))
            }
            commitment::botanix::Error::TrieFatal(err) => {
                Error::BackendError(BackendError::TrieLayerError(err))
            }
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
///     pending.insert_bitcoin_header_unchecked(block_hash, parent_hash)?;
///     pending.register_bitcoin_tx_unchecked(hash, tx, pegouts)?;
///     Ok(())
/// })?;
///
/// // Extract root for inclusion in block
/// let state_root = proof.compute_root();
///
/// // Finalization phase - verify and persist changes  
/// foundation.finalize_commitments(state_root, |pending| {
///     // Identical operations as proposal phase
///     pending.insert_bitcoin_header_unchecked(block_hash, parent_hash)?;
///     pending.register_bitcoin_tx_unchecked(hash, tx, pegouts)?;
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
pub struct Foundation<D, A> {
    /* PRIVATE! */
    data_layer: D,
    atomic_layer: A,
    block_tree: BlockTree,
    height: u64,
}

impl<D, A> Foundation<D, A>
where
    D: DataLayer,
    A: AtomicLayer,
    Error<D::Error, A::BackendError>: From<D::Error>,
    Error<D::Error, A::BackendError>: From<AtomicError<A::BackendError>>,
{
    /// Creates a new Foundation instance with the specified data layer,
    /// commitment layer, and initial Bitcoin block.
    //
    // TODO: There must be a way to preload the `BlockTree` from the local
    // database.
    pub fn new(
        data_layer: D,
        mut atomic_layer: A,
        block_hash: BlockHash,
        height: u64,
    ) -> Result<Self, Error<D::Error, A::BackendError>> {
        // Commit the initial block hash.
        {
            let mut l = atomic_layer.start_db_tx()?;
            l.bitcoin_header(&block_hash, &vec![].into())?;
            std::mem::drop(l);

            atomic_layer.commit()?;
        }

        Ok(Foundation {
            data_layer,
            atomic_layer,
            block_tree: BlockTree::new(block_hash, 3).unwrap(), // TODO
            height,
        })
    }
    pub fn commitment_root(&self) -> Result<CommitmentStateRoot, Error<D::Error, A::BackendError>> {
        self.atomic_layer.root().map_err(Into::into)
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
    ) -> Result<CheckedFoundationProof<R>, Error<D::Error, A::BackendError>>
    where
        F: FnOnce(&mut CommitmentsDraft<D, A>) -> Result<R, Error<D::Error, A::BackendError>>,
    {
        let mut draft = CommitmentsDraft {
            data: &mut self.data_layer,
            // NOTE: We do a full copy of the block tree since it does not
            // implement a rollback mechanism natively. It's usually small
            // enough (~18 entries) such that a full copy is considered
            // inexpensive.
            block_tree: self.block_tree.clone(),
            layer: self.atomic_layer.start_db_tx()?,
            aux_msgs: Vec::new(),
            _p: std::marker::PhantomData,
        };

        let origin_root = draft.layer.root();

        // Handle the commitments within the closure, and acquire the
        // UPDATED state root.
        let res: Result<R, Error<D::Error, A::BackendError>> = f(&mut draft);
        let (_block_tree, foundation_state) = draft.into_foundation_state(self.height);

        // ROLLBACK: Always reset state after construction, on both success or
        // failure.
        let reset_root = self.atomic_layer.rollback()?;

        // Essentially a sanity check.
        if reset_root != origin_root {
            return Err(BackendError::BadPostAtomicRoot.into());
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
    ) -> Result<CheckedFoundationProof<R>, Error<D::Error, A::BackendError>>
    where
        F: FnOnce(&mut CommitmentsDraft<D, A>) -> Result<R, Error<D::Error, A::BackendError>>,
    {
        let mut draft = CommitmentsDraft {
            data: &mut self.data_layer,
            // NOTE: We do a full copy of the block tree since it does not
            // implement a rollback mechanism natively. It's usually small
            // enough (~18 entries) such that a full copy is considered
            // inexpensive.
            block_tree: self.block_tree.clone(),
            layer: self.atomic_layer.start_db_tx()?,
            aux_msgs: Vec::new(),
            _p: std::marker::PhantomData,
        };

        let origin_root = draft.layer.root();

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
                    return Err(BackendError::BadPostAtomicRoot.into());
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
                return Err(BackendError::BadPostAtomicRoot.into());
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

            Ok(CheckedFoundationProof {
                _foundation_state: foundation_state,
                _extra_val: extra_val,
            })
        } else {
            // ROLLBACK: Bad expected root; discard state!
            let reset_root = self.atomic_layer.rollback()?;

            // Essentially a sanity check.
            if reset_root != origin_root {
                return Err(BackendError::BadPostAtomicRoot.into());
            }

            // Discard updated block tree.
            std::mem::drop(block_tree);

            Err(ValidationError::BadFoundationStateRoot.into())
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
pub struct CommitmentsDraft<'db, D, A> {
    data: &'db mut D,
    block_tree: BlockTree,
    layer: BotanixLayer<'db>,
    aux_msgs: Vec<AuxEvent>,
    _p: std::marker::PhantomData<A>,
}

impl<'db, D, A> CommitmentsDraft<'db, D, A>
where
    D: DataLayer,
    A: AtomicLayer,
    Error<D::Error, A::BackendError>: From<D::Error>,
    Error<D::Error, A::BackendError>: From<AtomicError<A::BackendError>>,
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
    pub fn initiate_pegout(
        &mut self,
        multisig: MultisigId,
        pegout: PegoutWithId,
    ) -> Result<(), Error<D::Error, A::BackendError>> {
        self.layer.initiate_pegout(&multisig, &pegout)?;

        self.aux_msgs.push(AuxEvent::InitiatedPegout {
            multisig,
            pegout: pegout.id,
        });

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
    // TODO: Add a variant that mandates a `CheckedBitcoinHeader`.
    pub fn insert_bitcoin_header_unchecked(
        &mut self,
        block_hash: BlockHash,
        parent_hash: BlockHash,
    ) -> Result<(), Error<D::Error, A::BackendError>> {
        // VALIDATE: Insert the Bitcoin header into the commitment layer. We're
        // just using an empty Txid list.
        self.layer.bitcoin_header(&block_hash, &vec![].into())?;

        self.aux_msgs.push(AuxEvent::NewBitcoinHeader {
            block_hash: block_hash.into(),
        });

        // Insert the new Bitcoin header and retrieve any resulting prune events.
        let pruned = self
            .block_tree
            .insert(block_hash, parent_hash)
            .map_err(|_| ValidationError::BadBitcoinHeader)?;

        if pruned.is_empty() {
            // Nothing left to do.
            return Ok(());
        }

        for p in pruned {
            // Retrieve all tracked Txids for that pruned block hash.
            let txids: Sorted<Txid> = self.data.get_txids_by_block_hash(p.block_hash())?.into();

            // Retrieve all pegouts for each Txid.
            //
            // NOTE: It's important that we only sort the inner pegout list; we
            // must maintain the ordering of the Txid listing, such that each
            // Txid corresponds to the correct pegout list.
            let pegouts: Vec<Sorted<PegoutWithId>> = txids
                .iter()
                .map(|txid| self.data.get_pegouts_by_txid(&txid).map(Into::into))
                .collect::<Result<_, D::Error>>()?;

            // VALIDATE: Prune headers from the commitment layer.
            match p {
                BlockFate::Finalized(block_hash) => {
                    // Finalized pegouts are gone and unspendable, indefinitely.
                    self.layer
                        .bitcoin_header_finalize(&block_hash, &txids, &pegouts)?;

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
                    // Orhpaned pegouts are moved into the *delayed* set, ready
                    // to be spent again.
                    self.layer
                        .bitcoin_header_orphan(&block_hash, &txids, &pegouts)?;

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
    //
    // TODO: Add a variant that mandates a `CheckedBitcoinTransaction`.
    pub fn register_bitcoin_tx_unchecked(
        &mut self,
        block_hash: BlockHash,
        tx: bitcoin::Transaction,
        pegouts: Vec<PegoutId>,
    ) -> Result<(), Error<D::Error, A::BackendError>> {
        // VALIDATE: Pegout list must not be empty.
        if pegouts.is_empty() {
            return Err(ValidationError::EmptyPegoutList.into());
        }

        // Retrieve the full pegout data for each pegout Id.
        let pegouts: Vec<PegoutWithId> = pegouts
            .into_iter()
            .map(|id| {
                let data = self
                    .data
                    .get_pegout_by_id(&id)?
                    .ok_or(ValidationError::PegoutDoesNotExist)?;

                Ok(PegoutWithId { id, data })
            })
            .collect::<Result<_, Error<D::Error, A::BackendError>>>()?;

        // Used for PegoutId duplicate checking.
        let mut used_ids = HashSet::new();

        // Convert lists to VecDeque since it's easier to work with.
        let mut queue_tx_out: VecDeque<TxOut> = VecDeque::from(tx.output.clone());
        let mut queue_pegouts: VecDeque<PegoutWithId> = VecDeque::from(pegouts.clone());

        while let Some((tx_out, pegout)) = queue_tx_out.pop_front().zip(queue_pegouts.pop_front()) {
            // VALIDATE: The pegout is in an initiated state.
            //
            // This is essentially the sanity check; the later call to
            // `BotanixLayer::register_bitcoin_tx` checks this internally as well.
            self.layer.check_initiated_pegout(&MULTISIG, &pegout)?;

            // VALIDATE: Output value must be equal or less (fee-adjustment)
            // then the pegout amount.
            if pegout.data.amount < tx_out.value {
                return Err(ValidationError::TxOutValueExceedsPegoutAmount.into());
            }

            // VALIDATE: Output scriptPubkey matches the pegout destination.
            if !pegout
                .data
                .destination
                .matches_script_pubkey(&tx_out.script_pubkey)
            {
                return Err(ValidationError::TxOutDestNotMatchingPegoutDest.into());
            }

            // VALIDATE: PegoutId may not be reused.
            if !used_ids.insert(pegout.id) {
                return Err(ValidationError::PegoutIdReused.into());
            }
        }

        // VALIDATE: Optional change address.
        if let Some(change) = queue_tx_out.pop_front() {
            // TODO: Validate change - right now we always return an error.
            return Err(ValidationError::TxOutReturnBadChange.into());
        }

        // VALIDATE: All Bitcoin transaction outputs have been processed.
        if !queue_tx_out.is_empty() {
            // Transaction contains more fields
            return Err(ValidationError::TxOutputsRemainingUnchecked.into());
        }

        // VALIDATE: All passed-on pegouts have been processed.
        if !queue_pegouts.is_empty() {
            return Err(ValidationError::PegoutListRemainingUnchecked.into());
        }

        debug_assert!(queue_pegouts.is_empty());
        debug_assert!(queue_tx_out.is_empty());

        let computed_txid = tx.compute_txid();

        // Retrieve any tracked Txids for the given block hash.
        let tracked_txids = self.data.get_txids_by_block_hash(&block_hash)?;

        // VALIDATE: Txis has not been registered already.
        // NOTE: The commitment layer checks this as well.
        if tracked_txids.contains(&computed_txid) {
            return Err(ValidationError::TxidAlreadyRegistered.into());
        }

        // Construct updated Txids for the given block hash.
        let mut updated_txids = tracked_txids.clone();
        updated_txids.push(computed_txid);

        // Sort lists appropriately.
        let tracked_txids: Sorted<Txid> = tracked_txids.into();
        let updated_txids: Sorted<Txid> = updated_txids.into();
        let pegouts: Sorted<PegoutWithId> = pegouts.into();

        // COMMIT: Register Bitcoin transaction with the commitment layer.
        self.layer.register_bitcoin_tx(
            &block_hash,
            &MULTISIG,
            &tracked_txids,
            &updated_txids,
            &computed_txid,
            &pegouts,
        )?;

        let pegouts: Sorted<PegoutId> = pegouts.into_iter().map(|pegout| pegout.id).collect();

        self.aux_msgs.push(AuxEvent::RegisterBitcoinTx {
            block_hash: block_hash.into(),
            txid: computed_txid.into(),
            pegouts,
        });

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
        let commitments = self.layer.root();
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
