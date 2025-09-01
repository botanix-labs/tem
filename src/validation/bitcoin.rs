//! # Bitcoin Validation Module
//!
//! This module provides validation capabilities for Bitcoin blockchain data,
//! focusing on proof-of-work verification and transaction inclusion proofs.
//! It ensures that Bitcoin headers meet difficulty requirements and that
//! transactions are cryptographically proven to be included in valid blocks.
//!
//! ## Key Features
//!
//! - **Proof-of-Work Validation**: Verifies Bitcoin headers meet the required
//!   difficulty threshold using hardcoded minimum targets
//! - **Transaction Inclusion Proofs**: Validates transactions are included in
//!   Bitcoin blocks using partial Merkle tree proofs
//! - **Difficulty Enforcement**: Enforces minimum difficulty requirements to
//!   prevent acceptance of low-difficulty or fake blocks
//!
//! ## Security Model
//!
//! The module uses a hardcoded difficulty target based on Bitcoin block 840,000
//! (April 2024 halving) to ensure only legitimate Bitcoin blocks with
//! sufficient proof-of-work are accepted. This prevents attackers from creating
//! fake blocks without expending significant computational resources.
//!
//! ## Main Types
//!
//! - [`CheckedBitcoinHeader`]: A validated Bitcoin header that meets PoW requirements
//! - [`CheckedBitcoinTransaction`]: A validated transaction with inclusion proof
//!
//! These "Checked" types guarantee that the contained data has passed all
//! validation requirements and can be trusted for further processing.
use bitcoin::{
    BlockHash, CompactTarget, Target, Transaction, TxMerkleNode, Txid,
    block::{Header as BitcoinHeader, ValidationError},
    merkle_tree::{MerkleBlockError, PartialMerkleTree},
};

lazy_static::lazy_static! {
    /// The required target for the Bitcoin header to be considered valid. This
    /// is the exact target (`nBits`) of the Bitcoin block 840'000 at the April
    /// 2024 halving.
    ///
    /// ## Reference
    ///
    /// - [Block 840'000](https://www.blockchain.com/explorer/blocks/btc/0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5)
    //
    // TODO: Might be a little too strict, maybe?
    pub static ref REQUIRED_TARGET: Target = Target::from_compact(CompactTarget::from_consensus(386_089_497));
}

/// Errors that can occur during Bitcoin header and transaction validation.
///
/// These errors represent various validation failures when verifying Bitcoin
/// headers meet difficulty requirements and transactions are included in
/// blocks.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The header's provided difficulty target (nBits) is too low.
    NBitsDifficultyTooLow,
    /// The header failed proof-of-work validation against the required
    /// (hard-coded) difficulty target. This indicates insufficient
    /// computational work was performed.
    FailedPowTargetValidation(ValidationError),
    /// Error occurred while extracting matches from the merkle proof. This
    /// indicates a malformed or invalid partial merkle tree proof.
    MerkleRootError(MerkleBlockError),
    /// The computed merkle root doesn't match the expected root. This occurs
    /// when the partial merkle tree proof produces a different root hash than
    /// what's expected from the block header.
    MerkleRootMismatch {
        expected: TxMerkleNode,
        got: TxMerkleNode,
    },
    /// The transaction ID was not found in the merkle proof matches. This
    /// occurs when a transaction's computed TXID is not included in the set of
    /// transactions proven by the partial merkle tree.
    TxidNotIncluded { txid: Txid },
}

/// A validated Bitcoin header that meets difficulty and proof-of-work
/// requirements.
///
/// This wrapper ensures that the Bitcoin header has been validated to meet the
/// minimum difficulty target and has valid proof-of-work. The inner header and
/// computed block hash are kept private to prevent direct modification.
#[derive(Debug, Clone, Copy)]
pub struct CheckedBitcoinHeader {
    /* PRIVATE */ _header: BitcoinHeader,
    block_hash: BlockHash,
}

impl AsRef<BitcoinHeader> for CheckedBitcoinHeader {
    fn as_ref(&self) -> &BitcoinHeader {
        &self._header
    }
}

impl CheckedBitcoinHeader {
    /// Creates a new validated Bitcoin header by verifying difficulty and
    /// proof-of-work.
    ///
    /// This method validates that the Bitcoin header meets the system
    /// requirements by:
    /// - Checking that the difficulty target (nBits) meets the minimum required
    ///   target
    /// - Validating that the computed block hash satisfies the proof-of-work
    ///   requirement
    /// - Computing and storing the validated block hash
    ///
    /// # Arguments
    ///
    /// * `untrusted` - The Bitcoin header to validate
    ///
    /// # Returns
    ///
    /// A new `CheckedBitcoinHeader` if validation succeeds, or an error
    /// describing why validation failed.
    ///
    /// # Errors
    ///
    /// - `NBitsDifficultyTooLow` if the header's provided difficulty target is
    ///   too low
    /// - `FailedPowTargetValidation` if the proof-of-work validation fails
    pub fn new_checked(untrusted: BitcoinHeader) -> Result<Self, Error> {
        let nbits = Target::from_compact(untrusted.bits);
        // NOTE: The Bitcoin "difficulty" gets lower as it becomes harder.
        if nbits > *REQUIRED_TARGET {
            return Err(Error::NBitsDifficultyTooLow);
        }

        // VALIDATE: The computed Bitcoin header hash is below the required
        // target.
        let block_hash = untrusted
            .validate_pow(*REQUIRED_TARGET)
            .map_err(Error::FailedPowTargetValidation)?;

        let trusted = untrusted;

        Ok(Self {
            _header: trusted,
            block_hash,
        })
    }
    /// Returns the validated block hash of the Bitcoin header.
    pub fn block_hash(&self) -> &BlockHash {
        &self.block_hash
    }
}

/// A validated Bitcoin transaction with cryptographic proof of block inclusion.
///
/// This wrapper ensures that the Bitcoin transaction has been proven to be
/// included in a validated Bitcoin block using a partial merkle tree proof. The
/// inner transaction is kept private to prevent direct modification.
pub struct CheckedBitcoinTransaction {
    /* PRIVATE */ _header: Transaction,
    // The Bitcoin block this transaction is included in.
    block_hash: BlockHash,
}

impl AsRef<Transaction> for CheckedBitcoinTransaction {
    fn as_ref(&self) -> &Transaction {
        &self._header
    }
}

impl CheckedBitcoinTransaction {
    /// Creates a new validated Bitcoin transaction by verifying its inclusion
    /// proof.
    ///
    /// This method validates that the Bitcoin transaction is authentic by:
    /// - Verifying the partial merkle tree proof against the block's merkle
    ///   root
    /// - Ensuring the transaction's TXID is included in the proof
    /// - Confirming the proof produces the expected merkle root from the header
    ///
    /// # Arguments
    ///
    /// * `untrusted` - The Bitcoin transaction to validate
    /// * `proof` - Partial merkle tree proof of the transaction's inclusion
    /// * `checked` - A validated Bitcoin header containing the expected merkle
    ///   root
    ///
    /// # Returns
    ///
    /// A new `CheckedBitcoinTransaction` if validation succeeds, or an error
    /// describing why the proof verification failed.
    ///
    /// # Errors
    ///
    /// - `MerkleRootError` if the proof is malformed
    /// - `MerkleRootMismatch` if the proof doesn't produce the expected root
    /// - `TxidNotIncluded` if the transaction isn't included in the proof
    pub fn new_checked(
        untrusted: Transaction,
        proof: PartialMerkleTree,
        checked: &CheckedBitcoinHeader,
    ) -> Result<Self, Error> {
        verify_transaction_proof(&untrusted, proof, checked.as_ref().merkle_root.as_ref())?;
        let trusted = untrusted;

        Ok(CheckedBitcoinTransaction {
            _header: trusted,
            block_hash: checked.as_ref().block_hash(),
        })
    }
    pub fn block_hash(&self) -> &BlockHash {
        &self.block_hash
    }
}

/// Verifies that a Bitcoin transaction is included in a block using a merkle
/// proof.
///
/// This function validates transaction inclusion by:
/// - Extracting matches from the partial merkle tree proof
/// - Verifying the computed merkle root matches the expected root hash
/// - Confirming the transaction's TXID is among the extracted matches
///
/// This provides cryptographic proof that the transaction was included in the
/// block without requiring the full block data.
///
/// # Arguments
///
/// * `untrusted` - The Bitcoin transaction to verify inclusion for
/// * `proof` - Partial merkle tree proof of inclusion
/// * `root_hash` - Expected merkle root hash from the block header
///
/// # Returns
///
/// `Ok(())` if the transaction is proven to be included, or an error describing
/// why the proof verification failed.
///
/// # Errors
///
/// - `MerkleRootError` if the partial merkle tree is invalid
/// - `MerkleRootMismatch` if the computed root doesn't match expected
/// - `TxidNotIncluded` if the transaction isn't found in the proof matches
pub fn verify_transaction_proof(
    untrusted: &Transaction,
    proof: PartialMerkleTree,
    // TODO: Should this be `TxMerkleNode`?
    root_hash: &[u8; 32],
) -> Result<(), Error> {
    let mut matches = vec![];
    let mut indexes = vec![]; // TODO: Check this?

    let computed_txid = untrusted.compute_txid();
    let computed_root = proof
        .extract_matches(&mut matches, &mut indexes)
        .map_err(Error::MerkleRootError)?;

    let &hash = bitcoin::hashes::sha256d::Hash::from_bytes_ref(root_hash);
    let root_hash = TxMerkleNode::from_raw_hash(hash);

    // VALIDATE: Compare the computed root hash against the expected root.
    //
    // TODO: Look into that theoretical second pre-image attack, and whether it
    // is a concern.
    if root_hash != computed_root {
        return Err(Error::MerkleRootMismatch {
            expected: root_hash,
            got: computed_root,
        });
    }

    // VALIDATE: The computed Txid is included in the extracted matches.
    if !matches.contains(&computed_txid) {
        return Err(Error::TxidNotIncluded {
            txid: computed_txid,
        });
    }

    Ok(())
}
