//! # Botanix Validation Module
//!
//! This module provides validation capabilities for Botanix
//! (Ethereum-compatible) blockchain data, including header verification against
//! Tendermint consensus and Merkle Patricia Tree proof generation and
//! verification.
//!
//! ## Key Features
//!
//! - **Cross-Chain Header Validation**: Validates Botanix headers against
//!   corresponding Tendermint block commitments
//! - **Merkle Patricia Tree Operations**: Generates and verifies proofs for
//!   transactions and receipts using Merkle Patricia tries
//! - **Transaction and Receipt Proofs**: Creates cryptographic proofs that
//!   transactions and receipts are included in specific blocks
//!
//! ## Proof Systems
//!
//! The module implements Ethereum-compatible Merkle Patricia Tree proofs for:
//! - **Transaction Trees**: Proving transaction inclusion in blocks
//! - **Receipt Trees**: Proving receipt inclusion with bloom filters
//! - **Root Computation**: Computing transaction and receipt tree roots
//!
//! ## Integration
//!
//! This module bridges Botanix's execution layer with Tendermint's consensus
//! layer, ensuring that Botanix block data matches the commitments made by
//! Tendermint validators.
//!
//! ## Main Types
//!
//! - [`CheckedBotanixHeader`]: A validated Botanix header verified against
//!       Tendermint
use crate::{
    primitives::{BotanixHeader, Receipt, ReceiptWithBloom, TransactionSigned},
    structs::merkle_patricia::{self, MerklePatriciaProof},
    validation::tendermint::CheckedTendermintHeader,
};

/// Errors that can occur during Botanix header validation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The computed Botanix header hash doesn't match the Tendermint app hash,
    /// indicating the header is not from the same block or one has been
    /// tampered with.
    AppHashMismatch { expected: [u8; 32], got: [u8; 32] },
}

/// A validated Botanix header with cryptographic verification against
/// Tendermint.
///
/// This wrapper ensures that the Botanix header has been validated against a
/// trusted Tendermint header by verifying that the computed Botanix header's
/// hash matches the `app_hash` committed in the Tendermint block. The inner
/// header and computed hash are kept private to prevent direct modification.
#[derive(Debug, Clone)]
pub struct CheckedBotanixHeader {
    /* PRIVATE! */ _header: BotanixHeader,
    hash: [u8; 32],
}

impl AsRef<BotanixHeader> for CheckedBotanixHeader {
    fn as_ref(&self) -> &BotanixHeader {
        &self._header
    }
}

impl CheckedBotanixHeader {
    /// Creates a new validated Botanix header by verifying it against a
    /// Tendermint header.
    ///
    /// This method validates that the Botanix header is authentic by:
    /// - Computing the hash of the Botanix header
    /// - Comparing it against the `app_hash` field in the validated Tendermint
    ///   header
    ///
    /// # Arguments
    ///
    /// * `untrusted` - The Botanix header to validate
    /// * `checked` - A validated Tendermint header containing the expected app
    ///   hash
    ///
    /// # Returns
    ///
    /// A new `CheckedBotanixHeader` if validation succeeds, or an error if the
    /// header hash doesn't match the Tendermint app hash.
    ///
    /// # Errors
    ///
    /// - `AppHashMismatch` if the computed Botanix header hash doesn't match
    ///   the app hash committed in the Tendermint header
    pub fn new(untrusted: BotanixHeader, checked: &CheckedTendermintHeader) -> Result<Self, Error> {
        let computed_hash: [u8; 32] = untrusted.hash_slow().into();

        let expected: [u8; 32] = checked
            .as_ref()
            .app_hash
            .as_bytes()
            .try_into()
            .expect("appHash must be 32-bytes");

        if expected != computed_hash {
            return Err(Error::AppHashMismatch {
                expected,
                got: computed_hash,
            });
        }

        let trusted = untrusted;

        Ok(CheckedBotanixHeader {
            _header: trusted,
            hash: computed_hash.into(),
        })
    }
    /// Returns the validated hash of the Botanix header.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
}

/// Computes the Merkle Patricia Tree root hash for a collection of
/// transactions.
///
/// This function encodes each transaction and builds a Merkle Patricia Tree to
/// compute the root hash that represents all transactions in the collection, as
/// performed by the Botanix consensus layer. This root is typically used in
/// block headers for verification purposes.
///
/// # Arguments
///
/// * `txs` - Slice of signed transactions to include in the tree
///
/// # Returns
///
/// A 32-byte root hash of the constructed Merkle Patricia Tree.
pub fn compute_transactions_root(txs: &[TransactionSigned]) -> [u8; 32] {
    let items: Vec<Vec<u8>> = txs
        .into_iter()
        .map(|tx| {
            let mut item = vec![];
            tx.encode_inner(&mut item, false);
            item
        })
        .collect();

    merkle_patricia::compute_root(&items)
}

/// Generates a Merkle Patricia proof for a specific transaction in a
/// collection.
///
/// Creates a cryptographic proof that a specific transaction exists at a given
/// position within a collection of transactions, optionally validating against
/// an expected root hash.
///
/// # Arguments
///
/// * `txs` - Slice of all transactions in the tree
/// * `leaf_index` - Index of the transaction to generate a proof for
/// * `expected_root` - Optional root hash to validate the proof against
///
/// # Returns
///
/// A `MerklePatriciaProof` that can be used to verify the transaction's
/// inclusion, or an error if proof generation fails
pub fn compute_transaction_proof(
    txs: &[TransactionSigned],
    leaf_index: usize,
    expected_root: Option<[u8; 32]>,
) -> Result<MerklePatriciaProof, merkle_patricia::Error> {
    let items: Vec<Vec<u8>> = txs
        .into_iter()
        .map(|tx| {
            let mut item = vec![];
            tx.encode_inner(&mut item, false);
            item
        })
        .collect();

    merkle_patricia::compute_proof(&items, leaf_index, expected_root)
}

/// Verifies that a transaction is included in a Merkle Patricia Tree.
///
/// Uses a cryptographic proof to validate that the given transaction exists at
/// the specified position in a tree with the given root hash.
///
/// # Arguments
///
/// * `tx` - The transaction to verify inclusion for
/// * `proof` - Merkle Patricia proof of the transaction's inclusion
/// * `root_hash` - Expected root hash of the tree containing the transaction
///
/// # Returns
///
/// `Ok(())` if the transaction is proven to be included, or an error if
/// verification fails.
pub fn verify_transaction_proof(
    tx: &TransactionSigned,
    proof: &MerklePatriciaProof,
    root_hash: &[u8; 32],
) -> Result<(), merkle_patricia::Error> {
    let mut item = vec![];
    tx.encode_inner(&mut item, false);

    merkle_patricia::verify_proof(&item, &proof, &root_hash)
}

/// Computes the Merkle Patricia Tree root hash for a collection of receipts.
///
/// This function encodes each receipt with its bloom filter and builds a Merkle
/// Patricia Tree to compute the root hash as performed by a Botanix consensus
/// layer that can be used for verification purposes.
///
/// # Arguments
///
/// * `receipts` - Vector of transaction receipts to include in the tree
///
/// # Returns
///
/// A 32-byte root hash of the constructed Merkle Patricia Tree
pub fn compute_receipts_root(receipts: Vec<Receipt>) -> [u8; 32] {
    let items: Vec<Vec<u8>> = receipts
        .into_iter()
        .map(|receipt| {
            let mut item = vec![];

            // TODO: Implement a `ReceiptWithBloomRef<'a>` option
            ReceiptWithBloom {
                bloom: receipt.logs_bloom(),
                receipt,
            }
            .encode_inner(&mut item, false);

            item
        })
        .collect();

    merkle_patricia::compute_root(&items)
}

/// Generates a Merkle Patricia proof for a specific receipt in a collection.
///
/// Creates a cryptographic proof that a specific receipt exists at a given
/// position within a collection of receipts, optionally validating against an
/// expected root hash.
///
/// # Arguments
///
/// * `receipts` - Vector of all receipts in the tree
/// * `leaf_index` - Index of the receipt to generate a proof for
/// * `expected_root` - Optional root hash to validate the proof against
///
/// # Returns
///
/// A `MerklePatriciaProof` that can be used to verify the receipt's inclusion,
/// or an error if proof generation fails.
pub fn compute_receipt_proof(
    receipts: Vec<Receipt>,
    leaf_index: usize,
    expected_root: Option<[u8; 32]>,
) -> Result<MerklePatriciaProof, merkle_patricia::Error> {
    let items: Vec<Vec<u8>> = receipts
        .into_iter()
        .map(|receipt| {
            let mut item = vec![];

            // TODO: Implement a `ReceiptWithBloomRef<'_>` type.
            ReceiptWithBloom {
                bloom: receipt.logs_bloom(),
                receipt,
            }
            .encode_inner(&mut item, false);

            item
        })
        .collect();

    merkle_patricia::compute_proof(&items, leaf_index, expected_root)
}

/// Verifies that a receipt is included in a Merkle Patricia Tree.
///
/// Uses a cryptographic proof to validate that the given receipt exists at the
/// specified position in a tree with the given root hash.
///
/// # Arguments
///
/// * `receipt` - The receipt to verify inclusion for
/// * `proof` - Merkle Patricia proof of the receipt's inclusion
/// * `root_hash` - Expected root hash of the tree containing the receipt
///
/// # Returns
///
/// `Ok(())` if the receipt is proven to be included, or an error if
/// verification fails.
pub fn verify_receipt_proof(
    receipt: Receipt,
    proof: &MerklePatriciaProof,
    root_hash: &[u8; 32],
) -> Result<(), merkle_patricia::Error> {
    let mut item = vec![];
    ReceiptWithBloom {
        bloom: receipt.logs_bloom(),
        receipt,
    }
    .encode_inner(&mut item, false);

    merkle_patricia::verify_proof(&item, &proof, &root_hash)
}
