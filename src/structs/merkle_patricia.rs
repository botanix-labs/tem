//! # Merkle Patricia Tree Implementation
//!
//! This module provides Merkle Patricia Tree operations compatible with
//! Ethereum's trie specification. It implements root computation, proof
//! generation, and proof verification for key-value data stored in a radix tree
//! structure.
//!
//! ## Key Features
//!
//! - **Ethereum Compatibility**: Follows Ethereum's Merkle Patricia Tree
//!   specification
//! - **RLP Index Adjustment**: Uses `adjust_index_for_rlp` to ensure proper trie
//!   structure and key distribution
//! - **Nibble-based Keys**: Uses nibble paths for efficient trie navigation
//! - **Compact Proofs**: Generates minimal proofs containing only necessary
//!   intermediate nodes
//!
//! ## Trie Structure
//!
//! The implementation uses a radix tree where:
//! - Keys are RLP-encoded indices converted to nibble paths
//! - Values are stored at leaf nodes
//! - Intermediate nodes contain hash commitments
//! - Proofs contain the path from root to leaf with all intermediate nodes
//!
//! ## RLP Index Adjustment
//!
//! The module uses `adjust_index_for_rlp` to transform array indices into
//! proper trie keys. This ensures bijective mapping and proper key distribution
//! across the trie structure.
//!
//! ## Proof Format
//!
//! Proofs consist of:
//! - **Nibbles**: The path to the leaf in the trie
//! - **Nodes**: Intermediate nodes sorted root-to-leaf for verification
//!
//! This format allows efficient verification without reconstructing the entire
//! trie.

use alloy_primitives::Bytes;
use alloy_trie::{
    EMPTY_ROOT_HASH, HashBuilder, Nibbles, proof::ProofRetainer, root::adjust_index_for_rlp,
};

/// Errors that can occur during Merkle Patricia Trie operations.
///
/// These errors represent various validation failures when computing roots,
/// generating proofs, or verifying proofs in the Merkle Patricia Trie.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Attempted to operate on an empty list of items.
    EmptyItems,
    /// The specified leaf index is out of bounds.
    BadLeafIndex,
    /// The computed root doesn't match the expected root during proof generation.
    BadExpectedRoot { expected: [u8; 32], got: [u8; 32] },
    /// The proof verification failed against the provided root hash.
    BadProof,
}

/// A cryptographic proof for inclusion in a Merkle Patricia Trie.
///
/// Contains the path (nibbles) to the leaf and the intermediate nodes needed to
/// verify that a specific item exists in the trie with a known root hash. This
/// follows the Ethereum specification for Merkle Patricia Trie proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePatriciaProof {
    /// The nibble path to the leaf in the trie.
    pub nibbles: Nibbles,
    /// The intermediate nodes along the path, sorted root-to-leaf.
    pub nodes: Vec<Bytes>,
}

// TODO
#[test]
fn run_rlp_adj() {
    for i in 0..130 {
        let adj = adjust_index_for_rlp(i, 130);
        println!("i: {i}, adj: {adj}");
    }
}

/// Computes the Merkle Patricia Trie root hash for a collection of items.
///
/// Builds the Merkle Patricia Trie where each item is stored at a key derived
/// from its RLP-adjusted index. Returns the empty root hash for empty
/// collections.
///
/// # Arguments
///
/// * `items` - Collection of items that can be converted to byte slices
///
/// # Returns
///
/// A 32-byte root hash of the constructed Merkle Patricia Trie
///
/// # Note
///
/// Uses RLP index adjustment to ensure proper trie structure and key
/// distribution.
pub fn compute_root<T: AsRef<[u8]>>(items: &[T]) -> [u8; 32] {
    if items.is_empty() {
        return EMPTY_ROOT_HASH.into();
    }

    let items_len = items.len();
    let mut trie = HashBuilder::default();

    for i in 0..items_len {
        // Adjust the indices for RLP encoding.
        // TODO: Do a test where `i=127` exists
        // TODO: Clarify that this is fully bijective.
        let idx = adjust_index_for_rlp(i, items_len);

        // Encode the key
        let rlp = alloy_rlp::encode_fixed_size(&idx);
        let key = Nibbles::unpack(&rlp);

        // Insert the key-value pair into the trie
        trie.add_leaf(key, &items[idx].as_ref());
    }

    trie.root().into()
}

/// Generates a Merkle Patricia Trie proof for an item at the specified index.
///
/// Creates a cryptographic proof that demonstrates a specific item exists at
/// the given position in the trie. The proof contains the path (nibbles) and
/// all intermediate nodes needed for verification. Optionally validates the
/// generated proof against an expected root hash.
///
/// # Arguments
///
/// * `items` - The complete collection of items in the trie
/// * `leaf_index` - Index of the item to generate a proof for
/// * `expected_root` - Optional root hash to validate the proof against
///
/// # Returns
///
/// A `MerklePatriciaProof` for verifying the item's inclusion, or an error if
/// generation fails.
///
/// # Errors
///
/// - `EmptyItems` if the collection is empty
/// - `BadLeafIndex` if the index is out of bounds
/// - `BadExpectedRoot` if the optional expected root doesn't match the computed
///   root
///
/// # Note
///
/// The proof nodes are sorted in root-to-leaf order for verification purposes.
pub fn compute_proof<T: AsRef<[u8]>>(
    items: &[T],
    leaf_index: usize,
    expected_root: Option<[u8; 32]>,
) -> Result<MerklePatriciaProof, Error> {
    if items.is_empty() {
        return Err(Error::EmptyItems);
    }

    let items_len = items.len();

    if leaf_index >= items_len {
        return Err(Error::BadLeafIndex);
    }

    let rlp = alloy_rlp::encode_fixed_size(&leaf_index);
    let nibbles = Nibbles::unpack(&rlp);

    // Setup a proof retainer and the trie builder.
    let retainer = ProofRetainer::new(vec![nibbles]);
    let mut trie = HashBuilder::default().with_proof_retainer(retainer);

    for i in 0..items_len {
        // Adjust the indices for RLP encoding.
        // TODO: Do a test where `i=127` exists
        let idx = adjust_index_for_rlp(i, items_len);

        // Encode the key
        let rlp = alloy_rlp::encode_fixed_size(&idx);
        let key = Nibbles::unpack(&rlp);

        // Insert the key-value pair into the trie
        trie.add_leaf(key, &items[idx].as_ref());
    }

    if let Some(expected_root) = expected_root {
        let computed_root: [u8; 32] = trie.root().into();

        if expected_root != computed_root {
            return Err(Error::BadExpectedRoot {
                expected: expected_root,
                got: computed_root,
            });
        }
    }

    // Find the matching nibble-node pairs for the key.
    let mut nodes = trie.take_proof_nodes().matching_nodes(&nibbles);

    // Sorty by nibble in ascending order (root-to-leaf).
    nodes.sort_by(|(n0, _), (n1, _)| n0.cmp(&n1));

    // Filter out the nibbles, only retain the nodes.
    let nodes = nodes.into_iter().map(|(_, node)| node).collect();

    Ok(MerklePatriciaProof { nibbles, nodes })
}

/// Verifies that an item is included in a Merkle Patricia Trie using a proof.
///
/// Uses the provided proof to validate that the item exists at the specified
/// path in a trie with the given root hash.
///
/// # Arguments
///
/// * `item` - The item to verify inclusion for
/// * `proof` - The Merkle Patricia proof demonstrating inclusion
/// * `root_hash` - The expected root hash of the trie
///
/// # Returns
///
/// `Ok(())` if the item is proven to be included, or an error if verification
/// fails.
///
/// # Errors
///
/// - `BadProof` if the proof verification fails, indicating the item is not
///   included or the proof is malformed.
pub fn verify_proof<T: AsRef<[u8]>>(
    item: &T,
    proof: &MerklePatriciaProof,
    root_hash: &[u8; 32],
) -> Result<(), Error> {
    // Verify proof against root.
    // TODO: Is there a better way than doing `item.as_ref().to_vec()`?
    alloy_trie::proof::verify_proof(
        root_hash.into(),
        proof.nibbles,
        Some(item.as_ref().to_vec()),
        &proof.nodes,
    )
    .map_err(|_| Error::BadProof)
}
