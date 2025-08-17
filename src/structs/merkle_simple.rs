//! # Simple Merkle Tree Implementation
//!
//! This module provides functions to compute Merkle roots, generate Merkle
//! proofs, and verify those proofs. This implementation follows the
//! specification identical to the one used by CometBFT (RFC 6962). Notably,
//! leaf nodes and inner nodes use different prefixes for their hashes to
//! protect against "second pre-image attacks", meaning the proof of an inner
//! node being valid as the proof of a leaf. Bitcoin's Merkle tree is vulnerable
//! to this attack.
//!
//! ## Key Features
//!
//! - **CometBFT Compatibility**: Follows the exact specification used by
//!   CometBFT/Tendermint consensus
//! - **Security**: Uses prefix-based hashing (`0x00` for leaves, `0x01` for
//!   inner nodes) to prevent second pre-image attacks
//! - **Deterministic**: Recursive splitting at the largest power of 2 ensures
//!   consistent tree structure
//! - **Proof Generation**: Creates compact inclusion proofs using "aunt" hashes
//!
//! ## Tree Construction
//!
//! The implementation uses recursive splitting where the split point is always
//! the largest power of 2 less than the collection size. This ensures a
//! deterministic tree structure that can be reproduced independently.
//!
//! ## Security Model
//!
//! - **Leaf Hash**: `SHA256(0x00 || leaf_data)`
//! - **Inner Hash**: `SHA256(0x01 || left_hash || right_hash)`
//! - **Empty Hash**: `SHA256([])`
//!
//! This prefix system prevents attackers from using inner node hashes as leaf
//! hashes, eliminating second pre-image vulnerabilities.
//!
//! ## Reference
//!
//! - [CometBFT Merkle Trees](https://docs.cometbft.com/v0.38/spec/core/encoding#merkle-trees)
//! - [RFC 6962 - Certificate Transparency](https://tools.ietf.org/rfc/rfc6962.txt)

use sha2::{Digest, Sha256};

/// Errors that can occur during Merkle tree operations.
///
/// These errors represent various validation failures when computing roots,
/// generating proofs, or verifying proofs in the Merkle tree implementation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Attempted to operate on an empty list of items.
    EmptyItems,
    /// The specified leaf index is out of bounds for the tree.
    BadLeafIndex,
    /// The computed root doesn't match the expected root during proof
    /// generation.
    BadExpectedRoot { expected: [u8; 32], got: [u8; 32] },
    /// The proof verification failed against the provided root hash.
    BadProof { expected: [u8; 32], got: [u8; 32] },
}

/// A cryptographic proof that a specific leaf exists in a Merkle tree.
///
/// Contains all information needed to verify leaf inclusion without the full
/// tree data. Uses "aunt" hashes (sibling hashes at each level) to reconstruct
/// the path from leaf to root.
//
// TODO: Should use u64 instead of usize?
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// The total number of leaves in the original Merkle tree.
    pub total_leaves: usize,
    /// The index of the leaf in the original list of items.
    pub leaf_index: usize,
    /// The aunt hashes collected during proof generation in leaf-to-root order.
    pub aunts: Vec<[u8; 32]>,
}

/// Computes the Merkle root hash for a collection of items.
///
/// Builds a binary Merkle tree following the CometBFT specification with
/// prefix-based hashing to prevent second pre-image attacks. Uses recursive
/// splitting at the largest power of 2 less than the collection size.
///
/// # Arguments
///
/// * `items` - Collection of items that can be converted to byte slices
///
/// # Returns
///
/// A 32-byte root hash representing the entire collection
pub fn compute_root<T: AsRef<[u8]>>(items: &[T]) -> [u8; 32] {
    match items.len() {
        0 => empty_hash(),
        1 => leaf_hash(items[0].as_ref()),
        _ => {
            let k = get_split_point(items.len());
            let left = compute_root(&items[..k]);
            let right = compute_root(&items[k..]);
            inner_hash(&left, &right)
        }
    }
}

/// Generates a Merkle proof for a leaf at the specified index.
///
/// Creates a cryptographic proof demonstrating that a specific item exists at
/// the given position. Optionally validates the generated proof against an
/// expected root hash.
///
/// # Arguments
///
/// * `items` - The complete collection of items in the tree
/// * `leaf_index` - Index of the item to generate a proof for
/// * `expected_root` - Optional root hash to validate the proof against
///
/// # Returns
///
/// A `MerkleProof` for verifying the item's inclusion, or an error if
/// generation fails
///
/// # Errors
///
/// - `EmptyItems` if the collection is empty
/// - `BadLeafIndex` if the index is out of bounds
/// - `BadExpectedRoot` if the optional expected root doesn't match
pub fn compute_proof<T: AsRef<[u8]>>(
    items: &[T],
    leaf_index: usize,
    expected_root: Option<[u8; 32]>,
) -> Result<MerkleProof, Error> {
    if items.is_empty() {
        return Err(Error::EmptyItems);
    }

    if leaf_index >= items.len() {
        return Err(Error::BadLeafIndex);
    }

    let mut aunts = Vec::new();
    collect_aunts(items, leaf_index, &mut aunts);

    // The proof was constructed by walking down the tree, resulting in the
    // aunts being in a root-to-leaf order. So we simply reverse the
    // collection to get the leaf-to-root order required for verification,
    // as specified in the spec.
    aunts.reverse();

    let proof = MerkleProof {
        leaf_index,
        total_leaves: items.len(),
        aunts,
    };

    if let Some(expected_root) = expected_root {
        let leaf_hash = leaf_hash(items[leaf_index].as_ref());

        #[rustfmt::skip]
        let computed_root = compute_hash_from_aunts(
            leaf_index,
            proof.total_leaves,
            &leaf_hash,
            &proof.aunts
        );

        if expected_root != computed_root {
            return Err(Error::BadExpectedRoot {
                expected: expected_root,
                got: computed_root,
            });
        }
    }

    Ok(proof)
}

/// Verifies that an item is included in a Merkle tree using a proof.
///
/// Reconstructs the path from the item to the root using the proof's aunt
/// hashes and validates that the computed root matches the expected root hash.
///
/// # Arguments
///
/// * `item` - The item to verify inclusion for
/// * `proof` - The Merkle proof demonstrating inclusion
/// * `root_hash` - The expected root hash of the tree
///
/// # Returns
///
/// `Ok(())` if the item is proven to be included, or an error if verification
/// fails
///
/// # Errors
///
/// - `BadLeafIndex` if the proof's leaf index is invalid
/// - `BadProof` if the reconstructed root doesn't match the expected root
pub fn verify_proof<T: AsRef<[u8]>>(
    item: &T,
    proof: &MerkleProof,
    root_hash: &[u8; 32],
) -> Result<(), Error> {
    if proof.leaf_index >= proof.total_leaves {
        return Err(Error::BadLeafIndex);
    }

    let leaf_hash = leaf_hash(item.as_ref());

    let computed_root = compute_hash_from_aunts(
        proof.leaf_index,
        proof.total_leaves,
        &leaf_hash,
        proof.aunts.as_slice(),
    );

    if root_hash != &computed_root {
        return Err(Error::BadProof {
            expected: *root_hash,
            got: computed_root,
        });
    }

    Ok(())
}

/// Collects the aunt hashes by walking down the tree.
///
/// "Aunts" are sibling hashes at each level of the tree needed to compute the
/// path from leaf to root.
///
/// ## Warning
///
/// This function naturally collects the aunts in a root-to-leaf order, so the
/// collection must be reversed before creating the `MerkleProof` type, which
/// expects a leaf-to-root order.
///
/// # Example
///
/// For tree with 4 leaves [A, B, C, D], proving leaf B (index 1):
///
/// ```text
///        Root
///       /    \
///    Hash1    Hash2  <- Hash2 is aunt at this level
///    /  \     /   \
///   A    B   C     D
///   ^
///   |
///   A is aunt at this level
/// ```
///
/// ## Construction process
///
/// 1. Start at root with full range [A,B,C,D], target index 1
/// 2. Split at point 2: left=[A,B], right=[C,D]
/// 3. Index 1 < 2, so go left. Collect Hash2 as aunt
/// 4. Now in left subtree [A,B], target index 1
/// 5. Split at point 1: left=[A], right=[B]
/// 6. Index 1 >= 1, so go right. Collect A as aunt
/// 7. Reached target leaf B
/// 8. Final aunts = [Hash2, A]
fn collect_aunts<T: AsRef<[u8]>>(items: &[T], target_index: usize, aunts: &mut Vec<[u8; 32]>) {
    if items.len() <= 1 {
        // Base case: we've reached the target leaf
        return;
    }

    let split_point = get_split_point(items.len());

    if target_index < split_point {
        // Target is in LEFT subtree
        // Collect RIGHT subtree hash as aunt
        let right_hash = compute_root(&items[split_point..]);
        aunts.push(right_hash);

        // Recurse into left subtree
        collect_aunts(&items[..split_point], target_index, aunts);
    } else {
        // Target is in RIGHT subtree
        // Collect LEFT subtree hash as aunt
        let left_hash = compute_root(&items[..split_point]);
        aunts.push(left_hash);

        // Recurse into right subtree with adjusted index
        collect_aunts(&items[split_point..], target_index - split_point, aunts);
    }
}

/// Reconstructs the Merkle root by walking up the tree from a leaf using aunt
/// hashes.
///
/// "Aunts" are sibling hashes at each level of the tree needed to compute the
/// path from leaf to root.
///
/// # Example
///
/// For a tree with 4 leaves [A, B, C, D]:
///
/// ```text
///        Root
///       /    \
///    Hash1    Hash2
///    /  \     /   \
///   A    B   C     D
/// ```
///
/// ## If proving leaf A (index 0)
///
/// 1. A's sibling = B (at leaf level)
/// 2. Hash1's sibling = Hash2 (at intermediate level)
/// 3. Aunts array = [B, Hash2]
/// 4. Process: combine leafHash(A) with B to get Hash1, then combine Hash1 with
///    Hash2 to get Root
///
/// ## If proving leaf B (index 1)
///
/// 1. B's sibling = A (at leaf level)
/// 2. Hash1's sibling = Hash2 (at intermediate level)
/// 3. Aunts array = [A, Hash2]
/// 4. Process: combine leafHash(B) with A to get Hash1, then combine Hash1 with
///    Hash2 to get Root
///
/// The function climbs the tree level by level, using aunt hashes to compute
/// each parent hash until reaching the root.
fn compute_hash_from_aunts(
    index: usize,
    total: usize,
    leaf_hash: &[u8; 32],
    inner_hashes: &[[u8; 32]],
) -> [u8; 32] {
    // TODO:  assert(index < total && index >= 0 && total > 0)

    if total == 1 {
        return *leaf_hash;
    }

    let num_left = get_split_point(total);
    // Index of the aunt hash for the current level (always the last element)
    let aunt_idx = inner_hashes.len() - 1;

    if index < num_left {
        #[rustfmt::skip]
        let left_hash = compute_hash_from_aunts(
            index,
            num_left, // total
            leaf_hash,
            &inner_hashes[..aunt_idx]
        );

        inner_hash(&left_hash, &inner_hashes[aunt_idx])
    } else {
        let right_hash = compute_hash_from_aunts(
            index - num_left,
            total - num_left, // total
            leaf_hash,
            &inner_hashes[..aunt_idx],
        );

        inner_hash(&inner_hashes[aunt_idx], &right_hash)
    }
}

/// SHA256([])
fn empty_hash() -> [u8; 32] {
    let hasher = Sha256::new();
    hasher.finalize().into()
}

/// SHA256(0x00 || leaf)
fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[0x00]);
    hasher.update(leaf);
    hasher.finalize().into()
}

/// SHA256(0x01 || left || right)
fn inner_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Find the largest power of 2 less than k
// TODO: Check of possible overflow?
fn get_split_point(k: usize) -> usize {
    if k == 0 {
        return 0;
    }

    // Find the largest power of 2 less than k
    let mut split_point = 1;
    while split_point * 2 < k {
        split_point *= 2;
    }

    split_point
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let items: [&[u8]; 0] = [];

        let root = compute_root(&items);
        let expected = empty_hash();

        assert_eq!(root, expected);
    }

    #[test]
    fn test_single_leaf() {
        let items = [b"leaf0".as_slice()];

        let root = compute_root(&items);
        let expected = leaf_hash(b"leaf0");

        assert_eq!(root, expected);
    }

    #[test]
    fn test_two_leaves() {
        let items = [b"leaf0".as_slice(), b"leaf1".as_slice()];

        let root = compute_root(&items);

        let left = leaf_hash(b"leaf0");
        let right = leaf_hash(b"leaf1");
        let expected = inner_hash(&left, &right);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let items = [
            b"leaf0".as_slice(),
            b"leaf1".as_slice(),
            b"leaf2".as_slice(),
            b"leaf3".as_slice(),
        ];

        let root = compute_root(&items);

        // Test proof for each leaf
        for (i, item) in items.iter().enumerate() {
            let proof = compute_proof(&items, i, Some(root)).unwrap();

            verify_proof(item, &proof, &root).unwrap();
        }
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let items = [
            b"leaf0".as_slice(),
            b"leaf1".as_slice(),
            b"leaf2".as_slice(),
        ];

        let root = compute_root(&items);

        // Generate and verify proofs for all leaves
        for (i, item) in items.iter().enumerate() {
            let proof = compute_proof(&items, i, Some(root)).unwrap();

            verify_proof(item, &proof, &root).unwrap();
        }
    }

    #[test]
    fn test_split_point() {
        assert_eq!(get_split_point(0), 0);
        assert_eq!(get_split_point(1), 1);
        assert_eq!(get_split_point(2), 1);
        assert_eq!(get_split_point(3), 2);
        assert_eq!(get_split_point(4), 2);
        assert_eq!(get_split_point(5), 4);
        assert_eq!(get_split_point(8), 4);
        assert_eq!(get_split_point(9), 8);
    }

    // TODO: Test for invalid leaf index.
    #[test]
    fn test_invalid_proof() {
        let items = [b"leaf0".as_slice(), b"leaf1".as_slice()];

        let root = compute_root(&items);
        let proof = compute_proof(&items, 0, Some(root)).unwrap();

        // Try to verify with invalid leaf data
        let item = b"invalid";
        let err = verify_proof(item, &proof, &root).unwrap_err();
        assert!(matches!(err, Error::BadProof { .. }));
    }
}
