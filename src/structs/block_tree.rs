//! # Bitcoin Block Tree Implementation
//!
//! This module provides a tree structure for tracking Bitcoin block
//! relationships with automatic pruning based on confirmation depth. It handles
//! fork detection, resolution, and classification of blocks as either finalized
//! (canonical) or orphaned (rejected forks).
//!
//! ## Key Features
//!
//! - **Fork Handling**: Tracks multiple competing chains simultaneously
//! - **Automatic Pruning**: Removes old blocks based on confirmation depth
//! - **Block Classification**: Distinguishes between finalized and orphaned blocks
//! - **Elder Tracking**: Maintains the oldest retained block for efficient pruning
//!
//! ## Elder and Fork Retention
//!
//! The tree maintains exactly one elder (oldest retained block) at any time.
//! Importantly, the tree retains all blocks and competing forks even when they
//! exceed the confirmation depth. Pruning only occurs after forks have been
//! resolved; the tree will not prune blocks that still have unresolved
//! children.
//!
//! ## Block Classification
//!
//! When blocks are pruned, they are classified as:
//! - **Finalized**: Part of the canonical chain, associated pegouts are
//!   permanently confirmed
//! - **Orphaned**: Part of a rejected fork, associated pegouts must be returned
//!   to pending set
//!
//! This classification is crucial for handling Bitcoin withdrawal (pegout)
//! operations during blockchain reorganizations.
//!
//! ## Security Considerations
//!
//! - Requires minimum confirmation depth of 3 blocks for secure operation
//! - Handles reorganizations gracefully without losing track of competing forks
//! - Prevents premature finalization of blocks that might still be reorganized

use bitcoin::{BlockHash, hashes::Hash};
use std::collections::{HashMap, HashSet, VecDeque};

/// Errors that can occur during block tree operations.
///
/// These errors represent various validation failures when building and
/// maintaining a block tree structure for tracking Bitcoin block relationships
/// and pruning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The confirmation depth is too low for secure operation.
    ///
    /// A minimum confirmation depth of 3 blocks is required to ensure
    /// proper fork resolution and finality guarantees.
    //
    // TODO: This needs to be revisted.
    InsufficientConfirmationDepth,
    /// The parent block hash was not found in the tree.
    ParentHashNotFound,
    /// The block hash has already been inserted into the tree.
    HashAlreadyInserted,
    /// The maximum height has been reached (u64::MAX).
    ///
    /// This is extremely unlikely to happen in production but would require
    /// reinitializing the BlockTree if it occurs.
    MaxHeightReached,
}

/// Classification of pruned blocks based on their relationship to the main
/// chain.
///
/// When blocks are pruned from the tree, they are classified as either finalized
/// (part of the canonical chain) or orphaned (part of a rejected fork). This
/// classification determines how associated pending pegouts should be handled:
///
/// - Finalized blocks indicate pegouts are confirmed and cannot be spent again.
/// - Orphaned blocks indicate pegouts must be returned to the pending set and
///   can hence be spent again.
#[derive(Debug, PartialEq, Eq)]
pub enum BlockFate {
    /// A block that was pruned as part of the canonical chain. Associated
    /// pegouts are considered finalized and permanently confirmed.
    Finalized(BlockHash),
    /// A block that was pruned as part of a rejected fork. Associated pegouts
    /// must be returned to the pending set for potential re-spending.
    Orphaned(BlockHash),
}

impl BlockFate {
    /// Returns the block hash associated with this pruned classification.
    pub fn block_hash(&self) -> &BlockHash {
        match self {
            BlockFate::Finalized(h) => h,
            BlockFate::Orphaned(h) => h,
        }
    }
}

/// Internal representation of a block in the tree structure.
///
/// Tracks the block's position, parent relationship, and children for
/// efficient traversal and pruning operations.
#[derive(Debug, Clone)]
struct BlockNode {
    /// Relative height of this block.
    rheight: u64,
    /// Hash of the parent block.
    parent: BlockHash,
    /// Set of child block hashes.
    children: HashSet<BlockHash>,
}

/// A tree structure for tracking Bitcoin block relationships with automatic
/// pruning.
///
/// Maintains a directed acyclic graph of blocks with their parent-child
/// relationships, automatically pruning old blocks based on confirmation depth.
/// Supports fork detection and resolution, classifying pruned blocks as either
/// finalized (canonical) or orphaned (rejected forks).
///
/// # Elder and Fork Retention
///
/// The tree maintains exactly one elder (oldest retained block) at any time.
/// Importantly, the tree retains all blocks and competing forks even when they
/// exceed the confirmation depth. Pruning only occurs after forks have been
/// resolved - the tree will not prune blocks that still have unresolved
/// children.
///
/// # Pruning Strategy
///
/// The tree uses a two-phase pruning approach:
///
/// 1. **Forward traversal**: Prunes finalized blocks from the elder, but only
///    when there are no competing forks (exactly one child per block).
/// 2. **Backward traversal**: Prunes orphaned forks that fall too far behind
///    the best chain, enabling forward pruning to proceed.
///
/// Blocks become eligible for pruning when they are more than `conf_depth`
/// blocks behind the current best height, but actual pruning depends on fork
/// resolution.
#[derive(Debug, Clone)]
pub struct BlockTree {
    /// Current chain tips (blocks with no children)
    tips: HashSet<BlockHash>,
    /// The oldest block still retained in the tree
    elder: BlockHash,
    /// Map of all blocks in the tree with their metadata
    blocks: HashMap<BlockHash, BlockNode>,
    /// Height of the current best (longest) chain
    best_height: u64,
    /// Required confirmation depth for finality
    conf_depth: u64,
}

impl BlockTree {
    /// Creates a new block tree with an initial block and confirmation depth.
    ///
    /// # Arguments
    ///
    /// * `hash` - The initial block hash to start the tree
    /// * `conf_depth` - Minimum confirmation depth (must be at least 3)
    ///
    /// # Returns
    ///
    /// A new `BlockTree` or an error if the confirmation depth is insufficient.
    ///
    /// # Errors
    ///
    /// - `InsufficientConfirmationDepth` if conf_depth < 3
    pub fn new(hash: BlockHash, conf_depth: u64) -> Result<Self, Error> {
        // TODO: Is this restriction needed?
        // TODO: Add unit tests to cover/demonstrate this.
        if conf_depth < 3 {
            return Err(Error::InsufficientConfirmationDepth);
        }

        let node = BlockNode {
            rheight: 0,
            parent: BlockHash::all_zeros(),
            children: HashSet::new(),
        };

        Ok(Self {
            tips: HashSet::from([hash]),
            elder: hash,
            blocks: HashMap::from([(hash, node)]),
            best_height: 0,
            conf_depth,
        })
    }
    /// Returns the required confirmation depth for finality.
    pub fn conf_depth(&self) -> u64 {
        self.conf_depth
    }
    /// Returns the current set of chain tips.
    ///
    /// Tips are blocks that have no children and represent the current
    /// frontier of the block tree. Multiple tips indicate active forks.
    pub fn tips(&self) -> Vec<BlockHash> {
        self.tips.iter().copied().collect()
    }
    /// Returns the elder (oldest retained) block hash.
    ///
    /// The elder is the oldest block still maintained in the tree structure.
    /// All blocks older than the elder have been pruned as finalized.
    pub fn elder(&self) -> BlockHash {
        self.elder
    }
    /// Returns all block hashes currently in the tree.
    pub fn blocks(&self) -> Vec<BlockHash> {
        self.blocks.keys().copied().collect()
    }
    /// Returns the chain of block hashes from the elder to the given block
    /// hash.
    ///
    /// This method traverses the block tree backwards from the specified block
    /// hash to the elder, collecting all block hashes along the path.
    ///
    /// # Arguments
    ///
    /// * `hash` - The block hash to start the chain from
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<BlockHash>)` - A vector of block hashes where the first
    ///   element is the elder and the last element is the given block hash
    /// * `Err(Error::ParentHashNotFound)` - If the specified block hash doesn't
    ///   exist in the tree
    pub fn chain(&self, hash: &BlockHash) -> Result<Vec<BlockHash>, Error> {
        let mut target = *hash;
        let mut chain = VecDeque::new();

        // First target block must exist.
        let node = self.blocks.get(&target).ok_or(Error::ParentHashNotFound)?;
        chain.push_front(target);
        target = node.parent;

        // Walk-back the chain until all blocks have been collected.
        while let Some(node) = self.blocks.get(&target) {
            chain.push_front(target);
            target = node.parent;
        }

        // The first block must be the elder.
        debug_assert_eq!(chain.get(0).unwrap(), &self.elder());

        Ok(chain.into())
    }
    /// Checks if a block hash is currently tracked in the tree.
    ///
    /// # Arguments
    ///
    /// * `hash` - The block hash to check
    ///
    /// # Returns
    ///
    /// `true` if the block is in the tree, `false` otherwise.
    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.blocks.contains_key(hash)
    }
    /// Inserts a new block into the tree and performs pruning if necessary.
    ///
    /// Adds a new block as a child of the specified parent, updates the tree
    /// structure, and performs automatic pruning based on confirmation depth.
    /// Returns a list of blocks that were pruned during this operation.
    ///
    /// # Arguments
    ///
    /// * `new_hash` - Hash of the new block to insert
    /// * `parent_hash` - Hash of the parent block
    ///
    /// # Returns
    ///
    /// A vector of `BlockFate` entries for any blocks that were pruned,
    /// or an error if insertion fails.
    ///
    /// # Errors
    ///
    /// - `HashAlreadyInserted` if the block already exists in the tree
    /// - `ParentHashNotFound` if the parent block is not in the tree
    /// - `MaxHeightReached` if the height would overflow (extremely unlikely)
    ///
    /// # Pruning Behavior
    ///
    /// When a new block extends the best chain beyond the confirmation depth:
    ///
    /// 1. Orphaned forks are identified and pruned (classified as `Orphaned`)
    /// 2. Deep canonical blocks are pruned from the elder forward (classified
    ///    as `Finalized`)
    /// 3. The elder is updated to the new oldest retained block
    pub fn insert(
        &mut self,
        new_hash: BlockHash,
        parent_hash: BlockHash,
    ) -> Result<Vec<BlockFate>, Error> {
        if self.blocks.contains_key(&new_hash) {
            return Err(Error::HashAlreadyInserted);
        }

        // Retrieve the parent and update its children.
        let parent = self
            .blocks
            .get_mut(&parent_hash)
            .ok_or(Error::ParentHashNotFound)?;
        let rheight = parent.rheight.checked_add(1).unwrap();

        let is_new = parent.children.insert(new_hash);
        debug_assert!(is_new);

        // Track new block.
        let node = BlockNode {
            rheight,
            parent: parent_hash,
            children: HashSet::new(),
        };

        self.blocks.insert(new_hash, node);

        // Update tips.
        let is_new = self.tips.remove(&parent_hash);
        debug_assert!(is_new || !is_new); // latter implies fork-off an older block

        let is_new = self.tips.insert(new_hash);
        debug_assert!(is_new);

        if rheight <= self.best_height {
            // The new block is not the best fork, so we do not have to bother
            // with pruning checks or fork resolutions.
            return Ok(vec![]);
        }

        // Track best relative height.
        debug_assert_eq!(self.best_height + 1, rheight);
        self.best_height = rheight;

        let mut pruned = vec![];

        // Iterate through each tip/fork and check for pruning candidates.
        self.tips.retain(|&tip| {
            let did_prune = Self::prune_backwards_traversal(
                tip,
                None,
                self.conf_depth,
                self.best_height,
                &mut self.blocks,
                &mut pruned,
            );

            // Retain tip if the fork WAS NOT pruned.
            !did_prune
        });

        self.elder = Self::prune_forwards_traversal(
            self.elder,
            self.conf_depth,
            self.best_height,
            &mut self.blocks,
            &mut pruned,
        );

        Ok(pruned)
    }
    /// Prunes finalized blocks using forward traversal from the elder.
    ///
    /// Traverses forward from the elder through blocks that are deep enough to
    /// be considered finalized and have exactly one child (no competing forks).
    /// Stops at the first block that doesn't meet these criteria. All pruned
    /// blocks are classified as **finalized**.
    ///
    /// # Arguments
    ///
    /// * `elder` - Starting block for the traversal
    /// * `conf_depth` - Required confirmation depth
    /// * `best_rheight` - Current best chain height
    /// * `blocks` - Mutable reference to the blocks map
    /// * `pruned` - Vector to collect pruned block classifications
    ///
    /// # Returns
    ///
    /// The new (or current) elder block hash after pruning.
    fn prune_forwards_traversal(
        elder: BlockHash,
        conf_depth: u64,
        best_rheight: u64,
        blocks: &mut HashMap<BlockHash, BlockNode>,
        pruned: &mut Vec<BlockFate>,
    ) -> BlockHash {
        let node = blocks.get_mut(&elder).expect("elder must exist");

        let Some(prune_at) = best_rheight.checked_sub(conf_depth - 1) else {
            // Chain is too young to be pruned, abort.
            return elder;
        };

        if node.rheight > prune_at {
            // Node is not deep enough to qualify for pruning, abort.
            return elder;
        }

        if node.children.len() > 1 {
            // Node is part of an unresolved fork, abort.
            return elder;
        }

        // Prune node and retrieve child.
        let mut node = blocks.remove(&elder).expect("elder must exist");
        pruned.push(BlockFate::Finalized(elder));

        let child = node
            .children
            .drain()
            .next()
            .expect("node must have one child");

        debug_assert!(node.children.is_empty());

        // The pruned elder's child is now the new elder.
        Self::prune_forwards_traversal(child, conf_depth, best_rheight, blocks, pruned)
    }
    /// Prunes orphaned forks using backward traversal from tips.
    ///
    /// Traverses backward from a tip that is deep enough to be considered
    /// orphaned, removing parent-child relationships and pruning blocks that no
    /// longer have children. Stops at the first block that doesn't meet these
    /// criteria. All pruned blocks are classified as **orphaned**.
    ///
    /// # Arguments
    ///
    /// * `tip` - Starting tip for the traversal
    /// * `child` - Child block being processed (None for the initial tip)
    /// * `conf_depth` - Required confirmation depth
    /// * `best_rheight` - Current best chain height
    /// * `blocks` - Mutable reference to the blocks map
    /// * `pruned` - Vector to collect pruned block classifications
    ///
    /// # Returns
    ///
    /// `true` if the tip/fork was pruned, `false` if it was retained.
    fn prune_backwards_traversal(
        tip: BlockHash,
        child: Option<BlockHash>,
        conf_depth: u64,
        best_rheight: u64,
        blocks: &mut HashMap<BlockHash, BlockNode>,
        pruned: &mut Vec<BlockFate>,
    ) -> bool {
        let Some(node) = blocks.get_mut(&tip) else {
            debug_assert!(child.is_some());

            // Reached the end of the chain, implying pruning events must have
            // happened.
            return true;
        };

        let Some(prune_at) = best_rheight.checked_sub(conf_depth - 1) else {
            // Chain is too young to be pruned, abort.
            return false;
        };

        if node.rheight > prune_at {
            // Node is not deep enough to qualify for pruning, abort.
            return false;
        }

        // Parents (non-tip nodes) remove their now-orphaned child.
        if let Some(child) = child {
            let did_remove = node.children.remove(&child);
            debug_assert!(did_remove);
        }

        let parent = node.parent;

        // If there are no children left, prune node.
        if node.children.is_empty() {
            let entry = blocks.remove(&tip);
            debug_assert!(entry.is_some());

            pruned.push(BlockFate::Orphaned(tip));
        }

        // Grandparents remove their now-orphaned child (this tip) as well.
        Self::prune_backwards_traversal(parent, Some(tip), conf_depth, best_rheight, blocks, pruned)
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_snake_case)]

    use super::*;
    use crate::test_utils::gen_bitcoin_hash;

    #[test]
    fn block_tree_finalized_and_orphaned() {
        // Total structure to be processed, in alphabetical order:
        //
        // ─ A ─── B ─┬─ C
        //         │  └─ D ─── E ─── H ─── I
        //         └──── F ─── G
        //
        let A = gen_bitcoin_hash();
        let (B, B_PREV) = (gen_bitcoin_hash(), A);
        let (C, C_PREV) = (gen_bitcoin_hash(), B);
        let (D, D_PREV) = (gen_bitcoin_hash(), B);
        let (E, E_PREV) = (gen_bitcoin_hash(), D);
        let (F, F_PREV) = (gen_bitcoin_hash(), B);
        let (G, G_PREV) = (gen_bitcoin_hash(), F);
        let (H, H_PREV) = (gen_bitcoin_hash(), E);
        let (I, I_PREV) = (gen_bitcoin_hash(), H);

        // Initialize A: CONFIRMATION DEPTH of three.
        //
        // ─ A (elder/tip)
        //
        let conf_depth = 3;
        let mut tree = BlockTree::new(A, conf_depth).unwrap();

        let elder = tree.elder();
        assert_eq!(elder, A);

        let tips = tree.tips();
        assert_eq!(tips.len(), 1);
        assert!(tips.contains(&A));

        assert_eq!(tree.blocks().len(), 1);

        // Insert B
        //
        // ─ A ─────── B (tip)
        //   (elder)
        //
        let pruned = tree.insert(B, B_PREV).unwrap();
        assert!(pruned.is_empty());

        let elder = tree.elder();
        assert_eq!(elder, A);

        let tips = tree.tips();
        assert_eq!(tips.len(), 1);
        assert!(tips.contains(&B));

        assert_eq!(tree.blocks().len(), 2);

        // Insert C
        //
        // ─ B ─────── C (tip)
        //   (elder)
        //
        let pruned = tree.insert(C, C_PREV).unwrap();
        assert_eq!(pruned.len(), 1);
        assert!(pruned.contains(&BlockFate::Finalized(A)));

        let elder = tree.elder();
        assert_eq!(elder, B);

        let tips = tree.tips();
        assert_eq!(tips.len(), 1);
        assert!(tips.contains(&C));

        assert_eq!(tree.blocks().len(), 2);

        // Insert D
        //
        // ─ B ──────┬─── C (tip)
        //   (elder) └─── D (tip)
        //
        let pruned = tree.insert(D, D_PREV).unwrap();
        assert!(pruned.is_empty());

        let elder = tree.elder();
        assert_eq!(elder, B);

        let tips = tree.tips();
        assert_eq!(tips.len(), 2);
        assert!(tips.contains(&C));
        assert!(tips.contains(&D));

        assert_eq!(tree.blocks().len(), 3);

        // Insert E: NOTE that B is retained because there is an unresolved fork
        // depending on B!
        //
        // ─ B ──────┬─── C (tip)
        //   (elder) └─── D ─────── E (tip)
        //
        let pruned = tree.insert(E, E_PREV).unwrap();
        assert!(pruned.is_empty());

        let elder = tree.elder();
        assert_eq!(elder, B);

        let tips = tree.tips();
        assert_eq!(tips.len(), 2);
        assert!(tips.contains(&C));
        assert!(tips.contains(&E));

        assert_eq!(tree.blocks().len(), 4);

        // Insert F: There are now three competing forks depending on B.
        //
        // ─ B ───┬─── C (tip)
        //   │    └─── D ─────── E (tip)
        //   └──────── F (tip)
        //   (elder)
        //
        let pruned = tree.insert(F, F_PREV).unwrap();
        assert!(pruned.is_empty());

        let elder = tree.elder();
        assert_eq!(elder, B);

        let tips = tree.tips();
        assert_eq!(tips.len(), 3);
        assert!(tips.contains(&C));
        assert!(tips.contains(&E));
        assert!(tips.contains(&F));

        assert_eq!(tree.blocks().len(), 5);

        // Insert G
        //
        // ─ B ───┬─── C (tip)
        //   │    └─── D ─────── E (tip)
        //   └──────── F ─────── G (tip)
        //   (elder)
        //
        let pruned = tree.insert(G, G_PREV).unwrap();
        assert!(pruned.is_empty());

        let elder = tree.elder();
        assert_eq!(elder, B);

        let tips = tree.tips();
        assert_eq!(tips.len(), 3);
        assert!(tips.contains(&C));
        assert!(tips.contains(&E));
        assert!(tips.contains(&G));

        assert_eq!(tree.blocks().len(), 6);

        // Insert H: The tip of fork B..C is now deep enough to be considered
        // orphaned - C gets pruned but B remains because there are still
        // unresolved forks depending on B.
        //
        // ─ B ──────┬─── D ─────── E ─────── H (tip)
        //   (elder) └─── F ─────── G (tip)
        //
        let pruned = tree.insert(H, H_PREV).unwrap();
        assert_eq!(pruned.len(), 1);
        assert!(pruned.contains(&BlockFate::Orphaned(C)));

        let elder = tree.elder();
        assert_eq!(elder, B);

        let tips = tree.tips();
        assert_eq!(tips.len(), 2);
        assert!(tips.contains(&H));
        assert!(tips.contains(&G));

        assert_eq!(tree.blocks().len(), 6);

        // Insert I: The tip of fork B..G is now deep enough to be considered
        // oprhaned - the competing forks at B are now resolved and the blocks
        // get pruned accordingly!
        //
        // ─ H ─────── I (tip)
        //   (elder)
        //
        let pruned = tree.insert(I, I_PREV).unwrap();
        assert_eq!(pruned.len(), 5);
        //
        assert!(pruned.contains(&BlockFate::Orphaned(F)));
        assert!(pruned.contains(&BlockFate::Orphaned(G)));
        //
        assert!(pruned.contains(&BlockFate::Finalized(B)));
        assert!(pruned.contains(&BlockFate::Finalized(D)));
        assert!(pruned.contains(&BlockFate::Finalized(E)));

        // New elder!
        let elder = tree.elder();
        assert_eq!(elder, H);

        let tips = tree.tips();
        assert_eq!(tips.len(), 1);
        assert!(tips.contains(&I));

        assert_eq!(tree.blocks().len(), 2);
    }

    #[test]
    fn block_tree_chain_retrieval() {
        // Total structure to be processed, in alphabetical order:
        //
        // ─ A ─── B ─┬─ C
        //            └─ D ─── E ─── F
        //
        let A = gen_bitcoin_hash();
        let (B, B_PREV) = (gen_bitcoin_hash(), A);
        let (C, C_PREV) = (gen_bitcoin_hash(), B);
        let (D, D_PREV) = (gen_bitcoin_hash(), B);
        let (E, E_PREV) = (gen_bitcoin_hash(), D);
        let (F, F_PREV) = (gen_bitcoin_hash(), E);

        // Initialize A: CONFIRMATION DEPTH of three.
        //
        // ─ A (elder/tip)
        //
        let conf_depth = 3;
        let mut tree = BlockTree::new(A, conf_depth).unwrap();

        // Does not exist yet.
        let chain = tree.chain(&B).unwrap_err();
        assert_eq!(chain, Error::ParentHashNotFound);

        let chain = tree.chain(&A).unwrap();
        assert_eq!(chain, vec![A]);

        // Insert B
        //
        // ─ A ─────── B (tip)
        //   (elder)
        //
        tree.insert(B, B_PREV).unwrap();

        // Previous block.
        let chain = tree.chain(&A).unwrap();
        assert_eq!(chain, vec![A]);

        let chain = tree.chain(&B).unwrap();
        assert_eq!(chain, vec![A, B]);

        // Insert C
        //
        // ─ B ─────── C (tip)
        //   (elder)
        //
        tree.insert(C, C_PREV).unwrap();

        // Already pruned (finalized).
        let chain = tree.chain(&A).unwrap_err();
        assert_eq!(chain, Error::ParentHashNotFound);

        let chain = tree.chain(&B).unwrap();
        assert_eq!(chain, vec![B]);

        let chain = tree.chain(&C).unwrap();
        assert_eq!(chain, vec![B, C]);

        // Insert D
        //
        // ─ B ──────┬─── C (tip)
        //   (elder) └─── D (tip)
        //
        tree.insert(D, D_PREV).unwrap();

        let chain = tree.chain(&C).unwrap();
        assert_eq!(chain, vec![B, C]);

        let chain = tree.chain(&D).unwrap();
        assert_eq!(chain, vec![B, D]);

        // Insert E
        //
        // ─ B ──────┬─── C (tip)
        //   (elder) └─── D ─────── E (tip)
        //
        tree.insert(E, E_PREV).unwrap();

        let chain = tree.chain(&C).unwrap();
        assert_eq!(chain, vec![B, C]);

        let chain = tree.chain(&E).unwrap();
        assert_eq!(chain, vec![B, D, E]);

        // Insert F
        //
        // ─ E ─────── F (tip)
        //   (elder)
        //
        tree.insert(F, F_PREV).unwrap();

        // Already pruned (orphaned)
        let chain = tree.chain(&B).unwrap_err();
        assert_eq!(chain, Error::ParentHashNotFound);

        let chain = tree.chain(&C).unwrap_err();
        assert_eq!(chain, Error::ParentHashNotFound);

        let chain = tree.chain(&E).unwrap();
        assert_eq!(chain, vec![E]);

        let chain = tree.chain(&F).unwrap();
        assert_eq!(chain, vec![E, F]);
    }
}
