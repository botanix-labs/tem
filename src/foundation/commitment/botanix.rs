//! # Botanix Commitment Layer
//!
//! This module provides the higher-level interface for managing pegout state
//! transitions and Bitcoin block tracking within the commitment state trie. It
//! orchestrates multi-step operations while maintaining cryptographic integrity
//! and state consistency.
//!
//! ## Core Operations
//!
//! - **Pegout Lifecycle**: Manages transitions between initiated, pending, and
//!   delayed states with validation at each step
//! - **Bitcoin Block Processing**: Tracks transaction lists per block and
//!   handles finalization/orphaning events
//! - **Transaction Registration**: Associates Bitcoin transactions with their
//!   pegout fulfillments while preventing double-spending
//!
//! ## Error Categories
//!
//! The layer distinguishes between three types of errors:
//! - **Bad Trie Operations**: Violations of state consistency that may indicate
//!   malicious behavior
//! - **Implementation Errors**: Invalid input data indicating caller bugs
//! - **Backend Errors**: Database or infrastructure failures
//!
//! ## State Validation
//!
//! All operations include comprehensive validation to ensure state transitions
//! follow the correct pegout lifecycle and maintain referential integrity
//! across the commitment trie.

use super::{entry::Entry, trie::TrieLayer};
use crate::{
    foundation::commitment::{
        AliasFatDBMut, AliasMemoryDB, AliasTrieHash, CommitSchema, CommitmentStateRoot, MultisigId,
        sorted::Sorted,
        trie::{self, ErrorKind},
    },
    validation::pegout::PegoutWithId,
};
use bitcoin::{BlockHash, Txid};

/// Errors that can occur during Botanix layer operations.
///
/// Categorizes failures by their cause and severity to enable appropriate error
/// handling strategies in the consensus layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error<'a> {
    /// State transition violated trie consistency rules.
    ///
    /// These errors indicate potential malicious behavior where a validator is
    /// attempting invalid state modifications that could corrupt the commitment
    /// trie or enable double-spending attacks.
    BadTrieOp { entry: Entry<'a>, kind: ErrorKind },
    /// Invalid input data provided by the caller.
    ///
    /// These errors indicate implementation bugs in the calling code and should
    /// not result in validator punishment.
    ImplFatal(ImplFatalKind),
    /// Backend database or infrastructure failure.
    ///
    /// These errors are local to the validator and should not affect consensus
    /// or result in punishment.
    TrieFatal(trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>),
}

/// Implementation errors indicating invalid caller input.
///
/// These represent programming errors in the Foundation layer's usage rather
/// than consensus violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImplFatalKind {
    /// Attempted to register a transaction ID that's already tracked.
    TrackedTxidsContainsNewTxid,
    /// Updated transaction list has incorrect length.
    UpdatedTxidsBadLength,
    /// New transaction ID is missing from the updated list.
    UpdatedTxidsNotContainNewTxid,
    /// Attempted to register an empty pegout list.
    RegisterEmtpyPegouts,
    /// Tracked transaction list does not match the pegout list.
    TrackedTxidsNotMatchingPegouts,
}

impl<'a> From<ImplFatalKind> for Error<'a> {
    fn from(err: ImplFatalKind) -> Self {
        Error::ImplFatal(err)
    }
}

impl<'a> From<trie::Error<'a>> for Error<'a> {
    fn from(err: trie::Error<'a>) -> Self {
        match err {
            trie::Error::Mod { entry, kind } => Error::BadTrieOp { entry, kind },
            trie::Error::Fatal(err) => Error::TrieFatal(err),
        }
    }
}

/// Higher-level interface for Botanix state operations within the commitment
/// trie.
///
/// Provides validated operations for pegout lifecycle management and Bitcoin
/// block processing. All methods include comprehensive state validation to
/// prevent invalid transitions and maintain trie consistency.
pub struct BotanixLayer<'db> {
    /*PRIVATE*/ trie: TrieLayer<'db>,
}

impl<'db> From<TrieLayer<'db>> for BotanixLayer<'db> {
    fn from(trie: TrieLayer<'db>) -> Self {
        BotanixLayer { trie }
    }
}

impl<'db> From<AliasFatDBMut<'db>> for BotanixLayer<'db> {
    fn from(fat: AliasFatDBMut<'db>) -> Self {
        let trie = TrieLayer::from(fat);
        Self { trie }
    }
}

impl<'db> From<(&'db mut AliasMemoryDB, &'db mut AliasTrieHash)> for BotanixLayer<'db> {
    fn from(value: (&'db mut AliasMemoryDB, &'db mut AliasTrieHash)) -> Self {
        let trie = TrieLayer::from(value);
        Self { trie }
    }
}

impl<'db> BotanixLayer<'db> {
    pub fn root(&mut self) -> CommitmentStateRoot {
        CommitmentStateRoot(*self.trie.root())
    }
    pub fn check_initiated_pegout<'a>(
        &self,
        multisig: &'a MultisigId,
        pegout: &'a PegoutWithId,
    ) -> Result<(), Error<'a>> {
        // TODO: Check absence of other states here.
        self.trie
            .ensure_existing(Entry::Initiated {
                k: (multisig, &pegout.id),
                v: &pegout.data,
            })
            .map_err(Into::into)
    }
    pub fn check_pending_pegout<'a>(&self, pegout: &'a PegoutWithId) -> Result<(), Error<'a>> {
        self.trie
            .ensure_existing(Entry::Pending {
                k: &pegout.id,
                v: &pegout.data,
            })
            .map_err(Into::into)
    }
    pub fn check_delayed_pegout<'a>(&self, pegout: &'a PegoutWithId) -> Result<(), Error<'a>> {
        self.trie
            .ensure_existing(Entry::Delayed {
                k: &pegout.id,
                v: &pegout.data,
            })
            .map_err(Into::into)
    }
    /// Moves a pegout to the initiated state, making it available for spending.
    ///
    /// Creates a new pegout entry in the initiated table while ensuring it
    /// doesn't already exist in any state. This is typically called when a new
    /// pegout request is received from the Botanix chain.
    ///
    /// # State Changes
    /// - Sets the pegout to initiated state
    pub fn initiate_pegout<'a>(
        &mut self,
        multisig: &'a MultisigId,
        pegout: &'a PegoutWithId,
    ) -> Result<(), Error<'a>> {
        // Pegout must be newly inserted; not pre-existing!
        self.trie.insert_non_existing(Entry::Initiated {
            k: (multisig, &pegout.id),
            v: &pegout.data,
        })?;

        // Sanity check.
        #[cfg(debug_assertions)]
        self.trie.ensure_non_existing(Entry::Pending {
            k: &pegout.id,
            v: &pegout.data,
        })?;

        // Sanity check.
        #[cfg(debug_assertions)]
        self.trie.ensure_non_existing(Entry::Delayed {
            k: &pegout.id,
            v: &pegout.data,
        })?;

        Ok(())
    }
    /// Registers a Bitcoin transaction with associated pegout fulfillments.
    ///
    /// This operation:
    /// 1. Updates the tracked transaction list for the Bitcoin block
    /// 2. Moves pegouts from initiated to pending state  
    /// 3. Associates the transaction ID with its pegout list
    ///
    /// # Validation
    /// - Transaction ID must not already be tracked
    /// - Updated transaction list must contain exactly one more entry
    /// - All pegouts must be in initiated state
    /// - Pegout list must be non-empty
    ///
    /// # Arguments
    /// * `hash` - Bitcoin block hash where transaction will be included
    /// * `multisig` - Multisig ID that owns the pegouts
    /// * `tracked_txids` - Current list of tracked transactions
    /// * `updated_txids` - New list including the additional transaction
    /// * `txid` - The new transaction ID being registered
    /// * `pegouts` - List of pegouts fulfilled by this transaction
    pub fn register_bitcoin_tx<'a>(
        &mut self,
        hash: &'a BlockHash,
        multisig: &'a MultisigId,
        tracked_txids: &'a Sorted<Txid>,
        updated_txids: &'a Sorted<Txid>,
        txid: &'a Txid,
        pegouts: &'a Sorted<PegoutWithId>,
    ) -> Result<(), Error<'a>> {
        // NOTE: Tracked Txids might be empty - if this is the first.
        if tracked_txids.contains(txid) {
            return Err(Error::ImplFatal(ImplFatalKind::TrackedTxidsContainsNewTxid));
        }

        // Updated Txids must have exactly one(!) more item.
        if tracked_txids.len() + 1 != updated_txids.len() {
            return Err(Error::ImplFatal(ImplFatalKind::UpdatedTxidsBadLength));
        }

        // Updated txids must contain the new Txid.
        if !updated_txids.contains(txid) {
            return Err(Error::ImplFatal(
                ImplFatalKind::UpdatedTxidsNotContainNewTxid,
            ));
        }

        if pegouts.is_empty() {
            // The caller must make sure that pegouts are actually available!
            return Err(Error::ImplFatal(ImplFatalKind::RegisterEmtpyPegouts));
        }

        // Updated tracked Txids for the given Bitcoin hash.
        self.trie.update_existing(
            // New value
            Entry::BlockTxids {
                k: hash,
                v: &updated_txids,
            },
            // Existing entry MUST match this value.
            Entry::BlockTxids {
                k: hash,
                v: tracked_txids,
            },
        )?;

        // Track each pegout.
        debug_assert!(!pegouts.is_empty());
        for pegout in pegouts {
            // Remove pegout from initiated state.
            self.trie.remove_existing(Entry::Initiated {
                k: (multisig, &pegout.id),
                v: &pegout.data,
            })?;

            // Sanity check.
            #[cfg(debug_assertions)]
            self.trie.ensure_non_existing(Entry::Delayed {
                k: &pegout.id,
                v: &pegout.data,
            })?;

            // Move pegout to pending state.
            self.trie.insert_non_existing(Entry::Pending {
                k: &pegout.id,
                v: &pegout.data,
            })?;
        }

        // Track pegouts by Txid.
        self.trie.insert_non_existing(Entry::TxidPegouts {
            k: txid,
            v: pegouts,
        })?;

        Ok(())
    }
    /// Initializes tracking for a new Bitcoin block header.
    ///
    /// Creates an entry associating the block hash with its initial (typically
    /// empty) transaction list.
    ///
    /// # Arguments
    /// * `hash` - The Bitcoin block hash
    /// * `txids` - Initial list of tracked transactions (usually empty)
    // TODO: Should we just mandate that `txids` is empty here?
    pub fn bitcoin_header<'a>(
        &mut self,
        hash: &'a BlockHash,
        txids: &'a Sorted<Txid>,
    ) -> Result<(), Error<'a>> {
        self.trie
            .insert_non_existing(Entry::BlockTxids { k: hash, v: txids })
            .map_err(Into::into)
    }
    /// Finalizes a Bitcoin block by removing all associated data.
    ///
    /// This operation:
    /// 1. Removes the block's transaction tracking
    /// 2. Removes all transaction-to-pegout associations  
    /// 3. Removes pegouts from pending state, considered permanently confirmed
    ///
    /// # Arguments
    /// * `hash` - The Bitcoin block hash to finalize
    /// * `tracked_txids` - All transactions tracked for this block
    /// * `pegouts` - Pegout lists for each transaction (must match txid order)
    pub fn bitcoin_header_finalize<'a>(
        &mut self,
        hash: &'a BlockHash,
        tracked_txids: &'a Sorted<Txid>,
        pegouts: &'a [Sorted<PegoutWithId>],
    ) -> Result<(), Error<'a>> {
        // Remove tracked Txids
        //
        // Checks:
        // * The Bitcoin hash is committed.
        // * All passed-on Txids match the committed Txids.
        self.trie.remove_existing(Entry::BlockTxids {
            k: hash,
            v: tracked_txids,
        })?;

        // The passed-on pegouts size must match the tracked Txid size.
        if tracked_txids.len() != pegouts.len() {
            return Err(Error::ImplFatal(
                ImplFatalKind::TrackedTxidsNotMatchingPegouts,
            ));
        }

        // Remove each registered Bitcoin transaction.
        for (txid, pegouts) in tracked_txids.iter().zip(pegouts.iter()) {
            // Remove all associated pegouts with the Txid
            //
            // Checks:
            // * The Txid is committed.
            // * All passed-on pegouts match the committed pegouts.
            self.trie.remove_existing(Entry::TxidPegouts {
                k: txid,
                v: pegouts,
            })?;

            // Remove pegouts from pending state; they're now effectively
            // dropped and considered finalized.
            for pegout in pegouts {
                // Checks:
                // * The pegout is in pending state.
                // * The passed-on pegout id-data pair matches the committed
                //   pair.
                self.trie.remove_existing(Entry::Pending {
                    k: &pegout.id,
                    v: &pegout.data,
                })?;
            }
        }

        Ok(())
    }
    /// Orphans a Bitcoin block by moving pegouts to the delayed state.
    ///
    /// When a Bitcoin block is determined to be on a rejected fork:
    /// 1. Performs the same cleanup as finalization
    /// 2. Moves all pegouts to the delayed state, making them respendable
    ///
    /// This ensures pegouts from orphaned blocks can be included in
    /// future transactions on the canonical chain.
    ///
    /// # Arguments  
    /// * `hash` - The Bitcoin block hash to orphan
    /// * `tracked_txids` - All transactions tracked for this block
    /// * `pegouts` - Pegout lists for each transaction (must match txid order)
    pub fn bitcoin_header_orphan<'a>(
        &mut self,
        hash: &'a BlockHash,
        tracked_txids: &'a Sorted<Txid>,
        pegouts: &'a [Sorted<PegoutWithId>],
    ) -> Result<(), Error<'a>> {
        // The initial process for orphaned headers is the same as for finalized
        // headers
        self.bitcoin_header_finalize(hash, tracked_txids, pegouts)?;
        debug_assert_eq!(tracked_txids.len(), pegouts.len());

        // Now, each pegout is moved to the *delayed* set such that it can be
        // spent again.
        for pegouts in pegouts {
            for pegout in pegouts {
                self.trie.insert_non_existing(Entry::Delayed {
                    k: &pegout.id,
                    v: &pegout.data,
                })?;
            }
        }

        Ok(())
    }
}
