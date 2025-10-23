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
// TODO: Comment is outdated!

use crate::{
    foundation::{
        CommitHasher,
        commitment::{
            MultisigId,
            sorted::Sorted,
            trie::{self, EntryT, ErrorKind, StorageKey, StorageValue},
        },
        component::{BotanixLayer, ToCommit},
    },
    validation::pegout::{PegoutId, PegoutWithId},
};
use bitcoin::{BlockHash, OutPoint, Txid};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const T_UNASSIGNED: &[u8] = b"pegout:unassigned";
const T_PROPOSAL: &[u8] = b"pegout:proposal";
const T_ONCHAIN_UTXO: &[u8] = b"pegout:onchain-utxo";
const T_ONCHAIN_HEADER: &[u8] = b"pegout:onchain-header";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnassignedEntry {
    pub pegout: PegoutWithId,
    pub candidates: Sorted<MultisigId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProposalEntry {
    pub txid: Txid,
    pub fed_id: MultisigId,
    pub botanix_height: u64,
    pub utxos: Sorted<bitcoin::OutPoint>,
    pub pegouts: Sorted<PegoutWithId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OnchainUtxoEntry {
    pub utxo: OutPoint,
    pub txids: Sorted<Txid>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OnchainHeaderEntry {
    pub block_hash: BlockHash,
    pub bitcoin_height: u64,
    pub proposals: Sorted<Txid>,
}

/// Trie entry representing different types of Foundation state data.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PegoutEntry<'a> {
    // Freshly initiated pegout on the Botanix EVM, or pegouts that have been
    // orphaned and are not included in any competing proposal.
    Unassigned {
        k: &'a PegoutId,
        v: &'a UnassignedEntry,
    },
    // Proposals are always tracked, whether they're on-chain or not (mempool).
    // The only time a Proposal is removed is if gets finalized, or if a
    // competing Proposal is finalized that has reused at least one Utxo -
    // implying that this Proposal is orphaned!
    Proposal {
        k: &'a Txid,
        v: &'a ProposalEntry,
    },
    // A Utxo that has been spotted on-chain. This is required to check for
    // finalization events.
    OnchainUtxo {
        k: &'a OutPoint,
        v: &'a OnchainUtxoEntry,
    },
    // A Header that has been spotted on-chain.
    OnchainHeader {
        k: &'a BlockHash,
        v: &'a OnchainHeaderEntry,
    },
}

// TODO: Rename and document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryNames {
    Unassigned,
    Proposal,
    OnchainUtxo,
    OnchainHeader,
}

// TODO: We have many error types, so each error type should be prefixed like
// this. Makes it easier to follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PegoutError<D> {
    ValidationError(ValidationError),
    BackendError(super::BackendError<D>),
}

impl<D> From<ValidationError> for PegoutError<D> {
    fn from(err: ValidationError) -> Self {
        PegoutError::ValidationError(err)
    }
}

impl<D> From<DataSourceError<D>> for PegoutError<D> {
    fn from(err: DataSourceError<D>) -> Self {
        PegoutError::BackendError(super::BackendError::DataSource(err))
    }
}

impl<D> From<trie::Error<EntryNames>> for PegoutError<D> {
    fn from(err: trie::Error<EntryNames>) -> Self {
        match err {
            trie::Error::Mod { partition, kind } => {
                PegoutError::ValidationError(ValidationError::StateError { partition, kind })
            }
            trie::Error::Fatal(err) => PegoutError::BackendError(super::BackendError::Fatal(err)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    // TODO: It's technically prossible to re-insert a pending pegout!
    UnassignedPegoutAlreadyInserted,
    UnassignedPegoutInvalidOrAlreadyProposed,
    ProposalEmptyUtxos,
    ProposalEmptyPegouts,
    ProposalUtxoReuse,
    ProposalPegoutReuse,
    ProposalAlreadyInserted,
    ProposalDoesNotExist,
    UpgradedProposalMustReuseUtxo,
    UpgradedProposalBadFedId,
    UpgradedProposalBadPreviousRef,
    HeaderBadPreviousRef,
    HeaderDoesNotExist,
    BadCandidateClaim,
    TxidAlreadyInserted,
    UtxoAlreadyInserted,
    UtxoBadPreviousRef,
    //
    StateError {
        partition: EntryNames,
        kind: ErrorKind,
    },
}

impl<'a> EntryT for PegoutEntry<'a> {
    type PartitionName = EntryNames;

    /// Computes the cryptographic commitment for this entry's key.
    ///
    /// Uses Merlin transcript with domain separation by entry type to ensure
    /// keys from different tables cannot collide even with identical input
    /// data.
    fn as_key(&self) -> StorageKey {
        let mut h = CommitHasher::new(b"pegout-entry-key");

        match self {
            PegoutEntry::Unassigned { k, .. } => {
                h.append_message(b"table", T_UNASSIGNED);
                k.append_to_commit(&mut h);
            }
            PegoutEntry::Proposal { k, .. } => {
                h.append_message(b"table", T_PROPOSAL);
                k.append_to_commit(&mut h);
            }
            PegoutEntry::OnchainUtxo { k, .. } => {
                h.append_message(b"table", T_ONCHAIN_UTXO);
                k.append_to_commit(&mut h);
            }
            PegoutEntry::OnchainHeader { k, .. } => {
                h.append_message(b"table", T_ONCHAIN_HEADER);
                k.append_to_commit(&mut h);
            }
        }

        StorageKey::from(h.finalize())
    }

    /// Computes the cryptographic commitment for this entry's value.
    ///
    /// Creates a deterministic hash of the entry's value data that can be used
    /// for efficient equality comparisons in the trie.
    fn as_value(&self) -> StorageValue {
        let mut h = CommitHasher::new(b"pegout-entry-value");

        match self {
            PegoutEntry::Unassigned { v, .. } => v.append_to_commit(&mut h),
            PegoutEntry::Proposal { v, .. } => v.append_to_commit(&mut h),
            PegoutEntry::OnchainUtxo { v, .. } => v.append_to_commit(&mut h),
            PegoutEntry::OnchainHeader { v, .. } => v.append_to_commit(&mut h),
        }

        StorageValue::from(h.finalize())
    }

    /// Returns both the key and value commitments for this entry.
    fn as_key_value(&self) -> (StorageKey, StorageValue) {
        (self.as_key(), self.as_value())
    }

    fn partition_name(&self) -> Self::PartitionName {
        match self {
            PegoutEntry::Unassigned { .. } => EntryNames::Unassigned,
            PegoutEntry::Proposal { .. } => EntryNames::Proposal,
            PegoutEntry::OnchainUtxo { .. } => EntryNames::OnchainUtxo,
            PegoutEntry::OnchainHeader { .. } => EntryNames::OnchainHeader,
        }
    }
}

impl ToCommit for UnassignedEntry {
    fn append_to_commit(&self, t: &mut CommitHasher) {
        // Deconstruct so we do not miss anything accidentally.
        let UnassignedEntry { pegout, candidates } = self;

        pegout.append_to_commit(t);
        candidates.append_to_commit(t);
    }
}

impl ToCommit for ProposalEntry {
    fn append_to_commit(&self, t: &mut CommitHasher) {
        // Deconstruct so we do not miss anything accidentally.
        let ProposalEntry {
            txid,
            fed_id,
            botanix_height,
            utxos,
            pegouts,
        } = self;

        txid.append_to_commit(t);
        fed_id.append_to_commit(t);
        t.append_u64(b"botanix_height", *botanix_height);
        utxos.append_to_commit(t);
        pegouts.append_to_commit(t);
    }
}

impl ToCommit for OnchainUtxoEntry {
    fn append_to_commit(&self, t: &mut CommitHasher) {
        let OnchainUtxoEntry { utxo, txids } = self;

        utxo.append_to_commit(t);
        txids.append_to_commit(t);
    }
}

impl ToCommit for OnchainHeaderEntry {
    fn append_to_commit(&self, t: &mut CommitHasher) {
        // Deconstruct so we do not miss anything accidentally.
        let OnchainHeaderEntry {
            block_hash,
            bitcoin_height,
            proposals,
        } = self;

        block_hash.append_to_commit(t);
        t.append_u64(b"bitcoin_height", *bitcoin_height);
        proposals.append_to_commit(t);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSourceError<D>(pub D);

// TODO: Implement this for the other *Error wrappers as well.
impl<D> From<D> for DataSourceError<D> {
    fn from(value: D) -> Self {
        DataSourceError(value)
    }
}

// TODO: Those methods should never return an `Option<_>`, but an error instead.
// If the value does not exist, then this should be an error; implying a bug.
pub trait DataSource {
    type Error;

    fn insert_unassigned(
        &mut self,
        pegout: &PegoutId,
        entry: UnassignedEntry,
    ) -> Result<(), DataSourceError<Self::Error>>;
    fn get_unassigned(
        &mut self,
        pegout: &PegoutId,
    ) -> Result<Option<UnassignedEntry>, DataSourceError<Self::Error>>;
    fn remove_unassigned(&mut self, pegout: &PegoutId) -> Result<(), DataSourceError<Self::Error>>;
    //
    fn insert_utxo(
        &mut self,
        utxo: &OutPoint,
        entry: OnchainUtxoEntry,
    ) -> Result<(), DataSourceError<Self::Error>>;
    fn get_utxo(
        &mut self,
        utxo: &OutPoint,
    ) -> Result<Option<OnchainUtxoEntry>, DataSourceError<Self::Error>>;
    fn finalize_utxo(&mut self, utxo: &OutPoint) -> Result<(), DataSourceError<Self::Error>>;
    fn orphan_utxo(&mut self, utxo: &OutPoint) -> Result<(), DataSourceError<Self::Error>>;
    //
    fn insert_header(
        &mut self,
        block: &BlockHash,
        entry: OnchainHeaderEntry,
    ) -> Result<(), DataSourceError<Self::Error>>;
    fn get_header(
        &mut self,
        block: &BlockHash,
    ) -> Result<Option<OnchainHeaderEntry>, DataSourceError<Self::Error>>;
    fn remove_header(&mut self, block: &BlockHash) -> Result<(), DataSourceError<Self::Error>>;
    //
    fn insert_pegout_proposal(
        &mut self,
        txid: &Txid,
        entry: ProposalEntry,
    ) -> Result<(), DataSourceError<Self::Error>>;
    fn get_proposal(
        &mut self,
        txid: &Txid,
    ) -> Result<Option<ProposalEntry>, DataSourceError<Self::Error>>;
    fn finalize_proposal(&mut self, txid: &Txid) -> Result<(), DataSourceError<Self::Error>>;
    fn orphan_proposal(&mut self, txid: &Txid) -> Result<(), DataSourceError<Self::Error>>;
}

impl<'db> BotanixLayer<'db> {
    /// Moves a pegout to the initiated state, making it available for spending.
    ///
    /// Creates a new pegout entry in the initiated table while ensuring it
    /// doesn't already exist in any state. This is typically called when a new
    /// pegout request is received from the Botanix chain.
    ///
    /// # State Changes
    /// - Sets the pegout to initiated state
    pub fn insert_unassigned<DS: DataSource>(
        &mut self,
        pegout: PegoutWithId,
        candidates: Sorted<MultisigId>,
        data_source: &mut DS,
    ) -> Result<(), PegoutError<DS::Error>> {
        let id = pegout.id;
        let entry = UnassignedEntry { pegout, candidates };

        self.trie
            .insert_non_existing(PegoutEntry::Unassigned { k: &id, v: &entry })
            .map_err(|_| ValidationError::UnassignedPegoutAlreadyInserted)?;

        data_source.insert_unassigned(&id, entry)?;

        Ok(())
    }
    // TODO: Use untrusted_* notation for fields?
    pub fn insert_pegout_proposal<DS: DataSource>(
        &mut self,
        proposal: ProposalEntry,
        //
        // TODO: This should probably be a reference.
        unval_proposal: Option<ProposalEntry>,
        data_source: &mut DS,
    ) -> Result<(), PegoutError<DS::Error>> {
        self.trie
            .insert_non_existing(PegoutEntry::Proposal {
                k: &proposal.txid,
                v: &proposal,
            })
            .map_err(|_| ValidationError::ProposalAlreadyInserted)?;

        if proposal.utxos.is_empty() {
            return Err(ValidationError::ProposalEmptyUtxos.into());
        }

        if proposal.pegouts.is_empty() {
            return Err(ValidationError::ProposalEmptyPegouts.into());
        }

        let mut used_utxos: HashSet<&OutPoint> = HashSet::new();
        let mut used_pegouts: HashSet<&PegoutWithId> = HashSet::new();

        for utxo in &proposal.utxos {
            if !used_utxos.insert(utxo) {
                return Err(ValidationError::ProposalUtxoReuse.into());
            }
        }

        for pegout in &proposal.pegouts {
            if !used_pegouts.insert(pegout) {
                return Err(ValidationError::ProposalPegoutReuse.into());
            }
        }

        if let Some(unval) = unval_proposal {
            // VALIDATE: The previous proposal must exist.
            self.trie
                .ensure_existing(PegoutEntry::Proposal {
                    k: &unval.txid,
                    v: &unval,
                })
                .map_err(|_| ValidationError::UpgradedProposalBadPreviousRef)?;

            let prev = unval; // OK!

            // VALIDATE: Only the original author is allowed to upgrade a
            // proposal.
            if prev.fed_id != proposal.fed_id {
                return Err(ValidationError::UpgradedProposalBadFedId.into());
            }

            // VALIDATE: The FIRST Utxo in the previous proposal must be reused
            // explicitly.
            //
            // Do NOTE that the author does not have control over the ordering
            // of the Utxos, which is computed deterministically via the
            // `Sorted<_>` structure. Hence, we just check whether the FIRST
            // Utxo from the pevious proposal is found ANYWHERE in the list of
            // the upgraded proposal.
            let utxo_to_reuse = &prev.utxos[0];
            if !used_utxos.contains(&utxo_to_reuse) {
                return Err(ValidationError::UpgradedProposalMustReuseUtxo.into());
            }

            // VALIDATE: Any pegout in the new proposal that is NOT in the previous
            // proposal MUST be in an unassigned state, which is then claimed.
            for pegout in used_pegouts {
                if prev.pegouts.contains(pegout) {
                    continue;
                }

                let unval = data_source
                    .get_unassigned(&pegout.id)?
                    .ok_or(ValidationError::UnassignedPegoutInvalidOrAlreadyProposed)?;

                self.trie
                    .remove_existing(PegoutEntry::Unassigned {
                        k: &pegout.id,
                        v: &unval,
                    })
                    .map_err(|_| ValidationError::UnassignedPegoutInvalidOrAlreadyProposed)?;

                let unassigned: UnassignedEntry = unval; // OK!

                // VALIDATE: The federation is qualified to claim that pegout.
                if !unassigned.candidates.contains(&proposal.fed_id) {
                    return Err(ValidationError::BadCandidateClaim.into());
                }

                data_source.remove_unassigned(&pegout.id)?;
            }
        } else {
            // VALIDATE: If no previous propsal exists, then EVERY pegout MUST
            // be in an unassigned state, which are then claimed.
            for pegout in used_pegouts {
                let unval = data_source
                    .get_unassigned(&pegout.id)?
                    .ok_or(ValidationError::UnassignedPegoutInvalidOrAlreadyProposed)?;

                self.trie
                    .remove_existing(PegoutEntry::Unassigned {
                        k: &pegout.id,
                        v: &unval,
                    })
                    .map_err(|_| ValidationError::UnassignedPegoutInvalidOrAlreadyProposed)?;

                let unassigned: UnassignedEntry = unval; // Ok!

                // VALIDATE: The federation is qualified to claim that pegout.
                if !unassigned.candidates.contains(&proposal.fed_id) {
                    return Err(ValidationError::BadCandidateClaim.into());
                }

                data_source.remove_unassigned(&pegout.id)?;
            }
        }

        let txid = proposal.txid;
        data_source.insert_pegout_proposal(&txid, proposal)?;

        Ok(())
    }
    // TODO: Should `bitcoin_height` be specifically validated?
    pub fn insert_bitcoin_header<DS: DataSource>(
        &mut self,
        block_hash: BlockHash,
        bitcoin_height: u64,
        data_source: &mut DS,
    ) -> Result<(), PegoutError<DS::Error>> {
        let entry = OnchainHeaderEntry {
            block_hash,
            bitcoin_height,
            proposals: vec![].into(),
        };

        // VALIDATE: The passed-on header has not been tracked yet.
        self.trie.insert_non_existing(PegoutEntry::OnchainHeader {
            k: &block_hash,
            v: &entry,
        })?;

        data_source.insert_header(&block_hash, entry)?;

        Ok(())
    }
    pub fn register_bitcoin_tx<DS: DataSource>(
        &mut self,
        block_hash: BlockHash,
        proposal: ProposalEntry,
        data_source: &mut DS,
    ) -> Result<(), PegoutError<DS::Error>> {
        self.trie
            .ensure_existing(PegoutEntry::Proposal {
                k: &proposal.txid,
                v: &proposal,
            })
            .map_err(|_| ValidationError::ProposalDoesNotExist)?;

        // TODO: The method should not return an `Option<_>`, but an error instead.
        let unval = data_source
            .get_header(&block_hash)?
            .expect("header must exist");

        if unval.proposals.contains(&proposal.txid) {
            return Err(ValidationError::TxidAlreadyInserted.into());
        }

        let updated_proposals: Sorted<Txid> = {
            let mut p = unval.proposals.to_vec();
            p.push(proposal.txid);
            p.into()
        };

        let entry = OnchainHeaderEntry {
            block_hash,
            bitcoin_height: unval.bitcoin_height,
            proposals: updated_proposals,
        };

        self.trie
            .update_existing(
                // New entry.
                PegoutEntry::OnchainHeader {
                    k: &block_hash,
                    v: &entry,
                },
                // VALIDATE: The passed-on entry is valid.
                PegoutEntry::OnchainHeader {
                    k: &block_hash,
                    v: &unval,
                },
            )
            .map_err(|_| ValidationError::HeaderBadPreviousRef)?;

        let _prev_entry: OnchainHeaderEntry = unval; // OK!

        data_source.insert_header(&block_hash, entry)?;

        for utxo in &proposal.utxos {
            let Some(unval) = data_source.get_utxo(utxo)? else {
                let entry = OnchainUtxoEntry {
                    utxo: *utxo,
                    txids: vec![proposal.txid].into(),
                };

                self.trie
                    .insert_non_existing(PegoutEntry::OnchainUtxo { k: utxo, v: &entry })
                    .map_err(|_| ValidationError::UtxoAlreadyInserted)?;

                data_source.insert_utxo(utxo, entry)?;
                continue;
            };

            let updated_entry = OnchainUtxoEntry {
                utxo: unval.utxo,
                txids: {
                    let mut e = unval.txids.to_vec();
                    e.push(proposal.txid);
                    e.into()
                },
            };

            self.trie
                .update_existing(
                    // New entry.
                    PegoutEntry::OnchainUtxo {
                        k: utxo,
                        v: &updated_entry,
                    },
                    // VALIDATE: The passed-on entry is valid.
                    PegoutEntry::OnchainUtxo { k: utxo, v: &unval },
                )
                .map_err(|_| ValidationError::UtxoBadPreviousRef)?;

            let prev: OnchainUtxoEntry = unval; // OK!

            if prev.txids.contains(&proposal.txid) {
                return Err(ValidationError::TxidAlreadyInserted.into());
            }

            data_source.insert_utxo(utxo, updated_entry)?;
        }

        Ok(())
    }
    pub fn finalize_bitcoin_header<DS: DataSource>(
        &mut self,
        block_hash: BlockHash,
        data_source: &mut DS,
    ) -> Result<(), PegoutError<DS::Error>> {
        let unval = data_source.get_header(&block_hash)?.unwrap();
        self.trie
            .remove_existing(PegoutEntry::OnchainHeader {
                k: &block_hash,
                v: &unval,
            })
            .map_err(|_| ValidationError::HeaderDoesNotExist)?;

        let header: OnchainHeaderEntry = unval; // OK!

        data_source.remove_header(&block_hash)?;

        let mut finalized_txids: HashSet<Txid> = HashSet::new();
        let mut finalized_utxos: HashSet<OutPoint> = HashSet::new();
        let mut finalized_pegouts: HashSet<PegoutId> = HashSet::new();

        // For each finalized Txid, lookup the proposal.
        for finalized_txid in &header.proposals {
            let unval = data_source.get_proposal(finalized_txid)?.unwrap();
            self.trie.remove_existing(PegoutEntry::Proposal {
                //
                k: finalized_txid,
                v: &unval,
            })?;

            let proposal: ProposalEntry = unval; // OK!

            if !finalized_txids.insert(proposal.txid) {
                // FATAL: Bitcoin should prevent this.
                panic!()
            }

            for utxo in proposal.utxos {
                if !finalized_utxos.insert(utxo) {
                    // FATAL: Bitcoin should prevent this.
                    panic!()
                }
            }

            for pegout in &proposal.pegouts {
                if !finalized_pegouts.insert(pegout.id) {
                    // FATAL: Bitcoin should prevent this.
                    panic!()
                }
            }

            data_source.finalize_proposal(&proposal.txid)?;
        }

        let mut competing_txids: HashSet<Txid> = HashSet::new();

        for finalized_utxo in &finalized_utxos {
            let unval = data_source.get_utxo(finalized_utxo)?.unwrap();
            self.trie.remove_existing(PegoutEntry::OnchainUtxo {
                //
                k: finalized_utxo,
                v: &unval,
            })?;

            let entry: OnchainUtxoEntry = unval; // OK!

            for txid in &entry.txids {
                if !finalized_txids.contains(txid) {
                    competing_txids.insert(*txid);
                }
            }

            // TODO: Should call something like `entry.utxo` (TBD)
            data_source.finalize_utxo(finalized_utxo)?;
        }

        for competing_txid in &competing_txids {
            let unval = data_source.get_proposal(competing_txid)?.unwrap();
            self.trie.remove_existing(PegoutEntry::Proposal {
                //
                k: competing_txid,
                v: &unval,
            })?;

            let competing_proposal: ProposalEntry = unval; // OK!

            for utxo in &competing_proposal.utxos {
                self._cleanup_utxo(&competing_txids, utxo, data_source)?
            }

            for pegout in competing_proposal.pegouts {
                let pegout_id = pegout.id;

                if !finalized_pegouts.contains(&pegout_id) {
                    let entry = UnassignedEntry {
                        pegout,
                        candidates: Sorted::empty(), // TODO
                    };

                    self.trie.insert_non_existing(PegoutEntry::Unassigned {
                        k: &pegout_id,
                        v: &entry,
                    })?;

                    data_source.insert_unassigned(&pegout_id, entry)?;
                } else {
                    // Pegout DROPPED - officially finalized!
                }
            }

            data_source.orphan_proposal(&competing_proposal.txid)?;
        }

        Ok(())
    }
    pub fn orphan_bitcoin_header<DS: DataSource>(
        &mut self,
        block_hash: BlockHash,
        data_source: &mut DS,
    ) -> Result<(), PegoutError<DS::Error>> {
        let unval = data_source.get_header(&block_hash)?.unwrap();
        self.trie.remove_existing(PegoutEntry::OnchainHeader {
            k: &block_hash,
            v: &unval,
        })?;

        let header: OnchainHeaderEntry = unval; // OK!

        data_source.remove_header(&block_hash)?;

        let mut orphaned_txids: HashSet<Txid> = HashSet::new();
        let mut orphaned_utxos: HashSet<OutPoint> = HashSet::new();

        // For each orphaned Txid, lookup the proposal.
        for txid in &header.proposals {
            // NOTE: It's possible that an (orphaned) proposal was already
            // removed in `Self::finalize_bitcoin_header` when competing Txids
            // (such as this one) were found. Competing proposals are no longer
            // picked up by the Bitcoin mempool since Utxo reuse is prohibited.
            let Some(unval) = data_source.get_proposal(txid)? else {
                // TODO: Should still do a state check by key!
                continue;
            };

            self.trie.ensure_existing(PegoutEntry::Proposal {
                //
                k: txid,
                v: &unval,
            })?;

            let proposal: ProposalEntry = unval; // OK!

            if !orphaned_txids.insert(proposal.txid) {
                // FATAL: Bitcoin should prevent this.
                panic!()
            }

            for utxo in proposal.utxos {
                if !orphaned_utxos.insert(utxo) {
                    // FATAL: Bitcoin should prevent this.
                    panic!()
                }
            }

            // NOTE: The orphaned proposal MUST REMAIN in the state, since the
            // Bitcoin mempool might pick those up again!
        }

        for orphaned_utxo in &orphaned_utxos {
            self._cleanup_utxo(&orphaned_txids, orphaned_utxo, data_source)?
        }

        Ok(())
    }
    pub fn _cleanup_utxo<DS: DataSource>(
        &mut self,
        exclude: &HashSet<Txid>,
        utxo: &OutPoint,
        data_source: &mut DS,
    ) -> Result<(), PegoutError<DS::Error>> {
        let Some(unval) = data_source.get_utxo(utxo)? else {
            // The Utxo was already removed, nothing left to do.
            return Ok(());
        };

        // Remove self from Txid set.
        let updated_entry = OnchainUtxoEntry {
            utxo: unval.utxo,
            txids: {
                let mut e = unval.txids.to_vec();
                e.retain(|txid| !exclude.contains(txid));
                e.into()
            },
        };

        if updated_entry.txids.is_empty() {
            self.trie.remove_existing(PegoutEntry::OnchainUtxo {
                //
                k: utxo,
                v: &unval,
            })?;

            // TODO: Comment on this.
            data_source.orphan_utxo(utxo)?;
        } else {
            self.trie.update_existing(
                // New entry
                PegoutEntry::OnchainUtxo {
                    k: utxo,
                    v: &updated_entry,
                },
                // Previous entry
                PegoutEntry::OnchainUtxo { k: utxo, v: &unval },
            )?;
        }

        let _txids = unval; // OK!

        Ok(())
    }
}
