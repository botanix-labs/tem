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
        component::{BotanixLayer, BotanixLayerError, Checked, DatabaseError, ToCommit},
    },
    validation::pegout::{PegoutId, PegoutWithId},
};
use bitcoin::{BlockHash, OutPoint, Txid};
use hash_db::HashDB;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use trie_db::DBValue;

const T_GLOBAL: &[u8] = b"commitment-trie";
//
const T_UNASSIGNED: &str = "pegout:unassigned";
const T_PROPOSAL: &str = "pegout:proposal";
const T_ONCHAIN_UTXO: &str = "pegout:onchain-utxo";
const T_ONCHAIN_HEADER: &str = "pegout:onchain-header";

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

/// Freshly initiated pegout on the Botanix EVM, or pegouts that have been
/// orphaned and are not included in any competing proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EUnassigned {
    pub k: PegoutId,
    pub v: UnassignedEntry,
}

/// Proposals are always tracked, whether they're on-chain or not (mempool). The
/// only time a Proposal is removed is if gets finalized, or if a competing
/// Proposal is finalized that has reused at least one Utxo - implying that this
/// Proposal is orphaned!
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EProposal {
    pub k: Txid,
    pub v: ProposalEntry,
}

/// A Utxo that has been spotted on-chain. This is required to check for
/// finalization events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EOnchainUtxo {
    pub k: OutPoint,
    pub v: OnchainUtxoEntry,
}

/// A Header that has been spotted on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EOnchainHeader {
    pub k: BlockHash,
    pub v: OnchainHeaderEntry,
}

impl EntryT for EUnassigned {
    fn as_key(&self) -> StorageKey {
        let mut h = CommitHasher::new(T_GLOBAL);
        //
        h.append_message(b"table", T_UNASSIGNED.as_bytes());
        self.k.append_to_commit(&mut h);
        //
        StorageKey::from(h.finalize())
    }
    fn as_value(&self) -> StorageValue {
        let mut h = CommitHasher::new(T_GLOBAL);
        //
        h.append_message(b"table", T_UNASSIGNED.as_bytes());
        self.v.append_to_commit(&mut h);
        //
        StorageValue::from(h.finalize())
    }
    fn as_key_value(&self) -> (StorageKey, StorageValue) {
        (self.as_key(), self.as_value())
    }
    fn partition_name(&self) -> &'static str {
        T_UNASSIGNED
    }
}

impl EntryT for EProposal {
    fn as_key(&self) -> StorageKey {
        let mut h = CommitHasher::new(T_GLOBAL);
        //
        h.append_message(b"table", T_PROPOSAL.as_bytes());
        self.k.append_to_commit(&mut h);
        //
        StorageKey::from(h.finalize())
    }
    fn as_value(&self) -> StorageValue {
        let mut h = CommitHasher::new(T_GLOBAL);
        //
        h.append_message(b"table", T_PROPOSAL.as_bytes());
        self.v.append_to_commit(&mut h);
        //
        StorageValue::from(h.finalize())
    }
    fn as_key_value(&self) -> (StorageKey, StorageValue) {
        (self.as_key(), self.as_value())
    }
    fn partition_name(&self) -> &'static str {
        T_PROPOSAL
    }
}

impl EntryT for EOnchainUtxo {
    fn as_key(&self) -> StorageKey {
        let mut h = CommitHasher::new(T_GLOBAL);
        //
        h.append_message(b"table", T_ONCHAIN_UTXO.as_bytes());
        self.k.append_to_commit(&mut h);
        //
        StorageKey::from(h.finalize())
    }
    fn as_value(&self) -> StorageValue {
        let mut h = CommitHasher::new(T_GLOBAL);
        //
        h.append_message(b"table", T_ONCHAIN_UTXO.as_bytes());
        self.v.append_to_commit(&mut h);
        //
        StorageValue::from(h.finalize())
    }
    fn as_key_value(&self) -> (StorageKey, StorageValue) {
        (self.as_key(), self.as_value())
    }
    fn partition_name(&self) -> &'static str {
        T_ONCHAIN_UTXO
    }
}

impl EntryT for EOnchainHeader {
    fn as_key(&self) -> StorageKey {
        let mut h = CommitHasher::new(T_GLOBAL);
        //
        h.append_message(b"table", T_ONCHAIN_HEADER.as_bytes());
        self.k.append_to_commit(&mut h);
        //
        StorageKey::from(h.finalize())
    }
    fn as_value(&self) -> StorageValue {
        let mut h = CommitHasher::new(T_GLOBAL);
        //
        h.append_message(b"table", T_ONCHAIN_HEADER.as_bytes());
        self.v.append_to_commit(&mut h);
        //
        StorageValue::from(h.finalize())
    }
    fn as_key_value(&self) -> (StorageKey, StorageValue) {
        (self.as_key(), self.as_value())
    }
    fn partition_name(&self) -> &'static str {
        T_ONCHAIN_HEADER
    }
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

impl<D> From<DatabaseError<D>> for PegoutError<D> {
    fn from(err: DatabaseError<D>) -> Self {
        PegoutError::BackendError(super::BackendError::Database(err))
    }
}

impl<D> From<BotanixLayerError<D>> for PegoutError<D> {
    fn from(err: BotanixLayerError<D>) -> Self {
        match err {
            BotanixLayerError::Database(err) => {
                PegoutError::BackendError(super::BackendError::Database(err))
            }
            BotanixLayerError::Fatal(err) => {
                PegoutError::BackendError(super::BackendError::Fatal(err))
            }
            BotanixLayerError::NotExists => {
                PegoutError::ValidationError(ValidationError::InvalidState)
            }
            BotanixLayerError::Validation { partition, kind } => {
                PegoutError::ValidationError(ValidationError::StateError { partition, kind })
            }
        }
    }
}

impl<D> From<trie::Error> for PegoutError<D> {
    fn from(err: trie::Error) -> Self {
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
    InvalidState,
    StateError {
        partition: &'static str,
        kind: ErrorKind,
    },
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

pub trait DataSource {
    type Error;

    fn insert_unassigned(
        &mut self,
        entry: Checked<EUnassigned>,
    ) -> Result<(), DatabaseError<Self::Error>>;
    fn get_unassigned(
        &mut self,
        pegout: &PegoutId,
    ) -> Result<Option<EUnassigned>, DatabaseError<Self::Error>>;
    fn remove_unassigned(
        &mut self,
        entry: Checked<EUnassigned>,
    ) -> Result<(), DatabaseError<Self::Error>>;
    //
    fn insert_utxo(
        &mut self,
        entry: Checked<EOnchainUtxo>,
    ) -> Result<(), DatabaseError<Self::Error>>;
    fn get_utxo(
        &mut self,
        utxo: &OutPoint,
    ) -> Result<Option<EOnchainUtxo>, DatabaseError<Self::Error>>;
    fn finalize_utxo(
        &mut self,
        entry: Checked<EOnchainUtxo>,
    ) -> Result<(), DatabaseError<Self::Error>>;
    fn orphan_utxo(
        &mut self,
        entry: Checked<EOnchainUtxo>,
    ) -> Result<(), DatabaseError<Self::Error>>;
    //
    fn insert_header(
        &mut self,
        entry: Checked<EOnchainHeader>,
    ) -> Result<(), DatabaseError<Self::Error>>;
    fn get_header(
        &mut self,
        block: &BlockHash,
    ) -> Result<Option<EOnchainHeader>, DatabaseError<Self::Error>>;
    fn remove_header(
        &mut self,
        entry: Checked<EOnchainHeader>,
    ) -> Result<(), DatabaseError<Self::Error>>;
    //
    fn insert_pegout_proposal(
        &mut self,
        entry: Checked<EProposal>,
    ) -> Result<(), DatabaseError<Self::Error>>;
    fn get_proposal(
        &mut self,
        txid: &Txid,
    ) -> Result<Option<EProposal>, DatabaseError<Self::Error>>;
    fn finalize_proposal(
        &mut self,
        entry: Checked<EProposal>,
    ) -> Result<(), DatabaseError<Self::Error>>;
    fn orphan_proposal(
        &mut self,
        entry: Checked<EProposal>,
    ) -> Result<(), DatabaseError<Self::Error>>;
}

impl<'db, DB> BotanixLayer<'db, DB>
where
    DB: HashDB<CommitHasher, DBValue> + DataSource,
{
    /// Moves a pegout to the initiated state, making it available for spending.
    ///
    /// Creates a new pegout entry in the initiated table while ensuring it
    /// doesn't already exist in any state. This is typically called when a new
    /// pegout request is received from the Botanix chain.
    ///
    /// # State Changes
    /// - Sets the pegout to initiated state
    pub fn insert_unassigned(
        &mut self,
        pegout: PegoutWithId,
        candidates: Sorted<MultisigId>,
    ) -> Result<(), PegoutError<<DB as DataSource>::Error>> {
        let id = pegout.id;
        let value = UnassignedEntry { pegout, candidates };

        self.insert_checked(
            EUnassigned { k: id, v: value },
            //
            |db, checked| db.insert_unassigned(checked),
        )
        .map_err(|_| ValidationError::UnassignedPegoutAlreadyInserted)?;

        Ok(())
    }
    // TODO: Use untrusted_* notation for fields?
    pub fn insert_pegout_proposal(
        &mut self,
        proposal: ProposalEntry,
        prev_proposal: Option<Txid>,
    ) -> Result<(), PegoutError<<DB as DataSource>::Error>> {
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

        if let Some(prev) = prev_proposal {
            // VALIDATE: The previous proposal must exist.
            let prev: Checked<_> = self
                .get_checked(|db| db.get_proposal(&prev))
                .map_err(|_| ValidationError::UpgradedProposalBadPreviousRef)?;

            // VALIDATE: Only the original author is allowed to upgrade a
            // proposal.
            if prev.v.fed_id != proposal.fed_id {
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
            let utxo_to_reuse = &prev.v.utxos[0];
            if !used_utxos.contains(&utxo_to_reuse) {
                return Err(ValidationError::UpgradedProposalMustReuseUtxo.into());
            }

            // VALIDATE: Any pegout in the new proposal that is NOT in the previous
            // proposal MUST be in an unassigned state, which is then claimed.
            for pegout in used_pegouts {
                if prev.v.pegouts.contains(pegout) {
                    continue;
                }

                let unassigned: Checked<_> =
                    self.get_checked(|db| db.get_unassigned(&pegout.id))
                        .map_err(|_| ValidationError::UnassignedPegoutInvalidOrAlreadyProposed)?;

                // VALIDATE: The federation is qualified to claim that pegout.
                if !unassigned.v.candidates.contains(&proposal.fed_id) {
                    return Err(ValidationError::BadCandidateClaim.into());
                }

                self.remove_checked(unassigned.consume(), |db, checked| {
                    db.remove_unassigned(checked)
                })
                .map_err(|_| ValidationError::UnassignedPegoutInvalidOrAlreadyProposed)?;
            }
        } else {
            // VALIDATE: If no previous propsal exists, then EVERY pegout MUST
            // be in an unassigned state, which are then claimed.
            for pegout in used_pegouts {
                let unassigned: Checked<_> =
                    self.get_checked(|db| db.get_unassigned(&pegout.id))
                        .map_err(|_| ValidationError::UnassignedPegoutInvalidOrAlreadyProposed)?;

                // VALIDATE: The federation is qualified to claim that pegout.
                if !unassigned.v.candidates.contains(&proposal.fed_id) {
                    return Err(ValidationError::BadCandidateClaim.into());
                }

                self.remove_checked(unassigned.consume(), |db, checked| {
                    db.remove_unassigned(checked)
                })
                .map_err(|_| ValidationError::UnassignedPegoutInvalidOrAlreadyProposed)?;
            }
        }

        self.insert_checked(
            EProposal {
                k: proposal.txid,
                v: proposal,
            },
            //
            |db, checked| db.insert_pegout_proposal(checked),
        )
        .map_err(|_| ValidationError::ProposalAlreadyInserted)?;

        Ok(())
    }
    // TODO: Should `bitcoin_height` be specifically validated?
    pub fn insert_bitcoin_header(
        &mut self,
        block_hash: BlockHash,
        bitcoin_height: u64,
    ) -> Result<(), PegoutError<<DB as DataSource>::Error>> {
        let entry = OnchainHeaderEntry {
            block_hash,
            bitcoin_height,
            proposals: vec![].into(),
        };

        // VALIDATE: The passed-on header has not been tracked yet.
        self.insert_checked(
            EOnchainHeader {
                k: block_hash,
                v: entry,
            },
            //
            |db, checked| db.insert_header(checked),
        )?;

        Ok(())
    }
    pub fn register_bitcoin_tx(
        &mut self,
        block_hash: BlockHash,
        txid: Txid,
    ) -> Result<(), PegoutError<<DB as DataSource>::Error>> {
        let proposal: Checked<_> = self
            .get_checked(|db| db.get_proposal(&txid))
            .map_err(|_| ValidationError::ProposalDoesNotExist)?;

        let header: Checked<_> = self.get_checked(|db| db.get_header(&block_hash))?;

        if header.v.proposals.contains(&txid) {
            return Err(ValidationError::TxidAlreadyInserted.into());
        }

        let updated_proposals: Sorted<Txid> = {
            let mut p = header.v.proposals.to_vec();
            p.push(txid);
            p.into()
        };

        let entry = OnchainHeaderEntry {
            block_hash,
            bitcoin_height: header.v.bitcoin_height,
            proposals: updated_proposals,
        };

        self.update_checked(
            // New entry
            EOnchainHeader {
                k: block_hash,
                v: entry,
            },
            // Previous (checked) entry
            header,
            //
            |db, checked| db.insert_header(checked),
        )
        .map_err(|_| ValidationError::HeaderBadPreviousRef)?;

        debug_assert!(!proposal.v.utxos.is_empty());

        for utxo in proposal.v.utxos.iter().copied() {
            let Some(prev) = self.get_checked_optional(|db| db.get_utxo(&utxo))? else {
                let value = OnchainUtxoEntry {
                    utxo,
                    txids: vec![txid].into(),
                };

                self.insert_checked(
                    EOnchainUtxo { k: utxo, v: value },
                    //
                    |db, checked| db.insert_utxo(checked),
                )?;

                continue;
            };

            let prev: Checked<_> = prev;

            if prev.v.txids.contains(&txid) {
                return Err(ValidationError::TxidAlreadyInserted.into());
            }

            let updated_entry = OnchainUtxoEntry {
                utxo: prev.v.utxo,
                txids: {
                    let mut e = prev.v.txids.to_vec();
                    e.push(txid);
                    e.into()
                },
            };

            self.update_checked(
                // New entry
                EOnchainUtxo {
                    k: utxo,
                    v: updated_entry,
                },
                // Previous (checked) entry
                prev,
                //
                |db, checked| db.insert_utxo(checked),
            )
            .map_err(|_| ValidationError::UtxoBadPreviousRef)?;
        }

        Ok(())
    }
    pub fn finalize_bitcoin_header(
        &mut self,
        block_hash: BlockHash,
    ) -> Result<(), PegoutError<<DB as DataSource>::Error>> {
        let header: Checked<_> = self.get_checked(|db| db.get_header(&block_hash))?;

        let mut finalized_txids: HashSet<Txid> = HashSet::new();
        let mut finalized_utxos: HashSet<OutPoint> = HashSet::new();
        let mut finalized_pegouts: HashSet<PegoutId> = HashSet::new();

        // For each finalized Txid, lookup the proposal.
        for finalized_txid in &header.v.proposals {
            let proposal: Checked<_> = self.get_checked(|db| db.get_proposal(finalized_txid))?;

            if !finalized_txids.insert(proposal.v.txid) {
                // FATAL: Bitcoin should prevent this.
                panic!()
            }

            for utxo in &proposal.v.utxos {
                if !finalized_utxos.insert(*utxo) {
                    // FATAL: Bitcoin should prevent this.
                    panic!()
                }
            }

            for pegout in &proposal.v.pegouts {
                if !finalized_pegouts.insert(pegout.id) {
                    // FATAL: Bitcoin should prevent this.
                    panic!()
                }
            }

            self.remove_checked(
                proposal.consume(),
                //
                |db, checked| db.finalize_proposal(checked),
            )?;
        }

        let mut competing_txids: HashSet<Txid> = HashSet::new();

        for finalized_utxo in &finalized_utxos {
            let utxo: Checked<_> = self.get_checked(|db| db.get_utxo(finalized_utxo))?;

            for txid in &utxo.v.txids {
                if !finalized_txids.contains(txid) {
                    competing_txids.insert(*txid);
                }
            }

            self.remove_checked(
                utxo.consume(),
                //
                |db, checked| db.finalize_utxo(checked),
            )?;
        }

        for competing_txid in &competing_txids {
            let competing: Checked<_> = self.get_checked(|db| db.get_proposal(competing_txid))?;

            for utxo in &competing.v.utxos {
                self._cleanup_utxo(&competing_txids, utxo)?
            }

            for pegout in competing.v.pegouts.iter().cloned() {
                let pegout_id = pegout.id;

                if !finalized_pegouts.contains(&pegout_id) {
                    let value = UnassignedEntry {
                        pegout,
                        candidates: Sorted::empty(), // TODO
                    };

                    self.insert_checked(
                        EUnassigned {
                            k: pegout_id,
                            v: value,
                        },
                        //
                        |db, checked| db.insert_unassigned(checked),
                    )?;
                } else {
                    // Pegout DROPPED - officially finalized!
                }
            }

            self.remove_checked(
                competing.consume(),
                //
                |db, checked| db.orphan_proposal(checked),
            )?;
        }

        self.remove_checked(
            header.consume(),
            //
            |db, checked| db.remove_header(checked),
        )
        .map_err(|_| ValidationError::HeaderDoesNotExist)?;

        Ok(())
    }
    pub fn orphan_bitcoin_header(
        &mut self,
        block_hash: BlockHash,
    ) -> Result<(), PegoutError<<DB as DataSource>::Error>> {
        let header = self.get_checked(|db| db.get_header(&block_hash))?;

        let mut orphaned_txids: HashSet<Txid> = HashSet::new();
        let mut orphaned_utxos: HashSet<OutPoint> = HashSet::new();

        // For each orphaned Txid, lookup the proposal.
        for txid in &header.v.proposals {
            // NOTE: It's possible that an (orphaned) proposal was already
            // removed in `Self::finalize_bitcoin_header` when competing Txids
            // (such as this one) were found. Competing proposals are no longer
            // picked up by the Bitcoin mempool since Utxo reuse is prohibited.
            let Some(proposal) = self.get_checked_optional(|db| db.get_proposal(txid))? else {
                continue;
            };

            // IMPORTANT: The orphaned proposal MUST REMAIN in the state, since the
            // Bitcoin mempool might pick it up again!

            if !orphaned_txids.insert(proposal.v.txid) {
                // FATAL: Bitcoin should prevent this.
                panic!()
            }

            for utxo in &proposal.v.utxos {
                if !orphaned_utxos.insert(*utxo) {
                    // FATAL: Bitcoin should prevent this.
                    panic!()
                }
            }
        }

        for orphaned_utxo in &orphaned_utxos {
            self._cleanup_utxo(&orphaned_txids, orphaned_utxo)?
        }

        self.remove_checked(
            header.consume(),
            //
            |db, checked| db.remove_header(checked),
        )?;

        Ok(())
    }
    pub fn _cleanup_utxo(
        &mut self,
        exclude: &HashSet<Txid>,
        utxo: &OutPoint,
    ) -> Result<(), PegoutError<<DB as DataSource>::Error>> {
        let Some(prev) = self.get_checked_optional(|db| db.get_utxo(utxo))? else {
            // The Utxo was already removed, nothing left to do.
            return Ok(());
        };

        // Remove self from Txid set.
        let updated_entry = OnchainUtxoEntry {
            utxo: prev.v.utxo,
            txids: {
                let mut e = prev.v.txids.to_vec();
                e.retain(|txid| !exclude.contains(txid));
                e.into()
            },
        };

        if updated_entry.txids.is_empty() {
            self.remove_checked(
                prev.consume(),
                //
                |db, checked| db.orphan_utxo(checked),
            )?;
        } else {
            self.update_checked(
                // New entry
                EOnchainUtxo {
                    k: *utxo,
                    v: updated_entry,
                },
                // Previous (checked) entry
                prev,
                //
                |db, checked| db.insert_utxo(checked),
            )?;
        }

        Ok(())
    }
}
