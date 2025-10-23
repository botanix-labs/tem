use crate::{
    foundation::{
        self, AtomicError,
        commitment::{MultisigId, sorted::Sorted},
        component::{
            AtomicDataLayer, BotanixLayer, DataLayerError,
            pegout::{
                DataSource, DataSourceError, OnchainHeaderEntry, OnchainUtxoEntry, PegoutError,
                ProposalEntry, UnassignedEntry,
            },
        },
    },
    test_utils::{gen_bitcoin_txid, gen_bitcoin_utxo, gen_pegout_with_id},
    validation::pegout::{PegoutId, PegoutWithId},
};
use bitcoin::{BlockHash, OutPoint, Txid};
use rand::Rng;
use std::{
    collections::{HashMap, VecDeque},
    ops::{Deref, DerefMut},
};

mod foundation_interface;
mod header_finalize;
mod insert_proposal;
mod register_transaction;

const ALICE: MultisigId = 0;
const BOB: MultisigId = 1;
const EVE: MultisigId = 2;

#[derive(Debug, Clone, Default)]
pub struct InMemoryDataSource {
    candidates: Sorted<MultisigId>,
    unassigned: VecDeque<PegoutWithId>,
    //
    data_proposals: HashMap<Txid, ProposalEntry>,
    data_unassigned: HashMap<PegoutId, UnassignedEntry>,
    data_utxo: HashMap<OutPoint, OnchainUtxoEntry>,
    data_header: HashMap<BlockHash, OnchainHeaderEntry>,
    //
    // TODO: trash for headers
    trash_finalized_proposals: HashMap<Txid, ProposalEntry>,
    trash_orphaned_proposals: HashMap<Txid, ProposalEntry>,
    trash_finalized_utxos: HashMap<OutPoint, OnchainUtxoEntry>,
    trash_orphaned_utxos: HashMap<OutPoint, OnchainUtxoEntry>,
}

impl InMemoryDataSource {
    pub fn new() -> Self {
        InMemoryDataSource {
            candidates: vec![ALICE, BOB].into(),
            unassigned: (0..50).into_iter().map(|_| gen_pegout_with_id()).collect(),
            ..Default::default()
        }
    }
    pub fn setup_pegout_state(&mut self, layer: &mut BotanixLayer<'_>) {
        let candidates = self.candidates.clone();
        let unassigned = self.unassigned.clone();

        for pegout in unassigned {
            layer
                .insert_unassigned(pegout, candidates.clone(), self)
                .unwrap();
        }
    }
    pub fn candidates(&self) -> &Sorted<MultisigId> {
        &self.candidates
    }
    pub fn gen_new_proposal(&mut self, fed_id: MultisigId, botanix_height: u64) -> ProposalEntry {
        let mut utxos = vec![];
        for _ in 0..rand::rng().random_range::<usize, _>(2..=5) {
            utxos.push(gen_bitcoin_utxo());
        }

        let mut pegouts = vec![];
        for _ in 0..rand::rng().random_range::<usize, _>(2..=5) {
            let p = self
                .unassigned
                .pop_back()
                .expect("out of unassigned pegouts");

            pegouts.push(p);
        }

        let prop = ProposalEntry {
            txid: gen_bitcoin_txid(),
            fed_id,
            botanix_height,
            utxos: utxos.into(),
            pegouts: pegouts.into(),
        };

        prop
    }
    pub fn gen_upgrade_proposal_reused_pegout(&mut self, other: &ProposalEntry) -> ProposalEntry {
        let mut utxos = vec![other.utxos.first().unwrap().clone()];
        for _ in 0..rand::rng().random_range::<usize, _>(2..=5) {
            utxos.push(gen_bitcoin_utxo());
        }

        let mut pegouts = vec![other.pegouts.first().unwrap().clone()];
        for _ in 0..rand::rng().random_range::<usize, _>(2..=5) {
            let p = self
                .unassigned
                .pop_back()
                .expect("out of unassigned pegouts");

            pegouts.push(p);
        }

        let prop = ProposalEntry {
            txid: gen_bitcoin_txid(),
            fed_id: other.fed_id,
            botanix_height: other.botanix_height,
            utxos: utxos.into(),
            pegouts: pegouts.into(),
        };

        prop
    }
}

pub struct InMemoryDataLayer {
    db: InMemoryDataSource,
    prev_db: Option<InMemoryDataSource>,
}

impl InMemoryDataLayer {
    pub fn new() -> Self {
        InMemoryDataLayer {
            db: InMemoryDataSource::new(),
            prev_db: None,
        }
    }
}

impl Deref for InMemoryDataLayer {
    type Target = InMemoryDataSource;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DerefMut for InMemoryDataLayer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.db
    }
}

impl AtomicDataLayer for InMemoryDataLayer {
    type BackendError = ();
    type Transaction = InMemoryDataSource;

    fn commit(&mut self) -> Result<(), DataLayerError<Self::BackendError>> {
        let prev_db = self
            .prev_db
            .take()
            .ok_or(AtomicError::CommitmentLayerNotStarted)?;

        debug_assert!(self.prev_db.is_none());

        // Just drop the previous state.
        std::mem::drop(prev_db);

        Ok(())
    }
    fn rollback(&mut self) -> Result<(), DataLayerError<Self::BackendError>> {
        let prev_db = self
            .prev_db
            .take()
            .ok_or(AtomicError::CommitmentLayerNotStarted)?;

        // Reset to previous state.
        self.db = prev_db;

        debug_assert!(self.prev_db.is_none());

        Ok(())
    }
    fn start_data_tx<'tx>(
        &'tx mut self,
    ) -> Result<&'tx mut Self::Transaction, DataLayerError<Self::BackendError>> {
        if self.prev_db.is_some() {
            return Err(AtomicError::CommitmentLayerAlreadyStarted.into());
        }

        // NOTE: For the purely in-memory database, we just do a full copy. This
        // is not ideal, of course, but since it's going to be used primarily
        // for testing purposes anyway, we consider that acceptable.
        self.prev_db = Some(self.db.clone());

        Ok(&mut self.db)
    }
}

impl DataSource for InMemoryDataSource {
    type Error = ();

    fn insert_unassigned(
        &mut self,
        pegout: &PegoutId,
        entry: UnassignedEntry,
    ) -> Result<(), DataSourceError<Self::Error>> {
        self.data_unassigned.insert(*pegout, entry);
        Ok(())
    }

    fn get_unassigned(
        &mut self,
        pegout: &PegoutId,
    ) -> Result<Option<UnassignedEntry>, DataSourceError<Self::Error>> {
        Ok(self.data_unassigned.get(pegout).cloned())
    }

    fn remove_unassigned(&mut self, pegout: &PegoutId) -> Result<(), DataSourceError<Self::Error>> {
        self.data_unassigned.remove(pegout);
        Ok(())
    }

    fn insert_utxo(
        &mut self,
        utxo: &OutPoint,
        entry: OnchainUtxoEntry,
    ) -> Result<(), DataSourceError<Self::Error>> {
        self.data_utxo.insert(*utxo, entry);
        Ok(())
    }

    fn get_utxo(
        &mut self,
        utxo: &OutPoint,
    ) -> Result<Option<OnchainUtxoEntry>, DataSourceError<Self::Error>> {
        Ok(self.data_utxo.get(utxo).cloned())
    }

    fn finalize_utxo(&mut self, utxo: &OutPoint) -> Result<(), DataSourceError<Self::Error>> {
        let entry = self.data_utxo.remove(utxo).unwrap();
        let prev = self.trash_finalized_utxos.insert(*utxo, entry);
        assert!(prev.is_none());
        Ok(())
    }

    fn orphan_utxo(&mut self, utxo: &OutPoint) -> Result<(), DataSourceError<Self::Error>> {
        let entry = self.data_utxo.remove(utxo).unwrap();
        let prev = self.trash_orphaned_utxos.insert(*utxo, entry);
        assert!(prev.is_none());
        Ok(())
    }

    fn insert_header(
        &mut self,
        block: &BlockHash,
        entry: OnchainHeaderEntry,
    ) -> Result<(), DataSourceError<Self::Error>> {
        self.data_header.insert(*block, entry);
        Ok(())
    }

    fn get_header(
        &mut self,
        block: &BlockHash,
    ) -> Result<Option<OnchainHeaderEntry>, DataSourceError<Self::Error>> {
        Ok(self.data_header.get(block).cloned())
    }

    fn remove_header(&mut self, block: &BlockHash) -> Result<(), DataSourceError<Self::Error>> {
        self.data_header.remove(block);
        Ok(())
    }

    fn insert_pegout_proposal(
        &mut self,
        txid: &Txid,
        proposal: ProposalEntry,
    ) -> Result<(), DataSourceError<Self::Error>> {
        self.data_proposals.insert(*txid, proposal);
        Ok(())
    }

    fn get_proposal(
        &mut self,
        txid: &Txid,
    ) -> Result<Option<ProposalEntry>, DataSourceError<Self::Error>> {
        Ok(self.data_proposals.get(txid).cloned())
    }

    fn finalize_proposal(&mut self, txid: &Txid) -> Result<(), DataSourceError<Self::Error>> {
        let entry = self.data_proposals.remove(txid).unwrap();
        let prev = self.trash_finalized_proposals.insert(*txid, entry);
        assert!(prev.is_none());
        Ok(())
    }

    fn orphan_proposal(&mut self, txid: &Txid) -> Result<(), DataSourceError<Self::Error>> {
        let entry = self.data_proposals.remove(txid).unwrap();
        let prev = self.trash_orphaned_proposals.insert(*txid, entry);
        assert!(prev.is_none());
        Ok(())
    }
}
