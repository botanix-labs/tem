use crate::{
    foundation::{
        AtomicError, AtomicErrorVariant, AtomicLayer, CommitHasher, CommitmentStateRoot,
        commitment::{AliasMemoryDB, DBKey, MultisigId, sorted::Sorted},
        component::{
            BotanixLayer, Checked, DatabaseError,
            pegout::{
                DataSource, EOnchainHeader, EOnchainUtxo, EProposal, EUnassigned,
                OnchainHeaderEntry, OnchainUtxoEntry, ProposalEntry, UnassignedEntry,
            },
        },
    },
    test_utils::{gen_bitcoin_txid, gen_bitcoin_utxo, gen_pegout_with_id},
    validation::pegout::{PegoutId, PegoutWithId},
};
use bitcoin::{BlockHash, OutPoint, Txid};
use hash_db::{AsHashDB, HashDB};
use rand::Rng;
use std::collections::{HashMap, VecDeque};
use trie_db::DBValue;

mod foundation_interface;
mod header_finalize;
mod insert_proposal;
mod register_transaction;

const ALICE: MultisigId = 0;
const BOB: MultisigId = 1;
const EVE: MultisigId = 2;

pub struct InMemoryAtomicLayer {
    db: InMemoryDb,
    root: [u8; 32],
    prev_db: Option<InMemoryDb>,
    prev_root: Option<[u8; 32]>,
}

impl InMemoryAtomicLayer {
    pub fn new() -> Self {
        let (db, root) = InMemoryDb::new();

        let mut atomic = InMemoryAtomicLayer {
            db,
            root,
            prev_db: None,
            prev_root: None,
        };

        // Setup pegout state.
        let candidates = atomic.db.data.candidates.clone();
        let unassigned = atomic.db.data.unassigned.clone();

        {
            let mut b = atomic.start_tx().unwrap();
            for pegout in unassigned {
                b.insert_unassigned(pegout, candidates.clone()).unwrap();
            }
        }

        // Commit changes.
        atomic.commit().unwrap();
        atomic
    }
    /// Convenience method for automatically starting a database transactions
    /// and commiting the result on success or rollback on error.
    pub fn apply<F, T, E>(&mut self, f: F) -> Result<T, E>
    where
        F: FnOnce(BotanixLayer<'_, InMemoryDb>) -> Result<T, E>,
    {
        let tx = self.start_tx().unwrap();
        // Run the provided logic.
        let res = f(tx);

        if res.is_ok() {
            self.commit().unwrap();
        } else {
            self.rollback().unwrap();
        }

        res
    }
    pub fn candidates(&self) -> &Sorted<MultisigId> {
        self.db.data.candidates()
    }
    pub fn gen_new_proposal(&mut self, fed_id: MultisigId, botanix_height: u64) -> ProposalEntry {
        self.db.data.gen_new_proposal(fed_id, botanix_height)
    }
    pub fn gen_upgrade_proposal_reused_pegout(&mut self, other: &ProposalEntry) -> ProposalEntry {
        self.db.data.gen_upgrade_proposal_reused_pegout(other)
    }
}

impl AtomicLayer<InMemoryDb> for InMemoryAtomicLayer {
    // In-memory database never fails.
    type BackendError = ();

    fn start_tx<'db>(
        &'db mut self,
    ) -> Result<BotanixLayer<'db, InMemoryDb>, AtomicError<Self::BackendError>> {
        if self.prev_db.is_some() {
            return Err(AtomicErrorVariant::CommitmentLayerAlreadyStarted.into());
        }

        // NOTE: For the purely in-memory database, we just do a full copy. This
        // is not ideal, of course, but since it's going to be used primarily
        // for testing purposes anyway, we consider that acceptable.
        self.prev_db = Some(self.db.clone());
        self.prev_root = Some(self.root);

        Ok(BotanixLayer::new(&mut self.db, &mut self.root))
    }
    fn commit(&mut self) -> Result<CommitmentStateRoot, AtomicError<Self::BackendError>> {
        // Just drop the previous state.
        let _ = self
            .prev_db
            .take()
            .ok_or(AtomicErrorVariant::CommitmentLayerNotStarted)?;

        let _ = self
            //
            .prev_root
            .take()
            .ok_or(AtomicErrorVariant::CommitmentLayerNotStarted)?;

        debug_assert!(self.prev_db.is_none());
        debug_assert!(self.prev_root.is_none());

        let root = BotanixLayer::new(&mut self.db, &mut self.root).root();
        Ok(root)
    }
    fn rollback(&mut self) -> Result<CommitmentStateRoot, AtomicError<Self::BackendError>> {
        let prev_db = self
            .prev_db
            .take()
            .ok_or(AtomicErrorVariant::CommitmentLayerNotStarted)?;

        let prev_root = self
            .prev_root
            .take()
            .ok_or(AtomicErrorVariant::CommitmentLayerNotStarted)?;

        debug_assert!(self.prev_db.is_none());
        debug_assert!(self.prev_root.is_none());

        // Reset to previous state.
        self.db = prev_db;
        self.root = prev_root;

        let root = BotanixLayer::new(&mut self.db, &mut self.root).root();
        Ok(root)
    }
}

#[derive(Clone)]
pub struct InMemoryDb {
    data: InMemoryDataSource,
    commits: AliasMemoryDB,
}

impl InMemoryDb {
    pub fn new() -> (Self, [u8; 32]) {
        let data = InMemoryDataSource::new();
        let (commits, root) = AliasMemoryDB::default_with_root();

        (InMemoryDb { data, commits }, root)
    }
}

impl HashDB<CommitHasher, DBValue> for InMemoryDb {
    fn contains(&self, key: &DBKey, prefix: hash_db::Prefix) -> bool {
        self.commits.contains(key, prefix)
    }
    fn emplace(&mut self, key: DBKey, prefix: hash_db::Prefix, value: DBValue) {
        self.commits.emplace(key, prefix, value);
    }
    fn get(&self, key: &DBKey, prefix: hash_db::Prefix) -> Option<DBValue> {
        self.commits.get(key, prefix)
    }
    fn insert(&mut self, prefix: hash_db::Prefix, value: &[u8]) -> DBKey {
        self.commits.insert(prefix, value)
    }
    fn remove(&mut self, key: &DBKey, prefix: hash_db::Prefix) {
        self.commits.remove(key, prefix);
    }
}

impl AsHashDB<CommitHasher, DBValue> for InMemoryDb {
    fn as_hash_db(&self) -> &dyn HashDB<CommitHasher, DBValue> {
        self
    }
    fn as_hash_db_mut<'a>(&'a mut self) -> &'a mut (dyn HashDB<CommitHasher, DBValue> + 'a) {
        self
    }
}

impl DataSource for InMemoryDb {
    // In-memory database never fails.
    type Error = ();

    fn insert_unassigned(
        &mut self,
        entry: Checked<EUnassigned>,
    ) -> Result<(), DatabaseError<Self::Error>> {
        self.data.data_unassigned.insert(entry.k, entry.consume().v);
        Ok(())
    }

    fn get_unassigned(
        &mut self,
        pegout: &PegoutId,
    ) -> Result<Option<EUnassigned>, DatabaseError<Self::Error>> {
        Ok(self.data.data_unassigned.get(pegout).map(|v| EUnassigned {
            k: *pegout,
            v: v.clone(),
        }))
    }

    fn remove_unassigned(
        &mut self,
        entry: Checked<EUnassigned>,
    ) -> Result<(), DatabaseError<Self::Error>> {
        self.data.data_unassigned.remove(&entry.k);
        Ok(())
    }
    //
    fn insert_utxo(
        &mut self,
        entry: Checked<EOnchainUtxo>,
    ) -> Result<(), DatabaseError<Self::Error>> {
        self.data.data_utxo.insert(entry.k, entry.consume().v);
        Ok(())
    }

    fn get_utxo(
        &mut self,
        utxo: &OutPoint,
    ) -> Result<Option<EOnchainUtxo>, DatabaseError<Self::Error>> {
        Ok(self.data.data_utxo.get(utxo).map(|v| EOnchainUtxo {
            k: *utxo,
            v: v.clone(),
        }))
    }

    fn finalize_utxo(
        &mut self,
        entry: Checked<EOnchainUtxo>,
    ) -> Result<(), DatabaseError<Self::Error>> {
        let removed_entry = self.data.data_utxo.remove(&entry.k).unwrap();
        let prev = self
            .data
            .trash_finalized_utxos
            .insert(entry.k, removed_entry);
        assert!(prev.is_none());
        Ok(())
    }

    fn orphan_utxo(
        &mut self,
        entry: Checked<EOnchainUtxo>,
    ) -> Result<(), DatabaseError<Self::Error>> {
        let removed_entry = self.data.data_utxo.remove(&entry.k).unwrap();
        let prev = self
            .data
            .trash_orphaned_utxos
            .insert(entry.k, removed_entry);
        assert!(prev.is_none());
        Ok(())
    }
    //
    fn insert_header(
        &mut self,
        entry: Checked<EOnchainHeader>,
    ) -> Result<(), DatabaseError<Self::Error>> {
        self.data.data_header.insert(entry.k, entry.consume().v);
        Ok(())
    }

    fn get_header(
        &mut self,
        block: &BlockHash,
    ) -> Result<Option<EOnchainHeader>, DatabaseError<Self::Error>> {
        Ok(self.data.data_header.get(block).map(|v| EOnchainHeader {
            k: *block,
            v: v.clone(),
        }))
    }

    fn remove_header(
        &mut self,
        entry: Checked<EOnchainHeader>,
    ) -> Result<(), DatabaseError<Self::Error>> {
        self.data.data_header.remove(&entry.k);
        Ok(())
    }
    //
    fn insert_pegout_proposal(
        &mut self,
        entry: Checked<EProposal>,
    ) -> Result<(), DatabaseError<Self::Error>> {
        self.data.data_proposals.insert(entry.k, entry.consume().v);
        Ok(())
    }

    fn get_proposal(
        &mut self,
        txid: &Txid,
    ) -> Result<Option<EProposal>, DatabaseError<Self::Error>> {
        Ok(self.data.data_proposals.get(txid).map(|v| EProposal {
            k: *txid,
            v: v.clone(),
        }))
    }

    fn finalize_proposal(
        &mut self,
        entry: Checked<EProposal>,
    ) -> Result<(), DatabaseError<Self::Error>> {
        let removed_entry = self.data.data_proposals.remove(&entry.k).unwrap();
        let prev = self
            .data
            .trash_finalized_proposals
            .insert(entry.k, removed_entry);
        assert!(prev.is_none());
        Ok(())
    }

    fn orphan_proposal(
        &mut self,
        entry: Checked<EProposal>,
    ) -> Result<(), DatabaseError<Self::Error>> {
        let removed_entry = self.data.data_proposals.remove(&entry.k).unwrap();
        let prev = self
            .data
            .trash_orphaned_proposals
            .insert(entry.k, removed_entry);
        assert!(prev.is_none());
        Ok(())
    }
}

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
