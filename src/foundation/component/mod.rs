use crate::{
    foundation::{
        CommitHasher,
        commitment::{
            AliasFatDBMut, CommitSchema, MultisigId,
            sorted::Sorted,
            trie::{self, CommitmentStateRoot, EntryT, TrieLayer},
        },
    },
    validation::pegout::{PegoutData, PegoutId, PegoutWithId},
};
use bitcoin::hashes::Hash;
use hash_db::HashDB;
use trie_db::DBValue;

pub mod pegout;

// TODO: Should probably be in `foundation::commitment`?
/// Convenience trait for types that can be committed to a Merlin transcript.
pub trait ToCommit {
    /// Appends this type's data to the given transcript.
    ///
    /// Must be deterministic - identical values must produce identical
    /// transcript modifications across all implementations.
    fn append_to_commit(&self, h: &mut CommitHasher);
}

impl<T> ToCommit for &T
where
    T: ToCommit,
{
    fn append_to_commit(&self, h: &mut CommitHasher) {
        (*self).append_to_commit(h)
    }
}

impl<T> ToCommit for Sorted<T>
where
    T: ToCommit,
{
    fn append_to_commit(&self, h: &mut CommitHasher) {
        h.append_u64(b"sorted_list:len", self.len() as u64);

        for i in self.iter() {
            i.append_to_commit(h)
        }
    }
}

impl ToCommit for MultisigId {
    fn append_to_commit(&self, h: &mut CommitHasher) {
        h.append_u64(b"botanix:multisig_id", *self);
    }
}

impl ToCommit for bitcoin::Txid {
    fn append_to_commit(&self, h: &mut CommitHasher) {
        h.append_message(b"bitcoin:txid", self.as_raw_hash().as_byte_array());
    }
}

impl ToCommit for bitcoin::BlockHash {
    fn append_to_commit(&self, h: &mut CommitHasher) {
        h.append_message(b"bitcoin:block_hash", self.as_raw_hash().as_byte_array());
    }
}

impl ToCommit for bitcoin::network::Network {
    fn append_to_commit(&self, h: &mut CommitHasher) {
        let b: u64 = match self {
            bitcoin::Network::Bitcoin => 0,
            bitcoin::Network::Testnet => 1,
            bitcoin::Network::Signet => 2,
            bitcoin::Network::Regtest => 3,
            // From the `bitcoin` crate:
            //
            // > Bitcoin's testnet4 network. (In future versions this will be
            // > combined into a single variant containing the version)
            //
            // ¯\_(ツ)_/¯
            bitcoin::Network::Testnet4 => 4,
        };
        h.append_u64(b"bitcoin:network", b);
    }
}

impl ToCommit for bitcoin::OutPoint {
    fn append_to_commit(&self, h: &mut CommitHasher) {
        // Deconstruct so we do not miss anything accidentally.
        let bitcoin::OutPoint { txid, vout } = self;

        txid.append_to_commit(h);
        h.append_u64(b"bitcoin:vout", *vout as u64);
    }
}

impl ToCommit for PegoutId {
    fn append_to_commit(&self, h: &mut CommitHasher) {
        // Deconstruct so we do not miss anything accidentally.
        let PegoutId { tx_hash, log_idx } = self;

        h.append_message(b"pegout:tx_hash", tx_hash.as_slice());
        h.append_u64(b"pegout:log_idx", *log_idx as u64);
    }
}

impl ToCommit for PegoutData {
    fn append_to_commit(&self, h: &mut CommitHasher) {
        // Deconstruct so we do not miss anything accidentally.
        let PegoutData {
            amount,
            destination,
            network,
        } = self;

        h.append_u64(b"pegout:amount", amount.to_sat());
        h.append_message(b"pegout:dest", destination.script_pubkey().as_bytes());
        network.append_to_commit(h);
    }
}

impl ToCommit for PegoutWithId {
    fn append_to_commit(&self, h: &mut CommitHasher) {
        // Deconstruct so we do not miss anything accidentally.
        let PegoutWithId { id, data } = self;

        id.append_to_commit(h);
        data.append_to_commit(h);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError<T> {
    Database(DatabaseError<T>),
    Fatal(trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseError<T>(pub T);

impl<D> From<D> for DatabaseError<D> {
    fn from(value: D) -> Self {
        DatabaseError(value)
    }
}

/// A checked type returned by [`BotanixLayer`].
// TODO: Should be in it's own private module!
pub struct Checked<T>(/*PRIVATE*/ T);

impl<T> Checked<T> {
    pub fn consume(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for Checked<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> std::ops::Deref for Checked<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Checked<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub enum BotanixLayerError<D> {
    Validation {
        partition: &'static str,
        kind: trie::ErrorKind,
    },
    NotExists,
    Database(DatabaseError<D>),
    Fatal(trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>),
}

impl<D> From<DatabaseError<D>> for BotanixLayerError<D> {
    fn from(err: DatabaseError<D>) -> Self {
        BotanixLayerError::Database(err)
    }
}

impl<D> From<trie::Error> for BotanixLayerError<D> {
    fn from(err: trie::Error) -> Self {
        match err {
            trie::Error::Mod { partition, kind } => {
                BotanixLayerError::Validation { partition, kind }
            }
            trie::Error::Fatal(err) => {
                //
                BotanixLayerError::Fatal(err)
            }
        }
    }
}

/// Higher-level interface for Botanix state operations within the commitment
/// trie.
///
/// Provides validated operations for pegout lifecycle management and Bitcoin
/// block processing. All methods include comprehensive state validation to
/// prevent invalid transitions and maintain trie consistency.
// TODO: Move this to it's own separate module, so it's inner fields are not exposed.
pub struct BotanixLayer<'db, DB> {
    db: &'db mut DB,
    root: &'db mut [u8; 32],
}

impl<'db, DB> BotanixLayer<'db, DB>
where
    DB: HashDB<CommitHasher, DBValue>,
{
    pub fn new(db: &'db mut DB, root: &'db mut [u8; 32]) -> Self {
        BotanixLayer { db, root }
    }
    pub fn root(&mut self) -> CommitmentStateRoot {
        let mut trie: TrieLayer<'_> = AliasFatDBMut::from_existing(self.db, self.root).into();
        trie.root()
    }
    pub fn get_checked<F, E, D>(&mut self, f: F) -> Result<Checked<E>, BotanixLayerError<D>>
    where
        E: EntryT,
        F: FnOnce(&mut DB) -> Result<Option<E>, DatabaseError<D>>,
    {
        // Retrieve the data from the DB via the closure.
        let entry = f(&mut self.db)?.ok_or(BotanixLayerError::NotExists)?;

        // Validate entry against the Trie state.
        let trie: TrieLayer<'_> = AliasFatDBMut::from_existing(self.db, self.root).into();
        trie.ensure_existing(&entry)?;

        Ok(Checked(entry))
    }
    pub fn get_checked_optional<F, E, D>(
        &mut self,
        f: F,
    ) -> Result<Option<Checked<E>>, BotanixLayerError<D>>
    where
        E: EntryT,
        F: FnOnce(&mut DB) -> Result<Option<E>, DatabaseError<D>>,
    {
        // Retrieve the data from the DB via the closure.
        let Some(entry) = f(&mut self.db)? else {
            return Ok(None);
        };

        // Validate entry against the Trie state.
        let trie: TrieLayer<'_> = AliasFatDBMut::from_existing(self.db, self.root).into();
        trie.ensure_existing(&entry)?;

        Ok(Some(Checked(entry)))
    }
    pub fn insert_checked<F, E, D>(&mut self, entry: E, f: F) -> Result<(), BotanixLayerError<D>>
    where
        E: EntryT,
        F: FnOnce(&mut DB, Checked<E>) -> Result<(), DatabaseError<D>>,
    {
        // Validate entry against the Trie state.
        {
            let mut trie: TrieLayer<'_> = AliasFatDBMut::from_existing(self.db, self.root).into();
            trie.insert_non_existing(&entry)?;
        }

        // Insert the data into the DB via the closure.
        f(&mut self.db, Checked(entry)).map_err(Into::into)
    }
    pub fn update_checked<F, E, D>(
        &mut self,
        entry: E,
        prev: Checked<E>,
        f: F,
    ) -> Result<(), BotanixLayerError<D>>
    where
        E: EntryT,
        F: FnOnce(&mut DB, Checked<E>) -> Result<(), DatabaseError<D>>,
    {
        // Validate entry against the Trie state.
        {
            let mut trie: TrieLayer<'_> = AliasFatDBMut::from_existing(self.db, self.root).into();
            trie.update_existing(&entry, prev.as_ref())?;
        }

        // Insert the data into the DB via the closure.
        f(&mut self.db, Checked(entry)).map_err(Into::into)
    }
    // TODO: Consider wrapping `E` in `Checked<E>`?
    pub fn remove_checked<F, E, D>(&mut self, entry: E, f: F) -> Result<(), BotanixLayerError<D>>
    where
        E: EntryT,
        F: FnOnce(&mut DB, Checked<E>) -> Result<(), DatabaseError<D>>,
    {
        // Validate entry against the Trie state.
        {
            let mut trie: TrieLayer<'_> = AliasFatDBMut::from_existing(self.db, self.root).into();
            trie.remove_existing(&entry)?;
        }

        // Remove the data from the DB via the closure, returning the removed
        // entry.
        f(&mut self.db, Checked(entry)).map_err(Into::into)
    }
}
