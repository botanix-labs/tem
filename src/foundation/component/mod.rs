use crate::{
    foundation::{
        AtomicError, CommitHasher,
        commitment::{
            CommitSchema, MultisigId,
            sorted::Sorted,
            trie::{CommitmentStateRoot, TrieLayer},
        },
        component::pegout::DataSourceError,
    },
    validation::pegout::{PegoutData, PegoutId, PegoutWithId},
};
use bitcoin::hashes::Hash;

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

/// Higher-level interface for Botanix state operations within the commitment
/// trie.
///
/// Provides validated operations for pegout lifecycle management and Bitcoin
/// block processing. All methods include comprehensive state validation to
/// prevent invalid transitions and maintain trie consistency.
// TODO: Document how this should be constructed.
pub struct BotanixLayer<'db> {
    /* PRIVATE */ trie: TrieLayer<'db>,
}

impl<'db> From<TrieLayer<'db>> for BotanixLayer<'db> {
    fn from(trie: TrieLayer<'db>) -> Self {
        BotanixLayer { trie }
    }
}

impl<'db> BotanixLayer<'db> {
    pub fn root(&mut self) -> CommitmentStateRoot {
        self.trie.root()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError<D> {
    DataSource(DataSourceError<D>),
    Fatal(trie_db::TrieError<[u8; 32], trie_db::CError<CommitSchema>>),
}

impl<D> From<DataSourceError<D>> for BackendError<D> {
    fn from(err: DataSourceError<D>) -> Self {
        BackendError::DataSource(err)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DataLayerError<D>(pub AtomicError<D>);

impl<D> From<AtomicError<D>> for DataLayerError<D> {
    fn from(err: AtomicError<D>) -> Self {
        DataLayerError(err)
    }
}

pub trait AtomicDataLayer {
    type Transaction;
    /// Backend-specific error type for storage operations.
    type BackendError;

    /// Starts a new transaction and returns a mutable database layer.
    ///
    /// Only one transaction can be active at a time. The returned layer
    /// provides access to modify the database state without affecting the
    /// committed state until `commit()` is called.
    fn start_data_tx<'tx>(
        &'tx mut self,
    ) -> Result<&'tx mut Self::Transaction, DataLayerError<Self::BackendError>>;

    /// Commits the current transaction.
    ///
    /// Persists all changes made through the transaction layer. The transaction
    /// must be started before calling commit.
    fn commit(&mut self) -> Result<(), DataLayerError<Self::BackendError>>;

    /// Rolls back the current transaction.
    ///
    /// Discards all changes made through the transaction layer and restores the
    /// storage to its state before the transaction began.
    fn rollback(&mut self) -> Result<(), DataLayerError<Self::BackendError>>;
}
