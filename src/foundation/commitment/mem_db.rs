use super::AliasMemoryDB;
use crate::foundation::{
    AtomicCommitLayer, AtomicError,
    commitment::{
        atomic::CommitLayerError,
        fat_db::FatDB,
        trie::{CommitmentStateRoot, TrieLayer},
    },
};

/// In-memory implementation of atomic storage using memory databases.
///
/// Provides atomic storage operations through full state copying for
/// transaction isolation. While not performance-optimal, this approach ensures
/// reliable rollback semantics for memory-only operations. This structure is
/// **primarily used for testing**.
// TODO: This should be in a test module?
pub struct InMemoryCommitments {
    /// Current committed database state.
    db: FatDB<AliasMemoryDB>,
    /// Previous database state (active during transactions).
    prev_db: Option<FatDB<AliasMemoryDB>>,
}

impl InMemoryCommitments {
    /// Constructs a new in-memory database with the default root.
    pub fn new() -> Self {
        let (mem, root) = AliasMemoryDB::default_with_root();
        let db = FatDB::from_existing(mem, root);

        Self { db, prev_db: None }
    }
}

impl AtomicCommitLayer for InMemoryCommitments {
    type BackendError = ();

    fn root(&mut self) -> Result<CommitmentStateRoot, CommitLayerError<Self::BackendError>> {
        Ok(self.db.root())
    }
    fn start_trie_tx(&mut self) -> Result<TrieLayer<'_>, CommitLayerError<Self::BackendError>> {
        if self.prev_db.is_some() {
            return Err(AtomicError::CommitmentLayerAlreadyStarted.into());
        }

        // NOTE: For the purely in-memory database, we do a full copy. This is
        // not ideal, of course, but unfortunately it does not implement a
        // commit/rollback mechanism. But since it's going to be used primarily
        // for testing purposes anyway, we consider that acceptable.
        self.prev_db = Some(self.db.clone());

        // TODO: We should do a read check here already since an invalid
        // trie/root does not return an error immediately.

        let trie = self.db.trie_layer();
        Ok(trie)
    }
    fn commit(&mut self) -> Result<CommitmentStateRoot, CommitLayerError<Self::BackendError>> {
        let prev_db = self
            .prev_db
            .take()
            .ok_or(AtomicError::CommitmentLayerNotStarted)?;

        debug_assert!(self.prev_db.is_none());

        // Just drop the previous state.
        std::mem::drop(prev_db);

        self.root()
    }
    fn rollback(&mut self) -> Result<CommitmentStateRoot, CommitLayerError<Self::BackendError>> {
        let prev_db = self
            .prev_db
            .take()
            .ok_or(AtomicError::CommitmentLayerNotStarted)?;

        // Reset to previous state.
        self.db = prev_db;

        debug_assert!(self.prev_db.is_none());

        self.root()
    }
}
