//! # Storage Module
//!
//! Provides atomic storage operations for commitment state management with
//! transaction-like semantics. Enables safe state modifications through
//! start/commit/rollback operations on in-memory trie databases.
use super::{AliasFatDBMut, AliasMemoryDB, AliasTrieHash, botanix::BotanixLayer, trie::TrieLayer};
use crate::foundation::commitment::CommitmentStateRoot;
use std::fmt::Debug;

/// Error type for operations that cannot fail in the in-memory database.
///
/// The in-memory database implementation has no backend that can produce
/// errors, so this type serves as a placeholder for the generic error handling.
#[derive(Debug, PartialEq, Eq)]
pub struct NeverError;

/// Errors that can occur during atomic storage operations.
///
/// Represents various failure modes when working with atomic storage layers,
/// including backend-specific errors.
#[derive(Debug, PartialEq, Eq)]
pub enum AtomicError<E> {
    /// Attempted to commit or rollback without starting a transaction.
    CommitmentLayerNotStarted,
    /// Attempted to start a transaction when one is already active.
    CommitmentLayerAlreadyStarted,
    /// Backend-specific error occurred during storage operations.
    Backend(E),
}

/// Trait defining atomic storage operations with transaction semantics.
///
/// Provides a consistent interface for storage backends that support atomic
/// modifications through start/commit/rollback operations. Implementations must
/// ensure that uncommitted changes are isolated from the main state.
pub trait AtomicLayer {
    /// Backend-specific error type for storage operations.
    type BackendError: Debug;

    /// Returns the current, non-pending state root commitment.
    fn root(&self) -> Result<CommitmentStateRoot, AtomicError<Self::BackendError>>;

    /// Starts a new transaction and returns a mutable database layer.
    ///
    /// Only one transaction can be active at a time. The returned layer
    /// provides access to modify the database state without affecting the
    /// committed state until `commit()` is called.
    fn start_db_tx(&mut self) -> Result<BotanixLayer<'_>, AtomicError<Self::BackendError>>;

    /// Commits the current transaction and returns the new state root.
    ///
    /// Persists all changes made through the transaction layer and updates the
    /// storage's state root. The transaction must be started before calling
    /// commit.
    fn commit(&mut self) -> Result<CommitmentStateRoot, AtomicError<Self::BackendError>>;

    /// Rolls back the current transaction and returns the previous state root.
    ///
    /// Discards all changes made through the transaction layer and restores the
    /// storage to its state before the transaction began.
    fn rollback(&mut self) -> Result<CommitmentStateRoot, AtomicError<Self::BackendError>>;
}

/// In-memory implementation of atomic storage using memory databases.
///
/// Provides atomic storage operations through full state copying for
/// transaction isolation. While not performance-optimal, this approach ensures
/// reliable rollback semantics for memory-only operations. This structure is
/// **primarily used for testing**.
pub struct InMemoryCommitments {
    /// Current committed database state.
    db: AliasMemoryDB,
    /// Current committed state root.
    root: AliasTrieHash,
    /// Previous database state (active during transactions).
    prev_db: Option<AliasMemoryDB>,
    /// Previous state root (active during transactions).
    prev_root: Option<AliasTrieHash>,
}

impl InMemoryCommitments {
    /// Constructs a new in-memory database with the default root.
    pub fn new() -> Self {
        let (db, root) = AliasMemoryDB::default_with_root();
        Self {
            db,
            root,
            prev_db: None,
            prev_root: None,
        }
    }
}

impl AtomicLayer for InMemoryCommitments {
    type BackendError = NeverError;

    fn root(&self) -> Result<CommitmentStateRoot, AtomicError<Self::BackendError>> {
        Ok(CommitmentStateRoot(self.root))
    }
    fn start_db_tx(&mut self) -> Result<BotanixLayer<'_>, AtomicError<Self::BackendError>> {
        if self.prev_db.is_some() {
            debug_assert!(self.prev_root.is_some());
            return Err(AtomicError::CommitmentLayerAlreadyStarted);
        }

        // NOTE: For the purely in-memory database, we do a full copy. This is
        // not ideal, of course, but unfortunately it does not implement a
        // commit/rollback mechanism. But since it's going to be used primarily
        // for testing purposes anyway, we consider that acceptable.
        self.prev_db = Some(self.db.clone());
        self.prev_root = Some(self.root);

        let trie = AliasFatDBMut::from_existing(&mut self.db, &mut self.root);

        // TODO: We should do a read check here already since an invalid
        // trie/root does not return an error immediately.

        Ok(BotanixLayer::from(TrieLayer::from(trie)))
    }
    fn commit(&mut self) -> Result<CommitmentStateRoot, AtomicError<Self::BackendError>> {
        let (prev_db, prev_root) = self
            .prev_db
            .take()
            .zip(self.prev_root.take())
            .ok_or(AtomicError::CommitmentLayerNotStarted)?;

        debug_assert!(self.prev_db.is_none());
        debug_assert!(self.prev_root.is_none());

        // Just drop the previous state.
        std::mem::drop((prev_db, prev_root));

        Ok(CommitmentStateRoot(self.root))
    }
    fn rollback(&mut self) -> Result<CommitmentStateRoot, AtomicError<Self::BackendError>> {
        let (prev_db, prev_root) = self
            .prev_db
            .take()
            .zip(self.prev_root.take())
            .ok_or(AtomicError::CommitmentLayerNotStarted)?;

        // Reset to previous state.
        self.db = prev_db;
        self.root = prev_root;

        debug_assert!(self.prev_db.is_none());
        debug_assert!(self.prev_root.is_none());

        Ok(CommitmentStateRoot(self.root))
    }
}
