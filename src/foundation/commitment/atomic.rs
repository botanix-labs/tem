//! # Storage Module
//!
//! Provides atomic storage operations for commitment state management with
//! transaction-like semantics. Enables safe state modifications through
//! start/commit/rollback operations on in-memory trie databases.
use hash_db::HashDB;
use trie_db::DBValue;

use crate::foundation::{
    CommitHasher, commitment::trie::CommitmentStateRoot, component::BotanixLayer,
};

/// Errors that can occur during atomic storage operations.
///
/// Represents various failure modes when working with atomic storage layers,
/// including backend-specific errors.
#[derive(Debug, PartialEq, Eq)]
pub enum AtomicErrorVariant<E> {
    /// Attempted to commit or rollback without starting a transaction.
    CommitmentLayerNotStarted,
    /// Attempted to start a transaction when one is already active.
    CommitmentLayerAlreadyStarted,
    /// Backend-specific error occurred during storage operations.
    Backend(E),
}

/// Convenience error wrapper to make type conversion easier to implement.
#[derive(Debug, PartialEq, Eq)]
pub struct AtomicError<A>(pub AtomicErrorVariant<A>);

impl<A> From<AtomicErrorVariant<A>> for AtomicError<A> {
    fn from(err: AtomicErrorVariant<A>) -> Self {
        AtomicError(err)
    }
}

/// Trait defining atomic storage operations with transaction semantics.
///
/// Provides a consistent interface for storage backends that support atomic
/// modifications through start/commit/rollback operations. Implementations must
/// ensure that uncommitted changes are isolated from the main state.
pub trait AtomicLayer<DB>
where
    DB: HashDB<CommitHasher, DBValue>,
{
    /// Backend-specific error type for storage operations.
    type BackendError;

    /// Starts a new transaction and returns a mutable database layer.
    ///
    /// Only one transaction can be active at a time. The returned layer
    /// provides access to modify the database state without affecting the
    /// committed state until `commit()` is called.
    fn start_tx<'db>(
        &'db mut self,
    ) -> Result<BotanixLayer<'db, DB>, AtomicError<Self::BackendError>>;

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
