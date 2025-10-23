use super::{
    AliasFatDBMut, CommitHasher,
    trie::{CommitmentStateRoot, TrieLayer},
};
use hash_db::HashDB;
use trie_db::{DBValue, NodeCodec};

// TODO: This should be named with something else, since it clashes with
// `trie_db`.
#[derive(Debug, Clone)]
pub struct FatDB<DB> {
    db: DB,
    root: [u8; 32],
}

// TODO: Should do a lookup check.
// TODO: Combine this with `TrieLayer`?
impl<DB: HashDB<CommitHasher, DBValue>> FatDB<DB> {
    pub fn new(db: DB) -> Self {
        let root = super::node_codec::NodeCodec::<CommitHasher>::hashed_null_node();
        FatDB { db, root }
    }
    pub fn from_existing(db: DB, root: [u8; 32]) -> Self {
        FatDB { db, root }
    }
    pub fn root(&mut self) -> CommitmentStateRoot {
        let mut trie: TrieLayer = AliasFatDBMut::from_existing(&mut self.db, &mut self.root).into();
        let root = trie.root();

        std::mem::drop(trie);
        debug_assert_eq!(root.as_ref(), &self.root);

        root
    }
    pub fn trie_layer<'db>(&'db mut self) -> TrieLayer<'db> {
        AliasFatDBMut::from_existing(&mut self.db, &mut self.root).into()
    }
    pub fn into_db(self) -> DB {
        self.db
    }
}
