use crate::{
    foundation::commitment::{
        AliasMemoryDB, entry::Entry, trie::Error as TrieError, trie::ErrorKind as TrieErrorKind,
        trie::TrieLayer,
    },
    tests::{gen_pegout_data, gen_pegout_with_id},
};

#[test]
fn insert_non_existing() {
    let (mut db, mut root) = AliasMemoryDB::default_with_root();
    let mut t = TrieLayer::from((&mut db, &mut root));

    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();

    let entry_1 = Entry::Pending {
        k: &pegout_1.id,
        v: &pegout_1.data,
    };
    let entry_2 = Entry::Pending {
        k: &pegout_2.id,
        v: &pegout_2.data,
    };
    let entry_1_updated = Entry::Pending {
        k: &pegout_1.id,
        // This is not something that can actually happen in practice;
        // simply for demonstrated purposes.
        v: &gen_pegout_data(),
    };

    // Sanity checks.
    t.ensure_non_existing(entry_1).unwrap();
    t.ensure_non_existing(entry_2).unwrap();
    t.ensure_non_existing(entry_1_updated).unwrap();

    // ***

    // OK: Insert the entries that do not exist yet.
    t.insert_non_existing(entry_1).unwrap();
    t.insert_non_existing(entry_2).unwrap();
    //
    t.ensure_existing(entry_1).unwrap();
    t.ensure_existing(entry_2).unwrap();

    // ERR: Entry(1) already exists.
    let err = t.insert_non_existing(entry_1).unwrap_err();
    assert_eq!(
        err,
        TrieError::Mod {
            entry: entry_1,
            kind: TrieErrorKind::InsertDoesExist
        }
    );

    // ERR: Entry(1_updated) already exists (key checked).
    let err = t.insert_non_existing(entry_1_updated).unwrap_err();
    assert_eq!(
        err,
        TrieError::Mod {
            entry: entry_1_updated,
            kind: TrieErrorKind::InsertDoesExist
        }
    );

    // Sanity checks.
    t.ensure_existing(entry_1).unwrap();
    t.ensure_existing(entry_2).unwrap();
    t.ensure_non_existing(entry_1_updated).unwrap();
}

#[test]
fn update_existing() {
    let (mut db, mut root) = AliasMemoryDB::default_with_root();
    let mut t = TrieLayer::from((&mut db, &mut root));

    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();

    let entry_1 = Entry::Pending {
        k: &pegout_1.id,
        v: &pegout_1.data,
    };
    let entry_2 = Entry::Pending {
        k: &pegout_2.id,
        v: &pegout_2.data,
    };
    let entry_1_updated = Entry::Pending {
        k: &pegout_1.id,
        v: &gen_pegout_data(),
    };

    // ***

    // ERR: Key of updated entry (1_updated) does not match the key of the
    // previous entry(2).
    let err = t.update_existing(entry_1_updated, entry_2).unwrap_err();
    assert_eq!(
        err,
        TrieError::Mod {
            entry: entry_2,
            kind: TrieErrorKind::UpdateBadPrevKey
        }
    );

    // ERR: Previous entry(1) does not actually exist.
    let err = t.update_existing(entry_1_updated, entry_1).unwrap_err();
    assert_eq!(
        err,
        TrieError::Mod {
            entry: entry_1,
            kind: TrieErrorKind::UpdateNotExist
        }
    );

    // Insert the entries.
    t.insert_non_existing(entry_1).unwrap();
    t.insert_non_existing(entry_2).unwrap();
    //
    t.ensure_existing(entry_1).unwrap();
    t.ensure_existing(entry_2).unwrap();

    // ERR: Value of previous entry(1_updated) does not match the committed
    // value.
    let err = t
        .update_existing(entry_1_updated, entry_1_updated)
        .unwrap_err();
    assert_eq!(
        err,
        TrieError::Mod {
            entry: entry_1_updated,
            kind: TrieErrorKind::UpdateBadPrevValue
        }
    );

    // Ok: Previous entry(1) matches the committed value, and is updated
    // with the new entry (1_updated).
    t.update_existing(entry_1_updated, entry_1).unwrap();

    // Sanity checks.
    t.ensure_non_existing(entry_1).unwrap();
    t.ensure_existing(entry_2).unwrap();
    t.ensure_existing(entry_1_updated).unwrap();
}

#[test]
fn remove_existing() {
    let (mut db, mut root) = AliasMemoryDB::default_with_root();
    let mut t = TrieLayer::from((&mut db, &mut root));

    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();

    let entry_1 = Entry::Pending {
        k: &pegout_1.id,
        v: &pegout_1.data,
    };
    let entry_2 = Entry::Pending {
        k: &pegout_2.id,
        v: &pegout_2.data,
    };
    let entry_1_updated = Entry::Pending {
        k: &pegout_1.id,
        v: &gen_pegout_data(),
    };

    // ***

    // ERR: Entry(1) does not exist (key checked).
    let err = t.remove_existing(entry_1).unwrap_err();
    assert_eq!(
        err,
        TrieError::Mod {
            entry: entry_1,
            kind: TrieErrorKind::RemoveNotExist
        }
    );

    // Insert the entries.
    t.insert_non_existing(entry_1).unwrap();
    t.insert_non_existing(entry_2).unwrap();
    //
    t.ensure_existing(entry_1).unwrap();
    t.ensure_existing(entry_2).unwrap();

    // ERR: Value of entry(1_updated) does not match the committed value.
    let err = t.remove_existing(entry_1_updated).unwrap_err();
    assert_eq!(
        err,
        TrieError::Mod {
            entry: entry_1_updated,
            kind: TrieErrorKind::RemoveBadValue
        }
    );

    // OK: Entry(1) matches the commited entry.
    t.remove_existing(entry_1).unwrap();

    // Sanity checks.
    t.ensure_non_existing(entry_1).unwrap();
    t.ensure_existing(entry_2).unwrap();
    t.ensure_non_existing(entry_1_updated).unwrap();
}

#[test]
fn ensure_existing() {
    let (mut db, mut root) = AliasMemoryDB::default_with_root();
    let mut t = TrieLayer::from((&mut db, &mut root));

    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();

    let entry_1 = Entry::Pending {
        k: &pegout_1.id,
        v: &pegout_1.data,
    };
    let entry_2 = Entry::Pending {
        k: &pegout_2.id,
        v: &pegout_2.data,
    };
    let entry_1_updated = Entry::Pending {
        k: &pegout_1.id,
        v: &gen_pegout_data(),
    };

    // ***

    // ERR: Entry(1) does not exist.
    let err = t.ensure_existing(entry_1).unwrap_err();
    assert_eq!(
        err,
        TrieError::Mod {
            entry: entry_1,
            kind: TrieErrorKind::EnsureExistsNotExist
        }
    );

    // Insert the entries.
    t.insert_non_existing(entry_1).unwrap();
    t.insert_non_existing(entry_2).unwrap();
    //
    t.ensure_existing(entry_1).unwrap();
    t.ensure_existing(entry_2).unwrap();

    // ERR: Value of entry(1) does not match the committed value.
    let err = t.ensure_existing(entry_1_updated).unwrap_err();
    assert_eq!(
        err,
        TrieError::Mod {
            entry: entry_1_updated,
            kind: TrieErrorKind::EnsureExistsBadValue
        }
    );

    // OK: Entry(1) matches the committed entry.
    t.ensure_existing(entry_1).unwrap();

    // Sanity checks.
    t.ensure_existing(entry_2).unwrap();
    t.ensure_non_existing(entry_1_updated).unwrap();
}

#[test]
fn ensure_non_existing() {
    let (mut db, mut root) = AliasMemoryDB::default_with_root();
    let mut t = TrieLayer::from((&mut db, &mut root));

    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();

    let entry_1 = Entry::Pending {
        k: &pegout_1.id,
        v: &pegout_1.data,
    };
    let entry_2 = Entry::Pending {
        k: &pegout_2.id,
        v: &pegout_2.data,
    };
    let entry_1_updated = Entry::Pending {
        k: &pegout_1.id,
        v: &gen_pegout_data(),
    };

    // ***

    // OK: Entry(1) does not exist (key checked).
    t.ensure_non_existing(entry_1).unwrap();

    // Insert the entries.
    t.insert_non_existing(entry_1).unwrap();
    t.insert_non_existing(entry_2).unwrap();
    //
    t.ensure_existing(entry_1).unwrap();
    t.ensure_existing(entry_2).unwrap();

    // ERR: Entry(1) does exist.
    let err = t.ensure_non_existing(entry_1).unwrap_err();
    assert_eq!(
        err,
        TrieError::Mod {
            entry: entry_1,
            kind: TrieErrorKind::EnsureNotExistsDoesExist
        }
    );

    // OK: Value of entry(1_updated) does not match the committed value.
    t.ensure_non_existing(entry_1_updated).unwrap();

    // Sanity checks.
    t.ensure_existing(entry_1).unwrap();
    t.ensure_existing(entry_2).unwrap();
}
