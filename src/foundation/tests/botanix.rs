use crate::{
    foundation::{
        InMemoryCommitments, MULTISIG,
        commitment::{
            botanix::Error as BotanixError, entry::Entry, sorted::Sorted, storage::AtomicLayer,
            trie::ErrorKind as TrieErrorKind,
        },
    },
    tests::{gen_bitcoin_hash, gen_bitcoin_txid, gen_pegout_with_id},
    validation::pegout::PegoutWithId,
};
use bitcoin::Txid;

#[test]
fn initiate_pegout() {
    let mut db = InMemoryCommitments::new();
    let mut b = db.start_db_tx().unwrap();

    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();
    let pegout_3 = gen_pegout_with_id();

    // OK: Initiated pegouts(1,2) do not exist yet.
    b.initiate_pegout(&MULTISIG, &pegout_1).unwrap();
    b.initiate_pegout(&MULTISIG, &pegout_2).unwrap();

    // ERR: Initiated pegout already exists.
    let err = b.initiate_pegout(&MULTISIG, &pegout_1).unwrap_err();
    assert_eq!(
        err,
        BotanixError::BadTrieOp {
            entry: Entry::Initiated {
                k: (&MULTISIG, &pegout_1.id),
                v: &pegout_1.data
            },
            kind: TrieErrorKind::InsertDoesExist
        }
    );

    // Sanity check
    b.check_initiated_pegout(&MULTISIG, &pegout_1).unwrap();
    b.check_initiated_pegout(&MULTISIG, &pegout_2).unwrap();
    // Pegout(3) not initiated yet.
    b.check_initiated_pegout(&MULTISIG, &pegout_3).unwrap_err();
    //
    b.check_pending_pegout(&pegout_1).unwrap_err();
    b.check_pending_pegout(&pegout_2).unwrap_err();
    b.check_pending_pegout(&pegout_3).unwrap_err();
    //
    b.check_delayed_pegout(&pegout_1).unwrap_err();
    b.check_delayed_pegout(&pegout_2).unwrap_err();
    b.check_delayed_pegout(&pegout_3).unwrap_err();
}

#[test]
fn register_bitcoin_tx_trie_validation_properties() {
    let mut db = InMemoryCommitments::new();
    let mut b = db.start_db_tx().unwrap();

    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();
    let pegout_3 = gen_pegout_with_id();

    let block_hash = gen_bitcoin_hash();
    let txid_1 = gen_bitcoin_txid();
    let txid_2 = gen_bitcoin_txid();
    let txid_3 = gen_bitcoin_txid();

    // Prepare pegouts and header.
    {
        b.initiate_pegout(&MULTISIG, &pegout_1).unwrap();
        b.initiate_pegout(&MULTISIG, &pegout_2).unwrap();
        b.initiate_pegout(&MULTISIG, &pegout_3).unwrap();

        b.bitcoin_header(&block_hash, &vec![].into()).unwrap();
    }

    // OK: Registering valid Txid(1).
    {
        let tracked_txids: Sorted<Txid> = vec![].into();
        let updated_txids: Sorted<Txid> = vec![txid_1].into();
        let pegouts: Sorted<PegoutWithId> = vec![pegout_1.clone(), pegout_2.clone()].into();

        b.register_bitcoin_tx(
            &block_hash,
            &MULTISIG,
            &tracked_txids,
            &updated_txids,
            &txid_1,
            &pegouts,
        )
        .unwrap();

        // Verify pegout states.
        b.check_pending_pegout(&pegout_1).unwrap();
        b.check_pending_pegout(&pegout_2).unwrap();
        b.check_initiated_pegout(&MULTISIG, &pegout_3).unwrap();
    }

    // Commit.
    std::mem::drop(b);
    db.commit().unwrap();
    let mut b = db.start_db_tx().unwrap();

    // ERR: Attempting to register the same transaction again;
    // Txid(1) reuse.
    {
        let tracked_txids: Sorted<Txid> = vec![].into();
        let updated_txids: Sorted<Txid> = vec![txid_1].into();
        let pegouts: Sorted<PegoutWithId> = vec![pegout_1.clone(), pegout_2.clone()].into();

        let err = b
            .register_bitcoin_tx(
                &block_hash,
                &MULTISIG,
                &tracked_txids,
                &updated_txids,
                &txid_1,
                &pegouts,
            )
            .unwrap_err();

        assert_eq!(
            err,
            BotanixError::BadTrieOp {
                entry: Entry::BlockTxids {
                    k: &block_hash,
                    v: &tracked_txids
                },
                // Passed-on tracked Txids do not match committed value!
                kind: TrieErrorKind::UpdateBadPrevValue
            }
        );
    }

    // Rollback.
    std::mem::drop(b);
    db.rollback().unwrap();
    let mut b = db.start_db_tx().unwrap();

    // ERR: Attempting to reuse a registered pegout again;
    // pegout(2) is not in an initiated state.
    {
        let tracked_txids: Sorted<Txid> = vec![txid_1].into();
        let updated_txids: Sorted<Txid> = vec![txid_1, txid_2].into();
        let pegouts: Sorted<PegoutWithId> = vec![pegout_2.clone(), pegout_3.clone()].into();

        let err = b
            .register_bitcoin_tx(
                &block_hash,
                &MULTISIG,
                &tracked_txids,
                &updated_txids,
                &txid_2, // NOTE: New Txid(2)
                &pegouts,
            )
            .unwrap_err();

        assert_eq!(
            err,
            BotanixError::BadTrieOp {
                entry: Entry::Initiated {
                    k: (&MULTISIG, &pegout_2.id),
                    v: &pegout_2.data,
                },
                // Pegout(2) not in an initiated state!
                kind: TrieErrorKind::RemoveNotExist,
            }
        );
    }

    // Rollback.
    std::mem::drop(b);
    db.rollback().unwrap();
    let mut b = db.start_db_tx().unwrap();

    // ERR: Attempting to register a new transaction with a bad tracked Txid
    // preimage.
    {
        let tracked_txids: Sorted<Txid> = vec![txid_3].into(); // BAD
        let updated_txids: Sorted<Txid> = vec![txid_3, txid_2].into();
        let pegouts: Sorted<PegoutWithId> = vec![pegout_3.clone()].into();

        let err = b
            .register_bitcoin_tx(
                &block_hash,
                &MULTISIG,
                &tracked_txids,
                &updated_txids,
                &txid_2, // NOTE: New Txid(2)
                &pegouts,
            )
            .unwrap_err();

        assert_eq!(
            err,
            BotanixError::BadTrieOp {
                entry: Entry::BlockTxids {
                    k: &block_hash,
                    v: &tracked_txids
                },
                // Passed-on tracked Txids do not match committed value!
                kind: TrieErrorKind::UpdateBadPrevValue,
            }
        );
    }

    // Rollback.
    std::mem::drop(b);
    db.rollback().unwrap();
    let mut b = db.start_db_tx().unwrap();

    // OK: Registering valid Txid(2), without pegout reuse.
    {
        let tracked_txids: Sorted<Txid> = vec![txid_1].into();
        let updated_txids: Sorted<Txid> = vec![txid_1, txid_2].into();
        let pegouts: Sorted<PegoutWithId> = vec![pegout_3.clone()].into();

        b.register_bitcoin_tx(
            &block_hash,
            &MULTISIG,
            &tracked_txids,
            &updated_txids,
            &txid_2, // NOTE: New Txid(2)
            &pegouts,
        )
        .unwrap();
    }

    // Pegouts are in a pending state.
    b.check_initiated_pegout(&MULTISIG, &pegout_1).unwrap_err();
    b.check_initiated_pegout(&MULTISIG, &pegout_2).unwrap_err();
    b.check_initiated_pegout(&MULTISIG, &pegout_3).unwrap_err();
    //
    b.check_pending_pegout(&pegout_1).unwrap();
    b.check_pending_pegout(&pegout_2).unwrap();
    b.check_pending_pegout(&pegout_3).unwrap();
    //
    b.check_delayed_pegout(&pegout_1).unwrap_err();
    b.check_delayed_pegout(&pegout_2).unwrap_err();
    b.check_delayed_pegout(&pegout_3).unwrap_err();
}

#[test]
fn bitcoin_header_finalize() {
    let mut db = InMemoryCommitments::new();
    let mut b = db.start_db_tx().unwrap();

    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();
    let pegout_3 = gen_pegout_with_id();

    let block_hash = gen_bitcoin_hash();
    let txid_1 = gen_bitcoin_txid();
    let txid_2 = gen_bitcoin_txid();

    // ERR: Block hash does not exist.
    {
        let tracked_txids: Sorted<Txid> = vec![].into();
        let pegouts: Vec<Sorted<PegoutWithId>> = vec![].into();

        let err = b
            .bitcoin_header_finalize(&block_hash, &tracked_txids, &pegouts)
            .unwrap_err();

        assert_eq!(
            err,
            BotanixError::BadTrieOp {
                entry: Entry::BlockTxids {
                    k: &block_hash,
                    v: &tracked_txids
                },
                // Block hash not committed yet!
                kind: TrieErrorKind::RemoveNotExist,
            }
        );
    }

    // Rollback.
    std::mem::drop(b);
    db.rollback().unwrap();
    let mut b = db.start_db_tx().unwrap();

    // Prepare pegouts and header.
    {
        b.initiate_pegout(&MULTISIG, &pegout_1).unwrap();
        b.initiate_pegout(&MULTISIG, &pegout_2).unwrap();
        b.initiate_pegout(&MULTISIG, &pegout_3).unwrap();

        let tracked_txids: Sorted<Txid> = vec![].into();
        b.bitcoin_header(&block_hash, &tracked_txids).unwrap();
    }

    // Commit.
    std::mem::drop(b);
    db.commit().unwrap();
    let mut b = db.start_db_tx().unwrap();

    // ERR: Txid(1) does not exist.
    {
        let tracked_txids: Sorted<Txid> = vec![txid_1].into(); // Incorrect!
        let pegouts: Vec<Sorted<PegoutWithId>> = vec![].into();

        let err = b
            .bitcoin_header_finalize(&block_hash, &tracked_txids, &pegouts)
            .unwrap_err();

        assert_eq!(
            err,
            BotanixError::BadTrieOp {
                entry: Entry::BlockTxids {
                    k: &block_hash,
                    v: &tracked_txids,
                },
                // Passed-on tracked Txids do not match committed value!
                kind: TrieErrorKind::RemoveBadValue,
            }
        );
    }

    // Rollback.
    std::mem::drop(b);
    db.rollback().unwrap();
    let mut b = db.start_db_tx().unwrap();

    // OK: Registering valid Txid(1).
    {
        let tracked_txids: Sorted<Txid> = vec![].into();
        let updated_txids: Sorted<Txid> = vec![txid_1].into();
        let pegouts: Sorted<PegoutWithId> = vec![pegout_1.clone(), pegout_2.clone()].into();

        b.register_bitcoin_tx(
            &block_hash,
            &MULTISIG,
            &tracked_txids,
            &updated_txids,
            &txid_1,
            &pegouts,
        )
        .unwrap();

        // Verify pegout states.
        b.check_pending_pegout(&pegout_1).unwrap();
        b.check_pending_pegout(&pegout_2).unwrap();
        b.check_initiated_pegout(&MULTISIG, &pegout_3).unwrap();
    }

    // OK: Registering valid Txid(2).
    {
        let tracked_txids: Sorted<Txid> = vec![txid_1].into();
        let updated_txids: Sorted<Txid> = vec![txid_1, txid_2].into();
        let pegouts: Sorted<PegoutWithId> = vec![pegout_3.clone()].into();

        b.register_bitcoin_tx(
            &block_hash,
            &MULTISIG,
            &tracked_txids,
            &updated_txids,
            &txid_2, // NOTE: New Txid(2)
            &pegouts,
        )
        .unwrap();

        // Verify pegout states.
        b.check_pending_pegout(&pegout_1).unwrap();
        b.check_pending_pegout(&pegout_2).unwrap();
        b.check_pending_pegout(&pegout_3).unwrap();
    }

    // Commit.
    std::mem::drop(b);
    db.commit().unwrap();
    let mut b = db.start_db_tx().unwrap();

    // ERR: Bad tracked Txid preimage.
    {
        let tracked_txids: Sorted<Txid> = vec![txid_1].into(); // Missing Txid(2)
        let pegouts: Vec<Sorted<PegoutWithId>> = tracked_txids
            .iter()
            .map(|t| {
                if t == &txid_1 {
                    vec![pegout_1.clone(), pegout_2.clone()].into()
                } else if t == &txid_2 {
                    vec![pegout_3.clone()].into()
                } else {
                    unreachable!()
                }
            })
            .collect();

        let err = b
            .bitcoin_header_finalize(&block_hash, &tracked_txids, &pegouts)
            .unwrap_err();

        assert_eq!(
            err,
            BotanixError::BadTrieOp {
                entry: Entry::BlockTxids {
                    k: &block_hash,
                    v: &tracked_txids,
                },
                // Passed-on tracked Txids do not match committed value!
                kind: TrieErrorKind::RemoveBadValue,
            }
        );
    }

    // Rollback.
    std::mem::drop(b);
    db.rollback().unwrap();
    let mut b = db.start_db_tx().unwrap();

    // ERR: Bad tracked pegout list for Txid(1)
    {
        let tracked_txids: Sorted<Txid> = vec![txid_1, txid_2].into();
        let pegouts: Vec<Sorted<PegoutWithId>> = tracked_txids
            .iter()
            .map(|t| {
                if t == &txid_1 {
                    vec![pegout_1.clone()].into() // Missing pegout(2)
                } else if t == &txid_2 {
                    vec![pegout_3.clone()].into()
                } else {
                    unreachable!()
                }
            })
            .collect();

        let err = b
            .bitcoin_header_finalize(&block_hash, &tracked_txids, &pegouts)
            .unwrap_err();

        let pos = tracked_txids.iter().position(|t| t == &txid_1).unwrap();
        assert_eq!(
            err,
            BotanixError::BadTrieOp {
                entry: Entry::TxidPegouts {
                    k: &txid_1,
                    v: &pegouts[pos],
                },
                // Passed-on pegouts do not match committed value!
                kind: TrieErrorKind::RemoveBadValue,
            }
        );
    }

    // Rollback.
    std::mem::drop(b);
    db.rollback().unwrap();
    let mut b = db.start_db_tx().unwrap();

    // OK: Finalizing Bitcoin block by removing block header and its
    // associated Txids and pegouts.
    {
        let tracked_txids: Sorted<Txid> = vec![txid_1, txid_2].into();
        let pegouts: Vec<Sorted<PegoutWithId>> = tracked_txids
            .iter()
            .map(|t| {
                if t == &txid_1 {
                    vec![pegout_1.clone(), pegout_2.clone()].into()
                } else if t == &txid_2 {
                    vec![pegout_3.clone()].into()
                } else {
                    unreachable!()
                }
            })
            .collect();

        b.bitcoin_header_finalize(&block_hash, &tracked_txids, &pegouts)
            .unwrap();
    }

    // Pegouts are gone completely and considered finalized.
    b.check_initiated_pegout(&MULTISIG, &pegout_1).unwrap_err();
    b.check_initiated_pegout(&MULTISIG, &pegout_2).unwrap_err();
    b.check_initiated_pegout(&MULTISIG, &pegout_3).unwrap_err();
    //
    b.check_pending_pegout(&pegout_1).unwrap_err();
    b.check_pending_pegout(&pegout_2).unwrap_err();
    b.check_pending_pegout(&pegout_3).unwrap_err();
    //
    b.check_delayed_pegout(&pegout_1).unwrap_err();
    b.check_delayed_pegout(&pegout_2).unwrap_err();
    b.check_delayed_pegout(&pegout_3).unwrap_err();

    // TODO: Check other removed values.
}

// NOTE: Orphaning blocks wraps over the same logic as finalizing blocks, so
// pretty much all scenarios are tested in said unit test appropriately. The
// only thing we need to check is that pegouts in orphaned blocks are
// returned back to the *delayed* list.
#[test]
fn bitcoin_header_orphan() {
    let mut db = InMemoryCommitments::new();
    let mut b = db.start_db_tx().unwrap();

    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();
    let pegout_3 = gen_pegout_with_id();

    let block_hash = gen_bitcoin_hash();
    let txid_1 = gen_bitcoin_txid();

    // Prepare pegouts and header.
    {
        b.initiate_pegout(&MULTISIG, &pegout_1).unwrap();
        b.initiate_pegout(&MULTISIG, &pegout_2).unwrap();
        b.initiate_pegout(&MULTISIG, &pegout_3).unwrap();

        let tracked_txids: Sorted<Txid> = vec![].into();
        b.bitcoin_header(&block_hash, &tracked_txids).unwrap();
    }

    // OK: Registering valid Txid(1).
    {
        let tracked_txids: Sorted<Txid> = vec![].into();
        let updated_txids: Sorted<Txid> = vec![txid_1].into();
        let pegouts: Sorted<PegoutWithId> = vec![pegout_1.clone(), pegout_2.clone()].into();

        b.register_bitcoin_tx(
            &block_hash,
            &MULTISIG,
            &tracked_txids,
            &updated_txids,
            &txid_1,
            &pegouts,
        )
        .unwrap();

        // Verify pegout states.
        b.check_pending_pegout(&pegout_1).unwrap();
        b.check_pending_pegout(&pegout_2).unwrap();
        b.check_initiated_pegout(&MULTISIG, &pegout_3).unwrap();
    }

    // OK: Orphaning Bitcoin block by removing block header and its
    // associated Txid(1) - pegouts are moved to the delayed set.
    {
        let tracked_txids: Sorted<Txid> = vec![txid_1].into();
        let pegouts: Vec<Sorted<PegoutWithId>> =
            vec![vec![pegout_1.clone(), pegout_2.clone()].into()].into();

        b.bitcoin_header_orphan(&block_hash, &tracked_txids, &pegouts)
            .unwrap();
    }

    b.check_initiated_pegout(&MULTISIG, &pegout_1).unwrap_err();
    b.check_initiated_pegout(&MULTISIG, &pegout_2).unwrap_err();
    // Pegout(3) is still in an initiated state.
    b.check_initiated_pegout(&MULTISIG, &pegout_3).unwrap();
    //
    b.check_pending_pegout(&pegout_1).unwrap_err();
    b.check_pending_pegout(&pegout_2).unwrap_err();
    b.check_pending_pegout(&pegout_3).unwrap_err();
    //
    // Pegouts(1,2) are in the delayed state.
    b.check_delayed_pegout(&pegout_1).unwrap();
    b.check_delayed_pegout(&pegout_2).unwrap();
    b.check_delayed_pegout(&pegout_3).unwrap_err();
}
