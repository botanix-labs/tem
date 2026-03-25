use super::*;
use crate::test_utils::gen_bitcoin_header;

#[test]
fn finalize_header_valid() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let header = gen_bitcoin_header();

    atomic
        .apply(|mut db| db.insert_bitcoin_header(header, 200))
        .unwrap();

    atomic
        .apply(|mut db| db.insert_bitcoin_tx(header.block_hash(), prop.txid))
        .unwrap();

    atomic
        .apply(|mut db| db.finalize_bitcoin_header(header.block_hash()))
        .unwrap();

    let stored = atomic.db.get_header(&header.block_hash()).unwrap();
    assert!(stored.is_none());

    let stored = atomic.db.get_proposal(&prop.txid).unwrap();
    assert!(stored.is_none());
    assert!(
        atomic
            .db
            .data
            .trash_finalized_proposals
            .contains_key(&prop.txid)
    );

    for utxo in &prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap();
        assert!(stored.is_none());
        assert!(atomic.db.data.trash_finalized_utxos.contains_key(utxo));
    }
}

#[test]
fn finalize_header_with_competing_txid() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let first_prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(first_prop.clone(), None))
        .unwrap();

    let mut second_prop = atomic.gen_new_proposal(ALICE, botanix_height);
    second_prop.utxos = first_prop.utxos.clone();

    atomic
        .apply(|mut db| db.insert_pegout_proposal(second_prop.clone(), None))
        .unwrap();

    let header1 = gen_bitcoin_header();
    let mut header2 = gen_bitcoin_header();
    header2.prev_blockhash = header1.block_hash();

    atomic
        .apply(|mut db| db.insert_bitcoin_header(header1, 200))
        .unwrap();

    atomic
        .apply(|mut db| db.insert_bitcoin_header(header2, 201))
        .unwrap();

    atomic
        .apply(|mut db| db.insert_bitcoin_tx(header1.block_hash(), first_prop.txid))
        .unwrap();

    atomic
        .apply(|mut db| db.insert_bitcoin_tx(header2.block_hash(), second_prop.txid))
        .unwrap();

    assert_eq!(first_prop.utxos, second_prop.utxos);

    for utxo in &first_prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(
            stored.v.txids,
            vec![first_prop.txid, second_prop.txid].into()
        );
    }

    for utxo in &second_prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(
            stored.v.txids,
            vec![first_prop.txid, second_prop.txid].into()
        );
    }

    // # Finalize block-1

    atomic
        .apply(|mut db| db.finalize_bitcoin_header(header1.block_hash()))
        .unwrap();

    // ## State: First proposal

    // Proposal itself has been removed and categorized as _finalized_.
    let stored = atomic.db.get_proposal(&first_prop.txid).unwrap();
    assert!(stored.is_none());

    assert!(
        atomic
            .db
            .data
            .trash_finalized_proposals
            .contains_key(&first_prop.txid)
    );

    // All removed Utxos from the first proposal are categorized as _finalized_.
    for utxo in &first_prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap();
        assert!(stored.is_none());
        assert!(atomic.db.data.trash_finalized_utxos.contains_key(utxo));
    }

    // All pegouts are effectively gone.
    for pegout in &first_prop.pegouts {
        let stored = atomic.db.get_unassigned(&pegout.id).unwrap();
        assert!(stored.is_none());
    }

    // ## State: Second proposal

    // Proposal itself has been removed and categorized as _orphaned_.
    let stored = atomic.db.get_proposal(&second_prop.txid).unwrap();
    assert!(stored.is_none());

    assert!(
        atomic
            .db
            .data
            .trash_orphaned_proposals
            .contains_key(&second_prop.txid)
    );

    // All removed Utxos from the second proposal that are NOT reused in the
    // first proposal are categorized as _orphaned_.
    for utxo in &second_prop.utxos {
        if first_prop.utxos.contains(&utxo) {
            assert!(atomic.db.data.trash_finalized_utxos.contains_key(utxo));
        } else {
            assert!(atomic.db.data.trash_orphaned_utxos.contains_key(utxo));
        }
    }

    // All pegouts from the second proposal have been MOVED BACK into the
    // _Unassigned_ state, ready to be spent again!
    for pegout in &second_prop.pegouts {
        let stored = atomic.db.get_unassigned(&pegout.id).unwrap();
        assert!(stored.is_some());
    }

    // ## State: Block-1 was finalized

    let stored = atomic.db.get_header(&header1.block_hash()).unwrap();
    assert!(stored.is_none());

    // ## State: Block-2 remains

    // Do note that even though the second proposal has been implicitly orphaned
    // (removed), the Txid remains in `block_2` until the block itself is
    // explicitly orphaned (removed).
    //
    // The Bitcoin network would not allow finalizing `block_2` since the second
    // proposal reuses Utxos from `block_1`.
    //
    // TODO: Should this be cleaned up, though? Currently proposals do not
    // reference the block hash they're included in.
    let stored = atomic
        .db
        .get_header(&header2.block_hash())
        .unwrap()
        .unwrap();
    assert_eq!(stored.v.proposals, vec![second_prop.txid].into());

    // # Orphan block-2

    atomic
        .apply(|mut db| db.orphan_bitcoin_header(header2.block_hash()))
        .unwrap();

    let stored = atomic.db.get_header(&header2.block_hash()).unwrap();
    assert!(stored.is_none());
}

#[test]
fn orphan_header() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let header = gen_bitcoin_header();

    atomic
        .apply(|mut db| db.insert_bitcoin_header(header, 200))
        .unwrap();

    atomic
        .apply(|mut db| db.insert_bitcoin_tx(header.block_hash(), prop.txid))
        .unwrap();

    atomic
        .apply(|mut db| db.orphan_bitcoin_header(header.block_hash()))
        .unwrap();

    let stored = atomic.db.get_header(&header.block_hash()).unwrap();
    assert!(stored.is_none());

    // Importantly, the orphaned proposal MUST REMAIN in the state, since it
    // might get picked up by the Bitcoin mempool again. This is a different
    // scenario from removing orphaned pegouts when finalizing a block, since
    // that specifically looks for competing Txids - meaning Txids that reuse a
    // Utxo - which Bitcoin prohibits.
    let stored = atomic.db.get_proposal(&prop.txid).unwrap().unwrap();
    assert_eq!(stored.v, prop);
    assert!(
        // NOT!
        !atomic
            .db
            .data
            .trash_orphaned_proposals
            .contains_key(&prop.txid)
    );

    // The orpahned Utxos are removed from the state, but might get reinserted
    // again at some point later.
    // TODO: Do a test where there's a pending Txid registered; that Utxo should
    // remain in state.
    for utxo in &prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap();
        assert!(stored.is_none());
        assert!(atomic.db.data.trash_orphaned_utxos.contains_key(utxo));
    }
}
