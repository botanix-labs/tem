use super::*;
use crate::{
    foundation::{AtomicCommitLayer, commitment::mem_db::InMemoryCommitments},
    test_utils::gen_bitcoin_hash,
};

#[test]
fn finalize_header_valid() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(
        //
        prop.clone(),
        None,
        &mut data,
    )
    .unwrap();

    let block = gen_bitcoin_hash();

    b.insert_bitcoin_header(block, 200, &mut data).unwrap();

    b.register_bitcoin_tx(
        //
        block,
        prop.clone(),
        &mut data,
    )
    .unwrap();

    b.finalize_bitcoin_header(block, &mut data).unwrap();

    let stored = data.get_header(&block).unwrap();
    assert!(stored.is_none());

    let stored = data.get_proposal(&prop.txid).unwrap();
    assert!(stored.is_none());
    assert!(data.trash_finalized_proposals.contains_key(&prop.txid));

    for utxo in &prop.utxos {
        let stored = data.get_utxo(utxo).unwrap();
        assert!(stored.is_none());
        assert!(data.trash_finalized_utxos.contains_key(utxo));
    }
}

#[test]
fn finalize_header_with_competing_txid() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let first_prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(
        //
        first_prop.clone(),
        None,
        &mut data,
    )
    .unwrap();

    let mut second_prop = data.gen_new_proposal(ALICE, botanix_height);
    second_prop.utxos = first_prop.utxos.clone();

    b.insert_pegout_proposal(
        //
        second_prop.clone(),
        None,
        &mut data,
    )
    .unwrap();

    let block_1 = gen_bitcoin_hash();
    let block_2 = gen_bitcoin_hash();

    b.insert_bitcoin_header(block_1, 200, &mut data).unwrap();
    b.insert_bitcoin_header(block_2, 201, &mut data).unwrap();

    b.register_bitcoin_tx(
        //
        block_1,
        first_prop.clone(),
        &mut data,
    )
    .unwrap();

    b.register_bitcoin_tx(
        //
        block_2,
        second_prop.clone(),
        &mut data,
    )
    .unwrap();

    assert_eq!(first_prop.utxos, second_prop.utxos);

    for utxo in &first_prop.utxos {
        let stored = data.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.txids, vec![first_prop.txid, second_prop.txid].into());
    }

    for utxo in &second_prop.utxos {
        let stored = data.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.txids, vec![first_prop.txid, second_prop.txid].into());
    }

    // # Finalize block-1

    b.finalize_bitcoin_header(block_1, &mut data).unwrap();

    // ## State: First proposal

    // Proposal itself has been removed and categorized as _finalized_.
    let stored = data.get_proposal(&first_prop.txid).unwrap();
    assert!(stored.is_none());

    assert!(
        data.trash_finalized_proposals
            .contains_key(&first_prop.txid)
    );

    // All removed Utxos from the first proposal are categorized as _finalized_.
    for utxo in &first_prop.utxos {
        let stored = data.get_utxo(utxo).unwrap();
        assert!(stored.is_none());
        assert!(data.trash_finalized_utxos.contains_key(utxo));
    }

    // All pegouts are effectively gone.
    for pegout in &first_prop.pegouts {
        let stored = data.get_unassigned(&pegout.id).unwrap();
        assert!(stored.is_none());
    }

    // ## State: Second proposal

    // Proposal itself has been removed and categorized as _orphaned_.
    let stored = data.get_proposal(&second_prop.txid).unwrap();
    assert!(stored.is_none());

    assert!(
        data.trash_orphaned_proposals
            .contains_key(&second_prop.txid)
    );

    // All removed Utxos from the second proposal that are NOT reused in the
    // first proposal are categorized as _orphaned_.
    for utxo in &second_prop.utxos {
        if first_prop.utxos.contains(&utxo) {
            assert!(data.trash_finalized_utxos.contains_key(utxo));
        } else {
            assert!(data.trash_orphaned_utxos.contains_key(utxo));
        }
    }

    // All pegouts from the second proposal have been MOVED BACK into the
    // _Unassigned_ state, ready to be spent again!
    for pegout in &second_prop.pegouts {
        let stored = data.get_unassigned(&pegout.id).unwrap();
        assert!(stored.is_some());
    }

    // ## State: Block-1 was finalized

    let stored = data.get_header(&block_1).unwrap();
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
    let stored = data.get_header(&block_2).unwrap().unwrap();
    assert_eq!(stored.proposals, vec![second_prop.txid].into());

    // # Orphan block-2

    b.orphan_bitcoin_header(block_2, &mut data).unwrap();

    let stored = data.get_header(&block_2).unwrap();
    assert!(stored.is_none());
}

#[test]
fn orphan_header() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(
        //
        prop.clone(),
        None,
        &mut data,
    )
    .unwrap();

    let block = gen_bitcoin_hash();

    b.insert_bitcoin_header(block, 200, &mut data).unwrap();

    b.register_bitcoin_tx(
        //
        block,
        prop.clone(),
        &mut data,
    )
    .unwrap();

    b.orphan_bitcoin_header(block, &mut data).unwrap();

    let stored = data.get_header(&block).unwrap();
    assert!(stored.is_none());

    // Importantly, the orphaned proposal MUST REMAIN in the state, since it
    // might get picked up by the Bitcoin mempool again. This is a different
    // scenario from removing orphaned pegouts when finalizing a block, since
    // that specifically looks for competing Txids - meaning Txids that reuse a
    // Utxo - which Bitcoin prohibits.
    let stored = data.get_proposal(&prop.txid).unwrap().unwrap();
    assert_eq!(stored, prop);
    assert!(!data.trash_orphaned_proposals.contains_key(&prop.txid)); // NOT!

    // The orpahned Utxos are removed from the state, but might get reinserted
    // again at some point later.
    // TODO: Do a test where there's a pending Txid registered; that Utxo should
    // remain in state.
    for utxo in &prop.utxos {
        let stored = data.get_utxo(utxo).unwrap();
        assert!(stored.is_none());
        assert!(data.trash_orphaned_utxos.contains_key(utxo));
    }
}
