use super::*;
use crate::{
    foundation::{
        AtomicCommitLayer, commitment::mem_db::InMemoryCommitments,
        component::pegout::ValidationError,
    },
    test_utils::gen_bitcoin_hash,
};

#[test]
fn register_transaction_valid() {
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

    let stored = data.get_header(&block).unwrap().unwrap();
    assert_eq!(stored.proposals, vec![prop.txid].into());

    for utxo in &prop.utxos {
        let stored = data.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.txids, vec![prop.txid].into());
    }
}

#[test]
fn register_transaction_txid_already_inserted() {
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

    let err = b
        .register_bitcoin_tx(
            //
            block, prop, &mut data,
        )
        .unwrap_err();

    assert_eq!(err, ValidationError::TxidAlreadyInserted.into());
}

#[test]
fn register_transaction_proposal_does_not_exist() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);
    let block = gen_bitcoin_hash();

    b.insert_bitcoin_header(block, 200, &mut data).unwrap();

    let err = b
        .register_bitcoin_tx(
            //
            block,
            prop.clone(),
            &mut data,
        )
        .unwrap_err();

    assert_eq!(err, ValidationError::ProposalDoesNotExist.into());

    let stored = data.get_proposal(&prop.txid).unwrap();
    assert!(stored.is_none());
}

#[test]
fn register_transaction_multiple_proposals_good_utxo_reuse() {
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

    let block = gen_bitcoin_hash();

    b.insert_bitcoin_header(block, 200, &mut data).unwrap();

    b.register_bitcoin_tx(
        //
        block,
        first_prop.clone(),
        &mut data,
    )
    .unwrap();

    let stored = data.get_header(&block).unwrap().unwrap();
    assert_eq!(stored.proposals, vec![first_prop.txid].into());

    for utxo in &first_prop.utxos {
        let stored = data.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.txids, vec![first_prop.txid].into());
    }

    b.register_bitcoin_tx(
        //
        block,
        second_prop.clone(),
        &mut data,
    )
    .unwrap();

    let stored = data.get_header(&block).unwrap().unwrap();
    assert_eq!(
        stored.proposals,
        vec![first_prop.txid, second_prop.txid].into()
    );

    assert_eq!(first_prop.utxos, second_prop.utxos);

    for utxo in &first_prop.utxos {
        let stored = data.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.txids, vec![first_prop.txid, second_prop.txid].into());
    }
}

#[test]
fn register_transaction_multiple_proposals_unique_utxos() {
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

    let second_prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(
        //
        second_prop.clone(),
        None,
        &mut data,
    )
    .unwrap();

    let block = gen_bitcoin_hash();

    b.insert_bitcoin_header(block, 200, &mut data).unwrap();

    b.register_bitcoin_tx(
        //
        block,
        first_prop.clone(),
        &mut data,
    )
    .unwrap();

    b.register_bitcoin_tx(
        //
        block,
        second_prop.clone(),
        &mut data,
    )
    .unwrap();

    let stored = data.get_header(&block).unwrap().unwrap();
    assert_eq!(
        stored.proposals,
        vec![first_prop.txid, second_prop.txid].into()
    );

    for utxo in &first_prop.utxos {
        let stored = data.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.txids, vec![first_prop.txid].into());
    }

    for utxo in &second_prop.utxos {
        let stored = data.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.txids, vec![second_prop.txid].into());
    }
}

#[test]
fn register_transaction_upgraded_proposal_good_utxo_reuse() {
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

    let prev_prop = prop;

    let upgraded_prop = data.gen_upgrade_proposal_reused_pegout(&prev_prop);

    b.insert_pegout_proposal(
        //
        upgraded_prop.clone(),
        Some(prev_prop.clone()),
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
        prev_prop.clone(),
        &mut data,
    )
    .unwrap();

    b.register_bitcoin_tx(
        // NOTE: Different blocks!
        block_2,
        upgraded_prop.clone(),
        &mut data,
    )
    .unwrap();

    let stored = data.get_header(&block_1).unwrap().unwrap();
    assert_eq!(stored.proposals, vec![prev_prop.txid].into());

    let stored = data.get_header(&block_2).unwrap().unwrap();
    assert_eq!(stored.proposals, vec![upgraded_prop.txid].into());

    let utxo_reuse = prev_prop.utxos.get(0).unwrap();

    let stored = data.get_utxo(utxo_reuse).unwrap().unwrap();
    assert_eq!(
        stored.txids,
        vec![prev_prop.txid, upgraded_prop.txid].into()
    );

    for utxo in &prev_prop.utxos {
        let stored = data.get_utxo(utxo).unwrap().unwrap();
        if utxo == utxo_reuse {
            assert_eq!(
                stored.txids,
                vec![prev_prop.txid, upgraded_prop.txid].into()
            );
        } else {
            assert_eq!(stored.txids, vec![prev_prop.txid].into());
        }
    }

    for utxo in &upgraded_prop.utxos {
        let stored = data.get_utxo(utxo).unwrap().unwrap();
        if utxo == utxo_reuse {
            assert_eq!(
                stored.txids,
                vec![prev_prop.txid, upgraded_prop.txid].into()
            );
        } else {
            assert_eq!(stored.txids, vec![upgraded_prop.txid].into());
        }
    }
}
