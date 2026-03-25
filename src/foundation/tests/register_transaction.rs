use super::*;
use crate::{foundation::component::pegout::ValidationError, test_utils::gen_bitcoin_header};

#[test]
fn register_transaction_valid() {
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

    let stored = atomic.db.get_header(&header.block_hash()).unwrap().unwrap();
    assert_eq!(stored.v.proposals, vec![prop.txid].into());

    for utxo in &prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.v.txids, vec![prop.txid].into());
    }
}

#[test]
fn register_transaction_txid_already_inserted() {
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

    let err = atomic
        .apply(|mut db| db.insert_bitcoin_tx(header.block_hash(), prop.txid))
        .unwrap_err();

    assert_eq!(err, ValidationError::TxidAlreadyInserted.into());
}

#[test]
fn register_transaction_proposal_does_not_exist() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    let header = gen_bitcoin_header();

    atomic
        .apply(|mut db| db.insert_bitcoin_header(header, 200))
        .unwrap();

    let err = atomic
        .apply(|mut db| db.insert_bitcoin_tx(header.block_hash(), prop.txid))
        .unwrap_err();

    assert_eq!(err, ValidationError::ProposalDoesNotExist.into());

    let stored = atomic.db.get_proposal(&prop.txid).unwrap();
    assert!(stored.is_none());
}

#[test]
fn register_transaction_multiple_proposals_good_utxo_reuse() {
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

    let header = gen_bitcoin_header();

    atomic
        .apply(|mut db| db.insert_bitcoin_header(header, 200))
        .unwrap();

    atomic
        .apply(|mut db| db.insert_bitcoin_tx(header.block_hash(), first_prop.txid))
        .unwrap();

    let stored = atomic.db.get_header(&header.block_hash()).unwrap().unwrap();
    assert_eq!(stored.v.proposals, vec![first_prop.txid].into());

    for utxo in &first_prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.v.txids, vec![first_prop.txid].into());
    }

    atomic
        .apply(|mut db| db.insert_bitcoin_tx(header.block_hash(), second_prop.txid))
        .unwrap();

    let stored = atomic.db.get_header(&header.block_hash()).unwrap().unwrap();
    assert_eq!(
        stored.v.proposals,
        vec![first_prop.txid, second_prop.txid].into()
    );

    assert_eq!(first_prop.utxos, second_prop.utxos);

    for utxo in &first_prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(
            stored.v.txids,
            vec![first_prop.txid, second_prop.txid].into()
        );
    }
}

#[test]
fn register_transaction_multiple_proposals_unique_utxos() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let first_prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(first_prop.clone(), None))
        .unwrap();

    let second_prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(second_prop.clone(), None))
        .unwrap();

    let header = gen_bitcoin_header();

    atomic
        .apply(|mut db| db.insert_bitcoin_header(header, 200))
        .unwrap();

    atomic
        .apply(|mut db| db.insert_bitcoin_tx(header.block_hash(), first_prop.txid))
        .unwrap();

    atomic
        .apply(|mut db| db.insert_bitcoin_tx(header.block_hash(), second_prop.txid))
        .unwrap();

    let stored = atomic.db.get_header(&header.block_hash()).unwrap().unwrap();
    assert_eq!(
        stored.v.proposals,
        vec![first_prop.txid, second_prop.txid].into()
    );

    for utxo in &first_prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.v.txids, vec![first_prop.txid].into());
    }

    for utxo in &second_prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap().unwrap();
        assert_eq!(stored.v.txids, vec![second_prop.txid].into());
    }
}

#[test]
fn register_transaction_upgraded_proposal_good_utxo_reuse() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let prev_prop = prop;

    let upgraded_prop = atomic.gen_upgrade_proposal_reused_pegout(&prev_prop);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(upgraded_prop.clone(), Some(prev_prop.txid)))
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
        .apply(|mut db| db.insert_bitcoin_tx(header1.block_hash(), prev_prop.txid))
        .unwrap();

    atomic
        .apply(|mut db| {
            db.insert_bitcoin_tx(
                // NOTE: Different blocks!
                header2.block_hash(),
                upgraded_prop.txid,
            )
        })
        .unwrap();

    let stored = atomic
        .db
        .get_header(&header1.block_hash())
        .unwrap()
        .unwrap();
    assert_eq!(stored.v.proposals, vec![prev_prop.txid].into());

    let stored = atomic
        .db
        .get_header(&header2.block_hash())
        .unwrap()
        .unwrap();
    assert_eq!(stored.v.proposals, vec![upgraded_prop.txid].into());

    let utxo_reuse = prev_prop.utxos.get(0).unwrap();

    let stored = atomic.db.get_utxo(utxo_reuse).unwrap().unwrap();
    assert_eq!(
        stored.v.txids,
        vec![prev_prop.txid, upgraded_prop.txid].into()
    );

    for utxo in &prev_prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap().unwrap();
        if utxo == utxo_reuse {
            assert_eq!(
                stored.v.txids,
                vec![prev_prop.txid, upgraded_prop.txid].into()
            );
        } else {
            assert_eq!(stored.v.txids, vec![prev_prop.txid].into());
        }
    }

    for utxo in &upgraded_prop.utxos {
        let stored = atomic.db.get_utxo(utxo).unwrap().unwrap();
        if utxo == utxo_reuse {
            assert_eq!(
                stored.v.txids,
                vec![prev_prop.txid, upgraded_prop.txid].into()
            );
        } else {
            assert_eq!(stored.v.txids, vec![upgraded_prop.txid].into());
        }
    }
}
