use super::*;
use crate::{
    foundation::{
        AtomicCommitLayer, commitment::mem_db::InMemoryCommitments,
        component::pegout::ValidationError,
    },
    test_utils::{gen_bitcoin_utxo, gen_pegout_with_id},
};

#[test]
fn insert_unassigned() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();

    let pegout_0 = gen_pegout_with_id();
    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();

    b.insert_unassigned(pegout_0.clone(), vec![ALICE, BOB, EVE].into(), &mut data)
        .unwrap();
    b.insert_unassigned(pegout_1, vec![ALICE].into(), &mut data)
        .unwrap();
    b.insert_unassigned(pegout_2, vec![ALICE].into(), &mut data)
        .unwrap();

    // ERR: Attempting to re-insert an existing pegout.
    let err = b
        .insert_unassigned(pegout_0, vec![ALICE].into(), &mut data)
        .unwrap_err();

    assert_eq!(err, ValidationError::UnassignedPegoutAlreadyInserted.into());
}

#[test]
fn insert_proposal_valid() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    let stored = data.get_proposal(&prop.txid).unwrap();
    assert!(stored.is_none());

    for pegout in &prop.pegouts {
        let stored = data.get_unassigned(&pegout.id).unwrap();
        assert!(stored.is_some());
    }

    b.insert_pegout_proposal(prop.clone(), None, &mut data)
        .unwrap();

    let stored = data.get_proposal(&prop.txid).unwrap().unwrap();
    assert_eq!(prop, stored);

    for pegout in &prop.pegouts {
        let stored = data.get_unassigned(&pegout.id).unwrap();
        assert!(stored.is_none());
    }
}

#[test]
fn insert_proposal_good_utxo_reuse() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let first_prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(first_prop.clone(), None, &mut data)
        .unwrap();

    let mut second_prop = data.gen_new_proposal(ALICE, botanix_height);
    second_prop.utxos = first_prop.utxos.clone();

    // OK: We explicitly ALLOW reusing Utxos when no pegout are reused, and let
    // the Bitcoin network decide which competing proposal to probabilistically
    // finalize.
    // TODO: Clarify why we don't restrict this.
    b.insert_pegout_proposal(second_prop.clone(), None, &mut data)
        .unwrap();

    let stored = data.get_proposal(&first_prop.txid).unwrap().unwrap();
    assert_eq!(first_prop, stored);

    let stored = data.get_proposal(&second_prop.txid).unwrap().unwrap();
    assert_eq!(second_prop, stored);
}

#[test]
fn insert_proposal_bad_candidate_claim() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(EVE, botanix_height);

    assert!(!data.candidates().contains(&EVE));

    let err = b.insert_pegout_proposal(prop, None, &mut data).unwrap_err();

    assert_eq!(err, ValidationError::BadCandidateClaim.into());
}

#[test]
fn insert_proposal_bad_pegout_reuse() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let first_prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(first_prop.clone(), None, &mut data)
        .unwrap();

    // GENERATE new proposal with new Txid and new Utxos, but reused pegouts!
    let mut second_prop = data.gen_new_proposal(ALICE, botanix_height);
    second_prop.pegouts = first_prop.pegouts.clone();

    // ERR: Attempting to submit a second proposal with reused pegouts.
    let err = b
        .insert_pegout_proposal(second_prop.clone(), None, &mut data)
        .unwrap_err();

    assert_eq!(
        err,
        ValidationError::UnassignedPegoutInvalidOrAlreadyProposed.into()
    );

    // GENERATE new proposal with new Txid and new Utxos, but reused pegouts!
    let mut third_prop = data.gen_new_proposal(BOB, botanix_height);
    third_prop.pegouts = first_prop.pegouts;

    assert_eq!(second_prop.fed_id, ALICE);
    assert_eq!(third_prop.fed_id, BOB);

    // ERR: Attempting to submit a third proposal (by Bob) reused pegouts.
    let err = b
        .insert_pegout_proposal(third_prop.clone(), None, &mut data)
        .unwrap_err();

    assert_eq!(second_prop.fed_id, ALICE);
    assert_eq!(third_prop.fed_id, BOB);

    assert_eq!(
        err,
        ValidationError::UnassignedPegoutInvalidOrAlreadyProposed.into()
    );
}

#[test]
fn insert_proposal_good_upgrade() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(prop.clone(), None, &mut data)
        .unwrap();

    let prev_prop = prop;

    // Generate UPGRADED proposal with a reused pegout; the FIRST Utxo from the
    // previous proposal MUST be reused!
    let upgraded_prop = data.gen_upgrade_proposal_reused_pegout(&prev_prop);

    assert_ne!(prev_prop.txid, upgraded_prop.txid);
    assert_ne!(prev_prop.utxos, upgraded_prop.utxos);
    assert_ne!(prev_prop.pegouts, upgraded_prop.pegouts);

    assert!(
        upgraded_prop
            .utxos
            .contains(prev_prop.utxos.first().unwrap())
    );
    assert!(
        upgraded_prop
            .pegouts
            .contains(prev_prop.pegouts.first().unwrap())
    );

    b.insert_pegout_proposal(upgraded_prop.clone(), Some(prev_prop.clone()), &mut data)
        .unwrap();

    let stored = data.get_proposal(&prev_prop.txid).unwrap().unwrap();
    assert_eq!(prev_prop, stored);

    let stored = data.get_proposal(&upgraded_prop.txid).unwrap().unwrap();
    assert_eq!(upgraded_prop, stored);
}

#[test]
fn insert_proposal_bad_upgrade_no_utxo_reuse() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(prop.clone(), None, &mut data)
        .unwrap();

    let prev_prop = prop;

    // Generate UPGRADED proposal with a reused pegout, but WITHOUT reusing a Utxo (ERR).
    let mut upgraded_prop = data.gen_upgrade_proposal_reused_pegout(&prev_prop);
    upgraded_prop.utxos = vec![gen_bitcoin_utxo(), gen_bitcoin_utxo()].into();

    let err = b
        .insert_pegout_proposal(upgraded_prop, Some(prev_prop), &mut data)
        .unwrap_err();

    assert_eq!(err, ValidationError::UpgradedProposalMustReuseUtxo.into());
}

#[test]
fn insert_proposal_bad_upgrade_bad_utxo_reuse() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(prop.clone(), None, &mut data)
        .unwrap();

    let prev_prop = prop;

    let mut upgraded_prop = data.gen_upgrade_proposal_reused_pegout(&prev_prop);
    upgraded_prop.utxos = vec![
        // NOTE: Must be the first!
        prev_prop.utxos.last().unwrap().clone(),
        gen_bitcoin_utxo(),
    ]
    .into();

    let err = b
        .insert_pegout_proposal(upgraded_prop, Some(prev_prop), &mut data)
        .unwrap_err();

    assert_eq!(err, ValidationError::UpgradedProposalMustReuseUtxo.into());
}

#[test]
fn insert_proposal_bad_upgrade_different_fed_id() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(prop.clone(), None, &mut data)
        .unwrap();

    let prev_prop = prop;

    let mut upgraded_prop = data.gen_upgrade_proposal_reused_pegout(&prev_prop);
    upgraded_prop.fed_id = EVE;

    let err = b
        .insert_pegout_proposal(upgraded_prop, Some(prev_prop), &mut data)
        .unwrap_err();

    assert_eq!(err, ValidationError::UpgradedProposalBadFedId.into());
}

#[test]
fn insert_proposal_bad_upgrade_no_previous_reference() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(prop.clone(), None, &mut data)
        .unwrap();

    let prev_prop = prop;

    let upgraded_prop = data.gen_upgrade_proposal_reused_pegout(&prev_prop);

    let err = b
        .insert_pegout_proposal(upgraded_prop, None, &mut data)
        .unwrap_err();

    assert_eq!(
        err,
        ValidationError::UnassignedPegoutInvalidOrAlreadyProposed.into()
    );
}

#[test]
fn insert_proposal_bad_upgrade_bad_previous_reference() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(prop.clone(), None, &mut data)
        .unwrap();

    let mut prev_prop = prop;

    let upgraded_prop = data.gen_upgrade_proposal_reused_pegout(&prev_prop);

    prev_prop.utxos = vec![gen_bitcoin_utxo(), gen_bitcoin_utxo()].into();

    let err = b
        .insert_pegout_proposal(upgraded_prop, Some(prev_prop), &mut data)
        .unwrap_err();

    assert_eq!(err, ValidationError::UpgradedProposalBadPreviousRef.into());
}

#[test]
fn insert_proposal_bad_upgrade_pegout_already_claimed() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(prop.clone(), None, &mut data)
        .unwrap();

    let prev_prop = prop;

    let second_prop = data.gen_new_proposal(BOB, botanix_height);

    b.insert_pegout_proposal(second_prop.clone(), None, &mut data)
        .unwrap();

    let mut upgraded_prop = data.gen_upgrade_proposal_reused_pegout(&prev_prop);
    upgraded_prop.pegouts = second_prop.pegouts;

    let err = b
        .insert_pegout_proposal(upgraded_prop.clone(), Some(prev_prop.clone()), &mut data)
        .unwrap_err();

    assert_eq!(prev_prop.fed_id, ALICE);
    assert_eq!(second_prop.fed_id, BOB);
    assert_eq!(upgraded_prop.fed_id, ALICE);

    assert_eq!(
        err,
        ValidationError::UnassignedPegoutInvalidOrAlreadyProposed.into()
    );
}

#[test]
fn insert_proposal_good_upgrade_multiple_competing_refs() {
    let mut db = InMemoryCommitments::new();
    let mut b: BotanixLayer = db.start_trie_tx().unwrap().into();
    let mut data = InMemoryDataSource::new();
    data.setup_pegout_state(&mut b);

    // NOTE: We construct two upgraded proposals, both referening the same
    // initial proposal. The Utxo-reuse mandate will make sure that both
    // upgrades reuse the same (FIRST) Utxo from the initial proposal. This
    // gives us a guarantee that only one proposal will get probabilistically
    // finalized on Bitcoin.

    let botanix_height = 100;
    let prop = data.gen_new_proposal(ALICE, botanix_height);

    b.insert_pegout_proposal(prop.clone(), None, &mut data)
        .unwrap();

    let prev_prop = prop;

    let upgraded_prop_1 = data.gen_upgrade_proposal_reused_pegout(&prev_prop);

    b.insert_pegout_proposal(upgraded_prop_1.clone(), Some(prev_prop.clone()), &mut data)
        .unwrap();

    let upgraded_prop_2 = data.gen_upgrade_proposal_reused_pegout(&prev_prop);

    b.insert_pegout_proposal(upgraded_prop_2.clone(), Some(prev_prop.clone()), &mut data)
        .unwrap();

    assert!(
        upgraded_prop_1
            .utxos
            .contains(prev_prop.utxos.first().unwrap())
    );

    assert!(
        upgraded_prop_2
            .utxos
            .contains(prev_prop.utxos.first().unwrap())
    );

    let stored = data.get_proposal(&prev_prop.txid).unwrap().unwrap();
    assert_eq!(prev_prop, stored);

    let stored = data.get_proposal(&upgraded_prop_1.txid).unwrap().unwrap();
    assert_eq!(upgraded_prop_1, stored);

    let stored = data.get_proposal(&upgraded_prop_2.txid).unwrap().unwrap();
    assert_eq!(upgraded_prop_2, stored);
}
