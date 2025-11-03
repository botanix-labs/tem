use super::*;
use crate::{
    foundation::component::pegout::ValidationError,
    test_utils::{gen_bitcoin_utxo, gen_pegout_with_id},
};

#[test]
fn insert_unassigned() {
    let mut atomic = InMemoryAtomicLayer::new();

    let pegout_0 = gen_pegout_with_id();
    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();

    atomic
        .apply(|mut db| db.insert_unassigned(pegout_0.clone(), vec![ALICE, BOB, EVE].into()))
        .unwrap();

    atomic
        .apply(|mut db| db.insert_unassigned(pegout_1.clone(), vec![ALICE].into()))
        .unwrap();

    atomic
        .apply(|mut db| db.insert_unassigned(pegout_2.clone(), vec![ALICE].into()))
        .unwrap();

    let stored = atomic.db.get_unassigned(&pegout_0.id).unwrap().unwrap();
    assert_eq!(stored.v.pegout, pegout_0);

    let stored = atomic.db.get_unassigned(&pegout_1.id).unwrap().unwrap();
    assert_eq!(stored.v.pegout, pegout_1);

    let stored = atomic.db.get_unassigned(&pegout_2.id).unwrap().unwrap();
    assert_eq!(stored.v.pegout, pegout_2);

    // ERR: Attempting to re-insert an existing pegout.
    let err = atomic
        .apply(|mut db| db.insert_unassigned(pegout_0, vec![ALICE].into()))
        .unwrap_err();

    assert_eq!(err, ValidationError::UnassignedPegoutAlreadyInserted.into());
}

#[test]
fn insert_proposal_valid() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    let stored = atomic.db.get_proposal(&prop.txid).unwrap();
    assert!(stored.is_none());

    for pegout in &prop.pegouts {
        let stored = atomic.db.get_unassigned(&pegout.id).unwrap();
        assert!(stored.is_some());
    }

    atomic
        .start_tx()
        .unwrap()
        .insert_pegout_proposal(prop.clone(), None)
        .unwrap();

    let stored = atomic.db.get_proposal(&prop.txid).unwrap().unwrap();
    assert_eq!(stored.v, prop);

    for pegout in &prop.pegouts {
        let stored = atomic.db.get_unassigned(&pegout.id).unwrap();
        assert!(stored.is_none());
    }
}

#[test]
fn insert_proposal_good_utxo_reuse() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let first_prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut b| b.insert_pegout_proposal(first_prop.clone(), None))
        .unwrap();

    let mut second_prop = atomic.gen_new_proposal(ALICE, botanix_height);
    second_prop.utxos = first_prop.utxos.clone();

    // OK: We explicitly ALLOW reusing Utxos when no pegout are reused, and let
    // the Bitcoin network decide which competing proposal to probabilistically
    // finalize.
    // TODO: Clarify why we don't restrict this.
    atomic
        .apply(|mut b| b.insert_pegout_proposal(second_prop.clone(), None))
        .unwrap();
}

#[test]
fn insert_proposal_bad_candidate_claim() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(EVE, botanix_height);

    assert!(!atomic.candidates().contains(&EVE));

    let err = atomic
        .apply(|mut db| db.insert_pegout_proposal(prop, None))
        .unwrap_err();

    assert_eq!(err, ValidationError::BadCandidateClaim.into());
}

#[test]
fn insert_proposal_bad_pegout_reuse() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let first_prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(first_prop.clone(), None))
        .unwrap();

    // GENERATE new proposal with new Txid and new Utxos, but reused pegouts!
    let mut second_prop = atomic.gen_new_proposal(ALICE, botanix_height);
    second_prop.pegouts = first_prop.pegouts.clone();

    // ERR: Attempting to submit a second proposal with reused pegouts.
    let err = atomic
        .apply(|mut db| db.insert_pegout_proposal(second_prop.clone(), None))
        .unwrap_err();

    assert_eq!(
        err,
        ValidationError::UnassignedPegoutInvalidOrAlreadyProposed.into()
    );

    // GENERATE new proposal with new Txid and new Utxos, but reused pegouts!
    let mut third_prop = atomic.gen_new_proposal(BOB, botanix_height);
    third_prop.pegouts = first_prop.pegouts;

    assert_eq!(second_prop.fed_id, ALICE);
    assert_eq!(third_prop.fed_id, BOB);

    // ERR: Attempting to submit a third proposal (by Bob) reused pegouts.
    let err = atomic
        .apply(|mut db| db.insert_pegout_proposal(third_prop.clone(), None))
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
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let prev_prop = prop;

    // Generate UPGRADED proposal with a reused pegout; the FIRST Utxo from the
    // previous proposal MUST be reused!
    let upgraded_prop = atomic.gen_upgrade_proposal_reused_pegout(&prev_prop);

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

    atomic
        .apply(|mut db| db.insert_pegout_proposal(upgraded_prop.clone(), Some(prev_prop.txid)))
        .unwrap();

    let stored = atomic.db.get_proposal(&prev_prop.txid).unwrap().unwrap();
    assert_eq!(stored.v, prev_prop);

    let stored = atomic
        .db
        .get_proposal(&upgraded_prop.txid)
        .unwrap()
        .unwrap();
    assert_eq!(stored.v, upgraded_prop);
}

#[test]
fn insert_proposal_bad_upgrade_no_utxo_reuse() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let prev_prop = prop;

    // Generate UPGRADED proposal with a reused pegout, but WITHOUT reusing a Utxo (ERR).
    let mut upgraded_prop = atomic.gen_upgrade_proposal_reused_pegout(&prev_prop);
    upgraded_prop.utxos = vec![gen_bitcoin_utxo(), gen_bitcoin_utxo()].into();

    let err = atomic
        .apply(|mut db| db.insert_pegout_proposal(upgraded_prop, Some(prev_prop.txid)))
        .unwrap_err();

    assert_eq!(err, ValidationError::UpgradedProposalMustReuseUtxo.into());
}

#[test]
fn insert_proposal_bad_upgrade_bad_utxo_reuse() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let prev_prop = prop;

    let mut upgraded_prop = atomic.gen_upgrade_proposal_reused_pegout(&prev_prop);
    upgraded_prop.utxos = vec![
        // NOTE: Must be the first!
        prev_prop.utxos.last().unwrap().clone(),
        gen_bitcoin_utxo(),
    ]
    .into();

    let err = atomic
        .apply(|mut db| db.insert_pegout_proposal(upgraded_prop, Some(prev_prop.txid)))
        .unwrap_err();

    assert_eq!(err, ValidationError::UpgradedProposalMustReuseUtxo.into());
}

#[test]
fn insert_proposal_bad_upgrade_different_fed_id() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let prev_prop = prop;

    let mut upgraded_prop = atomic.gen_upgrade_proposal_reused_pegout(&prev_prop);
    upgraded_prop.fed_id = EVE;

    let err = atomic
        .apply(|mut db| db.insert_pegout_proposal(upgraded_prop, Some(prev_prop.txid)))
        .unwrap_err();

    assert_eq!(err, ValidationError::UpgradedProposalBadFedId.into());
}

#[test]
fn insert_proposal_bad_upgrade_no_previous_reference() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let prev_prop = prop;

    let upgraded_prop = atomic.gen_upgrade_proposal_reused_pegout(&prev_prop);

    let err = atomic
        .apply(|mut db| db.insert_pegout_proposal(upgraded_prop, None))
        .unwrap_err();

    assert_eq!(
        err,
        ValidationError::UnassignedPegoutInvalidOrAlreadyProposed.into()
    );
}

#[test]
fn insert_proposal_bad_upgrade_bad_previous_reference() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let prev_prop = prop;

    let upgraded_prop = atomic.gen_upgrade_proposal_reused_pegout(&prev_prop);

    let bad_prev_txid = gen_bitcoin_txid();

    let err = atomic
        .apply(|mut db| db.insert_pegout_proposal(upgraded_prop, Some(bad_prev_txid)))
        .unwrap_err();

    assert_eq!(err, ValidationError::UpgradedProposalBadPreviousRef.into());
}

#[test]
fn insert_proposal_bad_upgrade_pegout_already_claimed() {
    let mut atomic = InMemoryAtomicLayer::new();

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let prev_prop = prop;

    let second_prop = atomic.gen_new_proposal(BOB, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(second_prop.clone(), None))
        .unwrap();

    let mut upgraded_prop = atomic.gen_upgrade_proposal_reused_pegout(&prev_prop);
    upgraded_prop.pegouts = second_prop.pegouts;

    let err = atomic
        .apply(|mut db| db.insert_pegout_proposal(upgraded_prop.clone(), Some(prev_prop.txid)))
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
    let mut atomic = InMemoryAtomicLayer::new();

    // NOTE: We construct two upgraded proposals, both referening the same
    // initial proposal. The Utxo-reuse mandate will make sure that both
    // upgrades reuse the same (FIRST) Utxo from the initial proposal. This
    // gives us a guarantee that only one proposal will get probabilistically
    // finalized on Bitcoin.

    let botanix_height = 100;
    let prop = atomic.gen_new_proposal(ALICE, botanix_height);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(prop.clone(), None))
        .unwrap();

    let prev_prop = prop;

    let upgraded_prop_1 = atomic.gen_upgrade_proposal_reused_pegout(&prev_prop);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(upgraded_prop_1.clone(), Some(prev_prop.txid)))
        .unwrap();

    let upgraded_prop_2 = atomic.gen_upgrade_proposal_reused_pegout(&prev_prop);

    atomic
        .apply(|mut db| db.insert_pegout_proposal(upgraded_prop_2.clone(), Some(prev_prop.txid)))
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

    let stored = atomic.db.get_proposal(&prev_prop.txid).unwrap().unwrap();
    assert_eq!(stored.v, prev_prop);

    let stored = atomic
        .db
        .get_proposal(&upgraded_prop_1.txid)
        .unwrap()
        .unwrap();
    assert_eq!(stored.v, upgraded_prop_1);

    let stored = atomic
        .db
        .get_proposal(&upgraded_prop_2.txid)
        .unwrap()
        .unwrap();
    assert_eq!(stored.v, upgraded_prop_2);
}
