#![allow(non_snake_case)]

use crate::foundation::commitment::sorted::Sorted;
use crate::foundation::component::pegout::ProposalEntry;
use crate::foundation::proof::AuxEvent;
use crate::foundation::tests::InMemoryAtomicLayer;
use crate::foundation::{Error, Foundation, MULTISIG, ValidationError};
use crate::test_utils::{
    gen_bitcoin_header, gen_bitcoin_header_with_proof, gen_bitcoin_tx_from_pegouts,
    gen_foundation_state_root, gen_pegout_with_id,
};

#[test]
fn foundation_basic_atomic_properties() {
    let atomic_layer = InMemoryAtomicLayer::new();

    let A = gen_bitcoin_header();
    let B = gen_bitcoin_header();

    // FOUNDATION: Setup.
    let mut f = Foundation::new_genesis(atomic_layer, A, 200, 0, 3).unwrap();

    let origin_root = f.commitment_root().unwrap();

    // PROPOSE: Construct an invalid state transition.
    let res_err = f
        .propose_commitments(|c| {
            // INVALID: Block B does not reference A.
            assert_ne!(B.prev_blockhash, A.block_hash());

            c.insert_bitcoin_header(B, 201)?;
            Ok(())
        })
        .unwrap_err();

    assert_eq!(
        res_err,
        Error::ValidationError(ValidationError::BadBitcoinHeader)
    );

    // Commitment state was RESET accordingly.
    let current_root = f.commitment_root().unwrap();
    assert_eq!(current_root, origin_root);

    // FINALIZE: Finalize an invalid state transition.
    let random_root = gen_foundation_state_root();
    let res_err = f
        .finalize_commitments(random_root, |c| {
            // INVALID: Block B does not reference A.
            assert_ne!(B.prev_blockhash, A.block_hash());

            c.insert_bitcoin_header(B, 201)?;
            Ok(())
        })
        .unwrap_err();

    assert_eq!(
        res_err,
        Error::ValidationError(ValidationError::BadBitcoinHeader)
    );

    // Commitment state was RESET accordingly.
    let current_root = f.commitment_root().unwrap();
    assert_eq!(current_root, origin_root);
}

#[test]
fn foundation_propose_and_finalize() {
    let atomic_layer = InMemoryAtomicLayer::new();

    let A = gen_bitcoin_header();
    let mut B = gen_bitcoin_header();

    // Block B references block A.
    B.prev_blockhash = A.block_hash();

    // FOUNDATION: Setup.
    let mut f = Foundation::new_genesis(atomic_layer, A, 200, 0, 3).unwrap();

    let origin_root = f.commitment_root().unwrap();

    // PROPOSE: Construct a valid state transition.
    let proof = f
        .propose_commitments(|c| {
            // Valid header inclusion.
            assert_eq!(B.prev_blockhash, A.block_hash());

            c.insert_bitcoin_header(B, 201)?;
            Ok(())
        })
        .unwrap();

    // Commitment proof is different from the origin root.
    assert_ne!(origin_root, proof.state().commitments);

    // Commitment state was RESET accordingly.
    let current_root = f.commitment_root().unwrap();
    assert_eq!(current_root, origin_root);

    // FINALIZE: Finalizing a valid state transition.
    let expected_root = proof.compute_root();
    let final_proof = f
        .finalize_commitments(expected_root, |c| {
            // Valid header inclusion.
            assert_eq!(B.prev_blockhash, A.block_hash());

            c.insert_bitcoin_header(B, 201)?;
            Ok(())
        })
        .unwrap();

    // Commitment state has been UPDATED accordingly.
    let updated_root = f.commitment_root().unwrap();
    assert_ne!(updated_root, origin_root); // Not equal!
    assert_eq!(updated_root, proof.state().commitments);

    assert_eq!(proof, final_proof);
}

#[test]
fn foundation_propose_and_finalize_bad_proof() {
    let atomic_layer = InMemoryAtomicLayer::new();

    let A = gen_bitcoin_header();
    let mut B = gen_bitcoin_header();
    let mut C = gen_bitcoin_header();

    // Block B references block A.
    B.prev_blockhash = A.block_hash();
    // Block C references block A, as well.
    C.prev_blockhash = A.block_hash();

    // FOUNDATION: Setup.
    let mut f = Foundation::new_genesis(atomic_layer, A, 200, 0, 3).unwrap();

    let origin_root = f.commitment_root().unwrap();

    // PROPOSE: Construct a valid state transition.
    let proof = f
        .propose_commitments(|c| {
            // Valid header inclusion.
            assert_eq!(B.prev_blockhash, A.block_hash());

            c.insert_bitcoin_header(B, 201)?;
            Ok(())
        })
        .unwrap();

    // Commitment proof is different from the origin root.
    assert_ne!(origin_root, proof.state().commitments);

    // Commitment state was RESET accordingly.
    let current_root = f.commitment_root().unwrap();
    assert_eq!(current_root, origin_root);

    // FINALIZE: Finalizing a valid state transition, which DOES NOT match the
    // provided proof.
    let expected_root = proof.compute_root();
    let res_err = f
        .finalize_commitments(expected_root, |c| {
            // Valid header inclusion.
            // NOTE: The proprosal uses block hash B, but here we use block hash C.
            assert_eq!(C.prev_blockhash, A.block_hash());

            c.insert_bitcoin_header(C, 201)?;
            Ok(())
        })
        .unwrap_err();

    assert_eq!(
        res_err,
        Error::ValidationError(ValidationError::BadFoundationStateRoot)
    );

    // Commitment state was RESET accordingly.
    let current_root = f.commitment_root().unwrap();
    assert_eq!(current_root, origin_root);
}

#[test]
fn foundation_initiate_pegouts_with_aux_events() {
    let atomic_layer = InMemoryAtomicLayer::new();

    let A = gen_bitcoin_header();

    // Note that the `Sorted<_>` structure dictates the order of how pegouts are
    // processed and validated.
    let available: Sorted<_> = vec![
        gen_pegout_with_id(),
        gen_pegout_with_id(),
        gen_pegout_with_id(),
    ]
    .into();

    let pegout_1 = available[0].clone();
    let pegout_2 = available[1].clone();
    let pegout_3 = available[2].clone();

    let transaction = gen_bitcoin_tx_from_pegouts(&[&pegout_1.data, &pegout_2.data]);

    // Construct a block header with inclusion proof.
    let (mut B, tx_proof) = gen_bitcoin_header_with_proof(&transaction);
    B.prev_blockhash = A.block_hash();

    let proposal = ProposalEntry {
        txid: transaction.compute_txid(),
        fed_id: MULTISIG,
        botanix_height: 200,
        utxos: transaction
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect(),
        pegouts: vec![pegout_1.clone(), pegout_2.clone()].into(),
    };

    // FOUNDATION: Setup.
    let mut f = Foundation::new_genesis(atomic_layer, A, 200, 0, 3).unwrap();

    // PROPOSE: Construct a valid state transition.
    let foundation_proof = f
        .propose_commitments::<_, ()>(|c| {
            // Initite pegouts
            c.insert_unassigned(pegout_1.clone(), vec![MULTISIG])?;
            c.insert_unassigned(pegout_2.clone(), vec![MULTISIG])?;
            c.insert_unassigned(pegout_3.clone(), vec![MULTISIG])?;

            // Insert block B.
            c.insert_bitcoin_header(B, 201)?;

            // Submit the proposal first.
            c.insert_pegout_proposal(proposal.clone(), None)?;

            // Register transaction for block B, using pegouts(1&2).
            c.insert_bitcoin_tx(
                B.block_hash(),
                transaction.clone(),
                tx_proof.clone(),
                proposal.clone(),
            )?;

            Ok(())
        })
        .unwrap();

    // Validate auxiliary events.
    assert_eq!(
        foundation_proof.state().aux_events,
        vec![
            AuxEvent::InitiatedPegout {
                pegout: pegout_1.id,
                candidates: vec![MULTISIG].into(),
            },
            AuxEvent::InitiatedPegout {
                pegout: pegout_2.id,
                candidates: vec![MULTISIG].into(),
            },
            AuxEvent::InitiatedPegout {
                pegout: pegout_3.id,
                candidates: vec![MULTISIG].into(),
            },
            AuxEvent::NewBitcoinHeader {
                block_hash: B.block_hash()
            },
            AuxEvent::SubmittedProposal {
                proposal: proposal.clone()
            },
            AuxEvent::RegisterBitcoinTx {
                block_hash: B.block_hash().into(),
                txid: transaction.compute_txid(),
                pegouts: vec![pegout_1.id, pegout_2.id].into()
            }
        ]
    );

    // FINALIZE: Finalize the valid state transition.
    let expected_root = foundation_proof.compute_root();
    let final_foundation_proof = f
        .finalize_commitments::<_, ()>(expected_root, |c| {
            // Initite pegouts
            c.insert_unassigned(pegout_1.clone(), vec![MULTISIG])?;
            c.insert_unassigned(pegout_2.clone(), vec![MULTISIG])?;
            c.insert_unassigned(pegout_3.clone(), vec![MULTISIG])?;

            // Insert block B.
            c.insert_bitcoin_header(B, 201)?;

            // Submit the proposal first.
            c.insert_pegout_proposal(proposal.clone(), None)?;

            // Register transaction for block B, using pegouts(1&2).
            c.insert_bitcoin_tx(B.block_hash(), transaction.clone(), tx_proof, proposal)?;

            Ok(())
        })
        .unwrap();

    assert_eq!(foundation_proof, final_foundation_proof);
}
