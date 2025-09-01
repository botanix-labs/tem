use crate::foundation::commitment::storage::{
    AtomicError, InMemoryCommitments, NeverError as CommitmentLayerError,
};
use crate::foundation::proof::AuxEvent;
use crate::foundation::proof::tests::gen_foundation_state_root;
use crate::foundation::{BackendError, DataLayer, Error, Foundation, MULTISIG, ValidationError};
use crate::tests::{gen_bitcoin_hash, gen_bitcoin_tx_from_pegouts, gen_pegout_with_id};
use crate::validation::pegout::{PegoutData, PegoutId, PegoutWithId};
use bitcoin::{BlockHash, Txid};
use std::collections::HashMap;

#[derive(Debug, Default)]
struct InMemoryData {
    bitcoin_headers: HashMap<BlockHash, bitcoin::block::Header>,
    pegouts_by_id: HashMap<PegoutId, PegoutData>,
    pegouts_by_txid: HashMap<Txid, Vec<PegoutWithId>>,
    txids_by_hash: HashMap<BlockHash, Vec<Txid>>,
}

impl InMemoryData {
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DataLayerError;

impl DataLayer for InMemoryData {
    type Error = DataLayerError;

    fn get_bitcoin_header(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<bitcoin::block::Header>, Self::Error> {
        Ok(self.bitcoin_headers.get(block_hash).cloned())
    }
    fn get_pegout_by_id(&self, id: &PegoutId) -> Result<Option<PegoutData>, Self::Error> {
        Ok(self.pegouts_by_id.get(id).cloned())
    }
    fn get_txids_by_block_hash(&self, hash: &BlockHash) -> Result<Vec<Txid>, Self::Error> {
        Ok(self.txids_by_hash.get(hash).cloned().unwrap_or_default())
    }
    fn get_pegouts_by_txid(&self, txid: &Txid) -> Result<Vec<PegoutWithId>, Self::Error> {
        Ok(self.pegouts_by_txid.get(txid).cloned().unwrap_or_default())
    }
}

impl From<DataLayerError> for Error<DataLayerError, CommitmentLayerError> {
    fn from(value: DataLayerError) -> Self {
        BackendError::DataLayerError(value).into()
    }
}

impl From<AtomicError<CommitmentLayerError>> for Error<DataLayerError, CommitmentLayerError> {
    fn from(value: AtomicError<CommitmentLayerError>) -> Self {
        BackendError::AtomicLayerError(value).into()
    }
}

#[test]
fn foundation_basic_atomic_properties() {
    let data = InMemoryData::new();
    let commitment = InMemoryCommitments::new();

    let A = gen_bitcoin_hash();
    let B = gen_bitcoin_hash();
    let C = gen_bitcoin_hash();

    // FOUNDATION: Setup.
    let mut f = Foundation::new(data, commitment, A, 0).unwrap();
    let origin_root = f.commitment_root().unwrap();

    // PROPOSE: Construct an invalid state transition.
    let res_err = f
        .propose_commitments(|c| {
            // INVALID: block_hash: `B`, parent_hash: `C`
            c.insert_bitcoin_header_unchecked(B, C)?;
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
            // INVALID: block_hash: `B`, parent_hash: `C`
            c.insert_bitcoin_header_unchecked(B, C)?;
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
    let data = InMemoryData::new();
    let commitment = InMemoryCommitments::new();

    let A = gen_bitcoin_hash();
    let B = gen_bitcoin_hash();

    // FOUNDATION: Setup.
    let mut f = Foundation::new(data, commitment, A, 0).unwrap();
    let origin_root = f.commitment_root().unwrap();

    // PROPOSE: Construct a valid state transition.
    let proof = f
        .propose_commitments(|c| {
            // block_hash: `B`, parent_hash: `A`
            c.insert_bitcoin_header_unchecked(B, A)?;

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
            // block_hash: `B`, parent_hash: `A`
            c.insert_bitcoin_header_unchecked(B, A)?;
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
    let data = InMemoryData::new();
    let commitment = InMemoryCommitments::new();

    let A = gen_bitcoin_hash();
    let B = gen_bitcoin_hash();
    let C = gen_bitcoin_hash();

    // FOUNDATION: Setup.
    let mut f = Foundation::new(data, commitment, A, 0).unwrap();
    let origin_root = f.commitment_root().unwrap();

    // PROPOSE: Construct a valid state transition.
    let proof = f
        .propose_commitments(|c| {
            // block_hash: `B`, parent_hash: `A`
            c.insert_bitcoin_header_unchecked(B, A)?;

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
            // NOTE: The proprosal uses block hash B, but here we use block hash C.
            //
            // block_hash: `C`, parent_hash: `A`
            c.insert_bitcoin_header_unchecked(C, A)?;
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
    let mut data = InMemoryData::new();
    let commitment = InMemoryCommitments::new();

    let A = gen_bitcoin_hash();
    let (B, B_PREV) = (gen_bitcoin_hash(), A);
    let (C, C_PREV) = (gen_bitcoin_hash(), B);

    let pegout_1 = gen_pegout_with_id();
    let pegout_2 = gen_pegout_with_id();
    let pegout_3 = gen_pegout_with_id();

    let transaction = gen_bitcoin_tx_from_pegouts(&[&pegout_1.data, &pegout_2.data]);

    // Prefill data layer with pegouts.
    data.pegouts_by_id
        .insert(pegout_1.id, pegout_1.data.clone());
    data.pegouts_by_id
        .insert(pegout_2.id, pegout_2.data.clone());
    data.pegouts_by_id
        .insert(pegout_3.id, pegout_3.data.clone());

    // FOUNDATION: Setup.
    let mut f = Foundation::new(data, commitment, A, 0).unwrap();

    // PROPOSE: Construct a valid state transition.
    let proof = f
        .propose_commitments::<_, ()>(|c| {
            // Initite pegouts
            c.initiate_pegout(MULTISIG, pegout_1.clone())?;
            c.initiate_pegout(MULTISIG, pegout_2.clone())?;
            c.initiate_pegout(MULTISIG, pegout_3.clone())?;

            // Insert blocks B and C in one go (sequentially!).
            c.insert_bitcoin_header_unchecked(B, B_PREV)?;
            c.insert_bitcoin_header_unchecked(C, C_PREV)?;

            // Register transaction for block B, using pegouts(1&2).
            c.register_bitcoin_tx_unchecked(
                B,
                transaction.clone(),
                vec![pegout_1.id, pegout_2.id],
            )?;

            Ok(())
        })
        .unwrap();

    // Validate auxiliary events.
    assert_eq!(
        proof.state().aux_events,
        vec![
            AuxEvent::InitiatedPegout {
                multisig: MULTISIG,
                pegout: pegout_1.id,
            },
            AuxEvent::InitiatedPegout {
                multisig: MULTISIG,
                pegout: pegout_2.id,
            },
            AuxEvent::InitiatedPegout {
                multisig: MULTISIG,
                pegout: pegout_3.id,
            },
            AuxEvent::NewBitcoinHeader { block_hash: B },
            AuxEvent::NewBitcoinHeader { block_hash: C },
            AuxEvent::FinalizedBitcoinHeader {
                block_hash: A,
                // No pegouts finalized.
                finalized: vec![].into()
            },
            AuxEvent::RegisterBitcoinTx {
                block_hash: B.into(),
                txid: transaction.compute_txid(),
                pegouts: vec![pegout_1.id, pegout_2.id].into()
            }
        ]
    );

    // FINALIZE: Finalize the valid state transition.
    let expected_root = proof.compute_root();
    let final_proof = f
        .finalize_commitments::<_, ()>(expected_root, |c| {
            // Initite pegouts
            c.initiate_pegout(MULTISIG, pegout_1.clone())?;
            c.initiate_pegout(MULTISIG, pegout_2.clone())?;
            c.initiate_pegout(MULTISIG, pegout_3.clone())?;

            // Insert blocks B and C in one go (sequentially!).
            c.insert_bitcoin_header_unchecked(B, B_PREV)?;
            c.insert_bitcoin_header_unchecked(C, C_PREV)?;

            // Register transaction for block B, using pegouts(1&2).
            c.register_bitcoin_tx_unchecked(B, transaction.clone(), vec![pegout_1.id, pegout_2.id])
                .unwrap();

            Ok(())
        })
        .unwrap();

    assert_eq!(proof, final_proof);
}
