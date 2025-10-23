//! # Botanix Trusted Execution Environment (TEE) Library
//!
//! This library provides the core validation and execution framework for the
//! Botanix Trusted Execution Environment, enabling secure cross-chain Bitcoin
//! withdrawal (pegout) operations. The library implements cryptographic
//! validation across multiple blockchain systems while operating under TEE
//! constraints of no network access and no persistent storage.
//!
//! ## Overview
//!
//! The Botanix TEE system validates and processes Bitcoin withdrawals by:
//!
//! - **Multi-Chain Validation**: Cryptographically verifies data across
//!   Bitcoin, Botanix (Ethereum-compatible), and Tendermint/CometBFT consensus
//!   layers
//! - **Pegout Security**: Ensures withdrawal requests are legitimate and
//!   prevents double-spending through comprehensive proof verification
//! - **Stateless Operation**: Reconstructs all necessary state from
//!   cryptographic proofs rather than relying on persistent storage
//! - **Deterministic Execution**: Produces identical results for identical
//!   inputs, essential for consensus in distributed TEE deployments
//!
//! ## Architecture
//!
//! The library is organized into several key modules:
//!
//! ### [`validation`]
//! Provides cryptographic verification capabilities for multi-chain blockchain
//! operations. Implements comprehensive validation for Bitcoin proof-of-work,
//! Tendermint BFT consensus, Botanix execution data, and pegout operations. All
//! validation operates on a trust-but-verify model using cryptographic proofs.
//!
//! ### [`primitives`]
//! Defines core data types and structures used throughout the system, including
//! blockchain headers, transactions, receipts, and encoding/decoding utilities.
//! Provides the fundamental building blocks for representing multi-chain data.
//!
//! ### [`structs`]
//! Implements essential data structures and algorithms for cryptographic
//! operations, including Merkle trees (CometBFT-compatible), Merkle Patricia
//! trees (Ethereum-compatible), and Bitcoin block organization structures for
//! handling reorganizations.
//!
//! ### [`foundation`]
//! Provides the foundational layer for state management and commitment
//! operations within the federated multisig system and the TEE environment.
//! Handles the core execution logic for processing blockchain data and
//! maintaining cryptographic state commitments.
//!
//! ### [`tem`] *(Work in Progress)*
//! Implements the Trusted Execution Machine (TEM) interface, providing the main
//! entry points for TEE operations and Frost signing requests.
//!
//! ## TEE Design Principles
//!
//! This library is specifically designed for Trusted Execution Environment
//! deployment:
//!
//! - **Networkless**: All operations are performed on provided data without
//!   external network access
//! - **Stateless**: No persistent storage is required; all state is
//!   reconstructed from proofs
//! - **Deterministic**: Identical inputs always produce identical outputs
//! - **Single-threaded**: Sequential execution model suitable for secure
//!   enclaves
//! - **Cryptographically Verified**: All trust is based on cryptographic proofs
//!   rather than external sources
//!
//! ## Security Model
//!
//! The library implements multiple layers of security:
//!
//! 1. **Cryptographic Validation**: All blockchain data is verified using
//!    cryptographic proofs
//! 2. **Multi-Chain Consistency**: Cross-chain data consistency is enforced
//!    through proof verification
//! 3. **Pegout Authorization**: Withdrawal operations require valid proofs of
//!    authorization
//! 4. **Double-Spend Prevention**: Each pegout can only be processed once
//!    through cryptographic tracking
//! 5. **Consensus Verification**: Respects each blockchain's consensus
//!    mechanism (PoW, BFT)

pub mod foundation;
pub mod primitives;
pub mod structs;
pub mod tem;
pub mod validation;

// TODO: Hide behind feature/cfg guard?
pub mod test_utils {
    use crate::{
        foundation::proof::FoundationStateRoot,
        validation::pegout::{PegoutData, PegoutId, PegoutWithId},
    };
    use alloy_primitives::TxHash;
    use bitcoin::{
        BlockHash, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, WPubkeyHash, Witness,
    };
    use rand::Rng;

    // Re-export
    pub use crate::foundation::proof::test_utils::gen_foundation_state_root;

    pub fn gen_bitcoin_tx_from_pegouts(pegouts: &[&PegoutData]) -> bitcoin::Transaction {
        let mut input = vec![];
        for _ in 0..rand::rng().random_range(1..5) {
            // Mimicking a P2WPKH input; first item is the signature+sighash, second
            // item is the compressed public key.
            let witness: [Vec<u8>; 2] = [
                rand::rng().random::<[u8; 71]>().to_vec(),
                rand::rng().random::<[u8; 33]>().to_vec(),
            ];

            let txin = TxIn {
                previous_output: gen_bitcoin_utxo(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&witness),
            };

            input.push(txin);
        }

        let mut output = vec![];
        for pegout in pegouts {
            let txout = TxOut {
                value: pegout.amount,
                script_pubkey: pegout.destination.script_pubkey(),
            };

            output.push(txout);
        }

        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input,
            output,
        }
    }

    pub fn gen_bitcoin_hash() -> BlockHash {
        use bitcoin::hashes::sha256d::Hash;

        let r = rand::rng().random::<[u8; 32]>();
        let h = Hash::from_bytes_ref(&r);
        BlockHash::from_raw_hash(*h)
    }

    pub fn gen_bitcoin_txid() -> Txid {
        use bitcoin::hashes::sha256d::Hash;

        let r = rand::rng().random::<[u8; 32]>();
        let h = Hash::from_bytes_ref(&r);
        Txid::from_raw_hash(*h)
    }

    pub fn gen_bitcoin_utxo() -> OutPoint {
        OutPoint {
            txid: gen_bitcoin_txid(),
            vout: rand::rng().random::<u32>(),
        }
    }

    pub fn gen_botanix_hash() -> TxHash {
        let r = rand::rng().random::<[u8; 32]>();
        TxHash::from_slice(&r)
    }

    pub fn gen_pegout_with_id() -> PegoutWithId {
        PegoutWithId {
            id: gen_pegout_id(),
            data: gen_pegout_data(),
        }
    }

    pub fn gen_pegout_id() -> PegoutId {
        let tx_hash = rand::rng().random::<[u8; 32]>();
        let log_idx = rand::rng().random_range::<u32, _>(0..4_000);

        PegoutId { tx_hash, log_idx }
    }

    pub fn gen_pegout_data() -> PegoutData {
        use bitcoin::hashes::hash160::Hash;

        let sats = rand::rng().random_range::<u64, _>(10_000..100_000_000);

        let r = rand::rng().random::<[u8; 20]>();
        let &h = Hash::from_bytes_ref(&r);
        let wpub = WPubkeyHash::from_raw_hash(h);
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpub);

        PegoutData {
            amount: bitcoin::Amount::from_sat(sats),
            destination: bitcoin::Address::from_script(&script_pubkey, bitcoin::Network::Bitcoin)
                .unwrap(),
            network: bitcoin::Network::Bitcoin,
        }
    }
}
