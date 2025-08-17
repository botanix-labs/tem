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
//! ### [`foundation`] *(Work in Progress)*
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

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
