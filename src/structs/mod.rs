//! # Data Structures Module
//!
//! The `structs` module provides core data structures and algorithms for
//! cryptographic operations in the Botanix ecosystem. This module implements
//! various tree structures and algorithms used for generating and verifying
//! cryptographic proofs across different blockchain systems.
//!
//! ## Overview
//!
//! This module contains fundamental data structures that support:
//!
//! - **Merkle Tree Operations**: Simple binary Merkle trees following CometBFT
//!   specification for consensus-layer proofs
//! - **Merkle Patricia Trees**: Ethereum-compatible tries for execution-layer
//!   transaction and receipt proofs
//! - **Block Organization**: Tree structures for tracking Bitcoin block
//!   relationships and handling reorganizations
//!
//! ## Architecture
//!
//! The structures are designed to be deterministic and stateless, making them
//! suitable for use in Trusted Execution Environments (TEE) where reproducible
//! computation is essential. All implementations prioritize security and
//! correctness over performance optimizations.

pub mod block_tree;
pub mod merkle_patricia;
pub mod merkle_simple;
