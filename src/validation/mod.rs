//! # Validation Module
//!
//! The `validation` module provides cryptographic verification and validation
//! capabilities for multi-chain blockchain operations in the Botanix ecosystem.
//! This module ensures the integrity and authenticity of data across Bitcoin,
//! Botanix (Ethereum-compatible), and Tendermint/CometBFT consensus layers.
//!
//! ## Overview
//!
//! This module implements a comprehensive validation framework that handles:
//!
//! - **Cross-chain verification**: Validates data consistency between Bitcoin,
//!   Botanix, and Tendermint chains
//! - **Cryptographic proof verification**: Verifies Merkle proofs, digital
//!   signatures, and consensus mechanisms
//! - **State transition validation**: Ensures valid blockchain state
//!   transitions and prevents invalid operations
//! - **Pegout operation security**: Validates Bitcoin withdrawal operations
//!   with multiple layers of verification
//!
//! ## Architecture
//!
//! The validation system operates on a trust-but-verify model where each
//! component validates data from external sources using cryptographic proofs
//! rather than relying on trust assumptions. This approach is essential for the
//! Trusted Execution Environment (TEE) implementation where the system must
//! operate without network access or persistent storage.
//!
//! <img src="data:image/png;base64,
#![doc = include_str!("../../docs/assets/validation_overview_base64.txt")]
//! " alt="Validation Workflow Diagram" style="max-width: 90%; width: 800px; height: auto; display: block; margin: 0 auto;">

pub mod bitcoin;
pub mod botanix;
pub mod pegout;
pub mod tendermint;
