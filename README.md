_(This document has been revised with Claude.AI)_

# Introduction

This document describes the core architectural components that Botanix requires to achieve secure, decentralized Bitcoin withdrawals (pegouts). The rationale and technical foundation for this work was established in our [initial Proof-of-concept specification](./docs/initial_spec.md).

This project encompasses two interconnected but distinct components: the **Trusted Execution Machine (TEM)** and the **Foundation Layer**.

<div align="center">
<img src="docs/assets/tem_overview.png" alt="Trusted Execution Machine" width="100%">
</div>

## Foundation Layer

The Foundation Layer manages the complex validator coordination logic that underpins Botanix's multisig system and serves as the foundation for the eventual dynamic federation (DynaFed) implementation. It processes input from the Botanix chain through a Non-Deterministic Data (NDD) messaging system and maintains deterministic state management for all validator operations.

Key responsibilities include:

- **Validator Set Management**: Handling validator rotations and multisig membership changes
- **State Commitment Proofs**: Enforcing validator participation through cryptographic commitments
- **Equivocation Detection**: Providing the infrastructure for detecting and penalizing malicious validator behavior
- **Deterministic State Transitions**: Ensuring all validators maintain consistent views of system state, which is critical for implementing penalties and equivocation handling

The TEM depends on the Foundation Layer for validator state information, while the Foundation Layer operates independently. This unidirectional dependency ensures that the Foundation Layer can function as a standalone validator coordination system while providing the necessary infrastructure for TEM operations.

=> **More indepth writeup on the [Foundation Layer](docs/foundation.md)**

## Trusted Execution Machine (TEM)

The TEM operates as an isolated, networkless environment without persistent storage, responsible for cryptographically validating and authorizing pegout requests from Botanix users. It treats all input as potentially malicious and validates every piece of data through cryptographic proofs before taking any action.

While the TEM can independently validate the cryptographic legitimacy of individual pegout requests, it depends on the Foundation Layer to understand the broader multisig context. Specifically, the TEM requires knowledge of which multisig setup each pegout should be assigned to, which pegouts have already been processed, and which remain pending. This dependency is essential for preventing double-spend attacks, as the TEM must maintain accurate state about pegout lifecycle management across the distributed multisig system.

The TEM's primary security benefits include:

- **Key Protection**: Botanix validators can deploy the TEM within a Trusted Execution Environment (TEE), ensuring that multisig keys remain secure even if the main Reth node is compromised
- **Sequential Validation**: The pegout validation process operates deterministically with fewer moving parts, making the system significantly easier to test, audit, and reason about
- **Cryptographic Verification**: All trust assumptions are eliminated through comprehensive proof verification

=> **More indepth writeup on the [Trusted Execution Machine (TEM)](docs/tem.md)**

# Building

This repository is primarily intended to be used as a library. Further structural changes - including a TEM binary - to follow.

To generate the documentation for `botanix_tem`:

```
cargo doc --document-private-items
```

# Roadmap

Temporary roadmap while this repository remains primarily work-in-progress. This section will be removed later on.

## Foundation Module (`src/foundation/`)

- [x] **Commitment System** (`src/foundation/commitment/`) - Cryptographic state commitment using `trie-db`
  - [x] Entry system with domain-separated keys (`entry.rs`)
  - [x] Sorted data structures for deterministic operations (`sorted.rs`)
  - [x] Low-level trie operations with consistency guarantees (`trie.rs`)
  - [x] Higher-level Botanix state management (`botanix.rs`)
  - [x] Atomic storage operations with transaction semantics (`storage.rs`)
  - [x] Custom node codec for trie encoding/decoding (_forked_) (`node_codec.rs`)
- [x] **Proof System** (`src/foundation/proof.rs`) - Cryptographic state proofs for consensus
  - [x] Foundation state root computation
  - [x] Auxiliary event tracking for efficient lookups
  - [x] State reconstruction capabilities
- [x] **Core Foundation API** (`src/foundation/mod.rs`) - Main interface
  - [x] Two-phase operation model (propose/finalize)
  - [x] Pegout lifecycle management (initiated -> pending -> delayed/finalized)
  - [x] Bitcoin block tree coordination with automatic pruning
  - [x] Deterministic state transitions for consensus
- [ ] Testing
  - [x] Basic unit tests
  - [ ] Comprehensive tests

## TEM Module (`src/tem/`)

- [ ] **Core Implementation**
  - [x] Input validation workflow
  - [ ] Pegout set tracking (_requires Foundation module_)
  - [ ] Frost package signing implementation
  - [ ] gRPC interface
- [x] **Validation Framework**
  - [x] Tendermint chain validation setup
  - [x] Botanix header validation against Tendermint
  - [x] Pegout validation with Merkle proofs
- [ ] Testing
  - [ ] Basic unit tests
  - [ ] Comprehensive tests

## Validation Module (`src/validation/`)

### Bitcoin Validation (`bitcoin.rs`)
- [x] **CheckedBitcoinHeader**
  - [x] Proof-of-work validation with hardcoded difficulty target
  - [x] Block hash computation and verification
  - [x] Minimum difficulty enforcement (based on block 840,000)
- [x] **CheckedBitcoinTransaction**
  - [x] Transaction inclusion proof verification
  - [x] Partial Merkle tree proof validation
  - [x] TXID matching in proof validation
- [x] **Transaction Proof Verification**
  - [x] `verify_transaction_proof` function
  - [x] Merkle root validation
  - [x] TXID inclusion verification
- [ ] Testing
  - [ ] Basic unit tests
  - [ ] Comprehensive tests

### Tendermint Validation (`tendermint.rs`)
- [x] **CheckedTendermintHeader**
  - [x] Individual header validation wrapper
- [x] **CheckedTendermintChain**
  - [x] Genesis validator set bootstrapping
  - [x] Chain continuity validation (parent references)
  - [x] Sequential height increment validation
  - [x] Validator signature verification (≥2/3 voting power)
  - [x] Validator set transition handling
  - [ ] Bitcoin-anchored chain initialization
- [x] **Commit Validation**
  - [x] Commit structure validation
  - [x] Signature cryptographic verification
  - [x] Voting power threshold enforcement
- [ ] Testing
  - [x] Basic unit tests
  - [ ] Comprehensive tests

### Botanix Validation (`botanix.rs`)
- [x] **CheckedBotanixHeader**
  - [x] Cross-chain validation against Tendermint app_hash
  - [x] Header hash computation
  - [x] App hash mismatch error handling
- [x] **Transaction Root Operations**
  - [x] `compute_transactions_root` - Merkle Patricia tree root computation
  - [x] `compute_transaction_proof` - proof generation
  - [x] `verify_transaction_proof` - proof verification
- [x] **Receipt Root Operations**
  - [x] `compute_receipts_root` - Merkle Patricia tree root computation
  - [x] `compute_receipt_proof` - proof generation
  - [x] `verify_receipt_proof` - proof verification
- [ ] Testing
  - [x] Basic unit tests
  - [ ] Comprehensive tests

### Pegout Validation (`pegout.rs`)
- [x] **CheckedPegoutWithId**
  - [x] Multi-layer proof verification (transaction + receipt)
  - [x] Position consistency validation (matching nibbles)
  - [x] Log index bounds checking
  - [x] Tenderming proof validation (`appHash`)
- [x] **Pegout Data Structures**
  - [x] `PegoutWithId` - pegout with unique identifier
  - [x] `PegoutId` - transaction hash + log index identifier
  - [x] `PegoutData` - amount, destination, network
- [x] **Event Log Processing**
  - [x] `extract_pegout_data` function
  - [x] Pegout validation logic
- [ ] Testing
  - [x] Basic unit tests
  - [ ] Comprehensive tests

## Primitives Module (`src/primitives/`)

### Core Data Types (`mod.rs`)
- [x] **BotanixHeader**
  - [x] Complete header structure
  - [x] Hash computation (`hash_slow`)
- [x] **Transaction Types**
  - [x] `TxType` enum
  - [x] `TransactionSigned` structure
  - [ ] `Transaction` structure
  - [ ] `TransactionSigned::hash_slow` implementation
- [x] **Receipt Types**
  - [x] `Receipt`
  - [x] `ReceiptWithBloom`

## Structs Module (`src/structs/`)

### Merkle Patricia Tree (`merkle_patricia.rs`)
- [x] **Core Operations**
  - [x] `compute_root` - trie root computation
  - [x] `compute_proof` - inclusion proof generation
  - [x] `verify_proof` - inclusion proof verification
  - [x] `MerklePatriciaProof` with nibbles and nodes

### Simple Merkle Tree (`merkle_simple.rs`)
- [x] **Core Operations**
  - [x] `compute_root` - CometBFT-compatible Merkle root
  - [x] `compute_proof` - inclusion proof generation
  - [x] `verify_proof` - inclusion proof verification
- [x] **Security Features**
  - [x] Prefix-based hashing (0x00 for leaves, 0x01 for inner nodes)
  - [x] Protection against second pre-image attacks
  - [x] Deterministic tree construction
- [x] **Proof Structure**
  - [x] `MerkleProof` with total leaves, leaf index, and aunt hashes
  - [x] Aunt hash collection in correct order
- [ ] Testing
  - [x] Basic unit tests
  - [ ] Comprehensive tests

### Block Tree (`block_tree.rs`)
- [x] **Core Structure**
  - [x] `BlockTree` with tips, elder, blocks map, best height tracking
  - [x] Confirmation depth configuration
  - [x] Fork handling and resolution
- [x] **Block Management**
  - [x] Block insertion with parent-child relationships
  - [x] Automatic pruning based on confirmation depth
  - [x] Elder (oldest retained block) tracking
- [x] **Pruning Strategy**
  - [x] Forward pruning for finalized blocks
  - [x] Backward pruning for orphaned forks
  - [x] `BlockFate` classification (Finalized vs Orphaned)
- [ ] Testing
  - [x] Basic unit tests
  - [ ] Comprehensive tests
