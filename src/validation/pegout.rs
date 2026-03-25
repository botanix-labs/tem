//! # Pegout Validation Module
//!
//! This module provides comprehensive validation for Bitcoin withdrawal
//! (pegout) operations, ensuring that pegout requests are legitimate and
//! extracting validated pegout data from Ethereum event logs. It combines
//! multiple proof systems to provide end-to-end validation of cross-chain
//! withdrawals.
//!
//! ## Key Features
//!
//! - **Multi-Layer Proof Verification**: Validates both transaction and receipt
//!   inclusion proofs to ensure consistency
//! - **Event Log Parsing**: Extracts and validates pegout data from Ethereum
//!   Burn event logs emitted by the mint contract
//! - **Amount and Destination Validation**: Verifies withdrawal amounts and
//!   Bitcoin destination addresses for correctness
//! - **Position Consistency**: Ensures transaction and receipt proofs reference
//!   the same tree position to prevent manipulation
//!
//! ## Validation Process
//!
//! Pegout validation involves multiple steps:
//! 1. **Proof Consistency**: Transaction and receipt proofs must reference the
//!    same position
//! 2. **Cryptographic Verification**: Both proofs must be valid against their
//!    respective tree roots
//! 3. **Log Extraction**: Pegout data is extracted from the specified log index
//! 4. **Data Validation**: Amount, destination, and metadata are validated for
//!    correctness
//!
//! ## Security Considerations
//!
//! The module implements strict validation to prevent:
//! - **Double-spending**: Each pegout can only be processed once
//! - **Amount manipulation**: Withdrawal amounts must match log data exactly
//! - **Address validation**: Bitcoin addresses must be valid for the specified
//!   network
//! - **Contract verification**: Only logs from the authorized mint contract are
//!   accepted
//!
//! ## Main Types
//!
//! - [`CheckedPegoutWithId`]: A fully validated pegout with cryptographic proofs
//! - [`PegoutData`]: The core pegout information (amount, destination, network)
//! - [`PegoutId`]: Unique identifier combining transaction hash and log index
use super::botanix::CheckedBotanixHeader;
use crate::{
    primitives::{Receipt, TransactionSigned},
    structs::merkle_patricia::{self, MerklePatriciaProof},
    validation::botanix::{verify_receipt_proof, verify_transaction_proof},
};
use alloy_primitives::{Address, B256, Log, U256, keccak256};
use alloy_sol_types::{SolType, sol_data};
use alloy_trie::Nibbles;
use bitcoin::ScriptBuf;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

lazy_static::lazy_static! {
    /// Hash of the mint topic as it appears in the log
    static ref MINT_TOPIC: B256 = keccak256("Mint(address,uint256,uint32,bytes)");
    /// Hash of the burn topic as it appears in the log
    static ref BURN_TOPIC: B256 = keccak256("Burn(address,uint256,bytes,bytes)");
    /// Address of the mint contract
    static ref MINT_CONTRACT_ADDRESS: Address = Address::from_str("0x0Ea320990B44236A0cEd0ecC0Fd2b2df33071e78")
        .expect("mint contract address must be valid");
}

/// One satoshi expressed in wei (10^10)
const SATOSHI_IN_WEI: U256 = U256::from_limbs([10_000_000_000_u64, 0, 0, 0]);

/// The maximum bitcoin amount satoshi value
const MAX_SATOSHI: U256 = U256::from_limbs([u64::MAX, 0, 0, 0]);

/// Errors that can occur during pegout validation and extraction.
///
/// These errors represent various validation failures that can happen when
/// verifying pegout transactions and extracting pegout data from logs.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Transaction and receipt proofs reference different positions in their
    /// trees The nibbles (position identifiers) for the transaction and receipt
    /// proofs must be equal.
    NonMatchingNibbles { tx: Nibbles, receipt: Nibbles },
    /// The specified log index is out of bounds for the receipt.
    ///
    /// This occurs when trying to access a log at an index that doesn't exist
    /// in the transaction receipt.
    InvalidReceiptLogIdx { log_idx: usize, log_count: usize },
    /// The transaction proof failed validation against the transactions root.
    BadTransactionProof(merkle_patricia::Error),
    /// The receipt proof failed validation against the receipts root.
    BadReceiptProof(merkle_patricia::Error),
    /// Error occurred while extracting or validating pegout data from the log.
    PegoutError(PegoutError),
}

impl From<PegoutError> for Error {
    fn from(value: PegoutError) -> Self {
        Error::PegoutError(value)
    }
}

/// Errors specific to pegout data extraction and validation.
///
/// These errors occur when parsing Burn event logs from the mint contract and
/// validating the extracted pegout information.
#[derive(Debug)]
#[non_exhaustive]
pub enum PegoutError {
    /// The log is not from the expected mint contract address.
    BadMintContract,
    /// The log contains no topics.
    EmptyTopics,
    /// The first topic is not the expected Burn event signature.
    BadBurnTopic,
    /// The log has an unexpected number of topics for a Burn event.
    BadTopicLength,
    /// Failed to decode the ABI-encoded data in the log.
    BadAbiSequence,
    /// The pegout amount exceeds the maximum allowed satoshi value.
    MaxSatoshiExceeded,
    /// The metadata has an unexpected length.
    BadMetadataLength,
    /// The metadata version is not supported by this implementation.
    BadMetadataVersion,
    /// The destination address is invalid or not compatible with the specified
    /// network.
    BadBitcoinDestination,
}

/// A validated pegout transaction with cryptographic proof verification.
///
/// This wrapper ensures that pegout data has been extracted from a verified
/// transaction and receipt that are provably included in a verified Botanix
/// block. The inner pegout data is kept private to prevent direct modification.
pub struct CheckedPegoutWithId {
    /* PRIVATE */ _pegout: PegoutWithId,
}

impl AsRef<PegoutWithId> for CheckedPegoutWithId {
    fn as_ref(&self) -> &PegoutWithId {
        &self._pegout
    }
}

impl CheckedPegoutWithId {
    /// Creates a new validated pegout by verifying transaction and receipt
    /// proofs.
    ///
    /// This method performs comprehensive validation to ensure:
    /// - The transaction and receipt are at the same position in their
    ///   respective trees
    /// - Both the transaction and receipt are cryptographically proven to be in
    ///   the block
    /// - The specified log index exists and contains valid pegout data
    /// - The pegout data conforms to the expected format and network
    ///
    /// # Arguments
    ///
    /// * `untrusted_tx` - The transaction containing the pegout
    /// * `proof_tx` - Merkle Patricia proof for the transaction's inclusion
    /// * `untrusted_receipt` - The receipt containing the pegout log
    /// * `proof_receipt` - Merkle Patricia proof for the receipt's inclusion
    /// * `log_idx` - Index of the pegout log within the receipt
    /// * `network` - Bitcoin network the pegout should be performed on
    /// * `checked` - Validated Botanix header containing the merkle roots
    ///
    /// # Returns
    ///
    /// A new `CheckedPegoutWithId` containing validated pegout data,
    /// or an error describing why validation failed.
    ///
    /// # Errors
    ///
    /// - `NonMatchingNibbles` if transaction and receipt proofs don't match positions
    /// - `InvalidReceiptLogIdx` if the log index is out of bounds
    /// - `BadTransactionProof` or `BadReceiptProof` for cryptographic validation failures
    /// - `PegoutError` variants for pegout data extraction or validation failures
    pub fn new(
        // TODO: Maybe just pass on `Transaction` directly?
        untrusted_tx: TransactionSigned,
        untrusted_receipt: Receipt,
        proof_tx: MerklePatriciaProof,
        proof_receipt: MerklePatriciaProof,
        log_idx: usize,
        // TODO: This should probably not be here.
        network: bitcoin::Network,
        checked: &CheckedBotanixHeader,
    ) -> Result<Self, Error> {
        // VALIDATE: The position of the transaction corresponds to the position
        // of the receipt.
        //
        // TODO: Add note why this is important, and why we ALWAYS check the
        // transaction and receipt together.
        if proof_tx.nibbles != proof_receipt.nibbles {
            return Err(Error::NonMatchingNibbles {
                tx: proof_tx.nibbles,
                receipt: proof_receipt.nibbles,
            });
        }

        // VALIDATE: The log index must be valid.
        if log_idx >= untrusted_receipt.logs.len() {
            return Err(Error::InvalidReceiptLogIdx {
                log_idx,
                log_count: untrusted_receipt.logs.len(),
            });
        }

        let txs_root = checked.as_ref().transactions_root;
        let receipts_root = checked.as_ref().receipts_root;

        // VALIDATE: The transaction proof can be validated against the transactions root.
        verify_transaction_proof(&untrusted_tx, &proof_tx, &txs_root)
            .map_err(Error::BadTransactionProof)?;

        // VALIDATE: The receipt proof can be validated against the receipts root.
        // TODO: Avoid cloning?
        verify_receipt_proof(untrusted_receipt.clone(), &proof_receipt, &receipts_root)
            .map_err(Error::BadReceiptProof)?;

        let trusted_tx = untrusted_tx;
        let trusted_receipt = untrusted_receipt;

        // Construct appropriate PegoutId.
        let id = PegoutId {
            tx_hash: trusted_tx.hash_slow().into(),
            // NOTE: this log index is implicitly (in-)validated depending on
            // whether the upcoming pegout extraction mechanism succeeds.
            log_idx: log_idx as u32,
        };

        // Extract pegout data.
        let log = trusted_receipt
            .logs
            .get(log_idx)
            .expect("log index must be validated");

        let data = extract_pegout_data(log, network)?;

        Ok(CheckedPegoutWithId {
            _pegout: PegoutWithId { id, data },
        })
    }
}

/// A pegout transaction with its unique identifier.
///
/// Contains both the identifying information and the actual pegout data.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PegoutWithId {
    pub id: PegoutId,
    pub data: PegoutData,
}

/// Unique identifier for a pegout transaction.
///
/// Combines the transaction hash with the log index to create a globally unique
/// identifier for each pegout.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PegoutId {
    /// Hash of the transaction containing the pegout.
    // TODO: Newtype?
    pub tx_hash: [u8; 32],
    /// Index of the pegout log within the transaction's receipt.
    pub log_idx: u32,
}

/// Complete pegout operation data.
///
/// Contains all the information needed to perform a Bitcoin pegout.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
// TODO: Note the custom serde impl
pub struct PegoutData {
    /// Amount to be pegged out from Botanix to Bitcoin.
    pub amount: bitcoin::Amount,
    /// Bitcoin address where the funds should be sent.
    pub destination: bitcoin::Address,
    /// Bitcoin network the pegout should be performed on.
    pub network: bitcoin::Network,
}

impl PegoutData {
    /// current version of the pegout data structure
    pub const fn version() -> u8 {
        0
    }
}

/// Extracts and validates pegout data from a transaction log.
///
/// Parses a Burn event log from the mint contract to extract pegout
/// information, including the amount, destination address, and metadata.
/// Performs validation to ensure the log format is correct and the data is
/// valid for the specified network.
///
/// # Arguments
///
/// * `log` - The transaction log containing the Burn event
/// * `btc_network` - Bitcoin network to validate the destination address against
///
/// # Returns
///
/// Validated `PegoutData` containing the pegout details, or a `PegoutError`
/// describing why extraction or validation failed.
///
/// # Errors
///
/// - `BadMintContract` if the log is not from the expected contract
/// - `EmptyTopics`, `BadBurnTopic`, or `BadTopicLength` for malformed logs
/// - `BadAbiSequence` if the log data cannot be decoded
/// - `MaxSatoshiExceeded` if the amount is too large
/// - `BadMetadataLength` or `BadMetadataVersion` for invalid metadata
/// - `BadBitcoinDestination` if the address is invalid for the network
pub fn extract_pegout_data(
    log: &Log,
    btc_network: bitcoin::Network,
) -> Result<PegoutData, PegoutError> {
    if log.address != *MINT_CONTRACT_ADDRESS {
        return Err(PegoutError::BadMintContract);
    }

    let topics = log.topics();
    if topics.is_empty() {
        return Err(PegoutError::EmptyTopics);
    }

    if topics[0] != *BURN_TOPIC {
        return Err(PegoutError::BadBurnTopic);
    }

    // TODO: Why is this necessary?
    if topics.len() != 2 {
        return Err(PegoutError::BadTopicLength);
    }

    let params =
        <(sol_data::Uint<256>, sol_data::String, sol_data::Bytes) as SolType>::abi_decode_sequence(
            &log.data.data,
        )
        .map_err(|_| PegoutError::BadAbiSequence)?;

    let amount_wei = params.0;
    let destination = params.1;
    let metadata = params.2;

    // Convert Wei to Satoshi
    let sat = amount_wei / SATOSHI_IN_WEI;
    let btc_amount = if sat <= MAX_SATOSHI {
        bitcoin::Amount::from_sat(sat.try_into().expect("sat amount must be 8-bytes"))
    } else {
        return Err(PegoutError::MaxSatoshiExceeded);
    };

    if metadata.len() != 1 {
        return Err(PegoutError::BadMetadataLength);
    }

    if metadata[0] != PegoutData::version() {
        return Err(PegoutError::BadMetadataVersion);
    }

    // Check for valid address
    let destination: bitcoin::address::Address<bitcoin::address::NetworkUnchecked> =
        bitcoin::address::Address::from_str(destination.as_str())
            .map_err(|_| PegoutError::BadBitcoinDestination)?;

    // For is address if valid for network
    let network_checked_destination = destination
        .require_network(btc_network)
        .map_err(|_| PegoutError::BadBitcoinDestination)?;

    Ok(PegoutData {
        amount: btc_amount,
        destination: network_checked_destination,
        network: btc_network,
    })
}

// TODO: This should probably be placed in an individual module?
// TODO: Add explicit test for this.
impl serde::Serialize for PegoutData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("PegoutData", 3)?;
        state.serialize_field("amount", &self.amount)?;

        // Convert address to bytes using the network
        let address_bytes = self.destination.script_pubkey();
        state.serialize_field("destination", &address_bytes)?;

        state.serialize_field("network", &self.network)?;
        state.end()
    }
}

// TODO: This should probably be placed in an individual module?
// TODO: Add explicit test for this.
impl<'de> serde::Deserialize<'de> for PegoutData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        enum Field {
            Amount,
            Destination,
            Network,
        }

        impl<'de> serde::Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("`amount`, `destination`, or `network`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "amount" => Ok(Field::Amount),
                            "destination" => Ok(Field::Destination),
                            "network" => Ok(Field::Network),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct PegoutDataVisitor;

        impl<'de> Visitor<'de> for PegoutDataVisitor {
            type Value = PegoutData;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct PegoutData")
            }

            fn visit_map<V>(self, mut map: V) -> Result<PegoutData, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut amount = None;
                let mut destination_bytes = None;
                let mut network = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Amount => {
                            if amount.is_some() {
                                return Err(de::Error::duplicate_field("amount"));
                            }
                            amount = Some(map.next_value()?);
                        }
                        Field::Destination => {
                            if destination_bytes.is_some() {
                                return Err(de::Error::duplicate_field("destination"));
                            }
                            destination_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        Field::Network => {
                            if network.is_some() {
                                return Err(de::Error::duplicate_field("network"));
                            }
                            network = Some(map.next_value()?);
                        }
                    }
                }

                let amount = amount.ok_or_else(|| de::Error::missing_field("amount"))?;
                let destination_bytes =
                    destination_bytes.ok_or_else(|| de::Error::missing_field("destination"))?;
                let destination_bytes = ScriptBuf::from_bytes(destination_bytes);
                let network = network.ok_or_else(|| de::Error::missing_field("network"))?;

                let destination = bitcoin::Address::from_script(&destination_bytes, network)
                    .map_err(de::Error::custom)?;

                Ok(PegoutData {
                    amount,
                    destination,
                    network,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["amount", "destination", "network"];
        deserializer.deserialize_struct("PegoutData", FIELDS, PegoutDataVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{primitives::TxType, validation::botanix::compute_receipt_proof};
    use alloy_primitives::{Bytes, LogData};

    /// Pegout proof verification and extraction using live Botanix block:
    ///
    /// * https://botanixscan.io/block/672580
    #[test]
    fn test_calculate_verify_proof() {
        let log_0 = Log {
            address: Address::from_str("0x4f1b32aecffe190d80b9f553987ed4f20450e927").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str(
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000003be5b332203084cd11a3670e24f098fb0b711d02",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x000000000000000000000000e326cfdd4296443c27ace62d0a8e257f6d11f1d9",
                    )
                    .unwrap(),
                ],
                Bytes::from_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
            )
            .unwrap(),
        };

        let log_1 = Log {
            address: Address::from_str("0x4f1b32aecffe190d80b9f553987ed4f20450e927").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str(
                        "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000003be5b332203084cd11a3670e24f098fb0b711d02",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000005a0690ac82aaaa2e25bc130e900cd31ee9b67db8",
                    )
                    .unwrap(),
                ],
                Bytes::from_str(
                    "0x0000000000000000000000000000000000000000000000020fa74f2639fdfcc0",
                )
                .unwrap(),
            )
            .unwrap(),
        };

        let log_2 = Log {
            address: Address::from_str("0x5a0690ac82aaaa2e25bc130e900cd31ee9b67db8").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str(
                        "0x63641fd2aeafea4143cc44c28ca8af48dde6326ee1be502b0222b4f92dfae283",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x000000000000000000000000e326cfdd4296443c27ace62d0a8e257f6d11f1d9",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000004f1b32aecffe190d80b9f553987ed4f20450e927",
                    )
                    .unwrap(),
                ],
                Bytes::from_str(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
            )
            .unwrap(),
        };

        let log_3 = Log {
            address: Address::from_str("0x4f1b32aecffe190d80b9f553987ed4f20450e927").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str(
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000003be5b332203084cd11a3670e24f098fb0b711d02",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000005a0690ac82aaaa2e25bc130e900cd31ee9b67db8",
                    )
                    .unwrap(),
                ],
                Bytes::from_str(
                    "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
                )
                .unwrap(),
            )
            .unwrap(),
        };

        let log_4 = Log {
            address: Address::from_str("0x4f1b32aecffe190d80b9f553987ed4f20450e927").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str(
                        "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000003be5b332203084cd11a3670e24f098fb0b711d02",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000005a0690ac82aaaa2e25bc130e900cd31ee9b67db8",
                    )
                    .unwrap(),
                ],
                Bytes::from_str(
                    "0x00000000000000000000000000000000000000000000000201c698729299fcc0",
                )
                .unwrap(),
            )
            .unwrap(),
        };

        let log_5 = Log {
            address: Address::from_str("0x0d2437f93fed6ea64ef01ccde385fb1263910c56").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str(
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x000000000000000000000000b79fd7f333ca87b437afa37e0fd3a76f3a32503f",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000005a0690ac82aaaa2e25bc130e900cd31ee9b67db8",
                    )
                    .unwrap(),
                ],
                Bytes::from_str(
                    "0x000000000000000000000000000000000000000000000000000000013b121ba3",
                )
                .unwrap(),
            )
            .unwrap(),
        };

        let log_6 = Log {
            address: Address::from_str("0x4f1b32aecffe190d80b9f553987ed4f20450e927").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str(
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000005a0690ac82aaaa2e25bc130e900cd31ee9b67db8",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x000000000000000000000000b79fd7f333ca87b437afa37e0fd3a76f3a32503f",
                    )
                    .unwrap(),
                ],
                Bytes::from_str(
                    "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
                )
                .unwrap(),
            )
            .unwrap(),
        };

        let log_7 = Log {
            address: Address::from_str("0xb79fd7f333ca87b437afa37e0fd3a76f3a32503f").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str("0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67").unwrap(),
                    B256::from_str("0x0000000000000000000000005a0690ac82aaaa2e25bc130e900cd31ee9b67db8").unwrap(),
                    B256::from_str("0x0000000000000000000000005a0690ac82aaaa2e25bc130e900cd31ee9b67db8").unwrap(),
                ],
                Bytes::from_str("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffec4ede45d0000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000357547234e4e557a270cfb9634900000000000000000000000000000000000000000000000f691b666f360f5833c000000000000000000000000000000000000000000000000000000000002e81b").unwrap()
            ).unwrap()
        };

        let log_8 = Log {
            address: Address::from_str("0x0d2437f93fed6ea64ef01ccde385fb1263910c56").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str(
                        "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65",
                    )
                    .unwrap(),
                    B256::from_str(
                        "0x0000000000000000000000005a0690ac82aaaa2e25bc130e900cd31ee9b67db8",
                    )
                    .unwrap(),
                ],
                Bytes::from_str(
                    "0x000000000000000000000000000000000000000000000000000000013b121ba3",
                )
                .unwrap(),
            )
            .unwrap(),
        };

        let log_9 = Log {
            address: Address::from_str("0x5a0690ac82aaaa2e25bc130e900cd31ee9b67db8").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str("0xea3ff8efd368e77313f7c261d10549274899f7cf5db4b6b3d4b865cb5a21a8ea").unwrap(),
                    B256::from_str("0x0000000000000000000000004f1b32aecffe190d80b9f553987ed4f20450e927").unwrap(),
                    B256::from_str("0x000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap(),
                ],
                Bytes::from_str("0x0000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000013b121ba30000000000000000000000003be5b332203084cd11a3670e24f098fb0b711d020000000000000000000000003be5b332203084cd11a3670e24f098fb0b711d02").unwrap()
            ).unwrap()
        };

        let log_10 = Log {
            address: Address::from_str("0x0ea320990b44236a0ced0ecc0fd2b2df33071e78").unwrap(),
            data: LogData::new(
                vec![
                    B256::from_str("0x17f87987da8ca71c697791dcfd190d07630cf17bf09c65c5a59b8277d9fe1715").unwrap(),
                    B256::from_str("0x000000000000000000000000021268a7de837c0f6fdfede1ad5e632951d1429f").unwrap(),
                ],
                Bytes::from_str("0x000000000000000000000000000000000000000000000000000060680c58a000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000002a6263317133777276366c6d337236356a73306e637663743972303363776667356e6a61683765743076670000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000").unwrap()
            ).unwrap()
        };

        // https://botanixscan.io/tx/0x319619a2bb7dce72daf88e38212b14d69b0f0e4442c009614813cbfad32a6c38
        let receipt_0 = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 387_626,
            logs: vec![],
        };

        // https://botanixscan.io/tx/0x27de4c7a53c0f209115eef2c56538b5d1f3b1d02fcd0b3d33bc209a11fb42b07
        let receipt_1 = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 366_354,
            logs: vec![],
        };

        // https://botanixscan.io/tx/0x2880d3bbf666b6a38fe5fa2b7bf8c47c6a5bd262bbe5020ad20c011468ad86fe
        let receipt_2 = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 345_082,
            logs: vec![],
        };

        // https://botanixscan.io/tx/0x6c3b4b0008b546503d447741521616af22db74a756dc5e0d02763ac869c4c037
        let receipt_3 = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 323_810,
            logs: vec![],
        };

        // https://botanixscan.io/tx/0x4474baa98b95035861bbcd4171411c1651f46b036a4be10dd36b1f8c8dc08e85
        let receipt_4 = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 302_538,
            logs: vec![
                log_0, log_1, log_2, log_3, log_4, log_5, log_6, log_7, log_8,
                log_9, // NOTE the logs here!
            ],
        };

        // https://botanixscan.io/tx/0x2536444401e663a4c207d181a9fcd30c8619c5f23be9ec92766cddc5da44a91f
        let receipt_5 = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 112_737,
            logs: vec![],
        };

        // https://botanixscan.io/tx/0xc19a9aa1a6598e1f895ea5b461b74b6c8d49f6411d5e94ba5c44de8b219e8b00
        let receipt_6 = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 91_465,
            logs: vec![],
        };

        // https://botanixscan.io/tx/0xf9edfb7ae7d67ec893a8f181357d9e21127bfb74af5e2152fe494a92927c8413
        let receipt_7 = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 70_193,
            logs: vec![],
        };

        // https://botanixscan.io/tx/0xde170f9ed5ff4b882e6b813e6a570b42da2b1333f0b2469a632868bf1280d35c
        let receipt_8 = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 48_921,
            logs: vec![log_10], // NOTE the log here!
        };

        // https://botanixscan.io/tx/0x016b462a079de5dc9257cf701bc0bb02fbf6c5ea168d6dab043daa03788c3f70
        let receipt_9 = Receipt {
            tx_type: TxType::Legacy, // NOTE the Legacy type here!
            success: true,
            cumulative_gas_used: 21_272,
            logs: vec![],
        };

        // TODO: Reverse the ordering of the name index indicators, for clarity.
        let receipts = vec![
            receipt_9.clone(),
            receipt_8.clone(),
            receipt_7,
            receipt_6,
            receipt_5,
            receipt_4,
            receipt_3,
            receipt_2,
            receipt_1,
            receipt_0,
        ];

        // As provided in Botanix block: https://botanixscan.io/block/672580
        let expected_root: [u8; 32] =
            B256::from_str("0x637d304d4afb9ddcb4b4b3eabc8080de9fa8cf1e65137a44a0345b557fda5275")
                .unwrap()
                .into();

        // Construct the proof for receipt_8 and verify against the root.
        let proof = compute_receipt_proof(receipts, 1, Some(expected_root)).unwrap();

        verify_receipt_proof(receipt_8.clone(), &proof, &expected_root).unwrap();

        // The expected pegout.
        let expected_pegout = PegoutData {
            amount: bitcoin::Amount::from_sat(10_600),
            destination: bitcoin::Address::from_str("BC1Q3WRV6LM3R65JS0NCVCT9R03CWFG5NJAH7ET0VG")
                .unwrap()
                .require_network(bitcoin::Network::Bitcoin)
                .unwrap(),
            network: bitcoin::Network::Bitcoin,
        };

        // Extract the pegout.
        let extracted_pegout =
            extract_pegout_data(&receipt_8.logs[0], bitcoin::Network::Bitcoin).unwrap();

        debug_assert_eq!(expected_pegout, extracted_pegout);
    }
}
