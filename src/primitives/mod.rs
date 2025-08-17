use alloy_primitives::{
    Address, B256, BlockNumber, Bloom, Bytes, Log, Signature, TxHash, U256, keccak256,
};
use tendermint_light_client_verifier::types::{Header as CometHeader, SignedHeader, Validator};

mod rlp_impls;

pub fn cbft_signed_header_from_json(data: &[u8]) -> Result<SignedHeader, ()> {
    serde_json::from_slice(data).map_err(|_| ())
}

pub fn cbft_validator_set_from_json(data: &[u8]) -> Result<Vec<Validator>, ()> {
    serde_json::from_slice(data).map_err(|_| ())
}

pub fn cbft_header_from_json(data: &[u8]) -> Result<CometHeader, ()> {
    serde_json::from_slice(data).map_err(|_| ())
}

/// Botanix block header.
#[derive(Debug, Clone)]
pub struct BotanixHeader {
    pub parent_hash: B256,
    pub ommers_hash: B256,
    pub beneficiary: Address,
    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,
    pub withdrawals_root: Option<B256>,
    pub logs_bloom: Bloom,
    pub difficulty: U256,
    pub number: BlockNumber,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub mix_hash: B256,
    pub nonce: u64,
    pub base_fee_per_gas: Option<u64>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub parent_beacon_block_root: Option<B256>,
    pub requests_root: Option<B256>,
    pub extra_data: Bytes,
}

impl BotanixHeader {
    pub fn hash_slow(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum TxType {
    /// Legacy transaction pre EIP-2929
    #[default]
    Legacy = 0_isize,
    /// AccessList transaction
    Eip2930 = 1_isize,
    /// Transaction with Priority fee
    Eip1559 = 2_isize,
    /// Shard Blob Transactions - EIP-4844
    Eip4844 = 3_isize,
    /// EOA Contract Code Transactions - EIP-7702
    Eip7702 = 4_isize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Receipt type.
    pub tx_type: TxType,
    /// If transaction is executed successfully.
    ///
    /// This is the `statusCode`
    pub success: bool,
    /// Gas used
    pub cumulative_gas_used: u64,
    /// Log send from contracts.
    pub logs: Vec<Log>,
}

impl Receipt {
    /// Calculate receipt logs bloom.
    pub fn logs_bloom(&self) -> Bloom {
        let mut bloom = Bloom::ZERO;
        for log in &self.logs {
            bloom.m3_2048(log.address.as_slice());
            for topic in log.topics() {
                bloom.m3_2048(topic.as_slice());
            }
        }
        bloom
    }
}

pub struct ReceiptWithBloom {
    /// Bloom filter build from logs.
    pub bloom: Bloom,
    /// Main receipt body
    pub receipt: Receipt,
}

// TODO
pub struct Transaction;

pub struct TransactionSigned {
    /// Transaction hash
    pub hash: B256,
    /// The transaction signature values
    pub signature: Signature,
    /// Raw transaction info
    pub transaction: Transaction,
}

impl TransactionSigned {
    pub fn hash_slow(&self) -> TxHash {
        todo!()
    }
}
