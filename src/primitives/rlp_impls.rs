use super::{BotanixHeader, Receipt, ReceiptWithBloom, TransactionSigned, TxType};
use alloy_primitives::{B64, B256, U256};
use alloy_rlp::{Buf, BufMut, Decodable, Encodable, length_of_length};
use std::cmp::Ordering;

impl BotanixHeader {
    fn header_payload_length(&self) -> usize {
        let mut length = 0;
        length += self.parent_hash.length(); // Hash of the previous block.
        length += self.ommers_hash.length(); // Hash of uncle blocks.
        length += self.beneficiary.length(); // Address that receives rewards.
        length += self.state_root.length(); // Root hash of the state object.
        length += self.transactions_root.length(); // Root hash of transactions in the block.
        length += self.receipts_root.length(); // Hash of transaction receipts.
        length += self.logs_bloom.length(); // Data structure containing event logs.
        length += self.difficulty.length(); // Difficulty value of the block.
        length += U256::from(self.number).length(); // Block number.
        length += U256::from(self.gas_limit).length(); // Maximum gas allowed.
        length += U256::from(self.gas_used).length(); // Actual gas used.
        length += self.timestamp.length(); // Block timestamp.
        length += self.extra_data.length(); // Additional arbitrary data.
        length += self.mix_hash.length(); // Hash used for mining.
        length += B64::new(self.nonce.to_be_bytes()).length(); // Nonce for mining.

        if let Some(base_fee) = self.base_fee_per_gas {
            // Adding base fee length if it exists.
            length += U256::from(base_fee).length();
        }

        if let Some(root) = self.withdrawals_root {
            // Adding withdrawals_root length if it exists.
            length += root.length();
        }

        if let Some(blob_gas_used) = self.blob_gas_used {
            // Adding blob_gas_used length if it exists.
            length += U256::from(blob_gas_used).length();
        }

        if let Some(excess_blob_gas) = self.excess_blob_gas {
            // Adding excess_blob_gas length if it exists.
            length += U256::from(excess_blob_gas).length();
        }

        if let Some(parent_beacon_block_root) = self.parent_beacon_block_root {
            length += parent_beacon_block_root.length();
        }

        if let Some(requests_root) = self.requests_root {
            length += requests_root.length();
        }

        length
    }
}

impl Encodable for BotanixHeader {
    fn encode(&self, out: &mut dyn BufMut) {
        // Create a header indicating the encoded content is a list with the payload length computed
        // from the header's payload calculation function.
        let list_header = alloy_rlp::Header {
            list: true,
            payload_length: self.header_payload_length(),
        };
        list_header.encode(out);

        // Encode each header field sequentially
        self.parent_hash.encode(out); // Encode parent hash.
        self.ommers_hash.encode(out); // Encode ommer's hash.
        self.beneficiary.encode(out); // Encode beneficiary.
        self.state_root.encode(out); // Encode state root.
        self.transactions_root.encode(out); // Encode transactions root.
        self.receipts_root.encode(out); // Encode receipts root.
        self.logs_bloom.encode(out); // Encode logs bloom.
        self.difficulty.encode(out); // Encode difficulty.
        U256::from(self.number).encode(out); // Encode block number.
        U256::from(self.gas_limit).encode(out); // Encode gas limit.
        U256::from(self.gas_used).encode(out); // Encode gas used.
        self.timestamp.encode(out); // Encode timestamp.
        self.extra_data.encode(out); // Encode extra data.
        self.mix_hash.encode(out); // Encode mix hash.
        B64::new(self.nonce.to_be_bytes()).encode(out); // Encode nonce.

        // Encode base fee.
        if let Some(ref base_fee) = self.base_fee_per_gas {
            U256::from(*base_fee).encode(out);
        }

        // Encode withdrawals root.
        if let Some(ref root) = self.withdrawals_root {
            root.encode(out);
        }

        // Encode blob gas used.
        if let Some(ref blob_gas_used) = self.blob_gas_used {
            U256::from(*blob_gas_used).encode(out);
        }

        // Encode excess blob gas.
        if let Some(ref excess_blob_gas) = self.excess_blob_gas {
            U256::from(*excess_blob_gas).encode(out);
        }

        // Encode parent beacon block root.
        if let Some(ref parent_beacon_block_root) = self.parent_beacon_block_root {
            parent_beacon_block_root.encode(out);
        }

        // Encode EIP-7685 requests root
        if let Some(ref requests_root) = self.requests_root {
            requests_root.encode(out);
        }
    }

    fn length(&self) -> usize {
        let mut length = 0;
        length += self.header_payload_length();
        length += length_of_length(length);
        length
    }
}

impl Decodable for BotanixHeader {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let rlp_head = alloy_rlp::Header::decode(buf)?;
        if !rlp_head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let started_len = buf.len();
        let mut this = Self {
            parent_hash: Decodable::decode(buf)?,
            ommers_hash: Decodable::decode(buf)?,
            beneficiary: Decodable::decode(buf)?,
            state_root: Decodable::decode(buf)?,
            transactions_root: Decodable::decode(buf)?,
            receipts_root: Decodable::decode(buf)?,
            logs_bloom: Decodable::decode(buf)?,
            difficulty: Decodable::decode(buf)?,
            number: u64::decode(buf)?,
            gas_limit: u64::decode(buf)?,
            gas_used: u64::decode(buf)?,
            timestamp: Decodable::decode(buf)?,
            extra_data: Decodable::decode(buf)?,
            mix_hash: Decodable::decode(buf)?,
            nonce: u64::from_be_bytes(B64::decode(buf)?.0),
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_root: None,
        };
        if started_len - buf.len() < rlp_head.payload_length {
            this.base_fee_per_gas = Some(u64::decode(buf)?);
        }

        // Withdrawals root for post-shanghai headers
        if started_len - buf.len() < rlp_head.payload_length {
            this.withdrawals_root = Some(Decodable::decode(buf)?);
        }

        // Blob gas used and excess blob gas for post-cancun headers
        if started_len - buf.len() < rlp_head.payload_length {
            this.blob_gas_used = Some(u64::decode(buf)?);
        }

        if started_len - buf.len() < rlp_head.payload_length {
            this.excess_blob_gas = Some(u64::decode(buf)?);
        }

        // Decode parent beacon block root.
        if started_len - buf.len() < rlp_head.payload_length {
            this.parent_beacon_block_root = Some(B256::decode(buf)?);
        }

        // Decode requests root.
        if started_len - buf.len() < rlp_head.payload_length {
            this.requests_root = Some(B256::decode(buf)?);
        }

        let consumed = started_len - buf.len();
        if consumed != rlp_head.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: rlp_head.payload_length,
                got: consumed,
            });
        }
        Ok(this)
    }
}

impl ReceiptWithBloom {
    /// Returns the rlp header for the receipt payload.
    fn receipt_rlp_header(&self) -> alloy_rlp::Header {
        let mut rlp_head = alloy_rlp::Header {
            list: true,
            payload_length: 0,
        };

        rlp_head.payload_length += self.receipt.success.length();
        rlp_head.payload_length += self.receipt.cumulative_gas_used.length();
        rlp_head.payload_length += self.bloom.length();
        rlp_head.payload_length += self.receipt.logs.length();

        rlp_head
    }

    /// Encodes the receipt data.
    fn encode_fields(&self, out: &mut dyn BufMut) {
        self.receipt_rlp_header().encode(out);
        self.receipt.success.encode(out);
        self.receipt.cumulative_gas_used.encode(out);
        self.bloom.encode(out);
        self.receipt.logs.encode(out);
    }

    /// Encode receipt with or without the header data.
    pub fn encode_inner(&self, out: &mut dyn BufMut, with_header: bool) {
        if matches!(self.receipt.tx_type, TxType::Legacy) {
            self.encode_fields(out);
            return;
        }

        let mut payload = Vec::new();
        self.encode_fields(&mut payload);

        if with_header {
            let payload_length = payload.len() + 1;
            let header = alloy_rlp::Header {
                list: false,
                payload_length,
            };
            header.encode(out);
        }

        match self.receipt.tx_type {
            TxType::Legacy => unreachable!("legacy already handled"),

            TxType::Eip2930 => {
                out.put_u8(0x01);
            }
            TxType::Eip1559 => {
                out.put_u8(0x02);
            }
            TxType::Eip4844 => {
                out.put_u8(0x03);
            }
            TxType::Eip7702 => {
                out.put_u8(0x04);
            }
        }
        out.put_slice(payload.as_ref());
    }

    /// Decodes the receipt payload
    fn decode_receipt(buf: &mut &[u8], tx_type: TxType) -> alloy_rlp::Result<Self> {
        let b = &mut &**buf;
        let rlp_head = alloy_rlp::Header::decode(b)?;
        if !rlp_head.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let started_len = b.len();

        let success = alloy_rlp::Decodable::decode(b)?;
        let cumulative_gas_used = alloy_rlp::Decodable::decode(b)?;
        let bloom = Decodable::decode(b)?;
        let logs = alloy_rlp::Decodable::decode(b)?;

        let receipt = Receipt {
            tx_type,
            success,
            cumulative_gas_used,
            logs,
        };

        let this = Self { receipt, bloom };
        let consumed = started_len - b.len();
        if consumed != rlp_head.payload_length {
            return Err(alloy_rlp::Error::ListLengthMismatch {
                expected: rlp_head.payload_length,
                got: consumed,
            });
        }
        *buf = *b;
        Ok(this)
    }
}

// TODO: Need this?
impl Encodable for ReceiptWithBloom {
    fn encode(&self, out: &mut dyn BufMut) {
        self.encode_inner(out, true);
    }

    fn length(&self) -> usize {
        let rlp_head = self.receipt_rlp_header();
        let mut payload_len = length_of_length(rlp_head.payload_length) + rlp_head.payload_length;

        // account for eip-2718 type prefix and set the list
        if !matches!(self.receipt.tx_type, TxType::Legacy) {
            payload_len += 1;
            // we include a string header for typed receipts, so include the length here
            payload_len += length_of_length(payload_len);
        }

        payload_len
    }
}

// TODO: Need this?
impl Decodable for ReceiptWithBloom {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // a receipt is either encoded as a string (non legacy) or a list (legacy).
        // We should not consume the buffer if we are decoding a legacy receipt, so let's
        // check if the first byte is between 0x80 and 0xbf.
        let rlp_type = *buf.first().ok_or(alloy_rlp::Error::Custom(
            "cannot decode a receipt from empty bytes",
        ))?;

        match rlp_type.cmp(&alloy_rlp::EMPTY_LIST_CODE) {
            Ordering::Less => {
                // strip out the string header
                let _header = alloy_rlp::Header::decode(buf)?;
                let receipt_type = *buf.first().ok_or(alloy_rlp::Error::Custom(
                    "typed receipt cannot be decoded from an empty slice",
                ))?;
                match receipt_type {
                    0x01 => {
                        buf.advance(1);
                        Self::decode_receipt(buf, TxType::Eip2930)
                    }
                    0x02 => {
                        buf.advance(1);
                        Self::decode_receipt(buf, TxType::Eip1559)
                    }
                    0x03 => {
                        buf.advance(1);
                        Self::decode_receipt(buf, TxType::Eip4844)
                    }
                    0x04 => {
                        buf.advance(1);
                        Self::decode_receipt(buf, TxType::Eip7702)
                    }
                    _ => Err(alloy_rlp::Error::Custom("invalid receipt type")),
                }
            }
            Ordering::Equal => Err(alloy_rlp::Error::Custom(
                "an empty list is not a valid receipt encoding",
            )),
            Ordering::Greater => Self::decode_receipt(buf, TxType::Legacy),
        }
    }
}

impl TransactionSigned {
    pub fn encode_inner(&self, _out: &mut dyn BufMut, _with_header: bool) {
        todo!()
    }
}
