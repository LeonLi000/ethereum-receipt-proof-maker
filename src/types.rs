use crate::errors::AppError;
use crate::trie_nodes::Node;
use ethereum_types::{Address, Bloom, H160, H256, U256};
use rlp::{Encodable, RlpStream};
use serde::Deserialize;
use std::collections::HashMap;
use std::result;

pub type Byte = u8;
pub type Bytes = Vec<Byte>;
pub type HexProof = String;
pub type NodeStack = Vec<Node>;
pub type Database = HashMap<H256, Bytes>;
pub type ChildNodes = [Option<Bytes>; 16];
pub type Result<T> = result::Result<T, AppError>;

#[derive(Debug, Deserialize)]
pub struct BlockRpcResponse {
    pub result: BlockJson,
}

#[derive(Debug, Deserialize)]
pub struct ReceiptRpcResponse {
    pub result: ReceiptJson,
}

#[derive(Debug, Deserialize)]
pub struct LogRpcResponse {
    pub result: Vec<LogJson>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Block {
    // pub author: Address,
    pub difficulty: U256,
    pub extra_data: Bytes,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub hash: H256,
    pub logs_bloom: Bloom,
    pub miner: Address,
    pub mix_hash: H256,
    pub nonce: U256,
    pub number: U256,
    pub parent_hash: H256,
    pub receipts_root: H256,
    // pub seal_fields: (Bytes, U256),
    pub sha3_uncles: H256,
    pub size: U256,
    pub state_root: H256,
    pub timestamp: U256,
    pub total_difficulty: U256,
    pub transactions: Vec<H256>,
    pub transactions_root: H256,
    pub uncles: Vec<H256>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Receipt {
    pub to: Address,
    pub from: Address,
    pub status: bool,
    pub gas_used: U256,
    pub block_hash: H256,
    pub transaction_hash: H256,
    pub cumulative_gas_used: U256,
    pub block_number: U256,
    pub transaction_index: U256,
    pub contract_address: Address,
    pub logs: Vec<Log>,
    // pub root: H256,
    pub logs_bloom: Bloom,
}

impl Encodable for Receipt {
    fn rlp_append(&self, rlp_stream: &mut RlpStream) {
        let rlp = rlp_stream.begin_list(4);
        match &self.status {
            true => rlp.append(&self.status),
            false => rlp.append_empty_data(),
        };
        rlp.append(&self.cumulative_gas_used)
            .append(&self.logs_bloom)
            .append_list(&self.logs);
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Bytes,
    pub log_index: String,
    pub transactionHash: String,
    pub blockHash: String,
    pub transactionIndex: String,
    /*
    removed: bool,
    r#type: String,
    logIndex: String,
    blockHash: String,
    blockNumber: String,
    transactionIndex: String,
    */
}

impl Encodable for Log {
    fn rlp_append(&self, rlp_stream: &mut RlpStream) {
        rlp_stream
            .begin_list(7)
            .append(&self.address)
            .append_list(&self.topics)
            .append(&self.data)
            .append(&self.log_index)
            .append(&self.transactionHash)
            .append(&self.blockHash)
            .append(&self.transactionIndex);
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
pub struct BlockJson {
    // pub author: String,
    pub difficulty: String,
    pub extraData: String,
    pub gasLimit: String,
    pub gasUsed: String,
    pub hash: String,
    pub logsBloom: String,
    pub miner: String,
    pub mixHash: String,
    pub nonce: String,
    pub number: String,
    pub parentHash: String,
    pub receiptsRoot: String,
    // pub sealFields: (String, String),
    pub sha3Uncles: String,
    pub size: String,
    pub stateRoot: String,
    pub timestamp: String,
    pub totalDifficulty: String,
    pub transactions: Vec<String>,
    pub transactionsRoot: String,
    pub uncles: Vec<String>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
pub struct ReceiptJson {
    pub from: String,
    pub status: String,
    pub gasUsed: String,
    pub blockHash: String,
    pub logsBloom: String,
    pub logs: Vec<LogJson>,
    pub blockNumber: String,
    pub to: serde_json::Value,
    // pub root: serde_json::Value,
    pub transactionHash: String,
    pub transactionIndex: String,
    pub cumulativeGasUsed: String,
    pub contractAddress: serde_json::Value,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Deserialize)]
pub struct LogJson {
    pub data: String,
    // pub removed: bool,
    // pub r#type: String,
    pub address: String,
    pub logIndex: String,
    pub blockHash: String,
    pub blockNumber: String,
    pub topics: Vec<String>,
    pub transactionHash: String,
    pub transactionIndex: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct EthSpvProof {
    pub log_index: i32,
    pub log_entry_data: String,
    pub receipt_index: u64,
    pub receipt_data: String,
    pub header_data: String,
    pub proof: String,
    pub token: H160,
    pub lock_amount: u128,
    pub bridge_fee: u128,
    pub ckb_recipient: String,
    pub block_hash: H256,
    pub recipient_lockscript: Vec<u8>,
    pub replay_resist_outpoint: Vec<u8>,
    pub sudt_extra_data: Vec<u8>,
    pub sender: H160,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct UnlockEvent {
    pub token: H160,
    pub recipient: H160,
    pub received_amount: u128,
    pub bridge_fee: u128,
}
