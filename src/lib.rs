#![feature(try_trait)]
// #![feature(const_vec_new)]
#![feature(exclusive_range_pattern)]

mod connect_to_node;
mod constants;
mod errors;
mod get_block;
mod get_branch_from_trie;
mod get_database;
mod get_endpoint;
mod get_hex_proof_from_branch;
mod get_keccak_hash;
mod get_log;
mod get_receipts;
mod get_receipts_trie;
mod get_rpc_call_jsons;
mod get_tx_index;
mod initialize_state_from_cli_args;
mod make_rpc_call;
mod nibble_utils;
mod parse_cli_args;
mod path_codec;
mod rlp_codec;
mod state;
mod test_utils;
mod trie;
mod trie_nodes;
mod types;
mod usage_info;
mod utils;
mod validate_cli_args;
mod validate_tx_hash;

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
#[macro_use]
extern crate serial_test_derive;

use crate::get_block::get_block_from_tx_hash_in_state_and_set_in_state;
use crate::get_branch_from_trie::get_branch_from_trie_and_put_in_state;
use crate::get_hex_proof_from_branch::get_hex_proof_from_branch_in_state;
use crate::get_receipts::{
    get_all_receipts_from_block_in_state_and_set_in_state, get_receipt_from_tx_hash,
};
use crate::get_receipts_trie::get_receipts_trie_and_set_in_state;
use crate::get_tx_index::get_tx_index_and_add_to_state;
use crate::state::State;
use crate::types::{EthSpvProof, Receipt};
use crate::utils::convert_hex_to_h256;
use ethabi::{Event, EventParam, ParamType, RawLog, Token};
use rlp::{Encodable, RlpStream};

pub fn generate_eth_proof(
    tx_hash: String,
    endpoint: String,
) -> Result<EthSpvProof, errors::AppError> {
    let proof = State::init(
        convert_hex_to_h256(tx_hash.clone())?,
        tx_hash.clone(),
        Some(endpoint.clone()),
    )
    .and_then(get_block_from_tx_hash_in_state_and_set_in_state)
    .and_then(get_all_receipts_from_block_in_state_and_set_in_state)
    .and_then(get_tx_index_and_add_to_state)
    .and_then(get_receipts_trie_and_set_in_state)
    .and_then(get_branch_from_trie_and_put_in_state)
    .and_then(get_hex_proof_from_branch_in_state);
    let mut res_receipt =
        get_receipt_from_tx_hash(endpoint.clone().as_str(), tx_hash.clone().as_str());
    let mut stream = RlpStream::new();
    let receipt =  res_receipt.unwrap();
    println!("{:?}", receipt);

    let logs = &receipt.logs;
    receipt.rlp_append(&mut stream);
    let receipt_data = hex::encode(stream.out());
    // let mut log_data = String::new();
    let mut log_index = -1;
    let mut is_exist = false;

    // let mut eth_spv_proof = EthSpvProof::default();
    let mut eth_spv_proof = EthSpvProof {
        log_index: -1,
        receipt_index: receipt.transaction_index.as_u64(),
        receipt_data,
        block_hash: receipt.block_hash,
        proof: proof.unwrap(),
        ..Default::default()
    };
    for item in logs {
        println!("{:?}", item);
        log_index += 1;
        if hex::encode(item.clone().topics[0].0) == constants::LOCK_EVENT_STRING {
            let event = Event {
                name: "Locked".to_string(),
                inputs: vec![
                    EventParam {
                        name: "token".to_owned(),
                        kind: ParamType::Address,
                        indexed: true,
                    },
                    EventParam {
                        name: "sender".to_owned(),
                        kind: ParamType::Address,
                        indexed: true,
                    },
                    EventParam {
                        name: "lockedAmount".to_owned(),
                        kind: ParamType::Uint(256),
                        indexed: false,
                    },
                    EventParam {
                        name: "bridgeFee".to_owned(),
                        kind: ParamType::Uint(256),
                        indexed: false,
                    },
                    EventParam {
                        name: "recipientLockscript".to_owned(),
                        kind: ParamType::Bytes,
                        indexed: false,
                    },
                    EventParam {
                        name: "replayResistOutpoint".to_owned(),
                        kind: ParamType::Bytes,
                        indexed: false,
                    },
                    EventParam {
                        name: "sudtExtraData".to_owned(),
                        kind: ParamType::Bytes,
                        indexed: false,
                    },
                ],
                anonymous: false,
            };
            let raw_log = RawLog {
                topics: item.clone().topics,
                data: item.clone().data,
            };
            let result = event.parse_log(raw_log).unwrap();
            println!("parse event log: {:?}", result);
            for v in result.params {
                match v.name.as_str() {
                    "token" => {
                        eth_spv_proof.token = v.value.to_address().unwrap();
                    }
                    "lockedAmount" => {
                        eth_spv_proof.lock_amount = v.value.to_uint().unwrap().as_u128();
                    }
                    "bridgeFee" => {
                        eth_spv_proof.bridge_fee = v.value.to_uint().unwrap().as_u128();
                    }
                    "recipientLockscript" => {
                        eth_spv_proof.recipient_lockscript = v.value.to_bytes().unwrap();
                    }
                    "replayResistOutpoint" => {
                        eth_spv_proof.replay_resist_outpoint = v.value.to_bytes().unwrap();
                    }
                    "sudtExtraData" => {
                        eth_spv_proof.sudt_extra_data = v.value.to_bytes().unwrap();
                    }
                    _ => {}
                }
            }
            let mut stream = RlpStream::new();
            item.rlp_append(&mut stream);
            eth_spv_proof.log_index = log_index;
            eth_spv_proof.log_entry_data = hex::encode(stream.out());
            is_exist = true;
            break;
        }
    }
    if !is_exist {
        return Err(errors::AppError::Custom(String::from(
            "the locked tx is not exist.",
        )));
    }

    Ok(eth_spv_proof)
}

#[test]
fn test_get_hex_proof() {
    let endpoint = "http://127.0.0.1:8545";
    let tx_hash = "0x26ac5c1ecd1a3d3bd8d8715c5302420dc29c2840dba3ff88de69d4fe85b339fd";
    let proof = generate_eth_proof(String::from(tx_hash), String::from(endpoint));
    match proof {
        Ok(proof) => {
            println!("{:?}", proof.clone());
        }
        Err(err) => {
            println!("{:?}", err);
        }
    }
    // assert_eq!(proof.unwrap(), "f901b2f901af822080b901a9f901a60182d0d9b9010000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000010000000000000000000000000000000000000000000000000000000408000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000010000000000000000000000000000000000000000000000000000000400000000000100000000000000000000000000080000000000000000000000000000000000000000000100002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000f89df89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000006cc5f688a315f3dc28a7781717a9a798a59fda7ba00000000000000000000000007e7a32d9dc98c485c489be8e732f97b4ffe3a4cda000000000000000000000000000000000000000000000000000000001a13b8600");
}

#[test]
fn test_get_receipt_from_txhash() {
    let tx_hash = "0xb540248a9cca048c5861dec953d7a776bc1944319b9bd27a462469c8a437f4ff";
    let endpoint = "https://mainnet.infura.io/v3/9c7178cede9f4a8a84a151d058bd609c";
    let res = get_receipt_from_tx_hash(endpoint, tx_hash);
    println!("{:?}", res);
    let mut stream = RlpStream::new();
    res.unwrap().rlp_append(&mut stream);
    println!("{:?}", hex::encode(stream.out()));
}

#[test]
fn test_get_log_from_txhash() {
    let tx_hash = "0xcc699808af959a6c058a3b77f14f9dc18658c02b1b427d9d3cde01e370802ccf";
    let endpoint = "http://127.0.0.1:9545";
    let res = get_receipt_from_tx_hash(endpoint, tx_hash).unwrap().logs;
    println!("{:?}", res);
    for item in res {
        let mut stream = RlpStream::new();
        item.rlp_append(&mut stream);
        println!("{:?}", hex::encode(stream.out()));
    }
}
