#![feature(try_trait)]
// #![feature(const_vec_new)]
#![feature(exclusive_range_pattern)]
pub mod types;

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
use crate::get_receipts::{get_all_receipts_from_block_in_state_and_set_in_state, get_receipt_from_tx_hash, get_logs};
use crate::get_receipts_trie::get_receipts_trie_and_set_in_state;
use crate::get_tx_index::get_tx_index_and_add_to_state;
use crate::state::State;
use crate::types::{EthSpvProof, Receipt, UnlockEvent, Log};
use crate::utils::convert_hex_to_h256;
use ethabi::{Event, EventParam, ParamType, RawLog, Token};
use rlp::{Encodable, RlpStream};
use std::i64;


pub fn get_logs_with_address(endpoint: String,
                             block_hash: String,
                             contract_addr: String,) -> Result<Vec<Log>, errors::AppError> {
    get_logs(endpoint.as_str(), contract_addr.as_str(), block_hash.as_str())

}

pub fn parse_event(endpoint: &str,
                   contract_addr: &str,
                   block_hash: &str,
                   ) -> Result<(Vec<EthSpvProof>, Vec<UnlockEvent>), errors::AppError> {
    let logs = get_logs(endpoint, contract_addr, block_hash)?;
    if logs.is_empty() {
        return Err(errors::AppError::Custom(String::from(
            "the event is not exist.",
        )));
    }
    let mut lock_event = vec![];
    let mut unlock_event = vec![];
    for item in logs {
        if hex::encode(item.clone().topics[0].0) == constants::LOCK_EVENT_STRING {
            // handle lock event
            // let event = handle_lock_event(item.clone())?;
            let event = generate_eth_proof(item.transactionHash, String::from(endpoint), String::from(clear_0x(contract_addr)))?;
            if event.block_hash != block_hash {
                return Err(errors::AppError::Custom(String::from(
                    "the block hash is invalid. make sure the block is on the main chain.",
                )));
            }
            lock_event.push(event);
        } else if hex::encode(item.clone().topics[0].0) == constants::UNLOCK_EVENT_STRING {
            // handle unlock event
            let event = handle_unlock_event(&item)?;
            unlock_event.push(event);
        }
    }
    Ok((lock_event, unlock_event))
}

fn handle_unlock_event(item: &Log) -> Result<UnlockEvent, errors::AppError> {
    let mut unlock_event = UnlockEvent {
        tx_hash: item.transactionHash.clone(),
        ..Default::default()
    };
    let event = Event {
        name: "Unlocked".to_string(),
        inputs: vec![
            EventParam {
                name: "token".to_owned(),
                kind: ParamType::Address,
                indexed: true,
            },
            EventParam {
                name: "recipient".to_owned(),
                kind: ParamType::Address,
                indexed: true,
            },
            EventParam {
                name: "sender".to_owned(),
                kind: ParamType::Address,
                indexed: true,
            },
            EventParam {
                name: "receivedAmount".to_owned(),
                kind: ParamType::Uint(256),
                indexed: false,
            },
            EventParam {
                name: "bridgeFee".to_owned(),
                kind: ParamType::Uint(256),
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
    for v in result.params {
        match v.name.as_str() {
            "token" => {
                unlock_event.token = v.value.to_address().unwrap();
            }
            "recipient" => {
                unlock_event.recipient = v.value.to_address().unwrap();
            }
            "receivedAmount" => {
                unlock_event.received_amount = v.value.to_uint().unwrap().as_u128();
            }
            "bridgeFee" => {
                unlock_event.bridge_fee = v.value.to_uint().unwrap().as_u128();
            }
            _ => {}
        }
    }
    Ok(unlock_event)

}

fn handle_lock_event(item: Log) -> Result<EthSpvProof, errors::AppError> {
    let mut eth_spv_proof = EthSpvProof {
        log_index: i32::from_str_radix(clear_0x(item.log_index.as_str()), 16).unwrap(),
        receipt_index: u64::from_str_radix(clear_0x(item.transactionIndex.as_str()), 16).unwrap(),
        block_hash: item.blockHash.clone(),
        tx_hash: item.transactionHash.clone(),
        ..Default::default()
    };
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
        topics: item.topics.clone(),
        data: item.data.clone(),
    };
    let result = event.parse_log(raw_log).unwrap();
    for v in result.params {
        match v.name.as_str() {
            "token" => {
                eth_spv_proof.token = v.value.to_address().unwrap();
            }
            "sender" => {
                eth_spv_proof.sender = v.value.to_address().unwrap();
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

    Ok(eth_spv_proof)
}


pub fn generate_eth_proof(
    tx_hash: String,
    endpoint: String,
    contract_addr: String,
) -> Result<EthSpvProof, errors::AppError> {
    let receipt =
        get_receipt_from_tx_hash(endpoint.clone().as_str(), tx_hash.clone().as_str())?;
    let mut stream = RlpStream::new();
    let logs = &receipt.logs;
    receipt.rlp_append(&mut stream);
    let mut log_index = -1;
    let mut is_exist = false;

    let mut eth_spv_proof = EthSpvProof {
        log_index: -1,
        receipt_index: receipt.transaction_index.as_u64(),

        ..Default::default()
    };
    for item in logs {
        log_index += 1;
        let address_str = hex::encode(item.clone().address);
        if hex::encode(item.clone().topics[0].0) == constants::LOCK_EVENT_STRING && address_str.to_lowercase() == contract_addr.to_lowercase() {
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
            for v in result.params {
                match v.name.as_str() {
                    "token" => {
                        eth_spv_proof.token = v.value.to_address().unwrap();
                    }
                    "sender" => {
                        eth_spv_proof.sender = v.value.to_address().unwrap();
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
            eth_spv_proof.log_index = log_index;
            eth_spv_proof.block_hash = item.blockHash.clone();
            eth_spv_proof.tx_hash = item.transactionHash.clone();
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

pub fn parse_unlock_event(
    tx_hash: String,
    endpoint: String,
    contract_addr: String,
) -> Result<UnlockEvent, errors::AppError> {
    let receipt =
        get_receipt_from_tx_hash(endpoint.clone().as_str(), tx_hash.clone().as_str())?;
    let mut stream = RlpStream::new();
    let logs = &receipt.logs;
    receipt.rlp_append(&mut stream);
    let mut is_exist = false;

    let mut unlock_event = UnlockEvent {
        ..Default::default()
    };
    for item in logs {
        let address_str = hex::encode(item.clone().address);
        if hex::encode(item.clone().topics[0].0) == constants::UNLOCK_EVENT_STRING && address_str.to_lowercase() == contract_addr.to_lowercase() {
            let event = Event {
                name: "Unlocked".to_string(),
                inputs: vec![
                    EventParam {
                        name: "token".to_owned(),
                        kind: ParamType::Address,
                        indexed: true,
                    },
                    EventParam {
                        name: "recipient".to_owned(),
                        kind: ParamType::Address,
                        indexed: true,
                    },
                    EventParam {
                        name: "sender".to_owned(),
                        kind: ParamType::Address,
                        indexed: true,
                    },
                    EventParam {
                        name: "receivedAmount".to_owned(),
                        kind: ParamType::Uint(256),
                        indexed: false,
                    },
                    EventParam {
                        name: "bridgeFee".to_owned(),
                        kind: ParamType::Uint(256),
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
            for v in result.params {
                match v.name.as_str() {
                    "token" => {
                        unlock_event.token = v.value.to_address().unwrap();
                    }
                    "recipient" => {
                        unlock_event.recipient = v.value.to_address().unwrap();
                    }
                    "receivedAmount" => {
                        unlock_event.received_amount = v.value.to_uint().unwrap().as_u128();
                    }
                    "bridgeFee" => {
                        unlock_event.bridge_fee = v.value.to_uint().unwrap().as_u128();
                    }
                    _ => {}
                }
            }
            is_exist = true;
            break;
        }
    }
    if !is_exist {
        return Err(errors::AppError::Custom(String::from(
            "the unlocked tx is not exist.",
        )));
    }

    Ok(unlock_event)
}

#[test]
fn test_get_hex_proof() {
    let endpoint = "https://ropsten.infura.io/v3/71c02c451b6248708e493c4ea007c3b2";
    let tx_hash = "0xf576731c8b9033ee1c15665a58ed0e513946f1f3ef22c009546817d3daed836e";
    let proof = generate_eth_proof(String::from(tx_hash), String::from(endpoint), String::from("4347818b33aaf0b442a977900585b9ad1e1b581f"));
    match proof {
        Ok(proof) => {
            println!("{:?}", proof.clone());
        }
        Err(err) => {
            println!("{:?}", err);
        }
    }
    ///////////////////////////////f901b6f901b3822080b901adf901aa0182d0d9b9010000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000010000000000000000000000000000000000000000000000000000000408000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000010000000000000000000000000000000000000000000000000000000400000000000100000000000000000000000000080000000000000000000000000000000000000000000100002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000f8a1f89f94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000006cc5f688a315f3dc28a7781717a9a798a59fda7ba00000000000000000000000007e7a32d9dc98c485c489be8e732f97b4ffe3a4cda000000000000000000000000000000000000000000000000000000001a13b860083307830
    // assert_eq!(proof.unwrap(), "f901b2f901af822080b901a9f901a60182d0d9b9010000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000010000000000000000000000000000000000000000000000000000000408000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000010000000000000000000000000000000000000000000000000000000400000000000100000000000000000000000000080000000000000000000000000000000000000000000100002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000f89df89b94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000006cc5f688a315f3dc28a7781717a9a798a59fda7ba00000000000000000000000007e7a32d9dc98c485c489be8e732f97b4ffe3a4cda000000000000000000000000000000000000000000000000000000001a13b8600");
}

pub fn clear_0x(s: &str) -> &str {
    if &s[..2] == "0x" || &s[..2] == "0X" {
        &s[2..]
    } else {
        s
    }
}

#[test]
fn test_parse_event() {
    let endpoint = "https://ropsten.infura.io/v3/71c02c451b6248708e493c4ea007c3b2";
    // let endpoint = "http://127.0.0.1:8545";
    let hash = "0x480fc6cca516277b01b1e6b8a7c771d1b747096da3724d6aa7c8d9f4e2302278";
    let addr = "0x430a0670b8197e6a67cfe921b0d5601a0fa3dab7";
    let (lock, unlock) = parse_event(endpoint, addr, hash).unwrap();
    println!("{:?}", lock);
    println!("hahahah");
}

#[test]
fn test_get_logs() {
    let endpoint = "https://ropsten.infura.io/v3/71c02c451b6248708e493c4ea007c3b2";
    let hash = "0x480fc6cca516277b01b1e6b8a7c771d1b747096da3724d6aa7c8d9f4e2302278";
    let addr = "0x430a0670b8197e6a67cfe921b0d5601a0fa3dab7";
    let ret = get_logs(endpoint, addr, hash);
    println!("{:?}", ret);
    println!("hahahah");

}

#[test]
fn test_parse_unlock_event() {
    let endpoint = "http://127.0.0.1:8545";
    let tx_hash = "0x71624173e72646d9db6f3018133a592d09cc226d0ff4f85e470ce0388ae62b92";
    let proof = parse_unlock_event(String::from(tx_hash), String::from(endpoint), String::from(""));
    match proof {
        Ok(proof) => {
            println!("{:?}", proof.clone());
        }
        Err(err) => {
            println!("{:?}", err);
        }
    }
    ///////////////////////////////f901b6f901b3822080b901adf901aa0182d0d9b9010000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000010000000000000000000000000000000000000000000000000000000408000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000010000000000000000000000000000000000000000000000000000000400000000000100000000000000000000000000080000000000000000000000000000000000000000000100002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000f8a1f89f94dac17f958d2ee523a2206206994597c13d831ec7f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000006cc5f688a315f3dc28a7781717a9a798a59fda7ba00000000000000000000000007e7a32d9dc98c485c489be8e732f97b4ffe3a4cda000000000000000000000000000000000000000000000000000000001a13b860083307830
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

#[test]
fn test_decode() {
    let str = "f901f180a048201c1e6820c5a6a7063d7b143d68206b50c8d1fd4a78e57d4c4f8aeefcb2efa08bff796a59c00b08cc351d0c446dd67a8ded8872a3a1f583bb7007f2dacd1456a0dce11eeb6888cc63c232db7cba3f970f4b6a66f24952b7b013e446d7c959b813a0ba6c2fe47e1d1ef0b66e16d481953928c161b368b66c6a6cc7ee334f844ae8c1a0a158a490139ecd3e78874d1ea789cea6d6dce1c761097ab7e5e93ddf68490ec1a089d029f91f9e17b096dafdf529d195bc04d117072bbccdac54d4ce41532a5d23a03cc79fac9421ead02318a8b0feb1bc3acdaefbd3c733350158b55a52ef6ce99aa03d515de67f30144481e95e76fcd7f309e4c16562da2e12e2e152c8f5982206dda05834e55e8ced41cf79d32d6b5334f88e29445dff1baed5f49c7d62daa663a6ada0d25d3f853e2b860ce62d78b253c863ed10f9c2e220ddab6cf83fedd34190507ea0130d8e95e892ef14f277197d73d0340982986ab2c5b2b07ca792f4d981d57162a0e572f5026634f627200c74c717b4efc90eaaa869d4b7c372d11e6190e6f3e265a0ba1bca85a216fdbf76695f6252dd633614c78367e4f8f6f0d9fff1471d8bec8aa012bfd3a5f2458e08f77a1e7912c1e6d85a047a1841112a160c8bb00e9273b432a0f85a29ba78af0d0c24c2a3d8efb90d5ba9631162feed3543616195e3a1ee2c4680";
    let decode_str = hex::decode(str).unwrap();
    dbg!(decode_str);
}
