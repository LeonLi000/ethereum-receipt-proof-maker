use crate::types::Byte;
use ethereum_types::H256;
use crate::nibble_utils::Nibbles;

pub const ZERO_BYTE: u8 = 0u8;
pub const HASH_LENGTH: usize  = 32;
pub const HASH_HEX_CHARS: usize  = 64;
pub const HEX_PREFIX_LENGTH: usize = 2;
pub const NUM_BITS_IN_NIBBLE: usize = 4;
pub const REQWEST_TIMEOUT_TIME: u64 = 20;
pub const NUM_NIBBLES_IN_BYTE: usize = 2;
pub const HIGH_NIBBLE_MASK: Byte = 15u8; // NOTE: 15u8 == [0,0,0,0,1,1,1,1]
pub static DOT_ENV_PATH: &'static str = "./.env";
pub static LOG_FILE_PATH: &'static str = "logs/";
pub static LEAF_NODE_STRING: &'static str = "leaf";
pub static BRANCH_NODE_STRING: &'static str = "branch";
pub static EXTENSION_NODE_STRING: &'static str = "extension";
pub const HASHED_NULL_NODE: H256 = H256(HASHED_NULL_NODE_BYTES);
pub static DEFAULT_ENDPOINT: &'static str = "https://mainnet.infura.io/v3/9c7178cede9f4a8a84a151d058bd609c";
pub const EMPTY_NIBBLES: Nibbles = Nibbles { data: Vec::new(), offset: 0 };
pub static LOCK_EVENT_STRING: &'static str = "413055b58d692937cc2a7d80ca019c17e8d01175e58d11f157ae9124078b01d6";

const HASHED_NULL_NODE_BYTES: [u8; 32] = [ // NOTE: keccak hash of the RLP of null
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21
];
