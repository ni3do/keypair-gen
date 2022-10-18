use hex;
use secp256k1::PublicKey;
use std::fmt;

use super::crypto_util::keccak256;
use super::util::to_arr;

/// Fixed bytes number to represent `Address`
pub const ETHEREUM_ADDRESS_BYTES: usize = 20;

/// Account address (20 bytes)
#[derive(Clone, Copy, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct EthereumAddress(pub [u8; ETHEREUM_ADDRESS_BYTES]);

impl From<[u8; ETHEREUM_ADDRESS_BYTES]> for EthereumAddress {
    fn from(bytes: [u8; ETHEREUM_ADDRESS_BYTES]) -> Self {
        EthereumAddress(bytes)
    }
}

impl AsRef<[u8]> for EthereumAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl From<PublicKey> for EthereumAddress {
    fn from(value: PublicKey) -> Self {
        let hash = keccak256(&value.serialize_uncompressed()[1..] /* cut '04' */);
        EthereumAddress(to_arr(&hash[12..]))
    }
}
