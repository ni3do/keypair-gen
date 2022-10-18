use rand::{rngs::OsRng, Rng};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::{fmt, ops};

use super::eth_address::EthereumAddress;
use super::util::to_arr;

/// Private key length in bytes
pub const PRIVATE_KEY_BYTES: usize = 32;

/// Private key used as x in an ECDSA signature
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct EthereumPrivateKey(pub [u8; PRIVATE_KEY_BYTES]);

impl EthereumPrivateKey {
    /// Generate a new `PrivateKey` at random (`rand::OsRng`)
    pub fn gen() -> Self {
        Self::gen_custom(&mut OsRng)
    }

    /// Generate a new `PrivateKey` with given custom random generator
    pub fn gen_custom<R: Rng + ?Sized + secp256k1::rand::RngCore>(rng: &mut R) -> Self {
        EthereumPrivateKey::from(SecretKey::new(rng))
    }

    /// Extract `Address` from current private key.
    pub fn to_address(self) -> EthereumAddress {
        let key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &self.into());
        EthereumAddress::from(key)
    }
}

impl ops::Deref for EthereumPrivateKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; PRIVATE_KEY_BYTES]> for EthereumPrivateKey {
    fn from(bytes: [u8; PRIVATE_KEY_BYTES]) -> Self {
        EthereumPrivateKey(bytes)
    }
}

impl From<SecretKey> for EthereumPrivateKey {
    fn from(key: SecretKey) -> Self {
        EthereumPrivateKey(to_arr(&key[0..PRIVATE_KEY_BYTES]))
    }
}

impl Into<SecretKey> for EthereumPrivateKey {
    fn into(self) -> SecretKey {
        SecretKey::from_slice(&self).expect("Expect secret key")
    }
}

impl fmt::Display for EthereumPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}
