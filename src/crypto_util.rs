use sha3::{Digest, Keccak256};
/// Keccak-256 crypto hash length in bytes
pub const KECCAK256_BYTES: usize = 32;

/// Calculate Keccak-256 crypto hash
pub fn keccak256(data: &[u8]) -> [u8; KECCAK256_BYTES] {
    let mut keccak = Keccak256::default();
    keccak.update(data);
    let mut out = [0u8; KECCAK256_BYTES];
    out.copy_from_slice(&keccak.finalize()[..]);
    out
}
