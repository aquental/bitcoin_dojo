use crate::ecc::util::sha256;

/// Performs double SHA-256 hashing (hash256 = SHA256(SHA256(data)))
/// This is commonly used in Bitcoin for block hashes and transaction IDs
pub fn hash256(data: &[u8]) -> [u8; 32] {
    let first_hash = sha256(data);
    sha256(&first_hash)
}