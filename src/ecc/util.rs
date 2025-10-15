/// src/ecc/util.rs
use rand::RngCore;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use sha2::Sha256;

/// Computes the SHA-256 hash of the given input data and returns the result as a 32-byte array.
///
/// The input data is arbitrary and can be of any length. The output hash will always be 32 bytes.
///
/// # Example
///
///
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Securely generate random bytes of a given length.
///
/// This function uses the system's cryptographically secure random number generator
/// to generate random bytes. It is suitable for generating keys, nonces, and
/// other cryptographic materials.
///
/// # Panics
///
/// If the system's random number generator fails for any reason, this function
/// will panic. This is a deliberate choice to ensure that the generated random
/// numbers are secure.
///
/// # Example
///
///
pub fn secure_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

pub fn secure_random_scalar() -> num_bigint::BigUint {
    use super::constants::SECP256K1_N;
    loop {
        let bytes = secure_random_bytes(32);
        let candidate = num_bigint::BigUint::from_bytes_be(&bytes);
        if candidate < *SECP256K1_N && candidate > num_bigint::BigUint::from(0u32) {
            return candidate;
        }
    }
}

/// Computes the HASH256 (double SHA256) of the given input data.
///
/// HASH256 is defined as SHA256(SHA256(data)) and is commonly used in Bitcoin
/// for transaction IDs, block hashes, and other cryptographic operations.
/// The output is always 32 bytes.
///
/// # Example
///
/// ```
/// use bitcoin_dojo::ecc::util::hash256;
///
/// let data = b"hello world";
/// let hash = hash256(data);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn hash256(data: &[u8]) -> [u8; 32] {
    // First SHA256
    let first_hash = sha256(data);

    // Second SHA256 on the result
    sha256(&first_hash)
}

/// Computes the HASH160 of the given input data.
///
/// HASH160 is defined as RIPEMD160(SHA256(data)) and is commonly used in Bitcoin
/// for generating addresses from public keys. The output is always 20 bytes.
///
/// # Example
///
/// ```
/// use bitcoin_dojo::ecc::util::hash160;
///
/// let data = b"hello world";
/// let hash = hash160(data);
/// assert_eq!(hash.len(), 20);
/// ```
pub fn hash160(data: &[u8]) -> [u8; 20] {
    // First compute SHA256
    let sha256_hash = sha256(data);

    // Then compute RIPEMD160 of the SHA256 hash
    let mut hasher = Ripemd160::new();
    hasher.update(sha256_hash);
    hasher.finalize().into()
}
