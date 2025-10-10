/// src/ecc/util.rs
use rand::RngCore;
use sha2::{Digest, Sha256};

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
