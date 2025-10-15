use crate::ecc::util::sha256;

/// Performs HASH160 = RIPEMD160(SHA256(data))
/// This is used in Bitcoin for generating addresses from public keys
pub fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::{Ripemd160, Digest};
    
    let sha256_hash = sha256(data);
    let mut hasher = Ripemd160::new();
    hasher.update(sha256_hash);
    let result = hasher.finalize();
    
    let mut output = [0u8; 20];
    output.copy_from_slice(&result);
    output
}