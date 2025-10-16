/// src/utils/base58.rs

use crate::utils::hash256::hash256;
use num_bigint::BigUint;
use num_traits::Zero;

// Base58 alphabet (Bitcoin's alphabet, excludes 0, O, I, and l)
const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encodes a byte array into Base58 format
/// Base58 is used in Bitcoin to encode addresses and other data
/// It uses an alphabet that excludes confusing characters (0, O, I, l)
pub fn encode_base58(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    
    // Count leading zeros
    let leading_zeros = input.iter().take_while(|&&x| x == 0).count();
    
    // If all bytes are zero, return a string of '1's
    if leading_zeros == input.len() {
        return "1".repeat(leading_zeros);
    }
    
    // Convert bytes to BigUint (skip leading zeros for efficiency)
    let mut num = BigUint::from_bytes_be(&input[leading_zeros..]);
    
    // Convert to base58
    let mut encoded = Vec::new();
    let base = BigUint::from(58u32);
    
    while !num.is_zero() {
        let remainder = &num % &base;
        num /= &base;
        let digits = remainder.to_u32_digits();
        let idx = if digits.is_empty() { 0 } else { digits[0] } as usize;
        encoded.push(BASE58_ALPHABET.chars().nth(idx).unwrap());
    }
    
    // Add '1' for each leading zero byte
    for _ in 0..leading_zeros {
        encoded.push('1');
    }
    
    // Reverse the result (we built it backwards)
    encoded.reverse();
    encoded.into_iter().collect()
}

/// Decodes a Base58 encoded string back to bytes
/// Returns an error if the input contains invalid Base58 characters
pub fn decode_base58(input: &str) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    
    // Count leading '1's (which represent leading zero bytes)
    let leading_ones = input.chars().take_while(|&c| c == '1').count();
    
    // Convert from base58 to BigUint
    let mut num = BigUint::zero();
    let base = BigUint::from(58u32);
    
    for c in input.chars() {
        let idx = BASE58_ALPHABET.find(c)
            .ok_or("Invalid character: not in Base58 alphabet")?;
        num = num * &base + BigUint::from(idx);
    }
    
    // Convert BigUint to bytes
    let mut bytes = num.to_bytes_be();
    
    // Add leading zeros for each leading '1'
    let mut result = vec![0u8; leading_ones];
    result.append(&mut bytes);
    
    // Special case: if input is all '1's, we might have added extra bytes
    if input.chars().all(|c| c == '1') {
        result.truncate(leading_ones);
    }
    
    Ok(result)
}

/// Encodes a byte array into Base58Check format
/// Base58Check adds a 4-byte checksum to the data before encoding
/// This is used in Bitcoin for addresses, private keys, and other critical data
/// The checksum is the first 4 bytes of SHA256(SHA256(data))
pub fn encode_base58_check(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    
    // Calculate checksum: first 4 bytes of hash256(data)
    let checksum = &hash256(input)[..4];
    
    // Concatenate data and checksum
    let mut data_with_checksum = input.to_vec();
    data_with_checksum.extend_from_slice(checksum);
    
    // Encode as Base58
    encode_base58(&data_with_checksum)
}

/// Decodes a Base58Check encoded string back to the original data
/// Base58Check includes a 4-byte checksum that is verified during decoding
/// Returns an error if the input is invalid or the checksum doesn't match
pub fn decode_base58_check(input: &str) -> Result<Vec<u8>, &'static str> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    
    // First decode from Base58
    let decoded = decode_base58(input)?;
    
    // Need at least 4 bytes for the checksum
    if decoded.len() < 4 {
        return Err("Base58Check data too short: must be at least 4 bytes");
    }
    
    // Split data and checksum
    let (data, checksum) = decoded.split_at(decoded.len() - 4);
    
    // Calculate expected checksum
    let expected_checksum = &hash256(data)[..4];
    
    // Verify checksum
    if checksum != expected_checksum {
        return Err("Base58Check checksum verification failed");
    }
    
    Ok(data.to_vec())
}
