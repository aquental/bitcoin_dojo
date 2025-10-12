/// src/ecc/ecdsa.rs
use super::constants::SECP256K1_N;
use super::curve::Point;
use super::keys::{PrivateKey, PublicKey};
use super::scalar::Scalar;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub r: Scalar,
    pub s: Scalar,
}

/// Generate deterministic k value according to RFC 6979
/// This ensures that the same message and private key always produce the same signature
fn deterministic_k(private_key: &PrivateKey, message_hash: &[u8]) -> Scalar {
    // Convert message hash to scalar
    let mut z = Scalar::new(BigUint::from_bytes_be(message_hash));

    // Get the secp256k1 order (n)
    let n = &*SECP256K1_N;

    // Adjust z if it's >= n (reduce modulo n)
    if z.value() >= n {
        z = Scalar::new(z.value() % n);
    }

    // Convert private key and z to 32-byte arrays
    let private_key_bytes = private_key.scalar().value().to_bytes_be();
    let mut private_key_32 = [0u8; 32];
    let start_idx = if private_key_bytes.len() < 32 {
        32 - private_key_bytes.len()
    } else {
        0
    };
    private_key_32[start_idx..]
        .copy_from_slice(&private_key_bytes[private_key_bytes.len().saturating_sub(32)..]);

    let z_bytes = z.value().to_bytes_be();
    let mut z_32 = [0u8; 32];
    let z_start_idx = if z_bytes.len() < 32 {
        32 - z_bytes.len()
    } else {
        0
    };
    z_32[z_start_idx..].copy_from_slice(&z_bytes[z_bytes.len().saturating_sub(32)..]);

    // Step 1: Initialize K and V
    let mut k = vec![0u8; 32];
    let mut v = vec![1u8; 32];

    // Step 2: First HMAC round with 0x00
    let mut data = Vec::new();
    data.extend_from_slice(&v);
    data.push(0x00);
    data.extend_from_slice(&private_key_32);
    data.extend_from_slice(&z_32);

    let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
    hmac.update(&data);
    k = hmac.finalize().into_bytes().to_vec();

    // Update V
    let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
    hmac.update(&v);
    v = hmac.finalize().into_bytes().to_vec();

    // Step 3: Second HMAC round with 0x01
    let mut data = Vec::new();
    data.extend_from_slice(&v);
    data.push(0x01);
    data.extend_from_slice(&private_key_32);
    data.extend_from_slice(&z_32);

    let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
    hmac.update(&data);
    k = hmac.finalize().into_bytes().to_vec();

    // Update V
    let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
    hmac.update(&v);
    v = hmac.finalize().into_bytes().to_vec();

    // Step 4: Generate candidate k values until we find a valid one
    loop {
        // Generate V
        let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
        hmac.update(&v);
        v = hmac.finalize().into_bytes().to_vec();

        // Convert V to BigUint
        let candidate = BigUint::from_bytes_be(&v);

        // Check if candidate is in valid range [1, n-1]
        if candidate >= BigUint::from(1u32) && candidate < *n {
            return Scalar::new(candidate);
        }

        // Update K and V for next iteration
        let mut data = Vec::new();
        data.extend_from_slice(&v);
        data.push(0x00);

        let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
        hmac.update(&data);
        k = hmac.finalize().into_bytes().to_vec();

        let mut hmac = HmacSha256::new_from_slice(&k).expect("HMAC can take key of any size");
        hmac.update(&v);
        v = hmac.finalize().into_bytes().to_vec();
    }
}

/// ECDSA signature using deterministic k generation (RFC 6979)
/// This ensures that the same message and private key always produce the same signature
pub fn sign(private_key: &PrivateKey, message_hash: &[u8]) -> Signature {
    let n = &*SECP256K1_N;
    let z = Scalar::new(BigUint::from_bytes_be(message_hash));

    loop {
        // Generate deterministic k
        let k = deterministic_k(private_key, message_hash);

        // Compute R = k * G
        let g = Point::generator();
        let r_point = g.multiply(&k);

        // If R.x is None (point at infinity), try again
        let r_x = match r_point.x() {
            Some(x) => x,
            None => continue,
        };

        // r = R.x mod n
        let r = Scalar::new(r_x.unwrap());
        if r.value() == &BigUint::from(0u32) {
            continue;
        }

        // Compute s = k^(-1) * (z + r * d) mod n
        let k_inv = k.inverse().expect("k should have an inverse");
        let d = private_key.scalar();
        let r_times_d = &r * d;
        let z_plus_rd = &z + &r_times_d;
        let s = &k_inv * &z_plus_rd;

        // Ensure s is in range [1, n-1]
        if s.value() == &BigUint::from(0u32) {
            continue;
        }

        // If s > n/2, use lower s value to ensure low-s signatures (per BIP-146)
        let half_n = n >> 1;
        if s.value() > &half_n {
            return Signature {
                r,
                s: Scalar::new(n - s.value()),
            };
        }

        return Signature { r, s };
    }
}

/// Verifies an ECDSA signature for a given message hash and public key
pub fn verify(public_key: &PublicKey, message_hash: &[u8], signature: &Signature) -> bool {
    let n = &*SECP256K1_N;
    let r = &signature.r;
    let s = &signature.s;

    // Check that r and s are in the valid range [1, n-1]
    if r.value() == &BigUint::from(0u32)
        || r.value() >= n
        || s.value() == &BigUint::from(0u32)
        || s.value() >= n
    {
        return false;
    }

    // Convert message hash to scalar
    let z = Scalar::new(BigUint::from_bytes_be(message_hash));

    // Compute s^(-1)
    let s_inv = s.inverse().expect("s should have an inverse");

    // Compute u1 = z * s^(-1) mod n
    let u1 = &z * &s_inv;

    // Compute u2 = r * s^(-1) mod n
    let u2 = r * &s_inv;

    // Compute R = u1 * G + u2 * Q
    let g = Point::generator();
    let u1_g = g.multiply(&u1);
    let u2_q = public_key.point().multiply(&u2);
    let r_point = u1_g + u2_q;

    // If R is the point at infinity, the signature is invalid
    if r_point.is_infinity() {
        return false;
    }

    // Extract x-coordinate of R
    let r_x = match r_point.x() {
        Some(x) => x,
        None => return false,
    };

    // Verify that R.x mod n == r
    let r_computed = Scalar::new(r_x.unwrap());
    r_computed == *r
}
