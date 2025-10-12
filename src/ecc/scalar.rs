/// src/ecc/scalar.rs
use crate::ecc::constants::SECP256K1_N;
use crate::ecc::util::secure_random_scalar;
use num_bigint::BigUint;
use std::fmt;
use std::ops::{Add, Mul, Sub};

#[derive(Debug, Clone, PartialEq)]
pub struct Scalar {
    pub value: BigUint,
}

impl Scalar {
    /// Creates a new scalar from a value.
    ///
    /// The value is taken modulo SECP256K1_N to ensure it is within
    /// the valid range for the scalar.
    pub fn new(value: BigUint) -> Self {
        Self {
            value: value % &*SECP256K1_N,
        }
    }
    
    /// Generates a random scalar using a cryptographically secure random number generator.
    ///
    /// The generated scalar will be in the range (0, SECP256K1_N).
    ///
    /// # Returns
    ///
    /// A new scalar with a random value.
    pub fn random() -> Self {
        Self {
            value: secure_random_scalar(),
        }
    }

    /// Computes the modular inverse of the scalar value with respect to SECP256K1_N.
    ///
    /// returns Some(s) where s is the modular inverse of the scalar value if it exists,
    /// otherwise returns None.
    pub fn inverse(&self) -> Option<Self> {
        let (gcd, inv) = extended_gcd_for_inverse(self.value.clone(), SECP256K1_N.clone());
        if gcd == BigUint::from(1u32) {
            Some(Scalar::new(inv))
        } else {
            None
        }
    }

    /// Converts the scalar value to bytes (big-endian) and zero-pads to a fixed length of 32 bytes.
    ///
    /// If the scalar value is less than 32 bytes, it is zero-padded to the right.
    /// If the scalar value is 32 bytes or more, it is truncated to the leftmost 32 bytes.
    ///
    /// The resulting bytes can be safely used as input to cryptographic functions.
    pub fn as_bytes(&self) -> [u8; 32] {
        let bytes = self.value.to_bytes_be();
        let mut result = [0u8; 32];
        let start = 32 - bytes.len();
        result[start..].copy_from_slice(&bytes);
        result
    }

    /// Creates a new scalar from a 32-byte big-endian byte array.
    ///
    /// The byte array is interpreted as a big-endian unsigned integer, and
    /// the resulting scalar value is taken modulo SECP256K1_N to ensure it is within
    /// the valid range for the scalar.
    ///
    /// # Arguments
    ///
    /// * `bytes`: A 32-byte big-endian byte array representing the scalar value.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let value = BigUint::from_bytes_be(bytes);
        Self::new(value)
    }

    /// Returns a new scalar with a value of zero.
    ///
    /// This is a convenience function for creating a scalar with a value of zero,
    /// which is often used as an identity element in cryptographic operations.
    ///
    /// # Returns
    ///
    /// A new scalar with a value of zero.
    pub fn zero() -> Self {
        Self::new(BigUint::from(0u32))
    }

    /// Returns a new scalar with a value of one.
    ///
    /// This is a convenience function for creating a scalar with a value of one,
    /// which is often used as an identity element in cryptographic operations.
    ///
    /// # Returns
    ///
    /// A new scalar with a value of one.
    pub fn one() -> Self {
        Self::new(BigUint::from(1u32))
    }

    /// Returns a reference to the value of the scalar.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Returns a reference to the modulus of the scalar (SECP256K1_N).
    pub fn modulus(&self) -> &BigUint {
        &*SECP256K1_N
    }
}

/// Computes the modular inverse of the scalar value with respect to the modulus n.
/// Extended Euclidean Algorithm for modular inverse.
///
/// returns (gcd, x) where x is the modular inverse of a mod m.
///
/// If a has no inverse modulo m, returns (gcd, 0).
fn extended_gcd_for_inverse(a: BigUint, m: BigUint) -> (BigUint, BigUint) {
    if a == BigUint::from(0u32) {
        return (m, BigUint::from(0u32));
    }

    let mut old_r = a.clone();
    let mut r = m.clone();
    let mut old_s = BigUint::from(1u32);
    let mut s = BigUint::from(0u32);
    let mut old_s_neg = false;
    let mut s_neg = false;

    while r != BigUint::from(0u32) {
        let quotient = &old_r / &r;

        // Update r
        let temp_r = r.clone();
        r = &old_r - &quotient * &r;
        old_r = temp_r;

        // Update s (handling signs)
        let temp_s = s.clone();
        let temp_s_neg = s_neg;

        let product = &quotient * &s;
        if old_s_neg == s_neg {
            if old_s >= product {
                s = &old_s - &product;
                s_neg = old_s_neg;
            } else {
                s = &product - &old_s;
                s_neg = !old_s_neg;
            }
        } else {
            s = &old_s + &product;
            s_neg = old_s_neg;
        }

        old_s = temp_s;
        old_s_neg = temp_s_neg;
    }

    // If old_s is negative, convert to positive equivalent
    let result = if old_s_neg {
        &m - (&old_s % &m)
    } else {
        old_s % &m
    };

    (old_r, result)
}

impl fmt::Display for Scalar {
    /// Formats the scalar as "Scalar(<value>)".
    ///
    /// The value is represented in hexadecimal (base 16).
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Scalar({})",
            self.value.to_str_radix(16)
        )
    }
}

// Implement arithmetic traits
impl Add for Scalar {
    type Output = Self;

    /// Adds two scalars together, taking the result modulo SECP256K1_N.
    ///
    /// # Returns
    ///
    /// A new scalar with the result of the addition modulo SECP256K1_N.
    fn add(self, other: Self) -> Self {
        let result = (&self.value + &other.value) % &*SECP256K1_N;
        Scalar::new(result)
    }
}

impl Add for &Scalar {
    type Output = Scalar;

    /// Adds two scalars together, taking the result modulo SECP256K1_N.
    ///
    /// # Returns
    ///
    /// A new scalar with the result of the addition modulo SECP256K1_N.
    fn add(self, other: &Scalar) -> Scalar {
        let result = (&self.value + &other.value) % &*SECP256K1_N;
        Scalar::new(result)
    }
}

impl Sub for Scalar {
    type Output = Self;

    /// Subtracts two scalars together, taking the result modulo SECP256K1_N.
    ///
    /// # Returns
    ///
    /// A new scalar with the result of the subtraction modulo SECP256K1_N.
    fn sub(self, other: Self) -> Self {
        let result = if self.value >= other.value {
            (&self.value - &other.value) % &*SECP256K1_N
        } else {
            (&self.value + &*SECP256K1_N - &other.value) % &*SECP256K1_N
        };
        Scalar::new(result)
    }
}

impl Sub for &Scalar {
    type Output = Scalar;

    /// Subtracts two scalars together, taking the result modulo SECP256K1_N.
    ///
    /// # Returns
    ///
    /// A new scalar with the result of the subtraction modulo SECP256K1_N.
    fn sub(self, other: &Scalar) -> Scalar {
        let result = if self.value >= other.value {
            (&self.value - &other.value) % &*SECP256K1_N
        } else {
            (&self.value + &*SECP256K1_N - &other.value) % &*SECP256K1_N
        };
        Scalar::new(result)
    }
}

impl Mul for Scalar {
    type Output = Self;

    /// Multiplies two scalars together, taking the result modulo SECP256K1_N.
    ///
    /// # Returns
    ///
    /// A new scalar with the result of the multiplication modulo SECP256K1_N.
    fn mul(self, other: Self) -> Self {
        let result = (&self.value * &other.value) % &*SECP256K1_N;
        Scalar::new(result)
    }
}

impl Mul for &Scalar {
    type Output = Scalar;

    /// Multiplies two scalars together, taking the result modulo SECP256K1_N.
    ///
    /// # Returns
    ///
    /// A new scalar with the result of the multiplication modulo SECP256K1_N.
    fn mul(self, other: &Scalar) -> Scalar {
        let result = (&self.value * &other.value) % &*SECP256K1_N;
        Scalar::new(result)
    }
}
