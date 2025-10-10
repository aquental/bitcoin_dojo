use crate::ecc::constants::SECP256K1_P;
/// src/ecc/field.rs
use num_bigint::BigUint;
use num_traits::identities::Zero;
use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Div, Mul, Sub};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldElement {
    num: BigUint,
    prime: BigUint,
    //??
    //value: BigUint,
}

impl FieldElement {
    /// Creates a new field element from a value and modulus.
    ///
    /// The value is taken modulo the modulus to ensure it is within
    /// the valid range for the field element.
    ///
    /// # Panics
    ///
    /// Panics if the value is not in the range 0 to `prime - 1`.
    pub fn new(num: BigUint, prime: BigUint) -> Self {
        if num >= prime {
            panic!("num not in range 0 to {}", prime - BigUint::from(1u32));
        }
        FieldElement { num, prime }
    }

    /// Returns a new field element with a value of zero and the given modulus.
    ///
    /// This is a convenience function for creating a field element with a value of zero,
    /// which is often used as an identity element in cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `prime`: The modulus of the field element.
    ///
    /// # Returns
    ///
    /// A new field element with a value of zero and the given modulus.
    pub fn zero(prime: BigUint) -> Self {
        Self::new(BigUint::from(0u32), prime)
    }
    /// Returns a new field element with a value of one and the given modulus.
    ///
    /// This is a convenience function for creating a field element with a value of one,
    /// which is often used as an identity element in cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `prime`: The modulus of the field element.
    ///
    /// # Returns
    ///
    /// A new field element with a value of one and the given modulus.
    pub fn one(prime: BigUint) -> Self {
        Self::new(BigUint::from(1u32), prime)
    }

    /// Convenience constructor for u64 values.
    ///
    /// # Arguments
    ///
    /// * `num`: The value of the field element.
    /// * `prime`: The modulus of the field element.
    ///
    /// # Returns
    ///
    /// A new field element with the given value and modulus.
    pub fn from_u64(num: u64, prime: u64) -> Self {
        Self::new(BigUint::from(num), BigUint::from(prime))
    }

    /// Convenience constructor for hex strings.
    ///
    /// # Arguments
    ///
    /// * `num_hex`: The value of the field element as a hex string.
    /// * `prime_hex`: The modulus of the field element as a hex string.
    ///
    /// # Returns
    ///
    /// A new field element with the given value and modulus if the hex strings are valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex strings are invalid.
    pub fn from_hex(num_hex: &str, prime_hex: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let num =
            BigUint::parse_bytes(num_hex.as_bytes(), 16).ok_or("Invalid hex string for num")?;
        let prime =
            BigUint::parse_bytes(prime_hex.as_bytes(), 16).ok_or("Invalid hex string for prime")?;
        Ok(Self::new(num, prime))
    }

    /// Convenience constructor for bytes (big-endian)
    ///
    /// # Arguments
    ///
    /// * `num_bytes`: The value of the field element as a byte array.
    /// * `prime_bytes`: The modulus of the field element as a byte array.
    ///
    /// # Returns
    ///
    /// A new field element with the given value and modulus.
    ///
    pub fn from_bytes(num_bytes: &[u8], prime_bytes: &[u8]) -> Self {
        let num = BigUint::from_bytes_be(num_bytes);
        let prime = BigUint::from_bytes_be(prime_bytes);
        Self::new(num, prime)
    }

    /// Convenience constructor for creating from num bytes with known prime.
    ///
    /// # Arguments
    ///
    /// * `num_bytes`: The value of the field element as a byte array.
    /// * `prime`: The modulus of the field element.
    ///
    /// # Returns
    ///
    /// A new field element with the given value and modulus.
    pub fn from_num_bytes(num_bytes: &[u8], prime: BigUint) -> Self {
        let num = BigUint::from_bytes_be(num_bytes);
        Self::new(num, prime)
    }

    /// Converts the field element's num to bytes (big-endian).
    ///
    /// The resulting bytes can be safely used as input to cryptographic functions.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.num.to_bytes_be()
    }

    /// Converts the field element's num to bytes with fixed length (big-endian, zero-padded).
    ///
    /// If the field element's num is less than the given length, it is zero-padded to the right.
    /// If the field element's num is equal to the given length, it is returned as is.
    /// If the field element's num is greater than the given length, it is truncated to the least significant bytes of the given length.
    pub fn to_bytes_fixed(&self, len: usize) -> Vec<u8> {
        let mut bytes = self.num.to_bytes_be();
        match bytes.len().cmp(&len) {
            Ordering::Less => {
                let mut padded = vec![0u8; len - bytes.len()];
                padded.extend(bytes);
                padded
            }
            Ordering::Greater => {
                // Take the least significant bytes if the number is too large
                bytes.split_off(bytes.len() - len)
            }
            Ordering::Equal => bytes,
        }
    }

    /// Converts both the field element's num and prime to bytes (big-endian) and returns them as a tuple.
    ///
    /// # Returns
    ///
    /// A tuple containing the field element's num and prime as byte arrays.
    pub fn to_bytes_with_prime(&self) -> (Vec<u8>, Vec<u8>) {
        (self.num.to_bytes_be(), self.prime.to_bytes_be())
    }

    /// Computes the modular inverse of the field element with respect to the modulus prime.
    ///
    /// uses Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p), so a^(p-2) is the inverse
    ///
    pub fn inverse(&self) -> Self {
        // Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p), so a^(p-2) is the inverse
        self.pow(&self.prime - BigUint::from(2u32))
    }

    /// Returns true if the field element has a value of zero, false otherwise.
    pub fn is_zero(&self) -> bool {
        self.num == BigUint::from(0u32)
    }

    /// Returns a reference to the value of the field element.
    pub fn num(&self) -> &BigUint {
        &self.num
    }

    /// Returns a reference to the modulus of the field element.
    pub fn prime(&self) -> &BigUint {
        &self.prime
    }

    /// Computes the modular square root of the field element with respect to the modulus prime.
    ///
    /// uses the formula: a^((p+1)/4) ≡ ±√a (mod p)
    ///
    /// # Returns
    ///
    /// A new field element containing the modular square root of the original field element's num and the same modulus prime.
    pub fn sqrt(&self) -> Self {
        let exp = (&self.prime + BigUint::from(1u32)) / BigUint::from(4u32);
        let result = self.num.modpow(&exp, &self.prime);
        Self::new(result, self.prime.clone())
    }
}

impl fmt::Display for FieldElement {
    /// Formats the field element as "FieldElement_num_<num>_prime_<prime>".
    ///
    /// The num and prime are represented in hexadecimal (base 16).
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "FieldElement_num_{}_prime_{}",
            self.num.to_str_radix(16),
            self.prime.to_str_radix(16)
        )
    }
}

impl Add for &FieldElement {
    type Output = FieldElement;

    /// Adds two field elements together, taking the result modulo the modulus.
    ///
    /// # Panics
    ///
    /// This function will panic if the two field elements have different moduli.
    ///
    /// # Examples
    ///
    ///
    /// # Returns
    ///
    /// A new field element with the result of the addition modulo the modulus.

    fn add(self, other: Self) -> FieldElement {
        if self.prime != other.prime {
            panic!("Cannot add two numbers in different fields")
        }
        let num = (&self.num + &other.num) % &self.prime;
        FieldElement {
            num,
            prime: self.prime.clone(),
        }
    }
}

// Sub implementation
impl Sub for &FieldElement {
    type Output = FieldElement;

    /// Subtracts two field elements together, taking the result modulo the modulus.
    ///
    /// # Panics
    ///
    /// This function will panic if the two field elements have different moduli.
    ///
    /// # Examples
    ///
    ///
    /// # Returns
    ///
    /// A new field element with the result of the subtraction modulo the modulus.
    fn sub(self, other: Self) -> FieldElement {
        if self.prime != other.prime {
            panic!("Cannot subtract two numbers in different fields");
        }
        // Compute (self.num - other.num) mod prime
        // If self.num < other.num, add prime to ensure non-negative result
        let num = if self.num >= other.num {
            (&self.num - &other.num) % &self.prime
        } else {
            (&self.num + &self.prime - &other.num) % &self.prime
        };
        FieldElement {
            num,
            prime: self.prime.clone(),
        }
    }
}

// Mul implementation for FieldElement * FieldElement
impl Mul for &FieldElement {
    type Output = FieldElement;

    /// Multiplies two field elements together, taking the result modulo the modulus.
    ///
    /// # Panics
    ///
    /// This function will panic if the two field elements have different moduli.
    ///
    /// # Examples
    ///
    ///
    /// # Returns
    ///
    /// A new field element with the result of the multiplication modulo the modulus.
    fn mul(self, other: Self) -> FieldElement {
        if self.prime != other.prime {
            panic!("Cannot multiply two numbers in different fields");
        }
        let num = (&self.num * &other.num) % &self.prime;
        FieldElement {
            num,
            prime: self.prime.clone(),
        }
    }
}

// Mul implementation for FieldElement * u32
impl Mul<u32> for &FieldElement {
    type Output = FieldElement;

    /// Multiplies a field element by an unsigned 32-bit integer, taking the result modulo the modulus.
    ///
    /// # Panics
    ///
    /// This function will panic if the two field elements have different moduli.
    ///
    /// # Examples
    ///
    ///
    /// # Returns
    ///
    /// A new field element with the result of the multiplication modulo the modulus.
    fn mul(self, other: u32) -> FieldElement {
        let other_num = BigUint::from(other);
        let num = (&self.num * other_num) % &self.prime;
        FieldElement {
            num,
            prime: self.prime.clone(),
        }
    }
}

// Div implementation
impl Div for &FieldElement {
    type Output = FieldElement;

    /// Divides a field element by another field element, taking the result modulo the modulus.
    ///
    /// # Panics
    ///
    /// This function will panic if the two field elements have different moduli or if the second field element is zero.
    ///
    /// # Examples
    ///
    ///
    /// # Returns
    ///
    /// A new field element with the result of the division modulo the modulus.
    fn div(self, other: Self) -> FieldElement {
        if self.prime != other.prime {
            panic!("Cannot divide two numbers in different fields");
        }
        if other.num.is_zero() {
            panic!("Division by zero");
        }
        // Division is multiplication by the inverse: a / b = a * b^(-1)
        let other_inv = other.inverse();
        let num = (&self.num * &other_inv.num) % &self.prime;
        FieldElement {
            num,
            prime: self.prime.clone(),
        }
    }
}

pub trait Pow<T> {
    type Output;
    fn pow(self, exp: T) -> Self::Output;
}

// Pow implementation for &BigUint exponent
impl Pow<&BigUint> for &FieldElement {
    type Output = FieldElement;

    /// Computes the modular exponentiation of the field element with respect to the modulus prime.
    ///
    /// # Examples
    ///
    ///
    /// # Returns
    ///
    /// A new field element with the result of the modular exponentiation modulo the modulus.
    fn pow(self, exp: &BigUint) -> Self::Output {
        let num = self.num.modpow(exp, &self.prime);
        FieldElement {
            num,
            prime: self.prime.clone(),
        }
    }
}

// Pow implementation for BigUint exponent
impl Pow<BigUint> for &FieldElement {
    type Output = FieldElement;

    /// Computes the modular exponentiation of the field element with respect to the modulus prime.
    ///
    /// # Examples
    ///
    ///
    /// # Returns
    ///
    /// A new field element with the result of the modular exponentiation modulo the modulus.
    fn pow(self, exp: BigUint) -> Self::Output {
        let num = self.num.modpow(&exp, &self.prime);
        FieldElement {
            num,
            prime: self.prime.clone(),
        }
    }
}

// Pow implementation for u32 exponent
impl Pow<u32> for &FieldElement {
    type Output = FieldElement;

    /// Computes the modular exponentiation of the field element with respect to the modulus prime.
    ///
    /// # Examples
    ///
    ///
    /// # Returns
    ///
    /// A new field element with the result of the modular exponentiation modulo the modulus.
    fn pow(self, exp: u32) -> Self::Output {
        let exp_biguint = BigUint::from(exp);
        let num = self.num.modpow(&exp_biguint, &self.prime);
        FieldElement {
            num,
            prime: self.prime.clone(),
        }
    }
}
