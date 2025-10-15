/// src/ecc/field.rs
use crate::ecc::constants::SECP256K1_P;
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use num_traits::identities::Zero;
use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Div, Mul, Sub};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldElement {
    value: BigUint,
}

pub trait PowExponent {
    fn to_biguint_ref(&self) -> &BigUint;
}

impl PowExponent for u32 {
    fn to_biguint_ref(&self) -> &BigUint {
        thread_local! {
            static U32_CACHE: BigUint = BigUint::from(0u32);
        }
        U32_CACHE.with(|cache| {
            let mut cache = cache.clone();
            cache = BigUint::from(*self);
            Box::leak(Box::new(cache))
        })
    }
}

impl PowExponent for &BigUint {
    fn to_biguint_ref(&self) -> &BigUint {
        self
    }
}

impl FieldElement {
    /// Creates a new field element from a value.
    ///
    /// The value is taken modulo SECP256K1_P to ensure it is within
    /// the valid range for the field element.
    pub fn new(value: BigUint) -> Self {
        let value = value % &*SECP256K1_P;
        FieldElement { value }
    }

    /// Returns a new field element with a value of zero.
    ///
    /// This is a convenience function for creating a field element with a value of zero,
    /// which is often used as an identity element in cryptographic operations.
    ///
    /// # Returns
    ///
    /// A new field element with a value of zero.
    pub fn zero() -> Self {
        Self::new(BigUint::from(0u32))
    }

    /// Returns a new field element with a value of one.
    ///
    /// This is a convenience function for creating a field element with a value of one,
    /// which is often used as an identity element in cryptographic operations.
    ///
    /// # Returns
    ///
    /// A new field element with a value of one.
    pub fn one() -> Self {
        Self::new(BigUint::from(1u32))
    }

    /// Convenience constructor for u64 values.
    ///
    /// # Arguments
    ///
    /// * `value`: The value of the field element.
    ///
    /// # Returns
    ///
    /// A new field element with the given value.
    pub fn from_u64(value: u64) -> Self {
        Self::new(BigUint::from(value))
    }

    /// Convenience constructor for hex strings.
    ///
    /// # Arguments
    ///
    /// * `value_hex`: The value of the field element as a hex string.
    ///
    /// # Returns
    ///
    /// A new field element with the given value if the hex string is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid.
    pub fn from_hex(value_hex: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let value =
            BigUint::parse_bytes(value_hex.as_bytes(), 16).ok_or("Invalid hex string for value")?;
        Ok(Self::new(value))
    }

    /// Convenience constructor for bytes (big-endian)
    ///
    /// # Arguments
    ///
    /// * `value_bytes`: The value of the field element as a byte array.
    ///
    /// # Returns
    ///
    /// A new field element with the given value.
    pub fn from_bytes(value_bytes: &[u8]) -> Self {
        let value = BigUint::from_bytes_be(value_bytes);
        Self::new(value)
    }

    /// Converts the field element's value to bytes (big-endian).
    ///
    /// The resulting bytes can be safely used as input to cryptographic functions.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }

    /// Converts the field element's value to bytes with fixed length (big-endian, zero-padded).
    ///
    /// If the field element's value is less than the given length, it is zero-padded to the left.
    /// If the field element's value is equal to the given length, it is returned as is.
    /// If the field element's value is greater than the given length, it is truncated to the least significant bytes of the given length.
    pub fn to_bytes_fixed(&self, len: usize) -> Vec<u8> {
        let mut bytes = self.value.to_bytes_be();
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

    /// Computes the modular inverse of the field element with respect to SECP256K1_P.
    ///
    /// Uses Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p), so a^(p-2) is the inverse
    pub fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        // Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p), so a^(p-2) is the inverse
        Some(self.pow(&(&*SECP256K1_P - BigUint::from(2u32))))
    }

    /// Returns true if the field element has a value of zero, false otherwise.
    pub fn is_zero(&self) -> bool {
        self.value == BigUint::from(0u32)
    }

    /// Checking if the field element represents the zero element
    // A boolean indicating whether the field element is zero.
    pub fn is_none(&self) -> bool {
        self.value.is_zero()
    }

    pub fn is_odd(&self) -> bool {
        &self.value % BigUint::from_u32(2).unwrap() == BigUint::from_u32(1).unwrap()
    }

    /// Returns a reference to the value of the field element.
    pub fn num(&self) -> &BigUint {
        &self.value
    }

    /// Returns a reference to the value of the field element (alias for num()).
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Returns a reference to the modulus of the field element (SECP256K1_P).
    pub fn prime(&self) -> &BigUint {
        &*SECP256K1_P
    }

    /// Computes the modular square root of the field element with respect to SECP256K1_P.
    ///
    /// For secp256k1, p ≡ 3 (mod 4), so we can use the formula: x^((p+1)/4)
    ///
    /// # Returns
    ///
    /// A new field element containing the modular square root.
    pub fn sqrt(&self) -> Self {
        let exp = (&*SECP256K1_P + BigUint::from(1u32)) / BigUint::from(4u32);
        self.pow(&exp)
    }

    /// Computes the modular exponentiation of the field element with respect to SECP256K1_P.
    ///
    /// # Arguments
    ///
    /// * `exp`: The exponent, which can be a u32 or &BigUint.
    ///
    /// # Returns
    ///
    /// A new field element with value^exp mod SECP256K1_P.
    pub fn pow<E: PowExponent>(&self, exp: E) -> Self {
        let result = self.value.modpow(exp.to_biguint_ref(), &*SECP256K1_P);
        Self::new(result)
    }

    /// Returns the underlying BigUint value of the field element.
    ///
    /// This function extracts the value, which is guaranteed to be less than SECP256K1_P
    /// due to the modular reduction in the constructor.
    ///
    /// # Returns
    ///
    /// The `BigUint` value of the field element.
    pub fn unwrap(&self) -> BigUint {
        self.value.clone()
    }
}

impl fmt::Display for FieldElement {
    /// Formats the field element as "FieldElement_<prime>(<value>)".
    ///
    /// Both prime and value are represented in hexadecimal (base 16).
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FieldElement_{}", self.value.to_str_radix(16))
    }
}

impl Add for &FieldElement {
    type Output = FieldElement;

    /// Adds two field elements together, taking the result modulo SECP256K1_P.
    ///
    /// # Returns
    ///
    /// A new field element with the result of the addition modulo SECP256K1_P.
    fn add(self, other: Self) -> FieldElement {
        let value = (&self.value + &other.value) % &*SECP256K1_P;
        FieldElement { value }
    }
}

impl Add for FieldElement {
    type Output = FieldElement;

    fn add(self, other: Self) -> FieldElement {
        &self + &other
    }
}

// New implementation for FieldElement + &FieldElement
impl Add<&FieldElement> for FieldElement {
    type Output = FieldElement;

    /// Adds an owned field element and a borrowed field element, taking the result modulo SECP256K1_P.
    ///
    /// # Returns
    ///
    /// A new field element with the result of the addition modulo SECP256K1_P.
    fn add(self, other: &FieldElement) -> FieldElement {
        &self + other
    }
}

// New implementation for &FieldElement + FieldElement
impl Add<FieldElement> for &FieldElement {
    type Output = FieldElement;

    /// Adds a borrowed field element and an owned field element, taking the result modulo SECP256K1_P.
    ///
    /// # Returns
    ///
    /// A new field element with the result of the addition modulo SECP256K1_P.
    fn add(self, other: FieldElement) -> FieldElement {
        self + &other
    }
}

// Sub implementation
impl Sub for &FieldElement {
    type Output = FieldElement;

    /// Subtracts two field elements together, taking the result modulo SECP256K1_P.
    ///
    /// # Returns
    ///
    /// A new field element with the result of the subtraction modulo SECP256K1_P.
    fn sub(self, other: Self) -> FieldElement {
        // Compute (self.value - other.value) mod SECP256K1_P
        // If self.value < other.value, add SECP256K1_P to ensure non-negative result
        let value = if self.value >= other.value {
            (&self.value - &other.value) % &*SECP256K1_P
        } else {
            (&self.value + &*SECP256K1_P - &other.value) % &*SECP256K1_P
        };
        FieldElement { value }
    }
}

impl Sub for FieldElement {
    type Output = FieldElement;

    fn sub(self, other: Self) -> FieldElement {
        &self - &other
    }
}

// Mul implementation for FieldElement * FieldElement
impl Mul for &FieldElement {
    type Output = FieldElement;

    /// Multiplies two field elements together, taking the result modulo SECP256K1_P.
    ///
    /// # Returns
    ///
    /// A new field element with the result of the multiplication modulo SECP256K1_P.
    fn mul(self, other: Self) -> FieldElement {
        let value = (&self.value * &other.value) % &*SECP256K1_P;
        FieldElement { value }
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: Self) -> FieldElement {
        &self * &other
    }
}

// Mul implementation for FieldElement * u32
impl Mul<u32> for &FieldElement {
    type Output = FieldElement;

    /// Multiplies a field element by an unsigned 32-bit integer, taking the result modulo SECP256K1_P.
    ///
    /// # Returns
    ///
    /// A new field element with the result of the multiplication modulo SECP256K1_P.
    fn mul(self, other: u32) -> FieldElement {
        let other_value = BigUint::from(other);
        let value = (&self.value * other_value) % &*SECP256K1_P;
        FieldElement { value }
    }
}

impl Mul<u32> for FieldElement {
    type Output = FieldElement;

    fn mul(self, other: u32) -> FieldElement {
        &self * other
    }
}

// Div implementation
impl Div for &FieldElement {
    type Output = FieldElement;

    /// Divides a field element by another field element, taking the result modulo SECP256K1_P.
    ///
    /// # Panics
    ///
    /// This function will panic if the second field element is zero.
    ///
    /// # Returns
    ///
    /// A new field element with the result of the division modulo SECP256K1_P.
    fn div(self, other: Self) -> FieldElement {
        let other_inv = other.inverse().expect("Division by zero");
        let value = (&self.value * &other_inv.value) % &*SECP256K1_P;
        FieldElement { value }
    }
}

impl Div for FieldElement {
    type Output = FieldElement;

    fn div(self, other: Self) -> FieldElement {
        &self / &other
    }
}

pub trait Pow<T> {
    type Output;
    fn pow(self, exp: T) -> Self::Output;
}

// Pow implementation for &BigUint exponent
impl Pow<&BigUint> for &FieldElement {
    type Output = FieldElement;

    /// Computes the modular exponentiation of the field element with respect to SECP256K1_P.
    ///
    /// # Returns
    ///
    /// A new field element with the result of the modular exponentiation modulo SECP256K1_P.
    fn pow(self, exp: &BigUint) -> Self::Output {
        let value = self.value.modpow(exp, &*SECP256K1_P);
        FieldElement { value }
    }
}

// Pow implementation for BigUint exponent
impl Pow<BigUint> for &FieldElement {
    type Output = FieldElement;

    /// Computes the modular exponentiation of the field element with respect to SECP256K1_P.
    ///
    /// # Returns
    ///
    /// A new field element with the result of the modular exponentiation modulo SECP256K1_P.
    fn pow(self, exp: BigUint) -> Self::Output {
        let value = self.value.modpow(&exp, &*SECP256K1_P);
        FieldElement { value }
    }
}

// Pow implementation for u32 exponent
impl Pow<u32> for &FieldElement {
    type Output = FieldElement;

    /// Computes the modular exponentiation of the field element with respect to SECP256K1_P.
    ///
    /// # Returns
    ///
    /// A new field element with the result of the modular exponentiation modulo SECP256K1_P.
    fn pow(self, exp: u32) -> Self::Output {
        let exp_biguint = BigUint::from(exp);
        let value = self.value.modpow(&exp_biguint, &*SECP256K1_P);
        FieldElement { value }
    }
}
