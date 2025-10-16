use num_bigint::BigUint;
use num_traits::FromPrimitive;

use crate::ecc::constants::SECP256K1_B_FE_OPT;
use crate::ecc::field::FieldElement;
use crate::utils::address_types::{AddressType, Network};
use crate::utils::base58::encode_base58_check;
use crate::utils::hash160::hash160;

use super::curve::Point;
/// src/ecc/keys.rs
use super::scalar::Scalar;

#[derive(Debug, Clone)]
pub struct PrivateKey {
    scalar: Scalar,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey {
    point: Point,
}

impl PrivateKey {
    /// Generates a new private key using a cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A new private key with a random value.
    pub fn new() -> Self {
        Self {
            scalar: Scalar::random(),
        }
    }

    /// Creates a new private key from a scalar value.
    ///
    /// # Arguments
    ///
    /// * `scalar`: The scalar value to use for the private key.
    ///
    /// # Returns
    ///
    /// A new private key with the given scalar value.
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self { scalar }
    }

    /// Returns the public key corresponding to the private key.
    ///
    /// This function multiplies the generator point of the secp256k1 curve by the scalar value of the private key,
    /// and returns the resulting point as the public key.
    ///
    /// # Returns
    ///
    /// A new public key with the computed point.
    pub fn public_key(&self) -> PublicKey {
        let g = Point::generator();
        let point = std::ops::Mul::mul(g, &self.scalar);
        PublicKey { point }
    }

    /// Returns a reference to the scalar value of the private key.
    ///
    /// This value is the secret key used for signing transactions and generating public keys.
    ///
    /// Note that this value should not be shared with anyone, as it can be used to access and control the associated Bitcoin wallet.
    pub fn scalar(&self) -> &Scalar {
        &self.scalar
    }

    /// Convert private key to Wallet Import Format (WIF)
    ///
    /// WIF is a Base58Check encoded format for Bitcoin private keys
    ///
    /// `compressed`: if true, indicates the public key should be compressed
    ///
    /// # Arguments
    ///
    /// * `network`: The network to use for the WIF (mainnet, testnet, or regtest)
    /// * `compressed`: Whether to use compressed SEC format (true) or uncompressed SEC format (false)
    ///
    /// # Returns
    ///
    /// A string representing the WIF private key
    pub fn to_wif(&self, network: Network, compressed: bool) -> String {
        // Get the version byte based on network
        let version_byte = network.wif_version();

        // Get the private key bytes (32 bytes)
        let private_key_bytes = self.scalar.as_bytes();

        // Build the payload
        let mut payload = vec![version_byte];
        payload.extend_from_slice(&private_key_bytes);

        // If compressed, append 0x01 byte
        if compressed {
            payload.push(0x01);
        }

        // Encode with Base58Check
        encode_base58_check(&payload)
    }
}

impl Default for PrivateKey {
    /// Returns a new private key with a default value of zero.
    ///
    /// The default value is used as a placeholder for the private key when the actual value is unknown or not applicable.
    ///
    /// # Returns
    ///
    /// A new private key with a default value of zero.
    fn default() -> Self {
        Self::new()
    }
}

impl PublicKey {
    /// Returns a reference to the point on the elliptic curve that represents the public key.
    pub fn point(&self) -> &Point {
        &self.point
    }

    /// Serialize the public key in SEC format
    ///
    /// Returns a 33-byte array for compressed format or 65-byte Vec for uncompressed format
    ///
    /// Compressed format: [0x02/0x03, x_coordinate (32 bytes)]
    /// Uncompressed format: [0x04, x_coordinate (32 bytes), y_coordinate (32 bytes)]
    ///
    /// # Panics
    ///
    /// Panics if the input point is at infinity (invalid for SEC format).
    pub fn to_sec(&self, compressed: bool) -> Vec<u8> {
        let mut result = Vec::new();

        // Check if point has valid coordinates (not point at infinity)
        match (&self.point.x(), &self.point.y()) {
            (Some(x), Some(y)) => {
                if compressed {
                    // Compressed format: [0x02/0x03, x_coordinate (32 bytes)]
                    let prefix = if y.is_odd() { 0x03 } else { 0x02 };
                    result.push(prefix);
                    result.extend_from_slice(&x.to_bytes_fixed(32));
                } else {
                    // Uncompressed format: [0x04, x_coordinate (32 bytes), y_coordinate (32 bytes)]
                    result.push(0x04);
                    result.extend_from_slice(&x.to_bytes_fixed(32));
                    result.extend_from_slice(&y.to_bytes_fixed(32));
                }
            }
            _ => {
                // Handle point at infinity (return empty vec or panic, depending on requirements)
                // For SEC format, point at infinity is typically invalid
                panic!("Cannot serialize point at infinity to SEC format");
            }
        }

        result
    }

    /// Serialize the public key in compressed SEC format
    /// Returns a 33-byte Vec: [0x02/0x03, x_coordinate (32 bytes)]
    /// 0x02 if y is even, 0x03 if y is odd
    ///
    /// # Panics
    ///
    /// Panics if the input point is at infinity (invalid for SEC format).
    /// The error string will indicate the specific reason why the input is invalid.
    #[allow(dead_code)]
    fn sec_compressed(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Check if point has valid coordinates (not point at infinity)
        match (&self.point.x(), &self.point.y()) {
            (Some(x), Some(y)) => {
                // Compressed format: [0x02/0x03, x_coordinate (32 bytes)]
                let prefix = if y.is_odd() { 0x03 } else { 0x02 };
                result.push(prefix);
                result.extend_from_slice(&x.to_bytes_fixed(32));
            }
            _ => {
                // Handle point at infinity (invalid for SEC format)
                panic!("Cannot serialize point at infinity to compressed SEC format");
            }
        }

        result
    }

    /// Serialize the public key in uncompressed SEC format
    ///
    /// Returns a 65-byte Vec: [0x04, x_coordinate (32 bytes), y_coordinate (32 bytes)]
    ///
    /// # Panics
    ///
    /// Panics if the input point is at infinity (invalid for SEC format).
    /// The error string will indicate the specific reason why the input is invalid.
    #[allow(dead_code)]
    fn sec_uncompressed(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Check if point has valid coordinates (not point at infinity)
        match (&self.point.x(), &self.point.y()) {
            (Some(x), Some(y)) => {
                // Uncompressed format: [0x04, x_coordinate (32 bytes), y_coordinate (32 bytes)]
                result.push(0x04);
                result.extend_from_slice(&x.to_bytes_fixed(32));
                result.extend_from_slice(&y.to_bytes_fixed(32));
            }
            _ => {
                // Handle point at infinity (invalid for SEC format)
                panic!("Cannot serialize point at infinity to uncompressed SEC format");
            }
        }

        result
    }

    /// Parses a SEC format public key (compressed or uncompressed)
    ///
    /// This function checks the length of the input and delegates to either
    /// `parse_compressed` or `parse_uncompressed` depending on the length.
    ///
    /// # Errors
    ///
    /// Returns an error if the input length is not 33 bytes (compressed) or 65 bytes (uncompressed).
    /// The error string will indicate the specific reason why the input is invalid.
    pub fn parse(sec_bytes: &[u8]) -> Result<Self, &'static str> {
        match sec_bytes.len() {
            33 => Self::parse_compressed(sec_bytes),
            65 => Self::parse_uncompressed(sec_bytes),
            _ => Err(
                "Invalid SEC format length: must be 33 bytes (compressed) or 65 bytes (uncompressed)",
            ),
        }
    }

    /// Parse an uncompressed SEC format public key
    ///
    /// Format: [0x04, x_coordinate (32 bytes), y_coordinate (32 bytes)]
    ///
    /// Returns a `PublicKey` if the input is valid, otherwise returns an error.
    /// The error string will indicate the specific reason why the input is invalid.
    fn parse_uncompressed(sec_bytes: &[u8]) -> Result<Self, &'static str> {
        if sec_bytes.len() != 65 {
            return Err("Invalid uncompressed SEC format: must be 65 bytes");
        }
        if sec_bytes[0] != 0x04 {
            return Err("Invalid uncompressed SEC format: must start with 0x04");
        }

        // Extract x and y coordinates (32 bytes each)
        let x_bytes = &sec_bytes[1..33];
        let y_bytes = &sec_bytes[33..65];

        // Convert bytes to FieldElement
        let x = FieldElement::from_bytes(x_bytes);
        let y = FieldElement::from_bytes(y_bytes);

        // Create Point and verify it's on the curve
        let point = Point::new(Some(x), Some(y));
        if !point.is_on_curve() {
            return Err("Point is not on the secp256k1 curve");
        }

        Ok(PublicKey { point })
    }

    /// Parse a compressed SEC format public key
    ///
    /// Compressed format: [0x02/0x03, x_coordinate (32 bytes)]
    ///
    /// Returns a `PublicKey` if the input is valid, otherwise returns an error.
    /// The error string will indicate the specific reason why the input is invalid.
    fn parse_compressed(sec_bytes: &[u8]) -> Result<Self, &'static str> {
        if sec_bytes.len() != 33 {
            return Err("Invalid compressed SEC format: must be 33 bytes");
        }
        let prefix = sec_bytes[0];
        if prefix != 0x02 && prefix != 0x03 {
            return Err("Invalid compressed SEC format: must start with 0x02 or 0x03");
        }

        // Extract x-coordinate
        let x_bytes = &sec_bytes[1..33];
        let x = FieldElement::from_bytes(x_bytes);

        // secp256k1 curve equation: y^2 = x^3 + 7 mod p
        // Compute y^2 = x^3 + 7
        let x_cubed = x.pow(&BigUint::from_u32(3).unwrap());
        let y_squared = x_cubed + &SECP256K1_B_FE_OPT.clone().unwrap();

        // Compute square root mod p to get y
        let y = y_squared.sqrt();

        // Choose the y-coordinate based on the prefix (0x02 for even, 0x03 for odd)
        let is_y_odd = prefix == 0x03;
        let y_is_odd = y.is_odd();
        let p = y_squared.prime();
        let selected_y = if is_y_odd == y_is_odd {
            y
        } else {
            // Negate y mod p to get the other root
            let neg_y = *&p - y.value();
            FieldElement::from_big_uint(&neg_y)
        };

        // Create Point and verify it's on the curve
        let point = Point::new(Some(x), Some(selected_y));
        if !point.is_on_curve() {
            return Err("Point is not on the secp256k1 curve");
        }

        Ok(PublicKey { point })
    }

    /// Generate a Bitcoin address of the specified type
    ///
    /// Given a public key, it generates a Bitcoin address of the specified type (P2PKH)
    /// and network (mainnet, testnet, or regtest).
    ///
    /// This function takes into account the version byte of the network and applies
    /// HASH160 (SHA256 then RIPEMD160) to the compressed SEC format of the public key.
    /// The resulting hash is then encoded with Base58Check (includes checksum).
    ///
    /// # Returns
    ///
    /// A string representing the Bitcoin address.
    pub fn address(&self, address_type: AddressType, network: Network) -> String {
        match address_type {
            AddressType::P2PKH => {
                // Get compressed SEC format of the public key
                let compressed_sec = self.to_sec(true);

                // Apply HASH160 (SHA256 then RIPEMD160)
                let hash160_result = hash160(&compressed_sec);

                // Add version byte based on network
                let version_byte = network.p2pkh_version();
                let mut versioned_payload = vec![version_byte];
                versioned_payload.extend_from_slice(&hash160_result);

                // Encode with Base58Check (includes checksum)
                encode_base58_check(&versioned_payload)
            }
        }
    }

    /// Convenience method for generating P2PKH addresses.
    ///
    /// This method calls `address` with `AddressType::P2PKH` and the given network.
    ///
    pub fn p2pkh_address(&self, network: Network) -> String {
        self.address(AddressType::P2PKH, network)
    }
}
