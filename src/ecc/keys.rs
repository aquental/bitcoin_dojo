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
    pub fn scalar(&self) -> &Scalar {
        &self.scalar
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
    /// Returns a 33-byte array for compressed format or 65-byte Vec for uncompressed format
    /// Compressed format: [0x02/0x03, x_coordinate (32 bytes)]
    /// Uncompressed format: [0x04, x_coordinate (32 bytes), y_coordinate (32 bytes)]
    pub fn to_sec(&self, compressed: bool) -> Vec<u8> {
        let mut result = Vec::new();

        // Check if point has valid coordinates (not point at infinity)
        match (&self.point.x(), &self.point.y()) {
            (Some(x), Some(y)) => {
                if compressed {
                    // Compressed format: [0x02/0x03, x_coordinate (32 bytes)]
                    let prefix = if y.is_odd() { 0x03 } else { 0x02 };
                    result.push(prefix);
                    result.extend_from_slice(&x.to_bytes()); // Assume to_bytes() returns 32-byte array/slice
                } else {
                    // Uncompressed format: [0x04, x_coordinate (32 bytes), y_coordinate (32 bytes)]
                    result.push(0x04);
                    result.extend_from_slice(&x.to_bytes());
                    result.extend_from_slice(&y.to_bytes());
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
    fn sec_compressed(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Check if point has valid coordinates (not point at infinity)
        match (&self.point.x(), &self.point.y()) {
            (Some(x), Some(y)) => {
                // Compressed format: [0x02/0x03, x_coordinate (32 bytes)]
                let prefix = if y.is_odd() { 0x03 } else { 0x02 };
                result.push(prefix);
                result.extend_from_slice(&x.to_bytes()); // Assume to_bytes() returns 32-byte array/slice
            }
            _ => {
                // Handle point at infinity (invalid for SEC format)
                panic!("Cannot serialize point at infinity to compressed SEC format");
            }
        }

        result
    }

    /// Serialize the public key in uncompressed SEC format
    /// Returns a 65-byte Vec: [0x04, x_coordinate (32 bytes), y_coordinate (32 bytes)]
    fn sec_uncompressed(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Check if point has valid coordinates (not point at infinity)
        match (&self.point.x(), &self.point.y()) {
            (Some(x), Some(y)) => {
                // Uncompressed format: [0x04, x_coordinate (32 bytes), y_coordinate (32 bytes)]
                result.push(0x04);
                result.extend_from_slice(&x.to_bytes()); // Assume to_bytes() returns 32-byte array/slice
                result.extend_from_slice(&y.to_bytes()); // Assume to_bytes() returns 32-byte array/slice
            }
            _ => {
                // Handle point at infinity (invalid for SEC format)
                panic!("Cannot serialize point at infinity to uncompressed SEC format");
            }
        }

        result
    }
}
