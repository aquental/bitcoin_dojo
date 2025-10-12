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
}
