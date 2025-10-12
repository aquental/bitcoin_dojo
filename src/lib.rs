pub mod ecc {
    pub mod constants;
    pub mod curve;
    pub mod ecdsa;
    pub mod field;
    pub mod keys;
    pub mod scalar;
    pub mod util;
}

// Re-export the main types and functions for easy access
pub use ecc::curve::Point;
pub use ecc::ecdsa::{Signature, sign, verify};
pub use ecc::keys::{PrivateKey, PublicKey};
