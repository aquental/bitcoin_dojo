pub mod ecc {
    pub mod constants;
    pub mod curve;
    pub mod ecdsa;
    pub mod field;
    pub mod keys;
    pub mod scalar;
    pub mod util;
}

pub mod utils {
    pub mod address_types;
    pub mod base58;
    pub mod hash160;
    pub mod hash256;
    pub mod varint;
}

pub mod transaction {
    pub mod tx;
    pub mod tx_input;
    pub mod tx_output;
}

// Re-export the main types and functions for easy access
pub use ecc::curve::Point;
pub use ecc::ecdsa::{Signature, sign, verify};
pub use ecc::keys::{PrivateKey, PublicKey};
pub use ecc::util::{secure_random_bytes, sha256};
pub use utils::hash160::hash160;
