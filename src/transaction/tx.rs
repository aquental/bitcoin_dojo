/// src/transaction/tx.rs
use std::io::Read;

#[derive(Clone)]
pub struct Tx {
    pub version: u32,
}

impl Tx {
    /// Creates a new transaction with the given version.
    ///
    /// The version should be a little-endian 32-bit integer.
    ///
    /// # Examples
    ///
    ///
    pub fn new(version: u32) -> Self {
        Self { version }
    }

    /// Parse a transaction from a Read stream.
    ///
    /// Reads the first 4 bytes from the stream and interprets them as a little-endian 32-bit integer.
    /// This is the version of the transaction.
    ///
    /// Returns a parsed transaction or a Box containing an error if the input is invalid or if the stream is exhausted.
    pub fn parse<R: Read>(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        // Read the first 4 bytes for the version
        let mut version_bytes = [0u8; 4];
        reader.read_exact(&mut version_bytes)?;

        // Convert from little-endian to u32
        let version = u32::from_le_bytes(version_bytes);

        Ok(Self { version })
    }
}
