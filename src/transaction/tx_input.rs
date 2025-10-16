use crate::utils::varint::decode_varint;
/// src/transaction/tx_input.rs
use std::io::Read;

#[derive(Clone)]
pub struct TxInput {
    pub prev_tx_id: [u8; 32], // little endian
    pub prev_index: u32,
    pub script_sig: Vec<u8>, // Store the scriptSig as a Vec<u8> for now, we will parse it in a later track
    pub sequence: u32,
}

impl TxInput {
    /// Parses a TxInput from a Read stream.
    ///
    /// Reads the previous transaction ID (32 bytes, already in little-endian),
    /// the previous output index (4 bytes, little-endian), the script_sig length using varint,
    /// the script_sig bytes, and the sequence number (4 bytes, little-endian).
    ///
    /// Returns a parsed TxInput or a Box containing an error if the input is invalid or if the stream is exhausted.
    pub fn parse<R: Read>(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        // Parse the previous transaction ID (32 bytes, already in little-endian)
        let mut prev_tx_id = [0u8; 32];
        reader.read_exact(&mut prev_tx_id)?;

        // Parse the previous output index (4 bytes, little-endian)
        let mut prev_index_bytes = [0u8; 4];
        reader.read_exact(&mut prev_index_bytes)?;
        let prev_index = u32::from_le_bytes(prev_index_bytes);

        // Parse the script_sig length using varint
        let script_sig_length = decode_varint(&mut reader)? as usize;

        // Parse the script_sig bytes
        let mut script_sig = vec![0u8; script_sig_length];
        reader.read_exact(&mut script_sig)?;

        // Parse the sequence number (4 bytes, little-endian)
        let mut sequence_bytes = [0u8; 4];
        reader.read_exact(&mut sequence_bytes)?;
        let sequence = u32::from_le_bytes(sequence_bytes);

        Ok(Self {
            prev_tx_id,
            prev_index,
            script_sig,
            sequence,
        })
    }
}
