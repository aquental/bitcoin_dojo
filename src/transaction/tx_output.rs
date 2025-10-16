use crate::utils::varint::{decode_varint, encode_varint};
/// src/transaction/tx_output.rs
use std::io::Read;

#[derive(Clone, Debug)]
pub struct TxOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8>, // Store the script_pubkey as a Vec<u8> for now, we will parse it in a later track
}

impl TxOutput {
    /// Parses a TxOutput from a Read stream.
    ///
    /// Reads the amount (8 bytes, little-endian u64) and the script_pubkey length using varint.
    /// Then, reads the script_pubkey bytes.
    ///
    /// Returns a parsed TxOutput or a Box containing an error if the input is invalid or if the stream is exhausted.
    pub fn parse<R: Read>(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        // Parse the amount (8 bytes, little-endian u64)
        let mut amount_bytes = [0u8; 8];
        reader.read_exact(&mut amount_bytes)?;
        let amount = u64::from_le_bytes(amount_bytes);

        // Parse the script_pubkey length using varint
        let script_pubkey_length = decode_varint(&mut reader)? as usize;

        // Parse the script_pubkey bytes
        let mut script_pubkey = vec![0u8; script_pubkey_length];
        reader.read_exact(&mut script_pubkey)?;

        Ok(Self {
            amount,
            script_pubkey,
        })
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Serialize amount (8 bytes, little-endian)
        result.extend_from_slice(&self.amount.to_le_bytes());
        
        // Serialize script_pubkey length as varint
        result.extend_from_slice(&encode_varint(self.script_pubkey.len() as u64));
        
        // Serialize script_pubkey bytes
        result.extend_from_slice(&self.script_pubkey);
        
        result
    }
}
