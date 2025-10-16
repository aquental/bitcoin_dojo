use crate::{transaction::tx_output::TxOutput, utils::varint::{decode_varint, encode_varint}};
/// src/transaction/tx.rs
use std::io::Read;

use crate::transaction::tx_input::TxInput;

#[derive(Clone)]
pub struct Tx {
    pub version: u32,
    pub tx_ins: Vec<TxInput>,
    pub tx_outs: Vec<TxOutput>,
    pub locktime: u32,
}

impl Tx {
    /// Creates a new transaction with the given version, inputs, and outputs.
    ///
    /// # Parameters
    ///
    /// * `version`: The version of the transaction. Should be a little-endian 32-bit integer.
    /// * `tx_ins`: A vector of `TxInput` objects.
    /// * `tx_outs`: A vector of `TxOutput` objects.
    /// * `locktime`: The lock time of the transaction. Should be a little-endian 32-bit integer.
    ///
    /// # Returns
    ///
    /// A new `Tx` object with the given version, inputs, and outputs.
    pub fn new(version: u32, tx_ins: Vec<TxInput>, tx_outs: Vec<TxOutput>, locktime: u32) -> Self {
        Self {
            version,
            tx_ins,
            tx_outs,
            locktime,
        }
    }

    /// Parses a transaction from a Read stream.
    ///
    /// Reads the first 4 bytes from the stream and interprets them as a little-endian 32-bit integer.
    /// This is the version of the transaction.
    ///
    /// Then, reads a varint from the stream, which is the number of inputs.
    /// Each input is then parsed from the stream.
    ///
    /// Finally, reads a varint from the stream, which is the number of outputs.
    /// Each output is then parsed from the stream.
    ///
    /// Returns a parsed transaction or a Box containing an error if the input is invalid or if the stream is exhausted.
    pub fn parse<R: Read>(mut reader: R) -> Result<Self, Box<dyn std::error::Error>> {
        // Read the first 4 bytes for the version
        let mut version_bytes = [0u8; 4];
        reader.read_exact(&mut version_bytes)?;

        // Convert from little-endian to u32
        let version = u32::from_le_bytes(version_bytes);

        // Parse the number of inputs (varint)
        let num_inputs = decode_varint(&mut reader)? as usize;

        // Parse each input
        let mut tx_ins = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            let tx_input = TxInput::parse(&mut reader)?;
            tx_ins.push(tx_input);
        }
        // Parse the number of outputs (varint)
        let num_outputs = decode_varint(&mut reader)? as usize;

        // Parse each output
        let mut tx_outs = Vec::with_capacity(num_outputs);
        for _ in 0..num_outputs {
            let tx_output = TxOutput::parse(&mut reader)?;
            tx_outs.push(tx_output);
        }

        // Parse the locktime (final 4 bytes, little-endian)
        let mut locktime_bytes = [0u8; 4];
        reader.read_exact(&mut locktime_bytes)?;
        let locktime = u32::from_le_bytes(locktime_bytes);

        Ok(Self {
            version,
            tx_ins,
            tx_outs,
            locktime,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Serialize version (4 bytes, little-endian)
        result.extend_from_slice(&self.version.to_le_bytes());
        
        // Serialize number of inputs as varint
        result.extend_from_slice(&encode_varint(self.tx_ins.len() as u64));
        
        // Serialize each input
        for tx_in in &self.tx_ins {
            result.extend_from_slice(&tx_in.serialize());
        }
        
        // Serialize number of outputs as varint
        result.extend_from_slice(&encode_varint(self.tx_outs.len() as u64));
        
        // Serialize each output
        for tx_out in &self.tx_outs {
            result.extend_from_slice(&tx_out.serialize());
        }
        
        // Serialize locktime (4 bytes, little-endian)
        result.extend_from_slice(&self.locktime.to_le_bytes());
        
        result
    }
}
