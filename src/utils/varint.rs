/// src/utils/varint.rs
use std::io::{self, Error, Read};

/// Variable-length integer encoding and decoding functions
///
/// Varints encode integers from 0 to 2^64 - 1 using variable-length encoding:
/// - 0x00 to 0xFC: stored as single byte
/// - 0xFD: followed by 2-byte little-endian value (253 to 65535)
/// - 0xFE: followed by 4-byte little-endian value (65536 to 4294967295)
/// - 0xFF: followed by 8-byte little-endian value (4294967296 to 18446744073709551615)
/// Encode a u64 value as a varint
pub fn encode_varint(value: u64) -> Vec<u8> {
    if value <= 0xFC {
        // Single byte encoding for values 0-252
        vec![value as u8]
    } else if value <= 0xFFFF {
        // 0xFD followed by 2 bytes little-endian for values 253-65535
        let mut result = vec![0xFD];
        result.push((value & 0xFF) as u8);
        result.push(((value >> 8) & 0xFF) as u8);
        result
    } else if value <= 0xFFFFFFFF {
        // 0xFE followed by 4 bytes little-endian for values 65536-4294967295
        let mut result = vec![0xFE];
        result.push((value & 0xFF) as u8);
        result.push(((value >> 8) & 0xFF) as u8);
        result.push(((value >> 16) & 0xFF) as u8);
        result.push(((value >> 24) & 0xFF) as u8);
        result
    } else {
        // 0xFF followed by 8 bytes little-endian for values 4294967296+
        let mut result = vec![0xFF];
        result.push((value & 0xFF) as u8);
        result.push(((value >> 8) & 0xFF) as u8);
        result.push(((value >> 16) & 0xFF) as u8);
        result.push(((value >> 24) & 0xFF) as u8);
        result.push(((value >> 32) & 0xFF) as u8);
        result.push(((value >> 40) & 0xFF) as u8);
        result.push(((value >> 48) & 0xFF) as u8);
        result.push(((value >> 56) & 0xFF) as u8);
        result
    }
}

/// Reads a varint from a reader and returns the decoded u64 value.
///
/// Varints encode integers from 0 to 2^64 - 1 using variable-length encoding:
/// - 0x00 to 0xFC: stored as single byte
/// - 0xFD: followed by 2-byte little-endian value (253 to 65535)
/// - 0xFE: followed by 4-byte little-endian value (65536 to 4294967295)
/// - 0xFF: followed by 8-byte little-endian value (4294967296 to 18446744073709551615)
///
/// Returns an error if the input is invalid or the varint is not canonically encoded.
/// A varint is considered non-canonical if there is a shorter encoding that could represent the same value.
pub fn decode_varint<R: Read>(reader: &mut R) -> Result<u64, Error> {
    let mut first_byte = [0u8; 1];
    reader.read_exact(&mut first_byte)?;

    match first_byte[0] {
        0x00..=0xFC => {
            // Single byte encoding
            Ok(first_byte[0] as u64)
        }
        0xFD => {
            // 2-byte encoding
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            let value = u16::from_le_bytes(buf) as u64;

            // Check for non-canonical encoding
            if value <= 0xFC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Non-canonical varint encoding",
                ));
            }
            Ok(value)
        }
        0xFE => {
            // 4-byte encoding
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            let value = u32::from_le_bytes(buf) as u64;

            // Check for non-canonical encoding
            if value <= 0xFFFF {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Non-canonical varint encoding",
                ));
            }
            Ok(value)
        }
        0xFF => {
            // 8-byte encoding
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            let value = u64::from_le_bytes(buf);

            // Check for non-canonical encoding
            if value <= 0xFFFFFFFF {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Non-canonical varint encoding",
                ));
            }
            Ok(value)
        }
    }
}

/// Returns the number of bytes required to encode the given value as a varint.
/// The return value is the minimal number of bytes required to encode the value.
/// It is calculated according to the Bitcoin varint encoding rules.
pub fn varint_length(value: u64) -> usize {
    if value <= 0xFC {
        1
    } else if value <= 0xFFFF {
        3
    } else if value <= 0xFFFFFFFF {
        5
    } else {
        9
    }
}
