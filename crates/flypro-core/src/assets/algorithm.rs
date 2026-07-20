//! Strict parser for `FlyPRO` II `.alg` files.
//!
//! Layout and validation follow facts `F-ALG-010` through `F-ALG-020`.

use crc32fast::hash;
use thiserror::Error;

/// Size of the clear-text `.alg` header.
pub const HEADER_BYTES: usize = 0x200;
/// Maximum payload accepted by the baseline host-side structure.
pub const MAX_PAYLOAD_BYTES: usize = 0x4000;
/// Size of the zero-filled area between the payload and CRC32.
pub const RESERVED_BYTES: usize = 0x0c;
/// Size of the little-endian CRC32 trailer.
pub const CRC32_BYTES: usize = 4;

const MIN_FILE_BYTES: usize = HEADER_BYTES + RESERVED_BYTES + CRC32_BYTES;
const MAGIC: [u8; 4] = *b"ALG\0";

/// A validated algorithm asset.
///
/// The payload deliberately remains opaque because its device-side ABI is
/// unknown (`Q-ALG-001`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Algorithm {
    name: String,
    unknown_header_u32: u32,
    format_version: u16,
    timestamp: [u8; 8],
    region_names: [String; 3],
    copyright: String,
    payload: Box<[u8]>,
    payload_crc32: u32,
    file_crc32: u32,
}

impl Algorithm {
    /// Parses and validates an algorithm without checking its file stem.
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmError`] when any confirmed boundary or integrity
    /// rule is violated.
    pub fn parse(bytes: &[u8]) -> Result<Self, AlgorithmError> {
        Self::parse_inner(bytes, None)
    }

    /// Parses an algorithm and verifies that its internal name matches the
    /// requested file stem using ASCII case-insensitive comparison.
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmError`] for invalid content or a name mismatch.
    pub fn parse_for_stem(bytes: &[u8], expected_stem: &str) -> Result<Self, AlgorithmError> {
        Self::parse_inner(bytes, Some(expected_stem))
    }

    fn parse_inner(bytes: &[u8], expected_stem: Option<&str>) -> Result<Self, AlgorithmError> {
        if bytes.len() < MIN_FILE_BYTES {
            return Err(AlgorithmError::TooShort {
                actual: bytes.len(),
                minimum: MIN_FILE_BYTES,
            });
        }

        let magic = bytes[0..4].try_into().expect("four-byte slice");
        if magic != MAGIC {
            return Err(AlgorithmError::InvalidMagic { actual: magic });
        }

        let payload_length = usize::from(u16::from_le_bytes(
            bytes[0x08..0x0a].try_into().expect("two-byte slice"),
        ));
        if payload_length == 0 || payload_length > MAX_PAYLOAD_BYTES {
            return Err(AlgorithmError::InvalidPayloadLength {
                declared: payload_length,
                maximum: MAX_PAYLOAD_BYTES,
            });
        }

        let expected_length = HEADER_BYTES + payload_length + RESERVED_BYTES + CRC32_BYTES;
        if bytes.len() != expected_length {
            return Err(AlgorithmError::UnexpectedLength {
                actual: bytes.len(),
                expected: expected_length,
            });
        }

        let reserved_start = HEADER_BYTES + payload_length;
        if bytes[reserved_start..reserved_start + RESERVED_BYTES]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(AlgorithmError::NonZeroReserved);
        }

        let stored_crc32 = u32::from_le_bytes(
            bytes[bytes.len() - CRC32_BYTES..]
                .try_into()
                .expect("four-byte slice"),
        );
        let computed_crc32 = hash(&bytes[..bytes.len() - CRC32_BYTES]);
        if stored_crc32 != computed_crc32 {
            return Err(AlgorithmError::CrcMismatch {
                stored: stored_crc32,
                computed: computed_crc32,
            });
        }

        let name = parse_ascii_name(&bytes[0x10..0x20])?;
        if let Some(expected) = expected_stem {
            if !name.eq_ignore_ascii_case(expected) {
                return Err(AlgorithmError::NameMismatch {
                    expected: expected.to_owned(),
                    actual: name,
                });
            }
        }

        let timestamp: [u8; 8] = bytes[0x20..0x28].try_into().expect("eight-byte slice");
        validate_bcd_timestamp(timestamp)?;

        let payload = bytes[HEADER_BYTES..HEADER_BYTES + payload_length]
            .to_vec()
            .into_boxed_slice();

        Ok(Self {
            name,
            unknown_header_u32: u32::from_le_bytes(
                bytes[0x04..0x08].try_into().expect("four-byte slice"),
            ),
            format_version: u16::from_le_bytes(
                bytes[0x0a..0x0c].try_into().expect("two-byte slice"),
            ),
            timestamp,
            region_names: [
                parse_text(&bytes[0x30..0x70], "region 0")?,
                parse_text(&bytes[0x70..0xb0], "region 1")?,
                parse_text(&bytes[0xb0..0xf0], "region 2")?,
            ],
            copyright: parse_text(&bytes[0x180..0x200], "copyright")?,
            payload_crc32: hash(&payload),
            payload,
            file_crc32: stored_crc32,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn unknown_header_u32(&self) -> u32 {
        self.unknown_header_u32
    }

    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    #[must_use]
    pub const fn timestamp(&self) -> [u8; 8] {
        self.timestamp
    }

    #[must_use]
    pub fn region_names(&self) -> &[String; 3] {
        &self.region_names
    }

    #[must_use]
    pub fn copyright(&self) -> &str {
        &self.copyright
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub const fn payload_crc32(&self) -> u32 {
        self.payload_crc32
    }

    #[must_use]
    pub const fn file_crc32(&self) -> u32 {
        self.file_crc32
    }
}

fn parse_ascii_name(field: &[u8]) -> Result<String, AlgorithmError> {
    let value = nul_terminated(field);
    if value.is_empty() || !value.is_ascii() {
        return Err(AlgorithmError::InvalidText { field: "name" });
    }
    Ok(String::from_utf8(value.to_vec()).expect("ASCII is UTF-8"))
}

fn parse_text(field: &[u8], name: &'static str) -> Result<String, AlgorithmError> {
    let value = nul_terminated(field);
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| AlgorithmError::InvalidText { field: name })
}

fn nul_terminated(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    &field[..end]
}

fn validate_bcd_timestamp(timestamp: [u8; 8]) -> Result<(), AlgorithmError> {
    let invalid_digit = timestamp[..7]
        .iter()
        .any(|byte| byte >> 4 > 9 || byte & 0x0f > 9);
    if invalid_digit || timestamp[7] != 0 {
        return Err(AlgorithmError::InvalidBcdTimestamp { actual: timestamp });
    }
    Ok(())
}

/// Validation failures for a `FlyPRO` algorithm asset.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AlgorithmError {
    #[error("algorithm is too short: {actual} bytes, minimum is {minimum}")]
    TooShort { actual: usize, minimum: usize },
    #[error("invalid algorithm magic: {actual:02x?}")]
    InvalidMagic { actual: [u8; 4] },
    #[error("invalid algorithm payload length {declared}; maximum is {maximum}")]
    InvalidPayloadLength { declared: usize, maximum: usize },
    #[error("unexpected algorithm length: {actual} bytes, expected {expected}")]
    UnexpectedLength { actual: usize, expected: usize },
    #[error("algorithm reserved trailer contains non-zero bytes")]
    NonZeroReserved,
    #[error("algorithm CRC32 mismatch: stored {stored:#010x}, computed {computed:#010x}")]
    CrcMismatch { stored: u32, computed: u32 },
    #[error("invalid UTF-8 or empty required text in algorithm {field}")]
    InvalidText { field: &'static str },
    #[error("algorithm name mismatch: expected {expected}, found {actual}")]
    NameMismatch { expected: String, actual: String },
    #[error("invalid BCD algorithm timestamp: {actual:02x?}")]
    InvalidBcdTimestamp { actual: [u8; 8] },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let payload_length = 32_usize;
        let mut bytes = vec![0; HEADER_BYTES + payload_length + RESERVED_BYTES + CRC32_BYTES];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[0x04..0x08].copy_from_slice(&0x2000_0000_u32.to_le_bytes());
        bytes[0x08..0x0a].copy_from_slice(
            &u16::try_from(payload_length)
                .expect("fixture length fits")
                .to_le_bytes(),
        );
        bytes[0x0a..0x0c].copy_from_slice(&0x0100_u16.to_le_bytes());
        bytes[0x10..0x18].copy_from_slice(b"W25Q128\0");
        bytes[0x20..0x28].copy_from_slice(&[0x20, 0x24, 0x05, 0x18, 0x13, 0x04, 0x30, 0]);
        bytes[0x30..0x36].copy_from_slice(b"FLASH\0");
        bytes[0x70..0x77].copy_from_slice(b"<NONE>\0");
        bytes[0xb0..0xc0].copy_from_slice(b"Status Register\0");
        bytes[HEADER_BYTES..HEADER_BYTES + payload_length].fill(0xa5);
        let crc = hash(&bytes[..bytes.len() - CRC32_BYTES]);
        let crc_start = bytes.len() - CRC32_BYTES;
        bytes[crc_start..].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_valid_algorithm() {
        let algorithm = Algorithm::parse_for_stem(&fixture(), "w25q128").expect("valid fixture");

        assert_eq!(algorithm.name(), "W25Q128");
        assert_eq!(algorithm.format_version(), 0x0100);
        assert_eq!(algorithm.payload().len(), 32);
        assert_eq!(algorithm.region_names()[0], "FLASH");
    }

    #[test]
    fn rejects_crc_corruption() {
        let mut bytes = fixture();
        bytes[HEADER_BYTES] ^= 1;

        assert!(matches!(
            Algorithm::parse(&bytes),
            Err(AlgorithmError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn rejects_name_mismatch() {
        assert_eq!(
            Algorithm::parse_for_stem(&fixture(), "other"),
            Err(AlgorithmError::NameMismatch {
                expected: "other".to_owned(),
                actual: "W25Q128".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_non_zero_reserved_bytes() {
        let mut bytes = fixture();
        bytes[HEADER_BYTES + 32] = 1;
        let crc_start = bytes.len() - CRC32_BYTES;
        let crc = hash(&bytes[..crc_start]);
        bytes[crc_start..].copy_from_slice(&crc.to_le_bytes());

        assert_eq!(
            Algorithm::parse(&bytes),
            Err(AlgorithmError::NonZeroReserved)
        );
    }
}
