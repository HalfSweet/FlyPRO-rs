//! Parser for `FlyPro` II `.cfg` configuration assets.
//!
//! Only the boundaries confirmed by `F-CFG-001` through `F-CFG-009` are
//! named. Variable-record text and unknown flags remain in each raw record.

use thiserror::Error;

use super::device_db::sfly_crc16;

pub const HEADER_BYTES: usize = 0x130;
pub const DEFAULT_BLOCK_BYTES: usize = 64;
pub const RECORD_HEADER_BYTES: usize = 0x1c;

const MAGIC: [u8; 4] = *b"CFG\0";
const RECORD_MAGIC: [u8; 4] = [0x5a, 0x5a, 0xa5, 0xa5];
const SUPPORTED_VERSION: u16 = 9;

/// A validated configuration asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    name: String,
    version: u16,
    default_block_0: [u8; DEFAULT_BLOCK_BYTES],
    default_block_1: [u8; DEFAULT_BLOCK_BYTES],
    default_protection_bits: u32,
    records: Vec<ConfigurationRecord>,
    opaque_tail: Box<[u8]>,
}

impl Configuration {
    /// Parses a configuration without checking its file stem.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] for invalid content, boundaries, or
    /// whole-file SFLY CRC residue.
    pub fn parse(bytes: &[u8]) -> Result<Self, ConfigurationError> {
        Self::parse_inner(bytes, None)
    }

    /// Parses a configuration and verifies its internal name against the
    /// requested file stem.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] for invalid content or a name mismatch.
    pub fn parse_for_stem(bytes: &[u8], expected_stem: &str) -> Result<Self, ConfigurationError> {
        Self::parse_inner(bytes, Some(expected_stem))
    }

    fn parse_inner(bytes: &[u8], expected_stem: Option<&str>) -> Result<Self, ConfigurationError> {
        if bytes.len() < HEADER_BYTES {
            return Err(ConfigurationError::TooShort {
                actual: bytes.len(),
                minimum: HEADER_BYTES,
            });
        }
        let magic = bytes[0..4].try_into().expect("four-byte slice");
        if magic != MAGIC {
            return Err(ConfigurationError::InvalidMagic { actual: magic });
        }
        let version = read_u16(bytes, 0x04);
        if version != SUPPORTED_VERSION {
            return Err(ConfigurationError::UnsupportedVersion { actual: version });
        }
        if sfly_crc16(bytes) != 0 {
            return Err(ConfigurationError::CrcResidue);
        }

        let name = parse_ascii_name(&bytes[0x10..0x20])?;
        if let Some(expected) = expected_stem {
            if !name.eq_ignore_ascii_case(expected) {
                return Err(ConfigurationError::NameMismatch {
                    expected: expected.to_owned(),
                    actual: name,
                });
            }
        }

        let record_count = usize::from(bytes[0xa1]);
        let (records, records_end) = parse_records(bytes, record_count)?;
        Ok(Self {
            name,
            version,
            default_block_0: bytes[0x20..0x60].try_into().expect("64-byte slice"),
            default_block_1: bytes[0x60..0xa0].try_into().expect("64-byte slice"),
            default_protection_bits: read_u32(bytes, 0xa4),
            records,
            opaque_tail: bytes[records_end..].to_vec().into_boxed_slice(),
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    #[must_use]
    pub const fn default_block_0(&self) -> &[u8; DEFAULT_BLOCK_BYTES] {
        &self.default_block_0
    }

    #[must_use]
    pub const fn default_block_1(&self) -> &[u8; DEFAULT_BLOCK_BYTES] {
        &self.default_block_1
    }

    #[must_use]
    pub const fn default_protection_bits(&self) -> u32 {
        self.default_protection_bits
    }

    #[must_use]
    pub fn records(&self) -> &[ConfigurationRecord] {
        &self.records
    }

    /// Returns bytes after the confirmed variable-record sequence.
    ///
    /// The current facts only confirm whole-file CRC residue, so this suffix
    /// is preserved without assigning it a trailer schema.
    #[must_use]
    pub fn opaque_tail(&self) -> &[u8] {
        &self.opaque_tail
    }
}

/// Confirmed fields and raw bytes of one variable-length CFG record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationRecord {
    source_index: usize,
    source_offset: usize,
    type_flags: u8,
    unknown_09: u8,
    text_length_1: u16,
    text_length_2: u16,
    bit_offset: u16,
    bit_width_or_count: u16,
    value_or_default: u32,
    unknown_18: u8,
    choice_count: u8,
    raw: Box<[u8]>,
}

impl ConfigurationRecord {
    #[must_use]
    pub const fn source_index(&self) -> usize {
        self.source_index
    }

    #[must_use]
    pub const fn source_offset(&self) -> usize {
        self.source_offset
    }

    #[must_use]
    pub const fn type_flags(&self) -> u8 {
        self.type_flags
    }

    #[must_use]
    pub const fn unknown_09(&self) -> u8 {
        self.unknown_09
    }

    #[must_use]
    pub const fn text_length_1(&self) -> u16 {
        self.text_length_1
    }

    #[must_use]
    pub const fn text_length_2(&self) -> u16 {
        self.text_length_2
    }

    #[must_use]
    pub const fn bit_offset(&self) -> u16 {
        self.bit_offset
    }

    #[must_use]
    pub const fn bit_width_or_count(&self) -> u16 {
        self.bit_width_or_count
    }

    #[must_use]
    pub const fn value_or_default(&self) -> u32 {
        self.value_or_default
    }

    #[must_use]
    pub const fn unknown_18(&self) -> u8 {
        self.unknown_18
    }

    #[must_use]
    pub const fn choice_count(&self) -> u8 {
        self.choice_count
    }

    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

fn parse_records(
    bytes: &[u8],
    record_count: usize,
) -> Result<(Vec<ConfigurationRecord>, usize), ConfigurationError> {
    let mut offset = HEADER_BYTES;
    let mut records = Vec::with_capacity(record_count);
    for index in 0..record_count {
        let header_end = offset
            .checked_add(RECORD_HEADER_BYTES)
            .ok_or(ConfigurationError::RecordLengthOverflow { index })?;
        if header_end > bytes.len() {
            return Err(ConfigurationError::TruncatedRecord { index, offset });
        }
        let magic: [u8; 4] = bytes[offset..offset + 4]
            .try_into()
            .expect("four-byte slice");
        if magic != RECORD_MAGIC {
            return Err(ConfigurationError::InvalidRecordMagic {
                index,
                offset,
                actual: magic,
            });
        }
        let record_length = usize::try_from(read_u32(bytes, offset + 4))
            .map_err(|_| ConfigurationError::RecordLengthOverflow { index })?;
        if record_length < RECORD_HEADER_BYTES {
            return Err(ConfigurationError::InvalidRecordLength {
                index,
                actual: record_length,
                minimum: RECORD_HEADER_BYTES,
            });
        }
        let end = offset
            .checked_add(record_length)
            .ok_or(ConfigurationError::RecordLengthOverflow { index })?;
        if end > bytes.len() {
            return Err(ConfigurationError::TruncatedRecord { index, offset });
        }
        let raw = &bytes[offset..end];
        records.push(ConfigurationRecord {
            source_index: index,
            source_offset: offset,
            type_flags: raw[0x08],
            unknown_09: raw[0x09],
            text_length_1: read_u16(raw, 0x0a),
            text_length_2: read_u16(raw, 0x0c),
            bit_offset: read_u16(raw, 0x10),
            bit_width_or_count: read_u16(raw, 0x12),
            value_or_default: read_u32(raw, 0x14),
            unknown_18: raw[0x18],
            choice_count: raw[0x19],
            raw: raw.to_vec().into_boxed_slice(),
        });
        offset = end;
    }
    Ok((records, offset))
}

fn parse_ascii_name(field: &[u8]) -> Result<String, ConfigurationError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let value = &field[..end];
    if value.is_empty() || !value.is_ascii() {
        return Err(ConfigurationError::InvalidName);
    }
    Ok(String::from_utf8(value.to_vec()).expect("ASCII is UTF-8"))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("two-byte slice"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("four-byte slice"),
    )
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigurationError {
    #[error("configuration is too short: {actual} bytes, minimum is {minimum}")]
    TooShort { actual: usize, minimum: usize },
    #[error("invalid configuration magic: {actual:02x?}")]
    InvalidMagic { actual: [u8; 4] },
    #[error("unsupported configuration version {actual}")]
    UnsupportedVersion { actual: u16 },
    #[error("configuration whole-file SFLY CRC16 residue is not zero")]
    CrcResidue,
    #[error("configuration name is empty or not ASCII")]
    InvalidName,
    #[error("configuration name mismatch: expected {expected}, found {actual}")]
    NameMismatch { expected: String, actual: String },
    #[error("configuration record {index} at {offset:#x} is truncated")]
    TruncatedRecord { index: usize, offset: usize },
    #[error("configuration record {index} length overflows")]
    RecordLengthOverflow { index: usize },
    #[error("configuration record {index} length {actual} is less than {minimum}")]
    InvalidRecordLength {
        index: usize,
        actual: usize,
        minimum: usize,
    },
    #[error("configuration record {index} at {offset:#x} has magic {actual:02x?}")]
    InvalidRecordMagic {
        index: usize,
        offset: usize,
        actual: [u8; 4],
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let record_bytes = 72_usize;
        let mut bytes = vec![0_u8; HEADER_BYTES + record_bytes + 2];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[0x04..0x06].copy_from_slice(&SUPPORTED_VERSION.to_le_bytes());
        bytes[0x10..0x19].copy_from_slice(b"W25Q128S\0");
        bytes[0x20..0x60].fill(0x11);
        bytes[0x60..0xa0].fill(0x22);
        bytes[0xa1] = 1;
        bytes[0xa4..0xa8].copy_from_slice(&0x1234_5678_u32.to_le_bytes());

        let offset = HEADER_BYTES;
        bytes[offset..offset + 4].copy_from_slice(&RECORD_MAGIC);
        bytes[offset + 4..offset + 8].copy_from_slice(
            &u32::try_from(record_bytes)
                .expect("fixture record length fits")
                .to_le_bytes(),
        );
        bytes[offset + 0x08] = 0x80;
        bytes[offset + 0x10..offset + 0x12].copy_from_slice(&3_u16.to_le_bytes());
        bytes[offset + 0x12..offset + 0x14].copy_from_slice(&2_u16.to_le_bytes());
        bytes[offset + 0x14..offset + 0x18].copy_from_slice(&1_u32.to_le_bytes());
        bytes[offset + 0x19] = 2;

        let suffix = find_zero_residue_suffix(&bytes[..bytes.len() - 2]);
        let suffix_offset = bytes.len() - 2;
        bytes[suffix_offset..].copy_from_slice(&suffix);
        assert_eq!(sfly_crc16(&bytes), 0);
        bytes
    }

    fn find_zero_residue_suffix(prefix: &[u8]) -> [u8; 2] {
        for candidate in 0_u16..=u16::MAX {
            let suffix = candidate.to_le_bytes();
            let mut bytes = Vec::with_capacity(prefix.len() + 2);
            bytes.extend_from_slice(prefix);
            bytes.extend_from_slice(&suffix);
            if sfly_crc16(&bytes) == 0 {
                return suffix;
            }
        }
        panic!("a two-byte CRC suffix must exist");
    }

    #[test]
    fn parses_confirmed_defaults_and_record_fields() {
        let configuration =
            Configuration::parse_for_stem(&fixture(), "w25q128s").expect("valid fixture");

        assert_eq!(configuration.name(), "W25Q128S");
        assert_eq!(configuration.default_block_0(), &[0x11; 64]);
        assert_eq!(configuration.default_block_1(), &[0x22; 64]);
        assert_eq!(configuration.default_protection_bits(), 0x1234_5678);
        assert_eq!(configuration.records().len(), 1);
        assert_eq!(configuration.records()[0].type_flags(), 0x80);
        assert_eq!(configuration.records()[0].bit_offset(), 3);
        assert_eq!(configuration.opaque_tail().len(), 2);
    }

    #[test]
    fn rejects_crc_corruption() {
        let mut bytes = fixture();
        bytes[0x20] ^= 1;

        assert_eq!(
            Configuration::parse(&bytes),
            Err(ConfigurationError::CrcResidue)
        );
    }

    #[test]
    fn rejects_record_length_beyond_file() {
        let mut bytes = fixture();
        bytes[HEADER_BYTES + 4..HEADER_BYTES + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let suffix = find_zero_residue_suffix(&bytes[..bytes.len() - 2]);
        let suffix_offset = bytes.len() - 2;
        bytes[suffix_offset..].copy_from_slice(&suffix);

        assert!(matches!(
            Configuration::parse(&bytes),
            Err(ConfigurationError::TruncatedRecord { .. })
        ));
    }
}
