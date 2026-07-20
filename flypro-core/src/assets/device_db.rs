//! Lossless parser for the `SP20.dev` device database.
//!
//! Confirmed fields are named while every source record remains available as
//! raw bytes. Layout and integrity rules follow `F-DEV-001` through
//! `F-DEV-015`.

use encoding_rs::GBK;
use thiserror::Error;

pub const HEADER_BYTES: usize = 0x100;
pub const VENDOR_RECORD_BYTES: usize = 0x30;
pub const DEVICE_RECORD_BYTES: usize = 0x90;
pub const TRAILER_BYTES: usize = 4;

const MAGIC: [u8; 4] = *b"DEV\0";
const SUPPORTED_VERSION: u16 = 2;
const TRAILER_SUM: u16 = 0x3c5a;
const STEM_XOR_KEY: [u8; 16] = [
    0xc5, 0xfc, 0x82, 0xde, 0xb1, 0xf3, 0xaf, 0xe3, 0xbc, 0xc4, 0xa2, 0x99, 0xb1, 0xe1, 0x96, 0x9c,
];

/// A validated, lossless device catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceDatabase {
    version: u16,
    internal_file_name: String,
    timestamp: [u8; 8],
    vendors: Vec<VendorRecord>,
    devices: Vec<DeviceRecord>,
    stored_crc16: u16,
    stored_sum_word: u16,
}

impl DeviceDatabase {
    /// Parses a database while preserving all source records.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceDatabaseError`] when the header, table boundaries,
    /// references, text, or trailer integrity checks fail.
    pub fn parse(bytes: &[u8]) -> Result<Self, DeviceDatabaseError> {
        Self::parse_inner(bytes, None)
    }

    /// Parses a database and checks the internal file name against the source
    /// file name using ASCII case-insensitive comparison.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceDatabaseError`] for invalid content or a name mismatch.
    pub fn parse_for_file_name(
        bytes: &[u8],
        expected_file_name: &str,
    ) -> Result<Self, DeviceDatabaseError> {
        Self::parse_inner(bytes, Some(expected_file_name))
    }

    fn parse_inner(
        bytes: &[u8],
        expected_file_name: Option<&str>,
    ) -> Result<Self, DeviceDatabaseError> {
        let header = parse_header(bytes)?;
        if let Some(expected) = expected_file_name {
            if !header.internal_file_name.eq_ignore_ascii_case(expected) {
                return Err(DeviceDatabaseError::FileNameMismatch {
                    expected: expected.to_owned(),
                    actual: header.internal_file_name,
                });
            }
        }
        let (stored_crc16, stored_sum_word) = validate_trailer(bytes)?;
        let vendors = parse_vendors(bytes, header.vendor_count, header.device_count)?;
        let devices = parse_devices(
            bytes,
            header.device_table_offset,
            header.device_count,
            vendors.len(),
        )?;

        Ok(Self {
            version: header.version,
            internal_file_name: header.internal_file_name,
            timestamp: header.timestamp,
            vendors,
            devices,
            stored_crc16,
            stored_sum_word,
        })
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    #[must_use]
    pub fn internal_file_name(&self) -> &str {
        &self.internal_file_name
    }

    #[must_use]
    pub const fn timestamp(&self) -> [u8; 8] {
        self.timestamp
    }

    #[must_use]
    pub fn vendors(&self) -> &[VendorRecord] {
        &self.vendors
    }

    #[must_use]
    pub fn devices(&self) -> &[DeviceRecord] {
        &self.devices
    }

    #[must_use]
    pub const fn stored_crc16(&self) -> u16 {
        self.stored_crc16
    }

    #[must_use]
    pub const fn stored_sum_word(&self) -> u16 {
        self.stored_sum_word
    }

    /// Finds device records by case-insensitive ASCII substring in the device
    /// or vendor name.
    pub fn find_devices<'a>(&'a self, query: &str) -> impl Iterator<Item = &'a DeviceRecord> {
        let query = query.to_ascii_lowercase();
        self.devices.iter().filter(move |device| {
            device.name.to_ascii_lowercase().contains(&query)
                || self.vendors[device.vendor_index]
                    .name
                    .to_ascii_lowercase()
                    .contains(&query)
        })
    }

    /// Resolves one device by exact part name and an optional vendor name or
    /// code, all using ASCII case-insensitive comparison.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceSelectionError`] if no matching record exists or the
    /// selection is ambiguous.
    pub fn select_device(
        &self,
        device_name: &str,
        vendor: Option<&str>,
    ) -> Result<DeviceSelection<'_>, DeviceSelectionError> {
        let matches: Vec<_> = self
            .devices
            .iter()
            .filter(|device| device.name.eq_ignore_ascii_case(device_name))
            .filter(|device| {
                vendor.is_none_or(|requested| {
                    let candidate = &self.vendors[device.vendor_index];
                    candidate.name.eq_ignore_ascii_case(requested)
                        || candidate.code.eq_ignore_ascii_case(requested)
                })
            })
            .collect();

        match matches.as_slice() {
            [] => Err(DeviceSelectionError::NotFound {
                device: device_name.to_owned(),
                vendor: vendor.map(str::to_owned),
            }),
            [device] => Ok(DeviceSelection {
                device,
                vendor: &self.vendors[device.vendor_index],
            }),
            candidates => Err(DeviceSelectionError::Ambiguous {
                device: device_name.to_owned(),
                candidates: candidates
                    .iter()
                    .map(|device| {
                        format!(
                            "{} {} (record {})",
                            self.vendors[device.vendor_index].name,
                            device.name,
                            device.source_index
                        )
                    })
                    .collect(),
            }),
        }
    }
}

/// A uniquely selected device record and its owning vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceSelection<'a> {
    device: &'a DeviceRecord,
    vendor: &'a VendorRecord,
}

impl<'a> DeviceSelection<'a> {
    #[must_use]
    pub const fn device(self) -> &'a DeviceRecord {
        self.device
    }

    #[must_use]
    pub const fn vendor(self) -> &'a VendorRecord {
        self.vendor
    }
}

/// Failures while resolving a user-facing device selection.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DeviceSelectionError {
    #[error(
        "device {device:?} was not found{vendor_suffix}",
        vendor_suffix = vendor.as_ref().map_or(String::new(), |value| format!(" for vendor {value:?}"))
    )]
    NotFound {
        device: String,
        vendor: Option<String>,
    },
    #[error("device {device:?} is ambiguous; choose a vendor from: {candidates:?}")]
    Ambiguous {
        device: String,
        candidates: Vec<String>,
    },
}

struct ParsedHeader {
    version: u16,
    internal_file_name: String,
    timestamp: [u8; 8],
    vendor_count: usize,
    device_count: usize,
    device_table_offset: usize,
}

fn parse_header(bytes: &[u8]) -> Result<ParsedHeader, DeviceDatabaseError> {
    if bytes.len() < HEADER_BYTES + TRAILER_BYTES {
        return Err(DeviceDatabaseError::TooShort {
            actual: bytes.len(),
            minimum: HEADER_BYTES + TRAILER_BYTES,
        });
    }
    let magic = bytes[0..4].try_into().expect("four-byte slice");
    if magic != MAGIC {
        return Err(DeviceDatabaseError::InvalidMagic { actual: magic });
    }
    let header_xor = bytes[..HEADER_BYTES]
        .iter()
        .copied()
        .fold(0_u8, std::ops::BitXor::bitxor);
    if header_xor != 0 {
        return Err(DeviceDatabaseError::HeaderXor { actual: header_xor });
    }
    let version = read_u16(bytes, 0x04);
    if version != SUPPORTED_VERSION {
        return Err(DeviceDatabaseError::UnsupportedVersion { actual: version });
    }
    let timestamp = bytes[0x20..0x28].try_into().expect("eight-byte slice");
    validate_bcd_timestamp(timestamp)?;
    let vendor_count = usize::try_from(read_u32(bytes, 0x08))
        .map_err(|_| DeviceDatabaseError::TableSizeOverflow)?;
    let device_count = usize::try_from(read_u32(bytes, 0x0c))
        .map_err(|_| DeviceDatabaseError::TableSizeOverflow)?;
    let device_table_offset = HEADER_BYTES
        .checked_add(
            vendor_count
                .checked_mul(VENDOR_RECORD_BYTES)
                .ok_or(DeviceDatabaseError::TableSizeOverflow)?,
        )
        .ok_or(DeviceDatabaseError::TableSizeOverflow)?;
    let expected_length = device_table_offset
        .checked_add(
            device_count
                .checked_mul(DEVICE_RECORD_BYTES)
                .ok_or(DeviceDatabaseError::TableSizeOverflow)?,
        )
        .and_then(|value| value.checked_add(TRAILER_BYTES))
        .ok_or(DeviceDatabaseError::TableSizeOverflow)?;
    if bytes.len() != expected_length {
        return Err(DeviceDatabaseError::UnexpectedLength {
            actual: bytes.len(),
            expected: expected_length,
        });
    }
    Ok(ParsedHeader {
        version,
        internal_file_name: decode_text(&bytes[0x10..0x20], "internal file name")?,
        timestamp,
        vendor_count,
        device_count,
        device_table_offset,
    })
}

fn validate_trailer(bytes: &[u8]) -> Result<(u16, u16), DeviceDatabaseError> {
    let stored_crc16 = read_u16(bytes, bytes.len() - TRAILER_BYTES);
    let computed_crc16 = sfly_crc16(&bytes[..bytes.len() - TRAILER_BYTES]);
    if stored_crc16 != computed_crc16 {
        return Err(DeviceDatabaseError::CrcMismatch {
            stored: stored_crc16,
            computed: computed_crc16,
        });
    }
    let stored_sum_word = read_u16(bytes, bytes.len() - 2);
    let byte_sum = bytes[..bytes.len() - 2]
        .iter()
        .fold(0_u16, |sum, byte| sum.wrapping_add(u16::from(*byte)));
    let computed_sum = byte_sum.wrapping_add(stored_sum_word);
    if computed_sum != TRAILER_SUM {
        return Err(DeviceDatabaseError::SumMismatch {
            actual: computed_sum,
            expected: TRAILER_SUM,
        });
    }
    Ok((stored_crc16, stored_sum_word))
}

fn parse_vendors(
    bytes: &[u8],
    vendor_count: usize,
    device_count: usize,
) -> Result<Vec<VendorRecord>, DeviceDatabaseError> {
    (0..vendor_count)
        .map(|index| {
            let offset = HEADER_BYTES + index * VENDOR_RECORD_BYTES;
            let raw: [u8; VENDOR_RECORD_BYTES] = bytes[offset..offset + VENDOR_RECORD_BYTES]
                .try_into()
                .expect("vendor record boundary checked");
            let first_device_index = usize::try_from(read_u32(&raw, 0x04))
                .map_err(|_| DeviceDatabaseError::TableSizeOverflow)?;
            let record_device_count = usize::try_from(read_u32(&raw, 0x08))
                .map_err(|_| DeviceDatabaseError::TableSizeOverflow)?;
            let range_end = first_device_index
                .checked_add(record_device_count)
                .ok_or(DeviceDatabaseError::TableSizeOverflow)?;
            if range_end > device_count {
                return Err(DeviceDatabaseError::VendorRangeOutOfBounds {
                    vendor_index: index,
                    first_device_index,
                    device_count: record_device_count,
                    catalog_device_count: device_count,
                });
            }
            Ok(VendorRecord {
                source_index: index,
                source_offset: offset,
                code: decode_text(&raw[0x00..0x04], "vendor code")?,
                first_device_index,
                device_count: record_device_count,
                name: decode_text(&raw[0x10..0x30], "vendor name")?,
                raw,
            })
        })
        .collect()
}

fn parse_devices(
    bytes: &[u8],
    device_table_offset: usize,
    device_count: usize,
    vendor_count: usize,
) -> Result<Vec<DeviceRecord>, DeviceDatabaseError> {
    (0..device_count)
        .map(|index| {
            let offset = device_table_offset + index * DEVICE_RECORD_BYTES;
            let raw: [u8; DEVICE_RECORD_BYTES] = bytes[offset..offset + DEVICE_RECORD_BYTES]
                .try_into()
                .expect("device record boundary checked");
            let vendor_index = usize::from(raw[0x20]);
            if vendor_index >= vendor_count {
                return Err(DeviceDatabaseError::InvalidVendorReference {
                    device_index: index,
                    vendor_index,
                    vendor_count,
                });
            }
            let algorithm_stem = decode_stem(&raw[0x50..0x60], "algorithm stem")?;
            if algorithm_stem.is_empty() {
                return Err(DeviceDatabaseError::EmptyAlgorithmStem {
                    device_index: index,
                });
            }
            let configuration_stem = decode_stem(&raw[0x60..0x70], "configuration stem")?;
            Ok(DeviceRecord {
                source_index: index,
                source_offset: offset,
                name: decode_text(&raw[0x00..0x20], "device name")?,
                vendor_index,
                algorithm_stem,
                configuration_stem: (!configuration_stem.is_empty()).then_some(configuration_stem),
                raw,
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorRecord {
    source_index: usize,
    source_offset: usize,
    code: String,
    first_device_index: usize,
    device_count: usize,
    name: String,
    raw: [u8; VENDOR_RECORD_BYTES],
}

impl VendorRecord {
    #[must_use]
    pub const fn source_index(&self) -> usize {
        self.source_index
    }

    #[must_use]
    pub const fn source_offset(&self) -> usize {
        self.source_offset
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub const fn first_device_index(&self) -> usize {
        self.first_device_index
    }

    #[must_use]
    pub const fn device_count(&self) -> usize {
        self.device_count
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn raw(&self) -> &[u8; VENDOR_RECORD_BYTES] {
        &self.raw
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    source_index: usize,
    source_offset: usize,
    name: String,
    vendor_index: usize,
    algorithm_stem: String,
    configuration_stem: Option<String>,
    raw: [u8; DEVICE_RECORD_BYTES],
}

/// One addressable data region described by a device database record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRegion {
    start: u32,
    length: u32,
}

impl DeviceRegion {
    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }

    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }
}

impl DeviceRecord {
    #[must_use]
    pub const fn source_index(&self) -> usize {
        self.source_index
    }

    #[must_use]
    pub const fn source_offset(&self) -> usize {
        self.source_offset
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn vendor_index(&self) -> usize {
        self.vendor_index
    }

    #[must_use]
    pub fn algorithm_stem(&self) -> &str {
        &self.algorithm_stem
    }

    #[must_use]
    pub fn configuration_stem(&self) -> Option<&str> {
        self.configuration_stem.as_deref()
    }

    #[must_use]
    pub const fn raw(&self) -> &[u8; DEVICE_RECORD_BYTES] {
        &self.raw
    }

    /// Returns one of the two data regions populated by the original device
    /// record converter. Zero-length regions are unavailable.
    #[must_use]
    pub fn data_region(&self, index: usize) -> Option<DeviceRegion> {
        let (start_offset, length_offset) = match index {
            0 => (0x34, 0x30),
            1 => (0x3c, 0x38),
            _ => return None,
        };
        let length = read_u32(&self.raw, length_offset);
        (length != 0).then(|| DeviceRegion {
            start: read_u32(&self.raw, start_offset),
            length,
        })
    }
}

fn decode_stem(field: &[u8], name: &'static str) -> Result<String, DeviceDatabaseError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let decoded: Vec<u8> = field[..end]
        .iter()
        .zip(STEM_XOR_KEY)
        .map(|(byte, key)| byte ^ key)
        .collect();
    if !decoded.is_ascii() {
        return Err(DeviceDatabaseError::InvalidText { field: name });
    }
    Ok(String::from_utf8(decoded).expect("ASCII is UTF-8"))
}

fn decode_text(field: &[u8], name: &'static str) -> Result<String, DeviceDatabaseError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let value = &field[..end];
    if let Ok(text) = std::str::from_utf8(value) {
        return Ok(text.to_owned());
    }
    let (text, had_errors) = GBK.decode_without_bom_handling(value);
    if had_errors {
        return Err(DeviceDatabaseError::InvalidText { field: name });
    }
    Ok(text.into_owned())
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

fn validate_bcd_timestamp(timestamp: [u8; 8]) -> Result<(), DeviceDatabaseError> {
    let invalid_digit = timestamp[..7]
        .iter()
        .any(|byte| byte >> 4 > 9 || byte & 0x0f > 9);
    if invalid_digit || timestamp[7] != 0 {
        return Err(DeviceDatabaseError::InvalidBcdTimestamp { actual: timestamp });
    }
    Ok(())
}

/// Computes the non-standard SFLY CRC16 used by DEV and CFG assets.
#[must_use]
pub fn sfly_crc16(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0_u16, |crc, byte| {
        ((crc << 8) | u16::from(*byte)) ^ ccitt_table_entry((crc >> 8) as u8)
    })
}

fn ccitt_table_entry(index: u8) -> u16 {
    (0..8).fold(u16::from(index) << 8, |crc, _| {
        if crc & 0x8000 == 0 {
            crc << 1
        } else {
            (crc << 1) ^ 0x1021
        }
    })
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DeviceDatabaseError {
    #[error("device database is too short: {actual} bytes, minimum is {minimum}")]
    TooShort { actual: usize, minimum: usize },
    #[error("invalid device database magic: {actual:02x?}")]
    InvalidMagic { actual: [u8; 4] },
    #[error("device database header XOR is {actual:#04x}, expected zero")]
    HeaderXor { actual: u8 },
    #[error("unsupported device database version {actual}")]
    UnsupportedVersion { actual: u16 },
    #[error("device database file name mismatch: expected {expected}, found {actual}")]
    FileNameMismatch { expected: String, actual: String },
    #[error("invalid BCD device database timestamp: {actual:02x?}")]
    InvalidBcdTimestamp { actual: [u8; 8] },
    #[error("device database table size overflow")]
    TableSizeOverflow,
    #[error("unexpected device database length: {actual} bytes, expected {expected}")]
    UnexpectedLength { actual: usize, expected: usize },
    #[error("device database CRC16 mismatch: stored {stored:#06x}, computed {computed:#06x}")]
    CrcMismatch { stored: u16, computed: u16 },
    #[error("device database sum is {actual:#06x}, expected {expected:#06x}")]
    SumMismatch { actual: u16, expected: u16 },
    #[error(
        "vendor {vendor_index} range {first_device_index}+{device_count} exceeds {catalog_device_count} devices"
    )]
    VendorRangeOutOfBounds {
        vendor_index: usize,
        first_device_index: usize,
        device_count: usize,
        catalog_device_count: usize,
    },
    #[error(
        "device {device_index} references vendor {vendor_index}, but only {vendor_count} exist"
    )]
    InvalidVendorReference {
        device_index: usize,
        vendor_index: usize,
        vendor_count: usize,
    },
    #[error("device {device_index} has an empty algorithm stem")]
    EmptyAlgorithmStem { device_index: usize },
    #[error("invalid text in device database {field}")]
    InvalidText { field: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_stem(target: &mut [u8], stem: &str) {
        for (index, byte) in stem.bytes().enumerate() {
            target[index] = byte ^ STEM_XOR_KEY[index];
        }
    }

    fn fixture() -> Vec<u8> {
        let mut bytes =
            vec![0_u8; HEADER_BYTES + VENDOR_RECORD_BYTES + DEVICE_RECORD_BYTES + TRAILER_BYTES];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[0x04..0x06].copy_from_slice(&SUPPORTED_VERSION.to_le_bytes());
        bytes[0x08..0x0c].copy_from_slice(&1_u32.to_le_bytes());
        bytes[0x0c..0x10].copy_from_slice(&1_u32.to_le_bytes());
        bytes[0x10..0x19].copy_from_slice(b"SP20.dev\0");
        bytes[0x20..0x28].copy_from_slice(&[0x20, 0x26, 0x07, 0x14, 0x21, 0x00, 0x25, 0]);

        let header_xor = bytes[..HEADER_BYTES]
            .iter()
            .copied()
            .fold(0_u8, std::ops::BitXor::bitxor);
        bytes[HEADER_BYTES - 1] = header_xor;

        let vendor_offset = HEADER_BYTES;
        bytes[vendor_offset..vendor_offset + 4].copy_from_slice(b"WB\0\0");
        bytes[vendor_offset + 8..vendor_offset + 12].copy_from_slice(&1_u32.to_le_bytes());
        bytes[vendor_offset + 0x10..vendor_offset + 0x18].copy_from_slice(b"Winbond\0");

        let device_offset = HEADER_BYTES + VENDOR_RECORD_BYTES;
        bytes[device_offset..device_offset + 10].copy_from_slice(b"W25Q128BV\0");
        bytes[device_offset + 0x20] = 0;
        bytes[device_offset + 0x30..device_offset + 0x34]
            .copy_from_slice(&0x0100_0000_u32.to_le_bytes());
        encode_stem(
            &mut bytes[device_offset + 0x50..device_offset + 0x60],
            "W25Q128",
        );
        encode_stem(
            &mut bytes[device_offset + 0x60..device_offset + 0x70],
            "W25Q128S",
        );

        let crc_offset = bytes.len() - TRAILER_BYTES;
        let crc = sfly_crc16(&bytes[..crc_offset]);
        bytes[crc_offset..crc_offset + 2].copy_from_slice(&crc.to_le_bytes());
        let sum = bytes[..bytes.len() - 2]
            .iter()
            .fold(0_u16, |sum, byte| sum.wrapping_add(u16::from(*byte)));
        let correction = TRAILER_SUM.wrapping_sub(sum);
        let sum_offset = bytes.len() - 2;
        bytes[sum_offset..].copy_from_slice(&correction.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_catalog_and_preserves_raw_records() {
        let database =
            DeviceDatabase::parse_for_file_name(&fixture(), "sp20.dev").expect("valid fixture");

        assert_eq!(database.version(), 2);
        assert_eq!(database.vendors()[0].name(), "Winbond");
        assert_eq!(database.devices()[0].name(), "W25Q128BV");
        assert_eq!(database.devices()[0].algorithm_stem(), "W25Q128");
        assert_eq!(database.devices()[0].configuration_stem(), Some("W25Q128S"));
        assert_eq!(database.devices()[0].raw().len(), DEVICE_RECORD_BYTES);
        assert_eq!(
            database.devices()[0].data_region(0),
            Some(DeviceRegion {
                start: 0,
                length: 0x0100_0000
            })
        );
        assert_eq!(database.devices()[0].data_region(1), None);
    }

    #[test]
    fn rejects_header_corruption_before_reading_tables() {
        let mut bytes = fixture();
        bytes[0x30] ^= 1;

        assert!(matches!(
            DeviceDatabase::parse(&bytes),
            Err(DeviceDatabaseError::HeaderXor { .. })
        ));
    }

    #[test]
    fn rejects_trailer_corruption() {
        let mut bytes = fixture();
        bytes[HEADER_BYTES + VENDOR_RECORD_BYTES] ^= 1;

        assert!(matches!(
            DeviceDatabase::parse(&bytes),
            Err(DeviceDatabaseError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn finds_devices_by_vendor_or_part() {
        let database = DeviceDatabase::parse(&fixture()).expect("valid fixture");

        assert_eq!(database.find_devices("q128").count(), 1);
        assert_eq!(database.find_devices("winbond").count(), 1);
        assert_eq!(database.find_devices("missing").count(), 0);
    }

    #[test]
    fn selects_an_exact_device_with_optional_vendor_filter() {
        let database = DeviceDatabase::parse(&fixture()).expect("valid fixture");

        let selected = database
            .select_device("w25q128bv", None)
            .expect("exact device");
        assert_eq!(selected.device().algorithm_stem(), "W25Q128");
        assert_eq!(selected.vendor().name(), "Winbond");
        assert_eq!(
            database
                .select_device("W25Q128BV", Some("wb"))
                .expect("vendor code")
                .vendor()
                .code(),
            "WB"
        );
        assert!(matches!(
            database.select_device("W25Q128BV", Some("GigaDevice")),
            Err(DeviceSelectionError::NotFound { .. })
        ));
    }
}
