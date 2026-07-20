//! Encoding for the three application commands with confirmed semantics.
//!
//! `0x0008`, `0x0087`, and `0x008A` follow facts `F-PROTO-010` through
//! `F-PROTO-018`. Other observed command identifiers intentionally have no
//! constructors.

use thiserror::Error;

use crate::assets::algorithm::Algorithm;

pub const COMMAND_BYTES: usize = 64;
pub const ALGORITHM_CHUNK_MAX_BYTES: usize = 0x800;
pub const DEVICE_PARAMETER_BYTES: usize = 0x800;
pub const VERIFY_SENTINEL: u32 = 0x5555_5555;

/// Commands whose semantics are confirmed by the current baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KnownCommand {
    VerifyDeviceAlgorithm = 0x0008,
    DownloadAlgorithmChunk = 0x0087,
    DownloadDeviceParameters = 0x008a,
}

impl From<KnownCommand> for u16 {
    fn from(value: KnownCommand) -> Self {
        value as Self
    }
}

/// A zero-initialized, exactly 64-byte command block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandBlock {
    command: KnownCommand,
    bytes: [u8; COMMAND_BYTES],
}

impl CommandBlock {
    fn new(command: KnownCommand) -> Self {
        let mut bytes = [0; COMMAND_BYTES];
        bytes[..2].copy_from_slice(&u16::from(command).to_le_bytes());
        Self { command, bytes }
    }

    #[must_use]
    pub fn verify_device_algorithm() -> Self {
        Self::new(KnownCommand::VerifyDeviceAlgorithm)
    }

    #[must_use]
    pub fn download_device_parameters() -> Self {
        let mut block = Self::new(KnownCommand::DownloadDeviceParameters);
        block.bytes[0x0c..0x10].copy_from_slice(&0x800_u32.to_le_bytes());
        block
    }

    #[must_use]
    pub const fn command(&self) -> KnownCommand {
        self.command
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; COMMAND_BYTES] {
        &self.bytes
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; COMMAND_BYTES] {
        self.bytes
    }
}

/// One confirmed `0x0087` command and its matching payload slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmChunk<'a> {
    offset: usize,
    command: CommandBlock,
    payload: &'a [u8],
}

impl<'a> AlgorithmChunk<'a> {
    /// Builds the chunk beginning at `offset` and caps it at `0x800` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] when the algorithm name cannot be encoded or
    /// the offset is outside the payload.
    pub fn new(algorithm: &'a Algorithm, offset: usize) -> Result<Self, ProtocolError> {
        if offset >= algorithm.payload().len() {
            return Err(ProtocolError::ChunkOffset {
                offset,
                payload_length: algorithm.payload().len(),
            });
        }
        let name = EncodedAlgorithmName::new(algorithm.name())?;
        let end = offset
            .saturating_add(ALGORITHM_CHUNK_MAX_BYTES)
            .min(algorithm.payload().len());
        let payload = &algorithm.payload()[offset..end];
        let offset_u32 = u32::try_from(offset).map_err(|_| ProtocolError::IntegerOverflow)?;
        let length_u32 =
            u32::try_from(payload.len()).map_err(|_| ProtocolError::IntegerOverflow)?;

        let mut command = CommandBlock::new(KnownCommand::DownloadAlgorithmChunk);
        command.bytes[0x08..0x0c].copy_from_slice(&offset_u32.to_le_bytes());
        command.bytes[0x0c..0x10].copy_from_slice(&length_u32.to_le_bytes());
        command.bytes[0x10..0x20].copy_from_slice(name.as_bytes());
        command.bytes[0x20..0x28].copy_from_slice(&algorithm.timestamp());
        Ok(Self {
            offset,
            command,
            payload,
        })
    }

    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    #[must_use]
    pub const fn command(&self) -> &CommandBlock {
        &self.command
    }

    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Opaque, exactly 2048-byte device parameter context for `0x008A`.
///
/// No builder from a DEV record is provided because that construction schema
/// remains unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceParameterImage(Box<[u8; DEVICE_PARAMETER_BYTES]>);

impl DeviceParameterImage {
    #[must_use]
    pub fn from_bytes(bytes: [u8; DEVICE_PARAMETER_BYTES]) -> Self {
        Self(Box::new(bytes))
    }

    /// Copies an exact-length raw parameter image.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::DeviceParameterLength`] unless the slice is
    /// exactly 2048 bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let array: [u8; DEVICE_PARAMETER_BYTES] =
            bytes
                .try_into()
                .map_err(|_| ProtocolError::DeviceParameterLength {
                    actual: bytes.len(),
                    expected: DEVICE_PARAMETER_BYTES,
                })?;
        Ok(Self::from_bytes(array))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DEVICE_PARAMETER_BYTES] {
        &self.0
    }
}

/// Parsed result of the `0x0008` device-side algorithm identity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmVerification {
    device_name: String,
    sentinel: u32,
    raw: [u8; COMMAND_BYTES],
}

impl AlgorithmVerification {
    /// Parses an exact 64-byte response without treating the observed sentinel
    /// as a global success code.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] for a short/long response or invalid name.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let raw: [u8; COMMAND_BYTES] =
            bytes
                .try_into()
                .map_err(|_| ProtocolError::VerificationResponseLength {
                    actual: bytes.len(),
                    expected: COMMAND_BYTES,
                })?;
        let name_field = &raw[..16];
        let name_end = name_field
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ProtocolError::InvalidVerificationName)?;
        let name = &name_field[..name_end];
        if name.is_empty() || !name.is_ascii() {
            return Err(ProtocolError::InvalidVerificationName);
        }
        let device_name = std::str::from_utf8(name)
            .map_err(|_| ProtocolError::InvalidVerificationName)?
            .to_owned();
        Ok(Self {
            device_name,
            sentinel: u32::from_le_bytes([raw[0x3c], raw[0x3d], raw[0x3e], raw[0x3f]]),
            raw,
        })
    }

    #[must_use]
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    #[must_use]
    pub const fn sentinel(&self) -> u32 {
        self.sentinel
    }

    #[must_use]
    pub fn matches(&self, expected_name: &str) -> bool {
        self.device_name.eq_ignore_ascii_case(expected_name) && self.sentinel == VERIFY_SENTINEL
    }

    #[must_use]
    pub const fn raw(&self) -> &[u8; COMMAND_BYTES] {
        &self.raw
    }
}

struct EncodedAlgorithmName([u8; 16]);

impl EncodedAlgorithmName {
    fn new(name: &str) -> Result<Self, ProtocolError> {
        if name.is_empty() || !name.is_ascii() || name.len() >= 16 {
            return Err(ProtocolError::AlgorithmName {
                name: name.to_owned(),
                maximum_bytes: 15,
            });
        }
        let mut bytes = [0; 16];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self(bytes))
    }

    const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("algorithm name {name:?} must be 1..={maximum_bytes} ASCII bytes")]
    AlgorithmName { name: String, maximum_bytes: usize },
    #[error("algorithm chunk offset {offset} is outside payload length {payload_length}")]
    ChunkOffset {
        offset: usize,
        payload_length: usize,
    },
    #[error("protocol field does not fit its confirmed integer width")]
    IntegerOverflow,
    #[error("device parameter image is {actual} bytes, expected {expected}")]
    DeviceParameterLength { actual: usize, expected: usize },
    #[error("algorithm verification response is {actual} bytes, expected {expected}")]
    VerificationResponseLength { actual: usize, expected: usize },
    #[error("algorithm verification response has an invalid name field")]
    InvalidVerificationName,
}

#[cfg(test)]
mod tests {
    use crc32fast::hash;

    use super::*;
    use crate::assets::algorithm::{CRC32_BYTES, HEADER_BYTES, RESERVED_BYTES};

    fn algorithm(payload_length: usize) -> Algorithm {
        let mut bytes = vec![0_u8; HEADER_BYTES + payload_length + RESERVED_BYTES + CRC32_BYTES];
        bytes[..4].copy_from_slice(b"ALG\0");
        bytes[0x08..0x0a].copy_from_slice(
            &u16::try_from(payload_length)
                .expect("fixture length fits")
                .to_le_bytes(),
        );
        bytes[0x0a..0x0c].copy_from_slice(&0x0100_u16.to_le_bytes());
        bytes[0x10..0x18].copy_from_slice(b"W25Q128\0");
        bytes[0x20..0x28].copy_from_slice(&[0x20, 0x24, 0x05, 0x18, 0x13, 0x04, 0x30, 0]);
        for (index, byte) in bytes[HEADER_BYTES..HEADER_BYTES + payload_length]
            .iter_mut()
            .enumerate()
        {
            *byte = u8::try_from(index % 251).expect("modulo fits u8");
        }
        let crc_start = bytes.len() - CRC32_BYTES;
        let crc = hash(&bytes[..crc_start]);
        bytes[crc_start..].copy_from_slice(&crc.to_le_bytes());
        Algorithm::parse(&bytes).expect("valid fixture")
    }

    #[test]
    fn encodes_w25q128_first_chunk_golden_header() {
        let algorithm = algorithm(0x4000);
        let chunk = AlgorithmChunk::new(&algorithm, 0).expect("valid chunk");
        let mut expected = [0_u8; COMMAND_BYTES];
        expected[0..2].copy_from_slice(&0x0087_u16.to_le_bytes());
        expected[0x0c..0x10].copy_from_slice(&0x800_u32.to_le_bytes());
        expected[0x10..0x17].copy_from_slice(b"W25Q128");
        expected[0x20..0x28].copy_from_slice(&[0x20, 0x24, 0x05, 0x18, 0x13, 0x04, 0x30, 0]);

        assert_eq!(chunk.command().as_bytes(), &expected);
        assert_eq!(chunk.payload().len(), 0x800);
    }

    #[test]
    fn caps_final_algorithm_chunk_at_remaining_payload() {
        let algorithm = algorithm(0x801);
        let chunk = AlgorithmChunk::new(&algorithm, 0x800).expect("valid final chunk");

        assert_eq!(chunk.payload().len(), 1);
        assert_eq!(
            &chunk.command().as_bytes()[0x08..0x0c],
            &0x800_u32.to_le_bytes()
        );
        assert_eq!(
            &chunk.command().as_bytes()[0x0c..0x10],
            &1_u32.to_le_bytes()
        );
    }

    #[test]
    fn encodes_zero_filled_verify_and_parameter_commands() {
        let verify = CommandBlock::verify_device_algorithm();
        assert_eq!(&verify.as_bytes()[..2], &0x0008_u16.to_le_bytes());
        assert!(verify.as_bytes()[2..].iter().all(|byte| *byte == 0));

        let parameters = CommandBlock::download_device_parameters();
        assert_eq!(&parameters.as_bytes()[..2], &0x008a_u16.to_le_bytes());
        assert_eq!(&parameters.as_bytes()[0x0c..0x10], &0x800_u32.to_le_bytes());
    }

    #[test]
    fn verification_requires_matching_name_and_observed_sentinel() {
        let mut response = [0_u8; COMMAND_BYTES];
        response[..7].copy_from_slice(b"w25q128");
        response[0x3c..].copy_from_slice(&VERIFY_SENTINEL.to_le_bytes());
        let verification = AlgorithmVerification::parse(&response).expect("valid response");

        assert!(verification.matches("W25Q128"));
        assert!(!verification.matches("OTHER"));
    }
}
