//! Encoding for application commands with statically confirmed semantics.
//!
//! Algorithm commands follow `F-PROTO-010` through `F-PROTO-018`; core
//! operation commands and status handling follow `F-PROTO-024` through
//! `F-PROTO-033`.

use thiserror::Error;

use crate::assets::algorithm::Algorithm;

pub const COMMAND_BYTES: usize = 64;
pub const ALGORITHM_CHUNK_MAX_BYTES: usize = 0x800;
pub const DEVICE_PARAMETER_BYTES: usize = 0x800;
pub const CONFIGURATION_WRITE_BYTES: usize = 0x100;
pub const CONFIGURATION_READ_BYTES: usize = 0x40;
pub const DIAGNOSTIC_BYTES: usize = 0x40;
pub const VERIFY_SENTINEL: u32 = 0x5555_5555;

/// Commands whose semantics are confirmed by the current baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KnownCommand {
    VerifyDeviceAlgorithm = 0x0008,
    Erase = 0x0013,
    BlankCheckChunk = 0x0014,
    BlankCheckInitialize = 0x0015,
    BlankCheckFinish = 0x0016,
    ProgramInitialize = 0x0019,
    ProgramFinish = 0x001a,
    ReadInitialize = 0x001b,
    ReadData = 0x001d,
    ReadFinish = 0x001e,
    ReadConfiguration = 0x0025,
    ProgressEvents = 0x003a,
    DownloadAlgorithmChunk = 0x0087,
    DownloadDeviceParameters = 0x008a,
    ProgramChunk = 0x0098,
    WriteConfiguration = 0x00a3,
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
    pub fn blank_check_initialize(region: u32, region_length: u32) -> Self {
        Self::operation(KnownCommand::BlankCheckInitialize, region, 0, region_length)
    }

    #[must_use]
    pub fn blank_check_chunk(region: u32, offset: u32, chunk_length: u32) -> Self {
        Self::operation(KnownCommand::BlankCheckChunk, region, offset, chunk_length)
    }

    #[must_use]
    pub fn blank_check_finish(region: u32) -> Self {
        Self::operation(KnownCommand::BlankCheckFinish, region, 0, 0)
    }

    #[must_use]
    pub fn program_initialize(region: u32, total_length: u32) -> Self {
        Self::operation(KnownCommand::ProgramInitialize, region, 0, total_length)
    }

    #[must_use]
    pub fn program_chunk(region: u32, offset: u32, chunk_length: u32) -> Self {
        Self::operation(KnownCommand::ProgramChunk, region, offset, chunk_length)
    }

    #[must_use]
    pub fn program_finish(region: u32) -> Self {
        Self::operation(KnownCommand::ProgramFinish, region, 0, 0)
    }

    #[must_use]
    pub fn read_initialize(region: u32, total_length: u32) -> Self {
        Self::operation(KnownCommand::ReadInitialize, region, 0, total_length)
    }

    #[must_use]
    pub fn read_data(region: u32, total_length: u32) -> Self {
        Self::operation(KnownCommand::ReadData, region, 0, total_length)
    }

    #[must_use]
    pub fn read_finish(region: u32) -> Self {
        Self::operation(KnownCommand::ReadFinish, region, 0, 0)
    }

    #[must_use]
    pub fn write_configuration() -> Self {
        Self::operation(KnownCommand::WriteConfiguration, 0, 0, 0x100)
    }

    #[must_use]
    pub fn read_configuration() -> Self {
        Self::operation(KnownCommand::ReadConfiguration, 0, 0, 0x40)
    }

    /// Encodes `0x0013`. `path_selector` remains raw because the static facts
    /// confirm its location but do not yet name its individual bits.
    #[must_use]
    pub fn erase(path_selector: u32, mode: EraseMode) -> Self {
        let mut block = Self::operation(KnownCommand::Erase, path_selector, 0, 0);
        block.bytes[0x10] = mode as u8;
        block
    }

    #[must_use]
    pub fn progress_events() -> Self {
        Self::new(KnownCommand::ProgressEvents)
    }

    fn operation(
        command: KnownCommand,
        region_or_mode: u32,
        offset_or_start: u32,
        length: u32,
    ) -> Self {
        let mut block = Self::new(command);
        block.bytes[0x04..0x08].copy_from_slice(&region_or_mode.to_le_bytes());
        block.bytes[0x08..0x0c].copy_from_slice(&offset_or_start.to_le_bytes());
        block.bytes[0x0c..0x10].copy_from_slice(&length.to_le_bytes());
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

/// Confirmed mode byte for the shared `0x0013` erase path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EraseMode {
    Chip = 0,
    Automatic = 1,
}

/// Exact 256-byte payload sent by `0x00A3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationWritePayload([u8; CONFIGURATION_WRITE_BYTES]);

impl ConfigurationWritePayload {
    #[must_use]
    pub fn new(
        data: &[u8; CONFIGURATION_READ_BYTES],
        mask: &[u8; CONFIGURATION_READ_BYTES],
    ) -> Self {
        let mut bytes = [0; CONFIGURATION_WRITE_BYTES];
        bytes[..CONFIGURATION_READ_BYTES].copy_from_slice(data);
        bytes[0x80..0x80 + CONFIGURATION_READ_BYTES].copy_from_slice(mask);
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONFIGURATION_WRITE_BYTES] {
        &self.0
    }
}

/// Returns the statically confirmed acceptance result for a raw `0x82` byte.
#[must_use]
pub const fn completion_status_accepted(status: u8) -> bool {
    status & 0xa0 != 0 && status & 0x40 == 0
}

/// First masked difference in a configuration readback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationMismatch {
    pub offset: usize,
    pub expected: u8,
    pub actual: u8,
    pub mask: u8,
}

/// Applies the confirmed configuration comparison expression.
#[must_use]
pub fn configuration_mismatch(
    expected: &[u8; CONFIGURATION_READ_BYTES],
    actual: &[u8; CONFIGURATION_READ_BYTES],
    mask: &[u8; CONFIGURATION_READ_BYTES],
) -> Option<ConfigurationMismatch> {
    expected.iter().zip(actual).zip(mask).enumerate().find_map(
        |(offset, ((expected, actual), mask))| {
            ((*expected ^ *actual) & *mask != 0).then_some(ConfigurationMismatch {
                offset,
                expected: *expected,
                actual: *actual,
                mask: *mask,
            })
        },
    )
}

/// Parsed, lossless 64-byte operation diagnostic from Pipe `0x84`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationDiagnostic {
    kind: DiagnosticKind,
    raw: [u8; DIAGNOSTIC_BYTES],
}

impl OperationDiagnostic {
    /// Parses an exact diagnostic block while retaining every raw byte.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::DiagnosticLength`] unless `bytes` contains
    /// exactly 64 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let raw: [u8; DIAGNOSTIC_BYTES] =
            bytes
                .try_into()
                .map_err(|_| ProtocolError::DiagnosticLength {
                    actual: bytes.len(),
                    expected: DIAGNOSTIC_BYTES,
                })?;
        let kind = match raw[0] {
            0x01 => DiagnosticKind::FirmwareSystemError,
            0x02 => DiagnosticKind::CustomProgrammerProductRequired,
            0x04 => DiagnosticKind::ProgrammerDisabled,
            0x0b => DiagnosticKind::ChipInitializationFailed,
            0x0d => DiagnosticKind::VerifyMismatch {
                details: [
                    read_u32_at(&raw, 0x10),
                    read_u32_at(&raw, 0x14),
                    read_u32_at(&raw, 0x18),
                    read_u32_at(&raw, 0x1c),
                ],
            },
            0x0e => DiagnosticKind::BlankCheckFailed {
                address: read_u32_at(&raw, 0x10),
                chip_data: read_u32_at(&raw, 0x14),
            },
            0x0f => DiagnosticKind::ProgramFailed,
            0x10 => DiagnosticKind::ChipReadFailed,
            0x14 => DiagnosticKind::CurrentLimitProtection,
            0x15 => DiagnosticKind::TargetVoltageNotDetected,
            0x16 => DiagnosticKind::IspSupplyConflict,
            0x1e => DiagnosticKind::AdapterNotDetected,
            0x20 => DiagnosticKind::DriverAlgorithmNotMatched,
            0x22 => DiagnosticKind::AdapterMismatch,
            0x24 => DiagnosticKind::AdapterMaximumUseCount,
            0x34 => DiagnosticKind::ChipEccFailure {
                packed_block_page: read_u32_at(&raw, 0x10),
            },
            code => DiagnosticKind::Generic { code },
        };
        Ok(Self { kind, raw })
    }

    #[must_use]
    pub const fn code(&self) -> u8 {
        self.raw[0]
    }

    #[must_use]
    pub const fn kind(&self) -> &DiagnosticKind {
        &self.kind
    }

    #[must_use]
    pub const fn raw(&self) -> &[u8; DIAGNOSTIC_BYTES] {
        &self.raw
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticKind {
    FirmwareSystemError,
    CustomProgrammerProductRequired,
    ProgrammerDisabled,
    ChipInitializationFailed,
    VerifyMismatch { details: [u32; 4] },
    BlankCheckFailed { address: u32, chip_data: u32 },
    ProgramFailed,
    ChipReadFailed,
    CurrentLimitProtection,
    TargetVoltageNotDetected,
    IspSupplyConflict,
    AdapterNotDetected,
    DriverAlgorithmNotMatched,
    AdapterMismatch,
    AdapterMaximumUseCount,
    ChipEccFailure { packed_block_page: u32 },
    Generic { code: u8 },
}

fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("four-byte field"),
    )
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
    #[error("operation diagnostic is {actual} bytes, expected {expected}")]
    DiagnosticLength { actual: usize, expected: usize },
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

    #[test]
    fn encodes_confirmed_operation_command_fields() {
        let cases = [
            (
                CommandBlock::blank_check_initialize(2, 0x1234),
                KnownCommand::BlankCheckInitialize,
                2,
                0,
                0x1234,
            ),
            (
                CommandBlock::blank_check_chunk(2, 0x800, 0x400),
                KnownCommand::BlankCheckChunk,
                2,
                0x800,
                0x400,
            ),
            (
                CommandBlock::program_chunk(1, 0x1000, 0x800),
                KnownCommand::ProgramChunk,
                1,
                0x1000,
                0x800,
            ),
            (
                CommandBlock::read_data(0, 0x20_0000),
                KnownCommand::ReadData,
                0,
                0,
                0x20_0000,
            ),
        ];

        for (block, command, field_04, field_08, field_0c) in cases {
            assert_eq!(block.command(), command);
            assert_eq!(read_u32_at(block.as_bytes(), 0x04), field_04);
            assert_eq!(read_u32_at(block.as_bytes(), 0x08), field_08);
            assert_eq!(read_u32_at(block.as_bytes(), 0x0c), field_0c);
            assert!(block.as_bytes()[0x10..].iter().all(|byte| *byte == 0));
        }

        let erase = CommandBlock::erase(0x20, EraseMode::Automatic);
        assert_eq!(erase.command(), KnownCommand::Erase);
        assert_eq!(read_u32_at(erase.as_bytes(), 0x04), 0x20);
        assert_eq!(erase.as_bytes()[0x10], 1);
    }

    #[test]
    fn builds_and_compares_configuration_payloads() {
        let data = [0x5a; CONFIGURATION_READ_BYTES];
        let mut mask = [0xff; CONFIGURATION_READ_BYTES];
        mask[3] = 0;
        let payload = ConfigurationWritePayload::new(&data, &mask);

        assert_eq!(&payload.as_bytes()[..0x40], &data);
        assert!(payload.as_bytes()[0x40..0x80].iter().all(|byte| *byte == 0));
        assert_eq!(&payload.as_bytes()[0x80..0xc0], &mask);
        assert!(payload.as_bytes()[0xc0..].iter().all(|byte| *byte == 0));

        let mut actual = data;
        actual[3] ^= 1;
        assert_eq!(configuration_mismatch(&data, &actual, &mask), None);
        actual[4] ^= 1;
        assert_eq!(
            configuration_mismatch(&data, &actual, &mask),
            Some(ConfigurationMismatch {
                offset: 4,
                expected: 0x5a,
                actual: 0x5b,
                mask: 0xff,
            })
        );
    }

    #[test]
    fn exhaustively_matches_static_completion_predicate() {
        for value in u8::MIN..=u8::MAX {
            assert_eq!(
                completion_status_accepted(value),
                (value & 0xa0 != 0) && (value & 0x40 == 0)
            );
        }
        assert!(!completion_status_accepted(0));
    }

    #[test]
    fn parses_named_and_generic_diagnostics_losslessly() {
        let mut blank = [0_u8; DIAGNOSTIC_BYTES];
        blank[0] = 0x0e;
        blank[0x10..0x14].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        blank[0x14..0x18].copy_from_slice(&0xa5_u32.to_le_bytes());
        let diagnostic = OperationDiagnostic::parse(&blank).expect("valid diagnostic");
        assert_eq!(
            diagnostic.kind(),
            &DiagnosticKind::BlankCheckFailed {
                address: 0x1234_5678,
                chip_data: 0xa5,
            }
        );
        assert_eq!(diagnostic.raw(), &blank);

        let mut generic = [0_u8; DIAGNOSTIC_BYTES];
        generic[0] = 0x5c;
        assert_eq!(
            OperationDiagnostic::parse(&generic)
                .expect("valid generic diagnostic")
                .kind(),
            &DiagnosticKind::Generic { code: 0x5c }
        );
    }
}
