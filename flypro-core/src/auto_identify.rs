//! Non-destructive automatic identification for supported 25-series SPI Flash.
//!
//! This path mirrors `F-AUTO-001` through `F-AUTO-013`: every detection
//! downloads `M25ID.alg`, probes at an explicit voltage, reads an opaque
//! eight-byte result, and returns every catalog candidate whose ID prefix and
//! normalized package class match. A candidate is never promoted to a selected
//! programming profile without an explicit caller decision.

use std::time::Duration;

use thiserror::Error;

use crate::{
    assets::{
        algorithm::Algorithm,
        device_db::{DeviceDatabase, DeviceRecord, VendorRecord},
        package_map::{PackageMap, PackageRecord},
    },
    protocol::{COMMAND_BYTES, CommandBlock, CompletionDisposition, classify_completion_status},
    session::{CompletionPolicy, PrepareError, download_algorithm, verify_algorithm},
    transport::{
        COMMAND_TIMEOUT, Cancellation, Delay, InPipe, OutPipe, POST_DOWNLOAD_DELAY,
        TransferOptions, Transport,
    },
};

pub const IDENTIFICATION_RESULT_BYTES: usize = 8;
pub const IDENTIFICATION_DIAGNOSTIC_BYTES: usize = COMMAND_BYTES;
pub const PROBE_COMPLETION_TIMEOUT: Duration = Duration::from_millis(1_500);
pub const PROBE_DIAGNOSTIC_TIMEOUT: Duration = Duration::from_millis(1_000);
pub const RESULT_COMPLETION_TIMEOUT: Duration = Duration::from_millis(1_000);
pub const RESULT_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// Voltages offered by the original automatic-identification dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentificationVoltage {
    V3_3,
    V1_8,
}

impl IdentificationVoltage {
    #[must_use]
    pub const fn centivolts(self) -> u32 {
        match self {
            Self::V3_3 => 330,
            Self::V1_8 => 180,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::V3_3 => "3.3 V",
            Self::V1_8 => "1.8 V",
        }
    }
}

/// Lossless host-visible result produced by `M25ID.alg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectionResult8 {
    raw: [u8; IDENTIFICATION_RESULT_BYTES],
}

impl DetectionResult8 {
    #[must_use]
    pub const fn from_bytes(raw: [u8; IDENTIFICATION_RESULT_BYTES]) -> Self {
        Self { raw }
    }

    #[must_use]
    pub const fn detected_pin_class(self) -> u16 {
        u16::from_le_bytes([self.raw[0], self.raw[1]])
    }

    /// Bytes whose meaning is still unknown in the static baseline.
    #[must_use]
    pub const fn unknown_bytes(self) -> [u8; 2] {
        [self.raw[2], self.raw[3]]
    }

    #[must_use]
    pub const fn chip_id_bytes(self) -> [u8; 4] {
        [self.raw[4], self.raw[5], self.raw[6], self.raw[7]]
    }

    #[must_use]
    pub const fn raw(self) -> [u8; IDENTIFICATION_RESULT_BYTES] {
        self.raw
    }
}

/// Raw statuses and result retained for one identification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentificationResult {
    detection: DetectionResult8,
    algorithm_completion_statuses: Vec<u8>,
    probe_completion_status: u8,
    result_completion_status: u8,
}

impl IdentificationResult {
    #[must_use]
    pub const fn detection(&self) -> DetectionResult8 {
        self.detection
    }

    #[must_use]
    pub fn algorithm_completion_statuses(&self) -> &[u8] {
        &self.algorithm_completion_statuses
    }

    #[must_use]
    pub const fn probe_completion_status(&self) -> u8 {
        self.probe_completion_status
    }

    #[must_use]
    pub const fn result_completion_status(&self) -> u8 {
        self.result_completion_status
    }
}

/// One original-catalog device/package predicate matched by a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentificationCandidate<'a> {
    device: &'a DeviceRecord,
    vendor: &'a VendorRecord,
    package: &'a PackageRecord,
    id_prefix_length: usize,
}

impl<'a> IdentificationCandidate<'a> {
    #[must_use]
    pub const fn device(self) -> &'a DeviceRecord {
        self.device
    }

    #[must_use]
    pub const fn vendor(self) -> &'a VendorRecord {
        self.vendor
    }

    #[must_use]
    pub const fn package(self) -> &'a PackageRecord {
        self.package
    }

    #[must_use]
    pub fn chip_id_prefix(self) -> &'a [u8] {
        &self.device.raw()[0x24..0x24 + self.id_prefix_length]
    }
}

/// Applies the original host's SPI-family, ID-prefix, and package-class rules.
#[must_use]
pub fn match_identification_candidates<'a>(
    database: &'a DeviceDatabase,
    packages: &'a PackageMap,
    detection: DetectionResult8,
) -> Vec<IdentificationCandidate<'a>> {
    let chip_id = detection.chip_id_bytes();
    let detected_class = detection.detected_pin_class();
    let mut candidates = Vec::new();

    for device in database.devices() {
        if device.raw()[0x22] != 0 {
            continue;
        }
        let Some(id_prefix) = device_id_prefix(device) else {
            continue;
        };
        if chip_id[..id_prefix.len()] != *id_prefix {
            continue;
        }

        for package_key in device.package_keys() {
            let Some(package) = packages.get(package_key) else {
                continue;
            };
            if package.normalized_detection_class() != Some(detected_class) {
                continue;
            }
            candidates.push(IdentificationCandidate {
                device,
                vendor: &database.vendors()[device.vendor_index()],
                package,
                id_prefix_length: id_prefix.len(),
            });
        }
    }
    candidates
}

fn device_id_prefix(device: &DeviceRecord) -> Option<&[u8]> {
    let field = &device.raw()[0x24..0x28];
    let length = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    (length != 0).then_some(&field[..length])
}

/// One exclusive `M25ID` transaction over a claimed programmer.
pub struct SpiFlashIdentificationSession<'a, T: Transport> {
    transport: &'a mut T,
    cancellation: &'a dyn Cancellation,
}

impl<'a, T: Transport> SpiFlashIdentificationSession<'a, T> {
    #[must_use]
    pub fn new(transport: &'a mut T, cancellation: &'a dyn Cancellation) -> Self {
        Self {
            transport,
            cancellation,
        }
    }

    /// Always downloads and verifies `M25ID`, then performs `0x000F -> 0x0012`.
    /// No device parameter image or destructive operation is sent.
    ///
    /// # Errors
    ///
    /// Returns [`IdentificationError`] for a wrong algorithm, algorithm
    /// preparation failure, transport failure, or command-specific rejection.
    pub fn identify<P, D>(
        &mut self,
        completion_policy: &P,
        delay: &mut D,
        algorithm: &Algorithm,
        voltage: IdentificationVoltage,
    ) -> Result<IdentificationResult, IdentificationError<T::Error>>
    where
        P: CompletionPolicy,
        D: Delay,
    {
        if !algorithm.name().eq_ignore_ascii_case("M25ID") {
            return Err(IdentificationError::UnexpectedAlgorithm {
                actual: algorithm.name().to_owned(),
            });
        }

        let mut algorithm_completion_statuses = Vec::new();
        download_algorithm(
            self.transport,
            completion_policy,
            self.cancellation,
            algorithm,
            &mut algorithm_completion_statuses,
        )
        .map_err(IdentificationError::AlgorithmPreparation)?;
        delay.delay(POST_DOWNLOAD_DELAY);
        let verification = verify_algorithm(self.transport, self.cancellation, algorithm.name())
            .map_err(IdentificationError::AlgorithmPreparation)?;
        if !verification.matches(algorithm.name()) {
            return Err(IdentificationError::AlgorithmPreparation(
                PrepareError::PostDownloadVerification {
                    expected_name: algorithm.name().to_owned(),
                    device_name: verification.device_name().to_owned(),
                    sentinel: verification.sentinel(),
                },
            ));
        }

        self.write_command(
            &CommandBlock::spi_flash_identification_probe(voltage.centivolts()),
            IdentificationStage::ProbeCommandOut,
        )?;
        let probe_completion_status = self.read_completion(
            IdentificationStage::ProbeCompletionIn,
            PROBE_COMPLETION_TIMEOUT,
        )?;
        if classify_completion_status(probe_completion_status)
            == CompletionDisposition::AuxiliaryResult
        {
            let mut diagnostic = [0; IDENTIFICATION_DIAGNOSTIC_BYTES];
            self.read_response(
                &mut diagnostic,
                IdentificationStage::ProbeDiagnosticIn,
                PROBE_DIAGNOSTIC_TIMEOUT,
            )?;
            return Err(IdentificationError::ProbeRejected {
                raw_status: probe_completion_status,
                diagnostic,
            });
        }

        self.write_command(
            &CommandBlock::read_spi_flash_identification(),
            IdentificationStage::ResultCommandOut,
        )?;
        let result_completion_status = self.read_completion(
            IdentificationStage::ResultCompletionIn,
            RESULT_COMPLETION_TIMEOUT,
        )?;
        if classify_completion_status(result_completion_status)
            == CompletionDisposition::AuxiliaryResult
        {
            return Err(IdentificationError::ResultRejected {
                raw_status: result_completion_status,
            });
        }

        let mut raw = [0; IDENTIFICATION_RESULT_BYTES];
        self.read_response(
            &mut raw,
            IdentificationStage::ResultResponseIn,
            RESULT_RESPONSE_TIMEOUT,
        )?;
        Ok(IdentificationResult {
            detection: DetectionResult8::from_bytes(raw),
            algorithm_completion_statuses,
            probe_completion_status,
            result_completion_status,
        })
    }

    fn write_command(
        &mut self,
        command: &CommandBlock,
        stage: IdentificationStage,
    ) -> Result<(), IdentificationError<T::Error>> {
        self.transport
            .write_exact(
                OutPipe::Command,
                command.as_bytes(),
                options(COMMAND_TIMEOUT, self.cancellation),
            )
            .map_err(|source| IdentificationError::Transport { stage, source })
    }

    fn read_completion(
        &mut self,
        stage: IdentificationStage,
        timeout: Duration,
    ) -> Result<u8, IdentificationError<T::Error>> {
        let mut status = [0];
        self.transport
            .read_exact(
                InPipe::Completion,
                &mut status,
                options(timeout, self.cancellation),
            )
            .map_err(|source| IdentificationError::Transport { stage, source })?;
        Ok(status[0])
    }

    fn read_response(
        &mut self,
        bytes: &mut [u8],
        stage: IdentificationStage,
        timeout: Duration,
    ) -> Result<(), IdentificationError<T::Error>> {
        self.transport
            .read_exact(InPipe::Response, bytes, options(timeout, self.cancellation))
            .map_err(|source| IdentificationError::Transport { stage, source })
    }
}

const fn options(timeout: Duration, cancellation: &dyn Cancellation) -> TransferOptions<'_> {
    TransferOptions {
        timeout,
        cancellation,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentificationStage {
    ProbeCommandOut,
    ProbeCompletionIn,
    ProbeDiagnosticIn,
    ResultCommandOut,
    ResultCompletionIn,
    ResultResponseIn,
}

#[derive(Debug, Error)]
pub enum IdentificationError<E> {
    #[error("SPI Flash auto-identification requires M25ID, got {actual}")]
    UnexpectedAlgorithm { actual: String },
    #[error("M25ID preparation failed: {0}")]
    AlgorithmPreparation(#[source] PrepareError<E>),
    #[error("transport failed during {stage:?}: {source}")]
    Transport {
        stage: IdentificationStage,
        #[source]
        source: E,
    },
    #[error(
        "SPI Flash probe was rejected with status {raw_status:#04x} and diagnostic {code:#04x}",
        code = diagnostic[0]
    )]
    ProbeRejected {
        raw_status: u8,
        diagnostic: [u8; IDENTIFICATION_DIAGNOSTIC_BYTES],
    },
    #[error(
        "reading the SPI Flash identification result was rejected with status {raw_status:#04x}"
    )]
    ResultRejected { raw_status: u8 },
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, convert::Infallible};

    use super::*;
    use crate::{
        assets::{
            defaults::default_device_database, embedded_algorithms::embedded_algorithm,
            package_map::default_package_map,
        },
        protocol::{AlgorithmChunk, VERIFY_SENTINEL},
        transport::NeverCancelled,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Io {
        Write(OutPipe, Vec<u8>),
        Read(InPipe, Vec<u8>),
    }

    struct MockTransport {
        io: VecDeque<Io>,
    }

    impl MockTransport {
        fn new(io: impl Into<VecDeque<Io>>) -> Self {
            Self { io: io.into() }
        }

        fn assert_done(&self) {
            assert!(self.io.is_empty(), "unconsumed I/O: {:?}", self.io);
        }
    }

    impl Transport for MockTransport {
        type Error = Infallible;

        fn write_exact(
            &mut self,
            pipe: OutPipe,
            bytes: &[u8],
            _options: TransferOptions<'_>,
        ) -> Result<(), Self::Error> {
            assert_eq!(self.io.pop_front(), Some(Io::Write(pipe, bytes.to_vec())));
            Ok(())
        }

        fn read_exact(
            &mut self,
            pipe: InPipe,
            bytes: &mut [u8],
            _options: TransferOptions<'_>,
        ) -> Result<(), Self::Error> {
            let Some(Io::Read(expected_pipe, data)) = self.io.pop_front() else {
                panic!("expected scripted read")
            };
            assert_eq!(pipe, expected_pipe);
            assert_eq!(bytes.len(), data.len());
            bytes.copy_from_slice(&data);
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingDelay(Vec<Duration>);

    impl Delay for RecordingDelay {
        fn delay(&mut self, duration: Duration) {
            self.0.push(duration);
        }
    }

    fn m25id() -> Algorithm {
        embedded_algorithm("m25id")
            .expect("M25ID is embedded")
            .parse()
            .expect("M25ID is valid")
    }

    fn verification(name: &str) -> Vec<u8> {
        let mut response = vec![0; COMMAND_BYTES];
        response[..name.len()].copy_from_slice(name.as_bytes());
        response[0x3c..0x40].copy_from_slice(&VERIFY_SENTINEL.to_le_bytes());
        response
    }

    fn prepared_script(algorithm: &Algorithm) -> Vec<Io> {
        let mut io = Vec::new();
        for offset in (0..algorithm.payload().len()).step_by(0x800) {
            let chunk = AlgorithmChunk::new(algorithm, offset).expect("valid chunk");
            io.push(Io::Write(
                OutPipe::Command,
                chunk.command().as_bytes().to_vec(),
            ));
            io.push(Io::Write(OutPipe::Payload, chunk.payload().to_vec()));
            io.push(Io::Read(InPipe::Completion, vec![0x80]));
        }
        io.push(Io::Write(
            OutPipe::Command,
            CommandBlock::verify_device_algorithm().as_bytes().to_vec(),
        ));
        io.push(Io::Read(InPipe::Response, verification(algorithm.name())));
        io
    }

    #[test]
    fn parses_lossless_detection_result() {
        let result = DetectionResult8::from_bytes([8, 0, 0xaa, 0xbb, 0xef, 0x40, 0x18, 0]);

        assert_eq!(result.detected_pin_class(), 8);
        assert_eq!(result.unknown_bytes(), [0xaa, 0xbb]);
        assert_eq!(result.chip_id_bytes(), [0xef, 0x40, 0x18, 0]);
        assert_eq!(result.raw(), [8, 0, 0xaa, 0xbb, 0xef, 0x40, 0x18, 0]);
    }

    #[test]
    fn replays_original_w25q128bv_candidate_count() {
        let database = default_device_database().expect("database");
        let packages = default_package_map().expect("package map");
        let detection = DetectionResult8::from_bytes([8, 0, 0, 0, 0xef, 0x40, 0x18, 0]);

        let candidates = match_identification_candidates(database, packages, detection);

        assert_eq!(candidates.len(), 35);
        assert!(candidates.iter().any(|candidate| {
            candidate.device().source_index() == 4_187 && candidate.package().key() == 150
        }));
    }

    #[test]
    fn matches_w25q16jv_soic_route_from_its_jedec_prefix() {
        let database = default_device_database().expect("database");
        let packages = default_package_map().expect("package map");
        let detection = DetectionResult8::from_bytes([8, 0, 0, 0, 0xef, 0x40, 0x15, 0]);

        let candidates = match_identification_candidates(database, packages, detection);

        assert_eq!(candidates.len(), 37);
        assert!(candidates.iter().any(|candidate| {
            candidate.device().source_index() == 4_156
                && candidate.device().name() == "W25Q16JVxxxQ"
                && candidate.package().key() == 32
                && candidate.package().package_name() == "SOIC8-150"
        }));
    }

    #[test]
    fn normalizes_package_classes_like_the_original_matcher() {
        let packages = default_package_map().expect("package map");

        assert_eq!(
            packages.get(32).unwrap().normalized_detection_class(),
            Some(8)
        );
        assert_eq!(
            packages.get(190).unwrap().normalized_detection_class(),
            Some(16)
        );
        assert_eq!(
            packages.get(201).unwrap().normalized_detection_class(),
            Some(16)
        );
        assert_eq!(
            packages.get(8).unwrap().normalized_detection_class(),
            Some(0)
        );
    }

    #[test]
    fn downloads_m25id_without_sprj_then_reads_detection() {
        let algorithm = m25id();
        let mut io = prepared_script(&algorithm);
        io.extend([
            Io::Write(
                OutPipe::Command,
                CommandBlock::spi_flash_identification_probe(330)
                    .as_bytes()
                    .to_vec(),
            ),
            Io::Read(InPipe::Completion, vec![0x80]),
            Io::Write(
                OutPipe::Command,
                CommandBlock::read_spi_flash_identification()
                    .as_bytes()
                    .to_vec(),
            ),
            Io::Read(InPipe::Completion, vec![0x80]),
            Io::Read(
                InPipe::Response,
                vec![8, 0, 0xaa, 0xbb, 0xef, 0x40, 0x15, 0],
            ),
        ]);
        let mut transport = MockTransport::new(io);
        let mut delay = RecordingDelay::default();

        let result = SpiFlashIdentificationSession::new(&mut transport, &NeverCancelled)
            .identify(
                &crate::session::StaticCompletionPolicy,
                &mut delay,
                &algorithm,
                IdentificationVoltage::V3_3,
            )
            .expect("identification succeeds");

        assert_eq!(result.algorithm_completion_statuses(), &[0x80; 8]);
        assert_eq!(result.probe_completion_status(), 0x80);
        assert_eq!(result.result_completion_status(), 0x80);
        assert_eq!(result.detection().chip_id_bytes(), [0xef, 0x40, 0x15, 0]);
        assert_eq!(delay.0, [POST_DOWNLOAD_DELAY]);
        transport.assert_done();
    }

    #[test]
    fn probe_rejection_reads_diagnostic_from_response_pipe() {
        let algorithm = m25id();
        let mut io = prepared_script(&algorithm);
        let mut diagnostic = vec![0; IDENTIFICATION_DIAGNOSTIC_BYTES];
        diagnostic[0] = 0x1e;
        io.extend([
            Io::Write(
                OutPipe::Command,
                CommandBlock::spi_flash_identification_probe(180)
                    .as_bytes()
                    .to_vec(),
            ),
            Io::Read(InPipe::Completion, vec![0xc0]),
            Io::Read(InPipe::Response, diagnostic),
        ]);
        let mut transport = MockTransport::new(io);

        let error = SpiFlashIdentificationSession::new(&mut transport, &NeverCancelled)
            .identify(
                &crate::session::StaticCompletionPolicy,
                &mut RecordingDelay::default(),
                &algorithm,
                IdentificationVoltage::V1_8,
            )
            .expect_err("probe rejects");

        assert!(matches!(
            error,
            IdentificationError::ProbeRejected {
                raw_status: 0xc0,
                diagnostic
            } if diagnostic[0] == 0x1e
        ));
        transport.assert_done();
    }
}
