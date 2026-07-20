//! Static operation state machines for blank-check, program, read, verify,
//! configuration, erase, and progress-event command families.

use std::time::Duration;

use thiserror::Error;

use crate::{
    protocol::{
        COMMAND_BYTES, CONFIGURATION_READ_BYTES, CommandBlock, ConfigurationMismatch,
        ConfigurationWritePayload, EraseMode, OperationDiagnostic, ProtocolError,
        completion_status_accepted, configuration_mismatch,
    },
    transport::{
        COMMAND_TIMEOUT, Cancellation, InPipe, OutPipe, PAYLOAD_TIMEOUT, TransferOptions, Transport,
    },
};

pub const BLANK_INITIALIZE_TIMEOUT: Duration = Duration::from_millis(2_000);
pub const BLANK_CHUNK_TIMEOUT: Duration = Duration::from_millis(5_000);
pub const BLANK_FINISH_TIMEOUT: Duration = Duration::from_millis(1_000);
pub const READ_DATA_TIMEOUT: Duration = Duration::from_millis(2_000);
pub const VERIFY_DATA_TIMEOUT: Duration = Duration::from_millis(3_000);
pub const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_millis(500);
pub const EVENT_RECORD_TIMEOUT: Duration = Duration::from_millis(2_000);
pub const ERASE_COMPLETION_TIMEOUT: Duration = Duration::from_millis(1_000_000);

/// Timeouts not assigned a separate call-site value in the static field table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationTimings {
    pub completion: Duration,
    pub diagnostic: Duration,
}

impl Default for OperationTimings {
    fn default() -> Self {
        Self {
            completion: Duration::from_millis(600),
            diagnostic: DIAGNOSTIC_TIMEOUT,
        }
    }
}

/// Raw accepted completion bytes retained for auditing one operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OperationReceipt {
    statuses: Vec<u8>,
}

impl OperationReceipt {
    #[must_use]
    pub fn statuses(&self) -> &[u8] {
        &self.statuses
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    pub data: Vec<u8>,
    pub receipt: OperationReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationReadResult {
    pub data: [u8; CONFIGURATION_READ_BYTES],
    pub receipt: OperationReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressEvent {
    pub stage_or_progress: u8,
    pub finished: bool,
    pub raw: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressResult {
    pub events: Vec<ProgressEvent>,
    pub receipt: OperationReceipt,
}

/// Explicit controls for the partially named `0x0013` path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EraseRequest {
    pub path_selector: u32,
    pub mode: EraseMode,
    /// Read the optional 64-byte `0x83` result used by a static branch.
    pub read_result: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EraseResult {
    pub raw_result: Option<[u8; COMMAND_BYTES]>,
    pub receipt: OperationReceipt,
}

/// One exclusive operation stream over an already prepared programmer.
pub struct OperationSession<'a, T: Transport> {
    transport: &'a mut T,
    cancellation: &'a dyn Cancellation,
    timings: OperationTimings,
}

impl<'a, T: Transport> OperationSession<'a, T> {
    #[must_use]
    pub fn new(transport: &'a mut T, cancellation: &'a dyn Cancellation) -> Self {
        Self {
            transport,
            cancellation,
            timings: OperationTimings::default(),
        }
    }

    #[must_use]
    pub fn with_timings(mut self, timings: OperationTimings) -> Self {
        self.timings = timings;
        self
    }

    /// Executes `0x0015 -> 0x0014* -> 0x0016`.
    ///
    /// # Errors
    ///
    /// Fails on invalid lengths, transport errors, or rejected completion.
    pub fn blank_check(
        &mut self,
        region: u32,
        region_length: usize,
        chunk_bytes: usize,
    ) -> Result<OperationReceipt, OperationError<T::Error>> {
        let total = operation_length(region_length)?;
        if !(0x800..=0x1_0000).contains(&chunk_bytes) {
            return Err(OperationError::InvalidBlankChunk {
                actual: chunk_bytes,
            });
        }
        let mut receipt = OperationReceipt::default();
        self.command(
            &CommandBlock::blank_check_initialize(region, total),
            OperationStage::BlankInitialize,
        )?;
        self.completion(
            OperationStage::BlankInitialize,
            BLANK_INITIALIZE_TIMEOUT,
            &mut receipt,
        )?;
        for offset in (0..region_length).step_by(chunk_bytes) {
            let length = chunk_bytes.min(region_length - offset);
            self.command(
                &CommandBlock::blank_check_chunk(region, to_u32(offset)?, to_u32(length)?),
                OperationStage::BlankChunk { offset },
            )?;
            self.completion(
                OperationStage::BlankChunk { offset },
                BLANK_CHUNK_TIMEOUT,
                &mut receipt,
            )?;
        }
        self.command(
            &CommandBlock::blank_check_finish(region),
            OperationStage::BlankFinish,
        )?;
        self.completion(
            OperationStage::BlankFinish,
            BLANK_FINISH_TIMEOUT,
            &mut receipt,
        )?;
        Ok(receipt)
    }

    /// Executes `0x0019 -> 0x0098* -> 0x001A` without automatic retries.
    ///
    /// # Errors
    ///
    /// Fails on invalid lengths, transport errors, or rejected completion.
    pub fn program(
        &mut self,
        region: u32,
        data: &[u8],
        minimum_primary_chunk: u16,
    ) -> Result<OperationReceipt, OperationError<T::Error>> {
        let total = operation_length(data.len())?;
        let chunk_bytes = transfer_chunk_size(region, data.len(), minimum_primary_chunk)?;
        let mut receipt = OperationReceipt::default();
        self.command(
            &CommandBlock::program_initialize(region, total),
            OperationStage::ProgramInitialize,
        )?;
        self.completion(
            OperationStage::ProgramInitialize,
            self.timings.completion,
            &mut receipt,
        )?;
        for offset in (0..data.len()).step_by(chunk_bytes) {
            let chunk = &data[offset..(offset + chunk_bytes).min(data.len())];
            let stage = OperationStage::ProgramChunk { offset };
            self.command(
                &CommandBlock::program_chunk(region, to_u32(offset)?, to_u32(chunk.len())?),
                stage,
            )?;
            self.write_payload(chunk, stage)?;
            self.completion(stage, self.timings.completion, &mut receipt)?;
        }
        self.command(
            &CommandBlock::program_finish(region),
            OperationStage::ProgramFinish,
        )?;
        self.completion(
            OperationStage::ProgramFinish,
            self.timings.completion,
            &mut receipt,
        )?;
        Ok(receipt)
    }

    /// Reads one region through `0x001B -> 0x001D -> 0x001E`.
    ///
    /// # Errors
    ///
    /// Fails on invalid lengths, transport errors, or rejected completion.
    pub fn read(
        &mut self,
        region: u32,
        length: usize,
        minimum_primary_chunk: u16,
    ) -> Result<ReadResult, OperationError<T::Error>> {
        self.read_or_verify(region, length, minimum_primary_chunk, None)
            .map(|(data, receipt)| ReadResult { data, receipt })
    }

    /// Reads and compares one region without leaving unread data behind after
    /// the first mismatch.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError::VerifyMismatch`] after the receive and finish
    /// stages complete, or fails immediately on transport/protocol errors.
    pub fn verify(
        &mut self,
        region: u32,
        expected: &[u8],
        minimum_primary_chunk: u16,
    ) -> Result<OperationReceipt, OperationError<T::Error>> {
        let (_, receipt) = self.read_or_verify(
            region,
            expected.len(),
            minimum_primary_chunk,
            Some(expected),
        )?;
        Ok(receipt)
    }

    /// Sends `0x00A3` and its exact 256-byte payload.
    ///
    /// # Errors
    ///
    /// Fails on transport errors or rejected completion.
    pub fn write_configuration(
        &mut self,
        data: &[u8; CONFIGURATION_READ_BYTES],
        mask: &[u8; CONFIGURATION_READ_BYTES],
    ) -> Result<OperationReceipt, OperationError<T::Error>> {
        let mut receipt = OperationReceipt::default();
        self.command(
            &CommandBlock::write_configuration(),
            OperationStage::ConfigurationWrite,
        )?;
        let payload = ConfigurationWritePayload::new(data, mask);
        self.write_payload(payload.as_bytes(), OperationStage::ConfigurationWrite)?;
        self.completion(
            OperationStage::ConfigurationWrite,
            self.timings.completion,
            &mut receipt,
        )?;
        Ok(receipt)
    }

    /// Sends `0x0025`, waits for completion, then reads exactly 64 bytes.
    ///
    /// # Errors
    ///
    /// Fails on transport errors or rejected completion.
    pub fn read_configuration(
        &mut self,
    ) -> Result<ConfigurationReadResult, OperationError<T::Error>> {
        let mut receipt = OperationReceipt::default();
        self.command(
            &CommandBlock::read_configuration(),
            OperationStage::ConfigurationRead,
        )?;
        self.completion(
            OperationStage::ConfigurationRead,
            self.timings.completion,
            &mut receipt,
        )?;
        let mut data = [0; CONFIGURATION_READ_BYTES];
        self.read_response(
            &mut data,
            OperationStage::ConfigurationRead,
            READ_DATA_TIMEOUT,
        )?;
        Ok(ConfigurationReadResult { data, receipt })
    }

    /// Reads and applies the confirmed masked configuration comparison.
    ///
    /// # Errors
    ///
    /// Returns a configuration mismatch or any read-operation failure.
    pub fn verify_configuration(
        &mut self,
        expected: &[u8; CONFIGURATION_READ_BYTES],
        mask: &[u8; CONFIGURATION_READ_BYTES],
    ) -> Result<OperationReceipt, OperationError<T::Error>> {
        let result = self.read_configuration()?;
        if let Some(mismatch) = configuration_mismatch(expected, &result.data, mask) {
            return Err(OperationError::ConfigurationMismatch(mismatch));
        }
        Ok(result.receipt)
    }

    /// Sends the shared `0x0013` erase command. No failed stage is replayed.
    ///
    /// # Errors
    ///
    /// Fails on transport errors or rejected completion.
    pub fn erase(
        &mut self,
        request: EraseRequest,
    ) -> Result<EraseResult, OperationError<T::Error>> {
        let mut receipt = OperationReceipt::default();
        self.command(
            &CommandBlock::erase(request.path_selector, request.mode),
            OperationStage::Erase,
        )?;
        self.completion(
            OperationStage::Erase,
            ERASE_COMPLETION_TIMEOUT,
            &mut receipt,
        )?;
        let raw_result = if request.read_result {
            let mut result = [0; COMMAND_BYTES];
            self.read_response(&mut result, OperationStage::EraseResult, READ_DATA_TIMEOUT)?;
            Some(result)
        } else {
            None
        };
        Ok(EraseResult {
            raw_result,
            receipt,
        })
    }

    /// Runs `0x003A`, collects 16-byte events through the finish flag, then
    /// consumes the final completion byte.
    ///
    /// # Errors
    ///
    /// Fails on transport errors, rejected completion, or `max_records` before
    /// an event with `raw[1] & 0x80 != 0` arrives.
    pub fn progress_events(
        &mut self,
        max_records: usize,
    ) -> Result<ProgressResult, OperationError<T::Error>> {
        self.command(
            &CommandBlock::progress_events(),
            OperationStage::ProgressStart,
        )?;
        let mut events = Vec::new();
        loop {
            if events.len() == max_records {
                return Err(OperationError::ProgressLimit { max_records });
            }
            let mut raw = [0; 16];
            self.read_specialized(
                &mut raw,
                OperationStage::ProgressEvent,
                EVENT_RECORD_TIMEOUT,
            )?;
            let event = ProgressEvent {
                stage_or_progress: raw[2],
                finished: raw[1] & 0x80 != 0,
                raw,
            };
            let finished = event.finished;
            events.push(event);
            if finished {
                break;
            }
        }
        let mut receipt = OperationReceipt::default();
        self.completion(
            OperationStage::ProgressFinish,
            self.timings.completion,
            &mut receipt,
        )?;
        Ok(ProgressResult { events, receipt })
    }

    fn read_or_verify(
        &mut self,
        region: u32,
        length: usize,
        minimum_primary_chunk: u16,
        expected: Option<&[u8]>,
    ) -> Result<(Vec<u8>, OperationReceipt), OperationError<T::Error>> {
        let total = operation_length(length)?;
        let chunk_bytes = transfer_chunk_size(region, length, minimum_primary_chunk)?;
        let mut receipt = OperationReceipt::default();
        self.command(
            &CommandBlock::read_initialize(region, total),
            OperationStage::ReadInitialize,
        )?;
        self.completion(
            OperationStage::ReadInitialize,
            self.timings.completion,
            &mut receipt,
        )?;
        self.command(
            &CommandBlock::read_data(region, total),
            OperationStage::ReadDataCommand,
        )?;
        let mut data = vec![0; length];
        let mut mismatch = None;
        for offset in (0..length).step_by(chunk_bytes) {
            let end = (offset + chunk_bytes).min(length);
            let stage = OperationStage::ReadData { offset };
            self.read_response(
                &mut data[offset..end],
                stage,
                if expected.is_some() {
                    VERIFY_DATA_TIMEOUT
                } else {
                    READ_DATA_TIMEOUT
                },
            )?;
            if mismatch.is_none() {
                if let Some(reference) = expected {
                    mismatch = data[offset..end]
                        .iter()
                        .zip(&reference[offset..end])
                        .position(|(actual, expected)| actual != expected)
                        .map(|relative| VerifyMismatch {
                            offset: offset + relative,
                            expected: reference[offset + relative],
                            actual: data[offset + relative],
                        });
                }
            }
        }
        self.command(
            &CommandBlock::read_finish(region),
            OperationStage::ReadFinish,
        )?;
        self.completion(
            OperationStage::ReadFinish,
            self.timings.completion,
            &mut receipt,
        )?;
        if let Some(mismatch) = mismatch {
            return Err(OperationError::VerifyMismatch(mismatch));
        }
        Ok((data, receipt))
    }

    fn command(
        &mut self,
        command: &CommandBlock,
        stage: OperationStage,
    ) -> Result<(), OperationError<T::Error>> {
        let options = transfer_options(COMMAND_TIMEOUT, self.cancellation);
        self.transport
            .write_exact(OutPipe::Command, command.as_bytes(), options)
            .map_err(|source| OperationError::Transport { stage, source })
    }

    fn write_payload(
        &mut self,
        payload: &[u8],
        stage: OperationStage,
    ) -> Result<(), OperationError<T::Error>> {
        let options = transfer_options(PAYLOAD_TIMEOUT, self.cancellation);
        self.transport
            .write_exact(OutPipe::Payload, payload, options)
            .map_err(|source| OperationError::Transport { stage, source })
    }

    fn read_response(
        &mut self,
        bytes: &mut [u8],
        stage: OperationStage,
        timeout: Duration,
    ) -> Result<(), OperationError<T::Error>> {
        let options = transfer_options(timeout, self.cancellation);
        self.transport
            .read_exact(InPipe::Response, bytes, options)
            .map_err(|source| OperationError::Transport { stage, source })
    }

    fn read_specialized(
        &mut self,
        bytes: &mut [u8],
        stage: OperationStage,
        timeout: Duration,
    ) -> Result<(), OperationError<T::Error>> {
        let options = transfer_options(timeout, self.cancellation);
        self.transport
            .read_exact(InPipe::Specialized, bytes, options)
            .map_err(|source| OperationError::Transport { stage, source })
    }

    fn completion(
        &mut self,
        stage: OperationStage,
        timeout: Duration,
        receipt: &mut OperationReceipt,
    ) -> Result<(), OperationError<T::Error>> {
        let mut status = [0];
        let options = transfer_options(timeout, self.cancellation);
        self.transport
            .read_exact(InPipe::Completion, &mut status, options)
            .map_err(|source| OperationError::Transport { stage, source })?;
        if completion_status_accepted(status[0]) {
            receipt.statuses.push(status[0]);
            return Ok(());
        }

        let mut raw = [0; 64];
        let options = transfer_options(self.timings.diagnostic, self.cancellation);
        self.transport
            .read_exact(InPipe::AuxiliaryResult, &mut raw, options)
            .map_err(|source| OperationError::DiagnosticTransport {
                stage,
                raw_status: status[0],
                source,
            })?;
        let diagnostic = OperationDiagnostic::parse(&raw).map_err(OperationError::Protocol)?;
        Err(OperationError::CompletionRejected {
            stage,
            raw_status: status[0],
            diagnostic,
        })
    }
}

/// Confirmed primary-region chunk selector from `0x0042B820`.
///
/// # Errors
///
/// Rejects zero total length or values that cannot fit protocol fields.
pub fn transfer_chunk_size(
    region: u32,
    total_length: usize,
    minimum_primary_chunk: u16,
) -> Result<usize, OperationInputError> {
    if total_length == 0 {
        return Err(OperationInputError::ZeroLength);
    }
    u32::try_from(total_length).map_err(|_| OperationInputError::LengthOverflow {
        actual: total_length,
    })?;
    if region != 0 {
        return Ok(total_length);
    }
    let scaled = total_length >> 5;
    let buckets = [
        0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x1_0000,
    ];
    let selected = buckets
        .into_iter()
        .rev()
        .find(|bucket| *bucket <= scaled)
        .unwrap_or(0x40);
    Ok(selected.max(usize::from(minimum_primary_chunk)))
}

fn operation_length<E>(length: usize) -> Result<u32, OperationError<E>> {
    if length == 0 {
        return Err(OperationError::Input(OperationInputError::ZeroLength));
    }
    u32::try_from(length)
        .map_err(|_| OperationError::Input(OperationInputError::LengthOverflow { actual: length }))
}

fn to_u32<E>(value: usize) -> Result<u32, OperationError<E>> {
    u32::try_from(value)
        .map_err(|_| OperationError::Input(OperationInputError::LengthOverflow { actual: value }))
}

const fn transfer_options(
    timeout: Duration,
    cancellation: &dyn Cancellation,
) -> TransferOptions<'_> {
    TransferOptions {
        timeout,
        cancellation,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStage {
    BlankInitialize,
    BlankChunk { offset: usize },
    BlankFinish,
    ProgramInitialize,
    ProgramChunk { offset: usize },
    ProgramFinish,
    ReadInitialize,
    ReadDataCommand,
    ReadData { offset: usize },
    ReadFinish,
    ConfigurationWrite,
    ConfigurationRead,
    Erase,
    EraseResult,
    ProgressStart,
    ProgressEvent,
    ProgressFinish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyMismatch {
    pub offset: usize,
    pub expected: u8,
    pub actual: u8,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OperationInputError {
    #[error("operation length must be non-zero")]
    ZeroLength,
    #[error("operation length {actual} does not fit a 32-bit protocol field")]
    LengthOverflow { actual: usize },
}

#[derive(Debug, Error)]
pub enum OperationError<E> {
    #[error(transparent)]
    Input(#[from] OperationInputError),
    #[error("blank-check chunk size {actual} is outside 0x800..=0x10000")]
    InvalidBlankChunk { actual: usize },
    #[error("transport failed during {stage:?}: {source}")]
    Transport {
        stage: OperationStage,
        #[source]
        source: E,
    },
    #[error("diagnostic read failed after status {raw_status:#04x} during {stage:?}: {source}")]
    DiagnosticTransport {
        stage: OperationStage,
        raw_status: u8,
        #[source]
        source: E,
    },
    #[error("status {raw_status:#04x} rejected during {stage:?}; diagnostic code {code:#04x}", code = diagnostic.code())]
    CompletionRejected {
        stage: OperationStage,
        raw_status: u8,
        diagnostic: OperationDiagnostic,
    },
    #[error("protocol response error: {0}")]
    Protocol(#[source] ProtocolError),
    #[error("verification mismatch: {0:?}")]
    VerifyMismatch(VerifyMismatch),
    #[error("configuration mismatch: {0:?}")]
    ConfigurationMismatch(ConfigurationMismatch),
    #[error("progress stream did not finish within {max_records} records")]
    ProgressLimit { max_records: usize },
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, convert::Infallible};

    use super::*;
    use crate::transport::NeverCancelled;

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

    fn write(command: CommandBlock) -> Io {
        Io::Write(OutPipe::Command, command.into_bytes().to_vec())
    }

    fn accepted() -> Io {
        Io::Read(InPipe::Completion, vec![0x20])
    }

    #[test]
    fn selects_static_primary_chunk_buckets() {
        assert_eq!(transfer_chunk_size(0, 1, 0).expect("valid"), 0x40);
        assert_eq!(transfer_chunk_size(0, 0x4000, 0).expect("valid"), 0x200);
        assert_eq!(transfer_chunk_size(0, 0x4000, 0x800).expect("valid"), 0x800);
        assert_eq!(
            transfer_chunk_size(1, 0x12_345, 0).expect("valid"),
            0x12_345
        );
    }

    #[test]
    fn replays_program_sequence_and_chunk_boundaries() {
        let data = vec![0x5a; 0x801];
        let io = VecDeque::from([
            write(CommandBlock::program_initialize(0, 0x801)),
            accepted(),
            write(CommandBlock::program_chunk(0, 0, 0x800)),
            Io::Write(OutPipe::Payload, data[..0x800].to_vec()),
            accepted(),
            write(CommandBlock::program_chunk(0, 0x800, 1)),
            Io::Write(OutPipe::Payload, vec![0x5a]),
            accepted(),
            write(CommandBlock::program_finish(0)),
            accepted(),
        ]);
        let mut transport = MockTransport::new(io);
        let mut session = OperationSession::new(&mut transport, &NeverCancelled);

        let receipt = session.program(0, &data, 0x800).expect("program succeeds");

        assert_eq!(receipt.statuses(), &[0x20; 4]);
        transport.assert_done();
    }

    #[test]
    fn verify_drains_data_and_finishes_before_reporting_mismatch() {
        let expected = [1, 2, 3, 4];
        let io = VecDeque::from([
            write(CommandBlock::read_initialize(0, 4)),
            accepted(),
            write(CommandBlock::read_data(0, 4)),
            Io::Read(InPipe::Response, vec![1, 2, 0, 4]),
            write(CommandBlock::read_finish(0)),
            accepted(),
        ]);
        let mut transport = MockTransport::new(io);
        let mut session = OperationSession::new(&mut transport, &NeverCancelled);

        let error = session.verify(0, &expected, 64).expect_err("mismatch");

        assert!(matches!(
            error,
            OperationError::VerifyMismatch(VerifyMismatch {
                offset: 2,
                expected: 3,
                actual: 0
            })
        ));
        transport.assert_done();
    }

    #[test]
    fn rejected_status_consumes_one_diagnostic() {
        let mut diagnostic = vec![0; 64];
        diagnostic[0] = 0x0e;
        let io = VecDeque::from([
            write(CommandBlock::blank_check_initialize(0, 0x800)),
            Io::Read(InPipe::Completion, vec![0]),
            Io::Read(InPipe::AuxiliaryResult, diagnostic),
        ]);
        let mut transport = MockTransport::new(io);
        let mut session = OperationSession::new(&mut transport, &NeverCancelled);

        let error = session.blank_check(0, 0x800, 0x800).expect_err("rejected");

        assert!(matches!(
            error,
            OperationError::CompletionRejected {
                raw_status: 0,
                diagnostic,
                ..
            } if diagnostic.code() == 0x0e
        ));
        transport.assert_done();
    }

    #[test]
    fn replays_blank_check_initial_chunks_and_finish() {
        let io = VecDeque::from([
            write(CommandBlock::blank_check_initialize(1, 0x1000)),
            accepted(),
            write(CommandBlock::blank_check_chunk(1, 0, 0x800)),
            accepted(),
            write(CommandBlock::blank_check_chunk(1, 0x800, 0x800)),
            accepted(),
            write(CommandBlock::blank_check_finish(1)),
            accepted(),
        ]);
        let mut transport = MockTransport::new(io);
        let mut session = OperationSession::new(&mut transport, &NeverCancelled);

        let receipt = session
            .blank_check(1, 0x1000, 0x800)
            .expect("blank check succeeds");

        assert_eq!(receipt.statuses(), &[0x20; 4]);
        transport.assert_done();
    }

    #[test]
    fn replays_configuration_write_and_read() {
        let data = [0xa5; CONFIGURATION_READ_BYTES];
        let mask = [0x5a; CONFIGURATION_READ_BYTES];
        let payload = ConfigurationWritePayload::new(&data, &mask);
        let io = VecDeque::from([
            write(CommandBlock::write_configuration()),
            Io::Write(OutPipe::Payload, payload.as_bytes().to_vec()),
            accepted(),
            write(CommandBlock::read_configuration()),
            accepted(),
            Io::Read(InPipe::Response, data.to_vec()),
        ]);
        let mut transport = MockTransport::new(io);
        let mut session = OperationSession::new(&mut transport, &NeverCancelled);

        session
            .write_configuration(&data, &mask)
            .expect("configuration write succeeds");
        let read = session
            .read_configuration()
            .expect("configuration read succeeds");

        assert_eq!(read.data, data);
        transport.assert_done();
    }

    #[test]
    fn erase_optional_result_is_explicit() {
        let result = [0x33; COMMAND_BYTES];
        let io = VecDeque::from([
            write(CommandBlock::erase(0x20, EraseMode::Automatic)),
            accepted(),
            Io::Read(InPipe::Response, result.to_vec()),
        ]);
        let mut transport = MockTransport::new(io);
        let mut session = OperationSession::new(&mut transport, &NeverCancelled);

        let erased = session
            .erase(EraseRequest {
                path_selector: 0x20,
                mode: EraseMode::Automatic,
                read_result: true,
            })
            .expect("erase succeeds");

        assert_eq!(erased.raw_result, Some(result));
        transport.assert_done();
    }

    #[test]
    fn reads_progress_until_finish_then_completion() {
        let io = VecDeque::from([
            write(CommandBlock::progress_events()),
            Io::Read(
                InPipe::Specialized,
                vec![0, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            Io::Read(
                InPipe::Specialized,
                vec![0, 0x80, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
            accepted(),
        ]);
        let mut transport = MockTransport::new(io);
        let mut session = OperationSession::new(&mut transport, &NeverCancelled);

        let result = session.progress_events(3).expect("progress succeeds");

        assert_eq!(result.events.len(), 2);
        assert_eq!(result.events[0].stage_or_progress, 25);
        assert!(result.events[1].finished);
        transport.assert_done();
    }
}
