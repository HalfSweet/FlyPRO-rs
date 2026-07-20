//! Confirmed algorithm preparation state machine.
//!
//! The ordering follows `F-ALG-021` through `F-ALG-026`. Completion-byte
//! semantics are deliberately injected because `Q-PROTO-002` is unresolved.

use thiserror::Error;

use crate::{
    assets::algorithm::Algorithm,
    protocol::{
        AlgorithmChunk, AlgorithmVerification, CommandBlock, DeviceParameterImage, ProtocolError,
    },
    transport::{
        ALGORITHM_COMPLETION_TIMEOUT, ALGORITHM_VERIFY_TIMEOUT, COMMAND_TIMEOUT, Cancellation,
        Delay, InPipe, OutPipe, PAYLOAD_TIMEOUT, POST_DOWNLOAD_DELAY, TransferOptions, Transport,
    },
};

/// Stable identity retained by the host for one live device session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmIdentity {
    name: String,
    timestamp: [u8; 8],
    payload_length: usize,
    payload_crc32: u32,
}

impl AlgorithmIdentity {
    #[must_use]
    pub fn from_algorithm(algorithm: &Algorithm) -> Self {
        Self {
            name: algorithm.name().to_owned(),
            timestamp: algorithm.timestamp(),
            payload_length: algorithm.payload().len(),
            payload_crc32: algorithm.payload_crc32(),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn timestamp(&self) -> [u8; 8] {
        self.timestamp
    }

    #[must_use]
    pub const fn payload_length(&self) -> usize {
        self.payload_length
    }

    #[must_use]
    pub const fn payload_crc32(&self) -> u32 {
        self.payload_crc32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStage {
    VerifyCommandOut,
    VerifyResponseIn,
    AlgorithmCommandOut { offset: usize },
    AlgorithmPayloadOut { offset: usize },
    AlgorithmCompletionIn { offset: usize },
    DeviceParameterCommandOut,
    DeviceParameterPayloadOut,
    DeviceParameterCompletionIn,
}

/// Firmware/version-specific interpretation of an observed completion byte.
///
/// There is intentionally no default implementation.
pub trait CompletionPolicy {
    #[must_use]
    fn accepts(&self, stage: TransferStage, raw_status: u8) -> bool;
}

impl<F> CompletionPolicy for F
where
    F: Fn(TransferStage, u8) -> bool,
{
    fn accepts(&self, stage: TransferStage, raw_status: u8) -> bool {
        self(stage, raw_status)
    }
}

/// State retained only for one live programmer transport session.
#[derive(Debug, Default)]
pub struct AlgorithmSession {
    ready_identity: Option<AlgorithmIdentity>,
}

impl AlgorithmSession {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ready_identity: None,
        }
    }

    #[must_use]
    pub fn ready_identity(&self) -> Option<&AlgorithmIdentity> {
        self.ready_identity.as_ref()
    }

    pub fn reset(&mut self) {
        self.ready_identity = None;
    }

    /// Ensures an algorithm is accepted by the device and always sends the
    /// independent device parameter image before returning ready.
    ///
    /// # Errors
    ///
    /// Returns [`PrepareError`] on encoding, transport, completion-policy, or
    /// post-download verification failure. No failed transport stage is
    /// automatically replayed.
    pub fn prepare<T, P, D>(
        &mut self,
        transport: &mut T,
        completion_policy: &P,
        delay: &mut D,
        cancellation: &dyn Cancellation,
        algorithm: &Algorithm,
        parameters: &DeviceParameterImage,
    ) -> Result<AlgorithmReady, PrepareError<T::Error>>
    where
        T: Transport,
        P: CompletionPolicy,
        D: Delay,
    {
        let result = self.prepare_inner(
            transport,
            completion_policy,
            delay,
            cancellation,
            algorithm,
            parameters,
        );
        if result.is_err() {
            // After any incomplete transaction the device-side algorithm state
            // is not trusted, even if it had previously been verified.
            self.ready_identity = None;
        }
        result
    }

    fn prepare_inner<T, P, D>(
        &mut self,
        transport: &mut T,
        completion_policy: &P,
        delay: &mut D,
        cancellation: &dyn Cancellation,
        algorithm: &Algorithm,
        parameters: &DeviceParameterImage,
    ) -> Result<AlgorithmReady, PrepareError<T::Error>>
    where
        T: Transport,
        P: CompletionPolicy,
        D: Delay,
    {
        let expected_identity = AlgorithmIdentity::from_algorithm(algorithm);
        let identity_is_current = self.ready_identity.as_ref() == Some(&expected_identity);
        let reused = identity_is_current
            && verify_algorithm(transport, cancellation, algorithm.name())?
                .matches(algorithm.name());

        let mut completion_statuses = Vec::new();
        if !reused {
            self.ready_identity = None;
            download_algorithm(
                transport,
                completion_policy,
                cancellation,
                algorithm,
                &mut completion_statuses,
            )?;
            delay.delay(POST_DOWNLOAD_DELAY);
            let verification = verify_algorithm(transport, cancellation, algorithm.name())?;
            if !verification.matches(algorithm.name()) {
                return Err(PrepareError::PostDownloadVerification {
                    expected_name: algorithm.name().to_owned(),
                    device_name: verification.device_name().to_owned(),
                    sentinel: verification.sentinel(),
                });
            }
            self.ready_identity = Some(expected_identity.clone());
        }

        send_parameters(
            transport,
            completion_policy,
            cancellation,
            parameters,
            &mut completion_statuses,
        )?;
        Ok(AlgorithmReady {
            identity: expected_identity,
            reused,
            completion_statuses,
        })
    }
}

fn verify_algorithm<T: Transport>(
    transport: &mut T,
    cancellation: &dyn Cancellation,
    _expected_name: &str,
) -> Result<AlgorithmVerification, PrepareError<T::Error>> {
    let command = CommandBlock::verify_device_algorithm();
    transport
        .write_exact(
            OutPipe::Command,
            command.as_bytes(),
            options(COMMAND_TIMEOUT, cancellation),
        )
        .map_err(|source| PrepareError::Transport {
            stage: TransferStage::VerifyCommandOut,
            source,
        })?;
    let mut response = [0_u8; 64];
    transport
        .read_exact(
            InPipe::Response,
            &mut response,
            options(ALGORITHM_VERIFY_TIMEOUT, cancellation),
        )
        .map_err(|source| PrepareError::Transport {
            stage: TransferStage::VerifyResponseIn,
            source,
        })?;
    AlgorithmVerification::parse(&response).map_err(PrepareError::Protocol)
}

fn download_algorithm<T, P>(
    transport: &mut T,
    completion_policy: &P,
    cancellation: &dyn Cancellation,
    algorithm: &Algorithm,
    statuses: &mut Vec<u8>,
) -> Result<(), PrepareError<T::Error>>
where
    T: Transport,
    P: CompletionPolicy,
{
    for offset in (0..algorithm.payload().len()).step_by(0x800) {
        let chunk = AlgorithmChunk::new(algorithm, offset).map_err(PrepareError::Protocol)?;
        transport
            .write_exact(
                OutPipe::Command,
                chunk.command().as_bytes(),
                options(COMMAND_TIMEOUT, cancellation),
            )
            .map_err(|source| PrepareError::Transport {
                stage: TransferStage::AlgorithmCommandOut { offset },
                source,
            })?;
        transport
            .write_exact(
                OutPipe::Payload,
                chunk.payload(),
                options(PAYLOAD_TIMEOUT, cancellation),
            )
            .map_err(|source| PrepareError::Transport {
                stage: TransferStage::AlgorithmPayloadOut { offset },
                source,
            })?;
        read_completion(
            transport,
            completion_policy,
            cancellation,
            TransferStage::AlgorithmCompletionIn { offset },
            statuses,
        )?;
    }
    Ok(())
}

fn send_parameters<T, P>(
    transport: &mut T,
    completion_policy: &P,
    cancellation: &dyn Cancellation,
    parameters: &DeviceParameterImage,
    statuses: &mut Vec<u8>,
) -> Result<(), PrepareError<T::Error>>
where
    T: Transport,
    P: CompletionPolicy,
{
    let command = CommandBlock::download_device_parameters();
    transport
        .write_exact(
            OutPipe::Command,
            command.as_bytes(),
            options(COMMAND_TIMEOUT, cancellation),
        )
        .map_err(|source| PrepareError::Transport {
            stage: TransferStage::DeviceParameterCommandOut,
            source,
        })?;
    transport
        .write_exact(
            OutPipe::Payload,
            parameters.as_bytes(),
            options(PAYLOAD_TIMEOUT, cancellation),
        )
        .map_err(|source| PrepareError::Transport {
            stage: TransferStage::DeviceParameterPayloadOut,
            source,
        })?;
    read_completion(
        transport,
        completion_policy,
        cancellation,
        TransferStage::DeviceParameterCompletionIn,
        statuses,
    )
}

fn read_completion<T, P>(
    transport: &mut T,
    completion_policy: &P,
    cancellation: &dyn Cancellation,
    stage: TransferStage,
    statuses: &mut Vec<u8>,
) -> Result<(), PrepareError<T::Error>>
where
    T: Transport,
    P: CompletionPolicy,
{
    let mut status = [0_u8; 1];
    transport
        .read_exact(
            InPipe::Completion,
            &mut status,
            options(ALGORITHM_COMPLETION_TIMEOUT, cancellation),
        )
        .map_err(|source| PrepareError::Transport { stage, source })?;
    statuses.push(status[0]);
    if !completion_policy.accepts(stage, status[0]) {
        return Err(PrepareError::CompletionRejected {
            stage,
            raw_status: status[0],
        });
    }
    Ok(())
}

const fn options(
    timeout: std::time::Duration,
    cancellation: &dyn Cancellation,
) -> TransferOptions<'_> {
    TransferOptions {
        timeout,
        cancellation,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmReady {
    identity: AlgorithmIdentity,
    reused: bool,
    completion_statuses: Vec<u8>,
}

impl AlgorithmReady {
    #[must_use]
    pub const fn identity(&self) -> &AlgorithmIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn reused(&self) -> bool {
        self.reused
    }

    #[must_use]
    pub fn completion_statuses(&self) -> &[u8] {
        &self.completion_statuses
    }
}

#[derive(Debug, Error)]
pub enum PrepareError<E> {
    #[error("protocol encoding or response validation failed: {0}")]
    Protocol(#[source] ProtocolError),
    #[error("transport failed during {stage:?}: {source}")]
    Transport {
        stage: TransferStage,
        #[source]
        source: E,
    },
    #[error("completion policy rejected {raw_status:#04x} during {stage:?}")]
    CompletionRejected {
        stage: TransferStage,
        raw_status: u8,
    },
    #[error(
        "post-download verification failed: expected {expected_name}, got {device_name} with sentinel {sentinel:#010x}"
    )]
    PostDownloadVerification {
        expected_name: String,
        device_name: String,
        sentinel: u32,
    },
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, convert::Infallible, time::Duration};

    use crc32fast::hash;

    use super::*;
    use crate::{
        assets::algorithm::{CRC32_BYTES, HEADER_BYTES, RESERVED_BYTES},
        protocol::VERIFY_SENTINEL,
        transport::NeverCancelled,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ExpectedIo {
        Write(OutPipe, Vec<u8>),
        Read(InPipe, Vec<u8>),
    }

    #[derive(Default)]
    struct MockTransport {
        expected: VecDeque<ExpectedIo>,
    }

    impl MockTransport {
        fn scripted(expected: Vec<ExpectedIo>) -> Self {
            Self {
                expected: expected.into(),
            }
        }

        fn done(&self) -> bool {
            self.expected.is_empty()
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
            assert_eq!(
                self.expected.pop_front(),
                Some(ExpectedIo::Write(pipe, bytes.to_vec()))
            );
            Ok(())
        }

        fn read_exact(
            &mut self,
            pipe: InPipe,
            bytes: &mut [u8],
            _options: TransferOptions<'_>,
        ) -> Result<(), Self::Error> {
            let Some(ExpectedIo::Read(expected_pipe, data)) = self.expected.pop_front() else {
                panic!("expected scripted read");
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

    fn algorithm() -> Algorithm {
        let payload_length = 0x1000_usize;
        let mut bytes = vec![0_u8; HEADER_BYTES + payload_length + RESERVED_BYTES + CRC32_BYTES];
        bytes[..4].copy_from_slice(b"ALG\0");
        bytes[0x08..0x0a].copy_from_slice(
            &u16::try_from(payload_length)
                .expect("fixture length fits")
                .to_le_bytes(),
        );
        bytes[0x10..0x18].copy_from_slice(b"W25Q128\0");
        bytes[0x20..0x28].copy_from_slice(&[0x20, 0x24, 0x05, 0x18, 0x13, 0x04, 0x30, 0]);
        bytes[HEADER_BYTES..HEADER_BYTES + payload_length].fill(0x5a);
        let crc_offset = bytes.len() - CRC32_BYTES;
        let crc = hash(&bytes[..crc_offset]);
        bytes[crc_offset..].copy_from_slice(&crc.to_le_bytes());
        Algorithm::parse(&bytes).expect("valid fixture")
    }

    fn verification(name: &str, sentinel: u32) -> Vec<u8> {
        let mut response = vec![0_u8; 64];
        response[..name.len()].copy_from_slice(name.as_bytes());
        response[0x3c..0x40].copy_from_slice(&sentinel.to_le_bytes());
        response
    }

    fn fresh_session_script(algorithm: &Algorithm, status: u8) -> Vec<ExpectedIo> {
        let mut script = Vec::new();
        for offset in [0, 0x800] {
            let chunk = AlgorithmChunk::new(algorithm, offset).expect("valid chunk");
            script.push(ExpectedIo::Write(
                OutPipe::Command,
                chunk.command().as_bytes().to_vec(),
            ));
            script.push(ExpectedIo::Write(
                OutPipe::Payload,
                chunk.payload().to_vec(),
            ));
            script.push(ExpectedIo::Read(InPipe::Completion, vec![status]));
        }
        script.push(ExpectedIo::Write(
            OutPipe::Command,
            CommandBlock::verify_device_algorithm().as_bytes().to_vec(),
        ));
        script.push(ExpectedIo::Read(
            InPipe::Response,
            verification(algorithm.name(), VERIFY_SENTINEL),
        ));
        script.push(ExpectedIo::Write(
            OutPipe::Command,
            CommandBlock::download_device_parameters()
                .as_bytes()
                .to_vec(),
        ));
        script.push(ExpectedIo::Write(OutPipe::Payload, vec![0_u8; 0x800]));
        script.push(ExpectedIo::Read(InPipe::Completion, vec![status]));
        script
    }

    #[test]
    fn fresh_session_downloads_verifies_and_sends_parameters() {
        let algorithm = algorithm();
        let parameters = DeviceParameterImage::from_bytes([0; 0x800]);
        let mut transport = MockTransport::scripted(fresh_session_script(&algorithm, 0x42));
        let mut delay = RecordingDelay::default();
        let mut session = AlgorithmSession::new();

        let ready = session
            .prepare(
                &mut transport,
                &|_, status| status == 0x42,
                &mut delay,
                &NeverCancelled,
                &algorithm,
                &parameters,
            )
            .expect("script succeeds");

        assert!(!ready.reused());
        assert_eq!(ready.completion_statuses(), &[0x42, 0x42, 0x42]);
        assert_eq!(delay.0, vec![POST_DOWNLOAD_DELAY]);
        assert!(transport.done());
        assert_eq!(session.ready_identity(), Some(ready.identity()));
    }

    #[test]
    fn ready_session_verifies_before_reuse_and_still_sends_parameters() {
        let algorithm = algorithm();
        let parameters = DeviceParameterImage::from_bytes([0; 0x800]);
        let mut first_transport = MockTransport::scripted(fresh_session_script(&algorithm, 0x42));
        let mut delay = RecordingDelay::default();
        let mut session = AlgorithmSession::new();
        session
            .prepare(
                &mut first_transport,
                &|_, status| status == 0x42,
                &mut delay,
                &NeverCancelled,
                &algorithm,
                &parameters,
            )
            .expect("first preparation succeeds");

        let script = vec![
            ExpectedIo::Write(
                OutPipe::Command,
                CommandBlock::verify_device_algorithm().as_bytes().to_vec(),
            ),
            ExpectedIo::Read(
                InPipe::Response,
                verification(algorithm.name(), VERIFY_SENTINEL),
            ),
            ExpectedIo::Write(
                OutPipe::Command,
                CommandBlock::download_device_parameters()
                    .as_bytes()
                    .to_vec(),
            ),
            ExpectedIo::Write(OutPipe::Payload, vec![0; 0x800]),
            ExpectedIo::Read(InPipe::Completion, vec![0x42]),
        ];
        let mut transport = MockTransport::scripted(script);
        let ready = session
            .prepare(
                &mut transport,
                &|_, status| status == 0x42,
                &mut delay,
                &NeverCancelled,
                &algorithm,
                &parameters,
            )
            .expect("reuse succeeds");

        assert!(ready.reused());
        assert_eq!(ready.completion_statuses(), &[0x42]);
        assert!(transport.done());
    }

    #[test]
    fn completion_status_requires_explicit_policy_acceptance() {
        let algorithm = algorithm();
        let chunk = AlgorithmChunk::new(&algorithm, 0).expect("valid chunk");
        let mut transport = MockTransport::scripted(vec![
            ExpectedIo::Write(OutPipe::Command, chunk.command().as_bytes().to_vec()),
            ExpectedIo::Write(OutPipe::Payload, chunk.payload().to_vec()),
            ExpectedIo::Read(InPipe::Completion, vec![0xff]),
        ]);
        let mut session = AlgorithmSession::new();

        let error = session
            .prepare(
                &mut transport,
                &|_, _| false,
                &mut RecordingDelay::default(),
                &NeverCancelled,
                &algorithm,
                &DeviceParameterImage::from_bytes([0; 0x800]),
            )
            .expect_err("policy must reject status");

        assert!(matches!(
            error,
            PrepareError::CompletionRejected {
                raw_status: 0xff,
                ..
            }
        ));
        assert!(session.ready_identity().is_none());
    }
}
