//! Cross-platform `nusb` implementation of the exact staged transport.

use std::time::{Duration, Instant};

use nusb::{
    Endpoint, Interface, MaybeFuture,
    descriptors::TransferType,
    transfer::{Buffer, Bulk, Completion, In, Interrupt, Out, TransferError},
};
use thiserror::Error;

use crate::{
    transport::{InPipe, OutPipe, TransferOptions, Transport},
    usb::{REQUIRED_PIPE_ADDRESSES, UsbDiscoveryError, matching_device_infos},
};

const CANCELLATION_POLL: Duration = Duration::from_millis(20);
const CANCELLATION_DRAIN_LIMIT: Duration = Duration::from_secs(5);

/// An opened and exclusively claimed SP10/SP20 USB interface.
pub struct NusbTransport {
    _interface: Interface,
    command_out: OutEndpoint,
    payload_out: OutEndpoint,
    completion_in: InEndpoint,
    response_in: InEndpoint,
    diagnostic_in: InEndpoint,
    specialized_in: InEndpoint,
    interface_number: u8,
    alternate_setting: u8,
    usable: bool,
}

impl NusbTransport {
    /// Opens a matching device and claims the first interface/alternate setting
    /// containing all six statically observed Pipe addresses.
    ///
    /// On Linux this detaches a kernel driver for the selected interface when
    /// necessary. Windows and macOS use their native claim behavior.
    ///
    /// # Errors
    ///
    /// Returns [`NusbTransportError`] for discovery, open, descriptor,
    /// interface-claim, alternate-setting, or endpoint failures.
    pub fn open(index: usize) -> Result<Self, NusbTransportError> {
        let infos = matching_device_infos()?;
        let info = infos.get(index).ok_or(UsbDiscoveryError::DeviceIndex {
            requested: index,
            available: infos.len(),
        })?;
        let device = info.open().wait().map_err(NusbTransportError::Open)?;
        let configuration = device
            .active_configuration()
            .map_err(|error| NusbTransportError::ActiveConfiguration(error.to_string()))?;
        let candidate = configuration
            .interface_alt_settings()
            .find_map(|descriptor| interface_candidate(&descriptor))
            .ok_or(NusbTransportError::RequiredPipesNotFound)?;
        let interface = device
            .detach_and_claim_interface(candidate.interface_number)
            .wait()
            .map_err(|source| NusbTransportError::ClaimInterface {
                interface: candidate.interface_number,
                source,
            })?;
        if interface.get_alt_setting() != candidate.alternate_setting {
            interface
                .set_alt_setting(candidate.alternate_setting)
                .wait()
                .map_err(|source| NusbTransportError::SetAlternateSetting {
                    interface: candidate.interface_number,
                    alternate: candidate.alternate_setting,
                    source,
                })?;
        }

        Ok(Self {
            command_out: open_out(&interface, 0x02, candidate.transfer_type(0x02)?)?,
            payload_out: open_out(&interface, 0x03, candidate.transfer_type(0x03)?)?,
            completion_in: open_in(&interface, 0x82, candidate.transfer_type(0x82)?)?,
            response_in: open_in(&interface, 0x83, candidate.transfer_type(0x83)?)?,
            diagnostic_in: open_in(&interface, 0x84, candidate.transfer_type(0x84)?)?,
            specialized_in: open_in(&interface, 0x85, candidate.transfer_type(0x85)?)?,
            _interface: interface,
            interface_number: candidate.interface_number,
            alternate_setting: candidate.alternate_setting,
            usable: true,
        })
    }

    #[must_use]
    pub const fn interface_number(&self) -> u8 {
        self.interface_number
    }

    #[must_use]
    pub const fn alternate_setting(&self) -> u8 {
        self.alternate_setting
    }

    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.usable
    }

    fn out_endpoint(&mut self, pipe: OutPipe) -> &mut OutEndpoint {
        match pipe {
            OutPipe::Command => &mut self.command_out,
            OutPipe::Payload => &mut self.payload_out,
        }
    }

    fn in_endpoint(&mut self, pipe: InPipe) -> &mut InEndpoint {
        match pipe {
            InPipe::Completion => &mut self.completion_in,
            InPipe::Response => &mut self.response_in,
            InPipe::AuxiliaryResult => &mut self.diagnostic_in,
            InPipe::Specialized => &mut self.specialized_in,
        }
    }
}

impl Transport for NusbTransport {
    type Error = NusbTransportError;

    fn write_exact(
        &mut self,
        pipe: OutPipe,
        bytes: &[u8],
        options: TransferOptions<'_>,
    ) -> Result<(), Self::Error> {
        if !self.usable {
            return Err(NusbTransportError::SessionUnusable);
        }
        if bytes.is_empty() {
            return Err(NusbTransportError::ZeroLength {
                pipe: pipe.address(),
            });
        }
        if options.cancellation.is_cancelled() {
            self.usable = false;
            return Err(NusbTransportError::Cancelled {
                pipe: pipe.address(),
            });
        }

        let endpoint = self.out_endpoint(pipe);
        endpoint.submit(Buffer::from(bytes));
        let result = wait_out(endpoint, pipe.address(), bytes.len(), options);
        if result.is_err() {
            self.usable = false;
        }
        result
    }

    fn read_exact(
        &mut self,
        pipe: InPipe,
        bytes: &mut [u8],
        options: TransferOptions<'_>,
    ) -> Result<(), Self::Error> {
        if !self.usable {
            return Err(NusbTransportError::SessionUnusable);
        }
        if bytes.is_empty() {
            return Err(NusbTransportError::ZeroLength {
                pipe: pipe.address(),
            });
        }
        if options.cancellation.is_cancelled() {
            self.usable = false;
            return Err(NusbTransportError::Cancelled {
                pipe: pipe.address(),
            });
        }

        let endpoint = self.in_endpoint(pipe);
        let packet_size = endpoint.max_packet_size();
        if packet_size == 0 {
            return Err(NusbTransportError::InvalidPacketSize {
                pipe: pipe.address(),
            });
        }
        let request_length = bytes.len().div_ceil(packet_size) * packet_size;
        endpoint.submit(Buffer::new(request_length));
        let result = wait_in(endpoint, pipe.address(), bytes, options);
        if result.is_err() {
            self.usable = false;
        }
        result
    }
}

#[derive(Clone)]
struct InterfaceCandidate {
    interface_number: u8,
    alternate_setting: u8,
    endpoints: [(u8, TransferType); 6],
}

impl InterfaceCandidate {
    fn transfer_type(&self, address: u8) -> Result<TransferType, NusbTransportError> {
        self.endpoints
            .iter()
            .find_map(|(candidate, transfer_type)| {
                (*candidate == address).then_some(*transfer_type)
            })
            .ok_or(NusbTransportError::MissingEndpoint { address })
    }
}

fn interface_candidate(
    descriptor: &nusb::descriptors::InterfaceDescriptor<'_>,
) -> Option<InterfaceCandidate> {
    let endpoints: Vec<_> = descriptor
        .endpoints()
        .map(|endpoint| (endpoint.address(), endpoint.transfer_type()))
        .collect();
    let required: Vec<_> = REQUIRED_PIPE_ADDRESSES
        .iter()
        .map(|required| {
            endpoints
                .iter()
                .find(|(address, _)| address == required)
                .copied()
        })
        .collect::<Option<_>>()?;
    Some(InterfaceCandidate {
        interface_number: descriptor.interface_number(),
        alternate_setting: descriptor.alternate_setting(),
        endpoints: required.try_into().ok()?,
    })
}

enum OutEndpoint {
    Bulk(Endpoint<Bulk, Out>),
    Interrupt(Endpoint<Interrupt, Out>),
}

impl OutEndpoint {
    fn submit(&mut self, buffer: Buffer) {
        match self {
            Self::Bulk(endpoint) => endpoint.submit(buffer),
            Self::Interrupt(endpoint) => endpoint.submit(buffer),
        }
    }

    fn wait(&mut self, timeout: Duration) -> Option<Completion> {
        match self {
            Self::Bulk(endpoint) => endpoint.wait_next_complete(timeout),
            Self::Interrupt(endpoint) => endpoint.wait_next_complete(timeout),
        }
    }

    fn cancel_all(&mut self) {
        match self {
            Self::Bulk(endpoint) => endpoint.cancel_all(),
            Self::Interrupt(endpoint) => endpoint.cancel_all(),
        }
    }
}

enum InEndpoint {
    Bulk(Endpoint<Bulk, In>),
    Interrupt(Endpoint<Interrupt, In>),
}

trait PendingEndpoint {
    fn wait(&mut self, timeout: Duration) -> Option<Completion>;
    fn cancel_all(&mut self);
}

impl PendingEndpoint for OutEndpoint {
    fn wait(&mut self, timeout: Duration) -> Option<Completion> {
        Self::wait(self, timeout)
    }

    fn cancel_all(&mut self) {
        Self::cancel_all(self);
    }
}

impl PendingEndpoint for InEndpoint {
    fn wait(&mut self, timeout: Duration) -> Option<Completion> {
        Self::wait(self, timeout)
    }

    fn cancel_all(&mut self) {
        Self::cancel_all(self);
    }
}

impl InEndpoint {
    fn max_packet_size(&self) -> usize {
        match self {
            Self::Bulk(endpoint) => endpoint.max_packet_size(),
            Self::Interrupt(endpoint) => endpoint.max_packet_size(),
        }
    }

    fn submit(&mut self, buffer: Buffer) {
        match self {
            Self::Bulk(endpoint) => endpoint.submit(buffer),
            Self::Interrupt(endpoint) => endpoint.submit(buffer),
        }
    }

    fn wait(&mut self, timeout: Duration) -> Option<Completion> {
        match self {
            Self::Bulk(endpoint) => endpoint.wait_next_complete(timeout),
            Self::Interrupt(endpoint) => endpoint.wait_next_complete(timeout),
        }
    }

    fn cancel_all(&mut self) {
        match self {
            Self::Bulk(endpoint) => endpoint.cancel_all(),
            Self::Interrupt(endpoint) => endpoint.cancel_all(),
        }
    }
}

fn open_out(
    interface: &Interface,
    address: u8,
    transfer_type: TransferType,
) -> Result<OutEndpoint, NusbTransportError> {
    match transfer_type {
        TransferType::Bulk => interface
            .endpoint::<Bulk, Out>(address)
            .map(OutEndpoint::Bulk),
        TransferType::Interrupt => interface
            .endpoint::<Interrupt, Out>(address)
            .map(OutEndpoint::Interrupt),
        unsupported => {
            return Err(NusbTransportError::UnsupportedEndpointType {
                address,
                transfer_type: unsupported,
            });
        }
    }
    .map_err(|source| NusbTransportError::OpenEndpoint { address, source })
}

fn open_in(
    interface: &Interface,
    address: u8,
    transfer_type: TransferType,
) -> Result<InEndpoint, NusbTransportError> {
    match transfer_type {
        TransferType::Bulk => interface
            .endpoint::<Bulk, In>(address)
            .map(InEndpoint::Bulk),
        TransferType::Interrupt => interface
            .endpoint::<Interrupt, In>(address)
            .map(InEndpoint::Interrupt),
        unsupported => {
            return Err(NusbTransportError::UnsupportedEndpointType {
                address,
                transfer_type: unsupported,
            });
        }
    }
    .map_err(|source| NusbTransportError::OpenEndpoint { address, source })
}

fn wait_out(
    endpoint: &mut OutEndpoint,
    pipe: u8,
    expected: usize,
    options: TransferOptions<'_>,
) -> Result<(), NusbTransportError> {
    let completion = wait_for_completion(endpoint, pipe, options)?;
    validate_completion(completion, pipe, expected).map(|_| ())
}

fn wait_in(
    endpoint: &mut InEndpoint,
    pipe: u8,
    bytes: &mut [u8],
    options: TransferOptions<'_>,
) -> Result<(), NusbTransportError> {
    let completion = wait_for_completion(endpoint, pipe, options)?;
    let buffer = validate_completion(completion, pipe, bytes.len())?;
    bytes.copy_from_slice(&buffer[..bytes.len()]);
    Ok(())
}

fn wait_for_completion(
    endpoint: &mut impl PendingEndpoint,
    pipe: u8,
    options: TransferOptions<'_>,
) -> Result<Completion, NusbTransportError> {
    let started = Instant::now();
    loop {
        if options.cancellation.is_cancelled() {
            endpoint.cancel_all();
            drain_cancelled(endpoint, pipe)?;
            return Err(NusbTransportError::Cancelled { pipe });
        }
        let remaining = options.timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            endpoint.cancel_all();
            drain_cancelled(endpoint, pipe)?;
            return Err(NusbTransportError::Timeout {
                pipe,
                timeout: options.timeout,
            });
        }
        if let Some(completion) = endpoint.wait(CANCELLATION_POLL.min(remaining)) {
            return Ok(completion);
        }
    }
}

fn drain_cancelled(
    endpoint: &mut impl PendingEndpoint,
    pipe: u8,
) -> Result<(), NusbTransportError> {
    let started = Instant::now();
    while started.elapsed() < CANCELLATION_DRAIN_LIMIT {
        if endpoint.wait(CANCELLATION_POLL).is_some() {
            return Ok(());
        }
    }
    Err(NusbTransportError::CancellationRecovery { pipe })
}

fn validate_completion(
    completion: Completion,
    pipe: u8,
    expected: usize,
) -> Result<Buffer, NusbTransportError> {
    completion
        .status
        .map_err(|source| NusbTransportError::Transfer { pipe, source })?;
    if completion.actual_len != expected {
        return Err(NusbTransportError::ShortTransfer {
            pipe,
            expected,
            actual: completion.actual_len,
        });
    }
    Ok(completion.buffer)
}

#[derive(Debug, Error)]
pub enum NusbTransportError {
    #[error(transparent)]
    Discovery(#[from] UsbDiscoveryError),
    #[error("failed to open SP10/SP20 USB device: {0}")]
    Open(#[source] nusb::Error),
    #[error("active USB configuration is unavailable: {0}")]
    ActiveConfiguration(String),
    #[error("no interface/alternate setting contains all six required Pipe addresses")]
    RequiredPipesNotFound,
    #[error("failed to claim USB interface {interface}: {source}")]
    ClaimInterface {
        interface: u8,
        #[source]
        source: nusb::Error,
    },
    #[error("failed to select alternate setting {alternate} on interface {interface}: {source}")]
    SetAlternateSetting {
        interface: u8,
        alternate: u8,
        #[source]
        source: nusb::Error,
    },
    #[error("endpoint {address:#04x} uses unsupported transfer type {transfer_type:?}")]
    UnsupportedEndpointType {
        address: u8,
        transfer_type: TransferType,
    },
    #[error("failed to open endpoint {address:#04x}: {source}")]
    OpenEndpoint {
        address: u8,
        #[source]
        source: nusb::Error,
    },
    #[error("required endpoint {address:#04x} was missing from the selected interface")]
    MissingEndpoint { address: u8 },
    #[error("endpoint on Pipe {pipe:#04x} reported a zero maximum packet size")]
    InvalidPacketSize { pipe: u8 },
    #[error("zero-length transfer requested on Pipe {pipe:#04x}")]
    ZeroLength { pipe: u8 },
    #[error("transfer on Pipe {pipe:#04x} was cancelled")]
    Cancelled { pipe: u8 },
    #[error("transfer on Pipe {pipe:#04x} timed out after {timeout:?}")]
    Timeout { pipe: u8, timeout: Duration },
    #[error("transfer on Pipe {pipe:#04x} failed: {source}")]
    Transfer {
        pipe: u8,
        #[source]
        source: TransferError,
    },
    #[error("short transfer on Pipe {pipe:#04x}: expected {expected}, got {actual}")]
    ShortTransfer {
        pipe: u8,
        expected: usize,
        actual: usize,
    },
    #[error("cancelled transfer on Pipe {pipe:#04x} did not drain within recovery limit")]
    CancellationRecovery { pipe: u8 },
    #[error("USB session is unusable after an incomplete or failed transfer")]
    SessionUnusable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_pipe_order_matches_endpoint_slots() {
        assert_eq!(
            REQUIRED_PIPE_ADDRESSES,
            [0x02, 0x03, 0x82, 0x83, 0x84, 0x85]
        );
    }
}
