//! Platform-independent staged transport contract.
//!
//! The pipe addresses and observed roles follow `F-USB-010` through
//! `F-USB-019`. Their USB transfer types and descriptor packet sizes remain
//! unknown and are not represented here.

use std::time::Duration;

pub const COMMAND_TIMEOUT: Duration = Duration::from_millis(100);
pub const PAYLOAD_TIMEOUT: Duration = Duration::from_millis(500);
pub const ALGORITHM_COMPLETION_TIMEOUT: Duration = Duration::from_millis(600);
pub const ALGORITHM_VERIFY_TIMEOUT: Duration = Duration::from_millis(1_000);
pub const POST_DOWNLOAD_DELAY: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OutPipe {
    Command = 0x02,
    Payload = 0x03,
}

impl OutPipe {
    #[must_use]
    pub const fn address(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InPipe {
    Completion = 0x82,
    Response = 0x83,
    AuxiliaryResult = 0x84,
    Specialized = 0x85,
}

impl InPipe {
    #[must_use]
    pub const fn address(self) -> u8 {
        self as u8
    }
}

/// Cancellation source consulted by a transport while an overlapped transfer
/// is pending.
pub trait Cancellation {
    #[must_use]
    fn is_cancelled(&self) -> bool;
}

/// Cancellation source for callers that do not need cancellation.
#[derive(Debug, Default, Clone, Copy)]
pub struct NeverCancelled;

impl Cancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Options attached to one indivisible transport stage.
#[derive(Clone, Copy)]
pub struct TransferOptions<'a> {
    pub timeout: Duration,
    pub cancellation: &'a dyn Cancellation,
}

/// Exact-length I/O boundary implemented by a platform backend.
///
/// Implementations must treat a short read or write as an error, abort the
/// corresponding pipe after timeout/cancellation, and prevent late data from
/// leaking into the next transaction (`F-PROTO-008`, `T-USB-002` through
/// `T-USB-006`).
pub trait Transport {
    type Error;

    /// Writes all bytes to a confirmed OUT pipe.
    ///
    /// # Errors
    ///
    /// Returns the backend error for submission, timeout, cancellation,
    /// short transfer, device removal, or recovery failure.
    fn write_exact(
        &mut self,
        pipe: OutPipe,
        bytes: &[u8],
        options: TransferOptions<'_>,
    ) -> Result<(), Self::Error>;

    /// Fills the entire buffer from a confirmed IN pipe.
    ///
    /// # Errors
    ///
    /// Returns the backend error for submission, timeout, cancellation,
    /// short transfer, device removal, or recovery failure.
    fn read_exact(
        &mut self,
        pipe: InPipe,
        bytes: &mut [u8],
        options: TransferOptions<'_>,
    ) -> Result<(), Self::Error>;
}

/// Injectable delay boundary used by the confirmed 100 ms post-download wait.
pub trait Delay {
    fn delay(&mut self, duration: Duration);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadDelay;

impl Delay for ThreadDelay {
    fn delay(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_addresses_preserve_usb_direction_bit() {
        assert_eq!(OutPipe::Command.address(), 0x02);
        assert_eq!(OutPipe::Payload.address(), 0x03);
        assert_eq!(InPipe::Completion.address(), 0x82);
        assert_eq!(InPipe::Response.address(), 0x83);
        assert_eq!(InPipe::AuxiliaryResult.address(), 0x84);
        assert_eq!(InPipe::Specialized.address(), 0x85);
    }
}
