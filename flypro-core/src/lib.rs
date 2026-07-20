//! Evidence-driven `FlyPRO` asset, protocol, transport, and session abstractions.
//!
//! The crate only assigns semantic names to behavior supported by the current
//! fact baseline. Unknown fields and commands remain opaque.

pub mod assets;
pub mod operations;
pub mod parameters;
pub mod protocol;
pub mod session;
pub mod transport;
pub mod usb;
pub mod usb_transport;
