//! `FlyPro` asset and protocol support for SP10/SP20 programmers.
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
