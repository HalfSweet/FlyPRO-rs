//! Default release assets bundled into `flypro-core`.

use std::sync::OnceLock;

use super::device_db::{DeviceDatabase, DeviceDatabaseError};

static DEFAULT_DEVICE_DATABASE: OnceLock<Result<DeviceDatabase, DeviceDatabaseError>> =
    OnceLock::new();

/// Complete `SP20.dev` bytes bundled with the crate.
pub const DEFAULT_DEVICE_DATABASE_BYTES: &[u8] = include_bytes!("../../assets/device/SP20.dev");

/// Returns the parsed default device database.
///
/// Parsing and validation run at most once per process.
///
/// # Errors
///
/// Returns [`DeviceDatabaseError`] if the bundled database is invalid.
pub fn default_device_database() -> Result<&'static DeviceDatabase, DeviceDatabaseError> {
    DEFAULT_DEVICE_DATABASE
        .get_or_init(|| {
            DeviceDatabase::parse_for_file_name(DEFAULT_DEVICE_DATABASE_BYTES, "SP20.dev")
        })
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_bundled_database_once() {
        let first = default_device_database().expect("default device database is valid");
        let second = default_device_database().expect("cached device database remains valid");

        assert!(std::ptr::eq(first, second));
        assert_eq!(first.devices().len(), 4_576);
        assert_eq!(first.internal_file_name(), "SP20.dev");
    }
}
