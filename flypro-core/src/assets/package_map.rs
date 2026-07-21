//! Parser for the original application's package-to-adapter map.

use std::{collections::BTreeMap, sync::OnceLock};

use thiserror::Error;

static DEFAULT_PACKAGE_MAP: OnceLock<Result<PackageMap, PackageMapError>> = OnceLock::new();

/// Original `PkgID20.ini` text bundled with the crate.
pub const DEFAULT_PACKAGE_MAP_TEXT: &str = include_str!("../../assets/package/PkgID20.ini");

/// One package route used to populate the runtime profile and `SPRJ` image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRecord {
    key: u8,
    package_type: u16,
    package_name: String,
    adapter_name: String,
}

impl PackageRecord {
    #[must_use]
    pub const fn key(&self) -> u8 {
        self.key
    }

    #[must_use]
    pub const fn package_type(&self) -> u16 {
        self.package_type
    }

    #[must_use]
    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    #[must_use]
    pub fn adapter_name(&self) -> &str {
        &self.adapter_name
    }
}

/// Valid package routes indexed by the decimal package key stored in `SP20.dev`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMap {
    records: BTreeMap<u8, PackageRecord>,
}

impl PackageMap {
    /// Parses the simple `PkgID20.ini` format used by the original host.
    ///
    /// # Errors
    ///
    /// Returns [`PackageMapError`] for malformed or duplicate populated rows.
    pub fn parse(text: &str) -> Result<Self, PackageMapError> {
        let mut records = BTreeMap::new();
        for (index, raw_line) in text.lines().enumerate() {
            let line_number = index + 1;
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('[') {
                continue;
            }
            let (raw_key, raw_value) = line
                .split_once('=')
                .ok_or(PackageMapError::InvalidLine { line: line_number })?;
            let key = raw_key
                .trim()
                .parse::<u8>()
                .map_err(|_| PackageMapError::InvalidKey { line: line_number })?;
            let mut fields = raw_value.split(',').map(str::trim);
            let raw_type = fields.next().unwrap_or_default();
            let package_name = fields.next().unwrap_or_default();
            let adapter_name = fields.next().unwrap_or_default();
            if raw_type.is_empty() {
                continue;
            }
            let package_type = u16::from_str_radix(raw_type, 16)
                .map_err(|_| PackageMapError::InvalidType { line: line_number })?;
            let record = PackageRecord {
                key,
                package_type,
                package_name: package_name.to_owned(),
                adapter_name: adapter_name.to_owned(),
            };
            if records.insert(key, record).is_some() {
                return Err(PackageMapError::DuplicateKey { key });
            }
        }
        Ok(Self { records })
    }

    #[must_use]
    pub fn get(&self, key: u8) -> Option<&PackageRecord> {
        self.records.get(&key)
    }

    pub fn records(&self) -> impl Iterator<Item = &PackageRecord> {
        self.records.values()
    }
}

/// Returns the package map extracted from the original installer.
///
/// # Errors
///
/// Returns [`PackageMapError`] if the bundled map is invalid.
pub fn default_package_map() -> Result<&'static PackageMap, PackageMapError> {
    DEFAULT_PACKAGE_MAP
        .get_or_init(|| PackageMap::parse(DEFAULT_PACKAGE_MAP_TEXT))
        .as_ref()
        .map_err(Clone::clone)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PackageMapError {
    #[error("invalid package-map row at line {line}")]
    InvalidLine { line: usize },
    #[error("invalid decimal package key at line {line}")]
    InvalidKey { line: usize },
    #[error("invalid hexadecimal package type at line {line}")]
    InvalidType { line: usize },
    #[error("duplicate package key {key}")]
    DuplicateKey { key: u8 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::defaults::default_device_database;

    #[test]
    fn parses_bundled_package_routes() {
        let map = default_package_map().expect("bundled package map");
        let soic = map.get(32).expect("SOIC8 route");
        assert_eq!(soic.package_type(), 0x1008);
        assert_eq!(soic.package_name(), "SOIC8-150");
        assert_eq!(soic.adapter_name(), "SF-SOP8-150A");

        let isp = map.get(8).expect("SPI ISP route");
        assert_eq!(isp.package_type(), 0x0100);
        assert_eq!(isp.adapter_name(), "ISP-M25");
    }

    #[test]
    fn covers_every_package_key_referenced_by_the_device_database() {
        let map = default_package_map().expect("bundled package map");
        let database = default_device_database().expect("bundled device database");

        for device in database.devices() {
            for key in device.package_keys() {
                assert!(
                    map.get(key).is_some(),
                    "{} references missing package key {key}",
                    device.name()
                );
            }
        }
    }
}
