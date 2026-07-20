//! Configuration assets bundled into `flypro-core` at compile time.

use super::configuration::{Configuration, ConfigurationError};

/// A complete `.cfg` file embedded in the crate's read-only data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedConfiguration {
    stem: &'static str,
    file_name: &'static str,
    bytes: &'static [u8],
}

impl EmbeddedConfiguration {
    /// Returns the file stem used by `SP20.dev` configuration references.
    #[must_use]
    pub const fn stem(self) -> &'static str {
        self.stem
    }

    /// Returns the original file name, including `.cfg`.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        self.file_name
    }

    /// Returns the complete original `.cfg` file bytes.
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        self.bytes
    }

    /// Parses and validates the embedded file against its stem.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] if the bundled file is invalid.
    pub fn parse(self) -> Result<Configuration, ConfigurationError> {
        Configuration::parse_for_stem(self.bytes, self.stem)
    }
}

include!(concat!(env!("OUT_DIR"), "/embedded_configurations.rs"));

/// Number of configurations included in the default release bundle.
pub const EMBEDDED_CONFIGURATION_COUNT: usize = EMBEDDED_CONFIGURATIONS.len();

/// Returns every bundled configuration in stable, ASCII case-insensitive
/// file-name order.
#[must_use]
pub const fn embedded_configurations() -> &'static [EmbeddedConfiguration] {
    EMBEDDED_CONFIGURATIONS
}

/// Finds a bundled configuration by file stem using ASCII case-insensitive
/// matching. The `.cfg` suffix is not accepted.
#[must_use]
pub fn embedded_configuration(stem: &str) -> Option<EmbeddedConfiguration> {
    EMBEDDED_CONFIGURATIONS
        .iter()
        .copied()
        .find(|configuration| configuration.stem.eq_ignore_ascii_case(stem))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::super::defaults::default_device_database;
    use super::*;

    #[test]
    fn includes_and_validates_every_configuration() {
        assert_eq!(embedded_configurations().len(), 389);
        assert_eq!(
            embedded_configurations().len(),
            EMBEDDED_CONFIGURATION_COUNT
        );

        for configuration in embedded_configurations() {
            let parsed = configuration
                .parse()
                .expect("embedded configuration is valid");
            assert!(parsed.name().eq_ignore_ascii_case(configuration.stem()));
        }
    }

    #[test]
    fn registry_is_sorted_and_unique() {
        let mut stems = HashSet::new();
        for configuration in embedded_configurations() {
            assert!(stems.insert(configuration.stem().to_ascii_lowercase()));
        }
        assert!(embedded_configurations().windows(2).all(|pair| {
            pair[0]
                .stem()
                .to_ascii_lowercase()
                .cmp(&pair[1].stem().to_ascii_lowercase())
                .is_lt()
        }));
    }

    #[test]
    fn covers_every_default_database_configuration_reference() {
        let database = default_device_database().expect("default database is valid");
        for device in database.devices() {
            if let Some(stem) = device.configuration_stem() {
                assert!(
                    embedded_configuration(stem).is_some(),
                    "missing configuration {stem} for {}",
                    device.name()
                );
            }
        }
    }

    #[test]
    fn finds_configuration_case_insensitively() {
        let configuration = embedded_configuration("w25q128s").expect("W25Q128S is bundled");

        assert_eq!(configuration.stem(), "W25Q128S");
        assert_eq!(configuration.file_name(), "W25Q128S.cfg");
        assert!(configuration.bytes().starts_with(b"CFG\0"));
        assert!(embedded_configuration("W25Q128S.cfg").is_none());
    }
}
