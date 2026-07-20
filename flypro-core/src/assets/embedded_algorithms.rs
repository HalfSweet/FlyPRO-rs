//! Algorithm assets bundled into `flypro-core` at compile time.

use super::algorithm::{Algorithm, AlgorithmError};

/// A complete `.alg` file embedded in the crate's read-only data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedAlgorithm {
    stem: &'static str,
    file_name: &'static str,
    bytes: &'static [u8],
}

impl EmbeddedAlgorithm {
    /// Returns the file stem used by `SP20.dev` algorithm references.
    #[must_use]
    pub const fn stem(self) -> &'static str {
        self.stem
    }

    /// Returns the original lower-case file name, including `.alg`.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        self.file_name
    }

    /// Returns the complete original `.alg` file bytes.
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        self.bytes
    }

    /// Parses and validates the embedded file against its stem.
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmError`] if the bundled file fails its format,
    /// integrity, timestamp, or name checks.
    pub fn parse(self) -> Result<Algorithm, AlgorithmError> {
        Algorithm::parse_for_stem(self.bytes, self.stem)
    }
}

macro_rules! embed_algorithms {
    ($($stem:literal),+ $(,)?) => {
        const EMBEDDED_ALGORITHMS: &[EmbeddedAlgorithm] = &[
            $(
                EmbeddedAlgorithm {
                    stem: $stem,
                    file_name: concat!($stem, ".alg"),
                    bytes: include_bytes!(concat!("../../assets/alg/", $stem, ".alg")),
                },
            )+
        ];
    };
}

embed_algorithms!(
    "at25df128",
    "at25f1024",
    "at25pe",
    "at25sf321",
    "at25sl321",
    "at26df321",
    "at45dbxxb",
    "at45dbxxd",
    "at45dbxxe",
    "bl25wq40a",
    "br90xx",
    "by25q256fs",
    "ch9904",
    "ds25m4c",
    "en25q128",
    "en25q256",
    "en25qe32",
    "en25qx128",
    "en25qx256",
    "fd25q128",
    "fm24cxxd",
    "fm25ee",
    "fm25q128",
    "gd24cxx",
    "gd25b512mf",
    "gd25lb256e",
    "gd25lb256f",
    "gd25le128e",
    "gd25le255e",
    "gd25lx128j",
    "gd25q128",
    "gd25q256",
    "gd25r512mf",
    "gm25q128",
    "gt25q32",
    "gt25q40d",
    "hwt",
    "im25rwq",
    "is25p128",
    "is25p256",
    "m24all",
    "m24c1026",
    "m24c21",
    "m25id",
    "m45pexx",
    "mb85rs",
    "mw93",
    "mw93s",
    "mx25l128",
    "mx25l256",
    "n25q128",
    "n25q256",
    "n25q512",
    "p24cxx",
    "p25q128",
    "p25q21",
    "p25r40",
    "pn25f128",
    "rt25q128",
    "s25fl128l",
    "s25fl128s",
    "s25fl256l",
    "s25fl256s",
    "s25fs128s",
    "s25fs256s",
    "s70fl256",
    "seep25",
    "spd34",
    "sst25f080",
    "sst25f080b",
    "sst26f032",
    "sst26f064b",
    "td24cxx",
    "th25q40",
    "th25q40fe",
    "uc25wd20",
    "w25m512jv",
    "w25q01jv",
    "w25q128",
    "w25q128b",
    "w25q12rv",
    "w25q256",
    "w25q51rv",
    "w25x21",
    "wb24cxx",
    "x5043",
    "xm25qu40b",
    "xt25f128b",
    "xt25f128f",
    "xt25f256b",
    "xt25f32f",
    "xt55q1gf",
);

/// Number of algorithms included in the compatibility baseline.
pub const EMBEDDED_ALGORITHM_COUNT: usize = EMBEDDED_ALGORITHMS.len();

/// Returns every bundled algorithm in stable, ASCII file-name order.
#[must_use]
pub const fn embedded_algorithms() -> &'static [EmbeddedAlgorithm] {
    EMBEDDED_ALGORITHMS
}

/// Finds a bundled algorithm by file stem using ASCII case-insensitive
/// matching. The `.alg` suffix is not accepted.
#[must_use]
pub fn embedded_algorithm(stem: &str) -> Option<EmbeddedAlgorithm> {
    EMBEDDED_ALGORITHMS
        .iter()
        .copied()
        .find(|algorithm| algorithm.stem.eq_ignore_ascii_case(stem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_and_validates_every_baseline_algorithm() {
        assert_eq!(embedded_algorithms().len(), EMBEDDED_ALGORITHM_COUNT);

        for algorithm in embedded_algorithms() {
            let parsed = algorithm.parse().expect("embedded algorithm is valid");
            assert!(parsed.name().eq_ignore_ascii_case(algorithm.stem()));
            assert_eq!(
                algorithm.file_name().strip_suffix(".alg"),
                Some(algorithm.stem())
            );
        }
    }

    #[test]
    fn registry_is_strictly_sorted_and_unique() {
        assert!(embedded_algorithms().windows(2).all(|pair| {
            pair[0]
                .stem()
                .as_bytes()
                .cmp(pair[1].stem().as_bytes())
                .is_lt()
        }));
    }

    #[test]
    fn finds_algorithm_for_device_database_stem() {
        let algorithm = embedded_algorithm("W25Q128").expect("W25Q128 is bundled");

        assert_eq!(algorithm.stem(), "w25q128");
        assert_eq!(algorithm.file_name(), "w25q128.alg");
        assert!(algorithm.bytes().starts_with(b"ALG\0"));
        assert!(embedded_algorithm("w25q128.alg").is_none());
        assert!(embedded_algorithm("missing").is_none());
    }
}
