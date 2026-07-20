//! Deterministic construction of the 2048-byte `SPRJ` parameter image.
//!
//! The layout follows `F-PROTO-022` and `F-PROTO-023`. Runtime profile fields
//! whose business names remain unknown are intentionally identified by their
//! source offsets.

use std::ops::Range;

use crc32fast::hash;
use thiserror::Error;

use crate::{
    assets::{algorithm::Algorithm, device_db::DEVICE_RECORD_BYTES},
    protocol::{DEVICE_PARAMETER_BYTES, DeviceParameterImage},
};

pub const RUNTIME_PROFILE_BYTES: usize = 0x0a28;
pub const DERIVED_RANGE_BYTES: usize = 0x18;

/// Pre-encoded ANSI bytes for runtime-profile wide-string fields.
///
/// The original application uses the active Windows ANSI conversion. Keeping
/// conversion outside the byte-layout builder makes the selected code page an
/// explicit input and keeps output deterministic on all host platforms.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileTextFields {
    values: [Vec<u8>; 8],
}

impl ProfileTextFields {
    pub fn set(&mut self, field: ProfileTextField, encoded_ansi: impl Into<Vec<u8>>) {
        self.values[field as usize] = encoded_ansi.into();
    }

    #[must_use]
    pub fn get(&self, field: ProfileTextField) -> &[u8] {
        &self.values[field as usize]
    }
}

/// Source offsets of the eight profile strings copied into `SPRJ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum ProfileTextField {
    Source0050 = 0,
    Source000e = 1,
    Source0092 = 2,
    Source0526 = 3,
    Source00e0 = 4,
    Source0228 = 5,
    Source0370 = 6,
    Source0802 = 7,
}

/// Inputs retained by the original host around its `0x0041AC30` builder.
pub struct DeviceParameterInputs<'a> {
    pub runtime_profile: &'a [u8; RUNTIME_PROFILE_BYTES],
    pub profile_text: &'a ProfileTextFields,
    pub device_record: &'a [u8; DEVICE_RECORD_BYTES],
    pub algorithm: &'a Algorithm,
    pub project_data: &'a [u8],
    pub data_range: Range<usize>,
    pub local_time_bcd: [u8; 7],
    pub derived_ranges: [u8; DERIVED_RANGE_BYTES],
}

/// Builds the exact-size image after validating caller-controlled boundaries.
///
/// # Errors
///
/// Returns [`DeviceParameterBuildError`] when BCD time, project data range, or
/// an integer field cannot be represented by the confirmed layout.
// Keeping the assignments in source-offset order makes this byte-for-byte
// layout auditable against the static field table.
#[allow(clippy::too_many_lines)]
pub fn build_device_parameters(
    inputs: &DeviceParameterInputs<'_>,
) -> Result<DeviceParameterImage, DeviceParameterBuildError> {
    validate_bcd(inputs.local_time_bcd)?;
    if inputs.data_range.start > inputs.data_range.end
        || inputs.data_range.end > inputs.project_data.len()
    {
        return Err(DeviceParameterBuildError::DataRange {
            start: inputs.data_range.start,
            end: inputs.data_range.end,
            data_length: inputs.project_data.len(),
        });
    }

    let profile = inputs.runtime_profile;
    let mut image = [0_u8; DEVICE_PARAMETER_BYTES];
    image[0x000..0x004].copy_from_slice(b"SPRJ");
    write_u32(&mut image, 0x004, 0x0161_0001);
    write_u16(&mut image, 0x008, 0x0100);
    write_u16(
        &mut image,
        0x00a,
        if profile[0x7f0] == 0 { 0x0100 } else { 0x0132 },
    );
    let flags = if read_u32(profile, 0x124) > 0x0400_0000 || profile[0x72e] & 0x20 != 0 {
        0x0100
    } else {
        0
    };
    write_u16(&mut image, 0x00c, flags);
    image[0x010..0x017].copy_from_slice(&inputs.local_time_bcd);

    copy_text(
        &mut image,
        0x020,
        0x20,
        inputs.profile_text.get(ProfileTextField::Source0050),
    );
    copy_text(
        &mut image,
        0x040,
        0x20,
        inputs.profile_text.get(ProfileTextField::Source000e),
    );
    copy_text(
        &mut image,
        0x060,
        0x20,
        inputs.profile_text.get(ProfileTextField::Source0092),
    );
    copy_from(&mut image, 0x080, profile, 0x0d4, 4);
    copy_from(&mut image, 0x084, profile, 0x466, 2);
    image[0x086] = profile[0x464];
    image[0x090..0x120].copy_from_slice(inputs.device_record);
    copy_path_text(
        &mut image,
        0x190,
        0x104,
        inputs.profile_text.get(ProfileTextField::Source0526),
    );
    image[0x29f] = profile[0x72e];
    copy_text(
        &mut image,
        0x2a0,
        0x20,
        inputs.profile_text.get(ProfileTextField::Source00e0),
    );
    copy_text(
        &mut image,
        0x2c0,
        0x20,
        inputs.profile_text.get(ProfileTextField::Source0228),
    );
    copy_text(
        &mut image,
        0x2e0,
        0x40,
        inputs.profile_text.get(ProfileTextField::Source0370),
    );
    image[0x320] = profile[0x73c];
    image[0x321] = profile[0x73d];
    image[0x322] = profile[0x504];
    copy_from(&mut image, 0x324, profile, 0x7c4, 4);
    copy_from(&mut image, 0x328, profile, 0x7c2, 2);
    copy_from(&mut image, 0x330, profile, 0x7f0, 4);
    copy_from(&mut image, 0x334, profile, 0x7f4, 4);
    copy_from(&mut image, 0x338, profile, 0x7f8, 4);
    copy_from(&mut image, 0x33c, profile, 0x7fc, 4);
    image[0x340] = profile[0x800];
    copy_text(
        &mut image,
        0x348,
        0x104,
        inputs.profile_text.get(ProfileTextField::Source0802),
    );
    copy_from(&mut image, 0x44c, profile, 0xa0c, 4);
    copy_from(&mut image, 0x450, profile, 0x73e, 0x40);
    copy_from(&mut image, 0x490, profile, 0x77e, 0x40);
    copy_from(&mut image, 0x4d0, profile, 0x7be, 4);
    image[0x4e0] = profile[0x505];

    let mut operation_codes = [0; 16];
    operation_codes.copy_from_slice(&profile[0x516..0x526]);
    write_u32(&mut image, 0x4e4, fold_capabilities(operation_codes));
    image[0x4e8..0x4f8].copy_from_slice(&operation_codes);
    copy_from(&mut image, 0x4f8, profile, 0x506, 0x10);
    copy_from(&mut image, 0x508, profile, 0x7e8, 4);
    image[0x50c] = profile[0x7ec];
    copy_from(&mut image, 0x520, profile, 0x7c8, 0x20);
    copy_text(&mut image, 0x540, 0x10, inputs.algorithm.name().as_bytes());
    image[0x550..0x558].copy_from_slice(&inputs.algorithm.timestamp());
    write_u32(
        &mut image,
        0x558,
        u32::try_from(inputs.algorithm.payload().len())
            .map_err(|_| DeviceParameterBuildError::IntegerOverflow)?,
    );
    write_u32(&mut image, 0x55c, inputs.algorithm.payload_crc32());
    copy_from(&mut image, 0x560, profile, 0x730, 4);
    copy_from(&mut image, 0x564, profile, 0x734, 4);
    copy_from(&mut image, 0x568, profile, 0x738, 4);

    let range_start = u32::try_from(inputs.data_range.start)
        .map_err(|_| DeviceParameterBuildError::IntegerOverflow)?;
    let range_length = u32::try_from(inputs.data_range.len())
        .map_err(|_| DeviceParameterBuildError::IntegerOverflow)?;
    write_u32(&mut image, 0x56c, range_start);
    write_u32(&mut image, 0x570, range_length);
    write_u32(
        &mut image,
        0x574,
        hash(&inputs.project_data[inputs.data_range.clone()]),
    );
    image[0x578..0x590].copy_from_slice(&inputs.derived_ranges);

    let final_crc = hash(&image[..0x7fc]);
    write_u32(&mut image, 0x7fc, final_crc);
    Ok(DeviceParameterImage::from_bytes(image))
}

/// Applies the confirmed operation-code-to-capability mapping.
#[must_use]
pub fn fold_capabilities(operation_codes: [u8; 16]) -> u32 {
    operation_codes.into_iter().fold(0_u32, |bits, code| {
        bits | match code {
            1 => 0x001,
            2 => 0x002,
            3 => 0x004,
            4 => 0x008,
            5 => 0x010,
            6 => 0x020,
            7 => 0x800,
            9 => 0x808,
            10 => 0x040,
            _ => 0,
        }
    })
}

fn copy_text(image: &mut [u8], destination: usize, capacity: usize, value: &[u8]) {
    let length = value.len().min(capacity.saturating_sub(1));
    image[destination..destination + length].copy_from_slice(&value[..length]);
}

fn copy_path_text(image: &mut [u8], destination: usize, capacity: usize, value: &[u8]) {
    let maximum = capacity.saturating_sub(1);
    let selected = if value.len() <= maximum {
        value
    } else {
        value
            .iter()
            .rposition(|byte| matches!(byte, b'/' | b'\\'))
            .map_or(&value[value.len() - maximum..], |separator| {
                &value[separator.saturating_add(1)..]
            })
    };
    copy_text(image, destination, capacity, selected);
}

fn copy_from(
    destination: &mut [u8],
    destination_offset: usize,
    source: &[u8],
    source_offset: usize,
    length: usize,
) {
    destination[destination_offset..destination_offset + length]
        .copy_from_slice(&source[source_offset..source_offset + length]);
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("four-byte profile field"),
    )
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn validate_bcd(value: [u8; 7]) -> Result<(), DeviceParameterBuildError> {
    if value.iter().any(|byte| byte >> 4 > 9 || byte & 0x0f > 9) {
        return Err(DeviceParameterBuildError::InvalidBcdTime { value });
    }
    Ok(())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DeviceParameterBuildError {
    #[error("invalid seven-byte BCD local time {value:02x?}")]
    InvalidBcdTime { value: [u8; 7] },
    #[error("project data range {start}..{end} exceeds data length {data_length}")]
    DataRange {
        start: usize,
        end: usize,
        data_length: usize,
    },
    #[error("SPRJ field does not fit its confirmed 32-bit width")]
    IntegerOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::embedded_algorithms::embedded_algorithm;

    fn read_image_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("field"))
    }

    #[test]
    fn builds_deterministic_sprj_image() {
        let algorithm = embedded_algorithm("w25q128")
            .expect("embedded algorithm")
            .parse()
            .expect("valid algorithm");
        let mut profile = [0_u8; RUNTIME_PROFILE_BYTES];
        profile[0x124..0x128].copy_from_slice(&0x0400_0001_u32.to_le_bytes());
        profile[0x516..0x51b].copy_from_slice(&[1, 2, 3, 7, 9]);
        profile[0x73e..0x77e].fill(0xa5);
        profile[0x77e..0x7be].fill(0x5a);
        let device_record = [0x3c_u8; DEVICE_RECORD_BYTES];
        let project_data: Vec<_> = (0_u16..4096).map(|value| value.to_le_bytes()[0]).collect();
        let mut text = ProfileTextFields::default();
        text.set(ProfileTextField::Source0050, b"W25Q128BV".to_vec());
        text.set(ProfileTextField::Source000e, b"Winbond".to_vec());
        let inputs = DeviceParameterInputs {
            runtime_profile: &profile,
            profile_text: &text,
            device_record: &device_record,
            algorithm: &algorithm,
            project_data: &project_data,
            data_range: 0x800..0x1000,
            local_time_bcd: [0x20, 0x26, 0x07, 0x20, 0x18, 0x30, 0x45],
            derived_ranges: [0x11; DERIVED_RANGE_BYTES],
        };

        let image = build_device_parameters(&inputs).expect("valid inputs");
        let bytes = image.as_bytes();
        assert_eq!(&bytes[..4], b"SPRJ");
        assert_eq!(read_image_u32(bytes, 0x004), 0x0161_0001);
        assert_eq!(&bytes[0x010..0x017], &inputs.local_time_bcd);
        assert_eq!(&bytes[0x020..0x029], b"W25Q128BV");
        assert_eq!(&bytes[0x090..0x120], &device_record);
        assert_eq!(&bytes[0x450..0x490], &[0xa5; 64]);
        assert_eq!(&bytes[0x490..0x4d0], &[0x5a; 64]);
        assert_eq!(read_image_u32(bytes, 0x4e4), 0x080f);
        assert_eq!(&bytes[0x540..0x547], b"W25Q128");
        assert_eq!(read_image_u32(bytes, 0x558), 0x4000);
        assert_eq!(read_image_u32(bytes, 0x56c), 0x800);
        assert_eq!(read_image_u32(bytes, 0x570), 0x800);
        assert_eq!(
            read_image_u32(bytes, 0x574),
            hash(&project_data[0x800..0x1000])
        );
        assert_eq!(read_image_u32(bytes, 0x7fc), hash(&bytes[..0x7fc]));
        assert_eq!(read_image_u32(bytes, 0x7fc), 0xef84_ed2d);
    }

    #[test]
    fn folds_every_confirmed_operation_code() {
        assert_eq!(
            fold_capabilities([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0, 0]),
            0x087f
        );
    }
}
