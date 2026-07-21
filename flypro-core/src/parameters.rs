//! Deterministic construction of the 2048-byte `SPRJ` parameter image.
//!
//! The layout follows `F-PROTO-022` and `F-PROTO-023`. Runtime profile fields
//! whose business names remain unknown are intentionally identified by their
//! source offsets.

use std::ops::Range;

use crc32fast::hash;
use encoding_rs::GBK;
use thiserror::Error;

use crate::{
    assets::{
        algorithm::Algorithm,
        configuration::Configuration,
        device_db::{DEVICE_RECORD_BYTES, DeviceRecord},
        package_map::PackageRecord,
    },
    protocol::{DEVICE_PARAMETER_BYTES, DeviceParameterImage},
};

pub const RUNTIME_PROFILE_BYTES: usize = 0x0a28;
pub const DERIVED_RANGE_BYTES: usize = 0x18;
pub const PROJECT_ALIGNMENT_BYTES: usize = 0x800;

/// User-facing operation represented by the original profile's scheduled
/// operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterOperation {
    /// Original new-project defaults: program followed by verify.
    Prepare,
    Program,
    Read,
    Verify,
    BlankCheck,
    ConfigurationWrite,
    ConfigurationRead,
    ChipErase,
    AutomaticErase,
    ConfigurationVerify,
    Progress,
}

/// High-level inputs from which all confirmed runtime-profile defaults can be
/// derived without an external `SPRJ` file.
pub struct AutomaticParameterInputs<'a> {
    pub device: &'a DeviceRecord,
    pub vendor_name: &'a str,
    pub algorithm: &'a Algorithm,
    pub configuration: Option<&'a Configuration>,
    pub package: &'a PackageRecord,
    pub operation: ParameterOperation,
    pub region: u32,
    pub project_data: &'a [u8],
    pub local_time_bcd: [u8; 7],
}

/// Constructs an `SPRJ` image from a selected device and the operation to run.
///
/// The device record supplies capacity, addressing, capability, algorithm, and
/// configuration references. Configuration defaults and algorithm region names
/// are folded into the same fields populated by the original new-project path.
///
/// # Errors
///
/// Returns [`DeviceParameterBuildError`] if the selected assets do not match,
/// the region is unavailable, the input is too large, text is not representable
/// in the original GBK-compatible ANSI fields, or the final image cannot be
/// represented by the confirmed layout.
pub fn build_automatic_device_parameters(
    inputs: &AutomaticParameterInputs<'_>,
) -> Result<DeviceParameterImage, DeviceParameterBuildError> {
    validate_asset_bindings(inputs)?;

    let raw = inputs.device.raw();
    let region_capacity = region_capacity(inputs.device, inputs.region)?;
    let prepared = prepare_project_data(inputs.device, inputs.region, inputs.project_data)?;

    let mut profile = derive_runtime_profile(inputs.device)?;
    profile[0x464] = inputs.package.key();
    write_u16(&mut profile, 0x466, inputs.package.package_type());
    apply_new_project_defaults(&mut profile, inputs.operation, inputs.region);
    if let Some(configuration) = inputs.configuration {
        profile[0x73e..0x77e].copy_from_slice(configuration.default_block_0());
        profile[0x77e..0x7be].copy_from_slice(configuration.default_block_1());
        write_u32(&mut profile, 0x7be, configuration.default_protection_bits());
    }

    let mut text = ProfileTextFields::default();
    text.set(
        ProfileTextField::Source0050,
        encode_profile_text(inputs.vendor_name, "vendor name")?,
    );
    text.set(
        ProfileTextField::Source000e,
        encode_profile_text(inputs.device.name(), "device name")?,
    );
    text.set(
        ProfileTextField::Source0092,
        encode_profile_text(inputs.package.package_name(), "package name")?,
    );
    for (field, (name, label)) in [
        (
            ProfileTextField::Source00e0,
            (&inputs.algorithm.region_names()[0], "algorithm region 0"),
        ),
        (
            ProfileTextField::Source0228,
            (&inputs.algorithm.region_names()[1], "algorithm region 1"),
        ),
        (
            ProfileTextField::Source0370,
            (&inputs.algorithm.region_names()[2], "algorithm region 2"),
        ),
    ] {
        text.set(field, encode_profile_text(name, label)?);
    }

    let mut derived_ranges = [0_u8; DERIVED_RANGE_BYTES];
    write_u32(
        &mut derived_ranges,
        0x00,
        u32::try_from(prepared.range.start)
            .map_err(|_| DeviceParameterBuildError::IntegerOverflow)?,
    );
    write_u32(
        &mut derived_ranges,
        0x04,
        u32::try_from(prepared.range.len())
            .map_err(|_| DeviceParameterBuildError::IntegerOverflow)?,
    );
    let capacity =
        u32::try_from(region_capacity).map_err(|_| DeviceParameterBuildError::IntegerOverflow)?;
    write_u32(&mut derived_ranges, 0x0c, capacity);
    write_u32(&mut derived_ranges, 0x14, capacity);

    build_device_parameters(&DeviceParameterInputs {
        runtime_profile: &profile,
        profile_text: &text,
        device_record: raw,
        algorithm: inputs.algorithm,
        project_data: &prepared.bytes,
        data_range: prepared.range,
        local_time_bcd: inputs.local_time_bcd,
        derived_ranges,
    })
}

fn validate_asset_bindings(
    inputs: &AutomaticParameterInputs<'_>,
) -> Result<(), DeviceParameterBuildError> {
    if !inputs
        .device
        .package_keys()
        .any(|key| key == inputs.package.key())
    {
        return Err(DeviceParameterBuildError::PackageUnavailable {
            key: inputs.package.key(),
            device: inputs.device.name().to_owned(),
        });
    }
    if !inputs
        .algorithm
        .name()
        .eq_ignore_ascii_case(inputs.device.algorithm_stem())
    {
        return Err(DeviceParameterBuildError::AlgorithmMismatch {
            expected: inputs.device.algorithm_stem().to_owned(),
            actual: inputs.algorithm.name().to_owned(),
        });
    }

    if let (Some(expected), Some(configuration)) =
        (inputs.device.configuration_stem(), inputs.configuration)
    {
        if !configuration.name().eq_ignore_ascii_case(expected) {
            return Err(DeviceParameterBuildError::ConfigurationMismatch {
                expected: expected.to_owned(),
                actual: configuration.name().to_owned(),
            });
        }
    }
    if is_configuration_operation(inputs.operation) && inputs.configuration.is_none() {
        return Err(DeviceParameterBuildError::ConfigurationRequired {
            stem: inputs.device.configuration_stem().map(str::to_owned),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn derive_runtime_profile(
    device: &DeviceRecord,
) -> Result<[u8; RUNTIME_PROFILE_BYTES], DeviceParameterBuildError> {
    let raw = device.raw();
    let mut profile = [0_u8; RUNTIME_PROFILE_BYTES];
    write_u32(&mut profile, 0x000, 1);
    copy_from(&mut profile, 0x3f8, raw, 0x44, 4);
    profile[0x0d9] = raw[0x22];
    copy_from(&mut profile, 0x44c, raw, 0x28, 2);
    copy_from(&mut profile, 0x44e, raw, 0x2a, 2);
    write_u32(
        &mut profile,
        0x0d4,
        u32::try_from(device.source_index())
            .map_err(|_| DeviceParameterBuildError::IntegerOverflow)?,
    );
    profile[0x0d8] = raw[0x23];
    copy_from(&mut profile, 0x450, raw, 0x40, 2);
    if read_u16(&profile, 0x450) == 0 {
        write_u16(
            &mut profile,
            0x450,
            match raw[0x23] {
                0x10 => 2,
                0x20 => 4,
                _ => 1,
            },
        );
    }
    copy_from(&mut profile, 0x458, raw, 0x70, 4);
    copy_from(&mut profile, 0x0da, raw, 0x24, 4);
    copy_from(&mut profile, 0x120, raw, 0x34, 4);
    copy_from(&mut profile, 0x124, raw, 0x30, 4);
    copy_from(&mut profile, 0x268, raw, 0x3c, 4);
    copy_from(&mut profile, 0x26c, raw, 0x38, 4);
    profile[0x3f0] = raw[0x2c];
    profile[0x3f1] = raw[0x2f];
    copy_from(&mut profile, 0x452, raw, 0x74, 4);
    copy_from(&mut profile, 0x468, raw, 0x78, 4);
    copy_from(&mut profile, 0x46c, raw, 0x7c, 4);
    copy_from(&mut profile, 0x470, raw, 0x80, 4);
    copy_from(&mut profile, 0x460, raw, 0x48, 4);

    let mut region_count = 0_u8;
    let mut maximum_end = 0_u32;
    for (start_offset, length_offset) in [(0x34, 0x30), (0x3c, 0x38)] {
        let length = read_u32(raw, length_offset);
        if length != 0 {
            region_count = region_count.saturating_add(1);
            maximum_end = maximum_end.max(read_u32(raw, start_offset).wrapping_add(length));
        }
    }
    profile[0x3f2] = region_count;
    write_u32(&mut profile, 0x45c, maximum_end);
    write_u32(
        &mut profile,
        0x448,
        u32::from(device.configuration_stem().is_some()),
    );
    Ok(profile)
}

fn apply_new_project_defaults(
    profile: &mut [u8; RUNTIME_PROFILE_BYTES],
    operation: ParameterOperation,
    region: u32,
) {
    let device_capabilities = read_u32(profile, 0x460);
    let mut flag_index = 0;
    if device_capabilities & 0x800 != 0 {
        profile[0x506] = 0x87;
        flag_index = 1;
    }
    if device_capabilities & 0x08 != 0 && flag_index != 0 {
        profile[0x506 + flag_index] = 0x84;
        flag_index += 1;
    }
    if device_capabilities & 0x01 != 0 {
        profile[0x506 + flag_index] = 0x81;
        flag_index += 1;
    }
    if device_capabilities & 0x04 != 0 {
        profile[0x506 + flag_index] = 0x83;
    }
    profile[0x505] = if device_capabilities & 0x800 != 0 {
        1
    } else {
        2
    };

    match operation {
        ParameterOperation::Prepare => profile[0x516..0x518].copy_from_slice(&[1, 3]),
        _ => profile[0x516] = operation_code(operation),
    }
    let region_mask = 1_u8.checked_shl(region).unwrap_or(0);
    match operation {
        ParameterOperation::Read | ParameterOperation::ConfigurationRead => {
            profile[0x73d] = if is_configuration_operation(operation) {
                0x10
            } else {
                region_mask
            };
        }
        ParameterOperation::ConfigurationWrite | ParameterOperation::ConfigurationVerify => {
            profile[0x73c] = 0x10;
        }
        _ => profile[0x73c] = region_mask,
    }
    if matches!(
        operation,
        ParameterOperation::Prepare | ParameterOperation::Progress
    ) {
        profile[0x73d] = region_mask;
    }

    let profile_word = read_u16(profile, 0x44c);
    write_u16(profile, 0x7c2, profile_word);
    write_u32(profile, 0x7c4, 0x111);
    write_u32(profile, 0x7f0, 0x0104_0000);
    let primary_capacity = read_u32(profile, 0x124);
    write_u32(profile, 0x7f4, primary_capacity.wrapping_sub(0x10));
}

const fn operation_code(operation: ParameterOperation) -> u8 {
    match operation {
        ParameterOperation::Prepare => 0,
        ParameterOperation::Program => 1,
        ParameterOperation::Read => 2,
        ParameterOperation::Verify => 3,
        ParameterOperation::BlankCheck => 4,
        ParameterOperation::ConfigurationWrite => 5,
        ParameterOperation::ConfigurationRead => 6,
        ParameterOperation::ChipErase => 7,
        ParameterOperation::Progress => 8,
        ParameterOperation::AutomaticErase => 9,
        ParameterOperation::ConfigurationVerify => 10,
    }
}

const fn is_configuration_operation(operation: ParameterOperation) -> bool {
    matches!(
        operation,
        ParameterOperation::ConfigurationWrite
            | ParameterOperation::ConfigurationRead
            | ParameterOperation::ConfigurationVerify
    )
}

fn region_capacity(device: &DeviceRecord, region: u32) -> Result<usize, DeviceParameterBuildError> {
    let index = usize::try_from(region).map_err(|_| DeviceParameterBuildError::IntegerOverflow)?;
    let selected = device
        .data_region(index)
        .ok_or(DeviceParameterBuildError::RegionUnavailable { region })?;
    usize::try_from(selected.length()).map_err(|_| DeviceParameterBuildError::IntegerOverflow)
}

/// Padded project bytes and the aligned absolute range used by both `SPRJ`
/// metadata and program/verify transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedProjectData {
    bytes: Vec<u8>,
    range: Range<usize>,
}

impl PreparedProjectData {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    #[must_use]
    pub fn operation_bytes(&self) -> &[u8] {
        &self.bytes[self.range.clone()]
    }
}

/// Reproduces the original host's `0x800`-byte project range alignment. Bytes
/// outside the caller's file but inside the aligned range are filled with
/// erased-Flash value `0xff`.
///
/// # Errors
///
/// Returns [`DeviceParameterBuildError`] if the region is unavailable, the
/// source is too large, or alignment cannot be represented on this platform.
pub fn prepare_project_data(
    device: &DeviceRecord,
    region: u32,
    source: &[u8],
) -> Result<PreparedProjectData, DeviceParameterBuildError> {
    let capacity = region_capacity(device, region)?;
    if source.len() > capacity {
        return Err(DeviceParameterBuildError::ProjectTooLarge {
            data_length: source.len(),
            region,
            capacity,
        });
    }
    let Some(first) = source.iter().position(|byte| *byte != 0xff) else {
        return Ok(PreparedProjectData {
            bytes: Vec::new(),
            range: 0..0,
        });
    };
    let last = source
        .iter()
        .rposition(|byte| *byte != 0xff)
        .ok_or(DeviceParameterBuildError::IntegerOverflow)?;
    let start = first / PROJECT_ALIGNMENT_BYTES * PROJECT_ALIGNMENT_BYTES;
    let end = last
        .checked_add(1)
        .and_then(|value| value.checked_add(PROJECT_ALIGNMENT_BYTES - 1))
        .map(|value| value / PROJECT_ALIGNMENT_BYTES * PROJECT_ALIGNMENT_BYTES)
        .ok_or(DeviceParameterBuildError::IntegerOverflow)?;
    if end > capacity {
        return Err(DeviceParameterBuildError::ProjectTooLarge {
            data_length: end,
            region,
            capacity,
        });
    }
    let mut bytes = vec![0xff; end];
    bytes[..source.len().min(end)].copy_from_slice(&source[..source.len().min(end)]);
    Ok(PreparedProjectData {
        bytes,
        range: start..end,
    })
}

fn encode_profile_text(
    value: &str,
    field: &'static str,
) -> Result<Vec<u8>, DeviceParameterBuildError> {
    let (encoded, _, had_errors) = GBK.encode(value);
    if had_errors {
        return Err(DeviceParameterBuildError::InvalidProfileText { field });
    }
    Ok(encoded.into_owned())
}

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

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("two-byte profile field"),
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
    #[error("selected algorithm mismatch: expected {expected}, found {actual}")]
    AlgorithmMismatch { expected: String, actual: String },
    #[error("selected configuration mismatch: expected {expected}, found {actual}")]
    ConfigurationMismatch { expected: String, actual: String },
    #[error("this operation requires a configuration asset{suffix}", suffix = stem.as_ref().map_or(String::new(), |value| format!(" ({value})")))]
    ConfigurationRequired { stem: Option<String> },
    #[error("package key {key} is not available for device {device}")]
    PackageUnavailable { key: u8, device: String },
    #[error("device region {region} is not available")]
    RegionUnavailable { region: u32 },
    #[error("project data is {data_length} bytes, exceeding region {region} capacity {capacity}")]
    ProjectTooLarge {
        data_length: usize,
        region: u32,
        capacity: usize,
    },
    #[error("{field} cannot be represented by the original GBK-compatible profile")]
    InvalidProfileText { field: &'static str },
    #[error("SPRJ field does not fit its confirmed 32-bit width")]
    IntegerOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::{
        defaults::default_device_database, embedded_algorithms::embedded_algorithm,
        embedded_configurations::embedded_configuration, package_map::default_package_map,
    };

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
    fn derives_w25q128_parameters_from_default_assets() {
        let database = default_device_database().expect("default database");
        let selected = database
            .select_device("W25Q128BV", None)
            .expect("default device");
        let algorithm = embedded_algorithm(selected.device().algorithm_stem())
            .expect("default algorithm")
            .parse()
            .expect("valid algorithm");
        let configuration = embedded_configuration(
            selected
                .device()
                .configuration_stem()
                .expect("configuration reference"),
        )
        .expect("default configuration")
        .parse()
        .expect("valid configuration");
        let project_data = [0xa5; 256];
        let package = default_package_map()
            .expect("package map")
            .get(150)
            .expect("device package");

        let image = build_automatic_device_parameters(&AutomaticParameterInputs {
            device: selected.device(),
            vendor_name: selected.vendor().name(),
            algorithm: &algorithm,
            configuration: Some(&configuration),
            package,
            operation: ParameterOperation::Program,
            region: 0,
            project_data: &project_data,
            local_time_bcd: [0x20, 0x26, 0x07, 0x20, 0x18, 0x30, 0x45],
        })
        .expect("automatic parameters");
        let bytes = image.as_bytes();

        assert_eq!(&bytes[0x020..0x027], b"Winbond");
        assert_eq!(&bytes[0x040..0x049], b"W25Q128BV");
        assert_eq!(&bytes[0x090..0x120], selected.device().raw());
        assert_eq!(read_image_u32(bytes, 0x080), 4_187);
        assert_eq!(
            u16::from_le_bytes(bytes[0x084..0x086].try_into().unwrap()),
            0x1108
        );
        assert_eq!(bytes[0x086], 150);
        assert_eq!(&bytes[0x060..0x06a], b"WSON8(8x6)");
        assert_eq!(&bytes[0x450..0x490], configuration.default_block_0());
        assert_eq!(&bytes[0x490..0x4d0], configuration.default_block_1());
        assert_eq!(
            read_image_u32(bytes, 0x4d0),
            configuration.default_protection_bits()
        );
        assert_eq!(read_image_u32(bytes, 0x4e4), 0x001);
        assert_eq!(bytes[0x4e8], 1);
        assert_eq!(bytes[0x320], 1);
        assert_eq!(read_image_u32(bytes, 0x330), 0x0104_0000);
        assert_eq!(read_image_u32(bytes, 0x334), 0x00ff_fff0);
        assert_eq!(read_image_u32(bytes, 0x56c), 0);
        assert_eq!(read_image_u32(bytes, 0x570), 0x800);
        assert_eq!(read_image_u32(bytes, 0x57c), 0x800);
        assert_eq!(read_image_u32(bytes, 0x584), 0x0100_0000);
        assert_eq!(read_image_u32(bytes, 0x58c), 0x0100_0000);
        image
            .validate_for_algorithm(&algorithm)
            .expect("derived image matches algorithm");
    }

    #[test]
    fn derives_configuration_operation_and_rejects_unavailable_regions() {
        let database = default_device_database().expect("default database");
        let selected = database
            .select_device("W25Q128BV", None)
            .expect("default device");
        let algorithm = embedded_algorithm(selected.device().algorithm_stem())
            .expect("default algorithm")
            .parse()
            .expect("valid algorithm");
        let configuration = embedded_configuration("W25Q128S")
            .expect("default configuration")
            .parse()
            .expect("valid configuration");
        let package = default_package_map()
            .expect("package map")
            .get(150)
            .expect("device package");
        let mut inputs = AutomaticParameterInputs {
            device: selected.device(),
            vendor_name: selected.vendor().name(),
            algorithm: &algorithm,
            configuration: Some(&configuration),
            package,
            operation: ParameterOperation::ConfigurationVerify,
            region: 0,
            project_data: &[],
            local_time_bcd: [0x20, 0x26, 0x07, 0x20, 0x18, 0x30, 0x45],
        };

        let image = build_automatic_device_parameters(&inputs).expect("configuration profile");
        assert_eq!(image.as_bytes()[0x320], 0x10);
        assert_eq!(image.as_bytes()[0x4e8], 10);
        assert_eq!(read_image_u32(image.as_bytes(), 0x4e4), 0x40);

        inputs.region = 2;
        assert!(matches!(
            build_automatic_device_parameters(&inputs),
            Err(DeviceParameterBuildError::RegionUnavailable { region: 2 })
        ));
    }

    #[test]
    fn folds_every_confirmed_operation_code() {
        assert_eq!(
            fold_capabilities([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 0, 0]),
            0x087f
        );
    }

    #[test]
    fn aligns_the_effective_non_ff_project_range() {
        let database = default_device_database().expect("default database");
        let device = database
            .select_device("W25Q128BV", None)
            .expect("default device")
            .device();
        let mut source = vec![0xff; 0x1001];
        source[0x821] = 0x12;
        source[0x900] = 0x34;

        let prepared = prepare_project_data(device, 0, &source).expect("prepared project");

        assert_eq!(prepared.range(), 0x800..0x1000);
        assert_eq!(prepared.bytes().len(), 0x1000);
        assert_eq!(prepared.operation_bytes()[0x21], 0x12);
        assert_eq!(prepared.operation_bytes()[0x100], 0x34);
    }
}
