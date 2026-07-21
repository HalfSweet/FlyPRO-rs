use std::{fmt::Write as _, fs, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use chrono::{Datelike, Local, Timelike};
use clap::{Args, Subcommand, ValueEnum};
use flypro_core::{
    assets::{
        algorithm::Algorithm,
        configuration::Configuration,
        defaults::default_device_database,
        device_db::{DeviceDatabase, DeviceRecord},
        embedded_algorithms::embedded_algorithm,
        embedded_configurations::embedded_configuration,
        package_map::{PackageRecord, default_package_map},
    },
    operations::{EraseRequest, OperationReceipt, OperationSession},
    parameters::{
        AutomaticParameterInputs, ParameterOperation, PreparedProjectData,
        build_automatic_device_parameters, prepare_project_data,
    },
    protocol::{CONFIGURATION_READ_BYTES, DeviceParameterImage, EraseMode},
    session::{AlgorithmSession, StaticCompletionPolicy},
    transport::{NeverCancelled, ThreadDelay},
    usb_transport::NusbTransport,
};

#[derive(Debug, Args)]
pub(crate) struct DeviceArgs {
    #[command(subcommand)]
    command: DeviceCommand,
}

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// Claim a programmer, load the selected algorithm, and send `SPRJ`.
    Prepare {
        #[command(flatten)]
        target: TargetArgs,
    },
    /// Execute the statically recovered blank-check sequence.
    BlankCheck {
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long, default_value = "0", value_parser = parse_u32)]
        region: u32,
        /// Bytes to check; defaults to the selected region's full capacity.
        #[arg(long, value_parser = parse_usize)]
        length: Option<usize>,
        #[arg(long, default_value = "0x800", value_parser = parse_usize)]
        chunk: usize,
    },
    /// Read one region into a file.
    Read {
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long, default_value = "0", value_parser = parse_u32)]
        region: u32,
        /// Bytes to read; defaults to the selected region's full capacity.
        #[arg(long, value_parser = parse_usize)]
        length: Option<usize>,
        #[arg(long, default_value = "0", value_parser = parse_u16)]
        minimum_chunk: u16,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Read one region and compare it with a file.
    Verify {
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long, default_value = "0", value_parser = parse_u32)]
        region: u32,
        #[arg(long, default_value = "0", value_parser = parse_u16)]
        minimum_chunk: u16,
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Program one region from a file.
    Program {
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long, default_value = "0", value_parser = parse_u32)]
        region: u32,
        #[arg(long, default_value = "0", value_parser = parse_u16)]
        minimum_chunk: u16,
        #[arg(short, long)]
        input: PathBuf,
        /// Confirm that this command may modify the target device.
        #[arg(long)]
        yes: bool,
    },
    /// Execute the shared `0x0013` erase path.
    Erase {
        #[command(flatten)]
        target: TargetArgs,
        /// Raw selector stored at command offset `+0x04`; individual bits are unnamed.
        #[arg(long, value_parser = parse_u32)]
        path_selector: u32,
        #[arg(long, value_enum, default_value_t = EraseModeArg::Chip)]
        mode: EraseModeArg,
        /// Confirm that this command may erase the target device.
        #[arg(long)]
        yes: bool,
    },
    /// Read the exact 64-byte configuration response into a file.
    ConfigRead {
        #[command(flatten)]
        target: TargetArgs,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Read and apply the recovered masked configuration comparison.
    ConfigVerify {
        #[command(flatten)]
        target: TargetArgs,
        /// Exact 64-byte expected image; defaults to CFG block 0.
        #[arg(long)]
        data: Option<PathBuf>,
        /// Exact 64-byte mask; defaults to CFG block 1.
        #[arg(long)]
        mask: Option<PathBuf>,
    },
    /// Write a configuration image and mask through `0x00A3`.
    ConfigWrite {
        #[command(flatten)]
        target: TargetArgs,
        /// Exact 64-byte image; defaults to CFG block 0.
        #[arg(long)]
        data: Option<PathBuf>,
        /// Exact 64-byte mask; defaults to CFG block 1.
        #[arg(long)]
        mask: Option<PathBuf>,
        /// Confirm that this command may modify the target device.
        #[arg(long)]
        yes: bool,
    },
    /// Collect `0x85` progress records until the recovered finish flag.
    Progress {
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long, default_value_t = 4096, value_parser = parse_usize)]
        max_records: usize,
    },
}

#[derive(Debug, Args)]
struct TargetArgs {
    /// Zero-based index from `flypro usb list`.
    #[arg(long, visible_alias = "device-index", default_value_t = 0)]
    programmer_index: usize,
    /// Exact chip part name in the device database.
    #[arg(long)]
    chip: String,
    /// Vendor name or code, only needed to disambiguate duplicate part names.
    #[arg(long)]
    vendor: Option<String>,
    /// Decimal or hexadecimal package key listed by `device-db find`.
    #[arg(long, value_parser = parse_u8)]
    package_key: Option<u8>,
    /// Override the device database bundled into `flypro-core`.
    #[arg(long)]
    device_database: Option<PathBuf>,
    /// Override the CFG inferred from the selected device.
    #[arg(long)]
    configuration: Option<PathBuf>,
    /// Override the algorithm stem (normally paired with --parameters).
    #[arg(long)]
    algorithm: Option<String>,
    /// Override automatic parameter construction with an exact 2048-byte SPRJ.
    #[arg(long)]
    parameters: Option<PathBuf>,
    /// Explicitly opt in to the protocol recovered by static analysis.
    #[arg(long)]
    accept_static_protocol: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EraseModeArg {
    Chip,
    Automatic,
}

impl From<EraseModeArg> for EraseMode {
    fn from(value: EraseModeArg) -> Self {
        match value {
            EraseModeArg::Chip => Self::Chip,
            EraseModeArg::Automatic => Self::Automatic,
        }
    }
}

pub(crate) fn run(args: DeviceArgs) -> Result<()> {
    match args.command {
        DeviceCommand::Prepare { target } => {
            let _transport = prepare(&target)?;
            Ok(())
        }
        DeviceCommand::BlankCheck {
            target,
            region,
            length,
            chunk,
        } => run_blank_check(&target, region, length, chunk),
        DeviceCommand::Read {
            target,
            region,
            length,
            minimum_chunk,
            output,
        } => run_read(&target, region, length, minimum_chunk, &output),
        DeviceCommand::Verify {
            target,
            region,
            minimum_chunk,
            input,
        } => run_verify(&target, region, minimum_chunk, &input),
        DeviceCommand::Program {
            target,
            region,
            minimum_chunk,
            input,
            yes,
        } => run_program(&target, region, minimum_chunk, &input, yes),
        DeviceCommand::Erase {
            target,
            path_selector,
            mode,
            yes,
        } => run_erase(&target, path_selector, mode, yes),
        DeviceCommand::ConfigRead { target, output } => run_config_read(&target, &output),
        DeviceCommand::ConfigVerify { target, data, mask } => {
            run_config_verify(&target, data.as_ref(), mask.as_ref())
        }
        DeviceCommand::ConfigWrite {
            target,
            data,
            mask,
            yes,
        } => run_config_write(&target, data.as_ref(), mask.as_ref(), yes),
        DeviceCommand::Progress {
            target,
            max_records,
        } => run_progress(&target, max_records),
    }
}

fn run_blank_check(
    target: &TargetArgs,
    region: u32,
    length: Option<usize>,
    chunk: usize,
) -> Result<()> {
    ensure!(
        (0x800..=0x1_0000).contains(&chunk),
        "blank-check chunk size must be within 0x800..=0x10000"
    );
    let resolved = resolve_target(target, ParameterOperation::BlankCheck, region, &[])?;
    let length = inferred_operation_length(length, &resolved, region)?;
    let mut transport = open_prepared_target(target, &resolved)?;
    let receipt = OperationSession::new(&mut transport, &NeverCancelled)
        .blank_check(region, length, chunk)?;
    print_receipt("blank-check", &receipt);
    Ok(())
}

fn run_read(
    target: &TargetArgs,
    region: u32,
    length: Option<usize>,
    minimum_chunk: u16,
    output: &PathBuf,
) -> Result<()> {
    let resolved = resolve_target(target, ParameterOperation::Read, region, &[])?;
    let length = inferred_operation_length(length, &resolved, region)?;
    let mut transport = open_prepared_target(target, &resolved)?;
    let result = OperationSession::new(&mut transport, &NeverCancelled).read(
        region,
        length,
        minimum_chunk,
    )?;
    print_receipt("read", &result.receipt);
    ensure_flash_readback(&result.data, &resolved.parameters)?;
    write_file(output, &result.data)?;
    println!("wrote {} bytes to {}", result.data.len(), output.display());
    Ok(())
}

fn ensure_flash_readback(data: &[u8], parameters: &DeviceParameterImage) -> Result<()> {
    const MINIMUM_DISTINCTIVE_PREFIX_BYTES: usize = 0x20;

    let compared = data.len().min(parameters.as_bytes().len());
    ensure!(
        compared >= MINIMUM_DISTINCTIVE_PREFIX_BYTES,
        "readback is only {} bytes; at least {MINIMUM_DISTINCTIVE_PREFIX_BYTES} bytes are required to distinguish Flash data from the SPRJ parameter buffer; refusing to write an unverified backup",
        data.len()
    );
    ensure!(
        data[..compared] != parameters.as_bytes()[..compared],
        "device returned the SPRJ parameter buffer instead of Flash data; refusing to write an invalid backup"
    );
    Ok(())
}

fn run_verify(target: &TargetArgs, region: u32, minimum_chunk: u16, input: &PathBuf) -> Result<()> {
    let expected = read_file(input)?;
    validate_operation_length(expected.len())?;
    let resolved = resolve_target(target, ParameterOperation::Verify, region, &expected)?;
    validate_region_length(&resolved, region, expected.len())?;
    let range = resolved.prepared_project.range();
    ensure!(
        !range.is_empty(),
        "input contains only erased value 0xff; there is no effective range to verify"
    );
    let mut transport = open_prepared_target(target, &resolved)?;
    let receipt = OperationSession::new(&mut transport, &NeverCancelled).verify_range(
        region,
        range.start,
        resolved.prepared_project.operation_bytes(),
        minimum_chunk,
    )?;
    print_receipt("verify", &receipt);
    Ok(())
}

fn run_program(
    target: &TargetArgs,
    region: u32,
    minimum_chunk: u16,
    input: &PathBuf,
    confirmed: bool,
) -> Result<()> {
    require_destructive_confirmation(confirmed)?;
    let data = read_file(input)?;
    validate_operation_length(data.len())?;
    let resolved = resolve_target(target, ParameterOperation::Program, region, &data)?;
    validate_region_length(&resolved, region, data.len())?;
    let range = resolved.prepared_project.range();
    ensure!(
        !range.is_empty(),
        "input contains only erased value 0xff; there is no effective range to program"
    );
    let mut transport = open_prepared_target(target, &resolved)?;
    let receipt = OperationSession::new(&mut transport, &NeverCancelled).program_range(
        region,
        range.start,
        resolved.prepared_project.operation_bytes(),
        minimum_chunk,
    )?;
    print_receipt("program", &receipt);
    Ok(())
}

fn run_erase(
    target: &TargetArgs,
    path_selector: u32,
    mode: EraseModeArg,
    confirmed: bool,
) -> Result<()> {
    require_destructive_confirmation(confirmed)?;
    let operation = match mode {
        EraseModeArg::Chip => ParameterOperation::ChipErase,
        EraseModeArg::Automatic => ParameterOperation::AutomaticErase,
    };
    let resolved = resolve_target(target, operation, 0, &[])?;
    let mut transport = open_prepared_target(target, &resolved)?;
    let result = OperationSession::new(&mut transport, &NeverCancelled).erase(EraseRequest {
        path_selector,
        mode: mode.into(),
    })?;
    if let Some(raw) = &result.raw_result {
        println!("erase command-specific result: {}", encode_hex(raw));
    }
    if result.outcome == flypro_core::operations::EraseOutcome::Completed {
        print_receipt("erase", &result.receipt);
    } else {
        bail!(
            "erase did not return the normal accepted completion (outcome={:?}, statuses={})",
            result.outcome,
            format_statuses(result.receipt.statuses())
        );
    }
    Ok(())
}

fn run_config_read(target: &TargetArgs, output: &PathBuf) -> Result<()> {
    let resolved = resolve_target(target, ParameterOperation::ConfigurationRead, 0, &[])?;
    let mut transport = open_prepared_target(target, &resolved)?;
    let result = OperationSession::new(&mut transport, &NeverCancelled).read_configuration()?;
    write_file(output, &result.data)?;
    print_receipt("configuration read", &result.receipt);
    println!("wrote {} bytes to {}", result.data.len(), output.display());
    Ok(())
}

fn run_config_verify(
    target: &TargetArgs,
    data: Option<&PathBuf>,
    mask: Option<&PathBuf>,
) -> Result<()> {
    let resolved = resolve_target(target, ParameterOperation::ConfigurationVerify, 0, &[])?;
    let (expected, mask) = configuration_payload(data, mask, resolved.configuration.as_ref())?;
    let mut transport = open_prepared_target(target, &resolved)?;
    let receipt = OperationSession::new(&mut transport, &NeverCancelled)
        .verify_configuration(&expected, &mask)?;
    print_receipt("configuration verify", &receipt);
    Ok(())
}

fn run_config_write(
    target: &TargetArgs,
    data: Option<&PathBuf>,
    mask: Option<&PathBuf>,
    confirmed: bool,
) -> Result<()> {
    require_destructive_confirmation(confirmed)?;
    let resolved = resolve_target(target, ParameterOperation::ConfigurationWrite, 0, &[])?;
    let (data, mask) = configuration_payload(data, mask, resolved.configuration.as_ref())?;
    let mut transport = open_prepared_target(target, &resolved)?;
    let receipt =
        OperationSession::new(&mut transport, &NeverCancelled).write_configuration(&data, &mask)?;
    print_receipt("configuration write", &receipt);
    Ok(())
}

fn run_progress(target: &TargetArgs, max_records: usize) -> Result<()> {
    ensure!(max_records > 0, "--max-records must be greater than zero");
    let resolved = resolve_target(target, ParameterOperation::Progress, 0, &[])?;
    let mut transport = open_prepared_target(target, &resolved)?;
    let result =
        OperationSession::new(&mut transport, &NeverCancelled).progress_events(max_records)?;
    for (index, event) in result.events.iter().enumerate() {
        println!(
            "event {index}: value={:#04x} finished={} raw={}",
            event.stage_or_progress,
            event.finished,
            encode_hex(&event.raw)
        );
    }
    print_receipt("progress", &result.receipt);
    Ok(())
}

fn prepare(target: &TargetArgs) -> Result<NusbTransport> {
    let resolved = resolve_target(target, ParameterOperation::Prepare, 0, &[])?;
    open_prepared_target(target, &resolved)
}

struct ResolvedTarget {
    algorithm: Algorithm,
    parameters: DeviceParameterImage,
    configuration: Option<Configuration>,
    device_name: String,
    vendor_name: String,
    region_lengths: [Option<usize>; 2],
    prepared_project: PreparedProjectData,
    package_description: Option<String>,
}

fn resolve_target(
    target: &TargetArgs,
    operation: ParameterOperation,
    region: u32,
    project_data: &[u8],
) -> Result<ResolvedTarget> {
    require_static_opt_in(target)?;
    let database_override = target
        .device_database
        .as_ref()
        .map(|path| {
            let bytes = read_file(path)?;
            DeviceDatabase::parse(&bytes)
                .with_context(|| format!("invalid device database {}", path.display()))
        })
        .transpose()?;
    let database = match database_override.as_ref() {
        Some(database) => database,
        None => default_device_database().context("bundled device database is invalid")?,
    };
    let selected = database
        .select_device(&target.chip, target.vendor.as_deref())
        .context("failed to select chip")?;
    let algorithm_stem = target
        .algorithm
        .as_deref()
        .unwrap_or_else(|| selected.device().algorithm_stem());
    let asset = embedded_algorithm(algorithm_stem).with_context(|| {
        format!("embedded algorithm {algorithm_stem:?} was not found; use a stem without .alg")
    })?;
    let algorithm = asset
        .parse()
        .with_context(|| format!("embedded algorithm {} is invalid", asset.file_name()))?;

    let configuration = load_configuration(target, selected.device())?;
    let prepared_project = prepare_project_data(selected.device(), region, project_data)
        .context("failed to prepare aligned project data")?;
    let package = resolve_package(target, selected.device())?;
    let parameters = if let Some(path) = &target.parameters {
        let parameter_bytes = read_file(path)?;
        DeviceParameterImage::try_from_sprj(&parameter_bytes)
            .with_context(|| format!("invalid SPRJ image {}", path.display()))?
    } else {
        let package = package.context("automatic parameter construction has no package route")?;
        build_automatic_device_parameters(&AutomaticParameterInputs {
            device: selected.device(),
            vendor_name: selected.vendor().name(),
            algorithm: &algorithm,
            configuration: configuration.as_ref(),
            package,
            operation,
            region,
            project_data,
            local_time_bcd: current_local_time_bcd()?,
        })
        .context("failed to derive SPRJ parameters")?
    };
    parameters
        .validate_for_algorithm(&algorithm)
        .with_context(|| format!("SPRJ image does not match algorithm {}", algorithm.name()))?;

    let region_lengths = [0, 1].map(|index| {
        selected
            .device()
            .data_region(index)
            .and_then(|region| usize::try_from(region.length()).ok())
    });
    Ok(ResolvedTarget {
        algorithm,
        parameters,
        configuration,
        device_name: selected.device().name().to_owned(),
        vendor_name: selected.vendor().name().to_owned(),
        region_lengths,
        prepared_project,
        package_description: package.map(|package| {
            format!(
                "{} (key {}, type {:#06x}, adapter {})",
                package.package_name(),
                package.key(),
                package.package_type(),
                if package.adapter_name().is_empty() {
                    "direct"
                } else {
                    package.adapter_name()
                }
            )
        }),
    })
}

fn resolve_package(
    target: &TargetArgs,
    device: &DeviceRecord,
) -> Result<Option<&'static PackageRecord>> {
    if target.parameters.is_some() {
        return Ok(None);
    }
    let allowed = device
        .package_keys()
        .map(|key| key.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let key = target.package_key.with_context(|| {
        format!(
            "automatic parameters require --package-key; valid keys for {} are: {allowed}",
            device.name()
        )
    })?;
    ensure!(
        device.package_keys().any(|candidate| candidate == key),
        "package key {key} is not valid for {}; valid keys are: {allowed}",
        device.name()
    );
    let map = default_package_map().context("bundled package map is invalid")?;
    map.get(key)
        .with_context(|| format!("package key {key} is missing from the package map"))
        .map(Some)
}

fn load_configuration(target: &TargetArgs, device: &DeviceRecord) -> Result<Option<Configuration>> {
    if let Some(path) = &target.configuration {
        let bytes = read_file(path)?;
        return Configuration::parse(&bytes)
            .with_context(|| format!("invalid configuration {}", path.display()))
            .map(Some);
    }
    let Some(stem) = device.configuration_stem() else {
        return Ok(None);
    };
    let asset = embedded_configuration(stem)
        .with_context(|| format!("bundled configuration {stem:?} was not found"))?;
    asset
        .parse()
        .with_context(|| format!("bundled configuration {} is invalid", asset.file_name()))
        .map(Some)
}

fn open_prepared_target(target: &TargetArgs, resolved: &ResolvedTarget) -> Result<NusbTransport> {
    let mut transport = NusbTransport::open(target.programmer_index)?;
    println!("selected {} {}", resolved.vendor_name, resolved.device_name);
    if let Some(package) = &resolved.package_description {
        println!("package {package}");
    }
    println!(
        "claimed programmer {} interface {} alt {}",
        target.programmer_index,
        transport.interface_number(),
        transport.alternate_setting()
    );
    let ready = AlgorithmSession::new().prepare(
        &mut transport,
        &StaticCompletionPolicy,
        &mut ThreadDelay,
        &NeverCancelled,
        &resolved.algorithm,
        &resolved.parameters,
    )?;
    println!(
        "algorithm {} ready (reused={}, completion={})",
        ready.identity().name(),
        ready.reused(),
        format_statuses(ready.completion_statuses())
    );
    let adapter = OperationSession::new(&mut transport, &NeverCancelled).adapter_check()?;
    println!(
        "adapter check complete (completion={})",
        format_statuses(adapter.receipt.statuses())
    );
    let probe = OperationSession::new(&mut transport, &NeverCancelled).target_probe()?;
    println!(
        "target probe complete (completion={})",
        format_statuses(probe.receipt.statuses())
    );
    Ok(transport)
}

fn require_static_opt_in(target: &TargetArgs) -> Result<()> {
    ensure!(
        target.accept_static_protocol,
        "real device commands are based on static analysis and are not hardware-validated; pass --accept-static-protocol to continue"
    );
    Ok(())
}

fn require_destructive_confirmation(confirmed: bool) -> Result<()> {
    ensure!(
        confirmed,
        "this command can modify the target device; pass --yes to continue"
    );
    Ok(())
}

fn inferred_operation_length(
    requested: Option<usize>,
    resolved: &ResolvedTarget,
    region: u32,
) -> Result<usize> {
    let length = match requested {
        Some(length) => length,
        None => selected_region_length(resolved, region)?,
    };
    validate_operation_length(length)?;
    validate_region_length(resolved, region, length)?;
    Ok(length)
}

fn validate_region_length(resolved: &ResolvedTarget, region: u32, length: usize) -> Result<()> {
    let capacity = selected_region_length(resolved, region)?;
    ensure!(
        length <= capacity,
        "operation length {length} exceeds region {region} capacity {capacity}"
    );
    Ok(())
}

fn selected_region_length(resolved: &ResolvedTarget, region: u32) -> Result<usize> {
    let index = usize::try_from(region).context("region index does not fit this platform")?;
    resolved
        .region_lengths
        .get(index)
        .copied()
        .flatten()
        .with_context(|| format!("selected chip has no data region {region}"))
}

fn configuration_payload(
    data_path: Option<&PathBuf>,
    mask_path: Option<&PathBuf>,
    configuration: Option<&Configuration>,
) -> Result<(
    [u8; CONFIGURATION_READ_BYTES],
    [u8; CONFIGURATION_READ_BYTES],
)> {
    let data = match data_path {
        Some(path) => read_configuration_file(path)?,
        None => *configuration
            .context("no CFG is available; pass --data or --configuration")?
            .default_block_0(),
    };
    let mask = match mask_path {
        Some(path) => read_configuration_file(path)?,
        None => *configuration
            .context("no CFG is available; pass --mask or --configuration")?
            .default_block_1(),
    };
    Ok((data, mask))
}

fn current_local_time_bcd() -> Result<[u8; 7]> {
    let now = Local::now();
    encode_local_time_bcd(
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
    )
}

fn encode_local_time_bcd(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<[u8; 7]> {
    ensure!(
        (0..=9_999).contains(&year),
        "local year {year} is outside 0000..=9999"
    );
    let year = u32::try_from(year).context("local year is negative")?;
    Ok([
        to_bcd(year / 100),
        to_bcd(year % 100),
        to_bcd(month),
        to_bcd(day),
        to_bcd(hour),
        to_bcd(minute),
        to_bcd(second),
    ])
}

fn to_bcd(value: u32) -> u8 {
    u8::try_from(((value / 10) << 4) | (value % 10)).expect("date/time component fits in BCD")
}

fn validate_operation_length(length: usize) -> Result<()> {
    ensure!(
        length > 0,
        "operation data length must be greater than zero"
    );
    ensure!(
        u32::try_from(length).is_ok(),
        "operation data length {length} exceeds the 32-bit protocol field"
    );
    Ok(())
}

fn read_configuration_file(path: &PathBuf) -> Result<[u8; CONFIGURATION_READ_BYTES]> {
    let bytes = read_file(path)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "{} is {} bytes, expected exactly {}",
            path.display(),
            bytes.len(),
            CONFIGURATION_READ_BYTES
        )
    })
}

fn read_file(path: &PathBuf) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn write_file(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn print_receipt(operation: &str, receipt: &OperationReceipt) {
    println!(
        "{operation} complete; statuses={}",
        format_statuses(receipt.statuses())
    );
}

fn format_statuses(statuses: &[u8]) -> String {
    if statuses.is_empty() {
        return "none".to_owned();
    }
    statuses
        .iter()
        .map(|status| format!("{status:#04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        },
    )
}

fn parse_u16(value: &str) -> Result<u16, String> {
    parse_integer(value).and_then(|parsed| {
        u16::try_from(parsed).map_err(|_| format!("{value:?} does not fit a 16-bit integer"))
    })
}

fn parse_u8(value: &str) -> Result<u8, String> {
    parse_integer(value).and_then(|parsed| {
        u8::try_from(parsed).map_err(|_| format!("{value:?} does not fit an 8-bit integer"))
    })
}

fn parse_u32(value: &str) -> Result<u32, String> {
    parse_integer(value).and_then(|parsed| {
        u32::try_from(parsed).map_err(|_| format!("{value:?} does not fit a 32-bit integer"))
    })
}

fn parse_usize(value: &str) -> Result<usize, String> {
    parse_integer(value).and_then(|parsed| {
        usize::try_from(parsed).map_err(|_| format!("{value:?} does not fit this platform"))
    })
}

fn parse_integer(value: &str) -> Result<u64, String> {
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |digits| (digits, 16));
    if digits.is_empty() {
        return Err(format!("{value:?} is not an integer"));
    }
    u64::from_str_radix(digits, radix)
        .map_err(|error| format!("invalid integer {value:?}: {error}"))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::Cli;

    #[test]
    fn parses_hexadecimal_operation_arguments() {
        let cli = Cli::try_parse_from([
            "flypro",
            "device",
            "erase",
            "--chip",
            "W25Q128BV",
            "--accept-static-protocol",
            "--path-selector",
            "0x20",
            "--mode",
            "automatic",
            "--yes",
        ])
        .expect("valid command");

        let crate::Command::Device(DeviceArgs {
            command:
                DeviceCommand::Erase {
                    path_selector,
                    mode,
                    yes,
                    ..
                },
        }) = cli.command
        else {
            panic!("unexpected command");
        };
        assert_eq!(path_selector, 0x20);
        assert!(matches!(mode, EraseModeArg::Automatic));
        assert!(yes);
    }

    #[test]
    fn parses_a_minimal_read_with_inferred_assets_and_length() {
        let cli = Cli::try_parse_from([
            "flypro",
            "device",
            "read",
            "--chip",
            "W25Q128BV",
            "--accept-static-protocol",
            "--output",
            "flash.bin",
        ])
        .expect("minimal read command");

        let crate::Command::Device(DeviceArgs {
            command: DeviceCommand::Read { target, length, .. },
        }) = cli.command
        else {
            panic!("unexpected command");
        };
        assert_eq!(target.chip, "W25Q128BV");
        assert_eq!(target.programmer_index, 0);
        assert!(target.algorithm.is_none());
        assert!(target.parameters.is_none());
        assert!(length.is_none());
    }

    #[test]
    fn resolves_the_default_target_without_usb_access() {
        let target = TargetArgs {
            programmer_index: 0,
            chip: "W25Q128BV".to_owned(),
            vendor: None,
            package_key: Some(150),
            device_database: None,
            configuration: None,
            algorithm: None,
            parameters: None,
            accept_static_protocol: true,
        };

        let resolved = resolve_target(&target, ParameterOperation::Program, 0, &[0xa5; 16])
            .expect("default target resolves");
        assert_eq!(resolved.vendor_name, "Winbond");
        assert_eq!(resolved.device_name, "W25Q128BV");
        assert_eq!(resolved.algorithm.name(), "W25Q128");
        assert_eq!(resolved.region_lengths[0], Some(0x0100_0000));
        assert_eq!(
            resolved
                .configuration
                .as_ref()
                .expect("inferred configuration")
                .name(),
            "W25Q128S"
        );
        assert_eq!(&resolved.parameters.as_bytes()[..4], b"SPRJ");
    }

    #[test]
    fn resolves_w25q16jv_with_the_selected_soic_route() {
        let target = TargetArgs {
            programmer_index: 0,
            chip: "W25Q16JVxxxQ".to_owned(),
            vendor: None,
            package_key: Some(32),
            device_database: None,
            configuration: None,
            algorithm: None,
            parameters: None,
            accept_static_protocol: true,
        };

        let resolved = resolve_target(&target, ParameterOperation::Read, 0, &[])
            .expect("W25Q16JV target resolves");
        let parameters = resolved.parameters.as_bytes();

        assert_eq!(resolved.region_lengths[0], Some(0x20_0000));
        assert_eq!(resolved.algorithm.name(), "W25Q128");
        assert_eq!(parameters[0x086], 32);
        assert_eq!(
            u16::from_le_bytes(parameters[0x084..0x086].try_into().unwrap()),
            0x1008
        );
        assert_eq!(&parameters[0x060..0x069], b"SOIC8-150");
        assert_eq!(
            u32::from_le_bytes(parameters[0x324..0x328].try_into().unwrap()),
            0x111
        );
    }

    #[test]
    fn uses_configuration_blocks_when_payload_paths_are_omitted() {
        let configuration = embedded_configuration("W25Q128S")
            .expect("configuration")
            .parse()
            .expect("valid configuration");

        let (data, mask) = configuration_payload(None, None, Some(&configuration))
            .expect("inferred configuration payload");
        assert_eq!(&data, configuration.default_block_0());
        assert_eq!(&mask, configuration.default_block_1());
    }

    #[test]
    fn encodes_the_original_seven_byte_local_time_shape() {
        assert_eq!(
            encode_local_time_bcd(2026, 7, 20, 18, 30, 45).expect("valid time"),
            [0x20, 0x26, 0x07, 0x20, 0x18, 0x30, 0x45]
        );
    }

    #[test]
    fn destructive_commands_require_confirmation_before_usb() {
        assert!(require_destructive_confirmation(false).is_err());
        assert!(require_destructive_confirmation(true).is_ok());
    }

    #[test]
    fn operation_lengths_are_rejected_before_usb() {
        assert!(validate_operation_length(0).is_err());
        assert!(validate_operation_length(1).is_ok());
        if usize::BITS > 32 {
            assert!(validate_operation_length(usize::MAX).is_err());
        }
    }

    #[test]
    fn rejects_parameter_buffer_returned_as_flash_data() {
        let mut bytes = [0_u8; 0x800];
        bytes[..4].copy_from_slice(b"SPRJ");
        bytes[0x10..0x17].copy_from_slice(&[0x20, 0x26, 0x07, 0x20, 0x18, 0x30, 0x45]);
        let parameters = DeviceParameterImage::from_bytes(bytes);

        assert!(ensure_flash_readback(&bytes[..256], &parameters).is_err());

        let mut flash_data = bytes[..256].to_vec();
        flash_data[0] ^= 0xff;
        assert!(ensure_flash_readback(&flash_data, &parameters).is_ok());
    }

    #[test]
    fn reports_short_readback_as_inconclusive() {
        let mut bytes = [0_u8; 0x800];
        bytes[..4].copy_from_slice(b"SPRJ");
        let parameters = DeviceParameterImage::from_bytes(bytes);

        for readback in [&bytes[..1], &bytes[..4], &[0xff; 4]] {
            let error = ensure_flash_readback(readback, &parameters)
                .expect_err("short readback cannot be classified safely");
            assert!(error.to_string().contains("required to distinguish"));
            assert!(!error.to_string().contains("instead of Flash data"));
        }

        let mut distinctive = bytes[..0x20].to_vec();
        distinctive[0] ^= 0xff;
        assert!(ensure_flash_readback(&distinctive, &parameters).is_ok());
    }

    #[test]
    fn parses_decimal_and_hex_integers() {
        assert_eq!(parse_u32("32").expect("decimal"), 32);
        assert_eq!(parse_u32("0x20").expect("hex"), 32);
        assert!(parse_u16("0x10000").is_err());
    }
}
