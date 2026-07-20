use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use flypro_core::{
    assets::{algorithm::Algorithm, configuration::Configuration, device_db::DeviceDatabase},
    protocol::{ALGORITHM_CHUNK_MAX_BYTES, AlgorithmChunk, CommandBlock},
    usb::{
        EndpointDirection, PipeValidation, UsbDeviceReport, UsbDeviceSummary,
        inspect_flypro_device, list_flypro_devices,
    },
};

#[derive(Debug, Parser)]
#[command(
    name = "flypro",
    version,
    about = "Evidence-driven diagnostics for FlyPRO programmers and assets",
    long_about = "Inspect FlyPRO assets and connected USB descriptors. USB inspection is read-only: it does not claim an interface or send endpoint transfers. Programming commands remain unavailable until captured evidence closes their protocol details."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect or batch-verify `.alg` assets.
    Algorithm {
        #[command(subcommand)]
        command: AlgorithmCommand,
    },
    /// Inspect or search an `SP20.dev` catalog.
    DeviceDb {
        #[command(subcommand)]
        command: DeviceDbCommand,
    },
    /// Inspect or batch-verify `.cfg` assets.
    Configuration {
        #[command(subcommand)]
        command: ConfigurationCommand,
    },
    /// Discover programmers or export cached USB descriptors.
    Usb {
        #[command(subcommand)]
        command: UsbCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AlgorithmCommand {
    /// Validate one algorithm and print confirmed metadata.
    Inspect { path: PathBuf },
    /// Validate every `.alg` directly inside a directory.
    VerifyDir { directory: PathBuf },
    /// Print confirmed `0x0087`, `0x0008`, and `0x008A` command blocks.
    Frames { path: PathBuf },
}

#[derive(Debug, Subcommand)]
enum DeviceDbCommand {
    /// Validate the database and print catalog statistics.
    Inspect { path: PathBuf },
    /// Find devices by part or vendor name.
    Find {
        path: PathBuf,
        query: String,
        #[arg(short, long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigurationCommand {
    /// Validate one configuration and print confirmed metadata.
    Inspect { path: PathBuf },
    /// Validate every `.cfg` directly inside a directory.
    VerifyDir { directory: PathBuf },
}

#[derive(Debug, Subcommand)]
enum UsbCommand {
    /// List connected programmers matching the confirmed VID/PID.
    List {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Open one programmer and inspect cached descriptors without claiming it.
    Inspect {
        /// Zero-based index from `usb list`.
        #[arg(long, default_value_t = 0)]
        index: usize,
        /// Emit machine-readable JSON, including raw descriptor bytes.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Algorithm { command } => run_algorithm(command),
        Command::DeviceDb { command } => run_device_db(command),
        Command::Configuration { command } => run_configuration(command),
        Command::Usb { command } => run_usb(&command),
    }
}

fn run_usb(command: &UsbCommand) -> Result<()> {
    match command {
        UsbCommand::List { json } => {
            let devices = list_flypro_devices()?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&devices)?);
            } else {
                print_usb_device_list(&devices);
            }
            Ok(())
        }
        UsbCommand::Inspect { index, json } => {
            let report = inspect_flypro_device(*index)?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_usb_device_report(*index, &report);
            }
            Ok(())
        }
    }
}

fn print_usb_device_list(devices: &[UsbDeviceSummary]) {
    if devices.is_empty() {
        println!("connected FlyPRO programmers: 0");
        return;
    }

    for (index, device) in devices.iter().enumerate() {
        let product = device.product.as_deref().unwrap_or("<unknown product>");
        let serial = device.serial_number.as_deref().unwrap_or("<no serial>");
        println!(
            "[{index}] {product} | {:04x}:{:04x} | serial={serial} | bus={} address={} ports={}",
            device.vendor_id,
            device.product_id,
            device.bus_id,
            device.device_address,
            format_ports(&device.port_chain)
        );
    }
    println!("connected FlyPRO programmers: {}", devices.len());
}

fn print_usb_device_report(index: usize, report: &UsbDeviceReport) {
    let device = &report.device;
    println!("device index: {index}");
    println!("system id: {}", device.system_id);
    println!(
        "VID:PID: {:04x}:{:04x}",
        device.vendor_id, device.product_id
    );
    println!(
        "manufacturer: {}",
        optional_text(device.manufacturer.as_deref())
    );
    println!("product: {}", optional_text(device.product.as_deref()));
    println!("serial: {}", optional_text(device.serial_number.as_deref()));
    println!("speed: {}", device.speed.as_deref().unwrap_or("unknown"));
    println!("USB version BCD: {:#06x}", device.usb_version_bcd);
    println!("device version BCD: {:#06x}", device.device_version_bcd);
    println!(
        "device class: {:#04x}/{:#04x}/{:#04x}",
        device.class, device.subclass, device.protocol
    );
    println!(
        "raw device descriptor: {}",
        hex(&report.device_descriptor_raw)
    );
    match report.active_configuration {
        Some(configuration) => println!("active configuration: {configuration}"),
        None => println!(
            "active configuration: unavailable ({})",
            report
                .active_configuration_error
                .as_deref()
                .unwrap_or("unknown error")
        ),
    }

    for configuration in &report.configurations {
        println!(
            "configuration {}: interfaces={} attributes={:#04x} max-power={}mA",
            configuration.configuration_value,
            configuration.num_interfaces,
            configuration.attributes,
            configuration.max_power_milliamps
        );
        for interface in &configuration.interfaces {
            println!(
                "  interface {} alt {}: class={:#04x}/{:#04x}/{:#04x} endpoints={}",
                interface.interface_number,
                interface.alternate_setting,
                interface.class,
                interface.subclass,
                interface.protocol,
                interface.declared_endpoint_count
            );
            for endpoint in &interface.endpoints {
                let direction = match endpoint.direction {
                    EndpointDirection::In => "IN",
                    EndpointDirection::Out => "OUT",
                };
                println!(
                    "    endpoint {:#04x} {direction} {:?}: max-packet={} interval={}",
                    endpoint.address,
                    endpoint.transfer_type,
                    endpoint.max_packet_size,
                    endpoint.interval
                );
            }
            print_pipe_validation(&interface.flypro_pipe_validation);
        }
    }
}

fn print_pipe_validation(validation: &PipeValidation) {
    if validation.complete {
        println!("    confirmed Pipe set: complete");
    } else {
        println!(
            "    confirmed Pipe set: incomplete; missing={} unexpected={}",
            format_pipe_addresses(&validation.missing),
            format_pipe_addresses(&validation.unexpected)
        );
    }
}

fn format_pipe_addresses(addresses: &[u8]) -> String {
    if addresses.is_empty() {
        return "none".to_owned();
    }
    addresses
        .iter()
        .map(|address| format!("{address:#04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_ports(ports: &[u8]) -> String {
    if ports.is_empty() {
        return "unknown".to_owned();
    }
    ports
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn optional_text(value: Option<&str>) -> &str {
    value.unwrap_or("<not reported>")
}

fn run_algorithm(command: AlgorithmCommand) -> Result<()> {
    match command {
        AlgorithmCommand::Inspect { path } => print_algorithm(&path),
        AlgorithmCommand::VerifyDir { directory } => verify_algorithm_directory(&directory),
        AlgorithmCommand::Frames { path } => print_algorithm_frames(&path),
    }
}

fn run_device_db(command: DeviceDbCommand) -> Result<()> {
    match command {
        DeviceDbCommand::Inspect { path } => print_device_database(&path),
        DeviceDbCommand::Find { path, query, limit } => find_devices(&path, &query, limit),
    }
}

fn run_configuration(command: ConfigurationCommand) -> Result<()> {
    match command {
        ConfigurationCommand::Inspect { path } => print_configuration(&path),
        ConfigurationCommand::VerifyDir { directory } => verify_configuration_directory(&directory),
    }
}

fn print_algorithm(path: &Path) -> Result<()> {
    let algorithm = load_algorithm(path)?;
    println!("path: {}", path.display());
    println!("name: {}", algorithm.name());
    println!("format version: {:#06x}", algorithm.format_version());
    println!("timestamp: {}", format_bcd_timestamp(algorithm.timestamp()));
    println!("payload bytes: {}", algorithm.payload().len());
    println!("payload CRC32: {:#010x}", algorithm.payload_crc32());
    println!("file CRC32: {:#010x}", algorithm.file_crc32());
    println!(
        "unknown header u32: {:#010x}",
        algorithm.unknown_header_u32()
    );
    for (index, name) in algorithm.region_names().iter().enumerate() {
        println!("region {index}: {name}");
    }
    Ok(())
}

fn verify_algorithm_directory(directory: &Path) -> Result<()> {
    let paths = files_with_extension(directory, "alg")?;
    let mut versions = BTreeSet::new();
    for path in &paths {
        let algorithm = load_algorithm(path)?;
        versions.insert(algorithm.format_version());
    }
    let version_list = versions
        .iter()
        .map(|version| format!("{version:#06x}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("validated algorithms: {}", paths.len());
    println!("format versions: {version_list}");
    Ok(())
}

fn print_algorithm_frames(path: &Path) -> Result<()> {
    let algorithm = load_algorithm(path)?;
    let verify = CommandBlock::verify_device_algorithm();
    println!("algorithm: {}", algorithm.name());
    for (index, offset) in (0..algorithm.payload().len())
        .step_by(ALGORITHM_CHUNK_MAX_BYTES)
        .enumerate()
    {
        let chunk = AlgorithmChunk::new(&algorithm, offset)?;
        println!(
            "chunk {index}: offset={:#06x} length={:#06x} command={}",
            chunk.offset(),
            chunk.payload().len(),
            hex(chunk.command().as_bytes())
        );
    }
    println!("verify: command={}", hex(verify.as_bytes()));
    println!(
        "parameters: length=0x0800 command={}",
        hex(CommandBlock::download_device_parameters().as_bytes())
    );
    println!("note: completion-byte semantics and parameter-image construction remain unknown");
    Ok(())
}

fn print_device_database(path: &Path) -> Result<()> {
    let database = load_device_database(path)?;
    let algorithms: BTreeSet<_> = database
        .devices()
        .iter()
        .map(|device| device.algorithm_stem().to_ascii_lowercase())
        .collect();
    let configuration_count = database
        .devices()
        .iter()
        .filter(|device| device.configuration_stem().is_some())
        .count();
    println!("path: {}", path.display());
    println!("internal name: {}", database.internal_file_name());
    println!("version: {}", database.version());
    println!("timestamp: {}", format_bcd_timestamp(database.timestamp()));
    println!("vendors: {}", database.vendors().len());
    println!("devices: {}", database.devices().len());
    println!("unique algorithm stems: {}", algorithms.len());
    println!("non-empty configuration stems: {configuration_count}");
    println!("stored CRC16: {:#06x}", database.stored_crc16());
    println!("stored sum word: {:#06x}", database.stored_sum_word());
    Ok(())
}

fn find_devices(path: &Path, query: &str, limit: usize) -> Result<()> {
    let database = load_device_database(path)?;
    let mut found = 0;
    for device in database.find_devices(query).take(limit) {
        let vendor = &database.vendors()[device.vendor_index()];
        println!(
            "[{}] {} {} | algorithm={} | cfg={} | offset={:#010x}",
            device.source_index(),
            vendor.name(),
            device.name(),
            device.algorithm_stem(),
            device.configuration_stem().unwrap_or("-"),
            device.source_offset()
        );
        found += 1;
    }
    println!("shown: {found} (limit {limit})");
    Ok(())
}

fn print_configuration(path: &Path) -> Result<()> {
    let configuration = load_configuration(path)?;
    println!("path: {}", path.display());
    println!("name: {}", configuration.name());
    println!("version: {}", configuration.version());
    println!(
        "default protection bits: {:#010x}",
        configuration.default_protection_bits()
    );
    println!("records: {}", configuration.records().len());
    println!("opaque tail bytes: {}", configuration.opaque_tail().len());
    println!("default block 0: {}", hex(configuration.default_block_0()));
    println!("default block 1: {}", hex(configuration.default_block_1()));
    Ok(())
}

fn verify_configuration_directory(directory: &Path) -> Result<()> {
    let paths = files_with_extension(directory, "cfg")?;
    let mut record_count = 0_usize;
    for path in &paths {
        record_count += load_configuration(path)?.records().len();
    }
    println!("validated configurations: {}", paths.len());
    println!("variable records: {record_count}");
    Ok(())
}

fn load_algorithm(path: &Path) -> Result<Algorithm> {
    let bytes = read(path)?;
    let stem = utf8_file_stem(path)?;
    Algorithm::parse_for_stem(&bytes, stem)
        .with_context(|| format!("invalid algorithm {}", path.display()))
}

fn load_device_database(path: &Path) -> Result<DeviceDatabase> {
    let bytes = read(path)?;
    let file_name = utf8_file_name(path)?;
    DeviceDatabase::parse_for_file_name(&bytes, file_name)
        .with_context(|| format!("invalid device database {}", path.display()))
}

fn load_configuration(path: &Path) -> Result<Configuration> {
    let bytes = read(path)?;
    let stem = utf8_file_stem(path)?;
    Configuration::parse_for_stem(&bytes, stem)
        .with_context(|| format!("invalid configuration {}", path.display()))
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn utf8_file_stem(path: &Path) -> Result<&str> {
    path.file_stem()
        .and_then(|value| value.to_str())
        .with_context(|| format!("path has no UTF-8 file stem: {}", path.display()))
}

fn utf8_file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|value| value.to_str())
        .with_context(|| format!("path has no UTF-8 file name: {}", path.display()))
}

fn files_with_extension(directory: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(directory)
        .with_context(|| format!("failed to read directory {}", directory.display()))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| {
        path.is_file()
            && path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case(extension))
    });
    paths.sort_by_key(|path| path.file_name().map(std::ffi::OsStr::to_ascii_lowercase));
    if paths.is_empty() {
        bail!(
            "no .{extension} files found directly inside {}",
            directory.display()
        );
    }
    Ok(paths)
}

fn format_bcd_timestamp(timestamp: [u8; 8]) -> String {
    let decimal = |value: u8| (value >> 4) * 10 + (value & 0x0f);
    let year = u16::from(decimal(timestamp[0])) * 100 + u16::from(decimal(timestamp[1]));
    format!(
        "{year:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        decimal(timestamp[2]),
        decimal(timestamp[3]),
        decimal(timestamp[4]),
        decimal(timestamp[5]),
        decimal(timestamp[6])
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_cli_commands() {
        let cli = Cli::try_parse_from([
            "flypro",
            "device-db",
            "find",
            "SP20.dev",
            "W25Q128",
            "--limit",
            "3",
        ])
        .expect("valid command");

        assert!(matches!(
            cli.command,
            Command::DeviceDb {
                command: DeviceDbCommand::Find { limit: 3, .. }
            }
        ));
    }

    #[test]
    fn parses_usb_descriptor_export() {
        let cli = Cli::try_parse_from(["flypro", "usb", "inspect", "--index", "2", "--json"])
            .expect("valid USB inspect command");

        assert!(matches!(
            cli.command,
            Command::Usb {
                command: UsbCommand::Inspect {
                    index: 2,
                    json: true
                }
            }
        ));
    }

    #[test]
    fn formats_pipe_addresses_for_diagnostics() {
        assert_eq!(format_pipe_addresses(&[]), "none");
        assert_eq!(format_pipe_addresses(&[0x02, 0x83]), "0x02,0x83");
    }

    #[test]
    fn formats_confirmed_bcd_timestamp() {
        assert_eq!(
            format_bcd_timestamp([0x20, 0x24, 0x05, 0x18, 0x13, 0x04, 0x30, 0]),
            "2024-05-18 13:04:30"
        );
    }
}
