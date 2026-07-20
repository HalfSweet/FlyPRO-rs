use std::{fmt::Write as _, fs, path::PathBuf};

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use flypro_core::{
    assets::embedded_algorithms::embedded_algorithm,
    operations::{EraseRequest, OperationReceipt, OperationSession},
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
        #[arg(long, value_parser = parse_usize)]
        length: usize,
        #[arg(long, default_value = "0x800", value_parser = parse_usize)]
        chunk: usize,
    },
    /// Read one region into a file.
    Read {
        #[command(flatten)]
        target: TargetArgs,
        #[arg(long, default_value = "0", value_parser = parse_u32)]
        region: u32,
        #[arg(long, value_parser = parse_usize)]
        length: usize,
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
        /// Read the optional 64-byte result used by one recovered branch.
        #[arg(long)]
        read_result: bool,
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
        /// Exact 64-byte expected configuration image.
        #[arg(long)]
        data: PathBuf,
        /// Exact 64-byte comparison mask.
        #[arg(long)]
        mask: PathBuf,
    },
    /// Write a configuration image and mask through `0x00A3`.
    ConfigWrite {
        #[command(flatten)]
        target: TargetArgs,
        /// Exact 64-byte configuration image.
        #[arg(long)]
        data: PathBuf,
        /// Exact 64-byte write mask.
        #[arg(long)]
        mask: PathBuf,
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
    #[arg(long, default_value_t = 0)]
    device_index: usize,
    /// Embedded algorithm stem, without the `.alg` suffix.
    #[arg(long)]
    algorithm: String,
    /// Exact 2048-byte `SPRJ` image matching the selected algorithm.
    #[arg(long)]
    parameters: PathBuf,
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
            read_result,
            yes,
        } => run_erase(&target, path_selector, mode, read_result, yes),
        DeviceCommand::ConfigRead { target, output } => run_config_read(&target, &output),
        DeviceCommand::ConfigVerify { target, data, mask } => {
            run_config_verify(&target, &data, &mask)
        }
        DeviceCommand::ConfigWrite {
            target,
            data,
            mask,
            yes,
        } => run_config_write(&target, &data, &mask, yes),
        DeviceCommand::Progress {
            target,
            max_records,
        } => run_progress(&target, max_records),
    }
}

fn run_blank_check(target: &TargetArgs, region: u32, length: usize, chunk: usize) -> Result<()> {
    let mut transport = prepare(target)?;
    let receipt = OperationSession::new(&mut transport, &NeverCancelled)
        .blank_check(region, length, chunk)?;
    print_receipt("blank-check", &receipt);
    Ok(())
}

fn run_read(
    target: &TargetArgs,
    region: u32,
    length: usize,
    minimum_chunk: u16,
    output: &PathBuf,
) -> Result<()> {
    let mut transport = prepare(target)?;
    let result = OperationSession::new(&mut transport, &NeverCancelled).read(
        region,
        length,
        minimum_chunk,
    )?;
    write_file(output, &result.data)?;
    print_receipt("read", &result.receipt);
    println!("wrote {} bytes to {}", result.data.len(), output.display());
    Ok(())
}

fn run_verify(target: &TargetArgs, region: u32, minimum_chunk: u16, input: &PathBuf) -> Result<()> {
    let expected = read_file(input)?;
    let mut transport = prepare(target)?;
    let receipt = OperationSession::new(&mut transport, &NeverCancelled).verify(
        region,
        &expected,
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
    let mut transport = prepare(target)?;
    let receipt = OperationSession::new(&mut transport, &NeverCancelled).program(
        region,
        &data,
        minimum_chunk,
    )?;
    print_receipt("program", &receipt);
    Ok(())
}

fn run_erase(
    target: &TargetArgs,
    path_selector: u32,
    mode: EraseModeArg,
    read_result: bool,
    confirmed: bool,
) -> Result<()> {
    require_destructive_confirmation(confirmed)?;
    let mut transport = prepare(target)?;
    let result = OperationSession::new(&mut transport, &NeverCancelled).erase(EraseRequest {
        path_selector,
        mode: mode.into(),
        read_result,
    })?;
    print_receipt("erase", &result.receipt);
    if let Some(raw) = result.raw_result {
        println!("optional result: {}", encode_hex(&raw));
    }
    Ok(())
}

fn run_config_read(target: &TargetArgs, output: &PathBuf) -> Result<()> {
    let mut transport = prepare(target)?;
    let result = OperationSession::new(&mut transport, &NeverCancelled).read_configuration()?;
    write_file(output, &result.data)?;
    print_receipt("configuration read", &result.receipt);
    println!("wrote {} bytes to {}", result.data.len(), output.display());
    Ok(())
}

fn run_config_verify(target: &TargetArgs, data: &PathBuf, mask: &PathBuf) -> Result<()> {
    let expected = read_configuration_file(data)?;
    let mask = read_configuration_file(mask)?;
    let mut transport = prepare(target)?;
    let receipt = OperationSession::new(&mut transport, &NeverCancelled)
        .verify_configuration(&expected, &mask)?;
    print_receipt("configuration verify", &receipt);
    Ok(())
}

fn run_config_write(
    target: &TargetArgs,
    data: &PathBuf,
    mask: &PathBuf,
    confirmed: bool,
) -> Result<()> {
    require_destructive_confirmation(confirmed)?;
    let data = read_configuration_file(data)?;
    let mask = read_configuration_file(mask)?;
    let mut transport = prepare(target)?;
    let receipt =
        OperationSession::new(&mut transport, &NeverCancelled).write_configuration(&data, &mask)?;
    print_receipt("configuration write", &receipt);
    Ok(())
}

fn run_progress(target: &TargetArgs, max_records: usize) -> Result<()> {
    let mut transport = prepare(target)?;
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
    require_static_opt_in(target)?;
    let asset = embedded_algorithm(&target.algorithm).with_context(|| {
        format!(
            "embedded algorithm {:?} was not found; use a stem without .alg",
            target.algorithm
        )
    })?;
    let algorithm = asset
        .parse()
        .with_context(|| format!("embedded algorithm {} is invalid", asset.file_name()))?;
    let parameter_bytes = read_file(&target.parameters)?;
    let parameters = DeviceParameterImage::try_from_sprj(&parameter_bytes)
        .with_context(|| format!("invalid SPRJ image {}", target.parameters.display()))?;
    parameters
        .validate_for_algorithm(&algorithm)
        .with_context(|| format!("SPRJ image does not match algorithm {}", algorithm.name()))?;

    let mut transport = NusbTransport::open(target.device_index)?;
    println!(
        "claimed device {} interface {} alt {}",
        target.device_index,
        transport.interface_number(),
        transport.alternate_setting()
    );
    let ready = AlgorithmSession::new().prepare(
        &mut transport,
        &StaticCompletionPolicy,
        &mut ThreadDelay,
        &NeverCancelled,
        &algorithm,
        &parameters,
    )?;
    println!(
        "algorithm {} ready (reused={}, completion={})",
        ready.identity().name(),
        ready.reused(),
        format_statuses(ready.completion_statuses())
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
            "--algorithm",
            "w25q128",
            "--parameters",
            "target.sprj",
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
    fn destructive_commands_require_confirmation_before_usb() {
        assert!(require_destructive_confirmation(false).is_err());
        assert!(require_destructive_confirmation(true).is_ok());
    }

    #[test]
    fn parses_decimal_and_hex_integers() {
        assert_eq!(parse_u32("32").expect("decimal"), 32);
        assert_eq!(parse_u32("0x20").expect("hex"), 32);
        assert!(parse_u16("0x10000").is_err());
    }
}
