//! Cross-platform USB discovery and descriptor inspection.
//!
//! This module performs no endpoint transfers. It uses the native backends
//! selected by `nusb`: `WinUSB` on Windows, `IOKit` on macOS, and `usbfs` on Linux.

use std::collections::BTreeSet;

use nusb::{DeviceInfo, MaybeFuture};
use serde::Serialize;
use thiserror::Error;

pub const FLYPRO_VENDOR_ID: u16 = 0x5346;
pub const FLYPRO_PRODUCT_ID: u16 = 0x5109;
pub const REQUIRED_PIPE_ADDRESSES: [u8; 6] = [0x02, 0x03, 0x82, 0x83, 0x84, 0x85];

/// Information available without opening a matching programmer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbDeviceSummary {
    pub system_id: String,
    pub bus_id: String,
    pub device_address: u8,
    pub port_chain: Vec<u8>,
    pub vendor_id: u16,
    pub product_id: u16,
    pub usb_version_bcd: u16,
    pub device_version_bcd: u16,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub speed: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub interfaces: Vec<UsbInterfaceSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbInterfaceSummary {
    pub interface_number: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub interface_string: Option<String>,
}

/// Full cached descriptor report obtained after opening the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbDeviceReport {
    pub device: UsbDeviceSummary,
    pub device_descriptor_raw: Vec<u8>,
    pub active_configuration: Option<u8>,
    pub active_configuration_error: Option<String>,
    pub configurations: Vec<UsbConfigurationReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbConfigurationReport {
    pub configuration_value: u8,
    pub num_interfaces: u8,
    pub attributes: u8,
    pub max_power_milliamps: u16,
    pub raw_descriptor: Vec<u8>,
    pub interfaces: Vec<UsbInterfaceReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbInterfaceReport {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub declared_endpoint_count: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub endpoints: Vec<UsbEndpointReport>,
    pub flypro_pipe_validation: PipeValidation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbEndpointReport {
    pub address: u8,
    pub direction: EndpointDirection,
    pub transfer_type: EndpointTransferType,
    pub attributes: u8,
    pub max_packet_size: usize,
    pub max_packet_size_raw: u16,
    pub interval: u8,
    pub raw_descriptor: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EndpointDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndpointTransferType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

/// Comparison of one interface/alternate setting against all six statically
/// observed SP10/SP20 pipe addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PipeValidation {
    pub complete: bool,
    pub present: Vec<u8>,
    pub missing: Vec<u8>,
    pub unexpected: Vec<u8>,
}

/// Lists connected devices matching the confirmed SP10/SP20 VID/PID.
///
/// # Errors
///
/// Returns [`UsbDiscoveryError::Enumerate`] if the platform USB subsystem
/// cannot be queried.
pub fn list_flypro_devices() -> Result<Vec<UsbDeviceSummary>, UsbDiscoveryError> {
    Ok(matching_device_infos()?
        .iter()
        .map(summarize_device)
        .collect())
}

/// Opens one matching device and exports cached descriptors without claiming
/// an interface or submitting transfers.
///
/// # Errors
///
/// Returns [`UsbDiscoveryError`] if enumeration, selection, or open fails.
pub fn inspect_flypro_device(index: usize) -> Result<UsbDeviceReport, UsbDiscoveryError> {
    let devices = matching_device_infos()?;
    let info = devices.get(index).ok_or(UsbDiscoveryError::DeviceIndex {
        requested: index,
        available: devices.len(),
    })?;
    let device = info.open().wait().map_err(UsbDiscoveryError::Open)?;
    let active = device.active_configuration();
    let (active_configuration, active_configuration_error) = match active {
        Ok(configuration) => (Some(configuration.configuration_value()), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let configurations = device
        .configurations()
        .map(|configuration| {
            let interfaces = configuration
                .interface_alt_settings()
                .map(|interface| {
                    let endpoints: Vec<_> = interface
                        .endpoints()
                        .map(|endpoint| UsbEndpointReport {
                            address: endpoint.address(),
                            direction: if endpoint.address() & 0x80 == 0 {
                                EndpointDirection::Out
                            } else {
                                EndpointDirection::In
                            },
                            transfer_type: match endpoint.transfer_type() {
                                nusb::descriptors::TransferType::Control => {
                                    EndpointTransferType::Control
                                }
                                nusb::descriptors::TransferType::Isochronous => {
                                    EndpointTransferType::Isochronous
                                }
                                nusb::descriptors::TransferType::Bulk => EndpointTransferType::Bulk,
                                nusb::descriptors::TransferType::Interrupt => {
                                    EndpointTransferType::Interrupt
                                }
                            },
                            attributes: endpoint.attributes(),
                            max_packet_size: endpoint.max_packet_size(),
                            max_packet_size_raw: endpoint.max_packet_size_raw(),
                            interval: endpoint.interval(),
                            raw_descriptor: endpoint.as_bytes().to_vec(),
                        })
                        .collect();
                    let pipe_validation =
                        validate_pipe_addresses(endpoints.iter().map(|endpoint| endpoint.address));
                    UsbInterfaceReport {
                        interface_number: interface.interface_number(),
                        alternate_setting: interface.alternate_setting(),
                        declared_endpoint_count: interface.num_endpoints(),
                        class: interface.class(),
                        subclass: interface.subclass(),
                        protocol: interface.protocol(),
                        endpoints,
                        flypro_pipe_validation: pipe_validation,
                    }
                })
                .collect();
            UsbConfigurationReport {
                configuration_value: configuration.configuration_value(),
                num_interfaces: configuration.num_interfaces(),
                attributes: configuration.attributes(),
                max_power_milliamps: u16::from(configuration.max_power()) * 2,
                raw_descriptor: configuration.as_bytes().to_vec(),
                interfaces,
            }
        })
        .collect();
    Ok(UsbDeviceReport {
        device: summarize_device(info),
        device_descriptor_raw: device.device_descriptor().as_bytes().to_vec(),
        active_configuration,
        active_configuration_error,
        configurations,
    })
}

#[must_use]
pub fn validate_pipe_addresses(addresses: impl IntoIterator<Item = u8>) -> PipeValidation {
    let expected: BTreeSet<_> = REQUIRED_PIPE_ADDRESSES.into_iter().collect();
    let actual: BTreeSet<_> = addresses.into_iter().collect();
    let present = actual.intersection(&expected).copied().collect();
    let missing: Vec<_> = expected.difference(&actual).copied().collect();
    let unexpected = actual.difference(&expected).copied().collect();
    PipeValidation {
        complete: missing.is_empty(),
        present,
        missing,
        unexpected,
    }
}

pub(crate) fn matching_device_infos() -> Result<Vec<DeviceInfo>, UsbDiscoveryError> {
    Ok(nusb::list_devices()
        .wait()
        .map_err(UsbDiscoveryError::Enumerate)?
        .filter(|device| {
            device.vendor_id() == FLYPRO_VENDOR_ID && device.product_id() == FLYPRO_PRODUCT_ID
        })
        .collect())
}

fn summarize_device(info: &DeviceInfo) -> UsbDeviceSummary {
    UsbDeviceSummary {
        system_id: format!("{:?}", info.id()),
        bus_id: info.bus_id().to_owned(),
        device_address: info.device_address(),
        port_chain: info.port_chain().to_vec(),
        vendor_id: info.vendor_id(),
        product_id: info.product_id(),
        usb_version_bcd: info.usb_version(),
        device_version_bcd: info.device_version(),
        class: info.class(),
        subclass: info.subclass(),
        protocol: info.protocol(),
        speed: info.speed().map(|speed| format!("{speed:?}")),
        manufacturer: info.manufacturer_string().map(str::to_owned),
        product: info.product_string().map(str::to_owned),
        serial_number: info.serial_number().map(str::to_owned),
        interfaces: info
            .interfaces()
            .map(|interface| UsbInterfaceSummary {
                interface_number: interface.interface_number(),
                class: interface.class(),
                subclass: interface.subclass(),
                protocol: interface.protocol(),
                interface_string: interface.interface_string().map(str::to_owned),
            })
            .collect(),
    }
}

#[derive(Debug, Error)]
pub enum UsbDiscoveryError {
    #[error("failed to enumerate USB devices: {0}")]
    Enumerate(#[source] nusb::Error),
    #[error("SP10/SP20 device index {requested} does not exist; {available} device(s) available")]
    DeviceIndex { requested: usize, available: usize },
    #[error("failed to open SP10/SP20 USB device: {0}")]
    Open(#[source] nusb::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_confirmed_pipe_set() {
        let validation = validate_pipe_addresses(REQUIRED_PIPE_ADDRESSES);

        assert!(validation.complete);
        assert_eq!(validation.present, REQUIRED_PIPE_ADDRESSES);
        assert!(validation.missing.is_empty());
        assert!(validation.unexpected.is_empty());
    }

    #[test]
    fn reports_missing_and_unexpected_pipes_without_guessing() {
        let validation = validate_pipe_addresses([0x02, 0x03, 0x82, 0x86]);

        assert!(!validation.complete);
        assert_eq!(validation.present, vec![0x02, 0x03, 0x82]);
        assert_eq!(validation.missing, vec![0x83, 0x84, 0x85]);
        assert_eq!(validation.unexpected, vec![0x86]);
    }
}
