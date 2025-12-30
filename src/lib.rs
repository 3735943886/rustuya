//! # Rustuya
//!
//! A Rust implementation of the Tuya Local API.
//!
//! `rustuya` facilitates the control and monitoring of Tuya-compatible smart devices (plugs, switches, lights, gateways, etc.)
//! directly over the local network, eliminating the need for Tuya Cloud dependency.
//!
//! ## Key Features
//! - **Local LAN Control**: Direct device communication over the local network.
//! - **Asynchronous Architecture**: Built on `tokio` for modern, non-blocking applications.
//! - **Extensive Protocol Support**: Compatibility with versions 3.1, 3.2, 3.3, 3.4, and 3.5.
//! - **Automated Discovery**: Integrated UDP scanning (Active & Passive) for device identification.
//! - **Gateway Integration**: Management of sub-devices (Zigbee, Bluetooth) via Tuya Gateways.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use rustuya::Device;
//! use serde_json::json;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Initialize a device with its ID, IP, Local Key, and Protocol Version.
//!     // "Auto" can be used for IP and Version if the device is discoverable.
//!     let device = Device::new("DEVICE_ID", "DEVICE_IP", "LOCAL_KEY", "VERSION");
//!
//!     // Set DP 1 (Power) to true
//!     device.set_value(1, json!(true)).await;
//! }
//! ```

#[macro_use]
pub mod macros;
pub mod crypto;
pub mod device;
pub mod error;
pub mod manager;
pub mod protocol;
pub mod scanner;

pub use device::Device;
pub use error::TuyaError;
pub use manager::{Manager, ManagerEvent};
pub use protocol::{CommandType, Version};
pub use scanner::Scanner;
