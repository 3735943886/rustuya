//! # Rustuya
//!
//! Asynchronous Tuya Local API implementation for local control and monitoring
//! of Tuya-compatible devices without cloud dependencies.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use rustuya::Device;
//!
//! let device = Device::new("DEVICE_ID", "DEVICE_ADDRESS", "DEVICE_KEY", "DEVICE_VERSION");
//! // device.set_value(1, true); // Asynchronous call
//! ```
//!
#[macro_use]
pub mod macros;
pub mod crypto;
pub mod device;
pub mod error;
pub mod protocol;
pub mod runtime;
pub mod scanner;

pub use device::{Device, DeviceBuilder};
pub use error::TuyaError;
pub use protocol::{CommandType, Version};
pub use scanner::Scanner;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn version() -> &'static str {
    VERSION
}
