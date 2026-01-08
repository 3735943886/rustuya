//! # Rustuya
//!
//! Asynchronous Tuya Local API implementation for local control and monitoring
//! of Tuya-compatible devices without cloud dependencies.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use rustuya::sync::Device;
//!
//! let device = Device::new("DEVICE_ID", "DEVICE_KEY");
//! device.set_value(1, true);
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
pub mod sync;

pub use device::{Device, DeviceBuilder};
pub use error::TuyaError;
pub use protocol::{CommandType, Version};
pub use runtime::maximize_fd_limit;
pub use scanner::{Scanner, ScannerBuilder};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub fn version() -> &'static str {
    VERSION
}
