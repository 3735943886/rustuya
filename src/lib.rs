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
//! ## Choosing sync vs async
//!
//! Rustuya ships two parallel facades over the same internal actor:
//!
//! | When you're calling from… | Use |
//! |---|---|
//! | A non-async program (CLI, sync binary, scripting helpers) | [`sync::Device`](sync::Device), [`sync::SubDevice`](sync::SubDevice), [`sync::Scanner`](sync::Scanner) |
//! | Inside a `tokio` runtime (`#[tokio::main]`, `tokio::spawn`, axum, etc.) | [`Device`], [`DeviceBuilder`], [`Scanner`] (async) |
//!
//! Both flavours share state and reach the same backing tokio runtime — the
//! sync wrappers are just bridges. Calling the sync API from inside a tokio
//! runtime is **not** a supported configuration: the wrappers use
//! `blocking_send`, which would otherwise panic. Since v0.3.0 a runtime guard
//! turns that into a clear error, but you should pick the right facade up
//! front rather than relying on the guard.
//!
//! See the [`sync`] module docs for the full caveat.
//!
//! ## Lifecycle
//!
//! [`Device::new`] (and its `sync` mirror) **spawn a background connection
//! task immediately** on the library's internal runtime. The task stays
//! alive until the last `Device` clone is dropped or [`Device::stop`] is
//! called. Constructing many thousands of devices upfront is therefore
//! avoidable — prefer lazy construction in those scenarios.
//!
pub mod crypto;
pub mod device;
pub mod error;
pub(crate) mod macros;
pub mod protocol;
pub(crate) mod runtime;
pub mod scanner;
pub mod sync;

pub use device::{Device, DeviceBuilder};
pub use error::TuyaError;
pub use protocol::{CommandType, Version};
pub use runtime::{connect_concurrency, maximize_fd_limit, set_connect_concurrency};
pub use scanner::Scanner;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub fn version() -> &'static str {
    VERSION
}
