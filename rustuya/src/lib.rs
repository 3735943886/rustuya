//! Facade over the `rustuya-core`/`rustuya-*` driver crates. Pick a driver
//! via feature flag; its API surfaces under a matching module.
//!
//! ```toml
//! rustuya = { version = "0.4", features = ["tokio"] }
//! ```
//!
//! ```no_run
//! # #[cfg(feature = "tokio")]
//! use rustuya::tokio::DeviceBuilder;
//! ```

#[cfg(feature = "tokio")]
pub mod tokio {
    pub use rustuya_tokio::*;
}
