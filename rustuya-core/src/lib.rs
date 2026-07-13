//! `rustuya-core` — a sans-I/O, `no_std` core for the Tuya local protocol.
//!
//! Pure protocol logic only: framing, crypto, and (progressively) the Device
//! and Discovery state machines. There is **no** I/O, no timers, and no async
//! here — a driver crate (tokio / blocking-std / embassy) injects `now` and the
//! RNG, pumps bytes in, and executes what the core asks for. See `MILESTONES.md`
//! for the 0.4 clean-slate design.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod error;
pub mod command;
pub mod crypto;
pub mod device;
pub mod discovery;
pub mod frame;
pub mod json;
pub mod message;
pub mod payload;
pub mod rx;
pub mod session;
pub mod time;
pub mod version;

pub use command::CommandType;
pub use error::CoreError;
pub use time::{Duration, Instant};
pub use version::{DeviceType, Version};

/// Core-wide result type.
///
/// The core deliberately carries no `std::io::Error`; transport/I-O failures are
/// the driver's concern and enter the core only as neutral inputs.
pub type Result<T> = core::result::Result<T, CoreError>;
