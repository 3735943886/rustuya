//! Driver-side error type.
//!
//! The pure core carries a lean [`CoreError`](rustuya_core::CoreError) with **no**
//! `std::io::Error` (design D5). The driver owns I/O, so it owns the transport
//! failures: `TuyaError` wraps both the core error and `std::io::Error`, plus the
//! driver-only conditions (request timeout, actor gone). Hand-rolled `Display` /
//! `Error` — no `thiserror` — to keep the dependency surface small.

use std::fmt;

use rustuya_core::CoreError;

/// Errors surfaced by the tokio driver.
#[derive(Debug)]
#[non_exhaustive]
pub enum TuyaError {
    /// A socket / transport failure (connect, read, write).
    Io(std::io::Error),
    /// A protocol-layer failure bubbled up from the core FSM.
    Core(CoreError),
    /// A request did not receive a response within the configured timeout.
    Timeout,
    /// The connection dropped while the request was in flight.
    Disconnected,
    /// The device actor task is gone (the [`Device`](crate::Device) was closed).
    Closed,
    /// The response payload was not valid JSON when a JSON value was expected.
    NotJson,
    /// The builder was missing a required field (address) or had an invalid one
    /// (local key not 16 bytes).
    Config(&'static str),
}

impl fmt::Display for TuyaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TuyaError::Io(e) => write!(f, "transport I/O error: {e}"),
            // Name the common cause: a CRC/HMAC/GCM failure is almost always a
            // wrong local key or protocol version (0.3's "key or version" error).
            TuyaError::Core(e) if e.is_auth_failure() => {
                write!(f, "authentication failed ({e}) — likely a wrong local key or protocol version")
            }
            TuyaError::Core(e) => write!(f, "protocol error: {e}"),
            TuyaError::Timeout => f.write_str("request timed out"),
            TuyaError::Disconnected => f.write_str("connection dropped during request"),
            TuyaError::Closed => f.write_str("device actor is closed"),
            TuyaError::NotJson => f.write_str("response payload was not valid JSON"),
            TuyaError::Config(what) => write!(f, "invalid configuration: {what}"),
        }
    }
}

impl std::error::Error for TuyaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TuyaError::Io(e) => Some(e),
            TuyaError::Core(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TuyaError {
    fn from(e: std::io::Error) -> Self {
        TuyaError::Io(e)
    }
}

impl From<CoreError> for TuyaError {
    fn from(e: CoreError) -> Self {
        TuyaError::Core(e)
    }
}

/// Driver result alias.
pub type Result<T> = std::result::Result<T, TuyaError>;
