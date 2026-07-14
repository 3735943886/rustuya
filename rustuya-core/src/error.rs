//! Core error type.
//!
//! Hand-rolled (no `thiserror`) and `no_std`-clean — in particular it carries no
//! `std::io::Error`. Kept intentionally small; variants are added as the core
//! grows (protocol framing, state machine).

use core::fmt;

/// Errors produced by the pure protocol core.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreError {
    /// AES/GCM encryption failed, or a key/IV had the wrong shape.
    EncryptFailed,
    /// Decryption or authentication failed — a bad GCM tag, invalid PKCS7
    /// padding, or a malformed length.
    DecryptFailed,
    /// Fewer bytes than the header describes — the caller must read more, or
    /// the frame is malformed.
    Truncated,
    /// Unknown frame prefix (not 55AA / 6699).
    BadHeader,
    /// A header-declared length exceeds [`MAX_PAYLOAD_LEN`](crate::frame::MAX_PAYLOAD_LEN);
    /// rejected before any allocation.
    TooLong,
    /// 55AA CRC-32 check failed.
    CrcMismatch,
    /// 55AA HMAC-SHA256 check failed.
    HmacMismatch,
    /// 6699 encrypted region is smaller than IV + tag.
    InvalidPayload,
    /// A command was submitted before the connection was ready.
    NotConnected,
}

impl CoreError {
    /// Whether this error is an **authentication/decryption failure** — a failed
    /// CRC, HMAC, or GCM tag / PKCS7 check. On the Tuya LAN protocol the usual
    /// cause is a **wrong local key or a wrong protocol version** (0.3 mapped both
    /// `CrcMismatch` and `HmacMismatch` to a single "key or version" diagnostic).
    /// The classification lives here, where the protocol semantics are; the driver
    /// turns it into a human-facing message and surfaces it.
    #[must_use]
    pub fn is_auth_failure(&self) -> bool {
        matches!(
            self,
            CoreError::CrcMismatch | CoreError::HmacMismatch | CoreError::DecryptFailed
        )
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CoreError::EncryptFailed => "encryption failed",
            CoreError::DecryptFailed => "decryption failed",
            CoreError::Truncated => "truncated frame",
            CoreError::BadHeader => "unknown frame header",
            CoreError::TooLong => "declared length exceeds maximum",
            CoreError::CrcMismatch => "CRC-32 mismatch",
            CoreError::HmacMismatch => "HMAC-SHA256 mismatch",
            CoreError::InvalidPayload => "encrypted payload too short",
            CoreError::NotConnected => "not connected",
        })
    }
}

impl core::error::Error for CoreError {}

#[cfg(test)]
mod tests {
    use super::CoreError;

    #[test]
    fn auth_failures_are_classified() {
        // The "wrong key or version" class (0.3 ERR_KEY_OR_VER).
        assert!(CoreError::CrcMismatch.is_auth_failure());
        assert!(CoreError::HmacMismatch.is_auth_failure());
        assert!(CoreError::DecryptFailed.is_auth_failure());
        // Structural/transport errors are not.
        assert!(!CoreError::Truncated.is_auth_failure());
        assert!(!CoreError::BadHeader.is_auth_failure());
        assert!(!CoreError::TooLong.is_auth_failure());
        assert!(!CoreError::NotConnected.is_auth_failure());
    }
}
