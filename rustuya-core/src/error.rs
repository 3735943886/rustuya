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
        })
    }
}

impl core::error::Error for CoreError {}
