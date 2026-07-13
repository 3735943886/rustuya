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
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CoreError::EncryptFailed => "encryption failed",
            CoreError::DecryptFailed => "decryption failed",
        })
    }
}

impl core::error::Error for CoreError {}
