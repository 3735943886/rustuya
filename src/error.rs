//! Error types and result definitions for the rustuya crate.
//! Includes Tuya-specific error codes and conversion from standard IO/JSON errors.

use thiserror::Error;

/// Represents all possible errors that can occur when communicating with a Tuya device.
#[derive(Error, Debug, Clone)]
pub enum TuyaError {
    /// Standard IO error (network, timeout, etc.)
    #[error("IO error: {0}")]
    Io(String),

    /// JSON serialization or deserialization error
    #[error("JSON error: {0}")]
    Json(String),

    /// Failed to decrypt a message from the device (wrong key or version)
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Failed to encrypt a message for the device
    #[error("Encryption failed")]
    EncryptionFailed,

    /// The payload received from the device was malformed or unexpected
    #[error("Invalid payload")]
    InvalidPayload,

    /// Request timed out
    #[error("Timeout waiting for device")]
    Timeout,

    /// CRC check failed for the received message
    #[error("CRC mismatch")]
    CrcMismatch,

    /// HMAC signature verification failed (v3.4+)
    #[error("HMAC mismatch")]
    HmacMismatch,

    /// TCP connection could not be established
    #[error("Socket connection failed")]
    ConnectionFailed,

    /// The message header was invalid
    #[error("Invalid header")]
    InvalidHeader,

    /// Failed to decode hex or base64 data
    #[error("Decode error: {0}")]
    DecodeError(String),

    /// Device is currently unreachable or disconnected
    #[error("Device offline")]
    Offline,

    /// Key negotiation (handshake) failed
    #[error("Handshake failed")]
    HandshakeFailed,

    /// Generic error for wrong Local Key or Protocol Version
    #[error("Check device key or version (Error 914)")]
    KeyOrVersionError,

    /// Device ID already exists in manager
    #[error("Device ID '{0}' already exists")]
    DuplicateDevice(String),

    /// Device ID not found in manager or registry
    #[error("Device ID '{0}' not found")]
    DeviceNotFound(String),
}

/// A specialized Result type for Tuya operations.
pub type Result<T> = std::result::Result<T, TuyaError>;

impl From<std::io::Error> for TuyaError {
    fn from(err: std::io::Error) -> Self {
        TuyaError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for TuyaError {
    fn from(err: serde_json::Error) -> Self {
        TuyaError::Json(err.to_string())
    }
}

impl TuyaError {
    pub fn code(&self) -> u32 {
        match self {
            TuyaError::Io(_) => ERR_CONNECT,
            TuyaError::Json(_) => ERR_JSON,
            TuyaError::DecryptionFailed => ERR_KEY_OR_VER,
            TuyaError::EncryptionFailed => ERR_KEY_OR_VER,
            TuyaError::InvalidPayload => ERR_PAYLOAD,
            TuyaError::CrcMismatch => ERR_KEY_OR_VER,
            TuyaError::HmacMismatch => ERR_KEY_OR_VER,
            TuyaError::ConnectionFailed => ERR_CONNECT,
            TuyaError::InvalidHeader => ERR_PAYLOAD,
            TuyaError::DecodeError(_) => ERR_PAYLOAD,
            TuyaError::Offline => ERR_OFFLINE,
            TuyaError::HandshakeFailed => ERR_KEY_OR_VER,
            TuyaError::KeyOrVersionError => ERR_KEY_OR_VER,
            TuyaError::DuplicateDevice(_) => ERR_DUPLICATE,
            TuyaError::DeviceNotFound(_) => ERR_JSON,
            TuyaError::Timeout => ERR_TIMEOUT,
        }
    }

    pub fn from_code(code: u32) -> Self {
        match code {
            ERR_JSON => TuyaError::Json("Generic JSON error".to_string()),
            ERR_CONNECT => TuyaError::ConnectionFailed,
            ERR_TIMEOUT => TuyaError::Timeout,
            ERR_OFFLINE => TuyaError::Offline,
            ERR_KEY_OR_VER => TuyaError::KeyOrVersionError,
            ERR_DUPLICATE => TuyaError::DuplicateDevice("Unknown ID".to_string()),
            ERR_PAYLOAD => TuyaError::InvalidPayload,
            _ => TuyaError::Io(format!("Unknown error code: {}", code)),
        }
    }
}

// TinyTuya Error Response Codes
define_error_codes! {
    ERR_SUCCESS = 0 => "Connection Successful",
    ERR_JSON = 900 => "Invalid JSON Response from Device",
    ERR_CONNECT = 901 => "Network Error: Unable to Connect",
    ERR_TIMEOUT = 902 => "Timeout Waiting for Device",
    ERR_RANGE = 903 => "Specified Value Out of Range",
    ERR_PAYLOAD = 904 => "Unexpected Payload from Device",
    ERR_OFFLINE = 905 => "Network Error: Device Unreachable",
    ERR_STATE = 906 => "Device in Unknown State",
    ERR_FUNCTION = 907 => "Function Not Supported by Device",
    ERR_DEVTYPE = 908 => "Device22 Detected: Retry Command",
    ERR_CLOUDKEY = 909 => "Missing Tuya Cloud Key and Secret",
    ERR_CLOUDRESP = 910 => "Invalid JSON Response from Cloud",
    ERR_CLOUDTOKEN = 911 => "Unable to Get Cloud Token",
    ERR_PARAMS = 912 => "Missing Function Parameters",
    ERR_CLOUD = 913 => "Error Response from Tuya Cloud",
    ERR_KEY_OR_VER = 914 => "Check device key or version",
    ERR_DUPLICATE = 915 => "Device ID already exists",
}
