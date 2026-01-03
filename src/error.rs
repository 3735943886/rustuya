//! Error types and result definitions for the Tuya protocol.
//!
//! Defines Tuya-specific error codes and provides conversion from standard IO and JSON errors.

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum TuyaError {
    #[error("IO error: {0}")]
    Io(String),

    #[error("JSON error: {0}")]
    Json(String),

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Invalid payload")]
    InvalidPayload,

    #[error("Timeout waiting for device")]
    Timeout,

    #[error("CRC mismatch")]
    CrcMismatch,

    #[error("HMAC mismatch")]
    HmacMismatch,

    #[error("Socket connection failed")]
    ConnectionFailed,

    #[error("Invalid header")]
    InvalidHeader,

    #[error("Decode error: {0}")]
    DecodeError(String),

    #[error("Device offline")]
    Offline,

    #[error("Handshake failed")]
    HandshakeFailed,

    #[error("Check device key or version (Error 914)")]
    KeyOrVersionError,

    #[error("Device ID '{0}' already exists")]
    DuplicateDevice(String),

    #[error("Device ID '{0}' not found")]
    DeviceNotFound(String),
}

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
