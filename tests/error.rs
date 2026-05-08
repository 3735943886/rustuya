//! Tests for `TuyaError` construction, conversion, and code mapping.

use rustuya::TuyaError;
use rustuya::error::{
    ERR_CONNECT, ERR_JSON, ERR_KEY_OR_VER, ERR_OFFLINE, ERR_PAYLOAD, ERR_TIMEOUT,
};
use std::io;

#[test]
fn io_error_conversion_preserves_kind() {
    let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "boom");
    let tuya: TuyaError = io_err.into();

    assert_eq!(tuya.io_kind(), Some(io::ErrorKind::ConnectionReset));
    assert!(matches!(tuya, TuyaError::Io { .. }));
    assert_eq!(tuya.code(), ERR_CONNECT);
}

#[test]
fn io_kind_returns_none_for_non_io_variant() {
    assert_eq!(TuyaError::Timeout.io_kind(), None);
    assert_eq!(TuyaError::HmacMismatch.io_kind(), None);
}

#[test]
fn json_error_maps_to_err_json() {
    let je =
        serde_json::from_str::<serde_json::Value>("not json").expect_err("intentionally bad JSON");
    let tuya: TuyaError = je.into();
    assert!(matches!(tuya, TuyaError::Json(_)));
    assert_eq!(tuya.code(), ERR_JSON);
}

#[test]
fn from_code_roundtrip_for_known_codes() {
    for code in [
        ERR_JSON,
        ERR_CONNECT,
        ERR_TIMEOUT,
        ERR_OFFLINE,
        ERR_KEY_OR_VER,
        ERR_PAYLOAD,
    ] {
        let err = TuyaError::from_code(code);
        assert_eq!(err.code(), code, "code mismatch for {code}");
    }
}

#[test]
fn io_helpers_construct_correctly() {
    let e = TuyaError::io(io::ErrorKind::TimedOut, "deadline exceeded");
    assert_eq!(e.io_kind(), Some(io::ErrorKind::TimedOut));

    let e = TuyaError::io_other("worker died");
    assert_eq!(e.io_kind(), Some(io::ErrorKind::Other));
}
