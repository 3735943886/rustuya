//! Round-trip tests for `Version` and `DeviceType` parsing.

use rustuya::Version;
use rustuya::protocol::DeviceType;
use std::str::FromStr;

#[test]
fn version_roundtrip_through_str() {
    for v in [
        Version::Auto,
        Version::V3_1,
        Version::V3_2,
        Version::V3_3,
        Version::V3_4,
        Version::V3_5,
    ] {
        let parsed = Version::from_str(v.as_str()).expect("known version must parse");
        assert_eq!(parsed, v, "round-trip mismatch for {v:?}");
    }
}

#[test]
fn version_parse_invalid_returns_err() {
    assert!(Version::from_str("3.99").is_err());
    assert!(Version::from_str("nope").is_err());
}

#[test]
fn version_parse_empty_and_auto_alias_to_auto() {
    assert_eq!(Version::from_str("").unwrap(), Version::Auto);
    assert_eq!(Version::from_str("auto").unwrap(), Version::Auto);
    assert_eq!(Version::from_str("Auto").unwrap(), Version::Auto);
}

#[test]
fn version_try_from_matches_from_str() {
    use std::convert::TryFrom;
    assert_eq!(Version::try_from("3.3").unwrap(), Version::V3_3);
    assert!(Version::try_from("garbage").is_err());

    let owned = String::from("3.5");
    assert_eq!(Version::try_from(owned).unwrap(), Version::V3_5);
}

#[test]
fn device_type_roundtrip_through_str() {
    for dt in [DeviceType::Auto, DeviceType::Default, DeviceType::Device22] {
        let parsed = DeviceType::from_str(dt.as_str()).unwrap();
        assert_eq!(parsed, dt);
    }
}

#[test]
fn device_type_parse_invalid_returns_err() {
    assert!(DeviceType::from_str("device42").is_err());
}

#[test]
fn device_type_parse_is_case_insensitive() {
    assert_eq!(DeviceType::from_str("AUTO").unwrap(), DeviceType::Auto);
    assert_eq!(
        DeviceType::from_str("Default").unwrap(),
        DeviceType::Default
    );
    assert_eq!(
        DeviceType::from_str("DEVICE22").unwrap(),
        DeviceType::Device22
    );
}
