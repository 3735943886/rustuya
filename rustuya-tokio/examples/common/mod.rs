//! Shared helpers for the real-device examples — argument parsing and a
//! discovery-aware connect. Included with `#[path = "common/mod.rs"] mod common;`;
//! it has no `main`, so Cargo does not build it as a standalone example.
//!
//! Each example uses only a subset of these, hence the crate-wide dead-code allow.
#![allow(dead_code)]

use std::net::IpAddr;
use std::time::Duration;

use rustuya_tokio::{Device, Discovery, Result, TuyaError, Version};

/// Install a logger that shows the driver's `warn` output (e.g. an authentication
/// failure — wrong key/version) by default; raise with `RUST_LOG=rustuya_tokio=debug`.
pub fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
}

/// Map a `3.x` string to a [`Version`], or `None` if it isn't a version token.
pub fn parse_version(s: &str) -> Option<Version> {
    match s {
        "3.1" => Some(Version::V3_1),
        "3.2" => Some(Version::V3_2),
        "3.3" => Some(Version::V3_3),
        "3.4" => Some(Version::V3_4),
        "3.5" => Some(Version::V3_5),
        _ => None,
    }
}

/// Remove and return the first `3.x` version token, wherever it sits (a version is
/// unambiguous by shape). `None` if the args carry no version.
pub fn take_version(args: &mut Vec<String>) -> Option<Version> {
    let pos = args.iter().position(|s| parse_version(s).is_some())?;
    parse_version(&args.remove(pos))
}

/// Remove and return the first argument that parses as an IP literal, so `[ip]`
/// can sit anywhere among the trailing optionals. `None` if there is none.
pub fn take_ip(args: &mut Vec<String>) -> Option<String> {
    let pos = args.iter().position(|s| s.parse::<IpAddr>().is_ok())?;
    Some(args.remove(pos))
}

/// Parse a CLI scalar into JSON: `true`/`false` → bool, integer/float → number,
/// anything else → string. Lets a DP be set to whatever type the firmware expects.
pub fn parse_scalar(s: &str) -> serde_json::Value {
    if let Ok(b) = s.parse::<bool>() {
        return serde_json::Value::Bool(b);
    }
    if let Ok(i) = s.parse::<i64>() {
        return serde_json::Value::from(i);
    }
    if let Ok(f) = s.parse::<f64>() {
        return serde_json::Value::from(f);
    }
    serde_json::Value::String(s.to_string())
}

/// Fill a missing address/version from the discovery beacon, and cross-check an
/// explicit version against what the device announces (the 0.3-style mismatch
/// guard — a wrong version is the usual cause of a connect/flap failure). Returns
/// the address and version to actually connect with.
pub async fn resolve(
    disco: Option<&Discovery>,
    id: &str,
    ip: Option<String>,
    version: Option<Version>,
) -> Result<(String, Version)> {
    // Look the device up when a field is missing; also do a quick lookup even when
    // both are given, purely to catch a version mismatch. Best-effort — a miss is
    // only fatal if it leaves a *required* field (the address) unknown.
    let need = ip.is_none() || version.is_none();
    let found = match disco {
        Some(d) => {
            if need {
                println!("resolving {id} via discovery...");
            }
            let timeout = if need { Duration::from_secs(8) } else { Duration::from_secs(2) };
            d.find(id, timeout).await.ok()
        }
        None => None,
    };

    let ip = match ip.or_else(|| found.as_ref().map(|i| i.ip.to_string())) {
        Some(a) => a,
        None => {
            eprintln!("error: no address — pass an [ip], or run where the device is discoverable");
            return Err(TuyaError::Config("address unresolved"));
        }
    };

    let announced = found.as_ref().and_then(|i| i.version);
    let version = match (version, announced) {
        (Some(explicit), Some(ann)) if explicit != ann => {
            eprintln!(
                "error: version mismatch — you passed {explicit:?} but {id} announces {ann:?}; using {ann:?}"
            );
            ann
        }
        (Some(explicit), _) => explicit,
        (None, Some(ann)) => {
            println!("discovered version {ann:?}");
            ann
        }
        (None, None) => {
            eprintln!("warning: version unknown (not given, not discoverable) — defaulting to 3.3");
            Version::V3_3
        }
    };
    Ok((ip, version))
}

/// Resolve address+version (discovery fills any gap), then connect. Links the
/// discovery for fast reconnect rewake whenever it is available.
pub async fn connect_resolved(
    id: String,
    key: String,
    ip: Option<String>,
    version: Option<Version>,
) -> Result<Device> {
    let disco = Discovery::new().ok();
    if disco.is_none() {
        eprintln!("(discovery unavailable: ports busy — no auto-resolve or fast rewake)");
    }
    let (addr, ver) = resolve(disco.as_ref(), &id, ip, version).await?;
    println!("connecting to {addr} as {ver:?}...");
    let mut builder = Device::builder(id, key.into_bytes()).address(addr).version(ver);
    if let Some(d) = &disco {
        builder = builder.rediscover(d);
    }
    builder.connect()
}
