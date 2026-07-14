//! End-to-end tests against the real **tuyamock** device emulator — the M1.7
//! regression gate (tuyamock is validated against the tinytuya reference client).
//!
//! Unlike `loopback.rs` (hand-rolled device bytes), this drives the whole stack
//! against an independent implementation: framing, ECB/GCM, the v3.4/v3.5
//! session-key handshake, and the device22 dialect, across every version.
//!
//! **Opt-in.** These spawn the `tuyamock` executable as a subprocess. Point the
//! `RUSTUYA_TUYAMOCK` env var at it (e.g. `/path/to/.venv/bin/tuyamock`), or have
//! `tuyamock` on `PATH`; otherwise each test **skips** with a notice rather than
//! failing. CI installs it (unpinned) and sets the var.
//!
//! Startup is race-free without any sleep: the device is built with
//! `auto_reconnect` + a short backoff, so its own dial-retry loop connects as
//! soon as the mock finishes binding — `wait_connected` is the sync edge.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rustuya_tokio::{DeviceType, Value, Version};

const KEY: &str = "thisisarealkey00"; // tuyamock's documented default key
const ID: &str = "01234567890123456789ab";

/// Locate the tuyamock binary: `RUSTUYA_TUYAMOCK` if set, else `tuyamock` on PATH.
fn tuyamock_bin() -> String {
    match std::env::var("RUSTUYA_TUYAMOCK") {
        Ok(p) if !p.is_empty() => p,
        _ => "tuyamock".to_string(),
    }
}

/// A spawned tuyamock subprocess, killed on drop.
struct Mock {
    child: Child,
    port: u16,
}

impl Mock {
    /// Spawn a mock on `port`. Returns `None` if the binary isn't available (the
    /// caller then skips the test).
    fn spawn(version: &str, port: u16, dps: &str, dev22: bool) -> Option<Mock> {
        let mut cmd = Command::new(tuyamock_bin());
        cmd.args([
            "--version", version,
            "--port", &port.to_string(),
            "--local-key", KEY,
            "--dps", dps,
            "--gw-id", ID,
        ]);
        if dev22 {
            cmd.arg("--dev22");
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        match cmd.spawn() {
            Ok(child) => Some(Mock { child, port }),
            Err(_) => None, // binary not found → skip
        }
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Extract the `dps` map from a status response, tolerating the bare
/// `{"dps":..}` and the modern `{"data":{"dps":..}}` shapes.
fn dps_of(v: &Value) -> Value {
    v.get("dps")
        .or_else(|| v.get("data").and_then(|d| d.get("dps")))
        .cloned()
        .unwrap_or(Value::Null)
}

macro_rules! skip_if_absent {
    ($mock:expr, $what:expr) => {
        match $mock {
            Some(m) => m,
            None => {
                eprintln!("skipping {}: tuyamock not found (set RUSTUYA_TUYAMOCK)", $what);
                return;
            }
        }
    };
}

/// Build a device that dials `mock` and reconnect-retries through its startup.
fn connect(version: Version, dev_type: DeviceType, port: u16) -> rustuya_tokio::Device {
    rustuya_tokio::Device::builder(ID, KEY)
        .address("127.0.0.1")
        .port(port)
        .version(version)
        .dev_type(dev_type)
        // Short backoff: the device retries until the subprocess finishes binding.
        .backoff(Duration::from_millis(20), Duration::from_millis(200), Duration::ZERO)
        .connect()
        .unwrap()
}

async fn status_roundtrip(version: Version, wire: &str, port: u16) {
    let mock = skip_if_absent!(Mock::spawn(wire, port, r#"{"1":true,"20":"white"}"#, false), wire);
    let dev = connect(version, DeviceType::Auto, mock.port);
    dev.wait_connected(Duration::from_secs(5)).await.expect("connects to the mock");

    let status = dev.status().await.expect("status round-trips");
    let dps = dps_of(&status);
    assert_eq!(dps["1"], true, "v{wire} dps.1: {status}");
    assert_eq!(dps["20"], "white", "v{wire} dps.20: {status}");

    dev.close().await;
}

#[tokio::test]
async fn status_v31() {
    status_roundtrip(Version::V3_1, "3.1", 56720).await;
}

#[tokio::test]
async fn status_v33() {
    status_roundtrip(Version::V3_3, "3.3", 56721).await;
}

#[tokio::test]
async fn status_v34_handshake() {
    status_roundtrip(Version::V3_4, "3.4", 56722).await;
}

#[tokio::test]
async fn status_v35_handshake() {
    status_roundtrip(Version::V3_5, "3.5", 56723).await;
}

#[tokio::test]
async fn set_value_mutates_live_state_v34() {
    let mock = skip_if_absent!(
        Mock::spawn("3.4", 56724, r#"{"1":true,"20":"white"}"#, false),
        "set v3.4"
    );
    let dev = connect(Version::V3_4, DeviceType::Auto, mock.port);
    dev.wait_connected(Duration::from_secs(5)).await.expect("connects");

    dev.set_value("1", false).await.expect("set_value round-trips");
    // Read it back: the mock applied the mutation to its live dps.
    let dps = dps_of(&dev.status().await.expect("status after set"));
    assert_eq!(dps["1"], false, "set_value flipped dp 1: {dps}");

    dev.close().await;
}

#[tokio::test]
async fn device22_status_v33() {
    // device22: the mock rejects DP_QUERY, so the client falls back to the
    // CONTROL_NEW status path and gets exactly the requested dp (dp 1).
    let mock = skip_if_absent!(
        Mock::spawn("3.3", 56725, r#"{"1":true,"20":"white"}"#, true),
        "device22 v3.3"
    );
    let dev = connect(Version::V3_3, DeviceType::Device22, mock.port);
    dev.wait_connected(Duration::from_secs(5)).await.expect("connects");

    let dps = dps_of(&dev.status().await.expect("device22 status"));
    assert_eq!(dps["1"], true, "device22 returns the queried dp: {dps}");

    dev.close().await;
}
