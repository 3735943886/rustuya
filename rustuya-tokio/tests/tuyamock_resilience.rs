//! Adversarial / resilience E2E against tuyamock's fault-injection modes.
//!
//! `tuyamock.rs` proves the happy path; this proves the driver survives a
//! misbehaving device — the properties a real fleet actually stresses:
//!   * a **slow** device (`--response-delay`) still completes within the timeout,
//!   * our **heartbeat keeps a connection alive** against a device that drops idle
//!     links (`--idle-timeout`) — the keepalive isn't cosmetic,
//!   * a device that **goes silent** (`--go-dark-after`) is detected by idle-
//!     liveness and **recovered** by auto-reconnect once the outage clears
//!     (`--outages`),
//!   * a device that **stalls in the handshake** (`--go-dark-after 0` on v3.4) is
//!     timed out and recovered,
//!   * **misbehaving response seqnos** (`--seqno-mode`) are a non-issue — the
//!     fire-and-forget model reads replies off the listener bus and has no seqno
//!     dependency to corrupt.
//!
//! **Opt-in.** Spawns the `tuyamock` executable (`RUSTUYA_TUYAMOCK` or `PATH`);
//! skips with a notice if absent. Each test uses its own TCP port so they run
//! concurrently. Ports sit **below** Linux's ephemeral range (32768-60999): inside
//! it, any outgoing connection can be handed the mock's port first, and the mock
//! then dies on `Address already in use` before the device ever sees it. Timing waits here are genuine temporal assertions (does the link
//! survive past the device's idle window?), not sleeps papering over a race.

mod common;

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rustuya_tokio::{Device, DeviceBuilder, Value, Version};

const KEY: &str = "thisisarealkey00";
const ID: &str = "01234567890123456789ab";
const DPS: &str = r#"{"1":true,"20":"white"}"#;

fn tuyamock_bin() -> String {
    match std::env::var("RUSTUYA_TUYAMOCK") {
        Ok(p) if !p.is_empty() => p,
        _ => "tuyamock".to_string(),
    }
}

/// A spawned tuyamock subprocess, killed on drop. `extra` carries the fault flags.
struct Mock {
    child: Child,
    /// The mock's stderr, kept so a failure can say *why* the mock is unreachable
    /// (a port already taken, a bad flag) instead of a bare connect timeout.
    log: std::path::PathBuf,
}

impl Mock {
    fn spawn(version: &str, port: u16, extra: &[&str]) -> Option<Mock> {
        let mut cmd = Command::new(tuyamock_bin());
        cmd.args([
            "--version",
            version,
            "--port",
            &port.to_string(),
            "--local-key",
            KEY,
            "--dps",
            DPS,
            "--gw-id",
            ID,
        ]);
        cmd.args(extra);
        let log = std::env::temp_dir().join(format!(
            "rustuya-tuyamock-{}-{port}.log",
            std::process::id()
        ));
        let stderr = std::fs::File::create(&log)
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());
        cmd.stdout(Stdio::null()).stderr(stderr);
        cmd.spawn().ok().map(|child| Mock { child, log })
    }

    /// Whether the mock is still running, and what it printed to stderr — for a
    /// failure message.
    fn diagnose(&mut self) -> String {
        let state = match self.child.try_wait() {
            Ok(None) => "still running".to_string(),
            Ok(Some(status)) => format!("exited early ({status})"),
            Err(e) => format!("state unknown ({e})"),
        };
        let stderr = std::fs::read_to_string(&self.log).unwrap_or_default();
        format!("mock {state}; stderr: {:?}", stderr.trim())
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.log);
    }
}

macro_rules! skip_if_absent {
    ($mock:expr, $what:expr) => {
        match $mock {
            Some(m) => m,
            None => {
                eprintln!(
                    "skipping {}: tuyamock not found (set RUSTUYA_TUYAMOCK)",
                    $what
                );
                return;
            }
        }
    };
}

fn dps_of(v: &Value) -> Value {
    v.get("dps")
        .or_else(|| v.get("data").and_then(|d| d.get("dps")))
        .cloned()
        .unwrap_or(Value::Null)
}

/// Wait until `port` accepts TCP (the mock finished binding), so a device built
/// with `auto_reconnect(false)` connects on its first dial instead of giving up.
/// Polls a real connect — deterministic readiness, not a fixed sleep.
async fn wait_ready(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A device that dials `port` and reconnect-retries through the mock's startup.
fn builder(version: Version, port: u16) -> DeviceBuilder {
    Device::builder(ID, KEY)
        .address("127.0.0.1")
        .port(port)
        .version(version)
        // Short backoff: retry until the subprocess binds / recovers.
        .backoff(
            Duration::from_millis(20),
            Duration::from_millis(200),
            Duration::ZERO,
        )
}

#[tokio::test]
async fn slow_device_responds_within_timeout() {
    // A 1s-per-response device must still round-trip under a 5s request timeout.
    let mock = skip_if_absent!(
        Mock::spawn("3.3", 26760, &["--response-delay", "1"]),
        "slow device"
    );
    let dev = builder(Version::V3_3, 26760)
        .send_timeout(Duration::from_secs(5))
        .connect()
        .unwrap();
    dev.wait_connected(Duration::from_secs(5))
        .await
        .expect("connects");
    // Subscribe, fire, and wait out the 1s device delay for the reply on the bus.
    let mut ev = dev.listener();
    dev.query().await.expect("query fires");
    let dps = dps_of(
        &common::recv_dps(&mut ev, Duration::from_secs(5))
            .await
            .expect("slow status still completes"),
    );
    assert_eq!(dps["1"], true, "slow device dps: {dps}");
    let _ = mock;
    dev.close().await;
}

#[tokio::test]
async fn heartbeat_survives_device_idle_drop() {
    // The device drops any link idle for 2s; our sub-2s heartbeat must keep it
    // open. auto_reconnect(false) makes survival unambiguous: if the keepalive
    // failed, the drop would be terminal and is_connected would go false.
    let mock = skip_if_absent!(
        Mock::spawn("3.3", 26761, &["--idle-timeout", "2"]),
        "idle drop"
    );
    // auto_reconnect(false) makes survival unambiguous (a drop would be terminal),
    // but then the first dial must land — so wait for the mock to bind first.
    wait_ready(26761).await;
    let dev = builder(Version::V3_3, 26761)
        .heartbeat(Some(Duration::from_millis(500)))
        .idle_timeout(None)
        .auto_reconnect(false)
        .connect()
        .unwrap();
    dev.wait_connected(Duration::from_secs(5))
        .await
        .expect("connects");

    // Past the device's 2s idle window: only a working keepalive holds it open.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        dev.is_connected(),
        "heartbeat kept the connection alive past the device's idle-drop"
    );
    let _ = mock;
    dev.close().await;
}

#[tokio::test]
async fn recovers_after_device_goes_dark() {
    // The device answers once, then goes silent (one bounded outage). Idle-liveness
    // must detect the silence and auto-reconnect must recover once the outage
    // clears — the P5 silent-drop path end to end.
    let mock = skip_if_absent!(
        Mock::spawn("3.3", 26762, &["--go-dark-after", "1", "--outages", "1"]),
        "go dark"
    );
    let dev = builder(Version::V3_3, 26762)
        .idle_timeout(Some(Duration::from_millis(800))) // detect the silent device fast
        .heartbeat(None)
        .send_timeout(Duration::from_secs(3))
        .connect()
        .unwrap();
    dev.wait_connected(Duration::from_secs(5))
        .await
        .expect("connects");
    assert_eq!(dps_of(&common::query_dps(&dev).await)["1"], true);

    // The connection is now dark. Retry until a query actually gets a reply again —
    // proving recovery, not just that the fire queued. A reply only comes back after
    // idle-liveness tears the dead link down and a fresh connection (outage cleared)
    // serves it; a bare `query().is_ok()` would falsely pass while still dark.
    let mut ev = dev.listener();
    let mut recovered = false;
    for _ in 0..15 {
        if dev.query().await.is_ok()
            && common::recv_dps(&mut ev, Duration::from_millis(500))
                .await
                .is_some()
        {
            recovered = true;
            break;
        }
    }
    assert!(
        recovered,
        "recovered via reconnect after the device went dark"
    );
    let _ = mock;
    dev.close().await;
}

#[tokio::test]
async fn recovers_after_handshake_stall() {
    // v3.4 device that goes dark from connect (before the handshake completes) for
    // one outage: our handshake timeout must fire and auto-reconnect must recover.
    let mock = skip_if_absent!(
        Mock::spawn("3.4", 26763, &["--go-dark-after", "0", "--outages", "1"]),
        "handshake stall"
    );
    let dev = builder(Version::V3_4, 26763)
        .handshake_timeout(Some(Duration::from_millis(800)))
        .send_timeout(Duration::from_secs(4))
        .connect()
        .unwrap();

    // Recovery = a query that actually gets a reply back (see the go-dark test).
    let mut ev = dev.listener();
    let mut recovered = false;
    for _ in 0..15 {
        if dev.query().await.is_ok()
            && common::recv_dps(&mut ev, Duration::from_millis(500))
                .await
                .is_some()
        {
            recovered = true;
            break;
        }
    }
    assert!(recovered, "recovered after a handshake-stage outage");
    let _ = mock;
    dev.close().await;
}

#[tokio::test]
async fn misbehaving_seqno_does_not_break_anything() {
    // The Tuya LAN protocol has no request/response token; the fire-and-forget
    // model reads replies off the listener bus and never inspects response seqnos,
    // so a device that stamps them wrongly must not perturb anything.
    for (i, mode) in ["zero", "global", "echo"].iter().enumerate() {
        let port = 26770 + i as u16;
        let mut mock = skip_if_absent!(
            Mock::spawn("3.4", port, &["--seqno-mode", mode]),
            format!("seqno {mode}")
        );
        let dev = builder(Version::V3_4, port).connect().unwrap();
        if let Err(e) = dev.wait_connected(Duration::from_secs(5)).await {
            panic!("seqno-mode {mode}: connects: {e}; {}", mock.diagnose());
        }

        assert_eq!(
            dps_of(&common::query_dps(&dev).await)["1"],
            true,
            "seqno-mode {mode}: initial status"
        );
        dev.set_value("1", false).await.expect("set_value");
        assert_eq!(
            dps_of(&common::query_dps(&dev).await)["1"],
            false,
            "seqno-mode {mode}: after set_value"
        );
        let _ = mock;
        dev.close().await;
    }
}
