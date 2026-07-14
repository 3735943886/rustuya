//! End-to-end **discovery** tests against the real tuyamock emulator's
//! `--discovery` beacon — the gold-standard gate the discovery decode path was
//! missing (a hand-rolled loopback packet is self-consistent; tuyamock is
//! validated against tinytuya). This is what would have caught the 4-byte
//! announcement retcode bug immediately.
//!
//! For every protocol version (and device22 where it applies) this drives the
//! whole discovery + connection stack against an independent implementation:
//!   1. `Discovery::find` resolves the mock by its periodic UDP beacon (6699 +
//!      `tinytuya.udpkey`, retcode-prefixed exactly like a real device),
//!   2. the addressless `DeviceBuilder::discover` connects to the resolved IP,
//!   3. `status` + `set_value` round-trip over the live connection.
//!
//! **Opt-in / serial.** Spawns the `tuyamock` executable (via `RUSTUYA_TUYAMOCK`
//! or `PATH`); skips with a notice if absent. All scenarios run inside **one**
//! test fn because discovery binds the fixed UDP ports 6667/7000 — parallel tests
//! would contend. Each mock uses a unique gw-id (no discovery-cache collision)
//! and a unique TCP port.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rustuya_tokio::{DeviceType, Discovery, Value, Version};

const KEY: &str = "thisisarealkey00";

fn tuyamock_bin() -> String {
    match std::env::var("RUSTUYA_TUYAMOCK") {
        Ok(p) if !p.is_empty() => p,
        _ => "tuyamock".to_string(),
    }
}

/// A spawned discovery-enabled tuyamock subprocess, killed on drop.
struct Mock {
    child: Child,
}

impl Mock {
    fn spawn(version: &str, port: u16, id: &str, dev22: bool) -> Option<Mock> {
        let mut cmd = Command::new(tuyamock_bin());
        cmd.args([
            "--version", version,
            "--port", &port.to_string(),
            "--local-key", KEY,
            "--dps", r#"{"1":true,"20":"white"}"#,
            "--gw-id", id,
            "--discovery",
            "--discovery-addr", "127.0.0.1",
        ]);
        if dev22 {
            cmd.arg("--dev22");
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        cmd.spawn().ok().map(|child| Mock { child })
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn dps_of(v: &Value) -> Value {
    v.get("dps")
        .or_else(|| v.get("data").and_then(|d| d.get("dps")))
        .cloned()
        .unwrap_or(Value::Null)
}

struct Scenario {
    wire: &'static str,
    version: Version,
    dev_type: DeviceType,
    dev22: bool,
    port: u16,
    id: &'static str,
}

#[tokio::test]
async fn discovery_connect_setvalue_matrix() {
    // Bind discovery once (shared across scenarios; unique ids avoid cache
    // collisions). If the port is unavailable, skip rather than fail.
    let disco = match Discovery::new() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("skipping discovery matrix: cannot bind discovery ports ({e})");
            return;
        }
    };

    // Full matrix: every version without device22, plus device22 where it is a
    // valid quirk (tuyamock enforces dev22 ∈ {3.2, 3.3, 3.4}, matching tinytuya's
    // recoverable set — it rejects dev22 on 3.1/3.5).
    let scenarios = [
        Scenario { wire: "3.1", version: Version::V3_1, dev_type: DeviceType::Auto, dev22: false, port: 56740, id: "discov31000000000000aa" },
        Scenario { wire: "3.2", version: Version::V3_2, dev_type: DeviceType::Auto, dev22: false, port: 56741, id: "discov32000000000000aa" },
        Scenario { wire: "3.2", version: Version::V3_2, dev_type: DeviceType::Device22, dev22: true, port: 56742, id: "discov32d22000000000aa" },
        Scenario { wire: "3.3", version: Version::V3_3, dev_type: DeviceType::Auto, dev22: false, port: 56743, id: "discov33000000000000aa" },
        Scenario { wire: "3.3", version: Version::V3_3, dev_type: DeviceType::Device22, dev22: true, port: 56744, id: "discov33d22000000000aa" },
        Scenario { wire: "3.4", version: Version::V3_4, dev_type: DeviceType::Auto, dev22: false, port: 56745, id: "discov34000000000000aa" },
        Scenario { wire: "3.4", version: Version::V3_4, dev_type: DeviceType::Device22, dev22: true, port: 56746, id: "discov34d22000000000aa" },
        Scenario { wire: "3.5", version: Version::V3_5, dev_type: DeviceType::Auto, dev22: false, port: 56747, id: "discov35000000000000aa" },
    ];

    for s in &scenarios {
        let label = if s.dev22 { format!("v{} dev22", s.wire) } else { format!("v{}", s.wire) };
        let mock = match Mock::spawn(s.wire, s.port, s.id, s.dev22) {
            Some(m) => m,
            None => {
                eprintln!("skipping discovery matrix: tuyamock not found (set RUSTUYA_TUYAMOCK)");
                return;
            }
        };

        // 1. Discovery resolves the device by its beacon — the retcode-prefixed
        //    6699 announcement the strict decode used to drop. Generous timeout:
        //    the passive beacon cadence is ~8 s.
        let info = disco
            .find(s.id, Duration::from_secs(15))
            .await
            .unwrap_or_else(|_| panic!("{label}: not discovered within 15s"));
        assert_eq!(info.version, Some(s.version), "{label}: beacon-reported version");
        assert_eq!(info.ip.to_string(), "127.0.0.1", "{label}: beacon ip");

        // 2. Addressless connect: resolve IP+version from discovery, then dial.
        //    The beacon carries no TCP port, so set it explicitly.
        let dev = rustuya_tokio::Device::builder(s.id, KEY)
            .port(s.port)
            .dev_type(s.dev_type)
            .discover(&disco, Duration::from_secs(8))
            .await
            .unwrap_or_else(|e| panic!("{label}: discover+connect failed: {e:?}"));
        dev.wait_connected(Duration::from_secs(5))
            .await
            .unwrap_or_else(|e| panic!("{label}: connect failed: {e:?}"));

        // 3. status + set_value round-trip against the live device.
        let dps = dps_of(&dev.status().await.unwrap_or_else(|e| panic!("{label}: status: {e:?}")));
        assert_eq!(dps["1"], true, "{label}: initial dp1 = {dps}");

        dev.set_value("1", false).await.unwrap_or_else(|e| panic!("{label}: set_value: {e:?}"));
        let dps = dps_of(&dev.status().await.unwrap_or_else(|e| panic!("{label}: status2: {e:?}")));
        assert_eq!(dps["1"], false, "{label}: dp1 after set_value = {dps}");

        dev.close().await;
        drop(mock); // free the TCP port before the next scenario
        eprintln!("ok: {label} — discovered, connected, set_value verified");
    }
}
