//! Real-device test bench for the tokio driver.
//!
//! Everything else in the test suite runs against a *model* of Tuya — `tuyamock`
//! (an independent mock), loopback sockets, and `fleet_scale` (300 simulated
//! devices). Those gate the protocol logic, but a mock is still a model: it can't
//! prove the driver talks to **real firmware**, and it can't reproduce the timing
//! and quirks of a device physically powering off and on. This example is the
//! manual bench for that last mile — it can't live in CI (it needs hardware on
//! your LAN), so you drive it by hand.
//!
//! ## What each mode validates (and why a mock can't)
//!
//! | mode      | exercises                                    | mock blind spot it covers |
//! |-----------|----------------------------------------------|---------------------------|
//! | `control` | v3.x handshake + GCM crypto + framing        | real firmware session negotiation, real DPS payloads |
//! | `monitor` | connection liveness + **reconnect** + pushes | real power-cycle offline→online, real backoff/rewake |
//! | `scan`    | passive receive + one active probe round     | real announce cadence/format, real probe replies |
//! | `find`    | on-demand active probe resolves one id        | a device that only answers active probes (never self-announces) |
//! | `sniff`   | raw UDP hex dump (no decode)                  | the exact on-wire announcement bytes |
//!
//! The highest-value mode is **`monitor`**: the whole 0.4 discovery redesign
//! (registry routing, on-demand active, Seen/Found, backoff-cancelling rewake) has
//! so far only been checked against loopback simulations. Only a real device,
//! physically power-cycled, exercises the offline→online reconnect for real.
//!
//! ## Address / version are optional — discovery fills the gaps
//!
//! `control` and `monitor` take `id` and `key`; the **`[ip]`** and **`[version]`**
//! are optional trailing tokens. Whatever you omit is resolved from the LAN
//! discovery beacon (like 0.3's addressless `Device`). If you pass a `[version]`
//! that **contradicts** what the device announces, that mismatch is reported as an
//! error and the announced version is used (a wrong version is the usual cause of
//! a connect/flap failure).
//!
//! ## Usage
//!
//! ```text
//! # read status (ip+version auto-resolved via discovery):
//! cargo run --example real_device -- control <id> <key>
//! # ...or pin them, and optionally set one DP:
//! cargo run --example real_device -- control <id> <key> [dp value] [192.168.1.50] [3.4]
//!
//! # watch connection state + live pushes; power-cycle the device to test reconnect:
//! cargo run --example real_device -- monitor <id> <key> [192.168.1.50] [3.4]
//!
//! # enumerate every Tuya device on the LAN (no device args needed):
//! cargo run --example real_device -- scan [seconds]
//!
//! # resolve one device id by active probe:
//! cargo run --example real_device -- find <id> [seconds]
//!
//! # dump raw discovery datagrams as hex (diagnostic):
//! cargo run --example real_device -- sniff [seconds]
//! ```
//!
//! `[version]` is `3.1`/`3.2`/`3.3`/`3.4`/`3.5`; `[ip]` is any IPv4 literal — both
//! may appear in any trailing position (they're identified by shape). To see the
//! driver's internal logs (probe sends, route pruning, listener lag), set
//! `RUST_LOG`:
//!
//! ```text
//! RUST_LOG=rustuya_tokio=debug cargo run --example real_device -- monitor <id> <key>
//! ```
//!
//! **Safety:** `control`'s optional `dp value` writes to your device. Only pass a
//! DP you know is safe to toggle (e.g. a switch). Without it, `control` is
//! read-only (`status` query).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use rustuya_tokio::{Device, Discovery, Result, TuyaError, Version};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<()> {
    // Show the driver's `warn` logs by default (e.g. an authentication failure —
    // wrong key/version); raise with RUST_LOG=rustuya_tokio=debug for the rest.
    // Example-only convenience — the library never installs a logger.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]).to_vec();

    match cmd {
        "control" => control(rest).await,
        "monitor" => monitor(rest).await,
        "scan" => scan(rest).await,
        "find" => find(rest).await,
        "sniff" => sniff(rest).await,
        _ => {
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    eprintln!(
        "\
usage: real_device <mode> ...
  control <id> <key> [dp value] [ip] [version]   read status (and optionally set one DP)
  monitor <id> <key> [ip] [version]              watch connection + pushes (power-cycle to test reconnect)
  scan [seconds]                                 list every Tuya device on the LAN
  find <id> [seconds]                            resolve one device id by active probe
  sniff [seconds]                                dump raw discovery datagrams as hex (diagnostic)
[ip] and [version] (3.1/3.2/3.3/3.4/3.5) are optional and auto-resolved via discovery
when omitted; set RUST_LOG=rustuya_tokio=debug for driver logs."
    );
}

/// Map a `3.x` string to a [`Version`], or `None` if it isn't a version token.
fn parse_version(s: &str) -> Option<Version> {
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
fn take_version(args: &mut Vec<String>) -> Option<Version> {
    let pos = args.iter().position(|s| parse_version(s).is_some())?;
    parse_version(&args.remove(pos))
}

/// Remove and return the first argument that parses as an IPv4/IPv6 literal, so
/// `[ip]` can sit anywhere among the trailing optionals. `None` if there is none.
fn take_ip(args: &mut Vec<String>) -> Option<String> {
    let pos = args.iter().position(|s| s.parse::<IpAddr>().is_ok())?;
    Some(args.remove(pos))
}

/// Parse a CLI scalar into JSON: `true`/`false` → bool, an integer → number, a
/// float → number, anything else → string. Lets `control ... dp value` set a DP of
/// whatever type the firmware expects without a typed flag.
fn parse_scalar(s: &str) -> serde_json::Value {
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
async fn resolve(
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
async fn connect_resolved(
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

/// `control <id> <key> [dp value] [ip] [version]` — the ★★ handshake/crypto path.
///
/// Connecting is where the real work a mock can't fully vouch for happens: the
/// v3.4/v3.5 session-key negotiation and GCM crypto against actual firmware, then
/// a real `DpQuery` decode. If `dp value` is supplied, it also issues a real
/// `Control` write and reads the state back.
async fn control(mut args: Vec<String>) -> Result<()> {
    let version = take_version(&mut args);
    let ip = take_ip(&mut args);
    let (id, key) = match (args.first(), args.get(1)) {
        (Some(i), Some(k)) => (i.clone(), k.clone()),
        _ => {
            usage();
            std::process::exit(2);
        }
    };
    // After id/key, a remaining `dp value` pair means "also set this DP".
    let set = args.get(2).zip(args.get(3)).map(|(dp, v)| (dp.clone(), v.clone()));

    let dev = connect_resolved(id, key, ip, version).await?;
    // `status()` waits internally, but wait explicitly so a handshake failure
    // surfaces here as a clear Timeout rather than mid-query.
    dev.wait_connected(Duration::from_secs(10)).await?;
    println!("connected. status: {}", dev.status().await?);

    if let Some((dp, raw)) = set {
        let value = parse_scalar(&raw);
        println!("setting DP {dp} = {value}");
        let resp = dev.set_value(&dp, value).await?;
        println!("set response: {resp}");
        println!("status after: {}", dev.status().await?);
    }

    dev.close().await;
    Ok(())
}

/// `monitor <id> <key> [ip] [version]` — the ★★★ reconnect path.
///
/// Connects, then runs two observers concurrently until Ctrl-C:
///   1. a connection-state watch that prints every UP/DOWN transition, and
///   2. the lossless push [`Device::listener`] stream.
///
/// **The test:** while this runs, physically power the device off and back on. You
/// should see `DOWN` then `UP` again — the driver reconnecting for real. The linked
/// [`Discovery`] (via [`connect_resolved`]) lets the device's boot re-announcement
/// cancel the reconnect backoff and redial *immediately* instead of waiting it out.
async fn monitor(mut args: Vec<String>) -> Result<()> {
    let version = take_version(&mut args);
    let ip = take_ip(&mut args);
    let (id, key) = match (args.first(), args.get(1)) {
        (Some(i), Some(k)) => (i.clone(), k.clone()),
        _ => {
            usage();
            std::process::exit(2);
        }
    };

    let dev = connect_resolved(id, key, ip, version).await?;

    // Surface a clear connect failure (e.g. wrong key/version) up front instead of
    // silently flapping. A plain timeout is fine — the device may just be offline,
    // and monitoring its eventual reconnect is the whole point.
    match dev.wait_connected(Duration::from_secs(12)).await {
        Ok(()) => {}
        Err(TuyaError::Timeout) => println!("(not connected yet — will keep watching for it)"),
        Err(e) => return Err(e),
    }

    println!("monitoring; Ctrl-C to stop.");
    println!("=> power-cycle the device to watch it reconnect.");
    println!("=> heartbeat-ack proves liveness; status-push arrives only when the");
    println!("   device's state changes (button / another app / sensor).");

    let mut listener = dev.listener();
    // Poll the connection flag to render transitions to the console. This is a
    // *display* poll, not a correctness gate — the driver's own watch channel is
    // the authoritative signal; here we only sample it to print UP/DOWN edges.
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    let mut last = dev.is_connected();
    println!("[conn] {}", if last { "UP" } else { "connecting..." });

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let now = dev.is_connected();
                if now != last {
                    println!("[conn] {}", if now { "UP" } else { "DOWN" });
                    last = now;
                }
            }
            msg = listener.next() => match msg {
                Some(m) => {
                    // Label by command so a heartbeat reply isn't mistaken for a
                    // device push. Unsolicited STATUS (0x08) only arrives when the
                    // device's state actually changes (button, another app, a
                    // sensor) — an idle device pushes nothing but heartbeat acks.
                    let kind = match m.cmd {
                        0x09 => "heartbeat-ack",
                        0x08 => "status-push",
                        _ => "message",
                    };
                    println!(
                        "[{kind}] cmd={:#x} payload={}",
                        m.cmd,
                        String::from_utf8_lossy(&m.payload)
                    );
                }
                None => {
                    println!("device stopped.");
                    break;
                }
            }
        }
    }
    Ok(())
}

/// `scan [seconds]` — the ★ LAN enumerate. Needs no device args.
///
/// Binds the well-known discovery ports, fires **one** on-demand active probe
/// round, and collects every distinct device that announces (passively or in reply
/// to the probe) during the window. This is the standalone "what Tuya devices are
/// on my network" tool — no [`Device`] involved.
async fn scan(args: Vec<String>) -> Result<()> {
    let secs: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(5);
    let disco = Discovery::new()?;

    println!("scanning {secs}s (passive receive + one active probe round)...");
    let found = disco.scan(Duration::from_secs(secs)).await;

    if found.is_empty() {
        println!("no devices found — are you on the same L2 broadcast domain as them?");
    } else {
        println!("{} device(s):", found.len());
        for d in &found {
            println!(
                "- id={} ip={} version={:?} product_key={:?}",
                d.id, d.ip, d.version, d.product_key
            );
        }
    }
    disco.close().await;
    Ok(())
}

/// `find <id> [seconds]` — the ★ targeted resolve.
///
/// Fires one on-demand active probe and waits up to `seconds` for that specific id
/// to answer. This is the mode that exposes a Tuya firmware quirk a mock can't: a
/// device that **never self-announces** and only replies when actively probed —
/// the reason active discovery is mandatory, not optional.
async fn find(args: Vec<String>) -> Result<()> {
    let id = match args.first() {
        Some(id) => id.clone(),
        None => {
            usage();
            std::process::exit(2);
        }
    };
    let secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    let disco = Discovery::new()?;

    println!("resolving {id} (on-demand active probe, up to {secs}s)...");
    match disco.find(&id, Duration::from_secs(secs)).await {
        Ok(info) => println!(
            "found: ip={} version={:?} product_key={:?}",
            info.ip, info.version, info.product_key
        ),
        Err(TuyaError::Timeout) => println!("not found within {secs}s"),
        Err(e) => return Err(e),
    }
    disco.close().await;
    Ok(())
}

/// `sniff [seconds]` — raw diagnostic, no parsing by the driver.
///
/// Binds the discovery ports directly and hex-dumps every UDP datagram that
/// arrives, so we can see (a) whether announcements are even reaching this host
/// (a socket/network question, separate from decode), and (b) their exact
/// on-wire bytes. Paste the hex back to turn a real announcement into a
/// regression fixture — the authoritative check a self-crafted test can't be.
async fn sniff(args: Vec<String>) -> Result<()> {
    let secs: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(15);
    println!("sniffing ports 6666/6667/7000 for {secs}s (raw hex of each datagram)...");

    // One bound socket per port; each read task prints what it gets. socket2 for
    // SO_REUSEADDR/REUSEPORT so this coexists with a running Discovery/other tools.
    let mut tasks = Vec::new();
    for port in [6666u16, 6667, 7000] {
        let sock = match bind_recv(port) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("bind udp/{port} failed: {e}");
                continue;
            }
        };
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        println!("\n[{port}] {n} bytes from {from}");
                        println!("  hex: {}", to_hex(&buf[..n]));
                        println!("  ascii: {}", to_ascii(&buf[..n]));
                    }
                    Err(e) => {
                        eprintln!("[{port}] recv error: {e}");
                        break;
                    }
                }
            }
        }));
    }
    if tasks.is_empty() {
        return Err(TuyaError::Config("no discovery port could be bound"));
    }

    tokio::time::sleep(Duration::from_secs(secs)).await;
    for t in tasks {
        t.abort();
    }
    println!("\ndone.");
    Ok(())
}

/// Bind a UDP socket for receiving broadcasts on `port`, shareable with other
/// sockets/processes (mirrors the driver's own `bind_recv`).
fn bind_recv(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    tokio::net::UdpSocket::from_std(sock.into())
}

/// Lowercase hex, space-separated per byte — paste-ready for a test fixture.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Printable ASCII with non-printables shown as `.` (to eyeball the JSON).
fn to_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
}
