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
//! | mode              | exercises                                   | mock blind spot it covers |
//! |-------------------|---------------------------------------------|---------------------------|
//! | `control`         | v3.x handshake + GCM crypto + framing       | real firmware session negotiation, real DPS payloads |
//! | `monitor`         | connection liveness + **reconnect** + pushes| real power-cycle offline→online, real backoff/rewake |
//! | `scan`            | passive receive + one active probe round    | real announce cadence/format, real probe replies |
//! | `find`            | on-demand active probe resolves one id       | a device that only answers active probes (never self-announces) |
//! | `discover-connect`| addressless discover → connect → status      | the full LAN-resolve path end to end |
//!
//! The highest-value mode is **`monitor`**: the whole 0.4 discovery redesign
//! (registry routing, on-demand active, Seen/Found, backoff-cancelling rewake) has
//! so far only been checked against loopback simulations. Only a real device,
//! physically power-cycled, exercises the offline→online reconnect for real.
//!
//! ## Usage
//!
//! ```text
//! # read status (and optionally set one DP):
//! cargo run --example real_device -- control <ip> <id> <key> [dp value] [3.4]
//!
//! # watch connection state + live pushes; power-cycle the device to test reconnect:
//! cargo run --example real_device -- monitor <ip> <id> <key> [3.4]
//!
//! # enumerate every Tuya device on the LAN (no device args needed):
//! cargo run --example real_device -- scan [seconds]
//!
//! # resolve one device id by active probe:
//! cargo run --example real_device -- find <id> [seconds]
//!
//! # resolve address+version by discovery, then connect and read status:
//! cargo run --example real_device -- discover-connect <id> <key> [3.4]
//! ```
//!
//! The optional trailing `[3.4]` is the protocol version (`3.1`/`3.2`/`3.3`/`3.4`/
//! `3.5`); it defaults to `3.3`. To also see the driver's internal logs (probe
//! sends, route pruning, listener lag), set `RUST_LOG`:
//!
//! ```text
//! RUST_LOG=rustuya_tokio=debug cargo run --example real_device -- monitor 192.168.1.50 <id> <key> 3.4
//! ```
//!
//! **Safety:** `control`'s optional `dp value` writes to your device. Only pass a
//! DP you know is safe to toggle (e.g. a switch). Without it, `control` is
//! read-only (`status` query).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rustuya_tokio::{Device, Discovery, Result, TuyaError, Version};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<()> {
    // Surface the driver's internal `log` output when RUST_LOG is set; silent
    // otherwise. Example-only convenience — the library never installs a logger.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("off")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]).to_vec();

    match cmd {
        "control" => control(rest).await,
        "monitor" => monitor(rest).await,
        "scan" => scan(rest).await,
        "find" => find(rest).await,
        "discover-connect" => discover_connect(rest).await,
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
  control <ip> <id> <key> [dp value] [version]   read status (and optionally set one DP)
  monitor <ip> <id> <key> [version]              watch connection + pushes (power-cycle to test reconnect)
  scan [seconds]                                 list every Tuya device on the LAN
  find <id> [seconds]                            resolve one device id by active probe
  discover-connect <id> <key> [version]          resolve address by discovery, then connect
  sniff [seconds]                                dump raw discovery datagrams as hex (diagnostic)
version is one of 3.1/3.2/3.3/3.4/3.5 (default 3.3); set RUST_LOG=rustuya_tokio=debug for driver logs."
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

/// Pop a trailing `3.x` version token off the arg list if present, else default to
/// v3.3. Done first so the remaining positional args are unambiguous: a version is
/// the only trailing token that looks like `3.x`, so this never eats a real arg.
fn take_version(args: &mut Vec<String>) -> Version {
    if let Some(v) = args.last().and_then(|s| parse_version(s)) {
        args.pop();
        return v;
    }
    Version::V3_3
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

/// `control <ip> <id> <key> [dp value] [version]` — the ★★ handshake/crypto path.
///
/// Connecting is where the real work a mock can't fully vouch for happens: the
/// v3.4/v3.5 session-key negotiation and GCM crypto against actual firmware, then
/// a real `DpQuery` decode. If `dp value` is supplied, it also issues a real
/// `Control` write and reads the state back.
async fn control(mut args: Vec<String>) -> Result<()> {
    let version = take_version(&mut args);
    let (ip, id, key) = match (args.first(), args.get(1), args.get(2)) {
        (Some(a), Some(i), Some(k)) => (a.clone(), i.clone(), k.clone()),
        _ => {
            usage();
            std::process::exit(2);
        }
    };

    let dev = Device::builder(id, key.into_bytes())
        .address(ip)
        .version(version)
        .connect()?;

    // `status()` waits for the connection internally, but wait explicitly so a
    // handshake failure surfaces here as a clear Timeout rather than mid-query.
    println!("connecting ({version:?})...");
    dev.wait_connected(Duration::from_secs(10)).await?;
    println!("connected. status: {}", dev.status().await?);

    // Optional write: `control ip id key <dp> <value>`.
    if let (Some(dp), Some(raw)) = (args.get(3), args.get(4)) {
        let value = parse_scalar(raw);
        println!("setting DP {dp} = {value}");
        let resp = dev.set_value(dp, value).await?;
        println!("set response: {resp}");
        println!("status after: {}", dev.status().await?);
    }

    dev.close().await;
    Ok(())
}

/// `monitor <ip> <id> <key> [version]` — the ★★★ reconnect path.
///
/// Connects, then runs two observers concurrently until Ctrl-C:
///   1. a connection-state watch that prints every UP/DOWN transition, and
///   2. the lossless push [`Device::listener`] stream.
///
/// **The test:** while this runs, physically power the device off and back on. You
/// should see `DOWN` then `UP` again — the driver reconnecting for real. A
/// [`Discovery`] is linked ([`DeviceBuilder::rediscover`]) so the device's boot
/// re-announcement cancels the reconnect backoff and redials *immediately* instead
/// of waiting it out; if the UDP ports can't be bound (another process holds them)
/// it falls back to plain backoff reconnect, which is slower but still recovers.
async fn monitor(mut args: Vec<String>) -> Result<()> {
    let version = take_version(&mut args);
    let (ip, id, key) = match (args.first(), args.get(1), args.get(2)) {
        (Some(a), Some(i), Some(k)) => (a.clone(), i.clone(), k.clone()),
        _ => {
            usage();
            std::process::exit(2);
        }
    };

    // Best-effort discovery for fast rewake; None if the ports are taken.
    let disco = match Discovery::new() {
        Ok(d) => Some(d),
        Err(e) => {
            eprintln!("(discovery unavailable: {e}; reconnect falls back to backoff)");
            None
        }
    };

    let mut builder = Device::builder(id, key.into_bytes())
        .address(ip)
        .version(version);
    if let Some(d) = &disco {
        builder = builder.rediscover(d);
    }
    let dev = builder.connect()?;

    println!("monitoring {version:?}; Ctrl-C to stop.");
    println!("=> power-cycle the device to watch it reconnect.");
    println!("=> heartbeat-ack (~every 10s) proves liveness; status-push arrives");
    println!("   only when the device's state changes (button / another app / sensor).");

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

/// `discover-connect <id> <key> [version]` — the ★★ full addressless path.
///
/// Resolves the device's IP (and version, if the broadcast declares one) by LAN
/// discovery, then connects and reads status — no IP typed by hand. The trailing
/// `[version]` is only a fallback for firmware whose broadcast omits the version.
async fn discover_connect(mut args: Vec<String>) -> Result<()> {
    let version = take_version(&mut args);
    let (id, key) = match (args.first(), args.get(1)) {
        (Some(i), Some(k)) => (i.clone(), k.clone()),
        _ => {
            usage();
            std::process::exit(2);
        }
    };

    let disco = Discovery::new()?;
    println!("discovering {id} then connecting...");
    let dev = Device::builder(id, key.into_bytes())
        .version(version) // fallback; discovery overrides if the broadcast reports one
        .discover(&disco, Duration::from_secs(15))
        .await?;

    println!("resolved + connected. status: {}", dev.status().await?);
    dev.close().await;
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
