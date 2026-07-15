//! Read a real device's status, and optionally set one DP — the handshake +
//! crypto + framing path against actual firmware.
//!
//! `id` and `key` are required; `[ip]` and `[version]` are optional and resolved
//! from the LAN discovery beacon when omitted (like 0.3's addressless `Device`).
//! An explicit `[version]` that contradicts the announcement is reported as an
//! error and the announced one is used.
//!
//! ```text
//! cargo run --example control -- <id> <key>                       # auto-resolve
//! cargo run --example control -- <id> <key> 192.168.1.50 3.4      # pinned
//! cargo run --example control -- <id> <key> 1 true               # also set DP 1 = true
//! ```
//!
//! **Safety:** `dp value` writes to your device — only pass a DP you know is safe
//! to toggle. Without it, this is read-only.

#[path = "common/mod.rs"]
mod common;

use std::time::Duration;

use common::{connect_resolved, init_logging, parse_scalar, take_ip, take_version};
use rustuya_tokio::{Event, Listener, Result};

/// Fire-and-forget commands don't return a reply; the device's frames arrive on
/// [`Device::listener`]. Print the next non-empty frame (the reply to what we just
/// fired), skipping bare heartbeat acks, bounded so a silent device doesn't hang.
async fn next_reply(events: &mut Listener) -> String {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), events.recv()).await {
            Ok(Some(Event::Frame(msg))) if !msg.payload.is_empty() => {
                return String::from_utf8_lossy(&msg.payload).into_owned();
            }
            Ok(Some(Event::Frame(_))) => continue, // a bare ack — keep waiting
            Ok(Some(Event::Lagged(n))) => return format!("(lagged — missed {n} frames)"),
            Ok(None) => return "(device closed)".into(),
            Err(_) => return "(no reply within 5s)".into(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let version = take_version(&mut args);
    let ip = take_ip(&mut args);
    let (id, key) = match (args.first(), args.get(1)) {
        (Some(i), Some(k)) => (i.clone(), k.clone()),
        _ => {
            eprintln!("usage: control <id> <key> [dp value] [ip] [version]");
            std::process::exit(2);
        }
    };
    // After id/key, a remaining `dp value` pair means "also set this DP".
    let set = args
        .get(2)
        .zip(args.get(3))
        .map(|(dp, v)| (dp.clone(), v.clone()));

    let dev = connect_resolved(id, key, ip, version).await?;
    // `query()` waits for the connection internally, but wait explicitly so a
    // handshake failure surfaces here as a clear error rather than mid-query.
    dev.wait_connected(Duration::from_secs(10)).await?;

    // Subscribe before firing so the reply can't race the subscription; replies
    // arrive on the listener bus, not as a return value.
    let mut events = dev.listener();
    dev.query().await?;
    println!("connected. status: {}", next_reply(&mut events).await);

    if let Some((dp, raw)) = set {
        let value = parse_scalar(&raw);
        println!("setting DP {dp} = {value}");
        dev.set_value(&dp, value).await?;
        println!("state after: {}", next_reply(&mut events).await);
    }

    dev.close().await;
    Ok(())
}
