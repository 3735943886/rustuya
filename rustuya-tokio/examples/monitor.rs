//! Watch a real device's connection state and live pushes until Ctrl-C — the
//! reconnect path. **Power-cycle the device while this runs** to see it drop and
//! reconnect for real.
//!
//! `id` and `key` are required; `[ip]` and `[version]` are optional and resolved
//! from the discovery beacon when omitted. The linked discovery lets the device's
//! boot re-announcement cancel the reconnect backoff and redial immediately.
//!
//! ```text
//! cargo run --example monitor -- <id> <key>                  # auto-resolve
//! cargo run --example monitor -- <id> <key> 192.168.1.50 3.4
//! ```

#[path = "common/mod.rs"]
mod common;

use std::time::Duration;

use common::{connect_resolved, init_logging, take_ip, take_version};
use rustuya_tokio::{Event, Result, TuyaError};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let version = take_version(&mut args);
    let ip = take_ip(&mut args);
    let (id, key) = match (args.first(), args.get(1)) {
        (Some(i), Some(k)) => (i.clone(), k.clone()),
        _ => {
            eprintln!("usage: monitor <id> <key> [ip] [version]");
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
            ev = listener.next() => match ev {
                Some(Event::Frame(m)) => {
                    // Label by command so a heartbeat reply isn't mistaken for a
                    // device push. Unsolicited STATUS (0x08) only arrives when the
                    // device's state actually changes.
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
                // A slow consumer would surface here instead of silently dropping.
                Some(Event::Lagged(n)) => println!("[lagged] missed {n} frames"),
                None => {
                    println!("device stopped.");
                    break;
                }
            }
        }
    }
    Ok(())
}
