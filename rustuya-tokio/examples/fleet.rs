//! Watch several devices on ONE loop via [`MultiListener`] — the fleet path.
//!
//! Each argument is `id:key` or `id:key@ip` (the ip is optional; without it the
//! device is resolved by LAN discovery). Every device's frames arrive on one stream,
//! tagged with the device id; a slow-consumer gap shows up as `Event::Lagged`.
//!
//! ```text
//! cargo run --example fleet -- id1:key1 id2:key2@192.168.1.51
//! ```

#[path = "common/mod.rs"]
mod common;

use std::time::Duration;

use common::{connect_resolved, init_logging};
use rustuya_tokio::{Event, MultiListener, Result};

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let specs: Vec<String> = std::env::args().skip(1).collect();
    if specs.is_empty() {
        eprintln!("usage: fleet <id:key[@ip]> [<id:key[@ip]> ...]");
        std::process::exit(2);
    }

    // Subscribe each device into the aggregator *before* firing any query.
    let mut multi = MultiListener::new();
    let mut devices = Vec::new();
    for spec in &specs {
        let (idkey, ip) = match spec.split_once('@') {
            Some((l, r)) => (l, Some(r.to_string())),
            None => (spec.as_str(), None),
        };
        let (id, key) = idkey
            .split_once(':')
            .unwrap_or_else(|| panic!("bad spec {spec:?}: expected id:key[@ip]"));
        let dev = connect_resolved(id.to_string(), key.to_string(), ip, None).await?;
        multi.add(&dev);
        devices.push(dev);
    }
    println!("watching {} devices; Ctrl-C to stop.", multi.len());

    // Kick each with a status query so the first frame is its current state.
    for dev in &devices {
        let _ = dev.wait_connected(Duration::from_secs(10)).await;
        let _ = dev.query().await;
    }

    // One loop for the whole fleet, each event tagged with its device id.
    while let Some((id, ev)) = multi.recv().await {
        match ev {
            Event::Frame(m) => println!(
                "[{id}] cmd={:#x} {}",
                m.cmd,
                String::from_utf8_lossy(&m.payload)
            ),
            Event::Lagged(n) => println!("[{id}] lagged — missed {n} frames"),
        }
    }
    println!("all devices stopped.");
    Ok(())
}
