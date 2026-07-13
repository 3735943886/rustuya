//! Addressless connect: discover a device on the LAN by id, then control it —
//! **no IP and no version supplied**, discovery resolves both.
//!
//! This is the README's addressless shape (`Device` from just id + key), now
//! backed by the M2.3 discovery driver:
//!
//! ```text
//! cargo run --example discover_connect -- <device_id> <local_key>
//! # e.g.
//! cargo run --example discover_connect -- 01234567890123456789ab 0123456789abcdef
//! ```
//!
//! Requires the device to be on the same LAN as this host (discovery is UDP
//! broadcast). Flips DP 1 on, reads status, then streams pushes until Ctrl-C.

use std::time::Duration;

use rustuya_tokio::{Device, Discovery, Result};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<()> {
    let (id, key) = match (std::env::args().nth(1), std::env::args().nth(2)) {
        (Some(i), Some(k)) => (i, k),
        _ => {
            eprintln!("usage: discover_connect <device_id> <local_key>");
            std::process::exit(2);
        }
    };

    // Start LAN discovery (active broadcast probes on 6666/6667/7000).
    let disco = Discovery::new()?;

    // No address, no version — discovery fills both from the device's broadcast.
    println!("Discovering {id} on the LAN...");
    let dev = Device::builder(id, key.into_bytes())
        .discover(&disco, Duration::from_secs(15))
        .await?;
    println!("Connected to {} via discovery", dev.id());

    println!("Switching DP 1 ON...");
    dev.set_value(1, true).await?;
    println!("Status: {}", dev.status().await?);

    println!("Listening for pushes (Ctrl-C to stop)...");
    let mut listener = dev.listener();
    while let Some(msg) = listener.next().await {
        println!(
            "push: cmd={:#x} payload={}",
            msg.cmd,
            String::from_utf8_lossy(&msg.payload)
        );
    }

    Ok(())
}
