//! Enumerate every Tuya device on the LAN — the standalone discovery, no
//! [`Device`](rustuya_tokio::Device) involved.
//!
//! Binds the well-known discovery ports, fires one on-demand active probe round,
//! and collects every distinct device that announces (passively or in reply)
//! during the window.
//!
//! ```text
//! cargo run --example scan -- [seconds]
//! ```

use std::time::Duration;

use rustuya_tokio::{Discovery, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let secs: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(5);
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
