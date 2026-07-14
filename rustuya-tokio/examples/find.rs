//! Resolve one device id by an on-demand active probe — the mode that exposes a
//! Tuya quirk a mock can't: a device that never self-announces and only replies
//! when actively probed (the reason active discovery is mandatory).
//!
//! ```text
//! cargo run --example find -- <id> [seconds]
//! ```

use std::time::Duration;

use rustuya_tokio::{Discovery, Result, TuyaError};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let id = match args.next() {
        Some(id) => id,
        None => {
            eprintln!("usage: find <id> [seconds]");
            std::process::exit(2);
        }
    };
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(10);
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
