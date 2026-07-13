//! Runnable tokio example — the README async shape, over the sans-I/O core.
//!
//! Unlike the addressless README snippet (which needs the discovery driver, M2.3),
//! this passes an explicit address, so it runs today against a real device or a
//! `tuyamock` instance:
//!
//! ```text
//! cargo run --example tokio_control -- <ip> <device_id> <local_key> [version]
//! # e.g.
//! cargo run --example tokio_control -- 192.168.1.50 01234567890123456789ab 0123456789abcdef 3.4
//! ```
//!
//! It flips DP 1 on, reads status, then streams live device pushes until Ctrl-C.
//! `listener()` is a `Stream`, so the README idiom `while let Some(m) = l.next()`
//! works verbatim (here via `tokio_stream::StreamExt`; `futures_util::StreamExt`
//! is identical).

use rustuya_tokio::{Device, Result, Version};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let (addr, id, key) = match (args.next(), args.next(), args.next()) {
        (Some(a), Some(i), Some(k)) => (a, i, k),
        _ => {
            eprintln!(
                "usage: tokio_control <ip> <device_id> <local_key> [version=3.3]"
            );
            std::process::exit(2);
        }
    };
    let version = match args.next().as_deref() {
        Some("3.1") => Version::V3_1,
        Some("3.2") => Version::V3_2,
        Some("3.4") => Version::V3_4,
        Some("3.5") => Version::V3_5,
        _ => Version::V3_3,
    };

    let dev = Device::builder(id, key.into_bytes())
        .address(addr)
        .version(version)
        .connect()?;

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
