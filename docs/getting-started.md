---
title: Getting started with 0.4
---

# Getting started with 0.4

Use Rust 1.88+ and a Tokio runtime. You need the device ID, its 16-byte local key,
and either an IP address and protocol version or access to LAN discovery.
Rustuya does not obtain local keys from the cloud.

## Install

```toml
[dependencies]
rustuya = { version = "0.4", features = ["tokio"] }
tokio = { version = "1", features = ["full"] }
```

The facade has no default driver: enable `tokio` explicitly. Its public types
are under `rustuya::tokio`, rather than at the crate root.

## Query a device

Replace the example ID, key, address and protocol version with your device's values.
Subscribe before sending so a fast reply cannot race your subscription.

```rust,no_run
use std::time::Duration;
use rustuya::tokio::{Device, Event, Version};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dev = Device::builder("device_id_22chars0000", "0123456789abcdef")
        .address("192.168.1.50")
        .version(Version::V3_4)
        .connect()?;
    let mut events = dev.listener();
    dev.query().await?;

    // This is the next frame, not a response correlated to this particular query.
    match tokio::time::timeout(Duration::from_secs(5), events.recv()).await? {
        Some(Event::Frame(frame)) => {
            println!("{}", String::from_utf8_lossy(&frame.payload));
        }
        Some(Event::Lagged(count)) => eprintln!("Missed {count} frames"),
        None => eprintln!("The event stream ended"),
    }
    dev.close().await;
    Ok(())
}
```

`connect()` starts the background task; it does not await network establishment.
Command methods wait for connection and queue capacity within `send_timeout`.
Use `wait_connected(duration).await` if you need an explicit startup deadline.

## Write a data point

Call `dev.set_value(1, true).await?` for a boolean DP, or `set_dps` for a JSON
object containing several DPs. Use the DP IDs and value types for your device.
`Ok(())` means the command was queued; observe device frames to learn the result.
Closing immediately after queuing discards pending commands.

## Discover instead of specifying an IP

See [Discovery](discovery.md) for a complete scan and addressless connection
example. One shared `Discovery` can serve an entire fleet.

## Run the repository examples

```bash
cargo run --example scan
cargo run --example control -- <id> <key> <ip> <version>
cargo run --example monitor -- <id> <key>
cargo run --example fleet -- <id1:key1> <id2:key2>
```

The control example queries by default; passing a DP/value pair also writes it.
See the [example sources](https://github.com/3735943886/rustuya/tree/master/rustuya-tokio/examples)
for argument details, logging setup and event loops.
