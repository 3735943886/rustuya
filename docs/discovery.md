---
title: Discovery in 0.4
---

# Discovery in 0.4

`Discovery` listens for UDP device announcements and sends active probes on
demand. Share one instance across your devices. Discovery is IPv4 broadcast
based; use an explicit address where broadcast discovery cannot reach a device.

## Scan and connect

```rust,no_run
use std::time::Duration;
use rustuya::tokio::{Device, Discovery};

#[tokio::main]
async fn main() -> rustuya::tokio::Result<()> {
    let discovery = Discovery::new()?;
    for info in discovery.scan(Duration::from_secs(5)).await {
        println!("{} at {} ({:?})", info.id, info.ip, info.version);
    }

    let dev = Device::builder("device_id_22chars0000", "0123456789abcdef")
        .discover(&discovery, Duration::from_secs(10))
        .await?;
    dev.wait_connected(Duration::from_secs(10)).await?;
    println!("Connected to {}", dev.id());
    dev.close().await;
    discovery.close().await;
    Ok(())
}
```

`discover()` resolves the IP and reported protocol version, then links discovery
for reconnect wakes and later IP changes. With a known IP, use
`Device::builder(id, key).address(ip).rediscover(&discovery).connect()`.

## Discovery APIs

| Method | Use |
| --- | --- |
| `scan(window).await` | Trigger an active probe round and collect devices during the window |
| `find(id, timeout).await` | Resolve a device, using cached information if present |
| `known()` | Snapshot of devices retained in the driver's cache |
| `last_seen(id)` | Age of the most recent announcement |
| `discovered()` | Subscribe to discovery events |
| `request_scan()` | Request an on-demand active probe round |

There is no process-global scanner. Re-announcements route directly to linked
devices; a changed IP updates the next dial target. Cache presence is not proof
that a device is currently reachable—use `last_seen` and connection state.

## Interfaces, bounds and source checks

The builder's `local_ip` / `local_ips` options select the source addresses for
active probing on multi-interface hosts. `ports()` changes receive ports;
active probes still target the protocol's standard ports (6666, 6667 and 7000).

Announcements are not authenticated by a device's local key. By default,
`require_source_match(true)` checks that the announced IP equals the UDP source.
Only disable that check when an intentional relay requires it. `max_devices`
bounds discovery cache entries (default 16,384).
