---
title: Rust API guide for 0.4
---

# Rust API guide for 0.4

Import from `rustuya::tokio`. For signatures and all builder options, use the
[0.4.1 API reference](https://docs.rs/rustuya-tokio/0.4.1/rustuya_tokio/).

## Device commands

| Method | Behavior |
| --- | --- |
| `Device::builder(id, key)` | Configure a device; finish with `connect()` or `discover(...).await` |
| `query().await` | Queue a status query |
| `set_value(dp, value).await` | Queue a single-DP update |
| `set_dps(json).await` | Queue a map of DPS values |
| `send(command, data).await` | Queue an arbitrary protocol command |
| `sub_discover().await` | Ask a gateway to report sub-device online status |
| `sub(cid)` | Get a sub-device handle sharing the gateway connection |

All command methods return `Result<()>`. The protocol does not reliably
correlate responses with calls. Read replies and unsolicited pushes from
`listener()`, subscribing **before** sending. Connection loss can discard a
queued command; queued success does not promise delivery or acknowledgement.

## Events and state

| API | What it provides |
| --- | --- |
| `listener()` | `Event::Frame(Message)` and `Event::Lagged(skipped)` |
| `watch_status()` | Last non-empty frame; not a merged DPS map |
| `is_connected()` | Current connection state |
| `wait_connected(duration).await` | Wait for connection, authentication failure or timeout |
| `watch_connected()` | Last-value connection state with change notifications |
| `watch_error()` | Last authentication failure; cleared on a healthy connection |

The listener is a bounded broadcast stream. On `Lagged`, decide whether to query
fresh state or accept the gap. A watch channel retains only the latest value;
rapid transitions may coalesce. `watch_status()` retains its frame across a
disconnect, so check connection state when judging freshness.

## Fleets

Share a `Discovery` and, optionally, a `ConnectLimiter`. The limiter covers
TCP connection and handshake establishment, then releases its permit. It does
not limit the total number of live connections.

`MultiListener` combines device listeners and yields `(device_id, Event)`.
Keep the device handles alive, and add each device before firing its first query.

```rust,no_run
use rustuya::tokio::{ConnectLimiter, Device, MultiListener, Version};

#[tokio::main]
async fn main() -> rustuya::tokio::Result<()> {
    let limiter = ConnectLimiter::new(32);
    let dev = Device::builder("device_id_22chars0000", "0123456789abcdef")
        .address("192.168.1.50")
        .version(Version::V3_4)
        .connect_limiter(&limiter)
        .connect()?;
    let mut events = MultiListener::new();
    events.add(&dev);
    dev.query().await?;
    while let Some((id, event)) = events.recv().await {
        println!("{id}: {event:?}");
    }
    Ok(())
}
```

## Sub-devices

`let sub = gateway.sub("channel_id");` creates a handle whose `query`, `set_dps`,
`set_value` and `send` methods add the channel ID to the outgoing envelope.
Frames arrive on the gateway's listener; sub-devices do not open their own sockets.

## Timeouts and lifecycle

- `connect_timeout`: TCP dial limit, default 5 seconds.
- `handshake_timeout`: session negotiation limit, default 5 seconds.
- `send_timeout`: total wait for connection and command-queue capacity, default 5 seconds.
- `heartbeat`: keepalive cadence, default 10 seconds.
- `idle_timeout`: inbound liveness deadline, default 30 seconds.

`connect_now().await` queues a reconnect wake. `close().await` stops the actor
and waits for it to exit, discarding queued commands and partial writes. It
bypasses a full queue. Dropping the last device handle also stops the actor.
See [Technical notes](technical-notes.md) for details.
