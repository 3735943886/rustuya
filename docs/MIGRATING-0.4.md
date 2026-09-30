# Migrating from rustuya 0.3 to 0.4

0.4 is a breaking, pure-Rust redesign. It requires Rust 1.88+. Python bindings
and the blocking/sync API remain on 0.3.x; there is no 0.4 replacement for those
interfaces yet. The previous master is preserved on the
[`0.3-stable`](https://github.com/3735943886/rustuya/tree/0.3-stable) branch;
`master` now tracks 0.4. Embassy/ESP32 support is planned for 0.5+.

## Dependencies and imports

```toml
[dependencies]
rustuya = { version = "0.4", features = ["tokio"] }
tokio = { version = "1", features = ["full"] }
```

Import driver types from `rustuya::tokio`. The facade has no default driver.
For an embedded implementation, depend on `rustuya-core` directly; it contains
the `no_std + alloc` state machines, but does not provide sockets or a runtime.

## Commands and responses

Commands return after entering the bounded queue. Success does not mean the
device received or acknowledged the command. The protocol does not reliably
correlate responses with requests, so responses and pushes share an event stream.

```rust
use rustuya::tokio::{Device, Event, Version};

#[tokio::main]
async fn main() -> rustuya::tokio::Result<()> {
let dev = Device::builder("device_id_22chars0000", "0123456789abcdef")
    .address("192.168.1.50")
    .version(Version::V3_4)
    .connect()?;
let mut events = dev.listener(); // Subscribe before sending.
dev.query().await?;
while let Some(event) = events.recv().await {
    match event {
        Event::Frame(frame) => println!("{frame:?}"),
        Event::Lagged(skipped) => {
            eprintln!("missed {skipped} frames; requesting fresh status");
            dev.query().await?;
        }
    }
}
Ok(())
}
```

| 0.3 concept | 0.4 replacement |
| --- | --- |
| Top-level async device API | `rustuya::tokio::{Device, Discovery, ...}` |
| `status()` returning a response | `query() -> Result<()>`, then consume `listener()` |
| `request` / `request_message` | `send(cmd, data) -> Result<()>` |
| `set_dps` / `set_value` returning replies | `Result<()>`; acknowledgements arrive on the listener |
| Global scanner | Explicit shared `Discovery` |
| Addressless construction | `Device::builder(id, key).discover(&disco, timeout).await` |
| Global connection concurrency cap | Shared `ConnectLimiter` passed to builders |
| Unified listener | `MultiListener` with explicit device membership |
| Python / sync wrapper | Stay on 0.3.x |

`watch_status()` retains the last non-empty frame; it does not merge partial DPS
updates. Pair it with `watch_connected()` to judge whether that value is stale.
Connection transitions are separate from frame events. Use `watch_error()` for
authentication failures and `wait_connected(timeout)` when startup must complete.

## Timeouts, shutdown and discovery

`send_timeout` bounds waiting for both connection and command-queue capacity;
it is not a device-response timeout. Put your own deadline around awaiting an
event when your application needs one.

`close().await` stops the actor and waits for it to exit. It discards queued
commands and partial writes; await the application-level result you need before
closing. Dropping the last device handle also stops the actor.

Share one `Discovery` across devices. `.discover()` links it for later IP
changes and reconnect wakes; for a known IP, use `.rediscover(&disco)`.
Discovery checks the announced IP against the UDP source by default. If an
intentional relay changes that source, configure `require_source_match(false)`
explicitly. `max_devices` bounds the discovery cache.
