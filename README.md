# rustuya

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Local-network control and discovery of Tuya devices, in **pure Rust**.

`rustuya` is a **sans-I/O** implementation of the Tuya LAN protocol: a `no_std`
core state machine that owns every protocol decision, driven by a thin I/O layer.
The tokio driver runs it on a desktop/server; the same core is built to run on an
MCU (Embassy/ESP32) behind a different driver — one protocol implementation, many
runtimes.

## Scope

rustuya is built to drive **many devices at once with minimal overhead**, staying
low-level and close to the wire: raw data points (DPS) over the LAN protocol, with
no per-device-type modelling and no cloud. If you want higher-level, per-device
abstractions (`OutletDevice`, `CoverDevice`, `BulbDevice`, …) or the Tuya Cloud
API, use [tinytuya](https://github.com/jasonacox/tinytuya) — rustuya deliberately
stops at the local protocol layer those build on.

> **Status.** 0.4 is a from-scratch redesign on the `0.4-sansio` branch. The
> shipping 0.3 line — a monolithic `rustuya` crate with Python bindings — lives on
> `master` and the `v0.3.x` tags. This README covers 0.4.

## Layout

| crate | what it is |
|-------|------------|
| [`rustuya-core`](rustuya-core) | `no_std + alloc` protocol core — framing, crypto (v3.1–v3.5), and the connection + discovery state machines. No sockets, no timers, no clock: the driver injects `now` and an RNG. |
| [`rustuya-tokio`](rustuya-tokio) | the `std` + tokio driver — TCP, UDP discovery, one timer per device, the OS RNG. |

## Quick start (tokio)

```rust
use rustuya_tokio::{Device, Version};

#[tokio::main]
async fn main() -> rustuya_tokio::Result<()> {
    let dev = Device::builder("device_id_22chars0000", "0123456789abcdef")
        .address("192.168.1.50")
        .version(Version::V3_4)
        .connect()?;

    let state = dev.status().await?;   // query data points
    println!("{state}");
    dev.set_value(1, true).await?;     // flip DP 1

    // A lossless stream of device pushes (state changes) and responses.
    let mut events = dev.listener();
    let push = events.recv().await?;
    println!("push: {push:?}");
    Ok(())
}
```

The connection is managed for you: a dropped link reconnects with jittered backoff,
a keepalive heartbeat holds it open, and idle-liveness surfaces a silently-dead
peer promptly. Requests are correlated FIFO — the Tuya LAN protocol carries no
request/response token — so for asynchronous device pushes prefer `listener()`.

## Discovery

Devices announce themselves over UDP; some only answer active probes. A shared
`Discovery` handles both, and doubles as the reconnect fast-path.

```rust
use rustuya_tokio::Discovery;

let disco = Discovery::new()?;

// Enumerate the LAN (passive receive + one active probe round).
for info in disco.scan(std::time::Duration::from_secs(5)).await {
    println!("{} at {} ({:?})", info.id, info.ip, info.version);
}

// Or resolve + connect without hand-typing an address (fills in ip and version):
let dev = rustuya_tokio::Device::builder("device_id_22chars0000", "0123456789abcdef")
    .discover(&disco, std::time::Duration::from_secs(10))
    .await?;
```

Linking a `Discovery` to a device (via `.discover()` or `.rediscover()`) lets a
re-announcement cancel the reconnect backoff and redial immediately — and a
changed IP self-corrects.

## Design

- **Sans-I/O.** The core decides *which bytes, which port, which timer, whether to
  reconnect*; the driver only moves bytes and arms one timer. This is what lets the
  same protocol code target both tokio and a `no_std` MCU.
- **Injected clock + RNG.** The core reads no clock and generates no randomness —
  the driver passes `now` and an RNG in. That gives `no_std` portability,
  deterministic zero-wall-clock tests, and a guaranteed-fresh IV/nonce per frame.
- **Poll-split FSM** (quinn-proto style): `handle_input` / `handle_timeout` push in;
  `poll_transmit` / `poll_event` / `poll_timeout` pull out, with a single next
  deadline the driver arms one timer for.

## Examples

Runnable against a real device (or the `tuyamock` emulator), in `rustuya-tokio`:

```bash
cargo run --example control -- <id> <key>          # read status / set a DP
cargo run --example monitor -- <id> <key>          # watch state + reconnect
cargo run --example scan                            # list devices on the LAN
cargo run --example find    -- <id>                 # resolve one device by probe
cargo run --example sniff                           # raw discovery hex dump
```

`[ip]` and `[version]` are optional trailing args — omit them and they are resolved
from the discovery beacon.

## Testing

```bash
cargo test --workspace                              # unit + loopback + discovery
cargo build -p rustuya-core --no-default-features \
  --target riscv32imc-unknown-none-elf              # the no_std acceptance gate
```

Protocol correctness is gated end-to-end against the independent
[`tuyamock`](https://pypi.org/project/tuyamock/) device emulator (validated against
tinytuya) — connection, framing, crypto, the v3.4/v3.5 handshake, discovery, and
fault-injection resilience. Opt in by pointing `RUSTUYA_TUYAMOCK` at the binary;
tests skip cleanly without it.

## License

MIT — see [LICENSE](LICENSE).
