---
title: Technical notes for 0.4
---

# Technical notes for 0.4

## Queueing and backpressure

The command channel and listener broadcast ring are bounded. Builders expose
`command_capacity` (default 64) and `listener_capacity` (default 128).
`send_timeout` bounds the combined connection and queue-capacity wait.
It does not wait for a device acknowledgement.

When a peer stops reading, the driver retains partial-write progress and
continues servicing reads and core deadlines. Pending wire frames must drain
before the next application command is dequeued. `close()` bypasses that queue
and waits for the actor to exit; it does not flush queued application commands.

## Connection state

The core owns handshake, reconnect backoff, heartbeat and idle-liveness policy.
The driver arms the next deadline returned by the core. A successful TCP dial
is not enough for a 3.4/3.5 connection: session negotiation must finish first.

`ConnectLimiter` permits cover establishment only. Disabling handshake timeouts
while sharing a limiter can leave permits held by peers that never answer.
Applications can observe authentication errors through `watch_error()`.

## Frames and current state

`listener()` reports frames and lag events. It does not replay a complete device
state on subscription. `watch_status()` retains the last non-empty frame, which
may be a partial DPS update. Applications that need a merged state must maintain
that map themselves and decide how to recover after `Event::Lagged`.

## Logging

The driver uses the `log` facade. Applications choose a logger; the repository
examples use `env_logger`. Debug logs cover connection lifecycle. Trace logs
include wire bytes and decoded plaintext payloads.

## Verification

```bash
cargo test --locked --workspace --all-features
RUSTUYA_TUYAMOCK=/path/to/tuyamock cargo test --locked --workspace --all-features
cargo build --locked -p rustuya-core --no-default-features --target riscv32imc-unknown-none-elf
cargo build --locked -p rustuya-core --no-default-features --target thumbv7em-none-eabi
```

CI uses tuyamock 0.0.6 as an independent wire oracle and checks Rust 1.88,
formatting, Clippy, rustdoc and packaged crates. The emulator tests skip when
tuyamock is unavailable locally. Bare-metal builds require the corresponding
Rust targets installed through `rustup target add`.
