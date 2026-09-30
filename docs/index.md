---
title: Rustuya 0.4
---

# Rustuya 0.4

Control and discover Tuya devices on your local network in pure Rust.
Rustuya provides raw data points (DPS), managed connections and fleet discovery,
with a `no_std + alloc` protocol core and a Tokio driver.

**Current stable version: 0.4.2. Requires Rust 1.89 or later.**

```toml
[dependencies]
rustuya = { version = "0.4", features = ["tokio"] }
tokio = { version = "1", features = ["full"] }
```

Start with [Getting started](getting-started.md) for a complete query example.
Commands are fire-and-forget: replies and device pushes arrive on a subscribed
listener. Connections reconnect with backoff, and discovery can track IP changes.

## Choose your version

| Documentation | Use it for |
| --- | --- |
| **0.4 — this site** | The current pure-Rust API: `rustuya::tokio`, `rustuya-tokio`, `rustuya-core` |
| [0.3 archive](0.3/index.md) | The previous Rust async/sync API and Python bindings |

0.4 is a breaking redesign. **Python bindings and a blocking/sync driver are
not included in 0.4.** Existing users of those APIs should use the 0.3 documentation.
See [Migrating from 0.3](MIGRATING-0.4.md) for the API mapping.

## Guides

- [Getting started](getting-started.md) — dependencies, device credentials and a first query.
- [Rust API guide](rust-api.md) — commands, events, current state, sub-devices and fleets.
- [Discovery](discovery.md) — LAN scans, addressless connections and rediscovery.
- [Architecture](architecture.md) — the core/driver boundary and embedded scope.
- [Technical notes](technical-notes.md) — timeouts, backpressure, shutdown and testing.
- [Design philosophy](philosophy.md) — scope and API decisions.
- [FAQ](faq.md) — common connection and migration questions.

## API reference and source

- [rustuya 0.4.2 API](https://docs.rs/rustuya/0.4.2/rustuya/) — facade with the `tokio` feature.
- [rustuya-tokio 0.4.2 API](https://docs.rs/rustuya-tokio/0.4.2/rustuya_tokio/) — the Tokio driver.
- [rustuya-core 0.4.2 API](https://docs.rs/rustuya-core/0.4.2/rustuya_core/) — the sans-I/O core.
- [Release notes](https://github.com/3735943886/rustuya/releases/tag/v0.4.2).
- [Source on master](https://github.com/3735943886/rustuya), [0.3 source archive](https://github.com/3735943886/rustuya/tree/0.3-stable).
