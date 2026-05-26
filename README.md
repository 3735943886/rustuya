# Rustuya

[![Crates.io](https://img.shields.io/crates/v/rustuya.svg)](https://crates.io/crates/rustuya)
[![Pypi.org](https://badge.fury.io/py/rustuya.svg)](https://badge.fury.io/py/rustuya)
[![Documentation](https://docs.rs/rustuya/badge.svg)](https://docs.rs/rustuya)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Local-network control of Tuya-compatible devices, built in Rust with
first-class Python bindings. Designed for fleets of hundreds to
thousands of devices — a native Rust core handles the I/O while the
Python facade releases the GIL on every blocking call, so threaded
Python workers stay live.

## Install

**Rust**

```bash
cargo add rustuya
```

**Python**

```bash
pip install rustuya
```

## Quick start

**Rust**

```rust
use rustuya::sync::Device;

let dev = Device::new("DEVICE_ID", "LOCAL_KEY");
dev.set_value(1, true)?;                        // turn on DP 1
println!("{:?}", dev.status()?);                // read current DPS

for msg in dev.listener() {                     // real-time events
    println!("{:?}", msg);
}
```

**Python**

```python
from rustuya import Device

dev = Device("DEVICE_ID", "LOCAL_KEY")
dev.set_value(1, True)                          # turn on DP 1
print(dev.status())                             # read current DPS

for msg in dev.listener():                      # real-time events
    print(msg)
```

## Features

- Local-only — talks directly to devices over LAN, no Tuya Cloud
- Rust core + Python bindings (PyO3) — same engine for both
- Built for fleet scale — per-device background tasks with
  automatic reconnection and exponential backoff
- Full protocol coverage — Tuya 3.1 / 3.2 / 3.3 / 3.4 / 3.5 + device22

See the [Guide](https://3735943886.github.io/rustuya/) for the full API
reference, design philosophy, and architecture notes.

## Credits

The Tuya protocol layer in rustuya is derived from the specifications
and error codes documented in
[tinytuya](https://github.com/jasonacox/tinytuya):

- [Protocol Reference](https://github.com/jasonacox/tinytuya/blob/master/PROTOCOL.md)

## License

MIT
