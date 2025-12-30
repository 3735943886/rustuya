# Rustuya

[![Crates.io](https://img.shields.io/crates/v/rustuya.svg)](https://crates.io/crates/rustuya)
[![Documentation](https://docs.rs/rustuya/badge.svg)](https://docs.rs/rustuya)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Rustuya** is an asynchronous Rust implementation of the Tuya Local API. It allows for local control and monitoring of Tuya-compatible devices without cloud dependencies.

> [!WARNING]  
> This project is in an **early development stage (v0.1.0)**. APIs are subject to change.


## Installation

Add `rustuya` to `Cargo.toml`:

```bash
cargo add rustuya tokio --features tokio/full
```

## Quick Start

### Basic Device Control

```rust
use rustuya::Device;
use serde_json::json;

#[tokio::main]
async fn main() {
    // Address and version can be "Auto" for automatic discovery
    let device = Device::new("DEVICE_ID", "DEVICE_ADDRESS", "DEVICE_KEY", "DEVICE_VERSION");

    // Switch ON (DP 1 is usually power)
    device.set_value(1, json!(true)).await;
}
```

### Real-time Status Monitoring

```rust
use rustuya::Device;
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() {
    let device = Device::new("DEVICE_ID", "DEVICE_ADDRESS", "DEVICE_KEY", "DEVICE_VERSION");
    let mut stream = device.stream();

    while let Some(message) = stream.next().await {
        println!("Received: {:?}", message);
    }
}
```

## Credits

This project references the communication protocols and cipher implementations from the [tinytuya](https://github.com/jasonacox/tinytuya) Python library.

## License

MIT
