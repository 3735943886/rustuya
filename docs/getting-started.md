# Getting Started

Rustuya is a fast, concurrency-friendly library to control and monitor Tuya devices on the local network.

## Installation
- Add to Cargo.toml:

```toml
[dependencies]
rustuya = "0.1"
```

## Quick Start
Minimal example to set a value on a device:

```rust
use rustuya::sync::Device;

fn main() {
    let device = Device::new("DEVICE_ID", "ADDRESS", "DEVICE_KEY", "VER");
    device.set_value(1, true);
}
```

## More Examples
- Additional examples are available in the [examples]({{ site.github_url }}/tree/master/examples) directory.
