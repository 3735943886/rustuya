# Getting Started

A lightweight and efficient Rust library for controlling Tuya-compatible smart devices.

---

## **Rust Installation**

Add the following to the `Cargo.toml` file:

```toml
[dependencies]
rustuya = "0.2"
```

### **Quick Start (Rust)**
Minimal example to control a device from Rust:

```rust
use rustuya::sync::Device;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a device handle
    let device = Device::new("DEVICE_ID", "LOCAL_KEY");

    // Set a DP value (e.g., DP 1 to true)
    device.set_value(1, true)?;

    Ok(())
}
```

---

## **Python Installation**

Install the package via `pip`:

```bash
pip install rustuya
```

### **Quick Start (Python)**
Minimal example to control a device from Python:

```python
from rustuya import Device

# Create a device handle
device = Device("DEVICE_ID", "LOCAL_KEY")

# Set a DP value (e.g., DP 1 to true)
device.set_value(1, True)
```

---

## **Next Steps**
- Read the [Design Philosophy](./philosophy.md) to understand the connection management model.
- Check the [Rust API Reference](./rust-api.md) for detailed Rust documentation.
- Explore the [Python API Guide](./python-api.md) and [Python Examples](./python-examples.md) for more Python information.
- See the [examples]({{ site.github_url }}/tree/master/examples) directory in the repository for more complex use cases.
