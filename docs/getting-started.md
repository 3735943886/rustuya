# Getting Started

Rustuya is a fast, concurrency-friendly library to control and monitor Tuya devices on the local network. This guide provides instructions for both Rust and Python.

---

## **Rust Installation**

Add the following to the `Cargo.toml` file:

```toml
[dependencies]
rustuya = "0.1"
```

### **Quick Start (Rust)**
Minimal example to set a value on a device using the synchronous wrapper:

```rust
use rustuya::sync::Device;

fn main() {
    // Create a device handle
    let device = Device::new(
        "DEVICE_ID", 
        "DEVICE_IP", // Or "Auto"
        "LOCAL_KEY", 
        "DEVICE_VER" // Or "Auto"
    );
    
    // Set a DP value (e.g., DP 1 to true)
    device.set_value(1, true);
    
    println!("Command dispatched!");
}
```

For full asynchronous usage with `tokio`, refer to the [Rust API Reference](./rust-api).

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
device = Device(
    id="DEVICE_ID",
    address="DEVICE_IP", # Or "Auto"
    local_key="LOCAL_KEY",
    version="DEVICE_VER" # Or "Auto"
)

# Set a DP value
device.set_value(1, True)

print("Command dispatched!")
```

---

## **What's Next?**
- Read the [Design Philosophy](./philosophy) to understand how Rustuya manages connections.
- Check out the [Rust API Reference](./rust-api) for advanced Rust features.
- Explore the [Python API Guide](./python-api) and [Python Examples](./python-examples) for more Python information.
- See the [examples]({{ site.github_url }}/tree/master/examples) directory in the repository for more complex use cases.
