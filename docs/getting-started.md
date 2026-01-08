# Getting Started

A lightweight and efficient Rust library for controlling Tuya-compatible smart devices.

---

## **Rust Installation**

Add the following to the `Cargo.toml` file:

```toml
[dependencies]
rustuya = "0.1"
```

### **Quick Start (Rust)**
Minimal example to control a device from Rust:

```rust
use rustuya::sync::Device;

fn main() {
    // Create a device handle
    let device = Device::new("DEVICE_ID", "DEVICE_KEY");

    // Set a DP value (e.g., DP 1 to true)
    match device.set_value(1, true) {
        Ok(Some(res)) => println!("[SUCCESS] SetValue result: {}", res),
        Ok(None) => println!("[SUCCESS] SetValue sent (no response yet)"),
        Err(e) => println!("[ERROR] SetValue failed: {:?}", e),
    }
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

# Set a DP value
print(device.set_value(1, True))
```

---

## **System Optimization**
When managing a large number of concurrent device connections on Unix-like systems, it is recommended to maximize the file descriptor limit at the start of the application:

- **Rust**: `rustuya::maximize_fd_limit().ok();`
- **Python**: `rustuya.maximize_fd_limit()`

---

## **Next Steps**
- Read the [Design Philosophy](./philosophy.md) to understand the connection management model.
- Check the [Rust API Reference](./rust-api.md) for detailed Rust documentation.
- Explore the [Python API Guide](./python-api.md) and [Python Examples](./python-examples.md) for more Python information.
- See the [examples]({{ site.github_url }}/tree/master/examples) directory in the repository for more complex use cases.