# Rustuya Examples

This directory contains example code demonstrating the core features of the `rustuya` library.

## **Example List**

1.  **[control.rs](./control.rs)**: Basic device control example. Shows how to set a single DP (Data Point) and update multiple DPs simultaneously.
2.  **[scan.rs](./scan.rs)**: Real-time device discovery example. Scans the local network for Tuya devices and displays their information.
3.  **[unified_listener.rs](./unified_listener.rs)**: Unified event listener example. Demonstrates how to aggregate events from multiple devices into a single receiver.

---

## **How to Run**

Run each example using the `cargo run --example` command.

```bash
# Run the device control example
cargo run --example control

# Run the device discovery example
cargo run --example scan

# Run the unified listener example
cargo run --example unified_listener
```

---

## **Notes**

- Before running the examples, replace `device_id` and `device_key` in the code with actual device credentials.
- All examples utilize the synchronous API (`rustuya::sync`). Refer to the library documentation for asynchronous usage.
