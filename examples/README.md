# Rustuya Examples

This directory contains several examples demonstrating how to use Rustuya to interact with Tuya devices.

## List of Examples

- **[control.rs](./control.rs)**: Demonstrates the fundamental ways to control a Tuya device using `set_value` for single updates and `set_dps` for multiple updates.
- **[listen.rs](./listen.rs)**: Shows how to listen for real-time status updates and messages from a single Tuya device.
- **[manager.rs](./manager.rs)**: Demonstrates managing multiple Tuya devices using a single `Manager`, including setting up a global event listener.
- **[request.rs](./request.rs)**: Shows how to send specific Tuya commands directly to a device using the low-level `request` method.
- **[scan.rs](./scan.rs)**: Demonstrates using the synchronous UDP scanner to find Tuya devices on the local network.
- **[scan_async.rs](./scan_async.rs)**: Demonstrates using the asynchronous UDP scanner to find devices in real-time.
- **[subdevice.rs](./subdevice.rs)**: Demonstrates controlling a sub-device connected via a Tuya Gateway using the sub-device's CID.

## Running Examples

You can run any of these examples using `cargo run`:

```bash
cargo run --example <example_name>
```

For example, to run the scanner:

```bash
cargo run --example scan
```

*Note: Make sure to update the device information (ID, IP, Key, etc.) in the example files before running them.*
