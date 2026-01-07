# Rustuya Examples

This directory contains examples demonstrating how to use Rustuya to interact with Tuya devices asynchronously.

## List of Examples

- **[control.rs](./control.rs)**: Demonstrates the fundamental ways to control a Tuya device asynchronously using `set_value` for single updates and `set_dps` for multiple updates.
- **[scan.rs](./scan.rs)**: Demonstrates using the asynchronous UDP scanner to find Tuya devices on the local network in real-time.

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
