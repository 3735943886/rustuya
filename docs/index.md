# Rustuya

Rustuya is a high-performance, concurrency-friendly implementation of the Tuya Local API. It provides a robust way to control and monitor Tuya-compatible devices over the local network with minimal latency and high reliability.

---

## **Key Features**
- **High Performance**: Built on Rust's `tokio` for efficient asynchronous I/O.
- **Thread-Safe & Concurrent**: Designed for safe multi-threaded access across both Rust and Python.
- **Multi-language Support**: Native Rust API and high-level Python bindings.
- **Robust Connection Management**: Automatic background reconnection with exponential backoff.
- **Gateway & Sub-device Support**: Comprehensive support for Zigbee/Bluetooth gateways and sub-devices.
- **Real-time Monitoring**: Event-driven architecture for instant status updates.
- **Universal Compatibility**: Supports Tuya protocol versions 3.1, 3.3, 3.4, 3.5, and device22.

---

## **Documentation**
- [**Getting Started**](./getting-started) - Quick installation and usage guide for Rust and Python.
- [**Rust API Reference**](./rust-api) - Detailed documentation for the core Rust library.
- [**Python API Guide**](./python-api) - Guide and reference for Python developers.
- [**Python Examples**](./python-examples) - Practical code examples for Python.
- [**Design Philosophy**](./philosophy) - Understanding how Rustuya works under the hood.
- [**Architecture**](./architecture) - Internal structure and module overview.
- [**FAQ**](./faq) - Frequently asked questions.

---

## **Repository**
- **Source Code**: [{{ site.github_url }}]({{ site.github_url }})

## **Credits**
This library refers to the protocol specifications and error codes documented in [tinytuya](https://github.com/jasonacox/tinytuya):
- [Protocol Reference](https://github.com/jasonacox/tinytuya/blob/master/PROTOCOL.md)
