# Rustuya

Rustuya is a high-performance, concurrency-friendly implementation of the Tuya Local API. It provides a robust interface for controlling and monitoring Tuya-compatible devices over a local network with minimal latency and high reliability.

---

## **Key Features**
- **High Performance**: Built on Rust's efficient asynchronous I/O and non-blocking execution.
- **Thread-Safe & Concurrent**: Designed for safe multi-threaded access across both Rust and Python environments.
- **Multi-language Support**: Native Rust API and high-performance PyO3-based Python bindings.
- **Resilient Connections**: Per-device background tasks handle automatic reconnection with exponential backoff.
- **System Optimization**: Built-in utilities to maximize system resources for large-scale device management.
- **Gateway & Sub-device Support**: Comprehensive support for Zigbee/Bluetooth gateways and sub-devices.
- **Real-time Monitoring**: Event-driven architecture providing instant status updates via streams or iterators.
- **Universal Compatibility**: Supports Tuya protocol versions 3.1 to 3.5, including the device22 variation.

---

## **Documentation**
- [**Getting Started**](./getting-started.md) - Installation and quick start guide for Rust and Python.
- [**Rust API Reference**](./rust-api.md) - Detailed reference for the core Rust library components.
- [**Python API Guide**](./python-api.md) - API reference and guide for Python integration.
- [**Python Examples**](./python-examples.md) - Practical code examples for common Python use cases.
- [**Design Philosophy**](./philosophy.md) - Core concepts and the underlying execution model.
- [**Architecture**](./architecture.md) - System design and internal component breakdown.
- [**FAQ**](./faq.md) - Frequently asked questions and troubleshooting.

---

## **Repository**
- **Source Code**: [{{ site.github_url }}]({{ site.github_url }})

## **Credits**
This library refers to the protocol specifications and error codes documented in [tinytuya](https://github.com/jasonacox/tinytuya):
- [Protocol Reference](https://github.com/jasonacox/tinytuya/blob/master/PROTOCOL.md)
