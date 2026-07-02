# Rust API Reference

This document provides a detailed reference for the core components of Rustuya: `Device`, `SubDevice`, and `Scanner`. All core types are **thread-safe** and designed for high-concurrency environments.

### **Importing the Library**

Depending on the application architecture, select the appropriate import path:

- **Asynchronous (Tokio)**:
  ```rust
  use rustuya::{Device, Scanner};
  ```
- **Synchronous (Blocking)**:
  ```rust
  use rustuya::sync::{Device, Scanner};
  ```

#### Choosing sync vs async

Both facades wrap the same internal actor and reach the same backing Tokio
runtime — the `sync` types are just blocking bridges. Pick by the context you
call from:

| When you're calling from… | Use |
|---|---|
| A non-async program (CLI, sync binary, scripting helpers) | `rustuya::sync::{Device, SubDevice, Scanner}` |
| Inside a `tokio` runtime (`#[tokio::main]`, `tokio::spawn`, axum, etc.) | `rustuya::{Device, DeviceBuilder, Scanner}` (async) |

Calling the **sync** API from inside a Tokio runtime is **not** supported: the
wrappers use `blocking_send`, which would otherwise panic. Since v0.3.0 a
runtime guard turns that into a clear error, but choose the right facade up
front rather than relying on the guard.

---

## **1. System Optimization**

### `maximize_fd_limit()`
- **Definition**: `pub fn maximize_fd_limit() -> Result<()>`
- **Description**: Maximizes the file descriptor limit for the current process. Essential for managing hundreds of concurrent device connections on Unix-like systems.
- **Example**:
  ```rust
  rustuya::maximize_fd_limit().expect("Failed to optimize system limits");
  ```

---

## **2. Device API**
Direct interaction with individual Tuya devices.

### `Device::new()`
- **Definition**: `pub fn new<I, K>(id: I, local_key: K) -> Device`
- **Description**: Creates a new device handle with default settings (auto-discovery).
- **Arguments**: 
  - `id`: Device ID (String or &str)
  - `local_key`: Local Key (String, &str, or Vec<u8>)
- **Example**:
  ```rust
  let device = Device::new("DEVICE_ID", "LOCAL_KEY");
  ```

### `Device::builder()`
- **Definition**: `pub fn builder<I, K>(id: I, local_key: K) -> DeviceBuilder`
- **Description**: Returns a builder to configure advanced settings before starting the connection.
- **Settings available in Builder**:
    - `.address(addr)`: Specific IP address (default: auto-discovery).
    - `.version(ver)`: Tuya protocol version (default: auto).
    - `.dev_type(type)`: Device type (default: auto). Values: auto, default, device22.
    - `.persist(bool)`: Keep connection alive (default: true).
    - `.timeout(Duration)`: Global timeout for network operations and responses (default: 10s).
    - `.nowait(bool)`: Do not wait for response (default: false).
- **Example**:
  ```rust
  use rustuya::{Device, Version};

  let device = Device::builder("DEVICE_ID", "LOCAL_KEY")
      .address("192.168.1.100")
      .version(Version::V3_4)            // or "3.4".parse::<Version>()?
      .nowait(true)
      .build();
  ```

### `device.status()`
- **Definition**: `pub async fn status(&self) -> Result<Option<String>>`
- **Description**: Requests current status (DPS values) from the device.
- **Example**:
  ```rust
  let status = device.status().await?;
  ```

### `device.set_value()`
- **Definition**: `pub async fn set_value<I: ToString, T: Serialize>(&self, dp_id: I, value: T) -> Result<Option<String>>`
- **Description**: Sets a single DP value.
- **Arguments**: `dp_id` (e.g., "1"), `value` (e.g., `true`)
- **Example**:
  ```rust
  device.set_value(1, true).await?;
  ```

### `device.set_dps()`
- **Definition**: `pub async fn set_dps(&self, dps: Value) -> Result<Option<String>>`
- **Description**: Sends a command to set multiple DPS values at once.
- **Arguments**: `dps`: A `serde_json::Value` object (e.g., `json!({"1": true, "2": 50})`)
- **Example**:
  ```rust
  device.set_dps(json!({"1": true})).await?;
  ```

### `device.listener()`
- **Definition**: `pub fn listener(&self) -> impl Stream<Item = Result<TuyaMessage>>`
- **Description**: Returns an asynchronous stream of messages/events from this device.
- **Example**:
  ```rust
  let mut listener = device.listener();
  while let Some(msg) = listener.next().await {
      println!("Received: {:?}", msg);
  }
  ```

### `unified_listener()`
- **Definition**: `pub fn unified_listener(devices: Vec<Device>) -> impl Stream<Item = Result<DeviceEvent>>`
- **Description**: Aggregates event streams from multiple devices into a single unified stream.
- **Example**:
  ```rust
  let listener = unified_listener(vec![dev1, dev2]);
  ```

---

## **3. SubDevice API**
Interaction with sub-devices (endpoints) through a parent Gateway `Device`. Obtained via `device.sub(cid)`.

### `device.sub()`
- **Definition**: `pub fn sub(&self, cid: &str) -> SubDevice`
- **Description**: Creates a handle for a sub-device.
- **Arguments**: `cid`: Child ID of the sub-device.
- **Example**:
  ```rust
  let sub = gateway.sub("sub_id");
  ```

### `sub_device.status()` / `set_value()` / `set_dps()`
- **Description**: These methods mirror the `Device` API but target the specific sub-device via the parent gateway.
- **Example**:
  ```rust
  sub.set_value(1, true).await?;
  ```

---

## **4. Scanner API**
UDP-based device discovery on the local network.

### `Scanner::scan()`
- **Definition**: `pub async fn scan() -> Result<Vec<DiscoveryResult>>`
- **Description**: Performs a one-time scan using the global scanner instance and returns all found devices.
- **Example**:
  ```rust
  let devices = Scanner::scan().await?;
  for device in devices {
      println!("Found device: {} at {}", device.id, device.ip);
  }
  ```

### `Scanner::scan_stream()`
- **Definition**: `pub fn scan_stream() -> impl Stream<Item = DiscoveryResult>`
- **Description**: Returns a stream from the global scanner instance that yields devices as they are discovered in real-time.
- **Example**:
  ```rust
  let mut stream = Scanner::scan_stream();
  while let Some(device) = stream.next().await {
      println!("Found device: {} at {}", device.id, device.ip);
  }
  ```

### Advanced configuration (multi-homed hosts)

Every knob below takes `&self` and mutates the shared global scanner state; they exist on both the async `Scanner` and `rustuya::sync::Scanner`.

- **`set_bind_address(addr: &str)`** — bind address for the passive listener. A concrete unicast IP is **transparently widened to the family wildcard** (`0.0.0.0` / `::`) with a warning, because a socket bound to a specific unicast address does not receive limited-broadcast (`255.255.255.255`) discovery packets. `0.0.0.0`/`::` and loopback are used exactly as given.
- **`set_discovery_sources(sources: Vec<IpAddr>)` / `discovery_sources()`** — explicit source IP(s) for the **active** discovery broadcast. Empty (the default) auto-detects the source via a kernel route lookup. On a multi-homed host, configure one IPv4 per subnet you want to actively probe: each is used as the send socket's bind source (so the broadcast egresses the right interface) and as the v3.5 payload `ip` (so devices reply to a reachable address). Sending only — the passive listener still receives unsolicited broadcasts on every interface. IPv4-only.
  ```rust
  let scanner = Scanner::get(); // sync facade; async: Scanner::new()
  scanner.set_discovery_sources(vec![
      "192.168.1.10".parse().unwrap(),
      "10.0.20.5".parse().unwrap(),
  ]);
  ```
