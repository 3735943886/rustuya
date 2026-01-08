# Rust API Reference

This document provides a detailed reference for the core components of Rustuya: `Device`, `SubDevice`, and `Scanner`. All core types are **thread-safe** and designed for high-concurrency environments.

### **Importing the Library**

Depending on your application architecture, choose the appropriate import path:

- **Asynchronous (Tokio)**:
  ```rust
  use rustuya::{Device, Scanner};
  ```
- **Synchronous (Blocking)**:
  ```rust
  use rustuya::sync::{Device, Scanner};
  ```

---

## **1. System Optimization**

### `maximize_fd_limit()`
- **Definition**: `pub fn maximize_fd_limit() -> Result<()>`
- **Description**: Maximizes the file descriptor limit for the current process. Essential for managing hundreds of concurrent device connections on Unix-like systems.
- **Returns**: `Result<()>`
- **Example**:
  ```rust
  rustuya::maximize_fd_limit().expect("Failed to optimize system limits");
  ```

---

## **2. Device API**
Direct interaction with individual Tuya devices.

### `Device::new()`
- **Definition**: `pub fn new<I, K>(id: I, local_key: K) -> Device`
- **Description**: Creates a new device handle with default settings (auto-discovery, version 3.3).
- **Arguments**: 
  - `id`: Device ID (String or &str)
  - `local_key`: Local Key (String, &str, or Vec<u8>)
- **Returns**: `Device`
- **Example**:
  ```rust
  let device = Device::new("id", "key");
  ```

### `Device::builder()`
- **Definition**: `pub fn builder<I, K>(id: I, local_key: K) -> DeviceBuilder`
- **Description**: Returns a builder to configure advanced settings before starting the connection.
- **Settings available in Builder**:
  - `.address(addr)`: Specific IP address (default: auto-discovery).
  - `.version(ver)`: Tuya protocol version (default: 3.3).
  - `.nowait(bool)`: Global `nowait` setting for this device instance.
  - `.persist(bool)`: Keep connection alive (default: true).
- **Example**:
  ```rust
  let device = Device::builder("id", "key")
      .address("192.168.1.100")
      .version("3.4")
      .nowait(true)
      .run();
  ```

### `device.status()`
- **Definition**: `pub async fn status(&self) -> Result<Option<String>>`
- **Description**: Requests current status (DPS values) from the device.
- **Returns**: `Result<Option<String>>` If `nowait=false`
- **Example**:
  ```rust
  let status = device.status().await?;
  ```

### `device.set_value()`
- **Definition**: `pub async fn set_value<I: ToString, T: Serialize>(&self, dp_id: I, value: T) -> Result<Option<String>>`
- **Description**: Sets a single DP value.
- **Arguments**: `dp_id` (e.g., "1"), `value` (e.g., `true`)
- **Returns**: `Result<Option<String>>` If `nowait=false`
- **Example**:
  ```rust
  device.set_value(1, true).await?;
  ```

### `device.set_dps()`
- **Definition**: `pub async fn set_dps(&self, dps: Value) -> Result<Option<String>>`
- **Description**: Sends a command to set multiple DPS values at once.
- **Arguments**: `dps`: A `serde_json::Value` object (e.g., `json!({"1": true, "2": 50})`)
- **Returns**: `Result<Option<String>>` If `nowait=false`
- **Example**:
  ```rust
  device.set_dps(json!({"1": true})).await?;
  ```

### `device.listener()`
- **Definition**: `pub fn listener(&self) -> impl Stream<Item = Result<TuyaMessage>>`
- **Description**: Returns an asynchronous stream of messages/events from this device.
- **Returns**: `impl Stream<Item = Result<TuyaMessage>>`
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
- **Returns**: `impl Stream<Item = Result<DeviceEvent>>`
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
- **Returns**: `Result<Option<String>>`
- **Example**:
  ```rust
  sub.set_value(1, "on").await?;
  ```

---

## **4. Scanner API**
UDP-based device discovery on the local network.

### `scanner.scan()`
- **Definition**: `pub async fn scan(&self) -> Result<Vec<DiscoveryResult>>`
- **Description**: Performs a one-time scan and returns all found devices.
- **Returns**: `Result<Vec<DiscoveryResult>>`
- **Example**:
  ```rust
  let scanner = Scanner::get();
  let devices = scanner.scan().await?;
  for device in devices {
      println!("Found device: {} at {}", device.id, device.ip);
  }
  ```

### `scanner.scan_stream()`
- **Definition**: `pub fn scan_stream(&self) -> impl Stream<Item = DiscoveryResult>`
- **Description**: Returns a stream that yields devices as they are discovered in real-time.
- **Returns**: `impl Stream<Item = DiscoveryResult>`
- **Example**:
  ```rust
  let scanner = Scanner::get();
  let mut stream = scanner.scan_stream();
  while let Some(device) = stream.next().await {
      println!("Discovered: {} ({})", device.id, device.ip);
  }
  ```
