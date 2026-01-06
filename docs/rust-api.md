# Rust API Reference

This document provides a detailed reference for the core components of Rustuya: `Manager`, `Device`, `SubDevice`, and `Scanner`.

> [!TIP]
> **Thread-Safety**: All core types and the synchronous wrappers are **thread-safe**. They can be safely cloned and shared across multiple threads.

---

## **1. Manager API**
Centralized management for multiple devices, handling lifecycle and unified event streaming.

### `Manager::new()`
- **Definition**: `pub fn new() -> Self`
- **Description**: Creates a new manager instance.
- **Arguments**: None.
- **Returns**: `Manager`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let manager = Manager::new();
  ```

### `manager.add()`
- **Definition**: `pub async fn add<V>(&self, id: &str, addr: &str, key: &str, ver: V) -> Result<()>`
- **Description**: Registers a device with the manager. This starts a background connection task and event forwarder. Fails if the device ID is already registered or internal registry errors occur.
- **Arguments**:
  - `id`: Unique device ID.
  - `addr`: IP address or "Auto" for discovery.
  - `key`: Local key for encryption.
  - `ver`: Protocol version (e.g., "3.1", "3.3", "3.4", "3.5") or "Auto" for discovery.
- **Returns**: `Result<()>`
- **Behavior**: Immediate return (after registration)
- **Example**:
  ```rust
  manager.add(DEVICE_ID, DEVICE_IP, DEVICE_KEY, DEVICE_VER).await?;
  ```

### `manager.get()`
- **Definition**: `pub async fn get(&self, id: &str) -> Option<Device>`
- **Description**: Retrieves a specific `Device` instance by ID.
- **Arguments**: `id`: Device ID.
- **Returns**: `Option<Device>`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  if let Some(device) = manager.get(DEVICE_ID).await {
      // Use device
  }
  ```

### `manager.remove()`
- **Definition**: `pub async fn remove(&self, id: &str)`
- **Description**: Removes a device from the manager's tracking.
- **Arguments**: `id`: Device ID to remove.
- **Returns**: None
- **Behavior**: Immediate return
- **Example**:
  ```rust
  manager.remove(DEVICE_ID).await;
  ```

### `manager.clear()`
- **Definition**: `pub async fn clear(&self)`
- **Description**: Removes all devices currently tracked by this manager instance.
- **Arguments**: None.
- **Returns**: None
- **Behavior**: Immediate return
- **Example**:
  ```rust
  manager.clear().await;
  ```

### `manager.delete()`
- **Definition**: `pub async fn delete(&self, id: &str)`
- **Description**: Forcefully deletes a device from the global registry, stopping its connection task even if other managers are using it.
- **Arguments**: `id`: Device ID to delete.
- **Returns**: None
- **Behavior**: Immediate return
- **Example**:
  ```rust
  manager.delete(DEVICE_ID).await;
  ```

### `manager.modify()`
- **Definition**: `pub async fn modify<V>(&self, id: &str, addr: &str, key: &str, ver: V) -> Result<()>`
- **Description**: Updates the configuration for an existing device. Fails if the device ID is not found.
- **Arguments**: Same as `add()`.
- **Returns**: `Result<()>`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  manager.modify(DEVICE_ID, NEW_IP, DEVICE_KEY, DEVICE_VER).await?;
  ```

### `manager.list()`
- **Definition**: `pub async fn list(&self) -> Vec<DeviceInfo>`
- **Description**: Returns a list of all devices currently managed by this instance with status information.
- **Arguments**: None.
- **Returns**: `Vec<DeviceInfo>`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let devices = manager.list().await;
  ```

### `manager.listener()`
- **Definition**: `pub fn listener(&self) -> impl Stream<Item = ManagerEvent>`
- **Description**: Returns an asynchronous stream of events from all devices managed by this instance.
- **Arguments**: None.
- **Returns**: `impl Stream<Item = ManagerEvent>`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let mut events = manager.listener();
  while let Some(event) = events.next().await {
      println!("Event: {:?}", event);
  }
  ```

### `Manager::maximize_fd_limit()`
- **Definition**: `pub fn maximize_fd_limit() -> Result<()>`
- **Description**: (Unix-only) Attempts to increase the process file descriptor limit to handle more concurrent connections. Fails on non-Unix platforms or if the OS prevents the increase.
- **Arguments**: None.
- **Returns**: `Result<()>`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  Manager::maximize_fd_limit()?;
  ```

---

## **2. Device API**
Direct interaction and control for individual Tuya devices.

### `Device::new()`
- **Definition**: `pub fn new(id, addr, key, ver) -> Self`
- **Description**: Creates a device object. The actual connection is managed automatically in the background. Note that `Device` instances obtained through `manager.add()` and `manager.get()` provide the same functionality and handle as those created directly via `new()`.
- **Arguments**: `id`, `addr`, `key`, `ver`.
- **Returns**: `Device`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let device = Device::new(DEVICE_ID, DEVICE_IP, DEVICE_KEY, DEVICE_VER);
  ```

### `device.status()`
- **Definition**: `pub async fn status(&self)`
- **Description**: Requests the current status (all DPS values) from the device.
- **Arguments**: None.
- **Returns**: None
- **Behavior**: Wait until dispatched (Results arrive via listener)
- **Example**:
  ```rust
  device.status().await;
  ```

### `device.set_value()`
- **Definition**: `pub async fn set_value<I: ToString, T: Serialize>(&self, dp_id: I, value: T)`
- **Description**: Helper to set a single DP value.
- **Arguments**: `dp_id` (e.g., "1"), `value` (e.g., `true`).
- **Returns**: None
- **Behavior**: Wait until dispatched
- **Example**:
  ```rust
  device.set_value("1", true).await;
  ```
  
### `device.set_dps()`
- **Definition**: `pub async fn set_dps(&self, dps: Value)`
- **Description**: Sends a command to set multiple DPS values.
- **Arguments**: `dps`: A `serde_json::Value` object.
- **Returns**: None
- **Behavior**: Wait until dispatched
- **Example**:
  ```rust
  device.set_dps(json!({"1": true, "2": 50})).await;
  ```

### `device.listener()`
- **Definition**: `pub fn listener(&self) -> impl Stream<Item = Result<TuyaMessage>>`
- **Description**: Returns a stream of messages/events from this specific device.
- **Arguments**: None.
- **Returns**: `impl Stream`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let mut listener = device.listener();
  while let Some(msg) = listener.next().await {
      println!("Received: {:?}", msg);
  }
  ```

### Advanced Usage

#### `device.request()`
- **Definition**: `pub async fn request(&self, command: CommandType, data: Option<Value>, cid: Option<String>)`
- **Description**: Low-level method to send a raw Tuya command. This is used internally by other high-level methods.
- **Arguments**:
  - `command`: The `CommandType` to send (e.g., `CommandType::DpQuery`).
  - `data`: Optional JSON payload.
  - `cid`: Optional Child ID for gateway sub-devices.
- **Returns**: None
- **Behavior**: Wait until dispatched
- **Example**:
  ```rust
  use rustuya::CommandType;
  device.request(CommandType::DpQuery, None, None).await;
  ```

### Gateway API
These methods are used for interacting with sub-devices connected via a Tuya Gateway.

#### `device.sub_discover()`
- **Definition**: `pub async fn sub_discover(&self)`
- **Description**: Sends a command to the gateway to discover its connected sub-devices.
- **Arguments**: None.
- **Returns**: None
- **Behavior**: Wait until dispatched
- **Example**:
  ```rust
  device.sub_discover().await;
  ```

#### `device.sub()`
- **Definition**: `pub fn sub(&self, cid: &str) -> SubDevice`
- **Description**: Returns a `SubDevice` handle for an endpoint connected via the gateway.
- **Arguments**: `cid`: Child ID.
- **Returns**: `SubDevice`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let sub_device = device.sub("child_id_123");
  ```

---

## **3. SubDevice API**
API for interacting with sub-devices (endpoints) through a parent Gateway `Device`. These objects are obtained via `device.sub(cid)`.

### `sub_device.status()`
- **Definition**: `pub async fn status(&self)`
- **Description**: Requests the current status from the sub-device via the gateway.
- **Returns**: None
- **Behavior**: Wait until dispatched
- **Example**:
  ```rust
  sub_device.status().await;
  ```

### `sub_device.set_value()`
- **Definition**: `pub async fn set_value<I: ToString, T: Serialize>(&self, index: I, value: T)`
- **Description**: Sets a single DP value for the sub-device.
- **Arguments**: `index` (DP ID), `value` (Serializable value).
- **Returns**: None
- **Behavior**: Wait until dispatched
- **Example**:
  ```rust
  sub_device.set_value(1, true).await;
  ```

### `sub_device.set_dps()`
- **Definition**: `pub async fn set_dps(&self, dps: Value)`
- **Description**: Sets multiple DPS values for the sub-device.
- **Arguments**: `dps`: A `serde_json::Value` object.
- **Returns**: None
- **Behavior**: Wait until dispatched
- **Example**:
  ```rust
  sub_device.set_dps(json!({"1": false, "2": 30})).await;
  ```

### Advanced Usage

#### `sub_device.request()`
- **Definition**: `pub async fn request(&self, cmd: CommandType, data: Option<Value>)`
- **Description**: Low-level method to send a raw Tuya command to the sub-device via the gateway.
- **Arguments**:
  - `cmd`: The `CommandType` to send.
  - `data`: Optional JSON payload.
- **Returns**: None
- **Behavior**: Wait until dispatched
- **Example**:
  ```rust
  use rustuya::CommandType;
  sub_device.request(CommandType::DpQuery, None).await;
  ```

---

## **4. Scanner API**
Used for discovering Tuya devices on the local network via UDP broadcast.

### `Scanner::new()`
- **Definition**: `pub fn new() -> Self`
- **Description**: Creates a new scanner with default settings (timeout: 18s, bind: 0.0.0.0).
- **Arguments**: None.
- **Returns**: `Scanner`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let scanner = Scanner::new(); // Uses default configuration
  ```

### `Scanner` Configuration
These methods use the builder pattern to configure the scanner before performing a scan.

#### `with_timeout()` / `with_bind_addr()`
- **Definitions**: 
  - `pub fn with_timeout(mut self, timeout: Duration) -> Self`
  - `pub fn with_bind_addr(mut self, addr: String) -> Self`
- **Description**: Configures the scan timeout and local interface binding.
- **Returns**: `Scanner` (Self)
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let scanner = Scanner::new()
      .with_timeout(Duration::from_secs(18))
      .with_bind_addr("0.0.0.0".to_string());
  ```

### `scanner.scan()`
- **Definition**: `pub async fn scan(&self) -> Result<Vec<DiscoveryResult>>`
- **Description**: Performs an active scan and returns a list of all discovered devices. Fails if UDP port binding fails or network interface issues occur.
- **Arguments**: None.
- **Returns**: `Result<Vec<DiscoveryResult>>`
- **Behavior**: Wait until discovery timeout
- **Example**:
  ```rust
  // Simple usage (default settings):
  let devices = Scanner::new().scan().await?;

  // Custom configuration:
  let devices = Scanner::new()
      .with_timeout(Duration::from_secs(18))
      .with_bind_addr("0.0.0.0".to_string())
      .scan()
      .await?;
  ```

### `scanner.scan_stream()`
- **Definition**: `pub fn scan_stream(&self) -> impl Stream<Item = DiscoveryResult>`
- **Description**: Performs an active scan and returns a stream that yields devices as they are found.
- **Arguments**: None.
- **Returns**: `impl Stream`
- **Behavior**: Immediate return (returns stream handle)
- **Example**:
  ```rust
  // Simple usage (default settings):
  let stream = Scanner::new().scan_stream();

  // Custom configuration:
  let stream = Scanner::new()
      .with_timeout(Duration::from_secs(18))
      .scan_stream();
  ```
