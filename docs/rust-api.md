# Rust API Reference

This document provides a detailed reference for the core components of Rustuya: `Manager`, `Device`, `SubDevice`, and `Scanner`. All core types are **thread-safe** and designed for high-concurrency environments.

---

## **1. Manager API**
Centralized management for multiple devices, handling lifecycle and unified event streaming.

### `Manager::new()`
- **Definition**: `pub fn new() -> Self`
- **Description**: Creates a new manager instance.
- **Arguments**: None
- **Returns**: `Manager`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let manager = Manager::new();
  ```

### `manager.add()`
- **Definition**: `pub async fn add<V>(&self, id: &str, addr: &str, key: &str, ver: V) -> Result<Device>`
- **Description**: Registers a device with the manager. If a device with the same ID already exists:
  - If all parameters (addr, key, version) match exactly, returns a `DuplicateDevice` error.
  - If any parameter differs, it updates the existing device configuration (behaving like a modify) and returns the updated device.
- **Arguments**:
  - `id`: Unique device ID.
  - `addr`: IP address or "Auto" for discovery.
  - `key`: Local key for encryption.
  - `ver`: Protocol version (e.g., "3.1", "3.3", "3.4", "3.5") or "Auto" for discovery.
- **Returns**: `Result<Device>`
- **Behavior**: Returns the registered or updated device handle, allowing for method chaining.
- **Example**:
  ```rust
  let device = manager.add(DEVICE_ID, DEVICE_IP, DEVICE_KEY, DEVICE_VER).await?.with_nowait(true);
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
- **Arguments**: None
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

### `manager.list()`
- **Definition**: `pub async fn list(&self) -> Vec<DeviceInfo>`
- **Description**: Returns a list of all devices currently managed by this instance with status information.
- **Arguments**: None
- **Returns**: `Vec<DeviceInfo>`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let devices = manager.list().await;
  ```

### `manager.listener()`
- **Definition**: `pub fn listener(&self) -> impl Stream<Item = ManagerEvent>`
- **Description**: Returns an asynchronous stream of events from all devices managed by this instance.
- **Arguments**: None
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
- **Description**: (Unix-like systems only) Attempts to increase the process file descriptor limit to handle more concurrent connections. Fails on non-Unix platforms or if the OS prevents the increase.
- **Arguments**: None
- **Returns**: None
- **Example**: `Manager::maximize_fd_limit();`

---

## **2. Device API**
Direct interaction with individual Tuya devices.

### `Device::new()`
- **Definition**: `pub fn new(id: &str, address: &str, local_key: &str, version: &str) -> Self`
- **Description**: Creates a new device handle.
- **Arguments**: `id`, `address`, `local_key`, `version`.
- **Returns**: `Device`
- **Example**: `let device = Device::new("id", "ip", "key", "3.3");`

### `device.set_nowait()`
- **Definition**: `pub fn set_nowait(&self, nowait: bool)`
- **Description**: Configures whether command methods should wait for TCP transmission.
  - When `false` (default), methods wait until the command is written to the socket.
  - When `true`, methods return immediately after queuing the command.
- **Arguments**: `nowait` (bool)
- **Returns**: None
- **Note**: For detailed behavior and automation risks, see [API Design Philosophy](./philosophy#2-synchronous-command-dispatch--nowait-configuration).
- **Example**: `device.set_nowait(true);`

### `device.status()`
- **Definition**: `pub async fn status(&self)`
- **Description**: Requests current status (DPS values) from the device.
- **Returns**: None (Response is received via [listener](#devicelistener))
- **Behavior**: Respects `nowait` setting.
- **Example**: `device.status().await;`

### `device.set_value()`
- **Definition**: `pub async fn set_value<I: ToString, T: Serialize>(&self, dp_id: I, value: T)`
- **Description**: Helper to set a single DP value.
- **Arguments**: `dp_id` (e.g., "1"), `value` (e.g., `true`)
- **Returns**: None
- **Behavior**: Waits for TCP transmission by default (`nowait=false`). If `nowait` is `true`, it returns immediately after queuing.
- **Example**:
  ```rust
  device.set_value("1", true).await;
  ```
  
### `device.set_dps()`
- **Definition**: `pub async fn set_dps(&self, dps: Value)`
- **Description**: Sends a command to set multiple DPS values.
- **Arguments**: `dps`: A `serde_json::Value` object
- **Returns**: None
- **Behavior**: Waits for TCP transmission by default (`nowait=false`). If `nowait` is `true`, it returns immediately after queuing.
- **Example**:
  ```rust
  device.set_dps(json!({"1": true, "2": 50})).await;
  ```

### `device.listener()`
- **Definition**: `pub fn listener(&self) -> impl Stream<Item = Result<TuyaMessage>>`
- **Description**: Returns a stream of messages/events from this specific device.
- **Arguments**: None
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
- **Behavior**: Waits for TCP transmission by default (`nowait=false`). If `nowait` is `true`, it returns immediately after queuing.
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
- **Arguments**: None
- **Returns**: None (Response is received via [listener](#devicelistener))
- **Behavior**: Waits for TCP transmission by default (`nowait=false`). If `nowait` is `true`, it returns immediately after queuing.
- **Example**:
  ```rust
  device.sub_discover().await;
  ```

#### `device.sub()`
- **Definition**: `pub fn sub(&self, cid: &str) -> SubDevice`
- **Description**: Returns a `SubDevice` handle for an endpoint connected via the gateway.
- **Arguments**: `cid`: Child ID
- **Returns**: `SubDevice`
- **Behavior**: Immediate return
- **Example**:
  ```rust
  let sub_device = device.sub("child_id_123");
  ```

---

## **3. SubDevice API**
API for interacting with sub-devices (endpoints) through a parent Gateway `Device`. These objects are obtained via `device.sub(cid)`.

> [!NOTE]
> **Gateway Configuration**: `SubDevice` objects share the connection and configuration of their parent Gateway. For example, calling `set_nowait()` on the parent Gateway will also affect all its sub-devices.

### `sub_device.status()`
- **Definition**: `pub async fn status(&self)`
- **Description**: Requests the status for the sub-device via the gateway.
- **Returns**: None (Response is received via parent device's [listener](#devicelistener))
- **Behavior**: Respects `nowait` setting of the parent `Device`.
- **Example**:
  ```rust
  sub_device.status().await;
  ```

### `sub_device.set_value()`
- **Definition**: `pub async fn set_value<I: ToString, T: Serialize>(&self, index: I, value: T)`
- **Description**: Sets a single DP value for the sub-device.
- **Arguments**: `index` (DP ID), `value` (Serializable value)
- **Returns**: None
- **Behavior**: Waits for TCP transmission by default (`nowait=false`). If `nowait` is `true` (on the parent Gateway), it returns immediately after queuing.
- **Example**:
  ```rust
  sub_device.set_value(1, true).await;
  ```

### `sub_device.set_dps()`
- **Definition**: `pub async fn set_dps(&self, dps: Value)`
- **Description**: Sets multiple DPS values for the sub-device.
- **Arguments**: `dps`: A `serde_json::Value` object
- **Returns**: None
- **Behavior**: Waits for TCP transmission by default (`nowait=false`). If `nowait` is `true` (on the parent Gateway), it returns immediately after queuing.
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
- **Behavior**: Waits for TCP transmission by default (`nowait=false`). If `nowait` is `true` (on the parent Gateway), it returns immediately after queuing.
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
- **Arguments**: None
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
- **Arguments**: None
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
- **Arguments**: None
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
