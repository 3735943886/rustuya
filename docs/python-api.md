# Python API Reference

This document provides a detailed reference for the `rustuya` Python bindings. The Python API is a synchronous, thread-safe wrapper around the high-performance Rust core.

For practical code examples, see the [Python Examples](./python-examples.md) page.

---

## **1. Manager API**
The `Manager` is used for managing multiple devices simultaneously and receiving a unified event stream.

### `Manager()`
- **Description**: Creates a new manager instance.
- **Example**:
  ```python
  from rustuya import Manager
  mgr = Manager()
  ```

### `Manager.maximize_fd_limit()` (Static)
- **Description**: (Unix-like systems only) Increases the process file descriptor limit. Recommended when managing a large number of devices.
- **Example**: `Manager.maximize_fd_limit()`

### `manager.add(id, address, local_key, version)`
- **Description**: Registers a device with the manager. Starts a background connection task.
- **Arguments**:
  - `id`: Unique device ID.
  - `address`: IP address or "Auto" for discovery.
  - `local_key`: Local key for encryption.
  - `version`: Protocol version (e.g., "3.1", "3.3", "3.4", "3.5") or "Auto" for discovery.
- **Example**: `mgr.add("id", "192.168.1.100", "key", "3.3")`

### `manager.get(id)`
- **Description**: Returns a `Device` handle for the given ID. Returns `None` if not found.
- **Example**: `dev = mgr.get("id")`

### `manager.remove(id)`
- **Description**: Removes a device from the manager's tracking.
- **Example**: `mgr.remove("id")`

### `manager.list()`
- **Description**: Returns a list of `DeviceInfo` objects for all managed devices.
- **Example**: `devices = mgr.list()`

### `manager.listener()`
- **Description**: Returns a `ManagerEventReceiver` to iterate over events from all managed devices.
- **Example**:
  ```python
  for event in mgr.listener():
      print(f"Device {event['device_id']} sent: {event['payload']}")
  ```

---

## **2. Device API**
Direct interaction and control for individual Tuya devices.

### `Device(id, address, local_key, version)`
- **Description**: Creates a new device handle.
- **Note**: `Device` objects obtained via `manager.get()` provide the same functionality.

### `device.status()`
- **Description**: Requests the current status (all DPS) from the device.
- **Returns**: None (Results arrive via listener).

### `device.set_value(dp_id, value)`
- **Description**: Sets a single DP value.
- **Arguments**: `dp_id` (int or str), `value` (bool, int, str, etc.).

### `device.set_dps(dps_dict)`
- **Description**: Sets multiple DP values at once.
- **Arguments**: A dictionary of DP ID to value.
- **Example**: `dev.set_dps({"1": True, "2": 50})`

### `device.listener()`
- **Description**: Returns a `DeviceMessageReceiver` that yields messages from the device.
- **Example**:
  ```python
  listener = dev.listener()
  msg = listener.recv(timeout_ms=5000) # Optional timeout
  ```

### **Advanced Usage**

#### `device.request(command, data=None, cid=None)`
- **Description**: Low-level method to send a raw Tuya command.
- **Arguments**: `command` (int from `CommandType`), `data` (dict, optional), `cid` (str, optional).
- **Example**:
  ```python
  from rustuya import CommandType
  dev.request(CommandType["DpQuery"], None)
  ```

### **Gateway API**

#### `device.sub_discover()`
- **Description**: Sends a command to the gateway to discover connected sub-devices.

#### `device.sub(cid)`
- **Description**: Returns a `SubDevice` handle for the given cid.
- **Example**: `sub_device = dev.sub("sub_id_123")`

---

## **3. SubDevice API**
API for interacting with sub-devices (endpoints) through a parent Gateway `Device`. These objects are obtained via `device.sub(cid)`.

### `sub_device.status()`
- **Description**: Requests status for the sub-device via the gateway.

### `sub_device.set_value(dp_id, value)`
- **Description**: Sets a single DP value for the sub-device.

### `sub_device.set_dps(dps_dict)`
- **Description**: Sets multiple DP values for the sub-device.

### **Advanced Usage**
- **Note**: Sub-devices do not have a direct `request()` method. To send raw commands to a sub-device, use the parent `Device` handle's `request()` method and provide the sub-device's ID as the `cid` argument.
- **Example**:
  ```python
  from rustuya import CommandType
  # Use parent device to send request to sub-device
  parent_dev.request(CommandType["DpQuery"], None, cid=sub_dev.id)
  ```

---

## **4. Scanner API**
Used for discovering Tuya devices on the local network via UDP broadcast.

### `Scanner()`
- **Description**: Creates a new scanner instance with default settings.

### `scanner.with_timeout(timeout_ms)`
- **Description**: Sets the scan duration in milliseconds. Returns a new configured `Scanner`.

### `scanner.set_bind_address(address)`
- **Description**: Sets the local IP address to bind to for discovery.

### `scanner.scan()`
- **Description**: Performs an active scan and returns a list of discovered devices.
- **Example**: 
  ```python
  from rustuya import Scanner
  results = Scanner().with_timeout(5000).scan()
  for device in results:
      print(f"Found: {device['id']} at {device['ip']}")
  ```
