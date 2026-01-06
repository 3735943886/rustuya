# Python API Reference

This document provides a detailed reference for the `rustuya` Python bindings. The Python API is a synchronous, thread-safe wrapper around the high-performance Rust core.

For practical code examples, see the [Python Examples](./python-examples) page.

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
- **Description**: Registers a device with the manager. If a device with the same ID already exists:
  - If all parameters (address, local_key, version) match exactly, raises a `DuplicateDevice` error.
  - If any parameter differs, updates the existing device configuration and returns the updated `Device` handle.
- **Arguments**:
  - `id`: Unique device ID.
  - `address`: IP address or "Auto" for discovery.
  - `local_key`: Local key for encryption.
  - `version`: Protocol version (e.g., "3.1", "3.3", "3.4", "3.5") or "Auto" for discovery.
- **Returns**: `Device` handle.
- **Example**: `dev = mgr.add("id", "ip", "key", "ver")`

### `manager.get(id)` / `manager[id]`
- **Description**: Retrieves a `Device` handle for the given ID.
  - `manager.get(id)`: Returns `None` if the ID is not found.
  - `manager[id]`: Raises `KeyError` if the ID is not found.
- **Example**:
  ```python
  dev = mgr.get("id")
  dev = mgr["id"]
  ```

### `manager.remove(id)`
- **Description**: Removes a device from the manager's tracking. This releases the manager's reference to the device.
- **Example**: `mgr.remove("id")`

### `manager.delete(id)`
- **Description**: Forcefully deletes a device from the global registry, stopping its connection task even if other managers are using it.
- **Example**: `mgr.delete("id")`

### `len(manager)`
- **Description**: Returns the number of devices currently managed by this instance.
- **Example**: `count = len(mgr)`

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
- **Chaining**: All configuration methods (e.g., `with_persist`, `with_port`) return the device handle, allowing for method chaining.
- **Example**:
  ```python
  dev = Device("id", "address", "key", "version")
  ```

### `device.set_nowait(nowait: bool)`
- **Description**: Configures whether command methods should wait for TCP transmission.
  - When `false` (default), methods wait until the command is written to the socket.
  - When `true`, methods return immediately after queuing the command.
- **Returns**: `Device` (Self) for chaining.
- **Note**: For detailed behavior and automation risks, see [API Design Philosophy](./philosophy#2-synchronous-command-dispatch--nowait-configuration).
- **Example**: `dev.set_nowait(True)`

### `device.status()`
- **Description**: Requests current status (DPS) from the device.
- **Returns**: None
- **Behavior**: Respects `nowait` setting.
- **Example**: `dev.status()`

### `device.set_value(dp_id, value)`
- **Description**: Sets a single DP value.
- **Behavior**: Respects `nowait` setting.
- **Arguments**: `dp_id` (int or str), `value` (bool, int, str, etc.).

### `device.set_dps(dps_dict)`
- **Description**: Sets multiple DP values at once.
- **Behavior**: Respects `nowait` setting.
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
- **Behavior**: Respects `nowait` setting.
- **Arguments**: `command` (int from `CommandType`), `data` (dict, optional), `cid` (str, optional).
- **Example**:
  ```python
  from rustuya import CommandType
  dev.request(CommandType["DpQuery"], None)
  ```

### **Gateway API**

#### `device.sub_discover()`
- **Description**: Sends a command to the gateway to discover connected sub-devices.
- **Behavior**: Respects `nowait` setting.

#### `device.sub(cid)`
- **Description**: Returns a `SubDevice` handle for the given cid.
- **Example**: `sub_device = dev.sub("sub_id_123")`

---

## **3. SubDevice API**
API for interacting with sub-devices (endpoints) through a parent Gateway `Device`. These objects are obtained via `device.sub(cid)`.

> [!NOTE]
> **Gateway Configuration**: `SubDevice` objects share the connection and configuration of their parent Gateway. For example, setting `set_nowait()` on the parent Gateway will also affect all its sub-devices.

### `sub_device.id` (Property)
- **Description**: Returns the sub-device ID.

### `sub_device.status()`
- **Description**: Requests status for the sub-device via the gateway.
- **Behavior**: Respects `nowait` setting (on parent Gateway).

### `sub_device.set_value(dp_id, value)`
- **Description**: Sets a single DP value for the sub-device.
- **Behavior**: Respects `nowait` setting (on parent Gateway).

### `sub_device.set_dps(dps_dict)`
- **Description**: Sets multiple DP values for the sub-device.
- **Behavior**: Respects `nowait` setting (on parent Gateway).

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

### `scanner.timeout(timeout_sec)`
- **Description**: Sets the scan duration in seconds.
- **Returns**: `Scanner` (Self) for chaining.
- **Example**: `Scanner().timeout(2.0)`

### `scanner.bind_address(address)`
- **Description**: Sets the local IP address to bind to for discovery.
- **Returns**: `Scanner` (Self) for chaining.
- **Example**: `Scanner().bind_address("0.0.0.0")`

### `scanner.scan()`
- **Description**: Performs an active scan and returns a list of discovered devices.
- **Example**: 
  ```python
  from rustuya import Scanner
  
  # 1. Simple scan with default settings (18s timeout)
  results = Scanner().scan()
  
  # 2. Configured scan with chaining
  results = Scanner().timeout(18).bind_address("0.0.0.0").scan()
  
  for device in results:
      print(f"Found: {device['id']} at {device['ip']}")
  ```

---

## **5. Thread Safety**
The `rustuya` Python API is fully thread-safe. All core objects—`Manager`, `Device`, `SubDevice`, and `Scanner`—are designed to be shared and accessed across multiple threads without additional locking in Python.

- **Shared State**: The Python objects are handles to internal Rust state managed by a high-performance asynchronous runtime.
- **Concurrent Access**: You can call methods on the same `Device` or `Manager` from different threads simultaneously.
- **Background Tasks**: Connection maintenance and message processing happen in background threads, so your Python code only interacts with a lightweight wrapper.

Example using `threading`:
```python
import threading
from rustuya import Manager

mgr = Manager()
dev = mgr.add("id", "ip", "key", "ver")

def worker():
    # Safe to use the same device handle in multiple threads
    dev.set_value(1, True)

threads = [threading.Thread(target=worker) for _ in range(5)]
for t in threads: t.start()
for t in threads: t.join()
```

---

## **6. Integration with `asyncio`**

While Rustuya's Python API is synchronous, it is designed to be friendly to `asyncio` environments.

### **Recommended Pattern: `nowait=True`**
If you set `device.set_nowait(True)`, command methods like `set_value()` or `status()` return immediately after queuing the command to the background Rust worker. This happens so fast that it is safe to call directly from an `asyncio` event loop without noticeably blocking it.

```python
import asyncio
from rustuya import Manager

async def main():
    mgr = Manager()
    dev = mgr.add("id", "ip", "key", "ver")
    dev.set_nowait(True) # Ensure non-blocking calls

    # Safe to call directly in asyncio loop
    dev.set_value(1, True)
    await asyncio.sleep(1)

asyncio.run(main())
```

### **Handling Events in `asyncio`**
Since `listener().recv()` is a blocking call, it should be run via `loop.run_in_executor` to avoid freezing the event loop.

```python
async def async_listener(dev):
    loop = asyncio.get_running_loop()
    listener = dev.listener()
    while True:
        # Run blocking recv in a thread pool
        event = await loop.run_in_executor(None, listener.recv)
        if event:
            print(f"Async Event: {event}")

asyncio.create_task(async_listener(dev))
```

---