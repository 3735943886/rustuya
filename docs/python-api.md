# Python API Reference

This document provides a detailed reference for the `rustuya` Python bindings.

For practical code examples, see the [Python Examples](./python-examples.md) page.

---

## **1. System Optimization**
To handle high-concurrency environments with many device connections, use this utility.

### `maximize_fd_limit()`
- **Description**: Increases the maximum number of open file descriptors (sockets) allowed for the process. Recommended for gateways or management servers.
- **Example**:
  ```python
  import rustuya
  rustuya.maximize_fd_limit()
  ```

---

## **2. Device API**
Direct interaction and control for individual Tuya devices.

### `Device()`
- **Definition**: `Device(id, local_key, address="Auto", version="Auto", dev_type=None, persist=True, timeout=None, nowait=False)`
- **Description**: Creates a new device handle.
- **Arguments**:
  - `id` (str, **Required**): The unique device ID.
  - `local_key` (str, **Required**): The 16-character local key.
  - `address` (str, *Optional*): IP address. Default is `"Auto"` (uses UDP discovery).
  - `version` (str, *Optional*): Protocol version. Default is `"Auto"`.
  - `dev_type` (str, *Optional*): Device architecture type.
    - `None` (default): **Automatic detection**. Switches to `"device22"` if ID length is 22.
    - `"default"`: Force standard Tuya device architecture (disables auto-detection).
    - `"device22"`: Force specialized 22-character ID architecture.
  - `persist` (bool, *Optional*): Whether to keep the TCP connection alive. Default is `True`.
  - `timeout` (float, *Optional*): Global timeout for network operations and responses in seconds (default: 10.0)
  - `nowait` (bool, *Optional*): If `True`, command methods return immediately after queuing. Default is `False`.
- **Example**:
  ```python
  from rustuya import Device
  dev = Device("DEVICE_ID", "LOCAL_KEY")
  ```

### `device.status()`
- **Description**: Requests current status (DPS values) from the device.
- **Returns**: `dict` (or `None` if `nowait=True`)
- **Example**:
  ```python
  status = dev.status()
  ```

### `device.set_value()`
- **Description**: Sets a single DP value.
- **Arguments**: `dp_id` (int or str), `value` (bool, int, str, dict, etc.)
- **Example**:
  ```python
  dev.set_value(1, True)
  ```

### `device.set_dps()`
- **Description**: Sets multiple DP values at once.
- **Arguments**: A dictionary of DP ID to value.
- **Example**:
  ```python
  dev.set_dps({"1": True, "2": 50})
  ```

### `device.request()`
- **Description**: Sends a low-level Tuya command.
- **Arguments**:
  - `command` (int, **Required**): Command ID (use `CommandType`).
  - `data` (dict, *Optional*): Payload data. Default is `None`.
  - `cid` (str, *Optional*): Child ID for sub-devices. Default is `None`.
- **Example**:
  ```python
  from rustuya import CommandType
  dev.request(CommandType["DpQuery"], data=None)
  ```

### `device.listener()`
- **Description**: Returns a `DeviceEventReceiver` for real-time messages.
- **Example**:
  ```python
  listener = dev.listener()
  for msg in listener:
      print(f"Received: {msg}")
  ```

### `unified_listener()`
- **Description**: Aggregates event streams from multiple devices into a single receiver.
- **Arguments**: `devices` (list of `Device` objects)
- **Returns**: `UnifiedEventReceiver`
- **Example**:
  ```python
  from rustuya import unified_listener
  listener = unified_listener([dev1, dev2])
  for event in listener:
      print(f"Device {event['id']} updated: {event['payload']}")
  ```

---

## **3. SubDevice API**
Interaction with sub-devices (endpoints) through a parent Gateway `Device`. Obtained via `device.sub(cid)`.

### `device.sub()`
- **Description**: Returns a `SubDevice` handle for the given Child ID.
- **Example**:
  ```python
  sub = gateway.sub("sub_id")
  ```

### `sub_device.status()` / `set_value()` / `set_dps()`
- **Description**: These methods mirror the `Device` API but target the specific sub-device via the parent gateway.
- **Example**:
  ```python
  sub.set_value(1, True)
  ```

---

## **4. Discovery (Scanner)**
Search for devices on the local network.

### `Scanner.scan()`
- **Description**: Performs a one-time scan and returns a list of discovered devices.
- **Example**:
  ```python
  from rustuya import Scanner
  devices = Scanner.scan()
  for dev in devices:
      print(f"Found: {dev['id']} at {dev['ip']}")
  ```

### `Scanner.scan_stream()`
- **Description**: Returns an iterator that yields devices as they are discovered in real-time.
- **Example**:
  ```python
  from rustuya import Scanner
  stream = Scanner.scan_stream()
  for dev in stream:
      print(f"Found: {dev['id']} at {dev['ip']}")
  ```

---

## **5. Thread Safety**
The `rustuya` Python API is fully thread-safe. All core objects—`Device`, `SubDevice`, and `Scanner`—are designed to be shared across multiple threads without additional locking in Python.

- **Background Tasks**: Connection maintenance and message processing happen in background Rust threads.
- **Non-blocking Loop**: If using `asyncio`, set `nowait=True` to call methods without blocking the event loop.
