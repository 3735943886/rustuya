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
  - `id`: Device ID (str)
  - `local_key`: Local Key (str)
  - `address`: IP address (default: "Auto" for discovery)
  - `version`: Protocol version (default: "Auto" for discovery)
  - `dev_type`: Device type (default: `None` / "auto"). Values: "auto", "default", "device22".
  - `persist`: If `True`, keeps the TCP connection alive (default: True).
  - `timeout`: Global timeout for network operations and responses in seconds (default: 10.0)
  - `nowait`: If `True`, commands return immediately after queuing (default: False).
- **Example**:
  ```python
  from rustuya import Device
  dev = Device("id", "key", nowait=False)
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
- **Returns**: `dict` (or `None` if `nowait=True`)
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
      # event is a dict containing 'id' and 'data' (the message)
      print(f"Device {event['id']} updated: {event['data']}")
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

### `Scanner.discover()`
- **Description**: Discovers a specific device by its ID.
- **Example**:
  ```python
  from rustuya import Scanner
  dev = Scanner.discover("your_device_id")
  if dev:
      print(f"Found device at {dev['ip']}")
  ```

---

## **5. Thread Safety**
The `rustuya` Python API is fully thread-safe. All core objects—`Device`, `SubDevice`, and `Scanner`—are designed to be shared across multiple threads without additional locking in Python.

- **Background Tasks**: Connection maintenance and message processing happen in background Rust threads.
- **Non-blocking Loop**: If using `asyncio`, set `nowait=True` to call methods without blocking the event loop.
