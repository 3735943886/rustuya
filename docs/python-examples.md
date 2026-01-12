# Python Examples

This page provides comprehensive examples for using `rustuya` in Python. These examples cover common use cases from basic device control to advanced gateway management.

---

## **1. Basic Device Control**
This example shows how to connect to a single device and control its state.

```python
from rustuya import Device
import time

# Initialize device
# id and local_key are required (positional)
# address and version are optional (keyword)
dev = Device(
    "DEVICE_ID", 
    "LOCAL_KEY", 
    address="DEVICE_IP", # Or "Auto"
    version="DEVICE_VER" # Or "Auto"
)

# 1. Get current status
print("Requesting status...")
status = dev.status()
print(f"Status: {status}")

# 2. Set a value (DP ID 1 is usually a Switch)
print("Turning ON...")
dev.set_value(1, True)
time.sleep(2)

print("Turning OFF...")
dev.set_value(1, False)

# 3. Set multiple DPS values at once
print("Setting multiple DPs...")
dev.set_dps({"1": True, "2": 50})
```

---

## **2. Listening for Events**
Tuya devices are push-based. Use the `listener()` to receive real-time updates.

```python
from rustuya import Device

# Using positional arguments: (id, local_key, address, version)
dev = Device("DEVICE_ID", "LOCAL_KEY", "DEVICE_IP", "DEVICE_VER")

print("Starting listener... (Press Ctrl+C to stop)")
try:
    # listener() returns an iterator that blocks until a message arrives
    for msg in dev.listener():
        print(f"Received: {msg}")
except KeyboardInterrupt:
    print("Stopped.")
```

---

## **3. Device Discovery (Scanner)**
Search for Tuya devices on the local network.

```python
from rustuya import Scanner

print("Scanning for devices...")

# One-time scan directly from Scanner class
results = Scanner.scan()

print(f"Found {len(results)} devices:")
for dev in results:
    print(f"- ID: {dev['id']}")
    print(f"  IP: {dev['ip']}")
    print(f"  Ver: {dev['version']}")
    print("-" * 20)

# Alternative: Real-time scan stream directly from Scanner class
print("Streaming discovered devices...")
for dev in Scanner.scan_stream():
    print(f"Found: {dev['id']} at {dev['ip']}")
```

---

## **4. Unified Listener (Multiple Devices)**
Monitor events from multiple devices in a single loop.

```python
from rustuya import Device, unified_listener

dev1 = Device("DEVICE_ID_1", "LOCAL_KEY_1")
dev2 = Device("DEVICE_ID_2", "LOCAL_KEY_2")

# Aggregates events from all provided devices
listener = unified_listener([dev1, dev2])

print("Listening for events from all devices...")
for event in listener:
    print(f"Event from {event['id']}: {event['payload']}")
```

---

## **6. Gateway & Sub-devices**
To control sub-devices connected via a Zigbee/Bluetooth gateway.

```python
from rustuya import Device

# 1. Connect to the Gateway (id and local_key are positional)
gateway = Device("GATEWAY_ID", "GATEWAY_KEY", address="GATEWAY_IP")

# 2. Get a handle for a sub-device using its Child ID (cid)
sub_dev = gateway.sub("SUB_DEVICE_CID")

# 3. Control sub-device (same API as Device)
print("Turning sub-device ON...")
sub_dev.set_value(1, True)
status = sub_dev.status()
print(f"Sub-device status: {status}")

# 5. Discover all sub-devices connected to the gateway
print("Requesting sub-device discovery...")
sub_devices = gateway.sub_discover()
print(f"Found sub-devices: {sub_devices}")
```

---

## **7. Advanced Raw Requests**
Send custom commands using `CommandType`.

```python
from rustuya import Device, CommandType

# Using positional arguments: id, key, address, version
dev = Device("DEVICE_ID", "LOCAL_KEY", "DEVICE_IP", "DEVICE_VER")

# Send a DpQuery (Status) request manually
# CommandType provides common command codes
dev.request(CommandType["DpQuery"], None)

# Send with custom JSON data (e.g., Control)
# dev.request(CommandType["Control"], {"1": True})
```

---

## **8. System Optimization**
For high-performance applications managing many devices.

```python
import rustuya

# Increase open file descriptor limits (especially for Linux)
rustuya.maximize_fd_limit()
```
