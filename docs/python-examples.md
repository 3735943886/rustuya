# Python Examples

This page provides comprehensive examples for using `rustuya` in Python. These examples cover common use cases from basic device control to advanced gateway management.

---

## **1. Basic Device Control**
This example shows how to connect to a single device and control its state.

```python
from rustuya import Device
import time

# Initialize device
# IP address and version can be "Auto" for automatic discovery if the device is on the same subnet
dev = Device(
    id="DEVICE_ID",
    address="DEVICE_IP", # Or "Auto"
    local_key="LOCAL_KEY",
    version="DEVICE_VER" # Or "Auto"
)

# 1. Get current status
print("Requesting status...")
dev.status()

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

dev = Device("DEVICE_ID", "DEVICE_IP", "LOCAL_KEY", "DEVICE_VER")

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

# Create scanner and set timeout to 5 seconds
results = Scanner().scan()

print(f"Found {len(results)} devices:")
for dev in results:
    print(f"- ID: {dev['id']}")
    print(f"  IP: {dev['ip']}")
    print(f"  Ver: {dev['version']}")
    print(f"  Product ID: {dev['product_id']}")
    print("-" * 20)
```

---

## **4. Gateway & Sub-devices**
Control Zigbee or Bluetooth devices connected via a Tuya Gateway.

```python
from rustuya import Device

# 1. Connect to the Gateway itself
gateway = Device("GATEWAY_ID", "GATEWAY_IP", "GATEWAY_KEY", "GATEWAY_VER")

# 2. Get a handle for a sub-device using its CID
sub_dev = gateway.sub("SUB_DEVICE_CID")

# 3. Control the sub-device
print("Turning sub-device ON...")
sub_dev.set_value(1, True)

# 4. Request sub-device status
sub_dev.status()

# 5. Discover all sub-devices connected to the gateway
print("Requesting sub-device discovery...")
gateway.sub_discover()
```

---

## **5. Advanced Raw Requests**
Send custom commands using `CommandType`.

```python
from rustuya import Device, CommandType

dev = Device("id", "addr", "key", "ver")

# Send a DpQuery (Status) request manually
# CommandType keys match the Rust CommandType enum
dev.request(CommandType["DpQuery"], None)

# Send with custom JSON data
# dev.request(CommandType["DpControl"], {"1": True})
```
