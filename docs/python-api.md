# Python Guide

Python bindings expose API wrappers under the `rustuya` module.

## Installation

```bash
pip install rustuya
```

## Check Version

```python
import rustuya
print(rustuya.version())
```

## Device
- Create: `Device(id, address, local_key, version)`
- Request status: `status()`
- Set single value: `set_value(dp_id, value)`
- Set multiple DPs: `set_dps({...})`
- Event listener: `listener()`

```python
from rustuya import Device

dev = Device("ID", "ADDRESS", "LOCAL_KEY", "VER")
dev.set_value(1, True)

for msg in dev.listener():
    print(msg)
```

## Manager
- Create: `Manager()`
- Global settings: `maximize_fd_limit()` (static method). Recommended for Unix-like systems when managing many devices.
- Add/modify/remove/delete devices: `add(...)`, `modify(...)`, `remove(...)`, `delete(...)`
- Get/list: `get(id)`, `list()`
- Event listener: `listener()`

```python
from rustuya import Manager

Manager.maximize_fd_limit()

mgr = Manager()
mgr.add("ID", "ADDRESS", "LOCAL_KEY", "VER")

for msg in mgr.listener():
    print(msg)
```

## Logging, Listening and Control

```python
import logging
import threading
import time
from rustuya import Manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

mgr = Manager()
mgr.add("ID1", "ADDRESS1", "LOCAL_KEY1", "VER1")
mgr.add("ID2", "ADDRESS2", "LOCAL_KEY2", "VER2")

def listen():
    for msg in mgr.listener():
        print(msg)

def control():
    while True:
        mgr.get("ID1").set_value(1, True)
        time.sleep(1)
        mgr.get("ID2").set_value(2, True)
        time.sleep(1)
        mgr.get("ID1").set_value(1, False)
        time.sleep(1)
        mgr.get("ID2").set_value(2, False)
        time.sleep(1)

t_listen = threading.Thread(target=listen, daemon=True)
t_control = threading.Thread(target=control, daemon=True)
t_listen.start()
t_control.start()

time.sleep(10)
```

## Scanner

```python
import logging
from rustuya import Scanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
scanner = Scanner()
scanner.scan()
```