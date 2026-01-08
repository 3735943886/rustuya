# FAQ

Frequently asked questions about Rustuya.

---

### **1. Is Cloud supported?**
No. Rustuya is strictly a **Local API** implementation. It communicates directly with devices over the local network. It does not require or support Tuya Cloud APIs.

---

### **2. Which Tuya device versions are supported?**
Rustuya supports all major Tuya protocol versions:
- **3.1 to 3.5**: Standard protocol versions used by most Wi-Fi devices.
- **device22**: A special version used by some devices.

---

### **3. How to find the Local Key?**
The Local Key is required for encryption. It can be obtained by:
1.  Using the [Tuya IoT Platform](https://iot.tuya.com/) and utilizing the **Core API** to retrieve keys for registered devices.
2.  Using external tools and libraries:
    - [tinytuya](https://github.com/jasonacox/tinytuya)
    - [tuyawizard](https://github.com/3735943886/tuyawizard)
    - Or other community-maintained tools.

---

### **4. Is it possible to use Rustuya in synchronous code?**
Yes. While the core is asynchronous (`tokio`), a synchronous wrapper is provided in `rustuya::sync` for Rust and Python.

---

### **5. How many devices can be managed at once?**
Rustuya is designed for high concurrency and can manage thousands of devices efficiently. On Unix-like systems, the process file descriptor limit must be increased when handling a very large number of concurrent connections. This can be handled automatically by calling:

- **Rust**: `rustuya::maximize_fd_limit()`
- **Python**: `rustuya.maximize_fd_limit()`
