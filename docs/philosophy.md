# API Design Philosophy

Rustuya is engineered with a specific architectural pattern to ensure a balance between high-concurrency device management and deterministic command execution.

## **1. Asynchronous Device Initialization**

Core initialization methods, such as `Device::new()`, are designed to be **non-blocking** and return control to the caller immediately.

- **Rationale**: In large-scale deployments involving dozens or hundreds of devices, blocking the main execution thread for individual TCP handshakes would result in significant latency and performance degradation.
- **Implementation Details**: 
  - Invoking `new` registers the device within the internal registry and initializes a dedicated background worker.
  - Actual TCP connection establishment and protocol handshakes are performed asynchronously.
  - Connection attempts are intelligently staggered using randomized jitter to mitigate "thundering herd" effects on the network.
  - Resilience is maintained even if a device is offline; initialization completes successfully, and the background worker manages reconnection logic using an exponential backoff strategy.

## **2. Command Dispatch & `nowait` Configuration**

Methods like `set_value()`, `status()`, and `sub_discover()` provide a configurable execution model via the `nowait` parameter. This allows the application to balance between strict reliability and high-throughput performance.

### **`nowait = false` (Default: Strong Consistency)**
Blocks the calling thread until a physical response (acknowledgment or data) is received from the device.

- **Pros**:
  - **Deterministic**: The return value contains the actual execution result (e.g., a JSON response string).
  - **Reliable**: If the device is disconnected, the method waits for a successful reconnection before sending the command and returning the response.
  - **Error-Aware**: Network failures or protocol errors are caught immediately and returned as a `TuyaError`.
- **Cons**:
  - **Latency**: The calling thread is suspended for the duration of the network round-trip and device processing time.
  - **Throughput Limit**: Limited by the device's processing speed and network latency.

### **`nowait = true` (Fire-and-Forget)**
Returns control to the caller immediately after the command packet is committed to the local TCP stack.

- **Pros**:
  - **High Throughput**: Allows sending multiple commands in rapid succession without waiting for individual network round-trips.
  - **Minimal Latency**: The calling thread is never blocked by device processing or network delays.
- **Cons**:
  - **Indeterministic**: The method always returns `Ok(None)` / `None`. The actual execution result must be monitored via the `listener()`.
  - **Deferred Error Reporting**: If the device is disconnected or a network error occurs, the method call still returns success. The failure is reported later as an error message through the `listener()`.
  - **Execution Uncertainty**: There is no direct link between a specific `nowait=true` method call and its eventual success or failure reporting in the listener.

---

> [!TIP]
> **Error Handling with `nowait=true`**: When using `nowait=true`, network-level failures (like `Offline` or `ConnectionFailed`) are **broadcast to the `listener()`**. While the method call itself won't throw an error, your application can still detect and handle these issues by monitoring the event stream. For critical operations, `nowait=false` remains the recommended choice for immediate, synchronous error handling.

## **3. Event-Driven Feedback**

Regardless of the `nowait` setting, Rustuya employs a decoupled event listener mechanism to handle the push-based nature of the Tuya protocol.

- **Rationale**: Tuya devices emit status updates for various reasons, including manual physical interaction, sensor triggers, or as responses to commands.
- **Implementation Details**:
  - **All** protocol messages (including responses to every command, whether `nowait` is true or false) are accessible via `device.listener()`.
  - This architecture ensures that no state change is missed, providing a complete telemetry stream for the device.

---

## **4. Choice of Async vs. Sync**

Rustuya provides two distinct APIs to suit different application architectures:

- **Full Asynchronous (Tokio)**: The primary API built on top of `tokio`. If the application already uses an async runtime, the core `rustuya` types (`Device`, etc.) offer the best performance and scalability.
- **Synchronous (Blocking)**: For environments where an async event loop is not desired (e.g., simple scripts, standard Python applications), Rustuya provides a synchronous wrapper under `rustuya::sync`. These types manage the async bridge internally and block the calling thread until the requested operation completes.

> [!NOTE]
> For Python users, the synchronous wrapper provides high-performance interaction without the complexity of `asyncio`. The Rust core manages all network I/O in dedicated background threads and releases the GIL during blocking calls, allowing Python's standard `threading` module to operate with high efficiency.

### **Thread-Safety & Concurrency**

All core types and synchronous wrappers are designed for concurrent use.

- **Internal Architecture**: Rustuya uses a background worker model. `Device` instances act as thread-safe handles to these workers, communicating via internal message-passing.
- **Concurrent Access**: Multiple threads can safely share a single `Device` instance. Cloning an instance creates a new handle to the same background worker.
- **Python GIL Release**: Python bindings release the Global Interpreter Lock (GIL) during blocking network operations, enabling true parallel execution when using Python's `threading` module.
- **Event Listeners**: `listener()` provides a thread-safe channel to receive real-time updates across different parts of an application simultaneously.