# API Design Philosophy

Rustuya is engineered with a specific architectural pattern to ensure a balance between high-concurrency device management and deterministic command execution.

## 1. Asynchronous Device Initialization

Core initialization methods, such as `Device::new()` and `Manager::add()`, are designed to be **non-blocking** and return control to the caller immediately.

- **Rationale**: In large-scale deployments involving dozens or hundreds of devices, blocking the main execution thread for individual TCP handshakes would result in significant latency and performance degradation.
- **Implementation Details**: 
  - Invoking `new` or `add` registers the device within the internal registry and initializes a dedicated background worker.
  - The actual TCP connection establishment and protocol handshakes are performed asynchronously.
  - Connection attempts are intelligently staggered using randomized jitter to mitigate "thundering herd" effects on the network.
  - Resilience is maintained even if a device is offline; initialization completes successfully, and the background worker manages reconnection logic using an exponential backoff strategy.

## 2. Synchronous Command Dispatch

Methods responsible for device interaction, including `set_value()`, `set_dps()`, and `status()`, operate in a **synchronous** manner.

- **Rationale**: This ensures strict command serialization and provides the caller with immediate confirmation that the command has been successfully dispatched to the network interface.
- **Implementation Details**:
  - The calling thread is suspended until the command packet is successfully written to the underlying TCP socket.
  - Commands are strictly serialized via an internal per-device queue to prevent race conditions or protocol desynchronization.
  - **Note**: A successful return signifies that the command has been **dispatched to the network**, which is distinct from the device having completed the physical execution of the request.

## 3. Decoupled Event-Driven Feedback

Given the push-based nature of the Tuya protocol, state transitions and updates are managed through a decoupled event listener mechanism.

- **Rationale**: Devices may emit status updates spontaneously (e.g., manual physical interaction or sensor triggers) or as a delayed response to a previously issued command.
- **Implementation Details**:
  - Real-time telemetry and state changes are accessed via `device.listener()` or `manager.listener()`.
  - This architecture decouples command issuance from state monitoring, facilitating a more robust and responsive integration model.

---

### Execution Model Summary

| Action | Blocking | Description |
| :--- | :--- | :--- |
| `Device.new()` / `Manager.add()` | No | Registers the device; connection is established in the background. |
| `device.set_value()` / `status()` | Yes | Blocks until the command packet is committed to the TCP socket. |
| `device.listener()` | No | Provides a stream/iterator for real-time protocol events. |
| `scanner.scan()` | Yes | Suspends execution for the duration of the configured discovery timeout. |
