# Architecture

Rustuya is designed with a layered architecture that separates network concerns, protocol logic, and user-facing APIs. This separation ensures high performance, reliability, and ease of maintenance.

---

## **Layer Overview**

1.  **User API Layer**: Provides high-level interfaces for Rust (`Manager`, `Device`) and Python (via `PyO3`).
2.  **Sync Wrapper Layer**: Bridges the asynchronous core to synchronous APIs for ease of use in simple scripts.
3.  **Core Logic Layer**: Manages device lifecycle, connection pooling, and event dispatching.
4.  **Protocol Layer**: Handles Tuya-specific message framing, encryption, and decryption.
5.  **Transport Layer**: Manages low-level TCP/UDP communication using `tokio`.

---

## **Component Breakdown**

- **Manager ([manager.rs](file:///e:/Libraries/Documents/trae_projects/rustuya/src/manager.rs))**: Central registry for all devices. Handles unified event streaming and lifecycle management.
- **Device ([device.rs](file:///e:/Libraries/Documents/trae_projects/rustuya/src/device.rs))**: Represents a single physical Tuya device. Manages its own background connection task.
- **Protocol ([protocol/mod.rs](file:///e:/Libraries/Documents/trae_projects/rustuya/src/protocol/mod.rs))**: Implements the Tuya protocol versions (3.1, 3.3, 3.4, 3.5, and device22).
- **Crypto ([crypto.rs](file:///e:/Libraries/Documents/trae_projects/rustuya/src/crypto.rs))**: Handles AES encryption and MD5/HMAC hashing required by the protocol.
- **Scanner ([scanner.rs](file:///e:/Libraries/Documents/trae_projects/rustuya/src/scanner.rs))**: Manages UDP discovery for finding devices on the local network.
- **Runtime ([runtime.rs](file:///e:/Libraries/Documents/trae_projects/rustuya/src/runtime.rs))**: Internal utilities for managing background tasks and timers.

---

## **Data Flow**

1.  **Command Execution**: User calls `set_value()` -> Command is queued in `Device` -> Background worker encrypts and writes to TCP socket.
2.  **Status Updates**: Device sends packet -> Background worker decrypts -> Packet is parsed -> Event is emitted via `Device` or `Manager` listener.
3.  **Discovery**: `Scanner` sends UDP broadcast -> Devices respond with JSON -> `Scanner` parses responses and returns `DiscoveryResult`.
