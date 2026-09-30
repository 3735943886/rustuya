---
title: Architecture of 0.4
---

# Architecture of 0.4

| Crate | Responsibility |
| --- | --- |
| `rustuya-core` | `no_std + alloc` protocol framing, cryptography, device and discovery state machines |
| `rustuya-tokio` | TCP/UDP sockets, task ownership, channels, clocks and RNG injection |
| `rustuya` | Feature-gated facade, currently exposing `rustuya::tokio` |

The core takes inputs such as received bytes, connection changes, commands and
timer expiry. It exposes outbound frames, application events and its next timer
deadline. It does not open sockets or read a clock. Drivers supply monotonic time
and randomness, making protocol and lifecycle tests deterministic.

The Tokio driver owns one task per device. Socket readiness, timer deadlines and
bounded command queues drive the core. Partial writes retain their offset so a
stalled peer cannot prevent inbound processing or liveness deadlines. Shutdown
has a separate signal and can cancel a dial, permit wait or stalled connection.

Discovery follows the same core/driver split. A shared driver routes
announcements to registered devices by ID rather than waking every device for
every announcement.

## Embedded scope

The core builds without `std` on RISC-V and Cortex-M targets. It requires an
allocator. **0.4 does not include an Embassy/ESP32 driver**; that is a later
milestone. The Python bindings and blocking driver belong to 0.3.x.

See the [design decisions](DESIGN.md) and [milestones](MILESTONES.md) for the
core interfaces, rationale and future work.
