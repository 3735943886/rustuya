---
title: Design philosophy of 0.4
---

# Design philosophy of 0.4

Rustuya stays close to the local Tuya protocol: device discovery, connections
and raw data points. It does not model device categories or provide cloud APIs.

The protocol implementation is independent of the runtime. A pure state-machine
core can be tested with injected time and randomness, then driven by Tokio or a
future embedded driver.

Commands and responses are separate. A Tuya device can push a status update
without a request, and the protocol does not reliably correlate that frame to
a particular call. The API makes that explicit with queued commands and an
event stream rather than guessing which reply belongs to which request.

Shared resources are explicit: applications create `Discovery` and
`ConnectLimiter` objects and pass them to devices. Events expose listener lag;
watch channels provide the latest value when an application needs state instead
of a full event history.

See [Architecture](architecture.md), the [Rust API guide](rust-api.md), and the
[decision record](DESIGN.md).
