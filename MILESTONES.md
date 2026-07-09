# Rustuya 0.4 — Sans-I/O Redesign Milestones

Tracks the multi-release program that splits rustuya into a **pure, `no_std`
protocol/state-machine core** plus **thin I/O drivers**, so the same protocol
logic runs on a beefy Linux/tokio host (fleet scale) *and* on an ESP32-class
microcontroller (single-device controller).

This is a **long-lived branch** (`0.4-sansio`). The `0.3.x` line stays the
stable, shipping release; nothing here lands on `master` until a phase is
oracle-green and reviewed. The goal is "same behavior, new I/O boundary," not
"rewrite for its own sake."

---

## Why

- **Motivation:** tokio is a non-starter on ESP32 (needs mio/epoll; a
  multi-thread runtime on a 2-core, ~200 KB-RAM MCU is nonsensical). The wall
  is not sans-I/O itself — it is that **tokio + `std` must leave the core**.
  Sans-I/O is the mechanism (cf. `quinn-proto`, `rustls`).
- **Free wins that fall out of the same move:**
  - The reconnect/backoff/handshake/dev22 logic becomes a pure
    `step(event, now, rng) -> [action]` state machine → deterministic tests at
    **zero wall-clock** (today the reconnect path costs ~16 s of real time to
    test because `SLEEP_RECONNECT_MIN = 16 s` is real).
  - Injecting the RNG pins the random-IV / random-nonce property (immunity to
    the tinytuya #722 GCM-nonce-reuse class) **as a test**, not a convention.

## Non-goals / scope guards

- **Not** a behavior change. Wire behavior, defaults, and the public `std`/tokio
  API stay as in 0.3.x until a deliberate, separate decision.
- **Not** committing to Embassy-vs-esp-idf now. The core targets `no_std +
  alloc`, which is the **superset** — it compiles under both. The ESP32 driver
  flavor is a Phase-3 decision.
- **Not** zero-alloc. `alloc` is assumed (ESP32 has a heap via esp-alloc /
  esp-idf). Zero-alloc / `heapless` / `serde-json-core` is a later option if RAM
  demands it, not a v0.4 requirement.
- `master` / `0.3.x` is **not** destabilized. Fixes to 0.3 land on `master`; this
  branch rebases on them.

## Design invariants (hold across every phase)

1. **Core is `#![no_std]` + `alloc`.** No tokio, no sockets, no timers, no
   threads, no locks (the core is single-owner, driven by the driver).
2. **`now: Instant` and `rng: &mut impl RngCore` are injected** into the core.
   The core never reads the clock or the OS RNG itself.
3. **Addresses use `core::net::{IpAddr, SocketAddr}`** (stable since 1.77; MSRV
   is 1.88), so no `std::net` leaks into the core.
4. **The core owns policy, the driver owns I/O.** "Which bytes, which port,
   which timer duration, whether to reconnect" is the core. "Open the socket,
   write the bytes, sleep the timer" is the driver.
5. **Same oracle.** The core must pass the *existing* `tinytuya_parity`
   fixtures and the `tuyamock` end-to-end suite. These are the regression net
   against reopening the 0.3 lifecycle/race fixes.
6. **`no_std` buildability is the acceptance gate, not the refactor.** A CI job
   builds the core for a bare-metal target (`riscv32imc-unknown-none-elf`) with
   `--no-default-features` from day one. If it doesn't build `no_std`, the phase
   is not done.

## Target crate layout

```
rustuya-core       no_std + alloc   protocol · crypto · Device FSM · Discovery FSM
                                    (now/RNG injected; core::net; no I/O)
rustuya            std + tokio      thin driver: tokio TCP/UDP, timers, sync facade,
                                    scanner sockets, Python-facing surface
rustuya-embassy    no_std           thin driver: embassy-net + embassy-time  (Phase 3)
python             extension        unchanged; sits on rustuya (tokio)
```

- **Core deps:** RustCrypto (`aes`, `aes-gcm`, `cipher`, `hmac`, `sha2`,
  `md-5` — all `no_std`, default-features off) · `serde` / `serde_json`
  (`no_std` + `alloc`) · `base64` / `byteorder` (`no_std`) · `rand_core`
  (traits only) · `thiserror` 2 (`no_std`) · `core::net`.
- **Driver-only deps (must NOT appear in core):** `tokio`, `tokio-util`,
  `tokio-stream`, `socket2`, `rlimit`, `parking_lot`, `async-stream`,
  `futures-*`.

## Sans-I/O interface (shape)

```rust
// Device connection FSM — pure, single-owner, no I/O.
pub enum DevEvent<'a> {
    Connected,
    ConnectFailed(TuyaError),
    BytesReceived(&'a [u8]),   // driver read from the socket
    TimerFired(TimerId),       // Backoff | Heartbeat | IdleTimeout
    CommandQueued(Command),
    DiscoveryUpdated(IpAddr),  // replaces the wait_for_backoff sleep+watch coupling
    Closed,
}
pub enum DevAction {
    Send(Vec<u8>),                  // driver writes to the socket
    StartTimer(TimerId, Duration),  // core computes jitter/backoff; driver sleeps
    CancelTimer(TimerId),
    Emit(DeviceEvent),              // to listener()
    Reconnect,
}
impl DeviceCore {
    pub fn step(&mut self, ev: DevEvent<'_>, now: Instant, rng: &mut impl RngCore) -> Vec<DevAction>;
}
// Discovery FSM is isomorphic:
//   ScanEvent  { PacketReceived, TimerFired, ScanRequested }
//   ScanAction { SendBroadcast(bytes, port), StartTimer, EmitDiscovered }
```

> **This shape is not yet locked — see D1.** The single `step() -> Vec<Action>`
> above is the simplest form; the leading proposal is the quinn-proto-style
> poll-split (`handle_input` / `poll_transmit` / `poll_timeout` / `poll_event`),
> which is better proven for a cross-runtime, embedded-capable state machine.

---

## Key design decisions to settle before M0

Each is a fork that is expensive to reverse once M0 lands. Listed with a
**proposed** answer and the reasoning; these are for the maintainer to confirm
or override *before* any code, so the core's spine is settled up front.

- **D1 — Core API shape: quinn-proto-style poll-split _(proposed)_ vs monolithic
  `step -> Vec<Action>`.** Proposed: separate entry points —
  `handle_input(event, now)`, `poll_transmit() -> Option<Bytes>`,
  `poll_timeout() -> Option<Instant>`, `poll_event() -> Option<DeviceEvent>`.
  The driver loops: feed input → drain transmits → arm one timer at
  `poll_timeout` → deliver events. *Why:* battle-tested for exactly this (a
  connection state machine reused across runtimes incl. embedded), no
  per-step `Vec` allocation, and it separates "bytes to send" / "next deadline"
  / "app events" cleanly. The `step -> Vec` form is easier to write first but
  gets awkward around timers and re-entrancy.

- **D2 — Timer model: single next-deadline _(proposed)_ vs multiple named
  timers.** Proposed: `poll_timeout()` returns the earliest of {backoff,
  heartbeat, idle}; the driver arms exactly **one** timer; on fire it calls
  `handle_timeout(now)` and the core recomputes internally. *Why:* the driver
  manages one timer, no timer-id bookkeeping, trivial on `embassy-time` (one
  `Timer`) and on tokio (one `sleep`).

- **D3 — Clock: injected monotonic `Instant` newtype _(proposed)_.** Proposed:
  the core defines `Instant(u64 /* monotonic millis */)` with saturating
  arithmetic; each driver builds it from its own clock (tokio `Instant`,
  `embassy-time::Instant`, `std::Instant`). No `std::time` in the core. *Why:*
  simplest; a generic `<C: Clock>` adds type noise for no real gain here.

- **D4 — RX reassembly buffer lives in the core, bounded _(proposed)_.**
  Proposed: the core owns the receive buffer; `handle_input(bytes)` appends and
  extracts whole frames; cap at `MAX_PAYLOAD_LEN`; overflow → protocol error →
  reset. *Why:* this is what makes the core a real sans-I/O machine (the driver
  just pumps raw bytes); bounded so ESP32 RAM is predictable. The driver still
  owns its own socket-read scratch buffer — only the partial-frame state is core.

- **D5 — Split the error type: core vs transport.** Today `TuyaError` wraps
  `std::io::Error` (not `no_std`). Proposed: the core error carries **no**
  `std::io::Error`; transport/I/O failures are the driver's and enter the core
  only as a neutral event (`ConnectFailed`) or a marker (`TuyaError::Transport`).
  The public 0.3 `TuyaError` (with io) stays on the tokio driver for API
  compatibility; the core gets a leaner `CoreError`.

- **D6 — Public-API compatibility contract.** Proposed: the tokio driver
  preserves the **exact** 0.3 `rustuya::{Device, Scanner}`, `rustuya::sync::*`,
  and Python API — 0.3 → 0.4 is a non-breaking move for existing tokio/Python
  users; sans-I/O is an internal boundary. The blocking and embassy drivers are
  **additive** surface. Any 0.4 breakage should be a deliberate decision, never
  an incidental fallout of the refactor.

- **D7 — Concurrency primitives stay driver-side.** The listener latch/replay,
  `watch`/`broadcast` fan-out, mpsc command queue, and connect-concurrency cap
  remain in the tokio driver. The core only *emits* `DeviceEvent`s; how they are
  delivered (lost-wakeup-safe, per [[concurrency-design-rules]]) is a driver
  concern. Keeps the core single-threaded and allocation-light.

- **D8 — JSON behind a seam.** Isolate JSON encode/decode behind one small
  module so `serde_json` (alloc) ↔ `serde-json-core` (no-alloc) is a swap, not a
  rewrite. Decide the seam's signature in M0 even if the swap comes later.

---

## M0 — Core skeleton + `no_std` gate  (go/no-go)

> Proof of concept. Move only what is already pure. **No behavior change; parity
> + tuyamock stay green.** If M0 lands clean, the approach is validated.

- [ ] **M0.1** Create the `rustuya-core` crate (`#![no_std]` + `extern crate alloc`), workspace wiring.
- [ ] **M0.2** Move `protocol/` (pack/unpack, message types) into core. Swap `std::net` → `core::net`; `HashMap` → `alloc::collections::BTreeMap` (or `heapless`) where it appears in core paths.
- [ ] **M0.3** Move `crypto.rs` into core with RustCrypto `default-features = false`. Confirm GCM + ECB paths byte-identical.
- [ ] **M0.4** Thread the RNG through: replace every internal `rand::rng()` (GCM IV @ `protocol/mod.rs`, handshake nonce @ `prepare_session_key_negotiation`, backoff jitter) with an injected `&mut impl RngCore`. Driver supplies `rand::rng()`; tests supply a seeded RNG.
- [ ] **M0.5** Define a core-local `Instant`/monotonic abstraction (no `std::time`), and a `no_std`-clean error enum (verify `thiserror` 2 `no_std`, else hand-roll).
- [ ] **M0.6** Re-land the tokio `rustuya` crate as a **driver** calling core for pack/unpack/crypto. `sync` facade + Python unchanged.
- [ ] **M0.7** **CI: bare-metal build gate.** `cargo build -p rustuya-core --no-default-features --target riscv32imc-unknown-none-elf` (add the target + a no-std smoke). Also `--target thumbv7em-none-eabi`.
- [ ] **M0.8** Green gates: `tinytuya_parity` (210/210), `tuyamock` integration (fast + slow), clippy, MSRV.

**Acceptance:** core compiles `no_std` for a bare-metal target; the tokio side is
byte-for-byte behavior-identical under the existing oracles.

## M1 — Device connection FSM into the core

> Extract the connection/handshake/reconnect lifecycle as `step()`. The tokio
> actor becomes a translator (`DevAction` ↔ tokio TCP/timer).

- [ ] **M1.1** Model the FSM: states (Connecting → Handshaking → Connected → Backoff → …) + `DevEvent`/`DevAction` as above.
- [ ] **M1.2** Port the session-key negotiation (already near-pure: prepare/verify/finalize) into the FSM.
- [ ] **M1.3** Port backoff + jitter as `StartTimer(Backoff, dur)` actions; decouple the `wait_for_backoff` sleep-vs-scanner-rediscovery `select` into `TimerFired` vs `DiscoveryUpdated` events.
- [ ] **M1.4** Port heartbeat + idle-timeout as timer events; port dev22 fallback decisions (largely already in `decision.rs`).
- [ ] **M1.5** Rewrite the tokio actor as a thin driver over the FSM. `persist` / `nowait` / `connect_now` semantics preserved.
- [ ] **M1.6** **Deterministic FSM tests at zero wall-clock** (e.g. `ConnectFailed → [StartTimer(Backoff, 16 s)]`), plus the seeded-RNG IV/nonce-uniqueness test. The 0.3 `slow` reconnect test can now have a fast pure-FSM twin.
- [ ] **M1.7** `tuyamock` E2E unchanged and green (the regression gate for this extraction).

**Acceptance:** reconnect/handshake/dev22 covered by pure zero-time tests; tokio
behavior unchanged under tuyamock.

## M1.5 — Blocking (`std`, no-tokio) driver  [optional, high-value]

> A second driver over the same core using `std::net::TcpStream` +
> `set_read_timeout` + `thread::sleep` — **no tokio**. Independent of M2; a
> natural payoff right after the Device FSM (M1). This is also the **std-side
> rehearsal for the ESP32 driver (M3)**: same core, blocking loop.

- [ ] **M1.5.1** One background `std::thread` per device runs the read → `handle_input` → drain-transmit → arm-`thread::sleep` loop, so `persist` keepalive + `listener()` work without a tokio runtime.
- [ ] **M1.5.2** `blocking` feature on the `rustuya` crate; a pure-sync consumer compiles with **tokio / mio / socket2 absent** from the dependency tree.
- [ ] **M1.5.3** Removes the `block_on`-from-within-a-runtime footgun (the M1.7 guard) for this path — there is no runtime to borrow.
- [ ] **M1.5.4** Scope note in docs: **small-scale only** — one thread per device, NOT for fleet. Fleet/Python stay on the tokio driver.

**Acceptance:** a single-device sync flow (status / set / persist / listener)
runs with tokio absent from the dependency tree; same core, same oracle.

## M2 — Discovery FSM into the core

> ESP32 is a **controller that needs local search**, so discovery is in scope.
> The core decides ports/payloads/timing; the driver owns the UDP sockets and
> broadcast.

- [ ] **M2.1** Model the scanner FSM: `ScanEvent`/`ScanAction`; move the already-pure helpers (`compute_port_diff`, `effective_bind_ip`, packet parse, cache/dedup, cooldown math) into the core.
- [ ] **M2.2** Broadcast scheduling + cooldowns as timer actions; payload/port selection (incl. v3.5 source-IP / `set_discovery_sources`) as pure output.
- [ ] **M2.3** Tokio driver owns UDP bind / `SO_BROADCAST` / send-recv; passive listener + active scan re-expressed as driver loops feeding the FSM.
- [ ] **M2.4** Discovery cache / watch-channel semantics preserved (no lost wakeups — cf. concurrency rules).
- [ ] **M2.5** Parity of discovery behavior against 0.3 (unit + any mock discovery coverage).

**Acceptance:** the scanner is a driver over a pure discovery FSM; behavior
matches 0.3.

## M3 — ESP32 driver (`rustuya-embassy`)  [0.5+]

> Only after M0–M2 are solid. This is where the Embassy-vs-esp-idf choice is
> finally made, ideally validated on real hardware against a real Tuya device.
> The M1.5 blocking driver is this one's std-side rehearsal — same core, same
> blocking-loop shape — so most of the driver pattern is already proven by here.

- [ ] **M3.1** Decide runtime: bare-metal Embassy (`esp-hal` + `embassy-net`/smoltcp) vs esp-idf `std`. Record rationale.
- [ ] **M3.2** `rustuya-embassy` driver: `embassy-net` TCP/UDP + `embassy-time` timers wired to the core FSMs; HW RNG (`esp-hal`) as the injected `RngCore`.
- [ ] **M3.3** Memory profile: bounded buffers, one device, tiny channels; evaluate swapping `serde_json` → `serde-json-core` in core if RAM-bound.
- [ ] **M3.4** Validate: connect + status + set + one reconnect against a real Tuya device (or the smoltcp-side of tuyamock) on ESP32.

**Acceptance:** a real controller flow runs on ESP32 sharing the core with the
tokio driver.

---

## Risk / landmine register

- `std::time::Instant` → core abstraction / injected `now`. (M0.5)
- `HashMap` in core → `alloc` `BTreeMap` or `heapless`. (M0.2)
- `parking_lot` / locks → gone in core (single-owner FSM). (M1)
- `rand::rng()` internal calls → injected `RngCore` everywhere. (M0.4)
- **`serde_json` is the heaviest core dep (RAM).** Keep JSON handling behind one
  seam so it can become `serde-json-core` later. (M0.2 / M3.3)
- `thiserror` 2 `no_std` — verify; hand-roll the core error enum if needed. (M0.5)
- **RX buffer growth** — the core reassembly buffer must be bounded at
  `MAX_PAYLOAD_LEN` and reset on overflow, or a malformed length field balloons
  RAM on ESP32. (D4 / M1)
- **Error-type split leakage** — if any `std::io::Error` sneaks into the core
  error, `no_std` breaks. Enforce with the M0.7 bare-metal build gate. (D5)
- **API drift during refactor** — the tokio/Python surface must stay 0.3-identical
  (D6); guard with the unchanged public API + the parity/tuyamock oracles.
- smoltcp broadcast constraints — absorbed in the embassy driver, not the core. (M3)
- **Reopening 0.3 hardening bugs** — the single biggest risk. Mitigation: the
  existing `tinytuya_parity` + `tuyamock` oracles gate every phase; no phase
  merges to `master` without them green.

## Definition of done for 0.4

- `rustuya-core` builds `no_std` for a bare-metal target in CI.
- `rustuya` (tokio) is a thin driver over the core; Python + `sync` unchanged;
  all 0.3 oracles green.
- Device + discovery lifecycle covered by pure, zero-wall-clock FSM tests.
- (Stretch / 0.5) at least one working driver on ESP32.
