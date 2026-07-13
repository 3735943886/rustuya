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
7. **Minimal core dependencies.** Every core dep must build `no_std` for the
   bare-metal target; prefer a `core`/`alloc` built-in or a few inline lines
   over a crate. The only non-trivial deps are RustCrypto (essential) and the
   JSON seam — everything incidental is trimmed (see the Core-deps note under
   Target crate layout).

## Target crate layout

```
rustuya-core       no_std + alloc   protocol · crypto · Device FSM · Discovery FSM
                                    (now/RNG injected; core::net; no I/O)
rustuya-tokio      std + tokio      thin driver: tokio TCP, one timer, RNG/clock
                                    injection over the FSM (M1.5, from scratch).
                                    Grows into UDP scanner + sync facade + Python
                                    surface; supersedes the reference root crate.
rustuya-embassy    no_std           thin driver: embassy-net + embassy-time  (Phase 3)
python             extension        unchanged; sits on rustuya (tokio)
```

- **Core deps (minimal — see the dependency policy below):**
  - _Essential, keep:_ RustCrypto (`aes`, `aes-gcm`, `cipher`, `ecb`, `hmac`,
    `sha2`, `md-5` — all `no_std`, default-features off; **do not hand-roll
    crypto**) · `rand_core` (the `RngCore` **trait only** — the RNG is injected,
    so **not** the full `rand`) · `core::net` for addresses.
  - _Keep behind the D8 seam:_ `serde` + `serde_json` (`alloc`). Dynamic dps
    payloads are arbitrary maps, which `serde-json-core` (no-alloc, fixed
    shapes) does not handle well — so keep `serde_json` for now; swap only if
    ESP32 RAM forces it. Do **not** pre-emptively hand-roll JSON (parity-oracle
    risk).
  - _Borderline:_ `base64` (small, no transitive deps) — keep or inline later.
  - **Trimmed out of core:** `byteorder` → `u32::from_be_bytes`/`to_be_bytes`
    (core built-in); `thiserror` → hand-rolled `CoreError` enum + `Display`
    (drops a proc-macro dep; `TuyaError` with io stays in the tokio driver);
    `log` → diagnostics surfaced as events, not a logging side effect.
- **Driver-only deps (must NOT appear in core):** `tokio`, `tokio-util`,
  `tokio-stream`, `socket2`, `rlimit`, `parking_lot`, `async-stream`,
  `futures-*`, the full `rand`, `env_logger`.

## Sans-I/O interface (shape)

```rust
// Device connection FSM — pure, single-owner, no I/O, no per-call allocation.
// Inputs are pushed IN; outputs are pulled OUT separately (quinn-proto style).
pub enum DevInput<'a> {
    Connected,
    ConnectFailed(TransportError),  // neutral transport error (D5), not std::io
    BytesReceived(&'a [u8]),        // driver read; core reassembles frames (D4)
    CommandQueued(Command),
    DiscoveryUpdated(IpAddr),       // replaces wait_for_backoff sleep+watch coupling
    Closed,
}
impl DeviceCore {
    // push inputs (mutate state; may arm/clear internal deadlines)
    fn handle_input(&mut self, input: DevInput<'_>, now: Instant, rng: &mut impl RngCore);
    fn handle_timeout(&mut self, now: Instant, rng: &mut impl RngCore);

    // pull outputs (driver drains each to None after any handle_*)
    fn poll_transmit(&mut self) -> Option<Vec<u8>>;    // bytes to send
    fn poll_event(&mut self)    -> Option<DeviceEvent>;// app events for listener()
    fn poll_timeout(&self)      -> Option<Instant>;    // THE single next deadline (D2)
}
// Discovery FSM is isomorphic: handle_input / handle_timeout, and
// poll_transmit -> Option<(Vec<u8>, u16 /*port*/)>, poll_event -> Discovered.
```

> **D1 resolved → poll-split (B).** Driver loop: read `poll_timeout()` and arm
> **one** timer; on socket-read / that-timer / command, call the matching
> `handle_*`; then drain `poll_transmit()` and `poll_event()` to `None`. One
> deadline (no timer ids), no per-event `Vec`, and send/event/timeout on
> separate channels — the identical shape drives the tokio, blocking, and
> embassy drivers.

---

## Key design decisions to settle before M0

Each is a fork that is expensive to reverse once M0 lands. Listed with a
**proposed** answer and the reasoning; these are for the maintainer to confirm
or override *before* any code, so the core's spine is settled up front.

- **D1 — Core API shape. RESOLVED (2026-07-09) → quinn-proto-style poll-split.**
  Entry points: `handle_input(input, now, rng)` + `handle_timeout(now, rng)`;
  outputs pulled via `poll_transmit() -> Option<Vec<u8>>`,
  `poll_event() -> Option<DeviceEvent>`, `poll_timeout() -> Option<Instant>`.
  The driver loops: feed input → drain transmits + events → arm the **one**
  timer at `poll_timeout`. *Why over `step -> Vec<Action>`:* battle-tested for
  exactly this (a connection state machine reused across runtimes incl.
  embedded), no per-event `Vec` allocation, a **single** next-deadline so the
  driver never tracks timer ids, and "bytes to send" / "next deadline" / "app
  events" stay on separate channels. See the interface sketch above.

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

- **D4 — RX reassembly buffer lives in the core, bounded. RESOLVED (2026-07-13)
  → `rx::RxBuffer`.** The core owns the receive buffer; `Input::Received(bytes)`
  appends any fragment and the FSM drains every whole frame via
  `RxBuffer::next_frame()` (partial → `Ok(None)`; malformed/oversized prefix →
  `Err` → teardown + `clear()`). Bounded by construction: `peek_header` rejects a
  declared length past `MAX_PAYLOAD_LEN`, so the buffer never exceeds one
  max-sized frame — predictable ESP32 RAM. The driver just pumps raw socket
  bytes; only the partial-frame state is core. `RxBuffer` is cleared on every
  teardown so a fresh socket starts empty.

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
- [ ] **M0.5** Define a core-local `Instant`/monotonic abstraction (no `std::time`), and a hand-rolled `CoreError` enum + `Display` (no `thiserror` in core; no `std::io::Error` — D5). Replace `byteorder` with `u32::from_be_bytes`/`to_be_bytes`.
- [ ] **M0.6** Re-land the tokio `rustuya` crate as a **driver** calling core for pack/unpack/crypto. `sync` facade + Python unchanged.
- [ ] **M0.7** **CI: bare-metal build gate.** `cargo build -p rustuya-core --no-default-features --target riscv32imc-unknown-none-elf` (add the target + a no-std smoke). Also `--target thumbv7em-none-eabi`.
- [ ] **M0.8** Green gates: `tinytuya_parity` (210/210), `tuyamock` integration (fast + slow), clippy, MSRV.

**Acceptance:** core compiles `no_std` for a bare-metal target; the tokio side is
byte-for-byte behavior-identical under the existing oracles.

## M1 — Device connection FSM into the core

> Extract the connection/handshake/reconnect lifecycle as `step()`. The tokio
> actor becomes a translator (`DevAction` ↔ tokio TCP/timer).

- [x] **M1.1** Model the FSM: states (Connecting → Handshaking → Connected → Backoff → …) + `Input`/`Event` (poll-split). *v2, `device.rs`.*
- [x] **M1.2** Port the session-key negotiation (prepare/verify/finalize) into the FSM. *v1, `session.rs` + `device.rs`.*
- [x] **M1.3** Backoff + jitter as an injected `Backoff` policy + `poll_timeout` deadline (SMELLS P1/P2/P6). Discovery-wake half (`DiscoveryUpdated`) deferred to the discovery increment — in poll-split it's a driver `select!` arm, not core `select`. *v2, `device.rs` + `time.rs`.*
- [x] **M1.4** Heartbeat + idle-timeout + handshake-timeout as timer events, all merged into the single `poll_timeout` via `earliest()` (SMELLS P4/P5 resolved; a stalled handshake no longer stalls forever). *v3, `device.rs`.* dev22 fallback decisions still to port from `decision.rs`.
- [x] **M1.4b (core)** Thread `cid` through the FSM so **sub-devices** work:
  `Input::Send` gained a `cid: Option<&'a str>` field, `on_send` forwards it into
  `command::generate` (which already took `cid` but was called with `None`). Pinned
  by `send_with_cid_targets_the_sub_device_in_the_envelope` (zero-time: the emitted
  frame's `devId`/`cid` address the sub-device). 77 lib + parity + no_std(riscv)
  green. Unblocks the sub-device half of M1.5.
- [ ] **M1.5** Tokio driver as a thin loop over the FSM — **driver skeleton
  landed, milestone not complete.** Built **from scratch** as a new
  `rustuya-tokio` crate (standalone `[workspace]`, path dep on `rustuya-core`),
  **not** an in-place rewrite of the legacy root `rustuya` crate (now
  reference-only). One `tokio::spawn`ed actor per device runs the canonical
  poll-split loop: `wants_connect → dial`, then
  `select!{cmd_rx, socket-read, one poll_timeout timer}`, then drain
  `poll_transmit → socket` / `poll_event → {waiters, listener bus}`. The driver
  injects **only** I/O — a Send `StdRng` (OS-seeded, keeps IV/nonce uniqueness),
  a `tokio::time::Instant` base for `now`, and TCP. *No protocol decisions in the
  driver.* `persist`/`nowait` collapse into the core's `auto_reconnect` knob;
  backoff/heartbeat/idle/handshake-timeout are all FSM-owned. Public surface so
  far: `DeviceBuilder → Device` with `status`/`set_dps`/`set_value`/`request`,
  lossless `listener()` (a `Stream`, so the README `while let Some(m) =
  l.next().await` idiom works verbatim), `is_connected`/`wait_connected`, graceful
  `close`, and **sub-devices** via `Device::sub(cid) → SubDevice` (rides M1.4b; a
  loopback test asserts the `cid` reaches the wire envelope). Fire-and-forget FIFO
  response correlation (no seqno matching — protocol has no token). A runnable
  `examples/tokio_control.rs` mirrors the README async shape (explicit address).
  **Still required by this milestone before it can close:** `connect_now` (M1.5
  explicitly lists it) and the Python surface. *Addressless connect now works:*
  `DeviceBuilder::discover(&Discovery, timeout)` resolves IP **and** version from
  the LAN (via M2.3) and connects — see `examples/discover_connect.rs`, pinned by a
  deterministic E2E (UDP announce → discover → TCP connect → status). *Live
  rediscovery-wake now works too (P3):* `DeviceBuilder::rediscover(&Discovery)`
  (also auto-linked by `discover`) spawns a forwarder that feeds the core's
  `Input::DiscoveryUpdated` on each re-announcement, so a device backing off
  redials the instant it reappears on the LAN — pinned by a deterministic E2E
  (1-hour backoff, reconnect happens *only* via the wake; `tests/rediscovery.rs`).
  **Still required before this milestone can close:** `connect_now` and the Python
  surface; a literal addressless `Device::new` is the last bit of the exact README
  snippet.
- [ ] **M1.6** **Deterministic FSM tests at zero wall-clock** (e.g. `ConnectFailed → [StartTimer(Backoff, 16 s)]`), plus the seeded-RNG IV/nonce-uniqueness test. The 0.3 `slow` reconnect test can now have a fast pure-FSM twin.
- [ ] **M1.7** `tuyamock` E2E unchanged and green (the regression gate for this extraction). *Interim:* `rustuya-tokio/tests/loopback.rs` drives the full stack (dial → connect → send → framed reply → decode → correlate) against a hand-rolled v3.3 device **and** a real v3.4 session-key handshake over loopback TCP — a from-scratch stand-in until `tuyamock` is wired to the new driver.

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

- [x] **M2.1** Model the discovery FSM (`discovery::{Discovery, Input, Event, DeviceInfo}`); packet decode (6699/GCM + 55AA plaintext/ECB) + TTL cache/dedup moved into the core. *v1, passive receive only — `discovery.rs`.* (Renamed from `scanner`; singleton dropped — SMELLS Q1–Q3.)
- [x] **M2.2** Broadcast scheduling as timer actions (`StartScan`/`StopScan` + `poll_timeout`/`handle_timeout`, injected interval/burst); payload/port selection as pure output via a typed `Probe`/`Dialect` table (SMELLS Q4/Q5). v3.5 source-IP is `Config::local_ip` (driver fills it — Q6). *v2, `discovery.rs`.* Scan-start cooldown/throttle stays a driver policy (when to send `StartScan`).
- [x] **M2.3** Tokio UDP driver over the discovery FSM — `rustuya-tokio/src/discovery.rs`.
  Owns UDP bind (`SO_REUSEADDR`/`REUSEPORT` so the well-known ports 6666/6667/7000
  are shareable) + `SO_BROADCAST` send; one reader task per socket funnels
  datagrams into a channel, and one actor runs `select!{datagram, control, one
  poll_timeout timer}` → drain `poll_transmit → broadcast socket` /
  `poll_event → announcement bus`. Public surface (no "scanner" name, matching the
  core rename): `Discovery` / `DiscoveryBuilder` / `Discovered` (a `Stream`),
  `find(id, timeout)`, `discover_for(window)`, `known()`. **Best-effort local-IP
  detection** fills `Config::local_ip` (Q6). `find` is race-free by design — it
  holds a driver-side `known` map (id → info) and subscribes *before* the cache
  check, so it resolves an already-announced device immediately instead of hanging
  on the dedup-suppressed re-announcement (this replaced a magic short-TTL test
  hack). Two loopback E2E tests (crafted UDP announcement → `DeviceInfo`).
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
- **RX buffer growth** — handled: `rx::RxBuffer` is bounded by `peek_header`'s
  `MAX_PAYLOAD_LEN` check (a malformed length field errors before it can balloon
  RAM) and cleared on teardown. (D4 — resolved)
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
