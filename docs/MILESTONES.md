# rustuya 0.4 — Sans-I/O Redesign Milestones

Splits rustuya into a **pure, `no_std` protocol/state-machine core** plus **thin
I/O drivers**, so the same protocol logic runs on a Linux/tokio host (fleet
scale) *and* on an ESP32-class microcontroller (single-device controller).

Long-lived branch `0.4-sansio`. The `0.3.x` line stays the prior stable release;
nothing here lands on `master` until a phase is oracle-green. 0.4 is a **pure-Rust
library** — the deliverable is the `rustuya-tokio` (and later `rustuya-embassy`)
Rust API. Design-decision detail lives in [`DESIGN.md`](DESIGN.md) (IDs S/P/Q/R).

---

## Why

- **Motivation:** tokio is a non-starter on ESP32 (needs mio/epoll; a
  multi-thread runtime on a 2-core, ~200 KB-RAM MCU is nonsensical). The wall is
  that **tokio + `std` must leave the core**. Sans-I/O is the mechanism (cf.
  `quinn-proto`, `rustls`).
- **Free wins:** the reconnect/backoff/handshake logic becomes a pure
  `step(event, now, rng)` machine → deterministic tests at **zero wall-clock**;
  injecting the RNG pins the random-IV/nonce property (tinytuya #722 immunity) as
  a test, not a convention.

## Non-goals / scope guards

- **Not** a wire-behaviour change. Wire behaviour and defaults stay as in 0.3.x;
  the 0.4 Rust API is a fresh surface (the 0.3 crate is not carried forward).
- **Not** committing to Embassy-vs-esp-idf now. The core targets `no_std + alloc`
  (the superset — compiles under both); the ESP32 flavour is a Phase-3 decision.
- **Not** zero-alloc. `alloc` is assumed; `heapless`/`serde-json-core` is a later
  option if RAM demands it, not a v0.4 requirement.
- `master` / `0.3.x` is **not** destabilised.

## Design invariants (hold across every phase)

1. **Core is `#![no_std]` + `alloc`.** No tokio, sockets, timers, threads, or
   locks (single-owner, driven by the driver).
2. **`now: Instant` and `rng: &mut impl RngCore` are injected.** The core never
   reads the clock or the OS RNG itself.
3. **Addresses use `core::net`** (stable 1.77; MSRV 1.88) — no `std::net` leak.
4. **Core owns policy, driver owns I/O.** "Which bytes/port/timer-duration,
   whether to reconnect" is the core; "open the socket, write, sleep" is the
   driver.
5. **Same oracle.** The core passes the existing `tinytuya_parity` fixtures and
   the `tuyamock` E2E suite — the regression net against reopening 0.3 fixes.
6. **`no_std` buildability is the acceptance gate.** CI builds the core for
   `riscv32imc-unknown-none-elf` / `thumbv7em-none-eabi` with
   `--no-default-features`. If it doesn't build `no_std`, the phase isn't done.
7. **Minimal core dependencies.** Prefer a `core`/`alloc` built-in over a crate;
   the only non-trivial deps are RustCrypto and the JSON seam.

## Target crate layout

```
rustuya-core     no_std + alloc   protocol · crypto · Device FSM · Discovery FSM
                                  (now/RNG injected; core::net; no I/O)
rustuya-tokio    std + tokio      thin driver: tokio TCP/UDP, one timer, RNG/clock
                                  injection over the FSMs
rustuya-embassy  no_std           thin driver: embassy-net + embassy-time  (Phase 3)
```

- **Core deps:** RustCrypto (`aes`/`aes-gcm`/`cipher`/`ecb`/`hmac`/`sha2`/`md-5`,
  `no_std`, default-features off — **do not hand-roll crypto**) · `rand_core`
  (the `RngCore` trait only) · `serde_json` behind the D8 seam (dynamic dps maps
  don't fit `serde-json-core`; don't pre-hand-roll JSON) · `base64`. Trimmed:
  `byteorder` (→ `from_be_bytes`), `thiserror` (→ hand-rolled `CoreError`), `log`
  (→ events).
- **Driver-only deps (must NOT appear in core):** `tokio`, `tokio-stream`,
  `socket2`, `futures-*`, the full `rand`.

## Sans-I/O interface (D1 resolved → poll-split)

```rust
pub enum DevInput<'a> {
    Connected,
    ConnectFailed,                 // neutral transport failure (D5), not std::io
    Received(&'a [u8]),            // driver read; core reassembles frames (D4)
    Send { cmd, data, cid, t },
    ConnectNow,                    // cancel backoff / revive terminal (P3)
    Closed,
}
impl Device {
    fn handle_input(&mut self, input: DevInput<'_>, now: Instant, rng: &mut impl RngCore);
    fn handle_timeout(&mut self, now: Instant, rng: &mut impl RngCore);
    fn poll_transmit(&mut self) -> Option<Vec<u8>>;    // bytes to send
    fn poll_event(&mut self)    -> Option<Event>;      // app events for listener()
    fn poll_timeout(&self)      -> Option<Instant>;    // THE single next deadline (D2)
}
// Discovery FSM is isomorphic (poll_transmit -> (Vec<u8>, port); poll_event -> Found/Seen).
```

Driver loop: read `poll_timeout()` and arm **one** timer; on socket-read /
timer / command, call the matching `handle_*`; drain `poll_transmit()` and
`poll_event()` to `None`. One deadline (no timer ids), no per-event `Vec`.

## Settled interface decisions

- **D1 — poll-split** (over `step -> Vec<Action>`): no per-event allocation, a
  single next-deadline so the driver tracks no timer ids, separate channels for
  bytes/deadline/events. Battle-tested (quinn-proto).
- **D2 — single next-deadline.** `poll_timeout()` returns the earliest of
  {backoff, heartbeat, idle, handshake}; the driver arms one timer.
- **D3 — injected monotonic `Instant(u64 millis)`** with saturating arithmetic;
  each driver builds it from its own clock. No `std::time` in the core.
- **D4 — RX reassembly buffer in the core, bounded** (`rx::RxBuffer`). Bounded by
  `peek_header`'s `MAX_PAYLOAD_LEN` check; cleared on teardown.
- **D5 — split error type.** `CoreError` carries no `std::io::Error`; transport
  failures enter as `ConnectFailed`. The driver's `TuyaError` wraps io.
- **D6 — fresh 0.4 Rust API.** The tokio driver defines a new surface
  (`rustuya-tokio`); it is not a drop-in for the 0.3 crate, which stays on 0.3.x.
- **D7 — concurrency primitives stay driver-side** (listener latch/replay,
  watch/broadcast, mpsc, connect-concurrency cap). The core only *emits* events.
- **D8 — JSON behind one seam** so `serde_json` ↔ `serde-json-core` is a swap.

---

## M0 — Core skeleton + `no_std` gate  (done)

- [x] **M0.1** `rustuya-core` crate (`#![no_std]` + `alloc`), workspace wiring.
- [x] **M0.2** `protocol/` (pack/unpack, message types) in core; `core::net`;
  `BTreeMap` in core paths.
- [x] **M0.3** `crypto.rs` in core with RustCrypto `default-features = false`;
  GCM + ECB byte-identical.
- [x] **M0.4** RNG threaded through: every internal `rand::rng()` (GCM IV,
  handshake nonce, backoff jitter) replaced by an injected `&mut impl RngCore`.
- [x] **M0.5** Core-local `Instant`/`Duration`, hand-rolled `CoreError` +
  `Display` (no `thiserror`, no `std::io::Error` — D5); `byteorder` → built-in.
- [x] **M0.6** Tokio driver lands as a thin driver calling core for
  pack/unpack/crypto — built from scratch as `rustuya-tokio` (M1.5), not a
  re-land of the dropped root crate.
- [x] **M0.7** CI bare-metal build gate: `cargo build -p rustuya-core
  --no-default-features --target {riscv32imc,thumbv7em}-none-*`.
- [x] **M0.8** Green gates: `tinytuya_parity`, `tuyamock` integration, clippy
  (`-D warnings`), MSRV.

## M1 — Device connection FSM into the core

- [x] **M1.1** FSM states (Connecting → Handshaking → Connected → Backoff → …) +
  `Input`/`Event` (poll-split). *`device.rs`.*
- [x] **M1.2** Session-key negotiation (prepare/verify/finalize) in the FSM.
  *`session.rs` + `device.rs`.*
- [x] **M1.3** Backoff + jitter as an injected `Backoff` policy + `poll_timeout`
  deadline (DESIGN P1/P2/P6). The wake half is `Input::ConnectNow` (one signal
  for both discovery-rewake and explicit `connect_now`).
- [x] **M1.4** Heartbeat + idle-timeout + handshake-timeout as timer events,
  merged into the single `poll_timeout` via `earliest()` (DESIGN P4/P5).
- [x] **M1.4b** `cid` threaded through the FSM so **sub-devices** work
  (`Input::Send { cid }` → `command::generate`). Pinned by a zero-time envelope
  test.
- [x] **M1.5** **Tokio driver** — a thin actor per device over the FSM
  (`rustuya-tokio`, from scratch; the legacy root crate is dropped). Loop:
  `wants_connect → dial`, `select!{cmd, socket, one poll_timeout timer}`, drain
  `poll_transmit`/`poll_event`. Injects only I/O (Send `StdRng`, `tokio::Instant`
  clock, TCP). Surface: `DeviceBuilder → Device` (`status`/`set_dps`/`set_value`/
  `request`), sub-devices `Device::sub(cid)`, `listener()` (a `Stream`),
  `is_connected`/`wait_connected`/`close`, `connect_now()`. Addressless connect
  via `DeviceBuilder::discover(&Discovery, timeout)` (resolves IP **and**
  version). Live rewake and `connect_now` are one `Input::ConnectNow` (cancel
  backoff / revive terminal `Closed`); the rewake carries a changed IP so a DHCP
  renewal self-corrects the resolve-once address (`Discovery::last_seen` exposes
  staleness as a fact, not a policy). Fleet routing is an O(1) `id → Route`
  registry, not an O(N²) broadcast forwarder (DESIGN R1–R4). Constructor stays
  `Device::builder`; the 0.3 addressless `Device::new` is intentionally dropped
  (it would need a process-global scanner — DESIGN Q1). E2Es: `rediscovery`,
  `connect_now`, `rediscovery_ip_change`, `discovery_seen_flap`, `fleet_scale`,
  `discover_connect` + the `tokio_control` example.
- [x] **M1.6** Deterministic FSM tests at zero wall-clock (backoff curve,
  jitter bounds) + the seeded-RNG handshake-nonce / GCM-IV uniqueness tests.
  *`device.rs`.*
- [x] **M1.7** `tuyamock` E2E wired to the tokio driver
  (`rustuya-tokio/tests/tuyamock*.rs`): spawns the real `tuyamock` subprocess
  (opt-in via `RUSTUYA_TUYAMOCK`) and drives status/set across every version
  (3.1/3.3/3.4/3.5) + device22. It caught a real bug the self-crafted
  `loopback.rs` mock could not — the v3.4/v3.5 `SessKeyNegResp` retcode the core
  decoded with `has_retcode=false` (the loopback mock, built on the library's own
  encoder, was self-consistent and blind to it). Fixed; both mocks made faithful.

## M1.5-blocking — Blocking (`std`, no-tokio) driver  [optional, not started]

> A second driver over the same core using `std::net::TcpStream` +
> `set_read_timeout` + `thread::sleep` — no tokio. The std-side rehearsal for the
> ESP32 driver (M3): same core, blocking loop.

- [ ] **B.1** One `std::thread` per device runs read → `handle_input` →
  drain-transmit → arm-`thread::sleep`, so persist keepalive + `listener()` work
  with no tokio runtime.
- [ ] **B.2** `blocking` feature; a pure-sync consumer compiles with tokio / mio
  / socket2 absent from the dependency tree.
- [ ] **B.3** Removes the `block_on`-from-within-a-runtime footgun (no runtime to
  borrow).
- [ ] **B.4** Docs: small-scale only — one thread per device, not for fleet.

## M2 — Discovery FSM into the core

- [x] **M2.1** Discovery FSM (`discovery::{Discovery, Input, Event, DeviceInfo}`);
  packet decode (6699/GCM + 55AA plaintext/ECB) + TTL cache/dedup in the core.
  Renamed from `scanner`; singleton dropped (DESIGN Q1–Q3).
- [x] **M2.2** Broadcast scheduling as timer actions (`StartScan`/`StopScan` +
  `poll_timeout`/`handle_timeout`, injected interval/burst); payload/port
  selection via a typed `Probe`/`Dialect` table (DESIGN Q4/Q5).
- [x] **M2.3** Tokio UDP driver over the discovery FSM
  (`rustuya-tokio/src/discovery.rs`). UDP bind (`SO_REUSEADDR`/`REUSEPORT`) +
  `SO_BROADCAST`; one reader task per socket → actor. Surface: `Discovery` /
  `DiscoveryBuilder` / `Discovered` (a `Stream`), `find(id, timeout)`,
  `discover_for(window)`, `known()`. `find` is race-free — a driver-side `known`
  map + subscribe-before-check resolves an already-announced device immediately
  (no magic short-TTL hack).
- [x] **M2.4** On-demand active probing — the 0.3 magic cadence constants
  (6 s/60 s/30 min/3) are gone (DESIGN Q4). Passive receive is always on; an
  active probe fires only on demand (a `find`/`scan` miss or a failed dial),
  batch-drained to one round per burst (single-flight), re-spaced by the device's
  own reconnect backoff. Multi-source probing restored (`local_ips`, one probe
  per source). Standalone `Discovery::scan(window)`/`known()`/`discovered()`/
  `request_scan()` work with no `Device`. E2E:
  `tests/discovery_active_ondemand.rs`.
- [x] **M2.4b** Discovery watch-channel semantics preserved — no lost wakeups
  (`find`/`register` subscribe-before-check).
- [x] **M2.5** Discovery behaviour under mock coverage
  (`tests/tuyamock_discovery.rs`, the gold-standard gate for the decode path).

**Acceptance:** discovery is a driver over a pure FSM; the decode path is
mock-gated.

## M3 — ESP32 driver (`rustuya-embassy`)  [0.5+]

> Only after M0–M2 are solid. Where the Embassy-vs-esp-idf choice is made,
> validated on real hardware. The blocking driver is its std-side rehearsal.

- [ ] **M3.1** Decide runtime: bare-metal Embassy (`esp-hal` +
  `embassy-net`/smoltcp) vs esp-idf `std`. Record rationale.
- [ ] **M3.2** `rustuya-embassy` driver: `embassy-net` TCP/UDP + `embassy-time`
  wired to the core FSMs; HW RNG as the injected `RngCore`.
- [ ] **M3.3** Memory profile: bounded buffers, one device, tiny channels;
  evaluate `serde_json` → `serde-json-core` if RAM-bound.
- [ ] **M3.4** Validate connect + status + set + one reconnect against a real
  Tuya device (or tuyamock's smoltcp side) on ESP32.

---

## Risk / landmine register

- **`serde_json` is the heaviest core dep (RAM).** Keep it behind the D8 seam so
  it can become `serde-json-core` later. (D8 / M3.3)
- **Error-type split leakage** — any `std::io::Error` in the core breaks
  `no_std`; enforced by the M0.7 bare-metal gate. (D5)
- **Reopening 0.3 hardening bugs** — the biggest risk. Mitigation: the
  `tinytuya_parity` + `tuyamock` oracles gate every phase; no phase merges to
  `master` without them green.
- **smoltcp broadcast constraints** — absorbed in the embassy driver, not the
  core. (M3)

## Definition of done for 0.4

- `rustuya-core` builds `no_std` for a bare-metal target in CI.
- `rustuya-tokio` is a thin driver over the core; all oracles green.
- Device + discovery lifecycle covered by pure, zero-wall-clock FSM tests.
- (Stretch / 0.5) at least one working driver on ESP32.
