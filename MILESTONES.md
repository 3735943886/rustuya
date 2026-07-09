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
