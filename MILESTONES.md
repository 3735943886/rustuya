# Rustuya — Hardening Milestones

The library already works in production. This document tracks **defense-in-depth**
improvements — edge cases, narrow races, and corners that don't show up in the
happy path but would bite under unusual call patterns, stress, or maintenance.
The goal is "more robust, fewer surprises for future contributors," not "fix a
broken library."

Items are grouped by milestone; each one links to the offending site and lists
the concrete change.

> ### Out of scope: request/response correlation
>
> The Tuya LAN protocol is **fundamentally asynchronous**: the device treats
> inbound commands as fire-and-forget and independently emits unsolicited
> `Status` pushes whenever its DPs change. There is no correlation token on
> the wire — many firmwares echo `seqno=0` or a device-side counter unrelated
> to the request.
>
> As a structural consequence, an unsolicited `Status` push that arrives between
> `subscribe()` and the user's next request can be surfaced as that request's
> "response". **This is not a bug to be fixed.** It is the shape of the protocol.
>
> The intended pattern is:
> - subscribe to `listener()` for asynchronous device-pushed events;
> - serialize request/response calls per `Device` handle for synchronous-style
>   reads.
>
> A code comment at [device.rs:1354](src/device.rs#L1354) records this so future
> reviewers do not re-raise it. **Do not file this as an issue.**

---

## M1 — Correctness & Silent-Failure Hardening

Items in this group close paths where the library *could* silently return wrong
data, drop packets, or wedge forever under non-happy-path inputs (stop/restart,
runtime reconfiguration, narrow races). None of these are believed to be
currently triggering in production use — they're defense in depth.

- [x] **M1.1 — Scanner: replace one-shot `CancellationToken` with a re-creatable token**
  - Site: [scanner.rs:75-77, 326-330](src/scanner.rs#L326-L330)
  - Problem: `stop_passive_listener` calls `cancel()` once; subsequent `ensure_passive_listener` reuses the cancelled token, so new receivers exit immediately. Scanner becomes permanently dead.
  - Fix: wrap `cancel_token` in `parking_lot::RwLock<CancellationToken>` (or use `child_token`); reset on every start.

- [x] **M1.2 — Scanner: dispatcher must consume all receiver channels, not just the first**
  - Site: [scanner.rs:203-249, 257, 340-348](src/scanner.rs#L203-L249)
  - Problem: `spawn_receiver_tasks` creates a fresh `(tx, rx)` pair on each call, but the dispatcher only polls the *first* `rx`. After `set_ports` adds a port, packets on the new socket are silently dropped.
  - Fix: single long-lived `mpsc` whose `tx` is cloned to every receiver task; dispatcher polls the single `rx`. Or store a `Vec<rx>` and use `tokio_stream::StreamMap`.

- [x] **M1.3 — Scanner: track dispatcher `JoinHandle` so `Drop` can abort it**
  - Site: [scanner.rs:213-249](src/scanner.rs#L203-L249)
  - Problem: dispatcher `JoinHandle` is discarded; only the receiver tasks live in `receiver_tasks`. Leaks the dispatcher on `Drop`.
  - Fix: push the handle into `receiver_tasks` (or a separate field) so `Drop` aborts it.

- [x] **M1.4 — Device: replace `Notify::notified()` re-subscribe race with a `watch` channel**
  - Site: [device.rs:1037-1098](src/device.rs#L1037-L1098)
  - Problem: between `.set(get_scanner().notified())` and the next `.await`, a discovery notification can fire and be lost permanently (`Notify` only buffers one permit).
  - Fix: convert `Scanner` to publish discovery events on a `tokio::sync::watch` (or `broadcast`); subscribe once at the top of `wait_for_backoff`.

- [x] **M1.5 — Device: `persist=false` must still honor backoff**
  - Site: [device.rs:973-1010](src/device.rs#L973-L1010)
  - Problem: the no-persist branch loops on user-command arrivals without invoking jitter/backoff, hammering the network when a device is unreachable.
  - Fix: always run through `wait_for_backoff` before the next `connect_and_handshake` attempt; `persist=false` only controls *whether* to retry, not the spacing.

- [x] **M1.6 — Device: prefix-scan must surface a hard error after N bytes**
  - Site: [device.rs:1647-1674](src/device.rs#L1647-L1674)
  - Problem: when no valid prefix is found in 1024 bytes, `Ok(None)` is returned and the reader keeps spinning — the connection appears alive but produces nothing.
  - Fix: return `Err(TuyaError::KeyOrVersionError)` so the actor reconnects.

- [x] **M1.7 — Sync wrapper: panic-guard `blocking_send` against tokio runtime context**
  - Site: [sync.rs:54-75](src/sync.rs#L54-L75)
  - Problem: any sync call made from inside a tokio runtime panics with "Cannot block the current thread from within a runtime". No documentation, no guard.
  - Fix: at the top of `send_sync` / `wait_for_response!`, check `tokio::runtime::Handle::try_current()` and return `TuyaError::io_other("rustuya sync API called from inside a tokio runtime — use rustuya::Device (async) instead")`. Add a doc-warning to every sync method.

- [x] **M1.8 — Scanner: timeout window > last broadcast + RTT**
  - Site: [scanner.rs:62-65, 719-728](src/scanner.rs#L719-L728)
  - Problem: `BROADCAST_INTERVAL=6s`, `count<3` → up to 18s of broadcasting, with total timeout also 18s — zero margin for the device's reply.
  - Fix: either drop max broadcasts to 2 (12s of broadcast + 6s of receive) or extend timeout to e.g. 24s.

---

## M2 — Concurrency, Lifecycle & Resource Cleanup

- [x] **M2.1 — `Device::stop` / `close` should use a dedicated control channel**
  - Site: [device.rs:594-615](src/device.rs#L594-L615), [sync.rs:216-222](src/sync.rs#L216-L222)
  - Problem: shutdown commands ride the same FIFO as user requests, so they wait for any in-flight `status()` to finish before the cancel token fires. Async-side: `tx.send(Disconnect)` after `cancel()` can be dropped if the actor already exited.
  - Fix: add a `cancel-fast` lane (separate oneshot or cancel-with-payload) so shutdown short-circuits the queue. Make `close` idempotent and document ordering.

- [x] **M2.2 — Drop semantics: sync wrapper must propagate shutdown to async core**
  - Site: [sync.rs](src/sync.rs) (no `Drop` impl), [device.rs:251-272](src/device.rs#L251-L272)
  - Problem: listener tasks `clone()` the inner `AsyncDevice`, keeping it alive after the user drops their handle. The user expects "drop = shutdown" but gets a leaked actor.
  - Fix: use `Weak<DeviceInner>` inside long-running listener tasks; add explicit `Drop` to sync `Device`/`SubDevice`/`Scanner` that calls `cancel_token.cancel()`.

- [x] **M2.3 — `get_cipher` must use read-then-upgrade locking**
  - Site: [device.rs:1778-1796](src/device.rs#L1778-L1796)
  - Problem: every pack/unpack acquires a write lock, serializing reader and writer halves of the same connection.
  - Fix: `state.read()` first; only `state.write()` on cache miss. Move `TuyaCipher::new` (fallible) out of the critical section.

- [x] **M2.4 — Scanner: replace `8.8.8.8` phone-home with interface introspection**
  - Site: [scanner.rs:397-404](src/scanner.rs#L397-L404)
  - Problem: fails on offline, air-gapped, or blocked networks; on failure returns `0.0.0.0`, which devices ignore.
  - Fix: use `if_addrs` or platform routing (`route get`) to discover the LAN interface IP; surface an explicit error if none found.

- [x] **M2.5 — `get_local_ip` must not block in async**
  - Site: [scanner.rs:397-404](src/scanner.rs#L397-L404)
  - Problem: synchronous `std::net::UdpSocket` calls inside an `async fn` block the worker thread.
  - Fix: wrap in `tokio::task::spawn_blocking` or pre-compute once at scanner build time.

- [x] **M2.6 — `active_scanning` flag must use `compare_exchange`**
  - Site: [scanner.rs:471-485, 629-650](src/scanner.rs#L471-L485)
  - Problem: load→store on `AtomicBool` is not atomic; two concurrent stream starts both believe they "won" and both spawn discovery loops.
  - Fix: `compare_exchange(false, true, …)` to gate the spawn.

- [x] **M2.7 — `scan_stream` notify-wait race**
  - Site: [scanner.rs:483, 513-541](src/scanner.rs#L513-L541)
  - Problem: stream-side `notified()` registered after `notify_waiters()` fires misses the signal; falls through to `sleep(remaining)`.
  - Fix: follow the documented `Notify` pattern — create `notified()` *before* checking the cache, then check cache, then `.await` the future.

- [x] **M2.8 — `seqno` wrapping**
  - Site: [device.rs:1530-1554](src/device.rs#L1530-L1554)
  - Problem: `*seqno += 1` panics in debug on overflow.
  - Fix: `wrapping_add(1)`. Document that seqno wrap is harmless given M1 note above.

- [x] **M2.9 — `get_timestamp().unwrap_or_default()` masks clock skew**
  - Site: [device.rs:689-694](src/device.rs#L689-L694)
  - Problem: silently sends `t=0` if the system clock is broken; devices may reject without indication.
  - Fix: log a warning on `SystemTimeError`; consider returning `TuyaError::io_other`.

---

## M3 — API Surface Hygiene

- [x] **M3.1 — Remove `Deref<Target = AsyncDevice>` from sync wrapper**
  - Site: [sync.rs:245-250, 396-401](src/sync.rs#L245-L250)
  - Problem: sync handles auto-coerce to async, hiding which API the caller is invoking. The point of a sync wrapper is to be sync.
  - Fix: replace with an explicit `as_async(&self) -> AsyncDevice` accessor. Mirror every missing setter/getter (`set_persist`, `set_timeout`, `set_port`, `set_nowait`, `set_version`, `set_dev_type`, `set_address`, `connect_now`, `is_connected`, `is_stopped`, `receive`, `dev_type`, `local_key`, `address`) on the sync side.

- [x] **M3.2 — Hide pyo3-only types behind a `#[cfg]` re-export module**
  - Site: [sync.rs:49-52, 86-99, 314-323](src/sync.rs#L49-L99)
  - Problem: `DeviceCommand`, `SubDeviceCommand`, `SyncRequest` are `pub` (with `#[doc(hidden)]`) just so the Python crate can see them — pure encapsulation leak.
  - Fix: move them into `pub mod internal` gated behind `#[cfg(feature = "bindings")]`, off by default.

- [x] **M3.3 — Scanner: make `pub` fields private; reconcile static vs builder APIs**
  - Site: [scanner.rs:108-113](src/scanner.rs#L108-L113), [sync.rs:420-468](src/sync.rs#L420-L468)
  - Problem: `Scanner.ports`, `.bind_addr`, `.timeout` are `pub` but mutating them does not reach the listener. Static `Scanner::scan()` and builder-built instances behave differently and silently.
  - Fix: make fields private with setters that go through `ensure_passive_listener`. Either drop the static API or document that it always uses default config.

- [x] **M3.4 — Builder finalizer name**
  - Site: [device.rs:237-239](src/device.rs#L237-L239)
  - Problem: `run()` as terminal verb is ambiguous (does it block?).
  - Fix: rename to `build()`; keep `run()` as a deprecated alias for one release.

- [x] **M3.5 — `Device::new` should not spawn until connected**
  - Site: [device.rs:276-282](src/device.rs#L276-L282)
  - Problem: spawning on the dedicated runtime at construction time is surprising; failures are deferred.
  - Fix: lazy spawn on first `request` / `connect_now`, or document the eager-spawn contract prominently.

- [x] **M3.6 — `bridge_to_sync` must surface listener errors**
  - Site: [sync.rs:231](src/sync.rs#L231)
  - Problem: single-device listener silently drops `Err` (`filter_map(|res| async move { res.ok() })`); unified listener preserves them.
  - Fix: pass `Result<TuyaMessage>` through.

- [x] **M3.7 — `pub fn discover_device_internal` should be crate-private**
  - Site: [scanner.rs:584](src/scanner.rs#L584)
  - Fix: change to `pub(crate)`.

- [x] **M3.8 — Hot-path getters and the `RwLock`** *(no code change, intentional)*
  - On re-evaluation: `parking_lot::RwLock::read()` is ~10ns uncontended, and the genuinely hot path (`get_cipher`) was already moved off the write lock in M2.3. The remaining getters (`dev_type`, `version`, `timeout`, `port`, `persist`, `is_connected`, `address`) are not called in tight loops; the cost is dominated by network IO.
  - Dual-storing each field in an atomic shadow would create a synchronization invariant easy to break on a setter, in exchange for negligible wins.
  - A doc comment at [`Device::dev_type`](src/device.rs) records this decision so future reviewers don't re-raise it. If profiling ever shows a specific getter is hot, atomicize that single field instead of refactoring the whole state.

---

## M4 — Code Hygiene & Refactoring

- [x] **M4.1 — Extract response-matching logic from `process_command`**
  - Site: [device.rs:1317-1466](src/device.rs#L1317-L1466) (~150 lines, 6 levels nested)
  - Fix: factor `match_response(msg, target_cid) -> MatchOutcome { Accept, Continue, Stop }` as a pure function. Unit-test exhaustively.

- [x] **M4.2 — Collapse duplicated `generate_payload` arms in v3.1/v3.2/v3.3 and v3.4/v3.5**
  - Site: [protocol/v31.rs](src/protocol/v31.rs), [v32.rs](src/protocol/v32.rs), [v33.rs](src/protocol/v33.rs), [v34.rs](src/protocol/v34.rs), [v35.rs](src/protocol/v35.rs)
  - Fix: extract a `legacy_payload` helper (v3.1/3.2/3.3 family) and a `modern_payload` helper (v3.4/3.5 family). Per-version differences become small overrides.

- [x] **M4.3 — Decouple `Drop for Device`**
  - Site: [device.rs:267-272](src/device.rs#L267-L272)
  - Problem: empty `Drop` block, no value.
  - Fix: remove it; `DeviceInner::drop` already does the work.

- [x] **M4.4 — `decrypt_and_clean_payload` has unused `_prefix` parameter**
  - Site: [device.rs:1755](src/device.rs#L1755)
  - Fix: remove the parameter and callers.

- [x] **M4.5 — Move stray string constants into the `keys` module**
  - Site: [device.rs:1829-1832](src/device.rs#L1829-L1832) (`"data"`, `"payload"`)
  - Fix: move to the central constants module.

- [x] **M4.6 — Replace `wait_for_response!` macro with a generic helper**
  - Site: [sync.rs:64-75](src/sync.rs#L64-L75)
  - Fix: `fn wait_for_response<C, F: FnOnce(Sender<R>) -> C, R>(tx: &Sender<C>, build: F) -> Result<R>`.

- [x] **M4.7 — Constants for sync channel capacities**
  - Site: [sync.rs:129, 335, 434](src/sync.rs#L129)
  - Fix: `const CHAN_COMMAND_CAPACITY: usize = 32;` with a sizing rationale comment.

- [x] **M4.8 — Drop the `hex` dependency**
  - Site: [device.rs:16](src/device.rs#L16), used once
  - Fix: replace with a four-line inline encoder.

---

## M5 — Testability & Coverage

- [ ] **M5.1 — Trait-ify external dependencies for injection** *(deferred)*
  - The real value of `trait ScannerHandle` / `trait Clock` / generic `AsyncRead+Write` plumbing is **enabling** the mock-TCP integration tests in M5.2 — a partial implementation without those tests isn't useful, and the trait shapes are best designed informed by the tests they need to support. Deferred to a single follow-up that lands the traits and the mock-driven actor tests together, so the trait surface is justified by the assertions it makes possible rather than guessed up-front.

- [x] **M5.2 — Integration tests for the actor** *(partial)*
  - Lifecycle tests landed in [device.rs tests](src/device.rs): `fire_close_marks_disconnected_but_not_stopped`, `fire_stop_marks_stopped_and_cancels_token`, `close_notify_wakes_subscribers`, `dropping_last_device_clone_cancels_token`.
  - **Done (rc.4)** — covered via the external [tuyamock](https://pypi.org/project/tuyamock/) device emulator rather than an in-house capture-replay server: [`python/tests/test_tuyamock_integration.py`](python/tests/test_tuyamock_integration.py) drives the real client against an in-process mock across v3.1–v3.5 plus the device22 dialect, exercising connection / framing / encryption / the v3.4+v3.5 session-key handshake and dev22 status flow end-to-end (run in CI by the `python-integration` job). Broadcast-lag / error-cmd-0 paths remain covered by Rust unit tests only.

- [x] **M5.3 — Sync-wrapper unit tests for worker lifecycle** *(partial)*
  - Bridge tests cover overflow drop-and-resume and exit-on-receiver-disconnect ([sync.rs tests](src/sync.rs)).
  - Runtime-context panic guard tested both inside and outside a runtime.
  - **Still pending**: explicit "Close/Stop delivered even when worker queue has in-flight commands" — current sync `close`/`stop` now bypass the worker entirely (M2.1), so this scenario is structurally avoided rather than tested.

- [x] **M5.4 — Scanner integration tests** *(partial)*
  - Concurrent claim test landed: `active_scanning_compare_exchange_is_single_winner` (M2.6 regression).
  - `packet_tx_lifecycle_persists_then_clears_on_stop` covers the M1.2 channel-sharing invariant at the state-machine level.
  - `reset_cancel_token_yields_fresh_uncancelled_token` covers M1.1 at the same level.
  - **Still pending**: end-to-end tests that actually bind UDP sockets (set_ports after start, stop+restart cycle, real broadcast/receive). These need a network mocking layer; deferred with M5.1.

- [x] **M5.5 — State-machine tests for `ConnectionState` transitions**
  - Hand-rolled exhaustive tests rather than `proptest` (4-state machine, the table fits): `stopped_is_terminal_for_fire_close`, `fire_stop_is_idempotent`, `fire_close_does_not_set_stopped` in [device.rs tests](src/device.rs).
  - Pulling in `proptest` as a dev-dep for this would have been overkill given how small the state space is.

---

## M6 — Documentation & Release Polish

- [x] **M6.1 — Doc-warning on every sync method** about runtime-context behavior.
- [x] **M6.2 — Add module-level "when to use sync vs async" doc** to [lib.rs](src/lib.rs).
- [x] **M6.3 — Document the seqno-matching gap** prominently in `Device::status` / `Device::request` rustdoc, mirroring the inline comment at [device.rs:1354](src/device.rs#L1354).
- [ ] **M6.4 — Tracing migration** *(deferred)* — replacing `log` with `tracing` touches 50+ sites and would shift the consumer-facing logging contract (subscribers must change). The current `log` facade integrates cleanly with `pyo3-log` in the bindings crate; switching to `tracing` would force a parallel change there too. Scoped as a single follow-up PR: it's a worthwhile diagnostics improvement (span-aware logs around the actor's connection/heartbeat/scanner cycles) but it doesn't fit in the hardening pass.
- [x] **M6.5 — `CHANGELOG.md`** curated by hand as the single source of truth (git-cliff/`cliff.toml` removed — it produced a divergent commit-derived changelog that competed with the curated file); the publish workflow extracts the tag's `## [version]` section for the GitHub Release body. Security/correctness items from M1 are called out prominently.
- [x] **M6.6 — `cargo deny` / `cargo audit`** in CI to track supply-chain.

---

## Pre-0.3.0-stable checklist

Items to handle before promoting `0.3.0-rc.X` to a stable `0.3.0` tag.
Collected here so they don't get lost between rc cycles.

- [x] **docs/rust-api.md**: `.run()` → `.build()` at line 64. ✅ Done in rc.3 (the DeviceBuilder example now shows `.build()`).
- [ ] **docs/getting-started.md**: bump `rustuya = "0.2"` (line 13) → `"0.3"` once 0.3.0 stable is tagged. Cargo will not resolve pre-release versions from a plain `"0.3"` requirement, so leaving the example at `"0.2"` during the rc cycle is intentional; flip it the moment stable ships.
- [x] **docs/rust-api.md / docs/getting-started.md**: added a "sync vs async" note mirroring the [`lib.rs` section](src/lib.rs) — rust-api.md now carries the facade-choice table + the "don't call sync from inside a tokio runtime" caveat, and getting-started.md's Rust quick-start points to it.
- [x] **docs/python-api.md**: reviewed — no `.run()` references anywhere under `docs/` (grep clean); the python-side API is unchanged (`Device(...)` works the same way). Nothing to fix.
- [x] **README.md** (crates.io / GitHub / PyPI front page): expanded from a 1-line pitch into a first-impression page (install, Python + Rust quick-start, four-bullet feature list, Python-scale differentiation sentence, tinytuya credits). Single README is now shared across all three registries — `python/README.md` is a symlink to the root README, and `python/pyproject.toml` reads it as `readme = "README.md"` (maturin's sdist builder rejects `../` paths, so symlink is the canonical workaround). Verified with `maturin sdist`: PKG-INFO embeds the full README with `Description-Content-Type: text/markdown`.
- [x] **Real-device verification replaced by the tuyamock emulator (rc.4).** The actor's session-key negotiation and dev22 status paths now have end-to-end coverage against the [tuyamock](https://pypi.org/project/tuyamock/) device emulator (v3.1–v3.5 + device22) via [`python/tests/test_tuyamock_integration.py`](python/tests/test_tuyamock_integration.py), run in CI (`python-integration` job) — no physical hardware required. (The scanner-IP-mismatch path remains unit-tested only.)
- [x] **MSRV set to 1.88.** `rust-version = "1.88"` added to both `Cargo.toml` and `python/Cargo.toml`. Empirically verified: `cargo check --all-features` passes on 1.88.0 and fails on 1.87.0 (`error[E0658]: let expressions in this position are unstable`). The binding constraint is let-chains (`&& let`, ~11 sites) — stabilized only in edition-2024 + Rust 1.88; `let ... else` (1.65) is well below it.
