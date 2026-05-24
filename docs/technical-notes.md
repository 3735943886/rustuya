# Technical Notes

Internal-design notes for maintainers. Things that aren't obvious from a
single file but are worth knowing before changing behavior. The public API
reference lives in [`rust-api.md`](rust-api.md) / [`python-api.md`](python-api.md);
the high-level layering is in [`architecture.md`](architecture.md). This
document is for **how the runtime actually behaves** — lifecycles, channels,
timers, and the small decisions that the docs above gloss over.

---

## 1. Runtime

[`src/runtime.rs`](../src/runtime.rs) holds a process-wide, lazily
initialized multi-thread tokio runtime (`OnceLock<Runtime>`). Every
background task in the library is spawned on this runtime — `crate::runtime::spawn`,
not `tokio::spawn`.

**Why a dedicated runtime?** Spawning on `try_current` previously attached
scanner / device tasks to the *consumer application's* runtime. That made
clean shutdown of the consumer's runtime kill our background tasks at
arbitrary points (mid-handshake, mid-reconnect), and made `Device::new`
silently fail when called from outside any async context.

Consequences:

- `Device::new` and `Scanner::scan()` are safe to call from sync code; the
  tasks run on rustuya's own runtime.
- Calling them from inside `#[tokio::main]` is also fine — our tasks do
  *not* attach to the caller's runtime.
- If the consumer drops their tokio runtime, our tasks keep running. They
  exit only on explicit cancel (`Device::stop`, `Scanner::stop_passive_listener`)
  or when the relevant `Arc` reaches zero strong refs.

`runtime::maximize_fd_limit()` raises `RLIMIT_NOFILE` to the hard limit on
Unix. Called by the Python bindings on module init; not called automatically
from the Rust side (consumers may have their own fd policy).

---

## 2. Scanner

[`src/scanner.rs`](../src/scanner.rs). The whole scanner is a **process-wide
singleton** — `static GLOBAL_SCANNER: OnceLock<Scanner>`. `Scanner::get()` /
`scanner::get()` initialize on first access and return a `&'static Scanner`.
There is no public constructor and no builder: every consumer goes through
the singleton, and every configurable knob (`set_timeout`, `set_ports`,
`set_bind_address`) takes `&self` and mutates the singleton's interior state.
(A `ScannerBuilder` existed up through 0.3.0-rc.1 but spawned an independent
instance that bound the same UDP ports — packets went to one socket
nondeterministically, so it was removed.)

### Singleton lifecycle

- `Scanner::new()` is **eager**: it constructs the state and immediately
  calls `ensure_passive_listener()`, which binds UDP sockets on the default
  ports (`6666`, `6667`, `7000`) and spawns one receiver task per socket
  plus one dispatcher task.
- The singleton lives for the rest of the process. Drop is not a meaningful
  operation; the only way to "stop" it is `stop_passive_listener()`, which
  cancels the receiver+dispatcher tasks, closes the shared packet channel,
  and clears the bound sockets. The cache stays.
- A subsequent `set_ports()` / `scan()` call re-runs `ensure_passive_listener`
  and rebuilds everything. `cancel_token` is **replaced** (not just
  cancelled) on each stop — `CancellationToken` is one-shot by design, so
  reusing a cancelled instance would make every new task exit immediately.
  (M1.1 regression.)

### The shared packet channel

One long-lived `mpsc<(Vec<u8>, SocketAddr)>` is shared across **all**
receiver tasks. When `set_ports()` adds a port mid-flight, the new
receiver task clones the existing sender — so its packets reach the same
dispatcher. Before M1.2 each call to `spawn_receiver_tasks` created a
fresh channel whose `rx` was never polled, silently dropping every packet
on the newly-added port.

### Discovery notifications use `watch`, not `Notify`

`Notify::notified()` had a narrow re-subscribe race: a publish that fired
between two `notified().await` calls could be lost. The fix
([`ScannerState::discovery_version`](../src/scanner.rs#L99)) is a
`tokio::sync::watch::channel::<u64>`. Each cache update bumps the counter;
subscribers `changed().await` and re-read the cache. The carried value is
opaque — the *change itself* is the signal.

Subscribers are pre-marked-seen (`mark_unchanged()`) so only future updates
resolve `changed()`. This pattern shows up in [`subscribe_discoveries`](../src/scanner.rs#L165),
[`scan_stream_instance`](../src/scanner.rs#L657), and
[`wait_for_backoff`](../src/device/actor.rs#L496).

### Timing invariants

[`scanner.rs:62-80`](../src/scanner.rs#L62-L80) — discovery active-scan
schedule:

```
t=0       broadcast #1   (interval fires immediately on first tick)
t=6s      broadcast #2
t=12s     broadcast #3   (MAX_BROADCASTS reached)
t=18s     timeout        (RECEIVE_MARGIN of 6s after the last broadcast)
```

`DEFAULT_SCAN_TIMEOUT` is **derived** from `BROADCAST_INTERVAL`,
`MAX_BROADCASTS`, and `RECEIVE_MARGIN`. A unit test
([`scan_timeout_leaves_room_after_last_broadcast`](../src/scanner.rs#L1099))
pins the invariant so a future tweak to one constant can't silently destroy
the receive window for late replies.

Other timers:

- `GLOBAL_SCAN_COOLDOWN = 1800s` (30min) — minimum gap between full
  active scans, scanner-wide.
- `SCAN_THROTTLE_INTERVAL = 60s` — minimum gap between user-triggered
  `discover_device` scans.
- `CACHE_TTL = 86400s` (24h) — entries older than this are dropped on the
  next cache write.

### Active-scan single-winner

Multiple concurrent `scan_stream()` callers must not both start a discovery
loop. The "I am the active scanner" claim is a `compare_exchange` on
`active_scanning: AtomicBool`. Losers fall through to subscribe to the
discovery channel and yield results from the cache as they arrive.
Regression test: [`active_scanning_compare_exchange_is_single_winner`](../src/scanner.rs#L1187).

### Local-IP discovery

`discover_local_ip_blocking` tries `8.8.8.8`, `255.255.255.255`, and
`203.0.113.1` (TEST-NET-3). UDP `connect()` only does a kernel route
lookup — no packet is actually sent. Works on air-gapped LANs where
`8.8.8.8` is unreachable.

**Intentionally not cached.** A previous `OnceLock<Option<String>>` froze
the IP at first call, so a host whose IP later changed (DHCP renewal, WiFi
switch, VPN up/down, container restart, …) would forever stamp the stale
address into v3.5 discovery broadcasts. The lookup is sub-millisecond and
only runs from `send_discovery_broadcast`, which fires at most a few times
per active scan and is itself throttled by the 30-minute global scan
cooldown — so the saved cost was negligible compared to the staleness risk.
Only v3.5 (port 7000) discovery payloads carry the local IP; v3.1–v3.4
broadcasts omit it.

### `parse_packet` is brute-force by design

Tuya UDP discovery payloads can be: raw JSON, AES-ECB encrypted with one
of three different keys (`UDP_KEY_33` / `_34` / `_35`), wrapped in `55AA`
or `6699` envelopes, with or without a retcode field. There is no single
in-packet hint of which combination to try. `parse_packet` iterates all
key × retcode × envelope permutations and returns the first one whose
output parses as JSON with a `gwId` / `devId`. The brute-force is bounded
(~12 attempts per packet) and only runs on packets that already passed the
cheap raw-JSON attempt.

---

## 3. Device

### Construction is eager

`Device::new` / `DeviceBuilder::build` immediately spawn a long-running
background task on rustuya's runtime — `run_connection_task` in
[`src/device/actor.rs`](../src/device/actor.rs). The task performs
reconnects, heartbeats, and IP rediscovery. It stays alive until:

- the last `Arc<DeviceInner>` strong ref drops, or
- `Device::stop()` / `Device::fire_stop()` is called.

The constructor itself returns quickly — real TCP work happens on the
spawned task. **Construct devices lazily if you may have hundreds-to-thousands**
of them; each one starts a task on construction.

### Initial jitter

The connection task sleeps a uniform random 0–5000 ms before its first
connect attempt ([`actor.rs:147`](../src/device/actor.rs#L147)). This
prevents a thundering herd when many devices are constructed
back-to-back at process startup. Tests that measure Arc counts must
account for this — see the note in
[`unified_listener_cycle_does_not_leak_inner_arcs`](../src/device/listener.rs#L651).

### `Arc<DeviceInner>` ownership graph

- The user-side `Device` holds an `Arc<DeviceInner>` + a `Sender` half of
  the command mpsc.
- The background connection task (spawned in `with_builder`) holds a
  `Weak<DeviceInner>` *outside* the `select!`, then upgrades to `Arc`
  inside. If the user drops every `Device` clone and there are no other
  strong refs, the upgrade fails and the task exits.
- Each `Device::listener()` call adds one strong ref (the captured
  `Device` clone inside the stream's async block) and one
  `broadcast::Receiver`.
- The reader task spawned inside `maintain_connection` holds a `Device`
  clone for the lifetime of the current TCP connection.

`Drop for DeviceInner` calls `cancel_token.cancel()` — so a "leak-free"
shutdown via dropping all handles also fires the cancel for any tasks
that captured the token directly.

### `close` vs `stop` — and why there's a side-channel

| Method | State after | Reconnects? | Mechanism |
| --- | --- | --- | --- |
| `close()` / `fire_close()` | `Disconnected` | Yes, on next user request (if `persist=true`) | `close_notify.notify_waiters()` |
| `stop()` / `fire_stop()` | `Stopped` | Never | `close_notify` **then** `cancel_token.cancel()` |

Originally `close` was a `DeviceCommand::Disconnect` enqueued on the user
mpsc. That made shutdown wait behind every queued user request. M2.1
replaced it with `tokio::sync::Notify` on `DeviceInner`. The actor's
`select!` ([`actor.rs:301`](../src/device/actor.rs#L301)) listens to
`close_notify.notified()` alongside `rx.recv()` — so `close()` interrupts
the current connection without draining the command queue.

`stop` fires the notify **first** (drop the connection promptly), then
the cancel token (exit the outer loop). Ordering matters: cancelling
first would race against any in-flight reconnect.

`fire_close` / `fire_stop` are the sync mirrors of `close` / `stop` —
both implementations are actually sync (Notify + state lock are
synchronously usable); the `async` flavors just exist so users in async
contexts don't have to remember to `.await` an immediate operation.

### Heartbeats

Two constants, both in [`src/device/mod.rs:27-31`](../src/device/mod.rs#L27-L31):

- `SLEEP_HEARTBEAT_CHECK = 5s` — how often the `select!` arm fires.
- `SLEEP_HEARTBEAT_DEFAULT = 7s` — minimum gap since `last_sent` before
  we actually send a heartbeat.

Net effect: heartbeats go out roughly **every 10 seconds** of idleness
(every other 5s tick: the first tick after a send sees `last_sent`
elapsed of 5s < 7s and skips; the second tick sees 10s ≥ 7s and fires,
which updates `last_sent` — and the cycle repeats). Never back-to-back
if the user is actively sending commands: any successful send updates
`last_sent` via `update_last_sent` in `send_raw_to_stream`, so a busy
device sees no heartbeat traffic at all.

`process_heartbeat` ([`actor.rs:922`](../src/device/actor.rs#L922))
short-circuits if `last_sent.elapsed() < SLEEP_HEARTBEAT_DEFAULT`.
Heartbeats are sent **only when `persist=true`** — `persist=false`
devices are torn down at the end of a request anyway.

The interval uses `MissedTickBehavior::Skip` ([`actor.rs:164`](../src/device/actor.rs#L164)) —
if the actor was busy for several ticks, we get **one** catch-up tick,
not a flood. (`Burst` is the tokio default; it would queue up missed
ticks and fire them all at once.)

### Inactivity timeout

`SLEEP_INACTIVITY_TIMEOUT = 30s`. The reader task wraps its
`read_u8()` in a `timeout(SLEEP_INACTIVITY_TIMEOUT, …)`. If 30 seconds
pass with no byte arriving on the socket, we treat the connection as
dead and send `TuyaError::Timeout` to the actor via `internal_tx`,
which triggers a teardown + reconnect. This catches NAT timeouts and
silent half-open sockets that wouldn't otherwise raise an error.

The 30s vs 7s heartbeat gap: a healthy device replies to our heartbeat
within sub-second, so 30s of total silence means the path is broken
even if our `write_half` thinks the TCP socket is still up.

### Reconnect backoff

`get_backoff_duration` ([`actor.rs:1247`](../src/device/actor.rs#L1247)):

- Base: `2^min(failure_count, 10) * SLEEP_RECONNECT_MIN` (16s base),
  capped at `SLEEP_RECONNECT_MAX` (4096s ≈ 68min).
- Jitter: 70% fixed + 0–30% random. So `failure_count=2` gives
  `64s * (0.7 + rand(0, 0.3))` ≈ 44.8s–64s.
- `failure_count` is reset after **3 consecutive successes**
  ([`actor.rs:82-93`](../src/device/actor.rs#L82-L93)). One success
  isn't enough — that suppresses backoff oscillation when the device is
  flapping. **Operational consequence to be aware of:** the rule is
  "3 in a row", and `success_count` is set back to 0 on any failure.
  A device that succeeds 80% of the time but flakes the rest will
  reliably get to `success_count = 2` and then trip back to 0 before
  resetting `failure_count`, so its `failure_count` plateaus high and
  its backoff stays long. This is intentional — a chronically flaky
  device should not get the same short backoff as a freshly recovered
  one — but it does mean "I see successes in the log, why is the
  backoff still huge?" has a non-obvious answer.

### Scanner-triggered backoff bypass

While the actor is sleeping out a backoff in `wait_for_backoff`, it
subscribes to scanner discovery events. If the scanner reports a fresh
discovery (`< 10s` old) for **this** device, the actor consults
`decide_discovery_notify_action` ([`src/device/decision.rs`](../src/device/decision.rs))
to choose one of:

- **`BypassBackoff`** — discovered IP differs from current, so wake up
  immediately and retry. Tracked in `last_scanner_bypass_at` /
  `scanner_bypass_failures` with an exponential cooldown
  (`SCANNER_BYPASS_BASE_COOLDOWN = 60s`, doubles per useless bypass)
  to prevent a fast-flapping scanner from starving the regular backoff.
  Reset on a successful connect.
- **`Report`** — the device is configured with a fixed IP and the
  scanner saw it elsewhere. Broadcast a `reason: "ip_mismatch"` synthetic
  on the listener bus; don't bypass.
- **`Ignore`** — discovered IP matches what we already have.

The bypass/report decision is in `decision.rs` as a pure function with
its own test table, so the policy can be reasoned about without spinning
up an actor.

### `persist=false` mode

`persist=false` means "connect on-demand for a single request, then
disconnect". The connection task still exists, but it parks in
`rx.recv()` until a `Request` arrives, then connects, runs the request,
and drops the stream.

The subtle bit: rapid user requests against an unreachable
`persist=false` device used to translate into a TCP SYN storm — every
request immediately retried `connect_and_handshake`. M1.5 added an
exponential backoff *between user-triggered retries* in the
`persist=false` arm of `try_connect_with_backoff`
([`actor.rs:411-433`](../src/device/actor.rs#L411-L433)), using the same
`get_backoff_duration`. `ConnectNow` still bypasses the wait.

### `nowait` mode

`Device::set_nowait(true)` makes `status` / `set_value` / `request`
return immediately after queuing the command, without awaiting the
device's response. The oneshot `resp_tx` is still attached to the
command, but the caller drops `resp_rx` immediately so the actor's
`resp_tx.send(...)` becomes a no-op.

This is per-device, atomic, and runtime-mutable (`AtomicBool`). Useful
when you're firing commands at a known-unresponsive bulb during boot
and don't care about confirmation.

### Response matching: cmd + optional cid, *not* seqno

**The Tuya LAN protocol is structurally fire-and-forget.** Many firmwares
echo `seqno=0` or a device-side counter unrelated to what was sent, so
seqno-based correlation is unreliable. `match_response` in
[`decision.rs`](../src/device/decision.rs) matches on `cmd` (+ optional
`cid` for sub-devices). Consequences:

- An unsolicited `Status` push that arrives between subscribe-and-send
  may be returned as a request's "response". Documented in the rustdoc
  on `Device::status` / `Device::request`.
- Callers that need strict correlation must serialize their own calls
  per `Device`, or use `Device::listener()` for unsolicited events.

`NO_RESPONSE_CMDS` ([`mod.rs:49-54`](../src/device/mod.rs#L49-L54)):
session-key negotiation commands and heartbeats. The actor doesn't wait
for these.

`MANDATORY_DATA_CMDS` ([`mod.rs:45`](../src/device/mod.rs#L45)):
currently just `LanExtStream`. Empty-ACK responses for these commands
are ignored — the caller wants the actual payload, not the ACK.

### Seqno is informational on the wire

`*seqno = seqno.wrapping_add(1)` ([`actor.rs:957`](../src/device/actor.rs#L957)) —
the field is informational (see above), so wrapping is benign and avoids
a debug-build panic on a long-lived connection that crosses
`u32::MAX`.

### `get_cipher` read-then-upgrade

Cipher construction is amortized: `get_cipher` reads first
(`parking_lot::RwLock::read`) and only upgrades to write if the cipher
needs to be (re)created ([`actor.rs:1240-ish`](../src/device/actor.rs#L1240)).
Before M2.3 this was a write-lock unconditionally, which serialized the
reader and writer halves of every connection through cipher access.

---

## 4. Channels

| Channel | Owner | Capacity | Purpose |
| --- | --- | --- | --- |
| `mpsc<DeviceCommand>` | per `DeviceInner` | `CHAN_MPSC_CAPACITY = 64` | user → actor commands (`Request`, `ConnectNow`) |
| `broadcast<TuyaMessage>` | per `DeviceInner` | `CHAN_BROADCAST_CAPACITY = 128` | actor → listeners + response matcher |
| `Notify` (`close_notify`) | per `DeviceInner` | n/a | `close`/`stop` side-channel that bypasses the command queue |
| `CancellationToken` | per `DeviceInner` | n/a | shutdown signal for all tasks holding a clone |
| `oneshot<Result<Option<TuyaMessage>>>` | per `Request` | 1 | response back to the request's caller |
| `mpsc<TuyaError>` | per active connection | 1 | reader task → actor (transport errors) |
| `mpsc<(Vec<u8>, SocketAddr)>` | scanner singleton | 100 | UDP receivers → dispatcher |
| `watch<u64>` | scanner singleton | n/a (single-value) | discovery notifications |
| `std::sync::mpsc::sync_channel<...>` | per sync bridge | `CHAN_WORKER_COMMAND_CAPACITY` / `CHAN_UNIFIED_CAPACITY` | async → sync forwarder |

### Broadcast lag synthetic

If a listener falls behind by more than `CHAN_BROADCAST_CAPACITY` (128)
messages, `broadcast::Receiver::recv()` returns
`Err(Lagged(n))` instead of the missed messages. `Device::listener()`
turns that into a synthetic event with
`payload = {"errorCode": ERR_STATE, "reason": "listener_lagged", "skipped": n}`
([`listener.rs:39-50`](../src/device/listener.rs#L39-L50)) so the
consumer can detect and react. `Device::receive()` continues silently
(it has no event channel to inject into).

128 was picked as a reasonable compromise: tens of devices firing
simultaneously can briefly burst above the consumer's drain rate without
triggering lag, but a chronically slow consumer is surfaced rather than
hidden.

---

## 5. `Device::listener` and `unified_listener`

### Per-device listener

`Device::listener()` ([`listener.rs:19`](../src/device/listener.rs#L19))
returns an `impl Stream<Item = Result<TuyaMessage>> + Send + 'static`
backed by a fresh `broadcast::Receiver` and a `Device` clone (one strong
Arc). The stream's `select!` listens to both the broadcast and
`cancel_token.cancelled()` — without the cancel branch, the stream
would only exit when `broadcast_tx` is dropped, which requires the very
last `Arc<DeviceInner>` to disappear — and the stream itself holds one
of those refs.

Empty-payload messages are filtered out at the source ([`listener.rs:34-38`](../src/device/listener.rs#L34-L38))
so the listener only sees real events.

### `unified_listener(Vec<Device>)` — async

[`listener.rs:70`](../src/device/listener.rs#L70). A pure function that
maps each device's `listener()` into a `DeviceEvent { device_id, message }`
and merges them with `futures_util::stream::select_all`. No spawn, no
hidden state — the returned stream is a normal `impl Stream`. Dropping
it releases every per-device subscription. Dropping one device
mid-stream loses that sub-stream but doesn't kill the merged stream
([test](../src/device/listener.rs#L468)).

### `unified_listener(Vec<sync::Device>)` — sync

[`sync.rs:735`](../src/sync.rs#L735). Builds the async stream the same
way, then spawns a `bridge_to_sync` task on the library runtime that
pumps items into a `std::sync::mpsc::sync_channel<Result<DeviceEvent>>`.
The caller gets a `Receiver` they can `recv()` from any thread (no
tokio runtime required). Default buffer is `CHAN_UNIFIED_CAPACITY`;
`unified_listener_with_capacity` exposes it.

The bridge:

- On `try_send` success while there's a pending dropped-count, fires
  the `on_resume` callback once with that count (logged as a warning)
  and resets the counter.
- On `Full`: increments the dropped counter, **keeps running**. The
  philosophy is "consumer recovery should not require listener restart" —
  better to log a backpressure event than to disconnect.
- On `Disconnected`: bridge exits (the receiver was dropped).

### Calling it multiple times

Today, `unified_listener` can be called any number of times — each call
spins up an independent select_all (async) or bridge task (sync). The
sync variant is **not** a singleton; N calls = N bridge tasks = N×N
broadcast subscriptions. There's no resource cycle and no correctness
issue, but in workloads where multiple consumers want the same unified
stream the canonical pattern is **one `unified_listener` call, fan-out
on the consumer side**, not N parallel calls.

Reconfiguring (add/remove device) is done by **drop the old listener,
create a new one with the new device list**. There is no in-place
attach/detach API. The Tuya broadcast bus is per-device and outlives
the listener, so no events are lost on the device side during the
re-create gap (μs scale); whatever lands during that gap is missed by
the listener but will be re-pushed on the device's next periodic
status emission.

---

## 6. Sync wrapper

[`src/sync.rs`](../src/sync.rs). Each `sync::Device` owns a long-lived
worker task spawned on the library runtime ([`sync.rs:215`](../src/sync.rs#L215))
that owns the underlying async `Device` and reads `SyncRequest`s from a
tokio mpsc, then sends responses back via oneshot. Calling
`sync::Device::status()` looks like a blocking call but is really:

1. Build a `SyncRequest` with a oneshot tx.
2. `blocking_send` the request onto the worker's tokio mpsc.
3. Block on `oneshot::Receiver::blocking_recv`.

### Don't call sync APIs from inside a tokio runtime

`tokio::sync::mpsc::Sender::blocking_send` panics if called from within
a tokio runtime context. Before M1.7 this surfaced as a confusing panic
inside the bindings. `check_no_runtime_context` (called at the top of
every sync entry point) detects it and returns `TuyaError::io_other`
with a clear message.

### `fire_close` / `fire_stop` on sync

These bypass the worker channel entirely — they go straight to the
underlying async `DeviceInner` and fire `close_notify` /
`cancel_token`. This means shutdown can't queue behind a stuck request
on the worker mpsc. Calling `close()` (async) on `sync::Device` would
have the same end effect but requires the worker to drain.

### `sync::Device::listener`

Returns a `Receiver<Result<TuyaMessage>>` (one per call). Each call
spawns its own `bridge_to_sync` task. Mirrors the design of
`sync::unified_listener` for consistency.

---

## 7. Python bindings

[`python/src/lib.rs`](../python/src/lib.rs). Thin pyo3 wrappers over
`sync::*`. Module init:

- Calls `runtime::maximize_fd_limit()` (best effort).
- Installs the `pyo3-log` bridge so Rust `log` records surface as Python
  `logging` records.

The FFI surface is re-exported from `rustuya::sync::internal::*` (M3.2 —
`DeviceCommand`, `SubDeviceCommand`, `SyncRequest`). The top-level paths
also still work for backward compatibility but will be removed in a
future minor.

Python's GIL is **released** for the duration of any blocking sync call
(`py.allow_threads(...)`). The Rust worker doesn't need the GIL, and
other Python threads stay live.

---

## 8. Common gotchas

- **Address `"Auto"`** on a `Device` means "ask the scanner". The
  device task will block on scanner discovery before its first connect.
  If the scanner is in cooldown and has no cached entry, this can wait
  up to `Scanner::timeout` (default 18s).
- **`Version::Auto`** is resolved opportunistically from a scanner hit
  during address resolution ([`actor.rs:737-741`](../src/device/actor.rs#L737-L741)).
  If the scanner never sees the device, version stays `Auto` and the
  protocol defaults are used.
- **`set_address`** sets `force_discovery = true`, so the next connect
  attempt will re-query the scanner even if there's a cached entry.
- **Constructing many devices at startup** is expensive (one tokio task
  per device, 0–5s jitter sleep, then a full handshake). For
  thousands-scale fleets, construct lazily on first use.
- **Dropping a `Device` does NOT stop the connection task** if any
  other handle holds an `Arc<DeviceInner>` — including a live listener
  stream. Use `stop()` for guaranteed teardown.
- **`broadcast::Receiver::recv` returning `Lagged`** is not an error
  from the device's perspective — your consumer is just slow. The lag
  synthetic event is the user-visible signal; tune
  `CHAN_BROADCAST_CAPACITY` or drain faster.
