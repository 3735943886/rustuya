# rustuya 0.4 — Core Design Decisions

The 0.4 `rustuya-core` is a clean-slate rewrite of the Tuya local protocol, not a
port of the 0.3 implementation. Wherever 0.3 left a behaviour ambiguous,
underspecified, or coupled to global state, the new core makes an explicit,
documented choice rather than carrying the old behaviour over untouched.

This document is that decision record. Each entry names the **prior 0.3
approach**, the **issue** with it, and the **0.4 decision**, so a reviewer can see
*why* the core is shaped the way it is. Entries are grouped by the core layer that
owns the decision and are referenced from code comments and `MILESTONES.md` by
their stable IDs:

- **S** — framing & crypto (`crypto.rs`, `frame.rs`, `message.rs`, `payload.rs`)
- **P** — connection / reconnect FSM (`device.rs`)
- **Q** — discovery (`discovery.rs`)
- **R** — fleet-scale discovery routing

Status is **resolved** (implemented in the core) or **pending** (belongs to a
layer not yet built — recorded here so it is not forgotten).

## S — Framing & crypto (resolved)

| ID | Prior approach (0.3) | Issue | Decision (0.4) |
|----|----------------------|-------|----------------|
| S1 | Retcode presence guessed by sniffing payload bytes (`data[start] != b'{'`, `== b'3'`, `== 0`) in `unpack_message`'s `should_parse_retcode` | Fragile heuristic; a payload that happens to start with the wrong byte mis-parses. The `no_retcode: Option<bool>` tri-state papered over it. | Removed from framing entirely. `frame.rs` returns the raw `body`/plaintext and never inspects retcodes. Whether a retcode is present is a *protocol-layer* decision keyed on `cmd` (see S1b). |
| S1b | Tri-state `no_retcode: Option<bool>` (`None` = auto-sniff) in `unpack_message` | Confusing three-way flag driving the heuristic above. | Gone. The actor only ever passed `Some(false)` (retcode present), so the `None` auto-sniff branch was dead code. The message layer strips a retcode explicitly; the payload codec never sees it. |
| S2 | Decoded message carries an `iv` field (`iv: Some(iv.to_vec())`) from `unpack_message` (6699) | Conflates "IV to send with" vs "IV parsed while receiving"; dead data downstream. | `RawFrame` has no `iv`. The send IV is an explicit input to `pack_6699`. |
| S3 | `rand::rng()` called inside `pack_message` (6699) | The core generating randomness violates the sans-I/O injection rule and is not `no_std`. | `pack_6699` takes `iv: &[u8; 12]`. The core never touches an RNG; the driver injects it. |
| S4 | Crypto mega-function `encrypt(data, bool, Option, Option, bool)` in `crypto.rs` | Five positional bool/option args; hard to read, easy to misuse. | Explicit `ecb_encrypt`/`ecb_decrypt` and `gcm_encrypt`/`gcm_decrypt` methods. |
| S5 | Errors allocate `String` (`DecodeError("…".into())`, `format!`) throughout `protocol/mod.rs` | Allocation on a hot path; drags `alloc`/`format` into `no_std`; stringly-typed. | `CoreError` is a plain field-less enum. |
| S6 | `Crc::<u32>::new(...)` rebuilt every call in `pack_message`/`unpack_message` | Re-parses the algorithm table per frame. | A single `const CRC32`, built once. |
| S7 | 15-method `TuyaProtocol` trait with one near-duplicate impl per version (`v31.rs`…`v35.rs`) | Most methods differ only in data (prefix, integrity, session-key flag, header placement); copy-paste drift risk. | The data-driven parts move to a single `version::Profile` table; only genuinely version-specific behaviour (v3.1 md5/base64) stays as code. |
| S8 | Error type bakes in tinytuya's numeric code table with a lossy round-trip (`error.rs` `define_error_codes!`, `code()`/`from_code()`) | The core error carried tinytuya's internal numbers and English wording purely for output parity; `code()` is lossy (6 variants collapse to 914, so `from_code` can't recover them); it even inherited irrelevant **cloud** codes (909–913) into a LAN library. | Core `CoreError` is a clean semantic enum — no numeric codes, no tinytuya wording, no cloud codes. A tinytuya-compatible `{errorCode, errorMsg}` presentation, if a consumer wants parity, is an explicit mapping in the driver/compat layer, not part of the core error type (pending, driver slice). |

## P — Connection / reconnect FSM (resolved)

The largest cluster of ambiguous timing and lifecycle behaviour lived in the 0.3
actor. It is confronted directly as the Device FSM lands (`device.rs`), not
carried over. Resolved across Device FSM v2 (backoff/reconnect) and v3
(heartbeat/idle).

| ID | Prior approach (0.3) | Decision (0.4) |
|----|----------------------|----------------|
| P1 | `SLEEP_RECONNECT_MIN = 16 s` hard reconnect floor, not configurable (`device/mod.rs`, `actor.rs get_backoff_duration`) | Gone. Backoff is a `Backoff` policy (`base`/`max`/`jitter`) the driver injects, with **no floor**. Tests pass `base = ZERO` and drive the whole reconnect path at zero wall-clock. |
| P2 | Backoff jitter drawn from an internal `rand::rng()` (`actor.rs get_backoff_duration`) | Gone. `Backoff::delay(attempt, rng)` draws jitter from the injected `RngCore`; the FSM computes a pure `Duration`. A seeded-RNG test pins the bounds and variation. |
| P3 | `wait_for_backoff` selects over a sleep and a scanner-rediscovery `watch` inside the actor | No hidden `select` in the core: the backoff deadline is `poll_timeout()` and a wake enters as `Input::ConnectNow` — the single "connect now" signal fed by *both* an explicit `connect_now()` and the discovery re-wake forwarder — which cancels the wait and redials (attempt counter preserved, so a flapping/spamming device can't defeat escalation; it also revives a terminal `Closed`). The driver's `select!` multiplexes timer, socket, and command channel; the core stays pure. Driver refinement: the re-wake carries the freshly-announced address (`Cmd::ConnectNow { addr }`), so a device returning at a new IP (DHCP renewal) redials the new target, self-correcting the resolve-once address. 0.3 instead read-gated a cached address behind a 30-minute `GLOBAL_SCAN_COOLDOWN` (coupling scan cadence to read freshness); 0.4 keeps no freshness policy — `Discovery::last_seen(id)` exposes the raw age and callers decide. Pinned by `tests/rediscovery_ip_change.rs`. |
| P4 | `is_connected` slow/stale after a passive drop (observed via mock probe) | `is_connected()` is an explicit state (`== Connected`); it flips the instant the driver feeds `Closed`, and an `idle_timeout` deadline flips it on a *silent* drop without waiting for the driver. |
| P5 | A passive drop does not surface on `listener()` promptly (observed via mock probe) | `Config::idle_timeout`: any inbound frame pushes an idle deadline forward; on expiry the FSM emits `Event::Disconnected` and re-arms backoff — a silent drop surfaces at `idle_timeout`, not at the next reconnect. `Config::heartbeat` sends periodic `HeartBeat` keepalives (fresh v3.5 IV from the injected RNG) to provoke that traffic. |
| P6 | `persist = false` cooldown also floored at 16 s, only bypassable via `connect_now` (`actor.rs` cooldown loop) | Reconciled to one path. `Config::auto_reconnect` decides *whether* to retry; the delay curve is single and identical for both. `false` → terminal `Closed`; `true` → `Backoff`. |
| P7 | dev22 auto-detection — no agreed algorithm; a known unknown (`decision.rs` / protocol) | Resolved as a documented decision. The core performs **no** runtime detection: `DeviceType::Auto` == `Default` plus the one firm rule that **v3.2 is always Device22** (`command::generate`); `Device22` is set explicitly by the caller. The doc on `DeviceType` states this — no hidden heuristic. |

All connection- and discovery-FSM decisions (P1–P7, Q1–Q5) are resolved core-side;
only Q6's driver-side source-IP handling belongs to the tokio driver.

## Q — Discovery (resolved)

The 0.3 `scanner.rs` was tinytuya-derived and singleton-heavy. It is rewritten as
a pure `discovery` FSM (the name `scanner` is dropped). Resolved across Discovery
FSM v1 (passive receive + dedup) and v2 (active probing).

| ID | Prior approach (0.3) | Decision (0.4) |
|----|----------------------|----------------|
| Q1 | Process-wide `OnceLock<Scanner>` singleton plus replace-on-stop `CancellationToken`/`startup_guard` machinery (`scanner.rs GLOBAL_SCANNER`) | Gone. `Discovery` is an owned, single-instance FSM; no global mutable state, no cancel-token lifecycle. |
| Q2 | UDP keys stored as undocumented literal bytes (md5 provenance lost) (`scanner.rs:53-60`) | `UDP_KEY_V35` documented as `md5("yGAdlopoPVldABfn")` and pinned by a test; `UDP_KEY_V33` noted as a plain-ASCII (non-md5) key. |
| Q3 | Open-ended brute-force decode (every key × retcode × ECB-fallback × find-first-`{`) (`scanner.rs:1225-1308`) | A structured, bounded decode (6699/GCM → 55AA plaintext / ECB with optional version-header strip). Like dev22 it is an explicit, documented decision — validated against self-crafted packets, not claimed authoritative. |
| Q4 | Blocking sleeps / tokio `interval` for broadcast cadence (`scanner.rs perform_discovery_loop`) | Resolved, then hardened. Cadence is `poll_timeout`/`handle_timeout`; `broadcast_interval` + `broadcast_burst` are injected policy. Final model: active probing is on-demand, not a perpetual beat — the 6 s/60 s/30 min magic constants (0.3's `BROADCAST_INTERVAL`/`SCAN_THROTTLE`/`GLOBAL_SCAN_COOLDOWN`) are gone, not merely made injectable. A probe fires only on a `want` signal (a `find`/`scan` miss, or a device's failed dial); the discovery actor batch-drains those and emits one round per burst (single-flight — 1000 concurrent finds → one broadcast, keyed on dispatch not the reply, so reply latency can't race). Re-probe spacing is the device's own reconnect backoff (injected, jittered) — always ≫ reply latency, so no self-inflicted response storm; it self-extinguishes when devices connect. Passive receive is always on and does the bulk of discovery (devices self-announce, desynchronised). See `MILESTONES.md` M2.4. |
| Q5 | Port→behaviour coupling via scattered `== 7000` literals (`scanner.rs:809/829/841`) | A typed `Probe { port, Dialect::{Legacy, V35} }` descriptor table (`DEFAULT_PROBES`) drives frame kind / cmd / key — data-driven like `version::Profile`. |
| Q6 | `discover_local_ip_blocking` + `0.0.0.0` fallback plus `discovery_sources` multi-source send (`scanner.rs:762-805`) — *driver-owned* | `Config::local_ips: Vec<Ipv4Addr>` — one v3.5 probe per source, each tagged (`poll_transmit → (bytes, port, source)`) and sent from a driver socket bound to that IP, so a multi-homed host actively elicits across subnets. Empty → best-effort auto-detect one (`detect_local_ipv4`), else `0.0.0.0` degrade. Core builds payloads; driver owns sockets. |

## R — Fleet-scale discovery routing (resolved)

The clean-slate decomposition (an owned `Discovery` plus a per-device
broadcast-subscribe-and-filter forwarder) was correct for one device but
**regressed against the 0.3 singleton at fleet scale** — the singleton was
problematic for its *global lifecycle*, not its *keyed routing*, and the first cut
discarded the routing along with it. Resolved without reintroducing a global.

| ID | Trap | Decision (0.4) |
|----|------|----------------|
| R1 | Same-IP flap left stuck on backoff — a device that drops and re-announces at the *same* IP within TTL is deduped (no `Found`), so the broadcast forwarder never woke it; reconnect fell back to backoff-max latency. | The core emits `Event::Seen(id)` on an unchanged re-announcement (a pure liveness tick, distinct from `Found`); the driver routes it to a bare `ConnectNow` that cancels backoff and redials the current address. The common case (brief WiFi drop, IP unchanged) reconnects the instant the device reappears. Pinned by `tests/discovery_seen_flap.rs`. |
| R2 | O(N²) fan-out + bus-lag drop — every announcement cloned to all N forwarder subscribers (N² wakeups on a fleet event); a slow subscriber `Lagged` and could skip *its own* device's reconnect trigger during a mass reboot. | An `id → Route` registry on the owned `Discovery` (`register` at connect, lazy-prune on channel close): each announcement does one map lookup and a non-blocking `try_send` to just that device — O(1), no fan-out, no bus to lag. Broadcast remains only for the `find`/`discovered` enumerate API. Pinned by `tests/fleet_scale.rs` (300 devices, one announcement burst, all reconnect; verified 0/300 reconnect without the registry). |
| R3 | Single-subnet active probing — 0.3's per-source send sockets had been collapsed to one `local_ip`. | Q6 above — `local_ips` multi-source. |
| R4 | Driver `known` map never evicted while the core cache does — unbounded growth, and `find` handing out addresses the core had already forgotten. | The driver map carries a last-seen `Instant`; reads (`find`/`known`) treat entries older than `cache_ttl` as a miss, and a `Found` insert prunes expired entries. Bounded growth, honest reads. |

## Cross-cutting notes

- **Layering.** Discovery↔Device coupling (0.3's `address = "Auto"` reaching a
  global scanner singleton) was a layering problem, resolved by the clean-slate
  split: Device takes a concrete address; discovery is a separate module; the FSM
  only accepts an optional `ConnectNow` wake input. See `MILESTONES.md`.
- **No global singletons.** The scanner `OnceLock` and process-wide runtime are
  gone by design — a whole class of 0.3 lifecycle handling (cancel-token
  replacement, `startup_guard`) simply does not exist in owned-handle form.
