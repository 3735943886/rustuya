# 0.3 → 0.4 smell register

The 0.4 clean-slate core is written fresh, not ported. This file pins down every
ambiguous / smelly bit of the 0.3 implementation so none of it is silently
laundered into the new core: each gets an explicit decision. Grouped by the core
layer that owns the resolution.

Status: **resolved** (handled in the new core) · **pending** (belongs to a layer
not built yet — listed so it isn't forgotten).

## Framing / crypto (rustuya-core: `crypto.rs`, `frame.rs`) — resolved

| # | 0.3 smell | Where (0.3) | Why it smells | 0.4 resolution |
|---|-----------|-------------|---------------|----------------|
| S1 | **Retcode presence guessed by sniffing payload bytes** (`data[start] != b'{'`, `== b'3'`, `== 0`) | `unpack_message` `should_parse_retcode` | Fragile heuristic; a payload that happens to start with the wrong byte mis-parses. `no_retcode: Option<bool>` tri-state papered over it. | **Removed from framing entirely.** `frame.rs` returns the raw `body`/plaintext and never looks at retcodes. Whether a retcode is present is a *protocol-layer* decision keyed on `cmd` (pending, S1b). |
| S1b | Tri-state `no_retcode: Option<bool>` (None = auto-sniff) | `unpack_message` | Confusing three-way flag driving the heuristic above. | Gone. **Finding:** the actor only ever passed `Some(false)` (retcode present), so the `None` auto-sniff branch was *dead code*. The clean message layer strips a retcode explicitly; the payload codec never sees it. |
| S2 | **Decoded message carries an `iv` field** (`iv: Some(iv.to_vec())`) | `unpack_message` 6699 | Conflates "IV to send with" vs "IV parsed while receiving"; dead data downstream. | `RawFrame` has no `iv`. Send IV is an explicit input to `pack_6699`. |
| S3 | **`rand::rng()` called inside `pack_message`** | `pack_message` 6699 | The core generating randomness violates the sans-io injection rule; not `no_std`. | `pack_6699` takes `iv: &[u8; 12]`. The core never touches an RNG; the driver injects it. |
| S4 | **Crypto mega-function** `encrypt(data, bool, Option, Option, bool)` | `crypto.rs` | Five positional bool/option args; unreadable, error-prone. | Explicit `ecb_encrypt/decrypt` and `gcm_encrypt/decrypt` methods. |
| S5 | **Errors allocate `String`** (`DecodeError("…".into())`, `format!`) | throughout `protocol/mod.rs` | Alloc-heavy on a hot path; drags `alloc`/`format` into `no_std`; stringly-typed. | `CoreError` is a plain field-less enum. |
| S6 | **`Crc::<u32>::new(...)` rebuilt every call** | `pack_message` / `unpack_message` | Re-parsing the algorithm table per frame. | `const CRC32` built once. |
| S7 | **15-method `TuyaProtocol` trait, one near-duplicate impl per version** | `v31.rs`…`v35.rs` | Most methods differ only in data (prefix, integrity, session-key flag, header placement); copy-paste drift risk. | The data-driven parts move to a single `version::Profile` table; only genuinely version-specific behaviour (v3.1 md5/base64) stays as code. |
| S8 | **Error type carries tinytuya's numeric code table + lossy round-trip** | `error.rs` (`define_error_codes!` 900–914, `code()` / `from_code()`) | The core `TuyaError` bakes in tinytuya's internal error numbers and English wording purely for output parity; `code()` is **lossy** (6 variants → 914, so `from_code` can't recover them); it even inherits irrelevant **cloud** codes (909–913) into a LAN library. | Core `CoreError` is a clean semantic enum — no numeric codes, no tinytuya wording, no cloud codes. The tinytuya-compatible `{errorCode, errorMsg}` output (if a consumer wants parity) becomes an **explicit presentation mapping in the driver / compat layer**, not part of the core error type (pending, driver slice). |

## Connection / discovery FSM (rustuya-core FSM)

The big "ambiguous sleep / weird smell" cluster lived in the 0.3 actor. Confronted
head-on as the Device FSM lands (`device.rs`), not carried over.

**Resolved** (Device FSM v2 backoff/reconnect + v3 heartbeat/idle):

| # | 0.3 smell | Where (0.3) | 0.4 resolution |
|---|-----------|-------------|----------------|
| P1 | **`SLEEP_RECONNECT_MIN = 16 s` hard floor**, not configurable | `device/mod.rs`, `actor.rs get_backoff_duration` | **Gone.** Backoff is [`Backoff`] policy (`base`/`max`/`jitter`) the driver injects; **no floor**. Tests pass `base = ZERO` and drive the whole reconnect path at zero wall-clock. |
| P2 | **Backoff jitter via internal `rand::rng()`** | `actor.rs get_backoff_duration` | **Gone.** `Backoff::delay(attempt, rng)` draws jitter from the *injected* `RngCore`; the FSM computes a pure `Duration`. Seeded-RNG test pins bounds + variation. |
| P3 | **`wait_for_backoff` selects sleep + scanner-rediscovery `watch`** | `actor.rs` | **Resolved.** No hidden `select` in the core: the backoff deadline is `poll_timeout()` and a wake enters as `Input::ConnectNow` — the single "connect now" signal fed by *both* an explicit `connect_now()` and the discovery rewake forwarder — which cancels the wait and redials (attempt counter preserved, so a flapping device / spam can't defeat escalation; also revives a terminal `Closed`). The driver's `select!` multiplexes the timer, socket, and command channel; the core stays pure. **Driver refinement (0.4):** the rewake carries the *freshly-announced address* (`Cmd::ConnectNow { addr }`), so a device that comes back at a **new IP** (DHCP renewal) redials the new target instead of the stale one fixed at spawn — the resolve-once address self-corrects. The 0.3 scanner instead read-gated a cached address behind a 30-min magic cooldown (`GLOBAL_SCAN_COOLDOWN`, a smell coupling scan-cadence to read-freshness); 0.4 keeps *no* freshness policy — `Discovery::last_seen(id)` exposes the raw age and callers decide. Pinned by `tests/rediscovery_ip_change.rs` (changed-IP redial). |
| P4 | **`is_connected` slow/stale after a passive drop** | observed via mock probe | **Resolved.** `is_connected()` is an explicit state (`== Connected`); it flips the instant the driver feeds `Closed`, **and** an `idle_timeout` deadline (below) flips it on a *silent* drop without waiting for the driver. |
| P5 | **A passive drop does not surface on `listener()` promptly** | observed via mock probe | **Resolved.** `Config::idle_timeout`: any inbound frame pushes an idle deadline forward; on expiry the FSM emits `Event::Disconnected` and re-arms backoff — a silent drop surfaces at `idle_timeout`, not at the next ~16 s reconnect. `Config::heartbeat` sends periodic `HeartBeat` keepalives (fresh v3.5 IV from the injected RNG) to provoke that traffic. |
| P6 | **`persist=false` cooldown also floored at 16 s, only bypassable via `connect_now`** | `actor.rs` cooldown loop | **Reconciled to one path.** `Config::auto_reconnect` decides *whether* to retry; the delay curve is single/identical for both. `false` → terminal `Closed`; `true` → `Backoff`. |
| P7 | **dev22 auto-detection** — no agreed algorithm; a known unknown | `decision.rs` / protocol | **Resolved as a documented decision.** The core performs **no** runtime detection: `DeviceType::Auto` == `Default` plus the one firm rule that **v3.2 is always Device22** (`command::generate`); `Device22` is set explicitly by the caller. The doc on `DeviceType` states this. Matches the known-unknown guidance — no hidden heuristic. |

All connection- and discovery-FSM smells (P1–P7, Q1–Q5) are now resolved on
the core side; only Q6's driver-side source-IP auto-detection remains, and it
belongs to the tokio driver, not the core.

## Discovery / scanner (rustuya-core `discovery.rs`)

The 0.3 `scanner.rs` is tinytuya-derived and singleton-heavy. Rewritten as a pure
`discovery` FSM (the name `scanner` is dropped).

**Resolved** (Discovery FSM v1, passive receive + dedup):

| # | 0.3 smell | Where (0.3) | 0.4 resolution |
|---|-----------|-------------|----------------|
| Q1 | **Process-wide `OnceLock<Scanner>` singleton** + replace-on-stop `CancellationToken`/`startup_guard` machinery | `scanner.rs` `GLOBAL_SCANNER` | **Gone.** `Discovery` is an owned, single-instance FSM; no global mutable state, no cancel-token lifecycle. |
| Q2 | **UDP keys as undocumented literal bytes** (md5 provenance lost) | `scanner.rs:53-60` | `UDP_KEY_V35` documented as `md5("yGAdlopoPVldABfn")` and **pinned by a test**; `UDP_KEY_V33` noted as a plain-ASCII (non-md5) key. |
| Q3 | **Open-ended brute-force decode** (every key × retcode × ECB-fallback × find-first-`{`) | `scanner.rs:1225-1308` | Replaced with a **structured, bounded** decode (6699/GCM → 55AA plaintext / ECB with optional version-header strip). Like dev22 it is an explicit, documented decision — validated against self-crafted packets, **not** claimed authoritative. |
| Q4 | **Blocking sleeps / tokio `interval`** for broadcast cadence | `scanner.rs` `perform_discovery_loop` | **Resolved, then hardened.** Broadcast cadence is `poll_timeout`/`handle_timeout`; `broadcast_interval` + `broadcast_burst` are injected policy. **Final model: active probing is on-demand, not a perpetual beat** — the 6 s/60 s/30 min magic constants (0.3's `BROADCAST_INTERVAL`/`SCAN_THROTTLE`/`GLOBAL_SCAN_COOLDOWN`, author-chosen) are **gone**, not merely made injectable. A probe fires only on a `want` signal (a `find`/`scan` miss, or a device's failed dial); the discovery actor **batch-drains** those and emits **one round per burst** (single-flight — 1000 concurrent finds → one broadcast, keyed on dispatch not the reply, so the reply latency can't race). Re-probe spacing is the *device's own reconnect backoff* (injected, jittered) — always ≫ reply latency, so no self-inflicted response storm; it self-extinguishes when devices connect. Passive is always on and does the bulk of discovery (devices self-announce, desynchronized). See MILESTONES M2.4. |
| Q5 | **Port→behavior coupling by scattered `== 7000`** literals | `scanner.rs:809/829/841` | **Resolved.** A typed `Probe { port, Dialect::{Legacy, V35} }` descriptor table (`DEFAULT_PROBES`) drives frame kind / cmd / key — data-driven like `version::Profile`. |

**Resolved** (driver, 0.4):

| # | 0.3 smell | Where (0.3) | 0.4 resolution |
|---|-----------|-------------|----------------|
| Q6 | **`discover_local_ip_blocking` + `0.0.0.0` fallback** + `discovery_sources` multi-source send | `scanner.rs:762-805` | **Resolved.** `Config::local_ips: Vec<Ipv4Addr>` — **one v3.5 probe per source**, each tagged (`poll_transmit → (bytes, port, source)`) and sent from a driver socket bound to that IP, so a multi-homed host actively elicits across subnets (the 0.3 `discovery_sources`). Empty → best-effort auto-detect one (`detect_local_ipv4`), else `0.0.0.0` degrade. Core builds payloads; driver owns sockets. |

## Fleet-scale discovery — 0.4 keyed-routing hardening

The clean-slate 0.4 decomposition (an owned `Discovery` + a per-device broadcast
subscribe-and-filter forwarder) was correct for one device but **regressed vs the
0.3 singleton at fleet scale** — the singleton was smelly for its *global
lifecycle*, not its *keyed routing*, and the first cut threw out the routing with
the bathwater. Confronted head-on; all resolved without reintroducing a global.

| # | Trap | 0.4 resolution |
|---|------|----------------|
| R1 | **Same-IP flap left stuck on backoff** — a device that drops and re-announces at the *same* IP within TTL is deduped (no `Found`), so the broadcast forwarder never woke it; reconnect fell back to backoff-max latency. | Core emits **`Event::Seen(id)`** on an unchanged re-announcement (a pure liveness tick, distinct from `Found`); the driver routes it to a bare `ConnectNow` that cancels backoff and redials the current address. The common case (brief WiFi drop, IP unchanged) now reconnects the instant the device reappears. Pinned by `tests/discovery_seen_flap.rs`. |
| R2 | **O(N²) fan-out + bus-lag drop** — every announcement cloned to all N forwarder subscribers (N² wakeups on a fleet event); a slow subscriber `Lagged` and could skip *its own* device's reconnect trigger during a mass reboot. | An **`id → Route` registry** on the owned `Discovery` (`register` at connect, lazy-prune on channel close): each announcement does **one** map lookup and a non-blocking `try_send` to just that device — O(1), no fan-out, no bus to lag. Broadcast stays only for the `find`/`discovered` enumerate API. Pinned by `tests/fleet_scale.rs` (300 devices, one announcement burst, all reconnect; verified 0/300 without the registry). |
| R3 | **Single-subnet active probing** — 0.3's per-source send sockets became one `local_ip`. | Q6 above — `local_ips` multi-source. |
| R4 | **Driver `known` map never evicted** while the core cache does — unbounded growth + `find` handing out addresses the core already forgot. | The driver map now carries a last-seen `Instant`; reads (`find`/`known`) treat entries older than `cache_ttl` as a miss, and a `Found` insert prunes expired entries. Bounded growth, honest reads. |

## Notes

- Discovery vs Device coupling (`address="Auto"` reaching a global scanner
  singleton) is a *layering* smell, resolved by the clean-slate decision:
  Device takes a concrete address; discovery is a separate module; the FSM only
  accepts an optional `ConnectNow` wake input. (See `MILESTONES.md`.)
- Global singletons (scanner `OnceLock`, process-wide runtime) are gone by
  design — a whole class of 0.3 lifecycle hardening (cancel-token replacement,
  `startup_guard`) simply doesn't exist in owned-handle form.
