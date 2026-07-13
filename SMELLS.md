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

## Connection / discovery FSM (rustuya-core FSM) — pending (M1 / M2)

The big "ambiguous sleep / weird smell" cluster lives in the 0.3 actor. To be
confronted head-on when the Device FSM lands, not carried over:

| # | 0.3 smell | Where (0.3) | The question to settle |
|---|-----------|-------------|------------------------|
| P1 | **`SLEEP_RECONNECT_MIN = 16 s` hard floor**, not configurable | `device/mod.rs`, `actor.rs get_backoff_duration` | Is 16 s a real requirement or cargo-culted? Make it policy the driver injects; tests set it to 0. |
| P2 | **Backoff jitter via internal `rand::rng()`** | `actor.rs get_backoff_duration` | Same injection rule as S3 — the FSM computes a *duration*, randomness is injected/testable. |
| P3 | **`wait_for_backoff` selects sleep + scanner-rediscovery `watch`** | `actor.rs` | The sleep↔discovery coupling. In the poll-split FSM this splits into `TimerFired` vs `DiscoveryUpdated` — no hidden `select`. |
| P4 | **`is_connected` slow/stale after a passive drop** | observed via mock probe | `is_connected` didn't flip promptly on a peer-closed socket. Define connection state transitions explicitly in the FSM. |
| P5 | **A passive drop does not surface on `listener()` promptly** | observed via mock probe | Offline events only appeared at the next reconnect attempt (~16 s). Decide when the FSM emits an offline/`DeviceEvent`. |
| P6 | **`persist=false` cooldown also floored at 16 s, only bypassable via `connect_now`** | `actor.rs` cooldown loop | Reconcile the two backoff paths (persist vs not) into one clear FSM policy. |
| P7 | **dev22 auto-detection** — no agreed algorithm; a known unknown | `decision.rs` / protocol | Keep as an explicit, documented decision in the protocol layer; don't hide it. |

## Notes

- Discovery vs Device coupling (`address="Auto"` reaching a global scanner
  singleton) is a *layering* smell, resolved by the clean-slate decision:
  Device takes a concrete address; discovery is a separate module; the FSM only
  accepts an optional `DiscoveryUpdated` input. (See `MILESTONES.md`.)
- Global singletons (scanner `OnceLock`, process-wide runtime) are gone by
  design — a whole class of 0.3 lifecycle hardening (cancel-token replacement,
  `startup_guard`) simply doesn't exist in owned-handle form.
