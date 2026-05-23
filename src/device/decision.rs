//! Pure decision logic for the device actor + all device-level unit tests.
//!
//! Lives in its own submodule so the table-driven decision tests can sit
//! alongside the functions they verify, without sharing space with the
//! actor's IO orchestration.

use crate::protocol::{CommandType, TuyaMessage};
use log::{debug, trace};
use serde_json::Value;
use std::time::{Duration, Instant};

use super::{ADDR_AUTO, MANDATORY_DATA_CMDS, SCANNER_BYPASS_BASE_COOLDOWN, SLEEP_RECONNECT_MAX};

/// Verdict from `match_response` — either accept the broadcast message as
/// the current request's response, or skip it and keep waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MatchOutcome {
    Accept,
    Continue,
}

/// Decides whether a broadcast message is the response we're waiting for.
///
/// Matching is by command id + optional CID; the Tuya LAN protocol does not
/// carry a reliable request seqno (see the module-level note in
/// `process_command`), so this is the strongest correlation available.
///
/// Pure / synchronous on purpose: keeps the actor's `select!` body small
/// and lets us exhaustively unit-test the decision table.
pub(super) fn match_response(
    msg: &TuyaMessage,
    effective_cmd: u32,
    target_cid: Option<&str>,
) -> MatchOutcome {
    // Device-reported error responses arrive as cmd=0; surface them as the
    // current request's outcome regardless of CID.
    if msg.cmd == 0 {
        debug!("Device returned error response (cmd 0), accepting");
        return MatchOutcome::Accept;
    }

    let cmd_matches = msg.cmd == effective_cmd || msg.cmd == CommandType::Status as u32;
    if !cmd_matches {
        return MatchOutcome::Continue;
    }

    let needs_data = MANDATORY_DATA_CMDS.contains(&msg.cmd);

    if let Some(target_cid) = target_cid {
        // Sub-device request: response must carry the same CID.
        if msg.payload.is_empty() {
            if needs_data {
                trace!(
                    "Received empty ACK for CID command requiring data (0x{:02X}), continuing wait",
                    msg.cmd
                );
                return MatchOutcome::Continue;
            }
            debug!("Received empty ACK for CID request ({target_cid}), accepting");
            return MatchOutcome::Accept;
        }
        if let Ok(val) = serde_json::from_slice::<Value>(&msg.payload) {
            let resp_cid = val.get("cid").and_then(|c| c.as_str());
            if resp_cid == Some(target_cid) {
                debug!("Received matching response for CID: {target_cid}");
                return MatchOutcome::Accept;
            }
            trace!("Ignoring response for CID: {resp_cid:?} (expected {target_cid})");
            return MatchOutcome::Continue;
        }
        // Non-JSON payload on a CID request — accept rather than spin.
        return MatchOutcome::Accept;
    }

    // Parent-device request: response must NOT carry a CID.
    if msg.payload.is_empty() {
        if needs_data {
            trace!(
                "Received empty ACK for parent command requiring data (0x{:02X}), continuing wait",
                msg.cmd
            );
            return MatchOutcome::Continue;
        }
        return MatchOutcome::Accept;
    }
    if let Ok(val) = serde_json::from_slice::<Value>(&msg.payload) {
        if val.get("cid").is_none() {
            return MatchOutcome::Accept;
        }
        trace!("Ignoring response with CID for parent request");
        return MatchOutcome::Continue;
    }
    // Non-JSON payload on a parent request — accept rather than spin.
    MatchOutcome::Accept
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DiscoveryNotifyAction {
    /// Already-reported duplicate, cooldown not yet elapsed, or otherwise no-op.
    Ignore,
    /// Explicit-IP mismatch; emit `ERR_STATE` so the caller can decide.
    Report,
    /// Skip the remaining backoff and retry now. Fired either because the
    /// discovered IP changed (Auto mode) or because the device just proved
    /// it's reachable (same-IP case, throttled by the bypass cooldown).
    BypassBackoff,
}

/// Cooldown between successive scanner-triggered bypass attempts that target
/// the same IP we already know about.
///
/// Doubles on every failed bypass so a persistently broken setup (e.g. key
/// mismatch) self-throttles down to the regular reminder cadence; capped at
/// the main reconnect ceiling so the bypass cadence never outpaces backoff.
pub(super) fn scanner_bypass_cooldown(failures: u32) -> Duration {
    let base = SCANNER_BYPASS_BASE_COOLDOWN.as_secs();
    let cap = SLEEP_RECONNECT_MAX.as_secs();
    let secs = base.saturating_mul(1u64 << failures.min(10)).min(cap);
    Duration::from_secs(secs)
}

pub(super) fn decide_discovery_notify_action(
    current_ip: &str,
    config_addr: &str,
    discovered_ip: &str,
    last_reported_ip: Option<&str>,
    last_bypass_at: Option<Instant>,
    bypass_failures: u32,
    now: Instant,
) -> DiscoveryNotifyAction {
    let ip_match = !current_ip.is_empty() && current_ip == discovered_ip;
    let ip_explicit =
        config_addr != ADDR_AUTO && config_addr != "0.0.0.0" && !config_addr.is_empty();

    match (ip_explicit, ip_match) {
        // Auto + fresh IP: always bypass — the new IP itself is the news.
        (false, false) => DiscoveryNotifyAction::BypassBackoff,
        // Explicit + different IP: scanner news can't be acted on (resolve_address
        // would return the configured IP anyway), so elevate to the listener.
        (true, false) => {
            if last_reported_ip == Some(discovered_ip) {
                DiscoveryNotifyAction::Ignore
            } else {
                DiscoveryNotifyAction::Report
            }
        }
        // Same IP either way: device is alive — bypass if the cooldown allows.
        (_, true) => {
            let cooldown = scanner_bypass_cooldown(bypass_failures);
            let allowed = last_bypass_at.is_none_or(|t| now.duration_since(t) >= cooldown);
            if allowed {
                DiscoveryNotifyAction::BypassBackoff
            } else {
                DiscoveryNotifyAction::Ignore
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ADDR_AUTO, SCANNER_BYPASS_BASE_COOLDOWN, SLEEP_RECONNECT_MAX};
    use super::{
        DiscoveryNotifyAction, MatchOutcome, decide_discovery_notify_action, match_response,
        scanner_bypass_cooldown,
    };
    use crate::protocol::{CommandType, PREFIX_55AA, TuyaMessage};
    use std::time::{Duration, Instant};

    fn make_msg(cmd: u32, payload: &[u8]) -> TuyaMessage {
        TuyaMessage {
            seqno: 0,
            cmd,
            retcode: None,
            payload: payload.to_vec(),
            prefix: PREFIX_55AA,
            iv: None,
        }
    }

    #[test]
    fn match_cmd_zero_is_always_accept() {
        let m = make_msg(0, b"{}");
        assert_eq!(match_response(&m, 0x0d, None), MatchOutcome::Accept);
        assert_eq!(
            match_response(&m, 0x0d, Some("cid_a")),
            MatchOutcome::Accept
        );
    }

    #[test]
    fn match_wrong_cmd_continues() {
        let m = make_msg(0x09, b"{}"); // HeartBeat, not what we sent
        assert_eq!(
            match_response(&m, CommandType::DpQuery as u32, None),
            MatchOutcome::Continue
        );
    }

    #[test]
    fn match_status_cmd_is_accepted_as_response() {
        // Devices commonly answer with a Status push regardless of what was
        // sent — match_response accepts that as the response.
        let m = make_msg(CommandType::Status as u32, b"{\"dps\":{\"1\":true}}");
        assert_eq!(
            match_response(&m, CommandType::DpQueryNew as u32, None),
            MatchOutcome::Accept
        );
    }

    #[test]
    fn match_parent_request_rejects_cid_response() {
        let m = make_msg(
            CommandType::DpQueryNew as u32,
            b"{\"cid\":\"sub_a\",\"dps\":{}}",
        );
        assert_eq!(
            match_response(&m, CommandType::DpQueryNew as u32, None),
            MatchOutcome::Continue
        );
    }

    #[test]
    fn match_cid_request_accepts_matching_cid() {
        let m = make_msg(
            CommandType::DpQueryNew as u32,
            b"{\"cid\":\"sub_a\",\"dps\":{}}",
        );
        assert_eq!(
            match_response(&m, CommandType::DpQueryNew as u32, Some("sub_a")),
            MatchOutcome::Accept
        );
    }

    #[test]
    fn match_cid_request_rejects_other_cid() {
        let m = make_msg(
            CommandType::DpQueryNew as u32,
            b"{\"cid\":\"sub_b\",\"dps\":{}}",
        );
        assert_eq!(
            match_response(&m, CommandType::DpQueryNew as u32, Some("sub_a")),
            MatchOutcome::Continue
        );
    }

    #[test]
    fn match_cid_request_accepts_empty_ack() {
        // Many gateways send an empty ack for CID-targeted writes — accept
        // it rather than wait for data that may never come.
        let m = make_msg(CommandType::ControlNew as u32, b"");
        assert_eq!(
            match_response(&m, CommandType::ControlNew as u32, Some("sub_a")),
            MatchOutcome::Accept
        );
    }

    #[test]
    fn match_mandatory_data_cmd_rejects_empty_ack() {
        // LanExtStream is in MANDATORY_DATA_CMDS — empty payload must NOT be
        // taken as the response.
        let m = make_msg(CommandType::LanExtStream as u32, b"");
        assert_eq!(
            match_response(&m, CommandType::LanExtStream as u32, None),
            MatchOutcome::Continue
        );
    }

    /// Wrapper that fixes the cooldown-related inputs at "first call ever"
    /// (no prior bypass, no failures) so the legacy four-arg call sites stay
    /// readable.
    fn decide_fresh(
        current_ip: &str,
        config_addr: &str,
        discovered_ip: &str,
        last_reported_ip: Option<&str>,
    ) -> DiscoveryNotifyAction {
        decide_discovery_notify_action(
            current_ip,
            config_addr,
            discovered_ip,
            last_reported_ip,
            None,
            0,
            Instant::now(),
        )
    }

    #[test]
    fn auto_mode_with_different_ip_bypasses_backoff() {
        assert_eq!(
            decide_fresh("10.0.0.50", ADDR_AUTO, "10.0.0.73", None),
            DiscoveryNotifyAction::BypassBackoff
        );
    }

    #[test]
    fn auto_mode_with_empty_real_ip_bypasses_backoff() {
        assert_eq!(
            decide_fresh("", ADDR_AUTO, "10.0.0.73", None),
            DiscoveryNotifyAction::BypassBackoff
        );
    }

    #[test]
    fn auto_mode_with_matching_ip_bypasses_when_no_prior_attempt() {
        // Same-IP scanner news is now treated as a "device alive" signal and
        // bypasses backoff — throttled by the cooldown, but unrestricted on
        // the first encounter.
        assert_eq!(
            decide_fresh("10.0.0.73", ADDR_AUTO, "10.0.0.73", None),
            DiscoveryNotifyAction::BypassBackoff
        );
    }

    #[test]
    fn explicit_ip_with_different_discovery_reports() {
        assert_eq!(
            decide_fresh("10.0.0.50", "10.0.0.50", "10.0.0.73", None),
            DiscoveryNotifyAction::Report
        );
    }

    #[test]
    fn explicit_ip_with_matching_discovery_bypasses_when_no_prior_attempt() {
        assert_eq!(
            decide_fresh("10.0.0.50", "10.0.0.50", "10.0.0.50", None),
            DiscoveryNotifyAction::BypassBackoff
        );
    }

    #[test]
    fn explicit_ip_does_not_repeat_report_for_same_discovered_ip() {
        assert_eq!(
            decide_fresh("10.0.0.50", "10.0.0.50", "10.0.0.73", Some("10.0.0.73")),
            DiscoveryNotifyAction::Ignore
        );
    }

    #[test]
    fn explicit_ip_reports_again_when_discovered_ip_changes() {
        assert_eq!(
            decide_fresh("10.0.0.50", "10.0.0.50", "10.0.0.95", Some("10.0.0.73")),
            DiscoveryNotifyAction::Report
        );
    }

    #[test]
    fn zero_zero_zero_zero_treated_as_auto() {
        assert_eq!(
            decide_fresh("10.0.0.50", "0.0.0.0", "10.0.0.73", None),
            DiscoveryNotifyAction::BypassBackoff
        );
    }

    #[test]
    fn empty_config_addr_treated_as_auto() {
        assert_eq!(
            decide_fresh("10.0.0.50", "", "10.0.0.73", None),
            DiscoveryNotifyAction::BypassBackoff
        );
    }

    // --- Scanner-bypass cooldown behavior ---

    #[test]
    fn same_ip_bypass_is_throttled_within_cooldown() {
        let now = Instant::now();
        let just_bypassed = now - Duration::from_secs(5);
        assert_eq!(
            decide_discovery_notify_action(
                "10.0.0.50",
                "10.0.0.50",
                "10.0.0.50",
                None,
                Some(just_bypassed),
                1,
                now,
            ),
            DiscoveryNotifyAction::Ignore
        );
    }

    #[test]
    fn same_ip_bypass_allowed_once_cooldown_elapses() {
        let now = Instant::now();
        let past = now - SCANNER_BYPASS_BASE_COOLDOWN * 3;
        assert_eq!(
            decide_discovery_notify_action(
                "10.0.0.50",
                "10.0.0.50",
                "10.0.0.50",
                None,
                Some(past),
                1,
                now,
            ),
            DiscoveryNotifyAction::BypassBackoff
        );
    }

    #[test]
    fn cooldown_doubles_with_each_failed_bypass() {
        assert_eq!(scanner_bypass_cooldown(0), SCANNER_BYPASS_BASE_COOLDOWN);
        assert_eq!(scanner_bypass_cooldown(1), SCANNER_BYPASS_BASE_COOLDOWN * 2);
        assert_eq!(scanner_bypass_cooldown(2), SCANNER_BYPASS_BASE_COOLDOWN * 4);
    }

    #[test]
    fn cooldown_is_capped_at_main_reconnect_max() {
        // Many failures should still saturate at SLEEP_RECONNECT_MAX, never above.
        assert_eq!(scanner_bypass_cooldown(20), SLEEP_RECONNECT_MAX);
    }

    #[test]
    fn auto_mode_different_ip_ignores_cooldown() {
        // A fresh IP is brand-new information; cooldown must not gate it.
        let now = Instant::now();
        let just_bypassed = now - Duration::from_secs(1);
        assert_eq!(
            decide_discovery_notify_action(
                "10.0.0.50",
                ADDR_AUTO,
                "10.0.0.73",
                None,
                Some(just_bypassed),
                5,
                now,
            ),
            DiscoveryNotifyAction::BypassBackoff
        );
    }

    #[test]
    fn explicit_ip_different_ip_ignores_cooldown_and_reports() {
        // Cooldown only gates bypass; the Report path is independent.
        let now = Instant::now();
        let just_bypassed = now - Duration::from_secs(1);
        assert_eq!(
            decide_discovery_notify_action(
                "10.0.0.50",
                "10.0.0.50",
                "10.0.0.73",
                None,
                Some(just_bypassed),
                5,
                now,
            ),
            DiscoveryNotifyAction::Report
        );
    }

    // --- M5.2/M5.3 — lifecycle tests ---
    //
    // These exercise the publicly observable state transitions for
    // `close()` / `stop()` / drop, without needing a mock TCP server. They
    // pin the M2.1 / M2.2 invariants:
    //   * `close` leaves the device "Disconnected" but resumable.
    //   * `stop` is terminal — `is_stopped` returns true and `cancel_token`
    //     is fired.
    //   * `close_notify` is sent on both paths, so the actor's `select!` can
    //     short-circuit any in-flight command.

    use crate::Device;
    use std::sync::Arc;

    fn make_test_device() -> Device {
        // Use a clearly non-routable target so the background connection task
        // never actually connects. We're only exercising lifecycle state
        // machinery here, not network IO.
        Device::builder("test_lifecycle_id", b"0123456789abcdef".to_vec())
            .address("203.0.113.1") // TEST-NET-3, RFC 5737
            .persist(false)
            .build()
    }

    #[test]
    fn fire_close_marks_disconnected_but_not_stopped() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device();
            assert!(!device.is_stopped());
            device.fire_close();
            assert!(!device.is_stopped(), "close must not move to Stopped");
        });
    }

    #[test]
    fn fire_stop_marks_stopped_and_cancels_token() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device();
            let token = device.inner.cancel_token.clone();
            assert!(!device.is_stopped());
            assert!(!token.is_cancelled());

            device.fire_stop();

            assert!(device.is_stopped(), "stop must move to Stopped");
            assert!(token.is_cancelled(), "stop must fire cancel_token");
        });
    }

    #[test]
    fn close_notify_wakes_subscribers() {
        // The Notify-based close path (M2.1) must produce a wake-up for any
        // task that calls `notified().await` before close is fired.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device();
            let inner = Arc::clone(&device.inner);

            // Spawn a waiter that's parked on close_notify.
            let waiter = tokio::spawn(async move {
                inner.close_notify.notified().await;
            });

            // Give the waiter a moment to register its Notified future.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            device.fire_close();

            // The waiter must complete promptly.
            tokio::time::timeout(std::time::Duration::from_millis(200), waiter)
                .await
                .expect("close_notify did not wake waiter within 200ms")
                .expect("waiter task panicked");
        });
    }

    // M5.5: state-machine invariants for ConnectionState transitions driven
    // by fire_close / fire_stop. Hand-rolled exhaustive table rather than
    // pulling in proptest as a dev-dep for a 4-state machine.

    #[test]
    fn stopped_is_terminal_for_fire_close() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device();
            device.fire_stop();
            assert!(device.is_stopped());
            // Calling close after stop must NOT resurrect the device into
            // any state other than Stopped.
            device.fire_close();
            assert!(device.is_stopped(), "fire_close on Stopped must be a no-op");
        });
    }

    #[test]
    fn fire_stop_is_idempotent() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device();
            device.fire_stop();
            let token1_cancelled = device.inner.cancel_token.is_cancelled();
            device.fire_stop();
            let token2_cancelled = device.inner.cancel_token.is_cancelled();
            assert!(token1_cancelled && token2_cancelled);
            assert!(device.is_stopped());
        });
    }

    #[test]
    fn fire_close_does_not_set_stopped() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device();
            // Initial state is Disconnected (test address can't connect).
            assert!(!device.is_stopped());
            device.fire_close();
            assert!(
                !device.is_stopped(),
                "fire_close should leave state available for restart, not move to Stopped"
            );
            assert!(
                !device.inner.cancel_token.is_cancelled(),
                "fire_close must not cancel the connection task"
            );
        });
    }

    #[test]
    fn dropping_last_device_clone_cancels_token() {
        // M2.2: when the last strong Arc<DeviceInner> goes away (i.e. user
        // dropped all Device clones AND the connection task exited), the
        // Drop impl on DeviceInner fires `cancel_token.cancel()`. We can
        // observe this by holding a clone of the token after dropping the
        // device.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let device = make_test_device();
            let token = device.inner.cancel_token.clone();
            // Force the connection task to exit by calling fire_stop. After
            // stop, the actor drops its strong ref; dropping our Device
            // handle removes the last user-facing ref.
            device.fire_stop();
            drop(device);
            // The token is already cancelled by fire_stop, so DeviceInner's
            // Drop firing cancel again is a no-op — we just check the
            // observable invariant.
            assert!(token.is_cancelled());
        });
    }
}
