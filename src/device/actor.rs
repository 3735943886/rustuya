//! Internal actor loop, connection management, and protocol framing.
//!
//! This is the "engine room" of the Device. Public callers normally don't
//! reach in here; the surface in `super` (status/request/listener/close/…)
//! sends commands into this actor over an mpsc and reads responses back via
//! a `tokio::sync::broadcast`.

use crate::crypto::{TuyaCipher, hex_encode};
use crate::error::{
    ERR_DEVTYPE, ERR_JSON, ERR_OFFLINE, ERR_PAYLOAD, ERR_STATE, ERR_SUCCESS, Result, TuyaError,
    get_error_message,
};
use crate::protocol::{
    CommandType, DeviceType, PREFIX_55AA, PREFIX_6699, TuyaHeader, TuyaMessage, Version,
    get_protocol, pack_message, parse_header, unpack_message,
};
use crate::scanner::get as get_scanner;
use log::{debug, error, info, trace, warn};
use rand::Rng;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Interval, MissedTickBehavior, interval, sleep, timeout};

use super::decision::DiscoveryNotifyAction;
use super::decision::{MatchOutcome, decide_discovery_notify_action, match_response};
use super::{
    ADDR_AUTO, ConnectionState, DATA_UNVALID, Device, DeviceState, NO_RESPONSE_CMDS,
    SLEEP_HEARTBEAT_CHECK, SLEEP_HEARTBEAT_DEFAULT, SLEEP_INACTIVITY_TIMEOUT, SLEEP_RECONNECT_MAX,
    SLEEP_RECONNECT_MIN, keys,
};

/// Tracks when the most-recent `Device` was constructed, in milliseconds since
/// `UNIX_EPOCH`. Used by [`record_construction_and_compute_jitter`] so the
/// 0–5s initial-connect jitter is only applied when multiple devices are being
/// constructed in quick succession (the thundering-herd case it exists for).
/// A single-device caller pays no jitter.
static LAST_DEVICE_CONSTRUCT_MS: AtomicU64 = AtomicU64::new(0);

/// If another device was constructed within this window, the new device gets
/// the full 0–5s jitter; otherwise the jitter is zero.
const JITTER_QUIET_WINDOW: Duration = Duration::from_millis(100);

/// Maximum value of the random initial-connect jitter.
const JITTER_SPREAD: Duration = Duration::from_millis(5000);

/// Pure decision: given the elapsed time since the previous device
/// construction, return the jitter for this construction. Factored out from
/// [`record_construction_and_compute_jitter`] so it can be unit-tested
/// without racing the global atomic against parallel `Device::build` calls
/// in other tests.
fn jitter_for_elapsed(elapsed: Duration) -> Duration {
    if elapsed >= JITTER_QUIET_WINDOW {
        Duration::ZERO
    } else {
        let mut rng = rand::rng();
        Duration::from_millis(u64::from(rng.next_u32()) % JITTER_SPREAD.as_millis() as u64)
    }
}

/// Records that a device is being constructed *now* and returns the jitter
/// that device should sleep before its first connect attempt.
///
/// Returns `Duration::ZERO` if no other device was constructed within
/// [`JITTER_QUIET_WINDOW`] (single-device fast path); otherwise a uniform
/// random duration in `0..JITTER_SPREAD`.
///
/// Called from `Device::with_builder` (synchronously) so the bookkeeping is
/// based on construction wall-clock time, not on when the spawned task
/// happens to run.
pub(super) fn record_construction_and_compute_jitter() -> Duration {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let prev_ms = LAST_DEVICE_CONSTRUCT_MS.swap(now_ms, Ordering::Relaxed);
    let elapsed_ms = now_ms.saturating_sub(prev_ms);
    jitter_for_elapsed(Duration::from_millis(elapsed_ms))
}

pub(crate) enum DeviceCommand {
    // NOTE: `Disconnect` removed in M2.1. Use `close_notify` on DeviceInner for
    // graceful disconnect — going through the mpsc would queue behind pending
    // user requests, defeating the point of a fast close.
    Request {
        command: CommandType,
        data: Option<Value>,
        cid: Option<String>,
        resp_tx: oneshot::Sender<Result<Option<TuyaMessage>>>,
    },
    ConnectNow,
}

impl DeviceCommand {
    pub(super) fn respond(self, result: Result<Option<TuyaMessage>>) {
        if let DeviceCommand::Request { resp_tx, .. } = self {
            let _ = resp_tx.send(result);
        }
    }
}

impl Device {
    pub(super) fn with_state<R>(&self, f: impl FnOnce(&DeviceState) -> R) -> R {
        f(&self.inner.state.read())
    }

    pub(super) fn with_state_mut<R>(&self, f: impl FnOnce(&mut DeviceState) -> R) -> R {
        f(&mut self.inner.state.write())
    }

    pub(super) fn broadcast_error(&self, code: u32, payload: Option<Value>) {
        let msg = self.error_helper(code, payload);
        // Latch before sending so a listener subscribing AFTER this point can
        // replay it (see Device::listener). A tokio broadcast `send` reaches
        // only receivers present at send time, so a device that connects before
        // its listener subscribes would otherwise lose its ERR_SUCCESS forever.
        self.inner.state.write().last_status = Some(msg.clone());
        let _ = self.inner.broadcast_tx.send(msg);
    }

    fn update_last_received(&self) {
        self.inner.state.write().last_received = Instant::now();
    }

    fn update_last_sent(&self) {
        self.inner.state.write().last_sent = Instant::now();
    }

    fn reset_failure_count(&self) {
        let mut state = self.inner.state.write();
        state.success_count += 1;
        if state.failure_count > 0 && state.success_count >= 3 {
            debug!(
                "Resetting failure count for device {} (success_count: {})",
                self.inner.id, state.success_count
            );
            state.failure_count = 0;
            state.success_count = 0;
        }
    }

    pub(super) async fn send_to_task(&self, cmd: DeviceCommand) {
        if let Some(tx) = &self.tx {
            if let Err(e) = tx.send(cmd).await {
                error!(
                    "Failed to queue command for device {}: {}",
                    self.inner.id, e
                );
            }
        } else {
            error!(
                "Cannot send command for device {}: task not running",
                self.inner.id
            );
        }
    }

    pub(super) async fn send_command_to_task(
        &self,
        cmd_generator: impl FnOnce(oneshot::Sender<Result<Option<TuyaMessage>>>) -> DeviceCommand,
    ) -> Result<Option<TuyaMessage>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.send_to_task(cmd_generator(resp_tx)).await;
        if !self.inner.nowait.load(Ordering::Relaxed) {
            resp_rx.await.map_err(|_| TuyaError::Offline)?
        } else {
            Ok(None)
        }
    }

    fn get_timestamp(&self) -> u64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(e) => {
                // System clock is before UNIX_EPOCH. Tuya devices typically
                // reject requests whose `t` field is too far off, so a 0
                // timestamp will mostly fail anyway — but the silent
                // `.unwrap_or_default()` it replaces made that failure mode
                // very confusing. Warn once per call so an operator at least
                // sees the cause in the logs.
                warn!(
                    "System clock is before UNIX_EPOCH on device {} ({:?}); \
                     sending t=0 which the device will likely reject",
                    self.inner.id, e
                );
                0
            }
        }
    }
}

impl Device {
    pub(super) async fn run_connection_task(
        &self,
        mut rx: mpsc::Receiver<DeviceCommand>,
        initial_jitter: Duration,
    ) {
        if initial_jitter.is_zero() {
            debug!(
                "Starting background connection task for device {} with no initial jitter",
                self.inner.id
            );
        } else {
            debug!(
                "Starting background connection task for device {} with {:?} initial jitter",
                self.inner.id, initial_jitter
            );
            // Stagger connection attempts when multiple devices are starting.
            tokio::select! {
                () = self.inner.cancel_token.cancelled() => return,
                () = sleep(initial_jitter) => {}
            }
        }

        let mut heartbeat_interval = interval(SLEEP_HEARTBEAT_CHECK);
        heartbeat_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                () = self.inner.cancel_token.cancelled() => {
                    debug!("Background task for {} received stop signal", self.inner.id);
                    break;
                }
                res = async {
                    if self.is_stopped() {
                        return Some(());
                    }

                    // Reset seqno for each new connection attempt
                    let mut seqno = 1u32;

                    // 1. Connect and handshake
                    let (stream, initial_cmd) = match self
                        .try_connect_with_backoff(&mut rx, &mut seqno)
                        .await
                    {
                        Some(res) => res,
                        None => return Some(()),
                    };

                    // 2. Connection maintenance
                    let result = self
                        .maintain_connection(stream, &mut rx, &mut seqno, &mut heartbeat_interval, initial_cmd)
                        .await;

                    self.handle_disconnect(result.as_ref().err().cloned());

                    if let Err(e) = result {
                        self.with_state_mut(|s| {
                            s.failure_count += 1;
                            s.success_count = 0;
                        });
                        self.drain_rx(&mut rx, e, false);
                    } else {
                        return Some(());
                    }

                    if self.is_stopped() {
                        return Some(());
                    }

                    None
                } => {
                    if res.is_some() {
                        break;
                    }
                }
            }
        }

        // Ensure all associated tasks (like the Reader task) are stopped
        self.inner.cancel_token.cancel();
        debug!("Background connection task for {} exited", self.inner.id);
    }

    async fn maintain_connection(
        &self,
        stream: TcpStream,
        rx: &mut mpsc::Receiver<DeviceCommand>,
        seqno: &mut u32,
        heartbeat_interval: &mut Interval,
        initial_cmd: Option<DeviceCommand>,
    ) -> Result<()> {
        let (mut read_half, mut write_half) = stream.into_split();
        let (internal_tx, mut internal_rx) = mpsc::channel::<TuyaError>(1);

        // Process initial command if exists
        if let Some(cmd) = initial_cmd {
            self.process_command(&mut write_half, seqno, cmd)
                .await
                .map_err(|e| {
                    if !self.is_stopped() {
                        error!(
                            "Initial command processing failed for {}: {}",
                            self.inner.id, e
                        );
                    }
                    e
                })?;
        }

        let device_clone = self.clone();
        let parent_cancel_token = self.inner.cancel_token.clone();

        // Reader Task
        let reader_task = crate::runtime::spawn(async move {
            let mut packets_received = 0;
            loop {
                tokio::select! {
                    () = parent_cancel_token.cancelled() => break,
                    res = timeout(SLEEP_INACTIVITY_TIMEOUT, read_half.read_u8()) => {
                        match res {
                            Ok(Ok(byte)) => {
                                if let Err(e) = device_clone.process_socket_data(&mut read_half, byte).await {
                                    let _ = internal_tx.send(e).await;
                                    break;
                                }
                                packets_received += 1;
                            }
                            Ok(Err(e)) => {
                                let err = if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                    if packets_received > 0 {
                                        TuyaError::io(std::io::ErrorKind::ConnectionReset, "Connection reset")
                                    } else {
                                        TuyaError::KeyOrVersionError
                                    }
                                } else {
                                    TuyaError::from(e)
                                };
                                let _ = internal_tx.send(err).await;
                                break;
                            }
                            Err(_) => {
                                if !device_clone.is_stopped() {
                                    warn!("Inactivity timeout for {}", device_clone.inner.id);
                                }
                                let _ = internal_tx.send(TuyaError::Timeout).await;
                                break;
                            }
                        }
                    }
                }
            }
            debug!("Reader task for {} stopped", device_clone.inner.id);
        });

        let result = async {
            loop {
                tokio::select! {
                    () = self.inner.cancel_token.cancelled() => {
                        return Ok(());
                    }
                    () = self.inner.close_notify.notified() => {
                        // close() was called: tear down the current connection
                        // (the outer loop will reconnect on the next user
                        // request unless persist=false).
                        debug!("close_notify fired for {}, dropping connection", self.inner.id);
                        return Ok(());
                    }
                    cmd_opt = rx.recv() => {
                        if let Some(cmd) = cmd_opt {
                            self.process_command(&mut write_half, seqno, cmd).await?;
                        } else {
                            self.inner.state.write().state = ConnectionState::Stopped;
                            return Ok(());
                        }
                    }
                    _ = heartbeat_interval.tick() => {
                        if self.with_state(|s| s.persist) {
                            self.process_heartbeat(&mut write_half, seqno)
                                .await
                                .map_err(|e| {
                                    error!("Heartbeat failed for {}: {}", self.inner.id, e);
                                    e
                                })?;
                        }
                    }
                    err_opt = internal_rx.recv() => {
                        if let Some(e) = err_opt {
                            error!("Connection closed due to reader task error for {}: {}", self.inner.id, e);
                            return Err(e);
                        }
                    }
                }
            }
        }.await;

        reader_task.abort();
        result
    }

    async fn try_connect_with_backoff(
        &self,
        rx: &mut mpsc::Receiver<DeviceCommand>,
        seqno: &mut u32,
    ) -> Option<(TcpStream, Option<DeviceCommand>)> {
        loop {
            if self.is_stopped() {
                self.drain_rx(rx, TuyaError::Offline, true);
                return None;
            }

            // Reset seqno for new connection
            *seqno = 1;

            // Wait before retry if failed
            let backoff = self.with_state(|s| {
                if s.failure_count > 0 {
                    Some(self.get_backoff_duration(s.failure_count - 1))
                } else {
                    None
                }
            });

            if let Some(b) = backoff {
                warn!(
                    "Waiting {}s before next connection attempt for {}",
                    b.as_secs(),
                    self.inner.id
                );
                self.wait_for_backoff(rx, b).await?;
            }

            let result = self.establish_connection(seqno).await;
            if let Ok(Ok(s)) = result {
                self.with_state_mut(|s| {
                    s.state = ConnectionState::Connected;
                    s.scanner_bypass_failures = 0;
                    s.last_scanner_bypass_at = None;
                });
                info!(
                    "Connected to device {} ({})",
                    self.inner.id,
                    self.with_state(|s| s.real_ip.clone())
                );
                self.broadcast_error(ERR_SUCCESS, None);
                return Some((s, None));
            } else {
                let e = match result {
                    Ok(Err(e)) => e,
                    _ => TuyaError::Offline,
                };

                self.handle_connection_error(&e).await;
                self.drain_rx(rx, e.clone(), false);

                if !self.with_state(|s| s.persist) {
                    // persist=false has its own backoff state so that rapid user
                    // requests against an unreachable device don't translate into
                    // a TCP SYN storm. ConnectNow always bypasses the cooldown.
                    //
                    // Cooldown semantics (rc.2):
                    //   - On each failure we set `cooldown_until = now + backoff`.
                    //   - While a Request arrives within that window, respond
                    //     Offline immediately — don't queue it behind a fresh
                    //     backoff sleep. This collapses bursts (10 simultaneous
                    //     requests don't take 10× backoff to resolve).
                    //   - A Request arriving AFTER the cooldown elapses gets a
                    //     real retry attempt with no extra sleep.
                    //   - ConnectNow clears the cooldown unconditionally.
                    //
                    // The previous design slept `backoff` *before each retry*,
                    // which meant queued requests stacked their sleeps and the
                    // 10th request could wait hours.
                    self.with_state_mut(|s| {
                        s.failure_count = s.failure_count.saturating_add(1);
                    });
                    let initial_backoff = self.with_state(|s| {
                        self.get_backoff_duration(s.failure_count.saturating_sub(1))
                    });
                    let mut cooldown_until = Some(Instant::now() + initial_backoff);
                    warn!(
                        "Connection failed (persist: false) for {}: {}. Waiting for next command.",
                        self.inner.id, e
                    );

                    loop {
                        match rx.recv().await {
                            Some(DeviceCommand::ConnectNow) => {
                                // Bypass any active cooldown — user explicitly
                                // asked for an immediate connect attempt.
                                break;
                            }
                            Some(cmd @ DeviceCommand::Request { .. }) => {
                                if let Some(until) = cooldown_until
                                    && Instant::now() < until
                                {
                                    cmd.respond(Err(TuyaError::Offline));
                                    self.broadcast_error(ERR_OFFLINE, None);
                                    continue;
                                }
                                // Cooldown elapsed (or was never set). Fall
                                // through to retry; we'll either return Ok
                                // from the success branch or overwrite
                                // `cooldown_until` from the failure branch.

                                let retry_result = self.establish_connection(seqno).await;

                                if let Ok(Ok(s)) = retry_result {
                                    self.with_state_mut(|s| {
                                        s.state = ConnectionState::Connected;
                                        s.scanner_bypass_failures = 0;
                                        s.last_scanner_bypass_at = None;
                                    });
                                    info!("Connected to {} on demand", self.inner.id);
                                    self.broadcast_error(ERR_SUCCESS, None);
                                    return Some((s, Some(cmd)));
                                } else {
                                    let err = match retry_result {
                                        Ok(Err(e)) => e,
                                        _ => TuyaError::Offline,
                                    };
                                    self.handle_connection_error(&err).await;
                                    self.with_state_mut(|s| {
                                        s.failure_count = s.failure_count.saturating_add(1);
                                    });
                                    cmd.respond(Err(err.clone()));
                                    self.broadcast_error(ERR_OFFLINE, None);
                                    let next_backoff = self.with_state(|s| {
                                        self.get_backoff_duration(s.failure_count.saturating_sub(1))
                                    });
                                    cooldown_until = Some(Instant::now() + next_backoff);
                                }
                            }
                            None => return None,
                        }
                    }
                    continue;
                }

                self.with_state_mut(|s| {
                    s.failure_count += 1;
                    s.success_count = 0;
                    if s.config_address == ADDR_AUTO {
                        match e {
                            TuyaError::KeyOrVersionError | TuyaError::Offline => {
                                s.force_discovery = true;
                                let _ = get_scanner().invalidate_cache(&self.inner.id);
                            }
                            _ => {}
                        }
                    }
                });
            }
        }
    }

    async fn wait_for_backoff(
        &self,
        rx: &mut mpsc::Receiver<DeviceCommand>,
        backoff: Duration,
    ) -> Option<()> {
        let sleep_fut = sleep(backoff);
        tokio::pin!(sleep_fut);

        // Subscribe ONCE: `watch::Receiver` retains the "last seen version",
        // so any publish that arrives between awaits is replayed on the next
        // `changed()` instead of being lost (the previous `Notify::notified()`
        // re-subscription pattern had a documented gap here).
        let mut discovery_rx = get_scanner().subscribe_discoveries();

        loop {
            tokio::select! {
                () = &mut sleep_fut => return Some(()),
                _ = discovery_rx.changed() => {
                    if let Some(res) = get_scanner().get_cached_result(&self.inner.id)
                        && res.discovered_at.elapsed() < Duration::from_secs(10)
                    {
                        let (current_ip, config_addr, last_reported, last_bypass_at, bypass_failures) =
                            self.with_state(|s| {
                                (
                                    s.real_ip.clone(),
                                    s.config_address.clone(),
                                    s.last_reported_discovered_ip.clone(),
                                    s.last_scanner_bypass_at,
                                    s.scanner_bypass_failures,
                                )
                            });
                        match decide_discovery_notify_action(
                            &current_ip,
                            &config_addr,
                            &res.ip,
                            last_reported.as_deref(),
                            last_bypass_at,
                            bypass_failures,
                            Instant::now(),
                        ) {
                            DiscoveryNotifyAction::BypassBackoff => {
                                debug!(
                                    "Bypassing backoff for {} on scanner notify ({} -> {})",
                                    self.inner.id, current_ip, res.ip
                                );
                                self.with_state_mut(|s| {
                                    s.last_scanner_bypass_at = Some(Instant::now());
                                    s.scanner_bypass_failures =
                                        s.scanner_bypass_failures.saturating_add(1);
                                });
                                return Some(());
                            }
                            DiscoveryNotifyAction::Report => {
                                warn!(
                                    "Device {} configured at {} but scanner discovered it at {}",
                                    self.inner.id, current_ip, res.ip
                                );
                                self.with_state_mut(|s| {
                                    s.last_reported_discovered_ip = Some(res.ip.clone());
                                });
                                self.broadcast_error(
                                    ERR_STATE,
                                    Some(serde_json::json!({
                                        "reason": "ip_mismatch",
                                        "configured": current_ip,
                                        "discovered": res.ip,
                                    })),
                                );
                            }
                            DiscoveryNotifyAction::Ignore => {}
                        }
                    }
                }
                () = self.inner.cancel_token.cancelled() => {
                    self.drain_rx(rx, TuyaError::Offline, true);
                    return None;
                }
                cmd_opt = rx.recv() => {
                    // `?` is the sender-dropped exit: no handles left, so stop the actor.
                    let cmd = cmd_opt?;
                    if let DeviceCommand::ConnectNow = cmd { return Some(()) }
                    debug!("Rejecting command during backoff for device {}", self.inner.id);
                    cmd.respond(Err(TuyaError::Offline));
                    self.broadcast_error(ERR_OFFLINE, None);
                }
            }
        }
    }

    fn handle_disconnect(&self, err: Option<TuyaError>) {
        self.with_state_mut(|s| {
            if s.state != ConnectionState::Stopped {
                s.state = ConnectionState::Disconnected;
            }
            s.session_key = None; // Clear session key on disconnect
        });

        if let Some(e) = err {
            if matches!(e, TuyaError::KeyOrVersionError) {
                warn!(
                    "Device {} possibly has key or version mismatch (Error 914)",
                    self.inner.id
                );
            } else if !self.is_stopped() {
                debug!(
                    "Connection lost for device {} due to error: {}",
                    self.inner.id, e
                );
            }

            if !self.is_stopped() {
                self.broadcast_error(e.code(), None);
            }
        } else if !self.is_stopped() {
            debug!("Connection closed normally for device {}", self.inner.id);
            self.broadcast_error(ERR_OFFLINE, None);
        }
    }

    async fn handle_connection_error(&self, e: &TuyaError) {
        self.with_state_mut(|s| {
            if s.state != ConnectionState::Stopped {
                s.state = ConnectionState::Disconnected;
            }
        });
        self.broadcast_error(e.code(), Some(serde_json::json!(format!("{e}"))));
    }

    fn drain_rx(&self, rx: &mut mpsc::Receiver<DeviceCommand>, err: TuyaError, close: bool) {
        if close {
            rx.close();
        }
        while let Ok(cmd) = rx.try_recv() {
            cmd.respond(Err(err.clone()));
        }
    }
}

impl Device {
    // -------------------------------------------------------------------------
    // Protocol Implementation & Handshake
    // -------------------------------------------------------------------------

    /// Optional connect-storm guard around [`Self::connect_and_handshake`].
    ///
    /// If a cap was opted into via `set_connect_concurrency`, acquires a global
    /// establishment permit BEFORE the connect timeout so a queued device waits
    /// its turn instead of burning its timeout while waiting; otherwise there is
    /// no cap (the default). The connect + handshake then run under the timeout.
    /// The permit (when present) is dropped the moment this returns —
    /// establishment is the expensive part (TCP + crypto + a round trip); the
    /// resulting idle connection is cheap and must not hold a permit, or fleets
    /// larger than the permit count would deadlock. Applies to both the initial
    /// connect and every reconnect (a network blip's mass reconnect is the same
    /// storm).
    ///
    /// Returns the same shape as the bare `timeout(..)` it replaces:
    /// `Ok(Ok(stream))` on success, `Ok(Err(e))` on a connect error, and
    /// `Err(Elapsed)` on timeout.
    async fn establish_connection(
        &self,
        seqno: &mut u32,
    ) -> std::result::Result<Result<TcpStream>, tokio::time::error::Elapsed> {
        // Held across establishment, released on return (None = no cap engaged).
        let _permit = crate::runtime::connect_permit().await;
        timeout(self.timeout() * 2, self.connect_and_handshake(seqno)).await
    }

    async fn connect_and_handshake(&self, seqno: &mut u32) -> Result<TcpStream> {
        let addr = self.resolve_address().await?;
        let port = self.with_state(|s| s.port);

        info!(
            "Connecting to device {} at {}:{}",
            self.inner.id, addr, port
        );
        // Pass (host, port) as a tuple rather than `format!("{addr}:{port}")`:
        // tuple resolution (getaddrinfo) handles IPv6 literals without manual
        // bracketing, link-local zone ids (`fe80::1%eth0`), and NAT64-synthesized
        // addresses (`64:ff9b::c0a8:132`) — all of which the string form mangles
        // into an unparseable `host:port`. IPv4 literals and hostnames are
        // unaffected.
        let mut stream = timeout(self.timeout(), TcpStream::connect((addr.as_str(), port)))
            .await
            .map_err(|_| TuyaError::Timeout)?
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::ConnectionRefused => TuyaError::ConnectionFailed,
                _ => TuyaError::from(e),
            })?;

        let protocol = get_protocol(self.version(), self.dev_type());
        if protocol.requires_session_key()
            && !self.negotiate_session_key(&mut stream, seqno).await?
        {
            return Err(TuyaError::KeyOrVersionError);
        }

        Ok(stream)
    }

    async fn negotiate_session_key(&self, stream: &mut TcpStream, seqno: &mut u32) -> Result<bool> {
        let protocol = get_protocol(self.version(), self.dev_type());
        debug!("Session negotiation (v{})", protocol.version());

        // 1. Send SessKeyNegStart
        let local_nonce = protocol.prepare_session_key_negotiation();
        self.send_raw_to_stream(
            stream,
            self.build_message(
                seqno,
                CommandType::SessKeyNegStart as u32,
                local_nonce.clone(),
            ),
        )
        .await?;

        // 2. Read response and verify
        let first_byte = timeout(self.timeout(), stream.read_u8())
            .await
            .map_err(|_| TuyaError::Timeout)?
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    TuyaError::KeyOrVersionError
                } else {
                    TuyaError::from(e)
                }
            })?;

        let resp = self
            .read_and_parse_from_stream(stream, first_byte)
            .await?
            .ok_or(TuyaError::HandshakeFailed)?;

        if resp.cmd != CommandType::SessKeyNegResp as u32 {
            return Err(TuyaError::KeyOrVersionError);
        }

        let remote_nonce = protocol.verify_session_key_response(
            &local_nonce,
            &resp.payload,
            &self.inner.local_key,
        )?;

        // 3. Finalize and send SessKeyNegFinish
        let (session_key, finish_hmac) =
            protocol.finalize_session_key(&local_nonce, &remote_nonce, &self.inner.local_key)?;

        self.send_raw_to_stream(
            stream,
            self.build_message(seqno, CommandType::SessKeyNegFinish as u32, finish_hmac),
        )
        .await?;

        // 4. Encrypt and store session key
        let cipher = TuyaCipher::new(&self.inner.local_key)?;
        let encrypted_key = protocol.encrypt_session_key(&session_key, &cipher, &local_nonce)?;

        self.with_state_mut(|s| s.session_key = Some(encrypted_key));
        Ok(true)
    }

    async fn resolve_address(&self) -> Result<String> {
        let (config_addr, force_discovery, version) =
            self.with_state(|s| (s.config_address.clone(), s.force_discovery, s.version));

        let ip_explicit =
            config_addr != ADDR_AUTO && config_addr != "0.0.0.0" && !config_addr.is_empty();
        let ver_explicit = version != Version::Auto;

        if ip_explicit && ver_explicit && !force_discovery {
            return Ok(config_addr);
        }

        if let Ok(Some(result)) = get_scanner()
            .discover_device_internal(
                &self.inner.id,
                force_discovery,
                Some(&self.inner.cancel_token),
            )
            .await
        {
            let mut state = self.inner.state.write();
            if let Some(v) = result.version
                && state.version == Version::Auto
            {
                state.version = v;
            }

            let target_ip = if ip_explicit { config_addr } else { result.ip };
            state.real_ip = target_ip.clone();
            state.force_discovery = false;
            Ok(target_ip)
        } else if ip_explicit {
            self.with_state_mut(|s| {
                s.real_ip = config_addr.clone();
                s.force_discovery = false;
            });
            Ok(config_addr)
        } else {
            Err(TuyaError::Offline)
        }
    }

    async fn generate_payload(
        &self,
        command: CommandType,
        data: Option<Value>,
        cid: Option<&str>,
    ) -> Result<(u32, Value)> {
        let (version, mut dev_type) = self.with_state(|s| (s.version, s.dev_type));
        // If dev_type is Auto, treat it as Default for protocol selection
        if dev_type == DeviceType::Auto {
            dev_type = DeviceType::Default;
        }
        let protocol = get_protocol(version, dev_type);
        let t = self.get_timestamp();
        protocol.generate_payload(&self.inner.id, command, data, cid, t)
    }

    async fn process_command<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        seqno: &mut u32,
        cmd: DeviceCommand,
    ) -> Result<()> {
        match cmd {
            DeviceCommand::Request {
                command,
                data,
                cid,
                resp_tx,
            } => {
                let nowait = self.inner.nowait.load(Ordering::Relaxed);
                let cmd_code = command as u32;
                let response_rx = if !nowait && !NO_RESPONSE_CMDS.contains(&cmd_code) {
                    Some(self.inner.broadcast_tx.subscribe())
                } else {
                    None
                };

                let res = self
                    .generate_payload(command, data.clone(), cid.as_deref())
                    .await;
                let send_res = match res {
                    Ok((cmd_id, payload)) => {
                        debug!("Sending command: cmd=0x{:02X}, seqno={}", cmd_id, *seqno);
                        self.send_json_msg(stream, seqno, cmd_id, &payload).await
                    }
                    Err(e) => Err(e),
                };

                if let Err(e) = send_res {
                    let _ = resp_tx.send(Err(e));
                    return Ok(());
                }

                if let Some(mut rx) = response_rx {
                    let protocol = self.with_state(|s| get_protocol(s.version, s.dev_type));
                    let effective_cmd = protocol.get_effective_command(command);
                    let timeout_dur = self.timeout();

                    let id_for_logs = self.inner.id.clone();
                    let target_cid = cid.clone();
                    // NOTE: Tuya's LAN protocol is fundamentally asynchronous —
                    // the device treats inbound commands as fire-and-forget and
                    // independently emits unsolicited Status pushes whenever its
                    // DPs change. There is no request/response correlation token
                    // on the wire: many firmwares either echo seqno=0 or use a
                    // device-side counter unrelated to the request, so matching
                    // by request seqno is structurally impossible (not a bug to
                    // be fixed — it is the shape of the protocol).
                    //
                    // Consequently, an unsolicited Status push that arrives
                    // between subscribe() and the next user request may be
                    // surfaced as that request's response. This is by design;
                    // the "right" pattern for callers who care about strict
                    // correlation is to use the listener() stream for pushes
                    // and serialize their own per-Device request/response calls.
                    //
                    // DO NOT add seqno matching here in future reviews.
                    let wait_res = timeout(timeout_dur, async {
                        loop {
                            match rx.recv().await {
                                Ok(msg) => match match_response(
                                    &msg,
                                    effective_cmd,
                                    target_cid.as_deref(),
                                ) {
                                    MatchOutcome::Accept => return Ok(Some(msg)),
                                    MatchOutcome::Continue => continue,
                                },
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(
                                    skipped,
                                )) => {
                                    warn!(
                                        "Response wait for device {} lagged, skipped {} broadcast messages",
                                        id_for_logs, skipped
                                    );
                                    continue;
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    return Err(TuyaError::Offline);
                                }
                            }
                        }
                    })
                    .await;

                    let wait_res = match wait_res {
                        Ok(inner) => inner,
                        Err(_) => Err(TuyaError::Timeout),
                    };

                    let _ = resp_tx.send(wait_res);
                } else {
                    let _ = resp_tx.send(Ok(None));
                }
            }
            DeviceCommand::ConnectNow => {
                debug!(
                    "Device {} is already connected, ignoring ConnectNow",
                    self.inner.id
                );
            }
        }
        Ok(())
    }

    async fn process_socket_data<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        first_byte: u8,
    ) -> Result<()> {
        if let Some(msg) = self.read_and_parse_from_stream(stream, first_byte).await? {
            self.update_last_received();
            self.reset_failure_count();
            debug!(
                "Received message: cmd=0x{:02X}, payload_len={}",
                msg.cmd,
                msg.payload.len()
            );
            if msg.payload.is_empty() {
                debug!(
                    "Received empty payload message (cmd 0x{:02X}), broadcasting as ACK",
                    msg.cmd
                );
                let _ = self.inner.broadcast_tx.send(msg);
            } else {
                // Check if payload is valid JSON
                if serde_json::from_slice::<Value>(&msg.payload).is_err() {
                    debug!("Non-JSON payload detected, broadcasting as ERR_JSON");
                    let payload_hex = hex_encode(&msg.payload);
                    self.broadcast_error(
                        ERR_JSON,
                        Some(serde_json::json!({
                            keys::PAYLOAD_RAW: payload_hex,
                            "cmd": msg.cmd
                        })),
                    );
                } else {
                    let _ = self.inner.broadcast_tx.send(msg);
                }
            }
        }
        Ok(())
    }

    async fn process_heartbeat<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        seqno: &mut u32,
    ) -> Result<()> {
        let last = self.with_state(|s| s.last_sent);

        if last.elapsed() >= SLEEP_HEARTBEAT_DEFAULT {
            debug!("Auto-heartbeat for device {}", self.inner.id);
            let (cmd, payload) = self
                .generate_payload(CommandType::HeartBeat, None, None)
                .await?;
            self.send_json_msg(stream, seqno, cmd, &payload).await?;
        }
        Ok(())
    }
}

impl Device {
    // -------------------------------------------------------------------------
    // Low-level Message Framing & Encryption
    // -------------------------------------------------------------------------

    fn build_message<P: Into<Vec<u8>>>(
        &self,
        seqno: &mut u32,
        cmd: u32,
        payload: P,
    ) -> TuyaMessage {
        let payload = payload.into();
        let current_seq = *seqno;
        // `wrapping_add` so a long-lived connection that hits the u32 boundary
        // doesn't panic in debug builds. The seqno is informational on the
        // wire (Tuya doesn't reliably match request/response seqnos — see the
        // note in process_command) so wrapping is benign.
        *seqno = seqno.wrapping_add(1);
        debug!(
            "Building message: cmd=0x{:02X}, seqno={}, payload_len={}",
            cmd,
            current_seq,
            payload.len()
        );

        let protocol = get_protocol(self.version(), self.dev_type());

        TuyaMessage {
            seqno: current_seq,
            cmd,
            payload,
            prefix: protocol.get_prefix(),
            ..Default::default()
        }
    }

    fn pack_msg(&self, mut msg: TuyaMessage) -> Result<Vec<u8>> {
        let (version, dev_type) = self.with_state(|s| (s.version, s.dev_type));
        let cipher = self.get_cipher()?;
        let protocol = get_protocol(version, dev_type);

        msg.payload = protocol.pack_payload(&msg.payload, msg.cmd, &cipher)?;
        msg.prefix = protocol.get_prefix();

        let hmac_key = protocol.get_hmac_key(cipher.key());
        pack_message(&msg, hmac_key)
    }

    async fn send_json_msg<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        seqno: &mut u32,
        cmd: u32,
        payload: &Value,
    ) -> Result<()> {
        let payload_bytes = serde_json::to_vec(payload)?;
        let msg = self.build_message(seqno, cmd, payload_bytes);
        self.send_raw_to_stream(stream, msg).await
    }

    async fn send_raw_to_stream<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        msg: TuyaMessage,
    ) -> Result<()> {
        let packed = self.pack_msg(msg)?;
        timeout(self.timeout(), stream.write_all(&packed))
            .await
            .map_err(|_| TuyaError::Timeout)?
            .map_err(TuyaError::from)?;

        self.update_last_sent();
        Ok(())
    }

    async fn read_and_parse_from_stream<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        first_byte: u8,
    ) -> Result<Option<TuyaMessage>> {
        let prefix = self.scan_for_prefix(stream, first_byte).await?;

        // Read remaining 12 bytes of header (16 bytes total)
        let mut header_buf = [0u8; 16];
        header_buf[0..4].copy_from_slice(&prefix);
        timeout(self.timeout(), stream.read_exact(&mut header_buf[4..]))
            .await
            .map_err(|_| TuyaError::Timeout)?
            .map_err(TuyaError::from)?;

        // Parse and read body
        let dev_type_before = self.dev_type();
        match self.parse_and_read_body(stream, header_buf).await {
            Ok(Some(msg)) => {
                if dev_type_before != DeviceType::Device22
                    && self.dev_type() == DeviceType::Device22
                {
                    debug!("Device22 transition detected, reporting with original payload");
                    let original_payload = if msg.payload.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_slice(&msg.payload).unwrap_or_else(
                            |_| serde_json::json!({ keys::PAYLOAD_RAW: hex_encode(&msg.payload) }),
                        )
                    };
                    return Ok(Some(self.error_helper(ERR_DEVTYPE, Some(original_payload))));
                }
                Ok(Some(msg))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                if matches!(e, TuyaError::Io { .. }) {
                    return Err(e);
                }
                warn!("Error parsing message from {}: {}", self.inner.id, e);
                Ok(Some(self.error_helper(
                    ERR_PAYLOAD,
                    Some(serde_json::json!(format!("{e}"))),
                )))
            }
        }
    }

    async fn scan_for_prefix<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        first_byte: u8,
    ) -> Result<[u8; 4]> {
        let mut current_prefix = first_byte as u32;

        for _ in 0..3 {
            let next_byte = timeout(self.timeout(), stream.read_u8())
                .await
                .map_err(|_| TuyaError::Timeout)?
                .map_err(TuyaError::from)?;
            current_prefix = (current_prefix << 8) | (next_byte as u32);
        }

        for _ in 0..1024 {
            if current_prefix == PREFIX_55AA || current_prefix == PREFIX_6699 {
                return Ok(current_prefix.to_be_bytes());
            }

            let next_byte = timeout(self.timeout(), stream.read_u8())
                .await
                .map_err(|_| TuyaError::Timeout)?
                .map_err(TuyaError::from)?;
            current_prefix = (current_prefix << 8) | (next_byte as u32);
        }

        // 1024 bytes without a recognizable frame prefix means the stream is
        // structurally out of sync — almost always wrong key/version, a
        // protocol mismatch, or a corrupted device. Returning `Ok(None)` would
        // leave the reader silently spinning forever; surface a hard error so
        // the actor tears down the connection and reconnects.
        warn!(
            "scan_for_prefix on device {} found no valid frame after 1024 bytes; \
             treating as protocol/key mismatch and forcing reconnect",
            self.inner.id
        );
        Err(TuyaError::KeyOrVersionError)
    }

    async fn parse_and_read_body<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        header_buf: [u8; 16],
    ) -> Result<Option<TuyaMessage>> {
        let (packet, header) = self.read_full_packet(stream, header_buf).await?;
        trace!("Received packet (hex): {:?}", hex_encode(&packet));

        let mut decoded = self.unpack_and_check_dev22(&packet, header).await?;

        if !decoded.payload.is_empty() {
            trace!("Raw payload (hex): {:?}", hex_encode(&decoded.payload));
            decoded.payload = self.decrypt_and_clean_payload(decoded.payload).await?;
        }

        Ok(Some(decoded))
    }

    async fn read_full_packet<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        header_buf: [u8; 16],
    ) -> Result<(Vec<u8>, TuyaHeader)> {
        let prefix =
            u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);

        let (header, mut packet) = if prefix == PREFIX_6699 {
            let mut extra = [0u8; 2];
            timeout(self.timeout(), stream.read_exact(&mut extra))
                .await
                .map_err(|_| TuyaError::Timeout)?
                .map_err(TuyaError::from)?;

            let mut fh = Vec::with_capacity(18);
            fh.extend_from_slice(&header_buf);
            fh.extend_from_slice(&extra);
            (parse_header(&fh)?, fh)
        } else {
            (parse_header(&header_buf)?, header_buf.to_vec())
        };

        let total_len = header.total_length as usize;
        let header_len = packet.len();

        packet.resize(total_len, 0);
        timeout(self.timeout(), stream.read_exact(&mut packet[header_len..]))
            .await
            .map_err(|_| TuyaError::Timeout)?
            .map_err(TuyaError::from)?;

        Ok((packet, header))
    }

    async fn unpack_and_check_dev22(
        &self,
        packet: &[u8],
        header: TuyaHeader,
    ) -> Result<TuyaMessage> {
        let (version, dev_type) = self.with_state(|s| (s.version, s.dev_type));
        let protocol = get_protocol(version, dev_type);
        let cipher = self.get_cipher()?;
        let hmac_key = protocol.get_hmac_key(cipher.key());

        unpack_message(packet, hmac_key, Some(header.clone()), Some(false)).or_else(|e| {
            // Only allow switching if dev_type is Auto and protocol allows it
            if protocol.should_check_dev22_fallback()
                && dev_type == DeviceType::Auto
                && let Ok(d) = unpack_message(packet, None, Some(header), Some(false))
            {
                info!("Device22 detected via CRC32 fallback. Switching mode.");
                self.set_dev_type(DeviceType::Device22);
                return Ok(d);
            }
            Err(e)
        })
    }

    async fn decrypt_and_clean_payload(&self, payload: Vec<u8>) -> Result<Vec<u8>> {
        let (version, mut dev_type) = self.with_state(|s| (s.version, s.dev_type));
        let original_dev_type = dev_type;
        if dev_type == DeviceType::Auto {
            dev_type = DeviceType::Default;
        }

        let cipher = self.get_cipher()?;
        let protocol = get_protocol(version, dev_type);

        let decrypted = protocol.decrypt_payload(payload, &cipher)?;

        if protocol.should_check_dev22_fallback()
            && original_dev_type == DeviceType::Auto
            && String::from_utf8_lossy(&decrypted).contains(DATA_UNVALID)
        {
            warn!("Device22 detected via '{DATA_UNVALID}' payload. Switching mode.");
            self.set_dev_type(DeviceType::Device22);
        }

        Ok(decrypted)
    }

    fn get_cipher(&self) -> Result<Arc<TuyaCipher>> {
        // Fast path: cache hit under a read lock so concurrent pack/unpack
        // calls don't serialize on a write lock. The cipher is keyed by the
        // session_key (if any) or local_key; cache invalidation happens by
        // updating `state.session_key` elsewhere and falling through to the
        // slow path below.
        {
            let state = self.inner.state.read();
            let key: &[u8] = state
                .session_key
                .as_deref()
                .unwrap_or(&self.inner.local_key);
            if let Some(ref cipher) = state.cipher
                && cipher.key() == key
            {
                return Ok(Arc::clone(cipher));
            }
        }

        // Slow path: build the cipher *outside* the write lock so we don't
        // hold an exclusive lock across a fallible operation. Then re-check
        // under the write lock in case another caller installed a matching
        // cipher between the read and write — if so, drop ours.
        // (Building a TuyaCipher from a 16-byte key is cheap and pure; the
        // duplicate work in a race is negligible compared to lock contention.)
        let key_owned: Vec<u8> = {
            let state = self.inner.state.read();
            state
                .session_key
                .clone()
                .unwrap_or_else(|| self.inner.local_key.clone())
        };
        let new_cipher = Arc::new(TuyaCipher::new(&key_owned)?);

        let mut state = self.inner.state.write();
        if let Some(ref cipher) = state.cipher
            && cipher.key() == key_owned.as_slice()
        {
            return Ok(Arc::clone(cipher));
        }
        state.cipher = Some(Arc::clone(&new_cipher));
        Ok(new_cipher)
    }

    fn get_backoff_duration(&self, failure_count: u32) -> Duration {
        let min_secs = SLEEP_RECONNECT_MIN.as_secs();
        let max_secs = SLEEP_RECONNECT_MAX.as_secs();
        // Base exponential backoff: 2^n * min_secs
        let base_secs = (2u64.pow(failure_count.min(10)) * min_secs).min(max_secs);

        if base_secs == 0 {
            return Duration::from_secs(0);
        }

        let base_ms = base_secs * 1000;
        let fixed_ms = (base_ms * 70) / 100; // 70% fixed
        let random_range_ms = base_ms - fixed_ms; // 30% random range

        // Apply Jitter: 70% fixed + random(0% to 30%)
        let mut rng = rand::rng();
        let jitter_ms = fixed_ms + (rng.next_u64() % random_range_ms.max(1));

        Duration::from_millis(jitter_ms)
    }

    pub(super) fn error_helper(&self, code: u32, payload: Option<Value>) -> TuyaMessage {
        let mut response = serde_json::json!({
            keys::ERR_MSG: get_error_message(code),
            keys::ERR_CODE: code,
        });

        if let Some(p) = payload {
            match p {
                Value::String(s) => response[keys::PAYLOAD_STR] = Value::String(s),
                Value::Object(mut obj) => {
                    if let Some(raw) = obj
                        .remove(keys::IN_DATA)
                        .or_else(|| obj.remove(keys::IN_PAYLOAD))
                        .or_else(|| obj.remove(keys::PAYLOAD_RAW))
                    {
                        response[keys::PAYLOAD_RAW] = raw;
                    }
                    if let Some(res_obj) = response.as_object_mut() {
                        res_obj.extend(obj);
                    }
                }
                _ => response[keys::ERR_PAYLOAD_OBJ] = p,
            }
        }

        // Serializing a Value built from `serde_json::json!` cannot fail in
        // practice; if it ever does, fall back to an empty payload so we
        // still deliver an ACK rather than panicking inside the broadcast.
        let payload = serde_json::to_vec(&response).unwrap_or_else(|e| {
            warn!("error_helper: failed to serialize error payload: {e}");
            Vec::new()
        });
        TuyaMessage {
            payload,
            prefix: get_protocol(self.version(), self.dev_type()).get_prefix(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for actor-level helpers that don't require a live TCP
    //! connection. Heavier integration tests live in `device::listener::tests`.

    use super::*;

    // 0.3.0-rc.2: lock in the *decision* for initial-connect jitter. The
    // original design unconditionally slept 0–5s before the first connect
    // to spread out thundering-herd startups for fleets of 100s–1000s of
    // devices; that was pure overhead in the single-device case. The
    // contract: if the previous construction was more than JITTER_QUIET_WINDOW
    // ago, return zero (single-device fast path); otherwise return a random
    // value strictly under JITTER_SPREAD.
    //
    // We test `jitter_for_elapsed` (pure) rather than
    // `record_construction_and_compute_jitter` (touches a global atomic)
    // because the global is shared with every `Device::build` happening in
    // other tests run in parallel.
    #[test]
    fn jitter_for_elapsed_zero_when_idle() {
        // Anything ≥ JITTER_QUIET_WINDOW must skip jitter.
        assert_eq!(jitter_for_elapsed(JITTER_QUIET_WINDOW), Duration::ZERO);
        assert_eq!(
            jitter_for_elapsed(JITTER_QUIET_WINDOW + Duration::from_millis(1)),
            Duration::ZERO
        );
        assert_eq!(
            jitter_for_elapsed(Duration::from_secs(3600)),
            Duration::ZERO
        );
    }

    #[test]
    fn jitter_for_elapsed_bursty_within_bounds() {
        // Below JITTER_QUIET_WINDOW: bursty, must return strictly less than
        // JITTER_SPREAD (the upper bound of the random range). We loop to
        // sample across the RNG distribution.
        for _ in 0..1000 {
            let d = jitter_for_elapsed(Duration::from_millis(0));
            assert!(
                d < JITTER_SPREAD,
                "bursty jitter {:?} must be < JITTER_SPREAD ({:?})",
                d,
                JITTER_SPREAD
            );
        }
        for _ in 0..1000 {
            let d = jitter_for_elapsed(JITTER_QUIET_WINDOW - Duration::from_millis(1));
            assert!(
                d < JITTER_SPREAD,
                "edge-of-window jitter {:?} must be < JITTER_SPREAD ({:?})",
                d,
                JITTER_SPREAD
            );
        }
    }
}
