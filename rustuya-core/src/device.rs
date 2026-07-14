//! Connection-lifecycle state machine — **v2: reconnect / backoff timers**.
//!
//! Sans-I/O (poll-split, design D1): the driver pumps bytes/commands in via
//! [`Device::handle_input`], fires the single armed timer via
//! [`Device::handle_timeout`], and drains work out via [`Device::poll_transmit`]
//! / [`Device::poll_event`]. The next deadline is exposed as **one** value via
//! [`Device::poll_timeout`] (D2). No I/O, no clock, no randomness of its own —
//! the driver injects `now` (D3) and the RNG (handshake nonce, per-message IV).
//!
//! The reconnect loop is a pure state cycle:
//! `Connecting → (handshake) → Connected → Backoff → Connecting → …`. The driver
//! dials whenever [`Device::wants_connect`] is true and reports the outcome as
//! [`Input::Connected`] or [`Input::ConnectFailed`]; the *whether* and the *when*
//! (backoff delay) are the core's policy, testable at zero wall-clock.
//!
//! Smells confronted here (SMELLS.md): **P1** — no 16 s hard floor; the backoff
//! curve is [`Backoff`] policy the driver injects, and tests set it to zero.
//! **P2** — jitter is drawn from the injected RNG, not an internal `rand::rng()`.
//! **P6** — persist / non-persist collapse into one path: [`Config::auto_reconnect`]
//! decides *whether* to retry; the delay policy is single and identical.
//!
//! Still deferred to later increments: heartbeat / idle timers (P4/P5) and the
//! `ConnectNow` wake input (P3).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use rand_core::RngCore;

use crate::command::{self, CommandType};
use crate::json::{self, Value};
use crate::message::{self, Message};
use crate::rx::RxBuffer;
use crate::session::Handshake;
use crate::time::{Duration, Instant};
use crate::version::{DeviceType, Version};
use crate::CoreError;

/// Exponential-backoff policy for reconnect attempts (SMELLS.md P1/P2).
///
/// Delay for attempt `n` (0-based) is `min(base * 2^n, max)` plus a random
/// `[0, jitter)` drawn from the injected RNG. There is **no** hard floor — a
/// driver may pass `base = ZERO` for immediate retry, and tests do exactly that
/// to run the whole reconnect path at zero wall-clock.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// Delay before the first retry (attempt 0).
    pub base: Duration,
    /// Upper bound on the exponential term (before jitter).
    pub max: Duration,
    /// Extra uniform random delay in `[0, jitter)`, from the injected RNG.
    pub jitter: Duration,
}

impl Backoff {
    /// The delay for a given 0-based attempt number.
    fn delay(&self, attempt: u32, rng: &mut impl RngCore) -> Duration {
        // 2^attempt, saturating: attempt >= 64 (never realistic) pins to u64::MAX,
        // then `base * factor` saturates and is capped by `max` anyway.
        let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let capped = self.base.saturating_mul(factor).min(self.max);
        let jitter = match self.jitter.as_millis() {
            0 => 0,
            j => rng.next_u64() % j,
        };
        Duration::from_millis(capped.as_millis().saturating_add(jitter))
    }
}

/// Static configuration for one device.
pub struct Config {
    pub version: Version,
    pub dev_type: DeviceType,
    pub device_id: String,
    pub local_key: [u8; 16],
    /// Whether a dropped / failed connection re-arms a backoff timer (`true`) or
    /// drops to a terminal closed state (`false`). Unifies the 0.3
    /// persist-vs-nowait split into one policy knob (SMELLS.md P6).
    pub auto_reconnect: bool,
    /// Backoff curve used when `auto_reconnect` is set.
    pub backoff: Backoff,
    /// If set, this is the **max silence** allowed on the outbound direction: a
    /// `HeartBeat` keepalive is emitted once this long passes with no frame sent to
    /// the device. It is an *inactivity bound*, not a fixed beat — any real command
    /// (`on_send`) defers the next heartbeat a full interval, since that traffic
    /// already resets the device's client-idle timer (0.3 tracked `last_sent`).
    /// `None` disables keepalive. Must stay comfortably below the device's own
    /// idle-drop (~30 s on typical firmware) or the device closes the connection.
    pub heartbeat: Option<Duration>,
    /// If set, a connection with no inbound frame for this long is declared dead
    /// and disconnected — this is what makes a *silent* peer drop surface
    /// promptly instead of at the next reconnect (SMELLS.md P4/P5). `None`
    /// disables liveness timing (the driver's `Closed` is then the only signal).
    pub idle_timeout: Option<Duration>,
    /// If set, a v3.4/v3.5 handshake that does not complete within this window is
    /// torn down and retried. Without it a device that opens the socket but never
    /// sends `SessKeyNegResp` would stall `Handshaking` forever (idle_timeout only
    /// runs once `Connected`). `None` disables the handshake deadline.
    pub handshake_timeout: Option<Duration>,
}

/// An input pushed into the state machine by the driver.
pub enum Input<'a> {
    /// The driver established the TCP connection.
    Connected,
    /// The driver failed to open the TCP connection (arms backoff).
    ConnectFailed,
    /// The driver read these raw bytes from the socket — any fragment: a partial
    /// frame, one frame, or several coalesced. The core reassembles (D4).
    Received(&'a [u8]),
    /// The caller wants to send a command; `t` is the wall-clock timestamp
    /// (seconds) the driver stamps. `cid` addresses a gateway **sub-device** by
    /// its channel id; `None` addresses the device/gateway itself.
    Send {
        cmd: CommandType,
        data: Option<Value>,
        cid: Option<&'a str>,
        t: u64,
    },
    /// (Re)connect **now**: cancel any backoff wait and redial immediately, and
    /// revive a terminal `Closed` (`auto_reconnect = false`) device. The single
    /// "connect now" signal, fed either by an explicit user `connect_now()` or by
    /// the `discovery` FSM seeing this device on the LAN — both mean the same
    /// thing to the core, so there is one input. This is the sans-io replacement
    /// for the 0.3 `wait_for_backoff` sleep-vs-rediscovery `select` (SMELLS P3).
    /// The backoff *attempt* counter is left intact, so repeated wakes (a flapping
    /// device, or `connect_now` spam) can't defeat the escalation; a successful
    /// connection resets it.
    ConnectNow,
    /// The connection was closed / dropped.
    Closed,
}

/// An event drained by the driver, destined for the listener / caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Handshake complete (or not needed) — the device is ready for commands.
    Ready,
    /// A decoded inbound message (a response or an unsolicited push).
    Response(Message),
    /// A live connection was lost (only emitted when leaving a connected state,
    /// not on each failed retry).
    Disconnected,
    /// A protocol-level error occurred while processing input.
    ProtocolError(CoreError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// The driver should dial; awaiting `Connected` / `ConnectFailed`.
    Connecting,
    /// v3.4/v3.5 session-key negotiation in flight.
    Handshaking,
    /// Ready for commands.
    Connected,
    /// Waiting out a reconnect delay; `deadline` holds when to redial.
    Backoff,
    /// Terminal: disconnected with `auto_reconnect = false`.
    Closed,
}

/// The pure connection state machine.
pub struct Device {
    cfg: Config,
    state: State,
    session_key: Option<Vec<u8>>,
    handshake: Option<Handshake>,
    seqno: u32,
    /// Consecutive failed/lost connections; reset to 0 on reaching `Connected`.
    attempt: u32,
    /// When to redial while in `Backoff`.
    deadline: Option<Instant>,
    /// When to send the next keepalive `HeartBeat` while `Connected`.
    next_heartbeat: Option<Instant>,
    /// When silence declares the connection dead while `Connected`.
    idle_deadline: Option<Instant>,
    /// When to give up on an incomplete handshake while `Handshaking`.
    handshake_deadline: Option<Instant>,
    /// Reassembles whole frames out of the raw socket byte stream (D4).
    rx: RxBuffer,
    tx: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
}

impl Device {
    /// A new device that begins wanting to connect (`wants_connect() == true`).
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            state: State::Connecting,
            session_key: None,
            handshake: None,
            seqno: 1,
            attempt: 0,
            deadline: None,
            next_heartbeat: None,
            idle_deadline: None,
            handshake_deadline: None,
            rx: RxBuffer::new(),
            tx: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Feeds one input into the machine, queuing any resulting transmits/events.
    /// `now` is the driver's monotonic clock; the core never reads a clock itself.
    pub fn handle_input(&mut self, input: Input<'_>, now: Instant, rng: &mut impl RngCore) {
        match input {
            Input::Connected => self.on_connected(now, rng),
            Input::ConnectFailed => self.on_connect_failed(now, rng),
            Input::Received(data) => self.on_received(data, now, rng),
            Input::Send { cmd, data, cid, t } => self.on_send(cmd, data, cid, t, now, rng),
            Input::ConnectNow => self.on_connect_now(),
            Input::Closed => self.on_closed(now, rng),
        }
    }

    /// Fires the single armed timer and recomputes internal deadlines (D2). The
    /// driver arms **one** timer at [`poll_timeout`](Self::poll_timeout); on fire
    /// this evaluates whichever deadline(s) elapsed:
    ///  * `Backoff` elapsed → return to `Connecting` so the driver redials;
    ///  * `Connected` idle elapsed → declare the peer dead and disconnect (the
    ///    silent-drop fix, SMELLS P4/P5) — checked first so a dead link doesn't
    ///    also emit a doomed heartbeat;
    ///  * `Connected` heartbeat elapsed → emit a keepalive frame (needs the
    ///    injected RNG for the v3.5 GCM IV) and re-arm.
    pub fn handle_timeout(&mut self, now: Instant, rng: &mut impl RngCore) {
        match self.state {
            State::Backoff => {
                if let Some(deadline) = self.deadline
                    && now >= deadline
                {
                    self.deadline = None;
                    self.state = State::Connecting;
                }
            }
            State::Connected => {
                if let Some(idle) = self.idle_deadline
                    && now >= idle
                {
                    self.disconnect(now, rng);
                    return;
                }
                if let Some(hb) = self.next_heartbeat
                    && now >= hb
                {
                    self.send_heartbeat(rng);
                    self.next_heartbeat = self.cfg.heartbeat.map(|iv| now + iv);
                }
            }
            State::Handshaking => {
                // A handshake that never completes: tear the socket down (emit
                // Disconnected so the driver closes it) and re-arm backoff.
                if let Some(deadline) = self.handshake_deadline
                    && now >= deadline
                {
                    self.disconnect(now, rng);
                }
            }
            // Connecting/Closed are driver-driven; no core timer.
            State::Connecting | State::Closed => {}
        }
    }

    /// Bytes to write to the socket (drain to `None`).
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    /// Events for the listener/caller (drain to `None`).
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// The single next deadline the driver should arm a timer for (D2): the
    /// earliest of the currently-active internal deadlines. `Backoff` exposes the
    /// redial time; `Connected` exposes `min(next_heartbeat, idle_deadline)`.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        match self.state {
            State::Backoff => self.deadline,
            State::Connected => earliest(self.next_heartbeat, self.idle_deadline),
            State::Handshaking => self.handshake_deadline,
            State::Connecting | State::Closed => None,
        }
    }

    /// Whether the driver should (re)dial a socket. Level-triggered: true exactly
    /// while in `Connecting`, so the driver dials once and the result
    /// (`Connected` / `ConnectFailed`) moves the machine on.
    #[must_use]
    pub fn wants_connect(&self) -> bool {
        self.state == State::Connecting
    }

    /// Whether the device is connected and past any handshake.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    // -- transitions ---------------------------------------------------------

    fn on_connected(&mut self, now: Instant, rng: &mut impl RngCore) {
        if self.state != State::Connecting {
            return; // stray Connected (e.g. during backoff) — ignore
        }
        if self.cfg.version.profile().session_key {
            let mut nonce = [0u8; 16];
            rng.fill_bytes(&mut nonce);
            let hs = Handshake::new(nonce);
            let key = self.cfg.local_key;
            match self.encode(CommandType::SessKeyNegStart as u32, hs.local_nonce(), &key, rng) {
                Ok(bytes) => {
                    self.tx.push_back(bytes);
                    self.handshake = Some(hs);
                    self.handshake_deadline = self.cfg.handshake_timeout.map(|d| now + d);
                    self.state = State::Handshaking;
                }
                // A failure here never emitted Disconnected (we were mid-connect),
                // so route through the connect-failure path, not disconnect().
                Err(e) => {
                    self.events.push_back(Event::ProtocolError(e));
                    self.arm_backoff(now, rng);
                }
            }
        } else {
            self.reach_connected(now);
        }
    }

    fn on_connect_failed(&mut self, now: Instant, rng: &mut impl RngCore) {
        if self.state == State::Connecting {
            self.arm_backoff(now, rng);
        }
    }

    fn on_connect_now(&mut self) {
        // Cancel a backoff wait and revive a terminal `Closed`; the driver then
        // dials (`wants_connect`). The backoff *attempt* counter is left intact —
        // a flapping device or repeated `connect_now` can't reset the escalation;
        // a successful connection (`reach_connected`) is what resets it.
        if matches!(self.state, State::Backoff | State::Closed) {
            self.deadline = None;
            self.state = State::Connecting;
        }
    }

    fn on_received(&mut self, data: &[u8], now: Instant, rng: &mut impl RngCore) {
        // Only buffer bytes while a connection is live; stray bytes in any other
        // state belong to a dead socket and are dropped.
        if !matches!(self.state, State::Handshaking | State::Connected) {
            return;
        }
        self.rx.push(data);
        // Drain every whole frame the read completed. A frame may itself move the
        // FSM (handshake → connected, or a fault → teardown), so re-check state
        // each turn and stop the moment we leave a receiving state.
        loop {
            match self.rx.next_frame() {
                Ok(Some(frame)) => self.on_frame(&frame, now, rng),
                Ok(None) => break,
                Err(e) => {
                    self.rx.clear();
                    self.fail(e, now, rng);
                    break;
                }
            }
            if !matches!(self.state, State::Handshaking | State::Connected) {
                break;
            }
        }
    }

    /// Dispatch one fully-reassembled frame by connection state.
    fn on_frame(&mut self, frame: &[u8], now: Instant, rng: &mut impl RngCore) {
        match self.state {
            State::Handshaking => self.on_handshake_response(frame, now, rng),
            State::Connected => {
                // Any inbound frame proves the peer is alive: push the idle
                // (silent-drop) deadline forward.
                self.idle_deadline = self.cfg.idle_timeout.map(|d| now + d);
                // Data responses carry a 4-byte retcode (S1: explicit, cmd-context
                // driven — not byte-sniffed).
                match message::decode_message(self.cfg.version, frame, self.active_key(), true) {
                    Ok(msg) => self.events.push_back(Event::Response(msg)),
                    Err(e) => self.events.push_back(Event::ProtocolError(e)),
                }
            }
            State::Connecting | State::Backoff | State::Closed => {}
        }
    }

    fn on_handshake_response(&mut self, data: &[u8], now: Instant, rng: &mut impl RngCore) {
        // The SessKeyNegResp payload is `remote_nonce(16) || HMAC(32)`, framed
        // with the local key. Like every device→client message it carries a
        // 4-byte retcode (outside the ECB for 55AA, inside the GCM for 6699) that
        // must be stripped — `has_retcode = true`. A failure at any step lost the
        // negotiation, so disconnect (+ backoff).
        let key = self.cfg.local_key;
        let payload = match message::decode_message(self.cfg.version, data, &key, true) {
            Ok(m) => m.payload,
            Err(e) => return self.fail(e, now, rng),
        };
        let Some(hs) = self.handshake.take() else {
            return self.fail(CoreError::NotConnected, now, rng);
        };
        let remote_nonce = match hs.verify_response(&payload, &key) {
            Ok(n) => n,
            Err(e) => return self.fail(e, now, rng),
        };
        let finished = match hs.finish(self.cfg.version, &remote_nonce, &key) {
            Ok(f) => f,
            Err(e) => return self.fail(e, now, rng),
        };
        // SessKeyNegFinish is framed with the local key (before the session key
        // takes effect). For v3.5 this is a 6699/GCM frame, so it needs a fresh
        // random IV from the injected RNG — never a fixed one (S3/P2).
        match self.encode(CommandType::SessKeyNegFinish as u32, &finished.finish_hmac, &key, rng) {
            Ok(bytes) => self.tx.push_back(bytes),
            Err(e) => return self.fail(e, now, rng),
        }
        self.session_key = Some(finished.session_key);
        self.reach_connected(now);
    }

    fn on_send(
        &mut self,
        cmd: CommandType,
        data: Option<Value>,
        cid: Option<&str>,
        t: u64,
        now: Instant,
        rng: &mut impl RngCore,
    ) {
        if self.state != State::Connected {
            self.events.push_back(Event::ProtocolError(CoreError::NotConnected));
            return;
        }
        let (code, value) = command::generate(
            self.cfg.version,
            self.cfg.dev_type,
            &self.cfg.device_id,
            cmd,
            data,
            cid,
            t,
        );
        let plaintext = json::to_bytes(&value);
        let key = self.active_key().to_vec();
        match self.encode(code, &plaintext, &key, rng) {
            Ok(bytes) => {
                self.tx.push_back(bytes);
                // Outbound traffic keeps the device's client-idle timer alive just
                // like a heartbeat would, so defer the next keepalive by a full
                // interval (0.3 tracked `last_sent`; the heartbeat is an
                // inactivity bound, not a fixed beat). Nothing to do if heartbeats
                // are disabled.
                if let Some(iv) = self.cfg.heartbeat {
                    self.next_heartbeat = Some(now.saturating_add(iv));
                }
            }
            Err(e) => self.events.push_back(Event::ProtocolError(e)),
        }
    }

    fn on_closed(&mut self, now: Instant, rng: &mut impl RngCore) {
        match self.state {
            State::Handshaking | State::Connected => self.disconnect(now, rng),
            // Aborted mid-dial: never was up, so no Disconnected event — just retry.
            State::Connecting => self.arm_backoff(now, rng),
            State::Backoff | State::Closed => {} // idempotent
        }
    }

    // -- helpers -------------------------------------------------------------

    /// Leaving a live (Handshaking/Connected) state: surface Disconnected, clear
    /// session state, and re-arm backoff (or go terminal).
    fn disconnect(&mut self, now: Instant, rng: &mut impl RngCore) {
        self.session_key = None;
        self.handshake = None;
        self.events.push_back(Event::Disconnected);
        self.arm_backoff(now, rng);
    }

    /// Compute the next redial deadline (or go terminal if `!auto_reconnect`).
    fn arm_backoff(&mut self, now: Instant, rng: &mut impl RngCore) {
        self.session_key = None;
        self.handshake = None;
        self.next_heartbeat = None; // no keepalive/liveness timing while down
        self.idle_deadline = None;
        self.handshake_deadline = None;
        self.rx.clear(); // any buffered bytes belong to the dead connection
        if self.cfg.auto_reconnect {
            let delay = self.cfg.backoff.delay(self.attempt, rng);
            self.attempt = self.attempt.saturating_add(1);
            self.deadline = Some(now.saturating_add(delay));
            self.state = State::Backoff;
        } else {
            self.deadline = None;
            self.state = State::Closed;
        }
    }

    fn reach_connected(&mut self, now: Instant) {
        self.state = State::Connected;
        self.attempt = 0; // a good connection resets the backoff curve
        self.deadline = None;
        self.handshake_deadline = None;
        self.next_heartbeat = self.cfg.heartbeat.map(|iv| now + iv);
        self.idle_deadline = self.cfg.idle_timeout.map(|d| now + d);
        self.events.push_back(Event::Ready);
    }

    /// Emit a keepalive `HeartBeat` frame. Its payload carries no timestamp
    /// (`{gwId, devId}`), so a wall-clock `t` is irrelevant here.
    fn send_heartbeat(&mut self, rng: &mut impl RngCore) {
        let (code, value) = command::generate(
            self.cfg.version,
            self.cfg.dev_type,
            &self.cfg.device_id,
            CommandType::HeartBeat,
            None,
            None,
            0,
        );
        let plaintext = json::to_bytes(&value);
        let key = self.active_key().to_vec();
        match self.encode(code, &plaintext, &key, rng) {
            Ok(bytes) => self.tx.push_back(bytes),
            Err(e) => self.events.push_back(Event::ProtocolError(e)),
        }
    }

    fn active_key(&self) -> &[u8] {
        self.session_key.as_deref().unwrap_or(&self.cfg.local_key)
    }

    fn encode(
        &mut self,
        cmd: u32,
        plaintext: &[u8],
        key: &[u8],
        rng: &mut impl RngCore,
    ) -> Result<Vec<u8>, CoreError> {
        let mut iv = [0u8; 12];
        rng.fill_bytes(&mut iv);
        let seqno = self.seqno;
        self.seqno = self.seqno.wrapping_add(1);
        message::encode_message(self.cfg.version, cmd, seqno, plaintext, key, &iv)
    }

    /// Protocol error on a live (handshaking/connected) path: surface it, then
    /// disconnect and re-arm backoff with the injected `now`/`rng`.
    fn fail(&mut self, e: CoreError, now: Instant, rng: &mut impl RngCore) {
        self.events.push_back(Event::ProtocolError(e));
        self.disconnect(now, rng);
    }
}

/// The earlier of two optional deadlines (`None` acts as "no deadline").
fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if a <= b { a } else { b }),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::decode_message;
    use alloc::vec;
    use cipher::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    const KEY: [u8; 16] = *b"0123456789abcdef";
    const ID: &str = "01234567890123456789ab";
    const T0: Instant = Instant::from_millis(0);

    // A tiny deterministic RngCore so tests don't need `rand`.
    struct SeededRng(u64);
    impl RngCore for SeededRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn next_u64(&mut self) -> u64 {
            (u64::from(self.next_u32()) << 32) | u64::from(self.next_u32())
        }
        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for b in dst.iter_mut() {
                *b = self.next_u32() as u8;
            }
        }
    }

    fn cfg(version: Version) -> Config {
        cfg_with(version, true, zero_backoff())
    }

    fn cfg_with(version: Version, auto_reconnect: bool, backoff: Backoff) -> Config {
        Config {
            version,
            dev_type: DeviceType::Default,
            device_id: ID.into(),
            local_key: KEY,
            auto_reconnect,
            backoff,
            heartbeat: None,
            idle_timeout: None,
            handshake_timeout: None,
        }
    }

    /// Connect a legacy device and drain the `Ready` event, returning it ready.
    fn connected(cfg: Config, rng: &mut impl RngCore) -> Device {
        let mut dev = Device::new(cfg);
        dev.handle_input(Input::Connected, T0, rng);
        while dev.poll_event().is_some() {}
        while dev.poll_transmit().is_some() {}
        dev
    }

    fn zero_backoff() -> Backoff {
        Backoff {
            base: Duration::ZERO,
            max: Duration::ZERO,
            jitter: Duration::ZERO,
        }
    }

    fn drain_events(dev: &mut Device) -> Vec<Event> {
        let mut v = Vec::new();
        while let Some(e) = dev.poll_event() {
            v.push(e);
        }
        v
    }

    /// Recover the FSM's nonce from the SessKeyNegStart it emitted and craft the
    /// matching device SessKeyNegResp (framed bytes, not yet fed).
    fn craft_handshake_response(dev: &mut Device, version: Version) -> Vec<u8> {
        let start = dev.poll_transmit().expect("SessKeyNegStart");
        let start_msg = decode_message(version, &start, &KEY, false).unwrap();
        let local_nonce = start_msg.payload;
        let remote_nonce = [7u8; 16];
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(&local_nonce);
        let mut reply = remote_nonce.to_vec();
        reply.extend_from_slice(&mac.finalize().into_bytes());
        craft_device_frame(version, CommandType::SessKeyNegResp as u32, 1, &reply)
    }

    /// Build a faithful device→client frame: a 4-byte retcode plus the version-
    /// encoded `inner` payload (retcode outside the ECB for 55AA, inside the GCM
    /// plaintext for 6699), matching what a real device / tuyamock emits.
    fn craft_device_frame(version: Version, cmd: u32, seqno: u32, inner: &[u8]) -> Vec<u8> {
        use crate::crypto::TuyaCipher;
        use crate::frame::{self, Integrity};
        use crate::payload::encode_payload;
        let cipher = TuyaCipher::new(&KEY).unwrap();
        let encoded = encode_payload(version, cmd, inner, &cipher).unwrap();
        let mut body = vec![0u8; 4]; // retcode 0, ahead of the encoded payload
        body.extend_from_slice(&encoded);
        match version {
            // 6699: the retcode rides inside the GCM plaintext.
            Version::V3_5 => frame::pack_6699(seqno, cmd, &body, &KEY, &[3u8; 12]).unwrap(),
            // 55AA: the retcode sits in the frame body, outside the ciphertext.
            Version::V3_4 => frame::pack_55aa(seqno, cmd, &body, Integrity::Hmac(&KEY)),
            _ => frame::pack_55aa(seqno, cmd, &body, Integrity::Crc32),
        }
    }

    /// Drives a v3.4/v3.5 handshake to Connected in one feed.
    fn complete_handshake(dev: &mut Device, version: Version, rng: &mut impl RngCore) {
        let resp = craft_handshake_response(dev, version);
        dev.handle_input(Input::Received(&resp), T0, rng);
    }

    #[test]
    fn legacy_connect_is_ready_immediately() {
        let mut rng = SeededRng(1);
        let mut dev = Device::new(cfg(Version::V3_3));
        assert!(dev.wants_connect(), "starts wanting to connect");
        dev.handle_input(Input::Connected, T0, &mut rng);
        assert!(dev.is_connected());
        assert!(!dev.wants_connect());
        assert_eq!(drain_events(&mut dev), vec![Event::Ready]);
        assert!(dev.poll_transmit().is_none()); // no handshake on the wire
        assert_eq!(dev.poll_timeout(), None);
    }

    #[test]
    fn send_encodes_a_frame_that_decodes_back() {
        let mut rng = SeededRng(2);
        let mut dev = Device::new(cfg(Version::V3_3));
        dev.handle_input(Input::Connected, T0, &mut rng);
        let _ = drain_events(&mut dev);

        dev.handle_input(
            Input::Send {
                cmd: CommandType::Control,
                data: Some(json::from_bytes(br#"{"1":true}"#).unwrap()),
                cid: None,
                t: 1_700_000_000,
            },
            T0,
            &mut rng,
        );
        let wire = dev.poll_transmit().expect("a frame was queued");
        let msg = decode_message(Version::V3_3, &wire, &KEY, false).unwrap();
        assert_eq!(msg.cmd, CommandType::Control as u32);
        let v = json::from_bytes(&msg.payload).unwrap();
        assert_eq!(v["dps"], json::from_bytes(br#"{"1":true}"#).unwrap());
    }

    #[test]
    fn send_with_cid_targets_the_sub_device_in_the_envelope() {
        // A `cid` on Send must reach `command::generate`: the emitted frame's
        // envelope addresses the sub-device (`devId`/`cid` = the channel id), not
        // the gateway. Pins the M1.4b threading so a driver can never silently
        // drop the sub-device target.
        let mut rng = SeededRng(2);
        let mut dev = connected(cfg(Version::V3_3), &mut rng);
        dev.handle_input(
            Input::Send {
                cmd: CommandType::Control,
                data: Some(json::from_bytes(br#"{"1":true}"#).unwrap()),
                cid: Some("subchannel01"),
                t: 1_700_000_000,
            },
            T0,
            &mut rng,
        );
        let wire = dev.poll_transmit().expect("a frame was queued");
        let msg = decode_message(Version::V3_3, &wire, &KEY, false).unwrap();
        let v = json::from_bytes(&msg.payload).unwrap();
        assert_eq!(v["cid"], "subchannel01", "cid field present");
        assert_eq!(v["devId"], "subchannel01", "envelope addresses the sub-device");
        assert_eq!(v["dps"], json::from_bytes(br#"{"1":true}"#).unwrap());
    }

    #[test]
    fn send_before_ready_errors() {
        let mut rng = SeededRng(3);
        let mut dev = Device::new(cfg(Version::V3_5));
        dev.handle_input(
            Input::Send { cmd: CommandType::DpQuery, data: None, cid: None, t: 1 },
            T0,
            &mut rng,
        );
        assert_eq!(drain_events(&mut dev), vec![Event::ProtocolError(CoreError::NotConnected)]);
    }

    #[test]
    fn v34_and_v35_handshake_reaches_connected() {
        for version in [Version::V3_4, Version::V3_5] {
            let mut rng = SeededRng(42);
            let mut dev = Device::new(cfg(version));
            dev.handle_input(Input::Connected, T0, &mut rng);
            assert!(!dev.is_connected(), "{version:?} handshaking, not yet ready");
            complete_handshake(&mut dev, version, &mut rng);
            assert!(dev.is_connected(), "{version:?} connected after handshake");
            assert!(drain_events(&mut dev).contains(&Event::Ready), "{version:?}");
            assert!(dev.poll_transmit().is_some(), "{version:?} sent SessKeyNegFinish");
        }
    }

    #[test]
    fn bad_handshake_hmac_fails_and_reconnects() {
        let mut rng = SeededRng(9);
        let mut dev = Device::new(cfg(Version::V3_4));
        dev.handle_input(Input::Connected, T0, &mut rng);
        let _ = dev.poll_transmit();

        // A well-formed response frame but with a bad HMAC (48 zero bytes =
        // remote_nonce(16) + wrong hmac(32)) -> verify_response HMAC mismatch.
        let resp = craft_device_frame(Version::V3_4, CommandType::SessKeyNegResp as u32, 1, &[0u8; 48]);
        dev.handle_input(Input::Received(&resp), T0, &mut rng);
        assert!(!dev.is_connected());
        let events = drain_events(&mut dev);
        assert!(events.contains(&Event::Disconnected));
        // auto_reconnect: dropped into backoff (here zero-delay), wants to redial.
        assert_eq!(dev.poll_timeout(), Some(T0));
        dev.handle_timeout(T0, &mut rng);
        assert!(dev.wants_connect(), "backoff elapsed -> redial");
    }

    // -- reconnect / backoff (P1/P2/P6) --------------------------------------

    #[test]
    fn closed_reconnects_via_zero_backoff() {
        let mut rng = SeededRng(5);
        let mut dev = Device::new(cfg(Version::V3_3));
        dev.handle_input(Input::Connected, T0, &mut rng);
        let _ = drain_events(&mut dev);

        dev.handle_input(Input::Closed, T0, &mut rng);
        assert_eq!(drain_events(&mut dev), vec![Event::Disconnected]);
        assert!(!dev.is_connected());
        // Zero backoff: deadline is now; firing the timer returns to Connecting.
        assert_eq!(dev.poll_timeout(), Some(T0));
        assert!(!dev.wants_connect());
        dev.handle_timeout(T0, &mut rng);
        assert!(dev.wants_connect());
        assert_eq!(dev.poll_timeout(), None);

        // A second Closed while backing off is idempotent (no extra events).
        dev.handle_input(Input::Connected, T0, &mut rng);
        let _ = drain_events(&mut dev);
        dev.handle_input(Input::Closed, T0, &mut rng);
        let _ = drain_events(&mut dev);
        dev.handle_input(Input::Closed, T0, &mut rng);
        assert!(drain_events(&mut dev).is_empty());
    }

    #[test]
    fn no_auto_reconnect_goes_terminal() {
        let mut rng = SeededRng(5);
        let mut dev = Device::new(cfg_with(Version::V3_3, false, zero_backoff()));
        dev.handle_input(Input::Connected, T0, &mut rng);
        let _ = drain_events(&mut dev);
        dev.handle_input(Input::Closed, T0, &mut rng);
        assert_eq!(drain_events(&mut dev), vec![Event::Disconnected]);
        assert_eq!(dev.poll_timeout(), None);
        assert!(!dev.wants_connect(), "terminal — no redial");
        // Firing a stray timeout does nothing.
        dev.handle_timeout(Instant::from_millis(999), &mut rng);
        assert!(!dev.wants_connect());
    }

    #[test]
    fn connect_failed_arms_backoff_without_disconnected_event() {
        let mut rng = SeededRng(7);
        let backoff = Backoff {
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
            jitter: Duration::ZERO,
        };
        let mut dev = Device::new(cfg_with(Version::V3_3, true, backoff));
        let start = Instant::from_millis(10_000);
        dev.handle_input(Input::ConnectFailed, start, &mut rng);
        // Never was up: no Disconnected, but a backoff deadline is armed.
        assert!(drain_events(&mut dev).is_empty());
        assert_eq!(dev.poll_timeout(), Some(start + Duration::from_secs(1)));
        assert!(!dev.wants_connect());
    }

    #[test]
    fn backoff_grows_exponentially_and_caps_then_resets() {
        // jitter = 0 makes the curve deterministic: base, 2·base, 4·base, … ≤ max.
        let backoff = Backoff {
            base: Duration::from_secs(2),
            max: Duration::from_secs(10),
            jitter: Duration::ZERO,
        };
        let mut rng = SeededRng(1);
        let mut dev = Device::new(cfg_with(Version::V3_3, true, backoff));

        let mut now = Instant::from_millis(0);
        let expected = [2, 4, 8, 10, 10]; // seconds: exponential then capped at max
        for secs in expected {
            dev.handle_input(Input::ConnectFailed, now, &mut rng);
            let deadline = dev.poll_timeout().expect("armed");
            assert_eq!(deadline, now + Duration::from_secs(secs), "attempt at {now:?}");
            now = deadline;
            dev.handle_timeout(now, &mut rng); // elapse -> Connecting
            assert!(dev.wants_connect());
        }

        // A successful connection resets the attempt counter: next failure is base.
        dev.handle_input(Input::Connected, now, &mut rng);
        let _ = drain_events(&mut dev);
        dev.handle_input(Input::Closed, now, &mut rng);
        assert_eq!(dev.poll_timeout(), Some(now + Duration::from_secs(2)), "curve reset to base");
    }

    #[test]
    fn jitter_stays_within_bounds_and_uses_injected_rng() {
        let backoff = Backoff {
            base: Duration::from_secs(1),
            max: Duration::from_secs(1),
            jitter: Duration::from_secs(1),
        };
        // Two different seeds should (generally) yield different jittered delays,
        // and every delay lies in [base, base+jitter) = [1000, 2000) ms.
        let mut seen = Vec::new();
        for seed in [1u64, 2, 3, 4] {
            let mut rng = SeededRng(seed);
            let mut dev = Device::new(cfg_with(Version::V3_3, true, backoff));
            dev.handle_input(Input::ConnectFailed, T0, &mut rng);
            let ms = dev.poll_timeout().unwrap().as_millis();
            assert!((1000..2000).contains(&ms), "seed {seed}: {ms} out of range");
            seen.push(ms);
        }
        assert!(seen.iter().any(|&ms| ms != seen[0]), "jitter should vary with the RNG");
    }

    #[test]
    fn premature_timeout_is_ignored() {
        let backoff = Backoff {
            base: Duration::from_secs(5),
            max: Duration::from_secs(5),
            jitter: Duration::ZERO,
        };
        let mut rng = SeededRng(1);
        let mut dev = Device::new(cfg_with(Version::V3_3, true, backoff));
        dev.handle_input(Input::ConnectFailed, T0, &mut rng);
        let deadline = dev.poll_timeout().unwrap();
        // Fire a full second early: still backing off, still not wanting connect.
        let early = Instant::from_millis(deadline.as_millis() - 1000);
        dev.handle_timeout(early, &mut rng);
        assert!(!dev.wants_connect());
        assert_eq!(dev.poll_timeout(), Some(deadline));
        // Exactly at the deadline it fires.
        dev.handle_timeout(deadline, &mut rng);
        assert!(dev.wants_connect());
    }

    // -- connect-now / discovery-wake (P3) -----------------------------------

    #[test]
    fn connect_now_cancels_backoff_and_redials() {
        let backoff = Backoff {
            base: Duration::from_secs(30),
            max: Duration::from_secs(30),
            jitter: Duration::ZERO,
        };
        let mut rng = SeededRng(1);
        let mut dev = Device::new(cfg_with(Version::V3_3, true, backoff));
        dev.handle_input(Input::Connected, T0, &mut rng);
        let _ = drain_events(&mut dev);
        dev.handle_input(Input::Closed, T0, &mut rng);
        let _ = drain_events(&mut dev);
        assert_eq!(dev.poll_timeout(), Some(T0 + Duration::from_secs(30)));
        assert!(!dev.wants_connect());

        // Woken (LAN sighting or explicit connect_now) → skip the 30 s wait.
        dev.handle_input(Input::ConnectNow, T0, &mut rng);
        assert!(dev.wants_connect());
        assert_eq!(dev.poll_timeout(), None);
    }

    #[test]
    fn connect_now_revives_a_terminal_closed_device() {
        // auto_reconnect = false → Closed on drop; ConnectNow brings it back.
        let mut rng = SeededRng(1);
        let mut dev = Device::new(cfg_with(Version::V3_3, false, zero_backoff()));
        dev.handle_input(Input::Connected, T0, &mut rng);
        let _ = drain_events(&mut dev);
        dev.handle_input(Input::Closed, T0, &mut rng);
        assert!(!dev.wants_connect(), "terminal Closed");
        assert_eq!(dev.poll_timeout(), None);

        dev.handle_input(Input::ConnectNow, T0, &mut rng);
        assert!(dev.wants_connect(), "revived → wants to dial");
    }

    #[test]
    fn connect_now_preserves_backoff_escalation() {
        // Repeated wakes (flapping device / connect_now spam) must not reset the curve.
        let backoff = Backoff {
            base: Duration::from_secs(2),
            max: Duration::from_secs(100),
            jitter: Duration::ZERO,
        };
        let mut rng = SeededRng(1);
        let mut dev = Device::new(cfg_with(Version::V3_3, true, backoff));
        dev.handle_input(Input::Connected, T0, &mut rng);
        let _ = drain_events(&mut dev);
        dev.handle_input(Input::Closed, T0, &mut rng); // attempt 0 → 2 s
        assert_eq!(dev.poll_timeout(), Some(T0 + Duration::from_secs(2)));
        dev.handle_input(Input::ConnectNow, T0, &mut rng); // → Connecting, counter intact
        dev.handle_input(Input::ConnectFailed, T0, &mut rng); // attempt 1 → 4 s, not reset to 2 s
        assert_eq!(dev.poll_timeout(), Some(T0 + Duration::from_secs(4)));
    }

    #[test]
    fn connect_now_is_noop_when_connected() {
        let mut rng = SeededRng(1);
        let mut dev = connected(cfg(Version::V3_3), &mut rng);
        dev.handle_input(Input::ConnectNow, T0, &mut rng);
        assert!(dev.is_connected());
        assert!(dev.poll_event().is_none());
    }

    // -- heartbeat / idle liveness (P4/P5) -----------------------------------

    fn cfg_live(heartbeat: Option<Duration>, idle_timeout: Option<Duration>) -> Config {
        Config { heartbeat, idle_timeout, ..cfg(Version::V3_3) }
    }

    /// A valid inbound data frame (retcode(4) || json), as a device would send.
    fn inbound_data_frame() -> Vec<u8> {
        let mut body = vec![0u8; 4]; // retcode 0
        body.extend_from_slice(br#"{"dps":{"1":true}}"#);
        message::encode_message(Version::V3_3, CommandType::DpQuery as u32, 9, &body, &KEY, &[0u8; 12]).unwrap()
    }

    #[test]
    fn heartbeat_fires_and_rearms() {
        let mut rng = SeededRng(1);
        let mut dev = connected(cfg_live(Some(Duration::from_secs(10)), None), &mut rng);
        assert_eq!(dev.poll_timeout(), Some(Instant::from_millis(10_000)));

        // At the deadline: a HeartBeat frame goes out and the timer re-arms +10s.
        dev.handle_timeout(Instant::from_millis(10_000), &mut rng);
        let wire = dev.poll_transmit().expect("heartbeat frame");
        let msg = decode_message(Version::V3_3, &wire, &KEY, false).unwrap();
        assert_eq!(msg.cmd, CommandType::HeartBeat as u32);
        assert_eq!(dev.poll_timeout(), Some(Instant::from_millis(20_000)));
        assert!(dev.is_connected(), "heartbeat keeps the connection");
    }

    #[test]
    fn sending_defers_the_heartbeat() {
        // Outbound traffic keeps the device's client-idle timer alive, so a real
        // command should push the next keepalive out a full interval — the
        // heartbeat is an inactivity bound, not a fixed beat (mirrors 0.3's
        // `last_sent` tracking).
        let mut rng = SeededRng(1);
        let mut dev = connected(cfg_live(Some(Duration::from_secs(10)), None), &mut rng);
        assert_eq!(dev.poll_timeout(), Some(Instant::from_millis(10_000)));

        // A command goes out at t=6s → keepalive defers to 6+10 = 16s.
        dev.handle_input(
            Input::Send { cmd: CommandType::DpQuery, data: None, cid: None, t: 1 },
            Instant::from_millis(6_000),
            &mut rng,
        );
        let _ = dev.poll_transmit(); // the DpQuery frame itself
        assert_eq!(dev.poll_timeout(), Some(Instant::from_millis(16_000)), "send deferred the heartbeat");

        // The superseded 10s deadline fires nothing.
        dev.handle_timeout(Instant::from_millis(10_000), &mut rng);
        assert!(dev.poll_transmit().is_none(), "no heartbeat at the deferred-away 10s deadline");

        // At 16s the heartbeat finally goes out.
        dev.handle_timeout(Instant::from_millis(16_000), &mut rng);
        let wire = dev.poll_transmit().expect("heartbeat at the deferred deadline");
        let msg = decode_message(Version::V3_3, &wire, &KEY, false).unwrap();
        assert_eq!(msg.cmd, CommandType::HeartBeat as u32);
    }

    #[test]
    fn idle_timeout_declares_dead_and_reconnects() {
        let mut rng = SeededRng(1);
        let mut dev = connected(cfg_live(None, Some(Duration::from_secs(30))), &mut rng);
        assert_eq!(dev.poll_timeout(), Some(Instant::from_millis(30_000)));

        // Silence past the idle deadline: the FSM declares the peer dead — the
        // silent-drop fix (P5). Disconnected surfaces immediately, backoff arms.
        dev.handle_timeout(Instant::from_millis(30_000), &mut rng);
        assert!(!dev.is_connected());
        assert_eq!(drain_events(&mut dev), vec![Event::Disconnected]);
        assert!(dev.poll_timeout().is_some(), "dropped into backoff (auto_reconnect)");
    }

    #[test]
    fn inbound_frame_pushes_idle_deadline_forward() {
        let mut rng = SeededRng(1);
        let mut dev = connected(cfg_live(None, Some(Duration::from_secs(30))), &mut rng);
        // A frame arrives at t=20s → idle resets to 20+30 = 50s (peer is alive).
        let frame = inbound_data_frame();
        dev.handle_input(Input::Received(&frame), Instant::from_millis(20_000), &mut rng);
        let _ = drain_events(&mut dev);
        assert_eq!(dev.poll_timeout(), Some(Instant::from_millis(50_000)));
        // Firing at the *old* 30s deadline is now a no-op — still connected.
        dev.handle_timeout(Instant::from_millis(30_000), &mut rng);
        assert!(dev.is_connected());
    }

    #[test]
    fn poll_timeout_is_the_earliest_of_heartbeat_and_idle() {
        let mut rng = SeededRng(1);
        let mut dev = connected(
            cfg_live(Some(Duration::from_secs(10)), Some(Duration::from_secs(30))),
            &mut rng,
        );
        // min(heartbeat 10s, idle 30s) = 10s.
        assert_eq!(dev.poll_timeout(), Some(Instant::from_millis(10_000)));
        // After the heartbeat fires (and re-arms to 20s), idle (30s) is still the
        // farther one, so the next deadline is the re-armed heartbeat.
        dev.handle_timeout(Instant::from_millis(10_000), &mut rng);
        let _ = dev.poll_transmit();
        assert_eq!(dev.poll_timeout(), Some(Instant::from_millis(20_000)));
    }

    // -- handshake timeout ---------------------------------------------------

    #[test]
    fn stalled_handshake_times_out_and_reconnects() {
        let mut rng = SeededRng(1);
        let mut dev = Device::new(Config {
            handshake_timeout: Some(Duration::from_secs(5)),
            ..cfg(Version::V3_4)
        });
        dev.handle_input(Input::Connected, T0, &mut rng);
        let _ = dev.poll_transmit(); // SessKeyNegStart went out
        assert!(!dev.is_connected());
        assert_eq!(dev.poll_timeout(), Some(Instant::from_millis(5_000)), "handshake deadline armed");

        // Device never answers: at the deadline the FSM tears the socket down
        // (Disconnected → driver closes it) and re-arms backoff.
        dev.handle_timeout(Instant::from_millis(5_000), &mut rng);
        assert!(!dev.is_connected());
        assert_eq!(drain_events(&mut dev), vec![Event::Disconnected]);
        assert!(dev.poll_timeout().is_some(), "backoff armed for the retry");
    }

    #[test]
    fn completed_handshake_clears_its_deadline() {
        let mut rng = SeededRng(42);
        let mut dev = Device::new(Config {
            handshake_timeout: Some(Duration::from_secs(5)),
            ..cfg(Version::V3_4)
        });
        dev.handle_input(Input::Connected, T0, &mut rng);
        assert_eq!(dev.poll_timeout(), Some(Instant::from_millis(5_000)));
        complete_handshake(&mut dev, Version::V3_4, &mut rng);
        assert!(dev.is_connected());
        // No heartbeat/idle configured → the deadline is gone, not left stale.
        assert_eq!(dev.poll_timeout(), None, "handshake deadline cleared on connect");
    }

    // -- RX reassembly (D4) --------------------------------------------------

    #[test]
    fn fragmented_response_reassembles_into_one_event() {
        let mut rng = SeededRng(1);
        let mut dev = connected(cfg(Version::V3_3), &mut rng);
        let frame = inbound_data_frame();
        let mid = frame.len() / 2;
        dev.handle_input(Input::Received(&frame[..mid]), T0, &mut rng);
        assert!(dev.poll_event().is_none(), "half a frame yields nothing");
        dev.handle_input(Input::Received(&frame[mid..]), T0, &mut rng);
        let events = drain_events(&mut dev);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], Event::Response(_)));
    }

    #[test]
    fn coalesced_responses_emit_two_events() {
        let mut rng = SeededRng(1);
        let mut dev = connected(cfg(Version::V3_3), &mut rng);
        let mut glued = inbound_data_frame();
        glued.extend_from_slice(&inbound_data_frame());
        dev.handle_input(Input::Received(&glued), T0, &mut rng);
        let n = drain_events(&mut dev)
            .iter()
            .filter(|e| matches!(e, Event::Response(_)))
            .count();
        assert_eq!(n, 2, "both coalesced frames surface");
    }

    #[test]
    fn malformed_stream_tears_down() {
        let mut rng = SeededRng(1);
        let mut dev = connected(cfg(Version::V3_3), &mut rng);
        dev.handle_input(Input::Received(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]), T0, &mut rng);
        assert!(!dev.is_connected(), "a bad prefix corrupts the stream → teardown");
        let events = drain_events(&mut dev);
        assert!(events.iter().any(|e| matches!(e, Event::ProtocolError(_))));
        assert!(events.contains(&Event::Disconnected));
    }

    #[test]
    fn fragmented_handshake_response_reassembles() {
        let mut rng = SeededRng(42);
        let version = Version::V3_4;
        let mut dev = Device::new(cfg(version));
        dev.handle_input(Input::Connected, T0, &mut rng);
        let resp = craft_handshake_response(&mut dev, version);
        // Deliver the SessKeyNegResp in three fragments across three reads.
        dev.handle_input(Input::Received(&resp[..4]), T0, &mut rng);
        assert!(!dev.is_connected());
        dev.handle_input(Input::Received(&resp[4..20]), T0, &mut rng);
        assert!(!dev.is_connected());
        dev.handle_input(Input::Received(&resp[20..]), T0, &mut rng);
        assert!(dev.is_connected(), "handshake completes once the last fragment arrives");
    }

    // -- randomness uniqueness (injected RNG; tinytuya #722 immunity) ---------
    //
    // These pin the security property as *tests*, not convention: given a real
    // entropy source (modelled by one advancing seeded RNG), every handshake
    // nonce and every GCM IV the core puts on the wire is distinct. A driver that
    // wrongly fed a fixed/reset RNG would reuse a v3.5 nonce — exactly the
    // GCM-nonce-reuse class tinytuya PR #722 fixed, which rustuya is immune to.

    /// The 12-byte GCM IV a 6699 (v3.5) frame carries, at `header(18) .. +12`.
    fn frame_iv(wire: &[u8]) -> Vec<u8> {
        wire[18..30].to_vec()
    }

    fn assert_all_distinct(items: &[Vec<u8>]) {
        for i in 0..items.len() {
            for j in (i + 1)..items.len() {
                assert_ne!(items[i], items[j], "duplicate at ({i}, {j}) — randomness reuse");
            }
        }
    }

    /// A v3.5 device driven through the handshake to Connected, transmits drained.
    fn connected_v35(cfg: Config, rng: &mut impl RngCore) -> Device {
        let mut dev = Device::new(cfg);
        dev.handle_input(Input::Connected, T0, rng);
        complete_handshake(&mut dev, Version::V3_5, rng);
        while dev.poll_transmit().is_some() {}
        while dev.poll_event().is_some() {}
        dev
    }

    #[test]
    fn handshake_nonces_are_unique_across_connections() {
        let mut rng = SeededRng(123);
        let mut nonces = Vec::new();
        for _ in 0..8 {
            let mut dev = Device::new(cfg(Version::V3_4));
            dev.handle_input(Input::Connected, T0, &mut rng);
            let start = dev.poll_transmit().expect("SessKeyNegStart");
            // The SessKeyNegStart payload is the raw 16-byte local_nonce.
            nonces.push(decode_message(Version::V3_4, &start, &KEY, false).unwrap().payload);
        }
        assert_all_distinct(&nonces);
    }

    #[test]
    fn v35_message_ivs_are_unique() {
        let mut rng = SeededRng(7);
        let mut dev = connected_v35(cfg(Version::V3_5), &mut rng);
        let mut ivs = Vec::new();
        for i in 0..8 {
            dev.handle_input(
                Input::Send {
                    cmd: CommandType::Control,
                    data: Some(json::from_bytes(br#"{"1":true}"#).unwrap()),
                    cid: None,
                    t: 1_700_000_000 + i,
                },
                T0,
                &mut rng,
            );
            ivs.push(frame_iv(&dev.poll_transmit().expect("frame")));
        }
        assert_all_distinct(&ivs);
    }

    #[test]
    fn timer_driven_heartbeats_use_distinct_ivs() {
        let mut rng = SeededRng(3);
        let cfg = Config { heartbeat: Some(Duration::from_secs(10)), ..cfg(Version::V3_5) };
        let mut dev = connected_v35(cfg, &mut rng);
        let mut ivs = Vec::new();
        for k in 1..=5u64 {
            dev.handle_timeout(Instant::from_millis(k * 10_000), &mut rng);
            ivs.push(frame_iv(&dev.poll_transmit().expect("heartbeat frame")));
        }
        assert_all_distinct(&ivs);
    }
}
