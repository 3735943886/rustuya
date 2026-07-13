//! Connection-lifecycle state machine — **v1: happy path only**.
//!
//! Sans-I/O (poll-split, design D1): the driver pumps bytes/commands in via
//! [`Device::handle`] and drains work out via [`Device::poll_transmit`] /
//! [`Device::poll_event`]. No I/O, no timers, no randomness of its own — the
//! RNG is injected (handshake nonce, per-message GCM IV).
//!
//! v1 covers: connect → (v3.4/v3.5 session handshake) → connected → request /
//! response. Backoff/reconnect/heartbeat/idle timers and the discovery-wake
//! input come in later increments (SMELLS.md P1–P6) — deliberately excluded so
//! this stays a small, fully-tested skeleton.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use rand_core::RngCore;

use crate::command::{self, CommandType};
use crate::json::{self, Value};
use crate::message::{self, Message};
use crate::session::Handshake;
use crate::version::{DeviceType, Version};
use crate::CoreError;

/// Static configuration for one device.
pub struct Config {
    pub version: Version,
    pub dev_type: DeviceType,
    pub device_id: String,
    pub local_key: [u8; 16],
}

/// An input pushed into the state machine by the driver.
pub enum Input<'a> {
    /// The driver established the TCP connection.
    Connected,
    /// The driver read these bytes from the socket (one whole frame).
    Received(&'a [u8]),
    /// The caller wants to send a command; `t` is the wall-clock timestamp
    /// (seconds) the driver stamps.
    Send {
        cmd: CommandType,
        data: Option<Value>,
        t: u64,
    },
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
    /// The connection is gone.
    Disconnected,
    /// A protocol-level error occurred while processing input.
    ProtocolError(CoreError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Handshaking,
    Connected,
    Closed,
}

/// The pure connection state machine.
pub struct Device {
    cfg: Config,
    state: State,
    session_key: Option<Vec<u8>>,
    handshake: Option<Handshake>,
    seqno: u32,
    tx: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
}

impl Device {
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            state: State::Idle,
            session_key: None,
            handshake: None,
            seqno: 1,
            tx: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Feeds one input into the machine, queuing any resulting transmits/events.
    pub fn handle(&mut self, input: Input<'_>, rng: &mut impl RngCore) {
        match input {
            Input::Connected => self.on_connected(rng),
            Input::Received(data) => self.on_received(data, rng),
            Input::Send { cmd, data, t } => self.on_send(cmd, data, t, rng),
            Input::Closed => self.on_closed(),
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

    /// Whether the device is connected and past any handshake.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    // -- transitions ---------------------------------------------------------

    fn on_connected(&mut self, rng: &mut impl RngCore) {
        if self.cfg.version.profile().session_key {
            let mut nonce = [0u8; 16];
            rng.fill_bytes(&mut nonce);
            let hs = Handshake::new(nonce);
            let key = self.cfg.local_key;
            match self.encode(CommandType::SessKeyNegStart as u32, hs.local_nonce(), &key, rng) {
                Ok(bytes) => {
                    self.tx.push_back(bytes);
                    self.handshake = Some(hs);
                    self.state = State::Handshaking;
                }
                Err(e) => self.fail(e),
            }
        } else {
            self.state = State::Connected;
            self.events.push_back(Event::Ready);
        }
    }

    fn on_received(&mut self, data: &[u8], rng: &mut impl RngCore) {
        match self.state {
            State::Handshaking => self.on_handshake_response(data, rng),
            State::Connected => {
                // Data responses carry a 4-byte retcode (S1: explicit, cmd-context
                // driven — not byte-sniffed).
                match message::decode_message(self.cfg.version, data, self.active_key(), true) {
                    Ok(msg) => self.events.push_back(Event::Response(msg)),
                    Err(e) => self.events.push_back(Event::ProtocolError(e)),
                }
            }
            State::Idle | State::Closed => {}
        }
    }

    fn on_handshake_response(&mut self, data: &[u8], rng: &mut impl RngCore) {
        // The SessKeyNegResp payload is `remote_nonce(16) || HMAC(32)`, framed
        // with the local key and (unlike data responses) no retcode prefix.
        let key = self.cfg.local_key;
        let payload = match message::decode_message(self.cfg.version, data, &key, false) {
            Ok(m) => m.payload,
            Err(e) => return self.fail(e),
        };
        let Some(hs) = self.handshake.take() else {
            return self.fail(CoreError::NotConnected);
        };
        let remote_nonce = match hs.verify_response(&payload, &key) {
            Ok(n) => n,
            Err(e) => return self.fail(e),
        };
        let finished = match hs.finish(self.cfg.version, &remote_nonce, &key) {
            Ok(f) => f,
            Err(e) => return self.fail(e),
        };
        match self.encode(
            CommandType::SessKeyNegFinish as u32,
            &finished.finish_hmac,
            &key,
            rng,
        ) {
            Ok(bytes) => self.tx.push_back(bytes),
            Err(e) => return self.fail(e),
        }
        self.session_key = Some(finished.session_key);
        self.state = State::Connected;
        self.events.push_back(Event::Ready);
    }

    fn on_send(&mut self, cmd: CommandType, data: Option<Value>, t: u64, rng: &mut impl RngCore) {
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
            None,
            t,
        );
        let plaintext = json::to_bytes(&value);
        let key = self.active_key().to_vec();
        match self.encode(code, &plaintext, &key, rng) {
            Ok(bytes) => self.tx.push_back(bytes),
            Err(e) => self.events.push_back(Event::ProtocolError(e)),
        }
    }

    fn on_closed(&mut self) {
        if self.state != State::Closed {
            self.state = State::Closed;
            self.session_key = None;
            self.handshake = None;
            self.events.push_back(Event::Disconnected);
        }
    }

    // -- helpers -------------------------------------------------------------

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

    fn fail(&mut self, e: CoreError) {
        self.events.push_back(Event::ProtocolError(e));
        self.state = State::Closed;
        self.session_key = None;
        self.handshake = None;
        self.events.push_back(Event::Disconnected);
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
        Config {
            version,
            dev_type: DeviceType::Default,
            device_id: ID.into(),
            local_key: KEY,
        }
    }

    fn drain_events(dev: &mut Device) -> Vec<Event> {
        let mut v = Vec::new();
        while let Some(e) = dev.poll_event() {
            v.push(e);
        }
        v
    }

    #[test]
    fn legacy_connect_is_ready_immediately() {
        let mut rng = SeededRng(1);
        let mut dev = Device::new(cfg(Version::V3_3));
        dev.handle(Input::Connected, &mut rng);
        assert!(dev.is_connected());
        assert_eq!(drain_events(&mut dev), vec![Event::Ready]);
        assert!(dev.poll_transmit().is_none()); // no handshake on the wire
    }

    #[test]
    fn send_encodes_a_frame_that_decodes_back() {
        let mut rng = SeededRng(2);
        let mut dev = Device::new(cfg(Version::V3_3));
        dev.handle(Input::Connected, &mut rng);
        let _ = drain_events(&mut dev);

        dev.handle(
            Input::Send {
                cmd: CommandType::Control,
                data: Some(json::from_bytes(br#"{"1":true}"#).unwrap()),
                t: 1_700_000_000,
            },
            &mut rng,
        );
        let wire = dev.poll_transmit().expect("a frame was queued");
        let msg = decode_message(Version::V3_3, &wire, &KEY, false).unwrap();
        assert_eq!(msg.cmd, CommandType::Control as u32);
        // payload is the generated Control envelope (gwId dropped)
        let v = json::from_bytes(&msg.payload).unwrap();
        assert_eq!(v["dps"], json::from_bytes(br#"{"1":true}"#).unwrap());
    }

    #[test]
    fn send_before_ready_errors() {
        let mut rng = SeededRng(3);
        let mut dev = Device::new(cfg(Version::V3_5));
        dev.handle(
            Input::Send {
                cmd: CommandType::DpQuery,
                data: None,
                t: 1,
            },
            &mut rng,
        );
        assert_eq!(drain_events(&mut dev), vec![Event::ProtocolError(CoreError::NotConnected)]);
    }

    /// Drives a full v3.4/v3.5 handshake: read the SessKeyNegStart the FSM
    /// emits to recover its nonce, craft the device's response, and confirm the
    /// FSM reaches Connected with a working session key.
    fn handshake_reaches_connected(version: Version) {
        let mut rng = SeededRng(42);
        let mut dev = Device::new(cfg(version));
        dev.handle(Input::Connected, &mut rng);
        assert!(!dev.is_connected(), "{version:?} handshaking, not yet ready");

        // Recover local_nonce from the SessKeyNegStart the FSM sent.
        let start = dev.poll_transmit().expect("SessKeyNegStart");
        let start_msg = decode_message(version, &start, &KEY, false).unwrap();
        assert_eq!(start_msg.cmd, CommandType::SessKeyNegStart as u32);
        let local_nonce = start_msg.payload;

        // Craft SessKeyNegResp: remote_nonce(16) || HMAC(local_key, local_nonce).
        let remote_nonce = [7u8; 16];
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(&local_nonce);
        let mut resp_payload = remote_nonce.to_vec();
        resp_payload.extend_from_slice(&mac.finalize().into_bytes());
        let resp = message::encode_message(
            version,
            CommandType::SessKeyNegResp as u32,
            1,
            &resp_payload,
            &KEY,
            &[3u8; 12],
        )
        .unwrap();

        dev.handle(Input::Received(&resp), &mut rng);
        assert!(dev.is_connected(), "{version:?} connected after handshake");
        assert!(drain_events(&mut dev).contains(&Event::Ready), "{version:?}");
        assert!(dev.poll_transmit().is_some(), "{version:?} sent SessKeyNegFinish");
    }

    #[test]
    fn v34_and_v35_handshake_reaches_connected() {
        handshake_reaches_connected(Version::V3_4);
        handshake_reaches_connected(Version::V3_5);
    }

    #[test]
    fn bad_handshake_hmac_fails_and_disconnects() {
        let mut rng = SeededRng(9);
        let mut dev = Device::new(cfg(Version::V3_4));
        dev.handle(Input::Connected, &mut rng);
        let _ = dev.poll_transmit();

        // Garbage response of the right length (48 bytes) -> HMAC mismatch.
        let resp = message::encode_message(
            Version::V3_4,
            CommandType::SessKeyNegResp as u32,
            1,
            &[0u8; 48],
            &KEY,
            &[0u8; 12],
        )
        .unwrap();
        dev.handle(Input::Received(&resp), &mut rng);
        assert!(!dev.is_connected());
        let events = drain_events(&mut dev);
        assert!(events.contains(&Event::Disconnected));
    }

    #[test]
    fn closed_emits_disconnected_once() {
        let mut rng = SeededRng(5);
        let mut dev = Device::new(cfg(Version::V3_3));
        dev.handle(Input::Connected, &mut rng);
        let _ = drain_events(&mut dev);
        dev.handle(Input::Closed, &mut rng);
        assert_eq!(drain_events(&mut dev), vec![Event::Disconnected]);
        dev.handle(Input::Closed, &mut rng); // idempotent
        assert!(drain_events(&mut dev).is_empty());
    }
}
