//! Tuya device communication and state management.
//!
//! Handles TCP connections, handshakes, heartbeats, and command-response flows.

mod actor;
mod decision;
mod listener;

use crate::crypto::TuyaCipher;
use crate::crypto::hex_encode;
use crate::error::{Result, TuyaError};
use crate::protocol::{CommandType, DeviceType, TuyaMessage, Version};
use log::{debug, info, warn};
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use actor::DeviceCommand;

pub use listener::{DeviceEvent, unified_listener};

pub(super) const SLEEP_HEARTBEAT_DEFAULT: Duration = Duration::from_secs(7);
pub(super) const SLEEP_HEARTBEAT_CHECK: Duration = Duration::from_secs(5);
pub(super) const SLEEP_RECONNECT_MIN: Duration = Duration::from_secs(16);
pub(super) const SLEEP_RECONNECT_MAX: Duration = Duration::from_secs(4096);
pub(super) const SLEEP_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);

/// Base cooldown between scanner-triggered backoff bypasses when the
/// discovered IP matches what the device already knows. Doubles on each
/// useless bypass and resets on a successful connect.
pub(super) const SCANNER_BYPASS_BASE_COOLDOWN: Duration = Duration::from_secs(60);

pub(super) const ADDR_AUTO: &str = "Auto";
pub(super) const DATA_UNVALID: &str = "data unvalid";

pub(super) const CHAN_BROADCAST_CAPACITY: usize = 128;
pub(super) const CHAN_MPSC_CAPACITY: usize = 64;

/// Commands that must return data (payload) and should not return on empty ACK.
pub(super) const MANDATORY_DATA_CMDS: &[u32] = &[CommandType::LanExtStream as u32];

/// Commands that do not produce a response we should wait for
/// (handshake handshake-internal commands and heartbeats).
pub(super) const NO_RESPONSE_CMDS: &[u32] = &[
    CommandType::SessKeyNegStart as u32,
    CommandType::SessKeyNegResp as u32,
    CommandType::SessKeyNegFinish as u32,
    CommandType::HeartBeat as u32,
];

pub(super) mod keys {
    pub const REQ_TYPE: &str = "reqType";

    // Response keys
    pub const ERR_CODE: &str = "errorCode";
    pub const ERR_MSG: &str = "errorMsg";
    pub const ERR_PAYLOAD_OBJ: &str = "errorPayload";
    pub const PAYLOAD_STR: &str = "payloadStr";
    pub const PAYLOAD_RAW: &str = "payloadRaw";

    // Inbound payload keys consulted when synthesizing error messages from
    // device responses. Kept here so a future protocol change has one site
    // to update.
    pub const IN_DATA: &str = "data";
    pub const IN_PAYLOAD: &str = "payload";
}

/// A sub-device (endpoint) of a gateway device.
#[derive(Clone)]
pub struct SubDevice {
    parent: Device,
    cid: String,
}

impl SubDevice {
    pub(crate) fn new(parent: Device, cid: &str) -> Self {
        Self {
            parent,
            cid: cid.to_string(),
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.cid
    }

    pub async fn status(&self) -> Result<Option<String>> {
        self.request(CommandType::DpQuery, None).await
    }

    pub async fn set_dps(&self, dps: Value) -> Result<Option<String>> {
        self.request(CommandType::Control, Some(dps)).await
    }

    /// Sets a single DP value.
    pub async fn set_value<I: ToString, T: Serialize>(
        &self,
        index: I,
        value: T,
    ) -> Result<Option<String>> {
        if let Ok(val) = serde_json::to_value(value) {
            self.set_dps(serde_json::json!({ index.to_string(): val }))
                .await
        } else {
            Err(TuyaError::InvalidPayload)
        }
    }

    pub async fn request(&self, cmd: CommandType, data: Option<Value>) -> Result<Option<String>> {
        self.parent.request(cmd, data, Some(self.cid.clone())).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Stopped,
}

pub(super) struct DeviceState {
    pub(super) config_address: String,
    pub(super) real_ip: String,
    pub(super) version: Version,
    pub(super) port: u16,
    pub(super) dev_type: DeviceType,
    pub(super) state: ConnectionState,
    pub(super) last_received: Instant,
    pub(super) last_sent: Instant,
    pub(super) persist: bool,
    pub(super) session_key: Option<Vec<u8>>,
    pub(super) failure_count: u32,
    pub(super) success_count: u32,
    pub(super) force_discovery: bool,
    pub(super) timeout: Duration,
    pub(super) cipher: Option<Arc<TuyaCipher>>,
    pub(super) last_reported_discovered_ip: Option<String>,
    pub(super) last_scanner_bypass_at: Option<Instant>,
    pub(super) scanner_bypass_failures: u32,
    /// Latches the most recent status/error broadcast (`broadcast_error`) so a
    /// listener that subscribes *after* it was sent can still recover it. Tokio
    /// broadcast only delivers to receivers present at send time, so without
    /// this a device that connects before its listener subscribes loses its
    /// `ERR_SUCCESS` and is reported stuck "online"/unknown with no retry.
    pub(super) last_status: Option<TuyaMessage>,
}

pub struct DeviceBuilder {
    id: String,
    address: String,
    local_key: Vec<u8>,
    version: Version,
    dev_type: DeviceType,
    port: u16,
    persist: bool,
    timeout: Duration,
    nowait: bool,
}

impl DeviceBuilder {
    pub fn new<I, K>(id: I, local_key: K) -> Self
    where
        I: Into<String>,
        K: Into<Vec<u8>>,
    {
        Self {
            id: id.into(),
            address: ADDR_AUTO.to_string(),
            local_key: local_key.into(),
            version: Version::Auto,
            dev_type: DeviceType::Auto,
            port: 6668,
            persist: true,
            timeout: Duration::from_secs(10),
            nowait: false,
        }
    }

    pub fn address<A: Into<String>>(mut self, address: A) -> Self {
        self.address = address.into();
        self
    }

    pub fn version<V: Into<Version>>(mut self, version: V) -> Self {
        self.version = version.into();
        self
    }

    pub fn dev_type<DT: Into<DeviceType>>(mut self, dev_type: DT) -> Self {
        self.dev_type = dev_type.into();
        self
    }

    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    #[must_use]
    pub fn persist(mut self, persist: bool) -> Self {
        self.persist = persist;
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn nowait(mut self, nowait: bool) -> Self {
        self.nowait = nowait;
        self
    }

    /// Finalizes the builder and returns a connected [`Device`].
    #[must_use]
    pub fn build(self) -> Device {
        Device::with_builder(self)
    }
}

pub(super) struct DeviceInner {
    pub(super) id: String,
    pub(super) local_key: Vec<u8>,
    pub(super) state: RwLock<DeviceState>,
    pub(super) broadcast_tx: tokio::sync::broadcast::Sender<TuyaMessage>,
    pub(super) cancel_token: CancellationToken,
    // Side-channel for graceful disconnect. `close()` notifies this; the
    // actor's `select!` short-circuits the current connection without
    // dragging shutdown behind any queued user requests. Using a Notify here
    // instead of an mpsc message means close() doesn't have to wait for the
    // actor to drain its command queue.
    pub(super) close_notify: tokio::sync::Notify,
    pub(super) nowait: AtomicBool,
}

impl Drop for DeviceInner {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        debug!(
            "DeviceInner for {} dropped, cancelling connection task",
            self.id
        );
    }
}

#[derive(Clone)]
pub struct Device {
    pub(super) inner: Arc<DeviceInner>,
    pub(super) tx: Option<mpsc::Sender<DeviceCommand>>,
}

impl Device {
    /// Creates a new device with default settings and starts the background
    /// connection task.
    ///
    /// # Runtime behavior
    ///
    /// This is an **eager** constructor: it spawns a long-running tokio task
    /// on the library's dedicated runtime (see [`crate::runtime`]) before
    /// returning. The task stays alive — performing reconnects, heartbeats,
    /// and IP rediscovery — until the last `Device` clone is dropped or
    /// [`Device::stop`] is called.
    ///
    /// Consequences:
    ///
    /// - Calling `Device::new` outside any tokio runtime is fine; the
    ///   internal runtime takes care of execution.
    /// - You can `Device::new` from inside an async context as well; the
    ///   spawned task does *not* attach to the caller's runtime, so
    ///   consumer-side runtime shutdown won't kill it.
    /// - The constructor itself returns quickly — actual TCP work happens on
    ///   the spawned task.
    /// - Construct devices lazily if you may have hundreds-to-thousands of
    ///   them; each one starts a task on construction.
    pub fn new<I, K>(id: I, local_key: K) -> Self
    where
        I: Into<String>,
        K: Into<Vec<u8>>,
    {
        DeviceBuilder::new(id, local_key).build()
    }

    /// Returns a builder to configure device settings before running.
    pub fn builder<I, K>(id: I, local_key: K) -> DeviceBuilder
    where
        I: Into<String>,
        K: Into<Vec<u8>>,
    {
        DeviceBuilder::new(id, local_key)
    }

    pub(crate) fn with_builder(builder: DeviceBuilder) -> Self {
        let (device, rx) = Self::assemble(builder);
        device.spawn_connection_task(rx);
        device
    }

    /// Builds the `Device` and its channels but does **not** spawn the
    /// background connection task. Used by `with_builder` (which then spawns)
    /// and by the test-only [`Device::with_builder_no_actor`].
    fn assemble(builder: DeviceBuilder) -> (Self, mpsc::Receiver<DeviceCommand>) {
        let (addr, ip) = match builder.address.as_str() {
            "" | ADDR_AUTO => (ADDR_AUTO.to_string(), String::new()),
            _ => (builder.address.clone(), builder.address),
        };

        let (broadcast_tx, _) = tokio::sync::broadcast::channel(CHAN_BROADCAST_CAPACITY);
        let (tx, rx) = mpsc::channel(CHAN_MPSC_CAPACITY);
        let state = DeviceState {
            config_address: addr,
            real_ip: ip,
            version: builder.version,
            port: builder.port,
            dev_type: builder.dev_type,
            state: ConnectionState::Disconnected,
            last_received: Instant::now(),
            last_sent: Instant::now(),
            persist: builder.persist,
            session_key: None,
            failure_count: 0,
            success_count: 0,
            force_discovery: false,
            timeout: builder.timeout,
            cipher: TuyaCipher::new(&builder.local_key).ok().map(Arc::new),
            last_reported_discovered_ip: None,
            last_scanner_bypass_at: None,
            scanner_bypass_failures: 0,
            last_status: None,
        };

        let inner = Arc::new(DeviceInner {
            id: builder.id,
            local_key: builder.local_key,
            state: RwLock::new(state),
            broadcast_tx,
            cancel_token: CancellationToken::new(),
            close_notify: tokio::sync::Notify::new(),
            nowait: AtomicBool::new(builder.nowait),
        });

        let device = Self {
            inner: Arc::clone(&inner),
            tx: Some(tx),
        };

        (device, rx)
    }

    /// Spawns the long-running background connection task on the library's
    /// dedicated runtime. The task holds only a `Weak<DeviceInner>` (upgraded
    /// for the duration of a connection attempt), so dropping the last `Device`
    /// clone tears it down via [`DeviceInner::drop`] / the cancel token.
    fn spawn_connection_task(&self, rx: mpsc::Receiver<DeviceCommand>) {
        // Compute the initial-connect jitter synchronously so it reflects
        // construction time, not when the spawned task happens to run. A
        // single-device caller pays no jitter; bursty multi-device startup
        // still gets the staggering it needs.
        let initial_jitter = actor::record_construction_and_compute_jitter();

        let inner_weak = Arc::downgrade(&self.inner);
        let d_id = self.inner.id.clone();
        crate::runtime::spawn(async move {
            if let Some(inner) = inner_weak.upgrade() {
                let cancel_token = inner.cancel_token.clone();
                let d_task = Device { inner, tx: None };

                tokio::select! {
                    () = cancel_token.cancelled() => {
                        debug!("Device {d_id} connection task stopped via token");
                    }
                    () = d_task.run_connection_task(rx, initial_jitter) => {
                        debug!("Device {d_id} connection task finished");
                    }
                }
            }
        });
    }

    /// Test-only constructor that builds a fully-formed `Device` **without**
    /// spawning the background connection task. The actor runs on a separate
    /// runtime thread and would otherwise add nondeterministic
    /// `Arc::strong_count` churn; tests that assert exact ref counts (or that
    /// only inject via `broadcast_tx`) use this so the count is stable with no
    /// polling. The `rx` end of the command channel is dropped — these devices
    /// don't service user commands.
    #[cfg(test)]
    pub(crate) fn with_builder_no_actor(builder: DeviceBuilder) -> Self {
        Self::assemble(builder).0
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.inner.id
    }

    // ----------------------------------------------------------------
    // Getter implementation note
    //
    // These getters acquire `parking_lot::RwLock::read()` and return cheap
    // Copy values. We deliberately did not factor each field into a separate
    // atomic shadow: parking_lot's uncontended read is ~10ns, the getters
    // are not called in tight loops (the genuinely hot path,
    // `get_cipher`, was addressed separately with read-then-upgrade
    // locking — see M2.3), and dual storage between an atomic and the
    // canonical `DeviceState` would create a synchronization invariant
    // that's easy to forget on a setter. If a future profile shows one of
    // these is hot, the right move is to atomicize that single field.
    // ----------------------------------------------------------------

    #[must_use]
    pub fn dev_type(&self) -> DeviceType {
        self.with_state(|s| s.dev_type)
    }

    #[must_use]
    pub fn local_key(&self) -> &[u8] {
        &self.inner.local_key
    }

    #[must_use]
    pub fn address(&self) -> String {
        self.with_state(|s| {
            if s.real_ip.is_empty() {
                s.config_address.clone()
            } else {
                s.real_ip.clone()
            }
        })
    }

    /// Returns the user-configured address (e.g., "Auto" or a specific IP).
    #[must_use]
    pub fn config_address(&self) -> String {
        self.with_state(|s| s.config_address.clone())
    }

    #[must_use]
    pub fn version(&self) -> Version {
        self.with_state(|s| s.version)
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.with_state(|s| s.state == ConnectionState::Connected)
    }

    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.with_state(|s| s.state == ConnectionState::Stopped)
    }

    /// Returns the timeout duration for network operations and responses.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.with_state(|s| s.timeout)
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.with_state(|s| s.port)
    }

    #[must_use]
    pub fn persist(&self) -> bool {
        self.with_state(|s| s.persist)
    }

    /// Returns whether the device is in nowait mode.
    #[must_use]
    pub fn nowait(&self) -> bool {
        self.inner.nowait.load(Ordering::Relaxed)
    }
}

impl Device {
    pub fn set_persist(&self, persist: bool) {
        self.with_state_mut(|s| s.persist = persist);
    }

    pub fn set_timeout(&self, timeout: Duration) {
        self.with_state_mut(|s| s.timeout = timeout);
    }

    pub fn set_port(&self, port: u16) {
        self.with_state_mut(|s| s.port = port);
    }

    /// Sets whether requests should wait for a response from the device.
    /// If true, methods like `status()` and `set_value()` will return immediately after
    /// dispatching the command, without waiting for the network response.
    pub fn set_nowait(&self, nowait: bool) {
        self.inner.nowait.store(nowait, Ordering::Relaxed);
    }

    pub fn set_version<V: Into<Version>>(&self, version: V) {
        let ver = version.into();

        self.with_state_mut(|s| {
            s.version = ver;
            // If dev_type is Auto, we can either leave it as Auto (to allow future detection)
            // or initialize it to Default. Given the user's requirement that only Auto
            // allows switching, we should keep it as Auto if the user hasn't specified Default.
        });
    }

    pub fn set_dev_type<DT: Into<DeviceType>>(&self, dev_type: DT) {
        self.with_state_mut(|s| s.dev_type = dev_type.into());
    }

    pub fn set_address<A: Into<String>>(&self, address: A) {
        let addr = address.into();
        self.with_state_mut(|s| {
            s.config_address = addr;
            s.force_discovery = true; // Force discovery to update real_ip if needed
        });
    }
}

impl Device {
    /// Queries the device's current data points.
    ///
    /// # Note on request/response correlation
    ///
    /// The Tuya LAN protocol does not provide a reliable correlation token
    /// between an outbound request and its response — many firmwares echo
    /// `seqno=0` or a device-side counter unrelated to what was sent. The
    /// actor matches responses by command-id (+ optional CID), so an
    /// unsolicited `Status` push that arrives between subscribe-and-send may
    /// be returned as this call's response.
    ///
    /// This is by design (the protocol is asynchronous and fire-and-forget on
    /// the device side); callers that need strict correlation should
    /// serialize their own calls per `Device` handle, or use
    /// [`listener`](Self::listener) for asynchronous device-pushed events.
    pub async fn status(&self) -> Result<Option<String>> {
        self.request(CommandType::DpQuery, None, None).await
    }

    /// Sets multiple DP values at once.
    /// The `dps` argument should be a `serde_json::Value` object where keys are DP IDs.
    pub async fn set_dps(&self, dps: Value) -> Result<Option<String>> {
        self.request(CommandType::Control, Some(dps), None).await
    }

    /// Sets a single DP value by its ID.
    /// The `dp_id` can be provided as any type that can be converted to a String (e.g., u32, &str).
    /// The `value` can be any type that implements `Serialize` (e.g., bool, i32, String, `serde_json::Value`).
    pub async fn set_value<I: ToString, T: Serialize>(
        &self,
        dp_id: I,
        value: T,
    ) -> Result<Option<String>> {
        if let Ok(val) = serde_json::to_value(value) {
            self.set_dps(serde_json::json!({ dp_id.to_string(): val }))
                .await
        } else {
            Err(TuyaError::InvalidPayload)
        }
    }

    pub async fn sub_discover(&self) -> Result<Option<String>> {
        let data = serde_json::json!({
            "cids": [],
            keys::REQ_TYPE: "subdev_online_stat_query"
        });
        self.request(CommandType::LanExtStream, Some(data), None)
            .await
    }

    /// Waits for the next non-empty broadcast message from this device.
    ///
    /// Returns `Err(TuyaError::BroadcastLagged { skipped })` if the broadcast
    /// bus skipped messages because we fell behind by more than its capacity
    /// (currently 128). The skipped messages are permanently lost — the caller
    /// should re-query device state (e.g. via [`Self::status`]) or accept the
    /// gap. Previously this condition was silently swallowed and the next
    /// valid message was returned as if nothing had been missed, which made
    /// state-tracking consumers infer wrong values; rc.2 surfaces it.
    ///
    /// Returns `Err(TuyaError::Offline)` when the device is fully stopped and
    /// the broadcast channel is closed.
    pub async fn receive(&self) -> Result<TuyaMessage> {
        use tokio::sync::broadcast::error::RecvError;
        let mut rx = self.inner.broadcast_tx.subscribe();
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if !msg.payload.is_empty() {
                        return Ok(msg);
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    warn!(
                        "Device {} receive() lagged, skipped {} broadcast messages",
                        self.inner.id, skipped
                    );
                    return Err(TuyaError::BroadcastLagged { skipped });
                }
                Err(RecvError::Closed) => return Err(TuyaError::Offline),
            }
        }
    }

    #[must_use]
    pub fn sub(&self, cid: &str) -> SubDevice {
        SubDevice::new(self.clone(), cid)
    }

    /// Sends an arbitrary command and waits for the device's response.
    ///
    /// See [`status`](Self::status) for the same caveat about request/response
    /// correlation in the Tuya LAN protocol.
    pub async fn request(
        &self,
        command: CommandType,
        data: Option<Value>,
        cid: Option<String>,
    ) -> Result<Option<String>> {
        debug!("request: cmd={command:?}, data={data:?}");
        let resp = self
            .send_command_to_task(|resp_tx| DeviceCommand::Request {
                command,
                data,
                cid,
                resp_tx,
            })
            .await?;

        match resp {
            Some(msg) => {
                if let Some(s) = msg.payload_as_string() {
                    Ok(Some(s))
                } else {
                    Ok(Some(hex_encode(&msg.payload)))
                }
            }
            None => Ok(None),
        }
    }
}

impl Device {
    pub async fn close(&self) {
        self.fire_close();
    }

    pub async fn stop(&self) {
        self.fire_stop();
    }

    /// Synchronous variant of [`close`] — both Notify and the state lock are
    /// synchronously usable, so the `async` flavor is just a thin wrapper.
    pub fn fire_close(&self) {
        info!("Closing connection to device {}", self.inner.id);

        self.with_state_mut(|state| {
            if state.state != ConnectionState::Stopped {
                state.state = ConnectionState::Disconnected;
            }
        });

        // Signal the actor via the dedicated close channel. Going through the
        // user-command mpsc would queue the disconnect behind any pending
        // request; the Notify path interrupts the actor's `select!` directly.
        self.inner.close_notify.notify_waiters();
    }

    /// Synchronous variant of [`stop`].
    pub fn fire_stop(&self) {
        info!("Stopping device {} (explicit stop called)", self.inner.id);
        self.with_state_mut(|state| {
            state.state = ConnectionState::Stopped;
        });
        // Notify close FIRST so the actor drops its current connection
        // promptly, THEN cancel the token so the outer loop exits. Ordering
        // matters: if we cancelled first, the `select!` would race against
        // mid-flight reconnect logic.
        self.inner.close_notify.notify_waiters();
        self.inner.cancel_token.cancel();
    }

    /// Forces the device to attempt a connection immediately, bypassing any backoff.
    pub async fn connect_now(&self) {
        self.send_to_task(DeviceCommand::ConnectNow).await;
    }
}
