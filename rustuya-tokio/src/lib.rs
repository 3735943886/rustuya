//! `rustuya-tokio` — a tokio **driver** for the sans-I/O [`rustuya_core`] Tuya
//! protocol FSM.
//!
//! The driver owns only I/O: TCP sockets, one `sleep` timer per device, the RNG,
//! and the monotonic clock. Every protocol and lifecycle *decision* — the
//! v3.4/v3.5 handshake, reconnect/backoff, heartbeat keepalive, idle-liveness,
//! and frame reassembly — lives in the pure core FSM ([`rustuya_core::device`]).
//! One background task per [`Device`] runs the loop; the handle is cheap to clone
//! and talks to the task over channels.
//!
//! ```no_run
//! # async fn ex() -> rustuya_tokio::Result<()> {
//! use rustuya_tokio::{Device, Version};
//!
//! let dev = Device::builder("device_id_22chars0000", "0123456789abcdef")
//!     .address("192.168.1.50")
//!     .version(Version::V3_4)
//!     .connect()?;
//!
//! let state = dev.status().await?;      // query DPs
//! dev.set_value(1, true).await?;        // flip DP 1
//!
//! let mut events = dev.listener();      // lossless push stream
//! let push = events.recv().await?;
//! # Ok(()) }
//! ```
//!
//! ## Request / response correlation
//!
//! The Tuya LAN protocol carries **no** request/response token — devices echo
//! `seqno = 0` or a device-side counter unrelated to the request. Responses are
//! therefore matched to pending [`request`](Device::request)s in FIFO order, so an
//! unsolicited push arriving mid-request may be returned as that call's response.
//! This is inherent to the protocol (fire-and-forget on the device side); for
//! lossless push consumption use [`listener`](Device::listener).

mod actor;
mod discovery;
mod error;

use std::time::Duration as StdDuration;

use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt as _};

use rustuya_core::device::{Backoff, Config as CoreConfig};
use rustuya_core::time::Duration as CoreDuration;

use actor::{ActorConfig, Cmd};

pub use discovery::{DeviceInfo, Discovered, Discovery, DiscoveryBuilder};
pub use error::{Result, TuyaError};
pub use rustuya_core::json::Value;
pub use rustuya_core::message::Message;
pub use rustuya_core::{CommandType, CoreError, DeviceType, Version};

/// Milliseconds → core `Duration` (the core has no `std::time`).
fn core_dur(d: StdDuration) -> CoreDuration {
    CoreDuration::from_millis(d.as_millis() as u64)
}

/// Parse a response payload into JSON; an empty payload (a bare ack) is `Null`.
fn payload_to_value(msg: &Message) -> Result<Value> {
    if msg.payload.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&msg.payload).map_err(|_| TuyaError::NotJson)
}

/// Builder for a [`Device`]. Every knob has a sane default; only `address` is
/// required before [`connect`](DeviceBuilder::connect).
pub struct DeviceBuilder {
    id: String,
    local_key: Vec<u8>,
    address: Option<String>,
    port: u16,
    version: Version,
    dev_type: DeviceType,
    auto_reconnect: bool,
    backoff_base: StdDuration,
    backoff_max: StdDuration,
    backoff_jitter: StdDuration,
    heartbeat: Option<StdDuration>,
    idle_timeout: Option<StdDuration>,
    handshake_timeout: Option<StdDuration>,
    connect_timeout: StdDuration,
    request_timeout: StdDuration,
    command_capacity: usize,
    listener_capacity: usize,
    rediscover: Option<Discovery>,
}

impl DeviceBuilder {
    /// Start a builder for a device with the given 22-char id and 16-byte local
    /// key. Defaults: v3.3, auto-reconnect on, 10 s heartbeat, 30 s idle-liveness,
    /// 5 s handshake / connect / request timeouts, port 6668.
    #[must_use]
    pub fn new(id: impl Into<String>, local_key: impl Into<Vec<u8>>) -> Self {
        Self {
            id: id.into(),
            local_key: local_key.into(),
            address: None,
            port: 6668,
            version: Version::V3_3,
            dev_type: DeviceType::Auto,
            auto_reconnect: true,
            backoff_base: StdDuration::from_secs(1),
            backoff_max: StdDuration::from_secs(60),
            backoff_jitter: StdDuration::from_secs(1),
            heartbeat: Some(StdDuration::from_secs(10)),
            idle_timeout: Some(StdDuration::from_secs(30)),
            handshake_timeout: Some(StdDuration::from_secs(5)),
            connect_timeout: StdDuration::from_secs(5),
            request_timeout: StdDuration::from_secs(5),
            command_capacity: 64,
            listener_capacity: 128,
            rediscover: None,
        }
    }

    /// Device IP or hostname (required).
    #[must_use]
    pub fn address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    /// TCP port (default 6668).
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Protocol version (default [`Version::V3_3`]).
    #[must_use]
    pub fn version(mut self, version: impl Into<Version>) -> Self {
        self.version = version.into();
        self
    }

    /// Device dialect (default [`DeviceType::Auto`]).
    #[must_use]
    pub fn dev_type(mut self, dev_type: impl Into<DeviceType>) -> Self {
        self.dev_type = dev_type.into();
        self
    }

    /// Whether a dropped/failed connection re-arms backoff (`true`, default) or
    /// drops to a terminal closed state (`false`). Unifies the 0.3 persist/nowait
    /// split into one knob.
    #[must_use]
    pub fn auto_reconnect(mut self, on: bool) -> Self {
        self.auto_reconnect = on;
        self
    }

    /// Reconnect backoff curve: `min(base·2ⁿ, max)` plus `[0, jitter)`.
    #[must_use]
    pub fn backoff(mut self, base: StdDuration, max: StdDuration, jitter: StdDuration) -> Self {
        self.backoff_base = base;
        self.backoff_max = max;
        self.backoff_jitter = jitter;
        self
    }

    /// Keepalive interval, or `None` to disable heartbeats.
    #[must_use]
    pub fn heartbeat(mut self, interval: Option<StdDuration>) -> Self {
        self.heartbeat = interval;
        self
    }

    /// Silence-before-dead window, or `None` to disable idle-liveness.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Option<StdDuration>) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Handshake completion deadline (v3.4/v3.5), or `None` to disable it.
    #[must_use]
    pub fn handshake_timeout(mut self, timeout: Option<StdDuration>) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// TCP connect timeout (default 5 s).
    #[must_use]
    pub fn connect_timeout(mut self, timeout: StdDuration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// How long [`request`](Device::request) waits for a response (default 5 s).
    #[must_use]
    pub fn request_timeout(mut self, timeout: StdDuration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Link a [`Discovery`] so a live re-announcement of this device **cancels a
    /// pending reconnect backoff and redials immediately** (the core's
    /// `DiscoveryUpdated`, SMELLS P3). Independent of [`address`](Self::address):
    /// use it with a fixed address to cut reconnect latency when the device
    /// reappears, instead of waiting out the backoff. [`discover`](Self::discover)
    /// links this automatically.
    #[must_use]
    pub fn rediscover(mut self, disco: &Discovery) -> Self {
        self.rediscover = Some(disco.clone());
        self
    }

    /// Spawn the device actor and return a handle. Fails if `address` is unset or
    /// the local key is not 16 bytes.
    pub fn connect(self) -> Result<Device> {
        let address = self.address.ok_or(TuyaError::Config("address is required"))?;
        let local_key: [u8; 16] = self
            .local_key
            .as_slice()
            .try_into()
            .map_err(|_| TuyaError::Config("local key must be 16 bytes"))?;

        let core = CoreConfig {
            version: self.version,
            dev_type: self.dev_type,
            device_id: self.id.clone(),
            local_key,
            auto_reconnect: self.auto_reconnect,
            backoff: Backoff {
                base: core_dur(self.backoff_base),
                max: core_dur(self.backoff_max),
                jitter: core_dur(self.backoff_jitter),
            },
            heartbeat: self.heartbeat.map(core_dur),
            idle_timeout: self.idle_timeout.map(core_dur),
            handshake_timeout: self.handshake_timeout.map(core_dur),
        };

        let acfg = ActorConfig {
            core,
            addr: format!("{address}:{}", self.port),
            connect_timeout: self.connect_timeout,
        };

        let (cmd_tx, cmd_rx) = mpsc::channel(self.command_capacity);
        let (bcast_tx, _) = broadcast::channel(self.listener_capacity);
        let (conn_tx, conn_rx) = watch::channel(false);

        // If a discovery is linked, forward its re-announcements of this device to
        // the actor as `Cmd::ConnectNow` — the same signal `connect_now()` sends
        // (backoff cancellation, P3).
        if let Some(disco) = self.rediscover.as_ref() {
            spawn_rediscovery_forwarder(disco.clone(), self.id.clone(), cmd_tx.clone());
        }

        let bcast_for_actor = bcast_tx.clone();
        tokio::spawn(actor::run(acfg, cmd_rx, bcast_for_actor, conn_tx));

        Ok(Device {
            id: self.id,
            cmd_tx,
            bcast_tx,
            conn_rx,
            request_timeout: self.request_timeout,
        })
    }

    /// Resolve the device's address (and version) by LAN discovery, then connect —
    /// the addressless path. Waits up to `timeout` for `disco` to see this device
    /// id announce itself, fills in the reported IP and (if present) version, and
    /// calls [`connect`](Self::connect). Any explicitly-set `address`/`version` is
    /// overridden by what discovery reports; a `port` you set is kept (the device
    /// still connects on its TCP port, not the discovery port).
    ///
    /// *Resolve-once for the address:* this fixes the IP at connect time. It also
    /// **links the discovery for live rewake** (unless you already linked one via
    /// [`rediscover`](Self::rediscover)), so a later re-announcement cancels
    /// backoff and redials — see [`rediscover`](Self::rediscover).
    pub async fn discover(mut self, disco: &Discovery, timeout: StdDuration) -> Result<Device> {
        let info = disco.find(&self.id, timeout).await?;
        self.address = Some(info.ip.to_string());
        if let Some(v) = info.version {
            self.version = v;
        }
        self.rediscover.get_or_insert_with(|| disco.clone());
        self.connect()
    }
}

/// Subscribe to `disco`'s announcement bus and send the actor a `Cmd::ConnectNow`
/// on each re-announcement of `device_id`. Runs until the discovery bus closes or
/// the actor drops its receiver.
fn spawn_rediscovery_forwarder(disco: Discovery, device_id: String, cmd_tx: mpsc::Sender<Cmd>) {
    tokio::spawn(async move {
        let mut stream = disco.discovered();
        loop {
            match stream.recv().await {
                Ok(info) => {
                    if info.id == device_id && cmd_tx.send(Cmd::ConnectNow).await.is_err() {
                        break; // actor gone
                    }
                }
                Err(_) => break, // discovery closed
            }
        }
    });
}

/// A handle to one device's driver task. Cheap to clone; all clones share the one
/// underlying connection.
#[derive(Clone, Debug)]
pub struct Device {
    id: String,
    cmd_tx: mpsc::Sender<Cmd>,
    bcast_tx: broadcast::Sender<Message>,
    conn_rx: watch::Receiver<bool>,
    request_timeout: StdDuration,
}

impl Device {
    /// Start a [`DeviceBuilder`].
    #[must_use]
    pub fn builder(id: impl Into<String>, local_key: impl Into<Vec<u8>>) -> DeviceBuilder {
        DeviceBuilder::new(id, local_key)
    }

    /// The device id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether the connection is currently up and past any handshake.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        *self.conn_rx.borrow()
    }

    /// Wait until the connection is up, or `dur` elapses.
    pub async fn wait_connected(&self, dur: StdDuration) -> Result<()> {
        let mut rx = self.conn_rx.clone();
        let wait = async {
            loop {
                if *rx.borrow() {
                    return Ok(());
                }
                if rx.changed().await.is_err() {
                    return Err(TuyaError::Closed);
                }
            }
        };
        match tokio::time::timeout(dur, wait).await {
            Ok(r) => r,
            Err(_) => Err(TuyaError::Timeout),
        }
    }

    /// Query the device's current data points.
    pub async fn status(&self) -> Result<Value> {
        self.request(CommandType::DpQuery, None).await
    }

    /// Set multiple DPs at once (`dps` is a JSON object keyed by DP id).
    pub async fn set_dps(&self, dps: Value) -> Result<Value> {
        self.request(CommandType::Control, Some(dps)).await
    }

    /// Set one DP by id.
    pub async fn set_value<I, T>(&self, dp_id: I, value: T) -> Result<Value>
    where
        I: ToString,
        T: serde::Serialize,
    {
        let val = serde_json::to_value(value).map_err(|_| TuyaError::NotJson)?;
        let mut obj = serde_json::Map::new();
        obj.insert(dp_id.to_string(), val);
        self.set_dps(Value::Object(obj)).await
    }

    /// Send an arbitrary command and return the next response's payload as JSON.
    /// See the crate docs for the fire-and-forget correlation caveat.
    pub async fn request(&self, cmd: CommandType, data: Option<Value>) -> Result<Value> {
        let msg = self.request_message(cmd, data).await?;
        payload_to_value(&msg)
    }

    /// Like [`request`](Self::request) but returns the raw decoded [`Message`]
    /// (seqno / cmd / retcode / payload).
    pub async fn request_message(
        &self,
        cmd: CommandType,
        data: Option<Value>,
    ) -> Result<Message> {
        self.send_request(cmd, data, None).await
    }

    /// Address a gateway **sub-device** by its channel id (`cid`). The returned
    /// handle routes its `status`/`set_*`/`request` through this device but stamps
    /// the sub-device into the request envelope.
    #[must_use]
    pub fn sub(&self, cid: impl Into<String>) -> SubDevice {
        SubDevice {
            dev: self.clone(),
            cid: cid.into(),
        }
    }

    /// The one place a request is submitted to the actor. `cid` (if any) is
    /// forwarded into the core envelope; correlation and timeout are identical for
    /// device and sub-device traffic.
    async fn send_request(
        &self,
        cmd: CommandType,
        data: Option<Value>,
        cid: Option<String>,
    ) -> Result<Message> {
        // Wait for the connection first so a just-spawned device doesn't fail
        // fast with NotConnected while it is still dialing/handshaking.
        self.wait_connected(self.request_timeout).await?;

        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Request { cmd, data, cid, resp: resp_tx })
            .await
            .map_err(|_| TuyaError::Closed)?;

        match tokio::time::timeout(self.request_timeout, resp_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(TuyaError::Closed), // actor dropped the sender
            Err(_) => Err(TuyaError::Timeout),
        }
    }

    /// A lossless stream of device pushes and responses. Subscribes once and stays
    /// subscribed; prefer this over polling for asynchronous device events.
    #[must_use]
    pub fn listener(&self) -> Listener {
        Listener {
            stream: BroadcastStream::new(self.bcast_tx.subscribe()),
        }
    }

    /// Force an immediate (re)connection attempt: cancel any pending reconnect
    /// backoff and revive a device that has stopped reconnecting
    /// ([`auto_reconnect(false)`](DeviceBuilder::auto_reconnect)). A no-op while
    /// already connected/connecting. Returns once queued; pair with
    /// [`wait_connected`](Self::wait_connected) to await the outcome.
    pub async fn connect_now(&self) {
        let _ = self.cmd_tx.send(Cmd::ConnectNow).await;
    }

    /// Gracefully stop the driver task. Idempotent; further requests error with
    /// [`TuyaError::Closed`].
    pub async fn close(&self) {
        let _ = self.cmd_tx.send(Cmd::Close).await;
    }
}

/// A handle addressing one gateway sub-device by its channel id. Created by
/// [`Device::sub`]; shares the parent device's single connection.
#[derive(Clone, Debug)]
pub struct SubDevice {
    dev: Device,
    cid: String,
}

impl SubDevice {
    /// The sub-device channel id.
    #[must_use]
    pub fn cid(&self) -> &str {
        &self.cid
    }

    /// Query this sub-device's data points.
    pub async fn status(&self) -> Result<Value> {
        self.request(CommandType::DpQuery, None).await
    }

    /// Set multiple DPs on this sub-device.
    pub async fn set_dps(&self, dps: Value) -> Result<Value> {
        self.request(CommandType::Control, Some(dps)).await
    }

    /// Set one DP on this sub-device.
    pub async fn set_value<I, T>(&self, dp_id: I, value: T) -> Result<Value>
    where
        I: ToString,
        T: serde::Serialize,
    {
        let val = serde_json::to_value(value).map_err(|_| TuyaError::NotJson)?;
        let mut obj = serde_json::Map::new();
        obj.insert(dp_id.to_string(), val);
        self.set_dps(Value::Object(obj)).await
    }

    /// Send an arbitrary command to this sub-device, returning the response JSON.
    pub async fn request(&self, cmd: CommandType, data: Option<Value>) -> Result<Value> {
        let msg = self
            .dev
            .send_request(cmd, data, Some(self.cid.clone()))
            .await?;
        payload_to_value(&msg)
    }
}

/// A subscription to a device's event bus (pushes + responses). Created by
/// [`Device::listener`].
///
/// Implements [`Stream`](futures_core::Stream) with `Item = Message`, so it drives
/// the README idiom `while let Some(msg) = listener.next().await`, and also offers
/// an explicit [`recv`](Self::recv). Bus-lag gaps are skipped in both.
pub struct Listener {
    stream: BroadcastStream<Message>,
}

impl Listener {
    /// Await the next event. Skips over bus-lag gaps (returns the next live
    /// message); errors with [`TuyaError::Closed`] once the device stops.
    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            match self.stream.next().await {
                Some(Ok(msg)) => return Ok(msg),
                Some(Err(BroadcastStreamRecvError::Lagged(skipped))) => {
                    log::warn!("listener lagged, skipped {skipped} messages");
                }
                None => return Err(TuyaError::Closed),
            }
        }
    }
}

impl Stream for Listener {
    type Item = Message;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Message>> {
        use std::task::Poll;
        loop {
            match std::pin::Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => return Poll::Ready(Some(msg)),
                // A lag gap: the messages are gone; skip and poll again rather than
                // surfacing an error in the stream item.
                Poll::Ready(Some(Err(_lagged))) => continue,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
