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
//! use rustuya_tokio::{Device, Event, Version};
//!
//! let dev = Device::builder("device_id_22chars0000", "0123456789abcdef")
//!     .address("192.168.1.50")
//!     .version(Version::V3_4)
//!     .connect()?;
//!
//! let mut events = dev.listener();       // subscribe first
//! dev.query().await?;                    // fire a status query
//! dev.set_value(1, true).await?;         // flip DP 1
//!
//! // Replies and pushes arrive here; a slow-consumer gap is Event::Lagged, not silent.
//! if let Some(Event::Frame(msg)) = events.recv().await {
//!     println!("{msg:?}");
//! }
//! # Ok(()) }
//! ```
//!
//! ## Fire-and-forget; responses via `listener` / `watch_status`
//!
//! Every command method — [`query`](Device::query), [`set_dps`](Device::set_dps),
//! [`set_value`](Device::set_value), [`send`](Device::send) — is **fire-and-forget**:
//! it returns once the frame is queued and never waits for a reply. This mirrors the
//! Tuya LAN protocol, which carries **no** request/response token: a device's status
//! frames and its unsolicited pushes are indistinguishable and arrive asynchronously.
//!
//! Read them one of two ways, by audience: [`listener`](Device::listener) is the
//! **event stream** (every frame, in order; a slow-consumer gap surfaces as
//! [`Event::Lagged`], never silently) — subscribe *before* you fire. For **many
//! devices on one loop**, fan them into a [`MultiListener`]. If you only want the
//! **current value** and don't care to keep up, read [`watch_status`](Device::watch_status)
//! — state, not events, so it never lags.

mod actor;
mod discovery;
mod error;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, watch};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::{Stream, StreamExt as _, StreamMap};

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

/// A shared cap on how many devices may be **establishing** a connection at the
/// same instant — a connect-storm guard for fleet-scale drivers.
///
/// When a large fleet comes online, or reconnects en masse after a network blip,
/// every device actor would otherwise begin its (round-trip- and CPU-heavy)
/// dial + v3.4/v3.5 handshake at once. Backoff jitter spreads the *start* of
/// each attempt but, because connections are persistent, does not bound the peak
/// number of concurrent in-flight handshakes. This does.
///
/// Create one and hand it to every device via
/// [`connect_limiter`](DeviceBuilder::connect_limiter) — the same shared-object
/// pattern as [`Discovery`]. There is **no cap by default** and no process
/// global (DESIGN Q1): a device with no limiter dials freely, which is the right
/// default for the one- and few-device cases.
///
/// A permit is held only across
/// [`is_establishing`](rustuya_core::device::Device::is_establishing) — released
/// the instant the handshake finishes or the attempt fails, never for the
/// connection's lifetime. Holding it longer would deadlock any fleet larger than
/// `limit`, with the surplus devices never able to connect.
///
/// ```no_run
/// # fn ex() -> rustuya_tokio::Result<()> {
/// use rustuya_tokio::{ConnectLimiter, Device};
///
/// let limiter = ConnectLimiter::new(128);
/// for (id, key, ip) in [("device_id_22chars0000", "0123456789abcdef", "192.168.1.50")] {
///     Device::builder(id, key)
///         .address(ip)
///         .connect_limiter(&limiter)
///         .connect()?;
/// }
/// # Ok(()) }
/// ```
#[derive(Clone, Debug)]
pub struct ConnectLimiter {
    sem: Arc<Semaphore>,
    limit: usize,
}

impl ConnectLimiter {
    /// A limiter allowing `limit` simultaneous connection establishments.
    /// `limit` is clamped to at least 1 — a cap of zero would never let any
    /// device connect.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        let limit = limit.max(1);
        Self {
            sem: Arc::new(Semaphore::new(limit)),
            limit,
        }
    }

    /// The configured cap.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Permits not currently held — i.e. how many more devices could start
    /// establishing right now. `limit() - available()` is the number of dials
    /// and handshakes in flight, which is what a fleet operator wants to graph.
    #[must_use]
    pub fn available(&self) -> usize {
        self.sem.available_permits()
    }

    /// Wait for an establishment permit. Never errors: the semaphore is owned by
    /// this handle (and its clones) and is never closed.
    pub(crate) async fn acquire(&self) -> OwnedSemaphorePermit {
        Arc::clone(&self.sem)
            .acquire_owned()
            .await
            .expect("connect semaphore is never closed")
    }
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
    send_timeout: StdDuration,
    command_capacity: usize,
    listener_capacity: usize,
    rediscover: Option<Discovery>,
    connect_limiter: Option<ConnectLimiter>,
}

impl DeviceBuilder {
    /// Start a builder for a device with the given 22-char id and 16-byte local
    /// key. Defaults: v3.3, auto-reconnect on, 10 s heartbeat, 30 s idle-liveness,
    /// 5 s handshake / connect / send timeouts, port 6668.
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
            // Keepalive as a max-outbound-silence bound (deferred by any real
            // command — see the core `Config::heartbeat`). 10 s ≈ one third of the
            // ~30 s idle-drop typical firmware enforces, so up to three keepalives
            // cover the window before the device would close us; tune via
            // `heartbeat()`.
            heartbeat: Some(StdDuration::from_secs(10)),
            idle_timeout: Some(StdDuration::from_secs(30)),
            handshake_timeout: Some(StdDuration::from_secs(5)),
            connect_timeout: StdDuration::from_secs(5),
            send_timeout: StdDuration::from_secs(5),
            // Channel depths, both tunable via the builder. `command_capacity`
            // bounds in-flight fires before `.await` backpressure; `listener_capacity`
            // is the broadcast-ring depth a slow listener may lag before losing the
            // oldest frames. The listener ring is preallocated per device, so the
            // default stays modest for fleet scale (see the setters).
            command_capacity: 64,
            listener_capacity: 128,
            rediscover: None,
            connect_limiter: None,
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

    /// How long a fire-and-forget command waits for the connection to come up
    /// before giving up (default 5 s). Applies to [`query`](Device::query),
    /// [`set_dps`](Device::set_dps), [`set_value`](Device::set_value), and
    /// [`send`](Device::send).
    #[must_use]
    pub fn send_timeout(mut self, timeout: StdDuration) -> Self {
        self.send_timeout = timeout;
        self
    }

    /// Outbound command queue depth (default 64) — how many
    /// [`query`](Device::query) / [`set_dps`](Device::set_dps) /
    /// [`set_value`](Device::set_value) / [`send`](Device::send) calls may be
    /// in flight to the driver task before `.await` applies backpressure. A bounded
    /// mpsc that grows in blocks, so a larger value costs little until actually
    /// used; raise it for a bursty producer.
    #[must_use]
    pub fn command_capacity(mut self, capacity: usize) -> Self {
        self.command_capacity = capacity;
        self
    }

    /// Listener bus depth (default 128) — how far a [`listener`](Device::listener)
    /// consumer may fall behind before it starts losing the oldest frames (surfaced
    /// as a `Lagged` skip). Every command reply and device push fans out here, so
    /// size it to the largest reply/push burst a consumer might briefly lag behind.
    ///
    /// This is a [`tokio::sync::broadcast`] ring **preallocated at connect time**:
    /// `capacity` message slots are reserved per device whether or not a listener is
    /// ever attached. At fleet scale (thousands of devices) that fixed cost is why
    /// the default is kept modest.
    #[must_use]
    pub fn listener_capacity(mut self, capacity: usize) -> Self {
        self.listener_capacity = capacity;
        self
    }

    /// Link a [`Discovery`] so a live re-announcement of this device **cancels a
    /// pending reconnect backoff and redials immediately** (the core's
    /// `ConnectNow`, DESIGN P3). Independent of [`address`](Self::address):
    /// use it with a fixed address to cut reconnect latency when the device
    /// reappears, instead of waiting out the backoff. [`discover`](Self::discover)
    /// links this automatically.
    #[must_use]
    pub fn rediscover(mut self, disco: &Discovery) -> Self {
        self.rediscover = Some(disco.clone());
        self
    }

    /// Share a [`ConnectLimiter`] so this device's dial + handshake counts
    /// against a fleet-wide establishment cap (the connect-storm guard). Without
    /// one the device dials freely — there is no cap by default.
    #[must_use]
    pub fn connect_limiter(mut self, limiter: &ConnectLimiter) -> Self {
        self.connect_limiter = Some(limiter.clone());
        self
    }

    /// Spawn the device actor and return a handle. Fails if `address` is unset or
    /// the local key is not 16 bytes.
    pub fn connect(self) -> Result<Device> {
        let address = self
            .address
            .ok_or(TuyaError::Config("address is required"))?;
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

        let (cmd_tx, cmd_rx) = mpsc::channel(self.command_capacity);
        let (bcast_tx, _) = broadcast::channel(self.listener_capacity);
        // Current-status latch: last-value-wins state feeding `watch_status()`,
        // kept separate from the lossy event bus above so a slow consumer can read
        // the latest value without ever lagging.
        let (status_tx, status_rx) = watch::channel(None);
        let (conn_tx, conn_rx) = watch::channel(false);
        // Carries the last authentication failure (wrong key / version) so a
        // connect attempt reports *why* rather than only timing out.
        let (autherr_tx, autherr_rx) = watch::channel(None);

        // If a discovery is linked, register this device's actor so the discovery
        // loop wakes it directly (O(1)) on a re-announcement — carrying the fresh
        // address on a change (IP self-corrects) or a bare `ConnectNow` on an
        // unchanged sighting (same-IP reconnect, backoff cancellation, P3). No
        // per-device forwarder task, no broadcast subscription for the fast path.
        // The actor also gets the demand sender so a failed dial re-elicits a probe.
        let want_scan = self.rediscover.as_ref().map(|disco| {
            disco.register(self.id.clone(), cmd_tx.clone(), self.port);
            disco.want_sender()
        });

        let acfg = ActorConfig {
            core,
            addr: format!("{address}:{}", self.port),
            connect_timeout: self.connect_timeout,
            want_scan,
            connect_limiter: self.connect_limiter,
        };

        let bcast_for_actor = bcast_tx.clone();
        tokio::spawn(actor::run(
            acfg,
            cmd_rx,
            bcast_for_actor,
            status_tx,
            conn_tx,
            autherr_tx,
        ));

        Ok(Device {
            id: self.id,
            cmd_tx,
            bcast_tx,
            status_rx,
            conn_rx,
            autherr_rx,
            send_timeout: self.send_timeout,
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

/// A handle to one device's driver task. Cheap to clone; all clones share the one
/// underlying connection.
#[derive(Clone, Debug)]
pub struct Device {
    id: String,
    cmd_tx: mpsc::Sender<Cmd>,
    bcast_tx: broadcast::Sender<Message>,
    status_rx: watch::Receiver<Option<Message>>,
    conn_rx: watch::Receiver<bool>,
    autherr_rx: watch::Receiver<Option<CoreError>>,
    send_timeout: StdDuration,
}

impl Device {
    /// Start configuring a device with the given 22-char id and 16-byte local key
    /// — the entry point. Returns a [`DeviceBuilder`]: set an
    /// [`address`](DeviceBuilder::address) (or resolve one via
    /// [`discover`](DeviceBuilder::discover)) and any other knobs, then
    /// [`connect`](DeviceBuilder::connect).
    ///
    /// ```no_run
    /// # async fn ex() -> rustuya_tokio::Result<()> {
    /// use rustuya_tokio::{Device, Version};
    /// let dev = Device::builder("device_id_22chars0000", "0123456789abcdef")
    ///     .address("192.168.1.50")
    ///     .version(Version::V3_4)
    ///     .connect()?;
    /// # let _ = dev; Ok(()) }
    /// ```
    ///
    /// This is a **builder** entry, not a `Device::new` returning a `Device`: a
    /// device only exists once connected, and connecting is fallible, so there is
    /// no infallible `Self` to hand back before the address is known. Unlike 0.3,
    /// there is also **no** hidden global scanner behind an "auto" address
    /// (DESIGN Q1): resolving an address without a fixed IP is explicit — pass a
    /// shared [`Discovery`] to [`discover`](DeviceBuilder::discover).
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

    /// A [`watch`](tokio::sync::watch) of the connection state — `true` once the
    /// link is up and past any handshake, `false` while it is down.
    ///
    /// [`is_connected`](Self::is_connected) answers "right now" and
    /// [`wait_connected`](Self::wait_connected) answers "tell me when it's up";
    /// this is for a consumer that must react to **every transition in both
    /// directions** (publishing an online/offline event, say) without polling.
    /// Await [`changed`](watch::Receiver::changed) and read
    /// [`borrow`](watch::Receiver::borrow). Like any `watch` it is
    /// last-value-wins: a connect/disconnect pair faster than the consumer wakes
    /// collapses to no observed change, so treat it as *state*, not a count.
    #[must_use]
    pub fn watch_connected(&self) -> watch::Receiver<bool> {
        self.conn_rx.clone()
    }

    /// A [`watch`](tokio::sync::watch) of the last **authentication** failure —
    /// a payload that didn't authenticate, which in practice means a wrong local
    /// key or protocol version. `None` while the connection is healthy (a
    /// successful connect clears it).
    ///
    /// This is the diagnostic [`wait_connected`](Self::wait_connected) reports
    /// instead of a bare [`Timeout`](TuyaError::Timeout); exposed separately so a
    /// supervisor can surface *why* a device won't come up without having to
    /// call `wait_connected` on it. Only auth failures land here — routine
    /// transport errors are not failures worth escalating and stay in the
    /// driver's `debug` log.
    #[must_use]
    pub fn watch_error(&self) -> watch::Receiver<Option<CoreError>> {
        self.autherr_rx.clone()
    }

    /// Wait until the connection is up, or `dur` elapses.
    ///
    /// If the connection can't come up because the device rejects our
    /// authentication — a wrong local key or protocol version — this returns that
    /// [`CoreError`] (via [`TuyaError::Core`]) rather than waiting out the whole
    /// `dur` for a bare [`Timeout`](TuyaError::Timeout). That is the common
    /// misconfiguration, so naming it is worth more than a generic timeout.
    pub async fn wait_connected(&self, dur: StdDuration) -> Result<()> {
        let mut conn = self.conn_rx.clone();
        let mut err = self.autherr_rx.clone();
        let wait = async {
            loop {
                if *conn.borrow() {
                    return Ok(());
                }
                if let Some(e) = err.borrow().clone() {
                    return Err(TuyaError::Core(e));
                }
                // Wake on either a connection-state change or a new auth failure.
                tokio::select! {
                    r = conn.changed() => if r.is_err() { return Err(TuyaError::Closed); },
                    r = err.changed() => if r.is_err() { return Err(TuyaError::Closed); },
                }
            }
        };
        match tokio::time::timeout(dur, wait).await {
            Ok(r) => r,
            Err(_) => Err(TuyaError::Timeout),
        }
    }

    /// Fire a status query (`DpQuery`). Fire-and-forget: returns once the frame is
    /// queued; the device's reply arrives on [`listener`](Self::listener), not here.
    pub async fn query(&self) -> Result<()> {
        self.send(CommandType::DpQuery, None).await
    }

    /// Set multiple DPs at once (`dps` is a JSON object keyed by DP id).
    /// Fire-and-forget; any device acknowledgement arrives on
    /// [`listener`](Self::listener).
    pub async fn set_dps(&self, dps: Value) -> Result<()> {
        self.send(CommandType::Control, Some(dps)).await
    }

    /// Set one DP by id. Fire-and-forget (see [`set_dps`](Self::set_dps)).
    pub async fn set_value<I, T>(&self, dp_id: I, value: T) -> Result<()>
    where
        I: ToString,
        T: serde::Serialize,
    {
        let val = serde_json::to_value(value).map_err(|_| TuyaError::NotJson)?;
        let mut obj = serde_json::Map::new();
        obj.insert(dp_id.to_string(), val);
        self.set_dps(Value::Object(obj)).await
    }

    /// Fire an arbitrary command at the device. Fire-and-forget: returns once the
    /// frame is queued and never waits for a reply — the response, if any, is fanned
    /// out to [`listener`](Self::listener). See the crate docs.
    pub async fn send(&self, cmd: CommandType, data: Option<Value>) -> Result<()> {
        self.fire(cmd, data, None).await
    }

    /// Ask a **gateway** to report its sub-devices' online status (the Tuya
    /// `subdev_online_stat_query`). Fire-and-forget like every other command: the
    /// gateway's reply — the sub-device list — arrives on [`listener`](Self::listener)
    /// as a `LanExtStream` frame, not as a return value. Address each reported channel
    /// id with [`sub`](Self::sub).
    pub async fn sub_discover(&self) -> Result<()> {
        self.send(
            CommandType::LanExtStream,
            Some(serde_json::json!({ "reqType": "subdev_online_stat_query", "cids": [] })),
        )
        .await
    }

    /// Address a gateway **sub-device** by its channel id (`cid`). The returned
    /// handle routes its `query`/`set_*`/`send` through this device but stamps
    /// the sub-device into the command envelope.
    #[must_use]
    pub fn sub(&self, cid: impl Into<String>) -> SubDevice {
        SubDevice {
            dev: self.clone(),
            cid: cid.into(),
        }
    }

    /// The one place a command is submitted to the actor. `cid` (if any) is
    /// forwarded into the core envelope. Fire-and-forget: waits for the connection
    /// (so a just-spawned device doesn't fail fast while dialing/handshaking), then
    /// queues the frame and returns — the reply, if any, is fanned out to
    /// [`listener`](Self::listener).
    async fn fire(&self, cmd: CommandType, data: Option<Value>, cid: Option<String>) -> Result<()> {
        // Wait for the connection first so a just-spawned device doesn't fail
        // fast while it is still dialing/handshaking. A wrong key/version surfaces
        // here as the real auth error rather than a bare timeout.
        self.wait_connected(self.send_timeout).await?;

        self.cmd_tx
            .send(Cmd::Fire { cmd, data, cid })
            .await
            .map_err(|_| TuyaError::Closed)
    }

    /// A stream of device frames (pushes and query replies) as [`Event`]s. Subscribes
    /// once and stays subscribed; prefer this over polling for asynchronous events.
    /// Under a slow consumer the bus is lossy, but the loss is **observable** — a gap
    /// arrives as [`Event::Lagged`], not a silent skip. For "current state without
    /// keeping up", read [`watch_status`](Self::watch_status) instead.
    #[must_use]
    pub fn listener(&self) -> Listener {
        Listener {
            stream: BroadcastStream::new(self.bcast_tx.subscribe()),
        }
    }

    /// A [`watch`](tokio::sync::watch) of the device's current status frame — the
    /// last non-empty frame it sent (a query reply or a state push), or `None` until
    /// the first one. Unlike [`listener`](Self::listener) this is **state, not an
    /// event stream**: it never lags and always holds the latest value, so a consumer
    /// that only wants the current DPS can read it without keeping up with every
    /// frame. Pair with [`is_connected`](Self::is_connected) to judge staleness.
    #[must_use]
    pub fn watch_status(&self) -> watch::Receiver<Option<Message>> {
        self.status_rx.clone()
    }

    /// Force an immediate (re)connection attempt: cancel any pending reconnect
    /// backoff and revive a device that has stopped reconnecting
    /// ([`auto_reconnect(false)`](DeviceBuilder::auto_reconnect)). A no-op while
    /// already connected/connecting. Returns once queued; pair with
    /// [`wait_connected`](Self::wait_connected) to await the outcome.
    pub async fn connect_now(&self) {
        // No address: keep the current dial target (only the rewake forwarder,
        // which has a freshly-announced IP, supplies one).
        let _ = self.cmd_tx.send(Cmd::ConnectNow { addr: None }).await;
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

    /// Fire a status query at this sub-device. Fire-and-forget; the reply arrives on
    /// the parent device's [`listener`](Device::listener).
    pub async fn query(&self) -> Result<()> {
        self.send(CommandType::DpQuery, None).await
    }

    /// Set multiple DPs on this sub-device (fire-and-forget).
    pub async fn set_dps(&self, dps: Value) -> Result<()> {
        self.send(CommandType::Control, Some(dps)).await
    }

    /// Set one DP on this sub-device (fire-and-forget).
    pub async fn set_value<I, T>(&self, dp_id: I, value: T) -> Result<()>
    where
        I: ToString,
        T: serde::Serialize,
    {
        let val = serde_json::to_value(value).map_err(|_| TuyaError::NotJson)?;
        let mut obj = serde_json::Map::new();
        obj.insert(dp_id.to_string(), val);
        self.set_dps(Value::Object(obj)).await
    }

    /// Fire an arbitrary command at this sub-device (fire-and-forget).
    pub async fn send(&self, cmd: CommandType, data: Option<Value>) -> Result<()> {
        self.dev.fire(cmd, data, Some(self.cid.clone())).await
    }
}

/// An item delivered by a [`Listener`] or [`MultiListener`].
///
/// The bus is a bounded broadcast ring, so delivery is lossy under a slow consumer.
/// Rather than hide that, a gap is surfaced as [`Lagged`](Event::Lagged) — an
/// observable value, not a fabricated frame — so a state-tracking consumer knows it
/// missed `n` frames. A consumer that only wants the latest value (and never wants to
/// lag) should read [`Device::watch_status`] instead of consuming events.
#[derive(Debug, Clone)]
pub enum Event {
    /// A frame from the device: a query reply or an unsolicited state push.
    Frame(Message),
    /// The consumer fell behind and `n` frames were dropped from the bus before this
    /// point. Delivery then resumes with the next live frame.
    Lagged(u64),
}

/// A subscription to a device's event bus (pushes + query replies). Created by
/// [`Device::listener`].
///
/// Implements [`Stream`](futures_core::Stream) with `Item = Event`, so it drives the
/// idiom `while let Some(ev) = listener.next().await`, and also offers an explicit
/// [`recv`](Self::recv). A bus-lag gap is delivered as [`Event::Lagged`] in both,
/// never silently skipped.
pub struct Listener {
    stream: BroadcastStream<Message>,
}

impl Listener {
    /// Await the next [`Event`], or `None` once the device stops. A bus-lag gap is
    /// returned as [`Event::Lagged`] so loss stays observable.
    pub async fn recv(&mut self) -> Option<Event> {
        match self.stream.next().await {
            Some(Ok(msg)) => Some(Event::Frame(msg)),
            Some(Err(BroadcastStreamRecvError::Lagged(n))) => Some(Event::Lagged(n)),
            None => None,
        }
    }
}

impl Stream for Listener {
    type Item = Event;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Event>> {
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.stream).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => Poll::Ready(Some(Event::Frame(msg))),
            Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(n)))) => {
                Poll::Ready(Some(Event::Lagged(n)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A fan-in over several devices' [`Listener`]s: [`add`](Self::add) the devices you
/// care about and receive their events on one stream, each tagged with its device id.
///
/// Opt-in (only added devices are subscribed) and **buffer-free** — it holds no ring
/// of its own; each device's own bus does the buffering, so a busy device can't evict
/// a quiet one's frames, and total buffering scales with the number of devices added.
/// The per-device [`Event::Lagged`] signal is preserved and reported against the
/// device that lagged. This is the sans-io analogue of 0.3's `unified_listener`, but
/// with dynamic [`add`](Self::add)/[`remove`](Self::remove) and per-device loss
/// visibility.
pub struct MultiListener {
    map: StreamMap<String, Listener>,
}

impl Default for MultiListener {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiListener {
    /// An empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: StreamMap::new(),
        }
    }

    /// Subscribe `dev`'s events into this aggregator, keyed by its device id.
    /// Re-adding the same id replaces the previous subscription.
    pub fn add(&mut self, dev: &Device) {
        self.map.insert(dev.id().to_string(), dev.listener());
    }

    /// Stop receiving `id`'s events; returns whether it was subscribed.
    pub fn remove(&mut self, id: &str) -> bool {
        self.map.remove(id).is_some()
    }

    /// Whether `id` is currently subscribed.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.map.contains_key(id)
    }

    /// Number of devices currently subscribed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether no devices are subscribed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Await the next `(device_id, event)`, or `None` when every subscribed device has
    /// stopped (or none was ever added). Fair across devices.
    pub async fn recv(&mut self) -> Option<(String, Event)> {
        self.map.next().await
    }
}

impl Stream for MultiListener {
    type Item = (String, Event);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<(String, Event)>> {
        std::pin::Pin::new(&mut self.map).poll_next(cx)
    }
}
