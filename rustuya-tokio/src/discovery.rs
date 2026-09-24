//! UDP LAN-discovery driver: a thin tokio loop over the pure `rustuya-core`
//! [`Discovery`](rustuya_core::discovery::Discovery) FSM (MILESTONES M2.3).
//!
//! The driver owns only I/O — it binds the well-known UDP ports (shared via
//! `SO_REUSEADDR`/`SO_REUSEPORT`), reads datagrams, sends active probes to the
//! broadcast address (`SO_BROADCAST`), and injects `now`/RNG. The FSM owns every
//! decision: which packets are devices, dedup by TTL, and the probe cadence.
//!
//! Shape mirrors the device driver: one reader task per bound socket funnels
//! datagrams into a single channel, and one actor task runs
//! `select!{datagram, scan-demand, control, one poll_timeout timer}` → drain
//! `poll_transmit → broadcast socket` / `poll_event → discovered bus + routes`.
//! Active probing is **on demand** (a batch-coalesced `want` signal), never a
//! perpetual beat; passive receive is always on.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration as StdDuration, Instant as StdInstant};

use rand::SeedableRng;
use rand::rngs::StdRng;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant as TokioInstant;

use rustuya_core::Version;
use rustuya_core::discovery::{Config as CoreConfig, Discovery as DiscoveryFsm, Event, Input};
use rustuya_core::time::Instant as CoreInstant;

use crate::actor::Cmd;
use crate::error::{Result, TuyaError};
use crate::join_host_port;

/// A discovered device announcement (re-exported from the core).
pub use rustuya_core::discovery::DeviceInfo;

/// The standard Tuya discovery ports the driver listens on by default.
const DEFAULT_PORTS: &[u16] = &[6666, 6667, 7000];

/// Devices seen so far, `id → (latest info, when it was last seen)`. Shared
/// between the actor (writer) and the handle (reader), so `find` can resolve an
/// already-discovered device immediately instead of only awaiting the next
/// (dedup-suppressed) announcement. The timestamp is exposed via
/// [`Discovery::last_seen`] so callers judge staleness themselves — the map keeps
/// no hidden freshness policy: reads are not time-filtered, and a stale entry for
/// a departed device is harmless (a connect to it just fails). Size is bounded by
/// `max_devices`, not by a clock — when full, the longest-silent entry makes room
/// (see [`remember`]). A live device re-announces and stays fresh, so what goes is
/// the departed or the forged; the bound matters because an announcement's id is
/// attacker-chosen on an open LAN.
type Known = Arc<Mutex<BTreeMap<String, (DeviceInfo, StdInstant)>>>;

/// A registered device's reconnect route: where to deliver a targeted wake, plus
/// the TCP port to rebuild `ip:port` from an announced IP.
struct Route {
    /// **Weak** on purpose. A strong `Sender` here would keep the actor's
    /// `Receiver` open for as long as the route exists, so dropping every
    /// `Device` handle would never stop the driver task — and since the entry is
    /// only pruned when the channel closes, nothing would ever remove it either.
    /// The device would go on reconnecting forever, invisible to its owner. A
    /// `WeakSender` doesn't hold the channel open, so the actor exits when its
    /// last real handle goes and the next wake prunes the dead route.
    cmd_tx: mpsc::WeakSender<Cmd>,
    port: u16,
}

/// `id → route`. This is the reconnect fast-path: on a device announcement the
/// actor does **one** map lookup and wakes only that device — O(1), replacing an
/// O(N) per-device broadcast-subscribe-and-filter forwarder (which made the fleet
/// O(N²) and could drop the reconnect trigger under bus lag). Entries are
/// lazily pruned when a device's actor has gone (its `cmd_tx` closes).
type Routes = Arc<Mutex<BTreeMap<String, Route>>>;

/// Lock a discovery map, recovering from poisoning. Every critical section here is
/// a plain map operation that cannot leave the map half-updated, so a panic
/// elsewhere while the lock was held must not cascade into every later
/// `find` / wake on this shared handle.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Record a sighting, keeping `known` within `cap` entries: a *new* id at
/// capacity evicts the longest-silent one first.
fn remember(known: &Known, info: &DeviceInfo, cap: usize) {
    remember_at(known, info, cap, StdInstant::now());
}

/// [`remember`] with the sighting time supplied, so the eviction order is a plain
/// input rather than something a test has to wait for the clock to produce.
fn remember_at(known: &Known, info: &DeviceInfo, cap: usize, at: StdInstant) {
    let mut map = lock(known);
    if !map.contains_key(&info.id)
        && map.len() >= cap
        && let Some(oldest) = map
            .iter()
            .min_by_key(|(_, (_, at))| *at)
            .map(|(id, _)| id.clone())
    {
        map.remove(&oldest);
    }
    map.insert(info.id.clone(), (info.clone(), at));
}

/// Everything the actor pushes results out through, grouped so `run` and `settle`
/// pass one value instead of a long argument list: the outbound probe sockets
/// (default + per-source), the announcement bus, the `known` cache, and the
/// reconnect routing registry.
struct Sinks {
    default_send: UdpSocket,
    send_socks: BTreeMap<Ipv4Addr, UdpSocket>,
    found_tx: broadcast::Sender<DeviceInfo>,
    known: Known,
    /// `known`'s capacity (see [`remember`]).
    max_known: usize,
    routes: Routes,
}

/// Control messages from a [`Discovery`] handle to its actor.
enum Ctrl {
    /// Shut the actor (and its reader tasks) down.
    Close,
}

#[inline]
fn now_since(base: TokioInstant) -> CoreInstant {
    CoreInstant::from_millis(base.elapsed().as_millis() as u64)
}

/// Keep only addresses worth stamping into a probe as "reply to me here": a real
/// unicast IPv4 on a LAN — not loopback, link-local (169.254/16), unspecified,
/// multicast or broadcast.
fn usable_sources(addrs: impl IntoIterator<Item = Ipv4Addr>) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = addrs
        .into_iter()
        .filter(|ip| {
            !(ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast())
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Best-effort local IPv4 source(s) for v3.5 probes.
///
/// First choice is the interface the kernel would route *out of*: a connected but
/// never-written UDP socket reveals it without sending a byte (the target only
/// steers the route lookup, so it is an RFC 5737 documentation address — no third
/// party is named or contacted). That needs a default route, which an isolated
/// IoT LAN — this library's home turf — often lacks. Then fall back to every
/// operational, broadcast-capable, non-tunnel interface address: one probe per
/// source beats the `0.0.0.0` probe the core would otherwise send, which some
/// firmware ignores. Empty means neither worked (the caller warns).
fn detect_local_ipv4s() -> Vec<Ipv4Addr> {
    if let Ok(sock) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        && sock.connect((Ipv4Addr::new(203, 0, 113, 1), 9)).is_ok()
        && let Ok(addr) = sock.local_addr()
        && let std::net::IpAddr::V4(v4) = addr.ip()
    {
        let routed = usable_sources([v4]);
        if !routed.is_empty() {
            return routed;
        }
    }
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    usable_sources(ifaces.into_iter().filter_map(|i| match i.addr {
        if_addrs::IfAddr::V4(v4) if i.is_oper_up() && !i.is_p2p && v4.broadcast.is_some() => {
            Some(v4.ip)
        }
        _ => None,
    }))
}

/// Bind a UDP socket for **receiving** broadcasts on `port`, shareable with other
/// sockets/processes (`SO_REUSEADDR`, and `SO_REUSEPORT` on unix).
fn bind_recv(port: u16) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    UdpSocket::from_std(sock.into())
}

/// Bind an ephemeral UDP socket for **sending** broadcasts (`SO_BROADCAST`),
/// egressing from `src` (`UNSPECIFIED` = default route / any interface).
fn bind_send_from(src: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::from((src, 0)).into())?;
    UdpSocket::from_std(sock.into())
}

/// The default send socket (any interface).
fn bind_send() -> std::io::Result<UdpSocket> {
    bind_send_from(Ipv4Addr::UNSPECIFIED)
}

/// Builder for a [`Discovery`]. Sensible defaults; nothing is required.
pub struct DiscoveryBuilder {
    ports: Vec<u16>,
    cache_ttl: StdDuration,
    broadcast_interval: StdDuration,
    broadcast_burst: Option<u32>,
    active: bool,
    local_ips: Vec<Ipv4Addr>,
    capacity: usize,
    require_source_match: bool,
    max_devices: usize,
}

impl Default for DiscoveryBuilder {
    fn default() -> Self {
        Self {
            ports: DEFAULT_PORTS.to_vec(),
            cache_ttl: StdDuration::from_secs(60),
            broadcast_interval: StdDuration::from_secs(6),
            // One round per on-demand scan (demand-driven, not a perpetual beat).
            // Raise via `probe_cadence` for a multi-round burst per scan.
            broadcast_burst: Some(1),
            active: true,
            local_ips: Vec::new(), // auto-detect one at build
            // Found-device broadcast ring depth. Preallocated, but only *once* per
            // `Discovery` (shared app-wide, not per device), so a round default is
            // fine; tunable via `capacity()`.
            capacity: 256,
            require_source_match: true,
            max_devices: 16_384,
        }
    }
}

impl DiscoveryBuilder {
    /// Start a builder with defaults (ports 6666/6667/7000, 60 s dedup TTL, active
    /// probing **on demand** — one round per `find`/`scan`/failed-dial, not a
    /// perpetual beat).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the passive **receive** ports. Active probes are not affected: they
    /// always go to the standard 6666 / 6667 / 7000, because a custom port has no
    /// defined wire dialect to probe it with.
    #[must_use]
    pub fn ports(mut self, ports: impl Into<Vec<u16>>) -> Self {
        self.ports = ports.into();
        self
    }

    /// How long a device is remembered before a re-announcement counts as new.
    #[must_use]
    pub fn cache_ttl(mut self, ttl: StdDuration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Whether to actively broadcast probes (`true`, default) or only listen
    /// passively (`false`).
    #[must_use]
    pub fn active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }

    /// How many rounds one on-demand scan fires, and the delay between them.
    /// Default `Some(1)` — a single round per scan request. `Some(n)` spaces `n`
    /// rounds by `interval` (robustness against UDP loss). `None` makes a scan
    /// **perpetual** once triggered (the 0.3 always-on behavior) — an explicit
    /// opt-in that runs until the discovery is dropped, since there is no runtime
    /// stop; prefer a small `Some(n)` for a polite network.
    #[must_use]
    pub fn probe_cadence(mut self, interval: StdDuration, burst: Option<u32>) -> Self {
        self.broadcast_interval = interval;
        self.broadcast_burst = burst;
        self
    }

    /// Depth of the found-device broadcast bus (default 256) — how far a consumer of
    /// [`found`](Discovery::found) / [`scan`](Discovery::scan) may fall behind before
    /// it loses the oldest sightings (a `Lagged` skip). A `tokio::broadcast` ring
    /// preallocated once per `Discovery` (shared app-wide, not per device), so the
    /// cost is one-time; raise it if you enumerate very large fleets through a slow
    /// consumer.
    #[must_use]
    pub fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Whether to trust an announcement's self-reported `ip` only when it matches
    /// the datagram's source address (default `true`).
    ///
    /// Announcements are unauthenticated — the UDP keys are public — and a
    /// discovered address is where a device's connection gets redirected, so
    /// without this check any host on the LAN can relocate a device by forging one.
    /// A real device announces from its own address. Turn it off only for a
    /// topology that relays announcements from a different source; dropped
    /// announcements are logged (first at `warn`, then `debug`).
    #[must_use]
    pub fn require_source_match(mut self, on: bool) -> Self {
        self.require_source_match = on;
        self
    }

    /// Most devices remembered at once (default 16 384). Bounds the memory a flood
    /// of forged announcements can pin; a new device past the cap is ignored (the
    /// core) or evicts the longest-silent one (the `known` map).
    #[must_use]
    pub fn max_devices(mut self, max: usize) -> Self {
        self.max_devices = max.max(1);
        self
    }

    /// A local IPv4 stamped into v3.5 probes (so devices know where to reply).
    /// Sets a single source; defaults to best-effort auto-detection of one.
    #[must_use]
    pub fn local_ip(mut self, ip: Ipv4Addr) -> Self {
        self.local_ips = vec![ip];
        self
    }

    /// Multiple local IPv4 sources — **one v3.5 probe per source**, each sent from
    /// a socket bound to that address, so a multi-homed host actively elicits
    /// devices across several subnets (the 0.3 `discovery_sources`, DESIGN Q6).
    #[must_use]
    pub fn local_ips(mut self, ips: impl Into<Vec<Ipv4Addr>>) -> Self {
        self.local_ips = ips.into();
        self
    }

    /// Bind the sockets and spawn the discovery actor. Must be called inside a
    /// tokio runtime. Fails only if **every** requested port fails to bind.
    pub fn build(self) -> Result<Discovery> {
        // Bind each requested port; tolerate individual failures (a port already
        // held elsewhere) as long as at least one succeeds.
        let mut recv_socks = Vec::new();
        for &port in &self.ports {
            match bind_recv(port) {
                Ok(s) => recv_socks.push(s),
                Err(e) => log::warn!("discovery: bind udp/{port} failed: {e}"),
            }
        }
        if recv_socks.is_empty() {
            return Err(TuyaError::Config("no discovery port could be bound"));
        }

        // Resolve probe sources: explicit list, else best-effort auto-detect one.
        let local_ips: Vec<Ipv4Addr> = if self.local_ips.is_empty() {
            let found = detect_local_ipv4s();
            if found.is_empty() && self.active {
                log::warn!(
                    "discovery: no local IPv4 source found; active v3.5 probes will carry \
                     0.0.0.0, which some firmware ignores — set one with `local_ip()`"
                );
            }
            found
        } else {
            self.local_ips.clone()
        };
        // The default (any-interface) socket carries untagged probes; each source
        // gets its own socket so its broadcast egresses that interface.
        let default_send = bind_send().map_err(TuyaError::Io)?;
        let mut send_socks: BTreeMap<Ipv4Addr, UdpSocket> = BTreeMap::new();
        for &ip in &local_ips {
            match bind_send_from(ip) {
                Ok(s) => {
                    send_socks.insert(ip, s);
                }
                // A source we can't bind (interface gone) falls back to default.
                Err(e) => log::warn!("discovery: bind send from {ip} failed: {e}"),
            }
        }

        let core = CoreConfig {
            cache_ttl: crate::core_dur(self.cache_ttl),
            broadcast_interval: crate::core_dur(self.broadcast_interval),
            broadcast_burst: self.broadcast_burst,
            local_ips,
            require_source_match: self.require_source_match,
            max_entries: self.max_devices,
        };

        let (found_tx, _) = broadcast::channel(self.capacity);
        // Depth 8: a small backlog of control ops (subscribe/scan/close) — these are
        // rare and the actor services them promptly, so a shallow queue suffices.
        let (ctrl_tx, ctrl_rx) = mpsc::channel(8);
        // Depth 1: a single pending "please probe" is all the coalescing needs —
        // extra requests while one is queued are redundant (try_send drops them).
        let (want_tx, want_rx) = mpsc::channel(1);
        let known: Known = Arc::new(Mutex::new(BTreeMap::new()));
        let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));

        let sinks = Sinks {
            default_send,
            send_socks,
            found_tx: found_tx.clone(),
            known: known.clone(),
            max_known: self.max_devices,
            routes: routes.clone(),
        };
        tokio::spawn(run(core, recv_socks, self.active, ctrl_rx, want_rx, sinks));

        Ok(Discovery {
            ctrl_tx,
            want_tx,
            found_tx,
            known,
            routes,
        })
    }
}

/// A handle to the LAN-discovery driver task. Cheap to clone; all clones share the
/// one underlying UDP listener.
#[derive(Clone)]
pub struct Discovery {
    ctrl_tx: mpsc::Sender<Ctrl>,
    /// Demand signal for an on-demand active probe. Sent by `find`/`scan` and by a
    /// device that just failed to dial; the actor batch-drains these and emits at
    /// most one probe round per drain (single-flight). Non-blocking `try_send`, so
    /// a full channel simply means a probe is already pending — the ideal coalesce.
    want_tx: mpsc::Sender<()>,
    found_tx: broadcast::Sender<DeviceInfo>,
    known: Known,
    routes: Routes,
}

impl Discovery {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> DiscoveryBuilder {
        DiscoveryBuilder::new()
    }

    /// Bind and start discovery with all defaults.
    pub fn new() -> Result<Self> {
        DiscoveryBuilder::new().build()
    }

    /// A lossless stream of device announcements (each new or changed device).
    #[must_use]
    pub fn discovered(&self) -> Discovered {
        Discovered {
            stream: tokio_stream::wrappers::BroadcastStream::new(self.found_tx.subscribe()),
        }
    }

    /// Request one on-demand active probe round. Non-blocking and coalescing: if a
    /// probe is already pending the request is dropped (the pending one covers it),
    /// so N callers at once yield **one** broadcast. A no-op if the discovery was
    /// built `active(false)`. This is the single explicit active trigger; there is
    /// no perpetual beat.
    pub fn request_scan(&self) {
        let _ = self.want_tx.try_send(());
    }

    /// The demand sender, handed to a device actor so a failed dial can ask for a
    /// probe (active-only devices, or a moved IP the cache hasn't caught).
    pub(crate) fn want_sender(&self) -> mpsc::Sender<()> {
        self.want_tx.clone()
    }

    /// Fire an active scan and collect every device seen during `window` (deduped
    /// by id). The standalone enumerate — "list the Tuya devices on my LAN" — that
    /// needs no [`Device`](crate::Device). `window` is caller-chosen (no library
    /// cadence). Combines the active-probe replies with ongoing passive traffic.
    pub async fn scan(&self, window: StdDuration) -> Vec<DeviceInfo> {
        self.request_scan();
        self.discover_for(window).await
    }

    /// Register a device's actor so the discovery loop can wake it directly (O(1))
    /// when that id announces — the reconnect fast-path replacing a per-device
    /// broadcast forwarder. `port` rebuilds `ip:port` from an announced IP. The
    /// entry is pruned automatically once the actor's channel closes.
    ///
    /// **Last-wins** upsert (mirrors the 0.3 bridge's same-id defense): a second
    /// device registered under an id supersedes the first's route (the displaced
    /// one falls back to plain backoff). A collision is almost always a
    /// misconfiguration, so it is logged.
    pub(crate) fn register(&self, id: String, cmd_tx: mpsc::Sender<Cmd>, port: u16) {
        let prev = lock(&self.routes).insert(
            id.clone(),
            Route {
                // Downgraded so the registry never keeps a device alive — see `Route`.
                cmd_tx: cmd_tx.downgrade(),
                port,
            },
        );
        if prev.is_some() {
            log::warn!("discovery: device id {id} re-registered; superseding previous route");
        }
    }

    /// Resolve a device by id. Returns immediately if it is in the cache (kept
    /// current by passive re-announcements for a present device; a stale entry for
    /// a departed device is harmless — a connect to it just fails and recovers).
    /// On a miss it fires one on-demand probe and awaits the next announcement, up
    /// to `timeout`.
    pub async fn find(&self, device_id: &str, timeout: StdDuration) -> Result<DeviceInfo> {
        // Subscribe *before* checking the cache: if the device announces in the
        // gap between the cache miss and awaiting the stream, the subscription
        // still catches it — no lost-wakeup.
        let mut stream = self.discovered();
        if let Some((info, _)) = lock(&self.known).get(device_id).cloned() {
            return Ok(info);
        }
        // Miss: elicit it with one probe (coalesced), then wait.
        self.request_scan();
        let wait = async {
            loop {
                match stream.recv().await {
                    Ok(info) if info.id == device_id => return Ok(info),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }
        };
        match tokio::time::timeout(timeout, wait).await {
            Ok(r) => r,
            Err(_) => Err(TuyaError::Timeout),
        }
    }

    /// A snapshot of every device discovered so far (id → info). Not time-filtered;
    /// pair with [`last_seen`](Self::last_seen) to drop long-silent devices at your
    /// own threshold.
    #[must_use]
    pub fn known(&self) -> Vec<DeviceInfo> {
        lock(&self.known)
            .values()
            .map(|(info, _)| info.clone())
            .collect()
    }

    /// How long ago `device_id` was last announced, or `None` if never seen.
    ///
    /// Exposes the raw fact so the caller decides what "too stale" means — a
    /// resolved address (from [`find`](Self::find) or a linked device) is only a
    /// hint, and the map never evicts, so a device that went offline keeps its
    /// last address indefinitely. Pair this with [`known`](Self::known) to filter
    /// out long-silent devices at your own threshold.
    #[must_use]
    pub fn last_seen(&self, device_id: &str) -> Option<StdDuration> {
        lock(&self.known).get(device_id).map(|(_, at)| at.elapsed())
    }

    /// Collect every distinct device seen during a `window` (deduped by id, latest
    /// announcement wins).
    pub async fn discover_for(&self, window: StdDuration) -> Vec<DeviceInfo> {
        let mut stream = self.discovered();
        let mut seen: std::collections::BTreeMap<String, DeviceInfo> =
            std::collections::BTreeMap::new();
        let deadline = tokio::time::sleep(window);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                r = stream.recv() => match r {
                    Ok(info) => { seen.insert(info.id.clone(), info); }
                    Err(_) => break,
                }
            }
        }
        seen.into_values().collect()
    }

    /// Stop the discovery task and its readers.
    pub async fn close(&self) {
        let _ = self.ctrl_tx.send(Ctrl::Close).await;
    }
}

/// A stream of [`DeviceInfo`] announcements (README `.next().await` idiom); also
/// offers an explicit [`recv`](Self::recv). Bus-lag gaps are skipped.
pub struct Discovered {
    stream: tokio_stream::wrappers::BroadcastStream<DeviceInfo>,
}

impl Discovered {
    /// Await the next announcement; errors with [`TuyaError::Closed`] once
    /// discovery stops.
    pub async fn recv(&mut self) -> Result<DeviceInfo> {
        use tokio_stream::StreamExt as _;
        loop {
            match self.stream.next().await {
                Some(Ok(info)) => return Ok(info),
                Some(Err(_lagged)) => {}
                None => return Err(TuyaError::Closed),
            }
        }
    }
}

impl tokio_stream::Stream for Discovered {
    type Item = DeviceInfo;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<DeviceInfo>> {
        use std::task::Poll;
        loop {
            match std::pin::Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(Ok(info))) => return Poll::Ready(Some(info)),
                Poll::Ready(Some(Err(_lagged))) => continue,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// The discovery actor: reader tasks funnel datagrams into `dgram_rx`, and this
/// loop drives the FSM and the outbound broadcast socket.
async fn run(
    core: CoreConfig,
    recv_socks: Vec<UdpSocket>,
    active: bool,
    mut ctrl_rx: mpsc::Receiver<Ctrl>,
    mut want_rx: mpsc::Receiver<()>,
    sinks: Sinks,
) {
    let mut fsm = DiscoveryFsm::new(core);
    let mut rng = StdRng::from_os_rng();
    let base = TokioInstant::now();

    // One reader task per socket → a single datagram channel. Depth 256 bounds the
    // inbound-announce backlog before a reader backpressures (a whole fleet
    // announcing at once); the actor drains it promptly, so it rarely fills.
    let (dgram_tx, mut dgram_rx) = mpsc::channel::<(Vec<u8>, std::net::IpAddr)>(256);
    let mut readers: Vec<JoinHandle<()>> = Vec::new();
    for sock in recv_socks {
        let sock = Arc::new(sock);
        let tx = dgram_tx.clone();
        readers.push(tokio::spawn(async move {
            // UDP has no reassembly: one datagram, one recv, and `recv_from`
            // silently truncates anything past the buffer. Announce datagrams run a
            // few hundred bytes; 8 KiB is generous headroom so an oversized one is
            // never clipped into a decode failure — i.e. a silently-missed device.
            let mut buf = vec![0u8; 8192];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        if tx.send((buf[..n].to_vec(), from.ip())).await.is_err() {
                            break; // actor gone
                        }
                    }
                    Err(e) => {
                        log::debug!("discovery recv error: {e}");
                        break;
                    }
                }
            }
        }));
    }
    drop(dgram_tx); // only the reader tasks keep the sender alive

    // No perpetual scan: discovery starts passive. Active probes are on-demand,
    // driven by `want_rx` (find/scan, or a device that failed to dial), and
    // batch-coalesced below — one probe round per drained burst (single-flight).
    settle(&mut fsm, &sinks).await;

    let mut warned_drop = false;
    loop {
        let deadline = fsm
            .poll_timeout()
            .map(|d| base + StdDuration::from_millis(d.as_millis()));

        tokio::select! {
            dgram = dgram_rx.recv() => match dgram {
                Some((data, from)) => {
                    let dropped_before = fsm.rejected();
                    fsm.handle_input(Input::Datagram { data: &data, from }, now_since(base), &mut rng);
                    if fsm.rejected() != dropped_before {
                        // A well-formed announcement the policy refused: its ip did
                        // not match its source (spoof/relay), or the cache is full.
                        // Loud once, then quiet — a flood must not become a log flood.
                        if warned_drop {
                            log::debug!("discovery: dropped an announcement from {from}");
                        } else {
                            warned_drop = true;
                            log::warn!(
                                "discovery: dropped an announcement from {from} (its ip does not \
                                 match its source, or the device cache is full); further drops \
                                 are logged at debug"
                            );
                        }
                    }
                }
                None => { /* all readers ended; keep serving control/timer */ }
            },
            // Demand-driven active probe. Drain the whole burst so N simultaneous
            // requests collapse to one `StartScan` (single-flight). `active(false)`
            // discovery ignores the demand (passive only).
            want = want_rx.recv() => match want {
                Some(()) => {
                    while want_rx.try_recv().is_ok() {} // coalesce the burst
                    if active {
                        // Fire one round now (the burst config decides how many);
                        // StartScan arms `next_broadcast = now`, the timer arm emits.
                        fsm.handle_input(Input::StartScan, now_since(base), &mut rng);
                    }
                }
                None => { /* all want-senders dropped; keep serving */ }
            },
            ctrl = ctrl_rx.recv() => match ctrl {
                Some(Ctrl::Close) | None => {
                    for r in readers {
                        r.abort();
                    }
                    return;
                }
            },
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(TokioInstant::now)), if deadline.is_some() => {
                fsm.handle_timeout(now_since(base), &mut rng);
            }
        }

        settle(&mut fsm, &sinks).await;
    }
}

/// Push out probes (each from the socket bound to its tagged source) and process
/// events. `Found` updates the `known` map, fans out to the announcement bus, and
/// wakes a registered device at its **new** address; `Seen` is a same-IP liveness
/// tick that wakes a registered device at the address discovery already holds for
/// it (①). Both wakes are O(1) targeted `try_send`s — never blocking, never a
/// broadcast fan-out.
async fn settle(fsm: &mut DiscoveryFsm, sinks: &Sinks) {
    while let Some((bytes, port, source)) = fsm.poll_transmit() {
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, port));
        // Send from the tagged source's socket; fall back to the default one.
        let sock = source
            .and_then(|s| sinks.send_socks.get(&s))
            .unwrap_or(&sinks.default_send);
        if let Err(e) = sock.send_to(&bytes, dst).await {
            log::debug!("discovery probe send to {dst} failed: {e}");
        }
    }
    while let Some(ev) = fsm.poll_event() {
        match ev {
            Event::Found(info) => {
                remember(&sinks.known, &info, sinks.max_known);
                // Changed/new: wake the registered device at its announced
                // address, and tell it what the announcement said it speaks.
                route_wake(
                    &sinks.routes,
                    &info.id,
                    Some(&info.ip.to_string()),
                    info.version,
                );
                let _ = sinks.found_tx.send(info);
            }
            // Same-IP re-announcement. Wake with the address discovery already
            // holds rather than a bare "redial whatever you have": `Seen` means
            // the announcement *matched* the cache, so the cached address is by
            // definition the device's current one — passing it can never be
            // wrong, and it is the only thing that can relocate a device
            // registered *after* the cache entry was made. Such a device may be
            // parked on a placeholder address with no way off it: `Found` (the
            // only other carrier of an address) will not fire again while the
            // device keeps announcing, because every announcement refreshes the
            // cache entry and so the TTL never expires.
            Event::Seen(id) => {
                let announced = lock(&sinks.known)
                    .get(&id)
                    .map(|(info, _)| (info.ip.to_string(), info.version));
                let (ip, version) = match announced {
                    Some((ip, version)) => (Some(ip), version),
                    None => (None, None),
                };
                route_wake(&sinks.routes, &id, ip.as_deref(), version);
            }
        }
    }
}

/// Wake the device registered under `id`, if any: a non-blocking `try_send` of
/// `ConnectNow`, carrying `ip` (joined to the registered port) when the address
/// may have changed, and `version` when the announcement declared one. A closed
/// channel means the actor is gone → prune the route; a full channel means it's
/// busy → drop this wake (another announcement follows).
///
/// The version matters as much as the address for a device configured
/// `Version::Auto`: the core never probes, so an unresolved device speaks v3.3
/// at everything, and a v3.4 device accepts that TCP connection before hanging up
/// on the first frame that skipped its handshake.
fn route_wake(routes: &Routes, id: &str, ip: Option<&str>, version: Option<Version>) {
    use tokio::sync::mpsc::error::TrySendError;
    let mut map = lock(routes);
    let Some(route) = map.get(id) else { return };
    let addr = ip.map(|ip| join_host_port(ip, route.port));
    // A weak sender that won't upgrade means every real handle is gone: the
    // device was dropped by its owner and its actor has stopped. Prune.
    let Some(cmd_tx) = route.cmd_tx.upgrade() else {
        map.remove(id);
        return;
    };
    match cmd_tx.try_send(Cmd::ConnectNow { addr, version }) {
        Ok(()) | Err(TrySendError::Full(_)) => {}
        Err(TrySendError::Closed(_)) => {
            map.remove(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(id: &str) -> DeviceInfo {
        DeviceInfo {
            id: id.to_string(),
            ip: "192.168.0.9".parse().unwrap(),
            version: None,
            product_key: None,
        }
    }

    /// `known` never grows past its cap, and what makes room is the entry that has
    /// been silent longest — a live device that keeps announcing is never the one
    /// evicted by a flood of new ids.
    #[test]
    fn known_is_bounded_and_evicts_the_longest_silent() {
        let known: Known = Arc::new(Mutex::new(BTreeMap::new()));
        let t0 = StdInstant::now();
        let at = |ms| t0 + StdDuration::from_millis(ms);
        remember_at(&known, &info("old"), 3, at(1));
        remember_at(&known, &info("mid"), 3, at(2));
        remember_at(&known, &info("live"), 3, at(3));
        // Refreshing `old` makes `mid` the longest-silent.
        remember_at(&known, &info("old"), 3, at(4));
        remember_at(&known, &info("new"), 3, at(5));

        let map = lock(&known);
        assert_eq!(map.len(), 3, "the cap holds");
        assert!(!map.contains_key("mid"), "the longest-silent entry went");
        assert!(map.contains_key("old") && map.contains_key("live") && map.contains_key("new"));
    }

    /// A panic while a discovery map is locked must not turn every later access
    /// on the shared handle into a panic of its own.
    #[test]
    fn a_poisoned_map_is_still_usable() {
        let known: Known = Arc::new(Mutex::new(BTreeMap::new()));
        let k = Arc::clone(&known);
        let _ = std::thread::spawn(move || {
            let _guard = k.lock().unwrap();
            panic!("poison the lock");
        })
        .join();
        assert!(known.is_poisoned());

        remember(&known, &info("dev"), 8);
        assert!(lock(&known).contains_key("dev"));
    }

    #[test]
    fn probe_sources_are_real_lan_unicast_only() {
        let ip = |a, b, c, d| Ipv4Addr::new(a, b, c, d);
        let got = usable_sources([
            ip(127, 0, 0, 1),       // loopback
            ip(169, 254, 3, 4),     // link-local
            ip(0, 0, 0, 0),         // unspecified
            ip(224, 0, 0, 1),       // multicast
            ip(255, 255, 255, 255), // broadcast
            ip(192, 168, 1, 10),
            ip(10, 0, 0, 5),
            ip(192, 168, 1, 10), // duplicate
        ]);
        assert_eq!(got, vec![ip(10, 0, 0, 5), ip(192, 168, 1, 10)]);
    }

    /// The registry must not accumulate an entry per departed device: once the
    /// owner drops its `Device`, the weak route stops upgrading and the first
    /// wake that reaches it prunes it.
    ///
    /// A unit test because nothing public enumerates the registry — from the
    /// outside the prune is unobservable, so an integration test could only
    /// assert that waking a dead route does not panic, which is not the claim.
    #[test]
    fn a_wake_prunes_the_route_of_a_departed_device() {
        let routes: Routes = Arc::new(Mutex::new(BTreeMap::new()));
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(4);
        lock(&routes).insert(
            "dev".to_string(),
            Route {
                cmd_tx: cmd_tx.downgrade(),
                port: 6668,
            },
        );

        // While the device is alive the wake is delivered — carrying the announced
        // IP rejoined to the registered port — and the route stays.
        route_wake(&routes, "dev", Some("192.168.1.5"), None);
        assert!(
            matches!(
                cmd_rx.try_recv(),
                Ok(Cmd::ConnectNow { addr: Some(a), .. }) if a == "192.168.1.5:6668"
            ),
            "a live route should have been woken at the announced address"
        );
        assert_eq!(lock(&routes).len(), 1, "a live route must survive its wake");

        // The owner releases the device: no strong sender left to upgrade to.
        drop(cmd_tx);
        route_wake(&routes, "dev", None, None);
        assert!(
            lock(&routes).is_empty(),
            "the route of a departed device must be pruned by the wake that finds it dead"
        );

        // And waking an id that is no longer registered is a no-op, not a panic —
        // every later announcement for that device takes this path.
        route_wake(&routes, "dev", Some("192.168.1.5"), None);
    }
}
