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
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant as StdInstant};

use rand::rngs::StdRng;
use rand::SeedableRng;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant as TokioInstant;

use rustuya_core::discovery::{Config as CoreConfig, Discovery as DiscoveryFsm, Event, Input};
use rustuya_core::time::Instant as CoreInstant;

use crate::actor::Cmd;
use crate::error::{Result, TuyaError};

/// A discovered device announcement (re-exported from the core).
pub use rustuya_core::discovery::DeviceInfo;

/// The standard Tuya discovery ports the driver listens on by default.
const DEFAULT_PORTS: &[u16] = &[6666, 6667, 7000];

/// Devices seen so far, `id → (latest info, when it was last seen)`. Shared
/// between the actor (writer) and the handle (reader), so `find` can resolve an
/// already-discovered device immediately instead of only awaiting the next
/// (dedup-suppressed) announcement. The timestamp is exposed via
/// [`Discovery::last_seen`] so callers judge staleness themselves — the map keeps
/// no hidden freshness policy. It does not time-evict: present devices keep their
/// entries fresh by re-announcing (passive), and a stale entry for a departed
/// device is harmless (a connect to it just fails). Size is bounded by the
/// broadcast domain (one entry per device id ever seen), not by a clock.
type Known = Arc<Mutex<BTreeMap<String, (DeviceInfo, StdInstant)>>>;

/// A registered device's reconnect route: where to deliver a targeted wake, plus
/// the TCP port to rebuild `ip:port` from an announced IP.
struct Route {
    cmd_tx: mpsc::Sender<Cmd>,
    port: u16,
}

/// `id → route`. This is the reconnect fast-path: on a device announcement the
/// actor does **one** map lookup and wakes only that device — O(1), replacing an
/// O(N) per-device broadcast-subscribe-and-filter forwarder (which made the fleet
/// O(N²) and could drop the reconnect trigger under bus lag). Entries are
/// lazily pruned when a device's actor has gone (its `cmd_tx` closes).
type Routes = Arc<Mutex<BTreeMap<String, Route>>>;

/// Everything the actor pushes results out through, grouped so `run` and `settle`
/// pass one value instead of a long argument list: the outbound probe sockets
/// (default + per-source), the announcement bus, the `known` cache, and the
/// reconnect routing registry.
struct Sinks {
    default_send: UdpSocket,
    send_socks: BTreeMap<Ipv4Addr, UdpSocket>,
    found_tx: broadcast::Sender<DeviceInfo>,
    known: Known,
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

/// Best-effort local IPv4 detection: a connected-but-unsent UDP socket reveals the
/// interface the kernel would route from. `None` on failure (degrades to 0.0.0.0).
fn detect_local_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((Ipv4Addr::new(8, 8, 8, 8), 53)).ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
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
            capacity: 256,
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

    /// Override the passive receive ports.
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

    /// A local IPv4 stamped into v3.5 probes (so devices know where to reply).
    /// Sets a single source; defaults to best-effort auto-detection of one.
    #[must_use]
    pub fn local_ip(mut self, ip: Ipv4Addr) -> Self {
        self.local_ips = vec![ip];
        self
    }

    /// Multiple local IPv4 sources — **one v3.5 probe per source**, each sent from
    /// a socket bound to that address, so a multi-homed host actively elicits
    /// devices across several subnets (the 0.3 `discovery_sources`, SMELLS Q6).
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
            detect_local_ipv4().into_iter().collect()
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
        };

        let (found_tx, _) = broadcast::channel(self.capacity);
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
        let prev = self.routes.lock().unwrap().insert(id.clone(), Route { cmd_tx, port });
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
        if let Some((info, _)) = self.known.lock().unwrap().get(device_id).cloned() {
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
        self.known
            .lock()
            .unwrap()
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
        self.known
            .lock()
            .unwrap()
            .get(device_id)
            .map(|(_, at)| at.elapsed())
    }

    /// Collect every distinct device seen during a `window` (deduped by id, latest
    /// announcement wins).
    pub async fn discover_for(&self, window: StdDuration) -> Vec<DeviceInfo> {
        let mut stream = self.discovered();
        let mut seen: std::collections::BTreeMap<String, DeviceInfo> = std::collections::BTreeMap::new();
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

    // One reader task per socket → a single datagram channel.
    let (dgram_tx, mut dgram_rx) = mpsc::channel::<(Vec<u8>, std::net::IpAddr)>(256);
    let mut readers: Vec<JoinHandle<()>> = Vec::new();
    for sock in recv_socks {
        let sock = Arc::new(sock);
        let tx = dgram_tx.clone();
        readers.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
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

    loop {
        let deadline =
            fsm.poll_timeout().map(|d| base + StdDuration::from_millis(d.as_millis()));

        tokio::select! {
            dgram = dgram_rx.recv() => match dgram {
                Some((data, from)) => {
                    fsm.handle_input(Input::Datagram { data: &data, from }, now_since(base), &mut rng);
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
/// tick that wakes a registered device at its current address (①). Both wakes are
/// O(1) targeted `try_send`s — never blocking, never a broadcast fan-out.
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
                sinks
                    .known
                    .lock()
                    .unwrap()
                    .insert(info.id.clone(), (info.clone(), StdInstant::now()));
                // Changed/new: wake the registered device at its announced address.
                route_wake(&sinks.routes, &info.id, Some(&info.ip.to_string()));
                let _ = sinks.found_tx.send(info);
            }
            // Same-IP re-announcement: wake to redial the *current* address.
            Event::Seen(id) => route_wake(&sinks.routes, &id, None),
        }
    }
}

/// Wake the device registered under `id`, if any: a non-blocking `try_send` of
/// `ConnectNow`, carrying `ip` (joined to the registered port) when the address
/// may have changed. A closed channel means the actor is gone → prune the route;
/// a full channel means it's busy → drop this wake (another announcement follows).
fn route_wake(routes: &Routes, id: &str, ip: Option<&str>) {
    use tokio::sync::mpsc::error::TrySendError;
    let mut map = routes.lock().unwrap();
    let Some(route) = map.get(id) else { return };
    let addr = ip.map(|ip| format!("{ip}:{}", route.port));
    match route.cmd_tx.try_send(Cmd::ConnectNow { addr }) {
        Ok(()) | Err(TrySendError::Full(_)) => {}
        Err(TrySendError::Closed(_)) => {
            map.remove(id);
        }
    }
}
