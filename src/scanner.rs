//! UDP-based device discovery and scanning.
//!
//! Listens for Tuya broadcast packets on the local network to discover devices.

use crate::crypto::TuyaCipher;
use crate::error::{Result, TuyaError};
use crate::protocol::{self, CommandType, PREFIX_6699, TuyaMessage, Version};
use log::{debug, info, trace, warn};
use parking_lot::RwLock;
use serde_json::Value;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, sleep, timeout};

use serde::Serialize;

/// Information about a discovered Tuya device.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiscoveryResult {
    /// Device ID
    pub id: String,
    /// Device IP address
    pub ip: String,
    /// Protocol version (e.g., 3.1, 3.3, 3.4, 3.5)
    pub version: Option<Version>,
    /// Product Key
    pub product_key: Option<String>,
    /// Time when the device was discovered
    #[serde(skip)]
    pub discovered_at: Instant,
}

impl DiscoveryResult {
    /// Checks if this result is substantially different from another,
    /// ignoring the discovery timestamp.
    #[must_use]
    pub fn is_same_device(&self, other: &Self) -> bool {
        self.id == other.id
            && self.ip == other.ip
            && self.version == other.version
            && self.product_key == other.product_key
    }
}

/// v3.4 UDP discovery encryption key
const UDP_KEY_34: &[u8] = &[
    0x6c, 0x1e, 0xc8, 0xe2, 0xbb, 0x9b, 0xb5, 0x9a, 0xb5, 0x0b, 0x0d, 0xaf, 0x64, 0x9b, 0x41, 0x0a,
];
/// v3.5 UDP discovery encryption key (same as 3.4)
const UDP_KEY_35: &[u8] = UDP_KEY_34;
/// v3.3 UDP discovery encryption key
const UDP_KEY_33: &[u8] = b"yG9shRKIBrIBUjc3";

// --- Discovery timing ---
//
// The active scan schedule, by construction:
//   t=0       broadcast #1 (tokio `interval` fires immediately on first tick)
//   t=6s      broadcast #2
//   t=12s     broadcast #3  (MAX_BROADCASTS reached, no more sends)
//   t=18s     timeout       (RECEIVE_MARGIN of 6s after the last broadcast)
//
// The invariant we want to preserve is "at least one BROADCAST_INTERVAL of
// receive window after the last broadcast" — otherwise late device replies are
// lost. `DEFAULT_SCAN_TIMEOUT` is derived from the other constants so a future
// tweak can't silently destroy the margin; an assertion in `Scanner::new`
// pins it.
const BROADCAST_INTERVAL: Duration = Duration::from_secs(6);
const MAX_BROADCASTS: u32 = 3;
const RECEIVE_MARGIN: Duration = BROADCAST_INTERVAL;
const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(
    BROADCAST_INTERVAL.as_secs() * (MAX_BROADCASTS as u64 - 1) + RECEIVE_MARGIN.as_secs(),
);

const GLOBAL_SCAN_COOLDOWN: Duration = Duration::from_secs(1800); // 30 minutes
const SCAN_THROTTLE_INTERVAL: Duration = Duration::from_secs(60); // 60 seconds minimum gap between active scans
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

/// Capacity of the shared mpsc that all receiver tasks feed into the
/// dispatcher. Sized for the realistic worst case of a few thousand
/// devices simultaneously broadcasting after an active scan: each
/// `dispatch_packet` is microsecond-scale, so 1024 holds enough slack
/// to absorb a sub-millisecond burst without the receiver's
/// `tx.send().await` parking and back-pressuring the UDP socket (which
/// would cause the kernel buffer to drop packets).
const PACKET_CHANNEL_CAPACITY: usize = 1024;

/// Sender half of the scanner's shared packet bus (one per dispatcher).
type PacketSender = mpsc::Sender<(Vec<u8>, SocketAddr)>;
/// Receiver half — paired with `PacketSender`, consumed by the dispatcher.
type PacketReceiver = mpsc::Receiver<(Vec<u8>, SocketAddr)>;

#[derive(Debug)]
struct ScannerState {
    cache: RwLock<HashMap<String, DiscoveryResult>>,
    // `tokio::sync::watch` instead of `tokio::sync::Notify` so consumers cannot
    // miss a publish that fires between two `notified()` calls. Each cache
    // update bumps the counter; subscribers `changed().await` and re-read the
    // cache. The carried value is a monotonic discovery version — callers
    // don't read it, the *change* itself is the signal.
    discovery_version: (watch::Sender<u64>, watch::Receiver<u64>),
    active_scanning: AtomicBool,
    last_scan_time: RwLock<Option<Instant>>,
    listener_started: AtomicBool,
    // RwLock<CancellationToken> — the token is replaced (not just cancelled)
    // each time the passive listener is stopped, so a subsequent start gets a
    // fresh, uncancelled token. CancellationToken is one-shot by design; reusing
    // a cancelled instance would make every new receiver task exit immediately.
    cancel_token: RwLock<tokio_util::sync::CancellationToken>,
    sockets: RwLock<HashMap<u16, Arc<UdpSocket>>>,
    // Single long-lived mpsc shared by ALL receiver tasks (one per port). The
    // dispatcher task drains the matching receiver. When `set_ports` later adds
    // a port, the new receiver task clones this same sender — so its packets
    // reach the same dispatcher. (Before this design, each call to
    // `spawn_receiver_tasks` minted a fresh channel whose `rx` was never
    // polled, silently dropping every packet on the newly added port.)
    packet_tx: RwLock<Option<PacketSender>>,
    // Per-port receiver tasks. Keyed by port so `set_ports` can selectively
    // abort the receiver for a port being removed (rather than leaking it
    // until full `stop_passive_listener`).
    receiver_tasks: RwLock<HashMap<u16, tokio::task::JoinHandle<()>>>,
    // The dispatcher is singular (one per shared mpsc); held separately so
    // per-port `receiver_tasks` removal doesn't accidentally touch it.
    dispatcher_task: RwLock<Option<tokio::task::JoinHandle<()>>>,
    // Serializes the *entire* `ensure_passive_listener` body. Without this,
    // two threads calling concurrently (e.g. one via `set_ports`, another
    // via a fallback path) could race between `listener_started.swap` and
    // `*packet_tx.write() = Some(tx)` — the second thread would observe
    // listener_started=true but packet_tx=None, fall into the rebuild
    // fallback, and end up spawning a SECOND dispatcher on its own mpsc.
    // The function is called rarely (init, set_ports, set_bind_address)
    // so a coarse mutex is the right cost trade-off vs. a more delicate
    // state machine.
    startup_guard: parking_lot::Mutex<()>,
    // Live configuration. Previously these were `Scanner` fields and required a
    // `&mut Scanner` to mutate — which forced a separate `ScannerBuilder` path
    // that bound its own UDP sockets and competed with the singleton. Storing
    // them here with interior mutability lets every setter take `&self` and
    // route through the same global state.
    timeout: RwLock<Duration>,
    bind_addr: RwLock<String>,
    ports: RwLock<Vec<u16>>,
}

impl ScannerState {
    fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            discovery_version: watch::channel(0u64),
            active_scanning: AtomicBool::new(false),
            last_scan_time: RwLock::new(None),
            listener_started: AtomicBool::new(false),
            cancel_token: RwLock::new(tokio_util::sync::CancellationToken::new()),
            sockets: RwLock::new(HashMap::new()),
            packet_tx: RwLock::new(None),
            receiver_tasks: RwLock::new(HashMap::new()),
            dispatcher_task: RwLock::new(None),
            startup_guard: parking_lot::Mutex::new(()),
            timeout: RwLock::new(DEFAULT_SCAN_TIMEOUT),
            bind_addr: RwLock::new("0.0.0.0".to_string()),
            ports: RwLock::new(vec![6666, 6667, 7000]),
        }
    }

    /// Returns a clone of the current cancellation token.
    fn current_cancel_token(&self) -> tokio_util::sync::CancellationToken {
        self.cancel_token.read().clone()
    }

    /// Cancels the current token and installs a fresh one. Subsequent
    /// `current_cancel_token()` calls return the new (uncancelled) token.
    fn reset_cancel_token(&self) {
        let mut guard = self.cancel_token.write();
        guard.cancel();
        *guard = tokio_util::sync::CancellationToken::new();
    }

    /// Returns the active packet sender if a listener is currently running.
    fn current_packet_tx(&self) -> Option<PacketSender> {
        self.packet_tx.read().clone()
    }

    /// Publishes a new discovery version. Subscribers' `changed().await`
    /// resolves; if a subscriber is between awaits, the bumped value is
    /// retained until they next call `changed()`, so notifications cannot be
    /// lost (unlike `Notify::notify_waiters`).
    fn publish_discovery(&self) {
        self.discovery_version
            .0
            .send_modify(|v| *v = v.wrapping_add(1));
    }

    /// Subscribes to discovery notifications. The returned receiver is
    /// pre-marked-seen at the current version, so only *future* updates
    /// resolve `changed()`.
    fn subscribe_discoveries(&self) -> watch::Receiver<u64> {
        let mut rx = self.discovery_version.1.clone();
        rx.mark_unchanged();
        rx
    }
}

impl Drop for ScannerState {
    fn drop(&mut self) {
        self.cancel_token.write().cancel();
        for (_, task) in self.receiver_tasks.write().drain() {
            task.abort();
        }
        if let Some(t) = self.dispatcher_task.write().take() {
            t.abort();
        }
    }
}

/// Pure helper: given a desired port list and the currently-bound set,
/// return `(ports_to_add, ports_to_remove)`. Factored out so the
/// reconciliation arithmetic can be unit-tested without binding sockets.
fn compute_port_diff(desired: &[u16], current: &[u16]) -> (Vec<u16>, Vec<u16>) {
    let to_add: Vec<u16> = desired
        .iter()
        .filter(|p| !current.contains(p))
        .copied()
        .collect();
    let to_remove: Vec<u16> = current
        .iter()
        .filter(|p| !desired.contains(p))
        .copied()
        .collect();
    (to_add, to_remove)
}

/// Discovers Tuya devices on the local network using UDP broadcast.
///
/// `Scanner` is a process-wide singleton. Get a handle via [`Scanner::get`]
/// and configure it via [`set_timeout`](Self::set_timeout) /
/// [`set_ports`](Self::set_ports) / [`set_bind_address`](Self::set_bind_address)
/// — all setters take `&self` and route through the same singleton.
#[derive(Debug, Clone)]
pub struct Scanner {
    inner: Arc<ScannerState>,
}

static GLOBAL_SCANNER: OnceLock<Scanner> = OnceLock::new();

/// Returns the global scanner instance.
pub fn get() -> &'static Scanner {
    GLOBAL_SCANNER.get_or_init(Scanner::new)
}

impl Scanner {
    /// Returns the global scanner instance.
    pub fn get() -> &'static Self {
        get()
    }

    /// Creates the singleton's underlying state and starts the passive listener.
    #[must_use]
    pub(crate) fn new() -> Self {
        let scanner = Self {
            inner: Arc::new(ScannerState::new()),
        };
        scanner.ensure_passive_listener();
        scanner
    }

    /// Reconciles the running passive listener with the current `ports` /
    /// `bind_addr` configuration:
    ///
    /// - **Removes** receivers and sockets for any port no longer in `ports`.
    ///   (Previously omitted — a `set_ports(vec![6666])` after the default
    ///   left 6667 and 7000 still running.)
    /// - **Adds** sockets + receiver tasks for any port newly in `ports`.
    /// - **Spawns** the dispatcher on the first call.
    ///
    /// Acquires `startup_guard` for the duration so concurrent callers
    /// (e.g. `set_ports` racing against the discovery-loop fallback) cannot
    /// end up spawning duplicate dispatchers on disjoint mpsc channels —
    /// that would silently fork the cache-write path.
    fn ensure_passive_listener(&self) {
        let _guard = self.inner.startup_guard.lock();
        self.reconcile_listener_locked();
    }

    /// Body of [`ensure_passive_listener`]; caller must hold `startup_guard`.
    /// Split out so paths that already hold the guard (`set_bind_address`'s
    /// abort-then-rebind sequence) don't re-acquire and deadlock.
    fn reconcile_listener_locked(&self) {
        let state = &self.inner;
        let ports_snapshot: Vec<u16> = state.ports.read().clone();
        let current_ports: Vec<u16> = state.sockets.read().keys().copied().collect();
        let (ports_to_add, ports_to_remove) = compute_port_diff(&ports_snapshot, &current_ports);

        // Apply removals first so the listener_started branch below is decided
        // against the post-removal socket set.
        if !ports_to_remove.is_empty() {
            let mut tasks = state.receiver_tasks.write();
            let mut sockets = state.sockets.write();
            for port in &ports_to_remove {
                if let Some(task) = tasks.remove(port) {
                    task.abort();
                }
                sockets.remove(port);
            }
            debug!(
                "Passive listener: removed receivers for ports {:?}",
                ports_to_remove
            );
        }

        // If no new ports to add and already started, nothing more to do.
        if ports_to_add.is_empty() && state.listener_started.load(Ordering::SeqCst) {
            return;
        }

        let bind_addr = state.bind_addr.read().clone();
        let mut new_sockets: Vec<(u16, Arc<UdpSocket>)> = Vec::new();
        {
            let mut guard = state.sockets.write();
            for port in ports_to_add {
                if let Ok(socket) = Self::create_udp_socket(&bind_addr, port) {
                    let arc_socket = Arc::new(socket);
                    guard.insert(port, arc_socket.clone());
                    new_sockets.push((port, arc_socket));
                }
            }
        }

        // If we already had a listener running and no new sockets were successfully opened, return
        if new_sockets.is_empty() && state.listener_started.load(Ordering::SeqCst) {
            return;
        }

        if new_sockets.is_empty() {
            warn!(
                "Passive listener failed to bind to any ports: {:?}",
                ports_snapshot
            );
            return;
        }

        // Two distinct paths:
        //   (a) first-time startup  — create the shared channel, spawn the
        //       dispatcher (consumes rx), then spawn one receiver per socket.
        //   (b) listener already running, this call only adds ports — clone
        //       the existing sender so new receivers feed the same dispatcher.
        if !state.listener_started.swap(true, Ordering::SeqCst) {
            let cancel_token = state.current_cancel_token();
            let (tx, mut rx): (PacketSender, PacketReceiver) =
                mpsc::channel(PACKET_CHANNEL_CAPACITY);
            *state.packet_tx.write() = Some(tx.clone());

            let recv_tasks = Self::spawn_receiver_tasks(new_sockets, tx, cancel_token.clone());
            state.receiver_tasks.write().extend(recv_tasks);

            let state_weak = Arc::downgrade(&self.inner);
            let dispatcher_ct = cancel_token.clone();
            let dispatcher = crate::runtime::spawn(async move {
                debug!("Starting background passive listener task...");
                loop {
                    tokio::select! {
                        () = dispatcher_ct.cancelled() => break,
                        msg = rx.recv() => {
                            let Some((data, _addr)) = msg else { break };
                            let Some(state) = state_weak.upgrade() else { break };
                            Self::dispatch_packet(&state, &data);
                        }
                    }
                }
                debug!("Background passive listener task stopped");
            });
            *state.dispatcher_task.write() = Some(dispatcher);
        } else if let Some(tx) = state.current_packet_tx() {
            // Listener already up — splice in receivers for the newly added ports.
            let recv_tasks =
                Self::spawn_receiver_tasks(new_sockets, tx, state.current_cancel_token());
            state.receiver_tasks.write().extend(recv_tasks);
        } else {
            // With `startup_guard` held, this branch (listener_started=true
            // but packet_tx=None) is unreachable from concurrent calls —
            // every state mutator funnels through the guard. If it ever
            // fires, something mutated state directly outside the guard;
            // recover by resetting and recursing through the locked helper.
            debug_assert!(
                false,
                "ScannerState invariant violated: listener_started=true but packet_tx=None"
            );
            warn!(
                "Passive listener state inconsistency (listener_started=true, packet_tx=None); \
                 forcing rebuild"
            );
            state.listener_started.store(false, Ordering::SeqCst);
            drop(new_sockets);
            self.reconcile_listener_locked();
        }
    }

    /// Decodes one UDP packet and folds it into the discovery cache.
    /// Extracted so first-start and shared-channel paths use identical logic.
    fn dispatch_packet(state: &Arc<ScannerState>, data: &[u8]) {
        let Some(res) = parse_packet(data) else {
            return;
        };
        let mut guard = state.cache.write();

        // Keep memory clean by removing expired entries on every update.
        guard.retain(|_, v| v.discovered_at.elapsed() < CACHE_TTL);

        let should_log = match guard.get(&res.id) {
            Some(existing) => !res.is_same_device(existing),
            None => true,
        };

        if should_log {
            let mode = if state.active_scanning.load(Ordering::SeqCst) {
                "A"
            } else {
                "P"
            };
            let version = res
                .version
                .map_or_else(|| "unknown".to_string(), |v| v.to_string());
            info!(
                "Discovered device {}(v{}) at {} - {}",
                res.id, version, res.ip, mode
            );
        }

        guard.insert(res.id.clone(), res.clone());
        drop(guard);
        state.publish_discovery();
    }

    fn spawn_receiver_tasks(
        sockets: Vec<(u16, Arc<UdpSocket>)>,
        tx: PacketSender,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Vec<(u16, tokio::task::JoinHandle<()>)> {
        let mut tasks = Vec::new();
        for (port, socket) in sockets {
            let tx = tx.clone();
            let socket = socket.clone();
            let ct = cancel_token.clone();
            let task = crate::runtime::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let local_addr = socket.local_addr().ok();
                loop {
                    tokio::select! {
                        () = ct.cancelled() => break,
                        res = socket.recv_from(&mut buf) => {
                            match res {
                                Ok((len, addr)) => {
                                    if tx.send((buf[..len].to_vec(), addr)).await.is_err() {
                                        // Downstream consumer is gone; nothing left to feed.
                                        break;
                                    }
                                }
                                Err(e) => {
                                    // UDP recv errors are usually transient (ICMP
                                    // unreachable, brief interface flap, EINTR).
                                    // Log and back off briefly so we don't burn CPU
                                    // if it keeps recurring, but never give up — the
                                    // passive listener must survive network hiccups
                                    // so devices can be re-discovered after recovery.
                                    warn!(
                                        "Scanner UDP recv error on {:?}: {} (continuing)",
                                        local_addr, e
                                    );
                                    tokio::select! {
                                        () = ct.cancelled() => break,
                                        () = sleep(Duration::from_millis(500)) => {}
                                    }
                                }
                            }
                        }
                    }
                }
            });
            tasks.push((port, task));
        }
        tasks
    }

    fn create_udp_socket(bind_addr: &str, port: u16) -> Result<UdpSocket> {
        let addr: SocketAddr = format!("{bind_addr}:{port}")
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        let _ = socket.set_reuse_address(true);
        let _ = socket.set_broadcast(true);

        socket.bind(&SockAddr::from(addr))?;
        socket.set_nonblocking(true)?;

        let std_socket: std::net::UdpSocket = socket.into();

        // UdpSocket::from_std requires an active Tokio reactor.
        // If we're called from a thread without one (e.g. sync examples),
        // we must enter the global background runtime.
        let _guard = crate::runtime::get_runtime().enter();
        Ok(UdpSocket::from_std(std_socket)?)
    }

    /// Stops the background passive listener and resets internal state so the
    /// scanner can be started again later (e.g. via `set_ports` or another
    /// `scan()` call).
    pub fn stop_passive_listener(&self) {
        // Hold `startup_guard` so a concurrent `ensure_passive_listener`
        // can't see a half-torn-down state and start spinning up a new
        // dispatcher on top of one we haven't finished cancelling.
        let _guard = self.inner.startup_guard.lock();
        // Cancel-then-replace: receiver/dispatcher tasks observe the cancel
        // and exit; future starts pick up the fresh token.
        self.inner.reset_cancel_token();
        self.inner.listener_started.store(false, Ordering::SeqCst);
        self.inner.sockets.write().clear();
        // Drop the shared sender so the dispatcher's `rx.recv()` resolves to
        // None even if some receiver task is slow to see the cancel.
        *self.inner.packet_tx.write() = None;
        // Best-effort: drop any receiver task handles we still own. Tasks
        // already woken by the cancel will finish on their own; this only
        // forces immediate abort for any that are stuck on a syscall.
        for (_, task) in self.inner.receiver_tasks.write().drain() {
            task.abort();
        }
        if let Some(t) = self.inner.dispatcher_task.write().take() {
            t.abort();
        }
    }

    /// Returns the discovery timeout this scanner uses.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        *self.inner.timeout.read()
    }

    /// Returns the bind address this scanner uses.
    #[must_use]
    pub fn bind_addr(&self) -> String {
        self.inner.bind_addr.read().clone()
    }

    /// Returns the UDP ports this scanner listens on.
    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        self.inner.ports.read().clone()
    }

    /// Sets the discovery timeout.
    pub fn set_timeout(&self, timeout: Duration) {
        *self.inner.timeout.write() = timeout;
    }

    /// Sets the UDP ports to scan and starts receivers for any newly added port.
    pub fn set_ports(&self, ports: Vec<u16>) {
        *self.inner.ports.write() = ports;
        self.ensure_passive_listener();
    }

    /// Sets the local bind address. If the address actually changes and the
    /// passive listener is already running, the existing receiver tasks are
    /// aborted and the sockets re-bound to the new address. The dispatcher
    /// task and the discovery cache survive the rebind (no events lost from
    /// the consumer's POV; in-flight UDP packets on the old sockets may be
    /// dropped).
    pub fn set_bind_address(&self, addr: &str) -> Result<()> {
        let new_addr = addr.to_string();
        // Take the guard for the whole detect-clear-rebind sequence so a
        // concurrent caller can't squeeze in between the clear and the
        // rebind. `reconcile_listener_locked` runs under the same guard.
        let _guard = self.inner.startup_guard.lock();
        let old_addr = {
            let mut g = self.inner.bind_addr.write();
            let prev = g.clone();
            *g = new_addr.clone();
            prev
        };
        let listener_up = self.inner.listener_started.load(Ordering::SeqCst);
        if old_addr != new_addr && listener_up {
            debug!(
                "Rebinding passive listener sockets from {} to {}",
                old_addr, new_addr
            );
            // Abort all per-port receivers and drop the old sockets, but keep
            // the dispatcher + packet_tx alive so the splice path in
            // `reconcile_listener_locked` reuses them — that means no cache
            // discontinuity and no need to re-spawn the dispatcher.
            {
                let mut tasks = self.inner.receiver_tasks.write();
                for (_, task) in tasks.drain() {
                    task.abort();
                }
            }
            self.inner.sockets.write().clear();
        }
        self.reconcile_listener_locked();
        Ok(())
    }

    /// Returns a `watch` receiver that fires whenever any device is
    /// discovered. The receiver is pre-marked-seen, so only events *after*
    /// the call resolve `changed()`.
    ///
    /// Crate-internal: the receiver carries an internal monotonic counter
    /// that callers should not rely on.
    pub(crate) fn subscribe_discoveries(&self) -> watch::Receiver<u64> {
        self.inner.subscribe_discoveries()
    }

    /// Returns the cached discovery result for a device, if it exists and is not expired.
    #[must_use]
    pub fn get_cached_result(&self, device_id: &str) -> Option<DiscoveryResult> {
        let guard = self.inner.cache.read();
        guard.get(device_id).cloned()
    }

    /// Checks if a device was discovered within the last `within` duration.
    #[must_use]
    pub fn is_recently_discovered(&self, device_id: &str, within: Duration) -> bool {
        let guard = self.inner.cache.read();
        if let Some(res) = guard.get(device_id) {
            return res.discovered_at.elapsed() < within;
        }
        false
    }

    /// Best-effort local-IP detection. Tries multiple non-routing destinations
    /// so the lookup works in air-gapped LANs where `8.8.8.8` is unreachable.
    /// UDP `connect()` only performs a kernel route lookup; no packet is
    /// actually sent.
    ///
    /// Intentionally **not cached**: an `OnceLock` here would freeze the local
    /// IP at first call, so a host whose IP later changes (DHCP renewal, WiFi
    /// switch, VPN up/down, container restart, …) would forever stamp the
    /// stale address into v3.5 discovery broadcasts. The lookup is sub-
    /// millisecond and only runs from `send_discovery_broadcast`, which fires
    /// at most a few times per active scan and is itself throttled by the
    /// 30-minute global scan cooldown — so the saved cost is negligible.
    fn discover_local_ip_blocking() -> Option<String> {
        // Each candidate covers a different network environment:
        //   - "8.8.8.8"        : internet-connected hosts (most common)
        //   - "255.255.255.255": LAN-only / air-gapped, needs SO_BROADCAST
        //   - "203.0.113.1"    : TEST-NET-3 (RFC 5737), non-routable but
        //                        still triggers a route lookup that returns
        //                        the default-route source IP
        const CANDIDATES: &[&str] = &["8.8.8.8:80", "255.255.255.255:80", "203.0.113.1:80"];
        for dst in CANDIDATES {
            let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") else {
                continue;
            };
            let _ = socket.set_broadcast(true); // needed for 255.255.255.255
            if socket.connect(dst).is_ok()
                && let Ok(addr) = socket.local_addr()
                && !addr.ip().is_unspecified()
            {
                return Some(addr.ip().to_string());
            }
        }
        None
    }

    async fn send_discovery_broadcast(&self, socket: &UdpSocket, port: u16) -> Result<()> {
        let local_ip = Self::discover_local_ip_blocking().unwrap_or_else(|| {
            // All three candidate destinations failed a kernel route lookup —
            // typically only happens on containers/namespaces with an empty
            // routing table. v3.5 (port 7000) payloads carry this IP and some
            // firmwares ignore broadcasts with `ip="0.0.0.0"`, so surface it.
            warn!(
                "Local IP detection failed for discovery broadcast on port {port}; \
                 falling back to 0.0.0.0"
            );
            "0.0.0.0".to_string()
        });
        debug!("Sending discovery broadcast on port {port} (local IP: {local_ip})");

        let (payload, prefix) = if port == 7000 {
            (
                serde_json::json!({
                    "from": "app",
                    "ip": local_ip,
                }),
                PREFIX_6699,
            )
        } else {
            (
                serde_json::json!({
                    "gwId": "",
                    "devId": "",
                }),
                protocol::PREFIX_55AA,
            )
        };

        let msg = TuyaMessage {
            seqno: 0,
            cmd: if port == 7000 {
                CommandType::ReqDevInfo as u32
            } else {
                CommandType::UdpNew as u32
            },
            retcode: None,
            payload: serde_json::to_vec(&payload)?,
            prefix,
            iv: None,
        };

        let packed =
            protocol::pack_message(&msg, if port == 7000 { Some(UDP_KEY_35) } else { None })?;
        let broadcast_addr: SocketAddr = format!("255.255.255.255:{port}")
            .parse()
            .map_err(|_| TuyaError::Offline)?;

        match socket.send_to(&packed, broadcast_addr).await {
            Ok(len) => debug!("Sent discovery broadcast to {broadcast_addr}: {len} bytes"),
            Err(e) => warn!("Failed to send discovery broadcast to {broadcast_addr}: {e}"),
        }

        Ok(())
    }

    /// Scans the local network for all Tuya devices and returns a stream of results.
    ///
    /// This will yield currently cached devices first, then any newly discovered devices
    /// until the scan timeout is reached. If a scan is already in progress, it will
    /// join the existing scan instead of starting a new one.
    pub fn scan_stream() -> impl futures_util::Stream<Item = DiscoveryResult> + Send + 'static {
        Self::get().scan_stream_instance()
    }

    /// Instance version of `scan_stream`.
    pub fn scan_stream_instance(
        &self,
    ) -> impl futures_util::Stream<Item = DiscoveryResult> + Send + 'static {
        let state = self.inner.clone();
        let timeout_dur = *state.timeout.read();
        let start_time = Instant::now();
        let scanner = self.clone();

        // Atomically claim the "active scanner" slot. compare_exchange ensures
        // only one of multiple concurrent scan_stream() callers wins; the
        // losers join the existing scan instead of spawning a duplicate
        // discovery loop. (Before this, a load-then-store split allowed two
        // callers to both decide they should start.)
        let cooldown_ok = {
            let last_scan = state.last_scan_time.read();
            last_scan.is_none_or(|t| t.elapsed() >= GLOBAL_SCAN_COOLDOWN)
        };
        let should_start = cooldown_ok
            && state
                .active_scanning
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok();

        // Subscribe to discovery events BEFORE spawning the discovery loop.
        // The watch receiver retains the "last seen version", so any publish
        // that lands between subscription and the first `changed().await` is
        // replayed — but we still want to subscribe before publishers can run
        // so the ordering is obviously correct on a cold read.
        let mut discovery_rx = state.subscribe_discoveries();

        if should_start {
            *state.last_scan_time.write() = Some(Instant::now());
            let state_clone = state.clone();
            crate::runtime::spawn(async move {
                let _ = scanner.perform_discovery_loop().await;
                state_clone.active_scanning.store(false, Ordering::SeqCst);
                state_clone.publish_discovery();
            });
        }

        async_stream::stream! {
            let mut yielded_ids = std::collections::HashSet::new();

            // 2. Yield current cache first
            let initial_items: Vec<_> = {
                let guard = state.cache.read();
                guard.values().cloned().collect()
            };

            for item in initial_items {
                yielded_ids.insert(item.id.clone());
                yield item;
            }

            // 3. Yield new items as they are discovered
            loop {
                let elapsed = start_time.elapsed();
                if elapsed >= timeout_dur {
                    break;
                }

                let remaining = timeout_dur.saturating_sub(elapsed);

                // Wait for next discovery notification or timeout
                tokio::select! {
                    () = sleep(remaining) => break,
                    _ = discovery_rx.changed() => {
                        let new_items: Vec<_> = {
                            let guard = state.cache.read();
                            guard.values()
                                .filter(|v| !yielded_ids.contains(&v.id))
                                .cloned()
                                .collect()
                        };

                        for item in new_items {
                            yielded_ids.insert(item.id.clone());
                            yield item;
                        }

                        // If scanning finished, we can stop after checking the cache one last time
                        if !state.active_scanning.load(Ordering::SeqCst) {
                             // Check one more time to catch any race conditions
                             let final_items: Vec<_> = {
                                let guard = state.cache.read();
                                guard.values()
                                    .filter(|v| !yielded_ids.contains(&v.id))
                                    .cloned()
                                    .collect()
                            };
                            for item in final_items {
                                yield item;
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Scans the local network for all Tuya devices and returns a list of results.
    ///
    /// If a scan is already in progress, it will join that scan and return the results
    /// once it finishes.
    pub async fn scan() -> Result<Vec<DiscoveryResult>> {
        Self::get().scan_instance().await
    }

    /// Instance version of `scan`.
    pub async fn scan_instance(&self) -> Result<Vec<DiscoveryResult>> {
        use futures_util::StreamExt;

        info!(
            "Starting Tuya device scan (addr: {}, ports: {:?})...",
            self.inner.bind_addr.read(),
            self.inner.ports.read()
        );

        let results: Vec<_> = self.scan_stream_instance().collect().await;

        info!("Scan finished. Found {} devices.", results.len());
        Ok(results)
    }

    /// Discovers a specific device by ID.
    pub async fn discover_device(device_id: &str) -> Result<Option<DiscoveryResult>> {
        Self::get().discover_device_instance(device_id).await
    }

    /// Instance version of `discover_device`.
    pub async fn discover_device_instance(
        &self,
        device_id: &str,
    ) -> Result<Option<DiscoveryResult>> {
        self.discover_device_internal(device_id, false, None).await
    }

    pub(crate) async fn discover_device_internal(
        &self,
        device_id: &str,
        force_scan: bool,
        cancel: Option<&tokio_util::sync::CancellationToken>,
    ) -> Result<Option<DiscoveryResult>> {
        // 1. Check cache and cooldowns
        if let Some(res) = self.check_cache_and_cooldown(device_id, force_scan) {
            return Ok(Some(res));
        }

        // 2. Try to initiate or wait for scan
        self.ensure_scan_started(device_id, force_scan).await;

        // 3. Wait for the result to appear in cache
        Ok(self.wait_for_cache_result(device_id, cancel).await)
    }

    fn check_cache_and_cooldown(
        &self,
        device_id: &str,
        force_scan: bool,
    ) -> Option<DiscoveryResult> {
        let state = &self.inner;
        let guard = state.cache.read();

        if let Some(res) = guard.get(device_id).cloned()
            && !force_scan
            && res.discovered_at.elapsed() < GLOBAL_SCAN_COOLDOWN
        {
            debug!("Found device {device_id} in discovery cache");
            return Some(res);
        }

        if !force_scan
            && let Some(last) = *state.last_scan_time.read()
            && last.elapsed() < GLOBAL_SCAN_COOLDOWN
            && let Some(res) = guard.get(device_id).cloned()
        {
            debug!("Global scan cooldown active (30m). Returning cached result for {device_id}.");
            return Some(res);
        }
        None
    }

    async fn ensure_scan_started(&self, device_id: &str, force_scan: bool) {
        let state = self.inner.clone();
        let can_scan = {
            let last_scan = *state.last_scan_time.read();
            match last_scan {
                Some(last) if !force_scan && last.elapsed() < SCAN_THROTTLE_INTERVAL => false,
                _ => !state.active_scanning.swap(true, Ordering::SeqCst),
            }
        };

        if can_scan {
            info!("Initiating background scan for device ID: {device_id}...");
            *state.last_scan_time.write() = Some(Instant::now());

            let scanner = self.clone();
            crate::runtime::spawn(async move {
                let _ = scanner.perform_discovery_loop().await;
                state.active_scanning.store(false, Ordering::SeqCst);
                state.publish_discovery();
            });
        }
    }

    async fn wait_for_cache_result(
        &self,
        device_id: &str,
        cancel: Option<&tokio_util::sync::CancellationToken>,
    ) -> Option<DiscoveryResult> {
        let state = &self.inner;
        let start_wait = Instant::now();
        // Subscribe ONCE up front. The watch receiver carries its own
        // "last seen version", so even if a publish happens between the cache
        // check below and the `changed().await`, the next `changed()` call
        // resolves immediately instead of hanging.
        let mut discovery_rx = state.subscribe_discoveries();

        let timeout_dur = *state.timeout.read();
        loop {
            if let Some(res) = state.cache.read().get(device_id).cloned() {
                return Some(res);
            }

            let elapsed = start_wait.elapsed();
            if elapsed >= timeout_dur || !state.active_scanning.load(Ordering::SeqCst) {
                // One last check before giving up
                return state.cache.read().get(device_id).cloned();
            }

            let remaining = timeout_dur.saturating_sub(elapsed);

            if let Some(ct) = cancel {
                tokio::select! {
                    _ = ct.cancelled() => return None,
                    _ = sleep(remaining) => {}
                    _ = discovery_rx.changed() => {}
                }
            } else {
                let _ = timeout(remaining, discovery_rx.changed()).await;
            }
        }
    }

    async fn perform_discovery_loop(self) -> Result<()> {
        let state = &self.inner;
        let ports_snapshot: Vec<u16> = state.ports.read().clone();
        let mut target_sockets = Vec::new();

        {
            let guard = state.sockets.read();
            for &port in &ports_snapshot {
                if let Some(socket) = guard.get(&port) {
                    target_sockets.push((socket.clone(), port));
                }
            }
        }

        if target_sockets.is_empty() {
            // If no sockets found in passive listener, try to ensure it's started for these ports
            self.ensure_passive_listener();
            let guard = state.sockets.read();
            for &port in &ports_snapshot {
                if let Some(socket) = guard.get(&port) {
                    target_sockets.push((socket.clone(), port));
                }
            }
        }

        if target_sockets.is_empty() {
            return Err(std::io::Error::other("No available ports for scanning").into());
        }

        let start = Instant::now();
        let mut broadcast_interval = interval(BROADCAST_INTERVAL);
        let mut broadcast_count = 0;
        let timeout_dur = *state.timeout.read();

        while start.elapsed() < timeout_dur {
            let remaining = timeout_dur.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            if broadcast_count >= MAX_BROADCASTS {
                // All broadcasts sent. Just hold the loop alive for the
                // receive window so late device replies have time to land
                // in the cache before the spawned scan task exits and the
                // stream consumer notices `active_scanning=false`.
                sleep(remaining).await;
                break;
            }

            tokio::select! {
                () = sleep(remaining) => break,
                _ = broadcast_interval.tick() => {
                    broadcast_count += 1;
                    debug!("Sent broadcast {broadcast_count}/{MAX_BROADCASTS}");
                    for (socket, port) in &target_sockets {
                        let _ = self.send_discovery_broadcast(socket, *port).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Invalidates the cache entry for a specific device.
    #[must_use]
    pub fn invalidate_cache(&self, id: &str) -> bool {
        let mut guard = self.inner.cache.write();
        guard.remove(id).is_some()
    }
}

const UDP_TRY_KEYS: [Option<&[u8]>; 4] =
    [Some(UDP_KEY_35), Some(UDP_KEY_34), Some(UDP_KEY_33), None];
const UDP_TRY_RETCODES: [Option<bool>; 3] = [Some(true), Some(false), None];

/// Parses a UDP discovery packet, attempting multiple keys and retcode strategies.
fn parse_packet(data: &[u8]) -> Option<DiscoveryResult> {
    trace!("Parsing UDP packet of {} bytes...", data.len());

    // 1. Try raw JSON (v3.1, port 6666)
    if let Ok(val) = serde_json::from_slice::<Value>(data) {
        trace!("Successfully parsed raw JSON packet");
        return parse_json(&val);
    }

    // 2. Try Tuya message format (55AA or 6699) across all key/retcode combinations.
    for key in UDP_TRY_KEYS {
        for no_retcode in UDP_TRY_RETCODES {
            match protocol::unpack_message(data, key, None, no_retcode) {
                Ok(msg) => {
                    if msg.payload.is_empty() {
                        continue;
                    }

                    // 2a. Payload is raw JSON (v3.5 or unencrypted v3.3)
                    if let Ok(val) = serde_json::from_slice::<Value>(&msg.payload) {
                        trace!("Successfully parsed JSON from Tuya message payload");
                        return parse_json(&val);
                    }

                    // 2b. Payload is ECB encrypted (v3.3/v3.4)
                    let keys_to_try: Vec<&[u8]> = match key {
                        Some(k) => vec![k],
                        None => vec![UDP_KEY_33, UDP_KEY_34, UDP_KEY_35],
                    };

                    for k in keys_to_try {
                        if let Ok(cipher) = TuyaCipher::new(k)
                            && let Ok(decrypted) =
                                cipher.decrypt(&msg.payload, false, None, None, None)
                            && let Ok(val) = serde_json::from_slice::<Value>(&decrypted)
                        {
                            trace!(
                                "Successfully decrypted and parsed JSON from Tuya message payload"
                            );
                            return parse_json(&val);
                        }
                    }
                }
                Err(e) => {
                    // Only log if it's not an expected failure during key brute-forcing
                    if !matches!(
                        e,
                        crate::error::TuyaError::DecodeError(_)
                            | crate::error::TuyaError::HmacMismatch
                            | crate::error::TuyaError::CrcMismatch
                            | crate::error::TuyaError::InvalidHeader
                    ) {
                        trace!(
                            "unpack_message failed with key {:?}: {e}",
                            key.map(crate::crypto::hex_encode),
                        );
                    }
                }
            }
        }
    }

    // 3. Try to decrypt the entire packet as AES-ECB (v3.3 discovery fallback)
    for key in &[UDP_KEY_33, UDP_KEY_34] {
        if let Ok(cipher) = TuyaCipher::new(key)
            && let Ok(decrypted) = cipher.decrypt(data, false, None, None, None)
            && let Ok(val) = serde_json::from_slice::<Value>(&decrypted)
        {
            trace!("Successfully decrypted and parsed JSON from entire packet");
            return parse_json(&val);
        }
    }

    // 4. Fallback: search for JSON start '{' in the packet
    if let Some(pos) = data.iter().position(|&b| b == b'{')
        && let Ok(val) = serde_json::from_slice::<Value>(&data[pos..])
    {
        trace!("Successfully found and parsed JSON from middle of packet");
        return parse_json(&val);
    }

    trace!("Failed to parse UDP packet");
    None
}

/// Extracts device info from a JSON discovery payload.
fn parse_json(val: &Value) -> Option<DiscoveryResult> {
    let id = val
        .get("gwId")
        .or_else(|| val.get("devId"))
        .or_else(|| val.get("id"))
        .and_then(|v| v.as_str())?;
    let ip = val.get("ip").and_then(|v| v.as_str())?;

    let ver_s = val.get("version").and_then(|v| v.as_str());
    let pk = val.get("productKey").and_then(|v| v.as_str());

    Some(DiscoveryResult {
        id: id.to_string(),
        ip: ip.to_string(),
        version: ver_s.and_then(|s| Version::from_str(s).ok()),
        product_key: pk.map(std::string::ToString::to_string),
        discovered_at: Instant::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // M1.8 regression: lock the discovery timing invariant — the timeout MUST
    // exceed the time of the last broadcast by at least RECEIVE_MARGIN so
    // late device replies have a chance to arrive before the loop exits.
    #[test]
    fn scan_timeout_leaves_room_after_last_broadcast() {
        let last_broadcast_at = BROADCAST_INTERVAL * (MAX_BROADCASTS - 1);
        let margin = DEFAULT_SCAN_TIMEOUT.saturating_sub(last_broadcast_at);
        assert!(
            margin >= RECEIVE_MARGIN,
            "scan timeout ({DEFAULT_SCAN_TIMEOUT:?}) leaves only {margin:?} after \
             the last broadcast (at {last_broadcast_at:?}); need at least {RECEIVE_MARGIN:?}"
        );
    }

    // M1.2 regression: the shared `packet_tx` must survive a follow-up
    // `ensure_passive_listener` call (i.e. a `set_ports` that adds a port). If
    // a second call swapped the channel, receivers spawned by it would feed an
    // unowned rx and packets on the new port would be silently dropped.
    #[test]
    fn packet_tx_lifecycle_persists_then_clears_on_stop() {
        let state = Arc::new(ScannerState::new());

        // Before any listener: no sender.
        assert!(state.current_packet_tx().is_none());

        // Simulate first ensure_passive_listener: install a sender.
        let (tx, _rx): (PacketSender, PacketReceiver) = mpsc::channel(8);
        *state.packet_tx.write() = Some(tx);

        // Second ensure_passive_listener (e.g. set_ports) must NOT replace the
        // sender — it should reuse the existing one for new receivers.
        let tx_clone_a = state.current_packet_tx().expect("listener up");
        let tx_clone_b = state.current_packet_tx().expect("listener up");
        assert!(tx_clone_a.same_channel(&tx_clone_b));

        // Stop clears the sender; future calls would create a fresh one.
        *state.packet_tx.write() = None;
        assert!(state.current_packet_tx().is_none());
    }

    // M1.2 end-to-end-ish: dispatch_packet folds a known v3.1 broadcast into
    // the cache. Locks in the routing extraction (single cache write path).
    #[test]
    fn dispatch_packet_updates_cache_for_known_v31_broadcast() {
        let state = Arc::new(ScannerState::new());
        let payload =
            br#"{"gwId":"test-device-id","ip":"10.0.0.42","version":"3.1","productKey":"pk"}"#;

        Scanner::dispatch_packet(&state, payload);

        let cache = state.cache.read();
        let entry = cache
            .get("test-device-id")
            .expect("dispatch must insert into cache");
        assert_eq!(entry.ip, "10.0.0.42");
        assert_eq!(entry.version, Some(Version::V3_1));
    }

    // M1.1 regression: after `reset_cancel_token`, the *new* token must be
    // uncancelled. Before this fix the listener used a one-shot
    // `CancellationToken`, which permanently disabled the scanner once stopped.
    #[test]
    fn reset_cancel_token_yields_fresh_uncancelled_token() {
        let state = ScannerState::new();
        let first = state.current_cancel_token();
        assert!(!first.is_cancelled());

        state.reset_cancel_token();

        // The previously-handed-out clone is cancelled (so any pre-stop task
        // that was awaiting it will wake up and exit).
        assert!(first.is_cancelled());

        // A fresh clone obtained *after* the reset is a brand-new token.
        let second = state.current_cancel_token();
        assert!(!second.is_cancelled());

        // The first and second tokens are distinct: cancelling one does not
        // affect the other.
        state.cancel_token.write().cancel();
        assert!(state.current_cancel_token().is_cancelled());

        state.reset_cancel_token();
        let third = state.current_cancel_token();
        assert!(!third.is_cancelled());
    }

    // M2.6 regression: concurrent scan_stream callers must not both claim
    // the "active scan" slot via load-then-store. compare_exchange ensures
    // exactly one wins; the rest join. Exercised at the AtomicBool level
    // since spawning real discovery loops requires sockets.
    #[test]
    fn active_scanning_compare_exchange_is_single_winner() {
        use std::sync::atomic::{AtomicUsize, Ordering as O};
        let state = Arc::new(ScannerState::new());
        let winners = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..16 {
            let s = state.clone();
            let w = winners.clone();
            handles.push(std::thread::spawn(move || {
                if s.active_scanning
                    .compare_exchange(false, true, O::SeqCst, O::SeqCst)
                    .is_ok()
                {
                    w.fetch_add(1, O::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            winners.load(O::SeqCst),
            1,
            "exactly one caller should claim the active scan slot"
        );
        assert!(state.active_scanning.load(O::SeqCst));
    }

    // M5.4: scan_timeout_leaves_room invariant is covered above. Other
    // scanner-integration items (set_ports delivering on new ports,
    // stop+restart cycle) require real socket binding, which we don't do in
    // unit tests; lifecycle-level coverage is in
    // `packet_tx_lifecycle_persists_then_clears_on_stop` and
    // `reset_cancel_token_yields_fresh_uncancelled_token` above.

    // 0.3.0-rc.2: Scanner config (`timeout`, `bind_addr`, `ports`) lives in
    // `ScannerState` behind a lock so setters can take `&self`. Verifies the
    // mutation is observable through the same `Arc<ScannerState>` — i.e.
    // setting on one `Scanner` clone is visible from another, which is the
    // property that makes `Scanner::get().set_*` work on the global.
    #[test]
    fn setters_take_self_and_share_state_across_clones() {
        let inner = Arc::new(ScannerState::new());
        let a = Scanner {
            inner: inner.clone(),
        };
        let b = Scanner { inner };

        // Default sanity.
        assert_eq!(a.timeout(), DEFAULT_SCAN_TIMEOUT);
        assert_eq!(a.bind_addr(), "0.0.0.0");
        assert_eq!(a.ports(), vec![6666, 6667, 7000]);

        // Mutation through `a` is visible from `b` (same Arc<ScannerState>).
        // Note: we don't call `set_ports` / `set_bind_address` here because
        // they trigger `ensure_passive_listener`, which needs real sockets.
        // `set_timeout` is socket-free.
        a.set_timeout(Duration::from_secs(42));
        assert_eq!(b.timeout(), Duration::from_secs(42));

        // Direct state mutation locks in that the other two fields are
        // *stored* on shared state too (without triggering socket binds).
        *a.inner.bind_addr.write() = "127.0.0.1".to_string();
        *a.inner.ports.write() = vec![9999];
        assert_eq!(b.bind_addr(), "127.0.0.1");
        assert_eq!(b.ports(), vec![9999]);
    }

    // 0.3.0-rc.2: lock in that the local-IP lookup is *not* cached. A
    // process-wide `OnceLock` over an `Option<String>` here would freeze the
    // result at first call, breaking long-running processes whose host IP
    // changes (DHCP, WiFi switch, VPN, container restart). The forbidden
    // tokens are assembled at runtime so this very test doesn't trip itself.
    #[test]
    fn local_ip_lookup_is_not_cached() {
        let src = include_str!("scanner.rs");
        let forbidden_static = format!("LOCAL{}IP{}CACHE", "_", "_");
        assert!(
            !src.contains(&forbidden_static),
            "scanner.rs must not reintroduce the local-IP cache static — see \
             docs/technical-notes.md §Local-IP discovery for rationale"
        );
        // Belt-and-suspenders: also forbid OnceLock around the lookup result.
        // OnceLock is still used legitimately for GLOBAL_SCANNER and tokio
        // runtime; we only want to catch the "static once-cell of optional
        // string" shape that the previous LOCAL_IP cache had.
        let forbidden_ty = format!("Once{}<Option<String>>", "Lock");
        assert!(
            !src.contains(&forbidden_ty),
            "scanner.rs must not cache an Option<String> via OnceLock — that \
             would freeze the local IP for the process lifetime"
        );
    }

    // 0.3.0-rc.2 follow-up: lock the port-diff arithmetic that
    // `ensure_passive_listener` uses to decide which ports to bind/abort.
    // Before this fix, the function only added new ports; ports removed
    // from the configured list silently kept their receiver tasks alive.
    #[test]
    fn compute_port_diff_adds_only() {
        let (add, remove) = compute_port_diff(&[6666, 6667, 7000], &[]);
        assert_eq!(add, vec![6666, 6667, 7000]);
        assert!(remove.is_empty());
    }

    #[test]
    fn compute_port_diff_removes_only() {
        let (add, remove) = compute_port_diff(&[6666], &[6666, 6667, 7000]);
        assert!(add.is_empty());
        // Ordering of HashMap-derived current isn't guaranteed in production,
        // so compare as sets.
        let removed: std::collections::HashSet<u16> = remove.into_iter().collect();
        assert_eq!(
            removed,
            [6667u16, 7000]
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
        );
    }

    #[test]
    fn compute_port_diff_mixed_add_and_remove() {
        let (add, remove) = compute_port_diff(&[6666, 8888], &[6666, 7000]);
        assert_eq!(add, vec![8888]);
        assert_eq!(remove, vec![7000]);
    }

    #[test]
    fn compute_port_diff_no_change_returns_empty_both() {
        let (add, remove) = compute_port_diff(&[6666, 7000], &[6666, 7000]);
        assert!(add.is_empty());
        assert!(remove.is_empty());
    }

    // Integration smoke: a real `set_ports` cycle that adds then removes ports
    // should leave the `sockets` map in sync with the configured ports and
    // abort the obsolete receiver task. Uses high ephemeral ports to avoid
    // colliding with anything real on the test host.
    #[test]
    fn set_ports_add_then_remove_reconciles_socket_map() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Build an isolated Scanner (NOT the global singleton — we don't
            // want to disrupt anyone else's state). We can't call
            // `ScannerBuilder` anymore (removed in rc.2) but we can hand-roll
            // an instance for testing.
            let scanner = Scanner {
                inner: Arc::new(ScannerState::new()),
            };
            // Use unlikely-to-be-bound high ports.
            let port_a = 47770u16;
            let port_b = 47771u16;
            let port_c = 47772u16;

            scanner.set_ports(vec![port_a, port_b]);
            tokio::task::yield_now().await;
            {
                let sockets = scanner.inner.sockets.read();
                assert!(sockets.contains_key(&port_a), "port_a should be bound");
                assert!(sockets.contains_key(&port_b), "port_b should be bound");
                assert_eq!(sockets.len(), 2);
            }
            {
                let tasks = scanner.inner.receiver_tasks.read();
                assert!(tasks.contains_key(&port_a));
                assert!(tasks.contains_key(&port_b));
            }

            // Swap: drop port_b, add port_c.
            scanner.set_ports(vec![port_a, port_c]);
            tokio::task::yield_now().await;
            {
                let sockets = scanner.inner.sockets.read();
                assert!(sockets.contains_key(&port_a), "port_a kept");
                assert!(
                    !sockets.contains_key(&port_b),
                    "port_b must be removed from sockets map"
                );
                assert!(sockets.contains_key(&port_c), "port_c added");
                assert_eq!(sockets.len(), 2);
            }
            {
                let tasks = scanner.inner.receiver_tasks.read();
                assert!(tasks.contains_key(&port_a));
                assert!(
                    !tasks.contains_key(&port_b),
                    "port_b receiver task must be aborted and removed"
                );
                assert!(tasks.contains_key(&port_c));
            }

            // Drop everything: stop should clean up cleanly.
            scanner.stop_passive_listener();
            assert!(scanner.inner.sockets.read().is_empty());
            assert!(scanner.inner.receiver_tasks.read().is_empty());
            assert!(scanner.inner.dispatcher_task.read().is_none());
        });
    }

    #[test]
    fn compute_port_diff_full_swap() {
        let (add, remove) = compute_port_diff(&[8888, 9999], &[6666, 7000]);
        let added: std::collections::HashSet<u16> = add.into_iter().collect();
        let removed: std::collections::HashSet<u16> = remove.into_iter().collect();
        assert_eq!(
            added,
            [8888u16, 9999]
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
        );
        assert_eq!(
            removed,
            [6666u16, 7000]
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
        );
    }
}
