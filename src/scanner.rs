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
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};
use tokio::time::{Duration, Instant};

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

const BROADCAST_INTERVAL: Duration = Duration::from_secs(6);
const GLOBAL_SCAN_COOLDOWN: Duration = Duration::from_secs(1800); // 30 minutes
const SCAN_THROTTLE_INTERVAL: Duration = Duration::from_secs(60); // 60 seconds minimum gap between active scans
const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(18); // Hardcoded 18s timeout
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hours

#[derive(Debug)]
struct ScannerState {
    cache: RwLock<HashMap<String, DiscoveryResult>>,
    notify: Notify,
    active_scanning: AtomicBool,
    last_scan_time: RwLock<Option<Instant>>,
    listener_started: AtomicBool,
    cancel_token: tokio_util::sync::CancellationToken,
    sockets: RwLock<HashMap<u16, Arc<UdpSocket>>>,
}

impl ScannerState {
    fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            notify: Notify::new(),
            active_scanning: AtomicBool::new(false),
            last_scan_time: RwLock::new(None),
            listener_started: AtomicBool::new(false),
            cancel_token: tokio_util::sync::CancellationToken::new(),
            sockets: RwLock::new(HashMap::new()),
        }
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        // Only stop if this is the last instance
        if Arc::strong_count(&self.inner) <= 1 {
            self.stop_passive_listener();
        }
    }
}

/// Discovers Tuya devices on the local network using UDP broadcast.
#[derive(Debug, Clone)]
pub struct Scanner {
    inner: Arc<ScannerState>,
    /// Timeout for discovery
    pub timeout: Duration,
    /// Local address to bind to
    pub bind_addr: String,
    /// UDP ports to scan (default: 6666, 6667, 7000)
    pub ports: Vec<u16>,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    /// Creates a new Scanner with default settings.
    pub fn new() -> Self {
        let scanner = Self {
            inner: Arc::new(ScannerState::new()),
            timeout: DEFAULT_SCAN_TIMEOUT,
            bind_addr: "0.0.0.0".to_string(),
            ports: vec![6666, 6667, 7000],
        };
        scanner.ensure_passive_listener();
        scanner
    }

    /// Ensures background passive listener is running.
    fn ensure_passive_listener(&self) {
        let state = &self.inner;
        let mut ports_to_add = Vec::new();
        {
            let guard = state.sockets.read();
            for &port in &self.ports {
                if !guard.contains_key(&port) {
                    ports_to_add.push(port);
                }
            }
        }

        // If no new ports and already started, nothing to do
        if ports_to_add.is_empty() && state.listener_started.load(Ordering::SeqCst) {
            return;
        }

        let bind_addr = self.bind_addr.clone();
        let mut new_sockets = Vec::new();
        {
            let mut guard = state.sockets.write();
            for port in ports_to_add {
                if let Ok(socket) = Self::create_udp_socket(&bind_addr, port) {
                    let arc_socket = Arc::new(socket);
                    guard.insert(port, arc_socket.clone());
                    new_sockets.push(arc_socket);
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
                self.ports
            );
            return;
        }

        // Only start a new receiver task if it wasn't already started
        if !state.listener_started.swap(true, Ordering::SeqCst) {
            let cancel_token = state.cancel_token.clone();
            let state_weak = Arc::downgrade(&self.inner);

            crate::runtime::spawn(async move {
                debug!("Starting background passive listener task...");

                let (mut rx, _ct) = Self::spawn_receiver_tasks(new_sockets, cancel_token.clone());
                let scanner_temp = Scanner::new_silent();
                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => break,
                        Some((data, _addr)) = rx.recv() => {
                            if let Some(res) = scanner_temp.parse_packet(&data) {
                                let state = match state_weak.upgrade() {
                                    Some(s) => s,
                                    None => break,
                                };
                                let mut guard = state.cache.write();

                                // Keep memory clean by removing expired entries on every update.
                                guard.retain(|_, v| v.discovered_at.elapsed() < CACHE_TTL);

                                let should_log = match guard.get(&res.id) {
                                    Some(existing) => !res.is_same_device(existing),
                                    None => true,
                                };

                                if should_log {
                                    let mode = if state.active_scanning.load(Ordering::SeqCst) { "A" } else { "P" };
                                    let version = res.version.map(|v| v.to_string()).unwrap_or_else(|| "unknown".to_string());
                                    info!("Discovered device {}(v{}) at {} - {}", res.id, version, res.ip, mode);
                                }

                                guard.insert(res.id.clone(), res.clone());
                                state.notify.notify_waiters();
                            }
                        }
                    }
                }
                debug!("Background passive listener task stopped");
            });
        }
    }

    fn spawn_receiver_tasks(
        sockets: Vec<Arc<UdpSocket>>,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> (
        mpsc::Receiver<(Vec<u8>, SocketAddr)>,
        Arc<tokio_util::sync::CancellationToken>,
    ) {
        let (tx, rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);
        let ct = Arc::new(cancel_token);

        for socket in sockets {
            let tx = tx.clone();
            let socket = socket.clone();
            let ct = ct.clone();
            crate::runtime::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    tokio::select! {
                        _ = ct.cancelled() => break,
                        res = socket.recv_from(&mut buf) => {
                            match res {
                                Ok((len, addr)) => {
                                    if tx.send((buf[..len].to_vec(), addr)).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            });
        }
        (rx, ct)
    }

    fn create_udp_socket(bind_addr: &str, port: u16) -> Result<UdpSocket> {
        let addr: SocketAddr = format!("{}:{}", bind_addr, port)
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

    fn new_silent() -> Self {
        Self {
            inner: Arc::new(ScannerState::new()),
            timeout: DEFAULT_SCAN_TIMEOUT,
            bind_addr: "0.0.0.0".to_string(),
            ports: vec![6666, 6667, 7000],
        }
    }

    /// Stops background passive listener.
    pub fn stop_passive_listener(&self) {
        self.inner.cancel_token.cancel();
        self.inner.listener_started.store(false, Ordering::SeqCst);
        self.inner.sockets.write().clear();
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = ports;
        self.ensure_passive_listener();
        self
    }

    pub fn with_bind_addr(mut self, addr: String) -> Self {
        self.bind_addr = addr;
        self.ensure_passive_listener();
        self
    }

    /// Returns a future that resolves when any device is discovered.
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.inner.notify.notified()
    }

    /// Checks if a device was discovered within the last `within` duration.
    pub fn is_recently_discovered(&self, device_id: &str, within: Duration) -> bool {
        let guard = self.inner.cache.read();
        if let Some(res) = guard.get(device_id) {
            return res.discovered_at.elapsed() < within;
        }
        false
    }

    fn get_local_ip(&self) -> Option<String> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        socket.local_addr().ok().map(|addr| addr.ip().to_string())
    }

    async fn send_discovery_broadcast(&self, socket: &UdpSocket, port: u16) -> Result<()> {
        let local_ip = self.get_local_ip().unwrap_or_else(|| "0.0.0.0".to_string());
        debug!(
            "Sending discovery broadcast on port {} (local IP: {})",
            port, local_ip
        );

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
        let broadcast_addr: SocketAddr = format!("255.255.255.255:{}", port)
            .parse()
            .map_err(|_| TuyaError::Offline)?;

        match socket.send_to(&packed, broadcast_addr).await {
            Ok(len) => debug!(
                "Sent discovery broadcast to {}: {} bytes",
                broadcast_addr, len
            ),
            Err(e) => warn!(
                "Failed to send discovery broadcast to {}: {}",
                broadcast_addr, e
            ),
        }

        Ok(())
    }

    /// Scans the local network for all Tuya devices and returns a stream of results.
    ///
    /// This will yield currently cached devices first, then any newly discovered devices
    /// until the scan timeout is reached. If a scan is already in progress, it will
    /// join the existing scan instead of starting a new one.
    pub fn scan_stream(
        &self,
    ) -> impl futures_util::Stream<Item = DiscoveryResult> + Send + 'static {
        let state = self.inner.clone();
        let timeout_dur = self.timeout;
        let start_time = Instant::now();
        let scanner = self.clone();

        // 1. Start a new scan if none is in progress and cooldown has passed
        let should_start = !state.active_scanning.load(Ordering::SeqCst) && {
            let last_scan = state.last_scan_time.read();
            last_scan.is_none_or(|t| t.elapsed() >= GLOBAL_SCAN_COOLDOWN)
        };

        if should_start {
            state.active_scanning.store(true, Ordering::SeqCst);
            *state.last_scan_time.write() = Some(Instant::now());
            let state_clone = state.clone();
            crate::runtime::spawn(async move {
                let _ = scanner.perform_discovery_loop().await;
                state_clone.active_scanning.store(false, Ordering::SeqCst);
                state_clone.notify.notify_waiters();
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
                    _ = tokio::time::sleep(remaining) => break,
                    _ = state.notify.notified() => {
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
    pub async fn scan(&self) -> Result<Vec<DiscoveryResult>> {
        use futures_util::StreamExt;

        info!(
            "Starting Tuya device scan (addr: {}, ports: {:?})...",
            self.bind_addr, self.ports
        );

        let results: Vec<_> = self.scan_stream().collect().await;

        info!("Scan finished. Found {} devices.", results.len());
        Ok(results)
    }

    pub async fn discover_device(&self, device_id: &str) -> Result<Option<DiscoveryResult>> {
        self.discover_device_internal(device_id, false).await
    }

    pub async fn discover_device_internal(
        &self,
        device_id: &str,
        force_scan: bool,
    ) -> Result<Option<DiscoveryResult>> {
        // 1. Check cache and cooldowns
        if let Some(res) = self.check_cache_and_cooldown(device_id, force_scan) {
            return Ok(Some(res));
        }

        // 2. Try to initiate or wait for scan
        self.ensure_scan_started(device_id, force_scan).await;

        // 3. Wait for the result to appear in cache
        Ok(self.wait_for_cache_result(device_id).await)
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
            debug!("Found device {} in discovery cache", device_id);
            return Some(res);
        }

        if !force_scan
            && let Some(last) = *state.last_scan_time.read()
            && last.elapsed() < GLOBAL_SCAN_COOLDOWN
            && let Some(res) = guard.get(device_id).cloned()
        {
            debug!(
                "Global scan cooldown active (30m). Returning cached result for {}.",
                device_id
            );
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
            info!("Initiating background scan for device ID: {}...", device_id);
            *state.last_scan_time.write() = Some(Instant::now());

            let scanner = self.clone();
            crate::runtime::spawn(async move {
                let _ = scanner.perform_discovery_loop().await;
                state.active_scanning.store(false, Ordering::SeqCst);
                state.notify.notify_waiters();
            });
        }
    }

    async fn wait_for_cache_result(&self, device_id: &str) -> Option<DiscoveryResult> {
        let state = &self.inner;
        let start_wait = Instant::now();

        loop {
            if let Some(res) = state.cache.read().get(device_id).cloned() {
                return Some(res);
            }

            let elapsed = start_wait.elapsed();
            if elapsed >= self.timeout || !state.active_scanning.load(Ordering::SeqCst) {
                // One last check before giving up
                return state.cache.read().get(device_id).cloned();
            }

            let remaining = self.timeout.saturating_sub(elapsed);
            let _ = tokio::time::timeout(remaining, state.notify.notified()).await;
        }
    }

    async fn perform_discovery_loop(self) -> Result<()> {
        let state = &self.inner;
        let mut target_sockets = Vec::new();

        {
            let guard = state.sockets.read();
            for &port in &self.ports {
                if let Some(socket) = guard.get(&port) {
                    target_sockets.push((socket.clone(), port));
                }
            }
        }

        if target_sockets.is_empty() {
            // If no sockets found in passive listener, try to ensure it's started for these ports
            self.ensure_passive_listener();
            let guard = state.sockets.read();
            for &port in &self.ports {
                if let Some(socket) = guard.get(&port) {
                    target_sockets.push((socket.clone(), port));
                }
            }
        }

        if target_sockets.is_empty() {
            return Err(std::io::Error::other("No available ports for scanning").into());
        }

        let start = Instant::now();
        let mut broadcast_interval = tokio::time::interval(BROADCAST_INTERVAL);
        let mut broadcast_count = 0;

        while start.elapsed() < self.timeout {
            let remaining = self.timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            tokio::select! {
                _ = tokio::time::sleep(remaining) => break,
                _ = broadcast_interval.tick() => {
                    if broadcast_count < 3 {
                        broadcast_count += 1;
                        debug!("Sent broadcast {}/3", broadcast_count);
                        for (socket, port) in &target_sockets {
                            let _ = self.send_discovery_broadcast(socket, *port).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_packet(&self, data: &[u8]) -> Option<DiscoveryResult> {
        trace!("Parsing UDP packet of {} bytes...", data.len());

        // 1. Try raw JSON (v3.1, port 6666)
        if let Ok(val) = serde_json::from_slice::<Value>(data) {
            trace!("Successfully parsed raw JSON packet");
            return self.parse_json(&val);
        }

        // 2. Try Tuya message format (55AA or 6699)
        let tries: &[(Option<&[u8]>, Option<bool>)] = &[
            (Some(UDP_KEY_35), Some(true)),
            (Some(UDP_KEY_35), Some(false)),
            (Some(UDP_KEY_35), None),
            (Some(UDP_KEY_34), Some(true)),
            (Some(UDP_KEY_34), Some(false)),
            (Some(UDP_KEY_34), None),
            (Some(UDP_KEY_33), Some(true)),
            (Some(UDP_KEY_33), Some(false)),
            (Some(UDP_KEY_33), None),
            (None, Some(true)),
            (None, Some(false)),
            (None, None),
        ];

        for (key, no_retcode) in tries {
            match protocol::unpack_message(data, *key, None, *no_retcode) {
                Ok(msg) => {
                    if msg.payload.is_empty() {
                        continue;
                    }

                    // 2a. Payload is raw JSON (v3.5 or unencrypted v3.3)
                    if let Ok(val) = serde_json::from_slice::<Value>(&msg.payload) {
                        trace!("Successfully parsed JSON from Tuya message payload");
                        return self.parse_json(&val);
                    }

                    // 2b. Payload is ECB encrypted (v3.3/v3.4)
                    let keys_to_try = if let Some(k) = key {
                        vec![*k]
                    } else {
                        vec![UDP_KEY_33, UDP_KEY_34, UDP_KEY_35]
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
                            return self.parse_json(&val);
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
                            "unpack_message failed with key {:?}: {}",
                            key.map(hex::encode),
                            e
                        );
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
                return self.parse_json(&val);
            }
        }

        // 4. Fallback: search for JSON start '{' in the packet
        if let Some(pos) = data.iter().position(|&b| b == b'{')
            && let Ok(val) = serde_json::from_slice::<Value>(&data[pos..])
        {
            trace!("Successfully found and parsed JSON from middle of packet");
            return self.parse_json(&val);
        }

        trace!("Failed to parse UDP packet");
        None
    }

    /// Invalidates the cache entry for a specific device.
    pub fn invalidate_cache(&self, id: &str) -> bool {
        let mut guard = self.inner.cache.write();
        guard.remove(id).is_some()
    }

    /// Extract device info from JSON.
    fn parse_json(&self, val: &Value) -> Option<DiscoveryResult> {
        let id = val
            .get("gwId")
            .or_else(|| val.get("devId"))
            .or_else(|| val.get("id"))
            .and_then(|v| v.as_str());
        let ip = val.get("ip").and_then(|v| v.as_str());

        if let (Some(id), Some(ip)) = (id, ip) {
            let ver_s = val.get("version").and_then(|v| v.as_str());
            let pk = val.get("productKey").and_then(|v| v.as_str());

            Some(DiscoveryResult {
                id: id.to_string(),
                ip: ip.to_string(),
                version: ver_s.and_then(|s| Version::from_str(s).ok()),
                product_key: pk.map(|s| s.to_string()),
                discovered_at: Instant::now(),
            })
        } else {
            None
        }
    }
}
