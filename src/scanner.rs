//! UDP-based device discovery and scanning.
//! Listens for Tuya broadcast packets and decodes device information.

use crate::crypto::TuyaCipher;
use crate::error::{Result, TuyaError};
use crate::protocol::{self, CommandType, PREFIX_6699, TuyaMessage, Version};
use log::{debug, error, info, warn};
use serde_json::Value;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};
use tokio::time::{Duration, Instant};

/// DiscoveryResult contains information about a discovered Tuya device.
#[derive(Debug, Clone)]
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
    pub discovered_at: Instant,
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
const GLOBAL_SCAN_COOLDOWN: Duration = Duration::from_secs(300); // 5 minutes

static DISCOVERY_CACHE: OnceLock<Arc<RwLock<HashMap<String, DiscoveryResult>>>> = OnceLock::new();
static SCAN_NOTIFY: OnceLock<Arc<Notify>> = OnceLock::new();
static SCAN_ACTIVE: AtomicBool = AtomicBool::new(false);
static LAST_SCAN_TIME: OnceLock<Arc<RwLock<Option<Instant>>>> = OnceLock::new();
static PASSIVE_LISTENER_STARTED: AtomicBool = AtomicBool::new(false);
static PASSIVE_CANCEL_TOKEN: OnceLock<tokio_util::sync::CancellationToken> = OnceLock::new();

struct ScanGuard;
impl Drop for ScanGuard {
    fn drop(&mut self) {
        SCAN_ACTIVE.store(false, Ordering::SeqCst);
    }
}

fn get_cache() -> Arc<RwLock<HashMap<String, DiscoveryResult>>> {
    DISCOVERY_CACHE
        .get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
        .clone()
}

fn get_last_scan_time() -> Arc<RwLock<Option<Instant>>> {
    LAST_SCAN_TIME
        .get_or_init(|| Arc::new(RwLock::new(None)))
        .clone()
}

fn get_notify() -> Arc<Notify> {
    SCAN_NOTIFY.get_or_init(|| Arc::new(Notify::new())).clone()
}

fn get_passive_cancel_token() -> tokio_util::sync::CancellationToken {
    PASSIVE_CANCEL_TOKEN
        .get_or_init(|| tokio_util::sync::CancellationToken::new())
        .clone()
}

/// Scanner discovers Tuya devices on the local network using UDP broadcast.
///
/// It supports various protocol versions (3.1 - 3.5) and can find devices
/// even if their IP addresses are unknown.
pub struct Scanner {
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
    /// Create a new Scanner with default settings.
    pub fn new() -> Self {
        let scanner = Self {
            timeout: Duration::from_secs(10),
            bind_addr: "0.0.0.0".to_string(),
            ports: vec![6666, 6667, 7000],
        };
        scanner.ensure_passive_listener();
        scanner
    }

    /// Ensures the background passive listener is running.
    fn ensure_passive_listener(&self) {
        if PASSIVE_LISTENER_STARTED.swap(true, Ordering::SeqCst) {
            return;
        }

        let ports = self.ports.clone();
        let bind_addr = self.bind_addr.clone();
        let cancel_token = get_passive_cancel_token();

        tokio::spawn(async move {
            debug!("Starting background passive listener...");
            let mut sockets = Vec::new();
            for port in ports {
                let addr: SocketAddr = match format!("{}:{}", bind_addr, port).parse() {
                    Ok(a) => a,
                    Err(_) => continue,
                };

                let socket = match Socket::new(
                    Domain::for_address(addr),
                    Type::DGRAM,
                    Some(Protocol::UDP),
                ) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                let _ = socket.set_reuse_address(true);
                let _ = socket.set_broadcast(true);
                if socket.bind(&SockAddr::from(addr)).is_ok() {
                    let _ = socket.set_nonblocking(true);
                    let std_socket: std::net::UdpSocket = socket.into();
                    if let Ok(tokio_socket) = UdpSocket::from_std(std_socket) {
                        sockets.push(Arc::new(tokio_socket));
                    }
                }
            }

            if sockets.is_empty() {
                warn!("Passive listener failed to bind to any ports");
                PASSIVE_LISTENER_STARTED.store(false, Ordering::SeqCst);
                return;
            }

            let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);

            for socket in sockets {
                let tx = tx.clone();
                let ct = cancel_token.clone();
                tokio::spawn(async move {
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

            let scanner_temp = Scanner::new_silent();
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    Some((data, _addr)) = rx.recv() => {
                        if let Some(res) = scanner_temp.parse_packet(&data) {
                            if let Ok(mut guard) = get_cache().write() {
                                guard.insert(res.id.clone(), res);
                                get_notify().notify_waiters();
                            }
                        }
                    }
                }
            }
            debug!("Background passive listener stopped");
        });
    }

    /// Internal constructor to avoid recursion in passive listener
    fn new_silent() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            bind_addr: "0.0.0.0".to_string(),
            ports: vec![6666, 6667, 7000],
        }
    }

    /// Stops the background passive listener.
    pub fn stop_passive_listener() {
        get_passive_cancel_token().cancel();
        PASSIVE_LISTENER_STARTED.store(false, Ordering::SeqCst);
    }

    /// Set discovery timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set ports to scan.
    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = ports;
        self
    }

    /// Get local IP address.
    fn get_local_ip(&self) -> Option<String> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        socket.local_addr().ok().map(|addr| addr.ip().to_string())
    }

    /// Send discovery broadcast for v3.x devices.
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

    /// Create and configure a UDP socket for a given port.
    fn create_socket(&self, port: u16) -> Result<UdpSocket> {
        let addr: SocketAddr = format!("{}:{}", self.bind_addr, port)
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        debug!("Creating UDP socket for port {}...", port);
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;

        if let Err(e) = socket.set_reuse_address(true) {
            warn!("Failed to set reuse_address on port {}: {}", port, e);
        }

        if let Err(e) = socket.set_broadcast(true) {
            warn!("Failed to set broadcast on port {}: {}", port, e);
        }

        match socket.bind(&SockAddr::from(addr)) {
            Ok(_) => debug!("Successfully bound to {}", addr),
            Err(e) => {
                error!("Failed to bind to {}: {}", addr, e);
                return Err(e.into());
            }
        }

        socket.set_nonblocking(true)?;

        let std_socket: std::net::UdpSocket = socket.into();
        Ok(UdpSocket::from_std(std_socket)?)
    }

    /// Scans the local network for all Tuya devices.
    ///
    /// Returns a list of all discovered devices and their basic information.
    /// This method will block until the timeout is reached.
    pub async fn scan(&self) -> Result<Vec<DiscoveryResult>> {
        info!(
            "Starting Tuya device scan (addr: {}, ports: {:?})...",
            self.bind_addr, self.ports
        );

        // Use perform_discovery_loop but return all found devices
        let _ = self.perform_discovery_loop(None).await?;

        let cache = get_cache();
        let guard = cache
            .read()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let results: Vec<_> = guard.values().cloned().collect();
        info!("Scan finished. Found {} devices.", results.len());
        Ok(results)
    }

    /// Discovers a specific device by its ID.
    ///
    /// If the device is already in the local cache, it returns immediately.
    /// Otherwise, it starts a network scan and waits for the device to respond
    /// or for the timeout to occur.
    pub async fn discover_device(&self, device_id: &str) -> Result<Option<DiscoveryResult>> {
        self.discover_device_internal(device_id, false).await
    }

    /// Internal version of discover_device that allows forcing a scan.
    pub async fn discover_device_internal(
        &self,
        device_id: &str,
        force_scan: bool,
    ) -> Result<Option<DiscoveryResult>> {
        loop {
            // 1. Check cache first (unless forced and cooldown passed)
            if !force_scan {
                if let Some(res) = get_cache()
                    .read()
                    .ok()
                    .and_then(|g| g.get(device_id).cloned())
                {
                    if res.discovered_at.elapsed() < Duration::from_secs(30 * 60) {
                        debug!("Found device {} in discovery cache", device_id);
                        return Ok(Some(res));
                    }
                    debug!("Cached device {} expired, re-scanning...", device_id);
                }
            } else {
                debug!("Force scan requested for device {}", device_id);
            }

            // 2. Check global cooldown if force_scan is requested
            if force_scan {
                let last_scan = get_last_scan_time().read().ok().and_then(|g| *g);
                if let Some(last) = last_scan {
                    if last.elapsed() < GLOBAL_SCAN_COOLDOWN {
                        debug!(
                            "Global scan cooldown active. Returning cached result if available."
                        );
                        if let Some(res) = get_cache()
                            .read()
                            .ok()
                            .and_then(|g| g.get(device_id).cloned())
                        {
                            return Ok(Some(res));
                        }
                    }
                }
            }

            // 3. Try to become the scan initiator
            if !SCAN_ACTIVE.swap(true, Ordering::SeqCst) {
                // We are the initiator
                let _guard = ScanGuard; // Automatically resets SCAN_ACTIVE on drop
                info!("Initiating scan for device ID: {}...", device_id);

                // Update last scan time
                if let Ok(mut guard) = get_last_scan_time().write() {
                    *guard = Some(Instant::now());
                }

                let result = self.perform_discovery_loop(Some(device_id)).await;

                // Notify others that a scan iteration has finished
                get_notify().notify_waiters();

                return result;
            } else {
                // 4. Scan already in progress, wait for notification but check cache periodically
                debug!(
                    "Scan already in progress, waiting for device {}...",
                    device_id
                );

                let notify = get_notify();
                let start_wait = Instant::now();

                while start_wait.elapsed() < self.timeout {
                    let notified = notify.notified();

                    // Check cache before waiting to avoid race condition
                    if let Some(res) = get_cache()
                        .read()
                        .ok()
                        .and_then(|g| g.get(device_id).cloned())
                    {
                        return Ok(Some(res));
                    }

                    // Wait for notification or global timeout
                    let remaining = self.timeout.saturating_sub(start_wait.elapsed());
                    if remaining.is_zero() {
                        break;
                    }

                    if tokio::time::timeout(remaining, notified).await.is_err() {
                        // Global timeout reached
                        break;
                    }
                }

                if start_wait.elapsed() >= self.timeout {
                    warn!("Timed out waiting for device {} discovery", device_id);
                    return Ok(None);
                }
            }
        }
    }

    /// Internal discovery loop that populates the cache.
    async fn perform_discovery_loop(
        &self,
        target_id: Option<&str>,
    ) -> Result<Option<DiscoveryResult>> {
        let mut sockets = Vec::new();
        for &port in &self.ports {
            match self.create_socket(port) {
                Ok(s) => sockets.push(Arc::new(s)),
                Err(e) => warn!("Failed to listen on port {}: {}", port, e),
            }
        }

        if sockets.is_empty() {
            return Err(std::io::Error::other("No available ports for scanning").into());
        }

        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);
        let cancel_token = Arc::new(tokio_util::sync::CancellationToken::new());

        // Spawn a receiver task for each socket
        for socket in &sockets {
            let tx = tx.clone();
            let socket = socket.clone();
            let ct = cancel_token.clone();
            tokio::spawn(async move {
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

        let start = Instant::now();
        let mut broadcast_interval = tokio::time::interval(BROADCAST_INTERVAL);
        let mut broadcast_count = 0;
        let mut result = None;

        while start.elapsed() < self.timeout {
            let remaining = self.timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            tokio::select! {
                _ = tokio::time::sleep(remaining) => break,
                _ = broadcast_interval.tick() => {
                    if broadcast_count < 2 {
                        for (socket, port) in sockets.iter().zip(self.ports.iter()) {
                            let _ = self.send_discovery_broadcast(socket, *port).await;
                        }
                        broadcast_count += 1;
                    }
                }
                Some((data, addr)) = rx.recv() => {
                    debug!("Received UDP packet from {}: {} bytes", addr, data.len());

                    if let Some(res) = self.parse_packet(&data) {
                        // Update cache for all discovered devices
                        if let Ok(mut guard) = get_cache().write() {
                            guard.insert(res.id.clone(), res.clone());
                            // Notify waiters that cache has been updated
                            get_notify().notify_waiters();
                        }

                        if let Some(tid) = target_id
                            && res.id == tid
                        {
                            info!(
                                "Found target device: ID={}, IP={}, version={:?}",
                                res.id, res.ip, res.version
                            );
                            result = Some(res);
                            break;
                        }
                    }
                }
            }
        }

        cancel_token.cancel();
        if let Some(tid) = target_id
            && result.is_none()
        {
            debug!("Device ID {} not found within timeout.", tid);
        }
        Ok(result)
    }

    /// Parse a received UDP packet into a DiscoveryResult.
    fn parse_packet(&self, data: &[u8]) -> Option<DiscoveryResult> {
        debug!("Parsing UDP packet of {} bytes...", data.len());

        // 1. Try raw JSON (v3.1, port 6666)
        if let Ok(val) = serde_json::from_slice::<Value>(data) {
            debug!("Successfully parsed raw JSON packet");
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
                        debug!("Successfully parsed JSON from Tuya message payload");
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
                            debug!(
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
                        debug!(
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
                debug!("Successfully decrypted and parsed JSON from entire packet");
                return self.parse_json(&val);
            }
        }

        // 4. Fallback: search for JSON start '{' in the packet
        if let Some(pos) = data.iter().position(|&b| b == b'{')
            && let Ok(val) = serde_json::from_slice::<Value>(&data[pos..])
        {
            debug!("Successfully found and parsed JSON from middle of packet");
            return self.parse_json(&val);
        }

        debug!("Failed to parse UDP packet");
        None
    }

    /// Invalidates a specific device from the cache.
    pub fn invalidate_cache(&self, device_id: &str) -> bool {
        if let Ok(mut guard) = get_cache().write() {
            guard.remove(device_id).is_some()
        } else {
            false
        }
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
