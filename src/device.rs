//! Tuya device communication and state management.
//!
//! Handles TCP connections, handshakes, heartbeats, and command-response flows.

use crate::crypto::TuyaCipher;
use crate::error::{
    ERR_DEVTYPE, ERR_JSON, ERR_OFFLINE, ERR_PAYLOAD, ERR_SUCCESS, Result, TuyaError,
    get_error_message,
};
use crate::protocol::{
    CommandType, DeviceType, PREFIX_55AA, PREFIX_6699, TuyaHeader, TuyaMessage, Version,
    get_protocol, pack_message, parse_header, unpack_message,
};
use crate::scanner::Scanner;
use futures_core::stream::Stream;
use hex;
use hmac::{Hmac, Mac};
use log::{debug, error, info, trace, warn};
use parking_lot::RwLock;
use rand::RngCore;
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, sleep, timeout};
use tokio_util::sync::CancellationToken;

const SLEEP_HEARTBEAT_DEFAULT: Duration = Duration::from_secs(7);
const SLEEP_HEARTBEAT_CHECK: Duration = Duration::from_secs(5);
const SLEEP_RECONNECT_MIN: Duration = Duration::from_secs(1);
const SLEEP_RECONNECT_MAX: Duration = Duration::from_secs(1024);
const SLEEP_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);

const ADDR_AUTO: &str = "Auto";
const DATA_UNVALID: &str = "data unvalid";

const CHAN_BROADCAST_CAPACITY: usize = 128;
const CHAN_MPSC_CAPACITY: usize = 64;

mod keys {
    pub const REQ_TYPE: &str = "reqType";

    // Response keys
    pub const ERR_CODE: &str = "errorCode";
    pub const ERR_MSG: &str = "errorMsg";
    pub const ERR_PAYLOAD_OBJ: &str = "errorPayload";
    pub const PAYLOAD_STR: &str = "payloadStr";
    pub const PAYLOAD_RAW: &str = "payloadRaw";
}

/// A sub-device (endpoint) of a gateway device.
///
/// Note: Holding a `SubDevice` will keep the parent `Device` alive because it contains
/// an internal `Arc` reference to the parent.
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

    pub fn id(&self) -> &str {
        &self.cid
    }

    pub async fn status(&self) {
        self.request(CommandType::DpQuery, None).await
    }

    pub async fn set_dps(&self, dps: Value) {
        self.request(CommandType::Control, Some(dps)).await
    }

    /// Sets a single DP value by its ID.
    /// The `index` can be provided as any type that can be converted to a String (e.g., u32, &str).
    /// The `value` can be any type that implements `Serialize` (e.g., bool, i32, String, serde_json::Value).
    pub async fn set_value<I: ToString, T: Serialize>(&self, index: I, value: T) {
        if let Ok(val) = serde_json::to_value(value) {
            self.set_dps(serde_json::json!({ index.to_string(): val }))
                .await
        }
    }

    pub async fn request(&self, cmd: CommandType, data: Option<Value>) {
        self.parent.request(cmd, data, Some(self.cid.clone())).await
    }
}

enum DeviceCommand {
    Request {
        command: CommandType,
        data: Option<Value>,
        cid: Option<String>,
        resp_tx: oneshot::Sender<Result<()>>,
    },
    Disconnect,
    ConnectNow,
}

impl DeviceCommand {
    fn respond(self, result: Result<()>) {
        if let DeviceCommand::Request { resp_tx, .. } = self {
            let _ = resp_tx.send(result);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Stopped,
}

struct DeviceState {
    config_address: String,
    real_ip: String,
    version: Version,
    dev_type: DeviceType,
    state: ConnectionState,
    last_received: Instant,
    last_sent: Instant,
    persist: bool,
    session_key: Option<Vec<u8>>,
    failure_count: u32,
    success_count: u32,
    force_discovery: bool,
    connection_timeout: Duration,
}

pub struct DeviceBuilder {
    id: String,
    address: String,
    local_key: Vec<u8>,
    version: Version,
    port: u16,
    persist: bool,
    connection_timeout: Duration,
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
            port: 6668,
            persist: true,
            connection_timeout: Duration::from_secs(10),
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

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn persist(mut self, persist: bool) -> Self {
        self.persist = persist;
        self
    }

    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    pub fn build(self) -> Device {
        Device::with_builder(self)
    }
}

#[derive(Clone)]
pub struct Device {
    id: String,
    local_key: Vec<u8>,
    port: u16,
    state: Arc<RwLock<DeviceState>>,
    tx: Option<mpsc::Sender<DeviceCommand>>,
    pub(crate) broadcast_tx: tokio::sync::broadcast::Sender<TuyaMessage>,
    scanner: Arc<Scanner>,
    cancel_token: CancellationToken,
}

impl Device {
    pub fn new<I, A, K, V>(id: I, address: A, local_key: K, version: V) -> Self
    where
        I: Into<String>,
        A: Into<String>,
        K: Into<Vec<u8>>,
        V: Into<Version>,
    {
        DeviceBuilder::new(id, local_key)
            .address(address)
            .version(version)
            .build()
    }

    pub(crate) fn with_builder(builder: DeviceBuilder) -> Self {
        let (addr, ip) = match builder.address.as_str() {
            "" | ADDR_AUTO => (ADDR_AUTO.to_string(), "".to_string()),
            _ => (builder.address.clone(), builder.address),
        };
        let dev_type = DeviceType::from(builder.version.val());

        let (broadcast_tx, _) = tokio::sync::broadcast::channel(CHAN_BROADCAST_CAPACITY);
        let (tx, rx) = mpsc::channel(CHAN_MPSC_CAPACITY);
        let state = DeviceState {
            config_address: addr,
            real_ip: ip,
            version: builder.version,
            dev_type,
            state: ConnectionState::Disconnected,
            last_received: Instant::now(),
            last_sent: Instant::now(),
            persist: builder.persist,
            session_key: None,
            failure_count: 0,
            success_count: 0,
            force_discovery: false,
            connection_timeout: builder.connection_timeout,
        };

        let device = Self {
            id: builder.id,
            local_key: builder.local_key,
            port: builder.port,
            state: Arc::new(RwLock::new(state)),
            tx: Some(tx),
            broadcast_tx,
            scanner: Arc::new(Scanner::new()),
            cancel_token: CancellationToken::new(),
        };

        let cancel_token = device.cancel_token.clone();
        let d_clone = device.clone();
        let d_id = device.id.clone();
        crate::runtime::spawn(async move {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    debug!("Device {} connection task stopped via token", d_id);
                }
                _ = d_clone.run_connection_task(rx) => {
                    debug!("Device {} connection task finished", d_id);
                }
            }
        });
        device
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn dev_type(&self) -> DeviceType {
        self.with_state(|s| s.dev_type)
    }

    pub fn local_key(&self) -> &[u8] {
        &self.local_key
    }

    pub fn address(&self) -> String {
        self.with_state(|s| {
            if s.real_ip.is_empty() {
                s.config_address.clone()
            } else {
                s.real_ip.clone()
            }
        })
    }

    pub fn version(&self) -> Version {
        self.with_state(|s| s.version)
    }

    pub fn set_persist(&self, persist: bool) {
        self.with_state_mut(|s| s.persist = persist);
    }

    pub fn set_connection_timeout(&self, timeout: Duration) {
        self.with_state_mut(|s| s.connection_timeout = timeout);
    }

    fn connection_timeout(&self) -> Duration {
        self.with_state(|s| s.connection_timeout)
    }

    pub fn is_connected(&self) -> bool {
        self.with_state(|s| s.state == ConnectionState::Connected)
    }

    pub fn is_stopped(&self) -> bool {
        self.with_state(|s| s.state == ConnectionState::Stopped)
    }

    pub fn set_version<V: Into<Version>>(&self, version: V) {
        let ver = version.into();
        let dev_type = DeviceType::from(ver.val());

        self.with_state_mut(|s| {
            s.version = ver;
            s.dev_type = dev_type;
        });
    }

    pub fn set_dev_type(&self, dev_type: DeviceType) {
        self.with_state_mut(|s| s.dev_type = dev_type);
    }

    fn with_state<R>(&self, f: impl FnOnce(&DeviceState) -> R) -> R {
        f(&self.state.read())
    }

    fn with_state_mut<R>(&self, f: impl FnOnce(&mut DeviceState) -> R) -> R {
        f(&mut self.state.write())
    }

    fn broadcast_error(&self, code: u32, payload: Option<Value>) {
        let _ = self.broadcast_tx.send(self.error_helper(code, payload));
    }

    fn update_last_received(&self) {
        self.state.write().last_received = Instant::now();
    }

    fn update_last_sent(&self) {
        self.state.write().last_sent = Instant::now();
    }

    fn reset_failure_count(&self) {
        let mut state = self.state.write();
        state.success_count += 1;
        if state.failure_count > 0 && state.success_count >= 3 {
            debug!(
                "Resetting failure count for device {} (success_count: {})",
                self.id, state.success_count
            );
            state.failure_count = 0;
            state.success_count = 0;
        }
    }

    async fn send_to_task(&self, cmd: DeviceCommand) {
        if let Some(tx) = &self.tx {
            if let Err(e) = tx.send(cmd).await {
                error!("Failed to queue command for device {}: {}", self.id, e);
            }
        } else {
            error!(
                "Cannot send command for device {}: task not running",
                self.id
            );
        }
    }

    pub fn listener(&self) -> impl Stream<Item = Result<TuyaMessage>> + Send + 'static {
        let mut rx = self.broadcast_tx.subscribe();
        async_stream::stream! {
            while let Ok(msg) = rx.recv().await {
                yield Ok(msg);
            }
        }
    }

    pub async fn status(&self) {
        self.request(CommandType::DpQuery, None, None).await
    }

    /// Sets multiple DP values at once.
    /// The `dps` argument should be a `serde_json::Value` object where keys are DP IDs.
    pub async fn set_dps(&self, dps: Value) {
        self.request(CommandType::Control, Some(dps), None).await
    }

    /// Sets a single DP value by its ID.
    /// The `dp_id` can be provided as any type that can be converted to a String (e.g., u32, &str).
    /// The `value` can be any type that implements `Serialize` (e.g., bool, i32, String, serde_json::Value).
    pub async fn set_value<I: ToString, T: Serialize>(&self, dp_id: I, value: T) {
        if let Ok(val) = serde_json::to_value(value) {
            self.set_dps(serde_json::json!({ dp_id.to_string(): val }))
                .await
        }
    }

    pub fn sub(&self, cid: &str) -> SubDevice {
        SubDevice::new(self.clone(), cid)
    }

    async fn generate_payload(
        &self,
        command: CommandType,
        mut data: Option<Value>,
        cid: Option<&str>,
    ) -> Result<(u32, Value)> {
        let (version, dev_type) = self.with_state(|s| (s.version, s.dev_type));
        let t = self.get_timestamp();
        let protocol = get_protocol(version, dev_type);

        // Extract reqType from data if present
        let mut req_type = None;
        if let Some(Value::Object(ref mut map)) = data
            && let Some(Value::String(rt)) = map.remove(keys::REQ_TYPE)
        {
            req_type = Some(rt);
        }

        let (cmd_to_send, mut payload_val) =
            protocol.generate_payload(&self.id, command, data, cid, t)?;

        if let Some(rt) = req_type
            && let Some(obj) = payload_val.as_object_mut()
        {
            obj.insert(keys::REQ_TYPE.into(), rt.into());
        }

        Ok((cmd_to_send, payload_val))
    }

    pub async fn sub_discover(&self) {
        let data = serde_json::json!({
            "cids": [],
            keys::REQ_TYPE: "subdev_online_stat_query"
        });
        self.request(CommandType::LanExtStream, Some(data), None)
            .await
    }

    pub async fn receive(&self) -> Result<TuyaMessage> {
        let mut rx = self.broadcast_tx.subscribe();
        rx.recv().await.map_err(|e| TuyaError::Io(e.to_string()))
    }

    pub async fn close(&self) {
        info!("Closing connection to device {}", self.id);

        self.with_state_mut(|state| {
            if state.state != ConnectionState::Stopped {
                state.state = ConnectionState::Disconnected;
            }
        });

        if let Some(tx) = &self.tx {
            let _ = tx.send(DeviceCommand::Disconnect).await;
        }
    }

    pub async fn stop(&self) {
        info!("Stopping device {} (explicit stop called)", self.id);
        self.with_state_mut(|state| {
            state.state = ConnectionState::Stopped;
        });
        self.cancel_token.cancel();
        self.close().await;
    }

    /// Forces the device to attempt a connection immediately, bypassing any backoff.
    pub async fn connect_now(&self) {
        self.send_to_task(DeviceCommand::ConnectNow).await;
    }

    fn get_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    async fn send_command_to_task(
        &self,
        cmd_generator: impl FnOnce(oneshot::Sender<Result<()>>) -> DeviceCommand,
    ) {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.send_to_task(cmd_generator(resp_tx)).await;
        let _ = resp_rx.await;
    }

    pub async fn request(&self, command: CommandType, data: Option<Value>, cid: Option<String>) {
        debug!("request: cmd={:?}, data={:?}", command, data);
        self.send_command_to_task(|resp_tx| DeviceCommand::Request {
            command,
            data,
            cid,
            resp_tx,
        })
        .await;
    }

    async fn run_connection_task(mut self, mut rx: mpsc::Receiver<DeviceCommand>) {
        self.tx = None;

        let jitter = {
            let mut rng = rand::rng();
            Duration::from_millis((rng.next_u32() % 5000) as u64)
        };

        debug!(
            "Starting background connection task for device {} with {:?} initial jitter",
            self.id, jitter
        );

        // Stagger initial connection attempts to avoid "thundering herd" problem
        // when managing many devices.
        tokio::select! {
            _ = self.cancel_token.cancelled() => return,
            _ = tokio::time::sleep(jitter) => {}
        }

        let mut heartbeat_interval = tokio::time::interval(SLEEP_HEARTBEAT_CHECK);
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    debug!("Background task for {} received stop signal", self.id);
                    break;
                }
                res = async {
                    if self.is_stopped() {
                        return Some(());
                    }

                    // Reset seqno for each new connection attempt
                    let mut seqno = 1u32;

                    // 1. Attempt to connect and handshake
                    let stream = match self
                        .try_connect_with_backoff(&mut rx, &mut seqno)
                        .await
                    {
                        Some(s) => s,
                        None => return Some(()), // rx closed or stopped
                    };

                    // 2. Main loop for the active connection
                    let result = self
                        .maintain_connection(stream, &mut rx, &mut seqno, &mut heartbeat_interval)
                        .await;

                    // Cleanup on connection loss
                    self.handle_disconnect(result.as_ref().err().cloned());

                    // Drain any pending commands immediately upon connection loss
                    if let Err(e) = result {
                        self.with_state_mut(|s| {
                            s.failure_count += 1;
                            s.success_count = 0;
                        });
                        self.drain_rx(&mut rx, e, false);
                    } else {
                        // If maintain_connection returned Ok(()), it means it stopped normally (e.g. rx closed)
                        return Some(());
                    }

                    // If maintain_connection returned because rx was closed, exit the outer loop too
                    if self.is_stopped() {
                        return Some(());
                    }

                    None
                } => {
                    if res.is_some() {
                        break;
                    }
                }
            }
        }

        // Ensure all associated tasks (like the Reader task) are stopped
        self.cancel_token.cancel();
        debug!("Background connection task for {} exited", self.id);
    }

    fn handle_disconnect(&self, err: Option<TuyaError>) {
        self.with_state_mut(|s| {
            if s.state != ConnectionState::Stopped {
                s.state = ConnectionState::Disconnected;
            }
            s.session_key = None; // Clear session key on disconnect
        });

        if let Some(e) = err {
            if matches!(e, TuyaError::KeyOrVersionError) {
                warn!(
                    "Device {} possibly has key or version mismatch (Error 914)",
                    self.id
                );
            } else if !self.is_stopped() {
                debug!("Connection lost for device {} due to error: {}", self.id, e);
            }

            if !self.is_stopped() {
                self.broadcast_error(e.code(), None);
            }
        } else if !self.is_stopped() {
            debug!("Connection closed normally for device {}", self.id);
            self.broadcast_error(ERR_OFFLINE, None);
        }
    }

    fn drain_rx(&self, rx: &mut mpsc::Receiver<DeviceCommand>, err: TuyaError, close: bool) {
        if close {
            rx.close();
        }
        while let Ok(cmd) = rx.try_recv() {
            cmd.respond(Err(err.clone()));
        }
    }

    async fn try_connect_with_backoff(
        &self,
        rx: &mut mpsc::Receiver<DeviceCommand>,
        seqno: &mut u32,
    ) -> Option<TcpStream> {
        loop {
            if self.is_stopped() {
                self.drain_rx(rx, TuyaError::Offline, true);
                return None;
            }

            // Reset seqno to 1 for every new TCP connection attempt
            *seqno = 1;

            // If we have failures, wait before the next attempt
            let backoff = self.with_state(|s| {
                if s.failure_count > 0 {
                    Some((
                        self.get_backoff_duration(s.failure_count - 1),
                        s.failure_count,
                    ))
                } else {
                    None
                }
            });

            if let Some((b, count)) = backoff {
                warn!(
                    "Waiting {}s before next connection attempt for {} (fail count: {})",
                    b.as_secs(),
                    self.id,
                    count
                );
                self.wait_for_backoff(rx, b).await?;
            }

            let result = timeout(
                self.connection_timeout() * 2,
                self.connect_and_handshake(seqno),
            )
            .await;
            match result {
                Ok(Ok(s)) => {
                    self.with_state_mut(|s| s.state = ConnectionState::Connected);
                    info!(
                        "Connected to device {} ({})",
                        self.id,
                        self.with_state(|s| s.real_ip.clone())
                    );
                    self.broadcast_error(ERR_SUCCESS, None);
                    return Some(s);
                }
                _ => {
                    let e = match result {
                        Ok(Err(e)) => e,
                        _ => TuyaError::Offline,
                    };

                    self.handle_connection_error(&e).await;
                    self.drain_rx(rx, e.clone(), false);

                    if !self.with_state(|s| s.persist) {
                        error!(
                            "Connection failed (persist: false) for device {}: {}",
                            self.id, e
                        );
                        self.drain_rx(rx, e, true);
                        return None;
                    }

                    self.with_state_mut(|s| {
                        s.failure_count += 1;
                        s.success_count = 0;
                        // For Auto mode, set force_discovery on relevant errors
                        if s.config_address == ADDR_AUTO {
                            match e {
                                TuyaError::KeyOrVersionError | TuyaError::Offline => {
                                    debug!(
                                        "Setting force_discovery for {} due to error: {}",
                                        self.id, e
                                    );
                                    s.force_discovery = true;
                                    // Invalidate cache entry to ensure fresh discovery
                                    let _ = self.scanner.invalidate_cache(&self.id);
                                }
                                _ => {}
                            }
                        }
                    });
                }
            }
        }
    }

    async fn wait_for_backoff(
        &self,
        rx: &mut mpsc::Receiver<DeviceCommand>,
        backoff: Duration,
    ) -> Option<()> {
        let sleep_fut = sleep(backoff);
        tokio::pin!(sleep_fut);

        let discovery_notified = self.scanner.notified();
        tokio::pin!(discovery_notified);

        loop {
            tokio::select! {
                _ = &mut sleep_fut => return Some(()),
                _ = &mut discovery_notified => {
                    if self.scanner.is_recently_discovered(&self.id, Duration::from_secs(10)) {
                        debug!("Device {} discovered during backoff, waking up!", self.id);
                        return Some(());
                    }
                    // Re-arm the notification for the next discovery
                    discovery_notified.set(self.scanner.notified());
                }
                _ = self.cancel_token.cancelled() => {
                    self.drain_rx(rx, TuyaError::Offline, true);
                    return None;
                }
                cmd_opt = rx.recv() => {
                    if let Some(cmd) = cmd_opt {
                        match cmd {
                            DeviceCommand::ConnectNow => return Some(()),
                            _ => {
                                debug!("Rejecting command during backoff for device {}", self.id);
                                cmd.respond(Err(TuyaError::Offline));
                                self.broadcast_error(ERR_OFFLINE, None);
                            }
                        }
                    } else {
                        return None;
                    }
                }
            }
        }
    }

    async fn maintain_connection(
        &self,
        stream: TcpStream,
        rx: &mut mpsc::Receiver<DeviceCommand>,
        seqno: &mut u32,
        heartbeat_interval: &mut tokio::time::Interval,
    ) -> Result<()> {
        let (mut read_half, mut write_half) = stream.into_split();
        let (internal_tx, mut internal_rx) = mpsc::channel::<TuyaError>(1);

        let device_clone = self.clone();
        let connection_cancel_token = CancellationToken::new();
        let reader_cancel_token = connection_cancel_token.clone();
        let parent_cancel_token = self.cancel_token.clone();

        // Reader Task
        crate::runtime::spawn(async move {
            let mut packets_received = 0;
            loop {
                tokio::select! {
                    _ = parent_cancel_token.cancelled() => break,
                    _ = reader_cancel_token.cancelled() => break,
                    res = timeout(SLEEP_INACTIVITY_TIMEOUT, read_half.read_u8()) => {
                        match res {
                            Ok(Ok(byte)) => {
                                if let Err(e) = device_clone.process_socket_data(&mut read_half, byte).await {
                                    let _ = internal_tx.send(e).await;
                                    break;
                                }
                                packets_received += 1;
                            }
                            Ok(Err(e)) => {
                                let err = if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                    if packets_received > 0 {
                                        // Communication was working, now it's just a connection loss
                                        TuyaError::Io("Connection reset by peer".to_string())
                                    } else {
                                        // Dropped right at the start, likely wrong key/version
                                        TuyaError::KeyOrVersionError
                                    }
                                } else {
                                    TuyaError::Io(e.to_string())
                                };
                                let _ = internal_tx.send(err).await;
                                break;
                            }
                            Err(_) => {
                                // Timeout reached
                                if !device_clone.is_stopped() {
                                    warn!("Inactivity timeout ({}s) reached for device {}", SLEEP_INACTIVITY_TIMEOUT.as_secs(), device_clone.id);
                                }
                                let _ = internal_tx.send(TuyaError::Timeout).await;
                                break;
                            }
                        }
                    }
                }
            }
            debug!("Reader task for {} stopped", device_clone.id);
        });

        let result = async {
            loop {
                tokio::select! {
                    _ = self.cancel_token.cancelled() => {
                        return Ok(());
                    }
                    cmd_opt = rx.recv() => {
                    match cmd_opt {
                        Some(cmd) => {
                            if let Err(e) = self.process_command(&mut write_half, seqno, cmd).await {
                                if !self.is_stopped() {
                                    error!("Command processing failed for {}: {}", self.id, e);
                                }
                                return Err(e);
                            }
                        }
                        None => {
                                debug!("All handles for device {} dropped, stopping task", self.id);
                                self.state.write().state = ConnectionState::Stopped;
                                return Ok(());
                            }
                        }
                    }
                    _ = heartbeat_interval.tick() => {
                        if let Err(e) = self.process_heartbeat(&mut write_half, seqno).await {
                            error!("Heartbeat failed for {}: {}", self.id, e);
                            return Err(e);
                        }
                    }
                    err_opt = internal_rx.recv() => {
                        if let Some(e) = err_opt {
                            error!("Connection closed due to reader task error for {}: {}", self.id, e);
                            return Err(e);
                        }
                    }
                }
            }
        }.await;

        connection_cancel_token.cancel();
        result
    }

    async fn process_command<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        seqno: &mut u32,
        cmd: DeviceCommand,
    ) -> Result<()> {
        match cmd {
            DeviceCommand::Request {
                command,
                data,
                cid,
                resp_tx,
            } => {
                let res = async {
                    let (cmd_id, payload) =
                        self.generate_payload(command, data, cid.as_deref()).await?;
                    debug!("Sending command: cmd=0x{:02X}, seqno={}", cmd_id, *seqno);
                    self.send_json_msg(stream, seqno, cmd_id, &payload).await
                }
                .await;
                let _ = resp_tx.send(res);
            }
            DeviceCommand::Disconnect => {
                debug!("Disconnect command received for device {}", self.id);
                return Err(TuyaError::Offline);
            }
            DeviceCommand::ConnectNow => {
                debug!(
                    "Device {} is already connected, ignoring ConnectNow",
                    self.id
                );
            }
        }
        Ok(())
    }

    async fn send_json_msg<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        seqno: &mut u32,
        cmd: u32,
        payload: &Value,
    ) -> Result<()> {
        let payload_bytes = serde_json::to_vec(payload).unwrap_or_default();
        let msg = self.build_message(seqno, cmd, payload_bytes);
        self.send_raw_to_stream(stream, msg).await
    }

    async fn handle_connection_error(&self, e: &TuyaError) {
        self.with_state_mut(|s| {
            if s.state != ConnectionState::Stopped {
                s.state = ConnectionState::Disconnected;
            }
        });
        self.broadcast_error(e.code(), Some(serde_json::json!(format!("{}", e))));
    }

    async fn process_socket_data<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        first_byte: u8,
    ) -> Result<()> {
        if let Some(msg) = self.read_and_parse_from_stream(stream, first_byte).await? {
            self.update_last_received();
            self.reset_failure_count();
            debug!(
                "Received message: cmd=0x{:02X}, payload_len={}",
                msg.cmd,
                msg.payload.len()
            );
            if !msg.payload.is_empty() {
                // Check if payload is valid JSON
                if serde_json::from_slice::<Value>(&msg.payload).is_err() {
                    debug!("Non-JSON payload detected, broadcasting as ERR_JSON");
                    let payload_hex = hex::encode(&msg.payload);
                    self.broadcast_error(
                        ERR_JSON,
                        Some(serde_json::json!({
                            keys::PAYLOAD_RAW: payload_hex,
                            "cmd": msg.cmd
                        })),
                    );
                } else {
                    let _ = self.broadcast_tx.send(msg);
                }
            } else {
                // Version 3.5 gateways often send an empty 0x40 as an ACK,
                // but may not follow up with actual data in some cases.
                debug!("Received empty payload message, not broadcasting");
            }
        }
        Ok(())
    }

    async fn process_heartbeat<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        seqno: &mut u32,
    ) -> Result<()> {
        let last = self.with_state(|s| s.last_sent);

        if last.elapsed() >= SLEEP_HEARTBEAT_DEFAULT {
            debug!("Auto-heartbeat for device {}", self.id);
            let (cmd, payload) = self.generate_heartbeat_payload()?;
            self.send_json_msg(stream, seqno, cmd, &payload).await?;
        }
        Ok(())
    }

    async fn connect_and_handshake(&self, seqno: &mut u32) -> Result<TcpStream> {
        let addr = self.resolve_address().await?;

        info!("Connecting to device {} at {}:{}", self.id, addr, self.port);
        let mut stream = timeout(
            self.connection_timeout(),
            TcpStream::connect(format!("{}:{}", addr, self.port)),
        )
        .await
        .map_err(|_| TuyaError::Timeout)?
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::ConnectionRefused => TuyaError::ConnectionFailed,
            _ => TuyaError::Io(e.to_string()),
        })?;

        if self.version().val() >= 3.4 && !self.negotiate_session_key(&mut stream, seqno).await? {
            return Err(TuyaError::KeyOrVersionError);
        }

        Ok(stream)
    }

    async fn resolve_address(&self) -> Result<String> {
        let (config_addr, force_discovery, version) =
            self.with_state(|s| (s.config_address.clone(), s.force_discovery, s.version));

        let ip_explicit =
            config_addr != "Auto" && config_addr != "0.0.0.0" && !config_addr.is_empty();
        let ver_explicit = version != Version::Auto;

        if ip_explicit && ver_explicit && !force_discovery {
            return Ok(config_addr);
        }

        debug!(
            "Resolving address/version for device {} (config_addr={}, version={}, force={})",
            self.id, config_addr, version, force_discovery
        );
        if let Ok(Some(result)) = self
            .scanner
            .discover_device_internal(&self.id, force_discovery)
            .await
        {
            let found_addr = result.ip;
            let found_version = result.version;

            if let Some(v) = found_version
                && self.version() == Version::Auto
            {
                debug!("Auto-detected version {} for device {}", v, self.id);
                self.set_version(v);
            }

            let version_str = self.version().to_string();

            if ip_explicit {
                debug!(
                    "Using explicit address {} for device {} (v{})",
                    config_addr, self.id, version_str
                );
                self.with_state_mut(|s| {
                    s.real_ip = config_addr.clone();
                    s.force_discovery = false;
                });
                Ok(config_addr)
            } else {
                debug!(
                    "Using discovered address {} for device {} (v{})",
                    found_addr, self.id, version_str
                );
                self.with_state_mut(|s| {
                    s.real_ip = found_addr.clone();
                    s.force_discovery = false;
                });
                Ok(found_addr)
            }
        } else if ip_explicit {
            // Discovery failed but we have an explicit IP, try using it anyway
            warn!(
                "Discovery failed for device {}, attempting connection with explicit IP {}",
                self.id, config_addr
            );
            self.with_state_mut(|s| {
                s.real_ip = config_addr.clone();
                s.force_discovery = false;
            });
            Ok(config_addr)
        } else {
            Err(TuyaError::Offline)
        }
    }

    async fn send_raw_to_stream<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        msg: TuyaMessage,
    ) -> Result<()> {
        let packed = self.pack_msg(msg)?;
        timeout(self.connection_timeout(), stream.write_all(&packed))
            .await
            .map_err(|_| {
                TuyaError::Io(
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "Write timeout").to_string(),
                )
            })?
            .map_err(TuyaError::from)?;

        self.update_last_sent();
        Ok(())
    }

    async fn read_and_parse_from_stream<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        first_byte: u8,
    ) -> Result<Option<TuyaMessage>> {
        let prefix = match self.scan_for_prefix(stream, first_byte).await? {
            Some(p) => p,
            None => return Ok(None),
        };

        // Read remaining 12 bytes of header (16 bytes total)
        let mut header_buf = [0u8; 16];
        header_buf[0..4].copy_from_slice(&prefix);
        timeout(
            self.connection_timeout(),
            stream.read_exact(&mut header_buf[4..]),
        )
        .await
        .map_err(|_| {
            TuyaError::Io(
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Read header timeout")
                    .to_string(),
            )
        })?
        .map_err(TuyaError::from)?;

        // Parse and read body
        let dev_type_before = self.dev_type();
        match self.parse_and_read_body(stream, header_buf).await {
            Ok(Some(msg)) => {
                if dev_type_before != DeviceType::Device22
                    && self.dev_type() == DeviceType::Device22
                {
                    debug!("Device22 transition detected, reporting with original payload");
                    let original_payload = if msg.payload.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_slice(&msg.payload).unwrap_or_else(
                            |_| serde_json::json!({ keys::PAYLOAD_RAW: hex::encode(&msg.payload) }),
                        )
                    };
                    return Ok(Some(self.error_helper(ERR_DEVTYPE, Some(original_payload))));
                }
                Ok(Some(msg))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                if matches!(e, TuyaError::Io(_)) {
                    return Err(e);
                }
                warn!("Error parsing message from {}: {}", self.id, e);
                Ok(Some(self.error_helper(
                    ERR_PAYLOAD,
                    Some(serde_json::json!(format!("{}", e))),
                )))
            }
        }
    }

    async fn scan_for_prefix<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        first_byte: u8,
    ) -> Result<Option<[u8; 4]>> {
        let mut buf = [0u8; 4];
        buf[0] = first_byte;

        macro_rules! read_byte {
            () => {
                timeout(self.connection_timeout(), stream.read_u8())
                    .await
                    .map_err(|_| TuyaError::Timeout)?
                    .map_err(TuyaError::from)?
            };
        }

        for b in &mut buf[1..] {
            *b = read_byte!();
        }

        for _ in 0..1024 {
            let val = u32::from_be_bytes(buf);
            if val == PREFIX_55AA || val == PREFIX_6699 {
                return Ok(Some(buf));
            }
            buf.rotate_left(1);
            buf[3] = read_byte!();
        }
        Ok(None)
    }

    fn base_payload(&self) -> Value {
        serde_json::json!({
            "gwId": self.id,
            "devId": self.id,
        })
    }

    fn generate_heartbeat_payload(&self) -> Result<(u32, Value)> {
        Ok((CommandType::HeartBeat as u32, self.base_payload()))
    }

    fn build_message<P: Into<Vec<u8>>>(
        &self,
        seqno: &mut u32,
        cmd: u32,
        payload: P,
    ) -> TuyaMessage {
        let payload = payload.into();
        let version_val = self.version().val();
        let current_seq = *seqno;
        *seqno += 1;
        debug!(
            "Building message: cmd=0x{:02X}, seqno={}, payload_len={}",
            cmd,
            current_seq,
            payload.len()
        );

        TuyaMessage {
            seqno: current_seq,
            cmd,
            payload,
            prefix: if version_val >= 3.5 {
                PREFIX_6699
            } else {
                PREFIX_55AA
            },
            ..Default::default()
        }
    }

    fn get_backoff_duration(&self, failure_count: u32) -> Duration {
        let min_secs = SLEEP_RECONNECT_MIN.as_secs();
        let max_secs = SLEEP_RECONNECT_MAX.as_secs();
        // Base exponential backoff: 2^n * min_secs
        let base_secs = (2u64.pow(failure_count.min(10)) * min_secs).min(max_secs);

        if base_secs == 0 {
            return Duration::from_secs(0);
        }

        let base_ms = base_secs * 1000;
        let fixed_ms = (base_ms * 70) / 100; // 70% fixed
        let random_range_ms = base_ms - fixed_ms; // 30% random range

        // Apply Jitter: 70% fixed + random(0% to 30%)
        let mut rng = rand::rng();
        let jitter_ms = fixed_ms + (rng.next_u64() % random_range_ms.max(1));

        Duration::from_millis(jitter_ms)
    }

    fn error_helper(&self, code: u32, payload: Option<Value>) -> TuyaMessage {
        let err_msg = get_error_message(code);
        let mut response = serde_json::json!({
            keys::ERR_MSG: err_msg,
            keys::ERR_CODE: code,
        });

        if let Some(p) = payload {
            match p {
                Value::String(s) => {
                    response[keys::PAYLOAD_STR] = Value::String(s);
                }
                Value::Object(mut obj) => {
                    if let Some(raw) = obj
                        .remove("data")
                        .or_else(|| obj.remove("payload"))
                        .or_else(|| obj.remove(keys::PAYLOAD_RAW))
                    {
                        response[keys::PAYLOAD_RAW] = raw;
                    }
                    // Merge any remaining fields (like "cmd" or original JSON data)
                    if let Some(obj_map) = response.as_object_mut() {
                        for (k, v) in obj {
                            obj_map.insert(k, v);
                        }
                    }
                }
                _ => {
                    response[keys::ERR_PAYLOAD_OBJ] = p;
                }
            }
        }

        TuyaMessage {
            seqno: 0,
            cmd: 0,
            retcode: None,
            payload: serde_json::to_vec(&response).unwrap_or_default(),
            prefix: PREFIX_55AA,
            iv: None,
        }
    }

    async fn negotiate_session_key(&self, stream: &mut TcpStream, seqno: &mut u32) -> Result<bool> {
        debug!("Starting session key negotiation");

        let mut local_nonce = vec![0u8; 16];
        rand::rng().fill_bytes(&mut local_nonce);

        self.send_raw_to_stream(
            stream,
            self.build_message(
                seqno,
                CommandType::SessKeyNegStart as u32,
                local_nonce.clone(),
            ),
        )
        .await?;

        let first_byte = timeout(self.connection_timeout(), stream.read_u8())
            .await
            .map_err(|_| TuyaError::Timeout)?
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    TuyaError::KeyOrVersionError
                } else {
                    TuyaError::from(e)
                }
            })?;
        let resp = self
            .read_and_parse_from_stream(stream, first_byte)
            .await?
            .ok_or(TuyaError::HandshakeFailed)?;

        if resp.cmd != CommandType::SessKeyNegResp as u32 || resp.payload.len() < 48 {
            return Err(TuyaError::KeyOrVersionError);
        }

        let remote_nonce = &resp.payload[..16];
        let remote_hmac = &resp.payload[16..48];

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.local_key)
            .map_err(|_| TuyaError::EncryptionFailed)?;
        mac.update(&local_nonce);
        mac.verify_slice(remote_hmac)
            .map_err(|_| TuyaError::EncryptionFailed)?;

        let mut mac = Hmac::<Sha256>::new_from_slice(&self.local_key)
            .map_err(|_| TuyaError::EncryptionFailed)?;
        mac.update(remote_nonce);
        let rkey_hmac = mac.finalize().into_bytes().to_vec();
        self.send_raw_to_stream(
            stream,
            self.build_message(seqno, CommandType::SessKeyNegFinish as u32, rkey_hmac),
        )
        .await?;

        let session_key: Vec<u8> = local_nonce
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ remote_nonce[i % remote_nonce.len()])
            .collect();
        let cipher = TuyaCipher::new(&self.local_key)?;
        let encrypted_key = if self.version().val() >= 3.5 {
            cipher.encrypt(&session_key, false, Some(&local_nonce[..12]), None, false)?[12..28]
                .to_vec()
        } else {
            cipher.encrypt(&session_key, false, None, None, false)?
        };

        self.with_state_mut(|s| s.session_key = Some(encrypted_key));
        Ok(true)
    }

    fn pack_msg(&self, mut msg: TuyaMessage) -> Result<Vec<u8>> {
        let (version, dev_type) = self.with_state(|s| (s.version, s.dev_type));
        let key = self.get_cipher_key();
        let cipher = TuyaCipher::new(&key)?;
        let protocol = get_protocol(version, dev_type);

        msg.payload = protocol.pack_payload(&msg.payload, msg.cmd, &cipher)?;

        if version.val() >= 3.5 {
            msg.prefix = PREFIX_6699;
        }

        let hmac_key = if version.val() >= 3.4 {
            Some(key.as_slice())
        } else {
            None
        };
        pack_message(&msg, hmac_key)
    }

    fn get_cipher_key(&self) -> Vec<u8> {
        let state = self.state.read();
        state
            .session_key
            .clone()
            .unwrap_or_else(|| self.local_key.clone())
    }

    async fn parse_and_read_body<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        header_buf: [u8; 16],
    ) -> Result<Option<TuyaMessage>> {
        let (packet, header) = self.read_full_packet(stream, header_buf).await?;
        trace!("Received packet (hex): {:?}", hex::encode(&packet));

        let mut decoded = self.unpack_and_check_dev22(&packet, header).await?;

        if !decoded.payload.is_empty() {
            trace!("Raw payload (hex): {:?}", hex::encode(&decoded.payload));
            decoded.payload = self
                .decrypt_and_clean_payload(decoded.payload, decoded.prefix)
                .await?;
        }

        Ok(Some(decoded))
    }

    async fn read_full_packet<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        header_buf: [u8; 16],
    ) -> Result<(Vec<u8>, TuyaHeader)> {
        let prefix =
            u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
        let mut full_header = header_buf.to_vec();

        if prefix == PREFIX_6699 {
            let mut extra = [0u8; 2];
            timeout(self.connection_timeout(), stream.read_exact(&mut extra))
                .await
                .map_err(|_| {
                    TuyaError::Io(
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Read extra header timeout",
                        )
                        .to_string(),
                    )
                })?
                .map_err(TuyaError::from)?;
            full_header.extend_from_slice(&extra);
        }

        let header = parse_header(&full_header)?;
        let mut body = vec![0u8; header.total_length as usize - full_header.len()];
        timeout(self.connection_timeout(), stream.read_exact(&mut body))
            .await
            .map_err(|_| {
                TuyaError::Io(
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "Read body timeout")
                        .to_string(),
                )
            })?
            .map_err(TuyaError::from)?;

        let mut packet = full_header;
        packet.extend_from_slice(&body);
        Ok((packet, header))
    }

    async fn unpack_and_check_dev22(
        &self,
        packet: &[u8],
        header: TuyaHeader,
    ) -> Result<TuyaMessage> {
        let version = self.version().val();
        let key = self.get_cipher_key();
        let hmac_key = (version >= 3.4).then_some(key.as_slice());

        unpack_message(packet, hmac_key, Some(header.clone()), Some(false)).or_else(|e| {
            if version == 3.3
                && self.dev_type() != DeviceType::Device22
                && let Ok(d) = unpack_message(packet, None, Some(header), Some(false))
            {
                info!("Device22 detected via CRC32 fallback. Switching mode.");
                self.set_dev_type(DeviceType::Device22);
                return Ok(d);
            }
            Err(e)
        })
    }

    async fn decrypt_and_clean_payload(&self, payload: Vec<u8>, _prefix: u32) -> Result<Vec<u8>> {
        let (version, dev_type) = self.with_state(|s| (s.version, s.dev_type));
        let key = self.get_cipher_key();
        let cipher = TuyaCipher::new(&key)?;
        let protocol = get_protocol(version, dev_type);

        let decrypted = protocol.decrypt_payload(payload, &cipher)?;

        if (version.val() == 3.3 || version.val() == 3.4)
            && dev_type != DeviceType::Device22
            && String::from_utf8_lossy(&decrypted).contains(DATA_UNVALID)
        {
            warn!(
                "Device22 detected via '{}' payload. Switching mode.",
                DATA_UNVALID
            );
            self.set_dev_type(DeviceType::Device22);
        }

        Ok(decrypted)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // If this is an external handle (has tx), and it's the last one,
        // we signal the background task to stop.
        // Note: The background task itself holds a clone but with tx = None.
        if self.tx.is_some() && Arc::strong_count(&self.state) <= 2 {
            self.cancel_token.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_device_memory_leak() {
        let id = "test_device_id";
        let key = "0123456789abcdef";
        let addr = "127.0.0.1";

        let weak_state;
        {
            let device = Device::new(id, addr, key, "3.3");
            weak_state = Arc::downgrade(&device.state);

            // strong_count should be 2 (one for device handle, one for background task)
            assert!(Arc::strong_count(&device.state) >= 1);
            assert!(weak_state.upgrade().is_some());

            // Device goes out of scope here
        }

        // Wait a bit for the background task to detect cancellation and exit
        for _ in 0..10 {
            if weak_state.upgrade().is_none() {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }

        // The state should be dropped now
        assert!(
            weak_state.upgrade().is_none(),
            "DeviceState leaked! Background task might still be running."
        );
    }
}
