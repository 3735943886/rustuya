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
use crate::scanner::get as get_scanner;
use futures_core::stream::Stream;
use hex;
use log::{debug, error, info, trace, warn};
use parking_lot::RwLock;
use rand::RngCore;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, sleep, timeout};
use tokio_util::sync::CancellationToken;

const SLEEP_HEARTBEAT_DEFAULT: Duration = Duration::from_secs(7);
const SLEEP_HEARTBEAT_CHECK: Duration = Duration::from_secs(5);
const SLEEP_RECONNECT_MIN: Duration = Duration::from_secs(16);
const SLEEP_RECONNECT_MAX: Duration = Duration::from_secs(4096);
const SLEEP_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);

const ADDR_AUTO: &str = "Auto";
const DATA_UNVALID: &str = "data unvalid";

const CHAN_BROADCAST_CAPACITY: usize = 128;
const CHAN_MPSC_CAPACITY: usize = 64;

/// Commands that must return data (payload) and should not return on empty ACK.
const MANDATORY_DATA_CMDS: &[u32] = &[CommandType::LanExtStream as u32];

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

enum DeviceCommand {
    Request {
        command: CommandType,
        data: Option<Value>,
        cid: Option<String>,
        resp_tx: oneshot::Sender<Result<Option<TuyaMessage>>>,
    },
    Disconnect,
    ConnectNow,
}

impl DeviceCommand {
    fn respond(self, result: Result<Option<TuyaMessage>>) {
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
    port: u16,
    dev_type: DeviceType,
    state: ConnectionState,
    last_received: Instant,
    last_sent: Instant,
    persist: bool,
    session_key: Option<Vec<u8>>,
    failure_count: u32,
    success_count: u32,
    force_discovery: bool,
    timeout: Duration,
    cipher: Option<Arc<TuyaCipher>>,
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

    #[must_use]
    pub fn run(self) -> Device {
        Device::with_builder(self)
    }
}

#[derive(Clone)]
pub struct Device {
    id: String,
    local_key: Vec<u8>,
    state: Arc<RwLock<DeviceState>>,
    tx: Option<mpsc::Sender<DeviceCommand>>,
    pub(crate) broadcast_tx: tokio::sync::broadcast::Sender<TuyaMessage>,
    cancel_token: CancellationToken,
    nowait: Arc<AtomicBool>,
}

impl Drop for Device {
    fn drop(&mut self) {
        // Only cancel if this is the last instance
        if Arc::strong_count(&self.state) <= 1 {
            self.cancel_token.cancel();
        }
    }
}

impl Device {
    /// Creates a new device with default settings and starts the connection task.
    pub fn new<I, K>(id: I, local_key: K) -> Self
    where
        I: Into<String>,
        K: Into<Vec<u8>>,
    {
        DeviceBuilder::new(id, local_key).run()
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
        };

        let device = Self {
            id: builder.id,
            local_key: builder.local_key,
            state: Arc::new(RwLock::new(state)),
            tx: Some(tx),
            broadcast_tx,
            cancel_token: CancellationToken::new(),
            nowait: Arc::new(AtomicBool::new(builder.nowait)),
        };

        let cancel_token = device.cancel_token.clone();
        let d_clone = device.clone();
        let d_id = device.id.clone();
        crate::runtime::spawn(async move {
            tokio::select! {
                () = cancel_token.cancelled() => {
                    debug!("Device {d_id} connection task stopped via token");
                }
                () = d_clone.run_connection_task(rx) => {
                    debug!("Device {d_id} connection task finished");
                }
            }
        });
        device
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn dev_type(&self) -> DeviceType {
        self.with_state(|s| s.dev_type)
    }

    #[must_use]
    pub fn local_key(&self) -> &[u8] {
        &self.local_key
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
        self.nowait.load(Ordering::Relaxed)
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
        self.nowait.store(nowait, Ordering::Relaxed);
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
    pub fn listener(&self) -> impl Stream<Item = Result<TuyaMessage>> + Send + 'static {
        let mut rx = self.broadcast_tx.subscribe();
        async_stream::stream! {
            while let Ok(msg) = rx.recv().await {
                if !msg.payload.is_empty() {
                    yield Ok(msg);
                }
            }
        }
    }

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

    pub async fn receive(&self) -> Result<TuyaMessage> {
        let mut rx = self.broadcast_tx.subscribe();
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if !msg.payload.is_empty() {
                        return Ok(msg);
                    }
                }
                Err(e) => return Err(TuyaError::Io(e.to_string())),
            }
        }
    }

    #[must_use]
    pub fn sub(&self, cid: &str) -> SubDevice {
        SubDevice::new(self.clone(), cid)
    }

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
                    Ok(Some(hex::encode(&msg.payload)))
                }
            }
            None => Ok(None),
        }
    }
}

impl Device {
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
}

impl Device {
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

    async fn send_command_to_task(
        &self,
        cmd_generator: impl FnOnce(oneshot::Sender<Result<Option<TuyaMessage>>>) -> DeviceCommand,
    ) -> Result<Option<TuyaMessage>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.send_to_task(cmd_generator(resp_tx)).await;
        if !self.nowait.load(Ordering::Relaxed) {
            resp_rx.await.map_err(|_| TuyaError::Offline)?
        } else {
            Ok(None)
        }
    }

    fn get_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Represents an event from a specific device.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceEvent {
    /// The ID of the device that generated the event.
    pub device_id: String,
    /// The message received from the device.
    pub message: TuyaMessage,
}

/// Merges multiple device listeners into a single stream of events.
pub fn unified_listener(
    devices: Vec<Device>,
) -> impl Stream<Item = Result<DeviceEvent>> + Send + 'static {
    use futures_util::StreamExt;
    use futures_util::stream::select_all;

    let streams = devices.into_iter().map(|device| {
        let device_id = device.id().to_string();
        device
            .listener()
            .map(move |res| match res {
                Ok(message) => Ok(DeviceEvent {
                    device_id: device_id.clone(),
                    message,
                }),
                Err(e) => Err(e),
            })
            .boxed()
    });

    select_all(streams)
}

impl Device {
    async fn run_connection_task(&self, mut rx: mpsc::Receiver<DeviceCommand>) {
        let jitter = {
            let mut rng = rand::rng();
            Duration::from_millis(u64::from(rng.next_u32() % 5000))
        };

        debug!(
            "Starting background connection task for device {} with {:?} initial jitter",
            self.id, jitter
        );

        // Stagger connection attempts
        tokio::select! {
            () = self.cancel_token.cancelled() => return,
            () = tokio::time::sleep(jitter) => {}
        }

        let mut heartbeat_interval = tokio::time::interval(SLEEP_HEARTBEAT_CHECK);
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                () = self.cancel_token.cancelled() => {
                    debug!("Background task for {} received stop signal", self.id);
                    break;
                }
                res = async {
                    if self.is_stopped() {
                        return Some(());
                    }

                    // Reset seqno for each new connection attempt
                    let mut seqno = 1u32;

                    // 1. Connect and handshake
                    let (stream, initial_cmd) = match self
                        .try_connect_with_backoff(&mut rx, &mut seqno)
                        .await
                    {
                        Some(res) => res,
                        None => return Some(()),
                    };

                    // 2. Connection maintenance
                    let result = self
                        .maintain_connection(stream, &mut rx, &mut seqno, &mut heartbeat_interval, initial_cmd)
                        .await;

                    self.handle_disconnect(result.as_ref().err().cloned());

                    if let Err(e) = result {
                        self.with_state_mut(|s| {
                            s.failure_count += 1;
                            s.success_count = 0;
                        });
                        self.drain_rx(&mut rx, e, false);
                    } else {
                        return Some(());
                    }

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

    async fn maintain_connection(
        &self,
        stream: TcpStream,
        rx: &mut mpsc::Receiver<DeviceCommand>,
        seqno: &mut u32,
        heartbeat_interval: &mut tokio::time::Interval,
        initial_cmd: Option<DeviceCommand>,
    ) -> Result<()> {
        let (mut read_half, mut write_half) = stream.into_split();
        let (internal_tx, mut internal_rx) = mpsc::channel::<TuyaError>(1);

        // Process initial command if exists
        if let Some(cmd) = initial_cmd {
            self.process_command(&mut write_half, seqno, cmd)
                .await
                .map_err(|e| {
                    if !self.is_stopped() {
                        error!("Initial command processing failed for {}: {}", self.id, e);
                    }
                    e
                })?;
        }

        let device_clone = self.clone();
        let parent_cancel_token = self.cancel_token.clone();

        // Reader Task
        let reader_task = crate::runtime::spawn(async move {
            let mut packets_received = 0;
            loop {
                tokio::select! {
                    () = parent_cancel_token.cancelled() => break,
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
                                        TuyaError::Io("Connection reset".to_string())
                                    } else {
                                        TuyaError::KeyOrVersionError
                                    }
                                } else {
                                    TuyaError::Io(e.to_string())
                                };
                                let _ = internal_tx.send(err).await;
                                break;
                            }
                            Err(_) => {
                                if !device_clone.is_stopped() {
                                    warn!("Inactivity timeout for {}", device_clone.id);
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
                    () = self.cancel_token.cancelled() => {
                        return Ok(());
                    }
                    cmd_opt = rx.recv() => {
                        if let Some(cmd) = cmd_opt {
                            self.process_command(&mut write_half, seqno, cmd).await?;
                        } else {
                            self.state.write().state = ConnectionState::Stopped;
                            return Ok(());
                        }
                    }
                    _ = heartbeat_interval.tick() => {
                        if self.with_state(|s| s.persist) {
                            self.process_heartbeat(&mut write_half, seqno)
                                .await
                                .map_err(|e| {
                                    error!("Heartbeat failed for {}: {}", self.id, e);
                                    e
                                })?;
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

        reader_task.abort();
        result
    }

    async fn try_connect_with_backoff(
        &self,
        rx: &mut mpsc::Receiver<DeviceCommand>,
        seqno: &mut u32,
    ) -> Option<(TcpStream, Option<DeviceCommand>)> {
        loop {
            if self.is_stopped() {
                self.drain_rx(rx, TuyaError::Offline, true);
                return None;
            }

            // Reset seqno for new connection
            *seqno = 1;

            // Wait before retry if failed
            let backoff = self.with_state(|s| {
                if s.failure_count > 0 {
                    Some(self.get_backoff_duration(s.failure_count - 1))
                } else {
                    None
                }
            });

            if let Some(b) = backoff {
                warn!(
                    "Waiting {}s before next connection attempt for {}",
                    b.as_secs(),
                    self.id
                );
                self.wait_for_backoff(rx, b).await?;
            }

            let result = timeout(self.timeout() * 2, self.connect_and_handshake(seqno)).await;
            if let Ok(Ok(s)) = result {
                self.with_state_mut(|s| s.state = ConnectionState::Connected);
                info!(
                    "Connected to device {} ({})",
                    self.id,
                    self.with_state(|s| s.real_ip.clone())
                );
                self.broadcast_error(ERR_SUCCESS, None);
                return Some((s, None));
            } else {
                let e = match result {
                    Ok(Err(e)) => e,
                    _ => TuyaError::Offline,
                };

                self.handle_connection_error(&e).await;
                self.drain_rx(rx, e.clone(), false);

                if !self.with_state(|s| s.persist) {
                    warn!(
                        "Connection failed (persist: false) for {}: {}. Waiting for next command.",
                        self.id, e
                    );

                    loop {
                        match rx.recv().await {
                            Some(DeviceCommand::ConnectNow) => break,
                            Some(cmd @ DeviceCommand::Request { .. }) => {
                                let retry_result =
                                    timeout(self.timeout() * 2, self.connect_and_handshake(seqno))
                                        .await;

                                if let Ok(Ok(s)) = retry_result {
                                    self.with_state_mut(|s| s.state = ConnectionState::Connected);
                                    info!("Connected to {} on demand", self.id);
                                    self.broadcast_error(ERR_SUCCESS, None);
                                    return Some((s, Some(cmd)));
                                } else {
                                    let err = match retry_result {
                                        Ok(Err(e)) => e,
                                        _ => TuyaError::Offline,
                                    };
                                    self.handle_connection_error(&err).await;
                                    cmd.respond(Err(err.clone()));
                                    self.broadcast_error(ERR_OFFLINE, None);
                                }
                            }
                            Some(DeviceCommand::Disconnect) | None => return None,
                        }
                    }
                    continue;
                }

                self.with_state_mut(|s| {
                    s.failure_count += 1;
                    s.success_count = 0;
                    if s.config_address == ADDR_AUTO {
                        match e {
                            TuyaError::KeyOrVersionError | TuyaError::Offline => {
                                s.force_discovery = true;
                                let _ = get_scanner().invalidate_cache(&self.id);
                            }
                            _ => {}
                        }
                    }
                });
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

        let discovery_notified = get_scanner().notified();
        tokio::pin!(discovery_notified);

        loop {
            tokio::select! {
                () = &mut sleep_fut => return Some(()),
                () = &mut discovery_notified => {
                    if get_scanner().is_recently_discovered(&self.id, Duration::from_secs(10)) {
                        return Some(());
                    }
                    discovery_notified.set(get_scanner().notified());
                }
                () = self.cancel_token.cancelled() => {
                    self.drain_rx(rx, TuyaError::Offline, true);
                    return None;
                }
                cmd_opt = rx.recv() => {
                    if let Some(cmd) = cmd_opt {
                        if let DeviceCommand::ConnectNow = cmd { return Some(()) }
                        debug!("Rejecting command during backoff for device {}", self.id);
                        cmd.respond(Err(TuyaError::Offline));
                        self.broadcast_error(ERR_OFFLINE, None);
                    } else {
                        return None;
                    }
                }
            }
        }
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

    async fn handle_connection_error(&self, e: &TuyaError) {
        self.with_state_mut(|s| {
            if s.state != ConnectionState::Stopped {
                s.state = ConnectionState::Disconnected;
            }
        });
        self.broadcast_error(e.code(), Some(serde_json::json!(format!("{}", e))));
    }

    fn drain_rx(&self, rx: &mut mpsc::Receiver<DeviceCommand>, err: TuyaError, close: bool) {
        if close {
            rx.close();
        }
        while let Ok(cmd) = rx.try_recv() {
            cmd.respond(Err(err.clone()));
        }
    }
}

impl Device {
    // -------------------------------------------------------------------------
    // Protocol Implementation & Handshake
    // -------------------------------------------------------------------------

    async fn connect_and_handshake(&self, seqno: &mut u32) -> Result<TcpStream> {
        let addr = self.resolve_address().await?;
        let port = self.with_state(|s| s.port);

        info!("Connecting to device {} at {}:{}", self.id, addr, port);
        let mut stream = timeout(self.timeout(), TcpStream::connect(format!("{addr}:{port}")))
            .await
            .map_err(|_| TuyaError::Timeout)?
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::ConnectionRefused => TuyaError::ConnectionFailed,
                _ => TuyaError::Io(e.to_string()),
            })?;

        let protocol = get_protocol(self.version(), self.dev_type());
        if protocol.requires_session_key()
            && !self.negotiate_session_key(&mut stream, seqno).await?
        {
            return Err(TuyaError::KeyOrVersionError);
        }

        Ok(stream)
    }

    async fn negotiate_session_key(&self, stream: &mut TcpStream, seqno: &mut u32) -> Result<bool> {
        let protocol = get_protocol(self.version(), self.dev_type());
        debug!("Session negotiation (v{})", protocol.version());

        // 1. Send SessKeyNegStart
        let local_nonce = protocol.prepare_session_key_negotiation();
        self.send_raw_to_stream(
            stream,
            self.build_message(
                seqno,
                CommandType::SessKeyNegStart as u32,
                local_nonce.clone(),
            ),
        )
        .await?;

        // 2. Read response and verify
        let first_byte = timeout(self.timeout(), stream.read_u8())
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

        if resp.cmd != CommandType::SessKeyNegResp as u32 {
            return Err(TuyaError::KeyOrVersionError);
        }

        let remote_nonce =
            protocol.verify_session_key_response(&local_nonce, &resp.payload, &self.local_key)?;

        // 3. Finalize and send SessKeyNegFinish
        let (session_key, finish_hmac) =
            protocol.finalize_session_key(&local_nonce, &remote_nonce, &self.local_key)?;

        self.send_raw_to_stream(
            stream,
            self.build_message(seqno, CommandType::SessKeyNegFinish as u32, finish_hmac),
        )
        .await?;

        // 4. Encrypt and store session key
        let cipher = TuyaCipher::new(&self.local_key)?;
        let encrypted_key = protocol.encrypt_session_key(&session_key, &cipher, &local_nonce)?;

        self.with_state_mut(|s| s.session_key = Some(encrypted_key));
        Ok(true)
    }

    async fn resolve_address(&self) -> Result<String> {
        let (config_addr, force_discovery, version) =
            self.with_state(|s| (s.config_address.clone(), s.force_discovery, s.version));

        let ip_explicit =
            config_addr != ADDR_AUTO && config_addr != "0.0.0.0" && !config_addr.is_empty();
        let ver_explicit = version != Version::Auto;

        if ip_explicit && ver_explicit && !force_discovery {
            return Ok(config_addr);
        }

        if let Ok(Some(result)) = get_scanner()
            .discover_device_internal(&self.id, force_discovery)
            .await
        {
            let mut state = self.state.write();
            if let Some(v) = result.version
                && state.version == Version::Auto
            {
                state.version = v;
            }

            let target_ip = if ip_explicit { config_addr } else { result.ip };
            state.real_ip = target_ip.clone();
            state.force_discovery = false;
            Ok(target_ip)
        } else if ip_explicit {
            self.with_state_mut(|s| {
                s.real_ip = config_addr.clone();
                s.force_discovery = false;
            });
            Ok(config_addr)
        } else {
            Err(TuyaError::Offline)
        }
    }

    async fn generate_payload(
        &self,
        command: CommandType,
        data: Option<Value>,
        cid: Option<&str>,
    ) -> Result<(u32, Value)> {
        let (version, mut dev_type) = self.with_state(|s| (s.version, s.dev_type));
        // If dev_type is Auto, treat it as Default for protocol selection
        if dev_type == DeviceType::Auto {
            dev_type = DeviceType::Default;
        }
        let protocol = get_protocol(version, dev_type);
        let t = self.get_timestamp();
        protocol.generate_payload(&self.id, command, data, cid, t)
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
                let nowait = self.nowait.load(Ordering::Relaxed);
                let cmd_code = command as u32;
                let response_rx = if !nowait && ![3, 4, 5, 9].contains(&cmd_code) {
                    Some(self.broadcast_tx.subscribe())
                } else {
                    None
                };

                let res = self
                    .generate_payload(command, data.clone(), cid.as_deref())
                    .await;
                let send_res = match res {
                    Ok((cmd_id, payload)) => {
                        debug!("Sending command: cmd=0x{:02X}, seqno={}", cmd_id, *seqno);
                        self.send_json_msg(stream, seqno, cmd_id, &payload).await
                    }
                    Err(e) => Err(e),
                };

                if let Err(e) = send_res {
                    let _ = resp_tx.send(Err(e));
                    return Ok(());
                }

                if let Some(mut rx) = response_rx {
                    let protocol = self.with_state(|s| get_protocol(s.version, s.dev_type));
                    let effective_cmd = protocol.get_effective_command(command);
                    let timeout_dur = self.timeout();

                    let wait_res = timeout(timeout_dur, async {
                        loop {
                            match rx.recv().await {
                                Ok(msg) => {
                                    // 0. Check for error response from device (cmd 0)
                                    if msg.cmd == 0 {
                                        debug!("Device returned error response (cmd 0), returning as valid response");
                                        return Ok(Some(msg));
                                    }

                                    // 1. Check command ID
                                    let cmd_matches = msg.cmd == effective_cmd
                                        || msg.cmd == CommandType::Status as u32;

                                    if !cmd_matches {
                                        continue;
                                    }

                                    // 1.1 Check if this command requires data (must wait if payload is empty)
                                    let needs_data = MANDATORY_DATA_CMDS.contains(&msg.cmd);

                                    // Found matching response
                                    // 2. If we sent a request with a specific CID, verify the response CID matches
                                    if let Some(ref target_cid) = cid {
                                        if msg.payload.is_empty() {
                                            if needs_data {
                                                trace!("Received empty ACK for command requiring data (0x{:02X}), continuing wait", msg.cmd);
                                                continue;
                                            }
                                            // Empty payload for CID request is considered a valid ACK
                                            debug!("Received empty ACK for CID request ({}), accepting", target_cid);
                                            return Ok(Some(msg));
                                        }

                                        if let Ok(val) = serde_json::from_slice::<Value>(&msg.payload) {
                                            let resp_cid = val.get("cid").and_then(|c| c.as_str());
                                            if resp_cid == Some(target_cid) {
                                                debug!("Received matching response for CID: {}", target_cid);
                                                return Ok(Some(msg));
                                            } else {
                                                // Response for a different CID, ignore and keep waiting
                                                trace!("Ignoring response for CID: {:?} (expected {})", resp_cid, target_cid);
                                                continue;
                                            }
                                        }
                                    } else {
                                        // Request without CID (parent device request)
                                        if msg.payload.is_empty() {
                                            if needs_data {
                                                trace!("Received empty ACK for parent command requiring data (0x{:02X}), continuing wait", msg.cmd);
                                                continue;
                                            }
                                            return Ok(Some(msg));
                                        }

                                        if let Ok(val) = serde_json::from_slice::<Value>(&msg.payload) {
                                            if val.get("cid").is_none() {
                                                return Ok(Some(msg));
                                            } else {
                                                // Response with CID for a non-CID request, ignore
                                                trace!("Ignoring response with CID for parent request");
                                                continue;
                                            }
                                        }
                                    }

                                    return Ok(Some(msg));
                                }
                                Err(_) => return Err(TuyaError::Offline),
                            }
                        }
                    })
                    .await
                    .unwrap_or(Err(TuyaError::Timeout));

                    let _ = resp_tx.send(wait_res);
                } else {
                    let _ = resp_tx.send(Ok(None));
                }
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
            if msg.payload.is_empty() {
                debug!(
                    "Received empty payload message (cmd 0x{:02X}), broadcasting as ACK",
                    msg.cmd
                );
                let _ = self.broadcast_tx.send(msg);
            } else {
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
            let (cmd, payload) = self
                .generate_payload(CommandType::HeartBeat, None, None)
                .await?;
            self.send_json_msg(stream, seqno, cmd, &payload).await?;
        }
        Ok(())
    }
}

impl Device {
    // -------------------------------------------------------------------------
    // Low-level Message Framing & Encryption
    // -------------------------------------------------------------------------

    fn build_message<P: Into<Vec<u8>>>(
        &self,
        seqno: &mut u32,
        cmd: u32,
        payload: P,
    ) -> TuyaMessage {
        let payload = payload.into();
        let current_seq = *seqno;
        *seqno += 1;
        debug!(
            "Building message: cmd=0x{:02X}, seqno={}, payload_len={}",
            cmd,
            current_seq,
            payload.len()
        );

        let protocol = get_protocol(self.version(), self.dev_type());

        TuyaMessage {
            seqno: current_seq,
            cmd,
            payload,
            prefix: protocol.get_prefix(),
            ..Default::default()
        }
    }

    fn pack_msg(&self, mut msg: TuyaMessage) -> Result<Vec<u8>> {
        let (version, dev_type) = self.with_state(|s| (s.version, s.dev_type));
        let cipher = self.get_cipher()?;
        let protocol = get_protocol(version, dev_type);

        msg.payload = protocol.pack_payload(&msg.payload, msg.cmd, &cipher)?;
        msg.prefix = protocol.get_prefix();

        let hmac_key = protocol.get_hmac_key(cipher.key());
        pack_message(&msg, hmac_key)
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

    async fn send_raw_to_stream<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        msg: TuyaMessage,
    ) -> Result<()> {
        let packed = self.pack_msg(msg)?;
        timeout(self.timeout(), stream.write_all(&packed))
            .await
            .map_err(|_| TuyaError::Timeout)?
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
        timeout(self.timeout(), stream.read_exact(&mut header_buf[4..]))
            .await
            .map_err(|_| TuyaError::Timeout)?
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
        let mut current_prefix = first_byte as u32;

        for _ in 0..3 {
            let next_byte = timeout(self.timeout(), stream.read_u8())
                .await
                .map_err(|_| TuyaError::Timeout)?
                .map_err(TuyaError::from)?;
            current_prefix = (current_prefix << 8) | (next_byte as u32);
        }

        for _ in 0..1024 {
            if current_prefix == PREFIX_55AA || current_prefix == PREFIX_6699 {
                return Ok(Some(current_prefix.to_be_bytes()));
            }

            let next_byte = timeout(self.timeout(), stream.read_u8())
                .await
                .map_err(|_| TuyaError::Timeout)?
                .map_err(TuyaError::from)?;
            current_prefix = (current_prefix << 8) | (next_byte as u32);
        }
        Ok(None)
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

        let (header, mut packet) = if prefix == PREFIX_6699 {
            let mut extra = [0u8; 2];
            timeout(self.timeout(), stream.read_exact(&mut extra))
                .await
                .map_err(|_| TuyaError::Timeout)?
                .map_err(TuyaError::from)?;

            let mut fh = Vec::with_capacity(18);
            fh.extend_from_slice(&header_buf);
            fh.extend_from_slice(&extra);
            (parse_header(&fh)?, fh)
        } else {
            (parse_header(&header_buf)?, header_buf.to_vec())
        };

        let total_len = header.total_length as usize;
        let header_len = packet.len();

        packet.resize(total_len, 0);
        timeout(self.timeout(), stream.read_exact(&mut packet[header_len..]))
            .await
            .map_err(|_| TuyaError::Timeout)?
            .map_err(TuyaError::from)?;

        Ok((packet, header))
    }

    async fn unpack_and_check_dev22(
        &self,
        packet: &[u8],
        header: TuyaHeader,
    ) -> Result<TuyaMessage> {
        let (version, dev_type) = self.with_state(|s| (s.version, s.dev_type));
        let protocol = get_protocol(version, dev_type);
        let cipher = self.get_cipher()?;
        let hmac_key = protocol.get_hmac_key(cipher.key());

        unpack_message(packet, hmac_key, Some(header.clone()), Some(false)).or_else(|e| {
            // Only allow switching if dev_type is Auto and protocol allows it
            if protocol.should_check_dev22_fallback()
                && dev_type == DeviceType::Auto
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
        let (version, mut dev_type) = self.with_state(|s| (s.version, s.dev_type));
        let original_dev_type = dev_type;
        if dev_type == DeviceType::Auto {
            dev_type = DeviceType::Default;
        }

        let cipher = self.get_cipher()?;
        let protocol = get_protocol(version, dev_type);

        let decrypted = protocol.decrypt_payload(payload, &cipher)?;

        if protocol.should_check_dev22_fallback()
            && original_dev_type == DeviceType::Auto
            && String::from_utf8_lossy(&decrypted).contains(DATA_UNVALID)
        {
            warn!("Device22 detected via '{DATA_UNVALID}' payload. Switching mode.");
            self.set_dev_type(DeviceType::Device22);
        }

        Ok(decrypted)
    }

    fn get_cipher(&self) -> Result<Arc<TuyaCipher>> {
        let mut state = self.state.write();

        // Determine which key to use: session_key if available, otherwise local_key
        let key = state.session_key.as_deref().unwrap_or(&self.local_key);

        if let Some(ref cipher) = state.cipher
            && cipher.key() == key
        {
            return Ok(Arc::clone(cipher));
        }

        let new_cipher = Arc::new(TuyaCipher::new(key)?);
        state.cipher = Some(Arc::clone(&new_cipher));
        Ok(new_cipher)
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
        let mut response = serde_json::json!({
            keys::ERR_MSG: get_error_message(code),
            keys::ERR_CODE: code,
        });

        if let Some(p) = payload {
            match p {
                Value::String(s) => response[keys::PAYLOAD_STR] = Value::String(s),
                Value::Object(mut obj) => {
                    if let Some(raw) = obj
                        .remove("data")
                        .or_else(|| obj.remove("payload"))
                        .or_else(|| obj.remove(keys::PAYLOAD_RAW))
                    {
                        response[keys::PAYLOAD_RAW] = raw;
                    }
                    if let Some(res_obj) = response.as_object_mut() {
                        res_obj.extend(obj);
                    }
                }
                _ => response[keys::ERR_PAYLOAD_OBJ] = p,
            }
        }

        TuyaMessage {
            payload: serde_json::to_vec(&response).unwrap_or_default(),
            prefix: get_protocol(self.version(), self.dev_type()).get_prefix(),
            ..Default::default()
        }
    }
}
