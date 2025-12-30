//! Individual Tuya device communication and state management.
//! Handles TCP connection, handshakes, heartbeats, and command/response flows.

use crate::crypto::TuyaCipher;
use crate::error::{
    ERR_DEVTYPE, ERR_JSON, ERR_OFFLINE, ERR_PAYLOAD, ERR_SUCCESS, Result, TuyaError,
    get_error_message,
};
use crate::protocol::{
    CommandType, PREFIX_55AA, PREFIX_6699, TuyaHeader, TuyaMessage, Version, pack_message,
    parse_header, unpack_message,
};
use crate::scanner::Scanner;
use futures_core::stream::Stream;
use hex;
use hmac::{Hmac, Mac};
use log::{debug, error, info, warn};
use rand::RngCore;
use serde_json::Value;
use sha2::Sha256;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, sleep, timeout};
use tokio_util::sync::CancellationToken;

// Standardized Sleep Durations
const SLEEP_HEARTBEAT_DEFAULT: Duration = Duration::from_secs(7);
const SLEEP_HEARTBEAT_CHECK: Duration = Duration::from_secs(5);
const SLEEP_RECONNECT_MIN: Duration = Duration::from_secs(30);
const SLEEP_RECONNECT_MAX: Duration = Duration::from_secs(600); // 10 minutes

const NO_PROTOCOL_HEADER_CMDS: &[u32] = &[
    CommandType::DpQuery as u32,
    CommandType::DpQueryNew as u32,
    CommandType::UpdateDps as u32,
    CommandType::HeartBeat as u32,
    CommandType::SessKeyNegStart as u32,
    CommandType::SessKeyNegResp as u32,
    CommandType::SessKeyNegFinish as u32,
    CommandType::LanExtStream as u32,
];

const DEV_TYPE_DEVICE22: &str = "device22";
const DEV_TYPE_DEFAULT: &str = "default";

const KEY_CID: &str = "cid";
const KEY_DPS: &str = "dps";
const KEY_T: &str = "t";
const KEY_DATA: &str = "data";
const KEY_PROTOCOL: &str = "protocol";
const KEY_CTYPE: &str = "ctype";
const KEY_GW_ID: &str = "gwId";
const KEY_DEV_ID: &str = "devId";
const KEY_UID: &str = "uid";
const KEY_REQ_TYPE: &str = "reqType";

const PAYLOAD_STR: &str = "payload_str";
const PAYLOAD_RAW: &str = "payload_raw";
const ERR_CODE: &str = "Err";
const ERR_MSG: &str = "Error";
const ERR_PAYLOAD_OBJ: &str = "Payload";

const ADDR_AUTO: &str = "Auto";
const DATA_UNVALID: &str = "data unvalid";

/// Represents a sub-device (Zigbee/Bluetooth/etc.) connected via a Tuya gateway.
///
/// Sub-devices share the parent gateway's TCP connection but are identified
/// by a unique Node ID (CID).
#[derive(Clone)]
pub struct SubDevice {
    parent: Device,
    cid: String,
}

impl SubDevice {
    /// Create a new SubDevice handle.
    pub(crate) fn new(parent: Device, cid: &str) -> Self {
        Self {
            parent,
            cid: cid.to_string(),
        }
    }

    /// Returns the Node ID (CID) of this sub-device.
    pub fn id(&self) -> &str {
        &self.cid
    }

    /// Queries the current status of this sub-device.
    pub async fn status(&self) {
        self.request::<String>(CommandType::DpQuery, None, None)
            .await
    }

    /// Sets a single Data Point (DP) value on this sub-device.
    pub async fn set_dps(&self, dps: Value) {
        self.request::<String>(CommandType::Control, Some(dps), None)
            .await
    }

    /// Sets a single Data Point (DP) value on this sub-device.
    pub async fn set_value(&self, index: u32, value: Value) {
        self.set_dps(serde_json::json!({ index.to_string(): value }))
            .await
    }

    /// Sends a custom request for this sub-device.
    ///
    /// This is a low-level API. For common operations, use [`status`](Self::status)
    /// or [`set_value`](Self::set_value).
    pub async fn request<R>(&self, cmd: CommandType, data: Option<Value>, req_type: Option<R>)
    where
        R: Into<String>,
    {
        self.parent
            .request(cmd, data, Some(self.cid.clone()), req_type)
            .await
    }
}

/// Internal commands for the background connection task.
enum DeviceCommand {
    Request {
        command: CommandType,
        data: Option<Value>,
        cid: Option<String>,
        req_type: Option<String>,
        resp_tx: oneshot::Sender<Result<()>>,
    },
    Disconnect,
}

impl DeviceCommand {
    fn respond(self, result: Result<()>) {
        if let DeviceCommand::Request { resp_tx, .. } = self {
            let _ = resp_tx.send(result);
        }
    }
}

/// Internal state of a Tuya device that needs to be shared and mutable.
struct DeviceState {
    config_address: String,
    real_ip: String,
    version: Version,
    dev_type: String,
    connected: bool,
    last_received: Instant,
    last_sent: Instant,
    stopped: bool,
    persist: bool,
    session_key: Option<Vec<u8>>,
    failure_count: u32,
    force_discovery: bool,
}

/// Represents a Tuya device and handles communication.
#[derive(Clone)]
pub struct Device {
    id: String,
    local_key: Vec<u8>,
    port: u16,
    connection_timeout: Duration,

    // Shared mutable state
    state: Arc<RwLock<DeviceState>>,

    // Channel to send messages to the background task
    tx: Option<mpsc::Sender<DeviceCommand>>,

    // Broadcaster for received messages
    broadcast_tx: tokio::sync::broadcast::Sender<TuyaMessage>,
    // Shared scanner to avoid repeated socket creation
    scanner: Arc<Scanner>,

    // Token for stopping the device and its background tasks
    cancel_token: CancellationToken,
}

impl Device {
    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// Initialize device with ID, address, local key, and protocol version.
    ///
    /// Address can be "Auto" for automatic discovery on the local network.
    /// Version can be provided as a string (e.g., "3.3") or using the Version enum.
    pub fn new<I, A, K, V>(id: I, address: A, local_key: K, version: V) -> Self
    where
        I: Into<String>,
        A: Into<String>,
        K: Into<Vec<u8>>,
        V: Into<Version>,
    {
        let id_str = id.into();
        let addr_str = address.into();
        let (addr, ip) = match addr_str.as_str() {
            "" | ADDR_AUTO => (ADDR_AUTO.to_string(), "".to_string()),
            _ => (addr_str.clone(), addr_str),
        };
        let key_bytes = local_key.into();
        let ver = version.into();
        let dev_type = if ver.val() == 3.2 {
            DEV_TYPE_DEVICE22.to_string()
        } else {
            DEV_TYPE_DEFAULT.to_string()
        };

        let (broadcast_tx, _) = tokio::sync::broadcast::channel(4);
        let (tx, rx) = mpsc::channel(32);
        let state = DeviceState {
            config_address: addr,
            real_ip: ip,
            version: ver,
            dev_type,
            connected: false,
            last_received: Instant::now(),
            last_sent: Instant::now(),
            stopped: false,
            persist: true,
            session_key: None,
            failure_count: 0,
            force_discovery: false,
        };

        let device = Self {
            id: id_str,
            local_key: key_bytes,
            port: 6668,
            connection_timeout: Duration::from_secs(10),
            state: Arc::new(RwLock::new(state)),
            tx: Some(tx),
            broadcast_tx,
            scanner: Arc::new(Scanner::new()),
            cancel_token: CancellationToken::new(),
        };

        let d_clone = device.clone();
        tokio::spawn(async move { d_clone.run_connection_task(rx).await });
        device
    }

    pub fn get_version(&self) -> Version {
        self.with_state(|s| s.version)
    }

    pub fn get_dev_type(&self) -> String {
        self.with_state(|s| s.dev_type.clone())
    }

    pub fn get_address(&self) -> String {
        self.with_state(|s| s.config_address.clone())
    }

    pub fn version(&self) -> Version {
        self.get_version()
    }

    pub fn address(&self) -> String {
        self.get_address()
    }

    /// Sets whether the device should automatically reconnect on failure.
    pub fn set_persist(&self, persist: bool) {
        self.with_state_mut(|s| s.persist = persist);
    }

    /// Checks if the device is currently connected.
    pub fn is_connected(&self) -> bool {
        self.with_state(|s| s.connected)
    }

    /// Sets the protocol version and handles version-specific initialization.
    pub fn set_version<V: Into<Version>>(&self, version: V) {
        let ver = version.into();
        let dev_type = if ver.val() == 3.2 {
            DEV_TYPE_DEVICE22.to_string()
        } else {
            DEV_TYPE_DEFAULT.to_string()
        };

        self.with_state_mut(|s| {
            s.version = ver;
            s.dev_type = dev_type;
        });
    }

    /// Set device type (e.g., "smart_plug", DEV_TYPE_DEVICE22).
    pub fn set_dev_type<S: Into<String>>(&self, dev_type: S) {
        let dt = dev_type.into();
        self.with_state_mut(|s| s.dev_type = dt);
    }

    // -------------------------------------------------------------------------
    // Internal State Helpers
    // -------------------------------------------------------------------------

    fn with_state<R>(&self, f: impl FnOnce(&DeviceState) -> R) -> R {
        f(&self.state.read().expect("Device state lock poisoned"))
    }

    fn with_state_mut<R>(&self, f: impl FnOnce(&mut DeviceState) -> R) -> R {
        f(&mut self.state.write().expect("Device state lock poisoned"))
    }

    fn broadcast_error(&self, code: u32, payload: Option<Value>) {
        let _ = self.broadcast_tx.send(self.error_helper(code, payload));
    }

    fn update_last_received(&self) {
        if let Ok(mut state) = self.state.write() {
            state.last_received = Instant::now();
        }
    }

    fn update_last_sent(&self) {
        if let Ok(mut state) = self.state.write() {
            state.last_sent = Instant::now();
        }
    }

    fn reset_failure_count(&self) {
        if let Ok(mut state) = self.state.write() {
            if state.failure_count > 0 {
                debug!("Resetting failure count for device {}", self.id);
                state.failure_count = 0;
            }
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
}

// -------------------------------------------------------------------------
// Device Control API
// -------------------------------------------------------------------------
impl Device {
    /// Queries the current status of the device.
    ///
    /// This sends a `DpQuery` (or `DpQueryNew` for v3.4+) command to the device.
    /// The response will be broadcasted through the [`stream()`](Self::stream).
    pub async fn status(&self) {
        self.request::<String, String>(CommandType::DpQuery, None, None, None)
            .await
    }

    /// Sets multiple Data Points (DPs) on the device.
    ///
    /// # Arguments
    /// * `dps` - A JSON object containing DP IDs and their target values.
    ///
    /// The device will usually respond with the updated status, which is broadcasted
    /// through the [`stream()`](Self::stream).
    pub async fn set_dps(&self, dps: Value) {
        self.request::<String, String>(CommandType::Control, Some(dps), None, None)
            .await
    }

    /// Sets a single Data Point (DP) value on the device.
    ///
    /// # Arguments
    /// * `index` - The ID of the Data Point (e.g., 1 for power).
    /// * `value` - The new value (e.g., `json!(true)`).
    pub async fn set_value(&self, index: u32, value: Value) {
        self.set_dps(serde_json::json!({ index.to_string(): value }))
            .await
    }
}

// -------------------------------------------------------------------------
// Sub-Device Control API
// -------------------------------------------------------------------------
impl Device {
    /// Creates a SubDevice instance for the given Node ID (CID).
    pub fn sub_device(&self, cid: &str) -> SubDevice {
        SubDevice::new(self.clone(), cid)
    }

    /// Generates a payload for a command, handling version-specific overrides and sub-device structure.
    async fn generate_payload(
        &self,
        command: CommandType,
        data: Option<Value>,
        cid: Option<&str>,
        req_type: Option<&str>,
    ) -> Result<(u32, Value)> {
        let version_val = self.get_version().val();
        let dev_type = self.get_dev_type();
        let t = self.get_timestamp();

        // 1. Determine command
        let mut cmd_to_send = command as u32;
        if version_val >= 3.4 {
            cmd_to_send = match command {
                CommandType::Control => CommandType::ControlNew as u32,
                CommandType::DpQuery => CommandType::DpQueryNew as u32,
                _ => cmd_to_send,
            };
        }
        if dev_type == DEV_TYPE_DEVICE22 && cmd_to_send == CommandType::DpQuery as u32 {
            cmd_to_send = CommandType::ControlNew as u32;
        }

        // 2. Prepare data
        let final_data = match (&dev_type[..], cmd_to_send, data.as_ref()) {
            (DEV_TYPE_DEVICE22, c, None) if c == CommandType::ControlNew as u32 => {
                Some(serde_json::json!({"1": null}))
            }
            _ => data,
        };

        // 3. Build payload
        let mut payload = serde_json::Map::new();
        if let Some(c) = cid {
            payload.insert(KEY_CID.into(), c.into());
        }

        let use_nested = version_val >= 3.4
            && matches!(
                CommandType::from_u32(cmd_to_send),
                Some(CommandType::ControlNew | CommandType::LanExtStream)
            );

        if use_nested {
            payload.insert(KEY_PROTOCOL.into(), 5.into());
            payload.insert(KEY_T.into(), t.into());

            let mut data_obj = serde_json::Map::new();
            if let Some(c) = cid {
                data_obj.insert(KEY_CID.into(), c.into());
                data_obj.insert(KEY_CTYPE.into(), 0.into());
            }

            if let Some(d) = final_data {
                if cmd_to_send == CommandType::LanExtStream as u32 {
                    if let Some(obj) = d.as_object() {
                        data_obj.extend(obj.clone());
                    }
                } else {
                    data_obj.insert(KEY_DPS.into(), d);
                }
            }
            payload.insert(KEY_DATA.into(), Value::Object(data_obj));
        } else {
            let id = self.id.clone();
            payload.insert(KEY_GW_ID.into(), id.clone().into());
            payload.insert(KEY_DEV_ID.into(), cid.unwrap_or(&id).into());
            payload.insert(KEY_UID.into(), id.into());
            payload.insert(KEY_T.into(), t.to_string().into());
            if let Some(d) = final_data {
                payload.insert(KEY_DPS.into(), d);
            }
        }

        if let Some(rt) = req_type {
            payload.insert(KEY_REQ_TYPE.into(), rt.into());
        }

        Ok((cmd_to_send, Value::Object(payload)))
    }

    /// Discovers all sub-devices connected to this gateway.
    ///
    /// NOTE: For version 3.5 gateways, they may only send an empty ACK (0x40 with length 0)
    /// and occasionally fail to follow up with the actual report.
    pub async fn sub_discover(&self) {
        let data = serde_json::json!({ "cids": [] });
        self.request::<String, String>(
            CommandType::LanExtStream,
            Some(data),
            None,
            Some("subdev_online_stat_query".to_string()),
        )
        .await
    }
}

// -------------------------------------------------------------------------
// Connection & Streaming
// -------------------------------------------------------------------------
impl Device {
    /// Returns a Stream of messages from the device.
    pub fn stream(&self) -> impl Stream<Item = Result<TuyaMessage>> + Send + 'static {
        let mut rx = self.broadcast_tx.subscribe();
        async_stream::stream! {
            while let Ok(msg) = rx.recv().await {
                yield Ok(msg);
            }
        }
    }

    /// Receives a single message from the device.
    pub async fn receive(&self) -> Result<TuyaMessage> {
        let mut rx = self.broadcast_tx.subscribe();
        rx.recv().await.map_err(|e| TuyaError::Io(e.to_string()))
    }

    /// Closes the connection to the device and resets the stored IP address for discovery.
    pub async fn close(&self) {
        info!("Closing connection to device {}", self.id);

        self.with_state_mut(|state| {
            state.connected = false;
        });

        // Signal the background task to disconnect immediately
        if let Some(tx) = &self.tx {
            let _ = tx.send(DeviceCommand::Disconnect).await;
        }
    }

    /// Stops the device and its background tasks permanently.
    pub async fn stop(&self) {
        info!("Stopping device {}", self.id);
        self.with_state_mut(|state| {
            state.stopped = true;
        });
        self.cancel_token.cancel();
        self.close().await;
    }
}

// -------------------------------------------------------------------------
// Internal Communication & Background Task Helpers
// -------------------------------------------------------------------------
impl Device {
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

    /// Sends a custom request with a JSON payload to the device.
    ///
    /// This is a high-level API that ensures proper protocol version handling
    /// and automatic field injection.
    pub async fn request<C, R>(
        &self,
        command: CommandType,
        data: Option<Value>,
        cid: Option<C>,
        req_type: Option<R>,
    ) where
        C: Into<String>,
        R: Into<String>,
    {
        debug!("request: cmd={:?}, data={:?}", command, data);
        self.send_command_to_task(|resp_tx| DeviceCommand::Request {
            command,
            data,
            cid: cid.map(|c| c.into()),
            req_type: req_type.map(|r| r.into()),
            resp_tx,
        })
        .await;
    }

    async fn run_connection_task(mut self, mut rx: mpsc::Receiver<DeviceCommand>) {
        // Drop the internal sender to allow rx to close when all external handles are dropped.
        self.tx = None;

        // Add initial random jitter to heartbeat interval to avoid thundering herd (0-5 seconds)
        let jitter = {
            let mut rng = rand::rng();
            Duration::from_millis((rng.next_u32() % 5000) as u64)
        };
        let mut heartbeat_interval =
            tokio::time::interval_at(tokio::time::Instant::now() + jitter, SLEEP_HEARTBEAT_CHECK);
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        debug!("Starting background connection task for device {}", self.id);

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
                        self.with_state_mut(|s| s.failure_count += 1);
                        self.drain_rx(&mut rx, e.code(), false);
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

    pub fn id(&self) -> &str {
        &self.id
    }

    fn is_stopped(&self) -> bool {
        self.with_state(|s| s.stopped)
    }

    fn handle_disconnect(&self, err: Option<TuyaError>) {
        self.with_state_mut(|s| s.connected = false);

        if let Some(e) = err {
            if matches!(e, TuyaError::KeyOrVersionError) {
                warn!(
                    "Device {} possibly has key or version mismatch (Error 914)",
                    self.id
                );
            } else {
                debug!("Connection lost for device {} due to error: {}", self.id, e);
            }
            self.broadcast_error(e.code(), None);
        } else {
            debug!("Connection closed normally for device {}", self.id);
            self.broadcast_error(ERR_OFFLINE, None);
        }
    }

    fn drain_rx(&self, rx: &mut mpsc::Receiver<DeviceCommand>, code: u32, close: bool) {
        if close {
            rx.close();
        }
        while let Ok(cmd) = rx.try_recv() {
            let _ = cmd.respond(Err(TuyaError::from_code(code)));
        }
    }

    async fn try_connect_with_backoff(
        &self,
        rx: &mut mpsc::Receiver<DeviceCommand>,
        seqno: &mut u32,
    ) -> Option<TcpStream> {
        loop {
            if self.is_stopped() {
                self.drain_rx(rx, ERR_OFFLINE, true);
                return None;
            }

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
                self.connection_timeout * 2,
                self.connect_and_handshake(seqno),
            )
            .await;
            match result {
                Ok(Ok(s)) => {
                    self.with_state_mut(|s| s.connected = true);
                    self.broadcast_error(ERR_SUCCESS, None);
                    return Some(s);
                }
                _ => {
                    let e = match result {
                        Ok(Err(e)) => e,
                        _ => TuyaError::Offline,
                    };

                    self.handle_connection_error(&e).await;
                    self.drain_rx(rx, e.code(), false);

                    if !self.with_state(|s| s.persist) {
                        error!(
                            "Connection failed (persist: false) for device {}: {}",
                            self.id, e
                        );
                        self.drain_rx(rx, e.code(), true);
                        return None;
                    }

                    self.with_state_mut(|s| {
                        s.failure_count += 1;
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

        loop {
            tokio::select! {
                _ = &mut sleep_fut => return Some(()),
                _ = self.cancel_token.cancelled() => {
                    self.drain_rx(rx, ERR_OFFLINE, true);
                    return None;
                }
                cmd_opt = rx.recv() => {
                    if let Some(cmd) = cmd_opt {
                        debug!("Rejecting command during backoff for device {}", self.id);
                        let _ = cmd.respond(Err(TuyaError::Offline));
                        self.broadcast_error(ERR_OFFLINE, None);
                        // Continue waiting for backoff
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
        tokio::spawn(async move {
            let mut packets_received = 0;
            loop {
                tokio::select! {
                    _ = parent_cancel_token.cancelled() => break,
                    _ = reader_cancel_token.cancelled() => break,
                    res = read_half.read_u8() => {
                        match res {
                            Ok(byte) => {
                                if let Err(e) = device_clone.process_socket_data(&mut read_half, byte).await {
                                    let _ = internal_tx.send(e).await;
                                    break;
                                }
                                packets_received += 1;
                            }
                            Err(e) => {
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
                                    error!("Command processing failed for {}: {}", self.id, e);
                                    return Err(e);
                                }
                            }
                            None => {
                                debug!("All handles for device {} dropped, stopping task", self.id);
                                if let Ok(mut state) = self.state.write() {
                                    state.stopped = true;
                                }
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
        let (cmd_id, payload) = match cmd {
            DeviceCommand::Request {
                command,
                data,
                cid,
                req_type,
                resp_tx,
            } => {
                let _ = resp_tx.send(Ok(()));
                self.generate_payload(command, data, cid.as_deref(), req_type.as_deref())
                    .await?
            }
            DeviceCommand::Disconnect => {
                debug!("Disconnect command received for device {}", self.id);
                return Err(TuyaError::Io("Explicit disconnect".to_string()));
            }
        };

        self.send_json_msg(stream, seqno, cmd_id, &payload).await
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
        if let Ok(mut state) = self.state.write() {
            state.connected = false;
        }
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
                            PAYLOAD_RAW: payload_hex,
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
            self.connection_timeout,
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
        let (config_addr, force_discovery) =
            self.with_state(|s| (s.config_address.clone(), s.force_discovery));
        if config_addr != "Auto" && config_addr != "0.0.0.0" && !config_addr.is_empty() {
            return Ok(config_addr);
        }

        debug!(
            "Config address is {}, discovering device {} (force={})",
            config_addr, self.id, force_discovery
        );
        if let Ok(Some(result)) = self
            .scanner
            .discover_device_internal(&self.id, force_discovery)
            .await
        {
            let found_addr = result.ip;
            if let Some(version) = result.version
                && self.get_version() == Version::Auto
            {
                info!("Auto-detected version {} for device {}", version, self.id);
                self.set_version(version);
            }
            info!("Discovered device {} at {}", self.id, found_addr);
            self.with_state_mut(|s| {
                s.real_ip = found_addr.clone();
                s.force_discovery = false;
            });
            Ok(found_addr)
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
        timeout(self.connection_timeout, stream.write_all(&packed))
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
            self.connection_timeout,
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
        let dev_type_before = self.get_dev_type();
        match self.parse_and_read_body(stream, header_buf).await {
            Ok(Some(msg)) => {
                if dev_type_before != DEV_TYPE_DEVICE22 && self.get_dev_type() == DEV_TYPE_DEVICE22
                {
                    debug!("Device22 transition detected, reporting with original payload");
                    let original_payload = if msg.payload.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_slice(&msg.payload).unwrap_or_else(
                            |_| serde_json::json!({ PAYLOAD_RAW: hex::encode(&msg.payload) }),
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
                timeout(self.connection_timeout, stream.read_u8())
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
        let version_val = self.get_version().val();
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
        let secs = (2u64.pow(failure_count.min(6)) * min_secs).min(max_secs);
        Duration::from_secs(secs)
    }

    fn error_helper(&self, code: u32, payload: Option<Value>) -> TuyaMessage {
        let err_msg = get_error_message(code);
        let mut response = serde_json::json!({
            ERR_MSG: err_msg,
            ERR_CODE: code.to_string(),
        });

        if let Some(p) = payload {
            match p {
                Value::String(s) => {
                    response[PAYLOAD_STR] = Value::String(s);
                }
                Value::Object(mut obj) => {
                    if let Some(raw) = obj
                        .remove("raw")
                        .or_else(|| obj.remove("raw_payload"))
                        .or_else(|| obj.remove(PAYLOAD_RAW))
                    {
                        response[PAYLOAD_RAW] = raw;
                    }
                    // Merge any remaining fields (like "cmd" or original JSON data)
                    if let Some(obj_map) = response.as_object_mut() {
                        for (k, v) in obj {
                            obj_map.insert(k, v);
                        }
                    }
                }
                _ => {
                    response[ERR_PAYLOAD_OBJ] = p;
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

        let first_byte = timeout(self.connection_timeout, stream.read_u8())
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

    fn add_protocol_header(&self, payload: &[u8]) -> Vec<u8> {
        let mut header = self.get_version().as_bytes().to_vec();
        header.extend_from_slice(&[0u8; 12]);
        header.extend_from_slice(payload);
        header
    }

    fn pack_msg(&self, mut msg: TuyaMessage) -> Result<Vec<u8>> {
        let version_val = self.get_version().val();
        let dev_type = self.get_dev_type();
        let key = self.get_cipher_key();

        let cipher = TuyaCipher::new(&key)?;

        let use_header = !NO_PROTOCOL_HEADER_CMDS.contains(&msg.cmd);

        if version_val >= 3.4 {
            if use_header {
                msg.payload = self.add_protocol_header(&msg.payload);
            }
            if version_val >= 3.5 {
                msg.prefix = PREFIX_6699;
            } else {
                msg.payload = cipher.encrypt(&msg.payload, false, None, None, true)?;
            }
        } else if version_val >= 3.2 {
            msg.payload = cipher.encrypt(&msg.payload, false, None, None, true)?;
            if use_header {
                msg.payload = self.add_protocol_header(&msg.payload);
            }
        } else if dev_type == DEV_TYPE_DEVICE22 || msg.cmd == CommandType::Control as u32 {
            msg.payload = cipher.encrypt(&msg.payload, false, None, None, true)?;
        }

        let hmac_key = if version_val >= 3.4 {
            Some(key.as_slice())
        } else {
            None
        };
        pack_message(&msg, hmac_key)
    }

    fn get_cipher_key(&self) -> Vec<u8> {
        self.state
            .read()
            .map(|s| {
                s.session_key
                    .clone()
                    .unwrap_or_else(|| self.local_key.clone())
            })
            .unwrap_or_else(|_| self.local_key.clone())
    }

    async fn parse_and_read_body<R: AsyncReadExt + Unpin>(
        &self,
        stream: &mut R,
        header_buf: [u8; 16],
    ) -> Result<Option<TuyaMessage>> {
        let (packet, header) = self.read_full_packet(stream, header_buf).await?;
        debug!("Received packet (hex): {:?}", hex::encode(&packet));

        let mut decoded = self.unpack_and_check_dev22(&packet, header).await?;

        if !decoded.payload.is_empty() {
            debug!("Raw payload (hex): {:?}", hex::encode(&decoded.payload));
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
            timeout(self.connection_timeout, stream.read_exact(&mut extra))
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
        timeout(self.connection_timeout, stream.read_exact(&mut body))
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
        let version = self.get_version().val();
        let key = self.get_cipher_key();
        let hmac_key = (version >= 3.4).then_some(key.as_slice());

        unpack_message(packet, hmac_key, Some(header.clone()), Some(false)).or_else(|e| {
            if version == 3.3 && self.get_dev_type() != DEV_TYPE_DEVICE22 {
                if let Ok(d) = unpack_message(packet, None, Some(header), Some(false)) {
                    info!("Device22 detected via CRC32 fallback. Switching mode.");
                    self.set_dev_type(DEV_TYPE_DEVICE22);
                    return Ok(d);
                }
            }
            Err(e)
        })
    }

    async fn decrypt_and_clean_payload(
        &self,
        mut payload: Vec<u8>,
        prefix: u32,
    ) -> Result<Vec<u8>> {
        let version = self.get_version();
        let version_val = version.val();
        let dev_type = self.get_dev_type();
        let key = self.get_cipher_key();
        let cipher = TuyaCipher::new(&key)?;
        let version_bytes = version.as_bytes();

        if version_val >= 3.4 {
            if prefix == PREFIX_55AA {
                payload = cipher.decrypt(&payload, false, None, None, None)?;
            }
            if self.has_version_header(&payload, version_bytes, &dev_type) {
                payload = self.remove_version_header(payload);
            }
        } else if version_val >= 3.2 {
            if payload.len() >= 15 && &payload[..3] == version_bytes {
                payload = self.remove_version_header(payload);
            }
            if !payload.is_empty() {
                payload = self
                    .try_decrypt_32_payload(payload, &cipher, version_val, &dev_type, version_bytes)
                    .await?;
            }
            if (version_val == 3.3 || version_val == 3.4)
                && dev_type != DEV_TYPE_DEVICE22
                && String::from_utf8_lossy(&payload).contains(DATA_UNVALID)
            {
                warn!(
                    "Device22 detected via '{}' payload. Switching mode.",
                    DATA_UNVALID
                );
                self.set_dev_type(DEV_TYPE_DEVICE22);
            }
        }
        Ok(payload)
    }

    fn remove_version_header(&self, mut payload: Vec<u8>) -> Vec<u8> {
        if payload.len() >= 15 {
            payload.drain(..15);
            debug!(
                "Stripped version header, remaining (hex): {:?}",
                hex::encode(&payload)
            );
        }
        payload
    }

    async fn try_decrypt_32_payload(
        &self,
        payload: Vec<u8>,
        cipher: &TuyaCipher,
        version_val: f32,
        dev_type: &str,
        version_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        match cipher.decrypt(&payload, false, None, None, None) {
            Ok(mut decrypted) => {
                if self.has_version_header(&decrypted, version_bytes, dev_type) {
                    decrypted.drain(..15);
                }
                Ok(decrypted)
            }
            Err(e) => {
                let s = String::from_utf8_lossy(&payload);
                if ((version_val == 3.3 || version_val == 3.4) && s.contains(DATA_UNVALID))
                    || payload.first() == Some(&b'{')
                {
                    Ok(payload)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn has_version_header(&self, payload: &[u8], version_bytes: &[u8], dev_type: &str) -> bool {
        payload.len() >= 15
            && (&payload[..3] == version_bytes
                || (dev_type == DEV_TYPE_DEVICE22 && !payload.len().is_multiple_of(16)))
    }
}
