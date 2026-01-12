//! Synchronous API wrappers for Tuya device communication.
//!
//! Provides blocking handles for devices, managers, and scanners by bridging to the async core.
//! This allows using the library in non-async environments without manually managing a runtime.

use crate::device::SubDevice as AsyncSubDevice;
use crate::device::{
    Device as AsyncDevice, DeviceBuilder as AsyncDeviceBuilder, DeviceEvent,
    unified_listener as async_unified_listener,
};
use crate::error::Result;
use crate::protocol::{TuyaMessage, Version};
use crate::runtime::{self, get_runtime};
use crate::scanner::{DiscoveryResult, Scanner as AsyncScanner, get as get_async_scanner};
use serde::Serialize;
use serde_json::Value;
use std::ops::Deref;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::mpsc;

/// Default capacity for synchronous event channels to prevent memory buildup.
const CHAN_SYNC_CAPACITY: usize = 128;

pub mod internal {
    use super::*;
    pub fn get_sync_runtime() -> &'static tokio::runtime::Runtime {
        get_runtime()
    }
}

pub struct SyncRequest<C, R = Option<String>> {
    pub command: C,
    pub resp_tx: std::sync::mpsc::Sender<Result<R>>,
}

fn send_sync<C, R>(tx: &mpsc::Sender<SyncRequest<C, R>>, command: C) -> Result<R> {
    let (resp_tx, resp_rx) = std::sync::mpsc::channel();
    let _ = tx.blocking_send(SyncRequest { command, resp_tx });
    resp_rx
        .recv()
        .map_err(|_| crate::error::TuyaError::Io("Worker died".into()))?
}

macro_rules! wait_for_response {
    ($tx:expr, $cmd_gen:expr) => {{
        let (resp_tx, resp_rx) = std::sync::mpsc::channel();
        let _ = $tx.blocking_send($cmd_gen(resp_tx));
        resp_rx
            .recv()
            .map_err(|_| crate::error::TuyaError::Io("Worker died".into()))
    }};
}

// --- Device ---

#[derive(Debug)]
pub enum DeviceCommand {
    Status,
    SetDps(Value),
    SetValue(String, Value),
    Request {
        command: crate::protocol::CommandType,
        data: Option<Value>,
        cid: Option<String>,
    },
    SubDiscover,
    Close,
    Stop,
}

#[derive(Clone)]
pub struct Device {
    pub inner: AsyncDevice,
    pub cmd_tx: mpsc::Sender<SyncRequest<DeviceCommand>>,
}

impl Device {
    /// Creates a new device with default settings and starts the connection task.
    pub fn new<I, K>(id: I, local_key: K) -> Self
    where
        I: Into<String>,
        K: Into<Vec<u8>>,
    {
        Self::from_async(AsyncDevice::new(id, local_key))
    }

    /// Returns a builder to configure device settings before running.
    pub fn builder<I, K>(id: I, local_key: K) -> DeviceBuilder
    where
        I: Into<String>,
        K: Into<Vec<u8>>,
    {
        DeviceBuilder::new(id, local_key)
    }

    pub(crate) fn from_async(device: AsyncDevice) -> Self {
        let (tx, mut rx) = mpsc::channel::<SyncRequest<DeviceCommand>>(32);
        let inner_clone = device.clone();

        // Background worker for the sync device.
        // Automatically stops when all Device handles are dropped.
        runtime::spawn(async move {
            while let Some(req) = rx.recv().await {
                let res = match req.command {
                    DeviceCommand::Status => inner_clone.status().await,
                    DeviceCommand::SetDps(dps) => inner_clone.set_dps(dps).await,
                    DeviceCommand::SetValue(dp_id, value) => {
                        inner_clone.set_value(dp_id, value).await
                    }
                    DeviceCommand::Request { command, data, cid } => {
                        inner_clone.request(command, data, cid).await
                    }
                    DeviceCommand::SubDiscover => inner_clone.sub_discover().await,
                    DeviceCommand::Close => {
                        inner_clone.close().await;
                        Ok(None)
                    }
                    DeviceCommand::Stop => {
                        inner_clone.stop().await;
                        Ok(None)
                    }
                };
                let _ = req.resp_tx.send(res);
            }
        });

        Self {
            inner: device,
            cmd_tx: tx,
        }
    }

    pub fn id(&self) -> &str {
        self.inner.id()
    }

    pub fn status(&self) -> Result<Option<String>> {
        send_sync(&self.cmd_tx, DeviceCommand::Status)
    }

    pub fn set_dps(&self, dps: Value) -> Result<Option<String>> {
        send_sync(&self.cmd_tx, DeviceCommand::SetDps(dps))
    }

    pub fn set_value<I: ToString, T: Serialize>(
        &self,
        dp_id: I,
        value: T,
    ) -> Result<Option<String>> {
        if let Ok(val) = serde_json::to_value(value) {
            send_sync(
                &self.cmd_tx,
                DeviceCommand::SetValue(dp_id.to_string(), val),
            )
        } else {
            Err(crate::error::TuyaError::InvalidPayload)
        }
    }

    pub fn request(
        &self,
        cmd: crate::protocol::CommandType,
        data: Option<Value>,
        cid: Option<String>,
    ) -> Result<Option<String>> {
        send_sync(
            &self.cmd_tx,
            DeviceCommand::Request {
                command: cmd,
                data,
                cid,
            },
        )
    }

    pub fn sub_discover(&self) -> Result<Option<String>> {
        send_sync(&self.cmd_tx, DeviceCommand::SubDiscover)
    }

    pub fn sub(&self, cid: &str) -> SubDevice {
        SubDevice::new(self.inner.sub(cid))
    }

    pub fn close(&self) {
        let _ = send_sync(&self.cmd_tx, DeviceCommand::Close);
    }

    pub fn stop(&self) {
        let _ = send_sync(&self.cmd_tx, DeviceCommand::Stop);
    }

    pub fn listener(&self) -> std::sync::mpsc::Receiver<TuyaMessage> {
        let (tx, rx) = std::sync::mpsc::sync_channel(CHAN_SYNC_CAPACITY);
        let mut broadcast_rx = self.inner.broadcast_tx.subscribe();

        runtime::spawn(async move {
            while let Ok(msg) = broadcast_rx.recv().await {
                if !msg.payload.is_empty() && tx.try_send(msg).is_err() {
                    // Buffer full or receiver dropped
                    break;
                }
            }
        });

        rx
    }
}

impl Deref for Device {
    type Target = AsyncDevice;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// --- DeviceBuilder ---

pub struct DeviceBuilder {
    inner: AsyncDeviceBuilder,
}

impl DeviceBuilder {
    pub fn new<I, K>(id: I, local_key: K) -> Self
    where
        I: Into<String>,
        K: Into<Vec<u8>>,
    {
        Self {
            inner: AsyncDeviceBuilder::new(id, local_key),
        }
    }

    pub fn address<A: Into<String>>(mut self, address: A) -> Self {
        self.inner = self.inner.address(address);
        self
    }

    pub fn version<V: Into<Version>>(mut self, version: V) -> Self {
        self.inner = self.inner.version(version);
        self
    }

    pub fn dev_type<D: Into<crate::protocol::DeviceType>>(mut self, dev_type: D) -> Self {
        self.inner = self.inner.dev_type(dev_type);
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.inner = self.inner.port(port);
        self
    }

    pub fn persist(mut self, persist: bool) -> Self {
        self.inner = self.inner.persist(persist);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    pub fn nowait(mut self, nowait: bool) -> Self {
        self.inner = self.inner.nowait(nowait);
        self
    }

    pub fn run(self) -> Device {
        Device::from_async(self.inner.run())
    }
}

// --- SubDevice ---

#[derive(Debug)]
pub enum SubDeviceCommand {
    Status,
    SetDps(Value),
    SetValue(String, Value),
    Request {
        command: crate::protocol::CommandType,
        data: Option<Value>,
    },
}

#[derive(Clone)]
pub struct SubDevice {
    pub inner: AsyncSubDevice,
    pub cmd_tx: mpsc::Sender<SyncRequest<SubDeviceCommand>>,
}

impl SubDevice {
    pub(crate) fn new(inner: AsyncSubDevice) -> Self {
        let (tx, mut rx) = mpsc::channel::<SyncRequest<SubDeviceCommand>>(32);
        let inner_clone = inner.clone();

        runtime::spawn(async move {
            while let Some(req) = rx.recv().await {
                let res = match req.command {
                    SubDeviceCommand::Status => inner_clone.status().await,
                    SubDeviceCommand::SetDps(dps) => inner_clone.set_dps(dps).await,
                    SubDeviceCommand::SetValue(index, value) => {
                        inner_clone.set_value(index, value).await
                    }
                    SubDeviceCommand::Request { command, data } => {
                        inner_clone.request(command, data).await
                    }
                };
                let _ = req.resp_tx.send(res);
            }
        });

        Self { inner, cmd_tx: tx }
    }

    pub fn id(&self) -> &str {
        self.inner.id()
    }

    pub fn status(&self) -> Result<Option<String>> {
        send_sync(&self.cmd_tx, SubDeviceCommand::Status)
    }

    pub fn set_dps(&self, dps: Value) -> Result<Option<String>> {
        send_sync(&self.cmd_tx, SubDeviceCommand::SetDps(dps))
    }

    pub fn set_value<I: ToString, T: Serialize>(
        &self,
        index: I,
        value: T,
    ) -> Result<Option<String>> {
        if let Ok(val) = serde_json::to_value(value) {
            send_sync(
                &self.cmd_tx,
                SubDeviceCommand::SetValue(index.to_string(), val),
            )
        } else {
            Err(crate::error::TuyaError::InvalidPayload)
        }
    }

    pub fn request(
        &self,
        cmd: crate::protocol::CommandType,
        data: Option<Value>,
    ) -> Result<Option<String>> {
        send_sync(
            &self.cmd_tx,
            SubDeviceCommand::Request { command: cmd, data },
        )
    }
}

impl Deref for SubDevice {
    type Target = AsyncSubDevice;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// --- Scanner ---

enum ScannerCommand {
    Scan(std::sync::mpsc::Sender<Result<Vec<DiscoveryResult>>>),
    Discover(String, std::sync::mpsc::Sender<Option<DiscoveryResult>>),
}

#[derive(Clone)]
pub struct Scanner {
    inner: AsyncScanner,
    cmd_tx: mpsc::Sender<ScannerCommand>,
}

static SYNC_SCANNER: OnceLock<Scanner> = OnceLock::new();

impl Scanner {
    /// Returns the global sync scanner instance.
    pub fn get() -> &'static Self {
        SYNC_SCANNER.get_or_init(Self::new)
    }

    /// Creates a new Scanner builder.
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::new()
    }

    fn new() -> Self {
        Self::from_async(get_async_scanner().clone())
    }

    pub(crate) fn from_async(async_scanner: AsyncScanner) -> Self {
        let (tx, mut rx) = mpsc::channel::<ScannerCommand>(32);
        let scanner_inner = async_scanner.clone();

        // Background worker for the sync scanner.
        // It will automatically stop when all Sender (cmd_tx) handles are dropped,
        // as rx.recv() will return None. This ensures proper RAII and resource cleanup.
        runtime::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ScannerCommand::Scan(resp_tx) => {
                        let res = scanner_inner.scan_instance().await;
                        let _ = resp_tx.send(res);
                    }
                    ScannerCommand::Discover(id, resp_tx) => {
                        let res = scanner_inner
                            .discover_device_instance(&id)
                            .await
                            .ok()
                            .flatten();
                        let _ = resp_tx.send(res);
                    }
                }
            }
        });

        Self {
            inner: async_scanner,
            cmd_tx: tx,
        }
    }

    /// Scans the local network for all Tuya devices and returns a list of results.
    pub fn scan() -> Result<Vec<DiscoveryResult>> {
        Self::get().scan_instance()
    }

    /// Instance version of `scan`.
    pub fn scan_instance(&self) -> Result<Vec<DiscoveryResult>> {
        wait_for_response!(self.cmd_tx, ScannerCommand::Scan)?
    }

    /// Discovers a specific device by ID.
    pub fn discover(id: &str) -> Option<DiscoveryResult> {
        Self::get().discover_instance(id)
    }

    /// Instance version of `discover`.
    pub fn discover_instance(&self, id: &str) -> Option<DiscoveryResult> {
        wait_for_response!(self.cmd_tx, |resp_tx| ScannerCommand::Discover(
            id.to_string(),
            resp_tx
        ))
        .ok()
        .flatten()
    }

    /// Returns a synchronous iterator (Receiver) that yields discovery results in real-time.
    pub fn scan_stream() -> std::sync::mpsc::Receiver<DiscoveryResult> {
        Self::get().scan_stream_instance()
    }

    /// Instance version of `scan_stream`.
    pub fn scan_stream_instance(&self) -> std::sync::mpsc::Receiver<DiscoveryResult> {
        let (tx, rx) = std::sync::mpsc::sync_channel(CHAN_SYNC_CAPACITY);
        let async_scanner = self.inner.clone();

        runtime::spawn(async move {
            use futures_util::StreamExt;
            let stream = async_scanner.scan_stream_instance();
            tokio::pin!(stream);
            while let Some(device) = stream.next().await {
                if tx.try_send(device).is_err() {
                    break;
                }
            }
        });

        rx
    }
}

/// Builder for creating a custom synchronous `Scanner`.
pub struct ScannerBuilder {
    inner: crate::scanner::ScannerBuilder,
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ScannerBuilder {
    pub fn new() -> Self {
        Self {
            inner: crate::scanner::ScannerBuilder::new(),
        }
    }

    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    pub fn bind_addr<S: Into<String>>(mut self, addr: S) -> Self {
        self.inner = self.inner.bind_addr(addr);
        self
    }

    pub fn ports(mut self, ports: Vec<u16>) -> Self {
        self.inner = self.inner.ports(ports);
        self
    }

    pub fn build(self) -> Scanner {
        Scanner::from_async(self.inner.build())
    }
}

/// Merges multiple sync device listeners into a single synchronous receiver.
pub fn unified_listener(devices: Vec<Device>) -> std::sync::mpsc::Receiver<Result<DeviceEvent>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(CHAN_SYNC_CAPACITY);
    let async_devices: Vec<AsyncDevice> = devices.into_iter().map(|d| d.inner.clone()).collect();

    runtime::spawn(async move {
        use futures_util::StreamExt;
        let mut stream = async_unified_listener(async_devices);
        while let Some(event) = stream.next().await {
            if tx.try_send(event).is_err() {
                break;
            }
        }
    });

    rx
}
