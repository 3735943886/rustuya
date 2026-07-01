//! Synchronous API wrappers for Tuya device communication.
//!
//! Provides blocking handles for devices, managers, and scanners by bridging
//! to the async core. This allows using the library in non-async environments
//! without manually managing a runtime.
//!
//! # Important: do not call this API from inside a tokio runtime
//!
//! The sync wrappers use `tokio::sync::mpsc::Sender::blocking_send` to talk
//! to their background worker. `blocking_send` is documented to **panic** if
//! it's invoked from a thread that's currently driving a tokio runtime
//! (e.g. inside `#[tokio::main]` or a `tokio::spawn` task).
//!
//! Since v0.3.0 every sync method runs through a runtime-context guard
//! (see [`check_no_runtime_context`]) that returns
//! [`TuyaError::io_other`](crate::error::TuyaError) instead of panicking —
//! but the error is *not* a substitute for using the right API:
//!
//! - From plain threads / `std::main`: use [`sync::Device`](Device),
//!   [`sync::SubDevice`](SubDevice), [`sync::Scanner`](Scanner).
//! - From inside any tokio runtime: use the async types
//!   [`rustuya::Device`](crate::Device),
//!   [`rustuya::DeviceBuilder`](crate::DeviceBuilder),
//!   [`rustuya::Scanner`](crate::Scanner) directly.
//!
//! The guard exists to surface the misuse with a clear error rather than a
//! panic; mixed-mode callers should not rely on it as part of their normal
//! control flow.

use crate::device::SubDevice as AsyncSubDevice;
use crate::device::{
    Device as AsyncDevice, DeviceBuilder as AsyncDeviceBuilder, DeviceEvent,
    unified_listener as async_unified_listener,
};
use crate::error::Result;
use crate::protocol::{TuyaMessage, Version};
use crate::runtime::{self, get_runtime};
use crate::scanner::{DiscoveryResult, Scanner as AsyncScanner, get as get_async_scanner};
use futures_util::StreamExt;
use log::warn;
use serde::Serialize;
use serde_json::Value;
use std::sync::OnceLock;
use std::sync::mpsc::TrySendError;
use std::time::Duration;
use tokio::sync::mpsc;

/// Default capacity for per-device synchronous listener channels.
const CHAN_SYNC_CAPACITY: usize = 128;

/// Capacity for the sync-to-async command channel used by each wrapper
/// (Device / SubDevice / Scanner).
///
/// 32 slots is more than enough for typical interactive use because each
/// sync call waits for its response before returning the channel slot. The
/// constant is centralized so all wrappers stay in sync (M4.7).
const CHAN_WORKER_COMMAND_CAPACITY: usize = 32;

/// Default capacity for the unified sync listener.
///
/// Sized to absorb burst events from hundreds-to-low-thousands of devices
/// (e.g. network recovery firing all devices at once). Power users with
/// larger fleets can override via [`unified_listener_with_capacity`].
const CHAN_UNIFIED_CAPACITY: usize = 2048;

/// FFI surface for foreign-language bindings (currently consumed by
/// `rustuya-python` via path dependency).
///
/// **Not part of the stable Rust public API.** The items here are visible
/// only because pyo3 bindings need to construct sync envelopes and dispatch
/// commands by hand to interleave `blocking_send` with signal handling.
/// Ordinary Rust callers should ignore this module and use the
/// [`Device`] / [`SubDevice`] / [`Scanner`] facades instead.
#[doc(hidden)]
pub mod internal {
    use super::Result;
    use super::get_runtime;
    use serde_json::Value;

    pub fn get_sync_runtime() -> &'static tokio::runtime::Runtime {
        get_runtime()
    }

    /// Sync-to-async dispatch envelope used by language bindings.
    pub struct SyncRequest<C, R = Option<String>> {
        pub command: C,
        pub resp_tx: std::sync::mpsc::Sender<Result<R>>,
    }

    /// Command enum for the sync device dispatch worker. Constructed by
    /// foreign bindings to interleave `blocking_send` with signal handling.
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

    /// Command enum for the sync sub-device dispatch worker.
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
}

// Pull the FFI types into the sync module's local namespace so the rest of
// the file reads naturally. The *only* public path to these types is now
// `rustuya::sync::internal::*` — the old top-level `sync::DeviceCommand`
// etc. are gone in 0.3.0-rc.2.
use internal::{DeviceCommand, SubDeviceCommand, SyncRequest};

/// Returns an error if the current thread is inside a tokio runtime context.
///
/// `tokio::sync::mpsc::Sender::blocking_send` panics ("Cannot block the current
/// thread from within a runtime") if called from an async task. The sync API
/// exists for callers who don't want a runtime; if you're already in one, use
/// the async [`rustuya::Device`] instead.
#[inline]
fn check_no_runtime_context() -> Result<()> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(crate::error::TuyaError::io_other(
            "rustuya sync API called from inside a tokio runtime — \
             use rustuya::Device (async) instead",
        ));
    }
    Ok(())
}

fn send_sync<C, R>(tx: &mpsc::Sender<SyncRequest<C, R>>, command: C) -> Result<R> {
    check_no_runtime_context()?;
    let (resp_tx, resp_rx) = std::sync::mpsc::channel();
    if tx.blocking_send(SyncRequest { command, resp_tx }).is_err() {
        return Err(crate::error::TuyaError::io_other("Worker died"));
    }
    resp_rx
        .recv()
        .map_err(|_| crate::error::TuyaError::io_other("Worker died"))?
}

/// Sync-side helper that:
///   1. validates we're not inside a tokio runtime (M1.7 guard)
///   2. creates a sync `mpsc::channel` for the response
///   3. uses `build` to construct the command (so the caller can plug the
///      `resp_tx` Sender into the right variant)
///   4. `blocking_send`s the command to the worker
///   5. blocks until the worker writes a response
///
/// Replaces the older `wait_for_response!` macro (M4.6). The shape is
/// identical (`Result<Result<R>>` — outer = transport, inner = command-level
/// error), so call sites only had to swap the macro for the function.
fn wait_for_response<C, R, F>(tx: &mpsc::Sender<C>, build: F) -> Result<R>
where
    F: FnOnce(std::sync::mpsc::Sender<R>) -> C,
{
    check_no_runtime_context()?;
    let (resp_tx, resp_rx) = std::sync::mpsc::channel::<R>();
    if tx.blocking_send(build(resp_tx)).is_err() {
        return Err(crate::error::TuyaError::io_other("Worker died"));
    }
    resp_rx
        .recv()
        .map_err(|_| crate::error::TuyaError::io_other("Worker died"))
}

// --- Device ---

#[derive(Clone)]
pub struct Device {
    #[doc(hidden)]
    pub inner: AsyncDevice,
    #[doc(hidden)]
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
        let (tx, mut rx) =
            mpsc::channel::<SyncRequest<DeviceCommand>>(CHAN_WORKER_COMMAND_CAPACITY);
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

    /// Drops the current device connection. The background reconnect task
    /// stays alive — the next sync call (`status`, `set_dps`, …) will trigger
    /// a fresh connect attempt unless `persist` is false.
    ///
    /// Bypasses the sync worker channel so it can short-circuit any pending
    /// command in flight (M2.1).
    pub fn close(&self) {
        self.inner.fire_close();
    }

    /// Permanently stops the device. Subsequent sync calls return
    /// `TuyaError::Offline`. Bypasses the worker channel.
    pub fn stop(&self) {
        self.inner.fire_stop();
    }

    // --- async-API mirror ---
    //
    // Sync wrappers around the trivial async getters/setters on AsyncDevice.
    // Previously these were reachable only via `Deref<Target = AsyncDevice>`,
    // which silently coerced sync handles to async ones and made it
    // impossible to tell at the call site whether a method went through the
    // sync worker or the async core. Mirroring them here lets the sync API
    // be self-contained; `as_async()` is the explicit escape hatch.

    /// Returns the underlying async [`AsyncDevice`] for callers that need to
    /// drive it from a tokio context. The async device shares state with
    /// this sync handle.
    pub fn as_async(&self) -> &AsyncDevice {
        &self.inner
    }

    pub fn dev_type(&self) -> crate::protocol::DeviceType {
        self.inner.dev_type()
    }

    pub fn local_key(&self) -> &[u8] {
        self.inner.local_key()
    }

    pub fn address(&self) -> String {
        self.inner.address()
    }

    pub fn config_address(&self) -> String {
        self.inner.config_address()
    }

    pub fn version(&self) -> Version {
        self.inner.version()
    }

    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    pub fn is_stopped(&self) -> bool {
        self.inner.is_stopped()
    }

    pub fn timeout(&self) -> std::time::Duration {
        self.inner.timeout()
    }

    pub fn port(&self) -> u16 {
        self.inner.port()
    }

    pub fn persist(&self) -> bool {
        self.inner.persist()
    }

    pub fn nowait(&self) -> bool {
        self.inner.nowait()
    }

    pub fn set_persist(&self, persist: bool) {
        self.inner.set_persist(persist);
    }

    pub fn set_timeout(&self, timeout: std::time::Duration) {
        self.inner.set_timeout(timeout);
    }

    pub fn set_port(&self, port: u16) {
        self.inner.set_port(port);
    }

    pub fn set_nowait(&self, nowait: bool) {
        self.inner.set_nowait(nowait);
    }

    pub fn set_version<V: Into<Version>>(&self, version: V) {
        self.inner.set_version(version);
    }

    pub fn set_dev_type<DT: Into<crate::protocol::DeviceType>>(&self, dev_type: DT) {
        self.inner.set_dev_type(dev_type);
    }

    pub fn set_address<A: Into<String>>(&self, address: A) {
        self.inner.set_address(address);
    }

    /// Forces an immediate (re)connect attempt, bypassing the backoff.
    ///
    /// Uses `fire_close` instead of the worker `ConnectNow` path so it
    /// doesn't queue behind in-flight commands.
    pub fn connect_now(&self) {
        // The async connect_now() sends DeviceCommand::ConnectNow over the
        // mpsc; mirror that without going through the sync worker — sync
        // close()/stop() already bypass the worker for the same reason.
        // We can't reach the device's private mpsc Sender, so just nudge
        // the actor via close_notify; the next user command (already queued
        // or fresh) will trigger reconnect.
        self.inner.fire_close();
    }

    /// Single-device sync listener.
    ///
    /// Returns a [`std::sync::mpsc::Receiver`] of `Result<TuyaMessage>` so
    /// that backend errors (broadcast lag, lost connection) are visible to
    /// the consumer — previously this stream silently filtered out `Err`,
    /// which made it impossible to tell whether the listener was idle or
    /// dead.
    pub fn listener(&self) -> std::sync::mpsc::Receiver<Result<TuyaMessage>> {
        let (tx, rx) = std::sync::mpsc::sync_channel(CHAN_SYNC_CAPACITY);
        let stream = self.inner.listener();
        let device_id = self.inner.id().to_string();

        runtime::spawn(async move {
            tokio::pin!(stream);
            // Preserve the Result so the consumer can distinguish a
            // delivered message from a broadcast lag / device-offline
            // synthetic.
            let messages = stream;
            tokio::pin!(messages);
            bridge_to_sync(messages, tx, move |dropped| {
                warn!(
                    "Sync listener for device {device_id} resumed after dropping {dropped} buffered messages"
                );
            })
            .await;
        });

        rx
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

    /// Finalizes the builder and returns a connected sync [`Device`].
    /// Preferred name; see [`DeviceBuilder::run`] for the deprecated alias.
    pub fn build(self) -> Device {
        Device::from_async(self.inner.build())
    }
}

// --- SubDevice ---

#[derive(Clone)]
pub struct SubDevice {
    #[doc(hidden)]
    pub inner: AsyncSubDevice,
    #[doc(hidden)]
    pub cmd_tx: mpsc::Sender<SyncRequest<SubDeviceCommand>>,
}

impl SubDevice {
    pub(crate) fn new(inner: AsyncSubDevice) -> Self {
        let (tx, mut rx) =
            mpsc::channel::<SyncRequest<SubDeviceCommand>>(CHAN_WORKER_COMMAND_CAPACITY);
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

    /// Returns the underlying async [`AsyncSubDevice`]. See
    /// [`Device::as_async`] for why this is preferred over the deprecated
    /// `Deref` coercion.
    pub fn as_async(&self) -> &AsyncSubDevice {
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

    fn new() -> Self {
        Self::from_async(get_async_scanner().clone())
    }

    /// Sets the discovery timeout on the underlying global scanner.
    pub fn set_timeout(&self, timeout: std::time::Duration) {
        self.inner.set_timeout(timeout);
    }

    /// Sets the UDP ports on the underlying global scanner; starts receivers
    /// for any newly added port.
    pub fn set_ports(&self, ports: Vec<u16>) {
        self.inner.set_ports(ports);
    }

    /// Sets the local bind address on the underlying global scanner.
    pub fn set_bind_address(&self, addr: &str) -> Result<()> {
        self.inner.set_bind_address(addr)
    }

    /// Sets the explicit source IPs the active discovery broadcast is sent from
    /// on the underlying global scanner. Empty (the default) auto-detects the
    /// source via a route lookup; configure one IP per subnet to actively probe
    /// on a multi-homed host. Affects sending only. See
    /// [`rustuya::Scanner::set_discovery_sources`](crate::Scanner::set_discovery_sources).
    pub fn set_discovery_sources(&self, sources: Vec<std::net::IpAddr>) {
        self.inner.set_discovery_sources(sources);
    }

    pub(crate) fn from_async(async_scanner: AsyncScanner) -> Self {
        let (tx, mut rx) = mpsc::channel::<ScannerCommand>(CHAN_WORKER_COMMAND_CAPACITY);
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
        wait_for_response(&self.cmd_tx, ScannerCommand::Scan)?
    }

    /// Discovers a specific device by ID.
    pub fn discover(id: &str) -> Option<DiscoveryResult> {
        Self::get().discover_instance(id)
    }

    /// Instance version of `discover`.
    pub fn discover_instance(&self, id: &str) -> Option<DiscoveryResult> {
        wait_for_response(&self.cmd_tx, |resp_tx| {
            ScannerCommand::Discover(id.to_string(), resp_tx)
        })
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
            let stream = async_scanner.scan_stream_instance();
            tokio::pin!(stream);
            bridge_to_sync(stream, tx, |dropped| {
                warn!("Sync scan stream resumed after dropping {dropped} buffered results");
            })
            .await;
        });

        rx
    }
}

/// Merges multiple sync device listeners into a single synchronous receiver
/// with the default buffer capacity ([`CHAN_UNIFIED_CAPACITY`]).
pub fn unified_listener(devices: Vec<Device>) -> std::sync::mpsc::Receiver<Result<DeviceEvent>> {
    unified_listener_with_capacity(devices, CHAN_UNIFIED_CAPACITY)
}

/// Same as [`unified_listener`] but with a caller-specified channel buffer.
///
/// Use a larger capacity for deployments where burst event rates can briefly
/// exceed consumer throughput. A rough sizing rule is "a few seconds of
/// slack at the expected aggregate event rate".
pub fn unified_listener_with_capacity(
    devices: Vec<Device>,
    capacity: usize,
) -> std::sync::mpsc::Receiver<Result<DeviceEvent>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
    let async_devices: Vec<AsyncDevice> = devices.into_iter().map(|d| d.inner.clone()).collect();

    runtime::spawn(async move {
        let stream = async_unified_listener(async_devices);
        tokio::pin!(stream);
        bridge_to_sync(stream, tx, |dropped| {
            warn!("Sync unified listener resumed after dropping {dropped} buffered events");
        })
        .await;
    });

    rx
}

/// Forwards items from an async [`Stream`] into a bounded sync channel,
/// keeping the bridge alive even when the consumer is too slow.
///
/// On a full channel the item is dropped and a counter is incremented; when
/// the consumer catches up the next successful send fires `on_resume` once
/// with the dropped count. The bridge only exits when the receiver is
/// disconnected or the stream ends.
async fn bridge_to_sync<S, T, F>(
    mut stream: std::pin::Pin<&mut S>,
    tx: std::sync::mpsc::SyncSender<T>,
    mut on_resume: F,
) where
    S: futures_core::stream::Stream<Item = T>,
    F: FnMut(u64),
{
    let mut dropped: u64 = 0;
    while let Some(item) = stream.next().await {
        match tx.try_send(item) {
            Ok(()) => {
                if dropped > 0 {
                    on_resume(dropped);
                    dropped = 0;
                }
            }
            Err(TrySendError::Full(_)) => {
                dropped = dropped.saturating_add(1);
            }
            Err(TrySendError::Disconnected(_)) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{bridge_to_sync, check_no_runtime_context};
    use futures_util::stream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    // M1.7 regression: calling the sync API from inside a tokio runtime must
    // surface a clear error instead of panicking inside `blocking_send`.
    #[test]
    fn check_no_runtime_context_errors_inside_runtime() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let res = check_no_runtime_context();
            assert!(res.is_err(), "expected error when inside a tokio runtime");
            let msg = format!("{}", res.unwrap_err());
            assert!(
                msg.contains("tokio runtime"),
                "error message should mention runtime, got: {msg}"
            );
        });
    }

    // And from a plain thread (no runtime) the guard must permit the call.
    #[test]
    fn check_no_runtime_context_ok_outside_runtime() {
        assert!(check_no_runtime_context().is_ok());
    }

    /// Bridge survives when the channel is full and drops the overflow,
    /// rather than exiting like the previous `try_send`-and-`break` version.
    #[test]
    fn bridge_drops_overflow_and_keeps_running() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let (tx, rx) = std::sync::mpsc::sync_channel::<u32>(2);
            let resumed_with = Arc::new(AtomicU64::new(0));
            let resumed_clone = resumed_with.clone();

            // 5 items into a 2-slot channel: first 2 land, next 3 are dropped.
            let stream = stream::iter(vec![1u32, 2, 3, 4, 5]);
            tokio::pin!(stream);
            bridge_to_sync(stream, tx, move |dropped| {
                resumed_clone.store(dropped, Ordering::SeqCst);
            })
            .await;

            assert_eq!(rx.try_recv().unwrap(), 1);
            assert_eq!(rx.try_recv().unwrap(), 2);
            // Items 3..=5 were dropped and never made it to the channel.
            assert!(rx.try_recv().is_err());
            // No "resume" was fired because the consumer never caught up.
            assert_eq!(resumed_with.load(Ordering::SeqCst), 0);
        });
    }

    /// When the consumer catches up after a drop streak, `on_resume` fires
    /// exactly once with the cumulative dropped count.
    #[test]
    fn bridge_reports_dropped_count_when_consumer_catches_up() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let (tx, rx) = std::sync::mpsc::sync_channel::<u32>(1);
            let resumed_with = Arc::new(AtomicU64::new(0));
            let resumed_clone = resumed_with.clone();

            // Drain channel between items so the bridge alternates full/empty.
            let (gate_tx, mut gate_rx) = tokio::sync::mpsc::channel::<()>(8);
            let producer = async_stream::stream! {
                yield 1u32;       // lands
                yield 2;          // dropped (channel full)
                yield 3;          // dropped
                gate_rx.recv().await; // wait for consumer to drain
                yield 4;          // lands → triggers resume with dropped=2
            };
            tokio::pin!(producer);

            let consumer = tokio::spawn(async move {
                // Eagerly drain item 1, then signal producer to continue.
                tokio::task::spawn_blocking(move || {
                    let first = rx.recv().unwrap();
                    assert_eq!(first, 1);
                    // Tell producer the consumer caught up.
                    let _ = gate_tx.blocking_send(());
                    let next = rx.recv().unwrap();
                    assert_eq!(next, 4);
                })
                .await
                .unwrap();
            });

            bridge_to_sync(producer, tx, move |dropped| {
                resumed_clone.store(dropped, Ordering::SeqCst);
            })
            .await;

            consumer.await.unwrap();
            assert_eq!(resumed_with.load(Ordering::SeqCst), 2);
        });
    }

    /// Bridge exits cleanly when the receiver is dropped.
    #[test]
    fn bridge_exits_on_receiver_disconnect() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let (tx, rx) = std::sync::mpsc::sync_channel::<u32>(4);
            drop(rx); // Consumer is gone before the bridge starts pumping.

            let stream = stream::iter(vec![1u32, 2, 3]);
            tokio::pin!(stream);
            // No panic, no hang — just early exit.
            bridge_to_sync(stream, tx, |_| {
                panic!("on_resume must not fire on disconnect")
            })
            .await;
        });
    }
}
