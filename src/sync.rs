//! Synchronous API wrappers for Tuya device communication.
//!
//! Provides blocking handles for devices, managers, and scanners by bridging to the async core.

use crate::device::{Device as AsyncDevice, SubDevice as AsyncSubDevice};
use crate::error::Result;
use crate::manager::{Manager as AsyncManager, ManagerEvent};
use crate::protocol::{TuyaMessage, Version};
use crate::runtime::{self, get_runtime};
use crate::scanner::{DiscoveryResult, Scanner as AsyncScanner};
use serde::Serialize;
use serde_json::Value;
use std::ops::Deref;
use std::time::Duration;
use tokio::sync::mpsc;

pub mod internal {
    use super::*;
    pub fn get_sync_runtime() -> &'static tokio::runtime::Runtime {
        get_runtime()
    }
}

struct SyncRequest<C, R = ()> {
    command: C,
    resp_tx: std::sync::mpsc::Sender<R>,
}

fn send_sync<C, R>(
    tx: &mpsc::Sender<SyncRequest<C, R>>,
    command: C,
) -> std::result::Result<R, std::sync::mpsc::RecvError> {
    let (resp_tx, resp_rx) = std::sync::mpsc::channel();
    let _ = tx.blocking_send(SyncRequest { command, resp_tx });
    resp_rx.recv()
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

enum DeviceCommand {
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

enum SubDeviceCommand {
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
    inner: AsyncSubDevice,
    cmd_tx: mpsc::Sender<SyncRequest<SubDeviceCommand>>,
}

impl SubDevice {
    pub(crate) fn new(inner: AsyncSubDevice) -> Self {
        let (tx, mut rx) = mpsc::channel::<SyncRequest<SubDeviceCommand>>(32);
        let inner_clone = inner.clone();

        runtime::spawn(async move {
            while let Some(req) = rx.recv().await {
                match req.command {
                    SubDeviceCommand::Status => inner_clone.status().await,
                    SubDeviceCommand::SetDps(dps) => inner_clone.set_dps(dps).await,
                    SubDeviceCommand::SetValue(index, value) => {
                        inner_clone.set_value(index, value).await
                    }
                    SubDeviceCommand::Request { command, data } => {
                        inner_clone.request(command, data).await
                    }
                }
                let _ = req.resp_tx.send(());
            }
        });

        Self { inner, cmd_tx: tx }
    }

    pub fn status(&self) {
        let _ = send_sync(&self.cmd_tx, SubDeviceCommand::Status);
    }

    pub fn set_dps(&self, dps: Value) {
        let _ = send_sync(&self.cmd_tx, SubDeviceCommand::SetDps(dps));
    }

    pub fn set_value<I: ToString, T: Serialize>(&self, index: I, value: T) {
        if let Ok(val) = serde_json::to_value(value) {
            let _ = send_sync(
                &self.cmd_tx,
                SubDeviceCommand::SetValue(index.to_string(), val),
            );
        }
    }

    pub fn request(&self, cmd: crate::protocol::CommandType, data: Option<Value>) {
        let _ = send_sync(
            &self.cmd_tx,
            SubDeviceCommand::Request { command: cmd, data },
        );
    }
}

impl Deref for SubDevice {
    type Target = AsyncSubDevice;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Clone)]
pub struct Device {
    inner: AsyncDevice,
    cmd_tx: mpsc::Sender<SyncRequest<DeviceCommand>>,
}

impl Device {
    pub fn new<I, A, K, V>(id: I, address: A, local_key: K, version: V) -> Self
    where
        I: Into<String>,
        A: Into<String>,
        K: Into<Vec<u8>>,
        V: Into<Version>,
    {
        let device = AsyncDevice::new(id, address, local_key, version);
        Self::from_async(device)
    }

    pub(crate) fn from_async(device: AsyncDevice) -> Self {
        let (tx, mut rx) = mpsc::channel::<SyncRequest<DeviceCommand>>(32);
        let inner_clone = device.clone();

        runtime::spawn(async move {
            while let Some(req) = rx.recv().await {
                match req.command {
                    DeviceCommand::Status => inner_clone.status().await,
                    DeviceCommand::SetDps(dps) => inner_clone.set_dps(dps).await,
                    DeviceCommand::SetValue(dp_id, value) => {
                        inner_clone.set_value(dp_id, value).await
                    }
                    DeviceCommand::Request { command, data, cid } => {
                        inner_clone.request(command, data, cid).await
                    }
                    DeviceCommand::SubDiscover => inner_clone.sub_discover().await,
                    DeviceCommand::Close => inner_clone.close().await,
                    DeviceCommand::Stop => inner_clone.stop().await,
                }
                let _ = req.resp_tx.send(());
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

    pub fn local_key(&self) -> &[u8] {
        self.inner.local_key()
    }

    pub fn address(&self) -> String {
        self.inner.address()
    }

    pub fn status(&self) {
        let _ = send_sync(&self.cmd_tx, DeviceCommand::Status);
    }

    pub fn set_dps(&self, dps: Value) {
        let _ = send_sync(&self.cmd_tx, DeviceCommand::SetDps(dps));
    }

    pub fn set_value<I: ToString, T: Serialize>(&self, dp_id: I, value: T) {
        if let Ok(val) = serde_json::to_value(value) {
            let _ = send_sync(
                &self.cmd_tx,
                DeviceCommand::SetValue(dp_id.to_string(), val),
            );
        }
    }

    pub fn request(
        &self,
        cmd: crate::protocol::CommandType,
        data: Option<Value>,
        cid: Option<String>,
    ) {
        let _ = send_sync(
            &self.cmd_tx,
            DeviceCommand::Request {
                command: cmd,
                data,
                cid,
            },
        );
    }

    pub fn sub_discover(&self) {
        let _ = send_sync(&self.cmd_tx, DeviceCommand::SubDiscover);
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
        let (tx, rx) = std::sync::mpsc::channel();
        let mut broadcast_rx = self.inner.broadcast_tx.subscribe();

        runtime::spawn(async move {
            while let Ok(msg) = broadcast_rx.recv().await {
                if tx.send(msg).is_err() {
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

enum ScannerCommand {
    Scan(
        AsyncScanner,
        std::sync::mpsc::Sender<Result<Vec<DiscoveryResult>>>,
    ),
    Discover(
        AsyncScanner,
        String,
        std::sync::mpsc::Sender<Option<DiscoveryResult>>,
    ),
}

pub struct Scanner {
    inner: AsyncScanner,
    cmd_tx: mpsc::Sender<ScannerCommand>,
}

impl Clone for Scanner {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            cmd_tx: self.cmd_tx.clone(),
        }
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub fn new() -> Self {
        let inner = AsyncScanner::new();
        let (tx, mut rx) = mpsc::channel::<ScannerCommand>(32);

        runtime::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ScannerCommand::Scan(scanner, resp_tx) => {
                        let res = scanner.scan().await;
                        let _ = resp_tx.send(res);
                    }
                    ScannerCommand::Discover(scanner, id, resp_tx) => {
                        let res = scanner.discover_device(&id).await.ok().flatten();
                        let _ = resp_tx.send(res);
                    }
                }
            }
        });

        Self { inner, cmd_tx: tx }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.with_timeout(timeout);
        self
    }

    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.inner = self.inner.with_ports(ports);
        self
    }

    pub fn with_bind_address(mut self, addr: String) -> Self {
        self.inner = self.inner.with_bind_addr(addr);
        self
    }

    pub fn scan(&self) -> Result<Vec<DiscoveryResult>> {
        wait_for_response!(self.cmd_tx, |resp_tx| ScannerCommand::Scan(
            self.inner.clone(),
            resp_tx
        ))?
    }

    pub fn discover(&self, id: &str) -> Option<DiscoveryResult> {
        wait_for_response!(self.cmd_tx, |resp_tx| ScannerCommand::Discover(
            self.inner.clone(),
            id.to_string(),
            resp_tx
        ))
        .ok()
        .flatten()
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.inner = self.inner.clone().with_timeout(timeout);
    }

    pub fn set_bind_address(&mut self, addr: &str) -> Result<()> {
        self.inner = self.inner.clone().with_bind_addr(addr.to_string());
        Ok(())
    }

    pub fn stop_passive_listener() {
        AsyncScanner::stop_passive_listener();
    }
}

impl Deref for Scanner {
    type Target = AsyncScanner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

enum ManagerCommand {
    Add(
        String,
        String,
        String,
        Version,
        std::sync::mpsc::Sender<Result<()>>,
    ),
    Remove(String, std::sync::mpsc::Sender<()>),
    Delete(String, std::sync::mpsc::Sender<()>),
    Modify(
        String,
        String,
        String,
        Version,
        std::sync::mpsc::Sender<Result<()>>,
    ),
    Get(String, std::sync::mpsc::Sender<Option<AsyncDevice>>),
    List(std::sync::mpsc::Sender<Vec<crate::manager::DeviceInfo>>),
    Clear(std::sync::mpsc::Sender<()>),
    Shutdown(std::sync::mpsc::Sender<()>),
}

#[derive(Clone)]
pub struct Manager {
    inner: AsyncManager,
    cmd_tx: mpsc::Sender<ManagerCommand>,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    pub fn new() -> Self {
        let inner = AsyncManager::new();
        let (tx, mut rx) = mpsc::channel::<ManagerCommand>(32);
        let inner_clone = inner.clone();

        runtime::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    ManagerCommand::Add(id, addr, key, ver, resp) => {
                        let res = inner_clone.add(&id, &addr, &key, ver).await;
                        let _ = resp.send(res);
                    }
                    ManagerCommand::Remove(id, resp) => {
                        inner_clone.remove(&id).await;
                        let _ = resp.send(());
                    }
                    ManagerCommand::Delete(id, resp) => {
                        inner_clone.delete(&id).await;
                        let _ = resp.send(());
                    }
                    ManagerCommand::Modify(id, addr, key, ver, resp) => {
                        let res = inner_clone.modify(&id, &addr, &key, ver).await;
                        let _ = resp.send(res);
                    }
                    ManagerCommand::Get(id, resp) => {
                        let res = inner_clone.get(&id).await;
                        let _ = resp.send(res);
                    }
                    ManagerCommand::List(resp) => {
                        let res = inner_clone.list().await;
                        let _ = resp.send(res);
                    }
                    ManagerCommand::Clear(resp) => {
                        inner_clone.clear().await;
                        let _ = resp.send(());
                    }
                    ManagerCommand::Shutdown(resp) => {
                        inner_clone.clone().shutdown().await;
                        let _ = resp.send(());
                    }
                }
            }
        });

        Self { inner, cmd_tx: tx }
    }

    pub fn maximize_fd_limit() -> Result<()> {
        AsyncManager::maximize_fd_limit()
    }

    pub fn shutdown_all() {
        AsyncManager::shutdown_all();
    }

    pub fn add<V>(&self, id: &str, address: &str, local_key: &str, version: V) -> Result<()>
    where
        V: Into<Version>,
    {
        wait_for_response!(self.cmd_tx, |resp_tx| ManagerCommand::Add(
            id.to_string(),
            address.to_string(),
            local_key.to_string(),
            version.into(),
            resp_tx,
        ))?
    }

    pub fn remove(&self, id: &str) {
        let _ = wait_for_response!(self.cmd_tx, |resp_tx| ManagerCommand::Remove(
            id.to_string(),
            resp_tx
        ));
    }

    pub fn delete(&self, id: &str) {
        let _ = wait_for_response!(self.cmd_tx, |resp_tx| ManagerCommand::Delete(
            id.to_string(),
            resp_tx
        ));
    }

    pub fn modify<V>(&self, id: &str, address: &str, local_key: &str, version: V) -> Result<()>
    where
        V: Into<Version>,
    {
        wait_for_response!(self.cmd_tx, |resp_tx| ManagerCommand::Modify(
            id.to_string(),
            address.to_string(),
            local_key.to_string(),
            version.into(),
            resp_tx,
        ))?
    }

    pub fn get(&self, id: &str) -> Option<Device> {
        let res = wait_for_response!(self.cmd_tx, |resp_tx| ManagerCommand::Get(
            id.to_string(),
            resp_tx
        ))
        .ok()
        .flatten();
        res.map(Device::from_async)
    }

    pub fn list(&self) -> Vec<crate::manager::DeviceInfo> {
        wait_for_response!(self.cmd_tx, ManagerCommand::List)
            .ok()
            .unwrap_or_default()
    }

    pub fn clear(&self) {
        let _ = wait_for_response!(self.cmd_tx, ManagerCommand::Clear);
    }

    pub fn listener(&self) -> std::sync::mpsc::Receiver<ManagerEvent> {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut event_rx = self.inner.event_tx().subscribe();

        runtime::spawn(async move {
            while let Ok(event) = event_rx.recv().await {
                if tx.send(event).is_err() {
                    break;
                }
            }
        });

        rx
    }

    pub fn shutdown(self) {
        let _ = wait_for_response!(self.cmd_tx, ManagerCommand::Shutdown);
    }
}

impl Deref for Manager {
    type Target = AsyncManager;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
