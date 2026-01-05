//! Tuya device manager for handling multiple devices.
//!
//! Provides a centralized manager for device registration, lifecycle, and event streaming.

use crate::device::Device;
use crate::error::{Result, TuyaError};
use crate::protocol::{TuyaMessage, Version};
use futures_util::{Stream, StreamExt};
use log::{info, warn};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

const CHAN_UPDATE_CAPACITY: usize = 4;
const CHAN_EVENT_CAPACITY: usize = 1024;

struct RegistryEntry {
    device: Device,
    ref_count: usize,
    update_tx: broadcast::Sender<Device>,
}

static DEVICE_REGISTRY: OnceLock<Arc<RwLock<HashMap<String, RegistryEntry>>>> = OnceLock::new();

struct GlobalRegistry;

impl GlobalRegistry {
    fn get() -> Arc<RwLock<HashMap<String, RegistryEntry>>> {
        DEVICE_REGISTRY
            .get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
            .clone()
    }

    fn acquire<V>(
        id: &str,
        address: &str,
        local_key: &str,
        version: V,
    ) -> Result<(Device, broadcast::Receiver<Device>)>
    where
        V: Into<Version> + Send,
    {
        let registry = Self::get();
        let mut guard = registry.write();

        if let Some(entry) = guard.get_mut(id) {
            info!(
                "Device {} borrowed from global registry (ref_count: {})",
                id,
                entry.ref_count + 1
            );
            entry.ref_count += 1;
            Ok((entry.device.clone(), entry.update_tx.subscribe()))
        } else {
            let (update_tx, _) = broadcast::channel(CHAN_UPDATE_CAPACITY);
            let device = Device::new(id, address, local_key, version);
            guard.insert(
                id.to_string(),
                RegistryEntry {
                    device: device.clone(),
                    ref_count: 1,
                    update_tx: update_tx.clone(),
                },
            );
            info!("Device {} registered in global registry", id);
            Ok((device, update_tx.subscribe()))
        }
    }

    fn release(id: &str) {
        let registry = Self::get();
        let mut guard = registry.write();
        let mut should_remove = false;
        if let Some(entry) = guard.get_mut(id) {
            entry.ref_count = entry.ref_count.saturating_sub(1);
            if entry.ref_count == 0 {
                should_remove = true;
            }
        }
        if should_remove && let Some(entry) = guard.remove(id) {
            let device = entry.device;
            crate::runtime::spawn(async move {
                device.stop().await;
            });
            info!("Device {} released and removed from global registry", id);
        }
    }

    fn delete(id: &str) {
        let registry = Self::get();
        let mut guard = registry.write();
        if let Some(entry) = guard.remove(id) {
            let device = entry.device;
            crate::runtime::spawn(async move {
                device.stop().await;
            });
            info!("Device {} forcefully deleted from global registry", id);
        }
    }

    fn modify<V>(id: &str, address: &str, local_key: &str, version: V) -> Result<()>
    where
        V: Into<Version> + Send,
    {
        let registry = Self::get();
        let mut guard = registry.write();

        if let Some(entry) = guard.get_mut(id) {
            info!("Modifying device {} in global registry", id);
            let old_device = entry.device.clone();
            let new_device = Device::new(id, address, local_key, version);

            entry.device = new_device.clone();
            let _ = entry.update_tx.send(new_device);

            crate::runtime::spawn(async move {
                old_device.stop().await;
            });
            Ok(())
        } else {
            Err(TuyaError::DeviceNotFound(id.to_string()))
        }
    }

    fn shutdown_all() {
        let registry = Self::get();
        let mut guard = registry.write();
        for (_, entry) in guard.drain() {
            let device = entry.device;
            crate::runtime::spawn(async move {
                device.stop().await;
            });
        }
    }
}

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    pub id: String,
    pub address: String,
    pub local_key: String,
    pub version: String,
    pub is_connected: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagerEvent {
    pub device_id: String,
    pub message: TuyaMessage,
}

#[derive(Clone)]
pub struct Manager {
    inner: Arc<ManagerInner>,
}

struct ManagerInner {
    devices: RwLock<HashMap<String, Device>>,
    device_tokens: RwLock<HashMap<String, CancellationToken>>,
    event_tx: broadcast::Sender<ManagerEvent>,
    cancel_token: CancellationToken,
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl Manager {
    /// Maximizes the file descriptor limit (Unix-only).
    pub fn maximize_fd_limit() -> Result<()> {
        #[cfg(unix)]
        {
            let (soft, hard) = rlimit::getrlimit(rlimit::Resource::NOFILE)
                .map_err(|e| TuyaError::Io(format!("Failed to get rlimit: {}", e)))?;

            if soft < hard {
                rlimit::setrlimit(rlimit::Resource::NOFILE, hard, hard)
                    .map_err(|e| TuyaError::Io(format!("Failed to set rlimit: {}", e)))?;
                info!("File descriptor limit increased from {} to {}", soft, hard);
            }
        }
        Ok(())
    }

    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(CHAN_EVENT_CAPACITY);
        Self {
            inner: Arc::new(ManagerInner {
                devices: RwLock::new(HashMap::new()),
                device_tokens: RwLock::new(HashMap::new()),
                event_tx,
                cancel_token: CancellationToken::new(),
            }),
        }
    }

    pub(crate) fn event_tx(&self) -> &broadcast::Sender<ManagerEvent> {
        &self.inner.event_tx
    }

    pub fn listener(&self) -> impl Stream<Item = ManagerEvent> + 'static {
        let mut rx = self.inner.event_tx.subscribe();
        async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(event) => yield event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        }
    }

    pub async fn add<V>(&self, id: &str, address: &str, local_key: &str, version: V) -> Result<()>
    where
        V: Into<Version> + Send,
    {
        let mut devices = self.inner.devices.write();
        let mut device_tokens = self.inner.device_tokens.write();

        if devices.contains_key(id) {
            return Err(TuyaError::DuplicateDevice(id.to_string()));
        }

        let (device, update_rx) = GlobalRegistry::acquire(id, address, local_key, version)?;

        let device_token = self.inner.cancel_token.child_token();
        self.spawn_device_monitor(id, device.clone(), update_rx, device_token.clone());

        devices.insert(id.to_string(), device);
        device_tokens.insert(id.to_string(), device_token);

        info!("Device {} added to manager", id);
        Ok(())
    }

    pub async fn modify<V>(
        &self,
        id: &str,
        address: &str,
        local_key: &str,
        version: V,
    ) -> Result<()>
    where
        V: Into<Version> + Send,
    {
        GlobalRegistry::modify(id, address, local_key, version)
    }

    fn spawn_device_monitor(
        &self,
        id: &str,
        mut device: Device,
        mut update_rx: broadcast::Receiver<Device>,
        token: CancellationToken,
    ) {
        let device_id = id.to_string();
        let event_tx = self.inner.event_tx.clone();
        let inner = self.inner.clone();

        crate::runtime::spawn(async move {
            loop {
                info!("Starting event listener for device {}", device_id);
                let listener = device.listener();
                tokio::pin!(listener);

                let mut stream_ended = false;
                loop {
                    tokio::select! {
                        _ = token.cancelled() => return,
                        update_result = update_rx.recv() => {
                            match update_result {
                                Ok(new_device) => {
                                    info!("Device {} updated, restarting monitor", device_id);
                                    device = new_device.clone();
                                    let mut guard = inner.devices.write();
                                    guard.insert(device_id.clone(), new_device);
                                    break;
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    info!("Device {} removed globally, cleaning up local manager", device_id);
                                    let mut devices = inner.devices.write();
                                    devices.remove(&device_id);
                                    let mut tokens = inner.device_tokens.write();
                                    tokens.remove(&device_id);
                                    return;
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            }
                        }
                        msg_result = listener.next() => {
                            match msg_result {
                                Some(Ok(message)) => {
                                    let _ = event_tx.send(ManagerEvent {
                                        device_id: device_id.clone(),
                                        message,
                                    });
                                }
                                Some(Err(_)) => continue,
                                None => {
                                    stream_ended = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                if stream_ended {
                    info!("Stream for device {} ended", device_id);
                    break;
                }
            }
        });
    }

    pub async fn remove(&self, id: &str) {
        let mut devices = self.inner.devices.write();
        let mut device_tokens = self.inner.device_tokens.write();

        if devices.remove(id).is_some() {
            if let Some(token) = device_tokens.remove(id) {
                token.cancel();
            }
            GlobalRegistry::release(id);
            info!("Device {} removed from manager", id);
        } else {
            warn!("Attempted to remove non-existent device {}", id);
        }
    }

    pub async fn clear(&self) {
        let mut devices = self.inner.devices.write();
        let mut device_tokens = self.inner.device_tokens.write();

        for (id, _) in devices.drain() {
            if let Some(token) = device_tokens.remove(&id) {
                token.cancel();
            }
            GlobalRegistry::release(&id);
        }
        info!("All devices removed from manager");
    }

    pub async fn delete(&self, id: &str) {
        GlobalRegistry::delete(id);
    }

    pub async fn list(&self) -> Vec<DeviceInfo> {
        let devices = self.inner.devices.read();
        let mut result = Vec::new();
        for (_, device) in devices.iter() {
            result.push(DeviceInfo {
                id: device.id().to_string(),
                address: device.address(),
                local_key: hex::encode(device.local_key()),
                version: device.version().to_string(),
                is_connected: device.is_connected(),
            });
        }
        result
    }

    pub async fn get(&self, id: &str) -> Option<Device> {
        self.inner.devices.read().get(id).cloned()
    }

    pub async fn shutdown(self) {
        self.inner.cancel_token.cancel();

        let mut devices = self.inner.devices.write();
        let mut tokens = self.inner.device_tokens.write();

        for (id, _) in devices.drain() {
            tokens.remove(&id);
            GlobalRegistry::release(&id);
        }
        info!("Manager shut down");
    }

    pub fn shutdown_all() {
        GlobalRegistry::shutdown_all();
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.cancel_token.cancel();
            if let Some(mut devices) = self.inner.devices.try_write() {
                for id in devices.keys().cloned().collect::<Vec<String>>() {
                    GlobalRegistry::release(&id);
                }
                devices.clear();
            }
        }
    }
}
