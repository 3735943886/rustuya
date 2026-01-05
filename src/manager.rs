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

    #[cfg(test)]
    fn get_ref_count(id: &str) -> usize {
        let registry = Self::get();
        let guard = registry.read();
        guard.get(id).map(|entry| entry.ref_count).unwrap_or(0)
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
        let inner_weak = Arc::downgrade(&self.inner);

        crate::runtime::spawn(async move {
            info!("Starting event monitor for device {}", device_id);

            loop {
                let listener = device.listener();
                tokio::pin!(listener);

                let mut device_updated = false;

                loop {
                    tokio::select! {
                        _ = token.cancelled() => return,
                        update_result = update_rx.recv() => {
                            match update_result {
                                Ok(new_device) => {
                                    info!("Device {} configuration updated, restarting monitor", device_id);
                                    device = new_device.clone();
                                    if let Some(inner) = inner_weak.upgrade() {
                                        inner.devices.write().insert(device_id.clone(), new_device);
                                        device_updated = true;
                                        break;
                                    } else {
                                        return;
                                    }
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    info!("Device {} removed globally, stopping monitor", device_id);
                                    if let Some(inner) = inner_weak.upgrade() {
                                        inner.devices.write().remove(&device_id);
                                        inner.device_tokens.write().remove(&device_id);
                                    }
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
                                None => break, // Stream ended (e.g. device stopped or disconnected)
                            }
                        }
                    }
                }

                // If the device wasn't updated via broadcast, and the stream ended,
                // it means the monitor should stop.
                if !device_updated {
                    info!("Event monitor for device {} stopped", device_id);
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
            let mut devices = self.inner.devices.write();
            for id in devices.keys().cloned().collect::<Vec<String>>() {
                GlobalRegistry::release(&id);
            }
            devices.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_manager_drop_ref_count() {
        let manager = Manager::new();
        let device_id = "test_device_drop";

        // Add a device
        manager
            .add(
                device_id,
                "127.0.0.1",
                "0123456789abcdef0123456789abcdef",
                "3.3",
            )
            .await
            .unwrap();

        // Check ref count is 1
        assert_eq!(GlobalRegistry::get_ref_count(device_id), 1);

        // Clone manager
        let manager_clone = manager.clone();

        // Ref count should still be 1
        assert_eq!(GlobalRegistry::get_ref_count(device_id), 1);

        // Drop clone
        drop(manager_clone);

        // Ref count should still be 1 because the original manager still exists
        assert_eq!(GlobalRegistry::get_ref_count(device_id), 1);

        // Drop original
        drop(manager);

        // Ref count should be 0
        assert_eq!(GlobalRegistry::get_ref_count(device_id), 0);
    }

    #[tokio::test]
    async fn test_manager_manual_remove_ref_count() {
        let manager = Manager::new();
        let device_id = "test_device_remove";

        manager
            .add(
                device_id,
                "127.0.0.1",
                "0123456789abcdef0123456789abcdef",
                "3.3",
            )
            .await
            .unwrap();
        assert_eq!(GlobalRegistry::get_ref_count(device_id), 1);

        manager.remove(device_id).await;
        assert_eq!(GlobalRegistry::get_ref_count(device_id), 0);
    }

    #[tokio::test]
    async fn test_multiple_managers_sharing_device() {
        let manager1 = Manager::new();
        let manager2 = Manager::new();
        let device_id = "shared_device";
        let addr = "127.0.0.1";
        let key = "0123456789abcdef0123456789abcdef";
        let ver = "3.3";

        // 양쪽 매니저에 동일 장치 추가
        manager1.add(device_id, addr, key, ver).await.unwrap();
        assert_eq!(GlobalRegistry::get_ref_count(device_id), 1);

        manager2.add(device_id, addr, key, ver).await.unwrap();
        assert_eq!(
            GlobalRegistry::get_ref_count(device_id),
            2,
            "두 매니저가 공유하므로 ref_count는 2여야 함"
        );

        // 매니저 1 드랍
        drop(manager1);
        assert_eq!(
            GlobalRegistry::get_ref_count(device_id),
            1,
            "매니저 1이 드랍되어 ref_count는 1로 감소해야 함"
        );

        // 매니저 2 드랍
        drop(manager2);
        assert_eq!(
            GlobalRegistry::get_ref_count(device_id),
            0,
            "모든 매니저가 드랍되어 ref_count는 0이 되어야 함"
        );
    }

    #[tokio::test]
    async fn test_manager_repeated_add_clear() {
        let manager = Manager::new();
        let devices = vec![("dev1", "key1"), ("dev2", "key2"), ("dev3", "key3")];

        for i in 1..=5 {
            // Add all devices
            for (id, key) in &devices {
                manager.add(id, "127.0.0.1", key, "3.3").await.unwrap();
                assert_eq!(
                    GlobalRegistry::get_ref_count(id),
                    1,
                    "Iteration {}: {} ref_count should be 1 after add",
                    i,
                    id
                );
            }

            // List should match
            assert_eq!(manager.list().await.len(), 3);

            // Clear all
            manager.clear().await;

            // All ref counts should be 0
            for (id, _) in &devices {
                assert_eq!(
                    GlobalRegistry::get_ref_count(id),
                    0,
                    "Iteration {}: {} ref_count should be 0 after clear",
                    i,
                    id
                );
            }

            assert_eq!(manager.list().await.len(), 0);
        }
    }

    #[tokio::test]
    async fn test_manager_repeated_add_remove() {
        let manager = Manager::new();
        let device_id = "repeated_dev";
        let key = "repeated_key";

        for i in 1..=10 {
            manager
                .add(device_id, "127.0.0.1", key, "3.3")
                .await
                .unwrap();
            assert_eq!(
                GlobalRegistry::get_ref_count(device_id),
                1,
                "Iteration {}: ref_count should be 1 after add",
                i
            );

            manager.remove(device_id).await;
            assert_eq!(
                GlobalRegistry::get_ref_count(device_id),
                0,
                "Iteration {}: ref_count should be 0 after remove",
                i
            );
        }
    }
}
