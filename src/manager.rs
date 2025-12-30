//! High-level management of multiple Tuya devices.
//! Provides unified event streaming and system-level optimizations (e.g., FD limit).

use crate::device::Device;
use crate::error::{Result, TuyaError};
use crate::protocol::{TuyaMessage, Version};
use futures_util::{Stream, StreamExt};
use log::{info, warn};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock as StdRwLock};
use tokio::sync::{RwLock, broadcast};
use tokio_util::sync::CancellationToken;

struct RegistryEntry {
    device: Device,
    ref_count: usize,
    update_tx: broadcast::Sender<Device>,
}

static DEVICE_REGISTRY: OnceLock<StdRwLock<HashMap<String, RegistryEntry>>> = OnceLock::new();

/// Global device registry to manage shared device instances and reference counting.
struct GlobalRegistry;

impl GlobalRegistry {
    fn get() -> &'static StdRwLock<HashMap<String, RegistryEntry>> {
        DEVICE_REGISTRY.get_or_init(|| StdRwLock::new(HashMap::new()))
    }

    /// Acquires a device from the registry. If it doesn't exist, creates a new one.
    /// Returns the device and a receiver for future updates.
    fn acquire<V>(
        id: &str,
        address: &str,
        local_key: &str,
        version: V,
    ) -> Result<(Device, broadcast::Receiver<Device>)>
    where
        V: Into<Version>,
    {
        let registry = Self::get();
        let mut guard = registry
            .write()
            .map_err(|e| TuyaError::Io(format!("Registry lock poisoned: {}", e)))?;

        if let Some(entry) = guard.get_mut(id) {
            info!(
                "Device {} borrowed from global registry (ref_count: {})",
                id,
                entry.ref_count + 1
            );
            entry.ref_count += 1;
            Ok((entry.device.clone(), entry.update_tx.subscribe()))
        } else {
            let (update_tx, _) = broadcast::channel(4);
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

    /// Releases a device. Decrements ref_count and stops the device if it reaches 0.
    fn release(id: &str) {
        let registry = Self::get();
        if let Ok(mut guard) = registry.write() {
            let mut should_remove = false;
            if let Some(entry) = guard.get_mut(id) {
                entry.ref_count = entry.ref_count.saturating_sub(1);
                if entry.ref_count == 0 {
                    should_remove = true;
                }
            }
            if should_remove {
                if let Some(entry) = guard.remove(id) {
                    let device = entry.device;
                    tokio::spawn(async move {
                        device.stop().await;
                    });
                    info!("Device {} released and removed from global registry", id);
                }
            }
        }
    }

    /// Forcefully remove a device from the global registry.
    /// This will trigger cleanup in all managers using this device.
    fn delete(id: &str) {
        let registry = Self::get();
        if let Ok(mut guard) = registry.write() {
            if let Some(entry) = guard.remove(id) {
                let device = entry.device;
                tokio::spawn(async move {
                    device.stop().await;
                });
                info!("Device {} forcefully deleted from global registry", id);
            }
        }
    }

    /// Modify an existing device's parameters in the registry.
    fn modify<V>(id: &str, address: &str, local_key: &str, version: V) -> Result<()>
    where
        V: Into<Version>,
    {
        let registry = Self::get();
        let mut guard = registry
            .write()
            .map_err(|e| TuyaError::Io(format!("Registry lock poisoned: {}", e)))?;

        if let Some(entry) = guard.get_mut(id) {
            info!("Modifying device {} in global registry", id);
            let old_device = entry.device.clone();
            let new_device = Device::new(id, address, local_key, version);

            entry.device = new_device.clone();
            let _ = entry.update_tx.send(new_device);

            // Stop old device asynchronously
            tokio::spawn(async move {
                old_device.stop().await;
            });
            Ok(())
        } else {
            Err(TuyaError::DeviceNotFound(id.to_string()))
        }
    }

    /// Shuts down all devices in the registry and clears it.
    fn shutdown_all() {
        let registry = Self::get();
        if let Ok(mut guard) = registry.write() {
            for (_, entry) in guard.drain() {
                let device = entry.device;
                tokio::spawn(async move {
                    device.stop().await;
                });
            }
        }
    }
}

/// Represents an event from any device managed by TuyaManager.
#[derive(Debug, Clone)]
pub struct ManagerEvent {
    pub device_id: String,
    pub message: TuyaMessage,
}

/// A high-level manager for multiple Tuya devices.
///
/// It provides a unified event stream and easy access to individual devices.
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

impl Manager {
    /// Maximizes the file descriptor limit for the current process.
    ///
    /// This is useful when managing thousands of devices on Unix-like systems (Linux, macOS).
    /// On non-Unix systems, this does nothing.
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

    /// Create a new Manager.
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(32);
        Self {
            inner: Arc::new(ManagerInner {
                devices: RwLock::new(HashMap::new()),
                device_tokens: RwLock::new(HashMap::new()),
                event_tx,
                cancel_token: CancellationToken::new(),
            }),
        }
    }

    /// Returns a Stream of events from all managed devices.
    pub fn stream(&self) -> impl Stream<Item = ManagerEvent> {
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

    /// Add a new device to the manager.
    ///
    /// Returns an error if a device with the same ID already exists.
    pub async fn add<V>(&self, id: &str, address: &str, local_key: &str, version: V) -> Result<()>
    where
        V: Into<Version>,
    {
        let mut devices = self.inner.devices.write().await;
        let mut device_tokens = self.inner.device_tokens.write().await;

        if devices.contains_key(id) {
            return Err(TuyaError::DuplicateDevice(id.to_string()));
        }

        // Acquire from global registry (borrow or create)
        let (device, update_rx) = GlobalRegistry::acquire(id, address, local_key, version)?;

        // Setup device monitor (handles forwarding and updates)
        let device_token = self.inner.cancel_token.child_token();
        self.spawn_device_monitor(id, device.clone(), update_rx, device_token.clone());

        devices.insert(id.to_string(), device);
        device_tokens.insert(id.to_string(), device_token);

        info!("Device {} added to manager", id);
        Ok(())
    }

    /// Modify an existing device's connection parameters.
    ///
    /// This updates the device in the global registry, affecting all managers that use it.
    /// The old connection is closed and a new one is established with the new parameters.
    pub async fn modify<V>(
        &self,
        id: &str,
        address: &str,
        local_key: &str,
        version: V,
    ) -> Result<()>
    where
        V: Into<Version>,
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

        tokio::spawn(async move {
            loop {
                info!("Starting event stream for device {}", device_id);
                let stream = device.stream();
                tokio::pin!(stream);

                let mut stream_ended = false;
                loop {
                    tokio::select! {
                        _ = token.cancelled() => return,

                        // Listen for updates from GlobalRegistry
                        update_result = update_rx.recv() => {
                            match update_result {
                                Ok(new_device) => {
                                    info!("Device {} updated, restarting monitor", device_id);
                                    device = new_device.clone();

                                    // Update local map in the manager
                                    let mut guard = inner.devices.write().await;
                                    guard.insert(device_id.clone(), new_device);

                                    break; // Break inner loop to restart stream with new device
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    // GlobalRegistry dropped the sender, meaning device was deleted/released globally
                                    info!("Device {} removed globally, cleaning up local manager", device_id);
                                    let mut devices = inner.devices.write().await;
                                    devices.remove(&device_id);
                                    let mut tokens = inner.device_tokens.write().await;
                                    tokens.remove(&device_id);
                                    return;
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            }
                        }

                        // Forward events
                        msg_result = stream.next() => {
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

    /// Remove a device from the manager.
    ///
    /// This stops event forwarding for this device in this manager.
    /// If no other manager is using the device, it will be closed and removed from the global registry.
    pub async fn remove(&self, id: &str) {
        let mut devices = self.inner.devices.write().await;
        let mut device_tokens = self.inner.device_tokens.write().await;

        if let Some(_) = devices.remove(id) {
            if let Some(token) = device_tokens.remove(id) {
                token.cancel();
            }
            GlobalRegistry::release(id);
            info!("Device {} removed from manager", id);
        } else {
            warn!("Attempted to remove non-existent device {}", id);
        }
    }

    /// Delete a device globally from all managers and the registry.
    ///
    /// This forcefully stops the device connection and removes it from all active managers.
    pub async fn delete(&self, id: &str) {
        GlobalRegistry::delete(id);
    }

    /// List all registered devices and their current local connection status.
    /// Returns a Map of Device ID -> Is Connected (Local status, no network request).
    pub async fn list(&self) -> HashMap<String, bool> {
        let devices = self.inner.devices.read().await;
        let mut result = HashMap::new();
        for (id, device) in devices.iter() {
            result.insert(id.clone(), device.is_connected());
        }
        result
    }

    /// Get a device by ID.
    pub async fn get(&self, id: &str) -> Option<Device> {
        self.inner.devices.read().await.get(id).cloned()
    }

    /// Shutdown the manager and stop monitoring all managed devices.
    ///
    /// This stops event forwarding for this manager and decrements ref_counts for its devices.
    /// To close all connections immediately, use `Manager::shutdown_all()`.
    pub async fn shutdown(self) {
        self.inner.cancel_token.cancel();

        let mut devices = self.inner.devices.write().await;
        let mut tokens = self.inner.device_tokens.write().await;

        let ids: Vec<String> = devices.keys().cloned().collect();
        for id in ids {
            if let Some(token) = tokens.remove(&id) {
                token.cancel();
            }
            GlobalRegistry::release(&id);
        }

        devices.clear();
        tokens.clear();
    }

    /// Shutdown all devices in the global registry and clear it.
    ///
    /// This will close ALL connections for ALL managers.
    pub async fn shutdown_all() {
        GlobalRegistry::shutdown_all();
    }
}

impl Drop for ManagerInner {
    fn drop(&mut self) {
        // Trigger cancellation for background tasks.
        self.cancel_token.cancel();

        // Clean up registry
        if let Ok(devices) = self.devices.try_read() {
            for id in devices.keys() {
                GlobalRegistry::release(id);
            }
        }
    }
}

// Remove the Index trait implementation as it's not safe with async RwLock
