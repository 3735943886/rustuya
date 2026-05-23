//! Per-device listener stream + multi-device unified listener.

use crate::error::{ERR_STATE, Result};
use crate::protocol::TuyaMessage;
use futures_core::stream::Stream;
use log::warn;
use serde::Serialize;

use super::Device;

impl Device {
    /// Returns a stream of broadcast messages from this device.
    ///
    /// The returned stream holds a strong reference to the device. As long as
    /// the stream is alive (e.g. owned by a spawned task or
    /// [`unified_listener`]), the device's background connection task stays
    /// alive too — even if the caller dropped their original `Device` handle.
    /// To force shutdown, call [`Device::stop`].
    pub fn listener(&self) -> impl Stream<Item = Result<TuyaMessage>> + Send + 'static {
        use tokio::sync::broadcast::error::RecvError;
        let mut rx = self.inner.broadcast_tx.subscribe();
        let device = self.clone();
        let cancel = self.inner.cancel_token.clone();
        async_stream::stream! {
            loop {
                tokio::select! {
                    // Honor explicit stop() while waiting on the broadcast.
                    // Without this branch the listener would only exit when
                    // broadcast_tx is dropped, which requires the very last
                    // Arc<DeviceInner> reference to disappear — and *we* are
                    // holding one of those refs ourselves.
                    () = cancel.cancelled() => break,
                    res = rx.recv() => match res {
                        Ok(msg) => {
                            if !msg.payload.is_empty() {
                                yield Ok(msg);
                            }
                        }
                        Err(RecvError::Lagged(skipped)) => {
                            warn!(
                                "Listener for device {} lagged behind broadcast, skipped {} messages",
                                device.inner.id, skipped
                            );
                            yield Ok(device.error_helper(
                                ERR_STATE,
                                Some(serde_json::json!({
                                    "reason": "listener_lagged",
                                    "skipped": skipped,
                                })),
                            ));
                        }
                        Err(RecvError::Closed) => break,
                    }
                }
            }
        }
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
