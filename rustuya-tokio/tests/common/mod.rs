//! Shared helpers for the fire-and-forget listener model.
//!
//! Command methods no longer return a response — `query()`/`set_*()` fire and
//! return once queued, and the device's reply arrives asynchronously on
//! [`Device::listener`]. These helpers reproduce the old "fire a query, read the
//! DPS back" ergonomics for tests: subscribe *before* firing (so the reply can't
//! race the subscription), then collect the next DPS-bearing frame off the bus.
//!
//! The bound is a genuine failure deadline (a missing reply fails instead of
//! hanging), not a sleep papering over a race.
#![allow(dead_code)]

use std::time::Duration;

use rustuya_tokio::{Device, Event, Listener, Value};

/// Does this decoded payload carry a `dps` map — top-level or nested under `data`?
fn has_dps(v: &Value) -> bool {
    v.get("dps").is_some() || v.get("data").and_then(|d| d.get("dps")).is_some()
}

/// The next listener frame that actually carries DPS, within `within`. Heartbeat
/// acks and bare acks (empty / dps-less payloads) are skipped. `None` if nothing
/// qualifies in time — used to prove *absence* (e.g. a device gone dark).
pub async fn recv_dps(ev: &mut Listener, within: Duration) -> Option<Value> {
    let collect = async {
        loop {
            match ev.recv().await {
                Some(Event::Frame(msg)) => {
                    if msg.payload.is_empty() {
                        continue;
                    }
                    match serde_json::from_slice::<Value>(&msg.payload) {
                        Ok(v) if has_dps(&v) => return Some(v),
                        _ => continue,
                    }
                }
                Some(Event::Lagged(_)) => continue, // these tests keep up; ignore
                None => return None,                // device stopped
            }
        }
    };
    tokio::time::timeout(within, collect).await.ok().flatten()
}

/// Fire a status query on `dev` and return the DPS reply from the listener.
/// Subscribe-before-fire; 5 s bound so a missing reply fails the test.
pub async fn query_dps(dev: &Device) -> Value {
    let mut ev = dev.listener();
    dev.query().await.expect("query fires");
    recv_dps(&mut ev, Duration::from_secs(5))
        .await
        .expect("a DPS reply arrived on the listener")
}
