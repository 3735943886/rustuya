//! A device linked to a `Discovery` must still die when its owner drops it.
//!
//! The registry that makes the reconnect fast-path O(1) holds a sender to each
//! device's actor. Held *strongly*, that sender keeps the actor's receiver open
//! forever, so dropping every `Device` handle would never stop the driver task —
//! and because the entry is only pruned once the channel closes, nothing would
//! ever remove it either. The device would go on dialling forever, invisible to
//! the code that thought it had released it. At fleet scale that is thousands of
//! orphaned actors after a bulk removal.
//!
//! `watch_connected()` is the probe: its sender lives inside the driver task, so
//! a receiver kept after the `Device` is dropped reports `Err` exactly when that
//! task has ended.
//!
//! The other half — that the dead route is then *removed* rather than piling up
//! per departed device — is a unit test in `discovery.rs`, since the registry is
//! not publicly enumerable and from out here the prune is unobservable.

use std::time::Duration;

use rustuya_tokio::{Device, Discovery, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";

/// Poll until `f()` holds, bounded. Positive and pollable — no fixed sleep
/// standing in for "it probably finished by now".
async fn until(patience: Duration, f: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + patience;
    while tokio::time::Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::task::yield_now().await;
    }
    f()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_discovery_linked_device_stops_its_actor() {
    let disco = Discovery::new().expect("bind discovery");

    // Loopback so the dial is refused immediately: an unreachable address would
    // park the actor inside `TcpStream::connect` for the whole connect timeout
    // before it could observe its handles are gone, which is real behaviour but
    // would turn this into a timing race.
    let dev = Device::builder("route0000000000000000", KEY.to_vec())
        .address("127.0.0.1")
        .port(1) // nothing listens here
        .version(Version::V3_3)
        .rediscover(&disco)
        .connect()
        .expect("connect");

    // Deliberately outlives `dev`, and deliberately not a `Device` clone — one of
    // those would keep the actor alive by itself and make this pass vacuously.
    let watch = dev.watch_connected();
    assert!(
        watch.has_changed().is_ok(),
        "the actor should be running while the device is held"
    );

    drop(dev);

    assert!(
        until(Duration::from_secs(10), || watch.has_changed().is_err()).await,
        "the driver task outlived its last Device handle: the discovery route is \
         holding a strong sender and the actor can never observe its channel close"
    );
}
