//! Supervise a fleet: bound the connect storm and publish every online/offline
//! transition — the shape a bridge (MQTT, Home Assistant, …) needs from the driver.
//!
//! Nothing here is process-global. A fleet is many devices sharing a few explicit
//! objects: **one** [`Discovery`] for reconnect rewake, and **one**
//! [`ConnectLimiter`] capping how many devices may be dialling and handshaking at
//! the same instant. The permit covers only that establishment window, so a fleet
//! far larger than the cap still connects in full — it just does so in waves.
//!
//! Each transition is printed with the cap's live occupancy, which is what an
//! operator would graph: `establishing 2/2` means the cap is saturated and other
//! devices are queued behind it.
//!
//! ```text
//! cargo run --example supervise -- 2 id1:key1 id2:key2@192.168.1.51
//! cargo run --example supervise -- 8 id:key@192.168.1.50 3.4   # cap 8, pinned version
//! ```
//!
//! The cap is the bare integer argument (device specs always contain a `:`), and
//! defaults to 4. Pass a **wrong local key** to watch the other half of this: the
//! device never comes up and `watch_error` says why, instead of leaving you with a
//! silent timeout.

#[path = "common/mod.rs"]
mod common;

use tokio::task::JoinHandle;

use common::{init_logging, resolve, take_version};
use rustuya_tokio::{ConnectLimiter, Device, Discovery, Result};

/// Remove and return the first bare-integer argument — the cap. Unambiguous by
/// shape, like `take_ip`/`take_version`: every device spec contains a `:`.
fn take_cap(args: &mut Vec<String>) -> Option<usize> {
    let pos = args.iter().position(|s| s.parse::<usize>().is_ok())?;
    args.remove(pos).parse().ok()
}

/// Report every connection transition for one device, plus the authentication
/// failure behind a device that won't come up.
///
/// Both are `watch` channels, so this is state rather than a queue of events: a
/// connect/disconnect pair faster than this task wakes collapses to no observed
/// change. That is the right trade for publishing a device's *current* presence —
/// the last value is always the true one — and the reason a supervisor should not
/// try to count flaps with it.
/// The returned handle ends when the device's actor does, so awaiting them all is
/// how `main` stays alive for exactly as long as there is something to report.
fn supervise(id: String, dev: &Device, limiter: ConnectLimiter) -> JoinHandle<()> {
    let mut conn = dev.watch_connected();
    let mut err = dev.watch_error();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // `changed()` errors only when the sender is gone, i.e. the device
                // was dropped and its actor has stopped. Nothing left to report.
                r = conn.changed() => {
                    if r.is_err() {
                        break;
                    }
                    let up = *conn.borrow();
                    println!(
                        "[{id}] {:<7} (establishing {}/{})",
                        if up { "ONLINE" } else { "OFFLINE" },
                        limiter.limit() - limiter.available(),
                        limiter.limit()
                    );
                }
                r = err.changed() => {
                    if r.is_err() {
                        break;
                    }
                    // Only authentication failures land here — a payload that did
                    // not authenticate, which in practice means a wrong local key
                    // or the wrong protocol version. A device that is simply
                    // unreachable stays `None`, so "offline and no error" is the
                    // supervisor's signal for "cannot reach it".
                    let reported = err.borrow().clone();
                    if let Some(e) = reported {
                        println!("[{id}] auth failure: {e:?} — wrong local key or version");
                    }
                }
            }
        }
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let version = take_version(&mut args);
    let cap = take_cap(&mut args).unwrap_or(4);
    if args.is_empty() {
        eprintln!("usage: supervise [cap] <id:key[@ip]> [<id:key[@ip]> ...] [version]");
        std::process::exit(2);
    }

    // The two shared objects. One discovery for the whole fleet (binding the
    // well-known ports once), and one limiter every device counts against.
    let disco = Discovery::new().ok();
    if disco.is_none() {
        eprintln!("(discovery unavailable: ports busy — no auto-resolve or fast rewake)");
    }
    let limiter = ConnectLimiter::new(cap);

    // Resolve every device *concurrently*. Resolution talks to the network, so
    // doing it one device at a time would stagger the fleet's startup by seconds
    // per device — which both defeats the point at fleet scale and would hide the
    // cap here, since a fleet that starts in single file never has a storm to
    // bound. The cap, not the startup loop, is what should serialise the dials.
    let mut resolving = Vec::new();
    for spec in &args {
        let (idkey, ip) = match spec.split_once('@') {
            Some((l, r)) => (l, Some(r.to_string())),
            None => (spec.as_str(), None),
        };
        let (id, key) = idkey
            .split_once(':')
            .unwrap_or_else(|| panic!("bad spec {spec:?}: expected id:key[@ip]"));
        let (id, key) = (id.to_string(), key.to_string());
        let disco = disco.clone();
        resolving.push(tokio::spawn(async move {
            let resolved = resolve(disco.as_ref(), &id, ip, version).await;
            (id, key, resolved)
        }));
    }

    let mut devices = Vec::new();
    let mut watchers = Vec::new();
    for task in resolving {
        let (id, key, resolved) = task.await.expect("resolver task panicked");
        let (addr, ver) = resolved?;

        let mut builder = Device::builder(id.clone(), key.into_bytes())
            .address(addr)
            .version(ver)
            // The whole point: this device's dial + handshake counts against the
            // fleet-wide cap. Without it every device dials at once.
            .connect_limiter(&limiter);
        if let Some(d) = &disco {
            builder = builder.rediscover(d);
        }
        let dev = builder.connect()?;

        // Subscribe before anything can come up, so the first transition is not
        // missed — the device is spawned already dialling.
        watchers.push(supervise(id, &dev, limiter.clone()));
        devices.push(dev);
    }

    println!(
        "supervising {} device(s), at most {} establishing at once; Ctrl-C to stop.",
        devices.len(),
        limiter.limit()
    );
    println!("=> power-cycle a device to watch it drop, queue for a slot, and come back.");

    // Runs until every device's actor has stopped — i.e. until Ctrl-C, since
    // nothing here drops a handle.
    for w in watchers {
        let _ = w.await;
    }
    println!("all devices stopped.");
    Ok(())
}
