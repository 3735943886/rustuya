//! `ConnectLimiter` — the fleet-wide connect-storm guard.
//!
//! Two properties, both deterministic (no timing races decide either verdict):
//!
//! 1. **The cap holds.** With every device stalled *inside* the establishment
//!    window, no more than `limit` of them can be there at once. The mock accepts
//!    a v3.4 handshake and never answers, and `handshake_timeout` is disabled, so
//!    the window never closes and the accept count pins to exactly `limit` — no
//!    rotation, no close-detection lag, nothing to debounce.
//!
//! 2. **A fleet larger than the cap still fully connects.** The mirror-image
//!    failure: a permit held for the connection's *lifetime* rather than just its
//!    establishment would deadlock every device past the `limit`-th. v3.3 needs no
//!    handshake, so each device is connected on the TCP connect itself and must
//!    hand its slot straight back.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use rustuya_tokio::{ConnectLimiter, Device, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";
const LIMIT: usize = 4;
const FLEET: usize = 24;

fn device_id(i: usize) -> String {
    // 22-char id: "cap" + 19 digits.
    format!("cap{i:019}")
}

/// Accepts forever, counting how many sockets it has taken, and holds each one
/// open (draining reads) until the peer goes away.
async fn serve_counting(listener: TcpListener, accepted: Arc<AtomicUsize>) {
    while let Ok((mut sock, _)) = listener.accept().await {
        accepted.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let mut sink = [0u8; 256];
            while let Ok(n) = sock.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
        });
    }
}

/// Spin until `f()` holds, or give up after `patience`. Returns whether it held —
/// so a passing run is as fast as the machine allows and a failing one is bounded.
async fn until(patience: Duration, f: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + patience;
    while tokio::time::Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f()
}

/// With every device wedged mid-handshake, exactly `LIMIT` of a `FLEET` may be in
/// the establishment window — and it stays exactly `LIMIT`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cap_bounds_devices_in_the_establishment_window() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn(serve_counting(listener, accepted.clone()));

    let limiter = ConnectLimiter::new(LIMIT);
    let _devices: Vec<_> = (0..FLEET)
        .map(|i| {
            Device::builder(device_id(i), KEY.to_vec())
                .address(addr.ip().to_string())
                .port(addr.port())
                // v3.4 negotiates a session key. The mock never answers, so every
                // device that gets a slot parks in `Handshaking`...
                .version(Version::V3_4)
                // ...forever: with no handshake deadline the establishment window
                // never closes, so no permit is ever handed on.
                .handshake_timeout(None)
                .connect_limiter(&limiter)
                .connect()
                .unwrap()
        })
        .collect();

    // Wait for the steady state — every slot taken, and every slot-holder
    // through to the mock. Both conditions are positive and pollable, so there
    // is no "sleep and hope nothing else happened" step here.
    assert!(
        until(Duration::from_secs(5), || limiter.available() == 0
            && accepted.load(Ordering::SeqCst) == LIMIT)
        .await,
        "expected exactly {LIMIT} devices dialled with all slots held; \
         {} dialled, {} slot(s) free",
        accepted.load(Ordering::SeqCst),
        limiter.available()
    );

    // From here the cap is an *invariant*, not a race to observe: a device
    // cannot dial without a permit, no permit is free, and none can be freed
    // because every holder is parked mid-handshake forever. So the count above
    // is the final one, and no amount of extra waiting could raise it.
    assert_eq!(limiter.limit(), LIMIT);
}

/// A fleet many times the cap still connects in full: the permit covers the
/// establishment, not the connection's lifetime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fleet_larger_than_the_cap_all_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn(serve_counting(listener, accepted.clone()));

    let limiter = ConnectLimiter::new(LIMIT);
    let devices: Vec<_> = (0..FLEET)
        .map(|i| {
            Device::builder(device_id(i), KEY.to_vec())
                .address(addr.ip().to_string())
                .port(addr.port())
                // v3.3 has no session handshake: the TCP connect *is* the
                // establishment, so each device releases its slot immediately.
                .version(Version::V3_3)
                .connect_limiter(&limiter)
                .connect()
                .unwrap()
        })
        .collect();

    let all_up = {
        let devices = devices.clone();
        until(Duration::from_secs(10), move || {
            devices.iter().all(Device::is_connected)
        })
        .await
    };
    let up = devices.iter().filter(|d| d.is_connected()).count();
    assert!(
        all_up,
        "all {FLEET} devices must connect behind a cap of {LIMIT}; only {up} did \
         (a permit held for the connection's lifetime would stall at {LIMIT})"
    );

    // Every slot handed back once the fleet is up — nothing is still "establishing".
    assert!(
        until(Duration::from_secs(1), || limiter.available() == LIMIT).await,
        "all {LIMIT} slots should be free once the fleet is connected, {} are",
        limiter.available()
    );
}
