//! `watch_connected` / `watch_error` report **transitions**, not attempts.
//!
//! Both are `watch` channels of state, and `watch::Sender::send` wakes consumers
//! on every call — even when it writes the value already there. A device that
//! accepts TCP but never completes its handshake tears the link down once per
//! backoff round, so the naive form republishes the same `false` forever. For a
//! supervisor that turns these into events (a bridge publishing device presence)
//! that is one spurious OFFLINE per device per retry, indefinitely, for a fleet
//! that is merely misconfigured.
//!
//! The sync edge in both tests is the listener's accept count — a positive,
//! pollable fact — so no verdict here rests on a sleep.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;

use rustuya_tokio::{Device, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";

/// Spin until `f()` holds, bounded. Positive and pollable.
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

/// Accept and immediately drop each connection, counting accepts. To a v3.4
/// device that is a socket that dies mid-handshake: it reaches `Handshaking`,
/// reads EOF, tears down, and redials — the retry loop of a device that is
/// reachable but will never come up.
async fn serve_hanging_up(listener: TcpListener, accepted: Arc<AtomicUsize>) {
    while let Ok((sock, _)) = listener.accept().await {
        accepted.fetch_add(1, Ordering::SeqCst);
        drop(sock);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_that_never_comes_up_reports_no_connection_change() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn(serve_hanging_up(listener, accepted.clone()));

    let dev = Device::builder("conn00000000000000000", KEY.to_vec())
        .address(addr.ip().to_string())
        .port(addr.port())
        // v3.4 negotiates a session key, so the dropped socket kills the device
        // mid-handshake rather than after it is already up.
        .version(Version::V3_4)
        // Redial immediately: the point is to accumulate teardowns, not to wait.
        .backoff(Duration::ZERO, Duration::ZERO, Duration::ZERO)
        .connect()
        .expect("connect");
    let conn = dev.watch_connected();

    // Three full dial → handshake → teardown rounds. Under the naive `send` each
    // round republishes `false`, so by here the consumer has been woken repeatedly.
    assert!(
        until(Duration::from_secs(10), || accepted.load(Ordering::SeqCst)
            >= 3)
        .await,
        "the device should have retried at least three times; it dialled {} time(s)",
        accepted.load(Ordering::SeqCst)
    );

    assert!(
        !conn
            .has_changed()
            .expect("the actor should still be running"),
        "a device that has never been up must report no connection transition, but \
         {} teardown(s) each woke the consumer with the same `false`",
        accepted.load(Ordering::SeqCst)
    );
    assert!(!*conn.borrow(), "and it is still down");
}

/// The mirror image: suppressing the repeats must not suppress a real change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_that_comes_up_reports_the_transition() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let held = tokio::spawn({
        let accepted = accepted.clone();
        async move {
            // Hold each socket open: v3.3 needs no handshake, so the TCP connect
            // itself is the device coming up.
            let mut keep = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                keep.push(sock);
            }
        }
    });

    let dev = Device::builder("conn00000000000000001", KEY.to_vec())
        .address(addr.ip().to_string())
        .port(addr.port())
        .version(Version::V3_3)
        .connect()
        .expect("connect");
    let mut conn = dev.watch_connected();

    dev.wait_connected(Duration::from_secs(10))
        .await
        .expect("the device should come up");
    assert!(
        conn.has_changed()
            .expect("the actor should still be running"),
        "coming up is a real transition and must wake the consumer"
    );
    assert!(*conn.borrow_and_update());

    // And having reported it once, it does not report it again while still up.
    assert!(
        !conn.has_changed().unwrap(),
        "a device that stays up must not keep reporting that it came up"
    );
    held.abort();
}
