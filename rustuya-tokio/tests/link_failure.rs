//! `watch_failure` names why a link is down: the detail a supervisor needs to
//! tell "nothing listens there" from "it hung up on us" from "it went quiet",
//! where `watch_connected` only says "down".

use std::time::Duration;

use tokio::net::TcpListener;

use rustuya_tokio::{Device, LinkFailure, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";

/// Wait for the watch to hold `want`, bounded.
async fn failure_becomes(dev: &Device, want: LinkFailure) -> Option<LinkFailure> {
    let mut rx = dev.watch_failure();
    let _ = tokio::time::timeout(Duration::from_secs(10), rx.wait_for(|f| *f == Some(want))).await;
    *rx.borrow()
}

#[tokio::test]
async fn a_port_nothing_listens_on_is_refused() {
    let port = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dev = Device::builder("fail00000000000000000", KEY.to_vec())
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_3)
        .connect()
        .expect("connect");
    let want = LinkFailure::Dial(std::io::ErrorKind::ConnectionRefused);
    assert_eq!(failure_becomes(&dev, want).await, Some(want));
    assert_eq!(want.as_str(), "refused");
}

#[tokio::test]
async fn a_device_that_hangs_up_mid_handshake_closed_the_link() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            drop(sock);
        }
    });
    let dev = Device::builder("fail00000000000000001", KEY.to_vec())
        .address(addr.ip().to_string())
        .port(addr.port())
        .version(Version::V3_4)
        .connect()
        .expect("connect");
    assert_eq!(
        failure_becomes(&dev, LinkFailure::Closed).await,
        Some(LinkFailure::Closed)
    );
}

#[tokio::test]
async fn a_device_that_never_answers_the_handshake_timed_it_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let held = tokio::spawn(async move {
        let mut keep = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            keep.push(sock);
        }
    });
    let dev = Device::builder("fail00000000000000002", KEY.to_vec())
        .address(addr.ip().to_string())
        .port(addr.port())
        .version(Version::V3_4)
        .handshake_timeout(Some(Duration::from_millis(100)))
        .connect()
        .expect("connect");
    let want = LinkFailure::HandshakeTimeout;
    assert_eq!(failure_becomes(&dev, want).await, Some(want));
    held.abort();
}

#[tokio::test]
async fn a_silent_link_is_silent_and_coming_up_clears_the_reason() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let held = tokio::spawn(async move {
        let mut keep = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            keep.push(sock);
        }
    });
    let dev = Device::builder("fail00000000000000003", KEY.to_vec())
        .address(addr.ip().to_string())
        .port(addr.port())
        // v3.3 needs no handshake: the TCP connect is the device coming up.
        .version(Version::V3_3)
        .heartbeat(None)
        .idle_timeout(Some(Duration::from_millis(200)))
        .connect()
        .expect("connect");
    dev.wait_connected(Duration::from_secs(10))
        .await
        .expect("up");
    assert_eq!(
        *dev.watch_failure().borrow(),
        None,
        "a link that is up has no failure"
    );
    assert_eq!(
        failure_becomes(&dev, LinkFailure::Silent).await,
        Some(LinkFailure::Silent)
    );
    held.abort();
}
