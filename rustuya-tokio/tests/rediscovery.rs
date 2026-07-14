//! End-to-end P3 test: a live LAN re-announcement cancels a pending reconnect
//! backoff and redials immediately.
//!
//! The device is given a **1-hour** backoff, so after the mock drops the first
//! connection it would otherwise be stuck for an hour. A crafted UDP announcement
//! into the linked `Discovery` is the *only* thing that can bring it back within
//! the test's patience — proving the `ConnectNow` wake path drives a redial.
//!
//! Deterministic: the mock blocks on `accept()` for the redial (no timing guess),
//! and the announcement is injected only after the device is observed disconnected
//! (a spin on the real `is_connected` predicate, not a `sleep`).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use rustuya_core::crypto::TuyaCipher;
use rustuya_core::{frame, CommandType};
use rustuya_tokio::{Device, Discovery, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";
const ID: &str = "rediscover0000000001ab";
const DISCO_PORT: u16 = 56670;

/// A realistic v3.3 device reply: 55AA/CRC frame of `retcode(0) || ECB(json)`.
fn v33_response(json: &[u8]) -> Vec<u8> {
    let cipher = TuyaCipher::new(KEY).unwrap();
    let mut body = 0u32.to_be_bytes().to_vec();
    body.extend_from_slice(&cipher.ecb_encrypt(json).unwrap());
    frame::pack_55aa(1, CommandType::DpQuery as u32, &body, frame::Integrity::Crc32)
}

/// A plaintext 55AA discovery announcement for `ID` at loopback.
fn announcement() -> Vec<u8> {
    let json = format!(r#"{{"gwId":"{ID}","ip":"127.0.0.1","version":"3.3"}}"#);
    frame::pack_55aa(0, CommandType::UdpNew as u32, json.as_bytes(), frame::Integrity::Crc32)
}

/// Read until the client half-closes — a real sync edge, no wall-clock.
async fn wait_until_closed(sock: &mut tokio::net::TcpStream) {
    let mut sink = [0u8; 256];
    while let Ok(n) = sock.read(&mut sink).await {
        if n == 0 {
            break;
        }
    }
}

/// Serve one request+reply, then either drop (first call) or hold open.
async fn serve_one(listener: &TcpListener, reply_json: &[u8], hold: bool) {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.read(&mut buf).await.unwrap();
    assert!(n > 0, "device sent a request");
    sock.write_all(&v33_response(reply_json)).await.unwrap();
    if hold {
        wait_until_closed(&mut sock).await;
    }
    // else: `sock` drops here → connection closed, forcing the device into backoff.
}

#[tokio::test]
async fn rediscovery_cancels_backoff_and_reconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Mock: serve conn1 then drop it; then serve conn2 (the redial) and hold it.
    let server = tokio::spawn(async move {
        serve_one(&listener, br#"{"dps":{"1":true}}"#, false).await; // conn1, then drop
        serve_one(&listener, br#"{"dps":{"2":99}}"#, true).await; // conn2 (redial)
    });

    // Passive discovery on a private port, linked to the device for rewake.
    let disco = Discovery::builder()
        .ports(vec![DISCO_PORT])
        .active(false)
        .build()
        .expect("bind discovery socket");

    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_3)
        // 1-hour backoff: without a rewake, the device stays down for the test.
        .backoff(Duration::from_secs(3600), Duration::from_secs(3600), Duration::ZERO)
        .rediscover(&disco)
        .connect()
        .unwrap();

    // conn1 up and usable.
    let s1 = dev.status().await.expect("first status round-trips");
    assert_eq!(s1["dps"]["1"], true);

    // The mock dropped conn1: wait until the device actually observes the drop and
    // enters backoff (spin on the real predicate, no sleep). Only then does a
    // ConnectNow has a backoff to cancel.
    tokio::time::timeout(Duration::from_secs(3), async {
        while dev.is_connected() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("device observes the conn1 drop");

    // Inject a LAN re-announcement → forwarder → Input::ConnectNow → redial,
    // long before the 1-hour backoff would ever fire.
    let sender = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    sender.send_to(&announcement(), ("127.0.0.1", DISCO_PORT)).await.unwrap();

    // The redial reconnects to the mock; a fresh status proves conn2 is live.
    let s2 = dev.status().await.expect("reconnected via rediscovery, second status round-trips");
    assert_eq!(s2["dps"]["2"], 99);

    dev.close().await;
    disco.close().await;
    server.await.unwrap();
}
