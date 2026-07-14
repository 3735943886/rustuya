//! End-to-end test for ① — a **same-IP** re-announcement wakes a device from
//! backoff, via the core's `Event::Seen` liveness tick (not `Found`, which is
//! TTL-deduped away for an unchanged device).
//!
//! The device is seen once while connected (populating the discovery cache), the
//! mock drops it into a 1-hour backoff, and then a **second, identical** (same-IP)
//! announcement must bring it back — proving the same-IP flap path, the common
//! case a pure resolve-once design leaves stuck on backoff.
//!
//! Deterministic: the second mock blocks on `accept()`; the cache is confirmed
//! populated (spin on `disco.known()`) before the drop so the reviving
//! announcement is unambiguously a `Seen`, not a `Found`; and the announcement is
//! (re)sent until the device reconnects (UDP is lossy) — never a fixed sleep.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use rustuya_core::crypto::TuyaCipher;
use rustuya_core::{CommandType, frame};
use rustuya_tokio::{Device, Discovery, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";
const ID: &str = "seenflap0000000000001a";
const DISCO_PORT: u16 = 56672;

fn v33_response(json: &[u8]) -> Vec<u8> {
    let cipher = TuyaCipher::new(KEY).unwrap();
    let mut body = 0u32.to_be_bytes().to_vec();
    body.extend_from_slice(&cipher.ecb_encrypt(json).unwrap());
    frame::pack_55aa(
        1,
        CommandType::DpQuery as u32,
        &body,
        frame::Integrity::Crc32,
    )
}

/// Same-IP announcement (127.0.0.1) for `ID`.
fn announcement() -> Vec<u8> {
    let json = format!(r#"{{"gwId":"{ID}","ip":"127.0.0.1","version":"3.3"}}"#);
    frame::pack_55aa(
        0,
        CommandType::UdpNew as u32,
        json.as_bytes(),
        frame::Integrity::Crc32,
    )
}

async fn wait_until_closed(sock: &mut tokio::net::TcpStream) {
    let mut sink = [0u8; 256];
    while let Ok(n) = sock.read(&mut sink).await {
        if n == 0 {
            break;
        }
    }
}

async fn serve_one(listener: &TcpListener, reply_json: &[u8], hold: bool) {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.read(&mut buf).await.unwrap();
    assert!(n > 0, "device sent a request");
    sock.write_all(&v33_response(reply_json)).await.unwrap();
    if hold {
        wait_until_closed(&mut sock).await;
    }
}

#[tokio::test]
async fn same_ip_reannouncement_wakes_from_backoff_via_seen() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        serve_one(&listener, br#"{"dps":{"1":true}}"#, false).await; // conn1, then drop
        serve_one(&listener, br#"{"dps":{"9":9}}"#, true).await; // conn2 (only via a Seen wake)
    });

    let disco = Discovery::builder()
        .ports(vec![DISCO_PORT])
        .active(false)
        .build()
        .expect("bind discovery socket");

    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_3)
        .backoff(
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Duration::ZERO,
        )
        .rediscover(&disco)
        .connect()
        .unwrap();

    let sender = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();

    // conn1 up.
    let s1 = dev.status().await.expect("first status");
    assert_eq!(s1["dps"]["1"], true);

    // Populate the discovery cache with a first sighting, so the *reviving*
    // announcement below is unambiguously a `Seen` (unchanged) and not a `Found`.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            sender
                .send_to(&announcement(), ("127.0.0.1", DISCO_PORT))
                .await
                .unwrap();
            if disco.known().iter().any(|d| d.id == ID) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("discovery caches the device (first sighting)");

    // The mock dropped conn1: device enters the 1-hour backoff.
    tokio::time::timeout(Duration::from_secs(3), async {
        while dev.is_connected() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("device observes the conn1 drop");

    // Re-send the identical announcement until the device reconnects. Each is a
    // `Seen` (cached, same IP) → a bare `ConnectNow` that cancels backoff.
    let revive = tokio::spawn(async move {
        loop {
            sender
                .send_to(&announcement(), ("127.0.0.1", DISCO_PORT))
                .await
                .unwrap();
            tokio::task::yield_now().await;
        }
    });

    let s2 = dev
        .status()
        .await
        .expect("woken from backoff by a same-IP Seen");
    assert_eq!(s2["dps"]["9"], 9);

    revive.abort();
    dev.close().await;
    disco.close().await;
    server.await.unwrap();
}
