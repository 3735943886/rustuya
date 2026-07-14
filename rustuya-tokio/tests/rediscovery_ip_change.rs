//! End-to-end test: a re-announcement with a **changed IP** redials the *new*
//! address, not the stale one fixed at connect time.
//!
//! The device first connects at `127.0.0.1:P` (conn1). The mock drops it and,
//! with a 1-hour backoff, the device is stuck. A LAN announcement then reports the
//! device at `127.0.0.2:P` (a different loopback IP, same port) — the rewake must
//! adopt that address and reconnect there (conn2, served by a listener bound to
//! `127.0.0.2:P`). Before the fix the rewake redialed the fixed `127.0.0.1:P` and
//! could never reach conn2, so this pins the address-carrying `ConnectNow`.
//!
//! Deterministic: the second mock blocks on `accept()` (no timing guess), and the
//! announcement is injected only after the device is observed disconnected (a spin
//! on the real `is_connected` predicate, not a `sleep`).

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use rustuya_core::crypto::TuyaCipher;
use rustuya_core::{frame, CommandType};
use rustuya_tokio::{Device, Discovery, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";
const ID: &str = "ipchange000000000001ab";
const DISCO_PORT: u16 = 56671;

/// A realistic v3.3 device reply: 55AA/CRC frame of `retcode(0) || ECB(json)`.
fn v33_response(json: &[u8]) -> Vec<u8> {
    let cipher = TuyaCipher::new(KEY).unwrap();
    let mut body = 0u32.to_be_bytes().to_vec();
    body.extend_from_slice(&cipher.ecb_encrypt(json).unwrap());
    frame::pack_55aa(1, CommandType::DpQuery as u32, &body, frame::Integrity::Crc32)
}

/// A plaintext 55AA discovery announcement placing `ID` at `ip`.
fn announcement(ip: &str) -> Vec<u8> {
    let json = format!(r#"{{"gwId":"{ID}","ip":"{ip}","version":"3.3"}}"#);
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

/// Serve one request+reply, then either drop or hold open.
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
async fn rediscovery_with_changed_ip_redials_the_new_address() {
    // conn1 at 127.0.0.1:P; conn2 at 127.0.0.2:P (same port, different loopback IP).
    let l1 = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 1), 0)).await.unwrap();
    let port = l1.local_addr().unwrap().port();
    let l2 = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), port))
        .await
        .expect("bind 127.0.0.2:P (127.0.0.0/8 is all loopback on linux)");

    let server = tokio::spawn(async move {
        // conn1, then drop the listener so a redial to 127.0.0.1:P would be refused.
        serve_one(&l1, br#"{"dps":{"1":true}}"#, false).await;
        drop(l1);
        // conn2 — only reachable if the rewake adopted the 127.0.0.2 address.
        serve_one(&l2, br#"{"dps":{"2":42}}"#, true).await;
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
        // 1-hour backoff: without a rewake the device stays down for the test.
        .backoff(Duration::from_secs(3600), Duration::from_secs(3600), Duration::ZERO)
        .rediscover(&disco)
        .connect()
        .unwrap();

    // conn1 up at 127.0.0.1.
    let s1 = dev.status().await.expect("first status round-trips");
    assert_eq!(s1["dps"]["1"], true);

    // Wait until the device observes the conn1 drop and enters backoff (spin on the
    // real predicate, no sleep) — this also guarantees the forwarder is subscribed.
    tokio::time::timeout(Duration::from_secs(3), async {
        while dev.is_connected() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("device observes the conn1 drop");

    // Announce the device at its NEW IP. The rewake must redial 127.0.0.2:P.
    let sender = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 1), 0)).await.unwrap();
    sender
        .send_to(&announcement("127.0.0.2"), (Ipv4Addr::new(127, 0, 0, 1), DISCO_PORT))
        .await
        .unwrap();

    // conn2 round-trips only if the redial went to the new address.
    let s2 = dev
        .status()
        .await
        .expect("reconnected at the new IP, second status round-trips");
    assert_eq!(s2["dps"]["2"], 42);

    // The linked discovery now records the device (exposed staleness fact).
    assert!(disco.last_seen(ID).is_some(), "known map recorded a last-seen stamp");

    dev.close().await;
    disco.close().await;
    server.await.unwrap();
}
