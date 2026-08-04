//! A device registered **after** discovery cached its announcement must still be
//! able to reach it.
//!
//! This is the addressless-registration case: a controller that cannot know a
//! device's IP up front parks it on a placeholder address and relies on discovery
//! to relocate it. `Found` cannot do that job alone — it is TTL-deduped, and a
//! device that keeps announcing keeps refreshing its cache entry, so the TTL
//! never expires and `Found` never fires again. If the cache was warm at
//! registration time (the normal case for a long-running controller: it has been
//! listening since startup, or it ran a scan first), the only events left are
//! `Seen` ticks, so those must carry the cached address.
//!
//! Deterministic: the cache is confirmed populated (spin on `disco.known()`)
//! *before* the device is built, so every announcement afterwards is
//! unambiguously a `Seen`; the placeholder is TEST-NET-1 with a short connect
//! timeout so the failing dial is fast and unroutable rather than timing-dependent;
//! and the announcement is re-sent until the device connects (UDP is lossy) —
//! never a fixed sleep.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use rustuya_core::crypto::TuyaCipher;
use rustuya_core::{CommandType, frame};
use rustuya_tokio::{Device, Discovery, Version};

mod common;

const KEY: &[u8; 16] = b"0123456789abcdef";
const ID: &str = "seenreloc000000000001a";
const DISCO_PORT: u16 = 56673;
/// RFC 5737 TEST-NET-1: reserved for documentation, guaranteed never a real host.
const PLACEHOLDER: &str = "192.0.2.1";

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

/// The device's announcement — always 127.0.0.1, so the second and later ones
/// are `Seen` (unchanged), not `Found`.
fn announcement() -> Vec<u8> {
    let json = format!(r#"{{"gwId":"{ID}","ip":"127.0.0.1","version":"3.3"}}"#);
    frame::pack_55aa(
        0,
        CommandType::UdpNew as u32,
        json.as_bytes(),
        frame::Integrity::Crc32,
    )
}

#[tokio::test]
async fn a_seen_tick_relocates_a_device_registered_on_a_placeholder() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        assert!(n > 0, "device sent a request");
        sock.write_all(&v33_response(br#"{"dps":{"1":true}}"#))
            .await
            .unwrap();
        let mut sink = [0u8; 256];
        while let Ok(n) = sock.read(&mut sink).await {
            if n == 0 {
                break;
            }
        }
    });

    let disco = Discovery::builder()
        .ports(vec![DISCO_PORT])
        .active(false)
        .build()
        .expect("bind discovery socket");

    let sender = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();

    // Warm the cache *before* the device exists: this first sighting is the one
    // and only `Found`, and it reaches no route because nothing is registered yet.
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
    .expect("discovery caches the device before it is registered");

    // Registered with no usable address. Backoff is an hour, so nothing but a
    // discovery wake can produce a second dial.
    let dev = Device::builder(ID, *KEY)
        .address(PLACEHOLDER)
        .port(port)
        .version(Version::V3_3)
        .connect_timeout(Duration::from_millis(200))
        .backoff(
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Duration::ZERO,
        )
        .rediscover(&disco)
        .connect()
        .unwrap();

    // Keep announcing. Every one of these is a `Seen`; if they carry no address
    // the device redials TEST-NET-1 forever and the query below times out.
    let keep_announcing = tokio::spawn(async move {
        loop {
            sender
                .send_to(&announcement(), ("127.0.0.1", DISCO_PORT))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let dps = common::query_dps(&dev).await;
    assert_eq!(dps["dps"]["1"], true, "the relocated device answered");

    keep_announcing.abort();
    dev.close().await;
    disco.close().await;
    server.await.unwrap();
}
