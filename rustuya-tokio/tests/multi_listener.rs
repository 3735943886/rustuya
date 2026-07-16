//! Fan-in [`MultiListener`] and the [`Device::watch_status`] latch, over hand-rolled
//! v3.3 loopback devices (same approach as `loopback.rs`).
//!
//! Locks in: (1) events from several devices arrive on one stream tagged with the
//! right device id, (2) `add`/`remove`/`len` bookkeeping, (3) the status watch latches
//! the last frame as *state* (readable without consuming the event stream).

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rustuya_core::crypto::TuyaCipher;
use rustuya_core::{CommandType, frame};
use rustuya_tokio::{Device, Event, MultiListener, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";

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

/// Accept one connection, wait for the driver's query, reply once, hold open until
/// the client half-closes (deterministic — no sleep).
async fn serve_once(listener: TcpListener, json: &'static [u8]) {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.read(&mut buf).await.unwrap();
    assert!(n > 0, "device saw the request");
    sock.write_all(&v33_response(json)).await.unwrap();
    let mut sink = [0u8; 64];
    while let Ok(n) = sock.read(&mut sink).await {
        if n == 0 {
            break;
        }
    }
}

async fn spawn_dev(id: &str, json: &'static [u8]) -> (Device, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_once(listener, json));
    let dev = Device::builder(id, *KEY)
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_3)
        .connect()
        .unwrap();
    (dev, server)
}

#[tokio::test]
async fn multi_listener_tags_events_by_device() {
    let (dev_a, sa) = spawn_dev("aaaaaaaaaaaaaaaaaaaaaa", br#"{"dps":{"1":true}}"#).await;
    let (dev_b, sb) = spawn_dev("bbbbbbbbbbbbbbbbbbbbbb", br#"{"dps":{"2":42}}"#).await;

    // Subscribe both before firing so replies can't race the subscription.
    let mut multi = MultiListener::new();
    multi.add(&dev_a);
    multi.add(&dev_b);
    assert_eq!(multi.len(), 2);

    dev_a.query().await.expect("query a");
    dev_b.query().await.expect("query b");

    // One dps-bearing frame from each device, tagged by id (skip acks / lag).
    let mut seen: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let collect = async {
        while seen.len() < 2 {
            if let Some((id, Event::Frame(msg))) = multi.recv().await {
                if msg.payload.is_empty() {
                    continue;
                }
                let v: serde_json::Value = serde_json::from_slice(&msg.payload).unwrap();
                if v.get("dps").is_some() {
                    seen.insert(id, v);
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(3), collect)
        .await
        .expect("both devices reported on the merged stream");

    assert_eq!(seen["aaaaaaaaaaaaaaaaaaaaaa"]["dps"]["1"], true);
    assert_eq!(seen["bbbbbbbbbbbbbbbbbbbbbb"]["dps"]["2"], 42);

    assert!(multi.remove("aaaaaaaaaaaaaaaaaaaaaa"));
    assert_eq!(multi.len(), 1);
    assert!(!multi.contains("aaaaaaaaaaaaaaaaaaaaaa"));

    dev_a.close().await;
    dev_b.close().await;
    sa.await.unwrap();
    sb.await.unwrap();
}

#[tokio::test]
async fn watch_status_latches_current_frame() {
    let (dev, server) = spawn_dev("cccccccccccccccccccccc", br#"{"dps":{"5":"on"}}"#).await;
    dev.wait_connected(Duration::from_secs(5))
        .await
        .expect("connects");

    let mut st = dev.watch_status();
    assert!(
        st.borrow().is_none(),
        "no status latched until the first frame"
    );

    dev.query().await.expect("query");

    // State, not a stream: await the latch changing, then read the current value.
    tokio::time::timeout(Duration::from_secs(3), st.changed())
        .await
        .expect("status latched within 3s")
        .expect("sender alive");
    let msg = st.borrow().clone().expect("a status frame");
    let v: serde_json::Value = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(v["dps"]["5"], "on");

    dev.close().await;
    server.await.unwrap();
}
