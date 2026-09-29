//! A peer can keep TCP open while no longer reading. Saturate the real socket
//! and command queue before testing shutdown, liveness and partial-write recovery.
use std::time::Duration;

use rustuya_core::{CommandType, crypto::TuyaCipher, frame, message::decode_message};
use rustuya_tokio::{Device, Event, TuyaError, Version};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const KEY: &[u8; 16] = b"0123456789abcdef";
const LIMIT: Duration = Duration::from_secs(5);

async fn stalled_pair(idle: Option<Duration>) -> (Device, TcpStream, usize) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // Negotiate a small receive window so this is independent of host TCP
    // autotuning. The server deliberately does not read until the queue fills.
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(4096)
        .unwrap();
    let dev = Device::builder("backpressure", *KEY)
        .address("127.0.0.1")
        .port(listener.local_addr().unwrap().port())
        .version(Version::V3_3)
        .auto_reconnect(false)
        .heartbeat(None)
        .idle_timeout(idle)
        .command_capacity(1)
        .send_timeout(Duration::from_millis(100))
        .connect()
        .unwrap();
    let (peer, _) = timeout(LIMIT, listener.accept()).await.unwrap().unwrap();
    dev.wait_connected(LIMIT).await.unwrap();
    let count = timeout(LIMIT, async {
        let padding = "x".repeat(64 * 1024);
        for i in 0..2000 {
            match dev.set_dps(serde_json::json!({"1": i, "2": padding})).await {
                Ok(()) => {}
                Err(TuyaError::Timeout) => return i,
                Err(e) => panic!("unexpected send failure: {e}"),
            }
        }
        panic!("the unread peer never applied backpressure");
    })
    .await
    .expect("send_timeout must also bound a full command queue");
    assert!(dev.is_connected(), "saturate before the idle deadline");
    (dev, peer, count)
}

#[tokio::test]
async fn close_bypasses_a_full_queue_with_liveness_disabled() {
    let (dev, _peer, _) = stalled_pair(None).await;
    timeout(LIMIT, dev.close())
        .await
        .expect("close must bypass stalled writes");
    assert!(!dev.is_connected());
    assert!(matches!(dev.query().await, Err(TuyaError::Closed)));
    timeout(LIMIT, dev.close())
        .await
        .expect("close is idempotent");
}

#[tokio::test]
async fn dropping_the_last_handle_stops_a_stalled_actor() {
    let (dev, _peer, _) = stalled_pair(None).await;
    let mut connected = dev.watch_connected();
    drop(dev);
    timeout(LIMIT, async { while connected.changed().await.is_ok() {} })
        .await
        .expect("the actor must exit even with a full queue and no idle deadline");
    assert!(!*connected.borrow());
}

#[tokio::test]
async fn reads_and_idle_deadline_progress_while_writes_are_stalled() {
    let (dev, mut peer, _) = stalled_pair(Some(Duration::from_secs(2))).await;
    let mut events = dev.listener();
    let cipher = TuyaCipher::new(KEY).unwrap();
    let mut body = 0u32.to_be_bytes().to_vec();
    body.extend(cipher.ecb_encrypt(br#"{"dps":{"1":true}}"#).unwrap());
    peer.write_all(&frame::pack_55aa(
        1,
        CommandType::DpQuery as u32,
        &body,
        frame::Integrity::Crc32,
    ))
    .await
    .unwrap();
    let event = timeout(LIMIT, events.recv())
        .await
        .expect("reads must progress during a stalled write");
    assert!(matches!(event, Some(Event::Frame(_))));
    let mut connected = dev.watch_connected();
    timeout(LIMIT, async {
        while *connected.borrow_and_update() {
            connected.changed().await.unwrap();
        }
    })
    .await
    .expect("idle timeout must disconnect the stalled socket");
    dev.close().await;
}

#[tokio::test]
async fn partial_writes_resume_without_losing_or_duplicating_bytes() {
    let (dev, mut peer, count) = stalled_pair(None).await;
    timeout(LIMIT, async {
        for i in 0..count {
            let mut header = [0u8; 16];
            peer.read_exact(&mut header).await.unwrap();
            let len = u32::from_be_bytes(header[12..16].try_into().unwrap()) as usize;
            assert!(len <= frame::MAX_PAYLOAD_LEN as usize);
            let mut wire = header.to_vec();
            wire.resize(16 + len, 0);
            peer.read_exact(&mut wire[16..]).await.unwrap();
            let msg = decode_message(Version::V3_3, &wire, KEY, false).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&msg.payload).unwrap();
            assert_eq!(json["dps"]["1"], i);
            assert_eq!(json["dps"]["2"].as_str().unwrap().len(), 64 * 1024);
        }
    })
    .await
    .expect("all accepted commands must drain in order after the peer resumes reading");
    dev.close().await;
}
