//! End-to-end test for `Device::connect_now()` reviving a **terminal** device.
//!
//! With `auto_reconnect(false)` a dropped connection goes to a terminal `Closed`
//! state — the device never redials on its own. `connect_now()` is the only way
//! back. (The backoff-cancellation path is covered by `rediscovery.rs`.)
//!
//! Deterministic: the mock `accept()`s the revival connection (no timing guess),
//! and `connect_now()` is issued only after the device is observed disconnected.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rustuya_core::crypto::TuyaCipher;
use rustuya_core::{frame, CommandType};
use rustuya_tokio::{Device, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";
const ID: &str = "01234567890123456789ab";

fn v33_response(json: &[u8]) -> Vec<u8> {
    let cipher = TuyaCipher::new(KEY).unwrap();
    let mut body = 0u32.to_be_bytes().to_vec();
    body.extend_from_slice(&cipher.ecb_encrypt(json).unwrap());
    frame::pack_55aa(1, CommandType::DpQuery as u32, &body, frame::Integrity::Crc32)
}

async fn wait_until_closed(sock: &mut tokio::net::TcpStream) {
    let mut sink = [0u8; 256];
    while let Ok(n) = sock.read(&mut sink).await {
        if n == 0 {
            break;
        }
    }
}

async fn serve_one(listener: &TcpListener, reply: &[u8], hold: bool) {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.read(&mut buf).await.unwrap();
    assert!(n > 0);
    sock.write_all(&v33_response(reply)).await.unwrap();
    if hold {
        wait_until_closed(&mut sock).await;
    }
}

#[tokio::test]
async fn connect_now_revives_a_terminal_device() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        serve_one(&listener, br#"{"dps":{"1":true}}"#, false).await; // conn1, then drop
        serve_one(&listener, br#"{"dps":{"2":7}}"#, true).await; // conn2 (only via connect_now)
    });

    let dev = Device::builder(ID, *KEY)
        .address("127.0.0.1")
        .port(port)
        .version(Version::V3_3)
        .auto_reconnect(false) // dropped → terminal Closed, no self-redial
        .connect()
        .unwrap();

    let s1 = dev.status().await.expect("first status");
    assert_eq!(s1["dps"]["1"], true);

    // The mock dropped conn1: the device goes terminal and stays down.
    tokio::time::timeout(Duration::from_secs(3), async {
        while dev.is_connected() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("device observes the drop");

    // Explicit revival: cancel the terminal state and redial.
    dev.connect_now().await;

    let s2 = dev.status().await.expect("revived via connect_now, second status");
    assert_eq!(s2["dps"]["2"], 7);

    dev.close().await;
    server.await.unwrap();
}
