//! End-to-end addressless flow: a UDP announcement is discovered, its reported
//! address and version drive a TCP connect, and `status()` round-trips — all
//! without the caller supplying an address or version. Deterministic (no waits).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use rustuya_core::crypto::TuyaCipher;
use rustuya_core::{CommandType, frame};
use rustuya_tokio::{Device, Discovery};

const KEY: &[u8; 16] = b"0123456789abcdef";
const ID: &str = "discoverdevice000001";
/// Discovery UDP port for this test (high, unlikely to collide).
const DPORT: u16 = 56670;

/// A plaintext 55AA announcement carrying the device's id, self-reported ip, and
/// version — the shape `discover()` resolves address + version from.
fn announcement(id: &str, ip: &str) -> Vec<u8> {
    let json = format!(r#"{{"gwId":"{id}","ip":"{ip}","version":"3.3"}}"#);
    frame::pack_55aa(
        0,
        CommandType::UdpNew as u32,
        json.as_bytes(),
        frame::Integrity::Crc32,
    )
}

/// A realistic v3.3 device response (retcode || ECB(json)).
fn v33_response(json: &[u8]) -> Vec<u8> {
    let cipher = TuyaCipher::new(KEY).unwrap();
    let ct = cipher.ecb_encrypt(json).unwrap();
    let mut body = 0u32.to_be_bytes().to_vec();
    body.extend_from_slice(&ct);
    frame::pack_55aa(
        1,
        CommandType::DpQuery as u32,
        &body,
        frame::Integrity::Crc32,
    )
}

/// Hold the mock connection open until the driver closes it (deterministic edge,
/// no sleep).
async fn wait_until_closed(sock: &mut TcpStream) {
    let mut sink = [0u8; 256];
    while let Ok(n) = sock.read(&mut sink).await {
        if n == 0 {
            break;
        }
    }
}

async fn serve_once(listener: TcpListener, json: &'static [u8]) {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 4096];
    let n = sock.read(&mut buf).await.unwrap();
    assert!(n > 0, "device saw the request");
    sock.write_all(&v33_response(json)).await.unwrap();
    wait_until_closed(&mut sock).await;
}

#[tokio::test]
async fn discovers_then_connects_addressless() {
    // The TCP "device" on an ephemeral port.
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    let server = tokio::spawn(serve_once(tcp, br#"{"dps":{"1":true}}"#));

    // Passive discovery; announce the device at 127.0.0.1.
    let disco = Discovery::builder()
        .ports(vec![DPORT])
        .active(false)
        .build()
        .expect("bind discovery socket");
    let sender = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    sender
        .send_to(&announcement(ID, "127.0.0.1"), ("127.0.0.1", DPORT))
        .await
        .unwrap();

    // No address, no version: `discover` resolves both (ip 127.0.0.1, v3.3). Only
    // the TCP port is overridden, since the mock isn't on the real 6668.
    let dev = Device::builder(ID, *KEY)
        .port(tcp_port)
        .discover(&disco, Duration::from_secs(3))
        .await
        .expect("discovery resolves and connects");

    let state = dev.status().await.expect("status round-trips");
    assert_eq!(state["dps"]["1"], true);

    dev.close().await;
    disco.close().await;
    server.await.unwrap();
}
