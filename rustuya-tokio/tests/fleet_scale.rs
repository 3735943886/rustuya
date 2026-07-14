//! Fleet-scale end-to-end test for ② — the keyed registry routes an announcement
//! **burst** to every one of many devices with no O(N²) fan-out and no dropped
//! reconnect triggers (the failure mode of the old broadcast-subscribe-and-filter
//! forwarder under bus lag).
//!
//! `N` devices each start pointed at a **wrong** IP (`127.0.0.1:Pᵢ`, refused) with
//! `auto_reconnect(false)`, so each drops to a terminal state and can only come
//! back via discovery. All share **one** `Discovery`. A burst of `N` announcements
//! (each placing device `i` at `127.0.0.2:Pᵢ`, where its real mock listens) must
//! revive and reconnect **every** device — proving each registered route fired.
//!
//! Deterministic: mocks block on `accept()`; announcements are (re)sent for the
//! not-yet-connected devices until all `N` are up or the test's patience elapses
//! (UDP is lossy — a resend is a `Found` for any device discovery hasn't yet seen,
//! so the loop converges). No fixed sleeps.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};

use rustuya_tokio::{Device, Discovery, Version};

const KEY: &[u8; 16] = b"0123456789abcdef";
const DISCO_PORT: u16 = 56673;
const N: usize = 300;

fn device_id(i: usize) -> String {
    // 22-char id: "fleet" + 17 digits.
    format!("fleet{i:017}")
}

fn announcement(id: &str) -> Vec<u8> {
    // Each device's real mock is at 127.0.0.2:Pᵢ; the announcement supplies the
    // new IP (the port comes from the device's registered value).
    let json = format!(r#"{{"gwId":"{id}","ip":"127.0.0.2","version":"3.3"}}"#);
    rustuya_core::frame::pack_55aa(
        0,
        rustuya_core::CommandType::UdpNew as u32,
        json.as_bytes(),
        rustuya_core::frame::Integrity::Crc32,
    )
}

/// A mock that just accepts and holds — a v3.3 device is `is_connected` on the TCP
/// connect itself (no session handshake), so no reply is needed.
async fn serve_hold(listener: TcpListener) {
    if let Ok((mut sock, _)) = listener.accept().await {
        let mut sink = [0u8; 256];
        while let Ok(n) = sock.read(&mut sink).await {
            if n == 0 {
                break;
            }
        }
    }
}

#[tokio::test]
async fn fleet_reconnects_every_device_from_one_announcement_burst() {
    let disco = Discovery::builder()
        .ports(vec![DISCO_PORT])
        .active(false)
        .build()
        .expect("bind discovery socket");

    let mut devices = Vec::with_capacity(N);
    let mut ids = Vec::with_capacity(N);
    for i in 0..N {
        // Real mock at 127.0.0.2:Pᵢ.
        let listener = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve_hold(listener));

        let id = device_id(i);
        let dev = Device::builder(&id, *KEY)
            // Wrong IP (right port): refused → terminal, no self-redial.
            .address("127.0.0.1")
            .port(port)
            .version(Version::V3_3)
            .auto_reconnect(false)
            .connect_timeout(Duration::from_secs(2))
            .rediscover(&disco)
            .connect()
            .unwrap();
        ids.push(id);
        devices.push(dev);
    }

    // Burst-announce every device at its new IP, resending only for those not yet
    // connected, until the whole fleet is up.
    let sender = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await.unwrap());
    let all_up = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let mut pending = 0;
            for (dev, id) in devices.iter().zip(&ids) {
                if !dev.is_connected() {
                    pending += 1;
                    sender.send_to(&announcement(id), ("127.0.0.1", DISCO_PORT)).await.unwrap();
                }
            }
            if pending == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;

    let connected = devices.iter().filter(|d| d.is_connected()).count();
    assert!(all_up.is_ok(), "only {connected}/{N} devices reconnected before timeout");
    assert_eq!(connected, N, "every device reconnected via its keyed route");

    for dev in &devices {
        dev.close().await;
    }
    disco.close().await;
}
