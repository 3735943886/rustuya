//! End-to-end discovery-driver test: a crafted UDP announcement on loopback is
//! decoded by the core FSM and surfaces as a `DeviceInfo` through the driver.
//!
//! Uses a plaintext 55AA discovery packet (the v3.1-style dialect), which the core
//! decoder accepts without any UDP key — so the test needs nothing private.

use std::time::Duration;

use tokio::net::UdpSocket;

use rustuya_core::{CommandType, frame};
use rustuya_tokio::Discovery;

/// A fixed high port, unlikely to collide with the real 6666/6667/7000 or with
/// other tests. `SO_REUSEADDR`/`REUSEPORT` also lets it share if needed.
const PORT: u16 = 56666;

/// A plaintext 55AA discovery datagram (`{gwId, ip, version}` JSON, CRC-framed).
fn plaintext_announcement(id: &str, ip: &str, version: &str) -> Vec<u8> {
    let json = format!(r#"{{"gwId":"{id}","ip":"{ip}","version":"{version}"}}"#);
    frame::pack_55aa(
        0,
        CommandType::UdpNew as u32,
        json.as_bytes(),
        frame::Integrity::Crc32,
    )
}

#[tokio::test]
async fn discovers_a_device_from_a_udp_announcement() {
    // Passive only (no outbound probes) on our test port.
    let disco = Discovery::builder()
        .ports(vec![PORT])
        .active(false)
        .build()
        .expect("bind discovery socket");

    // Subscribe *before* sending so the (dedup-once) announcement can't be missed.
    let mut stream = disco.discovered();

    let sender = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let pkt = plaintext_announcement("gwtestdevice01", "192.168.1.77", "3.3");
    sender.send_to(&pkt, ("127.0.0.1", PORT)).await.unwrap();

    let info = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match stream.recv().await {
                Ok(i) if i.id == "gwtestdevice01" => return i,
                Ok(_) => {}
                Err(e) => panic!("stream closed: {e}"),
            }
        }
    })
    .await
    .expect("device discovered within 3s");

    assert_eq!(info.ip, "192.168.1.77".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(info.id, "gwtestdevice01");

    disco.close().await;
}

#[tokio::test]
async fn find_returns_the_matching_device() {
    let disco = Discovery::builder()
        .ports(vec![PORT + 1])
        .active(false)
        .build()
        .expect("bind discovery socket");

    // `find` is race-free by construction: it subscribes before checking the
    // cache, so whether the announcement lands before or after the call, it
    // resolves — one datagram is enough, no re-announcement needed.
    let sender = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let pkt = plaintext_announcement("targetdevice0001", "10.0.0.9", "3.3");
    sender.send_to(&pkt, ("127.0.0.1", PORT + 1)).await.unwrap();

    let info = disco
        .find("targetdevice0001", Duration::from_secs(3))
        .await
        .expect("find resolves the device");
    assert_eq!(info.ip, "10.0.0.9".parse::<std::net::IpAddr>().unwrap());

    disco.close().await;
}
