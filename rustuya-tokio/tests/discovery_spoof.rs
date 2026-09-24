//! A forged discovery announcement must not relocate a device.
//!
//! The UDP discovery keys are public constants, so anyone on the LAN can craft a
//! well-formed announcement for any device id. Its `ip` field is where a linked
//! device would be redirected to redial — so the driver only believes an
//! announcement whose claimed address is the one it actually came from (the
//! `require_source_match` policy, on by default).
//!
//! No sleeping to "prove a negative": both datagrams go out on the same socket to
//! the same port, so the single discovery actor processes them in send order. When
//! the honest announcement's `Found` arrives, the forged one before it has already
//! been decided — accepted, it would have surfaced first.

use std::net::IpAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use rustuya_core::{CommandType, frame};
use rustuya_tokio::Discovery;

const PORT: u16 = 56680;

fn announcement(id: &str, ip: &str) -> Vec<u8> {
    let json = format!(r#"{{"gwId":"{id}","ip":"{ip}","version":"3.3"}}"#);
    frame::pack_55aa(
        0,
        CommandType::UdpNew as u32,
        json.as_bytes(),
        frame::Integrity::Crc32,
    )
}

#[tokio::test]
async fn an_announcement_from_the_wrong_source_is_dropped() {
    let disco = Discovery::builder()
        .ports(vec![PORT])
        .active(false)
        .build()
        .expect("bind discovery socket");
    let mut stream = disco.discovered();

    // Both come from 127.0.0.1. The first claims a device at 192.168.1.66 — not
    // where it was sent from, so a spoof. The second is honest.
    let sender = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    sender
        .send_to(
            &announcement("spoofed00000000001", "192.168.1.66"),
            ("127.0.0.1", PORT),
        )
        .await
        .unwrap();
    sender
        .send_to(
            &announcement("honest000000000001", "127.0.0.1"),
            ("127.0.0.1", PORT),
        )
        .await
        .unwrap();

    let first = tokio::time::timeout(Duration::from_secs(3), stream.recv())
        .await
        .expect("the honest announcement is discovered within 3s")
        .expect("stream open");
    assert_eq!(
        first.id, "honest000000000001",
        "the forged announcement must not surface (or surface first)"
    );
    assert_eq!(first.ip, "127.0.0.1".parse::<IpAddr>().unwrap());

    let known: Vec<String> = disco.known().into_iter().map(|d| d.id).collect();
    assert_eq!(known, vec!["honest000000000001".to_string()]);

    disco.close().await;
}

/// The opt-out exists for a topology that genuinely relays announcements: with the
/// policy off, the same "wrong source" announcement is believed.
#[tokio::test]
async fn the_source_check_can_be_turned_off() {
    let disco = Discovery::builder()
        .ports(vec![PORT + 1])
        .active(false)
        .require_source_match(false)
        .build()
        .expect("bind discovery socket");
    let mut stream = disco.discovered();

    let sender = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    sender
        .send_to(
            &announcement("relayed00000000001", "192.168.1.66"),
            ("127.0.0.1", PORT + 1),
        )
        .await
        .unwrap();

    let info = tokio::time::timeout(Duration::from_secs(3), stream.recv())
        .await
        .expect("discovered within 3s")
        .expect("stream open");
    assert_eq!(info.id, "relayed00000000001");
    assert_eq!(info.ip, "192.168.1.66".parse::<IpAddr>().unwrap());

    disco.close().await;
}
